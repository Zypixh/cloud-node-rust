use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR, StaticAdmissionPermit};
use async_trait::async_trait;
use dashmap::DashMap;
use pingora_cache::key::CompactCacheKey;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::{CacheKey, CacheMeta};
use pingora_core::{Error, ErrorType, Result};
use pingora_http::ResponseHeader;
use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::LazyLock as Lazy;
use std::sync::{Arc, RwLock};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tracing::{info, warn};

use arc_swap::ArcSwap;

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

static CLUSTER_STORAGE_POLICY_SKIP_LOGGED: AtomicBool = AtomicBool::new(false);

static CACHED_DISK_AVAILABLE: AtomicU64 = AtomicU64::new(u64::MAX);
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

const DISK_HIT_CHUNK_BYTES: usize = 128 * 1024;
const DISK_HIT_CHUNK_BYTES_SENDFILE_REQUESTED: usize = 256 * 1024;
const MEMORY_SERVE_MAX: u64 = 50 * 1024 * 1024;
const BLOOM_BITS_PER_ENTRY_ESTIMATE: u64 = 10;
const BLOOM_LAYER_OVERHEAD_BYTES: u64 = 256;
const L1_RESIZE_GROW_MIN_DELTA_PCT: u64 = 25;
const L1_RESIZE_SHRINK_MIN_DELTA_PCT: u64 = 10;
const L1_RESIZE_GROW_MIN_DELTA_BYTES: u64 = 32 * 1024 * 1024;
const L1_RESIZE_SHRINK_MIN_DELTA_BYTES: u64 = 8 * 1024 * 1024;

fn cache_memory_hit_limit_bytes() -> u64 {
    MEMORY_GOVERNOR
        .cache_read_memory_object_limit_bytes()
        .min(MEMORY_SERVE_MAX)
}

fn try_admit_cache_memory_hit(bytes: u64) -> Option<StaticAdmissionPermit> {
    MEMORY_GOVERNOR.try_admit_cache_read(bytes)
}

/// Parse `stale-while-revalidate=N` from a Cache-Control header value.
/// Returns `None` if the directive is absent.
pub(crate) fn parse_swr_from_cache_control(cc: &str) -> Option<u64> {
    for part in cc.split(',') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed
            .to_ascii_lowercase()
            .strip_prefix("stale-while-revalidate")
        {
            let rest = rest.trim();
            if let Some(num_str) = rest.strip_prefix('=') {
                if let Ok(n) = num_str.trim().parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn zstd_decompress_to_bytes(data: &[u8], capacity: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let decoder = zstd::Decoder::new(data).ok()?;
    let mut out = Vec::with_capacity(capacity.min(64 * 1024));
    let mut reader = std::io::BufReader::new(decoder);
    let mut buf = [0u8; 32 * 1024];
    loop {
        let read = reader.read(&mut buf).ok()?;
        if read == 0 {
            return Some(out);
        }
        if out.len().saturating_add(read) > capacity {
            return None;
        }
        out.extend_from_slice(&buf[..read]);
    }
}

/// Dynamic Disk-based storage for Pingora-cache
pub struct FileStorage {
    pub inner: ArcSwap<FileStorageInner>,
    enable_sendfile: AtomicBool,
    enable_file_cache: AtomicBool,
}

pub struct FileStorageInner {
    layout: FileStorageLayout,
}

#[derive(Clone)]
pub struct PartialStorageLocation {
    pub roots: Vec<PathBuf>,
    pub write_root: PathBuf,
}

pub enum FileStorageLayout {
    Single {
        main_root: PathBuf,
        extra_roots: Vec<PathBuf>,
    },
    Sharded {
        shards: Vec<CacheShard>,
        fallback_roots: Vec<PathBuf>,
    },
}

#[derive(Clone)]
pub struct CacheShard {
    pub id: String,
    pub root: PathBuf,
    pub weight: u32,
}

impl FileStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let main_root = root.into();
        let _ = std::fs::create_dir_all(&main_root);
        Self {
            inner: ArcSwap::from_pointee(FileStorageInner::single(main_root, Vec::new())),
            enable_sendfile: AtomicBool::new(true),
            enable_file_cache: AtomicBool::new(true),
        }
    }

    pub fn update_config(
        &self,
        main: PathBuf,
        extras: Vec<PathBuf>,
        sendfile: bool,
        file_cache: bool,
    ) {
        let _ = std::fs::create_dir_all(&main);
        for extra in &extras {
            let _ = std::fs::create_dir_all(extra);
        }
        self.inner
            .store(Arc::new(FileStorageInner::single(main, extras)));
        self.enable_sendfile.store(sendfile, Ordering::Relaxed);
        self.enable_file_cache.store(file_cache, Ordering::Relaxed);
    }

    pub fn update_shards(
        &self,
        shards: Vec<CacheShard>,
        fallback_roots: Vec<PathBuf>,
        sendfile: bool,
        file_cache: bool,
    ) {
        for shard in &shards {
            let _ = std::fs::create_dir_all(&shard.root);
        }
        for root in &fallback_roots {
            let _ = std::fs::create_dir_all(root);
        }
        self.inner
            .store(Arc::new(FileStorageInner::sharded(shards, fallback_roots)));
        self.enable_sendfile.store(sendfile, Ordering::Relaxed);
        self.enable_file_cache.store(file_cache, Ordering::Relaxed);
    }

    fn get_hash(&self, key: &CacheKey) -> String {
        let k_str = key.primary_key_str().unwrap_or("unknown");
        format!("{:x}", md5_legacy::compute(k_str))
    }

    pub fn get_path(&self, key: &CacheKey) -> PathBuf {
        let hash = self.get_hash(key);
        self.get_path_by_hash(&hash)
    }

    fn get_write_location(&self, key: &CacheKey) -> (PathBuf, Option<String>, String) {
        let hash = self.get_hash(key);
        let inner = self.inner.load();
        inner.write_location(&hash)
    }

    fn enable_file_cache(&self) -> bool {
        self.enable_file_cache.load(Ordering::Relaxed)
    }

    fn enable_sendfile(&self) -> bool {
        self.enable_sendfile.load(Ordering::Relaxed)
    }

    fn disk_hit_chunk_bytes(&self) -> usize {
        if self.enable_sendfile() {
            DISK_HIT_CHUNK_BYTES_SENDFILE_REQUESTED
        } else {
            DISK_HIT_CHUNK_BYTES
        }
    }

    fn get_path_by_hash(&self, hash: &str) -> PathBuf {
        let inner = self.inner.load();
        inner.write_path(hash)
    }

    async fn find_existing_path_by_hash(&self, hash: &str) -> Option<PathBuf> {
        let paths = {
            let inner = self.inner.load();
            inner.read_paths(hash)
        };
        for path in paths {
            if tokio::fs::metadata(&path).await.is_ok() {
                return Some(path);
            }
        }
        None
    }

    pub fn partial_location_for_key_str(&self, key: &str) -> PartialStorageLocation {
        let root_key =
            crate::cache::partial::partial_base_key(key).unwrap_or_else(|| key.to_string());
        let hash = format!("{:x}", md5_legacy::compute(root_key.as_bytes()));
        let inner = self.inner.load();
        let (path, _, _) = inner.write_location(&hash);
        let write_root = path
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::paths::NodePaths::current().cache_dir());
        let mut roots = inner.all_roots();
        if !roots.iter().any(|root| root == &write_root) {
            roots.insert(0, write_root.clone());
        }
        PartialStorageLocation { roots, write_root }
    }
}

impl FileStorageInner {
    fn single(main_root: PathBuf, extra_roots: Vec<PathBuf>) -> Self {
        Self {
            layout: FileStorageLayout::Single {
                main_root,
                extra_roots,
            },
        }
    }

    fn sharded(shards: Vec<CacheShard>, fallback_roots: Vec<PathBuf>) -> Self {
        Self {
            layout: FileStorageLayout::Sharded {
                shards,
                fallback_roots,
            },
        }
    }

    fn write_path(&self, hash: &str) -> PathBuf {
        self.write_location(hash).0
    }

    fn write_location(&self, hash: &str) -> (PathBuf, Option<String>, String) {
        let relative = cache_relative_path(hash);
        let relative_str = relative.to_string_lossy().to_string();
        match &self.layout {
            FileStorageLayout::Single { main_root, .. } => {
                (main_root.join(relative), None, relative_str)
            }
            FileStorageLayout::Sharded { .. } => self
                .selected_shard(hash)
                .map(|shard| {
                    (
                        shard.root.join(&relative),
                        Some(shard.id.clone()),
                        relative_str.clone(),
                    )
                })
                .unwrap_or_else(|| {
                    (
                        crate::paths::NodePaths::current()
                            .cache_dir()
                            .join(relative),
                        None,
                        relative_str,
                    )
                }),
        }
    }

    fn read_paths(&self, hash: &str) -> Vec<PathBuf> {
        let relative = cache_relative_path(hash);
        match &self.layout {
            FileStorageLayout::Single {
                main_root,
                extra_roots,
            } => extra_roots
                .iter()
                .chain(std::iter::once(main_root))
                .map(|root| root.join(&relative))
                .collect(),
            FileStorageLayout::Sharded {
                shards,
                fallback_roots,
            } => {
                let mut roots = Vec::with_capacity(shards.len() + fallback_roots.len());
                if let Some(selected) = self.selected_shard(hash) {
                    roots.push(selected.root.clone());
                }
                for shard in shards {
                    if !roots.iter().any(|root| root == &shard.root) {
                        roots.push(shard.root.clone());
                    }
                }
                roots.extend(fallback_roots.iter().cloned());
                roots.into_iter().map(|root| root.join(&relative)).collect()
            }
        }
    }

    fn selected_shard(&self, hash: &str) -> Option<&CacheShard> {
        let FileStorageLayout::Sharded { shards, .. } = &self.layout else {
            return None;
        };
        if shards.is_empty() {
            return None;
        }
        let prefix = hash.get(..16).unwrap_or(hash);
        let value = u64::from_str_radix(prefix, 16).unwrap_or_else(|_| {
            let bytes = md5_legacy::compute(hash.as_bytes());
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        });
        shards.get((value as usize) % shards.len())
    }

    pub fn all_roots(&self) -> Vec<PathBuf> {
        match &self.layout {
            FileStorageLayout::Single {
                main_root,
                extra_roots,
            } => std::iter::once(main_root.clone())
                .chain(extra_roots.iter().cloned())
                .collect(),
            FileStorageLayout::Sharded {
                shards,
                fallback_roots,
            } => shards
                .iter()
                .map(|shard| shard.root.clone())
                .chain(fallback_roots.iter().cloned())
                .collect(),
        }
    }
}

fn cache_relative_path(hash: &str) -> PathBuf {
    Path::new(&hash[0..2]).join(&hash[2..4]).join(hash)
}

fn status_allows_content_length(status: u16) -> bool {
    !(status < 200 || status == 204 || status == 304)
}

fn restore_content_length(header: &mut ResponseHeader, status: u16, size: u64) {
    if size > 0
        && status_allows_content_length(status)
        && !header.headers.contains_key("content-length")
    {
        let _ = header.insert_header("content-length", size.to_string());
    }
}

fn parse_runtime_size_bytes(value: &str) -> anyhow::Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }

    let split_at = trimmed
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(trimmed.len());
    let (number, unit) = trimmed.split_at(split_at);
    let count = number
        .parse::<f64>()
        .map_err(|_| anyhow::anyhow!("invalid size value: {value}"))?;
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1_f64,
        "k" | "kb" | "ki" | "kib" => 1024_f64,
        "m" | "mb" | "mi" | "mib" => 1024_f64.powi(2),
        "g" | "gb" | "gi" | "gib" => 1024_f64.powi(3),
        "t" | "tb" | "ti" | "tib" => 1024_f64.powi(4),
        other => anyhow::bail!("unsupported size unit in {value}: {other}"),
    };
    Ok((count * multiplier) as u64)
}

async fn remove_cache_file_from_roots(inner: &FileStorageInner, hash: &str) {
    let relative = cache_relative_path(hash);
    for root in inner.all_roots() {
        let _ = fs::remove_file(root.join(&relative)).await;
    }
}

#[async_trait]
impl Storage for FileStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            let location = self.partial_location_for_key_str(k_str);
            return Ok(crate::cache::partial::lookup(k_str, &location.roots)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?
                .map(|hit| (hit.meta, hit.handler)));
        }

        let hash = self.get_hash(key);

        let meta = match crate::metrics::storage::get_cache_meta_memory(&hash) {
            Some(m) => m,
            None => return Ok(None),
        };

        let Some(path) = self.find_existing_path_by_hash(&hash).await else {
            crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
            return Ok(None);
        };

        let file_size = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata.len(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
                return Ok(None);
            }
            Err(_) => return Err(Error::new(ErrorType::InternalError)),
        };
        if !meta.compressed && meta.size != file_size {
            warn!(
                "CACHE_HIT_META_SIZE_MISMATCH: hash={} metadata_size={} file_size={} path={}",
                hash,
                meta.size,
                file_size,
                path.display()
            );
            crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
            return Ok(None);
        }

        let now = crate::utils::time::now_timestamp();
        let ttl = (meta.expires - now).max(0) as u64;

        let status = crate::metrics::storage::normalize_cache_status(meta.status);
        let mut header = pingora_http::ResponseHeader::build(status, None).unwrap();
        for (name, val) in &meta.headers {
            let _ = header.insert_header(name.to_string(), val.as_str());
        }
        restore_content_length(&mut header, status, meta.size);

        let cache_meta = CacheMeta::new(
            std::time::SystemTime::now() + std::time::Duration::from_secs(ttl),
            std::time::SystemTime::now(),
            0,
            0,
            header,
        );
        let io_start = std::time::Instant::now();
        let enable_file_cache = self.enable_file_cache();
        let disk_hit_chunk_bytes = self.disk_hit_chunk_bytes();
        let memory_hit_limit = cache_memory_hit_limit_bytes();

        if !meta.compressed {
            let memory_hit_permit = if enable_file_cache
                && meta.size <= memory_hit_limit
                && file_size <= memory_hit_limit
            {
                try_admit_cache_memory_hit(file_size)
            } else {
                None
            };
            if let Some(cache_read_permit) = memory_hit_permit {
                let file_data = match tokio::fs::read(&path).await {
                    Ok(data) => data,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
                        return Ok(None);
                    }
                    Err(_) => return Err(Error::new(ErrorType::InternalError)),
                };
                PROF_DISK_READ_US
                    .fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
                crate::metrics::storage::record_cache_access_memory(&hash);
                let body = bytes::Bytes::from(file_data);
                let body_len = body.len();
                return Ok(Some((
                    cache_meta,
                    Box::new(MemoryHitHandler {
                        data: body,
                        offset: 0,
                        end: body_len,
                        _cache_read_permit: Some(cache_read_permit),
                    }),
                )));
            }

            let file = match tokio::fs::File::open(&path).await {
                Ok(file) => file,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
                    return Ok(None);
                }
                Err(_) => return Err(Error::new(ErrorType::InternalError)),
            };
            PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
            crate::metrics::storage::record_cache_access_memory(&hash);
            return Ok(Some((
                cache_meta,
                Box::new(FileHitHandler {
                    reader: Box::new(file),
                    buf_size: disk_hit_chunk_bytes,
                }),
            )));
        }

        let compressed_memory_charge = meta.size.saturating_add(file_size).min(MEMORY_SERVE_MAX);
        let compressed_memory_permit = if enable_file_cache
            && meta.size > 0
            && meta.size <= DISK_HIT_CHUNK_BYTES as u64
            && file_size <= disk_hit_chunk_bytes as u64
        {
            try_admit_cache_memory_hit(compressed_memory_charge)
        } else {
            None
        };
        if let Some(cache_read_permit) = compressed_memory_permit {
            let file_data = match tokio::fs::read(&path).await {
                Ok(data) => data,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
                    return Ok(None);
                }
                Err(_) => return Err(Error::new(ErrorType::InternalError)),
            };
            PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
            crate::metrics::storage::record_cache_access_memory(&hash);
            let capacity = meta.size.min(MEMORY_SERVE_MAX) as usize;
            let result =
                tokio::task::spawn_blocking(move || zstd_decompress_to_bytes(&file_data, capacity))
                    .await;
            let body = match result {
                Ok(Some(data)) if data.len() as u64 == meta.size => bytes::Bytes::from(data),
                _ => return Ok(None),
            };
            let body_len = body.len();
            return Ok(Some((
                cache_meta,
                Box::new(MemoryHitHandler {
                    data: body,
                    offset: 0,
                    end: body_len,
                    _cache_read_permit: Some(cache_read_permit),
                }),
            )));
        }

        let file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
                return Ok(None);
            }
            Err(_) => return Err(Error::new(ErrorType::InternalError)),
        };
        PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
        crate::metrics::storage::record_cache_access_memory(&hash);
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(BufReader::new(file));
        Ok(Some((
            cache_meta,
            Box::new(FileHitHandler {
                reader: Box::new(decoder),
                buf_size: disk_hit_chunk_bytes,
            }),
        )))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<MissHandler> {
        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            let resp_headers = meta.response_header();
            let Some(content_range) =
                crate::cache::partial::content_range_from_headers(&resp_headers.headers)
            else {
                return Err(Error::new(ErrorType::InternalError));
            };
            let expires = meta
                .fresh_until()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs() as i64)
                .unwrap_or_else(|_| crate::utils::time::now_timestamp());
            let capture = crate::cache::partial::PartialCapture {
                start: content_range.start,
                end: content_range.end,
                total: content_range.total,
                expires,
                headers: crate::cache::partial::response_headers_to_store(&resp_headers.headers),
                min_size: None,
                max_size: None,
            };
            let location = self.partial_location_for_key_str(k_str);
            let Some(cache_write_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::CacheWrite)
            else {
                return Ok(Box::new(NoopMissHandler));
            };
            return Ok(Box::new(PartialMissHandler {
                cache_key: k_str.to_string(),
                capture,
                writer: None,
                location,
                disabled: false,
                _cache_write_permit: cache_write_permit,
            }));
        }

        let Some(cache_write_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::CacheWrite) else {
            return Ok(Box::new(NoopMissHandler));
        };

        let (path, shard_id, relative_path) = self.get_write_location(key);
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        // Use a unique temp path to prevent concurrent cache misses from corrupting the same file
        let unique_id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = path.with_extension(format!("tmp.{}.{}", std::process::id(), unique_id));

        let std_file = tokio::fs::File::create(&temp_path)
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;

        let k_str = key.primary_key_str().unwrap_or("unknown").to_string();
        let hash = self.get_hash(key);
        let ttl = meta
            .fresh_until()
            .duration_since(meta.created())
            .map(|d| d.as_secs())
            .unwrap_or(3600);

        // Smart Compression Decision (Synchronized with HIT path via metadata)
        let resp_headers = meta.response_header();
        let status = resp_headers.status.as_u16();
        let content_type = resp_headers
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let content_encoding = resp_headers
            .headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let should_compress = (content_type.contains("text/")
            || content_type.contains("json")
            || content_type.contains("javascript")
            || content_type.contains("xml"))
            && content_encoding.is_empty();

        // Parse stale-while-revalidate from Cache-Control header
        let swr_secs = resp_headers
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .and_then(|cc| parse_swr_from_cache_control(cc))
            .unwrap_or(0);

        let mut headers_json = serde_json::Map::new();
        for (name, value) in resp_headers.headers.iter() {
            if !crate::cache::should_store_response_header(name.as_str()) {
                continue;
            }
            headers_json.insert(
                name.to_string(),
                serde_json::Value::String(value.to_str().unwrap_or("").to_string()),
            );
        }

        Ok(Box::new(FileMissHandler {
            file: Some(std_file),
            encoder: None,
            written: 0,
            final_path: path,
            temp_path,
            hash,
            key_str: k_str,
            ttl,
            status,
            headers: headers_json
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect(),
            compressed: should_compress,
            shard_id,
            relative_path,
            stale_while_revalidate_secs: swr_secs,
            committed: false,
            _cache_write_permit: cache_write_permit,
        }))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        if key.user_tag.is_empty() {
            return Ok(false);
        }

        let hash = format!("{:x}", md5_legacy::compute(key.user_tag.as_ref()));
        let inner = self.inner.load();
        remove_cache_file_from_roots(&inner, &hash).await;
        crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
        Ok(true)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            return Ok(true);
        }

        let hash = self.get_hash(key);
        let k_str = key.primary_key_str().unwrap_or("unknown").to_string();
        let ttl = meta
            .fresh_until()
            .duration_since(meta.created())
            .map(|d| d.as_secs())
            .unwrap_or(3600);
        let resp_headers = meta.response_header();
        let status = resp_headers.status.as_u16();

        let mut headers_json = serde_json::Map::new();
        for (name, value) in resp_headers.headers.iter() {
            if !crate::cache::should_store_response_header(name.as_str()) {
                continue;
            }
            headers_json.insert(
                name.to_string(),
                serde_json::Value::String(value.to_str().unwrap_or("").to_string()),
            );
        }

        // We need to know if the file was compressed. For now, we can check the Content-Type
        // logic again, or store it in a way update_meta can see.
        // Simplest: re-run the same policy.
        let content_type = resp_headers
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let content_encoding = resp_headers
            .headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let compressed = (content_type.contains("text/")
            || content_type.contains("json")
            || content_type.contains("javascript")
            || content_type.contains("xml"))
            && content_encoding.is_empty();

        tracing::debug!(
            "CACHE_UPDATE_META: hash: {}, status: {}, compressed: {}, headers_len: {}",
            hash,
            status,
            compressed,
            headers_json.len()
        );
        let header_pairs: Vec<(String, String)> = headers_json
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
            .collect();
        let now = crate::utils::time::now_timestamp();
        let existing = crate::metrics::storage::STORAGE.get_cache_meta(&hash);
        // Preserve existing SWR and created_at when updating meta; re-parse SWR from new headers.
        let swr_secs = resp_headers
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .and_then(|cc| parse_swr_from_cache_control(cc))
            .unwrap_or_else(|| {
                existing
                    .as_ref()
                    .map(|m| m.stale_while_revalidate_secs)
                    .unwrap_or(0)
            });
        let created_at = existing.as_ref().map(|m| m.created_at).unwrap_or(now);
        crate::metrics::storage::STORAGE.upsert_cache_meta_absolute_async(
            crate::metrics::storage::CacheMetaUpsert {
                hash: &hash,
                cache_key: &k_str,
                size: existing.as_ref().map(|meta| meta.size).unwrap_or(0),
                expires: now + ttl as i64,
                access_time: existing
                    .as_ref()
                    .map(|meta| meta.access_time)
                    .unwrap_or(now),
                access_count: existing.as_ref().map(|meta| meta.access_count).unwrap_or(1),
                status,
                headers: &header_pairs,
                compressed,
                shard_id: existing.as_ref().and_then(|meta| meta.shard_id.as_deref()),
                relative_path: existing
                    .as_ref()
                    .and_then(|meta| meta.relative_path.as_deref()),
                event_version: existing.as_ref().and_then(|meta| meta.event_version),
                updated_at: Some(now),
                stale_while_revalidate_secs: swr_secs,
                created_at,
            },
        )
        .await;

        Ok(true)
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

/// In-memory hit handler that serves from a Bytes buffer in 32KB chunks.
/// Chunked delivery is required by Pingora's HTTP framing — one-shot delivery
/// breaks keep-alive and causes connection leaks.
struct MemoryHitHandler {
    data: bytes::Bytes,
    offset: usize,
    end: usize,
    _cache_read_permit: Option<StaticAdmissionPermit>,
}

#[async_trait]
impl HandleHit for MemoryHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        if self.offset >= self.end {
            return Ok(None);
        }
        let end = (self.offset + 32768).min(self.end);
        let chunk = self.data.slice(self.offset..end);
        self.offset = end;
        Ok(Some(chunk))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if start > self.data.len() {
            return Err(Error::new(ErrorType::InternalError));
        }
        if end.is_some_and(|end| end < start) {
            return Err(Error::new(ErrorType::InternalError));
        }
        self.offset = start;
        self.end = end.unwrap_or(self.data.len()).min(self.data.len());
        Ok(())
    }
}

struct FileHitHandler {
    reader: Box<dyn AsyncRead + Unpin + Send + Sync>,
    buf_size: usize,
}

#[async_trait]
impl HandleHit for FileHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        let mut buf = bytes::BytesMut::with_capacity(self.buf_size);
        let read = self
            .reader
            .read_buf(&mut buf)
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;
        if read == 0 {
            return Ok(None);
        }
        Ok(Some(buf.freeze()))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

struct FileMissHandler {
    file: Option<tokio::fs::File>,
    encoder: Option<async_compression::tokio::write::ZstdEncoder<tokio::fs::File>>,
    written: usize,
    final_path: PathBuf,
    temp_path: PathBuf,
    hash: String,
    key_str: String,
    ttl: u64,
    status: u16,
    headers: Vec<(String, String)>,
    compressed: bool,
    shard_id: Option<String>,
    relative_path: String,
    stale_while_revalidate_secs: u64,
    committed: bool,
    _cache_write_permit: StaticAdmissionPermit,
}

struct PartialMissHandler {
    cache_key: String,
    capture: crate::cache::partial::PartialCapture,
    writer: Option<crate::cache::partial::PartialWriter>,
    location: PartialStorageLocation,
    disabled: bool,
    _cache_write_permit: StaticAdmissionPermit,
}

struct NoopMissHandler;

#[async_trait]
impl HandleMiss for NoopMissHandler {
    async fn write_body(&mut self, _data: bytes::Bytes, _eof: bool) -> Result<()> {
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        Ok(MissFinishType::Created(0))
    }
}

#[async_trait]
impl HandleMiss for PartialMissHandler {
    async fn write_body(&mut self, data: bytes::Bytes, _eof: bool) -> Result<()> {
        if self.disabled || data.is_empty() {
            return Ok(());
        }
        if self.writer.is_none() {
            self.writer = crate::cache::partial::open_writer(
                &self.cache_key,
                self.capture.clone(),
                &self.location.roots,
                self.location.write_root.clone(),
            )
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;
            if self.writer.is_none() {
                self.disabled = true;
                return Ok(());
            }
        }
        if let Some(writer) = &mut self.writer
            && !writer
                .write(&data)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?
        {
            self.disabled = true;
        }
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        let PartialMissHandler {
            cache_key: _,
            capture,
            writer,
            location,
            disabled,
            _cache_write_permit: _,
        } = *self;
        if disabled {
            return Err(Error::new(ErrorType::InternalError));
        }
        let Some(writer) = writer else {
            return Err(Error::new(ErrorType::InternalError));
        };
        let written = capture.end - capture.start + 1;
        if !writer
            .finish(&location.roots, location.write_root.clone())
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?
        {
            return Err(Error::new(ErrorType::InternalError));
        }
        Ok(MissFinishType::Created(written as usize))
    }
}

#[async_trait]
impl HandleMiss for FileMissHandler {
    async fn write_body(&mut self, data: bytes::Bytes, _eof: bool) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        // Initialize encoder only if policy says so
        if self.compressed && self.encoder.is_none() {
            if let Some(f) = self.file.take() {
                let enc = async_compression::tokio::write::ZstdEncoder::new(f);
                self.encoder = Some(enc);
            }
        }

        let len = data.len();
        if let Some(enc) = &mut self.encoder {
            tokio::io::AsyncWriteExt::write_all(enc, &data)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?;
        } else if let Some(f) = &mut self.file {
            tokio::io::AsyncWriteExt::write_all(f, &data)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?;
        } else {
            return Err(Error::new(ErrorType::InternalError));
        }

        self.written += len;
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<MissFinishType> {
        let written = self.written;

        if let Some(mut enc) = self.encoder.take() {
            tokio::io::AsyncWriteExt::shutdown(&mut enc)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?;
        } else if let Some(mut f) = self.file.take() {
            tokio::io::AsyncWriteExt::flush(&mut f)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?;
        }

        // Use non-blocking async rename
        if let Err(_e) = tokio::fs::rename(&self.temp_path, &self.final_path).await {
            // Concurrent cache writes might cause rename failures if another thread already finished.
            // As long as the file exists, we consider it a success.
            let path_is_file = tokio::task::spawn_blocking({
                let p = self.final_path.clone();
                move || p.is_file()
            })
            .await
            .unwrap_or(false);

            if !path_is_file {
                return Err(Error::new(ErrorType::InternalError));
            }
            // Another writer already published this key. Do not let the losing
            // writer overwrite metadata for a file it did not publish.
            let _ = tokio::fs::remove_file(&self.temp_path).await;
            self.committed = true;
            return Ok(MissFinishType::Created(0));
        }

        let now = crate::utils::time::now_timestamp();
        let expires = now + self.ttl as i64;
        crate::metrics::storage::STORAGE.upsert_cache_meta_absolute_async(
            crate::metrics::storage::CacheMetaUpsert {
                hash: &self.hash,
                cache_key: &self.key_str,
                size: written as u64,
                expires,
                access_time: now,
                access_count: 1,
                status: self.status,
                headers: &self.headers,
                compressed: self.compressed,
                shard_id: self.shard_id.as_deref(),
                relative_path: Some(&self.relative_path),
                event_version: None,
                updated_at: Some(now),
                stale_while_revalidate_secs: self.stale_while_revalidate_secs,
                created_at: now,
            },
        )
        .await;
        negative_cache_remove(&self.key_str);
        index_surrogate_keys(&self.headers, &self.hash);
        crate::cluster::metadata::emit_upsert(crate::cluster::metadata::CacheMetaUpsertEvent {
            hash: &self.hash,
            cache_key: &self.key_str,
            shard_id: self.shard_id.as_deref(),
            relative_path: Some(&self.relative_path),
            size: written as u64,
            expires,
            status: self.status,
            headers: &self.headers,
            compressed: self.compressed,
            stale_while_revalidate_secs: self.stale_while_revalidate_secs,
        });

        self.committed = true;
        Ok(MissFinishType::Created(written))
    }
}

impl Drop for FileMissHandler {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        drop(self.encoder.take());
        drop(self.file.take());
        let temp_path = self.temp_path.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = tokio::fs::remove_file(temp_path).await;
            });
        } else {
            let _ = std::fs::remove_file(temp_path);
        }
    }
}

/// Reverse index: Surrogate-Key tag → set of cache-entry hashes.
/// Capacity is bounded by the number of in-memory cache entries at the time
/// a new tag is inserted; entries for evicted keys are pruned on purge.
static SURROGATE_KEY_INDEX: Lazy<DashMap<String, dashmap::DashSet<String>>> =
    Lazy::new(DashMap::new);
static SURROGATE_SATURATED_TAGS: Lazy<DashMap<String, ()>> = Lazy::new(DashMap::new);
static SURROGATE_MEMBERSHIPS: AtomicU64 = AtomicU64::new(0);
static SURROGATE_DEGRADED_PURGE: AtomicU64 = AtomicU64::new(0);
const SURROGATE_INDEX_MAX_TAGS_NORMAL: usize = 1_000_000;
const SURROGATE_INDEX_MAX_TAGS_PRESSURE: usize = 131_072;
const SURROGATE_INDEX_MAX_MEMBERSHIPS: usize = 4_000_000;
const SURROGATE_INDEX_MAX_MEMBERS_PER_TAG: usize = 16_384;
const SURROGATE_TAG_MAX_BYTES: usize = 256;
const SURROGATE_TAG_ENTRY_OVERHEAD: u64 = 96;


fn surrogate_index_capacity() -> usize {
    if MEMORY_GOVERNOR.is_memory_pressure_high() {
        SURROGATE_INDEX_MAX_TAGS_PRESSURE
    } else {
        SURROGATE_INDEX_MAX_TAGS_NORMAL
    }
}

pub(crate) fn index_surrogate_keys(headers: &[(String, String)], hash: &str) {
    let tags = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("surrogate-key")).map(|(_, v)| v.as_str()).unwrap_or("");
    for tag in tags.split_whitespace().take(64) {
        if tag.is_empty() || tag.len() > SURROGATE_TAG_MAX_BYTES { continue; }
        if SURROGATE_SATURATED_TAGS.contains_key(tag) { continue; }
        if !SURROGATE_KEY_INDEX.contains_key(tag)
            && SURROGATE_KEY_INDEX.len() >= surrogate_index_capacity() {
            mark_surrogate_tag_saturated(tag);
            continue;
        }
        let entry = SURROGATE_KEY_INDEX.entry(tag.to_string()).or_default();
        if entry.len() >= SURROGATE_INDEX_MAX_MEMBERS_PER_TAG
            || SURROGATE_MEMBERSHIPS.load(Ordering::Relaxed) as usize >= SURROGATE_INDEX_MAX_MEMBERSHIPS
        {
            mark_surrogate_tag_saturated(tag);
            continue;
        }
        if entry.insert(hash.to_string()) {
            SURROGATE_MEMBERSHIPS.fetch_add(1, Ordering::Relaxed);
            let owner = format!("{tag}\0{hash}");
            let bytes = SURROGATE_TAG_ENTRY_OVERHEAD + tag.len() as u64 + hash.len() as u64;
            let _ = MEMORY_GOVERNOR.resident_memory_replace_owned(crate::memory_governor::ResidentCategory::SurrogateIndex, &owner, bytes);
        }
    }
}

fn mark_surrogate_tag_saturated(tag: &str) {
    SURROGATE_SATURATED_TAGS.insert(tag.to_string(), ());
}

pub(crate) fn remove_hash_from_surrogate_index(hash: &str) {
    SURROGATE_KEY_INDEX.retain(|tag, set| {
        if set.remove(hash) {
            SURROGATE_MEMBERSHIPS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_sub(1))
            }).ok();
            let owner = format!("{tag}\0{hash}");
            let _ = MEMORY_GOVERNOR.resident_memory_replace_owned(crate::memory_governor::ResidentCategory::SurrogateIndex, &owner, 0);
        }
        !set.is_empty()
    });
}

pub(crate) fn meta_headers_contain_surrogate_tag(headers: &[(String, String)], tag: &str) -> bool {
    surrogate_headers_contain_tag(headers, tag)
}

fn surrogate_headers_contain_tag(headers: &[(String, String)], tag: &str) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("surrogate-key")
            && value.split_whitespace().any(|candidate| candidate == tag)
    })
}

// ═══════════════════════════════════════════════════════════
// TinyUfoL1: Production-grade lock-free L1 cache (TinyUFO)
// ═══════════════════════════════════════════════════════════

use bloom::{ASMS, BloomFilter};
use pingora_memory_cache::{CacheStatus, MemoryCache, MemoryCacheStats};

/// Entry stored in TinyUfoL1 (wrapper around MemoryCache<TinyUfo>)
#[derive(Clone)]
pub(crate) struct TinyUfoL1Entry {
    data: bytes::Bytes,
    response_header: ResponseHeader,
    fresh_until: i64,
    created_at: i64,
}

/// Lock-free L1 cache backed by TinyUFO (S3-FIFO + TinyLFU admission).
/// Replaces the old FAST_L1 (DashMap + BinaryHeap).
pub(crate) struct TinyUfoL1 {
    inner: RwLock<Arc<MemoryCache<String, TinyUfoL1Entry>>>,
    auto_budget: AtomicBool,
    max_bytes: AtomicU64,
    current_weight: AtomicU64,
}

impl TinyUfoL1 {
    fn new(max_bytes: u64) -> Self {
        let auto_budget = max_bytes == 0;
        let resolved_max_bytes = if auto_budget {
            HybridStorage::compute_memory_budget()
        } else {
            max_bytes
        };
        let cache = Arc::new(Self::build_cache(resolved_max_bytes));
        Self {
            inner: RwLock::new(cache),
            auto_budget: AtomicBool::new(auto_budget),
            max_bytes: AtomicU64::new(resolved_max_bytes),
            current_weight: AtomicU64::new(0),
        }
    }

    fn build_cache(max_bytes: u64) -> MemoryCache<String, TinyUfoL1Entry> {
        let capacity = Self::weight_limit_for_bytes(max_bytes);
        MemoryCache::new(capacity)
    }

    fn weight_limit_for_bytes(max_bytes: u64) -> usize {
        (max_bytes / 1024).max(1).min(usize::MAX as u64) as usize
    }

    fn read_inner(&self) -> Arc<MemoryCache<String, TinyUfoL1Entry>> {
        self.inner.read().expect("TinyUfoL1 lock poisoned").clone()
    }

    fn get(&self, key: &str) -> Option<TinyUfoL1Entry> {
        let inner = self.read_inner();
        let (value, status) = inner.get(key);
        if status == CacheStatus::Hit {
            value
        } else {
            None
        }
    }

    #[allow(dead_code)]
    fn get_stale(&self, key: &str) -> Option<(TinyUfoL1Entry, CacheStatus)> {
        let inner = self.read_inner();
        let (value, status) = inner.get_stale(key);
        value.map(|v| (v, status))
    }

    fn put(&self, key: &str, entry: TinyUfoL1Entry, ttl: std::time::Duration) {
        let weight = (entry.data.len().div_ceil(1024)).clamp(1, u16::MAX as usize) as u16;
        let inner = self.read_inner();
        inner.put(key, entry, Some(ttl), weight);
        self.refresh_stats(&inner);
    }

    fn remove(&self, key: &str) {
        let inner = self.read_inner();
        inner.remove(key);
        self.refresh_stats(&inner);
    }

    fn set_max_bytes(&self, bytes: u64) {
        let auto_budget = bytes == 0;
        self.auto_budget.store(auto_budget, Ordering::Relaxed);
        let resolved = if auto_budget {
            crate::memory_governor::MEMORY_GOVERNOR.cache_budget_bytes()
        } else {
            bytes
        };
        let old = self.max_bytes.swap(resolved, Ordering::Relaxed);
        if !Self::should_rebuild_for_budget_change(old, resolved) {
            return;
        }
        let new_cache = Arc::new(Self::build_cache(resolved));
        self.current_weight.store(0, Ordering::Relaxed);
        let mut guard = self.inner.write().expect("TinyUfoL1 lock poisoned");
        *guard = new_cache;
    }

    fn refresh_auto_budget(&self) {
        if !self.auto_budget.load(Ordering::Relaxed) {
            return;
        }
        self.set_max_bytes(0);
    }

    fn stats(&self) -> (usize, u64) {
        let inner = self.read_inner();
        self.refresh_stats(&inner);
        let stats = inner.stats();
        let bytes = (stats.current_weight as u64).saturating_mul(1024);
        let count = stats.current_items;
        (count, bytes)
    }

    fn max_bytes(&self) -> u64 {
        self.max_bytes.load(Ordering::Relaxed)
    }

    fn refresh_stats(&self, inner: &MemoryCache<String, TinyUfoL1Entry>) {
        let MemoryCacheStats { current_weight, .. } = inner.stats();
        self.current_weight.store(
            current_weight.min(u64::MAX as usize) as u64,
            Ordering::Relaxed,
        );
    }

    fn should_rebuild_for_budget_change(old: u64, new: u64) -> bool {
        if Self::weight_limit_for_bytes(old) == Self::weight_limit_for_bytes(new) {
            return false;
        }
        let delta = old.abs_diff(new);
        if new < old && MEMORY_GOVERNOR.is_memory_pressure_high() {
            return true;
        }
        let (min_delta_bytes, min_delta_pct) = if new < old {
            (
                L1_RESIZE_SHRINK_MIN_DELTA_BYTES,
                L1_RESIZE_SHRINK_MIN_DELTA_PCT,
            )
        } else {
            (L1_RESIZE_GROW_MIN_DELTA_BYTES, L1_RESIZE_GROW_MIN_DELTA_PCT)
        };
        delta >= min_delta_bytes && delta.saturating_mul(100) >= old.max(1) * min_delta_pct
    }
}

// ═══════════════════════════════════════════════════════════
// Bloom Filter + Negative Cache (Anti-Penetration)
// ═══════════════════════════════════════════════════════════

/// Adaptive bloom filter with auto-scaling for billion-scale caches.
/// Uses sharded layered BloomFilters so the filter can grow without a full rebuild
/// while keeping read/write contention bounded.
/// `current_size` is an approximate admission volume, not an exact distinct-key count.
struct AdaptiveBloomFilter {
    shards: Vec<BloomShard>,
    total_capacity: AtomicU64,
    current_size: AtomicU64,
    estimated_bytes: AtomicU64,
}

struct BloomShard {
    layers: parking_lot::RwLock<Vec<BloomLayer>>,
}

struct BloomLayer {
    filter: BloomFilter,
    capacity: u64,
    count: u64,
}

impl BloomShard {
    fn new(initial_capacity: u32) -> Self {
        Self {
            layers: parking_lot::RwLock::new(vec![AdaptiveBloomFilter::build_layer(
                initial_capacity,
            )]),
        }
    }
}

impl AdaptiveBloomFilter {
    fn new(initial_capacity: u32, shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        let per_shard_capacity = ((initial_capacity as usize).div_ceil(shard_count)) as u32;
        let shards = (0..shard_count)
            .map(|_| BloomShard::new(per_shard_capacity.max(1)))
            .collect::<Vec<_>>();

        Self {
            shards,
            total_capacity: AtomicU64::new(per_shard_capacity as u64 * shard_count as u64),
            current_size: AtomicU64::new(0),
            estimated_bytes: AtomicU64::new(
                Self::estimated_layer_bytes(per_shard_capacity as u64)
                    .saturating_mul(shard_count as u64),
            ),
        }
    }

    fn build_layer(expected_items: u32) -> BloomLayer {
        let capacity = expected_items.max(1);
        BloomLayer {
            filter: BloomFilter::with_rate(0.01, capacity),
            capacity: capacity as u64,
            count: 0,
        }
    }

    fn next_layer_capacity(&self, current: u64) -> u32 {
        let next = current.saturating_mul(2).max(1);
        next.min(u32::MAX as u64) as u32
    }

    fn estimated_layer_bytes(capacity: u64) -> u64 {
        capacity
            .saturating_mul(BLOOM_BITS_PER_ENTRY_ESTIMATE)
            .div_ceil(8)
            .saturating_add(BLOOM_LAYER_OVERHEAD_BYTES)
    }

    fn can_add_layer(&self, capacity: u64, remaining_budget: u64) -> bool {
        self.estimated_bytes
            .load(Ordering::Relaxed)
            .saturating_add(Self::estimated_layer_bytes(capacity))
            <= remaining_budget
    }

    fn shard_index(&self, key: &str) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = ahash::AHasher::default();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }

    fn contains(&self, key: &str) -> bool {
        let idx = self.shard_index(key);
        let layers = self.shards[idx].layers.read();
        layers.iter().any(|layer| layer.filter.contains(&key))
    }

    fn insert(&self, key: &str) {
        let idx = self.shard_index(key);
        let mut layers = self.shards[idx].layers.write();
        let mut next_capacity = None;
        if let Some(layer) = layers.last_mut() {
            let _ = layer.filter.insert(&key);
            layer.count = layer.count.saturating_add(1);
            self.current_size.fetch_add(1, Ordering::Relaxed);
            if layer.count >= layer.capacity {
                let candidate = self.next_layer_capacity(layer.capacity);
                if self.can_add_layer(candidate as u64, crate::memory_governor::MEMORY_GOVERNOR.bloom_budget_bytes()) {
                    next_capacity = Some(candidate);
                }
            }
        }
        if let Some(next_capacity) = next_capacity {
            layers.push(Self::build_layer(next_capacity));
            self.total_capacity
                .fetch_add(next_capacity as u64, Ordering::Relaxed);
            self.estimated_bytes.fetch_add(
                Self::estimated_layer_bytes(next_capacity as u64),
                Ordering::Relaxed,
            );
        }
    }

    fn remove(&self, key: &str) {
        let _ = key;
    }

    fn utilization(&self) -> f64 {
        let size = self.current_size.load(Ordering::Relaxed) as f64;
        let capacity = self.total_capacity.load(Ordering::Relaxed) as f64;
        if capacity > 0.0 { size / capacity } else { 0.0 }
    }

    fn stats(&self) -> (u64, u64, f64, u64) {
        let size = self.current_size.load(Ordering::Relaxed);
        let capacity = self.total_capacity.load(Ordering::Relaxed);
        let util = self.utilization();
        let estimated_bytes = self.estimated_bytes.load(Ordering::Relaxed);
        (size, capacity, util, estimated_bytes)
    }
}

/// Dual-generation Bloom: inserts go to the live generation; contains also
/// checks a retiring generation until it is dropped after rotation.
struct DualGenerationBloom {
    live: ArcSwap<AdaptiveBloomFilter>,
    stale: parking_lot::Mutex<Option<Arc<AdaptiveBloomFilter>>>,
    generation: AtomicU64,
}

impl DualGenerationBloom {
    fn new(initial_capacity: u32, shard_count: usize) -> Self {
        let live = AdaptiveBloomFilter::new(initial_capacity, shard_count);
        let estimated = live.estimated_bytes.load(Ordering::Relaxed);
        let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
            crate::memory_governor::ResidentCategory::BloomFilter,
            "cache-bloom",
            estimated,
        );
        Self {
            live: ArcSwap::from_pointee(live),
            stale: parking_lot::Mutex::new(None),
            generation: AtomicU64::new(1),
        }
    }

    fn contains(&self, key: &str) -> bool {
        if self.live.load().contains(key) {
            return true;
        }
        self.stale
            .lock()
            .as_ref()
            .is_some_and(|stale| stale.contains(key))
    }

    fn insert(&self, key: &str) {
        let live = self.live.load();
        let before = live.estimated_bytes.load(Ordering::Relaxed);
        live.insert(key);
        if live.estimated_bytes.load(Ordering::Relaxed) != before {
            self.sync_bloom_charge();
        }
    }

    fn stats(&self) -> (u64, u64, f64, u64, u64) {
        let live = self.live.load();
        let (size, capacity, util, estimated_bytes) = live.stats();
        let stale_bytes = self
            .stale
            .lock()
            .as_ref()
            .map(|stale| stale.estimated_bytes.load(Ordering::Relaxed))
            .unwrap_or(0);
        (
            size,
            capacity,
            util,
            estimated_bytes.saturating_add(stale_bytes),
            self.generation.load(Ordering::Relaxed),
        )
    }

    fn sync_bloom_charge(&self) {
        let (_, _, _, estimated, _) = self.stats();
        let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
            crate::memory_governor::ResidentCategory::BloomFilter,
            "cache-bloom",
            estimated,
        );
    }

    fn rotate_from_cache_meta(&self) {
        let Some(_permit) = crate::memory_governor::MEMORY_GOVERNOR
            .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork)
        else {
            return;
        };
        let replacement = AdaptiveBloomFilter::new(1_000_000, 64);
        let now = crate::utils::time::now_timestamp();
        crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
            if meta.expires > now {
                replacement.insert(&meta.cache_key);
            }
        });
        let previous = self.live.swap(Arc::new(replacement));
        {
            let mut stale = self.stale.lock();
            *stale = Some(previous);
        }
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.sync_bloom_charge();
    }

    fn drop_stale(&self) {
        *self.stale.lock() = None;
        self.sync_bloom_charge();
    }
}

static CACHE_BLOOM: Lazy<DualGenerationBloom> =
    Lazy::new(|| DualGenerationBloom::new(1_000_000, 64));

fn bloom_may_exist(key: &str) -> bool {
    CACHE_BLOOM.contains(key)
}

fn bloom_insert(key: &str) {
    CACHE_BLOOM.insert(key);
}

fn bloom_remove(key: &str) {
    let _ = key;
}

fn bloom_stats() -> (u64, u64, f64, u64) {
    let (size, capacity, util, estimated, _) = CACHE_BLOOM.stats();
    (size, capacity, util, estimated)
}

fn bloom_generation() -> u64 {
    CACHE_BLOOM.generation.load(Ordering::Relaxed)
}

fn warm_bloom_from_cache_meta() {
    let Some(_permit) = crate::memory_governor::MEMORY_GOVERNOR
        .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork)
    else {
        tracing::warn!("CACHE_BLOOM: skipping warmup because background memory admission is full");
        return;
    };
    let now = crate::utils::time::now_timestamp();
    crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
        if meta.expires > now {
            CACHE_BLOOM.insert(&meta.cache_key);
        }
    });
}

/// Negative cache: tracks keys confirmed to not exist in the local cache set.
/// This mainly absorbs stale Bloom positives after purge/expiry.
static NEGATIVE_CACHE: Lazy<DashMap<String, i64>> = Lazy::new(DashMap::new);
const NEGATIVE_CACHE_TTL_SECS: i64 = 60;
const NEGATIVE_CACHE_MIN_ENTRIES: usize = 1_000_000;
const NEGATIVE_CACHE_MAX_ENTRIES: usize = 16_000_000;

fn negative_cache_capacity_limit() -> usize {
    let (bloom_count, _, _, _) = bloom_stats();
    let adaptive = (bloom_count / 64).max(NEGATIVE_CACHE_MIN_ENTRIES as u64);
    let governor_limit = crate::memory_governor::MEMORY_GOVERNOR.negative_cache_limit() as u64;
    adaptive
        .min(NEGATIVE_CACHE_MAX_ENTRIES as u64)
        .max(NEGATIVE_CACHE_MIN_ENTRIES as u64)
        .min(governor_limit)
        .max(1) as usize
}

fn negative_cache_check(key: &str, now: i64) -> bool {
    if let Some(entry) = NEGATIVE_CACHE.get(key) {
        if *entry > now {
            return true;
        }
    }
    NEGATIVE_CACHE.remove(key);
    let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(crate::memory_governor::ResidentCategory::NegativeCache, key, 0);
    false
}

fn negative_cache_insert(key: &str, now: i64) {
    negative_cache_insert_with_capacity(key, now, negative_cache_capacity_limit());
}

fn negative_cache_insert_with_capacity(key: &str, now: i64, capacity: usize) {
    if crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high() {
        return;
    }
    let capacity = capacity.max(1);
    let current_len = NEGATIVE_CACHE.len();
    if current_len >= capacity {
        negative_cache_cleanup(now);
        if NEGATIVE_CACHE.len() >= capacity {
            return;
        }
    }
    NEGATIVE_CACHE.insert(key.to_string(), now + NEGATIVE_CACHE_TTL_SECS);
    let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(crate::memory_governor::ResidentCategory::NegativeCache, key, 160 + key.len() as u64);
}

fn negative_cache_remove(key: &str) {
    NEGATIVE_CACHE.remove(key);
    let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(crate::memory_governor::ResidentCategory::NegativeCache, key, 0);
}

fn negative_cache_stats() -> (usize, usize) {
    (NEGATIVE_CACHE.len(), negative_cache_capacity_limit())
}

fn negative_cache_cleanup(now: i64) {
    NEGATIVE_CACHE.retain(|_, &mut expires| expires > now);
}

pub(crate) fn warm_admission_filters_from_cache_meta() {
    warm_bloom_from_cache_meta();
    let (size, capacity, util, estimated_bytes) = bloom_stats();
    tracing::info!(
        "CACHE_BLOOM: warmed size={} capacity={} utilization={:.3} estimated_bytes={} generation={}",
        size,
        capacity,
        util,
        estimated_bytes,
        bloom_generation()
    );
}

pub(crate) fn start_bloom_rotation_task() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15 * 60)).await;
            let (_, _, util, estimated, _) = CACHE_BLOOM.stats();
            let budget = crate::memory_governor::MEMORY_GOVERNOR.bloom_budget_bytes();
            if util > 0.6 || estimated.saturating_mul(2) > budget.max(1) {
                if let Err(err) = tokio::task::spawn_blocking(|| CACHE_BLOOM.rotate_from_cache_meta()).await {
                    warn!(error = %err, "CACHE_BLOOM: rotation task failed");
                    continue;
                }
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                CACHE_BLOOM.drop_stale();
            }
        }
    });
}

pub(crate) fn on_cache_meta_upsert(meta: &crate::metrics::storage::CacheMetaEntry) {
    if meta.expires > crate::utils::time::now_timestamp() {
        bloom_insert(&meta.cache_key);
    }
    negative_cache_remove(&meta.cache_key);
}

pub(crate) fn on_cache_meta_delete(cache_key: &str) {
    negative_cache_insert(cache_key, crate::utils::time::now_timestamp());
}

const POLICY_FILE: u8 = 0;
const POLICY_MEMORY: u8 = 1;

pub struct HybridStorage {
    pub(crate) l1: Arc<TinyUfoL1>,
    pub l2: &'static FileStorage,
    pub max_disk_bytes: std::sync::atomic::AtomicU64,
    pub min_free_bytes: std::sync::atomic::AtomicU64,
    pub policy_type: AtomicU8,
}

pub struct CacheRuntimeStats {
    pub policy_type: String,
    pub memory_count: usize,
    pub memory_bytes: u64,
    pub disk_count: usize,
    pub disk_bytes: u64,
    pub max_disk_bytes: u64,
    pub min_free_bytes: u64,
    pub bloom_count: u64,
    pub bloom_capacity: u64,
    pub bloom_utilization: f64,
    pub bloom_estimated_bytes: u64,
    pub bloom_budget_bytes: u64,
    pub negative_cache_count: usize,
    pub negative_cache_capacity: usize,
    pub memory_budget_bytes: u64,
    pub memory_pressure_high: bool,
    pub file_cache_enabled: bool,
    pub sendfile_enabled: bool,
    pub disk_hit_chunk_bytes: usize,
}

impl HybridStorage {
    pub fn new(_max_mem_bytes: usize, disk_root: impl Into<PathBuf>) -> Self {
        let l1_budget = if _max_mem_bytes == 0 {
            0
        } else {
            _max_mem_bytes.min(u64::MAX as usize) as u64
        };
        let l1 = TinyUfoL1::new(l1_budget);

        Self {
            l1: Arc::new(l1),
            l2: Box::leak(Box::new(FileStorage::new(disk_root))),
            max_disk_bytes: std::sync::atomic::AtomicU64::new(10 * 1024 * 1024 * 1024),
            min_free_bytes: std::sync::atomic::AtomicU64::new(2 * 1024 * 1024 * 1024),
            policy_type: AtomicU8::new(POLICY_FILE),
        }
    }

    pub fn partial_location_for_key_str(&self, key: &str) -> PartialStorageLocation {
        self.l2.partial_location_for_key_str(key)
    }

    fn compute_memory_budget() -> u64 {
        crate::memory_governor::MEMORY_GOVERNOR.cache_budget_bytes()
    }

    #[doc(hidden)]
    pub fn bench_fast_l1_insert(
        key: &str,
        body: bytes::Bytes,
        meta: &CacheMeta,
        ttl_secs: u64,
    ) -> bool {
        let now = crate::utils::time::now_timestamp();
        let entry = TinyUfoL1Entry {
            data: body,
            response_header: meta.response_header().clone(),
            fresh_until: now + ttl_secs as i64,
            created_at: now,
        };
        crate::cache_manager::CACHE.storage.l1.put(
            key,
            entry,
            std::time::Duration::from_secs(ttl_secs.max(1)),
        );
        true
    }

    #[doc(hidden)]
    pub fn bench_fast_l1_remove(key: &str) {
        crate::cache_manager::CACHE.storage.l1.remove(key);
    }

    #[doc(hidden)]
    pub fn bench_compute_memory_budget() -> u64 {
        Self::compute_memory_budget()
    }

    pub fn apply_cluster_cache_config(
        &self,
        config: &crate::runtime_mode::ClusterCacheConfig,
    ) -> anyhow::Result<()> {
        if !config.shared_max_bytes.trim().is_empty() {
            let bytes = parse_runtime_size_bytes(&config.shared_max_bytes)?;
            if bytes > 0 {
                self.max_disk_bytes.store(bytes, Ordering::Relaxed);
            }
        }

        if !config.min_free_bytes.trim().is_empty() {
            let bytes = parse_runtime_size_bytes(&config.min_free_bytes)?;
            self.min_free_bytes.store(bytes, Ordering::Relaxed);
        }

        self.l1.set_max_bytes(config.max_fast_l1_bytes);

        let shards = config
            .shards
            .iter()
            .map(|shard| CacheShard {
                id: shard.id.clone(),
                root: shard.path.clone(),
                weight: shard.weight,
            })
            .collect();
        self.l2.update_shards(shards, Vec::new(), true, false);

        info!(
            "RPC_CACHE: Applied local RKE2 cache config: shards={}, sharedMaxBytes={}, minFreeBytes={}, maxFastL1Bytes={}",
            config.shards.len(),
            config.shared_max_bytes,
            config.min_free_bytes,
            config.max_fast_l1_bytes
        );
        Ok(())
    }

    pub async fn apply_policy(&self, policy: &crate::config_models::HTTPCachePolicy) {
        if crate::runtime_mode::RuntimeConfig::current_is_rke2() {
            self.policy_type.store(POLICY_FILE, Ordering::Relaxed);
            if !CLUSTER_STORAGE_POLICY_SKIP_LOGGED.swap(true, Ordering::Relaxed) {
                info!(
                    "RPC_CACHE: RKE2 runtime mode ignores control-plane cache storage path/capacity settings; local runtime cache config is authoritative."
                );
            }
            return;
        }

        let val = if policy.r#type == "memory" {
            POLICY_MEMORY
        } else {
            POLICY_FILE
        };
        self.policy_type.store(val, Ordering::Relaxed);

        if let Some(capacity) = &policy.capacity {
            let bytes = crate::config_models::SizeCapacity::from_json(capacity).to_bytes();
            if bytes > 0 {
                self.max_disk_bytes
                    .store(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }

        if let Some(options) = &policy.options {
            // Memory capacity for L1: 0 = auto-detect, explicit value = use directly
            if let Some(mem) = options
                .get("memoryCapacity")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
            {
                self.l1.set_max_bytes(mem);
            }

            let min_free_setting = if let Some(min_free) = options.get("minFreeSpace") {
                crate::config_models::SizeCapacity::from_json(min_free).to_bytes()
            } else {
                0
            };

            let mut final_min_free = min_free_setting as u64;
            if final_min_free == 0 {
                let main_path = options
                    .get("dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| crate::paths::NodePaths::current().cache_dir());

                let disks = sysinfo::Disks::new_with_refreshed_list();
                let disk_size = disks
                    .iter()
                    .find(|d| main_path.starts_with(d.mount_point()))
                    .map(|d| d.total_space())
                    .unwrap_or(100 * 1024 * 1024 * 1024);

                let auto_min = (disk_size / 20)
                    .max(1024 * 1024 * 1024)
                    .min(10 * 1024 * 1024 * 1024);

                info!(
                    "RPC_CACHE: Using auto-calculated min free space: {} bytes",
                    auto_min
                );
                final_min_free = auto_min;
            } else {
                info!(
                    "RPC_CACHE: Using policy specified min free space: {} bytes",
                    final_min_free
                );
            }
            self.min_free_bytes
                .store(final_min_free, std::sync::atomic::Ordering::Relaxed);

            let main_dir = options
                .get("dir")
                .and_then(|v| v.as_str())
                .map(PathBuf::from);
            let sub_dirs = options
                .get("subDirs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(PathBuf::from)
                        .collect::<Vec<_>>()
                });

            let enable_sendfile = options
                .get("enableSendfile")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let enable_file_cache = options
                .get("openFileCache")
                .and_then(|v| v.get("isOn"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false); // Default to false for 10M+ files safety unless explicitly ON.

            if let Some(main) = main_dir {
                info!(
                    "RPC_CACHE: Updating cache configuration (Sendfile: {}, HandleCache: {})",
                    enable_sendfile, enable_file_cache
                );
                self.l2.update_config(
                    main,
                    sub_dirs.unwrap_or_default(),
                    enable_sendfile,
                    enable_file_cache,
                );
            }
        }
    }

    fn cache_key_variants(key: &str) -> Vec<String> {
        let mut variants = Vec::with_capacity(12);
        variants.push(key.to_string());

        let suffixes = [
            "@br",
            "@gzip",
            "@webp",
            "@webp@br",
            "@webp@gzip",
            "@method:HEAD",
            "@method:HEAD@br",
            "@method:HEAD@gzip",
            "@method:HEAD@webp",
            "@method:HEAD@webp@br",
            "@method:HEAD@webp@gzip",
        ];
        if !suffixes.iter().any(|suffix| key.ends_with(suffix)) {
            variants.extend(suffixes.iter().map(|suffix| format!("{key}{suffix}")));
        }

        variants
    }

    async fn purge_exact_stored_key(&'static self, key: &str) -> bool {
        let location = self.l2.partial_location_for_key_str(key);
        crate::cache::partial::purge(key, &location.roots).await;
        let hash = format!("{:x}", md5_legacy::compute(key));
        let inner = self.l2.inner.load();
        remove_cache_file_from_roots(&inner, &hash).await;
        crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
        remove_hash_from_surrogate_index(&hash);
        self.l1.remove(key);
        bloom_remove(key);
        negative_cache_remove(key);

        true
    }

    pub async fn purge_by_key(&'static self, key: &str) -> bool {
        let mut variants = Self::cache_key_variants(key);
        let variant_prefix = format!("{}@", key);
        crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
            if meta.cache_key == key || meta.cache_key.starts_with(&variant_prefix) {
                variants.push(meta.cache_key.clone());
            }
        });
        variants.sort_unstable();
        variants.dedup();

        let deleted_count = variants.len();
        for variant in variants {
            self.purge_exact_stored_key(&variant).await;
        }
        info!(
            "RPC_CACHE: Purged {} variants for key: {}",
            deleted_count, key
        );
        true
    }

    pub async fn purge_by_tag(&'static self, tag: &str) -> bool {
        let location = self.l2.partial_location_for_key_str(tag);
        let partial_deleted = crate::cache::partial::purge_by_tag(tag, &location.roots).await;
        let hashes: Vec<String> = SURROGATE_KEY_INDEX
            .get(tag)
            .map(|set| set.iter().take(SURROGATE_INDEX_MAX_MEMBERS_PER_TAG).map(|h| h.clone()).collect())
            .unwrap_or_default();
        let mut keys_to_purge = Vec::new();
        for hash in &hashes {
            if let Some(meta) = crate::metrics::storage::get_cache_meta_memory(hash) {
                keys_to_purge.push(meta.cache_key.clone());
            }
        }
        let saturated = SURROGATE_SATURATED_TAGS.contains_key(tag);
        if hashes.is_empty() || saturated {
            let scanned = crate::metrics::storage::STORAGE.collect_cache_keys_by_surrogate_tag(tag, 512);
            if !scanned.is_empty() {
                SURROGATE_DEGRADED_PURGE.fetch_add(1, Ordering::Relaxed);
                warn!(
                    tag,
                    scanned = scanned.len(),
                    indexed = hashes.len(),
                    "RPC_CACHE: surrogate index saturated or incomplete; using bounded metadata scan"
                );
            }
            keys_to_purge.extend(scanned);
        }
        keys_to_purge.sort_unstable();
        keys_to_purge.dedup();
        if keys_to_purge.is_empty() {
            if partial_deleted > 0 {
                info!(
                    "RPC_CACHE: Purged {} partial entries by surrogate tag: {}",
                    partial_deleted, tag
                );
            }
            SURROGATE_SATURATED_TAGS.remove(tag);
            return true;
        }
        let deleted_count = keys_to_purge.len();
        for key in keys_to_purge {
            self.purge_exact_stored_key(&key).await;
        }
        SURROGATE_KEY_INDEX.remove(tag);
        SURROGATE_SATURATED_TAGS.remove(tag);
        info!(
            "RPC_CACHE: Purged {} entries and {} partial entries by surrogate tag: {}",
            deleted_count, partial_deleted, tag
        );
        true
    }

    pub async fn purge_by_prefix(&'static self, prefix: &str) -> bool {
        let clean_prefix = prefix.trim_end_matches('*');
        if Self::is_dangerous_purge_prefix(clean_prefix) {
            tracing::warn!(
                "RPC_CACHE: Refusing dangerous prefix purge request: {:?}",
                prefix
            );
            return false;
        }
        let location = self.l2.partial_location_for_key_str(clean_prefix);
        let partial_deleted =
            crate::cache::partial::purge_prefix(clean_prefix, &location.roots).await;
        let mut to_delete = Vec::new();

        crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
            if !meta.cache_key.is_empty() && meta.cache_key.starts_with(clean_prefix) {
                to_delete.push(meta.cache_key.clone());
            }
        });

        let deleted_count = to_delete.len();
        for key in to_delete {
            self.purge_exact_stored_key(&key).await;
        }
        info!(
            "RPC_CACHE: Purged {} items and {} partial items matching prefix: {}",
            deleted_count, partial_deleted, prefix
        );
        true
    }

    fn is_dangerous_purge_prefix(prefix: &str) -> bool {
        let normalized = prefix.trim().trim_end_matches('*').trim();
        if normalized.is_empty()
            || normalized == "/"
            || normalized.eq_ignore_ascii_case("http://")
            || normalized.eq_ignore_ascii_case("https://")
        {
            return true;
        }

        let lower = normalized.to_ascii_lowercase();
        if let Some(after_scheme) = lower
            .strip_prefix("http://")
            .or_else(|| lower.strip_prefix("https://"))
        {
            return after_scheme.find('/').is_none_or(|index| index == 0);
        }

        false
    }

    pub async fn runtime_stats(&self) -> CacheRuntimeStats {
        let (memory_count, memory_bytes) = self.l1.stats();
        let (disk_count, disk_bytes) = crate::metrics::storage::STORAGE.cache_summary();
        let (bloom_count, bloom_capacity, bloom_utilization, bloom_estimated_bytes) = bloom_stats();
        let (negative_cache_count, negative_cache_capacity) = negative_cache_stats();
        CacheRuntimeStats {
            policy_type: if self.policy_type.load(Ordering::Relaxed) == POLICY_MEMORY {
                "memory".to_string()
            } else {
                "file".to_string()
            },
            memory_count,
            memory_bytes,
            disk_count,
            disk_bytes,
            max_disk_bytes: self
                .max_disk_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            min_free_bytes: self
                .min_free_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            bloom_count,
            bloom_capacity,
            bloom_utilization,
            bloom_estimated_bytes,
            bloom_budget_bytes: crate::memory_governor::MEMORY_GOVERNOR.bloom_budget_bytes(),
            negative_cache_count,
            negative_cache_capacity,
            memory_budget_bytes: self.l1.max_bytes(),
            memory_pressure_high: crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high(),
            file_cache_enabled: self.l2.enable_file_cache(),
            sendfile_enabled: self.l2.enable_sendfile(),
            disk_hit_chunk_bytes: self.l2.disk_hit_chunk_bytes(),
        }
    }
}

#[async_trait]
impl Storage for HybridStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let p_type = self.policy_type.load(Ordering::Relaxed);

        let k_str = key.primary_key_str().unwrap_or("unknown");
        let is_partial_key = crate::cache::partial::is_partial_cache_key(k_str);

        if is_partial_key {
            return self.l2.lookup(key, trace).await;
        }

        let now = crate::utils::time::now_timestamp();

        // Anti-penetration Layer 1: Bloom filter - reject keys never cached
        if !bloom_may_exist(k_str) {
            prof_record_bloom_reject();
            return Ok(None);
        }

        // Anti-penetration Layer 2: short-lived local absence cache for stale Bloom positives
        if negative_cache_check(k_str, now) {
            return Ok(None);
        }

        // Check TinyUfoL1 (lock-free L1 cache with S3-FIFO + TinyLFU)
        if let Some(entry) = self.l1.get(k_str) {
            if entry.fresh_until > now {
                let fresh_until_dur = std::time::Duration::from_secs(entry.fresh_until as u64);
                let created_at_dur = std::time::Duration::from_secs(entry.created_at as u64);
                let meta = CacheMeta::new(
                    std::time::UNIX_EPOCH + fresh_until_dur,
                    std::time::UNIX_EPOCH + created_at_dur,
                    0,
                    0,
                    entry.response_header.clone(),
                );
                prof_record_l1_hit();
                return Ok(Some((
                    meta,
                    Box::new(MemoryHitHandler {
                        data: entry.data.clone(),
                        offset: 0,
                        end: entry.data.len(),
                        _cache_read_permit: None,
                    }),
                )));
            }
            // Expired: remove and fall through
            self.l1.remove(k_str);
        }

        // For memory-only policy, we're done (no L2 disk storage)
        if p_type == POLICY_MEMORY {
            return Ok(None);
        }

        // Check L2 (disk)
        if let Some((meta, handler)) = self.l2.lookup(key, trace).await? {
            prof_record_l2_hit();
            // Promote L2 disk hits to TinyUfoL1
            if let Some(mem_handler) = handler.as_any().downcast_ref::<MemoryHitHandler>() {
                let background_permit = crate::memory_governor::MEMORY_GOVERNOR
                    .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork);
                if mem_handler.data.len() <= MEMORY_SERVE_MAX as usize
                    && background_permit.is_some()
                    && !crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high()
                {
                    let now = crate::utils::time::now_timestamp();
                    let fresh_until = meta
                        .fresh_until()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or(std::time::Duration::from_secs(3600))
                        .as_secs() as i64;
                    let created_at = now;
                    let ttl_secs = (fresh_until - now).max(1);

                    let entry = TinyUfoL1Entry {
                        data: mem_handler.data.clone(),
                        response_header: meta.response_header().clone(),
                        fresh_until,
                        created_at,
                    };
                    self.l1.put(
                        k_str,
                        entry,
                        std::time::Duration::from_secs(ttl_secs as u64),
                    );
                    bloom_insert(k_str);
                    negative_cache_remove(k_str);
                    prof_record_l2_mem_promotion();
                }
            }

            return Ok(Some((meta, handler)));
        }

        Ok(None)
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<MissHandler> {
        let p_type = self.policy_type.load(Ordering::Relaxed);

        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            return self.l2.get_miss_handler(key, meta, trace).await;
        }

        if p_type == POLICY_FILE {
            let min_free = self
                .min_free_bytes
                .load(std::sync::atomic::Ordering::Relaxed);
            let available = CACHED_DISK_AVAILABLE.load(Ordering::Relaxed);

            if available < min_free {
                warn!(
                    "RPC_CACHE: Disk space below threshold. Bypassing disk cache to memory-only."
                );
                // Fall through to L2, which will handle it
            }
        }

        if p_type == POLICY_MEMORY {
            // Memory-only mode: no persistent storage, just serve from L1
            // Miss handler not needed for pure memory cache
            return Err(Error::explain(
                ErrorType::InternalError,
                "Memory-only policy does not support miss handler",
            ));
        }

        self.l2.get_miss_handler(key, meta, trace).await
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        purge_type: PurgeType,
        trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        if key.user_tag.is_empty() {
            return Ok(false);
        }

        self.l1.remove(key.user_tag.as_ref());
        bloom_remove(key.user_tag.as_ref());
        negative_cache_remove(key.user_tag.as_ref());
        let l2_ok = self.l2.purge(key, purge_type, trace).await?;
        Ok(l2_ok)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            return self.l2.update_meta(key, meta, trace).await;
        }

        let p_type = self.policy_type.load(Ordering::Relaxed);
        if p_type == POLICY_MEMORY {
            // TinyUfoL1 doesn't need explicit update_meta (TTL managed internally)
            return Ok(true);
        }
        self.l2.update_meta(key, meta, trace).await
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

#[derive(Eq, PartialEq)]
struct EvictCandidate {
    access_time: i64,
    size: u64,
    hash: String,
}

impl Ord for EvictCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.access_time.cmp(&other.access_time)
    }
}

impl PartialOrd for EvictCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub async fn start_cache_purger(storage: &'static HybridStorage, _disk_root: PathBuf) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

    loop {
        interval.tick().await;
        let Some(_permit) = crate::memory_governor::MEMORY_GOVERNOR
            .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork)
        else {
            tracing::warn!(
                "CACHE_PURGER: skipping cycle because background memory admission is full"
            );
            continue;
        };
        let now = crate::utils::time::now_timestamp();
        let max_bytes = storage
            .max_disk_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let inner = storage.l2.inner.load();

        let mut current_size: u64 = 0;
        let mut expired_hashes = Vec::new();

        // Pass 1: Stream metadata from in-memory index, collect expired, calculate size
        crate::metrics::storage::STORAGE.for_each_cache_meta(|hash, meta| {
            let expires = meta.expires;
            let size = meta.size;

            if now > expires {
                expired_hashes.push(hash);
            } else {
                current_size += size;
            }
        });

        // Execute: Delete expired files
        for hash in expired_hashes {
            remove_cache_file_from_roots(&inner, &hash).await;
            crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
        }

        // Pass 2: Capacity eviction using Max-Heap if disk exceeds limits
        if max_bytes > 0 && current_size > max_bytes {
            let bytes_to_free = current_size - max_bytes;

            let mut heap = std::collections::BinaryHeap::new();
            let mut heap_bytes: u64 = 0;

            crate::metrics::storage::STORAGE.for_each_cache_meta(|hash, meta| {
                let expires = meta.expires;
                // Only process active files
                if now <= expires {
                    let size = meta.size;
                    let access_time = meta.access_time;

                    heap.push(EvictCandidate {
                        access_time,
                        size,
                        hash,
                    });
                    heap_bytes += size;

                    // Maintain the heap size just enough to free the required bytes
                    while heap_bytes > bytes_to_free {
                        if let Some(top) = heap.peek() {
                            if heap_bytes - top.size >= bytes_to_free {
                                heap_bytes -= top.size;
                                heap.pop();
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            });

            // Execute: Delete oldest files
            let candidates_count = heap.len();
            tracing::info!(
                "CACHE_PURGER: Capacity reached. Evicting {} oldest files to free {} bytes.",
                candidates_count,
                heap_bytes
            );

            for candidate in heap {
                let hash = candidate.hash;
                remove_cache_file_from_roots(&inner, &hash).await;
                crate::metrics::storage::STORAGE.delete_cache_meta_async(&hash).await;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Cache performance profiling — log hit/miss/promotion stats
// ═══════════════════════════════════════════════════════════

static PROF_L1_HITS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_HITS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_MEM_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_ASYNC_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
static PROF_BLOOM_REJECTS: AtomicU64 = AtomicU64::new(0);
/// Accumulated disk read time in microseconds for the current 10s window.
static PROF_DISK_READ_US: AtomicU64 = AtomicU64::new(0);
/// Accumulated request_filter wall time in microseconds for the current 10s window.
static PROF_REQFILT_US: AtomicU64 = AtomicU64::new(0);
/// Number of request_filter calls in the current 10s window.
static PROF_REQFILT_COUNT: AtomicU64 = AtomicU64::new(0);
/// Number of FAST PATH (cacheable GET/HEAD early return) exits in the current 10s window.
static PROF_FASTPATH_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn prof_record_l1_hit() {
    PROF_L1_HITS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_l2_hit() {
    PROF_L2_HITS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_l2_mem_promotion() {
    PROF_L2_MEM_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_l2_async_promotion() {
    PROF_L2_ASYNC_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_bloom_reject() {
    PROF_BLOOM_REJECTS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_reqfilter(us: u64) {
    PROF_REQFILT_US.fetch_add(us, Ordering::Relaxed);
    PROF_REQFILT_COUNT.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_fastpath() {
    PROF_FASTPATH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Start a background task that logs cache performance stats every 10 seconds.
/// Provides real-time visibility into L1/L2 hit ratios and promotion rates.
pub fn start_cache_profiler() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let l1 = PROF_L1_HITS.swap(0, Ordering::Relaxed);
            let l2 = PROF_L2_HITS.swap(0, Ordering::Relaxed);
            let sync_prom = PROF_L2_MEM_PROMOTIONS.swap(0, Ordering::Relaxed);
            let async_prom = PROF_L2_ASYNC_PROMOTIONS.swap(0, Ordering::Relaxed);
            let bloom_rej = PROF_BLOOM_REJECTS.swap(0, Ordering::Relaxed);
            let disk_us = PROF_DISK_READ_US.swap(0, Ordering::Relaxed);
            let reqfil_us = PROF_REQFILT_US.swap(0, Ordering::Relaxed);
            let reqfil_cnt = PROF_REQFILT_COUNT.swap(0, Ordering::Relaxed);
            let fastpath = PROF_FASTPATH_COUNT.swap(0, Ordering::Relaxed);
            let total = l1 + l2;
            if total == 0 && reqfil_cnt == 0 && bloom_rej == 0 {
                continue;
            }
            let l1_pct = if total > 0 {
                l1 as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            let avg_disk_ms = if l2 > 0 {
                disk_us as f64 / l2 as f64 / 1000.0
            } else {
                0.0
            };
            let avg_reqfil_ms = if reqfil_cnt > 0 {
                reqfil_us as f64 / reqfil_cnt as f64 / 1000.0
            } else {
                0.0
            };
            tracing::info!(
                "CACHE_PROFILE: L1={l1}/s L2={l2}/s L1%={l1_pct:.1} bloom_rej={bloom_rej}/s sync_prom={sync_prom}/s async_prom={async_prom}/s total={total}/s disk={avg_disk_ms:.1}ms rf={avg_reqfil_ms:.1}ms fp={fastpath}/s"
            );
        }
    });
}

/// Periodically refresh disk space and memory budget.
/// TinyUFO handles eviction internally via S3-FIFO.
pub fn start_cache_janitor() {
    tokio::spawn(async {
        let disk_root = crate::paths::NodePaths::current().cache_dir();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let Some(_permit) = crate::memory_governor::MEMORY_GOVERNOR
                .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork)
            else {
                tracing::warn!(
                    "CACHE_JANITOR: skipping cycle because background memory admission is full"
                );
                continue;
            };

            // Refresh cached disk available space
            let disks = sysinfo::Disks::new_with_refreshed_list();
            let available = disks
                .iter()
                .find(|d| disk_root.starts_with(d.mount_point()))
                .map(|d| d.available_space())
                .unwrap_or(u64::MAX);
            CACHED_DISK_AVAILABLE.store(available, Ordering::Relaxed);

            crate::cache_manager::CACHE.storage.l1.refresh_auto_budget();

            // Clean expired negative cache entries
            let now = crate::utils::time::now_timestamp();
            NEGATIVE_CACHE.retain(|_, &mut expires| expires > now);
        }
    });
}

#[doc(hidden)]
pub fn fast_l1_lookup(key: &str) -> bool {
    crate::cache_manager::CACHE.storage.l1.get(key).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64 as TestAtomicU64, Ordering as TestOrdering};

    static TEST_UNIQUE_COUNTER: TestAtomicU64 = TestAtomicU64::new(0);

    fn unique_test_suffix(prefix: &str) -> String {
        let seq = TEST_UNIQUE_COUNTER.fetch_add(1, TestOrdering::Relaxed);
        format!("{prefix}-{}-{seq}", std::process::id())
    }

    #[test]
    fn dangerous_prefix_detection_requires_url_host_boundary() {
        assert!(HybridStorage::is_dangerous_purge_prefix("*"));
        assert!(HybridStorage::is_dangerous_purge_prefix(""));
        assert!(HybridStorage::is_dangerous_purge_prefix("https://"));
        assert!(HybridStorage::is_dangerous_purge_prefix(
            "https://cache.example.com"
        ));
        assert!(HybridStorage::is_dangerous_purge_prefix(
            "https://cache.example.com*"
        ));
        assert!(!HybridStorage::is_dangerous_purge_prefix(
            "https://cache.example.com/*"
        ));
    }

    #[tokio::test]
    async fn small_uncompressed_l2_hit_uses_memory_handler_for_fast_l1_promotion() {
        let unique = unique_test_suffix("small-l2-hit");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        tokio::fs::write(&path, b"small-body")
            .await
            .expect("write cache file");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str.clone(),
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (meta, handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<MemoryHitHandler>());
        assert_eq!(
            meta.response_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some("10")
        );

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn uncompressed_l2_hit_above_memory_read_limit_streams_file() {
        let unique = unique_test_suffix("stream-l2-hit");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        let advertised_size = cache_memory_hit_limit_bytes().saturating_add(1);
        let file = tokio::fs::File::create(&path)
            .await
            .expect("create cache file");
        file.set_len(advertised_size)
            .await
            .expect("set cache file size");
        drop(file);
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str.clone(),
                size: advertised_size,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (meta, handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<FileHitHandler>());
        let expected_len = advertised_size.to_string();
        assert_eq!(
            meta.response_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some(expected_len.as_str())
        );

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn file_cache_disabled_streams_small_l2_hits() {
        let unique = unique_test_suffix("file-cache-off");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        storage.update_config(root.clone(), Vec::new(), true, false);
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path_by_hash(&hash);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, b"small-body").await.unwrap();
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str,
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (_meta, mut handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<FileHitHandler>());
        assert_eq!(
            handler
                .read_body()
                .await
                .expect("read")
                .expect("chunk")
                .as_ref(),
            b"small-body"
        );

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn uncompressed_l2_hit_with_size_mismatch_is_treated_as_miss() {
        let unique = unique_test_suffix("small-meta-large-file");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path_by_hash(&hash);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        let file = tokio::fs::File::create(&path).await.unwrap();
        file.set_len(cache_memory_hit_limit_bytes().saturating_add(1))
            .await
            .unwrap();
        drop(file);
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str,
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let hit = storage.lookup(&key, &trace).await.expect("lookup result");
        assert!(hit.is_none());
        assert!(crate::metrics::storage::get_cache_meta_memory(&hash).is_none());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn l2_hit_with_invalid_cached_status_falls_back_to_ok() {
        let unique = unique_test_suffix("invalid-status-l2-hit");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        tokio::fs::write(&path, b"cached-body")
            .await
            .expect("write cache file");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str.clone(),
                size: 11,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 700,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (meta, _) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert_eq!(meta.response_header().status.as_u16(), 200);

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn small_compressed_l2_hit_uses_memory_handler_for_fast_l1_promotion() {
        let unique = unique_test_suffix("small-compressed-l2-hit");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        let body = b"small compressed text body";
        let compressed = zstd::encode_all(body.as_slice(), 0).expect("compress body");
        tokio::fs::write(&path, compressed)
            .await
            .expect("write cache file");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str.clone(),
                size: body.len() as u64,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: true,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (meta, mut handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<MemoryHitHandler>());
        let expected_len = body.len().to_string();
        assert_eq!(
            meta.response_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some(expected_len.as_str())
        );
        let chunk = handler
            .read_body()
            .await
            .expect("read body")
            .expect("body chunk");
        assert_eq!(chunk.as_ref(), body);

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[test]
    fn zstd_decompress_to_bytes_refuses_output_above_cap() {
        let body = vec![b'a'; 4096];
        let compressed = zstd::encode_all(body.as_slice(), 0).expect("compress body");

        assert!(zstd_decompress_to_bytes(&compressed, 1024).is_none());
        assert_eq!(
            zstd_decompress_to_bytes(&compressed, body.len()).expect("decompress body"),
            body
        );
    }

    #[tokio::test]
    async fn runtime_stats_include_tiny_ufo_l1_memory() {
        let unique = unique_test_suffix("runtime-stats-l1");
        let key = format!("https://cache.example.com/{unique}");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-stats-test-{unique}"));
        let storage = HybridStorage::new(0, &root);
        let before = storage.runtime_stats().await;
        assert!(before.file_cache_enabled);
        assert!(before.sendfile_enabled);
        assert_eq!(
            before.disk_hit_chunk_bytes,
            DISK_HIT_CHUNK_BYTES_SENDFILE_REQUESTED
        );

        storage.l1.put(
            &key,
            TinyUfoL1Entry {
                data: bytes::Bytes::from_static(b"body"),
                response_header: ResponseHeader::build(200, None).expect("response header"),
                fresh_until: crate::utils::time::now_timestamp() + 60,
                created_at: crate::utils::time::now_timestamp(),
            },
            std::time::Duration::from_secs(60),
        );

        let after = storage.runtime_stats().await;
        assert!(after.memory_bytes >= before.memory_bytes.saturating_add(4));
        assert!(after.memory_count >= before.memory_count.saturating_add(1));

        storage.l1.remove(&key);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn memory_hit_handler_supports_pingora_range_seek() {
        let mut handler = MemoryHitHandler {
            data: bytes::Bytes::from_static(b"abcdef"),
            offset: 0,
            end: 6,
            _cache_read_permit: None,
        };

        assert!(handler.can_seek());
        handler.seek(2, Some(5)).expect("seek should succeed");
        assert_eq!(
            handler
                .read_body()
                .await
                .expect("read")
                .expect("chunk")
                .as_ref(),
            b"cde"
        );
        assert!(handler.read_body().await.expect("read eof").is_none());

        handler.seek(6, None).expect("seek to EOF should succeed");
        assert!(handler.read_body().await.expect("read eof").is_none());
    }

    #[test]
    fn tiny_ufo_l1_resize_hysteresis_ignores_small_budget_changes() {
        let old = 512 * 1024 * 1024;
        assert!(!TinyUfoL1::should_rebuild_for_budget_change(
            old,
            600 * 1024 * 1024
        ));
        if !MEMORY_GOVERNOR.is_memory_pressure_high() {
            assert!(!TinyUfoL1::should_rebuild_for_budget_change(
                old,
                480 * 1024 * 1024
            ));
        }
        assert!(TinyUfoL1::should_rebuild_for_budget_change(
            old,
            440 * 1024 * 1024
        ));
        assert!(TinyUfoL1::should_rebuild_for_budget_change(
            old,
            768 * 1024 * 1024
        ));
    }

    #[tokio::test]
    async fn file_miss_handler_drop_removes_uncommitted_temp_file() {
        let unique = unique_test_suffix("drop-temp");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let temp_path = root.join("object.tmp");
        tokio::fs::write(&temp_path, b"partial").await.unwrap();
        let final_path = root.join("object");
        let file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&temp_path)
            .await
            .unwrap();
        let permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::CacheWrite)
            .expect("cache write permit should be available");

        drop(FileMissHandler {
            file: Some(file),
            encoder: None,
            written: 0,
            final_path,
            temp_path: temp_path.clone(),
            hash: unique.clone(),
            key_str: unique,
            ttl: 60,
            status: 200,
            headers: Vec::new(),
            compressed: false,
            shard_id: None,
            relative_path: "object".to_string(),
            stale_while_revalidate_secs: 0,
            committed: false,
            _cache_write_permit: permit,
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!temp_path.exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn file_miss_handler_failed_publish_does_not_overwrite_existing_meta() {
        let unique = unique_test_suffix("failed-publish");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let temp_path = root.join("object.tmp");
        let final_path = root.join("object");
        tokio::fs::create_dir_all(&final_path).await.unwrap();
        let file = tokio::fs::File::create(&temp_path).await.unwrap();
        let permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::CacheWrite)
            .expect("cache write permit should be available");
        let hash = unique.clone();
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: unique.clone(),
                size: 5,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let mut handler = Box::new(FileMissHandler {
            file: Some(file),
            encoder: None,
            written: 0,
            final_path,
            temp_path: temp_path.clone(),
            hash: hash.clone(),
            key_str: unique,
            ttl: 60,
            status: 200,
            headers: Vec::new(),
            compressed: false,
            shard_id: None,
            relative_path: "object".to_string(),
            stale_while_revalidate_secs: 0,
            committed: false,
            _cache_write_permit: permit,
        });
        handler
            .write_body(bytes::Bytes::from_static(b"loser-body"), false)
            .await
            .expect("write body");

        assert!(handler.finish().await.is_err());
        let meta = crate::metrics::storage::get_cache_meta_memory(&hash).expect("existing meta");
        assert_eq!(meta.size, 5);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!temp_path.exists());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn adaptive_bloom_scales_capacity() {
        let bloom = AdaptiveBloomFilter::new(8, 2);
        let (_, start_capacity, _, _) = bloom.stats();
        for i in 0..32 {
            bloom.insert(&format!("key-{i}"));
        }
        let (size, capacity, util, estimated_bytes) = bloom.stats();
        assert_eq!(size, 32);
        assert!(capacity > start_capacity);
        assert!(util > 0.0);
        assert!(estimated_bytes > 0);
        assert!(bloom.contains("key-0"));
        assert!(bloom.contains("key-31"));
    }

    #[test]
    fn negative_cache_capacity_tracks_bloom_size() {
        let unique = unique_test_suffix("cap-key");
        let before = negative_cache_capacity_limit();
        for i in 0..2_048 {
            bloom_insert(&format!("{unique}-{i}"));
        }
        let after = negative_cache_capacity_limit();
        assert!(after >= before);
        assert!(after <= NEGATIVE_CACHE_MAX_ENTRIES);
        assert!(after > 0);
    }

    #[test]
    fn negative_cache_expires_stale_entries() {
        let key = unique_test_suffix("neg-expire");
        let now = crate::utils::time::now_timestamp();
        NEGATIVE_CACHE.insert(key.clone(), now - 1);
        assert!(!negative_cache_check(&key, now));
        assert!(!NEGATIVE_CACHE.contains_key(&key));
    }

    #[test]
    fn negative_cache_refuses_insert_when_capacity_remains_full() {
        let now = crate::utils::time::now_timestamp();
        let prefix = format!("{}-", unique_test_suffix("neg-full"));
        for i in 0..3 {
            NEGATIVE_CACHE.insert(format!("{prefix}{i}"), now + NEGATIVE_CACHE_TTL_SECS);
        }

        let extra = format!("{prefix}extra");
        negative_cache_insert_with_capacity(&extra, now, 3);
        assert!(!NEGATIVE_CACHE.contains_key(&extra));

        NEGATIVE_CACHE.retain(|key, _| !key.starts_with(&prefix));
    }

    #[test]
    fn negative_cache_does_not_pollute_positive_bloom() {
        let now = crate::utils::time::now_timestamp();
        let unique = unique_test_suffix("neg-no-bloom");
        let key = (0..10_000)
            .map(|i| format!("{unique}-{i}"))
            .find(|key| !bloom_may_exist(key))
            .expect("test key should avoid existing Bloom positives");

        negative_cache_insert_with_capacity(&key, now, NEGATIVE_CACHE.len().saturating_add(1));

        assert!(!bloom_may_exist(&key));
        NEGATIVE_CACHE.remove(&key);
    }

    #[test]
    fn surrogate_index_capacity_is_bounded() {
        let capacity = surrogate_index_capacity();
        assert!(capacity <= SURROGATE_INDEX_MAX_TAGS_NORMAL);
        assert!(capacity >= SURROGATE_INDEX_MAX_TAGS_PRESSURE);
        assert!(meta_headers_contain_surrogate_tag(
            &[("Surrogate-Key".to_string(), "alpha beta".to_string())],
            "beta"
        ));
        assert!(!meta_headers_contain_surrogate_tag(
            &[("Surrogate-Key".to_string(), "alpha".to_string())],
            "beta"
        ));
        assert!(bloom_generation() >= 1);
    }

    #[test]
    fn cache_meta_hooks_warm_bloom_and_clear_negative_cache() {
        let key = unique_test_suffix("hook-key");
        let now = crate::utils::time::now_timestamp();
        negative_cache_insert(&key, now);
        let inserted = negative_cache_check(&key, now);

        let meta = crate::metrics::storage::CacheMetaEntry {
            cache_key: key.clone(),
            expires: now + 60,
            ..Default::default()
        };
        on_cache_meta_upsert(&meta);
        assert!(bloom_may_exist(&key));
        assert!(!negative_cache_check(&key, now));
        if inserted {
            assert!(
                negative_cache_check(&key, now)
                    || !crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high()
            );
        }
    }
}
