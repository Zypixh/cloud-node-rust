use async_trait::async_trait;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_cache::key::CompactCacheKey;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::{CacheKey, CacheMeta, MemCache};
use pingora_core::{Error, ErrorType, Result};
use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tracing::{info, warn};

use tokio::sync::RwLock;

use std::sync::atomic::{AtomicBool, Ordering};

/// Global cache for open file handles to reduce open() syscalls
static OPEN_FILE_CACHE: Lazy<DashMap<PathBuf, Arc<std::fs::File>>> = Lazy::new(DashMap::new);

/// Synchronous zstd decompression for serving small files from memory.
fn zstd_decompress_to_bytes(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let decoder = zstd::Decoder::new(data).ok()?;
    let mut out = Vec::with_capacity(data.len() * 3);
    let mut reader = std::io::BufReader::new(decoder);
    reader.read_to_end(&mut out).ok()?;
    Some(out)
}

const MEMORY_SERVE_MAX: u64 = 2 * 1024 * 1024; // 2MB

/// Read a small file entirely into memory, with optional zstd decompression.
/// Designed to run inside spawn_blocking — combines stat+read+decompress into one call.
fn read_file_into_memory(path: &std::path::Path, compressed: bool) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() == 0 || meta.len() > MEMORY_SERVE_MAX {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    if compressed {
        zstd_decompress_to_bytes(&data)
    } else {
        Some(data)
    }
}

/// Dynamic Disk-based storage for Pingora-cache
pub struct FileStorage {
    pub inner: Arc<RwLock<FileStorageInner>>,
    enable_sendfile: AtomicBool,
    enable_file_cache: AtomicBool,
}

pub struct FileStorageInner {
    pub main_root: PathBuf,
    pub extra_roots: Vec<PathBuf>,
}

impl FileStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let main_root = root.into();
        let _ = std::fs::create_dir_all(&main_root);
        Self {
            inner: Arc::new(RwLock::new(FileStorageInner {
                main_root,
                extra_roots: Vec::new(),
            })),
            enable_sendfile: AtomicBool::new(true),
            enable_file_cache: AtomicBool::new(true),
        }
    }

    pub async fn update_config(
        &self,
        main: PathBuf,
        extras: Vec<PathBuf>,
        sendfile: bool,
        file_cache: bool,
    ) {
        let mut lock = self.inner.write().await;
        let _ = std::fs::create_dir_all(&main);
        lock.main_root = main;
        lock.extra_roots = extras;
        self.enable_sendfile.store(sendfile, Ordering::Relaxed);
        self.enable_file_cache.store(file_cache, Ordering::Relaxed);

        if !file_cache {
            OPEN_FILE_CACHE.clear();
        }
    }

    fn get_hash(&self, key: &CacheKey) -> String {
        let k_str = key.primary_key_str().unwrap_or("unknown");
        format!("{:x}", md5_legacy::compute(k_str))
    }

    pub async fn get_path(&self, key: &CacheKey) -> PathBuf {
        let lock = self.inner.read().await;
        let hash = self.get_hash(key);

        lock.main_root
            .join(&hash[0..2])
            .join(&hash[2..4])
            .join(hash)
    }
}

#[async_trait]
impl Storage for FileStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let hash = self.get_hash(key);

        let meta_val = match crate::metrics::storage::STORAGE.get_cache_meta(&hash) {
            Some(m) => m,
            None => return Ok(None),
        };

        let now = crate::utils::time::now_timestamp();
        let (headers, ttl_remaining, compressed) = if let Some(meta) = meta_val.as_object() {
            let expires = meta.get("e").and_then(|v| v.as_i64()).unwrap_or(0);
            let ttl = (expires - now).max(0) as u64;
            let status = meta.get("st").and_then(|v| v.as_u64()).unwrap_or(200) as u16;
            let compressed = meta.get("c").and_then(|v| v.as_bool()).unwrap_or(false);

            let mut header = pingora_http::ResponseHeader::build(status, None).unwrap();
            if let Some(h_val) = meta.get("h")
                && let Some(h_obj) = h_val.as_object()
            {
                for (name, val) in h_obj {
                    if let Some(s) = val.as_str() {
                        let _ = header.insert_header(name.to_string(), s);
                    }
                }
            }
            tracing::debug!(
                "CACHE_HIT: status: {}, compressed: {}, headers: {:?}",
                status,
                compressed,
                header
            );
            (header, ttl, compressed)
        } else {
            (
                pingora_http::ResponseHeader::build(200, None).unwrap(),
                3600,
                false,
            )
        };

        let path = self.get_path(key).await;

        // Check the open-file cache first
        let std_file = if self.enable_file_cache.load(Ordering::Relaxed) {
            OPEN_FILE_CACHE.get(&path).map(|r| Arc::clone(r.value()))
        } else {
            None
        };

        let meta = CacheMeta::new(
            std::time::SystemTime::now() + std::time::Duration::from_secs(ttl_remaining),
            std::time::SystemTime::now(),
            0,
            0,
            headers,
        );

        // Fast path: combine stat+read+decompress into one spawn_blocking call
        // to avoid saturating Tokio's blocking thread pool under high concurrency.
        let path_clone = path.clone();
        let result = tokio::task::spawn_blocking(move || {
            read_file_into_memory(&path_clone, compressed)
        }).await;

        match result {
            Ok(Some(data)) => {
                crate::metrics::storage::STORAGE.record_cache_access(&hash);
                let body = bytes::Bytes::from(data);
                return Ok(Some((meta, Box::new(MemoryHitHandler { data: body, sent: false }))));
            }
            Ok(None) => {
                // File is >2MB, empty, or metadata failed — fall through to slow path.
                // Try to use the open-file cache for the streaming slow path.
            }
            Err(_) => {
                // spawn_blocking panicked or was cancelled
                return Ok(None);
            }
        }

        // Slow path for large files: streaming with open file cache.
        // Open via std::fs::File so we can try_clone() the fd into OPEN_FILE_CACHE.
        let file = match std_file {
            Some(f) => {
                // Duplicate the cached fd for this request
                let dup = f.try_clone().map_err(|_| Error::new(ErrorType::InternalError))?;
                tokio::fs::File::from_std(dup)
            }
            None => {
                let path_clone = path.clone();
                let result = tokio::task::spawn_blocking(move || {
                    std::fs::File::open(&path_clone)
                }).await;
                match result {
                    Ok(Ok(std_f)) => {
                        if self.enable_file_cache.load(Ordering::Relaxed) {
                            if let Ok(cached) = std_f.try_clone() {
                                OPEN_FILE_CACHE.insert(path.clone(), Arc::new(cached));
                            }
                        }
                        tokio::fs::File::from_std(std_f)
                    }
                    _ => {
                        crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
                        return Ok(None);
                    }
                }
            },
        };
        crate::metrics::storage::STORAGE.record_cache_access(&hash);

        let reader: Box<dyn tokio::io::AsyncRead + Unpin + Send> = if compressed {
            let buf_reader = tokio::io::BufReader::new(file);
            Box::new(async_compression::tokio::bufread::ZstdDecoder::new(buf_reader))
        } else {
            Box::new(file)
        };

        let handler = Box::new(FileHitHandler {
            reader: tokio::sync::Mutex::new(reader),
        });
        Ok(Some((meta, handler)))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<MissHandler> {
        let path = self.get_path(key).await;
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        
        // Use a unique temp path to prevent concurrent cache misses from corrupting the same file
        let random_id = crate::utils::time::now_timestamp_millis();
        let temp_path = path.with_extension(format!("tmp.{}", random_id));

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

        let mut headers_json = serde_json::Map::new();
        let hop_by_hop = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "content-length",
        ];

        for (name, value) in resp_headers.headers.iter() {
            let name_s = name.to_string().to_lowercase();
            if hop_by_hop.contains(&name_s.as_str()) {
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
            headers: serde_json::Value::Object(headers_json),
            compressed: should_compress,
        }))
    }

    async fn purge(
        &'static self,
        _key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        let hash = self.get_hash(key);
        let k_str = key.primary_key_str().unwrap_or("unknown").to_string();
        let ttl = meta
            .fresh_until()
            .duration_since(meta.created())
            .map(|d| d.as_secs())
            .unwrap_or(3600);
        let resp_headers = meta.response_header();
        let status = resp_headers.status.as_u16();

        // Use the same header filtering logic as miss handler
        let mut headers_json = serde_json::Map::new();
        let hop_by_hop = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "content-length",
        ];
        for (name, value) in resp_headers.headers.iter() {
            let name_s = name.to_string().to_lowercase();
            if hop_by_hop.contains(&name_s.as_str()) {
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

        tracing::info!(
            "CACHE_UPDATE_META: hash: {}, status: {}, compressed: {}, headers_len: {}",
            hash,
            status,
            compressed,
            headers_json.len()
        );
        crate::metrics::storage::STORAGE.update_cache_meta(
            &hash,
            &k_str,
            0,
            ttl,
            Some(serde_json::Value::Object(headers_json)),
            compressed,
            status,
        );

        Ok(true)
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

/// In-memory hit handler that serves from a Bytes buffer.
/// Eliminates disk I/O on every cache hit by reading the entire file once.
struct MemoryHitHandler {
    data: bytes::Bytes,
    sent: bool,
}

#[async_trait]
impl HandleHit for MemoryHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        if self.sent {
            return Ok(None);
        }
        self.sent = true;
        Ok(Some(self.data.clone()))
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

/// Streaming file hit handler for large files that don't fit in the memory budget.
struct FileHitHandler {
    reader: tokio::sync::Mutex<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
}

#[async_trait]
impl HandleHit for FileHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 32768];
        let mut r = self.reader.lock().await;
        let res = r.read(&mut buf).await.map_err(|e| {
            tracing::error!(
                "CACHE_HIT: Streaming read error (possibly corrupted zstd): {:?}",
                e
            );
            Error::new(ErrorType::InternalError)
        })?;

        if res == 0 {
            Ok(None)
        } else {
            buf.truncate(res);
            Ok(Some(bytes::Bytes::from(buf)))
        }
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
    headers: serde_json::Value,
    compressed: bool,
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
            let path_exists = tokio::task::spawn_blocking({
                let p = self.final_path.clone();
                move || p.exists()
            })
            .await
            .unwrap_or(false);

            if !path_exists {
                return Err(Error::new(ErrorType::InternalError));
            }
            // Cleanup the temporary file if another thread won the race
            let _ = tokio::fs::remove_file(&self.temp_path).await;
        }

        crate::metrics::storage::STORAGE.update_cache_meta(
            &self.hash,
            &self.key_str,
            written as u64,
            self.ttl,
            Some(self.headers.clone()),
            self.compressed,
            self.status,
        );

        Ok(MissFinishType::Created(written))
    }
}

pub struct HybridStorage {
    pub l1: Arc<MemCache>,
    pub l2: &'static FileStorage,
    hot_counts: DashMap<String, u32>,
    hot_threshold: std::sync::atomic::AtomicU32,
    pub max_disk_bytes: std::sync::atomic::AtomicU64,
    pub min_free_bytes: std::sync::atomic::AtomicU64,
    pub policy_type: Arc<RwLock<String>>,
}

pub struct CacheRuntimeStats {
    pub policy_type: String,
    pub memory_count: usize,
    pub memory_bytes: u64,
    pub disk_count: usize,
    pub disk_bytes: u64,
    pub open_file_cache_count: usize,
    pub max_disk_bytes: u64,
    pub min_free_bytes: u64,
}

impl HybridStorage {
    pub fn new(_max_mem_bytes: usize, disk_root: impl Into<PathBuf>) -> Self {
        let l1 = MemCache::new();

        Self {
            l1: Arc::new(l1),
            l2: Box::leak(Box::new(FileStorage::new(disk_root))),
            hot_counts: DashMap::new(),
            hot_threshold: std::sync::atomic::AtomicU32::new(5),
            max_disk_bytes: std::sync::atomic::AtomicU64::new(10 * 1024 * 1024 * 1024),
            min_free_bytes: std::sync::atomic::AtomicU64::new(2 * 1024 * 1024 * 1024), // 2GB default
            policy_type: Arc::new(RwLock::new("file".to_string())),
        }
    }

    pub async fn apply_policy(&self, policy: &crate::config_models::HTTPCachePolicy) {
        let mut p_type = self.policy_type.write().await;
        *p_type = policy.r#type.clone();

        if let Some(capacity) = &policy.capacity {
            let bytes = crate::config_models::SizeCapacity::from_json(capacity).to_bytes();
            if bytes > 0 {
                self.max_disk_bytes
                    .store(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }

        if let Some(options) = &policy.options {
            if let Some(hot) = options.get("hotThreshold").and_then(|v| v.as_u64()) {
                self.hot_threshold
                    .store(hot as u32, std::sync::atomic::Ordering::Relaxed);
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
                    .unwrap_or_else(|| PathBuf::from("../data/cache"));

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
                .unwrap_or(false); // Default to false for 10M+ files safety, matching GoEdge typical behavior unless explicitly ON

            if let Some(main) = main_dir {
                info!(
                    "RPC_CACHE: Updating cache configuration (Sendfile: {}, HandleCache: {})",
                    enable_sendfile, enable_file_cache
                );
                self.l2
                    .update_config(
                        main,
                        sub_dirs.unwrap_or_default(),
                        enable_sendfile,
                        enable_file_cache,
                    )
                    .await;
            }
        }
    }

    pub async fn purge_by_key(&self, key: &str) -> bool {
        let hash = format!("{:x}", md5_legacy::compute(key));
        let lock = self.l2.inner.read().await;
        let path = lock
            .main_root
            .join(&hash[0..2])
            .join(&hash[2..4])
            .join(&hash);
        let _ = fs::remove_file(&path).await;
        crate::metrics::storage::STORAGE.delete_cache_meta(&hash);

        let ck = CacheKey::new("edge", key, "").to_compact();
        // Use Global CACHE to bypass E0597
        tokio::spawn(async move {
            let trace = pingora_cache::trace::Span::inactive().handle();
            let _ = crate::cache_manager::CACHE
                .storage
                .l1
                .purge(&ck, PurgeType::Invalidation, &trace)
                .await;
        });
        true
    }

    pub async fn purge_by_prefix(&self, prefix: &str) -> bool {
        let clean_prefix = prefix.trim_end_matches('*');
        let mut deleted_count = 0;

        let all_meta = crate::metrics::storage::STORAGE.scan_all_cache_meta();
        for (hash, meta) in all_meta {
            if let Some(k) = meta["k"].as_str() {
                if k.starts_with(clean_prefix) {
                    let lock = self.l2.inner.read().await;
                    let path = lock
                        .main_root
                        .join(&hash[0..2])
                        .join(&hash[2..4])
                        .join(&hash);
                    let _ = fs::remove_file(&path).await;
                    crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
                    deleted_count += 1;
                }
            }
        }
        info!(
            "RPC_CACHE: Purged {} items matching prefix: {}",
            deleted_count, prefix
        );
        true
    }

    pub async fn runtime_stats(&self) -> CacheRuntimeStats {
        let (memory_count, memory_bytes) = self.l1.stats();
        let (disk_count, disk_bytes) = crate::metrics::storage::STORAGE.cache_summary();
        CacheRuntimeStats {
            policy_type: self.policy_type.read().await.clone(),
            memory_count,
            memory_bytes: memory_bytes as u64,
            disk_count,
            disk_bytes,
            open_file_cache_count: OPEN_FILE_CACHE.len(),
            max_disk_bytes: self
                .max_disk_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            min_free_bytes: self
                .min_free_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
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
        let p_type = self.policy_type.read().await;

        let k_str = key.primary_key_str().unwrap_or("unknown");

        if *p_type == "memory" {
            return self.l1.lookup(key, trace).await;
        }

        if let Some(hit) = self.l1.lookup(key, trace).await? {
            prof_record_l1_hit();
            return Ok(Some(hit));
        }

        if let Some((meta, handler)) = self.l2.lookup(key, trace).await? {
            prof_record_l2_hit();
            // Synchronously promote small memory-backed hits to L1 so the NEXT
            // request is served from memory at microsecond speed. Bytes::clone
            // is just an Arc refcount increment — near-zero cost.
            if let Some(mem_handler) = handler.as_any().downcast_ref::<MemoryHitHandler>() {
                if !mem_handler.sent && mem_handler.data.len() <= MEMORY_SERVE_MAX as usize {
                    if let Ok(mut miss_handler) = self.l1.get_miss_handler(key, &meta, trace).await {
                        let _ = miss_handler.write_body(mem_handler.data.clone(), true).await;
                        let _ = miss_handler.finish().await;
                        prof_record_l2_mem_promotion();
                    }
                }
            }

            // Async hot promotion for files that don't fit the memory fast path
            // (e.g. >2MB or already streamed via FileHitHandler).
            let threshold = self
                .hot_threshold
                .load(std::sync::atomic::Ordering::Relaxed);
            let mut is_hot = false;
            let hash = format!("{:x}", md5_legacy::compute(k_str));
            self.hot_counts
                .entry(hash.clone())
                .and_modify(|c| {
                    *c += 1;
                    if *c >= threshold {
                        is_hot = true;
                    }
                })
                .or_insert(1);

            if is_hot {
                prof_record_l2_async_promotion();
                let storage_l2 = self.l2;
                let cache_key_cloned = key.clone();
                tokio::spawn(async move {
                    let path = storage_l2.get_path(&cache_key_cloned).await;
                    if let Ok(attr) = tokio::fs::metadata(&path).await {
                        if attr.len() > 0 && attr.len() < MEMORY_SERVE_MAX {
                            if let Ok(mut file) = tokio::fs::File::open(&path).await {
                                use tokio::io::AsyncReadExt;
                                let mut buffer = Vec::with_capacity(attr.len() as usize);
                                if file.read_to_end(&mut buffer).await.is_ok() {
                                    let header =
                                        pingora_http::ResponseHeader::build(200, None).unwrap();
                                    let new_meta = CacheMeta::new(
                                        std::time::SystemTime::now()
                                            + std::time::Duration::from_secs(3600),
                                        std::time::SystemTime::now(),
                                        0,
                                        0,
                                        header,
                                    );
                                    let _trace = pingora_cache::trace::Span::inactive().handle();
                                    if let Ok(mut miss_handler) =
                                        crate::cache_manager::CACHE
                                            .storage
                                            .l1
                                            .get_miss_handler(&cache_key_cloned, &new_meta, &_trace)
                                            .await
                                    {
                                        let _ = miss_handler
                                            .write_body(bytes::Bytes::from(buffer), true)
                                            .await;
                                        let _ = miss_handler.finish().await;
                                    }
                                }
                            }
                        }
                    }
                });
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
        let p_type = self.policy_type.read().await;

        if *p_type == "file" {
            let lock = self.l2.inner.read().await;
            let min_free = self
                .min_free_bytes
                .load(std::sync::atomic::Ordering::Relaxed);

            let disks = sysinfo::Disks::new_with_refreshed_list();
            let available = disks
                .iter()
                .find(|d| lock.main_root.starts_with(d.mount_point()))
                .map(|d| d.available_space())
                .unwrap_or(u64::MAX);

            if available < min_free {
                warn!("RPC_CACHE: Disk space below threshold. Bypassing disk cache.");
                return self.l1.get_miss_handler(key, meta, trace).await;
            }
        }

        if *p_type == "memory" {
            return self.l1.get_miss_handler(key, meta, trace).await;
        }

        self.l2.get_miss_handler(key, meta, trace).await
    }

    async fn purge(
        &'static self,
        _key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        self.l1.update_meta(key, meta, trace).await?;
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

pub async fn start_cache_purger(storage: &'static HybridStorage, disk_root: PathBuf) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

    loop {
        interval.tick().await;
        let now = crate::utils::time::now_timestamp();
        let max_bytes = storage
            .max_disk_bytes
            .load(std::sync::atomic::Ordering::Relaxed);

        let mut current_size: u64 = 0;
        let mut expired_hashes = Vec::new();

        // Pass 1: Stream metadata from in-memory index, collect expired, calculate size
        crate::metrics::storage::STORAGE.for_each_cache_meta(|hash, meta| {
            let expires = meta["e"].as_i64().unwrap_or(0);
            let size = meta["s"].as_u64().unwrap_or(0);

            if now > expires {
                expired_hashes.push(hash);
            } else {
                current_size += size;
            }
        });

        // Execute: Delete expired files
        for hash in expired_hashes {
            let path = disk_root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
            let _ = tokio::fs::remove_file(&path).await;
            crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
        }

        // Pass 2: Capacity eviction using Max-Heap if disk exceeds limits
        if max_bytes > 0 && current_size > max_bytes {
            let bytes_to_free = current_size - max_bytes;

            let mut heap = std::collections::BinaryHeap::new();
            let mut heap_bytes: u64 = 0;

            crate::metrics::storage::STORAGE.for_each_cache_meta(|hash, meta| {
                let expires = meta["e"].as_i64().unwrap_or(0);
                // Only process active files
                if now <= expires {
                    let size = meta["s"].as_u64().unwrap_or(0);
                    let access_time = meta["a"].as_i64().unwrap_or(0);

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
                let path = disk_root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
                let _ = tokio::fs::remove_file(&path).await;
                crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Cache performance profiling — log hit/miss/promotion stats
// ═══════════════════════════════════════════════════════════

use std::sync::atomic::AtomicU64;

static PROF_L1_HITS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_HITS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_MEM_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_ASYNC_PROMOTIONS: AtomicU64 = AtomicU64::new(0);

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
            let total = l1 + l2;
            if total == 0 {
                continue;
            }
            let l1_pct = if total > 0 { l1 as f64 / total as f64 * 100.0 } else { 0.0 };
            tracing::info!(
                "CACHE_PROFILE: L1={l1}/s L2={l2}/s L1%={l1_pct:.1} sync_prom={sync_prom}/s async_prom={async_prom}/s total={total}/s"
            );
        }
    });
}
