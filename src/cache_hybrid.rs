use async_trait::async_trait;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_cache::key::CompactCacheKey;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::{CacheKey, CacheMeta, MemCache};
use pingora_core::{Error, ErrorType, Result};
use pingora_http::ResponseHeader;
use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};
use tracing::{info, warn};

use arc_swap::ArcSwap;

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicU64, Ordering};

static CACHED_DISK_AVAILABLE: AtomicU64 = AtomicU64::new(u64::MAX);
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
static CACHED_MEMORY_BUDGET: AtomicU64 = AtomicU64::new(0);
static CACHED_MEMORY_BUDGET_AT: AtomicI64 = AtomicI64::new(0);
const MEMORY_BUDGET_TTL_SECS: i64 = 30;

const DISK_HIT_CHUNK_BYTES: usize = 128 * 1024;
const MEMORY_SERVE_MAX: u64 = 50 * 1024 * 1024;

fn zstd_decompress_to_bytes(data: &[u8], capacity: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let decoder = zstd::Decoder::new(data).ok()?;
    let mut out = Vec::with_capacity(capacity);
    let mut reader = std::io::BufReader::new(decoder);
    reader.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Dynamic Disk-based storage for Pingora-cache
pub struct FileStorage {
    pub inner: ArcSwap<FileStorageInner>,
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
            inner: ArcSwap::from_pointee(FileStorageInner {
                main_root,
                extra_roots: Vec::new(),
            }),
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
        self.inner.store(Arc::new(FileStorageInner {
            main_root: main,
            extra_roots: extras,
        }));
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

    fn get_path_by_hash(&self, hash: &str) -> PathBuf {
        let lock = self.inner.load();
        lock.main_root.join(cache_relative_path(hash))
    }

    async fn find_existing_path_by_hash(&self, hash: &str) -> PathBuf {
        let lock = self.inner.load();
        let relative = cache_relative_path(hash);
        for root in &lock.extra_roots {
            let path = root.join(&relative);
            if tokio::fs::metadata(&path).await.is_ok() {
                return path;
            }
        }
        lock.main_root.join(&relative)
    }
}

fn cache_relative_path(hash: &str) -> PathBuf {
    Path::new(&hash[0..2]).join(&hash[2..4]).join(hash)
}

async fn remove_cache_file_from_roots(inner: &FileStorageInner, hash: &str) {
    let relative = cache_relative_path(hash);
    let _ = fs::remove_file(inner.main_root.join(&relative)).await;
    for root in &inner.extra_roots {
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
        let hash = self.get_hash(key);

        let meta = match crate::metrics::storage::get_cache_meta_memory(&hash) {
            Some(m) => m,
            None => return Ok(None),
        };

        let now = crate::utils::time::now_timestamp();
        let ttl = (meta.expires - now).max(0) as u64;

        let mut header = pingora_http::ResponseHeader::build(meta.status, None).unwrap();
        for (name, val) in &meta.headers {
            let _ = header.insert_header(name.to_string(), val.as_str());
        }

        let path = self.find_existing_path_by_hash(&hash).await;

        let cache_meta = CacheMeta::new(
            std::time::SystemTime::now() + std::time::Duration::from_secs(ttl),
            std::time::SystemTime::now(),
            0,
            0,
            header,
        );

        let io_start = std::time::Instant::now();

        if !meta.compressed {
            if meta.size <= MEMORY_SERVE_MAX {
                let file_data = tokio::fs::read(&path)
                    .await
                    .map_err(|_| Error::new(ErrorType::InternalError))?;
                PROF_DISK_READ_US
                    .fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
                crate::metrics::storage::record_cache_access_memory(&hash);
                return Ok(Some((
                    cache_meta,
                    Box::new(MemoryHitHandler {
                        data: bytes::Bytes::from(file_data),
                        offset: 0,
                    }),
                )));
            }

            let file = tokio::fs::File::open(&path)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?;
            PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
            crate::metrics::storage::record_cache_access_memory(&hash);
            return Ok(Some((
                cache_meta,
                Box::new(FileHitHandler {
                    reader: Box::new(file),
                    buf_size: DISK_HIT_CHUNK_BYTES,
                }),
            )));
        }

        if meta.size > 0 && meta.size <= DISK_HIT_CHUNK_BYTES as u64 {
            let file_data = tokio::fs::read(&path)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?;
            PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
            crate::metrics::storage::record_cache_access_memory(&hash);
            let capacity = meta.size.min(MEMORY_SERVE_MAX) as usize;
            let result =
                tokio::task::spawn_blocking(move || zstd_decompress_to_bytes(&file_data, capacity))
                    .await;
            let body = match result {
                Ok(Some(data)) => bytes::Bytes::from(data),
                _ => return Ok(None),
            };
            return Ok(Some((
                cache_meta,
                Box::new(MemoryHitHandler {
                    data: body,
                    offset: 0,
                }),
            )));
        }

        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;
        PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
        crate::metrics::storage::record_cache_access_memory(&hash);
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(BufReader::new(file));
        Ok(Some((
            cache_meta,
            Box::new(FileHitHandler {
                reader: Box::new(decoder),
                buf_size: DISK_HIT_CHUNK_BYTES,
            }),
        )))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<MissHandler> {
        let path = self.get_path(key);
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
            headers: headers_json
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                .collect(),
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
        crate::metrics::storage::STORAGE.update_cache_meta(
            &hash,
            &k_str,
            0,
            ttl,
            &header_pairs,
            compressed,
            status,
        );

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
}

#[async_trait]
impl HandleHit for MemoryHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        if self.offset >= self.data.len() {
            return Ok(None);
        }
        let end = (self.offset + 32768).min(self.data.len());
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
}

struct FileHitHandler {
    reader: Box<dyn AsyncRead + Unpin + Send + Sync>,
    buf_size: usize,
}

#[async_trait]
impl HandleHit for FileHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        let mut buf = Vec::with_capacity(self.buf_size);
        let read = self
            .reader
            .as_mut()
            .take(self.buf_size as u64)
            .read_to_end(&mut buf)
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;
        if read == 0 {
            return Ok(None);
        }
        Ok(Some(bytes::Bytes::from(buf)))
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
            &self.headers,
            self.compressed,
            self.status,
        );

        Ok(MissFinishType::Created(written))
    }
}

/// Fast lock-free L1 entry stored in a sharded DashMap.
/// Bypasses Pingora's single-lock MemCache entirely.
struct FastL1Entry {
    data: bytes::Bytes,
    fresh_until: i64,
    created_at: i64,
    generation: u64,
    response_header: ResponseHeader,
}

/// Global lock-free L1 cache. Sharded by DashMap, no contention at 1000+ concurrent reads.
static FAST_L1: Lazy<DashMap<u64, FastL1Entry>> = Lazy::new(DashMap::new);

/// Max total bytes in FAST_L1. 0 = auto-detect from available system memory.
static FAST_L1_MAX_BYTES: AtomicU64 = AtomicU64::new(0);

/// Current total bytes in FAST_L1. Maintained by insert (+=len) and remove (-=len).
static FAST_L1_BYTES: AtomicU64 = AtomicU64::new(0);

/// Monotonic generation used to distinguish stale heap entries from replaced cache entries.
static FAST_L1_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Min-heap for O(log n) eviction: entries with smallest fresh_until are evicted first.
/// Uses Reverse so BinaryHeap (max-heap) behaves as min-heap.
static EVICTION_HEAP: Lazy<
    parking_lot::Mutex<std::collections::BinaryHeap<std::cmp::Reverse<(i64, u64, u64)>>>,
> = Lazy::new(|| parking_lot::Mutex::new(std::collections::BinaryHeap::new()));

fn fast_l1_remove(hash: &u64) {
    if let Some((_, entry)) = FAST_L1.remove(hash) {
        FAST_L1_BYTES.fetch_sub(entry.data.len() as u64, Ordering::Release);
    }
}

fn fast_l1_remove_generation(hash: &u64, generation: u64) -> Option<FastL1Entry> {
    let removed = FAST_L1.remove_if(hash, |_, entry| entry.generation == generation)?;
    let entry = removed.1;
    FAST_L1_BYTES.fetch_sub(entry.data.len() as u64, Ordering::Release);
    Some(entry)
}

fn fast_l1_evict_expired(now: i64) -> (u64, usize) {
    let mut expired_bytes = 0u64;
    let mut evicted = 0usize;
    let mut heap = EVICTION_HEAP.lock();
    while let Some(&std::cmp::Reverse((fresh_until, _, _))) = heap.peek() {
        if fresh_until > now {
            break;
        }
        let std::cmp::Reverse((_, generation, victim_key)) = heap.pop().unwrap();
        if let Some(entry) = fast_l1_remove_generation(&victim_key, generation) {
            expired_bytes += entry.data.len() as u64;
            evicted += 1;
        }
    }
    (expired_bytes, evicted)
}

fn fast_l1_evict_over_budget(max_l1: u64, max_attempts: usize) -> (u64, usize) {
    let mut freed = 0u64;
    let mut evicted = 0usize;
    let mut attempts = 0usize;
    let mut heap = EVICTION_HEAP.lock();
    while FAST_L1_BYTES.load(Ordering::Acquire) > max_l1 && attempts < max_attempts {
        attempts += 1;
        let Some(std::cmp::Reverse((_, generation, victim_key))) = heap.pop() else {
            break;
        };
        if let Some(entry) = fast_l1_remove_generation(&victim_key, generation) {
            freed += entry.data.len() as u64;
            evicted += 1;
        }
    }
    (freed, evicted)
}

fn fast_l1_cache_meta(entry: &FastL1Entry) -> CacheMeta {
    let fresh_until_dur = std::time::Duration::from_secs(entry.fresh_until as u64);
    let created_at_dur = std::time::Duration::from_secs(entry.created_at as u64);
    CacheMeta::new(
        std::time::UNIX_EPOCH + fresh_until_dur,
        std::time::UNIX_EPOCH + created_at_dur,
        0,
        0,
        entry.response_header.clone(),
    )
}

const POLICY_FILE: u8 = 0;
const POLICY_MEMORY: u8 = 1;

#[inline]
fn fast_hash_key(s: &str) -> u64 {
    use std::hash::{BuildHasher, Hash, Hasher};
    static HASHER: Lazy<ahash::RandomState> = Lazy::new(|| {
        ahash::RandomState::with_seeds(
            0x9ae16a3b2f90404f,
            0x9e3779b97f4a7c15,
            0xff51afd7ed558ccd,
            0x517cc1b727220a95,
        )
    });
    let mut h = HASHER.build_hasher();
    s.hash(&mut h);
    h.finish()
}

pub struct HybridStorage {
    pub l1: Arc<MemCache>,
    pub l2: &'static FileStorage,
    pub max_disk_bytes: std::sync::atomic::AtomicU64,
    pub min_free_bytes: std::sync::atomic::AtomicU64,
    pub max_fast_l1_bytes: std::sync::atomic::AtomicU64,
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
}

impl HybridStorage {
    pub fn new(_max_mem_bytes: usize, disk_root: impl Into<PathBuf>) -> Self {
        let l1 = MemCache::new();

        Self {
            l1: Arc::new(l1),
            l2: Box::leak(Box::new(FileStorage::new(disk_root))),
            max_disk_bytes: std::sync::atomic::AtomicU64::new(10 * 1024 * 1024 * 1024),
            min_free_bytes: std::sync::atomic::AtomicU64::new(2 * 1024 * 1024 * 1024),
            max_fast_l1_bytes: std::sync::atomic::AtomicU64::new(0), // 0 = auto-detect
            policy_type: AtomicU8::new(POLICY_FILE),
        }
    }

    fn compute_memory_budget() -> u64 {
        let now = crate::utils::time::now_timestamp();
        let cached = CACHED_MEMORY_BUDGET.load(Ordering::Relaxed);
        let cached_at = CACHED_MEMORY_BUDGET_AT.load(Ordering::Relaxed);
        if cached > 0 && now.saturating_sub(cached_at) < MEMORY_BUDGET_TTL_SECS {
            return cached;
        }

        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let total = sys.total_memory();
        let available = sys.available_memory();
        let budget = (available as f64 * 0.25) as u64;
        let budget = budget.min((total as f64 * 0.5) as u64);
        CACHED_MEMORY_BUDGET.store(budget, Ordering::Relaxed);
        CACHED_MEMORY_BUDGET_AT.store(now, Ordering::Relaxed);
        budget
    }

    #[doc(hidden)]
    pub fn bench_compute_memory_budget() -> u64 {
        Self::compute_memory_budget()
    }

    #[doc(hidden)]
    pub fn bench_fast_l1_insert(
        key_str: &str,
        data: bytes::Bytes,
        meta: &CacheMeta,
        ttl_secs: i64,
    ) -> bool {
        let now = crate::utils::time::now_timestamp();
        let hash = fast_hash_key(key_str);
        Self::promote_to_fast_l1(hash, data, meta, now.saturating_add(ttl_secs), now)
    }

    #[doc(hidden)]
    pub fn bench_fast_l1_remove(key_str: &str) {
        let hash = fast_hash_key(key_str);
        fast_l1_remove(&hash);
    }

    /// Promote to FAST_L1 with capacity check and header extraction from CacheMeta.
    /// When budget is exceeded, evicts the entry closest to expiry to make room.
    /// Returns true if inserted, false if skipped (data too large).
    fn promote_to_fast_l1(
        hash: u64,
        data: bytes::Bytes,
        meta: &CacheMeta,
        fresh_until: i64,
        now: i64,
    ) -> bool {
        if data.len() > MEMORY_SERVE_MAX as usize {
            return false;
        }
        let max_l1 = FAST_L1_MAX_BYTES.load(Ordering::Relaxed);
        let len = data.len() as u64;
        let generation = FAST_L1_GENERATION.fetch_add(1, Ordering::Relaxed);
        if let Some(old_entry) = FAST_L1.insert(
            hash,
            FastL1Entry {
                data,
                fresh_until,
                created_at: now,
                generation,
                response_header: meta.response_header().clone(),
            },
        ) {
            FAST_L1_BYTES.fetch_sub(old_entry.data.len() as u64, Ordering::Release);
        }
        FAST_L1_BYTES.fetch_add(len, Ordering::Release);
        EVICTION_HEAP
            .lock()
            .push(std::cmp::Reverse((fresh_until, generation, hash)));
        if max_l1 > 0 && FAST_L1_BYTES.load(Ordering::Acquire) > max_l1 {
            fast_l1_evict_over_budget(max_l1, 100);
        }
        FAST_L1
            .get(&hash)
            .is_some_and(|entry| entry.generation == generation)
    }

    pub async fn apply_policy(&self, policy: &crate::config_models::HTTPCachePolicy) {
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
            // Memory capacity for FAST_L1: 0 = auto-detect, explicit value = use directly
            if let Some(mem) = options
                .get("memoryCapacity")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
            {
                FAST_L1_MAX_BYTES.store(mem, Ordering::Relaxed);
                self.max_fast_l1_bytes.store(mem, Ordering::Relaxed);
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

    pub async fn purge_by_key(&self, key: &str) -> bool {
        let hash = format!("{:x}", md5_legacy::compute(key));
        let inner = self.l2.inner.load();
        remove_cache_file_from_roots(&inner, &hash).await;
        crate::metrics::storage::STORAGE.delete_cache_meta(&hash);

        // Clear from lock-free L1 cache
        fast_l1_remove(&fast_hash_key(key));

        let full_key = CacheKey::new("edge", key, "");
        let ck = full_key.to_compact();
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
        let inner = self.l2.inner.load();
        let mut deleted_count = 0;
        let mut to_delete = Vec::new();

        crate::metrics::storage::STORAGE.for_each_cache_meta(|hash, meta| {
            if !meta.cache_key.is_empty() && meta.cache_key.starts_with(clean_prefix) {
                to_delete.push(hash);
            }
        });

        for hash in to_delete {
            remove_cache_file_from_roots(&inner, &hash).await;
            crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
            deleted_count += 1;
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
            policy_type: if self.policy_type.load(Ordering::Relaxed) == POLICY_MEMORY {
                "memory".to_string()
            } else {
                "file".to_string()
            },
            memory_count,
            memory_bytes: memory_bytes as u64,
            disk_count,
            disk_bytes,
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
        let p_type = self.policy_type.load(Ordering::Relaxed);

        let k_str = key.primary_key_str().unwrap_or("unknown");
        let hash = fast_hash_key(k_str);

        // Check lock-free FAST_L1 first for ALL policy types (DashMap, sharded, zero contention)
        if let Some(entry) = FAST_L1.get(&hash) {
            let now = crate::utils::time::now_timestamp();
            if entry.fresh_until > now {
                let meta = fast_l1_cache_meta(&entry);
                prof_record_l1_hit();
                return Ok(Some((
                    meta,
                    Box::new(MemoryHitHandler {
                        data: entry.data.clone(),
                        offset: 0,
                    }),
                )));
            }
            // Expired: remove and fall through
            drop(entry);
            fast_l1_remove(&hash);
        }

        // Fallback: try MemCache (for entries not yet in FAST_L1)
        if let Some((meta, handler)) = self.l1.lookup(key, trace).await? {
            prof_record_l1_hit();
            // Promote to FAST_L1 for subsequent zero-lock hits
            if let Some(mem_handler) = handler.as_any().downcast_ref::<MemoryHitHandler>() {
                let now = crate::utils::time::now_timestamp();
                let fresh_until = meta
                    .fresh_until()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::from_secs(3600))
                    .as_secs() as i64;
                if Self::promote_to_fast_l1(hash, mem_handler.data.clone(), &meta, fresh_until, now)
                {
                    prof_record_l2_mem_promotion();
                }
            }
            return Ok(Some((meta, handler)));
        }

        // For memory-only policy, we're done (no L2 disk storage)
        if p_type == POLICY_MEMORY {
            return Ok(None);
        }

        if let Some((meta, handler)) = self.l2.lookup(key, trace).await? {
            prof_record_l2_hit();
            // Always promote L2 disk hits to FAST_L1 immediately.
            // Memory budget + eviction control the total size, not an artificial threshold.
            if let Some(mem_handler) = handler.as_any().downcast_ref::<MemoryHitHandler>() {
                let now = crate::utils::time::now_timestamp();
                let fresh_until = meta
                    .fresh_until()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::from_secs(3600))
                    .as_secs() as i64;
                if Self::promote_to_fast_l1(hash, mem_handler.data.clone(), &meta, fresh_until, now)
                {
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

        if p_type == POLICY_FILE {
            let min_free = self
                .min_free_bytes
                .load(std::sync::atomic::Ordering::Relaxed);
            let available = CACHED_DISK_AVAILABLE.load(Ordering::Relaxed);

            if available < min_free {
                warn!("RPC_CACHE: Disk space below threshold. Bypassing disk cache.");
                return self.l1.get_miss_handler(key, meta, trace).await;
            }
        }

        if p_type == POLICY_MEMORY {
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
        let p_type = self.policy_type.load(Ordering::Relaxed);
        if p_type == POLICY_MEMORY {
            self.l1.update_meta(key, meta, trace).await?;
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
            crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
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
                crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Cache performance profiling — log hit/miss/promotion stats
// ═══════════════════════════════════════════════════════════

/// Public API: ultra-fast cache lookup for direct use in request_filter.
/// Returns the cached body bytes if a valid entry exists.
pub fn fast_l1_lookup(key_str: &str) -> Option<bytes::Bytes> {
    let hash = fast_hash_key(key_str);
    if let Some(entry) = FAST_L1.get(&hash) {
        let now = crate::utils::time::now_timestamp();
        if entry.fresh_until > now {
            return Some(entry.data.clone());
        }
        drop(entry);
        fast_l1_remove(&hash);
    }
    None
}

static PROF_L1_HITS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_HITS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_MEM_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_ASYNC_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
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
            let disk_us = PROF_DISK_READ_US.swap(0, Ordering::Relaxed);
            let reqfil_us = PROF_REQFILT_US.swap(0, Ordering::Relaxed);
            let reqfil_cnt = PROF_REQFILT_COUNT.swap(0, Ordering::Relaxed);
            let fastpath = PROF_FASTPATH_COUNT.swap(0, Ordering::Relaxed);
            let total = l1 + l2;
            if total == 0 && reqfil_cnt == 0 {
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
                "CACHE_PROFILE: L1={l1}/s L2={l2}/s L1%={l1_pct:.1} sync_prom={sync_prom}/s async_prom={async_prom}/s total={total}/s disk={avg_disk_ms:.1}ms rf={avg_reqfil_ms:.1}ms fp={fastpath}/s"
            );
        }
    });
}

/// Periodically evict expired entries from FAST_L1 and cap OPEN_FILE_CACHE size.
pub fn start_cache_janitor() {
    tokio::spawn(async {
        let disk_root = crate::paths::NodePaths::current().cache_dir();
        // Initialize memory budget immediately — don't wait 60s
        if FAST_L1_MAX_BYTES.load(Ordering::Relaxed) == 0 {
            let budget = HybridStorage::compute_memory_budget();
            if budget > 0 {
                FAST_L1_MAX_BYTES.store(budget, Ordering::Relaxed);
                tracing::info!("FAST_L1 auto memory budget: {} bytes", budget);
            }
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;

            // Refresh cached disk available space
            let disks = sysinfo::Disks::new_with_refreshed_list();
            let available = disks
                .iter()
                .find(|d| disk_root.starts_with(d.mount_point()))
                .map(|d| d.available_space())
                .unwrap_or(u64::MAX);
            CACHED_DISK_AVAILABLE.store(available, Ordering::Relaxed);

            // Evict expired FAST_L1 entries via heap (avoids full-table retain() lock)
            let now = crate::utils::time::now_timestamp();
            let (expired_bytes, evicted) = fast_l1_evict_expired(now);
            if evicted > 0 {
                tracing::debug!(
                    "FAST_L1 janitor: evicted {} expired entries ({} bytes), {} remain",
                    evicted,
                    expired_bytes,
                    FAST_L1.len()
                );
            }

            // Enforce FAST_L1 memory budget via eviction heap
            let max_l1 = FAST_L1_MAX_BYTES.load(Ordering::Relaxed);
            if max_l1 > 0 {
                let total = FAST_L1_BYTES.load(Ordering::Acquire);
                if total > max_l1 {
                    let (freed, _) = fast_l1_evict_over_budget(max_l1, usize::MAX);
                    if freed > 0 {
                        tracing::debug!(
                            "FAST_L1 memory budget: {}/{} bytes, evicted {} bytes, {} entries remain",
                            total,
                            max_l1,
                            freed,
                            FAST_L1.len()
                        );
                    }
                }
            }

            // Update auto memory budget from system
            if max_l1 == 0 {
                let budget = HybridStorage::compute_memory_budget();
                if budget > 0 {
                    FAST_L1_MAX_BYTES.store(budget, Ordering::Relaxed);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    static FAST_L1_TEST_LOCK: Lazy<parking_lot::Mutex<()>> =
        Lazy::new(|| parking_lot::Mutex::new(()));

    #[test]
    fn fast_l1_cache_meta_preserves_header_template() {
        let mut header = ResponseHeader::build(206, None).expect("response header");
        header
            .insert_header("x-cache-status", "HIT")
            .expect("insert header");
        let entry = FastL1Entry {
            data: bytes::Bytes::from_static(b"body"),
            fresh_until: 1_700_000_100,
            created_at: 1_700_000_000,
            generation: 1,
            response_header: header,
        };

        let meta = fast_l1_cache_meta(&entry);
        assert_eq!(meta.response_header().status.as_u16(), 206);
        assert_eq!(
            meta.response_header()
                .headers
                .get("x-cache-status")
                .and_then(|v| v.to_str().ok()),
            Some("HIT")
        );
    }

    #[tokio::test]
    async fn small_uncompressed_l2_hit_uses_memory_handler_for_fast_l1_promotion() {
        let key_str = format!(
            "small-l2-hit-{}-{}",
            std::process::id(),
            FAST_L1_GENERATION.fetch_add(1, Ordering::Relaxed)
        );
        let root = std::env::temp_dir().join(format!(
            "cloud-node-rust-cache-test-{}",
            FAST_L1_GENERATION.fetch_add(1, Ordering::Relaxed)
        ));
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
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (_, handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<MemoryHitHandler>());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn small_compressed_l2_hit_uses_memory_handler_for_fast_l1_promotion() {
        let key_str = format!(
            "small-compressed-l2-hit-{}-{}",
            std::process::id(),
            FAST_L1_GENERATION.fetch_add(1, Ordering::Relaxed)
        );
        let root = std::env::temp_dir().join(format!(
            "cloud-node-rust-cache-test-{}",
            FAST_L1_GENERATION.fetch_add(1, Ordering::Relaxed)
        ));
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
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (_, mut handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<MemoryHitHandler>());
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
    fn stale_heap_entry_does_not_remove_replaced_fast_l1_entry() {
        let _guard = FAST_L1_TEST_LOCK.lock();
        let hash = fast_hash_key("stale-heap-entry-test");
        fast_l1_remove(&hash);

        let old_generation = FAST_L1_GENERATION.fetch_add(1, Ordering::Relaxed);
        EVICTION_HEAP
            .lock()
            .push(std::cmp::Reverse((1_700_000_000, old_generation, hash)));

        let new_generation = FAST_L1_GENERATION.fetch_add(1, Ordering::Relaxed);
        let header = ResponseHeader::build(200, None).expect("response header");
        FAST_L1.insert(
            hash,
            FastL1Entry {
                data: bytes::Bytes::from_static(b"new"),
                fresh_until: 1_800_000_000,
                created_at: 1_700_000_100,
                generation: new_generation,
                response_header: header,
            },
        );
        FAST_L1_BYTES.fetch_add(3, Ordering::Release);

        let (_, evicted) = fast_l1_evict_expired(1_700_000_001);
        assert_eq!(evicted, 0);
        assert_eq!(
            FAST_L1.get(&hash).map(|entry| entry.generation),
            Some(new_generation)
        );

        fast_l1_remove(&hash);
    }

    #[test]
    fn current_generation_expired_heap_entry_removes_fast_l1_entry() {
        let _guard = FAST_L1_TEST_LOCK.lock();
        let hash = fast_hash_key("current-generation-expired-test");
        fast_l1_remove(&hash);

        let generation = FAST_L1_GENERATION.fetch_add(1, Ordering::Relaxed);
        let header = ResponseHeader::build(200, None).expect("response header");
        FAST_L1.insert(
            hash,
            FastL1Entry {
                data: bytes::Bytes::from_static(b"old"),
                fresh_until: 1_700_000_000,
                created_at: 1_699_999_900,
                generation,
                response_header: header,
            },
        );
        FAST_L1_BYTES.fetch_add(3, Ordering::Release);
        EVICTION_HEAP
            .lock()
            .push(std::cmp::Reverse((1_700_000_000, generation, hash)));

        let (expired_bytes, evicted) = fast_l1_evict_expired(1_700_000_001);
        assert_eq!(expired_bytes, 3);
        assert_eq!(evicted, 1);
        assert!(FAST_L1.get(&hash).is_none());
    }
}
