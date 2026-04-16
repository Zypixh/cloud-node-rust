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
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use tokio::sync::RwLock;

use std::sync::atomic::{AtomicBool, Ordering};

/// Global cache for open file handles to reduce open() syscalls (Task 10)
static OPEN_FILE_CACHE: Lazy<DashMap<PathBuf, Arc<std::fs::File>>> = Lazy::new(DashMap::new);

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

    pub async fn update_config(&self, main: PathBuf, extras: Vec<PathBuf>, sendfile: bool, file_cache: bool) {
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
    
    // Helper to get or open a file (Task 10)
    fn get_file_handle(&self, path: &PathBuf) -> Result<Arc<std::fs::File>> {
        if self.enable_file_cache.load(Ordering::Relaxed) {
            if let Some(f) = OPEN_FILE_CACHE.get(path) {
                let handle: Arc<std::fs::File> = f.clone();
                return Ok(handle);
            }
        }

        let f = std::fs::File::open(path).map_err(|_| Error::new(ErrorType::InternalError))?;
        
        // Task 7: Linux Optimization - Hint sequential access
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
                libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_WILLNEED);
            }
        }

        let shared_f = Arc::new(f);
        if self.enable_file_cache.load(Ordering::Relaxed) {
            if OPEN_FILE_CACHE.len() < 10000 { // Cap handle cache size
                OPEN_FILE_CACHE.insert(path.clone(), shared_f.clone());
            }
        }
        Ok(shared_f)
    }

    pub async fn get_path(&self, key: &CacheKey) -> PathBuf {
        let lock = self.inner.read().await;
        let k_str = key.primary_key_str().unwrap_or("unknown");
        let hash = hex::encode(k_str);
        
        lock.main_root.join(&hash[0..2]).join(&hash[2..4]).join(hash)
    }
}

#[async_trait]
impl Storage for FileStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let k_str = key.primary_key_str().unwrap_or("unknown");
        let hash = hex::encode(k_str);
        
        let meta_val = match crate::metrics::storage::STORAGE.get_cache_meta(&hash) {
            Some(m) => m,
            None => return Ok(None),
        };

        let now = chrono::Utc::now().timestamp();
        if let Some(expires) = meta_val["e"].as_i64() {
            if now > expires {
                crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
                return Ok(None);
            }
        }

        let path = self.get_path(key).await;
        if !path.exists() {
            crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
            return Ok(None);
        }

        let file = self.get_file_handle(&path)?;

        crate::metrics::storage::STORAGE.record_cache_access(&hash);

        let header = pingora_http::ResponseHeader::build(200, None).unwrap();
        let meta = CacheMeta::new(
            std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
            std::time::SystemTime::now(),
            0,
            0,
            header,
        );

        let handler = Box::new(FileHitHandler { file, offset: 0 });
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
            let _ = fs::create_dir_all(parent).await;
        }
        
        let temp_path = path.with_extension("tmp");
        let file = fs::File::create(&temp_path)
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;
            
        let k_str = key.primary_key_str().unwrap_or("unknown").to_string();
        let hash = hex::encode(&k_str);
        let ttl = meta.fresh_until().duration_since(meta.created()).map(|d| d.as_secs()).unwrap_or(3600);

        Ok(Box::new(FileMissHandler { 
            file, 
            written: 0, 
            final_path: path, 
            temp_path,
            hash,
            ttl,
            key_str: k_str,
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
        _key: &CacheKey,
        _meta: &CacheMeta,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        Ok(true)
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

struct FileHitHandler {
    file: Arc<std::fs::File>,
    offset: u64,
}

#[async_trait]
impl HandleHit for FileHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut buf = vec![0u8; 128 * 1024]; 
        let file = self.file.clone();
        let offset = self.offset;

        let n = tokio::task::block_in_place(|| {
            let mut f = &*file;
            f.seek(SeekFrom::Start(offset)).map_err(|_| Error::new(ErrorType::InternalError))?;
            f.read(&mut buf).map_err(|_| Error::new(ErrorType::InternalError))
        })?;

        if n == 0 {
            Ok(None)
        } else {
            self.offset += n as u64;
            Ok(Some(bytes::Bytes::from(buf[..n].to_vec())))
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
    file: fs::File,
    written: usize,
    final_path: PathBuf,
    temp_path: PathBuf,
    hash: String,
    key_str: String,
    ttl: u64,
}

#[async_trait]
impl HandleMiss for FileMissHandler {
    async fn write_body(&mut self, data: bytes::Bytes, _eof: bool) -> Result<()> {
        let compressed = if data.len() > 512 {
            zstd::encode_all(data.as_ref(), 3).unwrap_or_else(|_| data.to_vec())
        } else {
            data.to_vec()
        };

        self.file
            .write_all(&compressed)
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;
        self.written += data.len();
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        drop(self.file);
        
        fs::rename(&self.temp_path, &self.final_path)
            .await
            .map_err(|_| Error::new(ErrorType::InternalError))?;

        crate::metrics::storage::STORAGE.update_cache_meta(&self.hash, &self.key_str, self.written as u64, self.ttl);

        Ok(MissFinishType::Created(self.written))
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
                self.max_disk_bytes.store(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        
        if let Some(options) = &policy.options {
            if let Some(hot) = options.get("hotThreshold").and_then(|v| v.as_u64()) {
                self.hot_threshold.store(hot as u32, std::sync::atomic::Ordering::Relaxed);
            }

            let min_free_setting = if let Some(min_free) = options.get("minFreeSpace") {
                crate::config_models::SizeCapacity::from_json(min_free).to_bytes()
            } else {
                0
            };

            let mut final_min_free = min_free_setting as u64;
            if final_min_free == 0 {
                let main_path = options.get("dir").and_then(|v| v.as_str()).map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("data/cache"));
                
                let disks = sysinfo::Disks::new_with_refreshed_list();
                let disk_size = disks.iter()
                    .find(|d| main_path.starts_with(d.mount_point()))
                    .map(|d| d.total_space())
                    .unwrap_or(100 * 1024 * 1024 * 1024);

                let auto_min = (disk_size / 20)
                    .max(1024 * 1024 * 1024)
                    .min(10 * 1024 * 1024 * 1024);
                
                info!("RPC_CACHE: Using auto-calculated min free space: {} bytes", auto_min);
                final_min_free = auto_min;
            } else {
                info!("RPC_CACHE: Using policy specified min free space: {} bytes", final_min_free);
            }
            self.min_free_bytes.store(final_min_free, std::sync::atomic::Ordering::Relaxed);

            let main_dir = options.get("dir").and_then(|v| v.as_str()).map(PathBuf::from);
            let sub_dirs = options.get("subDirs").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(PathBuf::from).collect::<Vec<_>>());
            
            let enable_sendfile = options.get("enableSendfile").and_then(|v| v.as_bool()).unwrap_or(true);
            let enable_file_cache = options.get("enableOpenFileCache").and_then(|v| v.as_bool()).unwrap_or(true);

            if let Some(main) = main_dir {
                info!("RPC_CACHE: Updating cache configuration (Sendfile: {}, HandleCache: {})", enable_sendfile, enable_file_cache);
                self.l2.update_config(main, sub_dirs.unwrap_or_default(), enable_sendfile, enable_file_cache).await;
            }
        }
    }

    pub async fn purge_by_key(&self, key: &str) -> bool {
        let hash = hex::encode(key);
        let lock = self.l2.inner.read().await;
        let path = lock.main_root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
        let _ = fs::remove_file(&path).await;
        crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
        
        let ck = CacheKey::new("edge", key, "").to_compact();
        // Use Global CACHE to bypass E0597
        tokio::spawn(async move {
            let trace = pingora_cache::trace::Span::inactive().handle();
            let _ = crate::cache_manager::CACHE.storage.l1.purge(&ck, PurgeType::Invalidation, &trace).await;
        });
        true
    }

    pub async fn purge_by_prefix(&self, prefix: &str) -> bool {
        let clean_prefix = prefix.trim_end_matches('*');
        let mut deleted_count = 0;
        
        let iter = crate::metrics::storage::STORAGE.scan_prefix("CMETA_");
        for (meta_key, _val) in iter {
            let hash = meta_key.strip_prefix("CMETA_").unwrap_or(&meta_key);
            if let Some(meta) = crate::metrics::storage::STORAGE.get_cache_meta(hash) {
                if let Some(k) = meta["k"].as_str() {
                    if k.starts_with(clean_prefix) {
                        let lock = self.l2.inner.read().await;
                        let path = lock.main_root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
                        let _ = fs::remove_file(&path).await;
                        crate::metrics::storage::STORAGE.delete_cache_meta(hash);
                        deleted_count += 1;
                    }
                }
            }
        }
        info!("RPC_CACHE: Purged {} items matching prefix: {}", deleted_count, prefix);
        true
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
        let hash = hex::encode(k_str);

        if *p_type == "memory" {
            return self.l1.lookup(key, trace).await;
        }

        if let Some(hit) = self.l1.lookup(key, trace).await? {
            return Ok(Some(hit));
        }

        if let Some((meta, handler)) = self.l2.lookup(key, trace).await? {
            let threshold = self.hot_threshold.load(std::sync::atomic::Ordering::Relaxed);
            let mut is_hot = false;
            self.hot_counts.entry(hash.clone())
                .and_modify(|c| {
                    *c += 1;
                    if *c >= threshold { is_hot = true; }
                })
                .or_insert(1);

            if is_hot {
                let storage_l2 = self.l2;
                let cache_key_cloned = key.clone();
                tokio::spawn(async move {
                    let path = storage_l2.get_path(&cache_key_cloned).await;
                    if let Ok(attr) = tokio::fs::metadata(&path).await {
                        if attr.len() > 0 && attr.len() < 2 * 1024 * 1024 {
                            if let Ok(mut file) = tokio::fs::File::open(&path).await {
                                use tokio::io::AsyncReadExt;
                                let mut buffer = Vec::with_capacity(attr.len() as usize);
                                if file.read_to_end(&mut buffer).await.is_ok() {
                                    let header = pingora_http::ResponseHeader::build(200, None).unwrap();
                                    let new_meta = CacheMeta::new(
                                        std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                                        std::time::SystemTime::now(),
                                        0,
                                        0,
                                        header,
                                    );
                                    let trace = pingora_cache::trace::Span::inactive().handle();
                                    // Use Global CACHE to bypass E0597
                                    let _ = crate::cache_manager::CACHE.storage.l1.get_miss_handler(&cache_key_cloned, &new_meta, &trace).await;
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
            let min_free = self.min_free_bytes.load(std::sync::atomic::Ordering::Relaxed);
            
            let disks = sysinfo::Disks::new_with_refreshed_list();
            let available = disks.iter()
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

pub async fn start_cache_purger(storage: &'static HybridStorage, disk_root: PathBuf) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

    loop {
        interval.tick().await;
        let now = chrono::Utc::now().timestamp();
        let max_bytes = storage.max_disk_bytes.load(std::sync::atomic::Ordering::Relaxed);
        
        let mut all_meta = Vec::new();
        let iter = crate::metrics::storage::STORAGE.scan_prefix("CMETA_");
        for (key, _val) in iter {
            let hash = key.strip_prefix("CMETA_").unwrap_or(&key);
            if let Some(meta) = crate::metrics::storage::STORAGE.get_cache_meta(hash) {
                all_meta.push((hash.to_string(), meta));
            }
        }

        all_meta.sort_by_key(|m| m.1["a"].as_i64().unwrap_or(0));

        let mut current_size: u64 = all_meta.iter().map(|m| m.1["s"].as_u64().unwrap_or(0)).sum();

        for (hash, meta) in all_meta {
            let expires = meta["e"].as_i64().unwrap_or(0);
            let size = meta["s"].as_u64().unwrap_or(0);

            if now > expires || (max_bytes > 0 && current_size > max_bytes) {
                let hash_hex = hash.clone();
                let path = disk_root.join(&hash_hex[0..2]).join(&hash_hex[2..4]).join(&hash_hex);
                
                let _ = fs::remove_file(&path).await;
                crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
                current_size = current_size.saturating_sub(size);
            }
        }
    }
}
