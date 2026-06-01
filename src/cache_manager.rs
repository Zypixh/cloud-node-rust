pub use crate::cache_hybrid::HybridStorage;
use bytes::Bytes;
use pingora_cache::storage::Storage;
use pingora_cache::{CacheKey, CacheMeta};
use pingora_core::Result;
use pingora_http::ResponseHeader;
use std::time::{Duration, SystemTime};

/// Central manager for Pingora-based node caching.
pub struct CacheManager {
    pub storage: &'static HybridStorage,
}

impl CacheManager {
    pub fn new(max_memory_bytes: usize) -> Self {
        let cache_dir = crate::paths::NodePaths::current().cache_dir();
        Self {
            storage: Box::leak(Box::new(HybridStorage::new(
                max_memory_bytes,
                cache_dir.to_string_lossy().as_ref(),
            ))),
        }
    }

    /// Purges a specific key from the cache
    pub async fn purge_key(&'static self, key: &str) -> Result<bool> {
        Ok(self.storage.purge_by_key(key).await)
    }

    /// Purges all keys starting with a prefix
    pub async fn purge_prefix(&'static self, prefix: &str) -> Result<bool> {
        Ok(self.storage.purge_by_prefix(prefix).await)
    }

    pub async fn write_value(
        &'static self,
        key: &str,
        value: &[u8],
        ttl_secs: u64,
    ) -> anyhow::Result<usize> {
        let cache_key = CacheKey::new("", key, key);
        let now = SystemTime::now();
        let fresh_until = now + Duration::from_secs(ttl_secs);
        let mut header = ResponseHeader::build(200, Some(1))?;
        header.insert_header("content-length", value.len().to_string())?;
        let meta = CacheMeta::new(fresh_until, now, 0, 0, header);
        let trace = pingora_cache::trace::Span::inactive().handle();
        let mut handler = self
            .storage
            .get_miss_handler(&cache_key, &meta, &trace)
            .await?;
        handler
            .write_body(Bytes::copy_from_slice(value), true)
            .await?;
        let _ = handler.finish().await?;
        Ok(value.len())
    }

    pub async fn read_value_size(&'static self, key: &str) -> anyhow::Result<Option<u64>> {
        let hash = format!("{:x}", md5_legacy::compute(key));
        if let Some(meta) = crate::metrics::storage::STORAGE.get_cache_meta(&hash) {
            return Ok(Some(meta.size));
        }

        let cache_key = CacheKey::new("", key, key);
        let trace = pingora_cache::trace::Span::inactive().handle();
        Ok(self.storage.lookup(&cache_key, &trace).await?.map(|_| 0))
    }

    pub async fn clean_all(&'static self) -> anyhow::Result<usize> {
        let keys = crate::metrics::storage::STORAGE
            .scan_all_cache_meta()
            .into_iter()
            .map(|(_, meta)| meta.cache_key)
            .collect::<Vec<_>>();
        let mut count = 0usize;
        for key in keys {
            if self.storage.purge_by_key(&key).await {
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Global cache manager singleton
pub static CACHE: once_cell::sync::Lazy<CacheManager> = once_cell::sync::Lazy::new(|| {
    CacheManager::new(1024 * 1024 * 512) // Default 512MB memory cache
});

/// Shared utilities for cache metadata creation
pub fn create_meta(status: u16, ttl_seconds: u64) -> CacheMeta {
    let now = std::time::SystemTime::now();
    let fresh_until = now + std::time::Duration::from_secs(ttl_seconds);
    let header = pingora_http::ResponseHeader::build(status, None).unwrap();
    CacheMeta::new(fresh_until, now, 0, 0, header)
}
