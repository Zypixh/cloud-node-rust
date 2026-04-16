pub use crate::cache_hybrid::HybridStorage;
use pingora_cache::CacheMeta;
use pingora_core::Result;

/// Central manager for Pingora-based caching in GoEdge Node
pub struct CacheManager {
    pub storage: &'static HybridStorage,
}

impl CacheManager {
    pub fn new(max_memory_bytes: usize) -> Self {
        // HybridStorage uses L1 (Memory) and L2 (Disk at configs/cache/disk)
        Self {
            storage: Box::leak(Box::new(HybridStorage::new(
                max_memory_bytes,
                "configs/cache/disk",
            ))),
        }
    }

    /// Purges a specific key from the cache
    pub async fn purge_key(&self, key: &str) -> Result<bool> {
        Ok(self.storage.purge_by_key(key).await)
    }

    /// Purges all keys starting with a prefix
    pub async fn purge_prefix(&self, prefix: &str) -> Result<bool> {
        Ok(self.storage.purge_by_prefix(prefix).await)
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
