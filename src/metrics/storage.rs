use rocksdb::{DB, Options, WriteBatch, MergeOperands};
use std::path::Path;
use std::sync::Arc;
use once_cell::sync::Lazy;
use tracing::error;

/// A specialized storage engine for metrics based on RocksDB.
pub struct MetricStorage {
    db: Option<Arc<DB>>,
}

/// A simple sum operator for RocksDB merge
fn sum_merge_operator(_new_key: &[u8], existing_value: Option<&[u8]>, operands: &MergeOperands) -> Option<Vec<u8>> {
    let mut sum = existing_value
        .and_then(|v| {
            if v.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(v);
                Some(u64::from_be_bytes(buf))
            } else {
                None
            }
        })
        .unwrap_or(0);

    for op in operands {
        if op.len() == 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(op);
            sum = sum.saturating_add(u64::from_be_bytes(buf));
        }
    }

    Some(sum.to_be_bytes().to_vec())
}

impl MetricStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_merge_operator_associative("sum", sum_merge_operator);
        // Optimize for write-heavy metrics
        opts.set_use_direct_io_for_flush_and_compaction(true);
        opts.set_max_background_jobs(4);
        
        match DB::open(&opts, path) {
            Ok(db) => Ok(Self { db: Some(Arc::new(db)) }),
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("Resource temporarily unavailable") {
                    error!("RocksDB LOCK error: The database is already in use by another process.");
                    error!("Please run 'pkill -9 cloud-node-rust' and then try again.");
                }
                Err(anyhow::anyhow!("Failed to open RocksDB: {}", e))
            }
        }
    }

    pub fn unavailable() -> Self {
        Self { db: None }
    }

    /// Increments multiple counters in a single atomic batch.
    pub fn increment_batch(&self, updates: Vec<(String, u64)>) {
        let Some(db) = &self.db else {
            return;
        };
        let mut batch = WriteBatch::default();
        for (key, delta) in updates {
            batch.merge(key.as_bytes(), delta.to_be_bytes());
        }
        let _ = db.write(batch);
    }

    /// Deletes all data older than a specific timestamp.
    pub fn cleanup_old_stats(&self, older_than_timestamp: i64) {
        let Some(db) = &self.db else {
            return;
        };
        // RocksDB delete_range is often CF-specific or version-dependent in the Rust wrapper.
        // For maximum compatibility across environments, we use a scan-and-delete approach for small ranges,
        // or a WriteBatch with delete_range if available.
        let mut batch = WriteBatch::default();
        let end_prefix = format!("S0_T{}", older_than_timestamp);
        // We use a manual scan and delete for now to ensure compatibility
        let iter = db.iterator(rocksdb::IteratorMode::Start);
        for (key, _) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key);
            if (key_str.starts_with("S") && &*key_str < end_prefix.as_str()) || 
               (key_str.starts_with("NODE_T") && &*key_str < format!("NODE_T{}", older_than_timestamp).as_str()) {
                batch.delete(&key);
            } else if &*key_str >= "Z" { 
                break;
            }
        }
        let _ = db.write(batch);
    }

    /// Cache Metadata Management
    pub fn update_cache_meta(&self, hash: &str, key_str: &str, size: u64, ttl_secs: u64, headers: Option<serde_json::Value>, compressed: bool, status: u16) {
        let Some(db) = &self.db else {
            return;
        };
        let now = crate::utils::time::now_timestamp();
        let meta = serde_json::json!({
            "k": key_str,
            "s": size,
            "e": now + ttl_secs as i64,
            "a": now,
            "f": 1,
            "st": status,
            "h": headers.unwrap_or(serde_json::json!({})),
            "c": compressed
        });
        let _ = db.put(format!("CMETA_{}", hash).as_bytes(), meta.to_string().as_bytes());
    }

    pub fn record_cache_access(&self, hash: &str) {
        let Some(db) = &self.db else {
            return;
        };
        let key = format!("CMETA_{}", hash);
        if let Ok(Some(val)) = db.get(key.as_bytes())
            && let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&val) {
                let now = crate::utils::time::now_timestamp();
                meta["a"] = serde_json::json!(now);
                if let Some(f) = meta["f"].as_u64() {
                    meta["f"] = serde_json::json!(f + 1);
                }
                let _ = db.put(key.as_bytes(), meta.to_string().as_bytes());
            }
    }

    pub fn get_cache_meta(&self, hash: &str) -> Option<serde_json::Value> {
        let db = self.db.as_ref()?;
        db.get(format!("CMETA_{}", hash).as_bytes())
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
    }

    pub fn delete_cache_meta(&self, hash: &str) {
        let Some(db) = &self.db else {
            return;
        };
        let _ = db.delete(format!("CMETA_{}", hash).as_bytes());
    }

    /// WAF Token Persistence
    pub fn save_waf_token(&self, token: &str, ip: &str, ua_hash: &str, expired_at: u64) {
        let Some(db) = &self.db else {
            return;
        };
        let val = serde_json::json!({
            "ip": ip,
            "ua": ua_hash,
            "exp": expired_at
        });
        let _ = db.put(format!("WAFTOK_{}", token).as_bytes(), val.to_string().as_bytes());
    }

    pub fn get_waf_token(&self, token: &str) -> Option<serde_json::Value> {
        let db = self.db.as_ref()?;
        db.get(format!("WAFTOK_{}", token).as_bytes())
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
    }

    pub fn delete_waf_token(&self, token: &str) {
        let Some(db) = &self.db else {
            return;
        };
        let _ = db.delete(format!("WAFTOK_{}", token).as_bytes());
    }

    pub fn total_cache_size(&self) -> u64 {
        let mut total = 0u64;
        let Some(db) = &self.db else {
            return 0;
        };
        
        let iter = db.prefix_iterator("CMETA_".as_bytes());
        for (key, val) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with("CMETA_") {
                break;
            }
            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&val) {
                total += meta["s"].as_u64().unwrap_or(0);
            }
        }
        total
    }

    pub fn total_cache_count(&self) -> usize {
        let mut count = 0usize;
        let Some(db) = &self.db else {
            return 0;
        };
        let iter = db.prefix_iterator("CMETA_".as_bytes());
        for (key, _) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key).to_string();
            if !key_str.starts_with("CMETA_") {
                break;
            }
            count += 1;
        }
        count
    }

    pub fn get_value(&self, key: &str) -> u64 {
        let Some(db) = &self.db else {
            return 0;
        };
        db.get(key.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&v);
                    Some(u64::from_be_bytes(buf))
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    pub fn delete_key(&self, key: &str) {
        let Some(db) = &self.db else {
            return;
        };
        let _ = db.delete(key.as_bytes());
    }

    /// Iterates over all cache metadata efficiently using a closure.
    pub fn for_each_cache_meta<F>(&self, mut f: F) 
    where F: FnMut(String, serde_json::Value) {
        let Some(db) = &self.db else {
            return;
        };
        let iter = db.prefix_iterator("CMETA_".as_bytes());
        for (key, val) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with("CMETA_") {
                break;
            }
            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&val) {
                let hash = key_str.strip_prefix("CMETA_").unwrap_or(&key_str).to_string();
                f(hash, meta);
            }
        }
    }

    /// Scans all cache metadata, returning a vector of (hash, metadata_json)
    pub fn scan_all_cache_meta(&self) -> Vec<(String, serde_json::Value)> {
        let Some(db) = &self.db else {
            return Vec::new();
        };
        let mut results = Vec::new();
        let iter = db.prefix_iterator("CMETA_".as_bytes());
        for (key, val) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key).to_string();
            if !key_str.starts_with("CMETA_") {
                break;
            }
            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&val) {
                let hash = key_str.strip_prefix("CMETA_").unwrap_or(&key_str).to_string();
                results.push((hash, meta));
            }
        }
        results
    }

    /// Scans keys with a prefix, useful for extracting metrics for a specific server or period.
    pub fn scan_prefix(&self, prefix: &str) -> Vec<(String, u64)> {
        let Some(db) = &self.db else {
            return Vec::new();
        };
        let mut results = Vec::new();
        let iter = db.prefix_iterator(prefix.as_bytes());
        for (key, val) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key).to_string();
            if !key_str.starts_with(prefix) {
                break;
            }
            if val.len() == 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&val);
                results.push((key_str, u64::from_be_bytes(buf)));
            }
        }
        results
    }
}

pub static STORAGE: Lazy<MetricStorage> = Lazy::new(|| {
    let path = "data/metrics.db";
    match MetricStorage::open(path) {
        Ok(storage) => storage,
        Err(err) => {
            error!("Failed to open RocksDB for metrics, metrics storage disabled: {}", err);
            MetricStorage::unavailable()
        }
    }
});
