use dashmap::DashMap;
use once_cell::sync::Lazy;
use rocksdb::{DB, MergeOperands, Options, WriteBatch};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use tracing::error;

/// A specialized storage engine for metrics based on RocksDB.
pub struct MetricStorage {
    db: Option<Arc<DB>>,
}

/// A simple sum operator for RocksDB merge
fn sum_merge_operator(
    _new_key: &[u8],
    existing_value: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
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
            Ok(db) => Ok(Self {
                db: Some(Arc::new(db)),
            }),
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("Resource temporarily unavailable") {
                    error!(
                        "RocksDB LOCK error: The database is already in use by another process."
                    );
                    error!("Please run 'pkill -9 cloud-node-rust' and then try again.");
                }
                Err(anyhow::anyhow!("Failed to open RocksDB: {}", e))
            }
        }
    }

    pub fn unavailable() -> Self {
        Self { db: None }
    }

    pub fn record_server_batch(
        &self,
        period: i64,
        updates: Vec<crate::rpc::metrics::ServerMetricUpdate>,
        node_sent: u64,
        node_received: u64,
    ) {
        let Some(db) = &self.db else {
            return;
        };
        let mut batch = WriteBatch::default();

        for u in updates {
            let prefix = format!("S{}_T{}", u.server_id, period);
            
            // Store delta-based counters using merge operator
            batch.merge(format!("{}_req", prefix).as_bytes(), u.total_requests.to_be_bytes());
            batch.merge(format!("{}_sent", prefix).as_bytes(), u.bytes_sent.to_be_bytes());
            batch.merge(format!("{}_recv", prefix).as_bytes(), u.bytes_received.to_be_bytes());
            batch.merge(format!("{}_cached_sent", prefix).as_bytes(), u.cached_bytes.to_be_bytes());
            batch.merge(format!("{}_cached_req", prefix).as_bytes(), u.count_cached_requests.to_be_bytes());
            batch.merge(format!("{}_attack_req", prefix).as_bytes(), u.count_attack_requests.to_be_bytes());
            batch.merge(format!("{}_attack_sent", prefix).as_bytes(), u.attack_bytes.to_be_bytes());
            
            // Store gauge values using put
            batch.put(format!("{}_conns", prefix).as_bytes(), u.active_connections.to_be_bytes());
            batch.put(format!("{}_ips", prefix).as_bytes(), u.count_ips.to_be_bytes());
        }

        let node_prefix = format!("NODE_T{}", period);
        batch.merge(format!("{}_sent", node_prefix).as_bytes(), node_sent.to_be_bytes());
        batch.merge(format!("{}_recv", node_prefix).as_bytes(), node_received.to_be_bytes());

        let _ = db.write(batch);
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
            if (key_str.starts_with("S") && &*key_str < end_prefix.as_str())
                || (key_str.starts_with("NODE_T")
                    && &*key_str < format!("NODE_T{}", older_than_timestamp).as_str())
            {
                batch.delete(&key);
            } else if &*key_str >= "Z" {
                break;
            }
        }
        let _ = db.write(batch);
    }

    /// Cache Metadata Management
    pub fn update_cache_meta(
        &self,
        hash: &str,
        key_str: &str,
        size: u64,
        ttl_secs: u64,
        headers: Option<serde_json::Value>,
        compressed: bool,
        status: u16,
    ) {
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
        let _ = db.put(
            format!("CMETA_{}", hash).as_bytes(),
            meta.to_string().as_bytes(),
        );
    }

    /// Records a cache access in memory only — no RocksDB I/O on the hot path.
    /// Access timestamps and counts are flushed to RocksDB periodically by the background task.
    pub fn record_cache_access(&self, hash: &str) {
        let now = crate::utils::time::now_timestamp();
        CACHE_ACCESS_LOG
            .entry(hash.to_string())
            .or_insert_with(|| (AtomicI64::new(now), AtomicU64::new(0)));
        if let Some(entry) = CACHE_ACCESS_LOG.get(hash) {
            entry.0.store(now, Ordering::Relaxed);
            entry.1.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Flush in-memory access logs to RocksDB. Called by background task every 30s.
    pub fn flush_cache_accesses(&self) {
        let Some(db) = &self.db else {
            return;
        };
        if CACHE_ACCESS_LOG.is_empty() {
            return;
        }
        let mut batch = WriteBatch::default();
        for entry in CACHE_ACCESS_LOG.iter() {
            let hash = entry.key();
            let (access_ts, access_cnt) = entry.value();
            let now = crate::utils::time::now_timestamp();
            let cnt = access_cnt.swap(0, Ordering::Relaxed);
            let ts = access_ts.load(Ordering::Relaxed);
            if cnt == 0 {
                continue;
            }
            let db_key = format!("CMETA_{}", hash);
            if let Ok(Some(val)) = db.get(db_key.as_bytes())
                && let Ok(mut meta) = serde_json::from_slice::<serde_json::Value>(&val)
            {
                meta["a"] = serde_json::json!(ts);
                if let Some(f) = meta["f"].as_u64() {
                    meta["f"] = serde_json::json!(f + cnt);
                }
                batch.put(db_key.as_bytes(), meta.to_string().as_bytes());
            }
            // Stale entries without backing RocksDB data are silently dropped
            let _ = now; // suppress unused warning
        }
        let _ = db.write(batch);
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
        let _ = db.put(
            format!("WAFTOK_{}", token).as_bytes(),
            val.to_string().as_bytes(),
        );
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
        self.cache_summary().1
    }

    pub fn total_cache_count(&self) -> usize {
        self.cache_summary().0
    }

    pub fn cache_summary(&self) -> (usize, u64) {
        let mut count = 0usize;
        let mut size = 0u64;
        let Some(db) = &self.db else {
            return (0, 0);
        };

        let iter = db.prefix_iterator("CMETA_".as_bytes());
        for (key, val) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with("CMETA_") {
                break;
            }
            if let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&val) {
                count += 1;
                size += meta["s"].as_u64().unwrap_or(0);
            }
        }
        (count, size)
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
    where
        F: FnMut(String, serde_json::Value),
    {
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
                let hash = key_str
                    .strip_prefix("CMETA_")
                    .unwrap_or(&key_str)
                    .to_string();
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
                let hash = key_str
                    .strip_prefix("CMETA_")
                    .unwrap_or(&key_str)
                    .to_string();
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
    let path = "../data/metrics.db";
    match MetricStorage::open(path) {
        Ok(storage) => storage,
        Err(err) => {
            error!(
                "Failed to open RocksDB for metrics, metrics storage disabled: {}",
                err
            );
            MetricStorage::unavailable()
        }
    }
});

/// In-memory cache access tracker: hash → (last_access_timestamp, access_count)
/// Eliminates synchronous RocksDB I/O from the cache HIT hot path.
static CACHE_ACCESS_LOG: Lazy<DashMap<String, (AtomicI64, AtomicU64)>> = Lazy::new(DashMap::new);

/// Start a background task that flushes in-memory cache access logs to RocksDB every 30 seconds.
pub fn start_cache_access_flusher() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            STORAGE.flush_cache_accesses();
        }
    });
}
