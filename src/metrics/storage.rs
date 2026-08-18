use super::mace_backend::{DB, IteratorMode, WriteBatch};
use dashmap::DashMap;
use maxminddb::{self, geoip2};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{LazyLock as Lazy, OnceLock};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, warn};

const CACHE_META_QUEUE_CAPACITY: usize = 8192;
const STATS_CLEANUP_BATCH_SIZE: usize = 512;

/// A specialized storage engine for metrics backed by Mace.
pub struct MetricStorage {
    db: Option<Arc<DB>>,
}

impl MetricStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        match DB::open(path) {
            Ok(db) => Ok(Self {
                db: Some(Arc::new(db)),
            }),
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("Resource temporarily unavailable") {
                    error!("Mace storage is already in use by another process.");
                }
                Err(anyhow::anyhow!("Failed to open Mace storage: {}", e))
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
            batch.merge(
                format!("{}_req", prefix).as_bytes(),
                u.total_requests.to_be_bytes(),
            );
            batch.merge(
                format!("{}_sent", prefix).as_bytes(),
                u.bytes_sent.to_be_bytes(),
            );
            batch.merge(
                format!("{}_recv", prefix).as_bytes(),
                u.bytes_received.to_be_bytes(),
            );
            batch.merge(
                format!("{}_cached_sent", prefix).as_bytes(),
                u.cached_bytes.to_be_bytes(),
            );
            batch.merge(
                format!("{}_cached_req", prefix).as_bytes(),
                u.count_cached_requests.to_be_bytes(),
            );
            batch.merge(
                format!("{}_attack_req", prefix).as_bytes(),
                u.count_attack_requests.to_be_bytes(),
            );
            batch.merge(
                format!("{}_attack_sent", prefix).as_bytes(),
                u.attack_bytes.to_be_bytes(),
            );

            // Store gauge values using put
            batch.put(
                format!("{}_conns", prefix).as_bytes(),
                u.active_connections.to_be_bytes(),
            );
            batch.put(
                format!("{}_ips", prefix).as_bytes(),
                u.count_ips.to_be_bytes(),
            );
        }

        let node_prefix = format!("NODE_T{}", period);
        batch.merge(
            format!("{}_sent", node_prefix).as_bytes(),
            node_sent.to_be_bytes(),
        );
        batch.merge(
            format!("{}_recv", node_prefix).as_bytes(),
            node_received.to_be_bytes(),
        );

        if let Err(err) = db.write(&batch) {
            error!(error = %err, "Mace metrics batch write failed");
        }
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
        if let Err(err) = db.write(&batch) {
            error!(error = %err, "Mace counter batch write failed");
        }
    }

    /// Deletes all data older than a specific timestamp.
    pub fn cleanup_old_stats(&self, older_than_timestamp: i64) {
        let Some(db) = &self.db else {
            return;
        };
        // Delete by scan to keep retention behavior independent of engine range-delete semantics.
        // Compare the parsed period, not the complete key: lexical ordering by server id makes
        // keys such as S7_T... invisible when the old S0_T... sentinel is used.
        let mut batch = WriteBatch::default();
        let mut deleted = 0usize;
        let iter = db.iterator(IteratorMode::Start);
        for (key, _) in iter.flatten() {
            if stats_period_from_key(&key).is_some_and(|period| period < older_than_timestamp) {
                batch.delete(&key);
                deleted += 1;
                if deleted >= STATS_CLEANUP_BATCH_SIZE {
                    if let Err(err) = db.write(&batch) {
                        error!(error = %err, deleted, "Mace stats cleanup batch write failed");
                    }
                    batch = WriteBatch::default();
                    deleted = 0;
                }
            }
        }
        if deleted > 0
            && let Err(err) = db.write(&batch)
        {
            error!(error = %err, deleted, "Mace stats cleanup write failed");
        }
    }

    pub fn put_json<T: Serialize>(&self, key: &str, value: &T) -> bool {
        let Some(db) = &self.db else {
            return false;
        };
        match serde_json::to_vec(value) {
            Ok(bytes) => db.put(key.as_bytes(), bytes).is_ok(),
            Err(_) => false,
        }
    }

    pub fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let Some(db) = &self.db else {
            return None;
        };
        db.get(key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    pub fn record_unique_ip(&self, server_id: i64, day: &str, ip: IpAddr) {
        let Some(db) = &self.db else {
            return;
        };
        if server_id <= 0 || day.is_empty() {
            return;
        }
        let key = unique_ip_key(server_id, day, ip);
        if let Some(tx) = UNIQUE_IP_WRITER_TX.get() {
            match tx.try_send((key, Vec::new())) {
                Ok(()) => return,
                Err(TrySendError::Full(_)) => {
                    let dropped = UNIQUE_IP_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                    if dropped.is_power_of_two() {
                        warn!(dropped, "Mace unique-IP writer queue is full");
                    }
                    return;
                }
                Err(TrySendError::Disconnected(_)) => {
                    error!(server_id, day, "Mace unique-IP writer queue is closed");
                    return;
                }
            }
        }
        if let Err(err) = db.put(key.as_bytes(), []) {
            error!(error = %err, server_id, day, "Mace unique-IP write failed");
        }
    }

    pub fn load_unique_ips(&self, min_day: &str) -> Vec<(i64, String, IpAddr)> {
        let Some(db) = &self.db else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        let iter = db.prefix_iterator("UIP_".as_bytes());
        for (key, _) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with("UIP_") {
                break;
            }
            if let Some((server_id, day, ip)) = parse_unique_ip_key(&key_str)
                && day.as_str() >= min_day
            {
                rows.push((server_id, day, ip));
            }
        }
        rows
    }

    pub fn cleanup_unique_ips_before(&self, min_day: &str) {
        let Some(db) = &self.db else {
            return;
        };
        let mut batch = WriteBatch::default();
        let iter = db.prefix_iterator("UIP_".as_bytes());
        for (key, _) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with("UIP_") {
                break;
            }
            if let Some((_, day, _)) = parse_unique_ip_key(&key_str)
                && day.as_str() < min_day
            {
                batch.delete(&key);
            }
        }
        if let Err(err) = db.write(&batch) {
            error!(error = %err, "Mace unique-IP cleanup write failed");
        }
    }

    /// Cache Metadata Management
    pub fn update_cache_meta(
        &self,
        hash: &str,
        key_str: &str,
        size: u64,
        ttl_secs: u64,
        headers: &[(String, String)],
        compressed: bool,
        status: u16,
    ) {
        let now = crate::utils::time::now_timestamp();
        self.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash,
            cache_key: key_str,
            size,
            expires: now + ttl_secs as i64,
            access_time: now,
            access_count: 1,
            status,
            headers,
            compressed,
            shard_id: None,
            relative_path: None,
            event_version: None,
            updated_at: Some(now),
            stale_while_revalidate_secs: 0,
            created_at: now,
        });
    }

    pub fn upsert_cache_meta_absolute(&self, upsert: CacheMetaUpsert<'_>) {
        let meta = cache_meta_from_upsert(&upsert);
        apply_cache_meta_memory(upsert.hash, meta.clone());
        let Some(db) = &self.db else {
            return;
        };
        if let Err(err) = db.put(
            format!("CMETA_{}", upsert.hash).as_bytes(),
            cache_meta_json(&meta).to_string().as_bytes(),
        ) {
            error!(error = %err, hash = upsert.hash, "Mace cache metadata write failed");
        }
    }

    /// Applies metadata to the hot in-memory index, then waits for a bounded,
    /// dedicated Mace writer. The Tokio reactor never performs the sync write.
    pub async fn upsert_cache_meta_absolute_async(&self, upsert: CacheMetaUpsert<'_>) -> bool {
        let meta = cache_meta_from_upsert(&upsert);
        apply_cache_meta_memory(upsert.hash, meta.clone());

        let Some(tx) = CACHE_META_WRITER_TX.get() else {
            warn!(
                hash = upsert.hash,
                "Mace cache metadata writer is not started"
            );
            return false;
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if tx
            .send(CacheMetaWrite::Upsert {
                hash: upsert.hash.to_string(),
                meta,
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            error!(
                hash = upsert.hash,
                "Mace cache metadata writer queue is closed"
            );
            return false;
        }
        ack_rx.await.unwrap_or(false)
    }

    /// Records a cache access in memory only — no Mace I/O on the hot path.
    /// Access timestamps and counts are flushed periodically by the background task.
    pub fn record_cache_access(&self, hash: &str) {
        record_cache_access_memory(hash);
    }

    /// Flush in-memory access logs to Mace. Called by background task every 30s.
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
            let cnt = access_cnt.swap(0, Ordering::Relaxed);
            let ts = access_ts.load(Ordering::Relaxed);
            if cnt == 0 {
                continue;
            }
            // Read from the in-memory index, then update both memory and Mace.
            if let Some(mut meta) = CACHE_META_INDEX.get(hash).map(|v| v.clone()) {
                meta.access_time = ts;
                meta.access_count += cnt;
                // Write back to in-memory index so eviction/stats see updated access time
                CACHE_META_INDEX.insert(hash.clone(), meta.clone());
                // Persist to Mace.
                let db_key = format!("CMETA_{}", hash);
                batch.put(
                    db_key.as_bytes(),
                    cache_meta_json(&meta).to_string().as_bytes(),
                );
            }
        }
        if let Err(err) = db.write(&batch) {
            error!(error = %err, "Mace cache access flush failed");
        }
    }

    pub fn get_cache_meta(&self, hash: &str) -> Option<CacheMetaEntry> {
        get_cache_meta_memory(hash)
    }

    pub fn delete_cache_meta(&self, hash: &str) {
        remove_cache_meta_memory(hash);
        let Some(db) = &self.db else {
            return;
        };
        if let Err(err) = db.delete(format!("CMETA_{}", hash).as_bytes()) {
            error!(error = %err, hash, "Mace cache metadata delete failed");
        }
    }

    pub async fn delete_cache_meta_async(&self, hash: &str) -> bool {
        remove_cache_meta_memory(hash);

        let Some(tx) = CACHE_META_WRITER_TX.get() else {
            warn!(hash, "Mace cache metadata writer is not started");
            return false;
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if tx
            .send(CacheMetaWrite::Delete {
                hash: hash.to_string(),
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            error!(hash, "Mace cache metadata writer queue is closed");
            return false;
        }
        ack_rx.await.unwrap_or(false)
    }

    pub fn load_client_agent_ips(&self) -> Vec<crate::client_agent::ClientAgentIpRecord> {
        let Some(db) = &self.db else {
            return Vec::new();
        };
        let mut records = Vec::new();
        let iter = db.prefix_iterator("CAIP_IP_".as_bytes());
        for (key, val) in iter.flatten() {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with("CAIP_IP_") {
                break;
            }
            if let Some(record) = client_agent_ip_record_from_slice(&val) {
                records.push(record);
            }
        }
        records
    }

    pub fn get_client_agent_last_id(&self) -> i64 {
        let Some(db) = &self.db else {
            return 0;
        };
        db.get("CAIP_META_last_id".as_bytes())
            .ok()
            .flatten()
            .and_then(|v| {
                if v.len() == 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&v);
                    Some(i64::from_be_bytes(buf))
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    pub fn save_client_agent_ip(&self, record: &crate::client_agent::ClientAgentIpRecord) -> bool {
        let Some(db) = &self.db else {
            return true;
        };
        db.put(
            client_agent_ip_key(&record.ip).as_bytes(),
            client_agent_ip_json(record).to_string().as_bytes(),
        )
        .is_ok()
    }

    pub fn save_client_agent_ip_batch(
        &self,
        records: &[crate::client_agent::ClientAgentIpRecord],
        last_id: i64,
    ) -> bool {
        let Some(db) = &self.db else {
            return true;
        };
        let mut batch = WriteBatch::default();
        for record in records {
            batch.put(
                client_agent_ip_key(&record.ip).as_bytes(),
                client_agent_ip_json(record).to_string().as_bytes(),
            );
        }
        batch.put("CAIP_META_last_id".as_bytes(), last_id.to_be_bytes());
        db.write(&batch).is_ok()
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
        if let Err(err) = db.put(
            format!("WAFTOK_{}", token).as_bytes(),
            val.to_string().as_bytes(),
        ) {
            error!(error = %err, "Mace WAF token write failed");
        }
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
        if let Err(err) = db.delete(format!("WAFTOK_{}", token).as_bytes()) {
            error!(error = %err, "Mace WAF token delete failed");
        }
    }

    pub fn total_cache_size(&self) -> u64 {
        self.cache_summary().1
    }

    pub fn total_cache_count(&self) -> usize {
        self.cache_summary().0
    }

    pub fn cache_summary(&self) -> (usize, u64) {
        let count = CACHE_META_INDEX.len();
        let size = CACHE_META_INDEX
            .iter()
            .map(|entry| entry.value().size)
            .sum();
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
        if let Err(err) = db.delete(key.as_bytes()) {
            error!(error = %err, key, "Mace key delete failed");
        }
    }

    pub fn write_raw_batch(&self, puts: Vec<(String, Vec<u8>)>, deletes: Vec<String>) -> bool {
        let Some(db) = &self.db else {
            return false;
        };
        if puts.is_empty() && deletes.is_empty() {
            return true;
        }
        let mut batch = WriteBatch::default();
        for (key, value) in puts {
            batch.put(key.as_bytes(), value);
        }
        for key in deletes {
            batch.delete(key.as_bytes());
        }
        db.write(&batch).is_ok()
    }

    pub fn scan_json_prefix<T: DeserializeOwned>(&self, prefix: &str) -> Vec<(String, T)> {
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
            if let Ok(value) = serde_json::from_slice::<T>(&val) {
                results.push((key_str, value));
            }
        }
        results
    }

    /// Iterates over all cache metadata efficiently using a closure.
    pub fn for_each_cache_meta<F>(&self, mut f: F)
    where
        F: FnMut(String, &CacheMetaEntry),
    {
        for entry in CACHE_META_INDEX.iter() {
            f(entry.key().clone(), entry.value());
        }
    }

    /// Scans all cache metadata, returning a vector of (hash, metadata)
    pub fn scan_all_cache_meta(&self) -> Vec<(String, CacheMetaEntry)> {
        CACHE_META_INDEX
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
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
    let node_paths = crate::paths::NodePaths::current();
    let path = if let Some(config) = crate::runtime_mode::RuntimeConfig::current()
        && config.is_rke2()
    {
        let path = config.cluster.cache.local_meta_dir.join("metrics.mace");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        path
    } else {
        let canonical = node_paths.mace_metrics_db_dir();
        if !canonical.exists() && node_paths.legacy_mace_metrics_db_dir().exists() {
            let legacy = node_paths.legacy_mace_metrics_db_dir();
            tracing::warn!(
                "Using legacy Mace metrics path {}. New deployments should use {}.",
                legacy.display(),
                canonical.display()
            );
            legacy
        } else {
            let _ = std::fs::create_dir_all(node_paths.data_dir());
            canonical
        }
    };
    match MetricStorage::open(&path) {
        Ok(storage) => storage,
        Err(err) => {
            error!(
                "Failed to open Mace storage at {}, metrics storage disabled: {}",
                path.display(),
                err
            );
            MetricStorage::unavailable()
        }
    }
});

/// In-memory cache access tracker: hash → (last_access_timestamp, access_count)
/// Eliminates synchronous Mace I/O from the cache HIT hot path.
static CACHE_ACCESS_LOG: Lazy<DashMap<String, (AtomicI64, AtomicU64)>> = Lazy::new(DashMap::new);

pub struct CacheMetaUpsert<'a> {
    pub hash: &'a str,
    pub cache_key: &'a str,
    pub size: u64,
    pub expires: i64,
    pub access_time: i64,
    pub access_count: u64,
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub compressed: bool,
    pub shard_id: Option<&'a str>,
    pub relative_path: Option<&'a str>,
    pub event_version: Option<u64>,
    pub updated_at: Option<i64>,
    /// Value parsed from `Cache-Control: stale-while-revalidate=N` (0 = not set).
    pub stale_while_revalidate_secs: u64,
    /// Unix timestamp when this entry was first created.
    pub created_at: i64,
}

/// Typed cache metadata — avoids per-lookup JSON clone/parse overhead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheMetaEntry {
    pub cache_key: String,
    pub size: u64,
    pub expires: i64,
    pub access_time: i64,
    pub access_count: u64,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub compressed: bool,
    #[serde(default)]
    pub shard_id: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub event_version: Option<u64>,
    #[serde(default)]
    pub updated_at: i64,
    /// Seconds from `expires` during which the stale entry may be served while
    /// a background revalidation is in flight (RFC 5861 stale-while-revalidate).
    #[serde(default)]
    pub stale_while_revalidate_secs: u64,
    /// Unix timestamp when this entry was first created (used for weak ETag generation).
    #[serde(default)]
    pub created_at: i64,
}

enum CacheMetaWrite {
    Upsert {
        hash: String,
        meta: CacheMetaEntry,
        ack: oneshot::Sender<bool>,
    },
    Delete {
        hash: String,
        ack: oneshot::Sender<bool>,
    },
}

static CACHE_META_WRITER_TX: OnceLock<mpsc::Sender<CacheMetaWrite>> = OnceLock::new();
static UNIQUE_IP_WRITER_TX: OnceLock<SyncSender<(String, Vec<u8>)>> = OnceLock::new();
static UNIQUE_IP_DROPPED: AtomicU64 = AtomicU64::new(0);

/// In-memory cache metadata index: hash → typed metadata.
/// All cache lookups read from here, eliminating synchronous Mace reads on the hot path.
static CACHE_META_INDEX: Lazy<DashMap<String, CacheMetaEntry>> = Lazy::new(DashMap::new);

fn cache_meta_from_upsert(upsert: &CacheMetaUpsert<'_>) -> CacheMetaEntry {
    CacheMetaEntry {
        cache_key: upsert.cache_key.to_string(),
        size: upsert.size,
        expires: upsert.expires,
        access_time: upsert.access_time,
        access_count: upsert.access_count,
        status: normalize_cache_status(upsert.status),
        headers: upsert.headers.to_vec(),
        compressed: upsert.compressed,
        shard_id: upsert.shard_id.map(str::to_string),
        relative_path: upsert.relative_path.map(str::to_string),
        event_version: upsert.event_version,
        updated_at: upsert
            .updated_at
            .unwrap_or_else(crate::utils::time::now_timestamp),
        stale_while_revalidate_secs: upsert.stale_while_revalidate_secs,
        created_at: upsert.created_at,
    }
}

fn apply_cache_meta_memory(hash: &str, meta: CacheMetaEntry) {
    CACHE_META_INDEX.insert(hash.to_string(), meta.clone());
    crate::cache_hybrid::index_surrogate_keys(&meta.headers, hash);
    crate::cache_hybrid::on_cache_meta_upsert(&meta);
}

fn remove_cache_meta_memory(hash: &str) {
    let removed = CACHE_META_INDEX.remove(hash);
    if let Some((_, meta)) = &removed {
        crate::cache_hybrid::on_cache_meta_delete(&meta.cache_key);
    }
    crate::cache_hybrid::remove_hash_from_surrogate_index(hash);
    // Drop the access-log entry as well; otherwise it grows for every purged entry.
    CACHE_ACCESS_LOG.remove(hash);
}

fn start_cache_meta_writer() {
    let (tx, mut rx) = mpsc::channel(CACHE_META_QUEUE_CAPACITY);
    if CACHE_META_WRITER_TX.set(tx).is_err() {
        return;
    }

    let spawn_result = std::thread::Builder::new()
        .name("mace-cache-writer".to_string())
        .spawn(move || {
            while let Some(command) = rx.blocking_recv() {
                let result = match command {
                    CacheMetaWrite::Upsert { hash, meta, ack } => {
                        let result = STORAGE
                            .db
                            .as_ref()
                            .map(|db| {
                                db.put(
                                    format!("CMETA_{hash}").as_bytes(),
                                    cache_meta_json(&meta).to_string().as_bytes(),
                                )
                                .map(|_| ())
                            })
                            .transpose();
                        if let Err(err) = &result {
                            error!(error = %err, hash, "Mace async cache metadata write failed");
                        }
                        let ok = result.is_ok_and(|value| value.is_some());
                        let _ = ack.send(ok);
                        ok
                    }
                    CacheMetaWrite::Delete { hash, ack } => {
                        let result = STORAGE
                            .db
                            .as_ref()
                            .map(|db| db.delete(format!("CMETA_{hash}").as_bytes()))
                            .transpose();
                        if let Err(err) = &result {
                            error!(error = %err, hash, "Mace async cache metadata delete failed");
                        }
                        let ok = result.is_ok_and(|value| value.is_some());
                        let _ = ack.send(ok);
                        ok
                    }
                };
                if !result {
                    // The request receives the failure through its acknowledgement; this log
                    // also keeps a dropped receiver from becoming a silent persistence loss.
                    warn!("Mace cache metadata writer rejected a command");
                }
            }
        });
    if let Err(err) = spawn_result {
        error!(error = %err, "failed to start Mace cache metadata writer");
    }
}

fn start_unique_ip_writer() {
    let (tx, rx) = std::sync::mpsc::sync_channel(8192);
    if UNIQUE_IP_WRITER_TX.set(tx).is_err() {
        return;
    }
    let spawn_result = std::thread::Builder::new()
        .name("mace-unique-ip-writer".to_string())
        .spawn(move || {
            while let Ok((key, value)) = rx.recv() {
                let Some(db) = STORAGE.db.as_ref() else {
                    continue;
                };
                if let Err(err) = db.put(&key, value) {
                    error!(error = %err, key, "Mace async unique-IP write failed");
                }
            }
        });
    if let Err(err) = spawn_result {
        error!(error = %err, "failed to start Mace unique-IP writer");
    }
}

pub(crate) fn normalize_cache_status(status: u16) -> u16 {
    if (100..=599).contains(&status) {
        status
    } else {
        200
    }
}

fn parse_cache_status(status: Option<u64>) -> u16 {
    status
        .and_then(|status| u16::try_from(status).ok())
        .map(normalize_cache_status)
        .unwrap_or(200)
}

fn cache_meta_json(meta: &CacheMetaEntry) -> serde_json::Value {
    serde_json::json!({
        "k": meta.cache_key,
        "s": meta.size,
        "e": meta.expires,
        "a": meta.access_time,
        "f": meta.access_count,
        "st": meta.status,
        "h": meta.headers.iter().map(|(k,v)| (k.clone(), serde_json::Value::String(v.clone()))).collect::<serde_json::Map<_,_>>(),
        "c": meta.compressed,
        "sh": meta.shard_id,
        "rp": meta.relative_path,
        "v": meta.event_version,
        "u": meta.updated_at,
        "swr": meta.stale_while_revalidate_secs,
        "ca": meta.created_at,
    })
}

fn client_agent_ip_key(ip: &str) -> String {
    format!("CAIP_IP_{}", ip)
}

fn client_agent_ip_json(record: &crate::client_agent::ClientAgentIpRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "ip": record.ip,
        "ptr": record.ptr,
        "code": record.agent_code,
    })
}

fn client_agent_ip_record_from_slice(
    val: &[u8],
) -> Option<crate::client_agent::ClientAgentIpRecord> {
    let raw = serde_json::from_slice::<serde_json::Value>(val).ok()?;
    Some(crate::client_agent::ClientAgentIpRecord {
        id: raw.get("id").and_then(|v| v.as_i64()).unwrap_or(0),
        ip: raw.get("ip")?.as_str()?.to_string(),
        ptr: raw
            .get("ptr")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        agent_code: raw.get("code")?.as_str()?.to_string(),
    })
}

fn unique_ip_key(server_id: i64, day: &str, ip: IpAddr) -> String {
    format!("UIP_{}_{}_{}", day, server_id, ip)
}

fn parse_unique_ip_key(key: &str) -> Option<(i64, String, IpAddr)> {
    let rest = key.strip_prefix("UIP_")?;
    let mut parts = rest.splitn(3, '_');
    let day = parts.next()?.to_string();
    let server_id = parts.next()?.parse::<i64>().ok()?;
    let ip = parts.next()?.parse::<IpAddr>().ok()?;
    Some((server_id, day, ip))
}

fn stats_period_from_key(key: &[u8]) -> Option<i64> {
    let key = std::str::from_utf8(key).ok()?;
    let period = if let Some(rest) = key.strip_prefix("NODE_T") {
        rest.split('_').next()?
    } else if let Some(rest) = key.strip_prefix('S') {
        let (_, rest) = rest.split_once("_T")?;
        rest.split('_').next()?
    } else {
        return None;
    };
    period.parse().ok()
}

pub fn get_cache_meta_memory(hash: &str) -> Option<CacheMetaEntry> {
    CACHE_META_INDEX.get(hash).map(|v| v.clone())
}

pub fn record_cache_access_memory(hash: &str) {
    let now = crate::utils::time::now_timestamp();
    let entry = CACHE_ACCESS_LOG
        .entry(hash.to_string())
        .or_insert_with(|| (AtomicI64::new(now), AtomicU64::new(0)));
    entry.0.store(now, Ordering::Relaxed);
    entry.1.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
pub fn insert_cache_meta_for_test(hash: String, meta: CacheMetaEntry) {
    CACHE_META_INDEX.insert(hash, meta);
}

#[cfg(test)]
pub fn delete_cache_meta_for_test(hash: &str) {
    CACHE_META_INDEX.remove(hash);
    CACHE_ACCESS_LOG.remove(hash);
}

/// Load all existing cache metadata from Mace into the in-memory index at startup.
pub fn load_cache_meta_index() {
    let Some(db) = &STORAGE.db else {
        return;
    };
    let mut count = 0;
    let iter = db.prefix_iterator("CMETA_".as_bytes());
    for (key, val) in iter.flatten() {
        let key_str = String::from_utf8_lossy(&key);
        if !key_str.starts_with("CMETA_") {
            break;
        }
        if let Ok(raw) = serde_json::from_slice::<serde_json::Value>(&val) {
            let hash = key_str
                .strip_prefix("CMETA_")
                .unwrap_or(&key_str)
                .to_string();
            let headers: Vec<(String, String)> = raw
                .get("h")
                .and_then(|h| h.as_object())
                .map(|obj| {
                    obj.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let entry = CacheMetaEntry {
                cache_key: raw
                    .get("k")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                size: raw.get("s").and_then(|v| v.as_u64()).unwrap_or(0),
                expires: raw.get("e").and_then(|v| v.as_i64()).unwrap_or(0),
                access_time: raw.get("a").and_then(|v| v.as_i64()).unwrap_or(0),
                access_count: raw.get("f").and_then(|v| v.as_u64()).unwrap_or(0),
                status: parse_cache_status(raw.get("st").and_then(|v| v.as_u64())),
                headers,
                compressed: raw.get("c").and_then(|v| v.as_bool()).unwrap_or(false),
                shard_id: raw.get("sh").and_then(|v| v.as_str()).map(str::to_string),
                relative_path: raw.get("rp").and_then(|v| v.as_str()).map(str::to_string),
                event_version: raw.get("v").and_then(|v| v.as_u64()),
                updated_at: raw.get("u").and_then(|v| v.as_i64()).unwrap_or(0),
                stale_while_revalidate_secs: raw.get("swr").and_then(|v| v.as_u64()).unwrap_or(0),
                created_at: raw.get("ca").and_then(|v| v.as_i64()).unwrap_or(0),
            };
            CACHE_META_INDEX.insert(hash, entry);
            count += 1;
        }
    }
    tracing::info!("Loaded {} cache metadata entries into memory", count);
}

/// Start a background task that flushes in-memory cache access logs to Mace every 30 seconds.
pub fn start_cache_access_flusher() {
    // Load existing metadata into memory first
    load_cache_meta_index();
    crate::cache_hybrid::warm_admission_filters_from_cache_meta();
    start_cache_meta_writer();
    start_unique_ip_writer();
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if let Err(err) = tokio::task::spawn_blocking(|| STORAGE.flush_cache_accesses()).await {
                error!(error = %err, "Mace cache access flusher task failed");
            }
        }
    });
}

static ASN_READER: Lazy<Option<maxminddb::Reader<Vec<u8>>>> = Lazy::new(|| {
    let paths = crate::paths::NodePaths::current().geoip_asn_candidates();
    for path in &paths {
        if path.exists() {
            return maxminddb::Reader::open_readfile(path).ok();
        }
    }
    None
});

static ASN_NUMBER_CACHE: Lazy<DashMap<IpAddr, i64>> = Lazy::new(DashMap::new);

pub fn lookup_asn_number(ip: IpAddr) -> i64 {
    if let Some(cached) = ASN_NUMBER_CACHE.get(&ip) {
        return *cached;
    }
    let asn = ASN_READER
        .as_ref()
        .and_then(|reader| reader.lookup(ip).ok())
        .and_then(|result| result.decode::<geoip2::Asn>().ok().flatten())
        .and_then(|asn| asn.autonomous_system_number.map(i64::from))
        .unwrap_or(0);
    if ASN_NUMBER_CACHE.len() < 65536 {
        ASN_NUMBER_CACHE.insert(ip, asn);
    }
    asn
}

pub fn provider_name_to_id(name: &str) -> i64 {
    if name.is_empty() || name == "Unknown" {
        return 0;
    }
    let h = crate::utils::fnv_hash64(name);
    ((h >> 1) as i64).max(1)
}

pub fn lookup_region_provider_id(ip: IpAddr) -> i64 {
    lookup_asn_number(ip)
}

#[cfg(test)]
mod tests {
    use super::{
        MetricStorage, normalize_cache_status, parse_cache_status, parse_unique_ip_key,
        stats_period_from_key, unique_ip_key,
    };

    #[test]
    fn cache_status_normalization_rejects_invalid_http_codes() {
        assert_eq!(normalize_cache_status(99), 200);
        assert_eq!(normalize_cache_status(100), 100);
        assert_eq!(normalize_cache_status(599), 599);
        assert_eq!(normalize_cache_status(600), 200);

        assert_eq!(parse_cache_status(Some(200)), 200);
        assert_eq!(parse_cache_status(Some(700)), 200);
        assert_eq!(parse_cache_status(Some(u64::from(u16::MAX) + 1)), 200);
        assert_eq!(parse_cache_status(None), 200);
    }

    #[test]
    fn unique_ip_key_round_trips_ipv4_and_ipv6() {
        for ip in ["203.0.113.1", "2001:db8::1"] {
            let parsed = parse_unique_ip_key(&unique_ip_key(7, "20260621", ip.parse().unwrap()))
                .expect("unique ip key should parse");
            assert_eq!(parsed.0, 7);
            assert_eq!(parsed.1, "20260621");
            assert_eq!(parsed.2.to_string(), ip);
        }
    }

    #[test]
    fn stats_period_parsing_is_independent_of_server_id_order() {
        assert_eq!(stats_period_from_key(b"S0_T100_req"), Some(100));
        assert_eq!(stats_period_from_key(b"S7_T100_req"), Some(100));
        assert_eq!(stats_period_from_key(b"NODE_T100_sent"), Some(100));
        assert_eq!(stats_period_from_key(b"S7_bad"), None);
    }

    #[test]
    fn cleanup_old_stats_removes_old_periods_for_every_server() {
        let path =
            std::env::temp_dir().join(format!("cloud-node-mace-cleanup-{}", uuid::Uuid::new_v4()));
        let storage = MetricStorage::open(&path).expect("open Mace storage");
        let value = vec![0; 8];
        assert!(storage.write_raw_batch(
            vec![
                ("S0_T100_req".to_string(), value.clone()),
                ("S7_T100_req".to_string(), value.clone()),
                ("NODE_T100_sent".to_string(), value.clone()),
                ("S7_T200_req".to_string(), value),
            ],
            Vec::new(),
        ));

        storage.cleanup_old_stats(200);

        assert!(storage.scan_prefix("S0_T100").is_empty());
        assert!(storage.scan_prefix("S7_T100").is_empty());
        assert!(storage.scan_prefix("NODE_T100").is_empty());
        assert_eq!(storage.scan_prefix("S7_T200").len(), 1);

        drop(storage);
        std::fs::remove_dir_all(path).expect("remove Mace test database");
    }
}
