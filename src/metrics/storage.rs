use crate::rpc::metrics::ServerMetricUpdate;
use dashmap::DashMap;
use mace::{Bucket, BucketOptions, Mace, OpCode, Options};
use maxminddb::{self, geoip2};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use tracing::error;

const METRICS_BUCKET: &str = "metrics";
pub const SERVER_PERIOD_BYTES: usize = 72;
pub const NODE_PERIOD_BYTES: usize = 16;

struct StorageBackend {
    _mace: Mace,
    bucket: Bucket,
    counters: DashMap<String, u64>,
}

/// Open options shared by production `MetricStorage` and comparison benches.
pub fn mace_metrics_options(path: impl AsRef<Path>) -> Options {
    let mut opts = Options::new(path);
    // Match the previous RocksDB default (`WriteOptions.sync = false`).
    opts.sync_on_write = false;
    opts
}

/// Bucket policy for metrics/firewall/cache metadata.
pub fn mace_metrics_bucket_options() -> BucketOptions {
    let mut opts = BucketOptions::default();
    // Metrics commits are small and already coalesced; foreground backpressure
    // only adds latency on the flush path.
    opts.enable_backpressure = false;
    opts
}

pub fn server_period_key(server_id: i64, period: i64) -> String {
    format!("S{server_id}_T{period}")
}

pub fn node_period_key(period: i64) -> String {
    format!("NODE_T{period}")
}

pub fn fold_counter_deltas(updates: Vec<(String, u64)>) -> Vec<(String, u64)> {
    let mut merged: HashMap<String, u64> = HashMap::with_capacity(updates.len());
    for (key, delta) in updates {
        if delta == 0 {
            continue;
        }
        let entry = merged.entry(key).or_insert(0);
        *entry = (*entry).saturating_add(delta);
    }
    merged.into_iter().collect()
}

fn add_u64_be(buf: &mut [u8], offset: usize, delta: u64) {
    let current = parse_u64_be(&buf[offset..offset + 8]);
    buf[offset..offset + 8].copy_from_slice(&current.saturating_add(delta).to_be_bytes());
}

/// Packs one server's 5-minute counters into a single value so Mace does one
/// get+upsert per server instead of nine merge-style RMW operations.
pub fn apply_server_period_update(
    existing: Option<&[u8]>,
    update: &ServerMetricUpdate,
) -> [u8; SERVER_PERIOD_BYTES] {
    let mut buf = [0u8; SERVER_PERIOD_BYTES];
    if let Some(existing) = existing.filter(|value| value.len() == SERVER_PERIOD_BYTES) {
        buf.copy_from_slice(existing);
    }
    add_u64_be(&mut buf, 0, update.total_requests);
    add_u64_be(&mut buf, 8, update.bytes_sent);
    add_u64_be(&mut buf, 16, update.bytes_received);
    add_u64_be(&mut buf, 24, update.cached_bytes);
    add_u64_be(&mut buf, 32, update.count_cached_requests);
    add_u64_be(&mut buf, 40, update.count_attack_requests);
    add_u64_be(&mut buf, 48, update.attack_bytes);
    buf[56..64].copy_from_slice(&update.active_connections.to_be_bytes());
    buf[64..72].copy_from_slice(&update.count_ips.to_be_bytes());
    buf
}

pub fn apply_node_period_deltas(
    existing: Option<&[u8]>,
    sent: u64,
    received: u64,
) -> [u8; NODE_PERIOD_BYTES] {
    let mut buf = [0u8; NODE_PERIOD_BYTES];
    if let Some(existing) = existing.filter(|value| value.len() == NODE_PERIOD_BYTES) {
        buf.copy_from_slice(existing);
    }
    add_u64_be(&mut buf, 0, sent);
    add_u64_be(&mut buf, 8, received);
    buf
}

fn txn_get_slice(txn: &mace::TxnKV<'_>, key: &[u8]) -> Result<Option<Vec<u8>>, OpCode> {
    match txn.get(key) {
        Ok(value) => Ok(Some(value.to_vec())),
        Err(OpCode::NotFound) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Embedded key-value storage for metrics and node metadata (Mace).
pub struct MetricStorage {
    backend: Option<Arc<StorageBackend>>,
}

fn parse_u64_be(bytes: &[u8]) -> u64 {
    if bytes.len() == 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        u64::from_be_bytes(buf)
    } else {
        0
    }
}

impl MetricStorage {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let opts = mace_metrics_options(path)
            .validate()
            .map_err(mace_open_error)?;
        let mace = Mace::new(opts).map_err(mace_open_error)?;
        let bucket = mace
            .new_bucket(METRICS_BUCKET, mace_metrics_bucket_options())
            .or_else(|err| {
                if err == OpCode::Exist {
                    mace.get_bucket(METRICS_BUCKET)
                } else {
                    Err(err)
                }
            })
            .map_err(mace_open_error)?;

        Ok(Self {
            backend: Some(Arc::new(StorageBackend {
                _mace: mace,
                bucket,
                counters: DashMap::new(),
            })),
        })
    }

    pub fn unavailable() -> Self {
        Self { backend: None }
    }

    fn bucket(&self) -> Option<&Bucket> {
        self.backend.as_ref().map(|backend| &backend.bucket)
    }

    fn read<F, T>(&self, f: F) -> Option<T>
    where
        F: FnOnce(&mace::TxnView<'_>) -> Result<T, OpCode>,
    {
        let bucket = self.bucket()?;
        let view = bucket.view().ok()?;
        f(&view).ok()
    }

    fn write<F>(&self, f: F) -> bool
    where
        F: FnOnce(&mace::TxnKV<'_>) -> Result<(), OpCode>,
    {
        let Some(bucket) = self.bucket() else {
            return false;
        };
        let Ok(txn) = bucket.begin() else {
            return false;
        };
        if f(&txn).is_err() {
            return false;
        }
        txn.commit().is_ok()
    }

    fn get_raw(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.read(|view| view.get(key).map(|value| value.to_vec()))
    }

    fn put_raw(&self, key: &[u8], value: &[u8]) -> bool {
        self.write(|txn| txn.upsert(key, value))
    }

    fn delete_raw(&self, key: &[u8]) -> bool {
        self.write(|txn| match txn.del(key) {
            Ok(()) => Ok(()),
            Err(OpCode::NotFound) => Ok(()),
            Err(err) => Err(err),
        })
    }

    pub fn record_server_batch(
        &self,
        period: i64,
        updates: Vec<crate::rpc::metrics::ServerMetricUpdate>,
        node_sent: u64,
        node_received: u64,
    ) {
        let Some(backend) = self.backend.as_ref() else {
            return;
        };
        let Ok(txn) = backend.bucket.begin() else {
            return;
        };

        for u in updates {
            let key = server_period_key(u.server_id, period);
            let existing = match txn_get_slice(&txn, key.as_bytes()) {
                Ok(value) => value,
                Err(_) => return,
            };
            let packed = apply_server_period_update(existing.as_deref(), &u);
            if txn.upsert(key.as_bytes(), packed).is_err() {
                return;
            }
        }

        if node_sent != 0 || node_received != 0 {
            let key = node_period_key(period);
            let existing = match txn_get_slice(&txn, key.as_bytes()) {
                Ok(value) => value,
                Err(_) => return,
            };
            let packed = apply_node_period_deltas(existing.as_deref(), node_sent, node_received);
            if txn.upsert(key.as_bytes(), packed).is_err() {
                return;
            }
        }

        let _ = txn.commit();
    }

    /// Increments multiple counters in a single atomic batch.
    pub fn increment_batch(&self, updates: Vec<(String, u64)>) {
        let Some(backend) = self.backend.as_ref() else {
            return;
        };
        let updates = fold_counter_deltas(updates);
        if updates.is_empty() {
            return;
        }
        let Ok(txn) = backend.bucket.begin() else {
            return;
        };
        let mut committed = HashMap::with_capacity(updates.len());
        for (key, delta) in updates {
            let current = if let Some(cached) = backend.counters.get(&key) {
                *cached
            } else {
                match txn.get(key.as_bytes()) {
                    Ok(value) => parse_u64_be(value.slice()),
                    Err(OpCode::NotFound) => 0,
                    Err(_) => return,
                }
            };
            let next = current.saturating_add(delta);
            if txn.upsert(key.as_bytes(), next.to_be_bytes()).is_err() {
                return;
            }
            committed.insert(key, next);
        }
        if txn.commit().is_ok() {
            for (key, next) in committed {
                backend.counters.insert(key, next);
            }
        }
    }

    /// Deletes all data older than a specific timestamp.
    pub fn cleanup_old_stats(&self, older_than_timestamp: i64) {
        let Some(bucket) = self.bucket() else {
            return;
        };
        let Ok(view) = bucket.view() else {
            return;
        };
        let Ok(txn) = bucket.begin() else {
            return;
        };

        let end_prefix = format!("S0_T{older_than_timestamp}");
        let node_end_prefix = format!("NODE_T{older_than_timestamp}");

        for prefix in ["S", "NODE_T"] {
            let end = if prefix == "S" {
                end_prefix.as_str()
            } else {
                node_end_prefix.as_str()
            };
            for item in view.seek(prefix) {
                let key = item.key();
                let key_str = match std::str::from_utf8(key) {
                    Ok(key_str) => key_str,
                    Err(_) => continue,
                };
                if !key_str.starts_with(prefix) {
                    break;
                }
                if key_str >= end {
                    break;
                }
                if txn.del(key).is_err() {
                    return;
                }
            }
        }

        let _ = txn.commit();
    }

    pub fn put_json<T: Serialize>(&self, key: &str, value: &T) -> bool {
        match serde_json::to_vec(value) {
            Ok(bytes) => self.put_raw(key.as_bytes(), &bytes),
            Err(_) => false,
        }
    }

    pub fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.get_raw(key.as_bytes())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    pub fn record_unique_ip(&self, server_id: i64, day: &str, ip: IpAddr) {
        if server_id <= 0 || day.is_empty() {
            return;
        }
        let _ = self.put_raw(unique_ip_key(server_id, day, ip).as_bytes(), &[]);
    }

    pub fn load_unique_ips(&self, min_day: &str) -> Vec<(i64, String, IpAddr)> {
        let Some(bucket) = self.bucket() else {
            return Vec::new();
        };
        let Ok(view) = bucket.view() else {
            return Vec::new();
        };

        let mut rows = Vec::new();
        for item in view.seek("UIP_") {
            let key_str = match std::str::from_utf8(item.key()) {
                Ok(key_str) => key_str,
                Err(_) => continue,
            };
            if !key_str.starts_with("UIP_") {
                break;
            }
            if let Some((server_id, day, ip)) = parse_unique_ip_key(key_str)
                && day.as_str() >= min_day
            {
                rows.push((server_id, day, ip));
            }
        }
        rows
    }

    pub fn cleanup_unique_ips_before(&self, min_day: &str) {
        let Some(bucket) = self.bucket() else {
            return;
        };
        let Ok(view) = bucket.view() else {
            return;
        };
        let Ok(txn) = bucket.begin() else {
            return;
        };

        for item in view.seek("UIP_") {
            let key = item.key();
            let key_str = match std::str::from_utf8(key) {
                Ok(key_str) => key_str,
                Err(_) => continue,
            };
            if !key_str.starts_with("UIP_") {
                break;
            }
            if let Some((_, day, _)) = parse_unique_ip_key(key_str)
                && day.as_str() < min_day
                && txn.del(key).is_err()
            {
                return;
            }
        }

        let _ = txn.commit();
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
        let meta = CacheMetaEntry {
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
        };
        CACHE_META_INDEX.insert(upsert.hash.to_string(), meta.clone());
        crate::cache_hybrid::index_surrogate_keys(&meta.headers, upsert.hash);
        crate::cache_hybrid::on_cache_meta_upsert(&meta);
        let db_key = format!("CMETA_{}", upsert.hash);
        let _ = self.put_raw(
            db_key.as_bytes(),
            cache_meta_json(&meta).to_string().as_bytes(),
        );
    }

    /// Records a cache access in memory only — no storage I/O on the hot path.
    pub fn record_cache_access(&self, hash: &str) {
        record_cache_access_memory(hash);
    }

    /// Flush in-memory access logs to storage. Called by background task every 30s.
    pub fn flush_cache_accesses(&self) {
        if self.bucket().is_none() || CACHE_ACCESS_LOG.is_empty() {
            return;
        }

        let _ = self.write(|txn| {
            for entry in CACHE_ACCESS_LOG.iter() {
                let hash = entry.key();
                let (access_ts, access_cnt) = entry.value();
                let cnt = access_cnt.swap(0, Ordering::Relaxed);
                let ts = access_ts.load(Ordering::Relaxed);
                if cnt == 0 {
                    continue;
                }
                if let Some(mut meta) = CACHE_META_INDEX.get(hash).map(|v| v.clone()) {
                    meta.access_time = ts;
                    meta.access_count += cnt;
                    CACHE_META_INDEX.insert(hash.clone(), meta.clone());
                    let db_key = format!("CMETA_{hash}");
                    txn.upsert(
                        db_key.as_bytes(),
                        cache_meta_json(&meta).to_string().as_bytes(),
                    )?;
                }
            }
            Ok(())
        });
    }

    pub fn get_cache_meta(&self, hash: &str) -> Option<CacheMetaEntry> {
        get_cache_meta_memory(hash)
    }

    pub fn delete_cache_meta(&self, hash: &str) {
        let removed = CACHE_META_INDEX.remove(hash);
        if let Some((_, meta)) = &removed {
            crate::cache_hybrid::on_cache_meta_delete(&meta.cache_key);
        }
        crate::cache_hybrid::remove_hash_from_surrogate_index(hash);
        CACHE_ACCESS_LOG.remove(hash);
        let db_key = format!("CMETA_{hash}");
        let _ = self.delete_raw(db_key.as_bytes());
    }

    pub fn load_client_agent_ips(&self) -> Vec<crate::client_agent::ClientAgentIpRecord> {
        let Some(bucket) = self.bucket() else {
            return Vec::new();
        };
        let Ok(view) = bucket.view() else {
            return Vec::new();
        };

        let mut records = Vec::new();
        for item in view.seek("CAIP_IP_") {
            let key_str = match std::str::from_utf8(item.key()) {
                Ok(key_str) => key_str,
                Err(_) => continue,
            };
            if !key_str.starts_with("CAIP_IP_") {
                break;
            }
            if let Some(record) = client_agent_ip_record_from_slice(item.val()) {
                records.push(record);
            }
        }
        records
    }

    pub fn get_client_agent_last_id(&self) -> i64 {
        self.get_raw(b"CAIP_META_last_id")
            .map(|value| {
                if value.len() == 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&value);
                    i64::from_be_bytes(buf)
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    pub fn save_client_agent_ip(&self, record: &crate::client_agent::ClientAgentIpRecord) -> bool {
        self.put_raw(
            client_agent_ip_key(&record.ip).as_bytes(),
            client_agent_ip_json(record).to_string().as_bytes(),
        )
    }

    pub fn save_client_agent_ip_batch(
        &self,
        records: &[crate::client_agent::ClientAgentIpRecord],
        last_id: i64,
    ) -> bool {
        self.write(|txn| {
            for record in records {
                txn.upsert(
                    client_agent_ip_key(&record.ip).as_bytes(),
                    client_agent_ip_json(record).to_string().as_bytes(),
                )?;
            }
            txn.upsert(b"CAIP_META_last_id", last_id.to_be_bytes())
        })
    }

    /// WAF Token Persistence
    pub fn save_waf_token(&self, token: &str, ip: &str, ua_hash: &str, expired_at: u64) {
        let val = serde_json::json!({
            "ip": ip,
            "ua": ua_hash,
            "exp": expired_at
        });
        let _ = self.put_raw(
            format!("WAFTOK_{token}").as_bytes(),
            val.to_string().as_bytes(),
        );
    }

    pub fn get_waf_token(&self, token: &str) -> Option<serde_json::Value> {
        self.get_raw(format!("WAFTOK_{token}").as_bytes())
            .and_then(|value| serde_json::from_slice(&value).ok())
    }

    pub fn delete_waf_token(&self, token: &str) {
        let _ = self.delete_raw(format!("WAFTOK_{token}").as_bytes());
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
        if let Some(backend) = self.backend.as_ref()
            && let Some(cached) = backend.counters.get(key)
        {
            return *cached;
        }
        self.get_raw(key.as_bytes())
            .map(|value| parse_u64_be(&value))
            .unwrap_or(0)
    }

    pub fn delete_key(&self, key: &str) {
        let _ = self.delete_raw(key.as_bytes());
    }

    pub fn write_raw_batch(&self, puts: Vec<(String, Vec<u8>)>, deletes: Vec<String>) -> bool {
        if puts.is_empty() && deletes.is_empty() {
            return self.backend.is_some();
        }
        self.write(|txn| {
            for (key, value) in puts {
                txn.upsert(key.as_bytes(), value)?;
            }
            for key in deletes {
                match txn.del(key.as_bytes()) {
                    Ok(()) | Err(OpCode::NotFound) => {}
                    Err(err) => return Err(err),
                }
            }
            Ok(())
        })
    }

    pub fn scan_json_prefix<T: DeserializeOwned>(&self, prefix: &str) -> Vec<(String, T)> {
        let Some(bucket) = self.bucket() else {
            return Vec::new();
        };
        let Ok(view) = bucket.view() else {
            return Vec::new();
        };

        let mut results = Vec::new();
        for item in view.seek(prefix) {
            let key_str = match std::str::from_utf8(item.key()) {
                Ok(key_str) => key_str,
                Err(_) => continue,
            };
            if !key_str.starts_with(prefix) {
                break;
            }
            if let Ok(value) = serde_json::from_slice::<T>(item.val()) {
                results.push((key_str.to_string(), value));
            }
        }
        results
    }

    pub fn for_each_cache_meta<F>(&self, mut f: F)
    where
        F: FnMut(String, &CacheMetaEntry),
    {
        for entry in CACHE_META_INDEX.iter() {
            f(entry.key().clone(), entry.value());
        }
    }

    pub fn scan_all_cache_meta(&self) -> Vec<(String, CacheMetaEntry)> {
        CACHE_META_INDEX
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub fn scan_prefix(&self, prefix: &str) -> Vec<(String, u64)> {
        let Some(bucket) = self.bucket() else {
            return Vec::new();
        };
        let Ok(view) = bucket.view() else {
            return Vec::new();
        };

        let mut results = Vec::new();
        for item in view.seek(prefix) {
            let key_str = match std::str::from_utf8(item.key()) {
                Ok(key_str) => key_str,
                Err(_) => continue,
            };
            if !key_str.starts_with(prefix) {
                break;
            }
            let val = item.val();
            if val.len() == 8 {
                results.push((key_str.to_string(), parse_u64_be(val)));
            }
        }
        results
    }
}

fn mace_open_error(err: OpCode) -> anyhow::Error {
    anyhow::anyhow!("Failed to open Mace storage: {err:?}")
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
        let _ = std::fs::create_dir_all(node_paths.data_dir());
        node_paths.metrics_db_dir()
    };
    match MetricStorage::open(&path) {
        Ok(storage) => storage,
        Err(err) => {
            error!(
                "Failed to open Mace storage at {}, metrics storage disabled: {}",
                path.display(),
                err
            );
            error!("If another process holds the store, stop it before restarting.");
            MetricStorage::unavailable()
        }
    }
});

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
    pub stale_while_revalidate_secs: u64,
    pub created_at: i64,
}

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
    #[serde(default)]
    pub stale_while_revalidate_secs: u64,
    #[serde(default)]
    pub created_at: i64,
}

static CACHE_META_INDEX: Lazy<DashMap<String, CacheMetaEntry>> = Lazy::new(DashMap::new);

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
    format!("CAIP_IP_{ip}")
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
    format!("UIP_{day}_{server_id}_{ip}")
}

fn parse_unique_ip_key(key: &str) -> Option<(i64, String, IpAddr)> {
    let rest = key.strip_prefix("UIP_")?;
    let mut parts = rest.splitn(3, '_');
    let day = parts.next()?.to_string();
    let server_id = parts.next()?.parse::<i64>().ok()?;
    let ip = parts.next()?.parse::<IpAddr>().ok()?;
    Some((server_id, day, ip))
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

pub fn load_cache_meta_index() {
    let Some(bucket) = STORAGE.bucket() else {
        return;
    };
    let Ok(view) = bucket.view() else {
        return;
    };

    let mut count = 0;
    for item in view.seek("CMETA_") {
        let key_str = match std::str::from_utf8(item.key()) {
            Ok(key_str) => key_str,
            Err(_) => continue,
        };
        if !key_str.starts_with("CMETA_") {
            break;
        }
        if let Ok(raw) = serde_json::from_slice::<serde_json::Value>(item.val()) {
            let hash = key_str
                .strip_prefix("CMETA_")
                .unwrap_or(key_str)
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
    tracing::info!("Loaded {count} cache metadata entries into memory");
}

pub fn start_cache_access_flusher() {
    load_cache_meta_index();
    crate::cache_hybrid::warm_admission_filters_from_cache_meta();
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            STORAGE.flush_cache_accesses();
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
    use super::{normalize_cache_status, parse_cache_status, parse_unique_ip_key, unique_ip_key};
    use super::{MetricStorage, CacheMetaUpsert};
    use std::net::IpAddr;

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
    fn mace_storage_round_trip_and_prefix_scan() {
        let dir = std::env::temp_dir().join(format!(
            "cloud-node-mace-test-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = MetricStorage::open(&dir).expect("open mace storage");

        assert!(storage.put_json("FWBLK_META_test", &true));
        assert_eq!(storage.get_json::<bool>("FWBLK_META_test"), Some(true));

        storage.increment_batch(vec![("counter_a".to_string(), 10), ("counter_a".to_string(), 5)]);
        assert_eq!(storage.get_value("counter_a"), 15);

        let update = crate::rpc::metrics::ServerMetricUpdate {
            server_id: 7,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            total_requests: 10,
            bytes_sent: 100,
            bytes_received: 20,
            cached_bytes: 4,
            count_cached_requests: 1,
            count_attack_requests: 0,
            attack_bytes: 0,
            active_connections: 3,
            count_websocket_connections: 0,
            count_ips: 2,
        };
        storage.record_server_batch(1_700_000_000, vec![update.clone()], 50, 25);
        storage.record_server_batch(1_700_000_000, vec![update], 10, 5);
        let packed = storage
            .get_raw(super::server_period_key(7, 1_700_000_000).as_bytes())
            .expect("packed server period");
        assert_eq!(packed.len(), super::SERVER_PERIOD_BYTES);
        assert_eq!(super::parse_u64_be(&packed[0..8]), 20);
        assert_eq!(super::parse_u64_be(&packed[8..16]), 200);
        let node = storage
            .get_raw(super::node_period_key(1_700_000_000).as_bytes())
            .expect("packed node period");
        assert_eq!(super::parse_u64_be(&node[0..8]), 60);
        assert_eq!(super::parse_u64_be(&node[8..16]), 30);

        storage.write_raw_batch(
            vec![(
                "FWBLK_V1_global_0_192.0.2.1".to_string(),
                br#"{"target":"192.0.2.1"}"#.to_vec(),
            )],
            Vec::new(),
        );
        let scanned = storage.scan_json_prefix::<serde_json::Value>("FWBLK_V1_");
        assert_eq!(scanned.len(), 1);

        storage.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash: "abc123",
            cache_key: "/index.html",
            size: 1024,
            expires: 999_999,
            access_time: 1,
            access_count: 1,
            status: 200,
            headers: &[],
            compressed: false,
            shard_id: None,
            relative_path: None,
            event_version: None,
            updated_at: Some(1),
            stale_while_revalidate_secs: 0,
            created_at: 1,
        });
        assert!(storage.get_cache_meta("abc123").is_some());

        storage.record_unique_ip(1, "20260818", "203.0.113.9".parse::<IpAddr>().unwrap());
        let ips = storage.load_unique_ips("20260818");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].0, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
