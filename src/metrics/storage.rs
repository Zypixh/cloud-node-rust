use crate::rpc::metrics::ServerMetricUpdate;
use dashmap::DashMap;
use mace::{Bucket, BucketOptions, Mace, OpCode, Options};
use maxminddb::{self, geoip2};
use parking_lot::Mutex as ParkingMutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use tokio::sync::{mpsc, oneshot};
use tracing::{error, warn};

const METRICS_BUCKET: &str = "metrics";
pub const SERVER_PERIOD_BYTES: usize = 72;
pub const NODE_PERIOD_BYTES: usize = 16;
/// Mace treats empty values as tombstones, so unique-IP presence keys need a
/// non-empty sentinel (RocksDB previously allowed empty values).
const UNIQUE_IP_MARKER: &[u8] = b"1";
const CACHE_META_MAX_ENTRIES: usize = 1_000_000;
const CACHE_META_MAX_ENTRY_BYTES: u64 = 256 * 1024;
const CACHE_META_TOMBSTONE_PREFIX: &str = "CTOMB_";
// A broad purge (prefix/tag) may happen before a cache key has metadata.  A
// single durable watermark fences delayed cluster upserts without creating an
// unbounded tombstone row for every possible key in the purged set.
const CACHE_META_BROAD_PURGE_KEY: &str = "CBPURGE_V1";
const CACHE_META_TOMBSTONE_MAX_ENTRIES: usize = CACHE_META_MAX_ENTRIES;
const CACHE_ACCESS_LOG_MAX_ENTRIES: usize = 262_144;
const CACHE_META_QUEUE_CAPACITY: usize = 8192;
const CORRUPT_CMETA_ISOLATION_MAX: usize = 4_096;

static CORRUPT_CMETA_KEYS: Lazy<DashMap<String, ()>> = Lazy::new(DashMap::new);
static CORRUPT_CMETA_COUNT: AtomicU64 = AtomicU64::new(0);
static CACHE_META_VERSION: AtomicU64 = AtomicU64::new(0);
static CACHE_META_BROAD_PURGE_VERSION: AtomicU64 = AtomicU64::new(0);
// A delete must remain visible after the metadata row is gone.  Otherwise a
// delayed cluster upsert can recreate an old row and make the old body
// eligible again.  The durable CTOMB_* record is the source of truth; this
// bounded hot index avoids a Mace read for the normal event path.
static CACHE_META_TOMBSTONES: Lazy<DashMap<String, u64>> = Lazy::new(DashMap::new);

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
        let _ = self.put_raw(
            unique_ip_key(server_id, day, ip).as_bytes(),
            UNIQUE_IP_MARKER,
        );
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
            error_status_allowed: false,
            shard_id: None,
            relative_path: None,
            root_path: None,
            event_version: Some(next_cache_meta_event_version()),
            updated_at: Some(now),
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            created_at: now,
        });
    }

    pub fn upsert_cache_meta_absolute(&self, upsert: CacheMetaUpsert<'_>) {
        let meta = cache_meta_from_upsert(&upsert);
        if !cache_meta_upsert_is_valid(&upsert, &meta)
            || cache_meta_upsert_is_fenced(self, &upsert)
            || cache_meta_version_is_fenced(
                cache_meta_tombstone_version_for(self, upsert.hash),
                upsert.event_version,
            )
        {
            return;
        }
        if !apply_cache_meta_memory(upsert.hash, meta.clone()) {
            return;
        }
        let db_key = format!("CMETA_{}", upsert.hash);
        let tombstone_key = cache_meta_tombstone_key(upsert.hash);
        let ok = {
            let _db_guard = CACHE_META_DB_LOCK.lock();
            self.write(|txn| {
                let broad_purge_version = txn_get_slice(txn, CACHE_META_BROAD_PURGE_KEY.as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|value| parse_cache_meta_tombstone(&value));
                if cache_meta_version_is_fenced(broad_purge_version, upsert.event_version) {
                    return Err(OpCode::NotFound);
                }
                let durable_tombstone = txn_get_slice(txn, tombstone_key.as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|value| parse_cache_meta_tombstone(&value));
                if cache_meta_version_is_fenced(durable_tombstone, upsert.event_version) {
                    return Err(OpCode::NotFound);
                }
                let current = txn_get_slice(txn, db_key.as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|value| cache_meta_entry_from_bytes(&value));
                if cache_meta_update_is_stale(current.as_ref(), &meta) {
                    return Err(OpCode::NotFound);
                }
                if durable_tombstone.is_some() {
                    match txn.del(tombstone_key.as_bytes()) {
                        Ok(()) | Err(OpCode::NotFound) => {}
                        Err(err) => return Err(err),
                    }
                }
                txn.upsert(
                    db_key.as_bytes(),
                    cache_meta_json(&meta).to_string().as_bytes(),
                )
            })
        };
        if ok {
            remove_cache_meta_tombstone_memory_through(
                upsert.hash,
                cache_meta_entry_version(&meta),
            );
        } else {
            remove_cache_meta_memory_if_current(upsert.hash, &meta);
        }
    }

    /// Applies metadata to the hot in-memory index, then waits for a bounded,
    /// dedicated Mace writer. The Tokio reactor never performs the sync write.
    pub async fn upsert_cache_meta_absolute_async(&self, upsert: CacheMetaUpsert<'_>) -> bool {
        let meta = cache_meta_from_upsert(&upsert);
        if !cache_meta_upsert_is_valid(&upsert, &meta)
            || cache_meta_upsert_is_fenced(self, &upsert)
            || cache_meta_version_is_fenced(
                cache_meta_tombstone_version_for(self, upsert.hash),
                upsert.event_version,
            )
        {
            return false;
        }
        if !apply_cache_meta_memory(upsert.hash, meta.clone()) {
            return false;
        }
        let mut memory_rollback = CacheMetaMemoryRollback::new(upsert.hash, meta.clone());

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
                meta: meta.clone(),
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
        let persisted = ack_rx.await.unwrap_or(false);
        reconcile_cache_meta_upsert_result(upsert.hash, &meta, persisted);
        memory_rollback.disarm();
        persisted
    }

    /// Records a cache access in memory only — no storage I/O on the hot path.
    pub fn record_cache_access(&self, hash: &str) {
        record_cache_access_memory(hash);
    }

    /// Flush in-memory access logs to storage. Called by background task every 30s.
    pub fn flush_cache_accesses(&self) {
        if self.bucket().is_none() {
            return;
        }

        // Access flushes and metadata upsert/delete commands must be ordered
        // through the same DB mutex.  In particular, do not let a flush hold
        // an old in-memory row and write it after a purge has committed its
        // tombstone.
        let _db_guard = CACHE_META_DB_LOCK.lock();
        let mut pending = Vec::new();
        for entry in CACHE_ACCESS_LOG.iter() {
            let access_cnt = entry.value().1.swap(0, Ordering::AcqRel);
            if access_cnt == 0 {
                continue;
            }
            pending.push((
                entry.key().clone(),
                entry.value().0.load(Ordering::Acquire),
                access_cnt,
            ));
        }
        if pending.is_empty() {
            return;
        }

        // Keep only successful metadata snapshots.  If the transaction fails,
        // counters are restored below so a transient Mace error does not lose
        // access accounting permanently.
        let mut applied = Vec::with_capacity(pending.len());
        let committed = self.write(|txn| {
            let now = crate::utils::time::now_timestamp();
            for (hash, access_ts, access_cnt) in &pending {
                let Some(memory_meta) = CACHE_META_INDEX.get(hash).map(|meta| meta.clone()) else {
                    // The entry was purged or evicted after the access was
                    // recorded.  It must not be recreated by the flush.
                    continue;
                };
                if memory_meta.expires <= now
                    || memory_meta.cache_key.is_empty()
                    || format!(
                        "{:x}",
                        md5_legacy::compute(memory_meta.cache_key.as_bytes())
                    ) != *hash
                    || !crate::cache::status_allows_full_cache_with_error_policy(
                        memory_meta.status,
                        memory_meta.error_status_allowed,
                    )
                    || !crate::cache::stored_response_headers_allow_shared_cache(
                        &memory_meta.headers,
                    )
                    || !crate::cache::stored_response_encoding_matches_cache_key(
                        &memory_meta.cache_key,
                        &memory_meta.headers,
                    )
                {
                    continue;
                }

                let db_key = format!("CMETA_{hash}");
                let tombstone_key = cache_meta_tombstone_key(hash);
                let broad_purge_version = txn_get_slice(txn, CACHE_META_BROAD_PURGE_KEY.as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|value| parse_cache_meta_tombstone(&value));
                let broad_purge_version = broad_purge_version
                    .into_iter()
                    .chain(
                        Some(CACHE_META_BROAD_PURGE_VERSION.load(Ordering::Acquire))
                            .filter(|version| *version > 0),
                    )
                    .max();
                if cache_meta_version_is_fenced(broad_purge_version, memory_meta.event_version) {
                    continue;
                }
                let durable_tombstone_version = txn_get_slice(txn, tombstone_key.as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|value| parse_cache_meta_tombstone(&value));
                let tombstone_version = durable_tombstone_version
                    .into_iter()
                    .chain(cache_meta_tombstone_memory(hash))
                    .max();
                if cache_meta_version_is_fenced(tombstone_version, memory_meta.event_version) {
                    continue;
                }

                let durable_meta = txn_get_slice(txn, db_key.as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|value| cache_meta_entry_from_bytes(&value));
                let memory_version = cache_meta_entry_version(&memory_meta);
                if durable_meta
                    .as_ref()
                    .is_some_and(|durable| cache_meta_entry_version(durable) > memory_version)
                {
                    // A newer fill/cluster event is already durable.  An
                    // older access snapshot must never overwrite it.
                    continue;
                }

                let mut updated = memory_meta;
                if let Some(durable) = durable_meta {
                    // Preserve access counts accumulated by another worker or
                    // by a previous flush, then add only this batch once.
                    updated.access_count = updated.access_count.max(durable.access_count);
                    updated.access_time = updated.access_time.max(durable.access_time);
                }
                updated.access_count = updated.access_count.saturating_add(*access_cnt);
                updated.access_time = updated.access_time.max(*access_ts);

                if tombstone_version.is_some() {
                    match txn.del(tombstone_key.as_bytes()) {
                        Ok(()) | Err(OpCode::NotFound) => {}
                        Err(err) => return Err(err),
                    }
                }
                txn.upsert(
                    db_key.as_bytes(),
                    cache_meta_json(&updated).to_string().as_bytes(),
                )?;
                applied.push((hash.clone(), updated, memory_version));
            }
            Ok(())
        });

        if committed {
            for (hash, updated, version) in applied {
                // Do not overwrite a newer in-memory fill that arrived while
                // the transaction was committing.  Access counters are the
                // only fields this path owns.
                if let Some(mut current) = CACHE_META_INDEX.get_mut(&hash)
                    && cache_meta_entry_version(&current) == version
                    && current.cache_key == updated.cache_key
                {
                    current.access_time = current.access_time.max(updated.access_time);
                    current.access_count = current.access_count.max(updated.access_count);
                }
                remove_cache_meta_tombstone_memory_through(&hash, version);
            }
        } else {
            for (hash, access_ts, access_cnt) in pending {
                restore_cache_access_memory(&hash, access_ts, access_cnt);
            }
        }
    }

    pub fn get_cache_meta(&self, hash: &str) -> Option<CacheMetaEntry> {
        get_cache_meta_memory(hash)
    }

    pub fn delete_cache_meta(&self, hash: &str) {
        self.delete_cache_meta_at_version(hash, next_cache_meta_event_version());
    }

    fn delete_cache_meta_at_version(&self, hash: &str, version: u64) {
        remove_cache_meta_memory(hash);
        observe_cache_meta_event_version(version.max(1));
        remember_cache_meta_tombstone(hash, version);
        let _ = self.persist_cache_meta_delete_sync(hash, version);
    }

    pub async fn delete_cache_meta_async(&self, hash: &str) -> bool {
        self.delete_cache_meta_async_at_version(hash, next_cache_meta_event_version())
            .await
    }

    pub(crate) async fn delete_cache_meta_async_at_version(
        &self,
        hash: &str,
        version: u64,
    ) -> bool {
        remove_cache_meta_memory(hash);
        let version = version.max(1);
        observe_cache_meta_event_version(version);
        remember_cache_meta_tombstone(hash, version);

        let Some(tx) = CACHE_META_WRITER_TX.get() else {
            warn!(hash, "Mace cache metadata writer is not started");
            return self.persist_cache_meta_delete_sync(hash, version);
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if tx
            .send(CacheMetaWrite::Delete {
                hash: hash.to_string(),
                tombstone_version: version,
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            error!(hash, "Mace cache metadata writer queue is closed");
            return self.persist_cache_meta_delete_sync(hash, version);
        }
        if ack_rx.await.unwrap_or(false) {
            true
        } else {
            // A failed/closed asynchronous writer must not leave the old row
            // resurrectable after restart.  The synchronous fallback is only
            // used on the error path and is serialized by the same DB lock.
            self.persist_cache_meta_delete_sync(hash, version)
        }
    }

    fn persist_cache_meta_delete_sync(&self, hash: &str, version: u64) -> bool {
        let db_key = format!("CMETA_{hash}");
        let tombstone_key = cache_meta_tombstone_key(hash);
        let _db_guard = CACHE_META_DB_LOCK.lock();
        self.write(|txn| {
            let current = txn_get_slice(txn, tombstone_key.as_bytes())
                .ok()
                .flatten()
                .and_then(|value| parse_cache_meta_tombstone(&value))
                .unwrap_or(0);
            let tombstone_version = current.max(version).max(1);
            txn.upsert(
                tombstone_key.as_bytes(),
                tombstone_version.to_string().as_bytes(),
            )?;
            let current_meta = txn_get_slice(txn, db_key.as_bytes())
                .ok()
                .flatten()
                .and_then(|value| cache_meta_entry_from_bytes(&value));
            if current_meta
                .as_ref()
                .is_none_or(|meta| cache_meta_entry_version(meta) <= tombstone_version)
            {
                match txn.del(db_key.as_bytes()) {
                    Ok(()) | Err(OpCode::NotFound) => Ok(()),
                    Err(err) => Err(err),
                }
            } else {
                // A newer fill won the race with this delete.  Keep it and
                // leave the older tombstone as a fence for delayed writes.
                Ok(())
            }
        })
    }

    /// Persist the fence for a prefix/tag purge before the purge is exposed to
    /// callers.  The worker serializes this marker with all metadata writes so
    /// a queued old upsert cannot land after the fence.
    pub(crate) async fn record_cache_meta_broad_purge(&self, version: u64) -> bool {
        let version = version.max(1);
        observe_cache_meta_event_version(version);
        observe_cache_meta_broad_purge_version(version);

        let Some(tx) = CACHE_META_WRITER_TX.get() else {
            warn!(
                version,
                "Mace cache metadata writer is not started; broad purge fence is not durable"
            );
            return self.persist_cache_meta_broad_purge_sync(version);
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if tx
            .send(CacheMetaWrite::BroadPurge {
                version,
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            error!(
                version,
                "Mace cache metadata writer queue is closed; broad purge fence is not durable"
            );
            return self.persist_cache_meta_broad_purge_sync(version);
        }
        if ack_rx.await.unwrap_or(false) {
            true
        } else {
            self.persist_cache_meta_broad_purge_sync(version)
        }
    }

    fn persist_cache_meta_broad_purge_sync(&self, version: u64) -> bool {
        let _db_guard = CACHE_META_DB_LOCK.lock();
        self.write(|txn| {
            let current = txn_get_slice(txn, CACHE_META_BROAD_PURGE_KEY.as_bytes())
                .ok()
                .flatten()
                .and_then(|value| parse_cache_meta_tombstone(&value))
                .unwrap_or(0);
            let version = current.max(version).max(1);
            txn.upsert(
                CACHE_META_BROAD_PURGE_KEY.as_bytes(),
                version.to_string().as_bytes(),
            )
        })
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

    pub fn collect_cache_keys_by_surrogate_tag(&self, tag: &str, limit: usize) -> Vec<String> {
        let mut keys = Vec::new();
        if tag.is_empty() || limit == 0 {
            return keys;
        }
        for entry in CACHE_META_INDEX.iter() {
            if crate::cache_hybrid::meta_headers_contain_surrogate_tag(&entry.value().headers, tag)
            {
                keys.push(entry.value().cache_key.clone());
                if keys.len() >= limit {
                    break;
                }
            }
        }
        keys
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
// Cache metadata has a hot in-memory index and a dedicated asynchronous Mace
// writer. Access-log flushes also write the same records, so all metadata DB
// writes must share one ordering point.
static CACHE_META_DB_LOCK: Lazy<ParkingMutex<()>> = Lazy::new(|| ParkingMutex::new(()));
// DashMap makes individual operations thread-safe, but metadata publication
// is a multi-step operation: memory accounting, reverse-index replacement,
// and the entry update must agree on one generation. A small process-wide
// mutex keeps an older failed writer from removing or overwriting a newer
// entry between its validation and mutation.
static CACHE_META_INDEX_LOCK: Lazy<ParkingMutex<()>> = Lazy::new(|| ParkingMutex::new(()));

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
    /// True only when the selected cache rule explicitly allowed this exact
    /// 5xx status.  Missing/legacy metadata defaults to false.
    pub error_status_allowed: bool,
    pub shard_id: Option<&'a str>,
    pub relative_path: Option<&'a str>,
    pub root_path: Option<&'a str>,
    pub event_version: Option<u64>,
    pub updated_at: Option<i64>,
    pub stale_while_revalidate_secs: u64,
    pub stale_if_error_secs: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
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
    pub error_status_allowed: bool,
    #[serde(default)]
    pub shard_id: Option<String>,
    #[serde(default)]
    pub relative_path: Option<String>,
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub event_version: Option<u64>,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub stale_while_revalidate_secs: u64,
    #[serde(default)]
    pub stale_if_error_secs: u64,
    #[serde(default)]
    pub created_at: i64,
}

static CACHE_META_INDEX: Lazy<DashMap<String, CacheMetaEntry>> = Lazy::new(DashMap::new);

enum CacheMetaWrite {
    Upsert {
        hash: String,
        meta: CacheMetaEntry,
        ack: oneshot::Sender<bool>,
    },
    Delete {
        hash: String,
        tombstone_version: u64,
        ack: oneshot::Sender<bool>,
    },
    BroadPurge {
        version: u64,
        ack: oneshot::Sender<bool>,
    },
}

static CACHE_META_WRITER_TX: OnceLock<mpsc::Sender<CacheMetaWrite>> = OnceLock::new();

/// Roll back the hot metadata entry when an asynchronous upsert future is
/// cancelled before it receives the writer acknowledgement. The writer also
/// performs this reconciliation after it commits/rejects the command because
/// the receiver may disappear after the command has already been dequeued.
struct CacheMetaMemoryRollback {
    hash: String,
    meta: CacheMetaEntry,
    armed: bool,
}

impl CacheMetaMemoryRollback {
    fn new(hash: &str, meta: CacheMetaEntry) -> Self {
        Self {
            hash: hash.to_string(),
            meta,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CacheMetaMemoryRollback {
    fn drop(&mut self) {
        if self.armed {
            remove_cache_meta_memory_if_current(&self.hash, &self.meta);
        }
    }
}

fn cache_meta_from_upsert(upsert: &CacheMetaUpsert<'_>) -> CacheMetaEntry {
    CacheMetaEntry {
        cache_key: upsert.cache_key.to_string(),
        size: upsert.size,
        expires: upsert.expires,
        access_time: upsert.access_time,
        access_count: upsert.access_count,
        // Keep the wire value unchanged. Validation must happen before an
        // invalid status can be normalized into a cacheable 200 response.
        status: upsert.status,
        headers: upsert.headers.to_vec(),
        compressed: upsert.compressed,
        error_status_allowed: upsert.error_status_allowed,
        shard_id: upsert.shard_id.map(str::to_string),
        relative_path: upsert.relative_path.map(str::to_string),
        root_path: upsert.root_path.map(str::to_string),
        event_version: upsert.event_version,
        updated_at: upsert
            .updated_at
            .unwrap_or_else(crate::utils::time::now_timestamp),
        stale_while_revalidate_secs: upsert.stale_while_revalidate_secs,
        stale_if_error_secs: upsert.stale_if_error_secs,
        created_at: upsert.created_at,
    }
}

fn cache_meta_estimated_bytes(hash: &str, meta: &CacheMetaEntry) -> u64 {
    let headers = meta
        .headers
        .iter()
        .map(|(k, v)| {
            64u64
                .saturating_add(k.len() as u64)
                .saturating_add(v.len() as u64)
        })
        .sum::<u64>();
    (128u64)
        .saturating_add(hash.len() as u64)
        .saturating_add(meta.cache_key.len() as u64)
        .saturating_add(headers)
        .saturating_add((meta.headers.len() as u64).saturating_mul(32))
        .min(CACHE_META_MAX_ENTRY_BYTES)
}

fn cache_meta_tombstone_key(hash: &str) -> String {
    format!("{CACHE_META_TOMBSTONE_PREFIX}{hash}")
}

fn cache_meta_tombstone_owner(hash: &str) -> String {
    format!("cache-meta-tombstone:{hash}")
}

fn cache_meta_tombstone_estimated_bytes(hash: &str) -> u64 {
    (64u64.saturating_add(hash.len() as u64)).min(CACHE_META_MAX_ENTRY_BYTES)
}

fn parse_cache_meta_tombstone(value: &[u8]) -> Option<u64> {
    std::str::from_utf8(value)
        .ok()?
        .parse::<u64>()
        .ok()
        .filter(|v| *v > 0)
}

fn remember_cache_meta_tombstone(hash: &str, version: u64) {
    if hash.is_empty() || version == 0 {
        return;
    }
    let existing = CACHE_META_TOMBSTONES.get(hash).map(|value| *value);
    if existing.is_some_and(|current| current >= version) {
        return;
    }
    if existing.is_none() && CACHE_META_TOMBSTONES.len() >= CACHE_META_TOMBSTONE_MAX_ENTRIES {
        warn!(
            hash,
            version,
            "CACHE_META: tombstone hot index is full; durable tombstone remains authoritative"
        );
        return;
    }
    let owner = cache_meta_tombstone_owner(hash);
    if !crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
        crate::memory_governor::ResidentCategory::CacheMetadata,
        &owner,
        cache_meta_tombstone_estimated_bytes(hash),
    ) {
        warn!(
            hash,
            version,
            "CACHE_META: tombstone admission rejected; durable tombstone remains authoritative"
        );
        return;
    }
    CACHE_META_TOMBSTONES
        .entry(hash.to_string())
        .and_modify(|current| *current = (*current).max(version))
        .or_insert(version);
}

fn remove_cache_meta_tombstone_memory_through(hash: &str, version: u64) {
    if CACHE_META_TOMBSTONES
        .remove_if(hash, |_, current| *current <= version)
        .is_some()
    {
        let owner = cache_meta_tombstone_owner(hash);
        let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
            crate::memory_governor::ResidentCategory::CacheMetadata,
            &owner,
            0,
        );
    }
}

fn cache_meta_tombstone_memory(hash: &str) -> Option<u64> {
    CACHE_META_TOMBSTONES.get(hash).map(|value| *value)
}

fn cache_meta_tombstone_from_db(storage: &MetricStorage, hash: &str) -> Option<u64> {
    storage
        .get_raw(cache_meta_tombstone_key(hash).as_bytes())
        .as_deref()
        .and_then(parse_cache_meta_tombstone)
}

fn cache_meta_tombstone_version_for(storage: &MetricStorage, hash: &str) -> Option<u64> {
    cache_meta_tombstone_memory(hash)
        .into_iter()
        .chain(cache_meta_tombstone_from_db(storage, hash))
        .max()
}

fn cache_meta_version_is_fenced(
    tombstone_version: Option<u64>,
    event_version: Option<u64>,
) -> bool {
    tombstone_version.is_some_and(|version| event_version.is_none_or(|event| event <= version))
}

fn cache_meta_broad_purge_version_from_db(storage: &MetricStorage) -> Option<u64> {
    storage
        .get_raw(CACHE_META_BROAD_PURGE_KEY.as_bytes())
        .as_deref()
        .and_then(parse_cache_meta_tombstone)
}

fn newest_cache_meta_broad_purge_version(cached: u64, durable: u64) -> u64 {
    cached.max(durable)
}

fn current_cache_meta_broad_purge_version_for(storage: &MetricStorage) -> u64 {
    let cached = CACHE_META_BROAD_PURGE_VERSION.load(Ordering::Acquire);
    let durable = cache_meta_broad_purge_version_from_db(storage).unwrap_or(0);
    let newest = newest_cache_meta_broad_purge_version(cached, durable);
    if durable > cached {
        observe_cache_meta_broad_purge_version(durable);
    }
    newest
}

/// Return the newest durable or in-process broad-purge fence.  The hybrid L1
/// cache uses this on the file-backed policy path because a local memory entry
/// may have no CMETA row to receive the normal invalidation callback.
pub(crate) fn cache_meta_broad_purge_version() -> u64 {
    current_cache_meta_broad_purge_version_for(&STORAGE)
}

pub(crate) fn observe_cache_meta_broad_purge_version(version: u64) {
    if version == 0 {
        return;
    }
    let mut current = CACHE_META_BROAD_PURGE_VERSION.load(Ordering::Relaxed);
    while current < version {
        match CACHE_META_BROAD_PURGE_VERSION.compare_exchange_weak(
            current,
            version,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn cache_meta_upsert_is_fenced(storage: &MetricStorage, upsert: &CacheMetaUpsert<'_>) -> bool {
    let broad_purge_version = current_cache_meta_broad_purge_version_for(storage);
    broad_purge_version > 0
        && upsert
            .event_version
            .is_none_or(|event_version| event_version <= broad_purge_version)
}

pub(crate) fn next_cache_meta_event_version() -> u64 {
    let now = crate::utils::time::now_timestamp_millis()
        .try_into()
        .unwrap_or(1)
        .max(1);
    let mut current = CACHE_META_VERSION.load(Ordering::Relaxed);
    loop {
        let next = now.max(current.saturating_add(1));
        match CACHE_META_VERSION.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

pub(crate) fn observe_cache_meta_event_version(version: u64) {
    if version == 0 {
        return;
    }
    let mut current = CACHE_META_VERSION.load(Ordering::Relaxed);
    while current < version {
        match CACHE_META_VERSION.compare_exchange_weak(
            current,
            version,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn cache_meta_entry_version(meta: &CacheMetaEntry) -> u64 {
    meta.event_version
        .filter(|version| *version > 0)
        .unwrap_or_else(|| {
            meta.updated_at
                .saturating_mul(1_000)
                .try_into()
                .unwrap_or(0)
        })
}

fn cache_meta_update_is_stale(current: Option<&CacheMetaEntry>, incoming: &CacheMetaEntry) -> bool {
    let Some(current) = current else {
        return false;
    };

    match (
        current.event_version.filter(|version| *version > 0),
        incoming.event_version.filter(|version| *version > 0),
    ) {
        (Some(current), Some(incoming)) => incoming <= current,
        // A legacy/unversioned update must never overwrite a versioned row.
        (Some(_), None) => true,
        // A versioned event is a safe upgrade over a legacy row.
        (None, Some(_)) => false,
        // Legacy rows have no ordering token.  Equal timestamps are treated
        // as stale so two delayed writers cannot oscillate the value.
        (None, None) => incoming.updated_at <= current.updated_at,
    }
}

fn cache_meta_upsert_is_valid(upsert: &CacheMetaUpsert<'_>, meta: &CacheMetaEntry) -> bool {
    if upsert.hash.is_empty()
        || meta.cache_key.is_empty()
        || !crate::cache::status_allows_full_cache_with_error_policy(
            meta.status,
            meta.error_status_allowed,
        )
        || !crate::cache::stored_response_headers_allow_shared_cache(&meta.headers)
        || !crate::cache::stored_response_encoding_matches_cache_key(&meta.cache_key, &meta.headers)
    {
        return false;
    }
    let expected_hash = format!("{:x}", md5_legacy::compute(meta.cache_key.as_bytes()));
    if expected_hash != upsert.hash {
        warn!(
            hash = upsert.hash,
            cache_key = meta.cache_key,
            expected_hash,
            "CACHE_META: rejecting upsert with hash/key mismatch"
        );
        return false;
    }
    true
}

fn remove_cache_meta_memory_if_current(hash: &str, expected: &CacheMetaEntry) {
    let _index_guard = CACHE_META_INDEX_LOCK.lock();
    if let Some((_, meta)) = CACHE_META_INDEX.remove_if(hash, |_, current| current == expected) {
        remove_cache_meta_memory_entry(hash, &meta);
    }
}

fn reconcile_cache_meta_upsert_result(hash: &str, meta: &CacheMetaEntry, persisted: bool) {
    if persisted {
        remove_cache_meta_tombstone_memory_through(hash, cache_meta_entry_version(meta));
    } else {
        // Conditional removal is required: a newer fill may have replaced
        // this entry while the writer was blocked in Mace. Never remove that
        // newer generation as part of an older failure cleanup.
        remove_cache_meta_memory_if_current(hash, meta);
    }
}

fn apply_cache_meta_memory(hash: &str, meta: CacheMetaEntry) -> bool {
    let _index_guard = CACHE_META_INDEX_LOCK.lock();
    if hash.is_empty()
        || meta.cache_key.is_empty()
        || format!("{:x}", md5_legacy::compute(meta.cache_key.as_bytes())) != hash
    {
        return false;
    }
    if CACHE_META_INDEX
        .get(hash)
        .is_some_and(|current| cache_meta_update_is_stale(Some(&current), &meta))
    {
        return false;
    }
    if meta.expires <= crate::utils::time::now_timestamp() {
        // An expired update is not a deletion event.  Keep a still-valid
        // current row intact; the normal expiry/purge path owns deletion.
        return false;
    }
    if !crate::cache::status_allows_full_cache_with_error_policy(
        meta.status,
        meta.error_status_allowed,
    ) || !crate::cache::stored_response_headers_allow_shared_cache(&meta.headers)
    {
        return false;
    }
    if !crate::cache::stored_response_encoding_matches_cache_key(&meta.cache_key, &meta.headers) {
        return false;
    }
    let new_bytes = cache_meta_estimated_bytes(hash, &meta);
    let old_bytes = CACHE_META_INDEX
        .get(hash)
        .map(|v| cache_meta_estimated_bytes(hash, &v))
        .unwrap_or(0);
    if CACHE_META_INDEX.len() >= CACHE_META_MAX_ENTRIES && old_bytes == 0 {
        return false;
    }
    if !crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
        crate::memory_governor::ResidentCategory::CacheMetadata,
        hash,
        new_bytes,
    ) {
        // A failed replacement must not leave the old record serving while
        // the caller believes this update was accepted.  Removing the old
        // hot entry also releases its resident-memory ownership.
        remove_cache_meta_memory_locked(hash);
        return false;
    }
    // The same hash can receive a refreshed response with a different
    // Surrogate-Key set.  Remove the old reverse-index memberships before
    // adding the new set, otherwise purging an old tag deletes the refresh.
    crate::cache_hybrid::remove_hash_from_surrogate_index(hash);
    CACHE_META_INDEX.insert(hash.to_string(), meta.clone());
    crate::cache_hybrid::index_surrogate_keys(&meta.headers, hash);
    crate::cache_hybrid::on_cache_meta_upsert(&meta);
    true
}

fn remove_cache_meta_memory(hash: &str) {
    let _index_guard = CACHE_META_INDEX_LOCK.lock();
    remove_cache_meta_memory_locked(hash);
}

fn remove_cache_meta_memory_locked(hash: &str) {
    let removed = CACHE_META_INDEX.remove(hash);
    if let Some((_, meta)) = &removed {
        remove_cache_meta_memory_entry(hash, meta);
    }
}

fn remove_cache_meta_memory_entry(hash: &str, meta: &CacheMetaEntry) {
    crate::cache_hybrid::on_cache_meta_delete(&meta.cache_key);
    crate::cache_hybrid::remove_hash_from_surrogate_index(hash);
    CACHE_ACCESS_LOG.remove(hash);
    crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
        crate::memory_governor::ResidentCategory::CacheAccessLog,
        hash,
        0,
    );
    crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
        crate::memory_governor::ResidentCategory::CacheMetadata,
        hash,
        0,
    );
}

/// Parse the persisted status while retaining the distinction between a
/// missing legacy field and an explicitly malformed/invalid field. Treating
/// both as 200 can replay an object with metadata that never described a
/// valid cacheable response.
fn parse_cache_status(status: Option<&serde_json::Value>) -> Option<u16> {
    let status = match status {
        None => Some(200),
        Some(status) => status
            .as_u64()
            .and_then(|status| u16::try_from(status).ok()),
    }?;
    crate::cache::status_allows_full_cache(status).then_some(status)
}

fn cache_meta_json(meta: &CacheMetaEntry) -> serde_json::Value {
    serde_json::json!({
        "k": meta.cache_key,
        "s": meta.size,
        "e": meta.expires,
        "a": meta.access_time,
        "f": meta.access_count,
        "st": meta.status,
        // Keep headers as an ordered list instead of a JSON object: HTTP
        // permits repeated fields such as Cache-Control and Link.
        "h": serde_json::to_value(&meta.headers).unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
        "c": meta.compressed,
        "esa": meta.error_status_allowed,
        "sh": meta.shard_id,
        "rp": meta.relative_path,
        "rr": meta.root_path,
        "v": meta.event_version,
        "u": meta.updated_at,
        "swr": meta.stale_while_revalidate_secs,
        "sie": meta.stale_if_error_secs,
        "ca": meta.created_at,
    })
}

/// Expose the same ordering token used by metadata admission to cache layers
/// that need to compare an in-memory representation with a purge fence.
pub(crate) fn cache_meta_entry_version_for_l1(meta: &CacheMetaEntry) -> u64 {
    cache_meta_entry_version(meta)
}

fn cache_meta_headers_from_json(raw: &serde_json::Value) -> Option<Vec<(String, String)>> {
    let Some(headers) = raw.get("h") else {
        return Some(Vec::new());
    };

    // Current format: [[name, value], ...].
    if let Some(entries) = headers.as_array() {
        let mut parsed = Vec::with_capacity(entries.len());
        for entry in entries {
            let pair = entry.as_array()?;
            parsed.push((
                pair.first()?.as_str()?.to_string(),
                pair.get(1)?.as_str()?.to_string(),
            ));
        }
        return Some(parsed);
    }

    // Backward compatibility with the old object format.  It cannot recover
    // duplicates already lost by the old serializer, but it remains readable.
    Some(
        headers
            .as_object()?
            .iter()
            .map(|(name, value)| Some((name.clone(), value.as_str()?.to_string())))
            .collect::<Option<Vec<_>>>()?,
    )
}

fn cache_meta_entry_from_json(raw: &serde_json::Value) -> Option<CacheMetaEntry> {
    let entry = CacheMetaEntry {
        cache_key: raw.get("k")?.as_str()?.to_string(),
        size: raw.get("s").and_then(|value| value.as_u64()).unwrap_or(0),
        expires: raw.get("e").and_then(|value| value.as_i64()).unwrap_or(0),
        access_time: raw.get("a").and_then(|value| value.as_i64()).unwrap_or(0),
        access_count: raw.get("f").and_then(|value| value.as_u64()).unwrap_or(0),
        status: parse_cache_status(raw.get("st"))?,
        headers: cache_meta_headers_from_json(raw)?,
        compressed: raw
            .get("c")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        error_status_allowed: raw
            .get("esa")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        shard_id: raw
            .get("sh")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        relative_path: raw
            .get("rp")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        root_path: raw
            .get("rr")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        event_version: raw.get("v").and_then(|value| value.as_u64()),
        updated_at: raw.get("u").and_then(|value| value.as_i64()).unwrap_or(0),
        stale_while_revalidate_secs: raw.get("swr").and_then(|value| value.as_u64()).unwrap_or(0),
        stale_if_error_secs: raw.get("sie").and_then(|value| value.as_u64()).unwrap_or(0),
        created_at: raw.get("ca").and_then(|value| value.as_i64()).unwrap_or(0),
    };
    crate::cache::status_allows_full_cache_with_error_policy(
        entry.status,
        entry.error_status_allowed,
    )
    .then_some(entry)
}

fn cache_meta_entry_from_bytes(bytes: &[u8]) -> Option<CacheMetaEntry> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|raw| cache_meta_entry_from_json(&raw))
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
    let meta = CACHE_META_INDEX.get(hash).map(|v| v.clone())?;
    // A broad purge can be committed by another process. Always compare the
    // durable watermark with the local atomic instead of treating a non-zero
    // local value as authoritative; the watermark is monotonic and the
    // durable read failure path keeps the already observed local maximum.
    let broad_purge_version = current_cache_meta_broad_purge_version_for(&STORAGE);
    if broad_purge_version > 0 && cache_meta_entry_version(&meta) <= broad_purge_version {
        return None;
    }
    if cache_meta_tombstone_memory(hash)
        .is_some_and(|version| cache_meta_entry_version(&meta) <= version)
    {
        return None;
    }
    Some(meta)
}

pub(crate) fn cache_meta_tombstone_version(hash: &str) -> Option<u64> {
    cache_meta_tombstone_version_for(&STORAGE, hash)
}

pub fn record_cache_access_memory(hash: &str) {
    if !CACHE_META_INDEX.contains_key(hash) {
        return;
    }
    if CACHE_ACCESS_LOG.len() >= CACHE_ACCESS_LOG_MAX_ENTRIES
        && !CACHE_ACCESS_LOG.contains_key(hash)
    {
        return;
    }
    let now = crate::utils::time::now_timestamp();
    let entry = CACHE_ACCESS_LOG.entry(hash.to_string()).or_insert_with(|| {
        let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
            crate::memory_governor::ResidentCategory::CacheAccessLog,
            hash,
            128 + hash.len() as u64,
        );
        (AtomicI64::new(now), AtomicU64::new(0))
    });
    entry.0.store(now, Ordering::Relaxed);
    entry.1.fetch_add(1, Ordering::Relaxed);
}

fn restore_cache_access_memory(hash: &str, access_time: i64, access_count: u64) {
    if access_count == 0 || !CACHE_META_INDEX.contains_key(hash) {
        return;
    }
    if CACHE_ACCESS_LOG.len() >= CACHE_ACCESS_LOG_MAX_ENTRIES
        && !CACHE_ACCESS_LOG.contains_key(hash)
    {
        return;
    }
    let entry = CACHE_ACCESS_LOG.entry(hash.to_string()).or_insert_with(|| {
        let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
            crate::memory_governor::ResidentCategory::CacheAccessLog,
            hash,
            128 + hash.len() as u64,
        );
        (AtomicI64::new(access_time), AtomicU64::new(0))
    });
    let mut current = entry.0.load(Ordering::Relaxed);
    while current < access_time {
        match entry.0.compare_exchange_weak(
            current,
            access_time,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
    entry.1.fetch_add(access_count, Ordering::Relaxed);
}

#[cfg(test)]
pub fn insert_cache_meta_for_test(hash: String, meta: CacheMetaEntry) {
    CACHE_META_INDEX.insert(hash, meta);
}

#[cfg(test)]
pub fn delete_cache_meta_for_test(hash: &str) {
    remove_cache_meta_memory(hash);
    remove_cache_meta_tombstone_memory_through(hash, u64::MAX);
}

pub fn load_cache_meta_index() {
    let Some(bucket) = STORAGE.bucket() else {
        return;
    };
    let Ok(view) = bucket.view() else {
        return;
    };

    if let Ok(value) = view.get(CACHE_META_BROAD_PURGE_KEY.as_bytes())
        && let Some(version) = parse_cache_meta_tombstone(value.slice())
    {
        observe_cache_meta_event_version(version);
        observe_cache_meta_broad_purge_version(version);
    }

    for item in view.seek(CACHE_META_TOMBSTONE_PREFIX) {
        let key_str = match std::str::from_utf8(item.key()) {
            Ok(key_str) => key_str,
            Err(_) => continue,
        };
        if !key_str.starts_with(CACHE_META_TOMBSTONE_PREFIX) {
            break;
        }
        let Some(hash) = key_str.strip_prefix(CACHE_META_TOMBSTONE_PREFIX) else {
            continue;
        };
        let Some(version) = parse_cache_meta_tombstone(item.val()) else {
            warn!(key = key_str, "ignoring corrupt cache metadata tombstone");
            continue;
        };
        observe_cache_meta_event_version(version);
        remember_cache_meta_tombstone(hash, version);
    }

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
            let Some(entry) = cache_meta_entry_from_json(&raw) else {
                isolate_corrupt_cmeta(key_str);
                continue;
            };
            let expected_hash = format!("{:x}", md5_legacy::compute(entry.cache_key.as_bytes()));
            if entry.cache_key.is_empty()
                || expected_hash != hash
                || !crate::cache::stored_response_headers_allow_shared_cache(&entry.headers)
                || !crate::cache::stored_response_encoding_matches_cache_key(
                    &entry.cache_key,
                    &entry.headers,
                )
            {
                isolate_corrupt_cmeta(key_str);
                continue;
            }
            observe_cache_meta_event_version(cache_meta_entry_version(&entry));
            let broad_purge_version = CACHE_META_BROAD_PURGE_VERSION.load(Ordering::Acquire);
            if broad_purge_version > 0
                && entry
                    .event_version
                    .is_none_or(|version| version <= broad_purge_version)
            {
                continue;
            }
            if cache_meta_tombstone_version_for(&STORAGE, &hash)
                .is_some_and(|version| cache_meta_entry_version(&entry) <= version)
            {
                continue;
            }
            if entry.expires <= crate::utils::time::now_timestamp() {
                continue;
            }
            let entry_bytes = cache_meta_estimated_bytes(&hash, &entry);
            if CACHE_META_INDEX.len() >= CACHE_META_MAX_ENTRIES
                || !crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
                    crate::memory_governor::ResidentCategory::CacheMetadata,
                    &hash,
                    entry_bytes,
                )
            {
                continue;
            }
            crate::cache_hybrid::index_surrogate_keys(&entry.headers, &hash);
            CACHE_META_INDEX.insert(hash, entry);
            count += 1;
        } else {
            isolate_corrupt_cmeta(key_str);
        }
    }
    tracing::info!(
        "Loaded {count} cache metadata entries into memory (corrupt_isolated={})",
        CORRUPT_CMETA_COUNT.load(Ordering::Relaxed)
    );
}

fn isolate_corrupt_cmeta(key: &str) {
    CORRUPT_CMETA_COUNT.fetch_add(1, Ordering::Relaxed);
    if CORRUPT_CMETA_KEYS.len() < CORRUPT_CMETA_ISOLATION_MAX {
        CORRUPT_CMETA_KEYS.insert(key.to_string(), ());
    }
    warn!(
        key,
        "skipping corrupt cache metadata record; disk value retained"
    );
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
                let ok = match command {
                    CacheMetaWrite::Upsert { hash, meta, ack } => {
                        let db_key = format!("CMETA_{hash}");
                        let tombstone_key = cache_meta_tombstone_key(&hash);
                        let _db_guard = CACHE_META_DB_LOCK.lock();
                        let ok = STORAGE.write(|txn| {
                            let broad_purge_version =
                                txn_get_slice(txn, CACHE_META_BROAD_PURGE_KEY.as_bytes())
                                    .ok()
                                    .flatten()
                                    .and_then(|value| parse_cache_meta_tombstone(&value));
                            if cache_meta_version_is_fenced(broad_purge_version, meta.event_version)
                            {
                                return Err(OpCode::NotFound);
                            }
                            let tombstone = txn_get_slice(txn, tombstone_key.as_bytes())
                                .ok()
                                .flatten()
                                .and_then(|value| parse_cache_meta_tombstone(&value));
                            if cache_meta_version_is_fenced(tombstone, meta.event_version) {
                                return Err(OpCode::NotFound);
                            }
                            let current = txn_get_slice(txn, db_key.as_bytes())
                                .ok()
                                .flatten()
                                .and_then(|value| cache_meta_entry_from_bytes(&value));
                            if cache_meta_update_is_stale(current.as_ref(), &meta) {
                                return Err(OpCode::NotFound);
                            }
                            if tombstone.is_some() {
                                match txn.del(tombstone_key.as_bytes()) {
                                    Ok(()) | Err(OpCode::NotFound) => {}
                                    Err(err) => return Err(err),
                                }
                            }
                            txn.upsert(
                                db_key.as_bytes(),
                                cache_meta_json(&meta).to_string().as_bytes(),
                            )
                        });
                        reconcile_cache_meta_upsert_result(&hash, &meta, ok);
                        if !ok {
                            error!(hash, "Mace async cache metadata write failed");
                        }
                        let _ = ack.send(ok);
                        ok
                    }
                    CacheMetaWrite::Delete {
                        hash,
                        tombstone_version,
                        ack,
                    } => {
                        let db_key = format!("CMETA_{hash}");
                        let tombstone_key = cache_meta_tombstone_key(&hash);
                        let _db_guard = CACHE_META_DB_LOCK.lock();
                        let ok = STORAGE.write(|txn| {
                            let current = txn_get_slice(txn, tombstone_key.as_bytes())
                                .ok()
                                .flatten()
                                .and_then(|value| parse_cache_meta_tombstone(&value))
                                .unwrap_or(0);
                            let version = current.max(tombstone_version).max(1);
                            txn.upsert(tombstone_key.as_bytes(), version.to_string().as_bytes())?;
                            let current_meta = txn_get_slice(txn, db_key.as_bytes())
                                .ok()
                                .flatten()
                                .and_then(|value| cache_meta_entry_from_bytes(&value));
                            if current_meta
                                .as_ref()
                                .is_none_or(|meta| cache_meta_entry_version(meta) <= version)
                            {
                                match txn.del(db_key.as_bytes()) {
                                    Ok(()) | Err(OpCode::NotFound) => Ok(()),
                                    Err(err) => Err(err),
                                }
                            } else {
                                // Do not let an older delayed purge delete a
                                // newer fill that was already persisted.
                                Ok(())
                            }
                        });
                        if !ok {
                            error!(hash, "Mace async cache metadata delete failed");
                        }
                        let _ = ack.send(ok);
                        ok
                    }
                    CacheMetaWrite::BroadPurge { version, ack } => {
                        let _db_guard = CACHE_META_DB_LOCK.lock();
                        let ok = STORAGE.write(|txn| {
                            let current = txn_get_slice(txn, CACHE_META_BROAD_PURGE_KEY.as_bytes())
                                .ok()
                                .flatten()
                                .and_then(|value| parse_cache_meta_tombstone(&value))
                                .unwrap_or(0);
                            let version = current.max(version).max(1);
                            txn.upsert(
                                CACHE_META_BROAD_PURGE_KEY.as_bytes(),
                                version.to_string().as_bytes(),
                            )
                        });
                        if !ok {
                            error!(version, "Mace broad cache purge fence write failed");
                        }
                        let _ = ack.send(ok);
                        ok
                    }
                };
                if !ok {
                    warn!("Mace cache metadata writer rejected a command");
                }
            }
        });
    if let Err(err) = spawn_result {
        error!(error = %err, "failed to start Mace cache metadata writer");
    }
}

pub fn start_cache_access_flusher() {
    load_cache_meta_index();
    start_cache_meta_writer();
    crate::cache_hybrid::warm_admission_filters_from_cache_meta();
    crate::cache_hybrid::start_bloom_rotation_task();
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
    use super::*;
    use serde_json::json;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicI64, AtomicU64};

    #[test]
    fn cache_status_parsing_preserves_missing_default_and_rejects_invalid_values() {
        assert_eq!(parse_cache_status(None), Some(200));
        assert_eq!(parse_cache_status(Some(&json!(200))), Some(200));
        assert_eq!(parse_cache_status(Some(&json!(599))), Some(599));
        assert_eq!(parse_cache_status(Some(&json!(700))), None);
        assert_eq!(
            parse_cache_status(Some(&json!(u64::from(u16::MAX) + 1))),
            None
        );
        assert_eq!(parse_cache_status(Some(&json!("200"))), None);
        assert_eq!(parse_cache_status(Some(&json!(null))), None);
    }

    #[test]
    fn legacy_error_metadata_requires_explicit_persisted_opt_in() {
        let cache_key = "https://cache.example.test/error";
        let base = json!({
            "k": cache_key,
            "s": 4,
            "e": crate::utils::time::now_timestamp() + 60,
            "a": 1,
            "f": 1,
            "st": 503,
            "h": [],
            "c": false,
        });

        assert!(cache_meta_entry_from_json(&base).is_none());

        let mut explicitly_allowed = base;
        explicitly_allowed["esa"] = json!(true);
        let entry = cache_meta_entry_from_json(&explicitly_allowed)
            .expect("explicitly allowed error metadata should load");
        assert_eq!(entry.status, 503);
        assert!(entry.error_status_allowed);
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
        let dir =
            std::env::temp_dir().join(format!("cloud-node-mace-test-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = MetricStorage::open(&dir).expect("open mace storage");

        assert!(storage.put_json("FWBLK_META_test", &true));
        assert_eq!(storage.get_json::<bool>("FWBLK_META_test"), Some(true));

        storage.increment_batch(vec![
            ("counter_a".to_string(), 10),
            ("counter_a".to_string(), 5),
        ]);
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

        let future_expires = crate::utils::time::now_timestamp() + 86_400;

        let cache_key = format!("/index.html-{}", uuid::Uuid::new_v4());
        let cache_hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
        storage.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash: &cache_hash,
            cache_key: &cache_key,
            size: 1024,
            expires: future_expires,
            access_time: 1,
            access_count: 1,
            status: 200,
            headers: &[],
            compressed: false,
            error_status_allowed: false,
            shard_id: None,
            relative_path: None,
            root_path: None,
            event_version: None,
            updated_at: Some(1),
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            created_at: 1,
        });
        assert!(storage.get_cache_meta(&cache_hash).is_some());

        super::delete_cache_meta_for_test(&cache_hash);

        storage.record_unique_ip(1, "20260818", "203.0.113.9".parse::<IpAddr>().unwrap());
        let ips = storage.load_unique_ips("20260818");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].0, 1);

        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_metadata_delete_tombstone_fences_delayed_upsert() {
        let dir = std::env::temp_dir().join(format!(
            "cloud-node-mace-tombstone-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = MetricStorage::open(&dir).expect("open mace storage");
        let cache_key = format!("https://cache.example.test/{}", uuid::Uuid::new_v4());
        let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
        let expires = crate::utils::time::now_timestamp() + 86_400;

        storage.delete_cache_meta_at_version(&hash, 200);
        assert_eq!(cache_meta_tombstone_version_for(&storage, &hash), Some(200));

        storage.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash: &hash,
            cache_key: &cache_key,
            size: 4,
            expires,
            access_time: 1,
            access_count: 1,
            status: 200,
            headers: &[],
            compressed: false,
            error_status_allowed: false,
            shard_id: None,
            relative_path: None,
            root_path: None,
            event_version: Some(199),
            updated_at: Some(1),
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            created_at: 1,
        });
        assert!(storage.get_cache_meta(&hash).is_none());

        storage.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash: &hash,
            cache_key: &cache_key,
            size: 4,
            expires,
            access_time: 1,
            access_count: 1,
            status: 200,
            headers: &[],
            compressed: false,
            error_status_allowed: false,
            shard_id: None,
            relative_path: None,
            root_path: None,
            event_version: Some(201),
            updated_at: Some(1),
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            created_at: 1,
        });
        assert!(storage.get_cache_meta(&hash).is_some());
        assert_eq!(cache_meta_tombstone_version_for(&storage, &hash), None);

        remove_cache_meta_memory(&hash);
        remove_cache_meta_tombstone_memory_through(&hash, u64::MAX);
        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_metadata_tombstone_fences_unversioned_upsert() {
        assert!(super::cache_meta_version_is_fenced(Some(200), None));
        assert!(super::cache_meta_version_is_fenced(Some(200), Some(200)));
        assert!(super::cache_meta_version_is_fenced(Some(200), Some(199)));
        assert!(!super::cache_meta_version_is_fenced(Some(200), Some(201)));
        assert!(!super::cache_meta_version_is_fenced(None, None));
    }

    #[test]
    fn cache_metadata_upsert_rejects_explicitly_invalid_status() {
        let dir = std::env::temp_dir().join(format!(
            "cloud-node-mace-invalid-status-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = MetricStorage::open(&dir).expect("open mace storage");
        let cache_key = format!("https://cache.example.test/{}", uuid::Uuid::new_v4());
        let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));

        storage.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash: &hash,
            cache_key: &cache_key,
            size: 4,
            expires: crate::utils::time::now_timestamp() + 86_400,
            access_time: crate::utils::time::now_timestamp(),
            access_count: 1,
            status: 700,
            headers: &[],
            compressed: false,
            error_status_allowed: false,
            shard_id: None,
            relative_path: None,
            root_path: None,
            event_version: Some(1),
            updated_at: Some(1),
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            created_at: 1,
        });

        assert!(storage.get_cache_meta(&hash).is_none());
        remove_cache_meta_memory(&hash);
        remove_cache_meta_tombstone_memory_through(&hash, u64::MAX);
        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_access_flush_does_not_resurrect_tombstoned_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "cloud-node-mace-access-tombstone-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = MetricStorage::open(&dir).expect("open mace storage");
        let cache_key = format!("https://cache.example.test/access-{}", uuid::Uuid::new_v4());
        let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
        let now = crate::utils::time::now_timestamp();

        storage.delete_cache_meta_at_version(&hash, 200);
        CACHE_META_INDEX.insert(
            hash.clone(),
            CacheMetaEntry {
                cache_key,
                size: 4,
                expires: now + 86_400,
                access_time: now,
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                event_version: Some(100),
                updated_at: now,
                created_at: now,
                ..Default::default()
            },
        );
        CACHE_ACCESS_LOG.insert(hash.clone(), (AtomicI64::new(now), AtomicU64::new(1)));

        storage.flush_cache_accesses();

        assert!(
            storage
                .get_raw(format!("CMETA_{hash}").as_bytes())
                .is_none()
        );
        assert_eq!(cache_meta_tombstone_version_for(&storage, &hash), Some(200));

        remove_cache_meta_memory(&hash);
        remove_cache_meta_tombstone_memory_through(&hash, u64::MAX);
        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_access_flush_does_not_overwrite_newer_durable_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "cloud-node-mace-access-version-{}",
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = MetricStorage::open(&dir).expect("open mace storage");
        let cache_key = format!("https://cache.example.test/access-{}", uuid::Uuid::new_v4());
        let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
        let now = crate::utils::time::now_timestamp();
        let headers = Vec::new();

        storage.upsert_cache_meta_absolute(CacheMetaUpsert {
            hash: &hash,
            cache_key: &cache_key,
            size: 8,
            expires: now + 86_400,
            access_time: now,
            access_count: 9,
            status: 200,
            headers: &headers,
            compressed: false,
            error_status_allowed: false,
            shard_id: None,
            relative_path: None,
            root_path: None,
            event_version: Some(300),
            updated_at: Some(now),
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            created_at: now,
        });
        CACHE_META_INDEX.insert(
            hash.clone(),
            CacheMetaEntry {
                cache_key: cache_key.clone(),
                size: 4,
                expires: now + 86_400,
                access_time: now,
                access_count: 1,
                status: 200,
                headers,
                event_version: Some(100),
                updated_at: now,
                created_at: now,
                ..Default::default()
            },
        );
        CACHE_ACCESS_LOG.insert(hash.clone(), (AtomicI64::new(now), AtomicU64::new(1)));

        storage.flush_cache_accesses();

        let durable = storage
            .get_raw(format!("CMETA_{hash}").as_bytes())
            .and_then(|bytes| cache_meta_entry_from_bytes(&bytes))
            .expect("durable metadata");
        assert_eq!(durable.event_version, Some(300));
        assert_eq!(durable.access_count, 9);

        remove_cache_meta_memory(&hash);
        remove_cache_meta_tombstone_memory_through(&hash, u64::MAX);
        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broad_purge_version_never_moves_back_to_an_older_observation() {
        assert_eq!(newest_cache_meta_broad_purge_version(0, 7), 7);
        assert_eq!(newest_cache_meta_broad_purge_version(9, 7), 9);
        assert_eq!(newest_cache_meta_broad_purge_version(9, 12), 12);
    }

    #[test]
    fn cancelled_metadata_upsert_rolls_back_hot_entry() {
        let cache_key = format!(
            "https://cache.example.test/cancelled-upsert-{}",
            uuid::Uuid::new_v4()
        );
        let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
        let now = crate::utils::time::now_timestamp();
        let meta = CacheMetaEntry {
            cache_key,
            size: 4,
            expires: now + 86_400,
            access_time: now,
            access_count: 1,
            status: 200,
            event_version: Some(next_cache_meta_event_version()),
            updated_at: now,
            created_at: now,
            ..Default::default()
        };

        assert!(apply_cache_meta_memory(&hash, meta.clone()));
        {
            let _rollback = CacheMetaMemoryRollback::new(&hash, meta);
        }
        assert!(get_cache_meta_memory(&hash).is_none());
        delete_cache_meta_for_test(&hash);
    }

    #[test]
    fn failed_old_metadata_cleanup_cannot_remove_newer_hot_entry() {
        let cache_key = format!(
            "https://cache.example.test/failed-upsert-race-{}",
            uuid::Uuid::new_v4()
        );
        let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
        let now = crate::utils::time::now_timestamp();
        let old = CacheMetaEntry {
            cache_key: cache_key.clone(),
            size: 3,
            expires: now + 86_400,
            access_time: now,
            access_count: 1,
            status: 200,
            event_version: Some(next_cache_meta_event_version()),
            updated_at: now,
            created_at: now,
            ..Default::default()
        };
        let newer = CacheMetaEntry {
            size: 4,
            event_version: Some(cache_meta_entry_version(&old).saturating_add(1)),
            updated_at: now.saturating_add(1),
            ..old.clone()
        };

        assert!(apply_cache_meta_memory(&hash, old.clone()));
        assert!(apply_cache_meta_memory(&hash, newer.clone()));
        reconcile_cache_meta_upsert_result(&hash, &old, false);
        assert_eq!(get_cache_meta_memory(&hash), Some(newer));

        delete_cache_meta_for_test(&hash);
    }

    #[test]
    fn successful_metadata_upsert_clears_only_older_hot_tombstone() {
        let cache_key = format!(
            "https://cache.example.test/successful-upsert-{}",
            uuid::Uuid::new_v4()
        );
        let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
        let now = crate::utils::time::now_timestamp();
        let tombstone_version = next_cache_meta_event_version();
        remember_cache_meta_tombstone(&hash, tombstone_version);
        let meta = CacheMetaEntry {
            cache_key,
            size: 4,
            expires: now + 86_400,
            access_time: now,
            access_count: 1,
            status: 200,
            event_version: Some(tombstone_version.saturating_add(1)),
            updated_at: now,
            created_at: now,
            ..Default::default()
        };

        assert!(apply_cache_meta_memory(&hash, meta.clone()));
        reconcile_cache_meta_upsert_result(&hash, &meta, true);
        assert_eq!(cache_meta_tombstone_memory(&hash), None);

        delete_cache_meta_for_test(&hash);
    }
}
