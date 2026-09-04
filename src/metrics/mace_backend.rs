//! Mace adapter for the legacy flat metric-storage key space.
//!
//! Keeping the key format at this boundary makes the storage-engine migration
//! independent from cache, firewall, and RPC behavior. New records are placed
//! in separate Mace buckets, while callers continue to use their established
//! key prefixes.

use mace::{Bucket, BucketOptions, Mace, OpCode, Options as MaceOptions, TxnKV};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::time::Duration;

const TRANSACTION_RETRIES: usize = 8;
const BUCKET_CACHE_CAPACITY: usize = 8 << 20;
const BUCKET_POOL_CAPACITY: usize = 8 << 20;
const BUCKET_CHECKPOINT_SIZE: usize = 2 << 20;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum BucketKind {
    Metrics,
    UniqueIps,
    CacheMetadata,
    Firewall,
    WafTokens,
    ClientAgent,
    RuntimeState,
}

const ALL_BUCKETS: [BucketKind; 7] = [
    BucketKind::Metrics,
    BucketKind::UniqueIps,
    BucketKind::CacheMetadata,
    BucketKind::Firewall,
    BucketKind::WafTokens,
    BucketKind::ClientAgent,
    BucketKind::RuntimeState,
];

type KvIterator = std::vec::IntoIter<Result<(Vec<u8>, Vec<u8>), Error>>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Error(OpCode);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mace operation failed with {:?}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<OpCode> for Error {
    fn from(value: OpCode) -> Self {
        Self(value)
    }
}

pub(crate) enum IteratorMode {
    Start,
}

enum WriteOperation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
    Merge(Vec<u8>, Vec<u8>),
}

#[derive(Default)]
pub(crate) struct WriteBatch {
    operations: Vec<WriteOperation>,
}

impl WriteBatch {
    pub(crate) fn put<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.operations.push(WriteOperation::Put(
            key.as_ref().to_vec(),
            value.as_ref().to_vec(),
        ));
    }

    pub(crate) fn delete<K>(&mut self, key: K)
    where
        K: AsRef<[u8]>,
    {
        self.operations
            .push(WriteOperation::Delete(key.as_ref().to_vec()));
    }

    pub(crate) fn merge<K, V>(&mut self, key: K, value: V)
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.operations.push(WriteOperation::Merge(
            key.as_ref().to_vec(),
            value.as_ref().to_vec(),
        ));
    }
}

pub(crate) struct DB {
    // Bucket handles keep Mace's shared engine state alive. The engine handle
    // is retained explicitly so future explicit sync/checkpoint policy remains
    // available at this boundary.
    _engine: Mace,
    // Mace 0.1.0's short-lived view registration/collector path is not stable
    // under a burst of concurrent view creation. Serialize adapter operations
    // until the upstream collector invariant is fixed; callers still retain
    // concurrency outside the storage boundary and the lock is never held over
    // application or async work.
    operation_lock: Mutex<()>,
    metrics: Bucket,
    unique_ips: Bucket,
    cache_metadata: Bucket,
    firewall: Bucket,
    waf_tokens: Bucket,
    client_agent: Bucket,
    runtime_state: Bucket,
}

impl DB {
    pub(crate) fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut options = MaceOptions::new(path);
        // Mace defaults assume a standalone general-purpose database. This
        // node has seven small buckets and already keeps cache metadata in a
        // DashMap, so cap Mace's resident structures explicitly.
        options.lru_capacity = 16 << 20;
        options.stat_mask_cache_count = 1024;
        options.data_handle_cache_capacity = 32;
        options.blob_handle_cache_capacity = 16;
        options.sync_on_write = true;

        let engine = Mace::new(options.validate().map_err(Error::from)?).map_err(Error::from)?;
        let metrics = open_bucket(&engine, "metrics")?;
        let unique_ips = open_bucket(&engine, "unique_ip")?;
        let cache_metadata = open_bucket(&engine, "cache_meta")?;
        let firewall = open_bucket(&engine, "firewall")?;
        let waf_tokens = open_bucket(&engine, "waf_token")?;
        let client_agent = open_bucket(&engine, "client_agent")?;
        let runtime_state = open_bucket(&engine, "runtime_stats")?;

        Ok(Self {
            _engine: engine,
            operation_lock: Mutex::new(()),
            metrics,
            unique_ips,
            cache_metadata,
            firewall,
            waf_tokens,
            client_agent,
            runtime_state,
        })
    }

    pub(crate) fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>, Error> {
        let _guard = self.operation_lock.lock();
        let key = key.as_ref();
        // Mace 0.1.0's short-lived read-view collector path can reuse an
        // active CC node under sustained view churn. A read-only TxnKV still
        // takes a consistent snapshot, but avoids that broken view registry.
        let transaction = self.bucket_for_key(key).begin().map_err(Error::from)?;
        let value = match transaction.get(key) {
            Ok(value) => Some(value.to_vec()),
            Err(OpCode::NotFound) => None,
            Err(err) => return Err(Error::from(err)),
        };
        transaction.commit().map_err(Error::from)?;
        Ok(value)
    }

    pub(crate) fn put<K, V>(&self, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut batch = WriteBatch::default();
        batch.put(key, value);
        self.write(&batch)
    }

    pub(crate) fn delete<K: AsRef<[u8]>>(&self, key: K) -> Result<(), Error> {
        let mut batch = WriteBatch::default();
        batch.delete(key);
        self.write(&batch)
    }

    pub(crate) fn write(&self, batch: &WriteBatch) -> Result<(), Error> {
        let _guard = self.operation_lock.lock();
        let mut groups: HashMap<BucketKind, Vec<&WriteOperation>> = HashMap::new();
        for operation in &batch.operations {
            let key = match operation {
                WriteOperation::Put(key, _)
                | WriteOperation::Delete(key)
                | WriteOperation::Merge(key, _) => key,
            };
            groups
                .entry(bucket_kind_for_key(key))
                .or_default()
                .push(operation);
        }

        // Mace transactions are bucket scoped. Existing callers only batch
        // firewall keys; grouping retains atomicity for that path and makes
        // accidental cross-domain batches explicit at this boundary.
        for kind in ALL_BUCKETS {
            let Some(operations) = groups.remove(&kind) else {
                continue;
            };
            write_operations(self.bucket(kind), &operations)?;
        }
        Ok(())
    }

    pub(crate) fn iterator(&self, _mode: IteratorMode) -> KvIterator {
        let _guard = self.operation_lock.lock();
        let mut records = Vec::new();
        for kind in ALL_BUCKETS {
            records.extend(scan_bucket(self.bucket(kind), b""));
        }
        records.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        records.into_iter().map(Ok).collect::<Vec<_>>().into_iter()
    }

    pub(crate) fn prefix_iterator<K: AsRef<[u8]>>(&self, prefix: K) -> KvIterator {
        let _guard = self.operation_lock.lock();
        let prefix = prefix.as_ref();
        scan_bucket(self.bucket_for_key(prefix), prefix)
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn bucket_for_key(&self, key: &[u8]) -> &Bucket {
        self.bucket(bucket_kind_for_key(key))
    }

    fn bucket(&self, kind: BucketKind) -> &Bucket {
        match kind {
            BucketKind::Metrics => &self.metrics,
            BucketKind::UniqueIps => &self.unique_ips,
            BucketKind::CacheMetadata => &self.cache_metadata,
            BucketKind::Firewall => &self.firewall,
            BucketKind::WafTokens => &self.waf_tokens,
            BucketKind::ClientAgent => &self.client_agent,
            BucketKind::RuntimeState => &self.runtime_state,
        }
    }
}

fn open_bucket(engine: &Mace, name: &str) -> Result<Bucket, Error> {
    match engine.get_bucket(name) {
        Ok(bucket) => Ok(bucket),
        Err(OpCode::NotFound) => engine
            .new_bucket(name, bucket_options())
            .map_err(Error::from),
        Err(err) => Err(Error::from(err)),
    }
}

fn bucket_options() -> BucketOptions {
    BucketOptions {
        cache_capacity: BUCKET_CACHE_CAPACITY,
        pool_capacity: BUCKET_POOL_CAPACITY,
        checkpoint_size: BUCKET_CHECKPOINT_SIZE,
        enable_backpressure: true,
        ..BucketOptions::default()
    }
}

fn bucket_kind_for_key(key: &[u8]) -> BucketKind {
    if key.starts_with(b"UIP_") {
        BucketKind::UniqueIps
    } else if key.starts_with(b"CMETA_") {
        BucketKind::CacheMetadata
    } else if key.starts_with(b"FWBLK_") {
        BucketKind::Firewall
    } else if key.starts_with(b"WAFTOK_") {
        BucketKind::WafTokens
    } else if key.starts_with(b"CAIP_") {
        BucketKind::ClientAgent
    } else if is_metric_key(key) {
        BucketKind::Metrics
    } else {
        BucketKind::RuntimeState
    }
}

fn is_metric_key(key: &[u8]) -> bool {
    if key.starts_with(b"NODE_T") {
        return true;
    }
    let Some(separator) = key.windows(2).position(|window| window == b"_T") else {
        return false;
    };
    separator > 1
        && key.first() == Some(&b'S')
        && std::str::from_utf8(&key[1..separator])
            .ok()
            .and_then(|server_id| server_id.parse::<i64>().ok())
            .is_some()
}

fn write_operations(bucket: &Bucket, operations: &[&WriteOperation]) -> Result<(), Error> {
    run_transaction(bucket, |transaction| {
        for operation in operations {
            match operation {
                WriteOperation::Put(key, value) => transaction.upsert(key, value)?,
                WriteOperation::Delete(key) => match transaction.del(key) {
                    Ok(()) | Err(OpCode::NotFound) => {}
                    Err(err) => return Err(err),
                },
                WriteOperation::Merge(key, delta) => merge_u64(transaction, key, delta)?,
            }
        }
        Ok(())
    })
    .map_err(Error::from)
}

fn merge_u64(transaction: &TxnKV<'_>, key: &[u8], delta: &[u8]) -> Result<(), OpCode> {
    let existing = match transaction.get(key) {
        Ok(value) => u64_from_be_bytes(value.slice()).unwrap_or(0),
        Err(OpCode::NotFound) => 0,
        Err(err) => return Err(err),
    };
    let delta = u64_from_be_bytes(delta).unwrap_or(0);
    transaction.upsert(key, existing.saturating_add(delta).to_be_bytes())
}

fn u64_from_be_bytes(value: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = value.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn run_transaction<F>(bucket: &Bucket, mut operation: F) -> Result<(), OpCode>
where
    F: FnMut(&TxnKV<'_>) -> Result<(), OpCode>,
{
    for attempt in 0..TRANSACTION_RETRIES {
        let transaction = match bucket.begin() {
            Ok(transaction) => transaction,
            Err(err) if retryable(err) && attempt + 1 < TRANSACTION_RETRIES => {
                std::thread::yield_now();
                continue;
            }
            Err(err) => return Err(err),
        };

        match operation(&transaction).and_then(|()| transaction.commit()) {
            Ok(()) => return Ok(()),
            Err(err) if retryable(err) && attempt + 1 < TRANSACTION_RETRIES => {
                let backoff_us = 50u64.saturating_mul(1u64 << attempt.min(6));
                std::thread::sleep(Duration::from_micros(backoff_us));
            }
            Err(err) => return Err(err),
        }
    }
    Err(OpCode::Again)
}

fn retryable(error: OpCode) -> bool {
    matches!(error, OpCode::AbortTx | OpCode::Again)
}

fn scan_bucket(bucket: &Bucket, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Ok(view) = bucket.view() else {
        return Vec::new();
    };

    if prefix.is_empty() {
        // Mace's seek API intentionally rejects an empty prefix. A lower-bounded
        // range covers the full bucket without relying on an invalid sentinel.
        return view
            .range::<Vec<u8>, _>(..)
            .map(|item| (item.key().to_vec(), item.val().to_vec()))
            .collect();
    }

    view.seek(prefix)
        .take_while(|item| item.key().starts_with(prefix))
        .map(|item| (item.key().to_vec(), item.val().to_vec()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{DB, IteratorMode, WriteBatch};

    fn test_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cloud-node-mace-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn preserves_legacy_key_semantics_across_mace_buckets() {
        let path = test_path();
        let db = DB::open(&path).expect("open Mace test database");

        assert_eq!(
            super::bucket_kind_for_key(b"STAT_BANDWIDTH_STATE_V1"),
            super::BucketKind::RuntimeState
        );
        assert_eq!(
            super::bucket_kind_for_key(b"S7_T42_req"),
            super::BucketKind::Metrics
        );

        let mut batch = WriteBatch::default();
        batch.merge("S7_T42_req", 3u64.to_be_bytes());
        batch.merge("S7_T42_req", 4u64.to_be_bytes());
        batch.put("FWBLK_V1_global_0_203.0.113.9", br#"{\"expiresAt\":99}"#);
        batch.put("STAT_BANDWIDTH_STATE_V1", br#"{\"currentWindow\":\"42\"}"#);
        db.write(&batch).expect("write batch");

        assert_eq!(
            db.get("S7_T42_req")
                .expect("read metric")
                .expect("metric exists"),
            7u64.to_be_bytes()
        );

        let firewall_keys = db
            .prefix_iterator("FWBLK_")
            .flatten()
            .map(|(key, _)| String::from_utf8(key).expect("UTF-8 key"))
            .collect::<Vec<_>>();
        assert_eq!(firewall_keys, vec!["FWBLK_V1_global_0_203.0.113.9"]);

        db.delete("missing-key")
            .expect("missing delete is idempotent");
        db.delete("FWBLK_V1_global_0_203.0.113.9")
            .expect("delete firewall record");
        assert!(
            db.get("FWBLK_V1_global_0_203.0.113.9")
                .expect("read deleted firewall record")
                .is_none()
        );

        let all_keys = db
            .iterator(IteratorMode::Start)
            .flatten()
            .map(|(key, _)| String::from_utf8(key).expect("UTF-8 key"))
            .collect::<Vec<_>>();
        assert_eq!(all_keys, vec!["S7_T42_req", "STAT_BANDWIDTH_STATE_V1"]);

        drop(db);
        std::fs::remove_dir_all(path).expect("remove Mace test database");
    }

    #[test]
    fn serializes_concurrent_reads_without_view_churn() {
        let path = test_path();
        let db = std::sync::Arc::new(DB::open(&path).expect("open Mace test database"));
        db.put("concurrent-read", b"value")
            .expect("seed concurrent read key");

        let mut workers = Vec::new();
        for _ in 0..16 {
            let db = db.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    assert_eq!(
                        db.get("concurrent-read")
                            .expect("concurrent read")
                            .as_deref(),
                        Some(b"value".as_slice())
                    );
                }
            }));
        }
        for worker in workers {
            worker.join().expect("concurrent read worker panicked");
        }

        drop(db);
        std::fs::remove_dir_all(path).expect("remove Mace test database");
    }
}
