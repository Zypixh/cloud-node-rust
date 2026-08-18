use cloud_node_rust::rpc::metrics::ServerMetricUpdate;
use mace::{Bucket, BucketOptions, Mace, OpCode, Options};
use rust_rocksdb::{DB, MergeOperands, Options as RocksOptions, WriteBatch};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub enum BackendKind {
    Mace,
    RocksDb,
}

impl BackendKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Mace => "mace",
            Self::RocksDb => "rocksdb",
        }
    }

    pub const ALL: [Self; 2] = [Self::Mace, Self::RocksDb];
}

pub fn temp_store(tag: &str, backend: BackendKind) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "cn-storage-bench-{}-{}-{}",
        backend.name(),
        tag,
        uuid::Uuid::new_v4()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

pub trait StorageBackend: Send + Sync {
    fn put_json<T: Serialize>(&self, key: &str, value: &T) -> bool;
    fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T>;
    fn get_value(&self, key: &str) -> u64;
    fn increment_batch(&self, updates: Vec<(String, u64)>);
    fn record_server_batch(
        &self,
        period: i64,
        updates: Vec<ServerMetricUpdate>,
        node_sent: u64,
        node_received: u64,
    );
    fn write_raw_batch(&self, puts: Vec<(String, Vec<u8>)>, deletes: Vec<String>) -> bool;
    fn scan_json_prefix_count(&self, prefix: &str) -> usize;
    fn put_raw(&self, key: &[u8], value: &[u8]) -> bool;
}

pub enum Backend {
    Mace(MaceBackend),
    RocksDb(RocksDbBackend),
}

impl StorageBackend for Backend {
    fn put_json<T: Serialize>(&self, key: &str, value: &T) -> bool {
        match self {
            Self::Mace(b) => b.put_json(key, value),
            Self::RocksDb(b) => b.put_json(key, value),
        }
    }

    fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        match self {
            Self::Mace(b) => b.get_json(key),
            Self::RocksDb(b) => b.get_json(key),
        }
    }

    fn get_value(&self, key: &str) -> u64 {
        match self {
            Self::Mace(b) => b.get_value(key),
            Self::RocksDb(b) => b.get_value(key),
        }
    }

    fn increment_batch(&self, updates: Vec<(String, u64)>) {
        match self {
            Self::Mace(b) => b.increment_batch(updates),
            Self::RocksDb(b) => b.increment_batch(updates),
        }
    }

    fn record_server_batch(
        &self,
        period: i64,
        updates: Vec<ServerMetricUpdate>,
        node_sent: u64,
        node_received: u64,
    ) {
        match self {
            Self::Mace(b) => b.record_server_batch(period, updates, node_sent, node_received),
            Self::RocksDb(b) => b.record_server_batch(period, updates, node_sent, node_received),
        }
    }

    fn write_raw_batch(&self, puts: Vec<(String, Vec<u8>)>, deletes: Vec<String>) -> bool {
        match self {
            Self::Mace(b) => b.write_raw_batch(puts, deletes),
            Self::RocksDb(b) => b.write_raw_batch(puts, deletes),
        }
    }

    fn scan_json_prefix_count(&self, prefix: &str) -> usize {
        match self {
            Self::Mace(b) => b.scan_json_prefix_count(prefix),
            Self::RocksDb(b) => b.scan_json_prefix_count(prefix),
        }
    }

    fn put_raw(&self, key: &[u8], value: &[u8]) -> bool {
        match self {
            Self::Mace(b) => b.put_raw(key, value),
            Self::RocksDb(b) => b.put_raw(key, value),
        }
    }
}

pub fn open_backend(kind: BackendKind, tag: &str) -> Backend {
    let path = temp_store(tag, kind);
    match kind {
        BackendKind::Mace => Backend::Mace(MaceBackend::open(path).expect("open mace backend")),
        BackendKind::RocksDb => {
            Backend::RocksDb(RocksDbBackend::open(path).expect("open rocksdb backend"))
        }
    }
}

pub(crate) struct MaceBackend {
    bucket: Bucket,
}

impl MaceBackend {
    fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let opts = Options::new(&path).validate().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mace = Mace::new(opts).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let bucket = mace
            .new_bucket("metrics", BucketOptions::default())
            .or_else(|err| {
                if err == OpCode::Exist {
                    mace.get_bucket("metrics")
                } else {
                    Err(err)
                }
            })
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        Ok(Self { bucket })
    }

    fn write<F>(&self, f: F) -> bool
    where
        F: FnOnce(&mace::TxnKV<'_>) -> Result<(), OpCode>,
    {
        let Ok(txn) = self.bucket.begin() else {
            return false;
        };
        if f(&txn).is_err() {
            return false;
        }
        txn.commit().is_ok()
    }

    fn merge_u64(txn: &mace::TxnKV<'_>, key: &[u8], delta: u64) -> Result<(), OpCode> {
        let current = match txn.get(key) {
            Ok(value) => parse_u64_be(value.slice()),
            Err(OpCode::NotFound) => 0,
            Err(err) => return Err(err),
        };
        txn.upsert(key, current.saturating_add(delta).to_be_bytes())
    }
}

impl StorageBackend for MaceBackend {
    fn put_json<T: Serialize>(&self, key: &str, value: &T) -> bool {
        match serde_json::to_vec(value) {
            Ok(bytes) => self.put_raw(key.as_bytes(), &bytes),
            Err(_) => false,
        }
    }

    fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let view = self.bucket.view().ok()?;
        view.get(key.as_bytes())
            .ok()
            .map(|v| v.to_vec())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    fn get_value(&self, key: &str) -> u64 {
        let view = self.bucket.view().ok();
        view.and_then(|view| view.get(key.as_bytes()).ok())
            .map(|v| parse_u64_be(v.slice()))
            .unwrap_or(0)
    }

    fn increment_batch(&self, updates: Vec<(String, u64)>) {
        let Ok(txn) = self.bucket.begin() else {
            return;
        };
        for (key, delta) in updates {
            if Self::merge_u64(&txn, key.as_bytes(), delta).is_err() {
                return;
            }
        }
        let _ = txn.commit();
    }

    fn record_server_batch(
        &self,
        period: i64,
        updates: Vec<ServerMetricUpdate>,
        node_sent: u64,
        node_received: u64,
    ) {
        let Ok(txn) = self.bucket.begin() else {
            return;
        };
        for u in updates {
            let prefix = format!("S{}_T{}", u.server_id, period);
            for (suffix, delta) in [
                ("req", u.total_requests),
                ("sent", u.bytes_sent),
                ("recv", u.bytes_received),
                ("cached_sent", u.cached_bytes),
                ("cached_req", u.count_cached_requests),
                ("attack_req", u.count_attack_requests),
                ("attack_sent", u.attack_bytes),
            ] {
                if Self::merge_u64(&txn, format!("{prefix}_{suffix}").as_bytes(), delta).is_err() {
                    return;
                }
            }
            if txn
                .upsert(
                    format!("{prefix}_conns").as_bytes(),
                    u.active_connections.to_be_bytes(),
                )
                .is_err()
            {
                return;
            }
            if txn
                .upsert(format!("{prefix}_ips").as_bytes(), u.count_ips.to_be_bytes())
                .is_err()
            {
                return;
            }
        }
        let node_prefix = format!("NODE_T{period}");
        if Self::merge_u64(&txn, format!("{node_prefix}_sent").as_bytes(), node_sent).is_err() {
            return;
        }
        if Self::merge_u64(
            &txn,
            format!("{node_prefix}_recv").as_bytes(),
            node_received,
        )
        .is_err()
        {
            return;
        }
        let _ = txn.commit();
    }

    fn write_raw_batch(&self, puts: Vec<(String, Vec<u8>)>, deletes: Vec<String>) -> bool {
        if puts.is_empty() && deletes.is_empty() {
            return true;
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

    fn scan_json_prefix_count(&self, prefix: &str) -> usize {
        let Ok(view) = self.bucket.view() else {
            return 0;
        };
        view.seek(prefix)
            .filter(|item| {
                std::str::from_utf8(item.key())
                    .map(|key| key.starts_with(prefix))
                    .unwrap_or(false)
            })
            .filter(|item| serde_json::from_slice::<serde_json::Value>(item.val()).is_ok())
            .count()
    }

    fn put_raw(&self, key: &[u8], value: &[u8]) -> bool {
        self.write(|txn| txn.upsert(key, value))
    }
}

pub(crate) struct RocksDbBackend {
    db: Arc<DB>,
}

impl RocksDbBackend {
    fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut opts = RocksOptions::default();
        opts.create_if_missing(true);
        opts.set_merge_operator_associative("sum", sum_merge_operator);
        opts.set_use_direct_io_for_flush_and_compaction(true);
        opts.set_max_background_jobs(4);
        let db = DB::open(&opts, path)?;
        Ok(Self { db: Arc::new(db) })
    }
}

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

impl StorageBackend for RocksDbBackend {
    fn put_json<T: Serialize>(&self, key: &str, value: &T) -> bool {
        match serde_json::to_vec(value) {
            Ok(bytes) => self.db.put(key.as_bytes(), bytes).is_ok(),
            Err(_) => false,
        }
    }

    fn get_json<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.db
            .get(key.as_bytes())
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    fn get_value(&self, key: &str) -> u64 {
        self.db
            .get(key.as_bytes())
            .ok()
            .flatten()
            .map(|v| parse_u64_be(&v))
            .unwrap_or(0)
    }

    fn increment_batch(&self, updates: Vec<(String, u64)>) {
        let mut batch = WriteBatch::default();
        for (key, delta) in updates {
            batch.merge(key.as_bytes(), delta.to_be_bytes());
        }
        let _ = self.db.write(&batch);
    }

    fn record_server_batch(
        &self,
        period: i64,
        updates: Vec<ServerMetricUpdate>,
        node_sent: u64,
        node_received: u64,
    ) {
        let mut batch = WriteBatch::default();
        for u in updates {
            let prefix = format!("S{}_T{}", u.server_id, period);
            for (suffix, delta) in [
                ("req", u.total_requests),
                ("sent", u.bytes_sent),
                ("recv", u.bytes_received),
                ("cached_sent", u.cached_bytes),
                ("cached_req", u.count_cached_requests),
                ("attack_req", u.count_attack_requests),
                ("attack_sent", u.attack_bytes),
            ] {
                batch.merge(format!("{prefix}_{suffix}").as_bytes(), delta.to_be_bytes());
            }
            batch.put(
                format!("{prefix}_conns").as_bytes(),
                u.active_connections.to_be_bytes(),
            );
            batch.put(format!("{prefix}_ips").as_bytes(), u.count_ips.to_be_bytes());
        }
        let node_prefix = format!("NODE_T{period}");
        batch.merge(
            format!("{node_prefix}_sent").as_bytes(),
            node_sent.to_be_bytes(),
        );
        batch.merge(
            format!("{node_prefix}_recv").as_bytes(),
            node_received.to_be_bytes(),
        );
        let _ = self.db.write(&batch);
    }

    fn write_raw_batch(&self, puts: Vec<(String, Vec<u8>)>, deletes: Vec<String>) -> bool {
        let mut batch = WriteBatch::default();
        for (key, value) in puts {
            batch.put(key.as_bytes(), value);
        }
        for key in deletes {
            batch.delete(key.as_bytes());
        }
        self.db.write(&batch).is_ok()
    }

    fn scan_json_prefix_count(&self, prefix: &str) -> usize {
        let mut count = 0;
        for (key, val) in self.db.prefix_iterator(prefix.as_bytes()).flatten() {
            let key_str = String::from_utf8_lossy(&key);
            if !key_str.starts_with(prefix) {
                break;
            }
            if serde_json::from_slice::<serde_json::Value>(&val).is_ok() {
                count += 1;
            }
        }
        count
    }

    fn put_raw(&self, key: &[u8], value: &[u8]) -> bool {
        self.db.put(key, value).is_ok()
    }
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

pub fn prefill_firewall_records(backend: &Backend, count: usize) {
    let puts = (0..count)
        .map(|i| {
            (
                format!("FWBLK_V1_server_{i}_192.0.2.{i}"),
                format!(
                    r#"{{"target":"192.0.2.{i}","serverId":{i},"scope":"server","source":"runtime","reason":"bench","expiresAt":9999999999,"createdAt":1,"updatedAt":1,"kernelWanted":true,"kernelApplied":false,"kernelStatus":"pending"}}"#
                )
                .into_bytes(),
            )
        })
        .collect();
    assert!(backend.write_raw_batch(puts, Vec::new()));
}

pub fn sample_metric_updates(count: usize) -> Vec<ServerMetricUpdate> {
    (0..count)
        .map(|i| ServerMetricUpdate {
            server_id: (i as i64) + 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            total_requests: 10,
            bytes_sent: 1024,
            bytes_received: 512,
            cached_bytes: 256,
            count_cached_requests: 2,
            count_attack_requests: 0,
            attack_bytes: 0,
            active_connections: 4,
            count_websocket_connections: 0,
            count_ips: 3,
        })
        .collect()
}
