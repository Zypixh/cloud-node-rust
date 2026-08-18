use anyhow::{Context, Result, bail};
use mace::{Bucket, BucketOptions, Mace, OpCode, Options as MaceOptions, TxnKV};
use rust_rocksdb::{DB as RocksDb, IteratorMode, Options as RocksOptions};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const MIGRATION_VERSION: u32 = 1;
const STATE_BUCKET: &str = "migration_state";
const IDENTITY_KEY: &str = "migration-v1:identity";
const BUCKET_CACHE_CAPACITY: usize = 8 << 20;
const BUCKET_POOL_CAPACITY: usize = 8 << 20;
const BUCKET_CHECKPOINT_SIZE: usize = 2 << 20;
const TRANSACTION_RETRIES: usize = 8;

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

impl BucketKind {
    fn name(self) -> &'static str {
        match self {
            Self::Metrics => "metrics",
            Self::UniqueIps => "unique_ip",
            Self::CacheMetadata => "cache_meta",
            Self::Firewall => "firewall",
            Self::WafTokens => "waf_token",
            Self::ClientAgent => "client_agent",
            Self::RuntimeState => "runtime_stats",
        }
    }

    fn marker_key(self) -> String {
        format!("migration-v1:bucket:{}", self.name())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct MigrationIdentity {
    version: u32,
    source: String,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct MigrationMarker {
    records: u64,
    bytes: u64,
    sha256: String,
}

struct BucketDigest {
    hasher: Sha256,
    records: u64,
    bytes: u64,
}

impl BucketDigest {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            records: 0,
            bytes: 0,
        }
    }

    fn add(&mut self, key: &[u8], value: &[u8]) {
        self.hasher.update((key.len() as u64).to_be_bytes());
        self.hasher.update(key);
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value);
        self.records += 1;
        self.bytes += (key.len() + value.len()) as u64;
    }

    fn finish(self) -> MigrationMarker {
        MigrationMarker {
            records: self.records,
            bytes: self.bytes,
            sha256: hex::encode(self.hasher.finalize()),
        }
    }
}

struct MigrationStore {
    engine: Mace,
    buckets: HashMap<BucketKind, Bucket>,
    state: Bucket,
}

impl MigrationStore {
    fn open(destination: &Path) -> Result<Self> {
        let mut options = MaceOptions::new(destination);
        options.lru_capacity = 16 << 20;
        options.stat_mask_cache_count = 1024;
        options.data_handle_cache_capacity = 32;
        options.blob_handle_cache_capacity = 16;
        options.sync_on_write = true;
        let engine = Mace::new(options.validate().map_err(mace_error)?)
            .map_err(mace_error)
            .context("open destination Mace database")?;

        let mut buckets = HashMap::new();
        for kind in ALL_BUCKETS {
            buckets.insert(kind, open_bucket(&engine, kind.name())?);
        }
        let state = open_bucket(&engine, STATE_BUCKET)?;
        Ok(Self {
            engine,
            buckets,
            state,
        })
    }

    fn bucket(&self, kind: BucketKind) -> &Bucket {
        self.buckets
            .get(&kind)
            .expect("all migration buckets are initialized")
    }

    fn prepare(&self, source: &str) -> Result<()> {
        match self.get_state::<MigrationIdentity>(IDENTITY_KEY)? {
            Some(identity) => {
                if identity.version != MIGRATION_VERSION || identity.source != source {
                    bail!(
                        "destination belongs to a different migration source; use a new empty destination"
                    );
                }
            }
            None => {
                if !self.is_empty()? {
                    bail!(
                        "destination contains data but has no migration identity; refusing to merge into it"
                    );
                }
                self.put_state(
                    IDENTITY_KEY,
                    &MigrationIdentity {
                        version: MIGRATION_VERSION,
                        source: source.to_owned(),
                    },
                )?;
            }
        }
        Ok(())
    }

    fn completed_marker(&self, kind: BucketKind) -> Result<Option<MigrationMarker>> {
        self.get_state(&kind.marker_key())
    }

    fn mark_complete(&self, kind: BucketKind, marker: &MigrationMarker) -> Result<()> {
        self.put_state(&kind.marker_key(), marker)?;
        self.engine.sync().map_err(mace_error)?;
        Ok(())
    }

    fn import_batch(&self, kind: BucketKind, records: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        run_transaction(self.bucket(kind), |transaction| {
            for (key, value) in records {
                transaction.upsert(key, value)?;
            }
            Ok(())
        })
        .map_err(mace_error)
    }

    fn is_empty(&self) -> Result<bool> {
        for kind in ALL_BUCKETS {
            if bucket_has_records(self.bucket(kind))? {
                return Ok(false);
            }
        }
        Ok(!bucket_has_records(&self.state)?)
    }

    fn get_state<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let view = self.state.view().map_err(mace_error)?;
        match view.get(key) {
            Ok(value) => serde_json::from_slice(value.slice())
                .map(Some)
                .context("decode Mace migration state"),
            Err(OpCode::NotFound) => Ok(None),
            Err(err) => Err(mace_error(err)),
        }
    }

    fn put_state<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec(value).context("encode Mace migration state")?;
        run_transaction(&self.state, |transaction| transaction.upsert(key, &bytes))
            .map_err(mace_error)
    }
}

pub(crate) fn migrate_rocksdb_metrics(
    source: &Path,
    destination: &Path,
    batch_size: usize,
) -> Result<()> {
    if batch_size == 0 {
        bail!("batch size must be greater than zero");
    }
    let source = source
        .canonicalize()
        .with_context(|| format!("resolve RocksDB source {}", source.display()))?;
    let destination = absolute_path(destination)?;
    if destination == source || destination.starts_with(&source) {
        bail!("Mace destination must be outside the RocksDB source directory");
    }

    let mut options = RocksOptions::default();
    options.create_if_missing(false);
    let rocks = RocksDb::open_for_read_only(&options, &source, false)
        .with_context(|| format!("open legacy RocksDB source {}", source.display()))?;
    let mace = MigrationStore::open(&destination)?;
    let source_identity = source.to_string_lossy().into_owned();
    mace.prepare(&source_identity)?;

    let mut digests = ALL_BUCKETS
        .into_iter()
        .map(|kind| (kind, BucketDigest::new()))
        .collect::<HashMap<_, _>>();
    let mut complete = HashMap::new();
    for kind in ALL_BUCKETS {
        complete.insert(kind, mace.completed_marker(kind)?);
    }
    let mut pending = ALL_BUCKETS
        .into_iter()
        .map(|kind| (kind, Vec::with_capacity(batch_size)))
        .collect::<HashMap<_, _>>();

    for entry in rocks.iterator(IteratorMode::Start) {
        let (key, value) = entry.context("read legacy RocksDB record")?;
        if key.is_empty() {
            bail!("legacy RocksDB contains an empty key, which Mace cannot represent safely");
        }
        let kind = bucket_kind_for_key(&key);
        digests
            .get_mut(&kind)
            .expect("all buckets have digests")
            .add(&key, &value);
        if complete.get(&kind).and_then(Option::as_ref).is_some() {
            continue;
        }

        let records = pending.get_mut(&kind).expect("all buckets have queues");
        records.push((key.to_vec(), value.to_vec()));
        if records.len() >= batch_size {
            mace.import_batch(kind, records)?;
            records.clear();
        }
    }

    for kind in ALL_BUCKETS {
        if complete.get(&kind).and_then(Option::as_ref).is_none() {
            let records = pending.get_mut(&kind).expect("all buckets have queues");
            mace.import_batch(kind, records)?;
        }
        let marker = digests
            .remove(&kind)
            .expect("all buckets have digests")
            .finish();
        match complete.remove(&kind).flatten() {
            Some(previous) if previous == marker => {
                println!(
                    "Verified {}: {} records, {} bytes",
                    kind.name(),
                    marker.records,
                    marker.bytes
                );
            }
            Some(_) => bail!(
                "source digest for {} differs from its completed migration marker; use a new destination",
                kind.name()
            ),
            None => {
                mace.mark_complete(kind, &marker)?;
                println!(
                    "Imported {}: {} records, {} bytes",
                    kind.name(),
                    marker.records,
                    marker.bytes
                );
            }
        }
    }

    println!(
        "Migration complete. The RocksDB source was read-only and was not modified: {}",
        source.display()
    );
    Ok(())
}

fn open_bucket(engine: &Mace, name: &str) -> Result<Bucket> {
    match engine.get_bucket(name) {
        Ok(bucket) => Ok(bucket),
        Err(OpCode::NotFound) => engine
            .new_bucket(name, bucket_options())
            .map_err(mace_error),
        Err(err) => Err(mace_error(err)),
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

fn bucket_has_records(bucket: &Bucket) -> Result<bool> {
    let view = bucket.view().map_err(mace_error)?;
    Ok(view.range::<Vec<u8>, _>(..).next().is_some())
}

fn run_transaction<F>(bucket: &Bucket, mut operation: F) -> std::result::Result<(), OpCode>
where
    F: FnMut(&TxnKV<'_>) -> std::result::Result<(), OpCode>,
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
                std::thread::yield_now();
            }
            Err(err) => return Err(err),
        }
    }
    Err(OpCode::Again)
}

fn retryable(error: OpCode) -> bool {
    matches!(error, OpCode::AbortTx | OpCode::Again)
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

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("read current directory")?
            .join(path))
    }
}

fn mace_error(error: OpCode) -> anyhow::Error {
    anyhow::anyhow!("Mace operation failed with {error:?}")
}

#[cfg(test)]
mod tests {
    use super::{BucketKind, MigrationStore, RocksDb, RocksOptions, migrate_rocksdb_metrics};

    fn test_path(name: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cloud-node-mace-migration-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn imports_and_verifies_a_legacy_rocksdb_database() {
        let source = test_path("source");
        let destination = test_path("destination");
        {
            let mut options = RocksOptions::default();
            options.create_if_missing(true);
            let rocks = RocksDb::open(&options, &source).expect("create legacy RocksDB");
            rocks
                .put("S42_T7_req", 9u64.to_be_bytes())
                .expect("write metric");
            rocks
                .put("FWBLK_V1_global_0_203.0.113.9", br#"{\"expiresAt\":99}"#)
                .expect("write firewall record");
            rocks
                .put("STAT_BANDWIDTH_STATE_V1", br#"{\"currentWindow\":\"7\"}"#)
                .expect("write runtime state");
        }

        migrate_rocksdb_metrics(&source, &destination, 1).expect("import RocksDB into Mace");
        migrate_rocksdb_metrics(&source, &destination, 1).expect("verify completed migration");

        let mace = MigrationStore::open(&destination).expect("open migrated Mace database");
        {
            let view = mace
                .bucket(BucketKind::Metrics)
                .view()
                .expect("open metric bucket view");
            assert_eq!(
                view.get("S42_T7_req")
                    .expect("read imported metric")
                    .slice(),
                9u64.to_be_bytes()
            );
        }
        {
            let firewall = mace
                .bucket(BucketKind::Firewall)
                .view()
                .expect("open firewall bucket view");
            assert_eq!(
                firewall
                    .get("FWBLK_V1_global_0_203.0.113.9")
                    .expect("read imported firewall record")
                    .slice(),
                br#"{\"expiresAt\":99}"#
            );
        }
        {
            let runtime = mace
                .bucket(BucketKind::RuntimeState)
                .view()
                .expect("open runtime state bucket view");
            assert_eq!(
                runtime
                    .get("STAT_BANDWIDTH_STATE_V1")
                    .expect("read imported runtime state")
                    .slice(),
                br#"{\"currentWindow\":\"7\"}"#
            );
        }

        drop(mace);
        std::fs::remove_dir_all(source).expect("remove RocksDB test database");
        std::fs::remove_dir_all(destination).expect("remove Mace test database");
    }
}
