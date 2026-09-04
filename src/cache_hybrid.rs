use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR, StaticAdmissionPermit};
use async_trait::async_trait;
use dashmap::{DashMap, DashSet};
use pingora_cache::key::CompactCacheKey;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::{CacheKey, CacheMeta};
use pingora_core::{Error, ErrorType, Result};
use pingora_http::ResponseHeader;
use std::any::Any;
use std::cell::Cell;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::LazyLock as Lazy;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeek, BufReader};
use tokio::sync::{
    Mutex, OwnedMutexGuard, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock as AsyncRwLock,
};
use tracing::{info, warn};

use arc_swap::ArcSwap;

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

static CLUSTER_STORAGE_POLICY_SKIP_LOGGED: AtomicBool = AtomicBool::new(false);

static CACHED_DISK_AVAILABLE: AtomicU64 = AtomicU64::new(u64::MAX);
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
const CACHE_WRITE_LOCK_SHARDS: usize = 256;
static CACHE_WRITE_LOCKS: Lazy<Vec<Arc<Mutex<()>>>> = Lazy::new(|| {
    (0..CACHE_WRITE_LOCK_SHARDS)
        .map(|_| Arc::new(Mutex::new(())))
        .collect()
});
static CACHE_PURGE_GENERATION: AtomicU64 = AtomicU64::new(0);
// Metadata callbacks can invalidate an L1 entry while a memory-only fill is
// still collecting the origin body. Keep a bounded process-wide token for
// active fills so an invalidation cannot be followed by that older fill
// publishing its bytes back into L1. It is intentionally global rather than
// a per-key map, which avoids an unbounded request-path index; unrelated
// in-flight fills may conservatively be discarded.
static CACHE_L1_INVALIDATION_GENERATION: AtomicU64 = AtomicU64::new(0);
// A prefix/tag purge must wait for every fill that started before it, and it
// must prevent new fills from starting while its disk/index scan is running.
// Per-key locks cannot provide that guarantee because a broad purge does not
// know all keys in advance (especially when metadata has not been published
// yet). Keep the barrier separate from the per-key locks so ordinary fills do
// not contend with one another.
static CACHE_PURGE_BARRIER: Lazy<Arc<AsyncRwLock<()>>> =
    Lazy::new(|| Arc::new(AsyncRwLock::new(())));

/// A process-local Tokio lock is not sufficient when several node processes
/// share an RWX cache volume.  Keep a small set of persistent lock files on
/// each configured cache root and use the kernel advisory lock attached to
/// the open file descriptor.  The descriptor is retained by this guard for
/// the whole operation, so a purge cannot race a fill in another process.
pub(crate) struct CacheProcessLockGuard {
    _files: Vec<std::fs::File>,
}

#[derive(Clone, Copy)]
enum CacheProcessLockMode {
    Shared,
    Exclusive,
}

fn cache_process_lock_key(key: &str) -> String {
    let canonical = crate::cache::partial::partial_base_key(key);
    let canonical = canonical.as_deref().unwrap_or(key);
    format!("{:x}", md5_legacy::compute(canonical.as_bytes()))
}

fn cache_process_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = roots.to_vec();
    roots.sort();
    roots.dedup();
    roots
}

fn cache_process_barrier_path(root: &Path) -> PathBuf {
    root.join(".cloud-node-cache-locks").join("barrier.lock")
}

fn cache_process_key_path(root: &Path, key_hash: &str) -> PathBuf {
    let first = key_hash.get(..2).unwrap_or("00");
    root.join(".cloud-node-cache-locks")
        .join("keys")
        .join(first)
        .join(format!("{key_hash}.lock"))
}

#[cfg(unix)]
fn lock_cache_process_file(
    file: &std::fs::File,
    mode: CacheProcessLockMode,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let operation = match mode {
        CacheProcessLockMode::Shared => libc::LOCK_SH,
        CacheProcessLockMode::Exclusive => libc::LOCK_EX,
    };
    // SAFETY: `file` owns a valid open descriptor for the duration of this
    // call and the descriptor is retained in CacheProcessLockGuard until the
    // operation completes. flock does not retain any Rust references.
    let result = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn lock_cache_process_file(
    _file: &std::fs::File,
    _mode: CacheProcessLockMode,
) -> std::io::Result<()> {
    // Production deployments use Linux.  Keep non-Unix builds functional;
    // their existing process-local lock remains the only coordination layer.
    Ok(())
}

async fn acquire_cache_process_lock(
    key: Option<&str>,
    roots: &[PathBuf],
    mode: CacheProcessLockMode,
) -> std::io::Result<CacheProcessLockGuard> {
    let roots = cache_process_roots(roots);
    if roots.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache process lock requires at least one root",
        ));
    }
    let barrier_paths = roots
        .iter()
        .map(|root| cache_process_barrier_path(root))
        .collect::<Vec<_>>();
    let key_hash = key.map(cache_process_lock_key);
    let key_paths = key_hash.as_deref().map(|key_hash| {
        roots
            .iter()
            .map(|root| cache_process_key_path(root, key_hash))
            .collect::<Vec<_>>()
    });

    tokio::task::spawn_blocking(move || {
        let mut files =
            Vec::with_capacity(barrier_paths.len() + key_paths.as_ref().map(Vec::len).unwrap_or(0));

        // Every caller acquires all barrier files in sorted-root order before
        // taking any key file. This fixed order prevents cross-root lock
        // cycles when two processes have overlapping root configurations.
        for path in barrier_paths {
            let Some(parent) = path.parent() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "cache process lock path has no parent",
                ));
            };
            std::fs::create_dir_all(parent)?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&path)?;
            lock_cache_process_file(&file, mode)?;
            files.push(file);
        }
        if let Some(key_paths) = key_paths {
            for path in key_paths {
                let Some(parent) = path.parent() else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "cache process lock path has no parent",
                    ));
                };
                std::fs::create_dir_all(parent)?;
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .truncate(false)
                    .open(&path)?;
                // The resource itself is always exclusive. This prevents a
                // second process from publishing a competing body while a
                // first process is reading/filling the same key.
                lock_cache_process_file(&file, CacheProcessLockMode::Exclusive)?;
                files.push(file);
            }
        }
        Ok(CacheProcessLockGuard { _files: files })
    })
    .await
    .map_err(|err| std::io::Error::other(format!("cache process lock task failed: {err}")))?
}

/// Shared barrier plus exclusive resource lock for a cache read/fill. The
/// shared barrier allows unrelated keys to proceed concurrently, while the
/// key lock serializes all writers/readers for one representation family.
pub(crate) async fn acquire_cache_process_read_lock(
    key: &str,
    roots: &[PathBuf],
) -> std::io::Result<CacheProcessLockGuard> {
    acquire_cache_process_lock(Some(key), roots, CacheProcessLockMode::Shared).await
}

/// Exclusive cross-process barrier for exact, prefix, tag and eviction
/// purges. It blocks both cache reads and fills on every shared root.
pub(crate) async fn acquire_cache_process_barrier_write_lock(
    roots: &[PathBuf],
) -> std::io::Result<CacheProcessLockGuard> {
    acquire_cache_process_lock(None, roots, CacheProcessLockMode::Exclusive).await
}

thread_local! {
    // Cache reclamation updates resident-memory accounting. That observation
    // can synchronously ask the cache to reclaim again, including while a
    // lazy cache index is still being initialized.
    static CACHE_RECLAIM_IN_PROGRESS: Cell<bool> = const { Cell::new(false) };
}

/// A marker carried only by an L2 lookup result.  It lets the hybrid layer
/// prove that an L1 promotion was based on the same purge generation while
/// avoiding a second L2 lookup under the write lock.
#[derive(Clone, Copy)]
struct CacheLookupStamp {
    purge_generation: u64,
    metadata_updated_at: i64,
}

/// A response-cache admission decision that cannot be reconstructed from the
/// status code alone.  In particular, 5xx responses are only replayable when
/// the selected cache rule explicitly listed that exact status.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CacheErrorStatusPolicy {
    pub(crate) allowed: bool,
}

pub(crate) fn cache_meta_allows_error_status(meta: &CacheMeta) -> bool {
    meta.extensions()
        .get::<CacheErrorStatusPolicy>()
        .is_some_and(|policy| policy.allowed)
}

const DISK_HIT_CHUNK_BYTES: usize = 128 * 1024;
const DISK_HIT_CHUNK_BYTES_SENDFILE_REQUESTED: usize = 256 * 1024;
const MEMORY_SERVE_MAX: u64 = 50 * 1024 * 1024;
const BLOOM_BITS_PER_ENTRY_ESTIMATE: u64 = 10;
const BLOOM_LAYER_OVERHEAD_BYTES: u64 = 256;
const L1_RESIZE_GROW_MIN_DELTA_PCT: u64 = 25;
const L1_RESIZE_SHRINK_MIN_DELTA_PCT: u64 = 10;
const L1_RESIZE_GROW_MIN_DELTA_BYTES: u64 = 32 * 1024 * 1024;
const L1_RESIZE_SHRINK_MIN_DELTA_BYTES: u64 = 8 * 1024 * 1024;

fn cache_memory_hit_limit_bytes() -> u64 {
    MEMORY_GOVERNOR
        .cache_read_memory_object_limit_bytes()
        .min(MEMORY_SERVE_MAX)
}

fn try_admit_cache_memory_hit(bytes: u64) -> Option<StaticAdmissionPermit> {
    MEMORY_GOVERNOR.try_admit_cache_read(bytes)
}

pub(crate) fn cache_write_lock_for_key(key: &str) -> Arc<Mutex<()>> {
    // Full objects and all partial-range selectors represent the same
    // resource. Canonicalizing here makes lookup, fill, purge, and cluster
    // metadata updates serialize on one lock instead of allowing a partial
    // fill to race a purge of its base object.
    let canonical_key = crate::cache::partial::partial_base_key(key);
    let lock_key = canonical_key.as_deref().unwrap_or(key);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    lock_key.hash(&mut hasher);
    CACHE_WRITE_LOCKS[(hasher.finish() as usize) % CACHE_WRITE_LOCK_SHARDS].clone()
}

pub(crate) fn current_cache_purge_generation() -> u64 {
    CACHE_PURGE_GENERATION.load(Ordering::Acquire)
}

pub(crate) fn current_cache_l1_invalidation_generation() -> u64 {
    CACHE_L1_INVALIDATION_GENERATION.load(Ordering::Acquire)
}

pub(crate) fn advance_cache_purge_generation() -> u64 {
    CACHE_PURGE_GENERATION
        .fetch_add(1, Ordering::AcqRel)
        .saturating_add(1)
}

pub(crate) async fn acquire_cache_purge_read_guard() -> OwnedRwLockReadGuard<()> {
    CACHE_PURGE_BARRIER.clone().read_owned().await
}

pub(crate) async fn acquire_cache_purge_write_guard() -> OwnedRwLockWriteGuard<()> {
    CACHE_PURGE_BARRIER.clone().write_owned().await
}

fn timestamp_from_system_time(time: std::time::SystemTime) -> i64 {
    time.duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_else(|_| crate::utils::time::now_timestamp())
}

fn system_time_from_timestamp(timestamp: i64) -> std::time::SystemTime {
    if timestamp <= 0 {
        return std::time::UNIX_EPOCH;
    }
    std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(timestamp as u64))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
}

/// Allocate an ordering token for an L1 object that may not have a durable
/// CMETA row.  Purge fences are intentionally retained in shared metadata, so
/// the token must be newer than both an exact-key tombstone and a broad-purge
/// fence already visible to this process.  This lets a post-purge memory
/// fallback remain usable while an older delayed purge/upsert is still fenced.
fn new_cache_l1_state_version(hash: &str) -> u64 {
    let exact_fence = crate::metrics::storage::cache_meta_tombstone_version(hash).unwrap_or(0);
    let broad_fence = crate::metrics::storage::cache_meta_broad_purge_version();
    crate::metrics::storage::next_cache_meta_event_version()
        .max(exact_fence.saturating_add(1))
        .max(broad_fence.saturating_add(1))
}

fn cache_root_from_path(path: &Path) -> Option<PathBuf> {
    path.parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(PathBuf::from)
}

/// Parse a delta-seconds Cache-Control directive from one header value.
/// Returns `None` if the directive is absent or its value is invalid.
fn parse_cache_control_delta(cc: &str, directive: &str) -> Option<u64> {
    for part in cc.split(',') {
        let trimmed = part.trim();
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(directive) {
            return value.trim().trim_matches('"').parse::<u64>().ok();
        }
    }
    None
}

pub(crate) fn parse_stale_directive_from_headers(
    headers: &http::HeaderMap,
    directive: &str,
) -> Option<u64> {
    // RFC 9111 forbids serving stale when these directives are present. The
    // normal Pingora CacheControl parser applies the same rule; keep the
    // custom cache metadata path in lockstep with it.
    let forbids_stale = headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .any(|part| {
            let name = part
                .split_once('=')
                .map(|(name, _)| name.trim())
                .unwrap_or(part);
            name.eq_ignore_ascii_case("must-revalidate")
                || name.eq_ignore_ascii_case("proxy-revalidate")
                || name.eq_ignore_ascii_case("s-maxage")
        });
    if forbids_stale {
        return Some(0);
    }
    headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| parse_cache_control_delta(value, directive))
}

fn zstd_decompress_to_bytes(data: &[u8], capacity: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let decoder = zstd::Decoder::new(data).ok()?;
    let mut out = Vec::with_capacity(capacity.min(64 * 1024));
    let mut reader = std::io::BufReader::new(decoder);
    let mut buf = [0u8; 32 * 1024];
    loop {
        let read = reader.read(&mut buf).ok()?;
        if read == 0 {
            return Some(out);
        }
        if out.len().saturating_add(read) > capacity {
            return None;
        }
        out.extend_from_slice(&buf[..read]);
    }
}

/// Dynamic Disk-based storage for Pingora-cache
pub struct FileStorage {
    pub inner: ArcSwap<FileStorageInner>,
    enable_sendfile: AtomicBool,
    enable_file_cache: AtomicBool,
}

pub struct FileStorageInner {
    layout: FileStorageLayout,
}

#[derive(Clone)]
pub struct PartialStorageLocation {
    pub roots: Vec<PathBuf>,
    pub write_root: PathBuf,
}

pub enum FileStorageLayout {
    Single {
        main_root: PathBuf,
        extra_roots: Vec<PathBuf>,
    },
    Sharded {
        shards: Vec<CacheShard>,
        fallback_roots: Vec<PathBuf>,
    },
}

#[derive(Clone)]
pub struct CacheShard {
    pub id: String,
    pub root: PathBuf,
    pub weight: u32,
}

impl FileStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let main_root = root.into();
        let _ = std::fs::create_dir_all(&main_root);
        Self {
            inner: ArcSwap::from_pointee(FileStorageInner::single(main_root, Vec::new())),
            enable_sendfile: AtomicBool::new(true),
            enable_file_cache: AtomicBool::new(true),
        }
    }

    pub fn update_config(
        &self,
        main: PathBuf,
        extras: Vec<PathBuf>,
        sendfile: bool,
        file_cache: bool,
    ) {
        let _ = std::fs::create_dir_all(&main);
        for extra in &extras {
            let _ = std::fs::create_dir_all(extra);
        }
        self.inner
            .store(Arc::new(FileStorageInner::single(main, extras)));
        self.enable_sendfile.store(sendfile, Ordering::Relaxed);
        self.enable_file_cache.store(file_cache, Ordering::Relaxed);
    }

    pub fn update_shards(
        &self,
        shards: Vec<CacheShard>,
        fallback_roots: Vec<PathBuf>,
        sendfile: bool,
        file_cache: bool,
    ) {
        for shard in &shards {
            let _ = std::fs::create_dir_all(&shard.root);
        }
        for root in &fallback_roots {
            let _ = std::fs::create_dir_all(root);
        }
        self.inner
            .store(Arc::new(FileStorageInner::sharded(shards, fallback_roots)));
        self.enable_sendfile.store(sendfile, Ordering::Relaxed);
        self.enable_file_cache.store(file_cache, Ordering::Relaxed);
    }

    fn get_hash(&self, key: &CacheKey) -> String {
        let k_str = key.primary_key_str().unwrap_or("unknown");
        format!("{:x}", md5_legacy::compute(k_str))
    }

    pub fn get_path(&self, key: &CacheKey) -> PathBuf {
        let hash = self.get_hash(key);
        self.get_path_by_hash(&hash)
    }

    fn get_write_location(&self, key: &CacheKey) -> (PathBuf, Option<String>, String) {
        let hash = self.get_hash(key);
        let inner = self.inner.load();
        inner.write_location(&hash)
    }

    fn enable_file_cache(&self) -> bool {
        self.enable_file_cache.load(Ordering::Relaxed)
    }

    fn enable_sendfile(&self) -> bool {
        self.enable_sendfile.load(Ordering::Relaxed)
    }

    fn disk_hit_chunk_bytes(&self) -> usize {
        if self.enable_sendfile() {
            DISK_HIT_CHUNK_BYTES_SENDFILE_REQUESTED
        } else {
            DISK_HIT_CHUNK_BYTES
        }
    }

    fn get_path_by_hash(&self, hash: &str) -> PathBuf {
        let inner = self.inner.load();
        inner.write_path(hash)
    }

    async fn find_existing_path_by_hash(
        &self,
        hash: &str,
        preferred_root: Option<&str>,
        preferred_relative_path: Option<&str>,
    ) -> Option<PathBuf> {
        let relative = cache_relative_path_for_metadata(hash, preferred_relative_path)?;
        // Metadata records the root that owns the body. Once present, never
        // fall back to another configured root for the same hash: doing so can
        // pair a new body's bytes with an old root's metadata after a shard
        // or directory reconfiguration.
        if let Some(preferred_root) = preferred_root {
            let preferred_root = Path::new(preferred_root);
            let is_configured_root = {
                let inner = self.inner.load();
                inner.all_roots().iter().any(|root| root == preferred_root)
            };
            if !is_configured_root {
                return None;
            }
            let path = preferred_root.join(&relative);
            return tokio::fs::metadata(&path).await.is_ok().then_some(path);
        }
        let paths = {
            let inner = self.inner.load();
            inner
                .read_paths(hash)
                .into_iter()
                .filter_map(|path| cache_root_from_path(&path))
                .map(|root| root.join(&relative))
                .collect::<Vec<_>>()
        };
        for path in paths {
            if tokio::fs::metadata(&path).await.is_ok() {
                return Some(path);
            }
        }
        None
    }

    pub fn partial_location_for_key_str(&self, key: &str) -> PartialStorageLocation {
        let root_key =
            crate::cache::partial::partial_base_key(key).unwrap_or_else(|| key.to_string());
        let hash = format!("{:x}", md5_legacy::compute(root_key.as_bytes()));
        let inner = self.inner.load();
        let (path, _, _) = inner.write_location(&hash);
        let write_root = path
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::paths::NodePaths::current().cache_dir());
        let mut roots = inner.all_roots();
        if let Some(position) = roots.iter().position(|root| root == &write_root) {
            if position != 0 {
                let current_write_root = roots.remove(position);
                roots.insert(0, current_write_root);
            }
        } else {
            roots.insert(0, write_root.clone());
        }
        PartialStorageLocation { roots, write_root }
    }
}

impl FileStorageInner {
    fn single(main_root: PathBuf, extra_roots: Vec<PathBuf>) -> Self {
        Self {
            layout: FileStorageLayout::Single {
                main_root,
                extra_roots,
            },
        }
    }

    fn sharded(shards: Vec<CacheShard>, fallback_roots: Vec<PathBuf>) -> Self {
        Self {
            layout: FileStorageLayout::Sharded {
                shards,
                fallback_roots,
            },
        }
    }

    fn write_path(&self, hash: &str) -> PathBuf {
        self.write_location(hash).0
    }

    fn write_location(&self, hash: &str) -> (PathBuf, Option<String>, String) {
        let relative = cache_relative_path(hash);
        let relative_str = relative.to_string_lossy().to_string();
        match &self.layout {
            FileStorageLayout::Single { main_root, .. } => {
                (main_root.join(relative), None, relative_str)
            }
            FileStorageLayout::Sharded { .. } => self
                .selected_shard(hash)
                .map(|shard| {
                    (
                        shard.root.join(&relative),
                        Some(shard.id.clone()),
                        relative_str.clone(),
                    )
                })
                .unwrap_or_else(|| {
                    (
                        crate::paths::NodePaths::current()
                            .cache_dir()
                            .join(relative),
                        None,
                        relative_str,
                    )
                }),
        }
    }

    fn read_paths(&self, hash: &str) -> Vec<PathBuf> {
        let relative = cache_relative_path(hash);
        match &self.layout {
            FileStorageLayout::Single {
                main_root,
                extra_roots,
            } => extra_roots
                .iter()
                .chain(std::iter::once(main_root))
                .map(|root| root.join(&relative))
                .collect(),
            FileStorageLayout::Sharded {
                shards,
                fallback_roots,
            } => {
                let mut roots = Vec::with_capacity(shards.len() + fallback_roots.len());
                if let Some(selected) = self.selected_shard(hash) {
                    roots.push(selected.root.clone());
                }
                for shard in shards {
                    if !roots.iter().any(|root| root == &shard.root) {
                        roots.push(shard.root.clone());
                    }
                }
                roots.extend(fallback_roots.iter().cloned());
                roots.into_iter().map(|root| root.join(&relative)).collect()
            }
        }
    }

    fn selected_shard(&self, hash: &str) -> Option<&CacheShard> {
        let FileStorageLayout::Sharded { shards, .. } = &self.layout else {
            return None;
        };
        if shards.is_empty() {
            return None;
        }
        let prefix = hash.get(..16).unwrap_or(hash);
        let value = u64::from_str_radix(prefix, 16).unwrap_or_else(|_| {
            let bytes = md5_legacy::compute(hash.as_bytes());
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        });
        shards.get((value as usize) % shards.len())
    }

    pub fn all_roots(&self) -> Vec<PathBuf> {
        match &self.layout {
            FileStorageLayout::Single {
                main_root,
                extra_roots,
            } => std::iter::once(main_root.clone())
                .chain(extra_roots.iter().cloned())
                .collect(),
            FileStorageLayout::Sharded {
                shards,
                fallback_roots,
            } => shards
                .iter()
                .map(|shard| shard.root.clone())
                .chain(fallback_roots.iter().cloned())
                .collect(),
        }
    }
}

fn cache_relative_path(hash: &str) -> PathBuf {
    Path::new(&hash[0..2]).join(&hash[2..4]).join(hash)
}

/// Resolve the body path recorded in metadata. New entries use an immutable
/// `<hash>.body.<writer-id>` filename; older entries used the bare hash. Keep
/// the accepted shape narrow so a corrupt metadata record cannot escape the
/// configured cache root through `..` or an absolute path.
fn cache_relative_path_for_metadata(hash: &str, relative_path: Option<&str>) -> Option<PathBuf> {
    let canonical = cache_relative_path(hash);
    let Some(relative_path) = relative_path else {
        return Some(canonical);
    };
    let relative = Path::new(relative_path);
    if relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir
                    | std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return None;
    }
    if relative.parent() != canonical.parent() {
        return None;
    }
    let filename = relative.file_name()?.to_str()?;
    if filename == hash {
        return Some(relative.to_path_buf());
    }
    let version_prefix = format!("{hash}.body.");
    let version = filename.strip_prefix(&version_prefix)?;
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(relative.to_path_buf())
}

fn status_allows_content_length(status: u16) -> bool {
    !(status < 200 || status == 204 || status == 304)
}

fn restore_content_length(header: &mut ResponseHeader, status: u16, size: u64) {
    if status_allows_content_length(status) && !header.headers.contains_key("content-length") {
        let _ = header.insert_header("content-length", size.to_string());
    }
}

fn cache_key_is_head_variant(key: &str) -> bool {
    crate::cache::cache_key_is_head_variant(key)
}

fn should_store_header_for_cache_key(key: &str, name: &str) -> bool {
    crate::cache::should_store_response_header(name)
        || (cache_key_is_head_variant(key) && name.eq_ignore_ascii_case("content-length"))
}

fn content_length_matches_body(key: &str, content_length: Option<u64>, body_size: u64) -> bool {
    if cache_key_is_head_variant(key) {
        body_size == 0
    } else {
        content_length.is_none_or(|length| length == body_size)
    }
}

fn persisted_content_length_matches_body(
    key: &str,
    headers: &[(String, String)],
    body_size: u64,
) -> bool {
    let mut content_length = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let Some(value) = value.trim().parse::<u64>().ok() else {
            return false;
        };
        if content_length.is_some_and(|existing| existing != value) {
            return false;
        }
        content_length = Some(value);
    }
    content_length_matches_body(key, content_length, body_size)
}

fn parse_runtime_size_bytes(value: &str) -> anyhow::Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }

    let split_at = trimmed
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(trimmed.len());
    let (number, unit) = trimmed.split_at(split_at);
    let count = number
        .parse::<f64>()
        .map_err(|_| anyhow::anyhow!("invalid size value: {value}"))?;
    let multiplier = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1_f64,
        "k" | "kb" | "ki" | "kib" => 1024_f64,
        "m" | "mb" | "mi" | "mib" => 1024_f64.powi(2),
        "g" | "gb" | "gi" | "gib" => 1024_f64.powi(3),
        "t" | "tb" | "ti" | "tib" => 1024_f64.powi(4),
        other => anyhow::bail!("unsupported size unit in {value}: {other}"),
    };
    Ok((count * multiplier) as u64)
}

async fn remove_cache_file_from_roots(inner: &FileStorageInner, hash: &str) {
    for root in inner.all_roots() {
        let relative = cache_relative_path(hash);
        let Some(parent) = relative.parent() else {
            continue;
        };
        let directory = root.join(parent);
        let Ok(mut entries) = fs::read_dir(&directory).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let filename = entry.file_name();
            let Some(filename) = filename.to_str() else {
                continue;
            };
            if filename == hash
                || filename.starts_with(&format!("{hash}.body."))
                || filename.starts_with(&format!("{hash}.tmp."))
            {
                let _ = fs::remove_file(entry.path()).await;
            }
        }
    }
}

#[async_trait]
impl Storage for FileStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            let location = self.partial_location_for_key_str(k_str);
            return Ok(crate::cache::partial::lookup(k_str, &location.roots)
                .await
                .map_err(|_| Error::new(ErrorType::InternalError))?
                .map(|hit| (hit.meta, hit.handler)));
        }

        let key_str = key.primary_key_str().unwrap_or("unknown");
        // Keep the ordinary read path on the same ordering as broad purge:
        // purge read barrier, then canonical key lock. This prevents a
        // prefix/tag purge from validating metadata and opening an old body
        // after the purge has already acquired its write barrier.
        let _purge_guard = acquire_cache_purge_read_guard().await;
        let write_lock = cache_write_lock_for_key(key_str);
        let _write_guard = write_lock.lock().await;
        let process_roots = self.inner.load().all_roots();
        let process_lock = match acquire_cache_process_read_lock(key_str, &process_roots).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(
                    key = key_str,
                    error = %err,
                    "CACHE_HIT: unable to acquire cross-process cache lock; bypassing cache"
                );
                return Ok(None);
            }
        };
        let hash = self.get_hash(key);

        let meta = match crate::metrics::storage::get_cache_meta_memory(&hash) {
            Some(m) => m,
            None => return Ok(None),
        };
        if meta.cache_key != key_str {
            warn!(
                "CACHE_HIT_KEY_MISMATCH: hash={} requested_key={} stored_key={}",
                hash, key_str, meta.cache_key
            );
            return Ok(None);
        }
        let status = meta.status;
        if !crate::cache::status_allows_full_cache_with_error_policy(
            status,
            meta.error_status_allowed,
        ) {
            warn!(
                hash,
                key = key_str,
                status,
                "CACHE_HIT_UNREPLAYABLE_STATUS: dropping invalid full-object entry"
            );
            let inner = self.inner.load();
            remove_cache_file_from_roots(&inner, &hash).await;
            crate::metrics::storage::STORAGE
                .delete_cache_meta_async(&hash)
                .await;
            return Ok(None);
        }
        if !crate::cache::stored_response_headers_allow_shared_cache(&meta.headers) {
            warn!(
                hash,
                key = key_str,
                "CACHE_HIT_UNSAFE_METADATA: dropping cache entry with unsafe headers"
            );
            let inner = self.inner.load();
            remove_cache_file_from_roots(&inner, &hash).await;
            crate::metrics::storage::STORAGE
                .delete_cache_meta_async(&hash)
                .await;
            return Ok(None);
        }

        let now = crate::utils::time::now_timestamp();
        if meta.expires < now {
            let stale_window = meta
                .stale_while_revalidate_secs
                .max(meta.stale_if_error_secs)
                .min(i64::MAX as u64) as i64;
            let stale_until = meta.expires.saturating_add(stale_window);
            if stale_window == 0 || now > stale_until {
                let inner = self.inner.load();
                remove_cache_file_from_roots(&inner, &hash).await;
                crate::metrics::storage::STORAGE
                    .delete_cache_meta_async(&hash)
                    .await;
                return Ok(None);
            }
        }

        let Some(path) = self
            .find_existing_path_by_hash(
                &hash,
                meta.root_path.as_deref(),
                meta.relative_path.as_deref(),
            )
            .await
        else {
            crate::metrics::storage::STORAGE
                .delete_cache_meta_async(&hash)
                .await;
            return Ok(None);
        };

        let file_size = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata.len(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                crate::metrics::storage::STORAGE
                    .delete_cache_meta_async(&hash)
                    .await;
                return Ok(None);
            }
            Err(_) => return Err(Error::new(ErrorType::InternalError)),
        };
        if !meta.compressed && meta.size != file_size {
            warn!(
                "CACHE_HIT_META_SIZE_MISMATCH: hash={} metadata_size={} file_size={} path={}",
                hash,
                meta.size,
                file_size,
                path.display()
            );
            crate::metrics::storage::STORAGE
                .delete_cache_meta_async(&hash)
                .await;
            return Ok(None);
        }

        if !persisted_content_length_matches_body(key_str, &meta.headers, meta.size) {
            warn!(
                hash,
                key = key_str,
                "CACHE_HIT_CONTENT_LENGTH_MISMATCH: dropping inconsistent metadata"
            );
            let inner = self.inner.load();
            remove_cache_file_from_roots(&inner, &hash).await;
            crate::metrics::storage::STORAGE
                .delete_cache_meta_async(&hash)
                .await;
            return Ok(None);
        }

        if !crate::cache::stored_response_encoding_matches_cache_key(key_str, &meta.headers) {
            warn!(
                hash,
                key = key_str,
                "CACHE_HIT_ENCODING_MISMATCH: dropping cache entry with wrong representation"
            );
            let inner = self.inner.load();
            remove_cache_file_from_roots(&inner, &hash).await;
            crate::metrics::storage::STORAGE
                .delete_cache_meta_async(&hash)
                .await;
            return Ok(None);
        }

        let mut header = pingora_http::ResponseHeader::build(status, None).unwrap();
        for (name, val) in &meta.headers {
            let _ = header.append_header(name.to_string(), val.as_str());
        }
        restore_content_length(&mut header, status, meta.size);

        let mut cache_meta = CacheMeta::new(
            system_time_from_timestamp(meta.expires),
            system_time_from_timestamp(if meta.created_at > 0 {
                meta.created_at
            } else {
                meta.updated_at
            }),
            meta.stale_while_revalidate_secs.min(u32::MAX as u64) as u32,
            meta.stale_if_error_secs.min(u32::MAX as u64) as u32,
            header,
        );
        cache_meta.extensions_mut().insert(CacheLookupStamp {
            purge_generation: current_cache_purge_generation(),
            metadata_updated_at: meta.updated_at,
        });
        cache_meta.extensions_mut().insert(CacheErrorStatusPolicy {
            allowed: meta.error_status_allowed,
        });
        let io_start = std::time::Instant::now();
        let enable_file_cache = self.enable_file_cache();
        let disk_hit_chunk_bytes = self.disk_hit_chunk_bytes();
        let memory_hit_limit = cache_memory_hit_limit_bytes();

        if !meta.compressed {
            let memory_hit_permit = if enable_file_cache
                && meta.size <= memory_hit_limit
                && file_size <= memory_hit_limit
            {
                try_admit_cache_memory_hit(file_size)
            } else {
                None
            };
            if let Some(cache_read_permit) = memory_hit_permit {
                let file_data = match tokio::fs::read(&path).await {
                    Ok(data) => data,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        crate::metrics::storage::STORAGE
                            .delete_cache_meta_async(&hash)
                            .await;
                        return Ok(None);
                    }
                    Err(_) => return Err(Error::new(ErrorType::InternalError)),
                };
                PROF_DISK_READ_US
                    .fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
                crate::metrics::storage::record_cache_access_memory(&hash);
                let body = bytes::Bytes::from(file_data);
                let body_len = body.len();
                return Ok(Some((
                    cache_meta,
                    Box::new(MemoryHitHandler {
                        data: body,
                        offset: 0,
                        end: body_len,
                        _process_lock: Some(process_lock),
                        _cache_read_permit: Some(cache_read_permit),
                    }),
                )));
            }

            let file = match tokio::fs::File::open(&path).await {
                Ok(file) => file,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    crate::metrics::storage::STORAGE
                        .delete_cache_meta_async(&hash)
                        .await;
                    return Ok(None);
                }
                Err(_) => return Err(Error::new(ErrorType::InternalError)),
            };
            PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
            crate::metrics::storage::record_cache_access_memory(&hash);
            return Ok(Some((
                cache_meta,
                Box::new(FileHitHandler {
                    reader: FileHitReader::Plain(file),
                    buf_size: disk_hit_chunk_bytes,
                    expected_len: meta.size,
                    read_len: 0,
                    range_end: meta.size,
                    range_limited: false,
                    eof_verified: false,
                    seek_pending: false,
                    corruption_entry: Some(CorruptCacheEntry::from_meta(
                        &hash, key_str, &path, &meta,
                    )),
                    _process_lock: Some(process_lock),
                }),
            )));
        }

        let compressed_memory_charge = meta.size.saturating_add(file_size).min(MEMORY_SERVE_MAX);
        let compressed_memory_permit = if enable_file_cache
            && meta.size > 0
            && meta.size <= DISK_HIT_CHUNK_BYTES as u64
            && file_size <= disk_hit_chunk_bytes as u64
        {
            try_admit_cache_memory_hit(compressed_memory_charge)
        } else {
            None
        };
        if let Some(cache_read_permit) = compressed_memory_permit {
            let file_data = match tokio::fs::read(&path).await {
                Ok(data) => data,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    crate::metrics::storage::STORAGE
                        .delete_cache_meta_async(&hash)
                        .await;
                    return Ok(None);
                }
                Err(_) => return Err(Error::new(ErrorType::InternalError)),
            };
            PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
            crate::metrics::storage::record_cache_access_memory(&hash);
            let capacity = meta.size.min(MEMORY_SERVE_MAX) as usize;
            let result =
                tokio::task::spawn_blocking(move || zstd_decompress_to_bytes(&file_data, capacity))
                    .await;
            let body = match result {
                Ok(Some(data)) if data.len() as u64 == meta.size => bytes::Bytes::from(data),
                _ => {
                    discard_corrupt_cache_entry_locked(CorruptCacheEntry::from_meta(
                        &hash, key_str, &path, &meta,
                    ))
                    .await;
                    return Ok(None);
                }
            };
            let body_len = body.len();
            return Ok(Some((
                cache_meta,
                Box::new(MemoryHitHandler {
                    data: body,
                    offset: 0,
                    end: body_len,
                    _process_lock: Some(process_lock),
                    _cache_read_permit: Some(cache_read_permit),
                }),
            )));
        }

        let file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                crate::metrics::storage::STORAGE
                    .delete_cache_meta_async(&hash)
                    .await;
                return Ok(None);
            }
            Err(_) => return Err(Error::new(ErrorType::InternalError)),
        };
        PROF_DISK_READ_US.fetch_add(io_start.elapsed().as_micros() as u64, Ordering::Relaxed);
        crate::metrics::storage::record_cache_access_memory(&hash);
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(BufReader::new(file));
        Ok(Some((
            cache_meta,
            Box::new(FileHitHandler {
                reader: FileHitReader::Compressed(decoder),
                buf_size: disk_hit_chunk_bytes,
                expected_len: meta.size,
                read_len: 0,
                range_end: meta.size,
                range_limited: false,
                eof_verified: false,
                seek_pending: false,
                corruption_entry: Some(CorruptCacheEntry::from_meta(&hash, key_str, &path, &meta)),
                _process_lock: Some(process_lock),
            }),
        )))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<MissHandler> {
        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            let resp_headers = meta.response_header();
            if resp_headers.status.as_u16() != 206
                || !crate::cache::response_headers_allow_shared_cache(&resp_headers.headers)
                || !crate::cache::response_encoding_matches_cache_key(k_str, &resp_headers.headers)
            {
                return Ok(Box::new(NoopMissHandler));
            }
            let Some(content_range) =
                crate::cache::partial::content_range_from_headers(&resp_headers.headers)
            else {
                // A malformed partial cache metadata header must not abort a
                // valid origin response. Pingora can still stream the body;
                // this request simply becomes a cache no-op.
                warn!(
                    key = k_str,
                    "CACHE_PARTIAL_MISS: missing or invalid Content-Range; bypassing fill"
                );
                return Ok(Box::new(NoopMissHandler));
            };
            if !crate::cache::partial::content_range_matches_cache_key(k_str, &content_range)
                || resp_headers
                    .headers
                    .get("content-length")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        let expected = content_range
                            .end
                            .checked_sub(content_range.start)
                            .and_then(|length| length.checked_add(1));
                        value.trim().parse::<u64>().ok() != expected
                    })
            {
                warn!(
                    key = k_str,
                    "CACHE_PARTIAL_MISS: origin Content-Range does not match cache key; bypassing fill"
                );
                return Ok(Box::new(NoopMissHandler));
            }
            let expires = meta
                .fresh_until()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs() as i64)
                .unwrap_or_else(|_| crate::utils::time::now_timestamp());
            let capture = crate::cache::partial::PartialCapture {
                start: content_range.start,
                end: content_range.end,
                total: content_range.total,
                expires,
                headers: crate::cache::partial::response_headers_to_store(&resp_headers.headers),
                etag: resp_headers
                    .headers
                    .get("etag")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                last_modified: resp_headers
                    .headers
                    .get("last-modified")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string),
                created_at: timestamp_from_system_time(meta.created()),
                min_size: None,
                max_size: None,
            };
            let location = self.partial_location_for_key_str(k_str);
            let Some(cache_write_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::CacheWrite)
            else {
                return Ok(Box::new(NoopMissHandler));
            };
            // Acquire both fences before returning the miss handler. If this
            // is delayed until the first body chunk, an exact purge can finish
            // in the meantime and the old origin response can be published
            // after the purge.
            let purge_guard = acquire_cache_purge_read_guard().await;
            let write_guard = cache_write_lock_for_key(k_str).lock_owned().await;
            let process_lock = match acquire_cache_process_read_lock(k_str, &location.roots).await {
                Ok(lock) => lock,
                Err(err) => {
                    warn!(
                        key = k_str,
                        error = %err,
                        "CACHE_PARTIAL_MISS: unable to acquire cross-process cache lock; bypassing fill"
                    );
                    return Ok(Box::new(NoopMissHandler));
                }
            };
            let purge_generation = current_cache_purge_generation();
            return Ok(Box::new(PartialMissHandler {
                cache_key: k_str.to_string(),
                capture,
                writer: None,
                location,
                disabled: false,
                purge_generation,
                purge_guard: Some(purge_guard),
                write_guard: Some(write_guard),
                process_lock: Some(process_lock),
                _cache_write_permit: cache_write_permit,
            }));
        }

        let Some(cache_write_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::CacheWrite) else {
            return Ok(Box::new(NoopMissHandler));
        };

        let k_str = key.primary_key_str().unwrap_or("unknown").to_string();
        let resp_headers = meta.response_header();
        let status = resp_headers.status.as_u16();
        let error_status_allowed = cache_meta_allows_error_status(meta);
        if !crate::cache::status_allows_full_cache_with_error_policy(status, error_status_allowed)
            || !crate::cache::response_headers_allow_shared_cache(&resp_headers.headers)
            || !crate::cache::response_encoding_matches_cache_key(&k_str, &resp_headers.headers)
        {
            return Ok(Box::new(NoopMissHandler));
        }

        let mut header_pairs = Vec::with_capacity(resp_headers.headers.len());
        for (name, value) in resp_headers.headers.iter() {
            if !should_store_header_for_cache_key(&k_str, name.as_str()) {
                continue;
            }
            let Ok(value) = value.to_str() else {
                warn!(
                    key = %k_str,
                    header = %name,
                    "CACHE_MISS: response header is not UTF-8; bypassing fill"
                );
                return Ok(Box::new(NoopMissHandler));
            };
            header_pairs.push((name.to_string(), value.to_string()));
        }

        let expected_body_len = match crate::cache::response_content_length(&resp_headers.headers) {
            Ok(length) => length,
            Err(()) => {
                warn!(
                    key = %k_str,
                    "CACHE_MISS: invalid or conflicting Content-Length; bypassing fill"
                );
                return Ok(Box::new(NoopMissHandler));
            }
        };

        let purge_guard = acquire_cache_purge_read_guard().await;
        let write_lock = cache_write_lock_for_key(&k_str);
        let write_guard = write_lock.lock_owned().await;
        let process_roots = self.inner.load().all_roots();
        let process_lock = match acquire_cache_process_read_lock(&k_str, &process_roots).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(
                    key = %k_str,
                    error = %err,
                    "CACHE_MISS: unable to acquire cross-process cache lock; bypassing fill"
                );
                return Ok(Box::new(NoopMissHandler));
            }
        };
        let purge_generation = current_cache_purge_generation();
        let (base_path, shard_id, base_relative_path) = self.get_write_location(key);
        let hash = self.get_hash(key);
        if let Some(existing) =
            crate::metrics::storage::get_cache_meta_memory(&hash).filter(|existing| {
                existing.cache_key == k_str
                    && existing.expires >= crate::utils::time::now_timestamp()
            })
            && self
                .find_existing_path_by_hash(
                    &hash,
                    existing.root_path.as_deref(),
                    existing.relative_path.as_deref(),
                )
                .await
                .is_some()
        {
            // Another process published a fresh object while this request was
            // waiting for the shared key lock.  Do not let this older origin
            // response replace it when the miss handler eventually finishes.
            return Ok(Box::new(NoopMissHandler));
        }
        let event_version = crate::metrics::storage::next_cache_meta_event_version();
        let unique_id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let versioned_name = format!(
            "{}.body.{}.{}.{}",
            hash,
            std::process::id(),
            event_version,
            unique_id
        );
        let path = base_path.with_file_name(&versioned_name);
        let relative_path = Path::new(&base_relative_path)
            .with_file_name(&versioned_name)
            .to_string_lossy()
            .into_owned();
        if let Some(parent) = path.parent()
            && let Err(err) = tokio::fs::create_dir_all(parent).await
        {
            warn!(
                path = %parent.display(),
                error = %err,
                "CACHE_MISS: unable to create cache directory; bypassing fill"
            );
            return Ok(Box::new(NoopMissHandler));
        }

        let temp_path = path.with_extension(format!("tmp.{}.{}", std::process::id(), unique_id));

        let std_file = match tokio::fs::File::create(&temp_path).await {
            Ok(file) => file,
            Err(err) => {
                warn!(
                    path = %temp_path.display(),
                    error = %err,
                    "CACHE_MISS: unable to create cache temp file; bypassing fill"
                );
                return Ok(Box::new(NoopMissHandler));
            }
        };

        let expires = timestamp_from_system_time(meta.fresh_until());
        let created_at = timestamp_from_system_time(meta.created());

        // Keep the previous body alive until the new metadata is durable. New
        // fills use an immutable versioned path, so a failed metadata write
        // cannot leave an old manifest pointing at new bytes. The old path is
        // removed only after the replacement has committed.
        let previous_body_path = if let Some(existing) =
            crate::metrics::storage::get_cache_meta_memory(&hash)
                .filter(|existing| existing.cache_key == k_str)
        {
            self.find_existing_path_by_hash(
                &hash,
                existing.root_path.as_deref(),
                existing.relative_path.as_deref(),
            )
            .await
        } else {
            None
        };

        // Smart Compression Decision (Synchronized with HIT path via metadata)
        let content_type = resp_headers
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let content_encoding = resp_headers
            .headers
            .get("content-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let should_compress = (content_type.contains("text/")
            || content_type.contains("json")
            || content_type.contains("javascript")
            || content_type.contains("xml"))
            && content_encoding.is_empty();

        // Parse stale-while-revalidate from Cache-Control header
        let swr_secs =
            parse_stale_directive_from_headers(&resp_headers.headers, "stale-while-revalidate")
                .unwrap_or(0);
        let sie_secs = parse_stale_directive_from_headers(&resp_headers.headers, "stale-if-error")
            .unwrap_or(0);

        let head_request = cache_key_is_head_variant(&k_str);
        Ok(Box::new(FileMissHandler {
            file: Some(std_file),
            encoder: None,
            written: 0,
            final_path: path.clone(),
            temp_path,
            hash: hash.clone(),
            key_str: k_str,
            expires,
            created_at,
            status,
            headers: header_pairs,
            compressed: should_compress,
            error_status_allowed,
            shard_id,
            relative_path,
            root_path: cache_root_from_path(&path).map(|root| root.to_string_lossy().into_owned()),
            previous_body_path,
            purge_generation,
            expected_body_len,
            head_request,
            stale_while_revalidate_secs: swr_secs,
            stale_if_error_secs: sie_secs,
            event_version,
            disabled: false,
            committed: false,
            published: false,
            _purge_guard: purge_guard,
            _write_guard: write_guard,
            _process_lock: Some(process_lock),
            _cache_write_permit: cache_write_permit,
        }))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        if key.user_tag.is_empty() {
            return Ok(false);
        }

        let key_str = key.user_tag.as_ref();
        let _purge_guard = acquire_cache_purge_write_guard().await;
        advance_cache_purge_generation();
        let process_roots = self.inner.load().all_roots();
        let _process_lock = match acquire_cache_process_barrier_write_lock(&process_roots).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(
                    key = key_str,
                    error = %err,
                    "CACHE_PURGE: unable to acquire cross-process barrier; refusing purge"
                );
                return Ok(false);
            }
        };
        let write_lock = cache_write_lock_for_key(key_str);
        let _write_guard = write_lock.lock().await;
        let location = self.partial_location_for_key_str(key_str);
        crate::cache::partial::purge_locked(key_str, &location.roots).await;
        let hash = format!("{:x}", md5_legacy::compute(key_str));
        let inner = self.inner.load();
        remove_cache_file_from_roots(&inner, &hash).await;
        crate::metrics::storage::STORAGE
            .delete_cache_meta_async(&hash)
            .await;
        negative_cache_insert(key_str, crate::utils::time::now_timestamp());
        Ok(true)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            return Ok(true);
        }

        let hash = self.get_hash(key);
        let k_str = key.primary_key_str().unwrap_or("unknown").to_string();
        let _purge_guard = acquire_cache_purge_read_guard().await;
        let write_lock = cache_write_lock_for_key(&k_str);
        let _write_guard = write_lock.lock().await;
        let process_roots = self.inner.load().all_roots();
        let _process_lock = match acquire_cache_process_read_lock(&k_str, &process_roots).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(
                    key = %k_str,
                    error = %err,
                    "CACHE_UPDATE_META: unable to acquire cross-process cache lock"
                );
                return Ok(false);
            }
        };
        let Some(existing) = crate::metrics::storage::STORAGE.get_cache_meta(&hash) else {
            return Ok(false);
        };
        if existing.cache_key != k_str {
            return Ok(false);
        }
        if self
            .find_existing_path_by_hash(
                &hash,
                existing.root_path.as_deref(),
                existing.relative_path.as_deref(),
            )
            .await
            .is_none()
        {
            return Ok(false);
        }

        let resp_headers = meta.response_header();
        let status = resp_headers.status.as_u16();
        let error_status_allowed = cache_meta_allows_error_status(meta);
        if !crate::cache::status_allows_full_cache_with_error_policy(status, error_status_allowed)
            || !crate::cache::response_headers_allow_shared_cache(&resp_headers.headers)
            || !crate::cache::response_encoding_matches_cache_key(&k_str, &resp_headers.headers)
        {
            return Ok(false);
        }

        // Revalidation updates only metadata; the existing body remains on
        // disk.  Bind a new non-HEAD Content-Length to that body instead of
        // allowing a fresh header to advertise a different representation.
        // HEAD is different: its cached body is intentionally empty and its
        // Content-Length describes the selected representation, not bytes
        // carried by the HEAD response.
        let Ok(content_length) = crate::cache::response_content_length(&resp_headers.headers)
        else {
            return Ok(false);
        };
        let body_length_is_valid =
            content_length_matches_body(&k_str, content_length, existing.size);
        if !body_length_is_valid {
            warn!(
                key = %k_str,
                body_size = existing.size,
                content_length = ?content_length,
                "CACHE_UPDATE_META: new Content-Length does not match the existing cache body"
            );
            return Ok(false);
        }

        let mut header_pairs = Vec::with_capacity(resp_headers.headers.len());
        for (name, value) in resp_headers.headers.iter() {
            if !should_store_header_for_cache_key(&k_str, name.as_str()) {
                continue;
            }
            let Ok(value) = value.to_str() else {
                warn!(
                    key = %k_str,
                    header = %name,
                    "CACHE_UPDATE_META: response header is not UTF-8; keeping existing metadata"
                );
                return Ok(false);
            };
            header_pairs.push((name.to_string(), value.to_string()));
        }

        tracing::debug!(
            "CACHE_UPDATE_META: hash: {}, status: {}, compressed: {}, headers_len: {}",
            hash,
            status,
            existing.compressed,
            header_pairs.len()
        );
        let now = crate::utils::time::now_timestamp();
        // Preserve existing SWR and created_at when updating meta; re-parse SWR from new headers.
        let swr_secs =
            parse_stale_directive_from_headers(&resp_headers.headers, "stale-while-revalidate")
                .unwrap_or(existing.stale_while_revalidate_secs);
        let sie_secs = parse_stale_directive_from_headers(&resp_headers.headers, "stale-if-error")
            .unwrap_or(existing.stale_if_error_secs);
        let updated_at = now.max(existing.updated_at.saturating_add(1));
        let expires = timestamp_from_system_time(meta.fresh_until());
        let created_at = if existing.created_at > 0 {
            existing.created_at
        } else {
            timestamp_from_system_time(meta.created())
        };
        let persisted = crate::metrics::storage::STORAGE
            .upsert_cache_meta_absolute_async(crate::metrics::storage::CacheMetaUpsert {
                hash: &hash,
                cache_key: &k_str,
                size: existing.size,
                expires,
                access_time: existing.access_time,
                access_count: existing.access_count,
                status,
                headers: &header_pairs,
                compressed: existing.compressed,
                error_status_allowed,
                shard_id: existing.shard_id.as_deref(),
                relative_path: existing.relative_path.as_deref(),
                root_path: existing.root_path.as_deref(),
                event_version: Some(crate::metrics::storage::next_cache_meta_event_version()),
                updated_at: Some(updated_at),
                stale_while_revalidate_secs: swr_secs,
                stale_if_error_secs: sie_secs,
                created_at,
            })
            .await;

        if persisted {
            crate::cluster::metadata::emit_upsert(crate::cluster::metadata::CacheMetaUpsertEvent {
                hash: &hash,
                cache_key: &k_str,
                shard_id: existing.shard_id.as_deref(),
                relative_path: existing.relative_path.as_deref(),
                root_path: existing.root_path.as_deref(),
                size: existing.size,
                expires,
                status,
                headers: &header_pairs,
                compressed: existing.compressed,
                error_status_allowed,
                stale_while_revalidate_secs: swr_secs,
                stale_if_error_secs: sie_secs,
            });
        }
        Ok(persisted)
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

/// In-memory hit handler that serves from a Bytes buffer in 32KB chunks.
/// Chunked delivery is required by Pingora's HTTP framing — one-shot delivery
/// breaks keep-alive and causes connection leaks.
struct MemoryHitHandler {
    data: bytes::Bytes,
    offset: usize,
    end: usize,
    _process_lock: Option<CacheProcessLockGuard>,
    _cache_read_permit: Option<StaticAdmissionPermit>,
}

#[async_trait]
impl HandleHit for MemoryHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        if self.offset >= self.end {
            return Ok(None);
        }
        let end = (self.offset + 32768).min(self.end);
        let chunk = self.data.slice(self.offset..end);
        self.offset = end;
        Ok(Some(chunk))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if start > self.data.len() {
            return Err(Error::new(ErrorType::InternalError));
        }
        if end.is_some_and(|end| end < start) {
            return Err(Error::new(ErrorType::InternalError));
        }
        self.offset = start;
        self.end = end.unwrap_or(self.data.len()).min(self.data.len());
        Ok(())
    }
}

#[derive(Clone)]
struct CorruptCacheEntry {
    hash: String,
    key: String,
    path: PathBuf,
    size: u64,
    compressed: bool,
    event_version: Option<u64>,
    updated_at: i64,
    relative_path: Option<String>,
    root_path: Option<String>,
}

impl CorruptCacheEntry {
    fn from_meta(
        hash: &str,
        key: &str,
        path: &Path,
        meta: &crate::metrics::storage::CacheMetaEntry,
    ) -> Self {
        Self {
            hash: hash.to_string(),
            key: key.to_string(),
            path: path.to_path_buf(),
            size: meta.size,
            compressed: meta.compressed,
            event_version: meta.event_version,
            updated_at: meta.updated_at,
            relative_path: meta.relative_path.clone(),
            root_path: meta.root_path.clone(),
        }
    }

    fn owns_metadata(&self, meta: &crate::metrics::storage::CacheMetaEntry) -> bool {
        meta.cache_key == self.key
            && meta.size == self.size
            && meta.compressed == self.compressed
            && meta.event_version == self.event_version
            && meta.updated_at == self.updated_at
            && meta.relative_path.as_deref() == self.relative_path.as_deref()
            && meta.root_path.as_deref() == self.root_path.as_deref()
    }
}

/// Remove one corrupt body only while its metadata identity is still current.
/// The body path is immutable for new entries, so a newer fill cannot be
/// damaged by cleanup. Legacy bare-hash entries are also protected by the
/// metadata identity check and the key lock held by callers.
async fn discard_corrupt_cache_entry_locked(entry: CorruptCacheEntry) {
    let current = crate::metrics::storage::get_cache_meta_memory(&entry.hash);
    let owns_metadata = current
        .as_ref()
        .is_some_and(|meta| entry.owns_metadata(meta));

    let should_remove_path = if owns_metadata {
        let _ = crate::metrics::storage::STORAGE
            .delete_cache_meta_async(&entry.hash)
            .await;
        // A newer version may have won while the metadata delete was being
        // persisted. Do not remove a path that the new version still owns.
        crate::metrics::storage::get_cache_meta_memory(&entry.hash).is_none()
    } else {
        // If metadata is already absent, the body is orphaned (usually after
        // a purge) and this exact path is safe to reclaim. If another
        // metadata version is current, leave both it and its body untouched.
        current.is_none()
    };

    if should_remove_path {
        let _ = tokio::fs::remove_file(&entry.path).await;
    }
    negative_cache_insert(&entry.key, crate::utils::time::now_timestamp());
}

/// Variant used by a hit handler after it has released the cross-process read
/// lock. Acquiring the guards in the normal purge order avoids deadlocking a
/// purge that was waiting for the hit handler to finish reading.
async fn discard_corrupt_cache_entry(entry: CorruptCacheEntry) {
    let _purge_guard = acquire_cache_purge_read_guard().await;
    let write_lock = cache_write_lock_for_key(&entry.key);
    let _write_guard = write_lock.lock().await;
    discard_corrupt_cache_entry_locked(entry).await;
}

enum FileHitReader {
    Plain(tokio::fs::File),
    Compressed(async_compression::tokio::bufread::ZstdDecoder<BufReader<tokio::fs::File>>),
}

struct FileHitHandler {
    reader: FileHitReader,
    buf_size: usize,
    expected_len: u64,
    read_len: u64,
    range_end: u64,
    range_limited: bool,
    eof_verified: bool,
    seek_pending: bool,
    corruption_entry: Option<CorruptCacheEntry>,
    _process_lock: Option<CacheProcessLockGuard>,
}

impl FileHitHandler {
    async fn discard_corrupt_entry(&mut self) {
        let Some(entry) = self.corruption_entry.take() else {
            return;
        };
        // A broad purge takes the write side of the process barrier before it
        // waits for readers. Release this reader lock before acquiring the
        // async purge guard, otherwise corruption cleanup and purge can wait
        // on one another indefinitely.
        self._process_lock.take();
        discard_corrupt_cache_entry(entry).await;
    }
}

#[async_trait]
impl HandleHit for FileHitHandler {
    async fn read_body(&mut self) -> Result<Option<bytes::Bytes>> {
        if self.seek_pending {
            let seek_result = match &mut self.reader {
                FileHitReader::Plain(file) => {
                    std::future::poll_fn(|cx| std::pin::Pin::new(&mut *file).poll_complete(cx))
                        .await
                }
                FileHitReader::Compressed(_) => {
                    return Err(Error::new(ErrorType::InternalError));
                }
            };
            // Tokio completes a failed seek by returning the file to Idle;
            // do not retry the operation on a later body read, because that
            // would make the next read use an unspecified old offset.
            self.seek_pending = false;
            seek_result.map_err(|_| Error::new(ErrorType::InternalError))?;
        }
        if self.eof_verified {
            return Ok(None);
        }
        let remaining = self.range_end.saturating_sub(self.read_len);
        if remaining == 0 && self.range_limited {
            self.eof_verified = true;
            return Ok(None);
        }
        let capacity = if remaining == 0 {
            self.buf_size
        } else {
            remaining.min(self.buf_size as u64) as usize
        };
        let mut buf = bytes::BytesMut::with_capacity(capacity);
        let read_result = match &mut self.reader {
            FileHitReader::Plain(reader) => reader.read_buf(&mut buf).await,
            FileHitReader::Compressed(reader) => reader.read_buf(&mut buf).await,
        };
        let read = match read_result {
            Ok(read) => read,
            Err(_) => {
                if matches!(&self.reader, FileHitReader::Compressed(_)) {
                    self.discard_corrupt_entry().await;
                }
                return Err(Error::new(ErrorType::InternalError));
            }
        };
        if read == 0 {
            if self.read_len != self.range_end {
                self.discard_corrupt_entry().await;
                return Err(Error::new(ErrorType::InternalError));
            }
            self.eof_verified = true;
            return Ok(None);
        }
        let next_len = self
            .read_len
            .checked_add(read as u64)
            .ok_or_else(|| Error::new(ErrorType::InternalError))?;
        if next_len > self.range_end || next_len > self.expected_len {
            self.discard_corrupt_entry().await;
            return Err(Error::new(ErrorType::InternalError));
        }
        self.read_len = next_len;
        Ok(Some(buf.freeze()))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }

    fn can_seek(&self) -> bool {
        matches!(self.reader, FileHitReader::Plain(_))
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if !self.can_seek() {
            return Err(Error::new(ErrorType::InternalError));
        }
        let start = u64::try_from(start).map_err(|_| Error::new(ErrorType::InternalError))?;
        let end = end
            .map(u64::try_from)
            .transpose()
            .map_err(|_| Error::new(ErrorType::InternalError))?
            .unwrap_or(self.expected_len);
        if start > end || end > self.expected_len {
            return Err(Error::new(ErrorType::InternalError));
        }
        let FileHitReader::Plain(file) = &mut self.reader else {
            unreachable!("can_seek checked above");
        };
        std::pin::Pin::new(file)
            .start_seek(std::io::SeekFrom::Start(start))
            .map_err(|_| Error::new(ErrorType::InternalError))?;
        // `start_seek` only schedules the operation.  The first body read
        // must wait for `poll_complete` before touching the file, otherwise a
        // range response can read from the previous offset (or from an
        // implementation-defined intermediate offset).
        self.seek_pending = true;
        self.read_len = 0;
        self.range_end = end.saturating_sub(start);
        self.range_limited = true;
        self.eof_verified = false;
        Ok(())
    }
}

struct FileMissHandler {
    file: Option<tokio::fs::File>,
    encoder: Option<async_compression::tokio::write::ZstdEncoder<tokio::fs::File>>,
    written: usize,
    final_path: PathBuf,
    temp_path: PathBuf,
    hash: String,
    key_str: String,
    expires: i64,
    created_at: i64,
    status: u16,
    headers: Vec<(String, String)>,
    compressed: bool,
    error_status_allowed: bool,
    shard_id: Option<String>,
    relative_path: String,
    root_path: Option<String>,
    previous_body_path: Option<PathBuf>,
    purge_generation: u64,
    expected_body_len: Option<u64>,
    head_request: bool,
    stale_while_revalidate_secs: u64,
    stale_if_error_secs: u64,
    event_version: u64,
    disabled: bool,
    committed: bool,
    published: bool,
    _purge_guard: OwnedRwLockReadGuard<()>,
    _write_guard: OwnedMutexGuard<()>,
    _process_lock: Option<CacheProcessLockGuard>,
    _cache_write_permit: StaticAdmissionPermit,
}

impl FileMissHandler {
    fn metadata_belongs_to_this_fill(
        &self,
        meta: &crate::metrics::storage::CacheMetaEntry,
    ) -> bool {
        meta.cache_key == self.key_str
            && meta.event_version == Some(self.event_version)
            && meta.relative_path.as_deref() == Some(self.relative_path.as_str())
            && meta.root_path.as_deref() == self.root_path.as_deref()
    }

    async fn cleanup_failed_publish(&mut self) {
        let current = crate::metrics::storage::get_cache_meta_memory(&self.hash);
        let owns_metadata = current
            .as_ref()
            .is_some_and(|meta| self.metadata_belongs_to_this_fill(meta));

        if owns_metadata
            && !crate::metrics::storage::STORAGE
                .delete_cache_meta_async(&self.hash)
                .await
        {
            crate::metrics::storage::STORAGE.delete_cache_meta(&self.hash);
        }

        // Full-object body paths are immutable and unique per fill. Removing
        // this fill's path is therefore safe even when an older or newer
        // metadata record is still current; never remove a path selected by a
        // different fill.
        if self.published
            && (owns_metadata
                || current
                    .as_ref()
                    .is_none_or(|meta| !self.metadata_belongs_to_this_fill(meta)))
        {
            let _ = tokio::fs::remove_file(&self.final_path).await;
            self.published = false;
        }
    }
}

struct PartialMissHandler {
    cache_key: String,
    capture: crate::cache::partial::PartialCapture,
    writer: Option<crate::cache::partial::PartialWriter>,
    location: PartialStorageLocation,
    disabled: bool,
    purge_generation: u64,
    purge_guard: Option<OwnedRwLockReadGuard<()>>,
    write_guard: Option<OwnedMutexGuard<()>>,
    process_lock: Option<CacheProcessLockGuard>,
    _cache_write_permit: StaticAdmissionPermit,
}

struct NoopMissHandler;

/// Bounded in-memory miss handler used by the memory-only policy and by the
/// disk-pressure fallback.  It owns the same per-key write lock as file
/// admission, so a purge cannot be followed by an old fill publishing into
/// L1.
struct MemoryMissHandler {
    key: String,
    data: Vec<u8>,
    response_header: ResponseHeader,
    fresh_until: i64,
    created_at: i64,
    stale_while_revalidate_secs: u64,
    stale_if_error_secs: u64,
    error_status_allowed: bool,
    purge_generation: u64,
    l1_invalidation_generation: u64,
    metadata_required: bool,
    metadata_updated_at: i64,
    cache_state_version: u64,
    expected_body_len: Option<u64>,
    head_request: bool,
    l1: Arc<TinyUfoL1>,
    rejected: bool,
    _purge_guard: OwnedRwLockReadGuard<()>,
    write_guard: OwnedMutexGuard<()>,
    _cache_write_permit: StaticAdmissionPermit,
}

#[async_trait]
impl HandleMiss for NoopMissHandler {
    async fn write_body(&mut self, _data: bytes::Bytes, _eof: bool) -> Result<()> {
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        Ok(MissFinishType::Created(0))
    }
}

#[async_trait]
impl HandleMiss for MemoryMissHandler {
    async fn write_body(&mut self, data: bytes::Bytes, _eof: bool) -> Result<()> {
        if self.rejected || data.is_empty() {
            return Ok(());
        }
        if self.head_request {
            self.rejected = true;
            self.data.clear();
            return Ok(());
        }
        let Some(next_len) = self.data.len().checked_add(data.len()) else {
            self.rejected = true;
            self.data.clear();
            return Ok(());
        };
        if self.expected_body_len.is_some_and(|expected| {
            u64::try_from(next_len)
                .ok()
                .is_some_and(|next_len| next_len > expected)
        }) {
            self.rejected = true;
            self.data.clear();
            return Ok(());
        }
        if self.data.len().saturating_add(data.len()) > MEMORY_SERVE_MAX as usize {
            // A cache admission failure must not turn a valid origin response
            // into a 500.  Stop collecting and finish as a cache no-op.
            self.rejected = true;
            self.data.clear();
            return Ok(());
        }
        self.data.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        let MemoryMissHandler {
            key,
            data,
            response_header,
            fresh_until,
            created_at,
            stale_while_revalidate_secs,
            stale_if_error_secs,
            error_status_allowed,
            purge_generation,
            l1_invalidation_generation,
            metadata_required,
            metadata_updated_at,
            cache_state_version,
            expected_body_len,
            head_request,
            l1,
            rejected,
            _purge_guard: _,
            write_guard,
            _cache_write_permit: _,
        } = *self;
        let _write_guard = write_guard;
        let now = crate::utils::time::now_timestamp();
        let body_length_is_valid = if head_request {
            data.is_empty()
        } else {
            expected_body_len
                .is_none_or(|expected| u64::try_from(data.len()).ok() == Some(expected))
        };
        let metadata_is_current = crate::metrics::storage::get_cache_meta_memory(&format!(
            "{:x}",
            md5_legacy::compute(key.as_bytes())
        ))
        .map(|current| {
            current.cache_key == key
                && current.expires == fresh_until
                && current.updated_at == metadata_updated_at
        })
        .unwrap_or(!metadata_required);
        if rejected
            || !body_length_is_valid
            || !metadata_is_current
            || fresh_until <= now
            || purge_generation != current_cache_purge_generation()
            || l1_invalidation_generation != current_cache_l1_invalidation_generation()
        {
            return Ok(MissFinishType::Created(0));
        }

        let ttl = (fresh_until - now) as u64;
        let size = data.len();
        l1.put(
            &key,
            TinyUfoL1Entry {
                cache_key: key.clone(),
                data: bytes::Bytes::from(data),
                response_header,
                fresh_until,
                created_at,
                stale_while_revalidate_secs,
                stale_if_error_secs,
                error_status_allowed,
                metadata_updated_at,
                cache_state_version,
                purge_generation,
                metadata_required,
            },
            std::time::Duration::from_secs(ttl),
        );
        bloom_insert(&key);
        negative_cache_remove(&key);
        Ok(MissFinishType::Created(size))
    }
}

#[async_trait]
impl HandleMiss for PartialMissHandler {
    async fn write_body(&mut self, data: bytes::Bytes, _eof: bool) -> Result<()> {
        if self.disabled || data.is_empty() {
            return Ok(());
        }
        if self.purge_generation != current_cache_purge_generation() {
            self.disabled = true;
            return Ok(());
        }
        if self.writer.is_none() {
            let Some(purge_guard) = self.purge_guard.take() else {
                self.disabled = true;
                return Ok(());
            };
            let Some(write_guard) = self.write_guard.take() else {
                self.disabled = true;
                drop(purge_guard);
                return Ok(());
            };
            let process_lock = self.process_lock.take();
            self.writer = match crate::cache::partial::open_writer_with_guards(
                &self.cache_key,
                self.capture.clone(),
                self.location.write_root.clone(),
                Some(self.purge_generation),
                purge_guard,
                write_guard,
                process_lock,
            )
            .await
            {
                Ok(writer) => writer,
                Err(_) => {
                    self.disabled = true;
                    return Ok(());
                }
            };
            if self.writer.is_none() {
                self.disabled = true;
                return Ok(());
            }
        }
        if let Some(writer) = &mut self.writer {
            match writer.write(&data).await {
                Ok(true) => {}
                Ok(false) | Err(_) => {
                    self.disabled = true;
                    self.writer.take();
                }
            }
        }
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        let PartialMissHandler {
            cache_key: _,
            capture,
            writer,
            location,
            disabled,
            purge_generation: _,
            purge_guard: _,
            write_guard: _,
            process_lock: _,
            _cache_write_permit: _,
        } = *self;
        if disabled {
            return Ok(MissFinishType::Created(0));
        }
        let Some(writer) = writer else {
            return Ok(MissFinishType::Created(0));
        };
        let written = capture
            .end
            .checked_sub(capture.start)
            .and_then(|length| length.checked_add(1))
            .unwrap_or(0);
        match writer
            .finish(&location.roots, location.write_root.clone())
            .await
        {
            Ok(true) => Ok(MissFinishType::Created(written as usize)),
            Ok(false) | Err(_) => Ok(MissFinishType::Created(0)),
        }
    }
}

#[async_trait]
impl HandleMiss for FileMissHandler {
    async fn write_body(&mut self, data: bytes::Bytes, _eof: bool) -> Result<()> {
        if self.disabled {
            return Ok(());
        }
        if self.head_request && !data.is_empty() {
            // HEAD responses carry the representation length in the header
            // but must not publish a body. Receiving bytes means the origin
            // exchange is not a valid HEAD response for this cache entry.
            self.disabled = true;
            return Ok(());
        }
        if data.is_empty() {
            return Ok(());
        }
        let Some(next_written) = self.written.checked_add(data.len()) else {
            self.disabled = true;
            return Ok(());
        };
        let Some(next_written_u64) = u64::try_from(next_written).ok() else {
            self.disabled = true;
            return Ok(());
        };
        if self
            .expected_body_len
            .is_some_and(|expected| next_written_u64 > expected)
        {
            self.disabled = true;
            return Ok(());
        }

        // Initialize encoder only if policy says so
        if self.compressed
            && self.encoder.is_none()
            && let Some(f) = self.file.take()
        {
            let enc = async_compression::tokio::write::ZstdEncoder::new(f);
            self.encoder = Some(enc);
        }

        let write_result = if let Some(enc) = &mut self.encoder {
            tokio::io::AsyncWriteExt::write_all(enc, &data).await
        } else if let Some(f) = &mut self.file {
            tokio::io::AsyncWriteExt::write_all(f, &data).await
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "cache miss file is unavailable",
            ))
        };
        if let Err(err) = write_result {
            // Cache I/O is best effort. A full disk or a transient filesystem
            // failure must not convert the origin response into a 5xx.
            tracing::warn!(
                key = %self.key_str,
                error = %err,
                "CACHE_MISS: cache write failed; disabling this fill"
            );
            self.disabled = true;
            self.encoder.take();
            self.file.take();
            return Ok(());
        }

        self.written = next_written;
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<MissFinishType> {
        if self.disabled || self.purge_generation != current_cache_purge_generation() {
            return Ok(MissFinishType::Created(0));
        }
        let written = self.written;
        let written_u64 = u64::try_from(written).unwrap_or(u64::MAX);
        let body_length_is_valid = if self.head_request {
            written == 0
        } else {
            self.expected_body_len
                .is_none_or(|expected| expected == written_u64)
        };
        if !body_length_is_valid {
            tracing::warn!(
                key = %self.key_str,
                expected = ?self.expected_body_len,
                actual = written_u64,
                "CACHE_MISS: response body length does not match Content-Length; discarding fill"
            );
            self.disabled = true;
            return Ok(MissFinishType::Created(0));
        }

        if self.compressed && self.encoder.is_none() {
            // A zero-byte text response still needs a valid Zstd frame.  An
            // empty file marked as compressed is unreadable on the next hit.
            if let Some(file) = self.file.take() {
                self.encoder = Some(async_compression::tokio::write::ZstdEncoder::new(file));
            }
        }

        if let Some(mut enc) = self.encoder.take() {
            if let Err(err) = tokio::io::AsyncWriteExt::shutdown(&mut enc).await {
                tracing::warn!(
                    key = %self.key_str,
                    error = %err,
                    "CACHE_MISS: cache compression finalization failed; bypassing fill"
                );
                self.disabled = true;
                return Ok(MissFinishType::Created(0));
            }
        } else if let Some(mut f) = self.file.take()
            && let Err(err) = tokio::io::AsyncWriteExt::flush(&mut f).await
        {
            tracing::warn!(
                key = %self.key_str,
                error = %err,
                "CACHE_MISS: cache flush failed; bypassing fill"
            );
            self.disabled = true;
            return Ok(MissFinishType::Created(0));
        }

        if tokio::fs::rename(&self.temp_path, &self.final_path)
            .await
            .is_err()
        {
            tracing::warn!(
                key = %self.key_str,
                path = %self.final_path.display(),
                "CACHE_MISS: cache publish failed; bypassing fill"
            );
            return Ok(MissFinishType::Created(0));
        }
        self.published = true;

        if self.purge_generation != current_cache_purge_generation() {
            self.cleanup_failed_publish().await;
            return Ok(MissFinishType::Created(0));
        }

        let now = crate::utils::time::now_timestamp();
        let updated_at = crate::metrics::storage::get_cache_meta_memory(&self.hash)
            .map(|existing| now.max(existing.updated_at.saturating_add(1)))
            .unwrap_or(now);
        let persisted = crate::metrics::storage::STORAGE
            .upsert_cache_meta_absolute_async(crate::metrics::storage::CacheMetaUpsert {
                hash: &self.hash,
                cache_key: &self.key_str,
                size: written as u64,
                expires: self.expires,
                access_time: now,
                access_count: 1,
                status: self.status,
                headers: &self.headers,
                compressed: self.compressed,
                error_status_allowed: self.error_status_allowed,
                shard_id: self.shard_id.as_deref(),
                relative_path: Some(&self.relative_path),
                root_path: self.root_path.as_deref(),
                event_version: Some(self.event_version),
                updated_at: Some(updated_at),
                stale_while_revalidate_secs: self.stale_while_revalidate_secs,
                stale_if_error_secs: self.stale_if_error_secs,
                created_at: self.created_at,
            })
            .await;
        if !persisted {
            tracing::warn!(
                key = %self.key_str,
                "CACHE_MISS: cache metadata publish failed; discarding fill"
            );
            self.cleanup_failed_publish().await;
            return Ok(MissFinishType::Created(0));
        }
        if let Some(previous_body_path) = self.previous_body_path.take()
            && previous_body_path != self.final_path
        {
            // The key lock is still held. It is now safe to reclaim the old
            // immutable body; readers that already opened it keep their file
            // descriptor, while new readers use the metadata's new path.
            let _ = tokio::fs::remove_file(previous_body_path).await;
        }
        index_surrogate_keys(&self.headers, &self.hash);
        crate::cluster::metadata::emit_upsert(crate::cluster::metadata::CacheMetaUpsertEvent {
            hash: &self.hash,
            cache_key: &self.key_str,
            shard_id: self.shard_id.as_deref(),
            relative_path: Some(&self.relative_path),
            root_path: self.root_path.as_deref(),
            size: written as u64,
            expires: self.expires,
            status: self.status,
            headers: &self.headers,
            compressed: self.compressed,
            error_status_allowed: self.error_status_allowed,
            stale_while_revalidate_secs: self.stale_while_revalidate_secs,
            stale_if_error_secs: self.stale_if_error_secs,
        });

        self.committed = true;
        Ok(MissFinishType::Created(written))
    }
}

impl Drop for FileMissHandler {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        drop(self.encoder.take());
        drop(self.file.take());
        let temp_path = self.temp_path.clone();
        let final_path = self.published.then(|| self.final_path.clone());
        let hash = self.hash.clone();
        let key_str = self.key_str.clone();
        let event_version = self.event_version;
        let relative_path = self.relative_path.clone();
        let root_path = self.root_path.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = tokio::fs::remove_file(temp_path).await;
                if let Some(final_path) = final_path {
                    // Wait until the handler's write guard has been dropped,
                    // then re-check under the same key lock. A newer fill
                    // may have taken over the final path in the meantime.
                    let write_lock = cache_write_lock_for_key(&key_str);
                    let _write_guard = write_lock.lock().await;
                    let current = crate::metrics::storage::get_cache_meta_memory(&hash);
                    let owns_metadata = current.as_ref().is_some_and(|meta| {
                        meta.cache_key == key_str
                            && meta.event_version == Some(event_version)
                            && meta.relative_path.as_deref() == Some(relative_path.as_str())
                            && meta.root_path.as_deref() == root_path.as_deref()
                    });
                    if owns_metadata {
                        let _ = crate::metrics::storage::STORAGE
                            .delete_cache_meta_async(&hash)
                            .await;
                    }
                    // The body path is unique to this fill, so an older or
                    // newer metadata record cannot refer to this file unless
                    // `owns_metadata` was true above.
                    let _ = tokio::fs::remove_file(final_path).await;
                }
            });
        } else {
            let _ = std::fs::remove_file(temp_path);
            if let Some(final_path) = final_path {
                let current = crate::metrics::storage::get_cache_meta_memory(&hash);
                let owns_metadata = current.as_ref().is_some_and(|meta| {
                    meta.cache_key == key_str
                        && meta.event_version == Some(event_version)
                        && meta.relative_path.as_deref() == Some(relative_path.as_str())
                        && meta.root_path.as_deref() == root_path.as_deref()
                });
                if owns_metadata {
                    crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
                }
                let _ = std::fs::remove_file(final_path);
            }
        }
    }
}

/// Reverse index: Surrogate-Key tag → set of cache-entry hashes.
/// Capacity is bounded by the number of in-memory cache entries at the time
/// a new tag is inserted; entries for evicted keys are pruned on purge.
static SURROGATE_KEY_INDEX: Lazy<DashMap<String, dashmap::DashSet<String>>> =
    Lazy::new(DashMap::new);
static SURROGATE_SATURATED_TAGS: Lazy<DashMap<String, ()>> = Lazy::new(DashMap::new);
static SURROGATE_MEMBERSHIPS: AtomicU64 = AtomicU64::new(0);
static SURROGATE_DEGRADED_PURGE: AtomicU64 = AtomicU64::new(0);
const SURROGATE_INDEX_MAX_TAGS_NORMAL: usize = 1_000_000;
const SURROGATE_INDEX_MAX_TAGS_PRESSURE: usize = 131_072;
const SURROGATE_INDEX_MAX_MEMBERSHIPS: usize = 4_000_000;
const SURROGATE_INDEX_MAX_MEMBERS_PER_TAG: usize = 16_384;
const SURROGATE_TAG_MAX_BYTES: usize = 256;
const SURROGATE_TAG_ENTRY_OVERHEAD: u64 = 96;

fn surrogate_index_capacity() -> usize {
    if MEMORY_GOVERNOR.is_memory_pressure_high() {
        SURROGATE_INDEX_MAX_TAGS_PRESSURE
    } else {
        SURROGATE_INDEX_MAX_TAGS_NORMAL
    }
}

pub(crate) fn index_surrogate_keys(headers: &[(String, String)], hash: &str) {
    let tags = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("surrogate-key"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    for tag in tags.split_whitespace().take(64) {
        if tag.is_empty() || tag.len() > SURROGATE_TAG_MAX_BYTES {
            continue;
        }
        if SURROGATE_SATURATED_TAGS.contains_key(tag) {
            continue;
        }
        if !SURROGATE_KEY_INDEX.contains_key(tag)
            && SURROGATE_KEY_INDEX.len() >= surrogate_index_capacity()
        {
            mark_surrogate_tag_saturated(tag);
            continue;
        }
        let entry = SURROGATE_KEY_INDEX.entry(tag.to_string()).or_default();
        if entry.len() >= SURROGATE_INDEX_MAX_MEMBERS_PER_TAG
            || SURROGATE_MEMBERSHIPS.load(Ordering::Relaxed) as usize
                >= SURROGATE_INDEX_MAX_MEMBERSHIPS
        {
            mark_surrogate_tag_saturated(tag);
            continue;
        }
        if entry.insert(hash.to_string()) {
            SURROGATE_MEMBERSHIPS.fetch_add(1, Ordering::Relaxed);
            let owner = format!("{tag}\0{hash}");
            let bytes = SURROGATE_TAG_ENTRY_OVERHEAD + tag.len() as u64 + hash.len() as u64;
            let _ = MEMORY_GOVERNOR.resident_memory_replace_owned(
                crate::memory_governor::ResidentCategory::SurrogateIndex,
                &owner,
                bytes,
            );
        }
    }
}

fn mark_surrogate_tag_saturated(tag: &str) {
    SURROGATE_SATURATED_TAGS.insert(tag.to_string(), ());
}

pub(crate) fn remove_hash_from_surrogate_index(hash: &str) {
    SURROGATE_KEY_INDEX.retain(|tag, set| {
        if set.remove(hash).is_some() {
            SURROGATE_MEMBERSHIPS
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                })
                .ok();
            let owner = format!("{tag}\0{hash}");
            let _ = MEMORY_GOVERNOR.resident_memory_replace_owned(
                crate::memory_governor::ResidentCategory::SurrogateIndex,
                &owner,
                0,
            );
        }
        !set.is_empty()
    });
}

pub(crate) fn meta_headers_contain_surrogate_tag(headers: &[(String, String)], tag: &str) -> bool {
    surrogate_headers_contain_tag(headers, tag)
}

fn surrogate_headers_contain_tag(headers: &[(String, String)], tag: &str) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("surrogate-key")
            && value.split_whitespace().any(|candidate| candidate == tag)
    })
}

// ═══════════════════════════════════════════════════════════
// TinyUfoL1: Production-grade lock-free L1 cache (TinyUFO)
// ═══════════════════════════════════════════════════════════

use bloom::{ASMS, BloomFilter};
use pingora_memory_cache::{CacheStatus, MemoryCache, MemoryCacheStats};

/// Entry stored in TinyUfoL1 (wrapper around MemoryCache<TinyUfo>)
#[derive(Clone)]
pub(crate) struct TinyUfoL1Entry {
    cache_key: String,
    data: bytes::Bytes,
    response_header: ResponseHeader,
    fresh_until: i64,
    created_at: i64,
    stale_while_revalidate_secs: u64,
    stale_if_error_secs: u64,
    error_status_allowed: bool,
    metadata_updated_at: i64,
    /// Monotonic cache-state token used even when the entry has no CMETA row.
    /// Exact and broad purge fences are compared with this token on every
    /// file-policy L1 lookup, which closes the shared-volume invalidation gap.
    cache_state_version: u64,
    purge_generation: u64,
    metadata_required: bool,
}

/// Lock-free L1 cache backed by TinyUFO (S3-FIFO + TinyLFU admission).
/// Replaces the old FAST_L1 (DashMap + BinaryHeap).
pub(crate) struct TinyUfoL1 {
    inner: StdRwLock<Arc<MemoryCache<String, TinyUfoL1Entry>>>,
    // MemoryCache intentionally has no iterator. Keep a bounded best-effort
    // key index so prefix/tag purge can also invalidate memory-only entries.
    // Stale index members are pruned whenever the index grows past twice the
    // configured item capacity.
    keys: DashSet<String>,
    auto_budget: AtomicBool,
    max_bytes: AtomicU64,
    current_weight: AtomicU64,
}

impl TinyUfoL1 {
    fn new(max_bytes: u64) -> Self {
        let auto_budget = max_bytes == 0;
        let resolved_max_bytes = if auto_budget {
            HybridStorage::compute_memory_budget()
        } else {
            max_bytes
        };
        let cache = Arc::new(Self::build_cache(resolved_max_bytes));
        Self {
            inner: StdRwLock::new(cache),
            keys: DashSet::new(),
            auto_budget: AtomicBool::new(auto_budget),
            max_bytes: AtomicU64::new(resolved_max_bytes),
            current_weight: AtomicU64::new(0),
        }
    }

    fn build_cache(max_bytes: u64) -> MemoryCache<String, TinyUfoL1Entry> {
        let capacity = Self::weight_limit_for_bytes(max_bytes);
        MemoryCache::new(capacity)
    }

    fn weight_limit_for_bytes(max_bytes: u64) -> usize {
        (max_bytes / 1024).max(1).min(usize::MAX as u64) as usize
    }

    fn read_inner(&self) -> Arc<MemoryCache<String, TinyUfoL1Entry>> {
        self.inner.read().expect("TinyUfoL1 lock poisoned").clone()
    }

    fn get(&self, key: &str) -> Option<TinyUfoL1Entry> {
        let inner = self.read_inner();
        let (value, status) = inner.get(key);
        if status == CacheStatus::Hit {
            value.filter(|entry| entry.cache_key == key)
        } else {
            None
        }
    }

    fn get_stale(&self, key: &str) -> Option<(TinyUfoL1Entry, CacheStatus)> {
        let inner = self.read_inner();
        let (value, status) = inner.get_stale(key);
        value
            .filter(|entry| entry.cache_key == key)
            .map(|v| (v, status))
    }

    fn put(&self, key: &str, entry: TinyUfoL1Entry, ttl: std::time::Duration) {
        let stale_window = entry
            .stale_while_revalidate_secs
            .max(entry.stale_if_error_secs);
        let retention = ttl.saturating_add(std::time::Duration::from_secs(stale_window));
        let weight = (entry.data.len().div_ceil(1024)).clamp(1, u16::MAX as usize) as u16;
        let inner = self.read_inner();
        inner.put(key, entry, Some(retention), weight);
        if !retention.is_zero() {
            self.keys.insert(key.to_string());
            self.prune_key_index_if_needed();
        }
        self.refresh_stats(&inner);
    }

    fn remove(&self, key: &str) {
        let inner = self.read_inner();
        inner.remove(key);
        self.keys.remove(key);
        self.refresh_stats(&inner);
    }

    fn prune_key_index_if_needed(&self) {
        let limit = Self::weight_limit_for_bytes(self.max_bytes())
            .saturating_mul(2)
            .max(4_096);
        if self.keys.len() <= limit {
            return;
        }
        let candidates: Vec<String> = self.keys.iter().map(|key| key.clone()).collect();
        for key in candidates {
            if self.get_stale(&key).is_none() {
                self.keys.remove(&key);
            }
        }
    }

    fn keys_matching_prefix(&self, prefix: &str) -> Vec<String> {
        let candidates: Vec<String> = self.keys.iter().map(|key| key.clone()).collect();
        candidates
            .into_iter()
            .filter(|key| key.starts_with(prefix))
            .filter_map(|key| {
                if self.get_stale(&key).is_some() {
                    Some(key)
                } else {
                    self.keys.remove(&key);
                    None
                }
            })
            .collect()
    }

    fn keys_matching_family(&self, base_key: &str) -> Vec<String> {
        let variant_prefix = format!("{}@", base_key);
        let candidates: Vec<String> = self.keys.iter().map(|key| key.clone()).collect();
        candidates
            .into_iter()
            .filter(|key| key == base_key || key.starts_with(&variant_prefix))
            .filter_map(|key| {
                if self.get_stale(&key).is_some() {
                    Some(key)
                } else {
                    self.keys.remove(&key);
                    None
                }
            })
            .collect()
    }

    fn keys_with_surrogate_tag(&self, tag: &str) -> Vec<String> {
        let candidates: Vec<String> = self.keys.iter().map(|key| key.clone()).collect();
        candidates
            .into_iter()
            .filter_map(|key| {
                let Some((entry, _status)) = self.get_stale(&key) else {
                    self.keys.remove(&key);
                    return None;
                };
                let matches = entry
                    .response_header
                    .headers
                    .get_all("surrogate-key")
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .any(|value| value.split_whitespace().any(|candidate| candidate == tag));
                matches.then_some(key)
            })
            .collect()
    }

    fn set_max_bytes(&self, bytes: u64) {
        let auto_budget = bytes == 0;
        self.auto_budget.store(auto_budget, Ordering::Relaxed);
        let resolved = if auto_budget {
            crate::memory_governor::MEMORY_GOVERNOR.cache_budget_bytes()
        } else {
            bytes
        };
        let old = self.max_bytes.swap(resolved, Ordering::Relaxed);
        if !Self::should_rebuild_for_budget_change(old, resolved) {
            return;
        }
        let new_cache = Arc::new(Self::build_cache(resolved));
        self.current_weight.store(0, Ordering::Relaxed);
        let mut guard = self.inner.write().expect("TinyUfoL1 lock poisoned");
        *guard = new_cache;
        self.keys.clear();
    }

    fn refresh_auto_budget(&self) {
        if !self.auto_budget.load(Ordering::Relaxed) {
            return;
        }
        self.set_max_bytes(0);
    }

    fn force_rebuild_with_limit(&self, bytes: u64) {
        let resolved = bytes.max(1024);
        self.max_bytes.store(resolved, Ordering::Relaxed);
        let new_cache = Arc::new(Self::build_cache(resolved));
        self.current_weight.store(0, Ordering::Relaxed);
        let mut guard = self.inner.write().expect("TinyUfoL1 lock poisoned");
        *guard = new_cache;
        self.keys.clear();
    }

    fn force_clear(&self) {
        let limit = self.max_bytes.load(Ordering::Relaxed).max(1024);
        self.force_rebuild_with_limit(limit);
    }

    fn stats(&self) -> (usize, u64) {
        let inner = self.read_inner();
        self.refresh_stats(&inner);
        let stats = inner.stats();
        let bytes = (stats.current_weight as u64).saturating_mul(1024);
        let count = stats.current_items;
        (count, bytes)
    }

    fn max_bytes(&self) -> u64 {
        self.max_bytes.load(Ordering::Relaxed)
    }

    fn refresh_stats(&self, inner: &MemoryCache<String, TinyUfoL1Entry>) {
        let MemoryCacheStats { current_weight, .. } = inner.stats();
        self.current_weight.store(
            current_weight.min(u64::MAX as usize) as u64,
            Ordering::Relaxed,
        );
    }

    fn should_rebuild_for_budget_change(old: u64, new: u64) -> bool {
        if Self::weight_limit_for_bytes(old) == Self::weight_limit_for_bytes(new) {
            return false;
        }
        let delta = old.abs_diff(new);
        if new < old && MEMORY_GOVERNOR.is_memory_pressure_high() {
            return true;
        }
        let (min_delta_bytes, min_delta_pct) = if new < old {
            (
                L1_RESIZE_SHRINK_MIN_DELTA_BYTES,
                L1_RESIZE_SHRINK_MIN_DELTA_PCT,
            )
        } else {
            (L1_RESIZE_GROW_MIN_DELTA_BYTES, L1_RESIZE_GROW_MIN_DELTA_PCT)
        };
        delta >= min_delta_bytes && delta.saturating_mul(100) >= old.max(1) * min_delta_pct
    }
}

// ═══════════════════════════════════════════════════════════
// Bloom Filter + Negative Cache (Anti-Penetration)
// ═══════════════════════════════════════════════════════════

/// Adaptive bloom filter with auto-scaling for billion-scale caches.
/// Uses sharded layered BloomFilters so the filter can grow without a full rebuild
/// while keeping read/write contention bounded.
/// `current_size` is an approximate admission volume, not an exact distinct-key count.
struct AdaptiveBloomFilter {
    shards: Vec<BloomShard>,
    total_capacity: AtomicU64,
    current_size: AtomicU64,
    estimated_bytes: AtomicU64,
}

struct BloomShard {
    layers: parking_lot::RwLock<Vec<BloomLayer>>,
}

struct BloomLayer {
    filter: BloomFilter,
    capacity: u64,
    count: u64,
}

impl BloomShard {
    fn new(initial_capacity: u32) -> Self {
        Self {
            layers: parking_lot::RwLock::new(vec![AdaptiveBloomFilter::build_layer(
                initial_capacity,
            )]),
        }
    }
}

impl AdaptiveBloomFilter {
    fn new(initial_capacity: u32, shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        let per_shard_capacity = ((initial_capacity as usize).div_ceil(shard_count)) as u32;
        let shards = (0..shard_count)
            .map(|_| BloomShard::new(per_shard_capacity.max(1)))
            .collect::<Vec<_>>();

        Self {
            shards,
            total_capacity: AtomicU64::new(per_shard_capacity as u64 * shard_count as u64),
            current_size: AtomicU64::new(0),
            estimated_bytes: AtomicU64::new(
                Self::estimated_layer_bytes(per_shard_capacity as u64)
                    .saturating_mul(shard_count as u64),
            ),
        }
    }

    fn build_layer(expected_items: u32) -> BloomLayer {
        let capacity = expected_items.max(1);
        BloomLayer {
            filter: BloomFilter::with_rate(0.01, capacity),
            capacity: capacity as u64,
            count: 0,
        }
    }

    fn next_layer_capacity(&self, current: u64) -> u32 {
        let next = current.saturating_mul(2).max(1);
        next.min(u32::MAX as u64) as u32
    }

    fn estimated_layer_bytes(capacity: u64) -> u64 {
        capacity
            .saturating_mul(BLOOM_BITS_PER_ENTRY_ESTIMATE)
            .div_ceil(8)
            .saturating_add(BLOOM_LAYER_OVERHEAD_BYTES)
    }

    fn can_add_layer(&self, capacity: u64, remaining_budget: u64) -> bool {
        self.estimated_bytes
            .load(Ordering::Relaxed)
            .saturating_add(Self::estimated_layer_bytes(capacity))
            <= remaining_budget
    }

    fn shard_index(&self, key: &str) -> usize {
        use std::hash::{Hash, Hasher};
        let mut hasher = ahash::AHasher::default();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }

    fn contains(&self, key: &str) -> bool {
        let idx = self.shard_index(key);
        let layers = self.shards[idx].layers.read();
        layers.iter().any(|layer| layer.filter.contains(&key))
    }

    fn insert(&self, key: &str) {
        let idx = self.shard_index(key);
        let mut layers = self.shards[idx].layers.write();
        let mut next_capacity = None;
        if let Some(layer) = layers.last_mut() {
            let _ = layer.filter.insert(&key);
            layer.count = layer.count.saturating_add(1);
            self.current_size.fetch_add(1, Ordering::Relaxed);
            if layer.count >= layer.capacity {
                let candidate = self.next_layer_capacity(layer.capacity);
                if self.can_add_layer(
                    candidate as u64,
                    crate::memory_governor::MEMORY_GOVERNOR.bloom_budget_bytes(),
                ) {
                    next_capacity = Some(candidate);
                }
            }
        }
        if let Some(next_capacity) = next_capacity {
            layers.push(Self::build_layer(next_capacity));
            self.total_capacity
                .fetch_add(next_capacity as u64, Ordering::Relaxed);
            self.estimated_bytes.fetch_add(
                Self::estimated_layer_bytes(next_capacity as u64),
                Ordering::Relaxed,
            );
        }
    }

    fn utilization(&self) -> f64 {
        let size = self.current_size.load(Ordering::Relaxed) as f64;
        let capacity = self.total_capacity.load(Ordering::Relaxed) as f64;
        if capacity > 0.0 { size / capacity } else { 0.0 }
    }

    fn stats(&self) -> (u64, u64, f64, u64) {
        let size = self.current_size.load(Ordering::Relaxed);
        let capacity = self.total_capacity.load(Ordering::Relaxed);
        let util = self.utilization();
        let estimated_bytes = self.estimated_bytes.load(Ordering::Relaxed);
        (size, capacity, util, estimated_bytes)
    }

    fn shrink_layers(&self, keep_layers_per_shard: usize) -> u64 {
        let keep = keep_layers_per_shard.max(1);
        let mut removed_layers = 0u64;
        let mut freed_bytes = 0u64;
        for shard in &self.shards {
            let mut layers = shard.layers.write();
            while layers.len() > keep {
                if let Some(removed) = layers.first() {
                    freed_bytes =
                        freed_bytes.saturating_add(Self::estimated_layer_bytes(removed.capacity));
                }
                layers.remove(0);
                removed_layers = removed_layers.saturating_add(1);
            }
        }
        if freed_bytes > 0 {
            self.estimated_bytes
                .fetch_sub(freed_bytes, Ordering::Relaxed);
        }
        removed_layers
    }

    fn reset_to_minimal(&self) {
        let per_shard = (1_000_000usize / self.shards.len().max(1)).max(1) as u32;
        let mut total_capacity = 0u64;
        let mut total_bytes = 0u64;
        for shard in &self.shards {
            let layer = Self::build_layer(per_shard);
            total_capacity = total_capacity.saturating_add(layer.capacity);
            total_bytes = total_bytes.saturating_add(Self::estimated_layer_bytes(layer.capacity));
            *shard.layers.write() = vec![layer];
        }
        self.total_capacity.store(total_capacity, Ordering::Relaxed);
        self.current_size.store(0, Ordering::Relaxed);
        self.estimated_bytes.store(total_bytes, Ordering::Relaxed);
    }
}

/// Dual-generation Bloom: inserts go to the live generation; contains also
/// checks a retiring generation until it is dropped after rotation.
struct DualGenerationBloom {
    live: ArcSwap<AdaptiveBloomFilter>,
    stale: parking_lot::Mutex<Option<Arc<AdaptiveBloomFilter>>>,
    generation: AtomicU64,
    charge_initialized: AtomicBool,
}

impl DualGenerationBloom {
    fn new(initial_capacity: u32, shard_count: usize) -> Self {
        let live = AdaptiveBloomFilter::new(initial_capacity, shard_count);
        // Do not charge resident memory while the global CACHE_BLOOM lazy
        // value is being initialized. Accounting observes memory pressure and
        // may synchronously reclaim caches; reclaiming CACHE_BLOOM from its
        // own constructor would recursively wait on this LazyLock forever.
        // The charge is synchronized after construction by insert/rotation
        // paths, once the LazyLock is fully published.
        Self {
            live: ArcSwap::from_pointee(live),
            stale: parking_lot::Mutex::new(None),
            generation: AtomicU64::new(1),
            charge_initialized: AtomicBool::new(false),
        }
    }

    fn contains(&self, key: &str) -> bool {
        if self.live.load().contains(key) {
            return true;
        }
        self.stale
            .lock()
            .as_ref()
            .is_some_and(|stale| stale.contains(key))
    }

    fn insert(&self, key: &str) {
        let live = self.live.load();
        let before = live.estimated_bytes.load(Ordering::Relaxed);
        live.insert(key);
        if live.estimated_bytes.load(Ordering::Relaxed) != before
            || !self.charge_initialized.load(Ordering::Relaxed)
        {
            self.sync_bloom_charge();
        }
    }

    fn stats(&self) -> (u64, u64, f64, u64, u64) {
        let live = self.live.load();
        let (size, capacity, util, estimated_bytes) = live.stats();
        let stale_bytes = self
            .stale
            .lock()
            .as_ref()
            .map(|stale| stale.estimated_bytes.load(Ordering::Relaxed))
            .unwrap_or(0);
        (
            size,
            capacity,
            util,
            estimated_bytes.saturating_add(stale_bytes),
            self.generation.load(Ordering::Relaxed),
        )
    }

    fn sync_bloom_charge(&self) {
        let (_, _, _, estimated, _) = self.stats();
        let charged = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
            crate::memory_governor::ResidentCategory::BloomFilter,
            "cache-bloom",
            estimated,
        );
        if charged {
            self.charge_initialized.store(true, Ordering::Relaxed);
        }
    }

    fn rotate_from_cache_meta(&self) {
        let Some(_permit) = crate::memory_governor::MEMORY_GOVERNOR
            .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork)
        else {
            return;
        };
        let replacement = AdaptiveBloomFilter::new(1_000_000, 64);
        let now = crate::utils::time::now_timestamp();
        crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
            if meta.expires > now {
                replacement.insert(&meta.cache_key);
            }
        });
        let previous = self.live.swap(Arc::new(replacement));
        {
            let mut stale = self.stale.lock();
            *stale = Some(previous);
        }
        self.generation.fetch_add(1, Ordering::Relaxed);
        self.sync_bloom_charge();
    }

    fn drop_stale(&self) {
        *self.stale.lock() = None;
        self.sync_bloom_charge();
    }

    fn shrink_layers(&self, keep_layers_per_shard: usize) -> u64 {
        let live = self.live.load();
        let removed = live.shrink_layers(keep_layers_per_shard);
        if let Some(stale) = self.stale.lock().as_ref() {
            let _ = stale.shrink_layers(keep_layers_per_shard);
        }
        self.sync_bloom_charge();
        removed
    }

    fn reset_to_minimal(&self) {
        let live = self.live.load();
        live.reset_to_minimal();
        *self.stale.lock() = None;
        self.sync_bloom_charge();
    }
}

static CACHE_BLOOM: Lazy<DualGenerationBloom> =
    Lazy::new(|| DualGenerationBloom::new(1_000_000, 64));

fn bloom_may_exist(key: &str) -> bool {
    CACHE_BLOOM.contains(key)
}

fn bloom_insert(key: &str) {
    CACHE_BLOOM.insert(key);
}

fn bloom_remove(key: &str) {
    let _ = key;
}

fn bloom_stats() -> (u64, u64, f64, u64) {
    let (size, capacity, util, estimated, _) = CACHE_BLOOM.stats();
    (size, capacity, util, estimated)
}

fn bloom_generation() -> u64 {
    CACHE_BLOOM.generation.load(Ordering::Relaxed)
}

fn warm_bloom_from_cache_meta() {
    let Some(_permit) = crate::memory_governor::MEMORY_GOVERNOR
        .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork)
    else {
        tracing::warn!("CACHE_BLOOM: skipping warmup because background memory admission is full");
        return;
    };
    let now = crate::utils::time::now_timestamp();
    crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
        if meta.expires >= now {
            CACHE_BLOOM.insert(&meta.cache_key);
        }
    });
}

/// Negative cache: tracks keys confirmed to not exist in the local cache set.
/// This mainly absorbs stale Bloom positives after purge/expiry.
static NEGATIVE_CACHE: Lazy<DashMap<String, i64>> = Lazy::new(DashMap::new);
const NEGATIVE_CACHE_TTL_SECS: i64 = 60;
const NEGATIVE_CACHE_MIN_ENTRIES: usize = 1_000_000;
const NEGATIVE_CACHE_MAX_ENTRIES: usize = 16_000_000;

fn negative_cache_capacity_limit() -> usize {
    let (bloom_count, _, _, _) = bloom_stats();
    let adaptive = (bloom_count / 64).max(NEGATIVE_CACHE_MIN_ENTRIES as u64);
    let governor_limit = crate::memory_governor::MEMORY_GOVERNOR.negative_cache_limit() as u64;
    adaptive
        .min(NEGATIVE_CACHE_MAX_ENTRIES as u64)
        .max(NEGATIVE_CACHE_MIN_ENTRIES as u64)
        .min(governor_limit)
        .max(1) as usize
}

fn negative_cache_check(key: &str, now: i64) -> bool {
    if let Some(entry) = NEGATIVE_CACHE.get(key)
        && *entry > now
    {
        return true;
    }
    NEGATIVE_CACHE.remove(key);
    let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
        crate::memory_governor::ResidentCategory::NegativeCache,
        key,
        0,
    );
    false
}

fn negative_cache_insert(key: &str, now: i64) {
    negative_cache_insert_with_capacity(key, now, negative_cache_capacity_limit());
}

fn negative_cache_insert_with_capacity(key: &str, now: i64, capacity: usize) {
    if crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high() {
        return;
    }
    let capacity = capacity.max(1);
    let current_len = NEGATIVE_CACHE.len();
    if current_len >= capacity {
        negative_cache_cleanup(now);
        if NEGATIVE_CACHE.len() >= capacity {
            return;
        }
    }
    NEGATIVE_CACHE.insert(key.to_string(), now + NEGATIVE_CACHE_TTL_SECS);
    let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
        crate::memory_governor::ResidentCategory::NegativeCache,
        key,
        160 + key.len() as u64,
    );
}

fn negative_cache_remove(key: &str) {
    NEGATIVE_CACHE.remove(key);
    let _ = crate::memory_governor::MEMORY_GOVERNOR.resident_memory_replace_owned(
        crate::memory_governor::ResidentCategory::NegativeCache,
        key,
        0,
    );
}

fn negative_cache_stats() -> (usize, usize) {
    (NEGATIVE_CACHE.len(), negative_cache_capacity_limit())
}

fn negative_cache_cleanup(now: i64) {
    NEGATIVE_CACHE.retain(|_, &mut expires| expires > now);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheReclaimStats {
    pub l1_entries_removed: usize,
    pub l1_bytes_freed_estimate: u64,
    pub bloom_layers_removed: u64,
    pub negative_cache_entries_removed: usize,
}

fn reclaim_l1_from_storage(storage: &HybridStorage, shrink_to_bytes: Option<u64>) -> (usize, u64) {
    let (count_before, bytes_before) = storage.l1.stats();
    match shrink_to_bytes {
        Some(bytes) => storage.l1.force_rebuild_with_limit(bytes),
        None => storage.l1.force_clear(),
    }
    let (count_after, bytes_after) = storage.l1.stats();
    (
        count_before.saturating_sub(count_after),
        bytes_before.saturating_sub(bytes_after),
    )
}

pub fn reclaim_caches_elevated() -> CacheReclaimStats {
    if CACHE_RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.replace(true)) {
        return CacheReclaimStats::default();
    }
    let now = crate::utils::time::now_timestamp();
    let before = NEGATIVE_CACHE.len();
    negative_cache_cleanup(now);
    let stats = CacheReclaimStats {
        negative_cache_entries_removed: before.saturating_sub(NEGATIVE_CACHE.len()),
        ..Default::default()
    };
    CACHE_RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.set(false));
    stats
}

pub fn reclaim_caches_high() -> CacheReclaimStats {
    if CACHE_RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.replace(true)) {
        return CacheReclaimStats::default();
    }
    let target = MEMORY_GOVERNOR
        .cache_budget_bytes()
        .saturating_div(2)
        .max(8 * 1024 * 1024);
    let (l1_removed, l1_freed) =
        reclaim_l1_from_storage(crate::cache_manager::CACHE.storage, Some(target));
    let before = NEGATIVE_CACHE.len();
    NEGATIVE_CACHE.clear();
    let stats = CacheReclaimStats {
        l1_entries_removed: l1_removed,
        l1_bytes_freed_estimate: l1_freed,
        bloom_layers_removed: CACHE_BLOOM.shrink_layers(1),
        negative_cache_entries_removed: before,
    };
    CACHE_RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.set(false));
    stats
}

pub fn reclaim_caches_critical() -> CacheReclaimStats {
    if CACHE_RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.replace(true)) {
        return CacheReclaimStats::default();
    }
    let (l1_removed, l1_freed) = reclaim_l1_from_storage(crate::cache_manager::CACHE.storage, None);
    let before = NEGATIVE_CACHE.len();
    NEGATIVE_CACHE.clear();
    CACHE_BLOOM.reset_to_minimal();
    let stats = CacheReclaimStats {
        l1_entries_removed: l1_removed,
        l1_bytes_freed_estimate: l1_freed,
        bloom_layers_removed: 0,
        negative_cache_entries_removed: before,
    };
    CACHE_RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.set(false));
    stats
}

pub(crate) fn warm_admission_filters_from_cache_meta() {
    warm_bloom_from_cache_meta();
    let (size, capacity, util, estimated_bytes) = bloom_stats();
    tracing::info!(
        "CACHE_BLOOM: warmed size={} capacity={} utilization={:.3} estimated_bytes={} generation={}",
        size,
        capacity,
        util,
        estimated_bytes,
        bloom_generation()
    );
}

pub(crate) fn start_bloom_rotation_task() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15 * 60)).await;
            let (_, _, util, estimated, _) = CACHE_BLOOM.stats();
            let budget = crate::memory_governor::MEMORY_GOVERNOR.bloom_budget_bytes();
            if util > 0.6 || estimated.saturating_mul(2) > budget.max(1) {
                if let Err(err) =
                    tokio::task::spawn_blocking(|| CACHE_BLOOM.rotate_from_cache_meta()).await
                {
                    warn!(error = %err, "CACHE_BLOOM: rotation task failed");
                    continue;
                }
                tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                CACHE_BLOOM.drop_stale();
            }
        }
    });
}

pub(crate) fn invalidate_l1_key(cache_key: &str) {
    if !cache_key.is_empty() {
        CACHE_L1_INVALIDATION_GENERATION.fetch_add(1, Ordering::AcqRel);
        crate::cache_manager::CACHE.storage.l1.remove(cache_key);
    }
}

pub(crate) fn on_cache_meta_upsert(meta: &crate::metrics::storage::CacheMetaEntry) {
    // Metadata can be updated by a remote cluster event or by a disk fill
    // while a fallback memory entry is still resident. Remove that entry
    // eagerly; metadata_required=false intentionally permits a metadata-less
    // L1 entry, so relying only on a later metadata comparison can replay old
    // bytes when timestamps happen to share a second.
    invalidate_l1_key(&meta.cache_key);
    if meta.expires > crate::utils::time::now_timestamp() {
        bloom_insert(&meta.cache_key);
    }
    negative_cache_remove(&meta.cache_key);
}

pub(crate) fn on_cache_meta_delete(cache_key: &str) {
    invalidate_l1_key(cache_key);
    negative_cache_insert(cache_key, crate::utils::time::now_timestamp());
}

const POLICY_FILE: u8 = 0;
const POLICY_MEMORY: u8 = 1;

pub struct HybridStorage {
    pub(crate) l1: Arc<TinyUfoL1>,
    pub l2: &'static FileStorage,
    pub max_disk_bytes: std::sync::atomic::AtomicU64,
    pub min_free_bytes: std::sync::atomic::AtomicU64,
    pub policy_type: AtomicU8,
}

pub struct CacheRuntimeStats {
    pub policy_type: String,
    pub memory_count: usize,
    pub memory_bytes: u64,
    pub disk_count: usize,
    pub disk_bytes: u64,
    pub max_disk_bytes: u64,
    pub min_free_bytes: u64,
    pub bloom_count: u64,
    pub bloom_capacity: u64,
    pub bloom_utilization: f64,
    pub bloom_estimated_bytes: u64,
    pub bloom_budget_bytes: u64,
    pub negative_cache_count: usize,
    pub negative_cache_capacity: usize,
    pub memory_budget_bytes: u64,
    pub memory_pressure_high: bool,
    pub file_cache_enabled: bool,
    pub sendfile_enabled: bool,
    pub disk_hit_chunk_bytes: usize,
}

impl HybridStorage {
    pub fn new(_max_mem_bytes: usize, disk_root: impl Into<PathBuf>) -> Self {
        let l1_budget = if _max_mem_bytes == 0 {
            0
        } else {
            _max_mem_bytes.min(u64::MAX as usize) as u64
        };
        let l1 = TinyUfoL1::new(l1_budget);

        Self {
            l1: Arc::new(l1),
            l2: Box::leak(Box::new(FileStorage::new(disk_root))),
            max_disk_bytes: std::sync::atomic::AtomicU64::new(10 * 1024 * 1024 * 1024),
            min_free_bytes: std::sync::atomic::AtomicU64::new(2 * 1024 * 1024 * 1024),
            policy_type: AtomicU8::new(POLICY_FILE),
        }
    }

    pub fn partial_location_for_key_str(&self, key: &str) -> PartialStorageLocation {
        self.l2.partial_location_for_key_str(key)
    }

    /// A sharded cache layout is intended for a shared cluster volume.  A
    /// memory-only fallback without a CMETA row cannot observe a purge that
    /// happened in another process, so it must not be admitted there.
    fn memory_fallback_requires_metadata(&self) -> bool {
        crate::runtime_mode::RuntimeConfig::current_is_rke2()
            || matches!(
                &self.l2.inner.load().layout,
                FileStorageLayout::Sharded { .. }
            )
    }

    fn compute_memory_budget() -> u64 {
        crate::memory_governor::MEMORY_GOVERNOR.cache_budget_bytes()
    }

    async fn memory_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        metadata_required: bool,
    ) -> Result<MissHandler> {
        let key_str = key.primary_key_str().unwrap_or("unknown").to_string();
        let response_header = meta.response_header();
        let error_status_allowed = cache_meta_allows_error_status(meta);
        if !crate::cache::status_allows_full_cache_with_error_policy(
            response_header.status.as_u16(),
            error_status_allowed,
        ) || !crate::cache::response_headers_allow_shared_cache(&response_header.headers)
            || !crate::cache::response_encoding_matches_cache_key(
                &key_str,
                &response_header.headers,
            )
        {
            return Ok(Box::new(NoopMissHandler));
        }
        let expected_body_len =
            match crate::cache::response_content_length(&response_header.headers) {
                Ok(length) => length,
                Err(()) => return Ok(Box::new(NoopMissHandler)),
            };
        if expected_body_len.is_some_and(|length| length > MEMORY_SERVE_MAX) {
            return Ok(Box::new(NoopMissHandler));
        }

        let Some(cache_write_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::CacheWrite) else {
            return Ok(Box::new(NoopMissHandler));
        };
        let hash = format!("{:x}", md5_legacy::compute(key_str.as_bytes()));
        if metadata_required && crate::metrics::storage::get_cache_meta_memory(&hash).is_none() {
            // In a shared/sharded layout, a metadata-less L1 object has no
            // cross-process invalidation channel.  Do not retain a fallback
            // that could survive a remote purge indefinitely.
            return Ok(Box::new(NoopMissHandler));
        }
        let purge_guard = acquire_cache_purge_read_guard().await;
        let write_lock = cache_write_lock_for_key(&key_str);
        let write_guard = write_lock.lock_owned().await;
        // A preceding miss may have completed while this request waited for
        // the key lock. Re-check both layers after acquiring it; otherwise
        // this older origin response can overwrite the first fill in L1.
        // Capture the invalidation token before the check so an invalidation
        // racing this decision makes this fill a no-op at finish time.
        let l1_invalidation_generation = current_cache_l1_invalidation_generation();
        let policy_type = self.policy_type.load(Ordering::Acquire);
        let now = crate::utils::time::now_timestamp();
        if let Some((entry, _status)) = self.l1.get_stale(&key_str) {
            if self.l1_entry_is_current(&key_str, &entry, policy_type, now) {
                return Ok(Box::new(NoopMissHandler));
            }
            // The key lock is still held, so no concurrent fill can replace
            // this invalid entry between validation and removal.
            self.l1.remove(&key_str);
        }

        let current_meta = crate::metrics::storage::get_cache_meta_memory(&hash);
        let metadata_updated_at = if metadata_required {
            let Some(current_meta) = current_meta.as_ref() else {
                // The metadata that justified the shared-volume fallback was
                // purged while this miss waited. A metadata-less L1 entry
                // would be unable to observe that purge after restart.
                return Ok(Box::new(NoopMissHandler));
            };
            if current_meta.cache_key != key_str {
                return Ok(Box::new(NoopMissHandler));
            }
            current_meta.updated_at
        } else {
            // A metadata-less fallback is allowed, but when a row happens to
            // exist it still provides a useful freshness identity for this
            // L1 entry. This prevents an older fill from winning over a
            // concurrent metadata refresh without making metadata mandatory.
            current_meta
                .filter(|current_meta| current_meta.cache_key == key_str)
                .map(|current_meta| current_meta.updated_at)
                .unwrap_or(0)
        };
        let cache_state_version = new_cache_l1_state_version(&hash);
        let capacity = expected_body_len
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(MEMORY_SERVE_MAX as usize);
        let head_request = cache_key_is_head_variant(&key_str);
        Ok(Box::new(MemoryMissHandler {
            key: key_str,
            data: Vec::with_capacity(capacity),
            response_header: response_header.clone(),
            fresh_until: timestamp_from_system_time(meta.fresh_until()),
            created_at: timestamp_from_system_time(meta.created()),
            stale_while_revalidate_secs: meta.stale_while_revalidate_sec() as u64,
            stale_if_error_secs: meta.stale_if_error_sec() as u64,
            error_status_allowed,
            purge_generation: current_cache_purge_generation(),
            l1_invalidation_generation,
            metadata_required,
            metadata_updated_at,
            cache_state_version,
            expected_body_len,
            head_request,
            l1: self.l1.clone(),
            rejected: false,
            _purge_guard: purge_guard,
            write_guard,
            _cache_write_permit: cache_write_permit,
        }))
    }

    #[doc(hidden)]
    pub fn bench_fast_l1_insert(
        key: &str,
        body: bytes::Bytes,
        meta: &CacheMeta,
        ttl_secs: u64,
    ) -> bool {
        let now = crate::utils::time::now_timestamp();
        let entry = TinyUfoL1Entry {
            cache_key: key.to_string(),
            data: body,
            response_header: meta.response_header().clone(),
            fresh_until: now + ttl_secs as i64,
            created_at: now,
            stale_while_revalidate_secs: meta.stale_while_revalidate_sec() as u64,
            stale_if_error_secs: meta.stale_if_error_sec() as u64,
            error_status_allowed: cache_meta_allows_error_status(meta),
            metadata_updated_at: now,
            cache_state_version: new_cache_l1_state_version(&format!(
                "{:x}",
                md5_legacy::compute(key.as_bytes())
            )),
            purge_generation: current_cache_purge_generation(),
            metadata_required: false,
        };
        crate::cache_manager::CACHE.storage.l1.put(
            key,
            entry,
            std::time::Duration::from_secs(ttl_secs.max(1)),
        );
        true
    }

    #[doc(hidden)]
    pub fn bench_fast_l1_remove(key: &str) {
        crate::cache_manager::CACHE.storage.l1.remove(key);
    }

    #[doc(hidden)]
    pub fn bench_compute_memory_budget() -> u64 {
        Self::compute_memory_budget()
    }

    pub fn apply_cluster_cache_config(
        &self,
        config: &crate::runtime_mode::ClusterCacheConfig,
    ) -> anyhow::Result<()> {
        if !config.shared_max_bytes.trim().is_empty() {
            let bytes = parse_runtime_size_bytes(&config.shared_max_bytes)?;
            if bytes > 0 {
                self.max_disk_bytes.store(bytes, Ordering::Relaxed);
            }
        }

        if !config.min_free_bytes.trim().is_empty() {
            let bytes = parse_runtime_size_bytes(&config.min_free_bytes)?;
            self.min_free_bytes.store(bytes, Ordering::Relaxed);
        }

        self.l1.set_max_bytes(config.max_fast_l1_bytes);

        let shards = config
            .shards
            .iter()
            .map(|shard| CacheShard {
                id: shard.id.clone(),
                root: shard.path.clone(),
                weight: shard.weight,
            })
            .collect();
        self.l2.update_shards(shards, Vec::new(), true, false);

        info!(
            "RPC_CACHE: Applied local RKE2 cache config: shards={}, sharedMaxBytes={}, minFreeBytes={}, maxFastL1Bytes={}",
            config.shards.len(),
            config.shared_max_bytes,
            config.min_free_bytes,
            config.max_fast_l1_bytes
        );
        Ok(())
    }

    pub async fn apply_policy(&self, policy: &crate::config_models::HTTPCachePolicy) {
        if crate::runtime_mode::RuntimeConfig::current_is_rke2() {
            self.policy_type.store(POLICY_FILE, Ordering::Relaxed);
            if !CLUSTER_STORAGE_POLICY_SKIP_LOGGED.swap(true, Ordering::Relaxed) {
                info!(
                    "RPC_CACHE: RKE2 runtime mode ignores control-plane cache storage path/capacity settings; local runtime cache config is authoritative."
                );
            }
            return;
        }

        let val = if policy.r#type == "memory" {
            POLICY_MEMORY
        } else {
            POLICY_FILE
        };
        self.policy_type.store(val, Ordering::Relaxed);

        if let Some(capacity) = &policy.capacity {
            let bytes = crate::config_models::SizeCapacity::from_json(capacity).to_bytes();
            if bytes > 0 {
                self.max_disk_bytes
                    .store(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }

        if let Some(options) = &policy.options {
            // Memory capacity for L1: 0 = auto-detect, explicit value = use directly
            if let Some(mem) = options
                .get("memoryCapacity")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
            {
                self.l1.set_max_bytes(mem);
            }

            let min_free_setting = if let Some(min_free) = options.get("minFreeSpace") {
                crate::config_models::SizeCapacity::from_json(min_free).to_bytes()
            } else {
                0
            };

            let mut final_min_free = min_free_setting as u64;
            if final_min_free == 0 {
                let main_path = options
                    .get("dir")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| crate::paths::NodePaths::current().cache_dir());

                let disks = sysinfo::Disks::new_with_refreshed_list();
                let disk_size = disks
                    .iter()
                    .find(|d| main_path.starts_with(d.mount_point()))
                    .map(|d| d.total_space())
                    .unwrap_or(100 * 1024 * 1024 * 1024);

                let auto_min = (disk_size / 20).clamp(1024 * 1024 * 1024, 10 * 1024 * 1024 * 1024);

                info!(
                    "RPC_CACHE: Using auto-calculated min free space: {} bytes",
                    auto_min
                );
                final_min_free = auto_min;
            } else {
                info!(
                    "RPC_CACHE: Using policy specified min free space: {} bytes",
                    final_min_free
                );
            }
            self.min_free_bytes
                .store(final_min_free, std::sync::atomic::Ordering::Relaxed);

            let main_dir = options
                .get("dir")
                .and_then(|v| v.as_str())
                .map(PathBuf::from);
            let sub_dirs = options
                .get("subDirs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(PathBuf::from)
                        .collect::<Vec<_>>()
                });

            let enable_sendfile = options
                .get("enableSendfile")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let enable_file_cache = options
                .get("openFileCache")
                .and_then(|v| v.get("isOn"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false); // Default to false for 10M+ files safety unless explicitly ON.

            if let Some(main) = main_dir {
                info!(
                    "RPC_CACHE: Updating cache configuration (Sendfile: {}, HandleCache: {})",
                    enable_sendfile, enable_file_cache
                );
                self.l2.update_config(
                    main,
                    sub_dirs.unwrap_or_default(),
                    enable_sendfile,
                    enable_file_cache,
                );
            }
        }
    }

    fn cache_key_variants(key: &str) -> Vec<String> {
        let mut variants = Vec::with_capacity(28);
        variants.push(key.to_string());

        let suffixes = [
            "@br",
            "@gzip",
            "@webp",
            "@webp@br",
            "@webp@gzip",
            "@method:HEAD",
            "@method:HEAD@br",
            "@method:HEAD@gzip",
            "@method:HEAD@webp",
            "@method:HEAD@webp@br",
            "@method:HEAD@webp@gzip",
        ];
        if !suffixes.iter().any(|suffix| key.ends_with(suffix)) {
            variants.extend(suffixes.iter().map(|suffix| format!("{key}{suffix}")));
        }

        // Current HEAD keys use a digest-bound method marker. Keep the legacy
        // suffixes above for cleanup, but never use them as semantic HEAD
        // indicators because a user-defined cache key can contain the same
        // text.
        let mut webp = key.to_string();
        crate::cache::append_cache_webp_variant(&mut webp);
        let mut head = key.to_string();
        crate::cache::append_cache_method_variant(&mut head, "HEAD");
        let mut head_webp = head.clone();
        crate::cache::append_cache_webp_variant(&mut head_webp);
        let mut current_bases = vec![key.to_string(), webp, head.clone(), head_webp];
        variants.extend(current_bases.iter().cloned());

        // Current compressed keys use a marker bound to the unencoded key.
        // Keep the old suffixes above for cleanup of entries written by older
        // versions, but do not infer the current representation from them.
        // Include both the new method-marker bases and the old method suffix
        // bases: an older entry may have the current compression marker even
        // though its method component was written before method binding was
        // introduced.
        current_bases.extend(
            ["@webp", "@method:HEAD", "@method:HEAD@webp"]
                .iter()
                .map(|suffix| format!("{key}{suffix}")),
        );
        current_bases.sort_unstable();
        current_bases.dedup();
        for base in current_bases {
            let mut variant = base.clone();
            crate::cache::append_cache_encoding_variant(&mut variant, "br");
            variants.push(variant);

            let mut variant = base;
            crate::cache::append_cache_encoding_variant(&mut variant, "gzip");
            variants.push(variant);
        }

        variants
    }

    async fn purge_exact_stored_key_locked(
        &self,
        key: &str,
        requested_version: Option<u64>,
    ) -> bool {
        let location = self.l2.partial_location_for_key_str(key);
        crate::cache::partial::purge_locked(key, &location.roots).await;
        let hash = format!("{:x}", md5_legacy::compute(key));
        let inner = self.l2.inner.load();
        remove_cache_file_from_roots(&inner, &hash).await;
        let version = requested_version
            .filter(|version| *version > 0)
            .unwrap_or_else(crate::metrics::storage::next_cache_meta_event_version);
        crate::metrics::storage::observe_cache_meta_event_version(version);
        let metadata_deleted = crate::metrics::storage::STORAGE
            .delete_cache_meta_async_at_version(&hash, version)
            .await;
        remove_hash_from_surrogate_index(&hash);
        self.l1.remove(key);
        bloom_remove(key);
        negative_cache_insert(key, crate::utils::time::now_timestamp());

        metadata_deleted
    }

    async fn purge_exact_stored_key_at_version(
        &'static self,
        key: &str,
        requested_version: Option<u64>,
    ) -> bool {
        let write_lock = cache_write_lock_for_key(key);
        let _write_guard = write_lock.lock().await;
        self.purge_exact_stored_key_locked(key, requested_version)
            .await
    }

    pub async fn purge_by_key(&'static self, key: &str) -> bool {
        self.purge_by_key_at_version(key, None).await
    }

    pub(crate) async fn purge_by_key_at_version(
        &'static self,
        key: &str,
        requested_version: Option<u64>,
    ) -> bool {
        // Exact key purges also need a write barrier.  Otherwise a fill for a
        // variant that was not visible during enumeration can acquire its
        // key lock after this function has deleted the known variants and
        // publish the pre-purge response again.
        let _purge_guard = acquire_cache_purge_write_guard().await;
        advance_cache_purge_generation();
        let process_roots = self.l2.inner.load().all_roots();
        let _process_lock = match acquire_cache_process_barrier_write_lock(&process_roots).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(
                    key,
                    error = %err,
                    "RPC_CACHE: unable to acquire cross-process purge barrier"
                );
                return false;
            }
        };
        let mut variants = Self::cache_key_variants(key);
        let variant_prefix = format!("{}@", key);
        variants.extend(self.l1.keys_matching_family(key));
        crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
            if meta.cache_key == key || meta.cache_key.starts_with(&variant_prefix) {
                variants.push(meta.cache_key.clone());
            }
        });
        variants.sort_unstable();
        variants.dedup();

        let deleted_count = variants.len();
        let mut purge_succeeded = true;
        for variant in variants {
            purge_succeeded &= self
                .purge_exact_stored_key_at_version(&variant, requested_version)
                .await;
        }
        info!(
            "RPC_CACHE: Purged {} variants for key: {}",
            deleted_count, key
        );
        purge_succeeded
    }

    pub async fn purge_by_tag(&'static self, tag: &str) -> bool {
        self.purge_by_tag_at_version(tag, None).await
    }

    pub(crate) async fn purge_by_tag_at_version(
        &'static self,
        tag: &str,
        requested_version: Option<u64>,
    ) -> bool {
        let _purge_guard = acquire_cache_purge_write_guard().await;
        advance_cache_purge_generation();
        let process_roots = self.l2.inner.load().all_roots();
        let _process_lock = match acquire_cache_process_barrier_write_lock(&process_roots).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(
                    tag,
                    error = %err,
                    "RPC_CACHE: unable to acquire cross-process purge barrier"
                );
                return false;
            }
        };
        let purge_version = requested_version
            .filter(|version| *version > 0)
            .unwrap_or_else(crate::metrics::storage::next_cache_meta_event_version);
        let fence_persisted = crate::metrics::storage::STORAGE
            .record_cache_meta_broad_purge(purge_version)
            .await;
        let location = self.l2.partial_location_for_key_str(tag);
        let partial_deleted = crate::cache::partial::purge_by_tag(tag, &location.roots).await;
        let hashes: Vec<String> = SURROGATE_KEY_INDEX
            .get(tag)
            .map(|set| {
                set.iter()
                    .take(SURROGATE_INDEX_MAX_MEMBERS_PER_TAG)
                    .map(|h| h.clone())
                    .collect()
            })
            .unwrap_or_default();
        let mut keys_to_purge = Vec::new();
        keys_to_purge.extend(self.l1.keys_with_surrogate_tag(tag));
        for hash in &hashes {
            if let Some(meta) = crate::metrics::storage::get_cache_meta_memory(hash)
                && crate::cache_hybrid::meta_headers_contain_surrogate_tag(&meta.headers, tag)
            {
                keys_to_purge.push(meta.cache_key.clone());
            }
        }
        // The reverse index is deliberately bounded and may be incomplete;
        // it is an accelerator, never the source of truth.  Always merge a
        // complete metadata scan so an entry that missed indexing (or still
        // appears in a stale index membership) cannot survive tag purge.
        let scanned =
            crate::metrics::storage::STORAGE.collect_cache_keys_by_surrogate_tag(tag, usize::MAX);
        let saturated = SURROGATE_SATURATED_TAGS.contains_key(tag);
        if saturated || !scanned.is_empty() {
            SURROGATE_DEGRADED_PURGE.fetch_add(1, Ordering::Relaxed);
            warn!(
                tag,
                scanned = scanned.len(),
                indexed = hashes.len(),
                saturated,
                "RPC_CACHE: surrogate index is bounded; merged complete metadata scan"
            );
        }
        keys_to_purge.extend(scanned);
        keys_to_purge.sort_unstable();
        keys_to_purge.dedup();
        if keys_to_purge.is_empty() {
            if partial_deleted > 0 {
                info!(
                    "RPC_CACHE: Purged {} partial entries by surrogate tag: {}",
                    partial_deleted, tag
                );
            }
            SURROGATE_KEY_INDEX.remove(tag);
            SURROGATE_SATURATED_TAGS.remove(tag);
            return fence_persisted;
        }
        let deleted_count = keys_to_purge.len();
        let mut exact_purges_succeeded = true;
        for key in keys_to_purge {
            exact_purges_succeeded &= self
                .purge_exact_stored_key_at_version(&key, Some(purge_version))
                .await;
        }
        SURROGATE_KEY_INDEX.remove(tag);
        SURROGATE_SATURATED_TAGS.remove(tag);
        info!(
            "RPC_CACHE: Purged {} entries and {} partial entries by surrogate tag: {}",
            deleted_count, partial_deleted, tag
        );
        fence_persisted && exact_purges_succeeded
    }

    pub async fn purge_by_prefix(&'static self, prefix: &str) -> bool {
        self.purge_by_prefix_at_version(prefix, None).await
    }

    pub(crate) async fn purge_by_prefix_at_version(
        &'static self,
        prefix: &str,
        requested_version: Option<u64>,
    ) -> bool {
        let clean_prefix = prefix.trim_end_matches('*');
        if Self::is_dangerous_purge_prefix(clean_prefix) {
            tracing::warn!(
                "RPC_CACHE: Refusing dangerous prefix purge request: {:?}",
                prefix
            );
            return false;
        }
        let _purge_guard = acquire_cache_purge_write_guard().await;
        advance_cache_purge_generation();
        let process_roots = self.l2.inner.load().all_roots();
        let _process_lock = match acquire_cache_process_barrier_write_lock(&process_roots).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(
                    prefix,
                    error = %err,
                    "RPC_CACHE: unable to acquire cross-process purge barrier"
                );
                return false;
            }
        };
        let purge_version = requested_version
            .filter(|version| *version > 0)
            .unwrap_or_else(crate::metrics::storage::next_cache_meta_event_version);
        let fence_persisted = crate::metrics::storage::STORAGE
            .record_cache_meta_broad_purge(purge_version)
            .await;
        let location = self.l2.partial_location_for_key_str(clean_prefix);
        let partial_deleted =
            crate::cache::partial::purge_prefix(clean_prefix, &location.roots).await;
        let mut to_delete = Vec::new();
        to_delete.extend(self.l1.keys_matching_prefix(clean_prefix));

        crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
            if !meta.cache_key.is_empty() && meta.cache_key.starts_with(clean_prefix) {
                to_delete.push(meta.cache_key.clone());
            }
        });

        let deleted_count = to_delete.len();
        let mut exact_purges_succeeded = true;
        for key in to_delete {
            exact_purges_succeeded &= self
                .purge_exact_stored_key_at_version(&key, Some(purge_version))
                .await;
        }
        info!(
            "RPC_CACHE: Purged {} items and {} partial items matching prefix: {}",
            deleted_count, partial_deleted, prefix
        );
        fence_persisted && exact_purges_succeeded
    }

    fn is_dangerous_purge_prefix(prefix: &str) -> bool {
        let normalized = prefix.trim().trim_end_matches('*').trim();
        if normalized.is_empty()
            || normalized == "/"
            || normalized.eq_ignore_ascii_case("http://")
            || normalized.eq_ignore_ascii_case("https://")
        {
            return true;
        }

        let lower = normalized.to_ascii_lowercase();
        if let Some(after_scheme) = lower
            .strip_prefix("http://")
            .or_else(|| lower.strip_prefix("https://"))
        {
            return after_scheme.find('/').is_none_or(|index| index == 0);
        }

        false
    }

    pub async fn runtime_stats(&self) -> CacheRuntimeStats {
        let (memory_count, memory_bytes) = self.l1.stats();
        let (disk_count, disk_bytes) = crate::metrics::storage::STORAGE.cache_summary();
        let (bloom_count, bloom_capacity, bloom_utilization, bloom_estimated_bytes) = bloom_stats();
        let (negative_cache_count, negative_cache_capacity) = negative_cache_stats();
        CacheRuntimeStats {
            policy_type: if self.policy_type.load(Ordering::Relaxed) == POLICY_MEMORY {
                "memory".to_string()
            } else {
                "file".to_string()
            },
            memory_count,
            memory_bytes,
            disk_count,
            disk_bytes,
            max_disk_bytes: self
                .max_disk_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            min_free_bytes: self
                .min_free_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            bloom_count,
            bloom_capacity,
            bloom_utilization,
            bloom_estimated_bytes,
            bloom_budget_bytes: crate::memory_governor::MEMORY_GOVERNOR.bloom_budget_bytes(),
            negative_cache_count,
            negative_cache_capacity,
            memory_budget_bytes: self.l1.max_bytes(),
            memory_pressure_high: crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high(),
            file_cache_enabled: self.l2.enable_file_cache(),
            sendfile_enabled: self.l2.enable_sendfile(),
            disk_hit_chunk_bytes: self.l2.disk_hit_chunk_bytes(),
        }
    }

    fn l1_entry_is_current(
        &self,
        key: &str,
        entry: &TinyUfoL1Entry,
        policy_type: u8,
        now: i64,
    ) -> bool {
        let stale_window = entry
            .stale_while_revalidate_secs
            .max(entry.stale_if_error_secs);
        let stale_age = u64::try_from(now.saturating_sub(entry.fresh_until)).unwrap_or(0);
        if entry.cache_key != key
            || !crate::cache::status_allows_full_cache_with_error_policy(
                entry.response_header.status.as_u16(),
                entry.error_status_allowed,
            )
            || entry.purge_generation != current_cache_purge_generation()
            || (entry.fresh_until < now && stale_age > stale_window)
            || !crate::cache::response_headers_allow_shared_cache(&entry.response_header.headers)
            || !crate::cache::response_encoding_matches_cache_key(
                key,
                &entry.response_header.headers,
            )
        {
            return false;
        }
        let body_length_is_valid =
            match crate::cache::response_content_length(&entry.response_header.headers) {
                Ok(_content_length) if cache_key_is_head_variant(key) => entry.data.is_empty(),
                Ok(content_length) => content_length
                    .is_none_or(|length| u64::try_from(entry.data.len()).ok() == Some(length)),
                Err(()) => false,
            };
        if !body_length_is_valid {
            return false;
        }
        if policy_type == POLICY_MEMORY {
            return true;
        }

        let hash = format!("{:x}", md5_legacy::compute(key.as_bytes()));
        let state_version = entry.cache_state_version;
        let broad_purge_version = crate::metrics::storage::cache_meta_broad_purge_version();
        if broad_purge_version > 0 && (state_version == 0 || state_version <= broad_purge_version) {
            return false;
        }
        if crate::metrics::storage::cache_meta_tombstone_version(&hash).is_some_and(
            |tombstone_version| state_version == 0 || state_version <= tombstone_version,
        ) {
            return false;
        }
        let metadata = crate::metrics::storage::get_cache_meta_memory(&hash);
        if !entry.metadata_required {
            return metadata.is_none_or(|meta| {
                meta.cache_key == key
                    && meta.expires == entry.fresh_until
                    && meta.updated_at == entry.metadata_updated_at
            });
        }
        metadata.is_some_and(|meta| {
            meta.cache_key == key
                && meta.expires == entry.fresh_until
                && meta.updated_at == entry.metadata_updated_at
        })
    }
}

#[async_trait]
impl Storage for HybridStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let p_type = self.policy_type.load(Ordering::Relaxed);

        let k_str = key.primary_key_str().unwrap_or("unknown");
        let is_partial_key = crate::cache::partial::is_partial_cache_key(k_str);

        if is_partial_key {
            if p_type == POLICY_MEMORY {
                return Ok(None);
            }
            return self.l2.lookup(key, trace).await;
        }

        let now = crate::utils::time::now_timestamp();

        // Bloom is advisory only. A Bloom filter may return false after a
        // layer shrink/reset even when the durable metadata and body are
        // still present; using it as a hard gate would turn a false negative
        // into a cache miss until the object is rewritten. Keep the metric,
        // but always continue to the authoritative negative-cache/metadata
        // lookup path.
        if !bloom_may_exist(k_str) {
            prof_record_bloom_reject();
        }

        // Anti-penetration Layer 2: short-lived local absence cache for stale Bloom positives
        if negative_cache_check(k_str, now) {
            return Ok(None);
        }

        {
            // L1 validation and the Bytes clone must use the same ordering as
            // broad purge: purge read barrier, then canonical key lock. This
            // closes the window where purge advances the generation after the
            // validation but before the old body is returned.
            let _purge_guard = acquire_cache_purge_read_guard().await;
            let write_lock = cache_write_lock_for_key(k_str);
            let _write_guard = write_lock.lock().await;
            // File-policy L1 entries may be backed by a shared cache volume
            // whose purge is performed by another process.  Keep the same
            // cross-process read lock as the L2 hit path until the returned
            // body handler is dropped; otherwise a remote purge can finish
            // between L1 validation and body delivery while this process has
            // no metadata callback yet.
            let l1_process_lock = if p_type == POLICY_MEMORY {
                None
            } else {
                let process_roots = self.l2.inner.load().all_roots();
                match acquire_cache_process_read_lock(k_str, &process_roots).await {
                    Ok(lock) => Some(lock),
                    Err(err) => {
                        warn!(
                            key = k_str,
                            error = %err,
                            "CACHE_L1: unable to acquire cross-process cache lock; bypassing L1"
                        );
                        None
                    }
                }
            };
            // Check TinyUfoL1 (lock-free L1 cache with S3-FIFO + TinyLFU).
            if (p_type == POLICY_MEMORY || l1_process_lock.is_some())
                && let Some((entry, _cache_status)) = self.l1.get_stale(k_str)
            {
                if self.l1_entry_is_current(k_str, &entry, p_type, now) {
                    let mut response_header = entry.response_header.clone();
                    let status = response_header.status.as_u16();
                    restore_content_length(&mut response_header, status, entry.data.len() as u64);
                    let mut meta = CacheMeta::new(
                        system_time_from_timestamp(entry.fresh_until),
                        system_time_from_timestamp(entry.created_at),
                        entry.stale_while_revalidate_secs.min(u32::MAX as u64) as u32,
                        entry.stale_if_error_secs.min(u32::MAX as u64) as u32,
                        response_header,
                    );
                    meta.extensions_mut().insert(CacheErrorStatusPolicy {
                        allowed: entry.error_status_allowed,
                    });
                    prof_record_l1_hit();
                    return Ok(Some((
                        meta,
                        Box::new(MemoryHitHandler {
                            data: entry.data.clone(),
                            offset: 0,
                            end: entry.data.len(),
                            _process_lock: l1_process_lock,
                            _cache_read_permit: None,
                        }),
                    )));
                }
                // The key lock is still held, so a concurrent fill cannot
                // replace this entry between validation and removal.
                self.l1.remove(k_str);
            }
        }

        // For memory-only policy, we're done (no L2 disk storage)
        if p_type == POLICY_MEMORY {
            return Ok(None);
        }

        // Check L2 (disk)
        if let Some((meta, handler)) = self.l2.lookup(key, trace).await? {
            prof_record_l2_hit();
            // Promote L2 disk hits to TinyUfoL1
            let promotion =
                handler
                    .as_any()
                    .downcast_ref::<MemoryHitHandler>()
                    .map(|mem_handler| {
                        (
                            mem_handler.data.clone(),
                            meta.extensions().get::<CacheLookupStamp>().copied(),
                        )
                    });
            if let Some((promotion_data, stamp)) = promotion {
                let _purge_guard = acquire_cache_purge_read_guard().await;
                let write_lock = cache_write_lock_for_key(k_str);
                let _write_guard = write_lock.lock().await;
                let now = crate::utils::time::now_timestamp();
                let current_meta = crate::metrics::storage::get_cache_meta_memory(&format!(
                    "{:x}",
                    md5_legacy::compute(k_str.as_bytes())
                ));
                let stamp_is_current = stamp.is_some_and(|stamp| {
                    stamp.purge_generation == current_cache_purge_generation()
                        && current_meta.as_ref().is_some_and(|current| {
                            current.cache_key == k_str
                                && current.updated_at == stamp.metadata_updated_at
                                && current.expires > now
                        })
                });
                let background_permit = crate::memory_governor::MEMORY_GOVERNOR
                    .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork);
                if promotion_data.len() <= MEMORY_SERVE_MAX as usize
                    && background_permit.is_some()
                    && !crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high()
                    && stamp_is_current
                {
                    let current_meta = current_meta.expect("stamp validation checked metadata");
                    let fresh_until = current_meta.expires;
                    let created_at = if current_meta.created_at > 0 {
                        current_meta.created_at
                    } else {
                        timestamp_from_system_time(meta.created())
                    };
                    let ttl_secs = (fresh_until - now).max(1) as u64;
                    let mut response_header = meta.response_header().clone();
                    let status = response_header.status.as_u16();
                    restore_content_length(
                        &mut response_header,
                        status,
                        promotion_data.len() as u64,
                    );

                    let entry = TinyUfoL1Entry {
                        cache_key: k_str.to_string(),
                        data: promotion_data,
                        response_header,
                        fresh_until,
                        created_at,
                        stale_while_revalidate_secs: current_meta.stale_while_revalidate_secs,
                        stale_if_error_secs: current_meta.stale_if_error_secs,
                        error_status_allowed: current_meta.error_status_allowed,
                        metadata_updated_at: current_meta.updated_at,
                        cache_state_version:
                            crate::metrics::storage::cache_meta_entry_version_for_l1(&current_meta),
                        purge_generation: current_cache_purge_generation(),
                        metadata_required: true,
                    };
                    self.l1
                        .put(k_str, entry, std::time::Duration::from_secs(ttl_secs));
                    bloom_insert(k_str);
                    negative_cache_remove(k_str);
                    prof_record_l2_mem_promotion();
                }
            }

            return Ok(Some((meta, handler)));
        }

        Ok(None)
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<MissHandler> {
        let p_type = self.policy_type.load(Ordering::Relaxed);

        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            if p_type == POLICY_MEMORY {
                return Ok(Box::new(NoopMissHandler));
            }
            let min_free = self
                .min_free_bytes
                .load(std::sync::atomic::Ordering::Relaxed);
            if CACHED_DISK_AVAILABLE.load(Ordering::Relaxed) < min_free {
                return Ok(Box::new(NoopMissHandler));
            }
            return self.l2.get_miss_handler(key, meta, trace).await;
        }

        if p_type == POLICY_MEMORY {
            return self.memory_miss_handler(key, meta, false).await;
        }

        let min_free = self
            .min_free_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let available = CACHED_DISK_AVAILABLE.load(Ordering::Relaxed);
        if available < min_free {
            warn!(
                "RPC_CACHE: Disk space below threshold. Using bounded memory cache for this fill."
            );
            return self
                .memory_miss_handler(key, meta, self.memory_fallback_requires_metadata())
                .await;
        }

        self.l2.get_miss_handler(key, meta, trace).await
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        if key.user_tag.is_empty() {
            return Ok(false);
        }

        let key_str = key.user_tag.as_ref();
        let _purge_guard = acquire_cache_purge_write_guard().await;
        advance_cache_purge_generation();
        let process_roots = self.l2.inner.load().all_roots();
        let _process_lock = match acquire_cache_process_barrier_write_lock(&process_roots).await {
            Ok(lock) => lock,
            Err(err) => {
                warn!(
                    key = key_str,
                    error = %err,
                    "CACHE_PURGE: unable to acquire cross-process purge barrier"
                );
                return Ok(false);
            }
        };
        // Keep local PURGE behavior consistent with the RPC key purge: the
        // supplied key is the unsuffixed base key, but stored objects may be
        // split across method/WebP/content-encoding variants.
        let mut variants = Self::cache_key_variants(key_str);
        let variant_prefix = format!("{}@", key_str);
        variants.extend(self.l1.keys_matching_family(key_str));
        crate::metrics::storage::STORAGE.for_each_cache_meta(|_, meta| {
            if meta.cache_key == key_str || meta.cache_key.starts_with(&variant_prefix) {
                variants.push(meta.cache_key.clone());
            }
        });
        variants.sort_unstable();
        variants.dedup();
        for variant in variants {
            self.purge_exact_stored_key_at_version(&variant, None).await;
        }
        Ok(true)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        trace: &pingora_cache::trace::SpanHandle,
    ) -> Result<bool> {
        if let Some(k_str) = key.primary_key_str()
            && crate::cache::partial::is_partial_cache_key(k_str)
        {
            if self.policy_type.load(Ordering::Relaxed) == POLICY_MEMORY {
                return Ok(false);
            }
            return self.l2.update_meta(key, meta, trace).await;
        }

        let k_str = key.primary_key_str().unwrap_or("unknown");
        let p_type = self.policy_type.load(Ordering::Relaxed);
        if p_type == POLICY_MEMORY {
            let key_str = k_str;
            let _purge_guard = acquire_cache_purge_read_guard().await;
            let write_lock = cache_write_lock_for_key(key_str);
            let _write_guard = write_lock.lock().await;
            let Some(existing) = self.l1.get(key_str) else {
                return Ok(false);
            };
            let now = crate::utils::time::now_timestamp();
            let error_status_allowed = cache_meta_allows_error_status(meta);
            if !crate::cache::status_allows_full_cache_with_error_policy(
                meta.response_header().status.as_u16(),
                error_status_allowed,
            ) || !crate::cache::response_headers_allow_shared_cache(
                &meta.response_header().headers,
            ) || !crate::cache::response_encoding_matches_cache_key(
                key_str,
                &meta.response_header().headers,
            ) {
                return Ok(false);
            }
            if existing.purge_generation != current_cache_purge_generation() {
                return Ok(false);
            }
            let Ok(content_length) =
                crate::cache::response_content_length(&meta.response_header().headers)
            else {
                return Ok(false);
            };
            let body_length_is_valid = if cache_key_is_head_variant(key_str) {
                existing.data.is_empty()
            } else {
                content_length
                    .is_none_or(|length| u64::try_from(existing.data.len()).ok() == Some(length))
            };
            if !body_length_is_valid {
                return Ok(false);
            }
            let fresh_until = timestamp_from_system_time(meta.fresh_until());
            let ttl = (fresh_until - now).max(1) as u64;
            let mut response_header = meta.response_header().clone();
            let status = response_header.status.as_u16();
            restore_content_length(&mut response_header, status, existing.data.len() as u64);
            let created_at = timestamp_from_system_time(meta.created());
            self.l1.put(
                key_str,
                TinyUfoL1Entry {
                    cache_key: key_str.to_string(),
                    data: existing.data,
                    response_header,
                    fresh_until,
                    created_at,
                    stale_while_revalidate_secs: meta.stale_while_revalidate_sec() as u64,
                    stale_if_error_secs: meta.stale_if_error_sec() as u64,
                    error_status_allowed,
                    metadata_updated_at: now,
                    cache_state_version: new_cache_l1_state_version(&format!(
                        "{:x}",
                        md5_legacy::compute(key_str.as_bytes())
                    )),
                    purge_generation: current_cache_purge_generation(),
                    metadata_required: existing.metadata_required,
                },
                std::time::Duration::from_secs(ttl),
            );
            bloom_insert(key_str);
            negative_cache_remove(key_str);
            return Ok(true);
        }
        self.l2.update_meta(key, meta, trace).await
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

#[derive(Eq, PartialEq)]
struct EvictCandidate {
    access_time: i64,
    size: u64,
    hash: String,
    cache_key: String,
    expires: i64,
    updated_at: i64,
}

impl Ord for EvictCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.access_time.cmp(&other.access_time)
    }
}

impl PartialOrd for EvictCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

async fn evict_full_cache_entry_if_current(
    storage: &HybridStorage,
    hash: &str,
    cache_key: &str,
    expected_expires: i64,
    expected_updated_at: i64,
    now: i64,
    expired: bool,
) {
    let _purge_guard = acquire_cache_purge_read_guard().await;
    let write_lock = cache_write_lock_for_key(cache_key);
    let _write_guard = write_lock.lock().await;
    let process_roots = storage.l2.inner.load().all_roots();
    let _process_lock = match acquire_cache_process_read_lock(cache_key, &process_roots).await {
        Ok(lock) => lock,
        Err(err) => {
            warn!(
                cache_key,
                error = %err,
                "CACHE_EVICTOR: unable to acquire cross-process cache lock; skipping entry"
            );
            return;
        }
    };
    let Some(meta) = crate::metrics::storage::get_cache_meta_memory(hash) else {
        return;
    };
    // The scan is only a snapshot. Re-check identity after taking the key
    // lock so a newer fill cannot be deleted by an older janitor candidate.
    if meta.cache_key != cache_key
        || meta.expires != expected_expires
        || meta.updated_at != expected_updated_at
        || if expired {
            meta.expires > now
        } else {
            meta.expires <= now
        }
    {
        return;
    }

    let location = storage.l2.partial_location_for_key_str(cache_key);
    crate::cache::partial::purge_locked(cache_key, &location.roots).await;
    let inner = storage.l2.inner.load();
    remove_cache_file_from_roots(&inner, hash).await;
    storage.l1.remove(cache_key);
    crate::metrics::storage::STORAGE
        .delete_cache_meta_async(hash)
        .await;
}

pub async fn start_cache_purger(storage: &'static HybridStorage, _disk_root: PathBuf) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));

    loop {
        interval.tick().await;
        let Some(_permit) = crate::memory_governor::MEMORY_GOVERNOR
            .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork)
        else {
            tracing::warn!(
                "CACHE_PURGER: skipping cycle because background memory admission is full"
            );
            continue;
        };
        let now = crate::utils::time::now_timestamp();
        let max_bytes = storage
            .max_disk_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut current_size: u64 = 0;
        let mut expired_entries = Vec::new();

        // Pass 1: Stream metadata from in-memory index, collect expired, calculate size
        crate::metrics::storage::STORAGE.for_each_cache_meta(|hash, meta| {
            let expires = meta.expires;
            let size = meta.size;
            let stale_window = meta
                .stale_while_revalidate_secs
                .max(meta.stale_if_error_secs)
                .min(i64::MAX as u64) as i64;
            let stale_until = expires.saturating_add(stale_window);

            if now > stale_until {
                expired_entries.push((hash, meta.cache_key.clone(), expires, meta.updated_at));
            } else {
                current_size += size;
            }
        });

        // Execute: delete expired files under the same key lock used by a
        // miss handler and an explicit purge.
        for (hash, cache_key, expires, updated_at) in expired_entries {
            evict_full_cache_entry_if_current(
                storage, &hash, &cache_key, expires, updated_at, now, true,
            )
            .await;
        }

        // Pass 2: Capacity eviction using Max-Heap if disk exceeds limits
        if max_bytes > 0 && current_size > max_bytes {
            let bytes_to_free = current_size - max_bytes;

            let mut heap = std::collections::BinaryHeap::new();
            let mut heap_bytes: u64 = 0;

            crate::metrics::storage::STORAGE.for_each_cache_meta(|hash, meta| {
                let expires = meta.expires;
                // Only process active files
                if now <= expires {
                    let size = meta.size;
                    let access_time = meta.access_time;

                    heap.push(EvictCandidate {
                        access_time,
                        size,
                        hash,
                        cache_key: meta.cache_key.clone(),
                        expires,
                        updated_at: meta.updated_at,
                    });
                    heap_bytes += size;

                    // Maintain the heap size just enough to free the required bytes
                    while heap_bytes > bytes_to_free {
                        if let Some(top) = heap.peek() {
                            if heap_bytes - top.size >= bytes_to_free {
                                heap_bytes -= top.size;
                                heap.pop();
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            });

            // Execute: Delete oldest files
            let candidates_count = heap.len();
            tracing::info!(
                "CACHE_PURGER: Capacity reached. Evicting {} oldest files to free {} bytes.",
                candidates_count,
                heap_bytes
            );

            for candidate in heap {
                evict_full_cache_entry_if_current(
                    storage,
                    &candidate.hash,
                    &candidate.cache_key,
                    candidate.expires,
                    candidate.updated_at,
                    now,
                    false,
                )
                .await;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Cache performance profiling — log hit/miss/promotion stats
// ═══════════════════════════════════════════════════════════

static PROF_L1_HITS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_HITS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_MEM_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
static PROF_L2_ASYNC_PROMOTIONS: AtomicU64 = AtomicU64::new(0);
static PROF_BLOOM_REJECTS: AtomicU64 = AtomicU64::new(0);
/// Accumulated disk read time in microseconds for the current 10s window.
static PROF_DISK_READ_US: AtomicU64 = AtomicU64::new(0);
/// Accumulated request_filter wall time in microseconds for the current 10s window.
static PROF_REQFILT_US: AtomicU64 = AtomicU64::new(0);
/// Number of request_filter calls in the current 10s window.
static PROF_REQFILT_COUNT: AtomicU64 = AtomicU64::new(0);
/// Number of FAST PATH (cacheable GET/HEAD early return) exits in the current 10s window.
static PROF_FASTPATH_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn prof_record_l1_hit() {
    PROF_L1_HITS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_l2_hit() {
    PROF_L2_HITS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_l2_mem_promotion() {
    PROF_L2_MEM_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_l2_async_promotion() {
    PROF_L2_ASYNC_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_bloom_reject() {
    PROF_BLOOM_REJECTS.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_reqfilter(us: u64) {
    PROF_REQFILT_US.fetch_add(us, Ordering::Relaxed);
    PROF_REQFILT_COUNT.fetch_add(1, Ordering::Relaxed);
}
pub fn prof_record_fastpath() {
    PROF_FASTPATH_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Start a background task that logs cache performance stats every 10 seconds.
/// Provides real-time visibility into L1/L2 hit ratios and promotion rates.
pub fn start_cache_profiler() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let l1 = PROF_L1_HITS.swap(0, Ordering::Relaxed);
            let l2 = PROF_L2_HITS.swap(0, Ordering::Relaxed);
            let sync_prom = PROF_L2_MEM_PROMOTIONS.swap(0, Ordering::Relaxed);
            let async_prom = PROF_L2_ASYNC_PROMOTIONS.swap(0, Ordering::Relaxed);
            let bloom_rej = PROF_BLOOM_REJECTS.swap(0, Ordering::Relaxed);
            let disk_us = PROF_DISK_READ_US.swap(0, Ordering::Relaxed);
            let reqfil_us = PROF_REQFILT_US.swap(0, Ordering::Relaxed);
            let reqfil_cnt = PROF_REQFILT_COUNT.swap(0, Ordering::Relaxed);
            let fastpath = PROF_FASTPATH_COUNT.swap(0, Ordering::Relaxed);
            let total = l1 + l2;
            if total == 0 && reqfil_cnt == 0 && bloom_rej == 0 {
                continue;
            }
            let l1_pct = if total > 0 {
                l1 as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            let avg_disk_ms = if l2 > 0 {
                disk_us as f64 / l2 as f64 / 1000.0
            } else {
                0.0
            };
            let avg_reqfil_ms = if reqfil_cnt > 0 {
                reqfil_us as f64 / reqfil_cnt as f64 / 1000.0
            } else {
                0.0
            };
            tracing::info!(
                "CACHE_PROFILE: L1={l1}/s L2={l2}/s L1%={l1_pct:.1} bloom_rej={bloom_rej}/s sync_prom={sync_prom}/s async_prom={async_prom}/s total={total}/s disk={avg_disk_ms:.1}ms rf={avg_reqfil_ms:.1}ms fp={fastpath}/s"
            );
        }
    });
}

/// Periodically refresh disk space and memory budget.
/// TinyUFO handles eviction internally via S3-FIFO.
pub fn start_cache_janitor() {
    tokio::spawn(async {
        let disk_root = crate::paths::NodePaths::current().cache_dir();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let Some(_permit) = crate::memory_governor::MEMORY_GOVERNOR
                .try_admit(crate::memory_governor::AdmissionClass::BackgroundWork)
            else {
                tracing::warn!(
                    "CACHE_JANITOR: skipping cycle because background memory admission is full"
                );
                continue;
            };

            // Refresh cached disk available space
            let disks = sysinfo::Disks::new_with_refreshed_list();
            let available = disks
                .iter()
                .find(|d| disk_root.starts_with(d.mount_point()))
                .map(|d| d.available_space())
                .unwrap_or(u64::MAX);
            CACHED_DISK_AVAILABLE.store(available, Ordering::Relaxed);

            crate::cache_manager::CACHE.storage.l1.refresh_auto_budget();
            crate::memory_reclaim::periodic_reclaim_check();

            // Clean expired negative cache entries
            let now = crate::utils::time::now_timestamp();
            NEGATIVE_CACHE.retain(|_, &mut expires| expires > now);
        }
    });
}

#[doc(hidden)]
pub fn fast_l1_lookup(key: &str) -> bool {
    crate::cache_manager::CACHE.storage.l1.get(key).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64 as TestAtomicU64, Ordering as TestOrdering};
    use std::sync::Mutex as TestMutex;

    static TEST_UNIQUE_COUNTER: TestAtomicU64 = TestAtomicU64::new(0);
    static CACHE_GLOBAL_STATE_LOCK: TestMutex<()> = TestMutex::new(());

    fn unique_test_suffix(prefix: &str) -> String {
        let seq = TEST_UNIQUE_COUNTER.fetch_add(1, TestOrdering::Relaxed);
        format!("{prefix}-{}-{seq}", std::process::id())
    }

    async fn memory_miss_handler_for_test(
        storage: &HybridStorage,
        key: String,
        expected_body_len: u64,
    ) -> Box<MemoryMissHandler> {
        let mut response_header = ResponseHeader::build(200, Some(1)).expect("response header");
        response_header
            .insert_header("content-length", expected_body_len.to_string())
            .expect("content length");
        let now = crate::utils::time::now_timestamp();
        let permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::CacheWrite)
            .expect("cache write permit should be available");
        Box::new(MemoryMissHandler {
            key: key.clone(),
            data: Vec::with_capacity(expected_body_len as usize),
            response_header,
            fresh_until: now + 60,
            created_at: now,
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            error_status_allowed: false,
            purge_generation: current_cache_purge_generation(),
            l1_invalidation_generation: current_cache_l1_invalidation_generation(),
            metadata_required: false,
            metadata_updated_at: 0,
            cache_state_version: new_cache_l1_state_version(&format!(
                "{:x}",
                md5_legacy::compute(key.as_bytes())
            )),
            expected_body_len: Some(expected_body_len),
            head_request: false,
            l1: storage.l1.clone(),
            rejected: false,
            _purge_guard: acquire_cache_purge_read_guard().await,
            write_guard: cache_write_lock_for_key(&key).lock_owned().await,
            _cache_write_permit: permit,
        })
    }

    async fn file_miss_handler_for_test(
        root: &Path,
        key: &str,
        expected_body_len: u64,
    ) -> (Box<FileMissHandler>, PathBuf, PathBuf) {
        tokio::fs::create_dir_all(root).await.expect("cache root");
        let temp_path = root.join("object.tmp");
        let final_path = root.join("object");
        let file = tokio::fs::File::create(&temp_path)
            .await
            .expect("temp file");
        let now = crate::utils::time::now_timestamp();
        let permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::CacheWrite)
            .expect("cache write permit should be available");
        let handler = Box::new(FileMissHandler {
            file: Some(file),
            encoder: None,
            written: 0,
            final_path: final_path.clone(),
            temp_path: temp_path.clone(),
            hash: format!("{:x}", md5_legacy::compute(key.as_bytes())),
            key_str: key.to_string(),
            expires: now + 60,
            created_at: now,
            status: 200,
            headers: Vec::new(),
            compressed: false,
            error_status_allowed: false,
            shard_id: None,
            relative_path: "object".to_string(),
            root_path: None,
            previous_body_path: None,
            purge_generation: current_cache_purge_generation(),
            expected_body_len: Some(expected_body_len),
            head_request: false,
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            event_version: crate::metrics::storage::next_cache_meta_event_version(),
            disabled: false,
            committed: false,
            published: false,
            _purge_guard: acquire_cache_purge_read_guard().await,
            _write_guard: cache_write_lock_for_key(key).lock_owned().await,
            _process_lock: None,
            _cache_write_permit: permit,
        });
        (handler, temp_path, final_path)
    }

    async fn seed_purgeable_full_entry(
        storage: &'static HybridStorage,
        key: &str,
        headers: Vec<(String, String)>,
    ) -> (String, PathBuf) {
        let hash = format!("{:x}", md5_legacy::compute(key.as_bytes()));
        let path = storage.l2.get_path_by_hash(&hash);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache directory");
        tokio::fs::write(&path, b"purge-body")
            .await
            .expect("write cache body");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key.to_string(),
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers,
                compressed: false,
                ..Default::default()
            },
        );
        (hash, path)
    }

    fn current_encoding_variant(base: &str, suffix: &str, encoding: &str) -> String {
        let mut key = format!("{base}{suffix}");
        crate::cache::append_cache_encoding_variant(&mut key, encoding);
        key
    }

    #[test]
    fn dangerous_prefix_detection_requires_url_host_boundary() {
        assert!(HybridStorage::is_dangerous_purge_prefix("*"));
        assert!(HybridStorage::is_dangerous_purge_prefix(""));
        assert!(HybridStorage::is_dangerous_purge_prefix("https://"));
        assert!(HybridStorage::is_dangerous_purge_prefix(
            "https://cache.example.com"
        ));
        assert!(HybridStorage::is_dangerous_purge_prefix(
            "https://cache.example.com*"
        ));
        assert!(!HybridStorage::is_dangerous_purge_prefix(
            "https://cache.example.com/*"
        ));
    }

    #[tokio::test]
    async fn purge_by_key_removes_current_and_legacy_representation_variants() {
        let unique = unique_test_suffix("purge-encoding-variants");
        let base = format!("https://cache.example.test/{unique}");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(HybridStorage::new(0, &root)));

        let mut seeded = Vec::new();
        let mut add = |key: String, encoding: Option<&str>| {
            seeded.push((key, encoding.map(str::to_string)));
        };

        // Identity, WebP, and HEAD variants have no compression marker.
        add(base.clone(), None);
        add(format!("{base}@webp"), None);
        add(format!("{base}@method:HEAD"), None);
        add(format!("{base}@method:HEAD@webp"), None);

        let mut webp = base.clone();
        crate::cache::append_cache_webp_variant(&mut webp);
        let mut head = base.clone();
        crate::cache::append_cache_method_variant(&mut head, "HEAD");
        let mut head_webp = head.clone();
        crate::cache::append_cache_webp_variant(&mut head_webp);
        add(webp.clone(), None);
        add(head.clone(), None);
        add(head_webp.clone(), None);

        // Current compression keys are digest-bound to the unencoded key.
        for current_base in [base.clone(), webp, head, head_webp] {
            let mut br = current_base.clone();
            crate::cache::append_cache_encoding_variant(&mut br, "br");
            add(br, Some("br"));
            let mut gzip = current_base;
            crate::cache::append_cache_encoding_variant(&mut gzip, "gzip");
            add(gzip, Some("gzip"));
        }

        // A short-lived migration version used the digest-bound compression
        // marker with the old plain WebP/method suffixes. Purge must remove
        // those keys as well.
        for suffix in ["@webp", "@method:HEAD", "@method:HEAD@webp"] {
            add(current_encoding_variant(&base, suffix, "br"), Some("br"));
            add(
                current_encoding_variant(&base, suffix, "gzip"),
                Some("gzip"),
            );
        }

        // Legacy suffixes must still be deleted, but are not eligible for
        // cache hits anymore because they are ambiguous with user keys.
        add(format!("{base}@br"), Some("br"));
        add(format!("{base}@gzip"), Some("gzip"));
        add(format!("{base}@webp@br"), Some("br"));
        add(format!("{base}@method:HEAD@gzip"), Some("gzip"));

        let mut files = Vec::with_capacity(seeded.len());
        for (key, encoding) in seeded {
            let headers = encoding
                .map(|encoding| vec![("content-encoding".to_string(), encoding)])
                .unwrap_or_default();
            files.push(seed_purgeable_full_entry(storage, &key, headers).await);
        }

        assert!(storage.purge_by_key(&base).await);
        for (hash, path) in files {
            assert!(!path.exists(), "purge left body file for {hash}");
            assert!(
                crate::metrics::storage::get_cache_meta_memory(&hash).is_none(),
                "purge left metadata for {hash}"
            );
        }

        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn local_storage_purge_removes_the_whole_variant_family() {
        let unique = unique_test_suffix("local-purge-variants");
        let base = format!("https://cache.example.test/{unique}");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(HybridStorage::new(0, &root)));
        let br = current_encoding_variant(&base, "", "br");
        let head_webp_gzip = current_encoding_variant(&base, "@method:HEAD@webp", "gzip");
        let entries = [
            seed_purgeable_full_entry(storage, &base, Vec::new()).await,
            seed_purgeable_full_entry(
                storage,
                &br,
                vec![("content-encoding".to_string(), "br".to_string())],
            )
            .await,
            seed_purgeable_full_entry(
                storage,
                &head_webp_gzip,
                vec![("content-encoding".to_string(), "gzip".to_string())],
            )
            .await,
        ];
        let compact = CacheKey::new("", base.clone(), base.clone()).to_compact();
        let trace = pingora_cache::trace::Span::inactive().handle();

        assert!(
            <HybridStorage as Storage>::purge(storage, &compact, PurgeType::Invalidation, &trace)
                .await
                .expect("local purge result")
        );
        for (hash, path) in entries {
            assert!(!path.exists(), "local purge left body file for {hash}");
            assert!(crate::metrics::storage::get_cache_meta_memory(&hash).is_none());
        }

        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn partial_location_prioritizes_the_current_write_shard() {
        let unique = unique_test_suffix("partial-write-shard-order");
        let root_a = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}-a"));
        let root_b = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}-b"));
        let storage = FileStorage::new(root_a.clone());
        storage.update_shards(
            vec![
                CacheShard {
                    id: "a".to_string(),
                    root: root_a.clone(),
                    weight: 1,
                },
                CacheShard {
                    id: "b".to_string(),
                    root: root_b.clone(),
                    weight: 1,
                },
            ],
            Vec::new(),
            true,
            false,
        );

        let (base, selected_root) = (0..100)
            .map(|index| {
                let base = format!("https://cache.example.test/{unique}/{index}");
                let hash = format!("{:x}", md5_legacy::compute(base.as_bytes()));
                let selected_root = if u64::from_str_radix(&hash[..16], 16).unwrap() % 2 == 0 {
                    root_a.clone()
                } else {
                    root_b.clone()
                };
                (base, selected_root)
            })
            .find(|(_, selected_root)| selected_root == &root_b)
            .expect("find a key assigned to the second shard");
        let key = crate::cache::partial::partial_cache_key(&base, Some("bytes=0-3"))
            .expect("partial cache key");
        let location = storage.partial_location_for_key_str(&key);
        assert_eq!(location.write_root, selected_root);
        assert_eq!(location.roots.first(), Some(&selected_root));

        let capture = crate::cache::partial::PartialCapture {
            start: 0,
            end: 3,
            total: Some(crate::cache::partial::MIN_FORCE_PARTIAL_HIT_BYTES),
            expires: crate::utils::time::now_timestamp() + 60,
            headers: vec![(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
            etag: Some("v1".to_string()),
            last_modified: None,
            created_at: crate::utils::time::now_timestamp(),
            min_size: None,
            max_size: None,
        };
        let old_roots = vec![root_a.clone()];
        assert!(
            crate::cache::partial::store(&key, &capture, b"OLD!", &old_roots, root_a.clone(),)
                .await
                .expect("store old root")
        );
        let new_roots = vec![root_b.clone()];
        assert!(
            crate::cache::partial::store(&key, &capture, b"NEW!", &new_roots, root_b.clone(),)
                .await
                .expect("store current root")
        );

        let hit = crate::cache::partial::lookup(&key, &location.roots)
            .await
            .expect("lookup both roots")
            .expect("current root should win");
        let mut body = Vec::new();
        let mut handler = hit.handler;
        while let Some(chunk) = handler.read_body().await.expect("read partial body") {
            body.extend_from_slice(&chunk);
        }
        assert_eq!(body, b"NEW!");

        let _ = tokio::fs::remove_dir_all(&root_a).await;
        let _ = tokio::fs::remove_dir_all(&root_b).await;
    }

    #[tokio::test]
    async fn small_uncompressed_l2_hit_uses_memory_handler_for_fast_l1_promotion() {
        let unique = unique_test_suffix("small-l2-hit");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        tokio::fs::write(&path, b"small-body")
            .await
            .expect("write cache file");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str.clone(),
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (meta, handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<MemoryHitHandler>());
        assert_eq!(
            meta.response_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some("10")
        );

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn uncompressed_l2_hit_above_memory_read_limit_streams_file() {
        let unique = unique_test_suffix("stream-l2-hit");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        let advertised_size = cache_memory_hit_limit_bytes().saturating_add(1);
        let file = tokio::fs::File::create(&path)
            .await
            .expect("create cache file");
        file.set_len(advertised_size)
            .await
            .expect("set cache file size");
        drop(file);
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str.clone(),
                size: advertised_size,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (meta, handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<FileHitHandler>());
        let expected_len = advertised_size.to_string();
        assert_eq!(
            meta.response_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some(expected_len.as_str())
        );

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn file_cache_disabled_streams_small_l2_hits() {
        let unique = unique_test_suffix("file-cache-off");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        storage.update_config(root.clone(), Vec::new(), true, false);
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path_by_hash(&hash);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, b"small-body").await.unwrap();
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str,
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (_meta, mut handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<FileHitHandler>());
        assert_eq!(
            handler
                .read_body()
                .await
                .expect("read")
                .expect("chunk")
                .as_ref(),
            b"small-body"
        );

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn uncompressed_l2_hit_with_size_mismatch_is_treated_as_miss() {
        let unique = unique_test_suffix("small-meta-large-file");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path_by_hash(&hash);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        let file = tokio::fs::File::create(&path).await.unwrap();
        file.set_len(cache_memory_hit_limit_bytes().saturating_add(1))
            .await
            .unwrap();
        drop(file);
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str,
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let hit = storage.lookup(&key, &trace).await.expect("lookup result");
        assert!(hit.is_none());
        assert!(crate::metrics::storage::get_cache_meta_memory(&hash).is_none());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn file_update_meta_rejects_content_length_mismatch() {
        let unique = unique_test_suffix("update-meta-length-mismatch");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", unique.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache directory");
        tokio::fs::write(&path, b"old-body")
            .await
            .expect("write cache body");
        let now = crate::utils::time::now_timestamp();
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: unique.clone(),
                size: 8,
                expires: now + 60,
                access_time: now,
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let mut response_header = ResponseHeader::build(200, Some(1)).expect("response header");
        response_header
            .insert_header("content-length", "9")
            .expect("content length");
        let meta = CacheMeta::new(
            system_time_from_timestamp(now + 120),
            system_time_from_timestamp(now),
            0,
            0,
            response_header,
        );
        let trace = pingora_cache::trace::Span::inactive().handle();

        assert!(
            !<FileStorage as Storage>::update_meta(storage, &key, &meta, &trace)
                .await
                .expect("update metadata result")
        );
        let stored = crate::metrics::storage::get_cache_meta_memory(&hash)
            .expect("existing metadata should remain");
        assert_eq!(stored.size, 8);
        assert!(stored.headers.is_empty());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[test]
    fn head_update_meta_allows_representation_length_for_empty_body() {
        let unique = unique_test_suffix("update-meta-head-length");
        let base = format!("https://cache.example.test/{unique}");
        let mut head_key = base.clone();
        crate::cache::append_cache_method_variant(&mut head_key, "HEAD");
        assert!(cache_key_is_head_variant(&head_key));
        let mut headers = http::HeaderMap::new();
        headers.insert("content-length", http::HeaderValue::from_static("123"));
        let content_length = crate::cache::response_content_length(&headers)
            .expect("valid content length")
            .expect("content length should be present");
        assert!(content_length_matches_body(
            &head_key,
            Some(content_length),
            0
        ));
        assert!(!content_length_matches_body(
            &head_key,
            Some(content_length),
            1
        ));
        assert!(persisted_content_length_matches_body(
            &head_key,
            &[("content-length".to_string(), "123".to_string())],
            0
        ));
    }

    #[tokio::test]
    async fn l2_hit_with_invalid_cached_status_is_treated_as_miss() {
        let unique = unique_test_suffix("invalid-status-l2-hit");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        tokio::fs::write(&path, b"cached-body")
            .await
            .expect("write cache file");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str.clone(),
                size: 11,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 700,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let hit = storage.lookup(&key, &trace).await.expect("lookup result");
        assert!(hit.is_none());
        assert!(crate::metrics::storage::get_cache_meta_memory(&hash).is_none());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn l2_hit_with_legacy_error_status_is_treated_as_miss() {
        let unique = unique_test_suffix("legacy-error-status-l2-hit");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", unique.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        tokio::fs::write(&path, b"error-body")
            .await
            .expect("write cache file");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: unique.clone(),
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 503,
                headers: Vec::new(),
                compressed: false,
                // This simulates old metadata that had no explicit error
                // admission bit.
                error_status_allowed: false,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let hit = storage.lookup(&key, &trace).await.expect("lookup result");
        assert!(hit.is_none());
        assert!(crate::metrics::storage::get_cache_meta_memory(&hash).is_none());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn corrupted_compressed_l2_entry_is_removed_before_origin_retry() {
        let unique = unique_test_suffix("corrupt-compressed-l2");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", unique.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache directory");
        tokio::fs::write(&path, b"not-a-zstd-frame")
            .await
            .expect("write corrupt cache body");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: unique.clone(),
                size: 16,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: true,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let hit = storage.lookup(&key, &trace).await.expect("lookup result");
        assert!(hit.is_none());
        assert!(!path.exists());
        assert!(crate::metrics::storage::get_cache_meta_memory(&hash).is_none());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn partial_miss_handler_holds_purge_fences_before_first_body_chunk() {
        let unique = unique_test_suffix("partial-miss-purge-race");
        let base = format!("https://cache.example.test/{unique}");
        let key = crate::cache::partial::partial_cache_key(&base, Some("bytes=0-3"))
            .expect("partial cache key");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        tokio::fs::create_dir_all(&root)
            .await
            .expect("create cache root");
        let storage = Box::leak(Box::new(HybridStorage::new(0, &root)));
        let location = storage.partial_location_for_key_str(&key);
        let capture = crate::cache::partial::PartialCapture {
            start: 0,
            end: 3,
            total: Some(crate::cache::partial::MIN_FORCE_PARTIAL_HIT_BYTES),
            expires: crate::utils::time::now_timestamp() + 60,
            headers: vec![(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
            etag: Some("v1".to_string()),
            last_modified: None,
            created_at: crate::utils::time::now_timestamp(),
            min_size: None,
            max_size: None,
        };
        let permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::CacheWrite)
            .expect("cache write permit should be available");
        let mut handler = Box::new(PartialMissHandler {
            cache_key: key.clone(),
            capture,
            writer: None,
            location: location.clone(),
            disabled: false,
            purge_generation: current_cache_purge_generation(),
            purge_guard: Some(acquire_cache_purge_read_guard().await),
            write_guard: Some(cache_write_lock_for_key(&key).lock_owned().await),
            process_lock: None,
            _cache_write_permit: permit,
        });

        // The purge is started before the origin supplies its first body
        // chunk. It must wait for the miss handler's fences rather than
        // completing and allowing the old fill to be published afterwards.
        let purge_base = base.clone();
        let purge_storage = storage;
        let mut purge_task = tokio::spawn(async move {
            purge_storage
                .purge_exact_stored_key_at_version(&purge_base, None)
                .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut purge_task)
                .await
                .is_err(),
            "exact purge must wait for a partial miss handler created before it"
        );

        handler
            .write_body(bytes::Bytes::from_static(b"ABCD"), false)
            .await
            .expect("write origin body");
        assert!(matches!(
            handler.finish().await.expect("finish partial miss"),
            MissFinishType::Created(4)
        ));
        purge_task.await.expect("purge task");

        assert!(
            crate::cache::partial::lookup(&key, &location.roots)
                .await
                .expect("lookup after purge")
                .is_none(),
            "purge must remove the fill that was active when purge began"
        );
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn remote_delete_clears_metadata_less_l1_when_local_meta_is_missing() {
        let key = unique_test_suffix("remote-delete-l1");
        let now = crate::utils::time::now_timestamp();
        crate::cache_manager::CACHE.storage.l1.put(
            &key,
            TinyUfoL1Entry {
                cache_key: key.clone(),
                data: bytes::Bytes::from_static(b"stale-body"),
                response_header: ResponseHeader::build(200, None).expect("response header"),
                fresh_until: now + 60,
                created_at: now,
                stale_while_revalidate_secs: 0,
                stale_if_error_secs: 0,
                error_status_allowed: false,
                metadata_updated_at: now,
                cache_state_version: 0,
                purge_generation: current_cache_purge_generation(),
                metadata_required: false,
            },
            std::time::Duration::from_secs(60),
        );

        let hash = format!("{:x}", md5_legacy::compute(key.as_bytes()));
        assert!(crate::metrics::storage::get_cache_meta_memory(&hash).is_none());
        assert!(crate::cache_manager::CACHE.storage.l1.get(&key).is_some());

        crate::cluster::metadata::apply_remote_event(crate::cluster::metadata::CacheMetaEvent {
            event_id: unique_test_suffix("event"),
            event_type: crate::cluster::metadata::CacheMetaEventType::Delete,
            pod_name: "remote-pod".to_string(),
            hash: hash.clone(),
            cache_key: key.clone(),
            shard_id: None,
            relative_path: None,
            root_path: None,
            size: 0,
            expires: 0,
            status: 200,
            headers: Vec::new(),
            compressed: false,
            error_status_allowed: false,
            created_at: now,
            version: 100,
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
        })
        .await;

        assert!(crate::cache_manager::CACHE.storage.l1.get(&key).is_none());
        assert!(crate::metrics::storage::cache_meta_tombstone_version(&hash).is_some());

        // A delayed upsert from before the delete must not recreate the
        // metadata row after the delete has removed the current row.
        crate::cluster::metadata::apply_remote_event(crate::cluster::metadata::CacheMetaEvent {
            event_id: unique_test_suffix("late-upsert"),
            event_type: crate::cluster::metadata::CacheMetaEventType::Upsert,
            pod_name: "remote-pod".to_string(),
            hash: hash.clone(),
            cache_key: key.clone(),
            shard_id: None,
            relative_path: None,
            root_path: None,
            size: 10,
            expires: now + 60,
            status: 200,
            headers: Vec::new(),
            compressed: false,
            error_status_allowed: false,
            created_at: now,
            version: 99,
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
        })
        .await;
        assert!(crate::metrics::storage::get_cache_meta_memory(&hash).is_none());

        NEGATIVE_CACHE.remove(&key);
        crate::metrics::storage::delete_cache_meta_for_test(&hash);
    }

    #[tokio::test]
    async fn small_compressed_l2_hit_uses_memory_handler_for_fast_l1_promotion() {
        let unique = unique_test_suffix("small-compressed-l2-hit");
        let key_str = unique.clone();
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(FileStorage::new(&root)));
        let key = CacheKey::new("edge", key_str.as_str(), "");
        let hash = storage.get_hash(&key);
        let path = storage.get_path(&key);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache dir");
        let body = b"small compressed text body";
        let compressed = zstd::encode_all(body.as_slice(), 0).expect("compress body");
        tokio::fs::write(&path, compressed)
            .await
            .expect("write cache file");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: key_str.clone(),
                size: body.len() as u64,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: true,
                ..Default::default()
            },
        );

        let trace = pingora_cache::trace::Span::inactive().handle();
        let (meta, mut handler) = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup result")
            .expect("cache hit");
        assert!(handler.as_any().is::<MemoryHitHandler>());
        let expected_len = body.len().to_string();
        assert_eq!(
            meta.response_header()
                .headers
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some(expected_len.as_str())
        );
        let chunk = handler
            .read_body()
            .await
            .expect("read body")
            .expect("body chunk");
        assert_eq!(chunk.as_ref(), body);

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn metadata_less_l1_is_rejected_by_a_shared_exact_purge_fence() {
        let unique = unique_test_suffix("metadata-less-l1-fence");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(HybridStorage::new(0, &root)));
        let key = CacheKey::new("edge", unique.as_str(), "");
        let hash = format!("{:x}", md5_legacy::compute(unique.as_bytes()));
        let state_version = crate::metrics::storage::next_cache_meta_event_version();
        let now = crate::utils::time::now_timestamp();

        let entry = || TinyUfoL1Entry {
            cache_key: unique.clone(),
            data: bytes::Bytes::from_static(b"stale-body"),
            response_header: ResponseHeader::build(200, None).expect("response header"),
            fresh_until: now + 60,
            created_at: now,
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            error_status_allowed: false,
            metadata_updated_at: 0,
            cache_state_version: state_version,
            purge_generation: current_cache_purge_generation(),
            metadata_required: false,
        };
        storage
            .l1
            .put(&unique, entry(), std::time::Duration::from_secs(60));

        crate::cluster::metadata::apply_remote_event(crate::cluster::metadata::CacheMetaEvent {
            event_id: unique_test_suffix("fence-event"),
            event_type: crate::cluster::metadata::CacheMetaEventType::Delete,
            pod_name: "remote-pod".to_string(),
            hash: hash.clone(),
            cache_key: unique.clone(),
            shard_id: None,
            relative_path: None,
            root_path: None,
            size: 0,
            expires: 0,
            status: 200,
            headers: Vec::new(),
            compressed: false,
            error_status_allowed: false,
            created_at: now,
            version: state_version.saturating_add(1),
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
        })
        .await;

        // Reinsert the old process-local fallback after the event. This
        // simulates a delayed/lost callback; the shared tombstone itself must
        // still make the lookup fail closed.
        storage
            .l1
            .put(&unique, entry(), std::time::Duration::from_secs(60));
        let trace = pingora_cache::trace::Span::inactive().handle();
        assert!(
            storage
                .lookup(&key, &trace)
                .await
                .expect("lookup after shared purge fence")
                .is_none()
        );

        storage.l1.remove(&unique);
        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn l2_lookup_is_not_skipped_when_bloom_has_a_false_negative() {
        CACHE_BLOOM.reset_to_minimal();
        let unique = (0..256)
            .map(|index| unique_test_suffix(&format!("bloom-l2-{index}")))
            .find(|key| !bloom_may_exist(key))
            .expect("find a Bloom false-negative candidate");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = Box::leak(Box::new(HybridStorage::new(0, &root)));
        let key = CacheKey::new("edge", unique.as_str(), "");
        let hash = storage.l2.get_hash(&key);
        let path = storage.l2.get_path_by_hash(&hash);
        tokio::fs::create_dir_all(path.parent().expect("cache path parent"))
            .await
            .expect("create cache directory");
        tokio::fs::write(&path, b"bloom-body")
            .await
            .expect("write cache body");
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: unique.clone(),
                size: 10,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        assert!(!bloom_may_exist(&unique));
        let trace = pingora_cache::trace::Span::inactive().handle();
        let hit = storage
            .lookup(&key, &trace)
            .await
            .expect("lookup with Bloom false negative")
            .expect("authoritative L2 metadata should still hit");
        assert!(hit.1.as_any().is::<MemoryHitHandler>() || hit.1.as_any().is::<FileHitHandler>());

        storage.l1.remove(&unique);
        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[test]
    fn zstd_decompress_to_bytes_refuses_output_above_cap() {
        let body = vec![b'a'; 4096];
        let compressed = zstd::encode_all(body.as_slice(), 0).expect("compress body");

        assert!(zstd_decompress_to_bytes(&compressed, 1024).is_none());
        assert_eq!(
            zstd_decompress_to_bytes(&compressed, body.len()).expect("decompress body"),
            body
        );
    }

    #[tokio::test]
    async fn runtime_stats_include_tiny_ufo_l1_memory() {
        let unique = unique_test_suffix("runtime-stats-l1");
        let key = format!("https://cache.example.com/{unique}");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-stats-test-{unique}"));
        let storage = HybridStorage::new(0, &root);
        let before = storage.runtime_stats().await;
        assert!(before.file_cache_enabled);
        assert!(before.sendfile_enabled);
        assert_eq!(
            before.disk_hit_chunk_bytes,
            DISK_HIT_CHUNK_BYTES_SENDFILE_REQUESTED
        );

        storage.l1.put(
            &key,
            TinyUfoL1Entry {
                cache_key: key.clone(),
                data: bytes::Bytes::from_static(b"body"),
                response_header: ResponseHeader::build(200, None).expect("response header"),
                fresh_until: crate::utils::time::now_timestamp() + 60,
                created_at: crate::utils::time::now_timestamp(),
                stale_while_revalidate_secs: 0,
                stale_if_error_secs: 0,
                error_status_allowed: false,
                metadata_updated_at: crate::utils::time::now_timestamp(),
                cache_state_version: 0,
                purge_generation: current_cache_purge_generation(),
                metadata_required: false,
            },
            std::time::Duration::from_secs(60),
        );

        let after = storage.runtime_stats().await;
        assert!(after.memory_bytes >= before.memory_bytes.saturating_add(4));
        assert!(after.memory_count >= before.memory_count.saturating_add(1));

        storage.l1.remove(&key);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    #[tokio::test]
    async fn memory_hit_handler_supports_pingora_range_seek() {
        let mut handler = MemoryHitHandler {
            data: bytes::Bytes::from_static(b"abcdef"),
            offset: 0,
            end: 6,
            _process_lock: None,
            _cache_read_permit: None,
        };

        assert!(handler.can_seek());
        handler.seek(2, Some(5)).expect("seek should succeed");
        assert_eq!(
            handler
                .read_body()
                .await
                .expect("read")
                .expect("chunk")
                .as_ref(),
            b"cde"
        );
        assert!(handler.read_body().await.expect("read eof").is_none());

        handler.seek(6, None).expect("seek to EOF should succeed");
        assert!(handler.read_body().await.expect("read eof").is_none());
    }

    #[tokio::test]
    async fn uncompressed_file_hit_handler_supports_pingora_range_seek() {
        let unique = unique_test_suffix("file-range-seek");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        tokio::fs::create_dir_all(&root)
            .await
            .expect("create range seek root");
        let path = root.join("body");
        tokio::fs::write(&path, b"abcdef")
            .await
            .expect("write range seek body");
        let file = tokio::fs::File::open(&path)
            .await
            .expect("open range seek body");
        let mut handler = FileHitHandler {
            reader: FileHitReader::Plain(file),
            buf_size: 128,
            expected_len: 6,
            read_len: 0,
            range_end: 6,
            range_limited: false,
            eof_verified: false,
            seek_pending: false,
            corruption_entry: None,
            _process_lock: None,
        };

        assert!(handler.can_seek());
        handler.seek(2, Some(5)).expect("seek range");
        assert!(handler.seek_pending);
        assert_eq!(
            handler
                .read_body()
                .await
                .expect("read range")
                .expect("range chunk")
                .as_ref(),
            b"cde"
        );
        assert!(handler.read_body().await.expect("range eof").is_none());

        handler.seek(4, None).expect("seek open range");
        assert_eq!(
            handler
                .read_body()
                .await
                .expect("read open range")
                .expect("open range chunk")
                .as_ref(),
            b"ef"
        );
        assert!(handler.read_body().await.expect("open range eof").is_none());

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn tiny_ufo_l1_resize_hysteresis_ignores_small_budget_changes() {
        let old = 512 * 1024 * 1024;
        assert!(!TinyUfoL1::should_rebuild_for_budget_change(
            old,
            600 * 1024 * 1024
        ));
        if !MEMORY_GOVERNOR.is_memory_pressure_high() {
            assert!(!TinyUfoL1::should_rebuild_for_budget_change(
                old,
                480 * 1024 * 1024
            ));
        }
        assert!(TinyUfoL1::should_rebuild_for_budget_change(
            old,
            440 * 1024 * 1024
        ));
        assert!(TinyUfoL1::should_rebuild_for_budget_change(
            old,
            768 * 1024 * 1024
        ));
    }

    #[tokio::test]
    async fn file_miss_handler_drop_removes_uncommitted_temp_file() {
        let unique = unique_test_suffix("drop-temp");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let temp_path = root.join("object.tmp");
        tokio::fs::write(&temp_path, b"partial").await.unwrap();
        let final_path = root.join("object");
        let file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&temp_path)
            .await
            .unwrap();
        let permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::CacheWrite)
            .expect("cache write permit should be available");
        let write_guard = cache_write_lock_for_key(&unique).lock_owned().await;

        drop(FileMissHandler {
            file: Some(file),
            encoder: None,
            written: 0,
            final_path,
            temp_path: temp_path.clone(),
            hash: unique.clone(),
            key_str: unique,
            expires: crate::utils::time::now_timestamp() + 60,
            created_at: crate::utils::time::now_timestamp(),
            status: 200,
            headers: Vec::new(),
            compressed: false,
            error_status_allowed: false,
            shard_id: None,
            relative_path: "object".to_string(),
            root_path: None,
            previous_body_path: None,
            purge_generation: current_cache_purge_generation(),
            expected_body_len: None,
            head_request: false,
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            event_version: crate::metrics::storage::next_cache_meta_event_version(),
            disabled: false,
            committed: false,
            published: false,
            _purge_guard: acquire_cache_purge_read_guard().await,
            _write_guard: write_guard,
            _process_lock: None,
            _cache_write_permit: permit,
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!temp_path.exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn file_miss_handler_failed_publish_does_not_overwrite_existing_meta() {
        let unique = unique_test_suffix("failed-publish");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let temp_path = root.join("object.tmp");
        let final_path = root.join("object");
        tokio::fs::create_dir_all(&final_path).await.unwrap();
        let file = tokio::fs::File::create(&temp_path).await.unwrap();
        let permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::CacheWrite)
            .expect("cache write permit should be available");
        let write_guard = cache_write_lock_for_key(&unique).lock_owned().await;
        let hash = unique.clone();
        crate::metrics::storage::insert_cache_meta_for_test(
            hash.clone(),
            crate::metrics::storage::CacheMetaEntry {
                cache_key: unique.clone(),
                size: 5,
                expires: crate::utils::time::now_timestamp() + 60,
                access_time: crate::utils::time::now_timestamp(),
                access_count: 1,
                status: 200,
                headers: Vec::new(),
                compressed: false,
                ..Default::default()
            },
        );

        let mut handler = Box::new(FileMissHandler {
            file: Some(file),
            encoder: None,
            written: 0,
            final_path,
            temp_path: temp_path.clone(),
            hash: hash.clone(),
            key_str: unique,
            expires: crate::utils::time::now_timestamp() + 60,
            created_at: crate::utils::time::now_timestamp(),
            status: 200,
            headers: Vec::new(),
            compressed: false,
            error_status_allowed: false,
            shard_id: None,
            relative_path: "object".to_string(),
            root_path: None,
            previous_body_path: None,
            purge_generation: current_cache_purge_generation(),
            expected_body_len: None,
            head_request: false,
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
            event_version: crate::metrics::storage::next_cache_meta_event_version(),
            disabled: false,
            committed: false,
            published: false,
            _purge_guard: acquire_cache_purge_read_guard().await,
            _write_guard: write_guard,
            _process_lock: None,
            _cache_write_permit: permit,
        });
        handler
            .write_body(bytes::Bytes::from_static(b"loser-body"), false)
            .await
            .expect("write body");

        assert!(matches!(
            handler.finish().await.expect("cache failure is a no-op"),
            MissFinishType::Created(0)
        ));
        let meta = crate::metrics::storage::get_cache_meta_memory(&hash).expect("existing meta");
        assert_eq!(meta.size, 5);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!temp_path.exists());

        crate::metrics::storage::delete_cache_meta_for_test(&hash);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn memory_miss_handler_rejects_body_shorter_than_content_length() {
        let unique = unique_test_suffix("memory-short-body");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = HybridStorage::new(1024 * 1024, &root);
        let mut handler = memory_miss_handler_for_test(&storage, unique.clone(), 4).await;

        handler
            .write_body(bytes::Bytes::from_static(b"abc"), true)
            .await
            .expect("write body");
        assert!(matches!(
            handler.finish().await.expect("finish cache miss"),
            MissFinishType::Created(0)
        ));
        assert!(storage.l1.get(&unique).is_none());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn memory_miss_handler_rejects_body_longer_than_content_length() {
        let unique = unique_test_suffix("memory-long-body");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage = HybridStorage::new(1024 * 1024, &root);
        let mut handler = memory_miss_handler_for_test(&storage, unique.clone(), 4).await;

        handler
            .write_body(bytes::Bytes::from_static(b"abcde"), true)
            .await
            .expect("write body");
        assert!(matches!(
            handler.finish().await.expect("finish cache miss"),
            MissFinishType::Created(0)
        ));
        assert!(storage.l1.get(&unique).is_none());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn waiting_memory_miss_does_not_overwrite_first_fill() {
        let unique = unique_test_suffix("memory-double-check");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let storage: &'static HybridStorage =
            Box::leak(Box::new(HybridStorage::new(1024 * 1024, &root)));
        storage.policy_type.store(POLICY_MEMORY, Ordering::Release);

        let make_meta = || {
            let mut response_header = ResponseHeader::build(200, Some(1)).expect("response header");
            response_header
                .insert_header("content-length", "5")
                .expect("content length");
            let now = crate::utils::time::now_timestamp();
            CacheMeta::new(
                system_time_from_timestamp(now + 60),
                system_time_from_timestamp(now),
                0,
                0,
                response_header,
            )
        };

        let first_key = CacheKey::new("edge", unique.as_str(), "");
        let mut first = storage
            .memory_miss_handler(&first_key, &make_meta(), false)
            .await
            .expect("first memory miss handler");
        first
            .write_body(bytes::Bytes::from_static(b"first"), true)
            .await
            .expect("first body");

        let second_key = CacheKey::new("edge", unique.as_str(), "");
        let second = tokio::spawn(async move {
            storage
                .memory_miss_handler(&second_key, &make_meta(), false)
                .await
        });

        let first_result = first.finish().await.expect("finish first fill");
        assert!(matches!(first_result, MissFinishType::Created(5)));

        let mut second = tokio::time::timeout(std::time::Duration::from_secs(1), second)
            .await
            .expect("second miss handler should not remain blocked")
            .expect("second miss task")
            .expect("second memory miss handler");
        second
            .write_body(bytes::Bytes::from_static(b"second"), true)
            .await
            .expect("second body");
        assert!(matches!(
            second.finish().await.expect("finish second fill"),
            MissFinishType::Created(0)
        ));

        let entry = storage.l1.get(&unique).expect("first fill should remain");
        assert_eq!(entry.data.as_ref(), b"first");
        storage.l1.remove(&unique);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn file_miss_handler_rejects_body_shorter_than_content_length() {
        let unique = unique_test_suffix("file-short-body");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let (mut handler, temp_path, final_path) =
            file_miss_handler_for_test(&root, &unique, 4).await;

        handler
            .write_body(bytes::Bytes::from_static(b"abc"), true)
            .await
            .expect("write body");
        assert!(matches!(
            handler.finish().await.expect("finish cache miss"),
            MissFinishType::Created(0)
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!temp_path.exists());
        assert!(!final_path.exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn file_miss_handler_rejects_body_longer_than_content_length() {
        let unique = unique_test_suffix("file-long-body");
        let root = std::env::temp_dir().join(format!("cloud-node-rust-cache-test-{unique}"));
        let (mut handler, temp_path, final_path) =
            file_miss_handler_for_test(&root, &unique, 4).await;

        handler
            .write_body(bytes::Bytes::from_static(b"abcde"), true)
            .await
            .expect("write body");
        assert!(matches!(
            handler.finish().await.expect("finish cache miss"),
            MissFinishType::Created(0)
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!temp_path.exists());
        assert!(!final_path.exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn adaptive_bloom_scales_capacity() {
        let bloom = AdaptiveBloomFilter::new(8, 2);
        let (_, start_capacity, _, _) = bloom.stats();
        for i in 0..32 {
            bloom.insert(&format!("key-{i}"));
        }
        let (size, capacity, util, estimated_bytes) = bloom.stats();
        assert_eq!(size, 32);
        assert!(capacity > start_capacity);
        assert!(util > 0.0);
        assert!(estimated_bytes > 0);
        assert!(bloom.contains("key-0"));
        assert!(bloom.contains("key-31"));
    }

    #[test]
    fn negative_cache_capacity_tracks_bloom_size() {
        let unique = unique_test_suffix("cap-key");
        let before = negative_cache_capacity_limit();
        for i in 0..2_048 {
            bloom_insert(&format!("{unique}-{i}"));
        }
        let after = negative_cache_capacity_limit();
        assert!(after >= before);
        assert!(after <= NEGATIVE_CACHE_MAX_ENTRIES);
        assert!(after > 0);
    }

    #[test]
    fn negative_cache_expires_stale_entries() {
        let key = unique_test_suffix("neg-expire");
        let now = crate::utils::time::now_timestamp();
        NEGATIVE_CACHE.insert(key.clone(), now - 1);
        assert!(!negative_cache_check(&key, now));
        assert!(!NEGATIVE_CACHE.contains_key(&key));
    }

    #[test]
    fn negative_cache_refuses_insert_when_capacity_remains_full() {
        let now = crate::utils::time::now_timestamp();
        let prefix = format!("{}-", unique_test_suffix("neg-full"));
        for i in 0..3 {
            NEGATIVE_CACHE.insert(format!("{prefix}{i}"), now + NEGATIVE_CACHE_TTL_SECS);
        }

        let extra = format!("{prefix}extra");
        negative_cache_insert_with_capacity(&extra, now, 3);
        assert!(!NEGATIVE_CACHE.contains_key(&extra));

        NEGATIVE_CACHE.retain(|key, _| !key.starts_with(&prefix));
    }

    #[test]
    fn negative_cache_does_not_pollute_positive_bloom() {
        let now = crate::utils::time::now_timestamp();
        let unique = unique_test_suffix("neg-no-bloom");
        let key = (0..10_000)
            .map(|i| format!("{unique}-{i}"))
            .find(|key| !bloom_may_exist(key))
            .expect("test key should avoid existing Bloom positives");

        negative_cache_insert_with_capacity(&key, now, NEGATIVE_CACHE.len().saturating_add(1));

        assert!(!bloom_may_exist(&key));
        NEGATIVE_CACHE.remove(&key);
    }

    #[test]
    fn surrogate_index_capacity_is_bounded() {
        let capacity = surrogate_index_capacity();
        assert!(capacity <= SURROGATE_INDEX_MAX_TAGS_NORMAL);
        assert!(capacity >= SURROGATE_INDEX_MAX_TAGS_PRESSURE);
        assert!(meta_headers_contain_surrogate_tag(
            &[("Surrogate-Key".to_string(), "alpha beta".to_string())],
            "beta"
        ));
        assert!(!meta_headers_contain_surrogate_tag(
            &[("Surrogate-Key".to_string(), "alpha".to_string())],
            "beta"
        ));
        assert!(bloom_generation() >= 1);
    }

    #[test]
    fn cache_meta_hooks_warm_bloom_and_clear_negative_cache() {
        let _state_guard = CACHE_GLOBAL_STATE_LOCK.lock().expect("cache test lock");
        let key = unique_test_suffix("hook-key");
        let now = crate::utils::time::now_timestamp();
        negative_cache_insert(&key, now);
        let inserted = negative_cache_check(&key, now);

        let meta = crate::metrics::storage::CacheMetaEntry {
            cache_key: key.clone(),
            expires: now + 60,
            ..Default::default()
        };
        on_cache_meta_upsert(&meta);
        assert!(bloom_may_exist(&key));
        assert!(!negative_cache_check(&key, now));
        if inserted {
            assert!(
                negative_cache_check(&key, now)
                    || !crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high()
            );
        }
    }

    #[test]
    fn critical_reclaim_clears_l1_and_negative_cache() {
        let storage = &crate::cache_manager::CACHE.storage;
        let now = crate::utils::time::now_timestamp();
        let key = unique_test_suffix("reclaim-critical");
        storage.l1.put(
            &key,
            TinyUfoL1Entry {
                cache_key: key.clone(),
                data: bytes::Bytes::from_static(b"payload"),
                response_header: pingora_http::ResponseHeader::build(200, None).unwrap(),
                fresh_until: now + 60,
                created_at: now,
                stale_while_revalidate_secs: 0,
                stale_if_error_secs: 0,
                error_status_allowed: false,
                metadata_updated_at: now,
                cache_state_version: 0,
                purge_generation: current_cache_purge_generation(),
                metadata_required: false,
            },
            std::time::Duration::from_secs(60),
        );
        // The production admission path intentionally refuses new negative
        // entries during pressure. Seed the test entry directly so this test
        // exercises the critical reclaim operation itself.
        NEGATIVE_CACHE.insert(key.clone(), now + NEGATIVE_CACHE_TTL_SECS);
        let (count_before, _) = storage.l1.stats();
        assert!(count_before >= 1);

        let stats = super::reclaim_caches_critical();
        let (count_after, _) = storage.l1.stats();
        assert!(stats.l1_entries_removed >= 1 || count_after < count_before);
        assert!(!NEGATIVE_CACHE.contains_key(&key));
    }

    #[test]
    fn bloom_shrink_under_high_reclaim() {
        let bloom = AdaptiveBloomFilter::new(8, 1);
        for i in 0..32 {
            bloom.insert(&format!("layer-key-{i}"));
        }
        let removed = bloom.shrink_layers(1);
        let _ = removed;
    }
}
