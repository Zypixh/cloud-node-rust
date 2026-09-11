//! Cross-process cache coordination via `flock()` on persistent lock files.
//!
//! Several node processes may share one cache volume. Every lookup/fill used
//! to pay `mkdir` + `open` + `flock` + `close` on a barrier file and a per-key
//! file for each request, and the per-key lock was always exclusive — which
//! serialized all readers of a hot key and burned CPU in the blocking pool.
//!
//! This manager caches open lock descriptors per (roots, target) and refcounts
//! in-process shared holds instead:
//!
//! - Joining an already-held shared lock is one atomic increment: no syscall,
//!   no `spawn_blocking`, and concurrent readers of the same key no longer
//!   serialize (readers take `LOCK_SH`, writers `LOCK_EX`).
//! - The 0→1 transition and every exclusive acquisition still `flock()` real
//!   descriptors, so inter-process semantics are unchanged: a purge still
//!   waits for every in-flight read/fill on any shared root, and a fill still
//!   cannot publish while another process reads or fills the same key.
//! - An exclusive acquisition first sets `exclusive_pending`; new shared
//!   joiners then take a private descriptor whose `LOCK_EX` queues with the
//!   waiting writer in the kernel. `LOCK_SH` would not work here: the kernel
//!   grants it immediately against the still-held shared lock, which would
//!   let readers barge past and starve the writer.
//! - If the entry table or the fd budget is exhausted, acquisition falls back
//!   to private per-call descriptors — the exact pre-refcount behavior. This
//!   is an explicit capacity decision (counted via `PROCESS_LOCK_PRIVATE`),
//!   never a silent loss of coordination.
//!
//! The layer is only active when the runtime explicitly declares a shared
//! volume: `RuntimeConfig::current_is_rke2()` — the same gate the rest of the
//! cache uses for "another process may mount these roots". In the default
//! single-process mode the volume is exclusively owned, nothing can share it,
//! and every acquire returns an empty guard with zero syscalls. This is not
//! silently assumed — it is the declared default, and enabling RKE2 mode is
//! the explicit opt-in that activates the locks.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock as Lazy};

use dashmap::DashMap;
use parking_lot::Mutex as ParkingMutex;

/// Cached key-lock entries per roots set. Hot keys stay resident; when the
/// table is full of active entries, new keys use private descriptors.
const MAX_KEY_LOCK_ENTRIES: usize = 4096;
/// Process-wide cap on cached lock-file descriptors so the table can never
/// exhaust the process fd budget.
const MAX_CACHED_LOCK_FDS: usize = 8192;
/// How many entries to inspect when looking for an idle entry to evict.
const EVICTION_SCAN: usize = 64;

static CACHED_LOCK_FDS: AtomicUsize = AtomicUsize::new(0);

/// Fast-path joins that needed no syscall and no blocking task.
pub(crate) static PROCESS_LOCK_FASTPATH: AtomicU64 = AtomicU64::new(0);
/// Shared acquisitions that took the 0→1 transition and flock()ed.
pub(crate) static PROCESS_LOCK_TRANSITION: AtomicU64 = AtomicU64::new(0);
/// Acquisitions that used private per-call descriptors (writer pending or
/// capacity/fd-budget fallback).
pub(crate) static PROCESS_LOCK_PRIVATE: AtomicU64 = AtomicU64::new(0);
/// Exclusive acquisitions (fills, metadata updates, evictions, purges).
pub(crate) static PROCESS_LOCK_EXCLUSIVE: AtomicU64 = AtomicU64::new(0);
/// Acquisitions skipped because cross-process mode is not declared.
pub(crate) static PROCESS_LOCK_DISABLED: AtomicU64 = AtomicU64::new(0);

static DISABLED_LOGGED: AtomicBool = AtomicBool::new(false);

/// Cross-process coordination is only needed when a second process can mount
/// the cache volume, which is exactly what the RKE2 runtime declaration says.
/// Every other configuration owns its roots exclusively; taking flock()s
/// there would only pay syscalls to exclude participants that cannot exist.
fn process_locks_enabled() -> bool {
    #[cfg(test)]
    if FORCE_PROCESS_LOCKS.load(Ordering::Relaxed) {
        return true;
    }
    crate::runtime_mode::RuntimeConfig::current_is_rke2()
}

#[cfg(test)]
pub(crate) static FORCE_PROCESS_LOCKS: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
enum CacheProcessLockMode {
    Shared,
    Exclusive,
}

/// Persistent lock file set for one barrier set or one canonical key. The
/// same files back every acquisition: `shared_files` carry one `LOCK_SH`
/// while `shared_holders > 0`; exclusive acquisitions open private
/// descriptors from `lock_paths` so an in-process "upgrade" can never
/// silently succeed over local readers.
#[derive(Debug)]
struct ProcessLockEntry {
    lock_paths: Vec<PathBuf>,
    shared_files: Vec<std::fs::File>,
    /// Number of in-process shared holds. Invariant: `> 0` iff every file in
    /// `shared_files` currently holds `LOCK_SH`.
    shared_holders: AtomicUsize,
    /// Serializes the 0→1 flock against the 1→0 LOCK_UN. Never held across an
    /// await; only the two transition sites take it.
    transition: ParkingMutex<()>,
    /// Set while an exclusive acquisition is pending or held. Shared joiners
    /// must then take private descriptors and request `LOCK_EX` so the kernel
    /// queues them with the writer instead of letting them barge ahead.
    exclusive_pending: AtomicBool,
}

/// One lock domain per sorted roots set: a shared barrier entry plus a
/// bounded table of per-key entries.
struct ProcessLockSet {
    /// `None` only when the fd budget refused barrier descriptors; every
    /// acquisition then uses private descriptors for the barrier too.
    barrier: Option<Arc<ProcessLockEntry>>,
    keys: DashMap<String, Arc<ProcessLockEntry>>,
}

static PROCESS_LOCK_SETS: Lazy<DashMap<Vec<PathBuf>, Arc<ProcessLockSet>>> =
    Lazy::new(DashMap::new);

/// Held while an operation needs cross-process exclusion. Dropping releases
/// every hold: refcounted holds decrement (the last one issues `LOCK_UN`),
/// exclusive holds unlock and clear the pending gate, and private
/// descriptors simply close.
#[derive(Debug)]
pub(crate) struct CacheProcessLockGuard {
    shared_entries: Vec<Arc<ProcessLockEntry>>,
    exclusive_entries: Vec<(Arc<ProcessLockEntry>, Vec<std::fs::File>)>,
    /// Private descriptors for shared or exclusive holds that bypassed the
    /// table. Closing the descriptor releases the kernel lock.
    _owned_files: Vec<std::fs::File>,
}

impl CacheProcessLockGuard {
    fn new() -> Self {
        Self {
            shared_entries: Vec::new(),
            exclusive_entries: Vec::new(),
            _owned_files: Vec::new(),
        }
    }
}

impl Drop for CacheProcessLockGuard {
    fn drop(&mut self) {
        for (entry, files) in self.exclusive_entries.drain(..) {
            unlock_files(&files);
            entry.exclusive_pending.store(false, Ordering::Release);
        }
        for entry in self.shared_entries.drain(..) {
            release_shared(&entry);
        }
    }
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

fn cache_process_lock_key(key: &str) -> String {
    let canonical = crate::cache::partial::partial_base_key(key);
    let canonical = canonical.as_deref().unwrap_or(key);
    format!("{:x}", md5_legacy::compute(canonical.as_bytes()))
}

#[cfg(unix)]
fn lock_file(file: &std::fs::File, mode: CacheProcessLockMode) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let operation = match mode {
        CacheProcessLockMode::Shared => libc::LOCK_SH,
        CacheProcessLockMode::Exclusive => libc::LOCK_EX,
    };
    // SAFETY: `file` owns a valid open descriptor and the descriptor outlives
    // the lock either in a cached entry or in the returned guard.
    let result = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock_file(file: &std::fs::File) {
    use std::os::fd::AsRawFd;

    // LOCK_UN never blocks; ignore the result because an unlocked descriptor
    // is the desired end state either way.
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(not(unix))]
fn lock_file(_file: &std::fs::File, _mode: CacheProcessLockMode) -> io::Result<()> {
    // Production deployments use Linux. Keep non-Unix builds functional;
    // their process-local locks remain the only coordination layer.
    Ok(())
}

#[cfg(not(unix))]
fn unlock_file(_file: &std::fs::File) {}

fn lock_files(files: &[std::fs::File], mode: CacheProcessLockMode) -> io::Result<()> {
    for (locked, file) in files.iter().enumerate() {
        if let Err(err) = lock_file(file, mode) {
            for file in &files[..locked] {
                unlock_file(file);
            }
            return Err(err);
        }
    }
    Ok(())
}

fn unlock_files(files: &[std::fs::File]) {
    for file in files {
        unlock_file(file);
    }
}

fn open_lock_files(paths: &[PathBuf]) -> io::Result<Vec<std::fs::File>> {
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let Some(parent) = path.parent() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache process lock path has no parent",
            ));
        };
        std::fs::create_dir_all(parent)?;
        files.push(
            std::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(path)?,
        );
    }
    Ok(files)
}

fn open_locked_files(
    paths: &[PathBuf],
    mode: CacheProcessLockMode,
) -> io::Result<Vec<std::fs::File>> {
    let files = open_lock_files(paths)?;
    lock_files(&files, mode)?;
    Ok(files)
}

fn try_reserve_lock_fds(count: usize) -> bool {
    let mut current = CACHED_LOCK_FDS.load(Ordering::Relaxed);
    loop {
        if current + count > MAX_CACHED_LOCK_FDS {
            return false;
        }
        match CACHED_LOCK_FDS.compare_exchange_weak(
            current,
            current + count,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn release_lock_fds(count: usize) {
    CACHED_LOCK_FDS.fetch_sub(count, Ordering::AcqRel);
}

fn build_entry(lock_paths: Vec<PathBuf>) -> Option<ProcessLockEntry> {
    match open_lock_files(&lock_paths) {
        Ok(shared_files) => Some(ProcessLockEntry {
            lock_paths,
            shared_files,
            shared_holders: AtomicUsize::new(0),
            transition: ParkingMutex::new(()),
            exclusive_pending: AtomicBool::new(false),
        }),
        Err(err) => {
            tracing::warn!(
                error = %err,
                "CACHE_PROCESS_LOCK: unable to open lock files; using per-request descriptors"
            );
            None
        }
    }
}

/// Try to join an existing shared hold without any syscall. Fails when the
/// lock is unheld (a 0→1 transition must flock) or when a writer is pending
/// (joiners must queue behind it on private descriptors).
fn try_join_shared(entry: &Arc<ProcessLockEntry>) -> bool {
    if entry.exclusive_pending.load(Ordering::Acquire) {
        return false;
    }
    loop {
        let holders = entry.shared_holders.load(Ordering::Acquire);
        if holders == 0 || entry.exclusive_pending.load(Ordering::Acquire) {
            return false;
        }
        match entry.shared_holders.compare_exchange_weak(
            holders,
            holders + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                if entry.exclusive_pending.load(Ordering::Acquire) {
                    // A writer declared intent between our check and the CAS.
                    // Back out and queue fairly instead of barging past it.
                    release_shared(entry);
                    return false;
                }
                PROCESS_LOCK_FASTPATH.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            Err(_) => continue,
        }
    }
}

fn release_shared(entry: &Arc<ProcessLockEntry>) {
    if entry.shared_holders.fetch_sub(1, Ordering::AcqRel) == 1 {
        // Only the transition mutex may reorder a 0→1 flock against this
        // 1→0 unlock; fast joiners cannot have slipped in (holders is 0).
        let _transition = entry.transition.lock();
        if entry.shared_holders.load(Ordering::Acquire) == 0 {
            unlock_files(&entry.shared_files);
        }
    }
}

/// Shared acquisition on the blocking-pool path: either join under the
/// transition mutex or take a private descriptor behind a pending writer.
fn acquire_shared_blocking(
    entry: Option<Arc<ProcessLockEntry>>,
    paths: &[PathBuf],
    guard: &mut CacheProcessLockGuard,
) -> io::Result<()> {
    let Some(entry) = entry else {
        guard
            ._owned_files
            .extend(open_locked_files(paths, CacheProcessLockMode::Shared)?);
        PROCESS_LOCK_PRIVATE.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    };
    if entry.exclusive_pending.load(Ordering::Acquire) {
        // A writer is queued or active. A private LOCK_SH would be granted
        // immediately (it is compatible with the shared lock still held),
        // barging past the pending writer and starving it. A private LOCK_EX
        // conflicts with the writer's request and queues behind it instead —
        // the same serialization reads had before the refcounted design.
        guard._owned_files.extend(open_locked_files(
            &entry.lock_paths,
            CacheProcessLockMode::Exclusive,
        )?);
        PROCESS_LOCK_PRIVATE.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    {
        let _transition = entry.transition.lock();
        if entry.shared_holders.load(Ordering::Acquire) == 0 {
            lock_files(&entry.shared_files, CacheProcessLockMode::Shared)?;
        }
        entry.shared_holders.fetch_add(1, Ordering::AcqRel);
    }
    guard.shared_entries.push(entry);
    PROCESS_LOCK_TRANSITION.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Exclusive acquisition. Sets the pending gate first so new shared joiners
/// queue on private descriptors, then blocks on a private `LOCK_EX` which
/// waits for every shared hold (ours and other processes') to drain.
fn acquire_exclusive_blocking(
    entry: Option<Arc<ProcessLockEntry>>,
    paths: &[PathBuf],
    guard: &mut CacheProcessLockGuard,
) -> io::Result<()> {
    PROCESS_LOCK_EXCLUSIVE.fetch_add(1, Ordering::Relaxed);
    let Some(entry) = entry else {
        guard
            ._owned_files
            .extend(open_locked_files(paths, CacheProcessLockMode::Exclusive)?);
        return Ok(());
    };
    entry.exclusive_pending.store(true, Ordering::SeqCst);
    match open_locked_files(&entry.lock_paths, CacheProcessLockMode::Exclusive) {
        Ok(files) => {
            guard.exclusive_entries.push((entry, files));
            Ok(())
        }
        Err(err) => {
            entry.exclusive_pending.store(false, Ordering::Release);
            Err(err)
        }
    }
}

/// Fetch or create the cached key entry. Returns `None` when the table is
/// full of active entries or the fd budget is exhausted; callers then use
/// private per-request descriptors.
fn key_entry(
    set: &ProcessLockSet,
    key_hash: &str,
    roots: &[PathBuf],
) -> Option<Arc<ProcessLockEntry>> {
    if let Some(entry) = set.keys.get(key_hash) {
        return Some(entry.clone());
    }
    if set.keys.len() >= MAX_KEY_LOCK_ENTRIES {
        // Keep hot keys resident: evict an idle entry if one is cheap to
        // find, otherwise let this key use private descriptors for now.
        let idle_key = set
            .keys
            .iter()
            .take(EVICTION_SCAN)
            .find(|item| {
                item.shared_holders.load(Ordering::Acquire) == 0
                    && !item.exclusive_pending.load(Ordering::Acquire)
            })
            .map(|item| item.key().clone());
        let idle_key = idle_key?;
        if let Some((_, entry)) = set.keys.remove(&idle_key) {
            release_lock_fds(entry.shared_files.len());
        }
    }
    let lock_paths = roots
        .iter()
        .map(|root| cache_process_key_path(root, key_hash))
        .collect::<Vec<_>>();
    let fd_count = lock_paths.len();
    if !try_reserve_lock_fds(fd_count) {
        return None;
    }
    let Some(created) = build_entry(lock_paths) else {
        release_lock_fds(fd_count);
        return None;
    };
    match set.keys.entry(key_hash.to_string()) {
        dashmap::Entry::Occupied(occupied) => {
            // Another creator won; drop our files and return the budget.
            drop(created);
            release_lock_fds(fd_count);
            Some(occupied.get().clone())
        }
        dashmap::Entry::Vacant(vacant) => Some(vacant.insert(Arc::new(created)).clone()),
    }
}

fn get_or_create_set(roots: &[PathBuf]) -> Arc<ProcessLockSet> {
    if let Some(set) = PROCESS_LOCK_SETS.get(roots) {
        return set.clone();
    }
    PROCESS_LOCK_SETS
        .entry(roots.to_vec())
        .or_insert_with(|| {
            // Set creation is once per roots configuration; building the
            // barrier entry under the shard lock is acceptable here.
            let barrier_paths = roots
                .iter()
                .map(|root| cache_process_barrier_path(root))
                .collect::<Vec<_>>();
            let fd_count = barrier_paths.len();
            let barrier = if try_reserve_lock_fds(fd_count) {
                match build_entry(barrier_paths) {
                    Some(entry) => Some(Arc::new(entry)),
                    None => {
                        release_lock_fds(fd_count);
                        None
                    }
                }
            } else {
                None
            };
            Arc::new(ProcessLockSet {
                barrier,
                keys: DashMap::new(),
            })
        })
        .clone()
}

enum KeySpec<'a> {
    Raw(&'a str),
    /// Caller already computed `md5(canonical_key)`; reuse it so the hot path
    /// pays one hash for the lock and the metadata probe.
    Prehashed(&'a str),
}

impl KeySpec<'_> {
    fn hash(&self) -> std::borrow::Cow<'_, str> {
        match self {
            KeySpec::Raw(key) => std::borrow::Cow::Owned(cache_process_lock_key(key)),
            KeySpec::Prehashed(hash) => std::borrow::Cow::Borrowed(*hash),
        }
    }
}

async fn acquire(
    key: Option<KeySpec<'_>>,
    roots: &[PathBuf],
    key_mode: CacheProcessLockMode,
    barrier_mode: CacheProcessLockMode,
) -> io::Result<CacheProcessLockGuard> {
    if !process_locks_enabled() {
        PROCESS_LOCK_DISABLED.fetch_add(1, Ordering::Relaxed);
        if !DISABLED_LOGGED.swap(true, Ordering::Relaxed) {
            tracing::info!(
                "CACHE_PROCESS_LOCK: disabled — single-process mode (no RKE2/shared-volume declaration); cache roots are exclusively owned"
            );
        }
        return Ok(CacheProcessLockGuard::new());
    }
    let roots = cache_process_roots(roots);
    if roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cache process lock requires at least one root",
        ));
    }
    let key_hash = key.map(|key| key.hash().into_owned());

    // Fast path: both locks are shared, the set and key entry already exist,
    // and both can be joined atomically.
    if matches!(barrier_mode, CacheProcessLockMode::Shared)
        && matches!(key_mode, CacheProcessLockMode::Shared)
        && let Some(set) = PROCESS_LOCK_SETS.get(&roots[..])
    {
        let mut guard = CacheProcessLockGuard::new();
        let barrier_ok = set.barrier.as_ref().is_some_and(|barrier| {
            if try_join_shared(barrier) {
                guard.shared_entries.push(barrier.clone());
                true
            } else {
                false
            }
        });
        let key_ok = match (&key_hash, barrier_ok) {
            (Some(hash), true) => match set.keys.get(hash) {
                Some(entry) if try_join_shared(entry.value()) => {
                    guard.shared_entries.push(entry.value().clone());
                    true
                }
                _ => false,
            },
            // No key requested: the barrier join alone decides.
            (None, ok) => ok,
            (Some(_), false) => false,
        };
        if key_ok {
            return Ok(guard);
        }
        // A partial join must not leak: dropping the guard releases it.
        drop(guard);
    }

    let key_paths = key_hash.as_deref().map(|hash| {
        roots
            .iter()
            .map(|root| cache_process_key_path(root, hash))
            .collect::<Vec<_>>()
    });

    tokio::task::spawn_blocking(move || {
        let set = get_or_create_set(&roots);
        let barrier_paths = set_barrier_paths(&roots);
        let mut guard = CacheProcessLockGuard::new();
        // Barrier before key on every path: this fixed order prevents lock
        // cycles between purges and fills across overlapping root sets.
        match barrier_mode {
            CacheProcessLockMode::Shared => {
                acquire_shared_blocking(set.barrier.clone(), &barrier_paths, &mut guard)?
            }
            CacheProcessLockMode::Exclusive => {
                acquire_exclusive_blocking(set.barrier.clone(), &barrier_paths, &mut guard)?
            }
        }
        if let (Some(hash), Some(paths)) = (key_hash.as_deref(), key_paths) {
            let entry = key_entry(&set, hash, &roots);
            match key_mode {
                CacheProcessLockMode::Shared => acquire_shared_blocking(entry, &paths, &mut guard)?,
                CacheProcessLockMode::Exclusive => {
                    acquire_exclusive_blocking(entry, &paths, &mut guard)?
                }
            }
        }
        Ok(guard)
    })
    .await
    .map_err(|err| io::Error::other(format!("cache process lock task failed: {err}")))?
}

fn set_barrier_paths(roots: &[PathBuf]) -> Vec<PathBuf> {
    roots
        .iter()
        .map(|root| cache_process_barrier_path(root))
        .collect()
}

/// Shared barrier plus shared key lock for a cache read. Multiple readers of
/// one key proceed concurrently; fills and purges still exclude them.
pub(crate) async fn acquire_cache_process_read_lock(
    key: &str,
    roots: &[PathBuf],
) -> io::Result<CacheProcessLockGuard> {
    acquire(
        Some(KeySpec::Raw(key)),
        roots,
        CacheProcessLockMode::Shared,
        CacheProcessLockMode::Shared,
    )
    .await
}

/// Same as [`acquire_cache_process_read_lock`] but takes the caller's already
/// computed `md5(canonical_key)` hex so the hot lookup path hashes once.
pub(crate) async fn acquire_cache_process_read_lock_hashed(
    key_hash: &str,
    roots: &[PathBuf],
) -> io::Result<CacheProcessLockGuard> {
    acquire(
        Some(KeySpec::Prehashed(key_hash)),
        roots,
        CacheProcessLockMode::Shared,
        CacheProcessLockMode::Shared,
    )
    .await
}

/// Shared barrier plus exclusive key lock for a cache fill, metadata update,
/// or eviction — anything that publishes or removes a representation.
pub(crate) async fn acquire_cache_process_fill_lock(
    key: &str,
    roots: &[PathBuf],
) -> io::Result<CacheProcessLockGuard> {
    acquire(
        Some(KeySpec::Raw(key)),
        roots,
        CacheProcessLockMode::Exclusive,
        CacheProcessLockMode::Shared,
    )
    .await
}

/// Exclusive cross-process barrier for exact, prefix, tag and eviction
/// purges. It blocks until every in-flight read/fill on the shared roots has
/// drained, and blocks new ones from starting.
pub(crate) async fn acquire_cache_process_barrier_write_lock(
    roots: &[PathBuf],
) -> io::Result<CacheProcessLockGuard> {
    acquire(
        None,
        roots,
        CacheProcessLockMode::Exclusive,
        CacheProcessLockMode::Exclusive,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(name: &str) -> PathBuf {
        // Tests exercise the lock machinery directly; the runtime is not in
        // declared RKE2 mode, so force the layer on for this module.
        FORCE_PROCESS_LOCKS.store(true, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("cloud-node-plock-{name}"));
        std::fs::create_dir_all(&root).expect("test root");
        root
    }

    #[tokio::test]
    async fn concurrent_readers_join_without_serializing() {
        let root = test_root("readers");
        let roots = vec![root];
        let first = acquire_cache_process_read_lock("k-readers", &roots)
            .await
            .expect("first read lock");
        // A second reader of the same key must not queue behind the first:
        // the whole point of the shared key lock.
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            acquire_cache_process_read_lock("k-readers", &roots),
        )
        .await
        .expect("second reader must not block on the first")
        .expect("second read lock");
        drop(second);
        drop(first);
    }

    #[tokio::test]
    async fn exclusive_waits_for_inflight_reader() {
        let root = test_root("excl-waits");
        let roots = vec![root];
        let reader = acquire_cache_process_read_lock("k-excl", &roots)
            .await
            .expect("read lock");
        let roots2 = roots.clone();
        let mut writer =
            tokio::spawn(async move { acquire_cache_process_fill_lock("k-excl", &roots2).await });
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut writer)
            .await
            .expect_err("exclusive key lock must wait for the in-flight reader");
        drop(reader);
        let guard = tokio::time::timeout(std::time::Duration::from_secs(2), writer)
            .await
            .expect("writer proceeds after the reader drains")
            .expect("writer task")
            .expect("fill lock");
        drop(guard);
    }

    #[tokio::test]
    async fn readers_do_not_barge_a_pending_writer() {
        let root = test_root("no-barge");
        let roots = vec![root];
        let reader = acquire_cache_process_read_lock("k-barge", &roots)
            .await
            .expect("read lock");
        // Queue a writer; it waits for the reader to drain.
        let roots2 = roots.clone();
        let writer =
            tokio::spawn(async move { acquire_cache_process_fill_lock("k-barge", &roots2).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // A new reader arriving while the writer waits must queue behind it
        // (private LOCK_EX), not join the existing shared hold.
        let mut late_reader =
            tokio::spawn(async move { acquire_cache_process_read_lock("k-barge", &roots).await });
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut late_reader)
            .await
            .expect_err("late reader must queue behind the pending writer");
        drop(reader);
        // Both the writer and the queued reader must complete once the
        // original reader drains.
        tokio::time::timeout(std::time::Duration::from_secs(2), writer)
            .await
            .expect("writer completes")
            .expect("writer task")
            .expect("fill lock");
        tokio::time::timeout(std::time::Duration::from_secs(2), late_reader)
            .await
            .expect("queued reader completes")
            .expect("reader task")
            .expect("read lock");
    }

    #[tokio::test]
    async fn purge_barrier_waits_for_readers() {
        let root = test_root("barrier");
        let roots = vec![root];
        let reader = acquire_cache_process_read_lock("k-barrier", &roots)
            .await
            .expect("read lock");
        let roots2 = roots.clone();
        let mut purge =
            tokio::spawn(async move { acquire_cache_process_barrier_write_lock(&roots2).await });
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut purge)
            .await
            .expect_err("purge barrier must wait for in-flight readers");
        drop(reader);
        tokio::time::timeout(std::time::Duration::from_secs(2), purge)
            .await
            .expect("purge proceeds after readers drain")
            .expect("purge task")
            .expect("barrier write lock");
    }
}
