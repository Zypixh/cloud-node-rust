//! Cache purge barrier with sharded reader counters.
//!
//! The previous implementation used a single `tokio::sync::RwLock` read
//! acquisition per request. Every acquire is a CAS on one cache line, so at
//! high QPS all worker threads serialize on that line even though readers
//! never contend logically. This barrier instead stripes reader counts over
//! per-shard atomics; a writer waits for every shard to drain to zero.
//!
//! Ordering notes:
//! - Reader: SeqCst increment, then SeqCst load of `writer_active`. If the
//!   flag is clear, the increment is ordered before any subsequent writer's
//!   shard scan in the SeqCst total order, so the writer must observe it.
//! - Writer: SeqCst store of `writer_active`, then SeqCst loads of every
//!   shard. New readers arriving after the flag set see it and wait instead
//!   of barging ahead of the pending writer.
//! - Async: readers that find a writer pending subscribe to the epoch watch
//!   channel before re-checking the flag, so no wake-up can be lost.
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{Mutex, MutexGuard, watch};

const PURGE_BARRIER_SHARDS: usize = 32;

#[repr(align(64))]
struct Shard(AtomicU64);

pub(crate) struct PurgeBarrier {
    shards: [Shard; PURGE_BARRIER_SHARDS],
    writer_active: AtomicBool,
    /// Serializes writers; a write guard holds this for the whole critical
    /// section so two purges cannot interleave.
    writer_lock: Mutex<()>,
    /// Bumped every time a writer releases the barrier; readers blocked on a
    /// pending writer wait on this.
    epoch: watch::Sender<u64>,
    next_shard: AtomicU64,
}

pub(crate) struct PurgeReadGuard {
    shard: &'static Shard,
}

impl Drop for PurgeReadGuard {
    fn drop(&mut self) {
        self.shard.0.fetch_sub(1, Ordering::Release);
    }
}

pub(crate) struct PurgeWriteGuard {
    // Field order matters: `flag` is cleared and the epoch is bumped in Drop
    // *before* the writer mutex releases the next purge.
    barrier: &'static PurgeBarrier,
    _writers: MutexGuard<'static, ()>,
}

impl Drop for PurgeWriteGuard {
    fn drop(&mut self) {
        self.barrier.writer_active.store(false, Ordering::SeqCst);
        self.barrier.epoch.send_modify(|epoch| *epoch += 1);
    }
}

impl PurgeBarrier {
    fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Shard(AtomicU64::new(0))),
            writer_active: AtomicBool::new(false),
            writer_lock: Mutex::const_new(()),
            epoch: watch::Sender::new(0),
            next_shard: AtomicU64::new(0),
        }
    }

    fn shard_index(&'static self) -> usize {
        // One atomic add per thread, cached in TLS afterwards.
        thread_local! {
            static SHARD_INDEX: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
        }
        SHARD_INDEX.with(|index| {
            let cached = index.get();
            if cached != usize::MAX {
                return cached;
            }
            let assigned =
                self.next_shard.fetch_add(1, Ordering::Relaxed) as usize % PURGE_BARRIER_SHARDS;
            index.set(assigned);
            assigned
        })
    }

    /// Try to enter the read side without waiting; used by the opportunistic
    /// L2->L1 promotion path where blocking would invert lock order.
    fn try_read(&'static self) -> Option<PurgeReadGuard> {
        if self.writer_active.load(Ordering::SeqCst) {
            return None;
        }
        let shard = &self.shards[self.shard_index()];
        shard.0.fetch_add(1, Ordering::SeqCst);
        if self.writer_active.load(Ordering::SeqCst) {
            shard.0.fetch_sub(1, Ordering::Release);
            return None;
        }
        Some(PurgeReadGuard { shard })
    }

    async fn read(&'static self) -> PurgeReadGuard {
        loop {
            if let Some(guard) = self.try_read() {
                return guard;
            }
            // A writer is active (or starting). Subscribe first so the epoch
            // bump cannot slip between the flag check and the wait.
            let mut epoch_rx = self.epoch.subscribe();
            if !self.writer_active.load(Ordering::SeqCst) {
                continue;
            }
            let _ = epoch_rx.changed().await;
        }
    }

    async fn write(&'static self) -> PurgeWriteGuard {
        let writers = self.writer_lock.lock().await;
        self.writer_active.store(true, Ordering::SeqCst);
        // Reader critical sections are microseconds; yield to the scheduler
        // rather than block the worker thread while they drain.
        for shard in &self.shards {
            while shard.0.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        }
        PurgeWriteGuard {
            barrier: self,
            _writers: writers,
        }
    }
}

static PURGE_BARRIER: LazyLock<PurgeBarrier> = LazyLock::new(PurgeBarrier::new);

pub(crate) async fn acquire_cache_purge_read_guard() -> PurgeReadGuard {
    PURGE_BARRIER.read().await
}

pub(crate) async fn acquire_cache_purge_write_guard() -> PurgeWriteGuard {
    PURGE_BARRIER.write().await
}

pub(crate) fn try_acquire_cache_purge_read_guard() -> Option<PurgeReadGuard> {
    PURGE_BARRIER.try_read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writer_waits_for_active_reader() {
        let read_guard = acquire_cache_purge_read_guard().await;
        let write_task = tokio::spawn(acquire_cache_purge_write_guard());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!write_task.is_finished());
        drop(read_guard);
        let _write_guard = write_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readers_do_not_barge_a_pending_writer() {
        let read_guard = acquire_cache_purge_read_guard().await;
        let write_task = tokio::spawn(acquire_cache_purge_write_guard());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // The writer is pending; a new reader must not be granted.
        assert!(try_acquire_cache_purge_read_guard().is_none());
        drop(read_guard);
        let _write_guard = write_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readers_proceed_after_writer_releases() {
        let write_guard = acquire_cache_purge_write_guard().await;
        let read_task = tokio::spawn(acquire_cache_purge_read_guard());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!read_task.is_finished());
        drop(write_guard);
        let _read_guard = read_task.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_readers_do_not_starve_writer() {
        let _write_guard = acquire_cache_purge_write_guard().await;
        drop(_write_guard);
        let mut readers = Vec::new();
        for _ in 0..16 {
            readers.push(acquire_cache_purge_read_guard().await);
        }
        drop(readers);
        let _write_guard = acquire_cache_purge_write_guard().await;
    }
}
