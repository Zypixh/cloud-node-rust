use crate::memory_governor::{MEMORY_GOVERNOR, MemoryPressureLevel};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimStats {
    pub l1_entries_removed: usize,
    pub l1_bytes_freed_estimate: u64,
    pub bloom_layers_removed: u64,
    pub negative_cache_entries_removed: usize,
    pub geo_cache_entries_removed: usize,
    pub ua_cache_entries_removed: usize,
    pub tls_connectors_removed: usize,
    pub waf_regex_entries_removed: u64,
    /// Whole-tag sets dropped from the surrogate-key reverse index
    /// (Critical reclaim only).
    pub surrogate_index_tags_removed: usize,
    /// Process RSS sampled immediately before and after the reclaim pass.
    /// `after >= before` despite dropped caches means the allocator is
    /// retaining the freed pages instead of returning them to the OS.
    pub process_rss_before_bytes: u64,
    pub process_rss_after_bytes: u64,
}

impl ReclaimStats {
    pub fn total_entries_removed(&self) -> usize {
        self.l1_entries_removed
            .saturating_add(self.negative_cache_entries_removed)
            .saturating_add(self.geo_cache_entries_removed)
            .saturating_add(self.ua_cache_entries_removed)
            .saturating_add(self.tls_connectors_removed)
    }

    pub fn freed_bytes_estimate(&self) -> u64 {
        self.l1_bytes_freed_estimate
    }
}

static LAST_OBSERVED_PRESSURE: AtomicU8 = AtomicU8::new(MemoryPressureLevel::Normal as u8);
static LAST_RECLAIM_AT_MS: AtomicU64 = AtomicU64::new(0);

/// mimalloc v2 option: purge a thread's delayed purges when the thread
/// terminates. `libmimalloc-sys` extended only exports option constants up to
/// `mi_option_max_segment_reclaim` (21); this is enum slot 12 in
/// `mimalloc.h` (`mi_option_abandoned_page_purge`, default 0).
const MI_OPTION_ABANDONED_PAGE_PURGE: libmimalloc_sys::mi_option_t = 12;
/// Enum slot 26: allow a `free()` on a live thread to reclaim the abandoned
/// segment the block belongs to, instead of leaving the segment's committed
/// pages stranded on a dead heap. This is the dominant residency pattern in
/// this node — objects allocated on one runtime are routinely dropped on
/// another thread.
const MI_OPTION_ABANDONED_RECLAIM_ON_FREE: libmimalloc_sys::mi_option_t = 26;

/// Must run before worker threads spawn. Without these options, pages freed
/// on a dying thread's heap keep their delayed purges unexecuted and stay
/// committed until another thread slowly reclaims the abandoned segments
/// (capped at ~10% per attempt), which shows up as multi-ten-MiB RSS plateaus
/// after short-lived runtimes exit.
pub fn configure_allocator() {
    unsafe {
        libmimalloc_sys::mi_option_set(MI_OPTION_ABANDONED_PAGE_PURGE, 1);
        libmimalloc_sys::mi_option_set(MI_OPTION_ABANDONED_RECLAIM_ON_FREE, 1);
    }
}
static RECLAIM_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static RECLAIM_CLOCK_START: OnceLock<Instant> = OnceLock::new();
static LAST_RECLAIM_STATS: Mutex<Option<ReclaimStats>> = Mutex::new(None);

/// Most recent reclaim pass outcome, for runtime/node-status observability.
pub fn last_reclaim_stats() -> Option<ReclaimStats> {
    *LAST_RECLAIM_STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
// Highest pressure level observed since the monitor last drained it. Hot-path
// callers only bump this atomic and unpark the monitor; they never run reclaim
// work themselves.
static PENDING_RECLAIM_LEVEL: AtomicU8 = AtomicU8::new(MemoryPressureLevel::Normal as u8);
static RECLAIM_MONITOR_THREAD: OnceLock<std::thread::Thread> = OnceLock::new();

thread_local! {
    // Reclaiming cache state can update resident-memory accounting, which in
    // turn observes pressure again. Keep recursive notifications from
    // re-entering the same reclaim path on the current thread.
    static RECLAIM_IN_PROGRESS: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    /// Test-only panic injection: set on the current thread to make the next
    /// `reclaim_for_level` call panic inside the guarded region. Thread-local
    /// so parallel tests cannot consume each other's injection.
    static FORCE_RECLAIM_PANIC: Cell<bool> = const { Cell::new(false) };
}

const RECLAIM_COOLDOWN_MS: u64 = 5_000;
const ESCALATION_SAMPLES_REQUIRED: u8 = 2;
const RECOVERY_STABILITY_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimDecision {
    Hold,
    Trigger(MemoryPressureLevel),
}

/// Deterministic pressure hysteresis used by the runtime coordinator.
///
/// The clock is supplied by the caller so pressure transitions can be tested
/// without wall-clock sleeps. Reclaim work itself remains bounded by the
/// individual cache reclaimers.
#[derive(Clone, Copy, Debug)]
pub struct ReclaimCoordinator {
    observed: MemoryPressureLevel,
    escalation_level: MemoryPressureLevel,
    escalation_samples: u8,
    recovery_since_ms: Option<u64>,
    next_allowed_ms: u64,
    retry_backoff_ms: u64,
    /// Consecutive same-level re-triggers without the level recovering. When
    /// reclaim at the observed level keeps running but pressure persists, the
    /// sweep escalates one tier rather than repeating the same pass forever.
    repeat_triggers: u8,
}

impl Default for ReclaimCoordinator {
    fn default() -> Self {
        Self {
            observed: MemoryPressureLevel::Normal,
            escalation_level: MemoryPressureLevel::Normal,
            escalation_samples: 0,
            recovery_since_ms: None,
            next_allowed_ms: 0,
            retry_backoff_ms: RECLAIM_COOLDOWN_MS,
            repeat_triggers: 0,
        }
    }
}

impl ReclaimCoordinator {
    pub fn observed_level(&self) -> MemoryPressureLevel {
        self.observed
    }

    /// Repeated reclaim passes at the same level that fail to recover
    /// pressure escalate one tier after this many re-triggers.
    const REPEAT_TRIGGER_ESCALATION_THRESHOLD: u8 = 4;

    fn next_level(level: MemoryPressureLevel) -> MemoryPressureLevel {
        match level {
            MemoryPressureLevel::Normal => MemoryPressureLevel::Elevated,
            MemoryPressureLevel::Elevated => MemoryPressureLevel::High,
            MemoryPressureLevel::High => MemoryPressureLevel::Critical,
            MemoryPressureLevel::Critical => MemoryPressureLevel::Critical,
        }
    }

    pub fn observe(&mut self, level: MemoryPressureLevel, now_ms: u64) -> ReclaimDecision {
        if level > self.observed {
            self.recovery_since_ms = None;
            if self.escalation_level != level {
                self.escalation_level = level;
                self.escalation_samples = 0;
            }
            self.escalation_samples = self.escalation_samples.saturating_add(1);
            // Critical never waits for a second sample: it means the cgroup
            // is at/above its hard limit (or memory.events already recorded
            // an oom_kill), so every cycle of delay risks the OOM killer
            // firing first. The reclaim cooldown still applies — only the
            // confirmation sample is skipped.
            let confirmed = self.escalation_samples >= ESCALATION_SAMPLES_REQUIRED
                || level == MemoryPressureLevel::Critical;
            if confirmed && now_ms >= self.next_allowed_ms {
                self.observed = level;
                self.escalation_samples = 0;
                self.repeat_triggers = 0;
                return ReclaimDecision::Trigger(level);
            }
            return ReclaimDecision::Hold;
        }

        if level == self.observed
            && level >= MemoryPressureLevel::Elevated
            && self.next_allowed_ms != 0
            && now_ms >= self.next_allowed_ms
        {
            self.repeat_triggers = self.repeat_triggers.saturating_add(1);
            let trigger_level = if self.repeat_triggers
                >= Self::REPEAT_TRIGGER_ESCALATION_THRESHOLD
                && level < MemoryPressureLevel::Critical
            {
                self.repeat_triggers = 0;
                Self::next_level(level)
            } else {
                level
            };
            return ReclaimDecision::Trigger(trigger_level);
        }

        self.escalation_samples = 0;
        if level < self.observed {
            let since = *self.recovery_since_ms.get_or_insert(now_ms);
            if now_ms.saturating_sub(since) >= RECOVERY_STABILITY_MS {
                self.observed = level;
                self.escalation_level = level;
                self.recovery_since_ms = None;
                self.repeat_triggers = 0;
            }
        } else {
            self.recovery_since_ms = None;
        }
        ReclaimDecision::Hold
    }

    pub fn record_result(&mut self, now_ms: u64, stats: ReclaimStats) {
        let made_progress = stats.total_entries_removed() > 0 || stats.freed_bytes_estimate() > 0;
        if made_progress {
            self.retry_backoff_ms = RECLAIM_COOLDOWN_MS;
        } else {
            self.retry_backoff_ms =
                (self.retry_backoff_ms.saturating_mul(2)).clamp(RECLAIM_COOLDOWN_MS, 60_000);
        }
        self.next_allowed_ms = now_ms.saturating_add(self.retry_backoff_ms);
    }
}

static RECLAIM_COORDINATOR: OnceLock<Mutex<ReclaimCoordinator>> = OnceLock::new();

fn reclaim_coordinator() -> &'static Mutex<ReclaimCoordinator> {
    RECLAIM_COORDINATOR.get_or_init(|| Mutex::new(ReclaimCoordinator::default()))
}

fn monotonic_elapsed_ms() -> u64 {
    RECLAIM_CLOCK_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn level_from_u8(value: u8) -> MemoryPressureLevel {
    match value {
        1 => MemoryPressureLevel::Elevated,
        2 => MemoryPressureLevel::High,
        3 => MemoryPressureLevel::Critical,
        _ => MemoryPressureLevel::Normal,
    }
}

fn level_to_u8(level: MemoryPressureLevel) -> u8 {
    level as u8
}

pub fn current_observed_pressure() -> MemoryPressureLevel {
    level_from_u8(LAST_OBSERVED_PRESSURE.load(Ordering::Relaxed))
}

pub fn reclaim_for_level(level: MemoryPressureLevel) -> ReclaimStats {
    if RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.replace(true)) {
        return ReclaimStats::default();
    }
    // Clear the re-entrancy flag even if a reclaim step panics — otherwise a
    // single panicking path permanently disables reclaim on this thread.
    struct ReclaimInProgressReset;
    impl Drop for ReclaimInProgressReset {
        fn drop(&mut self) {
            // try_with: during TLS teardown (thread exit while unwinding) the
            // local may already be gone — a second panic here would abort.
            let _ = RECLAIM_IN_PROGRESS.try_with(|in_progress| in_progress.set(false));
        }
    }
    let _in_progress_reset = ReclaimInProgressReset;

    #[cfg(test)]
    if FORCE_RECLAIM_PANIC.with(|flag| flag.replace(false)) {
        panic!("forced reclaim panic for unwind-safety test");
    }

    let mut stats = ReclaimStats {
        process_rss_before_bytes: current_process_rss_bytes(),
        ..Default::default()
    };
    match level {
        MemoryPressureLevel::Normal => {}
        MemoryPressureLevel::Elevated => {
            let cache_stats = crate::cache_hybrid::reclaim_caches_elevated();
            stats.l1_entries_removed = cache_stats.l1_entries_removed;
            stats.l1_bytes_freed_estimate = cache_stats.l1_bytes_freed_estimate;
            stats.negative_cache_entries_removed = cache_stats.negative_cache_entries_removed;
            // Cheap purge only: Elevated must not pay a forced collect that
            // decommits this thread's live caches mid-request.
            trim_expired_heap_pages();
        }
        MemoryPressureLevel::High => {
            let cache_stats = crate::cache_hybrid::reclaim_caches_high();
            stats.l1_entries_removed = cache_stats.l1_entries_removed;
            stats.l1_bytes_freed_estimate = cache_stats.l1_bytes_freed_estimate;
            stats.bloom_layers_removed = cache_stats.bloom_layers_removed;
            stats.negative_cache_entries_removed = cache_stats.negative_cache_entries_removed;
            let geo = crate::metrics::analyzer::reclaim_geo_ua_caches(false);
            stats.geo_cache_entries_removed = geo.0;
            stats.ua_cache_entries_removed = geo.1;
            stats.tls_connectors_removed = crate::tcp_proxy::reclaim_tls_connector_cache(0.5);
            stats.waf_regex_entries_removed =
                crate::firewall::matcher::reclaim_waf_regex_caches(false)
                    .saturating_add(crate::bounded_regex_cache::reclaim_partial());
            crate::firewall::state::accelerate_block_map_gc();
            // High already rebuilt half of L1 — the freed side stays resident
            // without a forced collect on whichever thread ran this reclaim.
            trim_released_heap();
        }
        MemoryPressureLevel::Critical => {
            let cache_stats = crate::cache_hybrid::reclaim_caches_critical();
            stats.l1_entries_removed = cache_stats.l1_entries_removed;
            stats.l1_bytes_freed_estimate = cache_stats.l1_bytes_freed_estimate;
            stats.bloom_layers_removed = cache_stats.bloom_layers_removed;
            stats.negative_cache_entries_removed = cache_stats.negative_cache_entries_removed;
            stats.surrogate_index_tags_removed = cache_stats.surrogate_index_tags_removed;
            let geo = crate::metrics::analyzer::reclaim_geo_ua_caches(true);
            stats.geo_cache_entries_removed = geo.0;
            stats.ua_cache_entries_removed = geo.1;
            stats.tls_connectors_removed = crate::tcp_proxy::reclaim_tls_connector_cache(0.0);
            stats.waf_regex_entries_removed =
                crate::firewall::matcher::reclaim_waf_regex_caches(true);
            crate::firewall::state::accelerate_block_map_gc();
            crate::bounded_regex_cache::reclaim_all();
            trim_released_heap();
        }
    }

    stats.process_rss_after_bytes = current_process_rss_bytes();
    *LAST_RECLAIM_STATS
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(stats);
    tracing::info!(
        target: "memory_reclaim",
        level = level.as_str(),
        l1_removed = stats.l1_entries_removed,
        l1_bytes = stats.l1_bytes_freed_estimate,
        bloom_layers = stats.bloom_layers_removed,
        negative = stats.negative_cache_entries_removed,
        geo = stats.geo_cache_entries_removed,
        ua = stats.ua_cache_entries_removed,
        tls = stats.tls_connectors_removed,
        waf_regex = stats.waf_regex_entries_removed,
        surrogate_tags = stats.surrogate_index_tags_removed,
        rss_before = stats.process_rss_before_bytes,
        rss_after = stats.process_rss_after_bytes,
        "memory reclaim completed"
    );
    stats
}

pub fn request_reclaim(level: MemoryPressureLevel) -> Option<ReclaimStats> {
    if level < MemoryPressureLevel::Elevated
        || !RECLAIM_IN_FLIGHT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        return None;
    }
    let now = monotonic_elapsed_ms();
    let last = LAST_RECLAIM_AT_MS.load(Ordering::Acquire);
    // `last == 0` means "never reclaimed" — a bare `now - 0 < cooldown` would
    // wrongly suppress the first reclaim of a fresh process (e.g. a Critical
    // spike during startup config load) for up to RECLAIM_COOLDOWN_MS.
    if last != 0 && now.saturating_sub(last) < RECLAIM_COOLDOWN_MS {
        RECLAIM_IN_FLIGHT.store(false, Ordering::Release);
        return None;
    }
    // A panic inside reclaim must not wedge the in-flight flag — without this
    // guard every later reclaim request would silently return None and the
    // escalation machinery would be permanently disabled.
    struct InFlightReset;
    impl Drop for InFlightReset {
        fn drop(&mut self) {
            RECLAIM_IN_FLIGHT.store(false, Ordering::Release);
        }
    }
    let _reset = InFlightReset;
    // Contain unwind panics to this call (release builds abort before this
    // runs). Returning None lets the coordinator roll back so the consumed
    // trigger is re-observed on the next cycle instead of being lost, and the
    // monitor thread keeps driving future reclaims. The panic is still
    // reported by the default panic hook; we additionally log it as an error
    // so it cannot be mistaken for a normal cooldown skip.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reclaim_for_level(level)
    }));
    // Cooldown is measured from reclaim completion, not start — a slow pass
    // must not leave the window already expired when it finishes. `.max(1)`
    // keeps 0 reserved for "never reclaimed".
    LAST_RECLAIM_AT_MS.store(monotonic_elapsed_ms().max(1), Ordering::Release);
    match outcome {
        Ok(stats) => {
            drop(_reset);
            Some(stats)
        }
        Err(payload) => {
            tracing::error!(
                target: "memory_reclaim",
                level = level.as_str(),
                panic = panic_message(&*payload),
                "reclaim panicked; trigger preserved for retry"
            );
            None
        }
    }
}

/// Extract a human-readable message from a panic payload for logging.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        s
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.as_str()
    } else {
        "non-string panic payload"
    }
}

pub fn on_memory_pressure_observed(level: MemoryPressureLevel) {
    let now = monotonic_elapsed_ms();
    // A panic while holding this lock poisons it; the coordinator is a Copy
    // state machine whose partially-updated value is still valid input, so
    // recovering the guard keeps pressure observations flowing instead of
    // panicking every subsequent call on the monitor thread.
    let mut coordinator = reclaim_coordinator()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // The coordinator is Copy: if the trigger cannot be executed (cooldown or a
    // reclaim already in flight), roll the state machine back so the same
    // pressure level is re-observed and re-triggered later instead of being
    // consumed and lost.
    let before = *coordinator;
    let decision = coordinator.observe(level, now);
    if let ReclaimDecision::Trigger(trigger_level) = decision {
        match request_reclaim(trigger_level) {
            Some(stats) => coordinator.record_result(now, stats),
            None => {
                *coordinator = before;
            }
        }
    }
    drop(coordinator);
    LAST_OBSERVED_PRESSURE.store(level_to_u8(level), Ordering::Relaxed);
    crate::memory_shed::observe_pressure(level);
}

pub fn periodic_reclaim_check() {
    // The janitor task migrates across Tokio worker threads, so a periodic
    // non-forced collect rotates through the workers' mimalloc heaps over
    // time; `mi_collect` only purges the heap of the calling thread.
    unsafe {
        libmimalloc_sys::mi_collect(false);
    }
    let level = MEMORY_GOVERNOR.current_memory_pressure_level();
    on_memory_pressure_observed(level);
}

/// Record a hot-path pressure observation without doing reclaim work on the
/// caller's thread. The pending level is coalesced (max) and the dedicated
/// reclaim monitor is unparked once; repeated observations at the same or a
/// lower level cost a couple of relaxed atomic stores.
pub fn notify_pressure_async(level: MemoryPressureLevel) {
    let level_u8 = level_to_u8(level);
    loop {
        let current = PENDING_RECLAIM_LEVEL.load(Ordering::Acquire);
        if current >= level_u8 {
            return;
        }
        if PENDING_RECLAIM_LEVEL
            .compare_exchange(current, level_u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
    if let Some(thread) = RECLAIM_MONITOR_THREAD.get() {
        thread.unpark();
    }
}

fn drain_pending_pressure() -> MemoryPressureLevel {
    level_from_u8(PENDING_RECLAIM_LEVEL.swap(MemoryPressureLevel::Normal as u8, Ordering::AcqRel))
}

/// Return freed pages to the OS after dropping a large config generation.
/// The node allocates through mimalloc, so only `mi_collect` can release its
/// retained segments — glibc `malloc_trim` never reaches them. mimalloc
/// purges only the calling thread's heap, so callers on dedicated threads
/// free their own arenas while worker heaps rely on mimalloc's purge timers
/// and the rotating collect in `periodic_reclaim_check`.
pub fn trim_released_heap() {
    unsafe {
        libmimalloc_sys::mi_collect(true);
    }
}

/// Cheap non-forced collect: purge only pages whose retention has expired
/// (per `mi_option_purge_delay`) and retire frees other threads deferred to
/// this heap. Safe to call at repeated boundaries — unlike
/// `trim_released_heap`, it does not decommit the thread's live caches, so it
/// does not force the next allocation to re-fault fresh segments.
pub fn trim_expired_heap_pages() {
    unsafe {
        libmimalloc_sys::mi_collect(false);
    }
}

fn current_process_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:")
                && let Some(kib) = rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
            {
                return kib.saturating_mul(1024);
            }
        }
    }
    0
}

/// Ledger-vs-map reconciliation cadence. The charge/refund paths are
/// symmetric, so this safety net only needs to catch residual drift.
const LEDGER_RECONCILE_INTERVAL_MS: u64 = 300_000;
static LAST_LEDGER_RECONCILE_MS: AtomicU64 = AtomicU64::new(0);
static LEDGER_RECONCILE_STALE_OWNERS: AtomicU64 = AtomicU64::new(0);
static LEDGER_RECONCILE_BYTES_REFUNDED: AtomicU64 = AtomicU64::new(0);
static LEDGER_RECONCILE_PASSES: AtomicU64 = AtomicU64::new(0);

/// Cumulative owners refunded by periodic ledger reconciliation. Nonzero
/// means a removal path missed a refund — investigate rather than accept.
pub fn ledger_reconcile_stale_owners() -> u64 {
    LEDGER_RECONCILE_STALE_OWNERS.load(Ordering::Relaxed)
}

pub fn ledger_reconcile_bytes_refunded() -> u64 {
    LEDGER_RECONCILE_BYTES_REFUNDED.load(Ordering::Relaxed)
}

fn maybe_reconcile_resident_ledgers() {
    let now = monotonic_elapsed_ms();
    let last = LAST_LEDGER_RECONCILE_MS.load(Ordering::Relaxed);
    if now.saturating_sub(last) < LEDGER_RECONCILE_INTERVAL_MS {
        return;
    }
    // Skip the sweep under real pressure: it walks owner maps and probing it
    // mid-reclaim adds avoidable churn.
    if current_observed_pressure() > MemoryPressureLevel::Elevated {
        return;
    }
    LAST_LEDGER_RECONCILE_MS.store(now, Ordering::Relaxed);
    let stats = crate::cache_hybrid::reconcile_resident_ledgers();
    LEDGER_RECONCILE_PASSES.fetch_add(1, Ordering::Relaxed);
    LEDGER_RECONCILE_STALE_OWNERS
        .fetch_add(stats.stale_owners_removed as u64, Ordering::Relaxed);
    LEDGER_RECONCILE_BYTES_REFUNDED.fetch_add(stats.bytes_refunded, Ordering::Relaxed);
    if stats.stale_owners_removed > 0 || stats.truncated {
        tracing::warn!(
            target: "memory_reclaim",
            owners_scanned = stats.owners_scanned,
            stale_removed = stats.stale_owners_removed,
            bytes_refunded = stats.bytes_refunded,
            truncated = stats.truncated,
            "resident ledger reconciliation removed stale owner charges"
        );
    } else {
        tracing::debug!(
            target: "memory_reclaim",
            owners_scanned = stats.owners_scanned,
            "resident ledger reconciliation found no drift"
        );
    }
}

/// Re-entrant guard for `start_reclaim_monitor`: a second spawn would
/// silently succeed (RECLAIM_MONITOR_THREAD.set just fails after storing
/// nothing) and leave a duplicate monitor draining the same pending level.
static RECLAIM_MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

pub fn start_reclaim_monitor() {
    if RECLAIM_MONITOR_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let spawn_result = std::thread::Builder::new()
        .name("memory-reclaim".to_string())
        .spawn(|| {
            let _ = RECLAIM_MONITOR_THREAD.set(std::thread::current());
            loop {
                // Wake on an async pressure notification or every 5 seconds so
                // sustained pressure still re-escalates through the
                // coordinator's sample hysteresis and retry backoff.
                std::thread::park_timeout(Duration::from_secs(5));
                let pending = drain_pending_pressure();
                // In unwind builds a panic anywhere in this iteration
                // (reclaim, collect, reconcile, a poisoned lock) must not
                // kill the monitor: the pending-level slot and
                // RECLAIM_MONITOR_THREAD keep pointing at this thread, so its
                // death would silently disable every future reclaim while the
                // rest of the process looks healthy.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if pending >= MemoryPressureLevel::Elevated {
                        on_memory_pressure_observed(pending);
                    } else {
                        periodic_reclaim_check();
                    }
                    maybe_reconcile_resident_ledgers();
                }));
                if let Err(payload) = outcome {
                    tracing::error!(
                        target: "memory_reclaim",
                        panic = panic_message(&*payload),
                        "reclaim monitor iteration panicked; monitor stays alive"
                    );
                }
            }
        });
    if let Err(err) = spawn_result {
        tracing::warn!("failed to spawn memory reclaim monitor: {err}");
        // Spawn failed — allow a later call to retry instead of permanently
        // marking the monitor as started.
        RECLAIM_MONITOR_STARTED.store(false, Ordering::Release);
    }
    start_pressure_event_watcher();
}

static PRESSURE_EVENT_WAKEUPS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static LAST_EVENT_WAKE_MS: AtomicU64 = AtomicU64::new(0);

/// Kernel wakes can arrive in bursts under sustained stall; snapshot re-reads
/// are cheap but not free, so coalesce wakes closer than this into one.
#[cfg(target_os = "linux")]
const MIN_EVENT_WAKE_INTERVAL_MS: u64 = 250;

/// How many kernel pressure events have forced an early snapshot refresh.
/// Exposed for observability — a nonzero counter means the event path is
/// firing ahead of the 2s poll.
pub fn pressure_event_wakeups() -> u64 {
    PRESSURE_EVENT_WAKEUPS.load(Ordering::Relaxed)
}

#[cfg(target_os = "linux")]
fn on_pressure_event_wake(source: &'static str, floor: MemoryPressureLevel) {
    let now = monotonic_elapsed_ms();
    let last = LAST_EVENT_WAKE_MS.load(Ordering::Relaxed);
    // `last == 0` means "never woken" — monotonic elapsed starts near zero in
    // a fresh process, so a bare `now - 0 < interval` would eat the first
    // real event right after startup.
    if last != 0 && now.saturating_sub(last) < MIN_EVENT_WAKE_INTERVAL_MS {
        return;
    }
    LAST_EVENT_WAKE_MS.store(now.max(1), Ordering::Relaxed);
    PRESSURE_EVENT_WAKEUPS.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(target: "memory_reclaim", source, floor = floor.as_str(), "kernel memory pressure event");
    // Invalidate + re-read: `memory_snapshot()` recomputes the real pressure
    // level and notifies the reclaim coordinator itself. The kernel counter
    // floor only ADDS escalation the short-window average may still hide —
    // e.g. `oom_kill` incremented means the cgroup already hit its limit even
    // if the fresh snapshot briefly reads below thresholds.
    MEMORY_GOVERNOR.invalidate_snapshot_cache();
    let live = MEMORY_GOVERNOR
        .snapshot(MEMORY_GOVERNOR.pingora_worker_threads())
        .memory_pressure_level;
    if floor > live && floor >= MemoryPressureLevel::Elevated {
        notify_pressure_async(floor);
    }
}

/// Spawn the kernel pressure-event watcher. The 2-second snapshot poll stays
/// the detection floor; this adds event-driven wake-ups on top so reclaim
/// reacts to kernel-observed stalls/OOM counters between polls instead of
/// waiting out the TTL. Idempotent: repeated starts spawn only one thread.
#[cfg(target_os = "linux")]
pub fn start_pressure_event_watcher() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    pressure_events::spawn();
}

/// Non-Linux builds have no PSI/cgroup events to watch — the snapshot poll
/// already covers them.
#[cfg(not(target_os = "linux"))]
pub fn start_pressure_event_watcher() {}

#[cfg(target_os = "linux")]
mod pressure_events {
    use super::{Duration, on_pressure_event_wake};
    use crate::memory_governor::MemoryPressureLevel;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    /// `low`/`high`/`max`/`oom`/`oom_kill` counters from `memory.events`.
    /// `low` is intentionally not tracked: crossing memory.low downward is a
    /// normal fluctuation, not a pressure signal.
    #[derive(Clone, Copy, Default)]
    struct EventCounters {
        high: u64,
        max: u64,
        oom: u64,
        oom_kill: u64,
    }

    impl EventCounters {
        fn parse(content: &str) -> Self {
            let mut counters = EventCounters::default();
            for line in content.lines() {
                let mut parts = line.split_whitespace();
                let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                    continue;
                };
                let Ok(value) = value.parse::<u64>() else {
                    continue;
                };
                match key {
                    "high" => counters.high = value,
                    "max" => counters.max = value,
                    "oom" => counters.oom = value,
                    "oom_kill" => counters.oom_kill = value,
                    _ => {}
                }
            }
            counters
        }

        /// Pressure floor implied by counter increments since `prev`:
        /// max/oom/oom_kill mean the cgroup already hit its hard limit, and a
        /// `high` increment means the kernel throttled the cgroup at
        /// memory.high — both are facts the 2s average cannot override.
        fn pressure_floor_since(self, prev: Self) -> Option<MemoryPressureLevel> {
            if self.oom_kill > prev.oom_kill || self.oom > prev.oom || self.max > prev.max {
                Some(MemoryPressureLevel::Critical)
            } else if self.high > prev.high {
                Some(MemoryPressureLevel::High)
            } else {
                None
            }
        }
    }

    enum Source {
        Psi,
        CgroupEvents { last: EventCounters },
    }

    /// `some` = "at least one task stalled on memory": 200ms of stall in a 1s
    /// window is the same trigger family systemd-oomd watches before OOM.
    const PSI_TRIGGER: &[u8] = b"some 200000 1000000\n";

    pub fn spawn() {
        let spawn_result = std::thread::Builder::new()
            .name("memory-pressure-watch".to_string())
            .spawn(watch_loop);
        if let Err(err) = spawn_result {
            tracing::warn!("failed to spawn memory pressure watcher: {err}");
        }
    }

    /// PSI: register a stall trigger on /proc/pressure/memory. The write
    /// fails (EOPNOTSUPP/EINVAL) on kernels without CONFIG_PSI — skip then.
    fn open_psi_memory() -> Option<std::fs::File> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/proc/pressure/memory")
            .ok()?;
        file.write_all(PSI_TRIGGER).ok()?;
        Some(file)
    }

    /// cgroup v2 `memory.events` fires poll on low/high/max/oom/oom_kill
    /// counter changes. The memory controller is delegated per subtree, so
    /// the leaf cgroup (e.g. a systemd session scope) often lacks the file
    /// while an ancestor has it — climb toward the unified root and take the
    /// first readable one. v1-only nodes find none and are skipped.
    fn open_cgroup_v2_events() -> Option<std::fs::File> {
        let table = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let rel = table
            .lines()
            .find_map(|line| line.strip_prefix("0::"))?
            .trim();
        let root = std::path::PathBuf::from("/sys/fs/cgroup");
        let mut dir = root.join(rel.trim_start_matches('/'));
        loop {
            if let Ok(file) = std::fs::File::open(dir.join("memory.events")) {
                return Some(file);
            }
            if dir == root || !dir.pop() {
                return None;
            }
        }
    }

    fn read_contents(file: &std::fs::File) -> String {
        use std::os::unix::io::AsRawFd as _;
        unsafe {
            libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET);
        }
        let mut buf = [0u8; 512];
        let n = unsafe { libc::read(file.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return String::new();
        }
        String::from_utf8_lossy(&buf[..n as usize]).into_owned()
    }

    fn watch_loop() {
        let mut sources: Vec<(std::fs::File, Source)> = Vec::new();
        if let Some(file) = open_psi_memory() {
            sources.push((file, Source::Psi));
        }
        if let Some(file) = open_cgroup_v2_events() {
            // Baseline read: only increments observed after this point count.
            let last = EventCounters::parse(&read_contents(&file));
            sources.push((file, Source::CgroupEvents { last }));
        }
        if sources.is_empty() {
            tracing::debug!(
                target: "memory_reclaim",
                "no kernel memory pressure source; snapshot polling only"
            );
            return;
        }
        let mut fds: Vec<libc::pollfd> = sources
            .iter()
            .map(|(file, _)| libc::pollfd {
                fd: file.as_raw_fd(),
                events: libc::POLLPRI | libc::POLLERR,
                revents: 0,
            })
            .collect();
        loop {
            let rc =
                unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if rc < 0 {
                if std::io::Error::last_os_error().kind()
                    == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                // A broken fd should not spin — drop back to poll cadence.
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            for (pfd, (file, source)) in fds.iter_mut().zip(sources.iter_mut()) {
                if pfd.revents == 0 {
                    continue;
                }
                let content = read_contents(file);
                let (name, floor) = match source {
                    Source::Psi => ("psi", MemoryPressureLevel::Normal),
                    Source::CgroupEvents { last } => {
                        let counters = EventCounters::parse(&content);
                        let floor = counters
                            .pressure_floor_since(*last)
                            .unwrap_or(MemoryPressureLevel::Normal);
                        *last = counters;
                        ("memory.events", floor)
                    }
                };
                // Keep the watcher alive across a wake panic (e.g. a poisoned
                // lock inside the snapshot re-read): without this the thread
                // dies and all event-driven escalation is silently lost.
                if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                    || on_pressure_event_wake(name, floor),
                )) {
                    tracing::error!(
                        target: "memory_reclaim",
                        source = name,
                        panic = super::panic_message(&*payload),
                        "pressure event wake panicked; watcher stays alive"
                    );
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn memory_events_parses_counters_and_ignores_low() {
            let counters = EventCounters::parse(
                "low 0\nhigh 3\nmax 1\noom 0\noom_kill 2\noom_group_kill 0\n",
            );
            assert_eq!(counters.high, 3);
            assert_eq!(counters.max, 1);
            assert_eq!(counters.oom_kill, 2);
        }

        #[test]
        fn event_increments_floor_pressure_at_high_and_critical() {
            let base = EventCounters::parse("high 1\nmax 0\noom 0\noom_kill 0\n");
            assert_eq!(
                EventCounters::parse("high 2\nmax 0\noom 0\noom_kill 0\n")
                    .pressure_floor_since(base),
                Some(MemoryPressureLevel::High),
                "crossing memory.high must floor at High"
            );
            assert_eq!(
                EventCounters::parse("high 1\nmax 1\noom 0\noom_kill 0\n")
                    .pressure_floor_since(base),
                Some(MemoryPressureLevel::Critical),
                "hitting memory.max must floor at Critical"
            );
            assert_eq!(
                EventCounters::parse("high 1\nmax 0\noom 0\noom_kill 1\n")
                    .pressure_floor_since(base),
                Some(MemoryPressureLevel::Critical),
                "an oom_kill is always Critical regardless of average"
            );
            assert_eq!(
                EventCounters::parse("high 1\nmax 0\noom 0\noom_kill 0\n")
                    .pressure_floor_since(base),
                None,
                "no increment means no floor — snapshot decides alone"
            );
        }

        #[test]
        fn counter_reset_after_cgroup_recreate_produces_no_floor() {
            // If the cgroup is recreated (container restart, systemd scope
            // rotation) the counters restart at zero. A reset must read as
            // "no increment", never as a wraparound spike.
            let prev = EventCounters::parse("high 40\nmax 9\noom 7\noom_kill 5\n");
            let reset = EventCounters::parse("high 0\nmax 0\noom 0\noom_kill 0\n");
            assert_eq!(
                reset.pressure_floor_since(prev),
                None,
                "counter reset must not floor pressure"
            );
            let partial = EventCounters::parse("high 0\nmax 0\noom 8\noom_kill 0\n");
            assert_eq!(
                partial.pressure_floor_since(prev),
                Some(MemoryPressureLevel::Critical),
                "an increment on one counter still floors after others reset"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configure_allocator_enables_abandoned_page_purge() {
        configure_allocator();
        let value = unsafe { libmimalloc_sys::mi_option_get(MI_OPTION_ABANDONED_PAGE_PURGE) };
        assert_eq!(value, 1, "abandoned page purge option must be enabled");
        let reclaim =
            unsafe { libmimalloc_sys::mi_option_get(MI_OPTION_ABANDONED_RECLAIM_ON_FREE) };
        assert_eq!(reclaim, 1, "abandoned reclaim-on-free must be enabled");
    }

    #[test]
    fn elevated_reclaim_stats_default_fields_are_zero_when_normal_noop() {
        let stats = ReclaimStats::default();
        assert_eq!(stats.total_entries_removed(), 0);
        assert_eq!(stats.freed_bytes_estimate(), 0);
    }

    #[test]
    fn pressure_level_roundtrip_via_atomic_storage() {
        for level in [
            MemoryPressureLevel::Normal,
            MemoryPressureLevel::Elevated,
            MemoryPressureLevel::High,
            MemoryPressureLevel::Critical,
        ] {
            assert_eq!(level_from_u8(level_to_u8(level)), level);
        }
    }

    #[test]
    fn monotonic_elapsed_never_moves_backwards() {
        let first = monotonic_elapsed_ms();
        let second = monotonic_elapsed_ms();
        assert!(
            second >= first,
            "reclaim clock must be monotonic: first={first}, second={second}"
        );
    }

    #[test]
    fn pressure_requires_two_escalation_samples() {
        let mut coordinator = ReclaimCoordinator::default();
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 1),
            ReclaimDecision::Hold
        );
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 2),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
    }

    #[test]
    fn critical_pressure_triggers_on_first_sample() {
        let mut coordinator = ReclaimCoordinator::default();
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::Critical, 1),
            ReclaimDecision::Trigger(MemoryPressureLevel::Critical),
            "Critical must not wait for a second sample — the cgroup is already at its limit"
        );
        // Cooldown still applies: an immediate second Critical does not
        // stampede another reclaim while one is cooling down.
        let mut coordinator = ReclaimCoordinator {
            next_allowed_ms: 10_000,
            ..Default::default()
        };
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::Critical, 1),
            ReclaimDecision::Hold,
            "Critical still respects the reclaim cooldown"
        );
    }

    #[test]
    fn persistent_same_level_pressure_escalates_reclaim_one_tier() {
        let mut coordinator = ReclaimCoordinator::default();
        // Escalate to High (two samples), then keep observing High past each
        // allowed retry. The first three re-triggers sweep at High; the
        // fourth escalates the sweep to Critical because reclaim is not
        // recovering the level.
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 1),
            ReclaimDecision::Hold
        );
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 2),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
        let mut now = 10_000u64;
        for expected_retrigger in 1..=3u8 {
            coordinator.next_allowed_ms = now;
            assert_eq!(
                coordinator.observe(MemoryPressureLevel::High, now),
                ReclaimDecision::Trigger(MemoryPressureLevel::High),
                "retrigger {expected_retrigger} must stay at High"
            );
            now += 60_000;
        }
        coordinator.next_allowed_ms = now;
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, now),
            ReclaimDecision::Trigger(MemoryPressureLevel::Critical),
            "the fourth retrigger must escalate the sweep to Critical"
        );
        // After escalation the counter resets: next repeat is High again.
        now += 60_000;
        coordinator.next_allowed_ms = now;
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, now),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
    }

    #[test]
    fn recovery_resets_repeat_trigger_escalation() {
        let mut coordinator = ReclaimCoordinator::default();
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 1),
            ReclaimDecision::Hold
        );
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 2),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
        coordinator.next_allowed_ms = 10_000;
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 10_000),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
        // Recover after the stability window, then re-escalate: the repeat
        // counter must have reset so escalation takes four fresh retriggers.
        coordinator.observe(MemoryPressureLevel::Normal, 11_000);
        coordinator.observe(MemoryPressureLevel::Normal, 42_000);
        assert_eq!(coordinator.observed_level(), MemoryPressureLevel::Normal);
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 43_000),
            ReclaimDecision::Hold
        );
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 44_000),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
        assert_eq!(coordinator.repeat_triggers, 0);
    }

    #[test]
    fn pressure_downgrade_requires_thirty_seconds_of_stability() {
        let mut coordinator = ReclaimCoordinator::default();
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 1),
            ReclaimDecision::Hold
        );
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 2),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::Elevated, 30_001),
            ReclaimDecision::Hold
        );
        assert_eq!(coordinator.observed_level(), MemoryPressureLevel::High);
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::Elevated, 60_001),
            ReclaimDecision::Hold
        );
        assert_eq!(coordinator.observed_level(), MemoryPressureLevel::Elevated);
    }

    #[test]
    fn zero_progress_doubles_bounded_retry_backoff() {
        let mut coordinator = ReclaimCoordinator::default();
        coordinator.record_result(100, ReclaimStats::default());
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 5_000),
            ReclaimDecision::Hold
        );
        coordinator.record_result(100_000, ReclaimStats::default());
        coordinator.record_result(200_000, ReclaimStats::default());
        assert!(coordinator.next_allowed_ms <= 260_000);
    }

    #[test]
    fn sustained_pressure_retries_after_backoff_expires() {
        let mut coordinator = ReclaimCoordinator::default();
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 1),
            ReclaimDecision::Hold
        );
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 2),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
        coordinator.record_result(2, ReclaimStats::default());

        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 5_001),
            ReclaimDecision::Hold
        );
        assert_eq!(
            coordinator.observe(MemoryPressureLevel::High, 10_002),
            ReclaimDecision::Trigger(MemoryPressureLevel::High)
        );
    }

    #[test]
    fn trim_released_heap_calls_mimalloc_collect() {
        trim_released_heap();
        periodic_reclaim_check();
    }

    #[test]
    fn reclaim_records_process_rss_boundaries() {
        let stats = reclaim_for_level(MemoryPressureLevel::Normal);
        #[cfg(target_os = "linux")]
        assert!(stats.process_rss_before_bytes > 0 && stats.process_rss_after_bytes > 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(stats.process_rss_after_bytes, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pressure_event_wakes_are_coalesced_inside_the_min_interval() {
        let before = pressure_event_wakeups();
        on_pressure_event_wake("test-a", MemoryPressureLevel::Normal);
        assert_eq!(
            pressure_event_wakeups(),
            before + 1,
            "first wake must force a snapshot refresh"
        );
        on_pressure_event_wake("test-b", MemoryPressureLevel::Normal);
        assert_eq!(
            pressure_event_wakeups(),
            before + 1,
            "a second wake inside the coalescing window must be dropped"
        );
    }

    #[test]
    fn pressure_event_watcher_start_is_idempotent() {
        start_pressure_event_watcher();
        start_pressure_event_watcher();
    }

    #[test]
    fn reclaim_panic_resets_in_progress_flag() {
        // Force a panic inside the guarded region; the RAII reset must clear
        // the thread-local re-entrancy flag or this thread could never
        // reclaim again.
        FORCE_RECLAIM_PANIC.with(|flag| flag.set(true));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reclaim_for_level(MemoryPressureLevel::Critical);
        }));
        assert!(outcome.is_err(), "forced panic must propagate to the caller");
        RECLAIM_IN_PROGRESS.with(|flag| {
            assert!(
                !flag.get(),
                "RECLAIM_IN_PROGRESS must be cleared after a reclaim panic"
            );
        });
    }

    #[test]
    fn request_reclaim_panic_returns_none_and_resets_in_flight() {
        // This test doubles as the `last == 0` cooldown-bypass regression:
        // the thread-local injection is only consumed if the request passes
        // the cooldown gate, so "injection consumed" deterministically proves
        // a first-ever reclaim is not suppressed by the never-reclaimed state.
        for _ in 0..200 {
            LAST_RECLAIM_AT_MS.store(0, Ordering::Release);
            FORCE_RECLAIM_PANIC.with(|flag| flag.set(true));
            let stats = request_reclaim(MemoryPressureLevel::Critical);
            if stats.is_none() && FORCE_RECLAIM_PANIC.with(|flag| flag.get()) {
                // Rejected before the guarded region — a concurrent test
                // holds the in-flight flag. It releases on completion; retry.
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            assert!(
                stats.is_none(),
                "a panicking reclaim must report None so the coordinator rolls back"
            );
            break;
        }
        assert!(
            !FORCE_RECLAIM_PANIC.with(|flag| flag.get()),
            "reclaim must reach the guarded region despite `last == 0` (no startup suppression)"
        );
        RECLAIM_IN_PROGRESS.with(|flag| assert!(!flag.get()));
        // Wait for any concurrent reclaim to drain, then assert our panic did
        // not wedge the flag (a real wedge never clears).
        for _ in 0..200 {
            if !RECLAIM_IN_FLIGHT.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !RECLAIM_IN_FLIGHT.load(Ordering::Acquire),
            "RECLAIM_IN_FLIGHT must be cleared after a reclaim panic"
        );
    }
}
