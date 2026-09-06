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
    pub metric_rows_flushed: usize,
}

impl ReclaimStats {
    pub fn total_entries_removed(&self) -> usize {
        self.l1_entries_removed
            .saturating_add(self.negative_cache_entries_removed)
            .saturating_add(self.geo_cache_entries_removed)
            .saturating_add(self.ua_cache_entries_removed)
            .saturating_add(self.tls_connectors_removed)
            .saturating_add(self.metric_rows_flushed)
    }

    pub fn freed_bytes_estimate(&self) -> u64 {
        self.l1_bytes_freed_estimate
    }
}

static LAST_OBSERVED_PRESSURE: AtomicU8 = AtomicU8::new(MemoryPressureLevel::Normal as u8);
static LAST_RECLAIM_AT_MS: AtomicU64 = AtomicU64::new(0);
static RECLAIM_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static RECLAIM_CLOCK_START: OnceLock<Instant> = OnceLock::new();
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
        }
    }
}

impl ReclaimCoordinator {
    pub fn observed_level(&self) -> MemoryPressureLevel {
        self.observed
    }

    pub fn observe(&mut self, level: MemoryPressureLevel, now_ms: u64) -> ReclaimDecision {
        if level > self.observed {
            self.recovery_since_ms = None;
            if self.escalation_level != level {
                self.escalation_level = level;
                self.escalation_samples = 0;
            }
            self.escalation_samples = self.escalation_samples.saturating_add(1);
            if self.escalation_samples >= ESCALATION_SAMPLES_REQUIRED
                && now_ms >= self.next_allowed_ms
            {
                self.observed = level;
                self.escalation_samples = 0;
                return ReclaimDecision::Trigger(level);
            }
            return ReclaimDecision::Hold;
        }

        if level == self.observed
            && level >= MemoryPressureLevel::Elevated
            && self.next_allowed_ms != 0
            && now_ms >= self.next_allowed_ms
        {
            return ReclaimDecision::Trigger(level);
        }

        self.escalation_samples = 0;
        if level < self.observed {
            let since = *self.recovery_since_ms.get_or_insert(now_ms);
            if now_ms.saturating_sub(since) >= RECOVERY_STABILITY_MS {
                self.observed = level;
                self.escalation_level = level;
                self.recovery_since_ms = None;
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

    let mut stats = ReclaimStats::default();
    match level {
        MemoryPressureLevel::Normal => {}
        MemoryPressureLevel::Elevated => {
            let cache_stats = crate::cache_hybrid::reclaim_caches_elevated();
            stats.l1_entries_removed = cache_stats.l1_entries_removed;
            stats.l1_bytes_freed_estimate = cache_stats.l1_bytes_freed_estimate;
            stats.negative_cache_entries_removed = cache_stats.negative_cache_entries_removed;
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
                crate::firewall::matcher::reclaim_waf_regex_caches(false);
            crate::firewall::state::accelerate_block_map_gc();
        }
        MemoryPressureLevel::Critical => {
            let cache_stats = crate::cache_hybrid::reclaim_caches_critical();
            stats.l1_entries_removed = cache_stats.l1_entries_removed;
            stats.l1_bytes_freed_estimate = cache_stats.l1_bytes_freed_estimate;
            stats.bloom_layers_removed = cache_stats.bloom_layers_removed;
            stats.negative_cache_entries_removed = cache_stats.negative_cache_entries_removed;
            let geo = crate::metrics::analyzer::reclaim_geo_ua_caches(true);
            stats.geo_cache_entries_removed = geo.0;
            stats.ua_cache_entries_removed = geo.1;
            stats.tls_connectors_removed = crate::tcp_proxy::reclaim_tls_connector_cache(0.0);
            stats.waf_regex_entries_removed =
                crate::firewall::matcher::reclaim_waf_regex_caches(true);
            crate::firewall::state::accelerate_block_map_gc();
            crate::bounded_regex_cache::reclaim_all();
        }
    }

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
        metrics = stats.metric_rows_flushed,
        "memory reclaim completed"
    );
    RECLAIM_IN_PROGRESS.with(|in_progress| in_progress.set(false));
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
    if now.saturating_sub(last) < RECLAIM_COOLDOWN_MS {
        RECLAIM_IN_FLIGHT.store(false, Ordering::Release);
        return None;
    }
    let result = reclaim_for_level(level);
    LAST_RECLAIM_AT_MS.store(now, Ordering::Release);
    RECLAIM_IN_FLIGHT.store(false, Ordering::Release);
    Some(result)
}

pub fn on_memory_pressure_observed(level: MemoryPressureLevel) {
    let now = monotonic_elapsed_ms();
    let mut coordinator = reclaim_coordinator()
        .lock()
        .expect("reclaim coordinator lock poisoned");
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
}

pub fn periodic_reclaim_check() {
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
/// No-op on non-Linux targets; glibc `malloc_trim` is what the node ships on.
pub fn trim_released_heap() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::malloc_trim(0);
    }
}

pub fn start_reclaim_monitor() {
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
                if pending >= MemoryPressureLevel::Elevated {
                    on_memory_pressure_observed(pending);
                } else {
                    periodic_reclaim_check();
                }
            }
        });
    if let Err(err) = spawn_result {
        tracing::warn!("failed to spawn memory reclaim monitor: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
