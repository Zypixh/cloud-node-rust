//! Preemptive in-flight shed — the last lever before the OOM killer.
//!
//! Cooperative reclaim (`memory_reclaim`) shrinks caches and rejects new
//! admissions, but cannot touch work already in flight: a long download or a
//! lingering keepalive connection keeps its buffers until it finishes. When
//! observed pressure reaches `Critical` (cgroup at/above its hard limit),
//! waiting for in-flight work to drain on its own risks the OOM killer
//! firing first.
//!
//! Shed escalation, driven from `memory_reclaim::on_memory_pressure_observed`:
//!
//! - `High`     → keepalive suppression: every response is written with
//!   keepalive disabled, so idle connections drain at the next request
//!   boundary instead of holding buffers open.
//! - `Critical` → keepalive suppression **plus** a drain pass over
//!   `L4_CONNECTION_REGISTRY`: connections older than an age threshold are
//!   cancelled with `MemoryPressureShed`. Each consecutive Critical
//!   observation tightens the threshold down the ladder, so if RSS keeps
//!   rising the shed gets progressively more aggressive, ending at "all
//!   registered connections".
//!
//! New-connection admission already collapses toward its critical floor via
//! `pressure_adjusted_min_limit`; outright refusal is deliberately NOT added
//! here — a hard-refused connection produces no response at all, while shed
//! connections at least get their in-flight response finished (keepalive
//! tier) or a clean close (drain tier).
//!
//! De-escalation follows the same hysteresis as the reclaim coordinator:
//! once the *observed* level drops below `High`, shed flags clear and the
//! escalation ladder resets. Everything is atomic-flag based; the proxy hot
//! path costs one relaxed load per request when inactive.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::l4_connection_registry::{
    self, ConnectionCancelReason,
};
use crate::memory_governor::MemoryPressureLevel;

/// Consecutive-Critical drain ladder: each *confirmed* Critical step
/// drains connections older than the next rung. The final step (0)
/// cancels every registered connection — reached only after the gentler
/// tiers failed to stop RSS growth.
const DRAIN_AGE_LADDER_MS: [u64; 5] = [300_000, 120_000, 60_000, 30_000, 0];

/// Minimum wall-clock-free interval between ladder rungs. Repeated
/// observations of the same stale snapshot cannot advance the ladder —
/// only a *fresh* Critical sample at least this far after the last rung
/// may escalate.
const RUNG_MIN_INTERVAL_MS: u64 = 5_000;

/// Keepalive suppression is lifted only after the observed level has
/// stayed below High for this recovery window (mirrors the reclaim
/// coordinator's stability hysteresis).
const RECOVERY_STABILITY_MS: u64 = 30_000;

/// Keepalive suppression flag, read once per request on the proxy hot path.
static KEEPALIVE_SHED_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Ladder position: number of confirmed Critical rungs taken. Advances
/// only on time-separated fresh Critical observations.
static CRITICAL_STREAK: AtomicU64 = AtomicU64::new(0);

/// Monotonic ms of the last ladder advance (u64::MAX = none yet).
static LAST_RUNG_AT_MS: AtomicU64 = AtomicU64::new(u64::MAX);

/// Monotonic ms when the observed level first dropped below High
/// (u64::MAX = not recovering).
static RECOVERY_SINCE_MS: AtomicU64 = AtomicU64::new(u64::MAX);

/// Connections cancelled by shed passes, cumulative.
static SHED_DRAINED_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

/// Requests that ran with keepalive suppressed under shed, cumulative.
static SHED_KEEPALIVE_MARKED: AtomicU64 = AtomicU64::new(0);

/// Last drain pass's age threshold in ms (observability; `u64::MAX` = none).
static SHED_LAST_DRAIN_AGE_MS: AtomicU64 = AtomicU64::new(u64::MAX);

/// Hot-path read: should responses suppress keepalive right now?
/// One relaxed load; false is the overwhelmingly common answer.
#[inline]
pub fn shed_keepalive_active() -> bool {
    KEEPALIVE_SHED_ACTIVE.load(Ordering::Relaxed)
}

/// Metric hook: a response was written with keepalive suppressed.
#[inline]
pub fn note_keepalive_shed() {
    SHED_KEEPALIVE_MARKED.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ShedStats {
    pub keepalive_shed_active: bool,
    pub critical_streak: u64,
    pub drained_connections_total: u64,
    pub keepalive_marked_total: u64,
    pub last_drain_age_ms: Option<u64>,
}

pub fn shed_stats() -> ShedStats {
    let last_age = SHED_LAST_DRAIN_AGE_MS.load(Ordering::Relaxed);
    ShedStats {
        keepalive_shed_active: shed_keepalive_active(),
        critical_streak: CRITICAL_STREAK.load(Ordering::Relaxed),
        drained_connections_total: SHED_DRAINED_CONNECTIONS.load(Ordering::Relaxed),
        keepalive_marked_total: SHED_KEEPALIVE_MARKED.load(Ordering::Relaxed),
        last_drain_age_ms: (last_age != u64::MAX).then_some(last_age),
    }
}

/// Called from `memory_reclaim::on_memory_pressure_observed` with the raw
/// observed level on every pressure sample (periodic check, PSI watcher,
/// hot-path notifications). Cheap: sub-High levels cost two stores.
pub fn observe_pressure(level: MemoryPressureLevel) {
    observe_pressure_at(level, monotonic_now_ms());
}

/// Monotonic clock for the escalation timing — wall-clock jumps cannot
/// accelerate or stall the ladder.
fn monotonic_now_ms() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Time-driven core of `observe_pressure`. Split out so tests drive the
/// ladder without sleeping.
fn observe_pressure_at(level: MemoryPressureLevel, now_ms: u64) {
    match level {
        MemoryPressureLevel::High => {
            KEEPALIVE_SHED_ACTIVE.store(true, Ordering::Relaxed);
            CRITICAL_STREAK.store(0, Ordering::Relaxed);
            RECOVERY_SINCE_MS.store(u64::MAX, Ordering::Relaxed);
            // A High observation between Criticals is a new escalation
            // episode: the next Critical must run rung 0 immediately, not
            // be suppressed by the previous episode's interval gate.
            LAST_RUNG_AT_MS.store(u64::MAX, Ordering::Relaxed);
        }
        MemoryPressureLevel::Critical => {
            KEEPALIVE_SHED_ACTIVE.store(true, Ordering::Relaxed);
            RECOVERY_SINCE_MS.store(u64::MAX, Ordering::Relaxed);
            let last_rung = LAST_RUNG_AT_MS.load(Ordering::Relaxed);
            // First Critical of an episode always runs rung 0 (the mildest
            // drain); later rungs require a fresh sample separated by
            // RUNG_MIN_INTERVAL_MS so a repeated stale observation cannot
            // escalate on its own.
            if last_rung != u64::MAX
                && now_ms.saturating_sub(last_rung) < RUNG_MIN_INTERVAL_MS
            {
                return;
            }
            LAST_RUNG_AT_MS.store(now_ms, Ordering::Relaxed);
            let streak = CRITICAL_STREAK.fetch_add(1, Ordering::Relaxed);
            let rung = streak.min(DRAIN_AGE_LADDER_MS.len() as u64 - 1) as usize;
            let max_age_ms = DRAIN_AGE_LADDER_MS[rung];
            SHED_LAST_DRAIN_AGE_MS.store(max_age_ms, Ordering::Relaxed);
            let drained = l4_connection_registry::L4_CONNECTION_REGISTRY
                .drain_matching_with_reason(
                    |conn| conn.elapsed() >= Duration::from_millis(max_age_ms),
                    ConnectionCancelReason::MemoryPressureShed,
                );
            if drained > 0 {
                SHED_DRAINED_CONNECTIONS.fetch_add(drained as u64, Ordering::Relaxed);
                tracing::warn!(
                    target: "memory_shed",
                    drained,
                    max_age_ms,
                    streak = streak + 1,
                    "memory pressure critical: shed {} in-flight connection(s) older than {}ms",
                    drained,
                    max_age_ms
                );
            }
        }
        _ => {
            // Sub-High: start (or continue) the 30s recovery window.
            // Suppression lifts and the ladder resets only once the level
            // has held below High for the full window — a single quiet
            // sample mid-incident must not de-escalate.
            let since = match RECOVERY_SINCE_MS
                .compare_exchange(u64::MAX, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => now_ms,
                Err(existing) => existing,
            };
            if now_ms.saturating_sub(since) >= RECOVERY_STABILITY_MS {
                KEEPALIVE_SHED_ACTIVE.store(false, Ordering::Relaxed);
                CRITICAL_STREAK.store(0, Ordering::Relaxed);
                LAST_RUNG_AT_MS.store(u64::MAX, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l4_connection_registry::{self, L4ConnectionProtocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last)), 41000 + last as u16)
    }

    #[test]
    fn high_pressure_suppresses_keepalive_without_draining() {
        let _serial = l4_connection_registry::REGISTRY_TEST_LOCK.lock().unwrap();
        observe_pressure_at(MemoryPressureLevel::Normal, 1_000_000); // clear residual state
        let guard = l4_connection_registry::register(addr(1), L4ConnectionProtocol::Http1);
        let mut rx = guard.cancel_receiver();

        observe_pressure_at(MemoryPressureLevel::High, 1_000_100);
        assert!(shed_keepalive_active());
        assert_eq!(
            *rx.borrow_and_update(),
            ConnectionCancelReason::None,
            "High must not cancel in-flight connections"
        );
        // Sub-High within the recovery window keeps suppression active;
        // only a stable 30s below High lifts it.
        observe_pressure_at(MemoryPressureLevel::Normal, 1_001_000);
        assert!(shed_keepalive_active());
        observe_pressure_at(MemoryPressureLevel::Normal, 1_031_000);
        assert!(!shed_keepalive_active());
        drop(guard);
    }

    #[test]
    fn critical_drains_oldest_first_then_escalates() {
        let _serial = l4_connection_registry::REGISTRY_TEST_LOCK.lock().unwrap();
        observe_pressure_at(MemoryPressureLevel::Normal, 2_000_000); // clear residual state
        // The ladder's first rung (300s) spares every test connection, so the
        // first Critical observation drains nothing.
        let g1 = l4_connection_registry::register(addr(2), L4ConnectionProtocol::Http1);
        let mut rx1 = g1.cancel_receiver();

        observe_pressure_at(MemoryPressureLevel::Critical, 2_000_100);
        assert_eq!(
            *rx1.borrow_and_update(),
            ConnectionCancelReason::None,
            "first Critical rung must spare young connections"
        );

        // Rapid repeats inside RUNG_MIN_INTERVAL_MS must NOT advance the
        // ladder — re-reading the same stale snapshot cannot escalate.
        for i in 1..10u64 {
            observe_pressure_at(MemoryPressureLevel::Critical, 2_000_100 + i * 400);
        }
        assert_eq!(
            *rx1.borrow_and_update(),
            ConnectionCancelReason::None,
            "stale-sample repeats must not advance the drain ladder"
        );

        // Drive the streak to the final rung with time-separated fresh
        // samples (age 0 = cancel all). Steps 2..5 still have positive
        // thresholds that spare fresh conns.
        for step in 1..=4u64 {
            observe_pressure_at(
                MemoryPressureLevel::Critical,
                2_000_100 + 4_000 + step * RUNG_MIN_INTERVAL_MS,
            );
        }
        assert_eq!(
            *rx1.borrow_and_update(),
            ConnectionCancelReason::MemoryPressureShed,
            "final rung must cancel every registered connection"
        );
        drop(g1);
        observe_pressure_at(MemoryPressureLevel::Normal, 2_100_000);
    }

    #[test]
    fn deescalation_resets_ladder() {
        let _serial = l4_connection_registry::REGISTRY_TEST_LOCK.lock().unwrap();
        observe_pressure_at(MemoryPressureLevel::Normal, 3_000_000); // clear residual state
        let g = l4_connection_registry::register(addr(3), L4ConnectionProtocol::Http2);
        let mut rx = g.cancel_receiver();

        observe_pressure_at(MemoryPressureLevel::Critical, 3_000_100);
        observe_pressure_at(MemoryPressureLevel::Critical, 3_005_200);
        observe_pressure_at(MemoryPressureLevel::Normal, 3_006_000);
        // Inside the recovery window suppression still holds.
        assert!(shed_keepalive_active());
        observe_pressure_at(MemoryPressureLevel::Normal, 3_036_000);
        assert!(!shed_keepalive_active());

        // Back to Critical restarts at the top of the ladder — young
        // connections are spared again.
        observe_pressure_at(MemoryPressureLevel::Critical, 3_040_000);
        assert_eq!(*rx.borrow_and_update(), ConnectionCancelReason::None);
        drop(g);
        observe_pressure_at(MemoryPressureLevel::Normal, 3_100_000);
    }

    #[test]
    fn stats_reflect_activity() {
        let _serial = l4_connection_registry::REGISTRY_TEST_LOCK.lock().unwrap();
        observe_pressure_at(MemoryPressureLevel::Normal, 4_000_000); // clear residual state
        observe_pressure_at(MemoryPressureLevel::High, 4_000_100);
        note_keepalive_shed();
        let stats = shed_stats();
        assert!(stats.keepalive_shed_active);
        assert!(stats.keepalive_marked_total >= 1);
        // First sub-High sample opens the recovery window; the next
        // sample ≥30s later lifts suppression.
        observe_pressure_at(MemoryPressureLevel::Normal, 4_001_000);
        observe_pressure_at(MemoryPressureLevel::Normal, 4_032_000);
        assert!(!shed_stats().keepalive_shed_active);
    }
}
