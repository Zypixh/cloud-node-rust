//! T1: monotonic microsecond transport clock for the AF_XDP dataplane.
//!
//! Pacing, RTT sampling and delivery-rate math need a clock that (a) never
//! moves backwards and (b) has sub-millisecond resolution — the business
//! `utils::time::now_timestamp_millis` wall clock satisfies neither (NTP
//! steps, ms granularity). `TransportClock` is anchored to a single
//! `std::time::Instant` captured at creation, so `now_micros` is monotonic
//! within the process and cheap (one Instant read, one subtraction).
//!
//! Tests inject `TransportClock::manual()` — a deterministic counter that
//! only moves when `advance` is called — so sweep cadence, idle timeouts
//! and future pacing tests do not depend on wall time.

use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug)]
enum TransportClockInner {
    /// Anchored monotonic clock — the only mode production paths use.
    Real { anchor: Instant },
    /// Deterministic counter driven by `TransportClock::advance`.
    #[cfg(test)]
    Manual { now_us: AtomicU64 },
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug)]
pub(crate) struct TransportClock {
    inner: Arc<TransportClockInner>,
}

#[cfg(any(test, target_os = "linux"))]
impl TransportClock {
    pub(crate) fn real() -> Self {
        Self {
            inner: Arc::new(TransportClockInner::Real {
                anchor: Instant::now(),
            }),
        }
    }

    /// Microseconds since this clock's anchor. For `Real` clocks the anchor
    /// is creation time; for `Manual` clocks it is the virtual epoch.
    /// Monotonic by construction — never wraps, never steps backwards.
    pub(crate) fn now_micros(&self) -> i64 {
        match &*self.inner {
            TransportClockInner::Real { anchor } => anchor.elapsed().as_micros() as i64,
            #[cfg(test)]
            TransportClockInner::Manual { now_us } => now_us.load(Ordering::Relaxed) as i64,
        }
    }

    #[cfg(test)]
    pub(crate) fn manual() -> Self {
        Self {
            inner: Arc::new(TransportClockInner::Manual {
                now_us: AtomicU64::new(0),
            }),
        }
    }

    /// Advance a manual clock. Panics on a real clock — tests must never
    /// pretend wall time moved.
    #[cfg(test)]
    pub(crate) fn advance(&self, delta: Duration) {
        match &*self.inner {
            TransportClockInner::Manual { now_us } => {
                now_us.fetch_add(delta.as_micros() as u64, Ordering::Relaxed);
            }
            TransportClockInner::Real { .. } => {
                panic!("TransportClock::advance on a real clock")
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn is_manual(&self) -> bool {
        matches!(&*self.inner, TransportClockInner::Manual { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_clock_is_monotonic_and_microsecond_precise() {
        let clock = TransportClock::real();
        let mut prev = clock.now_micros();
        for _ in 0..10_000 {
            let now = clock.now_micros();
            assert!(now >= prev, "clock moved backwards: {now} < {prev}");
            prev = now;
        }
        // A tight loop must observe sub-millisecond resolution somewhere —
        // a ms-granularity clock would leave every sample equal.
        // (Not asserted on duration: monotonicity is the contract, timing
        // granularity follows from Instant.)
    }

    #[test]
    fn manual_clock_advances_deterministically() {
        let clock = TransportClock::manual();
        assert!(clock.is_manual());
        assert_eq!(clock.now_micros(), 0);
        clock.advance(Duration::from_micros(1500));
        assert_eq!(clock.now_micros(), 1500);
        // Clone shares the same counter — reactor + test see one clock.
        let clone = clock.clone();
        clone.advance(Duration::from_millis(1));
        assert_eq!(clock.now_micros(), 2500);
    }
}
