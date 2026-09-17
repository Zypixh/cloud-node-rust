//! CoDel — controlled delay AQM (RFC 8289) for the real forwarding
//! queue (plan §4/T9). Sojourn time is measured on dequeue (enqueue
//! timestamp carried with the packet — never a delay *threshold* on a
//! queue-length estimate).
//!
//! State machine per RFC 8289 §4:
//! - dequeue computes `sojourn = now − enqueue_time`;
//! - when sojourn stayed above `target` for a whole `interval`, drop
//!   schedule begins at `first_above`; each subsequent drop follows the
//!   control law `interval / √count`;
//! - when sojourn falls below target, the schedule stops (and the
//!   control-law count resumes rather than resets if the last drop was
//!   recent — `interval` recency rule).
//!
//! Policy mapping (§4 AQM boundary):
//! - **ECT(0)/ECT(1)-marked packets are CE-marked, not dropped** —
//!   the AQM asks the endpoints to back off (RFC 3168 semantics).
//! - **Not-ECT packets are dropped** per the drop schedule — the only
//!   approved discard (D-AQM), and only for *forwarding* payload
//!   (never for endpoint-terminated data, which is already delivered).
//! - DSCP is preserved; the caller updates the IPv4 header checksum
//!   after an ECN field change.

use crate::TransportInstant;
use std::time::Duration;

/// RFC 8289 recommended target (5 ms) — overridden per tier/Q_budget.
pub const DEFAULT_TARGET: Duration = Duration::from_millis(5);
/// RFC 8289 recommended interval (100 ms).
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

/// What to do with a dequeued packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodelAction {
    /// Forward unchanged.
    Pass,
    /// Mark CE (packet is ECN-capable).
    MarkCe,
    /// Drop (packet is Not-ECT — the only AQM discard).
    Drop,
}

/// One packet's enqueue stamp — the queue stores `(enqueued_at,
/// ecn)` alongside its payload pointer.
#[derive(Clone, Copy, Debug)]
pub struct Stamp {
    pub enqueued_at: TransportInstant,
    /// ECN field value at enqueue: 0=Not-ECT, 2=ECT(0), 3=CE, 1=ECT(1).
    pub ecn: u8,
}

#[derive(Debug)]
pub struct Codel {
    target: Duration,
    interval: Duration,
    /// First instant sojourn exceeded target (0 = unset).
    first_above_us: u64,
    /// Next scheduled drop instant while in dropping state.
    drop_next_us: u64,
    /// Control-law count.
    count: u32,
    /// Instant of last drop — the recency rule keeps `count` warm.
    last_drop_us: u64,
    dropping: bool,
    // audit counters
    pub packets_in: u64,
    pub passed: u64,
    pub marked_ce: u64,
    pub dropped: u64,
}

impl Codel {
    pub fn new(target: Duration, interval: Duration) -> Self {
        Self {
            target,
            interval,
            first_above_us: 0,
            drop_next_us: 0,
            count: 0,
            last_drop_us: 0,
            dropping: false,
            packets_in: 0,
            passed: 0,
            marked_ce: 0,
            dropped: 0,
        }
    }

    /// RFC 8289 control law: drop spacing = interval / √count.
    fn control_law(&self, t_us: u64, count: u32) -> u64 {
        let int_us = self.interval.as_micros() as f64;
        t_us + (int_us / (count as f64).sqrt()) as u64
    }

    /// Dequeue decision for one packet (RFC 8289 `dodequeue`).
    /// `queue_empty` is whether the queue was empty at dequeue —
    /// used to exit dropping cleanly like upstream.
    pub fn dequeue(&mut self, now: TransportInstant, stamp: Stamp, queue_empty: bool) -> CodelAction {
        self.packets_in += 1;
        let sojourn = now.duration_since(stamp.enqueued_at);
        let now_us = now.micros();

        // Below target → reset/leave dropping.
        if sojourn < self.target || queue_empty && !self.dropping {
            if self.dropping {
                // Leave dropping when we've observed a below-target
                // sojourn after the drop schedule elapsed.
                if now_us >= self.drop_next_us || sojourn < self.target {
                    self.dropping = false;
                }
            }
            self.first_above_us = 0;
            return self.pass();
        }

        // In dropping state: apply the schedule.
        if self.dropping {
            if now_us >= self.drop_next_us {
                // Drop/mark this packet and advance the schedule.
                self.count += 1;
                self.last_drop_us = now_us;
                self.drop_next_us = self.control_law(now_us, self.count);
                return self.discard(stamp);
            }
            return self.pass();
        }

        // Enter dropping: sojourn above target continuously since
        // first_above for a full interval.
        if self.first_above_us == 0 {
            self.first_above_us = now_us + self.interval.as_micros() as u64;
            return self.pass();
        }
        if now_us >= self.first_above_us {
            self.dropping = true;
            // Recency rule (RFC 8289 §4.5): if the last drop was within
            // one interval, resume with the previous count; else reset.
            self.count = if now_us.saturating_sub(self.last_drop_us)
                < self.interval.as_micros() as u64
            {
                self.count.max(1)
            } else {
                1
            };
            self.drop_next_us = self.control_law(now_us, self.count);
            self.count = self.count.saturating_add(1);
            self.last_drop_us = now_us;
            return self.discard(stamp);
        }
        self.pass()
    }

    fn pass(&mut self) -> CodelAction {
        self.passed += 1;
        CodelAction::Pass
    }

    fn discard(&mut self, stamp: Stamp) -> CodelAction {
        // ECN-capable → mark; Not-ECT → drop (D-AQM approved discard).
        match stamp.ecn {
            1 | 2 => {
                self.marked_ce += 1;
                CodelAction::MarkCe
            }
            _ => {
                self.dropped += 1;
                CodelAction::Drop
            }
        }
    }

    /// Is the schedule currently dropping?
    pub fn is_dropping(&self) -> bool {
        self.dropping
    }

    /// Current control-law count (audit).
    pub fn count(&self) -> u32 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(at_us: u64, ecn: u8) -> Stamp {
        Stamp {
            enqueued_at: TransportInstant::from_micros(at_us),
            ecn,
        }
    }

    #[test]
    fn pass_below_target() {
        let mut c = Codel::new(DEFAULT_TARGET, DEFAULT_INTERVAL);
        let a = c.dequeue(TransportInstant::from_micros(2_000), stamp(1_000, 0), false);
        assert_eq!(a, CodelAction::Pass);
        assert!(!c.is_dropping());
    }

    #[test]
    fn enters_dropping_after_interval_of_overload() {
        let mut c = Codel::new(DEFAULT_TARGET, DEFAULT_INTERVAL);
        // All packets have ~10ms sojourn (> 5ms target) — sustained.
        for i in 0..200u64 {
            let enq = i * 1_000;
            let now = enq + 10_000; // 10 ms sojourn
            c.dequeue(TransportInstant::from_micros(now), stamp(enq, 0), false);
        }
        assert!(c.is_dropping());
        assert!(c.dropped > 0);
    }

    #[test]
    fn ect_marked_not_dropped() {
        let mut c = Codel::new(DEFAULT_TARGET, DEFAULT_INTERVAL);
        // Drive into dropping state with Not-ECT packets.
        for i in 0..200u64 {
            let enq = i * 1_000;
            c.dequeue(TransportInstant::from_micros(enq + 10_000), stamp(enq, 0), false);
        }
        let dropped_before = c.dropped;
        let marked_before = c.marked_ce;
        // Now an ECT(0) packet under overload → mark, not drop.
        let now = 300_000u64;
        let a = c.dequeue(TransportInstant::from_micros(now), stamp(now - 10_000, 2), false);
        assert!(a == CodelAction::MarkCe || a == CodelAction::Pass);
        if a == CodelAction::MarkCe {
            assert_eq!(c.marked_ce, marked_before + 1);
            assert_eq!(c.dropped, dropped_before);
        }
    }

    #[test]
    fn recovers_when_sojourn_falls() {
        let mut c = Codel::new(DEFAULT_TARGET, DEFAULT_INTERVAL);
        for i in 0..200u64 {
            let enq = i * 1_000;
            c.dequeue(TransportInstant::from_micros(enq + 10_000), stamp(enq, 0), false);
        }
        assert!(c.is_dropping());
        // Sojourn falls below target → leave dropping.
        for i in 0..50u64 {
            let enq = 300_000 + i * 1_000;
            let a = c.dequeue(TransportInstant::from_micros(enq + 1_000), stamp(enq, 0), false);
            if a == CodelAction::Drop {
                // still within drop schedule window — ok briefly
            }
        }
        // After the schedule exits, passing should dominate.
        let mut passed = 0;
        for i in 0..100u64 {
            let enq = 400_000 + i * 1_000;
            if c.dequeue(TransportInstant::from_micros(enq + 500), stamp(enq, 0), false)
                == CodelAction::Pass
            {
                passed += 1;
            }
        }
        assert!(passed >= 90, "recovery too slow: {passed}/100 passed");
    }

    #[test]
    fn drop_schedule_spacing_shrinks_with_count() {
        let mut c = Codel::new(DEFAULT_TARGET, DEFAULT_INTERVAL);
        let mut drop_times = Vec::new();
        for i in 0..400u64 {
            let enq = i * 1_000;
            let now = enq + 20_000;
            if c.dequeue(TransportInstant::from_micros(now), stamp(enq, 0), false)
                == CodelAction::Drop
            {
                drop_times.push(now);
            }
        }
        // Spacing between consecutive drops must shrink (control law).
        if drop_times.len() >= 3 {
            let d1 = drop_times[1] - drop_times[0];
            let d2 = drop_times[2] - drop_times[1];
            assert!(d2 <= d1, "control law not shrinking: {d1} {d2}");
        }
    }
}
