//! PRR (RFC 6937, Slow-Start Reduction Bound variant) — reusable part.
//!
//! Shared by the reference window controllers and reused by EdgeCC
//! recovery (§2.8): Linux runs PRR for both Reno and CUBIC recovery.
//!
//! `pipe` is the caller-supplied `in_flight`: the sim/stack's scoreboard
//! already applies Linux `tcp_packets_in_flight` accounting (outstanding
//! minus sacked minus lost, plus retransmits-in-flight), which is exactly
//! the pipe RFC 6937's sndcnt formula expects.

use crate::TransportInstant;

#[derive(Clone, Copy, Debug, Default)]
pub struct Prr {
    /// True while fast recovery is in flight.
    pub active: bool,
    /// Delivered bytes accumulated since recovery entry.
    pub delivered: u64,
    /// Bytes sent during recovery (via `note_sent`).
    pub out: u64,
    /// FlightSize at recovery entry (RFC 6937 RecoverFS).
    pub recover_fs: u64,
    /// Cumulative-ack edge that ends recovery.
    pub recovery_point: u64,
    /// Bytes currently judged lost (decremented as SACKs confirm them).
    pub lost_out: u64,
}

impl Prr {
    pub fn enter(&mut self, now_in_flight: u64, high_seq: u64) {
        *self = Prr {
            active: true,
            recover_fs: now_in_flight.max(1),
            recovery_point: high_seq,
            ..Prr::default()
        };
    }

    /// A (re)transmission happened during recovery.
    pub fn note_sent(&mut self, bytes: u64) {
        if self.active {
            self.out += bytes;
        }
    }

    /// Additional bytes were judged lost.
    pub fn note_lost(&mut self, bytes: u64) {
        self.lost_out += bytes;
    }

    /// RFC 6937 sndcnt: returns the send allowance this ACK grants
    /// (cwnd target = pipe + sndcnt). Exits recovery when `cum_ack`
    /// passes the recovery point.
    pub fn on_ack(
        &mut self,
        delivered: u64,
        cum_ack: u64,
        in_flight: u64,
        ssthresh: u64,
        mss: u64,
        _now: TransportInstant,
    ) -> Option<u64> {
        if !self.active {
            return None;
        }
        self.delivered += delivered;
        self.lost_out = self.lost_out.saturating_sub(delivered);
        if cum_ack > self.recovery_point {
            // RFC 6937: leaving recovery, cwnd = ssthresh.
            self.active = false;
            return Some(ssthresh);
        }
        let pipe = in_flight;
        let sndcnt = if pipe > ssthresh {
            // Proportional rate reduction.
            let target = self
                .delivered
                .saturating_mul(ssthresh)
                .div_ceil(self.recover_fs)
                .saturating_add(mss);
            target.saturating_sub(self.out)
        } else {
            let limit = self.delivered.saturating_sub(self.out).max(delivered) + mss;
            ssthresh.saturating_sub(pipe).min(limit)
        };
        Some(pipe + sndcnt)
    }
}
