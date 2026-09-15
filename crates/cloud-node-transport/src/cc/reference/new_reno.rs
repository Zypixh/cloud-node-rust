//! NewRenoRef — RFC 5681 (SS/CA/fast retransmit/recovery) + RFC 6582
//! (recovery heuristics) + PRR RFC 6937 + RFC 3168 ECN response
//! (once-per-RTT halving + CWR semantics carried by the stack).
//!
//! **校验模式，不是生产算法**（plan §2.9）：golden reference for
//! bookkeeping correctness and the simulator baseline. The production
//! dataplane ships EdgeCC; this controller is kept only for regression
//! and in-stack comparison.

use super::super::parts::Prr;
use super::super::{CcSnapshot, CongestionController};
use crate::rate_sample::RateSample;
use crate::rtt::RttState;
use crate::TransportInstant;
use std::time::Duration;

const MODE_SS: &str = "slow_start";
const MODE_CA: &str = "congestion_avoidance";
const MODE_REC: &str = "recovery";

#[derive(Debug)]
pub struct NewRenoRef {
    mss: u64,
    cwnd: u64,
    ssthresh: u64,
    mode: &'static str,
    reason: &'static str,
    prr: Prr,
    /// Cumulative bytes ever queued for transmission — the recovery point
    /// is taken from this (sender seqs are contiguous).
    sent_total: u64,
    /// RFC 3168: CE responses are once per window — set on a response,
    /// cleared when a full RTT elapses since.
    ce_responded_at: Option<TransportInstant>,
    min_rtt: Option<Duration>,
    srtt: Option<Duration>,
    /// Eifel checkpoint: (cwnd, ssthresh, mode) at loss/RTO entry so a
    /// spurious-loss verdict can undo the response.
    saved: Option<(u64, u64, &'static str)>,
}

impl NewRenoRef {
    /// RFC 5681 IW = min(4*MSS, max(2*MSS, 4380)) (RFC 6928 IW10 is wider;
    /// we keep the conservative 4×MSS default).
    pub fn new(mss: u64) -> Self {
        let mss = mss.max(1);
        Self {
            mss,
            cwnd: 4 * mss,
            ssthresh: u64::MAX,
            mode: MODE_SS,
            reason: "init",
            prr: Prr::default(),
            sent_total: 0,
            ce_responded_at: None,
            min_rtt: None,
            srtt: None,
            saved: None,
        }
    }

    fn enter_recovery(&mut self, now: TransportInstant, in_flight: u64) {
        // RFC 5681: ssthresh = max(FlightSize/2, 2*SMSS); PRR then drives
        // the send allowance through recovery.
        // Keep the earliest checkpoint so cascaded responses undo fully.
        self.saved = self.saved.or(Some((self.cwnd, self.ssthresh, self.mode)));
        self.ssthresh = (in_flight / 2).max(2 * self.mss);
        self.prr.enter(in_flight, self.sent_total);
        self.mode = MODE_REC;
        self.reason = "loss";
        let _ = now;
    }
}

impl CongestionController for NewRenoRef {
    fn on_sent(
        &mut self,
        _now: TransportInstant,
        bytes: u64,
        _in_flight: u64,
        _is_app_limited: bool,
    ) {
        self.sent_total += bytes;
        self.prr.note_sent(bytes);
    }

    fn on_rate_sample(&mut self, rs: &RateSample, in_flight: u64, rtt: &RttState) {
        if let Some(r) = rs.rtt {
            self.srtt = rtt.srtt.or(Some(r));
        }
        self.min_rtt = rtt.min_rtt;
        // RFC 3168: one CE response per window — clear the mark once a
        // full RTT has elapsed since the response.
        if let Some(t) = self.ce_responded_at
            && let Some(min) = self.min_rtt
            && rs.now.duration_since(t) > min
        {
            self.ce_responded_at = None;
        }

        if self.prr.active {
            if let Some(cwnd) =
                self.prr
                    .on_ack(rs.delivered, rs.cum_ack, in_flight, self.ssthresh, self.mss, rs.now)
            {
                self.cwnd = cwnd;
                if !self.prr.active {
                    self.mode = MODE_CA;
                    self.reason = "recovery_done";
                    self.cwnd = self.ssthresh;
                    // Episode ended legitimately — a stale checkpoint must
                    // not undo a later, unrelated loss response.
                    self.saved = None;
                }
            }
            return;
        }

        match self.mode {
            MODE_SS => {
                // RFC 3465 ABC L=2: bounded per-ACK growth.
                self.cwnd = self.cwnd.saturating_add(rs.acked_sacked.min(2 * self.mss));
                if self.cwnd >= self.ssthresh {
                    self.mode = MODE_CA;
                    self.reason = "ss_to_ca";
                }
            }
            _ => {
                // AIMD: +MSS per RTT → cwnd += mss*acked/cwnd.
                if rs.acked_sacked > 0 {
                    let inc = (self.mss * rs.acked_sacked / self.cwnd.max(self.mss)).max(1);
                    self.cwnd = self.cwnd.saturating_add(inc);
                }
            }
        }
    }

    fn on_loss_event(
        &mut self,
        now: TransportInstant,
        lost_bytes: u64,
        in_flight: u64,
        persistent: bool,
    ) {
        self.prr.note_lost(lost_bytes);
        if persistent {
            self.on_rto(now, in_flight);
            return;
        }
        // RFC 6582: only enter recovery once per window of data.
        if !self.prr.active {
            self.enter_recovery(now, in_flight);
        }
    }

    fn on_ecn_ce(&mut self, now: TransportInstant, _ce_bytes: u64, _delivered: u64, in_flight: u64) {
        // RFC 3168: reduce once per window; the stack reports CE events as
        // they arrive — repeats inside the same RTT are folded away here.
        if self.ce_responded_at.is_some() {
            return;
        }
        self.ce_responded_at = Some(now);
        self.ssthresh = (in_flight / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh;
        self.mode = MODE_CA;
        self.reason = "ecn";
    }

    fn on_rto(&mut self, _now: TransportInstant, _in_flight: u64) {
        // RFC 5681: ssthresh = FlightSize/2, cwnd = LW, restart slow start.
        self.saved = self.saved.or(Some((self.cwnd, self.ssthresh, self.mode)));
        self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.mode = MODE_SS;
        self.reason = "rto";
        self.prr = Prr::default();
    }

    fn on_loss_undo(&mut self, _now: TransportInstant) {
        // Eifel: the loss/RTO verdict was spurious — restore the
        // checkpointed window and cancel the PRR episode.
        if let Some((cwnd, ssthresh, mode)) = self.saved.take() {
            self.cwnd = cwnd;
            self.ssthresh = ssthresh;
            self.mode = mode;
            self.reason = "loss_undo";
            self.prr = Prr::default();
        }
    }

    fn on_idle_restart(&mut self, _now: TransportInstant, idle_for: Duration) {
        // Linux tcp_cwnd_restart: decay cwnd toward the restart window by
        // halving per idle RTT; clamp at 2*MSS.
        let rtt = self.min_rtt.unwrap_or(Duration::from_millis(1));
        let mut restart = self.cwnd;
        let mut idle = idle_for;
        while idle > rtt && restart > self.mss {
            restart /= 2;
            idle -= rtt;
        }
        self.cwnd = self.cwnd.min(restart.max(self.mss));
        self.reason = "idle_restart";
    }

    fn on_mss_update(&mut self, mss: u64) {
        self.mss = mss.max(1);
        self.cwnd = self.cwnd.max(self.mss);
    }

    fn cwnd(&self) -> u64 {
        self.cwnd
    }

    fn pacing_rate(&self) -> Option<u64> {
        // Derived pacing: cwnd/srtt (bytes/s) — plan §2.2.
        let srtt = self.srtt?;
        let us = srtt.as_micros() as u64;
        (us > 0).then(|| self.cwnd.saturating_mul(1_000_000) / us)
    }

    fn snapshot(&self) -> CcSnapshot {
        CcSnapshot {
            algo: "newreno_ref",
            version_pin: "rfc5681+6582+6937",
            mode: self.mode,
            cwnd_bytes: self.cwnd,
            ssthresh_bytes: self.ssthresh.min(u64::MAX / 2),
            pacing_rate_bps: self.pacing_rate(),
            min_rtt: self.min_rtt,
            bandwidth_hi_bps: None,
            bandwidth_lo_bps: None,
            inflight_hi_bytes: None,
            inflight_lo_bytes: None,
            extra_acked_bytes: None,
            ecn_alpha_milli: None,
            belief_milli: None,
            queue_estimate_bytes: None,
            p_rand_milli: None,
            bw_sigma_bps: None,
            envelope_bytes: None,
            reason_code: self.reason,
        }
    }
}
