//! CubicRef — RFC 9438 (+ TCP-friendly region W_est) with the shared
//! HyStart++ slow-start exit (RFC 9406, `cc::parts::HyStart`).
//!
//! **校验模式，不是生产算法**（plan §2.9）：kept for bookkeeping
//! regression and as the in-stack baseline EdgeCC must beat in T10
//! before any default switch. Internal math is in *segments* (SMSS
//! units) per RFC 9438; the public surface stays in bytes.

use super::super::parts::{HyStart, HystartVerdict, Prr};
use super::super::{CcSnapshot, CongestionController};
use crate::rate_sample::RateSample;
use crate::rtt::RttState;
use crate::TransportInstant;
use std::time::Duration;

const MODE_SS: &str = "slow_start";
const MODE_SS_CSS: &str = "slow_start_css";
const MODE_CA: &str = "congestion_avoidance";
const MODE_REC: &str = "recovery";

/// RFC 9438: C — the cubic scaling constant (per-second units).
const CUBIC_C: f64 = 0.4;
/// RFC 9438: β_cubic — multiplicative decrease factor.
const CUBIC_BETA: f64 = 0.7;

#[derive(Debug)]
pub struct CubicRef {
    mss: u64,
    /// Congestion window in bytes (public surface).
    cwnd: u64,
    ssthresh: u64,
    mode: &'static str,
    reason: &'static str,
    prr: Prr,
    sent_total: u64,
    // --- RFC 9438 cubic state ---
    /// W_max in segments at the last congestion event.
    w_max_seg: f64,
    /// K = cbrt(w_max·(1-β)/C) in seconds.
    k_seconds: f64,
    /// Time origin of the current cubic epoch.
    epoch_start: Option<TransportInstant>,
    /// Min RTT observed inside the current epoch (drives W_est and t).
    epoch_min_rtt: Option<Duration>,
    // --- RFC 9406 HyStart++ (shared part) ---
    hystart: HyStart,
    // --- ECN (RFC 3168 once-per-window) ---
    ce_responded_at: Option<TransportInstant>,
    min_rtt: Option<Duration>,
    srtt: Option<Duration>,
}

impl CubicRef {
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
            w_max_seg: 0.0,
            k_seconds: 0.0,
            epoch_start: None,
            epoch_min_rtt: None,
            hystart: HyStart::new(),
            ce_responded_at: None,
            min_rtt: None,
            srtt: None,
        }
    }

    /// RFC 9438 W_cubic(t) with t in seconds since epoch start plus the
    /// min-RTT offset (origin point correction): W = C·(t - K)³ + W_max.
    fn w_cubic(&self, t_seconds: f64) -> f64 {
        let t = t_seconds - self.k_seconds;
        CUBIC_C * t * t * t + self.w_max_seg
    }

    /// RFC 9438 TCP-friendly estimate: W_est(t) = W_max·β +
    /// [3·(1-β)/(1+β)] · (t/RTT).
    fn w_est(&self, t_seconds: f64, rtt: Duration) -> f64 {
        let rtt_s = (rtt.as_secs_f64()).max(1e-6);
        self.w_max_seg * CUBIC_BETA
            + (3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA)) * (t_seconds / rtt_s)
    }

    /// RFC 9438: on a congestion event record W_max and re-derive K, then
    /// apply the β decrease.
    fn on_congestion(&mut self, in_flight: u64) {
        let cwnd_seg = (self.cwnd / self.mss).max(1) as f64;
        // RFC 9438: W_max keeps the larger of current and previous peak
        // (fast convergence is intentionally not implemented — v1 pin).
        self.w_max_seg = cwnd_seg;
        self.k_seconds = (self.w_max_seg * (1.0 - CUBIC_BETA) / CUBIC_C).cbrt();
        self.epoch_start = None;
        self.epoch_min_rtt = None;
        self.ssthresh = ((in_flight / 2).max(2 * self.mss)).max(
            (self.cwnd as f64 * CUBIC_BETA) as u64,
        );
        self.cwnd = (self.cwnd as f64 * CUBIC_BETA) as u64;
        self.cwnd = self.cwnd.max(2 * self.mss);
    }

    /// Leave slow start into congestion avoidance (HyStart++ exit or
    /// ssthresh crossing) — arms the cubic epoch.
    fn leave_slow_start(&mut self, now: TransportInstant, reason: &'static str) {
        let cwnd_seg = (self.cwnd / self.mss).max(1) as f64;
        if self.w_max_seg < cwnd_seg {
            self.w_max_seg = cwnd_seg;
            self.k_seconds = (self.w_max_seg * (1.0 - CUBIC_BETA) / CUBIC_C).cbrt();
        }
        self.epoch_start = Some(now);
        self.epoch_min_rtt = self.min_rtt;
        self.mode = MODE_CA;
        self.reason = reason;
    }
}

impl CongestionController for CubicRef {
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
        if rs.rtt.is_some() {
            self.srtt = rtt.srtt.or(rs.rtt);
        }
        self.min_rtt = rtt.min_rtt;
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
                    self.epoch_start = Some(rs.now);
                    self.epoch_min_rtt = self.min_rtt;
                }
            }
            return;
        }

        match self.mode {
            MODE_SS | MODE_SS_CSS => {
                if self.hystart.baseline_min().is_none()
                    && let Some(b) = rs.rtt.or(self.min_rtt)
                {
                    self.hystart.seed_baseline(b, self.sent_total);
                }
                // RFC 3465 ABC L=2 per ACK event.
                self.cwnd = self.cwnd.saturating_add(rs.acked_sacked.min(2 * self.mss));
                match self
                    .hystart
                    .on_ack(rs.rtt, rs.cum_ack, self.sent_total)
                {
                    HystartVerdict::Exit => {
                        self.leave_slow_start(rs.now, "hystart");
                        return;
                    }
                    HystartVerdict::ElevatedRound => self.mode = MODE_SS_CSS,
                    HystartVerdict::Continue => {}
                }
                if self.cwnd >= self.ssthresh {
                    self.leave_slow_start(rs.now, "ss_to_ca");
                }
            }
            _ => {
                let epoch_start = *self.epoch_start.get_or_insert(rs.now);
                let t = rs.now.duration_since(epoch_start).as_secs_f64();
                if let Some(min) = self.epoch_min_rtt {
                    self.epoch_min_rtt = Some(min.min(self.min_rtt.unwrap_or(min)));
                } else {
                    self.epoch_min_rtt = rs.rtt.or(self.min_rtt);
                }
                let cwnd_seg = (self.cwnd / self.mss).max(1) as f64;
                let acked_seg = (rs.acked_sacked / self.mss).max(1) as f64;
                let rtt_est = self.epoch_min_rtt.or(rs.rtt).unwrap_or(Duration::from_millis(1));
                // Friendly region wins when W_est exceeds the cubic curve.
                let target = self.w_cubic(t).max(self.w_est(t, rtt_est));
                if target > cwnd_seg {
                    // Per-ack increment toward target: (target-cwnd)/cwnd
                    // segments per acked segment — RFC 9438 §4.4/4.5.
                    let inc = acked_seg * (target - cwnd_seg) / cwnd_seg;
                    self.cwnd = self
                        .cwnd
                        .saturating_add((inc.max(1.0 / cwnd_seg) * self.mss as f64) as u64);
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
        if !self.prr.active {
            self.on_congestion(in_flight);
            self.prr.enter(in_flight, self.sent_total);
            self.mode = MODE_REC;
            self.reason = "loss";
        }
    }

    fn on_ecn_ce(&mut self, now: TransportInstant, _ce_bytes: u64, _delivered: u64, in_flight: u64) {
        if self.ce_responded_at.is_some() {
            return;
        }
        self.ce_responded_at = Some(now);
        // CUBIC treats CE like a loss for window purposes (RFC 9438 §4.7
        // point to ECN response equivalent to a congestion event).
        self.on_congestion(in_flight);
        self.mode = MODE_CA;
        self.epoch_start = Some(now);
        self.epoch_min_rtt = self.min_rtt;
        self.reason = "ecn";
    }

    fn on_rto(&mut self, _now: TransportInstant, _in_flight: u64) {
        self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.mode = MODE_SS;
        self.reason = "rto";
        self.prr = Prr::default();
        // RFC 9438: reset epoch and HyStart++ state after RTO.
        self.epoch_start = None;
        self.epoch_min_rtt = None;
        self.hystart.reset(self.sent_total);
    }

    fn on_idle_restart(&mut self, now: TransportInstant, idle_for: Duration) {
        // Linux tcp_cwnd_validate-equivalent decay + RFC 9438 epoch reset
        // so t does not include the idle gap.
        let rtt = self.min_rtt.unwrap_or(Duration::from_millis(1));
        let mut restart = self.cwnd;
        let mut idle = idle_for;
        while idle > rtt && restart > self.mss {
            restart /= 2;
            idle -= rtt;
        }
        self.cwnd = self.cwnd.min(restart.max(self.mss));
        self.epoch_start = Some(now);
        self.epoch_min_rtt = self.min_rtt;
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
        let srtt = self.srtt?;
        let us = srtt.as_micros() as u64;
        (us > 0).then(|| self.cwnd.saturating_mul(1_000_000) / us)
    }

    fn snapshot(&self) -> CcSnapshot {
        CcSnapshot {
            algo: "cubic_ref",
            version_pin: "rfc9438+9406",
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
