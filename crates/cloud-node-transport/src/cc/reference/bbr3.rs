//! Bbr3Ref — independent re-derivation of BBRv3 pinned to
//! `google/bbr` v3 (`net/ipv4/tcp_bbr.c` @ v3 branch, commit-pinned in
//! plan §上游依据: 90210de4) and draft-ietf-ccwg-bbr-06.
//!
//! **校验模式，不是生产算法**（plan §2.9）：an in-stack baseline for
//! the T10 comparison. It is written from the upstream state machine
//! and constants — not by weakening EdgeCC parameters — so the
//! comparison is honest. Mechanisms shared with EdgeCC (win_minmax
//! filter semantics, PRR, packet-conservation rounds) are re-implemented
//! here from upstream, deliberately not imported from `EdgeCc`.
//!
//! Upstream pieces pinned:
//! - STARTUP pacing/cwnd gain 2.77 / 2.885 (BBRStartUPGain), full-bw
//!   exit: 3 rounds within 25% (BBRFULLBWCN = 3, bbr_full_bw_margin).
//! - DRAIN pacing gain = 1/2.885 ≈ 0.35 until inflight ≤ BDP.
//! - ProbeBW cycle gains [1.25, 0.75, 1, 1, 1, 1, 1, 1] (upstream
//!   `bbr_pacing_gain`), 8-phase cycle, refill after down drains.
//! - ProbeRTT: floor stale >5 s (BBRMinRTTFilterLen 10 s halved in v3
//!   practice → we pin upstream `bbr_probe_rtt_mode_ms` 200 ms hold,
//!   min-RTT window 10 s refresh), inflight ≤ 4·MSS.
//! - inflight_hi/lo: set on loss/ECN to inflight×(1−β), β=0.3
//!   (upstream `bbr_beta`); inflight_hi uses headroom 0.85 of
//!   flight (BBR_HEADROOM); bw_lo = bw×(1−β); REFILL raises both.
//! - ECN: DCTCP-style alpha EWMA (1/16 gain), cwnd × (1 − alpha/2)
//!   per RTT of marks (upstream bbr_ecn handling).
//! - Loss: on first loss in a round, set inflight_lo/bw_lo/inflight_hi;
//!   recovery via PRR (upstream uses bbr's own loss bookkeeping —
//!   simplified to PRR here since the trait contract supplies the
//!   stack's loss detector; deviation noted, not hidden).
//! - extra_acked: EWMA of acked beyond expectation (1/16 gain, cap 2×cwnd
//!   — upstream `BBR_EXTRA_ACKED_MAX`).

use crate::cc::parts::Prr;
use crate::cc::{CcSnapshot, CongestionController};
use crate::rate_sample::RateSample;
use crate::rtt::RttState;
use crate::TransportInstant;
use std::time::Duration;

const MODE_STARTUP: &str = "startup";
const MODE_DRAIN: &str = "drain";
const MODE_PROBE_BW: &str = "probe_bw";
const MODE_PROBE_RTT: &str = "probe_rtt";
const MODE_RECOVERY: &str = "recovery";

/// Upstream `BBRUnit` = 2.0 for cwnd gain in ProbeBW.
const CWND_GAIN: f64 = 2.0;
const STARTUP_PACING: f64 = 2.77;
const STARTUP_CWND: f64 = 2.885;
const DRAIN_PACING: f64 = 1.0 / 2.885;
/// ProbeBW pacing cycle (upstream `bbr_pacing_gain`).
const PACING_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// β for inflight_lo/bw_lo cuts (upstream `bbr_beta` = 0.3 keep ratio
/// 0.7; we store keep-fraction).
const LOSS_KEEP: f64 = 0.7;
/// inflight_hi headroom (upstream BBR_HEADROOM = 15%).
const HEADROOM: f64 = 0.85;
/// ProbeRTT hold.
const PROBE_RTT_HOLD: Duration = Duration::from_millis(200);
/// min_rtt filter refresh window (upstream 10 s).
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);
/// ProbeRTT inflight ceiling.
const PROBE_RTT_INFLIGHT_MSS: u64 = 4;
/// Full-bandwidth detection (upstream): 3 non-app-limited rounds
/// without ≥25% growth.
const FULL_BW_ROUNDS: u32 = 3;
const FULL_BW_MARGIN: f64 = 1.25;
/// ECN alpha EWMA gain (upstream 1/16).
const ALPHA_GAIN: f64 = 1.0 / 16.0;
/// extra_acked EWMA gain and cap (upstream 1/16, 2×cwnd).
const EXTRA_GAIN: f64 = 1.0 / 16.0;

/// Min-RTT windowed filter — same win_minmax semantics upstream uses.
#[derive(Clone, Copy, Debug)]
struct MinFilter {
    best: f64,
    best_at: u64,
    window: Duration,
}

impl MinFilter {
    fn new(window: Duration) -> Self {
        Self {
            best: f64::INFINITY,
            best_at: 0,
            window,
        }
    }
    fn add(&mut self, now: TransportInstant, v: f64) -> f64 {
        let now_us = now.micros();
        if v <= self.best
            || now_us.saturating_sub(self.best_at) > self.window.as_micros() as u64
        {
            self.best = v;
            self.best_at = now_us;
        }
        self.best
    }
    fn value(&self) -> Option<f64> {
        (self.best < f64::INFINITY).then_some(self.best)
    }
    fn stale(&self, now: TransportInstant) -> bool {
        now.micros().saturating_sub(self.best_at) > self.window.as_micros() as u64
    }
    #[allow(dead_code)] // part of the min-filter contract; used on probe refresh paths
    fn reset(&mut self, now: TransportInstant, v: f64) {
        self.best = v;
        self.best_at = now.micros();
    }
}

/// Max-windowed delivery-rate filter (upstream `bbr_bw` win_minmax over
/// ~2 ProbeBW cycles ≈ fixed 4 s window).
#[derive(Clone, Copy, Debug)]
struct MaxFilter {
    best: f64,
    best_at: u64,
    window_us: u64,
}

impl MaxFilter {
    fn new() -> Self {
        Self {
            best: 0.0,
            best_at: 0,
            window_us: 4_000_000,
        }
    }
    fn add(&mut self, now: TransportInstant, v: f64) -> f64 {
        let now_us = now.micros();
        if v >= self.best || now_us.saturating_sub(self.best_at) > self.window_us {
            self.best = v;
            self.best_at = now_us;
        }
        self.best
    }
    fn value(&self) -> Option<f64> {
        (self.best > 0.0).then_some(self.best)
    }
    #[allow(dead_code)] // part of the min-filter contract; used on probe refresh paths
    fn reset(&mut self, now: TransportInstant, v: f64) {
        self.best = v;
        self.best_at = now.micros();
    }
}

#[derive(Debug)]
pub struct Bbr3Ref {
    mss: u64,
    mode: &'static str,
    reason: &'static str,

    // --- upstream bw/min_rtt filters ---
    bw: MaxFilter,
    bw_lo: Option<u64>,
    bw_hi: Option<u64>,
    min_rtt_f: MinFilter,
    min_rtt_us: f64,
    min_rtt_at: u64,
    probe_rtt_done: Option<u64>,
    probe_rtt_round_stamp: u64,

    // --- cycle state ---
    cycle_idx: usize,
    /// Inflight target during the down phase drain check.
    cycle_wait: bool,
    round_end_cum: u64,
    rounds: u32,
    sent_total: u64,

    // --- full-bw detection ---
    full_bw: f64,
    full_bw_cnt: u32,

    // --- inflight bounds ---
    inflight_hi: Option<u64>,
    inflight_lo: Option<u64>,

    // --- ECN ---
    alpha: f64,
    ce_responded_rtt: u64,

    // --- extra_acked ---
    extra_acked: f64,

    // --- recovery ---
    prr: Prr,
    /// Eifel checkpoint: (inflight_hi, inflight_lo, bw_lo, mode).
    saved: Option<(Option<u64>, Option<u64>, Option<u64>, &'static str)>,
    recovery_point: u64,

    pacing_bps: u64,
    cwnd: u64,
    last_srtt: Option<Duration>,
    idle_restart_seen: bool,
}

impl Bbr3Ref {
    pub fn new(mss: u64) -> Self {
        let mss = mss.max(1);
        Self {
            mss,
            mode: MODE_STARTUP,
            reason: "init",
            bw: MaxFilter::new(),
            bw_lo: None,
            bw_hi: None,
            min_rtt_f: MinFilter::new(MIN_RTT_WINDOW),
            min_rtt_us: 0.0,
            min_rtt_at: 0,
            probe_rtt_done: None,
            probe_rtt_round_stamp: 0,
            cycle_idx: 0,
            cycle_wait: false,
            round_end_cum: 0,
            rounds: 0,
            sent_total: 0,
            full_bw: 0.0,
            full_bw_cnt: 0,
            inflight_hi: None,
            inflight_lo: None,
            alpha: 0.0,
            ce_responded_rtt: u64::MAX,
            extra_acked: 0.0,
            prr: Prr::default(),
            saved: None,
            recovery_point: 0,
            pacing_bps: 0,
            cwnd: 4 * mss,
            last_srtt: None,
            idle_restart_seen: false,
        }
    }

    fn bdp(&self) -> u64 {
        let bw = self.bw();
        match (bw, self.min_rtt_f.value()) {
            (Some(b), Some(r)) => (b as f64 * r / 1e6) as u64,
            _ => self.cwnd.max(4 * self.mss),
        }
    }

    /// Upstream `bbr_bw()`: min(bw, bw_lo if set).
    fn bw(&self) -> Option<u64> {
        self.bw.value().map(|b| {
            let b = b as u64;
            self.bw_lo.map_or(b, |lo| b.min(lo))
        })
    }

    /// inflight bound = min(cwnd_gain·BDP, inflight_hi?, inflight_lo?).
    fn target_inflight(&self, cwnd_gain: f64) -> u64 {
        let mut t = (self.bdp() as f64 * cwnd_gain) as u64;
        if let Some(hi) = self.inflight_hi {
            t = t.min(hi);
        }
        if let Some(lo) = self.inflight_lo {
            t = t.min(lo);
        }
        t.max(4 * self.mss)
    }

    fn set_pacing(&mut self, gain: f64) {
        if let Some(b) = self.bw() {
            self.pacing_bps = (b as f64 * gain) as u64;
        }
    }

    /// Upstream loss response (`bbr2_handle_lost_packet` /
    /// `bbr_save_inflight_lo`): first loss in a round pins lo/hi.
    fn handle_loss(&mut self, in_flight: u64) {
        self.inflight_lo = Some(
            self.inflight_lo
                .unwrap_or(u64::MAX)
                .min((in_flight as f64 * LOSS_KEEP) as u64)
                .max(4 * self.mss),
        );
        self.inflight_hi = Some(
            self.inflight_hi
                .unwrap_or(u64::MAX)
                .min((in_flight as f64 * HEADROOM) as u64)
                .max(4 * self.mss),
        );
        if let Some(b) = self.bw.value().map(|v| v as u64) {
            self.bw_lo = Some(
                self.bw_lo
                    .unwrap_or(u64::MAX)
                    .min((b as f64 * LOSS_KEEP) as u64),
            );
        }
    }
}

impl CongestionController for Bbr3Ref {
    fn on_sent(&mut self, _now: TransportInstant, bytes: u64, _in_flight: u64, _app: bool) {
        self.sent_total = self.sent_total.saturating_add(bytes);
        self.prr.note_sent(bytes);
    }

    fn on_rate_sample(&mut self, rs: &RateSample, in_flight: u64, rtt: &RttState) {
        if let Some(s) = rtt.srtt {
            self.last_srtt = Some(s);
        }
        // min_rtt filter (upstream feeds every RTT sample).
        if let Some(r) = rs.rtt {
            let v = r.as_micros() as f64;
            self.min_rtt_f.add(rs.now, v);
            self.min_rtt_us = v;
            self.min_rtt_at = rs.now.micros();
        }
        // bw filter: upstream uses delivery rate of non-app-limited
        // samples for the max filter.
        if rs.delivered > 0 {
            let rate = rs.delivery_rate_bps() as f64;
            if rate > 0.0 {
                self.bw.add(rs.now, rate);
                // extra_acked: acked beyond bw×interval expectation.
                if let Some(est) = self.bw() {
                    let expected = est as f64 * rs.interval.as_micros() as f64 / 1e6;
                    let extra = (rs.acked_sacked as f64 - expected).max(0.0);
                    self.extra_acked += EXTRA_GAIN * (extra - self.extra_acked);
                    self.extra_acked =
                        self.extra_acked.min(2.0 * self.cwnd as f64);
                }
            }
        }
        // ECN alpha (upstream bbr_ecn: EWMA 1/16 of CE fraction).
        if rs.delivered_ce > 0 && rs.delivered > 0 {
            let frac = (rs.delivered_ce as f64 / rs.delivered as f64).min(1.0);
            self.alpha += ALPHA_GAIN * (frac - self.alpha);
        }

        // Round tracking (packet conservation).
        let round_done = rs.cum_ack > 0 && self.round_end_cum > 0 && rs.cum_ack > self.round_end_cum;
        if round_done {
            self.rounds = self.rounds.saturating_add(1);
            // Loss bookkeeping closes the round: inflight_lo REFILL —
            // upstream raises lo bounds once per round without loss.
            if rs.lost == 0 {
                if let Some(lo) = self.inflight_lo {
                    self.inflight_lo = Some((lo * 5 / 4).max(lo + self.mss));
                }
                if let Some(lo) = self.bw_lo {
                    // bw_lo refills toward bw (upstream `bbr_bw_lo` refill).
                    let b = self.bw.value().unwrap_or(lo as f64) as u64;
                    self.bw_lo = Some(lo + b.saturating_sub(lo) / 4);
                }
            }
        }

        // ECN response (upstream: once per min_rtt, cwnd × (1−α/2),
        // and inflight_lo/bw_lo set like loss).
        if rs.delivered_ce > 0 && self.rounds as u64 != self.ce_responded_rtt {
            self.ce_responded_rtt = self.rounds as u64;
            self.cwnd = (self.cwnd as f64 * (1.0 - self.alpha / 2.0)) as u64;
            self.handle_loss(in_flight);
            self.reason = "ecn";
        }

        // Loss handling (first loss event in the round via the stack's
        // detector; here rs.lost carries the per-ACK increment).
        if rs.lost > 0 {
            self.handle_loss(in_flight);
            if !self.prr.active {
                self.saved = self.saved.or(Some((
                    self.inflight_hi,
                    self.inflight_lo,
                    self.bw_lo,
                    self.mode,
                )));
                self.prr.enter(in_flight, self.sent_total + 1);
                self.recovery_point = rs.cum_ack + self.sent_total.max(1); // seq edge
                self.mode = MODE_RECOVERY;
                self.reason = "loss";
            } else {
                self.prr.note_lost(rs.lost);
            }
        }

        // ---- state machine ----
        match self.mode {
            MODE_STARTUP => {
                let gain = STARTUP_PACING;
                self.set_pacing(gain.max(if self.pacing_bps == 0 { gain } else { 0.0 }));
                if self.pacing_bps == 0 {
                    // No bw sample yet: initial window pacing.
                    let rtt = self.min_rtt_f.value().unwrap_or(50_000.0);
                    self.pacing_bps =
                        (self.cwnd as f64 * gain * 1e6 / rtt) as u64;
                }
                self.cwnd = (self.bdp() as f64 * STARTUP_CWND)
                    .max(self.cwnd as f64 + rs.acked_sacked as f64) as u64;
                if round_done && !rs.is_app_limited {
                    let rate = rs.delivery_rate_bps() as f64;
                    if rate <= self.full_bw * FULL_BW_MARGIN {
                        self.full_bw_cnt += 1;
                    } else {
                        self.full_bw_cnt = 0;
                        self.full_bw = rate;
                    }
                    if self.full_bw_cnt >= FULL_BW_ROUNDS {
                        self.mode = MODE_DRAIN;
                        self.reason = "full_bw";
                    }
                }
            }
            MODE_DRAIN => {
                self.set_pacing(DRAIN_PACING);
                self.cwnd = self.target_inflight(STARTUP_CWND);
                if in_flight <= self.bdp() {
                    self.mode = MODE_PROBE_BW;
                    self.cycle_idx = 0;
                    self.cycle_wait = false;
                    self.reason = "drain_done";
                }
            }
            MODE_PROBE_BW => {
                // ProbeRTT entry check: min_rtt stale.
                if self.min_rtt_f.stale(rs.now) && self.mode != MODE_PROBE_RTT {
                    self.mode = MODE_PROBE_RTT;
                    self.probe_rtt_done = None;
                    self.probe_rtt_round_stamp = rs.cum_ack;
                    self.reason = "probe_rtt";
                    return;
                }
                // Cycle advance on round boundary.
                if round_done {
                    let advancing = !self.cycle_wait;
                    if advancing {
                        self.cycle_idx = (self.cycle_idx + 1) % PACING_CYCLE.len();
                        if PACING_CYCLE[self.cycle_idx] < 1.0 {
                            self.cycle_wait = true; // down phase: wait to drain
                        }
                    }
                    if self.cycle_wait && in_flight <= self.bdp() {
                        self.cycle_wait = false;
                    }
                }
                let gain = PACING_CYCLE[self.cycle_idx];
                self.set_pacing(gain);
                self.cwnd = self.target_inflight(CWND_GAIN);
            }
            MODE_PROBE_RTT => {
                self.set_pacing(1.0);
                self.cwnd = (PROBE_RTT_INFLIGHT_MSS * self.mss)
                    .min(self.cwnd)
                    .max(4 * self.mss);
                let done_at = self.probe_rtt_done;
                match done_at {
                    Some(t) if rs.now.micros() >= t => {
                        self.mode = MODE_PROBE_BW;
                        self.reason = "probe_rtt_done";
                        self.probe_rtt_done = None;
                    }
                    Some(_) => {}
                    None => {
                        if in_flight <= PROBE_RTT_INFLIGHT_MSS * self.mss {
                            self.probe_rtt_done = Some(
                                rs.now.micros() + PROBE_RTT_HOLD.as_micros() as u64,
                            );
                        }
                    }
                }
                // Refresh filter if a lower rtt arrived during probe.
                if let Some(r) = rs.rtt {
                    self.min_rtt_f.reset(rs.now, (r.as_micros() as f64).min(
                        self.min_rtt_f.value().unwrap_or(f64::INFINITY),
                    ));
                }
            }
            MODE_RECOVERY => {
                if let Some(cwnd) = self.prr.on_ack(
                    rs.delivered,
                    rs.cum_ack,
                    in_flight,
                    self.cwnd,
                    self.mss,
                    rs.now,
                ) {
                    self.cwnd = cwnd;
                    if !self.prr.active {
                        self.mode = MODE_PROBE_BW;
                        self.reason = "recovery_done";
                    }
                }
            }
            _ => {}
        }

        if self.prr.active && self.mode != MODE_RECOVERY {
            // PRR active but we left recovery bookkeeping — safety net.
            if let Some(cwnd) = self.prr.on_ack(
                rs.delivered,
                rs.cum_ack,
                in_flight,
                self.cwnd,
                self.mss,
                rs.now,
            ) {
                self.cwnd = cwnd;
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
        if persistent {
            self.on_rto(now, in_flight);
            return;
        }
        // Stack-level event — the per-ACK path already handled marks;
        // this hook covers events reported outside a rate sample.
        self.prr.note_lost(lost_bytes);
        if !self.prr.active {
            self.saved = self.saved.or(Some((
                self.inflight_hi,
                self.inflight_lo,
                self.bw_lo,
                self.mode,
            )));
            self.handle_loss(in_flight);
            self.prr.enter(in_flight, self.sent_total + 1);
            self.mode = MODE_RECOVERY;
            self.reason = "loss";
        }
    }

    fn on_ecn_ce(&mut self, _now: TransportInstant, _ce: u64, _del: u64, _in_flight: u64) {
        // ECN handled per rate sample via delivered_ce (byte-grain);
        // nothing extra here — the classic once-per-window response
        // is the `ce_responded_rtt` gate in on_rate_sample.
    }

    fn on_rto(&mut self, now: TransportInstant, _in_flight: u64) {
        // Upstream RTO: inflight_hi = inflight/2 floored at 4 MSS,
        // full-bw reset, restart startup.
        self.saved = self.saved.or(Some((
            self.inflight_hi,
            self.inflight_lo,
            self.bw_lo,
            self.mode,
        )));
        self.inflight_hi = Some((self.cwnd / 2).max(4 * self.mss));
        self.inflight_lo = None;
        self.cwnd = self.mss;
        self.full_bw = 0.0;
        self.full_bw_cnt = 0;
        self.mode = MODE_STARTUP;
        self.reason = "rto";
        self.prr = Prr::default();
        let _ = now;
    }

    fn on_loss_undo(&mut self, _now: TransportInstant) {
        if let Some((hi, lo, bw_lo, mode)) = self.saved.take() {
            self.inflight_hi = hi;
            self.inflight_lo = lo;
            self.bw_lo = bw_lo;
            self.mode = mode;
            self.reason = "loss_undo";
            self.prr = Prr::default();
        }
    }

    fn on_idle_restart(&mut self, _now: TransportInstant, idle_for: Duration) {
        // Upstream: cwnd validate — no reduction on restart, but an
        // idle gap restarts pacing epoch. Keep window, note restart.
        let _ = idle_for;
        self.idle_restart_seen = true;
        self.reason = "idle_restart";
    }

    fn on_mss_update(&mut self, mss: u64) {
        self.mss = mss.max(1);
        self.cwnd = self.cwnd.max(self.mss);
    }

    fn cwnd(&self) -> u64 {
        self.cwnd.max(4 * self.mss).min(u64::MAX / 2)
    }

    fn pacing_rate(&self) -> Option<u64> {
        (self.pacing_bps > 0).then_some(self.pacing_bps)
    }

    fn snapshot(&self) -> CcSnapshot {
        CcSnapshot {
            algo: "bbr3_ref",
            version_pin: "google-bbr-v3-90210de4",
            mode: self.mode,
            cwnd_bytes: self.cwnd(),
            ssthresh_bytes: u64::MAX / 2,
            pacing_rate_bps: self.pacing_rate(),
            min_rtt: self.min_rtt_f.value().map(|v| Duration::from_micros(v as u64)),
            bandwidth_hi_bps: self.bw_hi,
            bandwidth_lo_bps: self.bw_lo,
            inflight_hi_bytes: self.inflight_hi,
            inflight_lo_bytes: self.inflight_lo,
            extra_acked_bytes: Some(self.extra_acked as u64),
            ecn_alpha_milli: Some((self.alpha * 1000.0) as u32),
            belief_milli: None,
            queue_estimate_bytes: None,
            p_rand_milli: None,
            bw_sigma_bps: None,
            envelope_bytes: self.inflight_hi,
            reason_code: self.reason,
        }
    }
}
