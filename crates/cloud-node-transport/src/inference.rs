//! Multi-signal congestion inference (plan §2.3).
//!
//! `congestion_belief` is a bounded log-odds accumulator: each ACK adds
//! evidence weights, and the accumulator decays toward 0 every RTT so
//! belief always reflects *recent* evidence. Responses are proportional
//! to belief — never "one loss → halve", never "loss-blind" when the
//! evidence says congestion.
//!
//! All updates are per-ACK O(1). No online learning.

use crate::model::PathModel;
use crate::rate_sample::RateSample;
use crate::TransportInstant;
use std::time::Duration;

/// Evidence weights in log-odds units (plan §2.3 ordering):
///
/// CE (AccECN, scaled by mark fraction) > qdelay over budget with a
/// positive gradient > loss with a qdelay rise > inflight-plateau >
/// quiet loss above `p_rand`; DSACK/Eifel spurious retransmits are
/// negative evidence.
///
/// Magnitudes are pinned constants, chosen so a single CE-dominated RTT
/// crosses belief 0.9 while quiet loss alone needs sustained evidence
/// (D-E1: T10 measurements may retune them; they are not a runtime
/// configuration surface).
pub mod weights {
    /// AccECN per-byte CE evidence, scaled by the marked fraction.
    pub const CE_ACCECN: f64 = 2.5;
    /// Classic ECN once-per-window event.
    pub const CE_CLASSIC: f64 = 1.5;
    /// qdelay above the tier budget while its gradient is positive.
    pub const QDELAY_OVER_BUDGET: f64 = 1.0;
    /// Loss accompanied by a qdelay rise.
    pub const LOSS_WITH_QDELAY: f64 = 0.8;
    /// inflight rising while the delivery rate plateaus.
    pub const PLATEAU_INFLIGHT_UP: f64 = 0.5;
    /// Quiet-path loss evidence is `(loss_rate − p_rand)+ × this`.
    pub const LOSS_QUIET_SCALE: f64 = 6.0;
    /// DSACK/Eifel spurious retransmission — negative evidence.
    pub const DSACK_SPURIOUS: f64 = -1.5;
}

/// Belief decay per RTT (≈4-RTT memory horizon, new constant).
pub const DECAY_PER_RTT: f64 = 0.75;

/// D-D2: public-internet CE — weight scaled down and its total belief
/// contribution capped; controlled links (`trusted_ecn`) get full
/// weight.
pub const PUBLIC_CE_WEIGHT_SCALE: f64 = 0.5;
/// Max CE-attributable log-odds on untrusted paths.
pub const PUBLIC_CE_LO_CAP: f64 = 1.5;

const LO_MIN: f64 = -6.0;
const LO_MAX: f64 = 6.0;

/// RFC 8382-style shared-bottleneck statistics collected per flow.
///
/// The *decision* (merge/split of candidate aggregates) is T6; this
/// struct only carries the correlation inputs: recent loss-event
/// instants and the per-ACK qdelay delta stream.
#[derive(Clone, Copy, Debug, Default)]
pub struct SbdStats {
    /// Ring of the last loss-event instants (µs, 0 = empty slot).
    pub loss_times_us: [u64; 8],
    /// Write cursor into `loss_times_us`.
    pub loss_cursor: u8,
    /// EWMA of per-ACK qdelay deltas (µs) — the correlation signal.
    pub qdelay_delta: f64,
    /// EWMA of |qdelay delta| — normalizes the correlation strength.
    pub qdelay_delta_abs: f64,
    /// Previous raw qdelay sample (µs) for delta computation.
    qdelay_prev: f64,
    have_qdelay: bool,
}

impl SbdStats {
    /// Feed one ACK's qdelay observation (O(1)).
    pub fn note_qdelay(&mut self, qdelay_us: f64) {
        if self.have_qdelay {
            let d = qdelay_us - self.qdelay_prev;
            self.qdelay_delta += (d - self.qdelay_delta) / 8.0;
            self.qdelay_delta_abs += (d.abs() - self.qdelay_delta_abs) / 8.0;
        } else {
            self.have_qdelay = true;
            self.qdelay_delta = 0.0;
            self.qdelay_delta_abs = 0.0;
        }
        self.qdelay_prev = qdelay_us;
    }

    /// Record a loss-event instant for cross-flow timing correlation.
    pub fn note_loss(&mut self, now: TransportInstant) {
        self.loss_times_us[self.loss_cursor as usize % 8] = now.micros();
        self.loss_cursor = self.loss_cursor.wrapping_add(1);
    }
}

/// The T6 decision interface: given two flows' statistics, judge how
/// correlated their congestion signals are. `None` = not enough data.
/// (RFC 8382 summary statistics; merge/split policy — including
/// D-A2's "宁可误拆不可误并" hysteresis — is implemented in T6.)
pub trait SharedBottleneckJudge {
    /// Correlation estimate ∈ [0,1] between two flows' signals.
    fn correlation(&self, a: &SbdStats, b: &SbdStats) -> Option<f64>;
}

/// Bounded log-odds congestion-belief accumulator (§2.3).
#[derive(Debug)]
pub struct Inference {
    /// Log-odds accumulator (all evidence).
    lo: f64,
    /// CE-attributable portion of `lo` — tracked separately so D-D2 can
    /// cap CE's contribution on untrusted paths.
    ce_lo: f64,
    /// Last update instant for RTT-scaled decay.
    last_update_us: u64,
    /// Current RTT estimate (µs) for decay normalization.
    rtt_us: f64,
    /// Controlled link (own infra on the origin side) → full CE weight;
    /// public-internet paths get D-D2's scaled+capped treatment.
    pub trusted_ecn: bool,
    /// Shared-bottleneck statistics (consumed by T6).
    pub sbd: SbdStats,
    /// Classic-ECN flag for the current path: CE events arrive as
    /// once-per-window events rather than byte counts.
    classic_ecn: bool,
    /// Ablation (§7.4): force the random-loss baseline to zero so every
    /// quiet loss counts as congestion evidence — classic-CC behavior.
    /// Production never sets it.
    pub prand_off: bool,
}

impl Default for Inference {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Inference {
    /// `trusted_ecn` — D-D2: true on controlled links (origin side to
    /// own infrastructure), false on the public Internet.
    pub fn new(trusted_ecn: bool) -> Self {
        Self {
            lo: 0.0,
            ce_lo: 0.0,
            last_update_us: 0,
            rtt_us: 0.0,
            trusted_ecn,
            sbd: SbdStats::default(),
            classic_ecn: false,
            prand_off: false,
        }
    }

    /// Mark the path as classic-ECN (once-per-window CE events) rather
    /// than AccECN byte counts.
    pub fn set_classic_ecn(&mut self, classic: bool) {
        self.classic_ecn = classic;
    }

    /// Current congestion belief ∈ [0,1).
    pub fn belief(&self) -> f64 {
        1.0 / (1.0 + (-self.lo).exp())
    }

    pub fn belief_milli(&self) -> u32 {
        (self.belief() * 1000.0) as u32
    }

    /// `queue_estimate` ≈ qdelay × bw_est — bytes we believe we hold in
    /// the bottleneck queue (§2.3). `None` until both inputs exist.
    pub fn queue_estimate(&self, model: &PathModel) -> Option<u64> {
        let bw = model.bw_est()? as f64;
        let qd = model.qdelay().as_micros() as f64;
        Some((qd * bw / 1e6) as u64)
    }

    /// DSACK/Eifel judged a retransmission spurious — negative evidence
    /// (§2.3): losses we repaired that were never lost should pull the
    /// belief back down.
    pub fn note_spurious_retx(&mut self) {
        self.lo = (self.lo + weights::DSACK_SPURIOUS).clamp(LO_MIN, LO_MAX);
    }

    /// Per-ACK update. `q_budget` is the tier's acceptable self-queue
    /// delay (§2.4 Q_budget); `in_flight_delta` is the change in
    /// in-flight bytes attributable to this event's window (positive
    /// when the sender expanded).
    ///
    /// Returns the updated belief.
    pub fn on_rate_sample(
        &mut self,
        rs: &RateSample,
        model: &PathModel,
        in_flight_delta: i64,
        q_budget: Duration,
        rtt: Duration,
    ) -> f64 {
        let now_us = rs.now.micros();
        // RTT-scaled decay toward 0 (§2.3: 每 RTT 衰减).
        let rtt_us = (rtt.as_micros() as f64).max(1.0);
        self.rtt_us = rtt_us;
        if self.last_update_us > 0 {
            let rtts = (now_us.saturating_sub(self.last_update_us)) as f64 / rtt_us;
            let decay = DECAY_PER_RTT.powf(rtts.min(32.0));
            self.lo *= decay;
            self.ce_lo *= decay;
        }
        self.last_update_us = now_us;

        // Shared-bottleneck statistics (input collection only; T6 judges).
        self.sbd.note_qdelay(model.qdelay().as_micros() as f64);

        let mut w = 0.0f64;

        // CE evidence — strongest (§2.3). AccECN: scaled by the marked
        // fraction; classic: a once-per-window event weight.
        if rs.delivered_ce > 0 {
            let w_ce = if self.classic_ecn {
                weights::CE_CLASSIC
            } else {
                let frac = (rs.delivered_ce as f64 / rs.delivered.max(1) as f64).min(1.0);
                weights::CE_ACCECN * frac
            };
            let w_ce = if self.trusted_ecn {
                w_ce
            } else {
                // D-D2: public-internet CE weight is limited and its
                // cumulative belief contribution is capped.
                w_ce * PUBLIC_CE_WEIGHT_SCALE
            };
            let headroom = if self.trusted_ecn {
                LO_MAX - self.ce_lo
            } else {
                PUBLIC_CE_LO_CAP - self.ce_lo
            };
            let applied = w_ce.clamp(0.0, headroom.max(0.0));
            self.ce_lo += applied;
            w += applied;
        }

        // qdelay over the tier budget while its gradient is positive.
        if model.qdelay() > q_budget && model.qdelay_grad_us_per_rtt() > 0.0 {
            w += weights::QDELAY_OVER_BUDGET;
        }

        if rs.lost > 0 {
            self.sbd.note_loss(rs.now);
            if model.qdelay() > model.qdelay_elevated_thresh() {
                w += weights::LOSS_WITH_QDELAY;
            } else {
                // Quiet loss counts only for the part above the random
                // baseline: weight = (loss_rate − p_rand)+ × scale.
                let total = (rs.delivered + rs.lost).max(1) as f64;
                let rate = rs.lost as f64 / total;
                let baseline = if self.prand_off {
                    0.0
                } else {
                    model.p_rand().unwrap_or(0.0)
                };
                let excess = (rate - baseline).max(0.0);
                w += weights::LOSS_QUIET_SCALE * excess;
            }
        }

        // inflight rising while delivery plateaus — compare the same
        // per-sample rate the model filtered.
        if in_flight_delta > 0 && rs.delivered > 0 {
            if let Some(est) = model.bw_est() {
                let rate = model.bw_last_sample();
                if rate <= est + est / 20 {
                    w += weights::PLATEAU_INFLIGHT_UP;
                }
            }
        }

        self.lo = (self.lo + w).clamp(LO_MIN, LO_MAX);
        self.belief()
    }

    /// Log-odds value — exposed for diagnostics/tests.
    pub fn log_odds(&self) -> f64 {
        self.lo
    }
}
