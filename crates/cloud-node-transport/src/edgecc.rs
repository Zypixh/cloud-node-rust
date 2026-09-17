//! EdgeCC — the unified congestion controller decision layer (plan §2.4).
//!
//! One [`EdgeCc`] instance per terminated flow (accepted or dialed). It
//! consumes [`PathModel`] estimates (§2.2) and [`Inference`] belief
//! (§2.3), applies the [`Envelope`] safety ceiling (§2.5), and emits a
//! congestion window + pacing rate through [`CongestionController`].
//!
//! # Single action committer (§2.4 单一控制权)
//!
//! Every round the controller picks exactly ONE action, in strict
//! priority:
//!
//! 1. **Recovery/safety** — RTO, PRR fast recovery, belief response,
//!    envelope set. Wins over everything.
//! 2. **Startup/drain** — prior-seeded or exponential start, queue
//!    drain to BDP.
//! 3. **base_rtt refresh** — coordinated down-probe when the floor is
//!    stale (§2.4 base_rtt 刷新).
//! 4. **Bandwidth probe** — uncertainty-driven dose-response trial
//!    (§2.4 不确定度驱动探测); at most one prober per aggregate (T6
//!    arbitrates via [`crate::aggregate`]).
//! 5. **Utility tune** — bounded ±ε paired trials (PCC-Vivace, D-E2).
//! 6. **Steady state** — dual-mode work point: `delay_target` when the
//!    delay signal is clean, `plateau_probe` when jitter swamps it.
//!
//! `reason_code` records every mode/target change (§2.1.6 可审计).
//!
//! # Units contract (§8 先固定单位)
//!
//! All rates are bytes/s, all windows bytes, all instants
//! [`TransportInstant`] µs. The Quinn adapter converts pacing to bits/s
//! at the boundary — never inside the algorithm.
//!
//! # Rounds
//!
//! A round ends when the ACK edge passes a byte that was sent after the
//! round began (BBR packet-conservation semantics, implemented via
//! `cum_ack` vs the sent-total snapshot taken at round start).

use crate::cc::parts::{HyStart, HystartVerdict, Prr};
use crate::cc::{CcSnapshot, CongestionController};
use crate::envelope::Envelope;
use crate::inference::Inference;
use crate::model::PathModel;
use crate::rate_sample::RateSample;
use crate::rtt::RttState;
use crate::TransportInstant;
use std::time::Duration;

// ---------------------------------------------------------------------
// Pinned constants (§2.4; T10 may retune — not a runtime config surface)
// ---------------------------------------------------------------------

/// Startup pacing gain (BBR STARTUP `pacing_gain` = 2/ln(2) ≈ 2.89;
/// plan §2.4 lists 2.77 as the candidate pending source check — we pin
/// the BBR value, which is the documented source for this mechanism).
const STARTUP_PACING_GAIN: f64 = 2.77;

/// Prior-seeded start (§2.4 启动): pace at ~½ prior bandwidth, cap
/// inflight at 1.5× prior BDP until verified by fresh delivery.
const PRIOR_BW_GAIN: f64 = 0.5;
const PRIOR_BDP_GAIN: f64 = 1.5;

/// Full-bandwidth exit test: delivery rate must keep growing for this
/// many consecutive rounds before startup considers the pipe full
/// (BBR `full_bw_cnt` = 3 rounds within 25%).
const FULL_BW_MARGIN: f64 = 0.25;
const FULL_BW_ROUNDS: u32 = 3;

/// Delay-target mode: qdelay goal as a fraction of base_rtt (Copa-style
/// δ; bounded so the target stays inside the tier budget).
const D_TARGET_BASE_FRAC: f64 = 0.125;
/// Bounded proportional rate step for delay-target mode
/// (Copa window change is bounded per RTT; we bound the *rate* step).
const DELAY_TARGET_STEP: f64 = 0.25;

/// Minimum probe duration (≥1 RTT per §2.4).
const PROBE_MIN_RTTS: u32 = 1;
/// Probe amplitude bounds as a fraction of bw_est — proportional to
/// uncertainty but bounded (§2.4 探测幅度与不确定度成比例（有上下限）).
const PROBE_AMP_MIN: f64 = 0.05;
const PROBE_AMP_MAX: f64 = 0.5;
/// Randomized horizon between spontaneous probes, in RTTs.
const PROBE_HORIZON_RTTS_MIN: u32 = 8;
const PROBE_HORIZON_RTTS_SPAN: u32 = 16;
/// Accept a probe when delivered rate grew by at least this fraction of
/// the attempted inflight increase (dose-response acceptance, BBRv3).
const PROBE_ACCEPT_MIN_GAIN: f64 = 0.5;

/// Belief response (§2.4): `inflight_lo = inflight × (1 − β·belief)`;
/// β caps the maximum single-round proportional cut.
const BELIEF_BETA: f64 = 0.7;
/// Belief above this is treated as congestion evidence for response.
const BELIEF_RESPOND_MILLI: u32 = 650;

/// Strong evidence → envelope set (§2.5): CE fraction or loss+qdelay.
const ENVELOPE_CE_FRAC: f64 = 0.5;
const ENVELOPE_LOSS_QDELAY_BYTES: u64 = 4 * 1460;

/// Steady pacing gain (deliver at estimated bandwidth, no overdrive).
const STEADY_PACING_GAIN: f64 = 1.0;
/// Delay-target mode pacing gain (Copa keeps a small margin).
const DELAY_PACING_GAIN: f64 = 1.0;

/// base_rtt refresh: when the floor has not been re-confirmed for this
/// horizon, take a coordinated down-probe (BBR ProbeRTT analog; §2.4
/// base_rtt 刷新 — bounded, never starves: capped at 4·MSS inflight for
/// at most `BASE_RTT_PROBE_RTTS` rounds then refill).
const BASE_RTT_STALE: Duration = Duration::from_secs(10);
const BASE_RTT_PROBE_RTTS: u32 = 1;
const BASE_RTT_PROBE_INFLIGHT_MSS: u64 = 4;

/// Utility tuner (D-E2, PCC-Vivace bounded): ±ε fraction of the current
/// rate, observation window in RTTs, cooldown between trials.
const UTILITY_EPSILON: f64 = 0.05;
const UTILITY_WINDOW_RTTS: u32 = 4;
const UTILITY_COOLDOWN_RTTS: u32 = 8;
/// Minimum lifetime (RTTs) and required stability before utility tuning
/// may run (§2.4 受限使用).
const UTILITY_MIN_AGE_RTTS: u32 = 5;
/// Utility noise gate: a utility delta below this fraction of |U| is a
/// tie — direction is not changed on noise.
const UTILITY_NOISE_FRAC: f64 = 0.02;
/// Fixed dimensionless weights for U = goodput^a − b·(rate·grad)+ −
/// c·rate·loss (D-E1 initial values; T10 sweep may retune, data only).
const UTILITY_A: f64 = 0.9;
const UTILITY_B: f64 = 1.0;
const UTILITY_C: f64 = 1.0;

/// Dual-mode hysteresis (§2.4 切换带迟滞): delay mode requires the
/// delay-signal quality above HI; it drops to plateau below LO.
const DSQ_ENTER_HI: f64 = 0.6;
const DSQ_EXIT_LO: f64 = 0.35;

/// Inflight floor: never target below 4·MSS (RWND/loss liveness).
/// Startup inflight cap once the model has a BDP estimate (BBR
/// startup cwnd_gain ≈ 2×BDP): unbounded doubling + HyStart's 3-round
/// fuse would otherwise overshoot a shallow buffer by ~an order of
/// magnitude.
const STARTUP_BDP_CAP: f64 = 2.0;

const MIN_INFLIGHT_MSS: u64 = 4;

/// Belief/loss-response inflight floor: 8×MSS, not the liveness floor —
/// a window of ~4 MSS turns every tail loss into an RTO (no trailing
/// segments left to generate the three dupacks fast recovery needs).
const RESPOND_FLOOR_MSS: u64 = 8;

/// Belief must hold above the gate for this many consecutive rounds
/// before the proportional cut applies — a single borderline sample
/// near the threshold must not pin the window (flicker → RTO churn).
const BELIEF_RESPOND_ROUNDS: u32 = 2;
/// Absolute inflight cap sanity bound (256 MiB — memory-governed paths
/// enforce tighter caps externally; this only prevents u64 silliness).
const MAX_INFLIGHT: u64 = 256 * 1024 * 1024;

/// Modes (CcSnapshot.mode value set, §8 reason tokens).
pub mod modes {
    pub const PACED_START: &str = "paced_start";
    pub const STARTUP: &str = "startup";
    pub const DRAIN: &str = "drain";
    pub const DELAY_TARGET: &str = "delay_target";
    pub const PLATEAU_PROBE: &str = "plateau_probe";
    pub const PROBE: &str = "probe";
    pub const UTILITY_TUNE: &str = "utility_tune";
    pub const BASE_RTT_PROBE: &str = "base_rtt_probe";
    pub const RECOVERY: &str = "recovery";
}

/// Reason tokens (CcSnapshot.reason_code — stable strings for /status).
pub mod reasons {
    pub const INIT: &str = "init";
    pub const PRIOR_START: &str = "prior_start";
    pub const PLATEAU_EXIT: &str = "plateau_exit";
    pub const HYSTART_EXIT: &str = "hystart_exit";
    pub const LOSS_EXIT: &str = "loss_exit";
    pub const CE_EXIT: &str = "ce_exit";
    pub const DRAIN_DONE: &str = "drain_done";
    pub const PROBE_START: &str = "probe_start";
    pub const PROBE_ACCEPT: &str = "probe_accept";
    pub const PROBE_REJECT: &str = "probe_reject";
    pub const MODE_DELAY: &str = "mode_delay";
    pub const MODE_PLATEAU: &str = "mode_plateau";
    pub const BELIEF_RESPONSE: &str = "belief_response";
    pub const CE_RESPONSE: &str = "ce_response";
    pub const RTO_RECOVER: &str = "rto_model_recover";
    pub const ENVELOPE_SET: &str = "envelope_set";
    pub const ENVELOPE_REFILL: &str = "envelope_refill";
    pub const BASE_RTT_REFRESH: &str = "base_rtt_refresh";
    pub const IDLE_RESTART: &str = "idle_restart";
    pub const MSS_UPDATE: &str = "mss_update";
    pub const UTILITY_TUNE: &str = "utility_tune";
    pub const AGG_CLAMP: &str = "agg_clamp";
}

/// Business tier (§2.4 `Q_budget(tier)`): the self-queue delay budget
/// the flow is allowed to stand. T0 = control progress, T1 =
/// completion-time sensitive, T2 = bulk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tier {
    /// Interactive / latency-sensitive: smallest queue budget.
    T0,
    /// Default tier.
    #[default]
    T1,
    /// Bulk: larger standing queue tolerated for throughput.
    T2,
}

impl Tier {
    /// Queue-delay budget for the dual-mode target and belief evidence.
    /// Relative to base_rtt where known; these are absolute floors.
    pub fn q_budget(&self, base_rtt: Option<Duration>) -> Duration {
        let base = base_rtt.unwrap_or(Duration::from_millis(50));
        let frac = match self {
            Tier::T0 => 0.10,
            Tier::T1 => 0.25,
            Tier::T2 => 0.50,
        };
        let floor = match self {
            Tier::T0 => Duration::from_millis(2),
            Tier::T1 => Duration::from_millis(5),
            Tier::T2 => Duration::from_millis(15),
        };
        floor.max(Duration::from_micros(
            (base.as_micros() as f64 * frac) as u64,
        ))
    }
}

/// Long-lived prior offered by `path_table` (§2.2/T6): capacity and
/// loss character measured on this path before the flow started.
#[derive(Clone, Copy, Debug, Default)]
pub struct PathPrior {
    /// Prior bandwidth estimate (bytes/s).
    pub bw_bps: u64,
    /// Prior base RTT.
    pub base_rtt: Duration,
    /// Prior random-loss baseline ∈ [0,1].
    pub p_rand: f64,
    /// Prior ECN alpha if the path marks.
    pub alpha: f64,
    /// Confidence ∈ [0,1] — scales how much the prior seeds startup.
    pub confidence: f64,
}

/// Ablation switches (§7.4): each flag removes one mechanism so its
/// marginal contribution is measurable against the full controller.
/// All-false is the only production-valid value.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ablations {
    /// No uncertainty-driven bandwidth probes.
    pub no_probe: bool,
    /// No paired ±ε utility tuning.
    pub no_utility: bool,
    /// No belief-proportional inflight floor — loss recovery still
    /// runs (PRR), only the belief-scaled cap is removed.
    pub no_belief: bool,
    /// Single steady mode: never enter plateau mode.
    pub no_plateau: bool,
}

/// State of an in-flight dose-response / bandwidth probe.
#[derive(Clone, Copy, Debug, Default)]
struct Probe {
    active: bool,
    /// Inflight target before the probe (restore on reject).
    base_inflight: u64,
    /// Delivery rate baseline at probe start (bytes/s).
    base_rate: u64,
    /// Attempted inflight increase (bytes).
    delta: u64,
    /// Round count inside the probe.
    rounds: u32,
    /// Best delivery rate observed during the probe.
    best_rate: u64,
}

/// Bounded PCC-Vivace utility tuner (D-E2). Paired ±ε trials: run at
/// rate·(1+ε) for a window, rate·(1−ε) for a window, compare U; move
/// the reference point toward the better side, hold on a tie.
#[derive(Clone, Copy, Debug, Default)]
struct Utility {
    /// 0 = idle, 1 = high arm, 2 = low arm, 3 = decided/cooldown.
    phase: u8,
    /// Reference rate the trial orbits (bytes/s).
    ref_rate: u64,
    /// Accumulated utility inputs for the current arm.
    arm_goodput: u64,
    arm_loss: u64,
    arm_grad_sum: f64,
    arm_samples: u64,
    /// Completed-arm utilities.
    u_high: Option<f64>,
    u_low: Option<f64>,
    /// Rounds left in current arm.
    rounds_left: u32,
    /// Cooldown rounds before the next trial.
    cooldown: u32,
    /// Rounds since flow start (age gate).
    age_rounds: u32,
}

/// Aggregate coordination handle (§2.6/T6). The controller *asks*;
/// it never mutates shared state itself. `None` = single-flow
/// aggregate (the degenerate case, not a disabled controller).
///
/// `!Send` by design — leases are worker-local `Rc<RefCell>` handles.
pub trait AggregateLease: std::fmt::Debug {
    /// Try to take the aggregate's single probe permit. False when
    /// another member is probing (§2.6 一次一个探测者).
    fn try_take_probe_permit(&mut self) -> bool;
    /// Return the permit (probe done, crashed round, or preemption).
    fn release_probe_permit(&mut self) {}
    /// Aggregate-level inflight share cap for this flow (§2.6 分配).
    /// `None` = no shared cap in effect.
    fn inflight_share_cap(&self) -> Option<u64> {
        None
    }
    /// Push this member's per-round stats into the aggregate (RFC 8382
    /// inputs + allocation fields). Called once per completed round —
    /// never per ACK. Default no-op for stub leases.
    fn push_stats(&self, _stats: crate::aggregate::MemberStats) {}
}

/// EdgeCC decision controller (plan §2.4). Pure algorithm — no I/O,
/// no allocation on the ACK path, deterministic given an event stream.
#[derive(Debug)]
pub struct EdgeCc {
    mss: u64,
    tier: Tier,
    pub model: PathModel,
    pub infer: Inference,
    pub envelope: Envelope,

    mode: &'static str,
    reason: &'static str,

    /// Current inflight target (bytes) — the cwnd equivalent.
    inflight_target: u64,
    /// Derived pacing rate bytes/s.
    pacing_bps: u64,

    /// Sent-byte total for round bookkeeping (packet conservation).
    sent_total: u64,
    /// cum_ack value that ends the current round (the ACK edge must
    /// pass a byte sent after the round began).
    round_end_cum: u64,
    /// Count of completed rounds (age/dosing units).
    rounds: u32,
    /// in_flight at previous rate sample (delta feeds inference).
    prev_in_flight: u64,

    /// inflight_lo — belief-proportional floor-in-response cap (§2.4).
    /// `None` when no belief response is active.
    inflight_lo: Option<u64>,
    /// Consecutive rounds with belief ≥ the response gate (hysteresis).
    belief_hi_rounds: u32,

    // --- startup ---
    hystart: HyStart,
    startup_full_bw: u64,
    startup_full_cnt: u32,
    prior: Option<PathPrior>,
    /// Inflight cap applied until prior is validated (prior mode only).
    prior_inflight_cap: Option<u64>,

    // --- steady state ---
    probe: Probe,
    /// Rounds until the next spontaneous uncertainty probe.
    probe_horizon: u32,
    /// Deterministic per-flow counter for randomized horizons (splitmix
    /// of sent_total — deterministic replay needs no RNG import).
    horizon_ctr: u64,
    utility: Utility,
    /// Probe permit borrowed from the aggregate (T6), if installed.
    agg_permit_held: bool,
    /// Probe trigger fired but the aggregate permit was denied —
    /// reported via `wants_probe` so the arbiter can grant it later.
    probe_want: bool,
    /// Last time base_rtt floor was confirmed (now-derived).
    base_rtt_confirmed_at: u64,
    base_probe_rounds_left: u32,
    last_srtt: Option<Duration>,
    /// Aggregate lease (installed by the T6 wiring layer).
    /// Boxed trait object: the aggregate owns the shared state; the
    /// controller only holds its permit/clamp channel.
    agg: Option<Box<dyn AggregateLease>>,

    // --- recovery ---
    prr: Prr,
    /// Eifel checkpoint: (inflight_target, mode) at loss entry.
    saved: Option<(u64, &'static str)>,
    /// Prior-good rate recorded at recovery entry (restore bound).
    recovery_entry_rate: u64,

    /// Ablation flag (§2.9 LossBlindRef): when set, the belief path
    /// sees loss-blinded samples while the model still sees true loss
    /// (recovery/PRR unchanged). Production controllers never set it.
    pub loss_blind: bool,
    /// §7.4 per-mechanism ablation switches.
    pub ablations: Ablations,
}

impl EdgeCc {
    /// New controller. `prior` seeds the paced start (§2.4 启动);
    /// `trusted_ecn` is the D-D2 controlled-link flag.
    pub fn new(mss: u64, tier: Tier, prior: Option<PathPrior>, trusted_ecn: bool) -> Self {
        let mss = mss.max(1);
        let mut cc = Self {
            mss,
            tier,
            model: PathModel::new(mss),
            infer: Inference::new(trusted_ecn),
            envelope: Envelope::new(),
            mode: modes::STARTUP,
            reason: reasons::INIT,
            inflight_target: MIN_INFLIGHT_MSS * mss,
            pacing_bps: 0,
            sent_total: 0,
            round_end_cum: 0,
            rounds: 0,
            prev_in_flight: 0,
            inflight_lo: None,
            belief_hi_rounds: 0,
            hystart: HyStart::new(),
            startup_full_bw: 0,
            startup_full_cnt: 0,
            prior,
            prior_inflight_cap: None,
            probe: Probe::default(),
            probe_horizon: PROBE_HORIZON_RTTS_MIN,
            horizon_ctr: 0x9e3779b97f4a7c15,
            utility: Utility::default(),
            agg_permit_held: false,
            probe_want: false,
            base_rtt_confirmed_at: 0,
            base_probe_rounds_left: 0,
            last_srtt: None,
            agg: None,
            prr: Prr::default(),
            saved: None,
            recovery_entry_rate: 0,
            loss_blind: false,
            ablations: Ablations::default(),
        };
        if let Some(p) = prior.filter(|p| p.bw_bps > 0 && p.confidence > 0.0) {
            // §2.4 启动: ~0.5× prior bw pacing, ≤1.5× prior BDP inflight,
            // immediately validated by fresh delivery samples.
            let conf = p.confidence.clamp(0.0, 1.0);
            let seed_bw = (p.bw_bps as f64 * PRIOR_BW_GAIN * conf) as u64;
            let prior_bdp = (p.bw_bps as f64 * p.base_rtt.as_secs_f64()) as u64;
            cc.pacing_bps = seed_bw.max(1);
            cc.prior_inflight_cap =
                Some(((prior_bdp as f64 * PRIOR_BDP_GAIN) as u64).max(4 * mss));
            cc.inflight_target = cc.prior_inflight_cap.unwrap_or(4 * mss);
            cc.mode = modes::PACED_START;
            cc.reason = reasons::PRIOR_START;
        }
        cc
    }

    /// Install the aggregate lease (T6). Called once at session setup.
    pub fn set_aggregate(&mut self, agg: Box<dyn AggregateLease>) {
        self.agg = Some(agg);
    }

    /// §5 migration seed: rebuild meaningful state from a snapshot —
    /// window, pacing and model priors carry; per-round episode
    /// machinery restarts at the delay-target mode.
    fn seed_from_cc_snapshot(&mut self, snap: &CcSnapshot) {
        self.inflight_target = snap.cwnd_bytes.max(self.mss.saturating_mul(2));
        if let Some(p) = snap.pacing_rate_bps {
            self.pacing_bps = p;
        }
        self.model
            .set_bw_bounds(snap.bandwidth_hi_bps, snap.bandwidth_lo_bps);
        let bw = snap
            .bandwidth_lo_bps
            .or(snap.bandwidth_hi_bps)
            .unwrap_or(0);
        if bw > 0 {
            self.prior = Some(PathPrior {
                bw_bps: bw,
                base_rtt: snap.min_rtt.unwrap_or_default(),
                p_rand: snap
                    .p_rand_milli
                    .map(|m| f64::from(m) / 1000.0)
                    .unwrap_or(0.0),
                alpha: snap
                    .ecn_alpha_milli
                    .map(|m| f64::from(m) / 1000.0)
                    .unwrap_or(0.0),
                confidence: 0.5,
            });
        }
        self.mode = modes::DELAY_TARGET;
        self.reason = "migrate_restore";
    }

    /// SplitMix64 step for deterministic randomized horizons.
    fn next_rand(&mut self) -> u64 {
        self.horizon_ctr ^= self.sent_total;
        self.horizon_ctr = self
            .horizon_ctr
            .wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.horizon_ctr;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    /// The inflight target after every applicable cap — envelope §2.5,
    /// belief response §2.4, aggregate share §2.6, sanity bounds.
    fn effective_target(&self) -> u64 {
        let mut t = self.inflight_target;
        if let Some(lo) = self.inflight_lo {
            t = t.min(lo);
        }
        t = self.envelope.clamp(t);
        if let Some(cap) = self.agg.as_ref().and_then(|a| a.inflight_share_cap()) {
            t = t.min(cap);
        }
        if let Some(cap) = self.prior_inflight_cap {
            t = t.min(cap);
        }
        t.clamp(MIN_INFLIGHT_MSS * self.mss, MAX_INFLIGHT)
    }

    /// Round completion check + rollover (BBR: a round ends when an ACK
    /// arrives covering a byte sent after the round began).
    fn maybe_advance_round(&mut self, rs: &RateSample) -> bool {
        if rs.cum_ack == 0 || self.round_end_cum == 0 {
            return false;
        }
        if rs.cum_ack > self.round_end_cum {
            self.rounds = self.rounds.saturating_add(1);
            self.utility.age_rounds = self.utility.age_rounds.saturating_add(1);
            self.round_end_cum = rs.cum_ack + 1; // provisional; on_sent re-arms
            return true;
        }
        false
    }

    /// Dual-mode pick with hysteresis (§2.4 双模控制).
    fn pick_steady_mode(&mut self) {
        if self.ablations.no_plateau {
            self.mode = modes::DELAY_TARGET;
            return;
        }
        let quality = self.model.delay_signal_quality().unwrap_or(0.0);
        match self.mode {
            modes::DELAY_TARGET => {
                if quality < DSQ_EXIT_LO {
                    self.mode = modes::PLATEAU_PROBE;
                    self.reason = reasons::MODE_PLATEAU;
                }
            }
            _ => {
                if quality > DSQ_ENTER_HI {
                    self.mode = modes::DELAY_TARGET;
                    self.reason = reasons::MODE_DELAY;
                } else {
                    self.mode = modes::PLATEAU_PROBE;
                    self.reason = reasons::MODE_PLATEAU;
                }
            }
        }
    }

    /// Steady-state work point (§2.4 工作点):
    /// `inflight = bw_est·base_rtt + Q_budget(tier)`, `pacing = bw_est·g`.
    fn steady_work_point(&mut self) {
        let bw = self.model.bw_est().or_else(|| self.model.bw_max());
        let base = self.model.base_rtt();
        let (bw, base) = match (bw, base) {
            (Some(b), Some(r)) if b > 0 => (b, r),
            _ => return, // no estimate yet — hold target
        };
        let q_budget = self.tier.q_budget(Some(base));
        let queue_bytes = (bw as f64 * q_budget.as_secs_f64()) as u64;
        let bdp = (bw as f64 * base.as_secs_f64()) as u64;
        let work = bdp.saturating_add(queue_bytes).max(MIN_INFLIGHT_MSS * self.mss);

        if self.mode == modes::DELAY_TARGET {
            // Copa-style bounded proportional step toward d_target.
            let d_target = q_budget.min(Duration::from_micros(
                (base.as_micros() as f64 * D_TARGET_BASE_FRAC) as u64,
            ));
            let qd = self.model.qdelay();
            let err = (d_target.as_secs_f64() - qd.as_secs_f64())
                / d_target.as_secs_f64().max(1e-9);
            let step = (err * DELAY_TARGET_STEP).clamp(-DELAY_TARGET_STEP, DELAY_TARGET_STEP);
            let adjusted = (self.inflight_target as f64 * (1.0 + step)) as u64;
            self.inflight_target = adjusted.max(MIN_INFLIGHT_MSS * self.mss).min(work.max(
                MIN_INFLIGHT_MSS * self.mss,
            ));
            self.pacing_bps = (bw as f64 * DELAY_PACING_GAIN) as u64;
        } else {
            // Plateau mode: hold the BDP+budget work point.
            self.inflight_target = work;
            self.pacing_bps = (bw as f64 * STEADY_PACING_GAIN) as u64;
        }
    }

    /// Belief-proportional response (§2.4): one bounded cut per round,
    /// `inflight_lo = inflight × (1 − β·belief)`. Never stacked with
    /// envelope or model cuts for the same event (single committer).
    fn belief_response(&mut self, in_flight: u64, round_done: bool) {
        if self.ablations.no_belief {
            return;
        }
        let belief_milli = self.infer.belief_milli();
        if belief_milli >= BELIEF_RESPOND_MILLI {
            if round_done {
                self.belief_hi_rounds = self.belief_hi_rounds.saturating_add(1);
            }
            if self.belief_hi_rounds >= BELIEF_RESPOND_ROUNDS
                || self.inflight_lo.is_some()
            {
                let keep = 1.0 - BELIEF_BETA * (belief_milli as f64 / 1000.0);
                let lo = (in_flight.max(self.inflight_target) as f64 * keep) as u64;
                self.inflight_lo = Some(lo.max(RESPOND_FLOOR_MSS * self.mss));
                self.reason = reasons::BELIEF_RESPONSE;
            }
        } else {
            if round_done {
                self.belief_hi_rounds = 0;
            }
            if self.inflight_lo.is_some() {
                // Belief decayed below the gate — release the cap
                // gradually: refill toward the target, not an instant
                // uncap.
                let target = self.inflight_target;
                let lo = self.inflight_lo.unwrap_or(target);
                let next = lo + (target.saturating_sub(lo)) / 2;
                self.inflight_lo =
                    (next < target).then_some(next.max(MIN_INFLIGHT_MSS * self.mss));
                if self.inflight_lo.is_none() {
                    self.reason = reasons::ENVELOPE_REFILL;
                }
            }
        }
    }

    /// Uncertainty-driven probe (§2.4): dose-response trial.
    /// Trigger: high bw_sigma/bw_est, expired randomized horizon, or a
    /// prior showing higher capacity. Requires the aggregate's single
    /// probe permit (T6) — denied permits defer, never duplicate.
    fn maybe_probe(&mut self, rs: &RateSample) {
        if self.ablations.no_probe {
            return;
        }
        if self.probe.active {
            // Inside a trial: hold the raised inflight ≥1 RTT, then judge.
            self.probe.rounds += 1;
            self.probe.best_rate = self.probe.best_rate.max(rs.delivery_rate_bps());
            if self.probe.rounds >= PROBE_MIN_RTTS {
                let required = self.probe.base_rate
                    + (self.probe.delta as f64 * PROBE_ACCEPT_MIN_GAIN
                        / self.last_srtt.unwrap_or(Duration::from_millis(1)).as_secs_f64())
                        as u64;
                if self.probe.best_rate >= required {
                    // Accept: keep the expanded work point; lift bw_lo.
                    self.reason = reasons::PROBE_ACCEPT;
                    let rate = self.probe.best_rate;
                    let (hi, lo) = (self.model.bw_hi(), self.model.bw_lo());
                    self.model
                        .set_bw_bounds(hi, Some(lo.unwrap_or(0).max(rate)));
                } else {
                    // Reject: restore; the refusal is dose-response
                    // evidence — record bw_hi at the attempted rate.
                    self.inflight_target = self.probe.base_inflight;
                    let attempted = (self.probe.delta as f64
                        / self.last_srtt.unwrap_or(Duration::from_millis(1)).as_secs_f64())
                        as u64
                        + self.probe.base_rate;
                    let (hi, lo) = (self.model.bw_hi(), self.model.bw_lo());
                    self.model
                        .set_bw_bounds(Some(hi.map_or(attempted, |h| h.min(attempted))), lo);
                    self.reason = reasons::PROBE_REJECT;
                }
                self.probe = Probe::default();
                self.release_probe_permit();
                self.probe_horizon = PROBE_HORIZON_RTTS_MIN
                    + (self.next_rand() as u32 % PROBE_HORIZON_RTTS_SPAN);
            }
            return;
        }

        if self.probe_horizon > 0 {
            self.probe_horizon -= 1;
        }
        let uncertainty = match (self.model.bw_sigma(), self.model.bw_est()) {
            (Some(s), Some(e)) if e > 0 => s as f64 / e as f64,
            _ => 0.0,
        };
        let prior_says_more = self
            .prior
            .map(|p| {
                p.bw_bps
                    > self.model.bw_est().unwrap_or(0) * 2
                    && p.confidence > 0.3
            })
            .unwrap_or(false);
        let trigger = uncertainty > 0.3 || self.probe_horizon == 0 || prior_says_more;
        if !trigger {
            return;
        }
        // One prober per aggregate (§2.6).
        if let Some(agg) = self.agg.as_mut() {
            if !self.agg_permit_held && !agg.try_take_probe_permit() {
                self.probe_want = true; // deferred, not duplicated
                return;
            }
            self.agg_permit_held = true;
        }
        self.probe_want = false;
        let amp = (PROBE_AMP_MIN + uncertainty).clamp(PROBE_AMP_MIN, PROBE_AMP_MAX);
        let delta = (self.inflight_target as f64 * amp) as u64;
        self.probe = Probe {
            active: true,
            base_inflight: self.inflight_target,
            base_rate: self.model.bw_est().unwrap_or(0),
            delta: delta.max(self.mss),
            rounds: 0,
            best_rate: 0,
        };
        self.inflight_target = self
            .inflight_target
            .saturating_add(delta.max(self.mss));
        self.mode = modes::PROBE;
        self.reason = reasons::PROBE_START;
        // Causal-test window for the post-speedup loss check (§2.2).
        self.model
            .note_speedup(rs.now, self.last_srtt.unwrap_or(Duration::from_millis(10)) * 3);
    }

    fn release_probe_permit(&mut self) {
        if self.agg_permit_held {
            if let Some(agg) = self.agg.as_mut() {
                agg.release_probe_permit();
            }
            self.agg_permit_held = false;
        }
    }

    /// Bounded ±ε utility tuner (PCC-Vivace, D-E2). Two arms per trial,
    /// each `UTILITY_WINDOW_RTTS` rounds, then a cooldown. Never runs
    /// concurrently with a bandwidth probe (same coordinator, §2.4).
    fn maybe_utility(&mut self, rs: &RateSample) {
        if self.ablations.no_utility {
            return;
        }
        let u = &mut self.utility;
        u.arm_goodput += rs.delivered;
        u.arm_loss += rs.lost;
        u.arm_grad_sum += self.model.qdelay_grad_us_per_rtt();
        u.arm_samples += 1;

        if u.cooldown > 0 {
            u.cooldown -= 1;
            return;
        }
        if u.age_rounds < UTILITY_MIN_AGE_RTTS
            || rs.is_app_limited
            || self.probe.active
            || self.mode == modes::RECOVERY
        {
            return;
        }
        if u.phase == 0 {
            // Start a trial around the current pacing rate.
            let Some(bw) = self.model.bw_est() else { return };
            u.ref_rate = bw.max(1);
            u.phase = 1;
            u.rounds_left = UTILITY_WINDOW_RTTS;
            u.arm_goodput = 0;
            u.arm_loss = 0;
            u.arm_grad_sum = 0.0;
            u.arm_samples = 0;
            self.mode = modes::UTILITY_TUNE;
            self.reason = reasons::UTILITY_TUNE;
            return;
        }
        if u.rounds_left > 0 {
            u.rounds_left -= 1;
            // Apply the arm's rate.
            let sign = if u.phase == 1 { 1.0 } else { -1.0 };
            let rate = (u.ref_rate as f64 * (1.0 + sign * UTILITY_EPSILON)) as u64;
            self.pacing_bps = rate.max(1);
            let base = self.model.base_rtt().unwrap_or(Duration::from_millis(50));
            let bdp = (rate as f64 * base.as_secs_f64()) as u64;
            self.inflight_target = (bdp as f64
                + self.tier.q_budget(Some(base)).as_secs_f64() * rate as f64) as u64;
            return;
        }
        // Arm complete: score it.
        let norm = u.ref_rate.max(1) as f64;
        let goodput = u.arm_goodput as f64;
        let loss_rate = u.arm_loss as f64 / (u.arm_goodput + u.arm_loss).max(1) as f64;
        let grad = (u.arm_grad_sum / u.arm_samples.max(1) as f64).max(0.0);
        let util = goodput.powf(UTILITY_A)
            - UTILITY_B * norm * grad.max(0.0)
            - UTILITY_C * norm * loss_rate;
        match u.phase {
            1 => {
                u.u_high = Some(util);
                u.phase = 2;
                u.rounds_left = UTILITY_WINDOW_RTTS;
                u.arm_goodput = 0;
                u.arm_loss = 0;
                u.arm_grad_sum = 0.0;
                u.arm_samples = 0;
            }
            2 => {
                u.u_low = Some(util);
                u.phase = 3;
            }
            _ => {
                // Decide: move the reference toward the better arm;
                // a tie below the noise gate holds position.
                let (hi, lo) = (u.u_high.unwrap_or(0.0), u.u_low.unwrap_or(0.0));
                let noise = hi.abs().max(lo.abs()).max(1.0) * UTILITY_NOISE_FRAC;
                if hi - lo > noise {
                    u.ref_rate = (u.ref_rate as f64 * (1.0 + UTILITY_EPSILON)) as u64;
                } else if lo - hi > noise {
                    u.ref_rate = (u.ref_rate as f64 * (1.0 - UTILITY_EPSILON)) as u64;
                }
                // Re-anchor the work point at the tuned rate.
                let base = self.model.base_rtt().unwrap_or(Duration::from_millis(50));
                let bdp = (u.ref_rate as f64 * base.as_secs_f64()) as u64;
                self.inflight_target = (bdp as f64
                    + self.tier.q_budget(Some(base)).as_secs_f64() * u.ref_rate as f64)
                    as u64;
                self.pacing_bps = u.ref_rate;
                u.phase = 0;
                u.u_high = None;
                u.u_low = None;
                u.cooldown = UTILITY_COOLDOWN_RTTS;
                self.pick_steady_mode();
            }
        }
    }

    /// base_rtt coordinated down-probe (§2.4): when the floor is stale,
    /// briefly hold inflight at 4·MSS to drain the queue and take a
    /// clean sample. Never starves — bounded to BASE_RTT_PROBE_RTTS.
    fn maybe_base_rtt_probe(&mut self, now: TransportInstant) -> bool {
        if self.base_probe_rounds_left > 0 {
            self.base_probe_rounds_left -= 1;
            if self.base_probe_rounds_left == 0 {
                self.pick_steady_mode();
            }
            return true;
        }
        let stale = now
            .micros()
            .saturating_sub(self.base_rtt_confirmed_at)
            > BASE_RTT_STALE.as_micros() as u64
            && self.base_rtt_confirmed_at > 0;
        if stale && !self.probe.active && self.utility.phase == 0 {
            self.mode = modes::BASE_RTT_PROBE;
            self.reason = reasons::BASE_RTT_REFRESH;
            self.base_probe_rounds_left = BASE_RTT_PROBE_RTTS;
            self.inflight_target = BASE_RTT_PROBE_INFLIGHT_MSS * self.mss;
            return true;
        }
        false
    }

    /// Strong-evidence → envelope set (§2.5). One set per round max.
    fn envelope_check(&mut self, rs: &RateSample, in_flight: u64) {
        let ce_strong = rs.delivered > 0
            && (rs.delivered_ce as f64 / rs.delivered as f64) >= ENVELOPE_CE_FRAC;
        let loss_qdelay = rs.lost >= ENVELOPE_LOSS_QDELAY_BYTES.min(rs.delivered + rs.lost)
            && rs.lost > 0
            && self.model.qdelay() > self.model.qdelay_elevated_thresh();
        let policer = self.model.lt_bw().is_some();
        if ce_strong || loss_qdelay {
            self.envelope
                .set_default(in_flight.max(self.mss), reasons::ENVELOPE_SET);
            if ce_strong {
                self.reason = reasons::CE_RESPONSE;
            }
        }
        if policer {
            // BBRv1 lt_bw verdict pins the rate ceiling too.
            if let Some(lt) = self.model.lt_bw() {
                self.pacing_bps = self.pacing_bps.min(lt);
            }
        }
    }
}

impl CongestionController for EdgeCc {
    fn on_sent(&mut self, _now: TransportInstant, bytes: u64, _in_flight: u64, _is_app_limited: bool) {
        self.sent_total = self.sent_total.saturating_add(bytes);
        self.prr.note_sent(bytes);
        // Arm the next round boundary at the latest sent edge — a round
        // ends when cum_ack passes a byte sent after the round began.
        if self.round_end_cum == 0 {
            self.round_end_cum = self.sent_total;
        }
    }

    fn on_rate_sample(&mut self, rs: &RateSample, in_flight: u64, rtt: &RttState) {
        let now = rs.now;
        let in_flight_delta = in_flight as i64 - self.prev_in_flight as i64;
        self.prev_in_flight = in_flight;
        if let Some(s) = rtt.srtt {
            self.last_srtt = Some(s);
        }

        // Model + inference always see the sample (§2.2/§2.3). The
        // LossBlind ablation zeroes the belief-path loss evidence only —
        // the model still gets true loss (recovery and p_rand need it).
        self.model.on_rate_sample(rs, in_flight, rtt);
        let rtt_d = rtt.srtt.or(rs.rtt).unwrap_or(Duration::from_millis(1));
        let belief_sample;
        let rs_for_belief = if self.loss_blind {
            belief_sample = RateSample { lost: 0, ..*rs };
            &belief_sample
        } else {
            rs
        };
        self.infer.on_rate_sample(
            rs_for_belief,
            &self.model,
            in_flight_delta,
            self.tier.q_budget(self.model.base_rtt()),
            rtt_d,
        );

        // Round bookkeeping: base_rtt floor re-confirmation.
        if let Some(base) = self.model.base_rtt()
            && let Some(r) = rs.rtt
            && r <= base + base / 8
        {
            self.base_rtt_confirmed_at = now.micros();
        }
        if self.base_rtt_confirmed_at == 0 {
            self.base_rtt_confirmed_at = now.micros();
        }
        let round_done = self.maybe_advance_round(rs);
        if round_done {
            self.envelope.on_round(self.infer.belief_milli());
            if self.envelope.reason_code() == reasons::ENVELOPE_REFILL {
                self.reason = reasons::ENVELOPE_REFILL;
            }
            // Per-round member report to the aggregate (§2.6): RFC 8382
            // correlation inputs + allocation fields + probe intent.
            if let Some(agg) = self.agg.as_ref() {
                agg.push_stats(crate::aggregate::MemberStats {
                    loss_times_us: self.infer.sbd.loss_times_us,
                    qdelay_delta: self.infer.sbd.qdelay_delta,
                    qdelay_delta_abs: self.infer.sbd.qdelay_delta_abs,
                    inflight: in_flight,
                    rate_bps: self.model.bw_last_sample(),
                    tier: self.tier as u8,
                    progress_ctr: self.rounds as u64,
                    wants_probe: self.probe_want,
                });
            }
        }

        // ---- single action committer, strict priority ----

        // 1. Recovery: PRR window law while active.
        if self.prr.active {
            if let Some(cwnd) = self.prr.on_ack(
                rs.delivered,
                rs.cum_ack,
                in_flight,
                self.effective_target(),
                self.mss,
                now,
            ) {
                self.inflight_target = cwnd;
                if !self.prr.active {
                    self.mode = modes::DRAIN;
                    self.reason = reasons::DRAIN_DONE;
                    self.saved = None;
                }
            }
            return;
        }

        // Envelope set + belief response are safety actions — they
        // adjust caps but don't consume the round's committer slot;
        // the committer only picks mode/target below.
        self.envelope_check(rs, in_flight);
        self.belief_response(in_flight, round_done);

        // 2. Startup / paced start.
        match self.mode {
            modes::STARTUP | modes::PACED_START => {
                if self.hystart.baseline_min().is_none()
                    && let Some(b) = rs.rtt.or(rtt.min_rtt)
                {
                    self.hystart.seed_baseline(b, self.sent_total);
                }
                match self.hystart.on_ack(rs.rtt, rs.cum_ack, self.sent_total) {
                    HystartVerdict::Exit => {
                        self.mode = modes::DRAIN;
                        self.reason = reasons::HYSTART_EXIT;
                        return;
                    }
                    HystartVerdict::ElevatedRound => {}
                    HystartVerdict::Continue => {}
                }
                // Exponential-ish start: grow inflight by the delivered
                // bytes (ABC) while pacing at the startup gain.
                self.inflight_target = self
                    .inflight_target
                    .saturating_add(rs.acked_sacked)
                    .min(self.prior_inflight_cap.unwrap_or(MAX_INFLIGHT));
                // Cap = STARTUP_BDP_CAP × bw_est × base_rtt. base_rtt
                // (not srtt) — a growing queue inflates srtt and would
                // raise the cap with the very overshoot it bounds.
                if let (Some(bw), Some(base)) =
                    (self.model.bw_est(), self.model.base_rtt())
                {
                    let bdp = bw as f64 * base.as_secs_f64();
                    let capped = ((bdp * STARTUP_BDP_CAP) as u64)
                        .max(MIN_INFLIGHT_MSS * self.mss);
                    self.inflight_target = self.inflight_target.min(capped);
                }
                // Pacing must never collapse when the sampler has no
                // interval yet (delivery_rate_bps()==0): fall back to
                // inflight_target/rtt — the rate a full window implies.
                let bw = rs.delivery_rate_bps().max(
                    (self.inflight_target as u128 * 1_000_000
                        / rtt_d.as_micros().max(1)) as u64,
                );
                self.pacing_bps = (bw as f64 * STARTUP_PACING_GAIN) as u64;
                // Full-bandwidth exit: delivery stops growing.
                if round_done && !rs.is_app_limited {
                    let rate = rs.delivery_rate_bps();
                    if rate >= self.startup_full_bw
                        && rate <= self.startup_full_bw + self.startup_full_bw / 4
                    {
                        self.startup_full_cnt += 1;
                    } else if rate as f64
                        > self.startup_full_bw as f64 * (1.0 + FULL_BW_MARGIN)
                    {
                        self.startup_full_cnt = 0;
                        self.startup_full_bw = rate;
                    }
                    if self.startup_full_cnt >= FULL_BW_ROUNDS {
                        self.mode = modes::DRAIN;
                        self.reason = reasons::PLATEAU_EXIT;
                        self.prior_inflight_cap = None; // prior validated
                        return;
                    }
                }
                // Loss/CE exit from startup (§2.4: 丢包与 CE 负责退出).
                if rs.lost >= self.mss || (rs.delivered_ce > 0 && rs.delivered > 0) {
                    self.mode = modes::DRAIN;
                    self.reason = if rs.lost > 0 {
                        reasons::LOSS_EXIT
                    } else {
                        reasons::CE_EXIT
                    };
                    return;
                }
                return;
            }
            modes::DRAIN => {
                // Drain to BDP, then steady state.
                if let Some(bdp) = self.model.bdp_est() {
                    self.inflight_target = self
                        .inflight_target
                        .min(bdp.max(MIN_INFLIGHT_MSS * self.mss));
                    self.pick_steady_mode();
                    return;
                }
                self.inflight_target =
                    (self.inflight_target as f64 * 0.9) as u64;
                if self.inflight_target <= MIN_INFLIGHT_MSS * self.mss * 2 {
                    self.pick_steady_mode();
                }
                return;
            }
            _ => {}
        }

        // 3. base_rtt refresh (bounded down-probe).
        if self.maybe_base_rtt_probe(now) {
            return;
        }

        // 4/5. Probe / utility (never concurrent — same coordinator).
        self.maybe_probe(rs);
        if self.probe.active {
            return;
        }
        self.maybe_utility(rs);
        if self.utility.phase != 0 && self.utility.cooldown == 0 {
            return;
        }

        // 6. Steady state.
        self.steady_work_point();
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
            self.saved = self
                .saved
                .or(Some((self.inflight_target, self.mode)));
            self.recovery_entry_rate = self.model.bw_est().unwrap_or(0);
            // Envelope: loss is strong evidence only with qdelay (§2.5).
            if self.model.qdelay() > self.model.qdelay_elevated_thresh() {
                self.envelope
                    .set_default(in_flight.max(self.mss), reasons::ENVELOPE_SET);
            }
            // Belief-proportional inflight_lo (single cut, no stacking).
            if !self.ablations.no_belief {
                let keep = 1.0 - BELIEF_BETA * self.infer.belief();
                self.inflight_lo = Some(
                    ((in_flight as f64 * keep) as u64).max(RESPOND_FLOOR_MSS * self.mss),
                );
            }
            self.prr.enter(in_flight, self.sent_total + 1);
            self.mode = modes::RECOVERY;
            self.reason = reasons::LOSS_EXIT;
            self.release_probe_permit();
            self.probe = Probe::default();
            self.utility.phase = 0;
        }
    }

    fn on_ecn_ce(&mut self, now: TransportInstant, ce_bytes: u64, delivered: u64, in_flight: u64) {
        // Classic-ECN once-per-window event: the model's per-ACK EWMA
        // sees byte-grain fractions; a classic event is coarser — feed
        // belief through the inference path only (already done in
        // on_rate_sample via delivered_ce), and respond here at
        // event granularity (§2.4: CE 比例充分 → alpha 型响应).
        let _ = now;
        if delivered > 0 && ce_bytes * 2 >= delivered {
            self.envelope
                .set_default(in_flight.max(self.mss), reasons::ENVELOPE_SET);
            self.reason = reasons::CE_RESPONSE;
        }
    }

    fn on_rto(&mut self, now: TransportInstant, in_flight: u64) {
        let _ = now;
        // RTO is the strongest evidence: ceiling at current inflight
        // (minus headroom), rate floored, model keeps its state for
        // bounded recovery (§2.4: 不能凭陈旧 BDP 立即发满).
        self.envelope
            .set_default(in_flight.max(self.mss), reasons::ENVELOPE_SET);
        self.inflight_lo = Some(MIN_INFLIGHT_MSS * self.mss);
        self.inflight_target = MIN_INFLIGHT_MSS * self.mss;
        self.pacing_bps = 0;
        self.prr = Prr::default();
        self.probe = Probe::default();
        self.release_probe_permit();
        self.utility.phase = 0;
        self.mode = modes::STARTUP;
        self.reason = reasons::RTO_RECOVER;
        self.startup_full_bw = 0;
        self.startup_full_cnt = 0;
    }

    fn on_loss_undo(&mut self, now: TransportInstant) {
        // Eifel/DSACK: restore the checkpointed target and mode; the
        // model's spurious accounting adjusts belief separately.
        self.model.note_spurious_retx(self.mss);
        self.infer.note_spurious_retx();
        if let Some((target, mode)) = self.saved.take() {
            self.inflight_target = target;
            self.inflight_lo = None;
            self.mode = mode;
            self.reason = reasons::BASE_RTT_REFRESH; // closest audit token
            self.prr = Prr::default();
        }
        let _ = now;
    }

    fn on_idle_restart(&mut self, _now: TransportInstant, idle_for: Duration) {
        // §2.4 启动: bounded restart — no instant refill to a stale BDP.
        // Halve the target per idle RTT (bounded), keep the model.
        let rtt = self.last_srtt.unwrap_or(Duration::from_millis(1));
        let mut restart = self.inflight_target;
        let mut idle = idle_for;
        while idle > rtt && restart > self.mss {
            restart /= 2;
            idle = idle.saturating_sub(rtt);
        }
        self.inflight_target = restart.max(MIN_INFLIGHT_MSS * self.mss).min(self.inflight_target);
        self.inflight_lo = None;
        self.reason = reasons::IDLE_RESTART;
    }

    fn on_mss_update(&mut self, mss: u64) {
        self.mss = mss.max(1);
        self.inflight_target = self.inflight_target.max(self.mss);
        self.reason = reasons::MSS_UPDATE;
    }

    fn cwnd(&self) -> u64 {
        self.effective_target()
    }

    fn pacing_rate(&self) -> Option<u64> {
        (self.pacing_bps > 0).then_some(self.pacing_bps)
    }

    fn snapshot(&self) -> CcSnapshot {
        CcSnapshot {
            algo: "edgecc",
            version_pin: "edgecc-v1",
            mode: self.mode,
            cwnd_bytes: self.effective_target(),
            ssthresh_bytes: u64::MAX / 2,
            pacing_rate_bps: self.pacing_rate(),
            min_rtt: self.model.base_rtt(),
            bandwidth_hi_bps: self.model.bw_hi(),
            bandwidth_lo_bps: self.model.bw_lo(),
            inflight_hi_bytes: self.envelope.ceiling(),
            inflight_lo_bytes: self.inflight_lo,
            extra_acked_bytes: Some(self.model.extra_acked()),
            ecn_alpha_milli: self.model.alpha().map(|a| (a * 1000.0) as u32),
            belief_milli: Some(self.infer.belief_milli()),
            queue_estimate_bytes: self.infer.queue_estimate(&self.model),
            p_rand_milli: self.model.p_rand().map(|p| (p * 1000.0) as u32),
            bw_sigma_bps: self.model.bw_sigma(),
            envelope_bytes: self.envelope.ceiling(),
            reason_code: self.reason,
        }
    }

    fn seed_from_snapshot(&mut self, snap: &CcSnapshot) {
        self.seed_from_cc_snapshot(snap);
    }
}
