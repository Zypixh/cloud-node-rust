//! EdgeCC — the unified congestion controller decision layer (plan §2.4).
//!
//! One [`EdgeCc`] instance per terminated flow (accepted or dialed). It
//! consumes [`PathModel`] estimates (§2.2) and [`Inference`] belief
//! (§2.3), applies the [`Envelope`] safety ceiling (§2.5), and emits a
//! congestion window + pacing rate through [`CongestionController`].
//!
//! # BDP-assignment work point (skyline-style, §2.4 改造)
//!
//! The window law is a direct assignment, not an incremental control:
//! every ACK the inflight target is recomputed as
//! `bw × base_rtt × gain × 1/(1−p)` — the measured BDP times a mode
//! gain, inflated for the path's own quiet-path loss rate. Loss itself
//! never shrinks the window: on high-p_rand WAN links the loss stream
//! carries no congestion information, and collapsing the window on
//! every random drop is what kept the old law pinned in recovery.
//!
//! Two modes only:
//!
//! - **startup** — shared gain `STARTUP_GAIN` for cwnd and pacing;
//!   exits to cruise on a bandwidth plateau (growth below
//!   `STARTUP_GROWTH_RATIO` for `STARTUP_PLATEAU_ROUNDS` rounds) or on
//!   a tripped guardrail. Without a bandwidth estimate it falls back
//!   to ACK-clocked growth (TCP slow-start analog).
//! - **cruise** — cwnd gain `CRUISE_INFLIGHT_GAIN` (deliberately
//!   generous; the window only needs to not be the limiter) and pacing
//!   gain `CRUISE_PACING_GAIN` — the pacing rate is the real limiter
//!   and the >1.0 gain is how the bandwidth estimate keeps refreshing.
//!
//! The congestion signals are queue delay and ECN: when `qdelay`
//! exceeds the tier-scaled guardrail threshold or a CE mark arrives,
//! `queue_clamped` engages for that round and both gains drop to
//! `GUARDRAIL_GAIN` (and loss inflation is suppressed — extra window
//! is what the clamp drains). The envelope (§2.5) stays as an outer
//! safety ceiling for strong-CE events and aggregate share caps; PRR
//! bookkeeping still tracks recovery for observability but no longer
//! governs the window — retransmission pacing is the stack's job.
//!
//! # Guardrail-blind paths (shallow-buffer, short-RTT)
//!
//! The delay guardrail is structurally blind where the bottleneck
//! queue drains faster than the tier floor can measure: on a 5 ms RTT
//! link one BDP of standing queue adds ~5 ms of delay, far under the
//! T1 floor of 70 ms. Where `base_rtt < guardrail_thresh` the
//! controller therefore substitutes loss-free rate evidence:
//!
//! - **slope bound on work rate** — the confirmed-delivered slope
//!   (windowed / proven-peak / lifetime, all cum-based and immune to
//!   per-sample ACK compression) caps the work estimate so inflated
//!   delivery samples cannot detonate the BDP assignment;
//! - **proven-window cap on inflight** — the target is additionally
//!   clipped to ~3× the proven window (slope × RTT): nothing else
//!   stops an inflated work rate from parking several buffer-loads in
//!   the pipe;
//! - **self-inflicted-loss clamp** — a loss taken while inflight
//!   exceeds 1.5× the proven window is buffer-overflow evidence and
//!   engages the clamp for ~2 srtt; a loss observed *after the flight
//!   has drained below ~1.2× the proven window* disproves the
//!   self-infliction hypothesis (external loss) and disables the test
//!   for ~8 srtt. Drain-backlog drops are deliberately not counted as
//!   disproof.
//!
//! On WAN paths (base_rtt ≥ threshold) none of this applies: the
//! delay guardrail sees a standing queue, the work rate follows the
//! EWMA estimate directly, and a stall-diluted slope bound would
//! throttle the recovery burst — a self-fulfilling depression.
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

use crate::TransportInstant;
use crate::cc::parts::{HyStart, HystartVerdict, Prr};
use crate::cc::{CcSnapshot, CongestionController};
use crate::envelope::Envelope;
use crate::inference::Inference;
use crate::model::PathModel;
use crate::rate_sample::RateSample;
use crate::rtt::RttState;
use std::time::Duration;

// ---------------------------------------------------------------------
// Pinned constants (§2.4; T10 may retune — not a runtime config surface)
// ---------------------------------------------------------------------

/// Startup gain — shared by the cwnd target and the pacing rate while
/// the bandwidth estimate is still climbing (upstream `startup_gain`).
const STARTUP_GAIN: f64 = 3.0;

/// Prior-seeded start (§2.4 启动): pace at ~½ prior bandwidth, cap
/// inflight at 1.5× prior BDP until verified by fresh delivery.
const PRIOR_BW_GAIN: f64 = 0.5;
const PRIOR_BDP_GAIN: f64 = 1.5;

/// Startup plateau exit (upstream `startup_growth_ratio` /
/// `startup_plateau_rtts`): bandwidth growth below the ratio for this
/// many consecutive rounds means the pipe is full — switch to cruise.
const STARTUP_GROWTH_RATIO: f64 = 0.20;
const STARTUP_PLATEAU_ROUNDS: u32 = 5;

/// Cruise cwnd-target gain (upstream `cruise_inflight_gain`) —
/// deliberately generous; the window only needs to not be the
/// limiter, the pacing rate below is.
const CRUISE_INFLIGHT_GAIN: f64 = 3.0;
/// Cruise pacing gain (upstream `cruise_pacing_gain`) — the real rate
/// limiter; >1.0 keeps the bandwidth estimate refreshing since cruise
/// has no separate probing episode.
const CRUISE_PACING_GAIN: f64 = 1.25;
/// Guardrail gain (upstream `guardrail_gain`): applied to both the
/// cwnd target and pacing while `queue_clamped` — an active cut to
/// 80% of the measured rate, not merely "stop accelerating".
const GUARDRAIL_GAIN: f64 = 0.8;

/// Loss-inflation cap on `p` in `1/(1−p)` (upstream
/// `loss_inflation_max_ratio`, high-random-loss profile): at most
/// ×2.0 send-rate compensation for the measured quiet-path loss rate.
const LOSS_INFLATION_MAX: f64 = 0.5;

/// Strong evidence → envelope set (§2.5): CE fraction. Loss+qdelay no
/// longer sets the ceiling — the per-round queue guardrail owns that
/// response now and cannot ratchet the way a sticky ceiling could.
const ENVELOPE_CE_FRAC: f64 = 0.5;

const MIN_INFLIGHT_MSS: u64 = 4;

/// Envelope floor unit: the ceiling never drops below the path's
/// proven work point or this many MSS.
const RESPOND_FLOOR_MSS: u64 = 8;

/// Absolute inflight cap sanity bound (256 MiB — memory-governed paths
/// enforce tighter caps externally; this only prevents u64 silliness).
const MAX_INFLIGHT: u64 = 256 * 1024 * 1024;

/// Modes (CcSnapshot.mode value set, §8 reason tokens).
pub mod modes {
    pub const PACED_START: &str = "paced_start";
    pub const STARTUP: &str = "startup";
    pub const CRUISE: &str = "cruise";
    /// Display mode while PRR fast recovery is in flight — the window
    /// law is identical to cruise (BDP assignment), the token exists
    /// only so /status can see recovery episodes.
    pub const RECOVERY: &str = "recovery";
}

/// Reason tokens (CcSnapshot.reason_code — stable strings for /status).
pub mod reasons {
    pub const INIT: &str = "init";
    pub const PRIOR_START: &str = "prior_start";
    pub const PLATEAU_EXIT: &str = "plateau_exit";
    pub const HYSTART_EXIT: &str = "hystart_exit";
    pub const GUARDRAIL: &str = "guardrail";
    pub const RECOVERY_DONE: &str = "recovery_done";
    pub const CE_RESPONSE: &str = "ce_response";
    pub const RTO_RECOVER: &str = "rto_model_recover";
    pub const ENVELOPE_SET: &str = "envelope_set";
    pub const ENVELOPE_REFILL: &str = "envelope_refill";
    pub const IDLE_RESTART: &str = "idle_restart";
    pub const MSS_UPDATE: &str = "mss_update";
    pub const LOSS_UNDO: &str = "loss_undo";
}

/// Business tier (§2.4 `Q_budget(tier)`): the self-queue delay the
/// flow is allowed to stand before the guardrail trips. T0 = control
/// progress, T1 = completion-time sensitive, T2 = bulk.
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
    /// Queue-delay budget used as belief evidence by [`Inference`]:
    /// queue occupancy beyond this counts toward congestion belief.
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

    /// Queue-delay guardrail threshold (upstream `max_queue_delay`):
    /// `max(absolute floor, fraction × base_rtt)`. The T1 pair is the
    /// upstream production default (70ms, 0.6); T0 tightens for
    /// latency-sensitive traffic, T2 tolerates more standing queue.
    pub fn guardrail_thresh(&self, base_rtt: Option<Duration>) -> Duration {
        let base = base_rtt.unwrap_or(Duration::from_millis(50));
        let (floor_ms, frac) = match self {
            Tier::T0 => (40, 0.4),
            Tier::T1 => (70, 0.6),
            Tier::T2 => (120, 0.8),
        };
        Duration::from_millis(floor_ms).max(Duration::from_micros(
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

    /// Queue-delay/ECN guardrail state — recomputed once per round,
    /// never sticky: the round after the queue drains or CE marks
    /// stop, the cruise gains apply again (upstream `queue_clamped`).
    queue_clamped: bool,
    /// CE bytes seen since the last round boundary — a fresh mark this
    /// round trips the guardrail.
    round_ce: bool,
    /// Self-inflicted-loss guardrail (shallow-buffer paths): the
    /// qdelay guardrail is blind where a full buffer drains faster
    /// than an ACK can measure — on a 5 ms RTT link one BDP of queue
    /// adds only ~5 ms, under the tier threshold floor. There, a loss
    /// event while inflight exceeds 1.5× the slope-proven window IS
    /// the congestion signal: a buffer overflow the flow itself
    /// caused. `loss_clamp_until_us` engages `queue_clamped` for ~2
    /// srtt; losses persisting through the clamp prove the loss was
    /// external, so the test disables itself for ~8 srtt
    /// (`loss_clamp_off_until_us`) to keep the loss-blind law honest.
    /// `loss_clamp_off_shift` doubles the disable window on each
    /// disproof (8→16→32→64 srtt): an honestly lossy path keeps
    /// disproving, so the test backs off exponentially instead of
    /// burning ~2 srtt of throughput per re-arm cycle. A truly
    /// self-inflicted path never disproves — losses stop while the
    /// clamp drains — so the shift stays low there.
    /// All timestamps are transport µs.
    loss_clamp_until_us: u64,
    loss_clamp_off_shift: u32,
    /// Loss events before this instant are the pre-clamp drops'
    /// delayed marks — stale evidence that must not disarm the test.
    loss_clamp_judge_us: u64,
    /// The slope-proven window (bytes) captured when the clamp
    /// engaged. The drain backlog keeps shedding self-inflicted drops
    /// while inflight is still above it, so only a loss taken at or
    /// below ~1.2× this window counts as external-loss disproof.
    loss_clamp_bdp: u64,
    loss_clamp_off_until_us: u64,
    /// Latest transport instant seen (round boundary checks compare
    /// against the clamp timestamps).
    now_us: u64,
    /// High-water mark of `bw_slope_proven` (B/s) — the best rate the
    /// path demonstrably sustained for a full RTT. Slope measures
    /// what the flow *achieved*, not what the path *can do*: a bare
    /// `delivered × slack` cap is self-fulfilling (low pacing → low
    /// slope → low cap → lower pacing) and locks in post-stall
    /// depression. Bounding by the proven peak keeps the cap honest
    /// without throttling recovery — the guardrails own the response
    /// if the path genuinely degraded. Stored with its refresh
    /// instant: a peak unproven for >4 s halves (per check) so a
    /// permanently degraded path cannot hold a stale bound forever.
    peak_slope: Option<(u64, u64)>,

    // --- startup ---
    hystart: HyStart,
    /// Consecutive rounds with bandwidth growth below
    /// `STARTUP_GROWTH_RATIO` — the plateau exit counter.
    plateau_rounds: u32,
    /// Bandwidth estimate at the previous round boundary (plateau
    /// comparison baseline).
    prior_round_bw: u64,
    prior: Option<PathPrior>,
    /// Inflight cap applied until prior is validated (prior mode only).
    prior_inflight_cap: Option<u64>,

    last_srtt: Option<Duration>,
    /// Aggregate lease (installed by the T6 wiring layer).
    /// Boxed trait object: the aggregate owns the shared state; the
    /// controller only holds its permit/clamp channel.
    agg: Option<Box<dyn AggregateLease>>,

    // --- recovery ---
    /// PRR bookkeeping: tracks fast-recovery episodes for the mode
    /// display and loss accounting. Its cwnd output is deliberately
    /// ignored — the BDP assignment owns the window in every state,
    /// so the window never collapses inside recovery (upstream: "M2
    /// owns cwnd directly in every CA state, bypassing PRR entirely").
    prr: Prr,

    /// Ablation flag (§2.9 LossBlindRef): when set, the belief path
    /// sees loss-blinded samples while the model still sees true loss
    /// (p_rand still needs it). Production controllers never set it.
    pub loss_blind: bool,
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
            queue_clamped: false,
            round_ce: false,
            loss_clamp_until_us: 0,
            loss_clamp_off_shift: 0,
            loss_clamp_judge_us: 0,
            loss_clamp_bdp: 0,
            loss_clamp_off_until_us: 0,
            now_us: 0,
            peak_slope: None,
            hystart: HyStart::new(),
            plateau_rounds: 0,
            prior_round_bw: 0,
            prior,
            prior_inflight_cap: None,
            last_srtt: None,
            agg: None,
            prr: Prr::default(),
            loss_blind: false,
        };
        if let Some(p) = prior.filter(|p| p.bw_bps > 0 && p.confidence > 0.0) {
            // §2.4 启动: ~0.5× prior bw pacing, ≤1.5× prior BDP inflight,
            // immediately validated by fresh delivery samples.
            let conf = p.confidence.clamp(0.0, 1.0);
            let seed_bw = (p.bw_bps as f64 * PRIOR_BW_GAIN * conf) as u64;
            let prior_bdp = (p.bw_bps as f64 * p.base_rtt.as_secs_f64()) as u64;
            cc.pacing_bps = seed_bw.max(1);
            cc.prior_inflight_cap = Some(((prior_bdp as f64 * PRIOR_BDP_GAIN) as u64).max(4 * mss));
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
        let bw = snap.bandwidth_lo_bps.or(snap.bandwidth_hi_bps).unwrap_or(0);
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
        self.mode = modes::CRUISE;
        self.reason = "migrate_restore";
    }

    /// The inflight target after every applicable cap — envelope §2.5,
    /// aggregate share §2.6, sanity bounds. Loss is absent here by
    /// design: random loss is not congestion evidence, so the window
    /// is never cut for it.
    fn effective_target(&self) -> u64 {
        let mut t = self.inflight_target;
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
            self.round_end_cum = rs.cum_ack + 1; // provisional; on_sent re-arms
            return true;
        }
        false
    }

    /// The rate the work point paces at. `bw_est` is the honest EWMA
    /// point estimate; on random-loss paths the delivered stream sags
    /// while the windowed `bw_max` keeps the last proven rate — the gap
    /// is itself the loss-vs-capacity signal. The peak is allowed to
    /// lift the estimate, but only by PEAK_LIFT: raw `bw_max` is a
    /// 4-second max filter that ACK compression can poison with
    /// back-to-back-burst samples many times the serialization rate —
    /// pacing straight off it was what burst a 10 Mbps link into
    /// 6× the retransmits of the loss path it was compensating for.
    /// The final bound is `bw_slope`: the cum_ack slope over ~2 srtt
    /// cannot be inflated by compression or stall-drains at all, so
    /// work rate may exceed it only by SLOPE_SLACK.
    fn work_rate_bps(&self) -> Option<u64> {
        const PEAK_LIFT_NUM: u64 = 3;
        const PEAK_LIFT_DEN: u64 = 2;
        let est = self.model.bw_est();
        let max = self
            .model
            .bw_max()
            .map(|m| self.model.bw_hi().map_or(m, |hi| m.min(hi)));
        let rate = match (est, max) {
            (Some(e), Some(m)) => e.max(m.min(e.saturating_mul(PEAK_LIFT_NUM) / PEAK_LIFT_DEN)),
            (Some(e), None) => e,
            (None, m) => m?,
        };
        Some(match self.slope_bound() {
            Some(bound) => rate.min(bound),
            None => rate,
        })
    }

    /// The hard bound the confirmed-delivery slope puts on any rate
    /// derived from delivery samples — used ONLY on guardrail-blind
    /// paths (base RTT below the tier's delay floor), where the queue
    /// drains too fast for the delay guardrail to see and the estimate
    /// is the only ceiling between ACK compression and a detonated
    /// BDP assignment. The slope counts confirmed-delivered bytes over
    /// real time, so it cannot be inflated by compressed samples —
    /// but it CAN be diluted by stalls, so the peak/lifetime fallbacks
    /// keep the bound alive across the drain epochs a shallow path
    /// cycles through. While clamped the slack collapses to 1.0 —
    /// 0.8 × (2×slope) still exceeds the delivered rate and a clamp
    /// applied to the slackened bound could never drain the queue.
    ///
    /// Returns `None` on WAN paths (the delay guardrail is sighted
    /// there — pacing follows the estimate) and when no slope exists
    /// yet (the caller falls back to ACK-clocked growth). The floor is
    /// a liveness guarantee, not an estimate: a degraded link can hold
    /// the delivered slope near zero for whole windows, and capping
    /// work rate at ~0 paces the flow into a death spiral (no sends →
    /// no ACKs → slope stays 0).
    fn slope_bound(&self) -> Option<u64> {
        const SLOPE_SLACK: u64 = 2;
        // The liveness floor's RTT input is floored at 1 ms: on
        // retx-heavy paths Karn's rule starves honest samples and the
        // surviving srtt can collapse to sub-ms noise, which would
        // otherwise price the floor above the link itself.
        let floor_rtt = self
            .model
            .base_rtt()
            .or(self.last_srtt)
            .unwrap_or(Duration::from_millis(50))
            .max(Duration::from_millis(1));
        let slope_floor = 4 * self.mss * 1_000_000 / floor_rtt.as_micros() as u64;
        let slack = if self.queue_clamped { 1 } else { SLOPE_SLACK };
        let windowed = self.model.bw_slope_windowed();
        // The blindness test is the tier's own delay floor: if one
        // base RTT of queue delay cannot reach the guardrail
        // threshold, the guardrail can never see this path's
        // congestion and the slope bound must carry the load —
        // persistent across stalls so inflated catch-up bursts cannot
        // re-detonate the shallow buffer.
        let persistent = self
            .model
            .base_rtt()
            .is_none_or(|b| b < self.tier.guardrail_thresh(Some(b)));
        if !persistent {
            // WAN regime: the delay guardrail sees the standing queue,
            // so pacing needs no slope ceiling — and a stall-diluted
            // bound would throttle the recovery burst into a
            // self-fulfilling depression. The estimate (EWMA of
            // confirmed-delivery samples) is honest here.
            return None;
        }
        let slope = [
            windowed,
            self.peak_slope.map(|(v, _)| v),
            self.model.bw_slope_lifetime(),
        ]
        .into_iter()
        .flatten()
        .max();
        slope.map(|s| s.max(slope_floor).saturating_mul(slack))
    }

    /// Loss-rate compensation multiplier `1/(1−p)` (upstream M3). `p`
    /// is the model's quiet-path loss baseline — loss taken while no
    /// queue was building, i.e. the path's intrinsic drop rate, not
    /// congestion collapse. The delivered-rate filter under-provisions
    /// by exactly `(1−p)` on such a path, so every BDP-derived target
    /// and the pacing rate are inflated by the reciprocal. Capped at
    /// `LOSS_INFLATION_MAX` (×2.0) so a mis-measured path cannot run
    /// away — the queue guardrail is the backstop either way.
    fn loss_inflation(&self) -> f64 {
        let p = self.model.p_rand().unwrap_or(0.0).min(LOSS_INFLATION_MAX);
        1.0 / (1.0 - p).max(1e-9)
    }

    /// BDP assignment (upstream `skyline_bdp_packets`): the inflight
    /// target is recomputed from the measured bandwidth and base RTT
    /// every ACK — `bw × base_rtt × gain × inflation`, floored at the
    /// liveness window. Returns `false` when the model has no estimate
    /// yet (callers fall back to ACK-clocked growth).
    ///
    /// Loss inflation applies to the *window* only — inflight headroom
    /// covers the retransmissions a lossy path needs in flight. It is
    /// deliberately kept OUT of the pacing rate: pacing is the burst
    /// maker, and letting the measured loss rate loosen the burst rate
    /// is a positive feedback loop (overpaced bursts → tail drops →
    /// p_rand up → faster bursts) that runs away on short-RTT links
    /// where the queue drains before any delay guardrail can see it.
    /// The slope cap on `bw` already bounds pacing to ~2× the rate the
    /// path demonstrably delivers, and a pace bounded by delivered
    /// slope self-stabilizes: drops can only lower the bound.
    fn assign_bdp_target(&mut self, cwnd_gain: f64, pacing_gain: f64) -> bool {
        // No slope estimate yet → nothing has been *proven* about the
        // path, and the delivery filters can already be poisoned by
        // compressed ACKs (the first few ACKs of a fast link report
        // GB/s). Without the slope bound the BDP assignment would
        // detonate the window inside the first RTT — the caller falls
        // back to ACK-clocked growth, which is bounded by real data.
        if self.model.bw_slope().is_none() {
            return false;
        }
        // base_rtt falls back to the live srtt: on retx-heavy paths
        // Karn's rule can starve min_rtt for whole episodes, and the
        // ACK-clocked fallback paces off the raw delivery rate — which
        // ACK compression inflates orders of magnitude past the link.
        let rtt = self.model.base_rtt().or(self.last_srtt);
        let (Some(bw), Some(base)) = (self.work_rate_bps(), rtt) else {
            return false;
        };
        if bw == 0 {
            return false;
        }
        // Loss inflation grants retx headroom — but only while the
        // flow is *not* clamped. Once a guardrail says the pipe is
        // overfilled, extra window is exactly what it is draining;
        // carrying inflation through the clamp keeps inflight above
        // the overflow point, losses continue, and the shallow-buffer
        // detector reads its own tail as disproof and disarms.
        let infl = if self.queue_clamped {
            1.0
        } else {
            self.loss_inflation()
        };
        let bdp = bw as f64 * base.as_secs_f64();
        let mut target = (bdp * cwnd_gain * infl) as u64;
        // Proven-window cap (guardrail-blind paths only): where the
        // delay guardrail cannot see the queue, nothing else stops a
        // work-rate estimate inflated by compressed-ACK history from
        // parking several buffer-loads in the pipe — the massacre
        // driver on shallow buffers. `proven` is confirmed-delivered
        // slope × RTT, so the cap self-adjusts to what the path
        // demonstrably carried and never binds below it.
        if self
            .model
            .base_rtt()
            .is_none_or(|b| b < self.tier.guardrail_thresh(Some(b)))
        {
            let proven = [
                self.model.bw_slope_windowed(),
                self.peak_slope.map(|(v, _)| v),
                self.model.bw_slope_lifetime(),
            ]
            .into_iter()
            .flatten()
            .max()
            .map(|s| (s as u128 * base.as_micros().max(1) / 1_000_000).min(u64::MAX as u128) as u64);
            if let Some(p) = proven {
                target = target.min(p.saturating_mul(3));
            }
        }
        self.inflight_target = target.max(MIN_INFLIGHT_MSS * self.mss);
        self.pacing_bps = ((bw as f64 * pacing_gain) as u64).max(1);
        true
    }

    /// Envelope floor (§2.5): the ceiling never drops below the path's
    /// proven work point — the inflight the link demonstrably carried
    /// (work-rate × base_rtt) — nor below the response floor. Without
    /// it, strong-evidence sets taken mid-recovery ratchet the ceiling
    /// toward one MSS on lossy paths.
    fn envelope_floor(&self) -> u64 {
        let proven = self
            .work_rate_bps()
            .zip(self.model.base_rtt())
            .map(|(bw, base)| (bw as f64 * base.as_secs_f64()) as u64)
            .unwrap_or(0);
        proven.max(RESPOND_FLOOR_MSS * self.mss)
    }

    /// Strong-evidence → envelope set (§2.5): a CE-majority ACK stream
    /// is unambiguous congestion marking, so it still pins the safety
    /// ceiling. Loss-with-queue no longer sets the envelope — the
    /// per-round `queue_clamped` gain owns that response, and a sticky
    /// ceiling is exactly what ratcheted lossy paths to the floor.
    /// BBRv1 `lt_bw` policer verdicts still pin the pacing ceiling.
    fn envelope_check(&mut self, rs: &RateSample, in_flight: u64) {
        let ce_strong =
            rs.delivered > 0 && (rs.delivered_ce as f64 / rs.delivered as f64) >= ENVELOPE_CE_FRAC;
        if ce_strong {
            let floor = self.envelope_floor();
            self.envelope.set_default_floored(
                in_flight.max(self.mss),
                floor,
                reasons::ENVELOPE_SET,
            );
            self.reason = reasons::CE_RESPONSE;
        }
        if let Some(lt) = self.model.lt_bw() {
            self.pacing_bps = self.pacing_bps.min(lt);
        }
    }
}

impl CongestionController for EdgeCc {
    fn on_sent(
        &mut self,
        _now: TransportInstant,
        bytes: u64,
        _in_flight: u64,
        _is_app_limited: bool,
    ) {
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
        self.now_us = now.micros();
        let in_flight_delta = in_flight as i64 - self.prev_in_flight as i64;
        self.prev_in_flight = in_flight;
        if let Some(s) = rtt.srtt {
            self.last_srtt = Some(s);
        }

        // Model + inference always see the sample (§2.2/§2.3). The
        // LossBlind ablation zeroes the belief-path loss evidence only —
        // the model still gets true loss (recovery and p_rand need it).
        self.model.on_rate_sample(rs, in_flight, rtt);
        if let Some(s) = self.model.bw_slope_proven() {
            match self.peak_slope {
                Some((p, _)) if s <= p => {}
                _ => self.peak_slope = Some((s, now.micros())),
            }
        }
        // Decay an unproven peak — a stale bound must not outlive the
        // path's demonstrated capacity indefinitely.
        if let Some((p, t)) = self.peak_slope
            && now.micros().saturating_sub(t) > 4_000_000
        {
            self.peak_slope = Some((p / 2, now.micros()));
        }
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
            in_flight,
            in_flight_delta,
            self.tier.q_budget(self.model.base_rtt()),
            rtt_d,
        );

        // Fresh CE this round feeds the guardrail at the boundary.
        self.round_ce |= rs.delivered_ce > 0;

        let round_done = self.maybe_advance_round(rs);
        if round_done {
            // The guardrail is the only congestion signal left: queue
            // delay above the tier threshold or a fresh CE mark.
            // Recomputed every round, never sticky (upstream
            // `queue_clamped`) — the round after the queue drains the
            // cruise gains apply again.
            self.queue_clamped = self.model.qdelay()
                > self.tier.guardrail_thresh(self.model.base_rtt())
                || self.round_ce
                || self.now_us < self.loss_clamp_until_us;
            self.round_ce = false;
            if self.queue_clamped {
                self.reason = reasons::GUARDRAIL;
            }

            self.envelope.on_round(self.infer.belief_milli());
            if self.envelope.reason_code() == reasons::ENVELOPE_REFILL {
                self.reason = reasons::ENVELOPE_REFILL;
            }

            // Startup plateau bookkeeping (upstream): bandwidth growth
            // below STARTUP_GROWTH_RATIO for STARTUP_PLATEAU_ROUNDS
            // consecutive rounds means the pipe is full; a tripped
            // guardrail exits immediately. The estimate is compared at
            // round granularity — per-ACK max-filter spikes would
            // otherwise reset the counter forever on lossy paths.
            if matches!(self.mode, modes::STARTUP | modes::PACED_START) {
                let bw = self.work_rate_bps().unwrap_or(0);
                if self.prior_round_bw > 0
                    && (bw as f64) < self.prior_round_bw as f64 * (1.0 + STARTUP_GROWTH_RATIO)
                {
                    self.plateau_rounds = self.plateau_rounds.saturating_add(1);
                } else {
                    self.plateau_rounds = 0;
                }
                self.prior_round_bw = bw;
                if self.plateau_rounds >= STARTUP_PLATEAU_ROUNDS || self.queue_clamped {
                    self.mode = modes::CRUISE;
                    self.reason = if self.queue_clamped {
                        reasons::GUARDRAIL
                    } else {
                        reasons::PLATEAU_EXIT
                    };
                    self.prior_inflight_cap = None; // prior validated
                }
            }

            // Per-round member report to the aggregate (§2.6): RFC 8382
            // correlation inputs + allocation fields.
            if let Some(agg) = self.agg.as_ref() {
                agg.push_stats(crate::aggregate::MemberStats {
                    loss_times_us: self.infer.sbd.loss_times_us,
                    qdelay_delta: self.infer.sbd.qdelay_delta,
                    qdelay_delta_abs: self.infer.sbd.qdelay_delta_abs,
                    inflight: in_flight,
                    rate_bps: self.model.bw_last_sample(),
                    tier: self.tier as u8,
                    progress_ctr: self.rounds as u64,
                    wants_probe: false,
                });
            }
        }

        // ---- single action committer ----

        // Safety ceiling: strong-CE envelope set + policer pin. Neither
        // consumes the round's action — the committer assigns below.
        self.envelope_check(rs, in_flight);

        // PRR bookkeeping advances so recovery exit is observable; its
        // cwnd output is ignored — the BDP assignment owns the window
        // in every state, recovery included.
        if self.prr.active {
            let _ = self.prr.on_ack(
                rs.delivered,
                rs.cum_ack,
                in_flight,
                self.effective_target(),
                self.mss,
                now,
            );
            if !self.prr.active && self.mode == modes::RECOVERY {
                self.mode = modes::CRUISE;
                self.reason = reasons::RECOVERY_DONE;
            }
        }

        match self.mode {
            modes::STARTUP | modes::PACED_START => {
                if self.hystart.baseline_min().is_none()
                    && let Some(b) = rs.rtt.or(rtt.min_rtt)
                {
                    self.hystart.seed_baseline(b, self.sent_total);
                }
                if self.hystart.on_ack(rs.rtt, rs.cum_ack, self.sent_total) == HystartVerdict::Exit
                {
                    self.mode = modes::CRUISE;
                    self.reason = reasons::HYSTART_EXIT;
                    self.prior_inflight_cap = None;
                    return;
                }
                let gain = if self.queue_clamped {
                    GUARDRAIL_GAIN
                } else {
                    STARTUP_GAIN
                };
                // Direct BDP assignment once the model has estimates —
                // before that, ACK-clocked growth (TCP slow start).
                // A seeded prior stands in until fresh samples land.
                let prior_bw = self.prior.map(|p| {
                    (p.bw_bps as f64 * PRIOR_BW_GAIN * p.confidence.clamp(0.0, 1.0)) as u64
                });
                if self.work_rate_bps().is_none() && prior_bw.is_some() {
                    let bw = prior_bw.unwrap_or(0).max(1);
                    let base = self.prior.map(|p| p.base_rtt).unwrap_or_else(|| rtt_d);
                    let infl = self.loss_inflation();
                    let bdp = bw as f64 * base.as_secs_f64();
                    self.inflight_target = ((bdp * gain * infl) as u64)
                        .max(MIN_INFLIGHT_MSS * self.mss)
                        .min(self.prior_inflight_cap.unwrap_or(MAX_INFLIGHT));
                    // Same rule as `assign_bdp_target`: inflation
                    // grants window headroom, never burst rate — a
                    // poisoned prior p_rand must not loosen pacing.
                    self.pacing_bps = ((bw as f64 * gain) as u64).max(1);
                    return;
                }
                if !self.assign_bdp_target(gain, gain) {
                    self.inflight_target = self
                        .inflight_target
                        .saturating_add(rs.acked_sacked)
                        .min(self.prior_inflight_cap.unwrap_or(MAX_INFLIGHT));
                    // Pacing must never collapse when the sampler has no
                    // interval yet (delivery_rate_bps()==0): fall back to
                    // inflight_target/rtt — the rate a full window implies.
                    // The raw delivery rate is ACK-compression-inflated on
                    // exactly the retx-heavy paths that land here (Karn
                    // starves base_rtt → BDP assignment unavailable), so it
                    // passes through the same slope bound as work_rate —
                    // and so does the window-implied rate: its `rtt_d` can
                    // be a starved sub-ms srtt, which unbounded would
                    // price a full window far above the link.
                    let bound = self.slope_bound();
                    let delivery = bound.map_or_else(|| rs.delivery_rate_bps(), |b| {
                        rs.delivery_rate_bps().min(b)
                    });
                    let floor_rtt = rtt_d.max(Duration::from_millis(1));
                    let implied = (self.inflight_target as u128 * 1_000_000
                        / floor_rtt.as_micros())
                        .min(u64::MAX as u128) as u64;
                    // Blind paths pace at min(delivery, window-implied):
                    // before any slope exists the delivery sample is the
                    // most compression-inflated value on the path, and a
                    // window-bounded flow cannot sustain more than
                    // inflight/rtt anyway. WAN paths keep max() — the
                    // post-RTO catch-up burst is legitimate rate there
                    // and the queue guardrail watches the buffer. The
                    // split is on the path's blindness, not on whether a
                    // slope happens to exist yet: a blind path with no
                    // slope sample still bursts through max().
                    let persistent = self
                        .model
                        .base_rtt()
                        .is_none_or(|b| b < self.tier.guardrail_thresh(Some(b)));
                    let bw = if persistent {
                        delivery.min(implied).min(bound.unwrap_or(u64::MAX))
                    } else {
                        delivery.max(implied)
                    };
                    self.pacing_bps = (bw as f64 * gain) as u64;
                }
                if let Some(cap) = self.prior_inflight_cap {
                    self.inflight_target = self.inflight_target.min(cap);
                }
            }
            _ => {
                // Cruise — and recovery, which shares the same law: the
                // window is the BDP assignment regardless of loss state.
                let cwnd_gain = if self.queue_clamped {
                    GUARDRAIL_GAIN
                } else {
                    CRUISE_INFLIGHT_GAIN
                };
                let pacing_gain = if self.queue_clamped {
                    GUARDRAIL_GAIN
                } else {
                    CRUISE_PACING_GAIN
                };
                self.assign_bdp_target(cwnd_gain, pacing_gain);
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
            // RTO sweeps bypass `rs.lost` — feed the model's loss
            // columns directly so p_rand sees the real loss process.
            self.model
                .note_rto_loss(lost_bytes, self.model.loss_congested(in_flight));
            self.on_rto(now, in_flight);
            return;
        }
        // Self-inflicted-loss test (shallow-buffer guardrail): drops
        // while inflight exceeds 1.5× the slope-proven window are
        // buffer-overflow evidence — the only congestion signal a
        // short-RTT path can produce, since its queue drains before
        // the delay guardrail could ever measure it. Engage the clamp
        // for ~2 srtt; a loss landing while clamped proves the loss
        // was not ours, so the test then disables itself for ~8 srtt
        // rather than throttle an honestly random-loss path.
        let now_us = now.micros();
        self.now_us = self.now_us.max(now_us);
        let srtt_us = self
            .last_srtt
            .or_else(|| self.model.base_rtt())
            .unwrap_or(Duration::from_millis(50))
            .as_micros() as u64;
        let pre_loss_inflight = in_flight.saturating_add(lost_bytes) as u128;
        if now_us < self.loss_clamp_until_us && now_us >= self.loss_clamp_judge_us {
            // Loss persisted past the judge point — but the drain
            // backlog sheds self-inflicted drops while inflight is
            // still above the proven window, so only a loss taken at
            // or below ~1.2× that window proves the loss was external.
            if pre_loss_inflight <= self.loss_clamp_bdp as u128 * 6 / 5 {
                self.loss_clamp_until_us = 0;
                let off = (8 * srtt_us).saturating_mul(1 << self.loss_clamp_off_shift.min(3));
                self.loss_clamp_off_until_us = now_us.saturating_add(off);
                self.loss_clamp_off_shift = (self.loss_clamp_off_shift + 1).min(3);
            }
        } else if now_us >= self.loss_clamp_until_us && now_us >= self.loss_clamp_off_until_us {
            // No slope estimate → nothing proven → cannot tell our
            // overflow from the path's; stay loss-blind.
            let proven = [
                self.model.bw_slope_windowed(),
                self.peak_slope.map(|(v, _)| v),
                self.model.bw_slope_lifetime(),
            ]
            .into_iter()
            .flatten()
            .max()
            .zip(self.model.base_rtt().or(self.last_srtt))
            .map(|(s, b)| s as u128 * b.as_micros().max(1) / 1_000_000);
            if proven.is_some_and(|p| pre_loss_inflight > p.saturating_mul(3) / 2) {
                self.loss_clamp_until_us = now_us.saturating_add(2 * srtt_us);
                self.loss_clamp_judge_us = now_us.saturating_add(srtt_us);
                self.loss_clamp_bdp = proven.unwrap_or(0).min(u64::MAX as u128) as u64;
                // Engage now — recomputation at the next round
                // boundary keeps it while the timestamp is live.
                self.queue_clamped = true;
                self.reason = reasons::GUARDRAIL;
            }
        }
        // Fast-recovery bookkeeping only: the window is the BDP
        // assignment in every state, so a loss event never cuts it.
        // The RECOVERY display mode marks the episode for /status;
        // startup is exempt — a loss there does not exit startup
        // (upstream: CA state never changes the M2 mode).
        if !self.prr.active {
            self.prr.enter(in_flight, self.sent_total + 1);
            if !matches!(self.mode, modes::STARTUP | modes::PACED_START) {
                self.mode = modes::RECOVERY;
            }
        }
    }

    fn on_ecn_ce(&mut self, now: TransportInstant, ce_bytes: u64, delivered: u64, in_flight: u64) {
        // Classic-ECN once-per-window event: a CE mark is guardrail
        // evidence — engage the clamp now (it is recomputed each round,
        // so this can only hold for the remainder of the round) and
        // record it for the boundary evaluation. A CE-majority window
        // is unambiguous congestion: pin the envelope too (§2.5).
        let _ = now;
        self.round_ce = true;
        self.queue_clamped = true;
        if delivered > 0 && ce_bytes * 2 >= delivered {
            let floor = self.envelope_floor();
            self.envelope.set_default_floored(
                in_flight.max(self.mss),
                floor,
                reasons::ENVELOPE_SET,
            );
            self.reason = reasons::CE_RESPONSE;
        }
    }

    fn on_rto(&mut self, now: TransportInstant, _in_flight: u64) {
        let _ = now;
        // A timeout is loss evidence, and loss never shrinks the
        // window: the retransmit timer already paces the retry, and
        // collapsing the target on every RTO is what livelocked
        // high-p_rand paths. Keep the BDP-assigned work point (still
        // bounded by the envelope); reset the recovery bookkeeping.
        self.prr = Prr::default();
        if self.mode == modes::RECOVERY {
            self.mode = modes::CRUISE;
        }
        if self.pacing_bps == 0 {
            self.pacing_bps = self.work_rate_bps().unwrap_or(0);
        }
        self.reason = reasons::RTO_RECOVER;
    }

    fn on_loss_undo(&mut self, now: TransportInstant) {
        // Eifel/DSACK: the window was never reduced, so there is
        // nothing to restore — only the model's spurious accounting.
        self.model.note_spurious_retx(self.mss);
        self.infer.note_spurious_retx();
        self.prr = Prr::default();
        if self.mode == modes::RECOVERY {
            self.mode = modes::CRUISE;
        }
        self.reason = reasons::LOSS_UNDO;
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
        self.inflight_target = restart
            .max(MIN_INFLIGHT_MSS * self.mss)
            .min(self.inflight_target);
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
            inflight_lo_bytes: None,
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
