//! The bidirectional congestion-controller contract (plan §2.2).
//!
//! The trait is role-agnostic: accepted (client-facing) and dialed
//! (origin-facing) sessions drive it identically. Every callback receives
//! the quantities it needs by value so implementations never reach back
//! into stack internals.
//!
//! Layout:
//! - [`parts`]: reusable mechanisms (PRR, HyStart++) shared by the
//!   reference controllers and the EdgeCC decision layer (T5).
//! - [`reference`]: validation-mode controllers (**not production
//!   algorithms**) — NewRenoRef/CubicRef today, Bbr3Ref/LossBlindRef in
//!   T5 via parameter-pinning of the same code.

use crate::rate_sample::RateSample;
use crate::rtt::RttState;
use crate::TransportInstant;
use std::time::Duration;

pub mod parts;
pub mod reference;

pub use reference::{CubicRef, NewRenoRef};

/// Status payload exported into /status and per-session logs (F8).
///
/// Fields a controller cannot honestly provide stay `None` — a null in
/// /status is the contract for "the algorithm does not track this",
/// never a fabricated number.
///
/// `mode` value sets:
/// - reference controllers: "slow_start", "slow_start_css",
///   "congestion_avoidance", "recovery".
/// - EdgeCC (T5): "paced_start", "startup", "delay_target",
///   "plateau_probe", "probe", "utility_tune", "recovery",
///   "base_rtt_probe".
///
/// `reason_code` EdgeCC set (T5, stable tokens): "init", "prior_start",
/// "plateau_exit", "hystart_exit", "loss_exit", "ce_exit",
/// "probe_start", "probe_accept", "probe_reject", "mode_delay",
/// "mode_plateau", "belief_response", "ce_response",
/// "rto_model_recover", "envelope_set", "envelope_refill",
/// "base_rtt_refresh", "idle_restart", "mss_update".
#[derive(Clone, Debug, PartialEq)]
pub struct CcSnapshot {
    /// Algorithm name: "newreno_ref", "cubic_ref", "edgecc".
    pub algo: &'static str,
    /// Pinned reference the implementation follows, e.g.
    /// "rfc5681+6582+6937" — reviewers diff behavior against this pin.
    pub version_pin: &'static str,
    /// Controller-internal mode — see the value sets above.
    pub mode: &'static str,
    pub cwnd_bytes: u64,
    pub ssthresh_bytes: u64,
    /// Derived pacing rate in bytes/s (cwnd/srtt for window controllers).
    pub pacing_rate_bps: Option<u64>,
    pub min_rtt: Option<Duration>,
    // BBR-family fields — None on window controllers.
    pub bandwidth_hi_bps: Option<u64>,
    pub bandwidth_lo_bps: Option<u64>,
    pub inflight_hi_bytes: Option<u64>,
    pub inflight_lo_bytes: Option<u64>,
    pub extra_acked_bytes: Option<u64>,
    /// ECN alpha EWMA in milli-units (alpha*1000).
    pub ecn_alpha_milli: Option<u32>,
    // --- EdgeCC model/inference/envelope outputs (plan §2.2–2.5) ---
    /// Congestion belief × 1000 (log-odds posterior, §2.3).
    pub belief_milli: Option<u32>,
    /// qdelay × bw_est — bytes we believe we hold in the bottleneck.
    pub queue_estimate_bytes: Option<u64>,
    /// Random-loss baseline estimate × 1000 (§2.2 `p_rand`).
    pub p_rand_milli: Option<u32>,
    /// Delivery-rate uncertainty (bw_sigma) in bytes/s.
    pub bw_sigma_bps: Option<u64>,
    /// Safety envelope ceiling `inflight_hi` (§2.5) — None when uncapped.
    pub envelope_bytes: Option<u64>,
    /// Why the controller last changed mode — short stable token.
    pub reason_code: &'static str,
}

pub trait CongestionController {
    /// A segment was queued for transmission. `in_flight` counts
    /// outstanding bytes *including* this segment.
    fn on_sent(&mut self, now: TransportInstant, bytes: u64, in_flight: u64, is_app_limited: bool);

    /// One ACK event was folded into a [`RateSample`].
    fn on_rate_sample(&mut self, rs: &RateSample, in_flight: u64, rtt: &RttState);

    /// The loss detector judged `lost_bytes` newly lost.
    /// `persistent` = RTO-grade loss (already covered by `on_rto` for most
    /// controllers; BBR distinguishes).
    fn on_loss_event(
        &mut self,
        now: TransportInstant,
        lost_bytes: u64,
        in_flight: u64,
        persistent: bool,
    );

    /// CE-marked bytes (AccECN count, or 1 event for classic ECN) arrived.
    fn on_ecn_ce(&mut self, now: TransportInstant, ce_bytes: u64, delivered: u64, in_flight: u64);

    /// Retransmission timeout fired.
    fn on_rto(&mut self, now: TransportInstant, in_flight: u64);

    /// The stack proved a recent loss/RTO response spurious (DSACK of a
    /// retransmitted range, or a TSecr echoing a pre-retransmission
    /// timestamp — Eifel). Controllers that checkpoint their window at
    /// loss entry restore it here; the default is a no-op for
    /// controllers that do not checkpoint.
    fn on_loss_undo(&mut self, _now: TransportInstant) {}

    /// Sender was idle (nothing in flight) for `idle_for` and resumes.
    fn on_idle_restart(&mut self, now: TransportInstant, idle_for: Duration);

    /// Path MSS changed; controllers quantize to it.
    fn on_mss_update(&mut self, mss: u64);

    /// Current congestion window in bytes — the stack's send ceiling.
    fn cwnd(&self) -> u64;

    /// Pacing ceiling in bytes/s, if the controller paces.
    fn pacing_rate(&self) -> Option<u64>;

    fn snapshot(&self) -> CcSnapshot;
}
