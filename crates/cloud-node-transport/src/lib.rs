//! cloud-node-transport — pure transport algorithms for the edge
//! dataplane, the EdgeCC foundation layer
//! (tasks/xdp-transport-next-steps-2026-09-15.md §2).
//!
//! - [`TransportInstant`]: monotonic µs instant type shared by
//!   everything.
//! - [`rate_sample`]: per-segment [`TxRecord`] bookkeeping and
//!   [`RateSample`] generation aligned with Linux `net/ipv4/tcp_rate.c`.
//! - [`RttState`]: RFC 6298 estimator plus running min-RTT.
//! - [`cc`]: the bidirectional [`CongestionController`] trait, the
//!   [`CcSnapshot`] status payload, reusable `parts` (PRR, HyStart++)
//!   and `reference` validation-mode controllers
//!   (NewRenoRef/CubicRef — **not production algorithms**).
//! - [`PathModel`]: per-ACK O(1) path estimates — bw_max/bw_est/bw_sigma,
//!   base_rtt + drift, qdelay + gradient, extra_acked, two-column loss
//!   process + p_rand + causal test, alpha, lt_bw policer, delay-signal
//!   quality (§2.2).
//! - [`Inference`]: bounded log-odds congestion belief + queue estimate
//!   + shared-bottleneck statistics (§2.3).
//! - [`Envelope`]: the inflight_hi safety envelope (§2.5).
//! - [`sim`]: deterministic multi-flow event-driven simulator (§7.1).
//!
//! The EdgeCC decision layer (§2.4) is T5; this crate deliberately ships
//! the model/inference/envelope foundation first.

pub mod cc;
pub mod envelope;
mod instant;
pub mod inference;
pub mod model;
pub mod rate_sample;
pub mod rtt;
pub mod sim;

pub use cc::{CcSnapshot, CongestionController};
pub use envelope::Envelope;
pub use inference::{Inference, SbdStats, SharedBottleneckJudge};
pub use instant::TransportInstant;
pub use model::PathModel;
pub use rate_sample::{RateSample, RateSampler, TxRecord};
pub use rtt::RttState;
