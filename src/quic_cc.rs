//! T5 (§5): bridge the cloud-node-transport pure algorithm core into
//! quinn's `congestion::Controller` contract — same EdgeCc state machine
//! as AF_XDP TCP, plus the reference controllers for validation.
//!
//! Fidelity notes (no fabricated signals):
//! - `on_ack` carries no packet number; the adapter keys send records by
//!   `time_sent` and snapshots the delivered-marker per send burst. QUIC
//!   packet numbers are never retransmitted, so every record is honestly
//!   `is_retransmit = false` and RTT samples are Karn-clean by
//!   construction.
//! - `lost_bytes == 0` congestion events are classic-ECN triggers; the
//!   transport trait's documented convention feeds them as a single
//!   coarse event (`ce_bytes = delivered = 1`), never a fabricated byte
//!   count.
//! - QUIC has PTO, not RTO — `on_rto` is never invoked; persistent
//!   congestion arrives via `on_congestion_event(persistent = true)`.
//! - `clone_box` (path migration) rebuilds the controller from its
//!   snapshot: window/pacing carry over, model estimates seed as a
//!   `PathPrior`, episode machinery restarts — the documented §5
//!   "迁移保留CC状态" level the model supports.
//! - Aggregation is not installed on QUIC controllers: quinn
//!   connections live on tokio tasks, not reactor workers, and the
//!   aggregate is deliberately worker-local `Rc` state. The `Send`/`Sync`
//!   impl is therefore safe only under the invariant that this adapter
//!   never installs an aggregate lease.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use cloud_node_transport::cc as tcc;
use cloud_node_transport::{
    CongestionController, RateSampler, RttState, TransportInstant, TxRecord,
};
use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

use crate::runtime_mode::{XdpTransportController, XdpTransportSettings};

/// Bound on `sent_markers` — oldest entries are for packets long since
/// resolved; pruning them is accounting hygiene, never state loss.
const SENT_MARKERS_CAP: usize = 4096;

/// Build the policy-selected transport controller for a QUIC
/// connection. `mss` is the datagram budget (quinn `current_mtu`).
fn build_inner(
    settings: &XdpTransportSettings,
    mss: u64,
) -> Box<dyn CongestionController> {
    match settings.controller {
        XdpTransportController::Cubic => Box::new(tcc::CubicRef::new(mss)),
        XdpTransportController::NewReno => Box::new(tcc::NewRenoRef::new(mss)),
        XdpTransportController::Bbr3 => Box::new(tcc::Bbr3Ref::new(mss)),
        XdpTransportController::LossBlind => Box::new(tcc::LossBlindRef::new(
            mss,
            cloud_node_transport::Tier::T1,
            None,
            settings.trusted_ecn,
        )),
        XdpTransportController::Edgecc => Box::new(cloud_node_transport::EdgeCc::new(
            mss,
            cloud_node_transport::Tier::T1,
            None, // no path prior on the tokio side — path_table is worker-local
            settings.trusted_ecn,
        )),
    }
}

/// quinn `Controller` adapter over the transport trait.
pub struct QuinnTransportCc {
    inner: Box<dyn CongestionController>,
    sampler: RateSampler,
    rtt: RttState,
    /// Instant → TransportInstant anchor (adapter construction time).
    epoch: Instant,
    /// In-flight bytes tracked locally (quinn doesn't pass it).
    in_flight: u64,
    /// Cumulative delivered edge (RateSample.cum_ack).
    cum_acked: u64,
    /// `time_sent` → delivered marker at send time. Multiple packets in
    /// one datagram share the instant — the marker is burst-grain, which
    /// is exactly what the sampler's delivered-delta needs.
    sent_markers: BTreeMap<Instant, u64>,
    /// Controller rebuild parameters for `clone_box`.
    settings: XdpTransportSettings,
    mss: u64,
}

// Invariant: `set_aggregate` is never called on `inner` — the only
// !Send component of EdgeCc is its aggregate lease, which is statically
// absent here. All other state is plain value data.
unsafe impl Send for QuinnTransportCc {}
unsafe impl Sync for QuinnTransportCc {}

impl QuinnTransportCc {
    fn new(settings: XdpTransportSettings, now: Instant, current_mtu: u16) -> Self {
        Self {
            inner: build_inner(&settings, u64::from(current_mtu)),
            sampler: RateSampler::new(),
            rtt: RttState::new(),
            epoch: now,
            in_flight: 0,
            cum_acked: 0,
            sent_markers: BTreeMap::new(),
            settings,
            mss: u64::from(current_mtu),
        }
    }

    fn ti(&self, t: Instant) -> TransportInstant {
        TransportInstant::from_duration(t.saturating_duration_since(self.epoch))
    }

    /// ACK body — the adapter keeps its own `RttState` and does not
    /// consume quinn's `RttEstimator` (no public constructor), so the
    /// trait callback delegates here.
    fn ack(&mut self, now: Instant, sent: Instant, bytes: u64, app_limited: bool) {
        let tnow = self.ti(now);
        let tsent = self.ti(sent);
        // Per-packet RTT sample — Karn-clean (no retransmission of
        // packet numbers in QUIC).
        self.rtt.sample(tnow.duration_since(tsent));
        let delivered_at_send = self
            .sent_markers
            .get(&sent)
            .copied()
            .unwrap_or_else(|| self.sampler.delivered_marker());
        let rec = TxRecord {
            seq: self.cum_acked,
            end_seq: self.cum_acked + bytes,
            sent_at: tsent,
            first_tx_at: tsent,
            delivered_at_send,
            is_app_limited: app_limited,
            is_retransmit: false,
        };
        let prior_in_flight = self.in_flight;
        self.cum_acked = self.cum_acked.saturating_add(bytes);
        let rs = self.sampler.on_ack(
            tnow,
            &[rec],
            0,
            0,
            prior_in_flight,
            self.cum_acked,
        );
        self.in_flight = self.in_flight.saturating_sub(bytes);
        self.inner.on_rate_sample(&rs, self.in_flight, &self.rtt);
    }
}

impl Controller for QuinnTransportCc {
    fn on_sent(&mut self, now: Instant, bytes: u64, _last_packet_number: u64) {
        self.in_flight = self.in_flight.saturating_add(bytes);
        self.sent_markers
            .insert(now, self.sampler.delivered_marker());
        if self.sent_markers.len() > SENT_MARKERS_CAP {
            // Drop the oldest quarter — those packets resolved long ago.
            let cutoff = self
                .sent_markers
                .keys()
                .nth(SENT_MARKERS_CAP / 4)
                .copied();
            if let Some(cut) = cutoff {
                self.sent_markers = self.sent_markers.split_off(&cut);
            }
        }
        self.inner.on_sent(
            self.ti(now),
            bytes,
            self.in_flight,
            self.sampler.app_limited_now(),
        );
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        _rtt: &RttEstimator,
    ) {
        self.ack(now, sent, bytes, app_limited);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        let t = self.ti(now);
        if lost_bytes > 0 {
            self.in_flight = self.in_flight.saturating_sub(lost_bytes);
            self.inner
                .on_loss_event(t, lost_bytes, self.in_flight, is_persistent_congestion);
        } else {
            // Classic-ECN trigger — the trait's documented single-event
            // convention; no byte count is fabricated.
            self.inner.on_ecn_ce(t, 1, 1, self.in_flight);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mss = u64::from(new_mtu);
        self.inner.on_mss_update(u64::from(new_mtu));
    }

    fn window(&self) -> u64 {
        self.inner.cwnd()
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.inner.cwnd();
        // quinn reports pacing in bits/s; the transport core works
        // in bytes/s.
        metrics.pacing_rate = self.inner.pacing_rate().map(|r| r.saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        // Path migration: rebuild from the snapshot — window, pacing and
        // model priors carry; per-round episode state restarts.
        let snap = self.inner.snapshot();
        let mut inner = build_inner(&self.settings, self.mss);
        inner.seed_from_snapshot(&snap);
        Box::new(Self {
            inner,
            sampler: RateSampler::new(),
            rtt: RttState::new(),
            epoch: Instant::now(),
            in_flight: self.in_flight,
            cum_acked: self.cum_acked,
            sent_markers: BTreeMap::new(),
            settings: self.settings.clone(),
            mss: self.mss,
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.cwnd()
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

/// `ControllerFactory` carrying the resolved XDP transport policy.
/// Install only on AF_XDP-scoped endpoints — kernel-socket QUIC keeps
/// the stock controller (§A.4: non-XDP contract unchanged).
#[derive(Clone, Debug)]
pub struct XdpTransportControllerFactory {
    settings: XdpTransportSettings,
}

impl XdpTransportControllerFactory {
    pub fn new(settings: XdpTransportSettings) -> Self {
        Self { settings }
    }
}

impl ControllerFactory for XdpTransportControllerFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(QuinnTransportCc::new(
            self.settings.clone(),
            now,
            current_mtu,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const MSS: u16 = 1200;

    fn factory(controller: XdpTransportController) -> Arc<XdpTransportControllerFactory> {
        Arc::new(XdpTransportControllerFactory::new(XdpTransportSettings {
            controller,
            ..Default::default()
        }))
    }

    fn build(controller: XdpTransportController) -> QuinnTransportCc {
        QuinnTransportCc::new(
            XdpTransportSettings {
                controller,
                ..Default::default()
            },
            Instant::now(),
            MSS,
        )
    }

    /// Recover the concrete adapter behind a `Box<dyn Controller>`.
    fn adapter(c: Box<dyn Controller>) -> Box<QuinnTransportCc> {
        c.into_any()
            .downcast::<QuinnTransportCc>()
            .expect("factory must build QuinnTransportCc")
    }

    /// Drive one full send→ACK round at ~100ms RTT so the controller
    /// has real history before the asserted event. Goes through the
    /// same `ack()` path the trait callback delegates to — quinn's
    /// `RttEstimator` has no public constructor and is unused anyway.
    fn drive_round(c: &mut QuinnTransportCc, base: Instant, packets: u64) {
        for i in 0..packets {
            c.on_sent(base + Duration::from_millis(i), u64::from(MSS), i);
        }
        for i in 0..packets {
            c.ack(
                base + Duration::from_millis(100 + i),
                base + Duration::from_millis(i),
                u64::from(MSS),
                false,
            );
        }
    }

    #[test]
    fn every_policy_controller_builds() {
        for controller in [
            XdpTransportController::Cubic,
            XdpTransportController::NewReno,
            XdpTransportController::Bbr3,
            XdpTransportController::LossBlind,
            XdpTransportController::Edgecc,
        ] {
            let c = factory(controller).build(Instant::now(), MSS);
            assert!(
                c.initial_window() > 0,
                "{controller:?} must publish a nonzero initial window"
            );
            assert_eq!(c.initial_window(), c.window());
            adapter(c); // downcast sanity
        }
    }

    #[test]
    fn metrics_report_window_and_pacing() {
        let c = build(XdpTransportController::Edgecc);
        let m = c.metrics();
        assert_eq!(m.congestion_window, c.window());
    }

    #[test]
    fn send_ack_round_accounts_in_flight() {
        let mut c = build(XdpTransportController::Edgecc);
        drive_round(&mut c, Instant::now(), 8);
        assert_eq!(c.in_flight, 0, "all sent bytes were ACKed");
        assert_eq!(c.cum_acked, 8 * u64::from(MSS));
        assert!(
            !c.sent_markers.is_empty(),
            "send records retained for future ACKs"
        );
    }

    #[test]
    fn startup_ack_grows_window() {
        let mut c = build(XdpTransportController::Edgecc);
        let w0 = c.window();
        drive_round(&mut c, Instant::now(), 8);
        assert!(
            c.window() > w0,
            "startup must grow inflight on delivered ACKs"
        );
    }

    #[test]
    fn loss_event_routes_to_loss_path() {
        let mut c = build(XdpTransportController::Edgecc);
        let now = Instant::now();
        drive_round(&mut c, now, 8);
        c.on_sent(now + Duration::from_millis(200), u64::from(MSS), 8);
        let before = c.inner.snapshot();
        c.on_congestion_event(now + Duration::from_millis(300), now, false, u64::from(MSS));
        let after = c.inner.snapshot();
        // BDP-assignment law: loss enters recovery bookkeeping but
        // never shrinks the window — the retransmit timer paces the
        // retry, and collapsing cwnd on random loss is what livelocked
        // high-loss paths.
        assert_eq!(after.mode, "recovery");
        assert_eq!(after.cwnd_bytes, before.cwnd_bytes);
    }

    #[test]
    fn persistent_congestion_routes_to_bounded_recovery() {
        let mut c = build(XdpTransportController::Edgecc);
        let now = Instant::now();
        drive_round(&mut c, now, 8);
        c.on_congestion_event(now + Duration::from_millis(300), now, true, u64::from(MSS));
        assert_eq!(c.inner.snapshot().reason_code, "rto_model_recover");
    }

    #[test]
    fn ecn_event_routes_to_ce_not_loss() {
        let mut c = build(XdpTransportController::Edgecc);
        let now = Instant::now();
        drive_round(&mut c, now, 8);
        c.on_congestion_event(now + Duration::from_millis(300), now, false, 0);
        assert_eq!(c.inner.snapshot().reason_code, "ce_response");
    }

    #[test]
    fn mtu_update_propagates_to_inner() {
        let mut c = build(XdpTransportController::Edgecc);
        c.on_mtu_update(9_000);
        assert_eq!(c.mss, 9_000);
        assert_eq!(c.inner.snapshot().reason_code, "mss_update");
    }

    #[test]
    fn clone_box_migrates_window_and_reason() {
        let mut c = build(XdpTransportController::Edgecc);
        drive_round(&mut c, Instant::now(), 8);
        let before = c.inner.snapshot();
        let migrated = adapter(c.clone_box());
        let after = migrated.inner.snapshot();
        // §5 迁移保留CC状态: window and pacing carry; the episode
        // machinery restarts at the cruise work point, not a fresh
        // startup.
        assert_eq!(after.cwnd_bytes, before.cwnd_bytes);
        assert_eq!(after.reason_code, "migrate_restore");
        assert_eq!(after.mode, "cruise");
    }

    #[test]
    fn sent_markers_stay_bounded() {
        let mut c = build(XdpTransportController::Edgecc);
        let now = Instant::now();
        for i in 0..(SENT_MARKERS_CAP + 512) {
            c.on_sent(now + Duration::from_micros(i as u64), u64::from(MSS), i as u64);
        }
        assert!(
            c.sent_markers.len() <= SENT_MARKERS_CAP,
            "marker map must be bounded, got {}",
            c.sent_markers.len()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn runtime_gate_matches_configured_controller() {
        let effective = crate::runtime_mode::RuntimeConfig::current()
            .and_then(|r| r.xdp.transport.clone())
            .unwrap_or_default()
            .controller;
        let factory = crate::xdp::xdp_quic_cc_factory();
        assert_eq!(
            factory.is_some(),
            effective != XdpTransportController::Cubic,
            "custom factory must exist exactly for non-cubic selections"
        );
    }
}
