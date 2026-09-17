//! LossBlindRef — experimental control (plan §2.9): EdgeCC with the
//! belief path's *loss evidence* disabled. CE/qdelay/plateau evidence
//! still feeds belief; losses still drive PRR recovery and the
//! envelope — only the belief contribution of loss is removed so the
//! T10 ablation isolates "did belief-proportional loss response help".
//!
//! Not a full Linux BBRv1 stand-in (§2.9: 不等同于完整 Linux BBRv1) —
//! it shares every other EdgeCC mechanism so the comparison is clean.

use crate::cc::{CcSnapshot, CongestionController};
use crate::edgecc::{EdgeCc, PathPrior, Tier};
use crate::rate_sample::RateSample;
use crate::rtt::RttState;
use crate::TransportInstant;
use std::time::Duration;

#[derive(Debug)]
pub struct LossBlindRef {
    inner: EdgeCc,
}

impl LossBlindRef {
    pub fn new(mss: u64, tier: Tier, prior: Option<PathPrior>, trusted_ecn: bool) -> Self {
        let mut inner = EdgeCc::new(mss, tier, prior, trusted_ecn);
        inner.loss_blind = true;
        Self { inner }
    }
}

impl CongestionController for LossBlindRef {
    fn on_sent(&mut self, now: TransportInstant, bytes: u64, in_flight: u64, app: bool) {
        self.inner.on_sent(now, bytes, in_flight, app)
    }
    fn on_rate_sample(&mut self, rs: &RateSample, in_flight: u64, rtt: &RttState) {
        self.inner.on_rate_sample(rs, in_flight, rtt)
    }
    fn on_loss_event(&mut self, now: TransportInstant, lost: u64, in_flight: u64, persistent: bool) {
        self.inner.on_loss_event(now, lost, in_flight, persistent)
    }
    fn on_ecn_ce(&mut self, now: TransportInstant, ce: u64, del: u64, in_flight: u64) {
        self.inner.on_ecn_ce(now, ce, del, in_flight)
    }
    fn on_rto(&mut self, now: TransportInstant, in_flight: u64) {
        self.inner.on_rto(now, in_flight)
    }
    fn on_loss_undo(&mut self, now: TransportInstant) {
        self.inner.on_loss_undo(now)
    }
    fn on_idle_restart(&mut self, now: TransportInstant, idle: Duration) {
        self.inner.on_idle_restart(now, idle)
    }
    fn on_mss_update(&mut self, mss: u64) {
        self.inner.on_mss_update(mss)
    }
    fn cwnd(&self) -> u64 {
        self.inner.cwnd()
    }
    fn pacing_rate(&self) -> Option<u64> {
        self.inner.pacing_rate()
    }
    fn snapshot(&self) -> CcSnapshot {
        let mut s = self.inner.snapshot();
        s.algo = "loss_blind_ref";
        s.version_pin = "edgecc-v1-minus-loss-belief";
        s
    }
}
