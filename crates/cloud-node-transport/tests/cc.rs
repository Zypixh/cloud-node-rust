//! Controller-level cases driven through the public
//! `CongestionController` trait on the *reference* controllers
//! (validation modes, not production algorithms — plan §2.9):
//! PRR recovery, once-per-RTT ECN, RTO, HyStart++ exit, CUBIC
//! multiplicative decrease.

use cloud_node_transport::cc::reference::{CubicRef, NewRenoRef};
use cloud_node_transport::cc::CongestionController;
use cloud_node_transport::rate_sample::RateSample;
use cloud_node_transport::rtt::RttState;
use cloud_node_transport::TransportInstant;
use std::time::Duration;

const MSS: u64 = 1460;

fn t(us: u64) -> TransportInstant {
    TransportInstant::from_micros(us)
}

fn sample(now_us: u64, delivered: u64, acked: u64, cum_ack: u64, rtt_us: u64) -> RateSample {
    RateSample {
        delivered,
        acked_sacked: acked,
        cum_ack,
        rtt: Some(Duration::from_micros(rtt_us)),
        now: t(now_us),
        prior_in_flight: 0,
        interval: Duration::from_micros(rtt_us),
        ..RateSample::default()
    }
}

fn rtt_state(rtt_us: u64) -> RttState {
    let mut r = RttState::new();
    r.sample(Duration::from_micros(rtt_us));
    r
}

#[test]
fn new_reno_prr_exits_recovery_at_ssthresh() {
    let mut cc = NewRenoRef::new(MSS);
    let rtt = rtt_state(10_000);
    // Fill cwnd to ~10 MSS via slow start.
    let mut sent = 0u64;
    for i in 0..10u64 {
        cc.on_sent(t(i * 100), MSS, sent + MSS, false);
        sent += MSS;
    }
    // Two 2*MSS ACK events: RFC 3465 ABC caps each event at L=2*MSS, so
    // total growth equals acked bytes across the two events.
    cc.on_rate_sample(&sample(2000, 2 * MSS, 2 * MSS, 2 * MSS, 10_000), 8 * MSS, &rtt);
    cc.on_rate_sample(&sample(2100, 2 * MSS, 2 * MSS, 4 * MSS, 10_000), 6 * MSS, &rtt);
    assert_eq!(cc.cwnd(), 8 * MSS, "SS grows cwnd by acked bytes");

    // Loss enters recovery: ssthresh = flight/2.
    cc.on_loss_event(t(3000), MSS, 8 * MSS, false);
    let snap = cc.snapshot();
    assert_eq!(snap.mode, "recovery");
    assert_eq!(snap.ssthresh_bytes, 4 * MSS);

    // ACKs grind cum_ack past the recovery point (sent_total at entry).
    cc.on_rate_sample(&sample(4000, 2 * MSS, 2 * MSS, sent + MSS, 10_000), 4 * MSS, &rtt);
    let snap = cc.snapshot();
    assert_eq!(snap.mode, "congestion_avoidance");
    assert_eq!(cc.cwnd(), 4 * MSS, "RFC 6937: cwnd = ssthresh on recovery exit");
    assert_eq!(snap.reason_code, "recovery_done");
}

#[test]
fn new_reno_ecn_responds_once_per_rtt() {
    let mut cc = NewRenoRef::new(MSS);
    let rtt = rtt_state(10_000);
    for i in 0..10u64 {
        cc.on_sent(t(i * 100), MSS, (i + 1) * MSS, false);
    }
    cc.on_rate_sample(&sample(2000, 4 * MSS, 4 * MSS, 4 * MSS, 10_000), 8 * MSS, &rtt);
    let cwnd_before = cc.cwnd();

    cc.on_ecn_ce(t(3000), MSS, 4 * MSS, 8 * MSS);
    let after_first = cc.cwnd();
    assert!(after_first < cwnd_before);

    // A second CE inside the same RTT is folded away.
    cc.on_ecn_ce(t(3500), MSS, MSS, 8 * MSS);
    assert_eq!(cc.cwnd(), after_first);

    // After a full RTT, a fresh CE gets a fresh response.
    cc.on_rate_sample(&sample(30_000, MSS, MSS, 9 * MSS, 10_000), 4 * MSS, &rtt);
    cc.on_ecn_ce(t(31_000), MSS, MSS, 4 * MSS);
    assert!(cc.cwnd() < after_first);
}

#[test]
fn new_reno_rto_collapses_to_loss_window() {
    let mut cc = NewRenoRef::new(MSS);
    let rtt = rtt_state(10_000);
    for i in 0..10u64 {
        cc.on_sent(t(i * 100), MSS, (i + 1) * MSS, false);
    }
    cc.on_rate_sample(&sample(2000, 4 * MSS, 4 * MSS, 4 * MSS, 10_000), 8 * MSS, &rtt);
    cc.on_rto(t(5000), 8 * MSS);
    let snap = cc.snapshot();
    assert_eq!(cc.cwnd(), MSS);
    assert_eq!(snap.mode, "slow_start");
    assert_eq!(snap.reason_code, "rto");
}

#[test]
fn cubic_hystart_exits_slow_start_on_delay_growth() {
    let mut cc = CubicRef::new(MSS);
    let rtt = rtt_state(10_000);
    let mut now = 0u64;
    let mut sent = 0u64;
    let mut cum = 0u64;

    // HyStart++ rounds are delimited by the send frontier: a round closes
    // when cum_ack passes the frontier recorded at round start, and needs
    // >= MIN_SAMPLES RTT samples to be trusted. Drive the link in bursts
    // (send a window, then receive its ACKs) so each round spans a full
    // window of ACKs instead of closing on every send/ack step.
    //
    // Block 1 at 10ms seeds the baseline; climbing blocks (14/18/22/26ms)
    // close three consecutive elevated rounds → HyStart++ exit before any
    // loss. (Each block's first ACK closes the previous block's round.)
    for rtt_us in [10_000u64, 14_000, 18_000, 22_000, 26_000] {
        for _ in 0..9 {
            cc.on_sent(t(now), MSS, sent + MSS, false);
            sent += MSS;
            now += 625;
        }
        for _ in 0..9 {
            cum += MSS;
            now += 625;
            cc.on_rate_sample(&sample(now, MSS, MSS, cum, rtt_us), sent - cum, &rtt);
        }
    }
    let snap = cc.snapshot();
    assert_eq!(snap.mode, "congestion_avoidance");
    assert_eq!(snap.reason_code, "hystart");
    assert_eq!(snap.algo, "cubic_ref");
    assert_eq!(snap.version_pin, "rfc9438+9406");
}

#[test]
fn cubic_loss_applies_beta_decrease() {
    let mut cc = CubicRef::new(MSS);
    let rtt = rtt_state(10_000);
    for i in 0..40u64 {
        cc.on_sent(t(i * 100), MSS, (i + 1) * MSS, false);
    }
    cc.on_rate_sample(&sample(10_000, 30 * MSS, 30 * MSS, 30 * MSS, 10_000), 20 * MSS, &rtt);
    let before = cc.cwnd();
    cc.on_loss_event(t(20_000), MSS, 20 * MSS, false);
    assert!(
        (cc.cwnd() as f64) <= before as f64 * 0.71 + MSS as f64,
        "β=0.7 decrease: cwnd {before} -> {}",
        cc.cwnd()
    );
    assert_eq!(cc.snapshot().mode, "recovery");
}

#[test]
fn pacing_rate_is_cwnd_over_srtt() {
    let mut cc = NewRenoRef::new(MSS);
    let rtt = rtt_state(10_000);
    cc.on_sent(t(0), MSS, MSS, false);
    cc.on_rate_sample(&sample(10_000, MSS, MSS, MSS, 10_000), 0, &rtt);
    assert_eq!(cc.pacing_rate(), Some(cc.cwnd() * 1_000_000 / 10_000));
}

#[test]
fn reference_snapshots_leave_edgecc_fields_none() {
    // Contract (cc.rs): fields a controller cannot honestly provide stay
    // None — never a fabricated number.
    let cc = NewRenoRef::new(MSS);
    let snap = cc.snapshot();
    assert_eq!(snap.algo, "newreno_ref");
    assert!(snap.belief_milli.is_none());
    assert!(snap.queue_estimate_bytes.is_none());
    assert!(snap.p_rand_milli.is_none());
    assert!(snap.bw_sigma_bps.is_none());
    assert!(snap.envelope_bytes.is_none());
}
