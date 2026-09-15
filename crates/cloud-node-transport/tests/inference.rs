//! Inference unit cases (plan §2.3): log-odds accumulation per evidence
//! class, RTT decay, DSACK negative evidence, D-D2 public-CE weight
//! cap, queue_estimate.

use cloud_node_transport::inference::{weights, Inference, PUBLIC_CE_LO_CAP};
use cloud_node_transport::model::PathModel;
use cloud_node_transport::rate_sample::RateSample;
use cloud_node_transport::rtt::RttState;
use cloud_node_transport::TransportInstant;
use std::time::Duration;

const MSS: u64 = 1460;

fn t(us: u64) -> TransportInstant {
    TransportInstant::from_micros(us)
}

fn rtt_state(rtt_us: u64) -> RttState {
    let mut r = RttState::new();
    r.sample(Duration::from_micros(rtt_us));
    r
}

fn rs(now_us: u64, delivered: u64, rtt_us: u64, lost: u64, ce: u64) -> RateSample {
    RateSample {
        delivered,
        lost,
        delivered_ce: ce,
        interval: Duration::from_micros(1_000),
        rtt: Some(Duration::from_micros(rtt_us)),
        now: t(now_us),
        ..RateSample::default()
    }
}

/// Model seeded with a 10ms floor so qdelay math is meaningful.
fn seeded_model() -> (PathModel, RttState) {
    let mut m = PathModel::new(MSS);
    let rtt = rtt_state(10_000);
    for i in 0..20u64 {
        let s = rs(i * 10_000, MSS, 10_000, 0, 0);
        m.on_rate_sample(&s, 0, &rtt);
    }
    (m, rtt)
}

#[test]
fn accecn_ce_raises_belief_proportionally() {
    let (mut m, rtt) = seeded_model();
    let mut inf = Inference::new(true); // trusted link → full CE weight
    // 20% CE fraction.
    let s = rs(300_000, 10 * MSS, 10_000, 0, 2 * MSS);
    m.on_rate_sample(&s, 8 * MSS, &rtt);
    let b = inf.on_rate_sample(&s, &m, 0, Duration::from_millis(5), Duration::from_millis(10));
    assert!(b > 0.5, "CE evidence should push belief up, got {b}");
}

#[test]
fn public_ce_contribution_is_capped() {
    // D-D2: untrusted path — CE weight scaled and belief contribution
    // capped at PUBLIC_CE_LO_CAP log-odds.
    let (mut m, rtt) = seeded_model();
    let mut inf = Inference::new(false);
    for i in 0..10u64 {
        let s = rs(300_000 + i * 1_000, 10 * MSS, 10_000, 0, 10 * MSS);
        m.on_rate_sample(&s, 8 * MSS, &rtt);
        inf.on_rate_sample(&s, &m, 0, Duration::from_secs(60), Duration::from_millis(10));
    }
    assert!(
        inf.log_odds() <= PUBLIC_CE_LO_CAP + 1e-9,
        "public CE log-odds {} exceeds cap {}",
        inf.log_odds(),
        PUBLIC_CE_LO_CAP
    );
}

#[test]
fn trusted_link_ce_gets_full_weight() {
    let (mut m, rtt) = seeded_model();
    let mut pub_inf = Inference::new(false);
    let mut tru_inf = Inference::new(true);
    for i in 0..10u64 {
        let s = rs(300_000 + i * 1_000, 10 * MSS, 10_000, 0, 10 * MSS);
        m.on_rate_sample(&s, 8 * MSS, &rtt);
        pub_inf.on_rate_sample(&s, &m, 0, Duration::from_secs(60), Duration::from_millis(10));
        tru_inf.on_rate_sample(&s, &m, 0, Duration::from_secs(60), Duration::from_millis(10));
    }
    assert!(
        tru_inf.log_odds() > pub_inf.log_odds(),
        "trusted {} must exceed public {}",
        tru_inf.log_odds(),
        pub_inf.log_odds()
    );
}

#[test]
fn loss_with_qdelay_outweighs_quiet_loss() {
    let (mut m, rtt10) = seeded_model();
    let mut inf = Inference::new(true);
    let budget = Duration::from_secs(60); // never triggers qdelay evidence

    // Elevated qdelay (15ms vs 10ms floor) + loss.
    let rtt15 = rtt_state(15_000);
    for i in 0..4u64 {
        let s = rs(300_000 + i * 15_000, 9 * MSS, 15_000, MSS, 0);
        m.on_rate_sample(&s, 8 * MSS, &rtt15);
        inf.on_rate_sample(&s, &m, 0, budget, Duration::from_millis(15));
    }
    let congested = inf.log_odds();

    // Fresh inference, quiet loss at 5% → weak evidence.
    let (mut m2, rtt2) = seeded_model();
    let mut inf2 = Inference::new(true);
    for i in 0..4u64 {
        let s = rs(300_000 + i * 10_000, 19 * MSS, 10_000, MSS, 0);
        m2.on_rate_sample(&s, 0, &rtt2);
        inf2.on_rate_sample(&s, &m2, 0, budget, Duration::from_millis(10));
    }
    assert!(
        congested > inf2.log_odds(),
        "loss+qdelay {congested} must outweigh quiet {}",
        inf2.log_odds()
    );
    let _ = rtt10;
}

#[test]
fn belief_decays_toward_zero_per_rtt() {
    let (mut m, rtt) = seeded_model();
    let mut inf = Inference::new(true);
    let s = rs(300_000, 10 * MSS, 10_000, 0, 5 * MSS);
    m.on_rate_sample(&s, 0, &rtt);
    let b0 = inf.on_rate_sample(&s, &m, 0, Duration::from_secs(60), Duration::from_millis(10));
    // 10 RTTs of silence.
    let s2 = rs(400_000, 0, 10_000, 0, 0);
    m.on_rate_sample(&s2, 0, &rtt);
    let b1 = inf.on_rate_sample(&s2, &m, 0, Duration::from_secs(60), Duration::from_millis(10));
    assert!(b1 < b0, "belief must decay: {b0} -> {b1}");
}

#[test]
fn spurious_retx_is_negative_evidence() {
    let (mut m, rtt) = seeded_model();
    let mut inf = Inference::new(true);
    let s = rs(300_000, 10 * MSS, 10_000, 0, 5 * MSS);
    m.on_rate_sample(&s, 0, &rtt);
    let before = inf.on_rate_sample(&s, &m, 0, Duration::from_secs(60), Duration::from_millis(10));
    inf.note_spurious_retx();
    assert!(inf.log_odds() < 0.0 || inf.belief() < before);
}

#[test]
fn quiet_loss_above_p_rand_adds_bounded_evidence() {
    let mut m = PathModel::new(MSS);
    let rtt = rtt_state(10_000);
    // Build p_rand ≈ 1% on the quiet path.
    for i in 0..200u64 {
        let lost = if i % 100 == 0 { MSS } else { 0 };
        let s = rs(i * 1_000, MSS, 10_000, lost, 0);
        m.on_rate_sample(&s, 0, &rtt);
    }
    assert!(m.p_rand().unwrap() < 0.02);
    let mut inf = Inference::new(true);
    // A burst of quiet loss at ~10% — evidence = (rate − p_rand)+ × scale.
    let s = rs(300_000, 9 * MSS, 10_000, MSS, 0);
    m.on_rate_sample(&s, 0, &rtt);
    inf.on_rate_sample(&s, &m, 0, Duration::from_secs(60), Duration::from_millis(10));
    let expected_max = weights::LOSS_QUIET_SCALE * 0.1 + 1e-9;
    assert!(
        inf.log_odds() <= expected_max,
        "quiet-loss weight {} must be ≤ (rate−p_rand)×scale {}",
        inf.log_odds(),
        expected_max
    );
    assert!(inf.log_odds() > 0.0);
}

#[test]
fn plateau_evidence_requires_rising_inflight() {
    let (mut m, rtt) = seeded_model();
    // Build bw_est then feed plateau samples.
    let mut inf = Inference::new(true);
    let mut prev_belief = inf.belief();
    for i in 0..6u64 {
        let s = rs(300_000 + i * 1_000, MSS, 10_000, 0, 0);
        m.on_rate_sample(&s, 8 * MSS, &rtt);
        let b = inf.on_rate_sample(&s, &m, MSS as i64, Duration::from_secs(60), Duration::from_millis(10));
        prev_belief = b;
    }
    // Same samples with inflight *not* rising → no plateau evidence.
    let (mut m2, rtt2) = seeded_model();
    let mut inf2 = Inference::new(true);
    for i in 0..6u64 {
        let s = rs(300_000 + i * 1_000, MSS, 10_000, 0, 0);
        m2.on_rate_sample(&s, 8 * MSS, &rtt2);
        inf2.on_rate_sample(&s, &m2, 0, Duration::from_secs(60), Duration::from_millis(10));
    }
    assert!(
        prev_belief > inf2.belief(),
        "rising inflight {} vs flat {}",
        prev_belief,
        inf2.belief()
    );
}

#[test]
fn queue_estimate_is_qdelay_times_bw() {
    let mut m = PathModel::new(MSS);
    let rtt10 = rtt_state(10_000);
    // Floor 10ms + bw_est ≈ 1.46MB/s.
    for i in 0..40u64 {
        let s = rs(i * 1_000, MSS, 10_000, 0, 0);
        m.on_rate_sample(&s, 0, &rtt10);
    }
    // Raise srtt to 15ms → qdelay ≈ 5ms → queue ≈ 5ms × 1.46MB/s ≈ 7300B.
    let rtt15 = rtt_state(15_000);
    for i in 0..4u64 {
        let s = rs(300_000 + i * 15_000, MSS, 15_000, 0, 0);
        m.on_rate_sample(&s, 8 * MSS, &rtt15);
    }
    let inf = Inference::new(true);
    let q = inf.queue_estimate(&m).unwrap();
    let expect = m.qdelay().as_micros() as u64 * m.bw_est().unwrap() / 1_000_000;
    assert_eq!(q, expect);
    assert!(q > 0);
}
