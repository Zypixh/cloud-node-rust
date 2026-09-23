//! PathModel unit cases (plan §2.2): every quantity gets a case —
//! bw_max/bw_est/bw_sigma/confidence, base_rtt + drift, qdelay +
//! gradient, extra_acked, two-column loss + burst + causal test +
//! p_rand, alpha, lt_bw policer, delay_signal_quality.

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

/// Build a sample: `delivered`/`acked` bytes, `rtt_us` sample,
/// `interval_us` measurement interval, `lost`/`ce` byte increments.
#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors the kernel RateSample field set; grouping into a struct adds noise at 19 call sites"
)]
fn rs(
    now_us: u64,
    delivered: u64,
    acked: u64,
    rtt_us: u64,
    interval_us: u64,
    lost: u64,
    ce: u64,
    app_limited: bool,
    in_flight: u64,
) -> (RateSample, u64) {
    (
        RateSample {
            delivered,
            lost,
            delivered_ce: ce,
            interval: Duration::from_micros(interval_us),
            rtt: Some(Duration::from_micros(rtt_us)),
            is_app_limited: app_limited,
            prior_in_flight: in_flight,
            acked_sacked: acked,
            cum_ack: 0,
            now: t(now_us),
        },
        in_flight,
    )
}

#[test]
fn bw_est_tracks_delivery_rate_and_ignores_app_limited() {
    let mut m = PathModel::new(MSS);
    let rtt = rtt_state(10_000);
    // 1 MSS delivered per 1ms → 1.46 MB/s.
    for i in 0..40u64 {
        let (s, f) = rs(i * 1_000, MSS, MSS, 10_000, 1_000, 0, 0, false, 8 * MSS);
        m.on_rate_sample(&s, f, &rtt);
    }
    let est = m.bw_est().unwrap() as f64;
    let expect = MSS as f64 * 1e6 / 1e3; // bytes/s
    assert!(
        (est - expect).abs() / expect < 0.02,
        "bw_est {est} vs {expect}"
    );
    // bw_max ≥ est (windowed max).
    assert!(m.bw_max().unwrap() >= m.bw_est().unwrap());

    // App-limited samples at half rate must not drag the estimate down.
    let before = m.bw_est().unwrap();
    for i in 40..80u64 {
        let (s, f) = rs(i * 1_000, MSS, MSS, 10_000, 2_000, 0, 0, true, 8 * MSS);
        m.on_rate_sample(&s, f, &rtt);
    }
    assert!(
        m.bw_est().unwrap() >= before * 9 / 10,
        "app-limited samples pulled bw_est down: {before} -> {}",
        m.bw_est().unwrap()
    );
    assert!(m.bw_sigma().is_some());
    assert!(m.bw_confidence(t(80_000)) > 0.5);
}

#[test]
fn base_rtt_is_windowed_min_and_rebases_on_route_drift() {
    let mut m = PathModel::new(MSS);
    let rtt10 = rtt_state(10_000);
    // Establish the floor at 10ms with low inflight.
    for i in 0..20u64 {
        let (s, f) = rs(i * 10_000, MSS, MSS, 10_000, 10_000, 0, 0, false, 0);
        m.on_rate_sample(&s, f, &rtt10);
    }
    assert_eq!(m.base_rtt(), Some(Duration::from_micros(10_000)));

    // Route change: every sample now 20ms — floor must NOT drop (drift
    // detection allows it up only after the horizon while inflight low).
    let rtt20 = rtt_state(20_000);
    for i in 0..20u64 {
        let now = 200_000 + i * 20_000;
        let (s, f) = rs(now, MSS, MSS, 20_000, 20_000, 0, 0, false, 0);
        m.on_rate_sample(&s, f, &rtt20);
    }
    assert_eq!(
        m.base_rtt(),
        Some(Duration::from_micros(10_000)),
        "floor holds inside the drift horizon"
    );

    // Past the 8s horizon with low inflight → rebase toward ~20ms.
    for i in 0..500u64 {
        let now = 600_000 + i * 20_000;
        let (s, f) = rs(now, MSS, MSS, 20_000, 20_000, 0, 0, false, 0);
        m.on_rate_sample(&s, f, &rtt20);
    }
    let base = m.base_rtt().unwrap();
    assert!(
        base >= Duration::from_micros(19_000),
        "drift rebase: base_rtt={base:?}"
    );
}

#[test]
fn qdelay_and_gradient_track_queue_growth() {
    let mut m = PathModel::new(MSS);
    // Floor at 10ms.
    for i in 0..20u64 {
        let (s, f) = rs(i * 10_000, MSS, MSS, 10_000, 10_000, 0, 0, false, 0);
        m.on_rate_sample(&s, f, &rtt_state(10_000));
    }
    // RTT climbs 5ms above the floor.
    let mut r = RttState::new();
    for _ in 0..8 {
        r.sample(Duration::from_micros(15_000));
    }
    for i in 0..20u64 {
        let (s, f) = rs(200_000 + i * 15_000, MSS, MSS, 15_000, 15_000, 0, 0, false, 8 * MSS);
        m.on_rate_sample(&s, f, &r);
    }
    let qd = m.qdelay();
    assert!(
        qd >= Duration::from_millis(4) && qd <= Duration::from_millis(6),
        "qdelay={qd:?} should be ~5ms"
    );
    // Growing sequence → gradient was positive during the climb; at a
    // plateau the EWMA decays toward 0 but stays ≥ 0.
    assert!(m.qdelay_grad_us_per_rtt() >= 0.0);
}

#[test]
fn extra_acked_counts_ack_aggregation() {
    let mut m = PathModel::new(MSS);
    let rtt = rtt_state(10_000);
    // est: 1 MSS / 1ms.
    for i in 0..20u64 {
        let (s, f) = rs(i * 1_000, MSS, MSS, 10_000, 1_000, 0, 0, false, 8 * MSS);
        m.on_rate_sample(&s, f, &rtt);
    }
    assert_eq!(m.extra_acked(), 0);
    // Compressed ACK: 8 segments acked over a 4ms interval — the model
    // expected ~4×MSS; the extra 4×MSS is aggregation over-count.
    let (s, f) = rs(30_000, 8 * MSS, 8 * MSS, 10_000, 4_000, 0, 0, false, 8 * MSS);
    m.on_rate_sample(&s, f, &rtt);
    assert!(m.extra_acked() > 0, "compressed ACK must feed extra_acked");
}

#[test]
fn loss_columns_split_by_qdelay_elevation() {
    let mut m = PathModel::new(MSS);
    // Floor at 10ms, quiet losses → quiet column.
    let rtt10 = rtt_state(10_000);
    for i in 0..40u64 {
        let lost = if i % 10 == 0 { MSS } else { 0 };
        let (s, f) = rs(i * 10_000, MSS, MSS, 10_000, 10_000, lost, 0, false, 0);
        m.on_rate_sample(&s, f, &rtt10);
    }
    // Elevated qdelay: srtt 15ms vs floor 10ms.
    let rtt15 = rtt_state(15_000);
    for i in 0..10u64 {
        let lost = if i % 5 == 0 { MSS } else { 0 };
        let (s, f) = rs(
            500_000 + i * 15_000,
            MSS,
            MSS,
            15_000,
            15_000,
            lost,
            0,
            false,
            8 * MSS,
        );
        m.on_rate_sample(&s, f, &rtt15);
    }
    let (qd_loss, quiet_loss) = m.loss_columns();
    assert_eq!(qd_loss, 2 * MSS, "elevated-qdelay losses: {qd_loss}");
    assert_eq!(quiet_loss, 4 * MSS, "quiet losses: {quiet_loss}");
    assert!(m.burst_len() > 0.0);
}

#[test]
fn p_rand_estimates_quiet_loss_baseline() {
    let mut m = PathModel::new(MSS);
    let rtt = rtt_state(10_000);
    // 5% quiet loss over ≥64KiB.
    let mut now = 0u64;
    for i in 0..200u64 {
        now += 1_000;
        let lost = if i % 20 == 0 { MSS } else { 0 };
        let (s, f) = rs(now, MSS, MSS, 10_000, 1_000, lost, 0, false, 0);
        m.on_rate_sample(&s, f, &rtt);
    }
    let p = m.p_rand().unwrap();
    assert!(
        (p - 0.05).abs() < 0.02,
        "p_rand={p} should track ~5% quiet loss"
    );
}

#[test]
fn causal_test_compares_post_speedup_loss_to_baseline() {
    let mut m = PathModel::new(MSS);
    let rtt = rtt_state(10_000);
    // Quiet baseline ~2%.
    for i in 0..200u64 {
        let lost = if i % 50 == 0 { MSS } else { 0 };
        let (s, f) = rs(i * 1_000, MSS, MSS, 10_000, 1_000, lost, 0, false, 0);
        m.on_rate_sample(&s, f, &rtt);
    }
    // Speed-up window: 20% loss inside.
    m.note_speedup(t(200_000), Duration::from_secs(1));
    for i in 0..40u64 {
        let lost = if i % 5 == 0 { MSS } else { 0 };
        let (s, f) = rs(200_000 + i * 1_000, MSS, MSS, 10_000, 1_000, lost, 0, false, 0);
        m.on_rate_sample(&s, f, &rtt);
    }
    let c = m.loss_causation().unwrap();
    assert!(c > 5.0, "loss causation ratio {c} should be >> 1");
}

#[test]
fn alpha_tracks_ce_fraction() {
    let mut m = PathModel::new(MSS);
    let rtt = rtt_state(10_000);
    for i in 0..40u64 {
        // 10% of delivered bytes CE-marked (AccECN-grain).
        let ce = MSS / 10;
        let (s, f) = rs(i * 1_000, MSS, MSS, 10_000, 1_000, 0, ce, false, 0);
        m.on_rate_sample(&s, f, &rtt);
    }
    let a = m.alpha().unwrap();
    assert!((a - 0.1).abs() < 0.03, "alpha={a} should track ~0.1");
}

#[test]
fn lt_bw_policer_detects_sustained_flat_loss() {
    let mut m = PathModel::new(MSS);
    let rtt = rtt_state(10_000);
    // Flat bw, one loss per RTT round — after LT_INTVL_MIN_RTT rounds the
    // policer verdict pins lt_bw.
    for round in 0..8u64 {
        for j in 0..4u64 {
            let now = round * 10_000 + j * 2_000;
            let lost = if j == 0 { MSS } else { 0 };
            let (s, f) = rs(now, MSS, MSS, 10_000, 2_000, lost, 0, false, 8 * MSS);
            m.on_rate_sample(&s, f, &rtt);
        }
    }
    assert!(m.lt_bw().is_some(), "sustained flat loss must pin lt_bw");
}

#[test]
fn delay_signal_quality_drops_when_jitter_swamps_signal() {
    let mut quiet = PathModel::new(MSS);
    let mut noisy = PathModel::new(MSS);
    // The noisy path needs ONE persistent RttState: its srtt converges to
    // the jitter mean, so |sample − srtt| exposes the ±40% swings. A fresh
    // RttState per sample would make srtt track each sample exactly and
    // report zero deviation.
    let mut noisy_rtt = RttState::new();
    for i in 0..40u64 {
        let (s, f) = rs(i * 10_000, MSS, MSS, 10_000, 10_000, 0, 0, false, 0);
        quiet.on_rate_sample(&s, f, &rtt_state(10_000));
        // ±40% RTT swings at low inflight.
        let nrtt = 10_000 + (i % 4) * 4_000;
        noisy_rtt.sample(Duration::from_micros(nrtt));
        let (s2, f2) = rs(i * 10_000, MSS, MSS, nrtt, 10_000, 0, 0, false, 0);
        noisy.on_rate_sample(&s2, f2, &noisy_rtt);
    }
    let q = quiet.delay_signal_quality().unwrap();
    let n = noisy.delay_signal_quality().unwrap();
    assert!(q > 0.8, "clean path quality {q}");
    assert!(n < q, "noisy path quality {n} should be lower than {q}");
}

#[test]
fn spurious_retx_ratio_tracks_dsack_evidence() {
    let mut m = PathModel::new(MSS);
    m.note_retx(4 * MSS);
    m.note_spurious_retx(MSS);
    assert_eq!(m.spurious_ratio(), Some(0.25));
}
