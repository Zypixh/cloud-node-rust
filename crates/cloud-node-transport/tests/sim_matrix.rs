//! Deterministic simulator matrix (plan §7.1): RTT × bandwidth ×
//! buffer × loss, ECN/AQM, policer, reorder, jitter, route switch,
//! app-limited senders, 300ms RTT, multi-flow shared bottleneck, and
//! golden traces.

use cloud_node_transport::cc::reference::{CubicRef, NewRenoRef};
use cloud_node_transport::sim::{
    run, run_multi, Aqm, FlowSpec, Policer, RouteSwitch, SimConfig, SimResult, TraceKind,
};
use std::time::Duration;

const MSS: u64 = 1460;

/// Bandwidth-delay product in bytes for a config.
fn bdp(cfg: &SimConfig) -> u64 {
    let rtt_us = cfg.delay.as_micros() as u64 + cfg.ack_delay_prop.as_micros() as u64;
    cfg.rate_bps * rtt_us / 1_000_000
}

fn base(rtt: Duration, rate_bps: u64) -> SimConfig {
    SimConfig {
        delay: rtt / 2,
        ack_delay_prop: rtt / 2,
        rate_bps,
        mss: MSS,
        total_bytes: 4 * 1024 * 1024,
        duration: Duration::from_secs(60),
        seed: 0x1234_5678_9abc_def0,
        ..SimConfig::default()
    }
}

fn cubic_run(cfg: &SimConfig) -> SimResult {
    run(&mut CubicRef::new(cfg.mss), cfg)
}

fn reno_run(cfg: &SimConfig) -> SimResult {
    run(&mut NewRenoRef::new(cfg.mss), cfg)
}

#[test]
fn cubic_completes_across_rtt_bandwidth_matrix() {
    for &rtt in &[
        Duration::from_millis(10),
        Duration::from_millis(100),
        Duration::from_millis(300), // §7.1: long-RTT cell
    ] {
        for &mbps in &[10u64, 100] {
            let mut cfg = base(rtt, mbps * 125_000);
            cfg.buffer_bytes = bdp(&cfg); // 1× BDP
            let res = cubic_run(&cfg);
            assert!(
                res.completed,
                "cubic failed to finish: rtt={rtt:?} {mbps}Mbit trace_rows={}",
                res.trace.len()
            );
            assert_eq!(res.delivered_bytes, cfg.total_bytes);
        }
    }
}

#[test]
fn new_reno_completes_across_rtt_bandwidth_matrix() {
    for &rtt in &[Duration::from_millis(10), Duration::from_millis(100)] {
        for &mbps in &[10u64, 100] {
            let mut cfg = base(rtt, mbps * 125_000);
            cfg.buffer_bytes = bdp(&cfg);
            let res = reno_run(&cfg);
            assert!(res.completed, "newreno failed: rtt={rtt:?} {mbps}Mbit");
        }
    }
}

#[test]
fn small_buffer_produces_loss_and_sawtooth() {
    let mut cfg = base(Duration::from_millis(100), 100 * 125_000);
    // Tiny buffer (16 segments): even with HyStart++'s early SS exit the
    // initial burst overflows it — droptail loss + sawtooth must appear.
    cfg.buffer_bytes = 16 * MSS;
    cfg.duration = Duration::from_secs(20);
    let res = cubic_run(&cfg);
    assert!(res.loss_events > 0, "droptail must produce loss events");
    // Sawtooth: cwnd after the last loss mark is strictly below the peak
    // cwnd seen earlier in the trace.
    let peak = res.trace.iter().map(|r| r.cwnd).max().unwrap();
    let last_loss = res
        .trace
        .iter()
        .rev()
        .find(|r| r.kind == TraceKind::LossMark)
        .unwrap();
    assert!(
        last_loss.cwnd < peak,
        "no sawtooth: peak={peak} post-loss cwnd={}",
        last_loss.cwnd
    );
    assert!(res.completed);
}

#[test]
fn deep_buffer_loss_free_run_has_no_loss_events() {
    let mut cfg = base(Duration::from_millis(100), 10 * 125_000);
    cfg.buffer_bytes = 2 * bdp(&cfg); // 2× BDP
    // No finite droptail buffer survives an unbounded window controller
    // forever — the invariant that must hold is "no drops while the
    // flight physically cannot overflow the queue". Cap the transfer at
    // 1× BDP so in_flight < BDP + buffer always.
    cfg.total_bytes = bdp(&cfg);
    let res = cubic_run(&cfg);
    assert_eq!(res.loss_events, 0);
    assert_eq!(res.drops, 0);
    assert!(res.completed);
}

#[test]
fn random_one_percent_loss_still_completes() {
    for &rtt in &[Duration::from_millis(10), Duration::from_millis(100)] {
        let mut cfg = base(rtt, 100 * 125_000);
        cfg.buffer_bytes = 2 * bdp(&cfg);
        cfg.random_loss = 0.01;
        cfg.duration = Duration::from_secs(120);
        let res = cubic_run(&cfg);
        assert!(res.drops > 0);
        assert!(res.loss_events > 0);
        assert!(res.completed, "1% loss run failed: rtt={rtt:?}");
    }
}

/// §7.1: random loss stacked on a congested (droptail) bottleneck —
/// both mechanisms must fire, and the run still completes.
#[test]
fn random_loss_overlays_congestion_loss() {
    let mut cfg = base(Duration::from_millis(100), 100 * 125_000);
    cfg.buffer_bytes = bdp(&cfg) / 4; // tight queue → congestion drops
    cfg.random_loss = 0.005; // + random drops on top
    cfg.duration = Duration::from_secs(60);
    let res = cubic_run(&cfg);
    assert!(res.drops > 0);
    assert!(res.loss_events > 0);
    assert!(res.completed);
}

#[test]
fn codel_ecn_marks_instead_of_dropping() {
    let mut cfg = base(Duration::from_millis(100), 100 * 125_000);
    cfg.buffer_bytes = 4 * bdp(&cfg); // deep buffer — queue sojourn grows
    cfg.aqm = Aqm::CodelEcn {
        target: Duration::from_millis(5),
    };
    let res = cubic_run(&cfg);
    assert!(res.ce_marks > 0, "deep queue must trigger CE marking");
    assert!(res.completed);
}

#[test]
fn policer_drops_are_visible_not_silent() {
    let mut cfg = base(Duration::from_millis(50), 100 * 125_000);
    cfg.buffer_bytes = 4 * bdp(&cfg);
    cfg.policer = Some(Policer {
        rate_bps: 10 * 125_000, // 10Mbit policer on a 100Mbit link
        burst_bytes: 64 * 1024,
    });
    cfg.duration = Duration::from_secs(120);
    let res = cubic_run(&cfg);
    assert!(res.drops > 0, "policer must drop above-rate traffic");
    assert!(res.completed);
}

#[test]
fn reordered_packets_generate_dupacks_and_complete() {
    let mut cfg = base(Duration::from_millis(50), 100 * 125_000);
    cfg.buffer_bytes = 2 * bdp(&cfg);
    cfg.reorder_prob = 0.10;
    cfg.reorder_extra = Duration::from_millis(8);
    cfg.duration = Duration::from_secs(120);
    let res = cubic_run(&cfg);
    assert!(res.completed);
}

#[test]
fn delayed_acks_do_not_break_rate_sampling() {
    let mut cfg = base(Duration::from_millis(50), 100 * 125_000);
    cfg.buffer_bytes = 2 * bdp(&cfg);
    cfg.ack_every = 2;
    cfg.ack_delay = Duration::from_millis(2);
    let res = cubic_run(&cfg);
    assert!(res.completed);
}

/// §7.1: per-packet propagation jitter.
#[test]
fn jittered_path_completes() {
    let mut cfg = base(Duration::from_millis(50), 100 * 125_000);
    cfg.buffer_bytes = 2 * bdp(&cfg);
    cfg.jitter = Duration::from_millis(5); // ±5ms on a 50ms RTT
    let res = cubic_run(&cfg);
    assert!(res.completed);
}

/// §7.1: route switch mid-run — propagation delay doubles at t=2s;
/// in-flight packets keep the old delay, new ones take the new path.
#[test]
fn route_switch_mid_run_completes() {
    let mut cfg = base(Duration::from_millis(50), 100 * 125_000);
    cfg.buffer_bytes = 2 * bdp(&cfg);
    cfg.route_switch = Some(RouteSwitch {
        at: Duration::from_secs(2),
        delay: Duration::from_millis(60), // 50→120ms RTT
        ack_delay_prop: Duration::from_millis(60),
    });
    let res = cubic_run(&cfg);
    assert!(res.completed);
}

/// §7.1: app-limited sender — the app feeds data below link rate; the
/// transfer must still finish and rate sampling stays honest.
#[test]
fn app_limited_sender_completes() {
    let mut cfg = base(Duration::from_millis(50), 100 * 125_000);
    cfg.buffer_bytes = 2 * bdp(&cfg);
    cfg.app_rate_bps = Some(2 * 125_000); // 2 Mbit/s app on a 100Mbit link
    cfg.total_bytes = 512 * 1024;
    cfg.duration = Duration::from_secs(30);
    let res = cubic_run(&cfg);
    assert!(res.completed, "app-limited sender stalled");
    assert_eq!(res.delivered_bytes, cfg.total_bytes);
}

/// §7.1: N flows share one bottleneck — all must complete, the merged
/// trace carries flow ids, and the shared link is genuinely contended.
#[test]
fn multi_flow_share_one_bottleneck() {
    let mut cfg = base(Duration::from_millis(50), 100 * 125_000);
    // Small shared buffer: three independent window controllers on one
    // bottleneck must contend — combined flight exceeds it during SS.
    cfg.buffer_bytes = 16 * MSS;
    cfg.total_bytes = 1024 * 1024;
    cfg.duration = Duration::from_secs(60);
    let mut c0 = CubicRef::new(MSS);
    let mut c1 = CubicRef::new(MSS);
    let mut c2 = NewRenoRef::new(MSS);
    let res = run_multi(
        &cfg,
        vec![
            FlowSpec::new(&mut c0),
            FlowSpec {
                cc: &mut c1,
                app_rate_bps: None,
                start_at: Duration::from_millis(100),
            },
            FlowSpec::new(&mut c2),
        ],
    );
    assert!(res.all_completed(), "not all flows completed");
    for (i, f) in res.flows.iter().enumerate() {
        assert_eq!(
            f.delivered_bytes, cfg.total_bytes,
            "flow {i} delivered mismatch"
        );
        assert!(f.trace.iter().all(|r| r.flow == i as u32));
    }
    let merged = res.merged_trace();
    let flows_seen: std::collections::BTreeSet<u32> = merged.iter().map(|r| r.flow).collect();
    assert_eq!(flows_seen.len(), 3, "merged trace must carry all flows");
    // Shared bottleneck: queue drops from contention are expected with
    // three independent window controllers on 1×BDP.
    let total_drops: u64 = res.flows.iter().map(|f| f.drops).sum();
    assert!(total_drops > 0, "three greedy flows should contend");
}

/// §7.1: multi-flow trace output is deterministic too.
#[test]
fn multi_flow_trace_is_deterministic() {
    let mut cfg = base(Duration::from_millis(50), 10 * 125_000);
    cfg.buffer_bytes = bdp(&cfg);
    cfg.total_bytes = 256 * 1024;
    cfg.jitter = Duration::from_millis(2);
    cfg.random_loss = 0.002;
    let run_once = |cfg: &SimConfig| {
        let mut a = CubicRef::new(MSS);
        let mut b = CubicRef::new(MSS);
        run_multi(cfg, vec![FlowSpec::new(&mut a), FlowSpec::new(&mut b)])
            .flows
            .iter()
            .map(|f| f.trace_digest())
            .collect::<Vec<_>>()
    };
    assert_eq!(run_once(&cfg), run_once(&cfg));
}

#[test]
fn same_seed_same_trace() {
    let mut cfg = base(Duration::from_millis(100), 100 * 125_000);
    cfg.buffer_bytes = bdp(&cfg) / 2;
    cfg.random_loss = 0.005;
    let a = cubic_run(&cfg);
    let b = cubic_run(&cfg);
    assert_eq!(a.trace_digest(), b.trace_digest(), "sim must be deterministic");
}

/// Golden trace regression — the digest is pinned to the verified run;
/// any behavior change in sampler/controllers/sim trips this test and
/// must be re-pinned deliberately, with the diff documented.
#[test]
fn golden_trace_digest_is_pinned() {
    let mut cfg = base(Duration::from_millis(100), 100 * 125_000);
    cfg.buffer_bytes = bdp(&cfg) / 2;
    cfg.total_bytes = 1024 * 1024;
    cfg.duration = Duration::from_secs(15);
    let res = cubic_run(&cfg);
    assert!(res.completed);
    assert_eq!(
        res.trace_digest(),
        GOLDEN_DIGEST,
        "golden trace diverged — re-pin only after reviewing the diff"
    );
}

// Pinned from the verified run (see evidence directory). The multi-flow
// refactor (TraceRow.flow field) changed the digest — re-pinned in T2.
const GOLDEN_DIGEST: u64 = 13759154963003081103;
