//! Temporary debug: dump EdgeCC trace stats on a harsh cell.
use cloud_node_transport::edgecc::{EdgeCc, Tier};
use cloud_node_transport::CongestionController;
use cloud_node_transport::sim::{run, SimConfig, TraceKind};
use std::time::Duration;

fn main() {
    let mut cfg = SimConfig {
        delay: Duration::from_millis(125),
        ack_delay_prop: Duration::from_millis(125),
        rate_bps: 100 * 125_000,
        random_loss: 0.20,
        mss: 1460,
        total_bytes: 2 * 1024 * 1024,
        duration: Duration::from_secs(240),
        buffer_bytes: 3_125_000,
        seed: 0x9e37_79b9_7f4a_7c15,
        ..SimConfig::default()
    };
    cfg.buffer_bytes = cfg.rate_bps * 250_000 / 1_000_000; // 1 BDP
    let mut cc = EdgeCc::new(cfg.mss, Tier::T1, None, false);
    let res = run(&mut cc, &cfg);
    eprintln!(
        "completed={} delivered={} fct_us={} drops={} loss_events={} rtos={} retx={}",
        res.completed, res.delivered_bytes, res.fct_us, res.drops, res.loss_events, res.rto_events, res.retransmits
    );
    let snap = cc.snapshot();
    eprintln!(
        "mode={} reason={} cwnd={} pacing={:?} bw_lo={:?} bw_hi={:?} p_rand={:?} belief={:?} env={:?} inflight_lo={:?}",
        snap.mode, snap.reason_code, snap.cwnd_bytes, snap.pacing_rate_bps,
        snap.bandwidth_lo_bps, snap.bandwidth_hi_bps, snap.p_rand_milli,
        snap.belief_milli, snap.envelope_bytes, snap.inflight_lo_bytes,
    );
    eprintln!(
        "model: bw_est={:?} bw_max={:?} bdp={:?} base_rtt={:?} qdelay={:?} lo={:.2}",
        cc.model.bw_est(), cc.model.bw_max(), cc.model.bdp_est(),
        cc.model.base_rtt(), cc.model.qdelay(), cc.infer.log_odds(),
    );
    eprintln!(
        "loss_cols(qd,quiet) bytes={:?} events={:?} burst_len={:.2} p_rand={:?} lt_bw={:?} dsq={:?}",
        cc.model.loss_columns(), cc.model.loss_events(), cc.model.burst_len(),
        cc.model.p_rand(), cc.model.lt_bw(), cc.model.delay_signal_quality(),
    );
    eprintln!(
        "infer weights: ce={:.2} qdelay={:.2} loss_qd={:.2} quiet={:.2} plateau={:.2}",
        cc.infer.w_ce_total, cc.infer.w_qdelay_total, cc.infer.w_loss_qd_total,
        cc.infer.w_quiet_total, cc.infer.w_plateau_total,
    );
    // cwnd histogram over time
    let mut buckets = std::collections::BTreeMap::new();
    for r in &res.trace {
        let kb = r.cwnd / 1024;
        *buckets.entry(kb).or_insert(0u64) += 1;
    }
    eprintln!("cwnd histogram (KB -> event count):");
    for (k, v) in buckets.iter().take(30) {
        eprintln!("  {k}KB -> {v}");
    }
    // event kind counts + cwnd at RTO
    let mut kinds = std::collections::BTreeMap::new();
    for r in &res.trace {
        *kinds.entry(format!("{:?}", r.kind)).or_insert(0u64) += 1;
    }
    eprintln!("kind counts: {kinds:?}");
    // sample cwnd at a few time points
    for frac in [0.1f64, 0.3, 0.5, 0.7, 0.9] {
        let t = (res.fct_us.max(res.trace.last().map(|r| r.t_us).unwrap_or(0)) as f64 * frac) as u64;
        let row = res.trace.iter().find(|r| r.t_us >= t);
        if let Some(r) = row {
            eprintln!("t={}ms kind={:?} cwnd={} flight={} delivered={}", r.t_us / 1000, r.kind, r.cwnd, r.in_flight, r.delivered_total);
        }
    }
    let _ = TraceKind::Send;
}
