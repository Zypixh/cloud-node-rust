use cloud_node_transport::CongestionController;
use cloud_node_transport::cc::reference::Bbr3Ref;
use cloud_node_transport::edgecc::{EdgeCc, Tier};
use cloud_node_transport::sim::{Policer, SimConfig, run};
use std::time::Duration;

fn cell(delay_ms: u64, policer_mbps: u64, burst_bytes: u64, link_mbps: u64) {
    let mut cfg = SimConfig {
        delay: Duration::from_millis(delay_ms / 2),
        ack_delay_prop: Duration::from_millis(delay_ms / 2),
        rate_bps: link_mbps * 125_000,
        policer: Some(Policer {
            rate_bps: policer_mbps * 125_000,
            burst_bytes,
        }),
        buffer_bytes: 64 * 1024,
        mss: 1460,
        total_bytes: 20 * 1024 * 1024,
        duration: Duration::from_secs(300),
        seed: 0x9e37_79b9_7f4a_7c15,
        ..SimConfig::default()
    };
    let mut ec = EdgeCc::new(cfg.mss, Tier::T1, None, false);
    let res = run(&mut ec, &cfg);
    let snap = ec.snapshot();
    println!(
        "  {:>7}: done={} fct={:.1}s rtos={} retx={} goodput={:.2}MB/s mode={} reason={} lt_bw={:?} bw_est={:?}",
        "edgecc",
        res.completed,
        res.fct_us as f64 / 1e6,
        res.rto_events,
        res.retransmits,
        res.delivered_bytes as f64 / 1e6 / (res.fct_us as f64 / 1e6).max(1e-9),
        snap.mode,
        snap.reason_code,
        ec.model.lt_bw(),
        ec.model.bw_est(),
    );
    let mut cc: Box<dyn CongestionController> = Box::new(Bbr3Ref::new(cfg.mss));
    let res = run(&mut *cc, &cfg);
    let snap = cc.snapshot();
    println!(
        "  {:>7}: done={} fct={:.1}s rtos={} retx={} goodput={:.2}MB/s mode={} reason={}",
        "bbr3",
        res.completed,
        res.fct_us as f64 / 1e6,
        res.rto_events,
        res.retransmits,
        res.delivered_bytes as f64 / 1e6 / (res.fct_us as f64 / 1e6).max(1e-9),
        snap.mode,
        snap.reason_code,
    );
}

fn main() {
    for (name, rtt, pm, burst, lm) in [
        ("rtt80 policer10M burst64K link100M", 80u64, 10u64, 65536u64, 100u64),
        ("rtt80 policer10M burst128K link100M", 80, 10, 131072, 100),
        ("rtt80 policer10M burst256K link100M", 80, 10, 262144, 100),
        ("rtt150 policer10M burst128K link100M", 150, 10, 131072, 100),
    ] {
        println!("== {name}");
        cell(rtt, pm, burst, lm);
    }
}
