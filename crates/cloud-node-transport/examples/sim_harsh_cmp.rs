use cloud_node_transport::CongestionController;
use cloud_node_transport::cc::reference::Bbr3Ref;
use cloud_node_transport::edgecc::{EdgeCc, Tier};
use cloud_node_transport::sim::{SimConfig, run};
use std::time::Duration;

fn cell(delay_ms: u64, loss: f64, rate_mbps: u64) {
    let mut cfg = SimConfig {
        delay: Duration::from_millis(delay_ms / 2),
        ack_delay_prop: Duration::from_millis(delay_ms / 2),
        rate_bps: rate_mbps * 125_000,
        random_loss: loss,
        mss: 1460,
        total_bytes: 2 * 1024 * 1024,
        duration: Duration::from_secs(240),
        seed: 0x9e37_79b9_7f4a_7c15,
        ..SimConfig::default()
    };
    cfg.buffer_bytes = cfg.rate_bps * (delay_ms as u64) * 1000 / 1_000_000;

    for (label, mut cc) in [
        (
            "edgecc",
            Box::new(EdgeCc::new(cfg.mss, Tier::T1, None, false)) as Box<dyn CongestionController>,
        ),
        ("bbr3", Box::new(Bbr3Ref::new(cfg.mss))),
    ] {
        let res = run(&mut *cc, &cfg);
        let snap = cc.snapshot();
        println!(
            "  {label:>7}: done={} fct={:.1}s rtos={} retx={} mode={} reason={}",
            res.completed,
            res.fct_us as f64 / 1e6,
            res.rto_events,
            res.retransmits,
            snap.mode,
            snap.reason_code,
        );
    }
}

fn main() {
    for (name, rtt, loss, mbps) in [
        ("rtt250+loss20%+100M", 250u64, 0.20, 100u64),
        ("rtt300+loss30%+100M", 300, 0.30, 100),
        ("rtt200+loss20%+10M", 200, 0.20, 10),
        ("rtt100+loss5%+100M", 100, 0.05, 100),
        ("clean rtt100+100M", 100, 0.0, 100),
    ] {
        println!("== {name}");
        cell(rtt, loss, mbps);
    }
}
