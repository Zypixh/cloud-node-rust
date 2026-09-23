use cloud_node_transport::CongestionController;
use cloud_node_transport::cc::reference::Bbr3Ref;
use cloud_node_transport::edgecc::{EdgeCc, Tier};
use cloud_node_transport::sim::{LossModel, SimConfig, run};
use std::time::Duration;

fn cell(delay_ms: u64, loss_model: Option<LossModel>, uniform_loss: f64, rate_mbps: u64) {
    let mut cfg = SimConfig {
        delay: Duration::from_millis(delay_ms / 2),
        ack_delay_prop: Duration::from_millis(delay_ms / 2),
        rate_bps: rate_mbps * 125_000,
        random_loss: uniform_loss,
        loss_model,
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
    // ~20% average loss under Gilbert-Elliott: p_gb=0.02, p_bg=0.08
    // gives mean burst length ~12.5 pkts and bad-state occupancy 20%;
    // p_bad=1.0 inside bursts, p_good=0 outside.
    let ge20 = LossModel::GilbertElliott {
        p_gb: 0.02,
        p_bg: 0.08,
        p_good: 0.0,
        p_bad: 1.0,
    };
    // ~5% mean loss, sd 4%, resampled every 100ms — slow quality drift.
    let nv5 = LossModel::NormalVarying {
        mean: 0.05,
        sd: 0.04,
        period: Duration::from_millis(100),
    };
    for (name, rtt, lm, ul, mbps) in [
        ("rtt250 uniform20% 100M", 250u64, None, 0.20, 100u64),
        ("rtt250 GE-burst~20% 100M", 250, Some(ge20), 0.0, 100),
        ("rtt200 uniform20% 10M", 200, None, 0.20, 10),
        ("rtt200 GE-burst~20% 10M", 200, Some(ge20), 0.0, 10),
        ("rtt100 uniform5% 100M", 100, None, 0.05, 100),
        ("rtt100 NV-drift~5% 100M", 100, Some(nv5), 0.0, 100),
        ("rtt300 GE-burst~20% 100M", 300, Some(ge20), 0.0, 100),
        ("clean rtt100 100M", 100, None, 0.0, 100),
    ] {
        println!("== {name}");
        cell(rtt, lm, ul, mbps);
    }
}
