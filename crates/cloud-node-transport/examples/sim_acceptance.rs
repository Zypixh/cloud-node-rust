//! §7/§8 acceptance matrix runner: sweeps the plan's RTT × loss ×
//! bandwidth grid plus per-axis slices (buffer, policer, jitter, AQM,
//! route switch, concurrency) over EdgeCC, its ablation variants, and
//! the pinned references. Emits CSV rows; deterministic per (cell,
//! replica) seed so runs are reproducible.
//!
//! Usage: cargo run -p cloud-node-transport --release --example \
//!          sim_acceptance > matrix.csv

use cloud_node_transport::cc::reference::{
    Bbr3Ref, CubicRef, LossBlindRef, NewRenoRef,
};
use cloud_node_transport::cc::CongestionController;
use cloud_node_transport::edgecc::{Ablations, EdgeCc, PathPrior, Tier};
use cloud_node_transport::sim::{
    run, run_multi, Aqm, FlowSpec, Policer, RouteSwitch, SimConfig, SimResult,
};
use std::time::Duration;

const MSS: u64 = 1460;
const TOTAL_BYTES: u64 = 4 * 1024 * 1024;
const RUN_DURATION: Duration = Duration::from_secs(60);
const REPLICAS: u32 = 3;

#[derive(Clone, Copy)]
struct Variant {
    name: &'static str,
    kind: Vk,
}

#[derive(Clone, Copy)]
enum Vk {
    Edge(Ablations, bool /* prand_off */, bool /* prior */),
    LossBlindFlag, // EdgeCc.loss_blind — the §2.9 ablation path
    Bbr3,
    LossBlindRef,
    Cubic,
    NewReno,
}

const NO_ABLATE: Ablations = Ablations {
    no_probe: false,
    no_utility: false,
    no_belief: false,
    no_plateau: false,
};

const VARIANTS: &[Variant] = &[
    Variant { name: "edgecc", kind: Vk::Edge(NO_ABLATE, false, false) },
    Variant {
        name: "edgecc_no_probe",
        kind: Vk::Edge(Ablations { no_probe: true, ..NO_ABLATE }, false, false),
    },
    Variant {
        name: "edgecc_no_utility",
        kind: Vk::Edge(Ablations { no_utility: true, ..NO_ABLATE }, false, false),
    },
    Variant {
        name: "edgecc_no_belief",
        kind: Vk::Edge(Ablations { no_belief: true, ..NO_ABLATE }, false, false),
    },
    Variant {
        name: "edgecc_no_plateau",
        kind: Vk::Edge(Ablations { no_plateau: true, ..NO_ABLATE }, false, false),
    },
    Variant {
        name: "edgecc_no_prand",
        kind: Vk::Edge(NO_ABLATE, true, false),
    },
    Variant { name: "edgecc_loss_blind", kind: Vk::LossBlindFlag },
    Variant { name: "edgecc_prior", kind: Vk::Edge(NO_ABLATE, false, true) },
    Variant { name: "bbr3ref", kind: Vk::Bbr3 },
    Variant { name: "lossblindref", kind: Vk::LossBlindRef },
    Variant { name: "cubicref", kind: Vk::Cubic },
    Variant { name: "newrenoref", kind: Vk::NewReno },
];

fn build(v: &Variant, cfg: &SimConfig) -> Box<dyn CongestionController> {
    match &v.kind {
        Vk::Edge(ab, prand_off, prior) => {
            let prior = prior.then(|| PathPrior {
                bw_bps: cfg.rate_bps,
                base_rtt: cfg.delay + cfg.ack_delay_prop,
                p_rand: cfg.random_loss,
                alpha: 0.0,
                confidence: 0.8,
            });
            let mut cc = EdgeCc::new(cfg.mss, Tier::T1, prior, false);
            cc.ablations = *ab;
            cc.infer.prand_off = *prand_off;
            Box::new(cc)
        }
        Vk::LossBlindFlag => {
            let mut cc = EdgeCc::new(cfg.mss, Tier::T1, None, false);
            cc.loss_blind = true;
            Box::new(cc)
        }
        Vk::Bbr3 => Box::new(Bbr3Ref::new(cfg.mss)),
        Vk::LossBlindRef => Box::new(LossBlindRef::new(cfg.mss, Tier::T1, None, false)),
        Vk::Cubic => Box::new(CubicRef::new(cfg.mss)),
        Vk::NewReno => Box::new(NewRenoRef::new(cfg.mss)),
    }
}

fn bdp(cfg: &SimConfig) -> u64 {
    let rtt_us = cfg.delay.as_micros() as u64 + cfg.ack_delay_prop.as_micros() as u64;
    cfg.rate_bps * rtt_us / 1_000_000
}

fn base_cell(rtt_ms: u64, mbps: u64, loss_pct: f64) -> SimConfig {
    SimConfig {
        delay: Duration::from_millis(rtt_ms / 2),
        ack_delay_prop: Duration::from_millis(rtt_ms / 2),
        rate_bps: mbps * 125_000,
        random_loss: loss_pct / 100.0,
        mss: MSS,
        total_bytes: TOTAL_BYTES,
        duration: RUN_DURATION,
        ..SimConfig::default()
    }
}

/// Queue-delay distribution from the sim's Karn-filtered per-ACK RTT
/// samples minus the configured propagation floor. Using send→ack edge
/// reconstruction from the trace conflates queueing with loss-recovery
/// stalls, so the harness records clean RTT samples directly.
fn qdelay_quantiles(res: &SimResult, base_rtt_us: u64) -> (u64, u64, u64) {
    if res.rtt_samples_us.is_empty() {
        return (0, 0, 0);
    }
    let mut samples: Vec<u64> = res
        .rtt_samples_us
        .iter()
        .map(|r| r.saturating_sub(base_rtt_us))
        .collect();
    samples.sort_unstable();
    let q = |p: f64| samples[((samples.len() - 1) as f64 * p) as usize];
    (q(0.5), q(0.95), q(0.99))
}

fn fct_us(res: &SimResult, _total: u64, cap_us: u64) -> u64 {
    if res.fct_us > 0 {
        res.fct_us
    } else {
        cap_us
    }
}

fn seed_for(cell_id: u64, replica: u32) -> u64 {
    let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ cell_id.wrapping_mul(0x2545_f491_4f6c_dd1d);
    x ^= replica as u64;
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x
}

/// Optional `SIM_ONLY=cell:variant[:replica]` filter for ad-hoc
/// profiling runs; unset = full matrix.
fn selected(cell: &str, variant: &str, replica: u32) -> bool {
    let Ok(f) = std::env::var("SIM_ONLY") else {
        return true;
    };
    let mut it = f.splitn(3, ':');
    it.next() == Some(cell)
        && it.next() == Some(variant)
        && it.next().map_or(true, |r| r == replica.to_string())
}

fn run_cell(v: &Variant, cfg: &SimConfig, flows: u32, cell: &str, replica: u32) {
    if !selected(cell, v.name, replica) {
        return;
    }
    let mut cfg = *cfg;
    cfg.seed = seed_for(cfg.seed, replica);
    // Multi-flow runs don't need the event trace — metrics come from
    // rtt_samples/fct_us/result counters — and the merged trace is the
    // dominant memory cost at concur100 scale.
    cfg.collect_trace = flows <= 1;
    let base_rtt_us = (cfg.delay + cfg.ack_delay_prop).as_micros() as u64;
    if flows <= 1 {
        let mut cc = build(v, &cfg);
        let res = run(&mut *cc, &cfg);
        if std::env::var("SIM_DEBUG").is_ok() {
            eprintln!(
                "dbg {cell}/{}/{replica}: trace_rows={} rtt_samples={}",
                v.name,
                res.trace.len(),
                res.rtt_samples_us.len()
            );
        }
        let fct = fct_us(&res, cfg.total_bytes, cfg.duration.as_micros() as u64);
        let elapsed = fct.max(1);
        let goodput = res.delivered_bytes * 1_000_000 / elapsed;
        let (q50, q95, q99) = qdelay_quantiles(&res, base_rtt_us);
        println!(
            "{cell},{},{replica},{},{},{},{goodput},{},{},{},{},{q50},{q95},{q99}",
            v.name,
            res.completed,
            res.delivered_bytes,
            fct,
            res.retransmits,
            res.rto_events,
            res.drops,
            res.ce_marks,
        );
    } else {
        let mut ccs: Vec<Box<dyn CongestionController>> =
            (0..flows).map(|_| build(v, &cfg)).collect();
        let specs: Vec<FlowSpec> = ccs
            .iter_mut()
            .map(|cc| FlowSpec::new(&mut **cc))
            .collect();
        let res = run_multi(&cfg, specs);
        let mut goodputs = Vec::new();
        for (i, fr) in res.flows.iter().enumerate() {
            let fct = fct_us(fr, cfg.total_bytes, cfg.duration.as_micros() as u64);
            let goodput = fr.delivered_bytes * 1_000_000 / fct.max(1);
            goodputs.push(goodput);
            let (q50, q95, q99) = qdelay_quantiles(fr, base_rtt_us);
            println!(
                "{cell},{},{replica},{},{},{},{goodput},{},{},{},{},{q50},{q95},{q99},flow={i}",
                v.name,
                fr.completed,
                fr.delivered_bytes,
                fct,
                fr.retransmits,
                fr.rto_events,
                fr.drops,
                fr.ce_marks,
            );
        }
        let (mn, mx) = (
            goodputs.iter().min().copied().unwrap_or(0),
            goodputs.iter().max().copied().unwrap_or(0),
        );
        println!(
            "{cell},{},{replica},fairness_min={mn},fairness_max={mx},fairness_ratio={:.3}",
            v.name,
            mn as f64 / mx.max(1) as f64
        );
    }
}

fn main() {
    println!(
        "cell,variant,replica,completed,delivered_bytes,fct_us,goodput_bps,retransmits,rto_events,drops,ce_marks,qdelay_p50_us,qdelay_p95_us,qdelay_p99_us"
    );

    // Primary grid (§7.3): RTT × loss × bandwidth, buffer=1BDP,
    // droptail, single flow.
    for &rtt in &[5u64, 10, 50, 150, 300] {
        for &loss in &[0.0f64, 0.1, 1.0, 3.0, 5.0] {
            for &mbps in &[10u64, 100, 1000] {
                let mut cfg = base_cell(rtt, mbps, loss);
                cfg.buffer_bytes = bdp(&cfg);
                let cell = format!("rtt{rtt}_loss{loss}_bw{mbps}");
                for v in VARIANTS {
                    for rep in 0..REPLICAS {
                        run_cell(v, &cfg, 1, &cell, rep);
                    }
                }
            }
        }
    }

    // Axis sweeps around the mid cell (rtt=50ms, bw=100Mbit, loss=1%).
    let mid = base_cell(50, 100, 1.0);
    let mid_bdp = bdp(&mid);
    let mut slices: Vec<(String, SimConfig, u32)> = Vec::new();

    let mut c = mid;
    c.buffer_bytes = mid_bdp / 4;
    slices.push(("axis_buffer_025bdp".into(), c, 1));
    let mut c = mid;
    c.buffer_bytes = mid_bdp * 4;
    slices.push(("axis_buffer_4bdp".into(), c, 1));

    let mut c = mid;
    c.buffer_bytes = mid_bdp;
    c.policer = Some(Policer {
        rate_bps: c.rate_bps * 4 / 5,
        burst_bytes: 64 * MSS,
    });
    slices.push(("axis_policer".into(), c, 1));

    let mut c = mid;
    c.buffer_bytes = mid_bdp;
    c.jitter = Duration::from_millis(10);
    slices.push(("axis_jitter10ms".into(), c, 1));

    let mut c = mid;
    c.buffer_bytes = mid_bdp;
    c.aqm = Aqm::CodelEcn {
        target: Duration::from_millis(5),
    };
    slices.push(("axis_codel_ecn".into(), c, 1));

    let mut c = mid;
    c.buffer_bytes = mid_bdp;
    c.route_switch = Some(RouteSwitch {
        at: Duration::from_secs(2),
        delay: Duration::from_millis(75),
        ack_delay_prop: Duration::from_millis(75),
    });
    slices.push(("axis_route_switch".into(), c, 1));

    let mut c = mid;
    c.buffer_bytes = mid_bdp;
    slices.push(("axis_concur10".into(), c, 10));
    slices.push(("axis_concur100".into(), c, 100));

    for (cell, cfg, flows) in slices {
        for v in VARIANTS {
            for rep in 0..REPLICAS {
                run_cell(v, &cfg, flows, &cell, rep);
            }
        }
    }
}
