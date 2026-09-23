//! Temporary debug: dump EdgeCC trace stats on a harsh cell.
use cloud_node_transport::CongestionController;
use cloud_node_transport::edgecc::{EdgeCc, Tier};
use cloud_node_transport::rate_sample::RateSample;
use cloud_node_transport::rtt::RttState;
use cloud_node_transport::sim::{SimConfig, TraceKind, run};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

struct Tap {
    inner: EdgeCc,
    rates: Rc<RefCell<Vec<(u64, u64, u64)>>>, // (t_us, rate_bps, delivered)
    loss_log: Rc<RefCell<Vec<(u64, u64, u64, bool, u64)>>>, // (t, lost, inflight, persist, proven)
    snap: Rc<RefCell<Vec<(u64, u64, u64, u64, u64, u64)>>>, // (t, cwnd, pacing, slope, p_rand, inflight)
}

impl CongestionController for Tap {
    fn on_sent(
        &mut self,
        now: cloud_node_transport::TransportInstant,
        bytes: u64,
        in_flight: u64,
        app: bool,
    ) {
        self.inner.on_sent(now, bytes, in_flight, app)
    }
    fn on_rate_sample(&mut self, rs: &RateSample, in_flight: u64, rtt: &RttState) {
        if rs.delivered > 0 {
            self.rates.borrow_mut().push((
                rs.now.micros(),
                rs.delivery_rate_bps(),
                rs.delivered,
            ));
        }
        self.inner.on_rate_sample(rs, in_flight, rtt);
        self.snap.borrow_mut().push((
            rs.now.micros(),
            self.inner.cwnd(),
            self.inner.pacing_rate().unwrap_or(0),
            self.inner.model.bw_slope().unwrap_or(0),
            self.inner.model.p_rand().unwrap_or(0.0) as u64,
            in_flight,
        ));
    }
    fn on_loss_event(
        &mut self,
        now: cloud_node_transport::TransportInstant,
        lost: u64,
        in_flight: u64,
        persistent: bool,
    ) {
        let proven = self
            .inner
            .model
            .bw_slope()
            .zip(self.inner.model.base_rtt())
            .map(|(s, b)| s as u128 * b.as_micros().max(1) as u128 / 1_000_000);
        if self.loss_log.borrow().len() < 60 {
            self.loss_log.borrow_mut().push((
                now.micros(),
                lost,
                in_flight,
                persistent,
                proven.map(|p| p as u64).unwrap_or(0),
            ));
        }
        self.inner.on_loss_event(now, lost, in_flight, persistent)
    }
    fn on_ecn_ce(
        &mut self,
        now: cloud_node_transport::TransportInstant,
        ce: u64,
        delivered: u64,
        in_flight: u64,
    ) {
        self.inner.on_ecn_ce(now, ce, delivered, in_flight)
    }
    fn on_rto(&mut self, now: cloud_node_transport::TransportInstant, in_flight: u64) {
        self.inner.on_rto(now, in_flight)
    }
    fn on_loss_undo(&mut self, now: cloud_node_transport::TransportInstant) {
        self.inner.on_loss_undo(now)
    }
    fn on_idle_restart(&mut self, now: cloud_node_transport::TransportInstant, idle: Duration) {
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
    fn snapshot(&self) -> cloud_node_transport::cc::CcSnapshot {
        self.inner.snapshot()
    }
}

fn run_bbr3_probe() {
    use cloud_node_transport::cc::reference::Bbr3Ref;
    use cloud_node_transport::cc::CongestionController;
    use cloud_node_transport::rate_sample::RateSample;
    use cloud_node_transport::rtt::RttState;
    use cloud_node_transport::TransportInstant;
    struct T {
        inner: Bbr3Ref,
        rates: Rc<RefCell<Vec<(u64, u64, u64, u64)>>>,
    }
    impl CongestionController for T {
        fn on_sent(&mut self, n: TransportInstant, b: u64, f: u64, a: bool) {
            self.inner.on_sent(n, b, f, a)
        }
        fn on_rate_sample(&mut self, rs: &RateSample, f: u64, r: &RttState) {
            self.rates.borrow_mut().push((
                rs.now.micros(),
                rs.delivery_rate_bps(),
                rs.delivered,
                rs.interval.as_micros() as u64,
            ));
            self.inner.on_rate_sample(rs, f, r)
        }
        fn on_loss_event(&mut self, n: TransportInstant, l: u64, f: u64, p: bool) {
            self.inner.on_loss_event(n, l, f, p)
        }
        fn on_ecn_ce(&mut self, n: TransportInstant, c: u64, d: u64, f: u64) {
            self.inner.on_ecn_ce(n, c, d, f)
        }
        fn on_rto(&mut self, n: TransportInstant, f: u64) {
            self.inner.on_rto(n, f)
        }
        fn on_loss_undo(&mut self, n: TransportInstant) {
            self.inner.on_loss_undo(n)
        }
        fn on_idle_restart(&mut self, n: TransportInstant, i: Duration) {
            self.inner.on_idle_restart(n, i)
        }
        fn on_mss_update(&mut self, m: u64) {
            self.inner.on_mss_update(m)
        }
        fn cwnd(&self) -> u64 {
            self.inner.cwnd()
        }
        fn pacing_rate(&self) -> Option<u64> {
            self.inner.pacing_rate()
        }
        fn snapshot(&self) -> cloud_node_transport::cc::CcSnapshot {
            self.inner.snapshot()
        }
    }
    let cfg = SimConfig {
        delay: Duration::from_micros(2500),
        ack_delay_prop: Duration::from_micros(2500),
        rate_bps: 100 * 125_000,
        random_loss: 0.0,
        mss: 1460,
        total_bytes: 4 * 1024 * 1024,
        duration: Duration::from_secs(120),
        buffer_bytes: 62500,
        seed: seed_for(0x9e3779b97f4a7c15, 0),
        ..SimConfig::default()
    };
    let rates = Rc::new(RefCell::new(Vec::new()));
    let mut cc = T {
        inner: Bbr3Ref::new(cfg.mss),
        rates: rates.clone(),
    };
    let res = run(&mut cc, &cfg);
    eprintln!(
        "bbr3: completed={} fct={} drops={} rtos={} retx={}",
        res.completed, res.fct_us, res.drops, res.rto_events, res.retransmits
    );
    let rs = rates.borrow();
    let mut sorted: Vec<u64> = rs.iter().map(|r| r.1).collect();
    sorted.sort_unstable();
    let q = |p: f64| {
        if sorted.is_empty() {
            0
        } else {
            sorted[((sorted.len() - 1) as f64 * p) as usize]
        }
    };
    eprintln!(
        "rate samples: n={} p50={:.2}MB/s p90={:.2} p99={:.2} max={:.2} (link={:.2})",
        rs.len(),
        q(0.5) as f64 / 1e6,
        q(0.9) as f64 / 1e6,
        q(0.99) as f64 / 1e6,
        q(1.0) as f64 / 1e6,
        cfg.rate_bps as f64 / 1e6,
    );
    for (t, r, d, iv) in rs.iter().rev().take(10) {
        eprintln!(
            "  t={}ms rate={:.2}MB/s delivered={} interval={}us",
            t / 1000,
            *r as f64 / 1e6,
            d,
            iv
        );
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

fn main() {
    if std::env::var("SIM_CC").as_deref().unwrap_or("edgecc") == "bbr3" {
        run_bbr3_probe();
        return;
    }
    let mut cfg = SimConfig {
        delay: Duration::from_micros(2500),
        ack_delay_prop: Duration::from_micros(2500),
        rate_bps: 10 * 125_000,
        random_loss: 0.0,
        mss: 1460,
        total_bytes: 4 * 1024 * 1024,
        duration: Duration::from_secs(120),
        buffer_bytes: 0,
        seed: seed_for(0x9e3779b97f4a7c15, 0),
        ..SimConfig::default()
    };
    cfg.buffer_bytes = cfg.rate_bps * 5_000 / 1_000_000; // 1 BDP
    let rates = Rc::new(RefCell::new(Vec::new()));
    let loss_log = Rc::new(RefCell::new(Vec::new()));
    let snap = Rc::new(RefCell::new(Vec::new()));
    let mut cc = Tap {
        inner: EdgeCc::new(cfg.mss, Tier::T1, None, false),
        rates: rates.clone(),
        loss_log: loss_log.clone(),
        snap: snap.clone(),
    };
    let res = run(&mut cc, &cfg);
    let cc = &cc.inner;
    eprintln!(
        "completed={} delivered={} fct_us={} drops={} loss_events={} rtos={} retx={}",
        res.completed, res.delivered_bytes, res.fct_us, res.drops, res.loss_events, res.rto_events, res.retransmits
    );
    let csnap = cc.snapshot();
    eprintln!(
        "mode={} reason={} cwnd={} pacing={:?} bw_lo={:?} bw_hi={:?} p_rand={:?} belief={:?} env={:?} inflight_lo={:?}",
        csnap.mode, csnap.reason_code, csnap.cwnd_bytes, csnap.pacing_rate_bps,
        csnap.bandwidth_lo_bps, csnap.bandwidth_hi_bps, csnap.p_rand_milli,
        csnap.belief_milli, csnap.envelope_bytes, csnap.inflight_lo_bytes,
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
    eprintln!("loss events (t_us, lost, inflight, persist, proven):");
    for (t, lost, inf, pers, prov) in loss_log.borrow().iter() {
        eprintln!("  t={t} lost={lost} inflight={inf} persist={pers} proven={prov}");
    }
    // Per-second: median cwnd/pacing/slope + delivered delta.
    {
        let s = snap.borrow();
        let mut buckets: std::collections::BTreeMap<u64, Vec<(u64, u64, u64, u64)>> =
            std::collections::BTreeMap::new();
        for &(t, cwnd, pacing, slope, _p, inf) in s.iter() {
            buckets.entry(t / 1_000_000).or_default().push((cwnd, pacing, slope, inf));
        }
        eprintln!("per-second (sec, n, cwnd_p50, pacing_p50, slope_p50, inflight_p50):");
        for (sec, rows) in &buckets {
            let mut cw: Vec<u64> = rows.iter().map(|r| r.0).collect();
            let mut pc: Vec<u64> = rows.iter().map(|r| r.1).collect();
            let mut sl: Vec<u64> = rows.iter().map(|r| r.2).collect();
            let mut inf: Vec<u64> = rows.iter().map(|r| r.3).collect();
            cw.sort_unstable();
            pc.sort_unstable();
            sl.sort_unstable();
            inf.sort_unstable();
            let n = rows.len();
            eprintln!(
                "  t={sec}s n={n} cwnd={} pacing={} slope={} inflight={}",
                cw[n / 2],
                pc[n / 2],
                sl[n / 2],
                inf[n / 2]
            );
        }
    }
    // ACK-slope deque internals (why is slope > link?)
    {
        let d = cc.model.ack_slope_dump();
        eprintln!("ack_slope deque: n={}", d.len());
        for (t, c) in d.iter().take(12) {
            eprintln!("  t={} cum={}", t, c);
        }
        if d.len() > 24 {
            eprintln!("  ...");
        }
        for (t, c) in d.iter().rev().take(12).rev() {
            eprintln!("  t={} cum={}", t, c);
        }
    }
    // delivery-rate sample distribution + the largest samples' context
    {
        let rs = rates.borrow();
        let mut sorted: Vec<u64> = rs.iter().map(|r| r.1).collect();
        sorted.sort_unstable();
        let q = |p: f64| {
            if sorted.is_empty() {
                0
            } else {
                sorted[((sorted.len() - 1) as f64 * p) as usize]
            }
        };
        eprintln!(
            "rate samples: n={} p50={:.2}MB/s p90={:.2} p99={:.2} max={:.2} (link={:.2})",
            rs.len(),
            q(0.5) as f64 / 1e6,
            q(0.9) as f64 / 1e6,
            q(0.99) as f64 / 1e6,
            q(1.0) as f64 / 1e6,
            cfg.rate_bps as f64 / 1e6,
        );
        for (t, r, d) in rs.iter().rev().take(8) {
            eprintln!("  t={}ms rate={:.2}MB/s delivered={}", t / 1000, *r as f64 / 1e6, d);
        }
    }
    // raw event window around a livelock cycle
    eprintln!("trace window t=18.5s..21.5s:");
    for r in &res.trace {
        if r.t_us >= 18_500_000 && r.t_us <= 21_500_000 {
            eprintln!(
                "  t={}us {:?} seq={} cwnd={} flight={} delivered={}",
                r.t_us, r.kind, r.seq, r.cwnd, r.in_flight, r.delivered_total
            );
        }
    }
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
