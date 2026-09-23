//! Deterministic event-driven network simulator (plan §7.1).
//!
//! **Multi-flow**: every flow shares one bottleneck link — a
//! serialization rate, a bounded queue, optional policer/AQM/random
//! loss/reorder, per-packet propagation jitter, and an optional
//! mid-run route switch that changes the propagation delay. Each flow
//! carries its own sender (CC + RateSampler + RttState) and receiver
//! (cumulative/SACK-lite ACK generation + delayed-ACK batching).
//! A SplitMix64 seeded by the config makes runs reproducible — golden
//! traces compare across runs.
//!
//! Loss detection is intentionally simple: 3 dupacks trigger a fast
//! retransmit of the first gap (RACK-TLP lands in T3 with the real
//! stack); RTO covers tail loss. That is enough to exercise SS/CA,
//! PRR recovery, HyStart++ and the sawtooth matrix.

use crate::cc::CongestionController;
use crate::rate_sample::RateSampler;
use crate::rtt::RttState;
use crate::TransportInstant;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, VecDeque};
use std::time::Duration;

/// AQM behavior when a packet meets a nonempty queue.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Aqm {
    /// Enqueue while the buffer has room, drop otherwise.
    #[default]
    None,
    /// Identical to `None` — explicit name for configs/tests.
    DropTail,
    /// CoDel-flavored ECN marking: packets are CE-marked (never dropped
    /// by the AQM) when estimated sojourn exceeds `target`.
    CodelEcn { target: Duration },
}

/// Token-bucket policer on the forward link.
#[derive(Clone, Copy, Debug)]
pub struct Policer {
    pub rate_bps: u64,
    pub burst_bytes: u64,
}

/// Mid-run route change (§7.1): packets admitted to the link after
/// `at` take the new propagation delays; packets already in flight
/// keep their original delays.
#[derive(Clone, Copy, Debug)]
pub struct RouteSwitch {
    pub at: Duration,
    /// New one-way forward delay.
    pub delay: Duration,
    /// New ACK-path delay.
    pub ack_delay_prop: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct SimConfig {
    /// One-way propagation delay of each direction (before any switch).
    pub delay: Duration,
    /// Symmetric ± uniform jitter applied per packet to each
    /// direction's propagation delay (RNG-drawn, deterministic).
    pub jitter: Duration,
    /// Optional mid-run route change.
    pub route_switch: Option<RouteSwitch>,
    /// Forward link serialization rate in bytes/s.
    pub rate_bps: u64,
    /// Forward queue capacity in bytes (excluding the packet in service).
    pub buffer_bytes: u64,
    pub aqm: Aqm,
    pub policer: Option<Policer>,
    /// Independent uniform drop probability on the forward link —
    /// stacks with queue/policer drops (congestion + random overlay).
    pub random_loss: f64,
    /// Probability a packet takes `reorder_extra` longer.
    pub reorder_prob: f64,
    pub reorder_extra: Duration,
    /// ACK path propagation delay (return direction is lossless,
    /// unbuffered — ACK compression semantics live in `ack_every`/`ack_delay`).
    pub ack_delay_prop: Duration,
    /// Receiver sends an ACK every `ack_every` data segments or after
    /// `ack_delay` at the latest (whichever first).
    pub ack_every: u32,
    pub ack_delay: Duration,
    pub mss: u64,
    /// Total bytes each sender has to send.
    pub total_bytes: u64,
    /// Application data rate for the single-flow `run()` path
    /// (bytes/s); `None` = backlogged sender. `run_multi` takes the
    /// per-flow value from its `FlowSpec`.
    pub app_rate_bps: Option<u64>,
    /// Virtual run duration cap.
    pub duration: Duration,
    /// SplitMix64 seed.
    pub seed: u64,
    /// Collect the full per-event trace (needed for trace_text/digest
    /// and seq-level post-analysis). Disable for large multi-flow runs
    /// where the trace dominates memory; rtt/fct are still recorded.
    pub collect_trace: bool,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            delay: Duration::from_millis(50),
            jitter: Duration::ZERO,
            route_switch: None,
            rate_bps: 12_500_000, // 100 Mbit/s
            buffer_bytes: 625_000,
            aqm: Aqm::None,
            policer: None,
            random_loss: 0.0,
            reorder_prob: 0.0,
            reorder_extra: Duration::ZERO,
            ack_delay_prop: Duration::from_millis(50),
            ack_every: 1,
            ack_delay: Duration::ZERO,
            mss: 1460,
            total_bytes: 10 * 1024 * 1024,
            app_rate_bps: None,
            duration: Duration::from_secs(30),
            seed: 0x9e3779b97f4a7c15,
            collect_trace: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    /// A pacing/cwnd/app-availability-gated send opportunity.
    SendDue,
    /// Data packet reached the receiver.
    DataArrive { seq: u64, len: u64, ce: bool },
    /// ACK reached the sender — cumulative edge plus the receiver's
    /// current out-of-order (SACK-lite) ranges.
    AckArrive {
        cum: u64,
        sacked: Vec<(u64, u64)>,
        ce_bytes_total: u64,
    },
    /// Delayed-ACK flush deadline reached at the receiver.
    AckFlush,
    /// RTO fired.
    Rto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceKind {
    Send,
    Ack,
    Drop,
    LossMark,
    Retransmit,
    Rto,
    CeMark,
}

#[derive(Clone, Debug)]
pub struct TraceRow {
    pub t_us: u64,
    /// Flow index — multi-flow traces are merged by `t_us`.
    pub flow: u32,
    pub kind: TraceKind,
    pub seq: u64,
    pub cwnd: u64,
    pub in_flight: u64,
    pub delivered_total: u64,
}

#[derive(Debug, Default)]
pub struct SimResult {
    pub trace: Vec<TraceRow>,
    pub delivered_bytes: u64,
    pub loss_events: u64,
    pub rto_events: u64,
    pub retransmits: u64,
    pub drops: u64,
    pub ce_marks: u64,
    /// All bytes delivered before `duration` elapsed.
    pub completed: bool,
    /// Per-ACK RTT samples (µs, Karn-filtered) — the queue-delay input
    /// that does not require the event trace.
    pub rtt_samples_us: Vec<u64>,
    /// Time (µs, sim clock) at which `cum_acked` reached `total_bytes`;
    /// 0 when the flow did not complete within `duration`.
    pub fct_us: u64,
}

/// Result of a multi-flow run — one [`SimResult`] per flow plus a
/// merged trace accessor.
#[derive(Debug)]
pub struct MultiSimResult {
    pub flows: Vec<SimResult>,
}

impl MultiSimResult {
    /// All flows' trace rows merged in global time order (stable on
    /// flow index for identical timestamps).
    pub fn merged_trace(&self) -> Vec<&TraceRow> {
        let mut rows: Vec<&TraceRow> = self
            .flows
            .iter()
            .flat_map(|f| f.trace.iter())
            .collect();
        rows.sort_by_key(|r| (r.t_us, r.flow));
        rows
    }

    /// Multi-flow trace text (§7.1): merged rows prefixed by flow.
    pub fn trace_text(&self) -> String {
        let mut out = String::new();
        for row in self.merged_trace() {
            out.push_str(&format!(
                "{} f{} {:?} seq={} cwnd={} flight={} delivered={}\n",
                row.t_us,
                row.flow,
                row.kind,
                row.seq,
                row.cwnd,
                row.in_flight,
                row.delivered_total
            ));
        }
        out
    }

    pub fn all_completed(&self) -> bool {
        self.flows.iter().all(|f| f.completed)
    }
}

impl SimResult {
    /// Compact FNV-1a digest over the trace — golden tests pin this.
    pub fn trace_digest(&self) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for row in &self.trace {
            for byte in row
                .t_us
                .to_be_bytes()
                .iter()
                .chain(row.flow.to_be_bytes().iter())
                .chain(row.seq.to_be_bytes().iter())
                .chain(row.cwnd.to_be_bytes().iter())
                .chain(row.in_flight.to_be_bytes().iter())
                .copied()
                .chain([row.kind as u8])
            {
                h ^= byte as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
        }
        h
    }

    pub fn trace_text(&self) -> String {
        let mut out = String::new();
        for row in &self.trace {
            out.push_str(&format!(
                "{} f{} {:?} seq={} cwnd={} flight={} delivered={}\n",
                row.t_us,
                row.flow,
                row.kind,
                row.seq,
                row.cwnd,
                row.in_flight,
                row.delivered_total
            ));
        }
        out
    }
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0,1).
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in [-j, +j] µs.
    fn jitter_us(&mut self, j: u64) -> i64 {
        if j == 0 {
            return 0;
        }
        ((self.f64() * 2.0 - 1.0) * j as f64) as i64
    }
}

struct QueueEntry {
    depart_us: u64,
    len: u64,
}

/// One flow's controller + per-flow knobs for `run_multi`.
pub struct FlowSpec<'a> {
    pub cc: &'a mut dyn CongestionController,
    /// App data rate (bytes/s); `None` = backlogged sender. When the
    /// sender catches up to the app, new segments carry the app-limited
    /// mark and the send resumes when more data is available.
    pub app_rate_bps: Option<u64>,
    /// Flow start offset.
    pub start_at: Duration,
}

impl<'a> FlowSpec<'a> {
    pub fn new(cc: &'a mut dyn CongestionController) -> Self {
        Self {
            cc,
            app_rate_bps: None,
            start_at: Duration::ZERO,
        }
    }
}

/// Run a single flow (`cfg.app_rate_bps` applies). Returns its result.
pub fn run(cc: &mut dyn CongestionController, cfg: &SimConfig) -> SimResult {
    let mut out = run_multi(
        cfg,
        vec![FlowSpec {
            cc,
            app_rate_bps: cfg.app_rate_bps,
            start_at: Duration::ZERO,
        }],
    );
    out.flows.pop().unwrap_or_default()
}

/// Run `flows` against one shared bottleneck. Deterministic.
pub fn run_multi<'a>(cfg: &'a SimConfig, flows: Vec<FlowSpec<'a>>) -> MultiSimResult {
    let mut sim = Sim::new(cfg, flows);
    sim.run();
    MultiSimResult {
        flows: sim.flows.into_iter().map(|f| f.result).collect(),
    }
}

/// Shared forward-link state (all flows compete here).
struct Link {
    link_free_us: u64,
    queued: VecDeque<QueueEntry>,
    queued_bytes: u64,
    policer_tokens: f64,
    policer_last_us: u64,
}

/// Outcome of one link admission.
struct Admit {
    admitted: bool,
    ce: bool,
    arrive_us: u64,
}

/// Sender scoreboard entry. `sacked`/`lost` track receiver-reported
/// arrival and loss marks so `in_flight` counts only bytes genuinely in
/// the pipe (Linux `tcp_packets_in_flight` semantics) — without this a
/// droptail massacre leaves the pipe permanently inflated and the sender
/// can never recover.
struct ScoreEntry {
    rec: crate::rate_sample::TxRecord,
    /// Receiver confirmed arrival (out-of-order) — no longer in flight.
    sacked: bool,
    /// Judged lost (dupack mark or RTO sweep) — out of the pipe until
    /// the retransmission goes out.
    lost: bool,
    /// A retransmission copy is believed in flight. Re-marking it lost
    /// before that copy lands would double-count the pipe and churn
    /// retransmits — the sim's stand-in for RACK's time-based test.
    retx_out: bool,
    /// RTT already sampled at SACK-confirmation time. Without this the
    /// cum-drain would re-sample `now − first_tx_at`, which spans the
    /// whole loss-recovery period of lower seqs (tens of seconds on a
    /// massacre path) and inflates srtt/RTO far beyond the wire RTT.
    rtt_taken: bool,
}

/// Per-flow state (sender + receiver halves).
struct Flow<'a> {
    cc: &'a mut dyn CongestionController,
    sampler: RateSampler,
    rtt: RttState,
    app_rate_bps: Option<u64>,
    start_us: u64,
    // sender
    next_seq: u64,
    sent_total: u64,
    cum_acked: u64,
    in_flight: u64,
    scoreboard: BTreeMap<u64, ScoreEntry>,
    /// Seq set of records needing retransmission (lost, not sacked, no
    /// retx outstanding) — keeps `try_send`'s next-loss pick O(1)
    /// instead of rescanning the whole scoreboard per segment.
    lost_pending: std::collections::BTreeSet<u64>,
    /// Count of `lost && !sacked` records (retx'd-but-lost stays
    /// counted) — feeds the per-event liveness check.
    lost_unsacked: u64,
    dupacks: u32,
    next_send_due: u64,
    send_due_armed: bool,
    rto_due: u64,
    rto_armed: bool,
    rto_backoff: u32,
    last_ack_progress_us: u64,
    ce_bytes_reported: u64,
    // receiver
    rx_next: u64,
    rx_sacked: BTreeMap<u64, u64>, // seq -> len beyond cum
    rx_ce_total: u64,
    rx_pending_ack: Option<u64>,
    rx_unacked_count: u32,
    ack_flush_due: u64,
    completed: bool,
    collect_trace: bool,
    result: SimResult,
}

struct Sim<'a> {
    cfg: &'a SimConfig,
    rng: SplitMix64,
    now_us: u64,
    events: BinaryHeap<Reverse<(u64, u32, u64, Event)>>,
    event_ord: u64,
    link: Link,
    flows: Vec<Flow<'a>>,
    /// O(1) all-done check (was a full scan after every event).
    completed_count: usize,
    /// Pacing prefetch quantum (µs): one MSS service time on the
    /// configured link. Sends due within a quantum are released
    /// immediately — pacing faster than line rate is unobservable
    /// through the serializing queue anyway, and without this each
    /// sub-quantum paced packet costs a whole SendDue event (storm).
    pace_quantum_us: u64,
    /// `SIM_EVENT_STATS` diagnostics: per-kind event counts.
    event_stats: bool,
    event_hist: [u64; 5],
}

impl<'a> Flow<'a> {
    fn new(spec: FlowSpec<'a>, collect_trace: bool) -> Self {
        Self {
            cc: spec.cc,
            sampler: RateSampler::new(),
            rtt: RttState::new(),
            app_rate_bps: spec.app_rate_bps,
            start_us: spec.start_at.as_micros() as u64,
            next_seq: 0,
            sent_total: 0,
            cum_acked: 0,
            in_flight: 0,
            scoreboard: BTreeMap::new(),
            lost_pending: std::collections::BTreeSet::new(),
            lost_unsacked: 0,
            dupacks: 0,
            next_send_due: spec.start_at.as_micros() as u64,
            send_due_armed: false,
            rto_due: 0,
            rto_armed: false,
            rto_backoff: 0,
            last_ack_progress_us: 0,
            ce_bytes_reported: 0,
            rx_next: 0,
            rx_sacked: BTreeMap::new(),
            rx_ce_total: 0,
            rx_pending_ack: None,
            rx_unacked_count: 0,
            ack_flush_due: u64::MAX,
            completed: false,
            collect_trace,
            result: SimResult::default(),
        }
    }

    fn now(&self, now_us: u64) -> TransportInstant {
        TransportInstant::from_micros(now_us)
    }

    /// Bytes the app has made available by `now_us` (None = backlogged).
    fn app_available(&self, now_us: u64) -> Option<u64> {
        self.app_rate_bps.map(|rate| {
            let elapsed = now_us.saturating_sub(self.start_us) as u128;
            (elapsed * rate as u128 / 1_000_000) as u64
        })
    }

    fn trace(&mut self, kind: TraceKind, seq: u64, now_us: u64, flow: u32) {
        if !self.collect_trace {
            return;
        }
        self.result.trace.push(TraceRow {
            t_us: now_us,
            flow,
            kind,
            seq,
            cwnd: self.cc.cwnd(),
            in_flight: self.in_flight,
            delivered_total: self.sampler.delivered_total(),
        });
    }
}

impl<'a> Sim<'a> {
    fn new(cfg: &'a SimConfig, specs: Vec<FlowSpec<'a>>) -> Self {
        Self {
            cfg,
            rng: SplitMix64(cfg.seed),
            now_us: 0,
            events: BinaryHeap::new(),
            event_ord: 0,
            link: Link {
                link_free_us: 0,
                queued: VecDeque::new(),
                queued_bytes: 0,
                policer_tokens: cfg
                    .policer
                    .map(|p| p.burst_bytes as f64)
                    .unwrap_or(0.0),
                policer_last_us: 0,
            },
            flows: specs
                .into_iter()
                .map(|s| Flow::new(s, cfg.collect_trace))
                .collect(),
            completed_count: 0,
            pace_quantum_us: (cfg.mss.saturating_mul(1_000_000) / cfg.rate_bps.max(1)).max(1),
            event_stats: std::env::var_os("SIM_EVENT_STATS").is_some(),
            event_hist: [0; 5],
        }
    }

    fn push(&mut self, at_us: u64, flow: u32, ev: Event) {
        self.event_ord += 1;
        // Never schedule in the past: an expired deadline means "fire
        // now", and admitting a backward timestamp would move the event
        // clock backwards (e.g. `now - policer_last_us` underflows).
        let at_us = at_us.max(self.now_us);
        self.events
            .push(Reverse((at_us, flow, self.event_ord, ev)));
    }

    /// Propagation delays in force for packets admitted at `now_us`.
    fn route_delays(&self, now_us: u64) -> (u64, u64) {
        match self.cfg.route_switch {
            Some(rs) if now_us >= rs.at.as_micros() as u64 => (
                rs.delay.as_micros() as u64,
                rs.ack_delay_prop.as_micros() as u64,
            ),
            _ => (
                self.cfg.delay.as_micros() as u64,
                self.cfg.ack_delay_prop.as_micros() as u64,
            ),
        }
    }

    /// Forward-path propagation delay for a packet admitted now
    /// (route switch + per-packet jitter).
    fn fwd_prop_us(&mut self, now_us: u64) -> u64 {
        let (base, _) = self.route_delays(now_us);
        let j = self.rng.jitter_us(self.cfg.jitter.as_micros() as u64);
        base.saturating_add_signed(j)
    }

    /// ACK-path propagation delay for an ACK emitted now.
    fn ack_prop_us(&mut self, now_us: u64) -> u64 {
        let (_, base) = self.route_delays(now_us);
        let j = self.rng.jitter_us(self.cfg.jitter.as_micros() as u64);
        base.saturating_add_signed(j)
    }

    /// Forward link admission: policer → buffer/AQM → random loss →
    /// serialization → propagation (jitter/route/reorder).
    fn link_admit(&mut self, len: u64) -> Admit {
        let cfg = self.cfg;
        let now_us = self.now_us;
        let link = &mut self.link;
        if let Some(policer) = cfg.policer {
            let elapsed = now_us - link.policer_last_us;
            link.policer_last_us = now_us;
            link.policer_tokens = (link.policer_tokens
                + elapsed as f64 * policer.rate_bps as f64 / 1e6)
                .min(policer.burst_bytes as f64);
            if len as f64 > link.policer_tokens {
                return Admit {
                    admitted: false,
                    ce: false,
                    arrive_us: 0,
                };
            }
            link.policer_tokens -= len as f64;
        }
        // Drain departed queue entries.
        while let Some(head) = link.queued.front()
            && head.depart_us <= now_us
        {
            link.queued_bytes -= head.len;
            link.queued.pop_front();
        }
        let mut ce = false;
        if let Aqm::CodelEcn { target } = cfg.aqm {
            let sojourn_us = (link.queued_bytes * 1_000_000)
                .checked_div(cfg.rate_bps)
                .unwrap_or(0);
            if sojourn_us > target.as_micros() as u64 {
                ce = true;
            }
        }
        if link.queued_bytes + len > cfg.buffer_bytes {
            return Admit {
                admitted: false,
                ce: false,
                arrive_us: 0,
            };
        }
        if cfg.random_loss > 0.0 && self.rng.f64() < cfg.random_loss {
            return Admit {
                admitted: false,
                ce: false,
                arrive_us: 0,
            };
        }
        // Serialize at the shared link rate.
        let start = link.link_free_us.max(now_us);
        let service_us = (len * 1_000_000).div_ceil(cfg.rate_bps.max(1));
        let depart = start + service_us;
        link.link_free_us = depart;
        link.queued.push_back(QueueEntry {
            depart_us: depart,
            len,
        });
        link.queued_bytes += len;
        let mut arrive = depart + self.fwd_prop_us(now_us);
        if cfg.reorder_prob > 0.0 && self.rng.f64() < cfg.reorder_prob {
            arrive += cfg.reorder_extra.as_micros() as u64;
        }
        Admit {
            admitted: true,
            ce,
            arrive_us: arrive,
        }
    }

    fn try_send(&mut self, fi: usize) {
        let cfg = self.cfg;
        let flow_id = fi as u32;
        loop {
            // Decide the next unit of work under a shared borrow: a
            // lost-marked segment retransmits ahead of new data (the
            // lost gap is the oldest unrecovered byte), then the next
            // unsent segment.
            enum Work {
                Retx { seq: u64, len: u64, first_tx_at: TransportInstant },
                New { seq: u64, len: u64, app_limited: bool },
                AppStall { due: u64 },
                Blocked,
                Done,
            }
            let work = {
                let f = &self.flows[fi];
                // Only un-sacked lost records retransmit: a sacked+lost
                // record is spurious-loss evidence (the original was
                // merely delayed) — retransmitting it would inject a dup
                // and leak in_flight (cum-drain never un-counts sacked).
                let next_lost = f
                    .lost_pending
                    .iter()
                    .next()
                    .and_then(|&s| f.scoreboard.get(&s).map(|e| (s, e)))
                    .map(|(s, e)| (s, e.rec.len(), e.rec.first_tx_at));
                if let Some((seq, len, first_tx_at)) = next_lost {
                    if f.in_flight + len > f.cc.cwnd() {
                        Work::Blocked
                    } else if self.now_us + self.pace_quantum_us < f.next_send_due {
                        // Retransmits pay the same pacing toll as new
                        // data. They MUST be gated: the send below
                        // advances `next_send_due`, so an ungated retx
                        // train (one per ACK) pushes the due clock
                        // unboundedly ahead of `now` and starves new
                        // data past the simulation deadline.
                        Work::Blocked
                    } else {
                        Work::Retx { seq, len, first_tx_at }
                    }
                } else if f.next_seq >= cfg.total_bytes {
                    Work::Done
                } else {
                    let len = cfg.mss.min(cfg.total_bytes - f.next_seq);
                    if f.in_flight + len > f.cc.cwnd()
                        || self.now_us + self.pace_quantum_us < f.next_send_due
                    {
                        Work::Blocked
                    } else {
                        match f.app_rate_bps {
                            Some(rate) => {
                                let avail = f.app_available(self.now_us).unwrap_or(0);
                                if f.next_seq + len > avail {
                                    let need = (f.next_seq + len) as u128;
                                    Work::AppStall {
                                        due: f.start_us
                                            + (need * 1_000_000)
                                                .div_ceil(rate.max(1) as u128)
                                                as u64,
                                    }
                                } else {
                                    // Outrunning the app within one more
                                    // segment = app-limited flight.
                                    Work::New {
                                        seq: f.next_seq,
                                        len,
                                        app_limited: f.next_seq + len + cfg.mss > avail,
                                    }
                                }
                            }
                            None => Work::New {
                                seq: f.next_seq,
                                len,
                                app_limited: false,
                            },
                        }
                    }
                }
            };
            let sent_len;
            match work {
                Work::Done | Work::Blocked => break,
                Work::AppStall { due } => {
                    let f = &mut self.flows[fi];
                    // Mark the delivery point so segments sent after the
                    // stall carry the app-limited flag (Linux semantics:
                    // flag clears once delivery passes the mark).
                    f.sampler.mark_app_limited();
                    f.next_send_due = f.next_send_due.max(due);
                    break;
                }
                Work::Retx {
                    seq,
                    len,
                    first_tx_at,
                } => {
                    sent_len = len;
                    let admit = self.link_admit(len);
                    let f = &mut self.flows[fi];
                    if let Some(e) = f.scoreboard.get_mut(&seq) {
                        e.lost = false;
                        e.retx_out = true;
                    }
                    if f.lost_pending.remove(&seq) {
                        f.lost_unsacked -= 1;
                    }
                    f.sent_total += len;
                    f.in_flight += len;
                    let now = f.now(self.now_us);
                    // Keep first_tx_at; mark retransmitted so Karn's rule
                    // applies.
                    let new_rec = f.sampler.note_sent(seq, len, now, true, Some(first_tx_at));
                    if let Some(e) = f.scoreboard.get_mut(&seq) {
                        e.rec = new_rec;
                    }
                    f.cc.on_sent(now, len, f.in_flight, false);
                    f.result.retransmits += 1;
                    f.trace(TraceKind::Retransmit, seq, self.now_us, flow_id);
                    if admit.ce {
                        f.result.ce_marks += 1;
                    }
                    if admit.admitted {
                        self.push(
                            admit.arrive_us,
                            flow_id,
                            Event::DataArrive {
                                seq,
                                len,
                                ce: admit.ce,
                            },
                        );
                    }
                }
                Work::New {
                    seq,
                    len,
                    app_limited,
                } => {
                    sent_len = len;
                    let admit = self.link_admit(len);
                    let f = &mut self.flows[fi];
                    // Consume the send opportunity even on drop — the
                    // sender believes the packet left.
                    f.next_seq += len;
                    f.sent_total += len;
                    f.in_flight += len;
                    let now = f.now(self.now_us);
                    let rec = f.sampler.note_sent(seq, len, now, false, None);
                    f.scoreboard.insert(
                        seq,
                        ScoreEntry {
                            rec,
                            sacked: false,
                            lost: false,
                            retx_out: false,
                            rtt_taken: false,
                        },
                    );
                    f.cc.on_sent(now, len, f.in_flight, app_limited);
                    f.trace(TraceKind::Send, seq, self.now_us, flow_id);
                    if admit.ce {
                        f.result.ce_marks += 1;
                        f.trace(TraceKind::CeMark, seq, self.now_us, flow_id);
                    }
                    if admit.admitted {
                        self.push(
                            admit.arrive_us,
                            flow_id,
                            Event::DataArrive {
                                seq,
                                len,
                                ce: admit.ce,
                            },
                        );
                    } else {
                        let f = &mut self.flows[fi];
                        f.result.drops += 1;
                        f.trace(TraceKind::Drop, seq, self.now_us, flow_id);
                    }
                }
            }
            // Pacing: accumulate the due clock per segment (max(due,now)
            // discards stale credit — no unbounded catch-up burst) so a
            // run of prefetch-eligible sends still honors the rate.
            let f = &mut self.flows[fi];
            match f.cc.pacing_rate() {
                Some(rate) if rate > 0 => {
                    let spacing = (sent_len * 1_000_000).div_ceil(rate);
                    f.next_send_due = f.next_send_due.max(self.now_us) + spacing;
                }
                _ => {
                    f.next_send_due = self.now_us;
                }
            }
        }
        // Arm a wake-up only when pacing/app-availability is what blocks
        // us — a cwnd-blocked sender is woken by the next ACK event, and
        // re-arming a due-now SendDue would spin the event loop.
        let f = &mut self.flows[fi];
        let due = f.next_send_due;
        let has_work = f.next_seq < cfg.total_bytes || f.lost_unsacked > 0;
        if has_work && !f.send_due_armed && due > self.now_us {
            self.push(due, flow_id, Event::SendDue);
            self.flows[fi].send_due_armed = true;
        }
        self.arm_rto(fi);
    }

    fn arm_rto(&mut self, fi: usize) {
        let f = &mut self.flows[fi];
        if f.scoreboard.is_empty() {
            f.rto_armed = false;
            return;
        }
        let rto = f.rtt.rto();
        // `last_ack_progress_us` may be far in the past (e.g. a policed
        // sender idle-waiting on tokens) — an already-expired deadline
        // fires immediately, not at a negative offset.
        f.rto_due = (f.last_ack_progress_us
            + rto.as_micros() as u64 * (1u64 << f.rto_backoff.min(6)))
        .max(self.now_us);
        if !f.rto_armed {
            let due = f.rto_due;
            self.push(due, fi as u32, Event::Rto);
            self.flows[fi].rto_armed = true;
        }
    }

    fn on_data_arrive(&mut self, fi: usize, seq: u64, len: u64, ce: bool) {
        let flow_id = fi as u32;
        let cfg = self.cfg;
        let f = &mut self.flows[fi];
        if ce {
            f.rx_ce_total += len;
        }
        if seq <= f.rx_next {
            // Advance cumulative over contiguous buffered bytes.
            f.rx_next = f.rx_next.max(seq + len);
            while let Some((&s, &l)) = f.rx_sacked.iter().next() {
                if s <= f.rx_next {
                    f.rx_next = f.rx_next.max(s + l);
                    f.rx_sacked.remove(&s);
                } else {
                    break;
                }
            }
        } else {
            f.rx_sacked.insert(seq, len);
        }
        f.rx_pending_ack = Some(f.rx_next);
        f.rx_unacked_count += 1;
        let send_now = f.rx_unacked_count >= cfg.ack_every.max(1)
            || !f.rx_sacked.is_empty(); // gap → ack immediately (dupack)
        if send_now {
            let cum = f.rx_next;
            let sacked: Vec<(u64, u64)> = f.rx_sacked.iter().map(|(&s, &l)| (s, l)).collect();
            let ce_total = f.rx_ce_total;
            let prop = self.ack_prop_us(self.now_us);
            self.push(
                self.now_us + prop,
                flow_id,
                Event::AckArrive {
                    cum,
                    sacked,
                    ce_bytes_total: ce_total,
                },
            );
            let f = &mut self.flows[fi];
            f.rx_unacked_count = 0;
            f.rx_pending_ack = None;
        } else {
            // Withheld ACK — flush at the delayed-ACK deadline.
            let due = self.now_us + cfg.ack_delay.as_micros() as u64;
            if due < f.ack_flush_due {
                f.ack_flush_due = due;
                self.push(due, flow_id, Event::AckFlush);
            }
        }
    }

    fn on_ack_flush(&mut self, fi: usize) {
        let flow_id = fi as u32;
        let f = &mut self.flows[fi];
        if f.ack_flush_due == u64::MAX || self.now_us < f.ack_flush_due {
            return;
        }
        f.ack_flush_due = u64::MAX;
        if f.rx_pending_ack.take().is_some() {
            let cum = f.rx_next;
            let sacked: Vec<(u64, u64)> = f.rx_sacked.iter().map(|(&s, &l)| (s, l)).collect();
            let ce_total = f.rx_ce_total;
            let prop = self.ack_prop_us(self.now_us);
            self.push(
                self.now_us + prop,
                flow_id,
                Event::AckArrive {
                    cum,
                    sacked,
                    ce_bytes_total: ce_total,
                },
            );
            self.flows[fi].rx_unacked_count = 0;
        }
    }

    fn on_ack_arrive(
        &mut self,
        fi: usize,
        cum: u64,
        sacked: Vec<(u64, u64)>,
        ce_total: u64,
    ) {
        let flow_id = fi as u32;
        let f = &mut self.flows[fi];
        let now = f.now(self.now_us);
        let prior_in_flight = f.in_flight;
        // Newly cumulatively-acked records leave the scoreboard; records
        // already sacked/lost were already out of the pipe count.
        // `confirmed` holds records whose delivery is first reported by
        // THIS ack — Linux `tp->delivered` semantics: a SACKed segment
        // counts when the SACK lands, not when the cumulative edge later
        // covers it. Feeding the drain set instead would let a hole-fill
        // register an entire sacked backlog as instant delivery, which
        // is exactly how a loss-heavy path's rate samples inflate.
        let mut confirmed = Vec::new();
        while let Some(&seq) = f.scoreboard.keys().next() {
            let e = &f.scoreboard[&seq];
            if e.rec.end_seq > cum {
                break;
            }
            let in_pipe = !e.sacked && !e.lost;
            let len = e.rec.len();
            let e = f.scoreboard.remove(&seq).unwrap();
            if in_pipe {
                f.in_flight = f.in_flight.saturating_sub(len);
            }
            if e.lost && !e.sacked {
                f.lost_unsacked -= 1;
                f.lost_pending.remove(&seq);
            }
            let mut rec = e.rec;
            if e.rtt_taken {
                // Suppress a second RTT sample for this record inside the
                // sampler (its `is_retransmit` flag is the Karn gate):
                // the wire RTT was measured when the SACK arrived, and
                // `now − first_tx_at` here would be the recovery delay.
                rec.is_retransmit = true;
            }
            if !e.sacked {
                // Never SACKed → cum coverage is the first confirmation.
                confirmed.push(rec);
            }
        }
        let progressed = cum > f.cum_acked;
        f.cum_acked = f.cum_acked.max(cum);
        // SACK markings: receiver-confirmed out-of-order arrivals leave
        // the pipe (Linux: sacked_out excluded from packets_in_flight).
        let mut newly_sacked = 0u64;
        let mut sack_rtts = Vec::new();
        for (s, _l) in &sacked {
            if let Some(e) = f.scoreboard.get_mut(s)
                && !e.sacked
            {
                e.sacked = true;
                if !e.lost {
                    f.in_flight = f.in_flight.saturating_sub(e.rec.len());
                } else {
                    f.lost_unsacked -= 1;
                }
                // Arrival evidence cancels the lost mark — keeps a
                // delayed (reordered) original from being retx'd as a
                // spurious retransmission later.
                e.lost = false;
                e.retx_out = false;
                f.lost_pending.remove(s);
                // Wire RTT is measured at first confirmation — now, at
                // SACK arrival. Deferring to cum-drain would add the
                // recovery delay of every lower seq (the srtt/RTO
                // inflation this flag prevents below).
                if !e.rec.is_retransmit {
                    sack_rtts.push(now.duration_since(e.rec.first_tx_at));
                    e.rtt_taken = true;
                }
                newly_sacked += e.rec.len();
                confirmed.push(e.rec);
            }
        }
        for r in sack_rtts {
            f.rtt.sample(r);
            f.result.rtt_samples_us.push(r.as_micros() as u64);
        }
        if progressed {
            f.dupacks = 0;
            f.last_ack_progress_us = self.now_us;
            f.rto_backoff = 0;
        } else if !sacked.is_empty() || newly_sacked > 0 {
            f.dupacks += 1;
        }
        // Loss detection (Linux `tcp_mark_head_lost` semantics): on the
        // third dupack, every un-sacked record below the SACK frontier is
        // judged lost — a droptail massacre marks the whole hole at once,
        // collapsing the pipe immediately instead of one segment per
        // dupack triple. Retransmission then runs through try_send under
        // cwnd/pacing.
        let mut lost_now = 0u64;
        let mut marked = false;
        if f.dupacks >= 3 {
            let frontier = sacked.iter().map(|(s, l)| s + l).max().unwrap_or(0);
            let mut gap_head = None;
            for (&seq, e) in f.scoreboard.iter_mut() {
                if e.sacked || e.lost || e.retx_out || e.rec.end_seq > frontier {
                    continue;
                }
                if gap_head.is_none() {
                    gap_head = Some(seq);
                }
                e.lost = true;
                f.lost_pending.insert(seq);
                f.lost_unsacked += 1;
                lost_now += e.rec.len();
            }
            if lost_now > 0 {
                f.in_flight = f.in_flight.saturating_sub(lost_now);
                f.cc.on_loss_event(now, lost_now, f.in_flight, false);
                f.result.loss_events += 1;
                f.trace(
                    TraceKind::LossMark,
                    gap_head.unwrap_or(0),
                    self.now_us,
                    flow_id,
                );
                marked = true;
            }
            f.dupacks = 0;
        }
        let ce_now = ce_total.saturating_sub(f.ce_bytes_reported);
        f.ce_bytes_reported = ce_total;
        let rs =
            f.sampler
                .on_ack(now, &confirmed, lost_now, ce_now, prior_in_flight, cum);
        if let Some(r) = rs.rtt {
            f.rtt.sample(r);
            f.result.rtt_samples_us.push(r.as_micros() as u64);
        }
        if ce_now > 0 {
            f.cc.on_ecn_ce(now, ce_now, rs.delivered, f.in_flight);
        }
        f.cc.on_rate_sample(&rs, f.in_flight, &f.rtt);
        f.trace(TraceKind::Ack, cum, self.now_us, flow_id);
        self.arm_rto(fi);
        if marked {
            // Fast retransmit: the lost mark is picked up by the send
            // path immediately (cwnd/pacing still apply).
            self.try_send(fi);
        }
    }

    fn on_rto(&mut self, fi: usize) {
        let flow_id = fi as u32;
        let f = &mut self.flows[fi];
        if f.scoreboard.is_empty() {
            f.rto_armed = false;
            return;
        }
        if self.now_us < f.rto_due {
            let due = f.rto_due;
            self.push(due, flow_id, Event::Rto);
            return;
        }
        // RTO sweep: every un-sacked record is judged lost — including
        // records whose retransmission copy is outstanding (an RTO means
        // the retx is presumed dead too). The pipe collapses and
        // retransmission restarts under the (reset) window, driven by the
        // normal send path.
        let mut lost_bytes = 0u64;
        let mut freed = 0u64;
        for (&seq, e) in f.scoreboard.iter_mut() {
            if e.sacked || e.lost {
                continue;
            }
            e.lost = true;
            e.retx_out = false;
            f.lost_pending.insert(seq);
            f.lost_unsacked += 1;
            lost_bytes += e.rec.len();
            freed += e.rec.len();
        }
        f.in_flight = f.in_flight.saturating_sub(freed);
        let now = f.now(self.now_us);
        let in_flight = f.in_flight;
        // persistent=true: the controller runs its own RTO collapse
        // (on_loss_event → on_rto internally).
        f.cc.on_loss_event(now, lost_bytes, in_flight, true);
        f.rto_backoff += 1;
        // The RTO timer restarts when the retransmission is sent — i.e.
        // now. Leaving the base at the stale last-ACK time would compute
        // an already-expired deadline and `arm_rto` would push a same-tick
        // event that re-pops forever without advancing `now_us`.
        f.last_ack_progress_us = self.now_us;
        f.rto_armed = false;
        f.result.rto_events += 1;
        f.trace(TraceKind::Rto, f.cum_acked, self.now_us, flow_id);
        self.try_send(fi);
    }

    fn run(&mut self) {
        for i in 0..self.flows.len() {
            let start = self.flows[i].start_us;
            self.push(start, i as u32, Event::SendDue);
        }
        let deadline = self.cfg.duration.as_micros() as u64;
        while let Some(Reverse((at, flow_id, _ord, ev))) = self.events.pop() {
            if at > deadline {
                break;
            }
            self.now_us = at;
            let fi = flow_id as usize;
            if self.event_stats {
                let idx = match &ev {
                    Event::SendDue => 0,
                    Event::DataArrive { .. } => 1,
                    Event::AckArrive { .. } => 2,
                    Event::AckFlush => 3,
                    Event::Rto => 4,
                };
                self.event_hist[idx] += 1;
                let total = self.event_hist.iter().sum::<u64>();
                if total % 2_000_000 == 0 {
                    eprintln!(
                        "sim>{}M t={}us heap={} senddue={} data={} ack={} flush={} rto={}",
                        total / 1_000_000,
                        self.now_us,
                        self.events.len(),
                        self.event_hist[0],
                        self.event_hist[1],
                        self.event_hist[2],
                        self.event_hist[3],
                        self.event_hist[4]
                    );
                }
            }
            match ev {
                Event::SendDue => {
                    self.flows[fi].send_due_armed = false;
                    self.try_send(fi);
                }
                Event::DataArrive { seq, len, ce } => self.on_data_arrive(fi, seq, len, ce),
                Event::AckArrive {
                    cum,
                    sacked,
                    ce_bytes_total,
                } => self.on_ack_arrive(fi, cum, sacked, ce_bytes_total),
                Event::AckFlush => self.on_ack_flush(fi),
                Event::Rto => self.on_rto(fi),
            }
            let f = &mut self.flows[fi];
            if !f.completed && f.cum_acked >= self.cfg.total_bytes {
                f.completed = true;
                f.result.completed = true;
                f.result.fct_us = self.now_us;
                self.completed_count += 1;
            }
            if self.completed_count == self.flows.len() {
                break;
            }
            // After each event, a freed window may allow immediate sends
            // (new data or retransmission of lost-marked records).
            // Retransmissions are event-driven, not pacing-driven — a
            // pending SendDue (or a next_send_due in the future, e.g. a
            // stale srtt under Karn's rule) must not suppress them.
            let f = &self.flows[fi];
            let has_lost = f.lost_unsacked > 0;
            let has_work = f.next_seq < self.cfg.total_bytes || has_lost;
            if has_work
                && f.in_flight < f.cc.cwnd()
                && (has_lost
                    || (!f.send_due_armed
                        && self.now_us + self.pace_quantum_us >= f.next_send_due))
            {
                self.try_send(fi);
            }
        }
        for f in &mut self.flows {
            f.result.delivered_bytes = f.sampler.delivered_total();
        }
        if self.event_stats {
            for (i, f) in self.flows.iter().enumerate() {
                if !f.completed {
                    eprintln!(
                        "sim-dump flow={i} t={} cum={} next_seq={} total={} inflight={} cwnd={} lost_unsacked={} lost_pending={} scoreboard={} due={} armed={} rto_armed={} rto_due={} last_prog={} backoff={} rx_next={} rx_sacked={}",
                        self.now_us,
                        f.cum_acked,
                        f.next_seq,
                        self.cfg.total_bytes,
                        f.in_flight,
                        f.cc.cwnd(),
                        f.lost_unsacked,
                        f.lost_pending.len(),
                        f.scoreboard.len(),
                        f.next_send_due,
                        f.send_due_armed,
                        f.rto_armed,
                        f.rto_due,
                        f.last_ack_progress_us,
                        f.rto_backoff,
                        f.rx_next,
                        f.rx_sacked.len(),
                    );
                }
            }
        }
    }
}
