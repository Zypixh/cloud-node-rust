//! smoltcp-edge transport extension (T3).
//!
//! Sender-side machinery that exists only when an external
//! `cloud_node_transport::cc::CongestionController` is installed via
//! [`Socket::set_transport_controller`]: per-segment scoreboard, SACK
//! consumption, RACK loss detection with an adaptive reorder window,
//! TLP probes, DSACK spurious-retransmit evidence, Eifel undo, per-ACK
//! RTT (scoreboard first-tx timing plus TSecr RTTM for retransmitted
//! records), pacing gate and app-limited marking.
//!
//! When no external controller is installed every entry point is
//! unreachable and the builtin `AnyController` path is byte-for-byte
//! upstream.
//!
//! [`Socket::set_transport_controller`]: super::Socket::set_transport_controller

use crate::time::{Duration, Instant};
use crate::wire::TcpSeqNumber;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use cloud_node_transport::cc::{CcSnapshot, CongestionController};
use cloud_node_transport::rate_sample::{RateSampler, TxRecord};
use cloud_node_transport::rtt::RttState;
use cloud_node_transport::TransportInstant;
use core::fmt;
use std::time::Duration as StdDuration;

/// RFC 8985 reorder-window floor: sub-ms reordering is still possible
/// on multi-queue NICs.
const REO_WND_FLOOR: StdDuration = StdDuration::from_millis(1);
/// RFC 8985 §7.2 recommendation: reo_wnd ≈ min_rtt/4.
const REO_WND_MIN_RTT_DIV: u32 = 4;
/// DSACK evidence doubles the multiplier; cap at 8× base (≈ one srtt).
const REO_WND_MAX_MULT: u32 = 8;
/// TLP probe timeout floor: max(2*srtt, 10ms), clamped under the RTO.
const TLP_MIN: StdDuration = StdDuration::from_millis(10);

pub(crate) fn ti(now: Instant) -> TransportInstant {
    TransportInstant::from_micros(now.total_micros().max(0) as u64)
}

fn to_std(d: Duration) -> StdDuration {
    StdDuration::from_micros(d.total_micros().max(0) as u64)
}

fn to_smol(d: StdDuration) -> Duration {
    Duration::from_micros(d.as_micros().min(u64::MAX as u128) as u64)
}

/// One entry of the sender scoreboard — a dispatched data segment.
///
/// `in_flight` accounting follows Linux `tcp_packets_in_flight`:
/// SACKed and lost-marked records leave the pipe; a retransmission
/// puts the record back until it is confirmed.
#[derive(Debug)]
pub(crate) struct SentRecord {
    /// First payload byte (absolute sequence number).
    pub seq: TcpSeqNumber,
    /// One past the last payload byte.
    pub end_seq: TcpSeqNumber,
    /// When this copy went out.
    pub last_tx: Instant,
    /// When the payload first went out (retransmits keep it).
    pub first_tx: Instant,
    /// Receiver confirmed arrival out-of-order (SACK) — leaves the pipe.
    pub sacked: bool,
    /// This record's latest transmission was a retransmit.
    pub retransmitted: bool,
    /// Judged lost (dupack frontier / RACK / RTO sweep) — out of pipe.
    pub lost: bool,
    /// Already folded into a RateSample — a record may linger on the
    /// board sacked-but-not-yet-cum-acked and must report exactly once.
    pub delivered_to_sampler: bool,
    /// Sampler cumulative delivered counter at first send.
    pub delivered_at_send: u64,
    /// Sender ran out of data when this segment went out.
    pub app_limited: bool,
    /// Our TSval the latest transmission carried (0 when TS off).
    pub tsval: u32,
}

impl SentRecord {
    pub fn len(&self) -> usize {
        self.end_seq - self.seq
    }

    fn in_pipe(&self) -> bool {
        !self.sacked && !self.lost
    }

    fn to_tx_record(&self, base: TcpSeqNumber) -> TxRecord {
        TxRecord {
            seq: (self.seq.0.wrapping_sub(base.0)) as u32 as u64,
            end_seq: (self.end_seq.0.wrapping_sub(base.0)) as u32 as u64,
            sent_at: ti(self.last_tx),
            first_tx_at: ti(self.first_tx),
            delivered_at_send: self.delivered_at_send,
            is_app_limited: self.app_limited,
            is_retransmit: self.retransmitted,
        }
    }
}

/// Outcome of [`ExtTransport::on_segment_ack`] — tells the socket layer
/// what the ext machinery concluded so upstream timer/state code can
/// stay in charge of everything else.
#[derive(Debug, Default)]
pub(crate) struct AckEffects {
    /// The segment was a duplicate ACK (no cum progress, no payload).
    pub dupack: bool,
    /// Bytes newly judged lost by this ACK event.
    pub newly_lost: usize,
    /// DSACK or TSecr evidence proved a loss response spurious and the
    /// controller was told to undo (Eifel).
    pub spurious_undo: bool,
    /// An RTT sample was folded into `rtt`.
    pub rtt_sampled: bool,
}

/// The most recently sent delivered record of an ACK event — anchors
/// RACK (`RACK.xmit_ts`/`RACK.end_seq`) and carries the retransmission
/// tsval for TSecr-Eifel.
#[derive(Clone, Copy)]
struct Anchor {
    last_tx: Instant,
    end_seq: TcpSeqNumber,
    retransmitted: bool,
    tsval: u32,
}

/// External-controller transport state. Owned by the socket; every
/// method takes what it needs by value so the borrow checker never sees
/// a socket held across a controller call.
pub(crate) struct ExtTransport {
    /// The production controller (CubicRef today, EdgeCC in T5).
    pub cc: Box<dyn CongestionController>,
    /// Per-segment delivery sampler (Linux tcp_rate.c semantics).
    pub sampler: RateSampler,
    /// RFC 6298 RTT state for the controller (µs precision).
    pub rtt: RttState,
    /// Sender scoreboard, ordered by `end_seq`; head ≈ SND.UNA edge.
    board: VecDeque<SentRecord>,
    /// Bytes genuinely in flight (Σ len of `in_pipe()` records).
    pub pipe: usize,
    /// RFC 8985 `RACK.xmit_ts`.
    rack_delivered_at: Option<Instant>,
    /// RFC 8985 `RACK.end_seq`.
    rack_delivered_end: TcpSeqNumber,
    /// Adaptive reorder-window multiplier (DSACK-driven).
    reo_wnd_mult: u32,
    /// When the earliest RACK-eligible record's reo_wnd expires.
    loss_deadline: Option<Instant>,
    /// TLP probe timeout.
    tlp_deadline: Option<Instant>,
    /// A TLP probe is owed to the next dispatch.
    tlp_probe: bool,
    /// Pacing gate: no new-data segment before this instant.
    pub next_send_due: Option<Instant>,
    /// Seq base for the sampler's u64 space: first record's seq.
    base_seq: Option<TcpSeqNumber>,
    /// Duplicate-ACK counter (the ext path owns it; the builtin
    /// `local_rx_dup_acks` is not driven on this path).
    dupacks: u32,
    /// A loss response is outstanding — the next DSACK/TSecr evidence
    /// of spurious retransmission triggers Eifel undo.
    loss_response_outstanding: bool,
    /// Scratch for `newly_acked` records — reused across ACKs so the
    /// per-ACK path does not allocate.
    scratch: Vec<TxRecord>,
    /// Cumulative DSACK events (observability).
    pub dsack_events: u64,
    /// Cumulative RACK time-marked bytes (observability).
    pub rack_lost_bytes: u64,
    /// Last send/ack activity — drives `on_idle_restart`.
    last_progress: Option<Instant>,
    /// Whether `on_idle_restart` already fired for the current idle gap.
    idle_notified: bool,
}

impl ExtTransport {
    pub fn new(cc: Box<dyn CongestionController>) -> Self {
        Self {
            cc,
            sampler: RateSampler::new(),
            rtt: RttState::new(),
            board: VecDeque::new(),
            pipe: 0,
            rack_delivered_at: None,
            rack_delivered_end: TcpSeqNumber(0),
            reo_wnd_mult: 1,
            loss_deadline: None,
            tlp_deadline: None,
            tlp_probe: false,
            next_send_due: None,
            base_seq: None,
            dupacks: 0,
            loss_response_outstanding: false,
            scratch: Vec::new(),
            dsack_events: 0,
            rack_lost_bytes: 0,
            last_progress: None,
            idle_notified: false,
        }
    }

    /// Snapshot passthrough for the /status table (T1).
    pub fn snapshot(&self) -> CcSnapshot {
        self.cc.snapshot()
    }

    /// Effective reorder window: min_rtt/4 scaled by the DSACK-driven
    /// multiplier, floored at 1ms and capped at one srtt.
    fn reo_wnd(&self) -> StdDuration {
        let base = self
            .rtt
            .min_rtt
            .map(|r| r / REO_WND_MIN_RTT_DIV)
            .unwrap_or(REO_WND_FLOOR)
            .max(REO_WND_FLOOR);
        let wnd = base * self.reo_wnd_mult;
        match self.rtt.srtt {
            Some(srtt) => wnd.min(srtt),
            None => wnd,
        }
    }

    /// Record a freshly emitted data segment. `retransmit` means the
    /// range covers an existing lost record — revive that record
    /// instead of pushing a new one.
    pub fn note_sent(
        &mut self,
        now: Instant,
        seq: TcpSeqNumber,
        len: usize,
        tsval: u32,
        retransmit: bool,
    ) {
        if len == 0 {
            return;
        }
        if self.base_seq.is_none() {
            self.base_seq = Some(seq);
        }
        let app_limited = self.sampler.app_limited_now();
        if retransmit {
            // The record containing `seq` is revived. For a lost record
            // the bytes re-enter the pipe (a partial-ack-clamped retx
            // re-adds the whole record — bounded one-record over-count,
            // conservative). For a TLP probe on an un-lost record only
            // the timestamps move — the bytes never left the pipe.
            if let Some(rec) = self
                .board
                .iter_mut()
                .find(|r| r.seq <= seq && r.end_seq > seq && !r.sacked)
            {
                let was_lost = rec.lost;
                rec.last_tx = now;
                rec.lost = false;
                rec.retransmitted = true;
                rec.tsval = tsval;
                if was_lost {
                    self.pipe += rec.len();
                }
            }
        } else {
            let rec = SentRecord {
                seq,
                end_seq: seq + len,
                last_tx: now,
                first_tx: now,
                sacked: false,
                retransmitted: false,
                lost: false,
                delivered_to_sampler: false,
                delivered_at_send: self.sampler.delivered_marker(),
                // The flag travels with the segment, like Linux's
                // per-skb stamp — the sampler was marked when the send
                // buffer drained.
                app_limited,
                tsval,
            };
            self.pipe += len;
            self.board.push_back(rec);
        }
        self.cc
            .on_sent(ti(now), len as u64, self.pipe as u64, app_limited);
        self.last_progress = Some(now);
    }

    /// Mark subsequent segments app-limited — the send buffer just
    /// drained (T3 C6, §2.7 coupling).
    pub fn mark_app_limited(&mut self) {
        self.sampler.mark_app_limited();
    }

    /// Idle-restart notification when a send resumes after ≥1 RTT of
    /// silence with an empty pipe (Linux tcp_event_new_data_sent
    /// territory; fired once per idle gap).
    pub fn note_send_resumed(&mut self, now: Instant) {
        if self.idle_notified || self.pipe > 0 || !self.board.is_empty() {
            return;
        }
        if let Some(last) = self.last_progress {
            let idle = to_std(now - last);
            let rtt = self.rtt.srtt.unwrap_or(StdDuration::from_millis(1));
            if idle >= rtt {
                self.idle_notified = true;
                self.cc.on_idle_restart(ti(now), idle);
            }
        }
    }

    /// Seq/len of the next record to retransmit — lowest un-sacked lost
    /// record, clamped above the cumulative edge (`una`): a cumulative
    /// ACK may land mid-record, leaving a partially-acked head whose
    /// confirmed prefix must not be re-sent. The socket maps `seq` back
    /// to a tx_buffer offset.
    pub fn next_lost(&self, mss: usize, una: TcpSeqNumber) -> Option<(TcpSeqNumber, usize)> {
        self.board
            .iter()
            .find(|r| r.lost && !r.sacked && r.end_seq > una)
            .map(|r| {
                let seq = r.seq.max(una);
                (seq, (r.end_seq - seq).min(mss))
            })
    }

    /// Tail record for a TLP probe when no new data is available —
    /// Linux `tcp_send_probe0` retransmits the last unacked segment.
    pub fn tail_unacked(&self, mss: usize, una: TcpSeqNumber) -> Option<(TcpSeqNumber, usize)> {
        self.board
            .iter()
            .rev()
            .find(|r| !r.sacked && !r.lost && r.end_seq > una)
            .map(|r| {
                let seq = r.seq.max(una);
                (seq, (r.end_seq - seq).min(mss))
            })
    }

    /// A TLP probe is owed to the next dispatch.
    pub fn tlp_probe_pending(&self) -> bool {
        self.tlp_probe
    }

    /// Consume the pending TLP probe after a probe segment was emitted.
    pub fn clear_tlp_probe(&mut self) {
        self.tlp_probe = false;
    }

    /// Pacing gate for new-data segments (retransmits and control
    /// traffic are exempt — a stale srtt under Karn must not stall
    /// recovery).
    pub fn pacing_allows(&self, now: Instant) -> bool {
        self.next_send_due.map(|due| now >= due).unwrap_or(true)
    }

    /// Advance the pacing gate after a new-data send of `len` bytes.
    pub fn pace_after_send(&mut self, now: Instant, len: usize) {
        self.next_send_due = self.cc.pacing_rate().filter(|&r| r > 0).map(|rate| {
            let us = (len as u64).saturating_mul(1_000_000) / rate;
            now + Duration::from_micros(us.max(1))
        });
    }

    /// RTO sweep: mark every un-sacked record lost and hand the event
    /// to the controller as a persistent loss (controllers run their
    /// own RTO collapse inside `on_loss_event` — do not also call
    /// `on_rto` on them).
    pub fn mark_all_lost(&mut self, now: Instant) -> usize {
        let mut lost = 0usize;
        for rec in self.board.iter_mut() {
            if rec.sacked || rec.lost {
                continue;
            }
            rec.lost = true;
            lost += rec.len();
        }
        self.pipe = 0;
        self.loss_deadline = None;
        self.tlp_deadline = None;
        self.tlp_probe = false;
        self.cc.on_loss_event(ti(now), lost as u64, 0, true);
        self.loss_response_outstanding = true;
        lost
    }

    /// Earliest instant at which time-based work needs dispatch — the
    /// socket folds this into `poll_at`.
    pub fn next_timer(&self) -> Option<Instant> {
        [self.loss_deadline, self.tlp_deadline]
            .into_iter()
            .flatten()
            .min()
    }

    /// Timer checks run at the top of every dispatch: the RACK deadline
    /// marks eligible records lost; the TLP deadline arms a probe.
    pub fn timer_checks(&mut self, now: Instant) {
        if let Some(at) = self.loss_deadline
            && now >= at
        {
            self.loss_deadline = None;
            let lost = self.rack_mark(now);
            if lost > 0 {
                self.cc
                    .on_loss_event(ti(now), lost as u64, self.pipe as u64, false);
                self.loss_response_outstanding = true;
            }
            self.arm_loss_deadline(now);
        }
        if let Some(at) = self.tlp_deadline
            && now >= at
        {
            self.tlp_deadline = None;
            self.tlp_probe = true;
        }
    }

    /// RFC 8985 loss marking: a record is lost when a later-sent record
    /// has been delivered and it has dwelled ≥ reo_wnd.
    fn rack_mark(&mut self, now: Instant) -> usize {
        let Some(rack_at) = self.rack_delivered_at else {
            return 0;
        };
        let reo = self.reo_wnd();
        let rack_end = self.rack_delivered_end;
        let mut lost = 0usize;
        for rec in self.board.iter_mut() {
            if rec.sacked || rec.lost {
                continue;
            }
            // Only records sent before the delivered one and below its
            // sequence point are candidates (RFC 8985 step 3).
            if rec.end_seq > rack_end || rec.last_tx > rack_at {
                continue;
            }
            if to_std(now - rec.last_tx) >= reo {
                rec.lost = true;
                self.pipe = self.pipe.saturating_sub(rec.len());
                lost += rec.len();
                self.rack_lost_bytes += rec.len() as u64;
            }
        }
        lost
    }

    /// Arm the RACK deadline at the earliest candidate's expiry.
    fn arm_loss_deadline(&mut self, now: Instant) {
        let reo = to_smol(self.reo_wnd());
        self.loss_deadline = self
            .board
            .iter()
            .filter(|r| !r.sacked && !r.lost)
            .map(|r| r.last_tx + reo)
            .filter(|&t| t > now)
            .min();
    }

    /// Arm the TLP probe timeout (PTO = max(2·srtt, 10ms) < RTO).
    fn arm_tlp(&mut self, now: Instant, rto: Duration) {
        if self.board.iter().all(|r| r.sacked || r.lost) {
            self.tlp_deadline = None;
            return;
        }
        let srtt = self.rtt.srtt.unwrap_or(StdDuration::from_millis(500));
        let pto = (srtt * 2).max(TLP_MIN).min(to_std(rto));
        self.tlp_deadline = Some(now + to_smol(pto));
    }

    /// Main ACK entry point — called from `Socket::process` once per
    /// incoming segment carrying an ACK number, replacing the builtin
    /// dupack/on_ack block while an external controller is installed.
    ///
    /// `cum_ack` is the segment's acknowledgment number, `sack_ranges`
    /// its SACK blocks (absolute seqs, half-open), `tsecr`/`now_tsval`
    /// the echoed and current timestamps (when TS negotiated),
    /// `is_window_update` mirrors the socket's dupack suppression rule
    /// and `rto` caps the TLP probe timeout.
    #[allow(clippy::too_many_arguments)]
    pub fn on_segment_ack(
        &mut self,
        now: Instant,
        cum_ack: TcpSeqNumber,
        payload_len: usize,
        sack_ranges: &[Option<(u32, u32)>; 3],
        tsecr: Option<u32>,
        now_tsval: Option<u32>,
        is_window_update: bool,
        rto: Duration,
    ) -> AckEffects {
        let mut fx = AckEffects::default();
        self.last_progress = Some(now);
        self.idle_notified = false;

        let prev_cum = self.board.front().map(|r| r.seq).unwrap_or(cum_ack);
        let progressed = cum_ack > prev_cum;

        // DSACK: a first SACK block fully below the cumulative edge
        // reports a duplicate arrival (RFC 2883 §4).
        let dsack = sack_ranges[0]
            .map(|(l, r)| (l < r) && ((r as i64) <= cum_ack.0 as i64))
            .unwrap_or(false);
        if dsack {
            self.dsack_events += 1;
        }

        // --- drain cum-acked records into the delivery scratch -------
        self.scratch.clear();
        let base = self.base_seq.unwrap_or(TcpSeqNumber(0));
        let mut anchor: Option<Anchor> = None;
        while let Some(front) = self.board.front()
            && front.end_seq <= cum_ack
        {
            let rec = self.board.pop_front().unwrap();
            if rec.in_pipe() {
                self.pipe = self.pipe.saturating_sub(rec.len());
            }
            if !rec.delivered_to_sampler {
                self.scratch.push(rec.to_tx_record(base));
            }
            if anchor
                .as_ref()
                .map(|a| rec.last_tx >= a.last_tx)
                .unwrap_or(true)
            {
                anchor = Some(Anchor {
                    last_tx: rec.last_tx,
                    end_seq: rec.end_seq,
                    retransmitted: rec.retransmitted,
                    tsval: rec.tsval,
                });
            }
        }

        // --- apply SACK ranges ---------------------------------------
        for range in sack_ranges.iter().flatten() {
            let (l, r) = (TcpSeqNumber(range.0 as i32), TcpSeqNumber(range.1 as i32));
            for rec in self.board.iter_mut() {
                if rec.sacked || rec.end_seq <= l || rec.seq >= r {
                    continue;
                }
                let was_in_pipe = rec.in_pipe();
                rec.sacked = true;
                // Arrival evidence cancels a lost mark — a reordered
                // original must not be retransmitted later.
                rec.lost = false;
                if was_in_pipe {
                    self.pipe = self.pipe.saturating_sub(rec.len());
                }
            }
        }
        // Newly-sacked records join this ACK's delivery set exactly once.
        for rec in self.board.iter_mut() {
            if !rec.sacked || rec.delivered_to_sampler {
                continue;
            }
            rec.delivered_to_sampler = true;
            self.scratch.push(rec.to_tx_record(base));
            if anchor
                .as_ref()
                .map(|a| rec.last_tx >= a.last_tx)
                .unwrap_or(true)
            {
                anchor = Some(Anchor {
                    last_tx: rec.last_tx,
                    end_seq: rec.end_seq,
                    retransmitted: rec.retransmitted,
                    tsval: rec.tsval,
                });
            }
        }

        // --- duplicate-ack classification ----------------------------
        fx.dupack = payload_len == 0 && !progressed && !is_window_update;

        // --- loss marking --------------------------------------------
        let mut lost_now = 0usize;
        if fx.dupack {
            self.dupacks = self.dupacks.saturating_add(1);
            if self.dupacks >= 3 {
                // Frontier marking: every unconfirmed record below the
                // highest SACK edge is gone (Linux tcp_mark_head_lost).
                // Without SACK the gap head alone is marked — classic
                // NewReno fast retransmit.
                match sack_ranges
                    .iter()
                    .flatten()
                    .map(|(_, r)| *r)
                    .max()
                    .map(|r| TcpSeqNumber(r as i32))
                {
                    Some(edge) => {
                        // A record sent (or re-sent) too recently to be
                        // judged lost again is still legitimately in
                        // flight — re-marking it on every dupack batch
                        // paces re-sends by ACK arrival instead of RTO,
                        // which turns one hole into a same-seq re-send
                        // storm under a dupack flood (observed ~300
                        // copies of a 71-byte hole segment inside 700 ms
                        // on the afxdp path). Fresh sends use the RACK
                        // reorder window; a *retransmitted* record gets
                        // a full srtt of benefit — its evidence can't
                        // arrive faster than the path returns it.
                        let reo = to_smol(self.reo_wnd());
                        let retx_reo = to_smol(
                            self.reo_wnd()
                                .max(self.rtt.srtt.unwrap_or_else(|| self.reo_wnd())),
                        );
                        for rec in self.board.iter_mut() {
                            if rec.sacked || rec.lost || rec.end_seq > edge {
                                continue;
                            }
                            let dwell = if rec.retransmitted { retx_reo } else { reo };
                            if rec.last_tx + dwell > now {
                                continue;
                            }
                            rec.lost = true;
                            self.pipe = self.pipe.saturating_sub(rec.len());
                            lost_now += rec.len();
                        }
                    }
                    None => {
                        // No SACK evidence: mark only the gap head, and
                        // only if it has dwelled past its recency
                        // window — same guard as the SACK frontier
                        // above (retransmitted records get a full srtt).
                        let reo = to_smol(self.reo_wnd());
                        let retx_reo = to_smol(
                            self.reo_wnd()
                                .max(self.rtt.srtt.unwrap_or_else(|| self.reo_wnd())),
                        );
                        if let Some(rec) = self.board.iter_mut().find(|r| {
                            !r.sacked
                                && !r.lost
                                && r.last_tx
                                    + if r.retransmitted { retx_reo } else { reo }
                                    <= now
                        }) {
                            rec.lost = true;
                            self.pipe = self.pipe.saturating_sub(rec.len());
                            lost_now += rec.len();
                        }
                    }
                }
            }
        } else {
            self.dupacks = 0;
        }

        // RACK anchor update + time-based marking.
        if let Some(a) = anchor
            && self.rack_delivered_at.map(|t| a.last_tx >= t).unwrap_or(true)
        {
            self.rack_delivered_at = Some(a.last_tx);
            self.rack_delivered_end = a.end_seq;
        }
        if !self.scratch.is_empty() {
            lost_now += self.rack_mark(now);
            self.arm_loss_deadline(now);
            self.arm_tlp(now, rto);
        }

        // --- Eifel / DSACK undo --------------------------------------
        // TSecr-Eifel: the ACK confirmed a retransmitted record and the
        // echoed tsval predates that record's retransmission tsval — the
        // ACK was triggered by the ORIGINAL, so the retx was spurious.
        let tsecr_spurious = match (tsecr, anchor) {
            (Some(tsecr), Some(a)) => {
                a.retransmitted
                    && a.tsval != 0
                    && tsecr.wrapping_sub(a.tsval) < 0x8000_0000
                    && tsecr != a.tsval
            }
            _ => false,
        };
        if (dsack || tsecr_spurious) && self.loss_response_outstanding {
            self.cc.on_loss_undo(ti(now));
            self.loss_response_outstanding = false;
            fx.spurious_undo = true;
            // Reorder evidence widens the window (RFC 8985 §7.3).
            self.reo_wnd_mult = (self.reo_wnd_mult * 2).min(REO_WND_MAX_MULT);
        }
        if lost_now > 0 {
            self.loss_response_outstanding = true;
        }

        // --- rate sample + controller --------------------------------
        let prior_in_flight = self.pipe as u64;
        let cum_u64 = cum_ack.0.wrapping_sub(base.0) as u32 as u64;
        let rs = self.sampler.on_ack(
            ti(now),
            &self.scratch,
            lost_now as u64,
            0, // classic ECN folds through `on_ecn_ce` at socket level
            prior_in_flight,
            cum_u64,
        );

        // RTT: scoreboard first-tx timing (µs, Karn-safe). Under a run
        // of pure retransmits the sampler yields None — then TSecr RTTM
        // is the only evidence source (it echoes the retx's own tsval).
        let mut rtt_sample = rs.rtt;
        if rtt_sample.is_none()
            && progressed
            && let (Some(tsecr), Some(now_ts)) = (tsecr, now_tsval)
        {
            let diff_ms = now_ts.wrapping_sub(tsecr);
            if diff_ms > 0 && diff_ms < 0x7FFF_FFFF {
                rtt_sample = Some(StdDuration::from_millis(diff_ms as u64));
            }
        }
        if let Some(r) = rtt_sample {
            self.rtt.sample(r);
            fx.rtt_sampled = true;
        }

        self.cc.on_rate_sample(&rs, self.pipe as u64, &self.rtt);
        if lost_now > 0 {
            self.cc
                .on_loss_event(ti(now), lost_now as u64, self.pipe as u64, false);
        }
        fx.newly_lost = lost_now;
        fx
    }
}

impl fmt::Debug for ExtTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtTransport")
            .field("pipe", &self.pipe)
            .field("board_len", &self.board.len())
            .field("rack_lost_bytes", &self.rack_lost_bytes)
            .field("dsack_events", &self.dsack_events)
            .field("reo_wnd_mult", &self.reo_wnd_mult)
            .finish_non_exhaustive()
    }
}
