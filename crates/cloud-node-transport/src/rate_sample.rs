//! Per-segment delivery bookkeeping aligned with Linux `net/ipv4/tcp_rate.c`.
//!
//! Model: the sender's stack records one [`TxRecord`] per segment at send
//! time. When an ACK/SACK newly confirms segments, the stack calls
//! [`RateSampler::on_ack`] with those records; the sampler produces one
//! [`RateSample`] per ACK event — never a per-segment stream — matching
//! `tcp_rate_gen()` semantics:
//!
//! - `delivered` counts *newly confirmed* bytes between the cumulative
//!   counter and `delivered_at_send` of the most recently sent acked
//!   record (so delayed/compressed ACKs still attribute correctly).
//! - `interval` = max(send_elapsed, ack_elapsed) — the delivery rate is
//!   `delivered / interval`, never `acked_bytes / time_between_acks`,
//!   which ACK compression would corrupt.
//! - `rtt` comes only from segments that were never retransmitted
//!   (Karn's rule).
//! - `is_app_limited` rides on the segment: a sender that ran out of data
//!   marks segments; their ACK marks the sample so controllers do not
//!   mistake a voluntary pause for a rate ceiling.

use crate::instant::TransportInstant;
use std::time::Duration;

/// Bookkeeping stamped on a segment when it leaves the sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxRecord {
    /// First sequence byte covered by this segment.
    pub seq: u64,
    /// One past the last sequence byte.
    pub end_seq: u64,
    /// When this copy of the segment was transmitted.
    pub sent_at: TransportInstant,
    /// When the segment's payload was first transmitted (retransmits keep
    /// the original instant — RTT sampling must use first_tx_at and only
    /// on records that were never retransmitted).
    pub first_tx_at: TransportInstant,
    /// Sender's cumulative delivered counter at `sent_at`.
    pub delivered_at_send: u64,
    /// Sender had no more data ready when this segment went out.
    pub is_app_limited: bool,
    /// This transmission is a retransmit of previously sent bytes.
    pub is_retransmit: bool,
}

impl TxRecord {
    pub fn len(&self) -> u64 {
        self.end_seq.saturating_sub(self.seq)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One ACK event's worth of rate information — the unit CC consumes.
#[derive(Clone, Copy, Debug, Default)]
pub struct RateSample {
    /// Newly confirmed bytes (SACK included).
    pub delivered: u64,
    /// Bytes newly judged lost by this ACK event (RACK/dupack/RTO marks —
    /// supplied by the stack's loss detector, not inferred here).
    pub lost: u64,
    /// CE-marked byte increment (AccECN ACE/CEB count) or 0/1 event for
    /// classic ECN, as supplied by the stack.
    pub delivered_ce: u64,
    /// max(send_elapsed, ack_elapsed) — RFC/Linux semantics.
    pub interval: Duration,
    /// RTT sample from the newest non-retransmitted acked segment.
    pub rtt: Option<Duration>,
    /// The sample reflects an app-limited (not network-limited) flight.
    pub is_app_limited: bool,
    /// Bytes in flight before this ACK was processed.
    pub prior_in_flight: u64,
    /// Bytes cumulatively acked+sacked by this event.
    pub acked_sacked: u64,
    /// Cumulative ACK edge after processing — controllers use it to detect
    /// recovery completion (cum_ack passing the recovery point).
    pub cum_ack: u64,
    /// When this ACK was processed.
    pub now: TransportInstant,
}

impl RateSample {
    /// Delivery rate in bytes/s over `interval` (0 when interval is 0).
    pub fn delivery_rate_bps(&self) -> u64 {
        let us = self.interval.as_micros() as u64;
        if us == 0 {
            return 0;
        }
        self.delivered.saturating_mul(1_000_000) / us
    }
}

/// Sender-side cumulative state shared across ACK events.
///
/// The owning stack feeds segments via [`RateSampler::note_sent`] (which
/// stamps `delivered_at_send` itself) and reports each ACK via
/// [`RateSampler::on_ack`].
#[derive(Debug, Default)]
pub struct RateSampler {
    /// Cumulative confirmed-delivered bytes (Linux `tp->delivered`).
    delivered: u64,
    /// Cumulative bytes judged lost (Linux `tp->lost`).
    lost: u64,
    /// Cumulative CE-marked bytes delivered.
    delivered_ce: u64,
    /// Time of the previous ACK event (Linux `rs->prior_time`).
    prior_time: Option<TransportInstant>,
    /// End-seq of the highest segment seen sent — used to order records.
    last_send_end: u64,
    /// Delivered counter below which segments are app-limited
    /// (Linux `tp->app_limited`); set by `mark_app_limited`.
    app_limited_mark: u64,
}

impl RateSampler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn delivered_total(&self) -> u64 {
        self.delivered
    }

    pub fn lost_total(&self) -> u64 {
        self.lost
    }

    pub fn delivered_ce_total(&self) -> u64 {
        self.delivered_ce
    }

    /// Current cumulative delivered counter — pass into `TxRecord` as
    /// `delivered_at_send` when stamping a new segment.
    pub fn delivered_marker(&self) -> u64 {
        self.delivered
    }

    /// Stamp a segment being sent now. `delivered_at_send` is filled by the
    /// sampler; `is_app_limited` is derived from the app-limited mark so the
    /// flag travels with the segment like Linux's per-skb stamp.
    pub fn note_sent(
        &self,
        seq: u64,
        len: u64,
        sent_at: TransportInstant,
        is_retransmit: bool,
        first_tx_at: Option<TransportInstant>,
    ) -> TxRecord {
        TxRecord {
            seq,
            end_seq: seq + len,
            sent_at,
            first_tx_at: first_tx_at.unwrap_or(sent_at),
            delivered_at_send: self.delivered,
            is_app_limited: self.delivered <= self.app_limited_mark && self.app_limited_mark > 0,
            is_retransmit,
        }
    }

    /// Mark the point where the sender ran out of data. Segments whose
    /// `delivered_at_send` is below this mark produce app-limited samples
    /// (mirrors `tp->app_limited` semantics: cleared once delivery catches
    /// up past the mark).
    pub fn mark_app_limited(&mut self) {
        self.app_limited_mark = self.delivered;
    }

    /// Process one ACK event.
    ///
    /// `newly_acked` are the TxRecords this ACK/SACK newly confirmed, in
    /// sequence order (the stack's scoreboard already resolved duplicates —
    /// a record appears here exactly once in its lifetime). `lost_now` and
    /// `ce_now` are the byte increments this event attributed to loss and
    /// CE respectively. `prior_in_flight` is in-flight bytes before this
    /// ACK was processed. `cum_ack` is the cumulative ACK edge after this
    /// event.
    pub fn on_ack(
        &mut self,
        now: TransportInstant,
        newly_acked: &[TxRecord],
        lost_now: u64,
        ce_now: u64,
        prior_in_flight: u64,
        cum_ack: u64,
    ) -> RateSample {
        self.lost += lost_now;
        self.delivered_ce += ce_now;

        let Some(last) = newly_acked.last() else {
            // Pure window update / keepalive ACK — no delivery information.
            self.prior_time = Some(now);
            return RateSample {
                lost: lost_now,
                delivered_ce: ce_now,
                prior_in_flight,
                cum_ack,
                now,
                ..RateSample::default()
            };
        };

        let first = newly_acked.first().copied().unwrap_or(*last);
        for rec in newly_acked {
            self.delivered += rec.len();
            self.last_send_end = self.last_send_end.max(rec.end_seq);
        }

        // delivered since the last-acked segment was sent — compressed or
        // delayed ACKs therefore report the full flight, not per-ack bits.
        let delivered = self.delivered.saturating_sub(last.delivered_at_send);
        let send_elapsed = last.sent_at.duration_since(first.sent_at);
        let ack_elapsed = self
            .prior_time
            .map(|t| now.duration_since(t))
            .unwrap_or(send_elapsed);
        // Karn: retransmitted segments never produce RTT samples.
        let rtt = (!last.is_retransmit).then(|| now.duration_since(last.first_tx_at));
        let interval = send_elapsed.max(ack_elapsed);

        self.prior_time = Some(now);
        RateSample {
            delivered,
            lost: lost_now,
            delivered_ce: ce_now,
            interval,
            rtt,
            is_app_limited: last.is_app_limited
                && self.delivered <= self.app_limited_mark.max(last.delivered_at_send + last.len()),
            prior_in_flight,
            acked_sacked: newly_acked.iter().map(TxRecord::len).sum(),
            cum_ack,
            now,
        }
    }
}
