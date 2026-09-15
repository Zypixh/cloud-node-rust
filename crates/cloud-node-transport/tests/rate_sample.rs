//! RateSample unit cases: ACK compression, delayed ACK, SACK subsets,
//! Karn's rule for retransmits, app-limited propagation.

use cloud_node_transport::rate_sample::{RateSampler, TxRecord};
use cloud_node_transport::TransportInstant;
use std::time::Duration;

const MSS: u64 = 1460;

fn t(us: u64) -> TransportInstant {
    TransportInstant::from_micros(us)
}

#[test]
fn single_acks_report_each_segment() {
    let mut s = RateSampler::new();
    let mut seq = 0u64;
    for i in 0..4u64 {
        let rec = s.note_sent(seq, MSS, t(i * 1000), false, None);
        seq += MSS;
        let rs = s.on_ack(t(i * 1000 + 500), &[rec], 0, 0, 3 * MSS, seq);
        assert_eq!(rs.delivered, MSS);
        assert_eq!(rs.acked_sacked, MSS);
        assert_eq!(rs.rtt, Some(Duration::from_micros(500)));
    }
    assert_eq!(s.delivered_total(), 4 * MSS);
}

#[test]
fn compressed_ack_reports_whole_flight() {
    // ACK compression: four segments acked by one event. The sample must
    // report all of them, and `interval` must be the send span — never
    // "one inter-ack gap" (that would quadruple the apparent rate).
    let mut s = RateSampler::new();
    // Establish a prior ACK event at t=1000 so ack_elapsed is measurable.
    let rec0 = s.note_sent(0, MSS, t(0), false, None);
    s.on_ack(t(1000), &[rec0], 0, 0, 0, MSS);

    let recs: Vec<TxRecord> = (1..=4u64)
        .map(|i| s.note_sent(i * MSS, MSS, t(1000 + i * 250), false, None))
        .collect();
    let rs = s.on_ack(t(2000), &recs, 0, 0, 4 * MSS, 5 * MSS);
    assert_eq!(rs.delivered, 4 * MSS);
    // send_elapsed = 1750-1250 = 500us < ack_elapsed = 2000-1000 = 1000us.
    assert_eq!(rs.interval, Duration::from_micros(1000));
    assert_eq!(rs.delivery_rate_bps(), 4 * MSS * 1_000_000 / 1000);
}

#[test]
fn send_span_governs_when_acks_arrive_faster_than_sends() {
    let mut s = RateSampler::new();
    let rec0 = s.note_sent(0, MSS, t(0), false, None);
    s.on_ack(t(100), &[rec0], 0, 0, 0, MSS);
    // Two segments sent 800us apart, acked 100us after the last send —
    // interval must follow the send span, not the tiny ack gap.
    let r1 = s.note_sent(MSS, MSS, t(200), false, None);
    let r2 = s.note_sent(2 * MSS, MSS, t(1000), false, None);
    let rs = s.on_ack(t(1100), &[r1, r2], 0, 0, 2 * MSS, 3 * MSS);
    assert_eq!(rs.delivered, 2 * MSS);
    // send_elapsed=800us vs ack_elapsed=1000us → max = 1000us.
    assert_eq!(rs.interval, Duration::from_micros(1000));
}

#[test]
fn retransmitted_segments_never_produce_rtt_samples() {
    let mut s = RateSampler::new();
    let orig = s.note_sent(0, MSS, t(0), false, None);
    // Lost; retransmitted at t=2000 with first_tx_at preserved.
    let retx = s.note_sent(0, MSS, t(2000), true, Some(orig.first_tx_at));
    assert!(retx.is_retransmit);
    let rs = s.on_ack(t(3000), &[retx], 0, 0, 0, MSS);
    assert_eq!(rs.delivered, MSS, "retransmitted bytes still count as delivered");
    assert_eq!(rs.rtt, None, "Karn: retransmits must not sample RTT");
}

#[test]
fn sack_subset_counts_only_confirmed_bytes() {
    let mut s = RateSampler::new();
    let recs: Vec<TxRecord> = (0..4u64)
        .map(|i| s.note_sent(i * MSS, MSS, t(i * 100), false, None))
        .collect();
    // SACK confirms segments 0 and 2 only (1 and 3 still in flight).
    let rs = s.on_ack(t(1000), &[recs[0], recs[2]], 0, 0, 3 * MSS, MSS);
    assert_eq!(rs.delivered, 2 * MSS);
    assert_eq!(rs.acked_sacked, 2 * MSS);
    // cum_ack passed through unchanged — recovery logic consumes it.
    assert_eq!(rs.cum_ack, MSS);
}

#[test]
fn app_limited_marks_samples_while_delivery_is_behind() {
    let mut s = RateSampler::new();
    let r1 = s.note_sent(0, MSS, t(0), false, None);
    s.on_ack(t(500), &[r1], 0, 0, 0, MSS);
    // App ran out of data after delivering the first segment.
    s.mark_app_limited();
    let r2 = s.note_sent(MSS, MSS, t(2000), false, None);
    assert!(r2.is_app_limited);
    let rs = s.on_ack(t(2500), &[r2], 0, 0, 0, 2 * MSS);
    assert!(rs.is_app_limited);
}

#[test]
fn empty_ack_event_carries_no_delivery() {
    let mut s = RateSampler::new();
    let rec = s.note_sent(0, MSS, t(0), false, None);
    let _ = rec;
    let rs = s.on_ack(t(1000), &[], 0, 0, MSS, 0);
    assert_eq!(rs.delivered, 0);
    assert_eq!(rs.rtt, None);
}
