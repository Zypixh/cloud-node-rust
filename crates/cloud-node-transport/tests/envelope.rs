//! Envelope unit cases (plan §2.5): set-on-strong-evidence, hold, K-round
//! low-belief REFILL, and the inviolable clamp() contract.

use cloud_node_transport::envelope::{
    Envelope, DEFAULT_HEADROOM_MILLI, REFILL_AFTER_ROUNDS, REFILL_BELIEF_MILLI,
};

#[test]
fn clamp_never_exceeds_ceiling() {
    let mut e = Envelope::new();
    // Uncapped: clamp is identity.
    assert_eq!(e.clamp(u64::MAX), u64::MAX);
    assert_eq!(e.clamp(1_000), 1_000);

    // Strong evidence at inflight 10_000, 30% headroom → hi = 7_000.
    e.set_default(10_000, "loss_qdelay");
    assert_eq!(e.ceiling(), Some(7_000));
    assert_eq!(e.clamp(10_000), 7_000);
    assert_eq!(e.clamp(5_000), 5_000);
}

#[test]
fn repeated_strong_evidence_only_tightens() {
    let mut e = Envelope::new();
    e.set(10_000, DEFAULT_HEADROOM_MILLI, "ce");
    e.set(20_000, DEFAULT_HEADROOM_MILLI, "rto"); // hi would be 14_000
    assert_eq!(e.ceiling(), Some(7_000), "ceiling never loosens on set");
    e.set(6_000, DEFAULT_HEADROOM_MILLI, "policer"); // hi = 4_200
    assert_eq!(e.ceiling(), Some(4_200));
}

#[test]
fn ceiling_holds_while_belief_high() {
    let mut e = Envelope::new();
    e.set_default(10_000, "loss_qdelay");
    for _ in 0..10 {
        e.on_round(REFILL_BELIEF_MILLI + 100);
    }
    assert_eq!(e.ceiling(), Some(7_000), "high belief holds the ceiling");
    assert_eq!(e.reason_code(), "loss_qdelay");
}

#[test]
fn refill_after_k_low_belief_rounds() {
    let mut e = Envelope::new();
    e.set_default(10_000, "loss_qdelay");
    // K−1 rounds: still capped.
    for _ in 0..REFILL_AFTER_ROUNDS - 1 {
        e.on_round(REFILL_BELIEF_MILLI - 1);
    }
    assert_eq!(e.ceiling(), Some(7_000));
    // Round K: one refill step ×5/4.
    e.on_round(REFILL_BELIEF_MILLI - 1);
    assert_eq!(e.ceiling(), Some(7_000 * 5 / 4));
    assert_eq!(e.reason_code(), "envelope_refill");
    // One high-belief round resets the counter — hold again.
    e.on_round(900);
    for _ in 0..REFILL_AFTER_ROUNDS - 1 {
        e.on_round(REFILL_BELIEF_MILLI - 1);
    }
    assert_eq!(e.ceiling(), Some(8_750));
}

#[test]
fn sustained_low_belief_eventually_lifts_the_cap() {
    let mut e = Envelope::new();
    e.set(4 * 1460, DEFAULT_HEADROOM_MILLI, "rto");
    for _ in 0..64 {
        e.on_round(0);
    }
    // ×1.25 per K rounds over 64 rounds ≈ e^(…) — saturates to
    // effectively uncapped (assert it grew a lot and never panic).
    let hi = e.ceiling().unwrap();
    assert!(hi > 1_000_000, "cap should have refilled up, got {hi}");
}
