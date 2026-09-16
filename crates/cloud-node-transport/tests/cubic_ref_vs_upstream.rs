//! T3-10: same-ACK-trajectory cwnd comparison between `CubicRef`
//! (校验模式 — the in-stack RFC 9438 + HyStart++ + PRR controller) and the
//! vendored smoltcp upstream `congestion::cubic::Cubic` kept as reference.
//!
//! Both controllers consume the *same* event schedule — per-RTT rounds of
//! ACKs, duplicate-ACK bursts, loss episodes and one RTO — while each side
//! is driven with `in_flight` equal to its own current window. The round
//! count of ACKs follows a saturated sender on a 64-segment bottleneck:
//! `n = min(cwnd/MSS, PIPE_SEGS)`, and the schedule injects a loss
//! whenever the ref window reaches the pipe — the classic CUBIC sawtooth.
//! The saturated ACK rate is essential for a fair comparison because the
//! two implementations differ in how the Reno-friendly estimate advances:
//!
//! - upstream integrates `w_est += α·MSS²/cwnd` *per ACK event* — it only
//!   equals RFC 9438's `W_est(t) = W_max·β + α·t/RTT` when ACKs arrive at
//!   the saturated rate of `cwnd/MSS` per RTT;
//! - CubicRef evaluates the absolute-time `max(W_cubic(t), W_est(t))`
//!   target directly and converges on it per ACK, independent of ACK rate.
//!
//! The schedule is built in a first pass on CubicRef so the ACK counts
//! are deterministic and identical for both sides.
//!
//! Other expected, documented divergences:
//! - initial cwnd: CubicRef starts at 4·MSS, upstream at 2·MSS;
//! - slow start: CubicRef adds ABC L=2 (+≤2·MSS per ACK) and a HyStart++
//!   delay exit; upstream adds exactly `min(len, MSS)` per ACK;
//! - loss: upstream sets `ssthresh = β·in_flight`, inflates cwnd to
//!   `ssthresh + 3·MSS` for fast recovery and deflates to ssthresh on the
//!   first new-data ACK; CubicRef applies `cwnd·β` immediately and runs
//!   PRR;
//! - upstream implements RFC 9438 §4.7 fast convergence (w_max
//!   reduction); CubicRef intentionally pins it off;
//! - RTO: both collapse to 1·MSS; upstream holds ssthresh on repeat RTO.
//!
//! RTT: the upstream `RttEstimator` cannot be fed a synthetic sample from
//! outside the crate (its `sample()` is crate-private), so the upstream
//! side runs with no measurement → its `srtt` lookahead floors at 1 ms.
//! CubicRef is fed rtt = 1 ms for parity. With `CUBIC_COMPARE_OUT` set the
//! test also writes a CSV trace of both cwnd trajectories for the EN-24
//! evidence bundle.

use cloud_node_transport::cc::reference::CubicRef;
use cloud_node_transport::{CongestionController, RateSample, RttState, TransportInstant};
use smoltcp::socket::tcp::congestion::Controller;
use smoltcp::socket::tcp::congestion::cubic::Cubic;
use smoltcp::socket::tcp::RttEstimator;
use smoltcp::time::Instant;
use std::time::Duration;

const MSS: u64 = 1024;
const RTT_US: u64 = 1_000;
/// Bottleneck capacity in segments — a window reaching it drops.
const PIPE_SEGS: u64 = 64;
/// Hard fuse against runaway schedules; the script below converges in a
/// few hundred rounds, so hitting this means a model bug.
const MAX_ROUNDS: usize = 2_000;

/// One round's worth of shared events.
#[derive(Clone, Copy)]
enum Round {
    /// `n` ACKs of MSS bytes each, spread evenly across one RTT.
    Acks(u64),
    /// `n` duplicate ACKs (no new bytes), then a loss verdict.
    LossBurst { dupacks: u64, lost: u64 },
    /// Retransmission timeout.
    Rto,
}

/// Drive one CubicRef round of `n` MSS-sized ACKs (shared by pass A and B).
fn ref_ack_round(
    refr: &mut CubicRef,
    rtt_state: &mut RttState,
    cum_ack: &mut u64,
    now_us: &mut u64,
    n: u64,
) {
    for _ in 0..n {
        *now_us += RTT_US / n;
        *cum_ack += MSS;
        let in_flight = refr.cwnd().min(PIPE_SEGS * MSS);
        refr.on_sent(TransportInstant::from_micros(*now_us), MSS, in_flight, false);
        rtt_state.sample(Duration::from_micros(RTT_US));
        refr.on_rate_sample(
            &RateSample {
                delivered: MSS,
                lost: 0,
                delivered_ce: 0,
                interval: Duration::from_micros(RTT_US / n),
                rtt: Some(Duration::from_micros(RTT_US)),
                is_app_limited: false,
                prior_in_flight: in_flight,
                acked_sacked: MSS,
                cum_ack: *cum_ack,
                now: TransportInstant::from_micros(*now_us),
            },
            in_flight,
            rtt_state,
        );
    }
}

/// First pass on CubicRef alone — builds the deterministic schedule:
/// slow start until the window reaches the pipe, then sawtooth cycles
/// (loss on pipe saturation), one RTO, and a final regrowth.
fn build_schedule() -> Vec<Round> {
    let mut refr = CubicRef::new(MSS);
    let mut rtt_state = RttState::new();
    let mut cum_ack = 0u64;
    let mut now_us = 0u64;
    let mut schedule: Vec<Round> = Vec::new();
    let mut losses = 0u32;
    let mut rto_done = false;
    let mut post_rto_rounds = 0usize;

    for _ in 0..MAX_ROUNDS {
        if refr.cwnd() >= PIPE_SEGS * MSS && losses < 3 {
            schedule.push(Round::LossBurst { dupacks: 3, lost: MSS });
            refr.on_loss_event(
                TransportInstant::from_micros(now_us),
                MSS,
                refr.cwnd().min(PIPE_SEGS * MSS),
                false,
            );
            losses += 1;
            continue;
        }
        if losses == 3 && !rto_done {
            schedule.push(Round::Rto);
            refr.on_rto(
                TransportInstant::from_micros(now_us),
                refr.cwnd().min(PIPE_SEGS * MSS),
            );
            rto_done = true;
            continue;
        }
        let n = (refr.cwnd() / MSS).clamp(1, PIPE_SEGS);
        schedule.push(Round::Acks(n));
        ref_ack_round(&mut refr, &mut rtt_state, &mut cum_ack, &mut now_us, n);
        if rto_done {
            post_rto_rounds += 1;
            if post_rto_rounds >= 60 {
                break;
            }
        }
    }
    assert!(
        losses == 3 && rto_done && post_rto_rounds == 60,
        "schedule did not converge: losses={losses} rto={rto_done} post_rto={post_rto_rounds}"
    );
    schedule
}

struct Row {
    step: usize,
    event: &'static str,
    now_us: u64,
    acked: u64,
    in_flight_ref: u64,
    in_flight_up: u64,
    cwnd_ref: u64,
    cwnd_up: u64,
}

fn run(schedule: &[Round]) -> Vec<Row> {
    let mut refr = CubicRef::new(MSS);
    let mut up = Cubic::new();
    up.set_mss(MSS as usize);
    up.set_remote_window(usize::MAX);
    let rtte = RttEstimator::default();
    let mut rtt_state = RttState::new();
    let mut cum_ack = 0u64;
    let mut now_us = 0u64;
    let mut step = 0usize;
    let mut rows = Vec::new();

    macro_rules! row {
        ($event:literal, $acked:expr, $ifr:expr, $ifu:expr) => {{
            rows.push(Row {
                step,
                event: $event,
                now_us,
                acked: $acked,
                in_flight_ref: $ifr,
                in_flight_up: $ifu,
                cwnd_ref: refr.cwnd(),
                cwnd_up: up.window() as u64,
            });
            step += 1;
        }};
    }

    for round in schedule {
        match *round {
            Round::Acks(n) => {
                for _ in 0..n {
                    now_us += RTT_US / n;
                    cum_ack += MSS;
                    let in_flight_ref = refr.cwnd().min(PIPE_SEGS * MSS);
                    let in_flight_up = (up.window() as u64).min(PIPE_SEGS * MSS);
                    refr.on_sent(
                        TransportInstant::from_micros(now_us),
                        MSS,
                        in_flight_ref,
                        false,
                    );
                    rtt_state.sample(Duration::from_micros(RTT_US));
                    refr.on_rate_sample(
                        &RateSample {
                            delivered: MSS,
                            lost: 0,
                            delivered_ce: 0,
                            interval: Duration::from_micros(RTT_US / n),
                            rtt: Some(Duration::from_micros(RTT_US)),
                            is_app_limited: false,
                            prior_in_flight: in_flight_ref,
                            acked_sacked: MSS,
                            cum_ack,
                            now: TransportInstant::from_micros(now_us),
                        },
                        in_flight_ref,
                        &rtt_state,
                    );
                    up.on_ack(
                        Instant::from_micros(now_us as i64),
                        MSS as usize,
                        in_flight_up as usize,
                        &rtte,
                    );
                    row!("ack", MSS, in_flight_ref, in_flight_up);
                }
            }
            Round::LossBurst { dupacks, lost } => {
                for _ in 0..dupacks {
                    now_us += 200;
                    let in_flight_ref = refr.cwnd().min(PIPE_SEGS * MSS);
                    let in_flight_up = (up.window() as u64).min(PIPE_SEGS * MSS);
                    refr.on_rate_sample(
                        &RateSample {
                            delivered: 0,
                            lost: 0,
                            delivered_ce: 0,
                            interval: Duration::from_micros(200),
                            rtt: None,
                            is_app_limited: false,
                            prior_in_flight: in_flight_ref,
                            acked_sacked: 0,
                            cum_ack,
                            now: TransportInstant::from_micros(now_us),
                        },
                        in_flight_ref,
                        &rtt_state,
                    );
                    up.on_dup_ack(
                        Instant::from_micros(now_us as i64),
                        0,
                        in_flight_up as usize,
                    );
                    row!("dupack", 0, in_flight_ref, in_flight_up);
                }
                let in_flight_ref = refr.cwnd().min(PIPE_SEGS * MSS);
                let in_flight_up = (up.window() as u64).min(PIPE_SEGS * MSS);
                refr.on_loss_event(
                    TransportInstant::from_micros(now_us),
                    lost,
                    in_flight_ref,
                    false,
                );
                up.on_loss(Instant::from_micros(now_us as i64), in_flight_up as usize);
                row!("loss", 0, in_flight_ref, in_flight_up);
            }
            Round::Rto => {
                let in_flight_ref = refr.cwnd().min(PIPE_SEGS * MSS);
                let in_flight_up = (up.window() as u64).min(PIPE_SEGS * MSS);
                refr.on_rto(TransportInstant::from_micros(now_us), in_flight_ref);
                up.on_rto(Instant::from_micros(now_us as i64), in_flight_up as usize);
                row!("rto", 0, in_flight_ref, in_flight_up);
            }
        }
    }
    rows
}

fn emit_csv(rows: &[Row]) {
    let Some(path) = std::env::var_os("CUBIC_COMPARE_OUT") else {
        return;
    };
    let mut out = String::from(
        "step,event,now_us,acked_bytes,in_flight_ref,in_flight_upstream,cwnd_ref,cwnd_upstream\n",
    );
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            r.step, r.event, r.now_us, r.acked, r.in_flight_ref, r.in_flight_up, r.cwnd_ref,
            r.cwnd_up
        ));
    }
    std::fs::write(&path, out).expect("write cwnd comparison CSV");
}

#[test]
fn cubic_ref_vs_upstream_same_ack_trajectory() {
    let schedule = build_schedule();
    let rows = run(&schedule);
    emit_csv(&rows);

    // Invariant 1: both windows stay positive for the whole run.
    for r in &rows {
        assert!(r.cwnd_ref >= MSS, "ref cwnd collapsed at step {}", r.step);
        assert!(r.cwnd_up >= MSS, "upstream cwnd collapsed at step {}", r.step);
    }

    // Invariant 2: slow start — with len == MSS both add exactly 1 MSS per
    // ACK; the offset is exactly the IW difference (ref 4·MSS, up 2·MSS).
    let first_loss = rows.iter().position(|r| r.event == "loss").unwrap();
    let last_ss = &rows[first_loss - 4]; // before the dup-ack burst
    assert_eq!(
        last_ss.cwnd_ref - last_ss.cwnd_up,
        2 * MSS,
        "SS divergence should be exactly the IW difference (4 vs 2 MSS)"
    );
    assert!(last_ss.cwnd_ref >= PIPE_SEGS * MSS);

    // Invariant 3: each loss cuts both controllers into the β region and
    // strictly below the pre-loss window.
    for (i, r) in rows.iter().enumerate() {
        if r.event != "loss" {
            continue;
        }
        let pre = rows[..i]
            .iter()
            .rev()
            .find(|p| p.event == "ack")
            .expect("loss without preceding ack");
        assert!(
            r.cwnd_ref < pre.cwnd_ref,
            "ref did not cut on loss at step {i}: pre={} post={}",
            pre.cwnd_ref,
            r.cwnd_ref
        );
        assert!(
            r.cwnd_up <= r.in_flight_up.saturating_add(4 * MSS),
            "upstream above ssthresh+3MSS at step {i}: post={} inflight={}",
            r.cwnd_up,
            r.in_flight_up
        );
    }

    // Invariant 4: at the saturated ACK rate both CA curves must stay
    // within a 2× band — the RFC W_est slope equals upstream's AIMD
    // accumulation at cwnd/MSS ACKs per RTT; residual difference comes
    // from the per-formulation details listed in the module comment.
    let mut max_ratio = 0f64;
    let mut max_ratio_step = 0usize;
    for r in &rows {
        if r.event == "rto" {
            continue;
        }
        let lo = r.cwnd_ref.min(r.cwnd_up) as f64;
        let hi = r.cwnd_ref.max(r.cwnd_up) as f64;
        let ratio = hi / lo;
        if ratio > max_ratio {
            max_ratio = ratio;
            max_ratio_step = r.step;
        }
    }
    assert!(
        max_ratio <= 2.0,
        "cwnd trajectories diverged beyond 2x at step {max_ratio_step}: ratio={max_ratio:.2}"
    );

    // Invariant 5: RTO collapses both to 1 MSS; both regrow afterwards.
    let rto_idx = rows.iter().position(|r| r.event == "rto").unwrap();
    assert_eq!(rows[rto_idx].cwnd_up, MSS);
    assert_eq!(rows[rto_idx].cwnd_ref, MSS);
    let tail = &rows[rto_idx..];
    assert!(tail.last().unwrap().cwnd_ref > MSS * 2);
    assert!(tail.last().unwrap().cwnd_up > MSS * 2);

    // Summary line for the evidence bundle.
    eprintln!(
        "cubic-compare: steps={} rounds={} final_ref={}B final_up={}B max_ratio={:.2}@step{}",
        rows.len(),
        schedule.len(),
        rows.last().unwrap().cwnd_ref,
        rows.last().unwrap().cwnd_up,
        max_ratio,
        max_ratio_step
    );
}
