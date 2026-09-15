//! HyStart++ (RFC 9406) delay-based slow-start exit — reusable part.
//!
//! Extracted from the CUBIC reference controller so EdgeCC's startup
//! (§2.4: "HyStart++ 式时延抬升" exit condition) runs the identical
//! judgement. Rounds are delimited by sequence space; each completed
//! round's min RTT is compared against
//! `clamp(lastRoundMinRtt, baseline + CSS_DELTA, baseline × CSS_GROWTH)`.
//! After `CSS_ROUNDS` consecutive elevated rounds the caller should
//! leave slow start.
//!
//! The baseline may be seeded from the aggregate's `base_rtt` (EdgeCC)
//! or from the flow's own first samples (reference controllers).

use std::time::Duration;

/// RFC 9406 §4.3: consecutive elevated-delay rounds before exiting SS.
pub const CSS_ROUNDS: u32 = 3;
/// RFC 9406 §4.2: minimum RTT samples per round for a trusted judgement.
pub const MIN_SAMPLES: u32 = 8;
/// RFC 9406 §4.3: CSS delay delta.
pub const CSS_DELTA: Duration = Duration::from_millis(4);
/// RFC 9406 §4.3: growth clamp — currMinRtt may not exceed baseline×1.25
/// before the round counts as elevated.
const CSS_GROWTH_NUM: u128 = 5;
const CSS_GROWTH_DEN: u128 = 4;

/// Per-ACK verdict for the slow-start driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HystartVerdict {
    /// Round still open, or a round closed without a trusted/elevated
    /// judgement — stay in slow start.
    Continue,
    /// A round closed with elevated delay (conservative slow start).
    ElevatedRound,
    /// `CSS_ROUNDS` consecutive elevated rounds — leave slow start.
    Exit,
}

#[derive(Clone, Debug, Default)]
pub struct HyStart {
    /// Sent-byte watermark that closes the current RTT round.
    round_end: u64,
    /// RTT samples seen this round.
    round_samples: u32,
    /// Min RTT seen this round.
    round_min_rtt: Option<Duration>,
    /// Min RTT of the previous completed round.
    last_round_min_rtt: Option<Duration>,
    /// Baseline min RTT (seeded by the caller).
    baseline_min: Option<Duration>,
    /// Consecutive elevated-delay rounds.
    css_rounds: u32,
}

impl HyStart {
    pub fn new() -> Self {
        Self::default()
    }

    /// Full reset (RTO / idle restart): clears the baseline too — the
    /// caller re-seeds on the next ACK, possibly from the aggregate.
    pub fn reset(&mut self, sent_total: u64) {
        *self = HyStart {
            round_end: sent_total,
            ..HyStart::default()
        };
    }

    /// Seed the delay baseline (first call wins). `sent_total` anchors
    /// the first round boundary.
    pub fn seed_baseline(&mut self, rtt: Duration, sent_total: u64) {
        if self.baseline_min.is_none() {
            self.baseline_min = Some(rtt);
            self.round_end = sent_total;
        }
    }

    pub fn baseline_min(&self) -> Option<Duration> {
        self.baseline_min
    }

    pub fn css_rounds(&self) -> u32 {
        self.css_rounds
    }

    /// Feed one ACK event during slow start. `rtt` is this event's RTT
    /// sample (None for retransmit-acked events), `cum_ack` the
    /// cumulative ACK edge, `sent_total` the sender's cumulative queued
    /// bytes (sequence-space progress delimits rounds).
    pub fn on_ack(
        &mut self,
        rtt: Option<Duration>,
        cum_ack: u64,
        sent_total: u64,
    ) -> HystartVerdict {
        if let Some(r) = rtt {
            self.round_samples += 1;
            self.round_min_rtt = Some(self.round_min_rtt.map_or(r, |m| m.min(r)));
        }
        if cum_ack <= self.round_end {
            return HystartVerdict::Continue;
        }
        // Round closed.
        let Some(curr) = self.round_min_rtt else {
            self.round_end = sent_total;
            return HystartVerdict::Continue;
        };
        let trusted = self.round_samples >= MIN_SAMPLES;
        let elevated = trusted && {
            let baseline = self.baseline_min.unwrap_or(curr);
            let last = self.last_round_min_rtt.unwrap_or(curr);
            let lo = baseline + CSS_DELTA;
            let hi = Duration::from_nanos(
                (baseline.as_nanos() * CSS_GROWTH_NUM / CSS_GROWTH_DEN) as u64,
            );
            // clamp() panics on lo>hi (tiny baselines make DELTA exceed
            // the growth bound) — order the bounds first.
            let (bound_lo, bound_hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
            curr > last.clamp(bound_lo, bound_hi)
        };
        if elevated {
            self.css_rounds += 1;
        } else if trusted {
            self.css_rounds = 0;
        }
        self.last_round_min_rtt = Some(curr);
        self.round_min_rtt = None;
        self.round_samples = 0;
        self.round_end = sent_total;
        if self.css_rounds >= CSS_ROUNDS {
            HystartVerdict::Exit
        } else if elevated {
            HystartVerdict::ElevatedRound
        } else {
            HystartVerdict::Continue
        }
    }
}
