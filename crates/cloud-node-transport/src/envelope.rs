//! Safety envelope (plan §2.5): `inflight_hi` is a hard ceiling set only
//! by strong evidence. Every caller takes its bound through `clamp()` —
//! inference errors degrade to in-envelope suboptimal, never to
//! uncontrolled overshoot (this is what bounds the "congestion loss
//! mistaken for random loss" failure mode of BBRv1).
//!
//! Strong evidence → set; hold otherwise; REFILL only after `K`
//! consecutive low-belief rounds (BBRv3 semantics).

/// Default headroom kept below the observed inflight when the ceiling
/// is set: `inflight_hi = inflight × (1 − HEADROOM)` (§2.5).
pub const DEFAULT_HEADROOM_MILLI: u32 = 300;

/// REFILL gate: belief (milli) must stay under this for
/// `REFILL_AFTER_ROUNDS` consecutive rounds before the ceiling grows.
/// Refill gate — *below* the belief sigmoid's neutral point (0.5) plus
/// margin: refills run at neutral/weak evidence, hold under real
/// evidence, and stop entirely past EdgeCC's response threshold.
pub const REFILL_BELIEF_MILLI: u32 = 600;

/// Consecutive low-belief rounds before each REFILL step (§2.5 "K 轮").
pub const REFILL_AFTER_ROUNDS: u32 = 2;

/// Each REFILL step grows the ceiling by 1/4 (bounded, saturating).
const REFILL_GAIN_NUM: u64 = 5;
const REFILL_GAIN_DEN: u64 = 4;

#[derive(Clone, Copy, Debug, Default)]
pub struct Envelope {
    /// Hard ceiling on inflight bytes; `None` = uncapped.
    inflight_hi: Option<u64>,
    /// Consecutive rounds with belief below the refill gate.
    low_belief_rounds: u32,
    /// Stable token for the last transition (CcSnapshot.reason_code).
    reason: &'static str,
}

impl Envelope {
    pub fn new() -> Self {
        Self {
            inflight_hi: None,
            low_belief_rounds: 0,
            reason: "init",
        }
    }

    /// Strong evidence (§2.5): losses with a qdelay rise past threshold,
    /// CE fraction past threshold, RTO, or a policer verdict → ceiling =
    /// `inflight × (1 − headroom_milli/1000)`. Setting always wins over
    /// the current ceiling — later evidence can tighten further.
    pub fn set(&mut self, inflight: u64, headroom_milli: u32, reason: &'static str) {
        let keep = 1000u64.saturating_sub(headroom_milli.min(1000) as u64);
        let hi = inflight.saturating_mul(keep) / 1000;
        self.inflight_hi = Some(match self.inflight_hi {
            // Repeated strong evidence tightens; it never loosens.
            Some(prev) => prev.min(hi),
            None => hi,
        });
        self.low_belief_rounds = 0;
        self.reason = reason;
    }

    /// Convenience: set with the default headroom.
    pub fn set_default(&mut self, inflight: u64, reason: &'static str) {
        self.set(inflight, DEFAULT_HEADROOM_MILLI, reason);
    }

    /// Per-RTT-round bookkeeping. `belief_milli` below the gate for
    /// `REFILL_AFTER_ROUNDS` consecutive rounds triggers one REFILL
    /// step (BBRv3): ceiling × 5/4, saturating. High belief resets the
    /// counter — the ceiling *holds*, it never drops on its own.
    pub fn on_round(&mut self, belief_milli: u32) {
        if self.inflight_hi.is_none() {
            self.low_belief_rounds = 0;
            return;
        }
        if belief_milli < REFILL_BELIEF_MILLI {
            self.low_belief_rounds += 1;
        } else {
            self.low_belief_rounds = 0;
            return;
        }
        if self.low_belief_rounds >= REFILL_AFTER_ROUNDS {
            let hi = self.inflight_hi.unwrap_or(u64::MAX);
            // Saturating growth; past u64::MAX/4 the ceiling is
            // effectively lifted (§2.5: REFILL → 上探).
            let grown = hi.saturating_mul(REFILL_GAIN_NUM) / REFILL_GAIN_DEN;
            self.inflight_hi = Some(grown);
            self.low_belief_rounds = 0;
            self.reason = "envelope_refill";
        }
    }

    /// The caller's send ceiling: `min(x, inflight_hi)` — uncapped when
    /// no ceiling is set. This is the *only* way to consume the bound.
    pub fn clamp(&self, inflight_target: u64) -> u64 {
        match self.inflight_hi {
            Some(hi) => inflight_target.min(hi),
            None => inflight_target,
        }
    }

    /// Current ceiling, if any.
    pub fn ceiling(&self) -> Option<u64> {
        self.inflight_hi
    }

    pub fn reason_code(&self) -> &'static str {
        self.reason
    }
}
