//! PathModel — per-ACK O(1) path estimates (plan §2.2).
//!
//! One instance per *aggregate* (T6 wires aggregation); flows feed their
//! [`RateSample`]s in. Every quantity is an EWMA or a fixed-size windowed
//! filter — no online learning, no per-ACK allocation, no unbounded
//! state. Each field's doc cites its mechanism source
//! (BBR / BBRv1 `lt_bw` / BBRv3 / Veno / DCTCP / GCC / new).
//!
//! What this module does NOT do: decision making. It produces estimates
//! and confidence; `inference` turns them into a congestion belief and
//! the (T5) decision layer consumes both.

use crate::rate_sample::RateSample;
use crate::rtt::RttState;
use crate::TransportInstant;
use std::time::Duration;

// ---------------------------------------------------------------------
// Filter primitives (all O(1), no allocation).
// ---------------------------------------------------------------------

/// Gain-parameterized EWMA. First sample initializes; afterwards
/// `v += gain·(x − v)`.
#[derive(Clone, Copy, Debug, Default)]
struct Ewma {
    v: f64,
    set: bool,
}

impl Ewma {
    fn add(&mut self, gain: f64, x: f64) {
        self.v = if self.set {
            self.v + gain * (x - self.v)
        } else {
            self.set = true;
            x
        };
    }

    fn get(&self) -> Option<f64> {
        self.set.then_some(self.v)
    }
}

/// 3-slot sliding-window extremum — Linux `win_minmax` semantics
/// (`lib/win_minmax.c`, used by `tcp_bbr.c` for `bw` and `min_rtt`):
/// the best value plus two younger runners-up, each carrying its
/// timestamp; when the best expires the runner-up takes over. The
/// effective window is `[window − window/3, window]` — the same
/// approximation the kernel ships.
#[derive(Clone, Copy, Debug)]
struct WinFilter {
    /// Slots ordered best-first: (value, timestamp_us).
    s: [(f64, u64); 3],
    window_us: u64,
    is_min: bool,
}

impl WinFilter {
    fn new(window: Duration, is_min: bool) -> Self {
        let worst = if is_min { f64::INFINITY } else { 0.0 };
        Self {
            s: [(worst, 0); 3],
            window_us: window.as_micros() as u64,
            is_min,
        }
    }

    fn new_max(window: Duration) -> Self {
        Self::new(window, false)
    }

    fn new_min(window: Duration) -> Self {
        Self::new(window, true)
    }

    fn worst(&self) -> f64 {
        if self.is_min {
            f64::INFINITY
        } else {
            0.0
        }
    }

    fn set_window(&mut self, window: Duration) {
        self.window_us = window.as_micros() as u64;
    }

    /// Fold a sample in and expire slots older than the window.
    /// Returns the current extremum.
    fn add(&mut self, now_us: u64, v: f64) -> f64 {
        // Fold into the best slot the sample improves on.
        let is_min = self.is_min;
        for slot in &mut self.s {
            let improves = if is_min { v < slot.0 } else { v > slot.0 };
            if improves {
                *slot = (v, now_us);
                break;
            }
        }
        // Expire: when s[0] goes stale, promote s[1], s[2], then a fresh
        // empty slot (win_minmax.c).
        while self.window_us > 0 && self.s[0].1.saturating_add(self.window_us) < now_us {
            self.s[0] = self.s[1];
            self.s[1] = self.s[2];
            self.s[2] = (self.worst(), now_us);
        }
        for i in 1..3 {
            if self.window_us > 0 && self.s[i].1.saturating_add(self.window_us) < now_us {
                self.s[i] = (self.worst(), now_us);
            }
        }
        self.s[0].0
    }

    /// Current extremum; `None` when no live sample exists (max: 0,
    /// min: +∞ are the empty sentinels — a real 0-bandwidth or
    /// infinite-RTT sample is never stored).
    fn value(&self) -> Option<f64> {
        let v = self.s[0].0;
        (v != self.worst()).then_some(v)
    }

    /// Force the filter to `v` (route-change rebase): all slots reset.
    fn rebase(&mut self, now_us: u64, v: f64) {
        self.s = [(v, now_us); 3];
    }
}

// ---------------------------------------------------------------------
// Constants (sources noted; pinned, not runtime-configurable).
// ---------------------------------------------------------------------

/// EWMA gain for bw_est / bw_dev / alpha / extra_acked / gradients —
/// ~8-sample memory, same order as Linux BBR's `bbr_gain`.
const EWMA_GAIN: f64 = 1.0 / 8.0;

/// `bw_max` window ≈ 8 RTTs (BBR keeps the max over ~2 probe cycles;
/// updated from srtt each sample so it scales with the path).
const BW_MAX_WINDOW_RTTS: u64 = 8;

/// base_rtt long window (BBR min-RTT window ≈ 10s; we keep the same
/// order but wider so drift detection can distinguish route changes).
const BASE_RTT_WINDOW: Duration = Duration::from_secs(10);

/// Recent-min window feeding drift rebase (short: the value we'd lift
/// the floor to when the route moved).
const RECENT_MIN_WINDOW: Duration = Duration::from_secs(4);

/// Route-drift horizon: all samples stayed above
/// `base × (1 + DRIFT_MARGIN)` for this long *with low inflight* → the
/// floor may rise (new — BBR only probes down; the up-drift rule is
/// the documented addition of §2.2).
const BASE_RTT_DRIFT_HORIZON: Duration = Duration::from_secs(8);
const BASE_RTT_DRIFT_MARGIN: f64 = 0.15;

/// qdelay above `max(QDELAY_MIN, base_rtt/8)` counts as "elevated" for
/// the loss-column split (Veno-style queue-occupancy threshold; new
/// constant — no upstream pin).
const QDELAY_ELEVATED_MIN: Duration = Duration::from_millis(1);

/// BBRv1 `lt_bw` (net/ipv4/tcp_bbr.c): a loss round counts toward the
/// policer verdict only while bw stays within `LT_BW_RATIO` of the
/// candidate; `LT_INTVL_MIN_RTT` consecutive rounds pin it.
const LT_BW_RATIO: f64 = 0.125;
const LT_INTVL_MIN_RTT: u32 = 4;

/// Low-inflight watermark for delay-signal sampling: max(4·MSS, BDP/4)
/// (new — samples taken above the noise of queue self-occupancy).
const LOW_INFLIGHT_MSS: u64 = 4;

/// Confidence saturates after this many non-app-limited rate samples.
const BW_CONFIDENCE_SAMPLES: u64 = 20;

/// Delay-signal quality needs at least this many low-inflight samples.
const DSQ_MIN_SAMPLES: u64 = 8;

/// p_rand (random-loss baseline) confidence needs this many quiet-path
/// bytes before the estimate is reported at all.
const P_RAND_MIN_QUIET_BYTES: u64 = 64 * 1024;

// ---------------------------------------------------------------------
// PathModel
// ---------------------------------------------------------------------

/// Per-aggregate path model (plan §2.2). Feed `on_rate_sample` once per
/// ACK event; all accessors are O(1) reads of the filters above.
#[derive(Debug)]
pub struct PathModel {
    mss: u64,

    // --- bandwidth ---
    /// `bw_max` — windowed max of delivery rate (BBR `bbr_bw`).
    bw_max: WinFilter,
    /// `bw_est` — EWMA of non-app-limited delivery samples (new:
    /// uncertainty-driven probing needs a point estimate, not the max).
    bw_est: Ewma,
    /// `bw_sigma` input — EWMA of |sample − est| (new). Scaled to a
    /// standard-deviation estimate on read (×√(π/2) for Gaussian).
    bw_dev: Ewma,
    bw_samples: u64,
    bw_last_us: u64,
    /// `bw_hi` / `bw_lo` — dose-response bounds (BBRv3 concept): the
    /// decision layer sets them from probe/response outcomes.
    bw_hi: Option<u64>,
    bw_lo: Option<u64>,

    // --- RTT / queueing delay ---
    /// `base_rtt` — long-window minimum (BBR `min_rtt`) plus drift
    /// rebase (new): if every sample exceeds the floor for a full
    /// horizon *while inflight is low*, a route change is assumed and
    /// the floor is allowed up to the recent-min.
    base_rtt: WinFilter,
    /// Short-window min used as the rebase target.
    recent_min: WinFilter,
    /// Last time a sample sat within DRIFT_MARGIN of the floor.
    base_floor_seen_us: u64,
    /// `qdelay` = srtt − base_rtt (Copa/Swift standing-queue estimate).
    qdelay_us: f64,
    prev_qdelay_us: Option<f64>,
    prev_rtt_us: u64,
    /// `qdelay_grad` — EWMA of qdelay change normalized to per-RTT
    /// (GCC filtered gradient, RMCAT).
    qdelay_grad: Ewma,

    // --- ACK aggregation ---
    /// `extra_acked` — EWMA of `acked_sacked − bw_est×interval`
    /// (BBRv3 `bbr_extra_acked`): how much ACK compression overstates
    /// the apparent delivery.
    extra_acked: Ewma,

    // --- loss process (two columns, Veno + new) ---
    lost_total: u64,
    delivered_total: u64,
    /// Losses while qdelay was elevated (congestion column).
    loss_qdelay_bytes: u64,
    loss_qdelay_events: u64,
    /// Losses without qdelay rise (quiet column — feeds p_rand).
    loss_quiet_bytes: u64,
    loss_quiet_events: u64,
    /// Loss-burst length EWMA (consecutive loss-ACKs within one RTT).
    burst_len: Ewma,
    cur_burst: u64,
    last_loss_us: u64,
    /// Causal test (new): loss/delivered bytes accumulated inside a
    /// post-speedup monitoring window opened by `note_speedup`.
    accel_lost: u64,
    accel_delivered: u64,
    accel_until_us: u64,
    /// Quiet-column denominators for `p_rand`.
    quiet_lost: u64,
    quiet_delivered: u64,
    /// Spurious-retransmit accounting (DSACK/Eifel, §2.8 feeds this).
    spurious_bytes: u64,
    retx_bytes: u64,

    // --- ECN ---
    /// `alpha` — EWMA of per-ACK CE fraction (DCTCP RFC 8257 alpha;
    /// with AccECN the fraction is exact, classic ECN is event-grain).
    alpha: Ewma,

    // --- lt_bw / policer (BBRv1) ---
    lt_bw: Option<u64>,
    lt_candidate: f64,
    lt_rounds: u32,
    lt_round_end_us: u64,
    lt_round_had_loss: bool,

    // --- delay signal quality (new) ---
    /// RTT deviation EWMA sampled only while inflight is low.
    low_inflight_dev: Ewma,
    low_inflight_samples: u64,

    /// Last `rtt.srtt` seen (µs) — cached because `on_rate_sample`
    /// receives `RttState` by reference each call.
    cached_srtt_us: Option<f64>,
}

impl PathModel {
    pub fn new(mss: u64) -> Self {
        Self {
            mss: mss.max(1),
            bw_max: WinFilter::new_max(Duration::from_secs(4)),
            bw_est: Ewma::default(),
            bw_dev: Ewma::default(),
            bw_samples: 0,
            bw_last_us: 0,
            bw_hi: None,
            bw_lo: None,
            base_rtt: WinFilter::new_min(BASE_RTT_WINDOW),
            recent_min: WinFilter::new_min(RECENT_MIN_WINDOW),
            base_floor_seen_us: 0,
            qdelay_us: 0.0,
            prev_qdelay_us: None,
            prev_rtt_us: 0,
            qdelay_grad: Ewma::default(),
            extra_acked: Ewma::default(),
            lost_total: 0,
            delivered_total: 0,
            loss_qdelay_bytes: 0,
            loss_qdelay_events: 0,
            loss_quiet_bytes: 0,
            loss_quiet_events: 0,
            burst_len: Ewma::default(),
            cur_burst: 0,
            last_loss_us: 0,
            accel_lost: 0,
            accel_delivered: 0,
            accel_until_us: 0,
            quiet_lost: 0,
            quiet_delivered: 0,
            spurious_bytes: 0,
            retx_bytes: 0,
            alpha: Ewma::default(),
            lt_bw: None,
            lt_candidate: 0.0,
            lt_rounds: 0,
            lt_round_end_us: 0,
            lt_round_had_loss: false,
            low_inflight_dev: Ewma::default(),
            low_inflight_samples: 0,
            cached_srtt_us: None,
        }
    }

    /// Low-inflight watermark: samples above it may be self-queued.
    fn low_inflight_thresh(&self) -> u64 {
        let bdp = self
            .bw_est
            .get()
            .map(|bw| (bw * self.srtt_us().unwrap_or(0.0) / 1e6) as u64)
            .unwrap_or(0);
        (LOW_INFLIGHT_MSS * self.mss).max(bdp / 4)
    }

    fn srtt_us(&self) -> Option<f64> {
        self.cached_srtt_us
    }

    /// Qdelay above this counts as elevated (loss-column split).
    pub fn qdelay_elevated_thresh(&self) -> Duration {
        let base = self.base_rtt().unwrap_or(Duration::from_millis(10));
        QDELAY_ELEVATED_MIN.max(base / 8)
    }

    /// Feed one ACK event — every filter updates, all O(1).
    pub fn on_rate_sample(
        &mut self,
        rs: &RateSample,
        in_flight: u64,
        rtt: &RttState,
    ) {
        let now_us = rs.now.micros();
        self.delivered_total += rs.delivered;
        self.lost_total += rs.lost;
        self.cached_srtt_us = rtt
            .srtt
            .map(|s| s.as_micros() as f64)
            .or(self.cached_srtt_us);

        // --- RTT chain ---
        if let Some(r) = rs.rtt {
            let r_us = r.as_micros() as f64;
            self.base_rtt.add(now_us, r_us);
            self.recent_min.add(now_us, r_us);
            let base = self.base_rtt.value().unwrap_or(r_us);
            let srtt_us = rtt.srtt.map(|s| s.as_micros() as f64).unwrap_or(r_us);
            let qdelay = (srtt_us - base).max(0.0);
            self.qdelay_us = qdelay;
            if let Some(prev) = self.prev_qdelay_us {
                let dt = (now_us.saturating_sub(self.prev_rtt_us)).max(1) as f64;
                // GCC-style gradient: Δqdelay normalized to per-RTT.
                let g = (qdelay - prev) * (srtt_us.max(1.0) / dt);
                self.qdelay_grad.add(EWMA_GAIN, g);
            }
            self.prev_qdelay_us = Some(qdelay);
            self.prev_rtt_us = now_us;

            // base_rtt drift detection (new): samples above the floor
            // for a whole horizon while inflight is low → route change.
            if r_us <= base * (1.0 + BASE_RTT_DRIFT_MARGIN) {
                self.base_floor_seen_us = now_us;
            } else if now_us.saturating_sub(self.base_floor_seen_us)
                > BASE_RTT_DRIFT_HORIZON.as_micros() as u64
                && self.base_floor_seen_us > 0
                && in_flight <= self.low_inflight_thresh()
                && let Some(recent) = self.recent_min.value()
            {
                self.base_rtt.rebase(now_us, recent);
                self.base_floor_seen_us = now_us;
            }

            // Delay-signal quality (new): deviation at low inflight.
            if in_flight <= self.low_inflight_thresh() {
                self.low_inflight_dev
                    .add(EWMA_GAIN, (r_us - srtt_us).abs());
                self.low_inflight_samples += 1;
            }
        }

        // --- bandwidth ---
        if rs.delivered > 0 {
            let rate = rs.delivery_rate_bps() as f64;
            if rate > 0.0 {
                if let Some(srtt) = rtt.srtt {
                    self.bw_max
                        .set_window(srtt * BW_MAX_WINDOW_RTTS as u32);
                }
                // bw_max sees every real sample (max-filter is safe);
                // bw_est only learns from network-limited flights —
                // app-limited samples must not pull the estimate down.
                self.bw_max.add(now_us, rate);
                if !rs.is_app_limited {
                    let prev = self.bw_est.get().unwrap_or(rate);
                    self.bw_dev.add(EWMA_GAIN, (rate - prev).abs());
                    self.bw_est.add(EWMA_GAIN, rate);
                    self.bw_samples += 1;
                    self.bw_last_us = now_us;
                }
            }
            // extra_acked (BBRv3): acked beyond the model's expectation.
            if let Some(est) = self.bw_est.get() {
                let expected = est * rs.interval.as_micros() as f64 / 1e6;
                self.extra_acked
                    .add(EWMA_GAIN, (rs.acked_sacked as f64 - expected).max(0.0));
            }
        }

        // --- lt_bw round close (BBRv1): close any overdue round BEFORE
        // attributing this ACK's loss to the current round.
        let rtt_us = rtt
            .srtt
            .or(rs.rtt)
            .unwrap_or(Duration::from_millis(1))
            .as_micros()
            .max(1) as u64;
        if self.lt_round_end_us > 0 && now_us >= self.lt_round_end_us {
            let bw = self.bw_est.get().unwrap_or(0.0);
            if self.lt_round_had_loss
                && self.lt_candidate > 0.0
                && (bw - self.lt_candidate).abs() <= self.lt_candidate * LT_BW_RATIO
            {
                self.lt_rounds += 1;
            } else {
                self.lt_rounds = 0;
                self.lt_candidate = bw;
            }
            if self.lt_rounds >= LT_INTVL_MIN_RTT && self.lt_candidate > 0.0 {
                self.lt_bw = Some(self.lt_candidate as u64);
            }
            self.lt_round_had_loss = false;
            self.lt_round_end_us = now_us + rtt_us;
        }

        // --- loss process ---
        let in_accel_window = now_us <= self.accel_until_us;
        let qd_elevated = self.qdelay_us
            > self.qdelay_elevated_thresh().as_micros() as f64;
        if in_accel_window {
            self.accel_delivered += rs.delivered + rs.lost;
            self.accel_lost += rs.lost;
        } else if !qd_elevated && rs.delivered_ce == 0 {
            // Quiet path sample: only these feed the random baseline.
            self.quiet_delivered += rs.delivered;
            self.quiet_lost += rs.lost;
        }
        if rs.lost > 0 {
            if qd_elevated {
                self.loss_qdelay_bytes += rs.lost;
                self.loss_qdelay_events += 1;
            } else {
                self.loss_quiet_bytes += rs.lost;
                self.loss_quiet_events += 1;
            }
            // Burst: loss ACKs inside the same RTT are one burst.
            if self.cur_burst > 0 && now_us.saturating_sub(self.last_loss_us) <= rtt_us {
                self.cur_burst += 1;
            } else {
                if self.cur_burst > 0 {
                    self.burst_len.add(EWMA_GAIN, self.cur_burst as f64);
                }
                self.cur_burst = 1;
            }
            self.last_loss_us = now_us;
            self.lt_round_had_loss = true;
            if self.lt_round_end_us == 0 {
                self.lt_round_end_us = now_us + rtt_us;
                self.lt_candidate = self.bw_est.get().unwrap_or_else(|| {
                    self.bw_max.value().unwrap_or(0.0)
                });
            }
        }

        // --- CE / alpha (DCTCP RFC 8257, per-ACK EWMA) ---
        if rs.delivered_ce > 0 && rs.delivered > 0 {
            let frac = (rs.delivered_ce as f64 / rs.delivered as f64).min(1.0);
            self.alpha.add(EWMA_GAIN, frac);
        }

        // A policer verdict is lifted when the path later delivers
        // clearly more than the pinned rate (BBRv1 does the same).
        if let Some(lt) = self.lt_bw
            && self.bw_est.get().unwrap_or(0.0) > lt as f64 * (1.0 + LT_BW_RATIO * 2.0)
        {
            self.lt_bw = None;
            self.lt_rounds = 0;
        }
    }

    /// Open a post-acceleration monitoring window for the causal loss
    /// test (§2.2 因果检验): losses inside the window are attributed to
    /// "did our speed-up raise the loss rate".
    pub fn note_speedup(&mut self, now: TransportInstant, horizon: Duration) {
        self.accel_lost = 0;
        self.accel_delivered = 0;
        self.accel_until_us = now.micros() + horizon.as_micros() as u64;
    }

    /// DSACK/Eifel judged `bytes` of retransmission spurious (§2.8).
    pub fn note_spurious_retx(&mut self, bytes: u64) {
        self.spurious_bytes += bytes;
    }

    /// The stack retransmitted `bytes` (denominator for the spurious
    /// ratio).
    pub fn note_retx(&mut self, bytes: u64) {
        self.retx_bytes += bytes;
    }

    // --------------------- accessors (all O(1)) ---------------------

    /// `bw_max` — BBR windowed-max delivery rate, bytes/s.
    pub fn bw_max(&self) -> Option<u64> {
        self.bw_max.value().map(|v| v as u64)
    }

    /// `bw_est` — EWMA point estimate of non-app-limited delivery rate.
    pub fn bw_est(&self) -> Option<u64> {
        self.bw_est.get().map(|v| v as u64)
    }

    /// `bw_sigma` — mean-deviation EWMA scaled to a σ estimate (√(π/2)
    /// converts mean absolute deviation to stddev for near-Gaussian
    /// samples). `None` before the first network-limited sample.
    pub fn bw_sigma(&self) -> Option<u64> {
        self.bw_dev.get().map(|d| (d * 1.2533) as u64)
    }

    /// Confidence in `bw_est` ∈ [0,1]: saturates with sample count and
    /// decays once the estimate goes stale (>8 RTT since last sample).
    pub fn bw_confidence(&self, now: TransportInstant) -> f64 {
        if self.bw_samples == 0 {
            return 0.0;
        }
        let n = (self.bw_samples as f64 / BW_CONFIDENCE_SAMPLES as f64).min(1.0);
        let stale = match self.cached_srtt_us {
            Some(srtt) if srtt > 0.0 => {
                let age = now.micros().saturating_sub(self.bw_last_us) as f64;
                let rtts = age / srtt;
                if rtts <= 8.0 {
                    1.0
                } else {
                    (0.5f64).powf(rtts / 8.0 - 1.0).max(0.05)
                }
            }
            _ => 0.5,
        };
        n * stale
    }

    /// Dose-response bounds (BBRv3 `bw_hi`/`bw_lo`), set by the decision
    /// layer via `set_bw_bounds`.
    pub fn bw_hi(&self) -> Option<u64> {
        self.bw_hi
    }

    pub fn bw_lo(&self) -> Option<u64> {
        self.bw_lo
    }

    /// BBRv3 dose-response bookkeeping: the decision layer records the
    /// tightest confirmed bound and the highest proven-safe rate.
    pub fn set_bw_bounds(&mut self, hi: Option<u64>, lo: Option<u64>) {
        self.bw_hi = hi;
        self.bw_lo = lo;
    }

    /// `base_rtt` — long-window minimum RTT (BBR min_rtt).
    pub fn base_rtt(&self) -> Option<Duration> {
        self.base_rtt
            .value()
            .map(|v| Duration::from_micros(v as u64))
    }

    /// `qdelay` = srtt − base_rtt (Copa/Swift), clamped ≥ 0.
    pub fn qdelay(&self) -> Duration {
        Duration::from_micros(self.qdelay_us.max(0.0) as u64)
    }

    /// `qdelay_grad` — filtered qdelay change per RTT in µs (GCC).
    /// Positive means the queue is growing.
    pub fn qdelay_grad_us_per_rtt(&self) -> f64 {
        self.qdelay_grad.get().unwrap_or(0.0)
    }

    /// `extra_acked` — ACK-aggregation over-count EWMA (BBRv3).
    pub fn extra_acked(&self) -> u64 {
        self.extra_acked.get().unwrap_or(0.0) as u64
    }

    /// Two-column loss split (Veno-style): bytes lost while qdelay was
    /// elevated vs quiet.
    pub fn loss_columns(&self) -> (u64, u64) {
        (self.loss_qdelay_bytes, self.loss_quiet_bytes)
    }

    pub fn loss_events(&self) -> (u64, u64) {
        (self.loss_qdelay_events, self.loss_quiet_events)
    }

    /// Loss-burst length EWMA (ACK events per burst).
    pub fn burst_len(&self) -> f64 {
        self.burst_len.get().unwrap_or(0.0)
    }

    /// Causal test (new): loss rate measured inside post-speedup
    /// windows vs the quiet baseline. `None` until a window collected
    /// ≥16 KiB of acked+lost bytes.
    pub fn loss_causation(&self) -> Option<f64> {
        let denom = self.accel_delivered;
        if denom < 16 * 1024 {
            return None;
        }
        let accel_rate = self.accel_lost as f64 / denom as f64;
        let base = self.p_rand().unwrap_or(0.0).max(1e-6);
        Some(accel_rate / base)
    }

    /// `p_rand` — random-loss baseline ∈ [0,1]: loss rate on samples
    /// with no qdelay rise, no CE, outside acceleration windows (new;
    /// high-loss international paths need this to avoid treating
    /// random loss as congestion).
    pub fn p_rand(&self) -> Option<f64> {
        if self.quiet_delivered + self.quiet_lost < P_RAND_MIN_QUIET_BYTES {
            return None;
        }
        let d = (self.quiet_delivered + self.quiet_lost) as f64;
        Some((self.quiet_lost as f64 / d).clamp(0.0, 1.0))
    }

    /// Spurious-retransmit ratio (DSACK/Eifel) ∈ [0,1].
    pub fn spurious_ratio(&self) -> Option<f64> {
        (self.retx_bytes > 0)
            .then(|| (self.spurious_bytes as f64 / self.retx_bytes as f64).min(1.0))
    }

    /// `alpha` — CE fraction EWMA ∈ [0,1] (DCTCP RFC 8257).
    pub fn alpha(&self) -> Option<f64> {
        self.alpha.get()
    }

    /// `lt_bw` — BBRv1 token-bucket policer verdict: sustained loss
    /// with flat delivery rate pins a long-term bandwidth ceiling.
    pub fn lt_bw(&self) -> Option<u64> {
        self.lt_bw
    }

    /// `delay_signal_quality` ∈ [0,1] (new): 1.0 when low-inflight RTT
    /// deviation is tiny vs base_rtt, →0 as jitter swamps the signal.
    /// `None` until enough low-inflight samples exist.
    pub fn delay_signal_quality(&self) -> Option<f64> {
        if self.low_inflight_samples < DSQ_MIN_SAMPLES {
            return None;
        }
        let dev = self.low_inflight_dev.get()?;
        let base = self.base_rtt.value().unwrap_or(10_000.0);
        let frac = (dev / (base * 0.25).max(1.0)).clamp(0.0, 1.0);
        Some(1.0 - frac)
    }

    /// BDP estimate = bw_est × srtt (bytes), `None` until both exist.
    pub fn bdp_est(&self) -> Option<u64> {
        let bw = self.bw_est.get()?;
        let srtt = self.cached_srtt_us?;
        Some((bw * srtt / 1e6) as u64)
    }
}
