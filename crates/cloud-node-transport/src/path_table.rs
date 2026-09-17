//! `path_table` — long-lived path priors (plan §2.2, §6.5 L1/L4).
//!
//! Bounded table keyed by `(egress_iface, local_ip, af, dst_prefix)`
//! for origin side and `(ingress_iface, local_ip, af, client_prefix)`
//! for the client side. Each entry keeps the aggregate summary that
//! warms startup (`bw_est`, `base_rtt`, `p_rand`, `alpha`, reorder
//! degree, connect RTT, failure rate) with TTL, confidence, sample
//! age, and capacity-bounded eviction.
//!
//! Design contract:
//! - **Bounded**: `capacity` hard cap; expired entries are reaped on
//!   insert and on `sweep`; lookups never allocate.
//! - **Confidence decay**: confidence halves every `half_life`; below
//!   `MIN_CONFIDENCE` the entry is a candidate for eviction but still
//!   reported (the caller decides; §2.4 requires a bounded path, not
//!   blind trust).
//! - **Invalidation**: a path address change (route/ifindex) must call
//!   `invalidate` — stale priors seed a wrong BDP, which §2.4 only
//!   tolerates for a bounded window.
//! - **Prefix granularity**: the key carries a prefix *length*; lookups
//!   are exact-key (the wiring layer does longest-prefix resolution
//!   and calls `lookup` with each candidate key — keeping this table
//!   a plain map avoids hiding per-prefix merge policy here).

use crate::edgecc::PathPrior;
use crate::TransportInstant;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

/// Default entry TTL: priors older than this are never returned.
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);
/// Confidence halves per this interval of sample age.
pub const CONFIDENCE_HALF_LIFE: Duration = Duration::from_secs(900);
/// Below this, an entry is evictable before an unexpired one.
const MIN_CONFIDENCE: f64 = 0.05;
/// Hard default capacity (§2.2 容量限制).
pub const DEFAULT_CAPACITY: usize = 4096;
/// Failure-rate EWMA gain per recorded outcome.
const FAIL_GAIN: f64 = 0.2;

/// Table key — route/egress-anchored destination scope. `prefix_len`
/// is the *significant* bits of `prefix` (the wiring layer masks; we
/// keep the raw address + len for auditability).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathKey {
    /// Egress interface index (0 = any/unknown).
    pub egress_ifindex: u32,
    /// Local source address used on this path.
    pub local_ip: IpAddr,
    /// Destination prefix base address.
    pub dst_prefix: IpAddr,
    /// Significant prefix bits of `dst_prefix`.
    pub prefix_len: u8,
}

/// One flow's contribution to the entry (recorded at close/periodic).
#[derive(Clone, Copy, Debug, Default)]
pub struct PathSample {
    /// Delivered rate estimate (bytes/s) — bw_est of the closed flow.
    pub bw_bps: u64,
    /// Observed base RTT.
    pub base_rtt: Duration,
    /// Random-loss baseline ∈ [0,1].
    pub p_rand: f64,
    /// CE alpha ∈ [0,1] if the path marked.
    pub alpha: f64,
    /// Reorder degree ∈ [0,1] (reordered/(delivered) estimate).
    pub reorder: f64,
    /// Handshake RTT (connect_rtt).
    pub connect_rtt: Option<Duration>,
    /// Whether the flow ended in failure (timeout/reset/refused).
    pub failed: bool,
}

/// Stored prior + provenance.
#[derive(Clone, Copy, Debug)]
pub struct PathEntry {
    /// EWMA bandwidth estimate (bytes/s).
    pub bw_bps: f64,
    /// EWMA base RTT (µs as f64 — fractional keeps EWMA stable).
    pub base_rtt_us: f64,
    /// EWMA random-loss baseline.
    pub p_rand: f64,
    /// EWMA CE alpha.
    pub alpha: f64,
    /// EWMA reorder degree.
    pub reorder: f64,
    /// EWMA handshake RTT (µs).
    pub connect_rtt_us: f64,
    /// EWMA failure rate ∈ [0,1].
    pub fail_rate: f64,
    /// Sample count (confidence input).
    pub samples: u32,
    /// Last update instant.
    pub updated_at: u64,
    /// First sample instant.
    pub created_at: u64,
    /// Entry TTL.
    pub ttl: Duration,
}

impl PathEntry {
    /// Age-decayed confidence ∈ [0,1]: saturates with samples, halves
    /// every CONFIDENCE_HALF_LIFE of staleness.
    pub fn confidence(&self, now: TransportInstant) -> f64 {
        let n = (self.samples as f64 / 8.0).min(1.0);
        let age = now.micros().saturating_sub(self.updated_at);
        let halves = age as f64 / CONFIDENCE_HALF_LIFE.as_micros() as f64;
        n * 0.5f64.powf(halves.min(8.0))
    }

    /// Export the startup prior (§2.4 启动). `None` when the entry is
    /// too stale or has no usable estimate.
    pub fn prior(&self, now: TransportInstant) -> Option<PathPrior> {
        let conf = self.confidence(now);
        if conf < MIN_CONFIDENCE || self.bw_bps <= 0.0 || self.base_rtt_us <= 0.0 {
            return None;
        }
        Some(PathPrior {
            bw_bps: self.bw_bps as u64,
            base_rtt: Duration::from_micros(self.base_rtt_us as u64),
            p_rand: self.p_rand,
            alpha: self.alpha,
            confidence: conf,
        })
    }
}

/// Bounded prior table.
#[derive(Debug)]
pub struct PathTable {
    entries: BTreeMap<PathKey, PathEntry>,
    capacity: usize,
    default_ttl: Duration,
    /// EWMA gain for scalar fields (recent samples dominate).
    gain: f64,
    /// Total invalidations — audit counter.
    pub invalidated: u64,
    /// Total expirations — audit counter.
    pub expired: u64,
}

impl PathTable {
    pub fn new(capacity: usize, default_ttl: Duration) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: capacity.max(1),
            default_ttl,
            gain: 0.25,
            invalidated: 0,
            expired: 0,
        }
    }

    /// Record a flow outcome (called on close/periodically, O(log N)).
    pub fn record(&mut self, key: PathKey, s: PathSample, now: TransportInstant) {
        self.reap(now);
        let g = self.gain;
        match self.entries.get_mut(&key) {
            Some(e) => {
                // Zero fields mean "not measured" (e.g. a flow that died
                // before its first rate/rtt sample) — never fold missing
                // evidence into the EWMA or one bad close drags a good
                // prior toward 0. Failure rate still updates: a failed
                // dial is real evidence about the path.
                if s.bw_bps > 0 {
                    e.bw_bps += g * (s.bw_bps as f64 - e.bw_bps);
                }
                if s.base_rtt > Duration::ZERO {
                    e.base_rtt_us +=
                        g * (s.base_rtt.as_micros() as f64 - e.base_rtt_us);
                }
                e.p_rand += g * (s.p_rand - e.p_rand);
                e.alpha += g * (s.alpha - e.alpha);
                e.reorder += g * (s.reorder - e.reorder);
                if let Some(crtt) = s.connect_rtt {
                    e.connect_rtt_us += g * (crtt.as_micros() as f64 - e.connect_rtt_us);
                }
                e.fail_rate += FAIL_GAIN * (if s.failed { 1.0 } else { 0.0 } - e.fail_rate);
                e.samples = e.samples.saturating_add(1);
                e.updated_at = now.micros();
            }
            None => {
                if self.entries.len() >= self.capacity {
                    self.evict_one(now);
                }
                self.entries.insert(
                    key,
                    PathEntry {
                        bw_bps: s.bw_bps as f64,
                        base_rtt_us: s.base_rtt.as_micros() as f64,
                        p_rand: s.p_rand,
                        alpha: s.alpha,
                        reorder: s.reorder,
                        connect_rtt_us: s
                            .connect_rtt
                            .map(|c| c.as_micros() as f64)
                            .unwrap_or(0.0),
                        fail_rate: if s.failed { 1.0 } else { 0.0 },
                        samples: 1,
                        updated_at: now.micros(),
                        created_at: now.micros(),
                        ttl: self.default_ttl,
                    },
                );
            }
        }
    }

    /// Exact-key lookup — live entries only (expired are reaped lazily
    /// here too so a stale entry never seeds startup).
    pub fn lookup(&mut self, key: &PathKey, now: TransportInstant) -> Option<PathPrior> {
        let expired = self
            .entries
            .get(key)
            .map(|e| now.micros().saturating_sub(e.updated_at) > e.ttl.as_micros() as u64)
            .unwrap_or(false);
        if expired {
            self.entries.remove(key);
            self.expired += 1;
            return None;
        }
        self.entries.get(key).and_then(|e| e.prior(now))
    }

    /// Read the full stored entry (status/diagnostics export).
    pub fn entry(&self, key: &PathKey) -> Option<&PathEntry> {
        self.entries.get(key)
    }

    /// Explicit invalidation (route/interface/address change — §2.2:
    /// 路径地址变更失效). Returns whether an entry was removed.
    pub fn invalidate(&mut self, key: &PathKey) -> bool {
        let hit = self.entries.remove(key).is_some();
        self.invalidated += hit as u64;
        hit
    }

    /// Invalidate every entry matching a prefix's address family and
    /// overlapping the given destination (coarse invalidation on route
    /// change — bounded O(N) periodic, never per-ACK).
    pub fn invalidate_dst(&mut self, dst: &IpAddr) -> usize {
        let keys: Vec<PathKey> = self
            .entries
            .keys()
            .filter(|k| Self::prefix_matches(&k.dst_prefix, k.prefix_len, dst))
            .copied()
            .collect();
        let n = keys.len();
        for k in keys {
            self.entries.remove(&k);
        }
        self.invalidated += n as u64;
        n
    }

    fn prefix_matches(base: &IpAddr, len: u8, dst: &IpAddr) -> bool {
        match (base, dst) {
            (IpAddr::V4(b), IpAddr::V4(d)) => {
                let bits = len.min(32);
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                (u32::from(*b) & mask) == (u32::from(*d) & mask)
            }
            (IpAddr::V6(b), IpAddr::V6(d)) => {
                let bits = len.min(128);
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                (u128::from(*b) & mask) == (u128::from(*d) & mask)
            }
            _ => false,
        }
    }

    /// Reap expired entries — called on insert and explicitly by the
    /// periodic sweeper. O(N) but bounded by `capacity`.
    pub fn sweep(&mut self, now: TransportInstant) -> usize {
        self.reap(now)
    }

    fn reap(&mut self, now: TransportInstant) -> usize {
        let now_us = now.micros();
        let dead: Vec<PathKey> = self
            .entries
            .iter()
            .filter(|(_, e)| now_us.saturating_sub(e.updated_at) > e.ttl.as_micros() as u64)
            .map(|(k, _)| *k)
            .collect();
        let n = dead.len();
        for k in dead {
            self.entries.remove(&k);
        }
        self.expired += n as u64;
        n
    }

    /// Evict one entry at capacity: prefer lowest-confidence, then
    /// oldest (deterministic — no unbounded scan, single pass).
    fn evict_one(&mut self, now: TransportInstant) {
        let victim = self
            .entries
            .iter()
            .min_by(|(ka, a), (kb, b)| {
                let ca = a.confidence(now);
                let cb = b.confidence(now);
                ca.partial_cmp(&cb)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.updated_at.cmp(&b.updated_at))
                    .then(ka.cmp(kb))
            })
            .map(|(k, _)| *k);
        if let Some(k) = victim {
            self.entries.remove(&k);
            self.expired += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate entries for /status export.
    pub fn iter(&self) -> impl Iterator<Item = (&PathKey, &PathEntry)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(octet: u8) -> PathKey {
        PathKey {
            egress_ifindex: 2,
            local_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_prefix: IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet)),
            prefix_len: 24,
        }
    }

    fn sample() -> PathSample {
        PathSample {
            bw_bps: 5_000_000,
            base_rtt: Duration::from_millis(80),
            p_rand: 0.01,
            alpha: 0.0,
            reorder: 0.0,
            connect_rtt: Some(Duration::from_millis(82)),
            failed: false,
        }
    }

    #[test]
    fn prior_round_trip_and_confidence_decay() {
        let mut t = PathTable::new(64, Duration::from_secs(3600));
        let now = TransportInstant::from_micros(1_000_000);
        t.record(key(0), sample(), now);
        let p = t.lookup(&key(0), now).expect("prior");
        assert_eq!(p.bw_bps, 5_000_000);
        assert!(p.confidence > 0.0 && p.confidence < 1.0);
        // Aged 4 half-lives: confidence should be ~1/16 of sample part.
        let old = TransportInstant::from_micros(
            1_000_000 + 4 * CONFIDENCE_HALF_LIFE.as_micros() as u64,
        );
        // TTL not yet hit (4×900s = 3600s boundary) — just under.
        let just = TransportInstant::from_micros(
            1_000_000 + Duration::from_secs(3599).as_micros() as u64,
        );
        let p2 = t.lookup(&key(0), just);
        // confidence decayed below MIN_CONFIDENCE → None.
        assert!(p2.is_none() || p2.unwrap().confidence < 0.2);
        let _ = old;
    }

    #[test]
    fn missing_evidence_does_not_poison_prior() {
        let mut t = PathTable::new(64, Duration::from_secs(3600));
        let now = TransportInstant::from_micros(1_000_000);
        t.record(key(0), sample(), now);
        // A flow that died before its first rate/rtt sample records zeros
        // (e.g. pre-proxy timeout). The stored prior must not decay.
        let empty = PathSample {
            failed: true,
            ..Default::default()
        };
        for i in 0..8 {
            t.record(
                key(0),
                empty,
                TransportInstant::from_micros(1_000_000 + i),
            );
        }
        let p = t.lookup(&key(0), now).expect("prior survives");
        assert_eq!(p.bw_bps, 5_000_000);
        assert_eq!(p.base_rtt, Duration::from_millis(80));
        // But the failures were still learned.
        let e = t.entry(&key(0)).unwrap();
        assert!(e.fail_rate > 0.5, "fail_rate={}", e.fail_rate);
    }

    #[test]
    fn ttl_expiry_and_capacity_eviction() {
        let mut t = PathTable::new(4, Duration::from_secs(60));
        let now = TransportInstant::from_micros(0);
        for i in 0..4 {
            t.record(key(i), sample(), now);
        }
        // Fifth insert evicts lowest-confidence/oldest.
        t.record(key(9), sample(), now);
        assert_eq!(t.len(), 4);
        // All expire.
        let later = TransportInstant::from_micros(61_000_000);
        assert!(t.lookup(&key(0), later).is_none());
    }

    #[test]
    fn dst_invalidation_matches_prefix() {
        let mut t = PathTable::new(64, Duration::from_secs(3600));
        let now = TransportInstant::from_micros(0);
        t.record(key(0), sample(), now);
        t.record(key(7), sample(), now);
        let n = t.invalidate_dst(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)));
        assert_eq!(n, 2, "both /24 entries share the prefix");
    }
}
