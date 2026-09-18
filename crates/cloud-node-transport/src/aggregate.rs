//! Aggregate coordination (plan §2.6, RFC 3124 CM + RFC 8382 SBD).
//!
//! One [`Aggregate`] per candidate key
//! `(egress_iface, local_ip, af, dst_prefix, port_class)` — the keying
//! lives in the wiring layer; this module owns member bookkeeping,
//! shared-bottleneck merge/split with hysteresis (D-A2: 宁可误拆不可
//! 误并), single-prober arbitration, and tier-weighted inflight
//! allocation.
//!
//! Design contract:
//! - **Bounded**: `MAX_MEMBERS` cap, O(members) periodic scans only —
//!   never per-ACK pairwise scans, no global locks. Sharing is
//!   `Rc<RefCell>`: an aggregate never leaves its worker, so the
//!   per-ACK path touches a borrow-free slot — no mutex contention.
//! - **Pull model**: each [`EdgeCc`](crate::edgecc::EdgeCc) holds a
//!   [`MemberLease`] minted by [`Aggregate::join`]; the wiring layer
//!   calls [`Aggregate::on_period`] (≈ once per RTT / 10 ms) to
//!   recompute SBD verdicts and allocations. Per-ACK paths only touch
//!   the member's own slot.
//! - **D-A2 hysteresis**: merge requires `MERGE_CONFIRM` consecutive
//!   periods with correlation ≥ `MERGE_CORR`; a single period below
//!   `SPLIT_CORR` splits. Split is cheap, merge is expensive.
//! - **Probe arbitration**: exactly one permit per aggregate; a holder
//!   whose progress counter stalls for `PROBE_LEASE_TIMEOUT` periods
//!   forfeits the permit. The epoch bumps on every grant/revocation so
//!   a stale lease detects loss across a reload gap (F1: the session
//!   table and its aggregates survive adoption — epoch continuity is
//!   preserved, and a dead worker's permit is revoked by timeout,
//!   never held forever).
//! - **Reload**: `Aggregate` is `!Send` by `Rc` — it lives and dies
//!   with its worker's session table, exactly matching the F1 lease
//!   adoption contract (dataplane objects stay on their worker).

use crate::inference::SbdStats;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

/// Maximum members per aggregate (bounded periodic scans).
pub const MAX_MEMBERS: usize = 256;

/// SBD thresholds (D-A2): merge needs sustained strong correlation;
/// a single weak-correlation period splits.
const MERGE_CORR: f64 = 0.6;
const SPLIT_CORR: f64 = 0.35;
/// Consecutive correlated periods required before a candidate member
/// is merged into the shared-bottleneck set.
const MERGE_CONFIRM: u8 = 3;

/// Probe-permit inactivity timeout in periods.
const PROBE_LEASE_TIMEOUT: u32 = 40;

/// Minimum guaranteed inflight share for T0/T1 members (§2.6 最低保
/// 证) as a fraction of the aggregate allowance each.
const T0_FLOOR_FRAC: f64 = 0.25;
const T1_FLOOR_FRAC: f64 = 0.15;

/// Loss-time coincidence window (µs): two losses inside ±this window
/// count as coincident for the SBD correlation vote. Order-of-RTT
/// scale; the qdelay-delta term carries the continuous evidence.
const LOSS_COINCIDENCE_US: u64 = 5_000;

/// Per-member statistics pushed once per period — the RFC 8382
/// summary inputs (loss instants + qdelay-delta EWMA), plus the
/// allocation inputs (inflight, rate, tier) and probe signals.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemberStats {
    /// Recent loss-event instants (µs), newest first.
    pub loss_times_us: [u64; 8],
    /// EWMA of per-ACK qdelay deltas (µs).
    pub qdelay_delta: f64,
    /// EWMA of |qdelay delta| (µs) — correlation normalizer.
    pub qdelay_delta_abs: f64,
    /// Member's current inflight bytes.
    pub inflight: u64,
    /// Member's delivery rate (bytes/s).
    pub rate_bps: u64,
    /// Business tier (0=T0, 1=T1, 2=T2).
    pub tier: u8,
    /// Progress counter bumped every completed round — the probe-lease
    /// timeout signal.
    pub progress_ctr: u64,
    /// Member currently wants the probe permit.
    pub wants_probe: bool,
}

impl MemberStats {
    /// Copy the correlation fields out of a flow's `Inference::sbd`.
    pub fn with_sbd(mut self, sbd: &SbdStats) -> Self {
        self.loss_times_us = sbd.loss_times_us;
        self.qdelay_delta = sbd.qdelay_delta;
        self.qdelay_delta_abs = sbd.qdelay_delta_abs;
        self
    }
}

#[derive(Clone, Copy, Debug)]
struct Member {
    stats: MemberStats,
    /// Periods with correlation ≥ MERGE_CORR (merge hysteresis).
    merge_votes: u8,
    /// True once merged into the shared-bottleneck set.
    merged: bool,
    /// Holds the probe permit.
    probing: bool,
    /// Periods since `progress_ctr` last advanced while probing.
    probe_idle: u32,
    /// `progress_ctr` observed at the last period (stalled-prober test).
    probe_progress: u64,
    /// Cached inflight share cap from the last allocation pass.
    share_cap: u64,
}

/// Leave-one-out centroid inputs (merged members only).
#[derive(Clone, Copy, Debug, Default)]
struct Centroid {
    qdelay_delta: f64,
    qdelay_delta_abs: f64,
    last_loss_us: u64,
    members: u32,
}

/// One aggregate = one candidate key's member set + shared verdicts.
///
/// Share as `Rc<RefCell<Aggregate>>` among the flows of ONE worker;
/// `Aggregate::shared()` is the constructor for that pattern.
#[derive(Debug)]
pub struct Aggregate {
    members: BTreeMap<u64, Member>,
    next_id: u64,
    /// Node-level inflight allowance for the whole aggregate (§2.6
    /// 总额度); `u64::MAX` = unconstrained.
    allowance: u64,
    probe_holder: Option<u64>,
    /// Bumped on every permit grant/revocation (stale-lease detection).
    probe_epoch: u64,
    /// Last holder revoked for idleness — excluded from the next grant
    /// when other merged members also want the permit (fair rotation).
    last_revoked: Option<u64>,
    periods: u64,
    /// Audit: when each member merged (period index).
    merged_since: BTreeMap<u64, u64>,
}

impl Default for Aggregate {
    fn default() -> Self {
        Self::new()
    }
}

impl Aggregate {
    pub fn new() -> Self {
        Self {
            members: BTreeMap::new(),
            next_id: 0,
            allowance: u64::MAX,
            probe_holder: None,
            probe_epoch: 0,
            last_revoked: None,
            periods: 0,
            merged_since: BTreeMap::new(),
        }
    }

    /// Shared constructor — the session table keeps the `Rc`, flows get
    /// leases.
    pub fn shared() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new()))
    }

    /// Node-level allowance for this aggregate (§2.6 总额度).
    pub fn set_allowance(&mut self, bytes: u64) {
        self.allowance = bytes;
    }

    /// Register a member. `None` at capacity — the caller keeps the
    /// flow as a single-flow aggregate (unshared, NOT disabled).
    pub fn join(agg: &Rc<RefCell<Self>>) -> Option<MemberLease> {
        let mut a = agg.borrow_mut();
        if a.members.len() >= MAX_MEMBERS {
            return None;
        }
        let id = a.next_id;
        a.next_id += 1;
        a.members.insert(
            id,
            Member {
                stats: MemberStats::default(),
                merge_votes: 0,
                merged: false,
                probing: false,
                probe_idle: 0,
                probe_progress: 0,
                share_cap: u64::MAX,
            },
        );
        drop(a);
        Some(MemberLease {
            id,
            agg: Rc::clone(agg),
        })
    }

    /// Push a member's fresh stats — once per period, never per ACK.
    pub fn update_member(&mut self, id: u64, stats: MemberStats) {
        if let Some(m) = self.members.get_mut(&id) {
            m.stats = stats;
        }
    }

    /// Correlation of one member's stats against a centroid ∈ [0,1].
    /// O(1): same-sign qdelay-delta agreement (half) + loss-time
    /// coincidence (half).
    fn correlation(centroid: &Centroid, s: &MemberStats) -> Option<f64> {
        if centroid.members == 0 {
            return None;
        }
        let mag = (s.qdelay_delta_abs * centroid.qdelay_delta_abs).sqrt();
        if mag < 1e-9 {
            return Some(0.0);
        }
        let agree = ((s.qdelay_delta * centroid.qdelay_delta).max(0.0)) / mag;
        let coincident = s
            .loss_times_us
            .iter()
            .any(|&t| t > 0 && t.abs_diff(centroid.last_loss_us) <= LOSS_COINCIDENCE_US);
        Some(agree.min(1.0) * 0.5 + if coincident { 0.5 } else { 0.0 })
    }

    /// Centroid over merged members, optionally excluding one member
    /// (leave-one-out for self-correlation).
    fn compute_centroid(&self, exclude: Option<u64>) -> Centroid {
        let mut c = Centroid::default();
        for (&id, m) in &self.members {
            if !m.merged || Some(id) == exclude {
                continue;
            }
            c.qdelay_delta += m.stats.qdelay_delta;
            c.qdelay_delta_abs += m.stats.qdelay_delta_abs;
            c.last_loss_us = c
                .last_loss_us
                .max(m.stats.loss_times_us.iter().copied().max().unwrap_or(0));
            c.members += 1;
        }
        if c.members > 0 {
            c.qdelay_delta /= c.members as f64;
            c.qdelay_delta_abs /= c.members as f64;
        }
        c
    }

    /// Periodic pass (wiring cadence ≈ RTT / 10 ms): centroid, merge/
    /// split hysteresis, probe arbitration, tier-weighted allocation.
    pub fn on_period(&mut self) {
        self.periods += 1;

        // Merge/split hysteresis. Unmerged members correlate against the
        // merged centroid; merged members against their leave-one-out
        // centroid (a member must not validate itself).
        let ids: Vec<u64> = self.members.keys().copied().collect();
        for id in ids {
            let (merged, merge_votes, stats) = match self.members.get(&id) {
                Some(m) => (m.merged, m.merge_votes, m.stats),
                None => continue,
            };
            if merged {
                let c = self.compute_centroid(Some(id));
                if c.members > 0
                    && Self::correlation(&c, &stats).unwrap_or(0.0) < SPLIT_CORR
                {
                    if let Some(m) = self.members.get_mut(&id) {
                        m.merged = false;
                        m.merge_votes = 0;
                    }
                    self.merged_since.remove(&id);
                    if self.probe_holder == Some(id) {
                        self.probe_holder = None;
                        self.probe_epoch += 1;
                    }
                }
                continue;
            }
            let c = self.compute_centroid(None);
            let corr = if c.members == 0 {
                // Singleton aggregate: self-merge after residence —
                // one flow IS its own shared bottleneck.
                Some(1.0)
            } else {
                Self::correlation(&c, &stats)
            };
            let m = self.members.get_mut(&id).unwrap();
            match corr {
                Some(c) if c >= MERGE_CORR => {
                    m.merge_votes = merge_votes.saturating_add(1);
                    if m.merge_votes >= MERGE_CONFIRM {
                        m.merged = true;
                        self.merged_since.insert(id, self.periods);
                    }
                }
                Some(_) => m.merge_votes = merge_votes.saturating_sub(1),
                None => {}
            }
        }

        // Probe permit: the holder's progress counter must advance
        // between periods; a stalled (or absent/unmerged/unwilling)
        // holder forfeits. Revocation is counted here — not in
        // update_member — so a wedged worker that stops reporting is
        // still timed out.
        if let Some(h) = self.probe_holder {
            let (stalled, gone) = match self.members.get_mut(&h) {
                Some(m) if m.merged && m.stats.wants_probe => {
                    if m.stats.progress_ctr == m.probe_progress {
                        m.probe_idle = m.probe_idle.saturating_add(1);
                    } else {
                        m.probe_progress = m.stats.progress_ctr;
                        m.probe_idle = 0;
                    }
                    (m.probe_idle > PROBE_LEASE_TIMEOUT, false)
                }
                Some(_) => (true, false),
                None => (true, true),
            };
            let revoke = stalled || gone;
            if revoke {
                if let Some(m) = self.members.get_mut(&h) {
                    m.probing = false;
                }
                self.probe_holder = None;
                self.probe_epoch += 1;
                self.last_revoked = Some(h);
            }
        }
        if self.probe_holder.is_none() {
            // Prefer requesters that were not just revoked for idleness
            // (round-robin fairness); a lone requester gets it back.
            let skip = self.last_revoked;
            let find = |members: &BTreeMap<u64, Member>, skip: Option<u64>| {
                members
                    .iter()
                    .find(|(id, m)| {
                        Some(**id) != skip && m.merged && m.stats.wants_probe && !m.probing
                    })
                    .map(|(id, _)| *id)
            };
            let chosen = find(&self.members, skip).or_else(|| find(&self.members, None));
            if let Some(id) = chosen
                && let Some(m) = self.members.get_mut(&id)
            {
                m.probing = true;
                m.probe_idle = 0;
                self.probe_holder = Some(id);
                self.probe_epoch += 1;
            }
        }

        // Tier-weighted allocation of `allowance` over merged members.
        // T0/T1 floors first (bounded at half the pool), remainder by
        // weight — work-conserving: unclaimed headroom stays available
        // because the caps only bind when the allowance does.
        let merged: Vec<u64> = self
            .members
            .iter()
            .filter(|(_, m)| m.merged)
            .map(|(&id, _)| id)
            .collect();
        if self.allowance == u64::MAX {
            for m in self.members.values_mut() {
                m.share_cap = u64::MAX;
            }
            return;
        }
        let weight = |tier: u8| -> f64 {
            match tier {
                0 => 4.0,
                1 => 2.0,
                _ => 1.0,
            }
        };
        let floor_frac = |tier: u8| -> f64 {
            match tier {
                0 => T0_FLOOR_FRAC,
                1 => T1_FLOOR_FRAC,
                _ => 0.0,
            }
        };
        let floor_total_frac: f64 = merged
            .iter()
            .map(|id| floor_frac(self.members[id].stats.tier))
            .sum::<f64>()
            .min(0.5);
        let remainder = self.allowance.saturating_sub(
            (self.allowance as f64 * floor_total_frac) as u64,
        );
        let total_w: f64 = merged
            .iter()
            .map(|id| weight(self.members[id].stats.tier))
            .sum();
        for id in merged {
            let m = self.members.get_mut(&id).unwrap();
            let floor = (self.allowance as f64
                * floor_frac(m.stats.tier)
                * (floor_total_frac / floor_total_frac.max(f64::EPSILON)).min(1.0))
                as u64;
            let prop = (remainder as f64 * weight(m.stats.tier) / total_w.max(1e-9)) as u64;
            m.share_cap = floor.saturating_add(prop).max(1);
        }
    }

    /// Audit snapshot for /status.
    pub fn stats(&self) -> AggregateStats {
        AggregateStats {
            members: self.members.len() as u32,
            merged: self.members.values().filter(|m| m.merged).count() as u32,
            probe_holder: self.probe_holder,
            probe_epoch: self.probe_epoch,
            periods: self.periods,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AggregateStats {
    pub members: u32,
    pub merged: u32,
    pub probe_holder: Option<u64>,
    pub probe_epoch: u64,
    pub periods: u64,
}

/// [`crate::edgecc::AggregateLease`] minted by [`Aggregate::join`].
/// O(1) slot access; `!Send` with the aggregate (worker-local).
pub struct MemberLease {
    id: u64,
    agg: Rc<RefCell<Aggregate>>,
}

impl std::fmt::Debug for MemberLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberLease").field("id", &self.id).finish()
    }
}

impl crate::edgecc::AggregateLease for MemberLease {
    fn try_take_probe_permit(&mut self) -> bool {
        let mut a = self.agg.borrow_mut();
        if a.probe_holder == Some(self.id) {
            return true;
        }
        match a.members.get_mut(&self.id) {
            Some(m) => {
                if !m.stats.wants_probe {
                    m.stats.wants_probe = true;
                }
                m.probing
            }
            None => false,
        }
    }

    fn release_probe_permit(&mut self) {
        let mut a = self.agg.borrow_mut();
        if a.probe_holder == Some(self.id) {
            a.probe_holder = None;
            a.probe_epoch += 1;
        }
        if let Some(m) = a.members.get_mut(&self.id) {
            m.stats.wants_probe = false;
            m.probing = false;
        }
    }

    fn inflight_share_cap(&self) -> Option<u64> {
        let a = self.agg.borrow();
        a.members
            .get(&self.id)
            .and_then(|m| (m.merged && m.share_cap < u64::MAX).then_some(m.share_cap))
    }

    fn push_stats(&self, stats: crate::aggregate::MemberStats) {
        self.agg.borrow_mut().update_member(self.id, stats);
    }
}

impl Drop for MemberLease {
    fn drop(&mut self) {
        let mut a = self.agg.borrow_mut();
        if a.probe_holder == Some(self.id) {
            a.probe_holder = None;
            a.probe_epoch += 1;
        }
        a.merged_since.remove(&self.id);
        a.members.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(tier: u8, delta: f64, loss_us: u64) -> MemberStats {
        let mut s = MemberStats {
            tier,
            qdelay_delta: delta,
            qdelay_delta_abs: delta.abs().max(1.0),
            inflight: 64 * 1024,
            rate_bps: 1_000_000,
            ..MemberStats::default()
        };
        s.loss_times_us[0] = loss_us;
        s
    }

    #[test]
    fn merge_requires_sustained_correlation() {
        let agg = Aggregate::shared();
        let a = Aggregate::join(&agg).unwrap();
        let b = Aggregate::join(&agg).unwrap();
        agg.borrow_mut().update_member(a.id, stats(1, 100.0, 10_000));
        agg.borrow_mut().update_member(b.id, stats(1, 95.0, 10_500));
        agg.borrow_mut().on_period();
        assert_eq!(agg.borrow().stats().merged, 0);
        for _ in 0..MERGE_CONFIRM + 1 {
            agg.borrow_mut().update_member(a.id, stats(1, 100.0, 10_000));
            agg.borrow_mut().update_member(b.id, stats(1, 95.0, 10_500));
            agg.borrow_mut().on_period();
        }
        assert_eq!(agg.borrow().stats().merged, 2);
    }

    #[test]
    fn split_is_immediate_on_decorrelation() {
        let agg = Aggregate::shared();
        let a = Aggregate::join(&agg).unwrap();
        let b = Aggregate::join(&agg).unwrap();
        for _ in 0..MERGE_CONFIRM + 2 {
            agg.borrow_mut().update_member(a.id, stats(1, 100.0, 10_000));
            agg.borrow_mut().update_member(b.id, stats(1, 95.0, 10_500));
            agg.borrow_mut().on_period();
        }
        assert_eq!(agg.borrow().stats().merged, 2);
        agg.borrow_mut().update_member(b.id, stats(1, -500.0, 9_000_000));
        for _ in 0..4 {
            agg.borrow_mut().on_period();
        }
        assert!(agg.borrow().stats().merged < 2, "split failed: {:?}", agg.borrow().stats());
    }

    #[test]
    fn one_prober_at_a_time_and_timeout_revocation() {
        let agg = Aggregate::shared();
        let a = Aggregate::join(&agg).unwrap();
        let b = Aggregate::join(&agg).unwrap();
        for _ in 0..MERGE_CONFIRM + 2 {
            agg.borrow_mut().update_member(a.id, stats(1, 100.0, 10_000));
            agg.borrow_mut().update_member(b.id, stats(1, 100.0, 10_500));
            agg.borrow_mut().on_period();
        }
        assert_eq!(agg.borrow().stats().merged, 2);
        let mut sa = stats(1, 100.0, 10_000);
        sa.wants_probe = true;
        let mut sb = stats(1, 100.0, 10_500);
        sb.wants_probe = true;
        agg.borrow_mut().update_member(a.id, sa);
        agg.borrow_mut().update_member(b.id, sb);
        agg.borrow_mut().on_period();
        let holder = agg.borrow().probe_holder.unwrap();
        assert_eq!(holder, a.id.min(b.id));
        // Idle holder forfeits; permit re-granted to the other.
        for _ in 0..PROBE_LEASE_TIMEOUT + 2 {
            agg.borrow_mut().on_period();
        }
        assert_ne!(agg.borrow().probe_holder, Some(holder));
    }

    #[test]
    fn capacity_bound_rejects_extra_members() {
        let agg = Aggregate::shared();
        let mut kept = Vec::new();
        for _ in 0..MAX_MEMBERS {
            kept.push(Aggregate::join(&agg).unwrap());
        }
        assert!(Aggregate::join(&agg).is_none());
        drop(kept);
    }

    #[test]
    fn leave_releases_permit_and_slot() {
        let agg = Aggregate::shared();
        let a = Aggregate::join(&agg).unwrap();
        let id = a.id;
        for _ in 0..MERGE_CONFIRM + 1 {
            agg.borrow_mut().update_member(id, stats(1, 100.0, 10_000));
            agg.borrow_mut().on_period();
        }
        let mut s = stats(1, 100.0, 10_000);
        s.wants_probe = true;
        agg.borrow_mut().update_member(id, s);
        agg.borrow_mut().on_period();
        assert_eq!(agg.borrow().probe_holder, Some(id));
        drop(a);
        assert_eq!(agg.borrow().probe_holder, None);
        assert_eq!(agg.borrow().stats().members, 0);
    }
}
