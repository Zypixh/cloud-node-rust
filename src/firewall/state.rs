use crate::firewall::kernel::{KernelFilter, KernelFilterRange, KernelFilterSnapshot, NoopFilter};
use crate::firewall::persistence::FirewallBlockRecord;
use arc_swap::ArcSwap;
use dashmap::{DashMap, mapref::entry::Entry};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub struct CandidateRulesetStats {
    pub hits: AtomicU64,
    pub blocks: AtomicU64,
    pub observed: AtomicU64,
    pub last_seen: AtomicI64,
}

impl CandidateRulesetStats {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            observed: AtomicU64::new(0),
            last_seen: AtomicI64::new(crate::utils::time::now_timestamp()),
        }
    }

    fn touch(&self, now: i64) {
        self.last_seen.store(now, Ordering::Relaxed);
    }

    fn is_idle(&self, now: i64) -> bool {
        now.saturating_sub(self.last_seen.load(Ordering::Relaxed)) >= CANDIDATE_STATS_IDLE_SECS
    }
}

pub struct CandidateStatsSnapshot {
    pub policy_id: i64,
    pub version: i64,
    pub hits: u64,
    pub blocks: u64,
    pub observed: u64,
}

/// Closed IP range [from, to] stored as u128 for O(1) membership tests on both
/// IPv4 and IPv6.  `v6` distinguishes the address family so IPv4-mapped
/// addresses are compared correctly.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IpAddrRange {
    pub from: u128,
    pub to: u128,
    pub v6: bool,
}

fn canonical_lookup_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(v4);
    }
    ip
}

fn scope_label(server_id: i64) -> &'static str {
    if server_id == 0 { "global" } else { "server" }
}

fn rate_limit_key_ip(ip: IpAddr) -> IpAddr {
    let ip = canonical_lookup_ip(ip);
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
    }
}

fn parse_range_target(target: &str) -> Option<IpAddrRange> {
    let (from, to) = target.split_once('-')?;
    let from = canonical_lookup_ip(from.trim().parse().ok()?);
    let to = canonical_lookup_ip(to.trim().parse().ok()?);
    let (from_n, to_n, v6) = match (from, to) {
        (IpAddr::V4(f), IpAddr::V4(t)) => (
            u32::from_be_bytes(f.octets()) as u128,
            u32::from_be_bytes(t.octets()) as u128,
            false,
        ),
        (IpAddr::V6(f), IpAddr::V6(t)) => (
            u128::from_be_bytes(f.octets()),
            u128::from_be_bytes(t.octets()),
            true,
        ),
        _ => return None,
    };
    (from_n <= to_n).then_some(IpAddrRange {
        from: from_n,
        to: to_n,
        v6,
    })
}

impl IpAddrRange {
    pub fn contains(self, ip: IpAddr) -> bool {
        let canonical = match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 @ IpAddr::V4(_) => v4,
        };
        match (canonical, self.v6) {
            (IpAddr::V4(v4), false) => {
                let n = u32::from_be_bytes(v4.octets()) as u128;
                n >= self.from && n <= self.to
            }
            (IpAddr::V6(v6), true) => {
                let n = u128::from_be_bytes(v6.octets());
                n >= self.from && n <= self.to
            }
            _ => false,
        }
    }

    pub fn bounds(self) -> (IpAddr, IpAddr) {
        if self.v6 {
            (
                IpAddr::V6(std::net::Ipv6Addr::from(self.from)),
                IpAddr::V6(std::net::Ipv6Addr::from(self.to)),
            )
        } else {
            (
                IpAddr::V4(std::net::Ipv4Addr::from(self.from as u32)),
                IpAddr::V4(std::net::Ipv4Addr::from(self.to as u32)),
            )
        }
    }
}

const GC_INTERVAL_SECS: u64 = 60;
/// Idle threshold for rate-limiter GC. Set to 90 s (down from 300 s) to shrink
/// the window in which an adversary can exploit the "fresh bucket on re-entry"
/// semantic: at 90 s they must sustain near-legitimate request rates to keep
/// limiters alive, making periodic burst bypass impractical.
/// Acceptable trade-off: benign long-tail sessions see their per-IP limiter
/// reconstructed slightly more often, but quota enforcement is unaffected.
const LIMITER_IDLE_SECS: i64 = 90;
const LIMITER_SWEEP_INTERVAL_SECS: i64 = 30;
const STATE_CAPACITY_WARN_INTERVAL_SECS: i64 = 60;
static IP_LIMITER_CAPACITY_WARN_AT: AtomicI64 = AtomicI64::new(0);
static COUNTER_CAPACITY_WARN_AT: AtomicI64 = AtomicI64::new(0);
static IP_BW_CAPACITY_WARN_AT: AtomicI64 = AtomicI64::new(0);

/// Wraps a RateLimiter with a last-seen timestamp for GC and the QPS value the
/// quota was built from, so hot-reload can detect and replace stale limiters.
pub(crate) struct TrackedLimiter<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static> {
    pub limiter: Arc<RateLimiter<K, DashMapStateStore<K>, DefaultClock>>,
    pub last_seen: AtomicI64,
    /// The QPS value baked into `limiter`'s Quota at construction time.
    pub quota_value: AtomicU32,
}

impl<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static> TrackedLimiter<K> {
    fn new(
        limiter: Arc<RateLimiter<K, DashMapStateStore<K>, DefaultClock>>,
        quota_value: u32,
    ) -> Self {
        Self {
            limiter,
            last_seen: AtomicI64::new(crate::utils::time::now_timestamp()),
            quota_value: AtomicU32::new(quota_value),
        }
    }

    fn touch(&self) {
        self.last_seen
            .store(crate::utils::time::now_timestamp(), Ordering::Relaxed);
    }

    fn is_idle(&self, now: i64) -> bool {
        now.saturating_sub(self.last_seen.load(Ordering::Relaxed)) >= LIMITER_IDLE_SECS
    }
}

fn warn_state_capacity_full(
    last_warn: &AtomicI64,
    area: &str,
    len: usize,
    capacity: usize,
    behavior: &str,
) {
    let now = crate::utils::time::now_timestamp();
    let last = last_warn.load(Ordering::Relaxed);
    if now.saturating_sub(last) < STATE_CAPACITY_WARN_INTERVAL_SECS {
        return;
    }
    if last_warn
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tracing::warn!(
            "WAF state capacity full for {}; len={} capacity={}, {}",
            area,
            len,
            capacity,
            behavior
        );
    }
}

const ROLLING_COUNTER_BUCKETS: usize = 256;
const COUNTER_SWEEP_INTERVAL_SECS: i64 = 60;
const COUNTER_MAX_PERIOD_SECS: i64 = 7 * 86_400;
const CANDIDATE_STATS_IDLE_SECS: i64 = 6 * 3600;

type NetworkSnapshot = HashMap<i64, Arc<NetworkScopeSnapshot>>;
type RangeSnapshot = HashMap<i64, Arc<Vec<(IpAddrRange, i64)>>>;

#[derive(Clone, Debug, Default)]
struct NetworkScopeSnapshot {
    all: Vec<(IpNet, i64)>,
    v4_by_octet: HashMap<u8, Vec<(IpNet, i64)>>,
    v6_by_hextet: HashMap<u16, Vec<(IpNet, i64)>>,
}

impl NetworkScopeSnapshot {
    fn from_items(items: Vec<(IpNet, i64)>) -> Self {
        let mut snapshot = Self::default();
        for item in items {
            snapshot.push(item);
        }
        snapshot
    }

    fn push(&mut self, item: (IpNet, i64)) {
        match item.0 {
            IpNet::V4(net) if net.prefix_len() >= 8 => {
                let bucket = net.network().octets()[0];
                self.v4_by_octet.entry(bucket).or_default().push(item);
            }
            IpNet::V6(net) if net.prefix_len() >= 16 => {
                let segments = net.network().segments();
                self.v6_by_hextet.entry(segments[0]).or_default().push(item);
            }
            _ => self.all.push(item),
        }
    }

    fn overlaps(&self, net: IpNet, now: i64) -> bool {
        self.all
            .iter()
            .chain(self.v4_by_octet.values().flat_map(|items| items.iter()))
            .chain(self.v6_by_hextet.values().flat_map(|items| items.iter()))
            .any(|(candidate, expiry)| now < *expiry && networks_overlap(*candidate, net))
    }

    fn contains(&self, ip: IpAddr, now: i64) -> bool {
        if networks_contain(&self.all, ip, now) {
            return true;
        }
        match ip {
            IpAddr::V4(v4) => self
                .v4_by_octet
                .get(&v4.octets()[0])
                .is_some_and(|items| networks_contain(items, ip, now)),
            IpAddr::V6(v6) => self
                .v6_by_hextet
                .get(&v6.segments()[0])
                .is_some_and(|items| networks_contain(items, ip, now)),
        }
    }
}

fn networks_overlap(a: IpNet, b: IpNet) -> bool {
    match (a, b) {
        (IpNet::V4(a), IpNet::V4(b)) => a.contains(&b.network()) || b.contains(&a.network()),
        (IpNet::V6(a), IpNet::V6(b)) => a.contains(&b.network()) || b.contains(&a.network()),
        _ => false,
    }
}

fn range_overlaps_network(range: IpAddrRange, net: IpNet) -> bool {
    let (from, to) = range.bounds();
    match (from, to, net) {
        (IpAddr::V4(from), IpAddr::V4(to), IpNet::V4(net)) => {
            let net_from = u32::from_be_bytes(net.network().octets()) as u128;
            let net_to = u32::from_be_bytes(net.broadcast().octets()) as u128;
            net.contains(&from) || net.contains(&to) || (range.from <= net_to && range.to >= net_from)
        }
        (IpAddr::V6(from), IpAddr::V6(to), IpNet::V6(net)) => {
            let net_from = u128::from_be_bytes(net.network().octets());
            let net_to = u128::from_be_bytes(net.broadcast().octets());
            net.contains(&from) || net.contains(&to) || (range.from <= net_to && range.to >= net_from)
        }
        _ => false,
    }
}

fn networks_contain(items: &[(IpNet, i64)], ip: IpAddr, now: i64) -> bool {
    items
        .iter()
        .any(|(net, expiry)| now < *expiry && net.contains(&ip))
}

pub(crate) struct RollingCounter {
    buckets: [u64; ROLLING_COUNTER_BUCKETS],
    bucket_secs: i64,
    active_slots: usize,
    current_bucket: i64,
    current_slot: usize,
    total: u64,
    last_seen: i64,
}

impl Default for RollingCounter {
    fn default() -> Self {
        Self {
            buckets: [0; ROLLING_COUNTER_BUCKETS],
            bucket_secs: 1,
            active_slots: 1,
            current_bucket: 0,
            current_slot: 0,
            total: 0,
            last_seen: 0,
        }
    }
}

impl RollingCounter {
    pub(crate) fn increment(&mut self, now: i64, period_secs: i64) -> u64 {
        self.increment_by(now, period_secs, 1)
    }

    pub(crate) fn increment_by(&mut self, now: i64, period_secs: i64, amount: u64) -> u64 {
        let period_secs = period_secs.clamp(1, COUNTER_MAX_PERIOD_SECS);
        let (bucket_secs, active_slots) = Self::shape(period_secs);
        let now_bucket = now.div_euclid(bucket_secs);

        if self.current_bucket == 0
            || now_bucket < self.current_bucket
            || self.bucket_secs != bucket_secs
            || self.active_slots != active_slots
        {
            self.reset(now_bucket, bucket_secs, active_slots);
        } else {
            self.advance(now_bucket);
        }

        let amount = amount.max(1);
        self.buckets[self.current_slot] = self.buckets[self.current_slot].saturating_add(amount);
        self.total = self.total.saturating_add(amount);
        self.last_seen = now;
        self.total
    }

    pub(crate) fn is_stale(&self, now: i64, max_period_secs: i64) -> bool {
        self.last_seen <= now.saturating_sub(max_period_secs.max(1))
    }

    fn shape(period_secs: i64) -> (i64, usize) {
        let bucket_count = ROLLING_COUNTER_BUCKETS as i64;
        let bucket_secs = ((period_secs + bucket_count - 1) / bucket_count).max(1);
        let active_slots =
            ((period_secs + bucket_secs - 1) / bucket_secs).clamp(1, bucket_count) as usize;
        (bucket_secs, active_slots)
    }

    fn reset(&mut self, now_bucket: i64, bucket_secs: i64, active_slots: usize) {
        self.buckets[..active_slots].fill(0);
        self.bucket_secs = bucket_secs;
        self.active_slots = active_slots;
        self.current_bucket = now_bucket;
        self.current_slot = 0;
        self.total = 0;
    }

    fn advance(&mut self, now_bucket: i64) {
        let delta = now_bucket.saturating_sub(self.current_bucket) as usize;
        if delta == 0 {
            return;
        }

        if delta >= self.active_slots {
            self.buckets[..self.active_slots].fill(0);
            self.total = 0;
        } else {
            for _ in 0..delta {
                self.current_slot = (self.current_slot + 1) % self.active_slots;
                self.total = self.total.saturating_sub(self.buckets[self.current_slot]);
                self.buckets[self.current_slot] = 0;
            }
        }
        self.current_bucket = now_bucket;
    }
}

pub struct WafStateManager {
    pub blocks: DashMap<(i64, IpAddr), i64>,
    kernel_blocks: DashMap<(i64, IpAddr), i64>,
    pub block_networks: DashMap<(i64, IpNet), i64>,
    kernel_block_networks: DashMap<(i64, IpNet), i64>,
    block_network_snapshots: ArcSwap<NetworkSnapshot>,
    list_blocks: DashMap<(i64, IpAddr), i64>,
    list_block_networks: DashMap<(i64, IpNet), i64>,
    list_block_network_snapshots: ArcSwap<NetworkSnapshot>,
    pub whitelists: DashMap<(i64, IpAddr), i64>,
    whitelist_networks: DashMap<(i64, IpNet), i64>,
    whitelist_network_snapshots: ArcSwap<NetworkSnapshot>,
    list_whitelists: DashMap<(i64, IpAddr), i64>,
    list_whitelist_networks: DashMap<(i64, IpNet), i64>,
    list_whitelist_network_snapshots: ArcSwap<NetworkSnapshot>,
    graylists: DashMap<(i64, IpAddr), i64>,
    gray_networks: DashMap<(i64, IpNet), i64>,
    gray_network_snapshots: ArcSwap<NetworkSnapshot>,
    list_graylists: DashMap<(i64, IpAddr), i64>,
    list_gray_networks: DashMap<(i64, IpNet), i64>,
    list_gray_network_snapshots: ArcSwap<NetworkSnapshot>,
    server_limiters: DashMap<i64, TrackedLimiter<i64>>,
    ip_limiters: DashMap<(i64, IpAddr), TrackedLimiter<IpAddr>>,
    limiter_last_sweep: AtomicI64,
    ip_limiter_reservations: AtomicU64,
    counters: DashMap<String, RollingCounter>,
    counter_reservations: AtomicU64,
    counter_last_sweep: AtomicI64,
    list_block_ranges: DashMap<(i64, IpAddrRange), i64>,
    list_block_range_snapshots: ArcSwap<RangeSnapshot>,
    list_white_ranges: DashMap<(i64, IpAddrRange), i64>,
    list_white_range_snapshots: ArcSwap<RangeSnapshot>,
    list_gray_ranges: DashMap<(i64, IpAddrRange), i64>,
    list_gray_range_snapshots: ArcSwap<RangeSnapshot>,
    ip_bw_counters: DashMap<(i64, IpAddr), Arc<RwLock<(u64, u64)>>>,
    ip_bw_counter_reservations: AtomicU64,
    kernel_filter: RwLock<Arc<dyn KernelFilter>>,
    candidate_stats: DashMap<(i64, i64), Arc<CandidateRulesetStats>>,
    candidate_stats_reservations: AtomicU64,
}

impl Default for WafStateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WafStateManager {
    pub fn new() -> Self {
        Self {
            blocks: DashMap::new(),
            kernel_blocks: DashMap::new(),
            block_networks: DashMap::new(),
            kernel_block_networks: DashMap::new(),
            block_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            list_blocks: DashMap::new(),
            list_block_networks: DashMap::new(),
            list_block_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            whitelists: DashMap::new(),
            whitelist_networks: DashMap::new(),
            whitelist_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            list_whitelists: DashMap::new(),
            list_whitelist_networks: DashMap::new(),
            list_whitelist_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            graylists: DashMap::new(),
            gray_networks: DashMap::new(),
            gray_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            list_graylists: DashMap::new(),
            list_gray_networks: DashMap::new(),
            list_gray_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            server_limiters: DashMap::new(),
            ip_limiters: DashMap::new(),
            limiter_last_sweep: AtomicI64::new(0),
            ip_limiter_reservations: AtomicU64::new(0),
            counters: DashMap::new(),
            counter_reservations: AtomicU64::new(0),
            counter_last_sweep: AtomicI64::new(0),
            list_block_ranges: DashMap::new(),
            list_block_range_snapshots: ArcSwap::from_pointee(HashMap::new()),
            list_white_ranges: DashMap::new(),
            list_white_range_snapshots: ArcSwap::from_pointee(HashMap::new()),
            list_gray_ranges: DashMap::new(),
            list_gray_range_snapshots: ArcSwap::from_pointee(HashMap::new()),
            ip_bw_counters: DashMap::with_shard_amount(64),
            ip_bw_counter_reservations: AtomicU64::new(0),
            kernel_filter: RwLock::new(Arc::new(NoopFilter)),
            candidate_stats: DashMap::new(),
            candidate_stats_reservations: AtomicU64::new(0),
        }
    }

    pub fn set_kernel_filter(&self, filter: Box<dyn KernelFilter>) {
        if let Ok(mut guard) = self.kernel_filter.write() {
            *guard = Arc::from(filter);
        }
        self.publish_kernel_filter_snapshot();
    }

    pub fn install_kernel_snapshot_provider(self: &Arc<Self>) {
        let owner = Arc::clone(self);
        crate::firewall::kernel::set_kernel_snapshot_provider(Some(Arc::new(move || {
            owner.kernel_filter_snapshot()
        })));
    }

    fn kernel_filter(&self) -> Arc<dyn KernelFilter> {
        self.kernel_filter
            .read()
            .map(|guard| Arc::clone(&guard))
            .unwrap_or_else(|_| Arc::new(NoopFilter))
    }

    pub fn kernel_filter_status(&self) -> crate::firewall::kernel::KernelFilterStatus {
        self.kernel_filter().status()
    }

    pub fn publish_kernel_filter_snapshot(&self) {
        let filter = self.kernel_filter();
        if !filter.available() {
            return;
        }
        let snapshot = self.kernel_filter_snapshot();
        filter.sync_snapshot(&snapshot);
    }

    fn kernel_filter_snapshot(&self) -> KernelFilterSnapshot {
        let now = crate::utils::time::now_timestamp();
        KernelFilterSnapshot {
            blocked_ips: Self::snapshot_global_ips(&self.kernel_blocks, now)
                .into_iter()
                .chain(Self::snapshot_global_ips(&self.list_blocks, now))
                .collect(),
            allowed_ips: Self::snapshot_global_ips(&self.whitelists, now)
                .into_iter()
                .chain(Self::snapshot_global_ips(&self.list_whitelists, now))
                .collect(),
            blocked_networks: Self::snapshot_global_networks(&self.kernel_block_networks, now)
                .into_iter()
                .chain(Self::snapshot_global_networks(&self.list_block_networks, now))
                .collect(),
            allowed_networks: Self::snapshot_global_networks(&self.whitelist_networks, now)
                .into_iter()
                .chain(Self::snapshot_global_networks(
                    &self.list_whitelist_networks,
                    now,
                ))
                .collect(),
            blocked_ranges: Self::snapshot_global_ranges(&self.list_block_ranges, now),
            allowed_ranges: Self::snapshot_global_ranges(&self.list_white_ranges, now),
        }
    }

    fn snapshot_global_ips(map: &DashMap<(i64, IpAddr), i64>, now: i64) -> Vec<(IpAddr, i64)> {
        map.iter()
            .filter_map(|entry| {
                let expiry = *entry.value();
                (entry.key().0 == 0 && expiry > now).then_some((entry.key().1, expiry))
            })
            .collect()
    }

    fn snapshot_global_networks(
        map: &DashMap<(i64, IpNet), i64>,
        now: i64,
    ) -> Vec<(IpNet, i64)> {
        map.iter()
            .filter_map(|entry| {
                let expiry = *entry.value();
                (entry.key().0 == 0 && expiry > now).then_some((entry.key().1, expiry))
            })
            .collect()
    }

    fn snapshot_global_ranges(
        map: &DashMap<(i64, IpAddrRange), i64>,
        now: i64,
    ) -> Vec<KernelFilterRange> {
        map.iter()
            .filter_map(|entry| {
                let expiry = *entry.value();
                let range = entry.key().1;
                (entry.key().0 == 0 && expiry > now).then_some(KernelFilterRange {
                    from: range.from,
                    to: range.to,
                    v6: range.v6,
                    expires_at: expiry,
                })
            })
            .collect()
    }

    fn max_global_ip_expiry(
        map: &DashMap<(i64, IpAddr), i64>,
        ip: IpAddr,
        now: i64,
    ) -> Option<i64> {
        map.iter()
            .filter_map(|entry| {
                let expiry = *entry.value();
                (entry.key().0 == 0 && entry.key().1 == ip && expiry > now).then_some(expiry)
            })
            .max()
    }

    fn max_global_network_expiry(
        map: &DashMap<(i64, IpNet), i64>,
        net: IpNet,
        now: i64,
    ) -> Option<i64> {
        map.iter()
            .filter_map(|entry| {
                let expiry = *entry.value();
                (entry.key().0 == 0 && entry.key().1 == net && expiry > now).then_some(expiry)
            })
            .max()
    }

    fn reconcile_kernel_ip(&self, ip: IpAddr) {
        let filter = self.kernel_filter();
        if !filter.available() {
            return;
        }
        let now = crate::utils::time::now_timestamp();
        let whitelist_expiry = Self::max_global_ip_expiry(&self.whitelists, ip, now)
            .max(Self::max_global_ip_expiry(&self.list_whitelists, ip, now));
        if let Some(expiry) = whitelist_expiry {
            filter.allow(ip, expiry.saturating_sub(now));
            return;
        }
        filter.unallow(ip);
        let expiry = Self::max_global_ip_expiry(&self.kernel_blocks, ip, now)
            .max(Self::max_global_ip_expiry(&self.list_blocks, ip, now));
        match expiry {
            Some(expiry) => filter.block(ip, expiry.saturating_sub(now)),
            None => filter.unblock(ip),
        }
    }

    fn reconcile_kernel_network(&self, net: IpNet) {
        let filter = self.kernel_filter();
        if !filter.available() {
            return;
        }
        let now = crate::utils::time::now_timestamp();
        let whitelist_expiry = Self::max_global_network_expiry(&self.whitelist_networks, net, now)
            .max(Self::max_global_network_expiry(
                &self.list_whitelist_networks,
                net,
                now,
            ));
        if let Some(expiry) = whitelist_expiry {
            filter.allow_network(net, expiry.saturating_sub(now));
            return;
        }
        filter.unallow_network(net);
        let expiry = Self::max_global_network_expiry(&self.kernel_block_networks, net, now)
            .max(Self::max_global_network_expiry(
                &self.list_block_networks,
                net,
                now,
            ));
        match expiry {
            Some(expiry) => filter.block_network(net, expiry.saturating_sub(now)),
            None => filter.unblock_network(net),
        }
    }

    pub fn has_rules(&self) -> bool {
        !self.blocks.is_empty()
            || !self.block_networks.is_empty()
            || !self.list_blocks.is_empty()
            || !self.list_block_networks.is_empty()
            || !self.list_block_ranges.is_empty()
            || !self.whitelists.is_empty()
            || !self.whitelist_networks.is_empty()
            || !self.list_whitelists.is_empty()
            || !self.list_whitelist_networks.is_empty()
            || !self.list_white_ranges.is_empty()
            || !self.graylists.is_empty()
            || !self.gray_networks.is_empty()
            || !self.list_graylists.is_empty()
            || !self.list_gray_networks.is_empty()
            || !self.list_gray_ranges.is_empty()
    }

    pub fn is_whitelisted(&self, ip: IpAddr, server_id: i64) -> bool {
        let ip = canonical_lookup_ip(ip);
        let now = crate::utils::time::now_timestamp();
        Self::contains_scoped_ip(&self.whitelists, ip, server_id, now)
            || Self::contains_scoped_ip(&self.list_whitelists, ip, server_id, now)
            || Self::contains_scoped_network(&self.whitelist_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_network(
                &self.list_whitelist_network_snapshots,
                ip,
                server_id,
                now,
            )
            || Self::contains_scoped_range(&self.list_white_range_snapshots, ip, server_id, now)
    }

    pub fn is_whitelisted_any_scope(&self, ip: IpAddr) -> bool {
        let ip = canonical_lookup_ip(ip);
        let now = crate::utils::time::now_timestamp();
        Self::contains_any_scoped_ip(&self.whitelists, ip, now)
            || Self::contains_any_scoped_ip(&self.list_whitelists, ip, now)
            || Self::contains_any_scoped_network(&self.whitelist_network_snapshots, ip, now)
            || Self::contains_any_scoped_network(&self.list_whitelist_network_snapshots, ip, now)
            || Self::contains_any_scoped_range(&self.list_white_range_snapshots, ip, now)
    }

    pub fn has_whitelist_overlapping_network(&self, net: IpNet, server_id: i64) -> bool {
        let now = crate::utils::time::now_timestamp();
        Self::scoped_network_snapshot_overlaps(
            &self.whitelist_network_snapshots,
            net,
            server_id,
            now,
        ) || Self::scoped_network_snapshot_overlaps(
            &self.list_whitelist_network_snapshots,
            net,
            server_id,
            now,
        ) || Self::scoped_range_snapshot_overlaps(
            &self.list_white_range_snapshots,
            net,
            server_id,
            now,
        ) || self.whitelist_ip_overlaps_network(&self.whitelists, net, server_id, now)
            || self.whitelist_ip_overlaps_network(&self.list_whitelists, net, server_id, now)
    }

    fn whitelist_ip_overlaps_network(
        &self,
        map: &DashMap<(i64, IpAddr), i64>,
        net: IpNet,
        server_id: i64,
        now: i64,
    ) -> bool {
        map.iter().any(|entry| {
            let (scope, ip) = *entry.key();
            now < *entry.value() && (scope == 0 || scope == server_id) && net.contains(&ip)
        })
    }

    fn scoped_range_snapshot_overlaps(
        snapshots: &ArcSwap<RangeSnapshot>,
        net: IpNet,
        server_id: i64,
        now: i64,
    ) -> bool {
        let snapshot = snapshots.load();
        Self::ranges_overlap_network(snapshot.get(&0), net, now)
            || (server_id != 0
                && Self::ranges_overlap_network(snapshot.get(&server_id), net, now))
    }

    fn ranges_overlap_network(
        ranges: Option<&Arc<Vec<(IpAddrRange, i64)>>>,
        net: IpNet,
        now: i64,
    ) -> bool {
        ranges.is_some_and(|ranges| {
            ranges
                .iter()
                .any(|(range, expiry)| now < *expiry && range_overlaps_network(*range, net))
        })
    }

    fn scoped_network_snapshot_overlaps(
        snapshots: &ArcSwap<NetworkSnapshot>,
        net: IpNet,
        server_id: i64,
        now: i64,
    ) -> bool {
        snapshots
            .load()
            .get(&0)
            .is_some_and(|snapshot| snapshot.overlaps(net, now))
            || (server_id != 0
                && snapshots
                    .load()
                    .get(&server_id)
                    .is_some_and(|snapshot| snapshot.overlaps(net, now)))
    }

    pub fn is_blocked(&self, ip: IpAddr, server_id: i64) -> bool {
        let ip = canonical_lookup_ip(ip);
        let now = crate::utils::time::now_timestamp();
        Self::contains_scoped_ip(&self.blocks, ip, server_id, now)
            || Self::contains_scoped_ip(&self.list_blocks, ip, server_id, now)
            || Self::contains_scoped_network(&self.block_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_network(&self.list_block_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_range(&self.list_block_range_snapshots, ip, server_id, now)
    }

    pub fn is_blocked_any_scope(&self, ip: IpAddr) -> bool {
        let ip = canonical_lookup_ip(ip);
        let now = crate::utils::time::now_timestamp();
        Self::contains_any_scoped_ip(&self.blocks, ip, now)
            || Self::contains_any_scoped_ip(&self.list_blocks, ip, now)
            || Self::contains_any_scoped_network(&self.block_network_snapshots, ip, now)
            || Self::contains_any_scoped_network(&self.list_block_network_snapshots, ip, now)
            || Self::contains_any_scoped_range(&self.list_block_range_snapshots, ip, now)
    }

    pub fn is_graylisted(&self, ip: IpAddr, server_id: i64) -> bool {
        let ip = canonical_lookup_ip(ip);
        let now = crate::utils::time::now_timestamp();
        Self::contains_scoped_ip(&self.graylists, ip, server_id, now)
            || Self::contains_scoped_ip(&self.list_graylists, ip, server_id, now)
            || Self::contains_scoped_network(&self.gray_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_network(&self.list_gray_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_range(&self.list_gray_range_snapshots, ip, server_id, now)
    }

    pub fn apply_black_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        let ip = canonical_lookup_ip(ip);
        Self::apply_scoped_ip(&self.blocks, server_id, ip, expiry);
        Self::apply_scoped_ip(&self.kernel_blocks, server_id, ip, expiry);
        self.reconcile_kernel_ip(ip);
    }

    pub fn apply_black_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.block_networks,
            &self.block_network_snapshots,
            server_id,
            net,
            expiry,
        );
        Self::apply_scoped_network_map(&self.kernel_block_networks, server_id, net, expiry);
        self.reconcile_kernel_network(net);
    }

    pub fn remove_black_ip(&self, server_id: i64, ip: IpAddr) {
        let ip = canonical_lookup_ip(ip);
        Self::remove_scoped_ip(&self.blocks, server_id, ip);
        Self::remove_scoped_ip(&self.kernel_blocks, server_id, ip);
        crate::firewall::persistence::enqueue_delete(
            scope_label(server_id),
            server_id,
            &ip.to_string(),
        );
        self.reconcile_kernel_ip(ip);
    }

    pub fn remove_black_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.block_networks,
            &self.block_network_snapshots,
            server_id,
            net,
        );
        Self::remove_scoped_network_map(&self.kernel_block_networks, server_id, net);
        crate::firewall::persistence::enqueue_delete(
            scope_label(server_id),
            server_id,
            &net.to_string(),
        );
        self.reconcile_kernel_network(net);
    }

    pub fn apply_list_black_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        let ip = canonical_lookup_ip(ip);
        Self::apply_scoped_ip(&self.list_blocks, server_id, ip, expiry);
        self.reconcile_kernel_ip(ip);
    }

    pub fn apply_list_black_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.list_block_networks,
            &self.list_block_network_snapshots,
            server_id,
            net,
            expiry,
        );
        self.reconcile_kernel_network(net);
    }

    pub fn remove_list_black_ip(&self, server_id: i64, ip: IpAddr) {
        let ip = canonical_lookup_ip(ip);
        Self::remove_scoped_ip(&self.list_blocks, server_id, ip);
        self.reconcile_kernel_ip(ip);
    }

    pub fn remove_list_black_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.list_block_networks,
            &self.list_block_network_snapshots,
            server_id,
            net,
        );
        self.reconcile_kernel_network(net);
    }

    pub fn apply_white_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        let ip = canonical_lookup_ip(ip);
        Self::apply_scoped_ip(&self.whitelists, server_id, ip, expiry);
        self.reconcile_kernel_ip(ip);
    }

    pub fn apply_white_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.whitelist_networks,
            &self.whitelist_network_snapshots,
            server_id,
            net,
            expiry,
        );
        self.reconcile_kernel_network(net);
    }

    pub fn remove_white_ip(&self, server_id: i64, ip: IpAddr) {
        let ip = canonical_lookup_ip(ip);
        Self::remove_scoped_ip(&self.whitelists, server_id, ip);
        self.reconcile_kernel_ip(ip);
    }

    pub fn remove_white_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.whitelist_networks,
            &self.whitelist_network_snapshots,
            server_id,
            net,
        );
        self.reconcile_kernel_network(net);
    }

    pub fn apply_list_white_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        Self::apply_scoped_ip(&self.list_whitelists, server_id, ip, expiry);
        self.reconcile_kernel_ip(ip);
    }

    pub fn apply_list_white_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.list_whitelist_networks,
            &self.list_whitelist_network_snapshots,
            server_id,
            net,
            expiry,
        );
        self.reconcile_kernel_network(net);
    }

    pub fn remove_list_white_ip(&self, server_id: i64, ip: IpAddr) {
        let ip = canonical_lookup_ip(ip);
        Self::remove_scoped_ip(&self.list_whitelists, server_id, ip);
        self.reconcile_kernel_ip(ip);
    }

    pub fn remove_list_white_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.list_whitelist_networks,
            &self.list_whitelist_network_snapshots,
            server_id,
            net,
        );
        self.reconcile_kernel_network(net);
    }

    pub fn apply_gray_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        Self::apply_scoped_ip(&self.graylists, server_id, ip, expiry);
    }

    pub fn apply_gray_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.gray_networks,
            &self.gray_network_snapshots,
            server_id,
            net,
            expiry,
        );
    }

    pub fn remove_gray_ip(&self, server_id: i64, ip: IpAddr) {
        Self::remove_scoped_ip(&self.graylists, server_id, ip);
    }

    pub fn remove_gray_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.gray_networks,
            &self.gray_network_snapshots,
            server_id,
            net,
        );
    }

    pub fn apply_list_gray_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        Self::apply_scoped_ip(&self.list_graylists, server_id, ip, expiry);
    }

    pub fn apply_list_gray_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.list_gray_networks,
            &self.list_gray_network_snapshots,
            server_id,
            net,
            expiry,
        );
    }

    pub fn remove_list_gray_ip(&self, server_id: i64, ip: IpAddr) {
        Self::remove_scoped_ip(&self.list_graylists, server_id, ip);
    }

    pub fn remove_list_gray_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.list_gray_networks,
            &self.list_gray_network_snapshots,
            server_id,
            net,
        );
    }

    pub fn block_network(
        &self,
        net: IpNet,
        server_id: i64,
        timeout_secs: i64,
        scope: Option<&str>,
        use_local_firewall: bool,
    ) {
        let expiry = crate::utils::time::now_timestamp() + timeout_secs;
        let key_server_id = if matches!(scope, Some("global")) {
            0
        } else {
            server_id
        };
        let kernel_filter = self.kernel_filter();
        let kernel_filter_available = kernel_filter.available();
        Self::insert_scoped_network(
            &self.block_networks,
            &self.block_network_snapshots,
            key_server_id,
            net,
            expiry,
        );
        crate::firewall::persistence::enqueue_upsert(FirewallBlockRecord::runtime(
            net.to_string(),
            key_server_id,
            scope_label(key_server_id).to_string(),
            expiry,
            use_local_firewall,
        ));
        if use_local_firewall {
            Self::apply_scoped_network_map(
                &self.kernel_block_networks,
                key_server_id,
                net,
                expiry,
            );
        } else {
            Self::remove_scoped_network_map(&self.kernel_block_networks, key_server_id, net);
        }
        if use_local_firewall && !kernel_filter_available {
            self.exec_local_firewall(net.to_string(), timeout_secs);
        }
        if kernel_filter_available {
            self.reconcile_kernel_network(net);
        }
    }

    pub fn block_ip(
        &self,
        ip: IpAddr,
        server_id: i64,
        timeout_secs: i64,
        scope: Option<&str>,
        block_c_class: bool,
        use_local_firewall: bool,
    ) {
        let ip = canonical_lookup_ip(ip);
        let expiry = crate::utils::time::now_timestamp() + timeout_secs;
        let key_server_id = if matches!(scope, Some("global")) {
            0
        } else {
            server_id
        };
        let kernel_filter = self.kernel_filter();
        let kernel_filter_available = kernel_filter.available();

        if block_c_class {
            if let Ok(net) = self.get_c_class_net(ip) {
                Self::insert_scoped_network(
                    &self.block_networks,
                    &self.block_network_snapshots,
                    key_server_id,
                    net,
                    expiry,
                );
                crate::firewall::persistence::enqueue_upsert(FirewallBlockRecord::runtime(
                    net.to_string(),
                    key_server_id,
                    scope_label(key_server_id).to_string(),
                    expiry,
                    use_local_firewall,
                ));
                if use_local_firewall {
                    Self::apply_scoped_network_map(
                        &self.kernel_block_networks,
                        key_server_id,
                        net,
                        expiry,
                    );
                } else {
                    Self::remove_scoped_network_map(
                        &self.kernel_block_networks,
                        key_server_id,
                        net,
                    );
                }
                if use_local_firewall && !kernel_filter_available {
                    self.exec_local_firewall(net.to_string(), timeout_secs);
                }
                if kernel_filter_available {
                    self.reconcile_kernel_network(net);
                }
            }
        } else {
            Self::apply_scoped_ip(&self.blocks, key_server_id, ip, expiry);
            crate::firewall::persistence::enqueue_upsert(FirewallBlockRecord::runtime(
                ip.to_string(),
                key_server_id,
                scope_label(key_server_id).to_string(),
                expiry,
                use_local_firewall,
            ));
            if use_local_firewall && !kernel_filter_available {
                self.exec_local_firewall(ip.to_string(), timeout_secs);
            }
        }

        if !block_c_class {
            if use_local_firewall {
                Self::apply_scoped_ip(&self.kernel_blocks, key_server_id, ip, expiry);
            } else {
                Self::remove_scoped_ip(&self.kernel_blocks, key_server_id, ip);
            }
        }
        if kernel_filter_available {
            self.reconcile_kernel_ip(ip);
        }
    }

    fn exec_local_firewall(&self, target: String, timeout: i64) {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("ipset")
                .args(&[
                    "add",
                    "cloud_waf_block",
                    &target,
                    "timeout",
                    &timeout.to_string(),
                    "-exist",
                ])
                .spawn();
        }
        #[cfg(not(target_os = "linux"))]
        {
            tracing::info!(
                "Local firewall simulation: blocking {} for {}s",
                target,
                timeout
            );
        }
    }

    pub fn get_c_class_net(&self, ip: IpAddr) -> Result<IpNet, anyhow::Error> {
        match ip {
            IpAddr::V4(v4) => Ok(IpNet::V4(ipnet::Ipv4Net::new(v4, 24)?.trunc())),
            IpAddr::V6(v6) => Ok(IpNet::V6(ipnet::Ipv6Net::new(v6, 64)?.trunc())),
        }
    }

    pub fn unblock_ip(
        &self,
        ip: IpAddr,
        server_id: i64,
        scope: Option<&str>,
        use_local_firewall: bool,
    ) {
        self.unblock_ip_for(ip, server_id, scope, use_local_firewall, 3600);
    }

    pub fn unblock_ip_for(
        &self,
        ip: IpAddr,
        server_id: i64,
        scope: Option<&str>,
        use_local_firewall: bool,
        ttl_secs: i64,
    ) {
        let key_server_id = if matches!(scope, Some("global")) {
            0
        } else {
            server_id
        };
        self.remove_black_ip(key_server_id, ip);

        if let Ok(net) = self.get_c_class_net(ip) {
            self.remove_black_network(key_server_id, net);
            if use_local_firewall {
                self.exec_local_unblock(net.to_string());
            }
        }

        if use_local_firewall {
            self.exec_local_unblock(ip.to_string());
        }
        let kernel_filter = self.kernel_filter();
        if use_local_firewall && kernel_filter.available() {
            kernel_filter.unblock(ip);
        }

        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.apply_white_ip_until(key_server_id, ip, expiry);
    }

    fn exec_local_unblock(&self, target: String) {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("ipset")
                .args(&["del", "cloud_waf_block", &target, "-exist"])
                .spawn();
        }
        #[cfg(not(target_os = "linux"))]
        {
            tracing::info!("Local firewall simulation: unblocking {}", target);
        }
    }

    pub fn blocked_snapshot_items(&self) -> Vec<(String, i64, u64)> {
        let now = crate::utils::time::now_timestamp();
        let mut items = Vec::new();
        for entry in self.blocks.iter() {
            let ((server_id, ip), expiry) = (*entry.key(), *entry.value());
            if now < expiry {
                items.push((ip.to_string(), server_id, expiry as u64));
            }
        }
        for entry in self.list_blocks.iter() {
            let ((server_id, ip), expiry) = (*entry.key(), *entry.value());
            if now < expiry {
                items.push((ip.to_string(), server_id, expiry as u64));
            }
        }
        for entry in self.block_networks.iter() {
            let ((server_id, net), expiry) = (*entry.key(), *entry.value());
            if now < expiry {
                items.push((net.to_string(), server_id, expiry as u64));
            }
        }
        for entry in self.list_block_networks.iter() {
            let ((server_id, net), expiry) = (*entry.key(), *entry.value());
            if now < expiry {
                items.push((net.to_string(), server_id, expiry as u64));
            }
        }
        for entry in self.list_block_ranges.iter() {
            let ((server_id, range), expiry) = (*entry.key(), *entry.value());
            if now < expiry {
                let (from, to) = range.bounds();
                items.push((format!("{}-{}", from, to), server_id, expiry as u64));
            }
        }
        items.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        items
    }

    pub fn persist_blocked_snapshot(&self) {
        let _ = crate::firewall::persistence::flush_pending();
    }

    pub fn restore_runtime_blocks_from_disk(&self) -> usize {
        let now = crate::utils::time::now_timestamp();
        let records = crate::firewall::persistence::load_active_runtime_blocks(now);
        let mut restored = 0usize;
        for record in records {
            if record.expires_at <= now {
                continue;
            }
            if let Ok(ip) = record.target.parse::<IpAddr>() {
                let ip = canonical_lookup_ip(ip);
                Self::apply_scoped_ip(&self.blocks, record.server_id, ip, record.expires_at);
                if record.kernel_wanted {
                    Self::apply_scoped_ip(
                        &self.kernel_blocks,
                        record.server_id,
                        ip,
                        record.expires_at,
                    );
                }
                restored += 1;
                continue;
            }
            if let Ok(net) = record.target.parse::<IpNet>() {
                let net = net.trunc();
                Self::insert_scoped_network(
                    &self.block_networks,
                    &self.block_network_snapshots,
                    record.server_id,
                    net,
                    record.expires_at,
                );
                if record.kernel_wanted {
                    Self::apply_scoped_network_map(
                        &self.kernel_block_networks,
                        record.server_id,
                        net,
                        record.expires_at,
                    );
                }
                restored += 1;
                continue;
            }
            if let Some(range) = parse_range_target(&record.target) {
                self.apply_list_black_range_until(record.server_id, range, record.expires_at);
                restored += 1;
            }
        }
        self.publish_kernel_filter_snapshot();
        restored
    }

    pub fn check_rate_limit(&self, server_id: i64, max_qps: u32) -> bool {
        if max_qps == 0 {
            return true;
        }
        self.sweep_limiters_if_needed();
        // Lazily insert a new limiter, then check whether max_qps has changed
        // since the limiter was created.  If it has, evict the stale entry and
        // insert a fresh one so the new quota takes effect immediately.
        let entry = self.server_limiters.entry(server_id).or_insert_with(|| {
            let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
            TrackedLimiter::new(Arc::new(RateLimiter::dashmap(quota)), max_qps)
        });
        if entry.quota_value.load(Ordering::Relaxed) != max_qps {
            drop(entry);
            self.server_limiters.remove(&server_id);
            let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
            let fresh = TrackedLimiter::new(Arc::new(RateLimiter::dashmap(quota)), max_qps);
            let entry = self.server_limiters.entry(server_id).or_insert(fresh);
            entry.touch();
            return entry.limiter.check_key(&server_id).is_ok();
        }
        entry.touch();
        entry.limiter.check_key(&server_id).is_ok()
    }

    fn reserve_slot(counter: &AtomicU64, capacity: usize) -> bool {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < capacity as u64).then_some(current + 1)
            })
            .is_ok()
    }

    fn release_slot(counter: &AtomicU64) {
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            Some(current.saturating_sub(1))
        });
    }

    pub fn check_ip_rate_limit(&self, server_id: i64, ip: IpAddr, max_qps: u32) -> bool {
        if max_qps == 0 {
            return true;
        }
        let ip = rate_limit_key_ip(ip);
        self.sweep_limiters_if_needed();
        let key = (server_id, ip);
        let mut entry = match self.ip_limiters.entry(key) {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => {
                if !Self::reserve_slot(&self.ip_limiter_reservations, self.ip_limiter_capacity()) {
                    drop(entry);
                    self.sweep_limiters(crate::utils::time::now_timestamp());
                    let entry = match self.ip_limiters.entry(key) {
                        Entry::Occupied(entry) => entry.into_ref(),
                        Entry::Vacant(entry) => {
                            if !Self::reserve_slot(
                                &self.ip_limiter_reservations,
                                self.ip_limiter_capacity(),
                            ) {
                                warn_state_capacity_full(
                                    &IP_LIMITER_CAPACITY_WARN_AT,
                                    "per-IP rate limiters",
                                    self.ip_limiters.len(),
                                    self.ip_limiter_capacity(),
                                    "fail-closed for untracked rate-limit keys",
                                );
                                return false;
                            }
                            let quota =
                                Quota::per_second(NonZeroU32::new(max_qps).unwrap());
                            entry.insert(TrackedLimiter::new(
                                Arc::new(RateLimiter::dashmap(quota)),
                                max_qps,
                            ))
                        }
                    };
                    entry
                } else {
                    let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
                    entry.insert(TrackedLimiter::new(
                        Arc::new(RateLimiter::dashmap(quota)),
                        max_qps,
                    ))
                }
            }
        };
        if entry.quota_value.load(Ordering::Relaxed) != max_qps {
            drop(entry);
            loop {
                match self.ip_limiters.entry(key) {
                    Entry::Occupied(mut current) => {
                        if current.get().quota_value.load(Ordering::Relaxed) != max_qps {
                            let quota =
                                Quota::per_second(NonZeroU32::new(max_qps).unwrap());
                            let _ = current.insert(TrackedLimiter::new(
                                Arc::new(RateLimiter::dashmap(quota)),
                                max_qps,
                            ));
                        }
                        entry = current.into_ref();
                        break;
                    }
                    Entry::Vacant(current) => {
                        if !Self::reserve_slot(
                            &self.ip_limiter_reservations,
                            self.ip_limiter_capacity(),
                        ) {
                            return false;
                        }
                        let quota =
                            Quota::per_second(NonZeroU32::new(max_qps).unwrap());
                        entry = current.insert(TrackedLimiter::new(
                            Arc::new(RateLimiter::dashmap(quota)),
                            max_qps,
                        ));
                        break;
                    }
                }
            }
        }
        entry.touch();
        entry.limiter.check_key(&ip).is_ok()
    }

    fn ip_limiter_capacity(&self) -> usize {
        crate::memory_governor::MEMORY_GOVERNOR.firewall_ip_limiter_capacity()
    }

    fn sweep_limiters_if_needed(&self) {
        let now = crate::utils::time::now_timestamp();
        let last = self.limiter_last_sweep.load(Ordering::Relaxed);
        if now.saturating_sub(last) < LIMITER_SWEEP_INTERVAL_SECS {
            return;
        }
        if self
            .limiter_last_sweep
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.sweep_limiters(now);
        }
    }

    fn sweep_limiters(&self, now: i64) {
        self.server_limiters
            .retain(|_, tracked| !tracked.is_idle(now));
        let mut removed = 0u64;
        self.ip_limiters.retain(|_, tracked| {
            let retain = !tracked.is_idle(now);
            if !retain {
                removed = removed.saturating_add(1);
            }
            retain
        });
        if removed > 0 {
            let _ = self.ip_limiter_reservations.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| Some(current.saturating_sub(removed)),
            );
        }
    }

    pub fn record_failure(&self, key: String) -> u64 {
        self.increase_counter(format!("FAIL:{}", key), 3600)
    }

    pub fn check_special_defense(&self, key: String, threshold: u32, period: i64) -> bool {
        let count = self.increase_counter(format!("SPECIAL:{}", key), period);
        count <= threshold as u64
    }

    pub fn increase_counter(&self, key: String, period_secs: i64) -> u64 {
        self.increase_counter_by(key, period_secs, 1)
    }

    pub fn increase_counter_by(&self, key: String, period_secs: i64, amount: u64) -> u64 {
        let now = crate::utils::time::now_timestamp();
        let period_secs = period_secs.clamp(1, COUNTER_MAX_PERIOD_SECS);
        let amount = amount.max(1);
        self.sweep_counters(now);
        let key = format!("{}:{}", period_secs, key);
        let mut entry = match self.counters.entry(key.clone()) {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => {
                if !Self::reserve_slot(&self.counter_reservations, self.counter_capacity()) {
                    drop(entry);
                    self.sweep_counters_force(now);
                    match self.counters.entry(key) {
                        Entry::Occupied(entry) => entry.into_ref(),
                        Entry::Vacant(entry) => {
                            if !Self::reserve_slot(
                                &self.counter_reservations,
                                self.counter_capacity(),
                            ) {
                                warn_state_capacity_full(
                                    &COUNTER_CAPACITY_WARN_AT,
                                    "rolling counters",
                                    self.counters.len(),
                                    self.counter_capacity(),
                                    "fail-open for untracked counters",
                                );
                                return 0;
                            }
                            entry.insert(RollingCounter::default())
                        }
                    }
                } else {
                    entry.insert(RollingCounter::default())
                }
            }
        };
        entry.increment_by(now, period_secs, amount)
    }

    fn counter_capacity(&self) -> usize {
        crate::memory_governor::MEMORY_GOVERNOR.firewall_rolling_counter_capacity()
    }

    fn retain_active_counters(&self, now: i64) {
        let mut removed = 0u64;
        self.counters.retain(|_, counter| {
            let retain = !counter.is_stale(now, COUNTER_MAX_PERIOD_SECS);
            if !retain {
                removed = removed.saturating_add(1);
            }
            retain
        });
        if removed > 0 {
            let _ = self.counter_reservations.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| Some(current.saturating_sub(removed)),
            );
        }
    }

    fn sweep_counters(&self, now: i64) {
        let last = self.counter_last_sweep.load(Ordering::Relaxed);
        if now.saturating_sub(last) < COUNTER_SWEEP_INTERVAL_SECS {
            return;
        }
        if self
            .counter_last_sweep
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.retain_active_counters(now);
    }

    fn sweep_counters_force(&self, now: i64) {
        self.retain_active_counters(now);
    }

    fn apply_scoped_ip(map: &DashMap<(i64, IpAddr), i64>, server_id: i64, ip: IpAddr, expiry: i64) {
        if crate::utils::time::now_timestamp() >= expiry {
            map.remove(&(server_id, ip));
        } else {
            map.insert((server_id, ip), expiry);
        }
    }

    fn remove_scoped_ip(map: &DashMap<(i64, IpAddr), i64>, server_id: i64, ip: IpAddr) {
        map.remove(&(server_id, ip));
    }

    fn apply_scoped_network_map(
        map: &DashMap<(i64, IpNet), i64>,
        server_id: i64,
        net: IpNet,
        expiry: i64,
    ) {
        if crate::utils::time::now_timestamp() >= expiry {
            map.remove(&(server_id, net));
        } else {
            map.insert((server_id, net), expiry);
        }
    }

    fn remove_scoped_network_map(
        map: &DashMap<(i64, IpNet), i64>,
        server_id: i64,
        net: IpNet,
    ) {
        map.remove(&(server_id, net));
    }

    fn contains_scoped_ip(
        map: &DashMap<(i64, IpAddr), i64>,
        ip: IpAddr,
        server_id: i64,
        now: i64,
    ) -> bool {
        Self::contains_scoped_ip_for(map, 0, ip, now)
            || (server_id != 0 && Self::contains_scoped_ip_for(map, server_id, ip, now))
    }

    fn contains_scoped_ip_for(
        map: &DashMap<(i64, IpAddr), i64>,
        server_id: i64,
        ip: IpAddr,
        now: i64,
    ) -> bool {
        map.get(&(server_id, ip))
            .is_some_and(|expiry| now < *expiry)
    }

    fn contains_any_scoped_ip(map: &DashMap<(i64, IpAddr), i64>, ip: IpAddr, now: i64) -> bool {
        map.iter()
            .any(|entry| entry.key().1 == ip && now < *entry.value())
    }

    fn insert_scoped_network(
        map: &DashMap<(i64, IpNet), i64>,
        snapshots: &ArcSwap<NetworkSnapshot>,
        server_id: i64,
        net: IpNet,
        expiry: i64,
    ) {
        let now = crate::utils::time::now_timestamp();
        if now >= expiry {
            Self::remove_scoped_network(map, snapshots, server_id, net);
            return;
        }

        map.insert((server_id, net), expiry);
        Self::rebuild_network_snapshot(map, snapshots, now);
    }

    fn remove_scoped_network(
        map: &DashMap<(i64, IpNet), i64>,
        snapshots: &ArcSwap<NetworkSnapshot>,
        server_id: i64,
        net: IpNet,
    ) {
        map.remove(&(server_id, net));
        Self::rebuild_network_snapshot(map, snapshots, crate::utils::time::now_timestamp());
    }

    fn contains_scoped_network(
        snapshots: &ArcSwap<NetworkSnapshot>,
        ip: IpAddr,
        server_id: i64,
        now: i64,
    ) -> bool {
        Self::contains_scoped_network_for(snapshots, 0, ip, now)
            || (server_id != 0 && Self::contains_scoped_network_for(snapshots, server_id, ip, now))
    }

    fn contains_scoped_network_for(
        snapshots: &ArcSwap<NetworkSnapshot>,
        server_id: i64,
        ip: IpAddr,
        now: i64,
    ) -> bool {
        let snapshot = snapshots.load();
        let Some(networks) = snapshot.get(&server_id) else {
            return false;
        };
        networks.contains(ip, now)
    }

    fn contains_any_scoped_network(
        snapshots: &ArcSwap<NetworkSnapshot>,
        ip: IpAddr,
        now: i64,
    ) -> bool {
        snapshots
            .load()
            .values()
            .any(|networks| networks.contains(ip, now))
    }

    fn rebuild_network_snapshot(
        map: &DashMap<(i64, IpNet), i64>,
        snapshots: &ArcSwap<NetworkSnapshot>,
        now: i64,
    ) {
        let mut next_items: HashMap<i64, Vec<(IpNet, i64)>> = HashMap::new();
        for entry in map.iter() {
            let (server_id, net) = *entry.key();
            let expiry = *entry.value();
            if now >= expiry {
                continue;
            }
            next_items.entry(server_id).or_default().push((net, expiry));
        }
        let next = next_items
            .into_iter()
            .map(|(server_id, items)| {
                (server_id, Arc::new(NetworkScopeSnapshot::from_items(items)))
            })
            .collect::<HashMap<_, _>>();
        snapshots.store(Arc::new(next));
    }

    /// Evict all expired entries from IP block/white/gray lists and idle rate limiters.
    pub fn gc_once(&self) {
        let now = crate::utils::time::now_timestamp();

        let expired_ips = self
            .blocks
            .iter()
            .filter_map(|entry| {
                (now >= *entry.value()).then_some((entry.key().0, entry.key().1, *entry.value()))
            })
            .collect::<Vec<_>>();
        for (server_id, ip, observed_expiry) in expired_ips {
            let removed = self
                .blocks
                .remove_if(&(server_id, ip), |_, expiry| *expiry == observed_expiry)
                .is_some();
            if removed {
                crate::firewall::persistence::enqueue_delete(
                    scope_label(server_id),
                    server_id,
                    &ip.to_string(),
                );
            }
        }
        let expired_networks = self
            .block_networks
            .iter()
            .filter_map(|entry| {
                (now >= *entry.value()).then_some((entry.key().0, entry.key().1, *entry.value()))
            })
            .collect::<Vec<_>>();
        for (server_id, net, observed_expiry) in expired_networks {
            let removed = self
                .block_networks
                .remove_if(&(server_id, net), |_, expiry| *expiry == observed_expiry)
                .is_some();
            if removed {
                crate::firewall::persistence::enqueue_delete(
                    scope_label(server_id),
                    server_id,
                    &net.to_string(),
                );
            }
        }

        self.blocks.retain(|_, expiry| now < *expiry);
        self.kernel_blocks.retain(|_, expiry| now < *expiry);
        self.list_blocks.retain(|_, expiry| now < *expiry);
        self.whitelists.retain(|_, expiry| now < *expiry);
        self.list_whitelists.retain(|_, expiry| now < *expiry);
        self.graylists.retain(|_, expiry| now < *expiry);
        self.list_graylists.retain(|_, expiry| now < *expiry);
        self.block_networks.retain(|_, expiry| now < *expiry);
        self.kernel_block_networks
            .retain(|_, expiry| now < *expiry);
        self.list_block_networks.retain(|_, expiry| now < *expiry);
        self.whitelist_networks.retain(|_, expiry| now < *expiry);
        self.list_whitelist_networks
            .retain(|_, expiry| now < *expiry);
        self.gray_networks.retain(|_, expiry| now < *expiry);
        self.list_gray_networks.retain(|_, expiry| now < *expiry);
        Self::rebuild_network_snapshot(&self.block_networks, &self.block_network_snapshots, now);
        Self::rebuild_network_snapshot(
            &self.list_block_networks,
            &self.list_block_network_snapshots,
            now,
        );
        Self::rebuild_network_snapshot(
            &self.whitelist_networks,
            &self.whitelist_network_snapshots,
            now,
        );
        Self::rebuild_network_snapshot(
            &self.list_whitelist_networks,
            &self.list_whitelist_network_snapshots,
            now,
        );
        Self::rebuild_network_snapshot(&self.gray_networks, &self.gray_network_snapshots, now);
        Self::rebuild_network_snapshot(
            &self.list_gray_networks,
            &self.list_gray_network_snapshots,
            now,
        );
        self.retain_active_counters(now);
        self.sweep_candidate_stats(now);

        self.sweep_limiters(now);
        self.list_block_ranges.retain(|_, expiry| now < *expiry);
        self.list_white_ranges.retain(|_, expiry| now < *expiry);
        self.list_gray_ranges.retain(|_, expiry| now < *expiry);
        Self::rebuild_range_snapshot(
            &self.list_block_ranges,
            &self.list_block_range_snapshots,
            now,
        );
        Self::rebuild_range_snapshot(
            &self.list_white_ranges,
            &self.list_white_range_snapshots,
            now,
        );
        Self::rebuild_range_snapshot(&self.list_gray_ranges, &self.list_gray_range_snapshots, now);
        self.sweep_ip_bw_counters(now as u64);
        let _ = crate::firewall::persistence::cleanup_expired(now);
        self.persist_blocked_snapshot();
        self.publish_kernel_filter_snapshot();
    }

    pub fn apply_list_black_range_until(&self, server_id: i64, range: IpAddrRange, expiry: i64) {
        Self::apply_scoped_range(
            &self.list_block_ranges,
            &self.list_block_range_snapshots,
            server_id,
            range,
            expiry,
        );
        self.publish_kernel_filter_snapshot();
    }

    pub fn remove_list_black_range(&self, server_id: i64, range: IpAddrRange) {
        Self::remove_scoped_range(
            &self.list_block_ranges,
            &self.list_block_range_snapshots,
            server_id,
            range,
        );
        self.publish_kernel_filter_snapshot();
    }

    pub fn apply_list_white_range_until(&self, server_id: i64, range: IpAddrRange, expiry: i64) {
        Self::apply_scoped_range(
            &self.list_white_ranges,
            &self.list_white_range_snapshots,
            server_id,
            range,
            expiry,
        );
        self.publish_kernel_filter_snapshot();
    }

    pub fn remove_list_white_range(&self, server_id: i64, range: IpAddrRange) {
        Self::remove_scoped_range(
            &self.list_white_ranges,
            &self.list_white_range_snapshots,
            server_id,
            range,
        );
        self.publish_kernel_filter_snapshot();
    }

    pub fn apply_list_gray_range_until(&self, server_id: i64, range: IpAddrRange, expiry: i64) {
        Self::apply_scoped_range(
            &self.list_gray_ranges,
            &self.list_gray_range_snapshots,
            server_id,
            range,
            expiry,
        );
    }

    pub fn remove_list_gray_range(&self, server_id: i64, range: IpAddrRange) {
        Self::remove_scoped_range(
            &self.list_gray_ranges,
            &self.list_gray_range_snapshots,
            server_id,
            range,
        );
    }

    fn apply_scoped_range(
        map: &DashMap<(i64, IpAddrRange), i64>,
        snapshots: &ArcSwap<RangeSnapshot>,
        server_id: i64,
        range: IpAddrRange,
        expiry: i64,
    ) {
        let now = crate::utils::time::now_timestamp();
        if now >= expiry {
            Self::remove_scoped_range(map, snapshots, server_id, range);
        } else {
            map.insert((server_id, range), expiry);
            Self::rebuild_range_snapshot(map, snapshots, now);
        }
    }

    fn remove_scoped_range(
        map: &DashMap<(i64, IpAddrRange), i64>,
        snapshots: &ArcSwap<RangeSnapshot>,
        server_id: i64,
        range: IpAddrRange,
    ) {
        map.remove(&(server_id, range));
        Self::rebuild_range_snapshot(map, snapshots, crate::utils::time::now_timestamp());
    }

    fn rebuild_range_snapshot(
        map: &DashMap<(i64, IpAddrRange), i64>,
        snapshots: &ArcSwap<RangeSnapshot>,
        now: i64,
    ) {
        let mut next: RangeSnapshot = HashMap::new();
        for entry in map.iter() {
            let (server_id, range) = *entry.key();
            let expiry = *entry.value();
            if now >= expiry {
                continue;
            }
            let ranges = next
                .entry(server_id)
                .or_insert_with(|| Arc::new(Vec::new()));
            Arc::make_mut(ranges).push((range, expiry));
        }
        snapshots.store(Arc::new(next));
    }

    fn contains_scoped_range(
        snapshots: &ArcSwap<RangeSnapshot>,
        ip: IpAddr,
        server_id: i64,
        now: i64,
    ) -> bool {
        let snapshot = snapshots.load();
        Self::ranges_contain_ip(snapshot.get(&0), ip, now)
            || (server_id != 0 && Self::ranges_contain_ip(snapshot.get(&server_id), ip, now))
    }

    fn contains_any_scoped_range(snapshots: &ArcSwap<RangeSnapshot>, ip: IpAddr, now: i64) -> bool {
        snapshots
            .load()
            .values()
            .any(|ranges| Self::ranges_contain_ip(Some(ranges), ip, now))
    }

    fn ranges_contain_ip(
        ranges: Option<&Arc<Vec<(IpAddrRange, i64)>>>,
        ip: IpAddr,
        now: i64,
    ) -> bool {
        ranges.is_some_and(|ranges| {
            ranges
                .iter()
                .any(|(range, expiry)| now < *expiry && range.contains(ip))
        })
    }

    /// Sliding-window per-IP byte counter for CC bandwidth enforcement.
    /// Returns `true` if the IP has exceeded `limit_bytes` in the current
    /// 1-second window (caller decides what to do on breach).
    pub fn check_ip_bandwidth(
        &self,
        server_id: i64,
        ip: IpAddr,
        bytes: u64,
        limit_bytes: u64,
    ) -> bool {
        if limit_bytes == 0 {
            return false;
        }
        let ip = rate_limit_key_ip(ip);
        let now_secs = crate::utils::time::now_timestamp() as u64;
        let key = (server_id, ip);
        let entry = match self.ip_bw_counters.entry(key) {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => {
                if !Self::reserve_slot(
                    &self.ip_bw_counter_reservations,
                    self.ip_bw_counter_capacity(),
                ) {
                    drop(entry);
                    self.sweep_ip_bw_counters(now_secs);
                    match self.ip_bw_counters.entry(key) {
                        Entry::Occupied(entry) => entry.into_ref(),
                        Entry::Vacant(entry) => {
                            if !Self::reserve_slot(
                                &self.ip_bw_counter_reservations,
                                self.ip_bw_counter_capacity(),
                            ) {
                                warn_state_capacity_full(
                                    &IP_BW_CAPACITY_WARN_AT,
                                    "per-IP bandwidth counters",
                                    self.ip_bw_counters.len(),
                                    self.ip_bw_counter_capacity(),
                                    "fail-open for untracked bandwidth keys",
                                );
                                return false;
                            }
                            entry.insert(Arc::new(RwLock::new((0, now_secs))))
                        }
                    }
                } else {
                    entry.insert(Arc::new(RwLock::new((0, now_secs))))
                }
            }
        };
        let mut state = entry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if now_secs > state.1 {
            state.0 = bytes;
            state.1 = now_secs;
            return bytes > limit_bytes;
        }
        state.0 = state.0.saturating_add(bytes);
        state.0 > limit_bytes
    }

    fn sweep_ip_bw_counters(&self, now_secs: u64) {
        let mut removed = 0u64;
        self.ip_bw_counters.retain(|_, entry| {
            let win = entry
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .1;
            let retain = now_secs.saturating_sub(win) < 120;
            if !retain {
                removed = removed.saturating_add(1);
            }
            retain
        });
        if removed > 0 {
            let _ = self.ip_bw_counter_reservations.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| Some(current.saturating_sub(removed)),
            );
        }
    }

    fn ip_bw_counter_capacity(&self) -> usize {
        crate::memory_governor::MEMORY_GOVERNOR.firewall_ip_bw_counter_capacity()
    }

    pub fn record_candidate_hit(
        &self,
        policy_id: i64,
        version: i64,
        blocked: bool,
        observed: bool,
    ) {
        let now = crate::utils::time::now_timestamp();
        let key = (policy_id, version);
        let entry = match self.candidate_stats.entry(key) {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => {
                if !Self::reserve_slot(
                    &self.candidate_stats_reservations,
                    self.candidate_stats_capacity(),
                ) {
                    drop(entry);
                    self.sweep_candidate_stats(now);
                    match self.candidate_stats.entry(key) {
                        Entry::Occupied(entry) => entry.into_ref(),
                        Entry::Vacant(entry) => {
                            if !Self::reserve_slot(
                                &self.candidate_stats_reservations,
                                self.candidate_stats_capacity(),
                            ) {
                                return;
                            }
                            entry.insert(Arc::new(CandidateRulesetStats::new()))
                        }
                    }
                } else {
                    entry.insert(Arc::new(CandidateRulesetStats::new()))
                }
            }
        };
        entry.touch(now);
        entry.hits.fetch_add(1, Ordering::Relaxed);
        if blocked {
            entry.blocks.fetch_add(1, Ordering::Relaxed);
        }
        if observed {
            entry.observed.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn candidate_stats_capacity(&self) -> usize {
        crate::memory_governor::MEMORY_GOVERNOR.firewall_candidate_stats_capacity()
    }

    fn sweep_candidate_stats(&self, now: i64) {
        let mut removed = 0u64;
        self.candidate_stats.retain(|_, stats| {
            let retain = !stats.is_idle(now);
            if !retain {
                removed = removed.saturating_add(1);
            }
            retain
        });
        if removed > 0 {
            let _ = self.candidate_stats_reservations.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |current| Some(current.saturating_sub(removed)),
            );
        }
    }

    pub fn take_candidate_stats(&self) -> Vec<CandidateStatsSnapshot> {
        let keys: Vec<(i64, i64)> = self.candidate_stats.iter().map(|e| *e.key()).collect();
        keys.into_iter()
            .filter_map(|key| {
                self.candidate_stats.remove(&key).map(|(k, arc)| {
                    Self::release_slot(&self.candidate_stats_reservations);
                    CandidateStatsSnapshot {
                        policy_id: k.0,
                        version: k.1,
                        hits: arc.hits.load(Ordering::Relaxed),
                        blocks: arc.blocks.load(Ordering::Relaxed),
                        observed: arc.observed.load(Ordering::Relaxed),
                    }
                })
            })
            .collect()
    }

    pub fn flush_to_disk(&self) {}
}

/// Spawn a background tokio task that runs GC on the WAF state every 60 seconds.
pub fn start_gc_task(state: Arc<WafStateManager>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(GC_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            state.gc_once();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn ipv6_rate_limit_keys_are_aggregated_to_64() {
        let a = IpAddr::V6("2001:db8:abcd:12::1".parse::<Ipv6Addr>().unwrap());
        let b = IpAddr::V6(
            "2001:db8:abcd:12:ffff:ffff:ffff:ffff"
                .parse::<Ipv6Addr>()
                .unwrap(),
        );
        let c = IpAddr::V6("2001:db8:abcd:13::1".parse::<Ipv6Addr>().unwrap());

        assert_eq!(rate_limit_key_ip(a), rate_limit_key_ip(b));
        assert_ne!(rate_limit_key_ip(a), rate_limit_key_ip(c));
    }

    #[test]
    fn limiter_gc_removes_idle_entries() {
        let state = WafStateManager::new();
        assert!(state.check_ip_rate_limit(7, "192.0.2.1".parse().unwrap(), 10));
        assert_eq!(state.ip_limiters.len(), 1);
        for entry in state.ip_limiters.iter() {
            entry.last_seen.store(
                crate::utils::time::now_timestamp() - LIMITER_IDLE_SECS - 1,
                Ordering::Relaxed,
            );
        }
        state.sweep_limiters(crate::utils::time::now_timestamp());
        assert_eq!(state.ip_limiters.len(), 0);
    }

    #[test]
    fn bandwidth_counter_blocks_oversized_first_request_after_window_reset() {
        let state = WafStateManager::new();
        let server_id = 7;
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(!state.check_ip_bandwidth(server_id, ip, 50, 100));

        let key = (server_id, rate_limit_key_ip(ip));
        let entry = state
            .ip_bw_counters
            .get(&key)
            .expect("bandwidth counter should exist");
        entry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .1 = crate::utils::time::now_timestamp() as u64 - 1;
        drop(entry);

        assert!(state.check_ip_bandwidth(server_id, ip, 101, 100));
    }

    #[test]
    fn range_snapshots_track_apply_remove_and_gc() {
        let state = WafStateManager::new();
        let now = crate::utils::time::now_timestamp();
        let range = IpAddrRange {
            from: u32::from_be_bytes([203, 0, 113, 0]) as u128,
            to: u32::from_be_bytes([203, 0, 113, 255]) as u128,
            v6: false,
        };
        let inside: IpAddr = "203.0.113.10".parse().unwrap();
        let outside: IpAddr = "203.0.114.10".parse().unwrap();

        state.apply_list_black_range_until(42, range, now + 60);
        assert!(state.is_blocked(inside, 42));
        assert!(!state.is_blocked(outside, 42));

        state.remove_list_black_range(42, range);
        assert!(!state.is_blocked(inside, 42));

        state.apply_list_black_range_until(42, range, now - 1);
        state.gc_once();
        assert!(!state.is_blocked(inside, 42));
    }

    #[test]
    fn network_snapshots_bucket_ipv4_ipv6_and_gc_expired_entries() {
        let state = WafStateManager::new();
        let now = crate::utils::time::now_timestamp();
        let v4_net: IpNet = "203.0.113.0/24".parse().unwrap();
        let v6_net: IpNet = "2001:db8:abcd::/48".parse().unwrap();
        let v4_inside: IpAddr = "203.0.113.9".parse().unwrap();
        let v4_outside: IpAddr = "203.0.114.9".parse().unwrap();
        let v6_inside: IpAddr = "2001:db8:abcd::1".parse().unwrap();
        let v6_outside: IpAddr = "2001:db8:abce::1".parse().unwrap();

        state.apply_black_network_until(42, v4_net, now + 60);
        state.apply_black_network_until(42, v6_net, now + 60);

        assert!(state.is_blocked(v4_inside, 42));
        assert!(!state.is_blocked(v4_outside, 42));
        assert!(state.is_blocked(v6_inside, 42));
        assert!(!state.is_blocked(v6_outside, 42));

        state.apply_black_network_until(42, v4_net, now - 1);
        state.gc_once();

        assert!(!state.is_blocked(v4_inside, 42));
        assert!(state.is_blocked(v6_inside, 42));
    }

    #[test]
    fn bandwidth_counters_aggregate_ipv6_to_64() {
        let state = WafStateManager::new();
        let a = IpAddr::V6("2001:db8:abcd:12::1".parse::<Ipv6Addr>().unwrap());
        let b = IpAddr::V6(
            "2001:db8:abcd:12:ffff:ffff:ffff:ffff"
                .parse::<Ipv6Addr>()
                .unwrap(),
        );

        assert!(!state.check_ip_bandwidth(7, a, 60, 100));
        assert!(state.check_ip_bandwidth(7, b, 60, 100));
        assert_eq!(state.ip_bw_counters.len(), 1);
    }

    #[test]
    fn candidate_stats_are_evicted_after_idle_window() {
        let state = WafStateManager::new();
        state.record_candidate_hit(42, 9, true, false);
        assert_eq!(state.candidate_stats.len(), 1);
        for entry in state.candidate_stats.iter() {
            entry.last_seen.store(
                crate::utils::time::now_timestamp() - CANDIDATE_STATS_IDLE_SECS - 1,
                Ordering::Relaxed,
            );
        }
        state.gc_once();
        assert_eq!(state.candidate_stats.len(), 0);
    }
}
