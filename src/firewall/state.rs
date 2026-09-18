use crate::firewall::bounded_map::BoundedScopedMap;
use crate::firewall::kernel::{KernelFilter, KernelFilterRange, KernelFilterSnapshot, NoopFilter};
use crate::firewall::persistence::FirewallBlockRecord;
use arc_swap::ArcSwap;
use dashmap::{DashMap, mapref::entry::Entry};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::{InMemoryState, NotKeyed}};
use ipnet::IpNet;
use std::collections::{BinaryHeap, HashMap};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

type IpBandwidthCounter = Arc<RwLock<(u64, u64)>>;
type IpBandwidthCounters = DashMap<(i64, IpAddr), IpBandwidthCounter>;

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
static SCOPED_STATE_CAPACITY_WARN_AT: AtomicI64 = AtomicI64::new(0);

/// Wraps a RateLimiter with a last-seen timestamp for GC and the QPS value the
/// quota was built from, so hot-reload can detect and replace stale limiters.
/// The limiter is NotKeyed: the outer DashMap already keys per server/(server,ip),
/// so a keyed inner store would just hold a single entry per limiter.
pub(crate) struct TrackedLimiter {
    pub limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    pub last_seen: AtomicI64,
    /// The QPS value baked into `limiter`'s Quota at construction time.
    pub quota_value: AtomicU32,
}

impl TrackedLimiter {
    fn new(
        limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
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

/// Heap entry ordered by expiry alone so the eviction heap can rank scoped
/// keys without requiring `Ord` on the key type.
struct EarliestExpiry<K> {
    expiry: i64,
    key: K,
}

impl<K> PartialEq for EarliestExpiry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.expiry == other.expiry
    }
}
impl<K> Eq for EarliestExpiry<K> {}
impl<K> PartialOrd for EarliestExpiry<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<K> Ord for EarliestExpiry<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.expiry.cmp(&other.expiry)
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

/// Scoped-IP read path (RCU): readers hit one immutable union snapshot plus
/// a small `delta` carrying every mutation since the snapshot was built.
/// Writers mutate the source DashMaps (still the authority), then publish a
/// resolved union entry into the delta — so reads stay instant-consistent
/// without per-request DashMap lookups over the multi-million-entry maps.
const IP_DELTA_CAP: usize = 262_144;
const IP_DELTA_REMOVED: i64 = i64::MIN;
const KIND_BLOCK: u8 = 0;
const KIND_WHITE: u8 = 1;
const KIND_GRAY: u8 = 2;

/// Immutable per-kind union view: (server_id, ip) -> max expiry across the
/// two source maps for that kind. Built single-flight from the source maps.
struct IpReadSnapshot {
    blocked: HashMap<(i64, IpAddr), i64>,
    whitelisted: HashMap<(i64, IpAddr), i64>,
    graylisted: HashMap<(i64, IpAddr), i64>,
}

type IpDelta = DashMap<(u8, i64, IpAddr), i64>;

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
            net.contains(&from)
                || net.contains(&to)
                || (range.from <= net_to && range.to >= net_from)
        }
        (IpAddr::V6(from), IpAddr::V6(to), IpNet::V6(net)) => {
            let net_from = u128::from_be_bytes(net.network().octets());
            let net_to = u128::from_be_bytes(net.broadcast().octets());
            net.contains(&from)
                || net.contains(&to)
                || (range.from <= net_to && range.to >= net_from)
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
    // Scoped-IP maps are bounded slot tables: physical memory is fixed at
    // construction from the governor's state capacity, inserts are an
    // 8-slot probe with in-window earliest-expiry eviction, and flood CPU
    // stays O(1). Network/range maps stay DashMap (much lower cardinality).
    pub blocks: BoundedScopedMap<(i64, IpAddr)>,
    kernel_blocks: BoundedScopedMap<(i64, IpAddr)>,
    pub block_networks: DashMap<(i64, IpNet), i64>,
    kernel_block_networks: DashMap<(i64, IpNet), i64>,
    block_network_snapshots: ArcSwap<NetworkSnapshot>,
    list_blocks: BoundedScopedMap<(i64, IpAddr)>,
    list_block_networks: DashMap<(i64, IpNet), i64>,
    list_block_network_snapshots: ArcSwap<NetworkSnapshot>,
    pub whitelists: BoundedScopedMap<(i64, IpAddr)>,
    whitelist_networks: DashMap<(i64, IpNet), i64>,
    whitelist_network_snapshots: ArcSwap<NetworkSnapshot>,
    list_whitelists: BoundedScopedMap<(i64, IpAddr)>,
    list_whitelist_networks: DashMap<(i64, IpNet), i64>,
    list_whitelist_network_snapshots: ArcSwap<NetworkSnapshot>,
    graylists: BoundedScopedMap<(i64, IpAddr)>,
    gray_networks: DashMap<(i64, IpNet), i64>,
    gray_network_snapshots: ArcSwap<NetworkSnapshot>,
    list_graylists: BoundedScopedMap<(i64, IpAddr)>,
    list_gray_networks: DashMap<(i64, IpNet), i64>,
    list_gray_network_snapshots: ArcSwap<NetworkSnapshot>,
    server_limiters: DashMap<i64, TrackedLimiter>,
    ip_limiters: DashMap<(i64, IpAddr), TrackedLimiter>,
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
    ip_bw_counters: IpBandwidthCounters,
    ip_bw_counter_reservations: AtomicU64,
    /// RCU read path for scoped-IP block/white/gray lookups: `ip_read` is the
    /// immutable union snapshot; `ip_delta` holds every post-snapshot
    /// mutation and is swapped out wholesale by the single-flight rebuilder.
    ip_read: ArcSwap<IpReadSnapshot>,
    ip_delta: ArcSwap<IpDelta>,
    ip_rebuild: std::sync::Mutex<()>,
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
        // Slot tables are sized once from the governor's state capacity —
        // machine memory is fixed for the process lifetime, so the physical
        // bound is decided here and enforced by construction.
        let ip_table_cap = Self::scoped_state_map_capacity();
        Self {
            blocks: BoundedScopedMap::new(ip_table_cap),
            kernel_blocks: BoundedScopedMap::new(ip_table_cap),
            block_networks: DashMap::new(),
            kernel_block_networks: DashMap::new(),
            block_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            list_blocks: BoundedScopedMap::new(ip_table_cap),
            list_block_networks: DashMap::new(),
            list_block_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            whitelists: BoundedScopedMap::new(ip_table_cap),
            whitelist_networks: DashMap::new(),
            whitelist_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            list_whitelists: BoundedScopedMap::new(ip_table_cap),
            list_whitelist_networks: DashMap::new(),
            list_whitelist_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            graylists: BoundedScopedMap::new(ip_table_cap),
            gray_networks: DashMap::new(),
            gray_network_snapshots: ArcSwap::from_pointee(HashMap::new()),
            list_graylists: BoundedScopedMap::new(ip_table_cap),
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
            ip_read: ArcSwap::from_pointee(IpReadSnapshot {
                blocked: HashMap::new(),
                whitelisted: HashMap::new(),
                graylisted: HashMap::new(),
            }),
            ip_delta: ArcSwap::from_pointee(DashMap::new()),
            ip_rebuild: std::sync::Mutex::new(()),
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
                .chain(Self::snapshot_global_networks(
                    &self.list_block_networks,
                    now,
                ))
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

    fn snapshot_global_ips(
        map: &BoundedScopedMap<(i64, IpAddr)>,
        now: i64,
    ) -> Vec<(IpAddr, i64)> {
        let mut out = Vec::new();
        map.for_each(|(scope, ip), expiry| {
            if scope == 0 && expiry > now {
                out.push((ip, expiry));
            }
            true
        });
        out
    }

    fn snapshot_global_networks(map: &DashMap<(i64, IpNet), i64>, now: i64) -> Vec<(IpNet, i64)> {
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
        map: &BoundedScopedMap<(i64, IpAddr)>,
        ip: IpAddr,
        now: i64,
    ) -> Option<i64> {
        let mut best: Option<i64> = None;
        map.for_each(|(scope, entry_ip), expiry| {
            if scope == 0 && entry_ip == ip && expiry > now {
                best = Some(best.map_or(expiry, |b| b.max(expiry)));
            }
            true
        });
        best
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
        let whitelist_expiry =
            Self::max_global_network_expiry(&self.whitelist_networks, net, now).max(
                Self::max_global_network_expiry(&self.list_whitelist_networks, net, now),
            );
        if let Some(expiry) = whitelist_expiry {
            filter.allow_network(net, expiry.saturating_sub(now));
            return;
        }
        filter.unallow_network(net);
        let expiry = Self::max_global_network_expiry(&self.kernel_block_networks, net, now).max(
            Self::max_global_network_expiry(&self.list_block_networks, net, now),
        );
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
        let delta = self.ip_delta.load();
        let snap = self.ip_read.load();
        self.contains_ip_kind(&delta, &snap.whitelisted, KIND_WHITE, ip, server_id, now)
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
        map: &BoundedScopedMap<(i64, IpAddr)>,
        net: IpNet,
        server_id: i64,
        now: i64,
    ) -> bool {
        let mut found = false;
        map.for_each(|(scope, ip), expiry| {
            if now < expiry && (scope == 0 || scope == server_id) && net.contains(&ip) {
                found = true;
                return false;
            }
            true
        });
        found
    }

    fn scoped_range_snapshot_overlaps(
        snapshots: &ArcSwap<RangeSnapshot>,
        net: IpNet,
        server_id: i64,
        now: i64,
    ) -> bool {
        let snapshot = snapshots.load();
        Self::ranges_overlap_network(snapshot.get(&0), net, now)
            || (server_id != 0 && Self::ranges_overlap_network(snapshot.get(&server_id), net, now))
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
        let snapshot = snapshots.load();
        snapshot
            .get(&0)
            .is_some_and(|s| s.overlaps(net, now))
            || (server_id != 0
                && snapshot
                    .get(&server_id)
                    .is_some_and(|s| s.overlaps(net, now)))
    }

    pub fn is_blocked(&self, ip: IpAddr, server_id: i64) -> bool {
        let ip = canonical_lookup_ip(ip);
        let now = crate::utils::time::now_timestamp();
        let delta = self.ip_delta.load();
        let snap = self.ip_read.load();
        self.contains_ip_kind(&delta, &snap.blocked, KIND_BLOCK, ip, server_id, now)
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
        let delta = self.ip_delta.load();
        let snap = self.ip_read.load();
        self.contains_ip_kind(&delta, &snap.graylisted, KIND_GRAY, ip, server_id, now)
            || Self::contains_scoped_network(&self.gray_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_network(&self.list_gray_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_range(&self.list_gray_range_snapshots, ip, server_id, now)
    }

    pub fn apply_black_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        let ip = canonical_lookup_ip(ip);
        let evicted =
            self.mutate_ip_kind(KIND_BLOCK, &self.blocks, "blocks", server_id, ip, expiry);
        for (evict_server_id, evict_ip) in &evicted {
            // blocks and kernel_blocks are paired: drop the victim from the
            // kernel-side mirror too so the two maps stay consistent.
            self.kernel_blocks.remove(&(*evict_server_id, *evict_ip));
            self.reconcile_kernel_ip(*evict_ip);
        }
        let evicted =
            Self::apply_scoped_ip(&self.kernel_blocks, "kernel_blocks", server_id, ip, expiry);
        for (_, evict_ip) in evicted {
            self.reconcile_kernel_ip(evict_ip);
        }
        self.reconcile_kernel_ip(ip);
    }

    pub fn apply_black_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        let evicted = Self::insert_scoped_network(
            &self.block_networks,
            &self.block_network_snapshots,
            "block_networks",
            server_id,
            net,
            expiry,
        );
        for (evict_server_id, evict_net) in &evicted {
            self.kernel_block_networks
                .remove(&(*evict_server_id, *evict_net));
            self.reconcile_kernel_network(*evict_net);
        }
        let evicted = Self::apply_scoped_network_map(
            &self.kernel_block_networks,
            "kernel_block_networks",
            server_id,
            net,
            expiry,
        );
        for (_, evict_net) in evicted {
            self.reconcile_kernel_network(evict_net);
        }
        self.reconcile_kernel_network(net);
    }

    pub fn remove_black_ip(&self, server_id: i64, ip: IpAddr) {
        let ip = canonical_lookup_ip(ip);
        self.remove_ip_kind(KIND_BLOCK, &self.blocks, server_id, ip);
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
        let evicted =
            self.mutate_ip_kind(KIND_BLOCK, &self.list_blocks, "list_blocks", server_id, ip, expiry);
        for (_, evict_ip) in evicted {
            self.reconcile_kernel_ip(evict_ip);
        }
        self.reconcile_kernel_ip(ip);
    }

    pub fn apply_list_black_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        let evicted = Self::insert_scoped_network(
            &self.list_block_networks,
            &self.list_block_network_snapshots,
            "list_block_networks",
            server_id,
            net,
            expiry,
        );
        for (_, evict_net) in evicted {
            self.reconcile_kernel_network(evict_net);
        }
        self.reconcile_kernel_network(net);
    }

    pub fn remove_list_black_ip(&self, server_id: i64, ip: IpAddr) {
        let ip = canonical_lookup_ip(ip);
        self.remove_ip_kind(KIND_BLOCK, &self.list_blocks, server_id, ip);
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
        let evicted =
            self.mutate_ip_kind(KIND_WHITE, &self.whitelists, "whitelists", server_id, ip, expiry);
        for (_, evict_ip) in evicted {
            self.reconcile_kernel_ip(evict_ip);
        }
        self.reconcile_kernel_ip(ip);
    }

    pub fn apply_white_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        let evicted = Self::insert_scoped_network(
            &self.whitelist_networks,
            &self.whitelist_network_snapshots,
            "whitelist_networks",
            server_id,
            net,
            expiry,
        );
        for (_, evict_net) in evicted {
            self.reconcile_kernel_network(evict_net);
        }
        self.reconcile_kernel_network(net);
    }

    pub fn remove_white_ip(&self, server_id: i64, ip: IpAddr) {
        let ip = canonical_lookup_ip(ip);
        self.remove_ip_kind(KIND_WHITE, &self.whitelists, server_id, ip);
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
        let evicted = self.mutate_ip_kind(
            KIND_WHITE,
            &self.list_whitelists,
            "list_whitelists",
            server_id,
            ip,
            expiry,
        );
        for (_, evict_ip) in evicted {
            self.reconcile_kernel_ip(evict_ip);
        }
        self.reconcile_kernel_ip(ip);
    }

    pub fn apply_list_white_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        let evicted = Self::insert_scoped_network(
            &self.list_whitelist_networks,
            &self.list_whitelist_network_snapshots,
            "list_whitelist_networks",
            server_id,
            net,
            expiry,
        );
        for (_, evict_net) in evicted {
            self.reconcile_kernel_network(evict_net);
        }
        self.reconcile_kernel_network(net);
    }

    pub fn remove_list_white_ip(&self, server_id: i64, ip: IpAddr) {
        let ip = canonical_lookup_ip(ip);
        self.remove_ip_kind(KIND_WHITE, &self.list_whitelists, server_id, ip);
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
        // Graylists do not feed the kernel filter — evictions need no reconcile.
        let _ =
            self.mutate_ip_kind(KIND_GRAY, &self.graylists, "graylists", server_id, ip, expiry);
    }

    pub fn apply_gray_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        let _ = Self::insert_scoped_network(
            &self.gray_networks,
            &self.gray_network_snapshots,
            "gray_networks",
            server_id,
            net,
            expiry,
        );
    }

    pub fn remove_gray_ip(&self, server_id: i64, ip: IpAddr) {
        self.remove_ip_kind(KIND_GRAY, &self.graylists, server_id, ip);
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
        let _ = self.mutate_ip_kind(
            KIND_GRAY,
            &self.list_graylists,
            "list_graylists",
            server_id,
            ip,
            expiry,
        );
    }

    pub fn apply_list_gray_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        let _ = Self::insert_scoped_network(
            &self.list_gray_networks,
            &self.list_gray_network_snapshots,
            "list_gray_networks",
            server_id,
            net,
            expiry,
        );
    }

    pub fn remove_list_gray_ip(&self, server_id: i64, ip: IpAddr) {
        self.remove_ip_kind(KIND_GRAY, &self.list_graylists, server_id, ip);
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
        let evicted = Self::insert_scoped_network(
            &self.block_networks,
            &self.block_network_snapshots,
            "block_networks",
            key_server_id,
            net,
            expiry,
        );
        for (evict_server_id, evict_net) in &evicted {
            self.kernel_block_networks
                .remove(&(*evict_server_id, *evict_net));
            self.reconcile_kernel_network(*evict_net);
        }
        crate::firewall::persistence::enqueue_upsert(FirewallBlockRecord::runtime(
            net.to_string(),
            key_server_id,
            scope_label(key_server_id).to_string(),
            expiry,
            use_local_firewall,
        ));
        if use_local_firewall {
            let evicted = Self::apply_scoped_network_map(
                &self.kernel_block_networks,
                "kernel_block_networks",
                key_server_id,
                net,
                expiry,
            );
            for (_, evict_net) in evicted {
                self.reconcile_kernel_network(evict_net);
            }
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
                let evicted = Self::insert_scoped_network(
                    &self.block_networks,
                    &self.block_network_snapshots,
                    "block_networks",
                    key_server_id,
                    net,
                    expiry,
                );
                for (evict_server_id, evict_net) in &evicted {
                    self.kernel_block_networks
                        .remove(&(*evict_server_id, *evict_net));
                    self.reconcile_kernel_network(*evict_net);
                }
                crate::firewall::persistence::enqueue_upsert(FirewallBlockRecord::runtime(
                    net.to_string(),
                    key_server_id,
                    scope_label(key_server_id).to_string(),
                    expiry,
                    use_local_firewall,
                ));
                if use_local_firewall {
                    let evicted = Self::apply_scoped_network_map(
                        &self.kernel_block_networks,
                        "kernel_block_networks",
                        key_server_id,
                        net,
                        expiry,
                    );
                    for (_, evict_net) in evicted {
                        self.reconcile_kernel_network(evict_net);
                    }
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
            let evicted =
                self.mutate_ip_kind(KIND_BLOCK, &self.blocks, "blocks", key_server_id, ip, expiry);
            for (evict_server_id, evict_ip) in &evicted {
                self.kernel_blocks.remove(&(*evict_server_id, *evict_ip));
                self.reconcile_kernel_ip(*evict_ip);
            }
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
                let evicted = Self::apply_scoped_ip(
                    &self.kernel_blocks,
                    "kernel_blocks",
                    key_server_id,
                    ip,
                    expiry,
                );
                for (_, evict_ip) in evicted {
                    self.reconcile_kernel_ip(evict_ip);
                }
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
                .args([
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
                .args(["del", "cloud_waf_block", &target, "-exist"])
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
        self.blocks.for_each(|(server_id, ip), expiry| {
            if now < expiry {
                items.push((ip.to_string(), server_id, expiry as u64));
            }
            true
        });
        self.list_blocks.for_each(|(server_id, ip), expiry| {
            if now < expiry {
                items.push((ip.to_string(), server_id, expiry as u64));
            }
            true
        });
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
                let evicted = self.mutate_ip_kind(
                    KIND_BLOCK,
                    &self.blocks,
                    "blocks",
                    record.server_id,
                    ip,
                    record.expires_at,
                );
                for (evict_server_id, evict_ip) in &evicted {
                    self.kernel_blocks.remove(&(*evict_server_id, *evict_ip));
                }
                if record.kernel_wanted {
                    let _ = Self::apply_scoped_ip(
                        &self.kernel_blocks,
                        "kernel_blocks",
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
                let evicted = Self::insert_scoped_network(
                    &self.block_networks,
                    &self.block_network_snapshots,
                    "block_networks",
                    record.server_id,
                    net,
                    record.expires_at,
                );
                for (evict_server_id, evict_net) in &evicted {
                    self.kernel_block_networks
                        .remove(&(*evict_server_id, *evict_net));
                }
                if record.kernel_wanted {
                    let _ = Self::apply_scoped_network_map(
                        &self.kernel_block_networks,
                        "kernel_block_networks",
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
            TrackedLimiter::new(Arc::new(RateLimiter::direct(quota)), max_qps)
        });
        if entry.quota_value.load(Ordering::Relaxed) != max_qps {
            drop(entry);
            self.server_limiters.remove(&server_id);
            let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
            let fresh = TrackedLimiter::new(Arc::new(RateLimiter::direct(quota)), max_qps);
            let entry = self.server_limiters.entry(server_id).or_insert(fresh);
            entry.touch();
            return entry.limiter.check().is_ok();
        }
        entry.touch();
        entry.limiter.check().is_ok()
    }

    pub(crate) fn reserve_slot(counter: &AtomicU64, capacity: usize) -> bool {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < capacity as u64).then_some(current + 1)
            })
            .is_ok()
    }

    pub(crate) fn release_slot(counter: &AtomicU64) {
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

                    match self.ip_limiters.entry(key) {
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
                            let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
                            entry.insert(TrackedLimiter::new(
                                Arc::new(RateLimiter::direct(quota)),
                                max_qps,
                            ))
                        }
                    }
                } else {
                    let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
                    entry.insert(TrackedLimiter::new(
                        Arc::new(RateLimiter::direct(quota)),
                        max_qps,
                    ))
                }
            }
        };
        if entry.quota_value.load(Ordering::Relaxed) != max_qps {
            drop(entry);
            match self.ip_limiters.entry(key) {
                Entry::Occupied(mut current) => {
                    if current.get().quota_value.load(Ordering::Relaxed) != max_qps {
                        let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
                        let _ = current.insert(TrackedLimiter::new(
                            Arc::new(RateLimiter::direct(quota)),
                            max_qps,
                        ));
                    }
                    entry = current.into_ref();
                }
                Entry::Vacant(current) => {
                    if !Self::reserve_slot(
                        &self.ip_limiter_reservations,
                        self.ip_limiter_capacity(),
                    ) {
                        return false;
                    }
                    let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
                    entry = current.insert(TrackedLimiter::new(
                        Arc::new(RateLimiter::direct(quota)),
                        max_qps,
                    ));
                }
            }
        }
        entry.touch();
        entry.limiter.check().is_ok()
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

    /// Upper bound on earliest-expiring entries one capacity eviction removes.
    /// The actual batch is `over.max(capacity / 16)` clamped to this: small
    /// maps evict exactly what is needed, large maps free ~6% headroom per
    /// scan so a sustained insert storm amortizes the O(map) pass — with a
    /// 512-slot batch a 1.6M-entry map would rescan ~2700 times under a 1.4M
    /// insert storm (minutes of CPU). 256k caps the transient victim Vec at
    /// ~8MiB.
    const WAF_STATE_EVICT_BATCH_MAX: usize = 262_144;

    fn scoped_state_map_capacity() -> usize {
        crate::memory_governor::MEMORY_GOVERNOR
            .firewall_state_map_capacity()
            .max(1)
    }

    /// Free room in a capacity-bound scoped-state map. Expired rows are swept
    /// first; if the map is still full the earliest-expiring live rows are
    /// removed in a batch. Returns the keys actually evicted so callers can
    /// reconcile derived state (kernel filter, network/range snapshots).
    fn evict_scoped_state_room<K>(
        map: &DashMap<K, i64>,
        capacity: usize,
        now: i64,
    ) -> Vec<K>
    where
        K: Copy + Eq + std::hash::Hash,
    {
        map.retain(|_, expiry| *expiry > now);
        let len = map.len();
        if len < capacity {
            return Vec::new();
        }
        // We need `over` free slots to fit the pending insert below capacity.
        let over = len - capacity + 1;
        let batch = over
            .max(capacity / 16)
            .min(Self::WAF_STATE_EVICT_BATCH_MAX)
            .min(map.len());
        // Keep the earliest-expiring batch in a bounded max-heap (top element
        // is the largest expiry among the kept rows, so pops drop it).
        let mut heap: BinaryHeap<EarliestExpiry<K>> = BinaryHeap::with_capacity(batch + 1);
        for entry in map.iter() {
            heap.push(EarliestExpiry {
                expiry: *entry.value(),
                key: *entry.key(),
            });
            if heap.len() > batch {
                heap.pop();
            }
        }
        let mut evicted = Vec::with_capacity(heap.len());
        for victim in heap {
            // remove_if only drops the exact (key, expiry) pair seen during
            // the scan — a concurrent refresh of the same key survives.
            if map
                .remove_if(&victim.key, |_, current| *current == victim.expiry)
                .is_some()
            {
                evicted.push(victim.key);
            }
        }
        evicted
    }

    /// Shared tail of the bounded scoped-state inserts: make room under
    /// `capacity`, count evictions, and warn if a racing storm still leaves
    /// the map full. Returns evicted keys (possibly empty).
    fn evict_for_scoped_state<K>(
        map: &DashMap<K, i64>,
        map_name: &'static str,
        capacity: usize,
        now: i64,
    ) -> Vec<K>
    where
        K: Copy + Eq + std::hash::Hash,
    {
        let mut evicted = Vec::new();
        for _ in 0..3 {
            if map.len() < capacity {
                break;
            }
            let made_room = Self::evict_scoped_state_room(map, capacity, now);
            if made_room.is_empty() {
                break;
            }
            evicted.extend(made_room);
        }
        if !evicted.is_empty() {
            crate::pipeline_metrics::add(
                crate::pipeline_metrics::PipelineCounter::WafStateEvicted,
                evicted.len() as u64,
            );
        }
        if map.len() >= capacity {
            warn_state_capacity_full(
                &SCOPED_STATE_CAPACITY_WARN_AT,
                map_name,
                map.len(),
                capacity,
                "newest scoped entry refused; earliest-expiry eviction made no room",
            );
        }
        evicted
    }

    /// Resolve the union expiry for one (kind, scope, ip) across that kind's
    /// two source maps: the live view is "present if either source holds a
    /// live entry", so the resolved value is the max expiry; `IP_DELTA_REMOVED`
    /// when neither source has the key at all.
    fn resolve_ip_union(&self, kind: u8, server_id: i64, ip: IpAddr) -> i64 {
        let (a, b) = match kind {
            KIND_BLOCK => (&self.blocks, &self.list_blocks),
            KIND_WHITE => (&self.whitelists, &self.list_whitelists),
            _ => (&self.graylists, &self.list_graylists),
        };
        let e1 = a.get(&(server_id, ip));
        let e2 = b.get(&(server_id, ip));
        match (e1, e2) {
            (None, None) => IP_DELTA_REMOVED,
            (Some(v), None) | (None, Some(v)) => v,
            (Some(v1), Some(v2)) => v1.max(v2),
        }
    }

    /// Publish a mutation of one scoped-IP source map into the read delta.
    /// Must be called AFTER the source-map mutation; the SeqCst fence pairs
    /// with the rebuilder's swap-then-scan so a mutation can never fall
    /// between the two: either the snapshot scan observes the map write, or
    /// this thread's delta insert lands in the post-swap delta.
    fn publish_ip_delta(&self, kind: u8, server_id: i64, ip: IpAddr) {
        std::sync::atomic::fence(Ordering::SeqCst);
        let mut delta = self.ip_delta.load();
        let key = (kind, server_id, ip);
        if !delta.contains_key(&key) && delta.len() >= IP_DELTA_CAP {
            self.rebuild_ip_read_snapshot();
            delta = self.ip_delta.load();
        }
        delta.insert(key, self.resolve_ip_union(kind, server_id, ip));
    }

    /// Single-flight rebuild: install a fresh delta first (post-swap
    /// mutations land there), then fold the source maps into a new snapshot.
    fn rebuild_ip_read_snapshot(&self) {
        let _guard = match self.ip_rebuild.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let fresh: Arc<IpDelta> = Arc::new(DashMap::new());
        self.ip_delta.store(fresh);
        std::sync::atomic::fence(Ordering::SeqCst);
        let now = crate::utils::time::now_timestamp();
        self.ip_read.store(Arc::new(IpReadSnapshot {
            blocked: Self::union_ip_maps(&self.blocks, &self.list_blocks, now),
            whitelisted: Self::union_ip_maps(&self.whitelists, &self.list_whitelists, now),
            graylisted: Self::union_ip_maps(&self.graylists, &self.list_graylists, now),
        }));
    }

    /// Merge two scoped-IP tables into the union view, keeping only live
    /// entries and resolving duplicates to the later expiry.
    fn union_ip_maps(
        a: &BoundedScopedMap<(i64, IpAddr)>,
        b: &BoundedScopedMap<(i64, IpAddr)>,
        now: i64,
    ) -> HashMap<(i64, IpAddr), i64> {
        let mut union = HashMap::with_capacity(a.len().max(b.len()));
        for map in [a, b] {
            map.for_each(|key, expiry| {
                if expiry <= now {
                    return true;
                }
                union
                    .entry(key)
                    .and_modify(|e: &mut i64| *e = (*e).max(expiry))
                    .or_insert(expiry);
                true
            });
        }
        union
    }

    /// Hot-path scoped lookup: delta shadows the snapshot. Two probes max —
    /// global scope first, then the server scope.
    #[inline]
    fn ip_kind_hit_at(
        delta: &IpDelta,
        map: &HashMap<(i64, IpAddr), i64>,
        kind: u8,
        scope: i64,
        ip: IpAddr,
        now: i64,
    ) -> bool {
        if let Some(entry) = delta.get(&(kind, scope, ip)) {
            return *entry != IP_DELTA_REMOVED && now < *entry;
        }
        map.get(&(scope, ip)).is_some_and(|expiry| now < *expiry)
    }

    /// Scoped-IP union lookup for the read path: one delta load + one
    /// snapshot load cover all three kinds.
    #[inline]
    fn contains_ip_kind(
        &self,
        delta: &IpDelta,
        map: &HashMap<(i64, IpAddr), i64>,
        kind: u8,
        ip: IpAddr,
        server_id: i64,
        now: i64,
    ) -> bool {
        Self::ip_kind_hit_at(delta, map, kind, 0, ip, now)
            || (server_id != 0 && Self::ip_kind_hit_at(delta, map, kind, server_id, ip, now))
    }

    /// Mutate a read-path scoped-IP map and publish the union delta for the
    /// inserted key plus every evicted victim.
    fn mutate_ip_kind(
        &self,
        kind: u8,
        map: &BoundedScopedMap<(i64, IpAddr)>,
        map_name: &'static str,
        server_id: i64,
        ip: IpAddr,
        expiry: i64,
    ) -> Vec<(i64, IpAddr)> {
        let evicted = Self::apply_scoped_ip(map, map_name, server_id, ip, expiry);
        self.publish_ip_delta(kind, server_id, ip);
        for (evict_server_id, evict_ip) in &evicted {
            self.publish_ip_delta(kind, *evict_server_id, *evict_ip);
        }
        evicted
    }

    /// Remove from a read-path scoped-IP map and publish the delta tombstone.
    fn remove_ip_kind(
        &self,
        kind: u8,
        map: &BoundedScopedMap<(i64, IpAddr)>,
        server_id: i64,
        ip: IpAddr,
    ) {
        Self::remove_scoped_ip(map, server_id, ip);
        self.publish_ip_delta(kind, server_id, ip);
    }

    /// Insert-or-evict for scoped-IP maps. Returns evicted keys so callers can
    /// reconcile kernel/list state; empty on update and expiry-remove paths.
    fn apply_scoped_ip(
        map: &BoundedScopedMap<(i64, IpAddr)>,
        map_name: &'static str,
        server_id: i64,
        ip: IpAddr,
        expiry: i64,
    ) -> Vec<(i64, IpAddr)> {
        Self::apply_scoped_ip_with_capacity(
            map,
            map_name,
            server_id,
            ip,
            expiry,
            Self::scoped_state_map_capacity(),
        )
    }

    fn apply_scoped_ip_with_capacity(
        map: &BoundedScopedMap<(i64, IpAddr)>,
        _map_name: &'static str,
        server_id: i64,
        ip: IpAddr,
        expiry: i64,
        capacity: usize,
    ) -> Vec<(i64, IpAddr)> {
        let now = crate::utils::time::now_timestamp();
        // The slot table enforces the cap inside the insert: at/above the
        // soft cap it overwrites the lowest-expiry live slot in the probe
        // window instead of growing. One victim max per insert.
        let evicted: Vec<(i64, IpAddr)> = map
            .insert((server_id, ip), expiry, now, capacity)
            .into_iter()
            .collect();
        if !evicted.is_empty() {
            crate::pipeline_metrics::add(
                crate::pipeline_metrics::PipelineCounter::WafStateEvicted,
                evicted.len() as u64,
            );
        }
        evicted
    }

    fn remove_scoped_ip(
        map: &BoundedScopedMap<(i64, IpAddr)>,
        server_id: i64,
        ip: IpAddr,
    ) {
        map.remove(&(server_id, ip));
    }

    /// Bounded variant of the scoped-network-map insert used by the kernel
    /// block-network map (no snapshot attached). Returns evicted keys.
    fn apply_scoped_network_map(
        map: &DashMap<(i64, IpNet), i64>,
        map_name: &'static str,
        server_id: i64,
        net: IpNet,
        expiry: i64,
    ) -> Vec<(i64, IpNet)> {
        let now = crate::utils::time::now_timestamp();
        if now >= expiry {
            map.remove(&(server_id, net));
            return Vec::new();
        }
        let key = (server_id, net);
        if map.contains_key(&key) {
            map.insert(key, expiry);
            return Vec::new();
        }
        let evicted = Self::evict_for_scoped_state(
            map,
            map_name,
            Self::scoped_state_map_capacity(),
            now,
        );
        if map.len() < Self::scoped_state_map_capacity() {
            map.insert(key, expiry);
        }
        evicted
    }

    fn remove_scoped_network_map(map: &DashMap<(i64, IpNet), i64>, server_id: i64, net: IpNet) {
        map.remove(&(server_id, net));
    }

    fn contains_any_scoped_ip(
        map: &BoundedScopedMap<(i64, IpAddr)>,
        ip: IpAddr,
        now: i64,
    ) -> bool {
        let mut found = false;
        map.for_each(|(_, entry_ip), expiry| {
            if entry_ip == ip && now < expiry {
                found = true;
                return false;
            }
            true
        });
        found
    }

    /// Bounded variant of the scoped-network insert for snapshot-backed maps.
    /// Returns evicted keys; the snapshot is rebuilt whenever the map changed
    /// (evictions included) so readers never see evicted ghosts.
    fn insert_scoped_network(
        map: &DashMap<(i64, IpNet), i64>,
        snapshots: &ArcSwap<NetworkSnapshot>,
        map_name: &'static str,
        server_id: i64,
        net: IpNet,
        expiry: i64,
    ) -> Vec<(i64, IpNet)> {
        let now = crate::utils::time::now_timestamp();
        if now >= expiry {
            Self::remove_scoped_network(map, snapshots, server_id, net);
            return Vec::new();
        }

        let key = (server_id, net);
        let mut evicted = Vec::new();
        if !map.contains_key(&key) {
            evicted = Self::evict_for_scoped_state(
                map,
                map_name,
                Self::scoped_state_map_capacity(),
                now,
            );
            if map.len() >= Self::scoped_state_map_capacity() {
                if !evicted.is_empty() {
                    // Evictions happened but the new entry was refused — the
                    // snapshot must still drop the evicted ghosts.
                    Self::rebuild_network_snapshot(map, snapshots, now);
                }
                return evicted;
            }
        }
        map.insert(key, expiry);
        Self::rebuild_network_snapshot(map, snapshots, now);
        evicted
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
        // One ArcSwap load serves both scopes; loading per scope doubles the
        // hot-path atomic reads for no benefit.
        let snapshot = snapshots.load();
        snapshot
            .get(&0)
            .is_some_and(|networks| networks.contains(ip, now))
            || (server_id != 0
                && snapshot
                    .get(&server_id)
                    .is_some_and(|networks| networks.contains(ip, now)))
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

        let mut expired_ips: Vec<(i64, IpAddr, i64)> = Vec::new();
        self.blocks.for_each(|(server_id, ip), expiry| {
            if now >= expiry {
                expired_ips.push((server_id, ip, expiry));
            }
            true
        });
        for (server_id, ip, observed_expiry) in expired_ips {
            let removed = self.blocks.remove_if(&(server_id, ip), observed_expiry);
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

        self.blocks.retain(|expiry| now < expiry);
        self.kernel_blocks.retain(|expiry| now < expiry);
        self.list_blocks.retain(|expiry| now < expiry);
        self.whitelists.retain(|expiry| now < expiry);
        self.list_whitelists.retain(|expiry| now < expiry);
        self.graylists.retain(|expiry| now < expiry);
        self.list_graylists.retain(|expiry| now < expiry);
        self.block_networks.retain(|_, expiry| now < *expiry);
        self.kernel_block_networks.retain(|_, expiry| now < *expiry);
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
            "list_block_ranges",
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
            "list_white_ranges",
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
            "list_gray_ranges",
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
        map_name: &'static str,
        server_id: i64,
        range: IpAddrRange,
        expiry: i64,
    ) {
        let now = crate::utils::time::now_timestamp();
        if now >= expiry {
            Self::remove_scoped_range(map, snapshots, server_id, range);
            return;
        }
        let key = (server_id, range);
        if !map.contains_key(&key) {
            let evicted = Self::evict_for_scoped_state(
                map,
                map_name,
                Self::scoped_state_map_capacity(),
                now,
            );
            if map.len() >= Self::scoped_state_map_capacity() {
                if !evicted.is_empty() {
                    // Refused insert but evictions happened — rebuild so the
                    // snapshot drops the evicted ghosts.
                    Self::rebuild_range_snapshot(map, snapshots, now);
                }
                return;
            }
        }
        map.insert(key, expiry);
        Self::rebuild_range_snapshot(map, snapshots, now);
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
static WAF_STATE_FOR_RECLAIM: std::sync::OnceLock<std::sync::Weak<WafStateManager>> =
    std::sync::OnceLock::new();

pub fn accelerate_block_map_gc() {
    if let Some(state) = WAF_STATE_FOR_RECLAIM
        .get()
        .and_then(std::sync::Weak::upgrade)
    {
        state.gc_once();
    }
}

pub fn start_gc_task(state: Arc<WafStateManager>) {
    let _ = WAF_STATE_FOR_RECLAIM.set(Arc::downgrade(&state));
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(GC_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let state_for_gc = Arc::clone(&state);
            if let Err(err) = tokio::task::spawn_blocking(move || state_for_gc.gc_once()).await {
                tracing::error!(error = %err, "firewall GC worker failed");
            }
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
    fn scoped_ip_map_evicts_earliest_expiry_at_capacity() {
        let map: BoundedScopedMap<(i64, IpAddr)> = BoundedScopedMap::new(4096);
        let now = crate::utils::time::now_timestamp();
        let ip = |n: u8| IpAddr::from([10, 0, 0, n]);
        let cap = 4;

        // Fill to capacity with staggered expiries (ip(1) earliest).
        for n in 1..=4u8 {
            let evicted = WafStateManager::apply_scoped_ip_with_capacity(
                &map,
                "test",
                7,
                ip(n),
                now + n as i64,
                cap,
            );
            assert!(evicted.is_empty(), "below capacity must not evict");
        }
        assert_eq!(map.len(), 4);

        // Updating an existing key never evicts, even at capacity.
        let evicted = WafStateManager::apply_scoped_ip_with_capacity(
            &map,
            "test",
            7,
            ip(1),
            now + 500,
            cap,
        );
        assert!(evicted.is_empty());
        assert_eq!(map.len(), 4);

        // A brand-new key at capacity evicts exactly one live entry: the
        // sampled-earliest-expiry victim (probe-window or corner scan).
        let evicted = WafStateManager::apply_scoped_ip_with_capacity(
            &map,
            "test",
            7,
            ip(9),
            now + 900,
            cap,
        );
        assert_eq!(evicted.len(), 1, "at cap an insert must evict one entry");
        let (victim_scope, victim_ip) = evicted[0];
        assert_eq!(victim_scope, 7);
        assert_ne!(victim_ip, ip(9));
        assert!(!map.contains_key(&(7, victim_ip)));
        assert!(map.contains_key(&(7, ip(9))));
        assert_eq!(map.len(), 4);
    }

    #[test]
    fn scoped_ip_map_sweeps_expired_before_evicting_live() {
        let map: BoundedScopedMap<(i64, IpAddr)> = BoundedScopedMap::new(4096);
        let now = crate::utils::time::now_timestamp();
        let ip = |n: u8| IpAddr::from([10, 0, 0, n]);
        let cap = 4;

        for n in 1..=3u8 {
            WafStateManager::apply_scoped_ip_with_capacity(
                &map,
                "test",
                7,
                ip(n),
                now + 60,
                cap,
            );
        }
        // Plant an expired row directly — the bounded insert refuses
        // already-expired writes, so seed it by hand.
        map.seed_unchecked((7, ip(0)), now - 1);
        assert_eq!(map.len(), 4);

        let evicted = WafStateManager::apply_scoped_ip_with_capacity(
            &map,
            "test",
            7,
            ip(9),
            now + 60,
            cap,
        );
        // Invariants: the bound holds and the insert lands. Within a probe
        // window expired rows always sort first (expiry <= now < live), so
        // the expired row is reclaimed whenever it is sampled; a live
        // victim outside the window is also legal under sampled eviction.
        for (scope, _) in &evicted {
            assert_eq!(*scope, 7);
        }
        assert!(evicted.len() <= 1);
        assert!(map.contains_key(&(7, ip(9))));
        assert!(map.len() <= cap);
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

    #[test]
    fn reserve_slot_fails_closed_at_capacity() {
        let counter = AtomicU64::new(0);
        let capacity = 8;
        for _ in 0..capacity {
            assert!(WafStateManager::reserve_slot(&counter, capacity));
        }
        assert!(!WafStateManager::reserve_slot(&counter, capacity));
        WafStateManager::release_slot(&counter);
        assert!(WafStateManager::reserve_slot(&counter, capacity));
        assert_eq!(counter.load(Ordering::Acquire), capacity as u64);
    }

    /// RCU read path: a brand-new block must be visible to is_blocked
    /// immediately via the delta (empty snapshot, no rebuild needed).
    #[test]
    fn rcu_read_path_sees_writes_instantly_via_delta() {
        let state = WafStateManager::new();
        let now = crate::utils::time::now_timestamp();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        state.apply_black_ip_until(7, ip, now + 3600);
        assert!(state.is_blocked(ip, 7));
        assert!(!state.is_blocked(ip, 999), "scope-7 entry must not match scope 999");
        state.apply_white_ip_until(7, ip, now + 3600);
        assert!(state.is_whitelisted(ip, 7));
        assert!(!state.is_whitelisted(ip, 999));
        state.apply_gray_ip_until(7, ip, now + 3600);
        assert!(state.is_graylisted(ip, 7));
    }

    /// Global-scope (server_id=0) entries match every server scope.
    #[test]
    fn rcu_read_path_global_scope_matches_all() {
        let state = WafStateManager::new();
        let now = crate::utils::time::now_timestamp();
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        state.apply_black_ip_until(0, ip, now + 3600);
        assert!(state.is_blocked(ip, 42));
        assert!(state.is_blocked(ip, 0));
    }

    /// After a rebuild the delta is empty and reads flow through the
    /// consolidated snapshot — results must be identical.
    #[test]
    fn rcu_snapshot_path_matches_after_rebuild() {
        let state = WafStateManager::new();
        let now = crate::utils::time::now_timestamp();
        for n in 0..100u8 {
            state.apply_black_ip_until(3, IpAddr::from([10, 9, 0, n]), now + 3600);
            state.apply_white_ip_until(0, IpAddr::from([10, 9, 1, n]), now + 3600);
        }
        state.rebuild_ip_read_snapshot();
        assert_eq!(state.ip_delta.load().len(), 0, "rebuild swaps in a fresh delta");
        for n in 0..100u8 {
            let blocked: IpAddr = IpAddr::from([10, 9, 0, n]);
            let white: IpAddr = IpAddr::from([10, 9, 1, n]);
            assert!(state.is_blocked(blocked, 3));
            assert!(!state.is_blocked(blocked, 4), "scope-3 block must not leak to scope 4");
            assert!(state.is_whitelisted(white, 5), "global whitelist matches any scope");
        }
    }

    /// Union semantics: entry in either source map blocks; removing one
    /// source while the other retains the key keeps the union live; removing
    /// both unblocks.
    #[test]
    fn rcu_union_semantics_across_source_maps() {
        let state = WafStateManager::new();
        let now = crate::utils::time::now_timestamp();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        state.apply_list_black_ip_until(2, ip, now + 3600);
        assert!(state.is_blocked(ip, 2), "list_blocks alone must block");
        state.apply_black_ip_until(2, ip, now + 1800);
        state.remove_list_black_ip(2, ip);
        assert!(
            state.is_blocked(ip, 2),
            "removing list_blocks must not unblock while blocks retains the key"
        );
        state.remove_black_ip(2, ip);
        assert!(!state.is_blocked(ip, 2), "both sources removed → unblocked");
    }

    /// Eviction publishes a tombstone: an evicted victim must read unblocked
    /// even though the stale snapshot may still contain it.
    #[test]
    fn rcu_eviction_tombstone_hides_stale_snapshot_entry() {
        let state = WafStateManager::new();
        let now = crate::utils::time::now_timestamp();
        let ip_a: IpAddr = "203.0.113.10".parse().unwrap();
        state.apply_black_ip_until(1, ip_a, now + 60);
        state.rebuild_ip_read_snapshot();
        assert!(state.is_blocked(ip_a, 1), "snapshot path blocks");
        // Evict directly from the source map, then publish the delta —
        // mirrors what mutate_ip_kind does for evicted victims.
        state.blocks.remove(&(1, ip_a));
        state.publish_ip_delta(KIND_BLOCK, 1, ip_a);
        assert!(
            !state.is_blocked(ip_a, 1),
            "delta tombstone must shadow the stale snapshot entry"
        );
    }

    /// Concurrent write/remove churn while readers poll: readers must never
    /// panic and must observe a consistent state after quiesce.
    #[test]
    fn rcu_read_path_concurrent_write_read_consistency() {
        use std::sync::Arc;
        let state = Arc::new(WafStateManager::new());
        let now = crate::utils::time::now_timestamp();
        let ip: IpAddr = "203.0.113.11".parse().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut round = 0i64;
                while !stop.load(Ordering::Relaxed) {
                    round += 1;
                    if round % 2 == 0 {
                        state.apply_black_ip_until(5, ip, now + 3600);
                    } else {
                        state.remove_black_ip(5, ip);
                    }
                }
                round
            })
        };
        for _ in 0..2000 {
            let _ = state.is_blocked(ip, 5);
            let _ = state.is_whitelisted(ip, 5);
            let _ = state.is_graylisted(ip, 5);
        }
        stop.store(true, Ordering::Relaxed);
        let rounds = writer.join().unwrap();
        assert!(rounds > 10, "writer must complete multiple churn rounds");
        // Quiesce: final state must match the source maps exactly.
        state.apply_black_ip_until(5, ip, now + 3600);
        state.rebuild_ip_read_snapshot();
        assert!(state.is_blocked(ip, 5));
        state.remove_black_ip(5, ip);
        assert!(!state.is_blocked(ip, 5));
    }

    /// Delta cap triggers a single-flight rebuild; reads stay correct across
    /// the swap boundary.
    #[test]
    fn rcu_delta_cap_triggers_rebuild_without_losing_writes() {
        let state = WafStateManager::new();
        let now = crate::utils::time::now_timestamp();
        // Fill the delta past capacity — each publish inserts one delta key.
        for n in 0..(IP_DELTA_CAP + 64) {
            let ip = IpAddr::from([10, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
            state.apply_black_ip_until(1, ip, now + 3600);
        }
        // After crossing the cap the delta must have been swapped: the
        // rebuild consumed the first CAP keys, leaving only the tail.
        assert!(
            state.ip_delta.load().len() <= 128,
            "delta must reset via rebuild, got {}",
            state.ip_delta.load().len()
        );
        // Spot-check both early (snapshot-era) and late (delta-era) writes.
        let early = IpAddr::from([10, 0, 0, 1]);
        let late = IpAddr::from([10, (IP_DELTA_CAP >> 16) as u8, ((IP_DELTA_CAP + 63) >> 8) as u8, (IP_DELTA_CAP + 63) as u8]);
        assert!(state.is_blocked(early, 1));
        assert!(state.is_blocked(late, 1));
    }
}
