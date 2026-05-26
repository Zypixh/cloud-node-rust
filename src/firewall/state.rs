use arc_swap::ArcSwap;
use dashmap::DashMap;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use crate::firewall::kernel::{KernelFilter, NoopFilter};

pub struct CandidateRulesetStats {
    pub hits: AtomicU64,
    pub blocks: AtomicU64,
    pub observed: AtomicU64,
}

impl CandidateRulesetStats {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
            observed: AtomicU64::new(0),
        }
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
}

const GC_INTERVAL_SECS: u64 = 60;
/// Idle threshold for rate-limiter GC. Set to 90 s (down from 300 s) to shrink
/// the window in which an adversary can exploit the "fresh bucket on re-entry"
/// semantic: at 90 s they must sustain near-legitimate request rates to keep
/// limiters alive, making periodic burst bypass impractical.
/// Acceptable trade-off: benign long-tail sessions see their per-IP limiter
/// reconstructed slightly more often, but quota enforcement is unaffected.
const LIMITER_IDLE_SECS: i64 = 90;

/// Wraps a RateLimiter with a last-seen timestamp for GC and the QPS value the
/// quota was built from, so hot-reload can detect and replace stale limiters.
pub(crate) struct TrackedLimiter<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static> {
    pub limiter: Arc<RateLimiter<K, DashMapStateStore<K>, DefaultClock>>,
    pub last_seen: AtomicI64,
    /// The QPS value baked into `limiter`'s Quota at construction time.
    pub quota_value: AtomicU32,
}

impl<K: std::hash::Hash + Eq + Clone + Send + Sync + 'static> TrackedLimiter<K> {
    fn new(limiter: Arc<RateLimiter<K, DashMapStateStore<K>, DefaultClock>>, quota_value: u32) -> Self {
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

const ROLLING_COUNTER_BUCKETS: usize = 256;
const COUNTER_SWEEP_INTERVAL_SECS: i64 = 60;
const COUNTER_MAX_PERIOD_SECS: i64 = 7 * 86_400;

type NetworkSnapshot = HashMap<i64, Arc<Vec<(IpNet, i64)>>>;

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

        self.buckets[self.current_slot] = self.buckets[self.current_slot].saturating_add(1);
        self.total = self.total.saturating_add(1);
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
    pub block_networks: DashMap<(i64, IpNet), i64>,
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
    counters: DashMap<String, RollingCounter>,
    counter_last_sweep: AtomicI64,
    list_block_ranges: DashMap<(i64, IpAddrRange), i64>,
    list_white_ranges: DashMap<(i64, IpAddrRange), i64>,
    list_gray_ranges: DashMap<(i64, IpAddrRange), i64>,
    ip_bw_counters: DashMap<(i64, IpAddr), Arc<(AtomicU64, AtomicU64)>>,
    kernel_filter: RwLock<Arc<dyn KernelFilter>>,
    pub candidate_stats: DashMap<(i64, i64), Arc<CandidateRulesetStats>>,
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
            block_networks: DashMap::new(),
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
            counters: DashMap::new(),
            counter_last_sweep: AtomicI64::new(0),
            list_block_ranges: DashMap::new(),
            list_white_ranges: DashMap::new(),
            list_gray_ranges: DashMap::new(),
            ip_bw_counters: DashMap::with_shard_amount(64),
            kernel_filter: RwLock::new(Arc::new(NoopFilter)),
            candidate_stats: DashMap::new(),
        }
    }

    pub fn set_kernel_filter(&self, filter: Box<dyn KernelFilter>) {
        if let Ok(mut guard) = self.kernel_filter.write() {
            *guard = Arc::from(filter);
        }
    }

    fn kernel_filter(&self) -> Arc<dyn KernelFilter> {
        self.kernel_filter
            .read()
            .map(|guard| Arc::clone(&guard))
            .unwrap_or_else(|_| Arc::new(NoopFilter))
    }

    pub fn has_rules(&self) -> bool {
        !self.blocks.is_empty()
            || !self.block_networks.is_empty()
            || !self.list_blocks.is_empty()
            || !self.list_block_networks.is_empty()
            || !self.whitelists.is_empty()
            || !self.whitelist_networks.is_empty()
            || !self.list_whitelists.is_empty()
            || !self.list_whitelist_networks.is_empty()
            || !self.graylists.is_empty()
            || !self.gray_networks.is_empty()
            || !self.list_graylists.is_empty()
            || !self.list_gray_networks.is_empty()
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
            || Self::contains_scoped_range(&self.list_white_ranges, ip, server_id, now)
    }

    pub fn is_blocked(&self, ip: IpAddr, server_id: i64) -> bool {
        let ip = canonical_lookup_ip(ip);
        let now = crate::utils::time::now_timestamp();
        Self::contains_scoped_ip(&self.blocks, ip, server_id, now)
            || Self::contains_scoped_ip(&self.list_blocks, ip, server_id, now)
            || Self::contains_scoped_network(&self.block_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_network(&self.list_block_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_range(&self.list_block_ranges, ip, server_id, now)
    }

    pub fn is_graylisted(&self, ip: IpAddr, server_id: i64) -> bool {
        let ip = canonical_lookup_ip(ip);
        let now = crate::utils::time::now_timestamp();
        Self::contains_scoped_ip(&self.graylists, ip, server_id, now)
            || Self::contains_scoped_ip(&self.list_graylists, ip, server_id, now)
            || Self::contains_scoped_network(&self.gray_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_network(&self.list_gray_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_range(&self.list_gray_ranges, ip, server_id, now)
    }

    pub fn apply_black_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        Self::apply_scoped_ip(&self.blocks, server_id, ip, expiry);
    }

    pub fn apply_black_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.block_networks,
            &self.block_network_snapshots,
            server_id,
            net,
            expiry,
        );
    }

    pub fn remove_black_ip(&self, server_id: i64, ip: IpAddr) {
        Self::remove_scoped_ip(&self.blocks, server_id, ip);
    }

    pub fn remove_black_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.block_networks,
            &self.block_network_snapshots,
            server_id,
            net,
        );
    }

    pub fn apply_list_black_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        Self::apply_scoped_ip(&self.list_blocks, server_id, ip, expiry);
    }

    pub fn apply_list_black_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.list_block_networks,
            &self.list_block_network_snapshots,
            server_id,
            net,
            expiry,
        );
    }

    pub fn remove_list_black_ip(&self, server_id: i64, ip: IpAddr) {
        Self::remove_scoped_ip(&self.list_blocks, server_id, ip);
    }

    pub fn remove_list_black_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.list_block_networks,
            &self.list_block_network_snapshots,
            server_id,
            net,
        );
    }

    pub fn apply_white_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        Self::apply_scoped_ip(&self.whitelists, server_id, ip, expiry);
    }

    pub fn apply_white_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.whitelist_networks,
            &self.whitelist_network_snapshots,
            server_id,
            net,
            expiry,
        );
    }

    pub fn remove_white_ip(&self, server_id: i64, ip: IpAddr) {
        Self::remove_scoped_ip(&self.whitelists, server_id, ip);
    }

    pub fn remove_white_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.whitelist_networks,
            &self.whitelist_network_snapshots,
            server_id,
            net,
        );
    }

    pub fn apply_list_white_ip_until(&self, server_id: i64, ip: IpAddr, expiry: i64) {
        Self::apply_scoped_ip(&self.list_whitelists, server_id, ip, expiry);
    }

    pub fn apply_list_white_network_until(&self, server_id: i64, net: IpNet, expiry: i64) {
        Self::insert_scoped_network(
            &self.list_whitelist_networks,
            &self.list_whitelist_network_snapshots,
            server_id,
            net,
            expiry,
        );
    }

    pub fn remove_list_white_ip(&self, server_id: i64, ip: IpAddr) {
        Self::remove_scoped_ip(&self.list_whitelists, server_id, ip);
    }

    pub fn remove_list_white_network(&self, server_id: i64, net: IpNet) {
        Self::remove_scoped_network(
            &self.list_whitelist_networks,
            &self.list_whitelist_network_snapshots,
            server_id,
            net,
        );
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

    pub fn block_ip(
        &self,
        ip: IpAddr,
        server_id: i64,
        timeout_secs: i64,
        scope: Option<&str>,
        block_c_class: bool,
        use_local_firewall: bool,
    ) {
        let expiry = crate::utils::time::now_timestamp() + timeout_secs;
        let key_server_id = if matches!(scope, Some("global")) {
            0
        } else {
            server_id
        };

        if block_c_class {
            if let Ok(net) = self.get_c_class_net(ip) {
                self.apply_black_network_until(key_server_id, net, expiry);
                if use_local_firewall {
                    self.exec_local_firewall(net.to_string(), timeout_secs);
                }
            }
        } else {
            self.apply_black_ip_until(key_server_id, ip, expiry);
            if use_local_firewall {
                self.exec_local_firewall(ip.to_string(), timeout_secs);
            }
        }

        let kernel_filter = self.kernel_filter();
        if use_local_firewall && kernel_filter.available() && !block_c_class {
            kernel_filter.block(ip, timeout_secs);
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

    pub fn check_rate_limit(&self, server_id: i64, max_qps: u32) -> bool {
        if max_qps == 0 {
            return true;
        }
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

    pub fn check_ip_rate_limit(&self, server_id: i64, ip: IpAddr, max_qps: u32) -> bool {
        if max_qps == 0 {
            return true;
        }
        // Same quota hot-reload logic as check_rate_limit.
        let entry = self.ip_limiters.entry((server_id, ip)).or_insert_with(|| {
            let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
            TrackedLimiter::new(Arc::new(RateLimiter::dashmap(quota)), max_qps)
        });
        if entry.quota_value.load(Ordering::Relaxed) != max_qps {
            drop(entry);
            self.ip_limiters.remove(&(server_id, ip));
            let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
            let fresh = TrackedLimiter::new(Arc::new(RateLimiter::dashmap(quota)), max_qps);
            let entry = self.ip_limiters.entry((server_id, ip)).or_insert(fresh);
            entry.touch();
            return entry.limiter.check_key(&ip).is_ok();
        }
        entry.touch();
        entry.limiter.check_key(&ip).is_ok()
    }

    pub fn record_failure(&self, key: String) -> u64 {
        self.increase_counter(format!("FAIL:{}", key), 3600)
    }

    pub fn check_special_defense(&self, key: String, threshold: u32, period: i64) -> bool {
        let count = self.increase_counter(format!("SPECIAL:{}", key), period);
        count <= threshold as u64
    }

    pub fn increase_counter(&self, key: String, period_secs: i64) -> u64 {
        let now = crate::utils::time::now_timestamp();
        let period_secs = period_secs.clamp(1, COUNTER_MAX_PERIOD_SECS);
        self.sweep_counters(now);
        self.counters
            .entry(format!("{}:{}", period_secs, key))
            .or_default()
            .increment(now, period_secs)
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
        self.counters
            .retain(|_, counter| !counter.is_stale(now, COUNTER_MAX_PERIOD_SECS));
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
        let current = snapshots.load();
        let mut next = current.as_ref().clone();
        let mut networks = next
            .get(&server_id)
            .map(|items| {
                items
                    .iter()
                    .copied()
                    .filter(|(_, exp)| now < *exp)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        networks.retain(|(existing, _)| *existing != net);
        networks.push((net, expiry));
        next.insert(server_id, Arc::new(networks));
        snapshots.store(Arc::new(next));
    }

    fn remove_scoped_network(
        map: &DashMap<(i64, IpNet), i64>,
        snapshots: &ArcSwap<NetworkSnapshot>,
        server_id: i64,
        net: IpNet,
    ) {
        map.remove(&(server_id, net));
        let current = snapshots.load();
        let Some(items) = current.get(&server_id) else {
            return;
        };
        let mut next = current.as_ref().clone();
        let networks = items
            .iter()
            .copied()
            .filter(|(existing, _)| *existing != net)
            .collect::<Vec<_>>();
        if networks.is_empty() {
            next.remove(&server_id);
        } else {
            next.insert(server_id, Arc::new(networks));
        }
        snapshots.store(Arc::new(next));
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
        networks
            .iter()
            .any(|(net, expiry)| now < *expiry && net.contains(&ip))
    }

    /// Evict all expired entries from IP block/white/gray lists and idle rate limiters.
    pub fn gc_once(&self) {
        let now = crate::utils::time::now_timestamp();

        let kernel_filter = self.kernel_filter();
        if kernel_filter.available() {
            let expired: Vec<IpAddr> = self
                .blocks
                .iter()
                .filter_map(|e| (now >= *e.value()).then_some(e.key().1))
                .collect();
            for ip in expired {
                kernel_filter.unblock(ip);
            }
        }

        self.blocks.retain(|_, expiry| now < *expiry);
        self.list_blocks.retain(|_, expiry| now < *expiry);
        self.whitelists.retain(|_, expiry| now < *expiry);
        self.list_whitelists.retain(|_, expiry| now < *expiry);
        self.graylists.retain(|_, expiry| now < *expiry);
        self.list_graylists.retain(|_, expiry| now < *expiry);
        self.counters
            .retain(|_, counter| !counter.is_stale(now, COUNTER_MAX_PERIOD_SECS));

        self.server_limiters
            .retain(|_, tracked| !tracked.is_idle(now));
        self.ip_limiters
            .retain(|_, tracked| !tracked.is_idle(now));
        self.list_block_ranges.retain(|_, expiry| now < *expiry);
        self.list_white_ranges.retain(|_, expiry| now < *expiry);
        self.list_gray_ranges.retain(|_, expiry| now < *expiry);
        self.ip_bw_counters.retain(|_, entry| {
            let win = entry.1.load(Ordering::Relaxed);
            (now as u64).saturating_sub(win) < 120
        });
    }

    pub fn apply_list_black_range_until(&self, server_id: i64, range: IpAddrRange, expiry: i64) {
        Self::apply_scoped_range(&self.list_block_ranges, server_id, range, expiry);
    }

    pub fn remove_list_black_range(&self, server_id: i64, range: IpAddrRange) {
        self.list_block_ranges.remove(&(server_id, range));
    }

    pub fn apply_list_white_range_until(&self, server_id: i64, range: IpAddrRange, expiry: i64) {
        Self::apply_scoped_range(&self.list_white_ranges, server_id, range, expiry);
    }

    pub fn remove_list_white_range(&self, server_id: i64, range: IpAddrRange) {
        self.list_white_ranges.remove(&(server_id, range));
    }

    pub fn apply_list_gray_range_until(&self, server_id: i64, range: IpAddrRange, expiry: i64) {
        Self::apply_scoped_range(&self.list_gray_ranges, server_id, range, expiry);
    }

    pub fn remove_list_gray_range(&self, server_id: i64, range: IpAddrRange) {
        self.list_gray_ranges.remove(&(server_id, range));
    }

    fn apply_scoped_range(
        map: &DashMap<(i64, IpAddrRange), i64>,
        server_id: i64,
        range: IpAddrRange,
        expiry: i64,
    ) {
        if crate::utils::time::now_timestamp() >= expiry {
            map.remove(&(server_id, range));
        } else {
            map.insert((server_id, range), expiry);
        }
    }

    fn contains_scoped_range(
        map: &DashMap<(i64, IpAddrRange), i64>,
        ip: IpAddr,
        server_id: i64,
        now: i64,
    ) -> bool {
        map.iter().any(|entry| {
            let (sid, range) = entry.key();
            (*sid == 0 || *sid == server_id) && *entry.value() > now && range.contains(ip)
        })
    }

    /// Sliding-window per-IP byte counter for CC bandwidth enforcement.
    /// Returns `true` if the IP has exceeded `limit_bytes` in the current
    /// 1-second window (caller decides what to do on breach).
    pub fn check_ip_bandwidth(&self, server_id: i64, ip: IpAddr, bytes: u64, limit_bytes: u64) -> bool {
        if limit_bytes == 0 {
            return false;
        }
        let ip = canonical_lookup_ip(ip);
        let now_secs = crate::utils::time::now_timestamp() as u64;
        let entry = self
            .ip_bw_counters
            .entry((server_id, ip))
            .or_insert_with(|| Arc::new((AtomicU64::new(0), AtomicU64::new(now_secs))));
        let (byte_counter, window_start) = entry.as_ref();
        let win = window_start.load(Ordering::Relaxed);
        if now_secs > win
            && window_start
                .compare_exchange(win, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            byte_counter.store(bytes, Ordering::Relaxed);
            return false;
        }
        let total = byte_counter.fetch_add(bytes, Ordering::Relaxed) + bytes;
        total > limit_bytes
    }

    pub fn record_candidate_hit(&self, policy_id: i64, version: i64, blocked: bool, observed: bool) {
        let entry = self
            .candidate_stats
            .entry((policy_id, version))
            .or_insert_with(|| Arc::new(CandidateRulesetStats::new()));
        entry.hits.fetch_add(1, Ordering::Relaxed);
        if blocked {
            entry.blocks.fetch_add(1, Ordering::Relaxed);
        }
        if observed {
            entry.observed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn take_candidate_stats(&self) -> Vec<CandidateStatsSnapshot> {
        let keys: Vec<(i64, i64)> = self.candidate_stats.iter().map(|e| *e.key()).collect();
        keys.into_iter()
            .filter_map(|key| {
                self.candidate_stats.remove(&key).map(|(k, arc)| CandidateStatsSnapshot {
                    policy_id: k.0,
                    version: k.1,
                    hits: arc.hits.load(Ordering::Relaxed),
                    blocks: arc.blocks.load(Ordering::Relaxed),
                    observed: arc.observed.load(Ordering::Relaxed),
                })
            })
            .collect()
    }

    pub fn flush_to_disk(&self) {}
}

/// Spawn a background tokio task that runs GC on the WAF state every 60 seconds.
pub fn start_gc_task(state: Arc<WafStateManager>) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(GC_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            state.gc_once();
        }
    });
}
