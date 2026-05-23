use arc_swap::ArcSwap;
use dashmap::DashMap;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

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
    server_limiters: DashMap<i64, Arc<RateLimiter<i64, DashMapStateStore<i64>, DefaultClock>>>,
    ip_limiters:
        DashMap<(i64, IpAddr), Arc<RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>>>,
    counters: DashMap<String, RollingCounter>,
    counter_last_sweep: AtomicI64,
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
        }
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
    }

    pub fn is_blocked(&self, ip: IpAddr, server_id: i64) -> bool {
        let now = crate::utils::time::now_timestamp();
        Self::contains_scoped_ip(&self.blocks, ip, server_id, now)
            || Self::contains_scoped_ip(&self.list_blocks, ip, server_id, now)
            || Self::contains_scoped_network(&self.block_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_network(&self.list_block_network_snapshots, ip, server_id, now)
    }

    pub fn is_graylisted(&self, ip: IpAddr, server_id: i64) -> bool {
        let now = crate::utils::time::now_timestamp();
        Self::contains_scoped_ip(&self.graylists, ip, server_id, now)
            || Self::contains_scoped_ip(&self.list_graylists, ip, server_id, now)
            || Self::contains_scoped_network(&self.gray_network_snapshots, ip, server_id, now)
            || Self::contains_scoped_network(&self.list_gray_network_snapshots, ip, server_id, now)
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
    }

    fn exec_local_firewall(&self, target: String, timeout: i64) {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("ipset")
                .args(&[
                    "add",
                    "edge_waf_block",
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

        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.apply_white_ip_until(key_server_id, ip, expiry);
    }

    fn exec_local_unblock(&self, target: String) {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("ipset")
                .args(&["del", "edge_waf_block", &target, "-exist"])
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
        let limiter = self.server_limiters.entry(server_id).or_insert_with(|| {
            let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
            Arc::new(RateLimiter::dashmap(quota))
        });
        limiter.check_key(&server_id).is_ok()
    }

    pub fn check_ip_rate_limit(&self, server_id: i64, ip: IpAddr, max_qps: u32) -> bool {
        if max_qps == 0 {
            return true;
        }
        let limiter = self.ip_limiters.entry((server_id, ip)).or_insert_with(|| {
            let quota = Quota::per_second(NonZeroU32::new(max_qps).unwrap());
            Arc::new(RateLimiter::dashmap(quota))
        });
        limiter.check_key(&ip).is_ok()
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

    pub fn flush_to_disk(&self) {}
}
