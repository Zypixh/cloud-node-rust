use dashmap::DashMap;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use ipnet::IpNet;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

const ROLLING_COUNTER_BUCKETS: usize = 256;
const COUNTER_SWEEP_INTERVAL_SECS: i64 = 60;
const COUNTER_MAX_PERIOD_SECS: i64 = 7 * 86_400;

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
    pub block_networks: DashMap<(i64, IpNet), i64>, // Support CIDR/C-class blocks
    block_network_snapshots: RwLock<HashMap<i64, Arc<Vec<(IpNet, i64)>>>>,
    pub whitelists: DashMap<(i64, IpAddr), i64>,
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
            block_network_snapshots: RwLock::new(HashMap::new()),
            whitelists: DashMap::new(),
            server_limiters: DashMap::new(),
            ip_limiters: DashMap::new(),
            counters: DashMap::new(),
            counter_last_sweep: AtomicI64::new(0),
        }
    }

    pub fn has_rules(&self) -> bool {
        !self.whitelists.is_empty() || !self.blocks.is_empty() || !self.block_networks.is_empty()
    }

    pub fn is_whitelisted(&self, ip: IpAddr, server_id: i64) -> bool {
        if let Some(expiry) = self.whitelists.get(&(0, ip)) {
            if crate::utils::time::now_timestamp() < *expiry {
                return true;
            }
        }
        if let Some(expiry) = self.whitelists.get(&(server_id, ip)) {
            if crate::utils::time::now_timestamp() < *expiry {
                return true;
            }
        }
        false
    }

    pub fn is_blocked(&self, ip: IpAddr, server_id: i64) -> bool {
        let now = crate::utils::time::now_timestamp();

        // 1. Check IP-level blocks (Global and Site)
        if self.check_block_expiry(0, ip, now) || self.check_block_expiry(server_id, ip, now) {
            return true;
        }

        // 2. Check Network-level blocks (C-Class etc.) without scanning DashMap shards.
        let snapshots = self.block_network_snapshots.read();
        for sid in [0, server_id] {
            let Some(networks) = snapshots.get(&sid) else {
                continue;
            };
            for (net, expiry) in networks.iter() {
                if now < *expiry && net.contains(&ip) {
                    return true;
                }
            }
        }

        false
    }

    fn insert_block_network(&self, server_id: i64, net: IpNet, expiry: i64) {
        self.block_networks.insert((server_id, net), expiry);
        let now = crate::utils::time::now_timestamp();
        let mut snapshots = self.block_network_snapshots.write();
        let mut networks = snapshots
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
        snapshots.insert(server_id, Arc::new(networks));
    }

    fn remove_block_network(&self, server_id: i64, net: IpNet) {
        self.block_networks.remove(&(server_id, net));
        let mut snapshots = self.block_network_snapshots.write();
        if let Some(items) = snapshots.get(&server_id) {
            let networks = items
                .iter()
                .copied()
                .filter(|(existing, _)| *existing != net)
                .collect::<Vec<_>>();
            if networks.is_empty() {
                snapshots.remove(&server_id);
            } else {
                snapshots.insert(server_id, Arc::new(networks));
            }
        }
    }

    fn check_block_expiry(&self, server_id: i64, ip: IpAddr, now: i64) -> bool {
        if let Some(expiry) = self.blocks.get(&(server_id, ip)) {
            if now < *expiry {
                return true;
            }
        }
        false
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
                self.insert_block_network(key_server_id, net, expiry);
                if use_local_firewall {
                    self.exec_local_firewall(net.to_string(), timeout_secs);
                }
            }
        } else {
            self.blocks.insert((key_server_id, ip), expiry);
            if use_local_firewall {
                self.exec_local_firewall(ip.to_string(), timeout_secs);
            }
        }
    }

    fn exec_local_firewall(&self, target: String, timeout: i64) {
        // Attempt ipset (Linux) or simply log for now on non-linux
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

    fn get_c_class_net(&self, ip: IpAddr) -> Result<IpNet, anyhow::Error> {
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
        self.blocks.remove(&(key_server_id, ip));

        // Remove from network blocks as well (C-Class)
        if let Ok(net) = self.get_c_class_net(ip) {
            self.remove_block_network(key_server_id, net);
            if use_local_firewall {
                self.exec_local_unblock(net.to_string());
            }
        }

        if use_local_firewall {
            self.exec_local_unblock(ip.to_string());
        }

        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.whitelists.insert((key_server_id, ip), expiry);
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

    pub fn flush_to_disk(&self) {}
}
