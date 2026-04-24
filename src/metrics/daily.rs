use dashmap::{DashMap, DashSet};
use once_cell::sync::Lazy;
use std::sync::Arc;

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct DomainKey {
    server_id: i64,
    created_at: i64,
    domain: String,
}

#[derive(Debug, Default, Clone)]
pub struct DomainStatValue {
    pub bytes: i64,
    pub cached_bytes: i64,
    pub count_requests: i64,
    pub count_cached_requests: i64,
    pub count_attack_requests: i64,
    pub attack_bytes: i64,
}

pub struct DailyDomainTracker {
    domains: DashMap<DomainKey, DomainStatValue>,
}

impl Default for DailyDomainTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DailyDomainTracker {
    pub fn new() -> Self {
        Self {
            domains: DashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        server_id: i64,
        created_at: i64,
        domain: &str,
        bytes: i64,
        cached_bytes: i64,
        count_requests: i64,
        count_cached_requests: i64,
        count_attack_requests: i64,
        attack_bytes: i64,
    ) {
        if server_id <= 0 || domain.is_empty() || domain.len() >= 128 {
            return;
        }

        let key = DomainKey {
            server_id,
            created_at,
            domain: domain.to_string(),
        };
        let mut entry = self.domains.entry(key).or_default();
        entry.bytes += bytes;
        entry.cached_bytes += cached_bytes;
        entry.count_requests += count_requests;
        entry.count_cached_requests += count_cached_requests;
        entry.count_attack_requests += count_attack_requests;
        entry.attack_bytes += attack_bytes;
    }

    pub fn flush_older_than(&self, current_created_at: i64) -> Vec<(i64, i64, String, DomainStatValue)> {
        let keys: Vec<_> = self
            .domains
            .iter()
            .filter(|entry| entry.key().created_at < current_created_at)
            .map(|entry| entry.key().clone())
            .collect();
        let mut rows = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some((key, value)) = self.domains.remove(&key) {
                rows.push((key.server_id, key.created_at, key.domain, value));
            }
        }
        rows
    }
}

pub struct UniqueIpTracker {
    ips: DashSet<(i64, String, String)>,
}

impl Default for UniqueIpTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl UniqueIpTracker {
    pub fn new() -> Self {
        Self {
            ips: DashSet::new(),
        }
    }

    pub fn record(&self, server_id: i64, day: &str, ip: &str) {
        if server_id <= 0 || day.is_empty() || ip.is_empty() {
            return;
        }
        self.ips.insert((server_id, day.to_string(), ip.to_string()));
    }

    pub fn count(&self, server_id: i64, day: &str) -> i64 {
        self.ips
            .iter()
            .filter(|entry| entry.0 == server_id && entry.1 == day)
            .count() as i64
    }

    pub fn cleanup_before(&self, min_day: &str) {
        let keys: Vec<_> = self
            .ips
            .iter()
            .filter(|entry| entry.1.as_str() < min_day)
            .map(|entry| entry.clone())
            .collect();
        for key in keys {
            self.ips.remove(&key);
        }
    }
}

pub static DAILY_DOMAIN_TRACKER: Lazy<Arc<DailyDomainTracker>> =
    Lazy::new(|| Arc::new(DailyDomainTracker::new()));

pub static UNIQUE_IP_TRACKER: Lazy<Arc<UniqueIpTracker>> =
    Lazy::new(|| Arc::new(UniqueIpTracker::new()));
