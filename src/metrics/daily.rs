use chrono::Duration as ChronoDuration;
use dashmap::{DashMap, DashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;

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
        self.record_with_capacity(
            server_id,
            created_at,
            domain,
            bytes,
            cached_bytes,
            count_requests,
            count_cached_requests,
            count_attack_requests,
            attack_bytes,
            crate::memory_governor::MEMORY_GOVERNOR.metrics_cardinality_capacity(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_with_capacity(
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
        capacity: usize,
    ) {
        if server_id <= 0 || domain.is_empty() || domain.len() >= 128 {
            return;
        }

        let key = DomainKey {
            server_id,
            created_at,
            domain: domain.to_string(),
        };
        if !self.domains.contains_key(&key) && self.domains.len() >= capacity {
            crate::pipeline_metrics::note_cardinality_drop(
                "daily_domain_tracker",
                self.domains.len(),
                capacity,
            );
            return;
        }
        let mut entry = self.domains.entry(key).or_default();
        entry.bytes += bytes;
        entry.cached_bytes += cached_bytes;
        entry.count_requests += count_requests;
        entry.count_cached_requests += count_cached_requests;
        entry.count_attack_requests += count_attack_requests;
        entry.attack_bytes += attack_bytes;
    }

    /// Rough heap estimate: DomainKey carries a heap String (<=127 bytes)
    /// plus six counters and map overhead.
    pub fn approximate_bytes(&self) -> u64 {
        (self.domains.len() as u64).saturating_mul(192)
    }

    pub fn flush_older_than(
        &self,
        current_created_at: i64,
    ) -> Vec<(i64, i64, String, DomainStatValue)> {
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
    ips: DashSet<(i64, String, IpAddr)>,
}

impl Default for UniqueIpTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl UniqueIpTracker {
    pub fn new() -> Self {
        let min_day = (crate::utils::time::now_local() - ChronoDuration::days(2))
            .format("%Y%m%d")
            .to_string();
        let capacity = crate::memory_governor::MEMORY_GOVERNOR.metrics_cardinality_capacity();
        let ips = DashSet::new();
        for (server_id, day, ip) in crate::metrics::storage::STORAGE.load_unique_ips(&min_day) {
            if ips.len() >= capacity {
                // Seed load honors the same cap as live recording — a
                // storage side seeded beyond budget cannot bypass it.
                crate::pipeline_metrics::note_cardinality_drop(
                    "unique_ip_tracker",
                    ips.len(),
                    capacity,
                );
                break;
            }
            ips.insert((server_id, day, ip));
        }
        Self { ips }
    }

    pub fn record(&self, server_id: i64, day: &str, ip: IpAddr) {
        self.record_with_capacity(
            server_id,
            day,
            ip,
            crate::memory_governor::MEMORY_GOVERNOR.metrics_cardinality_capacity(),
        );
    }

    fn record_with_capacity(&self, server_id: i64, day: &str, ip: IpAddr, capacity: usize) {
        if server_id <= 0 || day.is_empty() {
            return;
        }
        let key = (server_id, day.to_string(), ip);
        if !self.ips.contains(&key) && self.ips.len() >= capacity {
            crate::pipeline_metrics::note_cardinality_drop(
                "unique_ip_tracker",
                self.ips.len(),
                capacity,
            );
            return;
        }
        if self.ips.insert(key) {
            crate::metrics::storage::STORAGE.record_unique_ip(server_id, day, ip);
        }
    }

    pub fn count(&self, server_id: i64, day: &str) -> i64 {
        self.ips
            .iter()
            .filter(|entry| entry.0 == server_id && entry.1 == day)
            .count() as i64
    }

    /// Rough heap estimate: (i64, day String, IpAddr) per set entry.
    pub fn approximate_bytes(&self) -> u64 {
        (self.ips.len() as u64).saturating_mul(96)
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
        crate::metrics::storage::STORAGE.cleanup_unique_ips_before(min_day);
    }
}

pub static DAILY_DOMAIN_TRACKER: Lazy<Arc<DailyDomainTracker>> =
    Lazy::new(|| Arc::new(DailyDomainTracker::new()));

pub static UNIQUE_IP_TRACKER: Lazy<Arc<UniqueIpTracker>> =
    Lazy::new(|| Arc::new(UniqueIpTracker::new()));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_domain_approximate_bytes_tracks_live_entries() {
        let tracker = DailyDomainTracker::new();
        assert_eq!(tracker.approximate_bytes(), 0);
        tracker.record(1, 100, "example.com", 10, 5, 1, 1, 0, 0);
        tracker.record(1, 100, "cdn.example.com", 20, 0, 1, 0, 0, 0);
        assert_eq!(tracker.approximate_bytes(), 2 * 192);
    }

    #[test]
    fn daily_domain_cardinality_cap_keeps_existing_keys() {
        let tracker = DailyDomainTracker::new();
        tracker.record_with_capacity(1, 100, "a.com", 10, 0, 1, 0, 0, 0, 2);
        tracker.record_with_capacity(1, 100, "b.com", 10, 0, 1, 0, 0, 0, 2);
        // Existing key accumulates at the cap.
        tracker.record_with_capacity(1, 100, "a.com", 5, 0, 1, 0, 0, 0, 2);
        let before = crate::pipeline_metrics::snapshot().metrics_cardinality_dropped;
        tracker.record_with_capacity(1, 100, "c.com", 10, 0, 1, 0, 0, 0, 2);
        assert!(
            crate::pipeline_metrics::snapshot().metrics_cardinality_dropped > before
        );
        assert_eq!(tracker.domains.len(), 2);
        assert_eq!(tracker.domains.get(&DomainKey {
            server_id: 1,
            created_at: 100,
            domain: "a.com".into(),
        }).unwrap().bytes, 15);
        // Flushing older days still releases capped state.
        let rows = tracker.flush_older_than(200);
        assert_eq!(rows.len(), 2);
        assert_eq!(tracker.domains.len(), 0);
    }

    #[test]
    fn unique_ip_cardinality_cap_rejects_new_ips() {
        let tracker = UniqueIpTracker { ips: DashSet::new() };
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();
        let ip3: IpAddr = "192.0.2.3".parse().unwrap();
        tracker.record_with_capacity(1, "20260917", ip1, 2);
        tracker.record_with_capacity(1, "20260917", ip2, 2);
        // Duplicate record of an existing key is a no-op, not a drop.
        tracker.record_with_capacity(1, "20260917", ip1, 2);
        let before = crate::pipeline_metrics::snapshot().metrics_cardinality_dropped;
        tracker.record_with_capacity(1, "20260917", ip3, 2);
        assert!(
            crate::pipeline_metrics::snapshot().metrics_cardinality_dropped > before
        );
        assert_eq!(tracker.ips.len(), 2);
        assert_eq!(tracker.count(1, "20260917"), 2);
        tracker.cleanup_before("20270917");
        assert_eq!(tracker.ips.len(), 0);
    }
}
