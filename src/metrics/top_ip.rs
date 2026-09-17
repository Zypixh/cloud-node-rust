use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;

pub struct TopIpTracker {
    counts: DashMap<(i64, IpAddr), u64>,
}

impl Default for TopIpTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TopIpTracker {
    pub fn new() -> Self {
        Self {
            counts: DashMap::new(),
        }
    }

    pub fn record(&self, server_id: i64, ip: &str) {
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return;
        };
        self.record_addr(server_id, ip);
    }

    /// Admit a new `(server_id, ip)` pair only below the cardinality cap;
    /// existing pairs always accumulate.
    fn admit_new_key(&self, key: (i64, IpAddr), capacity: usize) -> bool {
        if self.counts.contains_key(&key) {
            return true;
        }
        if self.counts.len() >= capacity {
            crate::pipeline_metrics::note_cardinality_drop(
                "top_ip_tracker",
                self.counts.len(),
                capacity,
            );
            return false;
        }
        true
    }

    pub fn record_addr(&self, server_id: i64, ip: IpAddr) {
        self.record_addr_with_capacity(
            server_id,
            ip,
            crate::memory_governor::MEMORY_GOVERNOR.metrics_cardinality_capacity(),
        );
    }

    fn record_addr_with_capacity(&self, server_id: i64, ip: IpAddr, capacity: usize) {
        if server_id <= 0 {
            return;
        }
        if !self.admit_new_key((server_id, ip), capacity) {
            return;
        }
        let mut entry = self.counts.entry((server_id, ip)).or_insert(0);
        *entry += 1;
    }

    /// Rough heap estimate for the governor's metrics gauge. Entry cost is
    /// ~(i64 + IpAddr + u64) plus DashMap slot overhead.
    pub fn approximate_bytes(&self) -> u64 {
        (self.counts.len() as u64).saturating_mul(112)
    }

    pub fn flush(&self) -> Vec<(i64, String, u64)> {
        let keys: Vec<(i64, IpAddr)> = self.counts.iter().map(|entry| *entry.key()).collect();
        let mut rows = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some((key, count)) = self.counts.remove(&key) {
                rows.push((key.0, key.1.to_string(), count));
            }
        }
        rows
    }

    /// Put flushed rows back so a failed upload does not lose the counts.
    /// The tracker has no time dimension, so restored rows merge exactly into
    /// the next upload window.
    pub fn restore(&self, rows: &[(i64, String, u64)]) {
        self.restore_with_capacity(
            rows,
            crate::memory_governor::MEMORY_GOVERNOR.metrics_cardinality_capacity(),
        );
    }

    fn restore_with_capacity(&self, rows: &[(i64, String, u64)], capacity: usize) {
        for (server_id, ip, count) in rows {
            let Ok(ip) = ip.parse::<IpAddr>() else {
                continue;
            };
            if *server_id <= 0 {
                continue;
            }
            if !self.admit_new_key((*server_id, ip), capacity) {
                continue;
            }
            let mut entry = self.counts.entry((*server_id, ip)).or_insert(0);
            *entry = entry.saturating_add(*count);
        }
    }
}

pub static TOP_IP_TRACKER: Lazy<Arc<TopIpTracker>> = Lazy::new(|| Arc::new(TopIpTracker::new()));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_returns_flushed_rows_for_retry_after_failed_upload() {
        let tracker = TopIpTracker::new();
        tracker.record_addr(7, "192.0.2.1".parse().unwrap());
        tracker.record_addr(7, "192.0.2.1".parse().unwrap());

        let rows = tracker.flush();
        assert_eq!(rows.len(), 1);
        assert!(tracker.flush().is_empty());

        tracker.restore(&rows);
        let restored = tracker.flush();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].0, 7);
        assert_eq!(restored[0].1, "192.0.2.1");
        assert_eq!(restored[0].2, 2);
    }

    #[test]
    fn approximate_bytes_tracks_live_entries() {
        let tracker = TopIpTracker::new();
        assert_eq!(tracker.approximate_bytes(), 0);
        tracker.record_addr(7, "192.0.2.1".parse().unwrap());
        tracker.record_addr(7, "2001:db8::1".parse().unwrap());
        assert_eq!(tracker.approximate_bytes(), 2 * 112);
        let _ = tracker.flush();
        assert_eq!(tracker.approximate_bytes(), 0);
    }

    #[test]
    fn cardinality_cap_rejects_new_pairs_but_keeps_existing() {
        let tracker = TopIpTracker::new();
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();
        let ip3: IpAddr = "192.0.2.3".parse().unwrap();
        tracker.record_addr_with_capacity(7, ip1, 2);
        tracker.record_addr_with_capacity(7, ip2, 2);
        // Existing keys still accumulate at the cap.
        tracker.record_addr_with_capacity(7, ip1, 2);
        let before = crate::pipeline_metrics::snapshot().metrics_cardinality_dropped;
        // New pair beyond the cap is dropped.
        tracker.record_addr_with_capacity(7, ip3, 2);
        let after = crate::pipeline_metrics::snapshot().metrics_cardinality_dropped;
        assert!(after > before);

        let rows = tracker.flush();
        assert_eq!(rows.len(), 2);
        let total: u64 = rows.iter().map(|r| r.2).sum();
        assert_eq!(total, 3);

        // Restore of new pairs also honors the cap.
        tracker.restore_with_capacity(
            &[(7, "192.0.2.9".into(), 5), (7, "192.0.2.10".into(), 5)],
            1,
        );
        assert_eq!(tracker.counts.len(), 1);
    }
}
