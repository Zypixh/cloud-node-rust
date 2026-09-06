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

    pub fn record_addr(&self, server_id: i64, ip: IpAddr) {
        if server_id <= 0 {
            return;
        }
        let mut entry = self.counts.entry((server_id, ip)).or_insert(0);
        *entry += 1;
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
        for (server_id, ip, count) in rows {
            let Ok(ip) = ip.parse::<IpAddr>() else {
                continue;
            };
            if *server_id <= 0 {
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
}
