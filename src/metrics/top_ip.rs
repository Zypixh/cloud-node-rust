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
}

pub static TOP_IP_TRACKER: Lazy<Arc<TopIpTracker>> = Lazy::new(|| Arc::new(TopIpTracker::new()));
