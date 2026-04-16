use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::Arc;

pub struct TopIpTracker {
    counts: DashMap<(i64, String), u64>,
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
        if server_id <= 0 || ip.is_empty() {
            return;
        }
        let mut entry = self.counts.entry((server_id, ip.to_string())).or_insert(0);
        *entry += 1;
    }

    pub fn flush(&self) -> Vec<(i64, String, u64)> {
        let keys: Vec<(i64, String)> = self
            .counts
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        let mut rows = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some((key, count)) = self.counts.remove(&key) {
                rows.push((key.0, key.1, count));
            }
        }
        rows
    }
}

pub static TOP_IP_TRACKER: Lazy<Arc<TopIpTracker>> = Lazy::new(|| Arc::new(TopIpTracker::new()));
