use crate::firewall::state::WafStateManager;
use dashmap::DashMap;
use ipnet::IpNet;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

pub struct GlobalIpListManager {
    pub lists: DashMap<i64, Vec<IpNet>>,
    pub version: AtomicI64,
    pub waf_state: Arc<WafStateManager>,
}

impl GlobalIpListManager {
    pub fn new(waf_state: Arc<WafStateManager>) -> Self {
        Self {
            lists: DashMap::new(),
            version: AtomicI64::new(0),
            waf_state,
        }
    }

    pub fn last_version(&self) -> i64 {
        self.version.load(Ordering::Relaxed)
    }

    pub fn update_last_version(&self, v: i64) {
        self.version.store(v, Ordering::Relaxed);
    }

    pub fn apply_item(&self, list_id: i64, value: &str, is_deleted: bool) {
        if let Ok(net) = value.parse::<IpNet>() {
            if is_deleted {
                self.lists.entry(list_id).and_modify(|list| {
                    list.retain(|x| x != &net);
                });
                // Sync Unblock to WAF State and System Firewall
                self.waf_state
                    .unblock_ip(net.addr(), 0, Some("global"), true);
            } else {
                self.lists.entry(list_id).or_default().push(net);
                // If it's a black list, we might want to block it immediately (optional based on list type)
            }
        }
    }

    pub fn remove_list(&self, list_id: i64) {
        self.lists.remove(&list_id);
    }

    pub fn update_list(&self, list_id: i64, items: Vec<IpNet>) {
        self.lists.insert(list_id, items);
    }

    /// Replace all IP list metadata from a full list of PB IpList objects.
    /// This clears existing lists (by ID not present) and updates present ones.
    pub fn replace_metadata(&self, ip_lists: Vec<crate::pb::IpList>) {
        // Collect all current list IDs
        let new_ids: std::collections::HashSet<i64> = ip_lists.iter().map(|l| l.id).collect();
        // Remove lists not present in new data
        self.lists.retain(|id, _| new_ids.contains(id));
        // Ensure all new list IDs exist (empty if not already populated)
        for list in &ip_lists {
            self.lists.entry(list.id).or_default();
        }
    }

    /// Update metadata for a single IP list from a PB IpList object.
    pub fn update_metadata(&self, ip_list: crate::pb::IpList) {
        // Ensure the entry exists (preserving existing items)
        self.lists.entry(ip_list.id).or_default();
    }
}
