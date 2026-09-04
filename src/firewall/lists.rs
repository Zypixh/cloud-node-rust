use crate::firewall::state::{IpAddrRange, WafStateManager};
use crate::pb;
use dashmap::DashMap;
use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use tracing::{debug, warn};

// Canonicalize IPv4-mapped IPv6 (::ffff:a.b.c.d) to IPv4 so the blacklist
// state map keys stay consistent regardless of how the same IP was framed.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(v4);
    }
    ip
}

#[derive(Clone)]
pub struct IpListMetadata {
    pub code: String,
    pub r#type: String,
    pub is_global: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum IpListKind {
    Black,
    White,
    Gray,
}

fn build_ip_addr_range(from: IpAddr, to: IpAddr) -> Option<IpAddrRange> {
    let (from_n, to_n, v6) = match (from, to) {
        (IpAddr::V4(f), IpAddr::V4(t)) => (
            u32::from_be_bytes(f.octets()) as u128,
            u32::from_be_bytes(t.octets()) as u128,
            false,
        ),
        (IpAddr::V6(f), IpAddr::V6(t)) => (
            u128::from_be_bytes(f.octets()),
            u128::from_be_bytes(t.octets()),
            true,
        ),
        _ => return None,
    };
    if from_n > to_n {
        return None;
    }
    Some(IpAddrRange {
        from: from_n,
        to: to_n,
        v6,
    })
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum IpListTarget {
    Ip(IpAddr),
    Network(IpNet),
    Range(IpAddrRange),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AppliedKey {
    list_id: i64,
    server_id: i64,
    kind: IpListKind,
    target: IpListTarget,
}

#[derive(Clone, Copy)]
struct AppliedItem {
    expiry: i64,
}

pub struct GlobalIpListManager {
    pub list_metadata: DashMap<i64, IpListMetadata>,
    items: DashMap<AppliedKey, AppliedItem>,
    pub version: AtomicI64,
    pub waf_state: Arc<WafStateManager>,
}

impl GlobalIpListManager {
    pub fn new(waf_state: Arc<WafStateManager>) -> Self {
        Self {
            list_metadata: DashMap::new(),
            items: DashMap::new(),
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

    pub fn apply_item(&self, item: pb::IpItem) -> bool {
        let Some(kind) = self.item_kind(&item) else {
            warn!(
                "Skipping IP list item {} from list {} with unsupported type {:?}",
                item.id, item.list_id, item.r#type
            );
            return false;
        };
        let Some(server_id) = self.target_server_id(&item, kind) else {
            warn!(
                "Skipping site-scoped IP list item {} from list {} without serverId",
                item.id, item.list_id
            );
            return false;
        };
        let Some(target) = Self::parse_target(&item) else {
            warn!(
                "Skipping IP list item {} from list {} with unsupported target value {:?}",
                item.id, item.list_id, item.value
            );
            return false;
        };

        let key = AppliedKey {
            list_id: item.list_id,
            server_id,
            kind,
            target,
        };
        let now = crate::utils::time::now_timestamp();
        if item.is_deleted || item.expired_at <= now {
            self.items.remove(&key);
        } else {
            self.items.insert(
                key,
                AppliedItem {
                    expiry: item.expired_at,
                },
            );
        }
        self.recompute_target(server_id, kind, target, now);
        true
    }

    pub fn remove_list(&self, list_id: i64) {
        self.list_metadata.remove(&list_id);
        let mut affected = HashSet::new();
        self.items.retain(|key, _| {
            if key.list_id == list_id {
                affected.insert((key.server_id, key.kind, key.target));
                false
            } else {
                true
            }
        });
        let now = crate::utils::time::now_timestamp();
        for (server_id, kind, target) in affected {
            self.recompute_target(server_id, kind, target, now);
        }
    }

    pub fn replace_metadata(&self, ip_lists: Vec<pb::IpList>) {
        let new_ids: HashSet<i64> = ip_lists.iter().map(|list| list.id).collect();
        let existing_ids = self
            .list_metadata
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        for list_id in existing_ids {
            if !new_ids.contains(&list_id) {
                self.remove_list(list_id);
            }
        }
        for list in ip_lists {
            self.update_metadata(list);
        }
    }

    pub fn update_metadata(&self, ip_list: pb::IpList) {
        self.list_metadata.insert(
            ip_list.id,
            IpListMetadata {
                code: ip_list.code,
                r#type: ip_list.r#type,
                is_global: ip_list.is_global,
            },
        );
    }

    fn item_kind(&self, item: &pb::IpItem) -> Option<IpListKind> {
        Self::kind_from_type(&item.list_type).or_else(|| {
            self.list_metadata
                .get(&item.list_id)
                .and_then(|meta| Self::kind_from_metadata(&meta))
        })
    }

    fn kind_from_type(value: &str) -> Option<IpListKind> {
        match value.trim().to_ascii_lowercase().as_str() {
            "black" | "deny" | "blacklist" => Some(IpListKind::Black),
            "white" | "allow" | "whitelist" => Some(IpListKind::White),
            "gray" | "grey" | "graylist" | "greylist" => Some(IpListKind::Gray),
            _ => None,
        }
    }

    fn kind_from_metadata(meta: &IpListMetadata) -> Option<IpListKind> {
        Self::kind_from_type(&meta.r#type).or_else(|| Self::kind_from_code(&meta.code))
    }

    fn kind_from_code(code: &str) -> Option<IpListKind> {
        let code = code.trim().to_ascii_lowercase();
        if code.contains("blacklist") || code.contains("black-list") || code.contains("black_list")
        {
            Some(IpListKind::Black)
        } else if code.contains("whitelist")
            || code.contains("white-list")
            || code.contains("white_list")
        {
            Some(IpListKind::White)
        } else if code.contains("graylist")
            || code.contains("greylist")
            || code.contains("gray-list")
            || code.contains("grey-list")
            || code.contains("gray_list")
            || code.contains("grey_list")
        {
            Some(IpListKind::Gray)
        } else {
            None
        }
    }

    fn target_server_id(&self, item: &pb::IpItem, _kind: IpListKind) -> Option<i64> {
        if item.is_global {
            return Some(0);
        }
        if let Some(meta) = self.list_metadata.get(&item.list_id)
            && meta.is_global
        {
            return Some(0);
        }
        (item.server_id > 0).then_some(item.server_id)
    }

    fn parse_target(item: &pb::IpItem) -> Option<IpListTarget> {
        let value = item.value.trim();
        if !value.is_empty() {
            if let Ok(net) = value.parse::<IpNet>() {
                return Some(IpListTarget::Network(net.trunc()));
            }
            if let Ok(ip) = value.parse::<IpAddr>() {
                return Some(IpListTarget::Ip(canonical_ip(ip)));
            }
        }

        let ip_from = item.ip_from.trim();
        let ip_to = item.ip_to.trim();
        if !ip_from.is_empty()
            && !ip_to.is_empty()
            && let (Ok(from), Ok(to)) = (ip_from.parse::<IpAddr>(), ip_to.parse::<IpAddr>())
        {
            let from = canonical_ip(from);
            let to = canonical_ip(to);
            if from == to {
                return Some(IpListTarget::Ip(from));
            }
            if let Some(range) = build_ip_addr_range(from, to) {
                return Some(IpListTarget::Range(range));
            }
        }
        None
    }

    fn recompute_target(&self, server_id: i64, kind: IpListKind, target: IpListTarget, now: i64) {
        let expiry = self
            .items
            .iter()
            .filter_map(|entry| {
                let key = entry.key();
                let item = entry.value();
                (key.server_id == server_id
                    && key.kind == kind
                    && key.target == target
                    && item.expiry > now)
                    .then_some(item.expiry)
            })
            .max();

        match (kind, target, expiry) {
            (IpListKind::Black, IpListTarget::Ip(ip), Some(expiry)) => {
                self.waf_state
                    .apply_list_black_ip_until(server_id, ip, expiry);
            }
            (IpListKind::Black, IpListTarget::Network(net), Some(expiry)) => {
                self.waf_state
                    .apply_list_black_network_until(server_id, net, expiry);
            }
            (IpListKind::Black, IpListTarget::Range(range), Some(expiry)) => {
                self.waf_state
                    .apply_list_black_range_until(server_id, range, expiry);
            }
            (IpListKind::White, IpListTarget::Ip(ip), Some(expiry)) => {
                self.waf_state
                    .apply_list_white_ip_until(server_id, ip, expiry);
            }
            (IpListKind::White, IpListTarget::Network(net), Some(expiry)) => {
                self.waf_state
                    .apply_list_white_network_until(server_id, net, expiry);
            }
            (IpListKind::White, IpListTarget::Range(range), Some(expiry)) => {
                self.waf_state
                    .apply_list_white_range_until(server_id, range, expiry);
            }
            (IpListKind::Gray, IpListTarget::Ip(ip), Some(expiry)) => {
                self.waf_state
                    .apply_list_gray_ip_until(server_id, ip, expiry);
            }
            (IpListKind::Gray, IpListTarget::Network(net), Some(expiry)) => {
                self.waf_state
                    .apply_list_gray_network_until(server_id, net, expiry);
            }
            (IpListKind::Gray, IpListTarget::Range(range), Some(expiry)) => {
                self.waf_state
                    .apply_list_gray_range_until(server_id, range, expiry);
            }
            (IpListKind::Black, IpListTarget::Ip(ip), None) => {
                self.waf_state.remove_list_black_ip(server_id, ip);
            }
            (IpListKind::Black, IpListTarget::Network(net), None) => {
                self.waf_state.remove_list_black_network(server_id, net);
            }
            (IpListKind::Black, IpListTarget::Range(range), None) => {
                self.waf_state.remove_list_black_range(server_id, range);
            }
            (IpListKind::White, IpListTarget::Ip(ip), None) => {
                self.waf_state.remove_list_white_ip(server_id, ip);
            }
            (IpListKind::White, IpListTarget::Network(net), None) => {
                self.waf_state.remove_list_white_network(server_id, net);
            }
            (IpListKind::White, IpListTarget::Range(range), None) => {
                self.waf_state.remove_list_white_range(server_id, range);
            }
            (IpListKind::Gray, IpListTarget::Ip(ip), None) => {
                self.waf_state.remove_list_gray_ip(server_id, ip);
            }
            (IpListKind::Gray, IpListTarget::Network(net), None) => {
                self.waf_state.remove_list_gray_network(server_id, net);
            }
            (IpListKind::Gray, IpListTarget::Range(range), None) => {
                self.waf_state.remove_list_gray_range(server_id, range);
            }
        }

        self.items.retain(|key, item| {
            if key.server_id == server_id && key.kind == kind && key.target == target {
                item.expiry > now
            } else {
                true
            }
        });
        debug!(
            "Applied IP list target list-kind={:?} server={} target={:?} expiry={:?}",
            kind, server_id, target, expiry
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_item() -> pb::IpItem {
        pb::IpItem {
            id: 1,
            list_id: 10,
            list_type: "black".to_string(),
            is_global: true,
            expired_at: crate::utils::time::now_timestamp() + 60,
            ..Default::default()
        }
    }

    #[test]
    fn ip_list_parse_target_accepts_single_ip() {
        let mut item = ip_item();
        item.value = "192.168.1.100".to_string();
        assert_eq!(
            GlobalIpListManager::parse_target(&item),
            Some(IpListTarget::Ip("192.168.1.100".parse().unwrap()))
        );
    }

    #[test]
    fn ip_list_parse_target_accepts_and_truncates_cidr() {
        let mut item = ip_item();
        item.value = "192.168.1.1/24".to_string();
        assert_eq!(
            GlobalIpListManager::parse_target(&item),
            Some(IpListTarget::Network("192.168.1.0/24".parse().unwrap()))
        );
    }

    #[test]
    fn ip_list_parse_target_accepts_ip_range() {
        let mut item = ip_item();
        item.ip_from = "192.168.1.1".to_string();
        item.ip_to = "192.168.1.255".to_string();
        assert_eq!(
            GlobalIpListManager::parse_target(&item),
            Some(IpListTarget::Range(IpAddrRange {
                from: u32::from_be_bytes([192, 168, 1, 1]) as u128,
                to: u32::from_be_bytes([192, 168, 1, 255]) as u128,
                v6: false,
            }))
        );
    }
}
