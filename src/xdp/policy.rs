use crate::firewall::kernel::{KernelFilterRange, KernelFilterSnapshot};
#[cfg(target_os = "linux")]
use crate::runtime_mode::{XdpConfig, XdpRuntimeMode};
#[cfg(target_os = "linux")]
use crate::xdp::XdpQueueStatus;
use ipnet::IpNet;
use std::collections::BTreeMap;
use std::net::IpAddr;
#[cfg(any(test, target_os = "linux"))]
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RangeKey {
    pub(crate) from: u128,
    pub(crate) to: u128,
    pub(crate) v6: bool,
}

impl RangeKey {
    #[cfg(test)]
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (ip, self.v6) {
            (IpAddr::V4(v4), false) => {
                let n = u32::from_be_bytes(v4.octets()) as u128;
                n >= self.from && n <= self.to
            }
            (IpAddr::V6(v6), true) => {
                let n = u128::from_be_bytes(v6.octets());
                n >= self.from && n <= self.to
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RuleState {
    pub(crate) blocked_ips: BTreeMap<IpAddr, i64>,
    pub(crate) allowed_ips: BTreeMap<IpAddr, i64>,
    pub(crate) blocked_networks: BTreeMap<String, (IpNet, i64)>,
    pub(crate) allowed_networks: BTreeMap<String, (IpNet, i64)>,
    pub(crate) blocked_ranges: BTreeMap<RangeKey, i64>,
    pub(crate) allowed_ranges: BTreeMap<RangeKey, i64>,
}

impl RuleState {
    pub(crate) fn entry_count(&self) -> usize {
        self.blocked_ips.len()
            + self.allowed_ips.len()
            + self.blocked_networks.len()
            + self.allowed_networks.len()
            + self.blocked_ranges.len()
            + self.allowed_ranges.len()
    }

    pub(crate) fn retain_active(&mut self, now: i64) -> bool {
        let before = self.entry_count();
        self.blocked_ips.retain(|_, expiry| *expiry > now);
        self.allowed_ips.retain(|_, expiry| *expiry > now);
        self.blocked_networks.retain(|_, (_, expiry)| *expiry > now);
        self.allowed_networks.retain(|_, (_, expiry)| *expiry > now);
        self.blocked_ranges.retain(|_, expiry| *expiry > now);
        self.allowed_ranges.retain(|_, expiry| *expiry > now);
        self.entry_count() != before
    }

    pub(crate) fn sync_from_snapshot(&mut self, snapshot: &KernelFilterSnapshot) {
        self.blocked_ips = snapshot
            .blocked_ips
            .iter()
            .copied()
            .filter(|(_, expiry)| *expiry > 0)
            .collect();
        self.allowed_ips = snapshot
            .allowed_ips
            .iter()
            .copied()
            .filter(|(_, expiry)| *expiry > 0)
            .collect();
        self.blocked_networks = snapshot
            .blocked_networks
            .iter()
            .copied()
            .filter(|(_, expiry)| *expiry > 0)
            .map(|(net, expiry)| (net.to_string(), (net, expiry)))
            .collect();
        self.allowed_networks = snapshot
            .allowed_networks
            .iter()
            .copied()
            .filter(|(_, expiry)| *expiry > 0)
            .map(|(net, expiry)| (net.to_string(), (net, expiry)))
            .collect();
        self.blocked_ranges = ranges_to_map(&snapshot.blocked_ranges);
        self.allowed_ranges = ranges_to_map(&snapshot.allowed_ranges);
    }

    pub(crate) fn active_snapshot(&self, now: i64) -> KernelFilterSnapshot {
        KernelFilterSnapshot {
            blocked_ips: self
                .blocked_ips
                .iter()
                .filter(|(_, expiry)| **expiry > now)
                .map(|(ip, expiry)| (*ip, *expiry))
                .collect(),
            allowed_ips: self
                .allowed_ips
                .iter()
                .filter(|(_, expiry)| **expiry > now)
                .map(|(ip, expiry)| (*ip, *expiry))
                .collect(),
            blocked_networks: self
                .blocked_networks
                .values()
                .filter(|(_, expiry)| *expiry > now)
                .map(|(net, expiry)| (*net, *expiry))
                .collect(),
            allowed_networks: self
                .allowed_networks
                .values()
                .filter(|(_, expiry)| *expiry > now)
                .map(|(net, expiry)| (*net, *expiry))
                .collect(),
            blocked_ranges: self
                .blocked_ranges
                .iter()
                .filter(|(_, expiry)| **expiry > now)
                .map(|(range, expiry)| KernelFilterRange {
                    from: range.from,
                    to: range.to,
                    v6: range.v6,
                    expires_at: *expiry,
                })
                .collect(),
            allowed_ranges: self
                .allowed_ranges
                .iter()
                .filter(|(_, expiry)| **expiry > now)
                .map(|(range, expiry)| KernelFilterRange {
                    from: range.from,
                    to: range.to,
                    v6: range.v6,
                    expires_at: *expiry,
                })
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn ip_verdict(&self, ip: IpAddr, now: i64) -> XdpRuleVerdict {
        if self
            .allowed_ips
            .get(&ip)
            .is_some_and(|expiry| *expiry > now)
            || self
                .allowed_networks
                .values()
                .any(|(net, expiry)| *expiry > now && net.contains(&ip))
            || self
                .allowed_ranges
                .iter()
                .any(|(range, expiry)| *expiry > now && range.contains(ip))
        {
            return XdpRuleVerdict::Allow;
        }
        if self
            .blocked_ips
            .get(&ip)
            .is_some_and(|expiry| *expiry > now)
            || self
                .blocked_networks
                .values()
                .any(|(net, expiry)| *expiry > now && net.contains(&ip))
            || self
                .blocked_ranges
                .iter()
                .any(|(range, expiry)| *expiry > now && range.contains(ip))
        {
            return XdpRuleVerdict::Block;
        }
        XdpRuleVerdict::Pass
    }
}

pub(crate) fn ranges_to_map(ranges: &[KernelFilterRange]) -> BTreeMap<RangeKey, i64> {
    ranges
        .iter()
        .filter(|range| range.expires_at > 0 && range.from <= range.to)
        .map(|range| {
            (
                RangeKey {
                    from: range.from,
                    to: range.to,
                    v6: range.v6,
                },
                range.expires_at,
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn configured_queue_statuses(config: &XdpConfig, detail: impl Into<String>) -> Vec<XdpQueueStatus> {
    let detail = detail.into();
    config
        .interfaces
        .iter()
        .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
        .flat_map(|interface| {
            let detail = detail.clone();
            interface.queues.iter().map(move |queue| XdpQueueStatus {
                interface: interface.name.clone(),
                queue: *queue,
                configured: true,
                detail: detail.clone(),
                ..XdpQueueStatus::default()
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn xdp_queue_failure_detail(statuses: &[XdpQueueStatus], fallback: &str) -> String {
    let details = statuses
        .iter()
        .filter(|status| !status.socket_created || !status.ready)
        .map(|status| format!("{}:{} {}", status.interface, status.queue, status.detail))
        .collect::<Vec<_>>();
    if details.is_empty() {
        fallback.to_string()
    } else {
        format!("{fallback}: {}", details.join("; "))
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn range_to_nets(range: &RangeKey) -> Vec<IpNet> {
    use ipnet::{Ipv4Net, Ipv6Net};

    let bits: u8 = if range.v6 { 128 } else { 32 };
    let max = if range.v6 {
        u128::MAX
    } else {
        u32::MAX as u128
    };
    if range.from > range.to || range.from > max {
        return Vec::new();
    }

    let mut current = range.from;
    let end = range.to.min(max);
    let mut nets = Vec::new();
    while current <= end {
        let max_host_bits = if current == 0 {
            bits
        } else {
            (current.trailing_zeros() as u8).min(bits)
        };
        let mut host_bits = max_host_bits;
        let last = loop {
            let candidate = if host_bits == 128 {
                u128::MAX
            } else {
                current + ((1u128 << host_bits) - 1)
            };
            if candidate <= end {
                break candidate;
            }
            host_bits = host_bits.saturating_sub(1);
        };
        let prefix_len = bits - host_bits;
        if range.v6 {
            if let Ok(net) = Ipv6Net::new(Ipv6Addr::from(current), prefix_len) {
                nets.push(IpNet::V6(net));
            }
        } else if let Ok(net) = Ipv4Net::new(Ipv4Addr::from(current as u32), prefix_len) {
            nets.push(IpNet::V4(net));
        }
        if last >= end {
            break;
        }
        current = last + 1;
    }
    nets
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpRuleVerdict {
    Allow,
    Block,
    Pass,
}
