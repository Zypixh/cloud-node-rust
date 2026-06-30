use crate::firewall::kernel::{
    KernelFilter, KernelFilterRange, KernelFilterSnapshot, KernelFilterStatus,
};
use crate::runtime_mode::{RuntimeConfig, XdpConfig, XdpProxyProtocol, XdpRuntimeMode};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const XDP_EBPF_OBJECT_NAME: &str = "cloud-node-xdp-ebpf.o";
#[cfg(target_os = "linux")]
const XDP_BPF_PIN_DIR: &str = "/sys/fs/bpf/cloud-node-xdp";
const XDP_STATE_WRITE_INTERVAL_SECS: u64 = 10;
const XDP_RULE_SWEEP_INTERVAL_SECS: u64 = 5;
// Coalescing window for rule-map writes: bursts of block/unblock events under an
// attack collapse into a single incremental eBPF map update. Off-round to avoid
// whole-second resonance with the rule sweeper.
const XDP_MAP_SYNC_DEBOUNCE_MS: u64 = 47;
const XDP_PROXY_DATAPLANE_ACTIVE: bool = true;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XdpQueueStatus {
    pub interface: String,
    pub queue: u32,
    pub configured: bool,
    pub socket_created: bool,
    pub registered: bool,
    pub ready: bool,
    pub detail: String,
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub tx_invalid_descs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XdpInterfaceStatus {
    pub name: String,
    pub mode: String,
    pub queues: Vec<u32>,
    pub local_ips: Vec<IpAddr>,
    pub frame_size: u32,
    pub attached: bool,
    pub xsk_ready: bool,
    pub xsk_queues: Vec<XdpQueueStatus>,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct XdpStatusSnapshot {
    pub enabled: bool,
    pub available: bool,
    pub attached: bool,
    pub attach_mode: String,
    pub fallback: String,
    pub fallback_reason: String,
    pub ebpf_object: String,
    pub interfaces: Vec<XdpInterfaceStatus>,
    pub exact_blocked_v4: usize,
    pub exact_blocked_v6: usize,
    pub exact_allowed_v4: usize,
    pub exact_allowed_v6: usize,
    pub blocked_networks: usize,
    pub allowed_networks: usize,
    pub blocked_ranges: usize,
    pub allowed_ranges: usize,
    pub proxy_ports: usize,
    #[serde(default)]
    pub proxy_supported_ports: usize,
    #[serde(default)]
    pub proxy_unsupported_ports: usize,
    pub proxy_ready: bool,
    #[serde(default)]
    pub proxy_redirect_enabled: bool,
    pub proxy_fallback_reason: String,
    pub tcp_dataplane_ready: bool,
    pub tcp_dataplane_detail: String,
    pub xsk_configured_queues: usize,
    pub xsk_ready_queues: usize,
    pub packets: u64,
    pub pass: u64,
    pub drop: u64,
    pub redirect: u64,
    pub parse_errors: u64,
    pub map_miss: u64,
    pub xsk_drops: u64,
    pub updated_at: i64,
}

fn write_status_snapshot_blocking(
    path: &std::path::Path,
    status: &XdpStatusSnapshot,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_vec_pretty(status)?;
    std::fs::write(path, body)?;
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RangeKey {
    from: u128,
    to: u128,
    v6: bool,
}

impl RangeKey {
    #[cfg(test)]
    fn contains(&self, ip: IpAddr) -> bool {
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
struct RuleState {
    blocked_ips: BTreeMap<IpAddr, i64>,
    allowed_ips: BTreeMap<IpAddr, i64>,
    blocked_networks: BTreeMap<String, (IpNet, i64)>,
    allowed_networks: BTreeMap<String, (IpNet, i64)>,
    blocked_ranges: BTreeMap<RangeKey, i64>,
    allowed_ranges: BTreeMap<RangeKey, i64>,
}

impl RuleState {
    fn entry_count(&self) -> usize {
        self.blocked_ips.len()
            + self.allowed_ips.len()
            + self.blocked_networks.len()
            + self.allowed_networks.len()
            + self.blocked_ranges.len()
            + self.allowed_ranges.len()
    }

    fn retain_active(&mut self, now: i64) -> bool {
        let before = self.entry_count();
        self.blocked_ips.retain(|_, expiry| *expiry > now);
        self.allowed_ips.retain(|_, expiry| *expiry > now);
        self.blocked_networks.retain(|_, (_, expiry)| *expiry > now);
        self.allowed_networks.retain(|_, (_, expiry)| *expiry > now);
        self.blocked_ranges.retain(|_, expiry| *expiry > now);
        self.allowed_ranges.retain(|_, expiry| *expiry > now);
        self.entry_count() != before
    }

    fn sync_from_snapshot(&mut self, snapshot: &KernelFilterSnapshot) {
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

    fn active_snapshot(&self, now: i64) -> KernelFilterSnapshot {
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
    fn ip_verdict(&self, ip: IpAddr, now: i64) -> XdpRuleVerdict {
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

fn ranges_to_map(ranges: &[KernelFilterRange]) -> BTreeMap<RangeKey, i64> {
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
fn configured_queue_statuses(config: &XdpConfig, detail: impl Into<String>) -> Vec<XdpQueueStatus> {
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
fn xdp_queue_failure_detail(statuses: &[XdpQueueStatus], fallback: &str) -> String {
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
fn range_to_nets(range: &RangeKey) -> Vec<IpNet> {
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

#[derive(Debug)]
struct XdpManager {
    config: XdpConfig,
    state: parking_lot::RwLock<RuleState>,
    fallback_reason: parking_lot::RwLock<String>,
    proxy_fallback_reason: parking_lot::RwLock<String>,
    tcp_dataplane_detail: parking_lot::RwLock<String>,
    xsk_status: parking_lot::RwLock<Vec<XdpQueueStatus>>,
    attached: parking_lot::RwLock<BTreeSet<String>>,
    #[cfg(target_os = "linux")]
    ebpf: parking_lot::Mutex<Option<aya::Ebpf>>,
    #[cfg(target_os = "linux")]
    af_xdp: parking_lot::Mutex<Option<linux::AfXdpRuntimeHandle>>,
    packets: AtomicU64,
    pass: AtomicU64,
    drop: AtomicU64,
    redirect: AtomicU64,
    parse_errors: AtomicU64,
    map_miss: AtomicU64,
    xsk_drops: AtomicU64,
    proxy_redirect_enabled: AtomicBool,
    last_state_write_at: AtomicU64,
    rule_sweeper_started: AtomicBool,
    rule_sweeper_generation: AtomicU64,
    /// Image of the rule state last successfully written to the eBPF maps. The
    /// incremental sync diffs the live shadow `state` against this to compute the
    /// minimal set of map inserts/removes.
    synced: parking_lot::Mutex<RuleState>,
    map_sync_started: AtomicBool,
    map_sync_notify: tokio::sync::Notify,
}

impl XdpManager {
    fn new(config: XdpConfig) -> Self {
        Self {
            config,
            state: parking_lot::RwLock::new(RuleState::default()),
            fallback_reason: parking_lot::RwLock::new(String::new()),
            proxy_fallback_reason: parking_lot::RwLock::new(String::new()),
            tcp_dataplane_detail: parking_lot::RwLock::new(String::new()),
            xsk_status: parking_lot::RwLock::new(Vec::new()),
            attached: parking_lot::RwLock::new(BTreeSet::new()),
            #[cfg(target_os = "linux")]
            ebpf: parking_lot::Mutex::new(None),
            #[cfg(target_os = "linux")]
            af_xdp: parking_lot::Mutex::new(None),
            packets: AtomicU64::new(0),
            pass: AtomicU64::new(0),
            drop: AtomicU64::new(0),
            redirect: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            map_miss: AtomicU64::new(0),
            xsk_drops: AtomicU64::new(0),
            proxy_redirect_enabled: AtomicBool::new(false),
            last_state_write_at: AtomicU64::new(0),
            rule_sweeper_started: AtomicBool::new(false),
            rule_sweeper_generation: AtomicU64::new(0),
            synced: parking_lot::Mutex::new(RuleState::default()),
            map_sync_started: AtomicBool::new(false),
            map_sync_notify: tokio::sync::Notify::new(),
        }
    }

    async fn initialize(&self) -> anyhow::Result<()> {
        if !self.config.enabled {
            self.set_fallback_reason("runtime xdp.enabled=false");
            return Ok(());
        }
        if self.config.interfaces.is_empty() {
            self.set_fallback_reason("runtime xdp.interfaces is empty");
            if self.config.fallback.fail_start() {
                anyhow::bail!("xdp enabled but no interfaces configured");
            }
            return Ok(());
        }
        let proxy_frame_size_detail = xdp_proxy_frame_size_detail(&self.config);
        if !proxy_frame_size_detail.is_empty() {
            self.set_fallback_reason(format!("{proxy_frame_size_detail}; traffic will PASS"));
            if self.config.fallback.fail_start() {
                anyhow::bail!("{proxy_frame_size_detail}");
            }
            self.persist_status();
            return Ok(());
        }
        if !self.attached.read().is_empty() {
            self.persist_status();
            return Ok(());
        }

        let object_path = ebpf_object_path();
        if !object_path.exists() {
            self.set_fallback_reason(format!(
                "eBPF object {} is missing; run cargo xtask build-ebpf",
                object_path.display()
            ));
            if self.config.fallback.fail_start() {
                anyhow::bail!("xdp eBPF object is missing: {}", object_path.display());
            }
            self.persist_status();
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            match linux::attach(&self.config, &object_path).await {
                Ok(attached_program) => {
                    *self.ebpf.lock() = Some(attached_program.ebpf);
                    let attached = attached_program.interfaces;
                    *self.attached.write() = attached;
                    self.set_fallback_reason(String::new());
                    self.flush_maps_full_blocking(self.proxy_redirect_ready());
                    self.configure_af_xdp_runtime()?;
                }
                Err(err) => {
                    self.set_fallback_reason(format!("attach failed: {err}"));
                    if self.config.fallback.fail_start() {
                        return Err(err);
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.set_fallback_reason("XDP attach is supported on Linux only");
            if self.config.fallback.fail_start() {
                anyhow::bail!("XDP attach is supported on Linux only");
            }
        }

        self.persist_status();
        Ok(())
    }

    fn set_fallback_reason(&self, reason: impl Into<String>) {
        *self.fallback_reason.write() = reason.into();
    }

    fn set_proxy_fallback_reason(&self, reason: impl Into<String>) {
        *self.proxy_fallback_reason.write() = reason.into();
    }

    #[cfg(target_os = "linux")]
    fn set_tcp_dataplane_detail(&self, detail: impl Into<String>) {
        *self.tcp_dataplane_detail.write() = detail.into();
    }

    fn tcp_dataplane_detail(&self) -> String {
        let detail = self.tcp_dataplane_detail.read().clone();
        if !detail.is_empty() {
            return detail;
        }
        xdp_tcp_dataplane_detail(&self.config)
    }

    fn proxy_xsk_ready(&self) -> bool {
        if !XDP_PROXY_DATAPLANE_ACTIVE
            || self.config.proxy.ports.is_empty()
            || xdp_supported_proxy_port_count(&self.config) == 0
        {
            return false;
        }
        let statuses = self.xsk_status.read();
        self.config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
            .any(|interface| {
                !interface.queues.is_empty()
                    && interface.queues.iter().all(|queue| {
                        statuses.iter().any(|status| {
                            status.interface == interface.name
                                && status.queue == *queue
                                && status.ready
                        })
                    })
            })
    }

    fn proxy_redirect_ready(&self) -> bool {
        self.proxy_redirect_enabled.load(Ordering::Relaxed) && self.proxy_xsk_ready()
    }

    #[cfg(any(test, target_os = "linux"))]
    fn mark_proxy_dataplane_degraded(&self, detail: impl Into<String>) {
        let detail = detail.into();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        self.set_proxy_fallback_reason(detail.clone());
        let mut statuses = self.xsk_status.write();
        for status in statuses.iter_mut() {
            let was_registered = status.registered;
            let was_ready = status.ready;
            status.registered = false;
            status.ready = false;
            if was_registered || was_ready || status.detail.is_empty() {
                status.detail = detail.clone();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn disable_proxy_redirect_for_fallback(&self, detail: impl Into<String>) {
        let detail = detail.into();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        self.mark_proxy_dataplane_degraded(detail.clone());
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::disable_proxy_redirect(ebpf, &self.config),
                None => Ok(()),
            }
        };
        if let Err(err) = result {
            self.set_proxy_fallback_reason(format!(
                "{detail}; failed to disable AF_XDP proxy redirect maps: {err}"
            ));
            tracing::warn!("failed to disable AF_XDP proxy redirect maps: {}", err);
        }
        self.persist_status();
    }

    #[cfg(target_os = "linux")]
    fn configure_af_xdp_runtime(&self) -> anyhow::Result<()> {
        if !self
            .config
            .interfaces
            .iter()
            .any(|interface| interface.mode == XdpRuntimeMode::Proxy)
        {
            self.xsk_status.write().clear();
            self.set_proxy_fallback_reason(String::new());
            return Ok(());
        }
        if self.config.proxy.ports.is_empty() {
            self.xsk_status.write().clear();
            self.set_proxy_fallback_reason("xdp.proxy.ports is empty; proxy traffic will PASS");
            return Ok(());
        }
        if xdp_supported_proxy_port_count(&self.config) == 0 {
            self.xsk_status.write().clear();
            self.set_proxy_fallback_reason(
                "xdp.proxy.ports has no AF_XDP-supported protocols; traffic will PASS",
            );
            self.set_tcp_dataplane_detail(xdp_tcp_dataplane_detail(&self.config));
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            match linux::prepare_af_xdp_sockets(&self.config) {
                Ok(mut runtime) => {
                    let mut registration_failed = false;
                    let mut registration_failure_detail = None;
                    if XDP_PROXY_DATAPLANE_ACTIVE
                        && runtime.statuses.iter().all(|status| status.socket_created)
                    {
                        let register_result = {
                            let mut ebpf = self.ebpf.lock();
                            match ebpf.as_mut() {
                                Some(ebpf) => linux::register_af_xdp_sockets(
                                    ebpf,
                                    &self.config,
                                    &mut runtime,
                                    false,
                                ),
                                None => Err(anyhow::anyhow!(
                                    "eBPF program is not loaded; cannot register AF_XDP sockets"
                                )),
                            }
                        };
                        if let Err(err) = register_result {
                            registration_failed = true;
                            registration_failure_detail = Some(format!(
                                "AF_XDP socket registration failed: {err}; proxy redirect disabled, traffic will PASS"
                            ));
                        }
                    }
                    let statuses = runtime.statuses.clone();
                    let failed = statuses.iter().any(|status| !status.socket_created);
                    let failure_detail = if failed {
                        Some(xdp_queue_failure_detail(
                            &statuses,
                            "one or more AF_XDP sockets failed to start",
                        ))
                    } else {
                        None
                    };
                    *self.xsk_status.write() = statuses;
                    *self.af_xdp.lock() = Some(runtime);
                    if failed {
                        let detail = failure_detail.unwrap_or_else(|| {
                            "one or more AF_XDP sockets failed to start".to_string()
                        });
                        self.disable_proxy_redirect_for_fallback(format!(
                            "{detail}; proxy redirect disabled, traffic will PASS"
                        ));
                        if self.config.fallback.fail_start() {
                            anyhow::bail!("{detail}");
                        }
                    } else if registration_failed {
                        let detail = registration_failure_detail.unwrap_or_else(|| {
                            "AF_XDP socket registration failed; proxy redirect disabled, traffic will PASS"
                                .to_string()
                        });
                        self.disable_proxy_redirect_for_fallback(detail);
                        if self.config.fallback.fail_start() {
                            anyhow::bail!("one or more AF_XDP sockets failed to register");
                        }
                    } else if XDP_PROXY_DATAPLANE_ACTIVE {
                        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
                        let partial = xdp_proxy_partial_detail(&self.config);
                        let detail = if partial.is_empty() {
                            "AF_XDP sockets registered; proxy bridge has not enabled redirect yet, traffic will PASS".to_string()
                        } else {
                            format!(
                                "AF_XDP sockets registered; proxy bridge has not enabled redirect yet, traffic will PASS; {partial}"
                            )
                        };
                        self.set_proxy_fallback_reason(detail);
                        self.set_tcp_dataplane_detail(
                            "AF_XDP TCP sockets registered; proxy bridge has not enabled redirect yet",
                        );
                    } else {
                        self.set_proxy_fallback_reason(
                            "AF_XDP sockets staged; userspace proxy dataplane is not active, traffic will PASS",
                        );
                        if self.config.fallback.fail_start() {
                            anyhow::bail!(
                                "xdp proxy requested but AF_XDP userspace proxy dataplane is not active"
                            );
                        }
                    }
                }
                Err(err) => {
                    *self.xsk_status.write() = configured_queue_statuses(
                        &self.config,
                        format!("AF_XDP socket setup failed: {err}"),
                    );
                    self.disable_proxy_redirect_for_fallback(format!(
                        "AF_XDP socket setup failed: {err}; proxy redirect disabled, traffic will PASS"
                    ));
                    if self.config.fallback.fail_start() {
                        return Err(err);
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            *self.xsk_status.write() = configured_queue_statuses(
                &self.config,
                "AF_XDP sockets are supported on Linux only",
            );
            self.set_proxy_fallback_reason("AF_XDP sockets are supported on Linux only");
            if self.config.fallback.fail_start() {
                anyhow::bail!("AF_XDP sockets are supported on Linux only");
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn enable_proxy_redirect(&self, source: &'static str) -> anyhow::Result<bool> {
        if !self.config.enabled
            || !XDP_PROXY_DATAPLANE_ACTIVE
            || self.config.proxy.ports.is_empty()
            || xdp_supported_proxy_port_count(&self.config) == 0
            || !self.proxy_xsk_ready()
        {
            return Ok(false);
        }

        self.flush_maps_full_blocking(true);

        // Check if still attached after flush (detach_after_runtime_failure may have been called)
        if self.attached.read().is_empty() {
            return Err(anyhow::anyhow!("{source} failed to enable AF_XDP redirect: map sync failed"));
        }

        self.proxy_redirect_enabled.store(true, Ordering::Relaxed);
        self.set_proxy_fallback_reason(xdp_proxy_partial_detail(&self.config));
        self.set_tcp_dataplane_detail(xdp_tcp_dataplane_detail(&self.config));
        self.persist_status();
        Ok(true)
    }

    fn queue_statuses_for_config(&self) -> Vec<XdpQueueStatus> {
        let statuses = self.xsk_status.read().clone();
        if !statuses.is_empty() {
            return statuses;
        }
        self.config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
            .flat_map(|interface| {
                interface.queues.iter().map(|queue| XdpQueueStatus {
                    interface: interface.name.clone(),
                    queue: *queue,
                    configured: true,
                    socket_created: false,
                    registered: false,
                    ready: false,
                    detail: if self.config.proxy.ports.is_empty() {
                        "proxy ports not configured; traffic will PASS".to_string()
                    } else if xdp_supported_proxy_port_count(&self.config) == 0 {
                        "no AF_XDP-supported proxy ports configured; traffic will PASS".to_string()
                    } else {
                        "AF_XDP runtime not started".to_string()
                    },
                    ..XdpQueueStatus::default()
                })
            })
            .collect()
    }

    fn status(&self) -> XdpStatusSnapshot {
        self.refresh_counters();
        let state = self.state.read();
        let attached = self.attached.read();
        let fallback_reason = self.fallback_reason.read().clone();
        let proxy_fallback_reason = self.proxy_fallback_reason.read().clone();
        let tcp_dataplane_detail = self.tcp_dataplane_detail();
        let queue_statuses = self.queue_statuses_for_config();
        let interfaces = self
            .config
            .interfaces
            .iter()
            .map(|interface| {
                let is_attached = attached.contains(&interface.name);
                let xsk_queues = queue_statuses
                    .iter()
                    .filter(|status| status.interface == interface.name)
                    .cloned()
                    .collect::<Vec<_>>();
                let xsk_ready = interface.mode == XdpRuntimeMode::Proxy
                    && !xsk_queues.is_empty()
                    && xsk_queues.iter().all(|status| status.ready);
                XdpInterfaceStatus {
                    name: interface.name.clone(),
                    mode: interface.mode.as_str().to_string(),
                    queues: interface.queues.clone(),
                    local_ips: interface.local_ips.clone(),
                    frame_size: interface.frame_size,
                    attached: is_attached,
                    xsk_ready,
                    xsk_queues,
                    detail: if is_attached {
                        if interface.mode == XdpRuntimeMode::Proxy {
                            if self.config.proxy.ports.is_empty() {
                                "attached; proxy port map is empty; passing traffic".to_string()
                            } else if !XDP_PROXY_DATAPLANE_ACTIVE {
                                "attached; AF_XDP sockets staged but proxy dataplane is not active"
                                    .to_string()
                            } else if xdp_supported_proxy_port_count(&self.config) == 0 {
                                "attached; no AF_XDP-supported proxy ports; passing traffic"
                                    .to_string()
                            } else if xsk_ready {
                                if !self.proxy_redirect_enabled.load(Ordering::Relaxed) {
                                    "attached; AF_XDP sockets ready; redirect disabled until proxy bridge starts; passing traffic".to_string()
                                } else {
                                    let detail = xdp_proxy_partial_detail(&self.config);
                                    if detail.is_empty() {
                                        "attached; AF_XDP redirect ready".to_string()
                                    } else {
                                        format!("attached; AF_XDP redirect ready; {detail}")
                                    }
                                }
                            } else {
                                "attached; AF_XDP sockets not ready".to_string()
                            }
                        } else {
                            "attached".to_string()
                        }
                    } else if fallback_reason.is_empty() {
                        "not attached".to_string()
                    } else {
                        fallback_reason.clone()
                    },
                }
            })
            .collect::<Vec<_>>();
        let attached_any = !attached.is_empty();
        let xsk_configured_queues = queue_statuses
            .iter()
            .filter(|status| status.configured)
            .count();
        let xsk_ready_queues = queue_statuses.iter().filter(|status| status.ready).count();
        let proxy_supported_ports = xdp_supported_proxy_port_count(&self.config);
        let proxy_unsupported_ports = self
            .config
            .proxy
            .ports
            .len()
            .saturating_sub(proxy_supported_ports);
        let proxy_ready = self.proxy_redirect_enabled.load(Ordering::Relaxed)
            && self.config.interfaces.iter().any(|interface| {
                interface.mode == XdpRuntimeMode::Proxy
                    && !interface.queues.is_empty()
                    && interface.queues.iter().all(|queue| {
                        queue_statuses.iter().any(|status| {
                            status.interface == interface.name
                                && status.queue == *queue
                                && status.ready
                        })
                    })
            });
        XdpStatusSnapshot {
            enabled: self.config.enabled,
            available: self.config.enabled && attached_any && fallback_reason.is_empty(),
            attached: attached_any,
            attach_mode: self.config.attach_mode.as_str().to_string(),
            fallback: self.config.fallback.as_str().to_string(),
            fallback_reason,
            ebpf_object: ebpf_object_path().display().to_string(),
            interfaces,
            exact_blocked_v4: state.blocked_ips.keys().filter(|ip| ip.is_ipv4()).count(),
            exact_blocked_v6: state.blocked_ips.keys().filter(|ip| ip.is_ipv6()).count(),
            exact_allowed_v4: state.allowed_ips.keys().filter(|ip| ip.is_ipv4()).count(),
            exact_allowed_v6: state.allowed_ips.keys().filter(|ip| ip.is_ipv6()).count(),
            blocked_networks: state.blocked_networks.len(),
            allowed_networks: state.allowed_networks.len(),
            blocked_ranges: state.blocked_ranges.len(),
            allowed_ranges: state.allowed_ranges.len(),
            proxy_ports: self.config.proxy.ports.len(),
            proxy_supported_ports,
            proxy_unsupported_ports,
            proxy_ready,
            proxy_redirect_enabled: self.proxy_redirect_enabled.load(Ordering::Relaxed),
            proxy_fallback_reason,
            tcp_dataplane_ready: xdp_proxy_has_tcp_like_ports(&self.config)
                && xdp_tcp_dataplane_supported()
                && proxy_ready
                && tcp_dataplane_detail.is_empty(),
            tcp_dataplane_detail,
            xsk_configured_queues,
            xsk_ready_queues,
            packets: self.packets.load(Ordering::Relaxed),
            pass: self.pass.load(Ordering::Relaxed),
            drop: self.drop.load(Ordering::Relaxed),
            redirect: self.redirect.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            map_miss: self.map_miss.load(Ordering::Relaxed),
            xsk_drops: self.xsk_drops.load(Ordering::Relaxed),
            updated_at: crate::utils::time::now_timestamp(),
        }
    }

    fn persist_status(&self) {
        let now = crate::utils::time::now_timestamp() as u64;
        let last = self.last_state_write_at.load(Ordering::Relaxed);
        if now.saturating_sub(last) < XDP_STATE_WRITE_INTERVAL_SECS {
            return;
        }
        if self
            .last_state_write_at
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let paths = crate::paths::NodePaths::current();
        let path = paths.xdp_state_file();
        let status = self.status();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Some(parent) = path.parent() {
                        let _ = tokio::fs::create_dir_all(parent).await;
                    }
                    match serde_json::to_vec_pretty(&status) {
                        Ok(body) => {
                            let _ = tokio::fs::write(path, body).await;
                        }
                        Err(err) => tracing::warn!("failed to encode XDP status: {}", err),
                    }
                });
            }
            Err(_) => {
                if let Err(err) = write_status_snapshot_blocking(&path, &status) {
                    tracing::warn!("failed to write XDP status: {}", err);
                }
            }
        }
    }

    fn persist_status_blocking(&self) {
        self.last_state_write_at.store(
            crate::utils::time::now_timestamp() as u64,
            Ordering::Relaxed,
        );
        let path = crate::paths::NodePaths::current().xdp_state_file();
        let status = self.status();
        if let Err(err) = write_status_snapshot_blocking(&path, &status) {
            tracing::warn!("failed to write XDP status: {}", err);
        }
    }

    fn update_block_ip(&self, ip: IpAddr, ttl_secs: i64) {
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state.write().blocked_ips.insert(ip, expiry);
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_block_ip(&self, ip: IpAddr) {
        self.state.write().blocked_ips.remove(&ip);
        self.request_map_sync();
        self.persist_status();
    }

    fn update_block_network(&self, net: IpNet, ttl_secs: i64) {
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state
            .write()
            .blocked_networks
            .insert(net.to_string(), (net, expiry));
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_block_network(&self, net: IpNet) {
        self.state.write().blocked_networks.remove(&net.to_string());
        self.request_map_sync();
        self.persist_status();
    }

    fn update_block_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        if from > to {
            return;
        }
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state
            .write()
            .blocked_ranges
            .insert(RangeKey { from, to, v6 }, expiry);
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_block_range(&self, from: u128, to: u128, v6: bool) {
        self.state
            .write()
            .blocked_ranges
            .remove(&RangeKey { from, to, v6 });
        self.request_map_sync();
        self.persist_status();
    }

    fn sync_snapshot(&self, snapshot: &KernelFilterSnapshot) {
        let mut state = self.state.write();
        state.sync_from_snapshot(snapshot);
        state.retain_active(crate::utils::time::now_timestamp());
        drop(state);
        self.request_map_sync();
        self.persist_status();
    }

    fn sweep_expired_rules(&self) -> bool {
        let changed = self
            .state
            .write()
            .retain_active(crate::utils::time::now_timestamp());
        if changed {
            self.request_map_sync();
            self.persist_status();
        }
        changed
    }

    #[cfg(test)]
    fn rule_verdict_for_ip(&self, ip: IpAddr) -> XdpRuleVerdict {
        self.state
            .read()
            .ip_verdict(ip, crate::utils::time::now_timestamp())
    }

    /// Signal the background worker that the shadow rule state changed. Multiple
    /// signals during a burst coalesce into one debounced incremental map write,
    /// so a flood that blocks thousands of distinct IPs no longer triggers a full
    /// map rebuild per block. The userspace `is_l4_blocked` check still applies
    /// immediately; XDP enforcement follows within the debounce window.
    fn request_map_sync(&self) {
        self.map_sync_notify.notify_one();
    }

    /// Synchronous full reconciliation of every map (interface policy, local IPs,
    /// proxy ports, XSK indices and all rule maps). Used on cold start / reload /
    /// proxy-redirect enable where we want the maps populated before returning.
    #[cfg(target_os = "linux")]
    fn flush_maps_full_blocking(&self, proxy_dataplane_active: bool) {
        if self.attached.read().is_empty() {
            return;
        }
        let state = self.state.read().clone();
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_maps(ebpf, &self.config, &state, proxy_dataplane_active),
                None => Ok(()),
            }
        };
        match result {
            Ok(()) => *self.synced.lock() = state,
            Err(err) => {
                let reason = format!("map sync failed: {err}");
                self.detach_after_runtime_failure(reason);
                tracing::warn!("XDP map sync failed; detached and falling back: {}", err);
            }
        }
    }

    /// Incremental reconciliation of just the rule maps, diffing the live shadow
    /// state against the last-applied image. Run by the background worker.
    #[cfg(target_os = "linux")]
    fn flush_maps_diff(&self) {
        if self.attached.read().is_empty() {
            return;
        }
        let new_state = self.state.read().clone();
        let old_state = self.synced.lock().clone();
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::apply_rule_diff(ebpf, &old_state, &new_state),
                None => Ok(()),
            }
        };
        match result {
            Ok(()) => *self.synced.lock() = new_state,
            Err(err) => {
                let reason = format!("map diff sync failed: {err}");
                self.detach_after_runtime_failure(reason);
                tracing::warn!("XDP map diff sync failed; detached and falling back: {}", err);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn flush_maps_diff(&self) {}

    #[cfg(not(target_os = "linux"))]
    fn flush_maps_full_blocking(&self, _proxy_dataplane_active: bool) {}

    #[cfg(target_os = "linux")]
    fn detach_after_runtime_failure(&self, reason: String) {
        if let Err(err) = linux::detach_blocking(&self.config) {
            let detail = format!("{reason}; detach failed: {err}");
            self.set_fallback_reason(detail.clone());
            tracing::warn!("failed to detach XDP after runtime failure: {}", err);
        } else {
            self.set_fallback_reason(reason);
        }
        *self.ebpf.lock() = None;
        *self.af_xdp.lock() = None;
        self.attached.write().clear();
        self.xsk_status.write().clear();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        self.set_proxy_fallback_reason("runtime failure detached XDP; socket path is active");
        self.persist_status_blocking();
    }

    fn refresh_counters(&self) {
        #[cfg(target_os = "linux")]
        {
            let counters = {
                let ebpf = self.ebpf.lock();
                ebpf.as_ref()
                    .and_then(|ebpf| linux::read_counters(ebpf).ok())
            };
            if let Some(counters) = counters {
                self.packets.store(counters.packets, Ordering::Relaxed);
                self.pass.store(counters.pass, Ordering::Relaxed);
                self.drop.store(counters.drop, Ordering::Relaxed);
                self.redirect.store(counters.redirect, Ordering::Relaxed);
                self.parse_errors
                    .store(counters.parse_errors, Ordering::Relaxed);
                self.map_miss.store(counters.map_miss, Ordering::Relaxed);
                self.xsk_drops.store(counters.xsk_drops, Ordering::Relaxed);
            }
        }
    }

    fn dump_maps(&self) -> serde_json::Value {
        let queue_statuses = self.queue_statuses_for_config();
        let interfaces = self
            .config
            .interfaces
            .iter()
            .map(|interface| {
                serde_json::json!({
                    "name": interface.name,
                    "mode": interface.mode.as_str(),
                    "queues": interface.queues,
                    "frameSize": interface.frame_size,
                    "localIpFilter": !interface.local_ips.is_empty(),
                    "localIps": interface.local_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        let proxy_ports = self
            .config
            .proxy
            .ports
            .iter()
            .map(|port| {
                serde_json::json!({
                    "protocol": port.protocol.as_str(),
                    "port": port.port,
                    "proto": xdp_ip_proto(&port.protocol),
                    "dataplaneSupported": xdp_protocol_dataplane_supported(&port.protocol),
                    "portBeBytes": port.port.to_be_bytes(),
                })
            })
            .collect::<Vec<_>>();
        let state = self.state.read();
        let now = crate::utils::time::now_timestamp();
        serde_json::json!({
            "interfaces": interfaces,
            "proxyPorts": proxy_ports,
            "proxyPortSummary": {
                "total": self.config.proxy.ports.len(),
                "supported": xdp_supported_proxy_port_count(&self.config),
                "unsupported": self.config.proxy.ports.len().saturating_sub(xdp_supported_proxy_port_count(&self.config)),
                "redirectEnabled": self.proxy_redirect_enabled.load(Ordering::Relaxed),
            },
            "tcpDataplane": {
                "ready": xdp_tcp_dataplane_supported(),
                "detail": self.tcp_dataplane_detail(),
            },
            "xskQueues": queue_statuses,
            "blockedIps": state.blocked_ips.iter().filter(|(_, expiry)| **expiry > now).map(|(ip, expiry)| serde_json::json!({"ip": ip.to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "allowedIps": state.allowed_ips.iter().filter(|(_, expiry)| **expiry > now).map(|(ip, expiry)| serde_json::json!({"ip": ip.to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "blockedNetworks": state.blocked_networks.values().filter(|(_, expiry)| *expiry > now).map(|(net, expiry)| serde_json::json!({"network": net.to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "allowedNetworks": state.allowed_networks.values().filter(|(_, expiry)| *expiry > now).map(|(net, expiry)| serde_json::json!({"network": net.to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "blockedRanges": state.blocked_ranges.iter().filter(|(_, expiry)| **expiry > now).map(|(range, expiry)| serde_json::json!({"from": range_bound_to_ip(range.from, range.v6).to_string(), "to": range_bound_to_ip(range.to, range.v6).to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
            "allowedRanges": state.allowed_ranges.iter().filter(|(_, expiry)| **expiry > now).map(|(range, expiry)| serde_json::json!({"from": range_bound_to_ip(range.from, range.v6).to_string(), "to": range_bound_to_ip(range.to, range.v6).to_string(), "expiresAt": expiry})).collect::<Vec<_>>(),
        })
    }

    fn active_rule_snapshot(&self) -> KernelFilterSnapshot {
        self.state
            .read()
            .active_snapshot(crate::utils::time::now_timestamp())
    }

    async fn detach_runtime(&self, reason: &'static str) -> anyhow::Result<()> {
        self.stop_rule_sweeper();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        {
            let disable_result = {
                let mut ebpf = self.ebpf.lock();
                match ebpf.as_mut() {
                    Some(ebpf) => linux::disable_proxy_redirect(ebpf, &self.config),
                    None => Ok(()),
                }
            };
            if let Err(err) = disable_result {
                tracing::warn!(
                    "failed to clear AF_XDP redirect maps during XDP detach: {}",
                    err
                );
            }
            *self.af_xdp.lock() = None;
            linux::detach(&self.config).await?;
            *self.ebpf.lock() = None;
        }
        self.attached.write().clear();
        self.xsk_status.write().clear();
        self.set_fallback_reason(reason);
        self.set_proxy_fallback_reason(String::new());
        self.persist_status_blocking();
        Ok(())
    }

    fn stop_rule_sweeper(&self) {
        self.rule_sweeper_generation.fetch_add(1, Ordering::Relaxed);
        self.rule_sweeper_started.store(false, Ordering::Relaxed);
    }
}

static XDP_MANAGER: OnceLock<parking_lot::RwLock<std::sync::Arc<XdpManager>>> = OnceLock::new();

fn manager_from_runtime() -> std::sync::Arc<XdpManager> {
    let config = RuntimeConfig::current()
        .map(|runtime| runtime.xdp)
        .unwrap_or_default();
    let manager = XDP_MANAGER.get_or_init(|| {
        parking_lot::RwLock::new(std::sync::Arc::new(XdpManager::new(config.clone())))
    });

    {
        let current = manager.read();
        if current.config == config || !current.attached.read().is_empty() {
            return current.clone();
        }
    }

    let mut current = manager.write();
    if current.config != config && current.attached.read().is_empty() {
        *current = std::sync::Arc::new(XdpManager::new(config));
    }
    current.clone()
}

fn replace_manager_from_runtime() -> std::sync::Arc<XdpManager> {
    let config = RuntimeConfig::current()
        .map(|runtime| runtime.xdp)
        .unwrap_or_default();
    let manager = XDP_MANAGER.get_or_init(|| {
        parking_lot::RwLock::new(std::sync::Arc::new(XdpManager::new(config.clone())))
    });
    let mut current = manager.write();
    *current = std::sync::Arc::new(XdpManager::new(config));
    current.clone()
}

fn manager_is_current(candidate: &std::sync::Arc<XdpManager>) -> bool {
    let Some(manager) = XDP_MANAGER.get() else {
        return false;
    };
    let current = manager.read();
    std::sync::Arc::ptr_eq(candidate, &*current)
}

fn start_rule_sweeper(manager: &std::sync::Arc<XdpManager>) {
    if !manager.config.enabled {
        return;
    }
    if manager.rule_sweeper_started.swap(true, Ordering::Relaxed) {
        return;
    }
    let generation = manager.rule_sweeper_generation.load(Ordering::Relaxed);
    let manager = manager.clone();
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(XDP_RULE_SWEEP_INTERVAL_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if manager.rule_sweeper_generation.load(Ordering::Relaxed) != generation {
                break;
            }
            if manager.sweep_expired_rules() {
                tracing::debug!("XDP rule sweeper removed expired shadow rules");
            }
        }
    });
}

fn start_map_sync_worker(manager: &std::sync::Arc<XdpManager>) {
    if !manager.config.enabled {
        return;
    }
    if manager.map_sync_started.swap(true, Ordering::Relaxed) {
        return;
    }
    let manager = manager.clone();
    tokio::spawn(async move {
        loop {
            manager.map_sync_notify.notified().await;
            tokio::time::sleep(std::time::Duration::from_millis(XDP_MAP_SYNC_DEBOUNCE_MS)).await;
            if !manager_is_current(&manager) {
                break;
            }
            manager.flush_maps_diff();
        }
    });
}

pub async fn initialize_from_runtime() -> anyhow::Result<()> {
    let manager = manager_from_runtime();
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    start_map_sync_worker(&manager);
    Ok(())
}

pub async fn build_kernel_filter() -> Option<Box<dyn KernelFilter>> {
    let manager = manager_from_runtime();
    if !manager.config.enabled {
        return None;
    }
    if let Err(err) = manager.initialize().await {
        tracing::warn!("XDP kernel filter unavailable: {}", err);
        return None;
    }
    let status = manager.status();
    if !status.available {
        tracing::warn!(
            "XDP kernel filter unavailable; fallback_reason={}",
            status.fallback_reason
        );
        return None;
    }
    start_rule_sweeper(&manager);
    Some(Box::new(XdpKernelFilter { manager }))
}

pub fn status_snapshot() -> XdpStatusSnapshot {
    manager_from_runtime().status()
}

pub fn persisted_status_snapshot() -> Option<XdpStatusSnapshot> {
    let path = crate::paths::NodePaths::current().xdp_state_file();
    let body = std::fs::read(path).ok()?;
    serde_json::from_slice(&body).ok()
}

pub async fn attach_from_runtime() -> anyhow::Result<()> {
    let manager = manager_from_runtime();
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    manager.persist_status_blocking();
    Ok(())
}

pub async fn detach() -> anyhow::Result<()> {
    let manager = manager_from_runtime();
    manager.detach_runtime("detached by CLI").await
}

pub async fn reload_from_runtime() -> anyhow::Result<()> {
    let runtime_config = RuntimeConfig::current()
        .map(|runtime| runtime.xdp)
        .unwrap_or_default();
    let current = manager_from_runtime();
    if current.config == runtime_config && !current.attached.read().is_empty() {
        current.flush_maps_full_blocking(current.proxy_redirect_ready());
        current.persist_status_blocking();
        return Ok(());
    }

    let snapshot = detach_current_for_reload().await?;
    let manager = replace_manager_from_runtime();
    manager.sync_snapshot(&snapshot);
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    manager.persist_status_blocking();
    Ok(())
}

async fn detach_current_for_reload() -> anyhow::Result<KernelFilterSnapshot> {
    let old_manager = manager_from_runtime();
    let snapshot = old_manager.active_rule_snapshot();
    old_manager
        .detach_runtime("detached for XDP reload")
        .await?;
    Ok(snapshot)
}

pub fn doctor_report() -> String {
    let runtime = RuntimeConfig::current()
        .map(|runtime| runtime.xdp.clone())
        .unwrap_or_default();
    doctor_report_for_config(&runtime)
}

fn doctor_report_for_config(config: &XdpConfig) -> String {
    let object_path = ebpf_object_path();
    let mut lines = Vec::new();
    lines.push("CloudNode XDP doctor".to_string());
    lines.push(format!("  enabled:       {}", yes_no(config.enabled)));
    lines.push(format!("  attach mode:   {}", config.attach_mode.as_str()));
    lines.push(format!("  fallback:      {}", config.fallback.as_str()));
    lines.push(format!(
        "  protocols:     {}",
        config
            .proxy
            .protocols
            .iter()
            .map(XdpProxyProtocol::as_str)
            .collect::<Vec<_>>()
            .join(",")
    ));
    lines.push(format!("  proxy ports:   {}", config.proxy.ports.len()));
    lines.push(format!("  eBPF object:   {}", object_path.display()));
    lines.push(format!("  object exists: {}", yes_no(object_path.exists())));
    lines.push(format!("  platform:      {}", std::env::consts::OS));
    #[cfg(target_os = "linux")]
    {
        lines.push(format!("  bpffs pin dir: {}", XDP_BPF_PIN_DIR));
        lines.push(format!(
            "  bpffs exists:  {}",
            yes_no(std::path::Path::new(XDP_BPF_PIN_DIR).is_dir())
        ));
    }
    if config.enabled && config.interfaces.is_empty() {
        lines.push("  issue:         xdp.enabled=true but interfaces is empty".to_string());
    }
    if config.enabled
        && !config.proxy.ports.is_empty()
        && config
            .interfaces
            .iter()
            .any(|interface| interface.mode == XdpRuntimeMode::Proxy)
    {
        let supported = xdp_supported_proxy_port_count(config);
        let unsupported = xdp_unsupported_proxy_protocols(config);
        if !XDP_PROXY_DATAPLANE_ACTIVE {
            lines.push(
                "  warning:       AF_XDP proxy sockets can be staged, but userspace proxy dataplane registration is not active; traffic will PASS"
                    .to_string(),
            );
        } else {
            lines.push(format!(
                "  dataplane:     AF_XDP proxy ports supported={supported} total={}",
                config.proxy.ports.len()
            ));
        }
        if !unsupported.is_empty() {
            lines.push(format!(
                "  warning:       unsupported AF_XDP proxy protocols stay on socket fallback: {}",
                unsupported.join(",")
            ));
        }
        let tcp_detail = xdp_tcp_dataplane_detail(config);
        if !tcp_detail.is_empty() {
            lines.push(format!("  warning:       {tcp_detail}"));
        }
        let frame_size_detail = xdp_proxy_frame_size_detail(config);
        if !frame_size_detail.is_empty() {
            lines.push(format!("  issue:         {frame_size_detail}"));
        }
    }
    for interface in &config.interfaces {
        lines.push(format!(
            "  interface:     {} mode={} queues={:?} frameSize={} localIps={}",
            interface.name,
            interface.mode.as_str(),
            interface.queues,
            interface.frame_size,
            interface.local_ips.len()
        ));
        if interface.mode == XdpRuntimeMode::Proxy && interface.frame_size > 2048 {
            lines.push(format!(
                "  warning:       interface {} proxy mode currently targets standard MTU; jumbo/multi-buffer should stay off",
                interface.name
            ));
        }
        if interface.mode == XdpRuntimeMode::Proxy && config.proxy.ports.is_empty() {
            lines.push(format!(
                "  warning:       interface {} proxy mode has no xdp.proxy.ports entries; traffic will PASS",
                interface.name
            ));
        }
        if interface.mode == XdpRuntimeMode::Proxy
            && !config.proxy.ports.is_empty()
            && interface.local_ips.is_empty()
        {
            lines.push(format!(
                "  warning:       interface {} proxy mode has no localIps; redirect matches configured ports on all destination IPs",
                interface.name
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    lines.push("  issue:         XDP attach is supported on Linux only".to_string());
    lines.join("\n")
}

pub fn dump_maps() -> serde_json::Value {
    manager_from_runtime().dump_maps()
}

#[cfg(target_os = "linux")]
pub async fn raw_smoke(
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    let manager = manager_from_runtime();
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    manager.enable_proxy_redirect("raw smoke")?;
    let result = raw_smoke_inner(manager, duration, ready_file).await;
    if let Err(err) = detach().await {
        tracing::warn!("failed to detach XDP after raw smoke: {}", err);
    }
    result
}

#[cfg(target_os = "linux")]
async fn raw_smoke_inner(
    manager: std::sync::Arc<XdpManager>,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    let initial_status = manager.status();
    anyhow::ensure!(
        initial_status.proxy_ready,
        "AF_XDP proxy runtime is not ready: {}",
        if initial_status.proxy_fallback_reason.is_empty() {
            initial_status.fallback_reason.as_str()
        } else {
            initial_status.proxy_fallback_reason.as_str()
        }
    );
    if let Some(path) = ready_file.as_ref() {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, b"ready\n")?;
    }

    let deadline = tokio::time::Instant::now() + duration;
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut frames_seen = 0u64;
    let mut udp_seen = 0u64;
    let mut tcp_seen = 0u64;
    let mut unparseable_seen = 0u64;
    let mut samples = Vec::new();

    while tokio::time::Instant::now() < deadline {
        let mut frames = Vec::with_capacity(64);
        let stats = {
            let mut runtime = manager.af_xdp.lock();
            let Some(runtime) = runtime.as_mut() else {
                anyhow::bail!("AF_XDP runtime is not initialized");
            };
            runtime.poll_raw_once(|interface, queue, frame| {
                frames.push((interface.to_string(), queue, frame));
            })?
        };

        for (interface, queue, frame) in frames {
            frames_seen = frames_seen.saturating_add(1);
            match af_xdp::parse_proxy_frame(&interface, queue, &frame) {
                Some(af_xdp::AfXdpProxyFrame::Udp { packet, .. }) => {
                    udp_seen = udp_seen.saturating_add(1);
                    if samples.len() < 8 {
                        samples.push(serde_json::json!({
                            "protocol": "udp",
                            "interface": interface,
                            "queue": queue,
                            "local": packet.local_addr.to_string(),
                            "peer": packet.peer_addr.to_string(),
                            "payloadBytes": packet.payload.len(),
                        }));
                    }
                }
                Some(af_xdp::AfXdpProxyFrame::Tcp {
                    flow, ip_packet, ..
                }) => {
                    tcp_seen = tcp_seen.saturating_add(1);
                    if samples.len() < 8 {
                        samples.push(serde_json::json!({
                            "protocol": "tcp",
                            "interface": interface,
                            "queue": queue,
                            "local": flow.local_addr.to_string(),
                            "peer": flow.peer_addr.to_string(),
                            "ipPacketBytes": ip_packet.len(),
                        }));
                    }
                }
                None => {
                    unparseable_seen = unparseable_seen.saturating_add(1);
                }
            }
        }

        if stats.packets == 0 {
            tick.tick().await;
        } else {
            tokio::task::yield_now().await;
        }
    }

    let status = manager.status();
    let report = serde_json::json!({
        "durationMillis": duration.as_millis(),
        "frames": frames_seen,
        "udp": udp_seen,
        "tcp": tcp_seen,
        "unparseable": unparseable_seen,
        "tcpDataplaneReady": status.tcp_dataplane_ready,
        "tcpDataplaneDetail": status.tcp_dataplane_detail,
        "proxyReady": status.proxy_ready,
        "xskReadyQueues": status.xsk_ready_queues,
        "packets": status.packets,
        "pass": status.pass,
        "drop": status.drop,
        "redirect": status.redirect,
        "parseErrors": status.parse_errors,
        "mapMiss": status.map_miss,
        "xskDrops": status.xsk_drops,
        "samples": samples,
    });
    Ok(report)
}

#[cfg(target_os = "linux")]
pub async fn proxy_smoke(
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    af_xdp::reset_tcp_diag();
    crate::tcp_proxy::reset_af_xdp_tcp_proxy_diag();
    let manager = manager_from_runtime();
    let ports = xdp_proxy_smoke_ports(&manager.config)?;

    manager.initialize().await?;
    start_rule_sweeper(&manager);
    let services = match XdpProxySmokeServices::start().await {
        Ok(services) => services,
        Err(err) => {
            if let Err(detach_err) = detach().await {
                tracing::warn!("failed to detach XDP after proxy smoke setup error: {detach_err}");
            }
            return Err(err);
        }
    };
    let (quic_demux, tcp_manager, http_manager) =
        match xdp_proxy_smoke_managers(&services, &ports).await {
            Ok(managers) => managers,
            Err(err) => {
                services.abort();
                if let Err(detach_err) = detach().await {
                    tracing::warn!(
                        "failed to detach XDP after proxy smoke manager setup error: {detach_err}"
                    );
                }
                return Err(err);
            }
        };

    let bridge = tokio::spawn(af_xdp::start_proxy_bridge(
        quic_demux,
        tcp_manager,
        http_manager,
    ));
    let result = proxy_smoke_inner(manager, services, ports, duration, ready_file, &bridge).await;
    bridge.abort();
    let _ = bridge.await;
    if let Err(err) = detach().await {
        tracing::warn!("failed to detach XDP after proxy smoke: {}", err);
    }
    result
}

#[cfg(target_os = "linux")]
pub async fn proxy_reload_smoke(
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    let old_manager = manager_from_runtime();
    let ports = xdp_proxy_smoke_ports(&old_manager.config)?;

    old_manager
        .initialize()
        .await
        .map_err(|err| anyhow::anyhow!("AF_XDP reload initial initialize failed: {err}"))?;
    start_rule_sweeper(&old_manager);
    let services = match XdpProxySmokeServices::start().await {
        Ok(services) => services,
        Err(err) => {
            if let Err(detach_err) = detach().await {
                tracing::warn!(
                    "failed to detach XDP after proxy reload smoke setup error: {detach_err}"
                );
            }
            return Err(err);
        }
    };
    let (old_quic_demux, old_tcp_manager, old_http_manager) = match xdp_proxy_smoke_managers(
        &services, &ports,
    )
    .await
    {
        Ok(managers) => managers,
        Err(err) => {
            services.abort();
            if let Err(detach_err) = detach().await {
                tracing::warn!(
                    "failed to detach XDP after proxy reload smoke manager setup error: {detach_err}"
                );
            }
            return Err(err);
        }
    };

    let old_bridge = tokio::spawn(af_xdp::start_proxy_bridge(
        old_quic_demux,
        old_tcp_manager,
        old_http_manager,
    ));
    let result = proxy_reload_smoke_inner(
        old_manager,
        services,
        ports,
        duration,
        ready_file,
        old_bridge,
    )
    .await;
    if let Err(err) = detach().await {
        tracing::warn!("failed to detach XDP after proxy reload smoke: {}", err);
    }
    result
}

#[cfg(target_os = "linux")]
async fn proxy_reload_smoke_inner(
    old_manager: std::sync::Arc<XdpManager>,
    services: XdpProxySmokeServices,
    _ports: XdpProxySmokePorts,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
    old_bridge: tokio::task::JoinHandle<()>,
) -> anyhow::Result<serde_json::Value> {
    wait_for_proxy_smoke_ready(&old_manager, duration, &old_bridge).await?;
    let before_reload = old_manager.status();

    reload_from_runtime().await?;
    let after_manager = manager_from_runtime();
    let bridge_preserved =
        std::sync::Arc::ptr_eq(&old_manager, &after_manager) && !old_bridge.is_finished();
    let result = async {
        wait_for_proxy_smoke_ready(&after_manager, duration, &old_bridge).await?;
        write_ready_file(ready_file.as_ref())?;
        tokio::time::sleep(duration).await;
        let after_reload = after_manager.status();
        anyhow::ensure!(
            before_reload.proxy_ready && before_reload.proxy_redirect_enabled,
            "proxy bridge was not ready before reload"
        );
        anyhow::ensure!(
            after_reload.proxy_ready && after_reload.proxy_redirect_enabled,
            "proxy bridge was not ready after reload"
        );
        anyhow::ensure!(
            after_reload.tcp_dataplane_ready,
            "TCP dataplane was not ready after reload: {}",
            after_reload.tcp_dataplane_detail
        );
        anyhow::ensure!(
            before_reload.redirect <= after_reload.redirect,
            "XDP redirect counter moved backwards across reload"
        );
        Ok(serde_json::json!({
            "durationMillis": duration.as_millis(),
            "oldBridgeExited": false,
            "bridgePreserved": bridge_preserved,
            "managerReplaced": !std::sync::Arc::ptr_eq(&old_manager, &after_manager),
            "beforeReload": {
                "proxyReady": before_reload.proxy_ready,
                "proxyRedirectEnabled": before_reload.proxy_redirect_enabled,
                "tcpDataplaneReady": before_reload.tcp_dataplane_ready,
                "xskReadyQueues": before_reload.xsk_ready_queues,
                "fallbackReason": before_reload.fallback_reason,
                "proxyFallbackReason": before_reload.proxy_fallback_reason,
                "redirect": before_reload.redirect,
                "xskDrops": before_reload.xsk_drops,
            },
            "afterReload": {
                "proxyReady": after_reload.proxy_ready,
                "proxyRedirectEnabled": after_reload.proxy_redirect_enabled,
                "tcpDataplaneReady": after_reload.tcp_dataplane_ready,
                "tcpDataplaneDetail": after_reload.tcp_dataplane_detail,
                "xskReadyQueues": after_reload.xsk_ready_queues,
                "fallbackReason": after_reload.fallback_reason,
                "proxyFallbackReason": after_reload.proxy_fallback_reason,
                "packets": after_reload.packets,
                "pass": after_reload.pass,
                "drop": after_reload.drop,
                "redirect": after_reload.redirect,
                "parseErrors": after_reload.parse_errors,
                "mapMiss": after_reload.map_miss,
                "xskDrops": after_reload.xsk_drops,
            },
        }))
    }
    .await;
    old_bridge.abort();
    let _ = old_bridge.await;
    services.abort();
    result
}

#[cfg(target_os = "linux")]
async fn proxy_smoke_inner(
    manager: std::sync::Arc<XdpManager>,
    services: XdpProxySmokeServices,
    ports: XdpProxySmokePorts,
    duration: std::time::Duration,
    ready_file: Option<std::path::PathBuf>,
    bridge: &tokio::task::JoinHandle<()>,
) -> anyhow::Result<serde_json::Value> {
    wait_for_proxy_smoke_ready(&manager, duration, bridge).await?;
    write_ready_file(ready_file.as_ref())?;

    tokio::time::sleep(duration).await;
    let status = manager.status();
    let report = serde_json::json!({
        "durationMillis": duration.as_millis(),
        "proxyReady": status.proxy_ready,
        "proxyRedirectEnabled": status.proxy_redirect_enabled,
        "tcpDataplaneReady": status.tcp_dataplane_ready,
        "tcpDataplaneDetail": status.tcp_dataplane_detail,
        "xskReadyQueues": status.xsk_ready_queues,
        "packets": status.packets,
        "pass": status.pass,
        "drop": status.drop,
        "redirect": status.redirect,
        "parseErrors": status.parse_errors,
        "mapMiss": status.map_miss,
        "xskDrops": status.xsk_drops,
        "ports": {
            "http": ports.http,
            "https": ports.https,
            "tcp": ports.tcp,
            "udp": ports.udp,
            "h3": ports.h3,
        },
        "backends": {
            "http": services.http_addr.to_string(),
            "https": services.https_addr.to_string(),
            "tcp": services.tcp_addr.to_string(),
            "udp": services.udp_addr.to_string(),
            "h3": services.h3_addr.to_string(),
            "sni": services.sni_addr.to_string(),
            "quic": services.quic_addr.to_string(),
        },
        "app": {
            "httpRequests": services.http_requests.load(Ordering::Relaxed),
            "httpsRequests": services.https_requests.load(Ordering::Relaxed),
            "tcpConnections": services.tcp_connections.load(Ordering::Relaxed),
            "udpDatagrams": services.udp_datagrams.load(Ordering::Relaxed),
            "h3Requests": services.h3_requests.load(Ordering::Relaxed),
            "sniConnections": services.sni_connections.load(Ordering::Relaxed),
            "quicRequests": services.quic_requests.load(Ordering::Relaxed),
        },
        "tcpDiag": af_xdp::tcp_diag_snapshot(),
        "tcpProxyDiag": crate::tcp_proxy::af_xdp_tcp_proxy_diag_snapshot(),
    });
    services.abort();
    Ok(report)
}

#[cfg(target_os = "linux")]
fn write_ready_file(path: Option<&std::path::PathBuf>) -> anyhow::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, b"ready\n")?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn wait_for_proxy_smoke_ready(
    manager: &XdpManager,
    timeout: std::time::Duration,
    bridge: &tokio::task::JoinHandle<()>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout.max(std::time::Duration::from_millis(1));
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(25));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let status = manager.status();
        if status.proxy_ready && status.tcp_dataplane_ready {
            return Ok(());
        }
        if bridge.is_finished() {
            anyhow::bail!(
                "AF_XDP proxy bridge exited before smoke was ready: {}",
                if status.proxy_fallback_reason.is_empty() {
                    status.fallback_reason
                } else {
                    status.proxy_fallback_reason
                }
            );
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for AF_XDP proxy bridge readiness: {}",
                if status.proxy_fallback_reason.is_empty() {
                    status.fallback_reason
                } else {
                    status.proxy_fallback_reason
                }
            );
        }
        tick.tick().await;
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct XdpProxySmokePorts {
    http: u16,
    https: u16,
    tcp: u16,
    udp: u16,
    h3: u16,
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_ports(config: &XdpConfig) -> anyhow::Result<XdpProxySmokePorts> {
    let mut http = None;
    let mut https = None;
    let mut tcp = None;
    let mut udp = None;
    let mut h3 = None;
    for port in &config.proxy.ports {
        if port.port == 0 {
            continue;
        }
        match port.protocol {
            XdpProxyProtocol::Http => http.get_or_insert(port.port),
            XdpProxyProtocol::Https => https.get_or_insert(port.port),
            XdpProxyProtocol::Tcp => tcp.get_or_insert(port.port),
            XdpProxyProtocol::Udp => udp.get_or_insert(port.port),
            XdpProxyProtocol::H3 => h3.get_or_insert(port.port),
        };
    }
    Ok(XdpProxySmokePorts {
        http: http.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing an http port"))?,
        https: https.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing an https port"))?,
        tcp: tcp.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing a tcp port"))?,
        udp: udp.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing a udp port"))?,
        h3: h3.ok_or_else(|| anyhow::anyhow!("xdp.proxy.ports is missing an h3 port"))?,
    })
}

#[cfg(target_os = "linux")]
struct XdpProxySmokeServices {
    http_addr: std::net::SocketAddr,
    https_addr: std::net::SocketAddr,
    tcp_addr: std::net::SocketAddr,
    udp_addr: std::net::SocketAddr,
    h3_addr: std::net::SocketAddr,
    sni_addr: std::net::SocketAddr,
    quic_addr: std::net::SocketAddr,
    http_requests: std::sync::Arc<AtomicU64>,
    https_requests: std::sync::Arc<AtomicU64>,
    tcp_connections: std::sync::Arc<AtomicU64>,
    udp_datagrams: std::sync::Arc<AtomicU64>,
    h3_requests: std::sync::Arc<AtomicU64>,
    sni_connections: std::sync::Arc<AtomicU64>,
    quic_requests: std::sync::Arc<AtomicU64>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl XdpProxySmokeServices {
    async fn start() -> anyhow::Result<Self> {
        let http_requests = std::sync::Arc::new(AtomicU64::new(0));
        let https_requests = std::sync::Arc::new(AtomicU64::new(0));
        let tcp_connections = std::sync::Arc::new(AtomicU64::new(0));
        let udp_datagrams = std::sync::Arc::new(AtomicU64::new(0));
        let h3_requests = std::sync::Arc::new(AtomicU64::new(0));
        let sni_connections = std::sync::Arc::new(AtomicU64::new(0));
        let quic_requests = std::sync::Arc::new(AtomicU64::new(0));

        let (http_addr, http_task) =
            start_xdp_smoke_http_backend(http_requests.clone(), b"xdp-http-smoke\n").await?;
        let (https_addr, https_task) =
            start_xdp_smoke_http_backend(https_requests.clone(), b"xdp-https-smoke\n").await?;
        let (tcp_addr, tcp_task) = start_xdp_smoke_tcp_backend(tcp_connections.clone()).await?;
        let (udp_addr, udp_task) = start_xdp_smoke_udp_backend(udp_datagrams.clone()).await?;
        let (h3_addr, h3_task) =
            start_xdp_smoke_http_backend(h3_requests.clone(), b"xdp-h3-smoke\n").await?;
        let (sni_addr, sni_task) = start_xdp_smoke_sni_backend(sni_connections.clone()).await?;
        let (quic_addr, quic_task) = start_xdp_smoke_quic_backend(quic_requests.clone()).await?;

        Ok(Self {
            http_addr,
            https_addr,
            tcp_addr,
            udp_addr,
            h3_addr,
            sni_addr,
            quic_addr,
            http_requests,
            https_requests,
            tcp_connections,
            udp_datagrams,
            h3_requests,
            sni_connections,
            quic_requests,
            tasks: vec![
                http_task, https_task, tcp_task, udp_task, h3_task, sni_task, quic_task,
            ],
        })
    }

    fn abort(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_http_backend(
    requests: std::sync::Arc<AtomicU64>,
    body: &'static [u8],
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let requests = requests.clone();
            tokio::spawn(async move {
                let mut request = Vec::with_capacity(512);
                let mut buf = [0u8; 512];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                    if request.len() >= 8192 {
                        break;
                    }
                }
                requests.fetch_add(1, Ordering::Relaxed);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_tcp_backend(
    connections: std::sync::Arc<AtomicU64>,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let connections = connections.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let Ok(n) = stream.read(&mut buf).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                connections.fetch_add(1, Ordering::Relaxed);
                let _ = stream.write_all(b"xdp-tcp-smoke:").await;
                let _ = stream.write_all(&buf[..n]).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_udp_backend(
    datagrams: std::sync::Arc<AtomicU64>,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let addr = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            datagrams.fetch_add(1, Ordering::Relaxed);
            let mut response = Vec::with_capacity("xdp-udp-smoke:".len() + n);
            response.extend_from_slice(b"xdp-udp-smoke:");
            response.extend_from_slice(&buf[..n]);
            let _ = socket.send_to(&response, peer).await;
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_sni_backend(
    connections: std::sync::Arc<AtomicU64>,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::{Read, Write};

    let certs = rustls_pemfile::certs(
        &mut include_bytes!("../pingora-main/pingora-core/examples/keys/server/cert.pem")
            .as_slice(),
    )
    .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../pingora-main/pingora-core/examples/keys/server/key.pem").as_slice(),
    )?
    .ok_or_else(|| anyhow::anyhow!("xdp smoke SNI backend key is missing"))?;
    let mut tls_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, PrivateKeyDer::clone_key(&key))?;
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls_config = std::sync::Arc::new(tls_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let connections = connections.clone();
            let tls_config = tls_config.clone();
            tokio::spawn(async move {
                let Ok(std_stream) = stream.into_std() else {
                    return;
                };
                let result = tokio::task::spawn_blocking(move || {
                    std_stream.set_nonblocking(false)?;
                    let mut tls_stream = rustls::StreamOwned::new(
                        rustls::ServerConnection::new(tls_config)?,
                        std_stream,
                    );
                    let mut request = Vec::with_capacity(512);
                    let mut buf = [0u8; 512];
                    loop {
                        let n = tls_stream.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                        if request.len() >= 8192 {
                            break;
                        }
                    }
                    connections.fetch_add(1, Ordering::Relaxed);
                    let body = b"xdp-sni-smoke\n";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n",
                        body.len()
                    );
                    tls_stream.write_all(response.as_bytes())?;
                    tls_stream.write_all(body)?;
                    tls_stream.flush()?;
                    anyhow::Ok(())
                })
                .await;
                if let Ok(Err(err)) = result {
                    tracing::debug!("xdp smoke SNI backend connection failed: {}", err);
                }
            });
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn start_xdp_smoke_quic_backend(
    requests: std::sync::Arc<AtomicU64>,
) -> anyhow::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs = rustls_pemfile::certs(
        &mut include_bytes!("../pingora-main/pingora-core/examples/keys/server/cert.pem")
            .as_slice(),
    )
    .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../pingora-main/pingora-core/examples/keys/server/key.pem").as_slice(),
    )?
    .ok_or_else(|| anyhow::anyhow!("xdp smoke QUIC backend key is missing"))?;
    let mut tls_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, PrivateKeyDer::clone_key(&key))?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(std::sync::Arc::new(tls_config))?,
    ));
    if let Some(transport_config) = std::sync::Arc::get_mut(&mut server_config.transport) {
        transport_config.max_concurrent_bidi_streams(32u32.into());
        transport_config.max_concurrent_uni_streams(32u32.into());
    }
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        while let Some(connecting) = endpoint.accept().await {
            let requests = requests.clone();
            tokio::spawn(async move {
                let Ok(connection) = connecting.await else {
                    return;
                };
                let Ok(mut h3_conn) = h3::server::builder()
                    .build(h3_quinn::Connection::new(connection))
                    .await
                else {
                    return;
                };
                loop {
                    let resolver = match h3_conn.accept().await {
                        Ok(Some(resolver)) => resolver,
                        Ok(None) => break,
                        Err(_) => break,
                    };
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        requests.fetch_add(1, Ordering::Relaxed);
                        let body = bytes::Bytes::from_static(b"xdp-quic-smoke\n");
                        let Ok(response) = http::Response::builder().status(200).body(()) else {
                            return;
                        };
                        let _ = stream.send_response(response).await;
                        let _ = stream.send_data(body).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    Ok((addr, task))
}

#[cfg(target_os = "linux")]
async fn xdp_proxy_smoke_managers(
    services: &XdpProxySmokeServices,
    ports: &XdpProxySmokePorts,
) -> anyhow::Result<(
    std::sync::Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
    std::sync::Arc<crate::tcp_proxy::TcpProxyManager>,
    std::sync::Arc<crate::http_proxy_manager::HttpProxyManager>,
)> {
    let store = xdp_proxy_smoke_config_store(services, ports).await;
    let waf_state = std::sync::Arc::new(crate::firewall::state::WafStateManager::new());
    let cert_selector = std::sync::Arc::new(crate::ssl::DynamicCertSelector::new());
    crate::ssl::sync_certs(&cert_selector, &[xdp_proxy_smoke_ssl_cert()]).await;
    let api_config = std::sync::Arc::new(crate::api_config::ApiConfig {
        rpc_endpoints: Vec::new(),
        rpc_disable_update: true,
        node_id: "1".to_string(),
        secret: "xdp-smoke-secret".to_string(),
        billing_count_inbound_traffic: false,
        access_log_pipeline: crate::api_config::AccessLogPipelineConfig::default(),
        relay: crate::api_config::RelayConfig::default(),
        kernel_tuning: crate::api_config::KernelTuningConfig::default(),
    });
    let proxy_logic = crate::proxy::EdgeProxy {
        config: std::sync::Arc::new(store.clone()),
        waf_state: waf_state.clone(),
        api_config: api_config.clone(),
        cert_selector: cert_selector.clone(),
        waf_verifier: std::sync::Arc::new(crate::firewall::verifier::WafVerifier::new(
            &api_config.secret,
        )),
        tls_downstream: false,
    };
    let server_conf =
        std::sync::Arc::new(pingora_core::server::configuration::ServerConf::default());
    let http_manager = crate::http_proxy_manager::HttpProxyManager::new(
        store.clone(),
        cert_selector.clone(),
        proxy_logic.clone(),
        server_conf.clone(),
    );
    let http3_manager = crate::http3_proxy_manager::Http3ProxyManager::new(
        store.clone(),
        cert_selector.clone(),
        proxy_logic,
        server_conf,
    );
    let udp_manager = crate::udp_proxy::UdpProxyManager::new(store.clone(), waf_state.clone(), 1);
    let quic_demux =
        crate::quic_udp_demux::QuicUdpDemuxManager::new(store.clone(), http3_manager, udp_manager);
    let tcp_manager = crate::tcp_proxy::TcpProxyManager::new(store, cert_selector, waf_state, 1);
    Ok((quic_demux, tcp_manager, http_manager))
}

#[cfg(target_os = "linux")]
async fn xdp_proxy_smoke_config_store(
    services: &XdpProxySmokeServices,
    ports: &XdpProxySmokePorts,
) -> crate::config::ConfigStore {
    let store = crate::config::ConfigStore::new();
    let http_server = xdp_proxy_smoke_http_server(ports.http, services.http_addr);
    let https_server = xdp_proxy_smoke_https_server(ports.https, services.https_addr);
    let tcp_server = xdp_proxy_smoke_tcp_server(ports.tcp, services.tcp_addr);
    let udp_server = xdp_proxy_smoke_udp_server(ports.udp, services.udp_addr);
    let h3_server = xdp_proxy_smoke_h3_server(ports.h3, services.h3_addr);
    let sni_server = xdp_proxy_smoke_sni_server(ports.https, services.sni_addr);
    let quic_server = xdp_proxy_smoke_quic_server(ports.h3, services.quic_addr);
    let all_servers = vec![
        http_server,
        https_server,
        tcp_server,
        udp_server,
        h3_server,
        sni_server,
        quic_server,
    ];
    let mut servers = std::collections::HashMap::new();
    let mut routes = std::collections::HashMap::new();
    let mut id_to_lb = std::collections::HashMap::new();

    for server in &all_servers {
        for host in server.get_plain_server_names() {
            servers.insert(host, server.clone());
        }
        if let Some(reverse_proxy) = server.reverse_proxy.as_ref() {
            let (lb, _) = crate::lb_factory::build_lb(
                server.numeric_id(),
                reverse_proxy,
                1,
                &std::collections::HashMap::new(),
                false,
                true,
            );
            id_to_lb.insert(server.numeric_id(), lb.clone());
            for host in server.get_plain_server_names() {
                routes.insert(host, lb.clone());
            }
        }
    }

    let mut global_http = crate::config_models::GlobalHTTPAllConfig::default();
    global_http.allow_lan_ip = true;
    let mut http3_policies = std::collections::HashMap::new();
    http3_policies.insert(
        1,
        crate::config_models::HTTP3Policy {
            is_on: true,
            port: 0,
            support_mobile_browsers: true,
        },
    );
    store
        .update_config(
            1,
            1,
            1,
            1,
            all_servers,
            servers,
            routes,
            id_to_lb,
            vec![],
            vec![],
            vec![],
            vec![xdp_proxy_smoke_ssl_cert()],
            None,
            0,
            1,
            true,
            false,
            std::collections::HashMap::new(),
            false,
            false,
            String::new(),
            std::collections::HashMap::new(),
            None,
            false,
            false,
            String::new(),
            false,
            false,
            0,
            true,
            false,
            false,
            String::new(),
            None,
            Some(global_http),
            vec![],
            vec![],
            vec![],
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            http3_policies,
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            None,
            None,
        )
        .await;
    store
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_http_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7101),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-http.local".to_string(),
            ..Default::default()
        }],
        http: Some(crate::config_models::HTTPConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("http", listen_port)],
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8101, "http", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_https_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7104),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-https.local".to_string(),
            ..Default::default()
        }],
        https: Some(crate::config_models::HTTPSConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("https", listen_port)],
            ssl_policy: None,
            supports_http3: Some(false),
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8104, "http", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_h3_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7105),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-h3.local".to_string(),
            ..Default::default()
        }],
        https: Some(crate::config_models::HTTPSConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("https", listen_port)],
            ssl_policy: None,
            supports_http3: Some(true),
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8105, "http", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_sni_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7106),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-sni.local@sni_passthrough".to_string(),
            ..Default::default()
        }],
        https: Some(crate::config_models::HTTPSConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("https", listen_port)],
            ssl_policy: None,
            supports_http3: Some(false),
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8106, "tcp", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_quic_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7107),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-quic.local@quic".to_string(),
            ..Default::default()
        }],
        udp: Some(crate::config_models::UDPConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("udp", listen_port)],
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8107, "udp", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_tcp_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7102),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-tcp.local".to_string(),
            ..Default::default()
        }],
        tcp: Some(crate::config_models::TCPConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("tcp", listen_port)],
            tls: None,
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8102, "tcp", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_udp_server(
    listen_port: u16,
    backend_addr: std::net::SocketAddr,
) -> std::sync::Arc<crate::config_models::ServerConfig> {
    std::sync::Arc::new(crate::config_models::ServerConfig {
        id: Some(7103),
        is_on: true,
        server_names: vec![crate::config_models::ServerNameConfig {
            name: "xdp-smoke-udp.local".to_string(),
            ..Default::default()
        }],
        udp: Some(crate::config_models::UDPConfig {
            is_on: true,
            listen: vec![xdp_proxy_smoke_listen("udp", listen_port)],
        }),
        reverse_proxy: Some(xdp_proxy_smoke_reverse_proxy(8103, "udp", backend_addr)),
        ..Default::default()
    })
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_listen(protocol: &str, port: u16) -> crate::config_models::NetworkAddressConfig {
    crate::config_models::NetworkAddressConfig {
        protocol: Some(protocol.to_string()),
        host: Some("0.0.0.0".to_string()),
        port_range: Some(port.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_reverse_proxy(
    origin_id: i64,
    protocol: &str,
    backend_addr: std::net::SocketAddr,
) -> crate::config_models::ReverseProxyConfig {
    crate::config_models::ReverseProxyConfig {
        is_on: true,
        primary_origins: vec![crate::config_models::OriginConfig {
            id: origin_id,
            name: format!("xdp-smoke-origin-{origin_id}"),
            addr: Some(crate::config_models::FlexibleAddr::Object(
                crate::config_models::NetworkAddressConfig {
                    protocol: Some(protocol.to_string()),
                    host: Some(backend_addr.ip().to_string()),
                    port_range: Some(backend_addr.port().to_string()),
                },
            )),
            is_on: true,
            weight: 1,
            health_check: None,
            request_host: String::new(),
            follow_host: false,
            follow_port: false,
            http2_enabled: false,
            http3_enabled: false,
            conn_timeout: None,
            read_timeout: None,
            idle_timeout: None,
            write_timeout: None,
            cert: None,
            tls_security_verify_mode: crate::config_models::OriginTlsSecurityVerifyMode::Skip,
            tls_verify: None,
            oss: None,
        }],
        backup_origins: Vec::new(),
        scheduling: None,
        request_host: String::new(),
        request_host_type: 0,
        request_host_excluding_port: false,
        proxy_protocol: crate::config_models::ProxyProtocolConfig::default(),
    }
}

#[cfg(target_os = "linux")]
fn xdp_proxy_smoke_ssl_cert() -> crate::config_models::SSLCertConfig {
    crate::config_models::SSLCertConfig {
        id: 7104,
        is_on: true,
        cert_data_json: Some(serde_json::json!(include_str!(
            "../pingora-main/pingora-core/examples/keys/server/cert.pem"
        ))),
        key_data_json: Some(serde_json::json!(include_str!(
            "../pingora-main/pingora-core/examples/keys/server/key.pem"
        ))),
        dns_names: vec![
            "xdp-smoke-https.local".to_string(),
            "xdp-smoke-h3.local".to_string(),
            "xdp-smoke-sni.local".to_string(),
        ],
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn raw_smoke(
    _duration: std::time::Duration,
    _ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("XDP raw smoke is supported on Linux only")
}

#[cfg(not(target_os = "linux"))]
pub async fn proxy_smoke(
    _duration: std::time::Duration,
    _ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("XDP proxy smoke is supported on Linux only")
}

#[cfg(not(target_os = "linux"))]
pub async fn proxy_reload_smoke(
    _duration: std::time::Duration,
    _ready_file: Option<std::path::PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("XDP proxy reload smoke is supported on Linux only")
}

fn range_bound_to_ip(value: u128, v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(value))
    } else {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    }
}

fn ebpf_object_path() -> PathBuf {
    crate::paths::NodePaths::current()
        .data_dir()
        .join(XDP_EBPF_OBJECT_NAME)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn xdp_ip_proto(protocol: &XdpProxyProtocol) -> u8 {
    match protocol {
        XdpProxyProtocol::Http | XdpProxyProtocol::Https | XdpProxyProtocol::Tcp => {
            cloud_node_xdp_common::XDP_PROTO_TCP
        }
        XdpProxyProtocol::Udp | XdpProxyProtocol::H3 => cloud_node_xdp_common::XDP_PROTO_UDP,
    }
}

fn xdp_protocol_dataplane_supported(protocol: &XdpProxyProtocol) -> bool {
    matches!(
        protocol,
        XdpProxyProtocol::Http
            | XdpProxyProtocol::Https
            | XdpProxyProtocol::Tcp
            | XdpProxyProtocol::Udp
            | XdpProxyProtocol::H3
    )
}

fn xdp_tcp_dataplane_supported() -> bool {
    true
}

fn xdp_tcp_dataplane_detail(config: &XdpConfig) -> String {
    if !xdp_proxy_has_tcp_like_ports(config) {
        return String::new();
    }
    String::new()
}

fn xdp_proxy_partial_detail(config: &XdpConfig) -> String {
    if !XDP_PROXY_DATAPLANE_ACTIVE {
        return "userspace proxy dataplane is not active; traffic will PASS".to_string();
    }
    let unsupported = xdp_unsupported_proxy_protocols(config);
    if unsupported.is_empty() {
        return String::new();
    }
    format!(
        "unsupported AF_XDP proxy protocols stay on socket fallback: {}",
        unsupported.join(",")
    )
}

fn xdp_proxy_frame_size_detail(config: &XdpConfig) -> String {
    let oversized = config
        .interfaces
        .iter()
        .filter(|interface| interface.mode == XdpRuntimeMode::Proxy && interface.frame_size > 2048)
        .map(|interface| format!("{} frameSize={}", interface.name, interface.frame_size))
        .collect::<Vec<_>>();
    if oversized.is_empty() {
        String::new()
    } else {
        format!(
            "XDP proxy mode requires standard-MTU frameSize<=2048 until jumbo/multi-buffer support is enabled: {}",
            oversized.join(",")
        )
    }
}

fn xdp_supported_proxy_port_count(config: &XdpConfig) -> usize {
    config
        .proxy
        .ports
        .iter()
        .filter(|port| xdp_protocol_dataplane_supported(&port.protocol))
        .count()
}

fn xdp_proxy_has_tcp_like_ports(config: &XdpConfig) -> bool {
    config.proxy.ports.iter().any(|port| {
        matches!(
            port.protocol,
            XdpProxyProtocol::Http | XdpProxyProtocol::Https | XdpProxyProtocol::Tcp
        )
    })
}

fn xdp_unsupported_proxy_protocols(config: &XdpConfig) -> Vec<&'static str> {
    let mut protocols = BTreeSet::new();
    for port in &config.proxy.ports {
        if !xdp_protocol_dataplane_supported(&port.protocol) {
            protocols.insert(port.protocol.as_str());
        }
    }
    protocols.into_iter().collect()
}

#[derive(Debug)]
struct XdpKernelFilter {
    manager: std::sync::Arc<XdpManager>,
}

impl KernelFilter for XdpKernelFilter {
    fn block(&self, ip: IpAddr, ttl_secs: i64) {
        self.manager.update_block_ip(ip, ttl_secs);
    }

    fn unblock(&self, ip: IpAddr) {
        self.manager.remove_block_ip(ip);
    }

    fn block_network(&self, net: IpNet, ttl_secs: i64) {
        self.manager.update_block_network(net, ttl_secs);
    }

    fn unblock_network(&self, net: IpNet) {
        self.manager.remove_block_network(net);
    }

    fn block_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        self.manager.update_block_range(from, to, v6, ttl_secs);
    }

    fn unblock_range(&self, from: u128, to: u128, v6: bool) {
        self.manager.remove_block_range(from, to, v6);
    }

    fn sync_snapshot(&self, snapshot: &KernelFilterSnapshot) {
        self.manager.sync_snapshot(snapshot);
    }

    fn available(&self) -> bool {
        self.manager.status().available
    }

    fn name(&self) -> &'static str {
        "xdp"
    }

    fn status(&self) -> KernelFilterStatus {
        let status = self.manager.status();
        KernelFilterStatus {
            name: "xdp",
            available: status.available,
            detail: status.fallback_reason,
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::runtime_mode::{XdpAttachMode, XdpRuntimeMode};
    use aya::maps::lpm_trie::Key as LpmKey;
    use aya::maps::{Array, HashMap as AyaHashMap, LpmTrie, XskMap};
    use aya::programs::links::PinnedLink;
    use cloud_node_xdp_common::{
        XdpCounters, XdpInterfacePolicy, XdpIpv4Key, XdpIpv6Key, XdpLocalIpv4Key, XdpLocalIpv6Key,
        XdpPortProtoKey, XdpQueueKey, XdpRuleValue,
    };
    use ipnet::IpNet;
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::io::Write;
    use std::num::NonZeroU32;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::path::{Path, PathBuf};
    use xsk_rs::config::{
        BindFlags, FrameSize, Interface, LibxdpFlags, QueueSize, SocketConfig, UmemConfig,
    };
    use xsk_rs::{CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem};

    const AF_XDP_FRAME_COUNT: u32 = 4096;
    const AF_XDP_RING_SIZE: u32 = 2048;
    const AF_XDP_RX_BATCH: usize = 64;
    const AF_XDP_SOCKET_CREATE_ATTEMPTS: usize = 80;
    const AF_XDP_SOCKET_CREATE_RETRY_DELAY: std::time::Duration =
        std::time::Duration::from_millis(250);

    pub struct AttachedProgram {
        pub interfaces: BTreeSet<String>,
        pub ebpf: aya::Ebpf,
    }

    #[derive(Debug)]
    pub struct AfXdpRuntimeHandle {
        queues: Vec<AfXdpQueueHandle>,
        pub statuses: Vec<XdpQueueStatus>,
    }

    #[derive(Clone, Copy, Debug, Default)]
    pub struct AfXdpPollStats {
        pub packets: usize,
        pub parsed: usize,
        pub parse_errors: usize,
        pub refilled: usize,
    }

    impl AfXdpRuntimeHandle {
        pub fn poll_raw_once<F>(&mut self, mut on_packet: F) -> anyhow::Result<AfXdpPollStats>
        where
            F: FnMut(&str, u32, Vec<u8>),
        {
            let mut stats = AfXdpPollStats::default();
            for queue in &mut self.queues {
                let queue_stats = queue.poll_raw_once(&mut on_packet)?;
                stats.packets += queue_stats.packets;
                stats.parsed += queue_stats.parsed;
                stats.parse_errors += queue_stats.parse_errors;
                stats.refilled += queue_stats.refilled;
            }
            self.refresh_statuses();
            Ok(stats)
        }

        pub fn send_udp_datagram(
            &mut self,
            interface: &str,
            queue: u32,
            link: &super::af_xdp::AfXdpLinkMeta,
            listen_addr: std::net::SocketAddr,
            peer_addr: std::net::SocketAddr,
            payload: &[u8],
        ) -> anyhow::Result<bool> {
            let Some(queue) = self
                .queues
                .iter_mut()
                .find(|handle| handle.interface == interface && handle.queue == queue)
            else {
                return Ok(false);
            };
            let sent = queue.send_udp_datagram(link, listen_addr, peer_addr, payload)?;
            self.refresh_statuses();
            Ok(sent)
        }

        pub fn send_raw_frame(
            &mut self,
            interface: &str,
            queue: u32,
            frame: &[u8],
        ) -> anyhow::Result<bool> {
            let Some(queue) = self
                .queues
                .iter_mut()
                .find(|handle| handle.interface == interface && handle.queue == queue)
            else {
                return Ok(false);
            };
            let sent = queue.send_raw_frame(frame)?;
            self.refresh_statuses();
            Ok(sent)
        }

        fn refresh_statuses(&mut self) {
            for queue in &self.queues {
                let Some(status) = self.statuses.iter_mut().find(|status| {
                    status.interface == queue.interface && status.queue == queue.queue
                }) else {
                    continue;
                };
                if let Ok(stats) = queue.rx.fd().xdp_statistics() {
                    status.rx_dropped = stats.rx_dropped();
                    status.rx_invalid_descs = stats.rx_invalid_descs();
                    status.rx_ring_full = stats.rx_ring_full();
                    status.tx_invalid_descs = stats.tx_invalid_descs();
                }
            }
        }
    }

    #[derive(Debug)]
    struct AfXdpQueueHandle {
        interface: String,
        queue: u32,
        tx: TxQueue,
        rx: RxQueue,
        fill: Option<FillQueue>,
        comp: Option<CompQueue>,
        umem: Umem,
        free_frames: Vec<FrameDesc>,
        rx_batch: Vec<FrameDesc>,
        tx_completion_batch: Vec<FrameDesc>,
        tx_scratch: Vec<u8>,
    }

    impl AfXdpQueueHandle {
        fn poll_raw_once<F>(&mut self, on_packet: &mut F) -> anyhow::Result<AfXdpPollStats>
        where
            F: FnMut(&str, u32, Vec<u8>),
        {
            let mut stats = AfXdpPollStats {
                refilled: self.replenish_fill(),
                ..AfXdpPollStats::default()
            };
            let limit = self.rx_batch.len();
            if limit == 0 {
                return Ok(stats);
            }
            // SAFETY: `rx_batch` only contains descriptors for this queue's UMEM. The
            // kernel owns any descriptors returned by RX until this method returns them
            // to the fill ring or `free_frames`.
            let received = unsafe { self.rx.poll_and_consume(&mut self.rx_batch[..limit], 0)? };
            stats.packets += received;
            for desc in &self.rx_batch[..received] {
                // SAFETY: RX populated `desc` from this queue's UMEM, and we copy the
                // frame before returning ownership to the fill ring.
                let (_, data) = unsafe { self.umem.frame(desc) };
                let frame = data.contents();
                if super::af_xdp::parse_l4_packet(frame).is_some() {
                    stats.parsed += 1;
                } else {
                    stats.parse_errors += 1;
                }
                on_packet(&self.interface, self.queue, frame.to_vec());
            }
            stats.refilled += self.return_rx_frames(received);
            Ok(stats)
        }

        fn replenish_fill(&mut self) -> usize {
            let Some(fill) = self.fill.as_mut() else {
                return 0;
            };
            let count = self.free_frames.len().min(AF_XDP_RX_BATCH);
            if count == 0 {
                return 0;
            }
            let split_at = self.free_frames.len() - count;
            let frames = self.free_frames.split_off(split_at);
            // SAFETY: `frames` came from this queue's UMEM free list and have not been
            // submitted to TX or fill while in `free_frames`.
            let produced = unsafe { fill.produce(&frames) };
            if produced < frames.len() {
                self.free_frames.extend_from_slice(&frames[produced..]);
            }
            produced
        }

        fn return_rx_frames(&mut self, count: usize) -> usize {
            if count == 0 {
                return 0;
            }
            let frames = &self.rx_batch[..count];
            let Some(fill) = self.fill.as_mut() else {
                self.free_frames.extend_from_slice(frames);
                return 0;
            };
            // SAFETY: RX returned these descriptors from the same UMEM and userspace no
            // longer holds packet data references when they are handed back to fill.
            let produced = unsafe { fill.produce(frames) };
            if produced < frames.len() {
                self.free_frames.extend_from_slice(&frames[produced..]);
            }
            produced
        }

        fn reclaim_tx_completions(&mut self) -> usize {
            let Some(comp) = self.comp.as_mut() else {
                return 0;
            };
            // SAFETY: `tx_completion_batch` descriptors belong to this queue's UMEM and
            // are only used here to receive TX completion ownership from the kernel.
            let completed = unsafe { comp.consume(&mut self.tx_completion_batch) };
            self.free_frames
                .extend_from_slice(&self.tx_completion_batch[..completed]);
            completed
        }

        fn send_udp_datagram(
            &mut self,
            link: &super::af_xdp::AfXdpLinkMeta,
            listen_addr: std::net::SocketAddr,
            peer_addr: std::net::SocketAddr,
            payload: &[u8],
        ) -> anyhow::Result<bool> {
            self.reclaim_tx_completions();
            let Some(mut desc) = self.free_frames.pop() else {
                return Ok(false);
            };
            desc.set_options(0);
            if super::af_xdp::encode_udp_reply_frame(
                link,
                listen_addr,
                peer_addr,
                payload,
                &mut self.tx_scratch,
            )
            .is_none()
            {
                self.free_frames.push(desc);
                return Ok(false);
            }
            let frame = std::mem::take(&mut self.tx_scratch);
            let result = self.submit_raw_frame(desc, &frame);
            self.tx_scratch = frame;
            result
        }

        fn send_raw_frame(&mut self, frame: &[u8]) -> anyhow::Result<bool> {
            self.reclaim_tx_completions();
            let Some(desc) = self.free_frames.pop() else {
                return Ok(false);
            };
            self.submit_raw_frame(desc, frame)
        }

        fn submit_raw_frame(&mut self, mut desc: FrameDesc, frame: &[u8]) -> anyhow::Result<bool> {
            desc.set_options(0);
            {
                // SAFETY: `desc` was taken from this queue's free list and therefore
                // belongs to this UMEM. It is not submitted to any ring while we hold
                // this mutable frame view.
                let (_, mut data) = unsafe { self.umem.frame_mut(&mut desc) };
                let mut cursor = data.cursor();
                cursor.zero_out();
                if let Err(err) = cursor.write_all(frame) {
                    self.free_frames.push(desc);
                    return Err(err.into());
                }
            }
            // SAFETY: `desc` describes a frame from this queue's UMEM. After successful
            // submission it is not reused until returned by the completion queue.
            match unsafe { self.tx.produce_one_and_wakeup(&desc) } {
                Ok(1) => Ok(true),
                Ok(_) => {
                    self.free_frames.push(desc);
                    Ok(false)
                }
                Err(err) => {
                    self.free_frames.push(desc);
                    Err(err.into())
                }
            }
        }
    }

    #[derive(Clone, Debug)]
    struct XskMapEntry {
        interface: String,
        ifindex: u32,
        queue: u32,
        index: u32,
    }

    pub fn prepare_af_xdp_sockets(config: &XdpConfig) -> anyhow::Result<AfXdpRuntimeHandle> {
        let mut queues = Vec::new();
        let mut statuses = Vec::new();
        for interface in config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
        {
            for queue in &interface.queues {
                match create_af_xdp_queue_with_retry(interface, *queue) {
                    Ok((handle, status)) => {
                        queues.push(handle);
                        statuses.push(status);
                    }
                    Err(err) => {
                        statuses.push(XdpQueueStatus {
                            interface: interface.name.clone(),
                            queue: *queue,
                            configured: true,
                            detail: format!("AF_XDP socket setup failed: {err}"),
                            ..XdpQueueStatus::default()
                        });
                    }
                }
            }
        }
        Ok(AfXdpRuntimeHandle { queues, statuses })
    }

    fn create_af_xdp_queue_with_retry(
        interface: &crate::runtime_mode::XdpInterfaceConfig,
        queue: u32,
    ) -> anyhow::Result<(AfXdpQueueHandle, XdpQueueStatus)> {
        let mut last_error = None;
        for attempt in 1..=AF_XDP_SOCKET_CREATE_ATTEMPTS {
            match create_af_xdp_queue(interface, queue) {
                Ok(queue) => return Ok(queue),
                Err(err) => {
                    last_error = Some(err);
                    if attempt < AF_XDP_SOCKET_CREATE_ATTEMPTS {
                        std::thread::sleep(AF_XDP_SOCKET_CREATE_RETRY_DELAY);
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("AF_XDP socket setup failed")))
    }

    pub fn register_af_xdp_sockets(
        ebpf: &mut aya::Ebpf,
        config: &XdpConfig,
        runtime: &mut AfXdpRuntimeHandle,
        enable_redirect: bool,
    ) -> anyhow::Result<()> {
        sync_proxy_ports(ebpf, config, false)?;
        sync_xsk_indices(ebpf, config, false)?;
        clear_xsk_map(ebpf)?;
        sync_xsk_indices(ebpf, config, true)?;

        let entries = xsk_map_entries(config)?;
        let map = ebpf
            .map_mut("XDP_XSKS")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_XSKS"))?;
        let mut xsk_map = XskMap::try_from(map)?;

        for entry in entries {
            let Some(queue) = runtime
                .queues
                .iter()
                .find(|queue| queue.interface == entry.interface && queue.queue == entry.queue)
            else {
                mark_queue_status(
                    &mut runtime.statuses,
                    &entry.interface,
                    entry.queue,
                    false,
                    false,
                    "AF_XDP socket not available for configured queue",
                );
                continue;
            };
            // SAFETY: the AF_XDP socket is owned by `runtime.queues` and remains alive
            // while its fd is registered in the XSK map. BorrowedFd does not take ownership.
            let socket_fd = unsafe { BorrowedFd::borrow_raw(queue.rx.fd().as_raw_fd()) };
            xsk_map.set(entry.index, socket_fd, 0)?;
            mark_queue_status(
                &mut runtime.statuses,
                &entry.interface,
                entry.queue,
                true,
                true,
                format!(
                    "AF_XDP socket registered in XSK map index {} for ifindex {} queue {}",
                    entry.index, entry.ifindex, entry.queue
                ),
            );
        }

        sync_proxy_ports(ebpf, config, enable_redirect)?;
        Ok(())
    }

    fn create_af_xdp_queue(
        interface: &crate::runtime_mode::XdpInterfaceConfig,
        queue: u32,
    ) -> anyhow::Result<(AfXdpQueueHandle, XdpQueueStatus)> {
        let frame_size = FrameSize::new(interface.frame_size)?;
        let ring_size = QueueSize::new(AF_XDP_RING_SIZE)?;
        let mut umem_config = UmemConfig::builder();
        umem_config
            .frame_size(frame_size)
            .fill_queue_size(ring_size)
            .comp_queue_size(ring_size);
        let umem_config = umem_config.build()?;
        let frame_count = NonZeroU32::new(AF_XDP_FRAME_COUNT)
            .ok_or_else(|| anyhow::anyhow!("AF_XDP frame count must be non-zero"))?;
        let (umem, mut frames) = Umem::new(umem_config, frame_count, false)?;

        let if_name: Interface = interface.name.parse()?;
        let mut socket_config = SocketConfig::builder();
        socket_config
            .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
            .bind_flags(BindFlags::XDP_USE_NEED_WAKEUP);
        let socket_config = socket_config.build();

        // SAFETY: The UMEM, queues, and socket-backed rings are owned by the returned
        // handle for the full socket lifetime. INHIBIT_PROG_LOAD prevents libxdp
        // from replacing the Aya-managed XDP program on this interface.
        let (tx, rx, fill_and_comp) = unsafe { Socket::new(socket_config, &umem, &if_name, queue) }
            .map_err(|err| {
                let mut detail = err.to_string();
                let mut source = std::error::Error::source(&err);
                while let Some(err) = source {
                    detail.push_str(": ");
                    detail.push_str(&err.to_string());
                    source = err.source();
                }
                anyhow::anyhow!(detail)
            })?;
        let (fill, comp, primed_frames) = match fill_and_comp {
            Some((mut fill, comp)) => {
                let fill_count = frames.len().min(AF_XDP_RING_SIZE as usize);
                let initial_fill = frames.drain(..fill_count).collect::<Vec<_>>();
                // SAFETY: `initial_fill` contains descriptors returned by the same UMEM
                // that owns this fill queue. Submitted descriptors are not reused until
                // the kernel returns them on RX.
                let produced = unsafe { fill.produce(&initial_fill) };
                if produced < initial_fill.len() {
                    frames.extend_from_slice(&initial_fill[produced..]);
                }
                (Some(fill), Some(comp), produced)
            }
            None => (None, None, 0),
        };
        let stats = rx.fd().xdp_statistics().ok();
        let status = XdpQueueStatus {
            interface: interface.name.clone(),
            queue,
            configured: true,
            socket_created: true,
            registered: false,
            ready: false,
            detail: format!(
                "AF_XDP socket created and fill ring primed with {} frames; awaiting XSK map registration",
                primed_frames
            ),
            rx_dropped: stats.map(|stats| stats.rx_dropped()).unwrap_or_default(),
            rx_invalid_descs: stats
                .map(|stats| stats.rx_invalid_descs())
                .unwrap_or_default(),
            rx_ring_full: stats.map(|stats| stats.rx_ring_full()).unwrap_or_default(),
            tx_invalid_descs: stats
                .map(|stats| stats.tx_invalid_descs())
                .unwrap_or_default(),
        };
        Ok((
            AfXdpQueueHandle {
                interface: interface.name.clone(),
                queue,
                tx,
                rx,
                fill,
                comp,
                umem,
                free_frames: frames,
                rx_batch: vec![FrameDesc::default(); AF_XDP_RX_BATCH],
                tx_completion_batch: vec![FrameDesc::default(); AF_XDP_RX_BATCH],
                tx_scratch: Vec::with_capacity(interface.frame_size as usize),
            },
            status,
        ))
    }

    pub async fn attach(config: &XdpConfig, object_path: &Path) -> anyhow::Result<AttachedProgram> {
        std::fs::create_dir_all(XDP_BPF_PIN_DIR)
            .map_err(|err| anyhow::anyhow!("create bpffs pin dir {XDP_BPF_PIN_DIR}: {err}"))?;
        detach(config).await?;
        let mut attached = BTreeSet::new();
        let mut ebpf = aya::EbpfLoader::new()
            .default_map_pin_directory(XDP_BPF_PIN_DIR)
            .load_file(object_path)?;
        sync_interface_policy(&mut ebpf, config)?;
        sync_local_ip_maps(&mut ebpf, config)?;
        sync_proxy_ports(&mut ebpf, config, false)?;
        sync_xsk_indices(&mut ebpf, config, false)?;
        zero_counters(&mut ebpf)?;
        let mode = match config.attach_mode {
            XdpAttachMode::Auto => aya::programs::XdpMode::default(),
            XdpAttachMode::Drv => aya::programs::XdpMode::Driver,
            XdpAttachMode::Skb => aya::programs::XdpMode::Skb,
        };
        let program: &mut aya::programs::Xdp = ebpf
            .program_mut("cloud_node_xdp")
            .ok_or_else(|| anyhow::anyhow!("missing eBPF program cloud_node_xdp"))?
            .try_into()?;
        program.load()?;
        for interface in &config.interfaces {
            let link_id = program.attach(&interface.name, mode)?;
            let link = program.take_link(link_id)?;
            let fd_link: aya::programs::links::FdLink = link.try_into().map_err(|err| {
                anyhow::anyhow!(
                    "kernel attached {} through a legacy XDP link that cannot be pinned: {err}",
                    interface.name
                )
            })?;
            let pin_path = link_pin_path(&interface.name);
            if pin_path.exists() {
                std::fs::remove_file(&pin_path)?;
            }
            fd_link.pin(&pin_path)?;
            attached.insert(interface.name.clone());
        }
        Ok(AttachedProgram {
            interfaces: attached,
            ebpf,
        })
    }

    pub async fn detach(config: &XdpConfig) -> anyhow::Result<()> {
        detach_blocking(config)
    }

    pub fn detach_blocking(config: &XdpConfig) -> anyhow::Result<()> {
        if let Err(err) = clear_pinned_xsk_map() {
            tracing::warn!("failed to clear pinned AF_XDP socket map: {}", err);
        }
        for interface in &config.interfaces {
            let pin_path = link_pin_path(&interface.name);
            match PinnedLink::from_pin(&pin_path) {
                Ok(pinned) => {
                    if let Err(err) = pinned.unpin() {
                        tracing::warn!("failed to unpin XDP link {}: {}", pin_path.display(), err);
                    }
                }
                Err(err) if !pin_path.exists() => {
                    let _ = err;
                }
                Err(err) => {
                    tracing::warn!(
                        "failed to open pinned XDP link {}: {}",
                        pin_path.display(),
                        err
                    );
                }
            }
        }
        Ok(())
    }

    pub fn sync_maps(
        ebpf: &mut aya::Ebpf,
        config: &XdpConfig,
        state: &RuleState,
        proxy_dataplane_active: bool,
    ) -> anyhow::Result<()> {
        sync_interface_policy(ebpf, config)?;
        sync_local_ip_maps(ebpf, config)?;
        sync_proxy_ports(ebpf, config, proxy_dataplane_active)?;
        sync_xsk_indices(ebpf, config, proxy_dataplane_active)?;
        sync_exact_ip_map(
            ebpf,
            "XDP_ALLOWED_V4",
            state.allowed_ips.iter(),
            true,
            false,
        )?;
        sync_exact_ip_map(ebpf, "XDP_ALLOWED_V6", state.allowed_ips.iter(), true, true)?;
        sync_exact_ip_map(
            ebpf,
            "XDP_BLOCKED_V4",
            state.blocked_ips.iter(),
            false,
            false,
        )?;
        sync_exact_ip_map(
            ebpf,
            "XDP_BLOCKED_V6",
            state.blocked_ips.iter(),
            false,
            true,
        )?;
        sync_network_map(
            ebpf,
            "XDP_ALLOWED_V4_LPM",
            state.allowed_networks.values(),
            true,
            false,
        )?;
        sync_network_map(
            ebpf,
            "XDP_ALLOWED_V6_LPM",
            state.allowed_networks.values(),
            true,
            true,
        )?;
        sync_network_map(
            ebpf,
            "XDP_BLOCKED_V4_LPM",
            state.blocked_networks.values(),
            false,
            false,
        )?;
        sync_network_map(
            ebpf,
            "XDP_BLOCKED_V6_LPM",
            state.blocked_networks.values(),
            false,
            true,
        )?;
        sync_range_lpm_maps(ebpf, state.allowed_ranges.iter(), true)?;
        sync_range_lpm_maps(ebpf, state.blocked_ranges.iter(), false)?;
        Ok(())
    }

    pub fn disable_proxy_redirect(ebpf: &mut aya::Ebpf, config: &XdpConfig) -> anyhow::Result<()> {
        sync_proxy_ports(ebpf, config, false)?;
        sync_xsk_indices(ebpf, config, false)?;
        clear_xsk_map(ebpf)?;
        Ok(())
    }

    pub fn read_counters(ebpf: &aya::Ebpf) -> anyhow::Result<XdpCounters> {
        let map = ebpf
            .map("XDP_COUNTERS")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_COUNTERS"))?;
        let counters = Array::<_, XdpCounters>::try_from(map)?.get(&0, 0)?;
        Ok(counters)
    }

    fn zero_counters(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
        let map = ebpf
            .map_mut("XDP_COUNTERS")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_COUNTERS"))?;
        let mut counters = Array::<_, XdpCounters>::try_from(map)?;
        counters.set(0, XdpCounters::default(), 0)?;
        Ok(())
    }

    fn sync_interface_policy(ebpf: &mut aya::Ebpf, config: &XdpConfig) -> anyhow::Result<()> {
        let map = ebpf
            .map_mut("XDP_INTERFACE_POLICY")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_INTERFACE_POLICY"))?;
        let mut policies = AyaHashMap::<_, u32, XdpInterfacePolicy>::try_from(map)?;
        clear_hash_map(&mut policies)?;
        for interface in &config.interfaces {
            let ifindex = ifindex_from_name(&interface.name)?;
            let policy = XdpInterfacePolicy {
                mode: match interface.mode {
                    XdpRuntimeMode::Observe => 0,
                    XdpRuntimeMode::Protect => 1,
                    XdpRuntimeMode::Proxy => 2,
                },
                fallback_pass: u8::from(!config.fallback.fail_start()),
                local_ip_filter: u8::from(!interface.local_ips.is_empty()),
                _pad: 0,
                frame_size: interface.frame_size,
            };
            policies.insert(ifindex, policy, 0)?;
        }
        Ok(())
    }

    fn sync_local_ip_maps(ebpf: &mut aya::Ebpf, config: &XdpConfig) -> anyhow::Result<()> {
        {
            let map = ebpf
                .map_mut("XDP_LOCAL_V4")
                .ok_or_else(|| anyhow::anyhow!("missing map XDP_LOCAL_V4"))?;
            let mut map = AyaHashMap::<_, XdpLocalIpv4Key, u32>::try_from(map)?;
            clear_hash_map(&mut map)?;
            for interface in &config.interfaces {
                let ifindex = ifindex_from_name(&interface.name)?;
                for ip in &interface.local_ips {
                    if let IpAddr::V4(addr) = ip {
                        map.insert(
                            XdpLocalIpv4Key::new(ifindex, u32::from_be_bytes(addr.octets())),
                            1,
                            0,
                        )?;
                    }
                }
            }
        }

        {
            let map = ebpf
                .map_mut("XDP_LOCAL_V6")
                .ok_or_else(|| anyhow::anyhow!("missing map XDP_LOCAL_V6"))?;
            let mut map = AyaHashMap::<_, XdpLocalIpv6Key, u32>::try_from(map)?;
            clear_hash_map(&mut map)?;
            for interface in &config.interfaces {
                let ifindex = ifindex_from_name(&interface.name)?;
                for ip in &interface.local_ips {
                    if let IpAddr::V6(addr) = ip {
                        map.insert(XdpLocalIpv6Key::new(ifindex, addr.octets()), 1, 0)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn sync_proxy_ports(
        ebpf: &mut aya::Ebpf,
        config: &XdpConfig,
        dataplane_active: bool,
    ) -> anyhow::Result<()> {
        let map = ebpf
            .map_mut("XDP_PROXY_PORTS")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_PROXY_PORTS"))?;
        let mut map = AyaHashMap::<_, XdpPortProtoKey, u32>::try_from(map)?;
        clear_hash_map(&mut map)?;
        if !dataplane_active {
            return Ok(());
        }
        for port in &config.proxy.ports {
            if !xdp_protocol_dataplane_supported(&port.protocol) {
                continue;
            }
            map.insert(
                XdpPortProtoKey {
                    port_be: port.port.to_be(),
                    proto: xdp_ip_proto(&port.protocol),
                    _pad: 0,
                },
                1,
                0,
            )?;
        }
        Ok(())
    }

    fn sync_xsk_indices(
        ebpf: &mut aya::Ebpf,
        config: &XdpConfig,
        dataplane_active: bool,
    ) -> anyhow::Result<()> {
        let map = ebpf
            .map_mut("XDP_XSK_INDEX")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_XSK_INDEX"))?;
        let mut map = AyaHashMap::<_, XdpQueueKey, u32>::try_from(map)?;
        clear_hash_map(&mut map)?;
        if !dataplane_active {
            return Ok(());
        }
        for entry in xsk_map_entries(config)? {
            map.insert(XdpQueueKey::new(entry.ifindex, entry.queue), entry.index, 0)?;
        }
        Ok(())
    }

    fn clear_xsk_map(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
        let map = ebpf
            .map_mut("XDP_XSKS")
            .ok_or_else(|| anyhow::anyhow!("missing map XDP_XSKS"))?;
        let mut map = XskMap::try_from(map)?;
        clear_xsk_map_entries(&mut map);
        Ok(())
    }

    fn clear_pinned_xsk_map() -> anyhow::Result<()> {
        let path = Path::new(XDP_BPF_PIN_DIR).join("XDP_XSKS");
        if !path.exists() {
            return Ok(());
        }
        let map = aya::maps::Map::XskMap(aya::maps::MapData::from_pin(path)?);
        let mut map = XskMap::try_from(map)?;
        clear_xsk_map_entries(&mut map);
        Ok(())
    }

    fn clear_xsk_map_entries<T>(map: &mut XskMap<T>)
    where
        T: std::borrow::BorrowMut<aya::maps::MapData>,
    {
        for index in 0..map.len() {
            let _ = map.unset(index);
        }
    }

    fn xsk_map_entries(config: &XdpConfig) -> anyhow::Result<Vec<XskMapEntry>> {
        let mut entries = Vec::new();
        for interface in config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
        {
            let ifindex = ifindex_from_name(&interface.name)?;
            for queue in &interface.queues {
                let index = u32::try_from(entries.len())
                    .map_err(|_| anyhow::anyhow!("too many AF_XDP queues configured"))?;
                if index >= 4096 {
                    anyhow::bail!("too many AF_XDP queues configured; XDP_XSKS max is 4096");
                }
                entries.push(XskMapEntry {
                    interface: interface.name.clone(),
                    ifindex,
                    queue: *queue,
                    index,
                });
            }
        }
        Ok(entries)
    }

    fn mark_queue_status(
        statuses: &mut [XdpQueueStatus],
        interface: &str,
        queue: u32,
        registered: bool,
        ready: bool,
        detail: impl Into<String>,
    ) {
        let detail = detail.into();
        for status in statuses
            .iter_mut()
            .filter(|status| status.interface == interface && status.queue == queue)
        {
            status.registered = registered;
            status.ready = ready;
            status.detail = detail.clone();
        }
    }

    fn sync_exact_ip_map<'a>(
        ebpf: &mut aya::Ebpf,
        name: &str,
        entries: impl Iterator<Item = (&'a IpAddr, &'a i64)>,
        allow: bool,
        v6: bool,
    ) -> anyhow::Result<()> {
        if v6 {
            let map = ebpf
                .map_mut(name)
                .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
            let mut map = AyaHashMap::<_, XdpIpv6Key, XdpRuleValue>::try_from(map)?;
            clear_hash_map(&mut map)?;
            for (ip, expiry) in entries {
                if let IpAddr::V6(addr) = ip {
                    map.insert(
                        XdpIpv6Key {
                            addr: addr.octets(),
                        },
                        rule_value(*expiry, allow),
                        0,
                    )?;
                }
            }
        } else {
            let map = ebpf
                .map_mut(name)
                .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
            let mut map = AyaHashMap::<_, XdpIpv4Key, XdpRuleValue>::try_from(map)?;
            clear_hash_map(&mut map)?;
            for (ip, expiry) in entries {
                if let IpAddr::V4(addr) = ip {
                    map.insert(
                        XdpIpv4Key {
                            addr_be: u32::from_be_bytes(addr.octets()),
                        },
                        rule_value(*expiry, allow),
                        0,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn sync_network_map<'a>(
        ebpf: &mut aya::Ebpf,
        name: &str,
        entries: impl Iterator<Item = &'a (IpNet, i64)>,
        allow: bool,
        v6: bool,
    ) -> anyhow::Result<()> {
        if v6 {
            let map = ebpf
                .map_mut(name)
                .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
            let mut map = LpmTrie::<_, [u8; 16], XdpRuleValue>::try_from(map)?;
            clear_lpm_map(&mut map)?;
            for (net, expiry) in entries {
                if let IpNet::V6(net) = net {
                    let key = LpmKey::new(net.prefix_len() as u32, net.network().octets());
                    map.insert(&key, rule_value(*expiry, allow), 0)?;
                }
            }
        } else {
            let map = ebpf
                .map_mut(name)
                .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
            let mut map = LpmTrie::<_, u32, XdpRuleValue>::try_from(map)?;
            clear_lpm_map(&mut map)?;
            for (net, expiry) in entries {
                if let IpNet::V4(net) = net {
                    let key = LpmKey::new(
                        net.prefix_len() as u32,
                        u32::from_be_bytes(net.network().octets()),
                    );
                    map.insert(&key, rule_value(*expiry, allow), 0)?;
                }
            }
        }
        Ok(())
    }

    fn sync_range_lpm_maps<'a>(
        ebpf: &mut aya::Ebpf,
        entries: impl Iterator<Item = (&'a RangeKey, &'a i64)>,
        allow: bool,
    ) -> anyhow::Result<()> {
        let ranges = entries
            .map(|(range, expiry)| (range.clone(), *expiry))
            .collect::<Vec<_>>();
        let (v4_name, v6_name) = if allow {
            ("XDP_ALLOWED_V4_LPM", "XDP_ALLOWED_V6_LPM")
        } else {
            ("XDP_BLOCKED_V4_LPM", "XDP_BLOCKED_V6_LPM")
        };

        {
            let map = ebpf
                .map_mut(v4_name)
                .ok_or_else(|| anyhow::anyhow!("missing map {v4_name}"))?;
            let mut map = LpmTrie::<_, u32, XdpRuleValue>::try_from(map)?;
            for (range, expiry) in &ranges {
                for net in range_to_nets(range) {
                    if let IpNet::V4(net) = net {
                        let key = LpmKey::new(
                            net.prefix_len() as u32,
                            u32::from_be_bytes(net.network().octets()),
                        );
                        map.insert(&key, rule_value(*expiry, allow), 0)?;
                    }
                }
            }
        }

        {
            let map = ebpf
                .map_mut(v6_name)
                .ok_or_else(|| anyhow::anyhow!("missing map {v6_name}"))?;
            let mut map = LpmTrie::<_, [u8; 16], XdpRuleValue>::try_from(map)?;
            for (range, expiry) in &ranges {
                for net in range_to_nets(range) {
                    if let IpNet::V6(net) = net {
                        let key = LpmKey::new(net.prefix_len() as u32, net.network().octets());
                        map.insert(&key, rule_value(*expiry, allow), 0)?;
                    }
                }
            }
        }

        Ok(())
    }

    // Desired-contents "images" of the rule maps, keyed so that an unchanged
    // entry (same expiry) is never rewritten. Keeping the diff keyed on the unix
    // expiry preserves each entry's original monotonic deadline in the eBPF map.
    type ExactV4Image = std::collections::BTreeMap<u32, i64>;
    type ExactV6Image = std::collections::BTreeMap<[u8; 16], i64>;
    type LpmV4Image = std::collections::BTreeMap<(u32, u32), i64>;
    type LpmV6Image = std::collections::BTreeMap<(u32, [u8; 16]), i64>;

    struct RuleMapImages {
        allowed_v4: ExactV4Image,
        allowed_v6: ExactV6Image,
        blocked_v4: ExactV4Image,
        blocked_v6: ExactV6Image,
        allowed_v4_lpm: LpmV4Image,
        allowed_v6_lpm: LpmV6Image,
        blocked_v4_lpm: LpmV4Image,
        blocked_v6_lpm: LpmV6Image,
    }

    fn exact_image(ips: &std::collections::BTreeMap<IpAddr, i64>) -> (ExactV4Image, ExactV6Image) {
        let mut v4 = ExactV4Image::new();
        let mut v6 = ExactV6Image::new();
        for (ip, expiry) in ips {
            match ip {
                IpAddr::V4(addr) => {
                    v4.insert(u32::from_be_bytes(addr.octets()), *expiry);
                }
                IpAddr::V6(addr) => {
                    v6.insert(addr.octets(), *expiry);
                }
            }
        }
        (v4, v6)
    }

    fn lpm_image(
        nets: &std::collections::BTreeMap<String, (IpNet, i64)>,
        ranges: &std::collections::BTreeMap<RangeKey, i64>,
    ) -> (LpmV4Image, LpmV6Image) {
        let mut v4 = LpmV4Image::new();
        let mut v6 = LpmV6Image::new();
        // Networks first, then range decomposition, matching the full-sync order.
        for (net, expiry) in nets.values() {
            insert_net_image(&mut v4, &mut v6, net, *expiry);
        }
        for (range, expiry) in ranges {
            for net in range_to_nets(range) {
                insert_net_image(&mut v4, &mut v6, &net, *expiry);
            }
        }
        (v4, v6)
    }

    fn insert_net_image(v4: &mut LpmV4Image, v6: &mut LpmV6Image, net: &IpNet, expiry: i64) {
        match net {
            IpNet::V4(net) => {
                let key = (net.prefix_len() as u32, u32::from_be_bytes(net.network().octets()));
                // Keep the latest-seen expiry deterministically (max wins).
                let slot = v4.entry(key).or_insert(expiry);
                if expiry > *slot {
                    *slot = expiry;
                }
            }
            IpNet::V6(net) => {
                let key = (net.prefix_len() as u32, net.network().octets());
                let slot = v6.entry(key).or_insert(expiry);
                if expiry > *slot {
                    *slot = expiry;
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn rule_map_images(state: &RuleState) -> RuleMapImages {
        let (allowed_v4, allowed_v6) = exact_image(&state.allowed_ips);
        let (blocked_v4, blocked_v6) = exact_image(&state.blocked_ips);
        let (allowed_v4_lpm, allowed_v6_lpm) =
            lpm_image(&state.allowed_networks, &state.allowed_ranges);
        let (blocked_v4_lpm, blocked_v6_lpm) =
            lpm_image(&state.blocked_networks, &state.blocked_ranges);
        RuleMapImages {
            allowed_v4,
            allowed_v6,
            blocked_v4,
            blocked_v6,
            allowed_v4_lpm,
            allowed_v6_lpm,
            blocked_v4_lpm,
            blocked_v6_lpm,
        }
    }

    /// Incrementally reconcile the six rule maps from `old` to `new` without ever
    /// clearing a whole map. Only changed/added keys are inserted and only removed
    /// keys are deleted, so the data plane never observes an empty-map window.
    pub fn apply_rule_diff(
        ebpf: &mut aya::Ebpf,
        old: &RuleState,
        new: &RuleState,
    ) -> anyhow::Result<()> {
        let old = rule_map_images(old);
        let new = rule_map_images(new);
        diff_exact_v4(ebpf, "XDP_ALLOWED_V4", &old.allowed_v4, &new.allowed_v4, true)?;
        diff_exact_v6(ebpf, "XDP_ALLOWED_V6", &old.allowed_v6, &new.allowed_v6, true)?;
        diff_exact_v4(ebpf, "XDP_BLOCKED_V4", &old.blocked_v4, &new.blocked_v4, false)?;
        diff_exact_v6(ebpf, "XDP_BLOCKED_V6", &old.blocked_v6, &new.blocked_v6, false)?;
        diff_lpm_v4(
            ebpf,
            "XDP_ALLOWED_V4_LPM",
            &old.allowed_v4_lpm,
            &new.allowed_v4_lpm,
            true,
        )?;
        diff_lpm_v6(
            ebpf,
            "XDP_ALLOWED_V6_LPM",
            &old.allowed_v6_lpm,
            &new.allowed_v6_lpm,
            true,
        )?;
        diff_lpm_v4(
            ebpf,
            "XDP_BLOCKED_V4_LPM",
            &old.blocked_v4_lpm,
            &new.blocked_v4_lpm,
            false,
        )?;
        diff_lpm_v6(
            ebpf,
            "XDP_BLOCKED_V6_LPM",
            &old.blocked_v6_lpm,
            &new.blocked_v6_lpm,
            false,
        )?;
        Ok(())
    }

    fn diff_exact_v4(
        ebpf: &mut aya::Ebpf,
        name: &str,
        old: &ExactV4Image,
        new: &ExactV4Image,
        allow: bool,
    ) -> anyhow::Result<()> {
        if old == new {
            return Ok(());
        }
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
        let mut map = AyaHashMap::<_, XdpIpv4Key, XdpRuleValue>::try_from(map)?;
        for (addr_be, expiry) in new {
            if old.get(addr_be) != Some(expiry) {
                map.insert(XdpIpv4Key { addr_be: *addr_be }, rule_value(*expiry, allow), 0)?;
            }
        }
        for addr_be in old.keys() {
            if !new.contains_key(addr_be) {
                let _ = map.remove(&XdpIpv4Key { addr_be: *addr_be });
            }
        }
        Ok(())
    }

    fn diff_exact_v6(
        ebpf: &mut aya::Ebpf,
        name: &str,
        old: &ExactV6Image,
        new: &ExactV6Image,
        allow: bool,
    ) -> anyhow::Result<()> {
        if old == new {
            return Ok(());
        }
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
        let mut map = AyaHashMap::<_, XdpIpv6Key, XdpRuleValue>::try_from(map)?;
        for (addr, expiry) in new {
            if old.get(addr) != Some(expiry) {
                map.insert(XdpIpv6Key { addr: *addr }, rule_value(*expiry, allow), 0)?;
            }
        }
        for addr in old.keys() {
            if !new.contains_key(addr) {
                let _ = map.remove(&XdpIpv6Key { addr: *addr });
            }
        }
        Ok(())
    }

    fn diff_lpm_v4(
        ebpf: &mut aya::Ebpf,
        name: &str,
        old: &LpmV4Image,
        new: &LpmV4Image,
        allow: bool,
    ) -> anyhow::Result<()> {
        if old == new {
            return Ok(());
        }
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
        let mut map = LpmTrie::<_, u32, XdpRuleValue>::try_from(map)?;
        for ((prefix_len, addr_be), expiry) in new {
            if old.get(&(*prefix_len, *addr_be)) != Some(expiry) {
                let key = LpmKey::new(*prefix_len, *addr_be);
                map.insert(&key, rule_value(*expiry, allow), 0)?;
            }
        }
        for (prefix_len, addr_be) in old.keys() {
            if !new.contains_key(&(*prefix_len, *addr_be)) {
                let key = LpmKey::new(*prefix_len, *addr_be);
                let _ = map.remove(&key);
            }
        }
        Ok(())
    }

    fn diff_lpm_v6(
        ebpf: &mut aya::Ebpf,
        name: &str,
        old: &LpmV6Image,
        new: &LpmV6Image,
        allow: bool,
    ) -> anyhow::Result<()> {
        if old == new {
            return Ok(());
        }
        let map = ebpf
            .map_mut(name)
            .ok_or_else(|| anyhow::anyhow!("missing map {name}"))?;
        let mut map = LpmTrie::<_, [u8; 16], XdpRuleValue>::try_from(map)?;
        for ((prefix_len, addr), expiry) in new {
            if old.get(&(*prefix_len, *addr)) != Some(expiry) {
                let key = LpmKey::new(*prefix_len, *addr);
                map.insert(&key, rule_value(*expiry, allow), 0)?;
            }
        }
        for (prefix_len, addr) in old.keys() {
            if !new.contains_key(&(*prefix_len, *addr)) {
                let key = LpmKey::new(*prefix_len, *addr);
                let _ = map.remove(&key);
            }
        }
        Ok(())
    }

    fn rule_value(expires_at: i64, allow: bool) -> XdpRuleValue {
        let flags = if allow {
            XdpRuleValue::FLAG_WHITELIST
        } else {
            XdpRuleValue::FLAG_BLOCK
        } | XdpRuleValue::FLAG_RUNTIME;
        XdpRuleValue::with_monotonic_deadline(
            expires_at.max(1) as u64,
            monotonic_deadline_ns(expires_at),
            0,
            flags,
        )
    }

    fn monotonic_deadline_ns(expires_at: i64) -> u64 {
        let now_mono_ns = monotonic_now_ns();
        if now_mono_ns == 0 {
            static LAST_WARN_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now_ms = crate::utils::time::now_timestamp_millis() as u64;
            let last = LAST_WARN_MS.load(std::sync::atomic::Ordering::Relaxed);
            if now_ms.saturating_sub(last) > 60_000 {
                LAST_WARN_MS.store(now_ms, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    "XDP monotonic clock read failed; rules will rely on 5s shadow sweeper for expiry"
                );
            }
            return 0;
        }
        let ttl_secs = expires_at
            .saturating_sub(crate::utils::time::now_timestamp())
            .max(0) as u64;
        now_mono_ns.saturating_add(ttl_secs.saturating_mul(1_000_000_000))
    }

    fn monotonic_now_ns() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` points to valid writable memory for the duration of the
        // call, and CLOCK_MONOTONIC does not require any additional ownership.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        if rc != 0 {
            return 0;
        }
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    }

    fn clear_hash_map<K, V>(
        map: &mut AyaHashMap<&mut aya::maps::MapData, K, V>,
    ) -> anyhow::Result<()>
    where
        K: aya::Pod,
        V: aya::Pod,
    {
        let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            let _ = map.remove(&key);
        }
        Ok(())
    }

    fn clear_lpm_map<K, V>(map: &mut LpmTrie<&mut aya::maps::MapData, K, V>) -> anyhow::Result<()>
    where
        K: aya::Pod,
        V: aya::Pod,
    {
        let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
        for key in keys {
            let _ = map.remove(&key);
        }
        Ok(())
    }

    fn ifindex_from_name(name: &str) -> anyhow::Result<u32> {
        let c_name = CString::new(name)?;
        let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if ifindex == 0 {
            anyhow::bail!("unknown interface {name}");
        }
        Ok(ifindex)
    }

    fn link_pin_path(interface: &str) -> PathBuf {
        let safe_name = interface
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        Path::new(XDP_BPF_PIN_DIR).join(format!("link-{safe_name}"))
    }
}

pub mod af_xdp {
    use super::*;
    use bytes::Bytes;
    #[cfg(any(test, target_os = "linux"))]
    use smoltcp::iface::{
        Config as SmoltcpConfig, Interface as SmoltcpInterface, PollIngressSingleResult,
        SocketHandle, SocketSet,
    };
    #[cfg(any(test, target_os = "linux"))]
    use smoltcp::phy::{Device as SmoltcpDevice, DeviceCapabilities, Medium, RxToken, TxToken};
    #[cfg(any(test, target_os = "linux"))]
    use smoltcp::socket::tcp as SmoltcpTcp;
    #[cfg(any(test, target_os = "linux"))]
    use smoltcp::time::Instant as SmoltcpInstant;
    #[cfg(any(test, target_os = "linux"))]
    use smoltcp::wire::{
        HardwareAddress, IpAddress as SmoltcpIpAddress, IpCidr as SmoltcpIpCidr, IpEndpoint,
        IpListenEndpoint,
    };
    #[cfg(any(test, target_os = "linux"))]
    use std::collections::HashMap;
    use std::future::Future;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    #[cfg(any(test, target_os = "linux"))]
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::sync::mpsc;
    #[cfg(target_os = "linux")]
    use tokio::sync::watch;
    #[cfg(target_os = "linux")]
    use tokio::time::{MissedTickBehavior, interval};

    const ETH_HEADER_LEN: usize = 14;
    const VLAN_HEADER_LEN: usize = 4;
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;
    const TCP_MIN_HEADER_LEN: usize = 20;
    const UDP_HEADER_LEN: usize = 8;
    const ETHERTYPE_IPV4: u16 = 0x0800;
    const ETHERTYPE_IPV6: u16 = 0x86dd;
    const ETHERTYPE_VLAN: u16 = 0x8100;
    const ETHERTYPE_QINQ: u16 = 0x88a8;
    const ETHERTYPE_QINQ_9100: u16 = 0x9100;
    const ETHERTYPE_QINQ_9200: u16 = 0x9200;
    const ETHERTYPE_QINQ_9300: u16 = 0x9300;
    const IP_PROTO_TCP: u8 = cloud_node_xdp_common::XDP_PROTO_TCP;
    const IP_PROTO_UDP: u8 = cloud_node_xdp_common::XDP_PROTO_UDP;
    const IP_PROTO_HOP_BY_HOP: u8 = 0;
    const IP_PROTO_ROUTING: u8 = 43;
    const IP_PROTO_FRAGMENT: u8 = 44;
    const IP_PROTO_AH: u8 = 51;
    const IP_PROTO_NO_NEXT: u8 = 59;
    const IP_PROTO_DEST_OPTS: u8 = 60;
    const AF_XDP_TCP_STREAM_CHANNEL_DEPTH: usize = 256;
    const AF_XDP_TCP_STREAM_WRITE_CHUNK: usize = 16 * 1024;
    #[cfg(any(test, target_os = "linux"))]
    const AF_XDP_TCP_SOCKET_BUFFER_BYTES: usize = 64 * 1024;
    #[cfg(any(test, target_os = "linux"))]
    const AF_XDP_TCP_RECV_SCRATCH_BYTES: usize = 16 * 1024;
    #[cfg(any(test, target_os = "linux"))]
    pub(super) const AF_XDP_TCP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

    #[cfg(target_os = "linux")]
    static AF_XDP_TCP_DIAG_ACCEPTED: AtomicU64 = AtomicU64::new(0);
    #[cfg(target_os = "linux")]
    static AF_XDP_TCP_DIAG_IGNORED_UNKNOWN: AtomicU64 = AtomicU64::new(0);
    #[cfg(target_os = "linux")]
    static AF_XDP_TCP_DIAG_PROXY_STARTED: AtomicU64 = AtomicU64::new(0);
    #[cfg(target_os = "linux")]
    static AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES: AtomicU64 = AtomicU64::new(0);
    #[cfg(target_os = "linux")]
    static AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES: AtomicU64 = AtomicU64::new(0);
    #[cfg(target_os = "linux")]
    static AF_XDP_TCP_DIAG_STREAM_EGRESS_BYTES: AtomicU64 = AtomicU64::new(0);
    #[cfg(target_os = "linux")]
    static AF_XDP_TCP_DIAG_EGRESS_FRAMES: AtomicU64 = AtomicU64::new(0);

    #[cfg(target_os = "linux")]
    pub(super) fn reset_tcp_diag() {
        AF_XDP_TCP_DIAG_ACCEPTED.store(0, Ordering::Relaxed);
        AF_XDP_TCP_DIAG_IGNORED_UNKNOWN.store(0, Ordering::Relaxed);
        AF_XDP_TCP_DIAG_PROXY_STARTED.store(0, Ordering::Relaxed);
        AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES.store(0, Ordering::Relaxed);
        AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES.store(0, Ordering::Relaxed);
        AF_XDP_TCP_DIAG_STREAM_EGRESS_BYTES.store(0, Ordering::Relaxed);
        AF_XDP_TCP_DIAG_EGRESS_FRAMES.store(0, Ordering::Relaxed);
    }

    #[cfg(target_os = "linux")]
    pub(super) fn tcp_diag_snapshot() -> serde_json::Value {
        serde_json::json!({
            "accepted": AF_XDP_TCP_DIAG_ACCEPTED.load(Ordering::Relaxed),
            "ignoredUnknown": AF_XDP_TCP_DIAG_IGNORED_UNKNOWN.load(Ordering::Relaxed),
            "proxyStarted": AF_XDP_TCP_DIAG_PROXY_STARTED.load(Ordering::Relaxed),
            "socketRecvBytes": AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES.load(Ordering::Relaxed),
            "streamIngressBytes": AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES.load(Ordering::Relaxed),
            "streamEgressBytes": AF_XDP_TCP_DIAG_STREAM_EGRESS_BYTES.load(Ordering::Relaxed),
            "egressFrames": AF_XDP_TCP_DIAG_EGRESS_FRAMES.load(Ordering::Relaxed),
        })
    }

    #[cfg(any(test, target_os = "linux"))]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum AfXdpTxStatus {
        Sent,
        Backpressured,
        Failed,
    }

    #[cfg(any(test, target_os = "linux"))]
    #[derive(Clone, Debug)]
    pub(super) struct AfXdpTxFailureTracker {
        consecutive_failures: u32,
        max_consecutive_failures: u32,
    }

    #[cfg(any(test, target_os = "linux"))]
    impl AfXdpTxFailureTracker {
        pub(super) fn new(max_consecutive_failures: u32) -> Self {
            Self {
                consecutive_failures: 0,
                max_consecutive_failures: max_consecutive_failures.max(1),
            }
        }

        pub(super) fn record(&mut self, status: AfXdpTxStatus) -> bool {
            match status {
                AfXdpTxStatus::Sent => {
                    self.consecutive_failures = 0;
                    false
                }
                AfXdpTxStatus::Backpressured | AfXdpTxStatus::Failed => {
                    self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                    self.consecutive_failures >= self.max_consecutive_failures
                }
            }
        }

        #[cfg(test)]
        pub(super) fn consecutive_failures(&self) -> u32 {
            self.consecutive_failures
        }
    }

    type TcpWritePermitFuture = Pin<
        Box<
            dyn Future<Output = Result<mpsc::OwnedPermit<Bytes>, mpsc::error::SendError<()>>>
                + Send,
        >,
    >;

    #[cfg(any(test, target_os = "linux"))]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum IngressDelivery {
        Delivered,
        Backpressured,
        Closed,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AfXdpVlanTag {
        pub tpid: u16,
        pub tci: u16,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AfXdpLinkMeta {
        pub destination_mac: [u8; 6],
        pub source_mac: [u8; 6],
        pub vlan_tags: [AfXdpVlanTag; 2],
        pub vlan_tag_count: u8,
        pub ethertype: u16,
    }

    impl AfXdpLinkMeta {
        pub fn reply_eth_header_len(&self) -> usize {
            ETH_HEADER_LEN + usize::from(self.vlan_tag_count.min(2)) * VLAN_HEADER_LEN
        }
    }

    #[derive(Clone, Debug)]
    pub struct AfXdpDatagram {
        pub listen_addr: SocketAddr,
        pub peer_addr: SocketAddr,
        pub payload: Bytes,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum AfXdpTransportProtocol {
        Tcp,
        Udp,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AfXdpL4Packet {
        pub protocol: AfXdpTransportProtocol,
        pub local_addr: SocketAddr,
        pub peer_addr: SocketAddr,
        pub payload: Bytes,
        pub link: AfXdpLinkMeta,
    }

    impl AfXdpL4Packet {
        pub fn tcp_flow_key(&self) -> Option<AfXdpTcpFlowKey> {
            (self.protocol == AfXdpTransportProtocol::Tcp).then_some(AfXdpTcpFlowKey {
                local_addr: self.local_addr,
                peer_addr: self.peer_addr,
            })
        }

        pub fn into_udp_datagram(self) -> Option<AfXdpDatagram> {
            (self.protocol == AfXdpTransportProtocol::Udp).then_some(AfXdpDatagram {
                listen_addr: self.local_addr,
                peer_addr: self.peer_addr,
                payload: self.payload,
            })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct AfXdpTcpFlowKey {
        pub local_addr: SocketAddr,
        pub peer_addr: SocketAddr,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct AfXdpRouteMeta {
        pub interface: String,
        pub queue: u32,
        pub link: AfXdpLinkMeta,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum AfXdpProxyFrame {
        Udp {
            route: AfXdpRouteMeta,
            packet: AfXdpL4Packet,
        },
        Tcp {
            route: AfXdpRouteMeta,
            flow: AfXdpTcpFlowKey,
            ip_packet: Bytes,
        },
    }

    pub struct AfXdpTcpStream {
        incoming_rx: mpsc::Receiver<Bytes>,
        outgoing_tx: Option<mpsc::Sender<Bytes>>,
        read_buf: Bytes,
        write_permit: Option<TcpWritePermitFuture>,
    }

    pub struct AfXdpTcpStreamParts {
        pub stream: AfXdpTcpStream,
        pub ingress_tx: mpsc::Sender<Bytes>,
        pub egress_rx: mpsc::Receiver<Bytes>,
    }

    struct AfXdpVirtualSocket<S> {
        inner: parking_lot::Mutex<S>,
    }

    impl<S> std::fmt::Debug for AfXdpVirtualSocket<S> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AfXdpVirtualSocket").finish_non_exhaustive()
        }
    }

    impl<S> AfXdpVirtualSocket<S> {
        fn new(inner: S) -> Self {
            Self {
                inner: parking_lot::Mutex::new(inner),
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for AfXdpVirtualSocket<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut inner = self.inner.lock();
            Pin::new(&mut *inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for AfXdpVirtualSocket<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut inner = self.inner.lock();
            Pin::new(&mut *inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut inner = self.inner.lock();
            Pin::new(&mut *inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut inner = self.inner.lock();
            Pin::new(&mut *inner).poll_shutdown(cx)
        }
    }

    impl<S> pingora_core::protocols::l4::virt::VirtualSocket for AfXdpVirtualSocket<S>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        fn set_socket_option(
            &self,
            _opt: pingora_core::protocols::l4::virt::VirtualSockOpt,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn virtual_l4_stream<S>(
        stream: S,
        client_addr: SocketAddr,
    ) -> pingora_core::protocols::l4::stream::Stream
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        use pingora_core::protocols::GetSocketDigest;
        use pingora_core::protocols::SocketDigest;
        use pingora_core::protocols::l4::virt::VirtualSocketStream;
        #[cfg(unix)]
        use std::os::unix::io::AsRawFd;
        #[cfg(windows)]
        use std::os::windows::io::AsRawSocket;

        let mut stream = pingora_core::protocols::l4::stream::Stream::from(
            VirtualSocketStream::new(Box::new(AfXdpVirtualSocket::new(stream))),
        );
        #[cfg(unix)]
        let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
        #[cfg(windows)]
        let digest = SocketDigest::from_raw_socket(stream.as_raw_socket());
        digest
            .peer_addr
            .set(Some(client_addr.into()))
            .expect("newly created OnceCell must be empty");
        stream.set_socket_digest(digest);
        stream
    }

    #[cfg(any(test, target_os = "linux"))]
    struct AfXdpTcpIngressFrame {
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        ip_packet: Bytes,
    }

    #[cfg(any(test, target_os = "linux"))]
    struct AfXdpTcpEgressFrame {
        route: Option<AfXdpRouteMeta>,
        ip_packet: Vec<u8>,
    }

    #[cfg(any(test, target_os = "linux"))]
    struct AfXdpTcpSession {
        flow: AfXdpTcpFlowKey,
        route: AfXdpRouteMeta,
        socket: SocketHandle,
        ingress_tx: Option<mpsc::Sender<Bytes>>,
        egress_rx: mpsc::Receiver<Bytes>,
        pending_ingress: Bytes,
        pending_egress: Bytes,
        last_activity: SmoltcpInstant,
        proxy_started: bool,
        closing: bool,
        egress_closed: bool,
    }

    #[cfg(any(test, target_os = "linux"))]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum AfXdpTcpIngestStatus {
        Accepted,
        IgnoredUnknownFlow,
        RefusedAtCapacity,
    }

    #[cfg(any(test, target_os = "linux"))]
    #[derive(Clone, Debug)]
    pub(super) struct AfXdpTcpAdmissionFailureTracker {
        consecutive_refusals: u32,
        max_consecutive_refusals: u32,
    }

    #[cfg(any(test, target_os = "linux"))]
    impl AfXdpTcpAdmissionFailureTracker {
        pub(super) fn new(max_consecutive_refusals: u32) -> Self {
            Self {
                consecutive_refusals: 0,
                max_consecutive_refusals: max_consecutive_refusals.max(1),
            }
        }

        pub(super) fn record(&mut self, status: AfXdpTcpIngestStatus) -> bool {
            match status {
                AfXdpTcpIngestStatus::Accepted => {
                    self.consecutive_refusals = 0;
                    false
                }
                AfXdpTcpIngestStatus::IgnoredUnknownFlow => false,
                AfXdpTcpIngestStatus::RefusedAtCapacity => {
                    self.consecutive_refusals = self.consecutive_refusals.saturating_add(1);
                    self.consecutive_refusals >= self.max_consecutive_refusals
                }
            }
        }

        #[cfg(test)]
        pub(super) fn consecutive_refusals(&self) -> u32 {
            self.consecutive_refusals
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    struct SmoltcpAfXdpDevice {
        ingress: std::collections::VecDeque<AfXdpTcpIngressFrame>,
        egress: Vec<AfXdpTcpEgressFrame>,
        current_route: Option<AfXdpRouteMeta>,
        max_transmission_unit: usize,
    }

    #[cfg(any(test, target_os = "linux"))]
    impl SmoltcpAfXdpDevice {
        fn new(max_transmission_unit: usize) -> Self {
            Self {
                ingress: std::collections::VecDeque::new(),
                egress: Vec::new(),
                current_route: None,
                max_transmission_unit,
            }
        }

        fn push_ingress(&mut self, route: AfXdpRouteMeta, flow: AfXdpTcpFlowKey, ip_packet: Bytes) {
            self.ingress.push_back(AfXdpTcpIngressFrame {
                route,
                flow,
                ip_packet,
            });
        }

        fn drain_egress(&mut self) -> impl Iterator<Item = AfXdpTcpEgressFrame> + '_ {
            self.egress.drain(..)
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    struct SmoltcpAfXdpRxToken {
        ip_packet: Bytes,
    }

    #[cfg(any(test, target_os = "linux"))]
    struct SmoltcpAfXdpTxToken<'a> {
        route: Option<AfXdpRouteMeta>,
        egress: &'a mut Vec<AfXdpTcpEgressFrame>,
    }

    #[cfg(any(test, target_os = "linux"))]
    impl SmoltcpDevice for SmoltcpAfXdpDevice {
        type RxToken<'a>
            = SmoltcpAfXdpRxToken
        where
            Self: 'a;
        type TxToken<'a>
            = SmoltcpAfXdpTxToken<'a>
        where
            Self: 'a;

        fn receive(
            &mut self,
            _timestamp: SmoltcpInstant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            let frame = self.ingress.pop_front()?;
            self.current_route = Some(frame.route.clone());
            tracing::trace!(
                "AF_XDP TCP reactor ingress flow local={} peer={} bytes={}",
                frame.flow.local_addr,
                frame.flow.peer_addr,
                frame.ip_packet.len()
            );
            Some((
                SmoltcpAfXdpRxToken {
                    ip_packet: frame.ip_packet,
                },
                SmoltcpAfXdpTxToken {
                    route: Some(frame.route),
                    egress: &mut self.egress,
                },
            ))
        }

        fn transmit(&mut self, _timestamp: SmoltcpInstant) -> Option<Self::TxToken<'_>> {
            Some(SmoltcpAfXdpTxToken {
                route: self.current_route.clone(),
                egress: &mut self.egress,
            })
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = self.max_transmission_unit;
            caps.max_burst_size = Some(64);
            caps
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    impl RxToken for SmoltcpAfXdpRxToken {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(&self.ip_packet)
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    impl TxToken for SmoltcpAfXdpTxToken<'_> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut packet = vec![0u8; len];
            let result = f(&mut packet);
            if let Some(route) = self.route {
                self.egress.push(AfXdpTcpEgressFrame {
                    route: Some(route),
                    ip_packet: packet,
                });
            } else {
                self.egress.push(AfXdpTcpEgressFrame {
                    route: None,
                    ip_packet: packet,
                });
            }
            result
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) struct AfXdpTcpReactor {
        iface: SmoltcpInterface,
        sockets: SocketSet<'static>,
        device: SmoltcpAfXdpDevice,
        sessions: HashMap<AfXdpTcpFlowKey, AfXdpTcpSession>,
        session_limit: usize,
        tx_scratch: Vec<u8>,
        rx_scratch: Vec<u8>,
        tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
        http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
        #[cfg(test)]
        test_auto_start_proxy: bool,
    }

    #[cfg(any(test, target_os = "linux"))]
    impl AfXdpTcpReactor {
        pub(super) fn new(
            tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
            http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
        ) -> Self {
            let session_limit = crate::memory_governor::MEMORY_GOVERNOR
                .limit_for(crate::memory_governor::AdmissionClass::TcpConnection)
                .max(1);
            Self::new_with_session_limit(tcp_manager, http_manager, session_limit)
        }

        #[cfg(test)]
        pub(super) fn new_with_session_limit_for_test(
            tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
            http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
            session_limit: usize,
        ) -> Self {
            let mut reactor =
                Self::new_with_session_limit(tcp_manager, http_manager, session_limit);
            reactor.test_auto_start_proxy = true;
            reactor
        }

        fn new_with_session_limit(
            tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
            http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
            session_limit: usize,
        ) -> Self {
            let mut device = SmoltcpAfXdpDevice::new(1500);
            let mut config = SmoltcpConfig::new(HardwareAddress::Ip);
            config.random_seed = crate::utils::time::now_timestamp() as u64;
            let mut iface =
                SmoltcpInterface::new(config, &mut device, SmoltcpInstant::from_millis(0));
            iface.set_any_ip(true);
            Self {
                iface,
                sockets: SocketSet::new(Vec::new()),
                device,
                sessions: HashMap::new(),
                session_limit: session_limit.max(1),
                tx_scratch: Vec::with_capacity(2048),
                rx_scratch: vec![0u8; AF_XDP_TCP_RECV_SCRATCH_BYTES],
                tcp_manager,
                http_manager,
                #[cfg(test)]
                test_auto_start_proxy: false,
            }
        }

        pub(super) fn ingest(
            &mut self,
            route: AfXdpRouteMeta,
            flow: AfXdpTcpFlowKey,
            ip_packet: Bytes,
        ) -> AfXdpTcpIngestStatus {
            if !self.sessions.contains_key(&flow) && !tcp_packet_is_initial_syn(&ip_packet) {
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_IGNORED_UNKNOWN.fetch_add(1, Ordering::Relaxed);
                tracing::trace!(
                    "AF_XDP TCP reactor dropped non-SYN packet for unknown flow local={} peer={} bytes={}",
                    flow.local_addr,
                    flow.peer_addr,
                    ip_packet.len()
                );
                return AfXdpTcpIngestStatus::IgnoredUnknownFlow;
            }
            if !self.ensure_session(route.clone(), flow) {
                tracing::debug!(
                    "AF_XDP TCP reactor refused new session at limit local={} peer={} limit={}",
                    flow.local_addr,
                    flow.peer_addr,
                    self.session_limit
                );
                return AfXdpTcpIngestStatus::RefusedAtCapacity;
            }
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_ACCEPTED.fetch_add(1, Ordering::Relaxed);
            self.device.push_ingress(route, flow, ip_packet);
            AfXdpTcpIngestStatus::Accepted
        }

        pub(super) fn poll(&mut self) -> Vec<(AfXdpRouteMeta, Vec<u8>)> {
            let now =
                SmoltcpInstant::from_millis(crate::utils::time::now_timestamp_millis() as i64);
            self.poll_at(now)
        }

        #[cfg(test)]
        pub(super) fn poll_at_for_test(
            &mut self,
            now: SmoltcpInstant,
        ) -> Vec<(AfXdpRouteMeta, Vec<u8>)> {
            self.poll_at(now)
        }

        fn poll_at(&mut self, now: SmoltcpInstant) -> Vec<(AfXdpRouteMeta, Vec<u8>)> {
            loop {
                match self
                    .iface
                    .poll_ingress_single(now, &mut self.device, &mut self.sockets)
                {
                    PollIngressSingleResult::None => break,
                    PollIngressSingleResult::PacketProcessed
                    | PollIngressSingleResult::SocketStateChanged => {}
                }
            }
            let _ = self
                .iface
                .poll_egress(now, &mut self.device, &mut self.sockets);
            self.pump_sessions(now);
            let frames = self.device.drain_egress().collect::<Vec<_>>();
            let mut egress = Vec::with_capacity(frames.len());
            for frame in frames {
                let route = frame.route.or_else(|| {
                    reply_flow_key_from_ip_packet(&frame.ip_packet).and_then(|flow| {
                        self.sessions
                            .get(&flow)
                            .map(|session| session.route.clone())
                    })
                });
                match route {
                    Some(route) => egress.push((route, frame.ip_packet)),
                    None => tracing::debug!(
                        "AF_XDP TCP reactor dropped egress packet without route bytes={}",
                        frame.ip_packet.len()
                    ),
                }
            }
            self.retain_live_sessions(now);
            egress
        }

        pub(super) fn encode_egress_frame(
            &mut self,
            route: &AfXdpRouteMeta,
            ip_packet: &[u8],
        ) -> Option<Vec<u8>> {
            encode_ip_reply_frame(&route.link, ip_packet, &mut self.tx_scratch)?;
            Some(self.tx_scratch.clone())
        }

        #[cfg(test)]
        pub(super) fn session_count(&self) -> usize {
            self.sessions.len()
        }

        #[cfg(test)]
        pub(super) fn close_session_and_push_routeless_egress_for_test(
            &mut self,
            flow: AfXdpTcpFlowKey,
            ip_packet: Vec<u8>,
        ) {
            if let Some(session) = self.sessions.get_mut(&flow) {
                session.closing = true;
                let socket = self
                    .sockets
                    .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                socket.abort();
            }
            self.device.egress.push(AfXdpTcpEgressFrame {
                route: None,
                ip_packet,
            });
        }

        fn ensure_session(&mut self, route: AfXdpRouteMeta, flow: AfXdpTcpFlowKey) -> bool {
            let now =
                SmoltcpInstant::from_millis(crate::utils::time::now_timestamp_millis() as i64);
            self.ensure_session_at(route, flow, now)
        }

        fn ensure_session_at(
            &mut self,
            route: AfXdpRouteMeta,
            flow: AfXdpTcpFlowKey,
            now: SmoltcpInstant,
        ) -> bool {
            if let Some(session) = self.sessions.get_mut(&flow) {
                session.route = route;
                session.last_activity = now;
                return true;
            }
            if self.sessions.len() >= self.session_limit {
                return false;
            }

            self.ensure_local_ip(flow.local_addr.ip());
            let rx_buffer = SmoltcpTcp::SocketBuffer::new(vec![0; AF_XDP_TCP_SOCKET_BUFFER_BYTES]);
            let tx_buffer = SmoltcpTcp::SocketBuffer::new(vec![0; AF_XDP_TCP_SOCKET_BUFFER_BYTES]);
            let mut socket = SmoltcpTcp::Socket::new(rx_buffer, tx_buffer);
            socket.set_nagle_enabled(false);
            if let Err(err) =
                socket.listen(IpListenEndpoint::from(IpEndpoint::from(flow.local_addr)))
            {
                tracing::debug!(
                    "AF_XDP TCP reactor failed to listen local={} peer={}: {:?}",
                    flow.local_addr,
                    flow.peer_addr,
                    err
                );
                return false;
            }

            let socket = self.sockets.add(socket);
            let AfXdpTcpStreamParts {
                stream,
                ingress_tx,
                egress_rx,
            } = AfXdpTcpStream::default_channel_pair();
            let mut session = AfXdpTcpSession {
                flow,
                route,
                socket,
                ingress_tx: Some(ingress_tx),
                egress_rx,
                pending_ingress: Bytes::new(),
                pending_egress: Bytes::new(),
                last_activity: now,
                proxy_started: false,
                closing: false,
                egress_closed: false,
            };
            self.spawn_proxy_task(&mut session, stream);
            #[cfg(test)]
            if self.test_auto_start_proxy && !session.proxy_started {
                session.proxy_started = true;
            }
            self.sessions.insert(flow, session);
            true
        }

        fn ensure_local_ip(&mut self, ip: IpAddr) {
            let cidr = SmoltcpIpCidr::new(
                SmoltcpIpAddress::from(ip),
                if ip.is_ipv4() { 32 } else { 128 },
            );
            if self.iface.ip_addrs().contains(&cidr) {
                return;
            }
            let mut inserted = false;
            self.iface.update_ip_addrs(|addrs| {
                if !addrs.contains(&cidr) {
                    inserted = addrs.push(cidr).is_ok();
                }
            });
            if !inserted {
                tracing::debug!("AF_XDP TCP reactor local IP table is full; ip={}", ip);
            }
        }

        fn spawn_proxy_task(&self, session: &mut AfXdpTcpSession, stream: AfXdpTcpStream) {
            let peer_addr = session.flow.peer_addr;
            let listen_port = session.flow.local_addr.port();
            if let Some(tcp_manager) = self.tcp_manager.as_ref().cloned()
                && let Some((server, is_tls)) =
                    tcp_manager.find_tcp_server_by_port_sync(listen_port)
            {
                session.proxy_started = true;
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_PROXY_STARTED.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let result = if is_tls {
                        tcp_manager
                            .handle_af_xdp_tls_tcp_stream(stream, peer_addr, server)
                            .await
                    } else {
                        tcp_manager
                            .handle_af_xdp_tcp_stream(stream, peer_addr, server)
                            .await
                    };
                    if let Err(err) = result {
                        tracing::debug!(
                            "AF_XDP TCP proxy stream failed peer={}: {}",
                            peer_addr,
                            err
                        );
                    }
                });
                return;
            }

            if let Some(http_manager) = self.http_manager.as_ref().cloned()
                && let Some(kind) = http_manager.af_xdp_http_port_kind_sync(listen_port)
            {
                session.proxy_started = true;
                #[cfg(target_os = "linux")]
                AF_XDP_TCP_DIAG_PROXY_STARTED.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Err(err) = http_manager
                        .handle_af_xdp_http_stream(stream, peer_addr, listen_port, kind)
                        .await
                    {
                        tracing::debug!(
                            "AF_XDP HTTP stream failed peer={} port={}: {}",
                            peer_addr,
                            listen_port,
                            err
                        );
                    }
                });
            }
        }

        fn pump_sessions(&mut self, now: SmoltcpInstant) {
            for session in self.sessions.values_mut() {
                if !session.proxy_started {
                    let socket = self
                        .sockets
                        .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                    socket.abort();
                    session.closing = true;
                    continue;
                }
                let socket = self
                    .sockets
                    .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);

                if let Some(ingress_tx) = session.ingress_tx.as_ref() {
                    match flush_pending_ingress(ingress_tx, &mut session.pending_ingress) {
                        IngressDelivery::Delivered => {}
                        IngressDelivery::Backpressured => {
                            tracing::debug!(
                                "AF_XDP TCP reactor ingress channel still full local={} peer={} pending={}",
                                session.flow.local_addr,
                                session.flow.peer_addr,
                                session.pending_ingress.len()
                            );
                            continue;
                        }
                        IngressDelivery::Closed => {
                            socket.close();
                            session.closing = true;
                            continue;
                        }
                    }
                }

                while socket.can_recv() {
                    match socket.recv_slice(&mut self.rx_scratch) {
                        Ok(0) => break,
                        Ok(n) => {
                            session.last_activity = now;
                            #[cfg(target_os = "linux")]
                            AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES
                                .fetch_add(n as u64, Ordering::Relaxed);
                            let bytes = Bytes::copy_from_slice(&self.rx_scratch[..n]);
                            if let Some(ingress_tx) = session.ingress_tx.as_ref() {
                                match send_or_store_ingress(
                                    ingress_tx,
                                    &mut session.pending_ingress,
                                    bytes.clone(),
                                ) {
                                    IngressDelivery::Delivered => {
                                        #[cfg(target_os = "linux")]
                                        AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES
                                            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                                    }
                                    IngressDelivery::Backpressured => {
                                        tracing::debug!(
                                            "AF_XDP TCP reactor ingress channel full local={} peer={} pending={}",
                                            session.flow.local_addr,
                                            session.flow.peer_addr,
                                            session.pending_ingress.len()
                                        );
                                        break;
                                    }
                                    IngressDelivery::Closed => {
                                        socket.close();
                                        session.closing = true;
                                        break;
                                    }
                                }
                            } else {
                                tracing::debug!(
                                    "AF_XDP TCP reactor discarded ingress after stream read side closed local={} peer={} bytes={}",
                                    session.flow.local_addr,
                                    session.flow.peer_addr,
                                    n
                                );
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::debug!(
                                "AF_XDP TCP reactor recv failed local={} peer={}: {:?}",
                                session.flow.local_addr,
                                session.flow.peer_addr,
                                err
                            );
                            session.closing = true;
                            break;
                        }
                    }
                }
                if af_xdp_tcp_stream_read_side_closed(socket.state())
                    && session.pending_ingress.is_empty()
                    && socket.recv_queue() == 0
                {
                    session.ingress_tx = None;
                }

                while socket.can_send() {
                    if session.pending_egress.is_empty() {
                        match session.egress_rx.try_recv() {
                            Ok(bytes) if bytes.is_empty() => continue,
                            Ok(bytes) => {
                                session.last_activity = now;
                                #[cfg(target_os = "linux")]
                                AF_XDP_TCP_DIAG_STREAM_EGRESS_BYTES
                                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                                session.pending_egress = bytes;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                session.egress_closed = true;
                                break;
                            }
                        }
                    }

                    match socket.send_slice(&session.pending_egress) {
                        Ok(0) => break,
                        Ok(sent) if sent < session.pending_egress.len() => {
                            tracing::debug!(
                                "AF_XDP TCP reactor partially queued egress local={} peer={} sent={} total={}",
                                session.flow.local_addr,
                                session.flow.peer_addr,
                                sent,
                                session.pending_egress.len()
                            );
                            let _ = session.pending_egress.split_to(sent);
                            break;
                        }
                        Ok(_) => {
                            session.last_activity = now;
                            session.pending_egress.clear();
                        }
                        Err(err) => {
                            tracing::debug!(
                                "AF_XDP TCP reactor send failed local={} peer={}: {:?}",
                                session.flow.local_addr,
                                session.flow.peer_addr,
                                err
                            );
                            session.closing = true;
                            break;
                        }
                    }
                }
                if session.egress_closed && session.pending_egress.is_empty() {
                    let socket = self
                        .sockets
                        .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                    if socket.send_queue() == 0 {
                        socket.close();
                        session.closing = true;
                    }
                }
            }
        }

        fn retain_live_sessions(&mut self, now: SmoltcpInstant) {
            let mut finished = Vec::new();
            for (flow, session) in &self.sessions {
                let socket = self
                    .sockets
                    .get::<SmoltcpTcp::Socket<'static>>(session.socket);
                let idle_timeout = effective_af_xdp_tcp_idle_timeout();
                if !session.closing && session_idle_for(now, session.last_activity) >= idle_timeout
                {
                    tracing::debug!(
                        "AF_XDP TCP reactor closing idle session local={} peer={} idle_ms={} timeout_ms={}",
                        session.flow.local_addr,
                        session.flow.peer_addr,
                        session_idle_for(now, session.last_activity).as_millis(),
                        idle_timeout.as_millis()
                    );
                    finished.push(*flow);
                } else if af_xdp_tcp_session_reapable(session.closing, socket.state()) {
                    finished.push(*flow);
                }
            }
            for flow in finished {
                if let Some(session) = self.sessions.remove(&flow) {
                    let socket = self
                        .sockets
                        .get_mut::<SmoltcpTcp::Socket<'static>>(session.socket);
                    socket.abort();
                    let _ = self.sockets.remove(session.socket);
                }
            }
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn af_xdp_tcp_session_reapable(closing: bool, state: SmoltcpTcp::State) -> bool {
        closing
            && matches!(
                state,
                SmoltcpTcp::State::Closed | SmoltcpTcp::State::TimeWait
            )
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn af_xdp_tcp_stream_read_side_closed(state: SmoltcpTcp::State) -> bool {
        matches!(
            state,
            SmoltcpTcp::State::Closing
                | SmoltcpTcp::State::LastAck
                | SmoltcpTcp::State::TimeWait
                | SmoltcpTcp::State::Closed
        )
    }

    #[cfg(any(test, target_os = "linux"))]
    fn effective_af_xdp_tcp_idle_timeout() -> Duration {
        crate::memory_governor::MEMORY_GOVERNOR
            .tcp_relay_pressure_idle_timeout()
            .unwrap_or(AF_XDP_TCP_SESSION_IDLE_TIMEOUT)
            .min(AF_XDP_TCP_SESSION_IDLE_TIMEOUT)
    }

    #[cfg(any(test, target_os = "linux"))]
    fn session_idle_for(now: SmoltcpInstant, last_activity: SmoltcpInstant) -> Duration {
        let elapsed_ms = now
            .total_millis()
            .saturating_sub(last_activity.total_millis())
            .max(0) as u64;
        Duration::from_millis(elapsed_ms)
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn flush_pending_ingress(
        ingress_tx: &mpsc::Sender<Bytes>,
        pending_ingress: &mut Bytes,
    ) -> IngressDelivery {
        if pending_ingress.is_empty() {
            return IngressDelivery::Delivered;
        }
        let bytes = std::mem::take(pending_ingress);
        send_or_store_ingress(ingress_tx, pending_ingress, bytes)
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn send_or_store_ingress(
        ingress_tx: &mpsc::Sender<Bytes>,
        pending_ingress: &mut Bytes,
        bytes: Bytes,
    ) -> IngressDelivery {
        match ingress_tx.try_send(bytes) {
            Ok(()) => IngressDelivery::Delivered,
            Err(mpsc::error::TrySendError::Full(bytes)) => {
                *pending_ingress = bytes;
                IngressDelivery::Backpressured
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                pending_ingress.clear();
                IngressDelivery::Closed
            }
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn proxy_bridge_should_idle(
        polled_packets: usize,
        parsed_frames: usize,
        downstream_datagrams: usize,
        tcp_egress_frames: usize,
        downstream_budget_exhausted: bool,
    ) -> bool {
        if downstream_budget_exhausted {
            return false;
        }
        polled_packets == 0
            && parsed_frames == 0
            && downstream_datagrams == 0
            && tcp_egress_frames == 0
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn proxy_bridge_should_continue(manager: &Arc<XdpManager>) -> bool {
        manager_is_current(manager)
            && manager.proxy_redirect_ready()
            && !manager.attached.read().is_empty()
    }

    impl AfXdpTcpStream {
        pub fn channel_pair(buffer: usize) -> AfXdpTcpStreamParts {
            let depth = buffer.max(1);
            let (ingress_tx, incoming_rx) = mpsc::channel(depth);
            let (outgoing_tx, egress_rx) = mpsc::channel(depth);
            AfXdpTcpStreamParts {
                stream: Self {
                    incoming_rx,
                    outgoing_tx: Some(outgoing_tx),
                    read_buf: Bytes::new(),
                    write_permit: None,
                },
                ingress_tx,
                egress_rx,
            }
        }

        pub fn default_channel_pair() -> AfXdpTcpStreamParts {
            Self::channel_pair(AF_XDP_TCP_STREAM_CHANNEL_DEPTH)
        }
    }

    impl AsyncRead for AfXdpTcpStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            loop {
                if !self.read_buf.is_empty() {
                    let len = self.read_buf.len().min(buf.remaining());
                    let chunk = self.read_buf.split_to(len);
                    buf.put_slice(&chunk);
                    return Poll::Ready(Ok(()));
                }
                match Pin::new(&mut self.incoming_rx).poll_recv(cx) {
                    Poll::Ready(Some(chunk)) if chunk.is_empty() => continue,
                    Poll::Ready(Some(chunk)) => {
                        self.read_buf = chunk;
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    impl AsyncWrite for AfXdpTcpStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if self.outgoing_tx.is_none() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "AF_XDP TCP stream write side is closed",
                )));
            }
            if self.write_permit.is_none() {
                let tx = self.outgoing_tx.as_ref().expect("checked above").clone();
                self.write_permit = Some(Box::pin(tx.reserve_owned()));
            }
            let permit = match self
                .write_permit
                .as_mut()
                .expect("created above")
                .as_mut()
                .poll(cx)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => {
                    self.write_permit = None;
                    permit
                }
                Poll::Ready(Err(_)) => {
                    self.write_permit = None;
                    self.outgoing_tx = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "AF_XDP TCP stream command channel is closed",
                    )));
                }
            };
            let len = buf.len().min(AF_XDP_TCP_STREAM_WRITE_CHUNK);
            permit.send(Bytes::copy_from_slice(&buf[..len]));
            Poll::Ready(Ok(len))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.write_permit = None;
            self.outgoing_tx = None;
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct AfXdpRuntime {
        pub enabled: bool,
        pub ready: bool,
        pub detail: String,
    }

    #[cfg(any(test, target_os = "linux"))]
    #[derive(Clone)]
    pub(super) struct AfXdpUdpRouteEntry {
        pub(super) route: AfXdpRouteMeta,
        pub(super) last_seen_ms: u64,
    }

    pub fn runtime() -> AfXdpRuntime {
        let status = status_snapshot();
        AfXdpRuntime {
            enabled: status.enabled,
            ready: status.available
                && status
                    .interfaces
                    .iter()
                    .any(|interface| interface.mode == "proxy" && interface.xsk_ready),
            detail: status.fallback_reason,
        }
    }

    pub async fn start_proxy_bridge(
        quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
        tcp_manager: Arc<crate::tcp_proxy::TcpProxyManager>,
        http_manager: Arc<crate::http_proxy_manager::HttpProxyManager>,
    ) {
        start_proxy_bridge_inner(quic_demux, Some(tcp_manager), Some(http_manager)).await;
    }

    async fn start_proxy_bridge_inner(
        quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
        tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
        http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
    ) {
        let manager = manager_from_runtime();
        if !manager.config.enabled {
            return;
        }
        if !XDP_PROXY_DATAPLANE_ACTIVE {
            manager.set_proxy_fallback_reason(
                "AF_XDP UDP bridge is compiled but TX dataplane is not active; traffic will PASS",
            );
            return;
        }
        #[cfg(target_os = "linux")]
        run_proxy_bridge(manager, quic_demux, tcp_manager, http_manager).await;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = quic_demux;
            let _ = tcp_manager;
            let _ = http_manager;
            manager.set_proxy_fallback_reason("AF_XDP proxy bridge is supported on Linux only");
        }
    }

    #[allow(dead_code)]
    pub async fn start_udp_bridge(quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>) {
        start_proxy_bridge_inner(quic_demux, None, None).await;
    }

    #[cfg(target_os = "linux")]
    async fn run_proxy_bridge(
        manager: Arc<XdpManager>,
        quic_demux: Arc<crate::quic_udp_demux::QuicUdpDemuxManager>,
        tcp_manager: Option<Arc<crate::tcp_proxy::TcpProxyManager>>,
        http_manager: Option<Arc<crate::http_proxy_manager::HttpProxyManager>>,
    ) {
        const AF_XDP_DOWNSTREAM_QUEUE: usize = 4096;
        const AF_XDP_DOWNSTREAM_DRAIN_BUDGET: usize = 1024;
        const AF_XDP_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(5);
        const AF_XDP_ROUTE_CACHE_MAX: usize = 65_536;
        const AF_XDP_ROUTE_CACHE_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
        const AF_XDP_ROUTE_CACHE_EVICT_BATCH: usize = 1024;
        const AF_XDP_ROUTE_CACHE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
        const AF_XDP_MAX_CONSECUTIVE_POLL_ERRORS: u32 = 3;
        const AF_XDP_MAX_CONSECUTIVE_TX_FAILURES: u32 = 256;
        const AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES: u32 = 1024;
        const AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS: u32 = 1024;

        let (downstream_tx, mut downstream_rx) =
            mpsc::channel::<crate::udp_proxy::DownstreamUdpDatagram>(AF_XDP_DOWNSTREAM_QUEUE);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut idle_tick = interval(AF_XDP_IDLE_POLL_INTERVAL);
        idle_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut udp_routes = HashMap::<(SocketAddr, SocketAddr), AfXdpUdpRouteEntry>::new();
        let mut last_route_cache_sweep_ms = crate::udp_proxy::udp_activity_now_ms();
        let mut tcp_reactor = AfXdpTcpReactor::new(tcp_manager, http_manager);
        let mut consecutive_poll_errors = 0u32;
        let mut tx_failures = AfXdpTxFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_TX_FAILURES);
        let mut udp_ingress_failures =
            AfXdpTxFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES);
        let mut tcp_admission_failures =
            AfXdpTcpAdmissionFailureTracker::new(AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS);
        let mut frames = Vec::with_capacity(64);

        match manager.enable_proxy_redirect("AF_XDP proxy bridge") {
            Ok(true) => {}
            Ok(false) => {
                manager.set_proxy_fallback_reason(
                    "AF_XDP proxy bridge did not enable redirect; sockets are not ready or proxy ports are empty, traffic will PASS",
                );
                manager.persist_status();
                return;
            }
            Err(err) => {
                manager.disable_proxy_redirect_for_fallback(format!(
                    "AF_XDP proxy bridge failed to enable AF_XDP redirect: {err}; traffic will PASS"
                ));
                return;
            }
        }

        loop {
            if !proxy_bridge_should_continue(&manager) {
                tracing::debug!(
                    "AF_XDP proxy bridge exiting because XDP manager is stale or redirect is disabled"
                );
                return;
            }
            frames.clear();
            let poll_result = {
                let mut runtime = manager.af_xdp.lock();
                match runtime.as_mut() {
                    Some(runtime) => runtime.poll_raw_once(|interface, queue, frame| {
                        frames.push((interface.to_string(), queue, frame));
                    }),
                    None => {
                        manager.set_proxy_fallback_reason(
                            "AF_XDP proxy bridge cannot start; AF_XDP runtime is not initialized",
                        );
                        return;
                    }
                }
            };

            let polled_packets = match poll_result {
                Ok(stats) => {
                    consecutive_poll_errors = 0;
                    stats.packets
                }
                Err(err) => {
                    frames.clear();
                    consecutive_poll_errors = consecutive_poll_errors.saturating_add(1);
                    let detail = format!(
                        "AF_XDP proxy bridge poll failed ({consecutive_poll_errors}/{AF_XDP_MAX_CONSECUTIVE_POLL_ERRORS}): {err}"
                    );
                    manager.set_proxy_fallback_reason(detail.clone());
                    tracing::warn!("{}", detail);
                    if consecutive_poll_errors >= AF_XDP_MAX_CONSECUTIVE_POLL_ERRORS {
                        manager.disable_proxy_redirect_for_fallback(format!(
                            "AF_XDP proxy bridge poll failed repeatedly: {err}; proxy redirect disabled, traffic will PASS"
                        ));
                        return;
                    }
                    idle_tick.tick().await;
                    continue;
                }
            };
            let parsed_frames = frames.len();
            let now_ms = crate::udp_proxy::udp_activity_now_ms();
            if udp_route_cache_sweep_due(
                now_ms,
                last_route_cache_sweep_ms,
                AF_XDP_ROUTE_CACHE_SWEEP_INTERVAL,
            ) {
                compact_udp_route_cache(
                    &mut udp_routes,
                    now_ms,
                    AF_XDP_ROUTE_CACHE_IDLE_TIMEOUT,
                    AF_XDP_ROUTE_CACHE_MAX,
                    AF_XDP_ROUTE_CACHE_EVICT_BATCH,
                );
                last_route_cache_sweep_ms = now_ms;
            }

            for (interface, queue, frame) in frames.drain(..) {
                match parse_proxy_frame(&interface, queue, &frame) {
                    Some(AfXdpProxyFrame::Udp { route, packet }) => {
                        let now_ms = crate::udp_proxy::udp_activity_now_ms();
                        if udp_routes.len() >= AF_XDP_ROUTE_CACHE_MAX {
                            compact_udp_route_cache(
                                &mut udp_routes,
                                now_ms,
                                AF_XDP_ROUTE_CACHE_IDLE_TIMEOUT,
                                AF_XDP_ROUTE_CACHE_MAX,
                                AF_XDP_ROUTE_CACHE_EVICT_BATCH,
                            );
                        }
                        udp_routes.insert(
                            (packet.local_addr, packet.peer_addr),
                            AfXdpUdpRouteEntry {
                                route,
                                last_seen_ms: now_ms,
                            },
                        );
                        let Some(datagram) = packet.into_udp_datagram() else {
                            continue;
                        };
                        match quic_demux
                            .receive_af_xdp_datagram(
                                datagram,
                                downstream_tx.clone(),
                                shutdown_rx.clone(),
                            )
                            .await
                        {
                            Ok(crate::udp_proxy::UdpIngressDatagramStatus::Sent)
                            | Ok(crate::udp_proxy::UdpIngressDatagramStatus::Blocked)
                            | Ok(crate::udp_proxy::UdpIngressDatagramStatus::NoRoute) => {
                                udp_ingress_failures.record(AfXdpTxStatus::Sent);
                            }
                            Ok(crate::udp_proxy::UdpIngressDatagramStatus::Full) => {
                                tracing::debug!("AF_XDP proxy bridge upstream session queue full");
                                if udp_ingress_failures.record(AfXdpTxStatus::Backpressured) {
                                    manager.disable_proxy_redirect_for_fallback(format!(
                                        "AF_XDP UDP ingress queues stayed full for {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams; proxy redirect disabled, traffic will PASS"
                                    ));
                                    return;
                                }
                            }
                            Ok(crate::udp_proxy::UdpIngressDatagramStatus::Closed) => {
                                tracing::debug!("AF_XDP proxy bridge upstream session closed");
                                if udp_ingress_failures.record(AfXdpTxStatus::Failed) {
                                    manager.disable_proxy_redirect_for_fallback(format!(
                                        "AF_XDP UDP ingress sessions stayed closed for {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams; proxy redirect disabled, traffic will PASS"
                                    ));
                                    return;
                                }
                            }
                            Err(err) => {
                                tracing::debug!(
                                    "AF_XDP proxy bridge failed to process datagram: {}",
                                    err
                                );
                                if udp_ingress_failures.record(AfXdpTxStatus::Failed) {
                                    manager.disable_proxy_redirect_for_fallback(format!(
                                        "AF_XDP UDP ingress failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_UDP_INGRESS_FAILURES} redirected datagrams: {err}; proxy redirect disabled, traffic will PASS"
                                    ));
                                    return;
                                }
                            }
                        }
                    }
                    Some(AfXdpProxyFrame::Tcp {
                        route,
                        flow,
                        ip_packet,
                    }) => {
                        let status = tcp_reactor.ingest(route, flow, ip_packet);
                        if tcp_admission_failures.record(status) {
                            manager.disable_proxy_redirect_for_fallback(format!(
                                "AF_XDP TCP reactor refused {AF_XDP_MAX_CONSECUTIVE_TCP_ADMISSION_REFUSALS} new sessions consecutively; proxy redirect disabled, traffic will PASS"
                            ));
                            return;
                        }
                    }
                    None => {
                        tracing::debug!(
                            "AF_XDP proxy bridge received unparseable redirected frame interface={} queue={} bytes={}",
                            interface,
                            queue,
                            frame.len()
                        );
                    }
                }
            }

            let mut downstream_datagrams = 0usize;
            let mut downstream_budget_exhausted = false;
            for _ in 0..AF_XDP_DOWNSTREAM_DRAIN_BUDGET {
                let datagram = match downstream_rx.try_recv() {
                    Ok(datagram) => datagram,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                };
                downstream_datagrams = downstream_datagrams.saturating_add(1);
                let now_ms = crate::udp_proxy::udp_activity_now_ms();
                let Some(entry) = udp_routes.get_mut(&(datagram.listen_addr, datagram.peer_addr))
                else {
                    tracing::debug!(
                        "AF_XDP proxy bridge has no L2 route for downstream datagram listen={} peer={} bytes={}",
                        datagram.listen_addr,
                        datagram.peer_addr,
                        datagram.payload.len()
                    );
                    continue;
                };
                entry.last_seen_ms = now_ms;
                let route = entry.route.clone();
                let sent = {
                    let mut runtime = manager.af_xdp.lock();
                    match runtime.as_mut() {
                        Some(runtime) => runtime.send_udp_datagram(
                            &route.interface,
                            route.queue,
                            &route.link,
                            datagram.listen_addr,
                            datagram.peer_addr,
                            datagram.payload.as_ref(),
                        ),
                        None => Ok(false),
                    }
                };
                match sent {
                    Ok(true) => {
                        tx_failures.record(AfXdpTxStatus::Sent);
                    }
                    Ok(false) => {
                        tracing::debug!(
                            "AF_XDP proxy bridge could not send downstream datagram listen={} peer={} bytes={}",
                            datagram.listen_addr,
                            datagram.peer_addr,
                            datagram.payload.len()
                        );
                        if tx_failures.record(AfXdpTxStatus::Backpressured) {
                            manager.disable_proxy_redirect_for_fallback(format!(
                                "AF_XDP proxy bridge TX backpressure repeated {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} times; proxy redirect disabled, traffic will PASS"
                            ));
                            return;
                        }
                    }
                    Err(err) => {
                        tracing::debug!(
                            "AF_XDP proxy bridge TX failed listen={} peer={} bytes={}: {}",
                            datagram.listen_addr,
                            datagram.peer_addr,
                            datagram.payload.len(),
                            err
                        );
                        if tx_failures.record(AfXdpTxStatus::Failed) {
                            manager.disable_proxy_redirect_for_fallback(format!(
                                "AF_XDP proxy bridge TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}; proxy redirect disabled, traffic will PASS"
                            ));
                            return;
                        }
                    }
                }
            }
            if downstream_datagrams == AF_XDP_DOWNSTREAM_DRAIN_BUDGET {
                downstream_budget_exhausted = true;
            }

            let tcp_egress = tcp_reactor.poll();
            let tcp_egress_frames = tcp_egress.len();
            #[cfg(target_os = "linux")]
            AF_XDP_TCP_DIAG_EGRESS_FRAMES.fetch_add(tcp_egress_frames as u64, Ordering::Relaxed);
            for (route, ip_packet) in tcp_egress {
                let Some(frame) = tcp_reactor.encode_egress_frame(&route, &ip_packet) else {
                    tracing::debug!(
                        "AF_XDP TCP reactor failed to encode egress frame interface={} queue={} bytes={}",
                        route.interface,
                        route.queue,
                        ip_packet.len()
                    );
                    continue;
                };
                let sent = {
                    let mut runtime = manager.af_xdp.lock();
                    match runtime.as_mut() {
                        Some(runtime) => {
                            runtime.send_raw_frame(&route.interface, route.queue, &frame)
                        }
                        None => Ok(false),
                    }
                };
                match sent {
                    Ok(true) => {
                        tx_failures.record(AfXdpTxStatus::Sent);
                    }
                    Ok(false) => {
                        tracing::debug!(
                            "AF_XDP TCP reactor could not send frame interface={} queue={} bytes={}",
                            route.interface,
                            route.queue,
                            frame.len()
                        );
                        if tx_failures.record(AfXdpTxStatus::Backpressured) {
                            manager.disable_proxy_redirect_for_fallback(format!(
                                "AF_XDP TCP reactor TX backpressure repeated {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} times; proxy redirect disabled, traffic will PASS"
                            ));
                            return;
                        }
                    }
                    Err(err) => {
                        tracing::debug!(
                            "AF_XDP TCP reactor TX failed interface={} queue={} bytes={}: {}",
                            route.interface,
                            route.queue,
                            frame.len(),
                            err
                        );
                        if tx_failures.record(AfXdpTxStatus::Failed) {
                            manager.disable_proxy_redirect_for_fallback(format!(
                                "AF_XDP TCP reactor TX failed repeatedly after {AF_XDP_MAX_CONSECUTIVE_TX_FAILURES} attempts: {err}; proxy redirect disabled, traffic will PASS"
                            ));
                            return;
                        }
                    }
                }
            }

            if proxy_bridge_should_idle(
                polled_packets,
                parsed_frames,
                downstream_datagrams,
                tcp_egress_frames,
                downstream_budget_exhausted,
            ) {
                idle_tick.tick().await;
            }
        }
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn udp_route_cache_sweep_due(
        now_ms: u64,
        last_sweep_ms: u64,
        sweep_interval: Duration,
    ) -> bool {
        let interval_ms = sweep_interval.as_millis().min(u64::MAX as u128) as u64;
        now_ms.saturating_sub(last_sweep_ms) >= interval_ms
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn compact_udp_route_cache(
        routes: &mut HashMap<(SocketAddr, SocketAddr), AfXdpUdpRouteEntry>,
        now_ms: u64,
        idle_timeout: Duration,
        max_entries: usize,
        evict_batch: usize,
    ) {
        if routes.is_empty() {
            return;
        }
        let idle_timeout_ms = idle_timeout.as_millis().min(u64::MAX as u128) as u64;
        routes.retain(|_, entry| now_ms.saturating_sub(entry.last_seen_ms) < idle_timeout_ms);
        if routes.len() < max_entries {
            return;
        }
        let evict_count = routes
            .len()
            .saturating_sub(max_entries.saturating_sub(1))
            .max(evict_batch.min(routes.len()));
        let mut oldest = routes
            .iter()
            .map(|(key, entry)| (*key, entry.last_seen_ms))
            .collect::<Vec<_>>();
        oldest.select_nth_unstable_by(evict_count.saturating_sub(1), |left, right| {
            left.1.cmp(&right.1)
        });
        for (key, _) in oldest.into_iter().take(evict_count) {
            routes.remove(&key);
        }
        tracing::debug!(
            "AF_XDP proxy bridge evicted stale UDP route cache entries count={} remaining={}",
            evict_count,
            routes.len()
        );
    }

    pub fn parse_l4_packet(frame: &[u8]) -> Option<AfXdpL4Packet> {
        let (link, l3_offset) = parse_link_meta(frame)?;
        let ethertype = link.ethertype;
        match ethertype {
            ETHERTYPE_IPV4 => parse_ipv4_l4(frame, l3_offset, link),
            ETHERTYPE_IPV6 => parse_ipv6_l4(frame, l3_offset, link),
            _ => None,
        }
    }

    pub fn parse_proxy_frame(interface: &str, queue: u32, frame: &[u8]) -> Option<AfXdpProxyFrame> {
        let (link, l3_offset) = parse_link_meta(frame)?;
        let protocol = transport_protocol_from_frame(frame, l3_offset, link.ethertype)?;
        let route = AfXdpRouteMeta {
            interface: interface.to_string(),
            queue,
            link,
        };
        match protocol {
            IP_PROTO_TCP => {
                let (_, ip_packet) = extract_ip_frame(frame)?;
                let flow = tcp_flow_key_from_ip_packet(&ip_packet)?;
                Some(AfXdpProxyFrame::Tcp {
                    route,
                    flow,
                    ip_packet,
                })
            }
            IP_PROTO_UDP => {
                let packet = parse_l4_packet(frame)?;
                Some(AfXdpProxyFrame::Udp { route, packet })
            }
            _ => None,
        }
    }

    pub fn extract_ip_frame(frame: &[u8]) -> Option<(AfXdpLinkMeta, Bytes)> {
        let (link, l3_offset) = parse_link_meta(frame)?;
        let ip_end = match link.ethertype {
            ETHERTYPE_IPV4 => ipv4_packet_end(frame, l3_offset)?,
            ETHERTYPE_IPV6 => ipv6_packet_end(frame, l3_offset)?,
            _ => return None,
        };
        Some((link, Bytes::copy_from_slice(&frame[l3_offset..ip_end])))
    }

    pub fn encode_ip_reply_frame(
        link: &AfXdpLinkMeta,
        ip_packet: &[u8],
        out: &mut Vec<u8>,
    ) -> Option<()> {
        let ethertype = match ip_packet.first()? >> 4 {
            4 => ETHERTYPE_IPV4,
            6 => ETHERTYPE_IPV6,
            _ => return None,
        };
        let total_len = link.reply_eth_header_len().checked_add(ip_packet.len())?;
        out.clear();
        out.reserve(total_len);
        encode_reply_eth_header(link, ethertype, out);
        out.extend_from_slice(ip_packet);
        Some(())
    }

    pub fn encode_udp_reply_frame(
        link: &AfXdpLinkMeta,
        listen_addr: SocketAddr,
        peer_addr: SocketAddr,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) -> Option<()> {
        if listen_addr.is_ipv4() != peer_addr.is_ipv4() {
            return None;
        }
        let udp_len = UDP_HEADER_LEN.checked_add(payload.len())?;
        if udp_len > u16::MAX as usize {
            return None;
        }
        let ethertype = if listen_addr.is_ipv4() {
            ETHERTYPE_IPV4
        } else {
            ETHERTYPE_IPV6
        };
        let ip_header_len = if listen_addr.is_ipv4() {
            IPV4_MIN_HEADER_LEN
        } else {
            IPV6_HEADER_LEN
        };
        let ip_payload_len = udp_len;
        let ip_total_len = ip_header_len.checked_add(ip_payload_len)?;
        if ip_total_len > u16::MAX as usize {
            return None;
        }
        let total_len = link
            .reply_eth_header_len()
            .checked_add(ip_header_len)?
            .checked_add(udp_len)?;

        out.clear();
        out.reserve(total_len);
        encode_reply_eth_header(link, ethertype, out);
        let ip_offset = out.len();
        match (listen_addr.ip(), peer_addr.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                out.extend_from_slice(&[
                    0x45,
                    0,
                    (ip_total_len >> 8) as u8,
                    ip_total_len as u8,
                    0,
                    0,
                    0,
                    0,
                    64,
                    IP_PROTO_UDP,
                    0,
                    0,
                ]);
                out.extend_from_slice(&source.octets());
                out.extend_from_slice(&destination.octets());
                let checksum = internet_checksum(&out[ip_offset..ip_offset + IPV4_MIN_HEADER_LEN]);
                out[ip_offset + 10..ip_offset + 12].copy_from_slice(&checksum.to_be_bytes());
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                out.extend_from_slice(&[
                    0x60,
                    0,
                    0,
                    0,
                    (ip_payload_len >> 8) as u8,
                    ip_payload_len as u8,
                    IP_PROTO_UDP,
                    64,
                ]);
                out.extend_from_slice(&source.octets());
                out.extend_from_slice(&destination.octets());
            }
            _ => return None,
        }

        let udp_offset = out.len();
        out.extend_from_slice(&listen_addr.port().to_be_bytes());
        out.extend_from_slice(&peer_addr.port().to_be_bytes());
        out.extend_from_slice(&(udp_len as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);

        let udp_checksum = udp_checksum(listen_addr.ip(), peer_addr.ip(), &out[udp_offset..])?;
        out[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
        Some(())
    }

    fn encode_reply_eth_header(link: &AfXdpLinkMeta, ethertype: u16, out: &mut Vec<u8>) {
        out.extend_from_slice(&link.source_mac);
        out.extend_from_slice(&link.destination_mac);
        for tag in link
            .vlan_tags
            .iter()
            .take(usize::from(link.vlan_tag_count.min(2)))
        {
            out.extend_from_slice(&tag.tpid.to_be_bytes());
            out.extend_from_slice(&tag.tci.to_be_bytes());
        }
        out.extend_from_slice(&ethertype.to_be_bytes());
    }

    fn udp_checksum(source: IpAddr, destination: IpAddr, udp_packet: &[u8]) -> Option<u16> {
        let pseudo_sum = match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                let mut pseudo_header = [0u8; 12];
                pseudo_header[0..4].copy_from_slice(&source.octets());
                pseudo_header[4..8].copy_from_slice(&destination.octets());
                pseudo_header[9] = IP_PROTO_UDP;
                pseudo_header[10..12].copy_from_slice(&(udp_packet.len() as u16).to_be_bytes());
                checksum_sum(&pseudo_header)
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                let mut pseudo_header = [0u8; 40];
                pseudo_header[0..16].copy_from_slice(&source.octets());
                pseudo_header[16..32].copy_from_slice(&destination.octets());
                pseudo_header[32..36].copy_from_slice(&(udp_packet.len() as u32).to_be_bytes());
                pseudo_header[39] = IP_PROTO_UDP;
                checksum_sum(&pseudo_header)
            }
            _ => return None,
        };
        Some(finalize_checksum(
            pseudo_sum.wrapping_add(checksum_sum(udp_packet)),
        ))
    }

    fn internet_checksum(data: &[u8]) -> u16 {
        finalize_checksum(checksum_sum(data))
    }

    fn checksum_sum(data: &[u8]) -> u32 {
        let mut chunks = data.chunks_exact(2);
        let mut sum = chunks.by_ref().fold(0u32, |sum, chunk| {
            sum + u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        });
        if let Some(byte) = chunks.remainder().first() {
            sum += u16::from_be_bytes([*byte, 0]) as u32;
        }
        sum
    }

    fn finalize_checksum(mut sum: u32) -> u16 {
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        if checksum == 0 { 0xffff } else { checksum }
    }

    fn parse_link_meta(frame: &[u8]) -> Option<(AfXdpLinkMeta, usize)> {
        if frame.len() < ETH_HEADER_LEN {
            return None;
        }
        let mut destination_mac = [0u8; 6];
        destination_mac.copy_from_slice(&frame[0..6]);
        let mut source_mac = [0u8; 6];
        source_mac.copy_from_slice(&frame[6..12]);
        let mut ethertype = read_u16(frame, 12)?;
        let mut offset = ETH_HEADER_LEN;
        let mut vlan_tags = [AfXdpVlanTag { tpid: 0, tci: 0 }; 2];
        let mut vlan_tag_count = 0u8;
        for _ in 0..2 {
            if !is_vlan_ethertype(ethertype) {
                return Some((
                    AfXdpLinkMeta {
                        destination_mac,
                        source_mac,
                        vlan_tags,
                        vlan_tag_count,
                        ethertype,
                    },
                    offset,
                ));
            }
            if frame.len() < offset + VLAN_HEADER_LEN {
                return None;
            }
            vlan_tags[usize::from(vlan_tag_count)] = AfXdpVlanTag {
                tpid: ethertype,
                tci: read_u16(frame, offset)?,
            };
            vlan_tag_count = vlan_tag_count.saturating_add(1);
            ethertype = read_u16(frame, offset + 2)?;
            offset += VLAN_HEADER_LEN;
        }
        Some((
            AfXdpLinkMeta {
                destination_mac,
                source_mac,
                vlan_tags,
                vlan_tag_count,
                ethertype,
            },
            offset,
        ))
    }

    fn is_vlan_ethertype(ethertype: u16) -> bool {
        matches!(
            ethertype,
            ETHERTYPE_VLAN
                | ETHERTYPE_QINQ
                | ETHERTYPE_QINQ_9100
                | ETHERTYPE_QINQ_9200
                | ETHERTYPE_QINQ_9300
        )
    }

    fn parse_ipv4_l4(frame: &[u8], ip_offset: usize, link: AfXdpLinkMeta) -> Option<AfXdpL4Packet> {
        let base = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN)?;
        let version = base[0] >> 4;
        let ihl = usize::from(base[0] & 0x0f) * 4;
        if version != 4 || ihl < IPV4_MIN_HEADER_LEN {
            return None;
        }
        let packet_end = ipv4_packet_end(frame, ip_offset)?;
        let fragment = u16::from_be_bytes([base[6], base[7]]);
        if fragment & 0x3fff != 0 {
            return None;
        }
        let protocol = base[9];
        let source = IpAddr::V4(Ipv4Addr::new(base[12], base[13], base[14], base[15]));
        let destination = IpAddr::V4(Ipv4Addr::new(base[16], base[17], base[18], base[19]));
        parse_transport(
            frame,
            protocol,
            ip_offset + ihl,
            packet_end,
            source,
            destination,
            link,
        )
    }

    fn parse_ipv6_l4(frame: &[u8], ip_offset: usize, link: AfXdpLinkMeta) -> Option<AfXdpL4Packet> {
        let base = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN)?;
        if base[0] >> 4 != 6 {
            return None;
        }
        let packet_end = ipv6_packet_end(frame, ip_offset)?;
        let mut source_octets = [0u8; 16];
        source_octets.copy_from_slice(&base[8..24]);
        let mut destination_octets = [0u8; 16];
        destination_octets.copy_from_slice(&base[24..40]);
        let source = IpAddr::V6(Ipv6Addr::from(source_octets));
        let destination = IpAddr::V6(Ipv6Addr::from(destination_octets));
        let (protocol, l4_offset) =
            ipv6_transport_offset(frame, base[6], ip_offset + IPV6_HEADER_LEN, packet_end)?;
        parse_transport(
            frame,
            protocol,
            l4_offset,
            packet_end,
            source,
            destination,
            link,
        )
    }

    fn transport_protocol_from_frame(frame: &[u8], ip_offset: usize, ethertype: u16) -> Option<u8> {
        match ethertype {
            ETHERTYPE_IPV4 => {
                let base = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN)?;
                let version = base[0] >> 4;
                let ihl = usize::from(base[0] & 0x0f) * 4;
                if version != 4 || ihl < IPV4_MIN_HEADER_LEN {
                    return None;
                }
                let total_len = usize::from(u16::from_be_bytes([base[2], base[3]]));
                if total_len < ihl || ip_offset.checked_add(total_len)? > frame.len() {
                    return None;
                }
                let fragment = u16::from_be_bytes([base[6], base[7]]);
                if fragment & 0x3fff != 0 {
                    return None;
                }
                Some(base[9])
            }
            ETHERTYPE_IPV6 => {
                let base = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN)?;
                if base[0] >> 4 != 6 {
                    return None;
                }
                let packet_end = ipv6_packet_end(frame, ip_offset)?;
                let (protocol, _) =
                    ipv6_transport_offset(frame, base[6], ip_offset + IPV6_HEADER_LEN, packet_end)?;
                Some(protocol)
            }
            _ => None,
        }
    }

    fn ipv4_packet_end(frame: &[u8], ip_offset: usize) -> Option<usize> {
        let base = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN)?;
        let version = base[0] >> 4;
        let ihl = usize::from(base[0] & 0x0f) * 4;
        if version != 4 || ihl < IPV4_MIN_HEADER_LEN {
            return None;
        }
        let total_len = usize::from(u16::from_be_bytes([base[2], base[3]]));
        if total_len < ihl {
            return None;
        }
        let packet_end = ip_offset.checked_add(total_len)?;
        (frame.len() >= packet_end).then_some(packet_end)
    }

    fn ipv6_packet_end(frame: &[u8], ip_offset: usize) -> Option<usize> {
        let base = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN)?;
        if base[0] >> 4 != 6 {
            return None;
        }
        let payload_len = usize::from(u16::from_be_bytes([base[4], base[5]]));
        let packet_end = ip_offset
            .checked_add(IPV6_HEADER_LEN)?
            .checked_add(payload_len)?;
        (frame.len() >= packet_end).then_some(packet_end)
    }

    fn ipv6_transport_offset(
        frame: &[u8],
        mut next_header: u8,
        mut offset: usize,
        packet_end: usize,
    ) -> Option<(u8, usize)> {
        for _ in 0..8 {
            match next_header {
                IP_PROTO_TCP | IP_PROTO_UDP => return Some((next_header, offset)),
                IP_PROTO_NO_NEXT => return None,
                IP_PROTO_HOP_BY_HOP | IP_PROTO_ROUTING | IP_PROTO_DEST_OPTS => {
                    let header = frame.get(offset..offset + 2)?;
                    next_header = header[0];
                    let len = (usize::from(header[1]) + 1) * 8;
                    offset = offset.checked_add(len)?;
                }
                IP_PROTO_AH => {
                    let header = frame.get(offset..offset + 2)?;
                    next_header = header[0];
                    let len = (usize::from(header[1]) + 2) * 4;
                    offset = offset.checked_add(len)?;
                }
                IP_PROTO_FRAGMENT => {
                    let header = frame.get(offset..offset + 8)?;
                    next_header = header[0];
                    let fragment = u16::from_be_bytes([header[2], header[3]]);
                    if fragment & 0xfff9 != 0 {
                        return None;
                    }
                    offset = offset.checked_add(8)?;
                }
                _ => return None,
            }
            if offset > packet_end {
                return None;
            }
        }
        None
    }

    fn parse_transport(
        frame: &[u8],
        protocol: u8,
        l4_offset: usize,
        packet_end: usize,
        source: IpAddr,
        destination: IpAddr,
        link: AfXdpLinkMeta,
    ) -> Option<AfXdpL4Packet> {
        match protocol {
            IP_PROTO_TCP => {
                let header = frame.get(l4_offset..l4_offset + TCP_MIN_HEADER_LEN)?;
                let source_port = u16::from_be_bytes([header[0], header[1]]);
                let destination_port = u16::from_be_bytes([header[2], header[3]]);
                let tcp_header_len = usize::from(header[12] >> 4) * 4;
                if tcp_header_len < TCP_MIN_HEADER_LEN || l4_offset + tcp_header_len > packet_end {
                    return None;
                }
                Some(AfXdpL4Packet {
                    protocol: AfXdpTransportProtocol::Tcp,
                    local_addr: SocketAddr::new(destination, destination_port),
                    peer_addr: SocketAddr::new(source, source_port),
                    payload: Bytes::copy_from_slice(&frame[l4_offset + tcp_header_len..packet_end]),
                    link,
                })
            }
            IP_PROTO_UDP => {
                let header = frame.get(l4_offset..l4_offset + UDP_HEADER_LEN)?;
                let source_port = u16::from_be_bytes([header[0], header[1]]);
                let destination_port = u16::from_be_bytes([header[2], header[3]]);
                let udp_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
                if udp_len < UDP_HEADER_LEN || l4_offset + udp_len > packet_end {
                    return None;
                }
                Some(AfXdpL4Packet {
                    protocol: AfXdpTransportProtocol::Udp,
                    local_addr: SocketAddr::new(destination, destination_port),
                    peer_addr: SocketAddr::new(source, source_port),
                    payload: Bytes::copy_from_slice(
                        &frame[l4_offset + UDP_HEADER_LEN..l4_offset + udp_len],
                    ),
                    link,
                })
            }
            _ => None,
        }
    }

    fn tcp_flow_key_from_ip_packet(ip_packet: &[u8]) -> Option<AfXdpTcpFlowKey> {
        let (protocol, l4_offset, packet_end) = ip_transport_bounds(ip_packet)?;
        if protocol != IP_PROTO_TCP || l4_offset + TCP_MIN_HEADER_LEN > packet_end {
            return None;
        }
        let header = ip_packet.get(l4_offset..l4_offset + TCP_MIN_HEADER_LEN)?;
        let source_port = u16::from_be_bytes([header[0], header[1]]);
        let destination_port = u16::from_be_bytes([header[2], header[3]]);
        let (source, destination) = match ip_packet.first()? >> 4 {
            4 => {
                let base = ip_packet.get(..IPV4_MIN_HEADER_LEN)?;
                (
                    IpAddr::V4(Ipv4Addr::new(base[12], base[13], base[14], base[15])),
                    IpAddr::V4(Ipv4Addr::new(base[16], base[17], base[18], base[19])),
                )
            }
            6 => {
                let base = ip_packet.get(..IPV6_HEADER_LEN)?;
                let mut source_octets = [0u8; 16];
                source_octets.copy_from_slice(&base[8..24]);
                let mut destination_octets = [0u8; 16];
                destination_octets.copy_from_slice(&base[24..40]);
                (
                    IpAddr::V6(Ipv6Addr::from(source_octets)),
                    IpAddr::V6(Ipv6Addr::from(destination_octets)),
                )
            }
            _ => return None,
        };
        Some(AfXdpTcpFlowKey {
            local_addr: SocketAddr::new(destination, destination_port),
            peer_addr: SocketAddr::new(source, source_port),
        })
    }

    #[cfg(any(test, target_os = "linux"))]
    pub(super) fn reply_flow_key_from_ip_packet(ip_packet: &[u8]) -> Option<AfXdpTcpFlowKey> {
        let flow = tcp_flow_key_from_ip_packet(ip_packet)?;
        Some(AfXdpTcpFlowKey {
            local_addr: flow.peer_addr,
            peer_addr: flow.local_addr,
        })
    }

    #[cfg(any(test, target_os = "linux"))]
    fn tcp_packet_is_initial_syn(ip_packet: &[u8]) -> bool {
        let Some((protocol, l4_offset, packet_end)) = ip_transport_bounds(ip_packet) else {
            return false;
        };
        if protocol != IP_PROTO_TCP || l4_offset + TCP_MIN_HEADER_LEN > packet_end {
            return false;
        }
        let flags = ip_packet[l4_offset + 13];
        flags & 0x17 == 0x02
    }

    fn ip_transport_bounds(ip_packet: &[u8]) -> Option<(u8, usize, usize)> {
        match ip_packet.first()? >> 4 {
            4 => {
                let base = ip_packet.get(..IPV4_MIN_HEADER_LEN)?;
                let ihl = usize::from(base[0] & 0x0f) * 4;
                if ihl < IPV4_MIN_HEADER_LEN {
                    return None;
                }
                let total_len = usize::from(u16::from_be_bytes([base[2], base[3]]));
                if total_len < ihl || total_len > ip_packet.len() {
                    return None;
                }
                let fragment = u16::from_be_bytes([base[6], base[7]]);
                if fragment & 0x3fff != 0 {
                    return None;
                }
                Some((base[9], ihl, total_len))
            }
            6 => {
                let base = ip_packet.get(..IPV6_HEADER_LEN)?;
                let payload_len = usize::from(u16::from_be_bytes([base[4], base[5]]));
                let packet_end = IPV6_HEADER_LEN.checked_add(payload_len)?;
                if packet_end > ip_packet.len() {
                    return None;
                }
                let (protocol, l4_offset) =
                    ipv6_transport_offset(ip_packet, base[6], IPV6_HEADER_LEN, packet_end)?;
                Some((protocol, l4_offset, packet_end))
            }
            _ => None,
        }
    }

    fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
        Some(u16::from_be_bytes([
            *buf.get(offset)?,
            *buf.get(offset + 1)?,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::kernel::KernelFilterSnapshot;

    fn test_proxy_config(interface: &str) -> XdpConfig {
        XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: interface.to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                ..Default::default()
            }],
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Udp,
                    port: 443,
                }],
                ..Default::default()
            },
            ..XdpConfig::default()
        }
    }

    fn mark_test_proxy_bridge_ready(manager: &std::sync::Arc<XdpManager>) {
        let interface = manager.config.interfaces[0].name.clone();
        let queue = manager.config.interfaces[0].queues[0];
        manager.attached.write().insert(interface.clone());
        *manager.xsk_status.write() = vec![XdpQueueStatus {
            interface,
            queue,
            configured: true,
            socket_created: true,
            registered: true,
            ready: true,
            detail: "AF_XDP ready".to_string(),
            ..Default::default()
        }];
        manager
            .proxy_redirect_enabled
            .store(true, Ordering::Relaxed);
    }

    #[test]
    fn xdp_shadow_rules_prefer_allow_over_block() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            ..XdpConfig::default()
        });
        let now = crate::utils::time::now_timestamp();
        manager.sync_snapshot(&KernelFilterSnapshot {
            blocked_ips: vec![("192.0.2.10".parse().unwrap(), now + 60)],
            allowed_ips: vec![("192.0.2.10".parse().unwrap(), now + 60)],
            ..KernelFilterSnapshot::default()
        });
        assert_eq!(
            manager.rule_verdict_for_ip("192.0.2.10".parse().unwrap()),
            XdpRuleVerdict::Allow
        );
    }

    #[test]
    fn xdp_shadow_rules_match_network_and_range() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            ..XdpConfig::default()
        });
        let now = crate::utils::time::now_timestamp();
        manager.sync_snapshot(&KernelFilterSnapshot {
            blocked_networks: vec![("198.51.100.0/24".parse().unwrap(), now + 60)],
            blocked_ranges: vec![KernelFilterRange {
                from: u32::from_be_bytes([203, 0, 113, 10]) as u128,
                to: u32::from_be_bytes([203, 0, 113, 20]) as u128,
                v6: false,
                expires_at: now + 60,
            }],
            ..KernelFilterSnapshot::default()
        });
        assert_eq!(
            manager.rule_verdict_for_ip("198.51.100.9".parse().unwrap()),
            XdpRuleVerdict::Block
        );
        assert_eq!(
            manager.rule_verdict_for_ip("203.0.113.15".parse().unwrap()),
            XdpRuleVerdict::Block
        );
        assert_eq!(
            manager.rule_verdict_for_ip("203.0.113.30".parse().unwrap()),
            XdpRuleVerdict::Pass
        );
    }

    #[test]
    fn xdp_rule_sweeper_removes_expired_shadow_rules() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            ..XdpConfig::default()
        });
        let now = crate::utils::time::now_timestamp();
        let expired_ip: IpAddr = "192.0.2.1".parse().unwrap();
        let active_ip: IpAddr = "192.0.2.2".parse().unwrap();
        let expired_net: IpNet = "198.51.100.0/24".parse().unwrap();
        let active_net: IpNet = "203.0.113.0/24".parse().unwrap();
        let expired_range = RangeKey {
            from: u32::from_be_bytes([198, 51, 100, 10]) as u128,
            to: u32::from_be_bytes([198, 51, 100, 20]) as u128,
            v6: false,
        };
        let active_range = RangeKey {
            from: u32::from_be_bytes([203, 0, 113, 10]) as u128,
            to: u32::from_be_bytes([203, 0, 113, 20]) as u128,
            v6: false,
        };

        {
            let mut state = manager.state.write();
            state.blocked_ips.insert(expired_ip, now - 1);
            state.blocked_ips.insert(active_ip, now + 60);
            state
                .blocked_networks
                .insert(expired_net.to_string(), (expired_net, now - 1));
            state
                .blocked_networks
                .insert(active_net.to_string(), (active_net, now + 60));
            state.blocked_ranges.insert(expired_range.clone(), now - 1);
            state.blocked_ranges.insert(active_range.clone(), now + 60);
        }

        assert!(manager.sweep_expired_rules());
        {
            let state = manager.state.read();
            assert!(!state.blocked_ips.contains_key(&expired_ip));
            assert!(state.blocked_ips.contains_key(&active_ip));
            assert!(
                !state
                    .blocked_networks
                    .contains_key(&expired_net.to_string())
            );
            assert!(state.blocked_networks.contains_key(&active_net.to_string()));
            assert!(!state.blocked_ranges.contains_key(&expired_range));
            assert!(state.blocked_ranges.contains_key(&active_range));
        }
        assert_eq!(
            manager.rule_verdict_for_ip(active_ip),
            XdpRuleVerdict::Block
        );
        assert!(!manager.sweep_expired_rules());
    }

    #[test]
    fn xdp_rule_sweeper_stop_invalidates_running_generation() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            ..XdpConfig::default()
        });

        assert_eq!(manager.rule_sweeper_generation.load(Ordering::Relaxed), 0);
        assert!(!manager.rule_sweeper_started.swap(true, Ordering::Relaxed));

        manager.stop_rule_sweeper();

        assert_eq!(manager.rule_sweeper_generation.load(Ordering::Relaxed), 1);
        assert!(!manager.rule_sweeper_started.load(Ordering::Relaxed));
        assert!(!manager.rule_sweeper_started.swap(true, Ordering::Relaxed));
    }

    #[test]
    fn xdp_reload_manager_replacement_preserves_active_rules() {
        let _guard = crate::runtime_mode::runtime_config_test_guard();
        let first_config = XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth-old".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Protect,
                ..Default::default()
            }],
            ..XdpConfig::default()
        };
        RuntimeConfig::set_current(RuntimeConfig {
            xdp: first_config,
            ..RuntimeConfig::default()
        });

        let old_manager = replace_manager_from_runtime();
        let now = crate::utils::time::now_timestamp();
        old_manager.sync_snapshot(&KernelFilterSnapshot {
            blocked_ips: vec![("192.0.2.10".parse().unwrap(), now + 60)],
            allowed_networks: vec![("198.51.100.0/24".parse().unwrap(), now + 60)],
            blocked_ranges: vec![KernelFilterRange {
                from: u32::from_be_bytes([203, 0, 113, 10]) as u128,
                to: u32::from_be_bytes([203, 0, 113, 20]) as u128,
                v6: false,
                expires_at: now + 60,
            }],
            ..KernelFilterSnapshot::default()
        });
        let snapshot = old_manager.active_rule_snapshot();

        RuntimeConfig::set_current(RuntimeConfig {
            xdp: XdpConfig {
                enabled: true,
                interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                    name: "eth-new".to_string(),
                    queues: vec![1],
                    mode: XdpRuntimeMode::Proxy,
                    ..Default::default()
                }],
                ..XdpConfig::default()
            },
            ..RuntimeConfig::default()
        });

        let new_manager = replace_manager_from_runtime();
        new_manager.sync_snapshot(&snapshot);

        assert_eq!(new_manager.config.interfaces[0].name, "eth-new");
        assert_eq!(
            new_manager.rule_verdict_for_ip("192.0.2.10".parse().unwrap()),
            XdpRuleVerdict::Block
        );
        assert_eq!(
            new_manager.rule_verdict_for_ip("198.51.100.42".parse().unwrap()),
            XdpRuleVerdict::Allow
        );
        assert_eq!(
            new_manager.rule_verdict_for_ip("203.0.113.15".parse().unwrap()),
            XdpRuleVerdict::Block
        );
    }

    #[test]
    fn xdp_manager_current_identity_changes_after_replacement() {
        let _guard = crate::runtime_mode::runtime_config_test_guard();
        RuntimeConfig::set_current(RuntimeConfig {
            xdp: test_proxy_config("eth-old"),
            ..RuntimeConfig::default()
        });
        let old_manager = replace_manager_from_runtime();
        assert!(manager_is_current(&old_manager));

        RuntimeConfig::set_current(RuntimeConfig {
            xdp: test_proxy_config("eth-new"),
            ..RuntimeConfig::default()
        });
        let new_manager = replace_manager_from_runtime();

        assert!(!manager_is_current(&old_manager));
        assert!(manager_is_current(&new_manager));
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn xdp_proxy_bridge_lifecycle_stops_on_reload_detach_and_degrade() {
        let _guard = crate::runtime_mode::runtime_config_test_guard();
        RuntimeConfig::set_current(RuntimeConfig {
            xdp: test_proxy_config("eth-old"),
            ..RuntimeConfig::default()
        });
        let old_manager = replace_manager_from_runtime();
        mark_test_proxy_bridge_ready(&old_manager);
        assert!(af_xdp::proxy_bridge_should_continue(&old_manager));

        RuntimeConfig::set_current(RuntimeConfig {
            xdp: test_proxy_config("eth-new"),
            ..RuntimeConfig::default()
        });
        let new_manager = replace_manager_from_runtime();
        mark_test_proxy_bridge_ready(&new_manager);

        assert!(!af_xdp::proxy_bridge_should_continue(&old_manager));
        assert!(af_xdp::proxy_bridge_should_continue(&new_manager));

        new_manager
            .mark_proxy_dataplane_degraded("test forced degraded");
        assert!(!af_xdp::proxy_bridge_should_continue(&new_manager));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn apply_rule_diff_adds_removes_only_deltas() {
        use std::net::IpAddr;

        let old_state = RuleState {
            blocked_ips: [
                ("192.0.2.1".parse::<IpAddr>().unwrap(), 9999),
                ("192.0.2.2".parse::<IpAddr>().unwrap(), 9999),
            ]
            .into_iter()
            .collect(),
            allowed_ips: [("198.51.100.1".parse::<IpAddr>().unwrap(), 9999)]
                .into_iter()
                .collect(),
            blocked_networks: [
                (
                    "203.0.113.0/24".to_string(),
                    (
                        "203.0.113.0/24".parse::<IpNet>().unwrap(),
                        9999,
                    ),
                ),
            ]
            .into_iter()
            .collect(),
            allowed_networks: Default::default(),
            blocked_ranges: Default::default(),
            allowed_ranges: Default::default(),
        };

        let new_state = RuleState {
            blocked_ips: [
                ("192.0.2.2".parse::<IpAddr>().unwrap(), 9999), // kept
                ("192.0.2.3".parse::<IpAddr>().unwrap(), 9999), // added
            ]
            .into_iter()
            .collect(),
            allowed_ips: [
                ("198.51.100.1".parse::<IpAddr>().unwrap(), 9999), // kept
                ("198.51.100.2".parse::<IpAddr>().unwrap(), 9999), // added
            ]
            .into_iter()
            .collect(),
            blocked_networks: Default::default(), // entire network removed
            allowed_networks: [
                (
                    "2001:db8::/32".to_string(),
                    (
                        "2001:db8::/32".parse::<IpNet>().unwrap(),
                        9999,
                    ),
                ),
            ]
            .into_iter()
            .collect(),
            blocked_ranges: Default::default(),
            allowed_ranges: Default::default(),
        };

        let old_img = rule_map_images(&old_state);
        let new_img = rule_map_images(&new_state);

        // Exact v4 blocked: 192.0.2.1 removed, 192.0.2.3 added, 192.0.2.2 kept (no-op)
        assert!(old_img.blocked_v4.contains_key(&u32::from_be_bytes([192, 0, 2, 1])));
        assert!(old_img.blocked_v4.contains_key(&u32::from_be_bytes([192, 0, 2, 2])));
        assert!(!old_img.blocked_v4.contains_key(&u32::from_be_bytes([192, 0, 2, 3])));

        assert!(!new_img.blocked_v4.contains_key(&u32::from_be_bytes([192, 0, 2, 1])));
        assert!(new_img.blocked_v4.contains_key(&u32::from_be_bytes([192, 0, 2, 2])));
        assert!(new_img.blocked_v4.contains_key(&u32::from_be_bytes([192, 0, 2, 3])));

        // Exact v4 allowed: 198.51.100.2 added, 198.51.100.1 kept
        assert!(old_img.allowed_v4.contains_key(&u32::from_be_bytes([198, 51, 100, 1])));
        assert!(!old_img.allowed_v4.contains_key(&u32::from_be_bytes([198, 51, 100, 2])));

        assert!(new_img.allowed_v4.contains_key(&u32::from_be_bytes([198, 51, 100, 1])));
        assert!(new_img.allowed_v4.contains_key(&u32::from_be_bytes([198, 51, 100, 2])));

        // LPM v4 blocked: 203.0.113.0/24 removed
        assert!(!old_img.blocked_lpm_v4.is_empty());
        assert!(new_img.blocked_lpm_v4.is_empty());

        // LPM v6 allowed: 2001:db8::/32 added
        assert!(old_img.allowed_lpm_v6.is_empty());
        assert!(!new_img.allowed_lpm_v6.is_empty());
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn xdp_proxy_bridge_lifecycle_continues_only_when_ready() {
        let _guard = crate::runtime_mode::runtime_config_test_guard();
        RuntimeConfig::set_current(RuntimeConfig {
            xdp: test_proxy_config("eth-new"),
            ..RuntimeConfig::default()
        });
        let new_manager = replace_manager_from_runtime();
        mark_test_proxy_bridge_ready(&new_manager);
        assert!(af_xdp::proxy_bridge_should_continue(&new_manager));

        new_manager.attached.write().clear();
        new_manager
            .proxy_redirect_enabled
            .store(false, Ordering::Relaxed);
        assert!(!af_xdp::proxy_bridge_should_continue(&new_manager));

        mark_test_proxy_bridge_ready(&new_manager);
        assert!(af_xdp::proxy_bridge_should_continue(&new_manager));
        new_manager.mark_proxy_dataplane_degraded(
            "AF_XDP proxy bridge poll failed repeatedly; proxy redirect disabled, traffic will PASS",
        );
        assert!(!af_xdp::proxy_bridge_should_continue(&new_manager));
    }

    #[test]
    fn xdp_rule_value_monotonic_deadline_controls_active_match() {
        let legacy = cloud_node_xdp_common::XdpRuleValue::new(
            10,
            0,
            cloud_node_xdp_common::XdpRuleValue::FLAG_BLOCK,
        );
        assert!(legacy.is_active_at_mono(u64::MAX));

        let active = cloud_node_xdp_common::XdpRuleValue::with_monotonic_deadline(
            10,
            1_000,
            0,
            cloud_node_xdp_common::XdpRuleValue::FLAG_BLOCK,
        );
        assert!(active.is_active_at_mono(999));
        assert!(!active.is_active_at_mono(1_000));
    }

    #[test]
    fn xdp_range_to_nets_covers_only_requested_span() {
        let range = RangeKey {
            from: u32::from_be_bytes([203, 0, 113, 10]) as u128,
            to: u32::from_be_bytes([203, 0, 113, 20]) as u128,
            v6: false,
        };
        let nets = range_to_nets(&range);
        assert!(!nets.is_empty());
        for last_octet in 10..=20 {
            let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet));
            assert!(nets.iter().any(|net| net.contains(&ip)));
        }
        assert!(
            !nets
                .iter()
                .any(|net| net.contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))))
        );
        assert!(
            !nets
                .iter()
                .any(|net| net.contains(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21))))
        );
    }

    #[test]
    fn doctor_reports_missing_interface_when_enabled() {
        let report = doctor_report_for_config(&XdpConfig {
            enabled: true,
            ..XdpConfig::default()
        });
        assert!(report.contains("interfaces is empty"));
    }

    #[test]
    fn xdp_doctor_warns_proxy_without_ports() {
        let report = doctor_report_for_config(&XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0, 1],
                mode: XdpRuntimeMode::Proxy,
                ..Default::default()
            }],
            ..XdpConfig::default()
        });
        assert!(report.contains("proxy mode has no xdp.proxy.ports entries"));
    }

    #[test]
    fn xdp_doctor_warns_proxy_without_local_ips() {
        let report = doctor_report_for_config(&XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                ..Default::default()
            }],
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Udp,
                    port: 443,
                }],
                ..Default::default()
            },
            ..XdpConfig::default()
        });

        assert!(report.contains("proxy mode has no localIps"));
    }

    #[test]
    fn xdp_doctor_rejects_proxy_jumbo_frame_size() {
        let report = doctor_report_for_config(&XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                frame_size: 4096,
                ..Default::default()
            }],
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Udp,
                    port: 443,
                }],
                ..Default::default()
            },
            ..XdpConfig::default()
        });

        assert!(report.contains("requires standard-MTU frameSize<=2048"));
    }

    #[tokio::test]
    async fn xdp_initialize_fallbacks_proxy_jumbo_frame_size() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                frame_size: 4096,
                ..Default::default()
            }],
            ..XdpConfig::default()
        });

        manager
            .initialize()
            .await
            .expect("fallback mode should not fail start");
        let status = manager.status();
        assert!(!status.available);
        assert!(!status.attached);
        assert!(status.fallback_reason.contains("frameSize<=2048"));
    }

    #[tokio::test]
    async fn xdp_initialize_fail_start_rejects_proxy_jumbo_frame_size() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            fallback: crate::runtime_mode::XdpFallbackMode::FailStart,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                frame_size: 4096,
                ..Default::default()
            }],
            ..XdpConfig::default()
        });

        let err = manager
            .initialize()
            .await
            .expect_err("fail-start must reject");
        assert!(err.to_string().contains("frameSize<=2048"));
    }

    #[test]
    fn xdp_protocol_mapping_uses_l4_protocol_numbers() {
        assert_eq!(
            xdp_ip_proto(&XdpProxyProtocol::Https),
            cloud_node_xdp_common::XDP_PROTO_TCP
        );
        assert_eq!(
            xdp_ip_proto(&XdpProxyProtocol::H3),
            cloud_node_xdp_common::XDP_PROTO_UDP
        );
    }

    #[test]
    fn xdp_dataplane_supports_tcp_udp_and_h3_proxy_protocols() {
        assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Http));
        assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Https));
        assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Tcp));
        assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Udp));
        assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::H3));
    }

    #[test]
    fn xdp_tcp_dataplane_is_supported_without_diagnostic_gate() {
        assert!(xdp_tcp_dataplane_supported());
        assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Http));
        assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Https));
        assert!(xdp_protocol_dataplane_supported(&XdpProxyProtocol::Tcp));
    }

    #[test]
    fn xdp_status_reports_tcp_ports_supported_but_not_ready_without_xsk() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                local_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
                ..Default::default()
            }],
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Tcp,
                    port: 8443,
                }],
                ..Default::default()
            },
            ..XdpConfig::default()
        });

        let status = manager.status();
        assert!(!status.tcp_dataplane_ready);
        assert!(status.tcp_dataplane_detail.is_empty());
        assert_eq!(status.proxy_ports, 1);
        assert_eq!(status.proxy_supported_ports, 1);
        assert_eq!(status.proxy_unsupported_ports, 0);
    }

    #[test]
    fn xdp_doctor_reports_tcp_ports_as_supported() {
        let report = doctor_report_for_config(&XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                local_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
                ..Default::default()
            }],
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Https,
                    port: 443,
                }],
                ..Default::default()
            },
            ..XdpConfig::default()
        });

        assert!(report.contains("dataplane:     AF_XDP proxy ports supported=1 total=1"));
        assert!(!report.contains("warning:"));
    }

    #[test]
    fn xdp_dump_maps_exposes_tcp_dataplane_support() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Tcp,
                    port: 8443,
                }],
                ..Default::default()
            },
            ..XdpConfig::default()
        });

        let maps = manager.dump_maps();
        assert_eq!(maps["tcpDataplane"]["ready"], true);
        assert_eq!(
            maps["tcpDataplane"]["detail"].as_str().unwrap_or_default(),
            ""
        );
    }

    #[test]
    fn xdp_dump_maps_exposes_local_ip_filter_state() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                local_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
                ..Default::default()
            }],
            ..XdpConfig::default()
        });

        let maps = manager.dump_maps();
        assert_eq!(maps["interfaces"][0]["name"], "eth0");
        assert_eq!(maps["interfaces"][0]["localIpFilter"], true);
        assert_eq!(maps["interfaces"][0]["localIps"][0], "198.51.100.5");
    }

    #[test]
    fn xdp_partial_proxy_detail_is_empty_for_supported_protocols() {
        let config = XdpConfig {
            enabled: true,
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![
                    crate::runtime_mode::XdpProxyPortConfig {
                        protocol: XdpProxyProtocol::Https,
                        port: 443,
                    },
                    crate::runtime_mode::XdpProxyPortConfig {
                        protocol: XdpProxyProtocol::Tcp,
                        port: 8443,
                    },
                    crate::runtime_mode::XdpProxyPortConfig {
                        protocol: XdpProxyProtocol::Udp,
                        port: 443,
                    },
                ],
                ..Default::default()
            },
            ..XdpConfig::default()
        };

        assert_eq!(xdp_supported_proxy_port_count(&config), 3);
        assert!(xdp_unsupported_proxy_protocols(&config).is_empty());
        assert!(xdp_proxy_partial_detail(&config).is_empty());

        let manager = XdpManager::new(config);
        let status = manager.status();
        assert_eq!(status.proxy_ports, 3);
        assert_eq!(status.proxy_supported_ports, 3);
        assert_eq!(status.proxy_unsupported_ports, 0);
    }

    #[test]
    fn xdp_proxy_port_status_counts_dataplane_support() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![
                    crate::runtime_mode::XdpProxyPortConfig {
                        protocol: XdpProxyProtocol::Https,
                        port: 443,
                    },
                    crate::runtime_mode::XdpProxyPortConfig {
                        protocol: XdpProxyProtocol::Udp,
                        port: 443,
                    },
                ],
                ..Default::default()
            },
            ..XdpConfig::default()
        });

        let ports = manager
            .config
            .proxy
            .ports
            .iter()
            .map(|port| {
                serde_json::json!({
                    "protocol": port.protocol.as_str(),
                    "port": port.port,
                    "dataplaneSupported": xdp_protocol_dataplane_supported(&port.protocol),
                })
            })
            .collect::<Vec<_>>();

        assert_eq!(ports[0]["dataplaneSupported"], true);
        assert_eq!(ports[1]["dataplaneSupported"], true);
        let status = manager.status();
        assert_eq!(status.proxy_supported_ports, 2);
        assert_eq!(status.proxy_unsupported_ports, 0);
    }

    #[test]
    fn xdp_proxy_port_key_uses_network_order_bytes() {
        let key = cloud_node_xdp_common::XdpPortProtoKey {
            port_be: 443u16.to_be(),
            proto: cloud_node_xdp_common::XDP_PROTO_TCP,
            _pad: 0,
        };

        assert_eq!(key.port_be.to_ne_bytes(), 443u16.to_be_bytes());
    }

    #[test]
    fn xdp_local_ip_keys_are_interface_scoped_and_network_ordered() {
        let v4 = cloud_node_xdp_common::host::local_ipv4_key(7, Ipv4Addr::new(198, 51, 100, 5));
        let v6 = cloud_node_xdp_common::host::local_ipv6_key(
            9,
            "2001:db8::443".parse::<Ipv6Addr>().unwrap(),
        );

        assert_eq!(v4.ifindex, 7);
        assert_eq!(v4.addr_be.to_be_bytes(), [198, 51, 100, 5]);
        assert_eq!(v6.ifindex, 9);
        assert_eq!(
            v6.addr,
            "2001:db8::443".parse::<Ipv6Addr>().unwrap().octets()
        );
    }

    #[test]
    fn xdp_status_reports_configured_proxy_queues() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0, 1],
                mode: XdpRuntimeMode::Proxy,
                ..Default::default()
            }],
            ..XdpConfig::default()
        });

        let status = manager.status();
        assert_eq!(status.xsk_configured_queues, 2);
        assert_eq!(status.xsk_ready_queues, 0);
        assert!(!status.proxy_ready);
        assert_eq!(status.interfaces[0].xsk_queues.len(), 2);
    }

    #[test]
    fn xdp_proxy_ready_requires_explicit_redirect_enable_after_xsk_registration() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                ..Default::default()
            }],
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Udp,
                    port: 443,
                }],
                ..Default::default()
            },
            ..XdpConfig::default()
        });
        manager.attached.write().insert("eth0".to_string());
        *manager.xsk_status.write() = vec![XdpQueueStatus {
            interface: "eth0".to_string(),
            queue: 0,
            configured: true,
            socket_created: true,
            registered: true,
            ready: true,
            detail: "AF_XDP socket registered".to_string(),
            ..Default::default()
        }];

        let status = manager.status();
        assert!(status.interfaces[0].xsk_ready);
        assert!(!status.proxy_ready);
        assert!(!status.proxy_redirect_enabled);
        assert!(
            status.interfaces[0]
                .detail
                .contains("redirect disabled until proxy bridge starts")
        );

        manager
            .proxy_redirect_enabled
            .store(true, Ordering::Relaxed);
        let status = manager.status();
        assert!(status.proxy_ready);
        assert!(status.proxy_redirect_enabled);
    }

    #[test]
    fn xdp_proxy_degradation_disables_ready_queues() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                ..Default::default()
            }],
            proxy: crate::runtime_mode::XdpProxyConfig {
                ports: vec![crate::runtime_mode::XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Udp,
                    port: 443,
                }],
                ..Default::default()
            },
            ..XdpConfig::default()
        });
        *manager.xsk_status.write() = vec![
            XdpQueueStatus {
                interface: "eth0".to_string(),
                queue: 0,
                configured: true,
                socket_created: true,
                registered: true,
                ready: true,
                detail: "AF_XDP ready".to_string(),
                ..Default::default()
            },
            XdpQueueStatus {
                interface: "eth0".to_string(),
                queue: 1,
                configured: true,
                detail: "AF_XDP socket setup failed".to_string(),
                ..Default::default()
            },
        ];

        manager
            .proxy_redirect_enabled
            .store(true, Ordering::Relaxed);
        assert!(manager.proxy_redirect_ready());
        manager.mark_proxy_dataplane_degraded(
            "AF_XDP proxy bridge poll failed repeatedly; proxy redirect disabled, traffic will PASS",
        );

        let status = manager.status();
        assert!(!manager.proxy_redirect_ready());
        assert!(!status.proxy_ready);
        assert_eq!(status.xsk_ready_queues, 0);
        assert!(status.proxy_fallback_reason.contains("redirect disabled"));
        assert!(
            status.interfaces[0].xsk_queues[0]
                .detail
                .contains("redirect disabled")
        );
        assert_eq!(
            status.interfaces[0].xsk_queues[1].detail,
            "AF_XDP socket setup failed"
        );
        assert!(
            status.interfaces[0]
                .xsk_queues
                .iter()
                .all(|queue| !queue.registered && !queue.ready)
        );
    }

    #[test]
    fn xdp_map_sync_failure_status_is_fail_open() {
        let manager = XdpManager::new(XdpConfig {
            enabled: true,
            interfaces: vec![crate::runtime_mode::XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0],
                mode: XdpRuntimeMode::Proxy,
                ..Default::default()
            }],
            ..XdpConfig::default()
        });

        manager.attached.write().insert("eth0".to_string());
        manager
            .proxy_redirect_enabled
            .store(true, Ordering::Relaxed);
        *manager.xsk_status.write() = vec![XdpQueueStatus {
            interface: "eth0".to_string(),
            queue: 0,
            configured: true,
            socket_created: true,
            registered: true,
            ready: true,
            detail: "ready".to_string(),
            ..Default::default()
        }];
        manager.set_fallback_reason("map sync failed: injected");
        manager.attached.write().clear();
        manager.xsk_status.write().clear();
        manager
            .proxy_redirect_enabled
            .store(false, Ordering::Relaxed);
        manager.set_proxy_fallback_reason("runtime failure detached XDP; socket path is active");

        let status = manager.status();
        assert!(!status.available);
        assert!(!status.attached);
        assert!(!status.proxy_redirect_enabled);
        assert_eq!(status.xsk_ready_queues, 0);
        assert!(status.fallback_reason.contains("map sync failed"));
        assert!(
            status
                .proxy_fallback_reason
                .contains("socket path is active")
        );
    }

    #[test]
    fn af_xdp_parser_extracts_ipv4_udp_datagram() {
        let frame = ipv4_udp_frame(false, 0, b"hello");
        let packet = af_xdp::parse_l4_packet(&frame).expect("valid UDP frame");

        assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Udp);
        assert_eq!(packet.peer_addr, "192.0.2.10:53000".parse().unwrap());
        assert_eq!(packet.local_addr, "198.51.100.5:443".parse().unwrap());
        assert_eq!(&packet.payload[..], b"hello");
        assert_eq!(packet.link.destination_mac, [0x02, 0, 0, 0, 0, 1]);
        assert_eq!(packet.link.source_mac, [0x02, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn af_xdp_proxy_frame_classifies_udp_with_route_meta() {
        let frame = ipv4_udp_frame(false, 0, b"hello");
        let proxy_frame =
            af_xdp::parse_proxy_frame("eth0", 3, &frame).expect("valid UDP proxy frame");

        let af_xdp::AfXdpProxyFrame::Udp { route, packet } = proxy_frame else {
            panic!("expected UDP proxy frame");
        };
        assert_eq!(route.interface, "eth0");
        assert_eq!(route.queue, 3);
        assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Udp);
        assert_eq!(packet.peer_addr, "192.0.2.10:53000".parse().unwrap());
        assert_eq!(packet.local_addr, "198.51.100.5:443".parse().unwrap());
        assert_eq!(&packet.payload[..], b"hello");
    }

    #[test]
    fn af_xdp_proxy_frame_classifies_tcp_and_preserves_ip_packet() {
        let frame = ipv4_tcp_frame(true, b"GET / HTTP/1.1\r\n\r\n");
        let proxy_frame =
            af_xdp::parse_proxy_frame("eth1", 7, &frame).expect("valid TCP proxy frame");

        let af_xdp::AfXdpProxyFrame::Tcp {
            route,
            flow,
            ip_packet,
        } = proxy_frame
        else {
            panic!("expected TCP proxy frame");
        };
        assert_eq!(route.interface, "eth1");
        assert_eq!(route.queue, 7);
        assert_eq!(route.link.vlan_tag_count, 1);
        assert_eq!(flow.peer_addr, "192.0.2.10:53000".parse().unwrap());
        assert_eq!(flow.local_addr, "198.51.100.5:443".parse().unwrap());
        assert_eq!(ip_packet[0] >> 4, 4);
        assert_eq!(
            usize::from(u16::from_be_bytes([ip_packet[2], ip_packet[3]])),
            ip_packet.len()
        );
        assert_eq!(
            &ip_packet[ip_packet.len() - 18..],
            b"GET / HTTP/1.1\r\n\r\n"
        );
    }

    #[test]
    fn af_xdp_proxy_frame_classifies_ipv6_tcp_with_destination_options() {
        let payload = b"hello";
        let mut frame = ethernet_header(0x86dd, false);
        let payload_len = 8 + 20 + payload.len();
        frame.extend_from_slice(&[
            0x60,
            0,
            0,
            0,
            (payload_len >> 8) as u8,
            payload_len as u8,
            60,
            64,
        ]);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        frame.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        frame.extend_from_slice(&[
            0xcf, 0x08, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0x40, 0, 0, 0, 0, 0,
        ]);
        frame.extend_from_slice(payload);

        let proxy_frame =
            af_xdp::parse_proxy_frame("eth0", 2, &frame).expect("valid IPv6 TCP proxy frame");

        let af_xdp::AfXdpProxyFrame::Tcp {
            route,
            flow,
            ip_packet,
        } = proxy_frame
        else {
            panic!("expected TCP proxy frame");
        };
        assert_eq!(route.interface, "eth0");
        assert_eq!(route.queue, 2);
        assert_eq!(flow.peer_addr, "[2001:db8::1]:53000".parse().unwrap());
        assert_eq!(flow.local_addr, "[2001:db8::2]:443".parse().unwrap());
        assert_eq!(ip_packet[0] >> 4, 6);
        assert_eq!(&ip_packet[ip_packet.len() - payload.len()..], payload);
    }

    #[test]
    fn af_xdp_reply_flow_key_maps_reply_packet_to_original_flow() {
        let ip_packet = ipv4_tcp_reply_ip_packet();
        let flow = af_xdp::reply_flow_key_from_ip_packet(&ip_packet).expect("valid TCP reply flow");

        assert_eq!(flow.local_addr, "198.51.100.5:443".parse().unwrap());
        assert_eq!(flow.peer_addr, "192.0.2.10:53000".parse().unwrap());
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_tcp_reactor_answers_syn_with_syn_ack() {
        let frame = ipv4_tcp_syn_frame(false);
        let af_xdp::AfXdpProxyFrame::Tcp {
            route,
            flow,
            ip_packet,
        } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP SYN frame")
        else {
            panic!("expected TCP proxy frame");
        };
        let mut reactor =
            af_xdp::AfXdpTcpReactor::new_with_session_limit_for_test(None, None, 1024);

        assert_eq!(
            reactor.ingest(route.clone(), flow, ip_packet),
            af_xdp::AfXdpTcpIngestStatus::Accepted
        );
        let egress = reactor.poll();

        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0].0, route);
        let reply = &egress[0].1;
        assert_eq!(reply[0] >> 4, 4);
        assert_eq!(reply[9], cloud_node_xdp_common::XDP_PROTO_TCP);
        assert_eq!(&reply[12..16], &[198, 51, 100, 5]);
        assert_eq!(&reply[16..20], &[192, 0, 2, 10]);
        let tcp_offset = 20;
        assert_eq!(
            u16::from_be_bytes([reply[tcp_offset], reply[tcp_offset + 1]]),
            443
        );
        assert_eq!(
            u16::from_be_bytes([reply[tcp_offset + 2], reply[tcp_offset + 3]]),
            53000
        );
        assert_eq!(reply[tcp_offset + 13] & 0x12, 0x12);
        assert!(reactor.encode_egress_frame(&route, reply).is_some());
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_tcp_reactor_ignores_unknown_non_syn_flow() {
        let frame = ipv4_tcp_frame(false, b"GET / HTTP/1.1\r\n\r\n");
        let af_xdp::AfXdpProxyFrame::Tcp {
            route,
            flow,
            ip_packet,
        } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP frame")
        else {
            panic!("expected TCP proxy frame");
        };
        let mut reactor = af_xdp::AfXdpTcpReactor::new(None, None);

        assert_eq!(
            reactor.ingest(route, flow, ip_packet),
            af_xdp::AfXdpTcpIngestStatus::IgnoredUnknownFlow
        );

        assert!(reactor.poll().is_empty());
        assert_eq!(reactor.session_count(), 0);
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_tcp_reactor_refuses_new_sessions_at_limit() {
        let first_frame = ipv4_tcp_syn_frame_with_source_port(false, 53000);
        let second_frame = ipv4_tcp_syn_frame_with_source_port(false, 53001);
        let af_xdp::AfXdpProxyFrame::Tcp {
            route: first_route,
            flow: first_flow,
            ip_packet: first_packet,
        } = af_xdp::parse_proxy_frame("eth0", 0, &first_frame).expect("valid first TCP SYN frame")
        else {
            panic!("expected first TCP proxy frame");
        };
        let af_xdp::AfXdpProxyFrame::Tcp {
            route: second_route,
            flow: second_flow,
            ip_packet: second_packet,
        } = af_xdp::parse_proxy_frame("eth0", 0, &second_frame)
            .expect("valid second TCP SYN frame")
        else {
            panic!("expected second TCP proxy frame");
        };
        assert_ne!(first_flow, second_flow);

        let mut reactor = af_xdp::AfXdpTcpReactor::new_with_session_limit_for_test(None, None, 1);

        assert_eq!(
            reactor.ingest(first_route.clone(), first_flow, first_packet),
            af_xdp::AfXdpTcpIngestStatus::Accepted
        );
        let first_egress = reactor.poll();
        assert_eq!(
            reactor.ingest(second_route, second_flow, second_packet),
            af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity
        );
        let second_egress = reactor.poll();

        assert_eq!(reactor.session_count(), 1);
        assert_eq!(first_egress.len(), 1);
        assert_eq!(first_egress[0].0, first_route);
        assert!(second_egress.is_empty());
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_tcp_reactor_reaps_idle_sessions() {
        let frame = ipv4_tcp_syn_frame(false);
        let af_xdp::AfXdpProxyFrame::Tcp {
            route,
            flow,
            ip_packet,
        } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP SYN frame")
        else {
            panic!("expected TCP proxy frame");
        };
        let mut reactor = af_xdp::AfXdpTcpReactor::new(None, None);

        assert_eq!(
            reactor.ingest(route, flow, ip_packet),
            af_xdp::AfXdpTcpIngestStatus::Accepted
        );
        assert_eq!(reactor.session_count(), 1);

        let reap_at = smoltcp::time::Instant::from_millis(
            crate::utils::time::now_timestamp_millis()
                + af_xdp::AF_XDP_TCP_SESSION_IDLE_TIMEOUT.as_millis() as i64
                + 1,
        );
        let _ = reactor.poll_at_for_test(reap_at);

        assert_eq!(reactor.session_count(), 0);
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_tcp_reactor_reaps_closing_time_wait_sessions() {
        assert!(af_xdp::af_xdp_tcp_session_reapable(
            true,
            smoltcp::socket::tcp::State::TimeWait
        ));
        assert!(af_xdp::af_xdp_tcp_session_reapable(
            true,
            smoltcp::socket::tcp::State::Closed
        ));
        assert!(!af_xdp::af_xdp_tcp_session_reapable(
            false,
            smoltcp::socket::tcp::State::TimeWait
        ));
        assert!(!af_xdp::af_xdp_tcp_session_reapable(
            true,
            smoltcp::socket::tcp::State::Established
        ));
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_tcp_reactor_resolves_egress_route_before_reaping_session() {
        let frame = ipv4_tcp_syn_frame(false);
        let af_xdp::AfXdpProxyFrame::Tcp {
            route,
            flow,
            ip_packet,
        } = af_xdp::parse_proxy_frame("eth0", 0, &frame).expect("valid TCP SYN frame")
        else {
            panic!("expected TCP proxy frame");
        };
        let mut reactor =
            af_xdp::AfXdpTcpReactor::new_with_session_limit_for_test(None, None, 1024);
        assert_eq!(
            reactor.ingest(route.clone(), flow, ip_packet),
            af_xdp::AfXdpTcpIngestStatus::Accepted
        );
        let _ = reactor.poll();

        let reply_packet = ipv4_tcp_reply_ip_packet();
        reactor.close_session_and_push_routeless_egress_for_test(flow, reply_packet.clone());

        let egress = reactor.poll();

        assert!(
            egress
                .iter()
                .any(|(egress_route, ip_packet)| *egress_route == route
                    && *ip_packet == reply_packet)
        );
        assert_eq!(reactor.session_count(), 0);
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_tcp_reactor_keeps_stream_read_side_open_during_half_close() {
        assert!(!af_xdp::af_xdp_tcp_stream_read_side_closed(
            smoltcp::socket::tcp::State::SynReceived
        ));
        assert!(!af_xdp::af_xdp_tcp_stream_read_side_closed(
            smoltcp::socket::tcp::State::Established
        ));
        assert!(!af_xdp::af_xdp_tcp_stream_read_side_closed(
            smoltcp::socket::tcp::State::CloseWait
        ));
        assert!(af_xdp::af_xdp_tcp_stream_read_side_closed(
            smoltcp::socket::tcp::State::LastAck
        ));
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_tcp_admission_failure_tracker_requires_consecutive_refusals() {
        let mut tracker = af_xdp::AfXdpTcpAdmissionFailureTracker::new(2);

        assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::IgnoredUnknownFlow));
        assert_eq!(tracker.consecutive_refusals(), 0);
        assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity));
        assert_eq!(tracker.consecutive_refusals(), 1);
        assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::Accepted));
        assert_eq!(tracker.consecutive_refusals(), 0);
        assert!(!tracker.record(af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity));
        assert!(tracker.record(af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity));

        let mut immediate = af_xdp::AfXdpTcpAdmissionFailureTracker::new(0);
        assert!(immediate.record(af_xdp::AfXdpTcpIngestStatus::RefusedAtCapacity));
    }

    #[cfg(any(test, target_os = "linux"))]
    #[test]
    fn af_xdp_proxy_bridge_idles_only_when_no_work_remains() {
        assert!(af_xdp::proxy_bridge_should_idle(0, 0, 0, 0, false));
        assert!(!af_xdp::proxy_bridge_should_idle(1, 0, 0, 0, false));
        assert!(!af_xdp::proxy_bridge_should_idle(0, 1, 0, 0, false));
        assert!(!af_xdp::proxy_bridge_should_idle(0, 0, 1, 0, false));
        assert!(!af_xdp::proxy_bridge_should_idle(0, 0, 0, 1, false));
        assert!(!af_xdp::proxy_bridge_should_idle(0, 0, 0, 0, true));
    }

    #[test]
    fn af_xdp_udp_packet_converts_to_datagram_only_for_udp() {
        let udp = af_xdp::AfXdpL4Packet {
            protocol: af_xdp::AfXdpTransportProtocol::Udp,
            local_addr: "127.0.0.1:443".parse().unwrap(),
            peer_addr: "127.0.0.1:53000".parse().unwrap(),
            payload: bytes::Bytes::from_static(b"hello"),
            link: test_link_meta(false),
        };
        assert!(udp.into_udp_datagram().is_some());

        let tcp = af_xdp::AfXdpL4Packet {
            protocol: af_xdp::AfXdpTransportProtocol::Tcp,
            local_addr: "127.0.0.1:443".parse().unwrap(),
            peer_addr: "127.0.0.1:53000".parse().unwrap(),
            payload: bytes::Bytes::from_static(b"hello"),
            link: test_link_meta(false),
        };
        assert!(tcp.into_udp_datagram().is_none());
    }

    #[test]
    fn af_xdp_udp_route_cache_expires_and_evicts_oldest_without_clearing_all() {
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use std::time::Duration;

        let mut routes = HashMap::new();
        for idx in 0..4u16 {
            let local = SocketAddr::from(([198, 51, 100, 5], 443));
            let peer = SocketAddr::from(([192, 0, 2, 10], 53000 + idx));
            routes.insert(
                (local, peer),
                af_xdp::AfXdpUdpRouteEntry {
                    route: af_xdp::AfXdpRouteMeta {
                        interface: "eth0".to_string(),
                        queue: u32::from(idx),
                        link: test_link_meta(false),
                    },
                    last_seen_ms: u64::from(idx) * 10,
                },
            );
        }

        af_xdp::compact_udp_route_cache(&mut routes, 115, Duration::from_millis(100), 8, 2);

        assert_eq!(routes.len(), 2);
        assert!(routes.keys().all(|(_, peer)| peer.port() >= 53002));

        af_xdp::compact_udp_route_cache(&mut routes, 116, Duration::from_millis(1_000), 2, 1);

        assert_eq!(routes.len(), 1);
        assert!(routes.keys().all(|(_, peer)| peer.port() == 53003));
        assert_eq!(routes.values().next().unwrap().route.queue, 3);
    }

    #[test]
    fn af_xdp_udp_route_cache_sweep_uses_saturating_interval() {
        use std::time::Duration;

        assert!(!af_xdp::udp_route_cache_sweep_due(
            1_000,
            900,
            Duration::from_millis(101)
        ));
        assert!(af_xdp::udp_route_cache_sweep_due(
            1_000,
            900,
            Duration::from_millis(100)
        ));
        assert!(!af_xdp::udp_route_cache_sweep_due(
            100,
            1_000,
            Duration::from_millis(100)
        ));
    }

    #[test]
    fn af_xdp_tx_failure_tracker_requires_consecutive_failures() {
        let mut tracker = af_xdp::AfXdpTxFailureTracker::new(3);

        assert!(!tracker.record(af_xdp::AfXdpTxStatus::Backpressured));
        assert_eq!(tracker.consecutive_failures(), 1);
        assert!(!tracker.record(af_xdp::AfXdpTxStatus::Failed));
        assert_eq!(tracker.consecutive_failures(), 2);
        assert!(!tracker.record(af_xdp::AfXdpTxStatus::Sent));
        assert_eq!(tracker.consecutive_failures(), 0);
        assert!(!tracker.record(af_xdp::AfXdpTxStatus::Failed));
        assert!(!tracker.record(af_xdp::AfXdpTxStatus::Backpressured));
        assert!(tracker.record(af_xdp::AfXdpTxStatus::Failed));
        assert_eq!(tracker.consecutive_failures(), 3);

        let mut immediate = af_xdp::AfXdpTxFailureTracker::new(0);
        assert!(immediate.record(af_xdp::AfXdpTxStatus::Failed));
    }

    #[test]
    fn af_xdp_udp_ingress_failure_tracker_resets_after_delivery() {
        let mut tracker = af_xdp::AfXdpTxFailureTracker::new(2);

        assert!(!tracker.record(af_xdp::AfXdpTxStatus::Backpressured));
        assert!(!tracker.record(af_xdp::AfXdpTxStatus::Sent));
        assert_eq!(tracker.consecutive_failures(), 0);
        assert!(!tracker.record(af_xdp::AfXdpTxStatus::Failed));
        assert!(tracker.record(af_xdp::AfXdpTxStatus::Backpressured));
    }

    #[tokio::test]
    async fn af_xdp_tcp_stream_bridges_bounded_channels() {
        use bytes::Bytes;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let af_xdp::AfXdpTcpStreamParts {
            mut stream,
            ingress_tx,
            mut egress_rx,
        } = af_xdp::AfXdpTcpStream::channel_pair(1);

        ingress_tx.send(Bytes::from_static(b"hello")).await.unwrap();
        let mut read = [0u8; 3];
        stream.read_exact(&mut read).await.unwrap();
        assert_eq!(&read, b"hel");

        let mut read = [0u8; 2];
        stream.read_exact(&mut read).await.unwrap();
        assert_eq!(&read, b"lo");

        stream.write_all(b"world").await.unwrap();
        assert_eq!(
            egress_rx.recv().await.unwrap(),
            Bytes::from_static(b"world")
        );

        stream.shutdown().await.unwrap();
        assert!(egress_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn af_xdp_tcp_stream_chunks_large_writes_with_backpressure() {
        use tokio::io::AsyncWriteExt;

        let af_xdp::AfXdpTcpStreamParts {
            mut stream,
            mut egress_rx,
            ..
        } = af_xdp::AfXdpTcpStream::channel_pair(1);
        let payload = vec![0x5au8; 40 * 1024];

        let writer = tokio::spawn(async move {
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut chunks = Vec::new();
        while let Some(chunk) = egress_rx.recv().await {
            chunks.push(chunk);
        }
        writer.await.unwrap();

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 16 * 1024);
        assert_eq!(chunks[1].len(), 16 * 1024);
        assert_eq!(chunks[2].len(), 8 * 1024);
        assert!(
            chunks
                .iter()
                .all(|chunk| chunk.iter().all(|byte| *byte == 0x5a))
        );
    }

    #[tokio::test]
    async fn af_xdp_ingress_delivery_preserves_backpressured_chunk() {
        use bytes::Bytes;

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut pending = Bytes::new();

        assert_eq!(
            af_xdp::send_or_store_ingress(&tx, &mut pending, Bytes::from_static(b"first")),
            af_xdp::IngressDelivery::Delivered
        );
        assert_eq!(
            af_xdp::send_or_store_ingress(&tx, &mut pending, Bytes::from_static(b"second")),
            af_xdp::IngressDelivery::Backpressured
        );
        assert_eq!(&pending[..], b"second");
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"first"));

        assert_eq!(
            af_xdp::flush_pending_ingress(&tx, &mut pending),
            af_xdp::IngressDelivery::Delivered
        );
        assert!(pending.is_empty());
        assert_eq!(rx.recv().await.unwrap(), Bytes::from_static(b"second"));

        drop(rx);
        pending = Bytes::from_static(b"orphaned");
        assert_eq!(
            af_xdp::flush_pending_ingress(&tx, &mut pending),
            af_xdp::IngressDelivery::Closed
        );
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn af_xdp_tcp_stream_reports_broken_pipe_when_reactor_side_closes() {
        use tokio::io::AsyncWriteExt;

        let af_xdp::AfXdpTcpStreamParts {
            mut stream,
            egress_rx,
            ..
        } = af_xdp::AfXdpTcpStream::channel_pair(1);
        drop(egress_rx);

        let err = stream.write_all(b"boom").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn af_xdp_extracts_ip_frame_with_vlan_link_meta() {
        let frame = ipv4_tcp_frame(true, b"GET / HTTP/1.1\r\n\r\n");
        let (link, ip_packet) = af_xdp::extract_ip_frame(&frame).expect("valid IP frame");

        assert_eq!(link.vlan_tag_count, 1);
        assert_eq!(link.ethertype, 0x0800);
        assert_eq!(ip_packet[0] >> 4, 4);
        assert_eq!(
            usize::from(u16::from_be_bytes([ip_packet[2], ip_packet[3]])),
            ip_packet.len()
        );
        assert_eq!(
            &ip_packet[ip_packet.len() - 18..],
            b"GET / HTTP/1.1\r\n\r\n"
        );
    }

    #[test]
    fn af_xdp_encodes_ip_reply_frame_with_reversed_l2() {
        let link = test_link_meta(true);
        let mut ip_packet = Vec::new();
        ip_packet.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 198, 51, 100, 5, 192, 0, 2, 10,
        ]);
        let mut frame = Vec::new();

        af_xdp::encode_ip_reply_frame(&link, &ip_packet, &mut frame).expect("reply frame");

        assert_eq!(&frame[0..6], &[0x02, 0, 0, 0, 0, 2]);
        assert_eq!(&frame[6..12], &[0x02, 0, 0, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), 0x0800);
        assert_eq!(&frame[18..], ip_packet.as_slice());
    }

    #[test]
    fn af_xdp_parser_extracts_vlan_ipv4_tcp_payload() {
        let frame = ipv4_tcp_frame(true, b"GET / HTTP/1.1\r\n\r\n");
        let packet = af_xdp::parse_l4_packet(&frame).expect("valid TCP frame");

        assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Tcp);
        assert_eq!(packet.peer_addr, "192.0.2.10:53000".parse().unwrap());
        assert_eq!(packet.local_addr, "198.51.100.5:443".parse().unwrap());
        assert_eq!(&packet.payload[..], b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(packet.link.vlan_tag_count, 1);
        assert_eq!(packet.link.vlan_tags[0].tpid, 0x8100);
    }

    #[test]
    fn af_xdp_parser_extracts_qinq_ipv4_tcp_payload() {
        let payload = b"GET /qinq HTTP/1.1\r\n\r\n";
        let mut frame = ethernet_header_with_vlan_tags(0x0800, &[(0x88a8, 10), (0x9100, 20)]);
        let total_len = 20 + 20 + payload.len();
        frame.extend_from_slice(&[
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0,
            1,
            0,
            0,
            64,
            6,
            0,
            0,
            192,
            0,
            2,
            10,
            198,
            51,
            100,
            5,
        ]);
        frame.extend_from_slice(&[
            0xcf, 0x08, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0x40, 0, 0, 0, 0, 0,
        ]);
        frame.extend_from_slice(payload);

        let packet = af_xdp::parse_l4_packet(&frame).expect("valid QinQ TCP frame");

        assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Tcp);
        assert_eq!(packet.peer_addr, "192.0.2.10:53000".parse().unwrap());
        assert_eq!(packet.local_addr, "198.51.100.5:443".parse().unwrap());
        assert_eq!(&packet.payload[..], payload);
        assert_eq!(packet.link.vlan_tag_count, 2);
        assert_eq!(packet.link.vlan_tags[0].tpid, 0x88a8);
        assert_eq!(packet.link.vlan_tags[0].tci, 10);
        assert_eq!(packet.link.vlan_tags[1].tpid, 0x9100);
        assert_eq!(packet.link.vlan_tags[1].tci, 20);
    }

    #[test]
    fn af_xdp_encodes_ipv4_udp_reply_frame_with_reversed_l2() {
        let link = test_link_meta(true);
        let mut frame = Vec::new();
        af_xdp::encode_udp_reply_frame(
            &link,
            "198.51.100.5:443".parse().unwrap(),
            "192.0.2.10:53000".parse().unwrap(),
            b"pong",
            &mut frame,
        )
        .expect("reply frame");

        assert_eq!(&frame[0..6], &[0x02, 0, 0, 0, 0, 2]);
        assert_eq!(&frame[6..12], &[0x02, 0, 0, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x8100);
        assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), 0x0800);
        let ip_offset = 18;
        assert_eq!(frame[ip_offset], 0x45);
        assert_eq!(frame[ip_offset + 9], 17);
        assert_eq!(
            &frame[ip_offset + 12..ip_offset + 20],
            &[198, 51, 100, 5, 192, 0, 2, 10]
        );
        let udp_offset = ip_offset + 20;
        assert_eq!(
            u16::from_be_bytes([frame[udp_offset], frame[udp_offset + 1]]),
            443
        );
        assert_eq!(
            u16::from_be_bytes([frame[udp_offset + 2], frame[udp_offset + 3]]),
            53000
        );
        assert_eq!(&frame[udp_offset + 8..], b"pong");
        assert_ne!(
            u16::from_be_bytes([frame[udp_offset + 6], frame[udp_offset + 7]]),
            0
        );
    }

    #[test]
    fn af_xdp_parser_rejects_fragmented_ipv4() {
        let frame = ipv4_udp_frame(false, 0x2000, b"hello");
        assert!(af_xdp::parse_l4_packet(&frame).is_none());
    }

    #[test]
    fn af_xdp_parser_skips_ipv6_destination_options() {
        let mut frame = ethernet_header(0x86dd, false);
        let udp_payload = b"quic";
        let payload_len = 8 + 8 + udp_payload.len();
        frame.extend_from_slice(&[
            0x60,
            0,
            0,
            0,
            (payload_len >> 8) as u8,
            payload_len as u8,
            60,
            64,
        ]);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        frame.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
        frame.extend_from_slice(&[
            0xcf,
            0x08,
            0x01,
            0xbb,
            0,
            (8 + udp_payload.len()) as u8,
            0,
            0,
        ]);
        frame.extend_from_slice(udp_payload);

        let packet = af_xdp::parse_l4_packet(&frame).expect("valid IPv6 UDP frame");
        assert_eq!(packet.protocol, af_xdp::AfXdpTransportProtocol::Udp);
        assert_eq!(packet.peer_addr, "[2001:db8::1]:53000".parse().unwrap());
        assert_eq!(packet.local_addr, "[2001:db8::2]:443".parse().unwrap());
        assert_eq!(&packet.payload[..], udp_payload);
    }

    fn ethernet_header(ethertype: u16, vlan: bool) -> Vec<u8> {
        if vlan {
            return ethernet_header_with_vlan_tags(ethertype, &[(0x8100, 0)]);
        }
        ethernet_header_with_vlan_tags(ethertype, &[])
    }

    fn ethernet_header_with_vlan_tags(ethertype: u16, tags: &[(u16, u16)]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        for (tpid, tci) in tags {
            frame.extend_from_slice(&tpid.to_be_bytes());
            frame.extend_from_slice(&tci.to_be_bytes());
        }
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame
    }

    fn test_link_meta(vlan: bool) -> af_xdp::AfXdpLinkMeta {
        af_xdp::AfXdpLinkMeta {
            destination_mac: [0x02, 0, 0, 0, 0, 1],
            source_mac: [0x02, 0, 0, 0, 0, 2],
            vlan_tags: [
                af_xdp::AfXdpVlanTag {
                    tpid: if vlan { 0x8100 } else { 0 },
                    tci: 0,
                },
                af_xdp::AfXdpVlanTag { tpid: 0, tci: 0 },
            ],
            vlan_tag_count: u8::from(vlan),
            ethertype: 0x0800,
        }
    }

    fn ipv4_udp_frame(vlan: bool, fragment: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = ethernet_header(0x0800, vlan);
        let total_len = 20 + 8 + payload.len();
        frame.extend_from_slice(&[
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0,
            1,
            (fragment >> 8) as u8,
            fragment as u8,
            64,
            17,
            0,
            0,
            192,
            0,
            2,
            10,
            198,
            51,
            100,
            5,
        ]);
        frame.extend_from_slice(&[0xcf, 0x08, 0x01, 0xbb, 0, (8 + payload.len()) as u8, 0, 0]);
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4_tcp_frame(vlan: bool, payload: &[u8]) -> Vec<u8> {
        let mut frame = ethernet_header(0x0800, vlan);
        let total_len = 20 + 20 + payload.len();
        frame.extend_from_slice(&[
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0,
            1,
            0,
            0,
            64,
            6,
            0,
            0,
            192,
            0,
            2,
            10,
            198,
            51,
            100,
            5,
        ]);
        frame.extend_from_slice(&[
            0xcf, 0x08, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        frame.extend_from_slice(payload);
        frame
    }

    #[cfg(any(test, target_os = "linux"))]
    fn ipv4_tcp_syn_frame(vlan: bool) -> Vec<u8> {
        ipv4_tcp_syn_frame_with_source_port(vlan, 53000)
    }

    #[cfg(any(test, target_os = "linux"))]
    fn ipv4_tcp_syn_frame_with_source_port(vlan: bool, source_port: u16) -> Vec<u8> {
        let mut frame = ethernet_header(0x0800, vlan);
        let total_len = 20 + 20;
        frame.extend_from_slice(&[
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0,
            1,
            0,
            0,
            64,
            6,
            0,
            0,
            192,
            0,
            2,
            10,
            198,
            51,
            100,
            5,
        ]);
        let [source_port_hi, source_port_lo] = source_port.to_be_bytes();
        frame.extend_from_slice(&[
            source_port_hi,
            source_port_lo,
            0x01,
            0xbb,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0x50,
            0x02,
            0xff,
            0xff,
            0,
            0,
            0,
            0,
        ]);
        write_ipv4_checksum(&mut frame, ethernet_header_len(vlan));
        write_tcp4_checksum(&mut frame, ethernet_header_len(vlan));
        frame
    }

    fn ipv4_tcp_reply_ip_packet() -> Vec<u8> {
        let total_len = 20 + 20;
        let mut packet = Vec::with_capacity(total_len);
        packet.extend_from_slice(&[
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0,
            1,
            0,
            0,
            64,
            6,
            0,
            0,
            198,
            51,
            100,
            5,
            192,
            0,
            2,
            10,
        ]);
        packet.extend_from_slice(&[
            0x01, 0xbb, 0xcf, 0x08, 0, 0, 0, 2, 0, 0, 0, 2, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        packet
    }

    #[cfg(any(test, target_os = "linux"))]
    fn ethernet_header_len(vlan: bool) -> usize {
        14 + if vlan { 4 } else { 0 }
    }

    #[cfg(any(test, target_os = "linux"))]
    fn write_ipv4_checksum(frame: &mut [u8], ip_offset: usize) {
        frame[ip_offset + 10] = 0;
        frame[ip_offset + 11] = 0;
        let checksum = test_internet_checksum(&frame[ip_offset..ip_offset + 20]);
        frame[ip_offset + 10..ip_offset + 12].copy_from_slice(&checksum.to_be_bytes());
    }

    #[cfg(any(test, target_os = "linux"))]
    fn write_tcp4_checksum(frame: &mut [u8], ip_offset: usize) {
        let tcp_offset = ip_offset + 20;
        let tcp_len = frame.len() - tcp_offset;
        frame[tcp_offset + 16] = 0;
        frame[tcp_offset + 17] = 0;
        let mut pseudo = Vec::with_capacity(12 + tcp_len);
        pseudo.extend_from_slice(&frame[ip_offset + 12..ip_offset + 20]);
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&frame[tcp_offset..]);
        let checksum = test_internet_checksum(&pseudo);
        frame[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&checksum.to_be_bytes());
    }

    #[cfg(any(test, target_os = "linux"))]
    fn test_internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                (chunk[0] as u32) << 8
            };
            sum = sum.wrapping_add(word);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
        }
        !(sum as u16)
    }
}
