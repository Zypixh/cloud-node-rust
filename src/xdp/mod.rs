use crate::firewall::kernel::{KernelFilter, KernelFilterSnapshot, KernelFilterStatus};
use crate::runtime_mode::{RuntimeConfig, XdpConfig, XdpProxyProtocol, XdpRuntimeMode};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// eBPF program embedded at build time (see build.rs). The kernel only accepts
/// verified eBPF bytecode at the XDP hook, so the program must ship as an ELF
/// object — embedding it keeps binary and program versioned atomically.
#[cfg(target_os = "linux")]
const XDP_EBPF_EMBEDDED: &[u8] = aya::include_bytes_aligned!(env!("CLOUD_NODE_XDP_EBPF_OBJECT"));
#[cfg(target_os = "linux")]
const XDP_BPF_PIN_DIR: &str = "/sys/fs/bpf/cloud-node-xdp";
const XDP_STATE_WRITE_INTERVAL_SECS: u64 = 10;
const XDP_RULE_SWEEP_INTERVAL_SECS: u64 = 5;
// Coalescing window for rule-map writes: bursts of block/unblock events under an
// attack collapse into a single incremental eBPF map update. Off-round to avoid
// whole-second resonance with the rule sweeper.
const XDP_MAP_SYNC_DEBOUNCE_MS: u64 = 47;
const XDP_PROXY_DATAPLANE_ACTIVE: bool = true;
#[cfg(any(test, target_os = "linux"))]
const XDP_XSK_STATUS_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

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
    #[serde(default)]
    pub rate_limited: u64,
    #[serde(default)]
    pub ratelimit_map_full: u64,
    #[serde(default)]
    pub udp_fwd_tx: u64,
    #[serde(default)]
    pub udp_fwd_map_full: u64,
    #[serde(default)]
    pub tcp_fwd_tx: u64,
    #[serde(default)]
    pub tcp_fwd_map_full: u64,
    /// SNAT source-port bindings successfully claimed.
    #[serde(default)]
    pub snat_bound: u64,
    /// SNAT port allocation failures; those packets take the userspace path.
    #[serde(default)]
    pub snat_alloc_fail: u64,
    /// Backend replies restored to clients via SNAT reverse bindings.
    #[serde(default)]
    pub snat_reply_tx: u64,
    /// Terminal XDP_TX actions (kernel-bypassed forwards).
    #[serde(default)]
    pub tx: u64,
    /// Terminal drops caused by ACL block rules.
    #[serde(default)]
    pub acl_blocked: u64,
    /// Deterministic-illegal packets dropped at parse (XDP_CLASS_MALFORMED).
    #[serde(default)]
    pub malformed: u64,
    /// Legal-but-unparseable traffic passed to the kernel (deep ext chains,
    /// >2 VLAN tags, non-TCP/UDP/ICMP).
    #[serde(default)]
    pub unsupported: u64,
    /// IP fragments classified before L4 handling.
    #[serde(default)]
    pub fragmented: u64,
    /// Observe-mode ACL hits that would have dropped in enforce modes.
    #[serde(default)]
    pub acl_would_block: u64,
    /// Packets passed because the destination is outside the protected
    /// VIP set (direction gate).
    #[serde(default)]
    pub nonlocal_pass: u64,
    /// EN-07: packets dropped at the aggregate unverified-packet budget.
    pub unverified_limited: u64,
    /// EN-07: new-state admissions rejected by the new-flow budget.
    pub admission_limited: u64,
    /// EN-09: SYN admissions rejected because the bounded half-open table
    /// XDP_PENDING is full.
    pub pending_limited: u64,
    /// ICMP/ICMPv6 control traffic handed to the kernel stack.
    #[serde(default)]
    pub control: u64,
    #[serde(default)]
    pub rate_limit_active: bool,
    #[serde(default)]
    pub rate_limit_detail: String,
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

#[cfg(any(test, target_os = "linux"))]
fn xsk_status_refresh_due(
    last_refresh_at: Option<std::time::Instant>,
    now: std::time::Instant,
    force: bool,
) -> bool {
    if force {
        return true;
    }
    match last_refresh_at {
        Some(last_refresh_at) => {
            now.saturating_duration_since(last_refresh_at) >= XDP_XSK_STATUS_REFRESH_INTERVAL
        }
        None => true,
    }
}

#[derive(Debug)]
pub(crate) struct XdpManager {
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
    rate_limited: AtomicU64,
    ratelimit_map_full: AtomicU64,
    udp_fwd_tx: AtomicU64,
    udp_fwd_map_full: AtomicU64,
    tcp_fwd_tx: AtomicU64,
    tcp_fwd_map_full: AtomicU64,
    snat_bound: AtomicU64,
    snat_alloc_fail: AtomicU64,
    snat_reply_tx: AtomicU64,
    tx: AtomicU64,
    acl_blocked: AtomicU64,
    malformed: AtomicU64,
    unsupported: AtomicU64,
    fragmented: AtomicU64,
    control: AtomicU64,
    acl_would_block: AtomicU64,
    nonlocal_pass: AtomicU64,
    unverified_limited: AtomicU64,
    admission_limited: AtomicU64,
    pending_limited: AtomicU64,
    rate_limit_active: AtomicU64,
    rate_limit_detail: parking_lot::Mutex<String>,
    proxy_redirect_enabled: AtomicBool,
    last_state_write_at: AtomicU64,
    rule_sweeper_started: AtomicBool,
    rule_sweeper_generation: AtomicU64,
    /// Image of the rule state last successfully written to the eBPF maps. The
    /// incremental sync diffs the live shadow `state` against this to compute the
    /// minimal set of map inserts/removes.
    #[cfg(target_os = "linux")]
    synced: parking_lot::Mutex<RuleState>,
    /// Last-aggregated per-flow totals for XDP UDP direct-forward accounting;
    /// sweeps emit deltas against this image so nothing is double-counted.
    #[cfg(target_os = "linux")]
    udp_flow_shadow: parking_lot::Mutex<
        std::collections::HashMap<
            cloud_node_xdp_common::XdpUdpCtKey,
            cloud_node_xdp_common::XdpFlowAcct,
        >,
    >,
    map_sync_started: AtomicBool,
    map_sync_generation: AtomicU64,
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
            rate_limited: AtomicU64::new(0),
            ratelimit_map_full: AtomicU64::new(0),
            udp_fwd_tx: AtomicU64::new(0),
            udp_fwd_map_full: AtomicU64::new(0),
            tcp_fwd_tx: AtomicU64::new(0),
            tcp_fwd_map_full: AtomicU64::new(0),
            snat_bound: AtomicU64::new(0),
            snat_alloc_fail: AtomicU64::new(0),
            snat_reply_tx: AtomicU64::new(0),
            tx: AtomicU64::new(0),
            acl_blocked: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            unsupported: AtomicU64::new(0),
            fragmented: AtomicU64::new(0),
            control: AtomicU64::new(0),
            acl_would_block: AtomicU64::new(0),
            nonlocal_pass: AtomicU64::new(0),
            unverified_limited: AtomicU64::new(0),
            admission_limited: AtomicU64::new(0),
            pending_limited: AtomicU64::new(0),
            rate_limit_active: AtomicU64::new(0),
            rate_limit_detail: parking_lot::Mutex::new(String::new()),
            proxy_redirect_enabled: AtomicBool::new(false),
            last_state_write_at: AtomicU64::new(0),
            rule_sweeper_started: AtomicBool::new(false),
            rule_sweeper_generation: AtomicU64::new(0),
            #[cfg(target_os = "linux")]
            synced: parking_lot::Mutex::new(RuleState::default()),
            #[cfg(target_os = "linux")]
            udp_flow_shadow: parking_lot::Mutex::new(std::collections::HashMap::new()),
            map_sync_started: AtomicBool::new(false),
            map_sync_generation: AtomicU64::new(0),
            map_sync_notify: tokio::sync::Notify::new(),
        }
    }

    async fn initialize(&self) -> anyhow::Result<()> {
        if !self.config.enabled {
            self.ensure_detached_when_disabled().await;
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

        let object_override = ebpf_object_override(&self.config);
        if let Some(path) = &object_override {
            if !path.exists() {
                self.set_fallback_reason(format!(
                    "configured eBPF object {} is missing",
                    path.display()
                ));
                if self.config.fallback.fail_start() {
                    anyhow::bail!("xdp eBPF object is missing: {}", path.display());
                }
                self.persist_status();
                return Ok(());
            }
        }

        #[cfg(target_os = "linux")]
        {
            match linux::attach(&self.config, object_override.as_deref()).await {
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

    async fn ensure_detached_when_disabled(&self) {
        if self.config.enabled {
            return;
        }
        self.stop_rule_sweeper();
        self.stop_map_sync_worker();
        self.proxy_redirect_enabled.store(false, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        {
            *self.af_xdp.lock() = None;
            *self.ebpf.lock() = None;
            if !self.config.interfaces.is_empty() {
                if let Err(err) = linux::detach(&self.config).await {
                    let detail = format!("runtime xdp.enabled=false; detach failed: {err}");
                    self.set_fallback_reason(detail.clone());
                    tracing::warn!("{detail}");
                    crate::logging::report_node_log(
                        "warn".to_string(),
                        "xdp".to_string(),
                        detail,
                        0,
                    );
                    self.persist_status_blocking();
                    return;
                }
            }
        }
        self.attached.write().clear();
        self.xsk_status.write().clear();
        self.set_fallback_reason(String::new());
        self.set_proxy_fallback_reason(String::new());
        self.persist_status_blocking();
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
        let proxy_interfaces = self
            .config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
            .collect::<Vec<_>>();
        !proxy_interfaces.is_empty()
            && proxy_interfaces.iter().all(|interface| {
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
        self.persist_status_now();
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
                    if failed || registration_failed {
                        drop(runtime);
                    } else {
                        *self.af_xdp.lock() = Some(runtime);
                    }
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
            return Err(anyhow::anyhow!(
                "{source} failed to enable AF_XDP redirect: map sync failed"
            ));
        }

        self.proxy_redirect_enabled.store(true, Ordering::Relaxed);
        self.set_proxy_fallback_reason(xdp_proxy_partial_detail(&self.config));
        self.set_tcp_dataplane_detail(xdp_tcp_dataplane_detail(&self.config));
        self.persist_status_now();
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
        #[cfg(target_os = "linux")]
        self.refresh_af_xdp_statuses(true);
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
        let proxy_interfaces = self
            .config
            .interfaces
            .iter()
            .filter(|interface| interface.mode == XdpRuntimeMode::Proxy)
            .collect::<Vec<_>>();
        let proxy_ready = self.proxy_redirect_enabled.load(Ordering::Relaxed)
            && !proxy_interfaces.is_empty()
            && proxy_interfaces.iter().all(|interface| {
                !interface.queues.is_empty()
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
            ebpf_object: ebpf_object_source_label(&self.config),
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
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            ratelimit_map_full: self.ratelimit_map_full.load(Ordering::Relaxed),
            udp_fwd_tx: self.udp_fwd_tx.load(Ordering::Relaxed),
            udp_fwd_map_full: self.udp_fwd_map_full.load(Ordering::Relaxed),
            tcp_fwd_tx: self.tcp_fwd_tx.load(Ordering::Relaxed),
            tcp_fwd_map_full: self.tcp_fwd_map_full.load(Ordering::Relaxed),
            snat_bound: self.snat_bound.load(Ordering::Relaxed),
            snat_alloc_fail: self.snat_alloc_fail.load(Ordering::Relaxed),
            snat_reply_tx: self.snat_reply_tx.load(Ordering::Relaxed),
            tx: self.tx.load(Ordering::Relaxed),
            acl_blocked: self.acl_blocked.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
            unsupported: self.unsupported.load(Ordering::Relaxed),
            fragmented: self.fragmented.load(Ordering::Relaxed),
            control: self.control.load(Ordering::Relaxed),
            acl_would_block: self.acl_would_block.load(Ordering::Relaxed),
            nonlocal_pass: self.nonlocal_pass.load(Ordering::Relaxed),
            unverified_limited: self.unverified_limited.load(Ordering::Relaxed),
            admission_limited: self.admission_limited.load(Ordering::Relaxed),
            pending_limited: self.pending_limited.load(Ordering::Relaxed),
            rate_limit_active: self.rate_limit_active.load(Ordering::Relaxed) != 0,
            rate_limit_detail: self.rate_limit_detail.lock().clone(),
            updated_at: crate::utils::time::now_timestamp(),
        }
    }

    fn persist_status(&self) {
        let now = crate::utils::time::now_timestamp() as u64;
        if !self.claim_status_write_slot(now, false) {
            return;
        }
        self.write_status_snapshot();
    }

    #[cfg(target_os = "linux")]
    fn persist_status_now(&self) {
        let now = crate::utils::time::now_timestamp() as u64;
        self.claim_status_write_slot(now, true);
        self.write_status_snapshot();
    }

    fn claim_status_write_slot(&self, now: u64, force: bool) -> bool {
        let last = self.last_state_write_at.load(Ordering::Relaxed);
        if !force && now.saturating_sub(last) < XDP_STATE_WRITE_INTERVAL_SECS {
            return false;
        }
        if force {
            self.last_state_write_at.store(now, Ordering::Relaxed);
            return true;
        }
        if self
            .last_state_write_at
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        true
    }

    fn write_status_snapshot(&self) {
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

    #[cfg(target_os = "linux")]
    fn update_xsk_queue_status(
        &self,
        interface: &str,
        queue: u32,
        update: impl FnOnce(&mut XdpQueueStatus),
    ) {
        let mut statuses = self.xsk_status.write();
        if let Some(status) = statuses
            .iter_mut()
            .find(|status| status.interface == interface && status.queue == queue)
        {
            update(status);
        }
    }

    #[cfg(target_os = "linux")]
    fn refresh_af_xdp_statuses(&self, force: bool) {
        let statuses = {
            let mut runtime = self.af_xdp.lock();
            let Some(runtime) = runtime.as_mut() else {
                return;
            };
            runtime.refresh_statuses(force);
            runtime.statuses.clone()
        };
        *self.xsk_status.write() = statuses;
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

    fn update_allowed_ip(&self, ip: IpAddr, ttl_secs: i64) {
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state.write().allowed_ips.insert(ip, expiry);
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_allowed_ip(&self, ip: IpAddr) {
        self.state.write().allowed_ips.remove(&ip);
        self.request_map_sync();
        self.persist_status();
    }

    fn update_allowed_network(&self, net: IpNet, ttl_secs: i64) {
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state
            .write()
            .allowed_networks
            .insert(net.to_string(), (net, expiry));
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_allowed_network(&self, net: IpNet) {
        self.state.write().allowed_networks.remove(&net.to_string());
        self.request_map_sync();
        self.persist_status();
    }

    fn update_allowed_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        if from > to {
            return;
        }
        let expiry = crate::utils::time::now_timestamp() + ttl_secs.max(1);
        self.state
            .write()
            .allowed_ranges
            .insert(RangeKey { from, to, v6 }, expiry);
        self.request_map_sync();
        self.persist_status();
    }

    fn remove_allowed_range(&self, from: u128, to: u128, v6: bool) {
        self.state
            .write()
            .allowed_ranges
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
                tracing::warn!(
                    "XDP map diff sync failed; detached and falling back: {}",
                    err
                );
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn flush_maps_diff(&self) {}

    /// Effective per-IP rate limit for the current pressure level: base
    /// settings apply at Elevated, halve at High, quarter at Critical, and the
    /// limiter is fully disabled at Normal (zero pps = off in eBPF).
    fn effective_rate_limit_config(&self) -> cloud_node_xdp_common::XdpRateLimitConfig {
        let config = cloud_node_xdp_common::XdpRateLimitConfig::default();
        let Some(base) = &self.config.rate_limit else {
            return config;
        };
        let divisor: u64 = match xdp_rate_limit_pressure_level() {
            crate::l4_defense::L4PressureLevel::Normal => return config,
            crate::l4_defense::L4PressureLevel::Elevated => 1,
            crate::l4_defense::L4PressureLevel::High => 2,
            crate::l4_defense::L4PressureLevel::Critical => 4,
        };
        scaled_rate_limit_config(base, divisor)
    }

    /// Effective aggregate budget (EN-07). Node-wide totals from
    /// `xdp.budget` (or the built-in baseline) are divided by the
    /// possible-CPU count into per-CPU shares — the sum of shares never
    /// exceeds the configured total, so CPU/queue changes cannot multiply
    /// the quota (I09). Pressure scaling narrows the elastic allowance
    /// (Elevated x1, High /2, Critical /4) but clamps each share at >=1:
    /// "divide to zero" never disables a dimension. `enabled: false` in
    /// config is the only off switch and writes flag=0 explicitly.
    fn effective_budget_config(&self) -> cloud_node_xdp_common::XdpBudgetConfig {
        use crate::l4_defense::L4PressureLevel;
        let base = self.config.budget.clone().unwrap_or_default();
        if !base.enabled {
            return cloud_node_xdp_common::XdpBudgetConfig::default();
        }
        let divisor: u64 = match crate::l4_defense::current_pressure_level() {
            L4PressureLevel::Normal | L4PressureLevel::Elevated => 1,
            L4PressureLevel::High => 2,
            L4PressureLevel::Critical => 4,
        };
        #[cfg(target_os = "linux")]
        let ncpu = aya::util::nr_cpus().map(|n| n as u64).unwrap_or(1).max(1);
        #[cfg(not(target_os = "linux"))]
        let ncpu: u64 = num_cpus::get() as u64;
        let share = |total: u64| -> u64 {
            // ceil(total / (ncpu * divisor)), floored at 1 so a share can
            // never collapse to "disabled" through integer division.
            let denom = ncpu.saturating_mul(divisor).max(1);
            let per = total.saturating_add(denom - 1) / denom;
            per.max(1)
        };
        cloud_node_xdp_common::XdpBudgetConfig {
            unverified_pps: share(base.unverified_pps),
            new_flow_per_sec: share(base.new_flow_per_sec),
            xsk_redirect_pps: 0,
            challenge_pps: 0,
            window_ns: base.window_ms.saturating_mul(1_000_000),
            flags: 0b0011,
        }
    }

    /// Push the effective budget into the eBPF config map; failures are
    /// logged and surfaced through the status detail, never silent.
    fn sync_budget_config(&self) {
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let config = self.effective_budget_config();
        #[cfg(target_os = "linux")]
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_budget(ebpf, &config),
                None => return,
            }
        };
        #[cfg(not(target_os = "linux"))]
        let result: anyhow::Result<()> = Ok(());
        if let Err(err) = result {
            tracing::warn!("XDP budget map sync unavailable: {err}");
        }
    }

    /// Push the EN-09 absolute pending deadline into XDP_PENDING_CAP.
    fn sync_pending_cap(&self) {
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let ttl_ns = self
            .config
            .admission
            .as_ref()
            .map(|a| a.tcp_pending_ms)
            .unwrap_or_else(crate::runtime_mode::default_tcp_pending_ms)
            .saturating_mul(1_000_000);
        #[cfg(target_os = "linux")]
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_pending_cap(ebpf, ttl_ns),
                None => return,
            }
        };
        #[cfg(not(target_os = "linux"))]
        let result: anyhow::Result<()> = Ok(());
        if let Err(err) = result {
            tracing::warn!("XDP pending-cap map sync unavailable: {err}");
        }
    }

    /// Push the effective rate limit into the eBPF config map and record the
    /// outcome in the status snapshot. An object without XDP_RATE_CFG (built
    /// before the limiter existed) is reported, never silently ignored.
    fn sync_rate_limit_config(&self) {
        let config = self.effective_rate_limit_config();
        let active = config.window_ns != 0 && (config.udp_pps != 0 || config.tcp_syn_pps != 0);
        let detail = format!(
            "udp_pps={} tcp_syn_pps={} window_ns={}",
            config.udp_pps, config.tcp_syn_pps, config.window_ns
        );
        #[cfg(target_os = "linux")]
        let result = {
            let mut ebpf = self.ebpf.lock();
            match ebpf.as_mut() {
                Some(ebpf) => linux::sync_rate_limit(ebpf, &config),
                None => return,
            }
        };
        #[cfg(not(target_os = "linux"))]
        let result: anyhow::Result<()> = Ok(());
        match result {
            Ok(()) => {
                self.rate_limit_active
                    .store(u64::from(active), Ordering::Relaxed);
                *self.rate_limit_detail.lock() = detail;
            }
            Err(err) => {
                let detail = format!("rate limit map sync unavailable: {err}");
                if *self.rate_limit_detail.lock() != detail {
                    tracing::warn!("{detail}");
                    *self.rate_limit_detail.lock() = detail;
                }
                self.rate_limit_active.store(0, Ordering::Relaxed);
                crate::pipeline_metrics::add(
                    crate::pipeline_metrics::PipelineCounter::XdpMapSyncFailed,
                    1,
                );
            }
        }
    }

    /// Pin a QUIC long-header DCID to the XSK queue owning the session, so
    /// retransmitted Initials and handshake datagrams keep landing on the
    /// reactor that holds the connection state instead of following RSS.
    /// Returns false when the eBPF object lacks the maps (stale object build);
    /// callers log that once and keep RSS affinity as the explicit fallback.
    #[cfg(target_os = "linux")]
    fn upsert_quic_dcid(&self, dcid: &[u8], ifindex: u32, queue: u32) -> bool {
        let Some(dcid_key) = cloud_node_xdp_common::XdpQuicDcidKey::new(dcid) else {
            return false;
        };
        let mut guard = self.ebpf.lock();
        let Some(ebpf) = guard.as_mut() else {
            return false;
        };
        let xsk_index = {
            let Some(map) = ebpf.map("XDP_XSK_INDEX") else {
                return false;
            };
            let Ok(map) =
                aya::maps::HashMap::<_, cloud_node_xdp_common::XdpQueueKey, u32>::try_from(map)
            else {
                return false;
            };
            map.get(&cloud_node_xdp_common::XdpQueueKey::new(ifindex, queue), 0)
                .ok()
        };
        let Some(xsk_index) = xsk_index else {
            return false;
        };
        let Some(map) = ebpf.map_mut("XDP_QUIC_DCID") else {
            return false;
        };
        let Ok(mut map) =
            aya::maps::HashMap::<_, cloud_node_xdp_common::XdpQuicDcidKey, u32>::try_from(map)
        else {
            return false;
        };
        map.insert(dcid_key, xsk_index, 0).is_ok()
    }

    #[cfg(target_os = "linux")]
    fn remove_quic_dcid(&self, dcid_key: &cloud_node_xdp_common::XdpQuicDcidKey) {
        let mut guard = self.ebpf.lock();
        let Some(ebpf) = guard.as_mut() else {
            return;
        };
        let Some(map) = ebpf.map_mut("XDP_QUIC_DCID") else {
            return;
        };
        let Ok(mut map) =
            aya::maps::HashMap::<_, cloud_node_xdp_common::XdpQuicDcidKey, u32>::try_from(map)
        else {
            return;
        };
        let _ = map.remove(dcid_key);
    }

    /// GC direct-forward conntrack entries and fold per-CPU flow accounting
    /// into billing. No-op unless the dataplane is attached and forwards are
    /// configured.
    #[cfg(target_os = "linux")]
    fn sweep_nat_maps(&self) {
        let configured = self
            .config
            .interfaces
            .iter()
            .any(|iface| !iface.udp_forwards.is_empty() || !iface.tcp_forwards.is_empty());
        if !configured || self.attached.read().is_empty() {
            return;
        }
        let pending_ttl = std::time::Duration::from_millis(
            self.config
                .admission
                .as_ref()
                .map(|a| a.tcp_pending_ms)
                .unwrap_or_else(crate::runtime_mode::default_tcp_pending_ms),
        );
        let result = {
            let mut guard = self.ebpf.lock();
            let mut shadow = self.udp_flow_shadow.lock();
            match guard.as_mut() {
                Some(ebpf) => linux::sweep_nat_maps(
                    ebpf,
                    &mut shadow,
                    std::time::Duration::from_secs(180),
                    std::time::Duration::from_secs(7200),
                    std::time::Duration::from_secs(120),
                    pending_ttl,
                ),
                None => Ok(()),
            }
        };
        if let Err(err) = result {
            tracing::warn!("XDP NAT map sweep failed: {err}");
            crate::pipeline_metrics::add(
                crate::pipeline_metrics::PipelineCounter::XdpMapSyncFailed,
                1,
            );
        }
    }

    /// EN-08: reap idle per-source rate buckets (bounded per pass).
    #[cfg(target_os = "linux")]
    fn sweep_rate_buckets(&self) {
        const MAX_REAP_PER_PASS: usize = 8192;
        let base = self.config.rate_limit.clone().unwrap_or_default();
        if base.window_ms == 0 || self.attached.read().is_empty() {
            return;
        }
        let result = {
            let mut guard = self.ebpf.lock();
            match guard.as_mut() {
                Some(ebpf) => linux::sweep_rate_maps(
                    ebpf,
                    base.window_ms.saturating_mul(1_000_000),
                    base.gc_after_windows,
                    MAX_REAP_PER_PASS,
                ),
                None => Ok(()),
            }
        };
        if let Err(err) = result {
            tracing::debug!("XDP rate-map GC skipped: {err}");
        }
    }

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
                self.rate_limited
                    .store(counters.rate_limited, Ordering::Relaxed);
                self.ratelimit_map_full
                    .store(counters.ratelimit_map_full, Ordering::Relaxed);
                self.udp_fwd_tx
                    .store(counters.udp_fwd_tx, Ordering::Relaxed);
                self.udp_fwd_map_full
                    .store(counters.udp_fwd_map_full, Ordering::Relaxed);
                self.tcp_fwd_tx
                    .store(counters.tcp_fwd_tx, Ordering::Relaxed);
                self.tcp_fwd_map_full
                    .store(counters.tcp_fwd_map_full, Ordering::Relaxed);
                self.snat_bound
                    .store(counters.snat_bound, Ordering::Relaxed);
                self.snat_alloc_fail
                    .store(counters.snat_alloc_fail, Ordering::Relaxed);
                self.snat_reply_tx
                    .store(counters.snat_reply_tx, Ordering::Relaxed);
                self.tx.store(counters.tx, Ordering::Relaxed);
                self.acl_blocked
                    .store(counters.acl_blocked, Ordering::Relaxed);
                self.malformed.store(counters.malformed, Ordering::Relaxed);
                self.unsupported
                    .store(counters.unsupported, Ordering::Relaxed);
                self.fragmented
                    .store(counters.fragmented, Ordering::Relaxed);
                self.control.store(counters.control, Ordering::Relaxed);
                self.acl_would_block
                    .store(counters.acl_would_block, Ordering::Relaxed);
                self.nonlocal_pass
                    .store(counters.nonlocal_pass, Ordering::Relaxed);
                self.unverified_limited
                    .store(counters.unverified_limited, Ordering::Relaxed);
                self.admission_limited
                    .store(counters.admission_limited, Ordering::Relaxed);
                self.pending_limited
                    .store(counters.pending_limited, Ordering::Relaxed);
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
        #[cfg(target_os = "linux")]
        let counters = linux::read_pinned_counters()
            .map(|c| {
                serde_json::json!({
                    "packets": c.packets,
                    "pass": c.pass,
                    "drop": c.drop,
                    "redirect": c.redirect,
                    "parseErrors": c.parse_errors,
                    "mapMiss": c.map_miss,
                    "xskDrops": c.xsk_drops,
                    "rateLimited": c.rate_limited,
                    "ratelimitMapFull": c.ratelimit_map_full,
                    "udpFwdTx": c.udp_fwd_tx,
                    "udpFwdMapFull": c.udp_fwd_map_full,
                    "tcpFwdTx": c.tcp_fwd_tx,
                    "tcpFwdMapFull": c.tcp_fwd_map_full,
                    "snatBound": c.snat_bound,
                    "snatAllocFail": c.snat_alloc_fail,
                    "snatReplyTx": c.snat_reply_tx,
                    "tx": c.tx,
                    "aclBlocked": c.acl_blocked,
                    "malformed": c.malformed,
                    "unsupported": c.unsupported,
                    "fragmented": c.fragmented,
                    "control": c.control,
                    "aclWouldBlock": c.acl_would_block,
                    "nonlocalPass": c.nonlocal_pass,
                    "unverifiedLimited": c.unverified_limited,
                    "admissionLimited": c.admission_limited,
                    "pendingLimited": c.pending_limited,
                })
            })
            .ok();
        #[cfg(not(target_os = "linux"))]
        let counters: Option<serde_json::Value> = None;
        serde_json::json!({
            "counters": counters,
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
        self.stop_map_sync_worker();
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

    fn stop_map_sync_worker(&self) {
        self.map_sync_generation.fetch_add(1, Ordering::Relaxed);
        self.map_sync_started.store(false, Ordering::Relaxed);
        self.map_sync_notify.notify_one();
    }

    fn stop_rule_sweeper(&self) {
        self.rule_sweeper_generation.fetch_add(1, Ordering::Relaxed);
        self.rule_sweeper_started.store(false, Ordering::Relaxed);
    }
}

static XDP_MANAGER: OnceLock<parking_lot::RwLock<std::sync::Arc<XdpManager>>> = OnceLock::new();

/// Pressure level used to scale the XDP per-source rate limiter. Release
/// builds always use the live aggregate pressure. Debug builds honor
/// `CLOUD_NODE_XDP_TEST_PRESSURE=normal|elevated|high|critical` so dataplane
/// e2e probes (scripts/edge/en08_rate_probe.py) can exercise the real
/// config→map→eBPF path without driving the host into memory pressure.
#[cfg(debug_assertions)]
fn xdp_rate_limit_pressure_level() -> crate::l4_defense::L4PressureLevel {
    use crate::l4_defense::L4PressureLevel;
    match std::env::var("CLOUD_NODE_XDP_TEST_PRESSURE").as_deref() {
        Ok("normal") => L4PressureLevel::Normal,
        Ok("elevated") => L4PressureLevel::Elevated,
        Ok("high") => L4PressureLevel::High,
        Ok("critical") => L4PressureLevel::Critical,
        _ => crate::l4_defense::current_pressure_level(),
    }
}

#[cfg(not(debug_assertions))]
fn xdp_rate_limit_pressure_level() -> crate::l4_defense::L4PressureLevel {
    crate::l4_defense::current_pressure_level()
}

/// EN-08: translate operator-facing rate settings into the eBPF ABI config.
/// Pressure scaling divides the per-source ceilings but clamps any nonzero
/// base at >=1 — "divide to zero" must never silently disable a dimension.
/// Prefix lengths are clamped to protocol width (32/128); 0 keeps the
/// default per-address granularity.
fn scaled_rate_limit_config(
    base: &crate::runtime_mode::XdpRateLimitSettings,
    divisor: u64,
) -> cloud_node_xdp_common::XdpRateLimitConfig {
    let scaled = |pps: u64| {
        if pps == 0 {
            0
        } else {
            (pps / divisor).max(1)
        }
    };
    cloud_node_xdp_common::XdpRateLimitConfig {
        udp_pps: scaled(base.udp_pps),
        tcp_syn_pps: scaled(base.tcp_syn_pps),
        window_ns: base.window_ms.saturating_mul(1_000_000),
        v4_prefix_len: base.prefix_v4_len.min(32),
        v6_prefix_len: base.prefix_v6_len.min(128),
    }
}

fn manager_from_runtime() -> std::sync::Arc<XdpManager> {
    let config = RuntimeConfig::current()
        .map(|runtime| runtime.xdp)
        .unwrap_or_default();
    let manager = XDP_MANAGER.get_or_init(|| {
        parking_lot::RwLock::new(std::sync::Arc::new(XdpManager::new(config.clone())))
    });

    {
        let current = manager.read();
        if current.config == config || (config.enabled && !current.attached.read().is_empty()) {
            return current.clone();
        }
    }

    let mut current = manager.write();
    if current.config != config && (!config.enabled || current.attached.read().is_empty()) {
        let previous = current.clone();
        *current = std::sync::Arc::new(XdpManager::new(config));
        previous.stop_rule_sweeper();
        previous.stop_map_sync_worker();
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
    let previous = current.clone();
    *current = std::sync::Arc::new(XdpManager::new(config));
    previous.stop_rule_sweeper();
    previous.stop_map_sync_worker();
    current.clone()
}

fn manager_is_current(candidate: &std::sync::Arc<XdpManager>) -> bool {
    let Some(manager) = XDP_MANAGER.get() else {
        return false;
    };
    let current = manager.read();
    std::sync::Arc::ptr_eq(candidate, &*current)
}

pub async fn ensure_current_xdp_auto_config() -> anyhow::Result<()> {
    let Some(mut runtime) = RuntimeConfig::current() else {
        return Ok(());
    };
    if !runtime.xdp.enabled || !runtime.xdp.interfaces.is_empty() {
        return Ok(());
    }

    let mut derived = crate::xdp_auto_config::derive_xdp_config_from_live_node(&runtime).await?;
    // Explicit file-level knobs that auto derivation cannot infer stay
    // authoritative; the derived part covers interfaces/queues/ports only.
    derived.attach_mode = runtime.xdp.attach_mode;
    derived.fallback = runtime.xdp.fallback;
    derived.rate_limit = runtime.xdp.rate_limit.clone().or(derived.rate_limit);
    runtime.xdp = derived;
    RuntimeConfig::set_current(runtime);
    Ok(())
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
            manager.sync_rate_limit_config();
            manager.sync_budget_config();
            manager.sync_pending_cap();
            #[cfg(target_os = "linux")]
            {
                manager.sweep_nat_maps();
                manager.sweep_rate_buckets();
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
    let generation = manager.map_sync_generation.load(Ordering::Relaxed);
    let manager = manager.clone();
    tokio::spawn(async move {
        loop {
            manager.map_sync_notify.notified().await;
            if manager.map_sync_generation.load(Ordering::Relaxed) != generation {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(XDP_MAP_SYNC_DEBOUNCE_MS)).await;
            if manager.map_sync_generation.load(Ordering::Relaxed) != generation
                || !manager_is_current(&manager)
            {
                break;
            }
            manager.flush_maps_diff();
        }
    });
}

pub async fn initialize_from_runtime() -> anyhow::Result<()> {
    ensure_current_xdp_auto_config().await?;
    let manager = manager_from_runtime();
    manager.initialize().await?;
    start_rule_sweeper(&manager);
    start_map_sync_worker(&manager);
    Ok(())
}

pub async fn build_kernel_filter() -> Option<Box<dyn KernelFilter>> {
    if let Err(err) = ensure_current_xdp_auto_config().await {
        tracing::warn!("XDP kernel filter auto configuration failed: {}", err);
        return None;
    }
    let manager = manager_from_runtime();
    if !manager.config.enabled {
        manager.ensure_detached_when_disabled().await;
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
    let manager = manager_from_runtime();
    if !manager.config.enabled {
        manager.persist_status_blocking();
    }
    manager.status()
}

pub fn persisted_status_snapshot() -> Option<XdpStatusSnapshot> {
    let path = crate::paths::NodePaths::current().xdp_state_file();
    let body = std::fs::read(path).ok()?;
    serde_json::from_slice(&body).ok()
}

pub async fn attach_from_runtime() -> anyhow::Result<()> {
    ensure_current_xdp_auto_config().await?;
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
    ensure_current_xdp_auto_config().await?;
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
    let mut lines = Vec::new();
    lines.push("CloudNode XDP doctor".to_string());
    lines.push(format!("  enabled:       {}", yes_no(config.enabled)));
    lines.push(format!("  attach mode:   {}", config.attach_mode.as_str()));
    lines.push(format!("  fallback:      {}", config.fallback.as_str()));
    lines.push("  L4 engine:     active".to_string());
    lines.push(format!(
        "  kernel backend: {}",
        if config.enabled {
            "xdp (fallback: nftables/iptables/noop)"
        } else {
            "nftables/iptables/noop"
        }
    ));
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
    lines.push(format!(
        "  eBPF object:   {}",
        ebpf_object_source_label(config)
    ));
    if let Some(path) = ebpf_object_override(config) {
        lines.push(format!("  object exists: {}", yes_no(path.exists())));
    }
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
        if interface.mode == XdpRuntimeMode::Proxy
            && interface.frame_size != cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
        {
            lines.push(format!(
                "  warning:       interface {} proxy mode requires frameSize={} until jumbo/multi-buffer support is enabled",
                interface.name,
                cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
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
    lines.extend(crate::xdp_netdev_tuning::doctor_lines_for_config(config));
    #[cfg(not(target_os = "linux"))]
    lines.push("  issue:         XDP attach is supported on Linux only".to_string());
    lines.join("\n")
}

pub fn dump_maps() -> serde_json::Value {
    manager_from_runtime().dump_maps()
}

fn range_bound_to_ip(value: u128, v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(value))
    } else {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    }
}

/// Explicit external eBPF object override. Precedence follows the project's
/// config convention: file config (`xdp.ebpfObject`) wins over the
/// `CLOUD_NODE_XDP_EBPF_OBJECT_PATH` environment variable; when neither is set
/// the binary loads the object embedded at build time.
fn ebpf_object_override(config: &XdpConfig) -> Option<PathBuf> {
    if let Some(path) = config
        .ebpf_object
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("CLOUD_NODE_XDP_EBPF_OBJECT_PATH")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn ebpf_object_source_label(config: &XdpConfig) -> String {
    match ebpf_object_override(config) {
        Some(path) => format!("external: {}", path.display()),
        None => "embedded".to_string(),
    }
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
    let invalid = config
        .interfaces
        .iter()
        .filter(|interface| {
            interface.mode == XdpRuntimeMode::Proxy
                && interface.frame_size != cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
        })
        .map(|interface| format!("{} frameSize={}", interface.name, interface.frame_size))
        .collect::<Vec<_>>();
    if invalid.is_empty() {
        String::new()
    } else {
        format!(
            "XDP proxy mode requires frameSize={} until jumbo/multi-buffer support is enabled: {}",
            cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE,
            invalid.join(",")
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

    fn allow(&self, ip: IpAddr, ttl_secs: i64) {
        self.manager.update_allowed_ip(ip, ttl_secs);
    }

    fn unallow(&self, ip: IpAddr) {
        self.manager.remove_allowed_ip(ip);
    }

    fn allow_network(&self, net: IpNet, ttl_secs: i64) {
        self.manager.update_allowed_network(net, ttl_secs);
    }

    fn unallow_network(&self, net: IpNet) {
        self.manager.remove_allowed_network(net);
    }

    fn allow_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        self.manager.update_allowed_range(from, to, v6, ttl_secs);
    }

    fn unallow_range(&self, from: u128, to: u128, v6: bool) {
        self.manager.remove_allowed_range(from, to, v6);
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

pub mod af_xdp;
#[cfg(target_os = "linux")]
mod linux;
mod policy;
mod smoke;
#[cfg(test)]
mod tests;

pub use policy::XdpRuleVerdict;
pub(crate) use policy::*;
pub use smoke::*;
