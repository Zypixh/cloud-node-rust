use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock as OnceCell;

static RUNTIME_CONFIG: OnceCell<parking_lot::RwLock<Option<RuntimeConfig>>> = OnceCell::new();
#[cfg(test)]
static RUNTIME_CONFIG_TEST_LOCK: OnceCell<parking_lot::Mutex<()>> = OnceCell::new();

const DEFAULT_INTERNAL_TOKEN_ENV: &str = "CLOUD_NODE_CLUSTER_INTERNAL_TOKEN";
const DEFAULT_POD_NAME_ENV: &str = "POD_NAME";
const DEFAULT_POD_IP_ENV: &str = "POD_IP";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum RuntimeMode {
    #[default]
    Standalone,
    Rke2,
}

impl RuntimeMode {
    pub fn from_env_value(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "standalone" | "single" | "local" => Ok(Self::Standalone),
            "rke2" | "kubernetes" | "k8s" | "cluster" => Ok(Self::Rke2),
            other => anyhow::bail!("unsupported CLOUD_NODE_MODE value: {other}"),
        }
    }

    pub fn is_rke2(self) -> bool {
        self == Self::Rke2
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeSection {
    #[serde(default)]
    pub mode: RuntimeMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum XdpAttachMode {
    #[default]
    Auto,
    Drv,
    Skb,
}

impl XdpAttachMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Drv => "drv",
            Self::Skb => "skb",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum XdpFallbackMode {
    #[default]
    Pass,
    FailStart,
}

impl XdpFallbackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::FailStart => "fail-start",
        }
    }

    pub fn fail_start(self) -> bool {
        self == Self::FailStart
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum XdpRuntimeMode {
    #[default]
    Observe,
    Protect,
    Proxy,
}

impl XdpRuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Protect => "protect",
            Self::Proxy => "proxy",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum XdpProxyProtocol {
    Http,
    Https,
    #[default]
    Tcp,
    Udp,
    H3,
}

impl XdpProxyProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::H3 => "h3",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct XdpProxyPortConfig {
    #[serde(default)]
    pub protocol: XdpProxyProtocol,
    #[serde(default)]
    pub port: u16,
}

impl Default for XdpProxyPortConfig {
    fn default() -> Self {
        Self {
            protocol: XdpProxyProtocol::Tcp,
            port: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct XdpInterfaceConfig {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub queues: Vec<u32>,
    /// Optional CPU ids aligned index-wise with `queues`; pins each per-queue
    /// AF_XDP reactor thread. Empty = auto round-robin across online CPUs.
    #[serde(default)]
    pub cpus: Vec<u32>,
    #[serde(default)]
    pub mode: XdpRuntimeMode,
    #[serde(rename = "localIps", default)]
    pub local_ips: Vec<std::net::IpAddr>,
    #[serde(rename = "frameSize", default = "default_xdp_frame_size")]
    pub frame_size: u32,
    /// Explicitly configured UDP direct-forward rules. Each entry DNATs a
    /// listen tuple to a backend at the XDP layer (XDP_TX, no userspace
    /// pass). The backend must route replies back through this node.
    #[serde(rename = "udpForwards", default)]
    pub udp_forwards: Vec<XdpUdpForwardConfig>,
    /// Explicitly configured TCP direct-forward rules: stateful L4 NAT at the
    /// XDP layer (conntrack on bare SYN; mid-stream packets without state fall
    /// back to the normal dataplane). The backend must route replies back
    /// through this node.
    #[serde(rename = "tcpForwards", default)]
    pub tcp_forwards: Vec<XdpUdpForwardConfig>,
    /// Fragment disposition for this interface's security domain: "pass"
    /// (default) hands all IP fragments to the kernel stack — the legacy
    /// behavior; "drop" rejects them at XDP. A first fragment never creates
    /// a trusted L4 flow under either setting.
    #[serde(rename = "fragmentAction", default)]
    pub fragment_action: XdpFragmentAction,
    /// Per-VIP service policy. Each `ip` must also be listed in `localIps`;
    /// overrides are meaningless without local-IP filtering.
    #[serde(rename = "protectedServices", default)]
    pub protected_services: Vec<XdpProtectedService>,
}

/// Fragment disposition at the XDP layer (EN-05): fragments are classified
/// before any L4 handling, so neither setting lets a fragment create flow
/// state — "pass" defers reassembly to the kernel, "drop" discards at RX.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpFragmentAction {
    #[default]
    Pass,
    Drop,
}

/// Per-VIP protected-service policy (EN-06): protection scope and the AF_XDP
/// redirect switch are independent. `redirect: false` keeps the VIP under
/// XDP protection (classification, ACL, rate limits, fragment policy) while
/// its ports are served by the kernel stack — two VIPs sharing a port do
/// not cross-redirect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct XdpProtectedService {
    pub ip: std::net::IpAddr,
    /// Whether proxy-port traffic for this VIP may redirect into AF_XDP.
    /// Default true — preserving pre-EN-06 semantics for plain localIps.
    #[serde(default = "default_true")]
    pub redirect: bool,
    /// Optional per-VIP fragment disposition override (resolved via the
    /// XDP_LOCAL_* map value bits[2:1]).
    #[serde(rename = "fragmentAction", default)]
    pub fragment_action: Option<XdpFragmentAction>,
}

fn default_true() -> bool {
    true
}

/// A single UDP direct-forward rule applied at the XDP layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct XdpUdpForwardConfig {
    /// Local listen address, e.g. "192.0.2.10:5353" or "0.0.0.0:5353".
    pub listen: std::net::SocketAddr,
    /// Backend target, e.g. "10.0.0.5:5353" (hostnames resolve at sync time).
    pub backend: String,
    /// Optional explicit next-hop MAC for the backend; when empty it is
    /// resolved from the neighbor table at sync time.
    #[serde(rename = "nextHopMac", default)]
    pub next_hop_mac: String,
    /// Billing dimension for flow accounting.
    #[serde(rename = "serverId", default)]
    pub server_id: i64,
    /// Rewrite forwarded frames' source to the listen address plus a
    /// node-allocated port. Required on fabrics that drop egress frames whose
    /// source IP is not bound to this port (cloud vSwitch anti-spoof).
    /// Default false = plain DNAT preserving the client IP.
    #[serde(rename = "snat", default)]
    pub snat: bool,
}

impl Default for XdpInterfaceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            queues: Vec::new(),
            cpus: Vec::new(),
            mode: XdpRuntimeMode::default(),
            local_ips: Vec::new(),
            frame_size: default_xdp_frame_size(),
            udp_forwards: Vec::new(),
            tcp_forwards: Vec::new(),
            fragment_action: XdpFragmentAction::default(),
            protected_services: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct XdpProxyConfig {
    #[serde(default = "default_xdp_proxy_protocols")]
    pub protocols: Vec<XdpProxyProtocol>,
    #[serde(default)]
    pub ports: Vec<XdpProxyPortConfig>,
}

impl Default for XdpProxyConfig {
    fn default() -> Self {
        Self {
            protocols: default_xdp_proxy_protocols(),
            ports: Vec::new(),
        }
    }
}

fn default_xdp_rate_limit_window_ms() -> u64 {
    1000
}

/// Base per-IP fixed-window limits for the eBPF limiter. Userspace scales
/// these down under elevated pressure (Elevated: x1, High: /2, Critical: /4)
/// and disables the limiter entirely at Normal pressure. `0` disables the
/// limit for that protocol.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct XdpRateLimitSettings {
    #[serde(rename = "udpPps", default)]
    pub udp_pps: u64,
    #[serde(rename = "tcpSynPps", default)]
    pub tcp_syn_pps: u64,
    #[serde(rename = "windowMs", default = "default_xdp_rate_limit_window_ms")]
    pub window_ms: u64,
}

impl Default for XdpRateLimitSettings {
    fn default() -> Self {
        Self {
            udp_pps: 0,
            tcp_syn_pps: 0,
            window_ms: default_xdp_rate_limit_window_ms(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct XdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(rename = "attachMode", default)]
    pub attach_mode: XdpAttachMode,
    #[serde(default)]
    pub fallback: XdpFallbackMode,
    #[serde(default)]
    pub interfaces: Vec<XdpInterfaceConfig>,
    #[serde(default)]
    pub proxy: XdpProxyConfig,
    #[serde(rename = "rateLimit", default)]
    pub rate_limit: Option<XdpRateLimitSettings>,
    /// Explicit path to an external eBPF object. When unset, the binary uses
    /// the object embedded at build time (recommended: binary and program can
    /// never drift apart). Set only for eBPF hotfix/debugging.
    #[serde(rename = "ebpfObject", default)]
    pub ebpf_object: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_cluster_type")]
    pub r#type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(rename = "serviceName", default)]
    pub service_name: String,
    #[serde(rename = "podNameEnv", default = "default_pod_name_env")]
    pub pod_name_env: String,
    #[serde(rename = "podIpEnv", default = "default_pod_ip_env")]
    pub pod_ip_env: String,
    #[serde(rename = "internalApi", default)]
    pub internal_api: InternalApiConfig,
    #[serde(rename = "leaderElection", default)]
    pub leader_election: LeaderElectionConfig,
    #[serde(default)]
    pub cache: ClusterCacheConfig,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            r#type: default_cluster_type(),
            name: String::new(),
            namespace: String::new(),
            service_name: String::new(),
            pod_name_env: default_pod_name_env(),
            pod_ip_env: default_pod_ip_env(),
            internal_api: InternalApiConfig::default(),
            leader_election: LeaderElectionConfig::default(),
            cache: ClusterCacheConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternalApiConfig {
    #[serde(default = "default_internal_api_bind")]
    pub bind: String,
    #[serde(rename = "tokenEnv", default = "default_internal_token_env")]
    pub token_env: String,
}

impl Default for InternalApiConfig {
    fn default() -> Self {
        Self {
            bind: default_internal_api_bind(),
            token_env: default_internal_token_env(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaderElectionConfig {
    #[serde(rename = "leaseName", default = "default_lease_name")]
    pub lease_name: String,
    #[serde(
        rename = "leaseDurationSeconds",
        default = "default_lease_duration_seconds"
    )]
    pub lease_duration_seconds: u64,
    #[serde(
        rename = "renewDeadlineSeconds",
        default = "default_renew_deadline_seconds"
    )]
    pub renew_deadline_seconds: u64,
    #[serde(
        rename = "retryPeriodSeconds",
        default = "default_retry_period_seconds"
    )]
    pub retry_period_seconds: u64,
}

impl Default for LeaderElectionConfig {
    fn default() -> Self {
        Self {
            lease_name: default_lease_name(),
            lease_duration_seconds: default_lease_duration_seconds(),
            renew_deadline_seconds: default_renew_deadline_seconds(),
            retry_period_seconds: default_retry_period_seconds(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClusterCacheConfig {
    #[serde(rename = "localMetaDir", default)]
    pub local_meta_dir: PathBuf,
    #[serde(rename = "maxFastL1Bytes", default)]
    pub max_fast_l1_bytes: u64,
    #[serde(rename = "sharedMaxBytes", default)]
    pub shared_max_bytes: String,
    #[serde(rename = "minFreeBytes", default)]
    pub min_free_bytes: String,
    #[serde(rename = "ignoreControlPlaneStorageOptions", default)]
    pub ignore_control_plane_storage_options: bool,
    #[serde(rename = "shardStrategy", default = "default_shard_strategy")]
    pub shard_strategy: String,
    #[serde(default)]
    pub shards: Vec<ClusterCacheShardConfig>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClusterCacheShardConfig {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub path: PathBuf,
    #[serde(default = "default_shard_weight")]
    pub weight: u32,
    #[serde(default = "default_longhorn_replicas")]
    pub replicas: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub runtime: RuntimeSection,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub xdp: XdpConfig,
}

impl RuntimeConfig {
    pub fn load_default() -> anyhow::Result<Self> {
        let node_paths = crate::paths::NodePaths::current();
        let config_path = node_paths.runtime_config_file();
        // Read the file twice: once as a raw value to learn whether the
        // operator explicitly set `xdp.enabled` (an absent key must not
        // override the environment), and once into the typed config.
        let mut file_xdp_enabled = None;
        let mut config = if config_path.exists() {
            tracing::info!("Loading runtime config from: {}", config_path.display());
            let content = std::fs::read_to_string(&config_path)?;
            file_xdp_enabled = serde_yaml::from_str::<serde_yaml::Value>(&content)
                .ok()
                .and_then(|root| {
                    root.get("xdp")
                        .and_then(|xdp| xdp.get("enabled"))
                        .and_then(|enabled| enabled.as_bool())
                });
            serde_yaml::from_str(&content)?
        } else {
            Self::default()
        };

        if let Ok(mode) = std::env::var("CLOUD_NODE_MODE") {
            config.runtime.mode = RuntimeMode::from_env_value(&mode)?;
            if config.runtime.mode.is_rke2() {
                config.cluster.enabled = true;
                if config.cluster.r#type.is_empty() {
                    config.cluster.r#type = default_cluster_type();
                }
            }
        }

        // XDP is enabled unless told otherwise. Precedence, weakest first:
        // built-in default (on) < CLOUD_NODE_XDP env var < explicit
        // `xdp.enabled` in the config file. Everything else about the
        // dataplane is auto-derived at attach time, so a missing file never
        // needs to be generated.
        let xdp_enabled = match file_xdp_enabled {
            Some(value) => Some(value),
            None => Self::xdp_enabled_from_env()?,
        };
        config.xdp.enabled = xdp_enabled.unwrap_or(true);
        if config.is_rke2() {
            // Cluster mode never runs the XDP dataplane: AF_XDP owns the NIC
            // queues and would starve Kubernetes networking on the node.
            config.xdp.enabled = false;
        }

        config.validate()?;
        Ok(config)
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    fn xdp_enabled_from_env() -> anyhow::Result<Option<bool>> {
        let Ok(value) = std::env::var("CLOUD_NODE_XDP") else {
            return Ok(None);
        };
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "1" | "true" | "on" | "yes" | "enable" | "enabled" => Ok(Some(true)),
            "0" | "false" | "off" | "no" | "disable" | "disabled" => Ok(Some(false)),
            other => anyhow::bail!("unsupported CLOUD_NODE_XDP value: {other}"),
        }
    }

    pub fn set_current(config: RuntimeConfig) {
        let current = RUNTIME_CONFIG.get_or_init(|| parking_lot::RwLock::new(None));
        *current.write() = Some(config);
    }

    pub fn current() -> Option<RuntimeConfig> {
        RUNTIME_CONFIG
            .get()
            .and_then(|config| config.read().clone())
    }

    pub fn current_mode() -> RuntimeMode {
        Self::current()
            .map(|config| config.mode())
            .unwrap_or_default()
    }

    pub fn current_is_rke2() -> bool {
        Self::current_mode().is_rke2()
    }

    pub fn mode(&self) -> RuntimeMode {
        self.runtime.mode
    }

    pub fn is_rke2(&self) -> bool {
        self.mode().is_rke2()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.validate_xdp()?;

        if !self.is_rke2() {
            return Ok(());
        }

        self.validate_cluster_cache_paths()?;

        if !self.cluster.enabled {
            anyhow::bail!("runtime.mode=rke2 requires cluster.enabled=true");
        }
        if self.cluster.r#type != "rke2" {
            anyhow::bail!("runtime.mode=rke2 requires cluster.type=rke2");
        }
        if self.cluster.name.trim().is_empty() {
            anyhow::bail!("runtime.mode=rke2 requires cluster.name");
        }
        if self.cluster.namespace.trim().is_empty() {
            anyhow::bail!("runtime.mode=rke2 requires cluster.namespace");
        }
        if self.cluster.service_name.trim().is_empty() {
            anyhow::bail!("runtime.mode=rke2 requires cluster.serviceName");
        }
        if self.cluster.cache.local_meta_dir.as_os_str().is_empty() {
            anyhow::bail!("runtime.mode=rke2 requires cluster.cache.localMetaDir");
        }
        if self.cluster.cache.shards.is_empty() {
            anyhow::bail!("runtime.mode=rke2 requires at least one cluster.cache.shards entry");
        }
        if self.cluster.internal_api.token_env.trim().is_empty() {
            anyhow::bail!("runtime.mode=rke2 requires cluster.internalApi.tokenEnv");
        }
        if std::env::var(&self.cluster.internal_api.token_env)
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            anyhow::bail!(
                "runtime.mode=rke2 requires non-empty {} environment variable",
                self.cluster.internal_api.token_env
            );
        }
        require_env(&self.cluster.pod_name_env, "pod name")?;
        require_env(&self.cluster.pod_ip_env, "pod ip")?;

        for shard in &self.cluster.cache.shards {
            if shard.id.trim().is_empty() {
                anyhow::bail!("runtime.mode=rke2 requires every cache shard to have an id");
            }
            if shard.path.as_os_str().is_empty() {
                anyhow::bail!("runtime.mode=rke2 requires every cache shard to have a path");
            }
            if shard.weight == 0 {
                anyhow::bail!("cache shard {} has invalid weight=0", shard.id);
            }
            if !(1..=3).contains(&shard.replicas) {
                anyhow::bail!("cache shard {} replicas must be 1, 2, or 3", shard.id);
            }
        }

        Ok(())
    }

    fn validate_xdp(&self) -> anyhow::Result<()> {
        if !self.xdp.enabled {
            return Ok(());
        }
        for interface in &self.xdp.interfaces {
            if interface.name.trim().is_empty() {
                anyhow::bail!("xdp.interfaces entries require name");
            }
            if interface.queues.is_empty() {
                anyhow::bail!(
                    "xdp interface {} requires at least one queue",
                    interface.name
                );
            }
            if interface.frame_size < 1024 || interface.frame_size > 4096 {
                anyhow::bail!(
                    "xdp interface {} frameSize must be between 1024 and 4096",
                    interface.name
                );
            }
            if interface.frame_size % 512 != 0 {
                anyhow::bail!(
                    "xdp interface {} frameSize must be a multiple of 512",
                    interface.name
                );
            }
            let mut seen_vips = std::collections::HashSet::new();
            for entry in &interface.protected_services {
                if !interface.local_ips.contains(&entry.ip) {
                    anyhow::bail!(
                        "xdp interface {} protectedServices ip {} is not listed in localIps",
                        interface.name,
                        entry.ip
                    );
                }
                if !seen_vips.insert(entry.ip) {
                    anyhow::bail!(
                        "xdp interface {} protectedServices has a duplicate entry for {}",
                        interface.name,
                        entry.ip
                    );
                }
            }
        }
        for port in &self.xdp.proxy.ports {
            if port.port == 0 {
                anyhow::bail!("xdp.proxy.ports entries require a non-zero port");
            }
            if !self.xdp.proxy.protocols.contains(&port.protocol) {
                anyhow::bail!(
                    "xdp.proxy.ports entry {}:{} is not enabled in xdp.proxy.protocols",
                    port.protocol.as_str(),
                    port.port
                );
            }
        }
        Ok(())
    }

    fn validate_cluster_cache_paths(&self) -> anyhow::Result<()> {
        let local_meta_dir = &self.cluster.cache.local_meta_dir;
        if local_meta_dir.as_os_str().is_empty() {
            return Ok(());
        }

        for shard in &self.cluster.cache.shards {
            if shard.path.as_os_str().is_empty() {
                continue;
            }
            if local_meta_dir.starts_with(&shard.path) {
                anyhow::bail!(
                    "cluster.cache.localMetaDir must not be inside shared cache shard {} ({})",
                    shard.id,
                    shard.path.display()
                );
            }
        }
        Ok(())
    }
}

fn require_env(name: &str, label: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("runtime.mode=rke2 requires {label} env name");
    }
    if std::env::var(name)
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        anyhow::bail!("runtime.mode=rke2 requires non-empty {name} environment variable");
    }
    Ok(())
}

fn default_xdp_frame_size() -> u32 {
    cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE
}

fn default_xdp_proxy_protocols() -> Vec<XdpProxyProtocol> {
    vec![
        XdpProxyProtocol::Http,
        XdpProxyProtocol::Https,
        XdpProxyProtocol::Tcp,
        XdpProxyProtocol::Udp,
        XdpProxyProtocol::H3,
    ]
}

fn default_cluster_type() -> String {
    "rke2".to_string()
}

fn default_pod_name_env() -> String {
    DEFAULT_POD_NAME_ENV.to_string()
}

fn default_pod_ip_env() -> String {
    DEFAULT_POD_IP_ENV.to_string()
}

fn default_internal_api_bind() -> String {
    "0.0.0.0:19090".to_string()
}

fn default_internal_token_env() -> String {
    DEFAULT_INTERNAL_TOKEN_ENV.to_string()
}

fn default_lease_name() -> String {
    "cloud-node-leader".to_string()
}

fn default_lease_duration_seconds() -> u64 {
    15
}

fn default_renew_deadline_seconds() -> u64 {
    10
}

fn default_retry_period_seconds() -> u64 {
    2
}

fn default_shard_strategy() -> String {
    "hash_mod".to_string()
}

fn default_shard_weight() -> u32 {
    1
}

fn default_longhorn_replicas() -> u32 {
    2
}

#[cfg(test)]
pub(crate) fn runtime_config_test_guard() -> parking_lot::MutexGuard<'static, ()> {
    RUNTIME_CONFIG_TEST_LOCK
        .get_or_init(|| parking_lot::Mutex::new(()))
        .lock()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdp_runtime_current_replaces_previous_config() {
        let _guard = runtime_config_test_guard();
        RuntimeConfig::set_current(RuntimeConfig::default());
        assert!(!RuntimeConfig::current().unwrap().xdp.enabled);

        RuntimeConfig::set_current(RuntimeConfig {
            xdp: XdpConfig {
                enabled: true,
                interfaces: vec![XdpInterfaceConfig {
                    name: "eth0".to_string(),
                    queues: vec![0],
                    cpus: Vec::new(),
                    mode: XdpRuntimeMode::Proxy,
                    ..Default::default()
                }],
                proxy: XdpProxyConfig {
                    ports: vec![XdpProxyPortConfig {
                        protocol: XdpProxyProtocol::Udp,
                        port: 443,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        });

        let current = RuntimeConfig::current().unwrap();
        assert!(current.xdp.enabled);
        assert_eq!(current.xdp.interfaces[0].name, "eth0");
        assert_eq!(current.xdp.proxy.ports[0].port, 443);
    }

    #[test]
    fn xdp_runtime_config_deserializes_proxy_ports() {
        let _guard = runtime_config_test_guard();
        let config: RuntimeConfig = serde_yaml::from_str(
            r#"
xdp:
  enabled: true
  interfaces:
    - name: eth0
      queues: [0]
      mode: proxy
  proxy:
    protocols: ["https", "h3"]
    ports:
      - protocol: https
        port: 443
      - protocol: h3
        port: 443
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.xdp.proxy.ports.len(), 2);
        assert_eq!(config.xdp.proxy.ports[0].protocol, XdpProxyProtocol::Https);
        assert_eq!(config.xdp.proxy.ports[1].protocol, XdpProxyProtocol::H3);
    }

    #[test]
    fn xdp_runtime_config_allows_empty_interfaces_for_auto_derivation() {
        let config: RuntimeConfig = serde_yaml::from_str(
            r#"
xdp:
  enabled: true
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert!(config.xdp.interfaces.is_empty());
    }

    #[test]
    fn xdp_runtime_config_rejects_disabled_proxy_port_protocol() {
        let _guard = runtime_config_test_guard();
        let config: RuntimeConfig = serde_yaml::from_str(
            r#"
xdp:
  enabled: true
  interfaces:
    - name: eth0
      queues: [0]
  proxy:
    protocols: ["tcp"]
    ports:
      - protocol: udp
        port: 53
"#,
        )
        .unwrap();

        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("not enabled in xdp.proxy.protocols"));
    }

    #[test]
    fn xdp_protected_service_deserializes_and_validates() {
        let _guard = runtime_config_test_guard();
        let config: RuntimeConfig = serde_yaml::from_str(
            r#"
xdp:
  enabled: true
  interfaces:
    - name: eth0
      queues: [0]
      localIps: ["10.0.0.5", "10.0.0.6"]
      protectedServices:
        - ip: "10.0.0.6"
          redirect: false
          fragmentAction: drop
"#,
        )
        .unwrap();
        config.validate().unwrap();
        let svc = &config.xdp.interfaces[0].protected_services[0];
        assert!(!svc.redirect);
        assert_eq!(
            svc.fragment_action,
            Some(crate::runtime_mode::XdpFragmentAction::Drop)
        );

        // ip outside localIps is rejected
        let bad: RuntimeConfig = serde_yaml::from_str(
            r#"
xdp:
  enabled: true
  interfaces:
    - name: eth0
      queues: [0]
      localIps: ["10.0.0.5"]
      protectedServices:
        - ip: "10.0.0.9"
"#,
        )
        .unwrap();
        let err = bad.validate().unwrap_err().to_string();
        assert!(err.contains("not listed in localIps"));

        // duplicates are rejected
        let dup: RuntimeConfig = serde_yaml::from_str(
            r#"
xdp:
  enabled: true
  interfaces:
    - name: eth0
      queues: [0]
      localIps: ["10.0.0.5"]
      protectedServices:
        - ip: "10.0.0.5"
        - ip: "10.0.0.5"
"#,
        )
        .unwrap();
        let err = dup.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate"));
    }

    struct XdpEnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl XdpEnvGuard {
        fn apply(home: &std::path::Path, vars: &[(&'static str, Option<&str>)]) -> Self {
            let mut saved = vec![("CLOUD_NODE_HOME", std::env::var_os("CLOUD_NODE_HOME"))];
            unsafe {
                std::env::set_var("CLOUD_NODE_HOME", home);
            }
            for (key, value) in vars {
                saved.push((key, std::env::var_os(key)));
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
            Self { saved }
        }
    }

    impl Drop for XdpEnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    fn xdp_home(contents: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cloud-node-xdp-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if let Some(contents) = contents {
            std::fs::create_dir_all(dir.join("configs")).unwrap();
            std::fs::write(dir.join("configs").join("runtime.yaml"), contents).unwrap();
        } else {
            std::fs::create_dir_all(&dir).unwrap();
        }
        dir
    }

    fn load_xdp_enabled(
        file: Option<&str>,
        vars: &[(&'static str, Option<&str>)],
    ) -> anyhow::Result<bool> {
        let home = xdp_home(file);
        let _env = XdpEnvGuard::apply(&home, vars);
        let enabled = RuntimeConfig::load_default().map(|config| config.xdp.enabled);
        std::fs::remove_dir_all(&home).ok();
        enabled
    }

    fn xdp_var(value: &str) -> (&'static str, Option<&str>) {
        ("CLOUD_NODE_XDP", Some(value))
    }

    const NO_XDP_ENV: (&'static str, Option<&'static str>) = ("CLOUD_NODE_XDP", None);
    const NO_MODE_ENV: (&'static str, Option<&'static str>) = ("CLOUD_NODE_MODE", None);

    #[test]
    fn xdp_enabled_precedence_default_env_file() {
        let _guard = runtime_config_test_guard();
        let clear = &[NO_XDP_ENV, NO_MODE_ENV];

        // No file, no env: default enabled.
        assert!(load_xdp_enabled(None, clear).unwrap());
        // No file: env toggles.
        assert!(!load_xdp_enabled(None, &[xdp_var("0"), NO_MODE_ENV]).unwrap());
        assert!(load_xdp_enabled(None, &[xdp_var("true"), NO_MODE_ENV]).unwrap());
        // File without xdp.enabled: env still applies.
        assert!(!load_xdp_enabled(Some("cluster: {}\n"), &[xdp_var("off"), NO_MODE_ENV]).unwrap());
        assert!(load_xdp_enabled(Some("xdp: {}\n"), clear).unwrap());
        // File is the final authority in both directions.
        assert!(
            load_xdp_enabled(
                Some("xdp:\n  enabled: true\n"),
                &[xdp_var("0"), NO_MODE_ENV]
            )
            .unwrap()
        );
        assert!(
            !load_xdp_enabled(
                Some("xdp:\n  enabled: false\n"),
                &[xdp_var("1"), NO_MODE_ENV]
            )
            .unwrap()
        );
        assert!(!load_xdp_enabled(Some("xdp:\n  enabled: false\n"), clear).unwrap());
        // Garbage env values are an explicit error, not a silent default.
        assert!(load_xdp_enabled(None, &[xdp_var("maybe"), NO_MODE_ENV]).is_err());
    }

    #[test]
    fn xdp_enabled_forced_off_in_rke2_mode() {
        let _guard = runtime_config_test_guard();
        let file = r#"
cluster:
  enabled: true
  type: rke2
  name: prod
  namespace: cloud-node
  serviceName: cloud-node
  cache:
    localMetaDir: /tmp/meta
    shards:
      - id: s0
        path: /tmp/shard0
        weight: 1
        replicas: 1
"#;
        let vars = &[
            xdp_var("1"),
            ("CLOUD_NODE_MODE", Some("rke2")),
            ("CLOUD_NODE_CLUSTER_INTERNAL_TOKEN", Some("token")),
            ("POD_NAME", Some("pod-0")),
            ("POD_IP", Some("10.0.0.1")),
        ];
        assert!(!load_xdp_enabled(Some(file), vars).unwrap());
    }

    #[test]
    fn xdp_save_xdp_enabled_preserves_other_keys() {
        let _guard = runtime_config_test_guard();
        let home = xdp_home(Some(
            "runtime:\n  mode: standalone\ncluster:\n  name: prod\nxdp:\n  enabled: false\n  attachMode: drv\n",
        ));
        let path = home.join("configs").join("runtime.yaml");
        crate::xdp_config_wizard::save_xdp_enabled(&path, true).unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        assert_eq!(value["xdp"]["enabled"].as_bool(), Some(true));
        assert!(value["xdp"]["attachMode"].is_null());
        assert_eq!(value["cluster"]["name"].as_str(), Some("prod"));
        std::fs::remove_dir_all(&home).ok();
    }
}
