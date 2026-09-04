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
    #[serde(default)]
    pub mode: XdpRuntimeMode,
    #[serde(rename = "localIps", default)]
    pub local_ips: Vec<std::net::IpAddr>,
    #[serde(rename = "frameSize", default = "default_xdp_frame_size")]
    pub frame_size: u32,
}

impl Default for XdpInterfaceConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            queues: Vec::new(),
            mode: XdpRuntimeMode::default(),
            local_ips: Vec::new(),
            frame_size: default_xdp_frame_size(),
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
        let mut config = if config_path.exists() {
            tracing::info!("Loading runtime config from: {}", config_path.display());
            Self::load(&config_path)?
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

        config.validate()?;
        Ok(config)
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
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
}
