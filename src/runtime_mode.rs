use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock as OnceCell;

static RUNTIME_CONFIG: OnceCell<RuntimeConfig> = OnceCell::new();

const DEFAULT_INTERNAL_TOKEN_ENV: &str = "CLOUD_NODE_CLUSTER_INTERNAL_TOKEN";
const DEFAULT_POD_NAME_ENV: &str = "POD_NAME";
const DEFAULT_POD_IP_ENV: &str = "POD_IP";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    Standalone,
    Rke2,
}

impl Default for RuntimeMode {
    fn default() -> Self {
        Self::Standalone
    }
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
        let _ = RUNTIME_CONFIG.set(config);
    }

    pub fn current() -> Option<&'static RuntimeConfig> {
        RUNTIME_CONFIG.get()
    }

    pub fn current_mode() -> RuntimeMode {
        Self::current().map(Self::mode).unwrap_or_default()
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
