use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

static RUNTIME_RPC_ENDPOINTS: Lazy<RwLock<Option<Vec<String>>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiConfig {
    #[serde(rename = "rpc.endpoints", default)]
    pub rpc_endpoints: Vec<String>,
    #[serde(rename = "rpc.disableUpdate", default)]
    pub rpc_disable_update: bool,
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "secret")]
    pub secret: String,
    #[serde(rename = "billing.countInboundTraffic", default)]
    pub billing_count_inbound_traffic: bool,
    #[serde(rename = "accessLogPipeline", default)]
    pub access_log_pipeline: AccessLogPipelineConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessLogPipelineConfig {
    #[serde(
        rename = "queueCapacity",
        default = "default_access_log_queue_capacity"
    )]
    pub queue_capacity: usize,
    #[serde(rename = "batchSize", default = "default_access_log_batch_size")]
    pub batch_size: usize,
    #[serde(
        rename = "flushIntervalMs",
        default = "default_access_log_flush_interval_ms"
    )]
    pub flush_interval_ms: u64,
    #[serde(
        rename = "uploadConcurrency",
        default = "default_access_log_upload_concurrency"
    )]
    pub upload_concurrency: usize,
    #[serde(rename = "retryQueueCapacity", default)]
    pub retry_queue_capacity: usize,
    #[serde(rename = "targetChunkBytes", default)]
    pub target_chunk_bytes: usize,
    #[serde(
        rename = "requestTimeoutMs",
        default = "default_access_log_request_timeout_ms"
    )]
    pub request_timeout_ms: u64,
    #[serde(
        rename = "warningIntervalMs",
        default = "default_access_log_warning_interval_ms"
    )]
    pub warning_interval_ms: u64,
}

impl Default for AccessLogPipelineConfig {
    fn default() -> Self {
        Self {
            queue_capacity: default_access_log_queue_capacity(),
            batch_size: default_access_log_batch_size(),
            flush_interval_ms: default_access_log_flush_interval_ms(),
            upload_concurrency: default_access_log_upload_concurrency(),
            retry_queue_capacity: 0,
            target_chunk_bytes: 0,
            request_timeout_ms: default_access_log_request_timeout_ms(),
            warning_interval_ms: default_access_log_warning_interval_ms(),
        }
    }
}

impl AccessLogPipelineConfig {
    pub fn normalized(&self) -> Self {
        let batch_size = self.batch_size.max(1);
        let upload_concurrency = self.upload_concurrency.max(1).min(32);
        Self {
            queue_capacity: self.queue_capacity.max(batch_size),
            batch_size,
            flush_interval_ms: self.flush_interval_ms.max(100),
            upload_concurrency,
            retry_queue_capacity: if self.retry_queue_capacity == 0 {
                batch_size
                    .saturating_mul(upload_concurrency)
                    .saturating_mul(10)
            } else {
                self.retry_queue_capacity.max(batch_size)
            },
            target_chunk_bytes: self.target_chunk_bytes,
            request_timeout_ms: self.request_timeout_ms.max(1000),
            warning_interval_ms: self.warning_interval_ms.max(1000),
        }
    }
}

fn default_access_log_queue_capacity() -> usize {
    100_000
}

fn default_access_log_batch_size() -> usize {
    10_000
}

fn default_access_log_flush_interval_ms() -> u64 {
    5_000
}

fn default_access_log_upload_concurrency() -> usize {
    1
}

fn default_access_log_request_timeout_ms() -> u64 {
    30_000
}

fn default_access_log_warning_interval_ms() -> u64 {
    5_000
}

impl ApiConfig {
    pub fn default_paths() -> Vec<PathBuf> {
        crate::paths::NodePaths::current().api_config_candidates()
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = fs::read_to_string(&path)?;
        let config: ApiConfig = serde_yaml::from_str(&content)?;
        if config.rpc_endpoints.is_empty() {
            anyhow::bail!("no valid 'rpc.endpoints' in {:?}", path.as_ref());
        }
        if config.node_id.is_empty() {
            anyhow::bail!("'nodeId' required in {:?}", path.as_ref());
        }
        if config.secret.is_empty() {
            anyhow::bail!("'secret' required in {:?}", path.as_ref());
        }
        Self::set_runtime_rpc_endpoints(config.rpc_endpoints.clone());
        Ok(config)
    }

    pub fn load_default() -> anyhow::Result<Self> {
        let node_paths = crate::paths::NodePaths::current();
        let canonical = node_paths.api_config_file();
        let paths = node_paths.api_config_candidates();
        for path in &paths {
            if path.exists() {
                if path != &canonical {
                    tracing::warn!(
                        "Loading API config from legacy path {}. Please migrate it to {}.",
                        path.display(),
                        canonical.display()
                    );
                } else {
                    tracing::info!("Loading config from: {}", path.display());
                }
                return Self::load(path);
            }
        }
        anyhow::bail!("no config file found in default paths: {:?}", paths)
    }

    pub fn write_default(&self) -> anyhow::Result<()> {
        let node_paths = crate::paths::NodePaths::current();
        fs::create_dir_all(node_paths.config_dir())?;
        let target = node_paths.api_config_file();
        let content = serde_yaml::to_string(self)?;
        fs::write(target, content)?;
        Ok(())
    }

    pub fn effective_rpc_endpoints(&self) -> Vec<String> {
        RUNTIME_RPC_ENDPOINTS
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .filter(|endpoints| !endpoints.is_empty())
            .unwrap_or_else(|| self.rpc_endpoints.clone())
    }

    pub fn set_runtime_rpc_endpoints(endpoints: Vec<String>) {
        if let Ok(mut guard) = RUNTIME_RPC_ENDPOINTS.write() {
            *guard = Some(endpoints);
        }
    }
}
