use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock as Lazy;
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
    #[serde(rename = "relay", default)]
    pub relay: RelayConfig,
    #[serde(rename = "kernelTuning", default)]
    pub kernel_tuning: KernelTuningConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KernelTuningConfig {
    #[serde(rename = "enabled", default = "default_kernel_tuning_enabled")]
    pub enabled: bool,
}

impl Default for KernelTuningConfig {
    fn default() -> Self {
        Self {
            enabled: default_kernel_tuning_enabled(),
        }
    }
}

impl KernelTuningConfig {
    pub fn normalized(&self) -> Self {
        Self {
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RelayConfig {
    #[serde(rename = "zeroCopy", default)]
    pub zero_copy: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self { zero_copy: false }
    }
}

impl RelayConfig {
    pub fn normalized(&self) -> Self {
        Self {
            zero_copy: self.zero_copy,
        }
    }
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

const MAX_ACCESS_LOG_UPLOAD_CONCURRENCY: usize = 32;

impl AccessLogPipelineConfig {
    pub fn normalized(&self) -> Self {
        let batch_size = self.batch_size.max(1);
        let queue_capacity = self.queue_capacity.max(batch_size);
        let upload_concurrency = if self.upload_concurrency == 0 {
            auto_access_log_upload_concurrency(queue_capacity, batch_size)
        } else {
            self.upload_concurrency
        }
        .clamp(1, MAX_ACCESS_LOG_UPLOAD_CONCURRENCY);
        Self {
            queue_capacity,
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

    pub fn batch_queue_capacity(&self) -> usize {
        let batch_size = self.batch_size.max(1);
        ceil_div(self.queue_capacity.max(batch_size), batch_size)
            .max(self.upload_concurrency.saturating_mul(2))
            .max(1)
    }
}

fn ceil_div(value: usize, divisor: usize) -> usize {
    value.saturating_add(divisor.saturating_sub(1)) / divisor.max(1)
}

fn auto_access_log_upload_concurrency(queue_capacity: usize, batch_size: usize) -> usize {
    let queue_batches = ceil_div(queue_capacity, batch_size).max(1);
    let cpu_parallelism = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    queue_batches
        .min(cpu_parallelism.saturating_mul(2).max(1))
        .clamp(1, MAX_ACCESS_LOG_UPLOAD_CONCURRENCY)
}

fn default_access_log_queue_capacity() -> usize {
    crate::memory_governor::MEMORY_GOVERNOR.access_log_queue_capacity()
}

fn default_access_log_batch_size() -> usize {
    crate::memory_governor::MEMORY_GOVERNOR.access_log_batch_size()
}

fn default_access_log_flush_interval_ms() -> u64 {
    5_000
}

fn default_access_log_upload_concurrency() -> usize {
    0
}

fn default_access_log_request_timeout_ms() -> u64 {
    30_000
}

fn default_access_log_warning_interval_ms() -> u64 {
    5_000
}

fn default_kernel_tuning_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_access_log_pipeline_uses_auto_upload_concurrency() {
        let normalized = AccessLogPipelineConfig::default().normalized();

        assert!(normalized.upload_concurrency > 1);
        assert!(normalized.upload_concurrency <= MAX_ACCESS_LOG_UPLOAD_CONCURRENCY);
        assert_eq!(
            normalized.queue_capacity,
            crate::memory_governor::MEMORY_GOVERNOR
                .access_log_queue_capacity()
                .max(crate::memory_governor::MEMORY_GOVERNOR.access_log_batch_size())
        );
        assert_eq!(
            normalized.batch_queue_capacity(),
            ceil_div(normalized.queue_capacity, normalized.batch_size)
                .max(normalized.upload_concurrency * 2)
        );
    }

    #[test]
    fn explicit_access_log_upload_concurrency_is_respected() {
        let config = AccessLogPipelineConfig {
            upload_concurrency: 3,
            ..Default::default()
        }
        .normalized();

        assert_eq!(config.upload_concurrency, 3);
    }

    #[test]
    fn batch_queue_capacity_covers_main_queue_batches() {
        let config = AccessLogPipelineConfig {
            queue_capacity: 250_001,
            batch_size: 10_000,
            upload_concurrency: 2,
            ..Default::default()
        }
        .normalized();

        assert_eq!(config.batch_queue_capacity(), 26);
    }

    #[test]
    fn relay_config_defaults_to_stable_copy_path() {
        let config = RelayConfig::default().normalized();

        assert!(!config.zero_copy);
    }

    #[test]
    fn kernel_tuning_defaults_to_enabled_for_legacy_config() {
        let config: ApiConfig = serde_yaml::from_str(
            r#"
rpc.endpoints:
  - https://api.example.com
nodeId: "1"
secret: "secret"
"#,
        )
        .unwrap();

        assert!(config.kernel_tuning.normalized().enabled);
    }

    #[test]
    fn kernel_tuning_can_be_disabled() {
        let config: ApiConfig = serde_yaml::from_str(
            r#"
rpc.endpoints:
  - https://api.example.com
nodeId: "1"
secret: "secret"
kernelTuning:
  enabled: false
"#,
        )
        .unwrap();

        assert!(!config.kernel_tuning.normalized().enabled);
    }

    #[test]
    fn remote_plaintext_rpc_endpoint_remains_supported() {
        let endpoint = "http://36.134.185.75:8001";

        assert_eq!(validate_rpc_endpoint(endpoint).unwrap(), endpoint);
    }
}

impl ApiConfig {
    pub fn default_paths() -> Vec<PathBuf> {
        crate::paths::NodePaths::current().api_config_candidates()
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = fs::read_to_string(&path)?;
        let mut config: ApiConfig = serde_yaml::from_str(&content)?;
        config.rpc_endpoints = validate_rpc_endpoints(config.rpc_endpoints)?;
        if config.rpc_endpoints.is_empty() {
            anyhow::bail!("no valid 'rpc.endpoints' in {:?}", path.as_ref());
        }
        if config.node_id.is_empty() {
            anyhow::bail!("'nodeId' required in {:?}", path.as_ref());
        }
        if config.secret.is_empty() {
            anyhow::bail!("'secret' required in {:?}", path.as_ref());
        }
        Self::set_runtime_rpc_endpoints(config.rpc_endpoints.clone())?;
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

    pub fn set_runtime_rpc_endpoints(endpoints: Vec<String>) -> anyhow::Result<()> {
        let endpoints = validate_rpc_endpoints(endpoints)?;
        if endpoints.is_empty() {
            anyhow::bail!("no valid RPC endpoints supplied");
        }
        if let Ok(mut guard) = RUNTIME_RPC_ENDPOINTS.write() {
            *guard = Some(endpoints);
        }
        Ok(())
    }
}

pub fn validate_rpc_endpoint(endpoint: &str) -> anyhow::Result<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        anyhow::bail!("RPC endpoint is empty");
    }
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid RPC endpoint {endpoint:?}: {err}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("RPC endpoint {endpoint:?} has no scheme"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("RPC endpoint {endpoint:?} has no host"))?;
    if uri.path_and_query().is_some_and(|value| value.as_str() != "/") {
        anyhow::bail!("RPC endpoint {endpoint:?} must not contain a path or query");
    }
    if authority.as_str().contains('@') {
        anyhow::bail!("RPC endpoint {endpoint:?} must not contain userinfo");
    }
    if !matches!(scheme, "http" | "https") {
        anyhow::bail!("RPC endpoint {endpoint:?} uses unsupported scheme {scheme:?}");
    }
    // Plain HTTP/2 gRPC remains supported for legacy control planes. Deployments
    // should protect remote plaintext endpoints with a private network or tunnel.
    Ok(endpoint.trim_end_matches('/').to_string())
}

pub fn validate_rpc_endpoints(endpoints: Vec<String>) -> anyhow::Result<Vec<String>> {
    let mut normalized = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let endpoint = validate_rpc_endpoint(&endpoint)?;
        if !normalized.contains(&endpoint) {
            normalized.push(endpoint);
        }
    }
    Ok(normalized)
}
