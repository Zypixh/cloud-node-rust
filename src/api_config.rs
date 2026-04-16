use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
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
}

impl ApiConfig {
    pub fn default_paths() -> Vec<String> {
        vec![
            "../configs/api_node.yaml".to_string(),
            "configs/api_node.yaml".to_string(),
            "api_node.yaml".to_string(),
            "cloud-node/configs/api_node.yaml".to_string(),
        ]
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
        let paths = Self::default_paths();
        for path in &paths {
            if Path::new(path).exists() {
                tracing::info!("Loading config from: {}", path);
                return Self::load(path);
            }
        }
        anyhow::bail!("no config file found in default paths: {:?}", paths)
    }

    pub fn write_default(&self) -> anyhow::Result<()> {
        let target = Self::default_paths()
            .into_iter()
            .find(|path| Path::new(path).parent().map(|p| p.exists()).unwrap_or(true))
            .unwrap_or_else(|| "api_node.yaml".to_string());
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
