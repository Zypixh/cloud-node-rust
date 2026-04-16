use crate::api_config::ApiConfig;
use crate::pb;
use crate::rpc::client::RpcClient;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

fn script_config_path() -> PathBuf {
    PathBuf::from("runtime").join("script_configs.json")
}

pub async fn start_script_syncer(api_config: ApiConfig) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
    loop {
        interval.tick().await;
        let _ = sync_script_configs(&api_config).await;
    }
}

pub async fn sync_script_configs(api_config: &ApiConfig) -> bool {
    let client = match RpcClient::new(api_config).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to connect for script config sync: {}", e);
            return false;
        }
    };
    let mut service = client.script_service();

    match service
        .compose_script_configs(pb::ComposeScriptConfigsRequest {})
        .await
    {
        Ok(resp) => {
            let payload = resp.into_inner().script_configs_json;
            let path = script_config_path();

            if payload.is_empty() {
                if path.exists()
                    && let Err(e) = fs::remove_file(&path) {
                        warn!(
                            "Failed to remove stale script config file {:?}: {}",
                            path, e
                        );
                    }
                return true;
            }

            if let Some(parent) = path.parent()
                && let Err(e) = fs::create_dir_all(parent) {
                    warn!(
                        "Failed to create script config directory {:?}: {}",
                        parent, e
                    );
                    return false;
                }

            match fs::write(&path, payload) {
                Ok(_) => {
                    info!("Updated local script config snapshot at {:?}", path);
                    true
                }
                Err(e) => {
                    warn!("Failed to write script config snapshot {:?}: {}", path, e);
                    false
                }
            }
        }
        Err(e) => {
            debug!("Failed to compose script configs: {}", e);
            false
        }
    }
}
