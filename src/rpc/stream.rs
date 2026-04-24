use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::RpcClient;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

#[derive(Debug, serde::Deserialize)]
struct ConnectedAPINodeMessage {
    #[serde(rename = "apiNodeId")]
    api_node_id: i64,
}

#[derive(Debug, serde::Deserialize)]
struct ChangeAPINodeMessage {
    #[serde(rename = "addr")]
    addr: String,
}

#[derive(Debug, serde::Deserialize)]
struct WriteCacheMessage {
    #[serde(rename = "key")]
    key: String,
    #[serde(rename = "value")]
    value: serde_json::Value, // Temporarily hold as Value to handle string or array
    #[serde(rename = "lifeSeconds")]
    _life_seconds: i64,
}

impl WriteCacheMessage {
    fn get_value_bytes(&self) -> Vec<u8> {
        match &self.value {
            serde_json::Value::String(s) => {
                use base64::{Engine as _, engine::general_purpose};
                general_purpose::STANDARD
                    .decode(s)
                    .unwrap_or_else(|_| s.as_bytes().to_vec())
            }
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect(),
            _ => vec![],
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct ReadCacheMessage {
    #[serde(rename = "key")]
    key: String,
}

pub async fn start_node_stream(api_config: ApiConfig, config_store: Arc<ConfigStore>) {
    loop {
        let client = match RpcClient::new(&api_config).await {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "Failed to connect to API node for stream: {}. Retrying in 10s...",
                    e
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        if let Err(e) = run_stream(client, &api_config, config_store.clone()).await {
            warn!("Node stream error: {}. Retrying in 10s...", e);
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
}

async fn run_stream(
    client: RpcClient,
    api_config: &ApiConfig,
    config_store: Arc<ConfigStore>,
) -> anyhow::Result<()> {
    let connected_endpoints = api_config.effective_rpc_endpoints();
    let (tx, rx) = mpsc::channel(100);
    let rx_stream = ReceiverStream::new(rx);

    let mut node_client = client.node_service();
    let response = node_client.node_stream(rx_stream).await?;
    let mut inbound = response.into_inner();

    info!("Node stream established.");

    let mut current_api_node_id = None;
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(60));
    let mut endpoint_check_interval = tokio::time::interval(Duration::from_secs(15));

    loop {
        tokio::select! {
            msg_res = inbound.message() => {
                match msg_res {
                    Ok(Some(message)) => {
                        if message.code == "connectedAPINode" {
                           match serde_json::from_slice::<ConnectedAPINodeMessage>(&message.data_json) {
                               Ok(msg) => {
                                   info!("Successfully connected to API node via stream. API Node ID: {}", msg.api_node_id);
                                   current_api_node_id = Some(msg.api_node_id);
                                   if let Ok(mut guard) = crate::rpc::node::CONNECTED_API_NODE_IDS.write() {
                                       guard.insert(msg.api_node_id);
                                   }
                                   crate::rpc::node::trigger_api_node_report();
                               }
                               Err(e) => {
                                   warn!("Failed to parse connectedAPINode message: {}. Data: {}", e, String::from_utf8_lossy(&message.data_json));
                               }
                           }
                        }

                        let _ = handle_message(&message, &tx, api_config, config_store.clone()).await;
                    }
                    Ok(None) => {
                        debug!("Node stream connection closed by API node.");
                        if let Some(id) = current_api_node_id {
                             if let Ok(mut guard) = crate::rpc::node::CONNECTED_API_NODE_IDS.write() {
                                 guard.remove(&id);
                             }
                        }
                        break;
                    }
                    Err(e) => {
                        // Downgrade common network/H2 errors to avoid excessive noise
                        let err_msg = e.to_string();
                        if err_msg.contains("h2 protocol error") || err_msg.contains("Broken pipe") || err_msg.contains("Connection reset") {
                            warn!("Node stream network interrupt: {}", err_msg);
                        } else {
                            error!("Node stream protocol error: {}", e);
                        }

                        if let Some(id) = current_api_node_id {
                             if let Ok(mut guard) = crate::rpc::node::CONNECTED_API_NODE_IDS.write() {
                                 guard.remove(&id);
                             }
                        }
                        return Err(e.into());
                    }
                }
            }
            _ = heartbeat_interval.tick() => {
                let current_node_id = config_store.get_node_id().await;
                if current_node_id > 0 {
                    let ping = pb::NodeStreamMessage {
                        node_id: current_node_id,
                        request_id: 0,
                        code: "ping".to_string(),
                        is_ok: true,
                        ..Default::default()
                    };
                    let _ = tx.try_send(ping);
                }
            }
            _ = endpoint_check_interval.tick() => {
                let latest_endpoints = api_config.effective_rpc_endpoints();
                if latest_endpoints != connected_endpoints {
                    info!(
                        "Detected runtime API endpoint change for node stream. Reconnecting from {:?} to {:?}",
                        connected_endpoints,
                        latest_endpoints
                    );
                    break;
                }
            }
        }
    }

    if let Some(id) = current_api_node_id {
        if let Ok(mut guard) = crate::rpc::node::CONNECTED_API_NODE_IDS.write() {
            guard.remove(&id);
        }
    }

    Ok(())
}

async fn handle_message(
    message: &pb::NodeStreamMessage,
    tx: &mpsc::Sender<pb::NodeStreamMessage>,
    _api_config: &ApiConfig,
    config_store: Arc<ConfigStore>,
) -> anyhow::Result<()> {
    debug!(
        "Received node stream message: code={}, requestId={}",
        message.code, message.request_id
    );

    let mut is_ok = true;
    let mut message_reply = "ok".to_string();
    let data_json = vec![];
    let node_id = config_store.get_node_id().await;

    match message.code.as_str() {
        "connectedAPINode" => {
            // Already handled in run_stream to track connection state
            crate::rpc::node_task::trigger_task_sync();
        }
        "newNodeTask" | "NewNodeTask" | "configChanged" => {
            info!(
                "Received notification: {}. Triggering immediate task sync...",
                message.code
            );
            crate::rpc::node_task::trigger_task_sync();
        }
        "writeCache" => {
            is_ok = false;
            match serde_json::from_slice::<WriteCacheMessage>(&message.data_json) {
                Ok(msg) => {
                    let key = msg.key.clone();
                    tokio::spawn(async move {
                        let full_key =
                            if !key.starts_with("http://") && !key.starts_with("https://") {
                                format!("http://{}", key)
                            } else {
                                key.clone()
                            };

                        if let Ok(url) = full_key.parse::<reqwest::Url>() {
                            let preheat_url = format!("http://127.0.0.1:80{}", url.path());
                            let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();
                            let final_url = format!("{}{}", preheat_url, query);

                            let client = reqwest::Client::builder()
                                .timeout(std::time::Duration::from_secs(10))
                                .build()
                                .unwrap_or_default();

                            // Use POST to carry the actual value payload (decoded from Base64 if needed)
                            let _ = client
                                .post(&final_url)
                                .header("host", &key)
                                .header("x-cloud-cache-action", "fetch")
                                .header("x-cloud-preheat", "1")
                                .body(msg.get_value_bytes())
                                .send()
                                .await;
                        }
                    });

                    is_ok = true;
                    message_reply = "write ok".to_string();
                }
                Err(e) => message_reply = format!("decode failed: {:?}", e),
            }
        }
        "readCache" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let mut is_ok = false;
                let reply_text;

                match serde_json::from_slice::<ReadCacheMessage>(&msg_cloned.data_json) {
                    Ok(msg) => {
                        let hash = format!("{:x}", md5_legacy::compute(&msg.key));
                        if let Some(meta) = crate::metrics::storage::STORAGE.get_cache_meta(&hash) {
                            is_ok = true;
                            reply_text = format!("value {} bytes", meta["s"].as_u64().unwrap_or(0));
                        } else {
                            reply_text = "key not found".to_string();
                        }
                    }
                    Err(e) => reply_text = format!("decode failed: {:?}", e),
                }

                let reply = pb::NodeStreamMessage {
                    node_id,
                    request_id: msg_cloned.request_id,
                    code: msg_cloned.code.clone(),
                    message: reply_text,
                    is_ok,
                    ..Default::default()
                };
                let _ = tx_cloned.send(reply).await;
            });
            return Ok(());
        }
        "statCache" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();
            let _config_store_cloned = config_store.clone();

            tokio::spawn(async move {
                let total_size = crate::metrics::storage::STORAGE.total_cache_size();
                let total_count = crate::metrics::storage::STORAGE.total_cache_count();

                let size_str = if total_size < 1024 {
                    format!("{} Bytes", total_size)
                } else if total_size < 1024 * 1024 {
                    format!("{:.2} KB", total_size as f64 / 1024.0)
                } else if total_size < 1024 * 1024 * 1024 {
                    format!("{:.2} MB", total_size as f64 / (1024.0 * 1024.0))
                } else if total_size < 1024 * 1024 * 1024 * 1024 {
                    format!("{:.2} GB", total_size as f64 / (1024.0 * 1024.0 * 1024.0))
                } else {
                    format!(
                        "{:.2} TB",
                        total_size as f64 / (1024.0 * 1024.0 * 1024.0 * 1024.0)
                    )
                };

                let reply = pb::NodeStreamMessage {
                    node_id,
                    request_id: msg_cloned.request_id,
                    code: msg_cloned.code.clone(),
                    message: format!("size:{}, count:{}", size_str, total_count),
                    is_ok: true,
                    ..Default::default()
                };
                let _ = tx_cloned.send(reply).await;
            });
            return Ok(());
        }
        "cleanCache" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let all_meta = crate::metrics::storage::STORAGE.scan_all_cache_meta();
                let mut count = 0;
                let root = std::path::Path::new("data/cache");

                for (hash, _) in all_meta {
                    let file_path = root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
                    if file_path.exists() {
                        let _ = std::fs::remove_file(&file_path);
                    }
                    crate::metrics::storage::STORAGE.delete_cache_meta(&hash);
                    count += 1;
                }

                info!("Global cache cleaned: {} items removed.", count);

                let reply = pb::NodeStreamMessage {
                    node_id,
                    request_id: msg_cloned.request_id,
                    code: msg_cloned.code.clone(),
                    message: "ok".to_string(),
                    is_ok: true,
                    ..Default::default()
                };
                let _ = tx_cloned.send(reply).await;
            });
            return Ok(()); // Handled asynchronously
        }
        "getStat" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let mut sys = sysinfo::System::new_all();
                sys.refresh_cpu_all();
                sys.refresh_memory();
                let load = sysinfo::System::load_average();
                let total_memory = sys.total_memory() as i64;
                let used_memory = sys.used_memory() as i64;
                let mem_usage = if total_memory > 0 {
                    used_memory as f64 / total_memory as f64
                } else {
                    0.0
                };

                let (traffic_out, traffic_in, connections) =
                    crate::metrics::METRICS.get_node_totals();
                let stat = serde_json::json!({
                    "cpuUsage": sys.global_cpu_usage() / 100.0,
                    "cpuLogicalCount": sys.cpus().len(),
                    "cpuPhysicalCount": sys.physical_core_count().unwrap_or(sys.cpus().len()),
                    "memUsage": mem_usage,
                    "memoryTotal": total_memory,
                    "memoryUsed": used_memory,
                    "load1": load.one,
                    "load5": load.five,
                    "load15": load.fifteen,
                    "trafficIn": traffic_in,
                    "trafficOut": traffic_out,
                    "connections": connections,
                });

                let reply = pb::NodeStreamMessage {
                    node_id,
                    request_id: msg_cloned.request_id,
                    code: msg_cloned.code.clone(),
                    data_json: stat.to_string().into_bytes(),
                    is_ok: true,
                    message: "ok".to_string(),
                    ..Default::default()
                };
                let _ = tx_cloned.send(reply).await;
            });
            return Ok(()); // Handled asynchronously
        }
        "changeAPINode" => {
            if let Ok(msg) = serde_json::from_slice::<ChangeAPINodeMessage>(&message.data_json) {
                info!(
                    "Received request to change API node address to: {}",
                    msg.addr
                );
                ApiConfig::set_runtime_rpc_endpoints(vec![msg.addr]);
            }
        }
        _ => {
            warn!("Unhandled node stream message code: {}", message.code);
            message_reply = "unhandled".to_string();
        }
    }

    if message.request_id >= 0 && message.code != "connectedAPINode" {
        let reply = pb::NodeStreamMessage {
            node_id,
            request_id: message.request_id,
            code: message.code.clone(),
            data_json,
            is_ok,
            message: message_reply,
            ..Default::default()
        };
        let _ = tx.send(reply).await;
    }

    Ok(())
}
