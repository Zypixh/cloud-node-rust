use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::RpcClient;
use futures_util::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

#[derive(Debug, Default)]
pub struct NodeStreamProbeResult {
    pub transport_opened: bool,
    pub response_headers_received: bool,
    pub connected_api_node_id: Option<i64>,
    pub inbound_messages: usize,
    pub pings_sent: usize,
}

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
}

#[derive(Debug, serde::Deserialize)]
struct ReadCacheMessage {
    #[serde(rename = "key")]
    key: String,
}

#[derive(Debug, serde::Deserialize)]
struct CheckLocalFirewallMessage {
    #[serde(default)]
    name: String,
}

pub async fn start_node_stream(api_config: ApiConfig, config_store: Arc<ConfigStore>) {
    let mut last_endpoints = api_config.effective_rpc_endpoints();
    loop {
        if !crate::cluster::leader::require_leader("node_stream") {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let client = match RpcClient::new_with_endpoints(&api_config, &last_endpoints, false).await {
            Ok(client) => client,
            Err(e) => {
                last_endpoints = api_config.effective_rpc_endpoints();
                error!(
                    "Failed to connect to API node for stream: {}. Retrying in 10s...",
                    e
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let stream_result = run_stream(client, &api_config, config_store.clone()).await;

        match stream_result {
            Ok(_) => {
                last_endpoints = api_config.effective_rpc_endpoints();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                warn!("Node stream error: {}. Reconnecting...", e);
                last_endpoints = api_config.effective_rpc_endpoints();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

pub async fn probe_node_stream(
    api_config: &ApiConfig,
    config_store: Arc<ConfigStore>,
    hold: Duration,
) -> anyhow::Result<NodeStreamProbeResult> {
    let client = RpcClient::new(api_config).await?;
    run_tonic_stream(client, api_config, config_store, Some(hold)).await
}

async fn send_node_stream_ping(
    config_store: &ConfigStore,
    tx: &mpsc::Sender<pb::NodeStreamMessage>,
) -> bool {
    let current_node_id = config_store.get_node_id().await;
    if current_node_id <= 0 {
        return false;
    }

    let ping = pb::NodeStreamMessage {
        node_id: current_node_id,
        request_id: 0,
        code: "ping".to_string(),
        is_ok: true,
        ..Default::default()
    };

    match tx.try_send(ping) {
        Ok(()) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            debug!("Skipped node stream heartbeat because outbound queue is full");
            false
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            warn!("Failed to send node stream heartbeat because outbound stream is closed");
            false
        }
    }
}

async fn run_stream(
    client: RpcClient,
    api_config: &ApiConfig,
    config_store: Arc<ConfigStore>,
) -> anyhow::Result<()> {
    run_tonic_stream(client, api_config, config_store, None)
        .await
        .map(|_| ())
}

async fn run_tonic_stream(
    client: RpcClient,
    api_config: &ApiConfig,
    config_store: Arc<ConfigStore>,
    hold: Option<Duration>,
) -> anyhow::Result<NodeStreamProbeResult> {
    let connected_endpoints = api_config.effective_rpc_endpoints();
    let (tx, rx) = mpsc::channel(100);
    let initial_ping_sent = send_node_stream_ping(&config_store, &tx).await;
    let rx_stream = ReceiverStream::new(rx);

    let mut node_client = client.node_service();
    let response =
        tokio::time::timeout(Duration::from_secs(30), node_client.node_stream(rx_stream))
            .await
            .map_err(|_| anyhow::anyhow!("nodeStream response headers timed out"))??;
    let mut inbound = response.into_inner();

    info!("Node stream established.");

    let mut current_api_node_id = None;
    let mut stats = NodeStreamProbeResult {
        transport_opened: true,
        response_headers_received: true,
        pings_sent: usize::from(initial_ping_sent),
        ..Default::default()
    };
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
    let mut endpoint_check_interval = tokio::time::interval(Duration::from_secs(15));
    let deadline = hold.map(|duration| tokio::time::Instant::now() + duration);
    let sleep_until_deadline = async {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(sleep_until_deadline);

    loop {
        tokio::select! {
            msg_res = inbound.message() => {
                match msg_res {
                    Ok(Some(message)) => {
                        stats.inbound_messages += 1;
                        if message.code == "connectedAPINode" {
                           match serde_json::from_slice::<ConnectedAPINodeMessage>(&message.data_json) {
                               Ok(msg) => {
                                   info!("Successfully connected to API node via stream. API Node ID: {}", msg.api_node_id);
                                   current_api_node_id = Some(msg.api_node_id);
                                   stats.connected_api_node_id = Some(msg.api_node_id);
                                   crate::rpc::node::CONNECTED_API_NODE_IDS.write().insert(msg.api_node_id);
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
                             crate::rpc::node::CONNECTED_API_NODE_IDS.write().remove(&id);
                        }
                        break;
                    }
                    Err(e) => {
                        if is_retryable_stream_transport_error(&e) {
                            debug!("Node stream transport closed: {}", e);
                        } else {
                            warn!("Node stream error: {}", e);
                        }

                        if let Some(id) = current_api_node_id {
                             crate::rpc::node::CONNECTED_API_NODE_IDS.write().remove(&id);
                        }
                        return Err(e.into());
                    }
                }
            }
            _ = heartbeat_interval.tick() => {
                if send_node_stream_ping(&config_store, &tx).await {
                    stats.pings_sent += 1;
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
            _ = &mut sleep_until_deadline => {
                break;
            }
        }
    }

    if let Some(id) = current_api_node_id {
        crate::rpc::node::CONNECTED_API_NODE_IDS.write().remove(&id);
    }

    Ok(stats)
}

fn is_retryable_stream_transport_error(error: &tonic::Status) -> bool {
    if error.code() == tonic::Code::Unavailable {
        return true;
    }
    let message = error.message().to_ascii_lowercase();
    message.contains("invalid connection")
        || message.contains("connection closed")
        || message.contains("connection reset")
        || message.contains("broken pipe")
        || message.contains("goaway")
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
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let mut is_ok = false;
                let reply_text;

                match serde_json::from_slice::<WriteCacheMessage>(&msg_cloned.data_json) {
                    Ok(msg) => {
                        let key = msg.key.clone();
                        let full_key =
                            if !key.starts_with("http://") && !key.starts_with("https://") {
                                format!("http://{}", key)
                            } else {
                                key.clone()
                            };

                        if let Ok(url) = full_key.parse::<reqwest::Url>() {
                            let host = url.host_str().unwrap_or("localhost");
                            let is_https = url.scheme() == "https";
                            let port = url.port().unwrap_or(if is_https { 443 } else { 80 });
                            let scheme = if is_https { "https" } else { "http" };
                            let preheat_url =
                                format!("{}://127.0.0.1:{}{}", scheme, port, url.path());
                            let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();
                            let final_url = format!("{}{}", preheat_url, query);

                            let client = reqwest::Client::builder()
                                .timeout(std::time::Duration::from_secs(30))
                                .build()
                                .unwrap_or_default();

                            match client
                                .get(&final_url)
                                .header("host", host)
                                .header("x-cloud-cache-action", "fetch")
                                .header("x-cloud-preheat", "1")
                                .header("user-agent", "Mozilla/5.0 (compatible; CacheTest/1.0)")
                                .send()
                                .await
                            {
                                Ok(resp) => {
                                    let status = resp.status();
                                    if status.is_success() {
                                        let mut body = resp.bytes_stream();
                                        let mut read_error = None;
                                        while let Some(chunk) = body.next().await {
                                            if let Err(e) = chunk {
                                                read_error = Some(e);
                                                break;
                                            }
                                        }
                                        if let Some(e) = read_error {
                                            reply_text = format!("body read failed: {}", e);
                                        } else {
                                            is_ok = true;
                                            reply_text = "write ok".to_string();
                                        }
                                    } else {
                                        reply_text = format!("upstream returned {}", status);
                                    }
                                }
                                Err(e) => {
                                    reply_text = format!("request failed: {}", e);
                                }
                            }
                        } else {
                            reply_text = "invalid URL".to_string();
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
        "readCache" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let mut is_ok = false;
                let reply_text;

                match serde_json::from_slice::<ReadCacheMessage>(&msg_cloned.data_json) {
                    Ok(msg) => {
                        // Reconstruct cache key in the same format as proxy's
                        // default_cache_key_for_session() which uses "http://{host}{path}"
                        let full_key = if !msg.key.starts_with("http://")
                            && !msg.key.starts_with("https://")
                        {
                            format!("http://{}", msg.key)
                        } else {
                            msg.key.clone()
                        };
                        let hash = format!("{:x}", md5_legacy::compute(&full_key));
                        if let Some(meta) = crate::metrics::storage::STORAGE.get_cache_meta(&hash) {
                            is_ok = true;
                            reply_text = format!("value {} bytes", meta.size);
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
                let roots = crate::cache_manager::CACHE
                    .storage
                    .l2
                    .inner
                    .load()
                    .all_roots();

                for (hash, _) in all_meta {
                    for root in &roots {
                        let file_path = root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
                        if file_path.exists() {
                            let _ = std::fs::remove_file(&file_path);
                        }
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
        "checkSystemdService" => {
            let (ok, reply) = check_systemd_service("cloud-node").await;
            is_ok = ok;
            message_reply = reply;
        }
        "checkLocalFirewall" => {
            let msg = serde_json::from_slice::<CheckLocalFirewallMessage>(&message.data_json)
                .unwrap_or(CheckLocalFirewallMessage {
                    name: "nftables".to_string(),
                });
            if msg.name == "nftables" {
                match crate::local_firewall::check_nftables().await {
                    Ok(status) => {
                        is_ok = true;
                        message_reply = format!("{} {}", status.name, status.version);
                    }
                    Err(err) => {
                        is_ok = false;
                        message_reply = err.to_string();
                    }
                }
            } else {
                is_ok = false;
                message_reply = format!("unsupported local firewall '{}'", msg.name);
            }
        }
        _ => {
            warn!("Unhandled node stream message code: {}", message.code);
            message_reply = "unhandled".to_string();
        }
    }

    if message.request_id > 0 && message.code != "connectedAPINode" {
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

async fn check_systemd_service(service_name: &str) -> (bool, String) {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("systemctl")
            .arg("is-enabled")
            .arg(service_name)
            .output(),
    )
    .await;

    match output {
        Ok(Ok(output)) => interpret_systemd_is_enabled(
            output.status.success(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ),
        Ok(Err(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            (false, "'systemctl' not found".to_string())
        }
        Ok(Err(err)) => (false, format!("'systemctl' command error: {}", err)),
        Err(_) => (false, "'systemctl' command timed out after 10s".to_string()),
    }
}

fn interpret_systemd_is_enabled(success: bool, stdout: &str, stderr: &str) -> (bool, String) {
    let stdout = stdout.trim();
    if stdout == "enabled" {
        return (true, "ok".to_string());
    }
    if success || !stdout.is_empty() {
        return (false, "not installed".to_string());
    }
    let err = stderr.trim();
    if err.is_empty() {
        (false, "'systemctl' command error".to_string())
    } else {
        (false, format!("'systemctl' command error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::interpret_systemd_is_enabled;

    #[test]
    fn systemd_enabled_output_maps_to_ok() {
        assert_eq!(
            interpret_systemd_is_enabled(true, "enabled\n", ""),
            (true, "ok".to_string())
        );
    }

    #[test]
    fn systemd_non_enabled_success_maps_to_not_installed() {
        assert_eq!(
            interpret_systemd_is_enabled(true, "disabled\n", ""),
            (false, "not installed".to_string())
        );
    }

    #[test]
    fn systemd_failed_output_keeps_error_detail() {
        assert_eq!(
            interpret_systemd_is_enabled(false, "", "unit not found\n"),
            (
                false,
                "'systemctl' command error: unit not found".to_string()
            )
        );
    }
}
