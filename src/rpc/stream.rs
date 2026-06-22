use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::config_models::HTTPCachePolicy;
use crate::pb;
use crate::rpc::client::RpcClient;
use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize as _;
use serde::de::Error as _;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

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
    #[serde(
        rename = "cachePolicyJSON",
        default,
        deserialize_with = "deserialize_go_json_bytes"
    )]
    cache_policy_json: Vec<u8>,
    #[serde(rename = "key")]
    key: String,
    #[serde(default, deserialize_with = "deserialize_go_json_bytes")]
    value: Vec<u8>,
    #[serde(rename = "lifeSeconds", default)]
    life_seconds: i64,
}

#[derive(Debug, serde::Deserialize)]
struct ReadCacheMessage {
    #[serde(
        rename = "cachePolicyJSON",
        default,
        deserialize_with = "deserialize_go_json_bytes"
    )]
    cache_policy_json: Vec<u8>,
    #[serde(rename = "key")]
    key: String,
}

#[derive(Debug, serde::Deserialize)]
struct StatCacheMessage {
    #[serde(
        rename = "cachePolicyJSON",
        default,
        deserialize_with = "deserialize_go_json_bytes"
    )]
    cache_policy_json: Vec<u8>,
}

#[derive(Debug, serde::Deserialize)]
struct CleanCacheMessage {
    #[serde(
        rename = "cachePolicyJSON",
        default,
        deserialize_with = "deserialize_go_json_bytes"
    )]
    cache_policy_json: Vec<u8>,
}

#[derive(Debug, serde::Deserialize)]
struct CheckLocalFirewallMessage {
    #[serde(default)]
    name: String,
}

fn deserialize_go_json_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::String(encoded) => general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(D::Error::custom),
        serde_json::Value::Array(values) => {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                let byte = value
                    .as_u64()
                    .filter(|value| *value <= u8::MAX as u64)
                    .ok_or_else(|| D::Error::custom("byte array contains non-byte value"))?;
                out.push(byte as u8);
            }
            Ok(out)
        }
        other => Err(D::Error::custom(format!(
            "expected base64 string or byte array, got {other}"
        ))),
    }
}

async fn apply_stream_cache_policy(cache_policy_json: &[u8]) -> Result<(), String> {
    if cache_policy_json.is_empty() {
        return Err("missing cachePolicyJSON".to_string());
    }
    let policy = serde_json::from_slice::<HTTPCachePolicy>(cache_policy_json)
        .map_err(|err| format!("decode cache policy config failed: {}", err))?;
    crate::cache_manager::CACHE
        .storage
        .apply_policy(&policy)
        .await;
    Ok(())
}

pub async fn start_node_stream(api_config: ApiConfig, config_store: Arc<ConfigStore>) {
    let mut last_endpoints = api_config.effective_rpc_endpoints();
    let mut fail_count: u32 = 0;
    const MAX_BACKOFF: Duration = Duration::from_secs(15);

    loop {
        if !crate::cluster::leader::require_leader("node_stream") {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let client =
            match RpcClient::new_stream_with_endpoints(&api_config, &last_endpoints, false).await {
                Ok(client) => client,
                Err(e) => {
                    last_endpoints = api_config.effective_rpc_endpoints();
                    fail_count = fail_count.saturating_add(1);
                    let delay = stream_backoff(fail_count, MAX_BACKOFF);
                    warn!(
                        "Failed to connect to API node for stream: {}. Retrying in {:?}...",
                        e, delay
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };
        let stream_result = run_stream(client, &api_config, config_store.clone())
            .await
            .map(|_| NodeStreamProbeResult::default());

        match stream_result {
            Ok(_) => {
                fail_count = 0;
                last_endpoints = api_config.effective_rpc_endpoints();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                fail_count = fail_count.saturating_add(1);
                let delay = stream_backoff(fail_count, MAX_BACKOFF);
                warn!("Node stream error: {}. Reconnecting in {:?}...", e, delay);
                last_endpoints = api_config.effective_rpc_endpoints();
                tokio::time::sleep(delay).await;
            }
        }
    }
}

fn stream_backoff(fail_count: u32, max: Duration) -> Duration {
    // Exponential backoff with a cap and jitter to avoid thundering herd.
    use rand::Rng;
    let base = Duration::from_secs(1).saturating_mul(1u32 << fail_count.saturating_sub(1).min(6));
    let capped = base.min(max);
    let jitter_ms = (capped.as_millis() as u64 / 4) as i64;
    let offset = rand::thread_rng().gen_range(-jitter_ms..=jitter_ms);
    if offset < 0 {
        capped.saturating_sub(Duration::from_millis((-offset) as u64))
    } else {
        capped
            .saturating_add(Duration::from_millis(offset as u64))
            .min(max)
    }
}

pub async fn probe_node_stream(
    api_config: &ApiConfig,
    config_store: Arc<ConfigStore>,
    hold: Duration,
) -> anyhow::Result<NodeStreamProbeResult> {
    let client = RpcClient::new_stream(api_config).await?;
    run_tonic_stream(client, api_config, config_store, Some(hold)).await
}

async fn send_node_stream_ping(
    config_store: &ConfigStore,
    tx: &mpsc::Sender<pb::NodeStreamMessage>,
) -> bool {
    let node_id = config_store.get_node_id().await;
    if node_id <= 0 {
        return false;
    }

    let ping = pb::NodeStreamMessage {
        node_id,
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
    let initial_node_id = config_store.get_node_id().await;
    let initial_ping = (initial_node_id > 0).then(|| pb::NodeStreamMessage {
        node_id: initial_node_id,
        request_id: 0,
        code: "ping".to_string(),
        is_ok: true,
        ..Default::default()
    });
    let initial_ping_sent = initial_ping.is_some();
    let (tx, mut rx) = mpsc::channel(100);
    let rx_stream = async_stream::stream! {
        if let Some(ping) = initial_ping {
            yield ping;
        }
        while let Some(message) = rx.recv().await {
            yield message;
        }
    };

    let mut current_api_node_id = None;
    let mut stats = NodeStreamProbeResult {
        transport_opened: true,
        pings_sent: usize::from(initial_ping_sent),
        ..Default::default()
    };
    let mut heartbeat_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );
    let mut endpoint_check_interval = tokio::time::interval(Duration::from_secs(15));
    let deadline = hold.map(|duration| tokio::time::Instant::now() + duration);
    let sleep_until_deadline = async {
        match deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(sleep_until_deadline);

    let mut node_client = client.node_service_plain();
    let response = {
        let response_future = node_client.node_stream(rx_stream);
        tokio::pin!(response_future);

        loop {
            tokio::select! {
                response = &mut response_future => {
                    let response = response?;
                    stats.response_headers_received = true;
                    break response;
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
                            "Detected runtime API endpoint change before node stream response headers. Reconnecting from {:?} to {:?}",
                            connected_endpoints,
                            latest_endpoints
                        );
                        return Ok(stats);
                    }
                }
                _ = &mut sleep_until_deadline => {
                    return Ok(stats);
                }
            }
        }
    };
    let mut inbound = response.into_inner();

    info!("Node stream established.");

    loop {
        tokio::select! {
            msg_res = inbound.message() => {
                match msg_res {
                    Ok(Some(message)) => {
                        stats.inbound_messages += 1;
                        if message.code.eq_ignore_ascii_case("connectedAPINode") {
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
    api_config: &ApiConfig,
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

    let code = message.code.to_ascii_lowercase();
    match code.as_str() {
        "connectedapinode" => {
            // Already handled in run_stream to track connection state
            crate::rpc::node_task::trigger_task_sync();
        }
        "newnodetask" | "configchanged" => {
            info!(
                "Received notification: {}. Triggering immediate task sync...",
                message.code
            );
            crate::rpc::node_task::trigger_task_sync();
        }
        "writecache" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let mut is_ok = false;
                let reply_text;

                match serde_json::from_slice::<WriteCacheMessage>(&msg_cloned.data_json) {
                    Ok(msg) => {
                        if let Err(err) = apply_stream_cache_policy(&msg.cache_policy_json).await {
                            reply_text = err;
                        } else {
                            match crate::cache_manager::CACHE
                                .write_value(&msg.key, &msg.value, msg.life_seconds.max(0) as u64)
                                .await
                            {
                                Ok(_) => {
                                    is_ok = true;
                                    reply_text = "write ok".to_string();
                                }
                                Err(err) => {
                                    reply_text = format!("write failed: {}", err);
                                }
                            }
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
        "readcache" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let mut is_ok = false;
                let reply_text;

                match serde_json::from_slice::<ReadCacheMessage>(&msg_cloned.data_json) {
                    Ok(msg) => {
                        if let Err(err) = apply_stream_cache_policy(&msg.cache_policy_json).await {
                            reply_text = err;
                        } else {
                            match crate::cache_manager::CACHE.read_value_size(&msg.key).await {
                                Ok(Some(size)) => {
                                    is_ok = true;
                                    reply_text = format!("value {} bytes", size);
                                }
                                Ok(None) => {
                                    reply_text = "key not found".to_string();
                                }
                                Err(err) => {
                                    reply_text = format!("read key failed: {}", err);
                                }
                            }
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
        "statcache" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();
            let _config_store_cloned = config_store.clone();

            tokio::spawn(async move {
                let mut is_ok = false;
                let reply_text;
                match serde_json::from_slice::<StatCacheMessage>(&msg_cloned.data_json) {
                    Ok(msg) => {
                        if let Err(err) = apply_stream_cache_policy(&msg.cache_policy_json).await {
                            reply_text = err;
                        } else {
                            let total_size = crate::metrics::storage::STORAGE.total_cache_size();
                            let total_count = crate::metrics::storage::STORAGE.total_cache_count();

                            let size_str = if total_size < 1024 {
                                format!("{} Bytes", total_size)
                            } else if total_size < 1024 * 1024 {
                                format!("{:.2} KiB", total_size as f64 / 1024.0)
                            } else if total_size < 1024 * 1024 * 1024 {
                                format!("{:.2} MiB", total_size as f64 / (1024.0 * 1024.0))
                            } else {
                                format!("{:.2} GiB", total_size as f64 / (1024.0 * 1024.0 * 1024.0))
                            };
                            is_ok = true;
                            reply_text = format!("size:{}, count:{}", size_str, total_count);
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
        "cleancache" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let mut is_ok = false;
                let reply_text;
                match serde_json::from_slice::<CleanCacheMessage>(&msg_cloned.data_json) {
                    Ok(msg) => {
                        if let Err(err) = apply_stream_cache_policy(&msg.cache_policy_json).await {
                            reply_text = err;
                        } else {
                            match crate::cache_manager::CACHE.clean_all().await {
                                Ok(count) => {
                                    info!("Global cache cleaned: {} items removed.", count);
                                    is_ok = true;
                                    reply_text = "ok".to_string();
                                }
                                Err(err) => {
                                    reply_text = format!("clean cache failed: {}", err);
                                }
                            }
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
            return Ok(()); // Handled asynchronously
        }
        "getstat" => {
            let tx_cloned = tx.clone();
            let msg_cloned = message.clone();

            tokio::spawn(async move {
                let mut sys = sysinfo::System::new_all();
                sys.refresh_cpu_all();
                let load = sysinfo::System::load_average();
                let (total_memory, used_memory) = crate::memory_governor::reported_memory_totals();
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
                    "cpuPhysicalCount": sysinfo::System::physical_core_count().unwrap_or(sys.cpus().len()),
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
        "changeapinode" => {
            if let Ok(msg) = serde_json::from_slice::<ChangeAPINodeMessage>(&message.data_json) {
                info!(
                    "Received request to change API node address to: {}",
                    msg.addr
                );
                ApiConfig::set_runtime_rpc_endpoints(vec![msg.addr]);
                if let Err(e) = crate::rpc::client::SharedRpcClient::refresh(&api_config) {
                    warn!(
                        "Failed to refresh shared RPC channel after endpoint change: {}",
                        e
                    );
                }
            }
        }
        "checksystemdservice" => {
            let (ok, reply) = check_systemd_service("cloud-node").await;
            is_ok = ok;
            message_reply = reply;
        }
        "checklocalfirewall" => {
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

    if message.request_id > 0 && !message.code.eq_ignore_ascii_case("connectedAPINode") {
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
    use super::{WriteCacheMessage, interpret_systemd_is_enabled, send_node_stream_ping};
    use crate::config::ConfigStore;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn node_stream_ping_uses_config_store_numeric_node_id() {
        let (tx, mut rx) = mpsc::channel(1);
        let config_store = ConfigStore::new();
        config_store.update_id(42).await;

        assert!(send_node_stream_ping(&config_store, &tx).await);

        let ping = rx.recv().await.expect("ping message");
        assert_eq!(ping.node_id, 42);
        assert_eq!(ping.request_id, 0);
        assert_eq!(ping.code, "ping");
        assert!(ping.is_ok);
    }

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

    #[test]
    fn write_cache_message_accepts_go_json_byte_base64() {
        let msg: WriteCacheMessage = serde_json::from_value(serde_json::json!({
            "cachePolicyJSON": "eyJpZCI6MX0=",
            "key": "https://cache.example.com/a.js",
            "value": "aGVsbG8=",
            "lifeSeconds": 60
        }))
        .unwrap();

        assert_eq!(msg.cache_policy_json, br#"{"id":1}"#);
        assert_eq!(msg.value, b"hello");
        assert_eq!(msg.life_seconds, 60);
    }
}
