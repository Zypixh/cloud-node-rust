use once_cell::sync::Lazy;
use serde_json::Value;
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::{Request, Status};
use tracing::{error, info, warn};

use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::RpcClient;
use crate::rpc::node_task::sync_node_tasks;
use crate::rpc::utils::sync_deleted_contents;

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
    value: Value,
    #[serde(rename = "lifeSeconds")]
    life_seconds: i64,
}

#[derive(Debug, serde::Deserialize)]
struct ReadCacheMessage {
    #[serde(rename = "key")]
    key: String,
}

static CONNECTED_API_NODE_IDS: Lazy<RwLock<HashSet<i64>>> =
    Lazy::new(|| RwLock::new(HashSet::new()));

async fn report_node_up(api_config: &ApiConfig, node_id: i64, is_up: bool) {
    if node_id <= 0 { return; }
    if let Ok(client) = RpcClient::new(api_config).await {
        let mut node_service = client.node_service_with_type();
        let _ = node_service.update_node_up(pb::UpdateNodeUpRequest { node_id, is_up }).await;
    }
}

async fn report_connected_api_nodes(api_config: &ApiConfig) {
    let api_node_ids = CONNECTED_API_NODE_IDS.read().ok()
        .map(|guard| guard.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    if let Ok(client) = RpcClient::new(api_config).await {
        let mut node_service = client.node_service_with_type();
        let _ = node_service.update_node_connected_api_nodes(pb::UpdateNodeConnectedApiNodesRequest { api_node_ids }).await;
    }
}

pub async fn start_config_syncer(
    config_store: Arc<ConfigStore>,
    api_config: ApiConfig,
    ip_list_manager: Arc<crate::firewall::lists::GlobalIpListManager>,
    health_manager: Arc<crate::health_manager::GlobalHealthManager>,
    cert_selector: Arc<crate::ssl::DynamicCertSelector>,
) {
    let mut state = crate::utils::persistence::load_state();
    let mut task_version = state.task_version;
    let mut deleted_content_version = state.deleted_content_version;
    let mut config_version = state.config_version;

    loop {
        let api_endpoint = api_config.effective_rpc_endpoints().first().cloned().unwrap_or_default();
        info!("Starting config syncer for API Node {} (Node ID: {})", api_endpoint, api_config.node_id);

        let client = match RpcClient::new(&api_config).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to connect to API node: {}. Will retry...", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let mut node_service = client.node_service();

        fetch_and_apply_config(
            &mut node_service, &config_store, &api_config, &ip_list_manager,
            &health_manager, &cert_selector, &mut task_version,
            &mut deleted_content_version, &mut config_version,
        ).await;

        if let Ok(mut guard) = CONNECTED_API_NODE_IDS.write() { guard.clear(); }
        let node_id = config_store.get_node_id().await;
        report_node_up(&api_config, node_id, true).await;
        report_connected_api_nodes(&api_config).await;

        state.config_version = config_version;
        state.task_version = task_version;
        state.deleted_content_version = deleted_content_version;
        crate::utils::persistence::save_state(&state);

        let (tx, rx) = mpsc::channel(100);
        let out_stream = ReceiverStream::new(rx);
        let mut should_reconnect = false;

        match node_service.node_stream(out_stream).await {
            Ok(response) => {
                let mut in_stream = response.into_inner();
                while let Ok(Some(message)) = in_stream.message().await {
                    if message.node_id > 0 {
                        let current_stored_id = config_store.get_node_id().await;
                        if current_stored_id == 0 {
                            info!("RPC_NODE: Automatically discovered numeric ID from stream: {}", message.node_id);
                            config_store.update_id(message.node_id).await;
                            crate::logging::set_numeric_node_id(message.node_id);
                        }
                    }

                    match message.code.as_str() {
                        "newNodeTask" | "NewNodeTask" | "configChanged" => {
                            info!("Received node config/task notification. Pulling updated state...");
                            fetch_and_apply_config(
                                &mut node_service, &config_store, &api_config, &ip_list_manager,
                                &health_manager, &cert_selector, &mut task_version,
                                &mut deleted_content_version, &mut config_version,
                            ).await;
                            let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: true,
                                message: "ok".to_string(),
                                ..Default::default()
                            }).await;
                        }
                        "writeCache" => {
                            info!("Received cache write test command");
                            let result: anyhow::Result<String> = (|| {
                                let msg = serde_json::from_slice::<WriteCacheMessage>(&message.data_json)?;
                                let hash = hex::encode(&msg.key);
                                
                                let data = match msg.value {
                                    Value::String(s) => general_purpose::STANDARD.decode(s)?,
                                    Value::Array(arr) => arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect(),
                                    _ => anyhow::bail!("Invalid value type for cache write"),
                                };

                                crate::metrics::storage::STORAGE.update_cache_meta(&hash, &msg.key, data.len() as u64, msg.life_seconds as u64);
                                // Directly write to disk for testing
                                let path = std::path::Path::new("configs/cache/disk").join(&hash[0..2]).join(&hash[2..4]).join(&hash);
                                if let Some(parent) = path.parent() {
                                    let _ = std::fs::create_dir_all(parent);
                                }
                                std::fs::write(path, data)?;
                                Ok("write ok".to_string())
                            })();

                            let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: result.is_ok(),
                                message: result.unwrap_or_else(|e| format!("Error: {:?}", e)),
                                ..Default::default()
                            }).await;
                        }
                        "readCache" => {
                            info!("Received cache read test command");
                            let result: anyhow::Result<String> = (|| {
                                let msg = serde_json::from_slice::<ReadCacheMessage>(&message.data_json)?;
                                let hash = hex::encode(&msg.key);
                                if let Some(meta) = crate::metrics::storage::STORAGE.get_cache_meta(&hash) {
                                    let size = meta["s"].as_u64().unwrap_or(0);
                                    Ok(format!("value {} bytes", size))
                                } else {
                                    Ok("key not found".to_string())
                                }
                            })();

                            let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: result.is_ok(),
                                message: result.unwrap_or_else(|e| format!("Error: {:?}", e)),
                                ..Default::default()
                            }).await;
                        }
                        "statCache" => {
                            info!("Received cache stat command");
                            let total_size = crate::metrics::storage::STORAGE.total_cache_size();
                            let total_count = crate::metrics::storage::STORAGE.total_cache_count();
                            
                            let size_format = if total_size < (1 << 10) {
                                format!("{} Bytes", total_size)
                            } else if total_size < (1 << 20) {
                                format!("{:.2} KiB", total_size as f64 / 1024.0)
                            } else if total_size < (1 << 30) {
                                format!("{:.2} MiB", total_size as f64 / (1024.0 * 1024.0))
                            } else {
                                format!("{:.2} GiB", total_size as f64 / (1024.0 * 1024.0 * 1024.0))
                            };

                            let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: true,
                                message: format!("size:{}, count:{}", size_format, total_count),
                                ..Default::default()
                            }).await;
                        }
                        "cleanCache" => {
                             info!("Received cache clean command");
                             // Implementation could call purge_prefix("*") or similar
                             let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: true,
                                message: "ok".to_string(),
                                ..Default::default()
                            }).await;
                        }
                        "getStat" => {
                            let mut sys = sysinfo::System::new_all();
                            sys.refresh_cpu_all();
                            sys.refresh_memory();
                            let (traffic_out, traffic_in, connections) = crate::metrics::METRICS.get_node_totals();
                            let stat = serde_json::json!({
                                "cpuUsage": sys.global_cpu_usage() / 100.0,
                                "memUsage": sys.used_memory() as f64 / sys.total_memory() as f64,
                                "trafficIn": traffic_in,
                                "trafficOut": traffic_out,
                                "connections": connections,
                            });
                            let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: true,
                                data_json: stat.to_string().into_bytes(),
                                ..Default::default()
                            }).await;
                        }
                        "tieredOriginBypass" => {
                            let bypass = String::from_utf8_lossy(&message.data_json) == "true";
                            info!("Received Tiered Origin Bypass command: {}", bypass);
                            config_store.set_tiered_origin_bypass(bypass).await;
                            let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: true,
                                message: "ok".to_string(),
                                ..Default::default()
                            }).await;
                        }
                        "connectedAPINode" => {
                            if let Ok(msg) = serde_json::from_slice::<ConnectedAPINodeMessage>(&message.data_json) {
                                info!("Connected to API node {}", msg.api_node_id);
                                if let Ok(mut guard) = CONNECTED_API_NODE_IDS.write() { guard.insert(msg.api_node_id); }
                                report_connected_api_nodes(&api_config).await;
                            }
                            let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: true,
                                message: "ok".to_string(),
                                ..Default::default()
                            }).await;
                        }
                        "changeAPINode" => {
                            if let Ok(msg) = serde_json::from_slice::<ChangeAPINodeMessage>(&message.data_json) {
                                info!("Received API node change request to {}", msg.addr);
                                ApiConfig::set_runtime_rpc_endpoints(vec![msg.addr]);
                                should_reconnect = true;
                                break;
                            }
                        }
                        _ => {
                            let _ = tx.send(pb::NodeStreamMessage {
                                node_id: config_store.get_node_id().await,
                                request_id: message.request_id,
                                is_ok: true,
                                message: "accepted".to_string(),
                                ..Default::default()
                            }).await;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Node stream error: {}", e);
                if let Ok(mut guard) = CONNECTED_API_NODE_IDS.write() { guard.clear(); }
                report_connected_api_nodes(&api_config).await;
                let node_id = config_store.get_node_id().await;
                report_node_up(&api_config, node_id, false).await;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }

        if !should_reconnect { tokio::time::sleep(std::time::Duration::from_secs(5)).await; }
    }
}

pub async fn fetch_and_apply_config<F>(
    client: &mut pb::node_service_client::NodeServiceClient<tonic::service::interceptor::InterceptedService<Channel, F>>,
    config_store: &ConfigStore,
    api_config: &ApiConfig,
    ip_list_manager: &crate::firewall::lists::GlobalIpListManager,
    health_manager: &crate::health_manager::GlobalHealthManager,
    cert_selector: &crate::ssl::DynamicCertSelector,
    task_version: &mut i64,
    deleted_content_version: &mut i64,
    config_version: &mut i64,
) where F: FnMut(Request<()>) -> Result<Request<()>, Status> + Send + 'static,
{
    let current_id = config_store.get_node_id().await;
    let fetch_version = if current_id == 0 { -1 } else { *config_version };

    info!("RPC_NODE: Fetching config (requested version: {})", fetch_version);
    let req = Request::new(pb::FindCurrentNodeConfigRequest {
        version: fetch_version,
        compress: false,
        node_task_version: *task_version,
        use_data_map: true,
    });

    match client.find_current_node_config(req).await {
        Ok(resp) => {
            let config_resp = resp.into_inner();
            if config_resp.node_json.is_empty() {
                if !config_resp.is_changed {
                    info!("RPC_NODE: No configuration changes reported by API.");
                } else {
                    warn!("RPC_NODE: API reported change but sent empty JSON!");
                }
            } else {
                *config_version = config_resp.timestamp;
                match serde_json::from_slice::<crate::config_models::NodeConfigPayload>(&config_resp.node_json) {
                    Ok(payload) => {
                        let numeric_id = payload.id.unwrap_or(0);
                        info!("Successfully parsed NodeConfigPayload. Numeric ID: {}, Server count: {}", numeric_id, payload.servers.len());
                        config_store.update_id(numeric_id).await;
                        crate::logging::set_numeric_node_id(numeric_id);
                        
                        for cp in &payload.http_cache_policies {
                            info!("RPC_NODE: Loaded Global Cache Policy: {} (ID: {}, Type: {})", 
                                cp.name, cp.id, cp.r#type);
                            
                            if let Some(max_item_size) = &cp.max_item_size {
                                let size = crate::config_models::SizeCapacity::from_json(max_item_size);
                                info!("  - Max Item Size: {} {}", size.count, size.unit);
                            }

                            for (idx, r) in cp.cache_refs.iter().enumerate() {
                                if !r.is_on { continue; }
                                info!("  -> Rule #{}", idx + 1);
                                
                                // 1. Conditions / Extensions
                                if let Some(cond) = &r.simple_cond {
                                    if cond.operator == "fileExt" {
                                        info!("     - File Extensions: {}", cond.value);
                                    } else {
                                        info!("     - Condition: {} {} {}", cond.param, cond.operator, cond.value);
                                    }
                                } else if let Some(conds) = &r.conds {
                                    info!("     - Complex Conditions: {} groups", conds.groups.len());
                                } else {
                                    info!("     - Condition: Match All");
                                }

                                // 2. Cache Time
                                let life_seconds = r.life.as_ref().map(crate::config_models::parse_life_to_seconds).unwrap_or(3600);
                                let life_desc = if life_seconds >= 86400 {
                                    format!("{} days", life_seconds / 86400)
                                } else if life_seconds >= 3600 {
                                    format!("{} hours", life_seconds / 3600)
                                } else {
                                    format!("{} minutes", life_seconds / 60)
                                };
                                info!("     - Cache Duration: {}", life_desc);

                                // 3. Key / Ignore URI Params
                                if let Some(key) = &r.key {
                                    if !key.contains("${args}") && !key.contains("${arg:") {
                                        info!("     - Ignore URI Parameters: Yes");
                                    } else {
                                        info!("     - Cache Key: {}", key);
                                    }
                                }

                                // 4. Size Range
                                let min_bytes = r.min_size.as_ref().map(|v| crate::config_models::SizeCapacity::from_json(v).to_bytes()).unwrap_or(0);
                                let max_bytes = r.max_size.as_ref().map(|v| crate::config_models::SizeCapacity::from_json(v).to_bytes()).unwrap_or(0);
                                let min_desc = if min_bytes >= 1024 * 1024 { format!("{} MB", min_bytes / (1024*1024)) } else { format!("{} KB", min_bytes / 1024) };
                                let max_desc = if max_bytes > 0 { format!("{} MB", max_bytes / (1024*1024)) } else { "Unlimited".to_string() };
                                info!("     - Size Range: {} - {}", min_desc, max_desc);

                                // 5. Partial Cache
                                info!("     - Partial Caching (分片缓存): {}", if r.allow_partial_content { "Enabled" } else { "Disabled" });
                            }

                            crate::cache_manager::CACHE.storage.apply_policy(cp).await;
                        }

                        let mut new_servers = std::collections::HashMap::new();
                        let mut new_routes = std::collections::HashMap::new();
                        let mut all_certs = Vec::new();
                        let mut ssl_policy = serde_json::Value::Null;

                        let node_level = payload.level;
                        let parent_nodes = payload.parent_nodes.clone();
                        let tiered_origin_bypass = config_store.is_tiered_origin_bypass().await;

                        for server in &payload.servers {
                            if !server.is_on { continue; }
                            
                            if let Some(https) = &server.https {
                                if https.is_on {
                                    all_certs.extend(https.ssl_certs.clone());
                                    if let Some(policy) = &https.ssl_policy {
                                        ssl_policy = policy.clone();
                                    }
                                }
                            }

                            let lb_arc = crate::rpc::utils::build_lb(server, node_level, &parent_nodes, tiered_origin_bypass);
                            if let Some(id) = server.id {
                                health_manager.register(id, lb_arc.clone(), std::time::Duration::from_secs(30));
                            }
                            for name in &server.server_names {
                                new_servers.insert(name.clone(), server.clone());
                                new_routes.insert(name.clone(), lb_arc.clone());
                            }
                        }

                        crate::ssl::sync_certs(cert_selector, &all_certs, &ssl_policy).await;

                        config_store.update_config(
                            numeric_id, config_resp.timestamp, new_servers, new_routes,
                            vec![], vec![], payload.metric_items.clone(),
                            node_level, parent_nodes, tiered_origin_bypass,
                            payload.http_cache_policies.first().cloned(),
                            payload.http_firewall_policies.clone(),
                            payload.waf_actions.clone()
                        ).await;

                    }
                    Err(e) => error!("Error parsing NodeConfigPayload: {}", e),
                }
            }
        }
        Err(e) => error!("Error fetching node config: {}", e),
    }

    sync_deleted_contents(api_config, config_store, deleted_content_version).await;
    sync_node_tasks(api_config, config_store, health_manager, ip_list_manager, task_version).await;
}

pub async fn start_metrics_reporter(config_store: Arc<ConfigStore>, api_config: ApiConfig) {
    let mut sys = sysinfo::System::new_all();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        interval.tick().await;
        let node_id = config_store.get_node_id().await;
        if node_id == 0 { continue; }

        sys.refresh_cpu_all();
        sys.refresh_memory();
        let (traffic_out, traffic_in, connections) = crate::metrics::METRICS.get_node_totals();
        let (api_success_percent, api_avg_cost) = crate::metrics::METRICS.rpc.snapshot();
        let load = sysinfo::System::load_average();

        let status = serde_json::json!({
            "buildVersion": "1.1.5",
            "buildVersionCode": 1001005,
            "cpuUsage": sys.global_cpu_usage() / 100.0,
            "memUsage": sys.used_memory() as f64 / sys.total_memory() as f64,
            "totalMemory": sys.total_memory(),
            "load1": load.one, "load5": load.five, "load15": load.fifteen,
            "trafficInBytes": traffic_in, "trafficOutBytes": traffic_out,
            "connectionCount": connections,
            "apiSuccessPercent": api_success_percent,
            "apiAvgCostSeconds": api_avg_cost,
            "cacheTotalDiskSize": crate::metrics::storage::STORAGE.total_cache_size(),
            "updatedAt": chrono::Utc::now().timestamp(),
            "isActive": true, "isHealthy": true,
        });

        if let Ok(client) = RpcClient::new(&api_config).await {
            let mut service = client.node_service();
            let _ = service.update_node_status(pb::UpdateNodeStatusRequest {
                node_id,
                status_json: status.to_string().into_bytes(),
            }).await;
        }
    }
}

pub async fn start_node_value_reporter(config_store: Arc<ConfigStore>, api_config: ApiConfig) {
    let mut sys = sysinfo::System::new_all();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;
        let node_id = config_store.get_node_id().await;
        if node_id == 0 { continue; }

        sys.refresh_cpu_all();
        sys.refresh_memory();
        let (traffic_out, traffic_in, connections) = crate::metrics::METRICS.get_node_totals();
        let values = vec![
            ("cpu", serde_json::json!({"usage": sys.global_cpu_usage() / 100.0})),
            ("memory", serde_json::json!({"usage": sys.used_memory() as f64 / sys.total_memory() as f64})),
            ("connections", serde_json::json!({"total": connections})),
            ("traffic", serde_json::json!({"in": traffic_in, "out": traffic_out})),
        ];

        let node_value_items = values.into_iter().map(|(item, value)| pb::create_node_values_request::NodeValueItem {
            item: item.to_string(),
            value_json: value.to_string().into_bytes(),
            created_at: chrono::Utc::now().timestamp(),
        }).collect();

        if let Ok(client) = RpcClient::new(&api_config).await {
            let _ = client.node_value_service().create_node_values(pb::CreateNodeValuesRequest { node_value_items }).await;
        }
    }
}
