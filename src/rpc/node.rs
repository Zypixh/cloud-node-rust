use futures_util::FutureExt;
use once_cell::sync::Lazy;
use std::io::Read;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use tonic::transport::Channel;
use tonic::{Request, Status};
use tracing::{debug, error, info, warn};

use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::RpcClient;
use crate::rpc::node_task::sync_node_tasks;
use crate::rpc::plan::sync_active_plans;
use crate::rpc::utils::sync_deleted_contents;
use std::collections::HashSet;

pub(crate) static CONNECTED_API_NODE_IDS: Lazy<RwLock<HashSet<i64>>> =
    Lazy::new(|| RwLock::new(HashSet::new()));

static REPORT_NOTIFY: Lazy<tokio::sync::Notify> = Lazy::new(tokio::sync::Notify::new);

pub fn trigger_api_node_report() {
    REPORT_NOTIFY.notify_one();
}

static LAST_CONFIG_HASH: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));
static LAST_WAF_HASH: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));
static LAST_GLOBAL_CONFIG_HASH: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));

fn log_raw_json_hints(label: &str, raw: &[u8]) {
    let text = String::from_utf8_lossy(raw);
    for needle in ["@sni_passthrough", "speedtest", "www.speedtest.cn"] {
        if let Some(pos) = text.find(needle) {
            let start = pos.saturating_sub(240);
            let end = (pos + needle.len() + 240).min(text.len());
            info!(
                "RPC_NODE: Raw {} contains {:?}. snippet={}",
                label,
                needle,
                &text[start..end]
            );
        }
    }
}

fn parse_i64_keyed_map<T>(
    raw: &std::collections::HashMap<String, T>,
) -> std::collections::HashMap<i64, T>
where
    T: Clone,
{
    raw.iter()
        .filter_map(|(key, value)| key.parse::<i64>().ok().map(|id| (id, value.clone())))
        .collect()
}

async fn report_connected_api_nodes(api_config: &ApiConfig) {
    let api_node_ids = CONNECTED_API_NODE_IDS
        .read()
        .ok()
        .map(|guard| guard.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();

    if api_node_ids.is_empty() {
        return;
    }

    if let Ok(client) = RpcClient::new(api_config).await {
        let mut node_service = client.node_service_with_type();
        match node_service
            .update_node_connected_api_nodes(pb::UpdateNodeConnectedApiNodesRequest {
                api_node_ids: api_node_ids.clone(),
            })
            .await
        {
            Ok(_) => info!(
                "Successfully reported connected API nodes: {:?}",
                api_node_ids
            ),
            Err(e) => warn!("Failed to report connected API nodes: {}", e),
        }
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

    let api_endpoint = api_config
        .effective_rpc_endpoints()
        .first()
        .cloned()
        .unwrap_or_default();
    info!(
        "Config syncer service started for API Node {} (Node ID: {})",
        api_endpoint, api_config.node_id
    );

    loop {
        debug!("RPC_NODE: Starting periodic configuration sync check.");

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
            &mut node_service,
            &config_store,
            &api_config,
            &ip_list_manager,
            &health_manager,
            &cert_selector,
            &mut task_version,
            &mut deleted_content_version,
            &mut config_version,
        )
        .await;

        report_connected_api_nodes(&api_config).await;

        state.config_version = config_version;
        state.task_version = task_version;
        state.deleted_content_version = deleted_content_version;
        crate::utils::persistence::save_state(&state);

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                debug!("Periodic config sync triggered.");
            }
            _ = crate::rpc::node_task::wait_for_task_sync() => {
                info!("Stream-triggered immediate config sync started.");
            }
            _ = REPORT_NOTIFY.notified() => {
                info!("Stream-triggered immediate API node reporting.");
                report_connected_api_nodes(&api_config).await;
            }
        }
    }
}

fn log_global_settings(
    payload: &crate::config_models::NodeConfigPayload,
    server_name: &str,
    force_ln: bool,
    ln_method: &str,
    supports_low_version_http: bool,
    match_cert_from_all_servers: bool,
    enable_server_addr_variable: bool,
    request_origins_with_encodings: bool,
    xff_max_addresses: i32,
    allow_lan_ip: bool,
    grpc_policy: &Option<crate::config_models::GRPCConfig>,
) {
    let global_settings_hash_input = format!(
        "{:?}-{:?}-{:?}",
        payload.global_server_config, payload.is_on, payload.enable_ip_lists
    );
    let current_gsc_hash = format!("{:x}", md5_legacy::compute(&global_settings_hash_input));

    let mut last_gsc_hash = LAST_GLOBAL_CONFIG_HASH.write().unwrap();
    if *last_gsc_hash != current_gsc_hash {
        *last_gsc_hash = current_gsc_hash;

        info!("RPC_NODE: Global Cluster/Node Settings Updated:");
        info!(
            "  - Node Enabled (isOn): {}",
            if payload.is_on {
                "YES"
            } else {
                "NO (Inaccessible)"
            }
        );
        info!(
            "  - Sync IP Lists: {}",
            if payload.enable_ip_lists { "YES" } else { "No" }
        );
        info!(
            "  - Server Flag: {}",
            if server_name.is_empty() {
                "Default"
            } else {
                server_name
            }
        );
        info!(
            "  - Force Ln Request: {}",
            if force_ln { "YES" } else { "No" }
        );
        info!("  - Ln Scheduling Method: {}", ln_method);
        info!(
            "  - Support Low HTTP Versions (<1.1): {}",
            if supports_low_version_http {
                "YES"
            } else {
                "No"
            }
        );
        info!(
            "  - Match Cert From All Servers: {}",
            if match_cert_from_all_servers {
                "YES"
            } else {
                "No"
            }
        );
        info!(
            "  - Enable ${{serverAddr}} Variable: {}",
            if enable_server_addr_variable {
                "YES"
            } else {
                "No"
            }
        );
        info!(
            "  - Auto Gzip Back to Origin: {}",
            if request_origins_with_encodings {
                "YES"
            } else {
                "No"
            }
        );
        info!(
            "  - XFF Max Addresses: {}",
            if xff_max_addresses == 0 {
                "Unlimited".to_string()
            } else {
                xff_max_addresses.to_string()
            }
        );
        info!(
            "  - Allow LAN Origin IP: {}",
            if allow_lan_ip {
                "YES (WARNING: Security Risk)"
            } else {
                "No"
            }
        );

        if let Some(gp) = grpc_policy {
            if gp.is_on {
                let r_size = gp
                    .max_receive_message_size
                    .as_ref()
                    .map(|s| format!("{} {}", s.count, s.unit))
                    .unwrap_or_else(|| "2 MiB".to_string());
                let s_size = gp
                    .max_send_message_size
                    .as_ref()
                    .map(|s| format!("{} {}", s.count, s.unit))
                    .unwrap_or_else(|| "2 MiB".to_string());
                info!(
                    "  - gRPC Proxy: ENABLED (Max Message: Recv={}, Send={})",
                    r_size, s_size
                );
            }
        }
    }
}

pub async fn fetch_and_apply_config<F>(
    client: &mut pb::node_service_client::NodeServiceClient<
        tonic::service::interceptor::InterceptedService<Channel, F>,
    >,
    config_store: &ConfigStore,
    api_config: &ApiConfig,
    ip_list_manager: &crate::firewall::lists::GlobalIpListManager,
    health_manager: &crate::health_manager::GlobalHealthManager,
    cert_selector: &crate::ssl::DynamicCertSelector,
    task_version: &mut i64,
    deleted_content_version: &mut i64,
    config_version: &mut i64,
) where
    F: FnMut(Request<()>) -> Result<Request<()>, Status> + Send + 'static,
{
    let current_id = config_store.get_node_id().await;
    let fetch_version = if current_id == 0 { -1 } else { *config_version };

    debug!(
        "RPC_NODE: Fetching config (requested version: {})",
        fetch_version
    );
    let req = Request::new(pb::FindCurrentNodeConfigRequest {
        version: fetch_version,
        compress: false,
        node_task_version: *task_version,
        use_data_map: false,
    });

    match client.find_current_node_config(req).await {
        Ok(resp) => {
            let config_resp = resp.into_inner();
            if config_resp.node_json.is_empty() {
                if !config_resp.is_changed {
                    debug!("RPC_NODE: No configuration changes reported by API.");
                    return; // Early return to avoid reprocessing same config
                } else {
                    warn!("RPC_NODE: API reported change but sent empty JSON!");
                }
            } else {
                debug!(
                    "RPC_NODE: Received node_json ({} bytes). First 256 bytes: {}",
                    config_resp.node_json.len(),
                    String::from_utf8_lossy(
                        &config_resp.node_json[..std::cmp::min(256, config_resp.node_json.len())]
                    )
                );
                *config_version = config_resp.timestamp;
                let mut node_json = config_resp.node_json;

                if config_resp.is_compressed {
                    let mut decompressor = brotli::Decompressor::new(&node_json[..], 4096);
                    let mut decoded = Vec::new();
                    if let Err(e) = decompressor.read_to_end(&mut decoded) {
                        error!("Failed to decompress node_json: {}", e);
                        return;
                    }
                    node_json = decoded;
                }

                // Check content hash to avoid redundant reloads
                let current_hash = format!("{:x}", md5_legacy::compute(&node_json));
                let mut should_reload = true;
                {
                    let last_hash = LAST_CONFIG_HASH.read().unwrap();
                    if *last_hash == current_hash {
                        debug!(
                            "RPC_NODE: Configuration content unchanged (Hash: {}), skipping heavy reload.",
                            current_hash
                        );
                        should_reload = false;
                    }
                }

                *config_version = config_resp.timestamp;

                if should_reload {
                    log_raw_json_hints("node_json", &node_json);
                    // Content changed, update hash and proceed
                    {
                        let mut last_hash = LAST_CONFIG_HASH.write().unwrap();
                        *last_hash = current_hash;
                    }

                    match serde_json::from_slice::<crate::config_models::NodeConfigPayload>(
                        &node_json,
                    ) {
                        Ok(payload) => {
                            let numeric_id = payload.id.unwrap_or(0);

                            debug!(
                                "Successfully parsed NodeConfigPayload. Numeric ID: {}, Server count: {}",
                                numeric_id,
                                payload.servers.len()
                            );
                            if let Some(gsc) = &payload.global_server_config {
                                debug!("RPC_NODE: Found GlobalServerConfig: {:?}", gsc);
                            }
                            config_store.update_id(numeric_id).await;
                            crate::logging::set_numeric_node_id(numeric_id);

                            for cp in &payload.http_cache_policies {
                                info!(
                                    "RPC_NODE: Loaded Global Cache Policy: {} (ID: {}, Type: {})",
                                    cp.name, cp.id, cp.r#type
                                );

                                if let Some(max_item_size) = &cp.max_item_size {
                                    let size = crate::config_models::SizeCapacity::from_json(
                                        max_item_size,
                                    );
                                    debug!("  - Max Item Size: {} {}", size.count, size.unit);
                                }

                                for (idx, r) in cp.cache_refs.iter().enumerate() {
                                    if !r.is_on {
                                        continue;
                                    }
                                    debug!("  -> Rule #{}", idx + 1);

                                    // 1. Conditions / Extensions
                                    if let Some(cond) = &r.simple_cond {
                                        if cond.operator == "fileExt" {
                                            debug!("     - File Extensions: {}", cond.value);
                                        } else {
                                            debug!(
                                                "     - Condition: {} {} {}",
                                                cond.param, cond.operator, cond.value
                                            );
                                        }
                                    } else if let Some(conds) = &r.conds {
                                        debug!(
                                            "     - Complex Conditions: {} groups",
                                            conds.groups.len()
                                        );
                                    } else {
                                        debug!("     - Condition: Match All");
                                    }

                                    // 2. Cache Time
                                    let life_seconds = r
                                        .life
                                        .as_ref()
                                        .map(crate::config_models::parse_life_to_seconds)
                                        .unwrap_or(3600);
                                    let life_desc = if life_seconds >= 86400 {
                                        format!("{} days", life_seconds / 86400)
                                    } else if life_seconds >= 3600 {
                                        format!("{} hours", life_seconds / 3600)
                                    } else {
                                        format!("{} minutes", life_seconds / 60)
                                    };
                                    debug!("     - Cache Duration: {}", life_desc);

                                    // 3. Key / Ignore URI Params
                                    if let Some(key) = &r.key {
                                        if !key.contains("${args}") && !key.contains("${arg:") {
                                            debug!("     - Ignore URI Parameters: Yes");
                                        } else {
                                            debug!("     - Cache Key: {}", key);
                                        }
                                    }

                                    // 4. Size Range
                                    let min_bytes = r
                                        .min_size
                                        .as_ref()
                                        .map(|v| {
                                            crate::config_models::SizeCapacity::from_json(v)
                                                .to_bytes()
                                        })
                                        .unwrap_or(0);
                                    let max_bytes = r
                                        .max_size
                                        .as_ref()
                                        .map(|v| {
                                            crate::config_models::SizeCapacity::from_json(v)
                                                .to_bytes()
                                        })
                                        .unwrap_or(0);
                                    let min_desc = if min_bytes >= 1024 * 1024 {
                                        format!("{} MB", min_bytes / (1024 * 1024))
                                    } else {
                                        format!("{} KB", min_bytes / 1024)
                                    };
                                    let max_desc = if max_bytes > 0 {
                                        format!("{} MB", max_bytes / (1024 * 1024))
                                    } else {
                                        "Unlimited".to_string()
                                    };
                                    debug!("     - Size Range: {} - {}", min_desc, max_desc);

                                    // 5. Partial Cache
                                    debug!(
                                        "     - Partial Caching (分片缓存): {}",
                                        if r.allow_partial_content {
                                            "Enabled"
                                        } else {
                                            "Disabled"
                                        }
                                    );
                                }
                                crate::cache_manager::CACHE.storage.apply_policy(cp).await;
                            }

                            // WAF Configuration Hashing and Logging
                            let current_waf_hash = format!(
                                "{:x}",
                                md5_legacy::compute(
                                    serde_json::to_string(&(
                                        payload.http_firewall_policies.clone(),
                                        payload.waf_actions.clone()
                                    ))
                                    .unwrap_or_default()
                                )
                            );
                            let mut waf_changed = false;
                            {
                                let mut last_waf_hash = LAST_WAF_HASH.write().unwrap();
                                if *last_waf_hash != current_waf_hash {
                                    *last_waf_hash = current_waf_hash;
                                    waf_changed = true;
                                }
                            }

                            if waf_changed {
                                for wp in &payload.http_firewall_policies {
                                    info!(
                                        "RPC_NODE: Loaded Global WAF Policy: {} (ID: {}, Mode: {}, IsOn: {})",
                                        wp.name, wp.id, wp.mode, wp.is_on
                                    );
                                    if let Some(inbound) = &wp.inbound {
                                        if !inbound.is_on {
                                            debug!("  - Inbound filtering: Disabled");
                                            continue;
                                        }
                                        for group in &inbound.groups {
                                            if !group.is_on {
                                                continue;
                                            }
                                            for set in &group.sets {
                                                if !set.is_on {
                                                    continue;
                                                }
                                                let mut set_desc = format!(
                                                    "  -> Rule Set: {} (Connector: {})",
                                                    set.name, set.connector
                                                );
                                                if set.ignore_local {
                                                    set_desc.push_str(", IgnoreLocal: Yes");
                                                }
                                                if set.ignore_search_engine {
                                                    set_desc.push_str(", IgnoreSearchEngine: Yes");
                                                }

                                                let actions: Vec<String> = set
                                                    .actions
                                                    .iter()
                                                    .filter_map(|a| {
                                                        a.get("code")
                                                            .and_then(|v| v.as_str())
                                                            .map(|s| s.to_string())
                                                    })
                                                    .collect();
                                                if !actions.is_empty() {
                                                    set_desc.push_str(&format!(
                                                        ", Actions: [{}]",
                                                        actions.join(", ")
                                                    ));
                                                }
                                                debug!("{}", set_desc);

                                                for rule in &set.rules {
                                                    let op = if rule.is_reverse {
                                                        format!("NOT {}", rule.operator)
                                                    } else {
                                                        rule.operator.clone()
                                                    };
                                                    let case = if rule.is_case_insensitive {
                                                        " (Case-Insensitive)"
                                                    } else {
                                                        ""
                                                    };

                                                    // Handle variable parameters (e.g., ${header:User-Agent})
                                                    let mut param = rule.param.clone();
                                                    if let Some(opts) = &rule.checkpoint_options {
                                                        if let Some(key) = opts
                                                            .get("name")
                                                            .and_then(|v| v.as_str())
                                                        {
                                                            param = format!("{}:{}", param, key);
                                                        }
                                                    }

                                                    let val_display = if rule.value.is_empty() {
                                                        "[empty]".to_string()
                                                    } else {
                                                        format!(
                                                            "\"{}\"",
                                                            rule.value.replace("\n", " | ")
                                                        )
                                                    };

                                                    debug!(
                                                        "     - Rule: {} {} {}{}",
                                                        param, op, val_display, case
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            let mut new_servers = std::collections::HashMap::new();
                            let mut new_routes = std::collections::HashMap::new();
                            let mut all_certs = Vec::new();
                            let mut active_ssl_policy: Option<
                                crate::config_models::SSLPolicyConfig,
                            > = None;

                            // 1. Collect everything first
                            all_certs.extend(payload.ssl_certs.clone());
                            if let Some(policy) = &payload.ssl_policy {
                                active_ssl_policy = Some(policy.clone());
                            }

                            for server in &payload.servers {
                                if !server.is_on {
                                    continue;
                                }
                                if let Some(https) = &server.https {
                                    if https.is_on {
                                        if let Some(policy) = &https.ssl_policy {
                                            all_certs.extend(policy.certs.clone());
                                            active_ssl_policy = Some(policy.clone());
                                        }
                                    }
                                }
                            }

                            // 2. Restore from DataMap if exists
                            let mut has_data_map_refs = false;
                            for cert in &all_certs {
                                if let Some(c) = &cert.cert_data_json {
                                    if c.as_str()
                                        .map(|s| s.contains("_DATA_MAP:"))
                                        .unwrap_or(false)
                                    {
                                        has_data_map_refs = true;
                                        break;
                                    }
                                }
                                if let Some(k) = &cert.key_data_json {
                                    if k.as_str()
                                        .map(|s| s.contains("_DATA_MAP:"))
                                        .unwrap_or(false)
                                    {
                                        has_data_map_refs = true;
                                        break;
                                    }
                                }
                            }

                            if let Some(dm) = &payload.data_map {
                                tracing::debug!(
                                    "RPC_NODE: DataMap found with {} entries. Restoring certificates...",
                                    dm.r#map.len()
                                );
                                let mut restored_count = 0;
                                let mut restore_cert =
                                    |cert: &mut crate::config_models::SSLCertConfig| {
                                        use base64::{Engine as _, engine::general_purpose};
                                        let mut process_field =
                                            |val: &mut Option<serde_json::Value>| {
                                                if let Some(serde_json::Value::String(s)) = val {
                                                    let raw_ref = if s.starts_with("base64:") {
                                                        let b64 =
                                                            s.strip_prefix("base64:").unwrap_or(s);
                                                        if let Ok(decoded) =
                                                            general_purpose::STANDARD
                                                                .decode(b64.trim())
                                                        {
                                                            String::from_utf8_lossy(&decoded)
                                                                .to_string()
                                                        } else {
                                                            s.clone()
                                                        }
                                                    } else {
                                                        s.clone()
                                                    };

                                                    if raw_ref.contains("_DATA_MAP:") {
                                                        if let Some(real_val) =
                                                            dm.r#map.get(&raw_ref)
                                                        {
                                                            *val = Some(serde_json::Value::String(
                                                                real_val.clone(),
                                                            ));
                                                            restored_count += 1;
                                                        } else {
                                                            tracing::warn!(
                                                                "RPC_NODE: DataMap reference {} not found in map",
                                                                raw_ref
                                                            );
                                                        }
                                                    }
                                                }
                                            };
                                        process_field(&mut cert.cert_data_json);
                                        process_field(&mut cert.key_data_json);
                                    };

                                for cert in &mut all_certs {
                                    restore_cert(cert);
                                }
                                tracing::debug!(
                                    "RPC_NODE: Restored {} fields from DataMap",
                                    restored_count
                                );
                            } else if has_data_map_refs {
                                tracing::warn!(
                                    "RPC_NODE: DataMap references found but NO DataMap in payload. Certificates will fail to parse."
                                );
                            }

                            let node_level = payload.level;
                            let parent_nodes: std::collections::HashMap<
                                i64,
                                Vec<crate::config_models::ParentNodeConfig>,
                            > = payload
                                .parent_nodes
                                .iter()
                                .filter_map(|(k, v)| {
                                    k.parse::<i64>().ok().map(|id| (id, v.clone()))
                                })
                                .collect();
                            let tiered_origin_bypass = config_store.is_tiered_origin_bypass().await;
                            let mut new_id_to_lb = std::collections::HashMap::new();

                            // Pre-extract Global Settings needed during LB construction
                            let mut allow_lan_ip = false;
                            let mut force_ln = false;
                            let mut ln_method = "random".to_string();
                            let mut supports_low_version_http = false;
                            let mut match_cert_from_all_servers = false;
                            let mut server_name = String::new();
                            let mut enable_server_addr_variable = false;
                            let mut request_origins_with_encodings = false;
                            let mut xff_max_addresses = 0;

                            if let Some(gsc) = &payload.global_server_config {
                                if let Some(http_all) = &gsc.http_all {
                                    allow_lan_ip = http_all.allow_lan_ip;
                                    force_ln = http_all.force_ln_request;
                                    ln_method = http_all.ln_request_scheduling_method.clone();
                                    supports_low_version_http = http_all.supports_low_version_http;
                                    match_cert_from_all_servers =
                                        http_all.match_cert_from_all_servers;
                                    server_name = http_all.server_name.clone();
                                    enable_server_addr_variable =
                                        http_all.enable_server_addr_variable;
                                    request_origins_with_encodings =
                                        http_all.request_origins_with_encodings;
                                    xff_max_addresses = http_all.xff_max_addresses;
                                }
                            }

                            let mut loaded_domain_names = std::collections::BTreeSet::new();
                            let mut port_only_server_count = 0usize;

                            for server in &payload.servers {
                                if !server.is_on {
                                    info!(
                                        "RPC_NODE: Skipping server {} because it is OFF",
                                        server.numeric_id()
                                    );
                                    continue;
                                }

                                if server.is_sni_passthrough() {
                                    match serde_json::to_string(server) {
                                        Ok(raw) => info!(
                                            "RPC_NODE: SNI passthrough server loaded. id={} names={:?} raw_json={}",
                                            server.numeric_id(),
                                            server.get_plain_server_names(),
                                            raw
                                        ),
                                        Err(err) => warn!(
                                            "RPC_NODE: Failed to serialize SNI passthrough server {} for debug logging: {}",
                                            server.numeric_id(),
                                            err
                                        ),
                                    }
                                }

                                let server_id = server.numeric_id();
                                let names = server.get_plain_server_names();
                                let (lb_arc, has_hc) = match &server.reverse_proxy {
                                    Some(rp_cfg) => crate::lb_factory::build_lb(
                                        server_id,
                                        rp_cfg,
                                        node_level,
                                        &parent_nodes,
                                        tiered_origin_bypass,
                                        allow_lan_ip,
                                    ),
                                    None => {
                                        // Default/Dummy LB if no reverse proxy config exists
                                        let mut b =
                                            pingora_load_balancing::Backend::new("127.0.0.1:80")
                                                .unwrap();
                                        let mut ext = http::Extensions::new();
                                        ext.insert(crate::lb_factory::BackendExtension {
                                            use_tls: false,
                                            host: String::new(),
                                            follow_host: false,
                                            tls_verify: true,
                                            client_cert: None,
                                        });
                                        b.ext = ext;
                                        let mut set = std::collections::BTreeSet::new();
                                        set.insert(b);
                                        let backends = pingora_load_balancing::Backends::new(
                                            pingora_load_balancing::discovery::Static::new(set),
                                        );
                                        let lb =
                                            pingora_load_balancing::LoadBalancer::from_backends(
                                                backends,
                                            );
                                        lb.update()
                                            .now_or_never()
                                            .expect("static fallback load balancer update should not block")
                                            .expect("static fallback load balancer update should not fail");
                                        (std::sync::Arc::new(lb), false)
                                    }
                                };
                                let server_id = server.numeric_id();
                                if server_id > 0 {
                                    new_id_to_lb.insert(server_id, lb_arc.clone());
                                    if has_hc {
                                        health_manager.register(
                                            server_id,
                                            lb_arc.clone(),
                                            std::time::Duration::from_secs(30),
                                        );
                                    }
                                }

                                if names.is_empty() {
                                    port_only_server_count += 1;
                                    if server.http.is_some() || server.https.is_some() {
                                        warn!(
                                            "RPC_NODE: HTTP/HTTPS Server {} has NO server names, only routable via direct port",
                                            server.numeric_id()
                                        );
                                    } else {
                                        debug!(
                                            "RPC_NODE: L4 Server {} initialized without names (Port-based routing)",
                                            server.numeric_id()
                                        );
                                    }
                                    new_servers.insert(
                                        format!("__id_{}", server.numeric_id()),
                                        Arc::new(server.clone()),
                                    );
                                    new_routes.insert(
                                        format!("__id_{}", server.numeric_id()),
                                        lb_arc.clone(),
                                    );
                                } else {
                                    debug!(
                                        "RPC_NODE: Server {} has names: {:?}",
                                        server.numeric_id(),
                                        names
                                    );
                                    for name in names {
                                        loaded_domain_names.insert(name.clone());
                                        if let Some(existing) = new_servers.get(&name) {
                                            warn!(
                                                "RPC_NODE: Host mapping overwrite detected for {}. existing_server_id={} existing_description={:?} new_server_id={} new_description={:?}",
                                                name,
                                                existing.numeric_id(),
                                                existing.description,
                                                server.numeric_id(),
                                                server.description
                                            );
                                        }
                                        new_servers.insert(name.clone(), Arc::new(server.clone()));
                                        new_routes.insert(name.clone(), lb_arc.clone());
                                    }
                                }

                                // 1. Collect server-specific certificates via SSLPolicy
                                if let Some(https) = &server.https {
                                    if https.is_on {
                                        if let Some(policy) = &https.ssl_policy {
                                            if !policy.certs.is_empty() {
                                                all_certs.extend(policy.certs.clone());
                                            }
                                            // Prefer server-level policy
                                            active_ssl_policy = Some(policy.clone());
                                        }
                                        debug!(
                                            "RPC_NODE: Server {} has HTTPS ON (Listen count: {})",
                                            server.numeric_id(),
                                            https.listen.len()
                                        );
                                    } else {
                                        debug!(
                                            "RPC_NODE: Server {} has HTTPS config but is_on is false",
                                            server.numeric_id()
                                        );
                                    }
                                } else {
                                    debug!(
                                        "RPC_NODE: Server {} has NO HTTPS config",
                                        server.numeric_id()
                                    );
                                }

                                if let Some(http) = &server.http {
                                    if http.is_on {
                                        debug!(
                                            "RPC_NODE: Server {} has HTTP ON (Listen count: {})",
                                            server.numeric_id(),
                                            http.listen.len()
                                        );
                                    } else {
                                        debug!(
                                            "RPC_NODE: Server {} has HTTP config but is_on is false",
                                            server.numeric_id()
                                        );
                                    }
                                } else {
                                    debug!(
                                        "RPC_NODE: Server {} has NO HTTP config",
                                        server.numeric_id()
                                    );
                                }
                            }

                            if loaded_domain_names.is_empty() {
                                info!(
                                    "RPC_NODE: Loaded 0 named domains. Port-only servers: {}",
                                    port_only_server_count
                                );
                            } else {
                                let loaded_names: Vec<_> =
                                    loaded_domain_names.into_iter().collect();
                                info!(
                                    "RPC_NODE: Loaded {} named domains. Port-only servers: {}",
                                    loaded_names.len(),
                                    port_only_server_count
                                );
                                for chunk in loaded_names.chunks(20) {
                                    info!("RPC_NODE: Domains => {}", chunk.join(", "));
                                }
                            }

                            info!(
                                "RPC_NODE: Loaded global custom pages: {}. Global page policies: {}",
                                payload.global_pages.len(),
                                payload.http_pages_policies.len()
                            );

                            tracing::debug!(
                                "Received {} certificates from RPC, starting sync...",
                                all_certs.len()
                            );
                            crate::ssl::sync_certs(
                                cert_selector,
                                &all_certs,
                                active_ssl_policy.as_ref(),
                            )
                            .await;
                            tracing::debug!("Certificate sync completed");

                            // 4. gRPC Policy
                            let grpc_policy = payload.primary_grpc_policy.clone();

                            // --- GLOBAL SETTINGS LOGGING ---
                            log_global_settings(
                                &payload,
                                &server_name,
                                force_ln,
                                &ln_method,
                                supports_low_version_http,
                                match_cert_from_all_servers,
                                enable_server_addr_variable,
                                request_origins_with_encodings,
                                xff_max_addresses,
                                allow_lan_ip,
                                &grpc_policy,
                            );

                            let mut new_parent_routes = std::collections::HashMap::new();
                            for (cluster_id, nodes) in &parent_nodes {
                                let lb = crate::lb_factory::build_parent_lb(
                                    *cluster_id,
                                    nodes,
                                    allow_lan_ip,
                                );
                                new_parent_routes.insert(*cluster_id, lb);
                            }

                            config_store
                                .update_config(
                                    numeric_id,
                                    config_resp.timestamp,
                                    payload.node_region.as_ref().map(|r| r.id).unwrap_or(0),
                                    payload.servers.clone().into_iter().map(Arc::new).collect(),
                                    new_servers,
                                    new_routes,
                                    new_id_to_lb,
                                    vec![],
                                    payload.global_pages.clone(),
                                    payload.metric_items.clone(),
                                    node_level,
                                    payload.is_on,
                                    payload.enable_ip_lists,
                                    parent_nodes,
                                    tiered_origin_bypass,
                                    force_ln,
                                    ln_method,
                                    new_parent_routes,
                                    grpc_policy,
                                    supports_low_version_http,
                                    match_cert_from_all_servers,
                                    server_name,
                                    enable_server_addr_variable,
                                    request_origins_with_encodings,
                                    xff_max_addresses,
                                    allow_lan_ip,
                                    payload.http_cache_policies.iter().map(|p| Arc::new(p.clone())).collect(),
                                    payload.http_firewall_policies.clone(),
                                    payload.waf_actions.clone(),
                                    parse_i64_keyed_map(&payload.uam_policies),
                                    parse_i64_keyed_map(&payload.http_cc_policies),
                                    parse_i64_keyed_map(&payload.http3_policies),
                                    parse_i64_keyed_map(&payload.http_pages_policies),
                                    parse_i64_keyed_map(&payload.webp_image_policies),
                                    payload.toa.clone(),
                                    payload.global_server_config.as_ref().and_then(|g| g.http_access_log.clone()),
                                )
                                .await;

                            if payload.toa.as_ref().map(|toa| toa.is_on).unwrap_or(false) {
                                let toa_config = payload.toa.clone();
                                tokio::spawn(async move {
                                    if let Err(err) =
                                        crate::toa::maybe_prepare_runtime(toa_config).await
                                    {
                                        warn!(
                                            "Failed to auto-prepare TOA runtime after config sync: {}",
                                            err
                                        );
                                    }
                                });
                            }

                            let _ = sync_active_plans(api_config, config_store).await;
                            // Fetch enabled features for management-plane reporting
                            if numeric_id > 0 {
                                if let Ok(client) = RpcClient::new(api_config).await {
                                    let mut service = client.node_service();
                                    match service
                                        .find_enabled_node_config_info(pb::FindEnabledNodeConfigInfoRequest {
                                            node_id: numeric_id,
                                        })
                                        .await
                                    {
                                        Ok(resp) => {
                                            let info = resp.into_inner();
                                            debug!("Node enabled features: DNS={} Cache={} Thresholds={} Sys={} DDoS={} Sched={} AccessLog={}",
                                                info.has_dns_info, info.has_cache_info, info.has_thresholds,
                                                info.has_system_settings, info.has_d_do_s_protection,
                                                info.has_schedule_settings, info.has_access_log_settings);
                                        }
                                        Err(e) => debug!("Failed to fetch enabled features: {}", e),
                                    }
                                }
                            }
                        }
                        Err(e) => error!("Error parsing NodeConfigPayload: {}", e),
                    }
                }
            }
        }
        Err(e) => error!("Error fetching node config: {}", e),
    }

    sync_deleted_contents(api_config, config_store, deleted_content_version).await;
    sync_node_tasks(
        api_config,
        config_store,
        health_manager,
        ip_list_manager,
        task_version,
    )
    .await;
}

pub async fn start_metrics_reporter(config_store: Arc<ConfigStore>, api_config: ApiConfig) {
    let mut sys = sysinfo::System::new_all();
    // Initial refresh to populate CPU baseline
    sys.refresh_all();

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        interval.tick().await;
        let node_id = config_store.get_node_id().await;
        if node_id == 0 {
            continue;
        }

        sys.refresh_all(); // Refresh everything
        let (traffic_out, traffic_in, connections) = crate::metrics::METRICS.get_node_totals();
        let rpc_snap = crate::metrics::METRICS.rpc.snapshot();
        let api_success_percent = if rpc_snap.total_requests > 0 {
            (rpc_snap.total_requests - rpc_snap.total_errors) as f64 / rpc_snap.total_requests as f64
        } else {
            1.0
        };
        let api_avg_cost = if rpc_snap.total_requests > 0 {
            rpc_snap.total_cost_ms as f64 / rpc_snap.total_requests as f64
        } else {
            0.0
        };
        let load = sysinfo::System::load_average();

        #[allow(unused_mut)]
        let mut total_memory = sys.total_memory() as i64;
        #[allow(unused_mut)]
        let mut used_memory = sys.used_memory() as i64;

        // Linux container cgroup memory limit detection
        #[cfg(target_os = "linux")]
        {
            if let Ok(limit_str) =
                std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
            {
                if let Ok(limit) = limit_str.trim().parse::<i64>() {
                    if limit > 0 && limit < 1024 * 1024 * 1024 * 1024 {
                        total_memory = limit;
                        // For used memory in CGroup V1
                        if let Ok(usage_str) =
                            std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
                        {
                            if let Ok(usage) = usage_str.trim().parse::<i64>() {
                                used_memory = usage;
                            }
                        }
                    }
                }
            } else if let Ok(limit_str) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
                if let Ok(limit) = limit_str.trim().parse::<i64>() {
                    if limit > 0 {
                        total_memory = limit;
                        if let Ok(usage_str) =
                            std::fs::read_to_string("/sys/fs/cgroup/memory.current")
                        {
                            if let Ok(usage) = usage_str.trim().parse::<i64>() {
                                used_memory = usage;
                            }
                        }
                    }
                }
            }
        }

        let cpu_usage = sys.global_cpu_usage() as f64 / 100.0;
        let mem_usage = if total_memory > 0 {
            used_memory as f64 / total_memory as f64
        } else {
            0.0
        };

        let now = crate::utils::time::now_timestamp();
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_default();
        let host_ip = local_ip_address::local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let exe_path = std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut disk_total = 0u64;
        let mut disk_used = 0u64;
        let mut disk_max_usage = 0.0f64;

        let disks = sysinfo::Disks::new_with_refreshed_list();
        for disk in &disks {
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            disk_total += total;
            disk_used += used;
            let usage = if total > 0 {
                used as f64 / total as f64
            } else {
                0.0
            };
            if usage > disk_max_usage {
                disk_max_usage = usage;
            }
        }
        let disk_usage = if disk_total > 0 {
            disk_used as f64 / disk_total as f64
        } else {
            0.0
        };

        let status = serde_json::json!({
            "buildVersion": "1.1.5",
            "buildVersionCode": 1001005,
            "configVersion": config_store.get_config_version().await,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hostname": hostname,
            "hostIP": host_ip,
            "exePath": exe_path,
            "cpuUsage": cpu_usage,
            "cpuLogicalCount": sys.cpus().len(),
            "cpuPhysicalCount": sys.physical_core_count().unwrap_or(sys.cpus().len()),
            "memoryUsage": mem_usage,
            "memoryTotal": total_memory,
            "diskUsage": disk_usage,
            "diskTotal": disk_total,
            "diskMaxUsage": disk_max_usage,
            "load1m": load.one,
            "load5m": load.five,
            "load15m": load.fifteen,
            "trafficInBytes": traffic_in,
            "trafficOutBytes": traffic_out,
            "connectionCount": connections,
            "apiSuccessPercent": api_success_percent,
            "apiAvgCostSeconds": api_avg_cost,
            "cacheTotalDiskSize": crate::metrics::storage::STORAGE.total_cache_size(),
            "updatedAt": now,
            "timestamp": now,
            "isActive": true,
            "isHealthy": true,
        });

        if let Ok(client) = RpcClient::new(&api_config).await {
            let mut service = client.node_service();
            let _ = service
                .update_node_status(pb::UpdateNodeStatusRequest {
                    node_id,
                    status_json: status.to_string().into_bytes(),
                })
                .await;
        }
    }
}
pub async fn start_node_value_reporter(config_store: Arc<ConfigStore>, api_config: ApiConfig) {
    info!("Node Value Reporter service started. Interval: 60s");
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut last_traffic_out = 0u64;
    let mut last_traffic_in = 0u64;
    let mut last_requests = 0u64;
    let mut last_attack_requests = 0u64;
    let mut last_tick = std::time::Instant::now();

    loop {
        interval.tick().await;
        let node_id = config_store.get_node_id().await;
        if node_id == 0 {
            continue;
        }

        sys.refresh_all();
        // ... (rest of the logic)

        let (traffic_out, traffic_in, connections) = crate::metrics::METRICS.get_node_totals();
        let load = sysinfo::System::load_average();

        #[allow(unused_mut)]
        let mut total_memory = sys.total_memory() as i64;
        #[allow(unused_mut)]
        let mut used_memory = sys.used_memory() as i64;

        #[cfg(target_os = "linux")]
        {
            if let Ok(limit_str) =
                std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
            {
                if let Ok(limit) = limit_str.trim().parse::<i64>() {
                    if limit > 0 && limit < 1024 * 1024 * 1024 * 1024 {
                        total_memory = limit;
                        if let Ok(usage_str) =
                            std::fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
                        {
                            if let Ok(usage) = usage_str.trim().parse::<i64>() {
                                used_memory = usage;
                            }
                        }
                    }
                }
            } else if let Ok(limit_str) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
                if let Ok(limit) = limit_str.trim().parse::<i64>() {
                    if limit > 0 {
                        total_memory = limit;
                        if let Ok(usage_str) =
                            std::fs::read_to_string("/sys/fs/cgroup/memory.current")
                        {
                            if let Ok(usage) = usage_str.trim().parse::<i64>() {
                                used_memory = usage;
                            }
                        }
                    }
                }
            }
        }

        let mut disk_total = 0u64;
        let mut disk_used = 0u64;
        let mut disk_max_usage = 0.0f64;
        let disks = sysinfo::Disks::new_with_refreshed_list();
        for disk in &disks {
            let total = disk.total_space();
            let available = disk.available_space();
            let used = total.saturating_sub(available);
            disk_total += total;
            disk_used += used;
            let usage = if total > 0 {
                used as f64 / total as f64
            } else {
                0.0
            };
            if usage > disk_max_usage {
                disk_max_usage = usage;
            }
        }
        let disk_usage = if disk_total > 0 {
            disk_used as f64 / disk_total as f64
        } else {
            0.0
        };

        let snapshots = crate::metrics::METRICS.take_snapshots();
        let requests: u64 = snapshots.iter().map(|s| s.1.total_requests).sum();
        let attack_requests: u64 = snapshots.iter().map(|s| s.1.count_attack_requests).sum();
        let elapsed = last_tick.elapsed().as_secs().max(1);
        let traffic_in_delta = traffic_in.saturating_sub(last_traffic_in);
        let traffic_out_delta = traffic_out.saturating_sub(last_traffic_out);
        let requests_delta = requests.saturating_sub(last_requests);
        let attack_requests_delta = attack_requests.saturating_sub(last_attack_requests);
        let traffic_in_bps = traffic_in_delta / elapsed;
        let traffic_out_bps = traffic_out_delta / elapsed;
        last_traffic_in = traffic_in;
        last_traffic_out = traffic_out;
        last_requests = requests;
        last_attack_requests = attack_requests;
        last_tick = std::time::Instant::now();

        let mut value_map = std::collections::HashMap::new();
        value_map.insert(
            "cpu".to_string(),
            serde_json::json!({
                "usage": sys.global_cpu_usage() / 100.0,
                "cores": sys.cpus().len(),
                "logicalCount": sys.cpus().len(),
                "physicalCount": sys.physical_core_count().unwrap_or(sys.cpus().len())
            }),
        );
        value_map.insert(
            "memory".to_string(),
            serde_json::json!({
                "usage": if total_memory > 0 { used_memory as f64 / total_memory as f64 } else { 0.0 },
                "total": total_memory,
                "used": used_memory,
                "memUsage": if total_memory > 0 { used_memory as f64 / total_memory as f64 } else { 0.0 }
            }),
        );
        value_map.insert(
            "load".to_string(),
            serde_json::json!({
                "load1m": load.one,
                "load5m": load.five,
                "load15m": load.fifteen
            }),
        );
        value_map.insert(
            "connections".to_string(),
            serde_json::json!({
                "total": connections
            }),
        );
        value_map.insert(
            "trafficIn".to_string(),
            serde_json::json!({
                "total": traffic_in_delta
            }),
        );
        value_map.insert(
            "trafficOut".to_string(),
            serde_json::json!({
                "total": traffic_out_delta
            }),
        );
        value_map.insert(
            "allTraffic".to_string(),
            serde_json::json!({
                "inBytes": traffic_in_delta,
                "outBytes": traffic_out_delta,
                "avgInBytes": traffic_in_bps,
                "avgOutBytes": traffic_out_bps
            }),
        );
        value_map.insert(
            "requests".to_string(),
            serde_json::json!({
                "total": requests_delta
            }),
        );
        value_map.insert(
            "attackRequests".to_string(),
            serde_json::json!({
                "total": attack_requests_delta
            }),
        );
        value_map.insert(
            "disk".to_string(),
            serde_json::json!({
                "usage": disk_usage,
                "total": disk_total,
                "used": disk_used,
                "maxUsage": disk_max_usage
            }),
        );

        // Compatibility aliases for any newer/alternate item names already present in control-plane data.
        value_map.insert(
            "traffic".to_string(),
            serde_json::json!({
                "in": traffic_in_delta,
                "out": traffic_out_delta,
                "total": traffic_in_delta + traffic_out_delta
            }),
        );
        value_map.insert(
            "cache".to_string(),
            serde_json::json!({
                "diskSize": crate::metrics::storage::STORAGE.total_cache_size(),
                "memorySize": 0
            }),
        );

        let metric_items = config_store.get_metric_items().await;
        let mut selected_items: Vec<String> = metric_items
            .into_iter()
            .filter(|item| item.is_on)
            .filter_map(|item| {
                let code = item.code.trim();
                if code.is_empty() {
                    None
                } else {
                    Some(code.to_string())
                }
            })
            .collect();

        let baseline_items = [
            "cpu",
            "memory",
            "load",
            "trafficIn",
            "trafficOut",
            "allTraffic",
            "connections",
            "requests",
            "attackRequests",
            "disk",
        ];
        if selected_items.is_empty() {
            selected_items = baseline_items.iter().map(|s| (*s).to_string()).collect();
        } else {
            for item in baseline_items {
                if !selected_items.iter().any(|existing| existing == item) {
                    selected_items.push(item.to_string());
                }
            }
        }

        selected_items.sort();
        selected_items.dedup();
        let created_at = crate::utils::time::now_timestamp();
        let node_value_items: Vec<pb::create_node_values_request::NodeValueItem> = selected_items
            .iter()
            .filter_map(|item| {
                value_map
                    .get(item)
                    .map(|value| pb::create_node_values_request::NodeValueItem {
                        item: item.clone(),
                        value_json: value.to_string().into_bytes(),
                        created_at,
                    })
            })
            .collect();

        let node_value_items_count = node_value_items.len();
        if let Ok(client) = RpcClient::new(&api_config).await {
            let mut service = client.node_value_service_with_type();
            match service
                .create_node_values(pb::CreateNodeValuesRequest { node_value_items })
                .await
            {
                Ok(_) => debug!(
                    "Successfully reported {} node values with items: {}",
                    node_value_items_count,
                    selected_items.join(",")
                ),
                Err(e) => error!("Error reporting node values: {}", e),
            }
        }
    }
}
