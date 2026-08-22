use parking_lot::RwLock;
use std::io::Read;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::time::Duration;
use tonic::transport::Channel;
use tonic::{Request, Status};
use tracing::{debug, info, warn};

use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::SharedRpcClient;
use crate::rpc::node_task::sync_node_tasks;
use crate::rpc::plan::sync_active_plans;
use crate::rpc::utils::sync_deleted_contents;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) static CONNECTED_API_NODE_IDS: Lazy<RwLock<HashSet<i64>>> =
    Lazy::new(|| RwLock::new(HashSet::new()));

static REPORT_NOTIFY: Lazy<tokio::sync::Notify> = Lazy::new(tokio::sync::Notify::new);

pub fn trigger_api_node_report() {
    REPORT_NOTIFY.notify_one();
}

static LAST_CONFIG_HASH: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));
static LAST_WAF_HASH: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));
static LAST_GLOBAL_CONFIG_HASH: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));
static CONNECTED_API_NODE_UNSUPPORTED_LOGGED: AtomicBool = AtomicBool::new(false);
static ENABLED_FEATURES_UNSUPPORTED_LOGGED: AtomicBool = AtomicBool::new(false);

fn build_version_code() -> u32 {
    env!("CARGO_PKG_VERSION")
        .split('.')
        .take(3)
        .map(|part| part.parse::<u32>().unwrap_or(0).min(999))
        .fold(0, |acc, part| acc * 1000 + part)
}

fn cert_data_score(cert: &crate::config_models::SSLCertConfig) -> usize {
    fn score(value: &Option<serde_json::Value>) -> usize {
        match value {
            Some(serde_json::Value::String(s)) => {
                if s.contains("-----BEGIN ") {
                    4
                } else if s.contains("GOEDGE_DATA_MAP:") || s.contains("_DATA_MAP:") {
                    1
                } else if s.trim().len() >= 128 {
                    3
                } else {
                    2
                }
            }
            Some(serde_json::Value::Array(items)) if items.len() >= 128 => 3,
            Some(serde_json::Value::Object(_)) => 2,
            Some(_) => 1,
            None => 0,
        }
    }

    score(&cert.cert_data_json) + score(&cert.key_data_json)
}

fn dedup_ssl_certs(
    certs: Vec<crate::config_models::SSLCertConfig>,
) -> Vec<crate::config_models::SSLCertConfig> {
    let mut order = Vec::new();
    let mut by_id: std::collections::HashMap<i64, crate::config_models::SSLCertConfig> =
        std::collections::HashMap::new();
    // Mirror of config::dedup_ssl_certs: id<=0 means the cert isn't backed
    // by the control plane. Give each its own synthetic negative key so
    // multiple in-line certs don't collide on `0` and silently drop all but
    // the last one (which previously broke TLS handshakes for the dropped
    // certs).
    let mut synthetic_id: i64 = -1;

    for mut cert in certs {
        if cert.id <= 0 {
            let key = synthetic_id;
            synthetic_id -= 1;
            cert.id = key;
            order.push(key);
            by_id.insert(key, cert);
            continue;
        }
        if !by_id.contains_key(&cert.id) {
            order.push(cert.id);
            by_id.insert(cert.id, cert);
            continue;
        }
        let replace = by_id
            .get(&cert.id)
            .map(|existing| cert_data_score(&cert) > cert_data_score(existing))
            .unwrap_or(true);
        if replace {
            by_id.insert(cert.id, cert);
        }
    }

    order.dedup();
    order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect()
}

fn cert_has_data_map_ref(cert: &crate::config_models::SSLCertConfig) -> bool {
    fn has_ref(value: &Option<serde_json::Value>) -> bool {
        value
            .as_ref()
            .and_then(|value| value.as_str())
            .map(|value| value.contains("_DATA_MAP:"))
            .unwrap_or(false)
    }

    has_ref(&cert.cert_data_json) || has_ref(&cert.key_data_json)
}

fn collect_enabled_ssl_certs(
    global_certs: &[crate::config_models::SSLCertConfig],
    global_policy: Option<&crate::config_models::SSLPolicyConfig>,
    servers: &[crate::config_models::ServerConfig],
) -> Vec<crate::config_models::SSLCertConfig> {
    let mut certs = Vec::new();
    certs.extend(global_certs.iter().cloned());

    if let Some(policy) = global_policy.filter(|policy| policy.is_on) {
        certs.extend(policy.certs.iter().cloned());
    }

    for server in servers.iter().filter(|server| server.is_on) {
        if let Some(https) = &server.https
            && https.is_on
            && let Some(policy) = &https.ssl_policy
            && policy.is_on
        {
            certs.extend(policy.certs.iter().cloned());
        }
    }

    dedup_ssl_certs(certs)
}

fn log_raw_json_hints(label: &str, raw: &[u8]) {
    let text = String::from_utf8_lossy(raw);
    for needle in ["@sni_passthrough", "speedtest", "www.speedtest.cn"] {
        if let Some(pos) = text.find(needle) {
            let start = pos.saturating_sub(240);
            let end = (pos + needle.len() + 240).min(text.len());
            debug!(
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
    if !crate::cluster::leader::require_leader("connected_api_nodes_report") {
        return;
    }
    let api_node_ids: Vec<_> = CONNECTED_API_NODE_IDS.read().iter().copied().collect();

    if api_node_ids.is_empty() {
        return;
    }

    if let Ok(shared) = SharedRpcClient::get(api_config).await {
        let client = shared.as_rpc_client();
        let mut node_service = client.node_service_with_type();
        match crate::rpc::track_rpc(node_service.update_node_connected_api_nodes(
            pb::UpdateNodeConnectedApiNodesRequest {
                api_node_ids: api_node_ids.clone(),
            },
        ))
        .await
        {
            Ok(_) => info!(
                "Successfully reported connected API nodes: {:?}",
                api_node_ids
            ),
            Err(e) if is_unsupported_node_type_error(&e) => {
                if !CONNECTED_API_NODE_UNSUPPORTED_LOGGED.swap(true, Ordering::Relaxed) {
                    debug!(
                        "Connected API node report is not supported by this API node for node credentials: {}",
                        e
                    );
                }
            }
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
    waf_state: Arc<crate::firewall::state::WafStateManager>,
) {
    let initial_state = crate::utils::persistence::load_state();
    let mut task_version = initial_state.task_version;
    let mut deleted_content_version = initial_state.deleted_content_version;
    let mut config_version = initial_state.config_version;

    let api_endpoint = api_config
        .effective_rpc_endpoints()
        .first()
        .cloned()
        .unwrap_or_default();
    info!(
        "Config syncer service started for API Node {} (Node ID: {})",
        api_endpoint, api_config.node_id
    );

    let mut connect_backoff = Duration::from_secs(5);
    loop {
        debug!("RPC_NODE: Starting periodic configuration sync check.");

        let client = match SharedRpcClient::get(&api_config).await {
            Ok(shared) => {
                connect_backoff = Duration::from_secs(5);
                shared.as_rpc_client()
            }
            Err(e) => {
                warn!("Failed to connect to API node: {}. Will retry...", e);
                tokio::time::sleep(connect_backoff).await;
                connect_backoff = (connect_backoff.saturating_mul(2)).min(Duration::from_secs(300));
                continue;
            }
        };

        let mut node_service = client.node_service();

        let config_synced = fetch_and_apply_config(
            &mut node_service,
            &config_store,
            &api_config,
            &health_manager,
            &cert_selector,
            waf_state.as_ref(),
            &mut task_version,
            &mut config_version,
        )
        .await;

        if config_synced {
            sync_deleted_contents(&api_config, &config_store, &mut deleted_content_version).await;
        }
        sync_node_tasks(
            &api_config,
            &config_store,
            &health_manager,
            &cert_selector,
            &ip_list_manager,
            &mut task_version,
            config_synced,
        )
        .await;

        report_connected_api_nodes(&api_config).await;

        let mut state = crate::utils::persistence::load_state();
        state.config_version = config_version;
        state.task_version = task_version;
        state.deleted_content_version = deleted_content_version;
        if let Err(err) = crate::utils::persistence::save_state(&state) {
            warn!("failed to persist node sync state: {}", err);
        }

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

    let mut last_gsc_hash = LAST_GLOBAL_CONFIG_HASH.write();
    if *last_gsc_hash != current_gsc_hash {
        *last_gsc_hash = current_gsc_hash;

        info!(
            "RPC_NODE: Global settings updated: node_on={} ip_lists={} server_name={} force_ln={} ln_method={} low_http={} lan_origin={}",
            if payload.is_on {
                "YES"
            } else {
                "NO (Inaccessible)"
            },
            if payload.enable_ip_lists { "YES" } else { "No" },
            if server_name.is_empty() {
                "Default"
            } else {
                server_name
            },
            if force_ln { "YES" } else { "No" },
            ln_method,
            if supports_low_version_http {
                "YES"
            } else {
                "No"
            },
            if allow_lan_ip { "YES" } else { "No" }
        );
        debug!(
            "  - Match Cert From All Servers: {}",
            match_cert_from_all_servers
        );
        debug!(
            "  - Enable ${{serverAddr}} Variable: {}",
            enable_server_addr_variable
        );
        debug!(
            "  - Auto Gzip Back to Origin: {}",
            request_origins_with_encodings
        );
        debug!("  - XFF Max Addresses: {}", xff_max_addresses);

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
                debug!(
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
    health_manager: &crate::health_manager::GlobalHealthManager,
    cert_selector: &crate::ssl::DynamicCertSelector,
    waf_state: &crate::firewall::state::WafStateManager,
    task_version: &mut i64,
    config_version: &mut i64,
) -> bool
where
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
        compress: true,
        node_task_version: *task_version,
        use_data_map: true,
    });

    match crate::rpc::track_rpc(client.find_current_node_config(req)).await {
        Ok(resp) => {
            let config_resp = resp.into_inner();
            // config_resp.timestamp is a Unix timestamp used as an RPC cursor
            // (tells the API server "I've synced up to this point"), NOT the
            // config version. The config version that the admin UI uses to
            // determine "同步中" vs "在线" comes from payload.version (the
            // edgeNodes.version column in the DB). We must separate these two
            // concepts: rpc_cursor for next request, config_version for status.
            let rpc_cursor = config_resp.timestamp;
            if config_resp.node_json.is_empty() {
                if !config_resp.is_changed {
                    // Config unchanged — config_version stays the same.
                    // Only update rpc_cursor for next request.
                    if rpc_cursor > 0 {
                        *config_version = rpc_cursor; // used as request parameter next time
                    }
                    debug!(
                        "RPC_NODE: No configuration changes reported by API. cursor={}",
                        rpc_cursor
                    );
                } else {
                    warn!("RPC_NODE: API reported change but sent empty JSON!");
                    return false;
                }
            } else {
                debug!(
                    "RPC_NODE: Received node_json ({} bytes, compressed={}).",
                    config_resp.node_json.len(),
                    config_resp.is_compressed
                );
                let mut node_json = config_resp.node_json;

                if config_resp.is_compressed {
                    let compressed = node_json;
                    let decoded = tokio::task::spawn_blocking(move || {
                        let mut decompressor = brotli::Decompressor::new(&compressed[..], 4096);
                        let mut decoded = Vec::new();
                        decompressor.read_to_end(&mut decoded).map(|_| decoded)
                    })
                    .await;
                    match decoded {
                        Ok(Ok(decoded)) => node_json = decoded,
                        Ok(Err(e)) => {
                            warn!("Failed to decompress node_json: {}", e);
                            return false;
                        }
                        Err(e) => {
                            warn!("Failed to join node_json decompression task: {}", e);
                            return false;
                        }
                    }
                }

                // Check content hash to avoid redundant reloads
                let current_hash = format!("{:x}", md5_legacy::compute(&node_json));
                let mut should_reload = true;
                {
                    let last_hash = LAST_CONFIG_HASH.read();
                    if *last_hash == current_hash {
                        debug!(
                            "RPC_NODE: Configuration content unchanged (Hash: {}), skipping heavy reload.",
                            current_hash
                        );
                        should_reload = false;
                    }
                }

                if !should_reload && rpc_cursor > 0 {
                    // Content unchanged — config_version stays the same (from payload.version).
                    // Update rpc_cursor for next request.
                    *config_version = rpc_cursor;
                }

                if should_reload {
                    log_raw_json_hints("node_json", &node_json);
                    match serde_json::from_slice::<crate::config_models::NodeConfigPayload>(
                        &node_json,
                    ) {
                        Ok(mut payload) => {
                            // The config version reported to the control panel MUST come
                            // from payload.version (the edgeNodes.version DB column),
                            // NOT from the RPC timestamp. The admin UI compares
                            // status.configVersion == node.Version to decide "在线" vs "同步中".
                            let payload_config_version = payload.version.unwrap_or(0);
                            // For the next FindCurrentNodeConfig request parameter, use
                            // rpc_cursor if available, otherwise the payload version.
                            let next_config_cursor = if rpc_cursor > 0 {
                                rpc_cursor
                            } else if payload_config_version > 0 {
                                payload_config_version
                            } else {
                                *config_version
                            };
                            let numeric_id = payload.id.unwrap_or(0);
                            let mut payload_servers = payload.servers.clone();

                            debug!(
                                "Successfully parsed NodeConfigPayload. Numeric ID: {}, Server count: {}",
                                numeric_id,
                                payload.servers.len()
                            );
                            if let Some(gsc) = &payload.global_server_config {
                                debug!("RPC_NODE: Found GlobalServerConfig: {:?}", gsc);
                            }
                            let kernel_filter = crate::firewall::kernel::build_filter(
                                payload.kernel_firewall_mode.as_deref(),
                            )
                            .await;

                            for cp in &payload.http_cache_policies {
                                debug!(
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
                                    info!(
                                        "RPC_NODE_CACHE_REF_DUMP policy_id={} policy_name={} rule_index={} rule={}",
                                        cp.id,
                                        cp.name,
                                        idx + 1,
                                        serde_json::to_string(r).unwrap_or_default()
                                    );
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
                                let mut last_waf_hash = LAST_WAF_HASH.write();
                                if *last_waf_hash != current_waf_hash {
                                    *last_waf_hash = current_waf_hash;
                                    waf_changed = true;
                                }
                            }

                            if waf_changed {
                                for wp in &payload.http_firewall_policies {
                                    debug!(
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

                            // 2. Restore from DataMap if exists
                            let has_data_map_refs =
                                payload.ssl_certs.iter().any(cert_has_data_map_ref)
                                    || payload.ssl_policy.as_ref().is_some_and(|policy| {
                                        policy.certs.iter().any(cert_has_data_map_ref)
                                    })
                                    || payload_servers.iter().any(|server| {
                                        server
                                            .https
                                            .as_ref()
                                            .and_then(|https| https.ssl_policy.as_ref())
                                            .is_some_and(|policy| {
                                                policy.certs.iter().any(cert_has_data_map_ref)
                                            })
                                    });

                            if let Some(dm) = &payload.data_map {
                                tracing::debug!(
                                    "RPC_NODE: DataMap found with {} entries. Restoring certificates...",
                                    dm.len()
                                );
                                let mut restored_count = 0;
                                let mut restore_cert =
                                    |cert: &mut crate::config_models::SSLCertConfig| {
                                        use base64::{Engine as _, engine::general_purpose};
                                        fn value_to_ref_string(
                                            value: &serde_json::Value,
                                        ) -> Option<String>
                                        {
                                            fn decode_ref_candidate(raw: &str) -> Option<String> {
                                                let encoded =
                                                    raw.strip_prefix("base64:").unwrap_or(raw);
                                                general_purpose::STANDARD
                                                    .decode(encoded.trim())
                                                    .or_else(|_| {
                                                        general_purpose::STANDARD_NO_PAD
                                                            .decode(encoded.trim())
                                                    })
                                                    .ok()
                                                    .map(|decoded| {
                                                        String::from_utf8_lossy(&decoded)
                                                            .to_string()
                                                    })
                                            }

                                            match value {
                                                serde_json::Value::String(s) => {
                                                    if s.contains("GOEDGE_DATA_MAP:")
                                                        || s.contains("_DATA_MAP:")
                                                    {
                                                        return Some(s.clone());
                                                    }
                                                    if let Some(decoded) = decode_ref_candidate(s) {
                                                        if decoded.contains("GOEDGE_DATA_MAP:")
                                                            || decoded.contains("_DATA_MAP:")
                                                        {
                                                            return Some(decoded);
                                                        }
                                                    }
                                                    Some(s.clone())
                                                }
                                                serde_json::Value::Array(items) => {
                                                    let mut bytes = Vec::with_capacity(items.len());
                                                    for item in items {
                                                        let byte = item.as_u64()?;
                                                        if byte > u8::MAX as u64 {
                                                            return None;
                                                        }
                                                        bytes.push(byte as u8);
                                                    }
                                                    Some(
                                                        String::from_utf8_lossy(&bytes).to_string(),
                                                    )
                                                }
                                                _ => None,
                                            }
                                        }
                                        let mut process_field =
                                            |val: &mut Option<serde_json::Value>| {
                                                if let Some(current) = val {
                                                    let Some(raw_ref) =
                                                        value_to_ref_string(current)
                                                    else {
                                                        return;
                                                    };

                                                    if raw_ref.contains("GOEDGE_DATA_MAP:")
                                                        || raw_ref.contains("_DATA_MAP:")
                                                    {
                                                        if let Some(real_val) = dm.get(&raw_ref) {
                                                            *val = Some(real_val.clone());
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

                                for cert in &mut payload.ssl_certs {
                                    restore_cert(cert);
                                }
                                if let Some(policy) = &mut payload.ssl_policy {
                                    for cert in &mut policy.certs {
                                        restore_cert(cert);
                                    }
                                }
                                for server in &mut payload_servers {
                                    if let Some(https) = &mut server.https
                                        && let Some(policy) = &mut https.ssl_policy
                                    {
                                        for cert in &mut policy.certs {
                                            restore_cert(cert);
                                        }
                                    }
                                    if let Some(rp) = &mut server.reverse_proxy {
                                        for origin in rp
                                            .primary_origins
                                            .iter_mut()
                                            .chain(rp.backup_origins.iter_mut())
                                        {
                                            if let Some(cert) = &mut origin.cert {
                                                restore_cert(cert);
                                            }
                                        }
                                    }
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
                            let mut match_domain_strictly = false;
                            let mut node_ip_show_page = false;
                            let mut node_ip_page_html = String::new();
                            let mut domain_mismatch_action = None;

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
                                    match_domain_strictly = http_all.match_domain_strictly;
                                    node_ip_show_page = http_all.node_ip_show_page;
                                    node_ip_page_html = http_all.node_ip_page_html.clone();
                                    domain_mismatch_action =
                                        http_all.domain_mismatch_action.clone();
                                }
                            }
                            let mut global_http_config = payload
                                .global_server_config
                                .as_ref()
                                .and_then(|g| g.http_all.clone());
                            if let Some(product_name) = payload
                                .product_config
                                .as_ref()
                                .map(|config| config.name.trim())
                                .filter(|name| !name.is_empty())
                            {
                                global_http_config
                                    .get_or_insert_with(Default::default)
                                    .product_name = product_name.to_string();
                            }

                            for server in &payload_servers {
                                server.compile_url_patterns();
                                if let Some(web) = &server.web
                                    && let Some(cache) = &web.cache
                                {
                                    for (idx, cache_ref) in cache.cache_refs.iter().enumerate() {
                                        info!(
                                            "RPC_NODE_SERVER_CACHE_REF_DUMP server_id={} names={:?} rule_index={} rule={}",
                                            server.numeric_id(),
                                            crate::rpc::utils::server_runtime_names(server),
                                            idx + 1,
                                            serde_json::to_string(cache_ref).unwrap_or_default()
                                        );
                                    }
                                    if let Some(policy) = &cache.cache_policy {
                                        for (idx, cache_ref) in policy.cache_refs.iter().enumerate()
                                        {
                                            info!(
                                                "RPC_NODE_SERVER_POLICY_CACHE_REF_DUMP server_id={} policy_id={} policy_name={} names={:?} rule_index={} rule={}",
                                                server.numeric_id(),
                                                policy.id,
                                                policy.name,
                                                crate::rpc::utils::server_runtime_names(server),
                                                idx + 1,
                                                serde_json::to_string(cache_ref)
                                                    .unwrap_or_default()
                                            );
                                        }
                                    }
                                }
                            }

                            let mut loaded_domain_names = std::collections::BTreeSet::new();
                            let mut port_only_server_count = 0usize;

                            for server in &payload_servers {
                                if !server.is_on {
                                    debug!(
                                        "RPC_NODE: Skipping server {} because it is OFF",
                                        server.numeric_id()
                                    );
                                    continue;
                                }

                                if server.is_sni_passthrough() {
                                    match serde_json::to_string(server) {
                                        Ok(raw) => debug!(
                                            "RPC_NODE: SNI passthrough server loaded. id={} names={:?} raw_json={}",
                                            server.numeric_id(),
                                            crate::rpc::utils::server_runtime_names(server),
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
                                let names = crate::rpc::utils::server_runtime_names(server);
                                let (lb_arc, has_hc) = match &server.reverse_proxy {
                                    Some(rp_cfg) => {
                                        match crate::lb_factory::build_lb_blocking_with_global_http(
                                            server_id,
                                            rp_cfg.clone(),
                                            node_level,
                                            Arc::new(parent_nodes.clone()),
                                            tiered_origin_bypass,
                                            allow_lan_ip,
                                            payload
                                                .global_server_config
                                                .as_ref()
                                                .and_then(|g| g.http_all.clone()),
                                        )
                                        .await
                                        {
                                            Ok(result) => result,
                                            Err(err) => {
                                                warn!(
                                                    "RPC_NODE: failed to build LB for server {}: {}. Using fallback dummy LB.",
                                                    server_id, err
                                                );
                                                crate::rpc::utils::fallback_runtime_lb()
                                            }
                                        }
                                    }
                                    None => crate::rpc::utils::fallback_runtime_lb(),
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

                                if let Some(https) = &server.https {
                                    if https.is_on {
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

                            let loaded_domain_count = loaded_domain_names.len();
                            if loaded_domain_names.is_empty() {
                                debug!(
                                    "RPC_NODE: Loaded 0 named domains. Port-only servers: {}",
                                    port_only_server_count
                                );
                            } else {
                                let loaded_names: Vec<_> =
                                    loaded_domain_names.into_iter().collect();
                                debug!(
                                    "RPC_NODE: Loaded {} named domains. Port-only servers: {}",
                                    loaded_names.len(),
                                    port_only_server_count
                                );
                                for chunk in loaded_names.chunks(20) {
                                    debug!("RPC_NODE: Domains => {}", chunk.join(", "));
                                }
                            }

                            debug!(
                                "RPC_NODE: Loaded global custom pages: {}. Global page policies: {}",
                                payload.global_pages.len(),
                                payload.http_pages_policies.len()
                            );

                            let all_certs = collect_enabled_ssl_certs(
                                &payload.ssl_certs,
                                payload.ssl_policy.as_ref(),
                                &payload_servers,
                            );
                            tracing::debug!(
                                "Received {} active certificates from RPC",
                                all_certs.len()
                            );

                            // 4. gRPC Policy
                            let node_cluster_id =
                                payload.node_cluster.as_ref().map(|c| c.id).unwrap_or(0);
                            let grpc_policy = payload
                                .grpc_policies
                                .get(&node_cluster_id.to_string())
                                .or_else(|| payload.grpc_policies.get("0"))
                                .or_else(|| payload.grpc_policies.values().next())
                                .cloned()
                                .or_else(|| payload.primary_grpc_policy.clone());

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

                            let deleted_contents = config_store.get_deleted_contents().await;
                            config_store
                                .update_config(
                                    numeric_id,
                                    payload_config_version,
                                    payload.node_region.as_ref().map(|r| r.id).unwrap_or(0),
                                    node_cluster_id,
                                    payload_servers.clone().into_iter().map(Arc::new).collect(),
                                    new_servers,
                                    new_routes,
                                    new_id_to_lb,
                                    deleted_contents,
                                    payload.global_pages.clone(),
                                    payload.metric_items.clone(),
                                    payload.ssl_certs.clone(),
                                    payload.ssl_policy.clone(),
                                    payload.updating_server_list_id,
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
                                    match_domain_strictly,
                                    node_ip_show_page,
                                    node_ip_page_html,
                                    domain_mismatch_action,
                                    global_http_config,
                                    payload
                                        .http_cache_policies
                                        .iter()
                                        .map(|p| Arc::new(p.clone()))
                                        .collect(),
                                    payload.http_firewall_policies.clone(),
                                    payload.waf_actions.clone(),
                                    parse_i64_keyed_map(&payload.uam_policies),
                                    parse_i64_keyed_map(&payload.http_cc_policies),
                                    parse_i64_keyed_map(&payload.http3_policies),
                                    parse_i64_keyed_map(&payload.http_pages_policies),
                                    parse_i64_keyed_map(&payload.webp_image_policies),
                                    payload.toa.clone(),
                                    payload
                                        .global_server_config
                                        .as_ref()
                                        .and_then(|g| g.http_access_log.clone()),
                                )
                                .await;
                            *config_version = next_config_cursor;
                            {
                                let mut last_hash = LAST_CONFIG_HASH.write();
                                *last_hash = current_hash;
                            }
                            if kernel_filter.available() {
                                waf_state.set_kernel_filter(kernel_filter);
                            }
                            for cache_policy in &payload.http_cache_policies {
                                crate::cache_manager::CACHE
                                    .storage
                                    .apply_policy(cache_policy)
                                    .await;
                            }
                            crate::ssl::sync_certs(cert_selector, &all_certs).await;
                            crate::logging::set_numeric_node_id(numeric_id);
                            config_store.set_global_stat_upload(
                                payload
                                    .global_server_config
                                    .as_ref()
                                    .and_then(|g| g.stat.as_ref())
                                    .map(|stat| stat.upload.clone()),
                            );

                            info!(
                                "RPC_NODE: Applied config version={} node_id={} servers={} domains={} port_only={} cache_policies={} waf_policies={} pages={}",
                                payload_config_version,
                                numeric_id,
                                payload_servers.len(),
                                loaded_domain_count,
                                port_only_server_count,
                                payload.http_cache_policies.len(),
                                payload.http_firewall_policies.len(),
                                payload.global_pages.len() + payload.http_pages_policies.len()
                            );

                            if let Err(err) =
                                report_node_online_once(config_store, api_config).await
                            {
                                debug!("RPC_NODE: immediate online status report failed: {}", err);
                            }

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
                                if let Ok(shared) = SharedRpcClient::get(api_config).await {
                                    let client = shared.as_rpc_client();
                                    let mut service = client.node_service_with_type();
                                    match crate::rpc::track_rpc(
                                        service.find_enabled_node_config_info(
                                            pb::FindEnabledNodeConfigInfoRequest {
                                                node_id: numeric_id,
                                            },
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(resp) => {
                                            let info = resp.into_inner();
                                            debug!(
                                                "Node enabled features: DNS={} Cache={} Thresholds={} SSH={} Sys={} DDoS={} Sched={} AccessLog={}",
                                                info.has_dns_info,
                                                info.has_cache_info,
                                                info.has_thresholds,
                                                info.has_ssh,
                                                info.has_system_settings,
                                                info.has_d_do_s_protection,
                                                info.has_schedule_settings,
                                                info.has_access_log_settings
                                            );
                                            config_store.set_enabled_features(
                                                info.has_dns_info,
                                                info.has_cache_info,
                                                info.has_thresholds,
                                                info.has_ssh,
                                                info.has_system_settings,
                                                info.has_d_do_s_protection,
                                                info.has_schedule_settings,
                                                info.has_access_log_settings,
                                            );
                                        }
                                        Err(e) if is_unsupported_node_type_error(&e) => {
                                            if !ENABLED_FEATURES_UNSUPPORTED_LOGGED
                                                .swap(true, Ordering::Relaxed)
                                            {
                                                debug!(
                                                    "Enabled feature sync is not supported by this API node for node credentials: {}",
                                                    e
                                                );
                                            }
                                        }
                                        Err(e) => debug!("Failed to fetch enabled features: {}", e),
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Error parsing NodeConfigPayload: {}", e);
                            return false;
                        }
                    }
                }
            }
        }
        Err(e) => {
            warn!("Error fetching node config: {}", e);
            return false;
        }
    }

    true
}

pub async fn start_metrics_reporter(config_store: Arc<ConfigStore>, api_config: ApiConfig) {
    let mut sys = sysinfo::System::new_all();
    // Initial refresh to populate CPU baseline
    sys.refresh_all();

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        interval.tick().await;
        if !crate::cluster::leader::require_leader("metrics_reporter") {
            continue;
        }
        let node_id = config_store.get_node_id().await;
        if node_id == 0 {
            continue;
        }

        sys.refresh_all(); // Refresh everything
        let (mut traffic_out, mut traffic_in, mut connections) =
            crate::metrics::METRICS.get_node_totals();
        let rpc_snap = crate::metrics::METRICS.rpc.snapshot();
        let mut rpc_total_requests = rpc_snap.total_requests;
        let mut rpc_total_errors = rpc_snap.total_errors;
        let mut rpc_total_cost_ms = rpc_snap.total_cost_ms;

        // Local memory + cpu first; the cluster aggregator (if any) replaces these
        // atomically below from a single snapshot so the report stays internally
        // consistent.
        let (mut total_memory, mut used_memory) = crate::memory_governor::reported_memory_totals();

        let mut cpu_usage = sys.global_cpu_usage() as f64 / 100.0;
        if crate::runtime_mode::RuntimeConfig::current_is_rke2() {
            let aggregated = crate::cluster::stats::aggregate();
            if aggregated.replica_count > 0 {
                traffic_out = aggregated.traffic_out;
                traffic_in = aggregated.traffic_in;
                connections = aggregated.active_connections;
                rpc_total_requests = aggregated.rpc_total_requests;
                rpc_total_errors = aggregated.rpc_total_errors;
                rpc_total_cost_ms = aggregated.rpc_total_cost_ms;
                cpu_usage = aggregated.cpu_usage_avg;
                total_memory = aggregated.memory_total;
                used_memory = aggregated.memory_used;
            }
        }
        let api_success_percent = if rpc_total_requests > 0 {
            (rpc_total_requests - rpc_total_errors) as f64 / rpc_total_requests as f64
        } else {
            1.0
        };
        let api_avg_cost_seconds = if rpc_total_requests > 0 {
            rpc_total_cost_ms as f64 / rpc_total_requests as f64 / 1000.0
        } else {
            0.0
        };
        let load = sysinfo::System::load_average();
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
        let mut disk_max_partition = String::new();

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
                disk_max_partition = disk.mount_point().to_string_lossy().to_string();
            }
        }
        let disk_usage = if disk_total > 0 {
            disk_used as f64 / disk_total as f64
        } else {
            0.0
        };
        let cache_stats = crate::cache_manager::CACHE.storage.runtime_stats().await;
        let governor_snapshot = crate::memory_governor::MEMORY_GOVERNOR
            .snapshot(crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads());
        let l4_metrics = crate::l4_defense::metrics_snapshot();
        let resource_governor = serde_json::json!({
            "memoryPressure": governor_snapshot.memory_pressure_level.as_str(),
            "fdUsed": governor_snapshot.fd_used,
            "fdSoftLimit": governor_snapshot.fd_soft_limit,
            "fdUsedPercent": governor_snapshot.fd_used_pct,
            "fdPressure": governor_snapshot.fd_pressure_level.as_str(),
            "connectionBudgetBytes": governor_snapshot.connection_budget_bytes,
            "connectionAdmissionUsedBytes": governor_snapshot.connection_admission_used_bytes,
            "zeroCopyRelayActive": governor_snapshot.zero_copy_relay_active,
            "zeroCopyRelayLimit": governor_snapshot.zero_copy_relay_limit,
            "zeroCopyRelayUsedBytes": governor_snapshot.zero_copy_relay_used_bytes,
            "zeroCopyRelayBudgetBytes": governor_snapshot.zero_copy_relay_budget_bytes,
            "udpQueuedBytes": governor_snapshot.udp_queued_bytes,
            "udpQueuedBytesBudget": governor_snapshot.udp_queued_bytes_budget,
            "httpAcceptWorkers": governor_snapshot.http_accept_workers,
            "listenerBacklog": governor_snapshot.listener_backlog,
            "cgroupManaged": governor_snapshot.cgroup_managed,
            "cgroupMemoryMaxBytes": governor_snapshot.cgroup_memory_max_bytes,
            "cgroupMemoryHighBytes": governor_snapshot.cgroup_memory_high_bytes,
            "cgroupSwapMaxBytes": governor_snapshot.cgroup_swap_max_bytes,
            "processRssBytes": governor_snapshot.process_rss_bytes,
            "processPssBytes": governor_snapshot.process_pss_bytes,
            "processAnonRssBytes": governor_snapshot.process_anon_rss_bytes,
            "residentUsedBytes": governor_snapshot.resident_memory.total_used_bytes,
            "residentBudgetBytes": governor_snapshot.resident_memory.total_budget_bytes,
        });
        let l4_defense = serde_json::json!({
            "eventsTotal": l4_metrics.events_total,
            "blockedTotal": l4_metrics.blocked_total,
            "alreadyBlockedTotal": l4_metrics.already_blocked_total,
            "prefixEventTotal": l4_metrics.prefix_event_total,
            "prefixBlockedTotal": l4_metrics.prefix_blocked_total,
            "aggregateDropTotal": l4_metrics.aggregate_drop_total,
            "exactCounterSaturatedTotal": l4_metrics.exact_counter_saturated_total,
            "distinctIpsRecent": l4_metrics.distinct_ips_recent,
            "prefixPressure": l4_metrics.prefix_pressure_level.as_str(),
            "topEventKind": l4_metrics.top_event_kind,
            "topPrefix": l4_metrics.top_prefix,
            "topPrefixEvents": l4_metrics.top_prefix_events,
        });
        let xdp_status = serde_json::to_value(crate::xdp::status_snapshot())
            .unwrap_or_else(|_| serde_json::json!({"available": false}));
        let pipeline_metrics = crate::pipeline_metrics::snapshot();
        let pipelines = serde_json::json!({
            "accessLogIngressDropped": pipeline_metrics.access_log_ingress_dropped,
            "accessLogRetryEvicted": pipeline_metrics.access_log_retry_evicted,
            "accessLogUploadFailed": pipeline_metrics.access_log_upload_failed,
            "nodeLogIngressDropped": pipeline_metrics.node_log_ingress_dropped,
            "nodeLogThrottled": pipeline_metrics.node_log_throttled,
            "nodeLogUploadFailed": pipeline_metrics.node_log_upload_failed,
            "httpDimensionDropped": pipeline_metrics.http_dimension_dropped,
            "ipReportDropped": pipeline_metrics.ip_report_dropped,
            "localLogDropped": pipeline_metrics.local_log_dropped,
            "localLogWriteFailed": pipeline_metrics.local_log_write_failed,
            "localLogRotationFailed": pipeline_metrics.local_log_rotation_failed,
            "kernelSyncCoalesced": pipeline_metrics.kernel_sync_coalesced,
            "kernelSyncReconcileRequested": pipeline_metrics.kernel_sync_reconcile_requested,
            "kernelSyncFailed": pipeline_metrics.kernel_sync_failed,
            "xdpMapSyncFailed": pipeline_metrics.xdp_map_sync_failed,
            "internalApiRejected": pipeline_metrics.internal_api_rejected,
            "rpcStreamCommandRejected": pipeline_metrics.rpc_stream_command_rejected,
            "rpcStreamReplyDropped": pipeline_metrics.rpc_stream_reply_dropped,
        });

        let status = serde_json::json!({
            "buildVersion": env!("CARGO_PKG_VERSION"),
            "buildVersionCode": build_version_code(),
            "configVersion": config_store.get_config_version().await,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hostname": hostname,
            "hostIP": host_ip,
            "exePath": exe_path,
            "cpuUsage": cpu_usage,
            "cpuLogicalCount": sys.cpus().len(),
            "cpuPhysicalCount": sysinfo::System::physical_core_count().unwrap_or(sys.cpus().len()),
            "memoryUsage": mem_usage,
            "memoryTotal": total_memory,
            "diskUsage": disk_usage,
            "diskTotal": disk_total,
            "diskMaxUsage": disk_max_usage,
            "diskMaxUsagePartition": disk_max_partition,
            "load1m": load.one,
            "load5m": load.five,
            "load15m": load.fifteen,
            "trafficInBytes": traffic_in,
            "trafficOutBytes": traffic_out,
            "connectionCount": connections,
            "apiSuccessPercent": api_success_percent,
            "apiAvgCostSeconds": api_avg_cost_seconds,
            "cacheTotalDiskSize": cache_stats.disk_bytes,
            "cacheTotalMemorySize": cache_stats.memory_bytes,
            "resourceGovernor": resource_governor,
            "pipelines": pipelines,
            "l4Defense": l4_defense,
            "xdp": xdp_status,
            "updatedAt": now,
            "timestamp": now,
            "isActive": true,
            "isHealthy": true,
        });

        if let Ok(shared) = SharedRpcClient::get(&api_config).await {
            let client = shared.as_rpc_client();
            let mut service = client.node_service();
            if let Err(e) =
                crate::rpc::track_rpc(service.update_node_status(pb::UpdateNodeStatusRequest {
                    node_id,
                    status_json: status.to_string().into_bytes(),
                }))
                .await
            {
                warn!("Failed to report node status: {}", e);
            }
        }
    }
}

pub async fn report_node_online_once(
    config_store: &ConfigStore,
    api_config: &ApiConfig,
) -> anyhow::Result<()> {
    let node_id = config_store.get_node_id().await;
    if node_id <= 0 {
        anyhow::bail!("node id is not available");
    }

    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    let (mut traffic_out, mut traffic_in, mut connections) =
        crate::metrics::METRICS.get_node_totals();
    let rpc_snap = crate::metrics::METRICS.rpc.snapshot();
    let mut rpc_total_requests = rpc_snap.total_requests;
    let mut rpc_total_errors = rpc_snap.total_errors;
    let mut rpc_total_cost_ms = rpc_snap.total_cost_ms;
    if crate::runtime_mode::RuntimeConfig::current_is_rke2() {
        let aggregated = crate::cluster::stats::aggregate();
        if aggregated.replica_count > 0 {
            traffic_out = aggregated.traffic_out;
            traffic_in = aggregated.traffic_in;
            connections = aggregated.active_connections;
            rpc_total_requests = aggregated.rpc_total_requests;
            rpc_total_errors = aggregated.rpc_total_errors;
            rpc_total_cost_ms = aggregated.rpc_total_cost_ms;
        }
    }
    let api_success_percent = if rpc_total_requests > 0 {
        (rpc_total_requests - rpc_total_errors) as f64 / rpc_total_requests as f64
    } else {
        1.0
    };
    let api_avg_cost_seconds = if rpc_total_requests > 0 {
        rpc_total_cost_ms as f64 / rpc_total_requests as f64 / 1000.0
    } else {
        0.0
    };
    let load = sysinfo::System::load_average();
    let (mut total_memory, mut used_memory) = crate::memory_governor::reported_memory_totals();
    let mut cpu_usage = sys.global_cpu_usage() as f64 / 100.0;
    if crate::runtime_mode::RuntimeConfig::current_is_rke2() {
        let aggregated = crate::cluster::stats::aggregate();
        if aggregated.replica_count > 0 {
            cpu_usage = aggregated.cpu_usage_avg;
            total_memory = aggregated.memory_total;
            used_memory = aggregated.memory_used;
        }
    }
    let memory_usage = if total_memory > 0 {
        used_memory as f64 / total_memory as f64
    } else {
        0.0
    };
    let cache_stats = crate::cache_manager::CACHE.storage.runtime_stats().await;
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_default();
    let host_ip = local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_default();
    let now = crate::utils::time::now_timestamp();
    let xdp_status = serde_json::to_value(crate::xdp::status_snapshot())
        .unwrap_or_else(|_| serde_json::json!({"available": false}));
    let status = serde_json::json!({
        "buildVersion": env!("CARGO_PKG_VERSION"),
        "buildVersionCode": build_version_code(),
        "configVersion": config_store.get_config_version().await,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "hostname": hostname,
        "hostIP": host_ip,
        "cpuUsage": cpu_usage,
        "cpuLogicalCount": sys.cpus().len(),
        "cpuPhysicalCount": sysinfo::System::physical_core_count().unwrap_or(sys.cpus().len()),
        "memoryUsage": memory_usage,
        "memoryTotal": total_memory,
        "load1m": load.one,
        "load5m": load.five,
        "load15m": load.fifteen,
        "trafficInBytes": traffic_in,
        "trafficOutBytes": traffic_out,
        "connectionCount": connections,
        "apiSuccessPercent": api_success_percent,
        "apiAvgCostSeconds": api_avg_cost_seconds,
        "cacheTotalDiskSize": cache_stats.disk_bytes,
        "cacheTotalMemorySize": cache_stats.memory_bytes,
        "xdp": xdp_status,
        "updatedAt": now,
        "timestamp": now,
        "isActive": true,
        "isHealthy": true,
    });

    let client = SharedRpcClient::get(api_config).await?.as_rpc_client();
    // updateNodeUp / updateNodeIsInstalled require admin credentials on cloud API
    // and will always fail with node credentials. UpdateNodeStatus already sets
    // isActive=true server-side.
    let mut service = client.node_service();
    crate::rpc::track_rpc(service.update_node_status(pb::UpdateNodeStatusRequest {
        node_id,
        status_json: status.to_string().into_bytes(),
    }))
    .await?;
    Ok(())
}

fn is_unsupported_node_type_error(err: &tonic::Status) -> bool {
    err.message().contains("not supported node type")
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
        if !crate::cluster::leader::require_leader("node_value_reporter") {
            continue;
        }
        let node_id = config_store.get_node_id().await;
        if node_id == 0 {
            continue;
        }

        sys.refresh_all();
        // ... (rest of the logic)

        let (mut traffic_out, mut traffic_in, mut connections) =
            crate::metrics::METRICS.get_node_totals();
        let load = sysinfo::System::load_average();

        let (mut total_memory, mut used_memory) = crate::memory_governor::reported_memory_totals();

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
        let cache_stats = crate::cache_manager::CACHE.storage.runtime_stats().await;

        let mut cpu_usage = sys.global_cpu_usage() as f64 / 100.0;
        let snapshots = crate::metrics::METRICS.take_snapshots();
        let mut requests: u64 = snapshots.iter().map(|s| s.1.total_requests).sum();
        let mut attack_requests: u64 = snapshots.iter().map(|s| s.1.count_attack_requests).sum();
        if crate::runtime_mode::RuntimeConfig::current_is_rke2() {
            let aggregated = crate::cluster::stats::aggregate();
            if aggregated.replica_count > 0 {
                traffic_out = aggregated.traffic_out;
                traffic_in = aggregated.traffic_in;
                connections = aggregated.active_connections;
                requests = aggregated.app_total_requests;
                attack_requests = aggregated.app_attack_requests;
                cpu_usage = aggregated.cpu_usage_avg;
                total_memory = aggregated.memory_total;
                used_memory = aggregated.memory_used;
            }
        }
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
                "usage": cpu_usage,
                "cores": sys.cpus().len(),
                "logicalCount": sys.cpus().len(),
                "physicalCount": sysinfo::System::physical_core_count().unwrap_or(sys.cpus().len())
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
                "diskSize": cache_stats.disk_bytes,
                "memorySize": cache_stats.memory_bytes
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
        if let Ok(shared) = SharedRpcClient::get(&api_config).await {
            let client = shared.as_rpc_client();
            let mut service = client.node_value_service();
            match crate::rpc::track_rpc(
                service.create_node_values(pb::CreateNodeValuesRequest { node_value_items }),
            )
            .await
            {
                Ok(_) => debug!(
                    "Successfully reported {} node values with items: {}",
                    node_value_items_count,
                    selected_items.join(",")
                ),
                Err(e) => warn!("Error reporting node values: {}", e),
            }
        }
    }
}
