use std::sync::Arc;
use std::time::Duration;

use cloud_node_rust::api_config::ApiConfig;
use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::firewall::state::WafStateManager;
use cloud_node_rust::health_manager::GlobalHealthManager;
use cloud_node_rust::pb;
use cloud_node_rust::rpc::client::RpcClient;
use cloud_node_rust::rpc::node::{fetch_and_apply_config, report_node_online_once};
use cloud_node_rust::ssl::DynamicCertSelector;
use std::io::Read;

fn real_api_config_from_env() -> anyhow::Result<Option<ApiConfig>> {
    if std::env::var("CLOUD_NODE_REAL_API_TEST").ok().as_deref() != Some("1") {
        eprintln!("skip real API config test: set CLOUD_NODE_REAL_API_TEST=1 to enable");
        return Ok(None);
    }

    if let Ok(path) = std::env::var("CLOUD_NODE_TEST_API_CONFIG") {
        return ApiConfig::load(path).map(Some);
    }

    let endpoints = std::env::var("CLOUD_NODE_TEST_RPC_ENDPOINTS")
        .or_else(|_| std::env::var("CLOUD_NODE_TEST_RPC_ENDPOINT"))
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })?;
    let node_id = std::env::var("CLOUD_NODE_TEST_NODE_ID")?;
    let secret = std::env::var("CLOUD_NODE_TEST_SECRET")?;

    Ok(Some(ApiConfig {
        rpc_endpoints: endpoints,
        rpc_disable_update: false,
        node_id,
        secret,
        billing_count_inbound_traffic: false,
        access_log_pipeline: Default::default(),
    }))
}

fn real_stream_hold_seconds() -> u64 {
    std::env::var("CLOUD_NODE_REAL_API_STREAM_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(45)
        .clamp(30, 60)
}

fn require_real_stream() -> bool {
    std::env::var("CLOUD_NODE_REAL_API_REQUIRE_STREAM")
        .ok()
        .as_deref()
        == Some("1")
}

fn require_real_doc_snapshot() -> bool {
    std::env::var("CLOUD_NODE_REAL_API_DOC_SNAPSHOT")
        .ok()
        .as_deref()
        == Some("1")
}

async fn decode_node_json(resp: pb::FindCurrentNodeConfigResponse) -> anyhow::Result<Vec<u8>> {
    if resp.is_compressed {
        tokio::task::spawn_blocking(move || {
            let mut decompressor = brotli::Decompressor::new(&resp.node_json[..], 4096);
            let mut decoded = Vec::new();
            decompressor.read_to_end(&mut decoded).map(|_| decoded)
        })
        .await?
        .map_err(Into::into)
    } else {
        Ok(resp.node_json)
    }
}

fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn json_shape(value: &serde_json::Value, depth: usize) -> serde_json::Value {
    if depth == 0 {
        return serde_json::json!(json_type(value));
    }

    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, value) in map {
                out.insert(key.clone(), json_shape(value, depth - 1));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => serde_json::json!({
            "type": "array",
            "len": items.len(),
            "item": items.first().map(|item| json_shape(item, depth - 1)).unwrap_or(serde_json::Value::Null),
        }),
        other => serde_json::json!(json_type(other)),
    }
}

fn json_bytes_summary(bytes: &[u8], depth: usize) -> serde_json::Value {
    if bytes.is_empty() {
        return serde_json::json!({
            "len": 0,
            "empty": true,
        });
    }

    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(value) => serde_json::json!({
            "len": bytes.len(),
            "shape": json_shape(&value, depth),
        }),
        Err(err) => serde_json::json!({
            "len": bytes.len(),
            "jsonError": err.to_string(),
        }),
    }
}

fn print_doc_sample(label: &str, value: serde_json::Value) -> anyhow::Result<()> {
    println!(
        "DOC_SAMPLE {} {}",
        label,
        serde_json::to_string_pretty(&value)?
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_api_config_can_be_fetched_parsed_and_applied() -> anyhow::Result<()> {
    let Some(api_config) = real_api_config_from_env()? else {
        return Ok(());
    };

    let config_store = ConfigStore::new();
    let health_manager = GlobalHealthManager::new(4);
    let cert_selector = Arc::new(DynamicCertSelector::new());
    let waf_state = WafStateManager::new();
    let rpc_client = RpcClient::new(&api_config).await?;

    let mut direct_node_service = rpc_client.node_service();
    let direct_resp = tokio::time::timeout(
        Duration::from_secs(30),
        direct_node_service.find_current_node_config(pb::FindCurrentNodeConfigRequest {
            version: -1,
            compress: true,
            node_task_version: 0,
            use_data_map: true,
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("direct real API config fetch timed out"))??
    .into_inner();

    assert!(
        !direct_resp.node_json.is_empty(),
        "API returned empty nodeJSON: isChanged={} isCompressed={} dataSize={} timestamp={}",
        direct_resp.is_changed,
        direct_resp.is_compressed,
        direct_resp.data_size,
        direct_resp.timestamp
    );

    let node_json = decode_node_json(direct_resp).await?;
    let parsed: cloud_node_rust::config_models::NodeConfigPayload =
        serde_json::from_slice(&node_json)?;
    assert!(
        parsed.id.unwrap_or(0) > 0 || parsed.node_id.as_deref().is_some_and(|id| !id.is_empty()),
        "parsed real config should contain node identity"
    );

    let mut node_service = rpc_client.node_service();
    let mut task_version = 0;
    let mut config_version = -1;

    tokio::time::timeout(
        Duration::from_secs(30),
        fetch_and_apply_config(
            &mut node_service,
            &config_store,
            &api_config,
            &health_manager,
            &cert_selector,
            &waf_state,
            &mut task_version,
            &mut config_version,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("real API config fetch timed out"))?;

    assert!(
        config_version > 0,
        "API should return a positive config timestamp/version"
    );
    assert!(
        config_store.get_node_id().await > 0,
        "applied config should set numeric node id"
    );

    let snapshot = config_store.get_hot_path_snapshot_sync();
    assert!(
        Arc::strong_count(&snapshot.global_http) >= 1,
        "global HTTP config should be available in hot path snapshot"
    );

    report_node_online_once(&config_store, &api_config).await?;

    let hold_secs = real_stream_hold_seconds();
    let status_config_store = &config_store;
    let status_api_config = &api_config;
    let status_deadline = tokio::time::Instant::now() + Duration::from_secs(hold_secs);
    let mut status_interval = tokio::time::interval(Duration::from_secs(15));
    let mut status_reports = 0usize;
    while tokio::time::Instant::now() < status_deadline {
        tokio::select! {
            _ = status_interval.tick() => {
                report_node_online_once(status_config_store, status_api_config).await?;
                status_reports += 1;
            }
            _ = tokio::time::sleep_until(status_deadline) => {
                break;
            }
        }
    }
    assert!(
        status_reports >= 2,
        "real API online status should be reported multiple times; reports={}",
        status_reports
    );

    if !require_real_stream() {
        return Ok(());
    }

    let stream_result = tokio::time::timeout(
        Duration::from_secs(hold_secs + 20),
        cloud_node_rust::rpc::stream::probe_node_stream(
            &api_config,
            Arc::new(config_store.clone()),
            Duration::from_secs(hold_secs),
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("real API node stream establish/hold timed out"))??;

    assert!(
        stream_result.transport_opened,
        "node stream HTTP/2 transport should open and hold for {}s",
        hold_secs
    );
    assert!(
        stream_result.response_headers_received,
        "node stream should receive gRPC response headers"
    );
    assert!(
        stream_result.inbound_messages > 0,
        "node stream should receive at least one control-plane message within {}s",
        hold_secs
    );
    assert!(
        stream_result.connected_api_node_id.is_some(),
        "node stream should emit connectedAPINode within {}s; inbound_messages={}",
        hold_secs,
        stream_result.inbound_messages
    );
    assert!(
        stream_result.pings_sent >= 1,
        "node stream should keep running long enough to send multiple pings; sent={}",
        stream_result.pings_sent
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_api_grpc_documentation_snapshot() -> anyhow::Result<()> {
    if !require_real_doc_snapshot() {
        eprintln!("skip real API documentation snapshot: set CLOUD_NODE_REAL_API_DOC_SNAPSHOT=1");
        return Ok(());
    }
    let Some(api_config) = real_api_config_from_env()? else {
        return Ok(());
    };

    let client = RpcClient::new(&api_config).await?;

    let mut ping_service = client.ping_service();
    let ping = tokio::time::timeout(Duration::from_secs(10), ping_service.ping(pb::PingRequest {}))
        .await
        .map_err(|_| anyhow::anyhow!("PingService.Ping timed out"))??;
    print_doc_sample(
        "PingService.Ping",
        serde_json::json!({ "result": ping.into_inner().result }),
    )?;

    let mut node_service = client.node_service();
    let raw_config_resp = tokio::time::timeout(
        Duration::from_secs(30),
        node_service.find_current_node_config(pb::FindCurrentNodeConfigRequest {
            version: -1,
            compress: true,
            node_task_version: 0,
            use_data_map: true,
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("NodeService.FindCurrentNodeConfig timed out"))??
    .into_inner();
    let config_meta = serde_json::json!({
        "isChanged": raw_config_resp.is_changed,
        "isCompressed": raw_config_resp.is_compressed,
        "dataSize": raw_config_resp.data_size,
        "timestamp": raw_config_resp.timestamp,
        "nodeJSONBytes": raw_config_resp.node_json.len(),
    });
    let node_json = decode_node_json(raw_config_resp).await?;
    let node_json_value: serde_json::Value = serde_json::from_slice(&node_json)?;
    let payload: cloud_node_rust::config_models::NodeConfigPayload =
        serde_json::from_slice(&node_json)?;
    let numeric_node_id = payload.id.unwrap_or(0);
    let first_server = payload.servers.iter().find_map(|server| {
        server
            .id
            .filter(|id| *id > 0)
            .map(|id| (id, server.user_id, server.user_plan_id))
    });
    print_doc_sample(
        "NodeService.FindCurrentNodeConfig",
        serde_json::json!({
            "response": config_meta,
            "nodeJSON": {
                "len": node_json.len(),
                "shape": json_shape(&node_json_value, 3),
                "serverCount": payload.servers.len(),
                "metricItemCount": payload.metric_items.len(),
                "httpCachePolicyCount": payload.http_cache_policies.len(),
                "httpFirewallPolicyCount": payload.http_firewall_policies.len(),
                "sslCertCount": payload.ssl_certs.len(),
                "grpcPolicyCount": payload.grpc_policies.len(),
                "hasPrimaryGRPCPolicy": payload.primary_grpc_policy.is_some(),
                "updatingServerListId": payload.updating_server_list_id,
            }
        }),
    )?;

    match node_service
        .find_node_level_info(pb::FindNodeLevelInfoRequest {})
        .await
    {
        Ok(resp) => {
            let resp = resp.into_inner();
            print_doc_sample(
                "NodeService.FindNodeLevelInfo",
                serde_json::json!({
                    "level": resp.level,
                    "parentNodesMapJSON": json_bytes_summary(&resp.parent_nodes_map_json, 2),
                }),
            )?;
        }
        Err(err) => print_doc_sample(
            "NodeService.FindNodeLevelInfo.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    if numeric_node_id > 0 {
        let mut node_service_with_type = client.node_service_with_type();
        match node_service_with_type
            .find_enabled_node_config_info(pb::FindEnabledNodeConfigInfoRequest {
                node_id: numeric_node_id,
            })
            .await
        {
            Ok(resp) => {
                let resp = resp.into_inner();
                print_doc_sample(
                    "NodeService.FindEnabledNodeConfigInfo",
                    serde_json::json!({
                        "hasDNSInfo": resp.has_dns_info,
                        "hasCacheInfo": resp.has_cache_info,
                        "hasThresholds": resp.has_thresholds,
                        "hasSSH": resp.has_ssh,
                        "hasSystemSettings": resp.has_system_settings,
                        "hasDDoSProtection": resp.has_d_do_s_protection,
                        "hasScheduleSettings": resp.has_schedule_settings,
                        "hasAccessLogSettings": resp.has_access_log_settings,
                    }),
                )?;
            }
            Err(err) => print_doc_sample(
                "NodeService.FindEnabledNodeConfigInfo.error",
                serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
            )?,
        }
    }

    let mut task_service = client.node_task_service();
    match task_service
        .find_node_tasks(pb::FindNodeTasksRequest { version: 0 })
        .await
    {
        Ok(resp) => {
            let tasks = resp.into_inner().node_tasks;
            let samples = tasks
                .iter()
                .take(5)
                .map(|task| {
                    serde_json::json!({
                        "id": task.id,
                        "version": task.version,
                        "type": task.r#type,
                        "serverId": task.server_id,
                        "userId": task.user_id,
                    })
                })
                .collect::<Vec<_>>();
            print_doc_sample(
                "NodeTaskService.FindNodeTasks",
                serde_json::json!({ "count": tasks.len(), "sample": samples }),
            )?;
        }
        Err(err) => print_doc_sample(
            "NodeTaskService.FindNodeTasks.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    let mut api_node_service = client.api_node_service();
    match api_node_service
        .find_all_enabled_api_nodes(pb::FindAllEnabledApiNodesRequest {})
        .await
    {
        Ok(resp) => {
            let nodes = resp.into_inner().api_nodes;
            let samples = nodes
                .iter()
                .take(5)
                .map(|node| {
                    serde_json::json!({
                        "id": node.id,
                        "isOn": node.is_on,
                        "nodeClusterId": node.node_cluster_id,
                        "name": node.name,
                        "accessAddrsCount": node.access_addrs.len(),
                        "accessAddrsJSON": json_bytes_summary(&node.access_addrs_json, 1),
                        "httpJSON": json_bytes_summary(&node.http_json, 1),
                        "httpsJSON": json_bytes_summary(&node.https_json, 1),
                        "statusJSON": json_bytes_summary(&node.status_json, 1),
                        "isPrimary": node.is_primary,
                        "instanceCode": node.instance_code,
                    })
                })
                .collect::<Vec<_>>();
            print_doc_sample(
                "APINodeService.FindAllEnabledAPINodes",
                serde_json::json!({ "count": nodes.len(), "sample": samples }),
            )?;
        }
        Err(err) => print_doc_sample(
            "APINodeService.FindAllEnabledAPINodes.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    let mut updating_service = client.updating_server_list_service();
    match updating_service
        .find_updating_server_lists(pb::FindUpdatingServerListsRequest {
            last_id: payload.updating_server_list_id,
        })
        .await
    {
        Ok(resp) => {
            let resp = resp.into_inner();
            print_doc_sample(
                "UpdatingServerListService.FindUpdatingServerLists",
                serde_json::json!({
                    "maxId": resp.max_id,
                    "serversJSON": json_bytes_summary(&resp.servers_json, 2),
                }),
            )?;
        }
        Err(err) => print_doc_sample(
            "UpdatingServerListService.FindUpdatingServerLists.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    let mut ip_item_service = client.ip_item_service();
    match ip_item_service
        .list_ip_items_after_version(pb::ListIpItemsAfterVersionRequest {
            version: 0,
            size: 10,
        })
        .await
    {
        Ok(resp) => {
            let resp = resp.into_inner();
            let samples = resp
                .ip_items
                .iter()
                .take(5)
                .map(|item| {
                    serde_json::json!({
                        "id": item.id,
                        "value": item.value,
                        "ipFrom": item.ip_from,
                        "ipTo": item.ip_to,
                        "version": item.version,
                        "expiredAt": item.expired_at,
                        "reason": item.reason,
                        "listId": item.list_id,
                        "isDeleted": item.is_deleted,
                        "type": item.r#type,
                        "eventLevel": item.event_level,
                        "listType": item.list_type,
                        "isGlobal": item.is_global,
                        "createdAt": item.created_at,
                        "nodeId": item.node_id,
                        "serverId": item.server_id,
                        "sourceNodeId": item.source_node_id,
                        "sourceServerId": item.source_server_id,
                        "sourceHTTPFirewallPolicyId": item.source_http_firewall_policy_id,
                        "sourceHTTPFirewallRuleGroupId": item.source_http_firewall_rule_group_id,
                        "sourceHTTPFirewallRuleSetId": item.source_http_firewall_rule_set_id,
                        "sourceURL": item.source_url,
                        "sourceUserAgent": item.source_user_agent,
                        "isRead": item.is_read,
                    })
                })
                .collect::<Vec<_>>();
            print_doc_sample(
                "IPItemService.ListIPItemsAfterVersion",
                serde_json::json!({ "version": resp.version, "count": resp.ip_items.len(), "sample": samples }),
            )?;
        }
        Err(err) => print_doc_sample(
            "IPItemService.ListIPItemsAfterVersion.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    let mut cache_service = client.cache_task_service();
    match cache_service
        .find_doing_http_cache_task_keys(pb::FindDoingHttpCacheTaskKeysRequest { size: 5 })
        .await
    {
        Ok(resp) => {
            let keys = resp.into_inner().http_cache_task_keys;
            let samples = keys
                .iter()
                .map(|key| {
                    serde_json::json!({
                        "id": key.id,
                        "taskId": key.task_id,
                        "key": key.key,
                        "type": key.r#type,
                        "keyType": key.key_type,
                        "isDone": key.is_done,
                        "isDoing": key.is_doing,
                        "errorsJSON": json_bytes_summary(&key.errors_json, 1),
                        "nodeClusterId": key.node_cluster_id,
                    })
                })
                .collect::<Vec<_>>();
            print_doc_sample(
                "HTTPCacheTaskKeyService.FindDoingHTTPCacheTaskKeys",
                serde_json::json!({ "count": keys.len(), "sample": samples }),
            )?;
        }
        Err(err) => print_doc_sample(
            "HTTPCacheTaskKeyService.FindDoingHTTPCacheTaskKeys.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    let mut deleted_content_service = client.deleted_content_service();
    match deleted_content_service
        .list_server_deleted_contents_after_version(
            pb::ListServerDeletedContentsAfterVersionRequest {
                version: 0,
                size: 5,
            },
        )
        .await
    {
        Ok(resp) => {
            let items = resp.into_inner().server_deleted_contents;
            let samples = items
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "id": item.id,
                        "adminId": item.admin_id,
                        "serverId": item.server_id,
                        "url": item.url,
                        "reasonType": item.reason_type,
                        "version": item.version,
                        "createdAt": item.created_at,
                        "isDeleted": item.is_deleted,
                    })
                })
                .collect::<Vec<_>>();
            print_doc_sample(
                "ServerDeletedContentService.ListServerDeletedContentsAfterVersion",
                serde_json::json!({ "count": items.len(), "sample": samples }),
            )?;
        }
        Err(err) => print_doc_sample(
            "ServerDeletedContentService.ListServerDeletedContentsAfterVersion.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    let mut ssl_service = client.ssl_cert_service();
    match ssl_service
        .list_updated_ssl_cert_ocsp(pb::ListUpdatedSslCertOcspRequest {
            version: 0,
            size: 5,
        })
        .await
    {
        Ok(resp) => {
            let items = resp.into_inner().ssl_cert_ocsp;
            let samples = items
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "sslCertId": item.ssl_cert_id,
                        "dataBytes": item.data.len(),
                        "version": item.version,
                        "expiresAt": item.expires_at,
                    })
                })
                .collect::<Vec<_>>();
            print_doc_sample(
                "SSLCertService.ListUpdatedSSLCertOCSP",
                serde_json::json!({ "count": items.len(), "sample": samples }),
            )?;
        }
        Err(err) => print_doc_sample(
            "SSLCertService.ListUpdatedSSLCertOCSP.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    let mut artifact_service = client.ip_library_artifact_service();
    let artifact_file_id = match artifact_service
        .find_public_ip_library_artifact(pb::FindPublicIpLibraryArtifactRequest {})
        .await
    {
        Ok(resp) => {
            let artifact = resp.into_inner().ip_library_artifact;
            let file_id = artifact.as_ref().map(|item| item.file_id).unwrap_or(0);
            let sample = artifact.map(|item| {
                serde_json::json!({
                    "id": item.id,
                    "fileId": item.file_id,
                    "createdAt": item.created_at,
                    "metaJSON": json_bytes_summary(&item.meta_json, 2),
                    "isPublic": item.is_public,
                    "name": item.name,
                    "code": item.code,
                    "file": item.file.map(|file| serde_json::json!({
                        "id": file.id,
                        "filename": file.filename,
                        "size": file.size,
                        "createdAt": file.created_at,
                        "isPublic": file.is_public,
                        "mimeType": file.mime_type,
                        "type": file.r#type,
                    })),
                })
            });
            print_doc_sample(
                "IPLibraryArtifactService.FindPublicIPLibraryArtifact",
                serde_json::json!({ "artifact": sample }),
            )?;
            file_id
        }
        Err(err) => {
            print_doc_sample(
                "IPLibraryArtifactService.FindPublicIPLibraryArtifact.error",
                serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
            )?;
            0
        }
    };

    if artifact_file_id > 0 {
        let mut file_chunk_service = client.file_chunk_service();
        match file_chunk_service
            .find_all_file_chunk_ids(pb::FindAllFileChunkIdsRequest {
                file_id: artifact_file_id,
                access_ticket: String::new(),
            })
            .await
        {
            Ok(resp) => {
                let ids = resp.into_inner().file_chunk_ids;
                print_doc_sample(
                    "FileChunkService.FindAllFileChunkIds",
                    serde_json::json!({
                        "fileId": artifact_file_id,
                        "count": ids.len(),
                        "firstIds": ids.iter().take(5).copied().collect::<Vec<_>>(),
                    }),
                )?;
                if let Some(first_id) = ids.first().copied() {
                    match file_chunk_service
                        .download_file_chunk(pb::DownloadFileChunkRequest {
                            file_chunk_id: first_id,
                            access_ticket: String::new(),
                        })
                        .await
                    {
                        Ok(resp) => {
                            let bytes = resp
                                .into_inner()
                                .file_chunk
                                .map(|chunk| chunk.data.len())
                                .unwrap_or(0);
                            print_doc_sample(
                                "FileChunkService.DownloadFileChunk",
                                serde_json::json!({ "fileChunkId": first_id, "dataBytes": bytes }),
                            )?;
                        }
                        Err(err) => print_doc_sample(
                            "FileChunkService.DownloadFileChunk.error",
                            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
                        )?,
                    }
                }
            }
            Err(err) => print_doc_sample(
                "FileChunkService.FindAllFileChunkIds.error",
                serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
            )?,
        }
    }

    let mut client_agent_service = client.client_agent_ip_service();
    match client_agent_service
        .list_client_agent_i_ps_after_id(pb::ListClientAgentIPsAfterIdRequest { id: 0, size: 5 })
        .await
    {
        Ok(resp) => {
            let items = resp.into_inner().client_agent_i_ps;
            let samples = items
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "id": item.id,
                        "ip": item.ip,
                        "ptr": item.ptr,
                        "clientAgent": item.client_agent.as_ref().map(|agent| serde_json::json!({
                            "id": agent.id,
                            "name": agent.name,
                            "code": agent.code,
                            "description": agent.description,
                            "countIPs": agent.count_i_ps,
                        })),
                    })
                })
                .collect::<Vec<_>>();
            print_doc_sample(
                "ClientAgentIPService.ListClientAgentIPsAfterId",
                serde_json::json!({ "count": items.len(), "sample": samples }),
            )?;
        }
        Err(err) => print_doc_sample(
            "ClientAgentIPService.ListClientAgentIPsAfterId.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    let mut acme_service = client.acme_service();
    match acme_service
        .find_acme_authentication_key_with_token(
            pb::FindAcmeAuthenticationKeyWithTokenRequest {
                token: "__codex_doc_probe__".to_string(),
            },
        )
        .await
    {
        Ok(resp) => print_doc_sample(
            "ACMEAuthenticationService.FindACMEAuthenticationKeyWithToken",
            serde_json::json!({ "key": resp.into_inner().key }),
        )?,
        Err(err) => print_doc_sample(
            "ACMEAuthenticationService.FindACMEAuthenticationKeyWithToken.error",
            serde_json::json!({ "code": format!("{:?}", err.code()), "message": err.message() }),
        )?,
    }

    if let Some((server_id, user_id, user_plan_id)) = first_server {
        let mut server_service = client.server_service();
        match server_service
            .compose_server_config(pb::ComposeServerConfigRequest { server_id })
            .await
        {
            Ok(resp) => {
                let resp = resp.into_inner();
                print_doc_sample(
                    "ServerService.ComposeServerConfig",
                    serde_json::json!({
                        "serverId": server_id,
                        "serverConfigJSON": json_bytes_summary(&resp.server_config_json, 3),
                    }),
                )?;
            }
            Err(err) => print_doc_sample(
                "ServerService.ComposeServerConfig.error",
                serde_json::json!({ "serverId": server_id, "code": format!("{:?}", err.code()), "message": err.message() }),
            )?,
        }

        let mut typed_server_service = client.server_service_with_type();
        match typed_server_service
            .find_server_user_plan(pb::FindServerUserPlanRequest { server_id })
            .await
        {
            Ok(resp) => {
                let user_plan = resp.into_inner().user_plan;
                print_doc_sample(
                    "ServerService.FindServerUserPlan",
                    serde_json::json!({
                        "serverId": server_id,
                        "userPlan": user_plan.as_ref().map(|plan| serde_json::json!({
                            "id": plan.id,
                            "userId": plan.user_id,
                            "planId": plan.plan_id,
                            "isOn": plan.is_on,
                            "dayTo": plan.day_to,
                            "name": plan.name,
                            "hasUser": plan.user.is_some(),
                            "hasPlan": plan.plan.is_some(),
                            "serverCount": plan.servers.len(),
                        })),
                    }),
                )?;
            }
            Err(err) => print_doc_sample(
                "ServerService.FindServerUserPlan.error",
                serde_json::json!({ "serverId": server_id, "code": format!("{:?}", err.code()), "message": err.message() }),
            )?,
        }

        if user_id > 0 {
            let mut user_service = client.user_service();
            match user_service
                .check_user_servers_state(pb::CheckUserServersStateRequest { user_id })
                .await
            {
                Ok(resp) => print_doc_sample(
                    "UserService.CheckUserServersState",
                    serde_json::json!({ "userId": user_id, "isEnabled": resp.into_inner().is_enabled }),
                )?,
                Err(err) => print_doc_sample(
                    "UserService.CheckUserServersState.error",
                    serde_json::json!({ "userId": user_id, "code": format!("{:?}", err.code()), "message": err.message() }),
                )?,
            }

            match server_service
                .compose_all_user_servers_config(pb::ComposeAllUserServersConfigRequest { user_id })
                .await
            {
                Ok(resp) => {
                    let resp = resp.into_inner();
                    print_doc_sample(
                        "ServerService.ComposeAllUserServersConfig",
                        serde_json::json!({
                            "userId": user_id,
                            "serversConfigJSON": json_bytes_summary(&resp.servers_config_json, 3),
                        }),
                    )?;
                }
                Err(err) => print_doc_sample(
                    "ServerService.ComposeAllUserServersConfig.error",
                    serde_json::json!({ "userId": user_id, "code": format!("{:?}", err.code()), "message": err.message() }),
                )?,
            }
        }

        if user_plan_id > 0 {
            let mut plan_service = client.plan_service();
            let plan_resp = match plan_service
                .find_enabled_plan(pb::FindEnabledPlanRequest {
                    plan_id: user_plan_id,
                })
                .await
            {
                Ok(resp) => Ok(resp.into_inner().plan),
                Err(_) => {
                    match plan_service
                        .find_basic_plan(pb::FindBasicPlanRequest {
                            plan_id: user_plan_id,
                        })
                        .await
                    {
                        Ok(resp) => Ok(resp.into_inner().plan),
                        Err(err) => Err(err),
                    }
                }
            };

            match plan_resp {
                Ok(plan) => {
                    print_doc_sample(
                        "PlanService.FindEnabledPlanOrFindBasicPlan",
                        serde_json::json!({
                            "planId": user_plan_id,
                            "plan": plan.as_ref().map(|plan| serde_json::json!({
                                "id": plan.id,
                                "isOn": plan.is_on,
                                "name": plan.name,
                                "clusterId": plan.cluster_id,
                                "trafficLimitJSON": json_bytes_summary(&plan.traffic_limit_json, 2),
                                "bandwidthLimitPerNodeJSON": json_bytes_summary(&plan.bandwidth_limit_per_node_json, 2),
                                "featuresJSON": json_bytes_summary(&plan.features_json, 2),
                                "maxUploadSizeJSON": json_bytes_summary(&plan.max_upload_size_json, 2),
                                "priceType": plan.price_type,
                                "hasFullFeatures": plan.has_full_features,
                                "lbMode": plan.lb_mode,
                            })),
                        }),
                    )?;
                }
                Err(err) => print_doc_sample(
                    "PlanService.FindEnabledPlanOrFindBasicPlan.error",
                    serde_json::json!({ "planId": user_plan_id, "code": format!("{:?}", err.code()), "message": err.message() }),
                )?,
            }
        }
    }

    Ok(())
}
