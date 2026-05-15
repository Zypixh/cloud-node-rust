use std::sync::Arc;
use std::time::Duration;

use cloud_node_rust::api_config::ApiConfig;
use cloud_node_rust::config::ConfigStore;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_api_config_can_be_fetched_parsed_and_applied() -> anyhow::Result<()> {
    let Some(api_config) = real_api_config_from_env()? else {
        return Ok(());
    };

    let config_store = ConfigStore::new();
    let health_manager = GlobalHealthManager::new(4);
    let cert_selector = Arc::new(DynamicCertSelector::new());
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

    let node_json = if direct_resp.is_compressed {
        tokio::task::spawn_blocking(move || {
            let mut decompressor = brotli::Decompressor::new(&direct_resp.node_json[..], 4096);
            let mut decoded = Vec::new();
            decompressor.read_to_end(&mut decoded).map(|_| decoded)
        })
        .await??
    } else {
        direct_resp.node_json
    };
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
