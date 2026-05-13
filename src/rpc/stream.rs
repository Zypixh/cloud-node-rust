use crate::api_config::ApiConfig;
use crate::auth::generate_token;
use crate::config::ConfigStore;
use crate::pb;
use crate::rpc::client::RpcClient;
use bytes::{Buf, Bytes};
use futures_util::StreamExt;
use h2::client::SendRequest;
use http::{HeaderValue, Request, Uri};
use prost::Message;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

const NODE_STREAM_PATH: &str = "/pb.NodeService/nodeStream";
const GRPC_FRAME_HEADER_LEN: usize = 5;

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
        let stream_result = if last_endpoints
            .first()
            .is_some_and(|endpoint| endpoint.starts_with("http://"))
        {
            try_run_h2_stream(&api_config, config_store.clone(), None).await
        } else {
            let client =
                match RpcClient::new_with_endpoints(&api_config, &last_endpoints, false).await {
                    Ok(c) => c,
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
            run_stream(client, &api_config, config_store.clone())
                .await
                .map(|_| NodeStreamProbeResult::default())
        };

        match stream_result {
            Ok(_) => {
                // Stream ended cleanly (server shutdown), brief pause before reconnect
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                warn!("Node stream error: {}. Reconnecting...", e);
                // On error, refresh endpoints in case the API node changed
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
    if api_config
        .effective_rpc_endpoints()
        .first()
        .is_some_and(|endpoint| endpoint.starts_with("http://"))
    {
        try_run_h2_stream(api_config, config_store, Some(hold)).await
    } else {
        let client = RpcClient::new(api_config).await?;
        run_tonic_stream(client, api_config, config_store, Some(hold)).await
    }
}

async fn try_run_h2_stream(
    api_config: &ApiConfig,
    config_store: Arc<ConfigStore>,
    hold: Option<Duration>,
) -> anyhow::Result<NodeStreamProbeResult> {
    let endpoints = api_config.effective_rpc_endpoints();
    let endpoint = endpoints
        .first()
        .ok_or_else(|| anyhow::anyhow!("No RPC endpoints configured"))?;
    let uri: Uri = endpoint.parse()?;
    let scheme = uri.scheme_str().unwrap_or("http");
    if scheme != "http" {
        anyhow::bail!("low-level node stream currently supports http endpoints only");
    }
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("RPC endpoint has no host: {}", endpoint))?;
    let port = uri.port_u16().unwrap_or(80);
    let authority = uri
        .authority()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| format!("{}:{}", host, port));

    let tcp = tokio::net::TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true)?;
    let (h2_client, connection) = h2::client::handshake(tcp).await?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            debug!("Node stream HTTP/2 connection ended: {}", err);
        }
    });

    let (mut response_rx, send_stream) =
        open_h2_node_stream(h2_client, &authority, api_config).await?;
    let (out_tx, mut out_rx) = mpsc::channel::<pb::NodeStreamMessage>(100);
    let writer = tokio::spawn(async move {
        let mut send_stream = send_stream;
        while let Some(message) = out_rx.recv().await {
            match encode_grpc_message(&message) {
                Ok(frame) => {
                    if let Err(err) = send_stream.send_data(Bytes::from(frame), false) {
                        debug!("Failed to write node stream message: {}", err);
                        break;
                    }
                }
                Err(err) => {
                    debug!("Failed to encode node stream message: {}", err);
                }
            }
        }
    });

    info!("Node stream transport opened.");

    let connected_endpoints = endpoints;
    let mut current_api_node_id = None;
    let mut stats = NodeStreamProbeResult {
        transport_opened: true,
        ..Default::default()
    };
    let mut recv_body = None;
    let mut response_encoding = None;
    let mut decode_buffer = Vec::with_capacity(8192);
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(60));
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
        if recv_body.is_none() {
            tokio::select! {
                response_result = &mut response_rx => {
                    match response_result {
                        Ok(Ok((body, encoding))) => {
                            info!("Node stream response headers received.");
                            stats.response_headers_received = true;
                            response_encoding = encoding;
                            recv_body = Some(body);
                        }
                        Ok(Err(err)) => return Err(err),
                        Err(_) => anyhow::bail!("nodeStream HTTP/2 response task ended unexpectedly"),
                    }
                }
                _ = heartbeat_interval.tick() => {
                    if send_node_stream_ping(&config_store, &out_tx).await {
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
            continue;
        }

        tokio::select! {
            next_message = read_next_h2_grpc_message(
                recv_body.as_mut().expect("node stream body exists"),
                &mut decode_buffer,
                response_encoding.as_deref(),
            ) => {
                let Some(message) = next_message? else {
                    debug!("Node stream connection closed by API node.");
                    break;
                };

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

                let _ = handle_message(&message, &out_tx, api_config, config_store.clone()).await;
            }
            _ = heartbeat_interval.tick() => {
                if send_node_stream_ping(&config_store, &out_tx).await {
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

    writer.abort();
    if let Some(id) = current_api_node_id {
        crate::rpc::node::CONNECTED_API_NODE_IDS.write().remove(&id);
    }

    Ok(stats)
}

async fn send_node_stream_ping(
    config_store: &ConfigStore,
    tx: &mpsc::Sender<pb::NodeStreamMessage>,
) -> bool {
    let current_node_id = config_store.get_node_id().await;
    if current_node_id <= 0 {
        return false;
    }

    tx.try_send(pb::NodeStreamMessage {
        node_id: current_node_id,
        request_id: 0,
        code: "ping".to_string(),
        is_ok: true,
        ..Default::default()
    })
    .is_ok()
}

async fn open_h2_node_stream(
    h2_client: SendRequest<Bytes>,
    authority: &str,
    api_config: &ApiConfig,
) -> anyhow::Result<(
    oneshot::Receiver<anyhow::Result<(h2::RecvStream, Option<String>)>>,
    h2::SendStream<Bytes>,
)> {
    let token = generate_token(&api_config.node_id, &api_config.secret, "node")?;
    let node_id = HeaderValue::from_str(&api_config.node_id)?;
    let token = HeaderValue::from_str(&token)?;
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{}{}", authority, NODE_STREAM_PATH))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "grpc-go/1.0")
        .header("nodeid", node_id)
        .header("token", token)
        .header("grpc-accept-encoding", "gzip")
        .body(())?;

    let mut ready = h2_client.ready().await?;
    let (response, send_stream) = ready.send_request(request, false)?;
    let (response_tx, response_rx) = oneshot::channel();
    tokio::spawn(async move {
        let result = async move {
            let response = response.await?;
            if response.status() != http::StatusCode::OK {
                anyhow::bail!("nodeStream returned HTTP status {}", response.status());
            }
            let encoding = response
                .headers()
                .get("grpc-encoding")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_ascii_lowercase());
            Ok((response.into_body(), encoding))
        }
        .await;
        let _ = response_tx.send(result);
    });

    Ok((response_rx, send_stream))
}

fn encode_grpc_message(message: &pb::NodeStreamMessage) -> anyhow::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    message.encode(&mut encoded)?;
    let mut frame = Vec::with_capacity(GRPC_FRAME_HEADER_LEN + encoded.len());
    frame.push(0);
    frame.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    frame.extend_from_slice(&encoded);
    Ok(frame)
}

async fn read_next_h2_grpc_message(
    body: &mut h2::RecvStream,
    buffer: &mut Vec<u8>,
    encoding: Option<&str>,
) -> anyhow::Result<Option<pb::NodeStreamMessage>> {
    loop {
        if let Some(message) = try_decode_grpc_message(buffer, encoding)? {
            return Ok(Some(message));
        }

        match body.data().await {
            Some(chunk) => {
                let mut chunk = chunk?;
                let len = chunk.remaining();
                body.flow_control().release_capacity(len)?;
                buffer.extend_from_slice(chunk.copy_to_bytes(len).as_ref());
            }
            None => {
                if !buffer.is_empty() {
                    anyhow::bail!("nodeStream ended with incomplete grpc frame");
                }
                return Ok(None);
            }
        }
    }
}

fn try_decode_grpc_message(
    buffer: &mut Vec<u8>,
    encoding: Option<&str>,
) -> anyhow::Result<Option<pb::NodeStreamMessage>> {
    if buffer.len() < GRPC_FRAME_HEADER_LEN {
        return Ok(None);
    }
    let compressed = buffer[0] != 0;
    let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
    if buffer.len() < GRPC_FRAME_HEADER_LEN + len {
        return Ok(None);
    }
    let mut payload = buffer[GRPC_FRAME_HEADER_LEN..GRPC_FRAME_HEADER_LEN + len].to_vec();
    buffer.drain(..GRPC_FRAME_HEADER_LEN + len);

    if compressed {
        match encoding.unwrap_or("gzip") {
            "gzip" => {
                let mut decoder = flate2::read::GzDecoder::new(payload.as_slice());
                let mut decoded = Vec::new();
                decoder.read_to_end(&mut decoded)?;
                payload = decoded;
            }
            other => anyhow::bail!("unsupported compressed nodeStream encoding: {}", other),
        }
    }

    Ok(Some(pb::NodeStreamMessage::decode(payload.as_slice())?))
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
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(60));
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
                        warn!("Node stream error: {}", e);

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
                let inner = crate::cache_manager::CACHE.storage.l2.inner.load();
                let root = &inner.main_root;

                for (hash, _) in all_meta {
                    let file_path = root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
                    if file_path.exists() {
                        let _ = std::fs::remove_file(&file_path);
                    }
                    // Also check extra_roots
                    for extra in &inner.extra_roots {
                        let extra_path = extra.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
                        if extra_path.exists() {
                            let _ = std::fs::remove_file(&extra_path);
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
