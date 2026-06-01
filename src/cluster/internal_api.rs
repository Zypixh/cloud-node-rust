use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

const MAX_INTERNAL_BODY_BYTES: usize = 2 * 1024 * 1024;
// Cap per-connection lifetime — a misbehaving / malicious peer that trickles
// one byte at a time must not be able to permanently occupy a Tokio task.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
struct PurgeRequest {
    #[serde(default)]
    key: String,
    #[serde(rename = "key_type", alias = "keyType", default)]
    key_type: String,
    #[serde(default)]
    prefix: String,
}

#[derive(Clone)]
pub struct InternalApiState {
    bind: String,
    token: String,
    cluster_name: String,
}

pub fn start(runtime_config: &crate::runtime_mode::RuntimeConfig) -> anyhow::Result<()> {
    if !runtime_config.is_rke2() {
        return Ok(());
    }

    let token_env = &runtime_config.cluster.internal_api.token_env;
    let token = std::env::var(token_env)?;
    if token.trim().is_empty() {
        anyhow::bail!("internal API token environment variable {token_env} is empty");
    }

    let state = InternalApiState {
        bind: runtime_config.cluster.internal_api.bind.clone(),
        token,
        cluster_name: runtime_config.cluster.name.clone(),
    };

    tokio::spawn(async move {
        if let Err(err) = run(state).await {
            error!("CLUSTER_INTERNAL_API: listener stopped: {}", err);
        }
    });
    Ok(())
}

async fn run(state: InternalApiState) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&state.bind).await?;
    info!("CLUSTER_INTERNAL_API: listening on {}", state.bind);

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(CONNECTION_TIMEOUT, handle_connection(stream, state)).await {
                Ok(Err(err)) => {
                    warn!(
                        "CLUSTER_INTERNAL_API: request from {} failed: {}",
                        peer, err
                    );
                }
                Err(_) => {
                    warn!(
                        "CLUSTER_INTERNAL_API: connection from {} timed out (slow loris guard)",
                        peer
                    );
                }
                Ok(Ok(())) => {}
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, state: InternalApiState) -> anyhow::Result<()> {
    let mut buffer = Vec::with_capacity(8192);
    let mut temp = [0_u8; 8192];
    let header_end;

    loop {
        let read = stream.read(&mut temp).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&temp[..read]);
        if buffer.len() > MAX_INTERNAL_BODY_BYTES + 8192 {
            write_response(&mut stream, 413, json!({"error":"request too large"})).await?;
            return Ok(());
        }
        if let Some(pos) = find_header_end(&buffer) {
            header_end = pos;
            break;
        }
    }

    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = headers.lines();
    let Some(request_line) = lines.next() else {
        write_response(&mut stream, 400, json!({"error":"bad request"})).await?;
        return Ok(());
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0_usize;
    let mut auth = String::new();
    let mut cluster_name = String::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => content_length = value.parse().unwrap_or(0),
            "authorization" => auth = value.to_string(),
            "x-cloud-node-cluster" => cluster_name = value.to_string(),
            _ => {}
        }
    }

    // The K8s kubelet probe cannot supply a Bearer token, so the health check
    // must be reachable without authentication. Other endpoints (purge, stats,
    // metadata) still require the token.
    if method == "GET" && path == "/internal/v1/health" {
        write_response(
            &mut stream,
            200,
            json!({"ok":true,"cluster":state.cluster_name}),
        )
        .await?;
        return Ok(());
    }

    if !authorized(&auth, &state.token) {
        write_response(&mut stream, 401, json!({"error":"unauthorized"})).await?;
        return Ok(());
    }
    if !cluster_name.is_empty() && cluster_name != state.cluster_name {
        write_response(&mut stream, 403, json!({"error":"cluster mismatch"})).await?;
        return Ok(());
    }
    if content_length > MAX_INTERNAL_BODY_BYTES {
        write_response(&mut stream, 413, json!({"error":"request too large"})).await?;
        return Ok(());
    }

    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let read = stream.read(&mut temp).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..read]);
    }
    let body = &buffer[body_start..buffer.len().min(body_start + content_length)];

    match (method.as_str(), path.as_str()) {
        // /internal/v1/health is handled above the auth check; this branch
        // would never run. Keeping it removed avoids dead-code drift.
        ("POST", "/internal/v1/purge") => {
            handle_purge(&mut stream, body).await?;
        }
        ("POST", "/internal/v1/metadata/events") => {
            handle_metadata_events(&mut stream, body).await?;
        }
        ("POST", "/internal/v1/stats/snapshot") => {
            handle_stats_snapshot(&mut stream, body).await?;
        }
        ("GET", "/internal/v1/cache/stat") => {
            let (count, size) = crate::metrics::storage::STORAGE.cache_summary();
            write_response(&mut stream, 200, json!({"count":count,"size":size})).await?;
        }
        _ => {
            write_response(&mut stream, 404, json!({"error":"not found"})).await?;
        }
    }

    Ok(())
}

async fn handle_purge(stream: &mut TcpStream, body: &[u8]) -> anyhow::Result<()> {
    let request: PurgeRequest = serde_json::from_slice(body)?;
    let key = request.key.trim();
    let prefix = request.prefix.trim();

    if crate::rpc::cache::is_tag_purge(&request.key_type) {
        if key.is_empty() {
            write_response(stream, 400, json!({"error":"tag key required"})).await?;
            return Ok(());
        }
        if !crate::cache_manager::CACHE.storage.purge_by_tag(key).await {
            write_response(stream, 500, json!({"error":"tag purge failed"})).await?;
            return Ok(());
        }
    } else if !prefix.is_empty() {
        if crate::rpc::cache::is_dangerous_purge_prefix(prefix) {
            write_response(stream, 400, json!({"error":"dangerous purge prefix"})).await?;
            return Ok(());
        }
        crate::cache_manager::CACHE.purge_prefix(prefix).await?;
    } else if !key.is_empty() {
        if crate::rpc::cache::is_prefix_purge(&request.key_type, key) {
            let prefix = crate::rpc::cache::normalize_purge_prefix(key);
            if crate::rpc::cache::is_dangerous_purge_prefix(&prefix) {
                write_response(stream, 400, json!({"error":"dangerous purge prefix"})).await?;
                return Ok(());
            }
            crate::cache_manager::CACHE.purge_prefix(&prefix).await?;
        } else {
            crate::cache_manager::CACHE.purge_key(key).await?;
        }
    } else {
        write_response(stream, 400, json!({"error":"key, tag or prefix required"})).await?;
        return Ok(());
    }

    write_response(stream, 200, json!({"ok":true})).await
}

async fn handle_metadata_events(stream: &mut TcpStream, body: &[u8]) -> anyhow::Result<()> {
    let events: Vec<crate::cluster::metadata::CacheMetaEvent> = serde_json::from_slice(body)?;
    let count = events.len();
    for event in events {
        crate::cluster::metadata::apply_remote_event(event);
    }
    write_response(stream, 200, json!({"ok":true,"count":count})).await
}

async fn handle_stats_snapshot(stream: &mut TcpStream, body: &[u8]) -> anyhow::Result<()> {
    if !crate::cluster::leader::is_leader() {
        write_response(stream, 409, json!({"error":"not leader"})).await?;
        return Ok(());
    }
    let snapshot: crate::cluster::stats::ReplicaStatsSnapshot = serde_json::from_slice(body)?;
    crate::cluster::stats::insert_snapshot(snapshot);
    let aggregated = crate::cluster::stats::aggregate();
    write_response(
        stream,
        200,
        json!({
            "ok": true,
            "replicas": aggregated.replica_count,
            "trafficOut": aggregated.traffic_out,
            "trafficIn": aggregated.traffic_in,
            "activeConnections": aggregated.active_connections,
        }),
    )
    .await
}

fn authorized(header: &str, token: &str) -> bool {
    header
        .strip_prefix("Bearer ")
        .map(|value| value == token)
        .unwrap_or(false)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: serde_json::Value,
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        _ => "Internal Server Error",
    };
    let body = body.to_string();
    let response = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        status,
        reason,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}
