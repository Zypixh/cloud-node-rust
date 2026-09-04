use http::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::path::{Component, Path};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

const MAX_INTERNAL_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_INTERNAL_HEADER_BYTES: usize = 16 * 1024;
const MAX_METADATA_EVENTS: usize = 256;
const MAX_METADATA_EVENT_STRING_BYTES: usize = 16 * 1024;
const MAX_METADATA_HEADERS: usize = 256;
const MAX_METADATA_HEADER_BYTES: usize = 64 * 1024;
const MAX_POD_NAME_BYTES: usize = 253;
const MAX_METADATA_OBJECT_BYTES: u64 = 1 << 40;
// Cap per-connection lifetime — a misbehaving / malicious peer that trickles
// one byte at a time must not be able to permanently occupy a Tokio task.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PURGE_ID_BYTES: usize = 256;

static APPLIED_PURGE_IDS: LazyLock<dashmap::DashMap<String, u64>> =
    LazyLock::new(dashmap::DashMap::new);

fn purge_request_is_duplicate(purge_id: &str) -> bool {
    APPLIED_PURGE_IDS.contains_key(purge_id)
}

#[derive(Debug, Deserialize)]
struct PurgeRequest {
    #[serde(default)]
    purge_id: String,
    #[serde(default)]
    key: String,
    #[serde(rename = "key_type", default)]
    key_type: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    version: u64,
    #[serde(default)]
    leader_epoch: u64,
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
    let token = token.trim().to_owned();
    if token.is_empty() {
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
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!("CLUSTER_INTERNAL_API: accept failed: {}", err);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(admission) = crate::memory_governor::MEMORY_GOVERNOR
            .try_admit(crate::memory_governor::AdmissionClass::ClusterInternalConnection)
        else {
            crate::pipeline_metrics::increment(
                crate::pipeline_metrics::PipelineCounter::InternalApiRejected,
            );
            let mut stream = stream;
            let _ = write_response(&mut stream, 503, json!({"error":"overloaded"})).await;
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _admission = admission;
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
        if find_header_end(&buffer).is_none() && buffer.len() > MAX_INTERNAL_HEADER_BYTES {
            write_response(
                &mut stream,
                431,
                json!({"error":"request headers too large"}),
            )
            .await?;
            return Ok(());
        }
        if buffer.len() > MAX_INTERNAL_BODY_BYTES + MAX_INTERNAL_HEADER_BYTES {
            write_response(&mut stream, 413, json!({"error":"request too large"})).await?;
            return Ok(());
        }
        if let Some(pos) = find_header_end(&buffer) {
            header_end = pos;
            break;
        }
    }

    let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = headers.split("\r\n");
    let Some(request_line) = lines.next() else {
        write_response(&mut stream, 400, json!({"error":"bad request"})).await?;
        return Ok(());
    };
    let request_parts: Vec<&str> = request_line.split_whitespace().collect();
    if request_parts.len() != 3 || request_parts[2] != "HTTP/1.1" {
        write_response(&mut stream, 400, json!({"error":"invalid request line"})).await?;
        return Ok(());
    }
    let method = request_parts[0].to_string();
    let path = request_parts[1].to_string();

    let mut content_length = None::<usize>;
    let mut auth = String::new();
    let mut cluster_name = String::new();
    let mut content_type = None::<String>;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            write_response(&mut stream, 400, json!({"error":"malformed header"})).await?;
            return Ok(());
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => {
                if content_length.is_some() {
                    write_response(
                        &mut stream,
                        400,
                        json!({"error":"duplicate content-length"}),
                    )
                    .await?;
                    return Ok(());
                }
                content_length = match value.parse() {
                    Ok(value) => Some(value),
                    Err(_) => {
                        write_response(&mut stream, 400, json!({"error":"invalid content-length"}))
                            .await?;
                        return Ok(());
                    }
                };
            }
            "transfer-encoding" => {
                write_response(
                    &mut stream,
                    400,
                    json!({"error":"transfer-encoding unsupported"}),
                )
                .await?;
                return Ok(());
            }
            "content-type" => content_type = Some(value.to_ascii_lowercase()),
            "authorization" => auth = value.to_string(),
            "x-cloud-node-cluster" => cluster_name = value.to_string(),
            _ => {}
        }
    }
    let content_length = content_length.unwrap_or(0);
    let body_start = header_end + 4;
    let buffered_body_bytes = buffer.len().saturating_sub(body_start);

    // The K8s kubelet probe cannot supply a Bearer token, so the health check
    // must be reachable without authentication. Other endpoints (purge, stats,
    // metadata) still require the token.
    if method == "GET" && path == "/internal/v1/health" {
        if content_length != 0 || buffered_body_bytes != 0 {
            write_response(
                &mut stream,
                400,
                json!({"error":"health request must not contain a body"}),
            )
            .await?;
            return Ok(());
        }
        write_response(&mut stream, 200, json!({"ok":true})).await?;
        return Ok(());
    }

    let bearer = auth.strip_prefix("Bearer ").unwrap_or_default();
    if !constant_time_eq(bearer.as_bytes(), state.token.as_bytes()) {
        write_response(&mut stream, 401, json!({"error":"unauthorized"})).await?;
        return Ok(());
    }
    if cluster_name.is_empty() || cluster_name != state.cluster_name {
        write_response(&mut stream, 403, json!({"error":"cluster mismatch"})).await?;
        return Ok(());
    }
    if method == "POST" {
        if content_length == 0 {
            write_response(&mut stream, 400, json!({"error":"content-length required"})).await?;
            return Ok(());
        }
        if content_type
            .as_deref()
            .is_none_or(|value| !is_json_content_type(value))
        {
            write_response(
                &mut stream,
                415,
                json!({"error":"application/json required"}),
            )
            .await?;
            return Ok(());
        }
    } else if content_length != 0 || buffered_body_bytes != 0 {
        write_response(
            &mut stream,
            400,
            json!({"error":"request method must not contain a body"}),
        )
        .await?;
        return Ok(());
    }
    if content_length > MAX_INTERNAL_BODY_BYTES {
        write_response(&mut stream, 413, json!({"error":"request too large"})).await?;
        return Ok(());
    }
    if buffered_body_bytes > content_length {
        write_response(
            &mut stream,
            400,
            json!({"error":"unexpected trailing request data"}),
        )
        .await?;
        return Ok(());
    }

    while buffer.len() < body_start + content_length {
        let read = stream.read(&mut temp).await?;
        if read == 0 {
            write_response(&mut stream, 400, json!({"error":"truncated request body"})).await?;
            return Ok(());
        }
        buffer.extend_from_slice(&temp[..read]);
    }
    if buffer.len() > body_start + content_length {
        write_response(
            &mut stream,
            400,
            json!({"error":"unexpected trailing request data"}),
        )
        .await?;
        return Ok(());
    }
    let body = &buffer[body_start..body_start + content_length];

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
    let request: PurgeRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            write_response(
                stream,
                400,
                json!({"error":format!("invalid purge request: {err}")}),
            )
            .await?;
            return Ok(());
        }
    };
    if request.purge_id.is_empty()
        || request.purge_id.len() > MAX_PURGE_ID_BYTES
        || request.leader_epoch == 0
    {
        write_response(
            stream,
            400,
            json!({"error":"purge_id and positive leader_epoch required"}),
        )
        .await?;
        return Ok(());
    }
    if request.leader_epoch < crate::cluster::leader::ROLE_STATE.epoch() {
        write_response(stream, 409, json!({"error":"stale leader epoch"})).await?;
        return Ok(());
    }
    if purge_request_is_duplicate(&request.purge_id) {
        write_response(stream, 200, json!({"ok":true,"duplicate":true})).await?;
        return Ok(());
    }
    let key = request.key.trim();
    let prefix = request.prefix.trim();

    if crate::rpc::cache::is_tag_purge(&request.key_type) {
        if key.is_empty() {
            write_response(stream, 400, json!({"error":"tag key required"})).await?;
            return Ok(());
        }
        let version = (request.version > 0).then_some(request.version);
        if !crate::cache_manager::CACHE
            .storage
            .purge_by_tag_at_version(key, version)
            .await
        {
            write_response(stream, 500, json!({"error":"tag purge failed"})).await?;
            return Ok(());
        }
    } else if !prefix.is_empty() {
        if crate::rpc::cache::is_dangerous_purge_prefix(prefix) {
            write_response(stream, 400, json!({"error":"dangerous purge prefix"})).await?;
            return Ok(());
        }
        let version = (request.version > 0).then_some(request.version);
        if !crate::cache_manager::CACHE
            .storage
            .purge_by_prefix_at_version(prefix, version)
            .await
        {
            write_response(stream, 500, json!({"error":"prefix purge failed"})).await?;
            return Ok(());
        }
    } else if !key.is_empty() {
        if crate::rpc::cache::is_prefix_purge(&request.key_type, key) {
            let prefix = crate::rpc::cache::normalize_purge_prefix(key);
            if crate::rpc::cache::is_dangerous_purge_prefix(&prefix) {
                write_response(stream, 400, json!({"error":"dangerous purge prefix"})).await?;
                return Ok(());
            }
            let version = (request.version > 0).then_some(request.version);
            if !crate::cache_manager::CACHE
                .storage
                .purge_by_prefix_at_version(&prefix, version)
                .await
            {
                write_response(stream, 500, json!({"error":"prefix purge failed"})).await?;
                return Ok(());
            }
        } else {
            let version = (request.version > 0).then_some(request.version);
            if !crate::cache_manager::CACHE
                .storage
                .purge_by_key_at_version(key, version)
                .await
            {
                write_response(stream, 500, json!({"error":"key purge failed"})).await?;
                return Ok(());
            }
        }
    } else {
        write_response(stream, 400, json!({"error":"key, tag or prefix required"})).await?;
        return Ok(());
    }

    APPLIED_PURGE_IDS.insert(request.purge_id, request.leader_epoch);
    write_response(stream, 200, json!({"ok":true})).await
}

async fn handle_metadata_events(stream: &mut TcpStream, body: &[u8]) -> anyhow::Result<()> {
    let events: Vec<crate::cluster::metadata::CacheMetaEvent> = match serde_json::from_slice(body) {
        Ok(events) => events,
        Err(err) => {
            write_response(
                stream,
                400,
                json!({"error":format!("invalid metadata events: {err}")}),
            )
            .await?;
            return Ok(());
        }
    };
    if events.len() > MAX_METADATA_EVENTS {
        write_response(stream, 413, json!({"error":"too many metadata events"})).await?;
        return Ok(());
    }
    for event in &events {
        if !valid_metadata_event(event) {
            write_response(
                stream,
                400,
                json!({"error":"metadata event exceeds field limits"}),
            )
            .await?;
            return Ok(());
        }
    }
    let count = events.len();
    for event in events {
        crate::cluster::metadata::apply_remote_event(event).await;
    }
    write_response(stream, 200, json!({"ok":true,"count":count})).await
}

fn valid_metadata_event(event: &crate::cluster::metadata::CacheMetaEvent) -> bool {
    if event.event_id.is_empty()
        || event.event_id.len() > MAX_METADATA_EVENT_STRING_BYTES
        || event.pod_name.is_empty()
        || event.pod_name.len() > MAX_POD_NAME_BYTES
        || event.cache_key.is_empty()
        || event.cache_key.len() > MAX_METADATA_EVENT_STRING_BYTES
        || event.cache_key.chars().any(char::is_control)
        || event.hash.len() != 32
        || !event.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        || event.hash != format!("{:x}", md5_legacy::compute(event.cache_key.as_bytes()))
        || event.version == 0
        || event.created_at <= 0
        || event.size > MAX_METADATA_OBJECT_BYTES
    {
        return false;
    }

    if event.pod_name.chars().any(char::is_control)
        || event.event_id.chars().any(char::is_control)
        || event.shard_id.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_METADATA_EVENT_STRING_BYTES
                || value.chars().any(char::is_control)
        })
        || event.relative_path.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_METADATA_EVENT_STRING_BYTES
                || !is_clean_relative_path(value)
        })
        || event.root_path.as_ref().is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_METADATA_EVENT_STRING_BYTES
                || !is_clean_absolute_path(value)
        })
    {
        return false;
    }

    match &event.event_type {
        crate::cluster::metadata::CacheMetaEventType::Upsert => {
            if !crate::cache::status_allows_full_cache_with_error_policy(
                event.status,
                event.error_status_allowed,
            ) || event.expires <= 0
            {
                return false;
            }
        }
        crate::cluster::metadata::CacheMetaEventType::Delete
        | crate::cluster::metadata::CacheMetaEventType::Purge => {}
    }

    valid_metadata_headers(&event.headers)
}

fn valid_metadata_headers(headers: &[(String, String)]) -> bool {
    if headers.len() > MAX_METADATA_HEADERS {
        return false;
    }
    let mut total_bytes = 0usize;
    let mut restored = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            return false;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            return false;
        };
        // Content-Length is intentionally omitted from most persisted full
        // object metadata and reconstructed from the body size.  HEAD
        // metadata is the exception: it has no body but must retain the
        // representation length.  HeaderMap also permits repeated fields
        // (including repeated Cache-Control); reject only fields that the
        // shared-cache policy itself rejects, not every duplicate name.
        let is_content_length = name.as_str().eq_ignore_ascii_case("content-length");
        if !crate::cache::should_store_response_header(name.as_str()) && !is_content_length {
            return false;
        }
        total_bytes = total_bytes
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .unwrap_or(MAX_METADATA_HEADER_BYTES.saturating_add(1));
        if total_bytes > MAX_METADATA_HEADER_BYTES {
            return false;
        }
        restored.append(name, value);
    }
    crate::cache::stored_response_headers_allow_shared_cache(headers)
}

fn is_clean_relative_path(value: &str) -> bool {
    Path::new(value).is_relative()
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_clean_absolute_path(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::RootDir))
        && components.all(|component| matches!(component, Component::Normal(_)))
}

async fn handle_stats_snapshot(stream: &mut TcpStream, body: &[u8]) -> anyhow::Result<()> {
    if !crate::cluster::leader::is_leader() {
        write_response(stream, 409, json!({"error":"not leader"})).await?;
        return Ok(());
    }
    let snapshot: crate::cluster::stats::ReplicaStatsSnapshot = match serde_json::from_slice(body) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            write_response(
                stream,
                400,
                json!({"error":format!("invalid stats snapshot: {err}")}),
            )
            .await?;
            return Ok(());
        }
    };
    if !valid_stats_snapshot(&snapshot) {
        write_response(
            stream,
            400,
            json!({"error":"invalid stats snapshot fields"}),
        )
        .await?;
        return Ok(());
    }
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

fn valid_stats_snapshot(snapshot: &crate::cluster::stats::ReplicaStatsSnapshot) -> bool {
    snapshot.pod_name.len() <= MAX_POD_NAME_BYTES
        && !snapshot.pod_name.is_empty()
        && snapshot.active_connections >= 0
        && snapshot.cpu_usage.is_finite()
        && (0.0..=1.0).contains(&snapshot.cpu_usage)
        && snapshot
            .created_at
            .abs_diff(crate::utils::time::now_timestamp())
            <= 60
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let compared_len = left.len().max(right.len());
    for index in 0..compared_len {
        let left_byte = left.get(index).copied().unwrap_or_default();
        let right_byte = right.get(index).copied().unwrap_or_default();
        difference |= usize::from(left_byte ^ right_byte);
    }
    difference == 0
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
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
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

#[cfg(test)]
mod tests {
    use super::valid_metadata_event;
    use crate::cluster::metadata::{CacheMetaEvent, CacheMetaEventType};

    fn event(event_type: CacheMetaEventType) -> CacheMetaEvent {
        let cache_key = "https://cache.example.test/item".to_string();
        let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
        CacheMetaEvent {
            event_id: "event-1".to_string(),
            event_type,
            pod_name: "cache-pod-1".to_string(),
            hash,
            cache_key,
            shard_id: None,
            relative_path: Some("ab/cdef".to_string()),
            root_path: Some("/var/lib/cloud-node/cache".to_string()),
            size: 42,
            expires: 2_000_000_000,
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            compressed: false,
            error_status_allowed: false,
            created_at: 1_900_000_000,
            version: 1,
            stale_while_revalidate_secs: 0,
            stale_if_error_secs: 0,
        }
    }

    #[test]
    fn metadata_event_validation_accepts_safe_upsert() {
        assert!(valid_metadata_event(&event(CacheMetaEventType::Upsert)));
    }

    #[test]
    fn metadata_event_validation_rejects_bad_identity_and_paths() {
        let mut bad_hash = event(CacheMetaEventType::Upsert);
        bad_hash.hash.replace_range(..1, "0");
        assert!(!valid_metadata_event(&bad_hash));

        let mut bad_path = event(CacheMetaEventType::Upsert);
        bad_path.root_path = Some("/var/lib/../etc".to_string());
        assert!(!valid_metadata_event(&bad_path));

        let mut bad_relative = event(CacheMetaEventType::Upsert);
        bad_relative.relative_path = Some("../outside".to_string());
        assert!(!valid_metadata_event(&bad_relative));
    }

    #[test]
    fn metadata_event_validation_rejects_unsafe_headers_and_conflicting_lengths() {
        let mut unsafe_header = event(CacheMetaEventType::Upsert);
        unsafe_header.headers = vec![("set-cookie".to_string(), "sid=1".to_string())];
        assert!(!valid_metadata_event(&unsafe_header));

        let mut conflicting_lengths = event(CacheMetaEventType::Upsert);
        conflicting_lengths.headers = vec![
            ("content-length".to_string(), "42".to_string()),
            ("Content-Length".to_string(), "43".to_string()),
        ];
        assert!(!valid_metadata_event(&conflicting_lengths));
    }

    #[test]
    fn metadata_event_validation_accepts_repeated_safe_headers_and_lengths() {
        let mut repeated = event(CacheMetaEventType::Upsert);
        repeated.headers = vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("cache-control".to_string(), "public".to_string()),
            ("Cache-Control".to_string(), "max-age=60".to_string()),
            ("content-length".to_string(), "42".to_string()),
            ("Content-Length".to_string(), "42".to_string()),
        ];
        assert!(valid_metadata_event(&repeated));
    }
}
