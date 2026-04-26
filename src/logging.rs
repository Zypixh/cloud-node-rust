use crate::config_models::ServerConfig;
use crate::pb;
use crate::proxy::ProxyCTX;
use once_cell::sync::OnceCell;
use pingora_proxy::Session;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::debug;

pub static LOG_SENDER: OnceCell<mpsc::Sender<pb::HttpAccessLog>> = OnceCell::new();
pub static NODE_LOG_SENDER: OnceCell<mpsc::Sender<pb::NodeLog>> = OnceCell::new();
static NUMERIC_NODE_ID: AtomicI64 = AtomicI64::new(0);
static REQUEST_ID_TIMESTAMP: AtomicI64 = AtomicI64::new(0);
static REQUEST_ID_COUNTER: AtomicI32 = AtomicI32::new(1_000_000);

pub fn init_global_log_bus(sender: mpsc::Sender<pb::HttpAccessLog>, node_sender: mpsc::Sender<pb::NodeLog>) {
    let _ = LOG_SENDER.set(sender);
    let _ = NODE_LOG_SENDER.set(node_sender);
}

pub fn set_numeric_node_id(id: i64) {
    NUMERIC_NODE_ID.store(id, Ordering::Relaxed);
}

pub fn next_request_id() -> String {
    let now = crate::utils::time::now_timestamp_millis();
    let prev = REQUEST_ID_TIMESTAMP.swap(now, Ordering::AcqRel);
    if now > prev {
        REQUEST_ID_COUNTER.store(1_000_000, Ordering::Release);
    }
    let counter = REQUEST_ID_COUNTER.fetch_add(1, Ordering::AcqRel);
    let node_id = NUMERIC_NODE_ID.load(Ordering::Relaxed);
    format!("{now}{node_id}{counter}")
}

pub fn report_node_log(level: String, tag: String, message: String, server_id: i64) {
    if let Some(sender) = NODE_LOG_SENDER.get() {
        let log = pb::NodeLog {
            level,
            tag,
            description: message,
            server_id,
            node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
            created_at: crate::utils::time::now_timestamp(),
            ..Default::default()
        };
        let _ = sender.try_send(log);
    }
}

pub fn log_access(session: &Session, ctx: &ProxyCTX) {
    if ctx.no_log {
        return;
    }
    let sender = match LOG_SENDER.get() {
        Some(s) => s,
        None => return,
    };

    if sender.capacity() == 0 {
        return;
    }

    let req = session.req_header();
    let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);

    let host = req
        .headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|v| v.split(':').next().unwrap_or(v))
        .unwrap_or_else(|| req.uri.host().unwrap_or("-"));

    let proto = if ctx.is_http3_bridge {
        "HTTP/3.0"
    } else {
        match req.version {
            pingora::http::Version::HTTP_10 => "HTTP/1.0",
            pingora::http::Version::HTTP_11 => "HTTP/1.1",
            pingora::http::Version::HTTP_2 => "HTTP/2.0",
            pingora::http::Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        }
    };

    let bytes_received = session.body_bytes_read() as i64 + 500;
    let bytes_sent = session.body_bytes_sent() as i64 + ctx.response_headers_size as i64 + 20;

    let request_started_at_millis = ctx.start_timestamp_millis;
    let request_started_at = request_started_at_millis / 1000;

    let is_tls = session
        .downstream_session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some();
    let scheme = if is_tls || req.uri.scheme_str() == Some("https") {
        "https"
    } else {
        "http"
    };

    let is_cached = ctx.cache_hit.unwrap_or(false);

    let mut log = pb::HttpAccessLog {
        request_id: ctx.request_id.clone(),
        server_id,
        node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
        remote_addr: ctx.client_ip_str.clone(),
        raw_remote_addr: if ctx.raw_remote_addr.is_empty() { ctx.client_ip_str.clone() } else { ctx.raw_remote_addr.clone() },
        remote_port: ctx.client_port as i32,
        request_uri: req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string()),
        request_path: req.uri.path().to_string(),
        request_method: req.method.to_string(),
        request_length: bytes_received,
        request_time: ctx.start_time.elapsed().as_secs_f64(),
        scheme: scheme.to_string(),
        proto: proto.to_string(),
        status: ctx.response_status as i32,
        bytes_sent,
        body_bytes_sent: session.body_bytes_sent() as i64,
        host: host.to_string(),
        user_agent: req.headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("-").to_string(),
        referer: req
            .headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        timestamp: request_started_at,
        msec: request_started_at_millis as f64 / 1000.0,
        hostname: hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        origin_address: ctx.origin_address.clone(),
        origin_status: ctx.origin_status,
        origin_header_response_time: ctx.ttfb.map(|d| d.as_secs_f64()).unwrap_or(0.0),
        ..Default::default()
    };

    if let Some(analyzed) = &ctx.analyzed {
        if let Some(geo) = &analyzed.geo {
            log.attrs.insert("region".to_string(), geo.region.to_string());
            log.attrs.insert("city".to_string(), geo.city.to_string());
            log.attrs.insert("isp".to_string(), geo.provider.to_string());
            log.attrs.insert("country".to_string(), geo.country.to_string());
        }
        log.attrs.insert("browser".to_string(), analyzed.browser.to_string());
        log.attrs.insert("os".to_string(), analyzed.os.to_string());
    }

    if is_cached {
        log.tags.push("CACHE_HIT".to_string());
    }
    if let Some(waf) = &ctx.waf_action {
        log.firewall_actions.push(waf.clone());
        log.firewall_policy_id = ctx.waf_policy_id;
    }

    let _ = sender.try_send(log);
}

#[allow(clippy::too_many_arguments)]
pub fn log_sni_passthrough_access(
    request_id: String,
    server: &Arc<ServerConfig>,
    sni_host: &str,
    client_addr: SocketAddr,
    listen_port: u16,
    backend_addr: &str,
    started_at_millis: i64,
    duration: Duration,
    bytes_received: u64,
    bytes_sent: u64,
    status: i32,
    error: Option<&str>,
) {
    let sender = match LOG_SENDER.get() {
        Some(s) => s,
        None => return,
    };

    let server_id = server.id.unwrap_or(0);
    let request_started_at = started_at_millis / 1000;

    let mut log = pb::HttpAccessLog {
        request_id,
        server_id,
        node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
        remote_addr: client_addr.ip().to_string(),
        raw_remote_addr: client_addr.ip().to_string(),
        remote_port: client_addr.port() as i32,
        request_uri: format!("https://{}/", sni_host),
        request_path: "/".to_string(),
        request_method: "CONNECT".to_string(),
        request_length: bytes_received as i64,
        request_time: duration.as_secs_f64(),
        scheme: "https".to_string(),
        proto: "TCP".to_string(),
        status,
        bytes_sent: bytes_sent as i64,
        body_bytes_sent: bytes_sent as i64,
        host: sni_host.to_string(),
        timestamp: request_started_at,
        msec: started_at_millis as f64 / 1000.0,
        hostname: hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        origin_address: backend_addr.to_string(),
        origin_status: status,
        server_port: listen_port as i32,
        ..Default::default()
    };

    if let Some(error) = error.filter(|value| !value.is_empty()) {
        log.errors.push(error.to_string());
    }

    debug!(
        "Reporting SNI passthrough log: {} -> Status {}",
        log.request_uri, log.status
    );
    let _ = sender.try_send(log);
}
