use crate::pb;
use crate::config_models::ServerConfig;
use crate::proxy::ProxyCTX;
use pingora_proxy::Session;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use once_cell::sync::OnceCell;
use chrono::{DateTime, FixedOffset};

static LOG_SENDER: OnceCell<mpsc::Sender<pb::HttpAccessLog>> = OnceCell::new();
static NODE_LOG_SENDER: OnceCell<mpsc::Sender<pb::NodeLog>> = OnceCell::new();
static NUMERIC_NODE_ID: AtomicI64 = AtomicI64::new(0);
static ATOMIC_REQUEST_ID: AtomicI64 = AtomicI64::new(100000);
static ATOMIC_REQUEST_TIMESTAMP: AtomicI64 = AtomicI64::new(0);

pub fn init_global_log_bus(
    access_sender: mpsc::Sender<pb::HttpAccessLog>,
    node_sender: mpsc::Sender<pb::NodeLog>,
) {
    let _ = LOG_SENDER.set(access_sender);
    let _ = NODE_LOG_SENDER.set(node_sender);
}

pub fn set_numeric_node_id(id: i64) {
    NUMERIC_NODE_ID.store(id, Ordering::Relaxed);
}

pub fn next_request_id() -> String {
    // CRITICAL: Use seconds instead of millis to prevent 20-digit overflow in API Node's int64 parsers
    let now = crate::utils::time::now_timestamp();
    let last_ts = ATOMIC_REQUEST_TIMESTAMP.load(Ordering::Relaxed);

    if now > last_ts {
        ATOMIC_REQUEST_ID.store(100000, Ordering::Relaxed);
        ATOMIC_REQUEST_TIMESTAMP.store(now, Ordering::Relaxed);
    }

    let counter = ATOMIC_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let node_id = NUMERIC_NODE_ID.load(Ordering::Relaxed);

    // This generates a 17-18 digit string: [10-digit TS][2-digit Node][6-digit Counter]
    // Example: 1776441600 11 100001 -> fits in int64!
    format!("{}{}{}", now, node_id, counter)
}

pub fn report_node_log(level: &str, tag: &str, message: &str, server_id: i64) {
    let sender = match NODE_LOG_SENDER.get() {
        Some(s) => s,
        None => return,
    };

    let log = pb::NodeLog {
        level: level.to_string(),
        tag: tag.to_string(),
        description: message.to_string(),
        role: "node".to_string(),
        node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
        server_id,
        created_at: crate::utils::time::now_timestamp(),
        ..Default::default()
    };

    let _ = sender.try_send(log);
}

pub fn log_access(session: &Session, ctx: &ProxyCTX) {
    if ctx.no_log {
        return;
    }
    let sender = match LOG_SENDER.get() {
        Some(s) => s,
        None => return,
    };

    let req = session.req_header();
    let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);
    
    let host = req.headers.get("host")
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

    let request_line = format!("{} {} {}", req.method, req.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"), proto);

    // Precise calculation for GoEdge compatibility
    let req_hdr_size = req.headers.iter().map(|(n, v)| n.as_str().len() + v.len() + 4).sum::<usize>() as i64 + request_line.len() as i64 + 4;
    let bytes_received = session.body_bytes_read() as i64 + req_hdr_size;
    let bytes_sent = session.body_bytes_sent() as i64 + ctx.response_headers_size as i64 + 20;

    // Real IP resolution
    let raw_socket_addr = if ctx.raw_remote_addr.is_empty() {
        session.client_addr().map(|a| a.to_string()).unwrap_or_default()
    } else {
        ctx.raw_remote_addr.clone()
    };
    let real_ip_str = ctx.client_ip.to_string();

    let client_ip = real_ip_str.parse::<IpAddr>().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let user_agent = req.headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("-");
    let analyzed = crate::metrics::analyzer::analyze_request(client_ip, user_agent);
    let request_started_at_millis = ctx.start_timestamp_millis;
    let request_started_at = request_started_at_millis / 1000;
    let request_started_local: DateTime<FixedOffset> =
        crate::utils::time::local_from_timestamp_millis(request_started_at_millis);

    let is_cached = ctx.cache_hit.unwrap_or(false);
    let final_request_line = if is_cached {
        format!("[cache hit] {}", request_line)
    } else {
        request_line
    };

    let mut log = pb::HttpAccessLog {
        request_id: ctx.request_id.clone(),
        server_id,
        node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
        remote_addr: real_ip_str,
        raw_remote_addr: raw_socket_addr,
        remote_port: ctx.client_port as i32,
        request_uri: req.uri.path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_else(|| "/".to_string()),
        request_path: req.uri.path().to_string(),
        request_method: req.method.to_string(),
        request_length: bytes_received,
        request_time: ctx.start_time.elapsed().as_secs_f64(),
        scheme: scheme.clone(),
        proto: proto.to_string(),
        status: ctx.response_status as i32,
        status_message: String::new(),
        bytes_sent,
        body_bytes_sent: session.body_bytes_sent() as i64,
        host: host.to_string(),
        user_agent: user_agent.to_string(),
        referer: req.headers.get("referer").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
        request: final_request_line,
        timestamp: request_started_at,
        msec: request_started_at_millis as f64 / 1000.0,
        time_iso8601: request_started_local.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string(),
        time_local: request_started_local.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
        hostname: hostname::get().unwrap_or_default().to_string_lossy().to_string(),
        origin_address: ctx.origin_address.clone(),
        origin_status: ctx.origin_status,
        origin_header_response_time: ctx.ttfb.map(|d| d.as_secs_f64()).unwrap_or(0.0),
        cache_hit: is_cached,
        ..Default::default()
    };

    // Correcting Prost field mappings
    let mut req_headers = HashMap::new();
    for (n, v) in req.headers.iter() {
        req_headers.entry(n.to_string()).or_insert(pb::Strings { values: vec![] }).values.push(v.to_str().unwrap_or("").to_string());
    }
    log.header = req_headers;

    let mut res_headers = HashMap::new();
    for (n, v) in &ctx.response_headers {
        res_headers.insert(n.clone(), pb::Strings { values: vec![v.clone()] });
    }
    log.sent_header = res_headers;

    if let Some((_, ct)) = ctx.response_headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")) {
        log.content_type = ct.clone();
    }

    if let Some(query) = req.uri.query() {
        log.args = query.to_string();
        log.query_string = query.to_string();
    }

    if let Some(server) = &ctx.server {
        log.server_name = server.server_names.first().map(|s| s.name.clone()).unwrap_or_default();
        log.server_port = req.uri.port_u16().unwrap_or(if log.scheme == "https" { 443 } else { 80 }) as i32;
    }

    // Populate Attrs for GeoIP display in GoEdge
    if let Some(geo) = &analyzed.geo {
        log.attrs.insert("region".to_string(), geo.region.clone());
        log.attrs.insert("city".to_string(), geo.city.clone());
        log.attrs.insert("isp".to_string(), geo.provider.clone());
        log.attrs.insert("country".to_string(), geo.country.clone());
    }
    log.attrs.insert("browser".to_string(), analyzed.browser.clone());
    log.attrs.insert("os".to_string(), analyzed.os.clone());
    if ctx.is_http3_bridge {
        log.attrs.insert("transport".to_string(), "http3".to_string());
        log.tags.push("HTTP3".to_string());
    }
    if let Some(cache_status) = ctx
        .response_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-cache"))
        .map(|(_, v)| v.clone())
    {
        log.attrs
            .insert("cacheStatus".to_string(), cache_status.clone());
        log.tags.push(format!("X_CACHE_{}", cache_status));
    }

    if ctx.cache_hit.unwrap_or(false) { log.tags.push("CACHE_HIT".to_string()); }
    if let Some(waf) = &ctx.waf_action { 
        log.firewall_actions.push(waf.clone());
        log.firewall_policy_id = ctx.waf_policy_id;
    }

    if server_id == 0 {
        warn!("Generated log for unconfigured host '{}', skipping report to API.", host);
    } else {
        debug!("Reporting log: {} {} -> Status {}", log.request_method, log.request_uri, log.status);
        let _ = sender.try_send(log);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn log_sni_passthrough_access(
    request_id: String,
    server: &ServerConfig,
    sni_host: &str,
    client_addr: SocketAddr,
    listen_port: u16,
    origin_address: &str,
    request_started_at_millis: i64,
    request_time: Duration,
    bytes_received: u64,
    bytes_sent: u64,
    status: i32,
    error: Option<&str>,
) {
    let sender = match LOG_SENDER.get() {
        Some(s) => s,
        None => return,
    };

    let server_id = server.numeric_id();
    if server_id == 0 {
        warn!(
            "Generated SNI passthrough log for unconfigured host '{}', skipping report to API.",
            sni_host
        );
        return;
    }

    let request_started_at = request_started_at_millis / 1000;
    let request_started_local: DateTime<FixedOffset> =
        crate::utils::time::local_from_timestamp_millis(request_started_at_millis);
    let request = format!("SNI {} TLS", sni_host);
    let mut log = pb::HttpAccessLog {
        request_id,
        server_id,
        node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
        remote_addr: client_addr.ip().to_string(),
        raw_remote_addr: client_addr.to_string(),
        remote_port: client_addr.port() as i32,
        request_uri: sni_host.to_string(),
        request_path: String::new(),
        request_method: "SNI".to_string(),
        request_length: bytes_received as i64,
        request_time: request_time.as_secs_f64(),
        scheme: "tls".to_string(),
        proto: "TLS".to_string(),
        status,
        status_message: String::new(),
        bytes_sent: bytes_sent as i64,
        body_bytes_sent: bytes_sent as i64,
        host: sni_host.to_string(),
        user_agent: "-".to_string(),
        referer: String::new(),
        request,
        timestamp: request_started_at,
        msec: request_started_at_millis as f64 / 1000.0,
        time_iso8601: request_started_local.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string(),
        time_local: request_started_local.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
        hostname: hostname::get().unwrap_or_default().to_string_lossy().to_string(),
        origin_address: origin_address.to_string(),
        origin_status: status,
        server_name: server.server_names.first().map(|s| s.name.clone()).unwrap_or_default(),
        server_port: listen_port as i32,
        server_protocol: "SNI_PASSTHROUGH".to_string(),
        ..Default::default()
    };

    log.attrs.insert("transport".to_string(), "tcp".to_string());
    log.attrs.insert("protocol".to_string(), "sni_passthrough".to_string());
    if !origin_address.is_empty() {
        log.attrs.insert("backend".to_string(), origin_address.to_string());
    }
    log.tags.push("SNI_PASSTHROUGH".to_string());
    if let Some(error) = error.filter(|value| !value.is_empty()) {
        log.errors.push(error.to_string());
    }

    debug!("Reporting SNI passthrough log: {} -> Status {}", log.request_uri, log.status);
    let _ = sender.try_send(log);
}
