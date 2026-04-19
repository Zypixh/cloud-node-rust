use crate::pb;
use crate::proxy::ProxyCTX;
use pingora_proxy::Session;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use once_cell::sync::OnceCell;

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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
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
        created_at: crate::utils::time::now_utc().timestamp(),
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

    let proto = match req.version {
        pingora::http::Version::HTTP_10 => "HTTP/1.0",
        pingora::http::Version::HTTP_11 => "HTTP/1.1",
        pingora::http::Version::HTTP_2 => "HTTP/2.0",
        pingora::http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    };

    let request_line = format!("{} {} {}", req.method, req.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"), proto);

    // Precise calculation for GoEdge compatibility
    let req_hdr_size = req.headers.iter().map(|(n, v)| n.as_str().len() + v.len() + 4).sum::<usize>() as i64 + request_line.len() as i64 + 4;
    let bytes_received = session.body_bytes_read() as i64 + req_hdr_size;
    let bytes_sent = session.body_bytes_sent() as i64 + ctx.response_headers_size as i64 + 20;

    // Real IP resolution
    let raw_socket_addr = session.client_addr().map(|a| a.to_string()).unwrap_or_default();
    let mut real_ip_str = raw_socket_addr.split(':').next().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_string();
    
    if let Some(xff) = session.get_header("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() { real_ip_str = first.trim().to_string(); }
    } else if let Some(rip) = session.get_header("x-real-ip").and_then(|v| v.to_str().ok()) {
        real_ip_str = rip.trim().to_string();
    }

    let client_ip = real_ip_str.parse::<IpAddr>().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let user_agent = req.headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("-");
    let analyzed = crate::metrics::analyzer::analyze_request(client_ip, user_agent);

        let is_tls = session.downstream_session.digest().and_then(|d| d.ssl_digest.as_ref()).is_some();
        let scheme = if is_tls || req.uri.scheme_str() == Some("https") { "https".to_string() } else { "http".to_string() };
        
        let mut log = pb::HttpAccessLog {
            request_id: ctx.request_id.clone(),
            server_id,
            node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
            remote_addr: real_ip_str,
            raw_remote_addr: raw_socket_addr.split(':').next().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_string(),
            remote_port: match session.client_addr() { Some(pingora_core::protocols::l4::socket::SocketAddr::Inet(addr)) => addr.port() as i32, _ => 0 },
            request_uri: req.uri.path_and_query().map(|pq| pq.as_str().to_string()).unwrap_or_else(|| "/".to_string()),
            request_path: req.uri.path().to_string(),
            request_method: req.method.to_string(),
            request_length: bytes_received,
            request_time: ctx.start_time.elapsed().as_secs_f64(),
            scheme: scheme.clone(),
            proto: proto.to_string(),
        status: ctx.response_status as i32,
        status_message: http::StatusCode::from_u16(ctx.response_status).map(|s| s.canonical_reason().unwrap_or("")).unwrap_or("").to_string(),
        bytes_sent,
        body_bytes_sent: session.body_bytes_sent() as i64,
        host: host.to_string(),
        user_agent: user_agent.to_string(),
        referer: req.headers.get("referer").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(),
        request: request_line,
        timestamp: crate::utils::time::now_utc().timestamp(),
        msec: crate::utils::time::now_utc().timestamp_millis() as f64 / 1000.0,
        time_iso8601: crate::utils::time::now_local().format("%Y-%m-%dT%H:%M:%S.000%:z").to_string(),
        time_local: crate::utils::time::now_local().format("%d/%b/%Y:%H:%M:%S %z").to_string(),
        hostname: hostname::get().unwrap_or_default().to_string_lossy().to_string(),
        origin_address: ctx.origin_address.clone(),
        origin_status: ctx.origin_status,
        origin_header_response_time: ctx.ttfb.map(|d| d.as_secs_f64()).unwrap_or(0.0),
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
