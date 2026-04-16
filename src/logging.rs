use crate::pb;
use crate::proxy::ProxyCTX;
use pingora_proxy::Session;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::error;

/// Global sender for access logs to be processed by LogUploader
static LOG_SENDER: OnceLock<mpsc::Sender<pb::HttpAccessLog>> = OnceLock::new();
static NODE_LOG_SENDER: OnceLock<mpsc::Sender<pb::NodeLog>> = OnceLock::new();
static NUMERIC_NODE_ID: AtomicI64 = AtomicI64::new(0);

/// Initializes the global log bus. Must be called once at startup.
pub fn init_global_log_bus(
    access_sender: mpsc::Sender<pb::HttpAccessLog>,
    node_sender: mpsc::Sender<pb::NodeLog>,
) {
    if LOG_SENDER.set(access_sender).is_err() {
        error!("LOG_SENDER was already initialized!");
    }
    if NODE_LOG_SENDER.set(node_sender).is_err() {
        error!("NODE_LOG_SENDER was already initialized!");
    }
}

pub fn set_numeric_node_id(id: i64) {
    NUMERIC_NODE_ID.store(id, Ordering::Relaxed);
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
        created_at: chrono::Utc::now().timestamp(),
        ..Default::default()
    };

    let _ = sender.try_send(log);
}

pub fn log_access(session: &Session, ctx: &ProxyCTX) {
    let sender = match LOG_SENDER.get() {
        Some(s) => s,
        None => return,
    };

    let req = session.req_header();
    let host = req
        .headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-");

    let request_time = ctx.start_time.elapsed().as_secs_f64();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let mut log = pb::HttpAccessLog {
        request_id: uuid::Uuid::new_v4().to_string(),
        server_id: ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
        node_id: 0,
        remote_addr: session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_default(),
        request_uri: req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string()),
        request_method: req.method.to_string(),
        request_length: 0,
        request_time,
        status: ctx.response_status as i32,
        bytes_sent: ctx.response_body_len as i64,
        host: host.to_string(),
        user_agent: session
            .get_header("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string(),
        referer: session
            .get_header("referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        timestamp: now.as_secs() as i64,
        msec: now.as_secs_f64(),
        origin_header_response_time: ctx
            .ttfb
            .map(|d: std::time::Duration| d.as_secs_f64())
            .unwrap_or(0.0),
        ..Default::default()
    };

    let client_ip = match session.client_addr() {
        Some(pingora_core::protocols::l4::socket::SocketAddr::Inet(addr)) => addr.ip(),
        _ => "127.0.0.1".parse().unwrap(),
    };
    crate::metrics::top_ip::TOP_IP_TRACKER.record(log.server_id, &client_ip.to_string());
    let analyzed = crate::metrics::analyzer::analyze_request(client_ip, &log.user_agent);

    // Enrich log when access log is enabled
    if let Some(web) = ctx.server.as_ref().and_then(|s| s.web.as_ref())
        && let Some(log_ref) = &web.access_log_ref
            && log_ref.is_on {
                // Request Headers
                let mut header_map = std::collections::HashMap::new();
                for (name, value) in req.headers.iter() {
                    let entry = header_map
                        .entry(name.to_string())
                        .or_insert(pb::Strings { values: vec![] });
                    entry.values.push(value.to_str().unwrap_or("").to_string());
                }
                log.header = header_map;

                // Response Headers
                let mut sent_header_map = std::collections::HashMap::new();
                for (name, value) in &ctx.response_headers {
                    sent_header_map.insert(
                        name.clone(),
                        pb::Strings {
                            values: vec![value.clone()],
                        },
                    );
                }
                log.sent_header = sent_header_map;

                // Query Args
                if let Some(query) = req.uri.query() {
                    log.args = query.to_string();
                    log.query_string = query.to_string();
                }

                // Cookies
                if let Some(cookie_hdr) = session.get_header("cookie") {
                    let mut cookies = std::collections::HashMap::new();
                    if let Ok(cookie_str) = cookie_hdr.to_str() {
                        for part in cookie_str.split(';') {
                            let part = part.trim();
                            let pieces: Vec<&str> = part.splitn(2, '=').collect();
                            if pieces.len() == 2 {
                                cookies.insert(pieces[0].to_string(), pieces[1].to_string());
                            }
                        }
                    }
                    log.cookie = cookies;
                }

                // Geo and Browser Analysis
                if let Some(geo) = &analyzed.geo {
                    log.attrs.insert("region".to_string(), geo.region.clone());
                    log.attrs.insert("city".to_string(), geo.city.clone());
                    log.attrs.insert("isp".to_string(), geo.provider.clone());
                    log.attrs.insert("country".to_string(), geo.country.clone());
                }
                log.attrs.insert("browser".to_string(), analyzed.browser.clone());
                log.attrs.insert("os".to_string(), analyzed.os.clone());

                // Request Body
                if !ctx.request_body.is_empty() {
                    log.request_body = ctx.request_body.clone();
                }
            }

    // Add WAF tags
    if let Some(action) = &ctx.waf_action {
        log.firewall_actions.push(format!("{:?}", action));
    }

    // Add Cache status
    if ctx.cache_hit.unwrap_or(false) {
        log.tags.push("CACHE_HIT".to_string());
    }

    crate::metrics::aggregator::AGGREGATOR.record(
        crate::metrics::aggregator::AggregationKey {
            server_id: log.server_id,
            country: analyzed
                .geo
                .as_ref()
                .map(|g| g.country.clone())
                .unwrap_or_default(),
            country_id: analyzed.geo.as_ref().map(|g| g.country_id).unwrap_or(0),
            province: analyzed
                .geo
                .as_ref()
                .map(|g| g.region.clone())
                .unwrap_or_default(),
            province_id: analyzed.geo.as_ref().map(|g| g.region_id).unwrap_or(0),
            city: analyzed
                .geo
                .as_ref()
                .map(|g| g.city.clone())
                .unwrap_or_default(),
            city_id: analyzed.geo.as_ref().map(|g| g.city_id).unwrap_or(0),
            provider: analyzed
                .geo
                .as_ref()
                .map(|g| g.provider.clone())
                .unwrap_or_default(),
            browser: analyzed.browser.clone(),
            os: analyzed.os.clone(),
            waf_group_id: ctx.waf_group_id,
            waf_action: ctx
                .waf_action
                .as_ref()
                .map(|a| a.to_string())
                .unwrap_or_default(),
        },
        log.bytes_sent,
        ctx.waf_action.is_some(),
    );

    if let Err(_e) = sender.try_send(log) {
        // Log drop occurred
    }
}
