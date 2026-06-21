use crate::config_models::ServerConfig;
use crate::pb;
use crate::proxy::ProxyCTX;
use base64::Engine as _;
use base64::engine::general_purpose;
use pingora_proxy::Session;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, Ordering};
use std::sync::{LazyLock as Lazy, OnceLock as OnceCell};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::debug;

pub struct AccessLogHandle {
    sender: mpsc::Sender<pb::HttpAccessLog>,
    queue_capacity: usize,
    warning_interval_ms: u64,
    dropped_since_warning: AtomicU64,
    last_warning_at_ms: AtomicI64,
}

impl AccessLogHandle {
    fn new(
        sender: mpsc::Sender<pb::HttpAccessLog>,
        queue_capacity: usize,
        warning_interval: Duration,
    ) -> Self {
        Self {
            sender,
            queue_capacity,
            warning_interval_ms: warning_interval.as_millis().min(u64::MAX as u128) as u64,
            dropped_since_warning: AtomicU64::new(0),
            last_warning_at_ms: AtomicI64::new(0),
        }
    }

    fn try_enqueue(&self, log: pb::HttpAccessLog, kind: &str) {
        if let Err(err) = self.sender.try_send(log) {
            self.dropped_since_warning.fetch_add(1, Ordering::Relaxed);
            let now = unix_epoch_millis_now();
            let last = self.last_warning_at_ms.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= self.warning_interval_ms as i64
                && self
                    .last_warning_at_ms
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                let dropped = self.dropped_since_warning.swap(0, Ordering::Relaxed);
                tracing::warn!(
                    "ACCESS_LOG: queue saturated kind={} dropped={} queue_capacity={} available_capacity={} error={}",
                    kind,
                    dropped,
                    self.queue_capacity,
                    self.sender.capacity(),
                    err
                );
            }
        }
    }
}

pub static LOG_SENDER: OnceCell<AccessLogHandle> = OnceCell::new();

static CACHED_HOSTNAME: Lazy<String> = Lazy::new(|| {
    hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
});
pub static NODE_LOG_SENDER: OnceCell<mpsc::Sender<pb::NodeLog>> = OnceCell::new();
static NUMERIC_NODE_ID: AtomicI64 = AtomicI64::new(0);
static GLOBAL_ACCESS_LOG_ON: AtomicBool = AtomicBool::new(true);
static REQUEST_ID_TIMESTAMP: AtomicI64 = AtomicI64::new(0);
static REQUEST_ID_COUNTER: AtomicI32 = AtomicI32::new(1_000_000);
pub fn init_global_log_bus(
    sender: mpsc::Sender<pb::HttpAccessLog>,
    node_sender: mpsc::Sender<pb::NodeLog>,
    queue_capacity: usize,
    warning_interval: Duration,
) {
    let _ = LOG_SENDER.set(AccessLogHandle::new(
        sender,
        queue_capacity,
        warning_interval,
    ));
    let _ = NODE_LOG_SENDER.set(node_sender);
}

pub fn set_numeric_node_id(id: i64) {
    NUMERIC_NODE_ID.store(id, Ordering::Relaxed);
}

pub fn get_numeric_node_id() -> i64 {
    NUMERIC_NODE_ID.load(Ordering::Relaxed)
}

pub fn set_global_access_log_on(is_on: bool) {
    GLOBAL_ACCESS_LOG_ON.store(is_on, Ordering::Relaxed);
}

fn unix_epoch_millis_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

fn access_log_started_at_millis(duration: Duration) -> i64 {
    unix_epoch_millis_now().saturating_sub(duration.as_millis().min(i64::MAX as u128) as i64)
}

pub fn next_request_id() -> String {
    let now = crate::utils::time::system_timestamp_millis();
    let prev = REQUEST_ID_TIMESTAMP.swap(now, Ordering::AcqRel);
    if now > prev {
        REQUEST_ID_COUNTER.store(1_000_000, Ordering::Release);
    }
    let counter = REQUEST_ID_COUNTER.fetch_add(1, Ordering::AcqRel);
    let node_id = NUMERIC_NODE_ID.load(Ordering::Relaxed);
    format!("{now}{node_id}{counter}")
}

const ACCESS_LOG_FIELD_MAX: usize = 53;

#[derive(Clone, Copy)]
struct AccessLogFieldMask {
    enabled: [bool; ACCESS_LOG_FIELD_MAX + 1],
}

impl AccessLogFieldMask {
    fn from_fields(fields: &[i32]) -> Self {
        let mut enabled = [false; ACCESS_LOG_FIELD_MAX + 1];
        for &field in fields {
            if field > 0 && (field as usize) <= ACCESS_LOG_FIELD_MAX {
                enabled[field as usize] = true;
            }
        }
        Self { enabled }
    }

    fn enabled(&self, field: i32) -> bool {
        field > 0 && (field as usize) <= ACCESS_LOG_FIELD_MAX && self.enabled[field as usize]
    }
}

fn access_log_field_enabled(fields: Option<&AccessLogFieldMask>, field: i32) -> bool {
    fields.is_none_or(|fields| fields.enabled(field))
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

pub fn access_log_needs_attrs(ctx: &ProxyCTX) -> bool {
    if !ctx.access_log_module_enabled || ctx.no_log || !ctx.global_access_log_on {
        return false;
    }
    if ctx
        .access_log_ref
        .as_ref()
        .is_some_and(|access_log| !access_log.is_on)
    {
        return false;
    }
    ctx.access_log_ref
        .as_ref()
        .map(|access_log| access_log.fields.is_empty() || access_log.fields.contains(&43))
        .unwrap_or(true)
}

pub fn log_access(session: &Session, ctx: &ProxyCTX) {
    if !ctx.access_log_module_enabled {
        debug!("ACCESS_LOG: blocked by access_log_module_enabled=false");
        return;
    }
    if ctx.no_log {
        debug!("ACCESS_LOG: blocked by no_log=true");
        return;
    }
    if let Some(ref access_log) = ctx.access_log_ref {
        if !access_log.is_on {
            debug!("ACCESS_LOG: blocked by per-server access_log_ref.is_on=false");
            return;
        }
    }
    if !ctx.global_access_log_on {
        debug!("ACCESS_LOG: blocked by global_access_log_on=false");
        return;
    }
    if ctx.server.is_none() {
        if let Some(ref cfg) = ctx.global_access_log_config {
            if !cfg.enable_server_not_found {
                debug!("ACCESS_LOG: blocked by enable_server_not_found=false (404)");
                return;
            }
        }
    }
    if let Some(ref cfg) = ctx.global_access_log_config {
        if cfg.firewall_only && !ctx.firewall_blocked {
            debug!("ACCESS_LOG: blocked by firewall_only=true (non-firewall request)");
            return;
        }
        if !cfg.enable_client_closed && ctx.response_status == 499 {
            debug!("ACCESS_LOG: blocked by enable_client_closed=false (499)");
            return;
        }
    }
    let sender = match LOG_SENDER.get() {
        Some(s) => s,
        None => {
            debug!("ACCESS_LOG: blocked by LOG_SENDER not initialized");
            return;
        }
    };

    let field_mask = ctx
        .access_log_ref
        .as_ref()
        .filter(|access_log| !access_log.fields.is_empty())
        .map(|access_log| AccessLogFieldMask::from_fields(&access_log.fields));
    let fields = field_mask.as_ref();
    let (log_cookies, log_req_headers, log_resp_headers, common_req_headers_only) =
        if let Some(ref cfg) = ctx.global_access_log_config {
            (
                cfg.enable_cookies && access_log_field_enabled(fields, 32),
                cfg.enable_request_headers && access_log_field_enabled(fields, 36),
                cfg.enable_response_headers && access_log_field_enabled(fields, 22),
                cfg.common_request_headers_only,
            )
        } else {
            (
                access_log_field_enabled(fields, 32),
                access_log_field_enabled(fields, 36),
                access_log_field_enabled(fields, 22),
                false,
            )
        };
    let log_request_body = access_log_field_enabled(fields, 51);
    let log_time_iso8601 = access_log_field_enabled(fields, 23);
    let log_time_local = access_log_field_enabled(fields, 24);
    let log_remote_user = access_log_field_enabled(fields, 9);
    let log_request_uri = access_log_field_enabled(fields, 10);
    let log_request_path = access_log_field_enabled(fields, 11);
    let log_request_method = access_log_field_enabled(fields, 14);
    let log_request_filename = access_log_field_enabled(fields, 15);
    let log_request_line = access_log_field_enabled(fields, 30);
    let log_content_type = access_log_field_enabled(fields, 31);
    let log_args = access_log_field_enabled(fields, 34);
    let log_query_string = access_log_field_enabled(fields, 35);
    let log_server_name = access_log_field_enabled(fields, 37);
    let log_hostname = access_log_field_enabled(fields, 40);
    let log_origin_address = access_log_field_enabled(fields, 41);
    let log_errors = access_log_field_enabled(fields, 42);
    let log_attrs = access_log_field_enabled(fields, 43);
    let log_firewall_actions = access_log_field_enabled(fields, 49);
    let log_tags = access_log_field_enabled(fields, 50);

    let req = session.req_header();
    let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);

    let host = req
        .headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            req.headers
                .get(":authority")
                .and_then(|h| h.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .or_else(|| req.uri.authority().map(|value| value.as_str()))
        .or_else(|| req.uri.host())
        .or_else(|| {
            if ctx.host.is_empty() {
                None
            } else {
                Some(ctx.host.as_str())
            }
        })
        .map(crate::lb_factory::strip_addr_port)
        .unwrap_or_else(|| "-".to_string());

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

    let request_duration = ctx.start_time.elapsed();
    let request_started_at_millis = access_log_started_at_millis(request_duration);
    let request_started_at = request_started_at_millis / 1000;

    let scheme = if ctx.is_tls_downstream
        || ctx.is_http3_downstream
        || ctx.is_http3_bridge
        || req.uri.scheme_str() == Some("https")
    {
        "https"
    } else {
        "http"
    };

    // Parse cookies from request header — gated by enableCookies
    let cookies: std::collections::HashMap<String, String> = if log_cookies {
        req.headers
            .get_all("cookie")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|cookie_str| cookie_str.split(';'))
            .filter_map(|p| {
                let p = p.trim();
                p.split_once('=')
                    .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            })
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    let query = req.uri.query().unwrap_or("");
    let query_string = if log_query_string {
        query.to_string()
    } else {
        String::new()
    };
    let args = if log_args {
        query.to_string()
    } else {
        String::new()
    };

    // Collect request headers — gated by enableRequestHeaders
    let mut req_headers: std::collections::HashMap<String, pb::Strings> =
        std::collections::HashMap::new();
    if log_req_headers {
        req_headers.reserve(req.headers.len());
        for (name, value) in req.headers.iter() {
            if value.is_empty() {
                continue;
            }
            if common_req_headers_only && !is_common_request_header(name.as_str()) {
                continue;
            }
            req_headers
                .entry(name.to_string())
                .or_default()
                .values
                .push(value.to_str().unwrap_or("").to_string());
        }
    }

    // Collect response headers — gated by enableResponseHeaders
    // Read sent headers from the ACTUAL response written (includes Pingora
    // modifications like chunked encoding, H2 eos flags, etc.)
    let mut sent_headers: std::collections::HashMap<String, pb::Strings> =
        std::collections::HashMap::new();
    let mut content_type = String::new();
    if let Some(resp) = session.response_written() {
        if log_resp_headers {
            sent_headers.reserve(resp.headers.len());
            for (name, value) in resp.headers.iter() {
                let v_str = value.to_str().unwrap_or("");
                sent_headers.insert(
                    name.to_string(),
                    pb::Strings {
                        values: vec![v_str.to_string()],
                    },
                );
            }
        }
        if log_content_type {
            content_type = resp
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
        }
    }

    let (time_iso8601, time_local) = if log_time_iso8601 || log_time_local {
        let start_dt = crate::utils::time::local_from_timestamp_millis(request_started_at_millis);
        (
            if log_time_iso8601 {
                start_dt.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string()
            } else {
                String::new()
            },
            if log_time_local {
                start_dt.format("%d/%b/%Y:%H:%M:%S %z").to_string()
            } else {
                String::new()
            },
        )
    } else {
        (String::new(), String::new())
    };

    let server_name = if log_server_name {
        ctx.server
            .as_ref()
            .and_then(|s| s.server_names.first())
            .map(|n| n.name.clone())
            .unwrap_or_else(|| host.to_string())
    } else {
        String::new()
    };

    let remote_user = if log_remote_user {
        req.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|auth| {
                auth.get(..6)
                    .filter(|prefix| prefix.eq_ignore_ascii_case("basic "))
                    .and_then(|_| {
                        let encoded = auth[6..].trim();
                        general_purpose::STANDARD
                            .decode(encoded.as_bytes())
                            .ok()
                            .and_then(|decoded| String::from_utf8(decoded).ok())
                            .and_then(|creds| {
                                creds.split_once(':').map(|(user, _)| user.to_string())
                            })
                    })
            })
            .unwrap_or_default()
    } else {
        String::new()
    };

    let request_line = if log_request_line {
        format!(
            "{} {} {}",
            req.method,
            req.uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
            proto
        )
    } else {
        String::new()
    };

    let request_filename = if log_request_filename {
        ctx.cache_key
            .clone()
            .unwrap_or_else(|| req.uri.path().to_string())
    } else {
        String::new()
    };

    // Origin ID from reverse proxy config
    let origin_id = ctx
        .server
        .as_ref()
        .and_then(|s| s.reverse_proxy.as_ref())
        .and_then(|rp| rp.primary_origins.first())
        .map(|o| o.id)
        .unwrap_or(0);

    let is_cached = ctx.cache_hit.unwrap_or(false);

    let mut log = pb::HttpAccessLog {
        request_id: ctx.request_id.clone(),
        server_id,
        node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
        location_id: 0,
        rewrite_id: ctx.rewrite_id,
        origin_id,
        remote_addr: ctx.client_ip_str.clone(),
        raw_remote_addr: if ctx.raw_remote_addr.is_empty() {
            ctx.client_ip_str.clone()
        } else {
            ctx.raw_remote_addr.clone()
        },
        remote_port: ctx.client_port as i32,
        remote_user,
        request_uri: if log_request_uri {
            req.uri
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string())
        } else {
            String::new()
        },
        request_path: if log_request_path {
            req.uri.path().to_string()
        } else {
            String::new()
        },
        request_method: if log_request_method {
            req.method.to_string()
        } else {
            String::new()
        },
        request_filename,
        request_length: bytes_received,
        request_time: request_duration.as_secs_f64(),
        request: request_line,
        request_body: if log_request_body {
            if ctx.request_body.is_empty() {
                vec![]
            } else if ctx.request_body.len() > 2_097_152 {
                ctx.request_body[..2_097_152].to_vec()
            } else {
                ctx.request_body.to_vec()
            }
        } else {
            vec![]
        },
        scheme: scheme.to_string(),
        proto: proto.to_string(),
        status: ctx.response_status as i32,
        status_message: String::new(),
        bytes_sent,
        body_bytes_sent: session.body_bytes_sent() as i64,
        content_type,
        host: host.to_string(),
        user_agent: req
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string(),
        referer: req
            .headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        query_string,
        args,
        cookie: cookies,
        header: req_headers,
        sent_header: sent_headers,
        timestamp: request_started_at,
        msec: request_started_at_millis as f64 / 1000.0,
        time_iso8601,
        time_local,
        hostname: if log_hostname {
            CACHED_HOSTNAME.clone()
        } else {
            String::new()
        },
        server_name,
        server_port: 0,
        server_protocol: proto.to_string(),
        origin_address: if log_origin_address {
            ctx.origin_address.clone()
        } else {
            String::new()
        },
        origin_status: ctx.origin_status,
        origin_header_response_time: ctx.ttfb.map(|d| d.as_secs_f64()).unwrap_or(0.0),
        firewall_policy_id: ctx.waf_policy_id,
        firewall_rule_group_id: ctx.waf_group_id,
        firewall_rule_set_id: ctx.waf_set_id,
        firewall_rule_id: ctx.waf_rule_id,
        errors: if log_errors {
            ctx.errors.clone().unwrap_or_default()
        } else {
            Vec::new()
        },
        ..Default::default()
    };

    if log_firewall_actions {
        if let Some(waf) = &ctx.waf_action {
            log.firewall_actions.push(waf.clone());
        }
    }

    if log_tags {
        if let Some(tags) = &ctx.tags {
            log.tags.extend(tags.iter().cloned());
        }
    } else if fields.is_some() {
        if let Some(tags) = &ctx.tags {
            log.tags
                .extend(tags.iter().filter(|tag| tag.as_str() == "rewrite").cloned());
        }
    }

    if log_attrs {
        log.attrs.insert(
            "cache.status".to_string(),
            if is_cached {
                "HIT".to_string()
            } else {
                "BYPASS".to_string()
            },
        );

        if let Some(analyzed) = &ctx.analyzed {
            if let Some(geo) = &analyzed.geo {
                log.attrs
                    .insert("region".to_string(), geo.region.to_string());
                log.attrs.insert("city".to_string(), geo.city.to_string());
                log.attrs
                    .insert("isp".to_string(), geo.provider.to_string());
                log.attrs
                    .insert("country".to_string(), geo.country.to_string());
            }
            log.attrs
                .insert("browser".to_string(), analyzed.browser.to_string());
            log.attrs.insert("os".to_string(), analyzed.os.to_string());
        }
    }

    if let Some(fields) = fields {
        apply_fields_whitelist(&mut log, fields);
    }

    debug!(
        "ACCESS_LOG: sending log origin_address='{}', origin_status={}, status={}",
        log.origin_address, log.origin_status, log.status
    );

    sender.try_enqueue(log, "http");
}

fn is_common_request_header(name: &str) -> bool {
    match name.len() {
        4 => name.eq_ignore_ascii_case("host"),
        6 => {
            name.eq_ignore_ascii_case("accept")
                || name.eq_ignore_ascii_case("origin")
                || name.eq_ignore_ascii_case("pragma")
        }
        7 => name.eq_ignore_ascii_case("referer"),
        10 => name.eq_ignore_ascii_case("user-agent") || name.eq_ignore_ascii_case("connection"),
        12 => name.eq_ignore_ascii_case("content-type"),
        13 => {
            name.eq_ignore_ascii_case("cache-control") || name.eq_ignore_ascii_case("if-none-match")
        }
        14 => name.eq_ignore_ascii_case("content-length"),
        15 => {
            name.eq_ignore_ascii_case("accept-encoding")
                || name.eq_ignore_ascii_case("accept-language")
        }
        17 => name.eq_ignore_ascii_case("if-modified-since"),
        _ => false,
    }
}

fn apply_fields_whitelist(log: &mut pb::HttpAccessLog, allowed: &AccessLogFieldMask) {
    if !allowed.enabled(1) {
        log.server_id = 0;
    }
    if !allowed.enabled(2) {
        log.node_id = 0;
    }
    if !allowed.enabled(3) {
        log.location_id = 0;
    }
    if !allowed.enabled(4) {
        log.rewrite_id = 0;
    }
    if !allowed.enabled(5) {
        log.origin_id = 0;
    }
    if !allowed.enabled(6) {
        log.remote_addr = String::new();
    }
    if !allowed.enabled(7) {
        log.raw_remote_addr = String::new();
    }
    if !allowed.enabled(8) {
        log.remote_port = 0;
    }
    if !allowed.enabled(9) {
        log.remote_user = String::new();
    }
    if !allowed.enabled(10) {
        log.request_uri = String::new();
    }
    if !allowed.enabled(11) {
        log.request_path = String::new();
    }
    if !allowed.enabled(12) {
        log.request_length = 0;
    }
    if !allowed.enabled(13) {
        log.request_time = 0.0;
    }
    if !allowed.enabled(14) {
        log.request_method = String::new();
    }
    if !allowed.enabled(15) {
        log.request_filename = String::new();
    }
    if !allowed.enabled(16) {
        log.scheme = String::new();
    }
    if !allowed.enabled(17) {
        log.proto = String::new();
    }
    if !allowed.enabled(18) {
        log.bytes_sent = 0;
    }
    if !allowed.enabled(19) {
        log.body_bytes_sent = 0;
    }
    if !allowed.enabled(20) {
        log.status = 0;
    }
    if !allowed.enabled(21) {
        log.status_message = String::new();
    }
    if !allowed.enabled(22) {
        log.sent_header.clear();
    }
    if !allowed.enabled(23) {
        log.time_iso8601 = String::new();
    }
    if !allowed.enabled(24) {
        log.time_local = String::new();
    }
    if !allowed.enabled(25) {
        log.msec = 0.0;
    }
    if !allowed.enabled(26) {
        log.timestamp = 0;
    }
    if !allowed.enabled(27) {
        log.host = String::new();
    }
    if !allowed.enabled(28) {
        log.referer = String::new();
    }
    if !allowed.enabled(29) {
        log.user_agent = String::new();
    }
    if !allowed.enabled(30) {
        log.request = String::new();
    }
    if !allowed.enabled(31) {
        log.content_type = String::new();
    }
    if !allowed.enabled(32) {
        log.cookie.clear();
    }
    if !allowed.enabled(34) {
        log.args = String::new();
    }
    if !allowed.enabled(35) {
        log.query_string = String::new();
    }
    if !allowed.enabled(36) {
        log.header.clear();
    }
    if !allowed.enabled(37) {
        log.server_name = String::new();
    }
    if !allowed.enabled(38) {
        log.server_port = 0;
    }
    if !allowed.enabled(39) {
        log.server_protocol = String::new();
    }
    if !allowed.enabled(40) {
        log.hostname = String::new();
    }
    if !allowed.enabled(41) {
        log.origin_address = String::new();
    }
    if !allowed.enabled(42) {
        log.errors.clear();
    }
    if !allowed.enabled(43) {
        log.attrs.clear();
    }
    if !allowed.enabled(44) {
        log.firewall_policy_id = 0;
    }
    if !allowed.enabled(45) {
        log.firewall_rule_group_id = 0;
    }
    if !allowed.enabled(46) {
        log.firewall_rule_set_id = 0;
    }
    if !allowed.enabled(47) {
        log.firewall_rule_id = 0;
    }
    if !allowed.enabled(48) {
        log.request_id = String::new();
    }
    if !allowed.enabled(49) {
        log.firewall_actions.clear();
    }
    if !allowed.enabled(50) {
        log.tags.retain(|tag| tag == "rewrite");
    }
    if !allowed.enabled(51) {
        log.request_body.clear();
    }
    if !allowed.enabled(52) {
        log.origin_status = 0;
    }
    if !allowed.enabled(53) {
        log.origin_header_response_time = 0.0;
    }
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
    log_l4_passthrough_access(
        request_id,
        server,
        sni_host,
        client_addr,
        listen_port,
        backend_addr,
        started_at_millis,
        duration,
        bytes_received,
        bytes_sent,
        status,
        error,
        "CONNECT",
        "https",
        "TCP",
    );
}

fn l4_passthrough_log_sender(
    access_log_ref: Option<&crate::config_models::HTTPAccessLogRef>,
) -> Option<&'static AccessLogHandle> {
    if access_log_ref.is_some_and(|access_log| !access_log.is_on) {
        return None;
    }
    if !GLOBAL_ACCESS_LOG_ON.load(Ordering::Relaxed) {
        return None;
    }
    LOG_SENDER.get()
}

fn l4_passthrough_time_fields(
    request_started_at_millis: i64,
    fields: Option<&AccessLogFieldMask>,
) -> (String, String) {
    if fields.is_some_and(|fields| !fields.enabled(23) && !fields.enabled(24)) {
        return (String::new(), String::new());
    }
    let start_dt = crate::utils::time::local_from_timestamp_millis(request_started_at_millis);
    (
        start_dt.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string(),
        start_dt.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
fn log_l4_passthrough_access(
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
    request_method: &str,
    scheme: &str,
    proto: &str,
) {
    let access_log_ref = server
        .web
        .as_ref()
        .and_then(|web| web.access_log_ref.as_ref());
    let Some(sender) = l4_passthrough_log_sender(access_log_ref) else {
        return;
    };

    let server_id = server.id.unwrap_or(0);
    let request_started_at_millis = if started_at_millis > 0 {
        started_at_millis
    } else {
        access_log_started_at_millis(duration)
    };
    let request_started_at = request_started_at_millis / 1000;

    let field_mask = access_log_ref
        .filter(|access_log| !access_log.fields.is_empty())
        .map(|access_log| AccessLogFieldMask::from_fields(&access_log.fields));
    let fields = field_mask.as_ref();
    let (time_iso8601, time_local) = l4_passthrough_time_fields(request_started_at_millis, fields);
    let request_uri = "/".to_string();
    let request_line = format!("{} {} {}", request_method, sni_host, proto);
    let mut log = pb::HttpAccessLog {
        request_id,
        server_id,
        node_id: NUMERIC_NODE_ID.load(Ordering::Relaxed),
        remote_addr: client_addr.ip().to_string(),
        raw_remote_addr: client_addr.ip().to_string(),
        remote_port: client_addr.port() as i32,
        request_uri: request_uri.clone(),
        request_path: request_uri,
        request_method: request_method.to_string(),
        request_length: bytes_received as i64,
        request_time: duration.as_secs_f64(),
        request: request_line,
        scheme: scheme.to_string(),
        proto: proto.to_string(),
        status,
        bytes_sent: bytes_sent as i64,
        body_bytes_sent: bytes_sent as i64,
        host: sni_host.to_string(),
        timestamp: request_started_at,
        msec: request_started_at_millis as f64 / 1000.0,
        time_iso8601,
        time_local,
        hostname: CACHED_HOSTNAME.clone(),
        origin_address: backend_addr.to_string(),
        origin_status: status,
        server_port: listen_port as i32,
        server_protocol: proto.to_string(),
        ..Default::default()
    };

    if let Some(error) = error.filter(|value| !value.is_empty()) {
        log.errors.push(error.to_string());
    }
    if let Some(fields) = fields {
        apply_fields_whitelist(&mut log, fields);
    }

    debug!(
        "Reporting L4 passthrough log: {} -> Status {}",
        log.request_uri, log.status
    );
    sender.try_enqueue(log, "sni_passthrough");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn l4_time_fields_use_cached_local_timezone_when_enabled() {
        let previous =
            crate::utils::time::LOCAL_TZ_OFFSET_SECONDS.swap(8 * 3600, Ordering::Relaxed);
        let fields = AccessLogFieldMask::from_fields(&[23, 24]);
        let (time_iso8601, time_local) =
            l4_passthrough_time_fields(1_700_000_000_123, Some(&fields));
        crate::utils::time::LOCAL_TZ_OFFSET_SECONDS.store(previous, Ordering::Relaxed);
        assert!(time_iso8601.ends_with("+08:00"));
        assert!(time_local.ends_with("+0800"));
    }

    #[test]
    fn common_request_headers_match_case_insensitively() {
        for name in [
            "host",
            "User-Agent",
            "accept",
            "Accept-Encoding",
            "Accept-Language",
            "Content-Type",
            "Content-Length",
            "referer",
            "origin",
            "connection",
            "Cache-Control",
            "pragma",
            "If-None-Match",
            "If-Modified-Since",
        ] {
            assert!(is_common_request_header(name), "{name}");
        }
        assert!(!is_common_request_header("x-custom-header"));
    }
}
