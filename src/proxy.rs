#![allow(dead_code)]
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use image::AnimationDecoder;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, ErrorSource, ErrorType::*, Result};
use pingora_load_balancing::{LoadBalancer, selection::RoundRobin};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};
use rand::Rng;
use std::sync::Arc;
use tracing::{debug, error};

use crate::api_config::ApiConfig;
use crate::cache::should_cache_response;
use crate::cache_manager::CACHE;
use crate::config::ConfigStore;
use crate::config_models::{HTTPCachePolicy, HTTPCacheRef, ServerConfig};
use crate::firewall::state::WafStateManager;
use crate::rewrite::{RewriteResult, evaluate_host_redirects, evaluate_rewrites};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Clone)]
pub struct ProxyCTX {
    pub start_time: std::time::Instant,
    pub start_timestamp_millis: i64,
    pub request_id: String,
    pub server: Option<Arc<ServerConfig>>,
    pub lb: Option<Arc<LoadBalancer<RoundRobin>>>,
    pub metrics_recorded: bool,
    pub ttfb: Option<std::time::Duration>,
    pub response_status: u16,
    pub cache_policy: Option<HTTPCachePolicy>,
    pub cache_ref: Option<HTTPCacheRef>,
    pub cache_key: Option<String>,
    pub cache_hit: Option<bool>,
    pub cacheable: bool,
    pub response_headers: HashMap<String, String>,
    pub response_body_len: usize,
    pub response_body_buffer: Vec<u8>,
    pub request_body: Vec<u8>,
    pub waf_policy_id: i64,
    pub waf_group_id: i64,
    pub waf_set_id: i64,
    pub waf_action: Option<String>,
    pub firewall_event_reported: bool,
    pub compress_zstd: bool,
    pub compression_type: Option<String>,
    pub compression_level: i8,
    pub custom_page_body: Option<String>,
    pub custom_page_status: u16,
    pub is_websocket: bool,
    pub is_grpc: bool,
    pub max_inspection_size: i64,
    pub no_log: bool,
    pub response_headers_size: usize,
    pub origin_address: String,
    pub origin_status: i32,
    pub is_on: bool,
    pub client_ip: std::net::IpAddr,
    pub client_port: u16,
    pub raw_remote_addr: String,
    pub is_http3_bridge: bool,
    pub webp_convert_enabled: bool,
    pub webp_source_content_type: Option<String>,
    pub webp_pending_body: Vec<u8>,
    pub webp_quality: i32,
    pub optimize_enabled: bool,
    pub optimize_kind: Option<String>,
    pub optimize_pending_body: Vec<u8>,
    pub hls_playlist_enabled: bool,
    pub hls_segment_encrypt_enabled: bool,
    pub hls_segment_key: Option<[u8; 16]>,
    pub hls_segment_iv: Option<[u8; 16]>,
    pub hls_segment_pending_body: Vec<u8>,
    pub hls_session_id: Option<String>,
    pub hls_session_exp: Option<i64>,
    pub request_limit_out_bandwidth_bytes: i64,
    pub request_limit_out_bandwidth_sent: i64,
    pub request_limit_out_bandwidth_window_start: Option<std::time::Instant>,
}

impl Default for ProxyCTX {
    fn default() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            start_timestamp_millis: crate::utils::time::now_timestamp_millis(),
            request_id: String::new(),
            server: None,
            lb: None,
            metrics_recorded: false,
            ttfb: None,
            response_status: 0,
            cache_policy: None,
            cache_ref: None,
            cache_key: None,
            cache_hit: None,
            cacheable: false,
            response_headers: HashMap::new(),
            response_body_len: 0,
            response_body_buffer: Vec::new(),
            request_body: Vec::new(),
            waf_policy_id: 0,
            waf_group_id: 0,
            waf_set_id: 0,
            waf_action: None,
            firewall_event_reported: false,
            compress_zstd: false,
            compression_type: None,
            compression_level: 0,
            custom_page_body: None,
            custom_page_status: 0,
            is_websocket: false,
            is_grpc: false,
            max_inspection_size: 512 * 1024, // Default 512K as per PB requirement
            no_log: false,
            response_headers_size: 0,
            origin_address: String::new(),
            origin_status: 0,
            is_on: true,
            client_ip: "127.0.0.1".parse().unwrap(),
            client_port: 0,
            raw_remote_addr: String::new(),
            is_http3_bridge: false,
            webp_convert_enabled: false,
            webp_source_content_type: None,
            webp_pending_body: Vec::new(),
            webp_quality: 80,
            optimize_enabled: false,
            optimize_kind: None,
            optimize_pending_body: Vec::new(),
            hls_playlist_enabled: false,
            hls_segment_encrypt_enabled: false,
            hls_segment_key: None,
            hls_segment_iv: None,
            hls_segment_pending_body: Vec::new(),
            hls_session_id: None,
            hls_session_exp: None,
            request_limit_out_bandwidth_bytes: 0,
            request_limit_out_bandwidth_sent: 0,
            request_limit_out_bandwidth_window_start: None,
        }
    }
}

#[derive(Clone)]
pub struct EdgeProxy {
    pub config: Arc<ConfigStore>,
    pub waf_state: Arc<WafStateManager>,
    pub api_config: Arc<ApiConfig>,
    pub cert_selector: Arc<crate::ssl::DynamicCertSelector>,
}

const DEFAULT_TRAFFIC_LIMIT_NOTICE_PAGE_BODY: &str = r#"<!DOCTYPE html>
<html>
<head>
<title>Traffic Limit Exceeded Warning</title>
<body>

<h1>Traffic Limit Exceeded Warning</h1>
<p>The site traffic has exceeded the limit. Please contact with the site administrator.</p>
<address>Request ID: ${requestId}.</address>

</body>
</html>"#;
const TEXT_MIME_TYPES: &[&str] = &[
    "application/atom+xml",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/rss+xml",
    "application/x-web-app-manifest+json",
    "application/xhtml+xml",
    "application/xml",
    "image/svg+xml",
    "text/css",
    "text/plain",
    "text/javascript",
    "text/xml",
    "text/html",
    "text/xhtml",
    "text/sgml",
];
const HLS_KEY_ROUTE: &str = "/.well-known/cloud-node/hls-key";

#[derive(Clone)]
struct RequestLimitBinding {
    server_id: i64,
    client_ip: std::net::IpAddr,
    last_seen: std::time::Instant,
}

static REQUEST_LIMIT_BINDINGS: Lazy<DashMap<String, RequestLimitBinding>> = Lazy::new(DashMap::new);
const REQUEST_LIMIT_BINDING_IDLE_SECS: u64 = 180;
const MAX_OPTIMIZATION_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_WEBP_CONVERSION_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_HLS_PLAYLIST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_HLS_SEGMENT_BODY_BYTES: usize = 16 * 1024 * 1024;

impl EdgeProxy {
    fn is_grpc_request(session: &Session) -> bool {
        session
            .get_header("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_ascii_lowercase().starts_with("application/grpc"))
            .unwrap_or(false)
    }

    fn raw_remote_ip(raw_remote_addr: &str, fallback: std::net::IpAddr) -> String {
        if raw_remote_addr.is_empty() {
            return fallback.to_string();
        }

        raw_remote_addr
            .parse::<std::net::SocketAddr>()
            .map(|addr| addr.ip().to_string())
            .or_else(|_| {
                raw_remote_addr
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.to_string())
            })
            .unwrap_or_else(|_| fallback.to_string())
    }

    fn status_message(status: u16) -> String {
        http::StatusCode::from_u16(status)
            .ok()
            .and_then(|code| code.canonical_reason().map(str::to_string))
            .unwrap_or_default()
    }

    fn apply_template_modifier(value: String, modifier: &str) -> String {
        match modifier.trim() {
            "urlEncode" => urlencoding::encode(&value).into_owned(),
            "urlDecode" => urlencoding::decode(&value)
                .map(|decoded| decoded.into_owned())
                .unwrap_or(value),
            "base64Encode" => base64::engine::general_purpose::STANDARD.encode(value),
            "base64Decode" => base64::engine::general_purpose::STANDARD
                .decode(value.as_bytes())
                .ok()
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .unwrap_or_default(),
            "md5" => format!("{:x}", md5_legacy::compute(value.as_bytes())),
            "sha1" => {
                use sha1::{Digest as _, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(value.as_bytes());
                hasher
                    .finalize()
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect()
            }
            "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(value.as_bytes());
                hasher
                    .finalize()
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect()
            }
            "toLowerCase" => value.to_ascii_lowercase(),
            "toUpperCase" => value.to_ascii_uppercase(),
            _ => value,
        }
    }

    fn render_page_template(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        template: &str,
        status: u16,
    ) -> String {
        static RE_VAR: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));

        RE_VAR
            .replace_all(template, |caps: &regex::Captures| {
                let raw = &caps[0];
                let inner = raw
                    .strip_prefix("${")
                    .and_then(|s| s.strip_suffix('}'))
                    .unwrap_or(raw);
                let mut parts = inner.split('|');
                let var_name = parts.next().unwrap_or("").trim();

                let mut value = match var_name {
                    "requestId" => ctx.request_id.clone(),
                    "status" => status.to_string(),
                    "statusMessage" => Self::status_message(status),
                    "rawRemoteAddr" => Self::raw_remote_ip(&ctx.raw_remote_addr, ctx.client_ip),
                    "remoteAddr" => ctx.client_ip.to_string(),
                    "remotePort" => ctx.client_port.to_string(),
                    "serverAddr" => {
                        if self
                            .config
                            .get_global_http_config_sync()
                            .enable_server_addr_variable
                        {
                            session
                                .downstream_session
                                .digest()
                                .and_then(|d| d.socket_digest.as_ref())
                                .and_then(|sd| sd.local_addr())
                                .and_then(|addr| addr.as_inet())
                                .map(|inet| inet.ip().to_string())
                                .unwrap_or_default()
                        } else {
                            String::new()
                        }
                    }
                    "serverPort" => session
                        .downstream_session
                        .digest()
                        .and_then(|d| d.socket_digest.as_ref())
                        .and_then(|sd| sd.local_addr())
                        .and_then(|addr| addr.as_inet())
                        .map(|inet| inet.port().to_string())
                        .unwrap_or_default(),
                    "scheme" => {
                        if session
                            .downstream_session
                            .digest()
                            .and_then(|d| d.ssl_digest.as_ref())
                            .is_some()
                            || session.req_header().uri.scheme_str() == Some("https")
                        {
                            "https".to_string()
                        } else {
                            "http".to_string()
                        }
                    }
                    "proto" => {
                        if ctx.is_http3_bridge {
                            "HTTP/3.0".to_string()
                        } else {
                            match session.req_header().version {
                                pingora::http::Version::HTTP_10 => "HTTP/1.0".to_string(),
                                pingora::http::Version::HTTP_11 => "HTTP/1.1".to_string(),
                                pingora::http::Version::HTTP_2 => "HTTP/2.0".to_string(),
                                pingora::http::Version::HTTP_3 => "HTTP/3.0".to_string(),
                                _ => "HTTP/1.1".to_string(),
                            }
                        }
                    }
                    "requestTime" => format!("{:.3}", ctx.start_time.elapsed().as_secs_f64()),
                    "bytesSent" => {
                        (session.body_bytes_sent() as u64 + ctx.response_headers_size as u64 + 20)
                            .to_string()
                    }
                    "bodyBytesSent" => session.body_bytes_sent().to_string(),
                    "timestamp" => (ctx.start_timestamp_millis / 1000).to_string(),
                    "msec" => format!("{:.3}", ctx.start_timestamp_millis as f64 / 1000.0),
                    "timeISO8601" => {
                        crate::utils::time::local_from_timestamp_millis(ctx.start_timestamp_millis)
                            .format("%Y-%m-%dT%H:%M:%S%.3f%:z")
                            .to_string()
                    }
                    "timeLocal" => {
                        crate::utils::time::local_from_timestamp_millis(ctx.start_timestamp_millis)
                            .format("%d/%b/%Y:%H:%M:%S %z")
                            .to_string()
                    }
                    "host" => session
                        .get_header("host")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.split(':').next().unwrap_or(v).to_string())
                        .unwrap_or_else(|| {
                            session
                                .req_header()
                                .uri
                                .host()
                                .unwrap_or_default()
                                .to_string()
                        }),
                    "requestURI" => session
                        .req_header()
                        .uri
                        .path_and_query()
                        .map(|pq| pq.as_str().to_string())
                        .unwrap_or_else(|| "/".to_string()),
                    "requestPath" => session.req_header().uri.path().to_string(),
                    "requestMethod" => session.req_header().method.to_string(),
                    "request" => format!(
                        "{} {} {}",
                        session.req_header().method,
                        session
                            .req_header()
                            .uri
                            .path_and_query()
                            .map(|pq| pq.as_str())
                            .unwrap_or("/"),
                        if ctx.is_http3_bridge {
                            "HTTP/3.0"
                        } else {
                            match session.req_header().version {
                                pingora::http::Version::HTTP_10 => "HTTP/1.0",
                                pingora::http::Version::HTTP_11 => "HTTP/1.1",
                                pingora::http::Version::HTTP_2 => "HTTP/2.0",
                                pingora::http::Version::HTTP_3 => "HTTP/3.0",
                                _ => "HTTP/1.1",
                            }
                        }
                    ),
                    "hostname" => hostname::get()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    _ => crate::firewall::matcher_plus::format_variables(
                        session,
                        raw,
                        &ctx.request_body,
                    ),
                };

                for modifier in parts {
                    value = Self::apply_template_modifier(value, modifier);
                }
                value
            })
            .to_string()
    }

    fn cleanup_request_limit_bindings() {
        let now = std::time::Instant::now();
        let stale_keys: Vec<String> = REQUEST_LIMIT_BINDINGS
            .iter()
            .filter_map(|entry| {
                (now.duration_since(entry.value().last_seen).as_secs()
                    > REQUEST_LIMIT_BINDING_IDLE_SECS)
                    .then(|| entry.key().clone())
            })
            .collect();

        for key in stale_keys {
            REQUEST_LIMIT_BINDINGS.remove(&key);
        }
    }

    fn try_bind_request_limit_connection(
        &self,
        raw_remote_addr: &str,
        server_id: i64,
        client_ip: std::net::IpAddr,
        max_conns: i32,
        max_conns_per_ip: i32,
    ) -> bool {
        if raw_remote_addr.is_empty() || server_id <= 0 || (max_conns <= 0 && max_conns_per_ip <= 0)
        {
            return true;
        }

        Self::cleanup_request_limit_bindings();
        let now = std::time::Instant::now();

        if let Some(mut existing) = REQUEST_LIMIT_BINDINGS.get_mut(raw_remote_addr) {
            existing.last_seen = now;
            return true;
        }

        if max_conns > 0 {
            let current_server_conns = REQUEST_LIMIT_BINDINGS
                .iter()
                .filter(|entry| entry.value().server_id == server_id)
                .count() as i32;
            if current_server_conns >= max_conns {
                return false;
            }
        }

        if max_conns_per_ip > 0 {
            let current_ip_conns = REQUEST_LIMIT_BINDINGS
                .iter()
                .filter(|entry| entry.value().client_ip == client_ip)
                .count() as i32;
            if current_ip_conns >= max_conns_per_ip {
                return false;
            }
        }

        REQUEST_LIMIT_BINDINGS.insert(
            raw_remote_addr.to_string(),
            RequestLimitBinding {
                server_id,
                client_ip,
                last_seen: now,
            },
        );
        true
    }

    fn response_content_length(resp: &pingora::http::ResponseHeader) -> Option<usize> {
        resp.headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
    }

    fn socket_client_ip(session: &Session) -> (std::net::IpAddr, u16, String) {
        let socket_addr = session
            .downstream_session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .and_then(|sd| sd.peer_addr().cloned())
            .or_else(|| session.client_addr().cloned());

        match socket_addr {
            Some(pingora_core::protocols::l4::socket::SocketAddr::Inet(addr)) => {
                (addr.ip(), addr.port(), addr.to_string())
            }
            _ => ("127.0.0.1".parse().unwrap(), 0, String::new()),
        }
    }

    fn parse_candidate_ip(raw: &str) -> Option<std::net::IpAddr> {
        let mut candidate = raw.trim().trim_matches('"').trim_matches('\'');
        if candidate.is_empty() {
            return None;
        }
        if let Some(value) = candidate
            .strip_prefix("for=")
            .or_else(|| candidate.strip_prefix("For="))
        {
            candidate = value.trim();
        }
        if let Some((first, _)) = candidate.split_once(';') {
            candidate = first.trim();
        }
        if let Some((first, _)) = candidate.split_once(',') {
            candidate = first.trim();
        }
        let candidate = candidate.trim_matches(|c| c == '[' || c == ']');
        candidate.parse().ok()
    }

    fn header_value_ci(session: &Session, name: &str) -> String {
        session
            .get_header(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn fallback_client_ip(session: &Session, raw_ip: std::net::IpAddr) -> std::net::IpAddr {
        for header in [
            "x-cloud-real-ip",
            "cf-connecting-ip",
            "true-client-ip",
            "x-forwarded-for",
            "x-real-ip",
            "x-client-ip",
            "x-original-forwarded-for",
            "x-cluster-client-ip",
            "fastly-client-ip",
            "ali-cdn-real-ip",
            "cdn-src-ip",
            "forwarded",
        ] {
            let value = Self::header_value_ci(session, header);
            if let Some(ip) = Self::parse_candidate_ip(&value) {
                return ip;
            }
        }
        raw_ip
    }

    fn resolve_remote_addr_template(
        session: &Session,
        template: &str,
        raw_ip: std::net::IpAddr,
        raw_remote_addr: &str,
        remote_port: u16,
    ) -> String {
        static RE_VAR: std::sync::LazyLock<Regex> =
            std::sync::LazyLock::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));

        RE_VAR
            .replace_all(template, |caps: &regex::Captures| {
                let inner = caps[0]
                    .strip_prefix("${")
                    .and_then(|s| s.strip_suffix('}'))
                    .unwrap_or("");
                if inner.eq_ignore_ascii_case("rawRemoteAddr") {
                    return raw_ip.to_string();
                }
                if inner.eq_ignore_ascii_case("remoteAddr")
                    || inner.eq_ignore_ascii_case("remoteAddrValue")
                {
                    return Self::fallback_client_ip(session, raw_ip).to_string();
                }
                if inner.eq_ignore_ascii_case("remotePort") {
                    return remote_port.to_string();
                }
                if inner.eq_ignore_ascii_case("host") || inner.eq_ignore_ascii_case("requestHost") {
                    return session
                        .get_header("host")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.split(':').next().unwrap_or(v).to_string())
                        .unwrap_or_default();
                }
                if let Some(name) = inner
                    .strip_prefix("requestHeader.")
                    .or_else(|| inner.strip_prefix("header."))
                    .or_else(|| inner.strip_prefix("requestHeader:"))
                    .or_else(|| inner.strip_prefix("header:"))
                {
                    return Self::header_value_ci(session, name);
                }
                if inner.eq_ignore_ascii_case("socketRemoteAddr") {
                    return raw_remote_addr.to_string();
                }
                String::new()
            })
            .to_string()
    }

    fn resolve_client_ip(
        &self,
        session: &Session,
        server: Option<&ServerConfig>,
        raw_ip: std::net::IpAddr,
        raw_remote_addr: &str,
        remote_port: u16,
    ) -> std::net::IpAddr {
        if let Some(remote_addr_cfg) = server
            .and_then(|server| server.web.as_ref())
            .and_then(|web| web.remote_addr.as_ref())
            .filter(|cfg| cfg.is_on && !cfg.is_empty())
        {
            for configured in remote_addr_cfg.configured_values() {
                let value =
                    if remote_addr_cfg.is_request_header_type() && !configured.contains("${") {
                        Self::header_value_ci(session, &configured)
                    } else {
                        Self::resolve_remote_addr_template(
                            session,
                            &configured,
                            raw_ip,
                            raw_remote_addr,
                            remote_port,
                        )
                    };
                if let Some(ip) = Self::parse_candidate_ip(&value) {
                    return ip;
                }
            }

            if remote_addr_cfg.is_request_header_type() {
                return raw_ip;
            }
        }

        Self::fallback_client_ip(session, raw_ip)
    }

    fn should_redirect_to_https(
        &self,
        session: &Session,
        server: &ServerConfig,
        host: &str,
    ) -> Option<(String, u16)> {
        let redirect = server
            .web
            .as_ref()
            .and_then(|web| web.redirect_to_https.as_ref())?;
        if !redirect.is_on {
            return None;
        }

        let is_https = session
            .downstream_session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
            .is_some()
            || session.req_header().uri.scheme_str() == Some("https");
        if is_https {
            return None;
        }

        if !redirect.domains.is_empty()
            && !redirect.domains.iter().any(|domain| {
                let domain = domain.to_ascii_lowercase();
                let host = host.to_ascii_lowercase();
                host == domain || host.ends_with(&format!(".{}", domain))
            })
        {
            return None;
        }

        let request_uri = session
            .req_header()
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");

        let target_host = if !redirect.host.is_empty() {
            if redirect.port > 0 && redirect.port != 443 {
                format!("{}:{}", redirect.host, redirect.port)
            } else {
                redirect.host.clone()
            }
        } else if redirect.port > 0 && redirect.port != 443 {
            format!("{}:{}", host, redirect.port)
        } else {
            host.to_string()
        };

        let status = u16::try_from(redirect.status)
            .ok()
            .filter(|code| matches!(*code, 301 | 302 | 307 | 308))
            .unwrap_or(302);
        Some((format!("https://{}{}", target_host, request_uri), status))
    }

    async fn respond_shutdown(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        shutdown: &crate::config_models::HTTPShutdownConfig,
    ) -> Result<bool> {
        if !shutdown.is_on {
            return Ok(false);
        }

        let status = u16::try_from(shutdown.status)
            .ok()
            .filter(|code| *code >= 100)
            .unwrap_or(200);
        let body_type = shutdown.body_type.to_ascii_lowercase();

        if body_type == "redirecturl" {
            let target = if shutdown.url.is_empty() {
                "/".to_string()
            } else {
                shutdown.url.clone()
            };
            let redirect_status = if matches!(status, 301 | 302 | 307 | 308) {
                status
            } else {
                307
            };
            let mut resp = pingora_http::ResponseHeader::build(redirect_status, None).unwrap();
            resp.insert_header("location", target).unwrap();
            session.write_response_header(Box::new(resp), true).await?;
            ctx.response_status = redirect_status;
            return Ok(true);
        }

        let body = if body_type == "html" {
            self.render_page_template(session, ctx, &shutdown.body, status)
        } else if shutdown.url.is_empty() {
            "The site have been shutdown.".to_string()
        } else {
            let path = std::path::Path::new(&shutdown.url);
            if !path.starts_with("pages") && !path.starts_with("/pages") {
                format!("404 page not found: '{}'", shutdown.url)
            } else {
                match std::fs::read_to_string(path) {
                    Ok(content) => self.render_page_template(session, ctx, &content, status),
                    Err(_) => format!("404 page not found: '{}'", shutdown.url),
                }
            }
        };

        let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
        resp.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        ctx.response_status = status;
        Ok(true)
    }

    fn global_webp_policy(&self) -> Option<crate::config_models::WebPImagePolicy> {
        self.config
            .get_global_webp_policy_sync()
            .filter(|policy| policy.is_on)
    }

    fn global_uam_enabled(&self) -> bool {
        self.config
            .get_global_uam_policy_sync()
            .map(|policy| policy.is_on)
            .unwrap_or(false)
    }

    fn global_cc_policy(&self) -> Option<crate::config_models::HTTPCCPolicy> {
        self.config
            .get_global_http_cc_policy_sync()
            .filter(|policy| policy.is_on)
    }

    fn global_http_pages(&self) -> Vec<crate::config_models::HTTPPageConfig> {
        self.config
            .get_global_http_pages_policy_sync()
            .filter(|policy| policy.is_on)
            .map(|policy| policy.pages)
            .unwrap_or_default()
    }

    fn request_accepts_webp(session: &Session) -> bool {
        session
            .get_header("accept")
            .and_then(|value| value.to_str().ok())
            .map(|accept| accept.contains("image/webp"))
            .unwrap_or(false)
    }

    fn response_is_webp_convertible(content_type: &str) -> bool {
        let content_type = content_type.to_ascii_lowercase();
        content_type.starts_with("image/jpeg")
            || content_type.starts_with("image/jpg")
            || content_type.starts_with("image/png")
            || content_type.starts_with("image/gif")
    }

    fn size_capacity_bytes(value: &Option<Value>) -> i64 {
        value
            .as_ref()
            .map(crate::config_models::SizeCapacity::from_json)
            .map(|size| size.to_bytes())
            .unwrap_or(0)
    }

    fn site_webp_matches_request(
        webp: &crate::config_models::WebPConfig,
        session: &Session,
    ) -> bool {
        if !webp.is_on || !Self::request_accepts_webp(session) {
            return false;
        }

        let path = session.req_header().uri.path().to_ascii_lowercase();
        let ext = std::path::Path::new(&path)
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{}", value.to_ascii_lowercase()))
            .unwrap_or_default();

        if !webp.file_extensions.is_empty()
            && !webp
                .file_extensions
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(&ext))
        {
            return false;
        }

        true
    }

    fn maybe_enable_webp_conversion(
        &self,
        session: &Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut ProxyCTX,
    ) {
        ctx.webp_convert_enabled = false;
        ctx.webp_source_content_type = None;
        ctx.webp_pending_body.clear();

        let Some(server) = ctx.server.as_ref() else {
            return;
        };
        let Some(web_cfg) = server.web.as_ref() else {
            return;
        };
        let Some(site_webp) = web_cfg.webp.as_ref() else {
            return;
        };
        let Some(policy) = self.global_webp_policy() else {
            return;
        };
        if !Self::site_webp_matches_request(site_webp, session) {
            return;
        }
        if policy.require_cache && ctx.cache_ref.is_none() {
            return;
        }
        if upstream_response.status.as_u16() != 200 {
            return;
        }
        if upstream_response.headers.get("content-encoding").is_some() {
            return;
        }

        let Some(content_type) = upstream_response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string())
        else {
            return;
        };

        if !Self::response_is_webp_convertible(&content_type) {
            return;
        }

        if !site_webp.mime_types.is_empty()
            && !site_webp.mime_types.iter().any(|mime| {
                content_type
                    .to_ascii_lowercase()
                    .starts_with(&mime.to_ascii_lowercase())
            })
        {
            return;
        }

        let content_length = upstream_response
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let Some(content_length_usize) = Self::response_content_length(upstream_response) else {
            return;
        };
        if content_length_usize > MAX_WEBP_CONVERSION_BODY_BYTES {
            return;
        }
        let site_min = Self::size_capacity_bytes(&site_webp.min_length);
        let site_max = Self::size_capacity_bytes(&site_webp.max_length);
        let policy_min = Self::size_capacity_bytes(&policy.min_length);
        let policy_max = Self::size_capacity_bytes(&policy.max_length);
        let effective_min = site_min.max(policy_min);
        let effective_max = match (site_max, policy_max) {
            (0, 0) => 0,
            (0, b) => b,
            (a, 0) => a,
            (a, b) => a.min(b),
        };
        if content_length > 0 && content_length < effective_min {
            return;
        }
        if effective_max > 0 && content_length > effective_max {
            return;
        }

        ctx.webp_convert_enabled = true;
        ctx.webp_source_content_type = Some(content_type);
        ctx.webp_quality = policy.quality;

        upstream_response.remove_header("content-length");
        let _ = upstream_response.insert_header("content-type", "image/webp");

        let vary = upstream_response
            .headers
            .get("vary")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let new_vary = if vary.is_empty() {
            "Accept".to_string()
        } else if vary
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("accept"))
        {
            vary.to_string()
        } else {
            format!("{}, Accept", vary)
        };
        let _ = upstream_response.insert_header("vary", new_vary.clone());

        ctx.response_headers
            .insert("content-type".to_string(), "image/webp".to_string());
        ctx.response_headers.remove("content-length");
        ctx.response_headers.insert("vary".to_string(), new_vary);
    }

    fn convert_to_webp(content_type: &str, body: &[u8], quality: i32) -> anyhow::Result<Vec<u8>> {
        let rgba = if content_type.to_ascii_lowercase().starts_with("image/gif") {
            let decoder = image::codecs::gif::GifDecoder::new(std::io::Cursor::new(body))?;
            let frames = decoder.into_frames().collect_frames()?;
            let frame = frames
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("gif has no frame"))?;
            image::DynamicImage::ImageRgba8(frame.into_buffer()).to_rgba8()
        } else {
            image::load_from_memory(body)?.to_rgba8()
        };

        let encoder = webp::Encoder::from_rgba(rgba.as_raw(), rgba.width(), rgba.height());
        Ok(encoder.encode(quality.clamp(1, 100) as f32).to_vec())
    }

    fn resolve_http3_advertisement_port(
        &self,
        session: &Session,
        server: Option<&ServerConfig>,
    ) -> Option<u16> {
        let policy = self.config.get_global_http3_policy_sync()?;
        if !policy.is_on {
            return None;
        }
        if server.is_some_and(ServerConfig::is_sni_passthrough) {
            return None;
        }
        let https_enabled = server
            .and_then(|server| server.https.as_ref())
            .map(|https| https.is_on && https.http3_enabled())
            .unwrap_or(false);
        if !https_enabled {
            return None;
        }

        let ua = session
            .get_header("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_mobile = ua.contains("mobile")
            || ua.contains("android")
            || ua.contains("iphone")
            || ua.contains("ipad");
        if is_mobile && !policy.support_mobile_browsers {
            return None;
        }

        if policy.port > 0 {
            return u16::try_from(policy.port).ok();
        }

        session.req_header().uri.port_u16().or(Some(443))
    }

    fn collect_candidate_pages(
        &self,
        server: Option<&ServerConfig>,
    ) -> Vec<crate::config_models::HTTPPageConfig> {
        let mut pages = Vec::new();
        if let Some(server) = server
            && let Some(web) = &server.web
        {
            pages.extend(web.pages.iter().filter(|page| page.is_on).cloned());
            if !web.enable_global_pages {
                return pages;
            }
        }
        pages.extend(self.config.get_global_pages_sync());
        pages.extend(self.global_http_pages());
        pages
    }

    fn find_custom_page(
        &self,
        server: Option<&ServerConfig>,
        status: u16,
    ) -> Option<crate::config_models::HTTPPageConfig> {
        self.collect_candidate_pages(server)
            .into_iter()
            .find(|page| page.is_on && page.matches_status(status))
    }

    async fn respond_status_with_pages(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        status: u16,
    ) -> Result<bool> {
        if let Some(page) = self.find_custom_page(ctx.server.as_deref(), status) {
            if let Some(url) = page.url.as_ref().filter(|url| !url.is_empty()) {
                let redirect_status = u16::try_from(page.new_status)
                    .ok()
                    .filter(|code| (300..400).contains(code))
                    .unwrap_or(302);
                ctx.response_status = redirect_status;
                ctx.response_body_len = 0;
                ctx.response_headers.clear();
                ctx.response_headers
                    .insert("location".to_string(), url.clone());
                let mut resp = pingora_http::ResponseHeader::build(redirect_status, None).unwrap();
                resp.insert_header("location", url.as_str()).unwrap();
                ctx.response_headers_size = resp
                    .headers
                    .iter()
                    .map(|(n, v)| n.as_str().len() + v.len() + 4)
                    .sum();
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }

            if let Some(body) = page.body.as_ref().filter(|body| !body.is_empty()) {
                let final_status = u16::try_from(page.new_status)
                    .ok()
                    .filter(|code| *code >= 100)
                    .unwrap_or(status);
                ctx.response_status = final_status;
                let resolved_body = self.render_page_template(session, ctx, body, final_status);
                ctx.response_body_len = resolved_body.len();
                ctx.response_headers.clear();
                ctx.response_headers.insert(
                    "content-type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                );
                let mut resp = pingora_http::ResponseHeader::build(final_status, None).unwrap();
                resp.insert_header("content-type", "text/html; charset=utf-8")
                    .unwrap();
                ctx.response_headers_size = resp
                    .headers
                    .iter()
                    .map(|(n, v)| n.as_str().len() + v.len() + 4)
                    .sum();
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::from(resolved_body)), true)
                    .await?;
                return Ok(true);
            }
        }

        if status >= 500 {
            let (site_page_count, enable_global_pages) = ctx
                .server
                .as_ref()
                .and_then(|server| server.web.as_ref())
                .map(|web| {
                    (
                        web.pages.iter().filter(|page| page.is_on).count(),
                        web.enable_global_pages,
                    )
                })
                .unwrap_or((0, false));
            debug!(
                "No custom page matched status {} for host {:?}. site_pages={}, enable_global_pages={}, global_pages={}, global_http_page_policy_pages={}",
                status,
                session
                    .get_header("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string()),
                site_page_count,
                enable_global_pages,
                self.config.get_global_pages_sync().len(),
                self.global_http_pages().len(),
            );
        }

        ctx.response_status = status;
        ctx.response_body_len = 0;
        ctx.response_headers.clear();
        ctx.response_headers_size = 0;
        session.respond_error(status).await?;
        Ok(true)
    }

    fn maybe_report_firewall_event(
        &self,
        ctx: &mut ProxyCTX,
        policy_id: i64,
        group_id: i64,
        set_id: i64,
    ) {
        if ctx.firewall_event_reported || policy_id <= 0 {
            return;
        }
        let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);
        if server_id <= 0 {
            return;
        }
        ctx.firewall_event_reported = true;
        let api_config = self.api_config.clone();
        tokio::spawn(async move {
            crate::rpc::firewall::notify_firewall_event(
                &api_config,
                server_id,
                policy_id,
                group_id,
                set_id,
            )
            .await;
        });
    }

    async fn enforce_uam(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        ip: &str,
    ) -> Result<bool> {
        let site_uam_enabled = ctx
            .server
            .as_ref()
            .map(|server| {
                server
                    .web
                    .as_ref()
                    .and_then(|web| web.uam.as_ref())
                    .map(|uam| uam.is_on)
                    .or_else(|| server.uam.as_ref().map(|uam| uam.is_on))
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        let global_uam_enabled = self.global_uam_enabled();
        if !site_uam_enabled && !global_uam_enabled {
            return Ok(false);
        }

        let matched = crate::firewall::MatchedAction {
            action: crate::firewall::ActionResponse::JsCookie { life_seconds: 300 },
            policy_id: 0,
            group_id: 0,
            set_id: 0,
            action_code: if site_uam_enabled {
                "site_uam".to_string()
            } else {
                "global_uam".to_string()
            },
            timeout_secs: None,
            max_timeout_secs: None,
            life_seconds: Some(300),
            max_fails: 0,
            fail_block_timeout: 0,
            scope: Some(if site_uam_enabled {
                "server".to_string()
            } else {
                "global".to_string()
            }),
            block_c_class: false,
            use_local_firewall: false,
            next_group_id: None,
            next_set_id: None,
            allow_scope: None,
            tags: vec![],
            ip_list_id: 0,
            event_level: "info".to_string(),
            block_options: None,
            page_options: None,
            captcha_options: None,
            js_cookie_options: None,
        };
        ctx.waf_action = Some(matched.action_code.clone());
        self.respond_waf_action(session, ctx, matched, ip.to_string())
            .await
    }

    async fn apply_cc_policy(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        policy: &crate::config_models::CCPolicy,
        scope_server_id: i64,
    ) -> Result<bool> {
        if !policy.is_on {
            return Ok(false);
        }
        if policy.max_qps > 0
            && !self
                .waf_state
                .check_rate_limit(scope_server_id, policy.max_qps as u32)
        {
            if policy.per_ip_max_qps > 0
                && !self.waf_state.check_ip_rate_limit(
                    scope_server_id,
                    ctx.client_ip,
                    policy.per_ip_max_qps as u32,
                )
            {
                if policy.block_ip {
                    let ban = if policy.block_ip_duration > 0 {
                        policy.block_ip_duration as i64
                    } else {
                        3600
                    };
                    self.waf_state.block_ip(
                        ctx.client_ip,
                        scope_server_id,
                        ban,
                        Some(if scope_server_id == 0 {
                            "global"
                        } else {
                            "server"
                        }),
                        false,
                        true,
                    );
                }
                if policy.show_page {
                    ctx.no_log = policy.no_log;
                    return self.respond_status_with_pages(session, ctx, 429).await;
                }
            }
        }
        Ok(false)
    }

    async fn apply_global_cc_policy(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        let Some(policy) = self.global_cc_policy() else {
            return Ok(false);
        };
        let policy = crate::config_models::CCPolicy {
            is_on: policy.is_on,
            max_qps: policy.max_qps,
            per_ip_max_qps: policy.per_ip_max_qps,
            max_bandwidth: policy.max_bandwidth,
            show_page: policy.show_page,
            block_ip: policy.block_ip,
            page_duration: policy.page_duration,
            block_ip_duration: policy.block_ip_duration,
            no_log: policy.no_log,
        };
        self.apply_cc_policy(session, ctx, &policy, 0).await
    }

    fn resolve_plan_max_upload_bytes(&self, server: &ServerConfig) -> i64 {
        if server.user_plan_id <= 0 {
            return 0;
        }

        let Some(user_plan) = self.config.get_user_plan_sync(server.user_plan_id) else {
            return 0;
        };
        let Some(plan) = self.config.get_plan_sync(user_plan.plan_id) else {
            return 0;
        };
        if plan.max_upload_size_json.is_empty() {
            return 0;
        }

        let value = match serde_json::from_slice::<Value>(&plan.max_upload_size_json) {
            Ok(value) => value,
            Err(_) => return 0,
        };

        if let Some(bytes) = value.as_i64() {
            return bytes.max(0);
        }
        if let Some(bytes) = value.get("bytes").and_then(|v| v.as_i64()) {
            return bytes.max(0);
        }

        crate::config_models::SizeCapacity::from_json(&value)
            .to_bytes()
            .max(0)
    }

    async fn enforce_plan_max_upload(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        let Some(server) = ctx.server.as_ref() else {
            return Ok(false);
        };

        let max_upload_bytes = self.resolve_plan_max_upload_bytes(server);
        if max_upload_bytes <= 0 {
            return Ok(false);
        }

        let content_length = session
            .get_header("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);

        if content_length > max_upload_bytes
            || (!ctx.request_body.is_empty() && (ctx.request_body.len() as i64) > max_upload_bytes)
        {
            ctx.response_status = 413;
            return self.respond_status_with_pages(session, ctx, 413).await;
        }

        Ok(false)
    }

    async fn enforce_request_limit(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        let Some(server) = ctx.server.as_ref() else {
            return Ok(false);
        };
        let Some(request_limit) = server
            .web
            .as_ref()
            .and_then(|web| web.request_limit.as_ref())
        else {
            return Ok(false);
        };
        if !request_limit.is_on {
            return Ok(false);
        }

        ctx.request_limit_out_bandwidth_bytes = request_limit.out_bandwidth_per_conn_bytes_value();
        if ctx.request_limit_out_bandwidth_bytes <= 0 {
            ctx.request_limit_out_bandwidth_sent = 0;
            ctx.request_limit_out_bandwidth_window_start = None;
        }

        if self
            .waf_state
            .is_whitelisted(ctx.client_ip, server.numeric_id())
        {
            return Ok(false);
        }

        let max_body_bytes = request_limit.max_body_bytes_value();
        if max_body_bytes > 0 {
            let content_length = session
                .get_header("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if content_length > max_body_bytes
                || (!ctx.request_body.is_empty()
                    && (ctx.request_body.len() as i64) > max_body_bytes)
            {
                ctx.response_status = 413;
                return self.respond_status_with_pages(session, ctx, 413).await;
            }
        }

        if !self.try_bind_request_limit_connection(
            &ctx.raw_remote_addr,
            server.numeric_id(),
            ctx.client_ip,
            request_limit.max_conns,
            request_limit.max_conns_per_ip,
        ) {
            ctx.response_status = 429;
            return self.respond_status_with_pages(session, ctx, 429).await;
        }

        Ok(false)
    }

    fn response_bandwidth_delay(
        &self,
        body_len: usize,
        ctx: &mut ProxyCTX,
    ) -> Option<std::time::Duration> {
        let limit = ctx.request_limit_out_bandwidth_bytes;
        if limit <= 0 || body_len == 0 {
            return None;
        }

        let now = std::time::Instant::now();
        let window_start = ctx
            .request_limit_out_bandwidth_window_start
            .get_or_insert(now);

        if now.duration_since(*window_start) >= std::time::Duration::from_secs(1) {
            *window_start = now;
            ctx.request_limit_out_bandwidth_sent = 0;
        }

        ctx.request_limit_out_bandwidth_sent += body_len as i64;
        if ctx.request_limit_out_bandwidth_sent < limit {
            return None;
        }

        let elapsed = now.duration_since(*window_start);
        ctx.request_limit_out_bandwidth_sent = 0;
        *window_start = now;

        if elapsed < std::time::Duration::from_secs(1) {
            Some(std::time::Duration::from_secs(1) - elapsed)
        } else {
            None
        }
    }

    fn apply_charset_to_response(
        &self,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut ProxyCTX,
    ) {
        let Some(server) = ctx.server.as_ref() else {
            return;
        };
        let Some(charset_cfg) = server.web.as_ref().and_then(|web| web.charset.as_ref()) else {
            return;
        };
        if !charset_cfg.is_on || charset_cfg.charset.is_empty() {
            return;
        }

        let Some(current) = upstream_response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            return;
        };

        let mut mime = current.to_string();
        if charset_cfg.force
            && let Some((head, _)) = current.split_once(';')
        {
            mime = head.trim().to_string();
        }

        if !TEXT_MIME_TYPES
            .iter()
            .any(|allowed| mime.eq_ignore_ascii_case(allowed))
        {
            return;
        }

        let charset = if charset_cfg.is_upper {
            charset_cfg.charset.to_ascii_uppercase()
        } else {
            charset_cfg.charset.clone()
        };
        let content_type = format!("{}; charset={}", mime, charset);
        upstream_response.remove_header("content-type");
        let _ = upstream_response.insert_header("content-type", content_type.clone());
        ctx.response_headers
            .insert("content-type".to_string(), content_type);
    }

    fn current_request_url(session: &Session) -> String {
        let scheme = if session
            .downstream_session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
            .is_some()
            || session.req_header().uri.scheme_str() == Some("https")
        {
            "https"
        } else {
            "http"
        };
        let host = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v))
            .unwrap_or_else(|| session.req_header().uri.host().unwrap_or(""));
        let path = session
            .req_header()
            .uri
            .path_and_query()
            .map(|v| v.as_str())
            .unwrap_or("/");
        format!("{scheme}://{host}{path}")
    }

    fn current_request_path_query(session: &Session) -> String {
        session
            .req_header()
            .uri
            .path_and_query()
            .map(|v| v.as_str().to_string())
            .unwrap_or_else(|| session.req_header().uri.path().to_string())
    }

    fn strip_hls_query_from_query(query: &str) -> String {
        query
            .split('&')
            .filter(|item| !item.starts_with("hls_session=") && !item.starts_with("hls_exp="))
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>()
            .join("&")
    }

    fn default_cache_key_for_session(session: &Session) -> String {
        let scheme = if session
            .downstream_session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
            .is_some()
            || session.req_header().uri.scheme_str() == Some("https")
        {
            "https"
        } else {
            "http"
        };
        let host = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v))
            .unwrap_or_else(|| session.req_header().uri.host().unwrap_or(""));
        let path = session.req_header().uri.path();
        let query = session
            .req_header()
            .uri
            .query()
            .map(Self::strip_hls_query_from_query)
            .unwrap_or_default();

        if query.is_empty() {
            format!("{scheme}://{host}{path}")
        } else {
            format!("{scheme}://{host}{path}?{query}")
        }
    }

    fn query_param(session: &Session, name: &str) -> Option<String> {
        session.req_header().uri.query().and_then(|query| {
            query.split('&').find_map(|part| {
                let mut it = part.splitn(2, '=');
                let key = it.next()?;
                (key == name).then(|| it.next().unwrap_or("").to_string())
            })
        })
    }

    fn hmac_sha256(secret: &[u8], data: &[u8]) -> [u8; 32] {
        const BLOCK: usize = 64;
        let mut key = [0u8; BLOCK];
        if secret.len() > BLOCK {
            let digest = Sha256::digest(secret);
            key[..32].copy_from_slice(&digest);
        } else {
            key[..secret.len()].copy_from_slice(secret);
        }

        let mut o_key_pad = [0u8; BLOCK];
        let mut i_key_pad = [0u8; BLOCK];
        for i in 0..BLOCK {
            o_key_pad[i] = key[i] ^ 0x5c;
            i_key_pad[i] = key[i] ^ 0x36;
        }

        let mut inner = Sha256::new();
        inner.update(i_key_pad);
        inner.update(data);
        let inner_digest = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(o_key_pad);
        outer.update(inner_digest);
        let digest = outer.finalize();

        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn hls_key_material(
        &self,
        server_id: i64,
        target: &str,
        session_id: &str,
        exp: i64,
    ) -> ([u8; 16], [u8; 16], String) {
        let secret = self.api_config.secret.as_bytes();
        let scope = format!("{server_id}|{target}|{session_id}|{exp}");

        let key_digest = Self::hmac_sha256(secret, format!("hls-key|{scope}").as_bytes());
        let iv_digest = Self::hmac_sha256(secret, format!("hls-iv|{scope}").as_bytes());
        let sig_digest = Self::hmac_sha256(secret, format!("hls-token|{scope}").as_bytes());

        let mut key = [0u8; 16];
        key.copy_from_slice(&key_digest[..16]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&iv_digest[..16]);
        (key, iv, hex::encode(sig_digest))
    }

    fn new_hls_session(&self) -> (String, i64) {
        let session_id = general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>());
        let exp = crate::utils::time::now_timestamp() + 300;
        (session_id, exp)
    }

    fn hls_key_uri(&self, server_id: i64, target: &str, session_id: &str, exp: i64) -> String {
        let (_, _, sig) = self.hls_key_material(server_id, target, session_id, exp);
        let path = general_purpose::URL_SAFE_NO_PAD.encode(target.as_bytes());
        format!(
            "{HLS_KEY_ROUTE}?sid={server_id}&path={path}&session={session_id}&exp={exp}&token={sig}"
        )
    }

    async fn maybe_serve_hls_key(&self, session: &mut Session, ctx: &mut ProxyCTX) -> Result<bool> {
        if session.req_header().uri.path() != HLS_KEY_ROUTE {
            return Ok(false);
        }

        let server_id = Self::query_param(session, "sid")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let encoded_path = Self::query_param(session, "path").unwrap_or_default();
        let session_id = Self::query_param(session, "session").unwrap_or_default();
        let exp = Self::query_param(session, "exp")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let provided_sig = Self::query_param(session, "token").unwrap_or_default();
        if server_id <= 0
            || encoded_path.is_empty()
            || session_id.is_empty()
            || exp <= 0
            || provided_sig.is_empty()
        {
            ctx.response_status = 403;
            return self.respond_status_with_pages(session, ctx, 403).await;
        }
        if crate::utils::time::now_timestamp() > exp {
            ctx.response_status = 403;
            return self.respond_status_with_pages(session, ctx, 403).await;
        }

        let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(encoded_path.as_bytes()) else {
            ctx.response_status = 403;
            return self.respond_status_with_pages(session, ctx, 403).await;
        };
        let Ok(target) = String::from_utf8(decoded) else {
            ctx.response_status = 403;
            return self.respond_status_with_pages(session, ctx, 403).await;
        };

        let Some(server) = self.config.get_server_by_id(server_id).await else {
            ctx.response_status = 404;
            return self.respond_status_with_pages(session, ctx, 404).await;
        };
        let Some(encrypting) = server
            .web
            .as_ref()
            .and_then(|web| web.hls.as_ref())
            .and_then(|hls| hls.encrypting.as_ref())
            .filter(|cfg| cfg.is_on && cfg.matches_url(&target))
        else {
            ctx.response_status = 403;
            return self.respond_status_with_pages(session, ctx, 403).await;
        };
        let _ = encrypting;

        let (key, _, expected_sig) = self.hls_key_material(server_id, &target, &session_id, exp);
        if expected_sig != provided_sig {
            ctx.response_status = 403;
            return self.respond_status_with_pages(session, ctx, 403).await;
        }

        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "application/octet-stream")
            .unwrap();
        resp.insert_header("cache-control", "private, max-age=60")
            .unwrap();
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(key.to_vec())), true)
            .await?;
        ctx.response_status = 200;
        ctx.no_log = true;
        Ok(true)
    }

    async fn maybe_serve_acme_challenge(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        const ACME_PREFIX: &str = "/.well-known/acme-challenge/";

        let path = session.req_header().uri.path();
        let Some(token) = path.strip_prefix(ACME_PREFIX) else {
            return Ok(false);
        };
        if token.is_empty() || token.contains('/') {
            ctx.response_status = 404;
            return self.respond_status_with_pages(session, ctx, 404).await;
        }

        let Some(key) = crate::rpc::acme::find_acme_key(&self.api_config, token).await else {
            ctx.response_status = 404;
            return self.respond_status_with_pages(session, ctx, 404).await;
        };

        let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
        resp.insert_header("content-type", "text/plain; charset=utf-8")
            .unwrap();
        resp.insert_header("cache-control", "no-store").unwrap();
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(key)), true)
            .await?;
        ctx.response_status = 200;
        ctx.no_log = true;
        Ok(true)
    }

    fn normalize_hls_target(base_path: &str, target: &str) -> String {
        if target.starts_with("http://") || target.starts_with("https://") {
            if let Some(idx) = target.find("://")
                && let Some(path_idx) = target[idx + 3..].find('/')
            {
                return target[idx + 3 + path_idx..].to_string();
            }
            return target.to_string();
        }
        if target.starts_with('/') {
            return target.to_string();
        }

        let mut parts: Vec<&str> = base_path
            .split('?')
            .next()
            .unwrap_or(base_path)
            .split('/')
            .collect();
        if !parts.is_empty() {
            parts.pop();
        }
        for piece in target.split('/') {
            match piece {
                "" | "." => {}
                ".." => {
                    if parts.len() > 1 {
                        parts.pop();
                    }
                }
                _ => parts.push(piece),
            }
        }
        let mut normalized = parts.join("/");
        if !normalized.starts_with('/') {
            normalized.insert(0, '/');
        }
        normalized
    }

    fn is_hls_encrypted_request(&self, session: &Session, server: &ServerConfig) -> bool {
        let Some(encrypting) = server
            .web
            .as_ref()
            .and_then(|web| web.hls.as_ref())
            .and_then(|hls| hls.encrypting.as_ref())
        else {
            return false;
        };
        if !encrypting.is_on {
            return false;
        }
        let path = session.req_header().uri.path().to_ascii_lowercase();
        if !path.ends_with(".m3u8") && !path.ends_with(".ts") {
            return false;
        }
        encrypting.matches_url(&Self::current_request_url(session))
    }

    fn strip_hls_session_query(path_and_query: &str) -> String {
        let mut parts = path_and_query.splitn(2, '?');
        let path = parts.next().unwrap_or("");
        let Some(query) = parts.next() else {
            return path.to_string();
        };

        let filtered: Vec<&str> = query
            .split('&')
            .filter(|item| !item.starts_with("hls_session=") && !item.starts_with("hls_exp="))
            .collect();

        if filtered.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, filtered.join("&"))
        }
    }

    fn rewrite_hls_playlist(&self, playlist: &str, server_id: i64, playlist_path: &str) -> String {
        let (session_id, exp) = self.new_hls_session();
        let mut output = Vec::new();
        for line in playlist.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                output.push(line.to_string());
                continue;
            }

            if trimmed.ends_with(".ts") || trimmed.contains(".ts?") {
                let target = Self::normalize_hls_target(playlist_path, trimmed);
                let (_, iv, _) = self.hls_key_material(server_id, &target, &session_id, exp);
                let key_uri = self.hls_key_uri(server_id, &target, &session_id, exp);
                let joiner = if trimmed.contains('?') { '&' } else { '?' };
                let segment_url = format!(
                    "{}{}hls_session={}&hls_exp={}",
                    trimmed, joiner, session_id, exp
                );
                output.push(format!(
                    "#EXT-X-KEY:METHOD=AES-128,URI=\"{}\",IV=0x{}",
                    key_uri,
                    hex::encode(iv)
                ));
                output.push(segment_url);
                continue;
            }
            output.push(line.to_string());
        }
        output.join("\n")
    }

    fn aes128_cbc_encrypt(body: &[u8], key: [u8; 16], iv: [u8; 16]) -> Vec<u8> {
        let pad_len = 16 - (body.len() % 16);
        let mut padded = body.to_vec();
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        let cipher = Aes128::new(&GenericArray::from(key));
        let mut prev = iv;
        let mut out = Vec::with_capacity(padded.len());

        for chunk in padded.chunks_mut(16) {
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= prev[i];
            }
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            prev.copy_from_slice(&block);
        }

        out
    }

    fn minify_html(
        body: &[u8],
        config: &crate::config_models::HTTPHTMLOptimizationConfig,
    ) -> anyhow::Result<Vec<u8>> {
        let mut text = String::from_utf8(body.to_vec())?;
        if !config.keep_comments {
            let comment_re = Regex::new(r"<!--[\s\S]*?-->").expect("valid html comment regex");
            text = comment_re
                .replace_all(&text, |caps: &regex::Captures| {
                    let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                    if config.keep_conditional_comments
                        && (matched.contains("[if") || matched.contains("[endif"))
                    {
                        matched.to_string()
                    } else {
                        String::new()
                    }
                })
                .to_string();
        }
        if !config.keep_whitespace {
            let between_tags = Regex::new(r">\s+<").expect("valid html spacing regex");
            text = between_tags.replace_all(&text, "><").to_string();
            let multi_space = Regex::new(r"[ \t\r\n]{2,}").expect("valid html multi-space regex");
            text = multi_space.replace_all(&text, " ").to_string();
        }
        Ok(text.into_bytes())
    }

    fn minify_css(body: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut text = String::from_utf8(body.to_vec())?;
        let comments = Regex::new(r"/\*[\s\S]*?\*/").expect("valid css comment regex");
        text = comments.replace_all(&text, "").to_string();
        let spaces = Regex::new(r"\s+").expect("valid css whitespace regex");
        text = spaces.replace_all(&text, " ").to_string();
        let tokens = Regex::new(r"\s*([{}:;,>])\s*").expect("valid css token regex");
        text = tokens.replace_all(&text, "$1").to_string();
        Ok(text.trim().as_bytes().to_vec())
    }

    fn minify_js(body: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut text = String::from_utf8(body.to_vec())?;
        let block_comments = Regex::new(r"/\*[\s\S]*?\*/").expect("valid js comment regex");
        text = block_comments.replace_all(&text, "").to_string();
        let line_comments = Regex::new(r"(?m)^\s*//.*$").expect("valid js line comment regex");
        text = line_comments.replace_all(&text, "").to_string();
        let spaces = Regex::new(r"\s+").expect("valid js whitespace regex");
        text = spaces.replace_all(&text, " ").to_string();
        Ok(text.trim().as_bytes().to_vec())
    }

    fn maybe_enable_optimization(
        &self,
        session: &Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut ProxyCTX,
    ) {
        ctx.optimize_enabled = false;
        ctx.optimize_kind = None;
        ctx.optimize_pending_body.clear();

        if upstream_response.status.as_u16() != 200
            || ctx.cache_ref.is_none()
            || upstream_response.headers.get("content-encoding").is_some()
        {
            return;
        }
        let Some(content_length) = Self::response_content_length(upstream_response) else {
            return;
        };
        if content_length > MAX_OPTIMIZATION_BODY_BYTES {
            return;
        }

        let Some(server) = ctx.server.as_ref() else {
            return;
        };
        let Some(optimization) = server
            .web
            .as_ref()
            .and_then(|web| web.optimization.as_ref())
        else {
            return;
        };
        if !optimization.is_on() {
            return;
        }

        let request_url = Self::current_request_url(session);
        let content_type = upstream_response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        let kind = if content_type == "text/html" || content_type == "application/xhtml+xml" {
            optimization
                .html
                .as_ref()
                .filter(|cfg| cfg.is_on && cfg.base.matches_url(&request_url))
                .map(|_| "html")
        } else if content_type == "text/css" {
            optimization
                .css
                .as_ref()
                .filter(|cfg| cfg.is_on && cfg.base.matches_url(&request_url))
                .map(|_| "css")
        } else if content_type == "text/javascript"
            || content_type == "application/javascript"
            || content_type == "application/x-javascript"
        {
            optimization
                .javascript
                .as_ref()
                .filter(|cfg| cfg.is_on && cfg.base.matches_url(&request_url))
                .map(|_| "js")
        } else {
            None
        };

        if let Some(kind) = kind {
            ctx.optimize_enabled = true;
            ctx.optimize_kind = Some(kind.to_string());
            upstream_response.remove_header("content-length");
            ctx.response_headers.remove("content-length");
        }
    }

    fn maybe_enable_hls(
        &self,
        session: &Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut ProxyCTX,
    ) {
        ctx.hls_playlist_enabled = false;
        ctx.hls_segment_encrypt_enabled = false;
        ctx.hls_segment_key = None;
        ctx.hls_segment_iv = None;
        ctx.hls_segment_pending_body.clear();

        let Some(server) = ctx.server.as_ref() else {
            return;
        };
        let Some(hls) = server.web.as_ref().and_then(|web| web.hls.as_ref()) else {
            return;
        };
        let Some(encrypting) = hls.encrypting.as_ref() else {
            return;
        };
        if !encrypting.is_on || upstream_response.status.as_u16() != 200 {
            return;
        }

        let request_url = Self::current_request_url(session);
        if !encrypting.matches_url(&request_url) {
            return;
        }
        let Some(content_length) = Self::response_content_length(upstream_response) else {
            return;
        };

        let path = session.req_header().uri.path().to_ascii_lowercase();
        if path.ends_with(".m3u8") {
            if content_length > MAX_HLS_PLAYLIST_BODY_BYTES {
                return;
            }
            ctx.hls_playlist_enabled = true;
            upstream_response.remove_header("content-length");
            let _ =
                upstream_response.insert_header("content-type", "application/vnd.apple.mpegurl");
            ctx.response_headers.insert(
                "content-type".to_string(),
                "application/vnd.apple.mpegurl".to_string(),
            );
        } else if path.ends_with(".ts") {
            let target = Self::strip_hls_session_query(&Self::current_request_path_query(session));
            let session_id = Self::query_param(session, "hls_session");
            let exp = Self::query_param(session, "hls_exp").and_then(|v| v.parse::<i64>().ok());
            let (Some(session_id), Some(exp)) = (session_id, exp) else {
                return;
            };
            if crate::utils::time::now_timestamp() > exp {
                return;
            }
            if content_length > MAX_HLS_SEGMENT_BODY_BYTES {
                return;
            }
            let (key, iv, _) =
                self.hls_key_material(server.numeric_id(), &target, &session_id, exp);
            ctx.hls_segment_encrypt_enabled = true;
            ctx.hls_segment_key = Some(key);
            ctx.hls_segment_iv = Some(iv);
            ctx.hls_session_id = Some(session_id);
            ctx.hls_session_exp = Some(exp);
            let _ = upstream_response.insert_header("content-type", "video/mp2t");
            ctx.response_headers
                .insert("content-type".to_string(), "video/mp2t".to_string());
            upstream_response.remove_header("content-length");
            ctx.response_headers.remove("content-length");
        }
    }

    fn resolve_traffic_limit_config(
        &self,
        server: &ServerConfig,
    ) -> Option<crate::config_models::TrafficLimitConfig> {
        if let Some(config) = server.traffic_limit.as_ref()
            && config.is_on
        {
            return Some(config.clone());
        }

        if server.user_plan_id <= 0 {
            return None;
        }

        let user_plan = self.config.get_user_plan_sync(server.user_plan_id)?;
        let plan = self.config.get_plan_sync(user_plan.plan_id)?;
        if plan.traffic_limit_json.is_empty() {
            return None;
        }

        let config = serde_json::from_slice::<crate::config_models::TrafficLimitConfig>(
            &plan.traffic_limit_json,
        )
        .ok()?;

        config.is_on.then_some(config)
    }

    async fn enforce_traffic_limit(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        let Some(server) = ctx.server.as_ref() else {
            return Ok(false);
        };
        if !server.has_valid_traffic_limit() {
            return Ok(false);
        }

        let body = self
            .resolve_traffic_limit_config(server)
            .and_then(|config| {
                (!config.notice_page_body.is_empty()).then_some(config.notice_page_body)
            })
            .unwrap_or_else(|| DEFAULT_TRAFFIC_LIMIT_NOTICE_PAGE_BODY.to_string());

        ctx.response_status = 509;
        let resolved_body = self.render_page_template(session, ctx, &body, 509);
        let mut resp = pingora_http::ResponseHeader::build(509, None).unwrap();
        resp.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(resolved_body)), true)
            .await?;
        Ok(true)
    }

    fn check_waf_challenge(
        &self,
        session: &Session,
        ip_str: &str,
        ua: &str,
        ctx: &ProxyCTX,
    ) -> bool {
        let verifier = crate::firewall::verifier::WafVerifier::new(&self.api_config.secret);

        if let Some(cookies) = session.get_header("cookie").and_then(|v| v.to_str().ok()) {
            let mut current_token = None;
            let mut current_pow = None;

            for part in cookies.split(';') {
                let part = part.trim();
                // 1. Check AES-256-GCM Token
                if let Some(token) = part.strip_prefix("WAF-Token=") {
                    if verifier.verify_token(ip_str, ua, token, 3600) {
                        current_token = Some(token);
                    }
                }
                // 2. Check PoW Solution
                if let Some(pow) = part.strip_prefix("WAF-PoW=") {
                    current_pow = Some(pow);
                }
            }

            if let (Some(token), Some(nonce)) = (current_token, current_pow) {
                // Strict Server-side verify
                if verifier.verify_pow(token, nonce, 4) {
                    if let Ok(ip) = ip_str.parse() {
                        let server_id = ctx.server.as_ref().map(|s| s.numeric_id()).unwrap_or(0);
                        self.waf_state
                            .unblock_ip(ip, server_id, Some("server"), true);
                    }
                    return true;
                }
            }
        }
        false
    }

    async fn respond_waf_action(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        matched: crate::firewall::MatchedAction,
        ip: String,
    ) -> Result<bool> {
        let action = matched.action;
        let global_actions = self.config.get_waf_actions_sync();

        match action {
            crate::firewall::ActionResponse::Allow => Ok(false),
            crate::firewall::ActionResponse::Block {
                mut status,
                mut body,
            } => {
                let mut final_timeout = matched.timeout_secs.unwrap_or(300);
                let mut scope = matched.scope.as_deref().unwrap_or("server");
                let mut max_timeout = 0;
                let mut fail_global = false;

                // Priority 1: From MatchedAction (Policy/Website Level)
                if let Some(opts) = &matched.block_options {
                    if opts.status_code > 0 {
                        status = opts.status_code;
                    }
                    if !opts.body.is_empty() {
                        body = opts.body.clone();
                    }
                    if opts.timeout > 0 {
                        final_timeout = opts.timeout as i64;
                    }
                    max_timeout = opts.max_timeout;
                    fail_global = opts.fail_global;
                }
                // Priority 2: From Global Default WAF Actions
                else if let Some(global) = global_actions.iter().find(|a| a.code == "block") {
                    if let Ok(opts) = serde_json::from_value::<crate::config_models::WAFBlockOptions>(
                        global.options.clone(),
                    ) {
                        if opts.status_code > 0 {
                            status = opts.status_code;
                        }
                        if !opts.body.is_empty() {
                            body = opts.body;
                        }
                        if opts.timeout > 0 {
                            final_timeout = opts.timeout as i64;
                        }
                        max_timeout = opts.max_timeout;
                        fail_global = opts.fail_global;
                    }
                }

                // Apply randomized timeout logic
                if max_timeout > final_timeout as i32 {
                    use rand::Rng;
                    final_timeout =
                        rand::thread_rng().gen_range(final_timeout..=max_timeout as i64);
                }
                if fail_global {
                    scope = "global";
                }

                // Apply Block
                if let Ok(ip_addr) = ip.parse() {
                    self.waf_state.block_ip(
                        ip_addr,
                        ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                        final_timeout,
                        Some(scope),
                        matched.block_c_class,
                        matched.use_local_firewall,
                    );

                    // Report to API if ip_list_id is set
                    if matched.ip_list_id > 0 {
                        let ua = session
                            .get_header("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let url = format!(
                            "{}{}",
                            session.req_header().uri.host().unwrap_or(""),
                            session.req_header().uri.path()
                        );
                        let node_id = self.config.get_node_id().await;
                        crate::rpc::ip_report::report_block(
                            crate::rpc::ip_report::IpReportMessage {
                                ip_list_id: matched.ip_list_id,
                                value: ip.clone(),
                                ip_from: ip.clone(),
                                ip_to: "".to_string(),
                                expired_at: crate::utils::time::now_timestamp() + final_timeout,
                                reason: format!("WAF Action: {}", matched.action_code),
                                r#type: "black".to_string(),
                                event_level: matched.event_level,
                                node_id,
                                server_id: ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                                source_node_id: node_id,
                                source_server_id: ctx
                                    .server
                                    .as_ref()
                                    .and_then(|s| s.id)
                                    .unwrap_or(0),
                                source_http_firewall_policy_id: matched.policy_id,
                                source_http_firewall_rule_group_id: matched.group_id,
                                source_http_firewall_rule_set_id: matched.set_id,
                                source_url: url,
                                source_user_agent: ua,
                                source_category: "waf".to_string(),
                            },
                        );
                    }
                }

                let resolved_body = self.render_page_template(session, ctx, &body, status as u16);
                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                resp.insert_header("content-type", "text/html; charset=utf-8")
                    .unwrap();
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::from(resolved_body)), true)
                    .await?;
                Ok(true)
            }
            crate::firewall::ActionResponse::Page {
                mut status,
                mut body,
                content_type,
            } => {
                // Priority 1: From MatchedAction
                if let Some(opts) = &matched.page_options {
                    if opts.status > 0 {
                        status = opts.status;
                    }
                    if !opts.body.is_empty() {
                        body = opts.body.clone();
                    }
                }
                // Priority 2: From Global Default
                else if let Some(global) = global_actions.iter().find(|a| a.code == "page") {
                    if let Ok(opts) = serde_json::from_value::<crate::config_models::WAFPageOptions>(
                        global.options.clone(),
                    ) {
                        if opts.status > 0 {
                            status = opts.status;
                        }
                        if !opts.body.is_empty() {
                            body = opts.body;
                        }
                    }
                }
                let resolved_body = self.render_page_template(session, ctx, &body, status as u16);
                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                resp.insert_header("content-type", content_type).unwrap();
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::from(resolved_body)), true)
                    .await?;
                Ok(true)
            }
            crate::firewall::ActionResponse::Redirect { status, location } => {
                let resolved_url =
                    self.render_page_template(session, ctx, &location, status as u16);
                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                resp.insert_header("location", resolved_url).unwrap();
                session.write_response_header(Box::new(resp), true).await?;
                Ok(true)
            }
            crate::firewall::ActionResponse::Captcha { mut life_seconds }
            | crate::firewall::ActionResponse::JsCookie { mut life_seconds }
            | crate::firewall::ActionResponse::Get302 { mut life_seconds }
            | crate::firewall::ActionResponse::Post307 { mut life_seconds } => {
                let ua = session
                    .get_header("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let verifier = crate::firewall::verifier::WafVerifier::new(&self.api_config.secret);
                let token = verifier.generate_token(&ip, ua);

                let (status, is_redirect) = match action {
                    crate::firewall::ActionResponse::Get302 { .. } => (302, true),
                    crate::firewall::ActionResponse::Post307 { .. } => (307, true),
                    _ => (403, false),
                };

                let mut captcha_opts = matched.captcha_options.clone();
                let mut js_opts = matched.js_cookie_options.clone();

                // Fallback to Global Defaults
                if captcha_opts.is_none() {
                    if let Some(global) = global_actions.iter().find(|a| a.code == "captcha") {
                        captcha_opts = serde_json::from_value(global.options.clone()).ok();
                    }
                }
                if js_opts.is_none() {
                    if let Some(global) = global_actions.iter().find(|a| a.code == "js_cookie") {
                        js_opts = serde_json::from_value(global.options.clone()).ok();
                    }
                }

                let mut body_html = String::new();
                let mut template = "<!doctype html><html><head><title>${title}</title><style>${css}</style></head><body>${promptHeader}${body}${promptFooter}</body></html>".to_string();

                if let Some(opts) = &captcha_opts {
                    if opts.life_seconds > 0 {
                        life_seconds = opts.life_seconds as i64;
                    }
                    if let Some(ui) = &opts.ui {
                        if !ui.template.is_empty() {
                            template = ui.template.clone();
                        }
                        let mut form = format!(
                            "<form method='GET' class='waf-form'><input type='hidden' name='__waf_token' value='{}'/><button type='submit' class='verify-btn'>{}</button></form>",
                            token, ui.button_title
                        );
                        if ui.show_request_id {
                            form.push_str(&format!(
                                "<p class='request-id'>Request ID: {}</p>",
                                "0"
                            ));
                        }

                        body_html = template
                            .replace("${title}", &ui.title)
                            .replace("${css}", &ui.css)
                            .replace("${promptHeader}", &ui.prompt_header)
                            .replace("${promptFooter}", &ui.prompt_footer)
                            .replace("${body}", &form);
                    }
                }

                if body_html.is_empty() {
                    if let Some(opts) = &js_opts {
                        if opts.life_seconds > 0 {
                            life_seconds = opts.life_seconds as i64;
                        }
                    }

                    let pow_script = verifier.get_pow_script(&token, 4); // Difficulty 4
                    body_html = if matches!(
                        action,
                        crate::firewall::ActionResponse::JsCookie { .. }
                    ) {
                        format!(
                            "<!doctype html><html><body><script>{}</script><script>document.cookie='WAF-Token={}; Path=/; Max-Age={}';</script></body></html>",
                            pow_script, token, life_seconds
                        )
                    } else {
                        format!(
                            "<!doctype html><html><head><script>{}</script></head><body><h1>Antigravity Security Verification</h1><p>Solving proof-of-work challenge...</p><form style='display:none'><input type='hidden' name='__waf_token' value='{}'/></form></body></html>",
                            pow_script, token
                        )
                    };
                }

                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                if is_redirect {
                    let mut path_and_query = session.req_header().uri.path().to_string();
                    let connector = if path_and_query.contains('?') {
                        "&"
                    } else {
                        "?"
                    };
                    path_and_query.push_str(&format!("{connector}__waf_token={token}"));
                    resp.insert_header("location", path_and_query).unwrap();
                    session.write_response_header(Box::new(resp), true).await?;
                } else {
                    resp.insert_header("content-type", "text/html; charset=utf-8")
                        .unwrap();
                    resp.insert_header(
                        "set-cookie",
                        format!("WAF-Token={token}; Path=/; HttpOnly; Max-Age={life_seconds}"),
                    )
                    .unwrap();
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(Bytes::from(body_html)), true)
                        .await?;
                }
                Ok(true)
            }
        }
    }
}

#[async_trait]
impl ProxyHttp for EdgeProxy {
    type CTX = ProxyCTX;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCTX::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let hot_path = self.config.get_hot_path_snapshot_sync();

        // --- GLOBAL CLUSTER SETTINGS: Node Enabled (isOn) ---
        ctx.is_on = hot_path.is_on;
        if !ctx.is_on {
            debug!("Node is DISABLED (isOn=false). Rejecting request.");
            return self.respond_status_with_pages(session, ctx, 403).await;
        }

        let host = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v)) // Remove port if present
            .unwrap_or_else(|| session.req_header().uri.host().unwrap_or(""))
            .to_lowercase();

        if self.maybe_serve_hls_key(session, ctx).await? {
            return Ok(true);
        }
        if self.maybe_serve_acme_challenge(session, ctx).await? {
            return Ok(true);
        }

        let (server, upstream) = self.config.get_server_and_upstream_sync(&host);
        ctx.server = server;
        ctx.lb = upstream;

        let _is_loopback = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|i| i.ip().is_loopback())
            .unwrap_or(false);

        let (mut detected_ip, detected_port, raw_remote_addr) = Self::socket_client_ip(session);
        ctx.client_ip = detected_ip;
        ctx.client_port = detected_port;
        ctx.raw_remote_addr = raw_remote_addr;

        ctx.is_http3_bridge = session.get_header("X-Cloud-Http3-Bridge").is_some();

        if let Some(edge_ip) = session.get_header("X-Cloud-Real-Ip") {
            if let Ok(ip_str) = edge_ip.to_str() {
                if let Ok(parsed_ip) = ip_str.parse::<std::net::IpAddr>() {
                    debug!("L2: Restoring real client IP {} from L1 header", parsed_ip);
                    detected_ip = parsed_ip;
                    ctx.client_ip = parsed_ip;
                }
            }
        }
        if let Some(edge_port) = session.get_header("X-Cloud-Real-Port")
            && let Ok(port_str) = edge_port.to_str()
            && let Ok(port) = port_str.parse::<u16>()
        {
            ctx.client_port = port;
        }

        ctx.client_ip = self.resolve_client_ip(
            session,
            ctx.server.as_ref().map(|v| &**v),
            detected_ip,
            &ctx.raw_remote_addr,
            ctx.client_port,
        );
        if let Some(user_agent) = session
            .get_header("user-agent")
            .and_then(|v| v.to_str().ok())
            .filter(|ua| !ua.is_empty())
        {
            crate::client_agent::maybe_report_client_agent(
                (*self.api_config).clone(),
                ctx.client_ip.to_string(),
                user_agent.to_string(),
            );
        }

        let ip_str = ctx.client_ip.to_string();

        let is_test = session.get_header("x-cloud-preheat").is_some();

        // Handle internal cache test (FULL PATH SIMULATION)
        if is_test {
            // 1. Buffer the value from API
            let mut buffered = Vec::new();
            while let Ok(Some(chunk)) = session.read_request_body().await {
                buffered.extend_from_slice(&chunk);
                if buffered.len() >= 2 * 1024 * 1024 {
                    break;
                }
            }
            ctx.request_body = buffered;
            ctx.no_log = true;

            // 2. Perform direct storage write to ensure Key match and NO PANICS
            // We use the Host header as the raw Key (parity with readCache)
            let hash = format!("{:x}", md5_legacy::compute(&host));
            let root = std::path::Path::new("../data/cache");
            let file_path = root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);

            if let Some(parent) = file_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            use std::io::Write;
            if let Ok(mut file) = std::fs::File::create(&file_path) {
                let _ = file.write_all(&ctx.request_body);
            }

            let mut headers_json = serde_json::Map::new();
            headers_json.insert(
                "content-type".to_string(),
                serde_json::Value::String("text/plain".to_string()),
            );

            crate::metrics::storage::STORAGE.update_cache_meta(
                &hash,
                &host,
                ctx.request_body.len() as u64,
                3600,
                Some(serde_json::Value::Object(headers_json)),
                false,
                200,
            );

            debug!(
                "Internal cache test write success: key={}, hash={}, size={}",
                host,
                hash,
                ctx.request_body.len()
            );

            // 3. Respond and stop to avoid Pingora Phase machine panic
            let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
            resp.insert_header("x-cloud-test", "1").unwrap();
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from("OK")), true)
                .await?;
            return Ok(true);
        }

        if let Some(server) = &ctx.server {
            if let Some(web) = &server.web
                && let Some(ws) = &web.websocket
                && ws.is_on
            {
                ctx.is_websocket = true;
                ctx.is_grpc = true; // Restore coupling: WebSocket on = gRPC support on
            }
            if let Some(grpc) = &server.grpc {
                if grpc.is_on {
                    ctx.is_grpc = true;
                }
            }

            // Apply gRPC message size limits if enabled
            if ctx.is_grpc {
                let max_recv = hot_path
                    .grpc_policy
                    .as_ref()
                    .and_then(|p| p.max_receive_message_size.as_ref())
                    .map(|s| s.to_bytes())
                    .unwrap_or(0);
                let final_max_recv = if max_recv <= 0 {
                    2 * 1024 * 1024
                } else {
                    max_recv
                };

                // For gRPC, we increase the inspection limit to allow larger messages
                ctx.max_inspection_size = final_max_recv;
                debug!(
                    "gRPC enabled for request, setting max_inspection_size to {} bytes",
                    final_max_recv
                );
            }
        }

        // --- GLOBAL CLUSTER SETTINGS: Low Version HTTP ---
        let global_cfg = hot_path.global_http.clone();
        if !global_cfg.supports_low_version_http {
            if session.req_header().version < pingora_http::Version::HTTP_11 {
                debug!(
                    "Blocking low version HTTP request: {:?}",
                    session.req_header().version
                );
                return self.respond_status_with_pages(session, ctx, 400).await;
            }
        }

        if ctx.server.is_none() {
            debug!(
                "404 Not Found for host: '{}'. Registered hosts: {:?}",
                host,
                self.config.get_all_hosts_sync()
            );
            return self.respond_status_with_pages(session, ctx, 404).await;
        }

        if let Some(server) = ctx.server.clone()
            && let Some(web) = server.web.clone()
        {
            if let Some((location, status)) = self.should_redirect_to_https(session, &server, &host)
            {
                let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                resp.insert_header("location", location).unwrap();
                session.write_response_header(Box::new(resp), true).await?;
                ctx.response_status = status;
                return Ok(true);
            }

            if let Some(shutdown) = web.shutdown.clone()
                && self.respond_shutdown(session, ctx, &shutdown).await?
            {
                return Ok(true);
            }
        }

        if ctx.lb.is_none() {
            if let Some(server) = &ctx.server {
                debug!("LB missing for host '{}', rebuilding manually.", host);
                let (level, parents) = self.config.get_tiered_origin_info().await;
                let bypass = self.config.is_tiered_origin_bypass().await;

                let rp_cfg = match &server.reverse_proxy {
                    Some(rp) => rp,
                    None => {
                        session.respond_error(502).await?;
                        return Ok(true);
                    }
                };

                let server_id = server.numeric_id();
                let (lb_arc, _has_hc) = crate::lb_factory::build_lb(
                    server_id,
                    rp_cfg,
                    level,
                    &parents,
                    bypass,
                    global_cfg.allow_lan_ip,
                );
                ctx.lb = Some(lb_arc.clone());

                self.config
                    .cache_server_route(host.clone(), server.clone(), lb_arc)
                    .await;
            }
        }

        if self.waf_state.is_whitelisted(
            ctx.client_ip,
            ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
        ) {
            return Ok(false);
        }

        let ua = session
            .get_header("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if self.check_waf_challenge(session, &ip_str, ua, ctx) {
            return Ok(false);
        }

        // Record request start for global metrics
        ctx.request_id = crate::logging::next_request_id();
        let user_plan_id = ctx.server.as_ref().map(|s| s.user_plan_id).unwrap_or(0);
        let plan_id = if user_plan_id > 0 {
            self.config
                .get_user_plan_sync(user_plan_id)
                .map(|user_plan| user_plan.plan_id)
                .unwrap_or(0)
        } else {
            0
        };
        crate::metrics::record::request_start(
            ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
            ip_str.clone(),
            ctx.server.as_ref().map(|s| s.user_id).unwrap_or(0),
            user_plan_id,
            plan_id,
        );

        if self.enforce_request_limit(session, ctx).await? {
            return Ok(true);
        }

        if self.enforce_traffic_limit(session, ctx).await? {
            return Ok(true);
        }

        if self.enforce_plan_max_upload(session, ctx).await? {
            return Ok(true);
        }

        if self.waf_state.is_blocked(
            ctx.client_ip,
            ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
        ) {
            return self.respond_status_with_pages(session, ctx, 403).await;
        }

        // 1. Mandatory Global Special Defenses
        let global_policies = &hot_path.firewall_policies;
        for gp in global_policies {
            if !gp.is_on {
                continue;
            }

            // 1.1 Empty Connection Flood
            if let Some(cfg) = &gp.empty_connection_flood {
                if cfg.is_on {
                    let threshold = cfg.threshold.max(10);
                    let period = if cfg.period > 0 {
                        cfg.period as i64
                    } else {
                        60
                    };
                    let ban = if cfg.ban_duration > 0 {
                        cfg.ban_duration as i64
                    } else {
                        3600
                    };

                    if !self.waf_state.check_special_defense(
                        format!("ECF:{}", ip_str),
                        threshold,
                        period,
                    ) {
                        self.waf_state.block_ip(
                            ctx.client_ip,
                            0,
                            ban,
                            Some("global"),
                            false,
                            gp.use_local_firewall,
                        );
                        return self.respond_status_with_pages(session, ctx, 403).await;
                    }
                }
            }

            // 1.2 TLS Exhaustion Attack
            if let Some(cfg) = &gp.tls_exhaustion_attack {
                let is_tls = session
                    .downstream_session
                    .digest()
                    .and_then(|d| d.ssl_digest.as_ref())
                    .is_some();
                if cfg.is_on && (is_tls || session.req_header().uri.scheme_str() == Some("https")) {
                    let threshold = cfg.threshold.max(10);
                    let period = if cfg.period > 0 {
                        cfg.period as i64
                    } else {
                        60
                    };
                    let ban = if cfg.ban_duration > 0 {
                        cfg.ban_duration as i64
                    } else {
                        3600
                    };

                    if !self.waf_state.check_special_defense(
                        format!("TLS:{}", ip_str),
                        threshold,
                        period,
                    ) {
                        self.waf_state.block_ip(
                            ctx.client_ip,
                            0,
                            ban,
                            Some("global"),
                            true,
                            gp.use_local_firewall,
                        );
                        return self.respond_status_with_pages(session, ctx, 403).await;
                    }
                }
            }
        }

        if self.enforce_uam(session, ctx, &ip_str).await? {
            return Ok(true);
        }

        // 2. Evaluate WAF Policies
        let mut waf_action = None;

        // --- BUFFERING REQUEST BODY (Max 2MB) ---
        if ctx.request_body.is_empty() {
            let content_length = session
                .get_header("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);

            if content_length > 0 && content_length <= 2 * 1024 * 1024 {
                let mut buffered = Vec::with_capacity(content_length);
                while let Some(chunk) = session.read_request_body().await? {
                    buffered.extend_from_slice(&chunk);
                    if buffered.len() >= content_length {
                        break;
                    }
                }
                ctx.request_body = buffered;
            }
        }
        // --- END BUFFERING ---

        if self.enforce_plan_max_upload(session, ctx).await? {
            return Ok(true);
        }

        if let Some(server) = &ctx.server
            && let Some(web) = &server.web
            && let Some(firewall_ref) = &web.firewall_ref
            && firewall_ref.is_on
        {
            // 2.1 Site-Level Policy
            if let Some(policy) = &web.firewall_policy {
                if policy.is_on {
                    // Check Request Body Size
                    if policy.max_request_body_size > 0 {
                        let content_length = session
                            .get_header("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<i64>().ok())
                            .unwrap_or(0);

                        if content_length > policy.max_request_body_size
                            || (ctx.request_body.len() as i64) > policy.max_request_body_size
                        {
                            waf_action = Some(crate::firewall::MatchedAction {
                                action: crate::firewall::ActionResponse::Block {
                                    status: 413,
                                    body: "Request Entity Too Large".to_string(),
                                },
                                policy_id: policy.id,
                                group_id: 0,
                                set_id: 0,
                                action_code: "block".to_string(),
                                timeout_secs: Some(3600),
                                max_timeout_secs: None,
                                life_seconds: None,
                                max_fails: 0,
                                fail_block_timeout: 0,
                                scope: None,
                                block_c_class: false,
                                use_local_firewall: false,
                                next_group_id: None,
                                next_set_id: None,
                                allow_scope: None,
                                tags: vec![],
                                ip_list_id: 0,
                                event_level: "error".to_string(),
                                block_options: None,
                                page_options: None,
                                captcha_options: None,
                                js_cookie_options: None,
                            });
                        }
                    }
                    if waf_action.is_none() {
                        waf_action =
                            crate::firewall::evaluate_policy(policy, session, &ctx.request_body);
                    }
                }
            }

            // 2.2 Global Policies (if not ignored)
            if waf_action.is_none() && !firewall_ref.ignore_global_rules {
                for gp in global_policies {
                    if gp.is_on {
                        if let Some(action) =
                            crate::firewall::evaluate_policy(gp, session, &ctx.request_body)
                        {
                            waf_action = Some(action);
                            break;
                        }
                    }
                }
            }
        }

        if let Some(matched) = waf_action {
            ctx.waf_policy_id = matched.policy_id;
            ctx.waf_group_id = matched.group_id;
            ctx.waf_set_id = matched.set_id;
            ctx.waf_action = Some(matched.action_code.clone());
            self.maybe_report_firewall_event(
                ctx,
                matched.policy_id,
                matched.group_id,
                matched.set_id,
            );

            if matched.action_code == "record_ip_white" {
                self.waf_state.unblock_ip(
                    ctx.client_ip,
                    ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                    matched.scope.as_deref(),
                    matched.use_local_firewall,
                );
                return Ok(false);
            }

            if matches!(matched.action_code.as_str(), "block" | "record_ip") {
                let mut final_timeout = matched.timeout_secs.unwrap_or(300);
                if let Some(max_t) = matched.max_timeout_secs {
                    if max_t > final_timeout {
                        final_timeout = rand::thread_rng().gen_range(final_timeout..=max_t);
                    }
                }

                self.waf_state.block_ip(
                    ctx.client_ip,
                    ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                    final_timeout,
                    matched.scope.as_deref(),
                    matched.block_c_class,
                    matched.use_local_firewall,
                );
            }
            if self
                .respond_waf_action(session, ctx, matched.clone(), ip_str.clone())
                .await?
            {
                return Ok(true);
            }
        }

        // 3. CC Basic Defense & Rate Limit
        if let Some(server) = &ctx.server
            && let Some(web) = &server.web
        {
            let site_cc_policy = web.cc_policy.clone();
            let site_server_id = server.id.unwrap_or(0);
            let host_redirects = web.host_redirects.clone();
            let rewrite_refs = web.rewrite_refs.clone();
            let rewrite_rules = web.rewrite_rules.clone();

            if let Some(cc) = site_cc_policy.as_ref()
                && self
                    .apply_cc_policy(session, ctx, cc, site_server_id)
                    .await?
            {
                return Ok(true);
            }

            let uri_str = session.req_header().uri.path();
            let query = session.req_header().uri.query().unwrap_or("");

            if !host_redirects.is_empty() {
                if let Some((location, status)) =
                    evaluate_host_redirects(&host, uri_str, &host_redirects)
                {
                    let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                    resp.insert_header("location", location).unwrap();
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }

            if !rewrite_rules.is_empty()
                && let RewriteResult::Redirect { location, status } =
                    evaluate_rewrites(uri_str, query, &rewrite_refs, &rewrite_rules)
            {
                let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                resp.insert_header("location", location).unwrap();
                session.write_response_header(Box::new(resp), true).await?;
                return Ok(true);
            }
        }

        if self.apply_global_cc_policy(session, ctx).await? {
            return Ok(true);
        }

        Ok(false)
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let is_upstream_http_status = matches!(e.esource(), ErrorSource::Upstream)
            && matches!(e.etype(), HTTPStatus(_));
        let code = match e.etype() {
            HTTPStatus(code) => *code,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    WriteError | ReadError | ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };

        if code > 0 {
            ctx.response_status = code;
            if matches!(e.esource(), ErrorSource::Upstream) {
                ctx.origin_status = code as i32;
            }
            let write_result = if is_upstream_http_status {
                // Preserve the upstream status code instead of treating a real upstream 5xx
                // as a transport failure that always maps to our local error page.
                session.respond_error(code).await
            } else {
                self.respond_status_with_pages(session, ctx, code)
                    .await
                    .map(|_| ())
            };
            if let Err(write_err) = write_result {
                error!(
                    "failed to send error response to downstream: {}",
                    write_err
                );
            }
        }

        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, e: &Error) -> bool {
        match e.etype() {
            // Silence common downstream disconnection errors to reduce log noise during load tests
            pingora::ErrorType::WriteError | pingora::ErrorType::ReadError | pingora::ErrorType::ConnectionClosed => {
                if matches!(e.esource(), pingora::ErrorSource::Downstream) {
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let node_level = self.config.get_node_level_sync();
        let force_ln = self.config.get_force_ln_request_sync();
        let bypass_l2 = self.config.is_tiered_origin_bypass().await;

        let mut target_peer = None;

        // --- TIERED ORIGIN (L1 -> L2) LOGIC ---
        if node_level == 1 && !bypass_l2 && (force_ln || ctx.cache_ref.is_some()) {
            if ctx.server.is_some() {
                // Find cluster-specific Parent LB
                // Note: We use cluster_id 0 for default cluster if not specifically mapped
                // In actual GoEdge, cluster_id is more specific.
                if let Some(parent_lb) = self.config.get_parent_upstream_sync(0) {
                    let ln_method = self.config.get_ln_method_sync();

                    let hash_key = if ln_method == "urlMapping" {
                        // Hash by full URL (Scheme + Host + Path + Query)
                        session.req_header().uri.to_string().into_bytes()
                    } else {
                        // Random-like (Round Robin is better for random, but Ketama works with random key)
                        rand::random::<u64>().to_le_bytes().to_vec()
                    };

                    if let Some(peer) = parent_lb.select(&hash_key, 128) {
                        let peer_addr = peer.to_string();
                        let pressure = self.config.get_parent_pressure(&peer_addr);

                        if pressure > 0.9 {
                            debug!(
                                "L2 node {} is overloaded (Pressure: {:.2}), trying fallback...",
                                peer_addr, pressure
                            );
                            // Try one more time with a different key to "drift" to another node in the ring
                            let fallback_key = format!("fallback:{:?}", hash_key);
                            if let Some(second_peer) =
                                parent_lb.select(fallback_key.as_bytes(), 128)
                            {
                                debug!(
                                    "Drifted L2 selection from {} to {}",
                                    peer_addr, second_peer.addr
                                );
                                target_peer = Some(second_peer.clone());
                            } else {
                                target_peer = Some(peer.clone());
                            }
                        } else {
                            debug!(
                                "Selected L2 upstream: {} (Method: {}, Pressure: {:.2}) for host: {}",
                                peer_addr,
                                ln_method,
                                pressure,
                                session.req_header().uri.host().unwrap_or("")
                            );
                            target_peer = Some(peer.clone());
                        }
                    }
                }
            }
        }

        // --- FALLBACK TO ORIGIN LB ---
        if target_peer.is_none() {
            if let Some(lb) = &ctx.lb {
                if let Some(peer) = lb.select(b"", 128) {
                    target_peer = Some(peer.clone());
                }
            }
        }

        if let Some(peer) = target_peer {
            let peer_addr = peer.to_string();
            let backend_ext = peer.ext.get::<crate::lb_factory::BackendExtension>();
            let is_tls = backend_ext
                .map(|e| e.use_tls)
                .unwrap_or(peer_addr.contains("443"));

            let host = if let Some(ext) = backend_ext {
                if !ext.host.is_empty() {
                    ext.host.clone()
                } else if ext.follow_host {
                    session
                        .get_header("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_else(|| session.req_header().uri.host().unwrap_or("localhost"))
                        .to_string()
                } else {
                    session
                        .get_header("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_else(|| session.req_header().uri.host().unwrap_or("localhost"))
                        .to_string()
                }
            } else {
                session
                    .get_header("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_else(|| session.req_header().uri.host().unwrap_or("localhost"))
                    .to_string()
            };

            debug!(
                "Selected upstream: {} (TLS={}) for SNI: {}",
                peer_addr, is_tls, host
            );
            ctx.origin_address = peer_addr.clone();

            let mut peer_obj = HttpPeer::new(peer_addr, is_tls, host);

            // --- OPTIMIZATION: L7 TCP & Protocol ---
            // Pingora sets nodelay by default.
            // For keepalive, we use Pingora's native struct:
            peer_obj.options.tcp_keepalive = Some(pingora_core::protocols::l4::ext::TcpKeepalive {
                idle: std::time::Duration::from_secs(60),
                interval: std::time::Duration::from_secs(10),
                count: 3,
                #[cfg(target_os = "linux")]
                user_timeout: std::time::Duration::from_secs(0),
            });

            // Default 60s idle timeout for backend connections
            peer_obj.options.idle_timeout = Some(std::time::Duration::from_secs(60));
            // Connection timeout (L1 -> L2 or L2 -> Origin)
            peer_obj.options.connection_timeout = Some(std::time::Duration::from_secs(10));

            if ctx.is_grpc && Self::is_grpc_request(session) {
                // Force ALPN to h2 ONLY for actual gRPC requests
                peer_obj.options.alpn = pingora_core::protocols::ALPN::H2;
            }

            // [DEBUG] DISABLE KEEPALIVE TO TEST CONNECTION REUSE ISSUES
            // peer_obj.options.set_keepalive(0); // Invalid method
            peer_obj.options.idle_timeout = Some(std::time::Duration::from_millis(1));

            if let Some(ext) = backend_ext {
                if !ext.tls_verify {
                    peer_obj.options.verify_cert = false;
                }
            }
            return Ok(Box::new(peer_obj));
        }

        if ctx.lb.is_none() {
            debug!(
                "LB is missing in context even though server was found. Server ID: {:?}",
                ctx.server.as_ref().map(|s| s.id)
            );
        } else {
            debug!(
                "No healthy backend selected from LB for context: {:?}",
                ctx.server.as_ref().map(|s| s.id)
            );
        }
        Err(Error::new(InternalError))
    }

    async fn logging(&self, session: &mut Session, _re: Option<&Error>, ctx: &mut Self::CTX) {
        if !ctx.metrics_recorded {
            let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);
            if server_id > 0 {
                let bytes_received = session.body_bytes_read() as u64;
                let bytes_sent =
                    session.body_bytes_sent() as u64 + ctx.response_headers_size as u64 + 20;
                let is_cached = ctx.cache_hit.unwrap_or(false);
                let is_attack = ctx.waf_action.is_some();
                crate::metrics::record::request_end(
                    server_id,
                    bytes_sent,
                    bytes_received,
                    is_cached,
                    is_attack,
                    ctx.is_websocket,
                );

                if !ctx.origin_address.is_empty() {
                    crate::metrics::record::record_origin_traffic(
                        server_id,
                        session.body_bytes_read() as u64,
                        ctx.response_body_len as u64,
                    );
                }

                let user_agent = session
                    .get_header("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                crate::metrics::record::record_http_dimensions(
                    server_id,
                    ctx.client_ip,
                    session
                        .get_header("host")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.split(':').next().unwrap_or(v))
                        .unwrap_or_else(|| session.req_header().uri.host().unwrap_or("")),
                    user_agent,
                    bytes_sent as i64,
                    if is_cached { bytes_sent as i64 } else { 0 },
                    ctx.waf_group_id,
                    ctx.waf_action.as_deref(),
                );
            }
            ctx.metrics_recorded = true;
        }
        crate::logging::log_access(session, ctx);
    }

    fn cache_key_callback(
        &self,
        _session: &Session,
        ctx: &mut Self::CTX,
    ) -> Result<pingora_cache::CacheKey> {
        if let Some(key) = &ctx.cache_key {
            return Ok(pingora_cache::CacheKey::new("", key.as_str(), ""));
        }

        // CRITICAL: If no key was set by request_cache_filter, we MUST return an error.
        // This ensures Pingora absolutely does not attempt any cache lookup or storage.
        Err(pingora::Error::new(pingora::ErrorType::Custom(
            "Cache Disabled for this request",
        )))
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        if let Some(s) = &ctx.server
            && let Some(web) = &s.web
            && let Some(cache) = &web.cache
            && cache.is_on
        {
            let mut matched_ref = None;
            for cache_ref in &cache.cache_refs {
                if !cache_ref.is_on {
                    continue;
                }
                let is_match = if let Some(conds) = &cache_ref.conds {
                    conds.match_request(session)
                } else if let Some(simple_cond) = &cache_ref.simple_cond {
                    simple_cond.match_request(session)
                } else {
                    true
                };

                if is_match {
                    if cache_ref.is_reverse {
                        tracing::debug!("Website Cache Rule matched: SKIP");
                        return Ok(());
                    }
                    matched_ref = Some(cache_ref.clone());
                    tracing::debug!("Website Cache Rule matched: ENABLE");
                    break;
                }
            }

            if matched_ref.is_none() && !cache.disable_policy_refs {
                let policy_opt = if let Some(p) = &cache.cache_policy {
                    Some(p.clone())
                } else {
                    self.config.get_cache_policy_sync()
                };
                if let Some(policy) = policy_opt {
                    for cache_ref in &policy.cache_refs {
                        if !cache_ref.is_on {
                            continue;
                        }
                        let is_match = if let Some(conds) = &cache_ref.conds {
                            conds.match_request(session)
                        } else if let Some(simple_cond) = &cache_ref.simple_cond {
                            simple_cond.match_request(session)
                        } else {
                            true
                        };
                        if is_match {
                            if cache_ref.is_reverse {
                                tracing::debug!(
                                    "GLOBAL Cluster Policy '{}' rule matched: SKIP",
                                    policy.name
                                );
                                return Ok(());
                            }
                            matched_ref = Some(cache_ref.clone());
                            tracing::debug!(
                                "GLOBAL Cluster Policy '{}' rule matched: ENABLE (Path: {})",
                                policy.name,
                                session.req_header().uri.path()
                            );
                            break;
                        }
                    }
                }
            }

            if let Some(cache_ref) = matched_ref {
                if self.is_hls_encrypted_request(session, s) {
                    tracing::debug!(
                        "Skip cache for HLS encrypted request: {}",
                        session.req_header().uri.path()
                    );
                    session
                        .cache
                        .disable(pingora_cache::NoCacheReason::Custom("HLSEncrypted"));
                    return Ok(());
                }
                if cache_ref.always_forward_range_request && session.get_header("range").is_some() {
                    return Ok(());
                }
                if cache_ref.enable_request_cache_pragma {
                    let cc = session
                        .get_header("cache-control")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let pragma = session
                        .get_header("pragma")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if cc.contains("no-cache") || pragma.contains("no-cache") {
                        return Ok(());
                    }
                }

                ctx.cache_policy = cache_ref.cache_policy.clone();
                ctx.cache_ref = Some(cache_ref.clone());

                // --- PROTOCOL PARITY: Salted Key Generation ---
                let mut key = if let Some(key_template) = &cache_ref.key {
                    if key_template.is_empty() {
                        Self::default_cache_key_for_session(session)
                    } else {
                        crate::cache::matching::format_variables(session, key_template)
                    }
                } else {
                    Self::default_cache_key_for_session(session)
                };

                // 1. Method Suffix (EdgeNode parity: "@method:METHOD")
                let method = session.req_header().method.as_str();
                if method != "GET" {
                    key.push_str("@method:");
                    key.push_str(method);
                }

                // 2. WebP Suffix (if applicable)
                let accept = session
                    .get_header("accept")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if accept.contains("image/webp") {
                    let path = session.req_header().uri.path().to_lowercase();
                    if path.ends_with(".jpg")
                        || path.ends_with(".jpeg")
                        || path.ends_with(".png")
                        || path.ends_with(".gif")
                    {
                        key.push_str("@webp");
                    }
                }

                // 3. Compression Suffix (EdgeNode parity: "@encoding")
                let accept_encoding = session
                    .get_header("accept-encoding")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if accept_encoding.contains("br") {
                    key.push_str("@br");
                } else if accept_encoding.contains("gzip") {
                    key.push_str("@gzip");
                }

                ctx.cache_key = Some(key);

                if !cache_ref.enable_if_none_match {
                    session.req_header_mut().headers.remove("if-none-match");
                }
                if !cache_ref.enable_if_modified_since {
                    session.req_header_mut().headers.remove("if-modified-since");
                }

                session.cache.enable(CACHE.storage, None, None, None, None);
            } else {
                tracing::debug!(
                    "No cache rule matched for request: {}",
                    session.req_header().uri.path()
                );
                // CRITICAL: Explicitly disable cache to clear state from Keep-Alive requests
                session
                    .cache
                    .disable(pingora_cache::NoCacheReason::Custom("RuleDisabled"));
            }
        } else {
            tracing::debug!("Cache is OFF for this server or web config.");
            session
                .cache
                .disable(pingora_cache::NoCacheReason::Custom("CacheConfigOff"));
        }
        Ok(())
    }

    #[allow(unused_variables)]
    async fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.origin_status = upstream_response.status.as_u16() as i32;

        if let Some(cache_ref) = &ctx.cache_ref {
            let mut force_cache = false;
            let mut seconds = 0;

            if let Some(expires_cfg) = &cache_ref.expires_time
                && expires_cfg.is_on
            {
                if let Some(duration_val) = &expires_cfg.duration {
                    seconds = crate::config_models::parse_life_to_seconds(duration_val);
                    if seconds > 0 {
                        force_cache = true;
                    }
                }
            } else if let Some(life) = &cache_ref.life {
                seconds = crate::config_models::parse_life_to_seconds(life);
                if seconds > 0 {
                    force_cache = true;
                }
            }

            if force_cache {
                // 1. Sanitize Cache-Control (Robust Split-Filter-Join)
                let cc_header = upstream_response
                    .headers
                    .get("cache-control")
                    .and_then(|v| v.to_str().ok());

                let blacklist = [
                    "no-cache",
                    "no-store",
                    "private",
                    "must-revalidate",
                    "proxy-revalidate",
                ];
                let mut parts: Vec<String> = vec![];

                if let Some(cc_val) = cc_header {
                    for part in cc_val.split(',') {
                        let trimmed = part.trim();
                        if !blacklist.iter().any(|&kw| trimmed.eq_ignore_ascii_case(kw)) {
                            if !trimmed.is_empty() {
                                parts.push(trimmed.to_string());
                            }
                        }
                    }
                }

                if !parts.iter().any(|p| p.to_lowercase().contains("max-age")) {
                    parts.push(format!("max-age={}", seconds));
                }

                if !parts.iter().any(|p| p.eq_ignore_ascii_case("public")) {
                    parts.push("public".to_string());
                }

                let new_cc = parts.join(", ");
                upstream_response
                    .insert_header("cache-control", new_cc)
                    .unwrap();

                // 2. Remove Pragma: no-cache
                if let Some(pragma) = upstream_response.headers.get("pragma") {
                    if pragma
                        .to_str()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains("no-cache")
                    {
                        upstream_response.remove_header("pragma");
                    }
                }

                // 3. Set Expires
                let expires =
                    crate::utils::time::now_utc() + chrono::Duration::seconds(seconds as i64);
                let expires_str = expires.to_rfc2822().replace("+0000", "GMT");
                upstream_response
                    .insert_header("expires", expires_str)
                    .unwrap();
            }
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.response_status = upstream_response.status.as_u16();
        ctx.ttfb = Some(ctx.start_time.elapsed());

        // Sync all response headers from upstream to context for accurate logging and WAF
        for (name, value) in upstream_response.headers.iter() {
            if let Ok(value_str) = value.to_str() {
                ctx.response_headers
                    .insert(name.to_string(), value_str.to_string());
            }
        }

        ctx.response_headers_size = upstream_response
            .headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.len() + 4)
            .sum();

        // --- SMART LOAD BALANCING FEEDBACK ---
        // 1. L2 Node: Announce pressure to L1
        if session.get_header("X-Cloud-Node-Id").is_some() {
            let pressure = crate::metrics::METRICS.get_node_pressure();
            upstream_response
                .insert_header("X-Cloud-Node-Pressure", format!("{:.2}", pressure))
                .unwrap();
        }

        // 2. L1 Node: Learn from L2's pressure announcement
        if let Some(p_header) = upstream_response.headers.get("X-Cloud-Node-Pressure") {
            if let Ok(p_str) = p_header.to_str() {
                if let Ok(p_val) = p_str.parse::<f32>() {
                    // Update the pressure map for this L2 node using the actual upstream address
                    self.config
                        .update_parent_pressure(&ctx.origin_address, p_val);
                }
            }
        }

        // --- GLOBAL CLUSTER SETTINGS: Server Flag ---
        let global_cfg = self.config.get_global_http_config_sync();
        if !global_cfg.server_name.is_empty() {
            upstream_response
                .insert_header("Server", &global_cfg.server_name)
                .unwrap();
        }

        // 1. Initial Outbound WAF (Status & Headers)
        let outbound_ctx = crate::firewall::OutboundContext {
            status: ctx.response_status,
            headers: &ctx.response_headers,
            body: &[],
            bytes_sent: 0,
        };

        let mut matched_outbound = None;
        let global_policies = self.config.get_firewall_policies_sync();
        for gp in &global_policies {
            if !gp.is_on {
                continue;
            }
            if let Some(action) = crate::firewall::evaluate_outbound_policy(
                gp,
                session,
                &ctx.request_body,
                &outbound_ctx,
            ) {
                matched_outbound = Some(action);
                break;
            }
        }
        if matched_outbound.is_none() {
            if let Some(server) = &ctx.server
                && let Some(web) = &server.web
                && let Some(fw_ref) = &web.firewall_ref
                && fw_ref.is_on
            {
                if let Some(policy) = &web.firewall_policy {
                    if let Some(action) = crate::firewall::evaluate_outbound_policy(
                        policy,
                        session,
                        &ctx.request_body,
                        &outbound_ctx,
                    ) {
                        matched_outbound = Some(action);
                    }
                }
            }
        }

        if let Some(action) = matched_outbound {
            if action.action_code == "block" {
                upstream_response.status = pingora::http::StatusCode::FORBIDDEN;
                upstream_response
                    .insert_header("x-waf-blocked", "outbound-header")
                    .unwrap();
                ctx.waf_policy_id = action.policy_id;
                ctx.waf_group_id = action.group_id;
                ctx.waf_set_id = action.set_id;
                ctx.waf_action = Some(action.action_code.clone());
                self.maybe_report_firewall_event(
                    ctx,
                    action.policy_id,
                    action.group_id,
                    action.set_id,
                );
            }
        }

        let is_https = session
            .downstream_session
            .digest()
            .and_then(|digest| digest.ssl_digest.as_ref())
            .is_some()
            || session.req_header().uri.scheme_str() == Some("https");
        if is_https
            && upstream_response.headers.get("alt-svc").is_none()
            && let Some(port) =
                self.resolve_http3_advertisement_port(session, ctx.server.as_deref())
        {
            upstream_response
                .insert_header("alt-svc", format!("h3=\":{}\"; ma=86400", port))
                .unwrap();
            ctx.response_headers
                .insert("alt-svc".to_string(), format!("h3=\":{}\"; ma=86400", port));
        }

        // ... (existing X-Cache and Expires logic)
        let phase = session.cache.phase();
        let x_cache = if !session.cache.enabled() && !session.cache.bypassing() {
            "BYPASS".to_string()
        } else {
            match phase {
                pingora_cache::CachePhase::Hit => "HIT".to_string(),
                pingora_cache::CachePhase::Miss => "MISS".to_string(),
                pingora_cache::CachePhase::Stale => "STALE".to_string(),
                pingora_cache::CachePhase::Bypass => "BYPASS".to_string(),
                pingora_cache::CachePhase::Expired => "EXPIRED".to_string(),
                pingora_cache::CachePhase::Revalidated => "REVALIDATED".to_string(),
                pingora_cache::CachePhase::Disabled(reason) => {
                    format!("DISABLED:{}", reason.as_str().to_uppercase())
                }
                _ => phase.as_str().to_uppercase(),
            }
        };
        upstream_response
            .insert_header("x-cache", x_cache.clone())
            .unwrap();
        ctx.response_headers.insert("x-cache".to_string(), x_cache);

        self.maybe_enable_optimization(session, upstream_response, ctx);
        self.maybe_enable_hls(session, upstream_response, ctx);
        self.maybe_enable_webp_conversion(session, upstream_response, ctx);

        if let Some(cache_ref) = &ctx.cache_ref
            && let Some(expires_cfg) = &cache_ref.expires_time
            && expires_cfg.is_on
            && expires_cfg.auto_calculate
        {
            if expires_cfg.overwrite || upstream_response.headers.get("expires").is_none() {
                let ttl = cache_ref
                    .life
                    .as_ref()
                    .map(crate::config_models::parse_life_to_seconds)
                    .unwrap_or(3600);
                let expires = crate::utils::time::now_utc() + chrono::Duration::seconds(ttl as i64);
                upstream_response
                    .insert_header("expires", expires.to_rfc2822().replace("+0000", "GMT"))
                    .unwrap();
                upstream_response
                    .insert_header("cache-control", format!("max-age={}", ttl))
                    .unwrap();
            }
        }
        self.apply_charset_to_response(upstream_response, ctx);
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let global_cfg = self.config.get_global_http_config_sync();
        upstream_request.remove_header("x-cloud-resolved-real-ip");

        // [DEBUG] DISABLE KEEPALIVE TO TEST CONNECTION REUSE ISSUES
        upstream_request.remove_header("connection");
        upstream_request.insert_header("connection", "close").unwrap();

        // 1. Automatic Gzip Back to Origin
        if global_cfg.request_origins_with_encodings {
            if upstream_request.headers.get("accept-encoding").is_none() {
                upstream_request
                    .insert_header("accept-encoding", "gzip, deflate, br")
                    .unwrap();
            }
        }

        // 2. L1 Logic: Inject Identity headers when talking to L2
        let (level, _) = self.config.get_tiered_origin_info().await;
        if level == 1 {
            let node_id = &self.api_config.node_id;
            let secret = &self.api_config.secret;

            // 2.1 Identification
            upstream_request
                .insert_header("X-Cloud-Node-Id", node_id)
                .unwrap();

            // 2.2 Real IP Propagation
            upstream_request
                .insert_header("X-Cloud-Real-Ip", ctx.client_ip.to_string())
                .unwrap();

            // 2.3 Security Token (Simple version of GoEdge token)
            if let Ok(token) = crate::auth::generate_token(node_id, secret, "edge") {
                upstream_request
                    .insert_header("X-Cloud-Access-Token", token)
                    .unwrap();
            }

            debug!("L1: Injected tiered-origin headers for node {}", node_id);
        }

        // 3. Standard logic: Add X-Forwarded-For with limit
        let ip = ctx.client_ip.to_string();
        if let Some(val) = upstream_request.headers.get("X-Forwarded-For") {
            let mut parts: Vec<String> = val
                .to_str()
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            parts.push(ip);

            // Apply XFF address limit
            let max_xff = global_cfg.xff_max_addresses;
            if max_xff > 0 && parts.len() > max_xff as usize {
                let start = parts.len() - max_xff as usize;
                parts = parts[start..].to_vec();
            }

            upstream_request
                .insert_header("X-Forwarded-For", parts.join(", "))
                .unwrap();
        } else {
            upstream_request
                .insert_header("X-Forwarded-For", ip)
                .unwrap();
        }

        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        // [DEBUG] TEMPORARILY DISABLED ALL BODY REWRITES AND OUTBOUND WAF
        // This is to isolate whether the "connection closed before message completed"
        // errors are caused by buffering/rewriting logic or upstream connection pooling.
        if let Some(chunk) = body.as_ref() {
            ctx.response_body_len += chunk.len();
        }
        Ok(None)
    }

    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<pingora_cache::RespCacheable> {
        if let Some(server) = &ctx.server
            && self.is_hls_encrypted_request(session, server)
        {
            return Ok(pingora_cache::RespCacheable::Uncacheable(
                pingora_cache::NoCacheReason::Custom("HLSEncrypted"),
            ));
        }

        if let Some(cache_ref) = &ctx.cache_ref {
            let mut hm: HashMap<String, String> = HashMap::new();
            for (k, v) in resp.headers.iter() {
                hm.insert(
                    k.to_string().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                );
            }
            let body_size = resp
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s: &str| s.parse::<usize>().ok())
                .unwrap_or(0);
            let host = session.req_header().uri.host().unwrap_or("");

            if !should_cache_response(
                resp.status.as_u16(),
                cache_ref,
                session.req_header().method.as_str(),
                &hm,
                host,
                body_size,
            ) {
                if resp.status.as_u16() == 206 && cache_ref.allow_partial_content {
                } else {
                    return Ok(pingora_cache::RespCacheable::Uncacheable(
                        pingora_cache::NoCacheReason::Custom("PolicyMismatch"),
                    ));
                }
            }

            let mut max_bytes = i64::MAX;
            if let Some(policy) = &ctx.cache_policy
                && let Some(cap) = &policy.max_item_size
            {
                let b = crate::config_models::SizeCapacity::from_json(cap).to_bytes();
                if b > 0 {
                    max_bytes = b;
                }
            }
            if let Some(cap) = &cache_ref.max_size {
                let b = crate::config_models::SizeCapacity::from_json(cap).to_bytes();
                if b > 0 && b < max_bytes {
                    max_bytes = b;
                }
            }
            if max_bytes > 0 && (body_size as i64) > max_bytes {
                return Ok(pingora_cache::RespCacheable::Uncacheable(
                    pingora_cache::NoCacheReason::Custom("FileTooLarge"),
                ));
            }

            let ttl = cache_ref
                .life
                .as_ref()
                .map(crate::config_models::parse_life_to_seconds)
                .unwrap_or(3600);

            let mut cached_header =
                pingora_http::ResponseHeader::build(resp.status.as_u16(), Some(resp.headers.len()))
                    .unwrap();
            for (k, v) in resp.headers.iter() {
                // Pingora's internal cache meta validation natively REJECTS saving any response with Set-Cookie.
                // If we reach here, it means our custom `should_cache_response` ALLOWED caching.
                // Therefore, we MUST strip Set-Cookie so Pingora actually saves it to disk.
                if k.as_str().eq_ignore_ascii_case("set-cookie") {
                    continue;
                }
                if k.as_str().eq_ignore_ascii_case("cache-control") {
                    // Force a valid Cache-Control so Pingora doesn't reject it internally
                    cached_header
                        .insert_header("cache-control", format!("public, max-age={}", ttl))
                        .unwrap();
                    continue;
                }
                cached_header.insert_header(k.clone(), v.clone()).unwrap();
            }
            if !cached_header.headers.contains_key("cache-control") {
                cached_header
                    .insert_header("cache-control", format!("public, max-age={}", ttl))
                    .unwrap();
            }

            // Add a debug log to trace why it's caching or not
            tracing::debug!("Returning Cacheable for request: {}. ttl={}", host, ttl);

            let now = std::time::SystemTime::now();
            let fresh_until = now + std::time::Duration::from_secs(ttl);
            let meta = pingora_cache::CacheMeta::new(fresh_until, now, 0, 0, cached_header);

            return Ok(pingora_cache::RespCacheable::Cacheable(meta));
        }
        Ok(pingora_cache::RespCacheable::Uncacheable(
            pingora_cache::NoCacheReason::Custom("NoPolicy"),
        ))
    }
}
