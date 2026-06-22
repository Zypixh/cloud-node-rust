use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use http::header::{COOKIE, HeaderValue};
use image::AnimationDecoder;
use pingora_core::connectors::L4Connect;
use pingora_core::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use pingora_core::protocols::l4::stream::Stream as PingoraL4Stream;
use pingora_core::protocols::tls::CustomALPN;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, ErrorSource, ErrorType::*, Result};
use pingora_proxy::{
    DownstreamParseErrorAction, DownstreamParseErrorLogLevel, FailToProxy, ProxyHttp, PurgeStatus,
    Session,
};
use rand::Rng;
use rand::seq::SliceRandom;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::api_config::ApiConfig;
use crate::cache::should_cache_response;
use crate::cache_manager::CACHE;
use crate::config::ConfigStore;
use crate::config_models::{
    HTTPCacheKeyConfig, HTTPCachePolicy, HTTPCacheRef, HTTPFirewallPolicy, ProxyProtocolConfig,
    ServerConfig, UAMConfig, WAFCaptchaOptions, WebCacheConfig,
};
use crate::firewall::state::WafStateManager;
use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR, StaticAdmissionPermit};
use crate::rewrite::{RewriteResult, evaluate_host_redirects, evaluate_rewrites_with_cond};
use crate::rpc::ip_report::{IpReportKind, IpReportMessage};
use dashmap::DashMap;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::LazyLock as Lazy;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[derive(Clone, Default)]
pub struct LazyBytes(Option<Vec<u8>>);

static EMPTY_BYTES_VEC: LazyLock<Vec<u8>> = LazyLock::new(Vec::new);

fn merged_session_cookie_header(session: &Session) -> Option<String> {
    let values = session
        .req_header()
        .headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    (!values.is_empty()).then(|| values.join("; "))
}

fn normalize_upstream_cookie_headers(upstream_request: &mut pingora_http::RequestHeader) {
    let values = upstream_request
        .headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if values.len() <= 1 {
        return;
    }

    let merged = values.join("; ");
    upstream_request.remove_header(&COOKIE);
    if let Ok(value) = HeaderValue::from_str(&merged) {
        let _ = upstream_request.insert_header(COOKIE, value);
    }
}

impl LazyBytes {
    fn take(&mut self) -> Vec<u8> {
        self.0.take().unwrap_or_default()
    }

    fn set(&mut self, value: Vec<u8>) {
        self.0 = Some(value);
    }

    fn clear(&mut self) {
        if let Some(value) = &mut self.0 {
            value.clear();
        }
    }
}

impl std::ops::Deref for LazyBytes {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap_or(&EMPTY_BYTES_VEC)
    }
}

impl std::ops::DerefMut for LazyBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.get_or_insert_with(Vec::new)
    }
}

#[derive(Clone, Default)]
pub struct LazyResponseHeaders(Option<HashMap<String, String>>);

static EMPTY_RESPONSE_HEADERS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

#[derive(Debug)]
struct ProxyProtocolL4Connector {
    client_addr: SocketAddr,
    config: ProxyProtocolConfig,
    connection_timeout: Duration,
}

#[async_trait]
impl L4Connect for ProxyProtocolL4Connector {
    async fn connect(&self, addr: &PingoraSocketAddr) -> pingora_core::Result<PingoraL4Stream> {
        let PingoraSocketAddr::Inet(destination_addr) = addr else {
            return Err(pingora_core::Error::explain(
                ConnectError,
                "PROXY Protocol to Unix socket origins is not supported",
            ));
        };
        let mut stream = match tokio::time::timeout(
            self.connection_timeout,
            tokio::net::TcpStream::connect(destination_addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                return Err(pingora_core::Error::because(
                    ConnectError,
                    "failed to connect origin for PROXY Protocol",
                    err,
                ));
            }
            Err(_) => {
                return Err(pingora_core::Error::explain(
                    ConnectTimedout,
                    "timed out connecting origin for PROXY Protocol",
                ));
            }
        };
        if let Some(header) = crate::proxy_protocol::build_header(
            self.config,
            self.client_addr,
            Some(*destination_addr),
        ) {
            stream.write_all(&header).await.map_err(|err| {
                pingora_core::Error::because(
                    WriteError,
                    "failed to write PROXY Protocol header",
                    err,
                )
            })?;
            stream.flush().await.map_err(|err| {
                pingora_core::Error::because(
                    WriteError,
                    "failed to flush PROXY Protocol header",
                    err,
                )
            })?;
        }
        Ok(PingoraL4Stream::from(stream))
    }
}

impl LazyResponseHeaders {
    fn clear(&mut self) {
        if let Some(value) = &mut self.0 {
            value.clear();
        }
    }

    fn ensure_allocated(&mut self) {
        self.0.get_or_insert_with(HashMap::new);
    }

    fn is_allocated(&self) -> bool {
        self.0.is_some()
    }
}

impl std::ops::Deref for LazyResponseHeaders {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap_or(&EMPTY_RESPONSE_HEADERS)
    }
}

impl std::ops::DerefMut for LazyResponseHeaders {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.get_or_insert_with(HashMap::new)
    }
}

pub struct ProxyCTX {
    pub start_time: std::time::Instant,
    pub start_timestamp_millis: i64,
    pub request_id: String,
    pub server: Option<Arc<ServerConfig>>,
    pub matched_location: Option<Arc<crate::config_models::LocationConfig>>,
    pub lb: Option<Arc<crate::lb_factory::AnyLoadBalancer>>,
    pub metrics_started: bool,
    pub metrics_recorded: bool,
    pub ttfb: Option<std::time::Duration>,
    pub response_status: u16,
    pub cache_policy: Option<Arc<HTTPCachePolicy>>,
    pub cache_ref: Option<Arc<HTTPCacheRef>>,
    pub compiled_cache_policy: Option<Arc<crate::cache::compiled::CompiledCachePolicy>>,
    pub compiled_cache_ref: Option<Arc<crate::cache::compiled::CompiledCacheRef>>,
    pub cache_key: Option<String>,
    pub cache_partial_range: Option<String>,
    pub cache_hit: Option<bool>,
    pub cache_purge_authorized: bool,
    pub cacheable: bool,
    pub response_headers: LazyResponseHeaders,
    pub response_body_len: usize,
    pub response_body_buffer: LazyBytes,
    pub request_body: LazyBytes,
    pub has_outbound_waf_body_rules: bool,
    pub outbound_waf_body_evaluated: bool,
    pub outbound_waf_block_body: Option<Bytes>,
    pub waf_policy_id: i64,
    pub waf_group_id: i64,
    pub waf_set_id: i64,
    pub waf_rule_id: i64,
    pub rewrite_id: i64,
    pub waf_deferred: bool,
    pub waf_whitelisted: bool,
    pub waf_action: Option<String>,
    pub errors: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub firewall_event_reported: bool,
    pub compress_zstd: bool,
    pub compression_type: Option<String>,
    pub compression_level: i8,
    pub custom_page_body: Option<String>,
    pub custom_page_status: u16,
    pub is_websocket: bool,
    pub ws_subprotocol: Option<String>,
    pub is_grpc: bool,
    pub max_inspection_size: i64,
    pub no_log: bool,
    pub firewall_blocked: bool,
    pub access_log_ref: Option<crate::config_models::HTTPAccessLogRef>,
    pub global_access_log_on: bool,
    pub global_access_log_config:
        Option<std::sync::Arc<crate::config_models::GlobalHTTPAccessLogConfig>>,
    pub global_waf_block_options: Option<Arc<crate::config_models::WAFBlockOptions>>,
    pub access_log_module_enabled: bool,
    pub response_headers_size: usize,
    pub origin_address: String,
    pub origin_id: i64,
    pub origin_connect_permit: Option<StaticAdmissionPermit>,
    pub request_body_waf_permit: Option<StaticAdmissionPermit>,
    pub response_body_waf_permit: Option<StaticAdmissionPermit>,
    pub response_transform_permit: Option<StaticAdmissionPermit>,
    pub upstream_retries: u8,
    pub origin_status: i32,
    pub is_on: bool,
    pub client_ip: std::net::IpAddr,
    pub client_ip_str: String,
    pub client_port: u16,
    pub raw_remote_addr: String,
    pub analyzed: Option<crate::metrics::analyzer::RequestStats>,
    pub is_http3_bridge: bool,
    pub is_http3_downstream: bool,
    pub is_tls_downstream: bool,
    pub is_loopback: bool,
    pub server_metrics: Option<Arc<crate::metrics::ServerMetrics>>,
    pub ip_recorded: bool,
    pub webp_convert_enabled: bool,
    pub webp_source_content_type: Option<String>,
    pub webp_source_content_length: Option<usize>,
    pub webp_pending_body: LazyBytes,
    pub webp_quality: i32,
    pub webp_cpu_permit: Option<crate::adaptive_cpu::CpuTransformReservation<'static>>,
    pub optimize_enabled: bool,
    pub optimize_kind: Option<String>,
    pub optimize_pending_body: LazyBytes,
    pub hls_playlist_enabled: bool,
    pub hls_playlist_pending_body: LazyBytes,
    pub hls_segment_encrypt_enabled: bool,
    pub hls_segment_key: Option<[u8; 16]>,
    pub hls_segment_iv: Option<[u8; 16]>,
    pub hls_segment_pending_body: LazyBytes,
    pub hls_session_id: Option<String>,
    pub hls_session_exp: Option<i64>,
    pub request_limit_out_bandwidth_bytes: i64,
    pub request_limit_out_bandwidth_sent: i64,
    pub request_limit_out_bandwidth_window_start: Option<std::time::Instant>,
    pub plan_max_upload_bytes: Option<i64>,
    pub traffic_limit_notice_body: Option<Option<String>>,
    pub global_cache_policies: Arc<Vec<Arc<HTTPCachePolicy>>>,
    pub compiled_plans: Arc<crate::compiled::CompiledPlanSet>,
    /// Cached during request_filter to avoid config lock in response_filter/body_filter
    pub global_http_config: Option<Arc<crate::config_models::GlobalHTTPAllConfig>>,
    pub firewall_policies_snapshot: Option<Arc<Vec<HTTPFirewallPolicy>>>,
    pub node_level: i32,
    pub upstream_is_parent: bool,
    pub host: String,
    pub origin_host: String,
    pub oss_backend: Option<crate::oss_origin::OssBackend>,
    /// IP parsed from an inbound PROXY Protocol v1/v2 header.
    ///
    /// Today the listeners (`http_proxy_manager`, `tcp_proxy`) rewrite the
    /// socket digest directly so `peer_socket_ip` already returns the proxied
    /// address — this field is left for callers that want to distinguish a
    /// PROXY-protocol-derived IP from a raw socket IP without re-parsing.
    /// Set by `maybe_consume_proxy_protocol_header` when wired through.
    #[allow(dead_code)]
    pub proxy_protocol_ip: Option<std::net::IpAddr>,
    pub request_phase: RequestPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestPhase {
    Init,
    Context,
    LocalService,
    ProtocolPolicy,
    EarlyResponse,
    SecurityState,
    Limits,
    LightweightWaf,
    BodyWaf,
    FeaturePolicy,
    Rewrite,
    Proxy,
}

struct RequestFilterState {
    host: String,
    hot_path: crate::config::HotPathSnapshot,
}

enum PhaseOutcome<T> {
    Continue(T),
    Done(bool),
}

impl Default for ProxyCTX {
    fn default() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            start_timestamp_millis: crate::utils::time::now_timestamp_millis(),
            request_id: String::new(),
            server: None,
            matched_location: None,
            lb: None,
            metrics_started: false,
            metrics_recorded: false,
            ttfb: None,
            response_status: 0,
            cache_policy: None,
            cache_ref: None,
            compiled_cache_policy: None,
            compiled_cache_ref: None,
            cache_key: None,
            cache_partial_range: None,
            cache_hit: None,
            cache_purge_authorized: false,
            cacheable: false,
            response_headers: LazyResponseHeaders::default(),
            response_body_len: 0,
            response_body_buffer: LazyBytes::default(),
            request_body: LazyBytes::default(),
            has_outbound_waf_body_rules: false,
            outbound_waf_body_evaluated: false,
            outbound_waf_block_body: None,
            waf_policy_id: 0,
            waf_group_id: 0,
            waf_set_id: 0,
            waf_rule_id: 0,
            rewrite_id: 0,
            waf_deferred: false,
            waf_whitelisted: false,
            waf_action: None,
            errors: None,
            tags: None,
            firewall_event_reported: false,
            compress_zstd: false,
            compression_type: None,
            compression_level: 0,
            custom_page_body: None,
            custom_page_status: 0,
            is_websocket: false,
            ws_subprotocol: None,
            is_grpc: false,
            max_inspection_size: 512 * 1024, // Default 512K as per PB requirement
            no_log: false,
            firewall_blocked: false,
            access_log_ref: None,
            global_access_log_on: true,
            global_access_log_config: None,
            global_waf_block_options: None,
            access_log_module_enabled: true,
            response_headers_size: 0,
            origin_address: String::new(),
            origin_id: 0,
            origin_connect_permit: None,
            request_body_waf_permit: None,
            response_body_waf_permit: None,
            response_transform_permit: None,
            upstream_retries: 0,
            origin_status: 0,
            is_on: true,
            client_ip: "127.0.0.1".parse().unwrap(),
            client_ip_str: "127.0.0.1".to_string(),
            client_port: 0,
            raw_remote_addr: String::new(),
            analyzed: None,
            is_http3_bridge: false,
            is_http3_downstream: false,
            is_tls_downstream: false,
            is_loopback: false,
            server_metrics: None,
            ip_recorded: false,
            webp_convert_enabled: false,
            webp_source_content_type: None,
            webp_source_content_length: None,
            webp_pending_body: LazyBytes::default(),
            webp_quality: 80,
            webp_cpu_permit: None,
            optimize_enabled: false,
            optimize_kind: None,
            optimize_pending_body: LazyBytes::default(),
            hls_playlist_enabled: false,
            hls_playlist_pending_body: LazyBytes::default(),
            hls_segment_encrypt_enabled: false,
            hls_segment_key: None,
            hls_segment_iv: None,
            hls_segment_pending_body: LazyBytes::default(),
            hls_session_id: None,
            hls_session_exp: None,
            request_limit_out_bandwidth_bytes: 0,
            request_limit_out_bandwidth_sent: 0,
            request_limit_out_bandwidth_window_start: None,
            plan_max_upload_bytes: None,
            traffic_limit_notice_body: None,
            global_cache_policies: Arc::new(Vec::new()),
            compiled_plans: Arc::new(crate::compiled::CompiledPlanSet::default()),
            global_http_config: None,
            firewall_policies_snapshot: None,
            node_level: 0,
            upstream_is_parent: false,
            host: String::new(),
            origin_host: String::new(),
            oss_backend: None,
            proxy_protocol_ip: None,
            request_phase: RequestPhase::Init,
        }
    }
}

#[derive(Clone)]
pub struct EdgeProxy {
    pub config: Arc<ConfigStore>,
    pub waf_state: Arc<WafStateManager>,
    pub api_config: Arc<ApiConfig>,
    pub cert_selector: Arc<crate::ssl::DynamicCertSelector>,
    pub waf_verifier: Arc<crate::firewall::verifier::WafVerifier>,
    pub tls_downstream: bool,
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
const WAF_VERIFY_ROUTE: &str = "/.well-known/cloud-node/waf-verify";
const UAM_DEFAULT_LIFE_SECONDS: i64 = 3600;
const UAM_CHALLENGE_LIFE_SECONDS: i64 = 120;
const UAM_MIN_VERIFY_SECONDS: i64 = 5;
const UAM_COOKIE_VERSION: &str = "v2";

#[derive(Clone)]
struct RequestLimitBinding {
    server_id: i64,
    client_ip: std::net::IpAddr,
    last_seen: std::time::Instant,
}

static REQUEST_LIMIT_BINDINGS: Lazy<DashMap<String, RequestLimitBinding>> =
    Lazy::new(|| DashMap::with_shard_amount(64));
static REQUEST_LIMIT_SERVER_COUNTS: Lazy<DashMap<i64, Arc<AtomicI32>>> =
    Lazy::new(|| DashMap::with_shard_amount(64));
static REQUEST_LIMIT_IP_COUNTS: Lazy<DashMap<std::net::IpAddr, Arc<AtomicI32>>> =
    Lazy::new(|| DashMap::with_shard_amount(64));
static WILDCARD_DOMAIN_REGEX_CACHE: Lazy<DashMap<String, Arc<Regex>>> =
    Lazy::new(|| DashMap::with_shard_amount(64));
static UA_WILDCARD_REGEX_CACHE: Lazy<DashMap<String, Arc<Regex>>> =
    Lazy::new(|| DashMap::with_shard_amount(64));
static HOSTNAME: LazyLock<String> = LazyLock::new(|| {
    hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
});
const REQUEST_LIMIT_BINDING_IDLE_SECS: u64 = 180;
const REQUEST_LIMIT_BINDINGS_MAX_NORMAL: usize = 1_000_000;
const REQUEST_LIMIT_BINDINGS_MAX_PRESSURE: usize = 131_072;
const MAX_OPTIMIZATION_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_WEBP_CONVERSION_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_HLS_PLAYLIST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_HLS_SEGMENT_BODY_BYTES: usize = 16 * 1024 * 1024;

use pingora_cache::lock::CacheLock;
use pingora_cache::storage::HitHandler;
use pingora_cache::{CacheMeta, ForcedFreshness};

static CACHE_LOCK: std::sync::LazyLock<CacheLock> =
    std::sync::LazyLock::new(|| CacheLock::new(std::time::Duration::from_secs(1)));

/// Tracks cache keys currently undergoing background SWR revalidation.
/// Prevents thundering herd: only one background fetch per key at a time.
static SWR_REVALIDATE_IN_FLIGHT: Lazy<DashMap<String, ()>> =
    Lazy::new(|| DashMap::with_shard_amount(64));

/// Hard cap on how many SWR background tasks may be in flight simultaneously.
/// Without it an attacker can spawn a task per unique cache key (each holding
/// its own DashMap entry and one tokio task) and exhaust memory / fds.
const SWR_REVALIDATE_INFLIGHT_MAX: usize = 1024;

/// Reused HTTP client for SWR background revalidation. Rebuilding a fresh
/// reqwest::Client per task would leak DNS resolvers and TLS state under load.
static SWR_REVALIDATE_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(8)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

impl EdgeProxy {
    fn is_access_log_only_proxy_error(error: &Error) -> bool {
        crate::process_log_policy::is_request_outcome_error(error, None)
    }

    fn record_access_log_error(ctx: &mut ProxyCTX, error: &Error, status: Option<u16>) {
        if !crate::process_log_policy::is_request_outcome_error(error, status) {
            return;
        }

        let label = crate::process_log_policy::access_log_error_label(error, status);
        let errors = ctx.errors.get_or_insert_with(Vec::new);
        if !errors.iter().any(|existing| existing == label) {
            errors.push(label.to_string());
        }
    }

    fn is_grpc_request(session: &Session) -> bool {
        session
            .get_header("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.trim()
                    .to_ascii_lowercase()
                    .starts_with("application/grpc")
            })
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

    fn cache_fetch_action_requested(session: &Session, ctx: &ProxyCTX) -> bool {
        if !ctx.is_loopback {
            return false;
        }
        ["x-edge-cache-action", "x-cloud-cache-action"]
            .iter()
            .filter_map(|name| session.get_header(*name))
            .filter_map(|value| value.to_str().ok())
            .any(|value| value.trim().eq_ignore_ascii_case("fetch"))
    }

    fn cache_purge_authorized(session: &Session, cache: &WebCacheConfig) -> bool {
        if !session
            .req_header()
            .method
            .as_str()
            .eq_ignore_ascii_case("PURGE")
            || !cache.purge_is_on
        {
            return false;
        }
        let purge_key = cache.purge_key.trim();
        !purge_key.is_empty()
            && session
                .get_header("x-edge-purge-key")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == purge_key)
    }

    fn purge_cache_ref(
        cache: &WebCacheConfig,
        global_policies: &[Arc<HTTPCachePolicy>],
    ) -> Option<(Arc<HTTPCacheRef>, Option<Arc<HTTPCachePolicy>>)> {
        if let Some(cache_ref) = cache
            .cache_refs
            .iter()
            .find(|cache_ref| cache_ref.is_on && !cache_ref.is_reverse)
        {
            return Some((cache_ref.clone(), None));
        }

        if !cache.disable_policy_refs {
            if let Some(policy) = &cache.cache_policy {
                if let Some(cache_ref) = policy
                    .cache_refs
                    .iter()
                    .find(|cache_ref| cache_ref.is_on && !cache_ref.is_reverse)
                {
                    return Some((cache_ref.clone(), Some(policy.clone())));
                }
            } else {
                for policy in global_policies {
                    if let Some(cache_ref) = policy
                        .cache_refs
                        .iter()
                        .find(|cache_ref| cache_ref.is_on && !cache_ref.is_reverse)
                    {
                        return Some((cache_ref.clone(), Some(policy.clone())));
                    }
                }
            }
        }

        None
    }

    fn report_remote_purge(api_config: Arc<ApiConfig>, key: String) {
        tokio::spawn(async move {
            let client = match crate::rpc::client::SharedRpcClient::get(&api_config)
                .await
                .map(|s| s.as_rpc_client())
            {
                Ok(client) => client,
                Err(err) => {
                    warn!("CACHE_PURGE: create RPC client failed: {}", err);
                    return;
                }
            };
            let mut service = client.server_service();
            match service
                .purge_server_cache(crate::pb::PurgeServerCacheRequest {
                    keys: vec![key.clone()],
                    prefixes: Vec::new(),
                    description: "local PURGE request".to_string(),
                })
                .await
            {
                Ok(resp) => {
                    let resp = resp.into_inner();
                    if !resp.is_ok {
                        warn!(
                            "CACHE_PURGE: remote purge task rejected for {}: {}",
                            key, resp.message
                        );
                    }
                }
                Err(err) => warn!("CACHE_PURGE: remote purge task failed for {}: {}", key, err),
            }
        });
    }

    fn build_location_lb_if_configured(
        &self,
        server_id: i64,
        location: Option<&crate::config_models::LocationConfig>,
    ) -> Option<Arc<crate::lb_factory::AnyLoadBalancer>> {
        let rp_cfg = location
            .and_then(|loc| loc.reverse_proxy.as_ref())
            .filter(|rp| {
                rp.is_on || !rp.primary_origins.is_empty() || !rp.backup_origins.is_empty()
            })?
            .clone();
        let (level, parent_nodes, tiered_origin_bypass, allow_lan_ip, global_http) =
            self.config.get_origin_build_context_sync();
        let (lb, _) = crate::lb_factory::build_lb_with_global_http(
            server_id,
            &rp_cfg,
            level,
            parent_nodes.as_ref(),
            tiered_origin_bypass,
            allow_lan_ip,
            global_http.as_ref(),
        );
        Some(lb)
    }

    fn outbound_waf_block_response(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        matched: &crate::firewall::MatchedAction,
    ) -> (u16, String) {
        let (mut status, mut body) = match &matched.action {
            crate::firewall::ActionResponse::Block { status, body } => (*status, body.clone()),
            crate::firewall::ActionResponse::Page { status, body, .. } => (*status, body.clone()),
            _ => (403, "Blocked by WAF".to_string()),
        };
        if let Some(opts) = &matched.block_options {
            if opts.status_code > 0 {
                status = opts.status_code;
            }
            if !opts.body.is_empty() {
                body = opts.body.clone();
            }
        } else if let Some(opts) = ctx.global_waf_block_options.as_deref() {
            if opts.status_code > 0 {
                status = opts.status_code;
            }
            if !opts.body.is_empty() {
                body = opts.body.clone();
            }
        }
        let status = status.clamp(100, 599) as u16;
        let resolved_body = self.render_waf_block_body(session, ctx, &body, status);
        (status, resolved_body)
    }

    fn render_waf_block_body(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        body: &str,
        status: u16,
    ) -> String {
        let resolved = self.render_page_template(session, ctx, body, status);
        let composed = Self::compose_waf_block_body(resolved, body, status, &ctx.request_id);
        self.render_page_template(session, ctx, &composed, status)
    }

    fn compose_waf_block_body(
        resolved: String,
        source_body: &str,
        status: u16,
        request_id: &str,
    ) -> String {
        if Self::looks_like_full_html_document(&resolved) {
            return resolved;
        }
        let extra = if Self::is_default_waf_block_body(source_body) {
            String::new()
        } else {
            format!(r#"<div class="block-custom" data-i18n-ignore>{resolved}</div>"#)
        };
        crate::pages::block_page(
            crate::pages::Lang::En,
            status,
            "This request was blocked by the security policy.",
            request_id,
            &extra,
        )
    }

    fn looks_like_full_html_document(body: &str) -> bool {
        let trimmed = Self::trim_html_document_preamble(body).to_ascii_lowercase();
        trimmed.starts_with("<!doctype html") || trimmed.starts_with("<html")
    }

    fn trim_html_document_preamble(mut body: &str) -> &str {
        body = body.trim_start_matches('\u{feff}').trim_start();
        loop {
            let lower = body.to_ascii_lowercase();
            if lower.starts_with("<!--") {
                if let Some(end) = lower.find("-->") {
                    body = body[end + 3..].trim_start_matches('\u{feff}').trim_start();
                    continue;
                }
            }
            if lower.starts_with("<?xml") {
                if let Some(end) = lower.find("?>") {
                    body = body[end + 2..].trim_start_matches('\u{feff}').trim_start();
                    continue;
                }
            }
            return body;
        }
    }

    fn is_default_waf_block_body(body: &str) -> bool {
        let normalized = body.trim();
        normalized.is_empty()
            || normalized.eq_ignore_ascii_case("Blocked by WAF")
            || normalized.eq_ignore_ascii_case("Blocked by Outbound WAF")
    }

    fn status_message(status: u16) -> String {
        http::StatusCode::from_u16(status)
            .ok()
            .and_then(|code| code.canonical_reason().map(str::to_string))
            .unwrap_or_default()
    }

    fn response_status_from_i64(status: i64, default_status: u16) -> u16 {
        u16::try_from(status)
            .ok()
            .filter(|code| (100..=599).contains(code))
            .unwrap_or(default_status)
    }

    fn waf_response_status(status: i32, default_status: u16) -> u16 {
        Self::response_status_from_i64(i64::from(status), default_status)
    }

    fn waf_redirect_status(status: i32) -> u16 {
        u16::try_from(status)
            .ok()
            .filter(|code| (300..=399).contains(code))
            .unwrap_or(302)
    }

    fn insert_location_header(resp: &mut pingora_http::ResponseHeader, location: impl AsRef<str>) {
        if resp.insert_header("location", location.as_ref()).is_err() {
            debug!("Invalid Location header value generated, falling back to /");
            let _ = resp.insert_header("location", "/");
        }
    }

    fn sync_response_headers(
        upstream_response: &pingora::http::ResponseHeader,
        ctx: &mut ProxyCTX,
    ) {
        let needs_response_headers =
            ctx.response_headers.is_allocated() || Self::access_log_needs_response_headers(ctx);

        if !needs_response_headers {
            ctx.response_headers_size = upstream_response
                .headers
                .iter()
                .map(|(name, value)| name.as_str().len() + value.len() + 4)
                .sum();
            return;
        }

        ctx.response_headers.ensure_allocated();
        ctx.response_headers.clear();
        ctx.response_headers_size = 0;
        for (name, value) in upstream_response.headers.iter() {
            ctx.response_headers_size += name.as_str().len() + value.len() + 4;
            if let Ok(value_str) = value.to_str() {
                ctx.response_headers
                    .insert(name.to_string(), value_str.to_string());
            }
        }
    }

    fn access_log_needs_response_headers(ctx: &ProxyCTX) -> bool {
        if !ctx.access_log_module_enabled || !ctx.global_access_log_on {
            return false;
        }
        let field_enabled = ctx
            .access_log_ref
            .as_ref()
            .map(|access_log| access_log.fields.is_empty() || access_log.fields.contains(&22))
            .unwrap_or(true);
        field_enabled
            && ctx
                .global_access_log_config
                .as_ref()
                .map(|cfg| cfg.enable_response_headers)
                .unwrap_or(true)
    }

    fn evaluate_outbound_waf_body(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        body: &[u8],
        bytes_sent: usize,
    ) -> Option<crate::firewall::MatchedAction> {
        let outbound_ctx = crate::firewall::OutboundContext {
            status: ctx.response_status,
            headers: &ctx.response_headers,
            body,
            bytes_sent,
        };
        Self::evaluate_outbound_waf_compiled_first(session, ctx, &outbound_ctx)
    }

    fn evaluate_outbound_waf_compiled_first(
        session: &Session,
        ctx: &ProxyCTX,
        outbound_ctx: &crate::firewall::OutboundContext<'_>,
    ) -> Option<crate::firewall::MatchedAction> {
        for policy in &ctx.compiled_plans.global_firewall {
            if let Some(action) = crate::firewall::compiled::evaluate_compiled_outbound_policy(
                policy,
                session,
                &ctx.request_body,
                &outbound_ctx,
                Self::forwarded_proto(session, ctx),
            ) {
                return Some(action);
            }
        }
        if ctx.compiled_plans.global_firewall.is_empty() {
            crate::metrics::METRICS.waf.record_legacy_fallback();
            if let Some(ref global_policies) = ctx.firewall_policies_snapshot {
                for policy in global_policies.iter() {
                    if !policy.is_on {
                        continue;
                    }
                    if let Some(action) = crate::firewall::evaluate_outbound_policy(
                        policy,
                        session,
                        &ctx.request_body,
                        &outbound_ctx,
                        Self::forwarded_proto(session, ctx),
                    ) {
                        return Some(action);
                    }
                }
            }
        }

        if let Some(server) = &ctx.server
            && let Some(web) = &server.web
            && let Some(fw_ref) = &web.firewall_ref
            && fw_ref.is_on
            && let Some(policy) = &web.firewall_policy
        {
            let compiled_policy = server
                .id
                .and_then(|id| ctx.compiled_plans.server_firewall.get(&id));
            return if let Some(compiled_policy) = compiled_policy {
                crate::firewall::compiled::evaluate_compiled_outbound_policy_with_server(
                    compiled_policy,
                    session,
                    &ctx.request_body,
                    &outbound_ctx,
                    Self::forwarded_proto(session, ctx),
                    Some(server.as_ref()),
                )
            } else {
                crate::metrics::METRICS.waf.record_legacy_fallback();
                crate::firewall::evaluate_outbound_policy_with_server(
                    policy,
                    session,
                    &ctx.request_body,
                    &outbound_ctx,
                    Self::forwarded_proto(session, ctx),
                    Some(server.as_ref()),
                )
            };
        }

        None
    }

    fn disable_request_cache(session: &mut Session, ctx: &mut ProxyCTX, reason: &'static str) {
        ctx.cache_ref = None;
        ctx.cache_policy = None;
        ctx.compiled_cache_ref = None;
        ctx.compiled_cache_policy = None;
        ctx.cache_key = None;
        ctx.cache_purge_authorized = false;
        if matches!(
            session.cache.phase(),
            pingora_cache::CachePhase::Disabled(pingora_cache::NoCacheReason::NeverEnabled)
        ) {
            return;
        }
        session
            .cache
            .disable(pingora_cache::NoCacheReason::Custom(reason));
    }

    fn cache_eval_context<'a>(
        session: &'a Session,
        ctx: &ProxyCTX,
        scheme: &'a str,
    ) -> crate::cache::compiled::CacheEvalContext<'a> {
        let mut cache_ctx = crate::cache::compiled::CacheEvalContext::new(session, scheme);
        cache_ctx.server = ctx.server.clone();
        cache_ctx.client_ip = Some(ctx.client_ip);
        cache_ctx.client_port = Some(ctx.client_port);
        cache_ctx.raw_remote_addr = Some(ctx.raw_remote_addr.clone());
        cache_ctx.start_timestamp_millis = Some(ctx.start_timestamp_millis);
        cache_ctx.is_http3_bridge = ctx.is_http3_bridge;
        cache_ctx.host = Some(ctx.host.clone());
        cache_ctx.analyzed = ctx.analyzed.clone();
        cache_ctx
    }

    fn cached_response_header_for_store(
        resp: &pingora_http::ResponseHeader,
        ttl: u64,
    ) -> pingora_http::ResponseHeader {
        let mut cached_header =
            pingora_http::ResponseHeader::build(resp.status.as_u16(), Some(resp.headers.len()))
                .unwrap();
        for (name, value) in resp.headers.iter() {
            if name.as_str().eq_ignore_ascii_case("cache-control") {
                // Force a valid shared-cache header for the stored copy. The
                // downstream response itself is not changed by this helper.
                cached_header
                    .insert_header("cache-control", format!("public, max-age={}", ttl))
                    .unwrap();
                continue;
            }
            if !crate::cache::should_store_response_header(name.as_str()) {
                continue;
            }
            cached_header
                .insert_header(name.clone(), value.clone())
                .unwrap();
        }
        if !cached_header.headers.contains_key("cache-control") {
            cached_header
                .insert_header("cache-control", format!("public, max-age={}", ttl))
                .unwrap();
        }
        cached_header
    }

    fn active_cache_key_config(cache: &WebCacheConfig) -> Option<&HTTPCacheKeyConfig> {
        cache
            .key
            .as_ref()
            .filter(|key| key.is_on && !key.host.trim().is_empty())
    }

    fn cache_key_scheme_host(
        request_scheme: &str,
        request_host: &str,
        cache: &WebCacheConfig,
    ) -> (String, String) {
        let mut scheme = request_scheme.to_ascii_lowercase();
        let mut host = Self::normalize_request_host(request_host);
        if let Some(key_config) = Self::active_cache_key_config(cache) {
            let configured_scheme = key_config.scheme.trim();
            if !configured_scheme.is_empty() {
                scheme = configured_scheme.to_ascii_lowercase();
            }
            host = Self::normalize_request_host(&key_config.host);
        }
        (scheme, host)
    }

    fn apply_cache_key_config_to_context(
        cache_ctx: &mut crate::cache::compiled::CacheEvalContext<'_>,
        cache: &WebCacheConfig,
    ) {
        let Some(key_config) = Self::active_cache_key_config(cache) else {
            return;
        };
        let request_host = cache_ctx.host.as_deref().unwrap_or_default();
        let (scheme, host) = Self::cache_key_scheme_host(cache_ctx.scheme, request_host, cache);
        if !key_config.scheme.trim().is_empty() {
            cache_ctx.cache_key_scheme = Some(scheme);
        }
        cache_ctx.cache_key_host = Some(host);
    }

    fn cache_ref_matches_request_with_context(
        cache_ref: &HTTPCacheRef,
        cache_ctx: &crate::cache::compiled::CacheEvalContext<'_>,
    ) -> bool {
        let session = cache_ctx.session;
        let scheme = cache_ctx.scheme;
        let path = session.req_header().uri.path();
        let mut url = None;
        if !cache_ref.except_url_patterns.is_empty()
            && cache_ref.except_url_patterns.iter().any(|pattern| {
                pattern.matches(path)
                    || pattern.matches(Self::cache_match_url(&mut url, session, scheme, path))
            })
        {
            return false;
        }
        if !cache_ref.only_url_patterns.is_empty()
            && !cache_ref.only_url_patterns.iter().any(|pattern| {
                pattern.matches(path)
                    || pattern.matches(Self::cache_match_url(&mut url, session, scheme, path))
            })
        {
            return false;
        }

        if let Some(conds) = &cache_ref.conds
            && conds.is_on
            && !conds.groups.is_empty()
        {
            return conds
                .request_match_with_context(cache_ctx)
                .is_request_candidate();
        }

        if let Some(simple_cond) = &cache_ref.simple_cond {
            return simple_cond
                .request_match_with_context(cache_ctx)
                .is_request_candidate();
        }

        true
    }

    fn uam_matches_request_url(cfg: &UAMConfig, session: &Session, ctx: &ProxyCTX) -> bool {
        let path = session.req_header().uri.path();
        let mut url = None;
        if cfg.except_url_patterns.iter().any(|pattern| {
            pattern.matches(path)
                || pattern.matches(Self::cache_match_url(
                    &mut url,
                    session,
                    Self::forwarded_proto(session, ctx),
                    path,
                ))
        }) {
            return false;
        }
        if cfg.only_url_patterns.is_empty() {
            return true;
        }
        cfg.only_url_patterns.iter().any(|pattern| {
            pattern.matches(path)
                || pattern.matches(Self::cache_match_url(
                    &mut url,
                    session,
                    Self::forwarded_proto(session, ctx),
                    path,
                ))
        })
    }

    fn cache_match_url<'a>(
        url: &'a mut Option<String>,
        session: &Session,
        scheme: &str,
        path: &str,
    ) -> &'a str {
        url.get_or_insert_with(|| {
            let host = session
                .get_header("host")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            format!("{scheme}://{host}{path}")
        })
        .as_str()
    }

    fn downstream_local_port(session: &Session) -> Option<u16> {
        session
            .downstream_session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .and_then(|sd| sd.local_addr())
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.port())
    }

    fn downstream_local_ip(session: &Session) -> Option<String> {
        session
            .downstream_session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .and_then(|sd| sd.local_addr())
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip().to_string())
    }

    fn web_document_root(server: Option<&crate::config_models::ServerConfig>) -> String {
        server
            .and_then(|server| server.web.as_ref())
            .and_then(|web| web.root.as_ref())
            .and_then(Self::document_root_from_value)
            .unwrap_or_default()
    }

    fn document_root_from_value(value: &Value) -> Option<String> {
        if let Some(raw) = value.as_str() {
            return Some(raw.to_string()).filter(|value| !value.is_empty());
        }
        let object = value.as_object()?;
        ["dir", "directory", "path", "root"]
            .into_iter()
            .filter_map(|key| object.get(key))
            .find_map(|value| value.as_str().map(str::to_string))
            .filter(|value| !value.is_empty())
    }

    fn infer_origin_protocol(origin_address: &str, downstream_scheme: &str) -> String {
        if let Some((scheme, _)) = origin_address.split_once("://") {
            return scheme.to_string();
        }
        let port = origin_address
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok());
        match port {
            Some(443) => "https".to_string(),
            Some(80) => "http".to_string(),
            _ => downstream_scheme.to_string(),
        }
    }

    fn maybe_strip_host_port(host: &str, strip: bool) -> String {
        if strip {
            crate::lb_factory::strip_addr_port(host)
        } else {
            host.to_string()
        }
    }

    fn normalize_request_host(host: &str) -> String {
        let host = host.rsplit('@').next().unwrap_or(host).trim();
        crate::lb_factory::strip_addr_port(host)
            .trim_end_matches('.')
            .to_ascii_lowercase()
    }

    fn request_host(session: &Session) -> String {
        let host = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| {
                session
                    .get_header(":authority")
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
            })
            .or_else(|| {
                session
                    .req_header()
                    .uri
                    .authority()
                    .map(|value| value.as_str())
            })
            .or_else(|| session.req_header().uri.host())
            .unwrap_or_default();
        Self::normalize_request_host(host)
    }

    fn replace_addr_port(addr: &str, port: u16) -> String {
        let host = crate::lb_factory::strip_addr_port(addr);
        if host.contains(':') && !host.starts_with('[') {
            format!("[{}]:{}", host, port)
        } else {
            format!("{}:{}", host, port)
        }
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

    fn template_value(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        raw: &str,
        var_name: &str,
        status: u16,
    ) -> String {
        match var_name {
            "requestId" => ctx.request_id.clone(),
            "product.name" => self.product_name(ctx),
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
            "scheme" => Self::forwarded_proto(session, ctx).to_string(),
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
            "requestRefererBlock" => {
                let referer = session
                    .get_header("referer")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                crate::headers::extract_referer_block(referer)
            }
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
            "hostname" => HOSTNAME.clone(),
            _ => crate::firewall::matcher_plus::format_variables(
                session,
                raw,
                &ctx.request_body,
                Self::forwarded_proto(session, ctx),
            ),
        }
    }

    fn metric_request_context(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        bytes_sent: u64,
        bytes_received: u64,
        user_agent: &str,
    ) -> crate::metrics::MetricRequestContext {
        let req = session.req_header();
        let mut values = BTreeMap::new();
        let scheme = Self::forwarded_proto(session, ctx);
        let request_uri = req
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let host = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v))
            .or_else(|| req.uri.host())
            .unwrap_or(ctx.host.as_str());
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
        let status = ctx.response_status;
        let started = crate::utils::time::local_from_timestamp_millis(ctx.start_timestamp_millis);
        let remote_user = req
            .headers
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
            .unwrap_or_default();

        values.insert(
            "edgeVersion".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
        values.insert("remoteAddr".to_string(), ctx.client_ip_str.clone());
        values.insert("remoteAddrValue".to_string(), ctx.client_ip_str.clone());
        values.insert(
            "rawRemoteAddr".to_string(),
            Self::raw_remote_ip(&ctx.raw_remote_addr, ctx.client_ip),
        );
        values.insert("remotePort".to_string(), ctx.client_port.to_string());
        values.insert("remoteUser".to_string(), remote_user);
        values.insert("requestId".to_string(), ctx.request_id.clone());
        values.insert("requestURI".to_string(), request_uri.to_string());
        values.insert("requestUri".to_string(), request_uri.to_string());
        values.insert(
            "requestURL".to_string(),
            format!("{}://{}{}", scheme, host, request_uri),
        );
        values.insert("requestPath".to_string(), req.uri.path().to_string());
        let extension = std::path::Path::new(req.uri.path())
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!(".{ext}"))
            .unwrap_or_default();
        values.insert("requestPathExtension".to_string(), extension.clone());
        values.insert(
            "requestPathLowerExtension".to_string(),
            extension.to_ascii_lowercase(),
        );
        values.insert("requestLength".to_string(), bytes_received.to_string());
        values.insert(
            "requestTime".to_string(),
            format!("{:.6}", ctx.start_time.elapsed().as_secs_f64()),
        );
        values.insert("requestMethod".to_string(), req.method.to_string());
        values.insert(
            "requestFilename".to_string(),
            ctx.cache_key
                .clone()
                .unwrap_or_else(|| req.uri.path().to_string()),
        );
        values.insert("scheme".to_string(), scheme.to_string());
        values.insert("serverProtocol".to_string(), proto.to_string());
        values.insert("proto".to_string(), proto.to_string());
        values.insert("bytesSent".to_string(), bytes_sent.to_string());
        values.insert(
            "bodyBytesSent".to_string(),
            session.body_bytes_sent().to_string(),
        );
        values.insert("status".to_string(), status.to_string());
        values.insert("statusMessage".to_string(), Self::status_message(status));
        values.insert(
            "timeISO8601".to_string(),
            started.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string(),
        );
        values.insert(
            "timeLocal".to_string(),
            started.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
        );
        values.insert(
            "msec".to_string(),
            format!("{:.6}", ctx.start_timestamp_millis as f64 / 1000.0),
        );
        values.insert(
            "timestamp".to_string(),
            (ctx.start_timestamp_millis / 1000).to_string(),
        );
        values.insert("host".to_string(), host.to_string());
        values.insert(
            "cname".to_string(),
            ctx.server
                .as_ref()
                .and_then(|server| {
                    server
                        .server_names
                        .iter()
                        .find(|name| {
                            name.r#type
                                .as_deref()
                                .is_some_and(|kind| kind.eq_ignore_ascii_case("cname"))
                        })
                        .map(|name| name.name.clone())
                })
                .unwrap_or_default(),
        );
        let referer = session
            .get_header("referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        values.insert("referer".to_string(), referer.to_string());
        values.insert(
            "referer.host".to_string(),
            referer
                .split_once("://")
                .map(|(_, rest)| rest.split('/').next().unwrap_or(""))
                .unwrap_or("")
                .to_string(),
        );
        values.insert("userAgent".to_string(), user_agent.to_string());
        values.insert(
            "contentType".to_string(),
            session
                .get_header("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string(),
        );
        values.insert(
            "request".to_string(),
            format!("{} {} {}", req.method, request_uri, proto),
        );
        let cookies_header = merged_session_cookie_header(session).unwrap_or_default();
        values.insert("cookies".to_string(), cookies_header.clone());
        values.insert(
            "isArgs".to_string(),
            if req.uri.query().is_some() { "?" } else { "" }.to_string(),
        );
        let query = req.uri.query().unwrap_or("");
        values.insert("args".to_string(), query.to_string());
        values.insert("queryString".to_string(), query.to_string());
        values.insert("serverName".to_string(), {
            ctx.server
                .as_ref()
                .and_then(|server| server.server_names.first())
                .map(|name| name.name.clone())
                .unwrap_or_else(|| host.to_string())
        });
        values.insert(
            "serverAddr".to_string(),
            if ctx
                .global_http_config
                .as_ref()
                .map(|config| config.enable_server_addr_variable)
                .unwrap_or_else(|| {
                    self.config
                        .get_global_http_config_sync()
                        .enable_server_addr_variable
                })
            {
                Self::downstream_local_ip(session).unwrap_or_default()
            } else {
                String::new()
            },
        );
        values.insert(
            "serverPort".to_string(),
            Self::downstream_local_port(session)
                .map(|port| port.to_string())
                .unwrap_or_default(),
        );
        values.insert("hostname".to_string(), HOSTNAME.clone());
        values.insert(
            "documentRoot".to_string(),
            Self::web_document_root(ctx.server.as_deref()),
        );
        values.insert("node.id".to_string(), self.api_config.node_id.clone());
        values.insert("node.name".to_string(), HOSTNAME.clone());
        values.insert("node.role".to_string(), String::new());
        values.insert("product.name".to_string(), self.product_name(ctx));
        values.insert(
            "product.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        );
        values.insert("origin.address".to_string(), ctx.origin_address.clone());
        values.insert("origin.addr".to_string(), ctx.origin_address.clone());
        values.insert(
            "origin.host".to_string(),
            ctx.origin_address
                .split(':')
                .next()
                .unwrap_or("")
                .to_string(),
        );
        values.insert("origin.id".to_string(), ctx.origin_id.to_string());
        let origin_protocol = Self::infer_origin_protocol(&ctx.origin_address, scheme);
        values.insert("origin.scheme".to_string(), origin_protocol.clone());
        values.insert("origin.protocol".to_string(), origin_protocol);
        values.insert("origin.code".to_string(), String::new());

        for (name, value) in req.headers.iter() {
            if let Ok(value) = value.to_str() {
                values
                    .entry(format!("header.{}", name.as_str()))
                    .or_insert_with(|| value.to_string());
                values
                    .entry(format!("http.{}", name.as_str()))
                    .or_insert_with(|| value.to_string());
            }
        }
        values.insert(
            "headers".to_string(),
            req.headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| format!("{}: {}", name.as_str(), value))
                })
                .collect::<Vec<_>>()
                .join("\n"),
        );
        for cookie in cookies_header.split(';').map(str::trim) {
            if let Some((name, value)) = cookie.split_once('=') {
                values.insert(format!("cookie.{}", name.trim()), value.trim().to_string());
            }
        }
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            if let Some((name, value)) = pair.split_once('=') {
                let decoded = urlencoding::decode(value)
                    .map(|value| value.into_owned())
                    .unwrap_or_else(|_| value.to_string());
                values.insert(format!("arg.{name}"), decoded);
            }
        }
        for (name, value) in ctx.response_headers.iter() {
            values.insert(format!("response.header.{name}"), value.clone());
            if name.eq_ignore_ascii_case("content-type") {
                values.insert("response.contentType".to_string(), value.clone());
            }
        }
        values.insert(
            "browser.isMobile".to_string(),
            if Self::is_mobile_user_agent(user_agent) {
                "1"
            } else {
                "0"
            }
            .to_string(),
        );

        if let Some(analyzed) = ctx.analyzed.as_ref() {
            values.insert("browser.name".to_string(), analyzed.browser.to_string());
            values.insert(
                "browser.version".to_string(),
                analyzed.browser_version.to_string(),
            );
            values.insert("browser.os.name".to_string(), analyzed.os.to_string());
            values.insert(
                "browser.os.version".to_string(),
                analyzed.os_version.to_string(),
            );
            if let Some(geo) = analyzed.geo.as_ref() {
                values.insert("geo.country.name".to_string(), geo.country.to_string());
                values.insert("geo.country.id".to_string(), geo.country_id.to_string());
                values.insert("geo.province.name".to_string(), geo.region.to_string());
                values.insert("geo.province.id".to_string(), geo.region_id.to_string());
                values.insert("geo.city.name".to_string(), geo.city.to_string());
                values.insert("geo.city.id".to_string(), geo.city_id.to_string());
                values.insert("isp.name".to_string(), geo.provider.to_string());
            }
        }
        values
            .entry("geo.country.id".to_string())
            .or_insert_with(|| "0".to_string());
        values
            .entry("geo.province.id".to_string())
            .or_insert_with(|| "0".to_string());
        values
            .entry("geo.city.id".to_string())
            .or_insert_with(|| "0".to_string());
        values.entry("geo.town.name".to_string()).or_default();
        values
            .entry("geo.town.id".to_string())
            .or_insert_with(|| "0".to_string());
        values.entry("isp.id".to_string()).or_insert_with(|| {
            crate::metrics::storage::lookup_region_provider_id(ctx.client_ip).to_string()
        });

        let host_parts = host.split('.').collect::<Vec<_>>();
        if let Some(first) = host_parts.first() {
            values.insert("host.first".to_string(), (*first).to_string());
            values.insert("host.0".to_string(), (*first).to_string());
        }
        if let Some(last) = host_parts.last() {
            values.insert("host.last".to_string(), (*last).to_string());
            values.insert("host.-1".to_string(), (*last).to_string());
        }
        for idx in 1..=4 {
            if let Some(part) = host_parts.get(idx) {
                values.insert(format!("host.{idx}"), (*part).to_string());
            }
            if host_parts.len() > idx {
                values.insert(
                    format!("host.-{}", idx + 1),
                    host_parts[host_parts.len() - idx - 1].to_string(),
                );
            }
        }

        crate::metrics::MetricRequestContext { values }
    }

    fn render_template(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        template: &str,
        status: u16,
        html_escape_by_default: bool,
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
                let mut value = self.template_value(session, ctx, raw, var_name, status);
                let mut escape_html = html_escape_by_default;

                for modifier in parts {
                    match modifier.trim() {
                        "raw" => escape_html = false,
                        "escape" | "htmlEscape" => {
                            value = Self::html_escape(&value);
                            escape_html = false;
                        }
                        other => value = Self::apply_template_modifier(value, other),
                    }
                }

                if escape_html {
                    Self::html_escape(&value)
                } else {
                    value
                }
            })
            .to_string()
    }

    fn render_page_template(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        template: &str,
        status: u16,
    ) -> String {
        self.render_template(session, ctx, template, status, true)
    }

    fn render_raw_template(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        template: &str,
        status: u16,
    ) -> String {
        self.render_template(session, ctx, template, status, false)
    }

    fn cleanup_request_limit_bindings() {
        let now = std::time::Instant::now();
        let stale: Vec<(String, i64, std::net::IpAddr)> = REQUEST_LIMIT_BINDINGS
            .iter()
            .filter_map(|entry| {
                (now.duration_since(entry.value().last_seen).as_secs()
                    > REQUEST_LIMIT_BINDING_IDLE_SECS)
                    .then(|| {
                        (
                            entry.key().clone(),
                            entry.value().server_id,
                            entry.value().client_ip,
                        )
                    })
            })
            .collect();

        for (key, server_id, client_ip) in stale {
            if REQUEST_LIMIT_BINDINGS.remove(&key).is_some() {
                Self::decrement_request_limit_count(server_id, client_ip);
            }
        }
        // Evict zero-count entries so counter maps don't grow unbounded.
        REQUEST_LIMIT_SERVER_COUNTS.retain(|_, count| count.load(Ordering::Relaxed) > 0);
        REQUEST_LIMIT_IP_COUNTS.retain(|_, count| count.load(Ordering::Relaxed) > 0);
    }

    fn request_limit_binding_capacity() -> usize {
        if MEMORY_GOVERNOR.is_memory_pressure_high() {
            REQUEST_LIMIT_BINDINGS_MAX_PRESSURE
        } else {
            REQUEST_LIMIT_BINDINGS_MAX_NORMAL
        }
    }

    fn request_limit_ip_key(ip: std::net::IpAddr) -> std::net::IpAddr {
        match ip {
            std::net::IpAddr::V4(_) => ip,
            std::net::IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return std::net::IpAddr::V4(v4);
                }
                let mut octets = v6.octets();
                octets[8..].fill(0);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
        }
    }

    fn cleanup_cc_bw_counters() {
        // WAF state now owns CC bandwidth counters so they share the same GC
        // cadence, capacity policy, and IPv6 /64 aggregation as other WAF maps.
    }

    fn request_limit_count(map: &DashMap<i64, Arc<AtomicI32>>, key: i64) -> i32 {
        map.get(&key)
            .map(|count| count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn request_limit_ip_count(ip: std::net::IpAddr) -> i32 {
        let ip = Self::request_limit_ip_key(ip);
        REQUEST_LIMIT_IP_COUNTS
            .get(&ip)
            .map(|count| count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn decrement_request_limit_count(server_id: i64, client_ip: std::net::IpAddr) {
        let client_ip = Self::request_limit_ip_key(client_ip);
        if let Some(count) = REQUEST_LIMIT_SERVER_COUNTS.get(&server_id) {
            loop {
                let cur = count.load(Ordering::Relaxed);
                if cur <= 0 {
                    break;
                }
                if count
                    .compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
        if let Some(count) = REQUEST_LIMIT_IP_COUNTS.get(&client_ip) {
            loop {
                let cur = count.load(Ordering::Relaxed);
                if cur <= 0 {
                    break;
                }
                if count
                    .compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
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

        let now = std::time::Instant::now();
        let client_ip = Self::request_limit_ip_key(client_ip);

        if let Some(mut existing) = REQUEST_LIMIT_BINDINGS.get_mut(raw_remote_addr) {
            existing.last_seen = now;
            return true;
        }

        if REQUEST_LIMIT_BINDINGS.len() >= Self::request_limit_binding_capacity() {
            Self::cleanup_request_limit_bindings();
            if REQUEST_LIMIT_BINDINGS.len() >= Self::request_limit_binding_capacity() {
                return false;
            }
        }

        // Fast-path: non-atomic reads for early bailout
        if max_conns > 0 {
            let current_server_conns =
                Self::request_limit_count(&REQUEST_LIMIT_SERVER_COUNTS, server_id);
            if current_server_conns >= max_conns {
                return false;
            }
        }

        if max_conns_per_ip > 0 {
            let current_ip_conns = Self::request_limit_ip_count(client_ip);
            if current_ip_conns >= max_conns_per_ip {
                return false;
            }
        }

        // CAS-based atomic increment to avoid TOCTOU between the reads above and the binding insert
        if max_conns > 0 {
            let entry = REQUEST_LIMIT_SERVER_COUNTS
                .entry(server_id)
                .or_insert_with(|| Arc::new(AtomicI32::new(0)));
            loop {
                let cur = entry.load(Ordering::Relaxed);
                if cur >= max_conns {
                    return false;
                }
                if entry
                    .compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }

        if max_conns_per_ip > 0 {
            let entry = REQUEST_LIMIT_IP_COUNTS
                .entry(client_ip)
                .or_insert_with(|| Arc::new(AtomicI32::new(0)));
            loop {
                let cur = entry.load(Ordering::Relaxed);
                if cur >= max_conns_per_ip {
                    // Rollback server count increment
                    if max_conns > 0 {
                        if let Some(count) = REQUEST_LIMIT_SERVER_COUNTS.get(&server_id) {
                            loop {
                                let c = count.load(Ordering::Relaxed);
                                if c <= 0 {
                                    break;
                                }
                                if count
                                    .compare_exchange_weak(
                                        c,
                                        c - 1,
                                        Ordering::Relaxed,
                                        Ordering::Relaxed,
                                    )
                                    .is_ok()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    return false;
                }
                if entry
                    .compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
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
        Self::http_session_socket_client_ip(&session.downstream_session)
    }

    fn downstream_client_socket_addr(session: &Session, ctx: &ProxyCTX) -> SocketAddr {
        session
            .downstream_session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .and_then(|sd| sd.peer_addr().cloned())
            .or_else(|| session.downstream_session.client_addr().cloned())
            .and_then(|addr| addr.as_inet().copied())
            .map(|socket_addr| {
                let port = if ctx.client_port > 0 {
                    ctx.client_port
                } else {
                    socket_addr.port()
                };
                SocketAddr::new(ctx.client_ip, port)
            })
            .unwrap_or_else(|| SocketAddr::new(ctx.client_ip, ctx.client_port))
    }

    fn proxy_protocol_origin_group_key(
        client_addr: SocketAddr,
        config: ProxyProtocolConfig,
    ) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut hasher = ahash::AHasher::default();
        client_addr.hash(&mut hasher);
        config.normalized_version().hash(&mut hasher);
        0x5050_4f52_4947_494e_u64 ^ hasher.finish()
    }

    fn http_session_socket_client_ip(
        session: &pingora_core::protocols::http::ServerSession,
    ) -> (std::net::IpAddr, u16, String) {
        let socket_addr = session
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

    fn classify_downstream_parse_error(error: &Error) -> (&'static str, &'static str) {
        if !matches!(error.etype(), InvalidHTTPHeader) {
            return ("downstream_error", "DOWNSTREAM_PARSE_ERROR");
        }
        let message = error.to_string();
        if message.contains("[22, 3,") || message.contains("\\x16\\x03") {
            return ("tls_on_http", "TLS_ON_HTTP");
        }
        if message.contains("PRI * HTTP/2.0") || message.contains("HTTP/2.0") {
            return ("h2c_probe", "H2C_PROBE");
        }
        ("malformed_http", "MALFORMED_HTTP")
    }

    fn record_malformed_http_defense(&self, defense: &'static str, ip: std::net::IpAddr) {
        let cluster_id = self.config.get_node_cluster_id_sync();
        let Some(config) =
            crate::special_defense::global_tls_exhaustion_config(&self.config, cluster_id)
        else {
            return;
        };
        let node_id = self.api_config.node_id.parse::<i64>().unwrap_or(0);
        crate::special_defense::record_special_defense_hit(
            &self.waf_state,
            node_id,
            cluster_id,
            defense,
            ip,
            config,
        );
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

    fn header_value_ci<'a>(session: &'a Session, name: &str) -> Option<&'a str> {
        session
            .get_header(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn fallback_client_ip(session: &Session, raw_ip: std::net::IpAddr) -> std::net::IpAddr {
        // Only trust forwarded-for-style headers when the immediate peer is
        // local (loopback / private / link-local). When the peer is on the
        // public internet, X-Forwarded-For is attacker-controlled and trusting
        // it would let the client spoof their IP for rate limiting / IP
        // reporting / access logs. The same guard runs in
        // firewall::matcher_plus::parse_remote_ip — keep them in sync.
        if !crate::firewall::matcher_plus::is_local_ip(&raw_ip) {
            return raw_ip;
        }
        for header in [
            "x-cloud-real-ip",
            "x-real-ip",
            "cf-connecting-ip",
            "true-client-ip",
            "x-forwarded-for",
            "x-client-ip",
            "x-original-forwarded-for",
            "x-cluster-client-ip",
            "fastly-client-ip",
            "ali-cdn-real-ip",
            "cdn-src-ip",
            "forwarded",
        ] {
            if let Some(value) = Self::header_value_ci(session, header)
                && let Some(ip) = Self::parse_candidate_ip(value)
            {
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
                let full = caps[0]
                    .strip_prefix("${")
                    .and_then(|s| s.strip_suffix('}'))
                    .unwrap_or("");

                // Split modifier pipeline: ${varName|mod1|mod2}
                let mut parts = full.splitn(2, '|');
                let inner = parts.next().unwrap_or("").trim();
                let modifiers_str = parts.next().unwrap_or("");

                let value = Self::resolve_remote_addr_template_var(
                    session,
                    inner,
                    raw_ip,
                    raw_remote_addr,
                    remote_port,
                );

                // Apply modifier pipeline (reuse existing apply_template_modifier).
                modifiers_str
                    .split('|')
                    .filter(|m| !m.trim().is_empty())
                    .fold(value, |v, m| Self::apply_template_modifier(v, m.trim()))
            })
            .to_string()
    }

    /// Resolve a single variable name (no modifiers) inside `${...}`.
    fn resolve_remote_addr_template_var(
        session: &Session,
        inner: &str,
        raw_ip: std::net::IpAddr,
        raw_remote_addr: &str,
        remote_port: u16,
    ) -> String {
        if inner.eq_ignore_ascii_case("rawRemoteAddr") {
            return raw_ip.to_string();
        }
        if inner.eq_ignore_ascii_case("remoteAddr") || inner.eq_ignore_ascii_case("remoteAddrValue")
        {
            return Self::fallback_client_ip(session, raw_ip).to_string();
        }
        if inner.eq_ignore_ascii_case("remotePort") {
            return remote_port.to_string();
        }
        if inner.eq_ignore_ascii_case("socketRemoteAddr") {
            return raw_remote_addr.to_string();
        }
        if inner.eq_ignore_ascii_case("host") || inner.eq_ignore_ascii_case("requestHost") {
            return session
                .get_header("host")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(':').next().unwrap_or(v).to_string())
                .unwrap_or_default();
        }

        // ${host.first} / ${host.last} — split Host header by '.' and take
        // the first or last segment (useful for building custom identifiers).
        if inner.eq_ignore_ascii_case("host.first") {
            let host = session
                .get_header("host")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(':').next().unwrap_or(v))
                .unwrap_or("");
            return host.split('.').next().unwrap_or("").to_string();
        }
        if inner.eq_ignore_ascii_case("host.last") {
            let host = session
                .get_header("host")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(':').next().unwrap_or(v))
                .unwrap_or("");
            return host.split('.').last().unwrap_or("").to_string();
        }

        // ${node.id} — numeric node identifier from the control-plane config.
        if inner.eq_ignore_ascii_case("node.id") {
            return crate::logging::get_numeric_node_id().to_string();
        }
        // ${node.name} — human-readable node name; falls back to hostname when
        // no explicit name has been assigned.
        if inner.eq_ignore_ascii_case("node.name") {
            return HOSTNAME.clone();
        }

        // ${origin.addr} / ${origin.host} — the upstream backend address used
        // for this request.  These are populated later in the request lifecycle
        // (after upstream selection), so they return an empty string when
        // called during the early IP-resolution phase.  Callers that need the
        // upstream address should use template rendering after upstream
        // selection instead.
        if inner.eq_ignore_ascii_case("origin.addr") || inner.eq_ignore_ascii_case("origin.host") {
            // Not available at IP-resolution time; return empty rather than panicking.
            return String::new();
        }

        // ${geo.country} / ${geo.province} / ${geo.city} / ${geo.isp}
        // — GeoIP lookup on the raw (socket-level) IP.
        if inner.eq_ignore_ascii_case("geo.country") {
            return crate::metrics::analyzer::lookup_geo(raw_ip)
                .map(|g| g.country.to_string())
                .unwrap_or_default();
        }
        if inner.eq_ignore_ascii_case("geo.province") {
            return crate::metrics::analyzer::lookup_geo(raw_ip)
                .map(|g| g.region.to_string())
                .unwrap_or_default();
        }
        if inner.eq_ignore_ascii_case("geo.city") {
            return crate::metrics::analyzer::lookup_geo(raw_ip)
                .map(|g| g.city.to_string())
                .unwrap_or_default();
        }
        if inner.eq_ignore_ascii_case("geo.isp") {
            return crate::metrics::analyzer::lookup_geo(raw_ip)
                .map(|g| g.provider.to_string())
                .unwrap_or_default();
        }

        // ${header.X-Name} / ${requestHeader.X-Name}
        if let Some(name) = inner
            .strip_prefix("requestHeader.")
            .or_else(|| inner.strip_prefix("header."))
            .or_else(|| inner.strip_prefix("requestHeader:"))
            .or_else(|| inner.strip_prefix("header:"))
        {
            // Multi-header syntax: ${header.Name1,Name2} — return the first
            // header that has a non-empty value.
            for part in name.split(',') {
                let part = part.trim();
                if let Some(value) = Self::header_value_ci(session, part) {
                    return value.to_string();
                }
            }
            return String::new();
        }

        String::new()
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
            // When `is_prior` is true this config should override any enclosing
            // location-block's remote-addr rule.  Location blocks are not yet
            // implemented; once they are, callers should consult `is_prior`
            // before falling back to an outer scope's config.

            if remote_addr_cfg.is_direct_type() {
                return raw_ip;
            }

            if remote_addr_cfg.is_request_header_type() {
                // If `request_header_name` is set it becomes the sole
                // lookup target (already reflected by configured_values() /
                // expanded_header_names()).  Otherwise expand multi-header
                // expressions from value/values.
                //
                // Use expanded_header_names() so comma-separated
                // multi-header syntax like `${header.X-Forwarded-For,CF-Connecting-IP}`
                // is flattened and each name is tried in order.
                for header_name in remote_addr_cfg.expanded_header_names() {
                    if let Some(value) = Self::header_value_ci(session, &header_name)
                        && let Some(ip) = Self::parse_candidate_ip(value)
                    {
                        return ip;
                    }
                }
                // No header yielded a valid IP — return raw socket IP rather
                // than falling through to the generic fallback heuristic.
                return raw_ip;
            }

            for configured in remote_addr_cfg.configured_values() {
                let value = Self::resolve_remote_addr_template(
                    session,
                    &configured,
                    raw_ip,
                    raw_remote_addr,
                    remote_port,
                );
                if let Some(ip) = Self::parse_candidate_ip(&value) {
                    return ip;
                }
            }
        }

        Self::fallback_client_ip(session, raw_ip)
    }

    fn should_redirect_to_https(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        server: &ServerConfig,
        host: &str,
    ) -> Option<(String, u16)> {
        if Self::is_https_downstream(session, ctx) {
            return None;
        }

        let request_uri = session
            .req_header()
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");

        if let Some(target) = server
            .id
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
            .and_then(|plan| plan.redirect_to_https_target(host, request_uri))
        {
            return Some(target);
        }

        let redirect = server
            .web
            .as_ref()
            .and_then(|web| web.redirect_to_https.as_ref())?;
        if !redirect.is_on {
            return None;
        }

        if Self::domain_list_matches(&redirect.except_domains, host) {
            return None;
        }
        if !redirect.domains.is_empty() && !Self::domain_list_matches(&redirect.domains, host) {
            return None;
        }

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

        let status = Self::redirect_to_https_status(redirect.status);
        Some((format!("https://{}{}", target_host, request_uri), status))
    }

    fn redirect_to_https_status(status: i32) -> u16 {
        u16::try_from(status)
            .ok()
            .filter(|code| matches!(*code, 301 | 302 | 307 | 308))
            .unwrap_or(301)
    }

    fn www_trailing_slash_redirect(
        server: &crate::config_models::ServerConfig,
        session: &Session,
        host: &str,
    ) -> Option<String> {
        let web = server.web.as_ref()?;
        let prefer_www = web.prefer_www.as_deref().unwrap_or("");
        let trailing_slash = web.trailing_slash.as_deref().unwrap_or("");

        if prefer_www.is_empty() && trailing_slash.is_empty() {
            return None;
        }

        let bare_host = crate::lb_factory::strip_addr_port(host);
        if bare_host.starts_with('[') || bare_host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let new_host = match prefer_www {
            "add" if !bare_host.starts_with("www.") => {
                format!("www.{}", bare_host)
            }
            "remove" if bare_host.starts_with("www.") => bare_host[4..].to_string(),
            _ => bare_host.to_string(),
        };

        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let path = session.req_header().uri.path();

        let new_path_and_query = match trailing_slash {
            "add" if !path.ends_with('/') && !path.contains('.') => {
                let query = session.req_header().uri.query();
                if let Some(q) = query {
                    format!("{}/?{}", path, q)
                } else {
                    format!("{}/", path)
                }
            }
            "remove" if path.len() > 1 && path.ends_with('/') => {
                let query = session.req_header().uri.query();
                let stripped = path.trim_end_matches('/');
                if let Some(q) = query {
                    format!("{}?{}", stripped, q)
                } else {
                    stripped.to_string()
                }
            }
            _ => path_and_query.to_string(),
        };

        if new_host == bare_host && new_path_and_query == path_and_query {
            return None;
        }

        let scheme = if session.req_header().uri.scheme_str() == Some("https") {
            "https"
        } else {
            "http"
        };

        let port_suffix = host
            .rfind(':')
            .map(|i| &host[i..])
            .filter(|s| *s != ":80" && *s != ":443")
            .unwrap_or("");

        Some(format!(
            "{}://{}{}{}",
            scheme, new_host, port_suffix, new_path_and_query
        ))
    }

    fn is_https_downstream(session: &Session, ctx: &ProxyCTX) -> bool {
        ctx.is_tls_downstream
            || ctx.is_http3_downstream
            || ctx.is_http3_bridge
            || session
                .downstream_session
                .digest()
                .and_then(|digest| digest.ssl_digest.as_ref())
                .is_some()
            || session.req_header().uri.scheme_str() == Some("https")
    }

    fn domain_list_matches(domains: &[String], host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        domains.iter().any(|domain| {
            let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
            !domain.is_empty() && (host == domain || host.ends_with(&format!(".{}", domain)))
        })
    }

    fn forwarded_proto(session: &Session, ctx: &ProxyCTX) -> &'static str {
        if Self::is_https_downstream(session, ctx) {
            "https"
        } else {
            "http"
        }
    }

    fn header_contains_ascii_case_insensitive(value: &str, needle: &[u8]) -> bool {
        let bytes = value.as_bytes();
        needle.is_empty()
            || (bytes.len() >= needle.len()
                && bytes
                    .windows(needle.len())
                    .any(|part| part.eq_ignore_ascii_case(needle)))
    }

    fn add_ctx_tag(ctx: &mut ProxyCTX, tag: &str) {
        let tags = ctx.tags.get_or_insert_with(Vec::new);
        if !tags.iter().any(|existing| existing == tag) {
            tags.push(tag.to_string());
        }
    }

    fn resolve_waf_block_runtime(
        matched: &crate::firewall::MatchedAction,
        global_block_options: Option<&crate::config_models::WAFBlockOptions>,
    ) -> (i64, String, i64, String, bool) {
        let mut final_timeout = matched.timeout_secs.unwrap_or(300);
        let mut scope = matched
            .scope
            .clone()
            .unwrap_or_else(|| "server".to_string());
        let mut ip_list_id = matched.ip_list_id;
        let mut event_level = matched.event_level.clone();
        let mut max_timeout = matched.max_timeout_secs.unwrap_or(0) as i32;
        let mut fail_global = matched.fail_global.unwrap_or(false);

        if let Some(opts) = &matched.block_options {
            if opts.timeout > 0 && matched.timeout_secs.is_none() {
                final_timeout = opts.timeout as i64;
            }
            if ip_list_id <= 0 && opts.ip_list_id > 0 {
                ip_list_id = opts.ip_list_id;
            }
            if matched.scope.is_none() && !opts.scope.is_empty() {
                scope = opts.scope.clone();
            }
            if event_level.is_empty() && !opts.event_level.is_empty() {
                event_level = opts.event_level.clone();
            }
            max_timeout = opts.max_timeout;
            fail_global = fail_global || opts.fail_global;
        } else if let Some(opts) = global_block_options {
            if opts.timeout > 0 && matched.timeout_secs.is_none() {
                final_timeout = opts.timeout as i64;
            }
            if ip_list_id <= 0 && opts.ip_list_id > 0 {
                ip_list_id = opts.ip_list_id;
            }
            if matched.scope.is_none() && !opts.scope.is_empty() {
                scope = opts.scope.clone();
            }
            if event_level.is_empty() && !opts.event_level.is_empty() {
                event_level = opts.event_level.clone();
            }
            max_timeout = opts.max_timeout;
            fail_global = fail_global || opts.fail_global;
        }

        if max_timeout > final_timeout as i32 {
            final_timeout = rand::thread_rng().gen_range(final_timeout..=max_timeout as i64);
        }
        if fail_global {
            scope = "global".to_string();
        }
        (
            final_timeout.max(1),
            scope,
            ip_list_id,
            event_level,
            fail_global,
        )
    }

    fn apply_waf_runtime_action(
        &self,
        session: &Session,
        ctx: &mut ProxyCTX,
        matched: &crate::firewall::MatchedAction,
    ) {
        if matches!(matched.action, crate::firewall::ActionResponse::Allow)
            && !matches!(
                matched.action_code.as_str(),
                "tag" | "record_ip_white" | "record_ip_gray"
            )
        {
            return;
        }
        match matched.action_code.as_str() {
            "tag" => {
                for tag in &matched.tags {
                    Self::add_ctx_tag(ctx, tag);
                }
            }
            "block" => {
                let (timeout, scope, _, _, _) = Self::resolve_waf_block_runtime(
                    matched,
                    ctx.global_waf_block_options.as_deref(),
                );
                self.waf_state.block_ip(
                    ctx.client_ip,
                    ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                    timeout,
                    Some(scope.as_str()),
                    matched.block_c_class,
                    matched.use_local_firewall,
                );
            }
            "record_ip" => {
                let (timeout, scope, ip_list_id, event_level, _) = Self::resolve_waf_block_runtime(
                    matched,
                    ctx.global_waf_block_options.as_deref(),
                );
                let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);
                self.waf_state.block_ip(
                    ctx.client_ip,
                    server_id,
                    timeout,
                    Some(scope.as_str()),
                    matched.block_c_class,
                    matched.use_local_firewall,
                );
                let target = if matched.block_c_class {
                    self.waf_state
                        .get_c_class_net(ctx.client_ip)
                        .map(|net| net.to_string())
                        .unwrap_or_else(|_| ctx.client_ip_str.clone())
                } else {
                    ctx.client_ip_str.clone()
                };
                let target_server_id = if scope == "global" { 0 } else { server_id };
                self.report_ip_list_item(
                    Some(session),
                    Some(ctx),
                    IpReportKind::Black,
                    ip_list_id,
                    target,
                    target_server_id,
                    server_id,
                    timeout,
                    format!("WAF Action: {}", matched.action_code),
                    event_level,
                    "waf",
                    matched.policy_id,
                    matched.group_id,
                    matched.set_id,
                );
            }
            "record_ip_white" | "record_ip_gray" => {
                let timeout = matched.timeout_secs.unwrap_or(3600).max(1);
                let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);
                let target_server_id = if matches!(matched.scope.as_deref(), Some("global")) {
                    0
                } else {
                    server_id
                };
                let expiry = crate::utils::time::now_timestamp() + timeout;
                let kind = if matched.action_code == "record_ip_white" {
                    self.waf_state
                        .apply_white_ip_until(target_server_id, ctx.client_ip, expiry);
                    IpReportKind::White
                } else {
                    self.waf_state
                        .apply_gray_ip_until(target_server_id, ctx.client_ip, expiry);
                    Self::add_ctx_tag(ctx, "graylist");
                    IpReportKind::Gray
                };
                self.report_ip_list_item(
                    Some(session),
                    Some(ctx),
                    kind,
                    matched.ip_list_id,
                    ctx.client_ip.to_string(),
                    target_server_id,
                    server_id,
                    timeout,
                    format!("WAF Action: {}", matched.action_code),
                    matched.event_level.clone(),
                    "waf",
                    matched.policy_id,
                    matched.group_id,
                    matched.set_id,
                );
            }
            _ => {}
        }
    }

    fn report_ip_list_item(
        &self,
        session: Option<&Session>,
        ctx: Option<&ProxyCTX>,
        kind: IpReportKind,
        ip_list_id: i64,
        value: String,
        server_id: i64,
        source_server_id: i64,
        timeout_secs: i64,
        reason: String,
        event_level: String,
        source_category: &str,
        policy_id: i64,
        group_id: i64,
        set_id: i64,
    ) {
        let node_id = self.api_config.node_id.parse::<i64>().unwrap_or(0);
        let (source_url, source_user_agent) = match session {
            Some(session) => {
                let source_url = ctx
                    .map(|ctx| Self::request_full_url(session, ctx))
                    .unwrap_or_else(|| session.req_header().uri.to_string());
                let source_user_agent = session
                    .get_header("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                (source_url, source_user_agent)
            }
            None => (String::new(), String::new()),
        };

        crate::rpc::ip_report::report_item(IpReportMessage {
            ip_list_id,
            value,
            ip_from: String::new(),
            ip_to: String::new(),
            expired_at: crate::utils::time::now_timestamp() + timeout_secs.max(1),
            reason,
            r#type: String::new(),
            list_kind: kind,
            event_level,
            node_id,
            server_id,
            source_node_id: node_id,
            source_server_id,
            source_http_firewall_policy_id: policy_id,
            source_http_firewall_rule_group_id: group_id,
            source_http_firewall_rule_set_id: set_id,
            source_url,
            source_user_agent,
            source_category: source_category.to_string(),
        });
    }

    fn request_full_url(session: &Session, ctx: &ProxyCTX) -> String {
        let scheme = Self::forwarded_proto(session, ctx);
        let authority = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .filter(|value| !value.is_empty())
            .or_else(|| {
                session
                    .req_header()
                    .uri
                    .authority()
                    .map(|value| value.as_str())
            })
            .unwrap_or(&ctx.host);
        let path_and_query = session
            .req_header()
            .uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        format!("{scheme}://{authority}{path_and_query}")
    }

    fn append_forwarded_for(existing: Option<&str>, ip: &str, max_addresses: i32) -> String {
        let mut parts: Vec<String> = existing
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect();
        parts.push(ip.to_string());

        if max_addresses > 0 && parts.len() > max_addresses as usize {
            let start = parts.len() - max_addresses as usize;
            parts = parts[start..].to_vec();
        }

        parts.join(", ")
    }

    async fn respond_compiled_shutdown(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        shutdown: &crate::compiled::CompiledShutdownPlan,
    ) -> Result<bool> {
        if let Some((target, redirect_status)) = shutdown.redirect_target() {
            let mut resp = pingora_http::ResponseHeader::build(redirect_status, None).unwrap();
            Self::insert_location_header(&mut resp, target);
            session.write_response_header(Box::new(resp), true).await?;
            ctx.response_status = redirect_status;
            return Ok(true);
        }

        let body = if shutdown.body_type == "html" {
            self.render_page_template(session, ctx, &shutdown.body, shutdown.status)
        } else if shutdown.url.is_empty() {
            "The site have been shutdown.".to_string()
        } else {
            let path = std::path::Path::new(&shutdown.url);
            if !path.starts_with("pages") && !path.starts_with("/pages") {
                format!("404 page not found: '{}'", shutdown.url)
            } else {
                match tokio::fs::read_to_string(path).await {
                    Ok(content) => {
                        self.render_page_template(session, ctx, &content, shutdown.status)
                    }
                    Err(_) => format!("404 page not found: '{}'", shutdown.url),
                }
            }
        };

        let mut resp = pingora_http::ResponseHeader::build(shutdown.status, None).unwrap();
        resp.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        ctx.response_status = shutdown.status;
        Ok(true)
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

        let status = Self::response_status_from_i64(i64::from(shutdown.status), 200);
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
            Self::insert_location_header(&mut resp, &target);
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
                match tokio::fs::read_to_string(path).await {
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

    fn site_uam_config(ctx: &ProxyCTX) -> Option<&UAMConfig> {
        let server = ctx.server.as_ref()?;
        let server_uam = server.uam.as_ref().filter(|uam| uam.is_on);
        let web_uam = server
            .web
            .as_ref()
            .and_then(|web| web.uam.as_ref())
            .filter(|uam| uam.is_on);
        if server_uam.is_some_and(|uam| uam.is_prior) {
            return server_uam;
        }
        web_uam.or(server_uam)
    }

    fn active_uam_config<'a>(
        site_uam: Option<&'a UAMConfig>,
        global_uam: Option<&'a UAMConfig>,
    ) -> Option<&'a UAMConfig> {
        site_uam.or_else(|| global_uam.filter(|uam| uam.is_on))
    }

    fn uam_scope_id(ctx: &ProxyCTX, site_uam_enabled: bool) -> i64 {
        if site_uam_enabled {
            ctx.server
                .as_ref()
                .map(|server| server.numeric_id())
                .unwrap_or(0)
        } else {
            0
        }
    }

    fn uam_life_seconds(uam_cfg: Option<&UAMConfig>) -> i64 {
        uam_cfg
            .map(|cfg| cfg.key_life as i64)
            .filter(|life| *life > 0)
            .unwrap_or(UAM_DEFAULT_LIFE_SECONDS)
    }

    fn uam_pow_difficulty(uam_cfg: Option<&UAMConfig>) -> u8 {
        uam_cfg
            .and_then(|cfg| cfg.pow_difficulty)
            .unwrap_or(5)
            .clamp(5, 8)
    }

    fn uam_mode(uam_cfg: Option<&UAMConfig>) -> crate::firewall::uam::UamMode {
        uam_cfg
            .and_then(|cfg| cfg.mode.as_deref())
            .map(crate::firewall::uam::UamMode::from_str)
            .unwrap_or(crate::firewall::uam::UamMode::Pow)
    }

    fn uam_mode_requires_slider_trace(mode: crate::firewall::uam::UamMode) -> bool {
        matches!(
            mode,
            crate::firewall::uam::UamMode::Captcha | crate::firewall::uam::UamMode::Slider
        )
    }

    fn uam_mode_requires_pow(mode: crate::firewall::uam::UamMode) -> bool {
        !matches!(mode, crate::firewall::uam::UamMode::JsCookie)
    }

    fn uam_mode_code(mode: crate::firewall::uam::UamMode) -> &'static str {
        match mode {
            crate::firewall::uam::UamMode::JsCookie => "jscookie",
            crate::firewall::uam::UamMode::Pow => "pow",
            crate::firewall::uam::UamMode::Captcha => "captcha",
            crate::firewall::uam::UamMode::Slider => "slider",
        }
    }

    fn parse_waf_challenge_method(method: &str) -> Result<Option<&'static str>, ()> {
        if crate::firewall::captcha_method_is_default(method) {
            return Ok(None);
        }
        match method.trim().to_ascii_lowercase().as_str() {
            "click" => Ok(Some("click")),
            "captcha" => Ok(Some("captcha")),
            "jscookie" => Ok(Some("jscookie")),
            "pow" => Ok(Some("pow")),
            "geetest" => Ok(Some("geetest")),
            "oneclick" => Ok(Some("click")),
            "slide" => Ok(Some("slider")),
            "slider" => Ok(Some("slider")),
            _ => Err(()),
        }
    }

    #[cfg(test)]
    fn normalize_waf_challenge_method(method: &str, action_code: &str) -> String {
        if action_code == "js_cookie" && method.trim().is_empty() {
            return "jscookie".to_string();
        }
        match Self::parse_waf_challenge_method(method) {
            Ok(Some(method)) => method.to_string(),
            Ok(None) => "default".to_string(),
            Err(()) => String::new(),
        }
    }

    fn waf_expected_challenge_method(&self, matched: &crate::firewall::MatchedAction) -> String {
        let global_captcha_opts = self
            .config
            .get_waf_actions_sync()
            .iter()
            .find(|global| global.code == matched.action_code)
            .and_then(|global| {
                let mut parsed: WAFCaptchaOptions =
                    serde_json::from_value(global.options.clone()).ok()?;
                crate::firewall::normalize_captcha_options(&mut parsed);
                Some(parsed)
            });
        Self::resolve_waf_challenge_method(
            &matched.action_code,
            matches!(
                matched.action,
                crate::firewall::ActionResponse::JsCookie { .. }
            ),
            matched.captcha_options.as_ref(),
            global_captcha_opts.as_ref(),
        )
    }

    fn resolve_waf_challenge_method(
        action_code: &str,
        is_js_cookie_action: bool,
        action_opts: Option<&WAFCaptchaOptions>,
        global_opts: Option<&WAFCaptchaOptions>,
    ) -> String {
        if is_js_cookie_action || action_code == "js_cookie" {
            return "jscookie".to_string();
        }

        if let Some(options) = action_opts {
            match Self::parse_waf_challenge_method(&options.method) {
                Ok(Some(method)) => return method.to_string(),
                Ok(None) => {}
                Err(()) => return "slider".to_string(),
            }
        }

        let global_use_geetest = global_opts
            .map(crate::firewall::captcha_options_use_geetest)
            .unwrap_or(false);
        let method = match global_opts {
            Some(options) => match Self::parse_waf_challenge_method(&options.method) {
                Ok(Some(method)) => method,
                Ok(None) => "slider",
                Err(()) => "slider",
            },
            None => "slider",
        };
        if method == "slider" && action_code == "captcha" && global_use_geetest {
            "geetest".to_string()
        } else {
            method.to_string()
        }
    }

    fn apply_site_default_captcha_type(
        matched: &mut crate::firewall::MatchedAction,
        firewall_ref: Option<&crate::config_models::HTTPFirewallRef>,
        inherited_options: Option<&crate::config_models::WAFCaptchaOptions>,
    ) {
        if matched.action_code == "captcha" {
            let site_default_type = firewall_ref
                .map(|fw_ref| fw_ref.default_captcha_type.trim())
                .filter(|value| !crate::firewall::captcha_method_is_default(value));

            if let Some(default_type) = site_default_type {
                let options = matched.captcha_options.get_or_insert_with(Default::default);
                if crate::firewall::captcha_method_is_default(&options.method) {
                    options.method = default_type.to_string();
                }
            } else {
                let options = matched.captcha_options.get_or_insert_with(Default::default);
                if crate::firewall::captcha_method_is_default(&options.method) {
                    options.method = "captcha".to_string();
                }
            }
            if let Some(inherited_options) = inherited_options {
                let options = matched.captcha_options.get_or_insert_with(Default::default);
                crate::firewall::merge_captcha_options(options, inherited_options);
            }
        }
        for chained in &mut matched.chained_actions {
            Self::apply_site_default_captcha_type(chained, firewall_ref, inherited_options);
        }
    }

    fn inherited_global_captcha_options(
        global_policies: &[crate::config_models::HTTPFirewallPolicy],
    ) -> Option<&crate::config_models::WAFCaptchaOptions> {
        global_policies
            .iter()
            .filter(|policy| policy.is_on && policy.mode != "bypass")
            .find_map(|policy| policy.captcha_options.as_ref())
    }

    fn uam_config_hash(site_uam: Option<&UAMConfig>, global_uam: Option<&UAMConfig>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"uam-config|");
        if let Some(cfg) = site_uam {
            match serde_json::to_vec(cfg) {
                Ok(bytes) => hasher.update(bytes),
                Err(_) => hasher.update(b"site-uam"),
            }
        } else if let Some(cfg) = global_uam.filter(|cfg| cfg.is_on) {
            match serde_json::to_vec(cfg) {
                Ok(bytes) => hasher.update(bytes),
                Err(_) => hasher.update(b"global-uam"),
            }
        } else {
            hasher.update(b"off");
        }
        hex::encode(hasher.finalize())
    }

    fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
        let prefix = format!("{name}=");
        cookies
            .split(';')
            .map(str::trim)
            .find_map(|part| part.strip_prefix(&prefix))
    }

    fn constant_time_eq(a: &str, b: &str) -> bool {
        let a = a.as_bytes();
        let b = b.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        a.iter()
            .zip(b.iter())
            .fold(0_u8, |acc, (lhs, rhs)| acc | (lhs ^ rhs))
            == 0
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn uam_host_scope(ctx: &ProxyCTX) -> String {
        let server_id = ctx
            .server
            .as_ref()
            .map(|server| server.numeric_id())
            .unwrap_or(0);
        format!("{}|{}", Self::normalize_request_host(&ctx.host), server_id)
    }

    fn uam_pass_signature(&self, payload: &str, ip: &str, ua: &str, host_scope: &str) -> String {
        let mut ua_hasher = Sha256::new();
        ua_hasher.update(ua.as_bytes());
        let ua_hash = hex::encode(ua_hasher.finalize());
        let data = format!("uam-pass|{payload}|{ip}|{ua_hash}|{host_scope}");
        Self::hmac_sha256_hex(self.api_config.secret.as_bytes(), data.as_bytes())
    }

    fn issue_uam_pass_cookie(
        &self,
        ip: &str,
        ua: &str,
        scope_id: i64,
        host_scope: &str,
        config_hash: &str,
        life_seconds: i64,
    ) -> String {
        let issued_at = crate::utils::time::now_timestamp();
        let exp = issued_at + life_seconds.max(1);
        let nonce = general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 12]>());
        let host_hash = Self::sha256_hex(host_scope.as_bytes());
        let payload =
            format!("{UAM_COOKIE_VERSION}|{exp}|{scope_id}|{host_hash}|{config_hash}|{nonce}");
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = self.uam_pass_signature(&payload, ip, ua, host_scope);
        format!("{encoded}.{signature}")
    }

    fn validate_uam_pass_cookie(
        &self,
        value: &str,
        ip: &str,
        ua: &str,
        scope_id: i64,
        host_scope: &str,
        config_hash: &str,
    ) -> Option<i64> {
        let (encoded_payload, signature) = value.split_once('.')?;
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_payload.as_bytes())
            .ok()?;
        let payload = String::from_utf8(decoded).ok()?;
        let expected = self.uam_pass_signature(&payload, ip, ua, host_scope);
        if !Self::constant_time_eq(signature, &expected) {
            return None;
        }

        let mut parts = payload.split('|');
        let version = parts.next()?;
        let exp = parts.next()?.parse::<i64>().ok()?;
        let cookie_scope = parts.next()?.parse::<i64>().ok()?;
        let cookie_host_hash = parts.next()?;
        let cookie_hash = parts.next()?;
        let nonce = parts.next()?;
        let host_hash = Self::sha256_hex(host_scope.as_bytes());
        if parts.next().is_some()
            || version != UAM_COOKIE_VERSION
            || cookie_scope != scope_id
            || cookie_host_hash != host_hash
            || cookie_hash != config_hash
            || nonce.is_empty()
        {
            return None;
        }

        let now = crate::utils::time::now_timestamp();
        (now <= exp).then_some(exp.saturating_sub(now).max(1))
    }

    fn uam_challenge_signature(
        &self,
        payload: &str,
        ip: &str,
        ua: &str,
        host_scope: &str,
    ) -> String {
        let mut ua_hasher = Sha256::new();
        ua_hasher.update(ua.as_bytes());
        let ua_hash = hex::encode(ua_hasher.finalize());
        let data = format!("uam-challenge|{payload}|{ip}|{ua_hash}|{host_scope}");
        let key = crate::firewall::uam::uam_hmac_key(self.api_config.secret.as_bytes());
        Self::hmac_sha256_hex(&key, data.as_bytes())
    }

    fn issue_uam_challenge_token(
        &self,
        ip: &str,
        ua: &str,
        scope_id: i64,
        host_scope: &str,
        config_hash: &str,
        life_seconds: i64,
        mode: crate::firewall::uam::UamMode,
        pow_difficulty: u8,
    ) -> String {
        let issued_at = crate::utils::time::now_timestamp();
        let exp = issued_at + life_seconds.max(1);
        let nonce = general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 12]>());
        let host_hash = Self::sha256_hex(host_scope.as_bytes());
        let mode_code = Self::uam_mode_code(mode);
        let payload = format!(
            "{UAM_COOKIE_VERSION}|{exp}|{scope_id}|{host_hash}|{config_hash}|{nonce}|{mode_code}|{pow_difficulty}|{issued_at}"
        );
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = self.uam_challenge_signature(&payload, ip, ua, host_scope);
        format!("{encoded}.{signature}")
    }

    fn validate_uam_challenge_token(
        &self,
        value: &str,
        ip: &str,
        ua: &str,
        scope_id: i64,
        host_scope: &str,
        _config_hash: &str,
    ) -> Option<(i64, crate::firewall::uam::UamMode, u8)> {
        let (encoded_payload, signature) = value.split_once('.')?;
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_payload.as_bytes())
            .ok()?;
        let payload = String::from_utf8(decoded).ok()?;
        let expected = self.uam_challenge_signature(&payload, ip, ua, host_scope);
        if !Self::constant_time_eq(signature, &expected) {
            return None;
        }

        let mut parts = payload.split('|');
        let version = parts.next()?;
        let exp = parts.next()?.parse::<i64>().ok()?;
        let cookie_scope = parts.next()?.parse::<i64>().ok()?;
        let cookie_host_hash = parts.next()?;
        let cookie_hash = parts.next()?;
        let nonce = parts.next()?;
        let mode = parts
            .next()
            .map(crate::firewall::uam::UamMode::from_str)
            .unwrap_or(crate::firewall::uam::UamMode::Pow);
        let pow_difficulty = parts
            .next()
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or_else(|| Self::uam_pow_difficulty(None));
        let issued_at = parts
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let host_hash = Self::sha256_hex(host_scope.as_bytes());
        if parts.next().is_some()
            || version != UAM_COOKIE_VERSION
            || cookie_scope != scope_id
            || cookie_host_hash != host_hash
            || cookie_hash != _config_hash
            || nonce.is_empty()
        {
            return None;
        }

        let now = crate::utils::time::now_timestamp();
        if issued_at > 0 && now.saturating_sub(issued_at) < UAM_MIN_VERIFY_SECONDS {
            return None;
        }
        (now <= exp).then_some((
            exp.saturating_sub(now).max(1),
            mode,
            pow_difficulty.clamp(5, 8),
        ))
    }

    fn global_cc_policy_for_main_cluster(&self) -> Option<(i64, crate::config_models::CCPolicy)> {
        let cluster_id = self.config.get_node_cluster_id_sync();
        if cluster_id <= 0 {
            return None;
        }
        let policy = self
            .config
            .get_http_cc_policy_for_cluster_sync(cluster_id)
            .filter(|policy| policy.is_on)
            .as_ref()
            .map(crate::config_models::CCPolicy::from)
            .or_else(|| {
                self.config
                    .get_firewall_policies_for_cluster_sync(cluster_id)
                    .iter()
                    .find_map(|policy| policy.cc_config.as_ref().filter(|cc| cc.is_on))
                    .map(crate::config_models::CCPolicy::from)
            })?;
        Some((cluster_id, policy))
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

    fn request_path_has_webp_image_extension(session: &Session) -> bool {
        let path = session.req_header().uri.path();
        let Some((_, ext)) = path.rsplit_once('.') else {
            return false;
        };
        ext.eq_ignore_ascii_case("jpg")
            || ext.eq_ignore_ascii_case("jpeg")
            || ext.eq_ignore_ascii_case("png")
            || ext.eq_ignore_ascii_case("gif")
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

    fn compiled_site_webp_matches_request(ctx: &ProxyCTX, session: &Session) -> Option<bool> {
        let server_id = ctx.server.as_ref()?.id?;
        let feature_plan = ctx.compiled_plans.server_features.get(&server_id)?;
        let accept = session
            .get_header("accept")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        Some(feature_plan.webp_matches_request(session.req_header().uri.path(), accept))
    }

    fn maybe_enable_webp_conversion(
        &self,
        session: &Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut ProxyCTX,
    ) {
        ctx.webp_convert_enabled = false;
        ctx.webp_source_content_type = None;
        ctx.webp_source_content_length = None;
        ctx.webp_cpu_permit = None;
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
        if !Self::compiled_site_webp_matches_request(ctx, session)
            .unwrap_or_else(|| Self::site_webp_matches_request(site_webp, session))
        {
            return;
        }
        // WebP conversion is treated as a transformed-cache feature. Without
        // a matched cache rule, converting here would spend CPU on every request.
        let Some(cache_ref) = ctx.cache_ref.as_ref() else {
            return;
        };
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

        let compiled_feature_plan = server
            .id
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id));
        let mime_matches = compiled_feature_plan
            .as_ref()
            .map(|plan| plan.webp_mime_matches(&content_type))
            .unwrap_or_else(|| {
                site_webp.mime_types.is_empty()
                    || site_webp.mime_types.iter().any(|mime| {
                        content_type
                            .to_ascii_lowercase()
                            .starts_with(&mime.to_ascii_lowercase())
                    })
            });
        if !mime_matches {
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
        let site_min = compiled_feature_plan
            .as_ref()
            .and_then(|plan| plan.webp_min_bytes())
            .unwrap_or_else(|| Self::size_capacity_bytes(&site_webp.min_length));
        let site_max = compiled_feature_plan
            .as_ref()
            .and_then(|plan| plan.webp_max_bytes())
            .unwrap_or_else(|| Self::size_capacity_bytes(&site_webp.max_length));
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
        let force_partial = cache_ref.force_partial_content
            || ctx
                .cache_policy
                .as_ref()
                .map(|p| p.force_partial_content)
                .unwrap_or(false);
        let host = session.req_header().uri.host().unwrap_or("");
        if !should_cache_response(
            upstream_response.status.as_u16(),
            cache_ref,
            session.req_header().method.as_str(),
            &upstream_response.headers,
            host,
            content_length_usize,
            force_partial,
            false,
            &session.req_header().headers,
        ) {
            return;
        }

        let Some(reservation) = crate::adaptive_cpu::CPU_TRANSFORM_GATE.try_reserve_optional()
        else {
            return;
        };
        let Some(transform_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::ResponseTransform)
        else {
            return;
        };

        ctx.webp_convert_enabled = true;
        ctx.response_transform_permit = Some(transform_permit);
        ctx.webp_cpu_permit = Some(reservation);
        ctx.webp_source_content_type = Some(content_type);
        ctx.webp_source_content_length = Some(content_length_usize);
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

    fn release_response_transform(ctx: &mut ProxyCTX) {
        ctx.response_transform_permit = None;
    }

    #[doc(hidden)]
    pub fn bench_convert_to_webp(
        content_type: &str,
        body: &[u8],
        quality: i32,
    ) -> anyhow::Result<Vec<u8>> {
        Self::convert_to_webp(content_type, body, quality)
    }

    pub(crate) fn is_mobile_user_agent(ua: &str) -> bool {
        let ua = ua.to_ascii_lowercase();
        ua.contains("mobile")
            || ua.contains("android")
            || ua.contains("iphone")
            || ua.contains("ipad")
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
        let server = server?;
        if !server.http3_enabled() {
            return None;
        }
        if policy.port > 0 {
            let port = u16::try_from(policy.port).ok()?;
            let ua = session
                .get_header("user-agent")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            if Self::is_mobile_user_agent(ua) && !policy.support_mobile_browsers {
                return None;
            }
            return Some(port);
        }

        let ua = session
            .get_header("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if Self::is_mobile_user_agent(ua) && !policy.support_mobile_browsers {
            return None;
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
        ctx: &ProxyCTX,
        status: u16,
    ) -> Option<crate::config_models::HTTPPageConfig> {
        if let Some(server) = ctx.server.as_deref() {
            let compiled_plan = server
                .id
                .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id));
            if let Some(plan) = compiled_plan {
                if let Some(page) = plan.custom_page_for_status(status) {
                    return Some(page);
                }
            } else if let Some(page) = server.web.as_ref().and_then(|web| {
                web.pages
                    .iter()
                    .find(|page| page.is_on && page.matches_status(status))
                    .cloned()
            }) {
                return Some(page);
            }

            if server
                .web
                .as_ref()
                .is_some_and(|web| !web.enable_global_pages)
            {
                return None;
            }
        }

        self.collect_candidate_pages(None)
            .into_iter()
            .find(|page| page.is_on && page.matches_status(status))
    }

    fn set_cors_headers(
        resp: &mut pingora_http::ResponseHeader,
        session: &Session,
        cors: &crate::config_models::CORSConfig,
    ) {
        // Track whether the effective Allow-Origin is the wildcard "*" — the
        // Fetch spec forbids combining `Allow-Origin: *` with
        // `Allow-Credentials: true`, and browsers actively reject such
        // responses. We must skip credentials in that case.
        let mut origin_is_wildcard = false;
        // Allow-Origin: use configured value, or echo the request Origin
        if cors.allow_origin.is_empty() {
            if let Some(origin) = session.get_header("origin") {
                if let Ok(origin_str) = origin.to_str() {
                    let _ = resp.insert_header("access-control-allow-origin", origin_str);
                }
            }
            // Also set Vary: Origin when echoing, so caches distinguish per-origin
            let _ = resp.insert_header("vary", "Origin");
        } else if cors.allow_origin.trim() == "*" {
            let _ = resp.insert_header("access-control-allow-origin", "*");
            origin_is_wildcard = true;
        } else {
            let _ = resp.insert_header("access-control-allow-origin", &cors.allow_origin);
        }

        // Allow-Methods
        if cors.allow_methods.is_empty() {
            let _ = resp.insert_header(
                "access-control-allow-methods",
                "PUT, GET, POST, DELETE, HEAD, OPTIONS, PATCH",
            );
        } else {
            let _ = resp.insert_header("access-control-allow-methods", cors.allow_methods_header());
        }

        // Allow-Headers: use configured value, or echo Access-Control-Request-Headers
        // from the preflight request so browsers allow non-simple headers
        // (Content-Type: application/json, Authorization, etc.)
        if !cors.allow_headers.is_empty() {
            let _ = resp.insert_header("access-control-allow-headers", cors.allow_headers_header());
        } else if let Some(req_headers) = session.get_header("access-control-request-headers") {
            if let Ok(req_headers_str) = req_headers.to_str() {
                let _ = resp.insert_header("access-control-allow-headers", req_headers_str);
            }
        }

        // Max-Age
        if cors.max_age > 0 {
            let _ = resp.insert_header("access-control-max-age", cors.max_age_header());
        }

        // Expose-Headers
        if !cors.expose_headers.is_empty() {
            let _ = resp.insert_header(
                "access-control-expose-headers",
                cors.expose_headers_header(),
            );
        }

        // Allow-Credentials — omitted when Allow-Origin is "*", since the
        // Fetch spec forbids that combination and browsers reject it.
        if !origin_is_wildcard {
            let _ = resp.insert_header("access-control-allow-credentials", "true");
        }
    }

    async fn respond_status_with_pages(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        status: u16,
    ) -> Result<bool> {
        if let Some(page) = self.find_custom_page(ctx, status) {
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
                Self::insert_location_header(&mut resp, url.as_str());
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
                    .filter(|code| (100..=599).contains(code))
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

        if status == 451 {
            return self
                .respond_default_deleted_content_page(session, ctx)
                .await;
        }

        ctx.response_status = status;
        ctx.response_body_len = 0;
        ctx.response_headers.clear();
        ctx.response_headers_size = 0;
        session.respond_error(status).await?;
        Ok(true)
    }

    async fn respond_default_deleted_content_page(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        let url = Self::request_full_url(session, ctx);
        let escaped_url = Self::html_escape(&url);
        let template = format!(
            r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>451 Unavailable For Legal Reasons</title>
<style>
:root {{ color-scheme: light dark; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 32px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at top left, #dbeafe, transparent 34%), linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%); color: #0f172a; }}
main {{ width: min(720px, 100%); border: 1px solid rgba(148, 163, 184, .28); border-radius: 28px; padding: 42px; background: rgba(255, 255, 255, .84); box-shadow: 0 24px 80px rgba(15, 23, 42, .14); backdrop-filter: blur(20px); }}
.badge {{ display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 999px; background: #fff7ed; color: #9a3412; font-weight: 700; font-size: 13px; letter-spacing: .04em; text-transform: uppercase; }}
h1 {{ margin: 24px 0 12px; font-size: clamp(32px, 6vw, 56px); line-height: .95; letter-spacing: -.05em; }}
p {{ margin: 0; color: #475569; font-size: 17px; line-height: 1.7; }}
.url {{ margin-top: 28px; padding: 16px 18px; border-radius: 16px; background: #f8fafc; border: 1px solid #e2e8f0; color: #334155; overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 14px; }}
.meta {{ margin-top: 26px; display: flex; flex-wrap: wrap; gap: 10px; color: #64748b; font-size: 13px; }}
.meta span {{ padding: 8px 10px; border-radius: 999px; background: rgba(15, 23, 42, .05); }}
@media (prefers-color-scheme: dark) {{ body {{ background: radial-gradient(circle at top left, #1e3a8a, transparent 34%), linear-gradient(135deg, #020617 0%, #111827 100%); color: #e5e7eb; }} main {{ background: rgba(15, 23, 42, .84); border-color: rgba(148, 163, 184, .22); }} p {{ color: #cbd5e1; }} .url {{ background: rgba(15, 23, 42, .7); border-color: rgba(148, 163, 184, .24); color: #e2e8f0; }} .meta {{ color: #94a3b8; }} .meta span {{ background: rgba(255, 255, 255, .08); }} }}
</style>
</head>
<body>
<main>
<div class="badge">HTTP ${{status}} · ${{statusMessage}}</div>
<h1>Content unavailable</h1>
<p>This resource is not available on this node for legal or compliance reasons.</p>
<div class="url">{escaped_url}</div>
<div class="meta"><span>Request ID: ${{requestId}}</span><span>Time: ${{timeISO8601}}</span></div>
</main>
</body>
</html>"#
        );
        let body = self.render_page_template(session, ctx, &template, 451);
        ctx.response_status = 451;
        ctx.response_body_len = body.len();
        ctx.response_headers.clear();
        ctx.response_headers.insert(
            "content-type".to_string(),
            "text/html; charset=utf-8".to_string(),
        );
        ctx.response_headers
            .insert("cache-control".to_string(), "no-store".to_string());
        let mut resp = pingora_http::ResponseHeader::build(451, None).unwrap();
        resp.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        resp.insert_header("cache-control", "no-store").unwrap();
        ctx.response_headers_size = resp
            .headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.len() + 4)
            .sum();
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        Ok(true)
    }

    fn html_escape(value: &str) -> String {
        let mut escaped = String::with_capacity(value.len());
        for ch in value.chars() {
            match ch {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&#39;"),
                _ => escaped.push(ch),
            }
        }
        escaped
    }

    fn product_name(&self, ctx: &ProxyCTX) -> String {
        Self::resolve_product_name(
            ctx.global_http_config.as_deref(),
            &self.config.get_global_http_config_sync(),
        )
    }

    fn non_empty_display_value(value: &str) -> Option<String> {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    }

    fn resolve_product_name(
        ctx_global: Option<&crate::config_models::GlobalHTTPAllConfig>,
        store_global: &crate::config_models::GlobalHTTPAllConfig,
    ) -> String {
        ctx_global
            .and_then(|config| Self::non_empty_display_value(&config.product_name))
            .or_else(|| Self::non_empty_display_value(&store_global.product_name))
            .or_else(|| {
                ctx_global.and_then(|config| Self::non_empty_display_value(&config.server_name))
            })
            .or_else(|| Self::non_empty_display_value(&store_global.server_name))
            .unwrap_or_else(|| "Cloud Node".to_string())
    }

    fn maybe_report_firewall_event(
        &self,
        session: &Session,
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
        let source_url = Self::request_full_url(session, ctx);
        let source_ip = ctx.client_ip_str.clone();
        let source_user_agent = session
            .req_header()
            .headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let api_config = self.api_config.clone();
        tokio::spawn(async move {
            crate::rpc::firewall::notify_firewall_event(
                &api_config,
                server_id,
                policy_id,
                group_id,
                set_id,
                source_url,
                source_ip,
                source_user_agent,
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
        let site_uam = Self::site_uam_config(ctx);
        let global_uam = self.config.get_global_uam_policy_sync();
        let uam_cfg = Self::active_uam_config(site_uam, global_uam.as_ref());
        let site_uam_enabled = site_uam.is_some();
        if uam_cfg.is_none() {
            return Ok(false);
        }

        if session.req_header().uri.path() == WAF_VERIFY_ROUTE {
            return Ok(false);
        }

        let ua = session
            .req_header()
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if let Some(cfg) = uam_cfg {
            if !Self::uam_matches_request_url(cfg, session, ctx) {
                return Ok(false);
            }
            if let Some(conds) = &cfg.conds {
                let scheme = Self::forwarded_proto(session, ctx);
                let cache_ctx = Self::cache_eval_context(session, ctx, scheme);
                if !conds.match_request_with_context(&cache_ctx) {
                    return Ok(false);
                }
            }
        }

        let scope_id = Self::uam_scope_id(ctx, site_uam_enabled);
        let host_scope = Self::uam_host_scope(ctx);
        let life_seconds = Self::uam_life_seconds(uam_cfg);
        let config_hash = Self::uam_config_hash(site_uam, global_uam.as_ref());
        let cookies = merged_session_cookie_header(session).unwrap_or_default();
        if let Some(pass_value) = Self::cookie_value(&cookies, "UAM-Pass")
            && let pass = pass_value
                .split_once(":type=")
                .map(|(t, _)| t)
                .unwrap_or(pass_value)
            && self
                .validate_uam_pass_cookie(pass, ip, ua, scope_id, &host_scope, &config_hash)
                .is_some()
        {
            return Ok(false);
        }

        if let Some(min_qps) = uam_cfg
            .map(|cfg| cfg.min_qps_per_ip)
            .filter(|value| *value > 0)
        {
            let count = self
                .waf_state
                .increase_counter(format!("UAM_QPS:{scope_id}:{ip}"), 60);
            let threshold = (min_qps as u64).saturating_mul(60).max(1);
            if count < threshold {
                return Ok(false);
            }
        }

        let mode = Self::uam_mode(uam_cfg);
        let pow_difficulty = Self::uam_pow_difficulty(uam_cfg);
        let challenge = crate::firewall::uam::dispatch(mode);
        let return_path = Self::current_request_path_query(session);
        let challenge_life_seconds = life_seconds.min(UAM_CHALLENGE_LIFE_SECONDS);
        let token = self.issue_uam_challenge_token(
            ip,
            ua,
            scope_id,
            &host_scope,
            &config_hash,
            challenge_life_seconds,
            mode,
            pow_difficulty,
        );

        let issue_ctx = crate::firewall::uam::UamIssueCtx {
            token: &token,
            challenge_life_seconds,
            pow_difficulty,
            verify_route: WAF_VERIFY_ROUTE,
            return_path: &return_path,
            slider_target: self.waf_verifier.slider_target(&token),
        };
        let body_html =
            self.render_page_template(session, ctx, &challenge.issue_html(&issue_ctx), 200);

        let action_code = if site_uam_enabled {
            "site_uam"
        } else {
            "global_uam"
        };
        ctx.waf_action = Some(action_code.to_string());
        ctx.firewall_blocked = true;

        let suffix = Self::waf_cookie_suffix(session, ctx, challenge_life_seconds);
        let mut resp = pingora_http::ResponseHeader::build(200u16, None).unwrap();
        resp.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        resp.insert_header("cache-control", "no-store").unwrap();
        resp.insert_header("x-uam-challenge", "1").unwrap();
        resp.insert_header("x-content-type-options", "nosniff")
            .unwrap();
        resp.insert_header("referrer-policy", "same-origin")
            .unwrap();
        resp.append_header(
            "set-cookie",
            format!("UAM-Token={token}; HttpOnly; {suffix}"),
        )
        .unwrap();
        ctx.response_status = 200;
        ctx.response_body_len = body_html.len();
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(bytes::Bytes::from(body_html)), true)
            .await?;
        Ok(true)
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
        let total_qps_exceeded = policy.max_qps > 0
            && !self
                .waf_state
                .check_rate_limit(scope_server_id, policy.max_qps as u32);
        let per_ip_qps_exceeded = policy.per_ip_max_qps > 0
            && !self.waf_state.check_ip_rate_limit(
                scope_server_id,
                ctx.client_ip,
                policy.per_ip_max_qps as u32,
            );
        if total_qps_exceeded || per_ip_qps_exceeded {
            if policy.block_ip {
                let ban = if policy.block_ip_duration > 0 {
                    policy.block_ip_duration as i64
                } else {
                    3600
                };
                let cluster_id = (scope_server_id < 0).then_some(-scope_server_id);
                let scope_label = if scope_server_id == 0 {
                    "global"
                } else if scope_server_id < 0 {
                    "cluster"
                } else {
                    "server"
                };
                self.waf_state.block_ip(
                    ctx.client_ip,
                    scope_server_id,
                    ban,
                    Some(scope_label),
                    false,
                    true,
                );
                self.report_ip_list_item(
                    Some(session),
                    Some(ctx),
                    IpReportKind::Black,
                    0,
                    ctx.client_ip.to_string(),
                    if scope_server_id < 0 {
                        0
                    } else {
                        scope_server_id
                    },
                    ctx.server.as_ref().map(|s| s.numeric_id()).unwrap_or(0),
                    ban,
                    cluster_id
                        .map(|cluster_id| format!("CC policy block cluster={cluster_id}"))
                        .unwrap_or_else(|| "CC policy block".to_string()),
                    "error".to_string(),
                    &cluster_id
                        .map(|cluster_id| format!("cc:cluster:{cluster_id}"))
                        .unwrap_or_else(|| "cc".to_string()),
                    0,
                    0,
                    0,
                );
            }
            if policy.show_page {
                ctx.no_log = policy.no_log;
                return self.respond_status_with_pages(session, ctx, 429).await;
            }
        }

        // Bandwidth enforcement: 1-second sliding window per (scope, IP).
        if policy.max_bandwidth > 0.0 {
            let request_bytes =
                (session.body_bytes_sent() as u64).saturating_add(ctx.response_headers_size as u64);
            let bw_limit = policy.max_bandwidth as u64;
            if self.waf_state.check_ip_bandwidth(
                scope_server_id,
                ctx.client_ip,
                request_bytes,
                bw_limit,
            ) {
                if policy.block_ip {
                    let ban = if policy.block_ip_duration > 0 {
                        policy.block_ip_duration as i64
                    } else {
                        3600
                    };
                    let cluster_id = (scope_server_id < 0).then_some(-scope_server_id);
                    let scope_label = if scope_server_id == 0 {
                        "global"
                    } else if scope_server_id < 0 {
                        "cluster"
                    } else {
                        "server"
                    };
                    self.waf_state.block_ip(
                        ctx.client_ip,
                        scope_server_id,
                        ban,
                        Some(scope_label),
                        false,
                        true,
                    );
                    self.report_ip_list_item(
                        Some(session),
                        Some(ctx),
                        IpReportKind::Black,
                        0,
                        ctx.client_ip.to_string(),
                        if scope_server_id < 0 {
                            0
                        } else {
                            scope_server_id
                        },
                        ctx.server.as_ref().map(|s| s.numeric_id()).unwrap_or(0),
                        ban,
                        cluster_id
                            .map(|cluster_id| {
                                format!("CC policy bandwidth block cluster={cluster_id}")
                            })
                            .unwrap_or_else(|| "CC policy bandwidth block".to_string()),
                        "error".to_string(),
                        &cluster_id
                            .map(|cluster_id| format!("cc:cluster:{cluster_id}"))
                            .unwrap_or_else(|| "cc".to_string()),
                        0,
                        0,
                        0,
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
        let Some((cluster_id, policy)) = self.global_cc_policy_for_main_cluster() else {
            return Ok(false);
        };
        let scope_server_id = crate::special_defense::cluster_block_scope_id(cluster_id);
        self.apply_cc_policy(session, ctx, &policy, scope_server_id)
            .await
    }

    fn wildcard_domain_matches(patterns: &[String], domain: &str) -> bool {
        let domain = crate::lb_factory::strip_addr_port(domain)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        patterns
            .iter()
            .any(|pattern| Self::wildcard_domain_pattern_matches(pattern, &domain))
    }

    fn wildcard_domain_pattern_matches(pattern: &str, normalized_domain: &str) -> bool {
        let pattern = crate::lb_factory::strip_addr_port(pattern)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if pattern == normalized_domain {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return normalized_domain == suffix
                || normalized_domain
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'));
        }
        pattern.contains('*')
            && Self::cached_wildcard_domain_regex_matches(&pattern, normalized_domain)
    }

    fn hsts_header_value(hsts: &crate::config_models::HSTSConfig) -> String {
        let max_age = if hsts.max_age > 0 {
            hsts.max_age
        } else {
            31_536_000
        };
        let mut value = format!("max-age={}", max_age);
        if hsts.include_sub_domains {
            value.push_str("; includeSubDomains");
        }
        if hsts.preload {
            value.push_str("; preload");
        }
        value
    }

    fn websocket_origin_allowed(
        ws: &crate::config_models::WebSocketConfig,
        origin_host: &str,
    ) -> bool {
        ws.allow_all_origins || Self::wildcard_domain_matches(&ws.allowed_origins, origin_host)
    }

    fn origin_header_host(origin: &str) -> Option<&str> {
        let (_, rest) = origin.split_once("://")?;
        let authority = rest.split('/').next().unwrap_or(rest);
        let host = authority.rsplit('@').next().unwrap_or(authority);
        (!host.is_empty()).then_some(host)
    }

    fn is_websocket_request(session: &Session) -> bool {
        let upgrade = session
            .get_header("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        Self::has_upgrade_connection(session) && upgrade
    }

    fn has_upgrade_connection(session: &Session) -> bool {
        session
            .get_header("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false)
    }

    fn cached_wildcard_domain_regex_matches(pattern: &str, domain: &str) -> bool {
        if let Some(re) = WILDCARD_DOMAIN_REGEX_CACHE.get(pattern) {
            return re.is_match(domain);
        }

        let escaped = regex::escape(pattern).replace("\\*", ".*");
        let Ok(re) = Regex::new(&format!("(?i)^{}$", escaped)) else {
            return false;
        };
        let re = Arc::new(re);
        let matched = re.is_match(domain);
        WILDCARD_DOMAIN_REGEX_CACHE.insert(pattern.to_string(), re);
        matched
    }

    fn cached_user_agent_wildcard_matches(keyword: &str, user_agent: &str) -> bool {
        if let Some(re) = UA_WILDCARD_REGEX_CACHE.get(keyword) {
            return re.is_match(user_agent);
        }

        let pattern = regex::escape(keyword).replace("\\*", ".*");
        let Ok(re) = Regex::new(&format!("(?i){}", pattern)) else {
            return false;
        };
        let re = Arc::new(re);
        let matched = re.is_match(user_agent);
        UA_WILDCARD_REGEX_CACHE.insert(keyword.to_string(), re);
        matched
    }

    fn url_patterns_match(
        url: &str,
        only: &[crate::config_models::URLPattern],
        except: &[crate::config_models::URLPattern],
    ) -> bool {
        if except.iter().any(|pattern| pattern.matches(url)) {
            return false;
        }
        if only.is_empty() {
            return true;
        }
        only.iter().any(|pattern| pattern.matches(url))
    }

    fn basic_auth_matches(
        session: &Session,
        params: &serde_json::Value,
    ) -> Option<(bool, String, Option<String>)> {
        if let Some(domains) = params.get("domains").and_then(|v| v.as_array()) {
            if !domains.is_empty() {
                let host = session
                    .get_header("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                let host = crate::lb_factory::strip_addr_port(host)
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if !domains
                    .iter()
                    .filter_map(|domain| domain.as_str())
                    .any(|domain| Self::wildcard_domain_pattern_matches(domain, &host))
                {
                    return None;
                }
            }
        }

        if let Some(exts) = params.get("exts").and_then(|v| v.as_array()) {
            if !exts.is_empty() {
                let path = session.req_header().uri.path().to_ascii_lowercase();
                if !exts.iter().filter_map(|ext| ext.as_str()).any(|ext| {
                    let ext = ext.trim().trim_start_matches('.').to_ascii_lowercase();
                    !ext.is_empty()
                        && path.len() > ext.len()
                        && path.ends_with(&ext)
                        && path.as_bytes()[path.len() - ext.len() - 1] == b'.'
                }) {
                    return None;
                }
            }
        }

        let realm = params
            .get("realm")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let charset = params
            .get("charset")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        let Some(auth) = session
            .get_header("authorization")
            .and_then(|v| v.to_str().ok())
        else {
            return Some((false, realm, charset));
        };
        let Some(encoded) = auth.trim().strip_prefix("Basic ") else {
            return Some((false, realm, charset));
        };
        let decoded = match general_purpose::STANDARD.decode(encoded.trim()) {
            Ok(data) => data,
            Err(_) => return Some((false, realm, charset)),
        };
        let decoded = String::from_utf8_lossy(&decoded);
        let Some((username, password)) = decoded.split_once(':') else {
            return Some((false, realm, charset));
        };

        let users = params
            .get("users")
            .and_then(|v| v.as_array())
            .map(|items| {
                items.iter().any(|item| {
                    item.get("username").and_then(|v| v.as_str()) == Some(username)
                        && item.get("password").and_then(|v| v.as_str()) == Some(password)
                })
            })
            .unwrap_or(false);
        Some((users, realm, charset))
    }

    async fn enforce_auth(&self, session: &mut Session, ctx: &mut ProxyCTX) -> Result<bool> {
        let Some(web) = ctx.server.as_ref().and_then(|s| s.web.as_ref()) else {
            return Ok(false);
        };
        let Some(auth) = &web.auth else {
            return Ok(false);
        };
        if !auth.is_on {
            return Ok(false);
        }

        let compiled_plan = ctx
            .server
            .as_ref()
            .and_then(|server| server.id)
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
            .filter(|plan| plan.has_auth());
        if let Some(compiled_plan) = compiled_plan {
            let authorization = session
                .get_header("authorization")
                .and_then(|value| value.to_str().ok());
            if let Some(result) = compiled_plan.auth_result(
                session
                    .get_header("host")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default(),
                session.req_header().uri.path(),
                authorization,
            ) {
                ctx.waf_action = Some(format!("auth:{}", result.auth_type));
                if result.ok {
                    return Ok(false);
                }
                let realm = if result.realm.is_empty() {
                    &ctx.host
                } else {
                    &result.realm
                };
                let mut header = format!("Basic realm=\"{}\"", realm.replace('"', ""));
                if let Some(charset) = result.charset {
                    header.push_str(&format!(", charset=\"{}\"", charset.replace('"', "")));
                }
                let mut resp = pingora_http::ResponseHeader::build(401, None).unwrap();
                let _ = resp.insert_header("www-authenticate", header);
                let _ = resp.insert_header("cache-control", "no-store");
                session.write_response_header(Box::new(resp), true).await?;
                ctx.response_status = 401;
                return Ok(true);
            }
            return Ok(false);
        }

        for policy_ref in &auth.policy_refs {
            let Some(policy) = &policy_ref.auth_policy else {
                continue;
            };
            if !policy_ref.is_on || !policy.is_on {
                continue;
            }
            if policy.auth_type != "basicAuth" {
                continue;
            }
            let Some((ok, realm, charset)) = Self::basic_auth_matches(session, &policy.params)
            else {
                continue;
            };
            ctx.waf_action = Some(format!("auth:{}", policy.auth_type));
            if ok {
                return Ok(false);
            }

            let realm = if realm.is_empty() { &ctx.host } else { &realm };
            let mut header = format!("Basic realm=\"{}\"", realm.replace('"', ""));
            if let Some(charset) = charset {
                header.push_str(&format!(", charset=\"{}\"", charset.replace('"', "")));
            }
            let mut resp = pingora_http::ResponseHeader::build(401, None).unwrap();
            let _ = resp.insert_header("www-authenticate", header);
            let _ = resp.insert_header("cache-control", "no-store");
            session.write_response_header(Box::new(resp), true).await?;
            ctx.response_status = 401;
            return Ok(true);
        }

        Ok(false)
    }

    async fn enforce_referers(&self, session: &mut Session, ctx: &mut ProxyCTX) -> Result<bool> {
        let Some(config) = ctx
            .server
            .as_ref()
            .and_then(|s| s.web.as_ref())
            .and_then(|w| w.referer_config.as_ref())
        else {
            return Ok(false);
        };
        if !config.is_on {
            return Ok(false);
        }
        let url = Self::current_request_url(session, ctx);

        let origin = session
            .get_header("origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let referer = session
            .get_header("referer")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let source = if referer.is_empty()
            && config.check_origin
            && !origin.is_empty()
            && origin != "null"
        {
            origin
        } else {
            referer
        };

        let source_host = if source.is_empty() {
            String::new()
        } else {
            http::Uri::try_from(source)
                .ok()
                .and_then(|uri| uri.host().map(str::to_string))
                .or_else(|| {
                    if source.contains("://") {
                        None
                    } else {
                        Some(crate::lb_factory::strip_addr_port(source))
                    }
                })
                .unwrap_or_default()
        };

        let compiled_allowed = ctx
            .server
            .as_ref()
            .and_then(|server| server.id)
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
            .and_then(|plan| plan.referer_allows(&url, &source_host, &ctx.host));
        let allowed = compiled_allowed.unwrap_or_else(|| {
            if !Self::url_patterns_match(
                &url,
                &config.only_url_patterns,
                &config.except_url_patterns,
            ) {
                return true;
            }
            if source_host.is_empty() {
                config.allow_empty
            } else if config.allow_same_domain && source_host.eq_ignore_ascii_case(&ctx.host) {
                true
            } else if config.allow_domains.is_empty() {
                !config.deny_domains.is_empty()
                    && !Self::wildcard_domain_matches(&config.deny_domains, &source_host)
            } else {
                Self::wildcard_domain_matches(&config.allow_domains, &source_host)
                    && !Self::wildcard_domain_matches(&config.deny_domains, &source_host)
            }
        });

        if allowed {
            return Ok(false);
        }

        ctx.waf_action = Some("refererCheck".to_string());
        ctx.firewall_blocked = true;
        let mut resp = pingora_http::ResponseHeader::build(403, None).unwrap();
        let _ = resp.insert_header("cache-control", "max-age=3600");
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(
                Some(bytes::Bytes::from_static(b"The referer has been blocked.")),
                true,
            )
            .await?;
        ctx.response_status = 403;
        Ok(true)
    }

    async fn enforce_user_agent(&self, session: &mut Session, ctx: &mut ProxyCTX) -> Result<bool> {
        let Some(config) = ctx
            .server
            .as_ref()
            .and_then(|s| s.web.as_ref())
            .and_then(|w| w.user_agent_config.as_ref())
        else {
            return Ok(false);
        };
        if !config.is_on {
            return Ok(false);
        }
        let url = Self::current_request_url(session, ctx);
        let ua = session
            .get_header("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let compiled_action = ctx
            .server
            .as_ref()
            .and_then(|server| server.id)
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
            .and_then(|plan| plan.user_agent_action(&url, ua));
        let blocked = if let Some(action) = compiled_action {
            match action {
                Some(true) => return Ok(false),
                Some(false) => true,
                None => false,
            }
        } else {
            if !Self::url_patterns_match(
                &url,
                &config.only_url_patterns,
                &config.except_url_patterns,
            ) {
                return Ok(false);
            }
            let mut blocked = false;
            for filter in &config.filters {
                if filter.keywords.is_empty() {
                    continue;
                }
                let matched = filter.keywords.iter().any(|keyword| {
                    if keyword.is_empty() {
                        ua.is_empty()
                    } else if keyword.contains('*') {
                        Self::cached_user_agent_wildcard_matches(keyword, ua)
                    } else {
                        ua.to_ascii_lowercase()
                            .contains(&keyword.to_ascii_lowercase())
                    }
                });
                if matched {
                    if filter.action == "allow" {
                        return Ok(false);
                    }
                    blocked = true;
                    break;
                }
            }
            blocked
        };
        if blocked {
            ctx.waf_action = Some("userAgentCheck".to_string());
            ctx.firewall_blocked = true;
            let mut resp = pingora_http::ResponseHeader::build(403, None).unwrap();
            let _ = resp.insert_header("cache-control", "max-age=3600");
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(
                    Some(bytes::Bytes::from_static(
                        b"The User-Agent has been blocked.",
                    )),
                    true,
                )
                .await?;
            ctx.response_status = 403;
            return Ok(true);
        }
        Ok(false)
    }

    async fn respond_domain_mismatch(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        hot_path: &crate::config::HotPathSnapshot,
        host: &str,
    ) -> Result<bool> {
        const HEALTH_CHECK_HEADER: &str = "X-Edge-Health-Check-Key";
        session.as_downstream_mut().set_keepalive(None);
        if let Some(value) = session
            .get_header(HEALTH_CHECK_HEADER)
            .and_then(|v| v.to_str().ok())
            && general_purpose::STANDARD.decode(value.trim()).is_ok()
        {
            let resp = pingora_http::ResponseHeader::build(200, None).unwrap();
            session.write_response_header(Box::new(resp), true).await?;
            ctx.response_status = 200;
            return Ok(true);
        }

        let server_id = 0;
        if self.waf_state.is_blocked(ctx.client_ip, server_id) {
            return self.respond_status_with_pages(session, ctx, 403).await;
        }

        if hot_path.global_http.match_domain_strictly {
            let count = self
                .waf_state
                .increase_counter(format!("MISMATCH_DOMAIN:{}", ctx.client_ip), 60);
            if count > 100 {
                self.waf_state.block_ip(
                    ctx.client_ip,
                    server_id,
                    3600,
                    Some("global"),
                    false,
                    false,
                );
                self.report_ip_list_item(
                    Some(session),
                    Some(ctx),
                    IpReportKind::Black,
                    0,
                    ctx.client_ip.to_string(),
                    0,
                    ctx.server.as_ref().map(|s| s.numeric_id()).unwrap_or(0),
                    3600,
                    "Domain mismatch block".to_string(),
                    "error".to_string(),
                    "domain_mismatch",
                    0,
                    0,
                    0,
                );
            }
        }

        let action = hot_path.global_http.domain_mismatch_action.as_ref();
        let status = action
            .and_then(|a| a.options.get("statusCode").and_then(|v| v.as_i64()))
            .map(|status| Self::response_status_from_i64(status, 404))
            .unwrap_or(404);

        if hot_path.global_http.node_ip_show_page && host.parse::<std::net::IpAddr>().is_ok() {
            let body = self.render_page_template(
                session,
                ctx,
                &hot_path.global_http.node_ip_page_html,
                status,
            );
            let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
            let _ = resp.insert_header("content-type", "text/html; charset=utf-8");
            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await?;
            ctx.response_status = status;
            return Ok(true);
        }

        match action.map(|a| a.code.as_str()) {
            Some("page") => {
                let body = action
                    .and_then(|a| a.options.get("contentHTML").and_then(|v| v.as_str()))
                    .unwrap_or("");
                let body = self.render_page_template(session, ctx, body, status);
                let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                let _ = resp.insert_header("content-type", "text/html; charset=utf-8");
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(bytes::Bytes::from(body)), true)
                    .await?;
            }
            Some("redirect") => {
                let location = action
                    .and_then(|a| a.options.get("url").and_then(|v| v.as_str()))
                    .unwrap_or("");
                if !location.is_empty() {
                    let location = self.render_raw_template(session, ctx, location, 307);
                    let mut resp = pingora_http::ResponseHeader::build(307, None).unwrap();
                    Self::insert_location_header(&mut resp, &location);
                    session.write_response_header(Box::new(resp), true).await?;
                    ctx.response_status = 307;
                    return Ok(true);
                }
                return self.respond_status_with_pages(session, ctx, 404).await;
            }
            Some("close") => {
                self.respond_status_with_pages(session, ctx, 404).await?;
            }
            _ => {
                return self.respond_status_with_pages(session, ctx, 404).await;
            }
        }
        ctx.response_status = status;
        Ok(true)
    }

    fn resolve_plan_max_upload_bytes(&self, ctx: &mut ProxyCTX) -> i64 {
        if let Some(bytes) = ctx.plan_max_upload_bytes {
            return bytes;
        }

        let bytes = ctx
            .server
            .as_ref()
            .map(|server| self.compute_plan_max_upload_bytes(server))
            .unwrap_or(0);
        ctx.plan_max_upload_bytes = Some(bytes);
        bytes
    }

    fn compute_plan_max_upload_bytes(&self, server: &ServerConfig) -> i64 {
        if server.user_plan_id <= 0 {
            return 0;
        }
        self.config
            .get_plan_derived_sync(server.user_plan_id)
            .map(|plan| plan.max_upload_bytes)
            .unwrap_or(0)
    }

    async fn enforce_plan_max_upload(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        if ctx.server.is_none() {
            return Ok(false);
        }

        let max_upload_bytes = self.resolve_plan_max_upload_bytes(ctx);
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
        let compiled_request_limit = server
            .id
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
            .and_then(|plan| plan.request_limit());
        let raw_request_limit = if compiled_request_limit.is_none() {
            let request_limit = server
                .web
                .as_ref()
                .and_then(|web| web.request_limit.as_ref());
            match request_limit {
                Some(request_limit) if request_limit.is_on => Some(request_limit),
                _ => None,
            }
        } else {
            None
        };
        if compiled_request_limit.is_none() && raw_request_limit.is_none() {
            return Ok(false);
        }

        ctx.request_limit_out_bandwidth_bytes = compiled_request_limit
            .map(|request_limit| request_limit.out_bandwidth_per_conn_bytes)
            .or_else(|| {
                raw_request_limit
                    .map(|request_limit| request_limit.out_bandwidth_per_conn_bytes_value())
            })
            .unwrap_or(0);
        if ctx.request_limit_out_bandwidth_bytes <= 0 {
            ctx.request_limit_out_bandwidth_sent = 0;
            ctx.request_limit_out_bandwidth_window_start = None;
        }

        let max_body_bytes = compiled_request_limit
            .map(|request_limit| request_limit.max_body_bytes)
            .or_else(|| raw_request_limit.map(|request_limit| request_limit.max_body_bytes_value()))
            .unwrap_or(0);
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
            compiled_request_limit
                .map(|request_limit| request_limit.max_conns)
                .or_else(|| raw_request_limit.map(|request_limit| request_limit.max_conns))
                .unwrap_or(0),
            compiled_request_limit
                .map(|request_limit| request_limit.max_conns_per_ip)
                .or_else(|| raw_request_limit.map(|request_limit| request_limit.max_conns_per_ip))
                .unwrap_or(0),
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
        let Some(current) = upstream_response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            return;
        };

        let content_type = if let Some(content_type) = server
            .id
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
            .and_then(|plan| plan.charset_content_type(current))
        {
            content_type
        } else {
            let Some(charset_cfg) = server.web.as_ref().and_then(|web| web.charset.as_ref()) else {
                return;
            };
            if !charset_cfg.is_on || charset_cfg.charset.is_empty() {
                return;
            }
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
            format!("{}; charset={}", mime, charset)
        };
        upstream_response.remove_header("content-type");
        let _ = upstream_response.insert_header("content-type", content_type.clone());
        ctx.response_headers
            .insert("content-type".to_string(), content_type);
    }

    fn current_request_url(session: &Session, ctx: &ProxyCTX) -> String {
        let scheme = Self::forwarded_proto(session, ctx);
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

    fn strip_hls_query_from_query(query: &str) -> std::borrow::Cow<'_, str> {
        if !query.contains("hls_session=") && !query.contains("hls_exp=") {
            return std::borrow::Cow::Borrowed(query);
        }

        let mut stripped = String::with_capacity(query.len());
        for item in query.split('&') {
            if item.is_empty() || item.starts_with("hls_session=") || item.starts_with("hls_exp=") {
                continue;
            }
            if !stripped.is_empty() {
                stripped.push('&');
            }
            stripped.push_str(item);
        }
        std::borrow::Cow::Owned(stripped)
    }

    fn default_cache_key_for_session(
        session: &Session,
        ctx: &ProxyCTX,
        cache: &WebCacheConfig,
    ) -> String {
        let request_host = Self::request_host(session);
        let (scheme, host) =
            Self::cache_key_scheme_host(Self::forwarded_proto(session, ctx), &request_host, cache);
        let path = session.req_header().uri.path();
        let query = session
            .req_header()
            .uri
            .query()
            .map(Self::strip_hls_query_from_query);

        let query_len = query.as_ref().map(|query| query.len() + 1).unwrap_or(0);
        let mut key = String::with_capacity(scheme.len() + 3 + host.len() + path.len() + query_len);
        key.push_str(&scheme);
        key.push_str("://");
        key.push_str(&host);
        key.push_str(path);
        if let Some(query) = query
            && !query.is_empty()
        {
            key.push('?');
            key.push_str(&query);
        }
        key
    }

    /// Build a Vary suffix string from a response `Vary` header and the current request headers.
    ///
    /// Returns:
    /// - `None` if no `Vary` header is present (no suffix needed).
    /// - `Some(Err(()))` if `Vary: *` — the response must not be cached.
    /// - `Some(Ok(suffix))` — the suffix to append to the base cache key.
    ///
    /// Format: `@vary:header-name=value&header-name2=value2`
    /// Header names and values are trim+lowercased for normalisation.
    fn vary_cache_key_suffix(
        vary_header: &str,
        request_headers: &http::HeaderMap,
    ) -> Option<Result<String, ()>> {
        // Limit the number of Vary dimensions and the length of each value so
        // an attacker who controls a Vary input (e.g. a unique 8 KiB
        // User-Agent) cannot blow up the cache key space — every unique
        // suffix becomes a separate cache entry in CACHE_META_INDEX and
        // triggers an origin miss.
        const MAX_VARY_FIELDS: usize = 6;
        const MAX_VARY_VALUE_BYTES: usize = 256;

        let vary = vary_header.trim();
        if vary.is_empty() {
            return None;
        }
        // Vary: * means the response is personalised — never cache it.
        if vary.eq_ignore_ascii_case("*") {
            return Some(Err(()));
        }

        let mut parts: Vec<String> = Vec::new();
        for field in vary.split(',') {
            if parts.len() >= MAX_VARY_FIELDS {
                break;
            }
            let name = field.trim().to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            let mut value = request_headers
                .get(&name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if value.len() > MAX_VARY_VALUE_BYTES {
                // Use a stable digest of the overflow so the key stays
                // bounded but still distinguishes different long values.
                let digest = format!("{:x}", md5_legacy::compute(value.as_bytes()));
                value.truncate(MAX_VARY_VALUE_BYTES);
                value.push('#');
                value.push_str(&digest);
            }
            parts.push(format!("{}={}", name, value));
        }

        if parts.is_empty() {
            return None;
        }

        Some(Ok(format!("@vary:{}", parts.join("&"))))
    }

    fn query_param(session: &Session, name: &str) -> Option<String> {
        session.req_header().uri.query().and_then(|query| {
            query.split('&').find_map(|part| {
                let mut it = part.splitn(2, '=');
                let key = it.next()?;
                if key != name {
                    return None;
                }
                let value = it.next().unwrap_or("").replace('+', " ");
                Some(
                    urlencoding::decode(&value)
                        .map(|decoded| decoded.into_owned())
                        .unwrap_or(value),
                )
            })
        })
    }

    fn sanitize_waf_return_path(value: &str) -> String {
        let decoded = urlencoding::decode(value)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| value.to_string());
        if decoded.starts_with('/')
            && !decoded.starts_with("//")
            && !decoded.contains('\r')
            && !decoded.contains('\n')
        {
            decoded
        } else {
            "/".to_string()
        }
    }

    fn waf_life_seconds(life_seconds: i64) -> i64 {
        if life_seconds > 0 { life_seconds } else { 600 }
    }

    fn waf_cookie_suffix(session: &Session, ctx: &ProxyCTX, life_seconds: i64) -> String {
        let secure = if Self::is_https_downstream(session, ctx) {
            "; Secure"
        } else {
            ""
        };
        format!(
            "Path=/; Max-Age={}; SameSite=Lax{}",
            Self::waf_life_seconds(life_seconds),
            secure
        )
    }

    fn ensure_request_metrics_started(&self, ctx: &mut ProxyCTX) {
        if ctx.metrics_started {
            return;
        }
        let Some((server_id, user_id, user_plan_id)) = ctx.server.as_ref().and_then(|server| {
            let server_id = server.id?;
            (server_id > 0).then_some((server_id, server.user_id, server.user_plan_id))
        }) else {
            return;
        };

        if ctx.server_metrics.is_none() {
            ctx.server_metrics = Some(crate::metrics::record::get_or_create(server_id));
        }
        let plan_id = if user_plan_id > 0 {
            self.config.get_user_plan_id_sync(user_plan_id).unwrap_or(0)
        } else {
            0
        };
        ctx.ip_recorded = crate::metrics::record::request_start(
            server_id,
            &ctx.client_ip_str,
            user_id,
            user_plan_id,
            plan_id,
            ctx.server_metrics.as_ref(),
            ctx.ip_recorded,
        );
        ctx.metrics_started = true;
    }

    fn waf_redirect_signature(&self, token: &str, ip: &str, ua: &str) -> String {
        let digest = Self::hmac_sha256(
            self.api_config.secret.as_bytes(),
            format!("waf-redirect|{token}|{ip}|{ua}").as_bytes(),
        );
        hex::encode(digest)
    }

    fn waf_pass_signature(&self, token: &str, ip: &str, ua: &str, challenge_type: &str) -> String {
        let digest = Self::hmac_sha256(
            self.api_config.secret.as_bytes(),
            format!("waf-pass|{token}|{ip}|{ua}|{challenge_type}").as_bytes(),
        );
        hex::encode(digest)
    }

    fn encode_waf_pass_cookie_value(challenge_type: &str, signature: &str) -> String {
        let payload = format!("{challenge_type}|{signature}");
        general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes())
    }

    fn decode_waf_pass_cookie_value(value: &str) -> Option<(String, String)> {
        let decoded = general_purpose::URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .ok()?;
        let payload = String::from_utf8(decoded).ok()?;
        let (challenge_type, signature) = payload.split_once('|')?;
        Some((challenge_type.to_string(), signature.to_string()))
    }

    fn waf_pass_cookie_verified_for_action(
        &self,
        session: &Session,
        matched: &crate::firewall::MatchedAction,
        ip: &str,
        ua: &str,
    ) -> bool {
        if !matches!(
            matched.action,
            crate::firewall::ActionResponse::Captcha { .. }
                | crate::firewall::ActionResponse::JsCookie { .. }
        ) {
            return false;
        }

        let cookies = match merged_session_cookie_header(session) {
            Some(cookies) => cookies,
            None => return false,
        };

        let mut token = None;
        let mut pass = None;
        for part in cookies.split(';') {
            let part = part.trim();
            if let Some(raw_token) = part.strip_prefix("WAF-Token=") {
                token = Some(
                    raw_token
                        .split_once(":type=")
                        .map(|(token, _)| token)
                        .unwrap_or(raw_token),
                );
            } else if let Some(raw_pass) = part.strip_prefix("WAF-Pass=") {
                pass = Some(raw_pass);
            }
        }

        let Some(token) = token else {
            return false;
        };
        if self
            .waf_verifier
            .token_seconds_remaining(ip, ua, token, 3600)
            .is_none()
        {
            return false;
        }

        let Some((challenge_type, signature)) = pass.and_then(Self::decode_waf_pass_cookie_value)
        else {
            return false;
        };
        if signature != self.waf_pass_signature(token, ip, ua, &challenge_type) {
            return false;
        }

        let expected = self.waf_expected_challenge_method(matched);
        challenge_type == expected
            || (expected == "geetest"
                && matches!(challenge_type.as_str(), "slider" | "click" | "captcha"))
    }

    fn clear_waf_challenge_block(
        &self,
        ip: std::net::IpAddr,
        server_id: i64,
        failure_config: Option<crate::firewall::verifier::ChallengeFailureConfig>,
    ) {
        let scope_id = if failure_config.is_some_and(|config| config.fail_global) {
            0
        } else {
            server_id
        };
        self.waf_state.remove_black_ip(scope_id, ip);
        if let Ok(net) = self.waf_state.get_c_class_net(ip) {
            self.waf_state.remove_black_network(scope_id, net);
        }
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

    fn hmac_sha256_hex(secret: &[u8], data: &[u8]) -> String {
        use hmac::digest::KeyInit as HmacKeyInit;
        use hmac::{Hmac, Mac};

        type HmacSha256 = Hmac<Sha256>;
        let Ok(mut mac) = <HmacSha256 as HmacKeyInit>::new_from_slice(secret) else {
            return hex::encode(Self::hmac_sha256(secret, data));
        };
        mac.update(data);
        hex::encode(mac.finalize().into_bytes())
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

    async fn maybe_serve_waf_verify(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        if session.req_header().uri.path() != WAF_VERIFY_ROUTE {
            return Ok(false);
        }

        let token = Self::query_param(session, "__waf_token").unwrap_or_default();
        let pow = Self::query_param(session, "__waf_pow").unwrap_or_default();
        let elapsed = Self::query_param(session, "__waf_elapsed")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let final_x = Self::query_param(session, "__waf_x")
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(i32::MIN);
        let trace = Self::query_param(session, "__waf_trace").unwrap_or_default();
        let return_path = Self::query_param(session, "__waf_return")
            .map(|value| Self::sanitize_waf_return_path(&value))
            .unwrap_or_else(|| "/".to_string());
        let ua = session
            .get_header("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let is_uam_verification = Self::query_param(session, "__waf_uam").as_deref() == Some("1");

        if is_uam_verification {
            let site_uam = Self::site_uam_config(ctx);
            let global_uam = self.config.get_global_uam_policy_sync();
            let uam_cfg = Self::active_uam_config(site_uam, global_uam.as_ref());
            let site_uam_enabled = site_uam.is_some();
            let verified = if uam_cfg.is_some() {
                let scope_id = Self::uam_scope_id(ctx, site_uam_enabled);
                let host_scope = Self::uam_host_scope(ctx);
                let config_hash = Self::uam_config_hash(site_uam, global_uam.as_ref());
                let token_result = (!token.is_empty())
                    .then(|| {
                        self.validate_uam_challenge_token(
                            &token,
                            &ctx.client_ip_str,
                            ua,
                            scope_id,
                            &host_scope,
                            &config_hash,
                        )
                    })
                    .flatten();
                let token_mode = token_result
                    .as_ref()
                    .map(|(_, mode, _)| *mode)
                    .unwrap_or_else(|| Self::uam_mode(uam_cfg));
                let token_pow_difficulty = token_result
                    .as_ref()
                    .map(|(_, _, difficulty)| *difficulty)
                    .unwrap_or_else(|| Self::uam_pow_difficulty(uam_cfg));
                let trace_verified = !Self::uam_mode_requires_slider_trace(token_mode)
                    || self
                        .waf_verifier
                        .verify_slider_trace(&token, final_x, elapsed, &trace);
                let pow_verified = !Self::uam_mode_requires_pow(token_mode)
                    || (!pow.is_empty()
                        && self
                            .waf_verifier
                            .verify_pow(&token, &pow, token_pow_difficulty as u32));
                token_result.filter(|_| pow_verified && trace_verified).map(
                    |(_, mode, pow_difficulty)| {
                        (scope_id, host_scope, config_hash, mode, pow_difficulty)
                    },
                )
            } else {
                None
            };

            if let Some((scope_id, host_scope, config_hash, mode, _pow_difficulty)) = verified {
                let pass_life_seconds = Self::uam_life_seconds(uam_cfg);
                let suffix = Self::waf_cookie_suffix(session, ctx, pass_life_seconds);
                let uam_pass = self.issue_uam_pass_cookie(
                    &ctx.client_ip_str,
                    ua,
                    scope_id,
                    &host_scope,
                    &config_hash,
                    pass_life_seconds,
                );
                let uam_challenge_type = Self::uam_mode_code(mode);
                let mut resp = pingora_http::ResponseHeader::build(303, None).unwrap();
                Self::insert_location_header(&mut resp, &return_path);
                resp.append_header(
                    "set-cookie",
                    format!("UAM-Pass={uam_pass}:type={uam_challenge_type}; HttpOnly; {suffix}"),
                )
                .unwrap();
                resp.append_header("set-cookie", format!("UAM-Token=; Max-Age=0; {suffix}"))
                    .unwrap();
                resp.insert_header("cache-control", "no-store").unwrap();
                resp.insert_header("x-uam-verified", "1").unwrap();
                session.write_response_header(Box::new(resp), true).await?;
                ctx.response_status = 303;
                ctx.response_body_len = 0;
                return Ok(true);
            }

            let mut resp = pingora_http::ResponseHeader::build(403, None).unwrap();
            resp.insert_header("content-type", "text/html; charset=utf-8")
                .unwrap();
            resp.insert_header("cache-control", "no-store").unwrap();
            resp.insert_header("x-uam-verified", "0").unwrap();
            session.write_response_header(Box::new(resp), false).await?;
            let body = Bytes::from(self.render_page_template(
                session,
                ctx,
                &crate::pages::verification_failed_page(),
                403,
            ));
            ctx.response_status = 403;
            ctx.response_body_len = body.len();
            session.write_response_body(Some(body), true).await?;
            return Ok(true);
        }

        let token_remaining = (!token.is_empty())
            .then(|| {
                self.waf_verifier
                    .token_seconds_remaining(&ctx.client_ip_str, ua, &token, 3600)
            })
            .flatten();

        let challenge_type = Self::query_param(session, "__waf_challenge_type")
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "slider".to_string());
        let challenge_token =
            Self::query_param(session, "__waf_challenge_token").filter(|v| !v.is_empty());

        let token_pow_difficulty = self
            .waf_verifier
            .token_pow_difficulty(&ctx.client_ip_str, ua, &token)
            .unwrap_or(4) as u32;
        // PoW is only required for explicit pow challenge types; slider/click/captcha
        // embed their own verification params (x/y, click_seq, captcha_hash) and skip PoW.
        let pow_required = matches!(challenge_type.as_str(), "pow" | "");
        let pow_ok = !pow_required
            || (!pow.is_empty()
                && self
                    .waf_verifier
                    .verify_pow(&token, &pow, token_pow_difficulty));

        let mut verified_js_cookie_name = None;
        let verified = token_remaining.is_some()
            && pow_ok
            && match challenge_type.as_str() {
                "click" => {
                    let sequence_str =
                        Self::query_param(session, "__waf_click_seq").unwrap_or_default();
                    let seq: Vec<usize> = sequence_str
                        .split(',')
                        .filter_map(|s| s.parse().ok())
                        .collect();
                    let click_elapsed = Self::query_param(session, "__waf_elapsed")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    challenge_token.as_deref().is_some_and(|challenge_token| {
                        crate::pages::challenges::click::verify(
                            challenge_token,
                            &seq,
                            click_elapsed,
                            self.api_config.secret.as_bytes(),
                        )
                    })
                }
                "captcha" => {
                    let answer_hash =
                        Self::query_param(session, "__waf_captcha_hash").unwrap_or_default();
                    challenge_token.as_deref().is_some_and(|challenge_token| {
                        crate::pages::challenges::captcha::verify(
                            challenge_token,
                            &answer_hash,
                            self.api_config.secret.as_bytes(),
                        )
                    })
                }
                "jscookie" => {
                    let elapsed = Self::query_param(session, "__waf_js_elapsed")
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0);
                    let fingerprint = Self::query_param(session, "__waf_js_fp").unwrap_or_default();
                    let digest = Self::query_param(session, "__waf_js_digest").unwrap_or_default();
                    let cookies = merged_session_cookie_header(session).unwrap_or_default();
                    verified_js_cookie_name =
                        challenge_token.as_deref().and_then(|challenge_token| {
                            crate::pages::challenges::jscookie::verify(
                                challenge_token,
                                &token,
                                &cookies,
                                elapsed,
                                &fingerprint,
                                &digest,
                                self.api_config.secret.as_bytes(),
                            )
                        });
                    verified_js_cookie_name.is_some()
                }
                "pow" => true,
                _ => {
                    // default: slider
                    let sx = Self::query_param(session, "__waf_x")
                        .or_else(|| Self::query_param(session, "x"))
                        .and_then(|v| v.parse::<f64>().ok())
                        .unwrap_or(0.0);
                    let sy = Self::query_param(session, "__waf_y")
                        .or_else(|| Self::query_param(session, "y"))
                        .and_then(|v| v.parse::<f64>().ok())
                        .unwrap_or(0.0);
                    if let Some(challenge_token) = challenge_token.as_deref() {
                        crate::pages::challenges::slider::verify_explicit(
                            challenge_token,
                            sx,
                            sy,
                            elapsed,
                            &trace,
                            self.api_config.secret.as_bytes(),
                        )
                    } else {
                        let target = self.waf_verifier.slider_target(&token);
                        crate::pages::challenges::slider::verify_anchor(
                            target, sx, sy, elapsed, &trace,
                        )
                    }
                }
            };

        if verified {
            let remaining = token_remaining.unwrap_or(1) as i64;
            if let Ok(ip) = ctx.client_ip_str.parse() {
                let server_id = ctx.server.as_ref().map(|s| s.numeric_id()).unwrap_or(0);
                let failure_config =
                    self.waf_verifier
                        .token_failure_config(&ctx.client_ip_str, ua, &token);
                self.clear_waf_challenge_block(ip, server_id, failure_config);
            }
            let suffix = Self::waf_cookie_suffix(session, ctx, remaining);
            let pass_sig = self.waf_pass_signature(&token, &ctx.client_ip_str, ua, &challenge_type);
            let pass_cookie = Self::encode_waf_pass_cookie_value(&challenge_type, &pass_sig);
            let mut resp = pingora_http::ResponseHeader::build(303, None).unwrap();
            Self::insert_location_header(&mut resp, &return_path);
            resp.append_header(
                "set-cookie",
                format!("WAF-Token={token}:type={challenge_type}; HttpOnly; {suffix}"),
            )
            .unwrap();
            if challenge_type == "pow" {
                resp.append_header("set-cookie", format!("WAF-PoW={pow}; {suffix}"))
                    .unwrap();
            }
            resp.append_header(
                "set-cookie",
                format!("WAF-Pass={pass_cookie}; HttpOnly; {suffix}"),
            )
            .unwrap();
            if let Some(cookie_name) = verified_js_cookie_name {
                resp.append_header(
                    "set-cookie",
                    format!("{cookie_name}=; Max-Age=0; Path=/; SameSite=Lax"),
                )
                .unwrap();
            }
            resp.insert_header("cache-control", "no-store").unwrap();
            session.write_response_header(Box::new(resp), true).await?;
            ctx.response_status = 303;
            ctx.response_body_len = 0;
            return Ok(true);
        }

        if let Some(failure_config) =
            self.waf_verifier
                .token_failure_config(&ctx.client_ip_str, ua, &token)
            && failure_config.max_fails > 0
        {
            let server_id = ctx.server.as_ref().map(|s| s.numeric_id()).unwrap_or(0);
            let failure_scope_id = if failure_config.fail_global {
                0
            } else {
                server_id
            };
            let failures = self.waf_state.record_failure(format!(
                "WAF_CHALLENGE:{challenge_type}:{failure_scope_id}:{}",
                ctx.client_ip_str
            ));
            if failures >= failure_config.max_fails as u64
                && let Ok(ip) = ctx.client_ip_str.parse()
            {
                let scope = if failure_config.fail_global {
                    "global"
                } else {
                    "server"
                };
                let timeout = failure_config.fail_block_timeout.max(1);
                self.waf_state
                    .block_ip(ip, server_id, timeout, Some(scope), false, true);
                self.report_ip_list_item(
                    Some(session),
                    Some(ctx),
                    IpReportKind::Black,
                    0,
                    ip.to_string(),
                    failure_scope_id,
                    server_id,
                    timeout,
                    "WAF challenge failure block".to_string(),
                    "error".to_string(),
                    "challenge",
                    0,
                    0,
                    0,
                );
            }
        }

        let mut resp = pingora_http::ResponseHeader::build(403, None).unwrap();
        resp.insert_header("content-type", "text/html; charset=utf-8")
            .unwrap();
        resp.insert_header("cache-control", "no-store").unwrap();
        session.write_response_header(Box::new(resp), false).await?;
        let body =
            self.render_page_template(session, ctx, &crate::pages::verification_failed_page(), 403);
        ctx.response_body_len = body.len();
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        ctx.response_status = 403;
        Ok(true)
    }

    async fn maybe_serve_acme_challenge(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        const ACME_PREFIX: &str = "/.well-known/acme-challenge/";

        let path = session.req_header().uri.path();
        let Some(token_path) = path.strip_prefix(ACME_PREFIX) else {
            return Ok(false);
        };
        let token = token_path.rsplit('/').next().unwrap_or_default();
        if token == "acme-challenge" || token.len() <= 32 {
            return Ok(false);
        }

        let key = match crate::rpc::acme::find_acme_key(&self.api_config, token).await {
            crate::rpc::acme::AcmeKeyLookup::Found(key) => key,
            crate::rpc::acme::AcmeKeyLookup::Missing => return Ok(false),
            crate::rpc::acme::AcmeKeyLookup::RpcError(err) => {
                debug!(
                    "ACME challenge key lookup failed for token={}: {}",
                    token, err
                );
                return Ok(false);
            }
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

    fn is_hls_encrypted_request(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        server: &ServerConfig,
    ) -> bool {
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
        encrypting.matches_url(&Self::current_request_url(session, ctx))
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

        let key = Array::from(key);
        let cipher = Aes128::new(&key);
        let mut prev = iv;
        let mut out = Vec::with_capacity(padded.len());

        for chunk in padded.chunks_mut(16) {
            for (i, b) in chunk.iter_mut().enumerate() {
                *b ^= prev[i];
            }
            let mut block = Array::from(<[u8; 16]>::try_from(&*chunk).expect("AES block"));
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            prev.copy_from_slice(&block);
        }

        out
    }

    #[doc(hidden)]
    pub fn bench_aes128_cbc_encrypt(body: &[u8], key: [u8; 16], iv: [u8; 16]) -> Vec<u8> {
        Self::aes128_cbc_encrypt(body, key, iv)
    }

    fn minify_html(
        body: &[u8],
        config: &crate::config_models::HTTPHTMLOptimizationConfig,
    ) -> anyhow::Result<Vec<u8>> {
        static RE_COMMENT: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"<!--[\s\S]*?-->").unwrap());
        static RE_BETWEEN_TAGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r">\s+<").unwrap());
        static RE_MULTI_SPACE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"[ \t\r\n]{2,}").unwrap());

        let mut text = String::from_utf8(body.to_vec())?;
        if !config.keep_comments {
            text = RE_COMMENT
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
            text = RE_BETWEEN_TAGS.replace_all(&text, "><").to_string();
            text = RE_MULTI_SPACE.replace_all(&text, " ").to_string();
        }
        Ok(text.into_bytes())
    }

    #[doc(hidden)]
    pub fn bench_minify_html(
        body: &[u8],
        config: &crate::config_models::HTTPHTMLOptimizationConfig,
    ) -> anyhow::Result<Vec<u8>> {
        Self::minify_html(body, config)
    }

    fn minify_css(body: &[u8]) -> anyhow::Result<Vec<u8>> {
        static RE_COMMENTS: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"/\*[\s\S]*?\*/").unwrap());
        static RE_SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());
        static RE_TOKENS: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"\s*([{}:;,>])\s*").unwrap());

        let mut text = String::from_utf8(body.to_vec())?;
        text = RE_COMMENTS.replace_all(&text, "").to_string();
        text = RE_SPACES.replace_all(&text, " ").to_string();
        text = RE_TOKENS.replace_all(&text, "$1").to_string();
        Ok(text.trim().as_bytes().to_vec())
    }

    #[doc(hidden)]
    pub fn bench_minify_css(body: &[u8]) -> anyhow::Result<Vec<u8>> {
        Self::minify_css(body)
    }

    fn minify_js(body: &[u8]) -> anyhow::Result<Vec<u8>> {
        static RE_BLOCK_COMMENTS: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"/\*[\s\S]*?\*/").unwrap());
        static RE_LINE_COMMENTS: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"(?m)^\s*//.*$").unwrap());
        static RE_SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

        let mut text = String::from_utf8(body.to_vec())?;
        text = RE_BLOCK_COMMENTS.replace_all(&text, "").to_string();
        text = RE_LINE_COMMENTS.replace_all(&text, "").to_string();
        text = RE_SPACES.replace_all(&text, " ").to_string();
        Ok(text.trim().as_bytes().to_vec())
    }

    #[doc(hidden)]
    pub fn bench_minify_js(body: &[u8]) -> anyhow::Result<Vec<u8>> {
        Self::minify_js(body)
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
        let request_url = Self::current_request_url(session, ctx);
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

        let compiled_plan = server
            .id
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id));
        let kind = if let Some(plan) = compiled_plan.filter(|plan| plan.has_optimization()) {
            plan.optimization_kind(&content_type, &request_url)
        } else {
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
            if content_type == "text/html" || content_type == "application/xhtml+xml" {
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
            }
        };

        if let Some(kind) = kind {
            let Some(transform_permit) =
                MEMORY_GOVERNOR.try_admit(AdmissionClass::ResponseTransform)
            else {
                return;
            };
            ctx.optimize_enabled = true;
            ctx.response_transform_permit = Some(transform_permit);
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
        if upstream_response.status.as_u16() != 200 {
            return;
        }

        let request_url = Self::current_request_url(session, ctx);
        let compiled_plan = server
            .id
            .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id));
        let hls_matches = if let Some(plan) = compiled_plan.filter(|plan| plan.has_hls_encrypting())
        {
            plan.hls_encrypting_matches(&request_url)
        } else {
            let Some(hls) = server.web.as_ref().and_then(|web| web.hls.as_ref()) else {
                return;
            };
            let Some(encrypting) = hls.encrypting.as_ref() else {
                return;
            };
            if !encrypting.is_on {
                return;
            }
            encrypting.matches_url(&request_url)
        };
        if !hls_matches {
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
            let Some(transform_permit) =
                MEMORY_GOVERNOR.try_admit(AdmissionClass::ResponseTransform)
            else {
                return;
            };
            ctx.hls_playlist_enabled = true;
            ctx.response_transform_permit = Some(transform_permit);
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
            let Some(transform_permit) =
                MEMORY_GOVERNOR.try_admit(AdmissionClass::ResponseTransform)
            else {
                return;
            };
            let (key, iv, _) =
                self.hls_key_material(server.numeric_id(), &target, &session_id, exp);
            ctx.hls_segment_encrypt_enabled = true;
            ctx.response_transform_permit = Some(transform_permit);
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

    fn resolve_traffic_limit_notice_body(&self, ctx: &mut ProxyCTX) -> Option<String> {
        if let Some(body) = ctx.traffic_limit_notice_body.as_ref() {
            return body.clone();
        }

        let body = ctx
            .server
            .as_ref()
            .and_then(|server| self.compute_traffic_limit_notice_body(server));
        ctx.traffic_limit_notice_body = Some(body.clone());
        body
    }

    fn compute_traffic_limit_notice_body(&self, server: &ServerConfig) -> Option<String> {
        if let Some(config) = server.traffic_limit.as_ref()
            && config.is_on
        {
            return (!config.notice_page_body.is_empty()).then(|| config.notice_page_body.clone());
        }

        if server.user_plan_id <= 0 {
            return None;
        }
        self.config
            .get_plan_derived_sync(server.user_plan_id)
            .and_then(|plan| plan.traffic_limit_notice_body)
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
            .resolve_traffic_limit_notice_body(ctx)
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
        ctx: &mut ProxyCTX,
    ) -> bool {
        if let Some(cookies) = merged_session_cookie_header(session) {
            if !cookies.contains("WAF-Token=") || !cookies.contains("WAF-Redirect=") {
                return false;
            }

            let verifier = self.waf_verifier.as_ref();
            let mut current_token = None;
            let mut redirect_sig = None;

            for part in cookies.split(';') {
                let part = part.trim();
                // 1. Check AES-256-GCM Token
                if let Some(raw_token) = part.strip_prefix("WAF-Token=")
                    && let token = raw_token
                        .split_once(":type=")
                        .map(|(t, _)| t)
                        .unwrap_or(raw_token)
                    && verifier
                        .token_seconds_remaining(ip_str, ua, token, 3600)
                        .is_some()
                {
                    current_token = Some(token);
                }
                if let Some(sig) = part.strip_prefix("WAF-Redirect=") {
                    redirect_sig = Some(sig);
                }
            }

            if let Some(token) = current_token {
                let redirect_verified = redirect_sig
                    .is_some_and(|sig| sig == self.waf_redirect_signature(token, ip_str, ua));
                if redirect_verified {
                    if let Ok(ip) = ip_str.parse() {
                        let server_id = ctx.server.as_ref().map(|s| s.numeric_id()).unwrap_or(0);
                        let failure_config = verifier.token_failure_config(ip_str, ua, token);
                        self.clear_waf_challenge_block(ip, server_id, failure_config);
                    }
                    ctx.waf_whitelisted = true;
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
        let action = matched.action.clone();

        if !matches!(action, crate::firewall::ActionResponse::Allow) {
            ctx.firewall_blocked = true;
        }

        match action {
            crate::firewall::ActionResponse::Allow => Ok(false),
            crate::firewall::ActionResponse::Block {
                mut status,
                mut body,
            } => {
                debug!(
                    "WAF_BLOCK: IP={} host={} method={} uri={} status={} policy_id={} group_id={} action={} tags={:?}",
                    ip,
                    ctx.host,
                    session.req_header().method,
                    session.req_header().uri,
                    status,
                    matched.policy_id,
                    matched.group_id,
                    matched.action_code,
                    matched.tags
                );
                if let Some(opts) = &matched.block_options {
                    if opts.status_code > 0 {
                        status = opts.status_code;
                    }
                    if !opts.body.is_empty() {
                        body = opts.body.clone();
                    }
                } else if let Some(opts) = ctx.global_waf_block_options.as_deref() {
                    if opts.status_code > 0 {
                        status = opts.status_code;
                    }
                    if !opts.body.is_empty() {
                        body = opts.body.clone();
                    }
                }

                let status = Self::waf_response_status(status, 403);
                let resolved_body = self.render_waf_block_body(session, ctx, &body, status);
                let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                resp.insert_header("content-type", "text/html; charset=utf-8")
                    .unwrap();
                ctx.response_status = status;
                ctx.response_body_len = resolved_body.len();
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
                else if let Some(global) = self
                    .config
                    .get_waf_actions_sync()
                    .iter()
                    .find(|a| a.code == "page")
                {
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
                let status = Self::waf_response_status(status, 403);
                let resolved_body = self.render_page_template(session, ctx, &body, status);
                let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                resp.insert_header("content-type", content_type).unwrap();
                ctx.response_status = status;
                ctx.response_body_len = resolved_body.len();
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::from(resolved_body)), true)
                    .await?;
                Ok(true)
            }
            crate::firewall::ActionResponse::Redirect { status, location } => {
                let status = Self::waf_redirect_status(status);
                let resolved_url = self.render_raw_template(session, ctx, &location, status);
                let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                Self::insert_location_header(&mut resp, &resolved_url);
                ctx.response_status = status;
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
                let verifier = self.waf_verifier.as_ref();

                let status = match action {
                    crate::firewall::ActionResponse::Get302 { .. } => 302,
                    crate::firewall::ActionResponse::Post307 { .. } => 307,
                    _ => 403,
                };

                let captcha_opts = matched.captcha_options.clone();
                let js_opts = matched.js_cookie_options.clone();
                let rule_life_seconds = matched.life_seconds.unwrap_or(0);
                let rule_max_fails = matched.max_fails;
                let rule_fail_block_timeout = matched.fail_block_timeout;
                let rule_fail_global = matched.fail_global;
                let policy_values = match action {
                    crate::firewall::ActionResponse::Captcha { .. }
                    | crate::firewall::ActionResponse::Get302 { .. }
                    | crate::firewall::ActionResponse::Post307 { .. } => {
                        captcha_opts.as_ref().map(|opts| {
                            (
                                opts.life_seconds as i64,
                                opts.max_fails,
                                opts.fail_block_timeout as i64,
                                opts.fail_global,
                            )
                        })
                    }
                    crate::firewall::ActionResponse::JsCookie { .. } => {
                        js_opts.as_ref().map(|opts| {
                            (
                                opts.life_seconds as i64,
                                opts.max_fails,
                                opts.fail_block_timeout as i64,
                                opts.fail_global,
                            )
                        })
                    }
                    _ => None,
                };
                let global_actions = self.config.get_waf_actions_sync();
                let global_values = global_actions
                    .iter()
                    .find(|global| global.code == matched.action_code)
                    .map(|global| {
                        (
                            global
                                .options
                                .get("life")
                                .and_then(serde_json::Value::as_i64)
                                .unwrap_or(0),
                            global
                                .options
                                .get("maxFails")
                                .and_then(serde_json::Value::as_i64)
                                .unwrap_or(0) as i32,
                            global
                                .options
                                .get("failBlockTimeout")
                                .and_then(serde_json::Value::as_i64)
                                .unwrap_or(0),
                            global
                                .options
                                .get("failBlockScopeAll")
                                .and_then(serde_json::Value::as_bool)
                                .unwrap_or(false),
                        )
                    });
                life_seconds = if rule_life_seconds > 0 {
                    rule_life_seconds
                } else {
                    policy_values
                        .and_then(|values| (values.0 > 0).then_some(values.0))
                        .or_else(|| {
                            global_values.and_then(|values| (values.0 > 0).then_some(values.0))
                        })
                        .unwrap_or(life_seconds)
                };
                let max_fails = rule_max_fails.unwrap_or_else(|| {
                    policy_values
                        .map(|values| values.1.max(0))
                        .or_else(|| global_values.map(|values| values.1.max(0)))
                        .unwrap_or(0)
                });
                let fail_block_timeout = rule_fail_block_timeout.unwrap_or_else(|| {
                    policy_values
                        .and_then(|values| (values.2 > 0).then_some(values.2))
                        .or_else(|| {
                            global_values.and_then(|values| (values.2 > 0).then_some(values.2))
                        })
                        .unwrap_or(3600)
                });
                let fail_global = rule_fail_global.unwrap_or_else(|| {
                    policy_values
                        .map(|values| values.3)
                        .or_else(|| global_values.map(|values| values.3))
                        .unwrap_or(false)
                });
                let difficulty = captcha_opts
                    .as_ref()
                    .map(|o| o.challenge_difficulty.max(1) as u32)
                    .unwrap_or(4);
                life_seconds = Self::waf_life_seconds(life_seconds);
                let token = verifier.generate_token_with_config(
                    &ip,
                    ua,
                    life_seconds as u64,
                    crate::firewall::verifier::ChallengeFailureConfig {
                        max_fails,
                        fail_block_timeout,
                        fail_global,
                        pow_difficulty: difficulty as u8,
                    },
                );
                let suffix = Self::waf_cookie_suffix(session, ctx, life_seconds);

                if matches!(
                    action,
                    crate::firewall::ActionResponse::Get302 { .. }
                        | crate::firewall::ActionResponse::Post307 { .. }
                ) {
                    let redirect_sig = self.waf_redirect_signature(&token, &ip, ua);
                    let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                    Self::insert_location_header(
                        &mut resp,
                        Self::current_request_path_query(session),
                    );
                    resp.append_header(
                        "set-cookie",
                        format!("WAF-Token={token}; HttpOnly; {suffix}"),
                    )
                    .unwrap();
                    resp.append_header(
                        "set-cookie",
                        format!("WAF-Redirect={redirect_sig}; HttpOnly; {suffix}"),
                    )
                    .unwrap();
                    resp.insert_header("cache-control", "no-store").unwrap();
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }

                let return_path =
                    urlencoding::encode(&Self::current_request_path_query(session)).into_owned();
                let challenge_lang = captcha_opts
                    .as_ref()
                    .and_then(|o| {
                        (!o.challenge_lang.trim().is_empty())
                            .then(|| crate::pages::detect_lang(Some(&o.challenge_lang), None))
                    })
                    .unwrap_or(crate::pages::Lang::En);
                // Determine the challenge method, resolving "geetest" into a
                // true random choice across the local challenge implementations.
                let raw_method = self.waf_expected_challenge_method(&matched);
                let effective_method = if raw_method == "geetest" {
                    let modes = ["slider", "click", "captcha"];
                    let mut rng = rand::thread_rng();
                    modes.choose(&mut rng).copied().unwrap_or("slider")
                } else {
                    raw_method.as_str()
                };

                let challenge_secret = self.api_config.secret.as_bytes();
                let challenge_expiry =
                    crate::utils::time::now_timestamp() as u64 + life_seconds.max(60) as u64;

                let body_html = match effective_method {
                    "click" => {
                        use crate::pages::challenges::click;
                        let body = click::issue_html(
                            challenge_lang,
                            &token,
                            WAF_VERIFY_ROUTE,
                            &return_path,
                            challenge_secret,
                            challenge_expiry,
                        );
                        let page = crate::pages::uam_challenge_page(
                            &body,
                            "",
                            challenge_lang,
                            &ctx.request_id,
                        );
                        page
                    }
                    "captcha" => {
                        use crate::pages::challenges::captcha;
                        let body = captcha::issue_html(
                            challenge_lang,
                            &token,
                            WAF_VERIFY_ROUTE,
                            &return_path,
                            challenge_secret,
                            challenge_expiry,
                        );
                        let page = crate::pages::uam_challenge_page(
                            &body,
                            "",
                            challenge_lang,
                            &ctx.request_id,
                        );
                        page
                    }
                    "jscookie" => {
                        use crate::pages::challenges::jscookie;
                        let body = jscookie::issue_html(
                            challenge_lang,
                            &token,
                            WAF_VERIFY_ROUTE,
                            &return_path,
                            challenge_secret,
                            challenge_expiry,
                            Self::is_https_downstream(session, ctx),
                        );
                        crate::pages::uam_challenge_page(&body, "", challenge_lang, &ctx.request_id)
                    }
                    "pow" => {
                        let t = crate::pages::lang::text(challenge_lang);
                        let pow_script = self.waf_verifier.get_pow_script_with_life(
                            &token,
                            difficulty,
                            life_seconds,
                        );
                        let body = format!(
                            "<h1 data-i18n=\"checking\">{}</h1><p data-i18n=\"checking_sub\">{}</p><div class=\"progress\"><span></span></div><div class=\"meta\">Request #{}</div>",
                            t.checking, t.checking_sub, ctx.request_id
                        );
                        crate::pages::uam_challenge_page(
                            &body,
                            &format!("<script>{pow_script}</script>"),
                            challenge_lang,
                            &ctx.request_id,
                        )
                    }
                    _ => {
                        // default: slider
                        let target = verifier.slider_target(&token);
                        use crate::pages::challenges::slider;
                        let body = slider::issue_html(
                            challenge_lang,
                            &token,
                            WAF_VERIFY_ROUTE,
                            &return_path,
                            target,
                            challenge_secret,
                            challenge_expiry,
                        );
                        let page = crate::pages::uam_challenge_page(
                            &body,
                            "",
                            challenge_lang,
                            &ctx.request_id,
                        );
                        page
                    }
                };
                let body_html = self.render_page_template(session, ctx, &body_html, status);

                let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                resp.insert_header("content-type", "text/html; charset=utf-8")
                    .unwrap();
                resp.insert_header("cache-control", "no-store").unwrap();
                resp.insert_header("x-content-type-options", "nosniff")
                    .unwrap();
                resp.insert_header("referrer-policy", "same-origin")
                    .unwrap();
                if !matches!(action, crate::firewall::ActionResponse::Captcha { .. })
                    || effective_method == "jscookie"
                {
                    let token_cookie = if effective_method == "jscookie" {
                        format!("{token}:type=jscookie")
                    } else {
                        token.clone()
                    };
                    resp.append_header(
                        "set-cookie",
                        format!("WAF-Token={token_cookie}; HttpOnly; {suffix}"),
                    )
                    .unwrap();
                }
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::from(body_html)), true)
                    .await?;
                Ok(true)
            }
        }
    }

    async fn run_lightweight_request_security(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<bool> {
        let client_ip = ctx.client_ip_str.clone();
        if self.enforce_uam(session, ctx, &client_ip).await? {
            return Ok(true);
        }

        let (site_server_id, user_plan_id, cc_base_clone) = {
            if let Some(server) = &ctx.server {
                let cc_clone = server
                    .web
                    .as_ref()
                    .and_then(|w| w.cc_policy.as_ref())
                    .cloned();
                (server.id.unwrap_or(0), server.user_plan_id, cc_clone)
            } else {
                (0, 0, None)
            }
        };

        if let Some(mut cc) = cc_base_clone {
            if user_plan_id > 0
                && let Some(pd) = self.config.get_plan_derived_sync(user_plan_id)
            {
                if pd.cc_max_qps > 0 {
                    cc.max_qps = pd.cc_max_qps;
                }
                if pd.cc_per_ip_max_qps > 0 {
                    cc.per_ip_max_qps = pd.cc_per_ip_max_qps;
                }
                if pd.cc_max_bandwidth > 0 {
                    cc.max_bandwidth = pd.cc_max_bandwidth as f64;
                }
            }
            if self
                .apply_cc_policy(session, ctx, &cc, site_server_id)
                .await?
            {
                return Ok(true);
            }
        }

        self.apply_global_cc_policy(session, ctx).await
    }

    fn inbound_waf_needs_request_body(
        ctx: &ProxyCTX,
        global_policies: &[crate::config_models::HTTPFirewallPolicy],
    ) -> bool {
        let site_needs_body = ctx
            .server
            .as_ref()
            .and_then(|server| {
                let web = server.web.as_ref()?;
                web.firewall_ref
                    .as_ref()
                    .filter(|firewall_ref| firewall_ref.is_on)?;
                let server_id = server.id?;
                ctx.compiled_plans.server_firewall.get(&server_id)
            })
            .map(|policy| crate::firewall::compiled::compiled_policy_uses_request_body(policy))
            .or_else(|| {
                ctx.server
                    .as_ref()
                    .and_then(|server| server.web.as_ref())
                    .and_then(|web| {
                        web.firewall_ref
                            .as_ref()
                            .filter(|firewall_ref| firewall_ref.is_on)
                            .and_then(|_| web.firewall_policy.as_ref())
                    })
                    .map(crate::firewall::inbound_policy_uses_request_body)
            })
            .unwrap_or(false);
        if site_needs_body {
            return true;
        }

        let global_rules_enabled = ctx
            .server
            .as_ref()
            .and_then(|server| server.web.as_ref())
            .and_then(|web| web.firewall_ref.as_ref())
            .is_some_and(|firewall_ref| firewall_ref.is_on && !firewall_ref.ignore_global_rules);
        if !global_rules_enabled {
            return false;
        }

        if ctx.compiled_plans.global_firewall.is_empty() {
            global_policies
                .iter()
                .any(crate::firewall::inbound_policy_uses_request_body)
        } else {
            ctx.compiled_plans
                .global_firewall
                .iter()
                .any(|policy| crate::firewall::compiled::compiled_policy_uses_request_body(policy))
        }
    }

    fn first_inbound_body_waf_policy<'a>(
        ctx: &'a ProxyCTX,
        global_policies: &'a [crate::config_models::HTTPFirewallPolicy],
    ) -> Option<&'a crate::config_models::HTTPFirewallPolicy> {
        let site_policy = ctx
            .server
            .as_ref()
            .and_then(|server| server.web.as_ref())
            .and_then(|web| {
                web.firewall_ref
                    .as_ref()
                    .filter(|firewall_ref| firewall_ref.is_on)
                    .and_then(|_| web.firewall_policy.as_ref())
            })
            .filter(|policy| {
                policy.is_on
                    && policy.mode != "bypass"
                    && crate::firewall::inbound_policy_uses_request_body(policy)
            });
        if site_policy.is_some() {
            return site_policy;
        }

        let global_rules_enabled = ctx
            .server
            .as_ref()
            .and_then(|server| server.web.as_ref())
            .and_then(|web| web.firewall_ref.as_ref())
            .is_some_and(|firewall_ref| firewall_ref.is_on && !firewall_ref.ignore_global_rules);
        if !global_rules_enabled {
            return None;
        }

        global_policies.iter().find(|policy| {
            policy.is_on
                && policy.mode != "bypass"
                && crate::firewall::inbound_policy_uses_request_body(policy)
        })
    }

    fn inbound_waf_body_buffer_limit(
        ctx: &ProxyCTX,
        global_policies: &[crate::config_models::HTTPFirewallPolicy],
    ) -> usize {
        const DEFAULT_LIMIT: usize = 2 * 1024 * 1024;
        let mut limit = DEFAULT_LIMIT;

        let mut apply_policy = |policy: &crate::config_models::HTTPFirewallPolicy| {
            if policy.is_on
                && policy.mode != "bypass"
                && crate::firewall::inbound_policy_uses_request_body(policy)
                && policy.max_request_body_size > 0
            {
                limit = limit.max(policy.max_request_body_size as usize);
            }
        };

        if let Some(web) = ctx.server.as_ref().and_then(|server| server.web.as_ref()) {
            if web
                .firewall_ref
                .as_ref()
                .is_some_and(|firewall_ref| firewall_ref.is_on)
            {
                if let Some(policy) = &web.firewall_policy {
                    apply_policy(policy);
                }
                if !web
                    .firewall_ref
                    .as_ref()
                    .is_some_and(|firewall_ref| firewall_ref.ignore_global_rules)
                {
                    for policy in global_policies {
                        apply_policy(policy);
                    }
                }
            }
        }

        limit
    }

    async fn buffer_request_body_for_waf(
        session: &mut Session,
        ctx: &mut ProxyCTX,
        limit: usize,
    ) -> Result<bool> {
        let content_length = session
            .get_header("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());
        if content_length.is_some_and(|len| len > limit) {
            return Ok(true);
        }
        if content_length == Some(0) {
            return Ok(false);
        }
        if content_length.is_none()
            && !session
                .get_header("transfer-encoding")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
            && matches!(
                session.req_header().method,
                http::Method::GET | http::Method::HEAD
            )
        {
            return Ok(false);
        }

        session.as_mut().enable_retry_buffering();
        let mut buffered = Vec::with_capacity(content_length.unwrap_or(0).min(limit));
        while let Some(chunk) = session.read_request_body().await? {
            if buffered.len().saturating_add(chunk.len()) > limit {
                return Ok(true);
            }
            buffered.extend_from_slice(&chunk);
            if content_length.is_some_and(|len| buffered.len() >= len) {
                break;
            }
        }
        crate::metrics::METRICS
            .waf
            .record_request_body_buffer(buffered.len());
        ctx.request_body.set(buffered);
        Ok(false)
    }

    fn request_body_too_large_action(
        policy: &crate::config_models::HTTPFirewallPolicy,
    ) -> crate::firewall::MatchedAction {
        let mut action = crate::firewall::MatchedAction {
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
            max_fails: None,
            fail_block_timeout: None,
            fail_global: None,
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
            chained_actions: vec![],
            observe_only: false,
        };
        crate::firewall::apply_observe_mode(policy, &mut action);
        action
    }

    fn evaluate_site_inbound_waf_compiled_first(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        server: &ServerConfig,
        policy: &crate::config_models::HTTPFirewallPolicy,
    ) -> Option<crate::firewall::MatchedAction> {
        if !policy.is_on || policy.mode == "bypass" {
            return None;
        }
        self.record_candidate_waf_sample(session, ctx, policy, Some(server));
        let compiled_policy = server
            .id
            .and_then(|id| ctx.compiled_plans.server_firewall.get(&id));

        if let Some(inbound) = &policy.inbound
            && let Some(region) = &inbound.region
        {
            let ua = session
                .get_header("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let region_match = if let Some(compiled_policy) = compiled_policy {
                crate::firewall::compiled::evaluate_compiled_region_deny(
                    compiled_policy,
                    ctx.client_ip,
                    ua,
                    session.req_header().uri.path(),
                )
            } else {
                let mut action = crate::firewall::check_region_deny(
                    region,
                    ctx.client_ip,
                    policy.id,
                    &policy.deny_country_html,
                    ua,
                    session.req_header().uri.path(),
                );
                if let Some(action) = &mut action {
                    crate::firewall::apply_observe_mode(policy, action);
                }
                action
            };
            if region_match.is_some() {
                return region_match;
            }
        }

        if policy.max_request_body_size > 0 {
            let content_length = session
                .get_header("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if content_length > policy.max_request_body_size
                || (ctx.request_body.len() as i64) > policy.max_request_body_size
            {
                return Some(Self::request_body_too_large_action(policy));
            }
        }

        if let Some(compiled_policy) = compiled_policy {
            crate::firewall::compiled::evaluate_compiled_policy_with_server(
                compiled_policy,
                session,
                &ctx.request_body,
                Self::forwarded_proto(session, ctx),
                Some(server),
            )
        } else {
            crate::metrics::METRICS.waf.record_legacy_fallback();
            crate::firewall::evaluate_policy_with_server(
                policy,
                session,
                &ctx.request_body,
                Self::forwarded_proto(session, ctx),
                Some(server),
            )
        }
    }

    fn evaluate_global_inbound_waf_compiled_first(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        global_policies: &[crate::config_models::HTTPFirewallPolicy],
    ) -> Option<crate::firewall::MatchedAction> {
        for policy in global_policies
            .iter()
            .filter(|policy| policy.is_on && policy.mode != "bypass")
        {
            self.record_candidate_waf_sample(session, ctx, policy, None);
        }

        for compiled_policy in &ctx.compiled_plans.global_firewall {
            let ua = session
                .get_header("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if let Some(action) = crate::firewall::compiled::evaluate_compiled_region_deny(
                compiled_policy,
                ctx.client_ip,
                ua,
                session.req_header().uri.path(),
            ) {
                return Some(action);
            }
            if let Some(action) = crate::firewall::compiled::evaluate_compiled_policy(
                compiled_policy,
                session,
                &ctx.request_body,
                Self::forwarded_proto(session, ctx),
            ) {
                return Some(action);
            }
        }
        if !ctx.compiled_plans.global_firewall.is_empty() {
            return None;
        }

        crate::metrics::METRICS.waf.record_legacy_fallback();
        for gp in global_policies {
            if gp.is_on && gp.mode != "bypass" {
                if let Some(inbound) = &gp.inbound
                    && let Some(region) = &inbound.region
                {
                    let ua = session
                        .get_header("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let mut action = crate::firewall::check_region_deny(
                        region,
                        ctx.client_ip,
                        gp.id,
                        &gp.deny_country_html,
                        ua,
                        session.req_header().uri.path(),
                    );
                    if let Some(action) = &mut action {
                        crate::firewall::apply_observe_mode(gp, action);
                    }
                    if action.is_some() {
                        return action;
                    }
                }
                if let Some(action) = crate::firewall::evaluate_policy(
                    gp,
                    session,
                    &ctx.request_body,
                    Self::forwarded_proto(session, ctx),
                ) {
                    return Some(action);
                }
            }
        }
        None
    }

    fn record_candidate_waf_sample(
        &self,
        session: &Session,
        ctx: &ProxyCTX,
        policy: &crate::config_models::HTTPFirewallPolicy,
        server: Option<&ServerConfig>,
    ) {
        let (candidate_rules, Some(version)) =
            crate::firewall::pick_ruleset(policy, ctx.client_ip, session.req_header().uri.path())
        else {
            return;
        };
        if candidate_rules.is_empty() {
            return;
        }
        let matched = candidate_rules.iter().any(|rule| {
            crate::firewall::matcher_plus::match_rule_with_server(
                rule,
                session,
                &ctx.request_body,
                Self::forwarded_proto(session, ctx),
                server,
            )
        });
        if matched {
            let observed = policy.mode == "observe";
            let blocked = !observed;
            self.waf_state
                .record_candidate_hit(policy.id, version, blocked, observed);
        }
    }

    /// Request-body WAF checks deferred to cache-miss path. See request_filter for rationale.
    async fn run_miss_only_body_waf(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        global_policies: &[crate::config_models::HTTPFirewallPolicy],
    ) -> Result<(bool, Option<String>)> {
        let mut waf_action: Option<String> = None;
        if ctx.waf_whitelisted {
            if self.enforce_plan_max_upload(session, ctx).await? {
                return Ok((true, None));
            }
            return Ok((false, waf_action));
        }

        // NOTE: Empty Connection Flood, TLS Exhaustion, and SYN Flood are
        // connection-level attacks. By the time request_filter runs, a complete
        // HTTP request has been received — counting requests here incorrectly
        // blocks legitimate traffic (e.g. 10+ requests/min triggers ECF).
        // These defenses belong at the TCP connection accept layer.

        let mut waf_match: Option<crate::firewall::MatchedAction> = None;
        let request_body_needed = Self::inbound_waf_needs_request_body(ctx, global_policies);

        if request_body_needed && ctx.request_body.is_empty() {
            if ctx.request_body_waf_permit.is_none() {
                let Some(permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::RequestBodyWaf) else {
                    ctx.response_status = 503;
                    ctx.errors
                        .get_or_insert_with(Vec::new)
                        .push("request body WAF memory admission rejected".to_string());
                    self.respond_status_with_pages(session, ctx, 503).await?;
                    return Ok((true, Some("request_body_waf_overloaded".to_string())));
                };
                ctx.request_body_waf_permit = Some(permit);
            }
            let body_limit = Self::inbound_waf_body_buffer_limit(ctx, global_policies);
            if Self::buffer_request_body_for_waf(session, ctx, body_limit).await?
                && let Some(policy) = Self::first_inbound_body_waf_policy(ctx, global_policies)
            {
                waf_match = Some(Self::request_body_too_large_action(policy));
            }
        }

        if self.enforce_plan_max_upload(session, ctx).await? {
            return Ok((true, None));
        }

        if let Some(server) = &ctx.server
            && let Some(web) = &server.web
            && let Some(firewall_ref) = &web.firewall_ref
            && firewall_ref.is_on
        {
            if let Some(policy) = &web.firewall_policy {
                waf_match =
                    self.evaluate_site_inbound_waf_compiled_first(session, ctx, server, policy);
                if let Some(action) = &mut waf_match {
                    Self::apply_site_default_captcha_type(
                        action,
                        Some(firewall_ref),
                        Self::inherited_global_captcha_options(global_policies),
                    );
                }
            }
            if waf_match.is_none() && !firewall_ref.ignore_global_rules {
                waf_match =
                    self.evaluate_global_inbound_waf_compiled_first(session, ctx, global_policies);
            }
        }

        if let Some(matched) = waf_match {
            ctx.waf_policy_id = matched.policy_id;
            ctx.waf_group_id = matched.group_id;
            ctx.waf_set_id = matched.set_id;
            waf_action = Some(matched.action_code.clone());
            ctx.waf_action = waf_action.clone();
            self.maybe_report_firewall_event(
                session,
                ctx,
                matched.policy_id,
                matched.group_id,
                matched.set_id,
            );

            if matched.observe_only {
                // In observe mode: still run non-blocking chained actions
                // (log / tag / notify / record_ip_white / record_ip_gray)
                // but skip actions with blocking side-effects.
                let actions_to_run: &[_] = if matched.chained_actions.is_empty() {
                    std::slice::from_ref(&matched)
                } else {
                    &matched.chained_actions
                };
                for action in actions_to_run {
                    if !crate::firewall::is_blocking_action_code(&action.action_code) {
                        self.apply_waf_runtime_action(session, ctx, action);
                    }
                }
                return Ok((false, waf_action));
            }

            let ua = session
                .get_header("user-agent")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if self.waf_pass_cookie_verified_for_action(session, &matched, &ctx.client_ip_str, ua) {
                return Ok((false, waf_action));
            }

            if matched.chained_actions.is_empty() {
                self.apply_waf_runtime_action(session, ctx, &matched);
            } else {
                for action in &matched.chained_actions {
                    self.apply_waf_runtime_action(session, ctx, action);
                }
            }

            if matches!(
                matched.action_code.as_str(),
                "record_ip_white" | "record_ip_gray" | "tag" | "log" | "notify" | "allow"
            ) {
                return Ok((false, waf_action));
            }

            if self
                .respond_waf_action(session, ctx, matched, ctx.client_ip_str.clone())
                .await?
            {
                return Ok((true, waf_action));
            }
        }

        Ok((false, waf_action))
    }

    async fn run_request_context_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::Context;
        let host = Self::request_host(session);
        ctx.host = host.clone();
        ctx.is_tls_downstream = self.tls_downstream;
        ctx.is_http3_downstream = session.req_header().version == http::Version::HTTP_3;
        normalize_upstream_cookie_headers(session.req_header_mut());

        let (hot_path, server, upstream) = self.config.get_request_context_sync(&host);
        debug!(
            "REQUEST_FILTER: method={} host='{}' server_found={} lb_found={} uri='{}'",
            session.req_header().method,
            host,
            server.is_some(),
            upstream.is_some(),
            session.req_header().uri
        );
        ctx.server = server;
        if let Some(s) = ctx.server.as_ref()
            && !s.locations.is_empty()
        {
            let server_id = s.id.unwrap_or(0);
            let compiled =
                crate::routing::location::get_compiled_locations(server_id, &s.locations);
            let path = session.req_header().uri.path();
            if let Some(matched) = crate::routing::location::match_location(&compiled, path) {
                ctx.matched_location = Some(matched.config.clone());
            }
        }
        ctx.lb = upstream;
        if let Some(server_id) = ctx.server.as_ref().map(|server| server.numeric_id())
            && let Some(location_lb) =
                self.build_location_lb_if_configured(server_id, ctx.matched_location.as_deref())
        {
            ctx.lb = Some(location_lb);
        }

        ctx.global_http_config = Some(Arc::clone(&hot_path.global_http));
        ctx.firewall_policies_snapshot = Some(Arc::clone(&hot_path.firewall_policies));
        ctx.global_cache_policies = hot_path.cache_policies.clone();
        ctx.compiled_plans = Arc::clone(&hot_path.compiled_plans);
        ctx.global_access_log_config = hot_path.global_access_log.clone();
        ctx.global_waf_block_options = hot_path.global_waf_block_options.clone();
        ctx.access_log_module_enabled = true;
        ctx.global_access_log_on = ctx
            .global_access_log_config
            .as_ref()
            .map(|cfg| cfg.is_on)
            .unwrap_or(true);

        if self.maybe_serve_acme_challenge(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }

        let is_loopback = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|i| i.ip().is_loopback())
            .unwrap_or(false);
        ctx.is_loopback = is_loopback;

        let (mut detected_ip, detected_port, raw_remote_addr) = Self::socket_client_ip(session);
        ctx.client_ip = detected_ip;
        ctx.client_port = detected_port;
        ctx.raw_remote_addr = raw_remote_addr;

        if is_loopback {
            ctx.is_http3_bridge = session.get_header("X-Cloud-Http3-Bridge").is_some();

            if let Some(cloud_ip) = session.get_header("X-Cloud-Real-Ip")
                && let Ok(ip_str) = cloud_ip.to_str()
                && let Ok(parsed_ip) = ip_str.parse::<std::net::IpAddr>()
            {
                debug!("L2: Restoring real client IP {} from L1 header", parsed_ip);
                detected_ip = parsed_ip;
                ctx.client_ip = parsed_ip;
            }
            if let Some(cloud_port) = session.get_header("X-Cloud-Real-Port")
                && let Ok(port_str) = cloud_port.to_str()
                && let Ok(port) = port_str.parse::<u16>()
            {
                ctx.client_port = port;
            }
        }

        if let Some(pp_ip) = ctx.proxy_protocol_ip {
            detected_ip = pp_ip;
            ctx.client_ip = pp_ip;
        }

        ctx.client_ip = self.resolve_client_ip(
            session,
            ctx.server.as_ref().map(|v| &**v),
            detected_ip,
            &ctx.raw_remote_addr,
            ctx.client_port,
        );
        ctx.client_ip_str = ctx.client_ip.to_string();
        ctx.request_id = crate::logging::next_request_id();
        self.ensure_request_metrics_started(ctx);

        Ok(PhaseOutcome::Continue(RequestFilterState {
            host,
            hot_path,
        }))
    }

    async fn run_local_service_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::LocalService;
        ctx.is_on = state.hot_path.is_on;
        if !ctx.is_on {
            debug!(
                "BLOCKED: Node is DISABLED (isOn=false), rejecting {} {} from IP={}",
                session.req_header().method,
                session.req_header().uri,
                ctx.client_ip_str
            );
            return self
                .respond_status_with_pages(session, ctx, 403)
                .await
                .map(PhaseOutcome::Done);
        }

        if self.maybe_serve_hls_key(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }

        if self.maybe_serve_waf_verify(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }

        Ok(PhaseOutcome::Continue(state))
    }

    async fn run_protocol_policy_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::ProtocolPolicy;
        if let Some(server) = &ctx.server {
            if let Some(web) = &server.web
                && let Some(ws) = &web.websocket
                && ws.is_on
                && Self::is_websocket_request(session)
            {
                if let Some(origin) = session.get_header("origin").and_then(|v| v.to_str().ok())
                    && let Some(origin_host) = Self::origin_header_host(origin)
                {
                    let same_origin = crate::lb_factory::strip_addr_port(origin_host)
                        .eq_ignore_ascii_case(&crate::lb_factory::strip_addr_port(&state.host));
                    let origin_allowed = server
                        .id
                        .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
                        .and_then(|plan| plan.websocket_origin_allowed(origin_host))
                        .unwrap_or_else(|| Self::websocket_origin_allowed(ws, origin_host));
                    if !same_origin && !origin_allowed {
                        return self
                            .respond_status_with_pages(session, ctx, 403)
                            .await
                            .map(PhaseOutcome::Done);
                    }
                }
                ctx.is_websocket = true;
            }
            if let Some(grpc) = &server.grpc {
                ctx.is_grpc = grpc.is_on && Self::is_grpc_request(session);
            }

            if ctx.is_grpc {
                let max_recv = state
                    .hot_path
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
                ctx.max_inspection_size = final_max_recv;
                debug!(
                    "gRPC enabled for request, setting max_inspection_size to {} bytes",
                    final_max_recv
                );
            }

            if let Some(web) = &server.web {
                ctx.access_log_ref = web.access_log_ref.clone();
            }
        }

        if !state.hot_path.global_http.supports_low_version_http
            && session.req_header().version < pingora_http::Version::HTTP_11
        {
            debug!(
                "Blocking low version HTTP request: {:?}",
                session.req_header().version
            );
            return self
                .respond_status_with_pages(session, ctx, 400)
                .await
                .map(PhaseOutcome::Done);
        }

        if ctx.server.is_none() {
            if tracing::enabled!(tracing::Level::DEBUG) {
                debug!(
                    "Unbound domain for host: '{}'. Bound hosts: {:?}",
                    state.host,
                    self.config.get_all_hosts_sync()
                );
            }
            return self
                .respond_domain_mismatch(session, ctx, &state.hot_path, &state.host)
                .await
                .map(PhaseOutcome::Done);
        }

        Ok(PhaseOutcome::Continue(state))
    }

    async fn run_early_response_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::EarlyResponse;
        if let Some(server) = ctx.server.clone()
            && let Some(ref web) = server.web
        {
            if let Some((location, status)) =
                self.should_redirect_to_https(session, ctx, &server, &state.host)
            {
                let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                Self::insert_location_header(&mut resp, &location);
                session.write_response_header(Box::new(resp), true).await?;
                ctx.response_status = status;
                return Ok(PhaseOutcome::Done(true));
            }

            if let Some(location) = Self::www_trailing_slash_redirect(&server, session, &state.host)
            {
                let mut resp = pingora_http::ResponseHeader::build(301u16, None).unwrap();
                Self::insert_location_header(&mut resp, &location);
                session.write_response_header(Box::new(resp), true).await?;
                ctx.response_status = 301;
                return Ok(PhaseOutcome::Done(true));
            }

            if let Some(plan) = server
                .id
                .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
                .and_then(|plan| plan.shutdown())
                .cloned()
            {
                if self.respond_compiled_shutdown(session, ctx, &plan).await? {
                    return Ok(PhaseOutcome::Done(true));
                }
            } else if let Some(ref shutdown) = web.shutdown
                && self.respond_shutdown(session, ctx, shutdown).await?
            {
                return Ok(PhaseOutcome::Done(true));
            }

            let is_options = session.req_header().method == http::method::Method::OPTIONS;
            let compiled_cors = server
                .id
                .and_then(|server_id| ctx.compiled_plans.server_headers.get(&server_id))
                .and_then(|plan| plan.cors.as_ref());
            if let Some(cors) = compiled_cors {
                if is_options && cors.applies_to_request(true) {
                    let mut resp = pingora_http::ResponseHeader::build(204, None).unwrap();
                    cors.apply(&mut resp, session);
                    resp.remove_header("content-length");
                    resp.remove_header("transfer-encoding");
                    session.write_response_header(Box::new(resp), true).await?;
                    ctx.response_status = 204;
                    return Ok(PhaseOutcome::Done(true));
                }
            } else if let Some(ref rhp) = web.response_header_policy
                && let Some(ref cors) = rhp.cors
                && cors.is_on
                && (!cors.options_method_only || is_options)
                && is_options
            {
                let mut resp = pingora_http::ResponseHeader::build(204, None).unwrap();
                Self::set_cors_headers(&mut resp, session, cors);
                resp.remove_header("content-length");
                resp.remove_header("transfer-encoding");
                session.write_response_header(Box::new(resp), true).await?;
                ctx.response_status = 204;
                return Ok(PhaseOutcome::Done(true));
            }
        }

        if ctx.lb.is_none()
            && let Some(server) = &ctx.server
        {
            debug!(
                "LB missing for host '{}'; scheduling background rebuild and returning 502 for this request.",
                state.host
            );
            let (level, parents) = self.config.get_tiered_origin_info().await;
            let bypass = self.config.is_tiered_origin_bypass().await;

            let rp_cfg = match ctx
                .matched_location
                .as_ref()
                .and_then(|l| l.reverse_proxy.clone())
                .or_else(|| server.reverse_proxy.clone())
            {
                Some(rp) => rp,
                None => {
                    session.respond_error(502).await?;
                    return Ok(PhaseOutcome::Done(true));
                }
            };

            let server_id = server.numeric_id();
            let config = self.config.clone();
            let host_c = state.host.clone();
            let server_c = server.clone();
            let allow_lan_ip = state.hot_path.global_http.allow_lan_ip;
            tokio::spawn(async move {
                let built = tokio::task::spawn_blocking(move || {
                    crate::lb_factory::build_lb(
                        server_id,
                        &rp_cfg,
                        level,
                        parents.as_ref(),
                        bypass,
                        allow_lan_ip,
                    )
                })
                .await;
                if let Ok((lb_arc, _has_hc)) = built {
                    config.cache_server_route(host_c, server_c, lb_arc).await;
                }
            });
            session.respond_error(502).await?;
            return Ok(PhaseOutcome::Done(true));
        }

        Ok(PhaseOutcome::Continue(state))
    }

    async fn run_security_state_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::SecurityState;
        let waf_enabled = ctx
            .server
            .as_ref()
            .and_then(|server| server.web.as_ref())
            .and_then(|web| web.firewall_ref.as_ref())
            .is_some_and(|firewall_ref| firewall_ref.is_on);
        if waf_enabled
            && self.waf_state.is_whitelisted(
                ctx.client_ip,
                ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
            )
        {
            ctx.waf_whitelisted = true;
        }

        if self.waf_state.is_graylisted(
            ctx.client_ip,
            ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
        ) {
            Self::add_ctx_tag(ctx, "graylist");
        }

        let ua = session
            .get_header("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let client_ip_str = ctx.client_ip_str.clone();
        if self.check_waf_challenge(session, &client_ip_str, ua, ctx) {
            return Ok(PhaseOutcome::Done(false));
        }

        self.ensure_request_metrics_started(ctx);
        Ok(PhaseOutcome::Continue(state))
    }

    async fn run_limits_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::Limits;
        let full_url = Self::request_full_url(session, ctx);
        if self.config.is_deleted_content_exact_sync(&full_url) {
            debug!(
                "Deleted content matched exact URL, returning 451: server_id={} url={}",
                ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                full_url
            );
            return self
                .respond_status_with_pages(session, ctx, 451)
                .await
                .map(PhaseOutcome::Done);
        }

        if self.enforce_request_limit(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }
        if self.enforce_traffic_limit(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }
        if self.enforce_plan_max_upload(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }

        if !ctx.waf_whitelisted
            && self.waf_state.is_blocked(
                ctx.client_ip,
                ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
            )
        {
            debug!(
                "BLOCKED: IP {} is blocked by WAF state (host={}, method={}, uri={})",
                ctx.client_ip_str,
                state.host,
                session.req_header().method,
                session.req_header().uri
            );
            return self
                .respond_status_with_pages(session, ctx, 403)
                .await
                .map(PhaseOutcome::Done);
        }

        let main_cluster_id = self.config.get_node_cluster_id_sync();
        if !ctx.waf_whitelisted
            && main_cluster_id > 0
            && self.waf_state.is_blocked(
                ctx.client_ip,
                crate::special_defense::cluster_block_scope_id(main_cluster_id),
            )
        {
            debug!(
                "BLOCKED: IP {} is blocked by main cluster WAF state (cluster_id={}, host={}, method={}, uri={})",
                ctx.client_ip_str,
                main_cluster_id,
                state.host,
                session.req_header().method,
                session.req_header().uri
            );
            return self
                .respond_status_with_pages(session, ctx, 403)
                .await
                .map(PhaseOutcome::Done);
        }

        Ok(PhaseOutcome::Continue(state))
    }

    async fn run_lightweight_waf_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::LightweightWaf;
        if self.run_lightweight_request_security(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }
        Ok(PhaseOutcome::Continue(state))
    }

    async fn run_body_waf_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::BodyWaf;
        let (blocked, _action) = self
            .run_miss_only_body_waf(session, ctx, &state.hot_path.firewall_policies)
            .await?;
        if blocked {
            return Ok(PhaseOutcome::Done(true));
        }
        Ok(PhaseOutcome::Continue(state))
    }

    async fn run_feature_policy_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::FeaturePolicy;
        if self.enforce_referers(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }
        if self.enforce_user_agent(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }
        if self.enforce_auth(session, ctx).await? {
            return Ok(PhaseOutcome::Done(true));
        }
        Ok(PhaseOutcome::Continue(state))
    }

    async fn run_rewrite_phase(
        &self,
        session: &mut Session,
        ctx: &mut ProxyCTX,
        state: RequestFilterState,
    ) -> Result<PhaseOutcome<RequestFilterState>> {
        ctx.request_phase = RequestPhase::Rewrite;
        if let Some(server) = &ctx.server
            && let Some(web) = &server.web
        {
            let host_redirects = &web.host_redirects;
            let rewrite_refs = &web.rewrite_refs;
            let rewrite_rules = &web.rewrite_rules;

            let uri_str = session.req_header().uri.path();
            let query = session.req_header().uri.query().unwrap_or("");

            if !host_redirects.is_empty() {
                let redirect_host = if state.host.is_empty() {
                    Self::request_host(session)
                } else {
                    state.host.clone()
                };
                let user_agent = session
                    .get_header("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let scheme = Self::forwarded_proto(session, ctx);
                let compiled_plan = server
                    .id
                    .and_then(|server_id| ctx.compiled_plans.server_rewrite.get(&server_id));
                let redirect = if let Some(plan) = compiled_plan {
                    crate::rewrite::evaluate_compiled_host_redirects(
                        &redirect_host,
                        scheme,
                        uri_str,
                        query,
                        user_agent,
                        plan,
                    )
                } else {
                    evaluate_host_redirects(
                        &redirect_host,
                        scheme,
                        uri_str,
                        query,
                        user_agent,
                        host_redirects,
                    )
                };
                if let Some((location, status)) = redirect {
                    let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                    Self::insert_location_header(&mut resp, &location);
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(PhaseOutcome::Done(true));
                }
            }

            if !rewrite_rules.is_empty() {
                let scheme = Self::forwarded_proto(session, ctx);
                let rewrite_result = server
                    .id
                    .and_then(|server_id| ctx.compiled_plans.server_rewrite.get(&server_id))
                    .map(|plan| {
                        crate::rewrite::evaluate_compiled_rewrites(
                            uri_str,
                            query,
                            Some(&state.host),
                            plan,
                            session,
                            scheme,
                        )
                    })
                    .unwrap_or_else(|| {
                        evaluate_rewrites_with_cond(
                            uri_str,
                            query,
                            Some(&state.host),
                            rewrite_refs,
                            rewrite_rules,
                            |rule| {
                                rule.conds
                                    .as_ref()
                                    .map(|conds| conds.match_request_with_scheme(session, scheme))
                                    .unwrap_or(true)
                            },
                        )
                    });
                match rewrite_result {
                    RewriteResult::Redirect {
                        location,
                        status,
                        rewrite_id,
                    } => {
                        ctx.rewrite_id = rewrite_id;
                        ctx.tags
                            .get_or_insert_with(Vec::new)
                            .push("rewrite".to_string());
                        let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                        Self::insert_location_header(&mut resp, &location);
                        session.write_response_header(Box::new(resp), true).await?;
                        return Ok(PhaseOutcome::Done(true));
                    }
                    RewriteResult::Proxy {
                        new_uri,
                        proxy_host,
                        rewrite_id,
                    } => {
                        ctx.rewrite_id = rewrite_id;
                        ctx.tags
                            .get_or_insert_with(Vec::new)
                            .push("rewrite".to_string());
                        let preserve_original_host = proxy_host.is_none();
                        if let Ok(new_parsed) = new_uri.parse::<http::Uri>() {
                            session.req_header_mut().set_uri(new_parsed);
                            if preserve_original_host && !ctx.host.is_empty() {
                                session
                                    .req_header_mut()
                                    .insert_header("host", ctx.host.clone())
                                    .unwrap();
                            }
                        }
                        if let Some(host) = proxy_host {
                            ctx.origin_host = host;
                        }
                    }
                    RewriteResult::NoMatch => {}
                }
            }
        }

        Ok(PhaseOutcome::Continue(state))
    }
}

#[async_trait]
impl ProxyHttp for EdgeProxy {
    type CTX = ProxyCTX;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCTX::default()
    }

    async fn downstream_request_parse_error(
        &self,
        session: &mut pingora_core::protocols::http::ServerSession,
        error: &Error,
        _ctx: &mut Self::CTX,
    ) -> DownstreamParseErrorAction {
        let (reason, defense) = Self::classify_downstream_parse_error(error);
        if matches!(error.etype(), ReadTimedout) {
            let (ip, _, raw_addr) = Self::http_session_socket_client_ip(session);
            let node_id = self.api_config.node_id.parse::<i64>().unwrap_or(0);
            crate::l4_defense::record_l4_event(
                &self.config,
                &self.waf_state,
                node_id,
                ip,
                crate::l4_defense::L4DefenseKind::HttpSlowHeader,
                format!("peer={} reason={}", raw_addr, reason),
            );
            return DownstreamParseErrorAction {
                respond_status: None,
                log_level: DownstreamParseErrorLogLevel::Debug,
                reason,
            };
        }
        if matches!(error.etype(), InvalidHTTPHeader) {
            let (ip, _, _) = Self::http_session_socket_client_ip(session);
            self.record_malformed_http_defense(defense, ip);
            return DownstreamParseErrorAction {
                respond_status: Some(400),
                log_level: DownstreamParseErrorLogLevel::Debug,
                reason,
            };
        }
        DownstreamParseErrorAction {
            respond_status: None,
            log_level: DownstreamParseErrorLogLevel::Debug,
            reason,
        }
    }

    async fn early_request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        let global_http = self.config.get_global_http_config_sync();
        let read_timeout = global_http
            .auto_read_timeout
            .as_ref()
            .and_then(crate::utils::non_zero_duration);
        let write_timeout = global_http
            .auto_write_timeout
            .as_ref()
            .and_then(crate::utils::non_zero_duration);
        if read_timeout.is_some() {
            session.as_mut().set_read_timeout(read_timeout);
        }
        if write_timeout.is_some() {
            session.as_mut().set_write_timeout(write_timeout);
        }
        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let mut state = match self.run_request_context_phase(session, ctx).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        state = match self.run_local_service_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        state = match self.run_protocol_policy_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        state = match self.run_early_response_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        state = match self.run_security_state_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        state = match self.run_limits_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        state = match self.run_lightweight_waf_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        state = match self.run_body_waf_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        state = match self.run_feature_policy_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };
        let _state = match self.run_rewrite_phase(session, ctx, state).await? {
            PhaseOutcome::Continue(state) => state,
            PhaseOutcome::Done(done) => return Ok(done),
        };

        ctx.request_phase = RequestPhase::Proxy;
        Ok(false)
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut e: Box<Error>,
    ) -> Box<Error> {
        crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(ctx.origin_id);
        ctx.upstream_retries = ctx.upstream_retries.saturating_add(1);
        e.set_retry(ctx.upstream_retries < 2);
        e
    }

    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        if ctx.origin_connect_permit.is_some() {
            return Ok(true);
        }

        if let Some(permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::OriginConnect) {
            ctx.origin_connect_permit = Some(permit);
            return Ok(true);
        }

        ctx.response_status = 503;
        ctx.origin_status = 0;
        ctx.errors
            .get_or_insert_with(Vec::new)
            .push("origin connect memory admission rejected".to_string());
        let _ = session
            .cache
            .disable(pingora_cache::NoCacheReason::Custom("OriginMemoryPressure"));
        self.respond_status_with_pages(session, ctx, 503).await?;
        Ok(false)
    }

    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        _reused: bool,
        _peer: &HttpPeer,
        #[cfg(unix)] _fd: std::os::unix::io::RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        _digest: Option<&pingora_core::protocols::Digest>,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        ctx.origin_connect_permit.take();
        Ok(())
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        let is_upstream_http_status =
            matches!(e.esource(), ErrorSource::Upstream) && matches!(e.etype(), HTTPStatus(_));
        let code = match e.etype() {
            HTTPStatus(code) => *code,
            ConnectTimedout | ReadTimedout | WriteTimedout => 504,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    WriteError | ReadError | ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };

        Self::record_access_log_error(ctx, e, (code > 0).then_some(code));

        if matches!(e.esource(), ErrorSource::Upstream) && (code == 0 || code >= 500) {
            crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(ctx.origin_id);
        }

        if code > 0 {
            ctx.response_status = code;
            if is_upstream_http_status {
                ctx.origin_status = code as i32;
                debug!(
                    "ACCESS_LOG: fail_to_proxy preserved upstream origin_status={}",
                    ctx.origin_status
                );
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
                debug!("failed to send error response to downstream: {}", write_err);
            }
        }

        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    fn should_serve_stale(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
        error: Option<&Error>,
    ) -> bool {
        if ctx.cache_ref.is_none() {
            return false;
        }

        // Check stale-while-revalidate: if the entry is expired but still inside the
        // SWR window, serve stale regardless of error status and trigger a background
        // refresh (thundering-herd protected by SWR_REVALIDATE_IN_FLIGHT).
        if let Some(cache_key) = &ctx.cache_key {
            let hash = format!("{:x}", md5_legacy::compute(cache_key.as_bytes()));
            if let Some(meta) = crate::metrics::storage::STORAGE.get_cache_meta(&hash) {
                let now = crate::utils::time::now_timestamp();
                // Entry is expired but within the SWR window?
                if meta.expires < now
                    && meta.stale_while_revalidate_secs > 0
                    && now < meta.expires + meta.stale_while_revalidate_secs as i64
                {
                    if MEMORY_GOVERNOR.is_memory_pressure_high()
                        || crate::origin_state::ORIGIN_STATE_MANAGER.is_down(ctx.origin_id)
                    {
                        return true;
                    }
                    // Global cap on in-flight revalidations to prevent
                    // amplification: unique cache keys × 1 task each could
                    // otherwise exhaust memory / fds.
                    if SWR_REVALIDATE_IN_FLIGHT.len() < SWR_REVALIDATE_INFLIGHT_MAX
                        && SWR_REVALIDATE_IN_FLIGHT
                            .insert(cache_key.clone(), ())
                            .is_none()
                    {
                        let Some(revalidate_permit) =
                            MEMORY_GOVERNOR.try_admit(AdmissionClass::CacheRevalidate)
                        else {
                            SWR_REVALIDATE_IN_FLIGHT.remove(cache_key);
                            return true;
                        };
                        // origin_host may not yet be set in cache-hit paths
                        // (upstream_peer hasn't run). Skip background refresh
                        // instead of issuing a GET to an empty host.
                        if !ctx.origin_host.is_empty() {
                            let origin_url = format!(
                                "{}://{}{}",
                                if ctx.is_tls_downstream {
                                    "https"
                                } else {
                                    "http"
                                },
                                ctx.origin_host,
                                _session
                                    .req_header()
                                    .uri
                                    .path_and_query()
                                    .map(|pq| pq.as_str())
                                    .unwrap_or("/")
                            );
                            let cache_key_owned = cache_key.clone();
                            tokio::spawn(async move {
                                let _revalidate_permit = revalidate_permit;
                                // Reuse the shared client so DNS/TLS state and
                                // the connection pool are amortized across all
                                // SWR background refreshes.
                                let _ = SWR_REVALIDATE_CLIENT
                                    .get(&origin_url)
                                    .header("X-SWR-Revalidate", "1")
                                    .send()
                                    .await;
                                SWR_REVALIDATE_IN_FLIGHT.remove(&cache_key_owned);
                            });
                        } else {
                            // Origin not yet known; release the in-flight slot.
                            drop(revalidate_permit);
                            SWR_REVALIDATE_IN_FLIGHT.remove(cache_key);
                        }
                    }
                    return true;
                }
            }
        }

        match error {
            None => true,
            Some(err) if err.esource() != &ErrorSource::Upstream => false,
            Some(err) => match err.etype() {
                HTTPStatus(502 | 503 | 504) => true,
                HTTPStatus(code) => *code == 0,
                _ => true,
            },
        }
    }

    fn suppress_error_log(&self, _session: &Session, _ctx: &Self::CTX, e: &Error) -> bool {
        if Self::is_access_log_only_proxy_error(e) {
            return true;
        }

        match e.etype() {
            // Silence common downstream disconnection errors to reduce log noise during load tests
            pingora::ErrorType::WriteError
            | pingora::ErrorType::ReadError
            | pingora::ErrorType::ConnectionClosed => {
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
        let (node_level, force_ln, bypass_l2, ln_by_url_mapping, node_cluster_id) =
            if ctx.waf_deferred {
                let (node_level, force_ln, bypass_l2, ln_by_url_mapping, node_cluster_id, _) = self
                    .config
                    .get_upstream_peer_context_with_firewall_policies_sync();
                (
                    node_level,
                    force_ln,
                    bypass_l2,
                    ln_by_url_mapping,
                    node_cluster_id,
                )
            } else {
                self.config.get_upstream_peer_context_sync()
            };
        ctx.node_level = node_level;

        let mut target_peer = None;

        // --- TIERED ORIGIN (L1 -> L2) LOGIC ---
        if node_level == 1 && !bypass_l2 && (force_ln || ctx.cache_ref.is_some()) {
            if ctx.server.is_some() {
                // Find cluster-specific Parent LB
                if let Some(parent_lb) = self.config.get_parent_upstream_sync(node_cluster_id) {
                    let hash_key = if ln_by_url_mapping {
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
                                ctx.upstream_is_parent = true;
                                target_peer = Some(second_peer.clone());
                            } else {
                                ctx.upstream_is_parent = true;
                                target_peer = Some(peer.clone());
                            }
                        } else {
                            debug!(
                                "Selected L2 upstream: {} (Method: {}, Pressure: {:.2}) for host: {}",
                                peer_addr,
                                if ln_by_url_mapping {
                                    "urlMapping"
                                } else {
                                    "random"
                                },
                                pressure,
                                session.req_header().uri.host().unwrap_or("")
                            );
                            ctx.upstream_is_parent = true;
                            target_peer = Some(peer.clone());
                        }
                    }
                } else {
                    let available_keys = self.config.get_parent_route_keys_sync();
                    debug!(
                        "No parent LB for cluster_id={}. Available cluster keys: {:?}. Falling back to origin.",
                        node_cluster_id, available_keys
                    );
                }
            }
        }

        // --- FALLBACK TO ORIGIN LB ---
        if target_peer.is_none() {
            if let Some(lb) = &ctx.lb {
                target_peer = lb.select_with_backup(b"", 16, |origin_id| {
                    crate::origin_state::ORIGIN_STATE_MANAGER.is_down(origin_id)
                });
            }
        }

        if let Some(peer) = target_peer {
            let mut peer_addr = peer.to_string();
            let backend_ext = peer.ext.get::<crate::lb_factory::BackendExtension>();
            if let Some(ext) = backend_ext
                && let Some(reason) = &ext.unsupported_reason
            {
                ctx.origin_id = ext.origin_id;
                ctx.origin_address = peer_addr.clone();
                debug!(
                    "Selected unsupported origin: server_id={} origin_id={} reason={}",
                    ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                    ext.origin_id,
                    reason
                );
                return Err(Error::new(HTTPStatus(502)));
            }
            if let Some(ext) = backend_ext
                && ext.origin_role == crate::lb_factory::OriginRole::Backup
            {
                debug!(
                    "Selected backup origin: server_id={} origin_id={} addr={}",
                    ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                    ext.origin_id,
                    peer_addr
                );
            }
            let is_tls = backend_ext
                .map(|e| e.use_tls)
                .unwrap_or(peer_addr.contains("443"));

            if let Some(ext) = backend_ext
                && ext.follow_port
            {
                if let Some(server_port) = Self::downstream_local_port(session) {
                    peer_addr = Self::replace_addr_port(
                        if ext.origin_host.is_empty() {
                            &peer_addr
                        } else {
                            &ext.origin_host
                        },
                        server_port,
                    );
                }
            }

            let client_host = session
                .get_header("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_else(|| session.req_header().uri.host().unwrap_or("localhost"));

            let (sni_host, host_override) = if let Some(ext) = backend_ext {
                if let Some(oss_backend) = &ext.oss_backend {
                    let host = oss_backend.host_header.clone();
                    (host.clone(), Some(host))
                } else if !ext.host.is_empty() {
                    // Per-origin requestHost: highest priority
                    let host =
                        Self::maybe_strip_host_port(&ext.host, ext.request_host_excluding_port);
                    (host.clone(), Some(host))
                } else if !ext.rp_host.is_empty() {
                    // ReverseProxy-level requestHost or requestHostType=origin.
                    let host =
                        Self::maybe_strip_host_port(&ext.rp_host, ext.request_host_excluding_port);
                    (host.clone(), Some(host))
                } else if ext.follow_host {
                    // follow_host=true: forward client's Host header to origin
                    let host =
                        Self::maybe_strip_host_port(&client_host, ext.request_host_excluding_port);
                    let override_host = if ext.request_host_excluding_port {
                        Some(host.clone())
                    } else {
                        None
                    };
                    (host, override_host)
                } else {
                    // requestHostType=proxyServer: keep the downstream Host.
                    let host =
                        Self::maybe_strip_host_port(&client_host, ext.request_host_excluding_port);
                    let override_host = if ext.request_host_excluding_port {
                        Some(host.clone())
                    } else {
                        None
                    };
                    (host, override_host)
                }
            } else {
                // No backend extension: forward client's Host header
                (client_host.to_string(), None)
            };

            ctx.origin_id = backend_ext.map(|ext| ext.origin_id).unwrap_or(0);
            ctx.origin_host = host_override.unwrap_or_default();
            ctx.oss_backend = backend_ext.and_then(|ext| ext.oss_backend.clone());
            if let Some(oss_backend) = &ctx.oss_backend {
                ctx.origin_host = oss_backend.host_header.clone();
                ctx.origin_address = oss_backend.log_origin_address();
            } else {
                ctx.origin_address = peer_addr.clone();
            }
            let is_upgrade_request =
                Self::has_upgrade_connection(session) || session.get_header("upgrade").is_some();
            let proxy_protocol_to_origin = backend_ext
                .map(|ext| ext.proxy_protocol)
                .unwrap_or_default();
            let origin_h3_configured = is_tls
                && ctx.is_http3_downstream
                && !is_upgrade_request
                && !(ctx.is_grpc && Self::is_grpc_request(session))
                && !proxy_protocol_to_origin.enabled()
                && backend_ext.map(|e| e.http3_enabled).unwrap_or(false);
            debug!("ACCESS_LOG: origin_address set to '{}'", ctx.origin_address);

            let mut peer_obj = HttpPeer::new(peer_addr, is_tls, sni_host);

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

            let connection_timeout = backend_ext
                .and_then(|e| e.connection_timeout)
                .unwrap_or_else(|| std::time::Duration::from_secs(15));
            let idle_timeout = backend_ext
                .and_then(|e| e.idle_timeout)
                .unwrap_or_else(|| std::time::Duration::from_secs(120));

            peer_obj.options.idle_timeout = Some(idle_timeout);
            peer_obj.options.read_timeout = backend_ext.and_then(|e| e.read_timeout);
            peer_obj.options.write_timeout = backend_ext.and_then(|e| e.write_timeout);
            peer_obj.options.connection_timeout = Some(connection_timeout);
            if proxy_protocol_to_origin.enabled() {
                let downstream_addr = Self::downstream_client_socket_addr(session, ctx);
                peer_obj.group_key = Self::proxy_protocol_origin_group_key(
                    downstream_addr,
                    proxy_protocol_to_origin,
                );
                peer_obj.options.custom_l4 = Some(Arc::new(ProxyProtocolL4Connector {
                    client_addr: downstream_addr,
                    config: proxy_protocol_to_origin,
                    connection_timeout,
                }));
            }

            let origin_h3_selected =
                origin_h3_configured && crate::origin_h3::should_try_origin_h3_for_peer(&peer_obj);
            if origin_h3_selected {
                peer_obj.options.alpn =
                    pingora_core::protocols::ALPN::Custom(CustomALPN::new(b"h3".to_vec()));
            } else if ctx.is_grpc && Self::is_grpc_request(session) {
                // Force ALPN to h2 ONLY for actual gRPC requests
                peer_obj.options.alpn = pingora_core::protocols::ALPN::H2;
            } else if is_tls && backend_ext.map(|e| e.http2_enabled).unwrap_or(false) {
                // Only enable upstream H2 when the HTTPS origin explicitly supports it.
                peer_obj.options.alpn = pingora_core::protocols::ALPN::H2H1;
            }

            if let Some(ext) = backend_ext {
                let verify_origin_tls = crate::lb_factory::should_verify_origin_tls(
                    ext,
                    &peer_obj.sni,
                    Some(client_host),
                );
                if !verify_origin_tls {
                    peer_obj.options.verify_cert = false;
                    peer_obj.options.verify_hostname = false;
                }
            }

            debug!(
                "Selected upstream: connect_addr={} TLS={} SNI={} HostOverride={} h2_enabled={} h3_configured={} h3_selected={}",
                ctx.origin_address,
                is_tls,
                peer_obj.sni,
                if ctx.origin_host.is_empty() {
                    "<original>"
                } else {
                    &ctx.origin_host
                },
                backend_ext.map(|e| e.http2_enabled).unwrap_or(false),
                origin_h3_configured,
                origin_h3_selected
            );

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
        ctx.origin_connect_permit.take();
        if ctx.response_status == 0 {
            if let Some(err) = _re {
                if matches!(err.esource(), ErrorSource::Downstream)
                    && matches!(err.etype(), WriteError | ReadError | ConnectionClosed)
                {
                    ctx.response_status = 499;
                }
            }
        }
        if !ctx.metrics_recorded {
            let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);
            if server_id > 0 && ctx.metrics_started {
                let bytes_received = session.body_bytes_read() as u64;
                let body_bytes_sent = session.body_bytes_sent() as u64;
                let bytes_sent = body_bytes_sent + ctx.response_headers_size as u64 + 20;
                let is_cached = ctx.cache_hit.unwrap_or(false);
                let is_attack = ctx.waf_action.is_some();
                crate::metrics::record::request_end(
                    server_id,
                    bytes_sent,
                    bytes_received,
                    is_cached,
                    is_attack,
                    ctx.is_websocket,
                    ctx.server_metrics.as_ref(),
                );

                if !ctx.origin_address.is_empty() {
                    crate::metrics::record::record_origin_traffic(
                        server_id,
                        bytes_received,
                        ctx.response_body_len as u64,
                        ctx.server_metrics.as_ref(),
                    );
                }

                let user_agent = session
                    .get_header("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if !user_agent.is_empty() {
                    if ctx.analyzed.is_none() && crate::logging::access_log_needs_attrs(ctx) {
                        ctx.analyzed = Some(crate::metrics::analyzer::analyze_request(
                            ctx.client_ip,
                            user_agent,
                        ));
                    }
                    crate::client_agent::maybe_report_client_agent(
                        &self.api_config,
                        &ctx.client_ip_str,
                        user_agent,
                    );
                }

                let metric_context = self.metric_request_context(
                    session,
                    ctx,
                    bytes_sent,
                    bytes_received,
                    user_agent,
                );

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
                    bytes_received as i64,
                    if is_cached { bytes_sent as i64 } else { 0 },
                    ctx.waf_group_id,
                    ctx.waf_action.as_deref(),
                    ctx.analyzed.as_ref(),
                    Some(metric_context),
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
            return Ok(pingora_cache::CacheKey::new("", key.as_str(), key.as_str()));
        }

        // CRITICAL: If no key was set by request_cache_filter, we MUST return an error.
        // This ensures Pingora absolutely does not attempt any cache lookup or storage.
        Err(pingora::Error::new(pingora::ErrorType::Custom(
            "Cache Disabled for this request",
        )))
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let location_cache = ctx.matched_location.as_ref().and_then(|l| l.cache.clone());
        if let Some(s) = &ctx.server
            && let Some(cache) = location_cache
                .as_ref()
                .or_else(|| s.web.as_ref().and_then(|w| w.cache.as_ref()))
            && cache.is_on
        {
            if Self::cache_purge_authorized(session, cache) {
                let Some((cache_ref, matched_policy)) =
                    Self::purge_cache_ref(cache, &ctx.global_cache_policies)
                else {
                    Self::disable_request_cache(session, ctx, "PurgeNoPolicy");
                    return Ok(());
                };

                let scheme = Self::forwarded_proto(session, ctx);
                let mut cache_key_ctx = Self::cache_eval_context(session, ctx, scheme);
                Self::apply_cache_key_config_to_context(&mut cache_key_ctx, cache);
                let key = if let Some(key_template) = &cache_ref.key {
                    if key_template.is_empty() {
                        Self::default_cache_key_for_session(session, ctx, cache)
                    } else {
                        crate::cache::matching::format_variables_with_context(
                            &cache_key_ctx,
                            key_template,
                        )
                    }
                } else {
                    Self::default_cache_key_for_session(session, ctx, cache)
                };

                ctx.cache_policy = if let Some(ref child) = cache_ref.cache_policy {
                    Some(child.clone())
                } else {
                    matched_policy
                };
                ctx.compiled_cache_policy = None;
                ctx.compiled_cache_ref = None;
                ctx.cache_ref = Some(cache_ref);
                ctx.cache_key = Some(key);
                ctx.cache_purge_authorized = true;
                session
                    .cache
                    .enable(CACHE.storage, None, None, Some(&*CACHE_LOCK), None);
                return Ok(());
            } else if session
                .req_header()
                .method
                .as_str()
                .eq_ignore_ascii_case("PURGE")
            {
                Self::disable_request_cache(session, ctx, "PurgeUnauthorized");
                return Ok(());
            }

            let scheme = Self::forwarded_proto(session, ctx);
            let cache_ctx = Self::cache_eval_context(session, ctx, scheme);
            let mut compiled_cache_plan_available = false;
            let mut compiled_match = None;
            if let Some(server_id) = s.id {
                match crate::cache::compiled::select_cache_ref_compiled_with_context(
                    &ctx.compiled_plans,
                    server_id,
                    &cache_ctx,
                ) {
                    crate::cache::compiled::CompiledCacheSelection::NoPlan => {}
                    crate::cache::compiled::CompiledCacheSelection::NoMatch => {
                        compiled_cache_plan_available = true;
                    }
                    crate::cache::compiled::CompiledCacheSelection::Matched(matched) => {
                        compiled_cache_plan_available = true;
                        compiled_match = Some(matched);
                    }
                }
            }
            if compiled_match
                .as_ref()
                .is_some_and(|matched| matched.cache_ref.is_reverse)
            {
                tracing::debug!("Compiled cache rule matched: SKIP");
                Self::disable_request_cache(session, ctx, "RuleSkipped");
                return Ok(());
            }

            let mut matched_ref = compiled_match
                .as_ref()
                .map(|matched| Arc::clone(&matched.cache_ref));
            let mut matched_policy: Option<std::sync::Arc<crate::config_models::HTTPCachePolicy>> =
                compiled_match
                    .as_ref()
                    .and_then(|matched| matched.cache_policy.as_ref().map(Arc::clone));

            if matched_ref.is_none() && !compiled_cache_plan_available {
                for cache_ref in &cache.cache_refs {
                    if !cache_ref.is_on {
                        continue;
                    }
                    let is_match =
                        Self::cache_ref_matches_request_with_context(cache_ref, &cache_ctx);

                    if is_match {
                        if cache_ref.is_reverse {
                            tracing::debug!("Website Cache Rule matched: SKIP");
                            Self::disable_request_cache(session, ctx, "RuleSkipped");
                            return Ok(());
                        }
                        matched_ref = Some(cache_ref.clone());
                        tracing::debug!("Website Cache Rule matched: ENABLE");
                        break;
                    }
                }

                if matched_ref.is_none() && !cache.disable_policy_refs {
                    if let Some(p) = &cache.cache_policy {
                        for cache_ref in &p.cache_refs {
                            if !cache_ref.is_on {
                                continue;
                            }
                            let is_match =
                                Self::cache_ref_matches_request_with_context(cache_ref, &cache_ctx);
                            if is_match {
                                if cache_ref.is_reverse {
                                    tracing::debug!(
                                        "Server Cache Policy '{}' rule matched: SKIP",
                                        p.name
                                    );
                                    Self::disable_request_cache(session, ctx, "RuleSkipped");
                                    return Ok(());
                                }
                                matched_ref = Some(cache_ref.clone());
                                matched_policy = Some(p.clone());
                                tracing::debug!(
                                    "Server Cache Policy '{}' rule matched: ENABLE (Path: {})",
                                    p.name,
                                    session.req_header().uri.path()
                                );
                                break;
                            }
                        }
                    } else {
                        'policy_loop: for policy in ctx.global_cache_policies.iter() {
                            for cache_ref in &policy.cache_refs {
                                if !cache_ref.is_on {
                                    continue;
                                }
                                let is_match = Self::cache_ref_matches_request_with_context(
                                    cache_ref, &cache_ctx,
                                );
                                if is_match {
                                    if cache_ref.is_reverse {
                                        tracing::debug!(
                                            "GLOBAL Cluster Policy '{}' rule matched: SKIP",
                                            policy.name
                                        );
                                        Self::disable_request_cache(session, ctx, "RuleSkipped");
                                        return Ok(());
                                    }
                                    matched_ref = Some(cache_ref.clone());
                                    matched_policy = Some(policy.clone());
                                    tracing::debug!(
                                        "GLOBAL Cluster Policy '{}' rule matched: ENABLE (Path: {})",
                                        policy.name,
                                        session.req_header().uri.path()
                                    );
                                    break 'policy_loop;
                                }
                            }
                        }
                    }
                }
            }

            if let Some(cache_ref) = matched_ref {
                if self.is_hls_encrypted_request(session, ctx, s) {
                    tracing::debug!(
                        "Skip cache for HLS encrypted request: {}",
                        session.req_header().uri.path()
                    );
                    Self::disable_request_cache(session, ctx, "HLSEncrypted");
                    return Ok(());
                }
                if cache_ref.always_forward_range_request && session.get_header("range").is_some() {
                    Self::disable_request_cache(session, ctx, "RangeForwarded");
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
                    if Self::header_contains_ascii_case_insensitive(cc, b"no-cache")
                        || Self::header_contains_ascii_case_insensitive(pragma, b"no-cache")
                    {
                        Self::disable_request_cache(session, ctx, "RequestNoCache");
                        return Ok(());
                    }
                }

                if let Some(matched) = compiled_match.take() {
                    ctx.cache_policy = matched.cache_policy;
                    ctx.compiled_cache_policy = matched.compiled_policy;
                    ctx.compiled_cache_ref = Some(matched.compiled_ref);
                } else {
                    ctx.cache_policy = if let Some(ref child) = cache_ref.cache_policy {
                        Some(child.clone())
                    } else {
                        matched_policy.clone()
                    };
                    ctx.compiled_cache_policy = None;
                    ctx.compiled_cache_ref = None;
                }
                ctx.cache_ref = Some(cache_ref.clone());

                let mut cache_key_ctx = cache_ctx.clone();
                Self::apply_cache_key_config_to_context(&mut cache_key_ctx, cache);

                // --- PROTOCOL PARITY: Salted Key Generation ---
                let mut key = if let Some(compiled_ref) = &ctx.compiled_cache_ref {
                    compiled_ref
                        .key_template
                        .as_ref()
                        .map(|key_template| key_template.format_with_context(&cache_key_ctx))
                        .unwrap_or_else(|| Self::default_cache_key_for_session(session, ctx, cache))
                } else if let Some(key_template) = &cache_ref.key {
                    if key_template.is_empty() {
                        Self::default_cache_key_for_session(session, ctx, cache)
                    } else {
                        crate::cache::matching::format_variables_with_context(
                            &cache_key_ctx,
                            key_template,
                        )
                    }
                } else {
                    Self::default_cache_key_for_session(session, ctx, cache)
                };

                // 1. Method suffix used by the cloud cache key format.
                let method = session.req_header().method.as_str();
                if method != "GET" && !ctx.cache_purge_authorized {
                    key.push_str("@method:");
                    key.push_str(method);
                }

                // 2. WebP Suffix (if applicable)
                if Self::request_path_has_webp_image_extension(session)
                    && Self::compiled_site_webp_matches_request(ctx, session).unwrap_or_else(|| {
                        s.web
                            .as_ref()
                            .and_then(|web| web.webp.as_ref())
                            .map(|webp| Self::site_webp_matches_request(webp, session))
                            .unwrap_or(false)
                    })
                {
                    key.push_str("@webp");
                }

                // 3. Compression suffix used by the cloud cache key format.
                let accept_encoding = session
                    .get_header("accept-encoding")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if accept_encoding.contains("br") {
                    key.push_str("@br");
                } else if accept_encoding.contains("gzip") {
                    key.push_str("@gzip");
                }

                // 4. Partial content. Pingora can satisfy client Range requests from a complete
                // cached object, so keep the complete-object key when that entry already exists.
                // When it does not exist and partial caching is enabled, the cloud-node partial
                // store keeps one aggregate sparse object and records covered byte ranges.
                let full_object_hash = format!("{:x}", md5_legacy::compute(key.as_bytes()));
                let full_object_cached = crate::metrics::storage::STORAGE
                    .get_cache_meta(&full_object_hash)
                    .is_some();
                let partial_cache_allowed = ctx
                    .compiled_cache_ref
                    .as_ref()
                    .map(|compiled_ref| compiled_ref.response_policy.allows_partial_content())
                    .unwrap_or(cache_ref.allow_partial_content || cache_ref.status.contains(&206));
                let force_partial = if let Some(compiled_ref) = &ctx.compiled_cache_ref {
                    compiled_ref
                        .response_policy
                        .force_partial_content(ctx.compiled_cache_policy.as_deref())
                } else {
                    cache_ref.force_partial_content
                        || ctx
                            .cache_policy
                            .as_ref()
                            .map(|policy| policy.force_partial_content)
                            .unwrap_or(false)
                };
                let requested_range = session
                    .get_header("range")
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|v| !v.is_empty());
                let selected_partial_range = if !partial_cache_allowed || full_object_cached {
                    None
                } else if let Some(requested_range) = requested_range {
                    if crate::cache::partial::parse_single_range_header(requested_range).is_none() {
                        Self::disable_request_cache(session, ctx, "UnsupportedRange");
                        return Ok(());
                    }
                    Some((requested_range.to_string(), true))
                } else if force_partial && crate::cache::partial::has_force_hit(&key) {
                    Some(("bytes=0-".to_string(), false))
                } else {
                    None
                };
                let mut using_partial_key = false;
                if let Some((range_value, forward_range_to_origin)) = selected_partial_range {
                    let partial_key = if forward_range_to_origin {
                        crate::cache::partial::partial_cache_key(&key, Some(&range_value))
                    } else {
                        crate::cache::partial::partial_cache_key(&key, None)
                    };
                    if let Some(partial_key) = partial_key {
                        key = partial_key;
                        ctx.cache_partial_range = forward_range_to_origin.then_some(range_value);
                        session.ignore_downstream_range = forward_range_to_origin;
                        using_partial_key = true;
                    }
                }

                // 5. Vary Suffix (#9) — look up the stored Vary header from the cached entry's
                //    metadata so we can reconstruct the correct key on both read and write paths.
                //    On a cache miss the base key is used for storage; on the response path we
                //    rewrite if the origin returned a Vary header (see upstream_response_filter).
                if !using_partial_key {
                    let base_hash = format!("{:x}", md5_legacy::compute(key.as_bytes()));
                    if let Some(meta) = crate::metrics::storage::STORAGE.get_cache_meta(&base_hash)
                    {
                        // Find the cached Vary header value from stored headers
                        let vary_val = meta
                            .headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("vary"))
                            .map(|(_, v)| v.as_str());
                        if let Some(vary) = vary_val {
                            match Self::vary_cache_key_suffix(vary, &session.req_header().headers) {
                                Some(Ok(suffix)) => key.push_str(&suffix),
                                Some(Err(())) => {
                                    // Vary: * — treat as uncacheable
                                    Self::disable_request_cache(session, ctx, "VaryStar");
                                    return Ok(());
                                }
                                None => {}
                            }
                        }
                    }
                }

                ctx.cache_key = Some(key);

                if !cache_ref.enable_if_none_match {
                    session.req_header_mut().headers.remove("if-none-match");
                }
                if !cache_ref.enable_if_modified_since {
                    session.req_header_mut().headers.remove("if-modified-since");
                }

                session
                    .cache
                    .enable(CACHE.storage, None, None, Some(&*CACHE_LOCK), None);
            } else {
                tracing::debug!(
                    "No cache rule matched for request: {}",
                    session.req_header().uri.path()
                );
                Self::disable_request_cache(session, ctx, "RuleDisabled");
            }
        } else {
            tracing::debug!("Cache is OFF for this server or web config.");
            Self::disable_request_cache(session, ctx, "CacheConfigOff");
        }
        Ok(())
    }

    async fn cache_hit_filter(
        &self,
        session: &mut Session,
        _meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        _is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<ForcedFreshness>>
    where
        Self::CTX: Send + Sync,
    {
        if Self::cache_fetch_action_requested(session, ctx) {
            return Ok(Some(ForcedFreshness::ForceMiss));
        }
        Ok(None)
    }

    fn is_purge(&self, _session: &Session, ctx: &Self::CTX) -> bool {
        ctx.cache_purge_authorized
    }

    fn purge_response_filter(
        &self,
        _session: &Session,
        ctx: &mut Self::CTX,
        purge_status: PurgeStatus,
        _purge_response: &mut std::borrow::Cow<'static, pingora_http::ResponseHeader>,
    ) -> Result<()> {
        if ctx.cache_purge_authorized
            && matches!(purge_status, PurgeStatus::Found | PurgeStatus::NotFound)
            && let Some(key) = ctx.cache_key.clone()
        {
            Self::report_remote_purge(self.api_config.clone(), key);
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
        if ctx.origin_status >= 500 {
            crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(ctx.origin_id);
        } else {
            crate::origin_state::ORIGIN_STATE_MANAGER.record_success(ctx.origin_id);
        }
        debug!("ACCESS_LOG: origin_status set to {}", ctx.origin_status);

        if let Some(cache_ref) = &ctx.cache_ref {
            let (force_cache, seconds, status_allows_cache) =
                if let Some(compiled_ref) = &ctx.compiled_cache_ref {
                    let seconds = compiled_ref
                        .response_policy
                        .force_ttl_seconds()
                        .unwrap_or(0);
                    let force_partial = compiled_ref
                        .response_policy
                        .force_partial_content(ctx.compiled_cache_policy.as_deref());
                    (
                        seconds > 0,
                        seconds,
                        crate::cache::compiled::cache_ref_allows_method_status_compiled(
                            compiled_ref,
                            upstream_response.status.as_u16(),
                            session.req_header().method.as_str(),
                            force_partial,
                        ),
                    )
                } else {
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

                    let force_partial = cache_ref.force_partial_content
                        || ctx
                            .cache_policy
                            .as_ref()
                            .map(|p| p.force_partial_content)
                            .unwrap_or(false);
                    let status_allows_cache = crate::cache::cache_ref_allows_method_status(
                        upstream_response.status.as_u16(),
                        cache_ref,
                        session.req_header().method.as_str(),
                        force_partial,
                    );
                    (force_cache, seconds, status_allows_cache)
                };

            if force_cache && status_allows_cache {
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

        // --- #9 Vary cache key (write path) ---
        // On a fresh origin response, check the Vary header and update ctx.cache_key so
        // Pingora stores the entry under the correct vary-qualified key.
        let is_partial_cache_key = ctx
            .cache_key
            .as_deref()
            .map(crate::cache::partial::is_partial_cache_key)
            .unwrap_or(false);
        if !is_partial_cache_key
            && let Some(vary_raw) = upstream_response
                .headers
                .get("vary")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        {
            match Self::vary_cache_key_suffix(&vary_raw, &session.req_header().headers) {
                Some(Err(())) => {
                    // Vary: * — do not cache this response.
                    Self::disable_request_cache(session, ctx, "VaryStar");
                }
                Some(Ok(suffix)) => {
                    if let Some(key) = ctx.cache_key.as_mut() {
                        // Only append vary suffix if it isn't already there
                        if !key.contains("@vary:") {
                            key.push_str(&suffix);
                        }
                    }
                }
                None => {}
            }
        }

        self.maybe_enable_webp_conversion(session, upstream_response, ctx);
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

        // Cache HIT: skip origin-response-only filters.
        if session.cache.phase() == pingora_cache::CachePhase::Hit {
            ctx.cache_hit = Some(true);

            // --- #8 Conditional GET: local 304 short-circuit ---
            // Must happen before any response mutation so the 304 is clean.
            {
                let cached_etag = upstream_response
                    .headers
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);

                // If no explicit ETag exists, generate a weak one from the
                // entry's created_at timestamp (stored in CacheMetaEntry).
                let effective_etag = cached_etag.clone().or_else(|| {
                    ctx.cache_key.as_ref().and_then(|k| {
                        let hash = format!("{:x}", md5_legacy::compute(k.as_bytes()));
                        crate::metrics::storage::STORAGE
                            .get_cache_meta(&hash)
                            .filter(|m| m.created_at > 0)
                            .map(|m| format!("W/\"{}\"", m.created_at))
                    })
                });

                let cached_last_modified = upstream_response
                    .headers
                    .get("last-modified")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);

                // Check If-None-Match
                fn strip_etag(s: &str) -> &str {
                    s.trim().trim_start_matches("W/").trim_matches('"')
                }
                let inm_match = session
                    .get_header("if-none-match")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|inm| {
                        effective_etag.as_ref().map(|etag| {
                            // Weak comparison: strip W/" prefix for matching
                            let etag_val = strip_etag(etag);
                            inm == "*"
                                || inm
                                    .split(',')
                                    .any(|part| strip_etag(part.trim()) == etag_val)
                        })
                    })
                    .unwrap_or(false);

                // Check If-Modified-Since
                let ims_match = if inm_match {
                    false // INM takes precedence
                } else {
                    session
                        .get_header("if-modified-since")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|ims| {
                            cached_last_modified.as_ref().and_then(|lm| {
                                let ims_dt = chrono::DateTime::parse_from_rfc2822(ims).ok()?;
                                let lm_dt = chrono::DateTime::parse_from_rfc2822(lm).ok()?;
                                // "not modified" if cached version is same age or older
                                Some(lm_dt <= ims_dt)
                            })
                        })
                        .unwrap_or(false)
                };

                if inm_match || ims_match {
                    upstream_response.status = pingora::http::StatusCode::NOT_MODIFIED;
                    ctx.response_status = 304;
                    // Populate weak ETag if we generated one (RFC 7232 §4.1)
                    if cached_etag.is_none() {
                        if let Some(ref etag) = effective_etag {
                            let _ = upstream_response.insert_header("etag", etag.as_str());
                        }
                    }
                    Self::sync_response_headers(upstream_response, ctx);
                    return Ok(());
                }

                // Write auto-generated weak ETag into response for future conditional requests
                if cached_etag.is_none() {
                    if let Some(ref etag) = effective_etag {
                        let _ = upstream_response.insert_header("etag", etag.as_str());
                    }
                }
            }

            if ctx
                .cache_policy
                .as_ref()
                .map(|p| p.add_status_header)
                .unwrap_or(true)
            {
                upstream_response.insert_header("x-cache", "HIT").unwrap();
            }
            if ctx
                .cache_policy
                .as_ref()
                .map(|p| p.add_age_header)
                .unwrap_or(false)
            {
                if let Some(date_val) = upstream_response.headers.get("date") {
                    if let Ok(date_str) = date_val.to_str() {
                        if let Ok(parsed) = chrono::DateTime::parse_from_rfc2822(date_str) {
                            let age = (chrono::Utc::now() - parsed.with_timezone(&chrono::Utc))
                                .num_seconds()
                                .max(0);
                            upstream_response
                                .insert_header("age", age.to_string())
                                .unwrap();
                        }
                    }
                }
            }
            if let Some(global_cfg) = &ctx.global_http_config {
                if !global_cfg.server_name.is_empty() {
                    upstream_response
                        .insert_header("Server", &global_cfg.server_name)
                        .unwrap();
                }
            }
            // CORS headers for cache HIT responses
            if let Some(server) = &ctx.server {
                if let Some(web) = &server.web {
                    if let Some(ref rhp) = web.response_header_policy {
                        if rhp.is_on {
                            let compiled_policy = server
                                .id
                                .and_then(|server_id| {
                                    ctx.compiled_plans.server_headers.get(&server_id)
                                })
                                .and_then(|plan| plan.response.as_ref());
                            let uses_template_vars = compiled_policy
                                .map(|policy| policy.uses_template_vars())
                                .unwrap_or_else(|| {
                                    crate::headers::response_policy_uses_template_vars(rhp)
                                });
                            let request_uri = if uses_template_vars
                                && compiled_policy
                                    .map(|policy| policy.needs_request_uri())
                                    .unwrap_or_else(|| {
                                        crate::headers::response_policy_needs_request_uri(rhp)
                                    }) {
                                session
                                    .req_header()
                                    .uri
                                    .path_and_query()
                                    .map(|pq| pq.as_str())
                                    .unwrap_or("/")
                            } else {
                                ""
                            };
                            let port_storage;
                            let port = if uses_template_vars
                                && compiled_policy
                                    .map(|policy| policy.needs_port())
                                    .unwrap_or_else(|| {
                                        crate::headers::response_policy_needs_port(rhp)
                                    }) {
                                port_storage = Self::downstream_local_port(session)
                                    .map(|port| port.to_string())
                                    .unwrap_or_default();
                                port_storage.as_str()
                            } else {
                                ""
                            };
                            let referer = if uses_template_vars {
                                session
                                    .get_header("referer")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                            } else {
                                ""
                            };
                            let referer_block_storage;
                            let referer_block = if uses_template_vars && !referer.is_empty() {
                                referer_block_storage =
                                    crate::headers::extract_referer_block(referer);
                                referer_block_storage.as_str()
                            } else {
                                ""
                            };
                            let user_agent = if uses_template_vars {
                                session
                                    .get_header("user-agent")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                            } else {
                                ""
                            };
                            let content_type = if uses_template_vars {
                                session
                                    .get_header("content-type")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("")
                            } else {
                                ""
                            };
                            let vars = crate::headers::RequestTemplateVars {
                                scheme: if uses_template_vars {
                                    Self::forwarded_proto(session, ctx)
                                } else {
                                    ""
                                },
                                method: if uses_template_vars {
                                    session.req_header().method.as_str()
                                } else {
                                    ""
                                },
                                host: if uses_template_vars { &ctx.host } else { "" },
                                request_uri,
                                path: if uses_template_vars {
                                    session.req_header().uri.path()
                                } else {
                                    ""
                                },
                                query: if uses_template_vars {
                                    session.req_header().uri.query().unwrap_or("")
                                } else {
                                    ""
                                },
                                port,
                                referer,
                                referer_block,
                                user_agent,
                                content_type,
                                remote_addr: if uses_template_vars {
                                    &ctx.client_ip_str
                                } else {
                                    ""
                                },
                            };
                            if let Some(compiled_policy) = compiled_policy {
                                crate::headers::apply_compiled_response_header_policy(
                                    upstream_response,
                                    compiled_policy,
                                    &vars,
                                    upstream_response.status.as_u16(),
                                    session.req_header().method.as_str(),
                                    &ctx.host,
                                );
                            } else {
                                crate::headers::apply_response_header_policy(
                                    upstream_response,
                                    rhp,
                                    &vars,
                                    upstream_response.status.as_u16(),
                                    session.req_header().method.as_str(),
                                    &ctx.host,
                                );
                            }
                        }
                        let compiled_cors = server
                            .id
                            .and_then(|server_id| ctx.compiled_plans.server_headers.get(&server_id))
                            .and_then(|plan| plan.cors.as_ref());
                        if let Some(cors) = compiled_cors {
                            cors.apply(upstream_response, session);
                        } else if let Some(ref cors) = rhp.cors {
                            if cors.is_on {
                                Self::set_cors_headers(upstream_response, session, cors);
                            }
                        }
                    }
                }
            }
            Self::sync_response_headers(upstream_response, ctx);
            return Ok(());
        }

        Self::sync_response_headers(upstream_response, ctx);

        // --- #5 Location header rewrite: replace internal origin host with client host ---
        let status_code = upstream_response.status.as_u16();
        if (301..=308).contains(&status_code) && !ctx.origin_host.is_empty() {
            if let Some(loc_val) = upstream_response.headers.get("location") {
                if let Ok(loc_str) = loc_val.to_str() {
                    if let Some(after_scheme) = loc_str.find("://").map(|i| &loc_str[i + 3..]) {
                        let loc_host_raw = after_scheme.split('/').next().unwrap_or("");
                        let loc_host = loc_host_raw.split(':').next().unwrap_or(loc_host_raw);
                        let origin_host_bare = ctx
                            .origin_host
                            .split(':')
                            .next()
                            .unwrap_or(&ctx.origin_host);
                        if loc_host.eq_ignore_ascii_case(origin_host_bare) {
                            let client_host = session
                                .get_header("host")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or(&ctx.host);
                            let rewritten = loc_str.replacen(loc_host_raw, client_host, 1);
                            let _ = upstream_response.insert_header("location", rewritten);
                        }
                    }
                }
            }
        }

        // --- SMART LOAD BALANCING FEEDBACK ---
        // 1. L2 Node: Announce pressure to L1
        // Only announce pressure to internal L1 nodes (loopback), not external clients
        if ctx.is_loopback && session.get_header("X-Cloud-Node-Id").is_some() {
            let pressure = crate::metrics::METRICS.get_node_pressure();
            upstream_response
                .insert_header("X-Cloud-Node-Pressure", format!("{:.2}", pressure))
                .unwrap();
        }

        // 2. L1 Node: Learn from L2's pressure announcement
        // Fire-and-forget: move write lock off the hot path
        if let Some(p_header) = upstream_response.headers.get("X-Cloud-Node-Pressure") {
            if let Ok(p_str) = p_header.to_str() {
                if let Ok(p_val) = p_str.parse::<f32>() {
                    let config = self.config.clone();
                    let addr = ctx.origin_address.clone();
                    tokio::spawn(async move {
                        config.update_parent_pressure(&addr, p_val);
                    });
                }
            }
        }

        // --- GLOBAL CLUSTER SETTINGS: Server Flag ---
        if let Some(global_cfg) = &ctx.global_http_config {
            if !global_cfg.server_name.is_empty() {
                upstream_response
                    .insert_header("Server", &global_cfg.server_name)
                    .unwrap();
            }
        }

        if Self::forwarded_proto(session, ctx) == "https" {
            if let Some(server) = &ctx.server {
                let compiled_value = server
                    .id
                    .and_then(|server_id| ctx.compiled_plans.server_features.get(&server_id))
                    .and_then(|plan| plan.hsts_header_value(&ctx.host).map(str::to_string));
                let raw_value = || {
                    server
                        .https
                        .as_ref()
                        .and_then(|https| https.ssl_policy.as_ref())
                        .and_then(|ssl_policy| ssl_policy.hsts.as_ref())
                        .filter(|hsts| {
                            hsts.is_on
                                && (hsts.domains.is_empty()
                                    || Self::wildcard_domain_matches(&hsts.domains, &ctx.host))
                        })
                        .map(Self::hsts_header_value)
                };
                if let Some(value) = compiled_value.or_else(raw_value) {
                    upstream_response
                        .insert_header("strict-transport-security", value.clone())
                        .unwrap();
                    ctx.response_headers
                        .insert("strict-transport-security".to_string(), value);
                }
            }
        }

        // CORS: add headers for all responses when CORS is enabled
        // (OPTIONS preflight is handled in request_filter)
        if let Some(server) = &ctx.server {
            if let Some(web) = &server.web {
                if let Some(ref rhp) = web.response_header_policy {
                    if rhp.is_on {
                        let compiled_policy = server
                            .id
                            .and_then(|server_id| ctx.compiled_plans.server_headers.get(&server_id))
                            .and_then(|plan| plan.response.as_ref());
                        let request_uri = session
                            .req_header()
                            .uri
                            .path_and_query()
                            .map(|pq| pq.as_str().to_string())
                            .unwrap_or_else(|| "/".to_string());
                        let port = Self::downstream_local_port(session)
                            .map(|port| port.to_string())
                            .unwrap_or_default();
                        let referer = session
                            .get_header("referer")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let referer_block_buf = crate::headers::extract_referer_block(referer);
                        let user_agent = session
                            .get_header("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let content_type = session
                            .get_header("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let vars = crate::headers::RequestTemplateVars {
                            scheme: Self::forwarded_proto(session, ctx),
                            method: session.req_header().method.as_str(),
                            host: &ctx.host,
                            request_uri: &request_uri,
                            path: session.req_header().uri.path(),
                            query: session.req_header().uri.query().unwrap_or(""),
                            port: &port,
                            referer,
                            referer_block: &referer_block_buf,
                            user_agent,
                            content_type,
                            remote_addr: &ctx.client_ip_str,
                        };
                        if let Some(compiled_policy) = compiled_policy {
                            crate::headers::apply_compiled_response_header_policy(
                                upstream_response,
                                compiled_policy,
                                &vars,
                                upstream_response.status.as_u16(),
                                session.req_header().method.as_str(),
                                &ctx.host,
                            );
                        } else {
                            crate::headers::apply_response_header_policy(
                                upstream_response,
                                rhp,
                                &vars,
                                upstream_response.status.as_u16(),
                                session.req_header().method.as_str(),
                                &ctx.host,
                            );
                        }
                    }
                    let compiled_cors = server
                        .id
                        .and_then(|server_id| ctx.compiled_plans.server_headers.get(&server_id))
                        .and_then(|plan| plan.cors.as_ref());
                    if let Some(cors) = compiled_cors {
                        debug!(
                            "CORS: adding headers for {} {} (status={})",
                            session.req_header().method,
                            session.req_header().uri.path(),
                            upstream_response.status.as_u16()
                        );
                        cors.apply(upstream_response, session);
                    } else if let Some(ref cors) = rhp.cors {
                        if cors.is_on {
                            debug!(
                                "CORS: adding headers for {} {} (status={})",
                                session.req_header().method,
                                session.req_header().uri.path(),
                                upstream_response.status.as_u16()
                            );
                            Self::set_cors_headers(upstream_response, session, cors);
                        }
                    }
                }
            }
        }

        Self::sync_response_headers(upstream_response, ctx);
        ctx.response_body_buffer.clear();
        ctx.outbound_waf_body_evaluated = false;
        ctx.outbound_waf_block_body = None;

        ctx.has_outbound_waf_body_rules = if ctx.compiled_plans.global_firewall.is_empty() {
            ctx.firewall_policies_snapshot
                .as_ref()
                .map(|policies| {
                    policies
                        .iter()
                        .any(crate::firewall::outbound_policy_uses_response_body)
                })
                .unwrap_or(false)
        } else {
            ctx.compiled_plans
                .global_firewall
                .iter()
                .any(|policy| crate::firewall::compiled::compiled_policy_uses_response_body(policy))
        } || ctx
            .server
            .as_ref()
            .and_then(|server| {
                let web = server.web.as_ref()?;
                web.firewall_ref.as_ref().filter(|fw_ref| fw_ref.is_on)?;
                let server_id = server.id?;
                ctx.compiled_plans.server_firewall.get(&server_id)
            })
            .map(|policy| crate::firewall::compiled::compiled_policy_uses_response_body(policy))
            .or_else(|| {
                ctx.server
                    .as_ref()
                    .and_then(|server| server.web.as_ref())
                    .and_then(|web| {
                        web.firewall_ref
                            .as_ref()
                            .filter(|fw_ref| fw_ref.is_on)
                            .and_then(|_| web.firewall_policy.as_ref())
                    })
                    .map(crate::firewall::outbound_policy_uses_response_body)
            })
            .unwrap_or(false);
        if ctx.has_outbound_waf_body_rules {
            if let Some(permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::ResponseBodyWaf) {
                ctx.response_body_waf_permit = Some(permit);
            } else {
                ctx.has_outbound_waf_body_rules = false;
                ctx.response_body_waf_permit = None;
                ctx.errors
                    .get_or_insert_with(Vec::new)
                    .push("outbound body WAF memory admission rejected".to_string());
            }
        } else {
            ctx.response_body_waf_permit = None;
        }

        // 1. Initial Outbound WAF (Status & Headers)
        let outbound_ctx = crate::firewall::OutboundContext {
            status: ctx.response_status,
            headers: &ctx.response_headers,
            body: &[],
            bytes_sent: 0,
        };

        let matched_outbound =
            Self::evaluate_outbound_waf_compiled_first(session, ctx, &outbound_ctx);

        if let Some(action) = matched_outbound {
            if action.action_code == "block" {
                let (status, body) = self.outbound_waf_block_response(session, ctx, &action);
                upstream_response.status = pingora::http::StatusCode::from_u16(status)
                    .unwrap_or(pingora::http::StatusCode::FORBIDDEN);
                ctx.response_status = status;
                upstream_response.remove_header("content-length");
                upstream_response.remove_header("transfer-encoding");
                upstream_response.remove_header("content-encoding");
                upstream_response.remove_header("etag");
                upstream_response.remove_header("last-modified");
                upstream_response.remove_header("cache-control");
                upstream_response
                    .insert_header("content-type", "text/html; charset=utf-8")
                    .unwrap();
                upstream_response
                    .insert_header("content-length", body.len().to_string())
                    .unwrap();
                upstream_response
                    .insert_header("cache-control", "no-store")
                    .unwrap();
                upstream_response
                    .insert_header("x-waf-blocked", "outbound-header")
                    .unwrap();
                ctx.outbound_waf_block_body = Some(Bytes::from(body));
                ctx.waf_policy_id = action.policy_id;
                ctx.waf_group_id = action.group_id;
                ctx.waf_set_id = action.set_id;
                ctx.waf_action = Some(action.action_code.clone());
                ctx.firewall_blocked = true;
                self.maybe_report_firewall_event(
                    session,
                    ctx,
                    action.policy_id,
                    action.group_id,
                    action.set_id,
                );
            }
        }

        if Self::is_https_downstream(session, ctx)
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

        // X-Cache header — gated by addStatusHeader on cache policy
        if ctx
            .cache_policy
            .as_ref()
            .map(|p| p.add_status_header)
            .unwrap_or(true)
        {
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
        }

        self.maybe_enable_optimization(session, upstream_response, ctx);
        self.maybe_enable_hls(session, upstream_response, ctx);

        if let Some(compiled_ref) = &ctx.compiled_cache_ref
            && compiled_ref.response_policy.auto_expires()
        {
            if compiled_ref.response_policy.overwrite_expires()
                || upstream_response.headers.get("expires").is_none()
            {
                let ttl = compiled_ref.response_policy.ttl_seconds();
                let expires = crate::utils::time::now_utc() + chrono::Duration::seconds(ttl as i64);
                upstream_response
                    .insert_header("expires", expires.to_rfc2822().replace("+0000", "GMT"))
                    .unwrap();
                upstream_response
                    .insert_header("cache-control", format!("max-age={}", ttl))
                    .unwrap();
            }
        } else if let Some(cache_ref) = &ctx.cache_ref
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

        Self::sync_response_headers(upstream_response, ctx);
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let global_cfg = ctx.global_http_config.as_ref().unwrap();
        normalize_upstream_cookie_headers(upstream_request);

        if let Some(oss_backend) = &ctx.oss_backend {
            let path = upstream_request.uri.path().to_string();
            let query = upstream_request.uri.query().map(ToString::to_string);
            let transform = oss_backend.transform_request(
                &upstream_request.method,
                &path,
                query.as_deref(),
                &upstream_request.headers,
                crate::utils::time::now_utc(),
            );
            let new_uri = transform
                .path_and_query
                .parse::<http::Uri>()
                .map_err(|_| Error::new(InternalError))?;
            upstream_request.set_uri(new_uri);
            ctx.origin_host = transform.host_header.clone();
            ctx.origin_address = oss_backend.log_origin_address_for_bucket(&transform.bucket);
            crate::oss_origin::insert_headers(upstream_request, transform.headers)
                .map_err(|_| Error::new(InternalError))?;
        }

        // Override Host header with origin-specific hostname if configured.
        // Pingora's HttpPeer only sets TLS SNI, not the HTTP Host header.
        if !ctx.origin_host.is_empty() {
            debug!(
                "UPSTREAM: overriding Host header to '{}' (origin_address={})",
                ctx.origin_host, ctx.origin_address
            );
            upstream_request
                .insert_header("host", ctx.origin_host.clone())
                .unwrap();
        } else {
            debug!(
                "UPSTREAM: keeping original Host header (origin_address={}, follow_host={})",
                ctx.origin_address,
                upstream_request
                    .headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("?")
            );
        }

        upstream_request.remove_header("x-cloud-resolved-real-ip");
        // Strip internal L1→L2 headers to prevent leaking them to origin servers
        upstream_request.remove_header("X-Cloud-Access-Token");
        upstream_request.remove_header("X-Cloud-Node-Id");
        upstream_request.remove_header("X-Cloud-Real-Ip");
        upstream_request.remove_header("X-Cloud-Real-Port");
        upstream_request.remove_header("X-Cloud-Http3-Bridge");
        if let Some(cache_ref) = &ctx.cache_ref {
            if cache_ref.enable_if_none_match
                && let Some(value) = _session.get_header("if-none-match")
            {
                upstream_request
                    .insert_header("if-none-match", value.clone())
                    .unwrap_or(());
            }
            if cache_ref.enable_if_modified_since
                && let Some(value) = _session.get_header("if-modified-since")
            {
                upstream_request
                    .insert_header("if-modified-since", value.clone())
                    .unwrap_or(());
            }
        }
        if let Some(range_value) = ctx.cache_partial_range.as_deref() {
            upstream_request
                .insert_header("range", range_value)
                .map_err(|_| Error::new(InternalError))?;
            if let Some(if_range) = _session.get_header("if-range") {
                upstream_request
                    .insert_header("if-range", if_range.clone())
                    .unwrap_or(());
            }
        }

        // Apply requestHeaderPolicy: set/delete/add custom headers to upstream request.
        // This mirrors the legacy processRequestHeaders behavior.
        if let Some(server) = &ctx.server {
            if let Some(web) = &server.web {
                if let Some(policy) = &web.request_header_policy {
                    if policy.is_on {
                        let request_uri = upstream_request
                            .uri
                            .path_and_query()
                            .map(|pq| pq.as_str().to_string())
                            .unwrap_or_else(|| "/".to_string());
                        let path = upstream_request.uri.path().to_string();
                        let query = upstream_request.uri.query().unwrap_or("").to_string();
                        let host_for_template = if !ctx.origin_host.is_empty() {
                            ctx.origin_host.clone()
                        } else {
                            ctx.host.clone()
                        };
                        let method = upstream_request.method.as_str().to_string();
                        let port = Self::downstream_local_port(_session)
                            .map(|port| port.to_string())
                            .unwrap_or_default();
                        let referer = _session
                            .get_header("referer")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let user_agent = _session
                            .get_header("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let content_type = _session
                            .get_header("content-type")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let referer_block_buf3 = crate::headers::extract_referer_block(referer);
                        let vars = crate::headers::RequestTemplateVars {
                            scheme: Self::forwarded_proto(_session, ctx),
                            method: &method,
                            host: &host_for_template,
                            request_uri: &request_uri,
                            path: &path,
                            query: &query,
                            port: &port,
                            referer,
                            referer_block: &referer_block_buf3,
                            user_agent,
                            content_type,
                            remote_addr: &ctx.client_ip_str,
                        };
                        let compiled_policy = server
                            .id
                            .and_then(|server_id| ctx.compiled_plans.server_headers.get(&server_id))
                            .and_then(|plan| plan.request.as_ref());
                        if let Some(compiled_policy) = compiled_policy {
                            crate::headers::apply_compiled_request_header_policy_to_upstream(
                                upstream_request,
                                compiled_policy,
                                &vars,
                            );
                        } else {
                            crate::headers::apply_request_header_policy_to_upstream(
                                upstream_request,
                                policy,
                                &vars,
                            );
                        }
                        debug!(
                            "UPSTREAM: applied requestHeaderPolicy (set={}, add={}, delete={})",
                            policy.set_headers.len(),
                            policy.add_headers.len(),
                            policy.delete_headers.len()
                        );
                    }
                }
            }
        }

        if ctx.is_websocket {
            // Forward Sec-WebSocket-Protocol so the upstream can honour subprotocol
            // negotiation (graphql-ws, mqtt, etc.).  Pingora does not copy this
            // header automatically during the upgrade handshake.
            if let Some(proto_val) = _session.get_header("sec-websocket-protocol") {
                if let Ok(proto_str) = proto_val.to_str() {
                    ctx.ws_subprotocol = Some(proto_str.to_string());
                    upstream_request
                        .insert_header("sec-websocket-protocol", proto_str)
                        .unwrap_or(());
                }
            }

            if let Some(server) = &ctx.server
                && let Some(web) = &server.web
                && let Some(ws) = &web.websocket
                && !ws.request_same_origin
                && !ws.request_origin.is_empty()
            {
                let request_uri = upstream_request
                    .uri
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                let path = upstream_request.uri.path().to_string();
                let query = upstream_request.uri.query().unwrap_or("").to_string();
                let port = Self::downstream_local_port(_session)
                    .map(|port| port.to_string())
                    .unwrap_or_default();
                let referer = _session
                    .get_header("referer")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let user_agent = _session
                    .get_header("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let content_type = _session
                    .get_header("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let referer_block_buf4 = crate::headers::extract_referer_block(referer);
                let vars = crate::headers::RequestTemplateVars {
                    scheme: Self::forwarded_proto(_session, ctx),
                    method: upstream_request.method.as_str(),
                    host: &ctx.host,
                    request_uri: &request_uri,
                    path: &path,
                    query: &query,
                    port: &port,
                    referer,
                    referer_block: &referer_block_buf4,
                    user_agent,
                    content_type,
                    remote_addr: &ctx.client_ip_str,
                };
                let request_origin =
                    crate::utils::template::format_template(&ws.request_origin, |var| {
                        crate::headers::resolve_request_template_var(&vars, var)
                    });
                upstream_request
                    .insert_header("origin", request_origin)
                    .unwrap();
            }
        }

        // 1. Automatic Gzip Back to Origin
        if global_cfg.request_origins_with_encodings {
            if upstream_request.headers.get("accept-encoding").is_none() {
                upstream_request
                    .insert_header("accept-encoding", "gzip, deflate, br")
                    .unwrap();
            }
        }

        // 2. L1 Logic: Inject Identity headers when talking to L2
        if ctx.node_level == 1 && ctx.upstream_is_parent {
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

            // 2.3 Security Token
            if let Ok(token) = crate::auth::generate_token(node_id, secret, "node") {
                upstream_request
                    .insert_header("X-Cloud-Access-Token", token)
                    .unwrap();
            }

            debug!("L1: Injected tiered-origin headers for node {}", node_id);
        }

        // 3. Standard forwarded headers. These are written after custom request
        // header policy so client-controlled or policy-injected values cannot
        // override the cloud-observed connection metadata.
        upstream_request
            .insert_header("X-Real-IP", ctx.client_ip_str.as_str())
            .unwrap();
        upstream_request
            .insert_header("X-Forwarded-Host", ctx.host.as_str())
            .unwrap();
        upstream_request
            .insert_header("X-Forwarded-Proto", Self::forwarded_proto(_session, ctx))
            .unwrap();

        let forwarded_for = Self::append_forwarded_for(
            upstream_request
                .headers
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok()),
            ctx.client_ip_str.as_str(),
            global_cfg.xff_max_addresses,
        );
        upstream_request
            .insert_header("X-Forwarded-For", forwarded_for)
            .unwrap();

        normalize_upstream_cookie_headers(upstream_request);

        Ok(())
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        if !ctx.webp_convert_enabled {
            return Ok(None);
        }

        if let Some(chunk) = body.take() {
            ctx.webp_pending_body.extend_from_slice(&chunk);
        }

        if !end_of_stream {
            return Ok(None);
        }

        let source_type = ctx
            .webp_source_content_type
            .clone()
            .unwrap_or_else(|| "image/jpeg".to_string());

        let pending = ctx.webp_pending_body.take();
        let quality = ctx.webp_quality;
        let Some(reservation) = ctx.webp_cpu_permit.take() else {
            ctx.webp_convert_enabled = false;
            return Err(Error::explain(
                Custom("WebPConversionNotReserved"),
                "WebP conversion reservation is missing",
            ));
        };
        let _permit = reservation.activate();
        let result =
            tokio::task::block_in_place(|| Self::convert_to_webp(&source_type, &pending, quality));
        ctx.webp_convert_enabled = false;
        Self::release_response_transform(ctx);

        match result {
            Ok(converted) => {
                *body = Some(Bytes::from(converted));
                Ok(None)
            }
            Err(err) => Err(Error::explain(
                Custom("WebPConversionFailed"),
                format!("WebP conversion failed: {}", err),
            )),
        }
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>> {
        // Cache HIT: skip optimize/webp/hls/outbound WAF — already done when first cached
        if session.cache.phase() == pingora_cache::CachePhase::Hit {
            if let Some(chunk) = body {
                ctx.response_body_len += chunk.len();
                return Ok(self.response_bandwidth_delay(chunk.len(), ctx));
            }
            return Ok(None);
        }

        if let Some(block_body) = ctx.outbound_waf_block_body.take() {
            *body = Some(block_body);
            ctx.has_outbound_waf_body_rules = false;
            ctx.outbound_waf_body_evaluated = true;
            ctx.response_body_waf_permit = None;
            ctx.response_body_buffer.clear();
            if let Some(chunk) = body.as_ref() {
                ctx.response_body_len += chunk.len();
                return Ok(self.response_bandwidth_delay(chunk.len(), ctx));
            }
            return Ok(None);
        }
        if ctx.firewall_blocked
            && ctx.waf_action.as_deref() == Some("block")
            && ctx.waf_policy_id > 0
            && ctx.response_status == 403
            && !ctx.has_outbound_waf_body_rules
        {
            *body = None;
            return Ok(None);
        }

        if ctx.optimize_enabled {
            if let Some(chunk) = body.take() {
                if ctx.optimize_pending_body.len().saturating_add(chunk.len())
                    > MAX_OPTIMIZATION_BODY_BYTES
                {
                    let mut pending = ctx.optimize_pending_body.take();
                    pending.extend_from_slice(&chunk);
                    ctx.optimize_enabled = false;
                    ctx.optimize_kind = None;
                    Self::release_response_transform(ctx);
                    *body = Some(Bytes::from(pending));
                } else {
                    ctx.optimize_pending_body.extend_from_slice(&chunk);
                }
            }

            if ctx.optimize_enabled {
                if !_end_of_stream {
                    return Ok(None);
                }

                let pending = ctx.optimize_pending_body.take();
                let optimized = if let Some(_permit) =
                    crate::adaptive_cpu::CPU_TRANSFORM_GATE.try_admit_optional()
                {
                    let kind = ctx.optimize_kind.as_deref();
                    let html_cfg = ctx
                        .server
                        .as_ref()
                        .and_then(|server| server.web.as_ref())
                        .and_then(|web| web.optimization.as_ref())
                        .and_then(|opt| opt.html.as_ref());
                    tokio::task::block_in_place(|| match kind {
                        Some("html") => {
                            html_cfg.and_then(|cfg| Self::minify_html(&pending, cfg).ok())
                        }
                        Some("css") => Self::minify_css(&pending).ok(),
                        Some("js") => Self::minify_js(&pending).ok(),
                        _ => None,
                    })
                } else {
                    None
                };

                if let Some(optimized) = optimized {
                    *body = Some(Bytes::from(optimized));
                } else {
                    *body = Some(Bytes::from(pending));
                }
                ctx.optimize_enabled = false;
                ctx.optimize_kind = None;
                Self::release_response_transform(ctx);
            }
        }

        if ctx.hls_playlist_enabled {
            // Buffer the playlist until end_of_stream so chunked / transfer-encoded
            // responses are rewritten as a complete m3u8 — the previous logic
            // ran on every chunk and shipped truncated playlists when an origin
            // returned more than one chunk.
            if let Some(chunk) = body.take() {
                ctx.hls_playlist_pending_body.extend_from_slice(&chunk);
            }
            if !_end_of_stream {
                return Ok(None);
            }
            let pending = ctx.hls_playlist_pending_body.take();
            if pending.is_empty() {
                ctx.hls_playlist_enabled = false;
                Self::release_response_transform(ctx);
            } else {
                let Some(_permit) = crate::adaptive_cpu::CPU_TRANSFORM_GATE
                    .acquire_required_blocking(std::time::Duration::from_millis(100))
                else {
                    ctx.hls_playlist_enabled = false;
                    Self::release_response_transform(ctx);
                    return Err(Error::explain(
                        Custom("HlsTransformOverloaded"),
                        "CPU transform gate overloaded while rewriting HLS playlist",
                    ));
                };
                let body_text = String::from_utf8_lossy(&pending).to_string();
                let playlist_path = ctx
                    .server
                    .as_ref()
                    .map(|_| Self::current_request_path_query(session))
                    .unwrap_or_default();
                let rewritten = ctx
                    .server
                    .as_ref()
                    .map(|server| {
                        tokio::task::block_in_place(|| {
                            self.rewrite_hls_playlist(
                                &body_text,
                                server.numeric_id(),
                                &playlist_path,
                            )
                        })
                    })
                    .unwrap_or(body_text);
                *body = Some(Bytes::from(rewritten));
                ctx.hls_playlist_enabled = false;
                Self::release_response_transform(ctx);
            }
        }

        if ctx.hls_segment_encrypt_enabled {
            if let Some(chunk) = body.take() {
                ctx.hls_segment_pending_body.extend_from_slice(&chunk);
            }
            if !_end_of_stream {
                return Ok(None);
            }

            let (Some(key), Some(iv)) = (ctx.hls_segment_key, ctx.hls_segment_iv) else {
                ctx.hls_segment_pending_body.clear();
                ctx.hls_segment_encrypt_enabled = false;
                Self::release_response_transform(ctx);
                return Err(Error::explain(
                    Custom("HlsEncryptionMissingKey"),
                    "HLS segment encryption key is missing",
                ));
            };
            let Some(_permit) = crate::adaptive_cpu::CPU_TRANSFORM_GATE
                .acquire_required_blocking(std::time::Duration::from_millis(200))
            else {
                ctx.hls_segment_pending_body.clear();
                ctx.hls_segment_encrypt_enabled = false;
                Self::release_response_transform(ctx);
                return Err(Error::explain(
                    Custom("HlsTransformOverloaded"),
                    "CPU transform gate overloaded while encrypting HLS segment",
                ));
            };
            let pending = ctx.hls_segment_pending_body.take();
            let encrypted =
                tokio::task::block_in_place(|| Self::aes128_cbc_encrypt(&pending, key, iv));
            *body = Some(Bytes::from(encrypted));
            ctx.hls_segment_encrypt_enabled = false;
            Self::release_response_transform(ctx);
        }

        if ctx.has_outbound_waf_body_rules && !ctx.outbound_waf_body_evaluated {
            let inspection_limit = ctx.max_inspection_size.max(0) as usize;
            if ctx.response_body_buffer.is_empty()
                && inspection_limit > 0
                && let Some(chunk) = body.as_ref()
                && (chunk.len() >= inspection_limit || _end_of_stream)
            {
                ctx.outbound_waf_body_evaluated = true;
                let inspect_len = chunk.len().min(inspection_limit);
                if let Some(action) = self.evaluate_outbound_waf_body(
                    session,
                    ctx,
                    &chunk[..inspect_len],
                    ctx.response_body_len + chunk.len(),
                ) {
                    if action.action_code == "block" {
                        debug!(
                            "Outbound WAF Blocked (Body): Policy ID {}",
                            action.policy_id
                        );
                        ctx.waf_policy_id = action.policy_id;
                        ctx.waf_group_id = action.group_id;
                        ctx.waf_set_id = action.set_id;
                        ctx.waf_action = Some(action.action_code.clone());
                        ctx.firewall_blocked = true;
                        ctx.response_body_waf_permit = None;
                        self.maybe_report_firewall_event(
                            session,
                            ctx,
                            action.policy_id,
                            action.group_id,
                            action.set_id,
                        );
                        *body = None;
                        return Err(Error::explain(
                            Custom("OutboundBlocked"),
                            "Blocked by Outbound WAF",
                        ));
                    }
                }
                ctx.response_body_waf_permit = None;
            } else {
                if let Some(chunk) = body.take() {
                    let previous_len = ctx.response_body_buffer.len();
                    let inspect_remaining = inspection_limit.saturating_sub(previous_len);
                    let mut passthrough_after_eval = Vec::new();
                    if inspect_remaining == 0 {
                        passthrough_after_eval.extend_from_slice(&chunk);
                    } else if chunk.len() <= inspect_remaining {
                        ctx.response_body_buffer.extend_from_slice(&chunk);
                    } else {
                        ctx.response_body_buffer
                            .extend_from_slice(&chunk[..inspect_remaining]);
                        passthrough_after_eval.extend_from_slice(&chunk[inspect_remaining..]);
                    }
                    if !passthrough_after_eval.is_empty() {
                        ctx.response_body_buffer
                            .extend_from_slice(&passthrough_after_eval);
                    }
                }

                let buffered_len = ctx.response_body_buffer.len();
                let should_evaluate =
                    _end_of_stream || inspection_limit == 0 || buffered_len >= inspection_limit;
                if !should_evaluate {
                    return Ok(None);
                }

                ctx.outbound_waf_body_evaluated = true;
                let inspect_len = if inspection_limit == 0 {
                    0
                } else {
                    buffered_len.min(inspection_limit)
                };
                if let Some(action) = self.evaluate_outbound_waf_body(
                    session,
                    ctx,
                    &ctx.response_body_buffer[..inspect_len],
                    ctx.response_body_len + buffered_len,
                ) {
                    if action.action_code == "block" {
                        debug!(
                            "Outbound WAF Blocked (Body): Policy ID {}",
                            action.policy_id
                        );
                        ctx.waf_policy_id = action.policy_id;
                        ctx.waf_group_id = action.group_id;
                        ctx.waf_set_id = action.set_id;
                        ctx.waf_action = Some(action.action_code.clone());
                        ctx.firewall_blocked = true;
                        ctx.response_body_waf_permit = None;
                        self.maybe_report_firewall_event(
                            session,
                            ctx,
                            action.policy_id,
                            action.group_id,
                            action.set_id,
                        );

                        ctx.response_body_buffer.clear();
                        *body = None;
                        return Err(Error::explain(
                            Custom("OutboundBlocked"),
                            "Blocked by Outbound WAF",
                        ));
                    }
                }

                if buffered_len > 0 {
                    *body = Some(Bytes::from(ctx.response_body_buffer.take()));
                }
                ctx.response_body_waf_permit = None;
            }
        }

        let mut delay = None;
        if let Some(chunk) = body.as_ref() {
            ctx.response_body_len += chunk.len();
            delay = self.response_bandwidth_delay(chunk.len(), ctx);
        }
        Ok(delay)
    }

    fn response_cache_filter(
        &self,
        session: &Session,
        resp: &pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<pingora_cache::RespCacheable> {
        if ctx.firewall_blocked {
            return Ok(pingora_cache::RespCacheable::Uncacheable(
                pingora_cache::NoCacheReason::Custom("WafBlocked"),
            ));
        }

        if let Some(server) = &ctx.server
            && self.is_hls_encrypted_request(session, ctx, server)
        {
            return Ok(pingora_cache::RespCacheable::Uncacheable(
                pingora_cache::NoCacheReason::Custom("HLSEncrypted"),
            ));
        }

        if let Some(cache_ref) = &ctx.cache_ref {
            let body_size = resp
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s: &str| s.parse::<usize>().ok())
                .or(ctx.webp_source_content_length)
                .unwrap_or(0);
            let is_partial_cache_key = ctx
                .cache_key
                .as_deref()
                .map(crate::cache::partial::is_partial_cache_key)
                .unwrap_or(false);
            let content_range = if resp.status.as_u16() == 206 {
                crate::cache::partial::content_range_from_headers(&resp.headers)
            } else {
                None
            };
            if resp.status.as_u16() == 206 && !is_partial_cache_key {
                return Ok(pingora_cache::RespCacheable::Uncacheable(
                    pingora_cache::NoCacheReason::Custom("PartialContentWithoutPartialKey"),
                ));
            }
            if is_partial_cache_key {
                if resp.status.as_u16() != 206 {
                    return Ok(pingora_cache::RespCacheable::Uncacheable(
                        pingora_cache::NoCacheReason::Custom("PartialRangeOriginNot206"),
                    ));
                }
                if content_range.is_none() {
                    return Ok(pingora_cache::RespCacheable::Uncacheable(
                        pingora_cache::NoCacheReason::Custom("PartialRangeMissingContentRange"),
                    ));
                }
                if content_range
                    .as_ref()
                    .and_then(|range| range.total)
                    .is_none()
                {
                    return Ok(pingora_cache::RespCacheable::Uncacheable(
                        pingora_cache::NoCacheReason::Custom("PartialRangeUnknownTotal"),
                    ));
                }
                if content_range
                    .as_ref()
                    .and_then(|range| range.total)
                    .is_some_and(|total| total < crate::cache::partial::MIN_FORCE_PARTIAL_HIT_BYTES)
                {
                    return Ok(pingora_cache::RespCacheable::Uncacheable(
                        pingora_cache::NoCacheReason::Custom("PartialRangeTooSmall"),
                    ));
                }
                if resp.headers.contains_key("vary") {
                    return Ok(pingora_cache::RespCacheable::Uncacheable(
                        pingora_cache::NoCacheReason::Custom("PartialRangeVary"),
                    ));
                }
            }
            let cache_size = if resp.status.as_u16() == 206 {
                content_range
                    .and_then(|range| range.total)
                    .and_then(|total| usize::try_from(total).ok())
                    .unwrap_or(body_size)
            } else {
                body_size
            };
            let host = session.req_header().uri.host().unwrap_or("");

            let (policy_matches, max_object_size, ttl) =
                if let Some(compiled_ref) = &ctx.compiled_cache_ref {
                    let compiled_policy = ctx.compiled_cache_policy.as_deref();
                    let allow_chunked = compiled_ref
                        .response_policy
                        .allows_chunked_encoding(compiled_policy);
                    let is_chunked = resp
                        .headers
                        .get("transfer-encoding")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| Self::header_contains_ascii_case_insensitive(v, b"chunked"))
                        .unwrap_or(false);
                    let skip_size_checks = allow_chunked && is_chunked && body_size == 0;
                    let force_partial = compiled_ref
                        .response_policy
                        .force_partial_content(compiled_policy);
                    let response_cache_ctx =
                        Self::cache_eval_context(session, ctx, Self::forwarded_proto(session, ctx))
                            .with_response(resp.status.as_u16(), &resp.headers);
                    let policy_matches = crate::cache::compiled::should_cache_response_compiled(
                        compiled_ref,
                        compiled_policy,
                        resp.status.as_u16(),
                        session.req_header().method.as_str(),
                        &resp.headers,
                        cache_size,
                        force_partial,
                        skip_size_checks,
                        &session.req_header().headers,
                    )
                        && crate::cache::compiled::cache_ref_response_conditions_match(
                            compiled_ref,
                            &response_cache_ctx,
                        );
                    (
                        policy_matches,
                        compiled_ref
                            .response_policy
                            .max_object_size_bytes(compiled_policy),
                        compiled_ref.response_policy.ttl_seconds(),
                    )
                } else {
                    let allow_chunked = cache_ref.allow_chunked_encoding
                        || ctx
                            .cache_policy
                            .as_ref()
                            .map(|p| p.allow_chunked_encoding)
                            .unwrap_or(false);
                    let is_chunked = resp
                        .headers
                        .get("transfer-encoding")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| Self::header_contains_ascii_case_insensitive(v, b"chunked"))
                        .unwrap_or(false);
                    let skip_size_checks = allow_chunked && is_chunked && body_size == 0;
                    let force_partial = cache_ref.force_partial_content
                        || ctx
                            .cache_policy
                            .as_ref()
                            .map(|p| p.force_partial_content)
                            .unwrap_or(false);
                    let response_cache_ctx =
                        Self::cache_eval_context(session, ctx, Self::forwarded_proto(session, ctx))
                            .with_response(resp.status.as_u16(), &resp.headers);
                    let response_conditions_match = if let Some(conds) = &cache_ref.conds
                        && conds.is_on
                        && !conds.groups.is_empty()
                    {
                        conds.match_request_with_context(&response_cache_ctx)
                    } else if let Some(simple_cond) = &cache_ref.simple_cond {
                        simple_cond.match_request_with_context(&response_cache_ctx)
                    } else {
                        true
                    };
                    let policy_matches = should_cache_response(
                        resp.status.as_u16(),
                        cache_ref,
                        session.req_header().method.as_str(),
                        &resp.headers,
                        host,
                        cache_size,
                        force_partial,
                        skip_size_checks,
                        &session.req_header().headers,
                    ) && response_conditions_match;
                    let mut max_bytes = i64::MAX;
                    if let Some(policy) = &ctx.cache_policy {
                        if let Some(cap) = &policy.max_item_size {
                            let b = crate::config_models::SizeCapacity::from_json(cap).to_bytes();
                            if b > 0 {
                                max_bytes = b;
                            }
                        }
                        if let Some(cap) = &policy.max_size {
                            let b = crate::config_models::SizeCapacity::from_json(cap).to_bytes();
                            if b > 0 && b < max_bytes {
                                max_bytes = b;
                            }
                        }
                    }
                    if let Some(cap) = &cache_ref.max_size {
                        let b = crate::config_models::SizeCapacity::from_json(cap).to_bytes();
                        if b > 0 && b < max_bytes {
                            max_bytes = b;
                        }
                    }
                    let max_object_size = (max_bytes != i64::MAX).then_some(max_bytes);
                    let ttl = cache_ref
                        .life
                        .as_ref()
                        .map(crate::config_models::parse_life_to_seconds)
                        .unwrap_or(3600);
                    (policy_matches, max_object_size, ttl)
                };
            if !policy_matches {
                return Ok(pingora_cache::RespCacheable::Uncacheable(
                    pingora_cache::NoCacheReason::Custom("PolicyMismatch"),
                ));
            }

            if max_object_size.is_some_and(|max_size| (cache_size as i64) > max_size) {
                return Ok(pingora_cache::RespCacheable::Uncacheable(
                    pingora_cache::NoCacheReason::Custom("FileTooLarge"),
                ));
            }

            let cached_header = Self::cached_response_header_for_store(resp, ttl);

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

pub fn start_request_limit_cleanup_task() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            EdgeProxy::cleanup_request_limit_bindings();
            EdgeProxy::cleanup_cc_bw_counters();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::EdgeProxy;
    use pingora_core::{Error, ErrorType};

    #[test]
    fn firewall_ref_parses_real_default_captcha_type_field() {
        let server: crate::config_models::ServerConfig =
            serde_json::from_value(serde_json::json!({
                "id":826,
                "serverNames":[{"name":"captcha.example.com","type":"full"}],
                "web":{
                    "firewallRef":{
                        "isOn":true,
                        "firewallPolicyId":144,
                        "ignoreGlobalRules":false,
                        "defaultCaptchaType":"oneClick"
                    }
                }
            }))
            .unwrap();
        let firewall_ref = server
            .web
            .as_ref()
            .and_then(|web| web.firewall_ref.as_ref())
            .unwrap();
        assert_eq!(firewall_ref.id, 144);
        assert_eq!(firewall_ref.default_captcha_type, "oneClick");
    }

    #[test]
    fn redirect_to_https_defaults_to_301_and_preserves_valid_status() {
        assert_eq!(EdgeProxy::redirect_to_https_status(0), 301);
        assert_eq!(EdgeProxy::redirect_to_https_status(999), 301);
        assert_eq!(EdgeProxy::redirect_to_https_status(302), 302);
        assert_eq!(EdgeProxy::redirect_to_https_status(307), 307);
        assert_eq!(EdgeProxy::redirect_to_https_status(308), 308);
    }

    #[test]
    fn request_limit_ip_key_aggregates_ipv6_to_64() {
        let a: std::net::IpAddr = "2001:db8:abcd:12::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:abcd:12:ffff:ffff:ffff:ffff".parse().unwrap();
        let c: std::net::IpAddr = "2001:db8:abcd:13::1".parse().unwrap();
        assert_eq!(
            EdgeProxy::request_limit_ip_key(a),
            EdgeProxy::request_limit_ip_key(b)
        );
        assert_ne!(
            EdgeProxy::request_limit_ip_key(a),
            EdgeProxy::request_limit_ip_key(c)
        );
    }

    #[test]
    fn proxy_ctx_starts_in_init_phase() {
        let ctx = crate::proxy::ProxyCTX::default();
        assert_eq!(ctx.request_phase, crate::proxy::RequestPhase::Init);
        assert!(ctx.request_body_waf_permit.is_none());
        assert!(ctx.response_body_waf_permit.is_none());
        assert!(ctx.response_transform_permit.is_none());
    }

    #[test]
    fn common_request_outcomes_are_access_log_only_errors() {
        for error_type in [
            ErrorType::ConnectTimedout,
            ErrorType::ReadTimedout,
            ErrorType::WriteTimedout,
            ErrorType::ConnectRefused,
            ErrorType::ConnectNoRoute,
        ] {
            let error = Error::new_up(error_type);
            assert!(EdgeProxy::is_access_log_only_proxy_error(&error));
        }

        let downstream_closed = Error::new_down(ErrorType::ConnectionClosed);
        assert!(EdgeProxy::is_access_log_only_proxy_error(
            &downstream_closed
        ));

        let internal_error = Error::new_in(ErrorType::InternalError);
        assert!(!EdgeProxy::is_access_log_only_proxy_error(&internal_error));
    }

    #[test]
    fn upstream_timeouts_are_access_log_only_errors() {
        for error_type in [
            ErrorType::ConnectTimedout,
            ErrorType::ReadTimedout,
            ErrorType::WriteTimedout,
        ] {
            let error = Error::new_up(error_type);
            assert!(EdgeProxy::is_access_log_only_proxy_error(&error));
        }
    }

    #[test]
    fn access_log_error_labels_are_recorded_once() {
        let mut ctx = crate::proxy::ProxyCTX::default();
        let error = Error::new_up(ErrorType::ReadTimedout);

        EdgeProxy::record_access_log_error(&mut ctx, &error, Some(504));
        EdgeProxy::record_access_log_error(&mut ctx, &error, Some(504));

        assert_eq!(
            ctx.errors,
            Some(vec!["proxy: upstream_read_timeout".to_string()])
        );
    }

    #[test]
    fn waf_status_helpers_reject_invalid_codes() {
        assert_eq!(EdgeProxy::response_status_from_i64(99, 404), 404);
        assert_eq!(EdgeProxy::response_status_from_i64(600, 404), 404);
        assert_eq!(EdgeProxy::response_status_from_i64(-1, 404), 404);
        assert_eq!(EdgeProxy::response_status_from_i64(100, 404), 100);
        assert_eq!(EdgeProxy::response_status_from_i64(599, 404), 599);

        assert_eq!(EdgeProxy::waf_response_status(99, 403), 403);
        assert_eq!(EdgeProxy::waf_response_status(600, 403), 403);
        assert_eq!(EdgeProxy::waf_response_status(-1, 403), 403);
        assert_eq!(EdgeProxy::waf_response_status(200, 403), 200);
        assert_eq!(EdgeProxy::waf_response_status(599, 403), 599);

        assert_eq!(EdgeProxy::waf_redirect_status(200), 302);
        assert_eq!(EdgeProxy::waf_redirect_status(600), 302);
        assert_eq!(EdgeProxy::waf_redirect_status(-1), 302);
        assert_eq!(EdgeProxy::waf_redirect_status(301), 301);
        assert_eq!(EdgeProxy::waf_redirect_status(308), 308);
    }

    #[test]
    fn insert_location_header_falls_back_for_invalid_values() {
        let mut resp = pingora_http::ResponseHeader::build(302, None).unwrap();
        EdgeProxy::insert_location_header(&mut resp, "https://example.com/ok");
        assert_eq!(
            resp.headers
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("https://example.com/ok")
        );

        let mut resp = pingora_http::ResponseHeader::build(302, None).unwrap();
        EdgeProxy::insert_location_header(&mut resp, "https://example.com/\r\nbad");
        assert_eq!(
            resp.headers
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("/")
        );
    }

    #[test]
    fn wildcard_domain_matching_uses_legacy_semantics() {
        let patterns = vec![
            "*.example.com".to_string(),
            "api-*.service.test".to_string(),
        ];

        assert!(EdgeProxy::wildcard_domain_matches(
            &patterns,
            "www.example.com"
        ));
        assert!(EdgeProxy::wildcard_domain_matches(&patterns, "example.com"));
        assert!(EdgeProxy::wildcard_domain_matches(
            &patterns,
            "api-east.service.test"
        ));
        assert!(!EdgeProxy::wildcard_domain_matches(
            &patterns,
            "static.service.test"
        ));
    }

    #[test]
    fn cache_key_main_domain_overrides_only_key_scheme_and_host() {
        let cache: crate::config_models::WebCacheConfig =
            serde_json::from_value(serde_json::json!({
                "isOn": true,
                "key": {
                    "isOn": true,
                    "scheme": "https",
                    "host": "cache.example.com"
                },
                "cacheRefs": []
            }))
            .unwrap();

        assert_eq!(
            EdgeProxy::cache_key_scheme_host("http", "a.example.com", &cache),
            ("https".to_string(), "cache.example.com".to_string())
        );

        let disabled: crate::config_models::WebCacheConfig =
            serde_json::from_value(serde_json::json!({
                "isOn": true,
                "key": {
                    "isOn": false,
                    "scheme": "https",
                    "host": "cache.example.com"
                },
                "cacheRefs": []
            }))
            .unwrap();
        assert_eq!(
            EdgeProxy::cache_key_scheme_host("http", "A.Example.com:8443", &disabled),
            ("http".to_string(), "a.example.com".to_string())
        );
    }

    #[test]
    fn cached_response_header_for_store_strips_set_cookie() {
        let mut resp = pingora_http::ResponseHeader::build(200, Some(5)).unwrap();
        resp.insert_header("set-cookie", "sid=1").unwrap();
        resp.insert_header("content-type", "text/html").unwrap();
        resp.insert_header("cache-control", "private, max-age=0")
            .unwrap();
        resp.insert_header("content-length", "42").unwrap();
        resp.insert_header("transfer-encoding", "chunked").unwrap();

        let cached = EdgeProxy::cached_response_header_for_store(&resp, 120);

        assert!(cached.headers.get("set-cookie").is_none());
        assert!(cached.headers.get("content-length").is_none());
        assert!(cached.headers.get("transfer-encoding").is_none());
        assert_eq!(
            cached
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("text/html")
        );
        assert_eq!(
            cached
                .headers
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=120")
        );
    }

    #[test]
    fn redirect_domain_lists_match_parent_and_subdomains() {
        let domains = vec!["example.com".to_string(), ".internal.test".to_string()];

        assert!(EdgeProxy::domain_list_matches(&domains, "example.com"));
        assert!(EdgeProxy::domain_list_matches(&domains, "www.example.com"));
        assert!(EdgeProxy::domain_list_matches(
            &domains,
            "api.internal.test"
        ));
        assert!(!EdgeProxy::domain_list_matches(&domains, "badexample.com"));
    }

    #[test]
    fn user_agent_wildcard_matching_is_case_insensitive() {
        assert!(EdgeProxy::cached_user_agent_wildcard_matches(
            "Bad*Bot",
            "Mozilla bad-crawler-bot"
        ));
        assert!(!EdgeProxy::cached_user_agent_wildcard_matches(
            "Bad*Bot",
            "Mozilla good crawler"
        ));
    }

    #[test]
    fn append_forwarded_for_honors_max_addresses() {
        assert_eq!(
            EdgeProxy::append_forwarded_for(Some("1.1.1.1, 2.2.2.2"), "3.3.3.3", 2),
            "2.2.2.2, 3.3.3.3"
        );
        assert_eq!(
            EdgeProxy::append_forwarded_for(None, "3.3.3.3", 0),
            "3.3.3.3"
        );
    }

    #[test]
    fn waf_challenge_method_normalization_uses_action_default() {
        assert_eq!(
            EdgeProxy::normalize_waf_challenge_method("", "js_cookie"),
            "jscookie"
        );
        assert_eq!(
            EdgeProxy::normalize_waf_challenge_method("js-cookie", "captcha"),
            ""
        );
        assert_eq!(
            EdgeProxy::normalize_waf_challenge_method("pow", "captcha"),
            "pow"
        );
        assert_eq!(
            EdgeProxy::normalize_waf_challenge_method("challengeType", "captcha"),
            ""
        );
        assert_eq!(
            EdgeProxy::normalize_waf_challenge_method("click", "captcha"),
            "click"
        );
        assert_eq!(
            EdgeProxy::normalize_waf_challenge_method("oneClick", "captcha"),
            "click"
        );
        assert_eq!(
            EdgeProxy::normalize_waf_challenge_method("slide", "captcha"),
            "slider"
        );
    }

    #[test]
    fn waf_challenge_method_uses_site_method_unless_default() {
        let site_click = crate::config_models::WAFCaptchaOptions {
            method: "click".to_string(),
            ..Default::default()
        };
        let cluster_geetest = crate::config_models::WAFCaptchaOptions {
            method: "slider".to_string(),
            use_geetest: true,
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                Some(&site_click),
                Some(&cluster_geetest),
            ),
            "click"
        );

        let site_one_click = crate::config_models::WAFCaptchaOptions {
            method: "oneClick".to_string(),
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                Some(&site_one_click),
                Some(&cluster_geetest),
            ),
            "click"
        );

        let site_default = crate::config_models::WAFCaptchaOptions {
            method: "default".to_string(),
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                Some(&site_default),
                Some(&cluster_geetest),
            ),
            "geetest"
        );

        let site_slider = crate::config_models::WAFCaptchaOptions {
            method: "slider".to_string(),
            use_geetest: true,
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                Some(&site_slider),
                Some(&cluster_geetest),
            ),
            "slider"
        );

        let site_slide = crate::config_models::WAFCaptchaOptions {
            method: "slide".to_string(),
            use_geetest: true,
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                Some(&site_slide),
                Some(&cluster_geetest),
            ),
            "slider"
        );

        let site_unknown = crate::config_models::WAFCaptchaOptions {
            method: "inherit".to_string(),
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                Some(&site_unknown),
                Some(&cluster_geetest),
            ),
            "slider"
        );

        let site_dash_default = crate::config_models::WAFCaptchaOptions {
            method: "de-fault".to_string(),
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                Some(&site_dash_default),
                Some(&cluster_geetest),
            ),
            "slider"
        );
    }

    #[test]
    fn waf_site_firewall_ref_default_captcha_type_overrides_empty_action_method() {
        let firewall_ref = crate::config_models::HTTPFirewallRef {
            is_on: true,
            ignore_global_rules: false,
            default_captcha_type: "slide".to_string(),
            id: 144,
        };
        let cluster_geetest = crate::config_models::WAFCaptchaOptions {
            method: "geetest".to_string(),
            use_geetest: true,
            ..Default::default()
        };
        let mut matched = crate::firewall::MatchedAction {
            action: crate::firewall::ActionResponse::Captcha { life_seconds: 0 },
            policy_id: 144,
            group_id: 206,
            set_id: 218,
            action_code: "captcha".to_string(),
            timeout_secs: None,
            max_timeout_secs: None,
            life_seconds: Some(0),
            max_fails: None,
            fail_block_timeout: None,
            fail_global: None,
            scope: None,
            block_c_class: false,
            use_local_firewall: false,
            next_group_id: None,
            next_set_id: None,
            allow_scope: None,
            tags: vec![],
            ip_list_id: 0,
            event_level: String::new(),
            block_options: None,
            page_options: None,
            captcha_options: Some(Default::default()),
            js_cookie_options: None,
            chained_actions: vec![],
            observe_only: false,
        };

        EdgeProxy::apply_site_default_captcha_type(
            &mut matched,
            Some(&firewall_ref),
            Some(&cluster_geetest),
        );
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                matched.captcha_options.as_ref(),
                Some(&cluster_geetest),
            ),
            "slider"
        );
    }

    #[test]
    fn product_name_prefers_product_config_over_server_name() {
        let ctx_global = crate::config_models::GlobalHTTPAllConfig {
            server_name: "edge-node".to_string(),
            ..Default::default()
        };
        let store_global = crate::config_models::GlobalHTTPAllConfig {
            product_name: "摸鱼云CDN".to_string(),
            server_name: "fallback-node".to_string(),
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_product_name(Some(&ctx_global), &store_global),
            "摸鱼云CDN"
        );

        let ctx_product = crate::config_models::GlobalHTTPAllConfig {
            product_name: "站点品牌".to_string(),
            ..Default::default()
        };
        assert_eq!(
            EdgeProxy::resolve_product_name(Some(&ctx_product), &store_global),
            "站点品牌"
        );
    }

    #[test]
    fn waf_site_captcha_action_default_type_keeps_site_captcha_mode() {
        let firewall_ref = crate::config_models::HTTPFirewallRef {
            is_on: true,
            ignore_global_rules: false,
            default_captcha_type: "default".to_string(),
            id: 144,
        };
        let cluster_geetest = crate::config_models::WAFCaptchaOptions {
            method: "geetest".to_string(),
            life_seconds: 300,
            max_fails: 5,
            ..Default::default()
        };
        let mut matched = crate::firewall::MatchedAction {
            action: crate::firewall::ActionResponse::Captcha { life_seconds: 0 },
            policy_id: 144,
            group_id: 206,
            set_id: 218,
            action_code: "captcha".to_string(),
            timeout_secs: None,
            max_timeout_secs: None,
            life_seconds: Some(0),
            max_fails: None,
            fail_block_timeout: None,
            fail_global: None,
            scope: None,
            block_c_class: false,
            use_local_firewall: false,
            next_group_id: None,
            next_set_id: None,
            allow_scope: None,
            tags: vec![],
            ip_list_id: 0,
            event_level: String::new(),
            block_options: None,
            page_options: None,
            captcha_options: Some(Default::default()),
            js_cookie_options: None,
            chained_actions: vec![],
            observe_only: false,
        };

        EdgeProxy::apply_site_default_captcha_type(
            &mut matched,
            Some(&firewall_ref),
            Some(&cluster_geetest),
        );
        assert_eq!(
            EdgeProxy::resolve_waf_challenge_method(
                "captcha",
                false,
                matched.captcha_options.as_ref(),
                Some(&cluster_geetest),
            ),
            "captcha"
        );
        assert_eq!(
            matched
                .captcha_options
                .as_ref()
                .map(|options| options.life_seconds),
            Some(cluster_geetest.life_seconds)
        );
        assert_eq!(
            matched
                .captcha_options
                .as_ref()
                .map(|options| options.max_fails),
            Some(cluster_geetest.max_fails)
        );
    }

    #[test]
    fn waf_block_body_uses_modern_page_for_default_and_fragments() {
        let default_page = EdgeProxy::compose_waf_block_body(
            "Blocked by WAF".to_string(),
            "Blocked by WAF",
            403,
            "req-1",
        );
        assert!(default_page.contains("block-panel"));
        assert!(default_page.contains("data-i18n=\"block_reason\""));
        assert!(default_page.contains("#req-1"));
        assert!(!default_page.contains("block-custom"));

        let fragment_page = EdgeProxy::compose_waf_block_body(
            "<strong data-i18n=\"custom\">custom detail</strong>".to_string(),
            "<strong data-i18n=\"custom\">custom detail</strong>",
            403,
            "req-2",
        );
        assert!(fragment_page.contains("block-panel"));
        assert!(fragment_page.contains("class=\"block-custom\" data-i18n-ignore"));
        assert!(fragment_page.contains("<strong data-i18n=\"custom\">custom detail</strong>"));

        let full_html = "<!doctype html><html><body><h1>Custom</h1></body></html>".to_string();
        assert_eq!(
            EdgeProxy::compose_waf_block_body(full_html.clone(), &full_html, 451, "req-3"),
            full_html
        );

        let commented_full_html =
            "<!-- built --><!doctype html><html><body><h1>Custom</h1></body></html>".to_string();
        assert_eq!(
            EdgeProxy::compose_waf_block_body(
                commented_full_html.clone(),
                &commented_full_html,
                451,
                "req-4",
            ),
            commented_full_html
        );
    }

    #[test]
    fn waf_pass_cookie_value_round_trips_without_cookie_delimiters() {
        let encoded = EdgeProxy::encode_waf_pass_cookie_value("captcha", "abc123");
        assert!(!encoded.contains('|'));
        assert!(!encoded.contains(';'));
        assert_eq!(
            EdgeProxy::decode_waf_pass_cookie_value(&encoded),
            Some(("captcha".to_string(), "abc123".to_string()))
        );
    }
}
