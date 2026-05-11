use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_flexible_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    match v {
        Value::Number(n) => Ok(n.as_i64().unwrap_or(0)),
        Value::String(s) => Ok(s.parse::<i64>().unwrap_or(0)),
        _ => Ok(0),
    }
}

fn deserialize_flexible_i64_opt<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    match v {
        Value::Number(n) => Ok(n.as_i64()),
        Value::String(s) => Ok(s.parse::<i64>().ok()),
        _ => Ok(None),
    }
}

fn deserialize_flexible_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    match v {
        Value::Bool(b) => Ok(b),
        Value::Number(n) => Ok(n.as_i64().unwrap_or(0) != 0),
        Value::String(s) => {
            let normalized = s.trim().to_ascii_lowercase();
            Ok(matches!(
                normalized.as_str(),
                "1" | "true" | "yes" | "on" | "enabled"
            ))
        }
        _ => Ok(false),
    }
}

fn default_connector() -> String {
    "or".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ServerNameConfig {
    #[serde(alias = "Name")]
    pub name: String,
    #[serde(alias = "Type")]
    pub r#type: Option<String>,
    #[serde(
        rename = "subNames",
        alias = "SubNames",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub sub_names: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ParentNodeConfig {
    pub id: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub addrs: Vec<String>,
    #[serde(
        rename = "lnAddrs",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub ln_addrs: Vec<String>,
    #[serde(rename = "secretHash", default)]
    pub secret_hash: String,
    #[serde(default)]
    pub weight: u32,
    #[serde(rename = "isBackup", default)]
    pub is_backup: bool,
}

impl ParentNodeConfig {
    pub fn to_addresses(&self) -> Vec<String> {
        if !self.ln_addrs.is_empty() {
            self.ln_addrs.clone()
        } else {
            self.addrs.clone()
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFBlockOptions {
    #[serde(rename = "statusCode", default)]
    pub status_code: i32,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub body: String,
    pub timeout: i32,
    #[serde(rename = "maxTimeout", default)]
    pub max_timeout: i32,
    #[serde(rename = "failGlobal", default)]
    pub fail_global: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFPageOptions {
    pub status: i32,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub body: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFCaptchaOptions {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub method: String,
    #[serde(rename = "lifeSeconds", default)]
    pub life_seconds: i32,
    #[serde(rename = "maxFails", default)]
    pub max_fails: i32,
    #[serde(rename = "failBlockTimeout", default)]
    pub fail_block_timeout: i32,
    #[serde(rename = "failGlobal", default)]
    pub fail_global: bool,
    #[serde(default)]
    pub count: i32,
    #[serde(rename = "useGeetest", default)]
    pub use_geetest: bool,
    #[serde(
        rename = "geetestId",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub geetest_id: String,
    #[serde(
        rename = "geetestKey",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub geetest_key: String,
    pub ui: Option<WAFCaptchaUIOptions>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFCaptchaUIOptions {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub title: String,
    #[serde(
        rename = "buttonTitle",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub button_title: String,
    #[serde(rename = "showRequestId", default)]
    pub show_request_id: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub css: String,
    #[serde(
        rename = "promptHeader",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub prompt_header: String,
    #[serde(
        rename = "promptFooter",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub prompt_footer: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub template: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFJSCookieOptions {
    #[serde(rename = "lifeSeconds", default)]
    pub life_seconds: i32,
    #[serde(rename = "maxFails", default)]
    pub max_fails: i32,
    #[serde(rename = "failBlockTimeout", default)]
    pub fail_block_timeout: i32,
    #[serde(rename = "failGlobal", default)]
    pub fail_global: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TOAConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "sockFile",
        alias = "socketFile",
        alias = "socketPath",
        alias = "socket",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub sock_file: String,
    #[serde(rename = "minPort", default)]
    pub min_port: Option<u16>,
    #[serde(rename = "maxPort", default)]
    pub max_port: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct UAMPolicy {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTP3Policy {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default)]
    pub port: i32,
    #[serde(rename = "supportMobileBrowsers", default)]
    pub support_mobile_browsers: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPCCPolicy {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "maxQPS", default)]
    pub max_qps: i32,
    #[serde(rename = "perIPMaxQPS", default)]
    pub per_ip_max_qps: i32,
    #[serde(rename = "maxBandwidth", default)]
    pub max_bandwidth: f64,
    #[serde(rename = "showPage", default)]
    pub show_page: bool,
    #[serde(rename = "blockIP", default)]
    pub block_ip: bool,
    #[serde(rename = "pageDuration", default)]
    pub page_duration: i32,
    #[serde(rename = "blockIPDuration", default)]
    pub block_ip_duration: i32,
    #[serde(rename = "noLog", default)]
    pub no_log: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WebPImagePolicy {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "requireCache", default)]
    pub require_cache: bool,
    #[serde(rename = "quality", default = "default_webp_quality")]
    pub quality: i32,
    #[serde(rename = "minLength", default)]
    pub min_length: Option<Value>,
    #[serde(rename = "maxLength", default)]
    pub max_length: Option<Value>,
}

fn default_webp_quality() -> i32 {
    80
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WebPConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    #[serde(
        rename = "mimeTypes",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub mime_types: Vec<String>,
    #[serde(
        rename = "fileExtensions",
        alias = "extensions",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub file_extensions: Vec<String>,
    #[serde(rename = "minLength", default)]
    pub min_length: Option<Value>,
    #[serde(rename = "maxLength", default)]
    pub max_length: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPPagesPolicy {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub pages: Vec<HTTPPageConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DataMapConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub r#map: std::collections::HashMap<String, String>, // Key is the reference, Value is the Base64 PEM
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GlobalHTTPAllConfig {
    #[serde(rename = "forceLnRequest", default)]
    pub force_ln_request: bool,
    #[serde(
        rename = "lnRequestSchedulingMethod",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub ln_request_scheduling_method: String,
    #[serde(rename = "supportsLowVersionHTTP", default = "default_true")]
    pub supports_low_version_http: bool,
    #[serde(rename = "matchCertFromAllServers", default)]
    pub match_cert_from_all_servers: bool,
    #[serde(
        rename = "serverName",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub server_name: String,
    #[serde(rename = "enableServerAddrVariable", default)]
    pub enable_server_addr_variable: bool,
    #[serde(rename = "requestOriginsWithEncodings", default)]
    pub request_origins_with_encodings: bool,
    #[serde(rename = "xffMaxAddresses", default)]
    pub xff_max_addresses: i32,
    #[serde(
        rename = "allowLANIP",
        alias = "allowLocalOrigins",
        default,
        deserialize_with = "deserialize_flexible_bool"
    )]
    pub allow_lan_ip: bool,
    #[serde(rename = "matchDomainStrictly", default)]
    pub match_domain_strictly: bool,
    #[serde(rename = "nodeIPShowPage", default)]
    pub node_ip_show_page: bool,
    #[serde(
        rename = "nodeIPPageHTML",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub node_ip_page_html: String,
    #[serde(rename = "domainMismatchAction", default)]
    pub domain_mismatch_action: Option<DomainMismatchActionConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DomainMismatchActionConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub code: String,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GlobalServerConfig {
    #[serde(rename = "httpAll")]
    pub http_all: Option<GlobalHTTPAllConfig>,
    #[serde(rename = "httpAccessLog", default)]
    pub http_access_log: Option<GlobalHTTPAccessLogConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GlobalHTTPAccessLogConfig {
    #[serde(rename = "isOn", default = "default_true")]
    pub is_on: bool,
    #[serde(rename = "enableRequestHeaders", default = "default_true")]
    pub enable_request_headers: bool,
    #[serde(rename = "commonRequestHeadersOnly", default)]
    pub common_request_headers_only: bool,
    #[serde(rename = "enableResponseHeaders", default = "default_true")]
    pub enable_response_headers: bool,
    #[serde(rename = "enableCookies", default = "default_true")]
    pub enable_cookies: bool,
    #[serde(rename = "enableServerNotFound", default = "default_true")]
    pub enable_server_not_found: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NodeConfigPayload {
    #[serde(alias = "Id")]
    pub id: Option<i64>,
    #[serde(rename = "nodeId")]
    pub node_id: Option<String>,
    pub version: Option<i64>,
    #[serde(default)]
    pub edition: String,
    #[serde(
        rename = "servers",
        alias = "Servers",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub servers: Vec<ServerConfig>,
    #[serde(rename = "dataMap", alias = "dataMap", alias = "data_map")]
    pub data_map: Option<DataMapConfig>,
    #[serde(
        rename = "metricItems",
        alias = "MetricItems",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub metric_items: Vec<MetricItemConfig>,
    #[serde(default)]
    pub level: i32,
    #[serde(rename = "isOn", default = "default_true")]
    pub is_on: bool,
    #[serde(rename = "enableIPLists", default)]
    pub enable_ip_lists: bool,
    #[serde(
        rename = "lnAddrs",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub ln_addrs: Vec<String>,
    #[serde(rename = "bypassMobile", default)]
    pub bypass_mobile: i32,
    #[serde(rename = "isCenter", default)]
    pub is_center: bool,
    #[serde(
        rename = "parentNodes",
        alias = "ParentNodes",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub parent_nodes: std::collections::HashMap<String, Vec<ParentNodeConfig>>, // Map keys in JSON are always strings
    #[serde(rename = "globalServerConfig", default)]
    pub global_server_config: Option<GlobalServerConfig>,
    #[serde(
        rename = "globalPages",
        alias = "pages",
        alias = "Pages",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub global_pages: Vec<HTTPPageConfig>,
    #[serde(
        rename = "grpcPolicies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub grpc_policies: std::collections::HashMap<String, GRPCConfig>,
    #[serde(rename = "primaryGRPCPolicy", default)]
    pub primary_grpc_policy: Option<GRPCConfig>,
    #[serde(
        rename = "httpCachePolicies",
        alias = "HTTPCachePolicies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub http_cache_policies: Vec<HTTPCachePolicy>,
    #[serde(
        rename = "httpFirewallPolicies",
        alias = "HTTPFirewallPolicies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub http_firewall_policies: Vec<HTTPFirewallPolicy>,
    #[serde(
        rename = "wafActions",
        alias = "WAFActions",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub waf_actions: Vec<WAFActionConfig>,
    pub toa: Option<TOAConfig>,
    #[serde(
        rename = "uamPolicies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub uam_policies: std::collections::HashMap<String, UAMPolicy>,
    #[serde(
        rename = "http3Policies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub http3_policies: std::collections::HashMap<String, HTTP3Policy>,
    #[serde(
        rename = "httpCCPolicies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub http_cc_policies: std::collections::HashMap<String, HTTPCCPolicy>,
    #[serde(
        rename = "webpImagePolicies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub webp_image_policies: std::collections::HashMap<String, WebPImagePolicy>,
    #[serde(
        rename = "httpPagesPolicies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub http_pages_policies: std::collections::HashMap<String, HTTPPagesPolicy>,
    #[serde(
        rename = "sslCerts",
        alias = "SSLCerts",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub ssl_certs: Vec<SSLCertConfig>,
    #[serde(rename = "sslPolicy", alias = "SSLPolicy")]
    pub ssl_policy: Option<SSLPolicyConfig>,
    #[serde(rename = "nodeRegion", alias = "NodeRegion", default)]
    pub node_region: Option<NodeRegionConfig>,
    #[serde(rename = "nodeCluster", alias = "NodeCluster", default)]
    pub node_cluster: Option<NodeClusterConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct NodeRegionConfig {
    #[serde(default, deserialize_with = "deserialize_flexible_i64")]
    pub id: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct NodeClusterConfig {
    #[serde(default, deserialize_with = "deserialize_flexible_i64")]
    pub id: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WAFActionConfig {
    pub code: String,
    pub options: Value,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MetricItemConfig {
    pub id: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub code: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub keys: Vec<String>,
    #[serde(default)]
    pub value: Value, // Flexible for CDN/Aggregated values
    pub period: i32,
    #[serde(
        rename = "periodUnit",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub period_unit: String,
    pub version: i32,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct NetworkAddressConfig {
    #[serde(alias = "protocol")]
    pub protocol: Option<String>,
    #[serde(alias = "host")]
    pub host: Option<String>,
    #[serde(rename = "portRange", alias = "port")]
    pub port_range: Option<String>,
}

impl NetworkAddressConfig {
    pub fn to_address(&self) -> String {
        let protocol = self.protocol.as_deref().unwrap_or("");
        let port = self
            .port_range
            .as_deref()
            .and_then(first_port_in_range)
            .map(|p| p.to_string())
            .unwrap_or_else(|| default_port_for_protocol(protocol).to_string());
        format!("{}:{}", self.host.as_deref().unwrap_or("127.0.0.1"), port)
    }

    pub fn is_https(&self) -> bool {
        let protocol = self.protocol.as_deref().unwrap_or("");
        let port = self.port_range.as_deref().and_then(first_port_in_range);
        corrected_origin_tls(protocol, port)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ServerConfig {
    #[serde(
        alias = "Id",
        default,
        deserialize_with = "deserialize_flexible_i64_opt"
    )]
    pub id: Option<i64>,
    #[serde(
        rename = "description",
        alias = "Description",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub description: String,
    #[serde(
        rename = "userId",
        alias = "UserId",
        default,
        deserialize_with = "deserialize_flexible_i64"
    )]
    pub user_id: i64,
    #[serde(rename = "isOn", alias = "IsOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "serverNames",
        alias = "ServerNames",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub server_names: Vec<ServerNameConfig>,
    #[serde(rename = "http", alias = "HTTP", alias = "Http")]
    pub http: Option<HTTPConfig>,
    #[serde(rename = "https", alias = "HTTPS", alias = "Https")]
    pub https: Option<HTTPSConfig>,
    #[serde(rename = "tcp", alias = "TCP", alias = "Tcp")]
    pub tcp: Option<TCPConfig>,
    #[serde(rename = "udp", alias = "UDP", alias = "Udp")]
    pub udp: Option<UDPConfig>,
    #[serde(rename = "web", alias = "Web")]
    pub web: Option<WebConfig>,
    #[serde(
        rename = "reverseProxy",
        alias = "ReverseProxy",
        alias = "reverseProxyConfig"
    )]
    pub reverse_proxy: Option<ReverseProxyConfig>,
    #[serde(rename = "grpc", alias = "grpcJSON", alias = "GRPC")]
    pub grpc: Option<GRPCConfig>,
    #[serde(rename = "uam", alias = "UAM", default)]
    pub uam: Option<UAMConfig>,
    #[serde(rename = "trafficLimit", default)]
    pub traffic_limit: Option<TrafficLimitConfig>,
    #[serde(rename = "trafficLimitStatus", default)]
    pub traffic_limit_status: Option<TrafficLimitStatus>,
    #[serde(
        rename = "userPlanId",
        alias = "UserPlanId",
        default,
        deserialize_with = "deserialize_flexible_i64"
    )]
    pub user_plan_id: i64,
}

impl ServerConfig {
    pub fn compile_url_patterns(&self) {
        if let Some(web) = &self.web {
            web.compile_url_patterns();
        }
    }

    pub(crate) fn normalize_runtime_server_name(name: &str) -> String {
        let trimmed = name.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(stripped) = lower.strip_suffix("@sni_passthrough") {
            let prefix_len = stripped.len();
            return trimmed[..prefix_len]
                .trim_end_matches('@')
                .to_ascii_lowercase();
        }
        lower
    }

    pub fn numeric_id(&self) -> i64 {
        self.id.unwrap_or(0)
    }

    pub fn get_plain_server_names(&self) -> Vec<String> {
        let mut results = Vec::new();
        for sn in &self.server_names {
            if !sn.name.is_empty() {
                let normalized = Self::normalize_runtime_server_name(&sn.name);
                if !normalized.is_empty() {
                    results.push(normalized);
                }
            }
            for ssn in &sn.sub_names {
                if !ssn.is_empty() {
                    let normalized = Self::normalize_runtime_server_name(ssn);
                    if !normalized.is_empty() {
                        results.push(normalized);
                    }
                }
            }
        }
        results
    }

    pub fn get_first_host(&self) -> String {
        self.server_names
            .first()
            .map(|sn| Self::normalize_runtime_server_name(&sn.name))
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "localhost".to_string())
    }

    pub fn has_valid_traffic_limit(&self) -> bool {
        self.traffic_limit_status
            .as_ref()
            .map(TrafficLimitStatus::is_valid)
            .unwrap_or(false)
    }

    pub fn is_sni_passthrough(&self) -> bool {
        // ONLY match if domain name specifically ends with @sni_passthrough
        // DO NOT match description to avoid accidental activation
        self.server_names.iter().any(|sn| {
            sn.name.to_ascii_lowercase().ends_with("@sni_passthrough")
                || sn
                    .sub_names
                    .iter()
                    .any(|sub| sub.to_ascii_lowercase().ends_with("@sni_passthrough"))
        })
    }

    pub fn listens_on_https_port(&self, port: u16) -> bool {
        self.https
            .as_ref()
            .filter(|https| https.is_on)
            .map(|https| {
                https.listen.iter().any(|addr| {
                    addr.port_range
                        .as_deref()
                        .and_then(|range| range.split('-').next())
                        .and_then(|value| value.parse::<u16>().ok())
                        == Some(port)
                })
            })
            .unwrap_or(false)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TrafficLimitConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "dailySize", default)]
    pub daily_size: Option<Value>,
    #[serde(rename = "monthlySize", default)]
    pub monthly_size: Option<Value>,
    #[serde(rename = "totalSize", default)]
    pub total_size: Option<Value>,
    #[serde(
        rename = "noticePageBody",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub notice_page_body: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TrafficLimitStatus {
    #[serde(
        rename = "untilDay",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub until_day: String,
    #[serde(
        rename = "planId",
        default,
        deserialize_with = "deserialize_flexible_i64"
    )]
    pub plan_id: i64,
    #[serde(
        rename = "dateType",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub date_type: String,
    #[serde(
        rename = "targetType",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub target_type: String,
}

impl TrafficLimitStatus {
    pub fn is_valid(&self) -> bool {
        !self.until_day.is_empty()
            && self.until_day >= crate::utils::time::now_local().format("%Y%m%d").to_string()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPConfig {
    #[serde(rename = "isOn", alias = "IsOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "listen",
        alias = "Listen",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub listen: Vec<NetworkAddressConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SSLPolicyConfig {
    pub id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub certs: Vec<SSLCertConfig>,
    #[serde(rename = "http2Enabled", default)]
    pub http2_enabled: bool,
    #[serde(rename = "minVersion", default)]
    pub min_version: String,
    #[serde(default)]
    pub hsts: Option<HSTSConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HSTSConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "maxAge", default)]
    pub max_age: i32,
    #[serde(rename = "includeSubDomains", default)]
    pub include_sub_domains: bool,
    #[serde(default)]
    pub preload: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub domains: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPSConfig {
    #[serde(rename = "isOn", alias = "IsOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "listen",
        alias = "Listen",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub listen: Vec<NetworkAddressConfig>,
    #[serde(rename = "sslPolicy", alias = "ssl", alias = "SSLPolicy")]
    pub ssl_policy: Option<SSLPolicyConfig>,
    #[serde(
        rename = "supportsHTTP3",
        alias = "http3Enabled",
        alias = "enableHTTP3",
        alias = "enableHttp3",
        default
    )]
    pub supports_http3: Option<bool>,
}

impl HTTPSConfig {
    pub fn http3_enabled(&self) -> bool {
        self.supports_http3.unwrap_or(true)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TCPConfig {
    #[serde(rename = "isOn", alias = "IsOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "listen",
        alias = "Listen",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub listen: Vec<NetworkAddressConfig>,
    pub tls: Option<HTTPSConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UDPConfig {
    #[serde(rename = "isOn", alias = "IsOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "listen",
        alias = "Listen",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub listen: Vec<NetworkAddressConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WebConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "redirectToHttps")]
    pub redirect_to_https: Option<HTTPRedirectToHttpsConfig>,
    #[serde(rename = "remoteAddr")]
    pub remote_addr: Option<HTTPRemoteAddrConfig>,
    #[serde(rename = "requestLimit")]
    pub request_limit: Option<HTTPRequestLimitConfig>,
    pub cache: Option<WebCacheConfig>,
    #[serde(rename = "firewallRef")]
    pub firewall_ref: Option<HTTPFirewallRef>,
    #[serde(rename = "firewallPolicy")]
    pub firewall_policy: Option<HTTPFirewallPolicy>,
    pub compression: Option<HTTPCompressionConfig>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub pages: Vec<HTTPPageConfig>,
    #[serde(rename = "enableGlobalPages", default)]
    pub enable_global_pages: bool,
    pub shutdown: Option<HTTPShutdownConfig>,
    pub auth: Option<HTTPAuthConfig>,
    pub websocket: Option<WebSocketConfig>,
    #[serde(rename = "maxQPS", default)]
    pub max_qps: i32,
    pub uam: Option<UAMConfig>,
    #[serde(rename = "ccPolicy")]
    pub cc_policy: Option<CCPolicy>,
    #[serde(rename = "webP", alias = "webp")]
    pub webp: Option<WebPConfig>,
    #[serde(rename = "userAgentConfig", alias = "userAgent")]
    pub user_agent_config: Option<UserAgentConfig>,
    #[serde(rename = "refererConfig", alias = "referers")]
    pub referer_config: Option<ReferersConfig>,
    #[serde(
        rename = "hostRedirects",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub host_redirects: Vec<HTTPHostRedirectConfig>,
    #[serde(
        rename = "rewriteRefs",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub rewrite_refs: Vec<HTTPRewriteRef>,
    #[serde(
        rename = "rewriteRules",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub rewrite_rules: Vec<HTTPRewriteRule>,
    #[serde(rename = "requestHeaderPolicy")]
    pub request_header_policy: Option<HTTPHeaderPolicy>,
    #[serde(rename = "responseHeaderPolicy")]
    pub response_header_policy: Option<HTTPHeaderPolicy>,
    #[serde(rename = "accessLogRef")]
    pub access_log_ref: Option<HTTPAccessLogRef>,
    #[serde(rename = "charset")]
    pub charset: Option<HTTPCharsetConfig>,
    #[serde(rename = "statRef")]
    pub stat_ref: Option<HTTPStatRef>,
    #[serde(rename = "optimization")]
    pub optimization: Option<HTTPPageOptimizationConfig>,
    #[serde(rename = "hls")]
    pub hls: Option<HLSConfig>,
    pub root: Option<Value>, // Root can be RootConfig object in Go
}

impl WebConfig {
    pub fn compile_url_patterns(&self) {
        if let Some(user_agent) = &self.user_agent_config {
            user_agent.compile_url_patterns();
        }
        if let Some(referers) = &self.referer_config {
            referers.compile_url_patterns();
        }
        if let Some(optimization) = &self.optimization {
            optimization.compile_url_patterns();
        }
        if let Some(hls) = &self.hls {
            hls.compile_url_patterns();
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WebSocketConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "allowAllOrigins", default)]
    pub allow_all_origins: bool,
    #[serde(
        rename = "allowedOrigins",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub allowed_origins: Vec<String>,
    #[serde(rename = "requestSameOrigin", default)]
    pub request_same_origin: bool,
    #[serde(
        rename = "requestOrigin",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub request_origin: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPRedirectToHttpsConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub host: String,
    #[serde(default)]
    pub port: i32,
    #[serde(default)]
    pub status: i32,
    #[serde(
        rename = "domains",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub domains: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPShutdownConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    #[serde(
        rename = "bodyType",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub body_type: String,
    #[serde(rename = "url", default, deserialize_with = "deserialize_null_default")]
    pub url: String,
    #[serde(
        rename = "body",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub body: String,
    #[serde(default)]
    pub status: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPRemoteAddrConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "type",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub type_name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub value: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub values: Vec<String>,
}

impl HTTPRemoteAddrConfig {
    pub fn configured_values(&self) -> Vec<String> {
        if !self.values.is_empty() {
            self.values.clone()
        } else if !self.value.is_empty() {
            vec![self.value.clone()]
        } else {
            Vec::new()
        }
    }

    pub fn is_request_header_type(&self) -> bool {
        self.type_name.eq_ignore_ascii_case("requestHeader")
            || self.type_name.eq_ignore_ascii_case("request-header")
            || self.type_name.eq_ignore_ascii_case("header")
    }

    pub fn is_empty(&self) -> bool {
        self.configured_values().is_empty()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPRequestLimitConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    #[serde(rename = "maxBodyBytes", default)]
    pub max_body_bytes: Option<Value>,
    #[serde(rename = "maxConns", default)]
    pub max_conns: i32,
    #[serde(rename = "maxConnsPerIP", default)]
    pub max_conns_per_ip: i32,
    #[serde(rename = "outBandwidthPerConnBytes", default)]
    pub out_bandwidth_per_conn_bytes: Option<Value>,
}

impl HTTPRequestLimitConfig {
    pub fn max_body_bytes_value(&self) -> i64 {
        self.max_body_bytes
            .as_ref()
            .map(SizeCapacity::from_json)
            .map(|v| v.to_bytes())
            .unwrap_or(0)
            .max(0)
    }

    pub fn out_bandwidth_per_conn_bytes_value(&self) -> i64 {
        self.out_bandwidth_per_conn_bytes
            .as_ref()
            .map(SizeCapacity::from_json)
            .map(|v| v.to_bytes())
            .unwrap_or(0)
            .max(0)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPCharsetConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    #[serde(
        rename = "charset",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub charset: String,
    #[serde(rename = "force", default)]
    pub force: bool,
    #[serde(rename = "isUpper", default)]
    pub is_upper: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPStatRef {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPPageOptimizationConfig {
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    pub html: Option<HTTPHTMLOptimizationConfig>,
    pub javascript: Option<HTTPJavascriptOptimizationConfig>,
    pub css: Option<HTTPCSSOptimizationConfig>,
}

impl HTTPPageOptimizationConfig {
    pub fn compile_url_patterns(&self) {
        if let Some(html) = &self.html {
            html.base.compile_url_patterns();
        }
        if let Some(javascript) = &self.javascript {
            javascript.base.compile_url_patterns();
        }
        if let Some(css) = &self.css {
            css.base.compile_url_patterns();
        }
    }

    pub fn is_on(&self) -> bool {
        self.html.as_ref().map(|v| v.is_on).unwrap_or(false)
            || self.javascript.as_ref().map(|v| v.is_on).unwrap_or(false)
            || self.css.as_ref().map(|v| v.is_on).unwrap_or(false)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPBaseOptimizationConfig {
    #[serde(
        rename = "onlyURLPatterns",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub only_url_patterns: Vec<URLPattern>,
    #[serde(
        rename = "exceptURLPatterns",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub except_url_patterns: Vec<URLPattern>,
}

impl HTTPBaseOptimizationConfig {
    pub fn compile_url_patterns(&self) {
        for pattern in self
            .only_url_patterns
            .iter()
            .chain(self.except_url_patterns.iter())
        {
            pattern.compile();
        }
    }

    pub fn matches_url(&self, url: &str) -> bool {
        let path = url.split('?').next().unwrap_or(url);
        if !self.except_url_patterns.is_empty()
            && self
                .except_url_patterns
                .iter()
                .any(|pattern| pattern.matches(path))
        {
            return false;
        }
        if self.only_url_patterns.is_empty() {
            return true;
        }
        self.only_url_patterns
            .iter()
            .any(|pattern| pattern.matches(path))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPHTMLOptimizationConfig {
    #[serde(flatten)]
    pub base: HTTPBaseOptimizationConfig,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "keepComments", default)]
    pub keep_comments: bool,
    #[serde(rename = "keepConditionalComments", default)]
    pub keep_conditional_comments: bool,
    #[serde(rename = "keepDefaultAttrVals", default)]
    pub keep_default_attr_vals: bool,
    #[serde(rename = "keepDocumentTags", default)]
    pub keep_document_tags: bool,
    #[serde(rename = "keepEndTags", default)]
    pub keep_end_tags: bool,
    #[serde(rename = "keepQuotes", default)]
    pub keep_quotes: bool,
    #[serde(rename = "keepWhitespace", default)]
    pub keep_whitespace: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPJavascriptOptimizationConfig {
    #[serde(flatten)]
    pub base: HTTPBaseOptimizationConfig,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "precision", default)]
    pub precision: i32,
    #[serde(rename = "version", default)]
    pub version: i32,
    #[serde(rename = "keepVarNames", default)]
    pub keep_var_names: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPCSSOptimizationConfig {
    #[serde(flatten)]
    pub base: HTTPBaseOptimizationConfig,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "precision", default)]
    pub precision: i32,
    #[serde(rename = "keepCSS2", default)]
    pub keep_css2: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HLSConfig {
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    pub encrypting: Option<HLSEncryptingConfig>,
}

impl HLSConfig {
    pub fn compile_url_patterns(&self) {
        if let Some(encrypting) = &self.encrypting {
            encrypting.compile_url_patterns();
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HLSEncryptingConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "onlyURLPatterns",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub only_url_patterns: Vec<URLPattern>,
    #[serde(
        rename = "exceptURLPatterns",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub except_url_patterns: Vec<URLPattern>,
}

impl HLSEncryptingConfig {
    pub fn compile_url_patterns(&self) {
        for pattern in self
            .only_url_patterns
            .iter()
            .chain(self.except_url_patterns.iter())
        {
            pattern.compile();
        }
    }

    pub fn matches_url(&self, url: &str) -> bool {
        let path = url.split('?').next().unwrap_or(url);
        if !self.except_url_patterns.is_empty()
            && self
                .except_url_patterns
                .iter()
                .any(|pattern| pattern.matches(path))
        {
            return false;
        }
        if self.only_url_patterns.is_empty() {
            return true;
        }
        self.only_url_patterns
            .iter()
            .any(|pattern| pattern.matches(path))
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct URLPattern {
    #[serde(
        rename = "type",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub type_name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub pattern: String,
    #[serde(skip)]
    pub compiled: OnceLock<Option<Arc<regex::Regex>>>,
}

impl Clone for URLPattern {
    fn clone(&self) -> Self {
        let cloned = Self {
            type_name: self.type_name.clone(),
            pattern: self.pattern.clone(),
            compiled: OnceLock::new(),
        };
        if let Some(compiled) = self.compiled.get() {
            let _ = cloned.compiled.set(compiled.clone());
        }
        cloned
    }
}

impl URLPattern {
    pub fn compile(&self) {
        let _ = self
            .compiled
            .get_or_init(|| Self::compile_regex(&self.type_name, &self.pattern));
    }

    fn compile_regex(type_name: &str, pattern: &str) -> Option<Arc<regex::Regex>> {
        let pattern = Self::compiled_pattern(type_name, pattern)?;
        regex::Regex::new(&pattern).ok().map(Arc::new)
    }

    fn compiled_pattern(type_name: &str, pattern: &str) -> Option<String> {
        match type_name {
            "images" | "audios" | "videos" => None,
            "regexp" => {
                if pattern.starts_with("(?i)") {
                    Some(pattern.to_string())
                } else {
                    Some(format!("(?i){}", pattern))
                }
            }
            _ => {
                if pattern.is_empty() {
                    return None;
                }
                let escaped = regex::escape(pattern);
                let wildcard = escaped.replace("\\*", "(.*)");
                if wildcard.starts_with('/') {
                    Some(format!("(?i)^(http|https)://[\\w.-]+{}$", wildcard))
                } else {
                    Some(format!("(?i)^{}$", wildcard))
                }
            }
        }
    }

    fn is_image_url(url: &str) -> bool {
        Self::has_any_suffix(
            url,
            &[
                ".apng", ".avif", ".gif", ".jpg", ".jpeg", ".jfif", ".pjpeg", ".pjp", ".png",
                ".svg", ".webp", ".bmp", ".ico", ".cur", ".tif", ".tiff",
            ],
        )
    }

    fn is_audio_url(url: &str) -> bool {
        Self::has_any_suffix(
            url,
            &[
                ".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma", ".m3u8",
            ],
        )
    }

    fn is_video_url(url: &str) -> bool {
        Self::has_any_suffix(
            url,
            &[
                ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".mpeg", ".3gp", ".webm", ".ts", ".m3u8",
            ],
        )
    }

    fn has_any_suffix(value: &str, suffixes: &[&str]) -> bool {
        let value = value.as_bytes();
        suffixes.iter().any(|suffix| {
            let suffix = suffix.as_bytes();
            value.len() >= suffix.len()
                && value[value.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        })
    }

    pub fn matches(&self, url: &str) -> bool {
        match self.type_name.as_str() {
            "images" => Self::is_image_url(url),
            "audios" => Self::is_audio_url(url),
            "videos" => Self::is_video_url(url),
            _ if self.pattern.is_empty() => url.is_empty(),
            _ => self
                .compiled
                .get_or_init(|| Self::compile_regex(&self.type_name, &self.pattern))
                .as_ref()
                .is_some_and(|re| re.is_match(url)),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UAMConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GRPCConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "maxReceiveMessageSize", default)]
    pub max_receive_message_size: Option<SizeCapacity>,
    #[serde(rename = "maxSendMessageSize", default)]
    pub max_send_message_size: Option<SizeCapacity>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct CCPolicy {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "maxQPS", default)]
    pub max_qps: i32,
    #[serde(rename = "perIPMaxQPS", default)]
    pub per_ip_max_qps: i32,
    #[serde(rename = "maxBandwidth", default)]
    pub max_bandwidth: f64,
    #[serde(rename = "showPage", default)]
    pub show_page: bool,
    #[serde(rename = "blockIP", default)]
    pub block_ip: bool,
    #[serde(rename = "pageDuration", default)]
    pub page_duration: i32,
    #[serde(rename = "blockIPDuration", default)]
    pub block_ip_duration: i32,
    #[serde(rename = "noLog", default)]
    pub no_log: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserAgentConfig {
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub filters: Vec<UserAgentFilter>,
    #[serde(
        rename = "onlyURLPatterns",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub only_url_patterns: Vec<URLPattern>,
    #[serde(
        rename = "exceptURLPatterns",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub except_url_patterns: Vec<URLPattern>,
}

impl UserAgentConfig {
    pub fn compile_url_patterns(&self) {
        for pattern in self
            .only_url_patterns
            .iter()
            .chain(self.except_url_patterns.iter())
        {
            pattern.compile();
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct UserAgentFilter {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub keywords: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub action: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ReferersConfig {
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "allowEmpty", default)]
    pub allow_empty: bool,
    #[serde(rename = "allowSameDomain", default)]
    pub allow_same_domain: bool,
    #[serde(
        rename = "allowDomains",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub allow_domains: Vec<String>,
    #[serde(
        rename = "denyDomains",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub deny_domains: Vec<String>,
    #[serde(rename = "checkOrigin", default = "default_true")]
    pub check_origin: bool,
    #[serde(
        rename = "onlyURLPatterns",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub only_url_patterns: Vec<URLPattern>,
    #[serde(
        rename = "exceptURLPatterns",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub except_url_patterns: Vec<URLPattern>,
}

impl ReferersConfig {
    pub fn compile_url_patterns(&self) {
        for pattern in self
            .only_url_patterns
            .iter()
            .chain(self.except_url_patterns.iter())
        {
            pattern.compile();
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPHostRedirectConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default)]
    pub status: i32,
    #[serde(rename = "statusCode", default)]
    pub status_code: i32,
    #[serde(
        rename = "type",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub r#type: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub mode: String,
    #[serde(
        rename = "beforeURL",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub before_url: String,
    #[serde(
        rename = "afterURL",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub after_url: String,
    #[serde(rename = "matchPrefix", default)]
    pub match_prefix: bool,
    #[serde(rename = "matchRegexp", default)]
    pub match_regexp: bool,
    #[serde(rename = "keepRequestURI", default)]
    pub keep_request_uri: bool,
    #[serde(rename = "keepArgs", default)]
    pub keep_args: bool,
    #[serde(rename = "domainsAll", alias = "domainAll", default)]
    pub domains_all: bool,
    #[serde(
        rename = "domainsBefore",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub domains_before: Vec<String>,
    #[serde(rename = "domainBeforeIgnorePorts", default)]
    pub domain_before_ignore_ports: bool,
    #[serde(
        rename = "domainAfter",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub domain_after: String,
    #[serde(
        rename = "domainAfterScheme",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub domain_after_scheme: String,
    #[serde(rename = "portsAll", default)]
    pub ports_all: bool,
    #[serde(
        rename = "portsBefore",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub ports_before: Vec<String>,
    #[serde(rename = "portAfter", alias = "port", default)]
    pub port_after: i32,
    #[serde(
        rename = "portAfterScheme",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub port_after_scheme: String,
    #[serde(
        rename = "onlyDomains",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub only_domains: Vec<String>,
    #[serde(
        rename = "exceptDomains",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub except_domains: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub before: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub after: String,
    #[serde(rename = "beforeHost")]
    pub before_host: Option<String>,
    #[serde(rename = "afterHost")]
    pub after_host: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPRewriteRef {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPRewriteRule {
    pub id: Option<i64>,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub pattern: Option<String>,
    pub replace: Option<String>,
    #[serde(rename = "withQuery", default)]
    pub with_query: bool,
    pub mode: Option<String>,
    #[serde(rename = "redirectStatus", default)]
    pub redirect_status: i32,
    #[serde(rename = "isBreak", default)]
    pub is_break: bool,
    #[serde(rename = "proxyHost", default)]
    pub proxy_host: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPAuthConfig {
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "policyRefs",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub policy_refs: Vec<HTTPAuthPolicyRef>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPAuthPolicyRef {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "authPolicyId", default)]
    pub auth_policy_id: i64,
    #[serde(rename = "authPolicy", default)]
    pub auth_policy: Option<HTTPAuthPolicy>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPAuthPolicy {
    #[serde(default)]
    pub id: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "type",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub auth_type: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WebCacheConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "cacheRefs",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub cache_refs: Vec<Arc<HTTPCacheRef>>,
    #[serde(rename = "cachePolicy")]
    pub cache_policy: Option<HTTPCachePolicy>,
    #[serde(rename = "disablePolicyRefs", default)]
    pub disable_policy_refs: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPCachePolicy {
    pub id: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub r#type: String,
    pub options: Option<std::collections::HashMap<String, Value>>,
    pub capacity: Option<Value>,
    #[serde(rename = "maxItemSize")]
    pub max_item_size: Option<Value>,
    #[serde(rename = "maxSize")]
    pub max_size: Option<Value>,
    #[serde(
        rename = "cacheRefs",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub cache_refs: Vec<Arc<HTTPCacheRef>>,
    #[serde(rename = "cachePolicyId", default)]
    pub cache_policy_id: i64,
    #[serde(rename = "addStatusHeader", default = "default_true")]
    pub add_status_header: bool,
    #[serde(rename = "addAgeHeader", default)]
    pub add_age_header: bool,
    #[serde(rename = "allowChunkedEncoding", default)]
    pub allow_chunked_encoding: bool,
    #[serde(rename = "forcePartialContent", default)]
    pub force_partial_content: bool,
    #[serde(rename = "enableReadingOriginAsync", default)]
    pub enable_reading_origin_async: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPCacheRef {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub key: Option<String>,
    pub life: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub methods: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub status: Vec<i32>,
    #[serde(rename = "minSize")]
    pub min_size: Option<Value>,
    #[serde(rename = "maxSize")]
    pub max_size: Option<Value>,
    #[serde(
        rename = "skipCacheControlValues",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub skip_cache_control_values: Vec<String>,
    #[serde(rename = "skipSetCookie", default)]
    pub skip_set_cookie: bool,
    #[serde(rename = "allowPartialContent", default)]
    pub allow_partial_content: bool,
    #[serde(rename = "alwaysForwardRangeRequest", default)]
    pub always_forward_range_request: bool,
    #[serde(rename = "enableRequestCachePragma", default)]
    pub enable_request_cache_pragma: bool,
    #[serde(rename = "enableIfNoneMatch", default)]
    pub enable_if_none_match: bool,
    #[serde(rename = "enableIfModifiedSince", default)]
    pub enable_if_modified_since: bool,
    #[serde(rename = "isReverse", default)]
    pub is_reverse: bool,
    pub conds: Option<HTTPRequestCondsConfig>,
    #[serde(rename = "simpleCond")]
    pub simple_cond: Option<HTTPRequestCond>,
    #[serde(rename = "expiresTime")]
    pub expires_time: Option<HTTPExpiresTimeConfig>,
    #[serde(rename = "cachePolicy")]
    pub cache_policy: Option<HTTPCachePolicy>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallPolicy {
    pub id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    pub inbound: Option<HTTPFirewallInboundConfig>,
    pub outbound: Option<HTTPFirewallOutboundConfig>,
    #[serde(rename = "emptyConnectionFlood", default)]
    pub empty_connection_flood: Option<EmptyConnectionFloodConfig>,
    #[serde(rename = "tlsExhaustionAttack", default)]
    pub tls_exhaustion_attack: Option<TLSExhaustionAttackConfig>,

    // Config Options from PB
    #[serde(rename = "blockOptions", default)]
    pub block_options: Option<WAFBlockOptions>,
    #[serde(rename = "pageOptions", default)]
    pub page_options: Option<WAFPageOptions>,
    #[serde(rename = "captchaOptions", default)]
    pub captcha_options: Option<WAFCaptchaOptions>,
    #[serde(rename = "jsCookieOptions", default)]
    pub js_cookie_options: Option<WAFJSCookieOptions>,
    #[serde(rename = "maxRequestBodySize", default)]
    pub max_request_body_size: i64,
    #[serde(
        rename = "denyCountryHTML",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub deny_country_html: String,
    #[serde(
        rename = "denyProvinceHTML",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub deny_province_html: String,
    #[serde(rename = "useLocalFirewall", default)]
    pub use_local_firewall: bool,
    #[serde(rename = "synFlood", default)]
    pub syn_flood: Option<SynFloodConfig>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub mode: String, // "defense" or "observe"
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallRef {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "ignoreGlobalRules", default)]
    pub ignore_global_rules: bool,
    pub id: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallInboundConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub groups: Vec<HTTPFirewallRuleGroup>,
    #[serde(default)]
    pub region: Option<HTTPFirewallRegionConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallOutboundConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub groups: Vec<HTTPFirewallRuleGroup>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPFirewallRegionConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "denyCountryIds",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub deny_country_ids: Vec<i64>,
    #[serde(
        rename = "allowCountryIds",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub allow_country_ids: Vec<i64>,
    #[serde(
        rename = "denyProvinceIds",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub deny_province_ids: Vec<i64>,
    #[serde(
        rename = "allowProvinceIds",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub allow_province_ids: Vec<i64>,
    #[serde(
        rename = "denyCountryHTML",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub deny_country_html: String,
    #[serde(
        rename = "denyProvinceHTML",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub deny_province_html: String,
    #[serde(default)]
    pub allow_search_engine: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallRuleGroup {
    pub id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    pub code: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub sets: Vec<HTTPFirewallRuleSet>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallRuleSet {
    pub id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub rules: Vec<HTTPFirewallRule>,
    #[serde(default = "default_connector")]
    pub connector: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub actions: Vec<Value>,
    #[serde(rename = "ignoreLocal", default)]
    pub ignore_local: bool,
    #[serde(rename = "ignoreSearchEngine", default)]
    pub ignore_search_engine: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallRule {
    pub param: String,
    pub operator: String,
    pub value: String,
    #[serde(rename = "checkpointOptions", default)]
    pub checkpoint_options: Option<Value>,
    #[serde(rename = "isReverse", default)]
    pub is_reverse: bool,
    #[serde(rename = "isCaseInsensitive", default)]
    pub is_case_insensitive: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct EmptyConnectionFloodConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default)]
    pub threshold: u32,
    #[serde(default)]
    pub period: i32,
    #[serde(rename = "banDuration", default)]
    pub ban_duration: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TLSExhaustionAttackConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default)]
    pub threshold: u32,
    #[serde(default)]
    pub period: i32,
    #[serde(rename = "banDuration", default)]
    pub ban_duration: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SynFloodConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default)]
    pub threshold: u32,
    #[serde(default)]
    pub period: i32,
    #[serde(rename = "banDuration", default)]
    pub ban_duration: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPExpiresTimeConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(rename = "autoCalculate", default)]
    pub auto_calculate: bool,
    pub duration: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPRequestCondsConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default = "default_connector")]
    pub connector: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub groups: Vec<HTTPRequestCondGroup>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPRequestCondGroup {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default = "default_connector")]
    pub connector: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub conds: Vec<HTTPRequestCond>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPRequestCond {
    pub param: String,
    pub operator: String,
    pub value: String,
    #[serde(rename = "isReverse", default)]
    pub is_reverse: bool,
    #[serde(rename = "isCaseInsensitive", default)]
    pub is_case_insensitive: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPStatusConfig {
    #[serde(default)]
    pub always: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub codes: Vec<i32>,
}

impl HTTPStatusConfig {
    pub fn matches(&self, status: u16) -> bool {
        self.always || self.codes.iter().any(|code| *code == status as i32)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPHeaderPolicy {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "setHeaders",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub set_headers: Vec<HTTPHeaderConfig>,
    #[serde(
        rename = "addHeaders",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub add_headers: Vec<HTTPHeaderConfig>,
    #[serde(
        rename = "deleteHeaders",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub delete_headers: Vec<String>,
    #[serde(
        rename = "replaceHeaders",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub replace_headers: Vec<HTTPHeaderReplaceConfig>,
    pub cors: Option<CORSConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct CORSConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "optionsMethodOnly", default)]
    pub options_method_only: bool,
    #[serde(
        rename = "allowOrigin",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub allow_origin: String,
    #[serde(
        rename = "allowMethods",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub allow_methods: Vec<String>,
    #[serde(rename = "maxAge", default)]
    pub max_age: i64,
    #[serde(
        rename = "exposeHeaders",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub expose_headers: Vec<String>,
    #[serde(
        rename = "requestMethod",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub request_method: String,
    #[serde(
        rename = "allowHeaders",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub allow_headers: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPHeaderConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub value: String,
    #[serde(default)]
    pub status: Option<HTTPStatusConfig>,
    #[serde(rename = "disableRedirect", default)]
    pub disable_redirect: bool,
    #[serde(rename = "shouldAppend", default)]
    pub should_append: bool,
    #[serde(rename = "shouldReplace", default)]
    pub should_replace: bool,
    #[serde(
        rename = "replaceValues",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub replace_values: Vec<HTTPHeaderReplaceValue>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub methods: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub domains: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPHeaderReplaceValue {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub pattern: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub replacement: String,
    #[serde(rename = "isCaseInsensitive", default)]
    pub is_case_insensitive: bool,
    #[serde(rename = "isRegexp", default)]
    pub is_regexp: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPHeaderReplaceConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(
        rename = "oldValue",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub old_value: String,
    #[serde(
        rename = "newValue",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub new_value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPPageConfig {
    pub id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub status: Option<Value>, // Flexible status (string or list)
    pub body: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "newStatus", default)]
    pub new_status: i32,
}

impl HTTPPageConfig {
    pub fn matches_status(&self, status: u16) -> bool {
        let Some(value) = self.status.as_ref() else {
            return true;
        };

        match value {
            Value::Number(n) => n.as_u64() == Some(status as u64),
            Value::String(s) => {
                if s.trim().is_empty() || s == "*" {
                    true
                } else {
                    s.parse::<u16>() == Ok(status)
                }
            }
            Value::Array(values) => values.iter().any(|item| match item {
                Value::Number(n) => n.as_u64() == Some(status as u64),
                Value::String(s) => s.parse::<u16>() == Ok(status),
                _ => false,
            }),
            _ => false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPCompressionConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub brotli: Option<HTTPCompressionSubConfig>,
    pub gzip: Option<HTTPCompressionSubConfig>,
    pub deflate: Option<HTTPCompressionSubConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPCompressionSubConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub level: i8,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IPListRef {
    #[serde(rename = "listId")]
    pub list_id: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SSLCertConfig {
    pub id: i64,
    #[serde(rename = "isOn", alias = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "certDataJSON", alias = "certData")]
    pub cert_data_json: Option<Value>,
    #[serde(rename = "keyDataJSON", alias = "keyData")]
    pub key_data_json: Option<Value>,
    #[serde(
        rename = "dnsNames",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub dns_names: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SchedulingConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub code: String,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ReverseProxyConfig {
    #[serde(rename = "isOn", alias = "IsOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "primaryOrigins",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub primary_origins: Vec<OriginConfig>,
    #[serde(
        rename = "backupOrigins",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub backup_origins: Vec<OriginConfig>,
    #[serde(default)]
    pub scheduling: Option<SchedulingConfig>,
    // Global request host override (used when requestHostType == 2)
    #[serde(
        rename = "requestHost",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub request_host: String,
    // 0=proxyServer(CDN domain), 1=origin, 2=customized
    #[serde(rename = "requestHostType", default)]
    pub request_host_type: i8,
    #[serde(rename = "requestHostExcludingPort", default)]
    pub request_host_excluding_port: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum FlexibleAddr {
    Object(NetworkAddressConfig),
    String(String),
}

impl FlexibleAddr {
    pub fn to_address(&self) -> String {
        match self {
            Self::Object(obj) => obj.to_address(),
            Self::String(s) => normalize_origin_addr_string(s).address,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Object(obj) => obj.host.clone().unwrap_or_default(),
            Self::String(s) => normalize_origin_addr_string(s).host,
        }
    }

    pub fn is_https(&self) -> bool {
        match self {
            Self::Object(obj) => obj.is_https(),
            Self::String(s) => normalize_origin_addr_string(s).use_tls,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedOriginAddr {
    address: String,
    host: String,
    use_tls: bool,
}

fn normalize_origin_addr_string(raw: &str) -> NormalizedOriginAddr {
    let trimmed = raw.trim();

    if has_uri_scheme(trimmed) {
        if let Ok(uri) = trimmed.parse::<http::Uri>() {
            let scheme = uri.scheme_str().unwrap_or("");
            let host = uri.host().unwrap_or("").to_string();
            let port = uri
                .port_u16()
                .unwrap_or_else(|| default_port_for_protocol(scheme));
            let use_tls = corrected_origin_tls(scheme, Some(port));
            return NormalizedOriginAddr {
                address: format_host_port(&host, port),
                host,
                use_tls,
            };
        }
    }

    let (without_scheme, use_tls) = strip_known_scheme(trimmed);
    let without_path = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let (host, port) = split_host_port(without_path);
    let port = port.unwrap_or_else(|| if use_tls { 443 } else { 80 });
    let use_tls = corrected_origin_tls(if use_tls { "https" } else { "http" }, Some(port));

    NormalizedOriginAddr {
        address: format_host_port(&host, port),
        host,
        use_tls,
    }
}

fn has_uri_scheme(value: &str) -> bool {
    value.find("://").is_some_and(|idx| {
        matches!(
            &value[..idx].to_ascii_lowercase()[..],
            "http" | "https" | "tls"
        )
    })
}

fn strip_known_scheme(value: &str) -> (&str, bool) {
    if let Some(rest) = value.strip_prefix("https://") {
        (rest, true)
    } else if let Some(rest) = value.strip_prefix("tls://") {
        (rest, true)
    } else if let Some(rest) = value.strip_prefix("http://") {
        (rest, false)
    } else {
        (value, false)
    }
}

fn split_host_port(value: &str) -> (String, Option<u16>) {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
    }

    if value.matches(':').count() == 1 {
        if let Some((host, port)) = value.rsplit_once(':') {
            return (host.to_string(), port.parse::<u16>().ok());
        }
    }

    (value.to_string(), None)
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn default_port_for_protocol(protocol: &str) -> u16 {
    if is_tls_origin_protocol(protocol) {
        443
    } else {
        80
    }
}

fn corrected_origin_tls(protocol: &str, port: Option<u16>) -> bool {
    match port {
        Some(443) => true,
        Some(80) => false,
        _ => is_tls_origin_protocol(protocol),
    }
}

fn is_tls_origin_protocol(protocol: &str) -> bool {
    matches!(
        protocol.to_ascii_lowercase().as_str(),
        "https" | "https4" | "https6" | "tls" | "tls4" | "tls6"
    )
}

fn first_port_in_range(port_range: &str) -> Option<u16> {
    let raw = port_range.trim();
    let first = raw.split(['-', ':']).next().unwrap_or(raw).trim();
    first.parse::<u16>().ok()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OriginConfig {
    #[serde(alias = "id")]
    pub id: i64,
    #[serde(alias = "name", default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(rename = "addr", alias = "address", alias = "Addr")]
    pub addr: Option<FlexibleAddr>,
    #[serde(rename = "isOn", alias = "IsOn", default = "default_true")]
    pub is_on: bool,
    #[serde(alias = "weight", default)]
    pub weight: u32,
    #[serde(rename = "healthCheck", alias = "HealthCheck")]
    pub health_check: Option<HealthCheckConfig>,
    // Legacy API uses "requestHost" for per-origin custom Host header override.
    #[serde(
        rename = "requestHost",
        alias = "host",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub request_host: String,
    #[serde(rename = "followHost", default)]
    pub follow_host: bool,
    #[serde(rename = "followPort", default)]
    pub follow_port: bool,
    #[serde(rename = "http2Enabled", default)]
    pub http2_enabled: bool,
    #[serde(
        rename = "http3Enabled",
        alias = "supportsHTTP3",
        alias = "enableHTTP3",
        alias = "enableHttp3",
        default
    )]
    pub http3_enabled: bool,
    #[serde(rename = "connTimeout", default)]
    pub conn_timeout: Option<Value>,
    #[serde(rename = "readTimeout", default)]
    pub read_timeout: Option<Value>,
    #[serde(rename = "idleTimeout", default)]
    pub idle_timeout: Option<Value>,
    pub cert: Option<SSLCertConfig>,
    #[serde(rename = "tlsVerify", default)]
    pub tls_verify: Option<Value>, // Can be boolean, object, or int in legacy configs.
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthCheckConfig {
    #[serde(rename = "isOn", alias = "IsOn", default)]
    pub is_on: bool,
    #[serde(alias = "protocol")]
    pub protocol: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub url: String,
    pub interval: Option<Value>,
    pub timeout: Option<Value>,
    #[serde(
        rename = "statusCodes",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub status_codes: Vec<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPAccessLogRef {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub fields: Vec<i32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SizeCapacity {
    pub count: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub unit: String,
}

impl SizeCapacity {
    pub fn from_json(v: &Value) -> Self {
        let fallback = || Self {
            count: 0,
            unit: "b".to_string(),
        };
        let Some(map) = v.as_object() else {
            return fallback();
        };
        let Some(count) = map.get("count").and_then(Value::as_i64) else {
            return fallback();
        };
        let unit = match map.get("unit") {
            Some(Value::String(unit)) => unit.clone(),
            Some(Value::Null) | None => String::new(),
            Some(_) => return fallback(),
        };
        Self { count, unit }
    }

    pub fn to_bytes(&self) -> i64 {
        if self.unit.eq_ignore_ascii_case("kb") || self.unit.eq_ignore_ascii_case("k") {
            self.count * 1024
        } else if self.unit.eq_ignore_ascii_case("mb") || self.unit.eq_ignore_ascii_case("m") {
            self.count * 1024 * 1024
        } else if self.unit.eq_ignore_ascii_case("gb") || self.unit.eq_ignore_ascii_case("g") {
            self.count * 1024 * 1024 * 1024
        } else {
            self.count
        }
    }
}

pub fn parse_life_to_seconds(v: &Value) -> u64 {
    if let Some(count) = v.get("count").and_then(|c| c.as_u64()) {
        let unit = v.get("unit").and_then(|u| u.as_str()).unwrap_or("s");
        return if unit.eq_ignore_ascii_case("m") || unit.eq_ignore_ascii_case("min") {
            count * 60
        } else if unit.eq_ignore_ascii_case("h") || unit.eq_ignore_ascii_case("hour") {
            count * 3600
        } else if unit.eq_ignore_ascii_case("d") || unit.eq_ignore_ascii_case("day") {
            count * 86400
        } else {
            count
        };
    }
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_pattern_preserves_match_semantics() {
        let regexp = URLPattern {
            type_name: "regexp".to_string(),
            pattern: r"^/api/v\d+/users/\d+$".to_string(),
            ..Default::default()
        };
        assert!(regexp.matches("/API/v2/users/123"));
        assert!(!regexp.matches("/api/v2/users/abc"));

        let wildcard = URLPattern {
            type_name: "wildcard".to_string(),
            pattern: "/static/*/image.jpg".to_string(),
            ..Default::default()
        };
        assert!(wildcard.matches("https://example.com/static/a/image.jpg"));
        assert!(!wildcard.matches("/static/a/image.jpg"));

        let empty = URLPattern {
            type_name: "wildcard".to_string(),
            pattern: String::new(),
            ..Default::default()
        };
        assert!(empty.matches(""));
        assert!(!empty.matches("/"));

        let invalid = URLPattern {
            type_name: "regexp".to_string(),
            pattern: "(".to_string(),
            ..Default::default()
        };
        assert!(!invalid.matches("/anything"));

        let image = URLPattern {
            type_name: "images".to_string(),
            pattern: String::new(),
            ..Default::default()
        };
        assert!(image.matches("/static/photo.JPG"));
        assert!(!image.matches("/static/photo.txt"));
    }

    #[test]
    fn size_capacity_from_json_and_to_bytes_preserve_fallbacks() {
        let kb = SizeCapacity::from_json(&serde_json::json!({"count": 2, "unit": "KB"}));
        assert_eq!(kb.count, 2);
        assert_eq!(kb.unit, "KB");
        assert_eq!(kb.to_bytes(), 2048);

        let raw = SizeCapacity::from_json(&serde_json::json!({"count": -5, "unit": "unknown"}));
        assert_eq!(raw.to_bytes(), -5);

        let missing_unit = SizeCapacity::from_json(&serde_json::json!({"count": 5}));
        assert_eq!(missing_unit.count, 5);
        assert_eq!(missing_unit.unit, "");
        assert_eq!(missing_unit.to_bytes(), 5);

        let missing_count = SizeCapacity::from_json(&serde_json::json!({"unit": "KB"}));
        assert_eq!(missing_count.count, 0);
        assert_eq!(missing_count.unit, "b");

        let invalid_unit_type =
            SizeCapacity::from_json(&serde_json::json!({"count": 5, "unit": 1}));
        assert_eq!(invalid_unit_type.count, 0);
        assert_eq!(invalid_unit_type.unit, "b");

        let fallback = SizeCapacity::from_json(&serde_json::json!(null));
        assert_eq!(fallback.count, 0);
        assert_eq!(fallback.unit, "b");
        assert_eq!(fallback.to_bytes(), 0);
    }

    #[test]
    fn parse_life_to_seconds_preserves_units_and_default() {
        assert_eq!(
            parse_life_to_seconds(&serde_json::json!({"count": 5, "unit": "m"})),
            300
        );
        assert_eq!(
            parse_life_to_seconds(&serde_json::json!({"count": 2, "unit": "hour"})),
            7200
        );
        assert_eq!(
            parse_life_to_seconds(&serde_json::json!({"count": 7, "unit": "DAY"})),
            604800
        );
        assert_eq!(
            parse_life_to_seconds(&serde_json::json!({"count": 9, "unit": "s"})),
            9
        );
        assert_eq!(
            parse_life_to_seconds(&serde_json::json!({"unit": "h"})),
            3600
        );
    }

    #[test]
    fn flexible_addr_http_url_normalizes_to_socket_address() {
        let addr = FlexibleAddr::String("http://127.0.0.1:8080".to_string());

        assert_eq!(addr.to_address(), "127.0.0.1:8080");
        assert_eq!(addr.host(), "127.0.0.1");
        assert!(!addr.is_https());
    }

    #[test]
    fn flexible_addr_http_url_on_443_is_https() {
        let addr = FlexibleAddr::String("http://127.0.0.1:443".to_string());

        assert_eq!(addr.to_address(), "127.0.0.1:443");
        assert!(addr.is_https());
    }

    #[test]
    fn flexible_addr_https_url_on_80_is_http() {
        let addr = FlexibleAddr::String("https://127.0.0.1:80".to_string());

        assert_eq!(addr.to_address(), "127.0.0.1:80");
        assert!(!addr.is_https());
    }

    #[test]
    fn flexible_addr_https_url_uses_default_port() {
        let addr = FlexibleAddr::String("https://127.0.0.1".to_string());

        assert_eq!(addr.to_address(), "127.0.0.1:443");
        assert_eq!(addr.host(), "127.0.0.1");
        assert!(addr.is_https());
    }

    #[test]
    fn flexible_addr_plain_host_port_stays_http() {
        let addr = FlexibleAddr::String("127.0.0.1:80".to_string());

        assert_eq!(addr.to_address(), "127.0.0.1:80");
        assert_eq!(addr.host(), "127.0.0.1");
        assert!(!addr.is_https());
    }

    #[test]
    fn network_address_https_defaults_to_443() {
        let addr = NetworkAddressConfig {
            protocol: Some("https".to_string()),
            host: Some("127.0.0.1".to_string()),
            port_range: None,
        };

        assert_eq!(addr.to_address(), "127.0.0.1:443");
    }

    #[test]
    fn network_address_corrects_protocol_by_special_ports() {
        let http_443 = NetworkAddressConfig {
            protocol: Some("http".to_string()),
            host: Some("127.0.0.1".to_string()),
            port_range: Some("443".to_string()),
        };
        let https_80 = NetworkAddressConfig {
            protocol: Some("https".to_string()),
            host: Some("127.0.0.1".to_string()),
            port_range: Some("80".to_string()),
        };

        assert!(http_443.is_https());
        assert!(!https_80.is_https());
    }

    #[test]
    fn node_config_payload_parses_global_http_compat_fields() {
        let payload: NodeConfigPayload = serde_json::from_value(serde_json::json!({
            "id": 1001,
            "globalServerConfig": {
                "httpAll": {
                    "forceLnRequest": true,
                    "lnRequestSchedulingMethod": "urlMapping",
                    "supportsLowVersionHTTP": true,
                    "matchCertFromAllServers": true,
                    "serverName": "edge-node",
                    "enableServerAddrVariable": true,
                    "requestOriginsWithEncodings": true,
                    "xffMaxAddresses": 3,
                    "allowLANIP": true,
                    "matchDomainStrictly": true,
                    "nodeIPShowPage": true,
                    "nodeIPPageHTML": "<h1>${host}</h1>",
                    "domainMismatchAction": {
                        "code": "page",
                        "options": {
                            "statusCode": 451,
                            "contentHTML": "blocked"
                        }
                    }
                }
            }
        }))
        .expect("node config payload should parse");

        let http_all = payload
            .global_server_config
            .and_then(|g| g.http_all)
            .expect("httpAll should be present");
        assert!(http_all.force_ln_request);
        assert_eq!(http_all.ln_request_scheduling_method, "urlMapping");
        assert!(http_all.match_domain_strictly);
        assert!(http_all.node_ip_show_page);
        assert_eq!(http_all.node_ip_page_html, "<h1>${host}</h1>");
        let action = http_all
            .domain_mismatch_action
            .expect("domain mismatch action should parse");
        assert_eq!(action.code, "page");
        assert_eq!(action.options["statusCode"], 451);
    }

    #[test]
    fn traffic_limit_status_represents_exceeded_state_not_config_presence() {
        let configured_only = ServerConfig {
            traffic_limit: Some(TrafficLimitConfig {
                is_on: true,
                ..Default::default()
            }),
            traffic_limit_status: None,
            ..Default::default()
        };
        assert!(!configured_only.has_valid_traffic_limit());

        let exceeded = ServerConfig {
            traffic_limit_status: Some(TrafficLimitStatus {
                until_day: "99991231".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(exceeded.has_valid_traffic_limit());

        let expired = ServerConfig {
            traffic_limit_status: Some(TrafficLimitStatus {
                until_day: "19700101".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!expired.has_valid_traffic_limit());
    }

    #[test]
    fn web_config_parses_auth_referer_and_user_agent_aliases() {
        let web: WebConfig = serde_json::from_value(serde_json::json!({
            "isOn": true,
            "auth": {
                "isOn": true,
                "policyRefs": [{
                    "isOn": true,
                    "authPolicyId": 10,
                    "authPolicy": {
                        "id": 10,
                        "name": "basic",
                        "isOn": true,
                        "type": "basicAuth",
                        "params": {
                            "realm": "private",
                            "users": [{"username": "u", "password": "p"}]
                        }
                    }
                }]
            },
            "referers": {
                "isOn": true,
                "allowEmpty": false,
                "allowSameDomain": true,
                "allowDomains": ["*.example.com"],
                "denyDomains": ["bad.example.com"],
                "checkOrigin": true
            },
            "userAgent": {
                "isOn": true,
                "filters": [{
                    "keywords": ["curl*", "BadBot"],
                    "action": "deny"
                }]
            }
        }))
        .expect("web config should parse compatibility aliases");

        let auth = web.auth.expect("auth should parse");
        assert!(auth.is_on);
        assert_eq!(auth.policy_refs[0].auth_policy_id, 10);
        assert_eq!(
            auth.policy_refs[0]
                .auth_policy
                .as_ref()
                .expect("policy should parse")
                .auth_type,
            "basicAuth"
        );

        let referers = web.referer_config.expect("referers alias should parse");
        assert!(referers.is_on);
        assert!(referers.allow_same_domain);
        assert_eq!(referers.allow_domains, vec!["*.example.com"]);
        assert_eq!(referers.deny_domains, vec!["bad.example.com"]);

        let ua = web.user_agent_config.expect("userAgent alias should parse");
        assert!(ua.is_on);
        assert_eq!(ua.filters[0].keywords, vec!["curl*", "BadBot"]);
        assert_eq!(ua.filters[0].action, "deny");
    }
}
