use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::HashMap;
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

fn deserialize_flexible_i32<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    match v {
        Value::Number(n) => Ok(n.as_i64().unwrap_or(0) as i32),
        Value::String(s) => Ok(s.parse::<i32>().unwrap_or(0)),
        _ => Ok(0),
    }
}

fn deserialize_flexible_u8_opt<'de, D>(deserializer: D) -> Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;
    match v {
        Value::Number(n) => Ok(n.as_u64().and_then(|v| u8::try_from(v).ok())),
        Value::String(s) => Ok(s.trim().parse::<u8>().ok()),
        _ => Ok(None),
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

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Eq, PartialEq)]
pub struct ProxyProtocolConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default = "default_proxy_protocol_version")]
    pub version: u8,
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        Self {
            is_on: false,
            version: default_proxy_protocol_version(),
        }
    }
}

impl ProxyProtocolConfig {
    pub fn enabled(self) -> bool {
        self.is_on
    }

    pub fn normalized_version(self) -> u8 {
        if self.version == 2 { 2 } else { 1 }
    }
}

fn default_proxy_protocol_version() -> u8 {
    1
}

fn deserialize_proxy_protocol_config<'de, D>(
    deserializer: D,
) -> Result<ProxyProtocolConfig, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<ProxyProtocolConfig>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_origin_tls_security_verify_mode<'de, D>(
    deserializer: D,
) -> Result<OriginTlsSecurityVerifyMode, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    let mode = match value {
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "force" | "strict" | "on" | "true" | "1" => OriginTlsSecurityVerifyMode::Force,
            "skip" | "none" | "off" | "false" | "0" => OriginTlsSecurityVerifyMode::Skip,
            _ => OriginTlsSecurityVerifyMode::Auto,
        },
        Value::Bool(true) => OriginTlsSecurityVerifyMode::Force,
        Value::Bool(false) => OriginTlsSecurityVerifyMode::Skip,
        Value::Number(value) if value.as_i64().unwrap_or(0) > 0 => {
            OriginTlsSecurityVerifyMode::Force
        }
        _ => OriginTlsSecurityVerifyMode::Auto,
    };
    Ok(mode)
}

fn default_connector() -> String {
    "or".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ServerNameConfig {
    pub name: String,
    pub r#type: Option<String>,
    #[serde(
        rename = "subNames",
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
    #[serde(rename = "failBlockScopeAll", default)]
    pub fail_global: bool,
    #[serde(rename = "ipListId", default)]
    pub ip_list_id: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub scope: String,
    #[serde(
        rename = "eventLevel",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub event_level: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFPageOptions {
    #[serde(default)]
    pub status: i32,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub body: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFCaptchaOptions {
    #[serde(
        rename = "captchaType",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub method: String,
    #[serde(rename = "life", default)]
    pub life_seconds: i32,
    #[serde(rename = "maxFails", default)]
    pub max_fails: i32,
    #[serde(rename = "failBlockTimeout", default)]
    pub fail_block_timeout: i32,
    #[serde(rename = "failBlockScopeAll", default)]
    pub fail_global: bool,
    #[serde(rename = "countLetters", default)]
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
    #[serde(rename = "challengeDifficulty", default)]
    pub challenge_difficulty: u8,
    #[serde(
        rename = "lang",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub challenge_lang: String,
    #[serde(rename = "geeTestConfig", default)]
    pub geetest_config: Option<WAFGeeTestConfig>,
    pub ui: Option<WAFCaptchaUIOptions>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFGeeTestConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "captchaId",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub captcha_id: String,
    #[serde(
        rename = "captchaKey",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub captcha_key: String,
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
    #[serde(rename = "life", default)]
    pub life_seconds: i32,
    #[serde(rename = "maxFails", default)]
    pub max_fails: i32,
    #[serde(rename = "failBlockTimeout", default)]
    pub fail_block_timeout: i32,
    #[serde(rename = "failBlockScopeAll", default)]
    pub fail_global: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TOAConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "sockPath",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub sock_file: String,
    #[serde(rename = "minLocalPort", default)]
    pub min_port: Option<u16>,
    #[serde(rename = "maxLocalPort", default)]
    pub max_port: Option<u16>,
}

pub type UAMPolicy = UAMConfig;

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
    #[serde(rename = "maxQPSPerIP", default)]
    pub max_qps_per_ip: i32,
    #[serde(rename = "maxBandwidthPerIP", default)]
    pub max_bandwidth_per_ip: f64,
    #[serde(rename = "blockPage", default)]
    pub block_page: HTTPCCBlockPageConfig,
    #[serde(rename = "blockIP", default)]
    pub block_ip: HTTPCCBlockIPConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPCCBlockPageConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default)]
    pub life: i32,
    #[serde(rename = "disableAccessLog", default)]
    pub disable_access_log: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPCCBlockIPConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default)]
    pub life: i32,
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
        rename = "extensions",
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
    #[serde(rename = "Map", default, deserialize_with = "deserialize_null_default")]
    pub r#map: std::collections::HashMap<String, Value>,
    #[serde(flatten, default)]
    pub extra: std::collections::HashMap<String, Value>,
}

impl DataMapConfig {
    pub fn len(&self) -> usize {
        self.r#map.len() + self.extra.len()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.r#map.get(key).or_else(|| self.extra.get(key))
    }
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
    #[serde(skip)]
    pub product_name: String,
    #[serde(rename = "enableServerAddrVariable", default)]
    pub enable_server_addr_variable: bool,
    #[serde(rename = "requestOriginsWithEncodings", default)]
    pub request_origins_with_encodings: bool,
    #[serde(rename = "xffMaxAddresses", default)]
    pub xff_max_addresses: i32,
    #[serde(rename = "allowLocalOrigins", default)]
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
    #[serde(rename = "connTimeout", default)]
    pub conn_timeout: Option<Value>,
    #[serde(rename = "readTimeout", default)]
    pub read_timeout: Option<Value>,
    #[serde(rename = "idleTimeout", default)]
    pub idle_timeout: Option<Value>,
    #[serde(rename = "writeTimeout", default)]
    pub write_timeout: Option<Value>,
    #[serde(rename = "autoReadTimeout", default)]
    pub auto_read_timeout: Option<Value>,
    #[serde(rename = "autoWriteTimeout", default)]
    pub auto_write_timeout: Option<Value>,
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
    #[serde(default)]
    pub stat: Option<GlobalStatConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GlobalStatConfig {
    #[serde(default)]
    pub upload: GlobalStatUploadConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct GlobalStatUploadConfig {
    #[serde(rename = "maxCities", default)]
    pub max_cities: i16,
    #[serde(rename = "maxProviders", default)]
    pub max_providers: i16,
    #[serde(rename = "maxSystems", default)]
    pub max_systems: i16,
    #[serde(rename = "maxBrowsers", default)]
    pub max_browsers: i16,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ProductConfig {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub version: String,
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
    #[serde(rename = "firewallOnly", default)]
    pub firewall_only: bool,
    #[serde(rename = "enableClientClosed", default)]
    pub enable_client_closed: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NodeConfigPayload {
    pub id: Option<i64>,
    #[serde(rename = "nodeId")]
    pub node_id: Option<String>,
    pub version: Option<i64>,
    #[serde(default)]
    pub edition: String,
    #[serde(
        rename = "servers",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub servers: Vec<ServerConfig>,
    #[serde(rename = "dataMap")]
    pub data_map: Option<DataMapConfig>,
    #[serde(
        rename = "metricItems",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub metric_items: Vec<MetricItemConfig>,
    #[serde(rename = "updatingServerListId", default)]
    pub updating_server_list_id: i64,
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
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub parent_nodes: std::collections::HashMap<String, Vec<ParentNodeConfig>>, // Map keys in JSON are always strings
    #[serde(rename = "globalServerConfig", default)]
    pub global_server_config: Option<GlobalServerConfig>,
    #[serde(rename = "productConfig", default)]
    pub product_config: Option<ProductConfig>,
    #[serde(
        rename = "globalPages",
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
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub http_cache_policies: Vec<HTTPCachePolicy>,
    #[serde(
        rename = "httpFirewallPolicies",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub http_firewall_policies: Vec<HTTPFirewallPolicy>,
    #[serde(
        rename = "wafActions",
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
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub ssl_certs: Vec<SSLCertConfig>,
    #[serde(rename = "sslPolicy")]
    pub ssl_policy: Option<SSLPolicyConfig>,
    #[serde(rename = "nodeRegion", default)]
    pub node_region: Option<NodeRegionConfig>,
    #[serde(rename = "nodeCluster", default)]
    pub node_cluster: Option<NodeClusterConfig>,
    #[serde(rename = "kernelFirewallMode", default)]
    pub kernel_firewall_mode: Option<String>,
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
    pub protocol: Option<String>,
    pub host: Option<String>,
    #[serde(rename = "portRange")]
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

    pub fn is_oss(&self) -> bool {
        self.protocol
            .as_deref()
            .map(|protocol| protocol.to_ascii_lowercase().starts_with("oss:"))
            .unwrap_or(false)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct ServerConfig {
    #[serde(default, deserialize_with = "deserialize_flexible_i64_opt")]
    pub id: Option<i64>,
    #[serde(
        rename = "description",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub description: String,
    #[serde(
        rename = "userId",
        default,
        deserialize_with = "deserialize_flexible_i64"
    )]
    pub user_id: i64,
    #[serde(
        rename = "clusterId",
        default,
        deserialize_with = "deserialize_flexible_i64"
    )]
    pub cluster_id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "serverNames",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub server_names: Vec<ServerNameConfig>,
    #[serde(rename = "http")]
    pub http: Option<HTTPConfig>,
    #[serde(rename = "https")]
    pub https: Option<HTTPSConfig>,
    #[serde(rename = "tcp")]
    pub tcp: Option<TCPConfig>,
    #[serde(rename = "udp")]
    pub udp: Option<UDPConfig>,
    #[serde(rename = "web")]
    pub web: Option<WebConfig>,
    #[serde(rename = "reverseProxy")]
    pub reverse_proxy: Option<ReverseProxyConfig>,
    #[serde(rename = "grpc")]
    pub grpc: Option<GRPCConfig>,
    #[serde(rename = "uam", default)]
    pub uam: Option<UAMConfig>,
    #[serde(rename = "trafficLimit", default)]
    pub traffic_limit: Option<TrafficLimitConfig>,
    #[serde(rename = "trafficLimitStatus", default)]
    pub traffic_limit_status: Option<TrafficLimitStatus>,
    #[serde(
        rename = "httpFirewallPolicyId",
        default,
        deserialize_with = "deserialize_flexible_i64"
    )]
    pub http_firewall_policy_id: i64,
    #[serde(rename = "httpFirewallPolicy", default)]
    pub http_firewall_policy: Option<HTTPFirewallPolicy>,
    #[serde(
        rename = "userPlanId",
        default,
        deserialize_with = "deserialize_flexible_i64"
    )]
    pub user_plan_id: i64,
    /// When enabled, the listener will attempt to parse an inbound PROXY
    /// Protocol v1/v2 header and use the reported source address as the true
    /// client IP.  Corresponds to the management-plane field
    /// `enableProxyProtocol`.
    #[serde(rename = "enableProxyProtocol", default)]
    pub enable_proxy_protocol: bool,
    #[serde(default, rename = "locations")]
    pub locations: Vec<LocationConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LocationConfig {
    #[serde(default, rename = "isOn")]
    pub is_on: bool,
    #[serde(default)]
    pub pattern: String,
    #[serde(default, rename = "patternType")]
    pub pattern_type: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default, rename = "reverseProxy")]
    pub reverse_proxy: Option<ReverseProxyConfig>,
    #[serde(default)]
    pub cache: Option<WebCacheConfig>,
}

impl ServerConfig {
    pub fn compile_url_patterns(&self) {
        if let Some(uam) = &self.uam {
            uam.compile_url_patterns();
        }
        if let Some(web) = &self.web {
            web.compile_url_patterns();
        }
    }

    pub(crate) fn normalize_runtime_server_name(name: &str) -> String {
        let trimmed = name.trim();
        let lower = trimmed.to_ascii_lowercase();
        for marker in ["@sni_passthrough", "@quic"] {
            if let Some(stripped) = lower.strip_suffix(marker) {
                let prefix_len = stripped.len();
                return trimmed[..prefix_len]
                    .trim_end_matches('@')
                    .to_ascii_lowercase();
            }
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
        self.has_server_name_marker("@sni_passthrough")
    }

    pub fn is_quic_passthrough(&self) -> bool {
        self.has_server_name_marker("@quic")
    }

    fn has_server_name_marker(&self, marker: &str) -> bool {
        self.server_names.iter().any(|sn| {
            sn.name.to_ascii_lowercase().ends_with(marker)
                || sn
                    .sub_names
                    .iter()
                    .any(|sub| sub.to_ascii_lowercase().ends_with(marker))
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
                        .is_some_and(|range| port_range_contains(range, port))
                })
            })
            .unwrap_or(false)
    }

    pub fn http3_enabled(&self) -> bool {
        self.https
            .as_ref()
            .is_some_and(|https| https.is_on && https.http3_enabled())
    }

    pub fn supports_http3_on_port(&self, port: u16) -> bool {
        self.http3_enabled() && self.listens_on_https_port(port)
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
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "listen",
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
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "listen",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub listen: Vec<NetworkAddressConfig>,
    #[serde(rename = "sslPolicy")]
    pub ssl_policy: Option<SSLPolicyConfig>,
    #[serde(rename = "http3Enabled", default)]
    pub supports_http3: Option<bool>,
}

impl HTTPSConfig {
    pub fn http3_enabled(&self) -> bool {
        self.supports_http3.unwrap_or(false)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TCPConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "listen",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub listen: Vec<NetworkAddressConfig>,
    pub tls: Option<HTTPSConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UDPConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(
        rename = "listen",
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
    #[serde(rename = "webp")]
    pub webp: Option<WebPConfig>,
    #[serde(rename = "userAgent")]
    pub user_agent_config: Option<UserAgentConfig>,
    #[serde(rename = "referers")]
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
    #[serde(rename = "preferWWW", default)]
    pub prefer_www: Option<String>,
    #[serde(rename = "trailingSlash", default)]
    pub trailing_slash: Option<String>,
}

impl WebConfig {
    pub fn compile_url_patterns(&self) {
        if let Some(cache) = &self.cache {
            cache.compile_url_patterns();
        }
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
        if let Some(firewall) = &self.firewall_policy {
            firewall.compile_url_patterns();
        }
        if let Some(uam) = &self.uam {
            uam.compile_url_patterns();
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
    #[serde(
        rename = "exceptDomains",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub except_domains: Vec<String>,
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
    /// When `type=requestHeader` and this field is non-empty, use this single
    /// header name as the authoritative source for the client IP, ignoring
    /// `value`/`values`.
    #[serde(
        rename = "requestHeaderName",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub request_header_name: String,
    /// Reserved for future location-block priority semantics. When true this
    /// config takes precedence over any enclosing scope's remote-addr rule.
    /// Currently recorded but not yet enforced (location blocks not yet
    /// implemented); enforcement will be added when the location-block system
    /// is introduced.
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
}

impl HTTPRemoteAddrConfig {
    fn normalized_type(&self) -> String {
        self.type_name
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase()
    }

    pub fn is_direct_type(&self) -> bool {
        self.normalized_type() == "default"
    }

    pub fn is_upper_proxy_type(&self) -> bool {
        self.normalized_type() == "proxy"
    }

    pub fn is_custom_variable_type(&self) -> bool {
        self.normalized_type() == "custom"
    }

    fn default_upper_proxy_headers() -> Vec<String> {
        [
            "X-Real-IP",
            "X-Forwarded-For",
            "CF-Connecting-IP",
            "True-Client-IP",
            "Ali-CDN-Real-IP",
            "CDN-Src-IP",
            "Forwarded",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    /// Returns the list of effective IP-source expressions.
    ///
    /// Priority: if `type=requestHeader` and `request_header_name` is set,
    /// return that single name so callers treat it as the sole header source.
    /// Otherwise fall back to `values` → `value`.
    pub fn configured_values(&self) -> Vec<String> {
        if self.is_request_header_type() && !self.request_header_name.is_empty() {
            return vec![self.request_header_name.clone()];
        }
        if self.is_upper_proxy_type() {
            return Self::default_upper_proxy_headers();
        }
        if !self.values.is_empty() {
            self.values.clone()
        } else if !self.value.is_empty() {
            vec![self.value.clone()]
        } else {
            Vec::new()
        }
    }

    pub fn is_request_header_type(&self) -> bool {
        matches!(
            self.normalized_type().as_str(),
            "requestheader" | "header" | "httpheader"
        ) || self.is_upper_proxy_type()
    }

    pub fn is_empty(&self) -> bool {
        !self.is_direct_type() && self.configured_values().is_empty()
    }

    /// Expand header-name expressions from `value`/`values` (or
    /// `request_header_name`) into a flat list of individual header names.
    /// Supports the multi-header syntax `${header.X-Forwarded-For,CF-Connecting-IP}`.
    pub fn expanded_header_names(&self) -> Vec<String> {
        let raw_list = self.configured_values();
        if raw_list.is_empty() {
            return Vec::new();
        }

        let mut out = Vec::new();
        for entry in raw_list {
            let trimmed = entry.trim();
            if let Some(inner) = trimmed.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
                let body = inner
                    .strip_prefix("header.")
                    .or_else(|| inner.strip_prefix("requestHeader."))
                    .unwrap_or(inner);
                for part in body.split(',') {
                    let name = part.trim().to_string();
                    if !name.is_empty() {
                        out.push(name);
                    }
                }
            } else if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
        out
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
        if !self.except_url_patterns.is_empty()
            && self
                .except_url_patterns
                .iter()
                .any(|pattern| pattern.matches(url))
        {
            return false;
        }
        if self.only_url_patterns.is_empty() {
            return true;
        }
        self.only_url_patterns
            .iter()
            .any(|pattern| pattern.matches(url))
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
        if !self.except_url_patterns.is_empty()
            && self
                .except_url_patterns
                .iter()
                .any(|pattern| pattern.matches(url))
        {
            return false;
        }
        if self.only_url_patterns.is_empty() {
            return true;
        }
        self.only_url_patterns
            .iter()
            .any(|pattern| pattern.matches(url))
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
        let pattern = Self::compiled_pattern(&Self::canonical_type(type_name), pattern)?;
        regex::Regex::new(&pattern).ok().map(Arc::new)
    }

    fn compiled_pattern(type_name: &str, pattern: &str) -> Option<String> {
        match type_name {
            "image" | "audio" | "video" => None,
            "regexp" => {
                if pattern.starts_with("(?i)") {
                    Some(pattern.to_string())
                } else {
                    Some(format!("(?i){}", pattern))
                }
            }
            "prefix" | "urlPrefix" | "url_prefix" | "dir" | "directory" => {
                if pattern.is_empty() {
                    return None;
                }
                let escaped = regex::escape(pattern.trim_end_matches('*').trim_end_matches('/'));
                if escaped.starts_with('/') {
                    Some(format!(
                        "(?i)^(?:(?:http|https)://[^/]+)?{}(?:/.*)?$",
                        escaped
                    ))
                } else {
                    Some(format!("(?i)^{}.*$", escaped))
                }
            }
            _ => {
                if pattern.is_empty() {
                    return None;
                }
                let escaped = regex::escape(pattern);
                let wildcard = escaped.replace("\\*", "(.*)");
                if wildcard.starts_with('/') {
                    Some(format!("(?i)^(?:(?:http|https)://[^/]+)?{}$", wildcard))
                } else {
                    Some(format!("(?i)^{}$", wildcard))
                }
            }
        }
    }

    fn canonical_type(type_name: &str) -> String {
        let normalized: String = type_name
            .trim()
            .chars()
            .filter(|ch| *ch != '-' && *ch != '_')
            .flat_map(char::to_lowercase)
            .collect();
        match normalized.as_str() {
            "regex" | "regexp" | "regular" | "regularexpression" => "regexp".to_string(),
            "prefix" | "urlprefix" | "pathprefix" | "dir" | "directory" => "prefix".to_string(),
            "image" | "images" | "img" | "commonimage" | "commonimages" => "image".to_string(),
            "audio" | "audios" | "commonaudio" | "commonaudios" => "audio".to_string(),
            "video" | "videos" | "commonvideo" | "commonvideos" => "video".to_string(),
            _ => "wildcard".to_string(),
        }
    }

    fn path_without_query_fragment(value: &str) -> &str {
        value
            .find(|ch| ch == '?' || ch == '#')
            .map(|idx| &value[..idx])
            .unwrap_or(value)
    }

    fn full_url_path(value: &str) -> Option<&str> {
        let scheme_idx = value.find("://")?;
        let after_scheme = &value[scheme_idx + 3..];
        let path_idx = after_scheme.find('/')?;
        Some(&after_scheme[path_idx..])
    }

    fn matches_regex_or_wildcard(&self, value: &str) -> bool {
        self.compiled
            .get_or_init(|| Self::compile_regex(&self.type_name, &self.pattern))
            .as_ref()
            .is_some_and(|re| re.is_match(value))
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
        let pattern_type = Self::canonical_type(&self.type_name);
        let stripped = Self::path_without_query_fragment(url);
        let path = Self::full_url_path(stripped)
            .map(Self::path_without_query_fragment)
            .unwrap_or(stripped);
        match pattern_type.as_str() {
            "image" => Self::is_image_url(path),
            "audio" => Self::is_audio_url(path),
            "video" => Self::is_video_url(path),
            _ if self.pattern.is_empty() => stripped.is_empty() || path.is_empty(),
            _ => {
                self.matches_regex_or_wildcard(stripped)
                    || (path != stripped && self.matches_regex_or_wildcard(path))
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UAMConfig {
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
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
    #[serde(
        rename = "minQPSPerIP",
        default,
        deserialize_with = "deserialize_flexible_i32"
    )]
    pub min_qps_per_ip: i32,
    #[serde(default)]
    pub conds: Option<HTTPRequestCondsConfig>,
    #[serde(
        rename = "keyLife",
        default,
        deserialize_with = "deserialize_flexible_i32"
    )]
    pub key_life: i32,
    #[serde(rename = "mode", default)]
    pub mode: Option<String>,
    #[serde(
        rename = "powDifficulty",
        default,
        deserialize_with = "deserialize_flexible_u8_opt"
    )]
    pub pow_difficulty: Option<u8>,
}

impl Default for UAMConfig {
    fn default() -> Self {
        Self {
            is_prior: false,
            is_on: false,
            only_url_patterns: Vec::new(),
            except_url_patterns: Vec::new(),
            min_qps_per_ip: 0,
            conds: None,
            key_life: 0,
            mode: None,
            pow_difficulty: None,
        }
    }
}

impl UAMConfig {
    pub fn compile_url_patterns(&self) {
        for pattern in &self.only_url_patterns {
            pattern.compile();
        }
        for pattern in &self.except_url_patterns {
            pattern.compile();
        }
    }

    pub fn matches_url(&self, url: &str) -> bool {
        if self
            .except_url_patterns
            .iter()
            .any(|pattern| pattern.matches(url))
        {
            return false;
        }
        if self.only_url_patterns.is_empty() {
            return true;
        }
        self.only_url_patterns
            .iter()
            .any(|pattern| pattern.matches(url))
    }
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

impl From<&HTTPCCPolicy> for CCPolicy {
    fn from(policy: &HTTPCCPolicy) -> Self {
        Self {
            is_on: policy.is_on,
            max_qps: policy.max_qps,
            per_ip_max_qps: policy.max_qps_per_ip,
            max_bandwidth: policy.max_bandwidth_per_ip,
            show_page: policy.block_page.is_on,
            block_ip: policy.block_ip.is_on,
            page_duration: policy.block_page.life,
            block_ip_duration: policy.block_ip.life,
            no_log: policy.block_page.disable_access_log,
        }
    }
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
    #[serde(rename = "domainsAll", default)]
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
    #[serde(rename = "portAfter", default)]
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
    pub conds: Option<HTTPRequestCondsConfig>,
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
    #[serde(rename = "purgeIsOn", default)]
    pub purge_is_on: bool,
    #[serde(
        rename = "purgeKey",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub purge_key: String,
    pub key: Option<HTTPCacheKeyConfig>,
    #[serde(
        rename = "cacheRefs",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub cache_refs: Vec<Arc<HTTPCacheRef>>,
    #[serde(rename = "cachePolicy")]
    pub cache_policy: Option<Arc<HTTPCachePolicy>>,
    #[serde(rename = "disablePolicyRefs", default)]
    pub disable_policy_refs: bool,
}

impl WebCacheConfig {
    pub fn compile_url_patterns(&self) {
        for cache_ref in &self.cache_refs {
            cache_ref.compile_url_patterns();
        }
        if let Some(policy) = &self.cache_policy {
            policy.compile_url_patterns();
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPCacheKeyConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub scheme: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub host: String,
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

impl HTTPCachePolicy {
    pub fn compile_url_patterns(&self) {
        for cache_ref in &self.cache_refs {
            cache_ref.compile_url_patterns();
        }
    }
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
    #[serde(rename = "skipSetCookie", default = "default_true")]
    pub skip_set_cookie: bool,
    #[serde(rename = "allowChunkedEncoding", default)]
    pub allow_chunked_encoding: bool,
    #[serde(rename = "allowPartialContent", default)]
    pub allow_partial_content: bool,
    #[serde(rename = "forcePartialContent", default)]
    pub force_partial_content: bool,
    #[serde(rename = "alwaysForwardRangeRequest", default)]
    pub always_forward_range_request: bool,
    #[serde(rename = "enableRequestCachePragma", default)]
    pub enable_request_cache_pragma: bool,
    #[serde(rename = "enableIfNoneMatch", default)]
    pub enable_if_none_match: bool,
    #[serde(rename = "enableIfModifiedSince", default)]
    pub enable_if_modified_since: bool,
    #[serde(rename = "enableReadingOriginAsync", default)]
    pub enable_reading_origin_async: bool,
    #[serde(rename = "isReverse", default)]
    pub is_reverse: bool,
    pub conds: Option<HTTPRequestCondsConfig>,
    #[serde(rename = "simpleCond")]
    pub simple_cond: Option<HTTPRequestCond>,
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
    #[serde(rename = "expiresTime")]
    pub expires_time: Option<HTTPExpiresTimeConfig>,
    #[serde(rename = "cachePolicy")]
    pub cache_policy: Option<Arc<HTTPCachePolicy>>,
}

impl HTTPCacheRef {
    pub fn compile_url_patterns(&self) {
        for pattern in self
            .only_url_patterns
            .iter()
            .chain(self.except_url_patterns.iter())
        {
            pattern.compile();
        }
        if let Some(policy) = &self.cache_policy {
            policy.compile_url_patterns();
        }
    }
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
    #[serde(rename = "ccConfig", default)]
    pub cc_config: Option<HTTPCCPolicy>,

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
    #[serde(rename = "candidateRules", default)]
    pub candidate_rules: Option<Vec<HTTPFirewallRule>>,
    #[serde(rename = "candidateTrafficPct", default)]
    pub candidate_traffic_pct: u8,
    #[serde(rename = "candidateVersion", default)]
    pub candidate_version: i64,
}

impl HTTPFirewallPolicy {
    pub fn compile_url_patterns(&self) {
        if let Some(inbound) = &self.inbound {
            inbound.compile_url_patterns();
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallRef {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "ignoreGlobalRules", default)]
    pub ignore_global_rules: bool,
    #[serde(
        rename = "defaultCaptchaType",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub default_captcha_type: String,
    #[serde(
        rename = "firewallPolicyId",
        default,
        deserialize_with = "deserialize_flexible_i64"
    )]
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

impl HTTPFirewallInboundConfig {
    pub fn compile_url_patterns(&self) {
        if let Some(region) = &self.region {
            region.compile_url_patterns();
        }
    }
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
    #[serde(rename = "allowSearchEngine", default)]
    pub allow_search_engine: bool,
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

impl HTTPFirewallRegionConfig {
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
        if !self.except_url_patterns.is_empty()
            && self
                .except_url_patterns
                .iter()
                .any(|pattern| pattern.matches(url))
        {
            return false;
        }
        if self.only_url_patterns.is_empty() {
            return true;
        }
        self.only_url_patterns
            .iter()
            .any(|pattern| pattern.matches(url))
    }
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

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct HTTPParamFilter {
    #[serde(rename = "code", default)]
    pub code: String, // "urlDecode" / "base64Decode" / "htmlDecode" / "toLowerCase" / "toUpperCase" / "md5" / "sha1" / "sha256" / "trim"
    #[serde(default)]
    pub options: HashMap<String, Value>,
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
    #[serde(
        rename = "paramFilters",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub param_filters: Vec<HTTPParamFilter>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct EmptyConnectionFloodConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "maxEmptyConnections", default)]
    pub max_empty_connections: u32,
    #[serde(default)]
    pub period: i32,
    #[serde(rename = "blockSeconds", default)]
    pub block_seconds: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct TLSExhaustionAttackConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "maxHandshakeFails", default)]
    pub max_handshake_fails: u32,
    #[serde(default)]
    pub period: i32,
    #[serde(rename = "blockSeconds", default)]
    pub block_seconds: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct SynFloodConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "minAttempts", default)]
    pub min_attempts: u32,
    #[serde(rename = "timeoutSeconds", default)]
    pub timeout_seconds: i32,
    #[serde(rename = "ignoreLocal", default)]
    pub ignore_local: bool,
    #[serde(rename = "isPrior", default)]
    pub is_prior: bool,
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
    #[serde(rename = "isRequest", default = "default_true")]
    pub is_request: bool,
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
    #[serde(skip)]
    allow_methods_header: std::sync::OnceLock<String>,
    #[serde(skip)]
    allow_headers_header: std::sync::OnceLock<String>,
    #[serde(skip)]
    expose_headers_header: std::sync::OnceLock<String>,
    #[serde(skip)]
    max_age_header: std::sync::OnceLock<String>,
}

impl CORSConfig {
    pub fn allow_methods_header(&self) -> &str {
        self.allow_methods_header
            .get_or_init(|| self.allow_methods.join(", "))
    }

    pub fn allow_headers_header(&self) -> &str {
        self.allow_headers_header
            .get_or_init(|| self.allow_headers.join(", "))
    }

    pub fn expose_headers_header(&self) -> &str {
        self.expose_headers_header
            .get_or_init(|| self.expose_headers.join(", "))
    }

    pub fn max_age_header(&self) -> &str {
        self.max_age_header.get_or_init(|| self.max_age.to_string())
    }
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
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "certData")]
    pub cert_data_json: Option<Value>,
    #[serde(rename = "keyData")]
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
    #[serde(rename = "isOn", default)]
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
    #[serde(
        rename = "proxyProtocol",
        default,
        deserialize_with = "deserialize_proxy_protocol_config"
    )]
    pub proxy_protocol: ProxyProtocolConfig,
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

    pub fn is_oss(&self) -> bool {
        match self {
            Self::Object(obj) => obj.is_oss(),
            Self::String(s) => s.trim().to_ascii_lowercase().starts_with("oss:"),
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

pub(crate) fn first_port_in_range(port_range: &str) -> Option<u16> {
    let raw = port_range.trim();
    let first = raw.split(['-', ':']).next().unwrap_or(raw).trim();
    first.parse::<u16>().ok()
}

pub(crate) fn ports_in_range(port_range: &str) -> Vec<u16> {
    let raw = port_range.trim();
    let Some((start, end)) = raw.split_once('-') else {
        return first_port_in_range(raw).into_iter().collect();
    };
    let Some(start) = first_port_in_range(start) else {
        return Vec::new();
    };
    let Some(end) = first_port_in_range(end) else {
        return Vec::new();
    };
    let (start, end) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };
    (start..=end).collect()
}

pub(crate) fn port_range_contains(port_range: &str, port: u16) -> bool {
    let raw = port_range.trim();
    let Some((start, end)) = raw.split_once('-') else {
        return first_port_in_range(raw) == Some(port);
    };
    let Some(start) = first_port_in_range(start) else {
        return false;
    };
    let Some(end) = first_port_in_range(end) else {
        return false;
    };
    let (start, end) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };
    (start..=end).contains(&port)
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OriginTlsSecurityVerifyMode {
    #[default]
    Auto,
    Force,
    Skip,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OriginConfig {
    pub id: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(rename = "addr")]
    pub addr: Option<FlexibleAddr>,
    #[serde(rename = "isOn", default = "default_true")]
    pub is_on: bool,
    #[serde(default)]
    pub weight: u32,
    #[serde(rename = "healthCheck")]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(
        rename = "requestHost",
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
    #[serde(rename = "http3Enabled", default)]
    pub http3_enabled: bool,
    #[serde(rename = "connTimeout", default)]
    pub conn_timeout: Option<Value>,
    #[serde(rename = "readTimeout", default)]
    pub read_timeout: Option<Value>,
    #[serde(rename = "idleTimeout", default)]
    pub idle_timeout: Option<Value>,
    #[serde(rename = "writeTimeout", default)]
    pub write_timeout: Option<Value>,
    pub cert: Option<SSLCertConfig>,
    #[serde(
        rename = "tlsSecurityVerifyMode",
        default,
        deserialize_with = "deserialize_origin_tls_security_verify_mode"
    )]
    pub tls_security_verify_mode: OriginTlsSecurityVerifyMode,
    #[serde(rename = "tlsVerify", default)]
    pub tls_verify: Option<Value>,
    #[serde(default)]
    pub oss: Option<Value>,
}

impl OriginConfig {
    pub fn is_oss(&self) -> bool {
        self.oss.is_some()
            || self
                .addr
                .as_ref()
                .map(FlexibleAddr::is_oss)
                .unwrap_or(false)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthCheckConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
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
    fn server_config_uses_exact_cluster_and_firewall_policy_fields() {
        let server: ServerConfig = serde_json::from_value(serde_json::json!({
            "id": 576,
            "clusterId": "12",
            "httpFirewallPolicyId": "34",
            "httpFirewallPolicy": {
                "id": 34,
                "isOn": true,
                "name": "embedded policy"
            }
        }))
        .expect("server config should parse cluster and firewall policy fields");

        assert_eq!(server.cluster_id, 12);
        assert_eq!(server.http_firewall_policy_id, 34);
        assert_eq!(
            server.http_firewall_policy.as_ref().map(|policy| policy.id),
            Some(34)
        );

        let legacy_server: ServerConfig = serde_json::from_value(serde_json::json!({
            "nodeClusterId": "15",
            "firewallPolicyId": "55"
        }))
        .expect("unknown legacy server keys should be ignored");
        assert_eq!(legacy_server.cluster_id, 0);
        assert_eq!(legacy_server.http_firewall_policy_id, 0);

        let unknown: ServerConfig =
            serde_json::from_value(serde_json::json!({})).expect("missing cluster should default");
        assert_eq!(unknown.cluster_id, 0);
    }

    #[test]
    fn http_cache_ref_parses_skip_set_cookie_as_exact_bool() {
        let enabled: HTTPCacheRef = serde_json::from_value(serde_json::json!({
            "skipSetCookie": true
        }))
        .expect("skipSetCookie should parse as a JSON bool");
        assert!(enabled.skip_set_cookie);

        let disabled: HTTPCacheRef = serde_json::from_value(serde_json::json!({
            "skipSetCookie": false
        }))
        .expect("explicit false should allow caching Set-Cookie responses");
        assert!(!disabled.skip_set_cookie);

        let missing: HTTPCacheRef =
            serde_json::from_value(serde_json::json!({})).expect("missing field should default");
        assert!(missing.skip_set_cookie);

        let string_false = serde_json::from_value::<HTTPCacheRef>(serde_json::json!({
            "skipSetCookie": "false"
        }));
        assert!(string_false.is_err());
    }

    #[test]
    fn http_cache_config_uses_exact_control_plane_field_names() {
        let payload: NodeConfigPayload = serde_json::from_value(serde_json::json!({
            "httpCachePolicies": [{
                "id": 1,
                "name": "policy",
                "cacheRefs": []
            }]
        }))
        .expect("exact httpCachePolicies should parse");
        assert_eq!(payload.http_cache_policies.len(), 1);

        let legacy_payload: NodeConfigPayload = serde_json::from_value(serde_json::json!({
            "HTTPCachePolicies": [{
                "id": 1,
                "name": "legacy",
                "cacheRefs": []
            }]
        }))
        .expect("unknown legacy cache policy key should be ignored");
        assert!(legacy_payload.http_cache_policies.is_empty());

        let cache_ref: HTTPCacheRef = serde_json::from_value(serde_json::json!({
            "onlyURLPatterns": [{"type": "prefix", "pattern": "/assets/"}],
            "exceptURLPatterns": [{"type": "prefix", "pattern": "/private/"}]
        }))
        .expect("exact URL pattern fields should parse");
        assert_eq!(cache_ref.only_url_patterns.len(), 1);
        assert_eq!(cache_ref.except_url_patterns.len(), 1);

        let legacy_cache_ref: HTTPCacheRef = serde_json::from_value(serde_json::json!({
            "onlyUrlPatterns": [{"type": "prefix", "pattern": "/assets/"}],
            "exceptUrlPatterns": [{"type": "prefix", "pattern": "/private/"}]
        }))
        .expect("unknown legacy URL pattern keys should be ignored");
        assert!(legacy_cache_ref.only_url_patterns.is_empty());
        assert!(legacy_cache_ref.except_url_patterns.is_empty());
    }

    #[test]
    fn node_config_payload_parses_snapshot_from_env_when_set() {
        let Ok(path) = std::env::var("CLOUD_NODE_CONFIG_SNAPSHOT") else {
            return;
        };
        let raw = std::fs::read(path).expect("snapshot should be readable");
        let payload: NodeConfigPayload =
            serde_json::from_slice(&raw).expect("snapshot should parse as NodeConfigPayload");
        assert!(!payload.servers.is_empty());
    }

    #[test]
    fn reverse_proxy_config_parses_proxy_protocol() {
        let v2: ReverseProxyConfig = serde_json::from_value(serde_json::json!({
            "isOn": true,
            "proxyProtocol": {
                "isOn": true,
                "version": 2
            }
        }))
        .expect("reverse proxy config should parse object proxyProtocol");

        assert!(v2.proxy_protocol.enabled());
        assert_eq!(v2.proxy_protocol.normalized_version(), 2);

        let disabled: ReverseProxyConfig = serde_json::from_value(serde_json::json!({}))
            .expect("missing proxyProtocol should default to false");
        assert!(!disabled.proxy_protocol.enabled());

        let null_disabled: ReverseProxyConfig = serde_json::from_value(serde_json::json!({
            "proxyProtocol": null
        }))
        .expect("null proxyProtocol should default to false");
        assert!(!null_disabled.proxy_protocol.enabled());

        let legacy_string = serde_json::from_value::<ReverseProxyConfig>(serde_json::json!({
            "proxyProtocol": "true"
        }));
        assert!(legacy_string.is_err());
    }

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
        assert!(wildcard.matches("/static/a/image.jpg"));
        assert!(
            (URLPattern {
                type_name: "wildcard".to_string(),
                pattern: "/hello/world/*".to_string(),
                ..Default::default()
            })
            .matches("/hello/world/a")
        );
        assert!(
            (URLPattern {
                type_name: "wildcard".to_string(),
                pattern: "*/hello/world".to_string(),
                ..Default::default()
            })
            .matches("/a/hello/world")
        );
        assert!(
            (URLPattern {
                type_name: "wildcard".to_string(),
                pattern: "*/article/*".to_string(),
                ..Default::default()
            })
            .matches("/news/article/123")
        );
        assert!(
            (URLPattern {
                type_name: "wildcard".to_string(),
                pattern: "*example.com/*".to_string(),
                ..Default::default()
            })
            .matches("https://example.com/a")
        );
        assert!(
            (URLPattern {
                type_name: "wildcard".to_string(),
                pattern: "*.js".to_string(),
                ..Default::default()
            })
            .matches("https://example.com/assets/app.js?v=1")
        );

        assert!(
            (URLPattern {
                type_name: "regexp".to_string(),
                pattern: "^/hello/world".to_string(),
                ..Default::default()
            })
            .matches("https://example.com/hello/world/a")
        );
        assert!(
            (URLPattern {
                type_name: "regexp".to_string(),
                pattern: "/hello/world$".to_string(),
                ..Default::default()
            })
            .matches("/a/hello/world")
        );
        assert!(
            (URLPattern {
                type_name: "regexp".to_string(),
                pattern: "/article/(\\d+)".to_string(),
                ..Default::default()
            })
            .matches("/article/123")
        );
        assert!(
            (URLPattern {
                type_name: "regexp".to_string(),
                pattern: "^(http|https)://example.com/".to_string(),
                ..Default::default()
            })
            .matches("https://example.com/article/123")
        );

        let prefix = URLPattern {
            type_name: "prefix".to_string(),
            pattern: "/static/".to_string(),
            ..Default::default()
        };
        assert!(prefix.matches("/static/a/image.jpg"));
        assert!(prefix.matches("https://example.com/static/a/image.jpg"));
        assert!(!prefix.matches("/assets/a/image.jpg"));

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
        assert!(image.matches("/static/photo.JPG?x=1"));
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
    fn waf_page_options_use_exact_control_plane_fields() {
        let options: WAFPageOptions = serde_json::from_value(serde_json::json!({
            "status": 403,
            "body": "<h1>Forbidden</h1>"
        }))
        .expect("WAF page options should parse exact control-plane fields");

        assert_eq!(options.status, 403);
        assert_eq!(options.body, "<h1>Forbidden</h1>");

        let legacy: WAFPageOptions = serde_json::from_value(serde_json::json!({
            "statusCode": 403,
            "contentHTML": "<h1>Forbidden</h1>"
        }))
        .expect("unknown legacy WAF page option keys should be ignored");
        assert_eq!(legacy.status, 0);
        assert_eq!(legacy.body, "");
    }

    #[test]
    fn node_config_payload_parses_global_http_exact_fields() {
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
                    "allowLocalOrigins": true,
                    "matchDomainStrictly": true,
                    "nodeIPShowPage": true,
                    "nodeIPPageHTML": "<h1>${host}</h1>",
                    "domainMismatchAction": {
                        "code": "page",
                        "options": {
                            "statusCode": 451,
                            "contentHTML": "blocked"
                        }
                    },
                    "connTimeout": 50,
                    "readTimeout": {"count": 10, "unit": "s"},
                    "idleTimeout": 0,
                    "autoReadTimeout": 15,
                    "autoWriteTimeout": "20"
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
        assert_eq!(
            http_all.conn_timeout.as_ref().and_then(|v| v.as_u64()),
            Some(50)
        );
        assert_eq!(
            http_all
                .read_timeout
                .as_ref()
                .and_then(|v| v.get("count"))
                .and_then(|v| v.as_u64()),
            Some(10)
        );
        assert_eq!(
            http_all.idle_timeout.as_ref().and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            http_all.auto_read_timeout.as_ref().and_then(|v| v.as_u64()),
            Some(15)
        );
        assert_eq!(
            http_all
                .auto_write_timeout
                .as_ref()
                .and_then(|v| v.as_str()),
            Some("20")
        );
    }

    #[test]
    fn node_config_payload_parses_product_config_exact_field() {
        let payload: NodeConfigPayload = serde_json::from_value(serde_json::json!({
            "productConfig": {
                "name": "摸鱼云CDN",
                "version": "1.1.5"
            }
        }))
        .expect("productConfig should parse");

        let product = payload
            .product_config
            .expect("productConfig should be present");
        assert_eq!(product.name, "摸鱼云CDN");
        assert_eq!(product.version, "1.1.5");
    }

    #[test]
    fn remote_addr_proxy_type_defaults_to_real_ip_then_forwarded_headers() {
        let cfg: HTTPRemoteAddrConfig = serde_json::from_value(serde_json::json!({
            "isOn": true,
            "type": "proxy",
            "value": "${remoteAddr}"
        }))
        .expect("remoteAddr should parse proxy type");

        assert!(cfg.is_request_header_type());
        assert!(cfg.is_upper_proxy_type());
        assert_eq!(
            cfg.expanded_header_names(),
            vec![
                "X-Real-IP",
                "X-Forwarded-For",
                "CF-Connecting-IP",
                "True-Client-IP",
                "Ali-CDN-Real-IP",
                "CDN-Src-IP",
                "Forwarded",
            ]
        );
    }

    #[test]
    fn remote_addr_accepts_request_header_name() {
        let cfg: HTTPRemoteAddrConfig = serde_json::from_value(serde_json::json!({
            "isOn": true,
            "type": "requestHeader",
            "requestHeaderName": "X-Forwarded-For",
            "value": "${header.X-Forwarded-For}"
        }))
        .expect("remoteAddr should parse request header type");

        assert!(cfg.is_request_header_type());
        assert_eq!(cfg.expanded_header_names(), vec!["X-Forwarded-For"]);
    }

    #[test]
    fn remote_addr_default_and_custom_types_match_control_plane_modes() {
        let direct: HTTPRemoteAddrConfig = serde_json::from_value(serde_json::json!({
            "isOn": true,
            "type": "default",
            "value": "${rawRemoteAddr}"
        }))
        .expect("remoteAddr should parse default type");
        assert!(direct.is_direct_type());
        assert!(!direct.is_empty());

        let custom: HTTPRemoteAddrConfig = serde_json::from_value(serde_json::json!({
            "isOn": true,
            "type": "custom",
            "value": "${header.X-Client-IP}"
        }))
        .expect("remoteAddr should parse custom type");
        assert!(custom.is_custom_variable_type());
        assert!(!custom.is_request_header_type());
        assert_eq!(custom.configured_values(), vec!["${header.X-Client-IP}"]);
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
    fn web_config_parses_auth_referer_and_user_agent_exact_fields() {
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
        .expect("web config should parse exact control-plane fields");

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

        let referers = web.referer_config.expect("referers should parse");
        assert!(referers.is_on);
        assert!(referers.allow_same_domain);
        assert_eq!(referers.allow_domains, vec!["*.example.com"]);
        assert_eq!(referers.deny_domains, vec!["bad.example.com"]);

        let ua = web.user_agent_config.expect("userAgent should parse");
        assert!(ua.is_on);
        assert_eq!(ua.filters[0].keywords, vec!["curl*", "BadBot"]);
        assert_eq!(ua.filters[0].action, "deny");

        let legacy: WebConfig = serde_json::from_value(serde_json::json!({
            "refererConfig": {"isOn": true},
            "userAgentConfig": {"isOn": true}
        }))
        .expect("unknown legacy web keys should be ignored");
        assert!(legacy.referer_config.is_none());
        assert!(legacy.user_agent_config.is_none());
    }

    #[test]
    fn global_server_config_parses_stat_upload_limits() {
        let payload: NodeConfigPayload = serde_json::from_value(serde_json::json!({
            "globalServerConfig": {
                "stat": {
                    "upload": {
                        "maxCities": 11,
                        "maxProviders": 12,
                        "maxSystems": 13,
                        "maxBrowsers": 14
                    }
                }
            }
        }))
        .expect("node config payload should parse stat upload config");

        let upload = payload
            .global_server_config
            .and_then(|global| global.stat)
            .map(|stat| stat.upload)
            .expect("stat upload config should be present");
        assert_eq!(upload.max_cities, 11);
        assert_eq!(upload.max_providers, 12);
        assert_eq!(upload.max_systems, 13);
        assert_eq!(upload.max_browsers, 14);
    }
}
