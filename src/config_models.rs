use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn default_connector() -> String {
    "or".to_string()
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ParentNodeConfig {
    pub id: i64,
    pub addr: NetworkAddressConfig,
    #[serde(default)]
    pub weight: u32,
    #[serde(rename = "isBackup", default)]
    pub is_backup: bool,
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
    #[serde(rename = "geetestId", default, deserialize_with = "deserialize_null_default")]
    pub geetest_id: String,
    #[serde(rename = "geetestKey", default, deserialize_with = "deserialize_null_default")]
    pub geetest_key: String,
    pub ui: Option<WAFCaptchaUIOptions>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct WAFCaptchaUIOptions {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub title: String,
    #[serde(rename = "buttonTitle", default, deserialize_with = "deserialize_null_default")]
    pub button_title: String,
    #[serde(rename = "showRequestId", default)]
    pub show_request_id: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub css: String,
    #[serde(rename = "promptHeader", default, deserialize_with = "deserialize_null_default")]
    pub prompt_header: String,
    #[serde(rename = "promptFooter", default, deserialize_with = "deserialize_null_default")]
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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NodeConfigPayload {
    #[serde(alias = "Id")]
    pub id: Option<i64>,
    #[serde(rename = "nodeId")]
    pub node_id: Option<String>,
    pub version: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub servers: Vec<ServerConfig>,
    #[serde(rename = "metricItems", default, deserialize_with = "deserialize_null_default")]
    pub metric_items: Vec<MetricItemConfig>,
    pub level: i32,
    #[serde(rename = "isCenter", default)]
    pub is_center: bool,
    #[serde(rename = "parentNodes", default, deserialize_with = "deserialize_null_default")]
    pub parent_nodes: std::collections::HashMap<i64, Vec<ParentNodeConfig>>,
    #[serde(rename = "httpCachePolicies", default, deserialize_with = "deserialize_null_default")]
    pub http_cache_policies: Vec<HTTPCachePolicy>,
    #[serde(rename = "httpFirewallPolicies", default, deserialize_with = "deserialize_null_default")]
    pub http_firewall_policies: Vec<HTTPFirewallPolicy>,
    #[serde(rename = "wafActions", default, deserialize_with = "deserialize_null_default")]
    pub waf_actions: Vec<WAFActionConfig>,
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
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub value: String,
    pub period: i32,
    #[serde(rename = "periodUnit", default, deserialize_with = "deserialize_null_default")]
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
        format!("{}:{}", self.host.as_deref().unwrap_or("127.0.0.1"), self.port_range.as_deref().unwrap_or("80"))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub id: Option<i64>,
    #[serde(rename = "userId")]
    pub user_id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "serverNames", default, deserialize_with = "deserialize_null_default")]
    pub server_names: Vec<String>,
    pub http: Option<HTTPConfig>,
    pub https: Option<HTTPSConfig>,
    pub tcp: Option<TCPConfig>,
    pub udp: Option<UDPConfig>,
    pub web: Option<WebConfig>,
    #[serde(rename = "reverseProxy")]
    pub reverse_proxy: Option<ReverseProxyConfig>,
    #[serde(rename = "userPlanId", default)]
    pub user_plan_id: i64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub listen: Vec<NetworkAddressConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPSConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub listen: Vec<NetworkAddressConfig>,
    #[serde(rename = "sslCerts", default, deserialize_with = "deserialize_null_default")]
    pub ssl_certs: Vec<SSLCertConfig>,
    #[serde(rename = "sslPolicy")]
    pub ssl_policy: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TCPConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub listen: Vec<NetworkAddressConfig>,
    pub tls: Option<HTTPSConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UDPConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub listen: Vec<NetworkAddressConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WebConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub cache: Option<WebCacheConfig>,
    #[serde(rename = "firewallPolicy")]
    pub firewall_policy: Option<HTTPFirewallPolicy>,
    pub compression: Option<HTTPCompressionConfig>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub pages: Vec<HTTPPageConfig>,
    pub auth: Option<HTTPAuthConfig>,
    pub websocket: Option<WebSocketConfig>,
    #[serde(rename = "maxQPS", default)]
    pub max_qps: i32,
    pub uam: Option<UAMConfig>,
    #[serde(rename = "ccPolicy")]
    pub cc_policy: Option<CCPolicy>,
    #[serde(rename = "userAgentConfig")]
    pub user_agent_config: Option<UserAgentConfig>,
    #[serde(rename = "refererConfig")]
    pub referer_config: Option<ReferersConfig>,
    #[serde(rename = "hostRedirects", default, deserialize_with = "deserialize_null_default")]
    pub host_redirects: Vec<HTTPHostRedirectConfig>,
    #[serde(rename = "rewriteRefs", default, deserialize_with = "deserialize_null_default")]
    pub rewrite_refs: Vec<HTTPRewriteRef>,
    #[serde(rename = "rewriteRules", default, deserialize_with = "deserialize_null_default")]
    pub rewrite_rules: Vec<HTTPRewriteRule>,
    #[serde(rename = "requestHeaderPolicy")]
    pub request_header_policy: Option<HTTPHeaderPolicy>,
    #[serde(rename = "responseHeaderPolicy")]
    pub response_header_policy: Option<HTTPHeaderPolicy>,
    #[serde(rename = "accessLogRef")]
    pub access_log_ref: Option<HTTPAccessLogRef>,
    pub root: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WebSocketConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UAMConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
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
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ReferersConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPHostRedirectConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub before: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub after: String,
    #[serde(rename = "beforeHost")]
    pub before_host: Option<String>,
    #[serde(rename = "afterHost")]
    pub after_host: Option<String>,
    #[serde(rename = "statusCode", default)]
    pub status_code: i32,
    #[serde(rename = "keepRequestURI", default)]
    pub keep_request_uri: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPRewriteRef {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPRewriteRule {
    pub id: Option<i64>,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub pattern: Option<String>,
    pub replace: Option<String>,
    #[serde(rename = "withQuery", default)]
    pub with_query: bool,
    pub mode: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPAuthConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WebCacheConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "cacheRefs", default, deserialize_with = "deserialize_null_default")]
    pub cache_refs: Vec<HTTPCacheRef>,
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
    #[serde(rename = "cacheRefs", default, deserialize_with = "deserialize_null_default")]
    pub cache_refs: Vec<HTTPCacheRef>,
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
    #[serde(rename = "skipCacheControlValues", default, deserialize_with = "deserialize_null_default")]
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
    #[serde(rename = "denyCountryHTML", default)]
    pub deny_country_html: String,
    #[serde(rename = "denyProvinceHTML", default)]
    pub deny_province_html: String,
    #[serde(rename = "useLocalFirewall", default)]
    pub use_local_firewall: bool,
    #[serde(rename = "synFlood", default)]
    pub syn_flood: Option<Value>,
    #[serde(default)]
    pub mode: String, // "defense" or "observe"
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallInboundConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub groups: Vec<HTTPFirewallRuleGroup>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallOutboundConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub groups: Vec<HTTPFirewallRuleGroup>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPFirewallRuleGroup {
    pub id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
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
pub struct HTTPHeaderPolicy {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "setHeaders", default, deserialize_with = "deserialize_null_default")]
    pub set_headers: Vec<HTTPHeaderConfig>,
    #[serde(rename = "addHeaders", default, deserialize_with = "deserialize_null_default")]
    pub add_headers: Vec<HTTPHeaderConfig>,
    #[serde(rename = "deleteHeaders", default, deserialize_with = "deserialize_null_default")]
    pub delete_headers: Vec<String>,
    #[serde(rename = "replaceHeaders", default, deserialize_with = "deserialize_null_default")]
    pub replace_headers: Vec<HTTPHeaderReplaceConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPHeaderConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPHeaderReplaceConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(rename = "oldValue", default, deserialize_with = "deserialize_null_default")]
    pub old_value: String,
    #[serde(rename = "newValue", default, deserialize_with = "deserialize_null_default")]
    pub new_value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HTTPPageConfig {
    pub id: i64,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub status: Option<String>,
    pub body: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "newStatus", default)]
    pub new_status: i32,
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
    #[serde(rename = "certDataJSON")]
    pub cert_data_json: Option<Value>,
    #[serde(rename = "keyDataJSON")]
    pub key_data_json: Option<Value>,
    #[serde(rename = "dnsNames", default, deserialize_with = "deserialize_null_default")]
    pub dns_names: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ReverseProxyConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(rename = "primaryOrigins", default, deserialize_with = "deserialize_null_default")]
    pub primary_origins: Vec<OriginConfig>,
    #[serde(rename = "backupOrigins", default, deserialize_with = "deserialize_null_default")]
    pub backup_origins: Vec<OriginConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OriginConfig {
    pub id: i64,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    pub addr: Option<NetworkAddressConfig>,
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    pub weight: u32,
    #[serde(rename = "healthCheck")]
    pub health_check: Option<HealthCheckConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HealthCheckConfig {
    #[serde(rename = "isOn", default)]
    pub is_on: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub url: String,
    pub interval: Option<Value>,
    pub timeout: Option<Value>,
    #[serde(rename = "statusCodes", default, deserialize_with = "deserialize_null_default")]
    pub status_codes: Vec<i32>,
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
        serde_json::from_value(v.clone()).unwrap_or(Self { count: 0, unit: "b".to_string() })
    }

    pub fn to_bytes(&self) -> i64 {
        match self.unit.to_lowercase().as_str() {
            "kb" | "k" => self.count * 1024,
            "mb" | "m" => self.count * 1024 * 1024,
            "gb" | "g" => self.count * 1024 * 1024 * 1024,
            _ => self.count,
        }
    }
}

pub fn parse_life_to_seconds(v: &Value) -> u64 {
    if let Some(count) = v.get("count").and_then(|c| c.as_u64()) {
        let unit = v.get("unit").and_then(|u| u.as_str()).unwrap_or("s");
        return match unit.to_lowercase().as_str() {
            "m" | "min" => count * 60,
            "h" | "hour" => count * 3600,
            "d" | "day" => count * 86400,
            _ => count,
        };
    }
    3600
}
