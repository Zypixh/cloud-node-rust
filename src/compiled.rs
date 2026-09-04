use crate::cache::compiled::{CompiledCachePolicy, CompiledWebCachePlan};
use crate::config_models::{
    HSTSConfig, HTTPAuthConfig, HTTPBaseOptimizationConfig, HTTPCachePolicy, HTTPCharsetConfig,
    HTTPFirewallPolicy, HTTPPageConfig, HTTPPageOptimizationConfig, HTTPRedirectToHttpsConfig,
    HTTPRequestLimitConfig, HTTPShutdownConfig, ReferersConfig, ServerConfig, SizeCapacity,
    URLPattern, UserAgentConfig, WebPConfig, WebSocketConfig,
};
use base64::{Engine as _, engine::general_purpose};
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(test)]
use std::sync::OnceLock;

#[derive(Clone, Debug, Default)]
pub struct CompiledPlanSet {
    pub global_firewall: Vec<Arc<crate::firewall::compiled::CompiledFirewallPolicy>>,
    pub global_cache: Vec<Arc<CompiledCachePolicy>>,
    pub server_firewall: HashMap<i64, Arc<crate::firewall::compiled::CompiledFirewallPolicy>>,
    pub server_cache: HashMap<i64, Arc<CompiledWebCachePlan>>,
    pub server_headers: HashMap<i64, Arc<crate::headers::CompiledServerHeaderPlan>>,
    pub server_rewrite: HashMap<i64, Arc<crate::rewrite::CompiledServerRewritePlan>>,
    pub server_features: HashMap<i64, Arc<CompiledServerFeaturePlan>>,
}

#[derive(Clone, Debug, Default)]
pub struct CompiledServerFeaturePlan {
    optimization: Option<CompiledOptimizationPlan>,
    hls_encrypting: Option<CompiledUrlPatternSet>,
    webp: Option<CompiledWebPPlan>,
    referers: Option<CompiledReferersPlan>,
    user_agent: Option<CompiledUserAgentPlan>,
    redirect_to_https: Option<CompiledRedirectToHttpsPlan>,
    websocket: Option<CompiledWebSocketPlan>,
    hsts: Option<CompiledHstsPlan>,
    auth: Option<CompiledAuthPlan>,
    request_limit: Option<CompiledRequestLimitPlan>,
    charset: Option<CompiledCharsetPlan>,
    shutdown: Option<CompiledShutdownPlan>,
    pages: Option<CompiledPagePlan>,
}

impl CompiledServerFeaturePlan {
    pub fn compile(server: &ServerConfig) -> Option<Self> {
        let web = server.web.as_ref()?;
        let optimization = web
            .optimization
            .as_ref()
            .and_then(CompiledOptimizationPlan::compile);
        let hls_encrypting = web
            .hls
            .as_ref()
            .and_then(|hls| hls.encrypting.as_ref())
            .filter(|encrypting| encrypting.is_on)
            .map(|encrypting| {
                CompiledUrlPatternSet::compile(
                    &encrypting.only_url_patterns,
                    &encrypting.except_url_patterns,
                )
            });
        let webp = web.webp.as_ref().and_then(CompiledWebPPlan::compile);
        let referers = web
            .referer_config
            .as_ref()
            .and_then(CompiledReferersPlan::compile);
        let user_agent = web
            .user_agent_config
            .as_ref()
            .and_then(CompiledUserAgentPlan::compile);
        let redirect_to_https = web
            .redirect_to_https
            .as_ref()
            .and_then(CompiledRedirectToHttpsPlan::compile);
        let websocket = web
            .websocket
            .as_ref()
            .and_then(CompiledWebSocketPlan::compile);
        let hsts = server
            .https
            .as_ref()
            .and_then(|https| https.ssl_policy.as_ref())
            .and_then(|ssl_policy| ssl_policy.hsts.as_ref())
            .and_then(CompiledHstsPlan::compile);
        let auth = web.auth.as_ref().and_then(CompiledAuthPlan::compile);
        let request_limit = web
            .request_limit
            .as_ref()
            .and_then(CompiledRequestLimitPlan::compile);
        let charset = web.charset.as_ref().and_then(CompiledCharsetPlan::compile);
        let shutdown = web
            .shutdown
            .as_ref()
            .and_then(CompiledShutdownPlan::compile);
        let pages = CompiledPagePlan::compile(&web.pages);
        (optimization.is_some()
            || hls_encrypting.is_some()
            || webp.is_some()
            || referers.is_some()
            || user_agent.is_some()
            || redirect_to_https.is_some()
            || websocket.is_some()
            || hsts.is_some()
            || auth.is_some()
            || request_limit.is_some()
            || charset.is_some()
            || shutdown.is_some()
            || pages.is_some())
        .then_some(Self {
            optimization,
            hls_encrypting,
            webp,
            referers,
            user_agent,
            redirect_to_https,
            websocket,
            hsts,
            auth,
            request_limit,
            charset,
            shutdown,
            pages,
        })
    }

    pub fn has_optimization(&self) -> bool {
        self.optimization.is_some()
    }

    pub fn optimization_kind(&self, content_type: &str, request_url: &str) -> Option<&'static str> {
        self.optimization
            .as_ref()
            .and_then(|optimization| optimization.kind(content_type, request_url))
    }

    /// Returns whether any response optimization rule can match this URL.
    /// The response content type is not known during request cache admission,
    /// so callers use this conservative predicate to avoid caching a body
    /// before a later optimization filter can change it.
    pub fn optimization_matches_url(&self, request_url: &str) -> bool {
        self.optimization.as_ref().is_some_and(|optimization| {
            optimization
                .html
                .as_ref()
                .is_some_and(|patterns| patterns.matches_url(request_url))
                || optimization
                    .css
                    .as_ref()
                    .is_some_and(|patterns| patterns.matches_url(request_url))
                || optimization
                    .javascript
                    .as_ref()
                    .is_some_and(|patterns| patterns.matches_url(request_url))
        })
    }

    pub fn has_hls_encrypting(&self) -> bool {
        self.hls_encrypting.is_some()
    }

    pub fn hls_encrypting_matches(&self, request_url: &str) -> bool {
        self.hls_encrypting
            .as_ref()
            .is_some_and(|patterns| patterns.matches_url(request_url))
    }

    pub fn webp_matches_request(&self, path: &str, accept: &str) -> bool {
        self.webp
            .as_ref()
            .is_some_and(|webp| webp.matches_request(path, accept))
    }

    pub fn webp_mime_matches(&self, content_type: &str) -> bool {
        self.webp
            .as_ref()
            .is_some_and(|webp| webp.mime_matches(content_type))
    }

    pub fn webp_min_bytes(&self) -> Option<i64> {
        self.webp.as_ref().map(|webp| webp.min_bytes)
    }

    pub fn webp_max_bytes(&self) -> Option<i64> {
        self.webp.as_ref().map(|webp| webp.max_bytes)
    }

    pub fn referer_allows(
        &self,
        request_url: &str,
        source_host: &str,
        request_host: &str,
    ) -> Option<bool> {
        self.referers
            .as_ref()
            .map(|referers| referers.allows(request_url, source_host, request_host))
    }

    pub fn user_agent_action(&self, request_url: &str, user_agent: &str) -> Option<Option<bool>> {
        self.user_agent
            .as_ref()
            .map(|user_agent_plan| user_agent_plan.action(request_url, user_agent))
    }

    pub fn redirect_to_https_target(&self, host: &str, request_uri: &str) -> Option<(String, u16)> {
        self.redirect_to_https
            .as_ref()
            .and_then(|redirect| redirect.target(host, request_uri))
    }

    pub fn websocket_origin_allowed(&self, origin_host: &str) -> Option<bool> {
        self.websocket
            .as_ref()
            .map(|websocket| websocket.origin_allowed(origin_host))
    }

    pub fn hsts_header_value(&self, host: &str) -> Option<&str> {
        self.hsts.as_ref().and_then(|hsts| hsts.header_value(host))
    }

    pub fn has_auth(&self) -> bool {
        self.auth.is_some()
    }

    pub fn auth_result(
        &self,
        host: &str,
        path: &str,
        authorization: Option<&str>,
    ) -> Option<CompiledAuthResult> {
        self.auth
            .as_ref()
            .and_then(|auth| auth.result(host, path, authorization))
    }

    pub fn request_limit(&self) -> Option<&CompiledRequestLimitPlan> {
        self.request_limit.as_ref()
    }

    pub fn charset_content_type(&self, current: &str) -> Option<String> {
        self.charset
            .as_ref()
            .and_then(|charset| charset.content_type(current))
    }

    pub fn shutdown(&self) -> Option<&CompiledShutdownPlan> {
        self.shutdown.as_ref()
    }

    pub fn custom_page_for_status(&self, status: u16) -> Option<HTTPPageConfig> {
        self.pages
            .as_ref()
            .and_then(|pages| pages.page_for_status(status))
    }
}

#[derive(Clone, Debug)]
struct CompiledPagePlan {
    pages: Vec<CompiledPageConfig>,
}

impl CompiledPagePlan {
    fn compile(pages: &[HTTPPageConfig]) -> Option<Self> {
        let pages: Vec<_> = pages
            .iter()
            .filter(|page| page.is_on)
            .map(CompiledPageConfig::compile)
            .collect();
        (!pages.is_empty()).then_some(Self { pages })
    }

    fn page_for_status(&self, status: u16) -> Option<HTTPPageConfig> {
        self.pages
            .iter()
            .find(|page| page.matches(status))
            .map(|page| page.raw.clone())
    }
}

#[derive(Clone, Debug)]
struct CompiledPageConfig {
    raw: HTTPPageConfig,
    status: CompiledPageStatus,
}

impl CompiledPageConfig {
    fn compile(page: &HTTPPageConfig) -> Self {
        Self {
            raw: page.clone(),
            status: CompiledPageStatus::compile(page.status.as_ref()),
        }
    }

    fn matches(&self, status: u16) -> bool {
        self.status.matches(status)
    }
}

#[derive(Clone, Debug)]
enum CompiledPageStatus {
    Any,
    One(u16),
    AnyOf(Vec<u16>),
    Never,
}

impl CompiledPageStatus {
    fn compile(value: Option<&Value>) -> Self {
        let Some(value) = value else {
            return Self::Any;
        };
        match value {
            Value::Number(number) => number
                .as_u64()
                .and_then(|status| u16::try_from(status).ok())
                .map(Self::One)
                .unwrap_or(Self::Never),
            Value::String(status) => {
                if status.trim().is_empty() || status == "*" {
                    Self::Any
                } else {
                    status.parse::<u16>().map(Self::One).unwrap_or(Self::Never)
                }
            }
            Value::Array(values) => {
                let statuses: Vec<_> = values
                    .iter()
                    .filter_map(|item| match item {
                        Value::Number(number) => number
                            .as_u64()
                            .and_then(|status| u16::try_from(status).ok()),
                        Value::String(status) => status.parse::<u16>().ok(),
                        _ => None,
                    })
                    .collect();
                if statuses.is_empty() {
                    Self::Never
                } else {
                    Self::AnyOf(statuses)
                }
            }
            _ => Self::Never,
        }
    }

    fn matches(&self, status: u16) -> bool {
        match self {
            Self::Any => true,
            Self::One(expected) => *expected == status,
            Self::AnyOf(expected) => expected.contains(&status),
            Self::Never => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledAuthResult {
    pub ok: bool,
    pub realm: String,
    pub charset: Option<String>,
    pub auth_type: String,
}

#[derive(Clone, Debug)]
struct CompiledAuthPlan {
    policies: Vec<CompiledAuthPolicy>,
}

impl CompiledAuthPlan {
    fn compile(config: &HTTPAuthConfig) -> Option<Self> {
        if !config.is_on {
            return None;
        }
        Some(Self {
            policies: config
                .policy_refs
                .iter()
                .filter(|policy_ref| policy_ref.is_on)
                .filter_map(|policy_ref| policy_ref.auth_policy.as_ref())
                .filter(|policy| policy.is_on && policy.auth_type == "basicAuth")
                .map(CompiledAuthPolicy::compile)
                .collect(),
        })
    }

    fn result(
        &self,
        host: &str,
        path: &str,
        authorization: Option<&str>,
    ) -> Option<CompiledAuthResult> {
        for policy in &self.policies {
            let result = policy.result(host, path, authorization)?;
            return Some(result);
        }
        None
    }
}

#[derive(Clone, Debug)]
struct CompiledAuthPolicy {
    auth_type: String,
    domains: Vec<CompiledWildcardDomainPattern>,
    exts: Vec<String>,
    realm: String,
    charset: Option<String>,
    users: Vec<(String, String)>,
}

impl CompiledAuthPolicy {
    fn compile(policy: &crate::config_models::HTTPAuthPolicy) -> Self {
        let domains = json_string_vec(&policy.params, "domains")
            .iter()
            .map(|domain| CompiledWildcardDomainPattern::compile(domain))
            .collect();
        let exts = json_string_vec(&policy.params, "exts")
            .into_iter()
            .map(|ext| ext.to_ascii_lowercase())
            .collect();
        let realm = policy
            .params
            .get("realm")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let charset = policy
            .params
            .get("charset")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let users = policy
            .params
            .get("users")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some((
                            item.get("username")?.as_str()?.to_string(),
                            item.get("password")?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            auth_type: policy.auth_type.clone(),
            domains,
            exts,
            realm,
            charset,
            users,
        }
    }

    fn result(
        &self,
        host: &str,
        path: &str,
        authorization: Option<&str>,
    ) -> Option<CompiledAuthResult> {
        if !self.domains.is_empty() && !self.domains.iter().any(|domain| domain.matches(host)) {
            return None;
        }
        if !self.exts.is_empty() {
            let path = path.to_ascii_lowercase();
            if !self.exts.iter().any(|ext| {
                if ext.starts_with('.') {
                    path.ends_with(ext)
                } else {
                    path.ends_with(&format!(".{}", ext))
                }
            }) {
                return None;
            }
        }
        Some(CompiledAuthResult {
            ok: authorization
                .and_then(authenticated_basic_user)
                .is_some_and(|(username, password)| {
                    self.users
                        .iter()
                        .any(|(expected_username, expected_password)| {
                            expected_username == &username && expected_password == &password
                        })
                }),
            realm: self.realm.clone(),
            charset: self.charset.clone(),
            auth_type: self.auth_type.clone(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct CompiledRequestLimitPlan {
    pub max_body_bytes: i64,
    pub max_conns: i32,
    pub max_conns_per_ip: i32,
    pub out_bandwidth_per_conn_bytes: i64,
}

impl CompiledRequestLimitPlan {
    fn compile(config: &HTTPRequestLimitConfig) -> Option<Self> {
        config.is_on.then_some(Self {
            max_body_bytes: config.max_body_bytes_value(),
            max_conns: config.max_conns,
            max_conns_per_ip: config.max_conns_per_ip,
            out_bandwidth_per_conn_bytes: config.out_bandwidth_per_conn_bytes_value(),
        })
    }
}

#[derive(Clone, Debug)]
struct CompiledCharsetPlan {
    charset: String,
    force: bool,
}

impl CompiledCharsetPlan {
    fn compile(config: &HTTPCharsetConfig) -> Option<Self> {
        if !config.is_on || config.charset.is_empty() {
            return None;
        }
        Some(Self {
            charset: if config.is_upper {
                config.charset.to_ascii_uppercase()
            } else {
                config.charset.clone()
            },
            force: config.force,
        })
    }

    fn content_type(&self, current: &str) -> Option<String> {
        let current = current.trim();
        if current.is_empty() {
            return None;
        }
        let mut mime = current.to_string();
        if self.force
            && let Some((head, _)) = current.split_once(';')
        {
            mime = head.trim().to_string();
        }
        if !TEXT_MIME_TYPES
            .iter()
            .any(|allowed| mime.eq_ignore_ascii_case(allowed))
        {
            return None;
        }
        Some(format!("{}; charset={}", mime, self.charset))
    }
}

#[derive(Clone, Debug)]
pub struct CompiledShutdownPlan {
    pub status: u16,
    pub body_type: String,
    pub url: String,
    pub body: String,
}

impl CompiledShutdownPlan {
    fn compile(config: &HTTPShutdownConfig) -> Option<Self> {
        if !config.is_on {
            return None;
        }
        Some(Self {
            status: u16::try_from(config.status)
                .ok()
                .filter(|code| (100..=599).contains(code))
                .unwrap_or(200),
            body_type: config.body_type.to_ascii_lowercase(),
            url: config.url.clone(),
            body: config.body.clone(),
        })
    }

    pub fn redirect_target(&self) -> Option<(&str, u16)> {
        if self.body_type != "redirecturl" {
            return None;
        }
        let target = if self.url.is_empty() { "/" } else { &self.url };
        let status = if matches!(self.status, 301 | 302 | 307 | 308) {
            self.status
        } else {
            307
        };
        Some((target, status))
    }
}

const TEXT_MIME_TYPES: &[&str] = &[
    "text/html",
    "text/css",
    "text/javascript",
    "text/plain",
    "application/javascript",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "image/svg+xml",
];

fn json_string_vec(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(|value| serde_json::from_value::<Vec<String>>(value.clone()).ok())
        .unwrap_or_default()
}

fn authenticated_basic_user(auth: &str) -> Option<(String, String)> {
    let encoded = auth.trim().strip_prefix("Basic ")?;
    let decoded = general_purpose::STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8_lossy(&decoded);
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

#[derive(Clone, Debug)]
struct CompiledRedirectToHttpsPlan {
    host: String,
    port: i32,
    status: u16,
    domains: Vec<CompiledSuffixDomainPattern>,
    except_domains: Vec<CompiledSuffixDomainPattern>,
}

impl CompiledRedirectToHttpsPlan {
    fn compile(config: &HTTPRedirectToHttpsConfig) -> Option<Self> {
        config.is_on.then_some(Self {
            host: config.host.clone(),
            port: config.port,
            status: redirect_to_https_status(config.status),
            domains: config
                .domains
                .iter()
                .map(|domain| CompiledSuffixDomainPattern::compile(domain))
                .collect(),
            except_domains: config
                .except_domains
                .iter()
                .map(|domain| CompiledSuffixDomainPattern::compile(domain))
                .collect(),
        })
    }

    fn target(&self, host: &str, request_uri: &str) -> Option<(String, u16)> {
        if self
            .except_domains
            .iter()
            .any(|domain| domain.matches(host))
        {
            return None;
        }
        if !self.domains.is_empty() && !self.domains.iter().any(|domain| domain.matches(host)) {
            return None;
        }
        let target_host = if !self.host.is_empty() {
            if self.port > 0 && self.port != 443 {
                format!("{}:{}", self.host, self.port)
            } else {
                self.host.clone()
            }
        } else if self.port > 0 && self.port != 443 {
            format!("{}:{}", host, self.port)
        } else {
            host.to_string()
        };
        Some((
            format!("https://{}{}", target_host, request_uri),
            self.status,
        ))
    }
}

#[derive(Clone, Debug)]
struct CompiledWebSocketPlan {
    allow_all_origins: bool,
    allowed_origins: Vec<CompiledWildcardDomainPattern>,
}

impl CompiledWebSocketPlan {
    fn compile(config: &WebSocketConfig) -> Option<Self> {
        config.is_on.then_some(Self {
            allow_all_origins: config.allow_all_origins,
            allowed_origins: config
                .allowed_origins
                .iter()
                .map(|origin| CompiledWildcardDomainPattern::compile(origin))
                .collect(),
        })
    }

    fn origin_allowed(&self, origin_host: &str) -> bool {
        self.allow_all_origins
            || self
                .allowed_origins
                .iter()
                .any(|origin| origin.matches(origin_host))
    }
}

#[derive(Clone, Debug)]
struct CompiledHstsPlan {
    domains: Vec<CompiledWildcardDomainPattern>,
    header_value: String,
}

impl CompiledHstsPlan {
    fn compile(config: &HSTSConfig) -> Option<Self> {
        config.is_on.then_some(Self {
            domains: config
                .domains
                .iter()
                .map(|domain| CompiledWildcardDomainPattern::compile(domain))
                .collect(),
            header_value: hsts_header_value(config),
        })
    }

    fn header_value(&self, host: &str) -> Option<&str> {
        (self.domains.is_empty() || self.domains.iter().any(|domain| domain.matches(host)))
            .then_some(self.header_value.as_str())
    }
}

#[derive(Clone, Debug)]
struct CompiledSuffixDomainPattern {
    suffix: String,
}

impl CompiledSuffixDomainPattern {
    fn compile(domain: &str) -> Self {
        Self {
            suffix: domain.trim().trim_start_matches('.').to_ascii_lowercase(),
        }
    }

    fn matches(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        !self.suffix.is_empty()
            && (host == self.suffix || host.ends_with(&format!(".{}", self.suffix)))
    }
}

fn redirect_to_https_status(status: i32) -> u16 {
    u16::try_from(status)
        .ok()
        .filter(|code| matches!(*code, 301 | 302 | 307 | 308))
        .unwrap_or(301)
}

fn hsts_header_value(hsts: &HSTSConfig) -> String {
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

#[derive(Clone, Debug)]
struct CompiledReferersPlan {
    allow_empty: bool,
    allow_same_domain: bool,
    allow_domains: Vec<CompiledWildcardDomainPattern>,
    deny_domains: Vec<CompiledWildcardDomainPattern>,
    url_patterns: CompiledUrlPatternSet,
}

impl CompiledReferersPlan {
    fn compile(config: &ReferersConfig) -> Option<Self> {
        config.is_on.then_some(Self {
            allow_empty: config.allow_empty,
            allow_same_domain: config.allow_same_domain,
            allow_domains: config
                .allow_domains
                .iter()
                .map(|pattern| CompiledWildcardDomainPattern::compile(pattern))
                .collect(),
            deny_domains: config
                .deny_domains
                .iter()
                .map(|pattern| CompiledWildcardDomainPattern::compile(pattern))
                .collect(),
            url_patterns: CompiledUrlPatternSet::compile(
                &config.only_url_patterns,
                &config.except_url_patterns,
            ),
        })
    }

    fn allows(&self, request_url: &str, source_host: &str, request_host: &str) -> bool {
        if !self.url_patterns.matches_url_raw(request_url) {
            return true;
        }
        if source_host.is_empty() {
            self.allow_empty
        } else if self.allow_same_domain && source_host.eq_ignore_ascii_case(request_host) {
            true
        } else if self.allow_domains.is_empty() {
            !self.deny_domains.is_empty()
                && !self
                    .deny_domains
                    .iter()
                    .any(|pattern| pattern.matches(source_host))
        } else {
            self.allow_domains
                .iter()
                .any(|pattern| pattern.matches(source_host))
                && !self
                    .deny_domains
                    .iter()
                    .any(|pattern| pattern.matches(source_host))
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledUserAgentPlan {
    url_patterns: CompiledUrlPatternSet,
    filters: Vec<CompiledUserAgentFilter>,
}

impl CompiledUserAgentPlan {
    fn compile(config: &UserAgentConfig) -> Option<Self> {
        config.is_on.then_some(Self {
            url_patterns: CompiledUrlPatternSet::compile(
                &config.only_url_patterns,
                &config.except_url_patterns,
            ),
            filters: config
                .filters
                .iter()
                .map(|filter| CompiledUserAgentFilter {
                    allow: filter.action == "allow",
                    keywords: filter
                        .keywords
                        .iter()
                        .map(|keyword| CompiledUserAgentKeyword::compile(keyword))
                        .collect(),
                })
                .collect(),
        })
    }

    fn action(&self, request_url: &str, user_agent: &str) -> Option<bool> {
        if !self.url_patterns.matches_url_raw(request_url) {
            return None;
        }
        for filter in &self.filters {
            if filter.keywords.is_empty() {
                continue;
            }
            if filter
                .keywords
                .iter()
                .any(|keyword| keyword.matches(user_agent))
            {
                return Some(filter.allow);
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
struct CompiledUserAgentFilter {
    allow: bool,
    keywords: Vec<CompiledUserAgentKeyword>,
}

#[derive(Clone, Debug)]
enum CompiledUserAgentKeyword {
    Empty,
    Contains(String),
    Regex(Option<Arc<Regex>>),
}

impl CompiledUserAgentKeyword {
    fn compile(keyword: &str) -> Self {
        if keyword.is_empty() {
            Self::Empty
        } else if keyword.contains('*') {
            let pattern = regex::escape(keyword).replace("\\*", ".*");
            Self::Regex(Regex::new(&format!("(?i){}", pattern)).ok().map(Arc::new))
        } else {
            Self::Contains(keyword.to_ascii_lowercase())
        }
    }

    fn matches(&self, user_agent: &str) -> bool {
        match self {
            Self::Empty => user_agent.is_empty(),
            Self::Contains(keyword) => user_agent.to_ascii_lowercase().contains(keyword),
            Self::Regex(regex) => regex
                .as_ref()
                .is_some_and(|regex| regex.is_match(user_agent)),
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledWildcardDomainPattern {
    exact: String,
    suffix: Option<String>,
    regex: Option<Arc<Regex>>,
}

impl CompiledWildcardDomainPattern {
    fn compile(pattern: &str) -> Self {
        let pattern = crate::lb_factory::strip_addr_port(pattern)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let suffix = pattern.strip_prefix("*.").map(str::to_string);
        let regex = if suffix.is_none() && pattern.contains('*') {
            let escaped = regex::escape(&pattern).replace("\\*", ".*");
            Regex::new(&format!("(?i)^{}$", escaped)).ok().map(Arc::new)
        } else {
            None
        };
        Self {
            exact: pattern,
            suffix,
            regex,
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let domain = crate::lb_factory::strip_addr_port(domain)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if self.exact == domain {
            return true;
        }
        if let Some(suffix) = &self.suffix {
            return domain == *suffix || domain.ends_with(&format!(".{}", suffix));
        }
        self.regex
            .as_ref()
            .is_some_and(|regex| regex.is_match(&domain))
    }
}

#[derive(Clone, Debug)]
struct CompiledOptimizationPlan {
    html: Option<CompiledUrlPatternSet>,
    css: Option<CompiledUrlPatternSet>,
    javascript: Option<CompiledUrlPatternSet>,
}

impl CompiledOptimizationPlan {
    fn compile(optimization: &HTTPPageOptimizationConfig) -> Option<Self> {
        let html = optimization
            .html
            .as_ref()
            .filter(|cfg| cfg.is_on)
            .map(|cfg| CompiledUrlPatternSet::compile_base(&cfg.base));
        let css = optimization
            .css
            .as_ref()
            .filter(|cfg| cfg.is_on)
            .map(|cfg| CompiledUrlPatternSet::compile_base(&cfg.base));
        let javascript = optimization
            .javascript
            .as_ref()
            .filter(|cfg| cfg.is_on)
            .map(|cfg| CompiledUrlPatternSet::compile_base(&cfg.base));
        (html.is_some() || css.is_some() || javascript.is_some()).then_some(Self {
            html,
            css,
            javascript,
        })
    }

    fn kind(&self, content_type: &str, request_url: &str) -> Option<&'static str> {
        if content_type == "text/html" || content_type == "application/xhtml+xml" {
            self.html
                .as_ref()
                .filter(|patterns| patterns.matches_url(request_url))
                .map(|_| "html")
        } else if content_type == "text/css" {
            self.css
                .as_ref()
                .filter(|patterns| patterns.matches_url(request_url))
                .map(|_| "css")
        } else if content_type == "text/javascript"
            || content_type == "application/javascript"
            || content_type == "application/x-javascript"
        {
            self.javascript
                .as_ref()
                .filter(|patterns| patterns.matches_url(request_url))
                .map(|_| "js")
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledWebPPlan {
    mime_types: Vec<String>,
    file_extensions: Vec<String>,
    min_bytes: i64,
    max_bytes: i64,
}

impl CompiledWebPPlan {
    fn compile(webp: &WebPConfig) -> Option<Self> {
        webp.is_on.then_some(Self {
            mime_types: webp
                .mime_types
                .iter()
                .map(|mime| mime.to_ascii_lowercase())
                .collect(),
            file_extensions: webp
                .file_extensions
                .iter()
                .map(|extension| extension.to_ascii_lowercase())
                .collect(),
            min_bytes: webp
                .min_length
                .as_ref()
                .map(SizeCapacity::from_json)
                .map(|size| size.to_bytes())
                .unwrap_or(0),
            max_bytes: webp
                .max_length
                .as_ref()
                .map(SizeCapacity::from_json)
                .map(|size| size.to_bytes())
                .unwrap_or(0),
        })
    }

    fn matches_request(&self, path: &str, accept: &str) -> bool {
        if !accept.contains("image/webp") {
            return false;
        }
        if self.file_extensions.is_empty() {
            return true;
        }
        let ext = std::path::Path::new(&path.to_ascii_lowercase())
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{}", value.to_ascii_lowercase()))
            .unwrap_or_default();
        self.file_extensions
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&ext))
    }

    fn mime_matches(&self, content_type: &str) -> bool {
        if self.mime_types.is_empty() {
            return true;
        }
        let content_type = content_type.to_ascii_lowercase();
        self.mime_types
            .iter()
            .any(|mime| content_type.starts_with(mime))
    }
}

#[derive(Clone, Debug)]
struct CompiledUrlPatternSet {
    only: Vec<CompiledUrlPattern>,
    except: Vec<CompiledUrlPattern>,
}

#[cfg(test)]
impl CompiledUrlPatternSet {
    fn test_compile(only: &[URLPattern], except: &[URLPattern]) -> Self {
        Self::compile(only, except)
    }
}

impl CompiledUrlPatternSet {
    fn compile_base(base: &HTTPBaseOptimizationConfig) -> Self {
        Self::compile(&base.only_url_patterns, &base.except_url_patterns)
    }

    fn compile(only: &[URLPattern], except: &[URLPattern]) -> Self {
        Self {
            only: only.iter().map(CompiledUrlPattern::compile).collect(),
            except: except.iter().map(CompiledUrlPattern::compile).collect(),
        }
    }

    fn matches_url(&self, url: &str) -> bool {
        self.matches_url_raw(url)
    }

    fn matches_url_raw(&self, url: &str) -> bool {
        if !self.except.is_empty() && self.except.iter().any(|pattern| pattern.matches(url)) {
            return false;
        }
        self.only.is_empty() || self.only.iter().any(|pattern| pattern.matches(url))
    }
}

#[derive(Clone, Debug)]
enum CompiledUrlPattern {
    Images,
    Audios,
    Videos,
    Regex(Option<Arc<Regex>>),
}

impl CompiledUrlPattern {
    fn compile(pattern: &URLPattern) -> Self {
        match canonical_url_pattern_type(&pattern.type_name).as_str() {
            "image" => Self::Images,
            "audio" => Self::Audios,
            "video" => Self::Videos,
            _ => Self::Regex(compile_url_pattern_regex(
                &pattern.type_name,
                &pattern.pattern,
            )),
        }
    }

    fn matches(&self, url: &str) -> bool {
        let stripped = url_without_query_fragment(url);
        let path = full_url_path(stripped)
            .map(url_without_query_fragment)
            .unwrap_or(stripped);
        match self {
            Self::Images => has_any_ascii_suffix(
                path,
                &[
                    ".apng", ".avif", ".gif", ".jpg", ".jpeg", ".jfif", ".pjpeg", ".pjp", ".png",
                    ".svg", ".webp", ".bmp", ".ico", ".cur", ".tif", ".tiff",
                ],
            ),
            Self::Audios => has_any_ascii_suffix(
                path,
                &[
                    ".mp3", ".flac", ".wav", ".aac", ".ogg", ".m4a", ".wma", ".m3u8",
                ],
            ),
            Self::Videos => has_any_ascii_suffix(
                path,
                &[
                    ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".mpeg", ".3gp", ".webm", ".ts",
                    ".m3u8",
                ],
            ),
            Self::Regex(regex) => regex.as_ref().is_some_and(|regex| {
                regex.is_match(stripped) || (path != stripped && regex.is_match(path))
            }),
        }
    }
}

fn compile_url_pattern_regex(type_name: &str, pattern: &str) -> Option<Arc<Regex>> {
    if pattern.is_empty() {
        return Regex::new("^$").ok().map(Arc::new);
    }
    let pattern = match canonical_url_pattern_type(type_name).as_str() {
        "regexp" => {
            if pattern.starts_with("(?i)") {
                pattern.to_string()
            } else {
                format!("(?i){}", pattern)
            }
        }
        "prefix" => {
            let escaped = regex::escape(pattern.trim_end_matches('*').trim_end_matches('/'));
            if escaped.starts_with('/') {
                format!("(?i)^(?:(?:http|https)://[^/]+)?{}(?:/.*)?$", escaped)
            } else {
                format!("(?i)^{}.*$", escaped)
            }
        }
        _ => {
            let escaped = regex::escape(pattern);
            let wildcard = escaped.replace("\\*", "(.*)");
            if wildcard.starts_with('/') {
                format!("(?i)^(?:(?:http|https)://[^/]+)?{}$", wildcard)
            } else {
                format!("(?i)^{}$", wildcard)
            }
        }
    };
    Regex::new(&pattern).ok().map(Arc::new)
}

fn canonical_url_pattern_type(type_name: &str) -> String {
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

fn url_without_query_fragment(value: &str) -> &str {
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

fn has_any_ascii_suffix(value: &str, suffixes: &[&str]) -> bool {
    let value = value.as_bytes();
    suffixes.iter().any(|suffix| {
        let suffix = suffix.as_bytes();
        value.len() >= suffix.len()
            && value[value.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    })
}

impl CompiledPlanSet {
    pub fn compile(
        global_firewall_policies: &[HTTPFirewallPolicy],
        global_cache_policies: &[Arc<HTTPCachePolicy>],
        servers: &[Arc<ServerConfig>],
    ) -> Self {
        let global_firewall = global_firewall_policies
            .iter()
            .map(crate::firewall::compiled::CompiledFirewallPolicy::compile)
            .map(Arc::new)
            .collect();
        let global_cache = global_cache_policies
            .iter()
            .map(CompiledCachePolicy::compile_arc)
            .collect();
        let server_firewall = servers
            .iter()
            .filter_map(|server| {
                let policy = server
                    .web
                    .as_ref()
                    .and_then(|web| web.firewall_policy.as_ref())?;
                Some((
                    server.numeric_id(),
                    Arc::new(crate::firewall::compiled::CompiledFirewallPolicy::compile(
                        policy,
                    )),
                ))
            })
            .collect();
        let server_cache = servers
            .iter()
            .filter_map(|server| {
                Some((
                    server.numeric_id(),
                    Arc::new(CompiledWebCachePlan::compile(server)?),
                ))
            })
            .collect();
        let server_headers = servers
            .iter()
            .filter_map(|server| {
                Some((
                    server.numeric_id(),
                    Arc::new(crate::headers::CompiledServerHeaderPlan::compile(server)?),
                ))
            })
            .collect();
        let server_rewrite = servers
            .iter()
            .filter_map(|server| {
                Some((
                    server.numeric_id(),
                    Arc::new(crate::rewrite::CompiledServerRewritePlan::compile(server)?),
                ))
            })
            .collect();
        let server_features = servers
            .iter()
            .filter_map(|server| {
                Some((
                    server.numeric_id(),
                    Arc::new(CompiledServerFeaturePlan::compile(server)?),
                ))
            })
            .collect();
        Self {
            global_firewall,
            global_cache,
            server_firewall,
            server_cache,
            server_headers,
            server_rewrite,
            server_features,
        }
    }

    fn remove_server_id(&mut self, server_id: i64) {
        self.server_firewall.remove(&server_id);
        self.server_cache.remove(&server_id);
        self.server_headers.remove(&server_id);
        self.server_rewrite.remove(&server_id);
        self.server_features.remove(&server_id);
    }

    fn insert_server(&mut self, server: &ServerConfig) {
        let id = server.numeric_id();
        self.remove_server_id(id);
        if let Some(policy) = server
            .web
            .as_ref()
            .and_then(|web| web.firewall_policy.as_ref())
        {
            self.server_firewall.insert(
                id,
                Arc::new(crate::firewall::compiled::CompiledFirewallPolicy::compile(
                    policy,
                )),
            );
        }
        if let Some(plan) = CompiledWebCachePlan::compile(server) {
            self.server_cache.insert(id, Arc::new(plan));
        }
        if let Some(plan) = crate::headers::CompiledServerHeaderPlan::compile(server) {
            self.server_headers.insert(id, Arc::new(plan));
        }
        if let Some(plan) = crate::rewrite::CompiledServerRewritePlan::compile(server) {
            self.server_rewrite.insert(id, Arc::new(plan));
        }
        if let Some(plan) = CompiledServerFeaturePlan::compile(server) {
            self.server_features.insert(id, Arc::new(plan));
        }
    }

    /// Keep global compiled plans and rewrite only the changed server entries.
    /// This avoids allocating a full derived index for every site on a
    /// single-site hot reload.
    pub fn recompile_servers(&self, added: &[Arc<ServerConfig>], removed_ids: &[i64]) -> Self {
        let mut next = self.clone();
        for server_id in removed_ids {
            next.remove_server_id(*server_id);
        }
        for server in added {
            next.insert_server(server);
        }
        next
    }

    pub fn compile_firewall(
        global_policies: &[HTTPFirewallPolicy],
        servers: &[Arc<ServerConfig>],
    ) -> Self {
        Self::compile(global_policies, &[], servers)
    }

    pub fn is_empty(&self) -> bool {
        self.global_firewall.is_empty()
            && self.global_cache.is_empty()
            && self.server_firewall.is_empty()
            && self.server_cache.is_empty()
            && self.server_headers.is_empty()
            && self.server_rewrite.is_empty()
            && self.server_features.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(type_name: &str, value: &str) -> URLPattern {
        URLPattern {
            type_name: type_name.to_string(),
            pattern: value.to_string(),
            compiled: OnceLock::new(),
        }
    }

    #[test]
    fn compiled_url_patterns_support_mixed_only_and_except_rules() {
        let patterns = CompiledUrlPatternSet::test_compile(
            &[
                pattern("wildcard", "*/article/*"),
                pattern("regexp", r"/download/(\d+)"),
                pattern("regexp", r"^(http|https)://example.com/files/"),
                pattern("image", ""),
            ],
            &[pattern("wildcard", "*.js"), pattern("video", "")],
        );

        assert!(patterns.matches_url("https://example.com/news/article/123"));
        assert!(patterns.matches_url("/download/42"));
        assert!(patterns.matches_url("https://example.com/files/archive.zip"));
        assert!(patterns.matches_url("/assets/photo.JPG?x=1"));
        assert!(!patterns.matches_url("/assets/app.js?v=1"));
        assert!(!patterns.matches_url("/assets/movie.mp4"));
        assert!(!patterns.matches_url("/other/path"));
    }

    #[test]
    fn recompile_servers_removes_and_inserts_without_full_rebuild_panic() {
        let first = Arc::new(ServerConfig {
            id: Some(11),
            is_on: true,
            ..Default::default()
        });
        let second = Arc::new(ServerConfig {
            id: Some(12),
            is_on: true,
            ..Default::default()
        });
        let plans = CompiledPlanSet::compile(&[], &[], &[Arc::clone(&first), Arc::clone(&second)]);
        let replacement = Arc::new(ServerConfig {
            id: Some(13),
            is_on: true,
            ..Default::default()
        });
        let next = plans.recompile_servers(&[replacement], &[11]);
        assert!(next.server_features.get(&11).is_none());
        let _ = second;
        let _ = next;
    }
}
