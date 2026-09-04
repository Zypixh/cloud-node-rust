use crate::config_models::{
    CORSConfig, HTTPHeaderConfig, HTTPHeaderPolicy, HTTPHeaderReplaceConfig,
    HTTPHeaderReplaceValue, HTTPStatusConfig,
};
use crate::utils::template::format_template;
use dashmap::DashMap;
use http::HeaderValue;
use http::header::HeaderName;
use pingora_proxy::Session;
use regex::Regex;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;

static HEADER_NAME_CACHE: Lazy<DashMap<String, Option<HeaderName>>> = Lazy::new(DashMap::new);

fn cached_header_name(name: &str) -> Option<HeaderName> {
    if let Some(cached) = HEADER_NAME_CACHE.get(name) {
        return cached.clone();
    }
    let parsed = HeaderName::from_str(name).ok();
    HEADER_NAME_CACHE.insert(name.to_string(), parsed.clone());
    parsed
}

fn template_contains_any(value: &str, names: &[&str]) -> bool {
    value.contains("${") && names.iter().any(|name| value.contains(name))
}

#[derive(Clone, Debug, Default)]
pub struct CompiledServerHeaderPlan {
    pub request: Option<CompiledHeaderPolicy>,
    pub response: Option<CompiledHeaderPolicy>,
    pub cors: Option<CompiledCorsPolicy>,
}

impl CompiledServerHeaderPlan {
    pub fn compile(server: &crate::config_models::ServerConfig) -> Option<Self> {
        let web = server.web.as_ref()?;
        let request = web
            .request_header_policy
            .as_ref()
            .filter(|policy| policy.is_on)
            .map(CompiledHeaderPolicy::compile);
        let response = web
            .response_header_policy
            .as_ref()
            .filter(|policy| policy.is_on)
            .map(CompiledHeaderPolicy::compile);
        let cors = web
            .response_header_policy
            .as_ref()
            .and_then(|policy| policy.cors.as_ref())
            .and_then(CompiledCorsPolicy::compile);
        (request.is_some() || response.is_some() || cors.is_some()).then_some(Self {
            request,
            response,
            cors,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CompiledCorsPolicy {
    pub options_method_only: bool,
    allow_origin: Option<HeaderValue>,
    allow_methods: HeaderValue,
    allow_headers: Option<HeaderValue>,
    max_age: Option<HeaderValue>,
    expose_headers: Option<HeaderValue>,
}

impl CompiledCorsPolicy {
    fn compile(cors: &CORSConfig) -> Option<Self> {
        if !cors.is_on {
            return None;
        }
        Some(Self {
            options_method_only: cors.options_method_only,
            allow_origin: (!cors.allow_origin.is_empty())
                .then(|| HeaderValue::from_str(&cors.allow_origin).ok())
                .flatten(),
            allow_methods: if cors.allow_methods.is_empty() {
                HeaderValue::from_static("PUT, GET, POST, DELETE, HEAD, OPTIONS, PATCH")
            } else {
                HeaderValue::from_str(&cors.allow_methods.join(", ")).unwrap_or_else(|_| {
                    HeaderValue::from_static("PUT, GET, POST, DELETE, HEAD, OPTIONS, PATCH")
                })
            },
            allow_headers: (!cors.allow_headers.is_empty())
                .then(|| HeaderValue::from_str(&cors.allow_headers.join(", ")).ok())
                .flatten(),
            max_age: (cors.max_age > 0)
                .then(|| HeaderValue::from_str(&cors.max_age.to_string()).ok())
                .flatten(),
            expose_headers: (!cors.expose_headers.is_empty())
                .then(|| HeaderValue::from_str(&cors.expose_headers.join(", ")).ok())
                .flatten(),
        })
    }

    pub fn applies_to_request(&self, is_options: bool) -> bool {
        !self.options_method_only || is_options
    }

    pub fn apply(&self, resp: &mut pingora_http::ResponseHeader, session: &Session) {
        // Fetch spec forbids combining `Allow-Origin: *` with
        // `Allow-Credentials: true`; track whether the wildcard is emitted.
        let mut origin_is_wildcard = false;
        if let Some(allow_origin) = &self.allow_origin {
            let _ = resp.insert_header("access-control-allow-origin", allow_origin.clone());
            origin_is_wildcard = allow_origin.as_bytes() == b"*";
        } else {
            if let Some(origin) = session.get_header("origin") {
                let _ = resp.insert_header("access-control-allow-origin", origin.clone());
            }
            let _ = resp.insert_header("vary", HeaderValue::from_static("Origin"));
        }
        let _ = resp.insert_header("access-control-allow-methods", self.allow_methods.clone());
        if let Some(allow_headers) = &self.allow_headers {
            let _ = resp.insert_header("access-control-allow-headers", allow_headers.clone());
        } else if let Some(req_headers) = session.get_header("access-control-request-headers") {
            let _ = resp.insert_header("access-control-allow-headers", req_headers.clone());
        }
        if let Some(max_age) = &self.max_age {
            let _ = resp.insert_header("access-control-max-age", max_age.clone());
        }
        if let Some(expose_headers) = &self.expose_headers {
            let _ = resp.insert_header("access-control-expose-headers", expose_headers.clone());
        }
        if !origin_is_wildcard {
            let _ = resp.insert_header(
                "access-control-allow-credentials",
                HeaderValue::from_static("true"),
            );
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompiledHeaderPolicy {
    pub raw: Arc<HTTPHeaderPolicy>,
    delete_headers: Vec<CompiledHeaderName>,
    set_headers: Vec<CompiledHeaderConfig>,
    add_headers: Vec<CompiledHeaderConfig>,
    replace_headers: Vec<CompiledHeaderReplaceConfig>,
    deleted_lowercase: Vec<String>,
    uses_template_vars: bool,
    needs_request_uri: bool,
    needs_port: bool,
}

impl CompiledHeaderPolicy {
    pub fn compile(policy: &HTTPHeaderPolicy) -> Self {
        let set_headers = policy
            .set_headers
            .iter()
            .map(CompiledHeaderConfig::compile)
            .collect::<Vec<_>>();
        let add_headers = policy
            .add_headers
            .iter()
            .map(CompiledHeaderConfig::compile)
            .collect::<Vec<_>>();
        let delete_headers = policy
            .delete_headers
            .iter()
            .map(|name| CompiledHeaderName::compile(name))
            .collect::<Vec<_>>();
        let deleted_lowercase = policy
            .delete_headers
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let uses_template_vars = set_headers
            .iter()
            .chain(add_headers.iter())
            .any(|header| header.is_on && header.value_template.uses_vars());
        let needs_request_uri = set_headers
            .iter()
            .chain(add_headers.iter())
            .any(|header| header.is_on && header.value_template.contains_vars(&["requestURI"]));
        let needs_port = set_headers.iter().chain(add_headers.iter()).any(|header| {
            header.is_on && header.value_template.contains_vars(&["port", "serverPort"])
        });
        Self {
            raw: Arc::new(policy.clone()),
            delete_headers,
            set_headers,
            add_headers,
            replace_headers: policy
                .replace_headers
                .iter()
                .map(CompiledHeaderReplaceConfig::compile)
                .collect(),
            deleted_lowercase,
            uses_template_vars,
            needs_request_uri,
            needs_port,
        }
    }

    pub fn uses_template_vars(&self) -> bool {
        self.uses_template_vars
    }

    pub fn needs_request_uri(&self) -> bool {
        self.needs_request_uri
    }

    pub fn needs_port(&self) -> bool {
        self.needs_port
    }

    fn deletes_header(&self, name: &str) -> bool {
        self.deleted_lowercase
            .iter()
            .any(|deleted| deleted.eq_ignore_ascii_case(name))
    }
}

#[derive(Clone, Debug)]
struct CompiledHeaderName {
    raw: String,
    parsed: Option<HeaderName>,
}

impl CompiledHeaderName {
    fn compile(name: &str) -> Self {
        Self {
            raw: name.to_string(),
            parsed: HeaderName::from_str(name).ok(),
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledHeaderConfig {
    is_on: bool,
    name: CompiledHeaderName,
    value_template: CompiledHeaderTemplate,
    status: CompiledHeaderStatus,
    disable_redirect: bool,
    should_append: bool,
    should_replace: bool,
    replace_values: Vec<CompiledHeaderReplaceValue>,
    methods: Vec<String>,
    domains: CompiledDomainMatcher,
}

impl CompiledHeaderConfig {
    fn compile(header: &HTTPHeaderConfig) -> Self {
        Self {
            is_on: header.is_on,
            name: CompiledHeaderName::compile(&header.name),
            value_template: CompiledHeaderTemplate::compile(&header.value),
            status: CompiledHeaderStatus::compile(header.status.as_ref()),
            disable_redirect: header.disable_redirect,
            should_append: header.should_append,
            should_replace: header.should_replace,
            replace_values: header
                .replace_values
                .iter()
                .map(CompiledHeaderReplaceValue::compile)
                .collect(),
            methods: header.methods.clone(),
            domains: CompiledDomainMatcher::compile(&header.domains),
        }
    }

    fn condition_matches(&self, status: u16, method: &str, normalized_host: Option<&str>) -> bool {
        if !self.is_on {
            return false;
        }
        if !self.status.matches(status) {
            return false;
        }
        if self.disable_redirect && (300..=399).contains(&status) {
            return false;
        }
        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(method))
        {
            return false;
        }
        if !self.domains.matches(normalized_host) {
            return false;
        }
        true
    }
}

#[derive(Clone, Debug, Default)]
struct CompiledDomainMatcher {
    configured: bool,
    match_all: bool,
    exact: HashSet<String>,
    suffixes: Vec<String>,
    wildcards: Vec<Arc<Regex>>,
}

impl CompiledDomainMatcher {
    fn compile(patterns: &[String]) -> Self {
        let mut matcher = Self {
            configured: !patterns.is_empty(),
            ..Self::default()
        };
        for pattern in patterns {
            let pattern = normalize_domain_pattern(pattern);
            if pattern == "*" {
                matcher.match_all = true;
                continue;
            }
            if let Some(suffix) = pattern.strip_prefix("*.") {
                matcher.exact.insert(suffix.to_string());
                matcher.suffixes.push(format!(".{suffix}"));
                continue;
            }
            if let Some(suffix) = pattern.strip_prefix('.') {
                matcher.suffixes.push(format!(".{suffix}"));
                continue;
            }
            if pattern.contains('*') {
                let regex = format!("^{}$", regex::escape(&pattern).replace("\\*", "[^.]*"));
                if let Some(regex) = cached_header_regex(&regex) {
                    matcher.wildcards.push(regex);
                }
                continue;
            }
            matcher.exact.insert(pattern);
        }
        matcher
    }

    fn matches(&self, normalized_domain: Option<&str>) -> bool {
        if !self.configured || self.match_all {
            return true;
        }
        let Some(domain) = normalized_domain else {
            return false;
        };
        self.exact.contains(domain)
            || self.suffixes.iter().any(|suffix| domain.ends_with(suffix))
            || self.wildcards.iter().any(|regex| regex.is_match(domain))
    }
}

#[derive(Clone, Debug)]
enum CompiledHeaderStatus {
    Any,
    Codes(Vec<i32>),
}

impl CompiledHeaderStatus {
    fn compile(status: Option<&HTTPStatusConfig>) -> Self {
        match status {
            Some(status) if status.always => Self::Any,
            Some(status) => Self::Codes(status.codes.clone()),
            None => Self::Any,
        }
    }

    fn matches(&self, status: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Codes(codes) => codes.contains(&(status as i32)),
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledHeaderReplaceValue {
    pattern: String,
    replacement: String,
    regex: Option<Arc<Regex>>,
    fast_plain: bool,
}

impl CompiledHeaderReplaceValue {
    fn compile(rule: &HTTPHeaderReplaceValue) -> Self {
        let regex = if rule.is_regexp || rule.is_case_insensitive {
            let pattern = if rule.is_regexp {
                rule.pattern.clone()
            } else {
                regex::escape(&rule.pattern)
            };
            let pattern = if rule.is_case_insensitive && !pattern.starts_with("(?i)") {
                format!("(?i){}", pattern)
            } else {
                pattern
            };
            Regex::new(&pattern).ok().map(Arc::new)
        } else {
            None
        };
        Self {
            pattern: rule.pattern.clone(),
            replacement: rule.replacement.clone(),
            regex,
            fast_plain: !rule.is_regexp && !rule.is_case_insensitive,
        }
    }

    fn apply(&self, value: String) -> String {
        if self.fast_plain {
            if value.contains(&self.pattern) {
                return value.replace(&self.pattern, &self.replacement);
            }
            return value;
        }
        self.regex
            .as_ref()
            .map(|regex| {
                regex
                    .replace_all(&value, self.replacement.as_str())
                    .into_owned()
            })
            .unwrap_or(value)
    }
}

#[derive(Clone, Debug)]
struct CompiledHeaderReplaceConfig {
    is_on: bool,
    name: CompiledHeaderName,
    old_value: String,
    new_value: String,
}

impl CompiledHeaderReplaceConfig {
    fn compile(replace: &HTTPHeaderReplaceConfig) -> Self {
        Self {
            is_on: replace.is_on,
            name: CompiledHeaderName::compile(&replace.name),
            old_value: replace.old_value.clone(),
            new_value: replace.new_value.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledHeaderTemplate {
    raw: String,
    parts: Option<Vec<CompiledHeaderTemplatePart>>,
}

impl CompiledHeaderTemplate {
    fn compile(template: &str) -> Self {
        if !template.contains("${") {
            return Self {
                raw: template.to_string(),
                parts: None,
            };
        }
        let mut parts = Vec::new();
        let mut rest = template;
        while let Some(start) = rest.find("${") {
            if start > 0 {
                parts.push(CompiledHeaderTemplatePart::Literal(
                    rest[..start].to_string(),
                ));
            }
            let after_start = &rest[start + 2..];
            let Some(end) = after_start.find('}') else {
                parts.push(CompiledHeaderTemplatePart::Literal(
                    rest[start..].to_string(),
                ));
                rest = "";
                break;
            };
            let name = &after_start[..end];
            parts.push(CompiledHeaderTemplatePart::Variable(name.to_string()));
            rest = &after_start[end + 1..];
        }
        if !rest.is_empty() {
            parts.push(CompiledHeaderTemplatePart::Literal(rest.to_string()));
        }
        Self {
            raw: template.to_string(),
            parts: Some(parts),
        }
    }

    fn uses_vars(&self) -> bool {
        self.parts.is_some()
    }

    fn contains_vars(&self, names: &[&str]) -> bool {
        let Some(parts) = &self.parts else {
            return false;
        };
        parts.iter().any(|part| match part {
            CompiledHeaderTemplatePart::Literal(_) => false,
            CompiledHeaderTemplatePart::Variable(name) => names.iter().any(|target| name == target),
        })
    }

    fn render(&self, vars: &RequestTemplateVars<'_>) -> String {
        let Some(parts) = &self.parts else {
            return self.raw.clone();
        };
        let mut value = String::new();
        for part in parts {
            match part {
                CompiledHeaderTemplatePart::Literal(part) => value.push_str(part),
                CompiledHeaderTemplatePart::Variable(name) => {
                    value.push_str(&resolve_request_template_var(vars, name))
                }
            }
        }
        value
    }
}

#[derive(Clone, Debug)]
enum CompiledHeaderTemplatePart {
    Literal(String),
    Variable(String),
}

pub fn response_policy_uses_template_vars(policy: &HTTPHeaderPolicy) -> bool {
    policy
        .set_headers
        .iter()
        .chain(policy.add_headers.iter())
        .any(|header| header.is_on && header.value.contains("${"))
}

pub fn response_policy_needs_request_uri(policy: &HTTPHeaderPolicy) -> bool {
    policy
        .set_headers
        .iter()
        .chain(policy.add_headers.iter())
        .any(|header| header.is_on && template_contains_any(&header.value, &["requestURI"]))
}

pub fn response_policy_needs_port(policy: &HTTPHeaderPolicy) -> bool {
    policy
        .set_headers
        .iter()
        .chain(policy.add_headers.iter())
        .any(|header| header.is_on && template_contains_any(&header.value, &["port", "serverPort"]))
}

fn cached_header_regex(pattern: &str) -> Option<Arc<Regex>> {
    crate::bounded_regex_cache::get_or_compile(pattern)
}

/// Applies request header policies to the upstream request headers.
/// Mirrors the legacy ProcessRequestHeaders behavior.
pub fn apply_request_header_policy(session: &mut Session, policy: &HTTPHeaderPolicy) {
    // Collect variables first to avoid borrowing session mutably and immutably at the same time
    let host = session
        .get_header("host")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let request_uri = session
        .req_header()
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let remote_addr = session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.peer_addr())
        .map(|addr| addr.to_string())
        .or_else(|| session.client_addr().map(|addr| addr.to_string()))
        .unwrap_or_default();

    let resolve = |value: &str| -> String {
        format_template(value, |var_name| match var_name {
            "host" => host.clone(),
            "requestURI" => request_uri.clone(),
            "remoteAddr" => remote_addr.clone(),
            _ => "".to_string(),
        })
    };

    // Now it's safe to take mutable reference to headers
    let req_headers = session.req_header_mut();

    // Delete headers
    for name in &policy.delete_headers {
        if let Some(header_name) = cached_header_name(name) {
            req_headers.remove_header(&header_name);
        }
    }

    // Set headers (overwrite existing)
    for h in &policy.set_headers {
        if !h.is_on {
            continue;
        }
        let name = &h.name;
        let resolved = resolve(&h.value);
        if let (Some(hn), Ok(hv)) = (cached_header_name(name), HeaderValue::from_str(&resolved)) {
            req_headers.insert_header(hn, hv).ok();
        }
    }

    // Add headers (do not overwrite if already present)
    for h in &policy.add_headers {
        if !h.is_on {
            continue;
        }
        let name = &h.name;
        let resolved = resolve(&h.value);
        if let (Some(hn), Ok(hv)) = (cached_header_name(name), HeaderValue::from_str(&resolved)) {
            // Only insert if not already present
            if req_headers.headers.get(&hn).is_none() {
                req_headers.insert_header(hn, hv).ok();
            }
        }
    }
}

pub struct RequestTemplateVars<'a> {
    pub scheme: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub request_uri: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub port: &'a str,
    pub referer: &'a str,
    pub user_agent: &'a str,
    pub content_type: &'a str,
    pub remote_addr: &'a str,
    pub referer_block: &'a str,
}

pub fn resolve_request_template_var(vars: &RequestTemplateVars<'_>, var_name: &str) -> String {
    match var_name {
        "scheme" => vars.scheme.to_string(),
        "method" | "requestMethod" => vars.method.to_string(),
        "host" => vars.host.to_string(),
        "requestURI" => vars.request_uri.to_string(),
        "path" | "requestPath" => vars.path.to_string(),
        "query" | "args" | "queryString" => vars.query.to_string(),
        "port" | "serverPort" => vars.port.to_string(),
        "referer" | "httpReferer" => vars.referer.to_string(),
        "requestRefererBlock" => vars.referer_block.to_string(),
        "userAgent" | "httpUserAgent" => vars.user_agent.to_string(),
        "contentType" => vars.content_type.to_string(),
        "remoteAddr" => vars.remote_addr.to_string(),
        _ if var_name.starts_with("host.") => var_name[5..]
            .parse::<usize>()
            .ok()
            .and_then(|index| vars.host.split('.').nth(index))
            .unwrap_or_default()
            .to_string(),
        _ if var_name.starts_with("host[") && var_name.ends_with(']') => var_name
            [5..var_name.len() - 1]
            .parse::<usize>()
            .ok()
            .and_then(|index| vars.host.split('.').nth(index))
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    }
}

pub fn apply_compiled_request_header_policy_to_upstream(
    upstream_request: &mut pingora_http::RequestHeader,
    policy: &CompiledHeaderPolicy,
    vars: &RequestTemplateVars<'_>,
) {
    for name in &policy.delete_headers {
        if let Some(header_name) = &name.parsed {
            upstream_request.remove_header(header_name);
        }
    }

    for header in &policy.set_headers {
        if !header.is_on {
            continue;
        }
        let resolved = header.value_template.render(vars);
        if let (Some(hn), Ok(hv)) = (&header.name.parsed, HeaderValue::from_str(&resolved)) {
            upstream_request.insert_header(hn.clone(), hv).ok();
        }
    }

    for header in &policy.add_headers {
        if !header.is_on {
            continue;
        }
        let resolved = header.value_template.render(vars);
        if let (Some(hn), Ok(hv)) = (&header.name.parsed, HeaderValue::from_str(&resolved))
            && upstream_request.headers.get(hn).is_none()
        {
            upstream_request.insert_header(hn.clone(), hv).ok();
        }
    }
}

/// Applies request header policies to upstream request headers.
/// Unlike `apply_request_header_policy`, this operates on the outgoing upstream request
/// rather than the downstream session, and receives template variables directly.
pub fn apply_request_header_policy_to_upstream(
    upstream_request: &mut pingora_http::RequestHeader,
    policy: &HTTPHeaderPolicy,
    vars: &RequestTemplateVars<'_>,
) {
    let resolve = |value: &str| -> String {
        format_template(value, |var_name| {
            resolve_request_template_var(vars, var_name)
        })
    };

    // Delete headers
    for name in &policy.delete_headers {
        if let Some(header_name) = cached_header_name(name) {
            upstream_request.remove_header(&header_name);
        }
    }

    // Set headers (overwrite existing)
    for h in &policy.set_headers {
        if !h.is_on {
            continue;
        }
        let resolved = resolve(&h.value);
        if let (Some(hn), Ok(hv)) = (
            cached_header_name(&h.name),
            HeaderValue::from_str(&resolved),
        ) {
            upstream_request.insert_header(hn, hv).ok();
        }
    }

    // Add headers (do not overwrite if already present)
    for h in &policy.add_headers {
        if !h.is_on {
            continue;
        }
        let resolved = resolve(&h.value);
        if let (Some(hn), Ok(hv)) = (
            cached_header_name(&h.name),
            HeaderValue::from_str(&resolved),
        ) && upstream_request.headers.get(&hn).is_none()
        {
            upstream_request.insert_header(hn, hv).ok();
        }
    }
}

pub fn extract_referer_block(referer: &str) -> String {
    let host = if let Some(after_scheme) = referer.find("://").map(|i| &referer[i + 3..]) {
        after_scheme.split('/').next().unwrap_or("")
    } else {
        return String::new();
    };
    let host = host.split(':').next().unwrap_or(host);
    let host = host.trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host);
    host.to_ascii_lowercase()
}

fn normalize_domain_pattern(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_domain_value(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn domain_matches(patterns: &[String], domain: &str) -> bool {
    let domain = normalize_domain_value(domain);
    let matcher = CompiledDomainMatcher::compile(patterns);
    matcher.matches(Some(&domain))
}

fn header_condition_matches(
    header: &HTTPHeaderConfig,
    status: u16,
    method: &str,
    host: &str,
) -> bool {
    if !header.is_on {
        return false;
    }
    if let Some(status_config) = &header.status
        && !status_config.matches(status)
    {
        return false;
    }
    if header.disable_redirect && (300..=399).contains(&status) {
        return false;
    }
    if !header.methods.is_empty()
        && !header
            .methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method))
    {
        return false;
    }
    if !header.domains.is_empty() && !domain_matches(&header.domains, host) {
        return false;
    }
    true
}

fn replace_header_value(value: String, rule: &HTTPHeaderReplaceValue) -> String {
    if !rule.is_regexp && !rule.is_case_insensitive && !value.contains(&rule.pattern) {
        return value;
    }

    if rule.is_regexp || rule.is_case_insensitive {
        let pattern = if rule.is_regexp {
            rule.pattern.clone()
        } else {
            regex::escape(&rule.pattern)
        };
        let pattern = if rule.is_case_insensitive && !pattern.starts_with("(?i)") {
            format!("(?i){}", pattern)
        } else {
            pattern
        };
        cached_header_regex(&pattern)
            .map(|re| {
                re.replace_all(&value, rule.replacement.as_str())
                    .into_owned()
            })
            .unwrap_or(value)
    } else {
        value.replace(&rule.pattern, &rule.replacement)
    }
}

pub fn apply_compiled_response_header_policy(
    headers: &mut pingora_http::ResponseHeader,
    policy: &CompiledHeaderPolicy,
    vars: &RequestTemplateVars<'_>,
    status: u16,
    method: &str,
    host: &str,
) {
    let normalized_host = normalize_domain_value(host);
    let normalized_host = (!normalized_host.is_empty()).then_some(normalized_host);
    let normalized_host = normalized_host.as_deref();
    for name in &policy.delete_headers {
        if let Some(header_name) = &name.parsed {
            headers.remove_header(header_name);
        } else {
            headers.remove_header(&name.raw);
        }
    }

    for header in &policy.set_headers {
        if !header.condition_matches(status, method, normalized_host)
            || policy.deletes_header(&header.name.raw)
        {
            continue;
        }
        let mut value = header.value_template.render(vars);
        if header.should_replace {
            if value.is_empty() {
                let Some(current) = headers
                    .headers
                    .get(header.name.raw.as_str())
                    .and_then(|v| v.to_str().ok())
                else {
                    continue;
                };
                value = current.to_string();
            }
            for rule in &header.replace_values {
                value = rule.apply(value);
            }
        }
        let Some(name) = &header.name.parsed else {
            continue;
        };
        if header.should_append {
            headers.append_header(name.clone(), value).ok();
        } else {
            headers.insert_header(name.clone(), value).ok();
        }
    }

    for header in &policy.add_headers {
        if !header.condition_matches(status, method, normalized_host)
            || headers.headers.get(header.name.raw.as_str()).is_some()
        {
            continue;
        }
        let value = header.value_template.render(vars);
        let Some(name) = &header.name.parsed else {
            continue;
        };
        headers.insert_header(name.clone(), value).ok();
    }

    for rh in &policy.replace_headers {
        if !rh.is_on {
            continue;
        }
        if let Some(current) = headers
            .headers
            .get(rh.name.raw.as_str())
            .and_then(|v| v.to_str().ok())
        {
            if !current.contains(&rh.old_value) {
                continue;
            }
            let Some(name) = &rh.name.parsed else {
                continue;
            };
            headers
                .insert_header(name.clone(), current.replace(&rh.old_value, &rh.new_value))
                .ok();
        }
    }
}

pub fn apply_response_header_policy(
    headers: &mut pingora_http::ResponseHeader,
    policy: &HTTPHeaderPolicy,
    vars: &RequestTemplateVars<'_>,
    status: u16,
    method: &str,
    host: &str,
) {
    for name in &policy.delete_headers {
        headers.remove_header(name);
    }

    for header in &policy.set_headers {
        if !header_condition_matches(header, status, method, host) {
            continue;
        }
        if policy
            .delete_headers
            .iter()
            .any(|deleted| deleted.eq_ignore_ascii_case(header.name.as_str()))
        {
            continue;
        }
        let mut value = format_template(&header.value, |var_name| {
            resolve_request_template_var(vars, var_name)
        });
        if header.should_replace {
            if value.is_empty() {
                let Some(current) = headers
                    .headers
                    .get(header.name.as_str())
                    .and_then(|v| v.to_str().ok())
                else {
                    continue;
                };
                value = current.to_string();
            }
            for rule in &header.replace_values {
                value = replace_header_value(value, rule);
            }
        }
        let Some(name) = cached_header_name(&header.name) else {
            continue;
        };
        if header.should_append {
            headers.append_header(name, value).ok();
        } else {
            headers.insert_header(name, value).ok();
        }
    }

    for header in &policy.add_headers {
        if !header_condition_matches(header, status, method, host)
            || headers.headers.get(header.name.as_str()).is_some()
        {
            continue;
        }
        let value = format_template(&header.value, |var_name| {
            resolve_request_template_var(vars, var_name)
        });
        let Some(name) = cached_header_name(&header.name) else {
            continue;
        };
        headers.insert_header(name, value).ok();
    }

    for rh in &policy.replace_headers {
        if !rh.is_on {
            continue;
        }
        if let Some(current) = headers
            .headers
            .get(rh.name.as_str())
            .and_then(|v| v.to_str().ok())
        {
            if !current.contains(&rh.old_value) {
                continue;
            }
            let Some(name) = cached_header_name(&rh.name) else {
                continue;
            };
            headers
                .insert_header(name, current.replace(&rh.old_value, &rh.new_value))
                .ok();
        }
    }
}

/// Applies response header policies using the legacy ProcessResponseHeaders behavior.
pub fn apply_response_header_policy_to_map(
    headers: &mut std::collections::HashMap<String, String>,
    policy: &HTTPHeaderPolicy,
) {
    // Delete headers
    for name in &policy.delete_headers {
        headers.remove(&name.to_lowercase());
    }

    // Set headers
    for h in &policy.set_headers {
        if !h.is_on {
            continue;
        }
        headers.insert(h.name.to_lowercase(), h.value.clone());
    }

    // Add headers (don't overwrite)
    for h in &policy.add_headers {
        if !h.is_on {
            continue;
        }
        headers
            .entry(h.name.to_lowercase())
            .or_insert_with(|| h.value.clone());
    }

    // Replace header values
    for rh in &policy.replace_headers {
        if !rh.is_on {
            continue;
        }
        let key = rh.name.to_lowercase();
        if let Some(current) = headers.get(&key).cloned() {
            let replaced = current.replace(rh.old_value.as_str(), rh.new_value.as_str());
            headers.insert(key, replaced);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn domain_matcher_preserves_empty_pattern_semantics() {
        let unrestricted = CompiledDomainMatcher::compile(&[]);
        assert!(unrestricted.matches(Some("example.com")));

        for domains in [
            patterns(&[""]),
            patterns(&["   "]),
            patterns(&["."]),
            patterns(&["..."]),
        ] {
            let matcher = CompiledDomainMatcher::compile(&domains);
            assert!(!matcher.matches(Some("example.com")));
            assert!(matcher.matches(Some("")));
        }
    }

    #[test]
    fn domain_matcher_preserves_host_whitespace_semantics() {
        let matcher = CompiledDomainMatcher::compile(&patterns(&["example.com"]));
        assert!(matcher.matches(Some(&normalize_domain_value("example.com."))));
        assert!(!matcher.matches(Some(&normalize_domain_value(" example.com "))));
    }

    #[test]
    fn domain_matcher_matches_exact_wildcard_suffix_and_regex_patterns() {
        let exact = CompiledDomainMatcher::compile(&patterns(&["Example.COM."]));
        assert!(exact.matches(Some(&normalize_domain_value("example.com"))));

        let any = CompiledDomainMatcher::compile(&patterns(&["*"]));
        assert!(any.matches(Some("example.com")));
        assert!(any.matches(Some("")));

        let wildcard_suffix = CompiledDomainMatcher::compile(&patterns(&["*.example.com"]));
        assert!(wildcard_suffix.matches(Some("example.com")));
        assert!(wildcard_suffix.matches(Some("www.example.com")));
        assert!(!wildcard_suffix.matches(Some("badexample.com")));

        let leading_dot = CompiledDomainMatcher::compile(&patterns(&[".example.com"]));
        assert!(!leading_dot.matches(Some("example.com")));
        assert!(leading_dot.matches(Some("www.example.com")));

        let mid_wildcard = CompiledDomainMatcher::compile(&patterns(&["api-*.example.com"]));
        assert!(mid_wildcard.matches(Some("api-v1.example.com")));
        assert!(!mid_wildcard.matches(Some("api-v1.foo.example.com")));
    }

    #[test]
    fn fallback_domain_matches_uses_same_compiled_semantics() {
        assert!(domain_matches(&patterns(&[]), "example.com"));
        assert!(!domain_matches(&patterns(&[""]), "example.com"));
        assert!(domain_matches(&patterns(&["*.example.com"]), "example.com"));
        assert!(domain_matches(
            &patterns(&["*.example.com"]),
            "www.example.com"
        ));
        assert!(!domain_matches(
            &patterns(&["example.com"]),
            " example.com "
        ));
    }
}
