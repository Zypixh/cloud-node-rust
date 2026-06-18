use crate::config_models::{
    HTTPFirewallRule, HTTPFirewallRuleGroup, HTTPFirewallRuleSet, HTTPParamFilter, ServerConfig,
};
use crate::firewall::OutboundContext;
use crate::metrics::analyzer;
use base64::Engine as _;
use dashmap::DashMap;
use http::header::COOKIE;
use pingora_proxy::Session;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::cell::OnceCell;
use std::net::IpAddr;
use std::sync::LazyLock as Lazy;
use std::sync::atomic::{AtomicI64, Ordering};

pub struct MatchResult<'a> {
    pub matched: bool,
    pub set: Option<&'a HTTPFirewallRuleSet>,
}

pub(crate) fn expression_uses_request_body(value: &str) -> bool {
    value.contains("requestBody")
        || value.contains("requestAll")
        || value.contains("requestForm")
        || value.contains("${form")
        || value.contains("requestJSON")
        || value.contains("${json")
        || value.contains("requestUpload")
}

pub(crate) fn value_uses_request_body(value: &Value) -> bool {
    match value {
        Value::String(value) => expression_uses_request_body(value),
        Value::Array(values) => values.iter().any(value_uses_request_body),
        Value::Object(map) => map.values().any(value_uses_request_body),
        _ => false,
    }
}

pub(crate) fn expression_uses_response_body(value: &str) -> bool {
    value.contains("responseBody")
}

pub(crate) fn value_uses_response_body(value: &Value) -> bool {
    match value {
        Value::String(value) => expression_uses_response_body(value),
        Value::Array(values) => values.iter().any(value_uses_response_body),
        Value::Object(map) => map.values().any(value_uses_response_body),
        _ => false,
    }
}

pub fn match_group<'a>(
    group: &'a HTTPFirewallRuleGroup,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
) -> Option<MatchResult<'a>> {
    match_group_with_server(group, session, request_body, scheme, None)
}

pub fn match_group_with_server<'a>(
    group: &'a HTTPFirewallRuleGroup,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchResult<'a>> {
    match_group_from(group, session, request_body, scheme, server, None)
}

pub fn match_group_from<'a>(
    group: &'a HTTPFirewallRuleGroup,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
    server: Option<&ServerConfig>,
    start_set_id: Option<i64>,
) -> Option<MatchResult<'a>> {
    if !group.is_on {
        return None;
    }

    let facts = RequestFacts::new_with_server(session, request_body, scheme, server);
    // Preset group matchers (sqlInjection, xss, ...) sit outside the set list,
    // so they only apply when iteration starts from the top.
    if start_set_id.is_none()
        && group
            .code
            .as_deref()
            .is_some_and(|code| preset_group_matches(code, &facts))
    {
        return Some(MatchResult {
            matched: true,
            set: None,
        });
    }

    let start_idx = match start_set_id {
        Some(sid) => group
            .sets
            .iter()
            .position(|s| s.id == sid)
            .unwrap_or(group.sets.len()),
        None => 0,
    };

    for set in group.sets.iter().skip(start_idx) {
        if match_set_with_facts(set, session, &facts) {
            return Some(MatchResult {
                matched: true,
                set: Some(set),
            });
        }
    }

    None
}

pub(crate) fn preset_group_matches(code: &str, facts: &RequestFacts<'_>) -> bool {
    let (operator, strict) = match code {
        "sqlInjection" => ("contains sql injection", false),
        "sqlInjectionStrict" => ("contains sql injection strictly", true),
        "xss" => ("contains xss", false),
        "xssStrict" => ("contains xss strictly", true),
        "cmdInjection" => ("contains cmd injection", false),
        _ => return false,
    };
    let str_values = [
        facts.request_uri(),
        facts.request_args(),
        facts.cookies_normalized(),
        facts.headers(),
    ];
    if str_values
        .iter()
        .any(|value| crate::firewall::matcher::evaluate_operator(value, operator, "", !strict))
    {
        return true;
    }
    crate::firewall::matcher::evaluate_operator_bytes(facts.request_body, operator, "", !strict)
}

pub(crate) fn preset_group_uses_request_body(code: &str) -> bool {
    matches!(
        code,
        "sqlInjection" | "sqlInjectionStrict" | "xss" | "xssStrict" | "cmdInjection"
    )
}

pub fn match_set(
    set: &HTTPFirewallRuleSet,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
) -> bool {
    if !set.is_on || set.rules.is_empty() {
        return false;
    }

    // Bypass check
    let ip = parse_remote_ip(session);
    if set.ignore_local && is_local_ip(&ip) {
        return false;
    }
    if set.ignore_search_engine
        && crate::client_agent::is_verified_search_engine_ip(
            ip,
            &header_value(session, "user-agent"),
        )
    {
        return false;
    }

    let facts = RequestFacts::new(session, request_body, scheme);
    match_set_with_facts(set, session, &facts)
}

fn match_set_with_facts(
    set: &HTTPFirewallRuleSet,
    session: &Session,
    facts: &RequestFacts<'_>,
) -> bool {
    if !set.is_on || set.rules.is_empty() {
        return false;
    }

    let ip = facts.remote_ip();
    if set.ignore_local && is_local_ip(&ip) {
        return false;
    }
    if set.ignore_search_engine
        && crate::client_agent::is_verified_search_engine_ip(
            ip,
            &header_value(session, "user-agent"),
        )
    {
        return false;
    }

    if set.connector == "and" {
        set.rules
            .iter()
            .all(|rule| match_rule_with_facts(rule, facts))
    } else {
        set.rules
            .iter()
            .any(|rule| match_rule_with_facts(rule, facts))
    }
}

pub fn match_set_response(
    set: &HTTPFirewallRuleSet,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
) -> bool {
    if !set.is_on || set.rules.is_empty() {
        return false;
    }

    // Bypass check
    let ip = parse_remote_ip(session);
    if set.ignore_local && is_local_ip(&ip) {
        return false;
    }
    if set.ignore_search_engine
        && crate::client_agent::is_verified_search_engine_ip(
            ip,
            &header_value(session, "user-agent"),
        )
    {
        return false;
    }

    let facts = ResponseFacts::new(session, request_body, response, scheme);
    match_set_response_with_facts(set, session, &facts)
}

fn match_set_response_with_facts(
    set: &HTTPFirewallRuleSet,
    session: &Session,
    facts: &ResponseFacts<'_, '_, '_>,
) -> bool {
    if !set.is_on || set.rules.is_empty() {
        return false;
    }

    let ip = facts.request().remote_ip();
    if set.ignore_local && is_local_ip(&ip) {
        return false;
    }
    if set.ignore_search_engine
        && crate::client_agent::is_verified_search_engine_ip(
            ip,
            &header_value(session, "user-agent"),
        )
    {
        return false;
    }

    if set.connector == "and" {
        set.rules
            .iter()
            .all(|rule| match_rule_response_with_facts(rule, facts))
    } else {
        set.rules
            .iter()
            .any(|rule| match_rule_response_with_facts(rule, facts))
    }
}

pub fn match_group_response<'a>(
    group: &'a HTTPFirewallRuleGroup,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
) -> Option<MatchResult<'a>> {
    match_group_response_with_server(group, session, request_body, response, scheme, None)
}

pub fn match_group_response_with_server<'a>(
    group: &'a HTTPFirewallRuleGroup,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchResult<'a>> {
    if !group.is_on {
        return None;
    }

    let facts = ResponseFacts::new_with_server(session, request_body, response, scheme, server);
    for set in &group.sets {
        if match_set_response_with_facts(set, session, &facts) {
            return Some(MatchResult {
                matched: true,
                set: Some(set),
            });
        }
    }

    None
}

pub(crate) fn is_local_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            // Canonicalize IPv4-mapped IPv6 (::ffff:a.b.c.d) before testing.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_private() || v4.is_loopback() || v4.is_link_local();
            }
            if v6.is_loopback() {
                return true;
            }
            let octets = v6.octets();
            // ULA (fc00::/7): first byte high 7 bits == 0xfc (octet & 0xfe == 0xfc).
            // Operator precedence requires explicit parens — the previous
            // `octets[0] & 0xfe == 0xfc` parses as `octets[0] & (0xfe == 0xfc)`
            // which is always 0.
            if (octets[0] & 0xfe) == 0xfc {
                return true;
            }
            // Link-local (fe80::/10): first 10 bits == 1111_1110_10
            if octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80 {
                return true;
            }
            false
        }
    }
}

fn is_raw_body_param(param: &str) -> bool {
    let inner = param
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(param);
    matches!(inner, "requestBody" | "requestAll")
}

pub fn match_rule(
    rule: &HTTPFirewallRule,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
) -> bool {
    match_rule_with_server(rule, session, request_body, scheme, None)
}

pub fn match_rule_with_server(
    rule: &HTTPFirewallRule,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
    server: Option<&ServerConfig>,
) -> bool {
    let facts = RequestFacts::new_with_server(session, request_body, scheme, server);
    match_rule_with_facts(rule, &facts)
}

fn match_rule_with_facts(rule: &HTTPFirewallRule, facts: &RequestFacts<'_>) -> bool {
    crate::metrics::METRICS.waf.record_rule_evaluation();

    // For body params with no filters applied, evaluate against raw bytes to
    // avoid U+FFFD corruption from from_utf8_lossy.
    if rule.param_filters.is_empty() && is_raw_body_param(&rule.param) {
        let matched = crate::firewall::matcher::evaluate_operator_bytes(
            facts.request_body,
            &rule.operator,
            &rule.value,
            rule.is_case_insensitive,
        );
        return if rule.is_reverse { !matched } else { matched };
    }

    let raw_value =
        get_compiled_rule_value_with_facts(&rule.param, rule.checkpoint_options.as_ref(), facts);
    let param_value = if rule.param_filters.is_empty() {
        raw_value
    } else {
        apply_param_filters(&raw_value, &rule.param_filters)
    };
    let matched = crate::firewall::matcher::evaluate_operator(
        &param_value,
        &rule.operator,
        &rule.value,
        rule.is_case_insensitive,
    );

    if rule.is_reverse { !matched } else { matched }
}

pub fn match_rule_response(
    rule: &HTTPFirewallRule,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
) -> bool {
    let facts = ResponseFacts::new(session, request_body, response, scheme);
    match_rule_response_with_facts(rule, &facts)
}

fn match_rule_response_with_facts(
    rule: &HTTPFirewallRule,
    facts: &ResponseFacts<'_, '_, '_>,
) -> bool {
    crate::metrics::METRICS.waf.record_rule_evaluation();

    if rule.param_filters.is_empty() {
        if is_raw_body_param(&rule.param) {
            let matched = crate::firewall::matcher::evaluate_operator_bytes(
                facts.request().request_body,
                &rule.operator,
                &rule.value,
                rule.is_case_insensitive,
            );
            return if rule.is_reverse { !matched } else { matched };
        }
        let resp_body_param = rule
            .param
            .strip_prefix("${")
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(&rule.param);
        if resp_body_param == "responseBody" {
            let matched = crate::firewall::matcher::evaluate_operator_bytes(
                facts.response_body_bytes(),
                &rule.operator,
                &rule.value,
                rule.is_case_insensitive,
            );
            return if rule.is_reverse { !matched } else { matched };
        }
    }

    let raw_value = get_compiled_response_rule_value_with_facts(
        &rule.param,
        rule.checkpoint_options.as_ref(),
        facts,
    );
    let param_value = if rule.param_filters.is_empty() {
        raw_value
    } else {
        apply_param_filters(&raw_value, &rule.param_filters)
    };
    let matched = crate::firewall::matcher::evaluate_operator(
        &param_value,
        &rule.operator,
        &rule.value,
        rule.is_case_insensitive,
    );

    if rule.is_reverse { !matched } else { matched }
}

/// Apply a chain of param filters to a string value in order.
///
/// Bounded to defuse amplification attacks: a chain of decoders
/// (`base64Decode` / `urlDecode`) can blow up the working string and stall
/// the request thread. We cap both the number of filters that actually run
/// and the maximum size of the intermediate string.
pub(crate) fn apply_param_filters(value: &str, filters: &[HTTPParamFilter]) -> String {
    /// Maximum filters honoured per rule. Reasonable real-world chains are
    /// 2–3 long; anything beyond is almost certainly a misconfig or attack.
    const MAX_FILTER_CHAIN: usize = 8;
    /// Cap each intermediate string at ~1 MiB. Above this we stop and return
    /// the truncated value so downstream operators still see something
    /// meaningful for rule matching.
    const MAX_FILTER_OUTPUT_BYTES: usize = 1024 * 1024;

    let mut current = value.to_string();
    for filter in filters.iter().take(MAX_FILTER_CHAIN) {
        current = apply_single_filter(&current, filter);
        if current.len() > MAX_FILTER_OUTPUT_BYTES {
            // Truncate on a UTF-8 char boundary so the result stays valid.
            let mut cut = MAX_FILTER_OUTPUT_BYTES;
            while cut > 0 && !current.is_char_boundary(cut) {
                cut -= 1;
            }
            current.truncate(cut);
            break;
        }
    }
    current
}

fn apply_single_filter(value: &str, filter: &HTTPParamFilter) -> String {
    match filter.code.as_str() {
        "urlDecode" => urlencoding::decode(value)
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| value.to_string()),
        "base64Decode" => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(value.trim())
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| value.to_string())
        }
        "htmlDecode" => value
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&apos;", "'"),
        "toLowerCase" => value.to_lowercase(),
        "toUpperCase" => value.to_uppercase(),
        "trim" => value.trim().to_string(),
        "md5" => {
            let digest = md5_legacy::compute(value.as_bytes());
            format!("{:x}", digest)
        }
        "sha1" => {
            use sha1::{Digest as _, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(value.as_bytes());
            hex::encode(hasher.finalize())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            hex::encode(hasher.finalize())
        }
        _ => value.to_string(),
    }
}

static CC_COUNTERS: Lazy<DashMap<String, crate::firewall::state::RollingCounter>> =
    Lazy::new(DashMap::new);
static CC_COUNTER_LAST_SWEEP: AtomicI64 = AtomicI64::new(0);
const CC_COUNTER_MAX_PERIOD_SECS: i64 = 7 * 86_400;
const CC_COUNTER_SWEEP_INTERVAL_SECS: i64 = 60;
const CC_COUNTER_MAX_ENTRIES_NORMAL: usize = 1_000_000;
const CC_COUNTER_MAX_ENTRIES_PRESSURE: usize = 131_072;

pub(crate) struct RequestFacts<'a> {
    session: &'a Session,
    request_body: &'a [u8],
    scheme: &'a str,
    server: Option<&'a ServerConfig>,
    remote_ip: OnceCell<std::net::IpAddr>,
    raw_remote_addr: OnceCell<String>,
    remote_port: OnceCell<String>,
    local_addr: OnceCell<String>,
    local_port: OnceCell<String>,
    request_uri: OnceCell<String>,
    request_path: OnceCell<String>,
    request_url: OnceCell<String>,
    host: OnceCell<String>,
    remote_user: OnceCell<String>,
    request_file_extension: OnceCell<String>,
    referer_origin: OnceCell<String>,
    request_body_text: OnceCell<String>,
    request_all: OnceCell<String>,
    cookies_normalized: OnceCell<String>,
    headers: OnceCell<String>,
    header_names: OnceCell<String>,
    header_max_length: OnceCell<usize>,
    general_header_length: OnceCell<usize>,
    request_path_lower_extension: OnceCell<String>,
    common_ai_bot: OnceCell<String>,
    common_bot: OnceCell<String>,
    geo_info: OnceCell<Option<analyzer::GeoInfo>>,
    isp_name: OnceCell<String>,
    query_params: OnceCell<Vec<(String, String)>>,
    cookie_params: OnceCell<Vec<(String, String)>>,
    form_params: OnceCell<Vec<(String, String)>>,
    json_body: OnceCell<Option<Value>>,
    upload_parts: OnceCell<Vec<UploadPart>>,
}

impl<'a> RequestFacts<'a> {
    pub(crate) fn new(session: &'a Session, request_body: &'a [u8], scheme: &'a str) -> Self {
        Self::new_with_server(session, request_body, scheme, None)
    }

    pub(crate) fn new_with_server(
        session: &'a Session,
        request_body: &'a [u8],
        scheme: &'a str,
        server: Option<&'a ServerConfig>,
    ) -> Self {
        Self {
            session,
            request_body,
            scheme,
            server,
            remote_ip: OnceCell::new(),
            raw_remote_addr: OnceCell::new(),
            remote_port: OnceCell::new(),
            local_addr: OnceCell::new(),
            local_port: OnceCell::new(),
            request_uri: OnceCell::new(),
            request_path: OnceCell::new(),
            request_url: OnceCell::new(),
            host: OnceCell::new(),
            remote_user: OnceCell::new(),
            request_file_extension: OnceCell::new(),
            referer_origin: OnceCell::new(),
            request_body_text: OnceCell::new(),
            request_all: OnceCell::new(),
            cookies_normalized: OnceCell::new(),
            headers: OnceCell::new(),
            header_names: OnceCell::new(),
            header_max_length: OnceCell::new(),
            general_header_length: OnceCell::new(),
            request_path_lower_extension: OnceCell::new(),
            common_ai_bot: OnceCell::new(),
            common_bot: OnceCell::new(),
            geo_info: OnceCell::new(),
            isp_name: OnceCell::new(),
            query_params: OnceCell::new(),
            cookie_params: OnceCell::new(),
            form_params: OnceCell::new(),
            json_body: OnceCell::new(),
            upload_parts: OnceCell::new(),
        }
    }

    pub(crate) fn remote_ip(&self) -> std::net::IpAddr {
        *self.remote_ip.get_or_init(|| parse_remote_ip(self.session))
    }

    pub(crate) fn remote_addr(&self) -> String {
        self.remote_ip().to_string()
    }

    pub(crate) fn raw_remote_addr(&self) -> String {
        self.raw_remote_addr
            .get_or_init(|| get_raw_remote_addr(self.session))
            .clone()
    }

    pub(crate) fn remote_port(&self) -> String {
        self.remote_port
            .get_or_init(|| get_remote_port(self.session))
            .clone()
    }

    pub(crate) fn local_addr(&self) -> String {
        self.local_addr
            .get_or_init(|| get_local_addr(self.session))
            .clone()
    }

    pub(crate) fn local_port(&self) -> String {
        self.local_port
            .get_or_init(|| get_local_port(self.session))
            .clone()
    }

    pub(crate) fn request_uri(&self) -> String {
        self.request_uri
            .get_or_init(|| get_request_uri(self.session))
            .clone()
    }

    pub(crate) fn request_path(&self) -> String {
        self.request_path
            .get_or_init(|| self.session.req_header().uri.path().to_string())
            .clone()
    }

    pub(crate) fn host(&self) -> String {
        self.host
            .get_or_init(|| {
                self.session
                    .req_header()
                    .uri
                    .host()
                    .unwrap_or("")
                    .to_string()
            })
            .clone()
    }

    pub(crate) fn cname(&self) -> String {
        let host = ServerConfig::normalize_runtime_server_name(&self.host());
        if host.is_empty() {
            return String::new();
        }
        self.server
            .and_then(|server| {
                server.server_names.iter().find_map(|server_name| {
                    let is_cname = server_name
                        .r#type
                        .as_deref()
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("cname"));
                    if !is_cname {
                        return None;
                    }
                    std::iter::once(&server_name.name)
                        .chain(server_name.sub_names.iter())
                        .find_map(|name| {
                            let normalized = ServerConfig::normalize_runtime_server_name(name);
                            (normalized == host).then(|| normalized)
                        })
                })
            })
            .unwrap_or_default()
    }

    pub(crate) fn is_cname(&self) -> String {
        bool_string(!self.cname().is_empty())
    }

    pub(crate) fn remote_user(&self) -> String {
        self.remote_user
            .get_or_init(|| {
                self.session
                    .get_header("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Basic "))
                    .and_then(|v| {
                        base64::engine::general_purpose::STANDARD
                            .decode(v.trim())
                            .ok()
                    })
                    .and_then(|v| String::from_utf8(v).ok())
                    .and_then(|v| v.split_once(':').map(|(u, _)| u.to_string()))
                    .unwrap_or_default()
            })
            .clone()
    }

    pub(crate) fn request_file_extension(&self) -> String {
        self.request_file_extension
            .get_or_init(|| {
                self.session
                    .req_header()
                    .uri
                    .path()
                    .split('.')
                    .last()
                    .filter(|ext| !ext.is_empty() && !ext.contains('/'))
                    .unwrap_or_default()
                    .to_string()
            })
            .clone()
    }

    pub(crate) fn referer_origin(&self) -> String {
        self.referer_origin
            .get_or_init(|| {
                let mut val = header_value(self.session, "referer");
                let origin = header_value(self.session, "origin");
                if !origin.is_empty() {
                    if !val.is_empty() {
                        val.push(' ');
                    }
                    val.push_str(&origin);
                }
                val
            })
            .clone()
    }

    pub(crate) fn request_length(&self) -> String {
        self.session
            .get_header("content-length")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    pub(crate) fn request_method(&self) -> String {
        self.session.req_header().method.as_str().to_string()
    }

    pub(crate) fn scheme(&self) -> String {
        self.scheme.to_string()
    }

    pub(crate) fn proto(&self) -> String {
        format!("{:?}", self.session.req_header().version)
    }

    pub(crate) fn request_args(&self) -> String {
        self.session
            .req_header()
            .uri
            .query()
            .unwrap_or("")
            .to_string()
    }

    pub(crate) fn request_header(&self, name: &str) -> String {
        header_value(self.session, name)
    }

    pub(crate) fn request_url(&self) -> String {
        self.request_url
            .get_or_init(|| {
                format!(
                    "{}://{}{}",
                    self.scheme,
                    self.session.req_header().uri.host().unwrap_or(""),
                    self.request_uri()
                )
            })
            .clone()
    }

    pub(crate) fn request_body_text(&self) -> String {
        self.request_body_text
            .get_or_init(|| String::from_utf8_lossy(self.request_body).to_string())
            .clone()
    }

    pub(crate) fn request_body_bytes(&self) -> &'a [u8] {
        self.request_body
    }

    pub(crate) fn request_all(&self) -> String {
        self.request_all
            .get_or_init(|| format!("{}{}", self.request_uri(), self.request_body_text()))
            .clone()
    }

    pub(crate) fn cookies_normalized(&self) -> String {
        self.cookies_normalized
            .get_or_init(|| normalize_cookies(self.session))
            .clone()
    }

    pub(crate) fn headers(&self) -> String {
        self.headers
            .get_or_init(|| all_headers(self.session))
            .clone()
    }

    pub(crate) fn header_names(&self) -> String {
        self.header_names
            .get_or_init(|| header_names(self.session))
            .clone()
    }

    pub(crate) fn header_max_length(&self) -> usize {
        *self
            .header_max_length
            .get_or_init(|| header_max_length(self.session))
    }

    pub(crate) fn general_header_length(&self) -> usize {
        *self
            .general_header_length
            .get_or_init(|| general_header_length(self.session))
    }

    pub(crate) fn request_path_lower_extension(&self) -> String {
        self.request_path_lower_extension
            .get_or_init(|| request_path_lower_extension(self.session))
            .clone()
    }

    pub(crate) fn common_ai_bot(&self) -> String {
        self.common_ai_bot
            .get_or_init(|| {
                bool_string(crate::firewall::matcher::evaluate_operator(
                    &self.request_header("user-agent"),
                    "common ai bot",
                    "",
                    true,
                ))
            })
            .clone()
    }

    pub(crate) fn common_bot(&self) -> String {
        self.common_bot
            .get_or_init(|| {
                bool_string(crate::firewall::matcher::evaluate_operator(
                    &self.request_header("user-agent"),
                    "common bot",
                    "",
                    true,
                ))
            })
            .clone()
    }

    pub(crate) fn geo_country_name(&self) -> String {
        self.geo_info()
            .map(|g| g.country.to_string())
            .unwrap_or_default()
    }

    pub(crate) fn geo_province_name(&self) -> String {
        self.geo_info()
            .map(|g| g.region.to_string())
            .unwrap_or_default()
    }

    pub(crate) fn geo_city_name(&self) -> String {
        self.geo_info()
            .map(|g| g.city.to_string())
            .unwrap_or_default()
    }

    pub(crate) fn isp_name(&self) -> String {
        self.isp_name
            .get_or_init(|| {
                self.geo_info()
                    .map(|g| g.provider.to_string())
                    .unwrap_or_else(|| analyzer::lookup_isp_name(self.remote_ip()).to_string())
            })
            .clone()
    }

    pub(crate) fn query_param(&self, name: &str) -> String {
        self.query_params
            .get_or_init(|| parse_query_params(self.session.req_header().uri.query().unwrap_or("")))
            .iter()
            .find_map(|(key, value)| (key == name).then(|| value.clone()))
            .unwrap_or_default()
    }

    pub(crate) fn cookie_param(&self, name: &str) -> String {
        self.cookie_params
            .get_or_init(|| parse_cookie_params(&merged_cookie_header(self.session)))
            .iter()
            .find_map(|(key, value)| (key == name).then(|| value.clone()))
            .unwrap_or_default()
    }

    pub(crate) fn form_param(&self, name: &str) -> String {
        self.form_params
            .get_or_init(|| parse_query_params(&String::from_utf8_lossy(self.request_body)))
            .iter()
            .find_map(|(key, value)| (key == name).then(|| value.clone()))
            .unwrap_or_default()
    }

    pub(crate) fn json_param(&self, path: &str) -> String {
        self.json_body()
            .map(|value| json_value_from_root(value, path))
            .unwrap_or_default()
    }

    pub(crate) fn upload_param(&self, name: &str) -> String {
        resolve_upload_param(self.upload_parts(), name)
    }

    pub(crate) fn upload_summary(&self) -> String {
        upload_summary(self.upload_parts())
    }

    fn upload_parts(&self) -> &[UploadPart] {
        self.upload_parts
            .get_or_init(|| parse_multipart_uploads(self.session, self.request_body))
    }

    fn geo_info(&self) -> Option<&analyzer::GeoInfo> {
        self.geo_info
            .get_or_init(|| analyzer::lookup_geo(self.remote_ip()))
            .as_ref()
    }

    fn json_body(&self) -> Option<&Value> {
        self.json_body
            .get_or_init(|| serde_json::from_slice::<Value>(self.request_body).ok())
            .as_ref()
    }
}

pub(crate) struct ResponseFacts<'request, 'response_ref, 'response_data> {
    request: RequestFacts<'request>,
    response: &'response_ref OutboundContext<'response_data>,
    response_body_text: OnceCell<String>,
    response_general_header_length: OnceCell<usize>,
}

impl<'request, 'response_ref, 'response_data>
    ResponseFacts<'request, 'response_ref, 'response_data>
{
    pub(crate) fn new(
        session: &'request Session,
        request_body: &'request [u8],
        response: &'response_ref OutboundContext<'response_data>,
        scheme: &'request str,
    ) -> Self {
        Self::new_with_server(session, request_body, response, scheme, None)
    }

    pub(crate) fn new_with_server(
        session: &'request Session,
        request_body: &'request [u8],
        response: &'response_ref OutboundContext<'response_data>,
        scheme: &'request str,
        server: Option<&'request ServerConfig>,
    ) -> Self {
        Self {
            request: RequestFacts::new_with_server(session, request_body, scheme, server),
            response,
            response_body_text: OnceCell::new(),
            response_general_header_length: OnceCell::new(),
        }
    }

    pub(crate) fn request(&self) -> &RequestFacts<'request> {
        &self.request
    }

    pub(crate) fn status(&self) -> String {
        self.response.status.to_string()
    }

    pub(crate) fn response_body_text(&self) -> String {
        self.response_body_text
            .get_or_init(|| String::from_utf8_lossy(self.response.body).to_string())
            .clone()
    }

    pub(crate) fn response_body_bytes(&self) -> &[u8] {
        self.response.body
    }

    pub(crate) fn bytes_sent(&self) -> String {
        self.response.bytes_sent.to_string()
    }

    pub(crate) fn response_general_header_length(&self) -> usize {
        *self.response_general_header_length.get_or_init(|| {
            self.response
                .headers
                .iter()
                .filter(|(name, _)| {
                    !matches!(
                        name.as_str(),
                        "set-cookie" | "location" | "content-type" | "content-length"
                    )
                })
                .map(|(name, value)| name.len() + value.len())
                .sum()
        })
    }

    pub(crate) fn response_header(&self, name: &str) -> String {
        response_header_value(self.response, name)
    }
}

fn get_variable_value_with_facts(param: &str, facts: &RequestFacts<'_>) -> String {
    if !param.contains("${") {
        return param.to_string();
    }

    static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));

    if let Some(inner) = param.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        return resolve_variable_with_facts(inner, facts);
    }

    RE_VAR
        .replace_all(param, |caps: &regex::Captures| {
            let inner = &caps[0];
            let inner = inner
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(inner);
            resolve_variable_with_facts(inner, facts)
        })
        .to_string()
}

pub(crate) fn get_compiled_rule_value_with_facts(
    param: &str,
    checkpoint_options: Option<&Value>,
    facts: &RequestFacts<'_>,
) -> String {
    if param.starts_with("${cc.") || param == "${cc}" {
        return cc_value_with_facts(param, checkpoint_options, facts, false);
    }
    if param.starts_with("${cc2.") || param == "${cc2}" {
        return cc_value_with_facts(param, checkpoint_options, facts, true);
    }
    get_variable_value_with_facts(param, facts)
}

pub(crate) fn get_compiled_response_rule_value_with_facts(
    param: &str,
    checkpoint_options: Option<&Value>,
    facts: &ResponseFacts<'_, '_, '_>,
) -> String {
    if param.starts_with("${cc.") || param == "${cc}" {
        return cc_value_with_facts(param, checkpoint_options, facts.request(), false);
    }
    if param.starts_with("${cc2.") || param == "${cc2}" {
        return cc_value_with_facts(param, checkpoint_options, facts.request(), true);
    }
    get_response_variable_value_with_facts(param, facts)
}

pub(crate) fn cc_value_with_facts(
    param: &str,
    options: Option<&Value>,
    facts: &RequestFacts<'_>,
    is_cc2: bool,
) -> String {
    let period = options
        .and_then(|v| v.get("period"))
        .and_then(Value::as_i64)
        .unwrap_or(60)
        .clamp(1, 7 * 86_400);

    let key = if is_cc2 {
        let keys = options
            .and_then(|v| v.get("keys"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![Value::String("${remoteAddr}".to_string())]);
        let key_values = keys
            .iter()
            .filter_map(Value::as_str)
            .map(|template| get_variable_value_with_facts(template, facts))
            .collect::<Vec<_>>();
        format!("WAF-CC2-{}-{}:{}", param, period, key_values.join("@"))
    } else {
        format!(
            "WAF-CC:{}:{}",
            period,
            aggregate_ip_counter_key(facts.remote_ip())
        )
    };

    increase_counter(key, period).to_string()
}

pub(crate) fn increase_counter(key: String, period_secs: i64) -> u64 {
    let now = crate::utils::time::now_timestamp();
    sweep_cc_counters(now);
    if !CC_COUNTERS.contains_key(&key) && CC_COUNTERS.len() >= cc_counter_capacity() {
        sweep_cc_counters_force(now);
        if CC_COUNTERS.len() >= cc_counter_capacity() {
            return u64::MAX;
        }
    }
    CC_COUNTERS
        .entry(key)
        .or_default()
        .increment(now, period_secs)
}

pub(crate) fn aggregate_ip_counter_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_string();
            }
            let mut octets = v6.octets();
            octets[8..].fill(0);
            std::net::Ipv6Addr::from(octets).to_string()
        }
    }
}

fn cc_counter_capacity() -> usize {
    if crate::memory_governor::MEMORY_GOVERNOR.is_memory_pressure_high() {
        CC_COUNTER_MAX_ENTRIES_PRESSURE
    } else {
        CC_COUNTER_MAX_ENTRIES_NORMAL
    }
}

fn sweep_cc_counters(now: i64) {
    let last = CC_COUNTER_LAST_SWEEP.load(Ordering::Relaxed);
    if now.saturating_sub(last) < CC_COUNTER_SWEEP_INTERVAL_SECS {
        return;
    }
    if CC_COUNTER_LAST_SWEEP
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    CC_COUNTERS.retain(|_, counter| !counter.is_stale(now, CC_COUNTER_MAX_PERIOD_SECS));
}

fn sweep_cc_counters_force(now: i64) {
    CC_COUNTERS.retain(|_, counter| !counter.is_stale(now, CC_COUNTER_MAX_PERIOD_SECS));
}

pub(crate) fn get_response_variable_value_with_facts(
    param: &str,
    facts: &ResponseFacts<'_, '_, '_>,
) -> String {
    if !param.contains("${") {
        return param.to_string();
    }

    static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));

    if let Some(inner) = param.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        return resolve_response_variable_with_facts(inner, facts);
    }

    RE_VAR
        .replace_all(param, |caps: &regex::Captures| {
            let inner = &caps[0];
            let inner = inner
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(inner);
            resolve_response_variable_with_facts(inner, facts)
        })
        .to_string()
}

fn resolve_variable(session: &Session, inner: &str, request_body: &[u8], scheme: &str) -> String {
    match inner {
        "remoteAddr" => get_remote_addr(session),
        "rawRemoteAddr" => get_raw_remote_addr(session),
        "remotePort" => get_remote_port(session),
        "remoteUser" => session
            .get_header("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|v| {
                base64::engine::general_purpose::STANDARD
                    .decode(v.trim())
                    .ok()
            })
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|v| v.split_once(':').map(|(u, _)| u.to_string()))
            .unwrap_or_default(),
        "requestURI" => get_request_uri(session),
        "requestPath" => session.req_header().uri.path().to_string(),
        "requestURL" => format!(
            "{}://{}{}",
            scheme,
            session.req_header().uri.host().unwrap_or(""),
            get_request_uri(session)
        ),
        "requestFileExtension" => session
            .req_header()
            .uri
            .path()
            .split('.')
            .last()
            .filter(|ext| !ext.is_empty() && !ext.contains('/'))
            .unwrap_or_default()
            .to_string(),
        "requestLength" => session
            .get_header("content-length")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        "requestBody" => String::from_utf8_lossy(request_body).to_string(),
        "requestAll" => format!(
            "{}{}",
            get_request_uri(session),
            String::from_utf8_lossy(request_body)
        ),
        "requestMethod" => session.req_header().method.as_str().to_string(),
        "scheme" => scheme.to_string(),
        "proto" => format!("{:?}", session.req_header().version),
        "host" | "requestHost" => session.req_header().uri.host().unwrap_or("").to_string(),
        "refererOrigin" => {
            let mut val = header_value(session, "referer");
            let origin = header_value(session, "origin");
            if !origin.is_empty() {
                if !val.is_empty() {
                    val.push(' ');
                }
                val.push_str(&origin);
            }
            val
        }
        "referer" => header_value(session, "referer"),
        "userAgent" => header_value(session, "user-agent"),
        "contentType" => header_value(session, "content-type"),
        "cookies" => normalize_cookies(session),
        "args" => session.req_header().uri.query().unwrap_or("").to_string(),
        "headers" => all_headers(session),
        "headerNames" => header_names(session),
        "headerMaxLength" => header_max_length(session).to_string(),
        "requestGeneralHeaderLength" => general_header_length(session).to_string(),
        "requestPathLowerExtension" => request_path_lower_extension(session),
        "commonAIBot" => bool_string(crate::firewall::matcher::evaluate_operator(
            &header_value(session, "user-agent"),
            "common ai bot",
            "",
            true,
        )),
        "commonBot" => bool_string(crate::firewall::matcher::evaluate_operator(
            &header_value(session, "user-agent"),
            "common bot",
            "",
            true,
        )),
        "geoCountryName" => geo_info(session)
            .map(|g| g.country.to_string())
            .unwrap_or_default(),
        "geoProvinceName" => geo_info(session)
            .map(|g| g.region.to_string())
            .unwrap_or_default(),
        "geoCityName" => geo_info(session)
            .map(|g| g.city.to_string())
            .unwrap_or_default(),
        "ispName" => geo_info(session)
            .map(|g| g.provider.to_string())
            .unwrap_or_else(|| analyzer::lookup_isp_name(parse_remote_ip(session)).to_string()),
        "serverAddr" => get_local_addr(session),
        "serverPort" => get_local_port(session),
        "requestUpload" => upload_summary(&parse_multipart_uploads(session, request_body)),
        "refererBlock" | "cname" => String::new(),
        "isCNAME" => "0".to_string(),
        _ => {
            if let Some(name) = dotted_arg(inner, &["arg", "requestArg"]) {
                return query_param(session, name);
            }
            if let Some(name) = dotted_arg(inner, &["header", "requestHeader"]) {
                return header_value(session, name);
            }
            if let Some(name) = dotted_arg(inner, &["cookie", "requestCookie"]) {
                return cookie_value(session, name);
            }
            if let Some(name) = dotted_arg(inner, &["requestForm", "form"]) {
                return form_value(request_body, name);
            }
            if let Some(path) = dotted_arg(inner, &["requestJSON", "json"]) {
                return json_value(request_body, path);
            }
            if let Some(field) = dotted_arg(inner, &["requestUpload"]) {
                return resolve_upload_param(
                    &parse_multipart_uploads(session, request_body),
                    field,
                );
            }
            if let Some(name) = colon_arg(inner, &["arg"]) {
                return query_param(session, name);
            }
            if let Some(name) = colon_arg(inner, &["header"]) {
                return header_value(session, name);
            }
            if let Some(name) = colon_arg(inner, &["cookie"]) {
                return cookie_value(session, name);
            }
            String::new()
        }
    }
}

pub(crate) fn resolve_variable_with_facts(inner: &str, facts: &RequestFacts<'_>) -> String {
    match inner {
        "remoteAddr" => facts.remote_addr(),
        "rawRemoteAddr" => facts.raw_remote_addr(),
        "remotePort" => facts.remote_port(),
        "remoteUser" => facts
            .session
            .get_header("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .and_then(|v| {
                base64::engine::general_purpose::STANDARD
                    .decode(v.trim())
                    .ok()
            })
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|v| v.split_once(':').map(|(u, _)| u.to_string()))
            .unwrap_or_default(),
        "requestURI" => facts.request_uri(),
        "requestPath" => facts.request_path(),
        "requestURL" => facts.request_url(),
        "requestFileExtension" => facts
            .session
            .req_header()
            .uri
            .path()
            .split('.')
            .last()
            .filter(|ext| !ext.is_empty() && !ext.contains('/'))
            .unwrap_or_default()
            .to_string(),
        "requestLength" => facts
            .session
            .get_header("content-length")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        "requestBody" => facts.request_body_text(),
        "requestAll" => facts.request_all(),
        "requestMethod" => facts.session.req_header().method.as_str().to_string(),
        "scheme" => facts.scheme.to_string(),
        "proto" => format!("{:?}", facts.session.req_header().version),
        "host" | "requestHost" => facts.host(),
        "refererOrigin" => {
            let mut val = header_value(facts.session, "referer");
            let origin = header_value(facts.session, "origin");
            if !origin.is_empty() {
                if !val.is_empty() {
                    val.push(' ');
                }
                val.push_str(&origin);
            }
            val
        }
        "referer" => header_value(facts.session, "referer"),
        "userAgent" => header_value(facts.session, "user-agent"),
        "contentType" => header_value(facts.session, "content-type"),
        "cookies" => facts.cookies_normalized(),
        "args" => facts
            .session
            .req_header()
            .uri
            .query()
            .unwrap_or("")
            .to_string(),
        "headers" => facts.headers(),
        "headerNames" => facts.header_names(),
        "headerMaxLength" => facts.header_max_length().to_string(),
        "requestGeneralHeaderLength" => facts.general_header_length().to_string(),
        "requestPathLowerExtension" => facts.request_path_lower_extension(),
        "commonAIBot" => bool_string(crate::firewall::matcher::evaluate_operator(
            &header_value(facts.session, "user-agent"),
            "common ai bot",
            "",
            true,
        )),
        "commonBot" => bool_string(crate::firewall::matcher::evaluate_operator(
            &header_value(facts.session, "user-agent"),
            "common bot",
            "",
            true,
        )),
        "geoCountryName" => analyzer::lookup_geo(facts.remote_ip())
            .map(|g| g.country.to_string())
            .unwrap_or_default(),
        "geoProvinceName" => analyzer::lookup_geo(facts.remote_ip())
            .map(|g| g.region.to_string())
            .unwrap_or_default(),
        "geoCityName" => analyzer::lookup_geo(facts.remote_ip())
            .map(|g| g.city.to_string())
            .unwrap_or_default(),
        "ispName" => analyzer::lookup_geo(facts.remote_ip())
            .map(|g| g.provider.to_string())
            .unwrap_or_else(|| analyzer::lookup_isp_name(facts.remote_ip()).to_string()),
        "serverAddr" => facts.local_addr(),
        "serverPort" => facts.local_port(),
        "requestUpload" => facts.upload_summary(),
        "refererBlock" => String::new(),
        "cname" => facts.cname(),
        "isCNAME" => facts.is_cname(),
        _ => {
            if let Some(name) = dotted_arg(inner, &["arg", "requestArg"]) {
                return facts.query_param(name);
            }
            if let Some(name) = dotted_arg(inner, &["header", "requestHeader"]) {
                return header_value(facts.session, name);
            }
            if let Some(name) = dotted_arg(inner, &["cookie", "requestCookie"]) {
                return facts.cookie_param(name);
            }
            if let Some(name) = dotted_arg(inner, &["requestForm", "form"]) {
                return facts.form_param(name);
            }
            if let Some(path) = dotted_arg(inner, &["requestJSON", "json"]) {
                return json_value_from_facts(facts, path);
            }
            if let Some(field) = dotted_arg(inner, &["requestUpload"]) {
                return facts.upload_param(field);
            }
            if let Some(name) = colon_arg(inner, &["arg"]) {
                return facts.query_param(name);
            }
            if let Some(name) = colon_arg(inner, &["header"]) {
                return header_value(facts.session, name);
            }
            if let Some(name) = colon_arg(inner, &["cookie"]) {
                return facts.cookie_param(name);
            }
            String::new()
        }
    }
}

fn resolve_response_variable(
    session: &Session,
    inner: &str,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
) -> String {
    let facts = ResponseFacts::new(session, request_body, response, scheme);
    resolve_response_variable_with_facts(inner, &facts)
}

pub(crate) fn resolve_response_variable_with_facts(
    inner: &str,
    facts: &ResponseFacts<'_, '_, '_>,
) -> String {
    match inner {
        "status" => facts.status(),
        "responseBody" => facts.response_body_text(),
        "bytesSent" => facts.bytes_sent(),
        "responseGeneralHeaderLength" => facts.response_general_header_length().to_string(),
        _ => {
            if let Some(name) = dotted_arg(inner, &["responseHeader"]) {
                return facts.response_header(name);
            }
            if let Some(name) = colon_arg(inner, &["responseHeader"]) {
                return facts.response_header(name);
            }
            resolve_variable_with_facts(inner, facts.request())
        }
    }
}

fn get_remote_addr(session: &Session) -> String {
    parse_remote_ip(session).to_string()
}

fn get_remote_port(session: &Session) -> String {
    session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.peer_addr())
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.port().to_string())
        .or_else(|| {
            session.client_addr().and_then(|addr| match addr {
                pingora_core::protocols::l4::socket::SocketAddr::Inet(addr) => {
                    Some(addr.port().to_string())
                }
                _ => None,
            })
        })
        .unwrap_or_default()
}

fn get_local_addr(session: &Session) -> String {
    session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.local_addr())
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.ip().to_string())
        .unwrap_or_default()
}

fn get_local_port(session: &Session) -> String {
    session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.local_addr())
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.port().to_string())
        .unwrap_or_default()
}

pub(crate) fn parse_remote_ip(session: &Session) -> std::net::IpAddr {
    let peer_ip = peer_socket_ip(session);
    let canonicalize = |ip: std::net::IpAddr| -> std::net::IpAddr {
        if let std::net::IpAddr::V6(v6) = ip {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return std::net::IpAddr::V4(v4);
            }
        }
        ip
    };
    // Only trust forwarded-for-style headers when the immediate peer is local
    // (loopback / private). Public clients can forge these headers to bypass
    // CC counters, IP blacklists, and rule matches. The trust boundary mirrors
    // proxy::resolve_client_ip.
    let trust_headers = peer_ip.map(|ip| is_local_ip(&ip)).unwrap_or(false);
    if trust_headers {
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
            if let Some(value) = session
                .get_header(header)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().trim_matches('"').trim_matches('\''))
            {
                let mut candidate = value;
                if let Some(v) = candidate
                    .strip_prefix("for=")
                    .or_else(|| candidate.strip_prefix("For="))
                {
                    candidate = v.trim();
                }
                if let Some((first, _)) = candidate.split_once(';') {
                    candidate = first.trim();
                }
                if let Some((first, _)) = candidate.split_once(',') {
                    candidate = first.trim();
                }
                let candidate = candidate.trim_matches(|c| c == '[' || c == ']');
                if let Ok(ip) = candidate.parse::<std::net::IpAddr>() {
                    return canonicalize(ip);
                }
            }
        }
    }
    canonicalize(peer_ip.unwrap_or(std::net::IpAddr::from([127, 0, 0, 1])))
}

fn peer_socket_ip(session: &Session) -> Option<std::net::IpAddr> {
    session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.peer_addr())
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.ip())
        .or_else(|| {
            session.client_addr().and_then(|addr| match addr {
                pingora_core::protocols::l4::socket::SocketAddr::Inet(addr) => Some(addr.ip()),
                _ => None,
            })
        })
}

fn geo_info(session: &Session) -> Option<analyzer::GeoInfo> {
    analyzer::lookup_geo(parse_remote_ip(session))
}

fn get_request_uri(session: &Session) -> String {
    let path = session.req_header().uri.path();
    let query = session
        .req_header()
        .uri
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    format!("{}{}", path, query)
}

fn get_raw_remote_addr(session: &Session) -> String {
    session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.peer_addr())
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.ip().to_string())
        .or_else(|| {
            session.client_addr().and_then(|addr| match addr {
                pingora_core::protocols::l4::socket::SocketAddr::Inet(addr) => {
                    Some(addr.ip().to_string())
                }
                _ => None,
            })
        })
        .unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]).to_string())
}

fn header_value(session: &Session, name: &str) -> String {
    session
        .get_header(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn response_header_value(response: &OutboundContext<'_>, name: &str) -> String {
    response
        .headers
        .get(&name.to_ascii_lowercase())
        .cloned()
        .unwrap_or_default()
}

fn merged_cookie_header(session: &Session) -> String {
    session
        .req_header()
        .headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

fn normalize_cookies(session: &Session) -> String {
    merged_cookie_header(session)
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("&")
}

fn all_headers(session: &Session) -> String {
    let mut headers = session
        .req_header()
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| format!("{}: {}", name.as_str(), v))
        })
        .collect::<Vec<_>>();
    headers.sort();
    headers.join("\n")
}

fn header_names(session: &Session) -> String {
    let mut headers = session
        .req_header()
        .headers
        .keys()
        .map(|name| name.as_str().to_string())
        .collect::<Vec<_>>();
    headers.sort();
    headers.join("\n")
}

fn header_max_length(session: &Session) -> usize {
    session
        .req_header()
        .headers
        .iter()
        .filter_map(|(name, value)| value.to_str().ok().map(|v| name.as_str().len() + v.len()))
        .max()
        .unwrap_or(0)
}

fn general_header_length(session: &Session) -> usize {
    session
        .req_header()
        .headers
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str().to_ascii_lowercase().as_str(),
                "cookie" | "set-cookie" | "referer" | "origin" | "user-agent"
            )
        })
        .filter_map(|(name, value)| value.to_str().ok().map(|v| name.as_str().len() + v.len()))
        .sum()
}

fn request_path_lower_extension(session: &Session) -> String {
    std::path::Path::new(session.req_header().uri.path())
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
        .unwrap_or_default()
}

fn dotted_arg<'a>(inner: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes.iter().find_map(|prefix| {
        inner
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix("."))
    })
}

fn colon_arg<'a>(inner: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes
        .iter()
        .find_map(|prefix| inner.strip_prefix(&format!("{prefix}:")))
}

fn query_param(session: &Session, name: &str) -> String {
    session
        .req_header()
        .uri
        .query()
        .and_then(|q| {
            q.split('&').find_map(|part| {
                let mut iter = part.splitn(2, '=');
                let key = iter.next()?;
                let decoded_key =
                    urlencoding::decode(key).unwrap_or_else(|_| std::borrow::Cow::Borrowed(key));
                if decoded_key == name {
                    let value = iter.next().unwrap_or("");
                    Some(
                        urlencoding::decode(value)
                            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(value))
                            .into_owned(),
                    )
                } else {
                    None
                }
            })
        })
        .unwrap_or_default()
}

fn parse_query_params(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .filter_map(|part| {
            if part.is_empty() {
                return None;
            }
            let mut iter = part.splitn(2, '=');
            let key = iter.next()?;
            let decoded_key = urlencoding::decode(key)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(key))
                .into_owned();
            let value = iter.next().unwrap_or("");
            let decoded_value = urlencoding::decode(value)
                .unwrap_or_else(|_| std::borrow::Cow::Borrowed(value))
                .into_owned();
            Some((decoded_key, decoded_value))
        })
        .collect()
}

fn parse_cookie_params(input: &str) -> Vec<(String, String)> {
    input
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            let mut iter = part.splitn(2, '=');
            let key = iter.next()?;
            Some((key.to_string(), iter.next().unwrap_or("").to_string()))
        })
        .collect()
}

fn cookie_value(session: &Session, name: &str) -> String {
    merged_cookie_header(session)
        .split(';')
        .find_map(|part| {
            let mut iter = part.trim().splitn(2, '=');
            let key = iter.next()?;
            if key == name {
                Some(iter.next().unwrap_or("").to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn form_value(request_body: &[u8], name: &str) -> String {
    String::from_utf8_lossy(request_body)
        .split('&')
        .find_map(|part| {
            let mut iter = part.splitn(2, '=');
            let key = iter.next()?;
            if key == name {
                Some(iter.next().unwrap_or("").to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

#[derive(Clone, Debug)]
struct UploadPart {
    field_name: String,
    filename: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

fn parse_multipart_uploads(session: &Session, request_body: &[u8]) -> Vec<UploadPart> {
    let Some(boundary) = multipart_boundary(session) else {
        return Vec::new();
    };
    if boundary.is_empty() || request_body.is_empty() {
        return Vec::new();
    }

    let body = String::from_utf8_lossy(request_body);
    let delimiter = format!("--{}", boundary);
    body.split(&delimiter)
        .filter_map(parse_multipart_part)
        .collect()
}

fn multipart_boundary(session: &Session) -> Option<String> {
    let content_type = header_value(session, "content-type");
    let mut parts = content_type.split(';');
    if !parts
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("multipart/form-data"))
    {
        return None;
    }
    parts.find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        name.trim().eq_ignore_ascii_case("boundary").then(|| {
            value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string()
        })
    })
}

fn parse_multipart_part(raw: &str) -> Option<UploadPart> {
    let raw = raw.trim_start_matches("\r\n");
    if raw.is_empty() || raw.starts_with("--") {
        return None;
    }
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))?;
    let mut field_name = None;
    let mut filename = None;
    let mut content_type = None;
    for header in headers.lines() {
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-disposition") {
            for attr in value.split(';').map(str::trim) {
                if let Some(value) = attr.strip_prefix("name=") {
                    field_name = Some(value.trim_matches('"').to_string());
                } else if let Some(value) = attr.strip_prefix("filename=") {
                    filename = Some(value.trim_matches('"').to_string());
                }
            }
        } else if name.trim().eq_ignore_ascii_case("content-type") {
            content_type = Some(value.trim().to_string());
        }
    }
    let field_name = field_name?;
    let body = body
        .trim_end_matches("\r\n")
        .trim_end_matches('\n')
        .as_bytes()
        .to_vec();
    Some(UploadPart {
        field_name,
        filename,
        content_type,
        body,
    })
}

fn resolve_upload_param(parts: &[UploadPart], name: &str) -> String {
    let (field, attr) = name.split_once('.').unwrap_or((name, ""));
    parts
        .iter()
        .find(|part| part.field_name == field)
        .map(|part| match attr {
            "filename" => part.filename.clone().unwrap_or_default(),
            "contentType" | "content-type" => part.content_type.clone().unwrap_or_default(),
            "size" => part.body.len().to_string(),
            _ => part
                .filename
                .clone()
                .unwrap_or_else(|| String::from_utf8_lossy(&part.body).to_string()),
        })
        .unwrap_or_default()
}

fn upload_summary(parts: &[UploadPart]) -> String {
    parts
        .iter()
        .map(|part| {
            let filename = part.filename.as_deref().unwrap_or("");
            let content_type = part.content_type.as_deref().unwrap_or("");
            format!(
                "{}:{}:{}:{}",
                part.field_name,
                filename,
                content_type,
                part.body.len()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn json_value(request_body: &[u8], path: &str) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(request_body) else {
        return String::new();
    };
    json_value_from_root(&value, path)
}

fn json_value_from_facts(facts: &RequestFacts<'_>, path: &str) -> String {
    facts
        .json_body()
        .map(|value| json_value_from_root(value, path))
        .unwrap_or_default()
}

fn json_value_from_root(value: &Value, path: &str) -> String {
    let mut current = value;
    for segment in path.split('.') {
        match current {
            Value::Object(map) => {
                let Some(next) = map.get(segment) else {
                    return String::new();
                };
                current = next;
            }
            Value::Array(items) => {
                let Ok(index) = segment.parse::<usize>() else {
                    return String::new();
                };
                let Some(next) = items.get(index) else {
                    return String::new();
                };
                current = next;
            }
            _ => return String::new(),
        }
    }
    match current {
        Value::Null => String::new(),
        Value::Bool(v) => bool_string(*v),
        Value::Number(v) => v.to_string(),
        Value::String(v) => v.clone(),
        _ => current.to_string(),
    }
}

fn bool_string(v: bool) -> String {
    if v { "1".to_string() } else { "0".to_string() }
}

fn apply_modifier(value: String, modifier: &str) -> String {
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
            use sha1::Sha1;
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

pub fn format_variables(
    session: &Session,
    template: &str,
    request_body: &[u8],
    scheme: &str,
) -> String {
    static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));
    RE_VAR
        .replace_all(template, |caps: &regex::Captures| {
            let inner = &caps[0];
            let inner = inner
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(inner);
            let mut parts = inner.split('|');
            let var_name = parts.next().unwrap_or("");
            let mut value = match var_name {
                "rawRemoteAddr" => get_raw_remote_addr(session),
                "requestPathExtension" => std::path::Path::new(session.req_header().uri.path())
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| format!(".{}", ext))
                    .unwrap_or_default(),
                "requestFilename" => session.req_header().uri.path().to_string(),
                _ => resolve_variable(session, var_name, request_body, scheme),
            };
            for modifier in parts {
                value = apply_modifier(value, modifier);
            }
            value
        })
        .to_string()
}

pub fn format_response_variables(
    session: &Session,
    template: &str,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
) -> String {
    static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));
    RE_VAR
        .replace_all(template, |caps: &regex::Captures| {
            let inner = &caps[0];
            let inner = inner
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(inner);
            let mut parts = inner.split('|');
            let var_name = parts.next().unwrap_or("");
            let mut value = match var_name {
                "rawRemoteAddr" => get_raw_remote_addr(session),
                "requestPathExtension" => std::path::Path::new(session.req_header().uri.path())
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| format!(".{}", ext))
                    .unwrap_or_default(),
                "requestFilename" => session.req_header().uri.path().to_string(),
                _ => resolve_response_variable(session, var_name, request_body, response, scheme),
            };
            for modifier in parts {
                value = apply_modifier(value, modifier);
            }
            value
        })
        .to_string()
}
