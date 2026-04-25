use crate::config_models::{HTTPFirewallRule, HTTPFirewallRuleGroup, HTTPFirewallRuleSet};
use crate::firewall::OutboundContext;
use crate::metrics::analyzer;
use base64::Engine as _;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_proxy::Session;
use regex::Regex;
use serde_json::Value;

pub struct MatchResult<'a> {
    pub matched: bool,
    pub set: Option<&'a HTTPFirewallRuleSet>,
}

pub fn match_group<'a>(
    group: &'a HTTPFirewallRuleGroup,
    session: &Session,
    request_body: &[u8],
) -> Option<MatchResult<'a>> {
    if !group.is_on {
        return None;
    }

    if let Some(code) = &group.code {
        if match_preset_group(code, session, request_body) {
            return Some(MatchResult {
                matched: true,
                set: None,
            });
        }
    }

    for set in &group.sets {
        if match_set(set, session, request_body) {
            return Some(MatchResult {
                matched: true,
                set: Some(set),
            });
        }
    }

    None
}

pub fn match_set(set: &HTTPFirewallRuleSet, session: &Session, request_body: &[u8]) -> bool {
    if !set.is_on || set.rules.is_empty() {
        return false;
    }

    // Bypass check
    let ip = parse_remote_ip(session);
    if set.ignore_local && is_local_ip(&ip) {
        return false;
    }
    if set.ignore_search_engine
        && crate::firewall::matcher::evaluate_operator(
            &header_value(session, "user-agent"),
            "common bot",
            "",
            true,
        )
    {
        return false;
    }

    if set.connector == "and" {
        set.rules
            .iter()
            .all(|rule| match_rule(rule, session, request_body))
    } else {
        set.rules
            .iter()
            .any(|rule| match_rule(rule, session, request_body))
    }
}

pub fn match_set_response(
    set: &HTTPFirewallRuleSet,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
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
        && crate::firewall::matcher::evaluate_operator(
            &header_value(session, "user-agent"),
            "common bot",
            "",
            true,
        )
    {
        return false;
    }

    if set.connector == "and" {
        set.rules
            .iter()
            .all(|rule| match_rule_response(rule, session, request_body, response))
    } else {
        set.rules
            .iter()
            .any(|rule| match_rule_response(rule, session, request_body, response))
    }
}

pub fn match_group_response<'a>(
    group: &'a HTTPFirewallRuleGroup,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
) -> Option<MatchResult<'a>> {
    if !group.is_on {
        return None;
    }

    for set in &group.sets {
        if match_set_response(set, session, request_body, response) {
            return Some(MatchResult {
                matched: true,
                set: Some(set),
            });
        }
    }

    None
}

fn is_local_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            let octets = v6.octets();
            // Simple check for unique local and loopback
            (octets[0] & 0xfe == 0xfc) || v6.is_loopback()
        }
    }
}

pub fn match_rule(rule: &HTTPFirewallRule, session: &Session, request_body: &[u8]) -> bool {
    let param_value = get_rule_value(rule, session, request_body);
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
) -> bool {
    let param_value = get_response_rule_value(rule, session, request_body, response);
    let matched = crate::firewall::matcher::evaluate_operator(
        &param_value,
        &rule.operator,
        &rule.value,
        rule.is_case_insensitive,
    );

    if rule.is_reverse { !matched } else { matched }
}

fn match_preset_group(code: &str, session: &Session, request_body: &[u8]) -> bool {
    let check_str = get_full_request_data(session, request_body);
    match code {
        "sqlInjection" => crate::firewall::matcher::evaluate_operator(
            &check_str,
            "contains sql injection",
            "",
            true,
        ),
        "sqlInjectionStrict" => crate::firewall::matcher::evaluate_operator(
            &check_str,
            "contains sql injection strictly",
            "",
            true,
        ),
        "xss" => crate::firewall::matcher::evaluate_operator(&check_str, "contains xss", "", true),
        "xssStrict" => crate::firewall::matcher::evaluate_operator(
            &check_str,
            "contains xss strictly",
            "",
            true,
        ),
        "cmdInjection" => crate::firewall::matcher::evaluate_operator(
            &check_str,
            "contains cmd injection",
            "",
            true,
        ),
        _ => false,
    }
}

static CC_COUNTERS: Lazy<DashMap<String, Vec<i64>>> = Lazy::new(DashMap::new);

fn get_full_request_data(session: &Session, request_body: &[u8]) -> String {
    let mut data = session.req_header().uri.to_string();
    if let Some(cookies) = session.get_header("cookie").and_then(|v| v.to_str().ok()) {
        data.push_str(cookies);
    }
    if !request_body.is_empty() {
        data.push_str(&String::from_utf8_lossy(request_body));
    }
    data
}

fn get_variable_value(session: &Session, param: &str, request_body: &[u8]) -> String {
    if !param.contains("${") {
        return param.to_string();
    }

    static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));

    if let Some(inner) = param.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        return resolve_variable(session, inner, request_body);
    }

    RE_VAR
        .replace_all(param, |caps: &regex::Captures| {
            let inner = &caps[0];
            let inner = inner
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(inner);
            resolve_variable(session, inner, request_body)
        })
        .to_string()
}

fn get_rule_value(rule: &HTTPFirewallRule, session: &Session, request_body: &[u8]) -> String {
    if rule.param.starts_with("${cc.")
        || rule.param == "${cc}"
        || rule.param.starts_with("${cc2.")
        || rule.param == "${cc2}"
    {
        return cc_value(rule, session, request_body, true);
    }
    get_variable_value(session, &rule.param, request_body)
}

fn get_response_rule_value(
    rule: &HTTPFirewallRule,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
) -> String {
    if rule.param.starts_with("${cc.")
        || rule.param == "${cc}"
        || rule.param.starts_with("${cc2.")
        || rule.param == "${cc2}"
    {
        return cc_value(rule, session, request_body, true);
    }
    get_response_variable_value(session, &rule.param, request_body, response)
}

fn cc_value(
    rule: &HTTPFirewallRule,
    session: &Session,
    request_body: &[u8],
    is_cc2: bool,
) -> String {
    let options = rule.checkpoint_options.as_ref();
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
            .map(|template| get_variable_value(session, template, request_body))
            .collect::<Vec<_>>();
        format!("WAF-CC2-{}-{}", rule.param, key_values.join("@"))
    } else {
        get_remote_addr(session)
    };

    increase_counter(key, period).to_string()
}

fn increase_counter(key: String, period_secs: i64) -> u64 {
    let now = crate::utils::time::now_timestamp();
    let min_ts = now - period_secs.max(1);
    let mut entry = CC_COUNTERS.entry(key).or_default();
    entry.retain(|ts| *ts >= min_ts);
    entry.push(now);
    entry.len() as u64
}

fn get_response_variable_value(
    session: &Session,
    param: &str,
    request_body: &[u8],
    response: &OutboundContext<'_>,
) -> String {
    if !param.contains("${") {
        return param.to_string();
    }

    static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));

    if let Some(inner) = param.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        return resolve_response_variable(session, inner, request_body, response);
    }

    RE_VAR
        .replace_all(param, |caps: &regex::Captures| {
            let inner = &caps[0];
            let inner = inner
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(inner);
            resolve_response_variable(session, inner, request_body, response)
        })
        .to_string()
}

fn resolve_variable(session: &Session, inner: &str, request_body: &[u8]) -> String {
    match inner {
        "remoteAddr" | "rawRemoteAddr" => get_remote_addr(session),
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
            get_scheme(session),
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
        "scheme" => get_scheme(session),
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
        "geoCountryName" => geo_info(session).map(|g| g.country).unwrap_or_default(),
        "geoProvinceName" => geo_info(session).map(|g| g.region).unwrap_or_default(),
        "geoCityName" => geo_info(session).map(|g| g.city).unwrap_or_default(),
        "ispName" => geo_info(session)
            .map(|g| g.provider)
            .unwrap_or_else(|| analyzer::lookup_isp_name(parse_remote_ip(session))),
        "serverAddr" => get_local_addr(session),
        "serverPort" => get_local_port(session),
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
            if let Some(_field) = dotted_arg(inner, &["requestUpload"]) {
                return String::new();
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

fn resolve_response_variable(
    session: &Session,
    inner: &str,
    request_body: &[u8],
    response: &OutboundContext<'_>,
) -> String {
    match inner {
        "status" => response.status.to_string(),
        "responseBody" => String::from_utf8_lossy(response.body).to_string(),
        "bytesSent" => response.bytes_sent.to_string(),
        "responseGeneralHeaderLength" => response
            .headers
            .iter()
            .filter(|(name, _)| {
                !matches!(
                    name.as_str(),
                    "set-cookie" | "location" | "content-type" | "content-length"
                )
            })
            .map(|(name, value)| name.len() + value.len())
            .sum::<usize>()
            .to_string(),
        _ => {
            if let Some(name) = dotted_arg(inner, &["responseHeader"]) {
                return response_header_value(response, name);
            }
            if let Some(name) = colon_arg(inner, &["responseHeader"]) {
                return response_header_value(response, name);
            }
            resolve_variable(session, inner, request_body)
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

fn parse_remote_ip(session: &Session) -> std::net::IpAddr {
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
            if let Ok(ip) = candidate.parse() {
                return ip;
            }
        }
    }
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
        .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]))
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

fn get_scheme(session: &Session) -> String {
    let is_tls = session
        .downstream_session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some();
    if is_tls || session.req_header().uri.scheme_str() == Some("https") {
        "https".to_string()
    } else {
        let xfp = header_value(session, "x-forwarded-proto");
        if !xfp.is_empty() {
            xfp
        } else {
            "http".to_string()
        }
    }
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

fn normalize_cookies(session: &Session) -> String {
    session
        .get_header("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|cookies| {
            cookies
                .split(';')
                .map(|part| part.trim())
                .collect::<Vec<_>>()
                .join("&")
        })
        .unwrap_or_default()
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
                if key == name {
                    Some(iter.next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default()
}

fn cookie_value(session: &Session, name: &str) -> String {
    session
        .get_header("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|part| {
                let mut iter = part.trim().splitn(2, '=');
                let key = iter.next()?;
                if key == name {
                    Some(iter.next().unwrap_or("").to_string())
                } else {
                    None
                }
            })
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

fn json_value(request_body: &[u8], path: &str) -> String {
    let Ok(value) = serde_json::from_slice::<Value>(request_body) else {
        return String::new();
    };
    let mut current = &value;
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

pub fn format_variables(session: &Session, template: &str, request_body: &[u8]) -> String {
    static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));
    RE_VAR
        .replace_all(template, |caps: &regex::Captures| {
            let inner = &caps[0];
            let inner = inner
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or(inner);
            resolve_variable(session, inner, request_body)
        })
        .to_string()
}
