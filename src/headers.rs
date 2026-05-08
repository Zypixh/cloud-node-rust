use crate::config_models::{HTTPHeaderConfig, HTTPHeaderPolicy, HTTPHeaderReplaceValue};
use crate::utils::template::format_template;
use http::HeaderValue;
use http::header::HeaderName;
use pingora_proxy::Session;
use regex::Regex;
use std::str::FromStr;

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
        if let Ok(header_name) = HeaderName::from_str(name) {
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
        if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(name), HeaderValue::from_str(&resolved)) {
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
        if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(name), HeaderValue::from_str(&resolved)) {
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
        if let Ok(header_name) = HeaderName::from_str(name) {
            upstream_request.remove_header(&header_name);
        }
    }

    // Set headers (overwrite existing)
    for h in &policy.set_headers {
        if !h.is_on {
            continue;
        }
        let resolved = resolve(&h.value);
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_str(&h.name),
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
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_str(&h.name),
            HeaderValue::from_str(&resolved),
        ) {
            if upstream_request.headers.get(&hn).is_none() {
                upstream_request.insert_header(hn, hv).ok();
            }
        }
    }
}

fn domain_matches(patterns: &[String], domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        if pattern == domain || pattern == "*" {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix('.') {
            return domain.ends_with(&format!(".{}", suffix));
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            return domain == suffix || domain.ends_with(&format!(".{}", suffix));
        }
        if pattern.contains('*') {
            let regex = format!("^{}$", regex::escape(&pattern).replace("\\*", "[^.]*"));
            return Regex::new(&regex)
                .map(|re| re.is_match(&domain))
                .unwrap_or(false);
        }
        false
    })
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
        Regex::new(&pattern)
            .map(|re| {
                re.replace_all(&value, rule.replacement.as_str())
                    .into_owned()
            })
            .unwrap_or(value)
    } else {
        value.replace(&rule.pattern, &rule.replacement)
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
                value = headers
                    .headers
                    .get(header.name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
            }
            for rule in &header.replace_values {
                value = replace_header_value(value, rule);
            }
        }
        let Ok(name) = HeaderName::from_str(&header.name) else {
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
        let Ok(name) = HeaderName::from_str(&header.name) else {
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
            .map(str::to_string)
        {
            let Ok(name) = HeaderName::from_str(&rh.name) else {
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
