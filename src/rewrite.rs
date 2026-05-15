use crate::config_models::{HTTPHostRedirectConfig, HTTPRewriteRef, HTTPRewriteRule};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;
use tracing::debug;

#[derive(Debug)]
pub enum RewriteResult {
    /// Continue to proxy with possibly modified URI
    Proxy {
        new_uri: String,
        proxy_host: Option<String>,
        rewrite_id: i64,
    },
    /// Redirect to another URL
    Redirect {
        location: String,
        status: u16,
        rewrite_id: i64,
    },
    /// No rewrite matched, continue with original
    NoMatch,
}

/// Match and evaluate rewrite rules using the legacy configureWeb/doRewrite behavior.
static REWRITE_RE_CACHE: Lazy<DashMap<String, std::sync::Arc<Regex>>> = Lazy::new(DashMap::new);

fn rewrite_pattern_regex(pattern: &str) -> Option<Arc<Regex>> {
    if let Some(cached) = REWRITE_RE_CACHE.get(pattern) {
        return Some(cached.clone());
    }
    let compiled = if pattern == "*" {
        Regex::new("^/(.*)$")
    } else {
        Regex::new(pattern)
    }
    .ok()?;
    let re = Arc::new(compiled);
    REWRITE_RE_CACHE.insert(pattern.to_string(), Arc::clone(&re));
    Some(re)
}

fn expand_rewrite_replacement(
    regex: &Regex,
    captures: &regex::Captures<'_>,
    replacement: &str,
) -> String {
    let mut result = expand_go_regex_replacement(regex, captures, replacement);
    for index in 0..captures.len() {
        let value = captures.get(index).map(|m| m.as_str()).unwrap_or_default();
        result = result.replace(&format!("${}", index), value);
    }
    result
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_proxy_target(
    target: String,
    configured_proxy_host: Option<String>,
) -> (String, Option<String>) {
    if let Ok(uri) = target.parse::<http::Uri>()
        && uri.scheme().is_some()
        && let Some(host) = uri.host()
    {
        let path = uri
            .path_and_query()
            .map(|path| path.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        return (
            path,
            configured_proxy_host.or_else(|| Some(host.to_string())),
        );
    }

    if !target.starts_with('/')
        && !target.starts_with('?')
        && let Some((host, rest)) = target.split_once('/')
        && host.contains('.')
        && !host.contains('@')
    {
        return (
            format!("/{}", rest),
            configured_proxy_host.or_else(|| Some(host.to_string())),
        );
    }

    (target, configured_proxy_host)
}

pub fn evaluate_rewrites(
    original_uri: &str,
    raw_query: &str,
    rewrite_refs: &[HTTPRewriteRef],
    rewrite_rules: &[HTTPRewriteRule],
) -> RewriteResult {
    evaluate_rewrites_with_host(original_uri, raw_query, None, rewrite_refs, rewrite_rules)
}

pub fn evaluate_rewrites_with_host(
    original_uri: &str,
    raw_query: &str,
    current_host: Option<&str>,
    rewrite_refs: &[HTTPRewriteRef],
    rewrite_rules: &[HTTPRewriteRule],
) -> RewriteResult {
    evaluate_rewrites_with_cond(
        original_uri,
        raw_query,
        current_host,
        rewrite_refs,
        rewrite_rules,
        |_| true,
    )
}

pub fn evaluate_rewrites_with_cond(
    original_uri: &str,
    raw_query: &str,
    current_host: Option<&str>,
    rewrite_refs: &[HTTPRewriteRef],
    rewrite_rules: &[HTTPRewriteRule],
    mut cond_matches: impl FnMut(&HTTPRewriteRule) -> bool,
) -> RewriteResult {
    let mut uri = original_uri.to_string();
    let current_host = current_host.map(normalize_host);
    let mut matched_rewrite_id = 0;
    let mut matched_proxy_host = None;

    // Support recursive rewrites up to 8 levels (Go parity)
    for _iteration in 0..8 {
        let mut matched_this_pass = false;

        for (i, rule) in rewrite_rules.iter().enumerate() {
            if !rule.is_on {
                continue;
            }
            if let Some(rule_ref) = rewrite_refs.get(i)
                && !rule_ref.is_on
            {
                continue;
            }
            if !cond_matches(rule) {
                continue;
            }
            let Some(pattern) = &rule.pattern else {
                continue;
            };
            let Some(replace) = &rule.replace else {
                continue;
            };

            let Some(re) = rewrite_pattern_regex(pattern) else {
                debug!("Invalid rewrite pattern: {}", pattern);
                continue;
            };

            let path = uri.split('?').next().unwrap_or(&uri);

            if let Some(captures) = re.captures(path) {
                let matched = captures.get(0).expect("captures always include full match");
                let replacement = expand_rewrite_replacement(&re, &captures, replace.as_str());
                let mut replaced =
                    String::with_capacity(path.len() - matched.as_str().len() + replacement.len());
                replaced.push_str(&path[..matched.start()]);
                replaced.push_str(&replacement);
                replaced.push_str(&path[matched.end()..]);

                let final_url = if rule.with_query && !raw_query.is_empty() {
                    if replaced.contains('?') {
                        format!("{}&{}", replaced, raw_query)
                    } else {
                        format!("{}?{}", replaced, raw_query)
                    }
                } else {
                    replaced
                };

                let mode = rule.mode.as_deref().unwrap_or("proxy");
                match mode {
                    "redirect" => {
                        let status = if rule.redirect_status > 0 {
                            rule.redirect_status as u16
                        } else {
                            307
                        };
                        return RewriteResult::Redirect {
                            location: final_url,
                            status,
                            rewrite_id: rule.id.unwrap_or_default(),
                        };
                    }
                    _ => {
                        let (new_uri, proxy_host) =
                            normalize_proxy_target(final_url, rule.proxy_host.clone());
                        let proxy_host = proxy_host.filter(|host| {
                            current_host
                                .as_deref()
                                .is_none_or(|current| normalize_host(host) != current)
                        });

                        if new_uri == uri && proxy_host == matched_proxy_host {
                            break;
                        }

                        if new_uri == uri && proxy_host.is_some() {
                            return RewriteResult::Proxy {
                                new_uri,
                                proxy_host,
                                rewrite_id: rule.id.unwrap_or_default(),
                            };
                        }

                        matched_rewrite_id = rule.id.unwrap_or_default();
                        matched_this_pass = true;
                        if proxy_host.is_some() {
                            matched_proxy_host = proxy_host.clone();
                        }
                        uri = new_uri;

                        if rule.is_break {
                            return RewriteResult::Proxy {
                                new_uri: uri,
                                proxy_host,
                                rewrite_id: rule.id.unwrap_or_default(),
                            };
                        }
                        break;
                    }
                }
            }
        }

        if !matched_this_pass {
            break;
        }
    }

    if uri != original_uri {
        return RewriteResult::Proxy {
            new_uri: uri,
            proxy_host: matched_proxy_host,
            rewrite_id: matched_rewrite_id,
        };
    }

    RewriteResult::NoMatch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_works_without_refs() {
        let rules = vec![HTTPRewriteRule {
            is_on: true,
            pattern: Some("/MoyuNetworkApi".to_string()),
            replace: Some("/api/v1".to_string()),
            ..Default::default()
        }];

        match evaluate_rewrites("/MoyuNetworkApi/passport/auth/login", "", &[], &rules) {
            RewriteResult::Proxy {
                new_uri,
                proxy_host,
                rewrite_id,
            } => {
                assert_eq!(new_uri, "/api/v1/passport/auth/login");
                assert!(proxy_host.is_none());
                assert_eq!(rewrite_id, 0);
            }
            other => panic!("unexpected rewrite result: {:?}", other),
        }
    }

    #[test]
    fn rewrite_respects_disabled_ref_when_present() {
        let rules = vec![HTTPRewriteRule {
            is_on: true,
            pattern: Some("/MoyuNetworkApi".to_string()),
            replace: Some("/api/v1".to_string()),
            ..Default::default()
        }];
        let refs = vec![HTTPRewriteRef { is_on: false }];

        assert!(matches!(
            evaluate_rewrites("/MoyuNetworkApi/passport/auth/login", "", &refs, &rules),
            RewriteResult::NoMatch
        ));
    }

    #[test]
    fn rewrite_skips_rule_when_condition_callback_rejects() {
        let rules = vec![HTTPRewriteRule {
            id: Some(6),
            is_on: true,
            pattern: Some("^/old$".to_string()),
            replace: Some("/new".to_string()),
            ..Default::default()
        }];

        assert!(matches!(
            evaluate_rewrites_with_cond("/old", "", None, &[], &rules, |_| false),
            RewriteResult::NoMatch
        ));
    }

    #[test]
    fn rewrite_supports_documented_capture_syntax() {
        let rules = vec![HTTPRewriteRule {
            id: Some(7),
            is_on: true,
            pattern: Some("^/MoyuNetworkApi/(.*)$".to_string()),
            replace: Some("/api/v1/${1}".to_string()),
            ..Default::default()
        }];

        match evaluate_rewrites("/MoyuNetworkApi/passport/auth/login", "", &[], &rules) {
            RewriteResult::Proxy {
                new_uri,
                proxy_host,
                rewrite_id,
            } => {
                assert_eq!(new_uri, "/api/v1/passport/auth/login");
                assert!(proxy_host.is_none());
                assert_eq!(rewrite_id, 7);
            }
            other => panic!("unexpected rewrite result: {:?}", other),
        }
    }

    #[test]
    fn rewrite_wildcard_target_url_keeps_query_when_enabled() {
        let rules = vec![HTTPRewriteRule {
            id: Some(8),
            is_on: true,
            pattern: Some("*".to_string()),
            replace: Some("st.mymya.cn/api/v1/${1}".to_string()),
            with_query: true,
            is_break: true,
            ..Default::default()
        }];

        match evaluate_rewrites("/passport/auth/login", "x=1", &[], &rules) {
            RewriteResult::Proxy {
                new_uri,
                proxy_host,
                rewrite_id,
            } => {
                assert_eq!(new_uri, "/api/v1/passport/auth/login?x=1");
                assert_eq!(proxy_host.as_deref(), Some("st.mymya.cn"));
                assert_eq!(rewrite_id, 8);
            }
            other => panic!("unexpected rewrite result: {:?}", other),
        }
    }

    #[test]
    fn rewrite_full_url_target_sets_proxy_host() {
        let rules = vec![HTTPRewriteRule {
            id: Some(9),
            is_on: true,
            pattern: Some("^/old$".to_string()),
            replace: Some("https://example.com/new".to_string()),
            ..Default::default()
        }];

        match evaluate_rewrites("/old", "", &[], &rules) {
            RewriteResult::Proxy {
                new_uri,
                proxy_host,
                rewrite_id,
            } => {
                assert_eq!(new_uri, "/new");
                assert_eq!(proxy_host.as_deref(), Some("example.com"));
                assert_eq!(rewrite_id, 9);
            }
            other => panic!("unexpected rewrite result: {:?}", other),
        }
    }

    #[test]
    fn rewrite_preserves_proxy_host_across_followup_path_rewrite() {
        let rules = vec![
            HTTPRewriteRule {
                id: Some(10),
                is_on: true,
                pattern: Some("^/old/(.*)$".to_string()),
                replace: Some("example.com/api/${1}".to_string()),
                ..Default::default()
            },
            HTTPRewriteRule {
                id: Some(11),
                is_on: true,
                pattern: Some("^/api/(.*)$".to_string()),
                replace: Some("/v1/${1}".to_string()),
                ..Default::default()
            },
        ];

        match evaluate_rewrites("/old/users", "", &[], &rules) {
            RewriteResult::Proxy {
                new_uri,
                proxy_host,
                rewrite_id,
            } => {
                assert_eq!(new_uri, "/v1/users");
                assert_eq!(proxy_host.as_deref(), Some("example.com"));
                assert_eq!(rewrite_id, 11);
            }
            other => panic!("unexpected rewrite result: {:?}", other),
        }
    }

    #[test]
    fn rewrite_stops_on_followup_noop_without_dropping_previous_change() {
        let rules = vec![
            HTTPRewriteRule {
                id: Some(12),
                is_on: true,
                pattern: Some("^/old/(.*)$".to_string()),
                replace: Some("/api/${1}".to_string()),
                ..Default::default()
            },
            HTTPRewriteRule {
                id: Some(13),
                is_on: true,
                pattern: Some("^/api/(.*)$".to_string()),
                replace: Some("/api/${1}".to_string()),
                ..Default::default()
            },
        ];

        match evaluate_rewrites("/old/users", "", &[], &rules) {
            RewriteResult::Proxy {
                new_uri,
                proxy_host,
                rewrite_id,
            } => {
                assert_eq!(new_uri, "/api/users");
                assert!(proxy_host.is_none());
                assert_eq!(rewrite_id, 12);
            }
            other => panic!("unexpected rewrite result: {:?}", other),
        }
    }

    #[test]
    fn rewrite_to_same_host_and_path_is_no_match() {
        let rules = vec![HTTPRewriteRule {
            id: Some(12),
            is_on: true,
            pattern: Some("^/api/(.*)$".to_string()),
            replace: Some("https://example.com/api/${1}".to_string()),
            ..Default::default()
        }];

        assert!(matches!(
            evaluate_rewrites_with_host("/api/users", "", Some("example.com"), &[], &rules),
            RewriteResult::NoMatch
        ));
    }

    #[test]
    fn rewrite_to_different_host_same_path_stops_after_host_change() {
        let rules = vec![HTTPRewriteRule {
            id: Some(13),
            is_on: true,
            pattern: Some("^/api/(.*)$".to_string()),
            replace: Some("https://origin.example.com/api/${1}".to_string()),
            ..Default::default()
        }];

        match evaluate_rewrites_with_host("/api/users", "", Some("example.com"), &[], &rules) {
            RewriteResult::Proxy {
                new_uri,
                proxy_host,
                rewrite_id,
            } => {
                assert_eq!(new_uri, "/api/users");
                assert_eq!(proxy_host.as_deref(), Some("origin.example.com"));
                assert_eq!(rewrite_id, 13);
            }
            other => panic!("unexpected rewrite result: {:?}", other),
        }
    }

    #[test]
    fn rewrite_explicit_mode_redirects() {
        let rules = vec![HTTPRewriteRule {
            id: Some(10),
            is_on: true,
            pattern: Some("^/old$".to_string()),
            replace: Some("https://example.com/new".to_string()),
            mode: Some("redirect".to_string()),
            ..Default::default()
        }];

        match evaluate_rewrites("/old", "", &[], &rules) {
            RewriteResult::Redirect {
                location,
                status,
                rewrite_id,
            } => {
                assert_eq!(location, "https://example.com/new");
                assert_eq!(status, 307);
                assert_eq!(rewrite_id, 10);
            }
            other => panic!("unexpected rewrite result: {:?}", other),
        }
    }
}

static HOST_REDIRECT_RE_CACHE: Lazy<DashMap<String, Arc<Regex>>> = Lazy::new(DashMap::new);

fn request_uri(path: &str, query: &str) -> String {
    let mut uri = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(query);
    }
    uri
}

fn full_request_url(scheme: &str, host: &str, path: &str, query: &str) -> String {
    format!("{}://{}{}", scheme, host, request_uri(path, query))
}

fn host_redirect_status(redirect: &HTTPHostRedirectConfig, user_agent: &str) -> u16 {
    let configured = if redirect.status > 0 {
        redirect.status
    } else {
        redirect.status_code
    };
    if let Ok(status) = u16::try_from(configured)
        && (300..=399).contains(&status)
    {
        return status;
    }

    if is_search_engine_bot(user_agent) {
        301
    } else {
        307
    }
}

fn is_search_engine_bot(user_agent: &str) -> bool {
    crate::firewall::SEARCH_ENGINE_BOTS
        .iter()
        .any(|bot| crate::firewall::matcher::contains_ascii_case_insensitive(user_agent, bot))
}

fn domain_matches(patterns: &[String], domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    patterns
        .iter()
        .any(|pattern| domain_pattern_matches(pattern, &domain))
}

fn domain_pattern_matches(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if pattern.is_empty() {
        return false;
    }
    if pattern == domain || pattern == "*" {
        return true;
    }
    if let Some(regex_pattern) = pattern.strip_prefix('~') {
        return Regex::new(regex_pattern)
            .map(|re| re.is_match(domain))
            .unwrap_or(false);
    }
    if pattern.starts_with('.') {
        return domain.ends_with(&pattern);
    }

    let pattern_parts: Vec<&str> = pattern.split('.').collect();
    let domain_parts: Vec<&str> = domain.split('.').collect();
    if pattern_parts.len() != domain_parts.len() {
        return false;
    }
    pattern_parts.iter().zip(domain_parts.iter()).all(|(p, d)| {
        if p.is_empty() || *p == "*" || p == d {
            return true;
        }
        if let Some(prefix) = p.strip_suffix(":*") {
            return *d == prefix || d.starts_with(&format!("{}:", prefix));
        }
        false
    })
}

fn cached_host_redirect_regex(pattern: &str) -> Option<Arc<Regex>> {
    if let Some(cached) = HOST_REDIRECT_RE_CACHE.get(pattern) {
        return Some(cached.clone());
    }
    let compiled = Regex::new(pattern).ok()?;
    let regex = Arc::new(compiled);
    HOST_REDIRECT_RE_CACHE.insert(pattern.to_string(), Arc::clone(&regex));
    Some(regex)
}

fn expand_go_regex_replacement(
    regex: &Regex,
    captures: &regex::Captures<'_>,
    replacement: &str,
) -> String {
    let mut result = replacement.to_string();
    for index in 0..captures.len() {
        let value = captures.get(index).map(|m| m.as_str()).unwrap_or_default();
        result = result.replace(&format!("${{{}}}", index), value);
    }
    for name in regex.capture_names().flatten() {
        if let Some(value) = captures.name(name) {
            result = result.replace(&format!("${{{}}}", name), value.as_str());
        }
    }
    result
}

fn real_before_url(before_url: &str) -> String {
    if let Some((_, rest)) = before_url.split_once("://")
        && !rest.contains('/')
    {
        return format!("{}/", before_url);
    }
    before_url.to_string()
}

fn split_host_port(value: &str) -> (String, Option<u16>) {
    if let Some(rest) = value.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = rest[..end].to_string();
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok());
        return (host, port);
    }
    if value.matches(':').count() == 1
        && let Some((host, port)) = value.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_string(), Some(port));
    }
    (value.to_string(), None)
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

fn port_matches(patterns: &[String], request_port: u16) -> bool {
    patterns.iter().any(|pattern| {
        if let Ok(port) = pattern.parse::<u16>() {
            return port == request_port;
        }
        if let Some((from, to)) = pattern.split_once('-')
            && let (Ok(mut from), Ok(mut to)) = (from.parse::<u16>(), to.parse::<u16>())
        {
            if from > to {
                std::mem::swap(&mut from, &mut to);
            }
            return from <= request_port && request_port <= to;
        }
        false
    })
}

fn append_current_query(mut target: String, query: &str) -> String {
    if !query.is_empty() {
        target.push('?');
        target.push_str(query);
    }
    target
}

fn redirect_type(redirect: &HTTPHostRedirectConfig) -> &str {
    if !redirect.r#type.is_empty() {
        return redirect.r#type.as_str();
    }
    match redirect.mode.as_str() {
        "url" | "domain" | "port" => redirect.mode.as_str(),
        _ => "url",
    }
}

pub fn evaluate_host_redirects(
    host: &str,
    scheme: &str,
    path: &str,
    query: &str,
    user_agent: &str,
    redirects: &[HTTPHostRedirectConfig],
) -> Option<(String, u16)> {
    let current_request_uri = request_uri(path, query);
    let status_for = |redirect: &HTTPHostRedirectConfig| host_redirect_status(redirect, user_agent);

    for redirect in redirects {
        if !redirect.is_on {
            continue;
        }
        if !redirect.except_domains.is_empty() && domain_matches(&redirect.except_domains, host) {
            continue;
        }
        if !redirect.only_domains.is_empty() && !domain_matches(&redirect.only_domains, host) {
            continue;
        }

        if redirect.r#type.is_empty()
            && redirect.mode.is_empty()
            && let (Some(before), Some(after)) = (&redirect.before_host, &redirect.after_host)
        {
            if domain_matches(&[before.clone()], host) {
                let location = if redirect.keep_request_uri {
                    format!("https://{}{}", after, current_request_uri)
                } else {
                    format!("https://{}/", after)
                };
                return Some((location, status_for(redirect)));
            }
            continue;
        }

        match redirect_type(redirect) {
            "domain" => {
                if redirect.domain_after.is_empty() {
                    continue;
                }
                let match_host = if redirect.domain_before_ignore_ports {
                    crate::lb_factory::strip_addr_port(host)
                } else {
                    host.to_string()
                };
                let after_scheme = if redirect.domain_after_scheme.is_empty() {
                    scheme
                } else {
                    redirect.domain_after_scheme.as_str()
                };
                if redirect.domains_all || domain_matches(&redirect.domains_before, &match_host) {
                    let after_url = format!(
                        "{}://{}{}",
                        after_scheme,
                        redirect.domain_after,
                        request_uri(path, "")
                    );
                    if full_request_url(scheme, host, path, "") == after_url
                        || redirect.domain_after.eq_ignore_ascii_case(&match_host)
                    {
                        return None;
                    }
                    return Some((append_current_query(after_url, query), status_for(redirect)));
                }
            }
            "port" => {
                if redirect.port_after <= 0 {
                    continue;
                }
                let after_scheme = if redirect.port_after_scheme.is_empty() {
                    scheme
                } else {
                    redirect.port_after_scheme.as_str()
                };
                let (request_host, request_port) = split_host_port(host);
                let request_port = request_port.or_else(|| default_port(scheme));
                let Some(request_port) = request_port else {
                    continue;
                };
                if request_port == redirect.port_after as u16 {
                    return None;
                }
                if redirect.ports_all || port_matches(&redirect.ports_before, request_port) {
                    let mut new_host = request_host;
                    if default_port(after_scheme) != Some(redirect.port_after as u16) {
                        if new_host.contains(':') && !new_host.starts_with('[') {
                            new_host = format!("[{}]", new_host);
                        }
                        new_host.push(':');
                        new_host.push_str(&redirect.port_after.to_string());
                    }
                    let after_url =
                        format!("{}://{}{}", after_scheme, new_host, request_uri(path, ""));
                    if full_request_url(scheme, host, path, "") == after_url {
                        return None;
                    }
                    return Some((after_url, status_for(redirect)));
                }
            }
            _ => {
                let before_url = if redirect.before_url.is_empty() {
                    redirect.before.as_str()
                } else {
                    redirect.before_url.as_str()
                };
                let after_url = if redirect.after_url.is_empty() {
                    redirect.after.as_str()
                } else {
                    redirect.after_url.as_str()
                };
                if before_url.is_empty() || after_url.is_empty() {
                    continue;
                }

                let include_query_in_match = !redirect.match_regexp && before_url.contains('?');
                let full_url = full_request_url(
                    scheme,
                    host,
                    path,
                    if include_query_in_match { query } else { "" },
                );

                if redirect.match_prefix {
                    if full_url.starts_with(before_url) {
                        let mut location = after_url.to_string();
                        if redirect.keep_request_uri {
                            location.push_str(&current_request_uri);
                        }
                        if full_url == location {
                            return None;
                        }
                        return Some((location, status_for(redirect)));
                    }
                } else if redirect.match_regexp {
                    let Some(regex) = cached_host_redirect_regex(before_url) else {
                        continue;
                    };
                    let Some(captures) = regex.captures(&full_url) else {
                        continue;
                    };
                    let mut location = expand_go_regex_replacement(&regex, &captures, after_url);
                    if full_url == location {
                        return None;
                    }
                    if redirect.keep_args && !query.is_empty() {
                        location.push('?');
                        location.push_str(query);
                    }
                    return Some((location, status_for(redirect)));
                } else if full_url == real_before_url(before_url) {
                    let mut location = after_url.to_string();
                    if full_url == location {
                        return None;
                    }
                    if redirect.keep_args && !query.is_empty() {
                        if let Some(index) = location.find('?') {
                            location.truncate(index);
                        }
                        location.push('?');
                        location.push_str(query);
                    }
                    return Some((location, status_for(redirect)));
                }
            }
        }
    }
    None
}
