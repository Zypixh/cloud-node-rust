use crate::config_models::{HTTPHostRedirectConfig, HTTPRewriteRef, HTTPRewriteRule};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;
use tracing::debug;

pub enum RewriteResult {
    /// Continue to proxy with possibly modified URI
    Proxy {
        new_uri: String,
        proxy_host: Option<String>,
    },
    /// Redirect to another URL
    Redirect { location: String, status: u16 },
    /// No rewrite matched, continue with original
    NoMatch,
}

/// Match and evaluate rewrite rules using the legacy configureWeb/doRewrite behavior.
static REWRITE_RE_CACHE: Lazy<DashMap<String, std::sync::Arc<Regex>>> = Lazy::new(DashMap::new);

pub fn evaluate_rewrites(
    original_uri: &str,
    raw_query: &str,
    rewrite_refs: &[HTTPRewriteRef],
    rewrite_rules: &[HTTPRewriteRule],
) -> RewriteResult {
    let mut uri = original_uri.to_string();

    // Support recursive rewrites up to 8 levels (Go parity)
    for _iteration in 0..8 {
        let mut matched_this_pass = false;

        for (i, rule_ref) in rewrite_refs.iter().enumerate() {
            if !rule_ref.is_on {
                continue;
            }
            let Some(rule) = rewrite_rules.get(i) else {
                continue;
            };
            if !rule.is_on {
                continue;
            }
            let Some(pattern) = &rule.pattern else {
                continue;
            };
            let Some(replace) = &rule.replace else {
                continue;
            };

            let re = if let Some(cached) = REWRITE_RE_CACHE.get(pattern) {
                cached.clone()
            } else {
                let Ok(compiled) = Regex::new(pattern) else {
                    debug!("Invalid rewrite pattern: {}", pattern);
                    continue;
                };
                let re = Arc::new(compiled);
                REWRITE_RE_CACHE.insert(pattern.clone(), Arc::clone(&re));
                re
            };

            let path = uri.split('?').next().unwrap_or(&uri);

            if re.captures(path).is_some() {
                let replaced = re.replace(path, replace.as_str()).to_string();

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
                        };
                    }
                    _ => {
                        matched_this_pass = true;
                        uri = final_url;

                        if rule.is_break {
                            return RewriteResult::Proxy {
                                new_uri: uri,
                                proxy_host: rule.proxy_host.clone(),
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
            proxy_host: None,
        };
    }

    RewriteResult::NoMatch
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
    let ua = user_agent.to_ascii_lowercase();
    ua.contains("googlebot")
        || ua.contains("bingbot")
        || ua.contains("baiduspider")
        || ua.contains("yandexbot")
        || ua.contains("sogou")
        || ua.contains("360spider")
        || ua.contains("duckduckbot")
        || ua.contains("facebookexternalhit")
        || ua.contains("twitterbot")
        || ua.contains("slurp")
        || ua.contains("msnbot")
        || ua.contains("yisouspider")
        || ua.contains("bytespider")
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
