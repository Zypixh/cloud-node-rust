use crate::config_models::{HTTPRequestCond, HTTPRequestCondGroup, HTTPRequestCondsConfig};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_proxy::Session;
use regex::Regex;
use std::sync::Arc;

static CACHE_RE_CACHE: Lazy<DashMap<String, std::sync::Arc<Regex>>> = Lazy::new(DashMap::new);
static CACHE_IN_VALUES: Lazy<DashMap<String, Arc<Vec<String>>>> = Lazy::new(DashMap::new);
static CACHE_EXTENSION_VALUES: Lazy<DashMap<String, Arc<Vec<String>>>> = Lazy::new(DashMap::new);
static CACHE_OPERATOR_VALUES: Lazy<DashMap<String, Arc<str>>> = Lazy::new(DashMap::new);

impl HTTPRequestCondsConfig {
    pub fn match_request_with_scheme(&self, session: &Session, scheme: &str) -> bool {
        if !self.is_on || self.groups.is_empty() {
            return true;
        }

        if self.connector == "and" {
            self.groups
                .iter()
                .all(|group| group.match_request_with_scheme(session, scheme))
        } else {
            self.groups
                .iter()
                .any(|group| group.match_request_with_scheme(session, scheme))
        }
    }
}

impl HTTPRequestCondGroup {
    pub fn match_request_with_scheme(&self, session: &Session, scheme: &str) -> bool {
        if !self.is_on || self.conds.is_empty() {
            return true;
        }

        if self.connector == "and" {
            self.conds
                .iter()
                .all(|cond| cond.match_request_with_scheme(session, scheme))
        } else {
            self.conds
                .iter()
                .any(|cond| cond.match_request_with_scheme(session, scheme))
        }
    }
}

impl HTTPRequestCond {
    pub fn match_request_with_scheme(&self, session: &Session, scheme: &str) -> bool {
        let param_value = get_variable_value_with_scheme(session, &self.param, scheme);
        let expected = self.value.as_str();
        let operator = normalized_operator(&self.operator);
        let matched = match operator.as_ref() {
            "matches" | "regexp" => regex_matches(&param_value, expected, self.is_case_insensitive),
            "notmatches" | "notregexp" => {
                !regex_matches(&param_value, expected, self.is_case_insensitive)
            }
            "wildcardmatch" => wildcard_matches(&param_value, expected, self.is_case_insensitive),
            "wildcardnotmatch" | "notwildcardmatch" => {
                !wildcard_matches(&param_value, expected, self.is_case_insensitive)
            }
            "eq" | "equals" => {
                if self.is_case_insensitive {
                    eq_case_insensitive(&param_value, expected)
                } else {
                    param_value == expected
                }
            }
            "neq" | "notequals" => {
                if self.is_case_insensitive {
                    !eq_case_insensitive(&param_value, expected)
                } else {
                    param_value != expected
                }
            }
            "prefix" | "hasprefix" => {
                if self.is_case_insensitive {
                    starts_with_ascii_case_insensitive(&param_value, expected)
                } else {
                    param_value.starts_with(expected)
                }
            }
            "suffix" | "hassuffix" => {
                if self.is_case_insensitive {
                    ends_with_ascii_case_insensitive(&param_value, expected)
                } else {
                    param_value.ends_with(expected)
                }
            }
            "contains" | "containsstring" => {
                if self.is_case_insensitive {
                    contains_ascii_case_insensitive(&param_value, expected)
                } else {
                    param_value.contains(expected)
                }
            }
            "in" => {
                let values = cached_list_values(expected);
                if !values.is_empty() {
                    if self.is_case_insensitive {
                        values.iter().any(|v| eq_case_insensitive(&param_value, v))
                    } else {
                        values.contains(&param_value)
                    }
                } else {
                    false
                }
            }
            "fileext" | "fileextension" | "fileextensions" => {
                let extension =
                    get_variable_value_with_scheme(session, "${requestPathLowerExtension}", scheme);
                extension_in_configured_values(&extension, expected)
            }
            _ => false,
        };

        if self.is_reverse { !matched } else { matched }
    }
}

pub fn get_variable_value_with_scheme(session: &Session, param: &str, scheme: &str) -> String {
    if let Some(inner) = param
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
    {
        return get_variable_inner_value_with_scheme(session, inner, scheme);
    }

    param.to_string()
}

fn get_variable_inner_value_with_scheme(session: &Session, inner: &str, scheme: &str) -> String {
    match inner {
        "requestPath" => session.req_header().uri.path().to_string(),
        "requestPathLowerExtension" => {
            let path = session.req_header().uri.path();
            std::path::Path::new(path)
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| format!(".{}", ext.to_lowercase()))
                .unwrap_or_default()
        }
        "host" | "requestHost" => session
            .req_header()
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v))
            .or_else(|| session.req_header().uri.host())
            .unwrap_or("")
            .to_string(),
        "scheme" => scheme.to_string(),
        "isArgs" => {
            if session.req_header().uri.query().is_some() {
                "?".to_string()
            } else {
                "".to_string()
            }
        }
        "args" => session.req_header().uri.query().unwrap_or("").to_string(),
        "requestURI" => {
            let path = session.req_header().uri.path();
            let query = session
                .req_header()
                .uri
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default();
            format!("{}{}", path, query)
        }
        "remoteAddr" => session
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
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        "referer" => header_value(session, "referer"),
        "userAgent" | "httpUserAgent" => header_value(session, "user-agent"),
        "contentType" => header_value(session, "content-type"),
        "cookies" => header_value(session, "cookie"),
        _ => {
            if let Some(key) = prefixed_variable_arg(inner, &["arg", "requestArg"]) {
                return query_param(session, key);
            }
            if let Some(key) = prefixed_variable_arg(inner, &["header", "requestHeader"]) {
                return header_value(session, key);
            }
            if let Some(key) = prefixed_variable_arg(inner, &["cookie", "requestCookie"]) {
                return cookie_value(session, key);
            }
            String::new()
        }
    }
}

fn prefixed_variable_arg<'a>(inner: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    for prefix in prefixes {
        let Some(rest) = inner.strip_prefix(prefix) else {
            continue;
        };
        if let Some(value) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('.')) {
            return Some(value);
        }
    }
    None
}

fn header_value(session: &Session, name: &str) -> String {
    session
        .get_header(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn query_param(session: &Session, name: &str) -> String {
    session
        .req_header()
        .uri
        .query()
        .and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                if key == name {
                    Some(value.to_string())
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
            cookies.split(';').map(str::trim).find_map(|cookie| {
                let (key, value) = cookie.split_once('=')?;
                if key == name {
                    Some(value.to_string())
                } else {
                    None
                }
            })
        })
        .unwrap_or_default()
}

pub fn format_variables_with_scheme(session: &Session, template: &str, scheme: &str) -> String {
    static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").unwrap());
    if !template.contains("${") {
        return template.to_string();
    }
    let re = &*RE_VAR;
    let result = re.replace_all(template, |caps: &regex::Captures| {
        get_variable_value_with_scheme(session, &caps[0], scheme)
    });
    result.to_string()
}

fn cached_list_values(value: &str) -> Arc<Vec<String>> {
    CACHE_IN_VALUES
        .entry(value.to_string())
        .or_insert_with(|| {
            let parsed = serde_json::from_str::<Vec<String>>(value).unwrap_or_else(|_| {
                value
                    .split(',')
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
                    .collect()
            });
            Arc::new(parsed)
        })
        .clone()
}

fn extension_in_configured_values(extension: &str, value: &str) -> bool {
    if extension.is_empty() {
        return false;
    }

    let extension = extension.to_ascii_lowercase();
    cached_extension_values(value)
        .iter()
        .any(|item| item.as_str() == extension)
}

fn cached_extension_values(value: &str) -> Arc<Vec<String>> {
    CACHE_EXTENSION_VALUES
        .entry(value.to_string())
        .or_insert_with(|| {
            let parsed = cached_list_values(value)
                .iter()
                .filter_map(|item| {
                    let item = item.trim().trim_matches('"').to_ascii_lowercase();
                    if item.is_empty() {
                        None
                    } else if item.starts_with('.') {
                        Some(item)
                    } else {
                        Some(format!(".{item}"))
                    }
                })
                .collect();
            Arc::new(parsed)
        })
        .clone()
}

fn eq_case_insensitive(value: &str, expected: &str) -> bool {
    if value.is_ascii() && expected.is_ascii() {
        value.eq_ignore_ascii_case(expected)
    } else {
        value.to_lowercase() == expected.to_lowercase()
    }
}

fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    if value.is_ascii() && prefix.is_ascii() {
        return value.len() >= prefix.len()
            && value.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes());
    }
    value.to_lowercase().starts_with(&prefix.to_lowercase())
}

fn ends_with_ascii_case_insensitive(value: &str, suffix: &str) -> bool {
    if value.is_ascii() && suffix.is_ascii() {
        return value.len() >= suffix.len()
            && value.as_bytes()[value.len() - suffix.len()..]
                .eq_ignore_ascii_case(suffix.as_bytes());
    }
    value.to_lowercase().ends_with(&suffix.to_lowercase())
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    if value.is_ascii() && needle.is_ascii() {
        return !needle.is_empty()
            && value.len() >= needle.len()
            && value
                .as_bytes()
                .windows(needle.len())
                .any(|part| part.eq_ignore_ascii_case(needle.as_bytes()));
    }
    value.to_lowercase().contains(&needle.to_lowercase())
}

fn normalized_operator(operator: &str) -> Arc<str> {
    if let Some(cached) = CACHE_OPERATOR_VALUES.get(operator) {
        return Arc::clone(&*cached);
    }
    let normalized: Arc<str> = operator
        .trim()
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != '_' && *ch != '-')
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .into();
    CACHE_OPERATOR_VALUES
        .entry(operator.to_string())
        .or_insert_with(|| Arc::clone(&normalized))
        .clone()
}

fn regex_matches(value: &str, pattern: &str, case_insensitive: bool) -> bool {
    let pattern = if case_insensitive && !pattern.starts_with("(?i)") {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };
    get_cached_regex(&pattern).is_some_and(|re| re.is_match(value))
}

fn wildcard_matches(value: &str, pattern: &str, case_insensitive: bool) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }
    let pattern = regex::escape(pattern).replace("\\*", ".*");
    let pattern = if case_insensitive {
        format!("(?i)^{pattern}$")
    } else {
        format!("^{pattern}$")
    };
    get_cached_regex(&pattern).is_some_and(|re| re.is_match(value))
}

fn get_cached_regex(pattern: &str) -> Option<Arc<Regex>> {
    if let Some(cached) = CACHE_RE_CACHE.get(pattern) {
        return Some(Arc::clone(&*cached));
    }
    Regex::new(pattern).ok().map(|re| {
        let re = Arc::new(re);
        CACHE_RE_CACHE.insert(pattern.to_string(), Arc::clone(&re));
        re
    })
}
