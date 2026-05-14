use crate::config_models::{HTTPRequestCond, HTTPRequestCondGroup, HTTPRequestCondsConfig};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pingora_proxy::Session;
use regex::Regex;
use std::sync::Arc;

static CACHE_RE_CACHE: Lazy<DashMap<String, std::sync::Arc<Regex>>> = Lazy::new(DashMap::new);
static CACHE_IN_VALUES: Lazy<DashMap<String, Arc<Vec<String>>>> = Lazy::new(DashMap::new);

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
        let matched = match self.operator.as_str() {
            "matches" | "regexp" => {
                let pattern = if self.is_case_insensitive && !self.value.starts_with("(?i)") {
                    format!("(?i){}", self.value)
                } else {
                    self.value.clone()
                };
                get_cached_regex(&pattern).map_or(false, |re| re.is_match(&param_value))
            }
            "notMatches" | "notRegexp" => {
                let pattern = if self.is_case_insensitive && !self.value.starts_with("(?i)") {
                    format!("(?i){}", self.value)
                } else {
                    self.value.clone()
                };
                get_cached_regex(&pattern).map_or(false, |re| !re.is_match(&param_value))
            }
            "eq" | "equals" => {
                if self.is_case_insensitive {
                    param_value.to_lowercase() == self.value.to_lowercase()
                } else {
                    param_value == self.value
                }
            }
            "neq" | "notEquals" => {
                if self.is_case_insensitive {
                    param_value.to_lowercase() != self.value.to_lowercase()
                } else {
                    param_value != self.value
                }
            }
            "prefix" | "hasPrefix" => {
                if self.is_case_insensitive {
                    param_value
                        .to_lowercase()
                        .starts_with(&self.value.to_lowercase())
                } else {
                    param_value.starts_with(&self.value)
                }
            }
            "suffix" | "hasSuffix" => {
                if self.is_case_insensitive {
                    param_value
                        .to_lowercase()
                        .ends_with(&self.value.to_lowercase())
                } else {
                    param_value.ends_with(&self.value)
                }
            }
            "contains" | "containsString" => {
                if self.is_case_insensitive {
                    param_value
                        .to_lowercase()
                        .contains(&self.value.to_lowercase())
                } else {
                    param_value.contains(&self.value)
                }
            }
            "in" => {
                let values = cached_list_values(&self.value);
                if !values.is_empty() {
                    if self.is_case_insensitive {
                        let lower_param = param_value.to_lowercase();
                        values.iter().any(|v| v.to_lowercase() == lower_param)
                    } else {
                        values.contains(&param_value)
                    }
                } else {
                    false
                }
            }
            "fileExt" | "fileExtension" | "fileExtensions" => {
                let extension =
                    get_variable_value_with_scheme(session, "${requestPathLowerExtension}", scheme);
                extension_in_configured_values(&extension, &self.value)
            }
            _ => false,
        };

        if self.is_reverse { !matched } else { matched }
    }
}

pub fn get_variable_value_with_scheme(session: &Session, param: &str, scheme: &str) -> String {
    match param {
        "${requestPath}" => session.req_header().uri.path().to_string(),
        "${requestPathLowerExtension}" => {
            let path = session.req_header().uri.path();
            std::path::Path::new(path)
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| format!(".{}", ext.to_lowercase()))
                .unwrap_or_default()
        }
        "${host}" | "${requestHost}" => {
            session
                .req_header()
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(':').next().unwrap_or(v)) // Remove port if present
                .or_else(|| session.req_header().uri.host())
                .unwrap_or("")
                .to_string()
        }
        "${scheme}" => scheme.to_string(),
        "${isArgs}" => {
            if session.req_header().uri.query().is_some() {
                "?".to_string()
            } else {
                "".to_string()
            }
        }
        "${args}" => session.req_header().uri.query().unwrap_or("").to_string(),
        "${requestURI}" => {
            let path = session.req_header().uri.path();
            let query = session
                .req_header()
                .uri
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default();
            format!("{}{}", path, query)
        }
        "${remoteAddr}" => session
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
        _ if param.starts_with("${arg:") => {
            let key = &param[6..param.len() - 1];
            session
                .req_header()
                .uri
                .query()
                .and_then(|q| {
                    q.split('&')
                        .find(|p| p.starts_with(key) && p.contains('='))
                        .map(|p| p.split('=').nth(1).unwrap_or("").to_string())
                })
                .unwrap_or_default()
        }
        _ if param.starts_with("${header:") => {
            let key = &param[9..param.len() - 1];
            session
                .get_header(key)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        }
        _ if param.starts_with("${cookie:") => {
            let key = &param[9..param.len() - 1];
            session
                .get_header("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies
                        .split(';')
                        .map(|c| c.trim())
                        .find(|c| c.starts_with(key) && c.contains('='))
                        .map(|c| c.split('=').nth(1).unwrap_or("").to_string())
                })
                .unwrap_or_default()
        }
        _ => param.to_string(),
    }
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
    cached_list_values(value).iter().any(|item| {
        let item = item.trim().trim_matches('"').to_ascii_lowercase();
        if item.is_empty() {
            return false;
        }
        let item = if item.starts_with('.') {
            item
        } else {
            format!(".{item}")
        };
        item == extension
    })
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
