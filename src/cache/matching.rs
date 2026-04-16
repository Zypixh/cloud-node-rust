use crate::config_models::{HTTPRequestCond, HTTPRequestCondGroup, HTTPRequestCondsConfig};
use regex::Regex;
use pingora_proxy::Session;

pub trait Matcher {
    fn match_request(&self, session: &Session) -> bool;
}

impl HTTPRequestCondsConfig {
    pub fn match_request(&self, session: &Session) -> bool {
        if !self.is_on || self.groups.is_empty() {
            return true;
        }

        if self.connector == "and" {
            self.groups.iter().all(|group| group.match_request(session))
        } else {
            self.groups.iter().any(|group| group.match_request(session))
        }
    }
}

impl HTTPRequestCondGroup {
    pub fn match_request(&self, session: &Session) -> bool {
        if !self.is_on || self.conds.is_empty() {
            return true;
        }

        if self.connector == "and" {
            self.conds.iter().all(|cond| cond.match_request(session))
        } else {
            self.conds.iter().any(|cond| cond.match_request(session))
        }
    }
}

impl HTTPRequestCond {
    pub fn match_request(&self, session: &Session) -> bool {
        let param_value = get_variable_value(session, &self.param);
        let matched = match self.operator.as_str() {
            "matches" | "regexp" => {
                let pattern = if self.is_case_insensitive && !self.value.starts_with("(?i)") {
                    format!("(?i){}", self.value)
                } else {
                    self.value.clone()
                };
                Regex::new(&pattern).map(|re| re.is_match(&param_value)).unwrap_or(false)
            }
            "notMatches" | "notRegexp" => {
                let pattern = if self.is_case_insensitive && !self.value.starts_with("(?i)") {
                    format!("(?i){}", self.value)
                } else {
                    self.value.clone()
                };
                Regex::new(&pattern).map(|re| !re.is_match(&param_value)).unwrap_or(false)
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
                    param_value.to_lowercase().starts_with(&self.value.to_lowercase())
                } else {
                    param_value.starts_with(&self.value)
                }
            }
            "suffix" | "hasSuffix" => {
                if self.is_case_insensitive {
                    param_value.to_lowercase().ends_with(&self.value.to_lowercase())
                } else {
                    param_value.ends_with(&self.value)
                }
            }
            "contains" | "containsString" => {
                if self.is_case_insensitive {
                    param_value.to_lowercase().contains(&self.value.to_lowercase())
                } else {
                    param_value.contains(&self.value)
                }
            }
            "in" => {
                if let Ok(values) = serde_json::from_str::<Vec<String>>(&self.value) {
                    if self.is_case_insensitive {
                        let lower_param = param_value.to_lowercase();
                        values.iter().any(|v| v.to_lowercase() == lower_param)
                    } else {
                        values.contains(&param_value)
                    }
                } else {
                    // Fallback for non-json values
                    self.value.split(',').any(|v| v.trim() == param_value)
                }
            }
            _ => false,
        };

        if self.is_reverse { !matched } else { matched }
    }
}

pub fn get_variable_value(session: &Session, param: &str) -> String {
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
        "${host}" | "${requestHost}" => session.req_header().uri.host().unwrap_or("").to_string(),
        "${scheme}" => "http".to_string(),
        "${requestURI}" => {
            let path = session.req_header().uri.path();
            let query = session.req_header().uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
            format!("{}{}", path, query)
        }
        "${remoteAddr}" => {
            match session.client_addr() {
                Some(pingora_core::protocols::l4::socket::SocketAddr::Inet(addr)) => addr.ip().to_string(),
                _ => "127.0.0.1".to_string(),
            }
        }
        _ if param.starts_with("${arg:") => {
            let key = &param[6..param.len() - 1];
            session.req_header().uri.query()
                .and_then(|q| {
                    q.split('&')
                        .find(|p| p.starts_with(key) && p.contains('='))
                        .map(|p| p.split('=').nth(1).unwrap_or("").to_string())
                })
                .unwrap_or_default()
        }
        _ if param.starts_with("${header:") => {
            let key = &param[9..param.len() - 1];
            session.get_header(key).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
        }
        _ if param.starts_with("${cookie:") => {
            let key = &param[9..param.len() - 1];
            session.get_header("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';')
                        .map(|c| c.trim())
                        .find(|c| c.starts_with(key) && c.contains('='))
                        .map(|c| c.split('=').nth(1).unwrap_or("").to_string())
                })
                .unwrap_or_default()
        }
        _ => param.to_string(),
    }
}

pub fn format_variables(session: &Session, template: &str) -> String {
    let re = Regex::new(r"\$\{[^}]+\}").unwrap();
    let result = re.replace_all(template, |caps: &regex::Captures| {
        get_variable_value(session, &caps[0])
    });
    result.to_string()
}
