use crate::config_models::{HTTPHostRedirectConfig, HTTPRewriteRef, HTTPRewriteRule};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;
use tracing::debug;

pub enum RewriteResult {
    /// Continue to proxy with possibly modified URI
    Proxy { new_uri: String },
    /// Redirect to another URL
    Redirect { location: String, status: u16 },
    /// No rewrite matched, continue with original
    NoMatch,
}

/// Match and evaluate rewrite rules, mirroring GoEdge's configureWeb/doRewrite logic
static REWRITE_RE_CACHE: Lazy<DashMap<String, std::sync::Arc<Regex>>> = Lazy::new(DashMap::new);

pub fn evaluate_rewrites(
    original_uri: &str,
    raw_query: &str,
    rewrite_refs: &[HTTPRewriteRef],
    rewrite_rules: &[HTTPRewriteRule],
) -> RewriteResult {
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

        // Use cached compiled regex — avoid per-request compilation
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

        // Extract path portion for matching
        let path = original_uri.split('?').next().unwrap_or(original_uri);

        if re.captures(path).is_some() {
            // Perform replacement with capture groups ($1, $2, etc.)
            let replaced = re.replace(path, replace.as_str()).to_string();

            // Append query string if withQuery is enabled
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
                    return RewriteResult::Redirect {
                        location: final_url,
                        status: 302,
                    };
                }
                _ => {
                    return RewriteResult::Proxy { new_uri: final_url };
                }
            }
        }
    }

    RewriteResult::NoMatch
}

/// Evaluate host redirect rules, mirroring GoEdge's doHostRedirect logic
pub fn evaluate_host_redirects(
    host: &str,
    uri: &str,
    redirects: &[HTTPHostRedirectConfig],
) -> Option<(String, u16)> {
    for redirect in redirects {
        if !redirect.is_on {
            continue;
        }
        let Some(before) = &redirect.before_host else {
            continue;
        };
        let Some(after) = &redirect.after_host else {
            continue;
        };

        // Simple host matching (could be extended with wildcard/regex)
        if host == before.as_str() {
            let status: u16 = if redirect.status_code > 0 {
                redirect.status_code as u16
            } else {
                301
            };
            let location = if redirect.keep_request_uri {
                format!("https://{}{}", after, uri)
            } else {
                format!("https://{}/", after)
            };
            return Some((location, status));
        }
    }
    None
}
