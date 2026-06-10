use crate::config_models::HTTPCacheRef;

pub mod compiled;
pub mod matching;
pub mod partial;

pub(crate) fn should_store_response_header(name: &str) -> bool {
    const SKIP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "content-range",
        "set-cookie",
    ];

    !SKIP.iter().any(|skip| name.eq_ignore_ascii_case(skip))
}

pub(crate) fn cache_control_has_skipped_value(cache_control: &str, skipped: &[String]) -> bool {
    cache_control
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .any(|value| {
            skipped
                .iter()
                .map(|skip| skip.trim())
                .filter(|skip| !skip.is_empty())
                .any(|skip| value.eq_ignore_ascii_case(skip))
        })
}

pub fn cache_ref_allows_method_status(
    status: u16,
    cache_ref: &HTTPCacheRef,
    method: &str,
    _force_partial_content: bool,
) -> bool {
    if !cache_ref.is_on {
        return false;
    }

    let method_allowed = if cache_ref.methods.is_empty() {
        method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
    } else {
        cache_ref
            .methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
    };
    if !method_allowed {
        return false;
    }

    let partial_content_allowed =
        cache_ref.allow_partial_content || cache_ref.status.contains(&(206_i32));
    if status == 206 && !partial_content_allowed {
        return false;
    }

    if cache_ref.status.is_empty() {
        true
    } else {
        cache_ref.status.contains(&(status as i32)) || (status == 206 && partial_content_allowed)
    }
}

pub fn should_cache_response(
    status: u16,
    cache_ref: &HTTPCacheRef,
    method: &str,
    headers: &http::HeaderMap,
    _host: &str,
    body_size: usize,
    force_partial_content: bool,
    skip_size_checks: bool,
    req_headers: &http::HeaderMap,
) -> bool {
    if !cache_ref_allows_method_status(status, cache_ref, method, force_partial_content) {
        return false;
    }

    // 3. Check Size (skip for chunked encoding when policy allows)
    if !skip_size_checks {
        if let Some(min_size_val) = &cache_ref.min_size {
            let min_bytes = crate::config_models::SizeCapacity::from_json(min_size_val).to_bytes();
            if min_bytes > 0 && (body_size as i64) < min_bytes {
                return false;
            }
        }
        if let Some(max_size_val) = &cache_ref.max_size {
            let max_bytes = crate::config_models::SizeCapacity::from_json(max_size_val).to_bytes();
            if max_bytes > 0 && (body_size as i64) > max_bytes {
                return false;
            }
        }
    }

    // 4. Check Cache-Control
    if let Some(cc) = headers.get("cache-control").and_then(|v| v.to_str().ok()) {
        if cache_control_has_skipped_value(cc, &cache_ref.skip_cache_control_values) {
            return false;
        }
    }

    // 5. Check Set-Cookie
    if cache_ref.skip_set_cookie && headers.contains_key("set-cookie") {
        return false;
    }

    // 6. Check Authorization: RFC 7234 §3.2 — responses with credentials must
    //    not be cached unless the response explicitly authorizes it.
    if req_headers.contains_key("authorization") {
        let cc_allows = headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|cc| {
                let lower = cc.to_ascii_lowercase();
                lower.contains("public")
                    || lower.contains("must-revalidate")
                    || lower.contains("s-maxage")
            })
            .unwrap_or(false);
        if !cc_allows {
            return false;
        }
    }

    true
}

pub fn parse_life_to_seconds(v: &serde_json::Value) -> u64 {
    crate::config_models::parse_life_to_seconds(v)
}

#[cfg(test)]
mod tests {
    use super::{
        cache_ref_allows_method_status, should_cache_response, should_store_response_header,
    };
    use crate::cache::compiled::{
        CompiledCacheRef, cache_ref_allows_method_status_compiled, should_cache_response_compiled,
    };
    use crate::config_models::{HTTPCacheRef, HTTPExpiresTimeConfig};
    use http::{HeaderMap, HeaderValue};
    use serde_json::json;
    use std::sync::Arc;

    fn cache_ref(methods: Vec<String>) -> HTTPCacheRef {
        HTTPCacheRef {
            is_on: true,
            key: None,
            life: None,
            methods,
            status: vec![200],
            min_size: None,
            max_size: None,
            skip_cache_control_values: vec![],
            skip_set_cookie: false,
            allow_chunked_encoding: false,
            allow_partial_content: false,
            force_partial_content: false,
            always_forward_range_request: false,
            enable_request_cache_pragma: false,
            enable_if_none_match: false,
            enable_if_modified_since: false,
            enable_reading_origin_async: false,
            is_reverse: false,
            conds: None,
            simple_cond: None,
            only_url_patterns: vec![],
            except_url_patterns: vec![],
            expires_time: None,
            cache_policy: None,
        }
    }

    #[test]
    fn empty_methods_default_to_safe_cache_methods() {
        let cache_ref = cache_ref(vec![]);

        assert!(cache_ref_allows_method_status(
            200, &cache_ref, "GET", false
        ));
        assert!(cache_ref_allows_method_status(
            200, &cache_ref, "HEAD", false
        ));
        assert!(!cache_ref_allows_method_status(
            200, &cache_ref, "PUT", false
        ));
        assert!(!cache_ref_allows_method_status(
            200, &cache_ref, "POST", false
        ));
    }

    #[test]
    fn explicit_methods_allow_non_get_cache_methods() {
        let cache_ref = cache_ref(vec!["PUT".to_string()]);

        assert!(cache_ref_allows_method_status(
            200, &cache_ref, "PUT", false
        ));
        assert!(!cache_ref_allows_method_status(
            200, &cache_ref, "GET", false
        ));
    }

    #[test]
    fn stored_cache_headers_exclude_set_cookie() {
        assert!(should_store_response_header("cache-control"));
        assert!(should_store_response_header("content-type"));
        assert!(!should_store_response_header("set-cookie"));
        assert!(!should_store_response_header("Set-Cookie"));
        assert!(!should_store_response_header("content-length"));
    }

    #[test]
    fn compiled_response_policy_matches_legacy_method_status_and_filters() {
        let mut cache_ref = cache_ref(vec![]);
        cache_ref.status = vec![];
        cache_ref.min_size = Some(json!({"count": 10, "unit": "b"}));
        cache_ref.max_size = Some(json!({"count": 20, "unit": "b"}));
        cache_ref.skip_cache_control_values = vec!["private".to_string()];
        cache_ref.skip_set_cookie = true;
        cache_ref.expires_time = Some(HTTPExpiresTimeConfig {
            is_on: true,
            overwrite: true,
            auto_calculate: false,
            duration: Some(json!({"count": 5, "unit": "m"})),
        });

        let compiled = CompiledCacheRef::compile_arc(&Arc::new(cache_ref.clone()));
        for (status, method, size, force_partial, expected) in [
            (200, "GET", 10, false, true),
            (200, "HEAD", 20, false, true),
            (200, "POST", 10, false, false),
            (206, "GET", 10, true, false),
            (302, "GET", 10, false, true),
            (200, "GET", 9, false, false),
            (200, "GET", 21, false, false),
        ] {
            let headers = HeaderMap::new();
            let req_headers = HeaderMap::new();
            assert_eq!(
                should_cache_response(
                    status,
                    &cache_ref,
                    method,
                    &headers,
                    "example.com",
                    size,
                    force_partial,
                    false,
                    &req_headers
                ),
                expected
            );
            assert_eq!(
                should_cache_response_compiled(
                    &compiled,
                    None,
                    status,
                    method,
                    &headers,
                    size,
                    force_partial,
                    false,
                    &req_headers
                ),
                expected
            );
            assert_eq!(
                cache_ref_allows_method_status(status, &cache_ref, method, force_partial),
                cache_ref_allows_method_status_compiled(&compiled, status, method, force_partial)
            );
        }

        cache_ref.status = vec![200];
        cache_ref.allow_partial_content = true;
        let compiled = CompiledCacheRef::compile_arc(&Arc::new(cache_ref.clone()));
        let headers = HeaderMap::new();
        assert!(cache_ref_allows_method_status(
            206, &cache_ref, "GET", false
        ));
        assert!(cache_ref_allows_method_status_compiled(
            &compiled, 206, "GET", false
        ));
        assert!(should_cache_response(
            206,
            &cache_ref,
            "GET",
            &headers,
            "example.com",
            10,
            false,
            false,
            &headers
        ));
        assert!(should_cache_response_compiled(
            &compiled, None, 206, "GET", &headers, 10, false, false, &headers
        ));

        let mut private_headers = HeaderMap::new();
        private_headers.insert(
            "cache-control",
            HeaderValue::from_static("max-age=60, private"),
        );
        assert!(!should_cache_response(
            200,
            &cache_ref,
            "GET",
            &private_headers,
            "example.com",
            10,
            false,
            false,
            &headers
        ));
        assert!(!should_cache_response_compiled(
            &compiled,
            None,
            200,
            "GET",
            &private_headers,
            10,
            false,
            false,
            &headers
        ));

        let mut cookie_headers = HeaderMap::new();
        cookie_headers.insert("set-cookie", HeaderValue::from_static("sid=1"));
        assert!(!should_cache_response(
            200,
            &cache_ref,
            "GET",
            &cookie_headers,
            "example.com",
            10,
            false,
            false,
            &headers
        ));
        assert!(!should_cache_response_compiled(
            &compiled,
            None,
            200,
            "GET",
            &cookie_headers,
            10,
            false,
            false,
            &headers
        ));

        cache_ref.skip_set_cookie = false;
        let compiled = CompiledCacheRef::compile_arc(&Arc::new(cache_ref.clone()));
        assert!(should_cache_response(
            200,
            &cache_ref,
            "GET",
            &cookie_headers,
            "example.com",
            10,
            false,
            false,
            &headers
        ));
        assert!(should_cache_response_compiled(
            &compiled,
            None,
            200,
            "GET",
            &cookie_headers,
            10,
            false,
            false,
            &headers
        ));

        assert_eq!(compiled.response_policy.ttl_seconds(), 3600);
        assert_eq!(compiled.response_policy.force_ttl_seconds(), Some(300));
        assert!(compiled.response_policy.overwrite_expires());
    }
}
