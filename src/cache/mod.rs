use crate::config_models::HTTPCacheRef;

pub mod matching;

pub fn cache_ref_allows_method_status(
    status: u16,
    cache_ref: &HTTPCacheRef,
    method: &str,
    force_partial_content: bool,
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

    if cache_ref.status.is_empty() {
        status == 200
            || (status == 206 && (cache_ref.allow_partial_content || force_partial_content))
    } else {
        cache_ref.status.contains(&(status as i32))
            || (status == 206 && cache_ref.allow_partial_content)
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
        let cc_lower = cc.to_lowercase();
        for skip in &cache_ref.skip_cache_control_values {
            if !skip.is_empty() && cc_lower.contains(&skip.to_lowercase()) {
                return false;
            }
        }
    }

    // 5. Check Set-Cookie
    if cache_ref.skip_set_cookie && headers.contains_key("set-cookie") {
        return false;
    }

    true
}

pub fn parse_life_to_seconds(v: &serde_json::Value) -> u64 {
    crate::config_models::parse_life_to_seconds(v)
}

#[cfg(test)]
mod tests {
    use super::cache_ref_allows_method_status;
    use crate::config_models::HTTPCacheRef;

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
            allow_partial_content: false,
            always_forward_range_request: false,
            enable_request_cache_pragma: false,
            enable_if_none_match: false,
            enable_if_modified_since: false,
            is_reverse: false,
            conds: None,
            simple_cond: None,
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
}
