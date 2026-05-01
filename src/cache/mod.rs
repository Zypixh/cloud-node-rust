use crate::config_models::HTTPCacheRef;

pub mod matching;

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
    if !cache_ref.is_on {
        return false;
    }

    // 1. Check Method
    let method_allowed = if cache_ref.methods.is_empty() {
        true
    } else {
        cache_ref
            .methods
            .iter()
            .any(|m| m.to_uppercase() == method.to_uppercase())
    };
    if !method_allowed {
        return false;
    }

    // 2. Check Status
    let status_allowed = if cache_ref.status.is_empty() {
        status == 200 || (status == 206 && (cache_ref.allow_partial_content || force_partial_content))
    } else {
        cache_ref.status.contains(&(status as i32))
            || (status == 206 && cache_ref.allow_partial_content)
    };
    if !status_allowed {
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
