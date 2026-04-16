use crate::config_models::HTTPHeaderPolicy;
use crate::utils::template::format_template;
use http::HeaderValue;
use http::header::HeaderName;
use pingora_proxy::Session;
use std::str::FromStr;

/// Applies request header policies to the upstream request headers.
/// Mirrors GoEdge's ProcessRequestHeaders logic.
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
    let remote_addr = match session.client_addr() {
        Some(addr) => addr.to_string(),
        None => "".to_string(),
    };

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

/// Applies response header policies to the response header, mirroring GoEdge's ProcessResponseHeaders
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
        headers.entry(h.name.to_lowercase()).or_insert_with(|| h.value.clone());
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
