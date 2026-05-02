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
    let remote_addr = session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.peer_addr())
        .map(|addr| addr.to_string())
        .or_else(|| session.client_addr().map(|addr| addr.to_string()))
        .unwrap_or_default();

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

/// Applies request header policies to upstream request headers.
/// Unlike `apply_request_header_policy`, this operates on the outgoing upstream request
/// rather than the downstream session, and receives template variables directly.
pub fn apply_request_header_policy_to_upstream(
    upstream_request: &mut pingora_http::RequestHeader,
    policy: &HTTPHeaderPolicy,
    host: &str,
    request_uri: &str,
    remote_addr: &str,
) {
    let resolve = |value: &str| -> String {
        format_template(value, |var_name| match var_name {
            "host" => host.to_string(),
            "requestURI" => request_uri.to_string(),
            "remoteAddr" => remote_addr.to_string(),
            _ => "".to_string(),
        })
    };

    // Delete headers
    for name in &policy.delete_headers {
        if let Ok(header_name) = HeaderName::from_str(name) {
            upstream_request.remove_header(&header_name);
        }
    }

    // Set headers (overwrite existing)
    for h in &policy.set_headers {
        if !h.is_on {
            continue;
        }
        let resolved = resolve(&h.value);
        if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&h.name), HeaderValue::from_str(&resolved))
        {
            upstream_request.insert_header(hn, hv).ok();
        }
    }

    // Add headers (do not overwrite if already present)
    for h in &policy.add_headers {
        if !h.is_on {
            continue;
        }
        let resolved = resolve(&h.value);
        if let (Ok(hn), Ok(hv)) = (HeaderName::from_str(&h.name), HeaderValue::from_str(&resolved))
        {
            if upstream_request.headers.get(&hn).is_none() {
                upstream_request.insert_header(hn, hv).ok();
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
        headers
            .entry(h.name.to_lowercase())
            .or_insert_with(|| h.value.clone());
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
