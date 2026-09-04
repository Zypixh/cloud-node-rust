use crate::config_models::HTTPCacheRef;
use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

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
            let directive_name = value
                .split_once('=')
                .map(|(name, _)| name.trim())
                .unwrap_or(value);
            skipped
                .iter()
                .map(|skip| skip.trim())
                .filter(|skip| !skip.is_empty())
                .any(|skip| {
                    value.eq_ignore_ascii_case(skip)
                        || (!skip.contains('=') && directive_name.eq_ignore_ascii_case(skip))
                })
        })
}

fn parse_content_length_values<'a>(
    values: impl Iterator<Item = &'a HeaderValue>,
) -> Result<Option<u64>, ()> {
    let mut content_length = None;
    for value in values {
        let value = value.to_str().map_err(|_| ())?;
        let value = value.trim().parse::<u64>().map_err(|_| ())?;
        if content_length.is_some_and(|previous| previous != value) {
            return Err(());
        }
        content_length = Some(value);
    }
    Ok(content_length)
}

/// Parse all Content-Length fields as one consistent value.
///
/// A response with repeated fields is only safe to cache when every value is
/// identical. Keeping this parser shared by admission and the miss handlers
/// prevents the decision path from accepting a response that the writer later
/// interprets differently.
pub(crate) fn response_content_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    parse_content_length_values(headers.get_all("content-length").iter())
}

/// Validate the response transfer framing and report whether it is chunked.
///
/// This cache only accepts the HTTP framing form Transfer-Encoding: chunked.
/// Other transfer codings, empty list elements, repeated chunked codings, and
/// a simultaneous Content-Length are rejected so the cache admission decision
/// cannot disagree with the body parser about the response boundary.
pub(crate) fn response_transfer_encoding_is_chunked(headers: &HeaderMap) -> Result<bool, ()> {
    let mut coding_count = 0usize;
    for value in headers.get_all("transfer-encoding").iter() {
        let value = value.to_str().map_err(|_| ())?;
        for coding in value.split(',') {
            let coding = coding.trim();
            if coding.is_empty() || !coding.eq_ignore_ascii_case("chunked") {
                return Err(());
            }
            coding_count = coding_count.checked_add(1).ok_or(())?;
        }
    }
    if coding_count > 0 && headers.contains_key("content-length") {
        return Err(());
    }
    if coding_count > 1 {
        return Err(());
    }
    Ok(coding_count == 1)
}

fn cache_control_has_directive(cache_control: &str, directive: &str) -> bool {
    cache_control.split(',').map(str::trim).any(|value| {
        value
            .split_once('=')
            .map(|(name, _)| name.trim())
            .unwrap_or(value)
            .eq_ignore_ascii_case(directive)
    })
}

pub(crate) fn cache_control_headers_have_skipped_value(
    headers: &HeaderMap,
    skipped: &[String],
) -> bool {
    headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| cache_control_has_skipped_value(value, skipped))
}

/// Shared-cache request admission. The configured cache method list may narrow
/// this set further, but it must never widen it to unsafe request methods or
/// requests carrying per-user state.
pub(crate) fn request_headers_allow_shared_cache(method: &str, headers: &HeaderMap) -> bool {
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    if headers.contains_key("cookie") || headers.contains_key("authorization") {
        return false;
    }
    if headers.contains_key("transfer-encoding") {
        return false;
    }
    // If-Range is evaluated against the origin representation's validator.
    // A cache hit path does not have enough information to safely decide
    // whether the client's Range should produce 206 or fall back to 200.
    // Treat the combination as a pass-through request so a stale/mismatched
    // validator can never receive a false partial response from cache.
    if headers.contains_key("range") && headers.contains_key("if-range") {
        return false;
    }
    let Ok(request_content_length) = response_content_length(headers) else {
        return false;
    };
    if request_content_length.is_some_and(|length| length > 0) {
        return false;
    }
    true
}

/// Responses with these fields cannot be shared safely by this cache. Vary
/// is deliberately rejected until the storage key and representation contract
/// use Pingora's native variance consistently.
pub(crate) fn response_headers_allow_shared_cache(headers: &HeaderMap) -> bool {
    // The storage metadata format is UTF-8 based. Silently replacing an
    // invalid value with an empty string would make a cache hit observably
    // different from the origin response, and can also invalidate security
    // headers. Reject the whole response until headers can be persisted as
    // bytes without loss.
    if headers.iter().any(|(_, value)| value.to_str().is_err()) {
        return false;
    }

    if headers.contains_key("set-cookie") || headers.contains_key("vary") {
        return false;
    }

    // Multiple Content-Length fields are only safe when every value is the
    // same.  Looking at HeaderMap::get() alone lets an attacker hide a second
    // length behind a valid first value and can desynchronize the cache body
    // from the response framing.
    if response_content_length(headers).is_err() {
        return false;
    }
    if response_transfer_encoding_is_chunked(headers).is_err() {
        return false;
    }

    for value in headers.get_all("cache-control").iter() {
        let Ok(value) = value.to_str() else {
            return false;
        };
        if cache_control_has_directive(value, "no-store")
            || cache_control_has_directive(value, "private")
            || cache_control_has_directive(value, "no-cache")
        {
            return false;
        }
    }
    for value in headers.get_all("pragma").iter() {
        let Ok(value) = value.to_str() else {
            return false;
        };
        if cache_control_has_directive(value, "no-cache") {
            return false;
        }
    }
    true
}

/// Validate headers restored from persisted metadata before replaying them.
/// Metadata can outlive the code that wrote it, so admission checks on the
/// original response are not sufficient for legacy or externally replicated
/// entries.
pub(crate) fn stored_response_headers_allow_shared_cache(headers: &[(String, String)]) -> bool {
    let mut restored = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            return false;
        };
        let Ok(value) = HeaderValue::from_str(value) else {
            return false;
        };
        let is_content_length = name.as_str().eq_ignore_ascii_case("content-length");
        if !should_store_response_header(name.as_str()) && !is_content_length {
            return false;
        }
        if is_content_length
            && value
                .to_str()
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .is_none()
        {
            return false;
        }
        restored.append(name, value);
    }
    response_headers_allow_shared_cache(&restored)
}

fn cache_key_representation_root(cache_key: &str) -> std::borrow::Cow<'_, str> {
    crate::cache::partial::partial_base_key(cache_key)
        .map(std::borrow::Cow::Owned)
        .unwrap_or_else(|| std::borrow::Cow::Borrowed(cache_key))
}

const CACHE_METHOD_KEY_MARKER: &str = "@__cloud_node_method:";
const CACHE_ENCODING_KEY_MARKER: &str = "@__cloud_node_ce:";
const CACHE_WEBP_KEY_MARKER: &str = "@__cloud_node_webp:";

/// Append the authenticated method marker used for method-specific cache
/// variants.  A plain `@method:HEAD` suffix is user-controlled when a custom
/// cache-key template is configured, so it can make a GET key collide with a
/// HEAD key.  Binding the marker to the complete key before it is appended
/// makes accidental collisions fail closed during replay.
pub(crate) fn append_cache_method_variant(key: &mut String, method: &str) {
    if !method.eq_ignore_ascii_case("HEAD") {
        return;
    }
    let digest = format!("{:x}", md5_legacy::compute(key.as_bytes()));
    key.push_str(CACHE_METHOD_KEY_MARKER);
    key.push_str("HEAD");
    key.push(':');
    key.push_str(&digest);
}

/// Return whether a cache key contains a valid digest-bound HEAD marker.
/// Legacy `@method:HEAD` keys deliberately do not count: they are retained
/// only as purge candidates because a user-supplied cache key can contain the
/// same text.
pub(crate) fn cache_key_is_head_variant(cache_key: &str) -> bool {
    let root = cache_key_representation_root(cache_key);
    let marker = CACHE_METHOD_KEY_MARKER;
    let Some(marker_start) = root.rfind(marker) else {
        return false;
    };
    let value_start = marker_start + marker.len();
    let value_end = root[value_start..]
        .find('@')
        .map(|offset| value_start + offset)
        .unwrap_or(root.len());
    let value = &root[value_start..value_end];
    let Some((method, digest)) = value.split_once(':') else {
        return false;
    };
    if !method.eq_ignore_ascii_case("HEAD")
        || digest.len() != 32
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    let expected = format!("{:x}", md5_legacy::compute(&root[..marker_start]));
    digest.eq_ignore_ascii_case(&expected)
}

/// Append a representation marker to a cache key.
///
/// The digest binds the marker to the complete key that precedes it.  A plain
/// suffix such as `@br` is ambiguous because it can be part of an otherwise
/// valid user-supplied cache key.
pub(crate) fn append_cache_encoding_variant(key: &mut String, encoding: &str) {
    if !matches!(encoding, "br" | "gzip") {
        return;
    }
    let digest = format!("{:x}", md5_legacy::compute(key.as_bytes()));
    key.push_str(CACHE_ENCODING_KEY_MARKER);
    key.push_str(encoding);
    key.push(':');
    key.push_str(&digest);
}

/// Append the authenticated WebP representation marker to a cache key.
///
/// A plain `@webp` suffix is part of the user-controlled key namespace.  Bind
/// the marker to the complete key that precedes it so a normal custom key can
/// never accidentally alias the transformed representation.
pub(crate) fn append_cache_webp_variant(key: &mut String) {
    let digest = format!("{:x}", md5_legacy::compute(key.as_bytes()));
    key.push_str(CACHE_WEBP_KEY_MARKER);
    key.push_str(&digest);
}

/// Return the representation selected by a cache key, or `Err(())` for an
/// invalid/legacy compression marker.  Invalid markers fail closed instead
/// of being treated as identity content.
fn cache_key_encoding_variant(cache_key: &str) -> Result<&'static str, ()> {
    let root = cache_key_representation_root(cache_key);
    if let Some((base_key, marker)) = root.rsplit_once(CACHE_ENCODING_KEY_MARKER) {
        let Some((encoding, digest)) = marker.split_once(':') else {
            return Err(());
        };
        if digest.len() != 32 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(());
        }
        let expected = format!("{:x}", md5_legacy::compute(base_key.as_bytes()));
        if !digest.eq_ignore_ascii_case(&expected) {
            return Err(());
        }
        return match encoding {
            "br" => Ok("br"),
            "gzip" => Ok("gzip"),
            _ => Err(()),
        };
    }

    // Without the digest-bound marker this is an identity representation.  A
    // user-defined key may legitimately end in "@br" or "@gzip"; treating
    // those ordinary characters as an encoding selector would make valid
    // identity objects uncacheable.  Legacy compressed objects still fail the
    // actual Content-Encoding check below, so removing this heuristic does
    // not make them replayable.
    Ok("identity")
}

fn parse_content_encoding_values<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<Option<String>, ()> {
    let mut encoding = None;
    for value in values {
        for token in value.split(',').map(str::trim) {
            // An empty list element is not a valid content-coding.  Do not
            // silently turn `gzip,` or `gzip,,br` into a different, valid
            // representation; the cache key must be authenticated by the
            // exact response header syntax as well as by its coding value.
            if token.is_empty() {
                return Err(());
            }
            if encoding.is_some() {
                // Multiple codings are a different representation from the
                // single-coding variants this cache key contract supports.
                return Err(());
            }
            encoding = Some(token.to_ascii_lowercase());
        }
    }
    Ok(encoding)
}

/// Checks that the response's actual content coding belongs to the encoding
/// variant encoded in the cache key.  The key is selected before the origin
/// response exists, so this check is required on both fill and hit paths.
pub(crate) fn response_encoding_matches_cache_key(cache_key: &str, headers: &HeaderMap) -> bool {
    let values = headers
        .get_all("content-encoding")
        .iter()
        .map(|value| value.to_str().map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>();
    let Ok(values) = values else {
        return false;
    };
    let Ok(actual) = parse_content_encoding_values(values.into_iter()) else {
        return false;
    };
    let Ok(variant) = cache_key_encoding_variant(cache_key) else {
        return false;
    };
    encoding_variant_matches_actual(variant, actual.as_deref())
}

pub(crate) fn stored_response_encoding_matches_cache_key(
    cache_key: &str,
    headers: &[(String, String)],
) -> bool {
    let Ok(actual) = parse_content_encoding_values(
        headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
            .map(|(_, value)| value.as_str()),
    ) else {
        return false;
    };
    let Ok(variant) = cache_key_encoding_variant(cache_key) else {
        return false;
    };
    encoding_variant_matches_actual(variant, actual.as_deref())
}

fn encoding_variant_matches_actual(variant: &str, actual: Option<&str>) -> bool {
    match variant {
        // Compressed variants never admit identity: otherwise a client with
        // identity;q=0 could hit an identity body inserted by a different
        // negotiation result under the same @br/@gzip key.
        "br" => actual == Some("br"),
        "gzip" => actual == Some("gzip"),
        _ => actual.is_none_or(|actual| actual == "identity"),
    }
}

/// Compare a streamed body size with a positive signed configuration limit
/// without converting the `usize` through `i64`.  On 64-bit hosts a body can
/// be larger than `i64::MAX`; wrapping that conversion would turn an oversized
/// response into a negative value and bypass the configured limit.
pub(crate) fn body_size_below_limit(body_size: usize, limit: i64) -> bool {
    limit > 0 && (body_size as u128) < (limit as u128)
}

pub(crate) fn body_size_exceeds_limit(body_size: usize, limit: i64) -> bool {
    limit > 0 && (body_size as u128) > (limit as u128)
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
    if !status_allows_shared_cache_with_error_policy(
        status,
        cache_ref_explicitly_allows_error_status(status, cache_ref),
    ) {
        return false;
    }

    let safe_method = method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD");
    let method_allowed = safe_method
        && (cache_ref.methods.is_empty()
            || cache_ref
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method)));
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

/// Only final responses with an independently replayable semantics may enter
/// the shared object store. Informational responses and 304 are tied to the
/// surrounding exchange and must never become standalone cache entries.
/// 204 is excluded as well because it has no representation body and has
/// repeatedly caused metadata/body mismatches in this backend.
pub(crate) fn status_allows_shared_cache(status: u16) -> bool {
    (200..=599).contains(&status) && status != 204 && status != 304
}

/// Error responses are structurally replayable, but must not enter the shared
/// cache unless the selected cache rule explicitly lists that exact status.
/// Keeping this separate from the structural predicate lets persisted legacy
/// metadata fail closed without changing the meaning of the status list.
pub(crate) fn status_allows_shared_cache_with_error_policy(
    status: u16,
    error_status_allowed: bool,
) -> bool {
    status_allows_shared_cache(status) && (status < 500 || error_status_allowed)
}

/// A complete-object entry must not contain a partial response. Range
/// responses use the separate partial-cache store and are replayable there
/// only with an explicit range selector.
pub(crate) fn status_allows_full_cache(status: u16) -> bool {
    status_allows_shared_cache(status) && status != 206
}

pub(crate) fn status_allows_full_cache_with_error_policy(
    status: u16,
    error_status_allowed: bool,
) -> bool {
    status_allows_full_cache(status) && (status < 500 || error_status_allowed)
}

pub(crate) fn cache_ref_explicitly_allows_error_status(
    status: u16,
    cache_ref: &HTTPCacheRef,
) -> bool {
    status >= 500 && cache_ref.status.contains(&(status as i32))
}

#[derive(Clone, Copy)]
pub struct CacheResponseDecisionInput<'a> {
    pub status: u16,
    pub method: &'a str,
    pub headers: &'a http::HeaderMap,
    pub body_size: usize,
    pub force_partial_content: bool,
    pub skip_size_checks: bool,
    pub req_headers: &'a http::HeaderMap,
}

pub fn should_cache_response(
    cache_ref: &HTTPCacheRef,
    input: CacheResponseDecisionInput<'_>,
) -> bool {
    if !request_headers_allow_shared_cache(input.method, input.req_headers)
        || !response_headers_allow_shared_cache(input.headers)
    {
        return false;
    }

    if !cache_ref_allows_method_status(
        input.status,
        cache_ref,
        input.method,
        input.force_partial_content,
    ) {
        return false;
    }

    // 3. Check Size (skip for chunked encoding when policy allows)
    if !input.skip_size_checks {
        if let Some(min_size_val) = &cache_ref.min_size {
            let min_bytes = crate::config_models::SizeCapacity::from_json(min_size_val).to_bytes();
            if body_size_below_limit(input.body_size, min_bytes) {
                return false;
            }
        }
        if let Some(max_size_val) = &cache_ref.max_size {
            let max_bytes = crate::config_models::SizeCapacity::from_json(max_size_val).to_bytes();
            if body_size_exceeds_limit(input.body_size, max_bytes) {
                return false;
            }
        }
    }

    // 4. Check every Cache-Control field. HTTP permits repeated fields and a
    // second field must not bypass a configured skip directive.
    if cache_control_headers_have_skipped_value(input.headers, &cache_ref.skip_cache_control_values)
    {
        return false;
    }

    true
}

pub fn parse_life_to_seconds(v: &serde_json::Value) -> u64 {
    crate::config_models::parse_life_to_seconds(v)
}

#[cfg(test)]
mod tests {
    use super::{
        CacheResponseDecisionInput, cache_ref_allows_method_status, should_cache_response,
        should_store_response_header,
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
    fn explicit_methods_cannot_widen_shared_cache_methods() {
        let cache_ref = cache_ref(vec!["PUT".to_string()]);

        assert!(!cache_ref_allows_method_status(
            200, &cache_ref, "PUT", false
        ));
        assert!(!cache_ref_allows_method_status(
            200, &cache_ref, "GET", false
        ));
    }

    #[test]
    fn non_replayable_response_statuses_are_not_cacheable() {
        let mut cache_ref = cache_ref(vec![]);
        cache_ref.status.clear();
        for status in [100, 199, 204, 304, 600, u16::MAX] {
            assert!(!cache_ref_allows_method_status(
                status, &cache_ref, "GET", false
            ));
        }
        assert!(cache_ref_allows_method_status(
            200, &cache_ref, "GET", false
        ));
        assert!(!cache_ref_allows_method_status(
            500, &cache_ref, "GET", false
        ));
        cache_ref.status.push(500);
        assert!(cache_ref_allows_method_status(
            500, &cache_ref, "GET", false
        ));
        assert!(!super::status_allows_full_cache(206));
        assert!(!super::status_allows_full_cache(304));
        assert!(super::status_allows_full_cache(200));
    }

    #[test]
    fn error_statuses_require_exact_rule_opt_in_on_both_policy_paths() {
        let mut cache_ref = cache_ref(vec![]);
        cache_ref.status.clear();
        let headers = HeaderMap::new();
        let request_headers = HeaderMap::new();
        let compiled = CompiledCacheRef::compile_arc(&Arc::new(cache_ref.clone()));

        assert!(!should_cache_response(
            &cache_ref,
            crate::cache::CacheResponseDecisionInput {
                status: 500,
                method: "GET",
                headers: &headers,
                body_size: 0,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &request_headers,
            },
        ));
        assert!(!should_cache_response_compiled(
            &compiled,
            None,
            crate::cache::CacheResponseDecisionInput {
                status: 500,
                method: "GET",
                headers: &headers,
                body_size: 0,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &request_headers,
            },
        ));

        cache_ref.status = vec![500];
        let compiled = CompiledCacheRef::compile_arc(&Arc::new(cache_ref.clone()));
        assert!(should_cache_response(
            &cache_ref,
            crate::cache::CacheResponseDecisionInput {
                status: 500,
                method: "GET",
                headers: &headers,
                body_size: 0,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &request_headers,
            },
        ));
        assert!(should_cache_response_compiled(
            &compiled,
            None,
            crate::cache::CacheResponseDecisionInput {
                status: 500,
                method: "GET",
                headers: &headers,
                body_size: 0,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &request_headers,
            },
        ));
        assert!(compiled.response_policy.error_status_allowed(500));
        assert!(!compiled.response_policy.error_status_allowed(503));
    }

    #[test]
    fn shared_cache_request_gate_rejects_credentials_and_bodies() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("sid=1"));
        assert!(!super::request_headers_allow_shared_cache("GET", &headers));

        headers.clear();
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        assert!(!super::request_headers_allow_shared_cache("GET", &headers));

        headers.clear();
        headers.insert("content-length", HeaderValue::from_static("1"));
        assert!(!super::request_headers_allow_shared_cache("GET", &headers));
        assert!(super::request_headers_allow_shared_cache(
            "GET",
            &HeaderMap::new()
        ));

        headers.clear();
        headers.append("content-length", HeaderValue::from_static("0"));
        headers.append("content-length", HeaderValue::from_static("0"));
        assert!(super::request_headers_allow_shared_cache("GET", &headers));

        headers.append("content-length", HeaderValue::from_static("1"));
        assert!(!super::request_headers_allow_shared_cache("GET", &headers));

        headers.clear();
        headers.insert("content-length", HeaderValue::from_static("0, 0"));
        assert!(!super::request_headers_allow_shared_cache("GET", &headers));
    }

    #[test]
    fn range_with_if_range_bypasses_shared_cache() {
        let mut headers = HeaderMap::new();
        headers.insert("range", HeaderValue::from_static("bytes=0-9"));
        headers.insert("if-range", HeaderValue::from_static("\"etag-v1\""));
        assert!(!super::request_headers_allow_shared_cache("GET", &headers));

        headers.remove("if-range");
        assert!(super::request_headers_allow_shared_cache("GET", &headers));
    }

    #[test]
    fn shared_cache_response_gate_rejects_privacy_directives() {
        for value in [
            "public, no-store",
            "max-age=60, private",
            "no-cache=\"Set-Cookie\"",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("cache-control", HeaderValue::from_static(value));
            assert!(!super::response_headers_allow_shared_cache(&headers));
        }

        let mut headers = HeaderMap::new();
        headers.insert("pragma", HeaderValue::from_static("foo, no-cache"));
        assert!(!super::response_headers_allow_shared_cache(&headers));

        headers.clear();
        headers.insert("vary", HeaderValue::from_static("Accept-Encoding"));
        assert!(!super::response_headers_allow_shared_cache(&headers));
    }

    #[test]
    fn shared_cache_response_gate_validates_transfer_framing() {
        let mut headers = HeaderMap::new();
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        assert!(super::response_transfer_encoding_is_chunked(&headers).unwrap());
        assert!(super::response_headers_allow_shared_cache(&headers));

        headers.insert(
            "transfer-encoding",
            HeaderValue::from_static("gzip, chunked"),
        );
        assert!(super::response_transfer_encoding_is_chunked(&headers).is_err());
        assert!(!super::response_headers_allow_shared_cache(&headers));

        headers.clear();
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked,"));
        assert!(super::response_transfer_encoding_is_chunked(&headers).is_err());

        headers.clear();
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-length", HeaderValue::from_static("10"));
        assert!(super::response_transfer_encoding_is_chunked(&headers).is_err());
        assert!(!super::response_headers_allow_shared_cache(&headers));
    }

    #[test]
    fn persisted_response_headers_are_revalidated_before_replay() {
        assert!(super::stored_response_headers_allow_shared_cache(&[(
            "content-type".to_string(),
            "text/plain".to_string()
        ),]));
        assert!(!super::stored_response_headers_allow_shared_cache(&[(
            "set-cookie".to_string(),
            "sid=1".to_string()
        ),]));
        assert!(!super::stored_response_headers_allow_shared_cache(&[(
            "vary".to_string(),
            "Accept-Encoding".to_string()
        ),]));
        assert!(!super::stored_response_headers_allow_shared_cache(&[(
            "not a header".to_string(),
            "value".to_string()
        ),]));
        assert!(super::stored_response_headers_allow_shared_cache(&[(
            "content-length".to_string(),
            "42".to_string()
        ),]));
        assert!(!super::stored_response_headers_allow_shared_cache(&[(
            "content-length".to_string(),
            "not-a-number".to_string()
        ),]));
    }

    #[test]
    fn duplicate_content_lengths_must_be_identical() {
        let mut headers = HeaderMap::new();
        headers.append("content-length", HeaderValue::from_static("42"));
        headers.append("content-length", HeaderValue::from_static("42"));
        assert!(super::response_headers_allow_shared_cache(&headers));

        headers.append("content-length", HeaderValue::from_static("43"));
        assert!(!super::response_headers_allow_shared_cache(&headers));

        assert!(super::stored_response_headers_allow_shared_cache(&[
            ("content-length".to_string(), "42".to_string()),
            ("Content-Length".to_string(), "42".to_string()),
        ]));
        assert!(!super::stored_response_headers_allow_shared_cache(&[
            ("content-length".to_string(), "42".to_string()),
            ("content-length".to_string(), "43".to_string()),
        ]));
    }

    #[test]
    fn compression_key_marker_is_bound_to_the_unencoded_key() {
        let mut compressed = "https://cache.example.test/image@br".to_string();
        super::append_cache_encoding_variant(&mut compressed, "br");

        let mut brotli = HeaderMap::new();
        brotli.insert("content-encoding", HeaderValue::from_static("br"));
        assert!(super::response_encoding_matches_cache_key(
            &compressed,
            &brotli
        ));

        let mut gzip = HeaderMap::new();
        gzip.insert("content-encoding", HeaderValue::from_static("gzip"));
        assert!(!super::response_encoding_matches_cache_key(
            &compressed,
            &gzip
        ));

        let mut tampered = compressed.clone();
        tampered.push('x');
        assert!(!super::response_encoding_matches_cache_key(
            &tampered, &brotli
        ));

        // A user key ending in the old suffix remains an ordinary identity
        // key. It must not select a compressed representation by accident.
        let user_key = "https://cache.example.test/image@br";
        assert!(super::response_encoding_matches_cache_key(
            user_key,
            &HeaderMap::new()
        ));
        assert!(!super::response_encoding_matches_cache_key(
            user_key, &brotli
        ));
    }

    #[test]
    fn malformed_content_encoding_list_is_rejected() {
        for value in ["gzip,", ",gzip", "gzip,,br", ""] {
            let mut headers = HeaderMap::new();
            headers.insert("content-encoding", HeaderValue::from_static(value));
            assert!(!super::response_encoding_matches_cache_key(
                "https://cache.example.test/image",
                &headers,
            ));
        }
    }

    #[test]
    fn head_key_marker_is_bound_and_legacy_suffix_is_not_semantic() {
        let mut head = "https://cache.example.test/document".to_string();
        super::append_cache_method_variant(&mut head, "HEAD");
        assert!(super::cache_key_is_head_variant(&head));

        let mut tampered = head.clone();
        tampered.push('x');
        assert!(!super::cache_key_is_head_variant(&tampered));

        // The legacy suffix is still removed by purge enumeration, but it is
        // not trusted for body/Content-Length decisions anymore.
        assert!(!super::cache_key_is_head_variant(
            "https://cache.example.test/document@method:HEAD"
        ));

        // User-defined keys and partial keys must preserve the same rule.
        assert!(!super::cache_key_is_head_variant(
            "https://cache.example.test/document@method:HEAD"
        ));
        let partial =
            super::partial::partial_cache_key(&head, Some("bytes=0-9")).expect("partial key");
        assert!(super::cache_key_is_head_variant(&partial));

        let mut head_webp = head.clone();
        super::append_cache_webp_variant(&mut head_webp);
        assert!(super::cache_key_is_head_variant(&head_webp));
        super::append_cache_encoding_variant(&mut head_webp, "br");
        assert!(super::cache_key_is_head_variant(&head_webp));
    }

    #[test]
    fn partial_cache_key_uses_the_compression_marker_of_its_base_key() {
        let mut compressed = "https://cache.example.test/video".to_string();
        super::append_cache_encoding_variant(&mut compressed, "gzip");
        let partial =
            super::partial::partial_cache_key(&compressed, Some("bytes=0-9")).expect("partial key");
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", HeaderValue::from_static("gzip"));
        assert!(super::response_encoding_matches_cache_key(
            &partial, &headers
        ));
        headers.insert("content-encoding", HeaderValue::from_static("br"));
        assert!(!super::response_encoding_matches_cache_key(
            &partial, &headers
        ));
    }

    #[test]
    fn webp_key_marker_is_bound_to_the_unencoded_key() {
        let mut webp = "https://cache.example.test/image.jpg".to_string();
        super::append_cache_webp_variant(&mut webp);
        assert_ne!(webp, "https://cache.example.test/image.jpg@webp");

        let mut compressed = webp.clone();
        super::append_cache_encoding_variant(&mut compressed, "br");
        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", HeaderValue::from_static("br"));
        assert!(super::response_encoding_matches_cache_key(
            &compressed,
            &headers
        ));
    }

    #[test]
    fn cache_size_comparisons_do_not_wrap_usize_through_i64() {
        assert!(super::body_size_below_limit(99, 100));
        assert!(!super::body_size_below_limit(100, 100));
        assert!(super::body_size_exceeds_limit(101, 100));
        assert!(!super::body_size_exceeds_limit(100, 100));

        #[cfg(target_pointer_width = "64")]
        assert!(super::body_size_exceeds_limit(usize::MAX, i64::MAX));
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
                    &cache_ref,
                    CacheResponseDecisionInput {
                        status,
                        method,
                        headers: &headers,
                        body_size: size,
                        force_partial_content: force_partial,
                        skip_size_checks: false,
                        req_headers: &req_headers,
                    },
                ),
                expected
            );
            assert_eq!(
                should_cache_response_compiled(
                    &compiled,
                    None,
                    CacheResponseDecisionInput {
                        status,
                        method,
                        headers: &headers,
                        body_size: size,
                        force_partial_content: force_partial,
                        skip_size_checks: false,
                        req_headers: &req_headers,
                    },
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
            &cache_ref,
            CacheResponseDecisionInput {
                status: 206,
                method: "GET",
                headers: &headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &headers,
            },
        ));
        assert!(should_cache_response_compiled(
            &compiled,
            None,
            CacheResponseDecisionInput {
                status: 206,
                method: "GET",
                headers: &headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &headers,
            },
        ));

        let mut private_headers = HeaderMap::new();
        private_headers.insert(
            "cache-control",
            HeaderValue::from_static("max-age=60, private"),
        );
        assert!(!should_cache_response(
            &cache_ref,
            CacheResponseDecisionInput {
                status: 200,
                method: "GET",
                headers: &private_headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &headers,
            },
        ));
        assert!(!should_cache_response_compiled(
            &compiled,
            None,
            CacheResponseDecisionInput {
                status: 200,
                method: "GET",
                headers: &private_headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &headers,
            },
        ));

        let mut cookie_headers = HeaderMap::new();
        cookie_headers.insert("set-cookie", HeaderValue::from_static("sid=1"));
        assert!(!should_cache_response(
            &cache_ref,
            CacheResponseDecisionInput {
                status: 200,
                method: "GET",
                headers: &cookie_headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &headers,
            },
        ));
        assert!(!should_cache_response_compiled(
            &compiled,
            None,
            CacheResponseDecisionInput {
                status: 200,
                method: "GET",
                headers: &cookie_headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &headers,
            },
        ));

        cache_ref.skip_set_cookie = false;
        let compiled = CompiledCacheRef::compile_arc(&Arc::new(cache_ref.clone()));
        assert!(!should_cache_response(
            &cache_ref,
            CacheResponseDecisionInput {
                status: 200,
                method: "GET",
                headers: &cookie_headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &headers,
            },
        ));
        assert!(!should_cache_response_compiled(
            &compiled,
            None,
            CacheResponseDecisionInput {
                status: 200,
                method: "GET",
                headers: &cookie_headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &headers,
            },
        ));

        assert_eq!(compiled.response_policy.ttl_seconds(), 3600);
        assert_eq!(compiled.response_policy.force_ttl_seconds(), Some(300));
        assert!(compiled.response_policy.overwrite_expires());
    }

    #[test]
    fn every_cache_control_field_is_checked_by_both_policy_paths() {
        let mut cache_ref = cache_ref(vec![]);
        cache_ref.skip_cache_control_values = vec!["private".to_string()];
        let compiled = CompiledCacheRef::compile_arc(&Arc::new(cache_ref.clone()));
        let mut headers = HeaderMap::new();
        headers.append(
            "cache-control",
            HeaderValue::from_static("public, max-age=60"),
        );
        headers.append("cache-control", HeaderValue::from_static("private"));
        let request_headers = HeaderMap::new();

        assert!(!should_cache_response(
            &cache_ref,
            crate::cache::CacheResponseDecisionInput {
                status: 200,
                method: "GET",
                headers: &headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &request_headers,
            },
        ));
        assert!(!should_cache_response_compiled(
            &compiled,
            None,
            crate::cache::CacheResponseDecisionInput {
                status: 200,
                method: "GET",
                headers: &headers,
                body_size: 10,
                force_partial_content: false,
                skip_size_checks: false,
                req_headers: &request_headers,
            },
        ));
    }
}
