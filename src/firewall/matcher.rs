use regex::{Regex, RegexBuilder};
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::time::Duration;

/// Limit regex memory usage to 1MB to prevent catastrophic backtracking from user-controlled WAF patterns
const REGEX_SIZE_LIMIT: usize = 1_048_576;

/// Bound on how many distinct WAF regex patterns we keep compiled in memory.
/// Each cached entry can hold a Regex up to REGEX_SIZE_LIMIT (1 MiB) bytes,
/// so the worst-case footprint is ~MAX × ~1 MiB. The cache uses moka's
/// W-TinyLFU eviction (the same algorithm behind Caffeine), which resists
/// "scanning" attacks where an adversary streams unique patterns to flush
/// hot entries — admission control gates a candidate against the historical
/// frequency of the victim before evicting it.
const WAF_RE_CACHE_MAX_ENTRIES: u64 = 16_384;

/// Cache compiled user-defined regex patterns to avoid per-request
/// compilation. moka::sync::Cache is concurrent (internally sharded) and
/// implements W-TinyLFU admission + segmented LRU eviction, suitable for
/// large-scale traffic where the hot set is a small subset of all patterns
/// ever seen.
static WAF_RE_CACHE: Lazy<moka::sync::Cache<String, Arc<Regex>>> = Lazy::new(|| {
    moka::sync::Cache::builder()
        .max_capacity(WAF_RE_CACHE_MAX_ENTRIES)
        .time_to_idle(Duration::from_secs(15 * 60))
        .build()
});

static WAF_BYTES_RE_CACHE: Lazy<moka::sync::Cache<String, Arc<regex::bytes::Regex>>> =
    Lazy::new(|| {
        moka::sync::Cache::builder()
            .max_capacity(WAF_RE_CACHE_MAX_ENTRIES)
            .time_to_idle(Duration::from_secs(15 * 60))
            .build()
    });

static RE_SQLI: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|truncate\s+table|benchmark\(|sleep\()").unwrap()
});
static RE_SQLI_STRICT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)('|--|#|/\*|\*/|\b(and|or)\b\s+\d+=\d+)").unwrap());
static RE_XSS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(<script|javascript:|onerror=|onload=|eval\(|alert\(|document\.cookie)")
        .unwrap()
});
static RE_XSS_STRICT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(<xml|<audio|<video|<svg|<iframe|<img|<link|<style|<form)").unwrap()
});

pub(crate) fn contains_sqli(value: &str, strict: bool) -> bool {
    if libinjectionrs::detect_sqli(value.as_bytes()).is_injection() {
        return true;
    }
    RE_SQLI.is_match(value) || (strict && RE_SQLI_STRICT.is_match(value))
}

pub(crate) fn contains_xss(value: &str, strict: bool) -> bool {
    if libinjectionrs::detect_xss(value.as_bytes()).is_injection() {
        return true;
    }
    RE_XSS.is_match(value) || (strict && RE_XSS_STRICT.is_match(value))
}

pub(crate) fn contains_cmd(value: &str) -> bool {
    const CMD_KEYWORDS: &[&str] = &[
        "/bin/sh",
        "/bin/bash",
        "cmd.exe",
        "powershell",
        "curl ",
        "wget ",
    ];
    CMD_KEYWORDS
        .iter()
        .any(|keyword| contains_ascii_case_insensitive(value, keyword))
}

pub fn evaluate_operator(
    actual_value: &str,
    operator: &str,
    expected_value: &str,
    case_insensitive: bool,
) -> bool {
    let operator_lower = normalize_operator(operator);
    let actual: Cow<'_, str> = if case_insensitive {
        Cow::Owned(actual_value.to_lowercase())
    } else {
        Cow::Borrowed(actual_value)
    };
    let expected: Cow<'_, str> = if case_insensitive {
        Cow::Owned(expected_value.to_lowercase())
    } else {
        Cow::Borrowed(expected_value)
    };

    match operator_lower.as_ref() {
        "eq string" => actual == expected,
        "neq string" => actual != expected,
        "match" | "matches" | "regexp" => {
            get_or_compile_regex(&expected).map_or(false, |re| re.is_match(&actual))
        }
        "not match" | "notmatches" | "notregexp" => {
            get_or_compile_regex(&expected).map_or(false, |re| !re.is_match(&actual))
        }
        "wildcard match" => {
            let escaped = regex::escape(&expected).replace("\\*", ".*");
            let re_str = format!("^{}$", escaped);
            get_or_compile_regex(&re_str).map_or(false, |re| re.is_match(&actual))
        }
        "wildcard not match" => {
            let escaped = regex::escape(&expected).replace("\\*", ".*");
            let re_str = format!("^{}$", escaped);
            get_or_compile_regex(&re_str).map_or(false, |re| !re.is_match(&actual))
        }
        "contains" | "containsstring" => actual.contains(expected.as_ref()),
        "not contains" | "notcontains" => !actual.contains(expected.as_ref()),
        "prefix" | "hasprefix" => actual.starts_with(expected.as_ref()),
        "suffix" | "hassuffix" => actual.ends_with(expected.as_ref()),
        "contains any" => expected.lines().any(|line| actual.contains(line)),
        "contains all" => expected.lines().all(|line| actual.contains(line)),
        "contains any word" => split_terms(&expected).any(|term| contains_word(&actual, term)),
        "contains all words" => split_terms(&expected).all(|term| contains_word(&actual, term)),
        "not contains any word" => !split_terms(&expected).any(|term| contains_word(&actual, term)),
        "eq" | "neq" | "gt" | "gte" | "lt" | "lte" => {
            // number comparisons
            if let (Ok(a), Ok(e)) = (actual.parse::<f64>(), expected.parse::<f64>()) {
                match operator_lower.as_ref() {
                    "eq" => (a - e).abs() < f64::EPSILON,
                    "neq" => (a - e).abs() > f64::EPSILON,
                    "gt" => a > e,
                    "gte" => a >= e,
                    "lt" => a < e,
                    "lte" => a <= e,
                    _ => false,
                }
            } else {
                false // fail parsing
            }
        }
        "eq ip" => actual == expected,
        "in ip list" => {
            expected.lines().any(|line| {
                let item = line.trim();
                if item.is_empty() {
                    return false;
                }
                if item == actual {
                    return true;
                }
                // Try parse as CIDR
                if let (Ok(net), Ok(addr)) = (
                    item.parse::<ipnet::IpNet>(),
                    actual.parse::<std::net::IpAddr>(),
                ) {
                    return net.contains(&addr);
                }
                false
            })
        }
        "neq ip" => actual != expected,
        "ip range" | "not ip range" => {
            // Support comma separated list of IPs or CIDRs
            let matched = expected.split(',').any(|part| {
                let item = part.trim();
                if item.is_empty() {
                    return false;
                }
                if item == actual {
                    return true;
                }
                if let (Ok(net), Ok(addr)) = (
                    item.parse::<ipnet::IpNet>(),
                    actual.parse::<std::net::IpAddr>(),
                ) {
                    return net.contains(&addr);
                }
                false
            });
            if operator_lower.as_ref() == "ip range" {
                matched
            } else {
                !matched
            }
        }
        "gt ip" | "gte ip" | "lt ip" | "lte ip" => {
            if let (Ok(actual_ip), Ok(expected_ip)) =
                (actual.parse::<IpAddr>(), expected.parse::<IpAddr>())
            {
                let ordering = compare_ip_bytes(actual_ip, expected_ip);
                match operator_lower.as_ref() {
                    "gt ip" => ordering.is_gt(),
                    "gte ip" => ordering.is_gt() || ordering.is_eq(),
                    "lt ip" => ordering.is_lt(),
                    "lte ip" => ordering.is_lt() || ordering.is_eq(),
                    _ => false,
                }
            } else {
                false
            }
        }
        "contains sql injection" | "contains sql injection strictly" => {
            contains_sqli(&actual, operator_lower.contains("strictly"))
        }
        "contains xss" | "contains xss strictly" => {
            contains_xss(&actual, operator_lower.contains("strictly"))
        }
        "contains binary" => decode_base64(&expected)
            .map(|needle| actual.as_bytes().windows(needle.len()).any(|w| w == needle))
            .unwrap_or(false),
        "not contains binary" => decode_base64(&expected)
            .map(|needle| !actual.as_bytes().windows(needle.len()).any(|w| w == needle))
            .unwrap_or(false),
        "has key" => {
            if let Ok(index) = expected.parse::<usize>() {
                actual.lines().nth(index).is_some()
            } else {
                actual.lines().any(|line| {
                    line.split_once('=')
                        .map(|(key, _)| key.trim() == expected)
                        .unwrap_or(false)
                }) || actual.lines().any(|line| {
                    line.split_once(':')
                        .map(|(key, _)| key.trim() == expected)
                        .unwrap_or(false)
                })
            }
        }
        "version gt" => compare_versions(&actual, &expected).is_some_and(|o| o.is_gt()),
        "version lt" => compare_versions(&actual, &expected).is_some_and(|o| o.is_lt()),
        "version range" => match expected.split_once(',') {
            Some((min, max)) => {
                let min = min.trim();
                let max = max.trim();
                let ge_min = min.is_empty()
                    || compare_versions(&actual, min).is_some_and(|o| o.is_gt() || o.is_eq());
                let le_max = max.is_empty()
                    || compare_versions(&actual, max).is_some_and(|o| o.is_lt() || o.is_eq());
                ge_min && le_max
            }
            None => compare_versions(&actual, &expected).is_some_and(|o| o.is_gt() || o.is_eq()),
        },
        "contains cmd injection" | "contains cmd injection strictly" => contains_cmd(&actual),
        "is bot" | "common bot" => is_common_bot(&actual),
        "common ai bot" => is_ai_bot(&actual),
        "ip mod" => {
            if let Ok(actual_ip) = actual.parse::<IpAddr>() {
                let ip_num = ip_to_u128(actual_ip);
                match expected.split_once(',') {
                    Some((div, rem)) => {
                        if let (Ok(div), Ok(rem)) =
                            (div.trim().parse::<u128>(), rem.trim().parse::<u128>())
                        {
                            div != 0 && ip_num % div == rem
                        } else {
                            false
                        }
                    }
                    None => expected
                        .trim()
                        .parse::<u128>()
                        .ok()
                        .is_some_and(|rem| ip_num % 10 == rem),
                }
            } else {
                false
            }
        }
        "ip mod 10" => actual
            .parse::<IpAddr>()
            .ok()
            .map(ip_to_u128)
            .zip(expected.trim().parse::<u128>().ok())
            .is_some_and(|(ip_num, rem)| ip_num % 10 == rem),
        "ip mod 100" => actual
            .parse::<IpAddr>()
            .ok()
            .map(ip_to_u128)
            .zip(expected.trim().parse::<u128>().ok())
            .is_some_and(|(ip_num, rem)| ip_num % 100 == rem),
        _ => false,
    }
}

fn compare_ip_bytes(left: IpAddr, right: IpAddr) -> std::cmp::Ordering {
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        (IpAddr::V4(left), IpAddr::V6(right)) => {
            left.octets().as_slice().cmp(right.octets().as_slice())
        }
        (IpAddr::V6(left), IpAddr::V4(right)) => {
            left.octets().as_slice().cmp(right.octets().as_slice())
        }
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
    }
}

fn normalize_operator(operator: &str) -> Cow<'_, str> {
    let operator = operator.trim();
    if operator.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(operator.to_ascii_lowercase())
    } else {
        Cow::Borrowed(operator)
    }
}

fn split_terms(expected: &str) -> impl Iterator<Item = &str> {
    expected.lines().map(str::trim).filter(|s| !s.is_empty())
}

fn contains_word(actual: &str, term: &str) -> bool {
    if term
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return actual.contains(term);
    }

    let pattern = format!(r"\b{}\b", regex::escape(term));
    get_or_compile_regex(&pattern)
        .map(|re| re.is_match(actual))
        .unwrap_or_else(|| actual.contains(term))
}

pub(crate) fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    let value = value.as_bytes();
    let needle = needle.as_bytes();
    !needle.is_empty()
        && value.len() >= needle.len()
        && value
            .windows(needle.len())
            .any(|part| part.eq_ignore_ascii_case(needle))
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .ok()
}

fn compare_versions(actual: &str, expected: &str) -> Option<std::cmp::Ordering> {
    let left = parse_version(actual)?;
    let right = parse_version(expected)?;
    Some(left.cmp(&right))
}

fn parse_version(input: &str) -> Option<Vec<u64>> {
    let mut parts = Vec::new();
    for piece in input.split(['.', '-', '_']) {
        if piece.is_empty() {
            continue;
        }
        let digits: String = piece.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        parts.push(digits.parse().ok()?);
    }
    if parts.is_empty() { None } else { Some(parts) }
}

fn is_common_bot(ua: &str) -> bool {
    let bots = [
        "googlebot",
        "google-inspectiontool",
        "bingbot",
        "baiduspider",
        "yandexbot",
        "bytespider",
        "duckduckbot",
        "semrushbot",
        "ahrefsbot",
        "applebot",
        "facebookexternalhit",
        "twitterbot",
        "linkedinbot",
    ];
    bots.iter()
        .any(|bot| contains_ascii_case_insensitive(ua, bot))
}

fn is_ai_bot(ua: &str) -> bool {
    let bots = [
        "gptbot",
        "chatgpt-user",
        "openai",
        "oai-searchbot",
        "chatgpt-user",
        "claudebot",
        "claude-web",
        "anthropic-ai",
        "perplexitybot",
        "perplexity-user",
        "ccbot",
        "amazonbot",
        "bytespider",
        "cohere-ai",
        "meta-externalagent",
        "meta-externalfetcher",
        "imagesiftbot",
        "youbot",
        "mistralai-user",
        "omgilibot",
        "diffbot",
        "phindbot",
    ];
    bots.iter()
        .any(|bot| contains_ascii_case_insensitive(ua, bot))
}

/// Get or compile a regex from cache — avoids per-request regex compilation.
///
/// On a miss the compile is attempted once per pattern; if compilation fails
/// we deliberately do not poison the cache, so a transient regex error in one
/// request never punishes future ones.
#[inline]
fn get_or_compile_regex(pattern: &str) -> Option<Arc<Regex>> {
    // Fast path: avoid allocating an owned String on every hit.
    if let Some(cached) = WAF_RE_CACHE.get(pattern) {
        return Some(cached);
    }
    // Slow path: try_get_with deduplicates concurrent compilations of the
    // same pattern (other waiters get the same Arc<Regex> without re-running
    // RegexBuilder), and only inserts when compilation succeeds. Failures
    // return Err and don't pollute the cache.
    WAF_RE_CACHE
        .try_get_with(pattern.to_string(), || {
            RegexBuilder::new(pattern)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map(Arc::new)
        })
        .ok()
}

#[inline]
fn get_or_compile_bytes_regex(
    pattern: &str,
    case_insensitive: bool,
) -> Option<Arc<regex::bytes::Regex>> {
    let cache_key = if case_insensitive {
        format!("i:{pattern}")
    } else {
        format!("s:{pattern}")
    };
    if let Some(cached) = WAF_BYTES_RE_CACHE.get(&cache_key) {
        return Some(cached);
    }
    WAF_BYTES_RE_CACHE
        .try_get_with(cache_key, || {
            regex::bytes::RegexBuilder::new(pattern)
                .case_insensitive(case_insensitive)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map(Arc::new)
        })
        .ok()
}

/// Evaluate a WAF operator against raw body bytes.
/// Only the operators meaningful on binary/body data are handled; all others
/// fall back to the lossy-string path so callers do not need to special-case
/// operators that are inherently text-only.
pub(crate) fn evaluate_operator_bytes(
    body: &[u8],
    operator: &str,
    expected_value: &str,
    case_insensitive: bool,
) -> bool {
    let operator_lower = normalize_operator(operator);
    let pattern_bytes: Cow<'_, [u8]> = if case_insensitive {
        Cow::Owned(expected_value.to_ascii_lowercase().into_bytes())
    } else {
        Cow::Borrowed(expected_value.as_bytes())
    };
    let subject: Cow<'_, [u8]> = if case_insensitive {
        Cow::Owned(body.iter().map(|b| b.to_ascii_lowercase()).collect())
    } else {
        Cow::Borrowed(body)
    };

    match operator_lower.as_ref() {
        "match" | "matches" | "regexp" => {
            get_or_compile_bytes_regex(expected_value, case_insensitive)
                .map_or(false, |re| re.is_match(body))
        }
        "not match" | "notmatches" | "notregexp" => {
            get_or_compile_bytes_regex(expected_value, case_insensitive)
                .map_or(false, |re| !re.is_match(body))
        }
        "wildcard match" => {
            let escaped = regex::escape(expected_value).replace("\\*", ".*");
            let re_str = format!("^{}$", escaped);
            get_or_compile_bytes_regex(&re_str, case_insensitive)
                .map_or(false, |re| re.is_match(body))
        }
        "wildcard not match" => {
            let escaped = regex::escape(expected_value).replace("\\*", ".*");
            let re_str = format!("^{}$", escaped);
            get_or_compile_bytes_regex(&re_str, case_insensitive)
                .map_or(false, |re| !re.is_match(body))
        }
        "contains" | "containsstring" => {
            if pattern_bytes.is_empty() {
                true
            } else {
                subject
                    .windows(pattern_bytes.len())
                    .any(|w| w == pattern_bytes.as_ref())
            }
        }
        "not contains" | "notcontains" => {
            if pattern_bytes.is_empty() {
                false
            } else {
                !subject
                    .windows(pattern_bytes.len())
                    .any(|w| w == pattern_bytes.as_ref())
            }
        }
        "contains binary" => decode_base64(expected_value)
            .map(|needle| !needle.is_empty() && body.windows(needle.len()).any(|w| w == needle))
            .unwrap_or(false),
        "not contains binary" => decode_base64(expected_value)
            .map(|needle| needle.is_empty() || !body.windows(needle.len()).any(|w| w == needle))
            .unwrap_or(false),
        "contains sql injection" | "contains sql injection strictly" => {
            let strict = operator_lower.contains("strictly");
            if let Ok(s) = std::str::from_utf8(body) {
                contains_sqli(s, strict)
            } else {
                libinjectionrs::detect_sqli(body).is_injection()
            }
        }
        "contains xss" | "contains xss strictly" => {
            let strict = operator_lower.contains("strictly");
            if let Ok(s) = std::str::from_utf8(body) {
                contains_xss(s, strict)
            } else {
                libinjectionrs::detect_xss(body).is_injection()
            }
        }
        "contains cmd injection" | "contains cmd injection strictly" => {
            if let Ok(s) = std::str::from_utf8(body) {
                contains_cmd(s)
            } else {
                false
            }
        }
        _ => {
            let lossy = String::from_utf8_lossy(body);
            evaluate_operator(&lossy, operator, expected_value, case_insensitive)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waf_regex_cache_evicts_beyond_max_entries() {
        for i in 0..(WAF_RE_CACHE_MAX_ENTRIES + 128) {
            let pattern = format!("^waf-cache-evict-{i}$");
            assert!(evaluate_operator(
                &format!("waf-cache-evict-{i}"),
                "regexp",
                &pattern,
                false
            ));
        }
        assert!(
            WAF_RE_CACHE.entry_count() <= WAF_RE_CACHE_MAX_ENTRIES,
            "WAF regex cache must stay at or below {WAF_RE_CACHE_MAX_ENTRIES} entries, got {}",
            WAF_RE_CACHE.entry_count()
        );
    }

    #[test]
    fn waf_bytes_regex_cache_evicts_beyond_max_entries() {
        for i in 0..(WAF_RE_CACHE_MAX_ENTRIES + 64) {
            let pattern = format!("^waf-bytes-evict-{i}$");
            let value = format!("waf-bytes-evict-{i}");
            assert!(evaluate_operator_bytes(
                value.as_bytes(),
                "regexp",
                &pattern,
                false,
            ));
        }
        assert!(
            WAF_BYTES_RE_CACHE.entry_count() <= WAF_RE_CACHE_MAX_ENTRIES,
            "WAF bytes regex cache must stay bounded, got {}",
            WAF_BYTES_RE_CACHE.entry_count()
        );
    }

    #[test]
    fn waf_regex_compile_failures_do_not_poison_cache() {
        assert!(!evaluate_operator("value", "regexp", "(?", false));
        assert!(!evaluate_operator("value", "regexp", "(?", false));
        assert!(evaluate_operator("abc", "regexp", "^abc$", false));
    }
}
