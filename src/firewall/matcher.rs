use once_cell::sync::Lazy;
use regex::Regex;
use std::net::IpAddr;

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

pub fn evaluate_operator(
    actual_value: &str,
    operator: &str,
    expected_value: &str,
    case_insensitive: bool,
) -> bool {
    let mut actual = actual_value.to_string();
    let mut expected = expected_value.to_string();

    if case_insensitive {
        actual = actual.to_lowercase();
        expected = expected.to_lowercase();
    }

    match operator.trim().to_ascii_lowercase().as_str() {
        "eq string" => actual == expected,
        "neq string" => actual != expected,
        "match" | "matches" | "regexp" => {
            if let Ok(re) = Regex::new(&expected) {
                re.is_match(&actual)
            } else {
                false
            }
        }
        "not match" | "notmatches" | "notregexp" => {
            if let Ok(re) = Regex::new(&expected) {
                !re.is_match(&actual)
            } else {
                false
            }
        }
        "wildcard match" => {
            // simplistic wildcard to regex conversion: * -> .*
            let escaped = regex::escape(&expected).replace("\\*", ".*");
            if let Ok(re) = Regex::new(&format!("^{}$", escaped)) {
                re.is_match(&actual)
            } else {
                false
            }
        }
        "wildcard not match" => {
            let escaped = regex::escape(&expected).replace("\\*", ".*");
            if let Ok(re) = Regex::new(&format!("^{}$", escaped)) {
                !re.is_match(&actual)
            } else {
                false
            }
        }
        "contains" | "containsstring" => actual.contains(&expected),
        "not contains" | "notcontains" => !actual.contains(&expected),
        "prefix" | "hasprefix" => actual.starts_with(&expected),
        "suffix" | "hassuffix" => actual.ends_with(&expected),
        "contains any" => {
            let lines: Vec<&str> = expected.lines().collect();
            lines.into_iter().any(|line| actual.contains(line))
        }
        "contains all" => {
            let lines: Vec<&str> = expected.lines().collect();
            lines.into_iter().all(|line| actual.contains(line))
        }
        "contains any word" => split_terms(&expected)
            .iter()
            .any(|term| contains_word(&actual, term)),
        "contains all words" => split_terms(&expected)
            .iter()
            .all(|term| contains_word(&actual, term)),
        "not contains any word" => !split_terms(&expected)
            .iter()
            .any(|term| contains_word(&actual, term)),
        "eq" | "neq" | "gt" | "gte" | "lt" | "lte" => {
            // number comparisons
            if let (Ok(a), Ok(e)) = (actual.parse::<f64>(), expected.parse::<f64>()) {
                match operator.trim().to_ascii_lowercase().as_str() {
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
            if operator == "ip range" {
                matched
            } else {
                !matched
            }
        }
        "gt ip" | "gte ip" | "lt ip" | "lte ip" => {
            if let (Ok(actual_ip), Ok(expected_ip)) =
                (actual.parse::<IpAddr>(), expected.parse::<IpAddr>())
            {
                let ordering = ip_to_bytes(actual_ip).cmp(&ip_to_bytes(expected_ip));
                match operator.trim().to_ascii_lowercase().as_str() {
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
            let is_strict = operator.contains("strictly");
            let mut matched = RE_SQLI.is_match(&actual.to_lowercase());
            if !matched && is_strict {
                matched = RE_SQLI_STRICT.is_match(&actual.to_lowercase());
            }
            matched
        }
        "contains xss" | "contains xss strictly" => {
            let is_strict = operator.contains("strictly");
            let mut matched = RE_XSS.is_match(&actual.to_lowercase());
            if !matched && is_strict {
                matched = RE_XSS_STRICT.is_match(&actual.to_lowercase());
            }
            matched
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
        "contains cmd injection" | "contains cmd injection strictly" => {
            let cmd_keywords = vec![
                "/bin/sh",
                "/bin/bash",
                "cmd.exe",
                "powershell",
                "curl ",
                "wget ",
            ];
            cmd_keywords
                .iter()
                .any(|keyword| actual.to_lowercase().contains(keyword))
        }
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

fn ip_to_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
    }
}

fn split_terms(expected: &str) -> Vec<String> {
    expected
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn contains_word(actual: &str, term: &str) -> bool {
    let pattern = format!(r"\b{}\b", regex::escape(term));
    Regex::new(&pattern)
        .map(|re| re.is_match(actual))
        .unwrap_or_else(|_| actual.contains(term))
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
    let ua_lower = ua.to_lowercase();
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
    bots.iter().any(|bot| ua_lower.contains(bot))
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
    let ua_lower = ua.to_lowercase();
    bots.iter().any(|bot| ua_lower.contains(bot))
}
