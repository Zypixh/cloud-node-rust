use crate::config_models::{HTTPRemoteAddrConfig, ServerConfig};
use base64::{Engine as _, engine::general_purpose};
use pingora_proxy::Session;
use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock as Lazy;

static RE_VAR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{[^}]+\}").expect("valid regex"));
static HOSTNAME: Lazy<String> = Lazy::new(|| {
    hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
});

pub fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_private() || v4.is_loopback() || v4.is_link_local();
            }
            if v6.is_loopback() {
                return true;
            }
            let octets = v6.octets();
            if (octets[0] & 0xfe) == 0xfc {
                return true;
            }
            octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
        }
    }
}

pub fn parse_candidate_ip(raw: &str) -> Option<IpAddr> {
    let mut candidate = raw.trim().trim_matches('"').trim_matches('\'');
    if candidate.is_empty() {
        return None;
    }
    if let Some(value) = candidate
        .strip_prefix("for=")
        .or_else(|| candidate.strip_prefix("For="))
    {
        candidate = value.trim();
    }
    if let Some((first, _)) = candidate.split_once(';') {
        candidate = first.trim();
    }
    if let Some((first, _)) = candidate.split_once(',') {
        candidate = first.trim();
    }
    let candidate = candidate.trim_matches(|c| c == '[' || c == ']');
    candidate.parse().ok()
}

pub fn header_value_ci<'a>(session: &'a Session, name: &str) -> Option<&'a str> {
    session
        .get_header(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub fn peer_socket_ip(session: &Session) -> IpAddr {
    canonicalize_ip(
        session
            .downstream_session
            .digest()
            .and_then(|d| d.socket_digest.as_ref())
            .and_then(|sd| sd.peer_addr())
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip())
            .or_else(|| {
                session.client_addr().and_then(|addr| match addr {
                    pingora_core::protocols::l4::socket::SocketAddr::Inet(addr) => Some(addr.ip()),
                    _ => None,
                })
            })
            .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1])),
    )
}

pub fn raw_remote_addr(session: &Session) -> String {
    session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.peer_addr())
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.ip().to_string())
        .or_else(|| {
            session.client_addr().and_then(|addr| match addr {
                pingora_core::protocols::l4::socket::SocketAddr::Inet(addr) => {
                    Some(addr.ip().to_string())
                }
                _ => None,
            })
        })
        .unwrap_or_else(|| IpAddr::from([127, 0, 0, 1]).to_string())
}

pub fn peer_remote_port(session: &Session) -> u16 {
    session
        .downstream_session
        .digest()
        .and_then(|d| d.socket_digest.as_ref())
        .and_then(|sd| sd.peer_addr())
        .and_then(|addr| addr.as_inet())
        .map(|inet| inet.port())
        .unwrap_or(0)
}

pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

pub fn fallback_client_ip(session: &Session, raw_ip: IpAddr) -> IpAddr {
    if !is_local_ip(&raw_ip) {
        return raw_ip;
    }
    for header in [
        "x-cloud-real-ip",
        "x-real-ip",
        "cf-connecting-ip",
        "true-client-ip",
        "x-forwarded-for",
        "x-client-ip",
        "x-original-forwarded-for",
        "x-cluster-client-ip",
        "fastly-client-ip",
        "ali-cdn-real-ip",
        "cdn-src-ip",
        "forwarded",
    ] {
        if let Some(value) = header_value_ci(session, header)
            && let Some(ip) = parse_candidate_ip(value)
        {
            return canonicalize_ip(ip);
        }
    }
    raw_ip
}

pub fn resolve_client_ip(
    session: &Session,
    server: Option<&ServerConfig>,
    raw_ip: IpAddr,
    raw_remote_addr: &str,
    remote_port: u16,
) -> IpAddr {
    if let Some(remote_addr_cfg) = server
        .and_then(|server| server.web.as_ref())
        .and_then(|web| web.remote_addr.as_ref())
        .filter(|cfg| cfg.is_on && !cfg.is_empty())
    {
        return resolve_with_remote_addr_config(
            session,
            remote_addr_cfg,
            raw_ip,
            raw_remote_addr,
            remote_port,
        );
    }
    fallback_client_ip(session, raw_ip)
}

pub fn resolve_for_session(session: &Session, server: Option<&ServerConfig>) -> IpAddr {
    resolve_client_ip(
        session,
        server,
        peer_socket_ip(session),
        &raw_remote_addr(session),
        peer_remote_port(session),
    )
}

fn resolve_with_remote_addr_config(
    session: &Session,
    remote_addr_cfg: &HTTPRemoteAddrConfig,
    raw_ip: IpAddr,
    raw_remote_addr: &str,
    remote_port: u16,
) -> IpAddr {
    if remote_addr_cfg.is_direct_type() {
        return raw_ip;
    }

    if remote_addr_cfg.is_request_header_type() {
        for header_name in remote_addr_cfg.expanded_header_names() {
            if let Some(value) = header_value_ci(session, &header_name)
                && let Some(ip) = parse_candidate_ip(value)
            {
                return canonicalize_ip(ip);
            }
        }
        return raw_ip;
    }

    for configured in remote_addr_cfg.configured_values() {
        let value = resolve_remote_addr_template(
            session,
            &configured,
            raw_ip,
            raw_remote_addr,
            remote_port,
        );
        if let Some(ip) = parse_candidate_ip(&value) {
            return canonicalize_ip(ip);
        }
    }

    raw_ip
}

fn resolve_remote_addr_template(
    session: &Session,
    template: &str,
    raw_ip: IpAddr,
    raw_remote_addr: &str,
    remote_port: u16,
) -> String {
    RE_VAR
        .replace_all(template, |caps: &regex::Captures| {
            let full = caps[0]
                .strip_prefix("${")
                .and_then(|s| s.strip_suffix('}'))
                .unwrap_or("");

            let mut parts = full.splitn(2, '|');
            let inner = parts.next().unwrap_or("").trim();
            let modifiers_str = parts.next().unwrap_or("");

            let value = resolve_remote_addr_template_var(
                session,
                inner,
                raw_ip,
                raw_remote_addr,
                remote_port,
            );

            modifiers_str
                .split('|')
                .filter(|m| !m.trim().is_empty())
                .fold(value, |v, m| apply_template_modifier(v, m.trim()))
        })
        .to_string()
}

fn resolve_remote_addr_template_var(
    session: &Session,
    inner: &str,
    raw_ip: IpAddr,
    raw_remote_addr: &str,
    remote_port: u16,
) -> String {
    if inner.eq_ignore_ascii_case("rawRemoteAddr") {
        return raw_ip.to_string();
    }
    if inner.eq_ignore_ascii_case("remoteAddr") || inner.eq_ignore_ascii_case("remoteAddrValue") {
        return fallback_client_ip(session, raw_ip).to_string();
    }
    if inner.eq_ignore_ascii_case("remotePort") {
        return remote_port.to_string();
    }
    if inner.eq_ignore_ascii_case("socketRemoteAddr") {
        return raw_remote_addr.to_string();
    }
    if inner.eq_ignore_ascii_case("host") || inner.eq_ignore_ascii_case("requestHost") {
        return session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v).to_string())
            .unwrap_or_default();
    }
    if inner.eq_ignore_ascii_case("host.first") {
        let host = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v))
            .unwrap_or("");
        return host.split('.').next().unwrap_or("").to_string();
    }
    if inner.eq_ignore_ascii_case("host.last") {
        let host = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v))
            .unwrap_or("");
        return host.split('.').last().unwrap_or("").to_string();
    }
    if inner.eq_ignore_ascii_case("node.id") {
        return crate::logging::get_numeric_node_id().to_string();
    }
    if inner.eq_ignore_ascii_case("node.name") {
        return HOSTNAME.clone();
    }
    if inner.eq_ignore_ascii_case("origin.addr") || inner.eq_ignore_ascii_case("origin.host") {
        return String::new();
    }
    if inner.eq_ignore_ascii_case("geo.country") {
        return crate::metrics::analyzer::lookup_geo(raw_ip)
            .map(|g| g.country.to_string())
            .unwrap_or_default();
    }
    if inner.eq_ignore_ascii_case("geo.province") {
        return crate::metrics::analyzer::lookup_geo(raw_ip)
            .map(|g| g.region.to_string())
            .unwrap_or_default();
    }
    if inner.eq_ignore_ascii_case("geo.city") {
        return crate::metrics::analyzer::lookup_geo(raw_ip)
            .map(|g| g.city.to_string())
            .unwrap_or_default();
    }
    if inner.eq_ignore_ascii_case("geo.isp") {
        return crate::metrics::analyzer::lookup_geo(raw_ip)
            .map(|g| g.provider.to_string())
            .unwrap_or_default();
    }
    if let Some(name) = inner
        .strip_prefix("requestHeader.")
        .or_else(|| inner.strip_prefix("header."))
        .or_else(|| inner.strip_prefix("requestHeader:"))
        .or_else(|| inner.strip_prefix("header:"))
    {
        for part in name.split(',') {
            let part = part.trim();
            if let Some(value) = header_value_ci(session, part) {
                return value.to_string();
            }
        }
        return String::new();
    }

    String::new()
}

fn apply_template_modifier(value: String, modifier: &str) -> String {
    match modifier.trim() {
        "urlEncode" => urlencoding::encode(&value).into_owned(),
        "urlDecode" => urlencoding::decode(&value)
            .map(|decoded| decoded.into_owned())
            .unwrap_or(value),
        "base64Encode" => general_purpose::STANDARD.encode(value),
        "base64Decode" => general_purpose::STANDARD
            .decode(value.as_bytes())
            .ok()
            .and_then(|decoded| String::from_utf8(decoded).ok())
            .unwrap_or_default(),
        "md5" => format!("{:x}", md5_legacy::compute(value.as_bytes())),
        "sha1" => {
            use sha1::{Digest as _, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(value.as_bytes());
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }
        "sha256" => {
            use sha2::{Digest as _, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(value.as_bytes());
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }
        "toLowerCase" => value.to_ascii_lowercase(),
        "toUpperCase" => value.to_ascii_uppercase(),
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{ServerConfig, WebConfig};

    #[test]
    fn parse_candidate_ip_handles_forwarded_for_first_hop() {
        assert_eq!(
            parse_candidate_ip("203.0.113.10, 198.51.100.2").unwrap(),
            IpAddr::from([203, 0, 113, 10])
        );
    }

    #[test]
    fn remote_addr_request_header_type_uses_configured_header() {
        let server: ServerConfig = serde_json::from_value(serde_json::json!({
            "id": 1,
            "web": {
                "remoteAddr": {
                    "isOn": true,
                    "type": "requestHeader",
                    "requestHeaderName": "X-Client-ASN-Test"
                }
            }
        }))
        .unwrap();
        let cfg = server.web.as_ref().unwrap().remote_addr.as_ref().unwrap();
        assert!(cfg.is_request_header_type());
    }

    #[test]
    fn is_local_ip_treats_private_v4_as_local() {
        assert!(is_local_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!is_local_ip(&"203.0.113.1".parse().unwrap()));
    }
}
