/// PROXY Protocol v1 / v2 helpers.
///
/// Reference: <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config_models::ProxyProtocolConfig;

/// Minimum bytes that let us decide whether a PROXY header is present at all.
/// We need at least 6 bytes for v1 ("PROXY ") and exactly 12 for the v2 signature.
pub const PROXY_HEADER_PEEK_LEN: usize = 16;

/// Result of a successful parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAddr {
    /// True client IP as reported by the upstream proxy.
    pub src_ip: Option<IpAddr>,
    /// True client port.
    pub src_port: Option<u16>,
    /// Number of bytes consumed from the front of `buf` by the PROXY header.
    pub consumed: usize,
}

/// Trust inbound PROXY Protocol only from the same boundary used for
/// forwarded-for style HTTP headers: loopback, private, or link-local peers.
///
/// A public client can forge a syntactically valid PROXY header, so callers may
/// consume the header for compatibility but must not replace the real socket IP
/// unless the immediate peer is trusted.
pub fn trusted_inbound_source(peer_ip: &IpAddr) -> bool {
    match peer_ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_private() || v4.is_loopback() || v4.is_link_local();
            }
            if v6.is_loopback() {
                return true;
            }
            let octets = v6.octets();
            (octets[0] & 0xfe) == 0xfc || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        }
    }
}

pub fn effective_client_addr(peer_addr: SocketAddr, parsed: &ProxyAddr) -> SocketAddr {
    if !trusted_inbound_source(&peer_addr.ip()) {
        return peer_addr;
    }
    match (parsed.src_ip, parsed.src_port) {
        (Some(ip), Some(port)) => SocketAddr::new(ip, port),
        _ => peer_addr,
    }
}

/// Errors produced by the parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocolError {
    /// The buffer does not start with a recognised PROXY signature — treat
    /// the connection as a normal (non-proxied) stream.
    NotProxyProtocol,
    /// A PROXY header was detected but the buffer is too short to contain it
    /// in full; the caller should read more data and retry.
    Incomplete,
    /// The header was detected and complete but contains invalid data.
    Invalid(String),
}

impl std::fmt::Display for ProxyProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotProxyProtocol => write!(f, "not a PROXY protocol header"),
            Self::Incomplete => write!(f, "PROXY header incomplete"),
            Self::Invalid(msg) => write!(f, "invalid PROXY header: {}", msg),
        }
    }
}

impl std::error::Error for ProxyProtocolError {}

/// Parse a PROXY Protocol v1 or v2 header from the front of `buf`.
///
/// Returns `Ok(ProxyAddr)` if a valid header is found, with `consumed` set to
/// the number of bytes that belong to the header so the caller can skip past
/// them.  Returns `Err(NotProxyProtocol)` when the bytes clearly do not start
/// with a PROXY header so the connection can proceed normally.
pub fn parse_proxy_v1_v2(buf: &[u8]) -> Result<ProxyAddr, ProxyProtocolError> {
    if buf.len() < 2 {
        // Not enough bytes to distinguish — report NotProxyProtocol so the
        // caller falls back to plain processing.
        return Err(ProxyProtocolError::NotProxyProtocol);
    }

    // v2: binary signature \r\n\r\n\0\r\nQUIT\n (12 bytes)
    const V2_SIG: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
    if buf.len() >= 12 && &buf[..12] == V2_SIG {
        return parse_v2(buf);
    }

    // v1: text signature "PROXY "
    if buf.len() >= 6 && &buf[..6] == b"PROXY " {
        return parse_v1(buf);
    }

    Err(ProxyProtocolError::NotProxyProtocol)
}

/// Build a PROXY Protocol v1 header for forwarding the downstream client
/// address to an origin server.
pub fn build_v1_header(client_addr: SocketAddr, destination_addr: Option<SocketAddr>) -> Vec<u8> {
    let family = match client_addr {
        SocketAddr::V4(_) => "TCP4",
        SocketAddr::V6(_) => "TCP6",
    };
    let dst_ip = destination_addr
        .map(|addr| addr.ip())
        .unwrap_or_else(|| match client_addr {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        });
    let dst_port = destination_addr.map(|addr| addr.port()).unwrap_or(0);
    format!(
        "PROXY {} {} {} {} {}\r\n",
        family,
        client_addr.ip(),
        dst_ip,
        client_addr.port(),
        dst_port
    )
    .into_bytes()
}

/// Build the configured PROXY Protocol header for forwarding the downstream
/// client address to an origin server.
pub fn build_header(
    config: ProxyProtocolConfig,
    client_addr: SocketAddr,
    destination_addr: Option<SocketAddr>,
) -> Option<Vec<u8>> {
    if !config.enabled() {
        return None;
    }
    Some(match config.normalized_version() {
        2 => build_v2_header(client_addr, destination_addr),
        _ => build_v1_header(client_addr, destination_addr),
    })
}

/// Build a PROXY Protocol v2 header for forwarding the downstream client
/// address to an origin server.
pub fn build_v2_header(client_addr: SocketAddr, destination_addr: Option<SocketAddr>) -> Vec<u8> {
    let mut header = Vec::with_capacity(52);
    header.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    header.push(0x21); // version=2, command=PROXY

    match client_addr {
        SocketAddr::V4(client) => {
            let destination = match destination_addr {
                Some(SocketAddr::V4(addr)) => *addr.ip(),
                _ => Ipv4Addr::UNSPECIFIED,
            };
            header.push(0x11); // AF_INET + STREAM
            header.extend_from_slice(&12u16.to_be_bytes());
            header.extend_from_slice(&client.ip().octets());
            header.extend_from_slice(&destination.octets());
            header.extend_from_slice(&client.port().to_be_bytes());
            header.extend_from_slice(
                &destination_addr
                    .map(|addr| addr.port())
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
        }
        SocketAddr::V6(client) => {
            let destination = match destination_addr {
                Some(SocketAddr::V6(addr)) => *addr.ip(),
                _ => Ipv6Addr::UNSPECIFIED,
            };
            header.push(0x21); // AF_INET6 + STREAM
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&client.ip().octets());
            header.extend_from_slice(&destination.octets());
            header.extend_from_slice(&client.port().to_be_bytes());
            header.extend_from_slice(
                &destination_addr
                    .map(|addr| addr.port())
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
        }
    }
    header
}

// ---------------------------------------------------------------------------
// v1 parser
// ---------------------------------------------------------------------------

fn parse_v1(buf: &[u8]) -> Result<ProxyAddr, ProxyProtocolError> {
    // Find the terminating \r\n
    let end = match buf.windows(2).position(|w| w == b"\r\n") {
        Some(pos) => pos,
        None => {
            if buf.len() > 108 {
                // v1 header must fit in 108 bytes per spec
                return Err(ProxyProtocolError::Invalid(
                    "v1 header exceeds 108 bytes without CRLF".into(),
                ));
            }
            return Err(ProxyProtocolError::Incomplete);
        }
    };

    let line = std::str::from_utf8(&buf[..end])
        .map_err(|_| ProxyProtocolError::Invalid("non-UTF8 v1 header".into()))?;

    // Format: "PROXY <INET_PROTO> <SRC_ADDR> <DST_ADDR> <SRC_PORT> <DST_PORT>"
    // or:     "PROXY UNKNOWN ..."
    let mut parts = line.split_ascii_whitespace();

    // "PROXY"
    parts.next(); // already verified above

    let proto = parts
        .next()
        .ok_or_else(|| ProxyProtocolError::Invalid("missing protocol field".into()))?;

    if proto.eq_ignore_ascii_case("UNKNOWN") {
        // Per spec: must be accepted and consumed; source address is undefined,
        // so callers should keep the original socket address.
        return Ok(ProxyAddr {
            src_ip: None,
            src_port: None,
            consumed: end + 2,
        });
    }

    let is_tcp4 = proto.eq_ignore_ascii_case("TCP4");
    let is_tcp6 = proto.eq_ignore_ascii_case("TCP6");
    if !is_tcp4 && !is_tcp6 {
        return Err(ProxyProtocolError::Invalid(format!(
            "unknown v1 protocol '{}'",
            proto
        )));
    }

    let src_addr_str = parts
        .next()
        .ok_or_else(|| ProxyProtocolError::Invalid("missing src addr".into()))?;
    let _dst_addr_str = parts
        .next()
        .ok_or_else(|| ProxyProtocolError::Invalid("missing dst addr".into()))?;
    let src_port_str = parts
        .next()
        .ok_or_else(|| ProxyProtocolError::Invalid("missing src port".into()))?;

    let src_ip: IpAddr = if is_tcp4 {
        src_addr_str
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|_| {
                ProxyProtocolError::Invalid(format!("invalid IPv4 addr '{}'", src_addr_str))
            })?
    } else {
        src_addr_str
            .parse::<Ipv6Addr>()
            .map(IpAddr::V6)
            .map_err(|_| {
                ProxyProtocolError::Invalid(format!("invalid IPv6 addr '{}'", src_addr_str))
            })?
    };

    let src_port: u16 = src_port_str
        .parse()
        .map_err(|_| ProxyProtocolError::Invalid(format!("invalid src port '{}'", src_port_str)))?;

    Ok(ProxyAddr {
        src_ip: Some(src_ip),
        src_port: Some(src_port),
        consumed: end + 2, // include the trailing \r\n
    })
}

// ---------------------------------------------------------------------------
// v2 parser
// ---------------------------------------------------------------------------

// v2 signature is 12 bytes, followed by 4 bytes of header:
//   [12]  version_command (high nibble = version=2, low nibble = command)
//   [13]  family (high nibble = addr_family, low nibble = transport)
//   [14-15] additional length (big-endian u16)
const V2_HEADER_LEN: usize = 16; // signature(12) + version_command(1) + family(1) + length(2)

fn parse_v2(buf: &[u8]) -> Result<ProxyAddr, ProxyProtocolError> {
    if buf.len() < V2_HEADER_LEN {
        return Err(ProxyProtocolError::Incomplete);
    }

    let version_command = buf[12];
    let version = (version_command >> 4) & 0x0f;
    let command = version_command & 0x0f;

    if version != 2 {
        return Err(ProxyProtocolError::Invalid(format!(
            "unexpected v2 version {}",
            version
        )));
    }

    // command: 0=LOCAL, 1=PROXY
    if command == 0 {
        // LOCAL command: ignore addresses, consume the header
        let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        let total = V2_HEADER_LEN + addr_len;
        if buf.len() < total {
            return Err(ProxyProtocolError::Incomplete);
        }
        return Ok(ProxyAddr {
            src_ip: None,
            src_port: None,
            consumed: total,
        });
    }
    if command != 1 {
        return Err(ProxyProtocolError::Invalid(format!(
            "unknown v2 command {}",
            command
        )));
    }

    let family_byte = buf[13];
    let addr_family = (family_byte >> 4) & 0x0f;
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total = V2_HEADER_LEN + addr_len;
    if buf.len() < total {
        return Err(ProxyProtocolError::Incomplete);
    }
    if addr_family == 0 {
        return Ok(ProxyAddr {
            src_ip: None,
            src_port: None,
            consumed: total,
        });
    }
    let transport = family_byte & 0x0f;
    if transport != 1 {
        return Err(ProxyProtocolError::Invalid(format!(
            "unsupported v2 transport {}",
            transport
        )));
    }

    let addr_data = &buf[V2_HEADER_LEN..total];

    match addr_family {
        1 => {
            // AF_INET: src(4) + dst(4) + src_port(2) + dst_port(2) = 12 bytes
            if addr_data.len() < 12 {
                return Err(ProxyProtocolError::Invalid(
                    "AF_INET addr block too short".into(),
                ));
            }
            let src_ip = IpAddr::V4(Ipv4Addr::new(
                addr_data[0],
                addr_data[1],
                addr_data[2],
                addr_data[3],
            ));
            let src_port = u16::from_be_bytes([addr_data[8], addr_data[9]]);
            Ok(ProxyAddr {
                src_ip: Some(src_ip),
                src_port: Some(src_port),
                consumed: total,
            })
        }
        2 => {
            // AF_INET6: src(16) + dst(16) + src_port(2) + dst_port(2) = 36 bytes
            if addr_data.len() < 36 {
                return Err(ProxyProtocolError::Invalid(
                    "AF_INET6 addr block too short".into(),
                ));
            }
            let mut src_octets = [0u8; 16];
            src_octets.copy_from_slice(&addr_data[..16]);
            let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets));
            let src_port = u16::from_be_bytes([addr_data[32], addr_data[33]]);
            Ok(ProxyAddr {
                src_ip: Some(src_ip),
                src_port: Some(src_port),
                consumed: total,
            })
        }
        _ => Err(ProxyProtocolError::Invalid(format!(
            "unknown v2 addr family {}",
            addr_family
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- v1 tests ---

    #[test]
    fn v1_tcp4_basic() {
        let hdr = b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 80\r\n";
        let result = parse_proxy_v1_v2(hdr).unwrap();
        assert_eq!(result.src_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(result.src_port, Some(12345));
        assert_eq!(result.consumed, hdr.len());
    }

    #[test]
    fn v1_tcp6_basic() {
        let hdr = b"PROXY TCP6 ::1 ::2 54321 443\r\n";
        let result = parse_proxy_v1_v2(hdr).unwrap();
        assert_eq!(
            result.src_ip,
            Some(IpAddr::V6("::1".parse::<Ipv6Addr>().unwrap()))
        );
        assert_eq!(result.src_port, Some(54321));
        assert_eq!(result.consumed, hdr.len());
    }

    #[test]
    fn v1_unknown_returns_not_proxy() {
        let hdr = b"PROXY UNKNOWN 1.2.3.4 5.6.7.8 100 200\r\n";
        let result = parse_proxy_v1_v2(hdr).unwrap();
        assert_eq!(result.src_ip, None);
        assert_eq!(result.src_port, None);
        assert_eq!(result.consumed, hdr.len());
    }

    #[test]
    fn v1_incomplete_no_crlf() {
        let hdr = b"PROXY TCP4 1.2.3.4 5.6.7.8 12345 80";
        assert_eq!(parse_proxy_v1_v2(hdr), Err(ProxyProtocolError::Incomplete));
    }

    #[test]
    fn v1_with_trailing_http_data() {
        let data = b"PROXY TCP4 10.0.0.1 10.0.0.2 1000 80\r\nGET / HTTP/1.1\r\n".to_vec();
        let result = parse_proxy_v1_v2(&data).unwrap();
        assert_eq!(result.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(result.src_port, Some(1000));
        // consumed only covers the PROXY header
        let proxy_hdr_bytes = b"PROXY TCP4 10.0.0.1 10.0.0.2 1000 80\r\n";
        assert_eq!(result.consumed, proxy_hdr_bytes.len());
        // remaining bytes are the HTTP request
        assert_eq!(&data[result.consumed..], b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn build_v1_tcp4_header() {
        let client = "1.2.3.4:12345".parse().unwrap();
        let destination = "5.6.7.8:443".parse().unwrap();
        assert_eq!(
            String::from_utf8(build_v1_header(client, Some(destination))).unwrap(),
            "PROXY TCP4 1.2.3.4 5.6.7.8 12345 443\r\n"
        );
    }

    #[test]
    fn build_v1_tcp6_header() {
        let client = "[2001:db8::1]:12345".parse().unwrap();
        let destination = "[2001:db8::2]:443".parse().unwrap();
        assert_eq!(
            String::from_utf8(build_v1_header(client, Some(destination))).unwrap(),
            "PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n"
        );
    }

    #[test]
    fn build_v2_tcp4_header() {
        let client = "1.2.3.4:12345".parse().unwrap();
        let destination = "5.6.7.8:443".parse().unwrap();
        let header = build_v2_header(client, Some(destination));

        assert_eq!(&header[..12], b"\r\n\r\n\x00\r\nQUIT\n");
        assert_eq!(header[12], 0x21);
        assert_eq!(header[13], 0x11);
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 12);

        let parsed = parse_proxy_v1_v2(&header).unwrap();
        assert_eq!(parsed.src_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert_eq!(parsed.src_port, Some(12345));
        assert_eq!(parsed.consumed, header.len());
    }

    #[test]
    fn configured_build_header_uses_v2() {
        let client = "1.2.3.4:12345".parse().unwrap();
        let destination = "5.6.7.8:443".parse().unwrap();
        let header = build_header(
            ProxyProtocolConfig {
                is_on: true,
                version: 2,
            },
            client,
            Some(destination),
        )
        .expect("enabled proxy protocol should build a header");

        assert_eq!(&header[..12], b"\r\n\r\n\x00\r\nQUIT\n");
        assert_eq!(parse_proxy_v1_v2(&header).unwrap().src_port, Some(12345));
    }

    #[test]
    fn inbound_proxy_header_only_replaces_addr_from_trusted_peer() {
        let hdr = b"PROXY TCP4 198.51.100.10 10.0.0.2 12345 443\r\n";
        let parsed = parse_proxy_v1_v2(hdr).unwrap();
        let peer: SocketAddr = "10.0.0.9:55000".parse().unwrap();

        assert!(trusted_inbound_source(&peer.ip()));
        assert_eq!(
            effective_client_addr(peer, &parsed),
            "198.51.100.10:12345".parse().unwrap()
        );
    }

    #[test]
    fn inbound_proxy_header_from_public_peer_keeps_socket_addr() {
        let hdr = b"PROXY TCP4 10.0.0.10 10.0.0.2 12345 443\r\n";
        let parsed = parse_proxy_v1_v2(hdr).unwrap();
        let peer: SocketAddr = "198.51.100.9:55000".parse().unwrap();

        assert!(!trusted_inbound_source(&peer.ip()));
        assert_eq!(effective_client_addr(peer, &parsed), peer);
    }

    #[test]
    fn non_proxy_http_returns_not_proxy() {
        assert_eq!(
            parse_proxy_v1_v2(b"GET / HTTP/1.1\r\n"),
            Err(ProxyProtocolError::NotProxyProtocol)
        );
    }

    #[test]
    fn too_short_returns_not_proxy() {
        assert_eq!(
            parse_proxy_v1_v2(b"P"),
            Err(ProxyProtocolError::NotProxyProtocol)
        );
    }

    // --- v2 tests ---

    fn build_v2_ipv4(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n"); // signature
        hdr.push(0x21); // version=2, command=PROXY
        hdr.push(0x11); // AF_INET, TCP
        hdr.extend_from_slice(&12u16.to_be_bytes()); // addr block length
        hdr.extend_from_slice(&src.octets());
        hdr.extend_from_slice(&dst.octets());
        hdr.extend_from_slice(&src_port.to_be_bytes());
        hdr.extend_from_slice(&dst_port.to_be_bytes());
        hdr
    }

    fn build_v2_ipv6(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        hdr.push(0x21); // version=2, command=PROXY
        hdr.push(0x21); // AF_INET6, TCP
        hdr.extend_from_slice(&36u16.to_be_bytes());
        hdr.extend_from_slice(&src.octets());
        hdr.extend_from_slice(&dst.octets());
        hdr.extend_from_slice(&src_port.to_be_bytes());
        hdr.extend_from_slice(&dst_port.to_be_bytes());
        hdr
    }

    #[test]
    fn v2_ipv4_basic() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let data = build_v2_ipv4(src, dst, 55000, 443);
        let result = parse_proxy_v1_v2(&data).unwrap();
        assert_eq!(result.src_ip, Some(IpAddr::V4(src)));
        assert_eq!(result.src_port, Some(55000));
        assert_eq!(result.consumed, data.len());
    }

    #[test]
    fn v2_ipv6_basic() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "::1".parse().unwrap();
        let data = build_v2_ipv6(src, dst, 33333, 80);
        let result = parse_proxy_v1_v2(&data).unwrap();
        assert_eq!(result.src_ip, Some(IpAddr::V6(src)));
        assert_eq!(result.src_port, Some(33333));
        assert_eq!(result.consumed, data.len());
    }

    #[test]
    fn v2_local_command_returns_not_proxy() {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
        hdr.push(0x20); // version=2, command=LOCAL
        hdr.push(0x00); // AF_UNSPEC
        hdr.extend_from_slice(&0u16.to_be_bytes());
        let result = parse_proxy_v1_v2(&hdr).unwrap();
        assert_eq!(result.src_ip, None);
        assert_eq!(result.src_port, None);
        assert_eq!(result.consumed, hdr.len());
    }

    #[test]
    fn v2_incomplete_returns_incomplete() {
        // Only the 12-byte signature, missing the 4 fixed header bytes
        let sig = b"\r\n\r\n\x00\r\nQUIT\n";
        assert_eq!(parse_proxy_v1_v2(sig), Err(ProxyProtocolError::Incomplete));
    }

    #[test]
    fn v2_with_trailing_payload() {
        let src = Ipv4Addr::new(1, 2, 3, 4);
        let dst = Ipv4Addr::new(5, 6, 7, 8);
        let mut data = build_v2_ipv4(src, dst, 9999, 80);
        let hdr_len = data.len();
        data.extend_from_slice(b"some payload bytes");
        let result = parse_proxy_v1_v2(&data).unwrap();
        assert_eq!(result.src_port, Some(9999));
        assert_eq!(result.consumed, hdr_len);
    }
}
