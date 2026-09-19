use super::*;

pub fn parse_l4_packet(frame: &[u8]) -> Option<AfXdpL4Packet> {
    let (link, l3_offset) = parse_link_meta(frame)?;
    let ethertype = link.ethertype;
    // AF_XDP RX has no checksum metadata — verify wire checksums in
    // software before the frame is trusted (see ipv4_header_checksum_ok).
    if ethertype == ETHERTYPE_IPV4 && !ipv4_header_checksum_ok(frame, l3_offset) {
        return None;
    }
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4_l4(frame, l3_offset, link),
        ETHERTYPE_IPV6 => parse_ipv6_l4(frame, l3_offset, link),
        _ => None,
    }
}

/// `interface` is `Into<Arc<str>>` so the RX path can pass an already-shared
/// name (refcount bump) while tests keep passing plain `&str` literals.
pub fn parse_proxy_frame(
    interface: impl Into<Arc<str>>,
    queue: u32,
    frame: &[u8],
) -> Option<AfXdpProxyFrame> {
    let (link, l3_offset) = parse_link_meta(frame)?;
    // Same RX integrity gate as parse_l4_packet: reject frames whose IPv4
    // header checksum is corrupt before any tuple is trusted.
    if link.ethertype == ETHERTYPE_IPV4 && !ipv4_header_checksum_ok(frame, l3_offset) {
        return None;
    }
    let protocol = transport_protocol_from_frame(frame, l3_offset, link.ethertype)?;
    let route = AfXdpRouteMeta {
        interface: interface.into(),
        queue,
        link,
    };
    match protocol {
        IP_PROTO_TCP => {
            let (_, ip_packet) = extract_ip_frame(frame)?;
            // RX integrity gate: verify the TCP checksum before any flow
            // key or session state is derived from a corrupt segment.
            let (source, destination, l4_offset) = ip_l4_span(&ip_packet)?;
            if !tcp_checksum_ok(source, destination, &ip_packet[l4_offset..]) {
                return None;
            }
            let flow = tcp_flow_key_from_ip_packet(&ip_packet)?;
            Some(AfXdpProxyFrame::Tcp {
                route,
                flow,
                ip_packet,
            })
        }
        IP_PROTO_UDP => {
            let packet = parse_l4_packet(frame)?;
            Some(AfXdpProxyFrame::Udp { route, packet })
        }
        _ => None,
    }
}

/// Locate (source, destination, l4_offset) inside a bare IP packet — the
/// TCP checksum needs the pseudo-header addresses plus the segment start,
/// which for v6 is behind the extension-header chain.
fn ip_l4_span(ip_packet: &[u8]) -> Option<(IpAddr, IpAddr, usize)> {
    match ip_packet.first()? >> 4 {
        4 => {
            let base = ip_packet.get(..IPV4_MIN_HEADER_LEN)?;
            let ihl = usize::from(base[0] & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER_LEN || ip_packet.len() < ihl {
                return None;
            }
            Some((
                IpAddr::V4(Ipv4Addr::new(base[12], base[13], base[14], base[15])),
                IpAddr::V4(Ipv4Addr::new(base[16], base[17], base[18], base[19])),
                ihl,
            ))
        }
        6 => {
            let base = ip_packet.get(..IPV6_HEADER_LEN)?;
            let source =
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&base[8..24]).ok()?));
            let destination =
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&base[24..40]).ok()?));
            let packet_end = ip_packet.len();
            let (_, l4_offset) =
                ipv6_transport_offset(ip_packet, base[6], IPV6_HEADER_LEN, packet_end)?;
            Some((source, destination, l4_offset))
        }
        _ => None,
    }
}

pub fn extract_ip_frame(frame: &[u8]) -> Option<(AfXdpLinkMeta, Bytes)> {
    let (link, l3_offset) = parse_link_meta(frame)?;
    let ip_end = match link.ethertype {
        ETHERTYPE_IPV4 => ipv4_packet_end(frame, l3_offset)?,
        ETHERTYPE_IPV6 => ipv6_packet_end(frame, l3_offset)?,
        _ => return None,
    };
    Some((link, Bytes::copy_from_slice(&frame[l3_offset..ip_end])))
}

pub fn encode_ip_reply_frame(
    link: &AfXdpLinkMeta,
    ip_packet: &[u8],
    out: &mut Vec<u8>,
) -> Option<()> {
    let ethertype = match ip_packet.first()? >> 4 {
        4 => ETHERTYPE_IPV4,
        6 => ETHERTYPE_IPV6,
        _ => return None,
    };
    let total_len = link.reply_eth_header_len().checked_add(ip_packet.len())?;
    out.clear();
    out.reserve(total_len);
    encode_reply_eth_header(link, ethertype, out);
    out.extend_from_slice(ip_packet);
    Some(())
}

/// `ecn` carries the IPv4 TOS / IPv6 Traffic-Class ECN bits (0–3) so
/// QUIC senders can mark packets; `None` emits an unmarked header.
pub fn encode_udp_reply_frame(
    link: &AfXdpLinkMeta,
    listen_addr: SocketAddr,
    peer_addr: SocketAddr,
    payload: &[u8],
    ecn: Option<u8>,
    out: &mut Vec<u8>,
) -> Option<()> {
    if listen_addr.is_ipv4() != peer_addr.is_ipv4() {
        return None;
    }
    let udp_len = UDP_HEADER_LEN.checked_add(payload.len())?;
    if udp_len > u16::MAX as usize {
        return None;
    }
    let ethertype = if listen_addr.is_ipv4() {
        ETHERTYPE_IPV4
    } else {
        ETHERTYPE_IPV6
    };
    let ip_header_len = if listen_addr.is_ipv4() {
        IPV4_MIN_HEADER_LEN
    } else {
        IPV6_HEADER_LEN
    };
    let ip_payload_len = udp_len;
    let ip_total_len = ip_header_len.checked_add(ip_payload_len)?;
    if ip_total_len > u16::MAX as usize {
        return None;
    }
    let total_len = link
        .reply_eth_header_len()
        .checked_add(ip_header_len)?
        .checked_add(udp_len)?;

    out.clear();
    out.reserve(total_len);
    encode_reply_eth_header(link, ethertype, out);
    let ip_offset = out.len();
    let ecn_bits = ecn.unwrap_or(0) & 0b11;
    match (listen_addr.ip(), peer_addr.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            out.extend_from_slice(&[
                0x45,
                ecn_bits,
                (ip_total_len >> 8) as u8,
                ip_total_len as u8,
                0,
                0,
                0,
                0,
                64,
                IP_PROTO_UDP,
                0,
                0,
            ]);
            out.extend_from_slice(&source.octets());
            out.extend_from_slice(&destination.octets());
            let checksum = internet_checksum(&out[ip_offset..ip_offset + IPV4_MIN_HEADER_LEN]);
            out[ip_offset + 10..ip_offset + 12].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            out.extend_from_slice(&[
                0x60,
                ecn_bits << 4,
                0,
                0,
                (ip_payload_len >> 8) as u8,
                ip_payload_len as u8,
                IP_PROTO_UDP,
                64,
            ]);
            out.extend_from_slice(&source.octets());
            out.extend_from_slice(&destination.octets());
        }
        _ => return None,
    }

    let udp_offset = out.len();
    out.extend_from_slice(&listen_addr.port().to_be_bytes());
    out.extend_from_slice(&peer_addr.port().to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);

    let udp_checksum = udp_checksum(listen_addr.ip(), peer_addr.ip(), &out[udp_offset..])?;
    out[udp_offset + 6..udp_offset + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Some(())
}

pub(crate) fn encode_reply_eth_header(link: &AfXdpLinkMeta, ethertype: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&link.source_mac);
    out.extend_from_slice(&link.destination_mac);
    for tag in link
        .vlan_tags
        .iter()
        .take(usize::from(link.vlan_tag_count.min(2)))
    {
        out.extend_from_slice(&tag.tpid.to_be_bytes());
        out.extend_from_slice(&tag.tci.to_be_bytes());
    }
    out.extend_from_slice(&ethertype.to_be_bytes());
}

/// T4-7: parsed ICMP error quoting a node-dialed outbound packet. The
/// inner IP/L4 header supplies the dialed 5-tuple — `flow.local` is the
/// *inner* source (our dialed endpoint) and `flow.peer` the inner
/// destination (the upstream peer); `mtu` carries the reported
/// next-hop/PTB MTU where the error type provides one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, target_os = "linux"))]
pub struct AfXdpIcmpError {
    pub flow: AfXdpTcpFlowKey,
    pub proto: u8,
    pub mtu: Option<u32>,
}

/// Parse a redirected ICMPv4/ICMPv6 error into the dialed-flow key it
/// quotes. Only error types that embed the offending packet are
/// accepted; echo/info messages return `None` and stay on the kernel
/// path (eBPF only redirects inner-tuple matches, but the userspace
/// parse is the authoritative gate).
#[cfg(any(test, target_os = "linux"))]
pub fn parse_icmp_error_frame(frame: &[u8]) -> Option<AfXdpIcmpError> {
    let (link, l3_offset) = parse_link_meta(frame)?;
    match link.ethertype {
        ETHERTYPE_IPV4 => parse_icmpv4_error(frame, l3_offset),
        ETHERTYPE_IPV6 => parse_icmpv6_error(frame, l3_offset),
        _ => None,
    }
}

#[cfg(any(test, target_os = "linux"))]
fn parse_icmpv4_error(frame: &[u8], ip_offset: usize) -> Option<AfXdpIcmpError> {
    if !ipv4_header_checksum_ok(frame, ip_offset) {
        return None;
    }
    let base = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN)?;
    if base[0] >> 4 != 4 || base[9] != IP_PROTO_ICMP {
        return None;
    }
    let ihl = usize::from(base[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let packet_end = ipv4_packet_end(frame, ip_offset)?;
    let icmp = frame.get(ip_offset + ihl..packet_end)?;
    if !icmpv4_checksum_ok(icmp) {
        return None;
    }
    let icmp_type = icmp[0];
    let icmp_code = icmp[1];
    // Errors that quote the offending datagram: dest-unreach (3),
    // source-quench (4, deprecated but quoted), redirect (5),
    // time-exceeded (11), parameter-problem (12).
    if !matches!(icmp_type, 3 | 4 | 5 | 11 | 12) {
        return None;
    }
    let mtu = (icmp_type == 3 && icmp_code == 4)
        .then(|| u32::from(u16::from_be_bytes([icmp[6], icmp[7]])))
        .filter(|mtu| *mtu > 0);
    let inner = icmp.get(8..)?;
    let (flow, proto) = parse_quoted_tuple(inner, 4)?;
    Some(AfXdpIcmpError { flow, proto, mtu })
}

#[cfg(any(test, target_os = "linux"))]
fn parse_icmpv6_error(frame: &[u8], ip_offset: usize) -> Option<AfXdpIcmpError> {
    let base = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN)?;
    if base[0] >> 4 != 6 || base[6] != IP_PROTO_ICMPV6 {
        return None;
    }
    let packet_end = ipv6_packet_end(frame, ip_offset)?;
    let icmp = frame.get(ip_offset + IPV6_HEADER_LEN..packet_end)?;
    if icmp.len() < 8 {
        return None;
    }
    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&base[8..24]).ok()?));
    let destination =
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&base[24..40]).ok()?));
    if !icmpv6_checksum_ok(source, destination, icmp) {
        return None;
    }
    let icmp_type = icmp[0];
    // ICMPv6 errors 1–4 (dest-unreach, packet-too-big, time-exceeded,
    // parameter-problem) all quote the offending packet.
    if !(1..=4).contains(&icmp_type) {
        return None;
    }
    let mtu = (icmp_type == 2)
        .then(|| u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]))
        .filter(|mtu| *mtu > 0);
    let inner = icmp.get(8..)?;
    let (flow, proto) = parse_quoted_tuple(inner, 6)?;
    Some(AfXdpIcmpError { flow, proto, mtu })
}

/// Extract the dialed 5-tuple from a quoted inner IP datagram.
/// `family` is 4 or 6; extension headers in a quoted IPv6 packet are
/// walked the same way as live traffic.
#[cfg(any(test, target_os = "linux"))]
fn parse_quoted_tuple(inner: &[u8], family: u8) -> Option<(AfXdpTcpFlowKey, u8)> {
    let (proto, source, destination, l4_offset, l4_end) = if family == 4 {
        let base = inner.get(..IPV4_MIN_HEADER_LEN)?;
        if base[0] >> 4 != 4 {
            return None;
        }
        let ihl = usize::from(base[0] & 0x0f) * 4;
        if ihl < IPV4_MIN_HEADER_LEN || inner.len() < ihl + 4 {
            return None;
        }
        (
            base[9],
            IpAddr::V4(Ipv4Addr::new(base[12], base[13], base[14], base[15])),
            IpAddr::V4(Ipv4Addr::new(base[16], base[17], base[18], base[19])),
            ihl,
            inner.len(),
        )
    } else {
        let base = inner.get(..IPV6_HEADER_LEN)?;
        if base[0] >> 4 != 6 {
            return None;
        }
        let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&base[8..24]).ok()?));
        let destination =
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&base[24..40]).ok()?));
        let (proto, l4_offset) =
            ipv6_transport_offset(inner, base[6], IPV6_HEADER_LEN, inner.len())?;
        (proto, source, destination, l4_offset, inner.len())
    };
    if !matches!(proto, IP_PROTO_TCP | IP_PROTO_UDP) || l4_offset + 4 > l4_end {
        return None;
    }
    let ports = &inner[l4_offset..l4_offset + 4];
    let flow = AfXdpTcpFlowKey {
        local_addr: SocketAddr::new(source, u16::from_be_bytes([ports[0], ports[1]])),
        peer_addr: SocketAddr::new(destination, u16::from_be_bytes([ports[2], ports[3]])),
    };
    Some((flow, proto))
}

/// Shared transport pseudo-header sum for checksum compute and verify.
fn l4_pseudo_sum(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    l4_len: usize,
) -> Option<u32> {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let mut pseudo_header = [0u8; 12];
            pseudo_header[0..4].copy_from_slice(&source.octets());
            pseudo_header[4..8].copy_from_slice(&destination.octets());
            pseudo_header[9] = protocol;
            pseudo_header[10..12].copy_from_slice(&(l4_len as u16).to_be_bytes());
            Some(checksum_sum(&pseudo_header))
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let mut pseudo_header = [0u8; 40];
            pseudo_header[0..16].copy_from_slice(&source.octets());
            pseudo_header[16..32].copy_from_slice(&destination.octets());
            pseudo_header[32..36].copy_from_slice(&(l4_len as u32).to_be_bytes());
            pseudo_header[39] = protocol;
            Some(checksum_sum(&pseudo_header))
        }
        _ => None,
    }
}

/// A valid internet checksum makes the folded 16-bit total 0xffff —
/// that includes the stored checksum field, so verification is a plain
/// re-sum rather than a zeroed-field recompute.
fn checksum_total_ok(total_sum: u32) -> bool {
    finalize_checksum(total_sum) == 0xffff
}

/// RX integrity gate (correctness contract): AF_XDP hands us raw wire
/// frames with no checksum metadata — the kernel's CHECKSUM_UNNECESSARY
/// marking is not visible at this layer, so "the skb was verified"
/// cannot be assumed. A real sender's NIC completes TX checksum offload
/// before the frame hits the wire, so valid wire frames always carry
/// complete checksums and only corrupt frames fail verification. Isolated
/// veth test links are the exception: a veth peer's TX offload leaves
/// the field partial in the bytes we receive — such test senders must
/// run with checksum offload disabled (`ethtool -K <peer> tx off`),
/// never by disabling verification here.
pub(crate) fn ipv4_header_checksum_ok(frame: &[u8], ip_offset: usize) -> bool {
    let Some(base) = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN) else {
        return false;
    };
    if base[0] >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(base[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN {
        return false;
    }
    let Some(header) = frame.get(ip_offset..ip_offset + ihl) else {
        return false;
    };
    checksum_total_ok(checksum_sum(header))
}

/// UDP datagram verification. `udp_packet` is the full datagram including
/// its checksum field. IPv4 permits a zero checksum (sender computed
/// none); IPv6 forbids it (RFC 8200 §8.1 — mandatory for UDP over v6).
pub(crate) fn udp_checksum_ok(
    source: IpAddr,
    destination: IpAddr,
    udp_packet: &[u8],
) -> bool {
    let Some(stored) = udp_packet
        .get(6..8)
        .map(|field| u16::from_be_bytes([field[0], field[1]]))
    else {
        return false;
    };
    if stored == 0 {
        return source.is_ipv4() && destination.is_ipv4();
    }
    let Some(pseudo_sum) = l4_pseudo_sum(source, destination, IP_PROTO_UDP, udp_packet.len())
    else {
        return false;
    };
    checksum_total_ok(pseudo_sum.wrapping_add(checksum_sum(udp_packet)))
}

/// ICMPv4 message verification — the checksum covers the message body
/// only (no pseudo-header).
#[cfg(any(test, target_os = "linux"))]
fn icmpv4_checksum_ok(icmp: &[u8]) -> bool {
    checksum_total_ok(checksum_sum(icmp))
}

/// TCP segment verification — mandatory in both families; `segment` is
/// the whole TCP datagram including its checksum field.
pub(crate) fn tcp_checksum_ok(
    source: IpAddr,
    destination: IpAddr,
    segment: &[u8],
) -> bool {
    if segment.len() < 18 {
        return false;
    }
    let Some(pseudo_sum) = l4_pseudo_sum(source, destination, IP_PROTO_TCP, segment.len())
    else {
        return false;
    };
    checksum_total_ok(pseudo_sum.wrapping_add(checksum_sum(segment)))
}

/// ICMPv6 message verification — mandatory checksum over pseudo-header
/// plus message (RFC 8200 §8.1).
#[cfg(any(test, target_os = "linux"))]
fn icmpv6_checksum_ok(source: IpAddr, destination: IpAddr, icmp: &[u8]) -> bool {
    let Some(pseudo_sum) = l4_pseudo_sum(source, destination, IP_PROTO_ICMPV6, icmp.len())
    else {
        return false;
    };
    checksum_total_ok(pseudo_sum.wrapping_add(checksum_sum(icmp)))
}

pub(crate) fn udp_checksum(source: IpAddr, destination: IpAddr, udp_packet: &[u8]) -> Option<u16> {
    let pseudo_sum = l4_pseudo_sum(source, destination, IP_PROTO_UDP, udp_packet.len())?;
    Some(finalize_checksum(
        pseudo_sum.wrapping_add(checksum_sum(udp_packet)),
    ))
}

pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
    finalize_checksum(checksum_sum(data))
}

pub(crate) fn checksum_sum(data: &[u8]) -> u32 {
    let (chunks, remainder) = data.as_chunks::<2>();
    let mut sum = chunks.iter().fold(0u32, |sum, chunk| {
        sum + u16::from_be_bytes([chunk[0], chunk[1]]) as u32
    });
    if let Some(byte) = remainder.first() {
        sum += u16::from_be_bytes([*byte, 0]) as u32;
    }
    sum
}

pub(crate) fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    if checksum == 0 { 0xffff } else { checksum }
}

pub(crate) fn parse_link_meta(frame: &[u8]) -> Option<(AfXdpLinkMeta, usize)> {
    if frame.len() < ETH_HEADER_LEN {
        return None;
    }
    let mut destination_mac = [0u8; 6];
    destination_mac.copy_from_slice(&frame[0..6]);
    let mut source_mac = [0u8; 6];
    source_mac.copy_from_slice(&frame[6..12]);
    let mut ethertype = read_u16(frame, 12)?;
    let mut offset = ETH_HEADER_LEN;
    let mut vlan_tags = [AfXdpVlanTag { tpid: 0, tci: 0 }; 2];
    let mut vlan_tag_count = 0u8;
    for _ in 0..2 {
        if !is_vlan_ethertype(ethertype) {
            return Some((
                AfXdpLinkMeta {
                    destination_mac,
                    source_mac,
                    vlan_tags,
                    vlan_tag_count,
                    ethertype,
                },
                offset,
            ));
        }
        if frame.len() < offset + VLAN_HEADER_LEN {
            return None;
        }
        vlan_tags[usize::from(vlan_tag_count)] = AfXdpVlanTag {
            tpid: ethertype,
            tci: read_u16(frame, offset)?,
        };
        vlan_tag_count = vlan_tag_count.saturating_add(1);
        ethertype = read_u16(frame, offset + 2)?;
        offset += VLAN_HEADER_LEN;
    }
    Some((
        AfXdpLinkMeta {
            destination_mac,
            source_mac,
            vlan_tags,
            vlan_tag_count,
            ethertype,
        },
        offset,
    ))
}

pub(crate) fn is_vlan_ethertype(ethertype: u16) -> bool {
    matches!(
        ethertype,
        ETHERTYPE_VLAN
            | ETHERTYPE_QINQ
            | ETHERTYPE_QINQ_9100
            | ETHERTYPE_QINQ_9200
            | ETHERTYPE_QINQ_9300
    )
}

pub(crate) fn parse_ipv4_l4(
    frame: &[u8],
    ip_offset: usize,
    link: AfXdpLinkMeta,
) -> Option<AfXdpL4Packet> {
    let base = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN)?;
    let version = base[0] >> 4;
    let ihl = usize::from(base[0] & 0x0f) * 4;
    if version != 4 || ihl < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let packet_end = ipv4_packet_end(frame, ip_offset)?;
    let fragment = u16::from_be_bytes([base[6], base[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }
    let protocol = base[9];
    let ecn = base[1] & 0b11;
    let source = IpAddr::V4(Ipv4Addr::new(base[12], base[13], base[14], base[15]));
    let destination = IpAddr::V4(Ipv4Addr::new(base[16], base[17], base[18], base[19]));
    parse_transport(
        frame,
        protocol,
        ip_offset + ihl,
        packet_end,
        source,
        destination,
        link,
        Some(ecn),
    )
}

pub(crate) fn parse_ipv6_l4(
    frame: &[u8],
    ip_offset: usize,
    link: AfXdpLinkMeta,
) -> Option<AfXdpL4Packet> {
    let base = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN)?;
    if base[0] >> 4 != 6 {
        return None;
    }
    let packet_end = ipv6_packet_end(frame, ip_offset)?;
    let mut source_octets = [0u8; 16];
    source_octets.copy_from_slice(&base[8..24]);
    let mut destination_octets = [0u8; 16];
    destination_octets.copy_from_slice(&base[24..40]);
    let source = IpAddr::V6(Ipv6Addr::from(source_octets));
    let destination = IpAddr::V6(Ipv6Addr::from(destination_octets));
    // Traffic Class spans byte0[3:0]|byte1[7:4]; ECN = TC[1:0] → byte1[5:4].
    let ecn = (base[1] >> 4) & 0b11;
    let (protocol, l4_offset) =
        ipv6_transport_offset(frame, base[6], ip_offset + IPV6_HEADER_LEN, packet_end)?;
    parse_transport(
        frame,
        protocol,
        l4_offset,
        packet_end,
        source,
        destination,
        link,
        Some(ecn),
    )
}

pub(crate) fn transport_protocol_from_frame(
    frame: &[u8],
    ip_offset: usize,
    ethertype: u16,
) -> Option<u8> {
    match ethertype {
        ETHERTYPE_IPV4 => {
            let base = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN)?;
            let version = base[0] >> 4;
            let ihl = usize::from(base[0] & 0x0f) * 4;
            if version != 4 || ihl < IPV4_MIN_HEADER_LEN {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([base[2], base[3]]));
            if total_len < ihl || ip_offset.checked_add(total_len)? > frame.len() {
                return None;
            }
            let fragment = u16::from_be_bytes([base[6], base[7]]);
            if fragment & 0x3fff != 0 {
                return None;
            }
            Some(base[9])
        }
        ETHERTYPE_IPV6 => {
            let base = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN)?;
            if base[0] >> 4 != 6 {
                return None;
            }
            let packet_end = ipv6_packet_end(frame, ip_offset)?;
            let (protocol, _) =
                ipv6_transport_offset(frame, base[6], ip_offset + IPV6_HEADER_LEN, packet_end)?;
            Some(protocol)
        }
        _ => None,
    }
}

pub(crate) fn ipv4_packet_end(frame: &[u8], ip_offset: usize) -> Option<usize> {
    let base = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN)?;
    let version = base[0] >> 4;
    let ihl = usize::from(base[0] & 0x0f) * 4;
    if version != 4 || ihl < IPV4_MIN_HEADER_LEN {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([base[2], base[3]]));
    if total_len < ihl {
        return None;
    }
    let packet_end = ip_offset.checked_add(total_len)?;
    (frame.len() >= packet_end).then_some(packet_end)
}

pub(crate) fn ipv6_packet_end(frame: &[u8], ip_offset: usize) -> Option<usize> {
    let base = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN)?;
    if base[0] >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([base[4], base[5]]));
    let packet_end = ip_offset
        .checked_add(IPV6_HEADER_LEN)?
        .checked_add(payload_len)?;
    (frame.len() >= packet_end).then_some(packet_end)
}

pub(crate) fn ipv6_transport_offset(
    frame: &[u8],
    mut next_header: u8,
    mut offset: usize,
    packet_end: usize,
) -> Option<(u8, usize)> {
    for _ in 0..8 {
        match next_header {
            IP_PROTO_TCP | IP_PROTO_UDP => return Some((next_header, offset)),
            IP_PROTO_NO_NEXT => return None,
            IP_PROTO_HOP_BY_HOP | IP_PROTO_ROUTING | IP_PROTO_DEST_OPTS => {
                let header = frame.get(offset..offset + 2)?;
                next_header = header[0];
                let len = (usize::from(header[1]) + 1) * 8;
                offset = offset.checked_add(len)?;
            }
            IP_PROTO_AH => {
                let header = frame.get(offset..offset + 2)?;
                next_header = header[0];
                let len = (usize::from(header[1]) + 2) * 4;
                offset = offset.checked_add(len)?;
            }
            IP_PROTO_FRAGMENT => {
                let header = frame.get(offset..offset + 8)?;
                next_header = header[0];
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                if fragment & 0xfff9 != 0 {
                    return None;
                }
                offset = offset.checked_add(8)?;
            }
            _ => return None,
        }
        if offset > packet_end {
            return None;
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_transport(
    frame: &[u8],
    protocol: u8,
    l4_offset: usize,
    packet_end: usize,
    source: IpAddr,
    destination: IpAddr,
    link: AfXdpLinkMeta,
    ecn: Option<u8>,
) -> Option<AfXdpL4Packet> {
    match protocol {
        IP_PROTO_TCP => {
            let header = frame.get(l4_offset..l4_offset + TCP_MIN_HEADER_LEN)?;
            let source_port = u16::from_be_bytes([header[0], header[1]]);
            let destination_port = u16::from_be_bytes([header[2], header[3]]);
            let tcp_header_len = usize::from(header[12] >> 4) * 4;
            if tcp_header_len < TCP_MIN_HEADER_LEN || l4_offset + tcp_header_len > packet_end {
                return None;
            }
            // Same RX integrity gate: a corrupt TCP checksum must drop the
            // frame before any session state is created for it.
            if !tcp_checksum_ok(source, destination, &frame[l4_offset..packet_end]) {
                return None;
            }
            Some(AfXdpL4Packet {
                protocol: AfXdpTransportProtocol::Tcp,
                local_addr: SocketAddr::new(destination, destination_port),
                peer_addr: SocketAddr::new(source, source_port),
                payload: Bytes::copy_from_slice(&frame[l4_offset + tcp_header_len..packet_end]),
                link,
                ecn,
            })
        }
        IP_PROTO_UDP => {
            let header = frame.get(l4_offset..l4_offset + UDP_HEADER_LEN)?;
            let source_port = u16::from_be_bytes([header[0], header[1]]);
            let destination_port = u16::from_be_bytes([header[2], header[3]]);
            let udp_len = usize::from(u16::from_be_bytes([header[4], header[5]]));
            if udp_len < UDP_HEADER_LEN || l4_offset + udp_len > packet_end {
                return None;
            }
            if !udp_checksum_ok(
                source,
                destination,
                &frame[l4_offset..l4_offset + udp_len],
            ) {
                return None;
            }
            Some(AfXdpL4Packet {
                protocol: AfXdpTransportProtocol::Udp,
                local_addr: SocketAddr::new(destination, destination_port),
                peer_addr: SocketAddr::new(source, source_port),
                payload: Bytes::copy_from_slice(
                    &frame[l4_offset + UDP_HEADER_LEN..l4_offset + udp_len],
                ),
                link,
                ecn,
            })
        }
        _ => None,
    }
}

pub(crate) fn tcp_flow_key_from_ip_packet(ip_packet: &[u8]) -> Option<AfXdpTcpFlowKey> {
    let (protocol, l4_offset, packet_end) = ip_transport_bounds(ip_packet)?;
    if protocol != IP_PROTO_TCP || l4_offset + TCP_MIN_HEADER_LEN > packet_end {
        return None;
    }
    let header = ip_packet.get(l4_offset..l4_offset + TCP_MIN_HEADER_LEN)?;
    let source_port = u16::from_be_bytes([header[0], header[1]]);
    let destination_port = u16::from_be_bytes([header[2], header[3]]);
    let (source, destination) = match ip_packet.first()? >> 4 {
        4 => {
            let base = ip_packet.get(..IPV4_MIN_HEADER_LEN)?;
            (
                IpAddr::V4(Ipv4Addr::new(base[12], base[13], base[14], base[15])),
                IpAddr::V4(Ipv4Addr::new(base[16], base[17], base[18], base[19])),
            )
        }
        6 => {
            let base = ip_packet.get(..IPV6_HEADER_LEN)?;
            let mut source_octets = [0u8; 16];
            source_octets.copy_from_slice(&base[8..24]);
            let mut destination_octets = [0u8; 16];
            destination_octets.copy_from_slice(&base[24..40]);
            (
                IpAddr::V6(Ipv6Addr::from(source_octets)),
                IpAddr::V6(Ipv6Addr::from(destination_octets)),
            )
        }
        _ => return None,
    };
    Some(AfXdpTcpFlowKey {
        local_addr: SocketAddr::new(destination, destination_port),
        peer_addr: SocketAddr::new(source, source_port),
    })
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn reply_flow_key_from_ip_packet(ip_packet: &[u8]) -> Option<AfXdpTcpFlowKey> {
    let flow = tcp_flow_key_from_ip_packet(ip_packet)?;
    Some(AfXdpTcpFlowKey {
        local_addr: flow.peer_addr,
        peer_addr: flow.local_addr,
    })
}

#[cfg(test)]
pub(crate) fn tcp_packet_is_initial_syn(ip_packet: &[u8]) -> bool {
    let Some(flags) = tcp_flags_from_ip_packet(ip_packet) else {
        return false;
    };
    tcp_flags_are_initial_syn(flags)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn tcp_flags_are_initial_syn(flags: u8) -> bool {
    flags & 0x17 == 0x02
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn parse_tcp_flow_flags_from_frame(frame: &[u8]) -> Option<(AfXdpTcpFlowKey, u8)> {
    let (link, ip_offset) = parse_link_meta(frame)?;
    tcp_flow_flags_from_frame(frame, ip_offset, link.ethertype)
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn tcp_flow_flags_from_frame(
    frame: &[u8],
    ip_offset: usize,
    ethertype: u16,
) -> Option<(AfXdpTcpFlowKey, u8)> {
    match ethertype {
        ETHERTYPE_IPV4 => {
            let base = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN)?;
            let version = base[0] >> 4;
            let ihl = usize::from(base[0] & 0x0f) * 4;
            if version != 4 || ihl < IPV4_MIN_HEADER_LEN {
                return None;
            }
            let packet_end = ipv4_packet_end(frame, ip_offset)?;
            let fragment = u16::from_be_bytes([base[6], base[7]]);
            if fragment & 0x3fff != 0 || base[9] != IP_PROTO_TCP {
                return None;
            }
            let tcp_offset = ip_offset.checked_add(ihl)?;
            let header = frame.get(tcp_offset..tcp_offset + TCP_MIN_HEADER_LEN)?;
            let tcp_header_len = usize::from(header[12] >> 4) * 4;
            if tcp_header_len < TCP_MIN_HEADER_LEN || tcp_offset + tcp_header_len > packet_end {
                return None;
            }
            let source = IpAddr::V4(Ipv4Addr::new(base[12], base[13], base[14], base[15]));
            let destination = IpAddr::V4(Ipv4Addr::new(base[16], base[17], base[18], base[19]));
            Some((
                AfXdpTcpFlowKey {
                    local_addr: SocketAddr::new(
                        destination,
                        u16::from_be_bytes([header[2], header[3]]),
                    ),
                    peer_addr: SocketAddr::new(source, u16::from_be_bytes([header[0], header[1]])),
                },
                header[13],
            ))
        }
        ETHERTYPE_IPV6 => {
            let base = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN)?;
            if base[0] >> 4 != 6 {
                return None;
            }
            let packet_end = ipv6_packet_end(frame, ip_offset)?;
            let (protocol, tcp_offset) =
                ipv6_transport_offset(frame, base[6], ip_offset + IPV6_HEADER_LEN, packet_end)?;
            if protocol != IP_PROTO_TCP {
                return None;
            }
            let header = frame.get(tcp_offset..tcp_offset + TCP_MIN_HEADER_LEN)?;
            let tcp_header_len = usize::from(header[12] >> 4) * 4;
            if tcp_header_len < TCP_MIN_HEADER_LEN || tcp_offset + tcp_header_len > packet_end {
                return None;
            }
            let mut source_octets = [0u8; 16];
            source_octets.copy_from_slice(&base[8..24]);
            let mut destination_octets = [0u8; 16];
            destination_octets.copy_from_slice(&base[24..40]);
            Some((
                AfXdpTcpFlowKey {
                    local_addr: SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(destination_octets)),
                        u16::from_be_bytes([header[2], header[3]]),
                    ),
                    peer_addr: SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(source_octets)),
                        u16::from_be_bytes([header[0], header[1]]),
                    ),
                },
                header[13],
            ))
        }
        _ => None,
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn tcp_flags_from_ip_packet(ip_packet: &[u8]) -> Option<u8> {
    let (protocol, l4_offset, packet_end) = ip_transport_bounds(ip_packet)?;
    if protocol != IP_PROTO_TCP || l4_offset + TCP_MIN_HEADER_LEN > packet_end {
        return None;
    }
    Some(ip_packet[l4_offset + 13])
}

pub(crate) fn ip_transport_bounds(ip_packet: &[u8]) -> Option<(u8, usize, usize)> {
    match ip_packet.first()? >> 4 {
        4 => {
            let base = ip_packet.get(..IPV4_MIN_HEADER_LEN)?;
            let ihl = usize::from(base[0] & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER_LEN {
                return None;
            }
            let total_len = usize::from(u16::from_be_bytes([base[2], base[3]]));
            if total_len < ihl || total_len > ip_packet.len() {
                return None;
            }
            let fragment = u16::from_be_bytes([base[6], base[7]]);
            if fragment & 0x3fff != 0 {
                return None;
            }
            Some((base[9], ihl, total_len))
        }
        6 => {
            let base = ip_packet.get(..IPV6_HEADER_LEN)?;
            let payload_len = usize::from(u16::from_be_bytes([base[4], base[5]]));
            let packet_end = IPV6_HEADER_LEN.checked_add(payload_len)?;
            if packet_end > ip_packet.len() {
                return None;
            }
            let (protocol, l4_offset) =
                ipv6_transport_offset(ip_packet, base[6], IPV6_HEADER_LEN, packet_end)?;
            Some((protocol, l4_offset, packet_end))
        }
        _ => None,
    }
}

pub(crate) fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *buf.get(offset)?,
        *buf.get(offset + 1)?,
    ]))
}

// ---------------------------------------------------------------------------
// EN-05 parse classification mirror: the same verdict taxonomy the eBPF
// parser applies (XDP_CLASS_*). Used by tests to assert kernel/userspace
// parse parity (T01) — the proxy dataplane itself still uses the Option-based
// parsers above; classification is additive observability.
// ---------------------------------------------------------------------------

/// Mirror of the eBPF parse classes (XDP_CLASS_* in cloud-node-xdp-common),
/// plus NonIp for frames the kernel program passes without classifying.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfXdpFrameClass {
    Supported,
    Malformed,
    Unsupported,
    Fragmented,
    Control,
    /// Non-IPv4/IPv6 ethertype: the kernel passes these without a class
    /// counter; kept distinct so parity tests can tell "uncounted pass" from
    /// "counted unsupported".
    NonIp,
}

/// Classify a received L2 frame exactly as the eBPF parser does:
/// deterministic-illegal -> Malformed, IP fragments -> Fragmented (never an
/// L4 flow), ICMP/ICMPv6 -> Control, legal-but-unresolvable -> Unsupported,
/// fully parsed TCP/UDP -> Supported.
#[cfg(test)]
pub(crate) fn classify_frame(frame: &[u8]) -> AfXdpFrameClass {
    use AfXdpFrameClass::*;
    if frame.len() < ETH_HEADER_LEN {
        return Malformed;
    }
    let mut ethertype = match read_u16(frame, 12) {
        Some(v) => v,
        None => return Malformed,
    };
    let mut ip_offset = ETH_HEADER_LEN;
    for _ in 0..2 {
        if !is_vlan_ethertype(ethertype) {
            break;
        }
        if frame.len() < ip_offset + VLAN_HEADER_LEN {
            return Malformed;
        }
        ethertype = match read_u16(frame, ip_offset + 2) {
            Some(v) => v,
            None => return Malformed,
        };
        ip_offset += VLAN_HEADER_LEN;
    }
    if is_vlan_ethertype(ethertype) {
        return Unsupported;
    }
    match ethertype {
        ETHERTYPE_IPV4 => classify_ipv4(frame, ip_offset),
        ETHERTYPE_IPV6 => classify_ipv6(frame, ip_offset),
        _ => NonIp,
    }
}

#[cfg(test)]
fn classify_ipv4(frame: &[u8], ip_offset: usize) -> AfXdpFrameClass {
    use AfXdpFrameClass::*;
    let Some(base) = frame.get(ip_offset..ip_offset + IPV4_MIN_HEADER_LEN) else {
        return Malformed;
    };
    let ihl = usize::from(base[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([base[2], base[3]]));
    if base[0] >> 4 != 4
        || !(IPV4_MIN_HEADER_LEN..=15 * 4).contains(&ihl)
        || total_len < ihl
        || ip_offset + total_len > frame.len()
    {
        return Malformed;
    }
    let fragment = u16::from_be_bytes([base[6], base[7]]);
    if fragment & 0x3fff != 0 {
        return Fragmented;
    }
    let packet_end = ip_offset + total_len;
    classify_transport(frame, base[9], ip_offset + ihl, packet_end)
}

#[cfg(test)]
fn classify_ipv6(frame: &[u8], ip_offset: usize) -> AfXdpFrameClass {
    use AfXdpFrameClass::*;
    let Some(base) = frame.get(ip_offset..ip_offset + IPV6_HEADER_LEN) else {
        return Malformed;
    };
    if base[0] >> 4 != 6 {
        return Malformed;
    }
    let payload_len = usize::from(u16::from_be_bytes([base[4], base[5]]));
    let Some(packet_end) = ip_offset
        .checked_add(IPV6_HEADER_LEN)
        .and_then(|o| o.checked_add(payload_len))
    else {
        return Malformed;
    };
    if packet_end > frame.len() {
        return Malformed;
    }
    match classify_ipv6_chain(frame, base[6], ip_offset + IPV6_HEADER_LEN, packet_end) {
        Ipv6Chain::L4(protocol, l4_offset) => {
            classify_transport(frame, protocol, l4_offset, packet_end)
        }
        Ipv6Chain::Fragmented => Fragmented,
        Ipv6Chain::Unsupported => Unsupported,
        Ipv6Chain::Malformed => Malformed,
    }
}

#[cfg(test)]
enum Ipv6Chain {
    L4(u8, usize),
    Fragmented,
    Unsupported,
    Malformed,
}

#[cfg(test)]
fn classify_ipv6_chain(
    frame: &[u8],
    mut next_header: u8,
    mut offset: usize,
    packet_end: usize,
) -> Ipv6Chain {
    for _ in 0..8 {
        match next_header {
            IP_PROTO_TCP | IP_PROTO_UDP | IP_PROTO_ICMPV6 => {
                return Ipv6Chain::L4(next_header, offset);
            }
            IP_PROTO_NO_NEXT => return Ipv6Chain::Unsupported,
            IP_PROTO_HOP_BY_HOP | IP_PROTO_ROUTING | IP_PROTO_DEST_OPTS => {
                let Some(header) = frame.get(offset..offset + 2) else {
                    return Ipv6Chain::Malformed;
                };
                if offset + 2 > packet_end {
                    return Ipv6Chain::Malformed;
                }
                next_header = header[0];
                offset = match offset.checked_add((usize::from(header[1]) + 1) * 8) {
                    Some(o) => o,
                    None => return Ipv6Chain::Malformed,
                };
            }
            IP_PROTO_AH => {
                let Some(header) = frame.get(offset..offset + 2) else {
                    return Ipv6Chain::Malformed;
                };
                if offset + 2 > packet_end {
                    return Ipv6Chain::Malformed;
                }
                next_header = header[0];
                offset = match offset.checked_add((usize::from(header[1]) + 2) * 4) {
                    Some(o) => o,
                    None => return Ipv6Chain::Malformed,
                };
            }
            IP_PROTO_FRAGMENT => {
                let Some(header) = frame.get(offset..offset + 8) else {
                    return Ipv6Chain::Malformed;
                };
                if offset + 8 > packet_end {
                    return Ipv6Chain::Malformed;
                }
                next_header = header[0];
                let fragment = u16::from_be_bytes([header[2], header[3]]);
                if fragment & 0xfff9 != 0 {
                    return Ipv6Chain::Fragmented;
                }
                offset = match offset.checked_add(8) {
                    Some(o) => o,
                    None => return Ipv6Chain::Malformed,
                };
            }
            _ => return Ipv6Chain::Unsupported,
        }
        if offset > packet_end {
            return Ipv6Chain::Malformed;
        }
    }
    Ipv6Chain::Unsupported
}

#[cfg(test)]
fn classify_transport(
    frame: &[u8],
    protocol: u8,
    l4_offset: usize,
    packet_end: usize,
) -> AfXdpFrameClass {
    use AfXdpFrameClass::*;
    match protocol {
        IP_PROTO_TCP => {
            let Some(header) = frame.get(l4_offset..l4_offset + TCP_MIN_HEADER_LEN) else {
                return Malformed;
            };
            if l4_offset + TCP_MIN_HEADER_LEN > packet_end {
                return Malformed;
            }
            let doff = usize::from(header[12] >> 4) * 4;
            if doff < TCP_MIN_HEADER_LEN || l4_offset + doff > packet_end {
                return Malformed;
            }
            // FIN|SYN|RST|PSH|ACK|URG — ECN (ECE/CWR) and NS are exempt.
            let flags = header[13] & 0x3f;
            if flags == 0 || (flags & 0x02 != 0 && flags & 0x05 != 0) {
                return Malformed;
            }
            Supported
        }
        IP_PROTO_UDP => {
            let Some(header) = frame.get(l4_offset..l4_offset + UDP_HEADER_LEN) else {
                return Malformed;
            };
            if l4_offset + UDP_HEADER_LEN > packet_end {
                return Malformed;
            }
            let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
            if len < UDP_HEADER_LEN || l4_offset + len > packet_end {
                return Malformed;
            }
            Supported
        }
        IP_PROTO_ICMP | IP_PROTO_ICMPV6 => Control,
        _ => Unsupported,
    }
}
