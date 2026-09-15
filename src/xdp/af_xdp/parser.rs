use super::*;

pub fn parse_l4_packet(frame: &[u8]) -> Option<AfXdpL4Packet> {
    let (link, l3_offset) = parse_link_meta(frame)?;
    let ethertype = link.ethertype;
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
    let protocol = transport_protocol_from_frame(frame, l3_offset, link.ethertype)?;
    let route = AfXdpRouteMeta {
        interface: interface.into(),
        queue,
        link,
    };
    match protocol {
        IP_PROTO_TCP => {
            let (_, ip_packet) = extract_ip_frame(frame)?;
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

pub fn encode_udp_reply_frame(
    link: &AfXdpLinkMeta,
    listen_addr: SocketAddr,
    peer_addr: SocketAddr,
    payload: &[u8],
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
    match (listen_addr.ip(), peer_addr.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            out.extend_from_slice(&[
                0x45,
                0,
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
                0,
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

pub(crate) fn udp_checksum(source: IpAddr, destination: IpAddr, udp_packet: &[u8]) -> Option<u16> {
    let pseudo_sum = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let mut pseudo_header = [0u8; 12];
            pseudo_header[0..4].copy_from_slice(&source.octets());
            pseudo_header[4..8].copy_from_slice(&destination.octets());
            pseudo_header[9] = IP_PROTO_UDP;
            pseudo_header[10..12].copy_from_slice(&(udp_packet.len() as u16).to_be_bytes());
            checksum_sum(&pseudo_header)
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let mut pseudo_header = [0u8; 40];
            pseudo_header[0..16].copy_from_slice(&source.octets());
            pseudo_header[16..32].copy_from_slice(&destination.octets());
            pseudo_header[32..36].copy_from_slice(&(udp_packet.len() as u32).to_be_bytes());
            pseudo_header[39] = IP_PROTO_UDP;
            checksum_sum(&pseudo_header)
        }
        _ => return None,
    };
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

pub(crate) fn parse_transport(
    frame: &[u8],
    protocol: u8,
    l4_offset: usize,
    packet_end: usize,
    source: IpAddr,
    destination: IpAddr,
    link: AfXdpLinkMeta,
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
            Some(AfXdpL4Packet {
                protocol: AfXdpTransportProtocol::Tcp,
                local_addr: SocketAddr::new(destination, destination_port),
                peer_addr: SocketAddr::new(source, source_port),
                payload: Bytes::copy_from_slice(&frame[l4_offset + tcp_header_len..packet_end]),
                link,
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
            Some(AfXdpL4Packet {
                protocol: AfXdpTransportProtocol::Udp,
                local_addr: SocketAddr::new(destination, destination_port),
                peer_addr: SocketAddr::new(source, source_port),
                payload: Bytes::copy_from_slice(
                    &frame[l4_offset + UDP_HEADER_LEN..l4_offset + udp_len],
                ),
                link,
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

#[cfg(test)]
const IP_PROTO_ICMP: u8 = 1;
#[cfg(test)]
const IP_PROTO_ICMPV6: u8 = 58;

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
        || ihl < IPV4_MIN_HEADER_LEN
        || ihl > 15 * 4
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
