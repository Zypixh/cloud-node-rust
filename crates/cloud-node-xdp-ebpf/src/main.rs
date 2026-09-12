#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_csum_diff, bpf_ktime_get_ns},
    macros::{map, xdp},
    maps::{Array, HashMap, LpmTrie, PerCpuHashMap, XskMap, lpm_trie::Key as LpmKey},
    programs::XdpContext,
};
use cloud_node_xdp_common::{
    XdpCounters, XdpFlowAcct, XdpInterfacePolicy, XdpIpv4Key, XdpIpv6Key, XdpLocalIpv4Key,
    XdpLocalIpv6Key, XdpPortProtoKey, XdpQueueKey, XdpQuicDcidKey, XdpRateBucket,
    XdpRateLimitConfig, XdpRuleValue, XdpUdpCtKey, XdpUdpCtValue, XdpUdpFwdKey, XdpUdpFwdRule,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
    vlan::VlanHdr,
};

const IP_PROTO_HOP_BY_HOP: u8 = 0;
const IP_PROTO_ROUTING: u8 = 43;
const IP_PROTO_FRAGMENT: u8 = 44;
const IP_PROTO_AH: u8 = 51;
const IP_PROTO_NO_NEXT: u8 = 59;
const IP_PROTO_DEST_OPTS: u8 = 60;

#[map(name = "XDP_BLOCKED_V4")]
static XDP_BLOCKED_V4: HashMap<XdpIpv4Key, XdpRuleValue> =
    HashMap::<XdpIpv4Key, XdpRuleValue>::with_max_entries(262_144, 0);

#[map(name = "XDP_BLOCKED_V6")]
static XDP_BLOCKED_V6: HashMap<XdpIpv6Key, XdpRuleValue> =
    HashMap::<XdpIpv6Key, XdpRuleValue>::with_max_entries(262_144, 0);

#[map(name = "XDP_ALLOWED_V4")]
static XDP_ALLOWED_V4: HashMap<XdpIpv4Key, XdpRuleValue> =
    HashMap::<XdpIpv4Key, XdpRuleValue>::with_max_entries(65_536, 0);

#[map(name = "XDP_ALLOWED_V6")]
static XDP_ALLOWED_V6: HashMap<XdpIpv6Key, XdpRuleValue> =
    HashMap::<XdpIpv6Key, XdpRuleValue>::with_max_entries(65_536, 0);

#[map(name = "XDP_BLOCKED_V4_LPM")]
static XDP_BLOCKED_V4_LPM: LpmTrie<u32, XdpRuleValue> =
    LpmTrie::<u32, XdpRuleValue>::with_max_entries(65_536, 0);

#[map(name = "XDP_BLOCKED_V6_LPM")]
static XDP_BLOCKED_V6_LPM: LpmTrie<[u8; 16], XdpRuleValue> =
    LpmTrie::<[u8; 16], XdpRuleValue>::with_max_entries(65_536, 0);

#[map(name = "XDP_ALLOWED_V4_LPM")]
static XDP_ALLOWED_V4_LPM: LpmTrie<u32, XdpRuleValue> =
    LpmTrie::<u32, XdpRuleValue>::with_max_entries(65_536, 0);

#[map(name = "XDP_ALLOWED_V6_LPM")]
static XDP_ALLOWED_V6_LPM: LpmTrie<[u8; 16], XdpRuleValue> =
    LpmTrie::<[u8; 16], XdpRuleValue>::with_max_entries(65_536, 0);

#[map(name = "XDP_INTERFACE_POLICY")]
static XDP_INTERFACE_POLICY: HashMap<u32, XdpInterfacePolicy> =
    HashMap::<u32, XdpInterfacePolicy>::with_max_entries(64, 0);

#[map(name = "XDP_LOCAL_V4")]
static XDP_LOCAL_V4: HashMap<XdpLocalIpv4Key, u32> =
    HashMap::<XdpLocalIpv4Key, u32>::with_max_entries(4096, 0);

#[map(name = "XDP_LOCAL_V6")]
static XDP_LOCAL_V6: HashMap<XdpLocalIpv6Key, u32> =
    HashMap::<XdpLocalIpv6Key, u32>::with_max_entries(4096, 0);

#[map(name = "XDP_PROXY_PORTS")]
static XDP_PROXY_PORTS: HashMap<XdpPortProtoKey, u32> =
    HashMap::<XdpPortProtoKey, u32>::with_max_entries(4096, 0);

#[map(name = "XDP_COUNTERS")]
static XDP_COUNTERS: Array<XdpCounters> = Array::<XdpCounters>::with_max_entries(1, 0);

#[map(name = "XDP_XSKS")]
static XDP_XSKS: XskMap = XskMap::with_max_entries(4096, 0);

#[map(name = "XDP_XSK_INDEX")]
static XDP_XSK_INDEX: HashMap<XdpQueueKey, u32> =
    HashMap::<XdpQueueKey, u32>::with_max_entries(4096, 0);

#[map(name = "XDP_RATE_CFG")]
static XDP_RATE_CFG: Array<XdpRateLimitConfig> =
    Array::<XdpRateLimitConfig>::with_max_entries(1, 0);

#[map(name = "XDP_RATE_V4")]
static XDP_RATE_V4: HashMap<XdpIpv4Key, XdpRateBucket> =
    HashMap::<XdpIpv4Key, XdpRateBucket>::with_max_entries(262_144, 0);

#[map(name = "XDP_RATE_V6")]
static XDP_RATE_V6: HashMap<XdpIpv6Key, XdpRateBucket> =
    HashMap::<XdpIpv6Key, XdpRateBucket>::with_max_entries(262_144, 0);

/// QUIC long-header DCID -> XSK map index. Keeps a connection's handshake and
/// migrated long-header traffic on the queue that owns its userspace session
/// instead of following RSS rehashes. Short-header DCIDs have no encoded
/// length, so those packets always take the normal RSS queue path.
#[map(name = "XDP_QUIC_DCID")]
static XDP_QUIC_DCID: HashMap<XdpQuicDcidKey, u32> =
    HashMap::<XdpQuicDcidKey, u32>::with_max_entries(131_072, 0);

/// Explicitly configured UDP listen tuples that bypass the userspace
/// dataplane: DNAT to the backend and XDP_TX out the same interface.
#[map(name = "XDP_UDP_FWD")]
static XDP_UDP_FWD: HashMap<XdpUdpFwdKey, XdpUdpFwdRule> =
    HashMap::<XdpUdpFwdKey, XdpUdpFwdRule>::with_max_entries(4096, 0);

/// Client 4-tuple -> listen tuple conntrack so backend replies can be
/// rewritten back before XDP_TX. Populated on the first forwarded datagram.
#[map(name = "XDP_UDP_CT")]
static XDP_UDP_CT: HashMap<XdpUdpCtKey, XdpUdpCtValue> =
    HashMap::<XdpUdpCtKey, XdpUdpCtValue>::with_max_entries(262_144, 0);

/// Per-CPU byte/packet accounting for direct-forwarded flows; userspace
/// aggregates periodically into the billing pipeline so the fast path never
/// bypasses traffic accounting.
#[map(name = "XDP_FLOW_ACCT")]
static XDP_FLOW_ACCT: PerCpuHashMap<XdpUdpCtKey, XdpFlowAcct> =
    PerCpuHashMap::<XdpUdpCtKey, XdpFlowAcct>::with_max_entries(262_144, 0);

#[xdp]
pub fn cloud_node_xdp(ctx: XdpContext) -> u32 {
    match try_cloud_node_xdp(ctx) {
        Ok(action) => action,
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

fn try_cloud_node_xdp(ctx: XdpContext) -> Result<u32, ()> {
    counter_packet();
    let (eth_proto, ip_offset) = parse_eth_payload(&ctx)?;
    let action = match eth_proto {
        value if value == EtherType::Ipv4 as u16 => handle_ipv4(&ctx, ip_offset)?,
        value if value == EtherType::Ipv6 as u16 => handle_ipv6(&ctx, ip_offset)?,
        _ => xdp_action::XDP_PASS,
    };
    match action {
        x if x == xdp_action::XDP_DROP => counter_drop(),
        x if x == xdp_action::XDP_REDIRECT => counter_redirect(),
        _ => counter_pass(),
    }
    Ok(action)
}

fn parse_eth_payload(ctx: &XdpContext) -> Result<(u16, usize), ()> {
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    let mut eth_proto = unsafe { (*eth).ether_type };
    let mut offset = mem::size_of::<EthHdr>();

    if is_vlan_ethertype(eth_proto) {
        let vlan: *const VlanHdr = ptr_at(ctx, offset)?;
        eth_proto = unsafe { (*vlan).ether_type };
        offset += mem::size_of::<VlanHdr>();
    }
    if is_vlan_ethertype(eth_proto) {
        let vlan: *const VlanHdr = ptr_at(ctx, offset)?;
        eth_proto = unsafe { (*vlan).ether_type };
        offset += mem::size_of::<VlanHdr>();
    }

    Ok((eth_proto, offset))
}

fn is_vlan_ethertype(ethertype: u16) -> bool {
    ethertype == EtherType::Ieee8021q as u16
        || ethertype == EtherType::Ieee8021ad as u16
        || ethertype == EtherType::Ieee8021QinQ1 as u16
        || ethertype == EtherType::Ieee8021QinQ2 as u16
        || ethertype == EtherType::Ieee8021QinQ3 as u16
}

fn handle_ipv4(ctx: &XdpContext, ip_offset: usize) -> Result<u32, ()> {
    let ip: *const Ipv4Hdr = ptr_at(ctx, ip_offset)?;
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    if policy.is_none() {
        counter_map_miss();
    }
    let version = unsafe { (*ip).version() };
    let ihl = unsafe { (*ip).ihl() as usize };
    let total_len = unsafe { (*ip).tot_len() as usize };
    if version != 4 || ihl < mem::size_of::<Ipv4Hdr>() || total_len < ihl {
        return Err(());
    }
    let source = unsafe { (*ip).src_addr };
    let source_be = u32::from_be_bytes(source);
    let key = XdpIpv4Key { addr_be: source_be };
    // SAFETY: XDP programs may call the ktime helper; the returned monotonic
    // timestamp is only used for read-only rule deadline comparisons.
    let now_mono_ns = unsafe { bpf_ktime_get_ns() };
    if active_exact_v4(&XDP_ALLOWED_V4, &key, now_mono_ns)
        || active_lpm_v4(&XDP_ALLOWED_V4_LPM, source_be, now_mono_ns)
    {
        return Ok(xdp_action::XDP_PASS);
    }
    if active_exact_v4(&XDP_BLOCKED_V4, &key, now_mono_ns)
        || active_lpm_v4(&XDP_BLOCKED_V4_LPM, source_be, now_mono_ns)
    {
        return Ok(block_action(policy));
    }
    if unsafe { (*ip).frag_offset() != 0 || ((*ip).frag_flags() & 1) != 0 } {
        return Ok(xdp_action::XDP_PASS);
    }
    let protocol = unsafe { (*ip).proto };
    let l4_offset = ip_offset + ihl;
    if rate_limited_v4(ctx, &key, protocol, l4_offset, now_mono_ns) {
        counter_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }
    let destination_be = u32::from_be_bytes(unsafe { (*ip).dst_addr });
    if let Some(policy) = policy {
        if !local_ipv4_allowed(policy, ifindex, destination_be) {
            return Ok(xdp_action::XDP_PASS);
        }
        if protocol == IpProto::Udp as u8 && policy.mode == 2 {
            if let Some(action) = try_udp_nat_v4(
                ctx,
                ip_offset,
                l4_offset,
                total_len as u64,
                now_mono_ns,
            )? {
                return Ok(action);
            }
        }
    }
    Ok(maybe_redirect(ctx, policy, protocol, l4_offset))
}

fn handle_ipv6(ctx: &XdpContext, ip_offset: usize) -> Result<u32, ()> {
    let ip: *const Ipv6Hdr = ptr_at(ctx, ip_offset)?;
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    if policy.is_none() {
        counter_map_miss();
    }
    if unsafe { (*ip).version() } != 6 {
        return Err(());
    }
    let source = unsafe { (*ip).src_addr };
    let key = XdpIpv6Key { addr: source };
    // SAFETY: XDP programs may call the ktime helper; the returned monotonic
    // timestamp is only used for read-only rule deadline comparisons.
    let now_mono_ns = unsafe { bpf_ktime_get_ns() };
    if active_exact_v6(&XDP_ALLOWED_V6, &key, now_mono_ns)
        || active_lpm_v6(&XDP_ALLOWED_V6_LPM, source, now_mono_ns)
    {
        return Ok(xdp_action::XDP_PASS);
    }
    if active_exact_v6(&XDP_BLOCKED_V6, &key, now_mono_ns)
        || active_lpm_v6(&XDP_BLOCKED_V6_LPM, source, now_mono_ns)
    {
        return Ok(block_action(policy));
    }
    let payload_len = unsafe { u16::from_be_bytes((*ip).payload_len) as usize };
    let packet_end = ip_offset
        .checked_add(mem::size_of::<Ipv6Hdr>())
        .and_then(|offset| offset.checked_add(payload_len))
        .ok_or(())?;
    if packet_end > ctx.data_end().saturating_sub(ctx.data()) {
        return Err(());
    }
    let protocol = unsafe { (*ip).next_hdr };
    let (protocol, l4_offset) = match ipv6_transport_offset(
        ctx,
        protocol,
        ip_offset + mem::size_of::<Ipv6Hdr>(),
        packet_end,
    )? {
        Some(bounds) => bounds,
        None => return Ok(xdp_action::XDP_PASS),
    };
    let destination = unsafe { (*ip).dst_addr };
    if rate_limited_v6(ctx, &key, protocol, l4_offset, now_mono_ns) {
        counter_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }
    if let Some(policy) = policy {
        if !local_ipv6_allowed(policy, ifindex, destination) {
            return Ok(xdp_action::XDP_PASS);
        }
        if protocol == IpProto::Udp as u8 && policy.mode == 2 {
            if let Some(action) =
                try_udp_nat_v6(ctx, ip_offset, l4_offset, payload_len as u64, now_mono_ns)?
            {
                return Ok(action);
            }
        }
    }
    Ok(maybe_redirect(ctx, policy, protocol, l4_offset))
}

fn ipv6_transport_offset(
    ctx: &XdpContext,
    mut next_header: u8,
    mut offset: usize,
    packet_end: usize,
) -> Result<Option<(u8, usize)>, ()> {
    for _ in 0..8 {
        match next_header {
            value if value == IpProto::Tcp as u8 || value == IpProto::Udp as u8 => {
                return Ok(Some((next_header, offset)));
            }
            IP_PROTO_NO_NEXT => return Ok(None),
            IP_PROTO_HOP_BY_HOP | IP_PROTO_ROUTING | IP_PROTO_DEST_OPTS => {
                if offset + 2 > packet_end {
                    return Err(());
                }
                let current = read_u8(ctx, offset)?;
                let len = (read_u8(ctx, offset + 1)? as usize + 1) * 8;
                next_header = current;
                offset = offset.checked_add(len).ok_or(())?;
            }
            IP_PROTO_AH => {
                if offset + 2 > packet_end {
                    return Err(());
                }
                let current = read_u8(ctx, offset)?;
                let len = (read_u8(ctx, offset + 1)? as usize + 2) * 4;
                next_header = current;
                offset = offset.checked_add(len).ok_or(())?;
            }
            IP_PROTO_FRAGMENT => {
                if offset + 8 > packet_end {
                    return Err(());
                }
                let current = read_u8(ctx, offset)?;
                let frag_hi = read_u8(ctx, offset + 2)?;
                let frag_lo = read_u8(ctx, offset + 3)?;
                let fragment = u16::from_be_bytes([frag_hi, frag_lo]);
                if fragment & 0xfff9 != 0 {
                    return Ok(None);
                }
                next_header = current;
                offset = offset.checked_add(8).ok_or(())?;
            }
            _ => return Ok(None),
        }
        if offset > packet_end {
            return Err(());
        }
    }
    Ok(None)
}

fn block_action(policy: Option<&XdpInterfacePolicy>) -> u32 {
    match policy {
        Some(policy) if policy.mode == 1 || policy.mode == 2 => xdp_action::XDP_DROP,
        _ => xdp_action::XDP_PASS,
    }
}

fn maybe_redirect(
    ctx: &XdpContext,
    policy: Option<&XdpInterfacePolicy>,
    protocol: u8,
    l4_offset: usize,
) -> u32 {
    let Some(policy) = policy else {
        return xdp_action::XDP_PASS;
    };
    let queue = ctx.rx_queue_index();
    let ifindex = ctx.ingress_ifindex() as u32;
    if policy.mode != 2 {
        return xdp_action::XDP_PASS;
    }

    let mut steered_xsk: Option<u32> = None;
    match protocol {
        value if value == IpProto::Tcp as u8 => {
            let Ok(tcp) = ptr_at::<TcpHdr>(ctx, l4_offset) else {
                counter_parse_error();
                return xdp_action::XDP_PASS;
            };
            let dst_port_be = unsafe { u16::from_ne_bytes((*tcp).dest) };
            if !proxy_port_enabled(dst_port_be, protocol) {
                return xdp_action::XDP_PASS;
            }
        }
        value if value == IpProto::Udp as u8 => {
            let Ok(udp) = ptr_at::<UdpHdr>(ctx, l4_offset) else {
                counter_parse_error();
                return xdp_action::XDP_PASS;
            };
            let dst_port_be = unsafe { u16::from_ne_bytes((*udp).dst) };
            if !proxy_port_enabled(dst_port_be, protocol) {
                return xdp_action::XDP_PASS;
            }
            steered_xsk = quic_dcid_xsk_index(ctx, l4_offset + mem::size_of::<UdpHdr>());
        }
        _ => return xdp_action::XDP_PASS,
    }

    let xsk_key = XdpQueueKey {
        ifindex,
        queue_id: queue,
    };
    let default_xsk_index = unsafe { XDP_XSK_INDEX.get(&xsk_key) }.copied();
    let xsk_index = match steered_xsk.or(default_xsk_index) {
        Some(index) => index,
        None => {
            counter_map_miss();
            if policy.fallback_pass != 0 {
                return xdp_action::XDP_PASS;
            }
            return xdp_action::XDP_DROP;
        }
    };

    match XDP_XSKS.redirect(xsk_index, 0) {
        Ok(_) => xdp_action::XDP_REDIRECT,
        Err(_) => {
            counter_xsk_drop();
            if policy.fallback_pass != 0 {
                xdp_action::XDP_PASS
            } else {
                xdp_action::XDP_DROP
            }
        }
    }
}

/// Steer QUIC long-header packets to the XSK queue owning their connection.
/// Parses the long-header form `flags | version | dcid_len | dcid | scid_len |
/// scid`; short headers carry no DCID length and cannot be parsed statelessly,
/// so they keep RSS queue affinity (userspace resolves those flows through the
/// shared demux route table). Returns the mapped XSK index, or None to use the
/// receiving queue.
fn quic_dcid_xsk_index(ctx: &XdpContext, payload_offset: usize) -> Option<u32> {
    let first = read_u8(ctx, payload_offset).ok()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([
        read_u8(ctx, payload_offset + 1).ok()?,
        read_u8(ctx, payload_offset + 2).ok()?,
        read_u8(ctx, payload_offset + 3).ok()?,
        read_u8(ctx, payload_offset + 4).ok()?,
    ]);
    if version == 0 {
        return None;
    }
    let dcid_len = read_u8(ctx, payload_offset + 5).ok()? as usize;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let mut bytes = [0u8; 20];
    for i in 0..20usize {
        if i >= dcid_len {
            break;
        }
        bytes[i] = read_u8(ctx, payload_offset + 6 + i).ok()?;
    }
    let key = XdpQuicDcidKey {
        bytes,
        len: dcid_len as u8,
        _pad: [0; 3],
    };
    unsafe { XDP_QUIC_DCID.get(&key).copied() }
}

/// Per-IP fixed-window pps limiter. Only UDP datagrams and TCP SYN-without-ACK
/// (connection attempts) are counted; established flows are never throttled.
/// A full map fails open (pass + `ratelimit_map_full` counter) so the limiter
/// can never blackhole traffic on map exhaustion.
fn rate_limited_v4(
    ctx: &XdpContext,
    key: &XdpIpv4Key,
    protocol: u8,
    l4_offset: usize,
    now_mono_ns: u64,
) -> bool {
    let Some(cfg) = XDP_RATE_CFG.get(0).copied() else {
        return false;
    };
    let limit = match protocol {
        value if value == IpProto::Udp as u8 => cfg.udp_pps,
        value if value == IpProto::Tcp as u8 => {
            if cfg.tcp_syn_pps == 0 || !is_tcp_syn_attempt(ctx, l4_offset) {
                return false;
            }
            cfg.tcp_syn_pps
        }
        _ => return false,
    };
    if limit == 0 || cfg.window_ns == 0 {
        return false;
    }
    rate_bucket_hit_v4(key, limit, cfg.window_ns, now_mono_ns)
}

fn rate_limited_v6(
    ctx: &XdpContext,
    key: &XdpIpv6Key,
    protocol: u8,
    l4_offset: usize,
    now_mono_ns: u64,
) -> bool {
    let Some(cfg) = XDP_RATE_CFG.get(0).copied() else {
        return false;
    };
    let limit = match protocol {
        value if value == IpProto::Udp as u8 => cfg.udp_pps,
        value if value == IpProto::Tcp as u8 => {
            if cfg.tcp_syn_pps == 0 || !is_tcp_syn_attempt(ctx, l4_offset) {
                return false;
            }
            cfg.tcp_syn_pps
        }
        _ => return false,
    };
    if limit == 0 || cfg.window_ns == 0 {
        return false;
    }
    rate_bucket_hit_v6(key, limit, cfg.window_ns, now_mono_ns)
}

fn is_tcp_syn_attempt(ctx: &XdpContext, l4_offset: usize) -> bool {
    match ptr_at::<TcpHdr>(ctx, l4_offset) {
        Ok(tcp) => unsafe { (*tcp).syn() == 1 && (*tcp).ack() == 0 },
        Err(_) => false,
    }
}

/// Fold a one's-complement sum to 16 bits and complement it.
#[inline(always)]
fn csum_fold(mut sum: u64) -> u16 {
    let mut i = 0;
    while i < 4 {
        sum = (sum & 0xffff) + (sum >> 16);
        i += 1;
    }
    !(sum as u16)
}

/// Apply a `bpf_csum_diff` delta to an existing checksum field (stored value,
/// network order as it appears in the packet).
#[inline(always)]
fn csum_apply_diff(old_check: u16, diff: i64) -> u16 {
    let sum = (!(old_check) as u64).wrapping_add(diff as u64);
    csum_fold(sum)
}

#[inline(always)]
fn csum_diff_u32(old: &mut u32, new: &mut u32) -> i64 {
    // SAFETY: stack copies of packet words; the helper only reads them.
    unsafe { bpf_csum_diff(old as *mut u32, 4, new as *mut u32, 4, 0) }
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

fn v4_embed(addr_be: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&addr_be.to_be_bytes());
    out
}

/// Update the IPv4 header checksum after a 32-bit field change. `old`/`new`
/// are the raw memory-order words (`u32::from_ne_bytes` of the addr bytes).
fn ipv4_csum_update(ctx: &XdpContext, ip_offset: usize, old: u32, new: u32) -> Result<(), ()> {
    let ip = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
    let mut old_v = old;
    let mut new_v = new;
    let diff = csum_diff_u32(&mut old_v, &mut new_v);
    let old_check = unsafe { u16::from_ne_bytes((*ip).check) };
    unsafe { (*ip).check = csum_apply_diff(old_check, diff).to_ne_bytes() };
    Ok(())
}

/// Update the UDP checksum after a pseudo-header address change plus an
/// optional port change. `old_port`/`new_port` are raw memory-order u16s
/// (`u16::from_ne_bytes` of the port field). A zero checksum (v4 only) is
/// left alone.
#[allow(clippy::too_many_arguments)]
fn udp_csum_update(
    ctx: &XdpContext,
    l4_offset: usize,
    old_addr_words: &mut [u32; 4],
    new_addr_words: &mut [u32; 4],
    addr_word_count: usize,
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    let udp = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
    let old_check = unsafe { u16::from_ne_bytes((*udp).check) };
    if old_check == 0 {
        return Ok(());
    }
    let mut diff: i64 = 0;
    let mut i = 0;
    while i < addr_word_count {
        diff = unsafe {
            bpf_csum_diff(
                &mut old_addr_words[i] as *mut u32,
                4,
                &mut new_addr_words[i] as *mut u32,
                4,
                diff as u32,
            )
        };
        i += 1;
    }
    if old_port != new_port {
        // The port is a 16-bit word; place it in the low two bytes of the
        // diff buffer (memory order) with zero padding.
        let mut old_p = old_port as u32;
        let mut new_p = new_port as u32;
        diff = unsafe {
            bpf_csum_diff(&mut old_p as *mut u32, 4, &mut new_p as *mut u32, 4, diff as u32)
        };
    }
    unsafe { (*udp).check = csum_apply_diff(old_check, diff).to_ne_bytes() };
    Ok(())
}

fn acct_flow(
    key: &XdpUdpCtKey,
    rx_bytes: u64,
    tx_bytes: u64,
    server_id: i64,
    now_mono_ns: u64,
) {
    if let Some(acct) = XDP_FLOW_ACCT.get_ptr_mut(key) {
        // SAFETY: per-CPU map value, exclusively owned by this CPU.
        let acct = unsafe { &mut *acct };
        acct.rx_bytes = acct.rx_bytes.saturating_add(rx_bytes);
        acct.tx_bytes = acct.tx_bytes.saturating_add(tx_bytes);
        acct.rx_pkts = acct.rx_pkts.saturating_add(u64::from(rx_bytes > 0));
        acct.tx_pkts = acct.tx_pkts.saturating_add(u64::from(tx_bytes > 0));
        acct.last_seen_ns = now_mono_ns;
        acct.server_id = server_id;
        return;
    }
    let acct = XdpFlowAcct {
        rx_bytes,
        tx_bytes,
        rx_pkts: u64::from(rx_bytes > 0),
        tx_pkts: u64::from(tx_bytes > 0),
        last_seen_ns: now_mono_ns,
        server_id,
    };
    if XDP_FLOW_ACCT.insert(key, &acct, 0).is_err() {
        counter_udp_fwd_map_full();
    }
}

/// Rewrite Ethernet addresses for same-interface transmission: destination
/// becomes the supplied next-hop (backend/gateway or client) MAC and source
/// becomes the inbound destination MAC (this interface's own address).
fn eth_rewrite(ctx: &XdpContext, dst_mac: [u8; 6]) -> Result<(), ()> {
    let eth = ptr_at_mut::<EthHdr>(ctx, 0)?;
    unsafe {
        (*eth).src_addr = (*eth).dst_addr;
        (*eth).dst_addr = dst_mac;
    }
    Ok(())
}

fn counter_udp_fwd_tx() {
    if let Some(counters) = counters() {
        counters.udp_fwd_tx = counters.udp_fwd_tx.saturating_add(1);
    }
}

fn counter_udp_fwd_map_full() {
    if let Some(counters) = counters() {
        counters.udp_fwd_map_full = counters.udp_fwd_map_full.saturating_add(1);
    }
}

fn rate_bucket_hit_v4(
    key: &XdpIpv4Key,
    limit: u64,
    window_ns: u64,
    now_mono_ns: u64,
) -> bool {
    if let Some(bucket) = XDP_RATE_V4.get_ptr_mut(key) {
        // SAFETY: `bucket` points into the map value for `key`; the update races
        // with other CPUs by design (fixed-window limiter tolerates slight
        // overcount-adjacent drift).
        let bucket = unsafe { &mut *bucket };
        if now_mono_ns.saturating_sub(bucket.window_start_ns) >= window_ns {
            bucket.window_start_ns = now_mono_ns;
            bucket.count = 1;
            return false;
        }
        bucket.count = bucket.count.saturating_add(1);
        return bucket.count > limit;
    }
    let bucket = XdpRateBucket {
        window_start_ns: now_mono_ns,
        count: 1,
    };
    match XDP_RATE_V4.insert(key, &bucket, 0) {
        Ok(()) => false,
        Err(_) => {
            counter_ratelimit_map_full();
            false
        }
    }
}

fn rate_bucket_hit_v6(
    key: &XdpIpv6Key,
    limit: u64,
    window_ns: u64,
    now_mono_ns: u64,
) -> bool {
    if let Some(bucket) = XDP_RATE_V6.get_ptr_mut(key) {
        // SAFETY: see rate_bucket_hit_v4.
        let bucket = unsafe { &mut *bucket };
        if now_mono_ns.saturating_sub(bucket.window_start_ns) >= window_ns {
            bucket.window_start_ns = now_mono_ns;
            bucket.count = 1;
            return false;
        }
        bucket.count = bucket.count.saturating_add(1);
        return bucket.count > limit;
    }
    let bucket = XdpRateBucket {
        window_start_ns: now_mono_ns,
        count: 1,
    };
    match XDP_RATE_V6.insert(key, &bucket, 0) {
        Ok(()) => false,
        Err(_) => {
            counter_ratelimit_map_full();
            false
        }
    }
}

/// UDP direct forward / NAT, IPv4. Returns `Some(action)` when the packet was
/// handled (XDP_TX); `None` falls through to the normal redirect/PASS path so
/// a forward-map miss never drops traffic silently.
fn try_udp_nat_v4(
    ctx: &XdpContext,
    ip_offset: usize,
    l4_offset: usize,
    packet_len: u64,
    now_mono_ns: u64,
) -> Result<Option<u32>, ()> {
    let udp = ptr_at::<UdpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*udp).src) };
    let dst_port = unsafe { u16::from_ne_bytes((*udp).dst) };
    let ip = ptr_at::<Ipv4Hdr>(ctx, ip_offset)?;
    let src_addr = unsafe { (*ip).src_addr };
    let dst_addr = unsafe { (*ip).dst_addr };
    let src_be = u32::from_be_bytes(src_addr);
    let dst_be = u32::from_be_bytes(dst_addr);

    // Reply path: source is a backend serving a tracked client flow.
    let ct_key = XdpUdpCtKey {
        client_addr: v4_embed(dst_be),
        backend_addr: v4_embed(src_be),
        client_port_be: dst_port,
        backend_port_be: src_port,
        family: 4,
        _pad: [0; 3],
    };
    if let Some(ct) = XDP_UDP_CT.get_ptr_mut(&ct_key) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        ct.last_seen_ns = now_mono_ns;
        let listen_be = u32::from_be_bytes([ct.listen_addr[0], ct.listen_addr[1], ct.listen_addr[2], ct.listen_addr[3]]);
        // Rewrite source -> listen tuple.
        let mut old_w = [u32::from_ne_bytes(src_addr), 0, 0, 0];
        let mut new_w = [u32::from_ne_bytes(listen_be.to_be_bytes()), 0, 0, 0];
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = listen_be.to_be_bytes() };
        ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(src_addr), u32::from_ne_bytes(listen_be.to_be_bytes()))?;
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = ct.listen_port_be.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, &mut old_w, &mut new_w, 1, src_port, ct.listen_port_be)?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(&ct_key, 0, packet_len, ct.server_id, now_mono_ns);
        counter_udp_fwd_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    // Forward path: destination is a configured direct-forward listen tuple.
    let fwd_key = XdpUdpFwdKey::new_v4(dst_be, dst_port);
    let Some(rule) = (unsafe { XDP_UDP_FWD.get(&fwd_key) }) else {
        return Ok(None);
    };
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let client_mac = unsafe { (*eth).src_addr };
    let backend_be = u32::from_be_bytes([
        rule.backend_addr[0],
        rule.backend_addr[1],
        rule.backend_addr[2],
        rule.backend_addr[3],
    ]);
    let ct_key = XdpUdpCtKey {
        client_addr: v4_embed(src_be),
        backend_addr: rule.backend_addr,
        client_port_be: src_port,
        backend_port_be: rule.backend_port_be,
        family: 4,
        _pad: [0; 3],
    };
    let ct_value = XdpUdpCtValue {
        listen_addr: v4_embed(dst_be),
        client_mac,
        listen_port_be: dst_port,
        family: 4,
        server_id: rule.server_id,
        last_seen_ns: now_mono_ns,
    };
    if let Some(ct) = XDP_UDP_CT.get_ptr_mut(&ct_key) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        *ct = ct_value;
    } else if XDP_UDP_CT.insert(&ct_key, &ct_value, 0).is_err() {
        // Fail explicit: report and leave the packet to the normal path so a
        // full conntrack table degrades to userspace handling, not drops.
        counter_udp_fwd_map_full();
        return Ok(None);
    }
    // Rewrite destination -> backend.
    let mut old_w = [u32::from_ne_bytes(dst_addr), 0, 0, 0];
    let mut new_w = [u32::from_ne_bytes(backend_be.to_be_bytes()), 0, 0, 0];
    let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
    unsafe { (*ip_hdr).dst_addr = backend_be.to_be_bytes() };
    ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(dst_addr), u32::from_ne_bytes(backend_be.to_be_bytes()))?;
    let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
    unsafe { (*udp_hdr).dst = rule.backend_port_be.to_ne_bytes() };
    udp_csum_update(ctx, l4_offset, &mut old_w, &mut new_w, 1, dst_port, rule.backend_port_be)?;
    eth_rewrite(ctx, rule.next_hop_mac)?;
    acct_flow(&ct_key, packet_len, 0, rule.server_id, now_mono_ns);
    counter_udp_fwd_tx();
    Ok(Some(xdp_action::XDP_TX))
}

/// UDP direct forward / NAT, IPv6. Same contract as `try_udp_nat_v4`; the
/// IPv6 header has no checksum, but the UDP checksum covers the pseudo-header
/// addresses and is mandatory, so it is always updated when non-zero (a zero
/// checksum is preserved rather than fabricated over unseen payload).
fn try_udp_nat_v6(
    ctx: &XdpContext,
    ip_offset: usize,
    l4_offset: usize,
    packet_len: u64,
    now_mono_ns: u64,
) -> Result<Option<u32>, ()> {
    let udp = ptr_at::<UdpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*udp).src) };
    let dst_port = unsafe { u16::from_ne_bytes((*udp).dst) };
    let ip = ptr_at::<Ipv6Hdr>(ctx, ip_offset)?;
    let src_addr = unsafe { (*ip).src_addr };
    let dst_addr = unsafe { (*ip).dst_addr };

    let ct_key = XdpUdpCtKey {
        client_addr: dst_addr,
        backend_addr: src_addr,
        client_port_be: dst_port,
        backend_port_be: src_port,
        family: 6,
        _pad: [0; 3],
    };
    if let Some(ct) = XDP_UDP_CT.get_ptr_mut(&ct_key) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        ct.last_seen_ns = now_mono_ns;
        let mut old_w = words16(src_addr);
        let mut new_w = words16(ct.listen_addr);
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = ct.listen_addr };
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = ct.listen_port_be.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, &mut old_w, &mut new_w, 4, src_port, ct.listen_port_be)?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(&ct_key, 0, packet_len, ct.server_id, now_mono_ns);
        counter_udp_fwd_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    let fwd_key = XdpUdpFwdKey::new_v6(dst_addr, dst_port);
    let Some(rule) = (unsafe { XDP_UDP_FWD.get(&fwd_key) }) else {
        return Ok(None);
    };
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let client_mac = unsafe { (*eth).src_addr };
    let ct_key = XdpUdpCtKey {
        client_addr: src_addr,
        backend_addr: rule.backend_addr,
        client_port_be: src_port,
        backend_port_be: rule.backend_port_be,
        family: 6,
        _pad: [0; 3],
    };
    let ct_value = XdpUdpCtValue {
        listen_addr: dst_addr,
        client_mac,
        listen_port_be: dst_port,
        family: 6,
        server_id: rule.server_id,
        last_seen_ns: now_mono_ns,
    };
    if let Some(ct) = XDP_UDP_CT.get_ptr_mut(&ct_key) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        *ct = ct_value;
    } else if XDP_UDP_CT.insert(&ct_key, &ct_value, 0).is_err() {
        counter_udp_fwd_map_full();
        return Ok(None);
    }
    let mut old_w = words16(dst_addr);
    let mut new_w = words16(rule.backend_addr);
    let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
    unsafe { (*ip_hdr).dst_addr = rule.backend_addr };
    let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
    unsafe { (*udp_hdr).dst = rule.backend_port_be.to_ne_bytes() };
    udp_csum_update(ctx, l4_offset, &mut old_w, &mut new_w, 4, dst_port, rule.backend_port_be)?;
    eth_rewrite(ctx, rule.next_hop_mac)?;
    acct_flow(&ct_key, packet_len, 0, rule.server_id, now_mono_ns);
    counter_udp_fwd_tx();
    Ok(Some(xdp_action::XDP_TX))
}

/// Read a 16-byte IPv6 address as four memory-order 32-bit words for
/// `bpf_csum_diff`.
fn words16(addr: [u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([addr[0], addr[1], addr[2], addr[3]]),
        u32::from_ne_bytes([addr[4], addr[5], addr[6], addr[7]]),
        u32::from_ne_bytes([addr[8], addr[9], addr[10], addr[11]]),
        u32::from_ne_bytes([addr[12], addr[13], addr[14], addr[15]]),
    ]
}

fn local_ipv4_allowed(policy: &XdpInterfacePolicy, ifindex: u32, destination_be: u32) -> bool {
    if policy.local_ip_filter == 0 {
        return true;
    }
    let key = XdpLocalIpv4Key::new(ifindex, destination_be);
    unsafe { XDP_LOCAL_V4.get(&key).is_some() }
}

fn local_ipv6_allowed(policy: &XdpInterfacePolicy, ifindex: u32, destination: [u8; 16]) -> bool {
    if policy.local_ip_filter == 0 {
        return true;
    }
    let key = XdpLocalIpv6Key::new(ifindex, destination);
    unsafe { XDP_LOCAL_V6.get(&key).is_some() }
}

fn active_exact_v4(
    map: &HashMap<XdpIpv4Key, XdpRuleValue>,
    key: &XdpIpv4Key,
    now_mono_ns: u64,
) -> bool {
    match unsafe { map.get(key) } {
        Some(value) => active_rule(value, now_mono_ns),
        None => false,
    }
}

fn active_exact_v6(
    map: &HashMap<XdpIpv6Key, XdpRuleValue>,
    key: &XdpIpv6Key,
    now_mono_ns: u64,
) -> bool {
    match unsafe { map.get(key) } {
        Some(value) => active_rule(value, now_mono_ns),
        None => false,
    }
}

fn active_lpm_v4(map: &LpmTrie<u32, XdpRuleValue>, addr_be: u32, now_mono_ns: u64) -> bool {
    let key = LpmKey::new(32, addr_be);
    match map.get(&key) {
        Some(value) => active_rule(value, now_mono_ns),
        None => false,
    }
}

fn active_lpm_v6(map: &LpmTrie<[u8; 16], XdpRuleValue>, addr: [u8; 16], now_mono_ns: u64) -> bool {
    let key = LpmKey::new(128, addr);
    match map.get(&key) {
        Some(value) => active_rule(value, now_mono_ns),
        None => false,
    }
}

fn active_rule(value: &XdpRuleValue, now_mono_ns: u64) -> bool {
    value.is_active_at_mono(now_mono_ns)
}

fn proxy_port_enabled(port_be: u16, protocol: u8) -> bool {
    let key = XdpPortProtoKey {
        port_be,
        proto: protocol,
        _pad: 0,
    };
    unsafe { XDP_PROXY_PORTS.get(&key).is_some() }
}

fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn read_u8(ctx: &XdpContext, offset: usize) -> Result<u8, ()> {
    let byte: *const u8 = ptr_at(ctx, offset)?;
    Ok(unsafe { *byte })
}

fn counters() -> Option<&'static mut XdpCounters> {
    XDP_COUNTERS.get_ptr_mut(0).map(|ptr| unsafe { &mut *ptr })
}

fn counter_packet() {
    if let Some(counters) = counters() {
        counters.packets = counters.packets.saturating_add(1);
    }
}

fn counter_pass() {
    if let Some(counters) = counters() {
        counters.pass = counters.pass.saturating_add(1);
    }
}

fn counter_drop() {
    if let Some(counters) = counters() {
        counters.drop = counters.drop.saturating_add(1);
    }
}

fn counter_redirect() {
    if let Some(counters) = counters() {
        counters.redirect = counters.redirect.saturating_add(1);
    }
}

fn counter_parse_error() {
    if let Some(counters) = counters() {
        counters.parse_errors = counters.parse_errors.saturating_add(1);
    }
}

fn counter_map_miss() {
    if let Some(counters) = counters() {
        counters.map_miss = counters.map_miss.saturating_add(1);
    }
}

fn counter_xsk_drop() {
    if let Some(counters) = counters() {
        counters.xsk_drops = counters.xsk_drops.saturating_add(1);
    }
}

fn counter_rate_limited() {
    if let Some(counters) = counters() {
        counters.rate_limited = counters.rate_limited.saturating_add(1);
    }
}

fn counter_ratelimit_map_full() {
    if let Some(counters) = counters() {
        counters.ratelimit_map_full = counters.ratelimit_map_full.saturating_add(1);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
