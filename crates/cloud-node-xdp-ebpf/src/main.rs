#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_csum_diff, bpf_ktime_get_ns},
    macros::{map, xdp},
    maps::{Array, HashMap, LpmTrie, PerCpuArray, PerCpuHashMap, ProgramArray, XskMap, lpm_trie::Key as LpmKey},
    programs::XdpContext,
};
use cloud_node_xdp_common::{
    XdpCounters, XdpFlowAcct, XdpInterfacePolicy, XdpIpv4Key, XdpIpv6Key, XdpLocalIpv4Key,
    XdpLocalIpv6Key, XdpPortProtoKey, XdpQueueKey, XdpQuicDcidKey, XdpRateBucket,
    XdpRateLimitConfig, XdpRuleValue, XdpSnatRevKey, XdpSnatRevValue, XdpUdpCtKey,
    XdpUdpCtValue, XdpUdpFwdKey, XdpUdpFwdRule, XDP_CT_STATE_CLOSING, XDP_CT_STATE_OPEN,
    XDP_SNI_MAX_LEN, XDP_SNAT_PORT_BASE, XDP_SNAT_PORT_SPAN,
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

/// Explicitly configured TCP listen tuples for full L4 passthrough NAT
/// (XDP_TX, no userspace proxy involvement). Conntrack is created only on a
/// bare SYN; anything else without state falls through to the userspace path.
#[map(name = "XDP_TCP_FWD")]
static XDP_TCP_FWD: HashMap<XdpUdpFwdKey, XdpUdpFwdRule> =
    HashMap::<XdpUdpFwdKey, XdpUdpFwdRule>::with_max_entries(4096, 0);

#[map(name = "XDP_TCP_CT")]
static XDP_TCP_CT: HashMap<XdpUdpCtKey, XdpUdpCtValue> =
    HashMap::<XdpUdpCtKey, XdpUdpCtValue>::with_max_entries(262_144, 0);

/// SNAT reverse bindings: (listen addr, allocated node port, proto) -> client
/// flow tuple. Claimed with BPF_NOEXIST by `snat_alloc`; orphan entries are
/// reaped by the userspace sweeper once the owning conntrack entry expires.
#[map(name = "XDP_SNAT_REV")]
static XDP_SNAT_REV: HashMap<XdpSnatRevKey, XdpSnatRevValue> =
    HashMap::<XdpSnatRevKey, XdpSnatRevValue>::with_max_entries(65_536, 0);

/// Per-CPU scratch space for NAT/DCID key construction. eBPF stack is capped
/// at 512 bytes and the conntrack/forward keys plus values exceed it when
/// inlined, so large temporaries are built in this map instead. Internal only;
/// never read by userspace.
#[repr(C)]
struct NatScratch {
    fwd_key: XdpUdpFwdKey,
    ct_key: XdpUdpCtKey,
    ct_value: XdpUdpCtValue,
    dcid_key: XdpQuicDcidKey,
    csum_old: [u32; 4],
    csum_new: [u32; 4],
    snat_rev_key: XdpSnatRevKey,
    snat_rev_value: XdpSnatRevValue,
    /// Packet header snapshots for the IPv6 handlers: keeping the two 16-byte
    /// addresses in the per-CPU map instead of locals keeps those frames
    /// under the 512-byte verifier stack limit.
    pkt_src: [u8; 16],
    pkt_dst: [u8; 16],
}

#[map(name = "XDP_NAT_SCRATCH")]
static XDP_NAT_SCRATCH: PerCpuArray<NatScratch> =
    PerCpuArray::<NatScratch>::with_max_entries(1, 0);

/// Tail-call table into the NAT subprogram. The NAT handlers need their own
/// 512-byte stack and instruction budget, so they run as a separate XDP
/// program; slot 0 = `xdp_nat_dispatch`.
#[map(name = "XDP_DISPATCH")]
static XDP_DISPATCH: ProgramArray = ProgramArray::with_max_entries(8, 0);

/// Lowercased-SNI FNV-1a hashes blocked at line rate. Only evaluated on TCP
/// segments whose payload starts a TLS handshake record; anything that does
/// not parse completely falls through to the userspace dataplane.
#[map(name = "XDP_SNI_BLOCK")]
static XDP_SNI_BLOCK: HashMap<u64, u32> = HashMap::<u64, u32>::with_max_entries(65_536, 0);

const XDP_DISPATCH_NAT: u32 = 0;
const XDP_DISPATCH_SNI: u32 = 1;
const XDP_DISPATCH_NAT_TCP: u32 = 2;
const XDP_DISPATCH_NAT_UDP6: u32 = 3;
const XDP_DISPATCH_NAT_TCP6: u32 = 4;
const XDP_DISPATCH_NAT_UDP6_FWD: u32 = 5;
const XDP_DISPATCH_NAT_TCP6_FWD: u32 = 6;

#[inline(always)]
fn nat_scratch() -> Result<*mut NatScratch, ()> {
    XDP_NAT_SCRATCH.get_ptr_mut(0).ok_or(())
}

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

/// NAT subprogram entered via tail call. Runs the configured direct-forward
/// handlers for the packet whose context the parent parked in XDP_NAT_SCRATCH,
/// then falls through to the same redirect/PASS decision the parent would make.
#[xdp]
pub fn xdp_nat_dispatch(ctx: XdpContext) -> u32 {
    match try_nat_dispatch(&ctx) {
        Ok(action) => action,
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

/// Shared frame parse for the tail-call subprograms. Each subprogram
/// re-parses the packet: offsets handed over through the scratch map arrive
/// as unbounded scalars and lose the verifier's packet range tracking,
/// whereas parsing derives them with proper bounds. Returns Err for packets
/// that should simply take the normal path.
#[allow(clippy::type_complexity)]
#[inline(always)]
/// `F` fixes the expected address family at compile time: each per-family
/// tail-call dispatcher monomorphizes away the other family's parse branch,
/// which halves the verifier's explored-state space on older kernels.
fn parse_frame<const F: u8>(
    ctx: &XdpContext,
) -> Result<(u8, usize, u8, usize, u64, u32, Option<&'static XdpInterfacePolicy>), ()> {
    let (eth_proto, ip_offset) = parse_eth_payload(ctx)?;
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let (family, proto, l4_offset, packet_len) = if F == 4 && eth_proto == EtherType::Ipv4 as u16 {
        let ip = ptr_at::<Ipv4Hdr>(ctx, ip_offset)?;
        let ihl = unsafe { (*ip).ihl() as usize };
        let total_len = unsafe { (*ip).tot_len() as usize };
        if unsafe { (*ip).version() } != 4
            || ihl < mem::size_of::<Ipv4Hdr>()
            || total_len < ihl
        {
            return Err(());
        }
        if unsafe { (*ip).frag_offset() } != 0 || unsafe { (*ip).frag_flags() & 1 } != 0 {
            return Err(());
        }
        (
            4u8,
            unsafe { (*ip).proto },
            ip_offset + ihl,
            total_len as u64,
        )
    } else if F == 6 && eth_proto == EtherType::Ipv6 as u16 {
        let ip = ptr_at::<Ipv6Hdr>(ctx, ip_offset)?;
        if unsafe { (*ip).version() } != 6 {
            return Err(());
        }
        let payload_len = unsafe { u16::from_be_bytes((*ip).payload_len) as usize };
        let packet_end = ip_offset
            .checked_add(mem::size_of::<Ipv6Hdr>())
            .and_then(|offset| offset.checked_add(payload_len))
            .ok_or(())?;
        if packet_end > ctx.data_end().saturating_sub(ctx.data()) {
            return Err(());
        }
        let next = unsafe { (*ip).next_hdr };
        let Some((proto, l4_offset)) = ipv6_transport_offset(
            ctx,
            next,
            ip_offset + mem::size_of::<Ipv6Hdr>(),
            packet_end,
        )? else {
            return Err(());
        };
        (6u8, proto, l4_offset, payload_len as u64)
    } else {
        return Err(());
    };
    Ok((family, ip_offset, proto, l4_offset, packet_len, ifindex, policy))
}

fn try_nat_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, _, policy) = parse_frame::<4>(ctx)?;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let action = if proto == IpProto::Udp as u8 {
        try_udp_nat_v4(ctx, ip_offset, l4_offset, packet_len, now_ns)?
    } else {
        None
    };
    if let Some(action) = action {
        return Ok(action);
    }
    Ok(maybe_redirect(ctx, policy, proto, l4_offset))
}

/// Per-family NAT dispatchers: one (family, proto) pair per tail-call target
/// keeps each verifier run under the pre-6.6 explored-state budget - the
/// SNAT/reverse-lookup branches in a single handler are already ~10KiB of
/// BPF, and pairing families in one program multiplies states past 1M insns.
fn try_nat_udp6_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, _, policy) = parse_frame::<6>(ctx)?;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if proto == IpProto::Udp as u8 {
        if let Some(action) = try_udp_nat_v6(ctx, ip_offset, l4_offset, packet_len, now_ns)? {
            return Ok(action);
        }
        // The forward half lives in its own tail-call program: keeping the
        // full handler here pushes the kernel 6.1 verifier past its explored-
        // state budget. An empty slot returns immediately.
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_UDP6_FWD) };
    }
    Ok(maybe_redirect(ctx, policy, proto, l4_offset))
}

fn try_nat_udp6_fwd(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, _, policy) = parse_frame::<6>(ctx)?;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let action = if proto == IpProto::Udp as u8 {
        try_udp_nat_v6_fwd(ctx, ip_offset, l4_offset, packet_len, now_ns)?
    } else {
        None
    };
    if let Some(action) = action {
        return Ok(action);
    }
    Ok(maybe_redirect(ctx, policy, proto, l4_offset))
}

#[xdp]
pub fn xdp_nat_udp6_fwd(ctx: XdpContext) -> u32 {
    match try_nat_udp6_fwd(&ctx) {
        Ok(action) => action,
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

fn try_nat_tcp_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, _, policy) = parse_frame::<4>(ctx)?;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let action = if proto == IpProto::Tcp as u8 {
        try_tcp_nat_v4(ctx, ip_offset, l4_offset, packet_len, now_ns)?
    } else {
        None
    };
    if let Some(action) = action {
        return Ok(action);
    }
    Ok(maybe_redirect(ctx, policy, proto, l4_offset))
}

fn try_nat_tcp6_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, _, policy) = parse_frame::<6>(ctx)?;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if proto == IpProto::Tcp as u8 {
        if let Some(action) = try_tcp_nat_v6(ctx, ip_offset, l4_offset, packet_len, now_ns)? {
            return Ok(action);
        }
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP6_FWD) };
    }
    Ok(maybe_redirect(ctx, policy, proto, l4_offset))
}

fn try_nat_tcp6_fwd(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, _, policy) = parse_frame::<6>(ctx)?;
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let action = if proto == IpProto::Tcp as u8 {
        try_tcp_nat_v6_fwd(ctx, ip_offset, l4_offset, packet_len, now_ns)?
    } else {
        None
    };
    if let Some(action) = action {
        return Ok(action);
    }
    Ok(maybe_redirect(ctx, policy, proto, l4_offset))
}

#[xdp]
pub fn xdp_nat_tcp6_fwd(ctx: XdpContext) -> u32 {
    match try_nat_tcp6_fwd(&ctx) {
        Ok(action) => action,
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_tcp_dispatch(ctx: XdpContext) -> u32 {
    match try_nat_tcp_dispatch(&ctx) {
        Ok(action) => action,
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_udp6_dispatch(ctx: XdpContext) -> u32 {
    match try_nat_udp6_dispatch(&ctx) {
        Ok(action) => action,
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_tcp6_dispatch(ctx: XdpContext) -> u32 {
    match try_nat_tcp6_dispatch(&ctx) {
        Ok(action) => action,
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

/// SNI subprogram entered via tail call ahead of NAT. Runs the TLS
/// ClientHello blocklist check on TCP segments; on pass it chains into the
/// NAT dispatcher, and falls back to the same redirect/PASS decision when
/// the NAT slot is empty.
#[xdp]
pub fn xdp_sni_dispatch(ctx: XdpContext) -> u32 {
    match try_sni_dispatch(&ctx) {
        Ok(action) => action,
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

/// Minimal reparse for the SNI subprogram: the ClientHello check only needs
/// the transport offset and protocol. The full `parse_frame` result (policy
/// map value, packet_len, family) is unnecessary here, and every extra live
/// value at the hash loop multiplies the verifier's explored-state count.
/// Returns the L4 proto and offset, or Err for packets that take the normal
/// path (non-IP, malformed, fragmented - identical to `parse_frame`).
fn sni_frame_proto(ctx: &XdpContext) -> Result<(u8, usize), ()> {
    let (eth_proto, ip_offset) = parse_eth_payload(ctx)?;
    if eth_proto == EtherType::Ipv4 as u16 {
        let ip = ptr_at::<Ipv4Hdr>(ctx, ip_offset)?;
        let ihl = unsafe { (*ip).ihl() as usize };
        if unsafe { (*ip).version() } != 4
            || ihl < mem::size_of::<Ipv4Hdr>()
            || unsafe { (*ip).tot_len() as usize } < ihl
        {
            return Err(());
        }
        if unsafe { (*ip).frag_offset() } != 0 || unsafe { (*ip).frag_flags() & 1 } != 0 {
            return Err(());
        }
        Ok((unsafe { (*ip).proto }, ip_offset + ihl))
    } else if eth_proto == EtherType::Ipv6 as u16 {
        let ip = ptr_at::<Ipv6Hdr>(ctx, ip_offset)?;
        if unsafe { (*ip).version() } != 6 {
            return Err(());
        }
        let payload_len = unsafe { u16::from_be_bytes((*ip).payload_len) as usize };
        let packet_end = ip_offset
            .checked_add(mem::size_of::<Ipv6Hdr>())
            .and_then(|offset| offset.checked_add(payload_len))
            .ok_or(())?;
        if packet_end > ctx.data_end().saturating_sub(ctx.data()) {
            return Err(());
        }
        let next = unsafe { (*ip).next_hdr };
        ipv6_transport_offset(ctx, next, ip_offset + mem::size_of::<Ipv6Hdr>(), packet_end)
            .and_then(|v| v.ok_or(()))
    } else {
        Err(())
    }
}

#[inline(always)]
fn sni_family_hint(ctx: &XdpContext) -> u8 {
    let Ok(eth) = ptr_at::<EthHdr>(ctx, 0) else {
        return 0;
    };
    if unsafe { (*eth).ether_type } == EtherType::Ipv6 as u16 {
        6
    } else {
        4
    }
}

fn try_sni_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (proto, l4_offset) = sni_frame_proto(ctx)?;
    let family = sni_family_hint(ctx);
    if proto == IpProto::Tcp as u8 {
        // Err must NOT skip the NAT chain: `try_sni_block` errors on ordinary
        // segments too (e.g. a bare SYN whose payload offset is past packet
        // end), and returning Err here would PASS them past the NAT program
        // and break DNAT on the configured forwards.
        match try_sni_block(ctx, l4_offset) {
            Ok(SNI_BLOCK) => {
                counter_sni_blocked();
                return Ok(xdp_action::XDP_DROP);
            }
            Ok(SNI_INCOMPLETE) => counter_sni_incomplete(),
            _ => {}
        }
    }
    // Chain into NAT; the tail call only returns when the slot is empty, in
    // which case this program must still make the redirect/PASS decision the
    // parent would have made.
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    if family == 6 {
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP6) };
    } else {
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP) };
    }
    Ok(maybe_redirect(ctx, policy, proto, l4_offset))
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
        if policy.mode == 2 {
            if protocol == IpProto::Tcp as u8 {
                // TCP enters through the SNI dispatcher, which chains into
                // NAT. A tail call only returns when the slot is empty:
                // explicit fallback to the redirect/PASS path, never a drop.
                unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_SNI) };
                unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP) };
            } else if protocol == IpProto::Udp as u8 {
                unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT) };
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
        if policy.mode == 2 {
            if protocol == IpProto::Tcp as u8 {
                unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_SNI) };
                unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP6) };
            } else if protocol == IpProto::Udp as u8 {
                unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_UDP6) };
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
#[inline(never)]
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
    let scratch = nat_scratch().ok()?;
    let key = unsafe { &mut (*scratch).dcid_key };
    key.len = dcid_len as u8;
    key._pad = [0; 3];
    for i in 0..20usize {
        if i >= dcid_len {
            key.bytes[i] = 0;
        } else {
            key.bytes[i] = read_u8(ctx, payload_offset + 6 + i).ok()?;
        }
    }
    unsafe { XDP_QUIC_DCID.get(&(*scratch).dcid_key).copied() }
}

/// Per-IP fixed-window pps limiter. Only UDP datagrams and TCP SYN-without-ACK
/// (connection attempts) are counted; established flows are never throttled.
/// A full map fails open (pass + `ratelimit_map_full` counter) so the limiter
/// can never blackhole traffic on map exhaustion.
#[inline(never)]
fn rate_limited_v4(
    ctx: &XdpContext,
    key: &XdpIpv4Key,
    protocol: u8,
    l4_offset: usize,
    now_mono_ns: u64,
) -> bool {
    let Some(cfg) = XDP_RATE_CFG.get(0) else {
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

#[inline(never)]
fn rate_limited_v6(
    ctx: &XdpContext,
    key: &XdpIpv6Key,
    protocol: u8,
    l4_offset: usize,
    now_mono_ns: u64,
) -> bool {
    let Some(cfg) = XDP_RATE_CFG.get(0) else {
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



/// Inspect a TCP segment for a TLS ClientHello and drop when its SNI hash is
/// blocklisted. Returns Some(XDP_DROP) on a block, None to continue the
/// normal path. Records that do not fully parse count as `sni_incomplete`
/// and pass - userspace remains the authoritative SNI implementation.
/// Inlined into the dispatcher: as a separate call LLVM specializes its
/// context argument into raw packet pointers and emits prohibited shift
/// arithmetic on them.
/// 0 = pass, 1 = block/drop, 2 = parsed-incomplete (pass, counted once by
/// the dispatcher).
const SNI_PASS: u32 = 0;
const SNI_BLOCK: u32 = 1;
const SNI_INCOMPLETE: u32 = 2;

#[inline(always)]
fn try_sni_block(ctx: &XdpContext, l4_offset: usize) -> Result<u32, ()> {
    // Read the data-offset byte directly: the `TcpHdr::doff` bitfield helper
    // compiles to a sign-extending reconstruction whose smin poisons the
    // packet-pointer arithmetic below on pre-6.6 verifiers.
    let doff = (read_u8(ctx, l4_offset + 12)? >> 4) as usize;
    if !(5..=15).contains(&doff) {
        return Ok(SNI_PASS);
    }
    let payload = l4_offset + doff * 4;
    // Cheap gate: TLS record content-type 0x16 (handshake) + major version 3.
    if read_u8(ctx, payload).map(u64::from).unwrap_or(0) != 0x16
        || read_u8(ctx, payload + 1).map(u64::from).unwrap_or(0) != 0x03
    {
        return Ok(SNI_PASS);
    }
    // Handshake type 0x01 (ClientHello) at payload+5.
    if read_u8(ctx, payload + 5).map(u64::from).unwrap_or(0) != 0x01 {
        return Ok(SNI_PASS);
    }
    // ClientHello body: version(2) random(32) at payload+9, then session id.
    let mut off = payload + 43;
    // Clamp every length field to a sane TLS bound: oversized values are
    // treated as unparseable (counted + passed to userspace) and also keep the
    // packet offset range tight enough for the verifier to track.
    let sid_len = match read_u8(ctx, off) {
        Ok(v) if v <= 32 => v as usize,
        _ => {
            return Ok(SNI_INCOMPLETE);
        }
    };
    off += 1 + sid_len;
    let cs_len = match (read_u8(ctx, off), read_u8(ctx, off + 1)) {
        (Ok(hi), Ok(lo)) => ((hi as usize) << 8) | lo as usize,
        _ => {
            return Ok(SNI_INCOMPLETE);
        }
    };
    if cs_len == 0 || cs_len > 512 {
        return Ok(SNI_INCOMPLETE);
    }
    // .min() keeps the verifier's bound on the scalar that feeds the packet
    // offset - a checked_add/mask round trip can lose it.
    off += 2 + cs_len.min(512);
    // LLVM emits redundant u16 truncation masks that wipe the verifier's
    // bound on length-derived scalars; an explicit ceiling on the packet
    // offset re-establishes it deterministically.
    if off > 1024 {
        return Ok(SNI_INCOMPLETE);
    }
    let comp_len = match read_u8(ctx, off).map(usize::from) {
        Ok(v) if v <= 8 && v > 0 => v,
        _ => {
            return Ok(SNI_INCOMPLETE);
        }
    };
    off += 1 + comp_len;
    if off > 1024 {
        return Ok(SNI_INCOMPLETE);
    }
    let ext_total = match (read_u8(ctx, off), read_u8(ctx, off + 1)) {
        (Ok(hi), Ok(lo)) => ((hi as usize) << 8) | lo as usize,
        _ => {
            return Ok(SNI_INCOMPLETE);
        }
    };
    if ext_total > 2048 {
        return Ok(SNI_INCOMPLETE);
    }
    // Fast path only parses the first extension: server_name leads the
    // extension list in the vast majority of ClientHellos; anything else is
    // counted incomplete and stays on the userspace dataplane. This keeps
    // the verifier's explored-state count far under the budget (no loop
    // back-edges at all).
    let ext_end = off + 2 + ext_total.min(2048);
    off += 2;
    if off + 4 > ext_end {
        return Ok(SNI_INCOMPLETE);
    }
    let (Ok(t_hi), Ok(t_lo), Ok(l_hi), Ok(l_lo)) = (
        read_u8(ctx, off).map(u64::from),
        read_u8(ctx, off + 1).map(u64::from),
        read_u8(ctx, off + 2).map(u64::from),
        read_u8(ctx, off + 3).map(u64::from),
    ) else {
        return Ok(SNI_INCOMPLETE);
    };
    let ext_type = ((t_hi as usize) << 8) | t_lo as usize;
    let ext_len = ((l_hi as usize) << 8) | l_lo as usize;
    off += 4;
    if ext_type != 0 {
        return Ok(SNI_INCOMPLETE);
    }
    if ext_len < 5 || ext_len > 255 {
        return Ok(SNI_INCOMPLETE);
    }
    // server_name ext: list_len(2) name_type(1) name_len(2) name.
    let (Ok(nt), Ok(n_hi), Ok(n_lo)) = (
        read_u8(ctx, off + 2).map(u64::from),
        read_u8(ctx, off + 3).map(u64::from),
        read_u8(ctx, off + 4).map(u64::from),
    ) else {
        return Ok(SNI_INCOMPLETE);
    };
    // black_box keeps LLVM from merging this test into a combined boolean
    // that aliases a packet-pointer register at a join point (verifier:
    // bitwise ops on pointers are prohibited).
    if core::hint::black_box(nt) != 0 {
        return Ok(SNI_PASS);
    }
    let name_len = ((n_hi as usize) << 8) | n_lo as usize;
    if name_len == 0 || name_len > XDP_SNI_MAX_LEN {
        return Ok(SNI_INCOMPLETE);
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    // One base pointer + one window check: the verifier marks the packet
    // range on this register and `base + j` loads stay on the same pointer
    // chain, so the range survives (scalar-offset reassembly let LLVM split
    // the check and the load onto different pointer chains). name_len <=
    // XDP_SNI_MAX_LEN keeps the loop bounded and inside the marked window.
    // black_box pins `off` to one opaque scalar: without it LLVM re-derives
    // `data + off` twice (once for the window check, once reassembled from
    // spilled length fields for the loads), and the range marked on the
    // check chain does not transfer to the reassembled pointer.
    let name_base =
        unsafe { (ctx.data() as *const u8).add(core::hint::black_box(off) + 5) };
    if unsafe { name_base.add(XDP_SNI_MAX_LEN) } > ctx.data_end() as *const u8 {
        return Ok(SNI_INCOMPLETE);
    }
    let mut j = 0usize;
    while j < name_len {
        // All bytes inside the declared name_len are hashed, including NUL;
        // userspace hashes the same raw name bytes.
        let b = unsafe { *name_base.add(j) } as u64;
        let lower = if b >= u64::from(b'A') && b <= u64::from(b'Z') {
            b + 32
        } else {
            b
        };
        hash = (hash ^ lower).wrapping_mul(0x0000_0100_0000_01b3);
        j += 1;
    }
    if unsafe { XDP_SNI_BLOCK.get(&hash) }.is_some() {
        return Ok(SNI_BLOCK);
    }
    Ok(SNI_PASS)
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

fn counter_tcp_fwd_tx() {
    if let Some(counters) = counters() {
        counters.tcp_fwd_tx = counters.tcp_fwd_tx.saturating_add(1);
    }
}

fn counter_tcp_fwd_map_full() {
    if let Some(counters) = counters() {
        counters.tcp_fwd_map_full = counters.tcp_fwd_map_full.saturating_add(1);
    }
}

fn counter_sni_blocked() {
    if let Some(counters) = counters() {
        counters.sni_blocked = counters.sni_blocked.saturating_add(1);
    }
}

fn counter_sni_incomplete() {
    if let Some(counters) = counters() {
        counters.sni_incomplete = counters.sni_incomplete.saturating_add(1);
    }
}

fn counter_snat_bound() {
    if let Some(counters) = counters() {
        counters.snat_bound = counters.snat_bound.saturating_add(1);
    }
}

fn counter_snat_alloc_fail() {
    if let Some(counters) = counters() {
        counters.snat_alloc_fail = counters.snat_alloc_fail.saturating_add(1);
    }
}

fn counter_snat_reply_tx() {
    if let Some(counters) = counters() {
        counters.snat_reply_tx = counters.snat_reply_tx.saturating_add(1);
    }
}

/// Claim a node source port for a client flow and install the reverse
/// binding (listen addr, port, proto) -> client tuple.
///
/// The caller pre-fills `scratch.snat_rev_key` (`listen_addr`, `proto`,
/// `family`) and `scratch.snat_rev_value` (full client tuple, MAC, server
/// id) before calling — keeping the signature to two arguments stays within
/// the 5-register BPF calling convention; wider argument lists are spilled
/// onto the caller frame, which older verifiers reject.
///
/// A deterministic hash base keeps the common case to a single map update;
/// the bounded probe loop skips ports that collide with configured listen
/// tuples or bindings already claimed by other flows (BPF_NOEXIST). Returns
/// the port in network byte order; `None` when the probe exhausts its tries —
/// the caller then leaves the packet to the userspace dataplane rather than
/// forwarding without reverse state.
#[inline(never)]
fn snat_alloc(
    scratch: *mut NatScratch,
    fwd_map: &HashMap<XdpUdpFwdKey, XdpUdpFwdRule>,
) -> Option<u16> {
    let mut h = 0x9e37_79b9u32;
    let mut i = 0usize;
    unsafe {
        let v = &(*scratch).snat_rev_value;
        while i < 16 {
            h = h.wrapping_mul(31) ^ v.client_addr[i] as u32;
            i += 1;
        }
        h ^= ((v.client_port_be as u32) << 8) | v.backend_port_be as u32;
    }
    h = h.wrapping_mul(0x85eb_ca6b);
    let base = (h % XDP_SNAT_PORT_SPAN as u32) as u16;

    let mut tries = 0usize;
    while tries < 8 {
        let port = XDP_SNAT_PORT_BASE.wrapping_add((base.wrapping_add(tries as u16)) % XDP_SNAT_PORT_SPAN);
        let port_be = port.to_be();
        // Never claim a port that is itself a configured listen tuple —
        // replies to it would be mistaken for forward traffic.
        unsafe {
            let rk = &(*scratch).snat_rev_key;
            let k = &mut (*scratch).fwd_key;
            k.addr = rk.listen_addr;
            k.port_be = port_be;
            k.family = rk.family;
            k._pad = 0;
        }
        if unsafe { fwd_map.get(&(*scratch).fwd_key) }.is_none() {
            unsafe { (*scratch).snat_rev_key.snat_port_be = port_be };
            if XDP_SNAT_REV
                .insert(
                    unsafe { &(*scratch).snat_rev_key },
                    unsafe { &(*scratch).snat_rev_value },
                    1, // BPF_NOEXIST: only the first CPU to claim wins
                )
                .is_ok()
            {
                counter_snat_bound();
                return Some(port_be);
            }
        }
        tries += 1;
    }
    counter_snat_alloc_fail();
    None
}

/// Pre-fill `scratch.snat_rev_*` for a flow about to claim a SNAT port.
/// All SNAT helpers funnel data through the scratch map instead of wide
/// argument lists — spilled arguments land on the caller frame, which the
/// kernel 6.1 verifier rejects as a cross-frame write. `listen_addr`/`proto`
////`family`/`client_mac`/`server_id` arrive via `ct_key`, the packet header
/// snapshot, or the caller's writes into `snat_rev_key`.
#[inline(always)]
fn snat_prefill(scratch: *mut NatScratch, client_mac: [u8; 6], server_id: i64) {
    unsafe {
        let ck = &(*scratch).ct_key;
        let rk = &(*scratch).snat_rev_key;
        let v = &mut (*scratch).snat_rev_value;
        v.client_addr = ck.client_addr;
        v.backend_addr = ck.backend_addr;
        v.client_mac = client_mac;
        v.client_port_be = ck.client_port_be;
        v.backend_port_be = ck.backend_port_be;
        v.listen_port_be = (*scratch).ct_value.listen_port_be;
        v.family = rk.family;
        v.proto = rk.proto;
        v._pad = [0; 2];
        v.server_id = server_id;
    }
}

/// Look up a SNAT reverse binding; the caller pre-fills
/// `scratch.snat_rev_key` (listen addr, port, proto, family). On hit the
/// client tuple lands in `scratch.snat_rev_value`.
#[inline(always)]
fn snat_rev_lookup(scratch: *mut NatScratch) -> bool {
    unsafe {
        if let Some(v) = XDP_SNAT_REV.get(&(*scratch).snat_rev_key) {
            (*scratch).snat_rev_value = *v;
            return true;
        }
    }
    false
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
#[inline(never)]
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
    let scratch = nat_scratch()?;

    // Reply path: source is a backend serving a tracked client flow.
    unsafe {
        let k = &mut (*scratch).ct_key;
        k.client_addr = v4_embed(dst_be);
        k.backend_addr = v4_embed(src_be);
        k.client_port_be = dst_port;
        k.backend_port_be = src_port;
        k.family = 4;
        k.proto = 17;
    };
    if let Some(ct) = XDP_UDP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        ct.last_seen_ns = now_mono_ns;
        let listen_be = u32::from_be_bytes([ct.listen_addr[0], ct.listen_addr[1], ct.listen_addr[2], ct.listen_addr[3]]);
        let listen_port = ct.listen_port_be;
        // Rewrite source -> listen tuple. Checksum deltas live in the
        // per-CPU scratch map: stack arrays here pushed the IPv6 variants of
        // this frame past the 512-byte verifier limit on older kernels.
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(src_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(listen_be.to_be_bytes()), 0, 0, 0];
        }
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = listen_be.to_be_bytes() };
        ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(src_addr), u32::from_ne_bytes(listen_be.to_be_bytes()))?;
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = listen_port.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 1, src_port, listen_port)?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(unsafe { &(*scratch).ct_key }, 0, packet_len, ct.server_id, now_mono_ns);
        counter_udp_fwd_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    // SNAT reply path: the packet targets a node-allocated source port on a
    // listen address — restore the client tuple before transmit. The source
    // must match the bound backend tuple, otherwise the packet is unrelated
    // traffic that continues to the normal forward/redirect checks.
    unsafe {
            let k = &mut (*scratch).snat_rev_key;
            k.listen_addr = v4_embed(dst_be);
            k.snat_port_be = dst_port;
            k.proto = 17;
            k.family = 4;
            k._pad = [0; 3];
            }
        if snat_rev_lookup(scratch)
        && unsafe {
            let rv = &(*scratch).snat_rev_value;
            rv.backend_port_be == src_port
                && rv.backend_addr[..4] == src_be.to_be_bytes()
        }
    {
        let client_be = u32::from_be_bytes(unsafe {
            let rv = &(*scratch).snat_rev_value;
            [rv.client_addr[0], rv.client_addr[1], rv.client_addr[2], rv.client_addr[3]]
        });
        let client_port = unsafe { (*scratch).snat_rev_value.client_port_be };
        let client_mac = unsafe { (*scratch).snat_rev_value.client_mac };
        let listen_port = unsafe { (*scratch).snat_rev_value.listen_port_be };
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(dst_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(client_be.to_be_bytes()), 0, 0, 0];
            // Rebuild the conntrack key for accounting and idle refresh.
            let k = &mut (*scratch).ct_key;
            let rv = &(*scratch).snat_rev_value;
            k.client_addr = rv.client_addr;
            k.backend_addr = rv.backend_addr;
            k.client_port_be = rv.client_port_be;
            k.backend_port_be = rv.backend_port_be;
            k.family = 4;
            k.proto = 17;
        }
        // Source becomes the listen tuple the client originally dialed.
        unsafe {
            let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
            (*ip_hdr).src_addr = dst_be.to_be_bytes();
        }
        ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(src_addr), u32::from_ne_bytes(dst_be.to_be_bytes()))?;
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(src_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(dst_be.to_be_bytes()), 0, 0, 0];
        }
        unsafe {
            let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
            (*udp_hdr).src = listen_port.to_ne_bytes();
        }
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 1, src_port, listen_port)?;
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).dst_addr = client_be.to_be_bytes() };
        ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(dst_addr), u32::from_ne_bytes(client_be.to_be_bytes()))?;
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).dst = client_port.to_ne_bytes() };
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(dst_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(client_be.to_be_bytes()), 0, 0, 0];
        }
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 1, dst_port, client_port)?;
        eth_rewrite(ctx, client_mac)?;
        if let Some(ct) = XDP_UDP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            ct.last_seen_ns = now_mono_ns;
        }
        // Account even when the conntrack entry was already reaped — the
        // binding still carries the billing server id.
        acct_flow(
            unsafe { &(*scratch).ct_key },
            0,
            packet_len,
            unsafe { (*scratch).snat_rev_value.server_id },
            now_mono_ns,
        );
        counter_udp_fwd_tx();
        counter_snat_reply_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    // Forward path: destination is a configured direct-forward listen tuple.
    unsafe {
        let k = &mut (*scratch).fwd_key;
        k.addr = v4_embed(dst_be);
        k.port_be = dst_port;
        k.family = 4;
    };
    let Some(rule) = (unsafe { XDP_UDP_FWD.get(&(*scratch).fwd_key) }) else {
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
    unsafe {
        let k = &mut (*scratch).ct_key;
        k.client_addr = v4_embed(src_be);
        k.backend_addr = rule.backend_addr;
        k.client_port_be = src_port;
        k.backend_port_be = rule.backend_port_be;
        k.family = 4;
        k.proto = 17;
        let v = &mut (*scratch).ct_value;
        v.listen_addr = v4_embed(dst_be);
        v.client_mac = client_mac;
        v.listen_port_be = dst_port;
        v.family = 4;
        v.state = XDP_CT_STATE_OPEN;
        v.snat_port_be = 0;
        v.server_id = rule.server_id;
        v.last_seen_ns = now_mono_ns;
    }
    let mut snat_port = 0u16;
    if let Some(ct) = XDP_UDP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        let v = unsafe { &(*scratch).ct_value };
        ct.listen_addr = v.listen_addr;
        ct.client_mac = v.client_mac;
        ct.listen_port_be = v.listen_port_be;
        ct.family = v.family;
        ct.state = v.state;
        ct.server_id = v.server_id;
        ct.last_seen_ns = v.last_seen_ns;
        // A flow established before SNAT was configured keeps its plain DNAT
        // tuple until it times out — mid-flow rewrites would desync the
        // backend's view of the connection.
        snat_port = ct.snat_port_be;
    } else {
        if rule.snat != 0 {
            unsafe {
                let k = &mut (*scratch).snat_rev_key;
                k.listen_addr = v4_embed(dst_be);
                k.snat_port_be = 0;
                k.proto = 17;
                k.family = 4;
                k._pad = [0; 3];
            }
            snat_prefill(scratch, client_mac, rule.server_id);
            match snat_alloc(scratch, &XDP_UDP_FWD) {
                Some(port) => {
                    snat_port = port;
                    unsafe { (*scratch).ct_value.snat_port_be = port };
                }
                // Port space exhausted: explicit userspace fallback.
                None => return Ok(None),
            }
        }
        if XDP_UDP_CT
            .insert(
                unsafe { &(*scratch).ct_key },
                unsafe { &(*scratch).ct_value },
                0,
            )
            .is_err()
        {
            // Fail explicit: report and leave the packet to the normal path so a
            // full conntrack table degrades to userspace handling, not drops.
            counter_udp_fwd_map_full();
            return Ok(None);
        }
    }
    // Rewrite destination -> backend.
    unsafe {
        (*scratch).csum_old = [u32::from_ne_bytes(dst_addr), 0, 0, 0];
        (*scratch).csum_new = [u32::from_ne_bytes(backend_be.to_be_bytes()), 0, 0, 0];
    }
    let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
    unsafe { (*ip_hdr).dst_addr = backend_be.to_be_bytes() };
    ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(dst_addr), u32::from_ne_bytes(backend_be.to_be_bytes()))?;
    let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
    unsafe { (*udp_hdr).dst = rule.backend_port_be.to_ne_bytes() };
    udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 1, dst_port, rule.backend_port_be)?;
    if snat_port != 0 {
        // Rewrite source -> (listen addr, allocated node port) so the frame
        // passes fabrics that egress-filter foreign source IPs.
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(src_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(dst_be.to_be_bytes()), 0, 0, 0];
        }
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = dst_be.to_be_bytes() };
        ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(src_addr), u32::from_ne_bytes(dst_be.to_be_bytes()))?;
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = snat_port.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 1, src_port, snat_port)?;
    }
    eth_rewrite(ctx, rule.next_hop_mac)?;
    acct_flow(
        unsafe { &(*scratch).ct_key },
        packet_len,
        0,
        rule.server_id,
        now_mono_ns,
    );
    counter_udp_fwd_tx();
    Ok(Some(xdp_action::XDP_TX))
}

/// UDP direct forward / NAT, IPv6. Same contract as `try_udp_nat_v4`; the
/// IPv6 header has no checksum, but the UDP checksum covers the pseudo-header
/// addresses and is mandatory, so it is always updated when non-zero (a zero
/// checksum is preserved rather than fabricated over unseen payload).
#[inline(never)]
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
    let scratch = nat_scratch()?;
    unsafe {
        (*scratch).pkt_src = (*ip).src_addr;
        (*scratch).pkt_dst = (*ip).dst_addr;
    }

    unsafe {
        let k = &mut (*scratch).ct_key;
        k.client_addr = (*scratch).pkt_dst;
        k.backend_addr = (*scratch).pkt_src;
        k.client_port_be = dst_port;
        k.backend_port_be = src_port;
        k.family = 6;
        k.proto = 17;
    };
    if let Some(ct) = XDP_UDP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        ct.last_seen_ns = now_mono_ns;
        let listen_port = ct.listen_port_be;
        unsafe {
            words16_into(&(*scratch).pkt_src, &mut (*scratch).csum_old);
            words16_into(&ct.listen_addr, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = ct.listen_addr };
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = listen_port.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, src_port, listen_port)?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(unsafe { &(*scratch).ct_key }, 0, packet_len, ct.server_id, now_mono_ns);
        counter_udp_fwd_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    // SNAT reply path: restore the client tuple bound to this node port; the
    // source must match the bound backend tuple.
    unsafe {
            let k = &mut (*scratch).snat_rev_key;
            k.listen_addr = unsafe { (*scratch).pkt_dst };
            k.snat_port_be = dst_port;
            k.proto = 17;
            k.family = 6;
            k._pad = [0; 3];
            }
        if snat_rev_lookup(scratch)
        && unsafe {
            let rv = &(*scratch).snat_rev_value;
            rv.backend_port_be == src_port && rv.backend_addr == (*scratch).pkt_src
        }
    {
        let client_port = unsafe { (*scratch).snat_rev_value.client_port_be };
        let client_mac = unsafe { (*scratch).snat_rev_value.client_mac };
        let listen_port = unsafe { (*scratch).snat_rev_value.listen_port_be };
        unsafe {
            let k = &mut (*scratch).ct_key;
            let rv = &(*scratch).snat_rev_value;
            k.client_addr = rv.client_addr;
            k.backend_addr = rv.backend_addr;
            k.client_port_be = rv.client_port_be;
            k.backend_port_be = rv.backend_port_be;
            k.family = 6;
            k.proto = 17;
        }
        // Source becomes the listen tuple the client originally dialed.
        unsafe {
            words16_into(&(*scratch).pkt_src, &mut (*scratch).csum_old);
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = (*scratch).pkt_dst };
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = listen_port.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, src_port, listen_port)?;
        unsafe {
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
            words16_into(&(*scratch).snat_rev_value.client_addr, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).dst_addr = (*scratch).snat_rev_value.client_addr };
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).dst = client_port.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, dst_port, client_port)?;
        eth_rewrite(ctx, client_mac)?;
        if let Some(ct) = XDP_UDP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            ct.last_seen_ns = now_mono_ns;
        }
        // Account even when the conntrack entry was already reaped — the
        // binding still carries the billing server id.
        acct_flow(
            unsafe { &(*scratch).ct_key },
            0,
            packet_len,
            unsafe { (*scratch).snat_rev_value.server_id },
            now_mono_ns,
        );
        counter_udp_fwd_tx();
        counter_snat_reply_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    Ok(None)

}

/// Forward half of UDP/IPv6 NAT: entered through the dispatch tail call. It
/// re-reads the header and rule; `Ok(None)` means no forward matched and the
/// caller applies the redirect/PASS fallback.
#[inline(never)]
fn try_udp_nat_v6_fwd(
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
    let scratch = nat_scratch()?;
    unsafe {
        (*scratch).pkt_src = (*ip).src_addr;
        (*scratch).pkt_dst = (*ip).dst_addr;
    }
    unsafe {
        let k = &mut (*scratch).fwd_key;
        k.addr = (*scratch).pkt_dst;
        k.port_be = dst_port;
        k.family = 6;
    };
    let Some(rule) = (unsafe { XDP_UDP_FWD.get(&(*scratch).fwd_key) }) else {
        return Ok(None);
    };
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let client_mac = unsafe { (*eth).src_addr };
    unsafe {
        let k = &mut (*scratch).ct_key;
        k.client_addr = (*scratch).pkt_src;
        k.backend_addr = rule.backend_addr;
        k.client_port_be = src_port;
        k.backend_port_be = rule.backend_port_be;
        k.family = 6;
        k.proto = 17;
        let v = &mut (*scratch).ct_value;
        v.listen_addr = (*scratch).pkt_dst;
        v.client_mac = client_mac;
        v.listen_port_be = dst_port;
        v.family = 6;
        v.state = XDP_CT_STATE_OPEN;
        v.snat_port_be = 0;
        v.server_id = rule.server_id;
        v.last_seen_ns = now_mono_ns;
    }
    let mut snat_port = 0u16;
    if let Some(ct) = XDP_UDP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        let v = unsafe { &(*scratch).ct_value };
        ct.listen_addr = v.listen_addr;
        ct.client_mac = v.client_mac;
        ct.listen_port_be = v.listen_port_be;
        ct.family = v.family;
        ct.state = v.state;
        ct.server_id = v.server_id;
        ct.last_seen_ns = v.last_seen_ns;
        snat_port = ct.snat_port_be;
    } else {
        if rule.snat != 0 {
            unsafe {
                let k = &mut (*scratch).snat_rev_key;
                k.listen_addr = unsafe { (*scratch).pkt_dst };
                k.snat_port_be = 0;
                k.proto = 17;
                k.family = 6;
                k._pad = [0; 3];
            }
            snat_prefill(scratch, client_mac, rule.server_id);
            match snat_alloc(scratch, &XDP_UDP_FWD) {
                Some(port) => {
                    snat_port = port;
                    unsafe { (*scratch).ct_value.snat_port_be = port };
                }
                None => return Ok(None),
            }
        }
        if XDP_UDP_CT
            .insert(
                unsafe { &(*scratch).ct_key },
                unsafe { &(*scratch).ct_value },
                0,
            )
            .is_err()
        {
            counter_udp_fwd_map_full();
            return Ok(None);
        }
    }
    unsafe {
        words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
        words16_into(&rule.backend_addr, &mut (*scratch).csum_new);
    }
    let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
    unsafe { (*ip_hdr).dst_addr = rule.backend_addr };
    let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
    unsafe { (*udp_hdr).dst = rule.backend_port_be.to_ne_bytes() };
    udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, dst_port, rule.backend_port_be)?;
    if snat_port != 0 {
        unsafe {
            words16_into(&(*scratch).pkt_src, &mut (*scratch).csum_old);
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = (*scratch).pkt_dst };
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = snat_port.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, src_port, snat_port)?;
    }
    eth_rewrite(ctx, rule.next_hop_mac)?;
    acct_flow(
        unsafe { &(*scratch).ct_key },
        packet_len,
        0,
        rule.server_id,
        now_mono_ns,
    );
    counter_udp_fwd_tx();
    Ok(Some(xdp_action::XDP_TX))
}

/// Update the TCP checksum after a pseudo-header address change plus an
/// optional port change. Unlike UDP the checksum is mandatory (both families),
/// so a zero stored value is still corrected rather than left alone.
#[allow(clippy::too_many_arguments)]
fn tcp_csum_update(
    ctx: &XdpContext,
    l4_offset: usize,
    old_addr_words: &mut [u32; 4],
    new_addr_words: &mut [u32; 4],
    addr_word_count: usize,
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    let tcp = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
    let old_check = unsafe { u16::from_ne_bytes((*tcp).check) };
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
        let mut old_p = old_port as u32;
        let mut new_p = new_port as u32;
        diff = unsafe {
            bpf_csum_diff(&mut old_p as *mut u32, 4, &mut new_p as *mut u32, 4, diff as u32)
        };
    }
    unsafe { (*tcp).check = csum_apply_diff(old_check, diff).to_ne_bytes() };
    Ok(())
}

/// TCP direct forward / NAT, IPv4. Conntrack is created only on a bare SYN so
/// mid-stream pickups never get silently fast-pathed: non-SYN packets without
/// state fall through to `None` (PASS -> userspace/kernel dataplane). FIN/RST
/// in either direction marks the entry CLOSING for early reaping by userspace.
#[inline(never)]
fn try_tcp_nat_v4(
    ctx: &XdpContext,
    ip_offset: usize,
    l4_offset: usize,
    packet_len: u64,
    now_mono_ns: u64,
) -> Result<Option<u32>, ()> {
    let tcp = ptr_at::<TcpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*tcp).source) };
    let dst_port = unsafe { u16::from_ne_bytes((*tcp).dest) };
    let syn = unsafe { (*tcp).syn() } == 1;
    let ack = unsafe { (*tcp).ack() } == 1;
    let closing = unsafe { (*tcp).fin() } == 1 || unsafe { (*tcp).rst() } == 1;
    let ip = ptr_at::<Ipv4Hdr>(ctx, ip_offset)?;
    let src_addr = unsafe { (*ip).src_addr };
    let dst_addr = unsafe { (*ip).dst_addr };
    let src_be = u32::from_be_bytes(src_addr);
    let dst_be = u32::from_be_bytes(dst_addr);
    let scratch = nat_scratch()?;

    // Reply path: source is a backend serving a tracked client flow.
    unsafe {
        let k = &mut (*scratch).ct_key;
        k.client_addr = v4_embed(dst_be);
        k.backend_addr = v4_embed(src_be);
        k.client_port_be = dst_port;
        k.backend_port_be = src_port;
        k.family = 4;
        k.proto = 6;
    };
    if let Some(ct) = XDP_TCP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        ct.last_seen_ns = now_mono_ns;
        if closing {
            ct.state = XDP_CT_STATE_CLOSING;
        }
        let listen_be = u32::from_be_bytes([
            ct.listen_addr[0],
            ct.listen_addr[1],
            ct.listen_addr[2],
            ct.listen_addr[3],
        ]);
        let listen_port = ct.listen_port_be;
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(src_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(listen_be.to_be_bytes()), 0, 0, 0];
        }
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = listen_be.to_be_bytes() };
        ipv4_csum_update(
            ctx,
            ip_offset,
            u32::from_ne_bytes(src_addr),
            u32::from_ne_bytes(listen_be.to_be_bytes()),
        )?;
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).source = listen_port.to_ne_bytes() };
        tcp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 1, src_port, listen_port)?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(unsafe { &(*scratch).ct_key }, 0, packet_len, ct.server_id, now_mono_ns);
        counter_tcp_fwd_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    // SNAT reply path: restore the client tuple bound to this node port; the
    // source must match the bound backend tuple.
    unsafe {
            let k = &mut (*scratch).snat_rev_key;
            k.listen_addr = v4_embed(dst_be);
            k.snat_port_be = dst_port;
            k.proto = 6;
            k.family = 4;
            k._pad = [0; 3];
            }
        if snat_rev_lookup(scratch)
        && unsafe {
            let rv = &(*scratch).snat_rev_value;
            rv.backend_port_be == src_port
                && rv.backend_addr[..4] == src_be.to_be_bytes()
        }
    {
        let client_be = u32::from_be_bytes(unsafe {
            let rv = &(*scratch).snat_rev_value;
            [rv.client_addr[0], rv.client_addr[1], rv.client_addr[2], rv.client_addr[3]]
        });
        let client_port = unsafe { (*scratch).snat_rev_value.client_port_be };
        let client_mac = unsafe { (*scratch).snat_rev_value.client_mac };
        let listen_port = unsafe { (*scratch).snat_rev_value.listen_port_be };
        unsafe {
            let k = &mut (*scratch).ct_key;
            let rv = &(*scratch).snat_rev_value;
            k.client_addr = rv.client_addr;
            k.backend_addr = rv.backend_addr;
            k.client_port_be = rv.client_port_be;
            k.backend_port_be = rv.backend_port_be;
            k.family = 4;
            k.proto = 6;
        }
        // Source becomes the listen tuple the client originally dialed.
        unsafe {
            let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
            (*ip_hdr).src_addr = dst_be.to_be_bytes();
        }
        ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(src_addr), u32::from_ne_bytes(dst_be.to_be_bytes()))?;
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(src_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(dst_be.to_be_bytes()), 0, 0, 0];
        }
        unsafe {
            let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
            (*tcp_hdr).source = listen_port.to_ne_bytes();
        }
        tcp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 1, src_port, listen_port)?;
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(dst_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(client_be.to_be_bytes()), 0, 0, 0];
        }
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).dst_addr = client_be.to_be_bytes() };
        ipv4_csum_update(ctx, ip_offset, u32::from_ne_bytes(dst_addr), u32::from_ne_bytes(client_be.to_be_bytes()))?;
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).dest = client_port.to_ne_bytes() };
        tcp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 1, dst_port, client_port)?;
        eth_rewrite(ctx, client_mac)?;
        if let Some(ct) = XDP_TCP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            ct.last_seen_ns = now_mono_ns;
            if closing {
                ct.state = XDP_CT_STATE_CLOSING;
            }
        }
        acct_flow(
            unsafe { &(*scratch).ct_key },
            0,
            packet_len,
            unsafe { (*scratch).snat_rev_value.server_id },
            now_mono_ns,
        );
        counter_tcp_fwd_tx();
        counter_snat_reply_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    // Forward path: destination is a configured direct-forward listen tuple.
    unsafe {
        let k = &mut (*scratch).fwd_key;
        k.addr = v4_embed(dst_be);
        k.port_be = dst_port;
        k.family = 4;
    };
    let Some(rule) = (unsafe { XDP_TCP_FWD.get(&(*scratch).fwd_key) }) else {
        return Ok(None);
    };
    let backend_be = u32::from_be_bytes([
        rule.backend_addr[0],
        rule.backend_addr[1],
        rule.backend_addr[2],
        rule.backend_addr[3],
    ]);
    unsafe {
        let k = &mut (*scratch).ct_key;
        k.client_addr = v4_embed(src_be);
        k.backend_addr = rule.backend_addr;
        k.client_port_be = src_port;
        k.backend_port_be = rule.backend_port_be;
        k.family = 4;
        k.proto = 6;
    }
    let mut snat_port = 0u16;
    match XDP_TCP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        Some(ct) => {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            ct.last_seen_ns = now_mono_ns;
            if closing {
                ct.state = XDP_CT_STATE_CLOSING;
            }
            // Flows established before SNAT was configured keep plain DNAT.
            snat_port = ct.snat_port_be;
        }
        None => {
            if !(syn && !ack) {
                // No state and not a fresh connection attempt: explicit
                // fallback to the userspace/kernel path.
                return Ok(None);
            }
            let eth = ptr_at::<EthHdr>(ctx, 0)?;
            let client_mac = unsafe { (*eth).src_addr };
            unsafe {
                let v = &mut (*scratch).ct_value;
                v.listen_addr = v4_embed(dst_be);
                v.client_mac = client_mac;
                v.listen_port_be = dst_port;
                v.family = 4;
                v.state = XDP_CT_STATE_OPEN;
                v.snat_port_be = 0;
                v.server_id = rule.server_id;
                v.last_seen_ns = now_mono_ns;
            }
            if rule.snat != 0 {
                unsafe {
                let k = &mut (*scratch).snat_rev_key;
                k.listen_addr = v4_embed(dst_be);
                k.snat_port_be = 0;
                k.proto = 6;
                k.family = 4;
                k._pad = [0; 3];
            }
            snat_prefill(scratch, client_mac, rule.server_id);
                match snat_alloc(scratch, &XDP_TCP_FWD) {
                    Some(port) => {
                        snat_port = port;
                        unsafe { (*scratch).ct_value.snat_port_be = port };
                    }
                    None => return Ok(None),
                }
            }
            if XDP_TCP_CT
                .insert(
                    unsafe { &(*scratch).ct_key },
                    unsafe { &(*scratch).ct_value },
                    0,
                )
                .is_err()
            {
                counter_tcp_fwd_map_full();
                return Ok(None);
            }
        }
    }
    unsafe {
        (*scratch).csum_old = [u32::from_ne_bytes(dst_addr), 0, 0, 0];
        (*scratch).csum_new = [u32::from_ne_bytes(backend_be.to_be_bytes()), 0, 0, 0];
    }
    let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
    unsafe { (*ip_hdr).dst_addr = backend_be.to_be_bytes() };
    ipv4_csum_update(
        ctx,
        ip_offset,
        u32::from_ne_bytes(dst_addr),
        u32::from_ne_bytes(backend_be.to_be_bytes()),
    )?;
    let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
    unsafe { (*tcp_hdr).dest = rule.backend_port_be.to_ne_bytes() };
    tcp_csum_update(
        ctx,
        l4_offset,
        unsafe { &mut (*scratch).csum_old },
        unsafe { &mut (*scratch).csum_new },
        1,
        dst_port,
        rule.backend_port_be,
    )?;
    if snat_port != 0 {
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(src_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(dst_be.to_be_bytes()), 0, 0, 0];
        }
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = dst_be.to_be_bytes() };
        ipv4_csum_update(
            ctx,
            ip_offset,
            u32::from_ne_bytes(src_addr),
            u32::from_ne_bytes(dst_be.to_be_bytes()),
        )?;
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).source = snat_port.to_ne_bytes() };
        tcp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            1,
            src_port,
            snat_port,
        )?;
    }
    eth_rewrite(ctx, rule.next_hop_mac)?;
    acct_flow(
        unsafe { &(*scratch).ct_key },
        packet_len,
        0,
        rule.server_id,
        now_mono_ns,
    );
    counter_tcp_fwd_tx();
    Ok(Some(xdp_action::XDP_TX))
}

/// TCP direct forward / NAT, IPv6. Same contract as `try_tcp_nat_v4`.
#[inline(never)]
fn try_tcp_nat_v6(
    ctx: &XdpContext,
    ip_offset: usize,
    l4_offset: usize,
    packet_len: u64,
    now_mono_ns: u64,
) -> Result<Option<u32>, ()> {
    let tcp = ptr_at::<TcpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*tcp).source) };
    let dst_port = unsafe { u16::from_ne_bytes((*tcp).dest) };
    let syn = unsafe { (*tcp).syn() } == 1;
    let ack = unsafe { (*tcp).ack() } == 1;
    let closing = unsafe { (*tcp).fin() } == 1 || unsafe { (*tcp).rst() } == 1;
    let ip = ptr_at::<Ipv6Hdr>(ctx, ip_offset)?;
    let scratch = nat_scratch()?;
    unsafe {
        (*scratch).pkt_src = (*ip).src_addr;
        (*scratch).pkt_dst = (*ip).dst_addr;
    }

    unsafe {
        let k = &mut (*scratch).ct_key;
        k.client_addr = (*scratch).pkt_dst;
        k.backend_addr = (*scratch).pkt_src;
        k.client_port_be = dst_port;
        k.backend_port_be = src_port;
        k.family = 6;
        k.proto = 6;
    };
    if let Some(ct) = XDP_TCP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        ct.last_seen_ns = now_mono_ns;
        if closing {
            ct.state = XDP_CT_STATE_CLOSING;
        }
        let listen_port = ct.listen_port_be;
        unsafe {
            words16_into(&(*scratch).pkt_src, &mut (*scratch).csum_old);
            words16_into(&ct.listen_addr, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = ct.listen_addr };
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).source = listen_port.to_ne_bytes() };
        tcp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, src_port, listen_port)?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(unsafe { &(*scratch).ct_key }, 0, packet_len, ct.server_id, now_mono_ns);
        counter_tcp_fwd_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    // SNAT reply path: restore the client tuple bound to this node port; the
    // source must match the bound backend tuple.
    unsafe {
            let k = &mut (*scratch).snat_rev_key;
            k.listen_addr = unsafe { (*scratch).pkt_dst };
            k.snat_port_be = dst_port;
            k.proto = 6;
            k.family = 6;
            k._pad = [0; 3];
            }
        if snat_rev_lookup(scratch)
        && unsafe {
            let rv = &(*scratch).snat_rev_value;
            rv.backend_port_be == src_port && rv.backend_addr == (*scratch).pkt_src
        }
    {
        let client_port = unsafe { (*scratch).snat_rev_value.client_port_be };
        let client_mac = unsafe { (*scratch).snat_rev_value.client_mac };
        let listen_port = unsafe { (*scratch).snat_rev_value.listen_port_be };
        unsafe {
            let k = &mut (*scratch).ct_key;
            let rv = &(*scratch).snat_rev_value;
            k.client_addr = rv.client_addr;
            k.backend_addr = rv.backend_addr;
            k.client_port_be = rv.client_port_be;
            k.backend_port_be = rv.backend_port_be;
            k.family = 6;
            k.proto = 6;
        }
        // Source becomes the listen tuple the client originally dialed.
        unsafe {
            words16_into(&(*scratch).pkt_src, &mut (*scratch).csum_old);
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = (*scratch).pkt_dst };
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).source = listen_port.to_ne_bytes() };
        tcp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, src_port, listen_port)?;
        unsafe {
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
            words16_into(&(*scratch).snat_rev_value.client_addr, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).dst_addr = (*scratch).snat_rev_value.client_addr };
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).dest = client_port.to_ne_bytes() };
        tcp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, dst_port, client_port)?;
        eth_rewrite(ctx, client_mac)?;
        if let Some(ct) = XDP_TCP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            ct.last_seen_ns = now_mono_ns;
            if closing {
                ct.state = XDP_CT_STATE_CLOSING;
            }
        }
        acct_flow(
            unsafe { &(*scratch).ct_key },
            0,
            packet_len,
            unsafe { (*scratch).snat_rev_value.server_id },
            now_mono_ns,
        );
        counter_tcp_fwd_tx();
        counter_snat_reply_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    Ok(None)

}

/// Forward half of TCP/IPv6 NAT (tail-called). `Ok(None)` = no rule matched;
/// caller applies redirect/PASS.
#[inline(never)]
fn try_tcp_nat_v6_fwd(
    ctx: &XdpContext,
    ip_offset: usize,
    l4_offset: usize,
    packet_len: u64,
    now_mono_ns: u64,
) -> Result<Option<u32>, ()> {
    let tcp = ptr_at::<TcpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*tcp).source) };
    let dst_port = unsafe { u16::from_ne_bytes((*tcp).dest) };
    let syn = unsafe { (*tcp).syn() } == 1;
    let ack = unsafe { (*tcp).ack() } == 1;
    let closing = unsafe { (*tcp).fin() } == 1 || unsafe { (*tcp).rst() } == 1;
    let ip = ptr_at::<Ipv6Hdr>(ctx, ip_offset)?;
    let scratch = nat_scratch()?;
    unsafe {
        (*scratch).pkt_src = (*ip).src_addr;
        (*scratch).pkt_dst = (*ip).dst_addr;
    }
    unsafe {
        let k = &mut (*scratch).fwd_key;
        k.addr = (*scratch).pkt_dst;
        k.port_be = dst_port;
        k.family = 6;
    };
    let Some(rule) = (unsafe { XDP_TCP_FWD.get(&(*scratch).fwd_key) }) else {
        return Ok(None);
    };
    unsafe {
        let k = &mut (*scratch).ct_key;
        k.client_addr = (*scratch).pkt_src;
        k.backend_addr = rule.backend_addr;
        k.client_port_be = src_port;
        k.backend_port_be = rule.backend_port_be;
        k.family = 6;
        k.proto = 6;
    }
    let mut snat_port = 0u16;
    match XDP_TCP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        Some(ct) => {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            ct.last_seen_ns = now_mono_ns;
            if closing {
                ct.state = XDP_CT_STATE_CLOSING;
            }
            snat_port = ct.snat_port_be;
        }
        None => {
            if !(syn && !ack) {
                return Ok(None);
            }
            let eth = ptr_at::<EthHdr>(ctx, 0)?;
            let client_mac = unsafe { (*eth).src_addr };
            unsafe {
                let v = &mut (*scratch).ct_value;
                v.listen_addr = (*scratch).pkt_dst;
                v.client_mac = client_mac;
                v.listen_port_be = dst_port;
                v.family = 6;
                v.state = XDP_CT_STATE_OPEN;
                v.snat_port_be = 0;
                v.server_id = rule.server_id;
                v.last_seen_ns = now_mono_ns;
            }
            if rule.snat != 0 {
                unsafe {
                let k = &mut (*scratch).snat_rev_key;
                k.listen_addr = unsafe { (*scratch).pkt_dst };
                k.snat_port_be = 0;
                k.proto = 6;
                k.family = 6;
                k._pad = [0; 3];
            }
            snat_prefill(scratch, client_mac, rule.server_id);
                match snat_alloc(scratch, &XDP_TCP_FWD) {
                    Some(port) => {
                        snat_port = port;
                        unsafe { (*scratch).ct_value.snat_port_be = port };
                    }
                    None => return Ok(None),
                }
            }
            if XDP_TCP_CT
                .insert(
                    unsafe { &(*scratch).ct_key },
                    unsafe { &(*scratch).ct_value },
                    0,
                )
                .is_err()
            {
                counter_tcp_fwd_map_full();
                return Ok(None);
            }
        }
    }
    unsafe {
        words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
        words16_into(&rule.backend_addr, &mut (*scratch).csum_new);
    }
    let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
    unsafe { (*ip_hdr).dst_addr = rule.backend_addr };
    let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
    unsafe { (*tcp_hdr).dest = rule.backend_port_be.to_ne_bytes() };
    tcp_csum_update(
        ctx,
        l4_offset,
        unsafe { &mut (*scratch).csum_old },
        unsafe { &mut (*scratch).csum_new },
        4,
        dst_port,
        rule.backend_port_be,
    )?;
    if snat_port != 0 {
        unsafe {
            words16_into(&(*scratch).pkt_src, &mut (*scratch).csum_old);
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).src_addr = (*scratch).pkt_dst };
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).source = snat_port.to_ne_bytes() };
        tcp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            4,
            src_port,
            snat_port,
        )?;
    }
    eth_rewrite(ctx, rule.next_hop_mac)?;
    acct_flow(
        unsafe { &(*scratch).ct_key },
        packet_len,
        0,
        rule.server_id,
        now_mono_ns,
    );
    counter_tcp_fwd_tx();
    Ok(Some(xdp_action::XDP_TX))
}

/// Read a 16-byte IPv6 address as four memory-order 32-bit words for
/// `bpf_csum_diff`.
fn words16_into(addr: &[u8; 16], out: &mut [u32; 4]) {
    out[0] = u32::from_ne_bytes([addr[0], addr[1], addr[2], addr[3]]);
    out[1] = u32::from_ne_bytes([addr[4], addr[5], addr[6], addr[7]]);
    out[2] = u32::from_ne_bytes([addr[8], addr[9], addr[10], addr[11]]);
    out[3] = u32::from_ne_bytes([addr[12], addr[13], addr[14], addr[15]]);
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
    let start = ctx.data();
    let end = ctx.data_end();
    // `end < ptr + N` compiles to `ptr + N > end` - a bound the verifier
    // can mark on variable-offset packet pointers; `ptr + 1 > end` folds
    // into `ptr >= end`, which is not marked on this kernel. The margin also
    // covers fixed offsets LLVM folds into the load instruction.
    if end < start + offset + 16 {
        return Err(());
    }
    let byte: *const u8 = (start + offset) as *const u8;
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
