#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_csum_diff, bpf_get_prandom_u32, bpf_ktime_get_ns},
    macros::{map, xdp},
    maps::{Array, HashMap, LpmTrie, PerCpuArray, PerCpuHashMap, ProgramArray, XskMap, lpm_trie::Key as LpmKey},
    programs::XdpContext,
};
use cloud_node_xdp_common::{
    XdpCounters, XdpFlowAcct, XdpInterfacePolicy, XdpIpv4Key, XdpIpv6Key, XdpLocalIpv4Key,
    XdpLocalIpv6Key, XdpPortProtoKey, XdpQueueKey, XdpQuicDcidKey, XdpRateBucket,
    XdpRateLimitConfig, XdpRuleValue, XdpSnatRevKey, XdpSnatRevValue, XdpUdpCtKey,
    XdpUdpCtValue, XdpUdpFwdKey, XdpUdpFwdRule, XDP_CLASS_MALFORMED, XDP_CLASS_UNSUPPORTED,
    XDP_CT_STATE_CLOSING, XDP_CT_STATE_OPEN, XDP_FRAGMENT_DROP, XDP_FRAGMENT_PASS,
    XDP_LOCAL_FRAG_DROP, XDP_LOCAL_FRAG_PASS, XDP_LOCAL_PRESENT, XDP_LOCAL_REDIRECT,
    XDP_SNAT_PORT_BASE, XDP_SNAT_PORT_SPAN,
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
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_ROUTING: u8 = 43;
const IP_PROTO_FRAGMENT: u8 = 44;
const IP_PROTO_AH: u8 = 51;
const IP_PROTO_ICMPV6: u8 = 58;
const IP_PROTO_NO_NEXT: u8 = 59;
const IP_PROTO_DEST_OPTS: u8 = 60;

/// TCP flag bits as stored in the flags byte (offset 13 of the header).
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;

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

/// Per-CPU verdict counters. A shared single slot loses updates under
/// multi-CPU RX; per-CPU storage plus userspace aggregation keeps counting
/// lossless without atomic instructions (which eBPF lacks for map values).
#[map(name = "XDP_COUNTERS")]
static XDP_COUNTERS: PerCpuArray<XdpCounters> =
    PerCpuArray::<XdpCounters>::with_max_entries(1, 0);

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
    /// Redirect context stashed before a NAT tail call: keeping these scalars
    /// in the per-CPU map instead of the main frame stops LLVM from spilling
    /// callee-saved registers through R11 (rejected by the verifier).
    redir_flags: u32,
    redir_proto: u8,
    redir_l4off: u16,
    redir_pad: u8,
    /// Worker context stashed before the dispatch -> work tail call: offsets
    /// are re-validated against packet bounds inside the worker program, so
    /// only plain scalars need to cross the call.
    work_ip_off: u32,
    work_ifindex: u32,
    work_pkt_len: u64,
}

#[map(name = "XDP_NAT_SCRATCH")]
static XDP_NAT_SCRATCH: PerCpuArray<NatScratch> =
    PerCpuArray::<NatScratch>::with_max_entries(1, 0);

/// Tail-call table into the NAT subprogram. The NAT handlers need their own
/// 512-byte stack and instruction budget, so they run as a separate XDP
/// program; slot 0 = `xdp_nat_dispatch`.
#[map(name = "XDP_DISPATCH")]
static XDP_DISPATCH: ProgramArray = ProgramArray::with_max_entries(16, 0);

const XDP_DISPATCH_NAT: u32 = 0;
const XDP_DISPATCH_NAT_TCP: u32 = 2;
const XDP_DISPATCH_NAT_UDP6: u32 = 3;
const XDP_DISPATCH_NAT_TCP6: u32 = 4;
const XDP_DISPATCH_NAT_UDP6_FWD: u32 = 5;
const XDP_DISPATCH_NAT_TCP6_FWD: u32 = 6;
/// Worker programs run the heavyweight NAT handlers with a single verifier
/// entry state: the dispatch programs above already parsed the frame, and
/// keeping the ~1.5KiB handlers in the same program multiplied the parser's
/// branch states past the pre-6.6 explored-state budget.
const XDP_DISPATCH_NAT_UDP4_WORK: u32 = 7;
const XDP_DISPATCH_NAT_TCP4_WORK: u32 = 8;
const XDP_DISPATCH_NAT_UDP6_WORK: u32 = 9;
const XDP_DISPATCH_NAT_TCP6_WORK: u32 = 10;

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
        Ok(action) => {
            count_action(action);
            action
        }
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
        Ok(action) => {
            count_action(action);
            action
        }
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
) -> Result<
    (
        u8,
        usize,
        u8,
        usize,
        u64,
        u32,
        Option<&'static XdpInterfacePolicy>,
        u32,
    ),
    (),
> {
    let (eth_proto, ip_offset) = parse_eth_payload(ctx).map_err(|_| ())?;
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let tuple = if F == 4 && eth_proto == EtherType::Ipv4 as u16 {
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
            local_flags_v4(
                policy,
                ifindex,
                u32::from_be_bytes(unsafe { (*ip).dst_addr }),
            )
            .unwrap_or(u32::MAX),
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
        let (proto, l4_offset) = match unpack_v6_next(ipv6_transport_offset(
            ctx,
            next,
            ip_offset + mem::size_of::<Ipv6Hdr>(),
            packet_end,
        )?) {
            Some(bounds) => bounds,
            None => return Err(()),
        };
        (
            6u8,
            proto,
            l4_offset,
            payload_len as u64,
            local_flags_v6(policy, ifindex, unsafe { (*ip).dst_addr }).unwrap_or(u32::MAX),
        )
    } else {
        return Err(());
    };
    let (family, proto, l4_offset, packet_len, local_flags) = tuple;
    Ok((
        family,
        ip_offset,
        proto,
        l4_offset,
        packet_len,
        ifindex,
        policy,
        local_flags,
    ))
}

fn try_nat_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, ifindex, policy, local_flags) =
        parse_frame::<4>(ctx)?;
    if proto == IpProto::Udp as u8 {
        stash_work_ctx(ifindex, local_flags, proto, ip_offset, l4_offset, packet_len);
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_UDP4_WORK) };
        return Ok(redirect_from_scratch(ctx, policy));
    }
    Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
}

/// UDP/IPv4 NAT worker: runs with a single verifier entry state so the big
/// handler is not re-explored under every parser branch state.
fn try_nat_udp4_work(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip_offset, l4_offset, packet_len, local_flags, proto, ifindex) = work_ctx()?;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if let Some(action) = try_udp_nat_v4(ctx, ip_offset, l4_offset, packet_len, now_ns)? {
        return Ok(action);
    }
    Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
}

/// Per-family NAT dispatchers: one (family, proto) pair per tail-call target
/// keeps each verifier run under the pre-6.6 explored-state budget - the
/// SNAT/reverse-lookup branches in a single handler are already ~10KiB of
/// BPF, and pairing families in one program multiplies states past 1M insns.
fn try_nat_udp6_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, ifindex, policy, local_flags) =
        parse_frame::<6>(ctx)?;
    if proto == IpProto::Udp as u8 {
        stash_work_ctx(ifindex, local_flags, proto, ip_offset, l4_offset, packet_len);
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_UDP6_WORK) };
        return Ok(redirect_from_scratch(ctx, policy));
    }
    Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
}

fn try_nat_udp6_work(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip_offset, l4_offset, packet_len, _, _, ifindex) = work_ctx()?;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if let Some(action) = try_udp_nat_v6(ctx, ip_offset, l4_offset, packet_len, now_ns)? {
        return Ok(action);
    }
    // The forward half lives in its own tail-call program: the work context
    // is already parked in scratch so no register must survive the call.
    unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_UDP6_FWD) };
    Ok(redirect_from_scratch(ctx, policy))
}

fn try_nat_udp6_fwd(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip_offset, l4_offset, packet_len, local_flags, proto, ifindex) = work_ctx()?;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let action = if proto == IpProto::Udp as u8 {
        try_udp_nat_v6_fwd(ctx, ip_offset, l4_offset, packet_len, now_ns)?
    } else {
        None
    };
    if let Some(action) = action {
        return Ok(action);
    }
    Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
}

#[xdp]
pub fn xdp_nat_udp6_fwd(ctx: XdpContext) -> u32 {
    match try_nat_udp6_fwd(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

fn try_nat_tcp_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, ifindex, policy, local_flags) =
        parse_frame::<4>(ctx)?;
    if proto == IpProto::Tcp as u8 {
        stash_work_ctx(ifindex, local_flags, proto, ip_offset, l4_offset, packet_len);
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP4_WORK) };
        return Ok(redirect_from_scratch(ctx, policy));
    }
    Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
}

fn try_nat_tcp4_work(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip_offset, l4_offset, packet_len, local_flags, proto, ifindex) = work_ctx()?;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if let Some(action) = try_tcp_nat_v4(ctx, ip_offset, l4_offset, packet_len, now_ns)? {
        return Ok(action);
    }
    Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
}

fn try_nat_tcp6_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, ifindex, policy, local_flags) =
        parse_frame::<6>(ctx)?;
    if proto == IpProto::Tcp as u8 {
        stash_work_ctx(ifindex, local_flags, proto, ip_offset, l4_offset, packet_len);
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP6_WORK) };
        return Ok(redirect_from_scratch(ctx, policy));
    }
    Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
}

fn try_nat_tcp6_work(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip_offset, l4_offset, packet_len, _, _, ifindex) = work_ctx()?;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    if let Some(action) = try_tcp_nat_v6(ctx, ip_offset, l4_offset, packet_len, now_ns)? {
        return Ok(action);
    }
    unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP6_FWD) };
    Ok(redirect_from_scratch(ctx, policy))
}

fn try_nat_tcp6_fwd(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip_offset, l4_offset, packet_len, local_flags, proto, ifindex) = work_ctx()?;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let action = if proto == IpProto::Tcp as u8 {
        try_tcp_nat_v6_fwd(ctx, ip_offset, l4_offset, packet_len, now_ns)?
    } else {
        None
    };
    if let Some(action) = action {
        return Ok(action);
    }
    Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
}

#[xdp]
pub fn xdp_nat_tcp6_fwd(ctx: XdpContext) -> u32 {
    match try_nat_tcp6_fwd(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_tcp_dispatch(ctx: XdpContext) -> u32 {
    match try_nat_tcp_dispatch(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_udp6_dispatch(ctx: XdpContext) -> u32 {
    match try_nat_udp6_dispatch(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_tcp6_dispatch(ctx: XdpContext) -> u32 {
    match try_nat_tcp6_dispatch(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_udp4_work(ctx: XdpContext) -> u32 {
    match try_nat_udp4_work(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_tcp4_work(ctx: XdpContext) -> u32 {
    match try_nat_tcp4_work(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_udp6_work(ctx: XdpContext) -> u32 {
    match try_nat_udp6_work(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

#[xdp]
pub fn xdp_nat_tcp6_work(ctx: XdpContext) -> u32 {
    match try_nat_tcp6_work(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            counter_parse_error();
            xdp_action::XDP_PASS
        }
    }
}

fn try_cloud_node_xdp(ctx: XdpContext) -> Result<u32, ()> {
    counter_packet();
    let (eth_proto, ip_offset) = match parse_eth_payload(&ctx) {
        Ok(bounds) => bounds,
        Err(XDP_CLASS_MALFORMED) => return Ok(malformed_drop()),
        Err(_) => return Ok(unsupported_pass()),
    };
    let action = match eth_proto {
        value if value == EtherType::Ipv4 as u16 => handle_ipv4(&ctx, ip_offset)?,
        value if value == EtherType::Ipv6 as u16 => handle_ipv6(&ctx, ip_offset)?,
        _ => xdp_action::XDP_PASS,
    };
    Ok(action)
}

/// Parse the Ethernet (+ up to two VLAN tags) boundary. `Err(class)` carries
/// an XDP_CLASS_* parse verdict: MALFORMED for deterministic-illegal frames
/// (truncated headers), UNSUPPORTED for legal-but-unparseable encapsulations
/// (more than two stacked VLAN tags).
fn parse_eth_payload(ctx: &XdpContext) -> Result<(u16, usize), u8> {
    let eth: *const EthHdr = ptr_at(ctx, 0).map_err(|_| XDP_CLASS_MALFORMED)?;
    let mut eth_proto = unsafe { (*eth).ether_type };
    let mut offset = mem::size_of::<EthHdr>();

    if is_vlan_ethertype(eth_proto) {
        let vlan: *const VlanHdr = ptr_at(ctx, offset).map_err(|_| XDP_CLASS_MALFORMED)?;
        eth_proto = unsafe { (*vlan).ether_type };
        offset += mem::size_of::<VlanHdr>();
    }
    if is_vlan_ethertype(eth_proto) {
        let vlan: *const VlanHdr = ptr_at(ctx, offset).map_err(|_| XDP_CLASS_MALFORMED)?;
        eth_proto = unsafe { (*vlan).ether_type };
        offset += mem::size_of::<VlanHdr>();
    }
    if is_vlan_ethertype(eth_proto) {
        return Err(XDP_CLASS_UNSUPPORTED);
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
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    if policy.is_none() {
        counter_map_miss();
    }
    let ip: *const Ipv4Hdr = match ptr_at(ctx, ip_offset) {
        Ok(ip) => ip,
        Err(_) => return Ok(malformed_drop()),
    };
    let version = unsafe { (*ip).version() };
    let ihl = unsafe { (*ip).ihl() as usize };
    let total_len = unsafe { (*ip).tot_len() as usize };
    let frame_len = ctx.data_end().saturating_sub(ctx.data());
    let packet_end = match ip_offset.checked_add(total_len) {
        Some(end) => end,
        None => return Ok(malformed_drop()),
    };
    // Deterministic-illegal IPv4: wrong version, header shorter than the
    // minimum, declared length shorter than the header, or a declared length
    // beyond what actually arrived (truncation). Never legal — drop.
    if version != 4
        || ihl < mem::size_of::<Ipv4Hdr>()
        || ihl > 15 * 4
        || total_len < ihl
        || packet_end > frame_len
    {
        return Ok(malformed_drop());
    }
    let source = unsafe { (*ip).src_addr };
    let source_be = u32::from_be_bytes(source);
    let destination_be = u32::from_be_bytes(unsafe { (*ip).dst_addr });
    // Scope resolution happens once: local_flags is the VIP's XDP_LOCAL_*
    // value, or None when the destination lies outside the protected set.
    let local_flags = local_flags_v4(policy, ifindex, destination_be);
    // Any fragment — first included — is classified FRAGMENTED and leaves the
    // pipeline here: a first fragment alone never creates a trusted L4 flow
    // (no rate bucket, no redirect, no NAT conntrack). The whitelist cannot
    // bypass this: fragment bounds are a hard budget, checked before ACL.
    if unsafe { (*ip).frag_offset() != 0 || ((*ip).frag_flags() & 1) != 0 } {
        return Ok(fragmented_action(fragment_policy(policy, local_flags)));
    }
    let protocol = unsafe { (*ip).proto };
    let l4_offset = ip_offset + ihl;
    match l4_sanity(ctx, protocol, l4_offset, packet_end) {
        L4Class::Ok => {}
        L4Class::Malformed => return Ok(malformed_drop()),
        L4Class::Control => return Ok(control_pass()),
        L4Class::Unsupported => return Ok(unsupported_pass()),
    }
    // SAFETY: XDP programs may call the ktime helper; the returned monotonic
    // timestamp is only used for read-only rule deadline comparisons.
    let now_mono_ns = unsafe { bpf_ktime_get_ns() };
    // Whitelist priority is explicit: an allowed source skips ACL block rules
    // and per-source rate limiting — but it already passed malformed,
    // fragment and L4 sanity checks above, so hard bounds still apply.
    match acl_verdict_v4(source_be, source_be, now_mono_ns) {
        AclVerdict::Allow => return Ok(xdp_action::XDP_PASS),
        AclVerdict::Block => return Ok(block_action(policy)),
        AclVerdict::None => {}
    }
    if rate_limited_v4(ctx, source_be, protocol, l4_offset, now_mono_ns) {
        counter_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }
    dispatch_local(ctx, policy, local_flags, protocol, l4_offset, XDP_DISPATCH_NAT_TCP, XDP_DISPATCH_NAT)
}

/// Shared tail for the IPv4/IPv6 inbound handlers: destinations outside the
/// protected VIP set pass to the kernel (observable), non-TCP/UDP always
/// passes — `maybe_redirect` is a no-op for them — and local TCP/UDP in
/// proxy mode dispatches through the NAT tail call first. When the slot is
/// empty the tail call returns and the redirect falls back to the inline
/// path, which re-reads its arguments from the per-CPU scratch so the
/// dispatch site carries no spillable registers across the call.
#[inline(always)]
fn dispatch_local(
    ctx: &XdpContext,
    policy: Option<&XdpInterfacePolicy>,
    local_flags: Option<u32>,
    protocol: u8,
    l4_offset: usize,
    tcp_slot: u32,
    udp_slot: u32,
) -> Result<u32, ()> {
    let Some(policy) = policy else {
        return Ok(xdp_action::XDP_PASS);
    };
    let Some(flags) = local_flags else {
        // Inbound direction only: destinations outside the protected VIP set
        // pass to the kernel untouched and stay observable.
        counter_nonlocal_pass();
        return Ok(xdp_action::XDP_PASS);
    };
    if policy.mode != 2 {
        return Ok(xdp_action::XDP_PASS);
    }
    let slot = match protocol {
        value if value == IpProto::Tcp as u8 => tcp_slot,
        value if value == IpProto::Udp as u8 => udp_slot,
        _ => return Ok(xdp_action::XDP_PASS),
    };
    stash_redirect_ctx(flags, protocol, l4_offset);
    // A tail call only returns when the slot is empty: explicit fallback to
    // the redirect/PASS path, never a silent drop.
    unsafe { XDP_DISPATCH.tail_call(ctx, slot) };
    Ok(redirect_from_scratch(ctx, Some(policy)))
}

/// Stash the redirect context before a tail call so nothing must survive the
/// call in registers — a missing scratch entry is recovered on read-back.
#[inline(always)]
fn stash_redirect_ctx(local_flags: u32, protocol: u8, l4_offset: usize) {
    if let Ok(scratch) = nat_scratch() {
        unsafe {
            (*scratch).redir_flags = local_flags;
            (*scratch).redir_proto = protocol;
            (*scratch).redir_l4off = l4_offset as u16;
        }
    }
}

/// Park the full worker context before a dispatch -> work tail call: packet
/// offsets are re-validated inside the worker (scalar provenance does not
/// survive a tail call anyway), while flags/proto/offsets feed the redirect
/// fallback when a later slot in the chain is empty.
#[inline(always)]
fn stash_work_ctx(
    ifindex: u32,
    local_flags: u32,
    protocol: u8,
    ip_offset: usize,
    l4_offset: usize,
    packet_len: u64,
) {
    if let Ok(scratch) = nat_scratch() {
        unsafe {
            (*scratch).redir_flags = local_flags;
            (*scratch).redir_proto = protocol;
            (*scratch).redir_l4off = l4_offset as u16;
            (*scratch).work_ip_off = ip_offset as u32;
            (*scratch).work_ifindex = ifindex;
            (*scratch).work_pkt_len = packet_len;
        }
    }
}

/// Read back the worker context parked by `stash_work_ctx`. Offsets arrive as
/// unbounded scalars; every packet access in the worker re-checks bounds via
/// `ptr_at`/`ptr_at_mut`, so no verifier provenance is needed here.
#[inline(always)]
fn work_ctx() -> Result<(usize, usize, u64, u32, u8, u32), ()> {
    let scratch = nat_scratch()?;
    unsafe {
        let ip_offset = (*scratch).work_ip_off as usize;
        let l4_offset = (*scratch).redir_l4off as usize;
        // Bound the scalars before they meet packet pointers: a full-width
        // u32/u16 range defeats the verifier's variable-offset tracking, and
        // every real offset is under a few hundred bytes anyway.
        if ip_offset > 2048 || l4_offset > 2048 {
            return Err(());
        }
        Ok((
            ip_offset,
            l4_offset,
            (*scratch).work_pkt_len,
            (*scratch).redir_flags,
            (*scratch).redir_proto,
            (*scratch).work_ifindex,
        ))
    }
}

/// Inline redirect fallback after an empty NAT slot: the context was written
/// to the per-CPU scratch before the tail call, so nothing must survive the
/// call in registers. Kept as a two-argument subprogram — all-argument
/// registers, no stack slot — so the post-tail-call path in the main frame
/// stays a single call instead of the full redirect body.
#[inline(never)]
fn redirect_from_scratch(ctx: &XdpContext, policy: Option<&XdpInterfacePolicy>) -> u32 {
    let Ok(scratch) = nat_scratch() else {
        counter_map_miss();
        return match policy {
            Some(p) if p.fallback_pass == 0 => xdp_action::XDP_DROP,
            _ => xdp_action::XDP_PASS,
        };
    };
    maybe_redirect(ctx, policy, scratch)
}

fn handle_ipv6(ctx: &XdpContext, ip_offset: usize) -> Result<u32, ()> {
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    if policy.is_none() {
        counter_map_miss();
    }
    let ip: *const Ipv6Hdr = match ptr_at(ctx, ip_offset) {
        Ok(ip) => ip,
        Err(_) => return Ok(malformed_drop()),
    };
    if unsafe { (*ip).version() } != 6 {
        return Ok(malformed_drop());
    }
    let source = unsafe { (*ip).src_addr };
    let destination = unsafe { (*ip).dst_addr };
    let payload_len = unsafe { u16::from_be_bytes((*ip).payload_len) as usize };
    let packet_end = match ip_offset
        .checked_add(mem::size_of::<Ipv6Hdr>())
        .and_then(|offset| offset.checked_add(payload_len))
    {
        Some(end) => end,
        None => return Ok(malformed_drop()),
    };
    if packet_end > ctx.data_end().saturating_sub(ctx.data()) {
        return Ok(malformed_drop());
    }
    // Same ordering as handle_ipv4: fragment bounds precede the whitelist.
    let local_flags = local_flags_v6(policy, ifindex, destination);
    let protocol = unsafe { (*ip).next_hdr };
    let (protocol, l4_offset) = match ipv6_transport_offset(
        ctx,
        protocol,
        ip_offset + mem::size_of::<Ipv6Hdr>(),
        packet_end,
    ) {
        Ok(packed) if packed & V6N_FLAG == 0 => (
            (packed >> 32) as u8,
            // black_box defeats store narrowing: without it LLVM can spill
            // only the low 32 bits of the masked value, and the verifier then
            // rejects the 64-bit reload as a partially-initialized read.
            core::hint::black_box(packed & 0xffff_ffff) as usize,
        ),
        Ok(packed) if packed & 0xff == V6N_FRAGMENTED => {
            return Ok(fragmented_action(fragment_policy(policy, local_flags)));
        }
        Ok(_) => return Ok(unsupported_pass()),
        Err(()) => return Ok(malformed_drop()),
    };
    match l4_sanity(ctx, protocol, l4_offset, packet_end) {
        L4Class::Ok => {}
        L4Class::Malformed => return Ok(malformed_drop()),
        L4Class::Control => return Ok(control_pass()),
        L4Class::Unsupported => return Ok(unsupported_pass()),
    }
    // SAFETY: XDP programs may call the ktime helper; the returned monotonic
    // timestamp is only used for read-only rule deadline comparisons.
    let now_mono_ns = unsafe { bpf_ktime_get_ns() };
    match acl_verdict_v6(source, now_mono_ns) {
        AclVerdict::Allow => return Ok(xdp_action::XDP_PASS),
        AclVerdict::Block => return Ok(block_action(policy)),
        AclVerdict::None => {}
    }
    if rate_limited_v6(ctx, source, protocol, l4_offset, now_mono_ns) {
        counter_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }
    dispatch_local(ctx, policy, local_flags, protocol, l4_offset, XDP_DISPATCH_NAT_TCP6, XDP_DISPATCH_NAT_UDP6)
}

/// IPv6 extension-chain walk, packed into a single u64 so the return value
/// stays in registers (a fat enum spills partially-written stack slots that
/// the verifier rejects). Non-fragment L4: `(proto << 32) | l4_offset`.
/// With V6N_FLAG set the low byte is a V6N_* class instead.
const V6N_FLAG: u64 = 1 << 63;
const V6N_FRAGMENTED: u64 = 1;
const V6N_UNSUPPORTED: u64 = 2;

/// Decode for call sites that only care whether an L4 header was found.
#[inline(always)]
fn unpack_v6_next(packed: u64) -> Option<(u8, usize)> {
    if packed & V6N_FLAG != 0 {
        return None;
    }
    // See handle_ipv6: black_box keeps the masked low word a full-width store.
    Some((
        (packed >> 32) as u8,
        core::hint::black_box(packed & 0xffff_ffff) as usize,
    ))
}

#[inline(always)]
fn ipv6_transport_offset(
    ctx: &XdpContext,
    mut next_header: u8,
    mut offset: usize,
    packet_end: usize,
) -> Result<u64, ()> {
    for _ in 0..8 {
        match next_header {
            value if value == IpProto::Tcp as u8 || value == IpProto::Udp as u8 => {
                return Ok(((next_header as u64) << 32) | offset as u64);
            }
            IP_PROTO_ICMPV6 => return Ok(((next_header as u64) << 32) | offset as u64),
            IP_PROTO_NO_NEXT => return Ok(V6N_FLAG | V6N_UNSUPPORTED),
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
                // Non-atomic fragment (offset != 0 or M set): leave the chain
                // — first fragments never reach the L4 path either.
                if fragment & 0xfff9 != 0 {
                    return Ok(V6N_FLAG | V6N_FRAGMENTED);
                }
                next_header = current;
                offset = offset.checked_add(8).ok_or(())?;
            }
            _ => return Ok(V6N_FLAG | V6N_UNSUPPORTED),
        }
        if offset > packet_end {
            return Err(());
        }
    }
    Ok(V6N_FLAG | V6N_UNSUPPORTED)
}

/// L4-level verdict after the transport header offset is known. Malformed is
/// deterministic-illegal (bad data offset, impossible flag combo, UDP length
/// outside the datagram); Control is ICMP/ICMPv6 handed to the kernel stack
/// (ND, PMTU); Unsupported is a protocol the dataplane does not terminate.
enum L4Class {
    Ok,
    Malformed,
    Control,
    Unsupported,
}

#[inline(never)]
fn l4_sanity(ctx: &XdpContext, protocol: u8, l4_offset: usize, packet_end: usize) -> L4Class {
    match protocol {
        value if value == IpProto::Tcp as u8 => {
            if tcp_sanity(ctx, l4_offset, packet_end).is_err() {
                L4Class::Malformed
            } else {
                L4Class::Ok
            }
        }
        value if value == IpProto::Udp as u8 => {
            if udp_sanity(ctx, l4_offset, packet_end).is_err() {
                L4Class::Malformed
            } else {
                L4Class::Ok
            }
        }
        IP_PROTO_ICMP | IP_PROTO_ICMPV6 => L4Class::Control,
        _ => L4Class::Unsupported,
    }
}

/// Deterministic-illegal TCP: header outside the datagram, data offset below
/// the 20-byte minimum or beyond the segment, or an impossible flag combo
/// (no flags at all, SYN+FIN, SYN+RST). ECN (ECE/CWR) and options (TFO, MSS,
/// SACK) are untouched — they never trip these checks.
#[inline(always)]
fn tcp_sanity(ctx: &XdpContext, l4_offset: usize, packet_end: usize) -> Result<(), ()> {
    if l4_offset.checked_add(mem::size_of::<TcpHdr>()).ok_or(())? > packet_end {
        return Err(());
    }
    // Single-byte reads keep the verifier's register tracking simple; the
    // bitfield accessor chain spills into partially-untracked stack slots on
    // older kernels.
    let doff = (read_u8(ctx, l4_offset + 12)? >> 4) as usize * 4;
    if doff < mem::size_of::<TcpHdr>()
        || l4_offset.checked_add(doff).ok_or(())? > packet_end
    {
        return Err(());
    }
    let flags = read_u8(ctx, l4_offset + 13)? & 0x3f;
    if flags == 0 || (flags & TCP_FLAG_SYN != 0 && flags & (TCP_FLAG_FIN | TCP_FLAG_RST) != 0) {
        return Err(());
    }
    Ok(())
}

/// Deterministic-illegal UDP: header outside the datagram or a declared
/// length shorter than the header / beyond the datagram end.
#[inline(always)]
fn udp_sanity(ctx: &XdpContext, l4_offset: usize, packet_end: usize) -> Result<(), ()> {
    if l4_offset.checked_add(mem::size_of::<UdpHdr>()).ok_or(())? > packet_end {
        return Err(());
    }
    let udp: *const UdpHdr = ptr_at(ctx, l4_offset)?;
    let len = unsafe { (*udp).len() as usize };
    if len < mem::size_of::<UdpHdr>()
        || l4_offset.checked_add(len).ok_or(())? > packet_end
    {
        return Err(());
    }
    Ok(())
}

fn block_action(policy: Option<&XdpInterfacePolicy>) -> u32 {
    match policy {
        Some(policy) if policy.mode == 1 || policy.mode == 2 => {
            counter_acl_blocked();
            xdp_action::XDP_DROP
        }
        // Observe mode: the would-be drop stays visible instead of a silent
        // pass — previewing enforcement is the point of observe.
        Some(_) => {
            counter_acl_would_block();
            xdp_action::XDP_PASS
        }
        None => xdp_action::XDP_PASS,
    }
}

/// Deterministic-illegal packet: always dropped, on every interface mode —
/// there is no legal interpretation of a truncated header or an impossible
/// flag combination.
#[inline(always)]
fn malformed_drop() -> u32 {
    counter_malformed();
    xdp_action::XDP_DROP
}

/// Legal traffic the bounded parser cannot fully classify. Passed to the
/// kernel stack; counted so blind spots stay observable.
#[inline(always)]
fn unsupported_pass() -> u32 {
    counter_unsupported();
    xdp_action::XDP_PASS
}

/// ICMP/ICMPv6 control traffic (ND, PMTU): always handed to the kernel —
/// dropping it would break neighbor discovery and path-MTU.
#[inline(always)]
fn control_pass() -> u32 {
    counter_control();
    xdp_action::XDP_PASS
}

/// Apply the resolved fragment disposition (XDP_FRAGMENT_*).
#[inline(always)]
fn fragmented_action(action: u8) -> u32 {
    counter_fragmented();
    if action == XDP_FRAGMENT_DROP {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    }
}

/// Per-VIP override (XDP_LOCAL_* value bits[2:1]) wins over the interface
/// fragment_action. `local_flags` is the already-resolved XDP_LOCAL_* value
/// (None = destination outside the protected set -> interface default).
#[inline(always)]
fn fragment_policy(
    policy: Option<&XdpInterfacePolicy>,
    local_flags: Option<u32>,
) -> u8 {
    if let Some(flags) = local_flags {
        let code = flags & (XDP_LOCAL_FRAG_PASS | XDP_LOCAL_FRAG_DROP);
        if code == XDP_LOCAL_FRAG_PASS {
            return XDP_FRAGMENT_PASS;
        }
        if code == XDP_LOCAL_FRAG_DROP {
            return XDP_FRAGMENT_DROP;
        }
    }
    match policy {
        Some(policy) => policy.fragment_action,
        None => XDP_FRAGMENT_PASS,
    }
}

/// `local_flags` is the destination VIP's resolved XDP_LOCAL_* value —
/// None when the destination is outside the protected set. A VIP without
/// XDP_LOCAL_REDIRECT is protected but never redirected: protection scope
/// and the redirect switch are independent (EN-06), so a management VIP
/// sharing a proxy port with a tenant VIP cannot be pulled into AF_XDP.
#[inline(never)]
/// Fills the per-CPU redirect context and enters `maybe_redirect`; a missing
/// scratch entry falls back per interface policy — never silently. The raw
/// flags stay a plain u32 (u32::MAX = nonlocal) so the whole signature fits
/// in argument registers — an Option<u32> would take two and push the sixth
/// argument onto the R11 caller-frame slot the verifier rejects.
fn maybe_redirect_scratch(
    ctx: &XdpContext,
    policy: Option<&XdpInterfacePolicy>,
    local_flags_raw: u32,
    protocol: u8,
    l4_offset: usize,
) -> u32 {
    let Ok(scratch) = nat_scratch() else {
        counter_map_miss();
        return match policy {
            Some(p) if p.fallback_pass == 0 => xdp_action::XDP_DROP,
            _ => xdp_action::XDP_PASS,
        };
    };
    unsafe {
        (*scratch).redir_flags = local_flags_raw;
        (*scratch).redir_proto = protocol;
        (*scratch).redir_l4off = l4_offset as u16;
    }
    maybe_redirect(ctx, policy, scratch)
}

/// Three register-width arguments only: a wider signature makes LLVM place
/// the spilled argument in the R11 frame that the verifier rejects in
/// programs containing tail calls.
fn maybe_redirect(
    ctx: &XdpContext,
    policy: Option<&XdpInterfacePolicy>,
    scratch: *mut NatScratch,
) -> u32 {
    let (local_flags_raw, protocol, l4_offset) = unsafe {
        (
            (*scratch).redir_flags,
            (*scratch).redir_proto,
            (*scratch).redir_l4off as usize,
        )
    };
    // A map-loaded scalar has no verifier range; bound it before it becomes a
    // packet offset. L4 never starts past the bounded header walk (~512B), so
    // a larger value only means a corrupt scratch — pass, never read blind.
    if l4_offset > 512 {
        counter_parse_error();
        return xdp_action::XDP_PASS;
    }
    let local_flags = if local_flags_raw == u32::MAX {
        None
    } else {
        Some(local_flags_raw)
    };
    let Some(policy) = policy else {
        return xdp_action::XDP_PASS;
    };
    let queue = ctx.rx_queue_index();
    let ifindex = ctx.ingress_ifindex() as u32;
    if policy.mode != 2 {
        return xdp_action::XDP_PASS;
    }
    match local_flags {
        Some(flags) if flags & XDP_LOCAL_REDIRECT != 0 => {}
        _ => return xdp_action::XDP_PASS,
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
            steered_xsk = ptr_at::<u8>(ctx, l4_offset + mem::size_of::<UdpHdr>())
                .ok()
                .and_then(|base| quic_dcid_xsk_index(ctx, base));
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
/// Takes a packet pointer (not a scalar offset): the pointer carries its
/// bounds binding across the subprogram boundary, while a scalar argument
/// arrives with no packet range and the verifier rejects `data + arg`.
#[inline(never)]
fn quic_dcid_xsk_index(ctx: &XdpContext, base: *const u8) -> Option<u32> {
    // black_box keeps LLVM from hoisting the data_end load into the caller
    // and handing it in as a pkt_end argument — truncating that pointer in
    // here trips "pointer arithmetic on pkt_end prohibited".
    let end = core::hint::black_box(ctx).data_end() as *const u8;
    // One bound check covers the fixed long-header prefix: first byte,
    // 4-byte version, DCID length.
    if unsafe { base.add(6) } > end {
        return None;
    }
    let first = unsafe { *base };
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(unsafe {
        [*base.add(1), *base.add(2), *base.add(3), *base.add(4)]
    });
    if version == 0 {
        return None;
    }
    let dcid_len = unsafe { *base.add(5) } as usize;
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
            // Per-iteration bound: a variable-length check up front gives the
            // verifier no constant range for the unrolled reads.
            if unsafe { base.add(7 + i) } > end {
                return None;
            }
            key.bytes[i] = unsafe { *base.add(6 + i) };
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
    addr_be: u32,
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
    let key = XdpIpv4Key::new(addr_be);
    rate_bucket_hit_v4(&key, limit, cfg.window_ns, now_mono_ns)
}

#[inline(never)]
fn rate_limited_v6(
    ctx: &XdpContext,
    source: [u8; 16],
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
    let key = XdpIpv6Key::new(source);
    rate_bucket_hit_v6(&key, limit, cfg.window_ns, now_mono_ns)
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
    // `addr_word_count` is 1 (IPv4) or 4 (IPv6) at the call sites; constant
    // indices keep the verifier's stack-slot tracking straight-line instead
    // of a variable-bound loop over `words[i]`.
    let mut diff: i64 = unsafe {
        bpf_csum_diff(
            &mut old_addr_words[0] as *mut u32,
            4,
            &mut new_addr_words[0] as *mut u32,
            4,
            0,
        )
    } as i64;
    if addr_word_count == 4 {
        diff = unsafe {
            bpf_csum_diff(
                &mut old_addr_words[1] as *mut u32,
                4,
                &mut new_addr_words[1] as *mut u32,
                4,
                diff as u32,
            )
        } as i64;
        diff = unsafe {
            bpf_csum_diff(
                &mut old_addr_words[2] as *mut u32,
                4,
                &mut new_addr_words[2] as *mut u32,
                4,
                diff as u32,
            )
        } as i64;
        diff = unsafe {
            bpf_csum_diff(
                &mut old_addr_words[3] as *mut u32,
                4,
                &mut new_addr_words[3] as *mut u32,
                4,
                diff as u32,
            )
        } as i64;
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
    // Word-wise mixing keeps this straight-line for the verifier; the hash
    // only feeds the SNAT probe start so any deterministic mix is valid.
    let mut h = 0x9e37_79b9u32;
    unsafe {
        let v = &(*scratch).snat_rev_value;
        let a = (v.client_addr.as_ptr() as *const u64).read_unaligned();
        let b = (v.client_addr.as_ptr() as *const u64).add(1).read_unaligned();
        h ^= a as u32 ^ (a >> 32) as u32;
        h = h.wrapping_mul(31);
        h ^= b as u32 ^ (b >> 32) as u32;
        h ^= ((v.client_port_be as u32) << 8) | v.backend_port_be as u32;
    }
    h = h.wrapping_mul(0x85eb_ca6b);
    // Re-randomize the probe start per call: the tuple hash alone gives every
    // packet of a flow the same 8-slot window, so a flow whose window lands
    // on a permanently-occupied range would fail every retry forever.
    let base = ((h ^ unsafe { bpf_get_prandom_u32() }) % XDP_SNAT_PORT_SPAN as u32) as u16;

    let mut tries = 0usize;
    while tries < 8 {
        let port = XDP_SNAT_PORT_BASE.wrapping_add((base.wrapping_add(tries as u16)) % XDP_SNAT_PORT_SPAN);
        let port_be = port.to_be();
        // Never claim a port that is itself a configured listen tuple —
        // replies to it would be mistaken for forward traffic.
        unsafe {
            let rk = &(*scratch).snat_rev_key;
            let k = &mut (*scratch).fwd_key;
            copy16(&mut k.addr, &rk.listen_addr);
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
        copy16(&mut v.client_addr, &ck.client_addr);
        copy16(&mut v.backend_addr, &ck.backend_addr);
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
            // Word-wise snapshot: a whole-struct assignment lowers to a
            // variable-index byte loop that multiplies verifier states past
            // the exploration limit on older kernels.
            let src = v as *const XdpSnatRevValue as *const u64;
            let dst = &mut (*scratch).snat_rev_value as *mut XdpSnatRevValue as *mut u64;
            let mut i = 0usize;
            while i < mem::size_of::<XdpSnatRevValue>() / mem::size_of::<u64>() {
                core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
                i += 1;
            }
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
            copy16(&mut k.client_addr, &rv.client_addr);
            copy16(&mut k.backend_addr, &rv.backend_addr);
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
        copy16(&mut k.backend_addr, &rule.backend_addr);
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
        unsafe { copy16(&mut ct.listen_addr, &v.listen_addr) };
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
    let scratch = nat_scratch()?;
    copy_v6_addrs(ctx, ip_offset, scratch)?;

    unsafe {
        let k = &mut (*scratch).ct_key;
        copy16(&mut k.client_addr, &(*scratch).pkt_dst);
        copy16(&mut k.backend_addr, &(*scratch).pkt_src);
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
        unsafe { copy16(&mut (*ip_hdr).src_addr, &ct.listen_addr) };
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
            copy16(&mut k.listen_addr, &(*scratch).pkt_dst);
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
            copy16(&mut k.client_addr, &rv.client_addr);
            copy16(&mut k.backend_addr, &rv.backend_addr);
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
        unsafe { copy16(&mut (*ip_hdr).src_addr, &(*scratch).pkt_dst) };
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = listen_port.to_ne_bytes() };
        udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, src_port, listen_port)?;
        unsafe {
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
            words16_into(&(*scratch).snat_rev_value.client_addr, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { copy16(&mut (*ip_hdr).dst_addr, &(*scratch).snat_rev_value.client_addr) };
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
    let scratch = nat_scratch()?;
    copy_v6_addrs(ctx, ip_offset, scratch)?;
    unsafe {
        let k = &mut (*scratch).fwd_key;
        copy16(&mut k.addr, &(*scratch).pkt_dst);
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
        copy16(&mut k.client_addr, &(*scratch).pkt_src);
        copy16(&mut k.backend_addr, &rule.backend_addr);
        k.client_port_be = src_port;
        k.backend_port_be = rule.backend_port_be;
        k.family = 6;
        k.proto = 17;
        let v = &mut (*scratch).ct_value;
        copy16(&mut v.listen_addr, &(*scratch).pkt_dst);
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
        unsafe { copy16(&mut ct.listen_addr, &v.listen_addr) };
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
                copy16(&mut k.listen_addr, &(*scratch).pkt_dst);
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
    unsafe { copy16(&mut (*ip_hdr).dst_addr, &rule.backend_addr) };
    let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
    unsafe { (*udp_hdr).dst = rule.backend_port_be.to_ne_bytes() };
    udp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, dst_port, rule.backend_port_be)?;
    if snat_port != 0 {
        unsafe {
            words16_into(&(*scratch).pkt_src, &mut (*scratch).csum_old);
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { copy16(&mut (*ip_hdr).src_addr, &(*scratch).pkt_dst) };
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
    // `addr_word_count` is 1 (IPv4) or 4 (IPv6) at the call sites; constant
    // indices keep the verifier's stack-slot tracking straight-line instead
    // of a variable-bound loop over `words[i]`.
    let mut diff: i64 = unsafe {
        bpf_csum_diff(
            &mut old_addr_words[0] as *mut u32,
            4,
            &mut new_addr_words[0] as *mut u32,
            4,
            0,
        )
    } as i64;
    if addr_word_count == 4 {
        diff = unsafe {
            bpf_csum_diff(
                &mut old_addr_words[1] as *mut u32,
                4,
                &mut new_addr_words[1] as *mut u32,
                4,
                diff as u32,
            )
        } as i64;
        diff = unsafe {
            bpf_csum_diff(
                &mut old_addr_words[2] as *mut u32,
                4,
                &mut new_addr_words[2] as *mut u32,
                4,
                diff as u32,
            )
        } as i64;
        diff = unsafe {
            bpf_csum_diff(
                &mut old_addr_words[3] as *mut u32,
                4,
                &mut new_addr_words[3] as *mut u32,
                4,
                diff as u32,
            )
        } as i64;
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
            copy16(&mut k.client_addr, &rv.client_addr);
            copy16(&mut k.backend_addr, &rv.backend_addr);
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
        copy16(&mut k.backend_addr, &rule.backend_addr);
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
    let scratch = nat_scratch()?;
    copy_v6_addrs(ctx, ip_offset, scratch)?;

    unsafe {
        let k = &mut (*scratch).ct_key;
        copy16(&mut k.client_addr, &(*scratch).pkt_dst);
        copy16(&mut k.backend_addr, &(*scratch).pkt_src);
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
        unsafe { copy16(&mut (*ip_hdr).src_addr, &ct.listen_addr) };
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
            copy16(&mut k.listen_addr, &(*scratch).pkt_dst);
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
            copy16(&mut k.client_addr, &rv.client_addr);
            copy16(&mut k.backend_addr, &rv.backend_addr);
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
        unsafe { copy16(&mut (*ip_hdr).src_addr, &(*scratch).pkt_dst) };
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).source = listen_port.to_ne_bytes() };
        tcp_csum_update(ctx, l4_offset, unsafe { &mut (*scratch).csum_old }, unsafe { &mut (*scratch).csum_new }, 4, src_port, listen_port)?;
        unsafe {
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
            words16_into(&(*scratch).snat_rev_value.client_addr, &mut (*scratch).csum_new);
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe { copy16(&mut (*ip_hdr).dst_addr, &(*scratch).snat_rev_value.client_addr) };
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
    let scratch = nat_scratch()?;
    copy_v6_addrs(ctx, ip_offset, scratch)?;
    unsafe {
        let k = &mut (*scratch).fwd_key;
        copy16(&mut k.addr, &(*scratch).pkt_dst);
        k.port_be = dst_port;
        k.family = 6;
    };
    let Some(rule) = (unsafe { XDP_TCP_FWD.get(&(*scratch).fwd_key) }) else {
        return Ok(None);
    };
    unsafe {
        let k = &mut (*scratch).ct_key;
        copy16(&mut k.client_addr, &(*scratch).pkt_src);
        copy16(&mut k.backend_addr, &rule.backend_addr);
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
                copy16(&mut v.listen_addr, &(*scratch).pkt_dst);
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
                copy16(&mut k.listen_addr, &(*scratch).pkt_dst);
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
    unsafe { copy16(&mut (*ip_hdr).dst_addr, &rule.backend_addr) };
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
        unsafe { copy16(&mut (*ip_hdr).src_addr, &(*scratch).pkt_dst) };
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
/// Copy the two 16-byte IPv6 addresses out of the packet into the scratch
/// via four u32 accesses each: a `[u8; 16]` field copy lowers to a 16-round
/// variable-offset byte loop whose state multiplies at every call site and
/// pushes the verifier past its explored-state budget.
#[inline(always)]
/// Copy a 16-byte address between map values / packet memory. Volatile word
/// copies keep this straight-line: a plain `[u8; 16]` assignment lowers to
/// an inlined memmove whose pointer-difference overlap check multiplies
/// verifier states on older kernels. u16 words only need 2-byte alignment,
/// which every address field here satisfies.
#[inline(always)]
unsafe fn copy16(dst: *mut [u8; 16], src: *const [u8; 16]) {
    unsafe {
        let d = dst as *mut u16;
        let s = src as *const u16;
        let mut i = 0usize;
        while i < 8 {
            core::ptr::write_volatile(d.add(i), core::ptr::read_volatile(s.add(i)));
            i += 1;
        }
    }
}

fn copy_v6_addrs(ctx: &XdpContext, ip_offset: usize, scratch: *mut NatScratch) -> Result<(), ()> {
    let base = ctx.data() + ip_offset + 8; // Ipv6Hdr::src_addr
    let end = ctx.data_end();
    if base + 32 > end {
        return Err(());
    }
    // Volatile word copies: a plain loop is recognized by LLVM's memcpy
    // idiom pass and lowered to an inlined memmove whose pointer-difference
    // overlap check multiplies verifier states on older kernels.
    unsafe {
        let src = base as *const u32;
        let dst = (base + 16) as *const u32;
        let ps = (*scratch).pkt_src.as_mut_ptr() as *mut u32;
        let pd = (*scratch).pkt_dst.as_mut_ptr() as *mut u32;
        for i in 0..4usize {
            core::ptr::write_volatile(ps.add(i), core::ptr::read_volatile(src.add(i)));
            core::ptr::write_volatile(pd.add(i), core::ptr::read_volatile(dst.add(i)));
        }
    }
    Ok(())
}

fn words16_into(addr: &[u8; 16], out: &mut [u32; 4]) {
    out[0] = u32::from_ne_bytes([addr[0], addr[1], addr[2], addr[3]]);
    out[1] = u32::from_ne_bytes([addr[4], addr[5], addr[6], addr[7]]);
    out[2] = u32::from_ne_bytes([addr[8], addr[9], addr[10], addr[11]]);
    out[3] = u32::from_ne_bytes([addr[12], addr[13], addr[14], addr[15]]);
}

/// Resolve the destination's VIP flags (XDP_LOCAL_* value). Returns
/// Some(flags) when the VIP is known or when the interface has no local-IP
/// filter (unfiltered interfaces treat every destination as local with
/// redirect allowed); None only when the filter is on and the destination
/// is outside the protected set.
fn local_flags_v4(
    policy: Option<&XdpInterfacePolicy>,
    ifindex: u32,
    destination_be: u32,
) -> Option<u32> {
    match policy {
        Some(policy) if policy.local_ip_filter != 0 => unsafe {
            XDP_LOCAL_V4
                .get(&XdpLocalIpv4Key::new(ifindex, destination_be))
                .copied()
        },
        _ => Some(XDP_LOCAL_PRESENT | XDP_LOCAL_REDIRECT),
    }
}

fn local_flags_v6(
    policy: Option<&XdpInterfacePolicy>,
    ifindex: u32,
    destination: [u8; 16],
) -> Option<u32> {
    match policy {
        Some(policy) if policy.local_ip_filter != 0 => unsafe {
            XDP_LOCAL_V6
                .get(&XdpLocalIpv6Key::new(ifindex, destination))
                .copied()
        },
        _ => Some(XDP_LOCAL_PRESENT | XDP_LOCAL_REDIRECT),
    }
}

/// ACL outcome for a source: whitelist wins over blocklist — the caller has
/// already applied malformed/fragment/sanity hard bounds (EN-06).
enum AclVerdict {
    None,
    Allow,
    Block,
}

/// Kept as a bpf-to-bpf subprogram: four map lookups plus deadline checks in
/// the caller's frame pushed LLVM into R11-relative spills the verifier
/// rejects.
#[inline(never)]
/// Addr is passed by value: taking a pointer into the main program's frame
/// makes LLVM emit R11-relative accesses the verifier rejects.
fn acl_verdict_v4(addr_be: u32, source_be: u32, now_mono_ns: u64) -> AclVerdict {
    let key = XdpIpv4Key::new(addr_be);
    if active_exact_v4(&XDP_ALLOWED_V4, &key, now_mono_ns)
        || active_lpm_v4(&XDP_ALLOWED_V4_LPM, source_be, now_mono_ns)
    {
        return AclVerdict::Allow;
    }
    if active_exact_v4(&XDP_BLOCKED_V4, &key, now_mono_ns)
        || active_lpm_v4(&XDP_BLOCKED_V4_LPM, source_be, now_mono_ns)
    {
        return AclVerdict::Block;
    }
    AclVerdict::None
}

#[inline(never)]
fn acl_verdict_v6(source: [u8; 16], now_mono_ns: u64) -> AclVerdict {
    let key = XdpIpv6Key::new(source);
    if active_exact_v6(&XDP_ALLOWED_V6, &key, now_mono_ns)
        || active_lpm_v6(&XDP_ALLOWED_V6_LPM, source, now_mono_ns)
    {
        return AclVerdict::Allow;
    }
    if active_exact_v6(&XDP_BLOCKED_V6, &key, now_mono_ns)
        || active_lpm_v6(&XDP_BLOCKED_V6_LPM, source, now_mono_ns)
    {
        return AclVerdict::Block;
    }
    AclVerdict::None
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
    // `ptr + 1 > end` via ptr_at is the bound shape this kernel's verifier
    // marks reliably on variable-offset packet pointers.
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

/// Count a program's terminal action. Tail-called subprograms return their
/// action straight to the kernel - the parent program's accounting never
/// runs for them - so every entry point must count its own action. XDP_TX
/// frames are already accounted by the forwarding counters and must not be
/// double-counted as PASS.
fn count_action(action: u32) {
    match action {
        x if x == xdp_action::XDP_DROP => counter_drop(),
        x if x == xdp_action::XDP_REDIRECT => counter_redirect(),
        x if x == xdp_action::XDP_TX => counter_tx(),
        _ => counter_pass(),
    }
}

/// ACL terminal drop: distinguishable from other drop sources so a blocklist
/// hit is never indistinguishable from a rate-limit or internal drop (I10).
fn counter_acl_blocked() {
    if let Some(counters) = counters() {
        counters.acl_blocked = counters.acl_blocked.saturating_add(1);
    }
}

fn counter_tx() {
    if let Some(counters) = counters() {
        counters.tx = counters.tx.saturating_add(1);
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

fn counter_malformed() {
    if let Some(counters) = counters() {
        counters.malformed = counters.malformed.saturating_add(1);
    }
}

fn counter_unsupported() {
    if let Some(counters) = counters() {
        counters.unsupported = counters.unsupported.saturating_add(1);
    }
}

fn counter_fragmented() {
    if let Some(counters) = counters() {
        counters.fragmented = counters.fragmented.saturating_add(1);
    }
}

fn counter_control() {
    if let Some(counters) = counters() {
        counters.control = counters.control.saturating_add(1);
    }
}

fn counter_acl_would_block() {
    if let Some(counters) = counters() {
        counters.acl_would_block = counters.acl_would_block.saturating_add(1);
    }
}

fn counter_nonlocal_pass() {
    if let Some(counters) = counters() {
        counters.nonlocal_pass = counters.nonlocal_pass.saturating_add(1);
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
