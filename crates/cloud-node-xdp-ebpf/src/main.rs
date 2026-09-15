#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{
        bpf_csum_diff, bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_xdp_adjust_tail,
        bpf_xdp_load_bytes, bpf_xdp_store_bytes,
    },
    macros::{map, xdp},
    maps::{
        Array, HashMap, LpmTrie, PerCpuArray, PerCpuHashMap, ProgramArray, RingBuf, XskMap,
        lpm_trie::Key as LpmKey,
    },
    programs::XdpContext,
};
use cloud_node_xdp_common::{
    XDP_CLASS_MALFORMED, XDP_CLASS_UNSUPPORTED, XDP_CT_STATE_CLOSING, XDP_CT_STATE_OPEN,
    XDP_CT_STATE_PENDING, XDP_CT_STATE_PENDING_ACKED, XDP_DECISION_FLOW_TABLE_FULL,
    XDP_DECISION_INTERNAL_ERR, XDP_DECISION_NAT_CONFLICT, XDP_DECISION_PASS,
    XDP_FLOW_EVENT_ADMITTED, XDP_FLOW_EVENT_CLOSED,
    XDP_FLOW_EVENT_EXPIRED, XDP_FLOW_EVENT_REJECTED, XDP_FLOW_EVENT_VALIDATED, XDP_FRAGMENT_DROP,
    XDP_FRAGMENT_PASS, XDP_LOCAL_FRAG_DROP, XDP_LOCAL_FRAG_PASS, XDP_LOCAL_PRESENT,
    XDP_LOCAL_REDIRECT, XDP_PENDING_CAP_FAIL_CT_INSERT, XDP_PENDING_CAP_FAIL_FORGE,
    XDP_PENDING_CAP_FAIL_PENDING_INSERT,
    XDP_SPLICE_DONE, XDP_SPLICE_NONE, XDP_SPLICE_WAIT,
    XDP_PENDING_CAP_FAIL_SNAT_ALLOC, XDP_SNAT_PORT_BASE, XDP_SNAT_PORT_SPAN, XdpBudgetBucket,
    XdpBudgetConfig, XdpCookieKey, XdpCounters, XdpFlowAcct, XdpFlowEvent, XdpInterfacePolicy,
    XdpIpv4Key, XdpSvcBucket,
    XdpIpv6Key, XdpLocalIpv4Key, XdpLocalIpv6Key, XdpPendingCap, XdpPortProtoKey, XdpQueueKey,
    XdpQuicDcidKey, XdpRateBucket, XdpRateLimitConfig, XdpRuleValue, XdpSnatRevKey,
    XdpSnatRevValue, XdpUdpCtKey, XdpUdpCtValue, XdpUdpFwdKey, XdpUdpFwdRule,
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
static XDP_COUNTERS: PerCpuArray<XdpCounters> = PerCpuArray::<XdpCounters>::with_max_entries(1, 0);

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

/// EN-07 aggregate budgets: node-wide quotas pre-divided by possible CPUs
/// in userspace so totals never scale with CPU/queue count. `flags` bit0
/// enforces the unverified-packet budget, bit1 the new-state admission
/// budget; a zero rate or zero window disables that dimension.
#[map(name = "XDP_BUDGET_CFG")]
static XDP_BUDGET_CFG: Array<XdpBudgetConfig> = Array::<XdpBudgetConfig>::with_max_entries(1, 0);

/// Per-CPU fixed-window buckets for the aggregate budgets. Each CPU owns
/// its slots exclusively; the sum of per-CPU shares equals the configured
/// node-wide quota (I09).
#[map(name = "XDP_BUDGET")]
static XDP_BUDGET: PerCpuArray<XdpBudgetBucket> =
    PerCpuArray::<XdpBudgetBucket>::with_max_entries(1, 0);

/// EN-07 per-service fairness: per-CPU admission buckets keyed by listen
/// port so a distributed flood on one service exhausts only its own share
/// of the new-flow envelope — siblings keep theirs. Bounded at 256 keys;
/// a full map degrades to the aggregate dim1 envelope (counted via
/// svc_budget_full), never a silent bypass.
#[map(name = "XDP_SVC_BUDGET")]
static XDP_SVC_BUDGET: PerCpuHashMap<u32, XdpSvcBucket> =
    PerCpuHashMap::<u32, XdpSvcBucket>::with_max_entries(256, 0);

/// EN-14 (ADR-001): TCP cookie challenge key ring. Userspace writes a
/// random {cur, prev} pair at attach; `cur` signs new challenges and both
/// validate ACKs so one rotation never invalidates in-flight handshakes.
/// An all-zero key means "no challenge capability" — challenged rules
/// fail closed (counted) rather than silently forwarding unverified SYNs.
#[map(name = "XDP_COOKIE_KEY")]
static XDP_COOKIE_KEY: Array<XdpCookieKey> = Array::<XdpCookieKey>::with_max_entries(1, 0);

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

/// EN-09 bounded half-open table: admitted TCP flows that have not yet shown
/// handshake evidence live here, not in XDP_TCP_CT. The map bound is the
/// hard capacity — a SYN flood can fill this table without ever touching the
/// authoritative CT space used by established flows.
#[map(name = "XDP_PENDING")]
static XDP_PENDING: HashMap<XdpUdpCtKey, XdpUdpCtValue> =
    HashMap::<XdpUdpCtKey, XdpUdpCtValue>::with_max_entries(65_536, 0);
/// EN-09 admission contract: carries the absolute pending deadline
/// (pending_ttl_ns) written by userspace.
#[map(name = "XDP_PENDING_CAP")]
static XDP_PENDING_CAP: Array<XdpPendingCap> = Array::with_max_entries(1, 0);

/// EN-10 lifecycle feedback channel: a bounded ring of `XdpFlowEvent`
/// records published to userspace. Emission is advisory — a full ring only
/// increments `flow_event_lost`; kernel maps stay authoritative for flow
/// state and the dataplane never blocks on the consumer.
#[map(name = "XDP_FLOW_EVENTS")]
static XDP_FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// EN-10 owner epoch stamped on every emitted event: userspace writes the
/// current manager generation at attach so a consumer can drop feedback
/// published by an older generation (stale workers cannot renew leases on
/// re-owned flows).
#[map(name = "XDP_OWNER_EPOCH")]
static XDP_OWNER_EPOCH: Array<u64> = Array::<u64>::with_max_entries(1, 0);

/// EN-10 per-CPU event sequence feeding the (incarnation, owner_epoch, seq)
/// ordering contract.
#[map(name = "XDP_FLOW_SEQ")]
static XDP_FLOW_SEQ: PerCpuArray<u64> = PerCpuArray::<u64>::with_max_entries(1, 0);

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
    /// XdpPendingCap.flags snapshot taken once per packet at the NAT entry
    /// points — the per-CPU scratch read keeps fault-injection checks a
    /// plain load instead of a map lookup per call site.
    debug_flags: u64,
    /// EN-14 forged-packet staging (mirror of the shared NatScratch tail).
    forge_seq: u32,
    forge_ack: u32,
    forge_mss: u16,
    forge_flags: u8,
    forge_pad0: u8,
    forge_win: u16,
    forge_src_port: u16,
    forge_next_hop: [u8; 6],
    forge_pad1: [u8; 2],
    forge_incarnation: u32,
    /// Worker opcode for the slot-11 program: 0 = challenge, 1 = splice.
    forge_op: u8,
    forge_pad4: u8,
    forge_pad5: u16,
    /// Forward-rule server_id parked before the challenge tail call —
    /// full i64 width, matching XdpUdpFwdRule::server_id.
    forge_server_id: i64,
    /// EN-14: forged IPv4/TCP header staging buffers — kept in the
    /// per-CPU scratch map value so the challenge -> forge call chain
    /// stays under the 512-byte combined-stack verifier limit.
    forge_ipb: [u8; 20],
    forge_tb: [u8; 24],
    /// Transient copies of the original addrs/ports while building.
    forge_tmp: [u8; 8],
    forge_pad3: u32,
}

#[map(name = "XDP_NAT_SCRATCH")]
static XDP_NAT_SCRATCH: PerCpuArray<NatScratch> = PerCpuArray::<NatScratch>::with_max_entries(1, 0);

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
/// EN-14: challenge/splice worker. The stateless-cookie path's combined
/// stack (parse -> NAT -> challenge -> forge) exceeded the 512-byte
/// verifier limit even with scratch staging, so the heavyweight part runs
/// as its own program reached by tail call — the call boundary resets the
/// stack budget. All cross-program state is parked in NatScratch.
const XDP_DISPATCH_TCP4_CHALLENGE: u32 = 11;
/// forge_op values staged in NatScratch. The tail call itself must happen
/// at program scope — kernel 6.1 rejects tail_call inside bpf2bpf subprogs
/// without BTF — so the deep call sites park the opcode and return None;
/// try_nat_tcp4_work clears it per packet and dispatches afterwards.
const XDP_FORGE_OP_NONE: u8 = 0;
const XDP_FORGE_OP_CHALLENGE: u8 = 1;
const XDP_FORGE_OP_SPLICE: u8 = 2;

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
        if unsafe { (*ip).version() } != 4 || ihl < mem::size_of::<Ipv4Hdr>() || total_len < ihl {
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
        stash_work_ctx(
            ifindex,
            local_flags,
            proto,
            ip_offset,
            l4_offset,
            packet_len,
        );
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_UDP4_WORK) };
        return Ok(redirect_from_scratch(ctx, policy));
    }
    Ok(maybe_redirect_scratch(
        ctx,
        policy,
        local_flags,
        proto,
        l4_offset,
    ))
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
    Ok(maybe_redirect_scratch(
        ctx,
        policy,
        local_flags,
        proto,
        l4_offset,
    ))
}

/// Per-family NAT dispatchers: one (family, proto) pair per tail-call target
/// keeps each verifier run under the pre-6.6 explored-state budget - the
/// SNAT/reverse-lookup branches in a single handler are already ~10KiB of
/// BPF, and pairing families in one program multiplies states past 1M insns.
fn try_nat_udp6_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, ifindex, policy, local_flags) =
        parse_frame::<6>(ctx)?;
    if proto == IpProto::Udp as u8 {
        stash_work_ctx(
            ifindex,
            local_flags,
            proto,
            ip_offset,
            l4_offset,
            packet_len,
        );
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_UDP6_WORK) };
        return Ok(redirect_from_scratch(ctx, policy));
    }
    Ok(maybe_redirect_scratch(
        ctx,
        policy,
        local_flags,
        proto,
        l4_offset,
    ))
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
    Ok(maybe_redirect_scratch(
        ctx,
        policy,
        local_flags,
        proto,
        l4_offset,
    ))
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

/// EN-14 challenge/splice worker (dispatch slot 11). Reached only by tail
/// call from try_tcp_nat_v4's challenged-rule branches; the parked work
/// context plus forge_* scratch fields carry everything the call site
/// could not keep in registers. A `None` from the worker helper means
/// "not ours" — resolved through the same redirect fallback the TCP4 work
/// program uses, so semantics match the pre-split call chain exactly.
#[xdp]
pub fn xdp_tcp4_challenge(ctx: XdpContext) -> u32 {
    match try_tcp4_challenge(&ctx) {
        Ok(action) => {
            count_action(action);
            action
        }
        Err(_) => {
            // The forge helpers may have already rewritten parts of the
            // frame before failing — passing it to the kernel stack would
            // deliver a corrupted packet as if it were normal traffic.
            // Explicit verdict: counted and dropped.
            counter_challenge_worker_err();
            xdp_action::XDP_DROP
        }
    }
}

fn try_tcp4_challenge(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip_offset, l4_offset, _, local_flags, proto, ifindex) = work_ctx()?;
    let scratch = nat_scratch()?;
    let op = unsafe { (*scratch).forge_op };
    let action = if op == XDP_FORGE_OP_SPLICE {
        tcp_splice_anchor_v4(ctx, scratch, ip_offset | l4_offset << 16)?
    } else {
        tcp_challenge_v4(ctx, scratch, ip_offset, l4_offset)?
    };
    match action {
        Some(a) => Ok(a),
        None => {
            let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
            Ok(maybe_redirect_scratch(ctx, policy, local_flags, proto, l4_offset))
        }
    }
}

fn try_nat_tcp_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, ifindex, policy, local_flags) =
        parse_frame::<4>(ctx)?;
    if proto == IpProto::Tcp as u8 {
        stash_work_ctx(
            ifindex,
            local_flags,
            proto,
            ip_offset,
            l4_offset,
            packet_len,
        );
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP4_WORK) };
        return Ok(redirect_from_scratch(ctx, policy));
    }
    Ok(maybe_redirect_scratch(
        ctx,
        policy,
        local_flags,
        proto,
        l4_offset,
    ))
}

fn try_nat_tcp4_work(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip_offset, l4_offset, packet_len, local_flags, proto, ifindex) = work_ctx()?;
    let policy = unsafe { XDP_INTERFACE_POLICY.get(&ifindex) };
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let scratch = nat_scratch()?;
    unsafe { (*scratch).forge_op = XDP_FORGE_OP_NONE };
    if let Some(action) = try_tcp_nat_v4(ctx, ip_offset, l4_offset, packet_len, now_ns)? {
        return Ok(action);
    }
    // EN-14: the challenged-rule branches parked a worker opcode in
    // scratch and returned None; the tail call must live at program scope
    // (kernel rejects tail_call inside bpf2bpf subprogs without BTF).
    if unsafe { (*scratch).forge_op } != XDP_FORGE_OP_NONE {
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_TCP4_CHALLENGE) };
        // Slot empty (stale object): fail closed and counted — an
        // unverified packet on a challenged rule never enters the
        // normal path; for the splice op the backend retransmits and
        // re-enters the anchor once a slot-11 program exists.
        counter_challenge_rejected();
        return Ok(xdp_action::XDP_DROP);
    }
    Ok(maybe_redirect_scratch(
        ctx,
        policy,
        local_flags,
        proto,
        l4_offset,
    ))
}

fn try_nat_tcp6_dispatch(ctx: &XdpContext) -> Result<u32, ()> {
    let (_, ip_offset, proto, l4_offset, packet_len, ifindex, policy, local_flags) =
        parse_frame::<6>(ctx)?;
    if proto == IpProto::Tcp as u8 {
        stash_work_ctx(
            ifindex,
            local_flags,
            proto,
            ip_offset,
            l4_offset,
            packet_len,
        );
        unsafe { XDP_DISPATCH.tail_call(ctx, XDP_DISPATCH_NAT_TCP6_WORK) };
        return Ok(redirect_from_scratch(ctx, policy));
    }
    Ok(maybe_redirect_scratch(
        ctx,
        policy,
        local_flags,
        proto,
        l4_offset,
    ))
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
    Ok(maybe_redirect_scratch(
        ctx,
        policy,
        local_flags,
        proto,
        l4_offset,
    ))
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
        L4Class::Control => {
            // EN-07: necessary-control traffic (ICMP/ND/PMTU) has its own
            // bounded budget — never free, never unbounded.
            if !budget_charge(5, unsafe { bpf_ktime_get_ns() }) {
                counter_control_limited();
                return Ok(xdp_action::XDP_DROP);
            }
            return Ok(control_pass());
        }
        L4Class::Unsupported => return Ok(unsupported_pass()),
    }
    // SAFETY: XDP programs may call the ktime helper; the returned monotonic
    // timestamp is only used for read-only rule deadline comparisons.
    let now_mono_ns = unsafe { bpf_ktime_get_ns() };
    // Whitelist priority is explicit: an allowed source skips ACL block rules
    // and per-source rate limiting — but it already passed malformed,
    // fragment and L4 sanity checks above, so hard bounds still apply.
    // EN-06: an Allow verdict skips block rules and the per-source limiter
    // only — it never bypasses the aggregate budget below and never
    // short-circuits dispatch_local, so an already-owned flow still reaches
    // its kernel/AF_XDP/NAT owner instead of being re-bound to the kernel.
    let acl_allowed = match acl_verdict_v4(source_be, source_be, now_mono_ns) {
        AclVerdict::Allow => true,
        AclVerdict::Block => return Ok(block_action(policy)),
        AclVerdict::None => false,
    };
    // Aggregate unverified-packet budget (EN-07): charged once here for
    // every local TCP/UDP packet — before the per-source bucket, before NAT
    // dispatch, and identically across observe/protect/proxy. Verified
    // conntrack flows share this ceiling; their reserved capacity is the
    // state they already hold plus exemption from the new-flow gate below.
    if local_flags.is_some()
        && (protocol == IpProto::Tcp as u8 || protocol == IpProto::Udp as u8)
        && !budget_charge(0, now_mono_ns)
    {
        counter_unverified_limited();
        return Ok(xdp_action::XDP_DROP);
    }
    if !acl_allowed && rate_limited_v4(ctx, source_be, protocol, l4_offset, now_mono_ns) {
        counter_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }
    dispatch_local(
        ctx,
        policy,
        local_flags,
        protocol,
        l4_offset,
        XDP_DISPATCH_NAT_TCP,
        XDP_DISPATCH_NAT,
    )
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

/// Re-bind parked worker offsets at the point of use. Returns CLAMPED
/// values rather than checking: with no preceding range proof the min()
/// is a real ALU select LLVM cannot fold, so the bounded SSA value is
/// what gets spilled/passed onward — a bare `x > K` check fails here
/// because LLVM can spill the pre-check argument and the reload arrives
/// unbounded at packet-pointer arithmetic (observed on kernel 6.1). The
/// bounds differ so `(a|b) > K` merging cannot produce a single compare
/// the verifier cannot decompose. Real parked offsets are far below the
/// bounds, so clamping is identity on every real input; a hypothetical
/// corrupt scratch entry degrades to a bounded in-range read that fails
/// parsing downstream instead of an unverifiable access.
#[inline(always)]
fn bound_work_offsets(ip_offset: usize, l4_offset: usize) -> (usize, usize) {
    // AND-mask rather than min()/compare: a comparison only narrows the
    // register on one branch path and a min() may be folded when LLVM
    // already carries a range for the argument — while the verifier can
    // still see an unbounded spill slot from before the bound (kernel
    // 6.1 keeps the store-time type). The AND is a single ALU op that
    // always executes, cannot fold away for unbounded inputs, and leaves
    // every downstream spill holding a verifier-visible umax<=0x7ff.
    (ip_offset & 0x7ff, l4_offset & 0x7ff)
}

/// Read back the worker context parked by `stash_work_ctx`. Offsets arrive as
/// unbounded scalars; every packet access in the worker re-checks bounds via
/// `ptr_at`/`ptr_at_mut`, so no verifier provenance is needed here.
#[inline(always)]
fn work_ctx() -> Result<(usize, usize, u64, u32, u8, u32), ()> {
    let scratch = nat_scratch()?;
    unsafe {
        // Mask (not min/check): the AND produces a bounded SSA value in a
        // single ALU op that LLVM cannot fold, and after it executes the
        // raw load is dead — so any defensive spill/reload anywhere
        // downstream carries a verifier-visible umax<=0x7ff. A conditional
        // clamp fails on strict kernels: the pre-clamp value may be
        // spilled before the bound runs and the slot's tracked type is
        // fixed at store time (observed on kernel 6.1). Parked offsets
        // always describe the current frame (<~200B) so masking is a
        // no-op on every real value; a corrupt scratch entry wraps to a
        // bounded in-range offset that fails parsing downstream.
        let ip_offset = ((*scratch).work_ip_off as usize) & 0x7ff;
        let l4_offset = ((*scratch).redir_l4off as usize) & 0x7ff;
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
        L4Class::Control => {
            // EN-07: necessary-control traffic (ICMP/ND/PMTU) has its own
            // bounded budget — never free, never unbounded.
            if !budget_charge(5, unsafe { bpf_ktime_get_ns() }) {
                counter_control_limited();
                return Ok(xdp_action::XDP_DROP);
            }
            return Ok(control_pass());
        }
        L4Class::Unsupported => return Ok(unsupported_pass()),
    }
    // SAFETY: XDP programs may call the ktime helper; the returned monotonic
    // timestamp is only used for read-only rule deadline comparisons.
    let now_mono_ns = unsafe { bpf_ktime_get_ns() };
    // EN-06: see the IPv4 entry — Allow skips block rules and the limiter
    // only, never the aggregate budget or the owner's dispatch path.
    let acl_allowed = match acl_verdict_v6(source, now_mono_ns) {
        AclVerdict::Allow => true,
        AclVerdict::Block => return Ok(block_action(policy)),
        AclVerdict::None => false,
    };
    // Aggregate unverified-packet budget (EN-07): same gate as IPv4 —
    // once per local TCP/UDP packet, before the per-source bucket and
    // before NAT dispatch.
    if local_flags.is_some()
        && (protocol == IpProto::Tcp as u8 || protocol == IpProto::Udp as u8)
        && !budget_charge(0, now_mono_ns)
    {
        counter_unverified_limited();
        return Ok(xdp_action::XDP_DROP);
    }
    // Network-order words: from_be_bytes keeps the leading address bits in
    // the high bits of each u64 so prefix masking is ordinary shift logic.
    let (src_hi, src_lo) = unsafe {
        (
            u64::from_be(core::ptr::read_unaligned(source.as_ptr() as *const u64)),
            u64::from_be(core::ptr::read_unaligned(
                source.as_ptr().add(8) as *const u64
            )),
        )
    };
    let rate_meta = (protocol as u64) | ((l4_offset as u64) << 8);
    if !acl_allowed && rate_limited_v6(ctx, src_hi, src_lo, rate_meta, now_mono_ns) {
        counter_rate_limited();
        return Ok(xdp_action::XDP_DROP);
    }
    dispatch_local(
        ctx,
        policy,
        local_flags,
        protocol,
        l4_offset,
        XDP_DISPATCH_NAT_TCP6,
        XDP_DISPATCH_NAT_UDP6,
    )
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
    if doff < mem::size_of::<TcpHdr>() || l4_offset.checked_add(doff).ok_or(())? > packet_end {
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
    if len < mem::size_of::<UdpHdr>() || l4_offset.checked_add(len).ok_or(())? > packet_end {
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
fn fragment_policy(policy: Option<&XdpInterfacePolicy>, local_flags: Option<u32>) -> u8 {
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
            // Mask at the load site so the raw map value is dead before any
            // defensive spill — the >512 check below then decides explicitly.
            ((*scratch).redir_l4off as usize) & 0x7ff,
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
            // F7: no DCID→XSK steering here. XSKMAP redirect is only valid
            // when the target socket is bound to the *current* ingress
            // netdev/queue — steering a packet to another queue's XSK is
            // silently dropped by the kernel. Cross-queue CID delivery is
            // the shared userspace demux's job (per-listen-port CID route
            // table), so the redirect target is always this queue's XSK.
        }
        _ => return xdp_action::XDP_PASS,
    }

    let xsk_key = XdpQueueKey {
        ifindex,
        queue_id: queue,
    };
    let xsk_index = match unsafe { XDP_XSK_INDEX.get(&xsk_key) }.copied() {
        Some(index) => index,
        None => {
            counter_map_miss();
            if policy.fallback_pass != 0 {
                return xdp_action::XDP_PASS;
            }
            return xdp_action::XDP_DROP;
        }
    };

    // EN-07: redirect work has its own bounded budget — exhaustion drops
    // here with the explicit fallback, never silently re-routes ownership.
    if !budget_charge(2, unsafe { bpf_ktime_get_ns() }) {
        counter_xsk_drop();
        if policy.fallback_pass != 0 {
            return xdp_action::XDP_PASS;
        }
        return xdp_action::XDP_DROP;
    }
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
    // Prefix fairness (EN-08): mask the source to the configured prefix so
    // a randomized flood inside one prefix shares one bucket; 0 = per-IP.
    let masked = if cfg.v4_prefix_len >= 32 || cfg.v4_prefix_len == 0 {
        addr_be
    } else {
        addr_be & (u32::MAX << (32 - cfg.v4_prefix_len))
    };
    let key = XdpIpv4Key::new(masked);
    rate_bucket_hit_v4(&key, limit, cfg.window_ns, now_mono_ns)
}

#[inline(never)]
fn rate_limited_v6(
    ctx: &XdpContext,
    src_hi: u64,
    src_lo: u64,
    meta: u64,
    now_mono_ns: u64,
) -> bool {
    let Some(cfg) = XDP_RATE_CFG.get(0) else {
        return false;
    };
    let protocol = (meta & 0xff) as u8;
    // Bound the packed offset before it is added to a packet pointer — an
    // unbounded variable offset defeats the verifier's range tracking.
    let l4_offset = ((meta >> 8) & 0x3fff) as usize;
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
    // Prefix fairness (EN-08): mask the source words to the configured v6
    // prefix — word ops only, no variable-index byte loops and no
    // stack-passed sixth argument (5-reg signature keeps LLVM off r11).
    let (mut hi, mut lo) = (src_hi, src_lo);
    if cfg.v6_prefix_len > 0 && cfg.v6_prefix_len < 128 {
        let hi_keep = (cfg.v6_prefix_len as usize).min(64);
        let lo_keep = (cfg.v6_prefix_len as usize).saturating_sub(64);
        if hi_keep == 0 {
            hi = 0;
        } else if hi_keep < 64 {
            hi &= u64::MAX << (64 - hi_keep);
        }
        if lo_keep == 0 {
            lo = 0;
        } else if lo_keep < 64 {
            lo &= u64::MAX << (64 - lo_keep);
        }
    }
    let key = XdpIpv6Key::new(unsafe {
        let mut b = [0u8; 16];
        core::ptr::write_unaligned(b.as_mut_ptr() as *mut u64, hi.to_be());
        core::ptr::write_unaligned(b.as_mut_ptr().add(8) as *mut u64, lo.to_be());
        b
    });
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
            bpf_csum_diff(
                &mut old_p as *mut u32,
                4,
                &mut new_p as *mut u32,
                4,
                diff as u32,
            )
        };
    }
    unsafe { (*udp).check = csum_apply_diff(old_check, diff).to_ne_bytes() };
    Ok(())
}

fn acct_flow(key: &XdpUdpCtKey, rx_bytes: u64, tx_bytes: u64, server_id: i64, now_mono_ns: u64) {
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

fn counter_nat_conflict() {
    if let Some(counters) = counters() {
        counters.nat_conflict = counters.nat_conflict.saturating_add(1);
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
    // Test hook: pretend port exhaustion so callers exercise the explicit
    // fallback without waiting for 20k ports to be claimed.
    if unsafe { (*scratch).debug_flags } & XDP_PENDING_CAP_FAIL_SNAT_ALLOC != 0 {
        counter_snat_alloc_fail();
        return None;
    }
    // Word-wise mixing keeps this straight-line for the verifier; the hash
    // only feeds the SNAT probe start so any deterministic mix is valid.
    let mut h = 0x9e37_79b9u32;
    unsafe {
        let v = &(*scratch).snat_rev_value;
        let a = (v.client_addr.as_ptr() as *const u64).read_unaligned();
        let b = (v.client_addr.as_ptr() as *const u64)
            .add(1)
            .read_unaligned();
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
        let port =
            XDP_SNAT_PORT_BASE.wrapping_add((base.wrapping_add(tries as u16)) % XDP_SNAT_PORT_SPAN);
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

/// EN-11 rollback: release a SNAT binding claimed by `snat_alloc` when the
/// owning conntrack/pending insert subsequently failed. `snat_rev_key`
/// still carries the claimed port, so removing it returns the port to the
/// allocatable space instead of leaking it as an orphan until the sweep.
#[inline(never)]
fn snat_release(scratch: *mut NatScratch) {
    let _ = XDP_SNAT_REV.remove(unsafe { &(*scratch).snat_rev_key });
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

fn rate_bucket_hit_v4(key: &XdpIpv4Key, limit: u64, window_ns: u64, now_mono_ns: u64) -> bool {
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
            // Source-bucket table exhausted: the packet already paid the
            // aggregate unverified budget above, so it falls back to that
            // ceiling — bounded and counted, never silently unlimited.
            counter_ratelimit_map_full();
            false
        }
    }
}

fn rate_bucket_hit_v6(key: &XdpIpv6Key, limit: u64, window_ns: u64, now_mono_ns: u64) -> bool {
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
            // Source-bucket table exhausted: falls back to the aggregate
            // unverified budget charged earlier — bounded and counted.
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
    let (ip_offset, l4_offset) = bound_work_offsets(ip_offset, l4_offset);
    let udp = ptr_at::<UdpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*udp).src) };
    let dst_port = unsafe { u16::from_ne_bytes((*udp).dst) };
    let ip = ptr_at::<Ipv4Hdr>(ctx, ip_offset)?;
    let src_addr = unsafe { (*ip).src_addr };
    let dst_addr = unsafe { (*ip).dst_addr };
    let src_be = u32::from_be_bytes(src_addr);
    let dst_be = u32::from_be_bytes(dst_addr);
    let scratch = nat_scratch()?;
    // Snapshot test-only fault flags once per packet — inner checks read
    // this scratch field instead of paying a map lookup per call site.
    unsafe { (*scratch).debug_flags = pending_cap_flags() };

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
        if !verified_hit(now_mono_ns) {
            return Ok(Some(xdp_action::XDP_DROP));
        }
        ct.last_seen_ns = now_mono_ns;
        let listen_be = u32::from_be_bytes([
            ct.listen_addr[0],
            ct.listen_addr[1],
            ct.listen_addr[2],
            ct.listen_addr[3],
        ]);
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
        ipv4_csum_update(
            ctx,
            ip_offset,
            u32::from_ne_bytes(src_addr),
            u32::from_ne_bytes(listen_be.to_be_bytes()),
        )?;
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = listen_port.to_ne_bytes() };
        udp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            1,
            src_port,
            listen_port,
        )?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(
            unsafe { &(*scratch).ct_key },
            0,
            packet_len,
            ct.server_id,
            now_mono_ns,
        );
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
        k._pad = [0; 4];
    }
    if snat_rev_lookup(scratch)
        && unsafe {
            let rv = &(*scratch).snat_rev_value;
            rv.backend_port_be == src_port && rv.backend_addr[..4] == src_be.to_be_bytes()
        }
    {
        if !verified_hit(now_mono_ns) {
            return Ok(Some(xdp_action::XDP_DROP));
        }
        let client_be = u32::from_be_bytes(unsafe {
            let rv = &(*scratch).snat_rev_value;
            [
                rv.client_addr[0],
                rv.client_addr[1],
                rv.client_addr[2],
                rv.client_addr[3],
            ]
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
        ipv4_csum_update(
            ctx,
            ip_offset,
            u32::from_ne_bytes(src_addr),
            u32::from_ne_bytes(dst_be.to_be_bytes()),
        )?;
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(src_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(dst_be.to_be_bytes()), 0, 0, 0];
        }
        unsafe {
            let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
            (*udp_hdr).src = listen_port.to_ne_bytes();
        }
        udp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            1,
            src_port,
            listen_port,
        )?;
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).dst_addr = client_be.to_be_bytes() };
        ipv4_csum_update(
            ctx,
            ip_offset,
            u32::from_ne_bytes(dst_addr),
            u32::from_ne_bytes(client_be.to_be_bytes()),
        )?;
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).dst = client_port.to_ne_bytes() };
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(dst_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(client_be.to_be_bytes()), 0, 0, 0];
        }
        udp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            1,
            dst_port,
            client_port,
        )?;
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
        if !verified_hit(now_mono_ns) {
            return Ok(Some(xdp_action::XDP_DROP));
        }
        // EN-11 multi-VIP disambiguation: the flow tuple is already bound
        // to a different listen tuple — reject instead of silently
        // rebinding the reply owner to a VIP the client never dialed.
        if ct.listen_addr != v.listen_addr || ct.listen_port_be != v.listen_port_be {
            counter_nat_conflict();
            emit_flow_event(
                ct,
                XDP_FLOW_EVENT_REJECTED,
                XDP_DECISION_NAT_CONFLICT,
                now_mono_ns,
            );
            return Ok(None);
        }
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
        // New-state admission: charge the new-flow budget BEFORE any
        // conntrack or SNAT state is created — rejection leaves nothing
        // behind and repeated same-tuple packets keep paying the cost.
        if !budget_charge(1, now_mono_ns) {
            counter_admission_limited();
            return Ok(Some(xdp_action::XDP_DROP));
        }
        // Per-service fairness (dim6): the listen port's bucket is charged
        // after the aggregate gate so a single flooded service cannot drain
        // sibling services' share of the new-flow envelope.
        if !svc_budget_charge(dst_port, now_mono_ns) {
            counter_service_limited();
            return Ok(Some(xdp_action::XDP_DROP));
        }
        if rule.snat != 0 {
            unsafe {
                let k = &mut (*scratch).snat_rev_key;
                k.listen_addr = v4_embed(dst_be);
                k.snat_port_be = 0;
                k.proto = 17;
                k.family = 4;
                k._pad = [0; 4];
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
            // EN-11 rollback: a claimed SNAT port must not outlive the
            // rejected admission — release the reverse binding first.
            if snat_port != 0 {
                snat_release(scratch);
            }
            emit_flow_event(
                unsafe { &(*scratch).ct_value },
                XDP_FLOW_EVENT_REJECTED,
                XDP_DECISION_FLOW_TABLE_FULL,
                now_mono_ns,
            );
            // Fail explicit: report and leave the packet to the normal path so a
            // full conntrack table degrades to userspace handling, not drops.
            counter_udp_fwd_map_full();
            return Ok(None);
        }
        emit_flow_event(
            unsafe { &(*scratch).ct_value },
            XDP_FLOW_EVENT_VALIDATED,
            XDP_DECISION_PASS,
            now_mono_ns,
        );
    }
    // Rewrite destination -> backend.
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
    let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
    unsafe { (*udp_hdr).dst = rule.backend_port_be.to_ne_bytes() };
    udp_csum_update(
        ctx,
        l4_offset,
        unsafe { &mut (*scratch).csum_old },
        unsafe { &mut (*scratch).csum_new },
        1,
        dst_port,
        rule.backend_port_be,
    )?;
    if snat_port != 0 {
        // Rewrite source -> (listen addr, allocated node port) so the frame
        // passes fabrics that egress-filter foreign source IPs.
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
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = snat_port.to_ne_bytes() };
        udp_csum_update(
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
    let (ip_offset, l4_offset) = bound_work_offsets(ip_offset, l4_offset);
    let udp = ptr_at::<UdpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*udp).src) };
    let dst_port = unsafe { u16::from_ne_bytes((*udp).dst) };
    let scratch = nat_scratch()?;
    // Snapshot test-only fault flags once per packet — inner checks read
    // this scratch field instead of paying a map lookup per call site.
    unsafe { (*scratch).debug_flags = pending_cap_flags() };
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
        if !verified_hit(now_mono_ns) {
            return Ok(Some(xdp_action::XDP_DROP));
        }
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
        udp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            4,
            src_port,
            listen_port,
        )?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(
            unsafe { &(*scratch).ct_key },
            0,
            packet_len,
            ct.server_id,
            now_mono_ns,
        );
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
        k._pad = [0; 4];
    }
    if snat_rev_lookup(scratch)
        && unsafe {
            let rv = &(*scratch).snat_rev_value;
            rv.backend_port_be == src_port && rv.backend_addr == (*scratch).pkt_src
        }
    {
        if !verified_hit(now_mono_ns) {
            return Ok(Some(xdp_action::XDP_DROP));
        }
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
        udp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            4,
            src_port,
            listen_port,
        )?;
        unsafe {
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
            words16_into(
                &(*scratch).snat_rev_value.client_addr,
                &mut (*scratch).csum_new,
            );
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe {
            copy16(
                &mut (*ip_hdr).dst_addr,
                &(*scratch).snat_rev_value.client_addr,
            )
        };
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).dst = client_port.to_ne_bytes() };
        udp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            4,
            dst_port,
            client_port,
        )?;
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
    let (ip_offset, l4_offset) = bound_work_offsets(ip_offset, l4_offset);
    let udp = ptr_at::<UdpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*udp).src) };
    let dst_port = unsafe { u16::from_ne_bytes((*udp).dst) };
    let scratch = nat_scratch()?;
    // Snapshot test-only fault flags once per packet — inner checks read
    // this scratch field instead of paying a map lookup per call site.
    unsafe { (*scratch).debug_flags = pending_cap_flags() };
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
        if !verified_hit(now_mono_ns) {
            return Ok(Some(xdp_action::XDP_DROP));
        }
        // EN-11 multi-VIP disambiguation: reject instead of silently
        // rebinding the reply owner to a VIP the client never dialed.
        if ct.listen_addr != v.listen_addr || ct.listen_port_be != v.listen_port_be {
            counter_nat_conflict();
            emit_flow_event(
                ct,
                XDP_FLOW_EVENT_REJECTED,
                XDP_DECISION_NAT_CONFLICT,
                now_mono_ns,
            );
            return Ok(None);
        }
        unsafe { copy16(&mut ct.listen_addr, &v.listen_addr) };
        ct.client_mac = v.client_mac;
        ct.listen_port_be = v.listen_port_be;
        ct.family = v.family;
        ct.state = v.state;
        ct.server_id = v.server_id;
        ct.last_seen_ns = v.last_seen_ns;
        snat_port = ct.snat_port_be;
    } else {
        // Admission gate: charge the new-flow budget before any conntrack
        // or SNAT state exists for this tuple.
        if !budget_charge(1, now_mono_ns) {
            counter_admission_limited();
            return Ok(Some(xdp_action::XDP_DROP));
        }
        // Per-service fairness (dim6): the listen port's bucket is charged
        // after the aggregate gate so a single flooded service cannot drain
        // sibling services' share of the new-flow envelope.
        if !svc_budget_charge(dst_port, now_mono_ns) {
            counter_service_limited();
            return Ok(Some(xdp_action::XDP_DROP));
        }
        if rule.snat != 0 {
            unsafe {
                let k = &mut (*scratch).snat_rev_key;
                copy16(&mut k.listen_addr, &(*scratch).pkt_dst);
                k.snat_port_be = 0;
                k.proto = 17;
                k.family = 6;
                k._pad = [0; 4];
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
            // EN-11 rollback: release the claimed SNAT port so a rejected
            // admission leaves no binding behind.
            if snat_port != 0 {
                snat_release(scratch);
            }
            emit_flow_event(
                unsafe { &(*scratch).ct_value },
                XDP_FLOW_EVENT_REJECTED,
                XDP_DECISION_FLOW_TABLE_FULL,
                now_mono_ns,
            );
            counter_udp_fwd_map_full();
            return Ok(None);
        }
        emit_flow_event(
            unsafe { &(*scratch).ct_value },
            XDP_FLOW_EVENT_VALIDATED,
            XDP_DECISION_PASS,
            now_mono_ns,
        );
    }
    unsafe {
        words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
        words16_into(&rule.backend_addr, &mut (*scratch).csum_new);
    }
    let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
    unsafe { copy16(&mut (*ip_hdr).dst_addr, &rule.backend_addr) };
    let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
    unsafe { (*udp_hdr).dst = rule.backend_port_be.to_ne_bytes() };
    udp_csum_update(
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
        let udp_hdr = ptr_at_mut::<UdpHdr>(ctx, l4_offset)?;
        unsafe { (*udp_hdr).src = snat_port.to_ne_bytes() };
        udp_csum_update(
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
            bpf_csum_diff(
                &mut old_p as *mut u32,
                4,
                &mut new_p as *mut u32,
                4,
                diff as u32,
            )
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
    let (ip_offset, l4_offset) = bound_work_offsets(ip_offset, l4_offset);
    let tcp = ptr_at::<TcpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*tcp).source) };
    let dst_port = unsafe { u16::from_ne_bytes((*tcp).dest) };
    let syn = unsafe { (*tcp).syn() } == 1;
    let ack = unsafe { (*tcp).ack() } == 1;
    let closing = unsafe { (*tcp).fin() } == 1 || unsafe { (*tcp).rst() } == 1;
    let seq = unsafe { u32::from_be_bytes((*tcp).seq) };
    let ackno = unsafe { u32::from_be_bytes((*tcp).ack_seq) };
    let ip = ptr_at::<Ipv4Hdr>(ctx, ip_offset)?;
    let src_addr = unsafe { (*ip).src_addr };
    let dst_addr = unsafe { (*ip).dst_addr };
    let src_be = u32::from_be_bytes(src_addr);
    let dst_be = u32::from_be_bytes(dst_addr);
    let scratch = nat_scratch()?;
    // Snapshot test-only fault flags once per packet — inner checks read
    // this scratch field instead of paying a map lookup per call site.
    unsafe { (*scratch).debug_flags = pending_cap_flags() };

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
    if let Some(ct) = XDP_TCP_CT
        .get_ptr_mut(unsafe { &(*scratch).ct_key })
        .or_else(|| XDP_PENDING.get_ptr_mut(unsafe { &(*scratch).ct_key }))
    {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        if ct.state == XDP_CT_STATE_PENDING || ct.state == XDP_CT_STATE_PENDING_ACKED {
            // EN-13/14: handshake evidence is only a backend SYN-ACK that
            // acknowledges the client's ISN (ackno == client_isn+1 anchored
            // at admission). Any other backend packet keeps the entry
            // half-open — blind replies must not mark strong verification.
            // Absolute deadline: last_seen_ns is never extended.
            if syn && ack && ackno == ct.expect_seq {
                ct.state = XDP_CT_STATE_PENDING_ACKED;
                ct.expect_ack = seq.wrapping_add(1);
            }
        } else {
            if !verified_hit(now_mono_ns) {
                return Ok(Some(xdp_action::XDP_DROP));
            }
            ct.last_seen_ns = now_mono_ns;
            if closing && ct.state == XDP_CT_STATE_OPEN {
                ct.state = XDP_CT_STATE_CLOSING;
                emit_flow_event(ct, XDP_FLOW_EVENT_CLOSED, XDP_DECISION_PASS, now_mono_ns);
            }
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
        tcp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            1,
            src_port,
            listen_port,
        )?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(
            unsafe { &(*scratch).ct_key },
            0,
            packet_len,
            ct.server_id,
            now_mono_ns,
        );
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
        k._pad = [0; 4];
    }
    if snat_rev_lookup(scratch)
        && unsafe {
            let rv = &(*scratch).snat_rev_value;
            rv.backend_port_be == src_port && rv.backend_addr[..4] == src_be.to_be_bytes()
        }
    {
        if !verified_hit(now_mono_ns) {
            return Ok(Some(xdp_action::XDP_DROP));
        }
        let client_be = u32::from_be_bytes(unsafe {
            let rv = &(*scratch).snat_rev_value;
            [
                rv.client_addr[0],
                rv.client_addr[1],
                rv.client_addr[2],
                rv.client_addr[3],
            ]
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
        // EN-14 splice gate — checked BEFORE the client-directed rewrite:
        // the slot-11 anchor worker forges the handshake-completing ACK on
        // the ORIGINAL backend-directed frame, whose eth.src is the
        // backend next-hop MAC and whose ip.dst is the VIP. After the
        // rewrite below both would already point at the client and the
        // forged ACK would carry the client address as its source.
        if let Some(ct) = XDP_TCP_CT
            .get_ptr_mut(unsafe { &(*scratch).ct_key })
            .or_else(|| XDP_PENDING.get_ptr_mut(unsafe { &(*scratch).ct_key }))
        {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            if (ct.state == XDP_CT_STATE_PENDING
                || ct.state == XDP_CT_STATE_PENDING_ACKED)
                && ct.splice_state == XDP_SPLICE_WAIT
                && syn && ack && ackno == ct.expect_seq
            {
                // Backend SYN-ACK anchors the splice — stage the wire seq
                // (b_isn) and hand off to the slot-11 worker via the
                // program-scope tail call in try_nat_tcp4_work. The worker
                // re-looks-up the record and re-checks the splice gate.
                unsafe {
                    (*scratch).forge_seq = seq;
                    (*scratch).forge_op = XDP_FORGE_OP_SPLICE;
                }
                return Ok(None);
            }
        }
        // Source becomes the listen tuple the client originally dialed.
        unsafe {
            let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
            (*ip_hdr).src_addr = dst_be.to_be_bytes();
        }
        ipv4_csum_update(
            ctx,
            ip_offset,
            u32::from_ne_bytes(src_addr),
            u32::from_ne_bytes(dst_be.to_be_bytes()),
        )?;
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(src_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(dst_be.to_be_bytes()), 0, 0, 0];
        }
        unsafe {
            let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
            (*tcp_hdr).source = listen_port.to_ne_bytes();
        }
        tcp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            1,
            src_port,
            listen_port,
        )?;
        unsafe {
            (*scratch).csum_old = [u32::from_ne_bytes(dst_addr), 0, 0, 0];
            (*scratch).csum_new = [u32::from_ne_bytes(client_be.to_be_bytes()), 0, 0, 0];
        }
        let ip_hdr = ptr_at_mut::<Ipv4Hdr>(ctx, ip_offset)?;
        unsafe { (*ip_hdr).dst_addr = client_be.to_be_bytes() };
        ipv4_csum_update(
            ctx,
            ip_offset,
            u32::from_ne_bytes(dst_addr),
            u32::from_ne_bytes(client_be.to_be_bytes()),
        )?;
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).dest = client_port.to_ne_bytes() };
        tcp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            1,
            dst_port,
            client_port,
        )?;
        eth_rewrite(ctx, client_mac)?;
        if let Some(ct) = XDP_TCP_CT
            .get_ptr_mut(unsafe { &(*scratch).ct_key })
            .or_else(|| XDP_PENDING.get_ptr_mut(unsafe { &(*scratch).ct_key }))
        {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            if ct.state == XDP_CT_STATE_PENDING || ct.state == XDP_CT_STATE_PENDING_ACKED {
                if ct.splice_state == XDP_SPLICE_WAIT {
                    // EN-14: backend SYN-ACK anchors the splice — consume it
                    // and answer the backend handshake; any other backend
                    // packet (e.g. RST refusing the replay) falls through to
                    // the normal rewrite so the client sees the refusal.
                    if syn && ack && ackno == ct.expect_seq {
                        // Stage the wire seq (b_isn) and hand off to the
                        // slot-11 worker via the program-scope tail call
                        // in try_nat_tcp4_work (subprog tail calls are
                        // rejected without BTF). The worker re-looks-up
                        // the record and re-checks the splice gate.
                        unsafe {
                            (*scratch).forge_seq = seq;
                            (*scratch).forge_op = XDP_FORGE_OP_SPLICE;
                        }
                        return Ok(None);
                    }
                } else if syn && ack && ackno == ct.expect_seq {
                    ct.state = XDP_CT_STATE_PENDING_ACKED;
                    ct.expect_ack = seq.wrapping_add(1);
                }
            } else {
                if !verified_hit(now_mono_ns) {
                    return Ok(Some(xdp_action::XDP_DROP));
                }
                ct.last_seen_ns = now_mono_ns;
                if closing && ct.state == XDP_CT_STATE_OPEN {
                    ct.state = XDP_CT_STATE_CLOSING;
                    emit_flow_event(ct, XDP_FLOW_EVENT_CLOSED, XDP_DECISION_PASS, now_mono_ns);
                }
                // EN-14 splice: backend seq space -> challenge seq space.
                if ct.splice_state == XDP_SPLICE_DONE {
                    tcp_patch_u32(ctx, l4_offset, 4, seq.wrapping_add(ct.seq_delta as u32))?;
                }
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
    let mut splice_delta = 0i32;
    match XDP_TCP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        Some(ct) => {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            if !verified_hit(now_mono_ns) {
                return Ok(Some(xdp_action::XDP_DROP));
            }
            // EN-11: flow tuple already bound to a different listen (VIP)
            // tuple — reject rather than rebinding reply ownership.
            if ct.listen_addr != v4_embed(dst_be) || ct.listen_port_be != dst_port {
                counter_nat_conflict();
                emit_flow_event(
                    ct,
                    XDP_FLOW_EVENT_REJECTED,
                    XDP_DECISION_NAT_CONFLICT,
                    now_mono_ns,
                );
                return Ok(None);
            }
            ct.last_seen_ns = now_mono_ns;
            if closing && ct.state == XDP_CT_STATE_OPEN {
                ct.state = XDP_CT_STATE_CLOSING;
                emit_flow_event(ct, XDP_FLOW_EVENT_CLOSED, XDP_DECISION_PASS, now_mono_ns);
            }
            // Flows established before SNAT was configured keep plain DNAT.
            snat_port = ct.snat_port_be;
            // EN-14 splice: client ACK numbers live in challenge space —
            // translate to backend space on the wire.
            if ct.splice_state == XDP_SPLICE_DONE && ack {
                splice_delta = ct.seq_delta;
            }
        }
        None => {
            // EN-09: consult the bounded half-open table before treating the
            // packet as an unknown flow. Pending hits forward through the
            // shared rewrite below without extending their absolute deadline.
            unsafe { (*scratch).pkt_dst = v4_embed(dst_be) };
            let r = pending_touch(
                scratch,
                now_mono_ns,
                ack && !syn,
                dst_port,
                seq as u64 | (ackno as u64) << 32,
            );
            let pend = r as u8;
            let incarnation = (r >> 8) as u32;
            let pending_port = (r >> 40) as u16;
            if pend == PENDING_CONFLICT {
                counter_nat_conflict();
                return Ok(None);
            }
            if pend == PENDING_ALIVE {
                snat_port = pending_port;
            } else if pend == PENDING_SPLICING {
                // Post-cookie splice in flight (backend handshake not yet
                // anchored): consume client packets — forwarding them would
                // reach a SYN-RECV backend with un-anchored sequence space.
                return Ok(Some(xdp_action::XDP_DROP));
            } else {
                if rule.challenge != 0 && rule.snat != 0 {
                    // EN-14 stateless challenge path (ADR-001): state is
                    // created only after cookie proof in the worker. The
                    // heavyweight forge chain runs in the slot-11 program
                    // (512B stack budget); rule fields it needs are parked
                    // in scratch because map pointers cannot cross the
                    // tail-call boundary. The opcode + None return hands
                    // dispatch to the program-scope tail call in
                    // try_nat_tcp4_work.
                    unsafe {
                        (*scratch).forge_incarnation = incarnation;
                        (*scratch).forge_server_id = rule.server_id;
                        (*scratch).forge_next_hop = rule.next_hop_mac;
                        (*scratch).forge_op = XDP_FORGE_OP_CHALLENGE;
                    }
                    return Ok(None);
                }
                if !(syn && !ack) {
                    return Ok(None);
                }
                // Fresh SYN creating new conntrack state: charge the new-flow
                // budget before snat_alloc / pending insert — a rejected
                // admission leaves no state behind.
                if !budget_charge(1, now_mono_ns) {
                    counter_admission_limited();
                    return Ok(Some(xdp_action::XDP_DROP));
                }
                // Per-service fairness (dim6) — same contract as UDP.
                if !svc_budget_charge(dst_port, now_mono_ns) {
                    counter_service_limited();
                    return Ok(Some(xdp_action::XDP_DROP));
                }
                let eth = ptr_at::<EthHdr>(ctx, 0)?;
                let client_mac = unsafe { (*eth).src_addr };
                unsafe {
                    let v = &mut (*scratch).ct_value;
                    v.listen_addr = v4_embed(dst_be);
                    v.client_mac = client_mac;
                    v.listen_port_be = dst_port;
                    v.family = 4;
                    v.state = XDP_CT_STATE_PENDING;
                    v.expect_seq = seq.wrapping_add(1);
                    v.expect_ack = 0;
                    v.snat_port_be = 0;
                    v.server_id = rule.server_id;
                    v.last_seen_ns = now_mono_ns;
                    v.incarnation = incarnation;
                }
                if rule.snat != 0 {
                    unsafe {
                        let k = &mut (*scratch).snat_rev_key;
                        k.listen_addr = v4_embed(dst_be);
                        k.snat_port_be = 0;
                        k.proto = 6;
                        k.family = 4;
                        k._pad = [0; 4];
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
                // Test hook: FAIL_PENDING_INSERT forces the bounded-table
                // failure path (rollback + counter + explicit fallback).
                let pending_insert_ok =
                    unsafe { (*scratch).debug_flags } & XDP_PENDING_CAP_FAIL_PENDING_INSERT == 0
                        && XDP_PENDING
                            .insert(
                                unsafe { &(*scratch).ct_key },
                                unsafe { &(*scratch).ct_value },
                                0,
                            )
                            .is_ok();
                if !pending_insert_ok {
                    // EN-11 rollback: release the claimed SNAT port so a
                    // rejected admission leaves no binding behind.
                    if snat_port != 0 {
                        snat_release(scratch);
                    }
                    counter_pending_limited();
                    emit_flow_event(
                        unsafe { &(*scratch).ct_value },
                        XDP_FLOW_EVENT_REJECTED,
                        XDP_DECISION_FLOW_TABLE_FULL,
                        now_mono_ns,
                    );
                    return Ok(None);
                }
                emit_flow_event(
                    unsafe { &(*scratch).ct_value },
                    XDP_FLOW_EVENT_ADMITTED,
                    XDP_DECISION_PASS,
                    now_mono_ns,
                );
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
    if splice_delta != 0 {
        tcp_patch_u32(ctx, l4_offset, 8, ackno.wrapping_sub(splice_delta as u32))?;
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
    let (ip_offset, l4_offset) = bound_work_offsets(ip_offset, l4_offset);
    let tcp = ptr_at::<TcpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*tcp).source) };
    let dst_port = unsafe { u16::from_ne_bytes((*tcp).dest) };
    let syn = unsafe { (*tcp).syn() } == 1;
    let ack = unsafe { (*tcp).ack() } == 1;
    let closing = unsafe { (*tcp).fin() } == 1 || unsafe { (*tcp).rst() } == 1;
    let seq = unsafe { u32::from_be_bytes((*tcp).seq) };
    let ackno = unsafe { u32::from_be_bytes((*tcp).ack_seq) };
    let scratch = nat_scratch()?;
    // Snapshot test-only fault flags once per packet — inner checks read
    // this scratch field instead of paying a map lookup per call site.
    unsafe { (*scratch).debug_flags = pending_cap_flags() };
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
    if let Some(ct) = XDP_TCP_CT
        .get_ptr_mut(unsafe { &(*scratch).ct_key })
        .or_else(|| XDP_PENDING.get_ptr_mut(unsafe { &(*scratch).ct_key }))
    {
        // SAFETY: pointer into the map value for `ct_key`.
        let ct = unsafe { &mut *ct };
        if ct.state == XDP_CT_STATE_PENDING || ct.state == XDP_CT_STATE_PENDING_ACKED {
            // EN-13/14: handshake evidence is only a backend SYN-ACK that
            // acknowledges the client's ISN (ackno == client_isn+1 anchored
            // at admission). Any other backend packet keeps the entry
            // half-open — blind replies must not mark strong verification.
            // Absolute deadline: last_seen_ns is never extended.
            if syn && ack && ackno == ct.expect_seq {
                ct.state = XDP_CT_STATE_PENDING_ACKED;
                ct.expect_ack = seq.wrapping_add(1);
            }
        } else {
            if !verified_hit(now_mono_ns) {
                return Ok(Some(xdp_action::XDP_DROP));
            }
            ct.last_seen_ns = now_mono_ns;
            if closing && ct.state == XDP_CT_STATE_OPEN {
                ct.state = XDP_CT_STATE_CLOSING;
                emit_flow_event(ct, XDP_FLOW_EVENT_CLOSED, XDP_DECISION_PASS, now_mono_ns);
            }
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
        tcp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            4,
            src_port,
            listen_port,
        )?;
        eth_rewrite(ctx, ct.client_mac)?;
        acct_flow(
            unsafe { &(*scratch).ct_key },
            0,
            packet_len,
            ct.server_id,
            now_mono_ns,
        );
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
        k._pad = [0; 4];
    }
    if snat_rev_lookup(scratch)
        && unsafe {
            let rv = &(*scratch).snat_rev_value;
            rv.backend_port_be == src_port && rv.backend_addr == (*scratch).pkt_src
        }
    {
        if !verified_hit(now_mono_ns) {
            return Ok(Some(xdp_action::XDP_DROP));
        }
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
        tcp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            4,
            src_port,
            listen_port,
        )?;
        unsafe {
            words16_into(&(*scratch).pkt_dst, &mut (*scratch).csum_old);
            words16_into(
                &(*scratch).snat_rev_value.client_addr,
                &mut (*scratch).csum_new,
            );
        }
        let ip_hdr = ptr_at_mut::<Ipv6Hdr>(ctx, ip_offset)?;
        unsafe {
            copy16(
                &mut (*ip_hdr).dst_addr,
                &(*scratch).snat_rev_value.client_addr,
            )
        };
        let tcp_hdr = ptr_at_mut::<TcpHdr>(ctx, l4_offset)?;
        unsafe { (*tcp_hdr).dest = client_port.to_ne_bytes() };
        tcp_csum_update(
            ctx,
            l4_offset,
            unsafe { &mut (*scratch).csum_old },
            unsafe { &mut (*scratch).csum_new },
            4,
            dst_port,
            client_port,
        )?;
        eth_rewrite(ctx, client_mac)?;
        if let Some(ct) = XDP_TCP_CT
            .get_ptr_mut(unsafe { &(*scratch).ct_key })
            .or_else(|| XDP_PENDING.get_ptr_mut(unsafe { &(*scratch).ct_key }))
        {
            // SAFETY: pointer into the map value for `ct_key`.
            let ct = unsafe { &mut *ct };
            if ct.state == XDP_CT_STATE_PENDING || ct.state == XDP_CT_STATE_PENDING_ACKED {
                if syn && ack && ackno == ct.expect_seq {
                    ct.state = XDP_CT_STATE_PENDING_ACKED;
                    ct.expect_ack = seq.wrapping_add(1);
                }
            } else {
                if !verified_hit(now_mono_ns) {
                    return Ok(Some(xdp_action::XDP_DROP));
                }
                ct.last_seen_ns = now_mono_ns;
                if closing && ct.state == XDP_CT_STATE_OPEN {
                    ct.state = XDP_CT_STATE_CLOSING;
                    emit_flow_event(ct, XDP_FLOW_EVENT_CLOSED, XDP_DECISION_PASS, now_mono_ns);
                }
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
    let (ip_offset, l4_offset) = bound_work_offsets(ip_offset, l4_offset);
    let tcp = ptr_at::<TcpHdr>(ctx, l4_offset)?;
    let src_port = unsafe { u16::from_ne_bytes((*tcp).source) };
    let dst_port = unsafe { u16::from_ne_bytes((*tcp).dest) };
    let syn = unsafe { (*tcp).syn() } == 1;
    let ack = unsafe { (*tcp).ack() } == 1;
    let closing = unsafe { (*tcp).fin() } == 1 || unsafe { (*tcp).rst() } == 1;
    let seq = unsafe { u32::from_be_bytes((*tcp).seq) };
    let ackno = unsafe { u32::from_be_bytes((*tcp).ack_seq) };
    let scratch = nat_scratch()?;
    // Snapshot test-only fault flags once per packet — inner checks read
    // this scratch field instead of paying a map lookup per call site.
    unsafe { (*scratch).debug_flags = pending_cap_flags() };
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
            if !verified_hit(now_mono_ns) {
                return Ok(Some(xdp_action::XDP_DROP));
            }
            // EN-11: flow tuple already bound to a different listen (VIP)
            // tuple — reject rather than rebinding reply ownership.
            if ct.listen_addr != unsafe { (*scratch).pkt_dst } || ct.listen_port_be != dst_port {
                counter_nat_conflict();
                emit_flow_event(
                    ct,
                    XDP_FLOW_EVENT_REJECTED,
                    XDP_DECISION_NAT_CONFLICT,
                    now_mono_ns,
                );
                return Ok(None);
            }
            ct.last_seen_ns = now_mono_ns;
            if closing && ct.state == XDP_CT_STATE_OPEN {
                ct.state = XDP_CT_STATE_CLOSING;
                emit_flow_event(ct, XDP_FLOW_EVENT_CLOSED, XDP_DECISION_PASS, now_mono_ns);
            }
            snat_port = ct.snat_port_be;
        }
        None => {
            let r = pending_touch(
                scratch,
                now_mono_ns,
                ack && !syn,
                dst_port,
                seq as u64 | (ackno as u64) << 32,
            );
            let pend = r as u8;
            let incarnation = (r >> 8) as u32;
            let pending_port = (r >> 40) as u16;
            if pend == PENDING_CONFLICT {
                counter_nat_conflict();
                return Ok(None);
            }
            if pend == PENDING_ALIVE {
                snat_port = pending_port;
            } else {
                if !(syn && !ack) {
                    return Ok(None);
                }
                // Fresh SYN creating new conntrack state: charge the new-flow
                // budget before snat_alloc / pending insert.
                if !budget_charge(1, now_mono_ns) {
                    counter_admission_limited();
                    return Ok(Some(xdp_action::XDP_DROP));
                }
                // Per-service fairness (dim6) — same contract as UDP.
                if !svc_budget_charge(dst_port, now_mono_ns) {
                    counter_service_limited();
                    return Ok(Some(xdp_action::XDP_DROP));
                }
                let eth = ptr_at::<EthHdr>(ctx, 0)?;
                let client_mac = unsafe { (*eth).src_addr };
                unsafe {
                    let v = &mut (*scratch).ct_value;
                    copy16(&mut v.listen_addr, &(*scratch).pkt_dst);
                    v.client_mac = client_mac;
                    v.listen_port_be = dst_port;
                    v.family = 6;
                    v.state = XDP_CT_STATE_PENDING;
                    v.expect_seq = seq.wrapping_add(1);
                    v.expect_ack = 0;
                    v.snat_port_be = 0;
                    v.server_id = rule.server_id;
                    v.last_seen_ns = now_mono_ns;
                    v.incarnation = incarnation;
                }
                if rule.snat != 0 {
                    unsafe {
                        let k = &mut (*scratch).snat_rev_key;
                        copy16(&mut k.listen_addr, &(*scratch).pkt_dst);
                        k.snat_port_be = 0;
                        k.proto = 6;
                        k.family = 6;
                        k._pad = [0; 4];
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
                // Test hook: FAIL_PENDING_INSERT forces the bounded-table
                // failure path (rollback + counter + explicit fallback).
                let pending_insert_ok =
                    unsafe { (*scratch).debug_flags } & XDP_PENDING_CAP_FAIL_PENDING_INSERT == 0
                        && XDP_PENDING
                            .insert(
                                unsafe { &(*scratch).ct_key },
                                unsafe { &(*scratch).ct_value },
                                0,
                            )
                            .is_ok();
                if !pending_insert_ok {
                    // EN-11 rollback: release the claimed SNAT port so a
                    // rejected admission leaves no binding behind.
                    if snat_port != 0 {
                        snat_release(scratch);
                    }
                    counter_pending_limited();
                    emit_flow_event(
                        unsafe { &(*scratch).ct_value },
                        XDP_FLOW_EVENT_REJECTED,
                        XDP_DECISION_FLOW_TABLE_FULL,
                        now_mono_ns,
                    );
                    return Ok(None);
                }
                emit_flow_event(
                    unsafe { &(*scratch).ct_value },
                    XDP_FLOW_EVENT_ADMITTED,
                    XDP_DECISION_PASS,
                    now_mono_ns,
                );
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

fn counter_service_limited() {
    if let Some(counters) = counters() {
        counters.service_limited = counters.service_limited.saturating_add(1);
    }
}

fn counter_svc_budget_full() {
    if let Some(counters) = counters() {
        counters.svc_budget_full = counters.svc_budget_full.saturating_add(1);
    }
}

/// EN-07 per-service fairness: charge one new-flow admission against the
/// listen port's per-CPU bucket (XDP_SVC_BUDGET keyed by dst port). A
/// distributed flood on one service exhausts only its own share of the
/// new-flow envelope; the aggregate dim1 cap still bounds the node on top.
/// A full service map degrades to the aggregate envelope — bounded and
/// counted, never a silent bypass of dim1.
#[inline(never)]
fn svc_budget_charge(dst_port: u16, now_mono_ns: u64) -> bool {
    let Some(cfg) = XDP_BUDGET_CFG.get(0) else {
        return true;
    };
    if cfg.flags & 0x40 == 0 || cfg.service_flow_pps == 0 || cfg.window_ns == 0 {
        return true;
    }
    let key = u32::from(dst_port);
    match XDP_SVC_BUDGET.get_ptr_mut(&key) {
        Some(bucket) => {
            let b = unsafe { &mut *bucket };
            if now_mono_ns.saturating_sub(b.window_start_ns) >= cfg.window_ns {
                b.window_start_ns = now_mono_ns;
                b.count = 0;
            }
            b.count = b.count.saturating_add(1);
            b.count <= cfg.service_flow_pps
        }
        None => {
            let bucket = XdpSvcBucket {
                window_start_ns: now_mono_ns,
                count: 1,
            };
            if XDP_SVC_BUDGET.insert(&key, &bucket, 0).is_err() {
                counter_svc_budget_full();
            }
            true
        }
    }
}

/// EN-07 aggregate budget gate: charge one unit of dimension `dim`
/// (0=unverified-packet, 1=new-flow admission) against the per-CPU bucket.
/// Returns true while within budget; false = exhausted, caller must drop.
/// A zero rate/window or cleared flag disables that dimension — userspace
/// writes an explicit flag, never relying on "divide to zero" semantics.
/// `dim` is a call-site constant folded after inlining.
#[inline(always)]
fn budget_charge(dim: usize, now_mono_ns: u64) -> bool {
    let Some(cfg) = XDP_BUDGET_CFG.get(0) else {
        return true;
    };
    let (limit, enabled) = match dim {
        0 => (cfg.unverified_pps, cfg.flags & 1 != 0),
        1 => (cfg.new_flow_per_sec, cfg.flags & 2 != 0),
        2 => (cfg.xsk_redirect_pps, cfg.flags & 4 != 0),
        3 => (cfg.challenge_pps, cfg.flags & 8 != 0),
        4 => (cfg.verified_pps, cfg.flags & 0x10 != 0),
        5 => (cfg.control_pps, cfg.flags & 0x20 != 0),
        _ => return true,
    };
    if !enabled || limit == 0 || cfg.window_ns == 0 {
        return true;
    }
    let Some(bucket) = XDP_BUDGET.get_ptr_mut(0) else {
        return true;
    };
    let b = unsafe { &mut *bucket };
    if now_mono_ns.saturating_sub(b.window_start_ns[dim]) >= cfg.window_ns {
        b.window_start_ns[dim] = now_mono_ns;
        b.count[dim] = 0;
    }
    b.count[dim] = b.count[dim].saturating_add(1);
    b.count[dim] <= limit
}

/// Return one unit of `dim`'s current-window count (saturating). Used when
/// a packet charged to the unverified pool at entry turns out to hold
/// verified conntrack state — the unverified ceiling then reflects only
/// not-yet-verified traffic. A rolled window needs no refund: the charge
/// already amortized with it.
#[inline(always)]
fn budget_refund(dim: usize, now_mono_ns: u64) {
    let Some(cfg) = XDP_BUDGET_CFG.get(0) else {
        return;
    };
    if cfg.flags & 1 == 0 || cfg.unverified_pps == 0 || cfg.window_ns == 0 {
        return;
    }
    let Some(bucket) = XDP_BUDGET.get_ptr_mut(0) else {
        return;
    };
    let b = unsafe { &mut *bucket };
    if now_mono_ns.saturating_sub(b.window_start_ns[dim]) < cfg.window_ns {
        b.count[dim] = b.count[dim].saturating_sub(1);
    }
}

/// EN-07 verified-state hit accounting: the packet proved membership in
/// live conntrack/SNAT state, so refund the entry-time unverified charge
/// and bill the verified pool instead. Established flows therefore keep a
/// reserved share an unverified flood cannot drain. Returns false when the
/// verified pool itself is exhausted — the caller must drop explicitly.
#[inline(never)]
fn verified_hit(now_mono_ns: u64) -> bool {
    budget_refund(0, now_mono_ns);
    if budget_charge(4, now_mono_ns) {
        true
    } else {
        counter_verified_limited();
        false
    }
}

const XDP_PENDING_TTL_DEFAULT_NS: u64 = 3_000_000_000;
const PENDING_MISS: u8 = 0;
const PENDING_ALIVE: u8 = 1;
/// EN-11: live pending entry owns this tuple for a different listen (VIP)
/// tuple — the caller rejects explicitly (multi-VIP same-backend ambiguity).
const PENDING_CONFLICT: u8 = 2;
/// EN-14: tuple is a post-cookie splice in flight (backend handshake not
/// anchored yet). The caller must consume the packet — forwarding it to a
/// SYN-RECV backend would race the replayed handshake.
const PENDING_SPLICING: u8 = 3;

#[inline(always)]
fn pending_cap_flags() -> u64 {
    XDP_PENDING_CAP.get(0).map(|cap| cap.flags).unwrap_or(0)
}

fn pending_ttl_ns() -> u64 {
    match XDP_PENDING_CAP.get(0) {
        Some(cap) if cap.pending_ttl_ns != 0 => cap.pending_ttl_ns,
        _ => XDP_PENDING_TTL_DEFAULT_NS,
    }
}

/// EN-10 lifecycle feedback: publish an event for the conntrack transition
/// the caller just performed on `ct` (key is `scratch.ct_key`). Advisory
/// only — when the ring is full the event is dropped and `flow_event_lost`
/// is incremented; flow state itself is never gated on the consumer.
#[inline(never)]
fn emit_flow_event(ct: &XdpUdpCtValue, kind: u8, reason: u8, now_ns: u64) {
    let Ok(scratch) = nat_scratch() else {
        return;
    };
    let key = unsafe { &(*scratch).ct_key };
    let seq = match XDP_FLOW_SEQ.get_ptr_mut(0) {
        Some(ptr) => {
            // SAFETY: per-CPU slot owned exclusively by this CPU.
            let s = unsafe { &mut *ptr };
            *s = s.wrapping_add(1);
            *s
        }
        None => 0,
    };
    let epoch = XDP_OWNER_EPOCH.get(0).copied().unwrap_or(0);
    let Some(mut entry) = XDP_FLOW_EVENTS.reserve::<XdpFlowEvent>(0) else {
        if let Some(counters) = XDP_COUNTERS.get_ptr_mut(0) {
            let counters = unsafe { &mut *counters };
            counters.flow_event_lost = counters.flow_event_lost.saturating_add(1);
        }
        return;
    };
    let ev: &mut XdpFlowEvent = unsafe { &mut *entry.as_mut_ptr() };
    unsafe {
        copy16(&mut ev.key.client_addr, &key.client_addr);
        copy16(&mut ev.key.service_addr, &ct.listen_addr);
    }
    ev.key.service_id = ct.server_id;
    ev.key.client_port_be = key.client_port_be;
    ev.key.service_port_be = ct.listen_port_be;
    ev.key.security_domain = unsafe { (*scratch).work_ifindex as u16 };
    ev.key.family = key.family;
    ev.key.proto = key.proto;
    ev.flow_incarnation = u64::from(ct.incarnation);
    ev.owner_epoch = epoch;
    ev.seq = seq;
    ev.timestamp_ns = now_ns;
    ev.kind = kind;
    ev.reason = reason;
    ev._pad = [0; 6];
    entry.submit(0);
}

/// EN-09 half-open lookup. Returns (PENDING_MISS, next_incarnation, 0) when
/// no live pending entry exists — a stale entry is removed first and its
/// incarnation+1 is returned so the caller can re-admit the tuple as a fresh
/// flow. Returns (PENDING_CONFLICT, 0, 0) when a live pending entry binds
/// this tuple to a different listen (VIP) tuple — EN-11 rejects the
/// ambiguity. Returns (PENDING_ALIVE, _, snat_port_be) when the tuple is
/// pending;
/// `promote` (client ACK&&!SYN on a PENDING_ACKED entry) moves the record
/// into the authoritative CT table. Pending hits never extend last_seen_ns.
#[inline(never)]
fn pending_touch(
    scratch: *mut NatScratch,
    now_mono_ns: u64,
    promote: bool,
    exp_port_be: u16,
    seq_ack: u64,
) -> u64 {
    // seq/ackno arrive packed — a sixth argument would spill through the
    // caller's frame (R11), which the verifier rejects.
    let seq = seq_ack as u32;
    let ackno = (seq_ack >> 32) as u32;
    // SAFETY: callers pass the per-CPU scratch map pointer; `ct_key` holds
    // the flow tuple and `pkt_dst` the expected listen address.
    let key = unsafe { &(*scratch).ct_key };
    let Some(p) = XDP_PENDING.get_ptr_mut(key) else {
        return pending_pack(PENDING_MISS, 1, 0);
    };
    // SAFETY: pointer into the map value for `key`.
    let p = unsafe { &mut *p };
    if now_mono_ns.saturating_sub(p.last_seen_ns) >= pending_ttl_ns() {
        let next = p.incarnation.wrapping_add(1);
        // EN-11: release the expired entry's SNAT port claim with it —
        // dropping pending state while the reverse binding stays would
        // leak the port until the sweeper's next orphan pass.
        if p.snat_port_be != 0 {
            let rk = XdpSnatRevKey {
                listen_addr: p.listen_addr,
                snat_port_be: p.snat_port_be,
                proto: 6,
                family: p.family,
                _pad: [0; 4],
            };
            let _ = XDP_SNAT_REV.remove(&rk);
        }
        emit_flow_event(p, XDP_FLOW_EVENT_EXPIRED, XDP_DECISION_PASS, now_mono_ns);
        let _ = XDP_PENDING.remove(key);
        return pending_pack(PENDING_MISS, next, 0);
    }
    // EN-11 multi-VIP disambiguation: the pending entry owns this flow
    // tuple for a different listen (VIP) tuple — reject rather than
    // silently rebinding replies to a VIP the client never dialed. The
    // expected listen address is the packet destination the caller
    // snapshotted into scratch.pkt_dst.
    if p.listen_addr != unsafe { (*scratch).pkt_dst } || p.listen_port_be != exp_port_be {
        emit_flow_event(
            p,
            XDP_FLOW_EVENT_REJECTED,
            XDP_DECISION_NAT_CONFLICT,
            now_mono_ns,
        );
        return pending_pack(PENDING_CONFLICT, 0, 0);
    }
    // EN-14: a post-cookie splice entry is not promotable by client ACKs —
    // promotion is driven by the consumed backend SYN-ACK on the reply
    // path. Client packets arriving while the splice is in flight are
    // consumed (PENDING_SPLICING): forwarding them would reach a backend
    // still in SYN-RECV with un-anchored sequence numbers.
    if p.splice_state != XDP_SPLICE_NONE {
        return pending_pack(PENDING_SPLICING, 0, p.snat_port_be);
    }
    let port = p.snat_port_be;
    // Handshake-evidence promotion: SNAT flows require the observed backend
    // SYN-ACK (PENDING_ACKED, set by the reply path). Plain-DNAT flows have
    // no observable SYN-ACK — replies addressed to the client are nonlocal
    // and transit the kernel — so the client's ACK is the only evidence.
    // EN-13/14: promotion requires the handshake ACK, not just any ACK —
    // the client's seq must equal client_isn+1 anchored at admission, and
    // SNAT flows additionally require the reply path to have observed a
    // real SYN-ACK (PENDING_ACKED) plus the ACK acknowledging the backend
    // ISN+1. An ACK failing the anchors is a weak observation: it keeps
    // the entry half-open, cannot extend its absolute deadline, and is
    // counted so blind-ACK floods stay observable.
    let seq_ok = seq == p.expect_seq;
    let can_promote = if p.snat_port_be == 0 {
        // Plain-DNAT flows have no observable SYN-ACK — replies addressed
        // to the client are nonlocal and transit the kernel — so the
        // client's anchored ACK is the only promotion evidence.
        seq_ok
    } else {
        p.state == XDP_CT_STATE_PENDING_ACKED && seq_ok && ackno == p.expect_ack
    };
    if promote && !can_promote {
        counter_nat_seq_rejected();
    }
    if promote && can_promote {
        // Insert the pending record verbatim and only then flip the CT copy
        // to OPEN: the pending record — state AND the absolute admission
        // deadline — must stay untouched until the authoritative insert
        // succeeds, otherwise a full CT table would wedge the entry into a
        // state that can never retry promotion while retransmitted ACKs keep
        // its deadline alive.
        // Test hook: FAIL_CT_INSERT forces the full-table path so rollback
        // semantics are exercised without filling 262k entries.
        let ct_insert_ok = unsafe { (*scratch).debug_flags } & XDP_PENDING_CAP_FAIL_CT_INSERT == 0
            && XDP_TCP_CT.insert(key, unsafe { &*p }, 0).is_ok();
        if ct_insert_ok {
            if let Some(ct) = XDP_TCP_CT.get_ptr_mut(key) {
                let ct = unsafe { &mut *ct };
                ct.state = XDP_CT_STATE_OPEN;
                ct.last_seen_ns = now_mono_ns;
                emit_flow_event(ct, XDP_FLOW_EVENT_VALIDATED, XDP_DECISION_PASS, now_mono_ns);
            }
            let _ = XDP_PENDING.remove(key);
        } else {
            // Authoritative table full: counted; the pending record keeps
            // its original state and absolute deadline, so the ACK neither
            // extends half-open lifetime nor marks the flow promoted.
            counter_tcp_fwd_map_full();
            emit_flow_event(
                p,
                XDP_FLOW_EVENT_REJECTED,
                XDP_DECISION_FLOW_TABLE_FULL,
                now_mono_ns,
            );
        }
    }
    pending_pack(PENDING_ALIVE, 0, port)
}

/// EN-11: pending_touch's tuple is packed into a scalar so no sret slot is
/// passed through the call frame — a pointer into the caller stack tripped
/// the verifier on older kernels (R11-invalid store). Layout:
/// [state:8][incarnation:32][snat_port_be:16].
#[inline(always)]
fn pending_pack(state: u8, incarnation: u32, port: u16) -> u64 {
    state as u64 | (incarnation as u64) << 8 | (port as u64) << 40
}

// ---------------------------------------------------------------------------
// EN-14 (ADR-001): TCP cookie challenge + sequence splice for SNAT forwards.
// A challenged rule never creates state for an unverified SYN: the node
// answers a SYN-ACK whose ISN is a keyed cookie, and only the client's
// proving ACK (ack == cookie+1) allocates pending/SNAT resources, replays
// the SYN to the backend, and anchors the seq delta once the backend's
// SYN-ACK arrives. All forgery rewrites the ingress frame in place and
// retransmits it with XDP_TX — every builder bounds-checks before writing.
// ---------------------------------------------------------------------------

/// Kernel-compatible MSS index table: the 3 low cookie bits carry the
/// negotiated MSS so the SYN replay can re-offer it without state.
const MSS_TAB: [u16; 8] = [536, 1300, 1440, 1460, 4310, 8960, 9000, 65535];

#[inline(always)]
fn sipround(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// SipHash-2-4 over exactly 16 bytes of input — the standard keyed hash
/// (not a novel construction), chosen for ~64 straight-line instructions.
#[inline(never)]
fn siphash24_16(k: &[u8; 16], w0: u64, w1: u64) -> u64 {
    let k0 = u64::from_le_bytes([
        k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7],
    ]);
    let k1 = u64::from_le_bytes([
        k[8], k[9], k[10], k[11], k[12], k[13], k[14], k[15],
    ]);
    let mut v = [
        k0 ^ 0x736f6d6570736575,
        k1 ^ 0x646f72616e646f6d,
        k0 ^ 0x6c7967656e657261,
        k1 ^ 0x7465646279746573,
    ];
    v[3] ^= w0;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= w0;
    v[3] ^= w1;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= w1;
    // Final block: input length (16) in the top byte, no trailing bytes.
    let b = 16u64 << 56;
    v[3] ^= b;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= b;
    v[2] ^= 0xff;
    sipround(&mut v);
    sipround(&mut v);
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// Cookie time slot (~4 s granularity); validation accepts the current
/// and previous slot under both key-ring entries.
#[inline(always)]
fn cookie_slot(now_mono_ns: u64) -> u32 {
    // ~4.3s slots (2^32 ns). Validation accepts the current and previous
    // slot (~8.6s window): comfortably covers real RTTs plus retransmit
    // cycles, still bounded so a captured cookie cannot be replayed
    // indefinitely. A retransmitted SYN that lands in a new slot gets a
    // fresh (different) cookie — correct SYN-cookie semantics.
    (now_mono_ns >> 32) as u32
}

/// Cookie tuple packed for the 5-register calling convention:
/// [client_be:32][client_port_be:16][listen_port_be:16].
#[inline(always)]
fn cookie_pack(client_be: u32, client_port_be: u16, listen_port_be: u16) -> u64 {
    (client_be as u64) << 32
        | (client_port_be as u64) << 16
        | listen_port_be as u64
}

/// SipHash over the packed tuple + listen addr + time slot. A tuple
/// return would spill through the caller frame (R11) — keep it scalar.
#[inline(never)]
fn cookie_hash(key: &[u8; 16], tuple: u64, listen_be: u32, slot: u32) -> u64 {
    let w0 = tuple;
    let w1 = (listen_be as u64) << 32 | slot as u64;
    siphash24_16(key, w0, w1)
}

/// Sign a challenge ISN: SipHash(tuple, slot) with the MSS index in the
/// low 3 bits. Returns None when no key is installed (fail-closed).
#[inline(never)]
fn cookie_make_v4(
    tuple: u64,
    listen_be: u32,
    mss_idx: u8,
    now_mono_ns: u64,
) -> Option<u32> {
    let key = XDP_COOKIE_KEY.get(0)?;
    if key.cur == [0u8; 16] {
        return None;
    }
    let h = cookie_hash(&key.cur, tuple, listen_be, cookie_slot(now_mono_ns)) as u32;
    Some((h & !7u32) | u32::from(mss_idx & 7))
}

/// Validate a challenge response: `cookie` is the client's ack number - 1.
/// Returns the embedded MSS index on success under cur or prev key and the
/// current or previous slot — four masked comparisons, all straight-line.
#[inline(never)]
fn cookie_check_v4(
    tuple: u64,
    listen_be: u32,
    cookie: u32,
    now_mono_ns: u64,
) -> Option<u8> {
    let key = XDP_COOKIE_KEY.get(0)?;
    let slot = cookie_slot(now_mono_ns);
    let masked = cookie & !7u32;
    // A zeroed key is "absent", never a valid key: an all-zero cur must not
    // participate in validation — an attacker could compute its SipHash
    // outputs offline and forge admission proofs. With no usable key every
    // comparison is disabled and the check fails closed.
    let cur_ok = key.cur != [0u8; 16];
    let prev_ok = key.prev != [0u8; 16];
    if (cur_ok && (cookie_hash(&key.cur, tuple, listen_be, slot) as u32) & !7 == masked)
        || (prev_ok
            && (cookie_hash(&key.prev, tuple, listen_be, slot) as u32) & !7 == masked)
    {
        return Some((cookie & 7) as u8);
    }
    let prev_slot = slot.wrapping_sub(1);
    if (cur_ok && (cookie_hash(&key.cur, tuple, listen_be, prev_slot) as u32) & !7 == masked)
        || (prev_ok
            && (cookie_hash(&key.prev, tuple, listen_be, prev_slot) as u32) & !7 == masked)
    {
        return Some((cookie & 7) as u8);
    }
    None
}

/// Read bytes out of the packet through bpf_xdp_load_bytes — variable
/// offsets never become packet pointers, so LLVM's 32-bit compare folding
/// (`ptr <<= 32`, rejected by the verifier) cannot appear. Direct reads
/// via `ptr_at` are still used for fixed-offset header fields.
#[inline(always)]
fn pkt_u16be(ctx: &XdpContext, off: usize) -> Result<u16, ()> {
    let mut b = [0u8; 2];
    let rc = unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            off as u32,
            b.as_mut_ptr() as *mut _,
            2,
        )
    };
    if rc != 0 {
        return Err(());
    }
    Ok(u16::from_be_bytes(b))
}

#[inline(always)]
fn pkt_u8(ctx: &XdpContext, off: usize) -> Result<u8, ()> {
    let mut b = [0u8; 1];
    let rc = unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            off as u32,
            b.as_mut_ptr() as *mut _,
            1,
        )
    };
    if rc != 0 {
        return Err(());
    }
    Ok(b[0])
}

#[inline(always)]
fn pkt_load(ctx: &XdpContext, off: usize, buf: &mut [u8]) -> Result<(), ()> {
    let rc = unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            off as u32,
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
        )
    };
    if rc != 0 {
        return Err(());
    }
    Ok(())
}

#[inline(always)]
fn pkt_store(ctx: &XdpContext, off: usize, buf: &[u8]) -> Result<(), ()> {
    pkt_store_n(ctx, off, buf, buf.len())
}

#[inline(always)]
fn pkt_store_n(ctx: &XdpContext, off: usize, buf: &[u8], len: usize) -> Result<(), ()> {
    let rc = unsafe {
        bpf_xdp_store_bytes(
            ctx.ctx,
            off as u32,
            buf.as_ptr() as *mut _,
            len as u32,
        )
    };
    if rc != 0 {
        return Err(());
    }
    Ok(())
}

/// Conservative fallback for an absent or malformed MSS option — the
/// smallest table entry (536, the IPv4 minimum-MTU default). A parse
/// failure must never forge a value larger than what the client may
/// have advertised: the previous 1460 default could exceed it.
const MSS_IDX_FALLBACK: u8 = 0;

/// Parse the client MSS option out of a SYN and map it to a table index.
/// Straight-line probe of the first three option slots (MSS, NOP+MSS,
/// NOP+NOP+MSS covers every mainstream TCP stack); a deeper, absent, or
/// malformed MSS falls back to MSS_IDX_FALLBACK — a conservative default,
/// never a parse failure and never an expansion of the advertised value.
/// A bounded loop would need either per-byte helper calls (jump-sequence
/// budget) or variable-offset stack reads (rejected by strict kernels).
#[inline(never)]
fn tcp_syn_mss_idx(ctx: &XdpContext, l4_offset: usize) -> u8 {
    let doff = match pkt_u8(ctx, l4_offset + 12) {
        Ok(b) => (b >> 4) as usize,
        Err(()) => return MSS_IDX_FALLBACK,
    };
    if doff <= 5 {
        return MSS_IDX_FALLBACK;
    }
    // Probe option slots at fixed offsets 0/1/2 past the header, skipping
    // leading NOPs (kind 1). kind==2 && len==4 is an MSS option.
    let mut i = 0usize;
    let mut probes = 0u8;
    loop {
        let kind = match pkt_u8(ctx, l4_offset + 20 + i) {
            Ok(k) => k,
            Err(()) => return MSS_IDX_FALLBACK,
        };
        if kind == 1 && probes < 2 {
            i += 1;
            probes += 1;
            continue;
        }
        if kind != 2 {
            return MSS_IDX_FALLBACK;
        }
        if doff * 4 < 20 + i + 4 {
            return MSS_IDX_FALLBACK;
        }
        let len = match pkt_u8(ctx, l4_offset + 20 + i + 1) {
            Ok(l) => l,
            Err(()) => return MSS_IDX_FALLBACK,
        };
        if len != 4 {
            return MSS_IDX_FALLBACK;
        }
        return match pkt_u16be(ctx, l4_offset + 20 + i + 2) {
            Ok(mss) => mss_to_idx(mss),
            Err(()) => MSS_IDX_FALLBACK,
        };
    }
}

/// Bounds-check-free table read: indexing would emit a panic_bounds_check
/// call into .text.unlikely, and a program image ending in that call fails
/// verification ("last insn is not an exit or jmp").
#[inline(always)]
fn mss_tab(idx: u8) -> u16 {
    MSS_TAB.get((idx & 7) as usize).copied().unwrap_or(1460)
}

#[inline(always)]
fn mss_to_idx(mss: u16) -> u8 {
    // Largest table entry <= offered MSS (kernel msstab semantics).
    let mut idx = 0u8;
    let mut i = 0usize;
    while let Some(&v) = MSS_TAB.get(i) {
        if v <= mss {
            idx = i as u8;
        }
        i += 1;
    }
    idx
}

/// Full TCP checksum of a segment being forged in a caller stack buffer
/// (check field already zeroed): pseudo-header + segment, two chained
/// bpf_csum_diff calls over stack memory only — no packet pointers, so
/// no variable-offset range proofs are needed anywhere in the forge path.
#[inline(always)]
fn tcp_pseudo_csum(src_ne: u32, dst_ne: u32, seg: &mut [u8; 24], tcp_len: usize) -> u64 {
    // Pseudo-header words carry the wire byte order — the addr args are
    // already the verbatim u32s of the wire [u8;4] fields.
    let len_be = (tcp_len as u32).to_be_bytes();
    let mut pseudo = [
        src_ne,
        dst_ne,
        u32::from_ne_bytes([0, 6, len_be[2], len_be[3]]),
    ];
    // csum_diff(NULL,0,buf,len,seed) = csum(buf) + seed.
    let s1 = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            seg.as_mut_ptr() as *mut u32,
            tcp_len as u32,
            0,
        )
    };
    unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            pseudo.as_mut_ptr(),
            12,
            s1 as u32,
        ) as u64
    }
}

/// Forge a challenge SYN-ACK in place of the incoming client SYN:
/// swap L2/L3 endpoints, cookie ISN, anchored ack, minimal options
/// (MSS only — no TS/SACK/wscale/ECN, per ADR-001 normalization).
/// `have_opt` — the ingress frame exposes >=4 writable option bytes so the
/// MSS option fits without growing the packet.
#[inline(never)]
fn forge_challenge_synack_v4(
    ctx: &XdpContext,
    offsets: usize,
    have_opt: bool,
) -> Result<(), ()> {
    let ip_offset = offsets & 0xffff;
    let l4_offset = (offsets >> 16) & 0x3fff;
    let s = nat_scratch()?;
    // Test-only fault injection: act as if the first write helper failed
    // so the worker error/rollback path is exercised on demand.
    if unsafe { (*s).debug_flags } & XDP_PENDING_CAP_FAIL_FORGE != 0 {
        return Err(());
    }
    let eth = ptr_at_mut::<EthHdr>(ctx, 0)?;
    unsafe {
        core::mem::swap(&mut (*eth).src_addr, &mut (*eth).dst_addr);
    }
    let f_mss = unsafe { (*s).forge_mss };
    let tcp_len: usize = if have_opt && f_mss != 0 { 24 } else { 20 };
    // All variable-offset header surgery runs through the load/store
    // helpers against scratch-map staging: on strict kernels the verifier
    // neither propagates a range back to a `data + var_off` pointer nor
    // affords the stack these buffers would cost in a nested call chain.
    let ipb = unsafe { &mut (*s).forge_ipb };
    pkt_load(ctx, ip_offset, ipb)?;
    let tmp = unsafe { &mut (*s).forge_tmp };
    tmp[0..4].copy_from_slice(&ipb[12..16]); // orig src
    tmp[4..8].copy_from_slice(&ipb[16..20]); // orig dst
    ipb[2..4].copy_from_slice(&(20u16 + tcp_len as u16).to_be_bytes());
    ipb[4] = 0;
    ipb[5] = 0;
    ipb[6..8].copy_from_slice(&u16::to_be_bytes(0x4000));
    ipb[8] = 64;
    ipb[10..12].copy_from_slice(&[0, 0]);
    ipb[12..16].copy_from_slice(&tmp[4..8]);
    ipb[16..20].copy_from_slice(&tmp[0..4]);
    let ip_check = csum_fold(unsafe {
        bpf_csum_diff(core::ptr::null_mut(), 0, ipb.as_mut_ptr() as *mut u32, 20, 0) as u64
    });
    ipb[10..12].copy_from_slice(&ip_check.to_ne_bytes()); // __sum16 is already wire order
    pkt_store(ctx, ip_offset, ipb)?;
    // Client ports into tb[0..4] then swapped in place: forged source =
    // original dest, and vice versa. tmp[0..8] keeps the orig addrs for
    // the pseudo-header checksum.
    let tb = unsafe { &mut (*s).forge_tb };
    pkt_load(ctx, l4_offset, &mut tb[0..4])?;
    let (p0, p1) = (tb[0], tb[1]);
    tb[0] = tb[2];
    tb[1] = tb[3];
    tb[2] = p0;
    tb[3] = p1;
    tb[4..8].copy_from_slice(&unsafe { (*s).forge_seq }.to_be_bytes());
    tb[8..12].copy_from_slice(&unsafe { (*s).forge_ack }.to_be_bytes());
    tb[12] = ((tcp_len / 4) as u8) << 4;
    tb[13] = 0x12; // SYN|ACK
    tb[14..16].copy_from_slice(&unsafe { (*s).forge_win }.to_be_bytes());
    // forge_tb is per-CPU scratch reused across packets: the checksum and
    // urgent-pointer bytes must be cleared before summing or a previous
    // frame's leftovers fold into this checksum.
    tb[16..20].copy_from_slice(&[0, 0, 0, 0]);
    if tcp_len == 24 {
        tb[20..24].copy_from_slice(&(0x0204_0000u32 | f_mss as u32).to_be_bytes());
    }
    // Forged src = original dst, forged dst = original src.
    let src_ne = u32::from_ne_bytes([tmp[4], tmp[5], tmp[6], tmp[7]]);
    let dst_ne = u32::from_ne_bytes([tmp[0], tmp[1], tmp[2], tmp[3]]);
    let tcp_check = csum_fold(tcp_pseudo_csum(src_ne, dst_ne, tb, tcp_len));
    tb[16..18].copy_from_slice(&tcp_check.to_ne_bytes()); // __sum16 is already wire order
    pkt_store_n(ctx, l4_offset, tb, tcp_len)?;
    let new_len = (14 + 20 + tcp_len) as i64;
    let delta = new_len - packet_len_of(ctx) as i64;
    if delta != 0 && unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta as i32) } != 0 {
        return Err(());
    }
    Ok(())
}

#[inline(always)]
fn packet_len_of(ctx: &XdpContext) -> usize {
    ctx.data_end() - ctx.data()
}

/// Forge a backend-directed TCP packet in place of the incoming frame
/// (SYN replay or handshake-completing ACK): dst MAC = rule next hop
/// (staged in scratch), src = listen VIP + claimed SNAT port.
#[inline(never)]
fn forge_to_backend_v4(
    ctx: &XdpContext,
    offsets: usize,
    have_opt: bool,
) -> Result<(), ()> {
    let ip_offset = offsets & 0xffff;
    let l4_offset = (offsets >> 16) & 0x3fff;
    let s = nat_scratch()?;
    // Test-only fault injection: forge fails before touching the frame so
    // callers' rollback paths are exercised without a helper fault.
    if unsafe { (*s).debug_flags } & XDP_PENDING_CAP_FAIL_FORGE != 0 {
        return Err(());
    }
    // Backend endpoint: replay SYN (client->VIP frame) or handshake ACK
    // (backend->VIP frame) — the backend address is always the CT tuple's
    // backend_addr; the forged source is the packet's destination (VIP).
    let eth = ptr_at_mut::<EthHdr>(ctx, 0)?;
    unsafe {
        (*eth).src_addr = (*eth).dst_addr;
        (*eth).dst_addr = (*s).forge_next_hop;
    }
    // Forge fields are read just-in-time from the scratch map value —
    // hoisting them into locals would make LLVM spill ~40B of registers
    // across the helper calls and push the call chain over 512B of stack.
    let f_mss = unsafe { (*s).forge_mss };
    let tcp_len: usize = if have_opt && f_mss != 0 { 24 } else { 20 };
    // Same scratch-staged, checksum-before-store surgery as
    // forge_challenge_synack_v4 — variable offsets never become packet
    // pointers and the frame stays small on strict kernels.
    let ipb = unsafe { &mut (*s).forge_ipb };
    pkt_load(ctx, ip_offset, ipb)?;
    let tmp = unsafe { &mut (*s).forge_tmp };
    tmp[0..4].copy_from_slice(&ipb[16..20]); // listen VIP (orig dst)
    tmp[4..8].copy_from_slice(&unsafe { (*s).ct_key.backend_addr }[0..4]);
    ipb[2..4].copy_from_slice(&(20u16 + tcp_len as u16).to_be_bytes());
    ipb[4] = 0;
    ipb[5] = 0;
    ipb[6..8].copy_from_slice(&u16::to_be_bytes(0x4000));
    ipb[8] = 64;
    ipb[10..12].copy_from_slice(&[0, 0]);
    ipb[12..16].copy_from_slice(&tmp[0..4]);
    ipb[16..20].copy_from_slice(&tmp[4..8]);
    let ip_check = csum_fold(unsafe {
        bpf_csum_diff(core::ptr::null_mut(), 0, ipb.as_mut_ptr() as *mut u32, 20, 0) as u64
    });
    ipb[10..12].copy_from_slice(&ip_check.to_ne_bytes()); // __sum16 is already wire order
    pkt_store(ctx, ip_offset, ipb)?;
    let tb = unsafe { &mut (*s).forge_tb };
    tb[0..2].copy_from_slice(&unsafe { (*s).forge_src_port }.to_ne_bytes());
    tb[2..4].copy_from_slice(&unsafe { (*s).ct_key.backend_port_be }.to_ne_bytes());
    tb[4..8].copy_from_slice(&unsafe { (*s).forge_seq }.to_be_bytes());
    tb[8..12].copy_from_slice(&unsafe { (*s).forge_ack }.to_be_bytes());
    tb[12] = ((tcp_len / 4) as u8) << 4;
    tb[13] = unsafe { (*s).forge_flags };
    tb[14..16].copy_from_slice(&unsafe { (*s).forge_win }.to_be_bytes());
    // Same scratch-reuse hazard as forge_challenge_synack_v4: clear the
    // checksum + urgent-pointer bytes before summing.
    tb[16..20].copy_from_slice(&[0, 0, 0, 0]);
    if tcp_len == 24 {
        tb[20..24].copy_from_slice(&(0x0204_0000u32 | f_mss as u32).to_be_bytes());
    }
    let src_ne = u32::from_ne_bytes([tmp[0], tmp[1], tmp[2], tmp[3]]);
    let dst_ne = u32::from_ne_bytes([tmp[4], tmp[5], tmp[6], tmp[7]]);
    let tcp_check = csum_fold(tcp_pseudo_csum(src_ne, dst_ne, tb, tcp_len));
    tb[16..18].copy_from_slice(&tcp_check.to_ne_bytes()); // __sum16 is already wire order
    pkt_store_n(ctx, l4_offset, tb, tcp_len)?;
    let new_len = (14 + 20 + tcp_len) as i64;
    let delta = new_len - packet_len_of(ctx) as i64;
    if delta != 0 && unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta as i32) } != 0 {
        return Err(());
    }
    Ok(())
}

/// Incrementally patch one 32-bit TCP field (seq or ack_seq) and its
/// checksum — used for the post-splice sequence translation. `new_val`
/// is the host-order value; the wire gets its big-endian bytes.
#[inline(always)]
fn tcp_patch_u32(
    ctx: &XdpContext,
    l4_offset: usize,
    field_off: usize,
    new_val: u32,
) -> Result<(), ()> {
    // Helper-only access: a `data + var_off` pointer through the field
    // writes below fails range propagation on strict kernels.
    let new_bytes = new_val.to_be_bytes();
    let mut old_b = [0u8; 4];
    pkt_load(ctx, l4_offset + field_off, &mut old_b)?;
    let mut old_v = u32::from_ne_bytes(old_b);
    let mut new_v = u32::from_ne_bytes(new_bytes);
    let diff = csum_diff_u32(&mut old_v, &mut new_v);
    pkt_store(ctx, l4_offset + field_off, &new_bytes)?;
    let mut cb = [0u8; 2];
    pkt_load(ctx, l4_offset + 16, &mut cb)?;
    let old_check = u16::from_ne_bytes(cb);
    pkt_store(ctx, l4_offset + 16, &csum_apply_diff(old_check, diff).to_ne_bytes())?;
    Ok(())
}

fn counter_challenge_sent() {
    if let Some(counters) = counters() {
        counters.challenge_sent = counters.challenge_sent.saturating_add(1);
    }
}

fn counter_challenge_rejected() {
    if let Some(counters) = counters() {
        counters.challenge_rejected = counters.challenge_rejected.saturating_add(1);
    }
}

fn counter_challenge_worker_err() {
    if let Some(counters) = counters() {
        counters.challenge_worker_err =
            counters.challenge_worker_err.saturating_add(1);
    }
}

/// EN-14 (ADR-001): challenged-rule entry point for packets without
/// conntrack/pending state. The SYN gets a stateless cookie challenge; the
/// proving ACK performs the real admission (dim1+dim6, SNAT claim, pending
/// SPLICING record) and emits the SYN replay to the backend. Everything is
/// staged through `scratch` so the signature stays within 5 registers.
/// Runs in the dedicated slot-11 worker program: rule fields the callee
/// needs (server_id, next_hop_mac) are staged into scratch by the caller
/// because map pointers cannot cross the tail-call boundary.
#[inline(never)]
fn tcp_challenge_v4(
    ctx: &XdpContext,
    scratch: *mut NatScratch,
    ip_offset: usize,
    l4_offset: usize,
) -> Result<Option<u32>, ()> {
    let (ip_offset, l4_offset) = bound_work_offsets(ip_offset, l4_offset);
    let now_mono_ns = unsafe { bpf_ktime_get_ns() };
    let tcp = ptr_at::<TcpHdr>(ctx, l4_offset)?;
    let ip = ptr_at::<Ipv4Hdr>(ctx, ip_offset)?;
    let (src_port, dst_port, seq, ackno) = unsafe {
        (
            u16::from_ne_bytes((*tcp).source),
            u16::from_ne_bytes((*tcp).dest),
            u32::from_be_bytes((*tcp).seq),
            u32::from_be_bytes((*tcp).ack_seq),
        )
    };
    let syn = unsafe { (*tcp).syn() } == 1;
    let ack = unsafe { (*tcp).ack() } == 1;
    let window = unsafe { u16::from_be_bytes([(*tcp).window[0], (*tcp).window[1]]) };
    let src_be = unsafe { u32::from_be_bytes((*ip).src_addr) };
    let dst_be = unsafe { u32::from_be_bytes((*ip).dst_addr) };
    // Writable option space: the MSS option needs 4 bytes inside the
    // current frame (adjust_tail can shrink but not expose new bytes).
    // Scalar-length compare: a `data + off <= data_end` pointer compare
    // gets folded into prohibited 32-bit pointer shifts by LLVM here.
    let have_opt = l4_offset + 24 <= ctx.data_end().saturating_sub(ctx.data());

    if syn && !ack {
        // Stateless challenge — dim3 budget first, no state on miss.
        if !budget_charge(3, now_mono_ns) {
            counter_challenge_rejected();
            return Ok(Some(xdp_action::XDP_DROP));
        }
        let mss_idx = tcp_syn_mss_idx(ctx, l4_offset);
        let tuple = cookie_pack(src_be, src_port.to_be(), dst_port);
        let Some(cookie) = cookie_make_v4(tuple, dst_be, mss_idx, now_mono_ns)
        else {
            // No key installed: fail closed, counted — never silently
            // forward an unverified SYN on a challenged rule.
            counter_challenge_rejected();
            return Ok(Some(xdp_action::XDP_DROP));
        };
        unsafe {
            (*scratch).forge_seq = cookie;
            (*scratch).forge_ack = seq.wrapping_add(1);
            (*scratch).forge_mss = mss_tab(mss_idx);
            (*scratch).forge_win = 64240;
        }
        forge_challenge_synack_v4(ctx, ip_offset | l4_offset << 16, have_opt)?;
        counter_challenge_sent();
        return Ok(Some(xdp_action::XDP_TX));
    }

    if ack && !syn && ackno != 0 {
        let cookie = ackno.wrapping_sub(1);
        let tuple = cookie_pack(src_be, src_port.to_be(), dst_port);
        let Some(mss_idx) = cookie_check_v4(tuple, dst_be, cookie, now_mono_ns)
        else {
            counter_challenge_rejected();
            return Ok(Some(xdp_action::XDP_DROP));
        };
        // Verified client: the admission budgets are paid HERE — the
        // challenge above created no state, so this is the real
        // new-flow commitment (dim1 aggregate + dim6 per-service).
        if !budget_charge(1, now_mono_ns) {
            counter_admission_limited();
            return Ok(Some(xdp_action::XDP_DROP));
        }
        if !svc_budget_charge(dst_port, now_mono_ns) {
            counter_service_limited();
            return Ok(Some(xdp_action::XDP_DROP));
        }
        let eth = ptr_at::<EthHdr>(ctx, 0)?;
        let client_mac = unsafe { (*eth).src_addr };
        let incarnation = unsafe { (*scratch).forge_incarnation };
        let mut snat_port = 0u16;
        unsafe {
            let v = &mut (*scratch).ct_value;
            v.listen_addr = v4_embed(dst_be);
            v.client_mac = client_mac;
            v.listen_port_be = dst_port;
            v.family = 4;
            v.state = XDP_CT_STATE_PENDING;
            v.expect_seq = seq; // client next seq = c_isn+1
            v.expect_ack = 0;
            v.splice_isn = cookie;
            v.seq_delta = 0;
            v.splice_state = XDP_SPLICE_WAIT;
            v._pad2 = [0; 3];
            v.snat_port_be = 0;
            v.server_id = (*scratch).forge_server_id;
            v.last_seen_ns = now_mono_ns;
            v.incarnation = incarnation;
            let k = &mut (*scratch).snat_rev_key;
            k.listen_addr = v4_embed(dst_be);
            k.snat_port_be = 0;
            k.proto = 6;
            k.family = 4;
            k._pad = [0; 4];
        }
        snat_prefill(scratch, client_mac, unsafe { (*scratch).forge_server_id });
        match snat_alloc(scratch, &XDP_TCP_FWD) {
            Some(port) => {
                snat_port = port;
                unsafe { (*scratch).ct_value.snat_port_be = port };
            }
            None => return Ok(None),
        }
        let pending_insert_ok =
            unsafe { (*scratch).debug_flags } & XDP_PENDING_CAP_FAIL_PENDING_INSERT == 0
                && XDP_PENDING
                    .insert(
                        unsafe { &(*scratch).ct_key },
                        unsafe { &(*scratch).ct_value },
                        0,
                    )
                    .is_ok();
        if !pending_insert_ok {
            if snat_port != 0 {
                snat_release(scratch);
            }
            counter_pending_limited();
            emit_flow_event(
                unsafe { &(*scratch).ct_value },
                XDP_FLOW_EVENT_REJECTED,
                XDP_DECISION_FLOW_TABLE_FULL,
                now_mono_ns,
            );
            return Ok(None);
        }
        emit_flow_event(
            unsafe { &(*scratch).ct_value },
            XDP_FLOW_EVENT_ADMITTED,
            XDP_DECISION_PASS,
            now_mono_ns,
        );
        // SYN replay to the backend (options normalized per ADR-001).
        unsafe {
            (*scratch).forge_seq = seq.wrapping_sub(1); // c_isn
            (*scratch).forge_ack = 0;
            (*scratch).forge_flags = 0x02; // SYN
            (*scratch).forge_win = window;
            (*scratch).forge_mss = mss_tab(mss_idx);
            (*scratch).forge_src_port = snat_port;
            // forge_next_hop was staged by the caller from the rule —
            // map pointers cannot cross the tail-call boundary.
        }
        if forge_to_backend_v4(ctx, ip_offset | l4_offset << 16, have_opt).is_err() {
            // Forge fault after admission: roll back every allocation so
            // no pending record or SNAT port leaks for a replay that was
            // never emitted. The worker maps Err to a counted DROP.
            let _ = XDP_PENDING.remove(unsafe { &(*scratch).ct_key });
            if snat_port != 0 {
                snat_release(scratch);
            }
            // Balance the ADMITTED event above so the feedback ledger
            // never carries a flow the dataplane dropped.
            emit_flow_event(
                unsafe { &(*scratch).ct_value },
                XDP_FLOW_EVENT_REJECTED,
                XDP_DECISION_INTERNAL_ERR,
                now_mono_ns,
            );
            return Err(());
        }
        counter_tcp_fwd_tx();
        return Ok(Some(xdp_action::XDP_TX));
    }

    // FIN/RST/other without state on a challenged rule: not our concern —
    // hand to the normal dataplane path unchanged.
    Ok(None)
}

/// EN-14: consume the backend SYN-ACK on a post-cookie splice — anchor the
/// sequence delta (s_isn - b_isn), promote the pending record into the
/// authoritative CT table as OPEN+SPLICED, and answer the backend's
/// handshake with a forged ACK. The consumed SYN-ACK is never forwarded:
/// the client already holds the challenge SYN-ACK's sequence space.
/// `scratch.forge_seq` carries the wire seq (b_isn) staged by the caller.
/// Runs in the slot-11 worker program: the pending/CT map pointer the
/// caller verified cannot cross the tail-call boundary, so the value is
/// re-looked-up here and the splice gate re-checked — a concurrent CPU
/// could have anchored or expired the record in between.
#[inline(never)]
fn tcp_splice_anchor_v4(
    ctx: &XdpContext,
    scratch: *mut NatScratch,
    offsets: usize,
) -> Result<Option<u32>, ()> {
    let now_mono_ns = unsafe { bpf_ktime_get_ns() };
    let b_isn = unsafe { (*scratch).forge_seq };
    let p = XDP_TCP_CT
        .get_ptr_mut(unsafe { &(*scratch).ct_key })
        .or_else(|| XDP_PENDING.get_ptr_mut(unsafe { &(*scratch).ct_key }));
    let Some(p) = p else {
        // The record vanished between the caller's check and this worker:
        // the consumed SYN-ACK cannot be answered, drop it — a backend
        // retransmit re-enters the anchor once state is consistent.
        counter_challenge_rejected();
        return Ok(Some(xdp_action::XDP_DROP));
    };
    // SAFETY: pointer into the map value for ct_key.
    let p = unsafe { &mut *p };
    if p.splice_state != XDP_SPLICE_WAIT {
        // Another CPU already anchored (or promoted) this flow — this
        // retransmitted SYN-ACK is a duplicate; dropping it is correct
        // because the client already holds the challenge sequence space.
        return Ok(Some(xdp_action::XDP_DROP));
    }
    let (splice_isn, expect_seq, snat_port) = (p.splice_isn, p.expect_seq, p.snat_port_be);
    // Forge the handshake-completing ACK to the backend BEFORE mutating
    // flow state: seq = c_isn+1 (the client seq space the replay
    // established), ack = b_isn+1. If the forge fails the packet is
    // dropped un-emitted with pending state untouched — the backend
    // retransmits the SYN-ACK and the anchor retries cleanly. Promoting
    // first would commit the splice while the ACK was never sent; a
    // retransmit would then hit SPLICE_DONE and stall the flow.
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let backend_mac = unsafe { (*eth).src_addr };
    unsafe {
        (*scratch).forge_seq = expect_seq;
        (*scratch).forge_ack = b_isn.wrapping_add(1);
        (*scratch).forge_flags = 0x10; // ACK
        (*scratch).forge_win = 65535;
        (*scratch).forge_mss = 0;
        (*scratch).forge_src_port = snat_port;
        (*scratch).forge_next_hop = backend_mac;
    }
    forge_to_backend_v4(ctx, offsets, false)?;
    let ct_insert_ok =
        unsafe { (*scratch).debug_flags } & XDP_PENDING_CAP_FAIL_CT_INSERT == 0
            && XDP_TCP_CT
                .insert(unsafe { &(*scratch).ct_key }, &*p, 0)
                .is_ok();
    if !ct_insert_ok {
        // Authoritative table full: the pending record is untouched and
        // the forged ACK is dropped un-emitted — the backend retransmits
        // and the next arrival retries the anchor. Counted, never a
        // partial splice.
        counter_tcp_fwd_map_full();
        return Ok(Some(xdp_action::XDP_DROP));
    }
    if let Some(ct) = XDP_TCP_CT.get_ptr_mut(unsafe { &(*scratch).ct_key }) {
        let ct = unsafe { &mut *ct };
        ct.state = XDP_CT_STATE_OPEN;
        ct.splice_state = XDP_SPLICE_DONE;
        ct.seq_delta = splice_isn.wrapping_sub(b_isn) as i32;
        ct.expect_ack = b_isn.wrapping_add(1);
        ct.last_seen_ns = now_mono_ns;
        emit_flow_event(ct, XDP_FLOW_EVENT_VALIDATED, XDP_DECISION_PASS, now_mono_ns);
    }
    let _ = XDP_PENDING.remove(unsafe { &(*scratch).ct_key });
    Ok(Some(xdp_action::XDP_TX))
}

fn counter_unverified_limited() {
    if let Some(counters) = XDP_COUNTERS.get_ptr_mut(0) {
        let counters = unsafe { &mut *counters };
        counters.unverified_limited = counters.unverified_limited.saturating_add(1);
    }
}

fn counter_admission_limited() {
    if let Some(counters) = XDP_COUNTERS.get_ptr_mut(0) {
        let counters = unsafe { &mut *counters };
        counters.admission_limited = counters.admission_limited.saturating_add(1);
    }
}

fn counter_pending_limited() {
    if let Some(counters) = XDP_COUNTERS.get_ptr_mut(0) {
        let counters = unsafe { &mut *counters };
        counters.pending_limited = counters.pending_limited.saturating_add(1);
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

fn counter_verified_limited() {
    if let Some(counters) = XDP_COUNTERS.get_ptr_mut(0) {
        let counters = unsafe { &mut *counters };
        counters.verified_limited = counters.verified_limited.saturating_add(1);
    }
}

fn counter_control_limited() {
    if let Some(counters) = XDP_COUNTERS.get_ptr_mut(0) {
        let counters = unsafe { &mut *counters };
        counters.control_limited = counters.control_limited.saturating_add(1);
    }
}

fn counter_nat_seq_rejected() {
    if let Some(counters) = XDP_COUNTERS.get_ptr_mut(0) {
        let counters = unsafe { &mut *counters };
        counters.nat_seq_rejected = counters.nat_seq_rejected.saturating_add(1);
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
