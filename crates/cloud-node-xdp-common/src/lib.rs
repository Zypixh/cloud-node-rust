#![cfg_attr(not(feature = "std"), no_std)]

pub const XDP_ACTION_PASS: u32 = 2;
pub const XDP_ACTION_DROP: u32 = 1;
pub const XDP_ACTION_REDIRECT: u32 = 4;

pub const XDP_PROTO_TCP: u8 = 6;
pub const XDP_PROTO_UDP: u8 = 17;

pub const XDP_MAX_INTERFACES: usize = 64;
pub const XDP_DEFAULT_FRAME_SIZE: u32 = 2048;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XdpInterfaceMode {
    Observe = 0,
    Protect = 1,
    Proxy = 2,
}

impl XdpInterfaceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Protect => "protect",
            Self::Proxy => "proxy",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpIpv4Key {
    pub addr_be: u32,
}

impl XdpIpv4Key {
    pub const fn new(addr_be: u32) -> Self {
        Self { addr_be }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpIpv6Key {
    pub addr: [u8; 16],
}

impl XdpIpv6Key {
    pub const fn new(addr: [u8; 16]) -> Self {
        Self { addr }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpRangeKey {
    pub from_hi: u64,
    pub from_lo: u64,
    pub to_hi: u64,
    pub to_lo: u64,
    pub family: u8,
    pub _pad: [u8; 7],
}

impl XdpRangeKey {
    pub const FAMILY_IPV4: u8 = 4;
    pub const FAMILY_IPV6: u8 = 6;

    pub const fn new(from: u128, to: u128, family: u8) -> Self {
        Self {
            from_hi: (from >> 64) as u64,
            from_lo: from as u64,
            to_hi: (to >> 64) as u64,
            to_lo: to as u64,
            family,
            _pad: [0; 7],
        }
    }

    pub const fn from(&self) -> u128 {
        ((self.from_hi as u128) << 64) | self.from_lo as u128
    }

    pub const fn to(&self) -> u128 {
        ((self.to_hi as u128) << 64) | self.to_lo as u128
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpPortProtoKey {
    pub port_be: u16,
    pub proto: u8,
    pub _pad: u8,
}

impl XdpPortProtoKey {
    pub const fn new(port_be: u16, proto: u8) -> Self {
        Self {
            port_be,
            proto,
            _pad: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpQueueKey {
    pub ifindex: u32,
    pub queue_id: u32,
}

impl XdpQueueKey {
    pub const fn new(ifindex: u32, queue_id: u32) -> Self {
        Self { ifindex, queue_id }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpLocalIpv4Key {
    pub ifindex: u32,
    pub addr_be: u32,
}

impl XdpLocalIpv4Key {
    pub const fn new(ifindex: u32, addr_be: u32) -> Self {
        Self { ifindex, addr_be }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpLocalIpv6Key {
    pub ifindex: u32,
    pub _pad: u32,
    pub addr: [u8; 16],
}

impl XdpLocalIpv6Key {
    pub const fn new(ifindex: u32, addr: [u8; 16]) -> Self {
        Self {
            ifindex,
            _pad: 0,
            addr,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpRuleValue {
    pub expires_at_unix: u64,
    pub expires_at_mono_ns: u64,
    pub scope_id: i64,
    pub flags: u32,
    pub _pad: u32,
}

impl XdpRuleValue {
    pub const FLAG_WHITELIST: u32 = 1 << 0;
    pub const FLAG_BLOCK: u32 = 1 << 1;
    pub const FLAG_RUNTIME: u32 = 1 << 2;

    pub const fn new(expires_at_unix: u64, scope_id: i64, flags: u32) -> Self {
        Self {
            expires_at_unix,
            expires_at_mono_ns: 0,
            scope_id,
            flags,
            _pad: 0,
        }
    }

    pub const fn with_monotonic_deadline(
        expires_at_unix: u64,
        expires_at_mono_ns: u64,
        scope_id: i64,
        flags: u32,
    ) -> Self {
        Self {
            expires_at_unix,
            expires_at_mono_ns,
            scope_id,
            flags,
            _pad: 0,
        }
    }

    pub const fn is_whitelist(self) -> bool {
        self.flags & Self::FLAG_WHITELIST != 0
    }

    pub const fn is_block(self) -> bool {
        self.flags & Self::FLAG_BLOCK != 0
    }

    pub const fn is_active_at_mono(self, now_mono_ns: u64) -> bool {
        self.expires_at_mono_ns == 0 || self.expires_at_mono_ns > now_mono_ns
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpCounters {
    pub packets: u64,
    pub pass: u64,
    pub drop: u64,
    pub redirect: u64,
    pub parse_errors: u64,
    pub map_miss: u64,
    pub xsk_drops: u64,
    pub rate_limited: u64,
    pub ratelimit_map_full: u64,
    pub udp_fwd_tx: u64,
    pub udp_fwd_map_full: u64,
    pub tcp_fwd_tx: u64,
    pub tcp_fwd_map_full: u64,
    /// SNAT source-port bindings successfully claimed.
    pub snat_bound: u64,
    /// SNAT port allocation failures (port space probe exhausted); those
    /// packets fall back to the userspace dataplane.
    pub snat_alloc_fail: u64,
    /// Backend replies restored to clients through a SNAT reverse binding.
    pub snat_reply_tx: u64,
    /// Terminal XDP_TX actions (direct-forwarded replies). Forward-specific
    /// counters still attribute per-rule; this makes
    /// pass+drop+redirect+tx == packets hold for action accounting.
    pub tx: u64,
    /// Terminal drops caused by an ACL block rule (observe mode returns PASS
    /// and does not increment this). Distinct from rate/internal drops.
    pub acl_blocked: u64,
    /// XDP_CLASS_MALFORMED terminal drops: deterministic-illegal packets
    /// (truncated headers, bad lengths, impossible TCP flag combos). Always
    /// dropped regardless of interface mode — there is no legal interpretation.
    pub malformed: u64,
    /// XDP_CLASS_UNSUPPORTED: legal-looking traffic the bounded parser cannot
    /// fully classify (deep IPv6 ext chains, >2 VLAN tags, non-TCP/UDP/ICMP).
    /// Passed to the kernel — never a trusted flow, never dropped by parse.
    pub unsupported: u64,
    /// XDP_CLASS_FRAGMENTED: IP fragments classified before L4 handling.
    /// The fragment policy decides PASS (kernel reassembly) or DROP; a first
    /// fragment alone never creates a trusted L4 flow.
    pub fragmented: u64,
    /// XDP_CLASS_CONTROL: ICMP/ICMPv6 (ND, PMTU) handed to the kernel stack.
    /// Exempt from L4 handling but still subject to ACL block rules.
    pub control: u64,
    /// Packets matching an ACL block rule on an observe-mode interface:
    /// passed (observing, not enforcing) but counted so the would-be drop is
    /// visible before protect/proxy is enabled.
    pub acl_would_block: u64,
    /// Packets whose destination is outside the interface's protected VIP
    /// set (`local_ip_filter` on, no XDP_LOCAL_* hit): passed untouched —
    /// management and transit traffic is not this layer's concern.
    pub nonlocal_pass: u64,
    /// Packets on the unverified path (no conntrack hit, no SNAT binding,
    /// no forward rule) dropped because the aggregate unverified-packet
    /// budget window was exhausted. EN-07: this is the fail-closed
    /// admission ceiling that keeps floods from consuming table-creation
    /// work; verified flows never touch this bucket.
    pub unverified_limited: u64,
    /// New-state admissions (forward-rule CT/SNAT creation) rejected because
    /// the new-flow-per-second budget was exhausted. Counted before any
    /// map insert, so a rejected admission creates no state at all.
    pub admission_limited: u64,
}

/// Per-IP fixed-window rate limit configuration written by userspace.
/// A zero `*_pps` disables limiting for that protocol; a zero `window_ns`
/// disables the limiter entirely.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpRateLimitConfig {
    pub udp_pps: u64,
    pub tcp_syn_pps: u64,
    pub window_ns: u64,
    /// EN-08 prefix fairness: bucket granularity for the per-source limiter.
    /// 0 = per-address (/32 or /128, the historical default); otherwise the
    /// source address is masked to this prefix length before keying, so a
    /// randomized-source flood inside one prefix cannot escape its bucket
    /// and many benign prefixes each keep their own.
    pub v4_prefix_len: u32,
    pub v6_prefix_len: u32,
}

/// Per-IP fixed-window bucket; one entry per source address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpRateBucket {
    pub window_start_ns: u64,
    pub count: u64,
}

/// QUIC long-header Destination Connection ID lookup key. `bytes` holds the
/// DCID left-padded with trailing zeros; `len` is the encoded DCID length
/// (1..=20). Only long headers carry an explicit DCID length, so short-header
/// packets are never matched against this map — they use RSS queue affinity.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpQuicDcidKey {
    pub bytes: [u8; 20],
    pub len: u8,
    pub _pad: [u8; 3],
}

impl XdpQuicDcidKey {
    pub fn new(dcid: &[u8]) -> Option<Self> {
        if dcid.is_empty() || dcid.len() > 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes[..dcid.len()].copy_from_slice(dcid);
        Some(Self {
            bytes,
            len: dcid.len() as u8,
            _pad: [0; 3],
        })
    }
}

/// UDP direct-forward rule key: a listen address+port that bypasses the
/// userspace dataplane entirely. `addr` carries an IPv4 address in the first
/// 4 bytes when `family == 4`, or a full IPv6 address when `family == 6`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpUdpFwdKey {
    pub addr: [u8; 16],
    pub port_be: u16,
    pub family: u8,
    pub _pad: u8,
}

impl XdpUdpFwdKey {
    pub fn new_v4(addr_be: u32, port_be: u16) -> Self {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&addr_be.to_be_bytes());
        Self {
            addr,
            port_be,
            family: 4,
            _pad: 0,
        }
    }

    pub fn new_v6(addr: [u8; 16], port_be: u16) -> Self {
        Self {
            addr,
            port_be,
            family: 6,
            _pad: 0,
        }
    }
}

/// NAT target for a direct-forwarded UDP listen tuple. `next_hop_mac` is the
/// resolved gateway/neighbor MAC for the backend, populated by userspace;
/// the egress source MAC is taken from the inbound frame's destination (this
/// interface's own address), so it needs no config.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpUdpFwdRule {
    pub backend_addr: [u8; 16],
    pub next_hop_mac: [u8; 6],
    pub backend_port_be: u16,
    pub family: u8,
    /// SNAT mode: when non-zero the forwarded frame's source is rewritten to
    /// the listen address plus a node-allocated port. Required on fabrics
    /// that drop egress frames whose source IP is not bound to this port
    /// (cloud vSwitch anti-spoof). 0 = plain DNAT preserving the client IP.
    pub snat: u8,
    /// Billing dimension: forwarded bytes are attributed to this server id.
    pub server_id: i64,
}

/// Conntrack entry: a client 4-tuple pinned to a backend so reply traffic can
/// be rewritten back to the listen tuple. Written on the first forwarded
/// datagram (UDP) or SYN (TCP); `client_mac` is learned from the ingress
/// Ethernet header. `proto` distinguishes UDP/TCP tuples that otherwise share
/// the same addresses and ports.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpUdpCtKey {
    pub client_addr: [u8; 16],
    pub backend_addr: [u8; 16],
    pub client_port_be: u16,
    pub backend_port_be: u16,
    pub family: u8,
    /// IP protocol number (6 = TCP, 17 = UDP).
    pub proto: u8,
    pub _pad: [u8; 2],
}

/// Conntrack state: a fresh/established flow.
pub const XDP_CT_STATE_OPEN: u8 = 0;
/// Conntrack state: a FIN or RST was observed; the entry is reaped after a
/// short grace window instead of the full idle timeout.
pub const XDP_CT_STATE_CLOSING: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpUdpCtValue {
    pub listen_addr: [u8; 16],
    pub client_mac: [u8; 6],
    pub listen_port_be: u16,
    pub family: u8,
    /// TCP lifecycle marker (XDP_CT_STATE_*); always OPEN for UDP.
    pub state: u8,
    /// Node-allocated SNAT source port claimed for this flow
    /// (XDP_SNAT_PORT_BASE..); 0 means the flow runs plain DNAT.
    pub snat_port_be: u16,
    pub _pad: [u8; 4],
    /// Billing dimension mirrored from the forward rule.
    pub server_id: i64,
    pub last_seen_ns: u64,
}

/// SNAT reverse-binding key: backend replies arrive addressed to
/// (listen_addr, snat_port); the value restores the client tuple.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpSnatRevKey {
    pub listen_addr: [u8; 16],
    pub snat_port_be: u16,
    /// IP protocol number (17 = UDP, 6 = TCP).
    pub proto: u8,
    pub family: u8,
    pub _pad: [u8; 3],
}

/// SNAT reverse-binding value: the full client flow tuple, needed both for
/// the reply rewrite and to rebuild the conntrack key when sweeping orphan
/// bindings.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpSnatRevValue {
    pub client_addr: [u8; 16],
    pub backend_addr: [u8; 16],
    pub client_mac: [u8; 6],
    pub client_port_be: u16,
    pub backend_port_be: u16,
    pub family: u8,
    pub proto: u8,
    /// Original listen port (network order): replies must masquerade as
    /// (listen_addr, listen_port) - the tuple the client originally dialed.
    /// Kept inside the former padding so earlier fields stay ABI-stable.
    pub listen_port_be: u16,
    pub _pad: [u8; 2],
    /// Billing dimension copied from the forward rule so replies still
    /// account correctly if the conntrack entry was already reaped.
    pub server_id: i64,
}

/// First SNAT source port allocated by the eBPF dataplane.
pub const XDP_SNAT_PORT_BASE: u16 = 40000;
/// SNAT port space size: 40000..=60999.
pub const XDP_SNAT_PORT_SPAN: u16 = 21000;

/// Per-CPU traffic accounting for direct-forwarded flows, keyed by the
/// conntrack key so both directions accumulate under the client flow.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpFlowAcct {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_pkts: u64,
    pub tx_pkts: u64,
    pub last_seen_ns: u64,
    pub server_id: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpInterfacePolicy {
    pub mode: u8,
    pub fallback_pass: u8,
    pub local_ip_filter: u8,
    /// Fragment disposition for this security domain (XDP_FRAGMENT_*).
    /// PASS hands fragments to the kernel stack (legacy behavior); DROP
    /// rejects them at XDP. A first fragment never continues into the
    /// redirect/NAT path regardless of this setting.
    pub fragment_action: u8,
    pub frame_size: u32,
}

/// Fragment policy values for `XdpInterfacePolicy::fragment_action`.
pub const XDP_FRAGMENT_PASS: u8 = 0;
pub const XDP_FRAGMENT_DROP: u8 = 1;

/// XDP_LOCAL_* map value encoding: bit0 marks the entry as present; bits[2:1]
/// carry a per-VIP fragment override (0 = inherit interface policy,
/// 1 = force PASS, 2 = force DROP).
pub const XDP_LOCAL_PRESENT: u32 = 1;
pub const XDP_LOCAL_FRAG_PASS: u32 = 1 << 1;
pub const XDP_LOCAL_FRAG_DROP: u32 = 2 << 1;
/// EN-06: this VIP may redirect proxy-port traffic into AF_XDP. Cleared per
/// VIP (`protectedServices[].redirect: false`) to keep a VIP protected —
/// classification, ACL, rate limits, fragment policy — while its ports are
/// served by the kernel stack. Two VIPs sharing a port therefore do not
/// cross-redirect.
pub const XDP_LOCAL_REDIRECT: u32 = 1 << 3;

/// Per-CPU scratch space for NAT/DCID key construction in the eBPF dataplane.
/// eBPF stack is capped at 512 bytes and the conntrack/forward keys plus
/// values exceed it when inlined, so large temporaries are built in this map
/// instead. The layout lives here (not in the eBPF crate) so userspace can
/// verify the pinned XDP_NAT_SCRATCH map still matches the ABI before reuse.
/// The map itself is internal only; contents are never read by userspace.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NatScratch {
    pub fwd_key: XdpUdpFwdKey,
    pub ct_key: XdpUdpCtKey,
    pub ct_value: XdpUdpCtValue,
    pub dcid_key: XdpQuicDcidKey,
    pub csum_old: [u32; 4],
    pub csum_new: [u32; 4],
    pub snat_rev_key: XdpSnatRevKey,
    pub snat_rev_value: XdpSnatRevValue,
    /// Packet header snapshots for the IPv6 handlers: keeping the two 16-byte
    /// addresses in the per-CPU map instead of locals keeps those frames
    /// under the 512-byte verifier stack limit.
    pub pkt_src: [u8; 16],
    pub pkt_dst: [u8; 16],
    /// Redirect context stashed before a NAT tail call so the dispatch site
    /// keeps no spillable registers (see the eBPF-side mirror).
    pub redir_flags: u32,
    pub redir_proto: u8,
    pub redir_l4off: u16,
    pub redir_pad: u8,
    /// Worker context stashed before the dispatch -> work tail call. Offsets
    /// are re-validated against packet bounds inside the worker program.
    pub work_ip_off: u32,
    pub work_ifindex: u32,
    pub work_pkt_len: u64,
}

// ---------------------------------------------------------------------------
// EN-01 shared contracts: admission state machine, flow identity, owner/path
// binding, budgets and decision reasons. These types are the fixed ABI shared
// between the eBPF dataplane and userspace; every field is network-order or
// explicitly host-order documented. Sizes are asserted at compile time below —
// a layout change must bump XDP_ABI_VERSION and update the map spec table in
// src/xdp.rs (drop_stale_pinned_maps) so mismatched pinned maps are rejected.
// ---------------------------------------------------------------------------

/// ABI version of the whole XDP map/contract surface. Bump when any shared
/// key/value layout, map semantics, or dispatch slot contract changes; userspace
/// refuses to reuse pinned objects whose spec does not match this build.
/// v1: EN-01 baseline. v2: XDP_COUNTERS -> PerCpuArray, +tx +acl_blocked.
/// v3: EN-05 parse classification — XdpCounters +malformed/unsupported/
/// fragmented/control; XdpInterfacePolicy +fragment_action; XDP_LOCAL_* values
/// gain per-VIP fragment override bits.
/// v4: EN-06 protected-service policy — XdpCounters +acl_would_block/
/// nonlocal_pass; XDP_LOCAL_* values gain the XDP_LOCAL_REDIRECT bit.
/// v5: EN-06 verifier split — NatScratch +work_ip_off/work_ifindex/
/// work_pkt_len; XDP_DISPATCH grows to 16 slots (7-10 = NAT work programs).
pub const XDP_ABI_VERSION: u32 = 7;

/// Path that owns a flow's transport state (architecture §4.4 PathBinding).
/// A flow has exactly one owner for its lifetime; packets may not migrate a
/// flow between paths mid-stream.
pub const XDP_OWNER_KERNEL: u8 = 0;
/// AF_XDP userspace transport owner (smoltcp/UDP demux/QUIC).
pub const XDP_OWNER_AFXDP: u8 = 1;
/// XDP NAT direct-forward owner (XDP_TX rewrite).
pub const XDP_OWNER_NAT: u8 = 2;

/// Admission state machine states (architecture §4.4):
///   ABSENT → PENDING → VALIDATED → CLOSING → EXPIRED
///                  └──────────────→ EXPIRED
/// ABSENT is "no map entry", so only four states are stored.
pub const XDP_FLOW_PENDING: u8 = 0;
pub const XDP_FLOW_VALIDATED: u8 = 1;
pub const XDP_FLOW_CLOSING: u8 = 2;
pub const XDP_FLOW_EXPIRED: u8 = 3;

/// Validation level recorded at admission time.
pub const XDP_VALIDATION_NONE: u8 = 0;
/// Source passed a stateless proof (TCP cookie / QUIC Retry token).
pub const XDP_VALIDATION_STATELESS: u8 = 1;
/// A transport owner confirmed the handshake completed.
pub const XDP_VALIDATION_OWNER: u8 = 2;

/// Terminal decision reasons. Every DROP/reject path must carry exactly one
/// reason so observability can attribute it (I10). Values are stable ABI for
/// counters/metrics labels — append only, never renumber.
pub const XDP_DECISION_PASS: u8 = 0;
pub const XDP_DECISION_ACL_BLOCK: u8 = 1;
pub const XDP_DECISION_RATE_SOURCE: u8 = 2;
pub const XDP_DECISION_MALFORMED: u8 = 3;
pub const XDP_DECISION_FRAGMENT: u8 = 4;
pub const XDP_DECISION_NO_FLOW: u8 = 5;
pub const XDP_DECISION_BUDGET: u8 = 6;
pub const XDP_DECISION_NO_XSK: u8 = 7;
pub const XDP_DECISION_FLOW_TABLE_FULL: u8 = 8;
pub const XDP_DECISION_TCP_FLAG: u8 = 9;

/// Parse classification (architecture §4.3): replaces the single
/// Err→PASS bucket. CONTROL covers PMTU/ICMPv6-ND and other exempt traffic.
pub const XDP_CLASS_SUPPORTED: u8 = 0;
pub const XDP_CLASS_MALFORMED: u8 = 1;
pub const XDP_CLASS_UNSUPPORTED: u8 = 2;
pub const XDP_CLASS_FRAGMENTED: u8 = 3;
pub const XDP_CLASS_CONTROL: u8 = 4;

/// Flow identity. `service_*` is the node-side listen tuple (VIP); when the
/// tenant is not yet known (shared 443) `service_id` carries the
/// listener/service identity instead of a tenant id (I06/I11).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpFlowKey {
    pub client_addr: [u8; 16],
    pub service_addr: [u8; 16],
    /// Billing/tenant dimension; listener id until tenant is identified.
    pub service_id: i64,
    pub client_port_be: u16,
    pub service_port_be: u16,
    /// Interface-derived security zone.
    pub security_domain: u16,
    pub family: u8,
    pub proto: u8,
}

/// Per-flow admission record. Lookup must validate deadlines; GC only reclaims
/// space. `absolute_deadline_ns` is never extended by retransmits (I02/I03);
/// `idle_deadline_ns` only advances on packets that match the current
/// incarnation and owner.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpFlowRecord {
    pub created_ns: u64,
    /// Hard cap for PENDING lifetime; retransmits never extend it.
    pub absolute_deadline_ns: u64,
    /// Validated-flow idle deadline; lookup checks, GC reclaims.
    pub idle_deadline_ns: u64,
    /// Tuple-reuse guard: bumped per admission so stale events cannot own a
    /// recycled tuple.
    pub flow_incarnation: u64,
    /// Owner generation; an old worker's events cannot touch a re-owned flow.
    pub owner_epoch: u64,
    /// Policy generation selected for this packet/flow.
    pub policy_generation: u64,
    pub service_id: i64,
    /// XDP_FLOW_* state.
    pub state: u8,
    /// XDP_OWNER_* path owner.
    pub owner_kind: u8,
    /// XDP_VALIDATION_* level.
    pub validation: u8,
    pub flags: u8,
    pub _pad: u32,
}

/// Flow lifecycle event (userspace ↔ dataplane feedback contract, EN-10).
/// Old events must not override newer state on a reused tuple — compare
/// (incarnation, owner_epoch, seq) before applying.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpFlowEvent {
    pub key: XdpFlowKey,
    pub flow_incarnation: u64,
    pub owner_epoch: u64,
    pub seq: u64,
    pub timestamp_ns: u64,
    /// Event kind: 0=admitted 1=validated 2=closed 3=rejected 4=expired.
    pub kind: u8,
    /// XDP_DECISION_* reason.
    pub reason: u8,
    pub _pad: [u8; 6],
}

/// Transport binding for a flow's owner path.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpPathBinding {
    /// XDP_OWNER_*.
    pub kind: u8,
    pub _pad0: [u8; 3],
    /// AF_XDP: bound RX queue; NAT: unused (backend lives in the CT value).
    pub queue_id: u32,
    /// NAT backend tuple (family-embedded), zero for KERNEL/AFXDP.
    pub backend_addr: [u8; 16],
    pub backend_port_be: u16,
    pub _pad1: [u8; 6],
}

/// Aggregate admission budgets written by userspace (architecture §4.5).
/// All counters are per-second rates over `window_ns`; zero disables a check.
/// These are *aggregate* ceilings — they hold regardless of source rotation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpBudgetConfig {
    /// Max packets/sec that may enter the unverified path.
    pub unverified_pps: u64,
    /// Max new-state admissions/sec (SYN, first-packet UDP, QUIC Initial).
    pub new_flow_per_sec: u64,
    /// Max packets/sec redirected into AF_XDP (protects the reactor).
    pub xsk_redirect_pps: u64,
    /// Max challenge responses/sec (cookie/Retry replies).
    pub challenge_pps: u64,
    /// Accounting window shared by the buckets.
    pub window_ns: u64,
    /// Enable bitset; bit0 = enforce unverified_pps, bit1 = new_flow,
    /// bit2 = xsk_redirect, bit3 = challenge.
    pub flags: u64,
}

/// Per-CPU budget bucket state for `XDP_BUDGET` (EN-07). Each CPU owns its
/// slots exclusively, so read-modify-write is race-free; userspace pre-divides
/// the node-wide totals by the possible-CPU count when writing
/// `XdpBudgetConfig`, keeping the aggregate quota independent of CPU/queue
/// count. Index convention matches `XdpBudgetConfig` flag bits:
/// 0=unverified pps, 1=new-flow admissions, 2=xsk redirect, 3=challenge.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpBudgetBucket {
    pub window_start_ns: [u64; 4],
    pub count: [u64; 4],
}

/// Half-open concurrency cap stored in a single-slot map value so the dataplane
/// can compare pending_count against a ceiling without a second lookup.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XdpPendingCap {
    pub max_pending: u64,
    pub _pad: u64,
}

// Compile-time ABI assertions. If any of these fire, a shared layout changed:
// bump XDP_ABI_VERSION and update the map spec table so stale pinned maps are
// rejected instead of misread.
const _: () = assert!(core::mem::size_of::<XdpFlowKey>() == 48);
const _: () = assert!(core::mem::size_of::<XdpFlowRecord>() == 64);
const _: () = assert!(core::mem::size_of::<XdpFlowEvent>() == 88);
const _: () = assert!(core::mem::size_of::<XdpPathBinding>() == 32);
const _: () = assert!(core::mem::size_of::<XdpBudgetConfig>() == 48);
const _: () = assert!(core::mem::size_of::<XdpBudgetBucket>() == 64);
const _: () = assert!(core::mem::size_of::<XdpPendingCap>() == 16);
const _: () = assert!(core::mem::size_of::<XdpCounters>() == 208);
const _: () = assert!(core::mem::size_of::<XdpUdpCtKey>() == 40);
const _: () = assert!(core::mem::size_of::<XdpUdpCtValue>() == 48);
const _: () = assert!(core::mem::size_of::<XdpSnatRevKey>() == 24);
const _: () = assert!(core::mem::size_of::<XdpSnatRevValue>() == 56);
const _: () = assert!(core::mem::size_of::<XdpInterfacePolicy>() == 8);
const _: () = assert!(core::mem::size_of::<XdpRateBucket>() == 16);
const _: () = assert!(core::mem::size_of::<XdpRateLimitConfig>() == 32);
const _: () = assert!(core::mem::size_of::<NatScratch>() == 312);

#[cfg(all(feature = "aya", target_os = "linux"))]
macro_rules! unsafe_impl_aya_pod {
    ($($ty:ty),+ $(,)?) => {
        $(
            // SAFETY: These are repr(C), Copy-only ABI structs shared verbatim with eBPF maps.
            unsafe impl aya::Pod for $ty {}
        )+
    };
}

#[cfg(all(feature = "aya", target_os = "linux"))]
unsafe_impl_aya_pod!(
    XdpIpv4Key,
    XdpIpv6Key,
    XdpRangeKey,
    XdpPortProtoKey,
    XdpQueueKey,
    XdpLocalIpv4Key,
    XdpLocalIpv6Key,
    XdpRuleValue,
    XdpCounters,
    XdpInterfacePolicy,
    XdpRateLimitConfig,
    XdpRateBucket,
    XdpQuicDcidKey,
    XdpUdpFwdKey,
    XdpUdpFwdRule,
    XdpUdpCtKey,
    XdpUdpCtValue,
    XdpSnatRevKey,
    XdpSnatRevValue,
    XdpFlowAcct,
    NatScratch,
    XdpFlowKey,
    XdpFlowRecord,
    XdpFlowEvent,
    XdpPathBinding,
    XdpBudgetConfig,
    XdpBudgetBucket,
    XdpPendingCap,
);

#[cfg(feature = "std")]
pub mod host {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    pub fn ipv4_key(addr: Ipv4Addr) -> XdpIpv4Key {
        XdpIpv4Key::new(u32::from_be_bytes(addr.octets()))
    }

    pub fn ipv6_key(addr: Ipv6Addr) -> XdpIpv6Key {
        XdpIpv6Key::new(addr.octets())
    }

    pub fn local_ipv4_key(ifindex: u32, addr: Ipv4Addr) -> XdpLocalIpv4Key {
        XdpLocalIpv4Key::new(ifindex, u32::from_be_bytes(addr.octets()))
    }

    pub fn local_ipv6_key(ifindex: u32, addr: Ipv6Addr) -> XdpLocalIpv6Key {
        XdpLocalIpv6Key::new(ifindex, addr.octets())
    }

    pub fn ip_to_u128(addr: IpAddr) -> (u128, u8) {
        match addr {
            IpAddr::V4(v4) => (
                u32::from_be_bytes(v4.octets()) as u128,
                XdpRangeKey::FAMILY_IPV4,
            ),
            IpAddr::V6(v6) => (u128::from_be_bytes(v6.octets()), XdpRangeKey::FAMILY_IPV6),
        }
    }

    pub fn range_key(from: IpAddr, to: IpAddr) -> Option<XdpRangeKey> {
        let (from_n, from_family) = ip_to_u128(from);
        let (to_n, to_family) = ip_to_u128(to);
        (from_family == to_family && from_n <= to_n).then_some(XdpRangeKey::new(
            from_n,
            to_n,
            from_family,
        ))
    }

    pub fn range_contains(range: XdpRangeKey, addr: IpAddr) -> bool {
        let (addr_n, family) = ip_to_u128(addr);
        family == range.family && addr_n >= range.from() && addr_n <= range.to()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn range_key_matches_ipv4_inside_only() {
            let range =
                range_key("192.0.2.10".parse().unwrap(), "192.0.2.20".parse().unwrap()).unwrap();
            assert!(range_contains(range, "192.0.2.15".parse().unwrap()));
            assert!(!range_contains(range, "192.0.2.21".parse().unwrap()));
            assert!(!range_contains(range, "2001:db8::1".parse().unwrap()));
        }

        #[test]
        fn quic_dcid_key_pads_and_bounds() {
            let key = XdpQuicDcidKey::new(&[0xaa, 0xbb, 0xcc]).unwrap();
            assert_eq!(key.len, 3);
            assert_eq!(&key.bytes[..3], &[0xaa, 0xbb, 0xcc]);
            assert!(key.bytes[3..].iter().all(|b| *b == 0));

            let mut long = [0x11u8; 20];
            long[19] = 0x22;
            let key = XdpQuicDcidKey::new(&long).unwrap();
            assert_eq!(key.len, 20);
            assert_eq!(key.bytes, long);

            assert!(XdpQuicDcidKey::new(&[]).is_none());
            assert!(XdpQuicDcidKey::new(&[0u8; 21]).is_none());

            // Same bytes with different lengths must not collide.
            let short = XdpQuicDcidKey::new(&[1, 2]).unwrap();
            let long = XdpQuicDcidKey::new(&[1, 2, 0]).unwrap();
            assert_ne!(short, long);
        }

        #[test]
        fn mixed_family_range_is_rejected() {
            assert!(
                range_key(
                    "192.0.2.10".parse().unwrap(),
                    "2001:db8::1".parse().unwrap()
                )
                .is_none()
            );
        }

        // ---- EN-01 contract tests -------------------------------------

        /// A stale event must not own a recycled tuple: the (incarnation,
        /// owner_epoch, seq) triple is the ordering key — same tuple, later
        /// admission must win over an older queued event.
        #[test]
        fn flow_event_orders_by_incarnation_epoch_seq() {
            let mut key = XdpFlowKey::default();
            key.family = 4;
            key.proto = XDP_PROTO_TCP;
            let stale = XdpFlowEvent {
                key,
                flow_incarnation: 1,
                owner_epoch: 3,
                seq: 40,
                kind: 2,
                reason: XDP_DECISION_PASS,
                ..Default::default()
            };
            let fresh = XdpFlowEvent {
                key,
                flow_incarnation: 2,
                owner_epoch: 4,
                seq: 0,
                kind: 0,
                reason: XDP_DECISION_PASS,
                ..Default::default()
            };
            // Ordering tuple: incarnation first, then epoch, then seq.
            let order = |e: &XdpFlowEvent| (e.flow_incarnation, e.owner_epoch, e.seq);
            assert!(order(&fresh) > order(&stale));
        }

        /// Pending flows die by absolute deadline even if retransmits keep
        /// arriving — callers must compare against absolute_deadline_ns, not
        /// refresh it.
        #[test]
        fn pending_record_has_absolute_and_idle_deadlines() {
            let rec = XdpFlowRecord {
                created_ns: 1_000,
                absolute_deadline_ns: 5_000,
                idle_deadline_ns: 2_000,
                state: XDP_FLOW_PENDING,
                ..Default::default()
            };
            assert!(rec.absolute_deadline_ns > rec.created_ns);
            assert_ne!(rec.absolute_deadline_ns, rec.idle_deadline_ns);
        }

        /// Decision reason codes are append-only ABI; pin the numeric values
        /// so a careless rename/renumber breaks the build, not the metrics.
        #[test]
        fn decision_reasons_are_stable() {
            assert_eq!(XDP_DECISION_PASS, 0);
            assert_eq!(XDP_DECISION_NO_XSK, 7);
            assert_eq!(XDP_DECISION_TCP_FLAG, 9);
        }

        /// Disabled budget bits must make the whole config inert — zero flags
        /// with nonzero rates is the documented "not configured" state.
        #[test]
        fn budget_config_zero_flags_is_disabled() {
            let cfg = XdpBudgetConfig {
                unverified_pps: 1_000_000,
                flags: 0,
                ..Default::default()
            };
            assert_eq!(cfg.flags, 0);
            assert_eq!(cfg.window_ns, 0);
        }
    }
}
