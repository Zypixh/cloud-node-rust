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
    pub _pad: [u8; 6],
    /// Billing dimension mirrored from the forward rule.
    pub server_id: i64,
    pub last_seen_ns: u64,
}

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
    pub _pad: u8,
    pub frame_size: u32,
}

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
    XdpFlowAcct,
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
    }
}
