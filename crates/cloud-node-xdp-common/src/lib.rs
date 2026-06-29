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
pub struct XdpIpv4LpmKey {
    pub prefix_len: u32,
    pub addr_be: u32,
}

impl XdpIpv4LpmKey {
    pub const fn new(prefix_len: u32, addr_be: u32) -> Self {
        Self {
            prefix_len,
            addr_be,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct XdpIpv6LpmKey {
    pub prefix_len: u32,
    pub addr: [u8; 16],
}

impl XdpIpv6LpmKey {
    pub const fn new(prefix_len: u32, addr: [u8; 16]) -> Self {
        Self { prefix_len, addr }
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
    XdpIpv4LpmKey,
    XdpIpv6LpmKey,
    XdpRangeKey,
    XdpPortProtoKey,
    XdpQueueKey,
    XdpLocalIpv4Key,
    XdpLocalIpv6Key,
    XdpRuleValue,
    XdpCounters,
    XdpInterfacePolicy,
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
