//! Shared QUIC transport tuning for the production HTTP/3 listeners and the
//! bench endpoints.
//!
//! The QUIC data plane cost scales with datagrams per second: every UDP
//! datagram costs a `sendmsg`/`recvmsg` syscall plus per-packet AEAD work in
//! userspace (no kernel acceleration). Two levers dominate: larger datagrams
//! (MTU) where the path allows them, and flow-control windows large enough
//! to keep a fast path busy.

use quinn::{MtuDiscoveryConfig, TransportConfig, VarInt};
use std::time::Duration;

/// Per-stream send window: the cap on unacked stream data we hold for
/// retransmit. The upstream default (~10 MiB) tops out below what a fast
/// loopback/DC path or a high-BDP WAN can sustain.
const SEND_WINDOW: u64 = 32 * 1024 * 1024;

/// Per-stream receive window we advertise to the peer.
const STREAM_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;

/// Re-probe interval for path MTU discovery. The upstream default (600 s)
/// effectively never climbs during a short connection.
const MTU_PROBE_INTERVAL: Duration = Duration::from_secs(60);

/// Build a [`TransportConfig`] with throughput-oriented windows.
///
/// `mtu_ceiling` controls how large a QUIC datagram may grow:
/// - `None`: internet-safe — discovery probes up to the ethernet ceiling
///   (1500) and black-hole detection backs off automatically;
/// - `Some(n)`: also sets `initial_mtu` so the first datagrams are large
///   immediately. Intended for loopback/jumbo paths (e.g. `BENCH_QUIC_MTU`
///   in the bench binaries) where 64 KiB datagrams cut the per-packet cost
///   proportionally.
pub fn tuned_transport_config(mtu_ceiling: Option<u16>) -> TransportConfig {
    let mut config = TransportConfig::default();
    config.send_window(SEND_WINDOW);
    config.stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW));

    let mut discovery = MtuDiscoveryConfig::default();
    discovery.interval(MTU_PROBE_INTERVAL);
    match mtu_ceiling {
        Some(mtu) => {
            discovery.upper_bound(mtu);
            config.initial_mtu(mtu);
        }
        None => {
            discovery.upper_bound(1500);
        }
    }
    config.mtu_discovery_config(Some(discovery));
    config
}
