use super::*;
use bytes::Bytes;
// Ungated: `AfXdpTcpStream` is compiled on all targets and its
// shared wake/stall fields name `DashMap` through `use super::*`.
use dashmap::DashMap;
#[cfg(any(test, target_os = "linux"))]
use smoltcp::iface::{
    Config as SmoltcpConfig, Interface as SmoltcpInterface, PollIngressSingleResult, SocketHandle,
    SocketSet,
};
#[cfg(any(test, target_os = "linux"))]
use smoltcp::phy::{
    Checksum, Device as SmoltcpDevice, DeviceCapabilities, Medium, RxToken, TxToken,
};
#[cfg(any(test, target_os = "linux"))]
use smoltcp::socket::tcp as SmoltcpTcp;
#[cfg(any(test, target_os = "linux"))]
use smoltcp::time::{Duration as SmolDuration, Instant as SmoltcpInstant};
#[cfg(any(test, target_os = "linux"))]
use smoltcp::wire::{
    HardwareAddress, IpAddress as SmoltcpIpAddress, IpCidr as SmoltcpIpCidr, IpEndpoint,
    IpListenEndpoint,
};
#[cfg(any(test, target_os = "linux"))]
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
#[cfg(any(test, target_os = "linux"))]
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tokio::sync::watch;

const ETH_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const ETHERTYPE_QINQ_9100: u16 = 0x9100;
const ETHERTYPE_QINQ_9200: u16 = 0x9200;
const ETHERTYPE_QINQ_9300: u16 = 0x9300;
const IP_PROTO_TCP: u8 = cloud_node_xdp_common::XDP_PROTO_TCP;
const IP_PROTO_UDP: u8 = cloud_node_xdp_common::XDP_PROTO_UDP;
/// T4-7: ICMPv4/ICMPv6 next-header values for the PMTU error parser.
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_ICMPV6: u8 = 58;
const IP_PROTO_HOP_BY_HOP: u8 = 0;
const IP_PROTO_ROUTING: u8 = 43;
const IP_PROTO_FRAGMENT: u8 = 44;
const IP_PROTO_AH: u8 = 51;
const IP_PROTO_NO_NEXT: u8 = 59;
const IP_PROTO_DEST_OPTS: u8 = 60;
const AF_XDP_TCP_STREAM_CHANNEL_DEPTH: usize = 256;
const AF_XDP_TCP_STREAM_WRITE_CHUNK: usize = 16 * 1024;
#[cfg(any(test, target_os = "linux"))]
const AF_XDP_TCP_SOCKET_BUFFER_BYTES: usize = 16 * 1024;
#[cfg(any(test, target_os = "linux"))]
const AF_XDP_TCP_SESSION_ESTIMATED_BYTES: u64 =
    (AF_XDP_TCP_SOCKET_BUFFER_BYTES as u64 * 2) + 16 * 1024;
#[cfg(any(test, target_os = "linux"))]
const AF_XDP_TCP_MIN_SESSION_LIMIT: usize = 512;
const AF_XDP_TCP_MAX_SESSION_LIMIT: usize = 16_384;
#[cfg(any(test, target_os = "linux"))]
const AF_XDP_TCP_IDLE_PROFILE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_RECV_SCRATCH_BYTES: usize = 16 * 1024;
/// EN-17: bound on sessions pumped per poll round — a large session table
/// cannot starve TX/timers under RX flood.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_PUMP_BUDGET: usize = 512;
/// EN-17: smoltcp ingress packets processed per poll round; the remainder
/// stays queued for the next round (queue itself is bounded separately).
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_INGRESS_BUDGET: usize = 512;
/// EN-17: bound on queued-but-unprocessed ingress packets per reactor.
/// Overflow is an explicit, counted refusal — never silent memory growth.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_INGRESS_QUEUE_MAX: usize = 4096;
/// EN-17: dirty-mark entries drained from the shared wake set per round.
/// The set itself is hard-bounded by the session limit (one entry per live
/// flow); the budget caps per-round drain work, leftovers stay queued.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_WAKE_DRAIN_BUDGET: usize = 8192;
/// EN-17: one full-table sweep cycle starts every SWEEP_INTERVAL, but the
/// cursor advances at most this many entries per poll round — sweeps share
/// the round's work budget instead of doing an unbounded pass.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_SWEEP_BATCH_BUDGET: usize = 256;
/// EN-17/F3: cap on the per-reactor stalled-writer set. One entry per
/// suspended writer task (re-registered on each wake), so the bound is
/// defensive — beyond it a writer stays parked until a peer's wake frees
/// budget and the next poll re-registers.
pub(crate) const AF_XDP_TCP_BUDGET_STALL_MAX: usize = 2 * AF_XDP_TCP_MAX_SESSION_LIMIT;
/// EN-17: amortized full-session sweep cadence — backstop for sessions
/// whose progress signal (packet or egress wake) was not observed, and
/// the reap/idle-timeout granularity.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_SWEEP_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// T4: absolute connect deadline for node-dialed flows — covers the full
/// SYN retrain sequence; a session still not Established past it is
/// aborted and the dial answered with a timeout, never left lingering.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(4);
/// T4/T4-5 (D-B1): default reserved source-port span for node-dialed
/// AF_XDP flows. The kernel guard carves this range out of
/// `ip_local_reserved_ports` so no kernel socket can claim a tuple that
/// XDP_OUT_CT steers into AF_XDP; configurable via
/// `xdp.upstream.dialPortRange`.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_DIAL_PORT_BASE: u16 = 40_000;

#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_ACCEPTED: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_IGNORED_UNKNOWN: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_REFUSED_AT_CAPACITY: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_PRE_PROXY_TIMEOUT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_PROXY_STARTED: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_STREAM_EGRESS_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_EGRESS_FRAMES: AtomicU64 = AtomicU64::new(0);
/// EN-17: ingress packets refused because the per-reactor queue was full.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_INGRESS_QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);
/// EN-17: egress wake signals received from proxy tasks.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_WAKE_SIGNALS: AtomicU64 = AtomicU64::new(0);
/// EN-17/F3: ingress packets refused because the node TCP queue byte
/// budget was exhausted (distinct from the per-reactor frame queue).
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_INGRESS_BUDGET_DROPPED: AtomicU64 = AtomicU64::new(0);
/// EN-17/F3: queue-byte-budget backpressure events — a recv drain parked
/// or a stream write suspended.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_BUDGET_STALLS: AtomicU64 = AtomicU64::new(0);

/// T1: live per-session transport snapshots surfaced through /status.
/// Queue workers refresh their rows during each amortized sweep; rows are
/// deleted when a session is reaped or the reactor drops. The map is
/// bounded by Σ per-queue session limits; the status export below is
/// additionally capped so a saturated node cannot emit an unbounded body.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_SESSION_SNAPSHOTS: std::sync::LazyLock<
    DashMap<String, serde_json::Value>,
> = std::sync::LazyLock::new(DashMap::new);

/// T1: cap on session rows exported into a single /status response.
#[cfg(target_os = "linux")]
pub(crate) const AF_XDP_TCP_SNAPSHOT_EXPORT_MAX: usize = 4096;

#[cfg(target_os = "linux")]
pub(crate) fn publish_tcp_session_snapshot(key: String, snapshot: serde_json::Value) {
    AF_XDP_TCP_SESSION_SNAPSHOTS.insert(key, snapshot);
}

#[cfg(target_os = "linux")]
pub(crate) fn remove_tcp_session_snapshot(key: &str) {
    AF_XDP_TCP_SESSION_SNAPSHOTS.remove(key);
}

/// T1: drop every snapshot row a reactor owned — called when a queue
/// worker exits so /status never shows sessions of a dead reactor.
#[cfg(target_os = "linux")]
pub(crate) fn purge_tcp_session_snapshots(label_prefix: &str) {
    if label_prefix.is_empty() {
        return;
    }
    let prefix = format!("{label_prefix}|");
    AF_XDP_TCP_SESSION_SNAPSHOTS.retain(|key, _| !key.starts_with(&prefix));
}

#[cfg(target_os = "linux")]
pub(crate) fn reset_tcp_diag() {
    AF_XDP_TCP_DIAG_ACCEPTED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_IGNORED_UNKNOWN.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_REFUSED_AT_CAPACITY.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_PRE_PROXY_TIMEOUT.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_PROXY_STARTED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_STREAM_EGRESS_BYTES.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_EGRESS_FRAMES.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_INGRESS_QUEUE_DROPPED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_WAKE_SIGNALS.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_INGRESS_BUDGET_DROPPED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_BUDGET_STALLS.store(0, Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
pub(crate) fn tcp_diag_snapshot() -> serde_json::Value {
    serde_json::json!({
        "accepted": AF_XDP_TCP_DIAG_ACCEPTED.load(Ordering::Relaxed),
        "ignoredUnknown": AF_XDP_TCP_DIAG_IGNORED_UNKNOWN.load(Ordering::Relaxed),
        "refusedAtCapacity": AF_XDP_TCP_DIAG_REFUSED_AT_CAPACITY.load(Ordering::Relaxed),
        "preProxyTimeout": AF_XDP_TCP_DIAG_PRE_PROXY_TIMEOUT.load(Ordering::Relaxed),
        "proxyStarted": AF_XDP_TCP_DIAG_PROXY_STARTED.load(Ordering::Relaxed),
        "socketRecvBytes": AF_XDP_TCP_DIAG_SOCKET_RECV_BYTES.load(Ordering::Relaxed),
        "streamIngressBytes": AF_XDP_TCP_DIAG_STREAM_INGRESS_BYTES.load(Ordering::Relaxed),
        "streamEgressBytes": AF_XDP_TCP_DIAG_STREAM_EGRESS_BYTES.load(Ordering::Relaxed),
        "egressFrames": AF_XDP_TCP_DIAG_EGRESS_FRAMES.load(Ordering::Relaxed),
        "ingressQueueDropped": AF_XDP_TCP_DIAG_INGRESS_QUEUE_DROPPED.load(Ordering::Relaxed),
        "wakeSignals": AF_XDP_TCP_DIAG_WAKE_SIGNALS.load(Ordering::Relaxed),
        "ingressBudgetDropped": AF_XDP_TCP_DIAG_INGRESS_BUDGET_DROPPED.load(Ordering::Relaxed),
        "queueBudgetStalls": AF_XDP_TCP_DIAG_BUDGET_STALLS.load(Ordering::Relaxed),
        "tcpQueueBytes": crate::memory_governor::MEMORY_GOVERNOR.tcp_queue_bytes(),
        "tcpQueueBytesBudget": crate::memory_governor::MEMORY_GOVERNOR.tcp_queue_bytes_budget(),
        "sessions": tcp_session_snapshots_json(),
    })
}

/// T1: bounded export of live per-session snapshots — `total` reflects
/// every tracked session, `rows` is capped at AF_XDP_TCP_SNAPSHOT_EXPORT_MAX.
#[cfg(target_os = "linux")]
fn tcp_session_snapshots_json() -> serde_json::Value {
    let total = AF_XDP_TCP_SESSION_SNAPSHOTS.len();
    let rows: Vec<serde_json::Value> = AF_XDP_TCP_SESSION_SNAPSHOTS
        .iter()
        .take(AF_XDP_TCP_SNAPSHOT_EXPORT_MAX)
        .map(|entry| entry.value().clone())
        .collect();
    serde_json::json!({
        "total": total,
        "truncated": total.saturating_sub(rows.len()),
        "rows": rows,
    })
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AfXdpTxStatus {
    Sent,
    Backpressured,
    Failed,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug)]
pub(crate) struct AfXdpTxFailureTracker {
    consecutive_failures: u32,
    max_consecutive_failures: u32,
}

#[cfg(any(test, target_os = "linux"))]
impl AfXdpTxFailureTracker {
    pub(crate) fn new(max_consecutive_failures: u32) -> Self {
        Self {
            consecutive_failures: 0,
            max_consecutive_failures: max_consecutive_failures.max(1),
        }
    }

    /// F2 split semantics. `Backpressured` is a capacity signal: it returns
    /// true exactly once when the streak reaches the threshold (a warn edge)
    /// and must never tear the queue down. `Failed` is a real TX error: it
    /// returns true on the threshold and stays true while the streak runs,
    /// so a device/worker fault buried in a backpressure streak still
    /// isolates the queue.
    pub(crate) fn record(&mut self, status: AfXdpTxStatus) -> bool {
        match status {
            AfXdpTxStatus::Sent => {
                self.consecutive_failures = 0;
                false
            }
            AfXdpTxStatus::Backpressured => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.consecutive_failures == self.max_consecutive_failures
            }
            AfXdpTxStatus::Failed => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.consecutive_failures >= self.max_consecutive_failures
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

type TcpWritePermitFuture = Pin<
    Box<
        dyn Future<
                Output = Result<
                    mpsc::OwnedPermit<AfXdpTcpChargedBytes>,
                    mpsc::error::SendError<()>,
                >,
            > + Send,
    >,
>;

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IngressDelivery {
    Delivered,
    Backpressured,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfXdpVlanTag {
    pub tpid: u16,
    pub tci: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfXdpLinkMeta {
    pub destination_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub vlan_tags: [AfXdpVlanTag; 2],
    pub vlan_tag_count: u8,
    pub ethertype: u16,
}

impl AfXdpLinkMeta {
    pub fn reply_eth_header_len(&self) -> usize {
        ETH_HEADER_LEN + usize::from(self.vlan_tag_count.min(2)) * VLAN_HEADER_LEN
    }
}

#[derive(Clone, Debug)]
pub struct AfXdpDatagram {
    pub listen_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub payload: Bytes,
    /// C11: IP-header ECN codepoint bits (0–3) carried from the parsed
    /// frame — QUIC receivers report them for congestion feedback.
    pub ecn: Option<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AfXdpTransportProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AfXdpL4Packet {
    pub protocol: AfXdpTransportProtocol,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub payload: Bytes,
    pub link: AfXdpLinkMeta,
    /// IP-header ECN codepoint bits (0–3) — QUIC receivers report them
    /// for congestion feedback; plain UDP relay ignores the field.
    pub ecn: Option<u8>,
}

impl AfXdpL4Packet {
    pub fn tcp_flow_key(&self) -> Option<AfXdpTcpFlowKey> {
        (self.protocol == AfXdpTransportProtocol::Tcp).then_some(AfXdpTcpFlowKey {
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
        })
    }

    pub fn into_udp_datagram(self) -> Option<AfXdpDatagram> {
        (self.protocol == AfXdpTransportProtocol::Udp).then_some(AfXdpDatagram {
            listen_addr: self.local_addr,
            peer_addr: self.peer_addr,
            payload: self.payload,
            ecn: self.ecn,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AfXdpTcpFlowKey {
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AfXdpRouteMeta {
    /// EN-17: shared string — cloning a route meta bumps a refcount instead
    /// of allocating per packet.
    pub interface: Arc<str>,
    pub queue: u32,
    pub link: AfXdpLinkMeta,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AfXdpProxyFrame {
    Udp {
        route: AfXdpRouteMeta,
        packet: AfXdpL4Packet,
    },
    Tcp {
        route: AfXdpRouteMeta,
        flow: AfXdpTcpFlowKey,
        ip_packet: Bytes,
    },
}

mod bridge;
#[cfg(target_os = "linux")]
mod dial;
mod parser;
mod tcp_reactor;

pub use bridge::{AfXdpRuntime, runtime, start_proxy_bridge, start_udp_bridge};
#[cfg(test)]
pub(crate) use bridge::*;
#[cfg(target_os = "linux")]
pub(crate) use dial::*;
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
pub(crate) use parser::*;
pub use parser::{
    encode_ip_reply_frame, encode_udp_reply_frame, extract_ip_frame, parse_l4_packet,
    parse_proxy_frame,
};
pub(crate) use tcp_reactor::*;
pub use tcp_reactor::{AfXdpTcpStream, AfXdpTcpStreamParts};
