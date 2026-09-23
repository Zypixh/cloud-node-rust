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
#[cfg(any(test, target_os = "linux"))]
const IP_PROTO_ICMP: u8 = 1;
#[cfg(any(test, target_os = "linux"))]
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
/// T9: in-session buffer growth ceiling per direction. The advertised
/// window shift is negotiated for this size at socket creation
/// (`set_rx_window_shift_for_ceiling`), so buffers can grow into it
/// without re-handshaking. 1 MiB ≈ 74 Mbps per leg at 113 ms RTT.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_SOCKET_BUFFER_MAX: usize = 1024 * 1024;
/// T9: smallest worthwhile charged growth step — below this the
/// allocation churn outweighs the window gain.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_BUFFER_GROW_MIN_DELTA: usize = 16 * 1024;
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
/// T9: a session parked on the queue-ledger budget dies after this long
/// regardless of arriving packets. Without it the stall is an immortal
/// zombie: client retransmissions keep refreshing `last_activity`, idle
/// reap never fires, and the session's buffer permits pin the ledger
/// for every other session — measured on-node as a permanent refusal
/// state after one saturation event ("断网").
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_BUDGET_STALL_DEADLINE: Duration = Duration::from_secs(10);
/// T9: a session parked on its fair-share *drain cap* (bounded channel
/// backlog, not the ledger) is reaped after this long with zero consumer
/// progress — the reader died but peer traffic keeps `last_activity`
/// fresh. Deliberately longer than BUDGET_STALL_DEADLINE: the parked
/// bytes are already bounded so this is zombie GC, not memory pressure.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_CAP_PARK_DEADLINE: Duration = Duration::from_secs(30);
/// T9: an established session whose socket queues, channel backlog and
/// pending chunks have all been empty for this long returns its grown
/// buffers to the ledger (capacity resize + growth-permit release).
/// Growth is demand-proven again on the next burst, so the shrink only
/// costs one window's worth of ramp-up — while idle holdings were
/// measured pinning the whole queue budget long after traffic stopped.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_IDLE_SHRINK_AFTER: Duration = Duration::from_secs(2);
/// T9: after a refused growth charge, wait this long before trying
/// again. Per-pump retries against a full ledger were measured at
/// ~11M CAS attempts/min — enough to starve the single reactor thread
/// by themselves.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_GROWTH_RETRY_BACKOFF: Duration = Duration::from_millis(250);
/// Unverified (pre-proxy) sessions hold a bounded share of the session
/// table: a peer that has not completed handshake + first payload is the
/// cheapest class to churn under pressure — scanners and SYN floods must
/// never displace verified proxied or dialed flows.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_PRE_PROXY_MIN_BUDGET: usize = 256;
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_PRE_PROXY_BUDGET_DIVISOR: usize = 8;
/// Per-source-IP cap on unverified sessions — one address can churn its
/// own pre-proxy slots but cannot hold the whole unverified budget.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const AF_XDP_TCP_PRE_PROXY_PER_IP_LIMIT: usize = 64;
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
#[cfg(target_os = "linux")]
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
/// EN-17/F3: queue-byte-budget backpressure events — a recv drain parked
/// on the ledger (or a session drain cap).
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_BUDGET_STALLS: AtomicU64 = AtomicU64::new(0);
/// T9: stream `poll_write` suspensions on the queue ledger — counted
/// separately from drain stalls because an upload direction stalls here
/// while downloads stall there; parked writers wake on
/// `release_budget_backpressure`.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_WRITE_STALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_SESSIONS_CURRENT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_PRE_PROXY_CURRENT: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_PRE_PROXY_EVICTED: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_PER_IP_EVICTED: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_PRE_PROXY_REFUSED: AtomicU64 = AtomicU64::new(0);
/// Sessions refused because the TCP queue ledger could not reserve even a
/// minimal socket-buffer pair — capacity is charged, so this is the
/// fail-closed edge of honest accounting, not a silent fallback.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_BUFFER_REFUSED: AtomicU64 = AtomicU64::new(0);
/// T9: successful in-session buffer growth steps (rx or tx) — each one
/// was charged to the queue ledger before the allocation grew.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_BUFFER_GROWTH: AtomicU64 = AtomicU64::new(0);
/// T9: growth attempts refused by the ledger even at the minimum step —
/// the session keeps its current window; this is observable backpressure,
/// not a failure.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_BUFFER_GROW_STALL: AtomicU64 = AtomicU64::new(0);
/// T9: sessions reaped by the budget-stall deadline while still parked on
/// the queue ledger — each one is a zombie whose retransmissions would
/// otherwise have kept `last_activity` fresh forever and pinned its
/// buffer permits permanently.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_STALL_REAPED: AtomicU64 = AtomicU64::new(0);
/// T9: drain-cap parks — the session hit its fair share of drained-but-
/// unconsumed bytes (consumer-bound backpressure, distinct from ledger
/// stalls which mean the account itself was full).
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_CAP_PARKS: AtomicU64 = AtomicU64::new(0);
/// T9: sessions reaped after parking on the drain cap with zero consumer
/// progress for AF_XDP_TCP_CAP_PARK_DEADLINE — a dead reader.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_CAP_REAPED: AtomicU64 = AtomicU64::new(0);
/// T9: idle sessions that returned grown socket buffers to the ledger.
#[cfg(target_os = "linux")]
static AF_XDP_TCP_DIAG_BUFFER_SHRINKS: AtomicU64 = AtomicU64::new(0);

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
    AF_XDP_TCP_DIAG_BUDGET_STALLS.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_WRITE_STALLS.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_SESSIONS_CURRENT.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_PRE_PROXY_CURRENT.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_PRE_PROXY_EVICTED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_PER_IP_EVICTED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_PRE_PROXY_REFUSED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_BUFFER_REFUSED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_BUFFER_GROWTH.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_BUFFER_GROW_STALL.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_STALL_REAPED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_CAP_PARKS.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_CAP_REAPED.store(0, Ordering::Relaxed);
    AF_XDP_TCP_DIAG_BUFFER_SHRINKS.store(0, Ordering::Relaxed);
}

/// Compact scalar-only diag line for periodic journal visibility —
/// per-session rows stay in `tcp_diag_snapshot` for the status endpoint.
#[cfg(target_os = "linux")]
pub fn tcp_diag_scalars() -> serde_json::Value {
    serde_json::json!({
        "sessions": AF_XDP_TCP_DIAG_SESSIONS_CURRENT.load(Ordering::Relaxed),
        "preProxy": AF_XDP_TCP_DIAG_PRE_PROXY_CURRENT.load(Ordering::Relaxed),
        "accepted": AF_XDP_TCP_DIAG_ACCEPTED.load(Ordering::Relaxed),
        "refusedAtCapacity": AF_XDP_TCP_DIAG_REFUSED_AT_CAPACITY.load(Ordering::Relaxed),
        "preProxyTimeout": AF_XDP_TCP_DIAG_PRE_PROXY_TIMEOUT.load(Ordering::Relaxed),
        "preProxyEvicted": AF_XDP_TCP_DIAG_PRE_PROXY_EVICTED.load(Ordering::Relaxed),
        "perIpPreProxyEvicted": AF_XDP_TCP_DIAG_PER_IP_EVICTED.load(Ordering::Relaxed),
        "preProxyRefused": AF_XDP_TCP_DIAG_PRE_PROXY_REFUSED.load(Ordering::Relaxed),
        "bufferRefused": AF_XDP_TCP_DIAG_BUFFER_REFUSED.load(Ordering::Relaxed),
        "bufferGrowth": AF_XDP_TCP_DIAG_BUFFER_GROWTH.load(Ordering::Relaxed),
        "bufferGrowStall": AF_XDP_TCP_DIAG_BUFFER_GROW_STALL.load(Ordering::Relaxed),
        "budgetStallReaped": AF_XDP_TCP_DIAG_STALL_REAPED.load(Ordering::Relaxed),
        "proxyStarted": AF_XDP_TCP_DIAG_PROXY_STARTED.load(Ordering::Relaxed),
        "egressFrames": AF_XDP_TCP_DIAG_EGRESS_FRAMES.load(Ordering::Relaxed),
        "ingressQueueDropped": AF_XDP_TCP_DIAG_INGRESS_QUEUE_DROPPED.load(Ordering::Relaxed),
        "queueBudgetStalls": AF_XDP_TCP_DIAG_BUDGET_STALLS.load(Ordering::Relaxed),
        "writeBudgetStalls": AF_XDP_TCP_DIAG_WRITE_STALLS.load(Ordering::Relaxed),
        "drainCapParks": AF_XDP_TCP_DIAG_CAP_PARKS.load(Ordering::Relaxed),
        "drainCapReaped": AF_XDP_TCP_DIAG_CAP_REAPED.load(Ordering::Relaxed),
        "bufferShrinks": AF_XDP_TCP_DIAG_BUFFER_SHRINKS.load(Ordering::Relaxed),
        "tcpQueueBytes": crate::memory_governor::MEMORY_GOVERNOR.tcp_queue_bytes(),
        "tcpQueueBytesBudget": crate::memory_governor::MEMORY_GOVERNOR.tcp_queue_bytes_budget(),
        "accountGrantable": crate::memory_governor::MEMORY_GOVERNOR.account_view().grantable_bytes,
        "accountUnconfirmed": crate::memory_governor::MEMORY_GOVERNOR.account_view().committed_unconfirmed_bytes,
        "accountRejects": crate::memory_governor::MEMORY_GOVERNOR.account_view().rejects_total,
        // T9: top ledger holders — distinguishes "ledger full from many
        // sessions" vs "one runaway" without the monitor endpoint. Capped
        // at 3 rows; each row is a trimmed copy of the full snapshot.
        "topHeld": tcp_top_held_json(3),
        "topActive": tcp_top_active_json(3),
    })
}

/// T9: compact top-N holder rows for the journal diag line. `heldBytes`
/// sums the per-session ledger-visible residency (socket buffer charge +
/// pending chunks); queue/CC fields let a single row explain *why* the
/// bytes sit (send backlog vs recv backlog vs congestion).
#[cfg(target_os = "linux")]
fn tcp_top_held_json(n: usize) -> serde_json::Value {
    let mut scored: Vec<(u64, serde_json::Value)> = AF_XDP_TCP_SESSION_SNAPSHOTS
        .iter()
        .map(|entry| {
            let row = entry.value();
            // socket occupancy (sendQ/recvQ) lives inside the charged
            // buffer capacity — counting it again would double-book.
            let held = row["socketBufChargeBytes"].as_u64().unwrap_or(0)
                + row["pendingIngressBytes"].as_u64().unwrap_or(0)
                + row["pendingEgressBytes"].as_u64().unwrap_or(0);
            (held, row.clone())
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    serde_json::json!(scored
        .into_iter()
        .take(n)
        .map(|(held, row)| serde_json::json!({
            "peer": row["peer"],
            "local": row["local"],
            "class": row["class"],
            "state": row["state"],
            "heldBytes": held,
            "cwnd": row["cwndBytes"],
            "rttUs": row["minRttMicros"],
            "sendQ": row["sendQueueBytes"],
            "recvQ": row["recvQueueBytes"],
            "pendIn": row["pendingIngressBytes"],
            "pendEg": row["pendingEgressBytes"],
            // EdgeCC observability — why the window/rate sits where it
            // does (mode + reason + model outputs), not just its size.
            "ccMode": row["ccMode"],
            "ccReason": row["reasonCode"],
            "paceBps": row["pacingRateBps"],
            "beliefMilli": row["beliefMilli"],
            "envelopeBytes": row["envelopeBytes"],
            "bwSigmaBps": row["bwSigmaBps"],
        }))
        .collect::<Vec<_>>())
}

/// Throughput-facing view of live sessions: rank by real queue pressure
/// (socket queues + pending chunks) rather than charged capacity, so
/// actively-moving flows don't hide behind idle big-buffered sessions.
#[cfg(target_os = "linux")]
fn tcp_top_active_json(n: usize) -> serde_json::Value {
    let mut scored: Vec<(u64, serde_json::Value)> = AF_XDP_TCP_SESSION_SNAPSHOTS
        .iter()
        .map(|entry| {
            let row = entry.value();
            let active = row["sendQueueBytes"].as_u64().unwrap_or(0)
                + row["recvQueueBytes"].as_u64().unwrap_or(0)
                + row["pendingIngressBytes"].as_u64().unwrap_or(0)
                + row["pendingEgressBytes"].as_u64().unwrap_or(0);
            (active, row.clone())
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    serde_json::json!(scored
        .into_iter()
        .take(n)
        .map(|(active, row)| serde_json::json!({
            "peer": row["peer"],
            "local": row["local"],
            "class": row["class"],
            "state": row["state"],
            "activeBytes": active,
            "cwnd": row["cwndBytes"],
            "rttUs": row["minRttMicros"],
            "sendQ": row["sendQueueBytes"],
            "pendIn": row["pendingIngressBytes"],
            "pendEg": row["pendingEgressBytes"],
            "ccMode": row["ccMode"],
            "ccReason": row["reasonCode"],
            "paceBps": row["pacingRateBps"],
            "remoteWin": row["remoteWinBytes"],
            "unacked": row["unackedBytes"],
            "pipe": row["pipeBytes"],
            "timer": row["timerState"],
        }))
        .collect::<Vec<_>>())
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
        "queueBudgetStalls": AF_XDP_TCP_DIAG_BUDGET_STALLS.load(Ordering::Relaxed),
        "writeBudgetStalls": AF_XDP_TCP_DIAG_WRITE_STALLS.load(Ordering::Relaxed),
        "drainCapParks": AF_XDP_TCP_DIAG_CAP_PARKS.load(Ordering::Relaxed),
        "drainCapReaped": AF_XDP_TCP_DIAG_CAP_REAPED.load(Ordering::Relaxed),
        "bufferShrinks": AF_XDP_TCP_DIAG_BUFFER_SHRINKS.load(Ordering::Relaxed),
        "sessionsCurrent": AF_XDP_TCP_DIAG_SESSIONS_CURRENT.load(Ordering::Relaxed),
        "preProxyCurrent": AF_XDP_TCP_DIAG_PRE_PROXY_CURRENT.load(Ordering::Relaxed),
        "preProxyEvicted": AF_XDP_TCP_DIAG_PRE_PROXY_EVICTED.load(Ordering::Relaxed),
        "perIpPreProxyEvicted": AF_XDP_TCP_DIAG_PER_IP_EVICTED.load(Ordering::Relaxed),
        "preProxyRefused": AF_XDP_TCP_DIAG_PRE_PROXY_REFUSED.load(Ordering::Relaxed),
        "bufferRefused": AF_XDP_TCP_DIAG_BUFFER_REFUSED.load(Ordering::Relaxed),
        "bufferGrowth": AF_XDP_TCP_DIAG_BUFFER_GROWTH.load(Ordering::Relaxed),
        "bufferGrowStall": AF_XDP_TCP_DIAG_BUFFER_GROW_STALL.load(Ordering::Relaxed),
        "budgetStallReaped": AF_XDP_TCP_DIAG_STALL_REAPED.load(Ordering::Relaxed),
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
