use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use moka::sync::Cache;
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock as Lazy;
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, RwLock, mpsc, watch};
use tokio::time::{Instant as TokioInstant, sleep_until};
use tracing::{debug, error, info, warn};

use crate::config::ConfigStore;
use crate::config_models::ServerConfig;
use crate::firewall::state::WafStateManager;
use crate::l4_defense::L4DefenseKind;
use crate::lb_factory::BackendExtension;
use crate::memory_governor::{
    AdmissionClass, MEMORY_GOVERNOR, StaticAdmissionPermit, StaticUdpQueueBytePermit,
};
use crate::net_bind::{UdpBatchReceiver, bind_udp_socket, dual_stack_bind_addrs};

const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_MAX_QUIC_CIDS: usize = 8;
const UDP_UPSTREAM_DRAIN_BUDGET: usize = 32;
const UDP_ERROR_BACKOFF: Duration = Duration::from_millis(1);
const UDP_UPSTREAM_PORT_REUSE_TTL: Duration = Duration::from_secs(120);
const UDP_UPSTREAM_PORT_REUSE_MAX: usize = 65_536;
const UDP_QUEUE_FULL_EVENT_INTERVAL_MS: u64 = 1_000;
pub(crate) const UDP_LISTENER_REMOVE_GRACE: Duration = Duration::from_secs(10);
const UDP_METRICS_FLUSH_BYTES: u64 = 1024 * 1024;
const UDP_METRICS_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const UDP_DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const UDP_DNS_CACHE_CAPACITY: u64 = 4096;
/// Datagrams buffered per (client, port) while its session is being created
/// off the ingress loop. Small on purpose: a client that cannot pace its
/// first packets within a session-establishment window is shed, not queued.
const UDP_PENDING_DATAGRAMS_PER_SESSION: usize = 8;
/// Distinct flows allowed to sit in the creation-pending map at once.
/// Beyond this the ingress reports Full — the same honest backpressure a
/// full session queue produces.
const UDP_PENDING_SESSIONS_MAX: usize = 4096;
/// Concurrent session-creation workers draining the pending map. Session
/// creation awaits DNS/LB/upstream-socket setup, so a burst of new flows
/// must overlap — serializing creations inside the AF_XDP queue loop let
/// the XSK ring overflow (~97% datagram loss at 2000 concurrent new flows,
/// EN-27 follow-up).
const UDP_SESSION_CREATION_WORKERS: usize = 64;

/// Release-validation diagnostics for the AF_XDP UDP ingress path. The
/// proxy-smoke harness runs without the tracing subscriber, so every
/// silent drop site gets a named counter instead — a burst loss must be
/// attributable to pending overflow, session-queue backpressure, or a
/// failed creation, never guesswork.
#[cfg(target_os = "linux")]
mod af_xdp_udp_diag {
    use std::sync::atomic::{AtomicU64, Ordering};

    pub(super) static RECEIVED: AtomicU64 = AtomicU64::new(0);
    pub(super) static PENDING_QUEUED: AtomicU64 = AtomicU64::new(0);
    pub(super) static PENDING_CREATED: AtomicU64 = AtomicU64::new(0);
    pub(super) static PENDING_QUEUE_FULL: AtomicU64 = AtomicU64::new(0);
    pub(super) static PENDING_SESSIONS_FULL: AtomicU64 = AtomicU64::new(0);
    pub(super) static SESSION_SENT: AtomicU64 = AtomicU64::new(0);
    pub(super) static SESSION_FULL: AtomicU64 = AtomicU64::new(0);
    pub(super) static SESSION_CLOSED: AtomicU64 = AtomicU64::new(0);
    pub(super) static NO_ROUTE: AtomicU64 = AtomicU64::new(0);
    pub(super) static BLOCKED: AtomicU64 = AtomicU64::new(0);
    pub(super) static CREATE_OK: AtomicU64 = AtomicU64::new(0);
    pub(super) static CREATE_NONE: AtomicU64 = AtomicU64::new(0);
    pub(super) static CREATE_ERR: AtomicU64 = AtomicU64::new(0);
    pub(super) static REPLAYED: AtomicU64 = AtomicU64::new(0);
    pub(super) static DROPPED_ON_FAIL: AtomicU64 = AtomicU64::new(0);
    // Reply path: backend datagrams the AF_XDP bridge delivered into a
    // dialed socket's ingress channel vs shed on a full channel; session
    // upstream send/recv outcomes; downstream enqueue vs channel-full shed.
    pub(super) static SOCK_INGRESS_DELIVERED: AtomicU64 = AtomicU64::new(0);
    pub(super) static SOCK_INGRESS_SHED: AtomicU64 = AtomicU64::new(0);
    pub(super) static UPSTREAM_TX: AtomicU64 = AtomicU64::new(0);
    pub(super) static UPSTREAM_TX_ERR: AtomicU64 = AtomicU64::new(0);
    pub(super) static UPSTREAM_RX: AtomicU64 = AtomicU64::new(0);
    pub(super) static DOWNSTREAM_ENQ: AtomicU64 = AtomicU64::new(0);
    pub(super) static DOWNSTREAM_SHED: AtomicU64 = AtomicU64::new(0);
    // Downstream drain outcomes on the bridge: produced to the TX ring,
    // parked on the deferred queue (backpressure), or skipped because the
    // L2 route cache lost the peer entry between ingress and reply.
    pub(super) static TX_OK: AtomicU64 = AtomicU64::new(0);
    pub(super) static TX_DEFERRED: AtomicU64 = AtomicU64::new(0);
    pub(super) static TX_NO_ROUTE: AtomicU64 = AtomicU64::new(0);
    // Pipeline latency probes (ms): age of a queued item measured at the
    // moment the next stage consumes it. egressChan = session socket →
    // per-queue reactor request channel → bridge drain; sockIngress =
    // bridge demux → dialed socket channel → session task recv;
    // downstreamChan = session task → downstream channel → bridge drain.
    pub(super) static EGRESS_CHAN_MAX_AGE_MS: AtomicU64 = AtomicU64::new(0);
    pub(super) static EGRESS_CHAN_AGED_500MS: AtomicU64 = AtomicU64::new(0);
    pub(super) static SOCK_INGRESS_MAX_AGE_MS: AtomicU64 = AtomicU64::new(0);
    pub(super) static SOCK_INGRESS_AGED_500MS: AtomicU64 = AtomicU64::new(0);
    pub(super) static DOWNSTREAM_CHAN_MAX_AGE_MS: AtomicU64 = AtomicU64::new(0);
    pub(super) static DOWNSTREAM_CHAN_AGED_500MS: AtomicU64 = AtomicU64::new(0);

    pub(super) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn note_age(max_counter: &AtomicU64, aged_counter: &AtomicU64, age_ms: u64) {
        max_counter.fetch_max(age_ms, Ordering::Relaxed);
        if age_ms >= 500 {
            aged_counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn reset() {
        for c in [
            &RECEIVED,
            &PENDING_QUEUED,
            &PENDING_CREATED,
            &PENDING_QUEUE_FULL,
            &PENDING_SESSIONS_FULL,
            &SESSION_SENT,
            &SESSION_FULL,
            &SESSION_CLOSED,
            &NO_ROUTE,
            &BLOCKED,
            &CREATE_OK,
            &CREATE_NONE,
            &CREATE_ERR,
            &REPLAYED,
            &DROPPED_ON_FAIL,
            &SOCK_INGRESS_DELIVERED,
            &SOCK_INGRESS_SHED,
            &UPSTREAM_TX,
            &UPSTREAM_TX_ERR,
            &UPSTREAM_RX,
            &DOWNSTREAM_ENQ,
            &DOWNSTREAM_SHED,
            &TX_OK,
            &TX_DEFERRED,
            &TX_NO_ROUTE,
            &EGRESS_CHAN_MAX_AGE_MS,
            &EGRESS_CHAN_AGED_500MS,
            &SOCK_INGRESS_MAX_AGE_MS,
            &SOCK_INGRESS_AGED_500MS,
            &DOWNSTREAM_CHAN_MAX_AGE_MS,
            &DOWNSTREAM_CHAN_AGED_500MS,
        ] {
            c.store(0, Ordering::Relaxed);
        }
    }

    pub fn snapshot() -> serde_json::Value {
        serde_json::json!({
            "received": RECEIVED.load(Ordering::Relaxed),
            "pendingQueued": PENDING_QUEUED.load(Ordering::Relaxed),
            "pendingCreated": PENDING_CREATED.load(Ordering::Relaxed),
            "pendingQueueFull": PENDING_QUEUE_FULL.load(Ordering::Relaxed),
            "pendingSessionsFull": PENDING_SESSIONS_FULL.load(Ordering::Relaxed),
            "sessionSent": SESSION_SENT.load(Ordering::Relaxed),
            "sessionFull": SESSION_FULL.load(Ordering::Relaxed),
            "sessionClosed": SESSION_CLOSED.load(Ordering::Relaxed),
            "noRoute": NO_ROUTE.load(Ordering::Relaxed),
            "blocked": BLOCKED.load(Ordering::Relaxed),
            "createOk": CREATE_OK.load(Ordering::Relaxed),
            "createNone": CREATE_NONE.load(Ordering::Relaxed),
            "createErr": CREATE_ERR.load(Ordering::Relaxed),
            "replayed": REPLAYED.load(Ordering::Relaxed),
            "droppedOnFail": DROPPED_ON_FAIL.load(Ordering::Relaxed),
            "sockIngressDelivered": SOCK_INGRESS_DELIVERED.load(Ordering::Relaxed),
            "sockIngressShed": SOCK_INGRESS_SHED.load(Ordering::Relaxed),
            "upstreamTx": UPSTREAM_TX.load(Ordering::Relaxed),
            "upstreamTxErr": UPSTREAM_TX_ERR.load(Ordering::Relaxed),
            "upstreamRx": UPSTREAM_RX.load(Ordering::Relaxed),
            "downstreamEnq": DOWNSTREAM_ENQ.load(Ordering::Relaxed),
            "downstreamShed": DOWNSTREAM_SHED.load(Ordering::Relaxed),
            "txOk": TX_OK.load(Ordering::Relaxed),
            "txDeferred": TX_DEFERRED.load(Ordering::Relaxed),
            "txNoRoute": TX_NO_ROUTE.load(Ordering::Relaxed),
            "egressChanMaxAgeMs": EGRESS_CHAN_MAX_AGE_MS.load(Ordering::Relaxed),
            "egressChanAged500ms": EGRESS_CHAN_AGED_500MS.load(Ordering::Relaxed),
            "sockIngressMaxAgeMs": SOCK_INGRESS_MAX_AGE_MS.load(Ordering::Relaxed),
            "sockIngressAged500ms": SOCK_INGRESS_AGED_500MS.load(Ordering::Relaxed),
            "downstreamChanMaxAgeMs": DOWNSTREAM_CHAN_MAX_AGE_MS.load(Ordering::Relaxed),
            "downstreamChanAged500ms": DOWNSTREAM_CHAN_AGED_500MS.load(Ordering::Relaxed),
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn reset_af_xdp_udp_diag() {
    af_xdp_udp_diag::reset();
}

#[cfg(target_os = "linux")]
pub(crate) fn af_xdp_udp_diag_snapshot() -> serde_json::Value {
    af_xdp_udp_diag::snapshot()
}

/// Reply-path counters the AF_XDP bridge records — the diag module is
/// private to this file, so the bridge bumps through these wrappers.
#[cfg(target_os = "linux")]
pub(crate) fn note_udp_sock_ingress_delivered() {
    af_xdp_udp_diag::bump(&af_xdp_udp_diag::SOCK_INGRESS_DELIVERED);
}

#[cfg(target_os = "linux")]
pub(crate) fn note_udp_sock_ingress_shed() {
    af_xdp_udp_diag::bump(&af_xdp_udp_diag::SOCK_INGRESS_SHED);
}

#[cfg(target_os = "linux")]
pub(crate) fn note_udp_tx_ok() {
    af_xdp_udp_diag::bump(&af_xdp_udp_diag::TX_OK);
}

#[cfg(target_os = "linux")]
pub(crate) fn note_udp_tx_deferred() {
    af_xdp_udp_diag::bump(&af_xdp_udp_diag::TX_DEFERRED);
}

#[cfg(target_os = "linux")]
pub(crate) fn note_udp_tx_no_route() {
    af_xdp_udp_diag::bump(&af_xdp_udp_diag::TX_NO_ROUTE);
}

/// Age probes (enqueue→consume, ms) for the three UDP pipeline channels
/// — the bridge and the dialed socket report through these so a stall
/// localizes to a specific hop instead of blending into end-to-end RTT.
#[cfg(target_os = "linux")]
pub(crate) fn note_udp_egress_chan_age_ms(age_ms: u64) {
    af_xdp_udp_diag::note_age(
        &af_xdp_udp_diag::EGRESS_CHAN_MAX_AGE_MS,
        &af_xdp_udp_diag::EGRESS_CHAN_AGED_500MS,
        age_ms,
    );
}

#[cfg(target_os = "linux")]
pub(crate) fn note_udp_sock_ingress_age_ms(age_ms: u64) {
    af_xdp_udp_diag::note_age(
        &af_xdp_udp_diag::SOCK_INGRESS_MAX_AGE_MS,
        &af_xdp_udp_diag::SOCK_INGRESS_AGED_500MS,
        age_ms,
    );
}

#[cfg(target_os = "linux")]
pub(crate) fn note_udp_downstream_chan_age_ms(age_ms: u64) {
    af_xdp_udp_diag::note_age(
        &af_xdp_udp_diag::DOWNSTREAM_CHAN_MAX_AGE_MS,
        &af_xdp_udp_diag::DOWNSTREAM_CHAN_AGED_500MS,
        age_ms,
    );
}

static UDP_ACTIVITY_EPOCH: Lazy<Instant> = Lazy::new(Instant::now);

pub(crate) fn udp_activity_now_ms() -> u64 {
    UDP_ACTIVITY_EPOCH
        .elapsed()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

pub(crate) fn udp_activity_is_alive(last_activity_ms: &AtomicU64, timeout: Duration) -> bool {
    let last = last_activity_ms.load(Ordering::Relaxed);
    let now = udp_activity_now_ms();
    now.saturating_sub(last) < timeout.as_millis().min(u64::MAX as u128) as u64
}

fn udp_session_idle_remaining(last_activity_ms: u64, now_ms: u64, timeout: Duration) -> Duration {
    let timeout_ms = timeout.as_millis().min(u64::MAX as u128) as u64;
    let elapsed_ms = now_ms.saturating_sub(last_activity_ms);
    Duration::from_millis(timeout_ms.saturating_sub(elapsed_ms))
}

fn udp_session_idle_deadline(last_activity_ms: &AtomicU64, timeout: Duration) -> TokioInstant {
    let remaining = udp_session_idle_remaining(
        last_activity_ms.load(Ordering::Relaxed),
        udp_activity_now_ms(),
        timeout,
    );
    TokioInstant::now() + remaining
}

/// Upstream socket address of a recently closed session, kept briefly so a
/// session recreated for the same `(client_addr, listen_port)` can try to
/// rebind the same upstream port. Protocols that pin server-side state to the
/// upstream 4-tuple then survive session churn transparently.
#[derive(Debug)]
struct RecentUpstreamPort {
    local_addr: SocketAddr,
    recorded_at: Instant,
}

type RecentUpstreamPorts = Arc<DashMap<(SocketAddr, u16), RecentUpstreamPort>>;

fn record_recent_upstream_port(
    registry: &RecentUpstreamPorts,
    client_addr: SocketAddr,
    listen_port: u16,
    local_addr: SocketAddr,
) {
    if local_addr.ip().is_unspecified() && local_addr.port() == 0 {
        return;
    }
    if registry.len() >= UDP_UPSTREAM_PORT_REUSE_MAX {
        return;
    }
    registry.insert(
        (client_addr, listen_port),
        RecentUpstreamPort {
            local_addr,
            recorded_at: Instant::now(),
        },
    );
}

async fn bind_backend_socket(
    preferred: Option<SocketAddr>,
    fallback_addr: &str,
    session_id: u64,
) -> io::Result<UdpSocket> {
    // The preferred bind uses an exclusive bind (no SO_REUSEPORT): if the port
    // was already claimed by another session's wildcard bind, we must fall
    // back instead of silently sharing the port and splitting replies.
    if let Some(addr) = preferred
        && let Ok(socket) = UdpSocket::bind(addr).await
    {
        debug!("UDP session {} reused upstream address {}", session_id, addr);
        return Ok(socket);
    }
    UdpSocket::bind(fallback_addr).await
}

/// T4-6: upstream UDP socket — kernel `UdpSocket` on the default path,
/// node-dialed AF_XDP flow when `xdp.upstream.mode=afxdp`.
enum UpstreamUdpSocket {
    Kernel(UdpSocket),
    #[cfg(target_os = "linux")]
    AfXdp(crate::xdp::af_xdp::AfXdpUdpSocket),
}

impl UpstreamUdpSocket {
    async fn send(&self, data: &[u8]) -> io::Result<usize> {
        match self {
            Self::Kernel(socket) => socket.send(data).await,
            #[cfg(target_os = "linux")]
            Self::AfXdp(socket) => socket.send(data).await,
        }
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Kernel(socket) => socket.recv(buf).await,
            #[cfg(target_os = "linux")]
            Self::AfXdp(socket) => {
                let payload = socket.recv().await?;
                let len = payload.len().min(buf.len());
                buf[..len].copy_from_slice(&payload[..len]);
                Ok(len)
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Kernel(socket) => socket.local_addr(),
            #[cfg(target_os = "linux")]
            Self::AfXdp(socket) => Ok(socket.local_addr()),
        }
    }

    /// True once the transport can never deliver again — kernel sockets
    /// can always recover (transient ICMP), a dead AF_XDP channel cannot.
    fn defunct(&self) -> bool {
        match self {
            Self::Kernel(_) => false,
            #[cfg(target_os = "linux")]
            Self::AfXdp(socket) => socket.defunct(),
        }
    }
}

/// T4-6: establish the upstream UDP socket. AF_XDP mode dials through
/// the dataplane registry (fail-closed — an unavailable registry is an
/// explicit session error); kernel mode is the pre-existing bind+connect.
async fn connect_backend_udp_socket(
    backend_addr: SocketAddr,
    preferred: Option<SocketAddr>,
    fallback_addr: &str,
    session_id: u64,
) -> io::Result<UpstreamUdpSocket> {
    #[cfg(target_os = "linux")]
    {
        // Loopback upstreams can never ride AF_XDP — `lo` has no XSK and
        // no reactor queue. A co-located upstream takes the kernel path
        // explicitly (not a silent fallback for dataplane failures).
        if crate::xdp::afxdp_upstream_selected() && !backend_addr.ip().is_loopback() {
            let socket =
                crate::xdp::af_xdp_dial_udp(backend_addr, preferred.map(|addr| addr.port()))
                    .await?;
            debug!(
                "UDP session {} dialed AF_XDP upstream {} from {}",
                session_id,
                backend_addr,
                socket.local_addr()
            );
            return Ok(UpstreamUdpSocket::AfXdp(socket));
        }
    }
    let socket = bind_backend_socket(preferred, fallback_addr, session_id).await?;
    socket.connect(backend_addr).await?;
    Ok(UpstreamUdpSocket::Kernel(socket))
}

pub(crate) fn udp_session_queue_full_event_due(session: &UdpSession) -> bool {
    let now = udp_activity_now_ms();
    let last = session.queue_full_event_at_ms.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < UDP_QUEUE_FULL_EVENT_INTERVAL_MS {
        return false;
    }
    session
        .queue_full_event_at_ms
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpMetricsFlush {
    downstream: u64,
    upstream: u64,
}

#[derive(Debug)]
struct UdpTransferAccumulator {
    downstream_sent: u64,
    upstream_sent: u64,
    unflushed_downstream: u64,
    unflushed_upstream: u64,
    last_flush: Instant,
}

impl UdpTransferAccumulator {
    fn new(now: Instant) -> Self {
        Self {
            downstream_sent: 0,
            upstream_sent: 0,
            unflushed_downstream: 0,
            unflushed_upstream: 0,
            last_flush: now,
        }
    }

    fn record_downstream(&mut self, bytes: u64) {
        self.downstream_sent = self.downstream_sent.saturating_add(bytes);
        self.unflushed_downstream = self.unflushed_downstream.saturating_add(bytes);
    }

    fn record_upstream(&mut self, bytes: u64) {
        self.upstream_sent = self.upstream_sent.saturating_add(bytes);
        self.unflushed_upstream = self.unflushed_upstream.saturating_add(bytes);
    }

    fn totals(&self) -> (u64, u64) {
        (self.downstream_sent, self.upstream_sent)
    }

    fn pending_bytes(&self) -> u64 {
        self.unflushed_downstream
            .saturating_add(self.unflushed_upstream)
    }

    fn next_flush_after(&self, now: Instant) -> Option<Duration> {
        if self.pending_bytes() == 0 {
            return None;
        }
        Some(UDP_METRICS_FLUSH_INTERVAL.saturating_sub(now.duration_since(self.last_flush)))
    }

    fn take_flush_due(&mut self, now: Instant, force: bool) -> Option<UdpMetricsFlush> {
        let pending = self.pending_bytes();
        if pending == 0 {
            if force {
                self.last_flush = now;
            }
            return None;
        }

        let due = force
            || pending >= UDP_METRICS_FLUSH_BYTES
            || now.duration_since(self.last_flush) >= UDP_METRICS_FLUSH_INTERVAL;
        if !due {
            return None;
        }

        let flush = UdpMetricsFlush {
            downstream: self.unflushed_downstream,
            upstream: self.unflushed_upstream,
        };
        self.unflushed_downstream = 0;
        self.unflushed_upstream = 0;
        self.last_flush = now;
        Some(flush)
    }

    fn flush_if_due(&mut self, server_id: i64, force: bool) {
        let Some(flush) = self.take_flush_due(Instant::now(), force) else {
            return;
        };
        crate::metrics::record::record_transfer(server_id, flush.downstream, flush.upstream, None);
        crate::metrics::record::record_origin_traffic(
            server_id,
            flush.upstream,
            flush.downstream,
            None,
        );
    }
}

#[cfg(test)]
async fn resolve_udp_backend_addr(
    addr: String,
    origin_host: Option<&str>,
    client_ip: IpAddr,
) -> anyhow::Result<SocketAddr> {
    let lookup_addr = origin_host
        .filter(|host| !host.is_empty() && host.parse::<IpAddr>().is_err())
        .and_then(|host| {
            addr.rsplit_once(':')
                .map(|(_, port)| format!("{}:{}", host, port))
        });

    let Some(lookup_addr) = lookup_addr else {
        if let Ok(addr) = addr.parse() {
            return Ok(addr);
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr).await?.collect();
        return addrs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("UDP backend address {} resolved no addresses", addr));
    };

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&lookup_addr).await?.collect();
    addrs
        .iter()
        .copied()
        .find(|addr| addr.is_ipv4() == client_ip.is_ipv4())
        .or_else(|| addrs.first().copied())
        .ok_or_else(|| anyhow::anyhow!("UDP backend address {} resolved no addresses", lookup_addr))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct UdpDnsCacheKey {
    origin_id: i64,
    host: String,
    port: u16,
    prefer_ipv4: bool,
    runtime_reload_generation: u64,
}

type SharedUdpDnsResult = Result<Arc<Vec<SocketAddr>>, Arc<anyhow::Error>>;

struct InflightUdpDnsLookup {
    result: Mutex<Option<SharedUdpDnsResult>>,
    notify: Notify,
}

impl InflightUdpDnsLookup {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            notify: Notify::new(),
        }
    }
}

/// Leader-side cleanup for an in-flight DNS lookup. If the leader future is
/// cancelled mid-lookup (outer timeout, session abort), the inflight entry
/// would stay in the map forever with `result == None` and every follower on
/// the same key would wait indefinitely. Dropping the guard always publishes
/// an outcome, removes the map entry, and wakes the waiters.
struct InflightLeaderGuard<'a> {
    inflight: &'a DashMap<UdpDnsCacheKey, Arc<InflightUdpDnsLookup>>,
    key: &'a UdpDnsCacheKey,
    flight: Arc<InflightUdpDnsLookup>,
}

impl Drop for InflightLeaderGuard<'_> {
    fn drop(&mut self) {
        {
            let mut result = self
                .flight
                .result
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if result.is_none() {
                *result = Some(Err(Arc::new(anyhow::anyhow!(
                    "UDP DNS lookup cancelled before completing"
                ))));
            }
        }
        self.inflight
            .remove_if(self.key, |_, current| Arc::ptr_eq(current, &self.flight));
        self.flight.notify.notify_waiters();
    }
}

struct UdpDnsResolutionCache {
    cache: Cache<UdpDnsCacheKey, Arc<Vec<SocketAddr>>>,
    inflight: DashMap<UdpDnsCacheKey, Arc<InflightUdpDnsLookup>>,
}

impl UdpDnsResolutionCache {
    fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(UDP_DNS_CACHE_CAPACITY)
                .time_to_live(UDP_DNS_CACHE_TTL)
                .build(),
            inflight: DashMap::new(),
        }
    }

    async fn resolve<F, Fut>(
        &self,
        key: UdpDnsCacheKey,
        lookup_addr: String,
        client_ip: IpAddr,
        lookup: F,
    ) -> anyhow::Result<SocketAddr>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = anyhow::Result<Vec<SocketAddr>>>,
    {
        if let Some(addrs) = self.cache.get(&key) {
            return select_udp_backend_addr(&addrs, &lookup_addr, client_ip);
        }

        let (flight, is_leader) = match self.inflight.entry(key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(entry) => (entry.get().clone(), false),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let flight = Arc::new(InflightUdpDnsLookup::new());
                entry.insert(flight.clone());
                (flight, true)
            }
        };

        if is_leader {
            // Held until the result is published; on cancellation it posts a
            // failure, removes the inflight entry, and wakes followers.
            let leader_guard = InflightLeaderGuard {
                inflight: &self.inflight,
                key: &key,
                flight: flight.clone(),
            };
            // Bound a blackholed resolver: getaddrinfo retries can otherwise
            // pin the inflight entry (and every follower) for tens of seconds.
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                lookup(lookup_addr.clone()),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!("UDP backend address {} resolution timed out", lookup_addr)
            })
            .and_then(|outcome| outcome)
            .and_then(|addrs| {
                if addrs.is_empty() {
                    Err(anyhow::anyhow!(
                        "UDP backend address {} resolved no addresses",
                        lookup_addr
                    ))
                } else {
                    Ok(Arc::new(addrs))
                }
            })
            .map_err(Arc::new);
            if let Ok(addrs) = &result {
                self.cache.insert(key.clone(), addrs.clone());
            }
            *flight.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());
            drop(leader_guard);
            match result {
                Ok(addrs) => select_udp_backend_addr(&addrs, &lookup_addr, client_ip),
                Err(err) => Err(anyhow::anyhow!(err.to_string())),
            }
        } else {
            loop {
                if let Some(result) = flight.result.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                    return match result {
                        Ok(addrs) => select_udp_backend_addr(&addrs, &lookup_addr, client_ip),
                        Err(err) => Err(anyhow::anyhow!(err.to_string())),
                    };
                }
                // `notify_waiters` only wakes already-registered waiters, so a
                // result published between the check above and our first poll
                // of `notified()` would sleep forever. Re-check on a bounded
                // interval instead of trusting the wake alone.
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    flight.notify.notified(),
                )
                .await;
            }
        }
    }
}

fn select_udp_backend_addr(
    addrs: &[SocketAddr],
    lookup_addr: &str,
    client_ip: IpAddr,
) -> anyhow::Result<SocketAddr> {
    addrs
        .iter()
        .copied()
        .find(|addr| addr.is_ipv4() == client_ip.is_ipv4())
        .or_else(|| addrs.first().copied())
        .ok_or_else(|| anyhow::anyhow!("UDP backend address {} resolved no addresses", lookup_addr))
}

async fn resolve_udp_backend_addr_cached(
    cache: &UdpDnsResolutionCache,
    origin_id: i64,
    addr: String,
    origin_host: Option<&str>,
    client_ip: IpAddr,
    runtime_reload_generation: u64,
) -> anyhow::Result<SocketAddr> {
    let lookup_host =
        origin_host.filter(|host| !host.is_empty() && host.parse::<IpAddr>().is_err());
    let lookup_addr = lookup_host.and_then(|host| {
        addr.rsplit_once(':')
            .map(|(_, port)| format!("{}:{}", host, port))
    });

    let Some(lookup_addr) = lookup_addr else {
        if let Ok(addr) = addr.parse() {
            return Ok(addr);
        }
        let lookup_addr = addr.clone();
        let key = UdpDnsCacheKey {
            origin_id,
            host: lookup_addr
                .rsplit_once(':')
                .map(|(host, _)| host.trim_matches(['[', ']']).to_string())
                .unwrap_or_else(|| lookup_addr.clone()),
            port: lookup_addr
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse().ok())
                .unwrap_or(0),
            prefer_ipv4: client_ip.is_ipv4(),
            runtime_reload_generation,
        };
        return cache
            .resolve(key, lookup_addr.clone(), client_ip, |lookup_addr| async move {
                Ok(tokio::net::lookup_host(&lookup_addr).await?.collect())
            })
            .await;
    };

    let port = addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid UDP backend address {}", addr))?;
    let key = UdpDnsCacheKey {
        origin_id,
        host: lookup_host.unwrap_or_default().to_string(),
        port,
        prefer_ipv4: client_ip.is_ipv4(),
        runtime_reload_generation,
    };
    cache
        .resolve(
            key,
            lookup_addr.clone(),
            client_ip,
            |lookup_addr| async move { Ok(tokio::net::lookup_host(&lookup_addr).await?.collect()) },
        )
        .await
}

/// Session tracking for UDP sessions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionSendStatus {
    Sent,
    Full,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpIngressDatagramStatus {
    Sent,
    Full,
    Closed,
    NoRoute,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpSessionQuicCid {
    pub session_id: u64,
    pub cid: Vec<u8>,
    pub retired_cid: Option<Vec<u8>>,
}

pub struct UdpSession {
    pub id: u64,
    pub client_addr: Arc<ArcSwap<SocketAddr>>,
    pub listen_port: u16,
    pub backend_addr: SocketAddr,
    pub origin_id: i64,
    pub server_id: i64,
    pub user_id: i64,
    pub user_plan_id: i64,
    pub plan_id: i64,
    pub last_activity_ms: Arc<AtomicU64>,
    pub quic_cids: Arc<RwLock<VecDeque<Vec<u8>>>>,
    // Learned from the backend's long-header SCID. A zero value means unknown.
    pub quic_server_cid_len: Arc<AtomicU8>,
    pub quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
    pub queue_full_event_at_ms: AtomicU64,
    pub tx: mpsc::Sender<QueuedUdpDatagram>,
    pub shutdown_tx: watch::Sender<bool>,
    pub shutdown: watch::Receiver<bool>,
}

#[derive(Clone, Debug)]
pub enum UdpDownstreamSender {
    Socket(Arc<UdpSocket>),
    Channel(Arc<ChannelUdpDownstreamSender>),
}

impl UdpDownstreamSender {
    pub fn socket(socket: Arc<UdpSocket>) -> Self {
        Self::Socket(socket)
    }

    pub fn channel(listen_addr: SocketAddr, tx: mpsc::Sender<DownstreamUdpDatagram>) -> Self {
        Self::Channel(Arc::new(ChannelUdpDownstreamSender { listen_addr, tx }))
    }

    pub(crate) async fn send_to(&self, data: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Socket(socket) => socket.send_to(data, target).await,
            Self::Channel(sender) => sender.try_send_to(data, target),
        }
    }

    pub(crate) fn try_send_to(&self, data: &[u8], target: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Socket(socket) => socket.try_send_to(data, target),
            Self::Channel(sender) => sender.try_send_to(data, target),
        }
    }

    pub(crate) fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Socket(socket) => socket.poll_send_ready(cx),
            Self::Channel(_) => Poll::Ready(Ok(())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownstreamUdpDatagram {
    pub listen_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub payload: Bytes,
    /// Monotonic enqueue timestamp (`udp_activity_now_ms`) — the AF_XDP
    /// bridge reports channel age when it drains the datagram.
    #[cfg(target_os = "linux")]
    pub enqueued_ms: u64,
}

#[derive(Debug)]
pub struct ChannelUdpDownstreamSender {
    listen_addr: SocketAddr,
    tx: mpsc::Sender<DownstreamUdpDatagram>,
}

impl ChannelUdpDownstreamSender {
    fn try_send_to(&self, data: &[u8], target: SocketAddr) -> io::Result<usize> {
        let len = data.len();
        match self.tx.try_send(DownstreamUdpDatagram {
            listen_addr: self.listen_addr,
            peer_addr: target,
            payload: Bytes::copy_from_slice(data),
            #[cfg(target_os = "linux")]
            enqueued_ms: udp_activity_now_ms(),
        }) {
            Ok(()) => Ok(len),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "UDP downstream channel is full",
            )),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "UDP downstream channel is closed",
            )),
        }
    }
}

fn udp_socket_downstream(socket: Arc<UdpSocket>) -> UdpDownstreamSender {
    UdpDownstreamSender::socket(socket)
}

pub struct QueuedUdpDatagram {
    data: Bytes,
    _byte_permit: StaticUdpQueueBytePermit,
}

impl QueuedUdpDatagram {
    fn new(data: Bytes) -> Option<Self> {
        MEMORY_GOVERNOR
            .try_reserve_udp_queue_bytes(data.len())
            .map(|permit| Self {
                data,
                _byte_permit: permit,
            })
    }

    pub fn as_deref(&self) -> Option<&[u8]> {
        Some(&self.data)
    }
}

struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
    listener_id: u64,
    generation: u64,
}

/// Datagrams buffered while a (client, port) session is created by a
/// worker task instead of inline on the caller's ingress path. The
/// resolved server is kept so the worker does not re-run route lookup.
struct PendingUdpSession {
    server: Arc<crate::config_models::ServerConfig>,
    queue: VecDeque<QueuedUdpDatagram>,
    downstream_sender: UdpDownstreamSender,
    shutdown_rx: watch::Receiver<bool>,
}

pub struct UdpProxyManager {
    config_store: ConfigStore,
    waf_state: Arc<WafStateManager>,
    node_id: i64,
    dns_cache: Arc<UdpDnsResolutionCache>,
    /// (ClientAddr, ListenPort) -> Session
    sessions: Arc<DashMap<(SocketAddr, u16), Arc<UdpSession>>>,
    inflight_sessions: Arc<DashMap<(SocketAddr, u16), Arc<InflightUdpSession>>>,
    /// (ClientAddr, ListenPort) -> datagrams waiting on an in-flight
    /// session creation. Checked before `sessions` on every ingress so
    /// ordering is preserved across the async handoff.
    pending_sessions: DashMap<(SocketAddr, u16), PendingUdpSession>,
    /// `DashMap::len()` read-locks every shard — calling it while holding
    /// an `entry()` write guard self-deadlocks, so the pending count is
    /// tracked separately for the admission cap.
    pending_sessions_count: AtomicUsize,
    creation_queue_tx: mpsc::UnboundedSender<(SocketAddr, u16)>,
    creation_queue_rx: Mutex<Option<mpsc::UnboundedReceiver<(SocketAddr, u16)>>>,
    /// (ClientAddr, ListenPort) -> last upstream socket address, kept briefly
    /// so a recreated session can try to keep the same upstream port.
    recent_upstream_ports: RecentUpstreamPorts,
    /// Bind addresses that disappeared from the desired listener set, first
    /// observed missing at this instant. Listeners are only torn down after
    /// the grace period so a transient config absence does not kill sessions.
    undesired_since: DashMap<SocketAddr, Instant>,
    #[cfg(test)]
    session_creation_attempts: AtomicU64,
    handled_ports: DashMap<SocketAddr, ListenerHandle>,
    next_listener_id: AtomicU64,
    next_listener_generation: AtomicU64,
    next_session_id: AtomicU64,
    /// Process runtime for session relay and creation workers. AF_XDP
    /// ingress calls run inside per-queue pinned single-thread reactor
    /// runtimes — spawning session work there multiplexes it with the
    /// dataplane loop, which only grants spawned tasks one yield slot
    /// per busy round (observed live: reply datagrams parking ~700ms in
    /// the dialed-socket channel while the queue thread is saturated).
    /// TCP session work already follows this split via `proxy_rt`; UDP
    /// must match so the reactor thread keeps dataplane cadence.
    session_rt: Option<tokio::runtime::Handle>,
}

type SharedUdpCreationResult = Result<Option<Arc<UdpSession>>, Arc<anyhow::Error>>;

struct InflightUdpSession {
    result: Mutex<Option<SharedUdpCreationResult>>,
    notify: Notify,
}

struct InflightUdpSessionGuard<'a> {
    manager: &'a UdpProxyManager,
    key: (SocketAddr, u16),
    flight: Arc<InflightUdpSession>,
}

impl Drop for InflightUdpSessionGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut result) = self.flight.result.lock()
            && result.is_none()
        {
            *result = Some(Err(Arc::new(anyhow::anyhow!(
                "UDP session creation cancelled"
            ))));
        }
        self.manager
            .inflight_sessions
            .remove_if(&self.key, |_, current| Arc::ptr_eq(current, &self.flight));
        self.flight.notify.notify_waiters();
    }
}

impl InflightUdpSession {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            notify: Notify::new(),
        }
    }
}

pub(crate) struct UdpPassthroughSessionArgs {
    pub client_addr: SocketAddr,
    pub port: u16,
    pub server: Arc<ServerConfig>,
    pub probed_server_name: Option<String>,
    pub downstream_sender: UdpDownstreamSender,
    pub shutdown_rx: watch::Receiver<bool>,
    pub quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
}

struct UdpHandleSessionArgs {
    session_id: u64,
    backend_addr: SocketAddr,
    _listen_port: u16,
    listener_shutdown_rx: watch::Receiver<bool>,
    session_shutdown_rx: watch::Receiver<bool>,
    server_id: i64,
    origin_id: i64,
    client_addr: Arc<ArcSwap<SocketAddr>>,
    domain: String,
    last_activity_ms: Arc<AtomicU64>,
    quic_cids: Arc<RwLock<VecDeque<Vec<u8>>>>,
    quic_server_cid_len: Arc<AtomicU8>,
    quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
    downstream_sender: UdpDownstreamSender,
    rx: mpsc::Receiver<QueuedUdpDatagram>,
    metrics_guard: crate::metrics::ActiveRequestMetricsGuard,
    recent_upstream_ports: RecentUpstreamPorts,
    preferred_backend_bind: Option<SocketAddr>,
}

impl UdpProxyManager {
    pub fn new(
        config_store: ConfigStore,
        waf_state: Arc<WafStateManager>,
        node_id: i64,
    ) -> Arc<Self> {
        let (creation_queue_tx, creation_queue_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            config_store,
            waf_state,
            node_id,
            dns_cache: Arc::new(UdpDnsResolutionCache::new()),
            sessions: Arc::new(DashMap::new()),
            inflight_sessions: Arc::new(DashMap::new()),
            pending_sessions: DashMap::new(),
            pending_sessions_count: AtomicUsize::new(0),
            creation_queue_tx,
            creation_queue_rx: Mutex::new(Some(creation_queue_rx)),
            recent_upstream_ports: Arc::new(DashMap::new()),
            undesired_since: DashMap::new(),
            #[cfg(test)]
            session_creation_attempts: AtomicU64::new(0),
            handled_ports: DashMap::new(),
            next_listener_id: AtomicU64::new(1),
            next_listener_generation: AtomicU64::new(1),
            next_session_id: AtomicU64::new(1),
            session_rt: tokio::runtime::Handle::try_current().ok(),
        })
    }

    /// Spawns UDP session/creation work on the process runtime captured
    /// at construction, falling back to `tokio::spawn` when the manager
    /// was built outside a runtime context (unit tests).
    fn spawn_session_work<F>(&self, fut: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match &self.session_rt {
            Some(rt) => rt.spawn(fut),
            None => tokio::spawn(fut),
        }
    }

    pub async fn start_listeners(self: Arc<Self>) {
        debug!(
            "Starting UDP Proxy Manager for v{}...",
            env!("CARGO_PKG_VERSION")
        );

        loop {
            let desired_ports = self.desired_ports().await;
            self.sync_listeners_for_ports(&desired_ports).await;

            // Re-check config every minute or on notification
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    pub async fn sync_listeners_for_ports(self: &Arc<Self>, desired_ports: &HashSet<u16>) {
        let desired_listeners = desired_ports
            .iter()
            .flat_map(|port| dual_stack_bind_addrs(*port))
            .collect::<HashSet<_>>();

        self.reconcile_listeners(&desired_listeners);
        for bind_addr in &desired_listeners {
            self.spawn_listener(*bind_addr).await;
        }
        self.cleanup_idle_sessions(UDP_SESSION_IDLE_TIMEOUT);
    }

    pub async fn desired_ports(&self) -> HashSet<u16> {
        let servers = self.config_store.get_all_servers().await;
        debug!(
            "UDP Proxy Manager: Found {} servers in config store",
            servers.len()
        );
        let mut desired_ports = HashSet::new();
        for server in servers {
            let mut server_ports = Vec::new();
            if let Some(udp_cfg) = &server.udp {
                if udp_cfg.is_on {
                    if udp_cfg.listen.is_empty() {
                        warn!(
                            "UDP Proxy Manager: Server {} has UDP ON but NO listen addresses",
                            server.numeric_id()
                        );
                    }
                    server_ports.extend(
                        udp_cfg
                            .listen
                            .iter()
                            .filter_map(|addr| addr.port_range.as_deref())
                            .flat_map(crate::config_models::ports_in_range),
                    );
                } else {
                    debug!(
                        "UDP Proxy Manager: Server {} UDP is OFF",
                        server.numeric_id()
                    );
                }
            } else {
                debug!(
                    "UDP Proxy Manager: Server {} has NO UDP config",
                    server.numeric_id()
                );
            }
            if server.is_quic_passthrough()
                && let Some(https) = &server.https
                && https.is_on
            {
                server_ports.extend(
                    https
                        .listen
                        .iter()
                        .filter_map(|addr| addr.port_range.as_deref())
                        .flat_map(crate::config_models::ports_in_range),
                );
            }
            desired_ports.extend(server_ports);
        }
        desired_ports
    }

    async fn spawn_listener(self: &Arc<Self>, bind_addr: SocketAddr) {
        if self.handled_ports.contains_key(&bind_addr) {
            return;
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener_id = self.next_listener_id.fetch_add(1, Ordering::Relaxed);
        let generation = self
            .next_listener_generation
            .fetch_add(1, Ordering::Relaxed);
        self.handled_ports.insert(
            bind_addr,
            ListenerHandle {
                shutdown_tx,
                listener_id,
                generation,
            },
        );

        let worker_count = MEMORY_GOVERNOR.udp_direct_worker_count();
        for worker_id in 0..worker_count {
            let manager = self.clone();
            let worker_shutdown_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = manager
                    .clone()
                    .run_listener(bind_addr, worker_shutdown_rx)
                    .await
                {
                    error!(
                        "UDP listener on {} worker {} failed: {}",
                        bind_addr, worker_id, e
                    );
                    manager.handled_ports.remove_if(&bind_addr, |_, handle| {
                        handle.listener_id == listener_id && handle.generation == generation
                    });
                }
            });
        }
    }

    fn reconcile_listeners(&self, desired_listeners: &std::collections::HashSet<SocketAddr>) {
        let active_listeners: Vec<SocketAddr> = self
            .handled_ports
            .iter()
            .map(|entry| *entry.key())
            .collect();
        for bind_addr in active_listeners {
            if desired_listeners.contains(&bind_addr) {
                self.undesired_since.remove(&bind_addr);
                continue;
            }
            // Keep the listener alive for a grace period when the port
            // disappears from the desired set: a transient config snapshot
            // must not kill the listener and every session on it.
            let first_missing = *self
                .undesired_since
                .entry(bind_addr)
                .or_insert_with(Instant::now);
            if first_missing.elapsed() < UDP_LISTENER_REMOVE_GRACE {
                continue;
            }
            self.undesired_since.remove(&bind_addr);
            if let Some((_, handle)) = self.handled_ports.remove(&bind_addr) {
                info!("UDP Proxy Manager: Stopping listener on {}", bind_addr);
                let _ = handle.shutdown_tx.send(true);
            }
            self.remove_sessions_for_port(bind_addr.port());
        }
    }

    async fn run_listener(
        self: Arc<Self>,
        bind_addr: SocketAddr,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let port = bind_addr.port();
        let listen_socket = Arc::new(bind_udp_socket(bind_addr).await?);
        let downstream_sender = udp_socket_downstream(listen_socket.clone());
        #[cfg(target_os = "linux")]
        if let Err(err) = crate::net_bind::enable_udp_rxq_overflow(&listen_socket) {
            warn!(
                "UDP listener on {} could not enable kernel RX overflow accounting: {}",
                bind_addr, err
            );
        }
        let mut receiver = UdpBatchReceiver::new(listen_socket);
        info!("UDP Proxy worker listening on {}", bind_addr);

        #[cfg(target_os = "linux")]
        let mut last_rxq_overflow = 0u32;
        loop {
            let datagrams = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("UDP listener on port {} shutting down", port);
                    return Ok(());
                }
                res = receiver.recv_batch() => res?,
            };

            for datagram in datagrams {
                #[cfg(target_os = "linux")]
                if let Some(rxq_overflow) = datagram.rxq_overflow
                    && rxq_overflow > last_rxq_overflow
                {
                    warn!(
                        "UDP listener on {} observed {} kernel RX queue drops",
                        bind_addr,
                        rxq_overflow.saturating_sub(last_rxq_overflow)
                    );
                    last_rxq_overflow = rxq_overflow;
                }
                match self
                    .receive_datagram_with_downstream(
                        datagram.peer_addr,
                        port,
                        datagram.payload,
                        downstream_sender.clone(),
                        shutdown_rx.clone(),
                    )
                    .await
                {
                    Ok(UdpIngressDatagramStatus::Sent)
                    | Ok(UdpIngressDatagramStatus::Blocked)
                    | Ok(UdpIngressDatagramStatus::NoRoute) => {}
                    Ok(UdpIngressDatagramStatus::Full) => {
                        debug!(
                            "UDP session {} buffer full, dropping packet",
                            datagram.peer_addr
                        );
                    }
                    Ok(UdpIngressDatagramStatus::Closed) => {
                        debug!("UDP session {} closed, dropping packet", datagram.peer_addr);
                    }
                    Err(err) => {
                        debug!(
                            "UDP session creation failed for {} on port {}: {}",
                            datagram.peer_addr, port, err
                        );
                    }
                }
            }
        }
    }

    pub async fn receive_datagram_with_downstream(
        self: &Arc<Self>,
        client_addr: SocketAddr,
        port: u16,
        data: Bytes,
        downstream_sender: UdpDownstreamSender,
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<UdpIngressDatagramStatus> {
        #[cfg(target_os = "linux")]
        af_xdp_udp_diag::bump(&af_xdp_udp_diag::RECEIVED);
        if crate::l4_defense::is_l4_blocked(&self.config_store, &self.waf_state, client_addr.ip()) {
            #[cfg(target_os = "linux")]
            af_xdp_udp_diag::bump(&af_xdp_udp_diag::BLOCKED);
            return Ok(UdpIngressDatagramStatus::Blocked);
        }

        let key = (client_addr, port);
        // Pending entries are checked before `sessions`: a datagram that
        // arrives while a worker drains the queue must join the queue so
        // per-flow ordering survives the async creation handoff. DashMap
        // guards are never held across an await.
        if let dashmap::mapref::entry::Entry::Occupied(mut entry) = self.pending_sessions.entry(key)
        {
            if entry.get().queue.len() >= UDP_PENDING_DATAGRAMS_PER_SESSION {
                #[cfg(target_os = "linux")]
                af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_QUEUE_FULL);
                return Ok(UdpIngressDatagramStatus::Full);
            }
            let Some(item) = QueuedUdpDatagram::new(data) else {
                #[cfg(target_os = "linux")]
                af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_QUEUE_FULL);
                return Ok(UdpIngressDatagramStatus::Full);
            };
            entry.get_mut().queue.push_back(item);
            #[cfg(target_os = "linux")]
            af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_QUEUED);
            return Ok(UdpIngressDatagramStatus::Sent);
        }
        let session = match self.sessions.get(&key) {
            Some(session) => session.clone(),
            None => {
                // Route lookup is synchronous lookups under the hood —
                // unroutable datagrams still get an honest NoRoute rather
                // than vanishing into the pending queue.
                let Some(server) = self.find_server_for_packet(port, &data).await else {
                    #[cfg(target_os = "linux")]
                    af_xdp_udp_diag::bump(&af_xdp_udp_diag::NO_ROUTE);
                    return Ok(UdpIngressDatagramStatus::NoRoute);
                };
                // Another datagram may have opened the pending entry while
                // the route lookup ran — re-enter to keep queue order.
                match self.pending_sessions.entry(key) {
                    dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                        if entry.get().queue.len() >= UDP_PENDING_DATAGRAMS_PER_SESSION {
                            #[cfg(target_os = "linux")]
                            af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_QUEUE_FULL);
                            return Ok(UdpIngressDatagramStatus::Full);
                        }
                        let Some(item) = QueuedUdpDatagram::new(data) else {
                            #[cfg(target_os = "linux")]
                            af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_QUEUE_FULL);
                            return Ok(UdpIngressDatagramStatus::Full);
                        };
                        entry.get_mut().queue.push_back(item);
                        #[cfg(target_os = "linux")]
                        af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_QUEUED);
                        return Ok(UdpIngressDatagramStatus::Sent);
                    }
                    dashmap::mapref::entry::Entry::Vacant(entry) => {
                        if self.pending_sessions_count.load(Ordering::Acquire)
                            >= UDP_PENDING_SESSIONS_MAX
                        {
                            #[cfg(target_os = "linux")]
                            af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_SESSIONS_FULL);
                            return Ok(UdpIngressDatagramStatus::Full);
                        }
                        let Some(item) = QueuedUdpDatagram::new(data) else {
                            #[cfg(target_os = "linux")]
                            af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_QUEUE_FULL);
                            return Ok(UdpIngressDatagramStatus::Full);
                        };
                        entry.insert(PendingUdpSession {
                            server,
                            queue: VecDeque::from([item]),
                            downstream_sender,
                            shutdown_rx,
                        });
                        self.pending_sessions_count.fetch_add(1, Ordering::AcqRel);
                        #[cfg(target_os = "linux")]
                        af_xdp_udp_diag::bump(&af_xdp_udp_diag::PENDING_CREATED);
                        self.ensure_creation_workers();
                        let _ = self.creation_queue_tx.send(key);
                        return Ok(UdpIngressDatagramStatus::Sent);
                    }
                }
            }
        };

        match Self::send_to_session_from_client(&session, client_addr, data).await {
            UdpSessionSendStatus::Sent => {
                #[cfg(target_os = "linux")]
                af_xdp_udp_diag::bump(&af_xdp_udp_diag::SESSION_SENT);
                Ok(UdpIngressDatagramStatus::Sent)
            }
            UdpSessionSendStatus::Full => {
                // Throttle defense accounting: a busy but legitimate session
                // can drop many datagrams per second and must not look like a
                // per-packet flood.
                if udp_session_queue_full_event_due(&session) {
                    self.record_l4_event(
                        client_addr.ip(),
                        L4DefenseKind::UdpQueueFull,
                        format!("port={} peer={} session={}", port, client_addr, session.id),
                    );
                }
                #[cfg(target_os = "linux")]
                af_xdp_udp_diag::bump(&af_xdp_udp_diag::SESSION_FULL);
                Ok(UdpIngressDatagramStatus::Full)
            }
            UdpSessionSendStatus::Closed => {
                self.sessions
                    .remove_if(&key, |_, existing| existing.id == session.id);
                #[cfg(target_os = "linux")]
                af_xdp_udp_diag::bump(&af_xdp_udp_diag::SESSION_CLOSED);
                Ok(UdpIngressDatagramStatus::Closed)
            }
        }
    }

    /// Lazily spawns the session-creation worker pool on the first pending
    /// datagram. `new` is callable outside a runtime (tests), so workers
    /// are not spawned at construction.
    fn ensure_creation_workers(self: &Arc<Self>) {
        let rx = self
            .creation_queue_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(rx) = rx else { return };
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        for _ in 0..UDP_SESSION_CREATION_WORKERS {
            let this = Arc::clone(self);
            let rx = rx.clone();
            self.spawn_session_work(async move {
                loop {
                    let key = rx.lock().await.recv().await;
                    let Some(key) = key else { return };
                    this.run_pending_session_creation(key).await;
                }
            });
        }
    }

    /// Removes a pending entry and releases its admission count. Every
    /// pending-map removal must go through here to keep the counter honest.
    fn remove_pending_session(&self, key: &(SocketAddr, u16)) {
        if self.pending_sessions.remove(key).is_some() {
            self.pending_sessions_count.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Runs one pending session creation, then replays the queued
    /// datagrams in order. The pending entry is removed only when its
    /// queue is observed empty under the shard lock, so datagrams that
    /// arrive during the drain still land behind the earlier ones.
    async fn run_pending_session_creation(self: &Arc<Self>, key: (SocketAddr, u16)) {
        let (client_addr, port) = key;
        let Some((server, sender, shutdown_rx)) = self.pending_sessions.get(&key).map(|p| {
            (
                p.server.clone(),
                p.downstream_sender.clone(),
                p.shutdown_rx.clone(),
            )
        }) else {
            return;
        };
        let session = match self
            .create_passthrough_session_for_server_with_downstream(
                client_addr,
                port,
                server,
                None,
                sender,
                shutdown_rx,
            )
            .await
        {
            Ok(session) => session,
            Err(err) => {
                debug!(
                    "async UDP session creation for {} on port {} failed: {}",
                    client_addr, port, err
                );
                #[cfg(target_os = "linux")]
                {
                    af_xdp_udp_diag::bump(&af_xdp_udp_diag::CREATE_ERR);
                    if let Some(entry) = self.pending_sessions.get(&key) {
                        for _ in 0..entry.queue.len() {
                            af_xdp_udp_diag::bump(&af_xdp_udp_diag::DROPPED_ON_FAIL);
                        }
                    }
                }
                self.remove_pending_session(&key);
                return;
            }
        };
        #[cfg(target_os = "linux")]
        if session.is_none() {
            af_xdp_udp_diag::bump(&af_xdp_udp_diag::CREATE_NONE);
            if let Some(entry) = self.pending_sessions.get(&key) {
                for _ in 0..entry.queue.len() {
                    af_xdp_udp_diag::bump(&af_xdp_udp_diag::DROPPED_ON_FAIL);
                }
            }
        } else {
            af_xdp_udp_diag::bump(&af_xdp_udp_diag::CREATE_OK);
        }
        loop {
            let batch = match self.pending_sessions.entry(key) {
                dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                    if entry.get().queue.is_empty() {
                        entry.remove();
                        self.pending_sessions_count.fetch_sub(1, Ordering::AcqRel);
                        None
                    } else {
                        Some(std::mem::take(&mut entry.get_mut().queue))
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(_) => None,
            };
            let Some(queue) = batch else { break };
            let Some(session) = session.as_ref() else {
                break;
            };
            for item in queue {
                #[cfg(target_os = "linux")]
                af_xdp_udp_diag::bump(&af_xdp_udp_diag::REPLAYED);
                let status =
                    Self::send_to_session_from_client(session, client_addr, item.data).await;
                if matches!(status, UdpSessionSendStatus::Closed) {
                    self.sessions
                        .remove_if(&key, |_, existing| existing.id == session.id);
                    self.remove_pending_session(&key);
                    return;
                }
            }
        }
        if session.is_none() {
            self.remove_pending_session(&key);
        }
    }

    pub async fn receive_af_xdp_datagram(
        self: &Arc<Self>,
        datagram: crate::xdp::af_xdp::AfXdpDatagram,
        downstream_tx: mpsc::Sender<DownstreamUdpDatagram>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<UdpIngressDatagramStatus> {
        self.receive_datagram_with_downstream(
            datagram.peer_addr,
            datagram.listen_addr.port(),
            datagram.payload,
            UdpDownstreamSender::channel(datagram.listen_addr, downstream_tx),
            shutdown_rx,
        )
        .await
    }

    pub async fn create_passthrough_session(
        &self,
        client_addr: SocketAddr,
        port: u16,
        data: &[u8],
        listen_socket: Arc<UdpSocket>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<Option<Arc<UdpSession>>> {
        self.create_passthrough_session_with_downstream(
            client_addr,
            port,
            data,
            udp_socket_downstream(listen_socket),
            shutdown_rx,
        )
        .await
    }

    pub async fn create_passthrough_session_with_downstream(
        &self,
        client_addr: SocketAddr,
        port: u16,
        data: &[u8],
        downstream_sender: UdpDownstreamSender,
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<Option<Arc<UdpSession>>> {
        let key = (client_addr, port);
        if let Some(session) = self.sessions.get(&key) {
            return Ok(Some(session.clone()));
        }
        let server = match self.find_server_for_packet(port, data).await {
            Some(s) => s,
            None => return Ok(None),
        };
        self.create_passthrough_session_for_server_with_downstream(
            client_addr,
            port,
            server,
            None,
            downstream_sender,
            shutdown_rx,
        )
        .await
    }

    pub async fn create_passthrough_session_for_server(
        &self,
        client_addr: SocketAddr,
        port: u16,
        server: Arc<ServerConfig>,
        probed_server_name: Option<String>,
        listen_socket: Arc<UdpSocket>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<Option<Arc<UdpSession>>> {
        self.create_passthrough_session_for_server_with_downstream(
            client_addr,
            port,
            server,
            probed_server_name,
            udp_socket_downstream(listen_socket),
            shutdown_rx,
        )
        .await
    }

    pub async fn create_passthrough_session_for_server_with_downstream(
        &self,
        client_addr: SocketAddr,
        port: u16,
        server: Arc<ServerConfig>,
        probed_server_name: Option<String>,
        downstream_sender: UdpDownstreamSender,
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<Option<Arc<UdpSession>>> {
        self.create_passthrough_session_for_server_with_cid_updates_and_downstream(
            UdpPassthroughSessionArgs {
                client_addr,
                port,
                server,
                probed_server_name,
                downstream_sender,
                shutdown_rx,
                quic_cid_tx: None,
            },
        )
        .await
    }

    pub(crate) async fn create_passthrough_session_for_server_with_cid_updates_and_downstream(
        &self,
        args: UdpPassthroughSessionArgs,
    ) -> anyhow::Result<Option<Arc<UdpSession>>> {
        let UdpPassthroughSessionArgs {
            client_addr,
            port,
            server,
            probed_server_name,
            downstream_sender,
            shutdown_rx,
            quic_cid_tx,
        } = args;
        let key = (client_addr, port);
        if let Some(session) = self.sessions.get(&key) {
            return Ok(Some(session.clone()));
        }
        let (flight, is_creator) = match self.inflight_sessions.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(entry) => (entry.get().clone(), false),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let flight = Arc::new(InflightUdpSession::new());
                entry.insert(flight.clone());
                (flight, true)
            }
        };
        if !is_creator {
            loop {
                let notified = flight.notify.notified();
                if let Some(result) = flight.result.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                    return result.map_err(|err| anyhow::anyhow!(err.to_string()));
                }
                notified.await;
            }
        }
        let _flight_guard = InflightUdpSessionGuard {
            manager: self,
            key,
            flight: flight.clone(),
        };
        #[cfg(test)]
        self.session_creation_attempts
            .fetch_add(1, Ordering::Relaxed);
        #[cfg(test)]
        tokio::task::yield_now().await;
        let result = self
            .create_passthrough_session_for_server_impl(UdpPassthroughSessionArgs {
                client_addr,
                port,
                server,
                probed_server_name,
                downstream_sender,
                shutdown_rx,
                quic_cid_tx,
            })
            .await
            .map_err(Arc::new);
        *flight.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(result.clone());
        flight.notify.notify_waiters();
        result.map_err(|err| anyhow::anyhow!(err.to_string()))
    }

    async fn create_passthrough_session_for_server_impl(
        &self,
        args: UdpPassthroughSessionArgs,
    ) -> anyhow::Result<Option<Arc<UdpSession>>> {
        let UdpPassthroughSessionArgs {
            client_addr,
            port,
            server,
            probed_server_name,
            downstream_sender,
            shutdown_rx,
            quic_cid_tx,
        } = args;
        let key = (client_addr, port);
        if crate::l4_defense::is_l4_blocked(&self.config_store, &self.waf_state, client_addr.ip()) {
            return Ok(None);
        }
        if server.has_valid_traffic_limit() {
            debug!(
                "UDP server {} is traffic-limited for client {}",
                server.numeric_id(),
                client_addr
            );
            return Ok(None);
        }
        if matches!(
            self.record_l4_event(
                client_addr.ip(),
                L4DefenseKind::UdpSessionFlood,
                format!(
                    "port={} peer={} server={} quic_cid_route={}",
                    port,
                    client_addr,
                    server.numeric_id(),
                    quic_cid_tx.is_some()
                ),
            ),
            crate::l4_defense::L4DefenseVerdict::Blocked
                | crate::l4_defense::L4DefenseVerdict::AggregateDropped
                | crate::l4_defense::L4DefenseVerdict::AlreadyBlocked
        ) {
            return Ok(None);
        }
        let Some(session_permit): Option<StaticAdmissionPermit> =
            MEMORY_GOVERNOR.try_admit(AdmissionClass::UdpSession)
        else {
            self.record_l4_event(
                client_addr.ip(),
                L4DefenseKind::UdpAdmissionReject,
                format!(
                    "port={} peer={} server={}",
                    port,
                    client_addr,
                    server.numeric_id()
                ),
            );
            debug!(
                "UDP session admission limit reached for client {} on port {}",
                client_addr, port
            );
            return Ok(None);
        };

        // EN-16: listener-pool slot for unattributed UDP sessions.
        let listener_key =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port);
        let Some(listener_permit) =
            MEMORY_GOVERNOR.try_admit_listener(listener_key, AdmissionClass::UdpSession)
        else {
            self.record_l4_event(
                client_addr.ip(),
                L4DefenseKind::UdpAdmissionReject,
                format!(
                    "port={} peer={} server={} phase=listener_pool",
                    port,
                    client_addr,
                    server.numeric_id()
                ),
            );
            return Ok(None);
        };
        let sid = server.id.unwrap_or(0);
        let user_id = server.user_id;
        let user_plan_id = server.user_plan_id;
        let plan_id = if user_plan_id > 0 {
            self.config_store
                .get_user_plan_sync(user_plan_id)
                .map(|user_plan| user_plan.plan_id)
                .unwrap_or(0)
        } else {
            0
        };
        let domain = probed_server_name.unwrap_or_else(|| {
            server
                .get_plain_server_names()
                .first()
                .cloned()
                .unwrap_or_default()
        });
        let lb = match self.config_store.get_lb_by_id(sid).await {
            Some(lb) => lb,
            None => {
                return Err(anyhow::anyhow!(
                    "No load balancer found for server id {}",
                    sid
                ));
            }
        };
        let peer = match lb.select_with_backup(b"", 16, |origin_id| {
            crate::origin_state::ORIGIN_STATE_MANAGER.is_down(origin_id)
        }) {
            Some(peer) => peer,
            None => {
                return Err(anyhow::anyhow!(
                    "No healthy backends for UDP server {}",
                    sid
                ));
            }
        };
        let origin_id = crate::lb_factory::peer_origin_id(&peer);
        let origin_host = peer
            .ext
            .get::<BackendExtension>()
            .map(|ext| ext.origin_host.as_str());
        let b_addr = resolve_udp_backend_addr_cached(
            &self.dns_cache,
            origin_id,
            peer.addr.to_string(),
            origin_host,
            client_addr.ip(),
            self.config_store.runtime_reload_generation(),
        )
        .await?;

        debug!(
            "Created new UDP session: {} -> {} (Server {})",
            client_addr, b_addr, sid
        );
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let queue_size = MEMORY_GOVERNOR.udp_session_queue_size();
        let (tx, rx) = mpsc::channel(queue_size);
        let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);
        let session = Arc::new(UdpSession {
            id: session_id,
            client_addr: Arc::new(ArcSwap::from_pointee(client_addr)),
            listen_port: port,
            backend_addr: b_addr,
            origin_id,
            server_id: sid,
            user_id,
            user_plan_id,
            plan_id,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: quic_cid_tx.clone(),
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx: session_shutdown_tx,
            shutdown: session_shutdown_rx.clone(),
        });

        let client_ip = client_addr.ip().to_string();
        let metrics = crate::metrics::record::get_or_create(sid);
        let metrics_guard = crate::metrics::ActiveRequestMetricsGuard::new(metrics.clone());
        crate::metrics::record::request_start_without_active(
            sid,
            &client_ip,
            user_id,
            user_plan_id,
            plan_id,
            None,
            false,
        );

        let backend_addr = session.backend_addr;
        let listen_port = session.listen_port;
        let listener_shutdown_rx = shutdown_rx.clone();
        let session_shutdown_rx = session.shutdown.clone();
        let server_id = session.server_id;
        let origin_id = session.origin_id;
        let initial_client_addr = client_addr;
        let client_addr = session.client_addr.clone();
        let last_activity_ms = session.last_activity_ms.clone();
        let quic_cids = session.quic_cids.clone();
        let quic_server_cid_len = session.quic_server_cid_len.clone();
        let session_quic_cid_tx = session.quic_cid_tx.clone();
        let sessions = self.sessions.clone();
        let recent_upstream_ports = self.recent_upstream_ports.clone();
        // One-shot reuse: a session recreated for the same key after churn
        // tries to keep the previous upstream port so tuple-pinned peers keep
        // working. The entry is consumed whether the rebind succeeds or not.
        let preferred_backend_bind = recent_upstream_ports
            .remove(&key)
            .and_then(|(_, entry)| {
                (entry.recorded_at.elapsed() <= UDP_UPSTREAM_PORT_REUSE_TTL)
                    .then_some(entry.local_addr)
            });
        self.sessions.insert(key, session.clone());

        self.spawn_session_work(async move {
            let _session_permit = session_permit;
            let _listener_permit = listener_permit;
            // Shadow counter for live UDP passthrough sessions.
            let _udp_session_transport = crate::metrics::transport_metrics_guard(
                crate::metrics::ShadowTransportKind::UdpSession,
            );
            let result = Self::handle_session(UdpHandleSessionArgs {
                session_id,
                backend_addr,
                _listen_port: listen_port,
                listener_shutdown_rx,
                session_shutdown_rx,
                server_id,
                origin_id,
                client_addr: client_addr.clone(),
                domain,
                last_activity_ms,
                quic_cids,
                quic_server_cid_len,
                quic_cid_tx: session_quic_cid_tx,
                downstream_sender,
                rx,
                metrics_guard,
                recent_upstream_ports,
                preferred_backend_bind,
            })
            .await;
            let last_client_addr = **client_addr.load();
            sessions.remove_if(&(initial_client_addr, listen_port), |_, session| {
                session.id == session_id
            });
            if last_client_addr != initial_client_addr {
                sessions.remove_if(&(last_client_addr, listen_port), |_, session| {
                    session.id == session_id
                });
            }
            if let Err(err) = result {
                debug!(
                    "UDP session {} -> {} closed: {}",
                    last_client_addr, backend_addr, err
                );
            }
        });

        Ok(Some(session))
    }

    pub fn update_session_activity(session: &UdpSession) {
        session
            .last_activity_ms
            .store(udp_activity_now_ms(), Ordering::Relaxed);
    }

    pub fn update_session_client_addr(session: &UdpSession, client_addr: SocketAddr) {
        if **session.client_addr.load() != client_addr {
            session.client_addr.store(Arc::new(client_addr));
        }
    }

    pub fn session_quic_cids(session: &UdpSession) -> Vec<Vec<u8>> {
        session
            .quic_cids
            .try_read()
            .map(|cids| cids.iter().cloned().collect())
            .unwrap_or_default()
    }

    async fn record_session_quic_cid(
        session_id: u64,
        cids: &Arc<RwLock<VecDeque<Vec<u8>>>>,
        quic_cid_tx: Option<&mpsc::Sender<UdpSessionQuicCid>>,
        cid: Vec<u8>,
    ) {
        if cid.is_empty() {
            return;
        }
        let mut cids = cids.write().await;
        if cids.iter().any(|existing| existing == &cid) {
            return;
        }
        cids.push_back(cid.clone());
        let mut retired_cid = None;
        while cids.len() > UDP_SESSION_MAX_QUIC_CIDS {
            retired_cid = cids.pop_front();
        }
        drop(cids);
        if let Some(tx) = quic_cid_tx {
            // CID bookkeeping is opportunistic: the demux re-derives routes
            // from `session_cids` on every dispatch, so a full update channel
            // must never stall the packet path.
            let _ = tx.try_send(UdpSessionQuicCid {
                session_id,
                cid,
                retired_cid,
            });
        }
    }

    async fn record_client_short_header_cid(session: &UdpSession, packet: &[u8]) {
        if session.quic_cid_tx.is_none() || packet.first().is_none_or(|first| first & 0x80 != 0) {
            return;
        }

        let cid_len = session.quic_server_cid_len.load(Ordering::Acquire) as usize;
        if !(1..=20).contains(&cid_len) {
            return;
        }

        let Some(cids) = crate::quic_probe::quic_packet_cids(packet, cid_len) else {
            return;
        };
        Self::record_session_quic_cid(
            session.id,
            &session.quic_cids,
            session.quic_cid_tx.as_ref(),
            cids.dcid,
        )
        .await;
    }

    pub fn send_to_session(session: &UdpSession, data: Bytes) -> UdpSessionSendStatus {
        let Some(item) = QueuedUdpDatagram::new(data) else {
            return UdpSessionSendStatus::Full;
        };
        match session.tx.try_send(item) {
            Ok(()) => {
                Self::update_session_activity(session);
                UdpSessionSendStatus::Sent
            }
            Err(mpsc::error::TrySendError::Full(_)) => UdpSessionSendStatus::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => UdpSessionSendStatus::Closed,
        }
    }

    pub async fn send_to_session_from_client(
        session: &UdpSession,
        client_addr: SocketAddr,
        data: Bytes,
    ) -> UdpSessionSendStatus {
        let Some(item) = QueuedUdpDatagram::new(data) else {
            return UdpSessionSendStatus::Full;
        };
        match session.tx.try_reserve() {
            Ok(permit) => {
                // Queue the datagram first; CID bookkeeping below may await a
                // lock and must not hold a reserved slot while the packet is
                // still undelivered.
                let data = item.data.clone();
                Self::update_session_client_addr(session, client_addr);
                permit.send(item);
                Self::record_client_short_header_cid(session, &data).await;
                Self::update_session_activity(session);
                UdpSessionSendStatus::Sent
            }
            Err(mpsc::error::TrySendError::Full(())) => UdpSessionSendStatus::Full,
            Err(mpsc::error::TrySendError::Closed(())) => UdpSessionSendStatus::Closed,
        }
    }

    pub fn remove_sessions_for_port(&self, port: u16) {
        self.sessions.retain(|(_, session_port), session| {
            let keep = *session_port != port;
            if !keep {
                let _ = session.shutdown_tx.send(true);
            }
            keep
        });
    }

    pub fn cleanup_idle_sessions(&self, timeout: Duration) {
        self.sessions.retain(|key, session| {
            let keep = udp_activity_is_alive(&session.last_activity_ms, timeout);
            if !keep {
                debug!("Cleaning up idle UDP session: {:?}", key);
                let _ = session.shutdown_tx.send(true);
            }
            keep
        });
        self.recent_upstream_ports
            .retain(|_, entry| entry.recorded_at.elapsed() <= UDP_UPSTREAM_PORT_REUSE_TTL);
    }

    async fn handle_session(args: UdpHandleSessionArgs) -> anyhow::Result<()> {
        let UdpHandleSessionArgs {
            session_id,
            backend_addr,
            _listen_port,
            mut listener_shutdown_rx,
            mut session_shutdown_rx,
            server_id,
            origin_id,
            client_addr,
            domain,
            last_activity_ms,
            quic_cids,
            quic_server_cid_len,
            quic_cid_tx,
            downstream_sender,
            mut rx,
            mut metrics_guard,
            recent_upstream_ports,
            preferred_backend_bind,
        } = args;
        let backend_bind_addr = if backend_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let mut backend_socket = match connect_backend_udp_socket(
            backend_addr,
            preferred_backend_bind,
            backend_bind_addr,
            session_id,
        )
        .await
        {
            Ok(socket) => socket,
            Err(err) => {
                crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                let current_client_addr = **client_addr.load();
                crate::metrics::record::record_network_dimensions(
                    crate::metrics::NetworkDimensionsArgs {
                        category: crate::metrics::METRIC_CATEGORY_UDP,
                        server_id,
                        client_ip: current_client_addr.ip(),
                        domain: &domain,
                        user_agent: "-",
                        bytes_sent: 0,
                        bytes_received: 0,
                        status: 502,
                    },
                );
                crate::metrics::record::request_end_without_active(
                    server_id,
                    0,
                    0,
                    false,
                    false,
                    false,
                    Some(metrics_guard.metrics()),
                );
                metrics_guard.finish();
                return Err(err.into());
            }
        };
        crate::origin_state::ORIGIN_STATE_MANAGER.record_success(origin_id);
        let mut transfer_metrics = UdpTransferAccumulator::new(Instant::now());
        let mut buf = vec![0u8; 65535];
        'session_relay: loop {
            let idle_deadline =
                udp_session_idle_deadline(&last_activity_ms, UDP_SESSION_IDLE_TIMEOUT);
            let metrics_flush_after = transfer_metrics.next_flush_after(Instant::now());
            let metrics_flush_enabled = metrics_flush_after.is_some();
            let metrics_flush_deadline =
                TokioInstant::now() + metrics_flush_after.unwrap_or(UDP_SESSION_IDLE_TIMEOUT);
            tokio::select! {
                _ = listener_shutdown_rx.changed() => {
                    break;
                }
                _ = session_shutdown_rx.changed() => {
                    break;
                }
                _ = sleep_until(idle_deadline) => {
                    let idle = !udp_activity_is_alive(&last_activity_ms, UDP_SESSION_IDLE_TIMEOUT);
                    if idle {
                        break;
                    }
                }
                _ = sleep_until(metrics_flush_deadline), if metrics_flush_enabled => {
                    transfer_metrics.flush_if_due(server_id, false);
                }
                item = rx.recv() => {
                    let Some(item) = item else {
                        break;
                    };
                    let mut drained = 0usize;
                    let mut next_item = Some(item);
                    while let Some(item) = next_item.take() {
                        let data = item.data;
                        let len = data.len() as u64;
                        if let Err(err) = backend_socket.send(&data).await {
                            // A UDP send error must not tear down the session:
                            // connected sockets surface transient ICMP and
                            // egress failures that would otherwise force a new
                            // upstream port and break tuple-pinned protocols.
                            crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                            #[cfg(target_os = "linux")]
                            af_xdp_udp_diag::bump(&af_xdp_udp_diag::UPSTREAM_TX_ERR);
                            debug!(
                                "UDP session {} upstream send to {} failed, dropping datagram: {}",
                                session_id, backend_addr, err
                            );
                            if backend_socket.defunct() {
                                break 'session_relay;
                            }
                            break;
                        }
                        #[cfg(target_os = "linux")]
                        af_xdp_udp_diag::bump(&af_xdp_udp_diag::UPSTREAM_TX);
                        last_activity_ms.store(udp_activity_now_ms(), Ordering::Relaxed);
                        transfer_metrics.record_upstream(len);
                        transfer_metrics.flush_if_due(server_id, false);
                        drained += 1;
                        if drained >= UDP_UPSTREAM_DRAIN_BUDGET {
                            break;
                        }
                        next_item = match rx.try_recv() {
                            Ok(item) => Some(item),
                            Err(mpsc::error::TryRecvError::Empty)
                            | Err(mpsc::error::TryRecvError::Disconnected) => None,
                        };
                    }
                }
                recv = backend_socket.recv(&mut buf) => {
                    let len = match recv {
                        Ok(packet) => packet,
                        Err(err) => {
                            if backend_socket.defunct() {
                                // The AF_XDP dataplane channel closed —
                                // the flow is permanently dead, not a
                                // transient loss.
                                break;
                            }
                            // Connected UDP sockets report ICMP errors (port or
                            // host unreachable) through recv; treat them as a
                            // dropped reply and keep the session alive.
                            debug!(
                                "UDP session {} upstream recv from {} failed, continuing: {}",
                                session_id, backend_addr, err
                            );
                            sleep_until(TokioInstant::now() + UDP_ERROR_BACKOFF).await;
                            continue;
                        }
                    };
                    #[cfg(target_os = "linux")]
                    af_xdp_udp_diag::bump(&af_xdp_udp_diag::UPSTREAM_RX);
                    let len_u64 = len as u64;
                    if let Some(cids) = crate::quic_probe::quic_packet_cids(&buf[..len], 0) {
                        if let Some(scid) = cids.scid.as_ref()
                            && let Ok(cid_len) = u8::try_from(scid.len())
                            && (1..=20).contains(&cid_len)
                        {
                            let _ = quic_server_cid_len.compare_exchange(
                                0,
                                cid_len,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            );
                        }
                        for cid in [Some(cids.dcid), cids.scid].into_iter().flatten() {
                            Self::record_session_quic_cid(
                                session_id,
                                &quic_cids,
                                quic_cid_tx.as_ref(),
                                cid,
                            )
                            .await;
                        }
                    }
                    let current_client_addr = **client_addr.load();
                    match downstream_sender.send_to(&buf[..len], current_client_addr).await {
                        Ok(_) => {
                            #[cfg(target_os = "linux")]
                            af_xdp_udp_diag::bump(&af_xdp_udp_diag::DOWNSTREAM_ENQ);
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            #[cfg(target_os = "linux")]
                            af_xdp_udp_diag::bump(&af_xdp_udp_diag::DOWNSTREAM_SHED);
                            debug!(
                                "UDP downstream sender queue full for {}, dropping backend packet",
                                current_client_addr
                            );
                            continue;
                        }
                        Err(err) => {
                            // A transient downstream send error (for example an
                            // ICMP error reported on the shared listen socket)
                            // must not tear down the session.
                            debug!(
                                "UDP session {} downstream send to {} failed, dropping backend packet: {}",
                                session_id, current_client_addr, err
                            );
                            continue;
                        }
                    }
                    last_activity_ms.store(udp_activity_now_ms(), Ordering::Relaxed);
                    transfer_metrics.record_downstream(len_u64);
                    transfer_metrics.flush_if_due(server_id, false);
                }
            }
        }
        transfer_metrics.flush_if_due(server_id, true);
        if let Ok(local_addr) = backend_socket.local_addr() {
            record_recent_upstream_port(
                &recent_upstream_ports,
                **client_addr.load(),
                _listen_port,
                local_addr,
            );
        }
        let (downstream_sent, upstream_sent) = transfer_metrics.totals();
        let current_client_addr = **client_addr.load();
        let status = 200;
        crate::metrics::record::record_network_dimensions(crate::metrics::NetworkDimensionsArgs {
            category: crate::metrics::METRIC_CATEGORY_UDP,
            server_id,
            client_ip: current_client_addr.ip(),
            domain: &domain,
            user_agent: "-",
            bytes_sent: downstream_sent as i64,
            bytes_received: upstream_sent as i64,
            status,
        });
        crate::metrics::record::request_end_without_active(
            server_id,
            0,
            0,
            false,
            false,
            false,
            Some(metrics_guard.metrics()),
        );
        metrics_guard.finish();
        Ok(())
    }

    pub async fn find_server_for_packet(
        &self,
        port: u16,
        data: &[u8],
    ) -> Option<Arc<ServerConfig>> {
        if self.config_store.has_any_quic_passthrough_sync()
            && let Some(client_hello) = crate::quic_probe::probe_quic_client_hello(data)
            && let Some(server_name) = client_hello.server_name.as_deref()
            && let Some(server) = self
                .config_store
                .find_quic_passthrough_server_sync(server_name, port)
        {
            debug!(
                "UDP Proxy: QUIC passthrough {} on port {} matched server {} alpn={:?}",
                server_name,
                port,
                server.numeric_id(),
                client_hello.alpns
            );
            return Some(server);
        }
        if let Some(server) = self.find_server_by_port(port).await {
            return Some(server);
        }
        if let Some(server) = self
            .config_store
            .find_unique_quic_passthrough_server_by_port_sync(port)
        {
            debug!(
                "UDP Proxy: QUIC passthrough fallback on port {} matched unique @quic server {}",
                port,
                server.numeric_id()
            );
            return Some(server);
        }
        None
    }

    pub async fn find_server_by_port(&self, port: u16) -> Option<Arc<ServerConfig>> {
        self.config_store.find_udp_server_by_port_sync(port)
    }

    pub(crate) fn is_l4_blocked(&self, ip: IpAddr) -> bool {
        crate::l4_defense::is_l4_blocked(&self.config_store, &self.waf_state, ip)
    }

    pub(crate) fn record_l4_event(
        &self,
        ip: IpAddr,
        kind: L4DefenseKind,
        detail: impl Into<String>,
    ) -> crate::l4_defense::L4DefenseVerdict {
        crate::l4_defense::record_l4_event(
            &self.config_store,
            &self.waf_state,
            self.node_id,
            ip,
            kind,
            detail,
        )
    }

    pub(crate) fn record_l4_event_with_pressure(
        &self,
        ip: IpAddr,
        kind: L4DefenseKind,
        detail: impl Into<String>,
        pressure_level: crate::l4_defense::L4PressureLevel,
    ) -> crate::l4_defense::L4DefenseVerdict {
        crate::l4_defense::record_l4_event_with_pressure(
            &self.config_store,
            &self.waf_state,
            self.node_id,
            ip,
            kind,
            detail,
            pressure_level,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{NetworkAddressConfig, ServerNameConfig, UDPConfig};
    use arc_swap::ArcSwap;
    use std::collections::HashMap;

    #[test]
    fn udp_session_idle_deadline_uses_last_activity_remaining_time() {
        assert_eq!(
            udp_session_idle_remaining(1_000, 1_250, Duration::from_secs(1)),
            Duration::from_millis(750)
        );
        assert_eq!(
            udp_session_idle_remaining(1_000, 2_000, Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    #[test]
    fn udp_metrics_accumulator_flushes_on_threshold() {
        let start = Instant::now();
        let mut accumulator = UdpTransferAccumulator::new(start);

        accumulator.record_upstream(UDP_METRICS_FLUSH_BYTES - 1);
        assert_eq!(accumulator.take_flush_due(start, false), None);

        accumulator.record_downstream(1);
        assert_eq!(
            accumulator.take_flush_due(start, false),
            Some(UdpMetricsFlush {
                downstream: 1,
                upstream: UDP_METRICS_FLUSH_BYTES - 1
            })
        );
        assert_eq!(accumulator.take_flush_due(start, false), None);
    }

    #[test]
    fn udp_metrics_accumulator_flushes_on_interval() {
        let start = Instant::now();
        let mut accumulator = UdpTransferAccumulator::new(start);

        accumulator.record_downstream(512);
        assert_eq!(
            accumulator.next_flush_after(start + Duration::from_millis(250)),
            Some(Duration::from_millis(750))
        );
        assert_eq!(
            accumulator.take_flush_due(start + UDP_METRICS_FLUSH_INTERVAL, false),
            Some(UdpMetricsFlush {
                downstream: 512,
                upstream: 0
            })
        );
        assert_eq!(
            accumulator.next_flush_after(start + UDP_METRICS_FLUSH_INTERVAL),
            None
        );
    }

    #[test]
    fn udp_metrics_accumulator_flushes_on_session_close() {
        let start = Instant::now();
        let mut accumulator = UdpTransferAccumulator::new(start);

        accumulator.record_upstream(128);
        assert_eq!(
            accumulator.take_flush_due(start + Duration::from_millis(10), true),
            Some(UdpMetricsFlush {
                downstream: 0,
                upstream: 128
            })
        );
        assert_eq!(accumulator.totals(), (0, 128));
    }

    #[tokio::test]
    async fn udp_backend_resolution_prefers_client_ip_family_for_domain_origin() {
        let addr = resolve_udp_backend_addr(
            "[::1]:18443".to_string(),
            Some("localhost"),
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(addr, "127.0.0.1:18443".parse().unwrap());
    }

    #[tokio::test]
    async fn dns_cache_single_flight_shares_success_and_preserves_all_addresses() {
        let cache = Arc::new(UdpDnsResolutionCache::new());
        let key = UdpDnsCacheKey {
            origin_id: 7,
            host: "controlled.example".to_string(),
            port: 18443,
            prefer_ipv4: true,
            runtime_reload_generation: 3,
        };
        let calls = Arc::new(AtomicU64::new(0));
        let lookup = |_: String| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(vec![
                    "[::1]:18443".parse().unwrap(),
                    "127.0.0.1:18443".parse().unwrap(),
                ])
            }
        };

        let (first, second) = tokio::join!(
            cache.resolve(
                key.clone(),
                "controlled.example:18443".to_string(),
                "127.0.0.1".parse().unwrap(),
                lookup
            ),
            cache.resolve(
                key.clone(),
                "controlled.example:18443".to_string(),
                "127.0.0.1".parse().unwrap(),
                |_| async { panic!("single-flight follower performed lookup") }
            ),
        );

        assert_eq!(first.unwrap(), "127.0.0.1:18443".parse().unwrap());
        assert_eq!(second.unwrap(), "127.0.0.1:18443".parse().unwrap());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(cache.cache.get(&key).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn dns_cache_leader_cancellation_releases_followers_and_entry() {
        let cache = Arc::new(UdpDnsResolutionCache::new());
        let key = UdpDnsCacheKey {
            origin_id: 9,
            host: "cancelled.example".to_string(),
            port: 18443,
            prefer_ipv4: true,
            runtime_reload_generation: 5,
        };

        // Leader blocks on a channel that is never signalled, then its task is
        // aborted — the inflight entry must still be removed and followers
        // must observe a published failure instead of hanging forever.
        // `_block_tx` stays alive so the leader never resolves on its own.
        let (_block_tx, block_rx) = tokio::sync::oneshot::channel::<()>();
        let leader = {
            let cache = cache.clone();
            let key = key.clone();
            tokio::spawn(async move {
                cache
                    .resolve(
                        key,
                        "cancelled.example:18443".to_string(),
                        "127.0.0.1".parse().unwrap(),
                        move |_| async move {
                            let _ = block_rx.await;
                            Ok(vec!["127.0.0.1:18443".parse().unwrap()])
                        },
                    )
                    .await
            })
        };

        // Let the leader publish the inflight entry before the follower joins.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(cache.inflight.len(), 1);

        let follower = {
            let cache = cache.clone();
            let key = key.clone();
            tokio::spawn(async move {
                cache
                    .resolve(
                        key,
                        "cancelled.example:18443".to_string(),
                        "127.0.0.1".parse().unwrap(),
                        |_| async {
                            panic!("follower must not become leader mid-flight")
                        },
                    )
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;

        leader.abort();
        // The follower must complete (with an error) well under any realistic
        // hang: it polls the result on a bounded interval.
        let outcome = tokio::time::timeout(Duration::from_secs(5), follower)
            .await
            .expect("follower must not hang after leader cancellation")
            .expect("follower task must not panic");
        assert!(outcome.is_err(), "cancelled lookup must surface an error");
        assert!(
            cache.inflight.is_empty(),
            "leader cancellation must remove the inflight entry"
        );
    }

    #[tokio::test]
    async fn dns_cache_shares_errors_without_caching_them_and_allows_retry() {
        let cache = Arc::new(UdpDnsResolutionCache::new());
        let key = UdpDnsCacheKey {
            origin_id: 8,
            host: "controlled.example".to_string(),
            port: 18443,
            prefer_ipv4: false,
            runtime_reload_generation: 4,
        };
        let calls = Arc::new(AtomicU64::new(0));
        let first_calls = calls.clone();
        let (first, second) = tokio::join!(
            cache.resolve(
                key.clone(),
                "controlled.example:18443".to_string(),
                "::1".parse().unwrap(),
                move |_| async move {
                    first_calls.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Err(anyhow::anyhow!("controlled resolver failure"))
                }
            ),
            cache.resolve(
                key.clone(),
                "controlled.example:18443".to_string(),
                "::1".parse().unwrap(),
                |_| async { panic!("single-flight follower performed lookup") }
            ),
        );
        assert_eq!(
            first.unwrap_err().to_string(),
            "controlled resolver failure"
        );
        assert_eq!(
            second.unwrap_err().to_string(),
            "controlled resolver failure"
        );
        assert!(cache.cache.get(&key).is_none());

        let retry_calls = calls.clone();
        let retry = cache
            .resolve(
                key,
                "controlled.example:18443".to_string(),
                "::1".parse().unwrap(),
                move |_| async move {
                    retry_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(vec!["[::1]:18443".parse().unwrap()])
                },
            )
            .await
            .unwrap();
        assert_eq!(retry, "[::1]:18443".parse().unwrap());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn dns_cache_does_not_cache_empty_success_results() {
        let cache = UdpDnsResolutionCache::new();
        let key = UdpDnsCacheKey {
            origin_id: 10,
            host: "controlled.example".to_string(),
            port: 18443,
            prefer_ipv4: true,
            runtime_reload_generation: 5,
        };
        let result = cache
            .resolve(
                key.clone(),
                "controlled.example:18443".to_string(),
                "127.0.0.1".parse().unwrap(),
                |_| async { Ok(Vec::new()) },
            )
            .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "UDP backend address controlled.example:18443 resolved no addresses"
        );
        assert!(cache.cache.get(&key).is_none());
    }

    #[test]
    fn dns_cache_key_separates_generation_and_address_family_preference() {
        let base = UdpDnsCacheKey {
            origin_id: 9,
            host: "controlled.example".to_string(),
            port: 53,
            prefer_ipv4: true,
            runtime_reload_generation: 1,
        };
        let mut generation = base.clone();
        generation.runtime_reload_generation = 2;
        let mut family = base.clone();
        family.prefer_ipv4 = false;
        assert_ne!(base, generation);
        assert_ne!(base, family);
    }

    #[tokio::test]
    async fn session_client_addr_updates_for_rebinding() {
        let first: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let second: SocketAddr = "[2001:db8::2]:10001".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = UdpSession {
            id: 1,
            client_addr: Arc::new(ArcSwap::from_pointee(first)),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx,
            shutdown,
        };

        UdpProxyManager::update_session_client_addr(&session, second);

        assert_eq!(**session.client_addr.load(), second);
    }

    #[tokio::test]
    async fn send_to_session_from_client_does_not_update_addr_when_full() {
        let first: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let second: SocketAddr = "[2001:db8::2]:10001".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(QueuedUdpDatagram::new(Bytes::from_static(b"queued")).unwrap())
            .unwrap();
        let (shutdown_tx, shutdown) = watch::channel(false);
        let last_activity_ms = Arc::new(AtomicU64::new(1234));
        let session = UdpSession {
            id: 1,
            client_addr: Arc::new(ArcSwap::from_pointee(first)),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: last_activity_ms.clone(),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx,
            shutdown,
        };

        assert_eq!(
            UdpProxyManager::send_to_session_from_client(
                &session,
                second,
                Bytes::from_static(b"next")
            )
            .await,
            UdpSessionSendStatus::Full
        );
        assert_eq!(**session.client_addr.load(), first);
        assert_eq!(last_activity_ms.load(Ordering::Relaxed), 1234);
    }

    #[tokio::test]
    async fn client_short_header_learns_rotated_server_cid_after_queue_reservation() {
        let client_addr: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let (cid_tx, mut cid_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = UdpSession {
            id: 7,
            client_addr: Arc::new(ArcSwap::from_pointee(client_addr)),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(4)),
            quic_cid_tx: Some(cid_tx),
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx,
            shutdown,
        };

        assert_eq!(
            UdpProxyManager::send_to_session_from_client(
                &session,
                client_addr,
                Bytes::from_static(&[0x40, 5, 6, 7, 8, 0xaa]),
            )
            .await,
            UdpSessionSendStatus::Sent
        );
        assert_eq!(
            cid_rx.recv().await,
            Some(UdpSessionQuicCid {
                session_id: 7,
                cid: vec![5, 6, 7, 8],
                retired_cid: None,
            })
        );
        assert_eq!(
            UdpProxyManager::session_quic_cids(&session),
            vec![vec![5, 6, 7, 8]]
        );
    }

    #[tokio::test]
    async fn unknown_server_cid_length_does_not_learn_client_short_header() {
        let client_addr: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let (cid_tx, mut cid_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = UdpSession {
            id: 8,
            client_addr: Arc::new(ArcSwap::from_pointee(client_addr)),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: Some(cid_tx),
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx,
            shutdown,
        };

        assert_eq!(
            UdpProxyManager::send_to_session_from_client(
                &session,
                client_addr,
                Bytes::from_static(&[0x40, 5, 6, 7, 8, 0xaa]),
            )
            .await,
            UdpSessionSendStatus::Sent
        );
        assert!(cid_rx.try_recv().is_err());
        assert!(UdpProxyManager::session_quic_cids(&session).is_empty());
    }

    #[tokio::test]
    async fn send_to_session_reports_full_without_waiting() {
        let first: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(QueuedUdpDatagram::new(Bytes::from_static(b"queued")).unwrap())
            .unwrap();
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = Arc::new(UdpSession {
            id: 1,
            client_addr: Arc::new(ArcSwap::from_pointee(first)),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx,
            shutdown,
        });
        assert_eq!(
            UdpProxyManager::send_to_session(&session, Bytes::from_static(b"next")),
            UdpSessionSendStatus::Full
        );
        assert_eq!(
            rx.recv().await.as_ref().and_then(|item| item.as_deref()),
            Some(&b"queued"[..])
        );
        assert_eq!(
            UdpProxyManager::send_to_session(&session, Bytes::from_static(b"next")),
            UdpSessionSendStatus::Sent
        );
        assert_eq!(
            rx.recv().await.as_ref().and_then(|item| item.as_deref()),
            Some(&b"next"[..])
        );
    }

    #[test]
    fn send_to_session_reports_closed() {
        let first: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = UdpSession {
            id: 1,
            client_addr: Arc::new(ArcSwap::from_pointee(first)),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx,
            shutdown,
        };

        assert_eq!(
            UdpProxyManager::send_to_session(&session, Bytes::from_static(b"next")),
            UdpSessionSendStatus::Closed
        );
    }

    #[tokio::test]
    async fn backend_session_relay_uses_connected_udp_and_stops_on_shutdown() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let listen_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(4);
        let (_listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
        let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(UdpProxyManager::handle_session(UdpHandleSessionArgs {
            session_id: 1,
            backend_addr,
            _listen_port: 443,
            listener_shutdown_rx,
            session_shutdown_rx,
            server_id: 1,
            origin_id: 1,
            client_addr: Arc::new(ArcSwap::from_pointee(client_addr)),
            domain: "udp.example.com".to_string(),
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            downstream_sender: UdpDownstreamSender::socket(listen_socket),
            rx,
            metrics_guard: crate::metrics::ActiveRequestMetricsGuard::new(
                crate::metrics::record::get_or_create(1),
            ),
            recent_upstream_ports: Arc::new(DashMap::new()),
            preferred_backend_bind: None,
        }));

        tx.send(QueuedUdpDatagram::new(Bytes::from_static(b"ping")).unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let (len, backend_peer) =
            tokio::time::timeout(Duration::from_secs(1), backend.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..len], b"ping");

        backend.send_to(b"pong", backend_peer).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"pong");

        session_shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn backend_session_relay_can_use_channel_downstream_sender() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (downstream_tx, mut downstream_rx) = mpsc::channel(4);
        let (tx, rx) = mpsc::channel(4);
        let (_listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
        let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(UdpProxyManager::handle_session(UdpHandleSessionArgs {
            session_id: 1,
            backend_addr,
            _listen_port: 443,
            listener_shutdown_rx,
            session_shutdown_rx,
            server_id: 1,
            origin_id: 1,
            client_addr: Arc::new(ArcSwap::from_pointee(client_addr)),
            domain: "udp.example.com".to_string(),
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            downstream_sender: UdpDownstreamSender::channel(listen_addr, downstream_tx),
            rx,
            metrics_guard: crate::metrics::ActiveRequestMetricsGuard::new(
                crate::metrics::record::get_or_create(1),
            ),
            recent_upstream_ports: Arc::new(DashMap::new()),
            preferred_backend_bind: None,
        }));

        tx.send(QueuedUdpDatagram::new(Bytes::from_static(b"ping")).unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let (len, backend_peer) =
            tokio::time::timeout(Duration::from_secs(1), backend.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..len], b"ping");

        backend.send_to(b"pong", backend_peer).await.unwrap();
        let datagram = tokio::time::timeout(Duration::from_secs(1), downstream_rx.recv())
            .await
            .unwrap()
            .expect("downstream datagram");
        assert_eq!(datagram.listen_addr, listen_addr);
        assert_eq!(datagram.peer_addr, client_addr);
        assert_eq!(&datagram.payload[..], b"pong");

        session_shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn backend_session_survives_downstream_send_error() {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (downstream_tx, downstream_rx) = mpsc::channel(4);
        // Dropping the receiver makes every downstream send fail with
        // BrokenPipe. The session must stay alive and keep relaying upstream.
        drop(downstream_rx);
        let (tx, rx) = mpsc::channel(4);
        let (_listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
        let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);
        let recent_upstream_ports: RecentUpstreamPorts = Arc::new(DashMap::new());
        let registry = recent_upstream_ports.clone();

        let task = tokio::spawn(UdpProxyManager::handle_session(UdpHandleSessionArgs {
            session_id: 1,
            backend_addr,
            _listen_port: 443,
            listener_shutdown_rx,
            session_shutdown_rx,
            server_id: 1,
            origin_id: 1,
            client_addr: Arc::new(ArcSwap::from_pointee(client_addr)),
            domain: "udp.example.com".to_string(),
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            downstream_sender: UdpDownstreamSender::channel(listen_addr, downstream_tx),
            rx,
            metrics_guard: crate::metrics::ActiveRequestMetricsGuard::new(
                crate::metrics::record::get_or_create(1),
            ),
            recent_upstream_ports,
            preferred_backend_bind: None,
        }));

        tx.send(QueuedUdpDatagram::new(Bytes::from_static(b"ping")).unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let (len, backend_peer) =
            tokio::time::timeout(Duration::from_secs(1), backend.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..len], b"ping");

        // This reply fails to enqueue downstream; the session must survive.
        backend.send_to(b"pong", backend_peer).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());

        tx.send(QueuedUdpDatagram::new(Bytes::from_static(b"ping2")).unwrap())
            .await
            .unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), backend.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"ping2");

        session_shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        // The closed session recorded its upstream socket address so a
        // recreated session for the same key can try to reuse the port.
        let entry = registry
            .get(&(client_addr, 443))
            .expect("recent upstream port recorded");
        assert_eq!(entry.local_addr, backend_peer);
    }

    #[tokio::test]
    async fn backend_socket_reuses_freed_port_and_falls_back_when_busy() {
        let previous = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let freed = previous.local_addr().unwrap();
        drop(previous);
        let reused = bind_backend_socket(Some(freed), "0.0.0.0:0", 1)
            .await
            .unwrap();
        assert_eq!(reused.local_addr().unwrap(), freed);

        let occupied = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let busy = occupied.local_addr().unwrap();
        let fallback = bind_backend_socket(Some(busy), "0.0.0.0:0", 2)
            .await
            .unwrap();
        assert_ne!(fallback.local_addr().unwrap().port(), busy.port());
    }

    #[tokio::test]
    async fn queue_full_event_is_throttled_per_session() {
        let (tx, _rx) = mpsc::channel(4);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = UdpSession {
            id: 1,
            client_addr: Arc::new(ArcSwap::from_pointee(
                "127.0.0.1:50000".parse().unwrap(),
            )),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx,
            shutdown,
        };
        assert!(udp_session_queue_full_event_due(&session));
        assert!(!udp_session_queue_full_event_due(&session));
        session.queue_full_event_at_ms.store(
            udp_activity_now_ms().saturating_sub(UDP_QUEUE_FULL_EVENT_INTERVAL_MS + 1),
            Ordering::Relaxed,
        );
        assert!(udp_session_queue_full_event_due(&session));
    }

    #[test]
    fn reconcile_keeps_missing_listener_during_grace_period() {
        let manager = UdpProxyManager::new(ConfigStore::new(), Arc::new(WafStateManager::new()), 1);
        let bind_addr: SocketAddr = "127.0.0.1:6001".parse().unwrap();
        let (shutdown_tx, _rx) = watch::channel(false);
        manager.handled_ports.insert(
            bind_addr,
            ListenerHandle {
                shutdown_tx,
                listener_id: 1,
                generation: 0,
            },
        );

        // First miss starts the grace period; the listener must stay.
        manager.reconcile_listeners(&std::collections::HashSet::new());
        assert!(manager.handled_ports.contains_key(&bind_addr));

        // Still within the grace period the listener survives.
        manager.reconcile_listeners(&std::collections::HashSet::new());
        assert!(manager.handled_ports.contains_key(&bind_addr));

        // A port that returns to the desired set clears the miss marker.
        let mut desired = std::collections::HashSet::new();
        desired.insert(bind_addr);
        manager.reconcile_listeners(&desired);
        assert!(!manager.undesired_since.contains_key(&bind_addr));

        // Once the grace period has elapsed the listener is removed.
        manager.undesired_since.insert(
            bind_addr,
            Instant::now() - UDP_LISTENER_REMOVE_GRACE - Duration::from_secs(1),
        );
        manager.reconcile_listeners(&std::collections::HashSet::new());
        assert!(!manager.handled_ports.contains_key(&bind_addr));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "manual high-burst UDP proxy A/B benchmark"]
    async fn high_burst_udp_proxy_batch_baseline() {
        let manager = UdpProxyManager::new(ConfigStore::new(), Arc::new(WafStateManager::new()), 1);
        let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let backend_addr = backend.local_addr().unwrap();
        let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_addr = client.local_addr().unwrap();
        let listen_socket = Arc::new(
            bind_udp_socket("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap(),
        );
        let proxy_addr = listen_socket.local_addr().unwrap();
        let downstream_sender = UdpDownstreamSender::socket(listen_socket.clone());
        let queue_size = MEMORY_GOVERNOR.udp_session_queue_size();
        let (tx, rx) = mpsc::channel(queue_size);
        let (listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
        let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);
        let session = Arc::new(UdpSession {
            id: 9001,
            client_addr: Arc::new(ArcSwap::from_pointee(client_addr)),
            listen_port: proxy_addr.port(),
            backend_addr,
            origin_id: 9001,
            server_id: 9001,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx: session_shutdown_tx.clone(),
            shutdown: session_shutdown_rx.clone(),
        });
        manager
            .sessions
            .insert((client_addr, proxy_addr.port()), session.clone());

        let backend_received = Arc::new(AtomicU64::new(0));
        let backend_replies_sent = Arc::new(AtomicU64::new(0));
        let client_received = Arc::new(AtomicU64::new(0));
        let ingress_received = Arc::new(AtomicU64::new(0));
        let ingress_sent = Arc::new(AtomicU64::new(0));
        let ingress_full = Arc::new(AtomicU64::new(0));
        let ingress_closed = Arc::new(AtomicU64::new(0));
        let (backend_stop_tx, mut backend_stop_rx) = watch::channel(false);
        let (client_stop_tx, mut client_stop_rx) = watch::channel(false);

        let backend_task = {
            let backend = backend.clone();
            let backend_received = backend_received.clone();
            let backend_replies_sent = backend_replies_sent.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    tokio::select! {
                        _ = backend_stop_rx.changed() => break,
                        result = backend.recv_from(&mut buf) => {
                            let Ok((len, peer)) = result else { break };
                            backend_received.fetch_add(1, Ordering::Relaxed);
                            if backend.send_to(&buf[..len], peer).await.is_ok() {
                                backend_replies_sent.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            })
        };
        let client_task = {
            let client = client.clone();
            let client_received = client_received.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    tokio::select! {
                        _ = client_stop_rx.changed() => break,
                        result = client.recv_from(&mut buf) => {
                            if result.is_ok() {
                                client_received.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            })
        };
        let listener_task = {
            let manager = manager.clone();
            let listen_socket = listen_socket.clone();
            let downstream_sender = downstream_sender.clone();
            let ingress_received = ingress_received.clone();
            let ingress_sent = ingress_sent.clone();
            let ingress_full = ingress_full.clone();
            let ingress_closed = ingress_closed.clone();
            let mut listener_shutdown_rx = listener_shutdown_rx.clone();
            tokio::spawn(async move {
                let mut receiver = crate::net_bind::UdpBatchReceiver::new(listen_socket);
                loop {
                    let datagrams = tokio::select! {
                        _ = listener_shutdown_rx.changed() => break,
                        result = receiver.recv_batch() => result?,
                    };
                    for datagram in datagrams {
                        ingress_received.fetch_add(1, Ordering::Relaxed);
                        match manager
                            .receive_datagram_with_downstream(
                                datagram.peer_addr,
                                proxy_addr.port(),
                                datagram.payload,
                                downstream_sender.clone(),
                                listener_shutdown_rx.clone(),
                            )
                            .await?
                        {
                            UdpIngressDatagramStatus::Sent => {
                                ingress_sent.fetch_add(1, Ordering::Relaxed);
                            }
                            UdpIngressDatagramStatus::Full => {
                                ingress_full.fetch_add(1, Ordering::Relaxed);
                            }
                            UdpIngressDatagramStatus::Closed => {
                                ingress_closed.fetch_add(1, Ordering::Relaxed);
                            }
                            UdpIngressDatagramStatus::NoRoute
                            | UdpIngressDatagramStatus::Blocked => {}
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        };
        let session_task = tokio::spawn(UdpProxyManager::handle_session(UdpHandleSessionArgs {
            session_id: session.id,
            backend_addr,
            _listen_port: proxy_addr.port(),
            listener_shutdown_rx: listener_shutdown_tx.subscribe(),
            session_shutdown_rx,
            server_id: session.server_id,
            origin_id: session.origin_id,
            client_addr: session.client_addr.clone(),
            domain: "high-burst-udp.example".to_string(),
            last_activity_ms: session.last_activity_ms.clone(),
            quic_cids: session.quic_cids.clone(),
            quic_server_cid_len: session.quic_server_cid_len.clone(),
            quic_cid_tx: None,
            downstream_sender,
            rx,
            metrics_guard: crate::metrics::ActiveRequestMetricsGuard::new(
                crate::metrics::record::get_or_create(session.server_id),
            ),
            recent_upstream_ports: Arc::new(DashMap::new()),
            preferred_backend_bind: None,
        }));

        const ATTEMPTED: u64 = 20_000;
        let payload = vec![0xA5; 1_200];
        let mut submitted = 0u64;
        let mut send_errors = 0u64;
        for _ in 0..ATTEMPTED {
            match client.send_to(&payload, proxy_addr).await {
                Ok(_) => submitted += 1,
                Err(_) => send_errors += 1,
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;

        println!(
            "udp proxy batch baseline: attempted={} submitted={} send_errors={} \
             ingress_received={} sent={} full={} closed={} backend_received={} \
             backend_replies_sent={} client_received={} queue_size={}",
            ATTEMPTED,
            submitted,
            send_errors,
            ingress_received.load(Ordering::Relaxed),
            ingress_sent.load(Ordering::Relaxed),
            ingress_full.load(Ordering::Relaxed),
            ingress_closed.load(Ordering::Relaxed),
            backend_received.load(Ordering::Relaxed),
            backend_replies_sent.load(Ordering::Relaxed),
            client_received.load(Ordering::Relaxed),
            queue_size,
        );

        let _ = listener_shutdown_tx.send(true);
        let _ = session_shutdown_tx.send(true);
        let _ = backend_stop_tx.send(true);
        let _ = client_stop_tx.send(true);
        tokio::time::timeout(Duration::from_secs(1), listener_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), session_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), backend_task)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), client_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn channel_downstream_sender_reports_backpressure_without_waiting() {
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(DownstreamUdpDatagram {
            listen_addr,
            peer_addr,
            payload: Bytes::from_static(b"queued"),
            #[cfg(target_os = "linux")]
            enqueued_ms: udp_activity_now_ms(),
        })
        .unwrap();
        let sender = UdpDownstreamSender::channel(listen_addr, tx);

        let err = sender.send_to(b"drop", peer_addr).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[tokio::test]
    async fn af_xdp_datagram_reuses_existing_udp_session_queue() {
        let store = ConfigStore::new();
        let manager = UdpProxyManager::new(store, Arc::new(WafStateManager::new()), 1);
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = Arc::new(UdpSession {
            id: 77,
            client_addr: Arc::new(ArcSwap::from_pointee(peer_addr)),
            listen_port: listen_addr.port(),
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_server_cid_len: Arc::new(AtomicU8::new(0)),
            quic_cid_tx: None,
            queue_full_event_at_ms: AtomicU64::new(0),
            tx,
            shutdown_tx,
            shutdown,
        });
        manager
            .sessions
            .insert((peer_addr, listen_addr.port()), session);
        let (downstream_tx, _downstream_rx) = mpsc::channel(4);
        let (_listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);

        let status = manager
            .receive_af_xdp_datagram(
                crate::xdp::af_xdp::AfXdpDatagram {
                    listen_addr,
                    peer_addr,
                    payload: Bytes::from_static(b"hello"),
                    ecn: None,
                },
                downstream_tx,
                listener_shutdown_rx,
            )
            .await
            .unwrap();

        assert_eq!(status, UdpIngressDatagramStatus::Sent);
        assert_eq!(
            rx.recv().await.as_ref().and_then(|item| item.as_deref()),
            Some(&b"hello"[..])
        );
    }

    #[tokio::test]
    async fn af_xdp_datagram_without_route_is_reported() {
        let store = ConfigStore::new();
        let manager = UdpProxyManager::new(store, Arc::new(WafStateManager::new()), 1);
        let (downstream_tx, _downstream_rx) = mpsc::channel(4);
        let (_listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);

        let status = manager
            .receive_af_xdp_datagram(
                crate::xdp::af_xdp::AfXdpDatagram {
                    listen_addr: "127.0.0.1:443".parse().unwrap(),
                    peer_addr: "127.0.0.1:53000".parse().unwrap(),
                    payload: Bytes::from_static(b"hello"),
                    ecn: None,
                },
                downstream_tx,
                listener_shutdown_rx,
            )
            .await
            .unwrap();

        assert_eq!(status, UdpIngressDatagramStatus::NoRoute);
    }

    #[tokio::test]
    async fn normal_udp_server_takes_precedence_over_unique_quic_fallback() {
        let store = ConfigStore::new();
        let normal_udp = Arc::new(ServerConfig {
            id: Some(10),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "udp.example.com".to_string(),
                ..Default::default()
            }],
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("udp".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
            }),
            ..Default::default()
        });
        let quic_udp = Arc::new(ServerConfig {
            id: Some(20),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "quic.example.com@quic".to_string(),
                ..Default::default()
            }],
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("udp".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
            }),
            ..Default::default()
        });
        let mut servers = HashMap::new();
        servers.insert("udp.example.com".to_string(), normal_udp.clone());
        servers.insert("quic.example.com".to_string(), quic_udp.clone());
        store
            .update_config(
                1,
                1,
                0,
                0,
                vec![normal_udp, quic_udp],
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        let manager = UdpProxyManager::new(store, Arc::new(WafStateManager::new()), 1);
        let server = manager
            .find_server_for_packet(443, b"not a quic initial")
            .await
            .expect("normal UDP server should match first");
        assert_eq!(server.numeric_id(), 10);
    }

    #[tokio::test]
    async fn concurrent_udp_session_creation_runs_route_chain_once_and_shares_failure() {
        let store = ConfigStore::new();
        let manager = UdpProxyManager::new(store, Arc::new(WafStateManager::new()), 1);
        let server = Arc::new(ServerConfig {
            id: Some(999),
            is_on: true,
            ..Default::default()
        });
        let client_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let (downstream_tx, _downstream_rx) = mpsc::channel(4);
        let args = || UdpPassthroughSessionArgs {
            client_addr,
            port: 443,
            server: server.clone(),
            probed_server_name: None,
            downstream_sender: UdpDownstreamSender::channel(
                "127.0.0.1:443".parse().unwrap(),
                downstream_tx.clone(),
            ),
            shutdown_rx: shutdown_rx.clone(),
            quic_cid_tx: None,
        };

        let (first, second) = tokio::join!(
            manager.create_passthrough_session_for_server_with_cid_updates_and_downstream(args()),
            manager.create_passthrough_session_for_server_with_cid_updates_and_downstream(args()),
        );

        let first = match first {
            Err(err) => err.to_string(),
            Ok(_) => panic!("first creation unexpectedly succeeded"),
        };
        let second = match second {
            Err(err) => err.to_string(),
            Ok(_) => panic!("second creation unexpectedly succeeded"),
        };
        assert_eq!(first, "No load balancer found for server id 999");
        assert_eq!(second, first);
        assert_eq!(manager.session_creation_attempts.load(Ordering::Relaxed), 1);
        assert!(manager.inflight_sessions.is_empty());
    }

    #[tokio::test]
    async fn af_xdp_datagram_new_flow_queues_pending_and_drains_via_worker() {
        let store = ConfigStore::new();
        let udp_server = Arc::new(ServerConfig {
            id: Some(10),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "udp.example.com".to_string(),
                ..Default::default()
            }],
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("udp".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("443".to_string()),
                }],
            }),
            ..Default::default()
        });
        let mut servers = HashMap::new();
        servers.insert("udp.example.com".to_string(), udp_server.clone());
        store
            .update_config(
                1,
                1,
                0,
                0,
                vec![udp_server],
                servers,
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                true,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                false,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;

        let manager = UdpProxyManager::new(store, Arc::new(WafStateManager::new()), 1);
        let (downstream_tx, _downstream_rx) = mpsc::channel(8);
        let (_listener_shutdown_tx, listener_shutdown_rx) = watch::channel(false);
        let datagram = |payload: &'static [u8]| crate::xdp::af_xdp::AfXdpDatagram {
            listen_addr: "127.0.0.1:443".parse().unwrap(),
            peer_addr: "127.0.0.1:53000".parse().unwrap(),
            payload: Bytes::from_static(payload),
            ecn: None,
        };

        // Both datagrams must be accepted immediately (Sent) even though no
        // session exists yet — creation runs on the worker pool, not the
        // caller's ingress loop.
        let first = manager
            .receive_af_xdp_datagram(
                datagram(b"one"),
                downstream_tx.clone(),
                listener_shutdown_rx.clone(),
            )
            .await
            .unwrap();
        let second = manager
            .receive_af_xdp_datagram(datagram(b"two"), downstream_tx, listener_shutdown_rx)
            .await
            .unwrap();
        assert_eq!(first, UdpIngressDatagramStatus::Sent);
        assert_eq!(second, UdpIngressDatagramStatus::Sent);

        // The worker resolves the (LB-less) creation, fails it honestly,
        // and reaps the pending entry — no stuck map state.
        let deadline = Instant::now() + Duration::from_secs(5);
        while manager.session_creation_attempts.load(Ordering::Relaxed) == 0
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(manager.session_creation_attempts.load(Ordering::Relaxed), 1);
        while manager.pending_sessions_count.load(Ordering::Relaxed) != 0
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(manager.pending_sessions_count.load(Ordering::Relaxed), 0);
        assert!(manager.inflight_sessions.is_empty());
    }
}
