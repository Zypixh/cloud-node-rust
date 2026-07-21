use anyhow::{Context, Result};
use bytes::Bytes;
use core::range::Range;
use dashmap::DashMap;
use quinn::{AsyncUdpSocket, Endpoint, UdpPoller};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr as StdIpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, error, info};

use crate::config::ConfigStore;
use crate::http3_proxy_manager::Http3ProxyManager;
use crate::l4_defense::L4DefenseKind;
use crate::memory_governor::MEMORY_GOVERNOR;
use crate::net_bind::{bind_udp_socket, dual_stack_bind_addrs};
use crate::quic_probe::{QuicCryptoFragment, QuicProbeFragmentResult};
use crate::udp_proxy::{
    DownstreamUdpDatagram, UdpDownstreamSender, UdpIngressDatagramStatus, UdpProxyManager,
    UdpSession, UdpSessionQuicCid, UdpSessionSendStatus, udp_activity_is_alive,
    udp_activity_now_ms,
};

const MAX_DATAGRAM_SIZE: usize = 65_535;
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const H3_ROUTE_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const NEW_ROUTE_RATE_WINDOW: Duration = Duration::from_secs(10);
const MAX_NEW_ROUTE_IP_WINDOWS_PER_PORT: usize = 16_384;
const ROUTE_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);
const ROUTE_CLEANUP_PRESSURE_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Clone)]
enum RouteKind {
    Http3(Arc<AtomicU64>),
    Passthrough(Arc<UdpSession>),
}

struct H3Datagram {
    from: SocketAddr,
    data: Bytes,
    queued_bytes: Option<Arc<AtomicUsize>>,
}

impl Drop for H3Datagram {
    fn drop(&mut self) {
        if let Some(queued_bytes) = &self.queued_bytes {
            release_h3_queued_bytes(queued_bytes, self.data.len());
        }
    }
}

#[derive(Clone)]
struct UdpDemuxSharedState {
    routes: Arc<DashMap<SocketAddr, RouteKind>>,
    cid_routes: Arc<CidRoutes>,
    session_routes: Arc<SessionRoutes>,
    pending_routes: Arc<DashMap<SocketAddr, PendingQuicRoute>>,
    pending_reassembly_bytes: Arc<AtomicUsize>,
    h3_queued_bytes: Arc<AtomicUsize>,
    new_route_windows: Arc<DashMap<StdIpAddr, VecDeque<Instant>>>,
    next_pressure_cleanup_ms: Arc<AtomicU64>,
    h3_tx: mpsc::Sender<H3Datagram>,
    quic_cid_tx: mpsc::Sender<UdpSessionQuicCid>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct QuicConnectionId(Vec<u8>);

type CidRoutes = DashMap<usize, DashMap<QuicConnectionId, RouteKind>>;
type SessionRoutes = DashMap<u64, RouteKind>;

struct PendingQuicRoute {
    created_at: Instant,
    data: Vec<u8>,
    ranges: Vec<Range<usize>>,
    datagrams: Vec<Bytes>,
}

impl PendingQuicRoute {
    fn retained_bytes(&self) -> usize {
        self.data.len() + self.datagrams.iter().map(Bytes::len).sum::<usize>()
    }
}

fn new_demux_shared_state(
    queue_size: usize,
) -> (
    Arc<UdpDemuxSharedState>,
    mpsc::Receiver<H3Datagram>,
    mpsc::Receiver<UdpSessionQuicCid>,
) {
    let (h3_tx, h3_rx) = mpsc::channel(queue_size);
    let (quic_cid_tx, quic_cid_rx) = mpsc::channel(queue_size);
    (
        Arc::new(UdpDemuxSharedState {
            routes: Arc::new(DashMap::<SocketAddr, RouteKind>::new()),
            cid_routes: Arc::new(CidRoutes::new()),
            session_routes: Arc::new(SessionRoutes::new()),
            pending_routes: Arc::new(DashMap::<SocketAddr, PendingQuicRoute>::new()),
            pending_reassembly_bytes: Arc::new(AtomicUsize::new(0)),
            h3_queued_bytes: Arc::new(AtomicUsize::new(0)),
            new_route_windows: Arc::new(DashMap::<StdIpAddr, VecDeque<Instant>>::new()),
            next_pressure_cleanup_ms: Arc::new(AtomicU64::new(
                udp_activity_now_ms()
                    .saturating_add(ROUTE_CLEANUP_PRESSURE_INTERVAL.as_millis() as u64),
            )),
            h3_tx,
            quic_cid_tx,
        }),
        h3_rx,
        quic_cid_rx,
    )
}

struct SharedQuinnState {
    rx: Mutex<mpsc::Receiver<H3Datagram>>,
}

#[derive(Clone)]
struct SharedQuinnUdpSocket {
    downstream_sender: UdpDownstreamSender,
    local_addr: SocketAddr,
    state: Arc<SharedQuinnState>,
}

impl fmt::Debug for SharedQuinnUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedQuinnUdpSocket")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl SharedQuinnUdpSocket {
    fn new(
        downstream_sender: UdpDownstreamSender,
        local_addr: SocketAddr,
        rx: mpsc::Receiver<H3Datagram>,
    ) -> Self {
        Self {
            downstream_sender,
            local_addr,
            state: Arc::new(SharedQuinnState { rx: Mutex::new(rx) }),
        }
    }
}

impl AsyncUdpSocket for SharedQuinnUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SharedUdpPoller {
            downstream_sender: self.downstream_sender.clone(),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        debug!(
            "HTTP/3 shared UDP socket sending {} bytes to {}",
            transmit.contents.len(),
            transmit.destination
        );
        if let Some(segment_size) = transmit.segment_size {
            for segment in transmit.contents.chunks(segment_size) {
                self.downstream_sender
                    .try_send_to(segment, transmit.destination)?;
            }
            Ok(())
        } else {
            self.downstream_sender
                .try_send_to(transmit.contents, transmit.destination)
                .map(|_| ())
        }
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut rx = self
            .state
            .rx
            .lock()
            .map_err(|_| io::Error::other("HTTP/3 UDP receive queue lock poisoned"))?;

        match Pin::new(&mut *rx).poll_recv(cx) {
            Poll::Ready(Some(datagram)) => {
                debug!(
                    "HTTP/3 shared UDP socket received {} bytes from {}",
                    datagram.data.len(),
                    datagram.from
                );
                Poll::Ready(copy_datagram(datagram, &mut bufs[0], &mut meta[0]).map(|_| 1))
            }
            Poll::Ready(None) => Poll::Ready(Ok(0)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct SharedUdpPoller {
    downstream_sender: UdpDownstreamSender,
}

impl UdpPoller for SharedUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.downstream_sender.poll_send_ready(cx)
    }
}

async fn bind_udp_with_retry(
    bind_addr: SocketAddr,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> io::Result<UdpSocket> {
    let mut last_error = None;
    for _ in 0..100 {
        match bind_udp_socket(bind_addr).await {
            Ok(socket) => return Ok(socket),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                last_error = Some(err);
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "UDP listener shutdown while waiting for port reuse",
                        ));
                    }
                    _ = sleep(Duration::from_millis(50)) => {}
                }
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrInUse,
            "UDP listener port is still in use",
        )
    }))
}

fn trim_new_route_window(window: &mut VecDeque<Instant>, now: Instant) {
    while window
        .front()
        .is_some_and(|created_at| now.duration_since(*created_at) > NEW_ROUTE_RATE_WINDOW)
    {
        window.pop_front();
    }
}

fn is_new_route_rate_limited(
    windows: &DashMap<StdIpAddr, VecDeque<Instant>>,
    ip: StdIpAddr,
    max_new_routes_per_window: usize,
) -> bool {
    if !windows.contains_key(&ip) && windows.len() >= MAX_NEW_ROUTE_IP_WINDOWS_PER_PORT {
        return true;
    }
    let now = Instant::now();
    let mut window = windows.entry(ip).or_default();
    trim_new_route_window(&mut window, now);
    window.len() >= max_new_routes_per_window.max(1)
}

fn record_new_route_for_ip(windows: &DashMap<StdIpAddr, VecDeque<Instant>>, ip: StdIpAddr) {
    let now = Instant::now();
    let mut window = windows.entry(ip).or_default();
    trim_new_route_window(&mut window, now);
    window.push_back(now);
}

fn cleanup_new_route_windows(windows: &DashMap<StdIpAddr, VecDeque<Instant>>) {
    let now = Instant::now();
    windows.retain(|_, window| {
        trim_new_route_window(window, now);
        !window.is_empty()
    });
}

fn release_pending_reassembly_bytes(pending_reassembly_bytes: &AtomicUsize, bytes: usize) {
    let mut current = pending_reassembly_bytes.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_sub(bytes);
        match pending_reassembly_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn try_reserve_pending_reassembly_bytes(
    pending_reassembly_bytes: &AtomicUsize,
    additional_bytes: usize,
    pending_reassembly_budget_bytes: usize,
) -> bool {
    if additional_bytes == 0 {
        return true;
    }
    loop {
        let current = pending_reassembly_bytes.load(Ordering::Relaxed);
        let next = current.saturating_add(additional_bytes);
        if next > pending_reassembly_budget_bytes {
            return false;
        }
        if pending_reassembly_bytes
            .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
}

fn cleanup_pending_routes(
    pending_routes: &DashMap<SocketAddr, PendingQuicRoute>,
    pending_reassembly_bytes: &AtomicUsize,
    now: Instant,
    pending_route_timeout: Duration,
) {
    let expired = pending_routes
        .iter()
        .filter_map(|entry| {
            (now.duration_since(entry.value().created_at) >= pending_route_timeout)
                .then_some(*entry.key())
        })
        .collect::<Vec<_>>();
    for client_addr in expired {
        if let Some((_, pending)) = pending_routes.remove(&client_addr) {
            release_pending_reassembly_bytes(pending_reassembly_bytes, pending.retained_bytes());
        }
    }
}

fn merge_quic_fragment(
    pending: &mut PendingQuicRoute,
    fragment: QuicCryptoFragment,
    datagram: Bytes,
    pending_reassembly_bytes: &AtomicUsize,
    pending_reassembly_budget_bytes: usize,
    max_pending_datagrams_per_client: usize,
    max_pending_ranges_per_client: usize,
) -> bool {
    if pending.datagrams.len() >= max_pending_datagrams_per_client.max(1)
        || pending.ranges.len() + fragment.ranges.len() > max_pending_ranges_per_client.max(1)
        || fragment.data.len() > crate::quic_probe::MAX_CRYPTO_REASSEMBLY
    {
        return false;
    }
    let old_bytes = pending.retained_bytes();
    let new_data_len = pending.data.len().max(fragment.data.len());
    let new_bytes =
        new_data_len + pending.datagrams.iter().map(Bytes::len).sum::<usize>() + datagram.len();
    let additional_bytes = new_bytes.saturating_sub(old_bytes);
    if !try_reserve_pending_reassembly_bytes(
        pending_reassembly_bytes,
        additional_bytes,
        pending_reassembly_budget_bytes,
    ) {
        return false;
    }
    if pending.data.len() < fragment.data.len() {
        pending.data.resize(fragment.data.len(), 0);
    }
    for range in fragment.ranges {
        if let Some(data) = fragment.data.get(range.clone()) {
            pending.data[range.clone()].copy_from_slice(data);
            pending.ranges.push(range);
        }
    }
    pending.datagrams.push(datagram);
    true
}

fn pending_client_hello(pending: &PendingQuicRoute) -> Option<crate::quic_probe::QuicClientHello> {
    crate::quic_probe::parse_tls_client_hello_from_crypto(&pending.data, &pending.ranges)
}

fn client_hello_supports_h3(client_hello: &crate::quic_probe::QuicClientHello) -> bool {
    client_hello
        .alpns
        .iter()
        .any(|alpn| alpn == "h3" || alpn.starts_with("h3-"))
}

fn insert_cid_route(cid_routes: &CidRoutes, cid: QuicConnectionId, route: RouteKind) {
    if cid.0.is_empty() {
        return;
    }
    cid_routes
        .entry(cid.0.len())
        .or_default()
        .insert(cid, route);
}

fn lookup_cid_route(cid_routes: &CidRoutes, data: &[u8]) -> Option<RouteKind> {
    cid_routes.iter().find_map(|bucket| {
        short_header_dcid(data, *bucket.key())
            .and_then(|cid| bucket.value().get(&cid).map(|route| route.value().clone()))
    })
}

fn remove_cid_routes_for_route(cid_routes: &CidRoutes, route: &RouteKind) {
    cid_routes.retain(|_, bucket| {
        bucket.retain(|_, existing| !route_kind_same(existing, route));
        !bucket.is_empty()
    });
}

fn insert_session_cids(cid_routes: &CidRoutes, route: &RouteKind) {
    for cid in session_cids(route) {
        insert_cid_route(cid_routes, cid, route.clone());
    }
}

fn remove_cid_route(cid_routes: &CidRoutes, cid: &[u8]) {
    if cid.is_empty() {
        return;
    }
    if let Some(bucket) = cid_routes.get(&cid.len()) {
        bucket.remove(&QuicConnectionId(cid.to_vec()));
    }
}

fn apply_session_cid_update(
    update: UdpSessionQuicCid,
    session_routes: &SessionRoutes,
    cid_routes: &CidRoutes,
) {
    let route = session_routes
        .get(&update.session_id)
        .map(|entry| entry.value().clone());
    let Some(route) = route else {
        return;
    };
    if let Some(retired_cid) = update.retired_cid {
        remove_cid_route(cid_routes, &retired_cid);
    }
    insert_cid_route(cid_routes, QuicConnectionId(update.cid), route);
}

fn drain_session_cid_updates(
    updates: &mut mpsc::Receiver<UdpSessionQuicCid>,
    session_routes: &SessionRoutes,
    cid_routes: &CidRoutes,
) {
    while let Ok(update) = updates.try_recv() {
        apply_session_cid_update(update, session_routes, cid_routes);
    }
}

fn session_cids(route: &RouteKind) -> Vec<QuicConnectionId> {
    match route {
        RouteKind::Passthrough(session) => UdpProxyManager::session_quic_cids(session)
            .into_iter()
            .map(QuicConnectionId)
            .collect(),
        RouteKind::Http3(_) => Vec::new(),
    }
}

fn route_cids(data: &[u8]) -> Vec<QuicConnectionId> {
    crate::quic_probe::quic_packet_cids(data, 0)
        .into_iter()
        .flat_map(|cids| [Some(cids.dcid), cids.scid].into_iter().flatten())
        .filter(|cid| !cid.is_empty())
        .map(QuicConnectionId)
        .collect()
}

fn short_header_dcid(data: &[u8], cid_len: usize) -> Option<QuicConnectionId> {
    crate::quic_probe::quic_packet_cids(data, cid_len).map(|cids| QuicConnectionId(cids.dcid))
}

fn should_use_generic_h3_fallback(
    config_store: &ConfigStore,
    port: u16,
    client_hello: &crate::quic_probe::QuicClientHello,
    http3_enabled: bool,
) -> bool {
    http3_enabled
        && client_hello_supports_h3(client_hello)
        && !config_store.has_quic_passthrough_on_port_sync(port)
        && client_hello
            .server_name
            .as_deref()
            .is_some_and(|server_name| {
                config_store
                    .get_l7_server_for_tls_name_sync(server_name)
                    .is_some_and(|server| server_has_http3_on_port(config_store, &server, port))
            })
}

fn server_has_http3_on_port(
    config_store: &ConfigStore,
    server: &crate::config_models::ServerConfig,
    port: u16,
) -> bool {
    if config_store
        .get_global_http3_policy_sync()
        .is_some_and(|policy| policy.is_on && u16::try_from(policy.port).ok() == Some(port))
    {
        return server.https.as_ref().is_some_and(|https| https.is_on);
    }
    server.supports_http3_on_port(port)
}

fn route_session_id(route: &RouteKind) -> Option<u64> {
    match route {
        RouteKind::Passthrough(session) => Some(session.id),
        RouteKind::Http3(_) => None,
    }
}

fn remove_route_aliases(routes: &DashMap<SocketAddr, RouteKind>, route: &RouteKind) {
    if let Some(session_id) = route_session_id(route) {
        routes.retain(|_, existing| route_session_id(existing) != Some(session_id));
    }
}

fn insert_session_route(session_routes: &SessionRoutes, route: &RouteKind) {
    if let Some(session_id) = route_session_id(route) {
        session_routes.insert(session_id, route.clone());
    }
}

fn remove_session_route(session_routes: &SessionRoutes, route: &RouteKind) {
    if let Some(session_id) = route_session_id(route) {
        session_routes.remove(&session_id);
    }
}

fn route_kind_same(left: &RouteKind, right: &RouteKind) -> bool {
    match (left, right) {
        (RouteKind::Http3(left), RouteKind::Http3(right)) => Arc::ptr_eq(left, right),
        (RouteKind::Passthrough(left), RouteKind::Passthrough(right)) => left.id == right.id,
        _ => false,
    }
}

fn route_kind_is_active_with_pressure(
    route: &RouteKind,
    pressure_level: crate::l4_defense::L4PressureLevel,
) -> bool {
    match route {
        RouteKind::Http3(last_activity_ms) => {
            udp_activity_is_alive(last_activity_ms, h3_route_idle_timeout(pressure_level))
        }
        RouteKind::Passthrough(session) => {
            udp_activity_is_alive(&session.last_activity_ms, UDP_SESSION_IDLE_TIMEOUT)
        }
    }
}

fn h3_route_idle_timeout(pressure_level: crate::l4_defense::L4PressureLevel) -> Duration {
    match pressure_level {
        crate::l4_defense::L4PressureLevel::Normal => H3_ROUTE_IDLE_TIMEOUT,
        crate::l4_defense::L4PressureLevel::Elevated => Duration::from_secs(60),
        crate::l4_defense::L4PressureLevel::High => Duration::from_secs(20),
        crate::l4_defense::L4PressureLevel::Critical => Duration::from_secs(10),
    }
}

fn cleanup_routes(
    udp_manager: &UdpProxyManager,
    routes: &DashMap<SocketAddr, RouteKind>,
    cid_routes: &CidRoutes,
    pending_routes: &DashMap<SocketAddr, PendingQuicRoute>,
    pending_reassembly_bytes: &AtomicUsize,
    session_routes: &SessionRoutes,
) {
    cleanup_routes_with_pressure(
        udp_manager,
        routes,
        cid_routes,
        pending_routes,
        pending_reassembly_bytes,
        session_routes,
        crate::l4_defense::current_pressure_level(),
    );
}

fn cleanup_routes_with_pressure(
    udp_manager: &UdpProxyManager,
    routes: &DashMap<SocketAddr, RouteKind>,
    cid_routes: &CidRoutes,
    pending_routes: &DashMap<SocketAddr, PendingQuicRoute>,
    pending_reassembly_bytes: &AtomicUsize,
    session_routes: &SessionRoutes,
    pressure_level: crate::l4_defense::L4PressureLevel,
) {
    let now = Instant::now();
    cleanup_pending_routes(
        pending_routes,
        pending_reassembly_bytes,
        now,
        crate::l4_defense::quic_pending_route_timeout(pressure_level),
    );
    udp_manager.cleanup_idle_sessions(UDP_SESSION_IDLE_TIMEOUT);
    routes.retain(|_, route| route_kind_is_active_with_pressure(route, pressure_level));
    session_routes.retain(|_, route| route_kind_is_active_with_pressure(route, pressure_level));
    cid_routes.retain(|_, bucket| {
        bucket.retain(|_, route| route_kind_is_active_with_pressure(route, pressure_level));
        !bucket.is_empty()
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchStatus {
    Sent,
    Dropped,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H3QueueStatus {
    Sent,
    Full,
    ByteLimited,
    Closed,
}

fn release_h3_queued_bytes(h3_queued_bytes: &AtomicUsize, data_len: usize) {
    let mut current = h3_queued_bytes.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_sub(data_len);
        match h3_queued_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn try_queue_h3_datagram(
    h3_tx: &mpsc::Sender<H3Datagram>,
    h3_queued_bytes: &Arc<AtomicUsize>,
    client_addr: SocketAddr,
    data: Bytes,
    byte_budget: usize,
) -> H3QueueStatus {
    let data_len = data.len();
    loop {
        let current = h3_queued_bytes.load(Ordering::Relaxed);
        if current.saturating_add(data_len) > byte_budget {
            return H3QueueStatus::ByteLimited;
        }
        if h3_queued_bytes
            .compare_exchange_weak(
                current,
                current.saturating_add(data_len),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            break;
        }
    }

    match h3_tx.try_send(H3Datagram {
        from: client_addr,
        data,
        queued_bytes: Some(Arc::clone(h3_queued_bytes)),
    }) {
        Ok(()) => H3QueueStatus::Sent,
        Err(mpsc::error::TrySendError::Full(_)) => H3QueueStatus::Full,
        Err(mpsc::error::TrySendError::Closed(_)) => H3QueueStatus::Closed,
    }
}

fn copy_datagram(
    datagram: H3Datagram,
    buf: &mut IoSliceMut<'_>,
    meta: &mut quinn::udp::RecvMeta,
) -> io::Result<()> {
    if datagram.data.len() > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/3 UDP datagram exceeds receive buffer",
        ));
    }
    buf[..datagram.data.len()].copy_from_slice(&datagram.data);
    *meta = quinn::udp::RecvMeta {
        addr: datagram.from,
        len: datagram.data.len(),
        stride: datagram.data.len(),
        ecn: None,
        dst_ip: None,
    };
    Ok(())
}

struct ListenerHandle {
    id: u64,
    shutdown_tx: watch::Sender<bool>,
    http3_enabled: bool,
}

#[derive(Clone)]
struct AfXdpDemuxHandle {
    shared: Arc<UdpDemuxSharedState>,
    shutdown_tx: watch::Sender<bool>,
    http3_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UdpPortClassification {
    demux_ports: HashSet<u16>,
    plain_udp_ports: HashSet<u16>,
}

fn classify_udp_ports(
    http3_ports: &HashSet<u16>,
    udp_ports: &HashSet<u16>,
    quic_passthrough_ports: &HashSet<u16>,
) -> UdpPortClassification {
    let demux_ports = http3_ports
        .union(quic_passthrough_ports)
        .copied()
        .collect::<HashSet<_>>();
    let plain_udp_ports = udp_ports
        .difference(&demux_ports)
        .copied()
        .collect::<HashSet<_>>();

    UdpPortClassification {
        demux_ports,
        plain_udp_ports,
    }
}

pub struct QuicUdpDemuxManager {
    config_store: ConfigStore,
    http3_manager: Arc<Http3ProxyManager>,
    udp_manager: Arc<UdpProxyManager>,
    handled_ports: DashMap<SocketAddr, ListenerHandle>,
    af_xdp_ports: DashMap<SocketAddr, AfXdpDemuxHandle>,
    next_listener_id: AtomicU64,
}

impl QuicUdpDemuxManager {
    pub fn new(
        config_store: ConfigStore,
        http3_manager: Arc<Http3ProxyManager>,
        udp_manager: Arc<UdpProxyManager>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config_store,
            http3_manager,
            udp_manager,
            handled_ports: DashMap::new(),
            af_xdp_ports: DashMap::new(),
            next_listener_id: AtomicU64::new(1),
        })
    }

    pub async fn start_listeners(self: Arc<Self>) {
        let mut reconcile_tick = interval(Duration::from_secs(5));
        reconcile_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut reload_generation = self.config_store.runtime_reload_generation();
        let mut last_port_summary = None;
        loop {
            let http3_ports = self.http3_manager.desired_ports().await;
            let udp_ports = self.udp_manager.desired_ports().await;
            let quic_passthrough_ports = self.config_store.quic_passthrough_ports_sync();
            let classification =
                classify_udp_ports(&http3_ports, &udp_ports, &quic_passthrough_ports);
            let port_summary = (
                classification.plain_udp_ports.len(),
                classification.demux_ports.len(),
                http3_ports.len(),
                quic_passthrough_ports.len(),
            );
            if last_port_summary != Some(port_summary) {
                let message = format!(
                    "udp_direct_ports={} quic_demux_ports={} http3_ports={} quic_passthrough_ports={} udp_demux_workers={}",
                    port_summary.0,
                    port_summary.1,
                    port_summary.2,
                    port_summary.3,
                    MEMORY_GOVERNOR.udp_demux_worker_count()
                );
                info!("L4 UDP performance summary: {}", message);
                crate::logging::report_node_log(
                    "info".to_string(),
                    "l4_performance".to_string(),
                    message,
                    0,
                );
                last_port_summary = Some(port_summary);
            }
            let desired_listeners = classification
                .demux_ports
                .iter()
                .flat_map(|port| dual_stack_bind_addrs(*port))
                .collect::<HashSet<_>>();

            self.reconcile_listeners(&desired_listeners, &http3_ports);
            self.reconcile_af_xdp_handles(&classification.demux_ports, &http3_ports);
            self.udp_manager
                .sync_listeners_for_ports(&classification.plain_udp_ports)
                .await;

            for bind_addr in &desired_listeners {
                self.spawn_listener(*bind_addr, http3_ports.contains(&bind_addr.port()))
                    .await;
            }
            tokio::select! {
                generation = self.config_store.wait_for_runtime_reload(reload_generation) => {
                    reload_generation = generation;
                }
                _ = reconcile_tick.tick() => {}
            }
        }
    }

    async fn spawn_listener(self: &Arc<Self>, bind_addr: SocketAddr, http3_enabled: bool) {
        if let Some(existing) = self.handled_ports.get(&bind_addr) {
            if existing.http3_enabled == http3_enabled {
                return;
            }
            let _ = existing.shutdown_tx.send(true);
            drop(existing);
            self.handled_ports.remove(&bind_addr);
        }

        let listener_id = self.next_listener_id.fetch_add(1, Ordering::Relaxed);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.handled_ports.insert(
            bind_addr,
            ListenerHandle {
                id: listener_id,
                shutdown_tx,
                http3_enabled,
            },
        );
        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(err) = manager
                .clone()
                .run_listener(bind_addr, http3_enabled, shutdown_rx)
                .await
            {
                error!("QUIC UDP demux listener on {} failed: {}", bind_addr, err);
            }
            if manager
                .handled_ports
                .get(&bind_addr)
                .is_some_and(|entry| entry.id == listener_id)
            {
                manager.handled_ports.remove(&bind_addr);
            }
        });
    }

    fn reconcile_listeners(
        &self,
        desired_listeners: &HashSet<SocketAddr>,
        http3_ports: &HashSet<u16>,
    ) {
        let active_listeners = self
            .handled_ports
            .iter()
            .map(|entry| (*entry.key(), entry.value().http3_enabled))
            .collect::<Vec<_>>();
        for (bind_addr, http3_enabled) in active_listeners {
            let port = bind_addr.port();
            let desired_http3 = http3_ports.contains(&port);
            let keep = desired_listeners.contains(&bind_addr) && http3_enabled == desired_http3;
            if keep {
                continue;
            }
            if let Some((_, handle)) = self.handled_ports.remove(&bind_addr) {
                info!("QUIC UDP demux: stopping listener on {}", bind_addr);
                let _ = handle.shutdown_tx.send(true);
                self.udp_manager.remove_sessions_for_port(port);
            }
        }
    }

    fn reconcile_af_xdp_handles(
        &self,
        desired_demux_ports: &HashSet<u16>,
        http3_ports: &HashSet<u16>,
    ) {
        let active_handles = self
            .af_xdp_ports
            .iter()
            .map(|entry| (*entry.key(), entry.value().http3_enabled))
            .collect::<Vec<_>>();
        for (listen_addr, http3_enabled) in active_handles {
            let port = listen_addr.port();
            let desired_http3 = http3_ports.contains(&port);
            let keep = desired_demux_ports.contains(&port) && http3_enabled == desired_http3;
            if keep {
                continue;
            }
            if let Some((_, handle)) = self.af_xdp_ports.remove(&listen_addr) {
                info!(
                    "QUIC UDP demux: stopping AF_XDP handle on {} (http3={})",
                    listen_addr, http3_enabled
                );
                let _ = handle.shutdown_tx.send(true);
                self.udp_manager.remove_sessions_for_port(port);
            }
        }
    }

    pub async fn receive_af_xdp_datagram(
        self: &Arc<Self>,
        datagram: crate::xdp::af_xdp::AfXdpDatagram,
        downstream_tx: mpsc::Sender<DownstreamUdpDatagram>,
        fallback_shutdown_rx: watch::Receiver<bool>,
    ) -> Result<UdpIngressDatagramStatus> {
        let port = datagram.listen_addr.port();
        let Some(http3_enabled) = self.af_xdp_demux_http3_enabled_sync(port) else {
            if let Some((_, handle)) = self.af_xdp_ports.remove(&datagram.listen_addr) {
                let _ = handle.shutdown_tx.send(true);
            }
            return self
                .udp_manager
                .receive_af_xdp_datagram(datagram, downstream_tx, fallback_shutdown_rx)
                .await;
        };

        let handle = self
            .ensure_af_xdp_demux_handle(datagram.listen_addr, http3_enabled, downstream_tx.clone())
            .await?;
        self.process_datagram_with_downstream(
            port,
            datagram.peer_addr,
            datagram.payload,
            UdpDownstreamSender::channel(datagram.listen_addr, downstream_tx),
            &handle.shared,
            handle.http3_enabled,
            handle.shutdown_tx.subscribe(),
        )
        .await
    }

    fn af_xdp_demux_http3_enabled_sync(&self, port: u16) -> Option<bool> {
        let http3_ports = self.http3_manager.desired_ports_sync();
        if http3_ports.contains(&port) {
            return Some(true);
        }
        self.config_store
            .quic_passthrough_ports_sync()
            .contains(&port)
            .then_some(false)
    }

    async fn ensure_af_xdp_demux_handle(
        self: &Arc<Self>,
        listen_addr: SocketAddr,
        http3_enabled: bool,
        downstream_tx: mpsc::Sender<DownstreamUdpDatagram>,
    ) -> Result<AfXdpDemuxHandle> {
        if let Some(existing) = self.af_xdp_ports.get(&listen_addr) {
            if existing.http3_enabled == http3_enabled {
                return Ok(existing.clone());
            }
            let _ = existing.shutdown_tx.send(true);
            drop(existing);
            self.af_xdp_ports.remove(&listen_addr);
        }

        let h3_queue_size = MEMORY_GOVERNOR.h3_datagram_queue_size();
        let (shared, h3_rx, quic_cid_rx) = new_demux_shared_state(h3_queue_size);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        if http3_enabled {
            self.spawn_shared_h3_endpoint(
                listen_addr.port(),
                listen_addr,
                UdpDownstreamSender::channel(listen_addr, downstream_tx),
                h3_rx,
                shutdown_rx.clone(),
            )
            .await?;
        }
        self.spawn_udp_demux_maintenance(
            listen_addr.port(),
            shared.clone(),
            quic_cid_rx,
            shutdown_rx.clone(),
        );

        let handle = AfXdpDemuxHandle {
            shared,
            shutdown_tx,
            http3_enabled,
        };
        self.af_xdp_ports.insert(listen_addr, handle.clone());
        Ok(handle)
    }

    async fn run_listener(
        self: Arc<Self>,
        bind_addr: SocketAddr,
        http3_enabled: bool,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let port = bind_addr.port();
        let socket = Arc::new(bind_udp_with_retry(bind_addr, &mut shutdown_rx).await?);
        let local_addr = socket.local_addr()?;
        let h3_queue_size = MEMORY_GOVERNOR.h3_datagram_queue_size();
        let (shared, h3_rx, quic_cid_rx) = new_demux_shared_state(h3_queue_size);

        if http3_enabled {
            self.spawn_shared_h3_endpoint(
                port,
                local_addr,
                UdpDownstreamSender::socket(socket.clone()),
                h3_rx,
                shutdown_rx.clone(),
            )
            .await?;
        }

        info!(
            "QUIC UDP demux listening on {} (http3={}, workers={})",
            local_addr,
            http3_enabled,
            MEMORY_GOVERNOR.udp_demux_worker_count()
        );
        self.spawn_udp_demux_maintenance(port, shared.clone(), quic_cid_rx, shutdown_rx.clone());

        let worker_count = MEMORY_GOVERNOR.udp_demux_worker_count();
        for worker_id in 1..worker_count {
            let manager = self.clone();
            let worker_shared = shared.clone();
            let mut bind_shutdown = shutdown_rx.clone();
            let worker_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                let socket = match bind_udp_with_retry(bind_addr, &mut bind_shutdown).await {
                    Ok(socket) => Arc::new(socket),
                    Err(err) => {
                        error!(
                            "QUIC UDP demux worker {} failed to bind {}: {}",
                            worker_id, bind_addr, err
                        );
                        return;
                    }
                };
                if let Err(err) = manager
                    .run_udp_demux_worker(
                        bind_addr,
                        http3_enabled,
                        worker_id,
                        socket,
                        worker_shared,
                        worker_shutdown,
                    )
                    .await
                {
                    error!(
                        "QUIC UDP demux worker {} on {} failed: {}",
                        worker_id, bind_addr, err
                    );
                }
            });
        }

        self.run_udp_demux_worker(bind_addr, http3_enabled, 0, socket, shared, shutdown_rx)
            .await
    }

    async fn spawn_shared_h3_endpoint(
        self: &Arc<Self>,
        port: u16,
        local_addr: SocketAddr,
        downstream_sender: UdpDownstreamSender,
        h3_rx: mpsc::Receiver<H3Datagram>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let server_config = self
            .http3_manager
            .build_quinn_server_config()
            .await
            .context("build shared HTTP/3 Quinn server config")?;
        let runtime = quinn::default_runtime().context("no Quinn runtime available")?;
        let shared_socket = Arc::new(SharedQuinnUdpSocket::new(
            downstream_sender,
            local_addr,
            h3_rx,
        ));
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            shared_socket,
            runtime,
        )?;
        let http3_manager = self.http3_manager.clone();
        tokio::spawn(async move {
            if let Err(err) = http3_manager
                .run_endpoint(port, endpoint, shutdown_rx)
                .await
            {
                error!(
                    "shared HTTP/3 endpoint on UDP port {} failed: {}",
                    port, err
                );
            }
        });
        Ok(())
    }

    fn spawn_udp_demux_maintenance(
        &self,
        port: u16,
        shared: Arc<UdpDemuxSharedState>,
        mut quic_cid_rx: mpsc::Receiver<UdpSessionQuicCid>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let udp_manager = self.udp_manager.clone();
        tokio::spawn(async move {
            let mut cleanup_tick = interval(ROUTE_CLEANUP_INTERVAL);
            cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        return;
                    }
                    _ = cleanup_tick.tick() => {
                        cleanup_routes(
                            &udp_manager,
                            &shared.routes,
                            &shared.cid_routes,
                            &shared.pending_routes,
                            &shared.pending_reassembly_bytes,
                            &shared.session_routes,
                        );
                        cleanup_new_route_windows(&shared.new_route_windows);
                    }
                    update = quic_cid_rx.recv() => {
                        if let Some(update) = update {
                            apply_session_cid_update(update, &shared.session_routes, &shared.cid_routes);
                            drain_session_cid_updates(&mut quic_cid_rx, &shared.session_routes, &shared.cid_routes);
                        } else {
                            return;
                        }
                    }
                }
                debug!("QUIC UDP demux maintenance tick completed on port {}", port);
            }
        });
    }

    async fn run_udp_demux_worker(
        self: Arc<Self>,
        bind_addr: SocketAddr,
        http3_enabled: bool,
        worker_id: usize,
        socket: Arc<UdpSocket>,
        shared: Arc<UdpDemuxSharedState>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let port = bind_addr.port();
        let downstream_sender = UdpDownstreamSender::socket(socket.clone());
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        loop {
            let recv_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!(
                        "QUIC UDP demux worker {} on port {} shutting down",
                        worker_id, port
                    );
                    return Ok(());
                }
                result = socket.recv_from(&mut buf) => result,
            };
            let (len, client_addr) = recv_result?;
            debug!(
                "QUIC UDP demux: datagram received from {} on port {} bytes={} http3_enabled={}",
                client_addr, port, len, http3_enabled
            );
            let data = Bytes::copy_from_slice(&buf[..len]);
            let _ = self
                .process_datagram_with_downstream(
                    port,
                    client_addr,
                    data,
                    downstream_sender.clone(),
                    &shared,
                    http3_enabled,
                    shutdown_rx.clone(),
                )
                .await?;
        }
    }

    async fn process_datagram_with_downstream(
        &self,
        port: u16,
        client_addr: SocketAddr,
        data: Bytes,
        downstream_sender: UdpDownstreamSender,
        shared: &Arc<UdpDemuxSharedState>,
        http3_enabled: bool,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<UdpIngressDatagramStatus> {
        if self.udp_manager.is_l4_blocked(client_addr.ip()) {
            if let Some((_, route)) = shared.routes.remove(&client_addr) {
                remove_session_route(&shared.session_routes, &route);
                remove_cid_routes_for_route(&shared.cid_routes, &route);
                if let RouteKind::Passthrough(session) = &route {
                    let _ = session.shutdown_tx.send(true);
                }
            }
            return Ok(UdpIngressDatagramStatus::Blocked);
        }

        let max_routes_per_port = MEMORY_GOVERNOR.udp_route_limit_per_port();
        let pending_route_limit = MEMORY_GOVERNOR.quic_pending_route_limit_per_port();
        let pending_reassembly_budget_bytes =
            MEMORY_GOVERNOR.quic_pending_reassembly_budget_bytes();
        let pressure_level = crate::l4_defense::current_pressure_level_with_quic_usage(
            shared.routes.len(),
            max_routes_per_port,
            shared.pending_routes.len(),
            pending_route_limit,
            shared.pending_reassembly_bytes.load(Ordering::Relaxed),
            pending_reassembly_budget_bytes,
        );
        let max_new_routes_per_ip = crate::l4_defense::quic_new_route_limit(pressure_level);
        self.cleanup_routes_under_pressure(shared, max_routes_per_port, pressure_level);

        if let Some(route) = shared
            .routes
            .get(&client_addr)
            .map(|entry| entry.value().clone())
        {
            let status = self
                .dispatch_existing_route(
                    route.clone(),
                    client_addr,
                    data,
                    &shared.h3_tx,
                    &shared.h3_queued_bytes,
                    http3_enabled,
                    pressure_level,
                )
                .await;
            return Ok(self.record_existing_route_dispatch(shared, client_addr, route, status));
        }

        if let Some(route) = lookup_cid_route(&shared.cid_routes, &data) {
            let status = self
                .dispatch_existing_route(
                    route.clone(),
                    client_addr,
                    data,
                    &shared.h3_tx,
                    &shared.h3_queued_bytes,
                    http3_enabled,
                    pressure_level,
                )
                .await;
            return Ok(self.record_cid_route_dispatch(shared, client_addr, route, status));
        }

        if shared.routes.len() >= max_routes_per_port {
            cleanup_routes_with_pressure(
                &self.udp_manager,
                &shared.routes,
                &shared.cid_routes,
                &shared.pending_routes,
                &shared.pending_reassembly_bytes,
                &shared.session_routes,
                pressure_level,
            );
        }
        if shared.routes.len() >= max_routes_per_port {
            self.record_l4_event_with_pressure(
                client_addr,
                L4DefenseKind::QuicNewRouteFlood,
                format!(
                    "port={} peer={} routes={} limit={} pressure={}",
                    port,
                    client_addr,
                    shared.routes.len(),
                    max_routes_per_port,
                    pressure_level.as_str()
                ),
                pressure_level,
            );
            debug!(
                "QUIC UDP demux: route limit reached on port {}, dropping new client {}",
                port, client_addr
            );
            return Ok(UdpIngressDatagramStatus::Full);
        }

        let has_pending_route = shared.pending_routes.contains_key(&client_addr);
        if !has_pending_route
            && is_new_route_rate_limited(
                &shared.new_route_windows,
                client_addr.ip(),
                max_new_routes_per_ip,
            )
        {
            self.record_l4_event_with_pressure(
                client_addr,
                L4DefenseKind::QuicNewRouteFlood,
                format!(
                    "port={} peer={} rate_limited=true per_ip_window={} pressure={}",
                    port,
                    client_addr,
                    max_new_routes_per_ip,
                    pressure_level.as_str()
                ),
                pressure_level,
            );
            debug!(
                "QUIC UDP demux: new route rate limit reached for {} on port {}",
                client_addr.ip(),
                port
            );
            return Ok(UdpIngressDatagramStatus::Full);
        }

        let route = self
            .classify_new_route(
                port,
                client_addr,
                data,
                &shared.pending_routes,
                &shared.pending_reassembly_bytes,
                &shared.new_route_windows,
                &shared.h3_tx,
                &shared.h3_queued_bytes,
                http3_enabled,
                downstream_sender,
                shutdown_rx,
                shared.quic_cid_tx.clone(),
                pressure_level,
            )
            .await?;
        let Some((route, datagrams)) = route else {
            return Ok(UdpIngressDatagramStatus::NoRoute);
        };
        if !has_pending_route {
            record_new_route_for_ip(&shared.new_route_windows, client_addr.ip());
        }
        shared.routes.insert(client_addr, route.clone());
        insert_session_route(&shared.session_routes, &route);
        if let Some(first_datagram) = datagrams.first() {
            for cid in route_cids(first_datagram) {
                insert_cid_route(&shared.cid_routes, cid, route.clone());
            }
        }

        let mut result = UdpIngressDatagramStatus::Sent;
        for datagram in datagrams {
            let status = self
                .dispatch_existing_route(
                    route.clone(),
                    client_addr,
                    datagram,
                    &shared.h3_tx,
                    &shared.h3_queued_bytes,
                    http3_enabled,
                    pressure_level,
                )
                .await;
            match status {
                DispatchStatus::Sent => {}
                DispatchStatus::Dropped => result = UdpIngressDatagramStatus::Full,
                DispatchStatus::Closed => {
                    shared.routes.remove(&client_addr);
                    remove_session_route(&shared.session_routes, &route);
                    remove_cid_routes_for_route(&shared.cid_routes, &route);
                    return Ok(UdpIngressDatagramStatus::Closed);
                }
            }
        }
        Ok(result)
    }

    fn cleanup_routes_under_pressure(
        &self,
        shared: &UdpDemuxSharedState,
        max_routes_per_port: usize,
        pressure_level: crate::l4_defense::L4PressureLevel,
    ) {
        let route_cleanup_pressure_threshold = max_routes_per_port.saturating_mul(9) / 10;
        if shared.routes.len() < route_cleanup_pressure_threshold {
            return;
        }
        let now_ms = udp_activity_now_ms();
        let next_ms = shared.next_pressure_cleanup_ms.load(Ordering::Relaxed);
        if now_ms < next_ms {
            return;
        }
        let new_next = now_ms.saturating_add(ROUTE_CLEANUP_PRESSURE_INTERVAL.as_millis() as u64);
        if shared
            .next_pressure_cleanup_ms
            .compare_exchange(next_ms, new_next, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        cleanup_routes_with_pressure(
            &self.udp_manager,
            &shared.routes,
            &shared.cid_routes,
            &shared.pending_routes,
            &shared.pending_reassembly_bytes,
            &shared.session_routes,
            pressure_level,
        );
        cleanup_new_route_windows(&shared.new_route_windows);
    }

    fn record_existing_route_dispatch(
        &self,
        shared: &UdpDemuxSharedState,
        client_addr: SocketAddr,
        route: RouteKind,
        status: DispatchStatus,
    ) -> UdpIngressDatagramStatus {
        match status {
            DispatchStatus::Closed => {
                shared.routes.remove(&client_addr);
                remove_session_route(&shared.session_routes, &route);
                remove_cid_routes_for_route(&shared.cid_routes, &route);
                UdpIngressDatagramStatus::Closed
            }
            DispatchStatus::Sent => {
                insert_session_cids(&shared.cid_routes, &route);
                UdpIngressDatagramStatus::Sent
            }
            DispatchStatus::Dropped => {
                insert_session_cids(&shared.cid_routes, &route);
                UdpIngressDatagramStatus::Full
            }
        }
    }

    fn record_cid_route_dispatch(
        &self,
        shared: &UdpDemuxSharedState,
        client_addr: SocketAddr,
        route: RouteKind,
        status: DispatchStatus,
    ) -> UdpIngressDatagramStatus {
        match status {
            DispatchStatus::Closed => {
                remove_route_aliases(&shared.routes, &route);
                remove_session_route(&shared.session_routes, &route);
                remove_cid_routes_for_route(&shared.cid_routes, &route);
                UdpIngressDatagramStatus::Closed
            }
            DispatchStatus::Sent => {
                remove_route_aliases(&shared.routes, &route);
                insert_session_cids(&shared.cid_routes, &route);
                insert_session_route(&shared.session_routes, &route);
                shared.routes.insert(client_addr, route);
                UdpIngressDatagramStatus::Sent
            }
            DispatchStatus::Dropped => {
                remove_route_aliases(&shared.routes, &route);
                insert_session_cids(&shared.cid_routes, &route);
                insert_session_route(&shared.session_routes, &route);
                shared.routes.insert(client_addr, route);
                UdpIngressDatagramStatus::Full
            }
        }
    }

    async fn classify_new_route(
        &self,
        port: u16,
        client_addr: SocketAddr,
        data: Bytes,
        pending_routes: &DashMap<SocketAddr, PendingQuicRoute>,
        pending_reassembly_bytes: &AtomicUsize,
        new_route_windows: &DashMap<StdIpAddr, VecDeque<Instant>>,
        h3_tx: &mpsc::Sender<H3Datagram>,
        h3_queued_bytes: &Arc<AtomicUsize>,
        http3_enabled: bool,
        downstream_sender: UdpDownstreamSender,
        shutdown_rx: watch::Receiver<bool>,
        quic_cid_tx: mpsc::Sender<UdpSessionQuicCid>,
        pressure_level: crate::l4_defense::L4PressureLevel,
    ) -> Result<Option<(RouteKind, Vec<Bytes>)>> {
        match crate::quic_probe::probe_quic_client_hello_fragment_result(&data) {
            QuicProbeFragmentResult::Found(client_hello) => {
                debug!(
                    "QUIC UDP demux: ClientHello found from {} on port {} sni={:?} alpn={:?} http3_enabled={}",
                    client_addr, port, client_hello.server_name, client_hello.alpns, http3_enabled
                );
                let mut datagrams = pending_routes
                    .remove(&client_addr)
                    .map(|(_, pending)| {
                        release_pending_reassembly_bytes(
                            pending_reassembly_bytes,
                            pending.retained_bytes(),
                        );
                        pending.datagrams
                    })
                    .unwrap_or_default();
                datagrams.push(data.clone());
                self.route_for_client_hello(
                    port,
                    client_addr,
                    &data,
                    client_hello,
                    http3_enabled,
                    downstream_sender,
                    shutdown_rx,
                    quic_cid_tx.clone(),
                    pressure_level,
                )
                .await
                .map(|route| route.map(|route| (route, datagrams)))
            }
            QuicProbeFragmentResult::Incomplete(fragment) => {
                debug!(
                    "QUIC UDP demux: incomplete ClientHello from {} on port {} fragment_bytes={} ranges={} http3_enabled={}",
                    client_addr,
                    port,
                    fragment.data.len(),
                    fragment.ranges.len(),
                    http3_enabled
                );
                let is_new_pending_route = !pending_routes.contains_key(&client_addr);
                if is_new_pending_route
                    && is_new_route_rate_limited(
                        new_route_windows,
                        client_addr.ip(),
                        crate::l4_defense::quic_new_route_limit(pressure_level),
                    )
                {
                    self.record_l4_event_with_pressure(
                        client_addr,
                        L4DefenseKind::QuicIncompleteClientHello,
                        format!(
                            "port={} peer={} pending_rate_limited=true per_ip_window={} pressure={}",
                            port,
                            client_addr,
                            crate::l4_defense::quic_new_route_limit(pressure_level),
                            pressure_level.as_str()
                        ),
                        pressure_level,
                    );
                    debug!(
                        "QUIC UDP demux: pending route rate limit reached for {} on port {}",
                        client_addr.ip(),
                        port
                    );
                    return Ok(None);
                }
                let pending_route_limit = MEMORY_GOVERNOR.quic_pending_route_limit_per_port();
                if is_new_pending_route && pending_routes.len() >= pending_route_limit {
                    self.record_l4_event_with_pressure(
                        client_addr,
                        L4DefenseKind::QuicPendingReject,
                        format!(
                            "port={} peer={} pending={} limit={} pressure={}",
                            port,
                            client_addr,
                            pending_routes.len(),
                            pending_route_limit,
                            pressure_level.as_str()
                        ),
                        pressure_level,
                    );
                    debug!(
                        "QUIC UDP demux: pending route limit reached on port {}, dropping incomplete ClientHello from {}",
                        port, client_addr
                    );
                    return Ok(None);
                }

                let maybe_client_hello = {
                    if is_new_pending_route {
                        self.record_l4_event_with_pressure(
                            client_addr,
                            L4DefenseKind::QuicIncompleteClientHello,
                            format!(
                                "port={} peer={} fragment_bytes={} ranges={} pressure={}",
                                port,
                                client_addr,
                                fragment.data.len(),
                                fragment.ranges.len(),
                                pressure_level.as_str()
                            ),
                            pressure_level,
                        );
                    }
                    let mut pending = pending_routes.entry(client_addr).or_insert_with(|| {
                        record_new_route_for_ip(new_route_windows, client_addr.ip());
                        PendingQuicRoute {
                            created_at: Instant::now(),
                            data: Vec::new(),
                            ranges: Vec::new(),
                            datagrams: Vec::new(),
                        }
                    });
                    if !merge_quic_fragment(
                        &mut pending,
                        fragment,
                        data.clone(),
                        pending_reassembly_bytes,
                        MEMORY_GOVERNOR.quic_pending_reassembly_budget_bytes(),
                        crate::l4_defense::quic_pending_datagrams_limit(pressure_level),
                        crate::l4_defense::quic_pending_ranges_limit(pressure_level),
                    ) {
                        self.record_l4_event_with_pressure(
                            client_addr,
                            L4DefenseKind::QuicReassemblyReject,
                            format!(
                                "port={} peer={} pressure={} datagrams_limit={} ranges_limit={}",
                                port,
                                client_addr,
                                pressure_level.as_str(),
                                crate::l4_defense::quic_pending_datagrams_limit(pressure_level),
                                crate::l4_defense::quic_pending_ranges_limit(pressure_level)
                            ),
                            pressure_level,
                        );
                        drop(pending);
                        if let Some((_, pending)) = pending_routes.remove(&client_addr) {
                            release_pending_reassembly_bytes(
                                pending_reassembly_bytes,
                                pending.retained_bytes(),
                            );
                        }
                        return Ok(None);
                    }
                    pending_client_hello(&pending)
                };

                let Some(client_hello) = maybe_client_hello else {
                    if let Some(server) = self
                        .config_store
                        .find_unique_quic_passthrough_server_by_port_sync(port)
                    {
                        let datagrams = pending_routes
                            .remove(&client_addr)
                            .map(|(_, pending)| {
                                release_pending_reassembly_bytes(
                                    pending_reassembly_bytes,
                                    pending.retained_bytes(),
                                );
                                pending.datagrams
                            })
                            .unwrap_or_else(|| vec![data.clone()]);
                        let session = match self
                            .udp_manager
                            .create_passthrough_session_for_server_with_cid_updates_and_downstream(
                                client_addr,
                                port,
                                server,
                                None,
                                downstream_sender.clone(),
                                shutdown_rx,
                                Some(quic_cid_tx.clone()),
                            )
                            .await
                        {
                            Ok(session) => session,
                            Err(err) => {
                                debug!(
                                    "QUIC UDP demux: unique @quic session creation failed for incomplete ClientHello from {} on port {}: {}",
                                    client_addr, port, err
                                );
                                return Ok(None);
                            }
                        };
                        return Ok(
                            session.map(|session| (RouteKind::Passthrough(session), datagrams))
                        );
                    }
                    debug!(
                        "QUIC UDP demux: incomplete QUIC ClientHello from {} on port {}, waiting for next datagram",
                        client_addr, port
                    );
                    return Ok(None);
                };

                let datagrams = pending_routes
                    .remove(&client_addr)
                    .map(|(_, pending)| {
                        release_pending_reassembly_bytes(
                            pending_reassembly_bytes,
                            pending.retained_bytes(),
                        );
                        pending.datagrams
                    })
                    .unwrap_or_else(|| vec![data.clone()]);
                self.route_for_client_hello(
                    port,
                    client_addr,
                    &data,
                    client_hello,
                    http3_enabled,
                    downstream_sender,
                    shutdown_rx,
                    quic_cid_tx.clone(),
                    pressure_level,
                )
                .await
                .map(|route| route.map(|route| (route, datagrams)))
            }
            QuicProbeFragmentResult::None => {
                debug!(
                    "QUIC UDP demux: no ClientHello from {} on port {} datagram_bytes={} first_byte={:?} http3_enabled={}",
                    client_addr,
                    port,
                    data.len(),
                    data.first().copied(),
                    http3_enabled
                );
                if pending_routes.contains_key(&client_addr) {
                    debug!(
                        "QUIC UDP demux: waiting for QUIC ClientHello fragments from {} on port {}, dropping undecidable datagram",
                        client_addr, port
                    );
                    return Ok(None);
                }
                let session = match self
                    .udp_manager
                    .create_passthrough_session_with_downstream(
                        client_addr,
                        port,
                        &data,
                        downstream_sender.clone(),
                        shutdown_rx.clone(),
                    )
                    .await
                {
                    Ok(session) => session,
                    Err(err) => {
                        debug!(
                            "QUIC UDP demux: passthrough session creation failed for {} on port {}: {}",
                            client_addr, port, err
                        );
                        return Ok(None);
                    }
                };
                if let Some(session) = session {
                    return Ok(Some((RouteKind::Passthrough(session), vec![data])));
                }
                if http3_enabled && !self.config_store.has_quic_passthrough_on_port_sync(port) {
                    match try_queue_h3_datagram(
                        h3_tx,
                        h3_queued_bytes,
                        client_addr,
                        data,
                        MEMORY_GOVERNOR.h3_datagram_queue_budget_bytes(),
                    ) {
                        H3QueueStatus::Sent => {}
                        H3QueueStatus::Full => {
                            self.record_l4_event_with_pressure(
                                client_addr,
                                L4DefenseKind::H3AdmissionReject,
                                format!(
                                    "port={} peer={} reason=queue_full pressure={}",
                                    port,
                                    client_addr,
                                    pressure_level.as_str()
                                ),
                                pressure_level,
                            );
                            debug!(
                                "HTTP/3 shared UDP queue full, dropping undecidable datagram from {}",
                                client_addr
                            );
                        }
                        H3QueueStatus::ByteLimited => {
                            self.record_l4_event_with_pressure(
                                client_addr,
                                L4DefenseKind::H3AdmissionReject,
                                format!(
                                    "port={} peer={} reason=byte_limited pressure={}",
                                    port,
                                    client_addr,
                                    pressure_level.as_str()
                                ),
                                pressure_level,
                            );
                            debug!(
                                "HTTP/3 shared UDP queue byte budget full, dropping undecidable datagram from {}",
                                client_addr
                            );
                        }
                        H3QueueStatus::Closed => {
                            debug!(
                                "HTTP/3 shared UDP queue unavailable, dropping undecidable datagram from {}",
                                client_addr
                            );
                        }
                    }
                }
                Ok(None)
            }
        }
    }

    async fn route_for_client_hello(
        &self,
        port: u16,
        client_addr: SocketAddr,
        data: &[u8],
        client_hello: crate::quic_probe::QuicClientHello,
        http3_enabled: bool,
        downstream_sender: UdpDownstreamSender,
        shutdown_rx: watch::Receiver<bool>,
        quic_cid_tx: mpsc::Sender<UdpSessionQuicCid>,
        pressure_level: crate::l4_defense::L4PressureLevel,
    ) -> Result<Option<RouteKind>> {
        if let Some(server_name) = client_hello.server_name.as_deref() {
            if let Some(server) = self
                .config_store
                .find_exact_quic_passthrough_server_sync(server_name, port)
            {
                debug!(
                    "QUIC UDP demux: exact @quic {} on port {} matched server {} alpn={:?}",
                    server_name,
                    port,
                    server.numeric_id(),
                    client_hello.alpns
                );
                let session = match self
                    .udp_manager
                    .create_passthrough_session_for_server_with_cid_updates_and_downstream(
                        client_addr,
                        port,
                        server,
                        Some(server_name.to_string()),
                        downstream_sender.clone(),
                        shutdown_rx,
                        Some(quic_cid_tx.clone()),
                    )
                    .await
                {
                    Ok(session) => session,
                    Err(err) => {
                        debug!(
                            "QUIC UDP demux: exact @quic session creation failed for {} on port {}: {}",
                            client_addr, port, err
                        );
                        return Ok(None);
                    }
                };
                return Ok(session.map(RouteKind::Passthrough));
            }

            if http3_enabled && client_hello_supports_h3(&client_hello) {
                let l7_server = self
                    .config_store
                    .get_l7_server_for_tls_name_sync(server_name);
                debug!(
                    "QUIC UDP demux: L7 H3 candidate {} on port {} server={:?} accepts_http3={} alpn={:?}",
                    server_name,
                    port,
                    l7_server.as_ref().map(|server| server.numeric_id()),
                    l7_server
                        .as_ref()
                        .is_some_and(|server| server_has_http3_on_port(
                            &self.config_store,
                            server,
                            port
                        )),
                    client_hello.alpns
                );
                if l7_server.as_ref().is_some_and(|server| {
                    server_has_http3_on_port(&self.config_store, server, port)
                }) {
                    debug!(
                        "QUIC UDP demux: L7 H3 {} on port {} matched alpn={:?}",
                        server_name, port, client_hello.alpns
                    );
                    return Ok(Some(RouteKind::Http3(Arc::new(AtomicU64::new(
                        udp_activity_now_ms(),
                    )))));
                }
            }

            if let Some(server) = self
                .config_store
                .find_quic_passthrough_server_sync(server_name, port)
            {
                debug!(
                    "QUIC UDP demux: @quic {} on port {} matched server {} alpn={:?}",
                    server_name,
                    port,
                    server.numeric_id(),
                    client_hello.alpns
                );
                let session = match self
                    .udp_manager
                    .create_passthrough_session_for_server_with_cid_updates_and_downstream(
                        client_addr,
                        port,
                        server,
                        Some(server_name.to_string()),
                        downstream_sender.clone(),
                        shutdown_rx,
                        Some(quic_cid_tx.clone()),
                    )
                    .await
                {
                    Ok(session) => session,
                    Err(err) => {
                        debug!(
                            "QUIC UDP demux: @quic session creation failed for {} on port {}: {}",
                            client_addr, port, err
                        );
                        return Ok(None);
                    }
                };
                return Ok(session.map(RouteKind::Passthrough));
            }
        }

        if let Some(server) = self
            .config_store
            .find_unique_quic_passthrough_server_by_port_sync(port)
        {
            debug!(
                "QUIC UDP demux: @quic fallback on port {} matched unique server {} sni={:?} alpn={:?}",
                port,
                server.numeric_id(),
                client_hello.server_name,
                client_hello.alpns
            );
            let session = match self
                .udp_manager
                .create_passthrough_session_for_server_with_cid_updates_and_downstream(
                    client_addr,
                    port,
                    server,
                    client_hello.server_name.clone(),
                    downstream_sender.clone(),
                    shutdown_rx,
                    Some(quic_cid_tx.clone()),
                )
                .await
            {
                Ok(session) => session,
                Err(err) => {
                    debug!(
                        "QUIC UDP demux: @quic fallback session creation failed for {} on port {}: {}",
                        client_addr, port, err
                    );
                    return Ok(None);
                }
            };
            return Ok(session.map(RouteKind::Passthrough));
        }

        if should_use_generic_h3_fallback(&self.config_store, port, &client_hello, http3_enabled) {
            return Ok(Some(RouteKind::Http3(Arc::new(AtomicU64::new(
                udp_activity_now_ms(),
            )))));
        }

        let Some(server) = self.udp_manager.find_server_for_packet(port, data).await else {
            self.record_l4_event_with_pressure(
                client_addr,
                L4DefenseKind::QuicNoRoute,
                format!(
                    "port={} peer={} sni={:?} alpn={:?} pressure={}",
                    port,
                    client_addr,
                    client_hello.server_name,
                    client_hello.alpns,
                    pressure_level.as_str()
                ),
                pressure_level,
            );
            return Ok(None);
        };
        let session = match self
            .udp_manager
            .create_passthrough_session_for_server_with_downstream(
                client_addr,
                port,
                server,
                client_hello.server_name.clone(),
                downstream_sender,
                shutdown_rx,
            )
            .await
        {
            Ok(session) => session,
            Err(err) => {
                debug!(
                    "QUIC UDP demux: UDP session creation failed for {} on port {}: {}",
                    client_addr, port, err
                );
                return Ok(None);
            }
        };
        Ok(session.map(RouteKind::Passthrough))
    }

    async fn dispatch_existing_route(
        &self,
        route: RouteKind,
        client_addr: SocketAddr,
        data: Bytes,
        h3_tx: &mpsc::Sender<H3Datagram>,
        h3_queued_bytes: &Arc<AtomicUsize>,
        http3_enabled: bool,
        pressure_level: crate::l4_defense::L4PressureLevel,
    ) -> DispatchStatus {
        match route {
            RouteKind::Http3(last_activity_ms) => {
                if !http3_enabled {
                    return DispatchStatus::Closed;
                }
                match try_queue_h3_datagram(
                    h3_tx,
                    h3_queued_bytes,
                    client_addr,
                    data,
                    MEMORY_GOVERNOR.h3_datagram_queue_budget_bytes(),
                ) {
                    H3QueueStatus::Sent => {
                        last_activity_ms.store(udp_activity_now_ms(), Ordering::Relaxed);
                        DispatchStatus::Sent
                    }
                    H3QueueStatus::Full => {
                        self.record_l4_event_with_pressure(
                            client_addr,
                            L4DefenseKind::H3AdmissionReject,
                            format!(
                                "peer={} reason=queue_full pressure={}",
                                client_addr,
                                pressure_level.as_str()
                            ),
                            pressure_level,
                        );
                        debug!(
                            "HTTP/3 shared UDP queue full, dropping datagram from {}",
                            client_addr
                        );
                        DispatchStatus::Dropped
                    }
                    H3QueueStatus::ByteLimited => {
                        self.record_l4_event_with_pressure(
                            client_addr,
                            L4DefenseKind::H3AdmissionReject,
                            format!(
                                "peer={} reason=byte_limited pressure={}",
                                client_addr,
                                pressure_level.as_str()
                            ),
                            pressure_level,
                        );
                        debug!(
                            "HTTP/3 shared UDP queue byte budget full, dropping datagram from {}",
                            client_addr
                        );
                        DispatchStatus::Dropped
                    }
                    H3QueueStatus::Closed => DispatchStatus::Closed,
                }
            }
            RouteKind::Passthrough(session) => {
                match UdpProxyManager::send_to_session_from_client(&session, client_addr, data)
                    .await
                {
                    UdpSessionSendStatus::Sent => DispatchStatus::Sent,
                    UdpSessionSendStatus::Full => {
                        self.record_l4_event_with_pressure(
                            client_addr,
                            L4DefenseKind::UdpQueueFull,
                            format!(
                                "peer={} session={} pressure={}",
                                client_addr,
                                session.id,
                                pressure_level.as_str()
                            ),
                            pressure_level,
                        );
                        debug!(
                            "UDP passthrough session {} buffer full, dropping packet",
                            client_addr
                        );
                        DispatchStatus::Dropped
                    }
                    UdpSessionSendStatus::Closed => DispatchStatus::Closed,
                }
            }
        }
    }

    fn record_l4_event_with_pressure(
        &self,
        client_addr: SocketAddr,
        kind: L4DefenseKind,
        detail: impl Into<String>,
        pressure_level: crate::l4_defense::L4PressureLevel,
    ) -> crate::l4_defense::L4DefenseVerdict {
        self.udp_manager.record_l4_event_with_pressure(
            client_addr.ip(),
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
    use std::collections::{HashMap, HashSet};

    fn test_demux_manager(store: ConfigStore) -> Arc<QuicUdpDemuxManager> {
        let waf_state = Arc::new(crate::firewall::state::WafStateManager::new());
        let cert_selector = Arc::new(crate::ssl::DynamicCertSelector::new());
        let api_config = Arc::new(crate::api_config::ApiConfig {
            rpc_endpoints: Vec::new(),
            rpc_disable_update: true,
            node_id: "1".to_string(),
            secret: "test-secret".to_string(),
            billing_count_inbound_traffic: false,
            access_log_pipeline: crate::api_config::AccessLogPipelineConfig::default(),
            relay: crate::api_config::RelayConfig::default(),
            kernel_tuning: crate::api_config::KernelTuningConfig::default(),
        });
        let proxy_logic = crate::proxy::EdgeProxy {
            config: Arc::new(store.clone()),
            waf_state: waf_state.clone(),
            api_config: api_config.clone(),
            cert_selector: cert_selector.clone(),
            waf_verifier: Arc::new(crate::firewall::verifier::WafVerifier::new(
                &api_config.secret,
            )),
            tls_downstream: false,
        };
        let http3_manager = crate::http3_proxy_manager::Http3ProxyManager::new(
            store.clone(),
            cert_selector,
            proxy_logic,
            Arc::new(pingora_core::server::configuration::ServerConf::default()),
        );
        let udp_manager = crate::udp_proxy::UdpProxyManager::new(store.clone(), waf_state, 1);
        QuicUdpDemuxManager::new(store, http3_manager, udp_manager)
    }

    fn ports(values: &[u16]) -> HashSet<u16> {
        values.iter().copied().collect()
    }

    fn insert_test_af_xdp_handle(
        manager: &Arc<QuicUdpDemuxManager>,
        listen_addr: SocketAddr,
        http3_enabled: bool,
    ) -> watch::Receiver<bool> {
        let (shared, _h3_rx, _cid_rx) = new_demux_shared_state(1);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        manager.af_xdp_ports.insert(
            listen_addr,
            AfXdpDemuxHandle {
                shared,
                shutdown_tx,
                http3_enabled,
            },
        );
        shutdown_rx
    }

    #[test]
    fn short_header_matches_registered_connection_id() {
        let initial = [
            0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 3, 5, 6, 7, 0, 4, 0, 0, 0, 0,
        ];
        let cids = route_cids(&initial);
        assert!(cids.contains(&QuicConnectionId(vec![1, 2, 3, 4])));
        assert!(cids.contains(&QuicConnectionId(vec![5, 6, 7])));

        let short = [0x40, 1, 2, 3, 4, 0xaa];
        assert_eq!(
            short_header_dcid(&short, 4),
            Some(QuicConnectionId(vec![1, 2, 3, 4]))
        );
    }

    #[test]
    fn cid_routes_are_bucketed_by_connection_id_length() {
        let cid_routes = CidRoutes::new();
        let route = RouteKind::Http3(Arc::new(AtomicU64::new(udp_activity_now_ms())));
        insert_cid_route(
            &cid_routes,
            QuicConnectionId(vec![1, 2, 3, 4]),
            route.clone(),
        );

        assert!(cid_routes.get(&4).is_some());
        assert!(lookup_cid_route(&cid_routes, &[0x40, 1, 2, 3, 4, 0xaa]).is_some());
        assert!(lookup_cid_route(&cid_routes, &[0x40, 1, 2, 3, 5, 0xaa]).is_none());
    }

    #[test]
    fn non_h3_quic_alpns_do_not_match_http3() {
        for alpn in ["hysteria", "hysteria2", "hy2", "hq-29", "masque"] {
            let client_hello = crate::quic_probe::QuicClientHello {
                server_name: Some("hy2.example.com".to_string()),
                alpns: vec![alpn.to_string()],
            };
            assert!(
                !client_hello_supports_h3(&client_hello),
                "{alpn} must stay on UDP/@quic passthrough, not HTTP/3"
            );
        }

        let h3_client_hello = crate::quic_probe::QuicClientHello {
            server_name: Some("www.example.com".to_string()),
            alpns: vec!["h3".to_string(), "h3-29".to_string()],
        };
        assert!(client_hello_supports_h3(&h3_client_hello));
    }

    #[test]
    fn udp_port_classification_sends_plain_udp_directly() {
        let classification = classify_udp_ports(&ports(&[]), &ports(&[5300]), &ports(&[]));

        assert_eq!(classification.plain_udp_ports, ports(&[5300]));
        assert!(classification.demux_ports.is_empty());
    }

    #[test]
    fn udp_port_classification_demuxes_http3_and_quic_passthrough() {
        let classification = classify_udp_ports(
            &ports(&[443, 8443]),
            &ports(&[5300, 8443, 9443]),
            &ports(&[9443]),
        );

        assert_eq!(classification.demux_ports, ports(&[443, 8443, 9443]));
        assert_eq!(classification.plain_udp_ports, ports(&[5300]));
    }

    #[test]
    fn udp_port_classification_does_not_duplicate_mixed_ports() {
        let classification = classify_udp_ports(&ports(&[443]), &ports(&[443]), &ports(&[443]));

        assert_eq!(classification.demux_ports, ports(&[443]));
        assert!(classification.plain_udp_ports.is_empty());
    }

    #[test]
    fn session_cid_updates_insert_and_retire_demux_routes() {
        let session_routes = SessionRoutes::new();
        let cid_routes = CidRoutes::new();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = Arc::new(UdpSession {
            id: 77,
            client_addr: Arc::new(tokio::sync::RwLock::new("127.0.0.1:10000".parse().unwrap())),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(tokio::sync::RwLock::new(VecDeque::new())),
            quic_cid_tx: None,
            tx,
            shutdown_tx,
            shutdown,
        });
        session_routes.insert(77, RouteKind::Passthrough(session));
        let (cid_tx, mut cid_rx) = mpsc::channel(2);
        cid_tx
            .try_send(UdpSessionQuicCid {
                session_id: 77,
                cid: vec![1, 2, 3, 4],
                retired_cid: None,
            })
            .unwrap();
        cid_tx
            .try_send(UdpSessionQuicCid {
                session_id: 77,
                cid: vec![5, 6, 7, 8],
                retired_cid: Some(vec![1, 2, 3, 4]),
            })
            .unwrap();

        drain_session_cid_updates(&mut cid_rx, &session_routes, &cid_routes);

        assert!(lookup_cid_route(&cid_routes, &[0x40, 1, 2, 3, 4, 0xaa]).is_none());
        assert!(lookup_cid_route(&cid_routes, &[0x40, 5, 6, 7, 8, 0xaa]).is_some());
    }

    #[tokio::test]
    async fn h3_queue_byte_accounting_releases_when_datagram_is_dropped() {
        let (tx, mut rx) = mpsc::channel(2);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        assert_eq!(
            try_queue_h3_datagram(
                &tx,
                &queued_bytes,
                client_addr,
                Bytes::from_static(b"abcdef"),
                5,
            ),
            H3QueueStatus::ByteLimited
        );
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);

        assert_eq!(
            try_queue_h3_datagram(
                &tx,
                &queued_bytes,
                client_addr,
                Bytes::from_static(b"abcdef"),
                16,
            ),
            H3QueueStatus::Sent
        );
        assert_eq!(queued_bytes.load(Ordering::Acquire), 6);

        let datagram = rx.recv().await.expect("queued datagram");
        assert_eq!(datagram.data.as_ref(), b"abcdef");
        drop(datagram);
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn shared_quinn_udp_socket_can_send_to_channel_downstream() {
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (downstream_tx, mut downstream_rx) = mpsc::channel(2);
        let (_h3_tx, h3_rx) = mpsc::channel(1);
        let socket = SharedQuinnUdpSocket::new(
            UdpDownstreamSender::channel(listen_addr, downstream_tx),
            listen_addr,
            h3_rx,
        );

        socket
            .try_send(&quinn::udp::Transmit {
                destination: peer_addr,
                ecn: None,
                contents: b"h3 response",
                segment_size: None,
                src_ip: None,
            })
            .unwrap();

        let datagram = downstream_rx.recv().await.expect("downstream datagram");
        assert_eq!(datagram.listen_addr, listen_addr);
        assert_eq!(datagram.peer_addr, peer_addr);
        assert_eq!(&datagram.payload[..], b"h3 response");
    }

    #[tokio::test]
    async fn shared_quinn_udp_socket_receives_h3_datagram_and_releases_budget() {
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (downstream_tx, _downstream_rx) = mpsc::channel(2);
        let (h3_tx, h3_rx) = mpsc::channel(1);
        let queued_bytes = Arc::new(AtomicUsize::new(3));
        h3_tx
            .send(H3Datagram {
                from: peer_addr,
                data: Bytes::from_static(b"h3!"),
                queued_bytes: Some(queued_bytes.clone()),
            })
            .await
            .unwrap();
        let socket = SharedQuinnUdpSocket::new(
            UdpDownstreamSender::channel(listen_addr, downstream_tx),
            listen_addr,
            h3_rx,
        );
        let mut buf = [0u8; 16];
        let mut bufs = [IoSliceMut::new(&mut buf)];
        let mut meta = [quinn::udp::RecvMeta {
            addr: listen_addr,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];

        let count = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap();
        drop(bufs);

        assert_eq!(count, 1);
        assert_eq!(&buf[..3], b"h3!");
        assert_eq!(meta[0].addr, peer_addr);
        assert_eq!(meta[0].len, 3);
        assert_eq!(meta[0].stride, 3);
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn shared_quinn_udp_socket_releases_budget_when_recv_buffer_is_too_small() {
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (downstream_tx, _downstream_rx) = mpsc::channel(2);
        let (h3_tx, h3_rx) = mpsc::channel(1);
        let queued_bytes = Arc::new(AtomicUsize::new(8));
        h3_tx
            .send(H3Datagram {
                from: peer_addr,
                data: Bytes::from_static(b"too-wide"),
                queued_bytes: Some(queued_bytes.clone()),
            })
            .await
            .unwrap();
        let socket = SharedQuinnUdpSocket::new(
            UdpDownstreamSender::channel(listen_addr, downstream_tx),
            listen_addr,
            h3_rx,
        );
        let mut buf = [0u8; 4];
        let mut bufs = [IoSliceMut::new(&mut buf)];
        let mut meta = [quinn::udp::RecvMeta {
            addr: listen_addr,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];

        let err = std::future::poll_fn(|cx| socket.poll_recv(cx, &mut bufs, &mut meta))
            .await
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn af_xdp_datagram_without_demux_port_uses_udp_fallback_and_cleans_handle() {
        let manager = test_demux_manager(ConfigStore::new());
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let mut demux_shutdown_rx = insert_test_af_xdp_handle(&manager, listen_addr, true);
        let (downstream_tx, _downstream_rx) = mpsc::channel(1);
        let (_fallback_shutdown_tx, fallback_shutdown_rx) = watch::channel(false);

        let status = manager
            .receive_af_xdp_datagram(
                crate::xdp::af_xdp::AfXdpDatagram {
                    listen_addr,
                    peer_addr,
                    payload: Bytes::from_static(b"probe"),
                },
                downstream_tx,
                fallback_shutdown_rx,
            )
            .await
            .unwrap();

        assert_eq!(status, UdpIngressDatagramStatus::NoRoute);
        assert!(manager.af_xdp_ports.get(&listen_addr).is_none());
        tokio::time::timeout(Duration::from_secs(1), demux_shutdown_rx.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*demux_shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn af_xdp_reconcile_removes_stale_or_mode_changed_handles() {
        let manager = test_demux_manager(ConfigStore::new());
        let stale_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let changed_addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let keep_addr: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let mut stale_shutdown = insert_test_af_xdp_handle(&manager, stale_addr, false);
        let mut changed_shutdown = insert_test_af_xdp_handle(&manager, changed_addr, true);
        let keep_shutdown = insert_test_af_xdp_handle(&manager, keep_addr, true);

        manager.reconcile_af_xdp_handles(&ports(&[8443, 9443]), &ports(&[9443]));

        assert!(manager.af_xdp_ports.get(&stale_addr).is_none());
        assert!(manager.af_xdp_ports.get(&changed_addr).is_none());
        assert!(manager.af_xdp_ports.get(&keep_addr).is_some());
        tokio::time::timeout(Duration::from_secs(1), stale_shutdown.changed())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), changed_shutdown.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*stale_shutdown.borrow());
        assert!(*changed_shutdown.borrow());
        assert!(!*keep_shutdown.borrow());
    }

    #[test]
    fn pending_reassembly_byte_accounting_is_bounded_and_saturating() {
        let pending_bytes = AtomicUsize::new(9);

        assert!(!try_reserve_pending_reassembly_bytes(&pending_bytes, 2, 10));
        assert_eq!(pending_bytes.load(Ordering::Acquire), 9);

        assert!(try_reserve_pending_reassembly_bytes(&pending_bytes, 1, 10));
        assert_eq!(pending_bytes.load(Ordering::Acquire), 10);

        release_pending_reassembly_bytes(&pending_bytes, 128);
        assert_eq!(pending_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn new_route_rate_limit_uses_adaptive_pressure_limit() {
        let windows = DashMap::new();
        let ip: StdIpAddr = "203.0.113.200".parse().unwrap();
        let high_limit =
            crate::l4_defense::quic_new_route_limit(crate::l4_defense::L4PressureLevel::High);

        for _ in 0..high_limit {
            assert!(!is_new_route_rate_limited(&windows, ip, high_limit));
            record_new_route_for_ip(&windows, ip);
        }

        assert!(is_new_route_rate_limited(&windows, ip, high_limit));
    }

    #[test]
    fn pending_route_cleanup_releases_retained_bytes() {
        let pending_routes = DashMap::new();
        let pending_bytes = AtomicUsize::new(0);
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let pending_timeout = crate::l4_defense::quic_pending_route_timeout(
            crate::l4_defense::L4PressureLevel::Normal,
        );
        let pending = PendingQuicRoute {
            created_at: Instant::now() - pending_timeout - Duration::from_secs(1),
            data: vec![0; 8],
            ranges: Vec::new(),
            datagrams: vec![Bytes::from_static(b"abcdef")],
        };
        let retained = pending.retained_bytes();
        pending_bytes.store(retained, Ordering::Release);
        pending_routes.insert(client_addr, pending);

        cleanup_pending_routes(
            &pending_routes,
            &pending_bytes,
            Instant::now(),
            pending_timeout,
        );

        assert!(pending_routes.is_empty());
        assert_eq!(pending_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn rebind_alias_cleanup_keeps_single_socket_route_per_session() {
        let routes = DashMap::new();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = Arc::new(UdpSession {
            id: 77,
            client_addr: Arc::new(tokio::sync::RwLock::new("127.0.0.1:10000".parse().unwrap())),
            listen_port: 443,
            backend_addr: "127.0.0.1:20000".parse().unwrap(),
            origin_id: 1,
            server_id: 1,
            user_id: 0,
            user_plan_id: 0,
            plan_id: 0,
            last_activity_ms: Arc::new(AtomicU64::new(udp_activity_now_ms())),
            quic_cids: Arc::new(tokio::sync::RwLock::new(VecDeque::new())),
            quic_cid_tx: None,
            tx,
            shutdown_tx,
            shutdown,
        });
        let route = RouteKind::Passthrough(session);
        routes.insert("127.0.0.1:10000".parse().unwrap(), route.clone());

        remove_route_aliases(&routes, &route);
        routes.insert("127.0.0.1:10001".parse().unwrap(), route.clone());

        assert_eq!(routes.len(), 1);
        assert!(
            routes
                .get(&"127.0.0.1:10001".parse::<SocketAddr>().unwrap())
                .is_some()
        );
    }

    #[tokio::test]
    async fn generic_h3_fallback_requires_bound_http3_host() {
        let store = ConfigStore::new();
        let quic_server = Arc::new(crate::config_models::ServerConfig {
            id: Some(9),
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
        let h3_server = Arc::new(crate::config_models::ServerConfig {
            id: Some(10),
            is_on: true,
            server_names: vec![ServerNameConfig {
                name: "h3.example.com".to_string(),
                ..Default::default()
            }],
            https: Some(crate::config_models::HTTPSConfig {
                is_on: true,
                listen: vec![NetworkAddressConfig {
                    protocol: Some("https".to_string()),
                    host: Some("0.0.0.0".to_string()),
                    port_range: Some("8443".to_string()),
                }],
                ssl_policy: None,
                supports_http3: Some(true),
            }),
            ..Default::default()
        });
        let mut servers = HashMap::new();
        servers.insert("quic.example.com".to_string(), quic_server.clone());
        servers.insert("h3.example.com".to_string(), h3_server.clone());
        store
            .update_config(
                1,
                1,
                0,
                0,
                vec![quic_server, h3_server],
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

        let client_hello = crate::quic_probe::QuicClientHello {
            server_name: Some("other.example.com".to_string()),
            alpns: vec!["h3".to_string()],
        };

        assert!(!should_use_generic_h3_fallback(
            &store,
            443,
            &client_hello,
            true
        ));
        assert!(!should_use_generic_h3_fallback(
            &store,
            8443,
            &client_hello,
            true
        ));

        let bound_client_hello = crate::quic_probe::QuicClientHello {
            server_name: Some("h3.example.com".to_string()),
            alpns: vec!["h3".to_string()],
        };
        assert!(should_use_generic_h3_fallback(
            &store,
            8443,
            &bound_client_hello,
            true
        ));
        assert!(!should_use_generic_h3_fallback(
            &store,
            443,
            &bound_client_hello,
            true
        ));
    }
}
