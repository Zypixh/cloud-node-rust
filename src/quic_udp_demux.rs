use anyhow::{Context, Result};
use bytes::Bytes;
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
use crate::net_bind::{bind_udp_socket, dual_stack_bind_addrs};
use crate::quic_probe::{QuicCryptoFragment, QuicProbeFragmentResult};
use crate::udp_proxy::{
    UdpProxyManager, UdpSession, UdpSessionQuicCid, UdpSessionSendStatus, udp_activity_is_alive,
    udp_activity_now_ms,
};

const MAX_DATAGRAM_SIZE: usize = 65_535;
const H3_QUEUE_SIZE: usize = 8192;
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const H3_ROUTE_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const PENDING_QUIC_ROUTE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_ROUTES_PER_PORT: usize = 65_536;
const MAX_NEW_ROUTES_PER_IP_WINDOW: usize = 128;
const NEW_ROUTE_RATE_WINDOW: Duration = Duration::from_secs(10);
const MAX_NEW_ROUTE_IP_WINDOWS_PER_PORT: usize = 16_384;
const MAX_PENDING_ROUTES_PER_PORT: usize = 2048;
const MAX_PENDING_REASSEMBLY_BYTES_PER_PORT: usize = 16 * 1024 * 1024;
const ROUTE_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);
const ROUTE_CLEANUP_PRESSURE_INTERVAL: Duration = Duration::from_millis(200);
const ROUTE_CLEANUP_PRESSURE_THRESHOLD: usize = MAX_ROUTES_PER_PORT * 9 / 10;
const MAX_PENDING_DATAGRAMS_PER_CLIENT: usize = 4;
const MAX_PENDING_RANGES_PER_CLIENT: usize = 16;

#[derive(Clone)]
enum RouteKind {
    Http3(Arc<AtomicU64>),
    Passthrough(Arc<UdpSession>),
}

struct H3Datagram {
    from: SocketAddr,
    data: Bytes,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct QuicConnectionId(Vec<u8>);

type CidRoutes = DashMap<usize, DashMap<QuicConnectionId, RouteKind>>;
type SessionRoutes = DashMap<u64, RouteKind>;

struct PendingQuicRoute {
    created_at: Instant,
    data: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    datagrams: Vec<Bytes>,
}

impl PendingQuicRoute {
    fn retained_bytes(&self) -> usize {
        self.data.len() + self.datagrams.iter().map(Bytes::len).sum::<usize>()
    }
}

struct SharedQuinnState {
    rx: Mutex<mpsc::Receiver<H3Datagram>>,
}

#[derive(Clone)]
struct SharedQuinnUdpSocket {
    socket: Arc<UdpSocket>,
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
    fn new(socket: Arc<UdpSocket>, local_addr: SocketAddr, rx: mpsc::Receiver<H3Datagram>) -> Self {
        Self {
            socket,
            local_addr,
            state: Arc::new(SharedQuinnState { rx: Mutex::new(rx) }),
        }
    }
}

impl AsyncUdpSocket for SharedQuinnUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SharedUdpPoller {
            socket: self.socket.clone(),
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
                self.socket.try_send_to(segment, transmit.destination)?;
            }
            Ok(())
        } else {
            self.socket
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
    socket: Arc<UdpSocket>,
}

impl UdpPoller for SharedUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
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
) -> bool {
    if !windows.contains_key(&ip) && windows.len() >= MAX_NEW_ROUTE_IP_WINDOWS_PER_PORT {
        return true;
    }
    let now = Instant::now();
    let mut window = windows.entry(ip).or_default();
    trim_new_route_window(&mut window, now);
    window.len() >= MAX_NEW_ROUTES_PER_IP_WINDOW
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

fn pending_retained_bytes(
    pending_routes: &DashMap<SocketAddr, PendingQuicRoute>,
    pending_reassembly_bytes: &AtomicUsize,
) -> usize {
    let bytes = pending_routes
        .iter()
        .map(|entry| entry.value().retained_bytes())
        .sum();
    pending_reassembly_bytes.store(bytes, Ordering::Relaxed);
    bytes
}

fn merge_quic_fragment(
    pending: &mut PendingQuicRoute,
    fragment: QuicCryptoFragment,
    datagram: Bytes,
    pending_reassembly_bytes: &AtomicUsize,
) -> bool {
    if pending.datagrams.len() >= MAX_PENDING_DATAGRAMS_PER_CLIENT
        || pending.ranges.len() + fragment.ranges.len() > MAX_PENDING_RANGES_PER_CLIENT
        || fragment.data.len() > crate::quic_probe::MAX_CRYPTO_REASSEMBLY
    {
        return false;
    }
    let old_bytes = pending.retained_bytes();
    let new_data_len = pending.data.len().max(fragment.data.len());
    let new_bytes =
        new_data_len + pending.datagrams.iter().map(Bytes::len).sum::<usize>() + datagram.len();
    let additional_bytes = new_bytes.saturating_sub(old_bytes);
    let current = pending_reassembly_bytes.load(Ordering::Relaxed);
    if current.saturating_add(additional_bytes) > MAX_PENDING_REASSEMBLY_BYTES_PER_PORT {
        return false;
    }
    if pending.data.len() < fragment.data.len() {
        pending.data.resize(fragment.data.len(), 0);
    }
    for (start, end) in fragment.ranges {
        if let Some(data) = fragment.data.get(start..end) {
            pending.data[start..end].copy_from_slice(data);
            pending.ranges.push((start, end));
        }
    }
    pending.datagrams.push(datagram);
    pending_reassembly_bytes.fetch_add(additional_bytes, Ordering::Relaxed);
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

fn route_kind_is_active(route: &RouteKind) -> bool {
    match route {
        RouteKind::Http3(last_activity_ms) => {
            udp_activity_is_alive(last_activity_ms, H3_ROUTE_IDLE_TIMEOUT)
        }
        RouteKind::Passthrough(session) => {
            udp_activity_is_alive(&session.last_activity_ms, UDP_SESSION_IDLE_TIMEOUT)
        }
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
    let now = Instant::now();
    pending_routes
        .retain(|_, pending| now.duration_since(pending.created_at) < PENDING_QUIC_ROUTE_TIMEOUT);
    pending_retained_bytes(pending_routes, pending_reassembly_bytes);
    udp_manager.cleanup_idle_sessions(UDP_SESSION_IDLE_TIMEOUT);
    routes.retain(|_, route| route_kind_is_active(route));
    session_routes.retain(|_, route| route_kind_is_active(route));
    cid_routes.retain(|_, bucket| {
        bucket.retain(|_, route| route_kind_is_active(route));
        !bucket.is_empty()
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchStatus {
    Sent,
    Dropped,
    Closed,
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

pub struct QuicUdpDemuxManager {
    config_store: ConfigStore,
    http3_manager: Arc<Http3ProxyManager>,
    udp_manager: Arc<UdpProxyManager>,
    handled_ports: DashMap<SocketAddr, ListenerHandle>,
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
            next_listener_id: AtomicU64::new(1),
        })
    }

    pub async fn start_listeners(self: Arc<Self>) {
        let mut reconcile_tick = interval(Duration::from_secs(5));
        reconcile_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            let http3_ports = self.http3_manager.desired_ports().await;
            let udp_ports = self.udp_manager.desired_ports().await;
            let desired_ports = http3_ports
                .union(&udp_ports)
                .copied()
                .collect::<HashSet<_>>();
            let desired_listeners = desired_ports
                .iter()
                .flat_map(|port| dual_stack_bind_addrs(*port))
                .collect::<HashSet<_>>();

            for bind_addr in &desired_listeners {
                self.spawn_listener(*bind_addr, http3_ports.contains(&bind_addr.port()))
                    .await;
            }
            self.reconcile_listeners(&desired_listeners, &http3_ports);
            tokio::select! {
                _ = self.config_store.wait_for_runtime_reload() => {}
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

    async fn run_listener(
        self: Arc<Self>,
        bind_addr: SocketAddr,
        http3_enabled: bool,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let port = bind_addr.port();
        let socket = Arc::new(bind_udp_with_retry(bind_addr, &mut shutdown_rx).await?);
        let local_addr = socket.local_addr()?;
        let routes = Arc::new(DashMap::<SocketAddr, RouteKind>::new());
        let cid_routes = Arc::new(CidRoutes::new());
        let session_routes = Arc::new(SessionRoutes::new());
        let pending_routes = Arc::new(DashMap::<SocketAddr, PendingQuicRoute>::new());
        let pending_reassembly_bytes = AtomicUsize::new(0);
        let new_route_windows = Arc::new(DashMap::<StdIpAddr, VecDeque<Instant>>::new());
        let (h3_tx, h3_rx) = mpsc::channel(H3_QUEUE_SIZE);
        let (quic_cid_tx, mut quic_cid_rx) = mpsc::channel(H3_QUEUE_SIZE);

        if http3_enabled {
            let server_config = self
                .http3_manager
                .build_quinn_server_config()
                .await
                .context("build shared HTTP/3 Quinn server config")?;
            let runtime = quinn::default_runtime().context("no Quinn runtime available")?;
            let shared_socket =
                Arc::new(SharedQuinnUdpSocket::new(socket.clone(), local_addr, h3_rx));
            let endpoint = Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server_config),
                shared_socket,
                runtime,
            )?;
            let http3_manager = self.http3_manager.clone();
            let h3_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(err) = http3_manager
                    .run_endpoint(port, endpoint, h3_shutdown)
                    .await
                {
                    error!(
                        "shared HTTP/3 endpoint on UDP port {} failed: {}",
                        port, err
                    );
                }
            });
        }

        info!(
            "QUIC UDP demux listening on {} (http3={})",
            local_addr, http3_enabled
        );
        let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
        let mut cleanup_tick = interval(ROUTE_CLEANUP_INTERVAL);
        cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut next_pressure_cleanup = Instant::now() + ROUTE_CLEANUP_PRESSURE_INTERVAL;
        loop {
            drain_session_cid_updates(&mut quic_cid_rx, &session_routes, &cid_routes);
            let recv_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("QUIC UDP demux listener on port {} shutting down", port);
                    return Ok(());
                }
                _ = cleanup_tick.tick() => {
                    cleanup_routes(
                        &self.udp_manager,
                        &routes,
                        &cid_routes,
                        &pending_routes,
                        &pending_reassembly_bytes,
                        &session_routes,
                    );
                    cleanup_new_route_windows(&new_route_windows);
                    continue;
                }
                update = quic_cid_rx.recv() => {
                    if let Some(update) = update {
                        apply_session_cid_update(update, &session_routes, &cid_routes);
                        drain_session_cid_updates(&mut quic_cid_rx, &session_routes, &cid_routes);
                    }
                    continue;
                }
                result = socket.recv_from(&mut buf) => result,
            };
            let (len, client_addr) = recv_result?;
            debug!(
                "QUIC UDP demux: datagram received from {} on port {} bytes={} http3_enabled={}",
                client_addr, port, len, http3_enabled
            );
            let data = Bytes::copy_from_slice(&buf[..len]);

            let now = Instant::now();
            if routes.len() >= ROUTE_CLEANUP_PRESSURE_THRESHOLD && now >= next_pressure_cleanup {
                cleanup_routes(
                    &self.udp_manager,
                    &routes,
                    &cid_routes,
                    &pending_routes,
                    &pending_reassembly_bytes,
                    &session_routes,
                );
                cleanup_new_route_windows(&new_route_windows);
                next_pressure_cleanup = now + ROUTE_CLEANUP_PRESSURE_INTERVAL;
            }

            if let Some(route) = routes.get(&client_addr).map(|entry| entry.value().clone()) {
                if self
                    .dispatch_existing_route(
                        route.clone(),
                        client_addr,
                        data,
                        &h3_tx,
                        http3_enabled,
                    )
                    .await
                    == DispatchStatus::Closed
                {
                    routes.remove(&client_addr);
                    remove_session_route(&session_routes, &route);
                    remove_cid_routes_for_route(&cid_routes, &route);
                } else {
                    insert_session_cids(&cid_routes, &route);
                }
                continue;
            }

            if let Some(route) = lookup_cid_route(&cid_routes, &data) {
                match self
                    .dispatch_existing_route(
                        route.clone(),
                        client_addr,
                        data,
                        &h3_tx,
                        http3_enabled,
                    )
                    .await
                {
                    DispatchStatus::Closed => {
                        remove_route_aliases(&routes, &route);
                        remove_session_route(&session_routes, &route);
                        remove_cid_routes_for_route(&cid_routes, &route);
                    }
                    DispatchStatus::Sent | DispatchStatus::Dropped => {
                        remove_route_aliases(&routes, &route);
                        insert_session_cids(&cid_routes, &route);
                        insert_session_route(&session_routes, &route);
                        routes.insert(client_addr, route);
                    }
                }
                continue;
            }

            if routes.len() >= MAX_ROUTES_PER_PORT {
                cleanup_routes(
                    &self.udp_manager,
                    &routes,
                    &cid_routes,
                    &pending_routes,
                    &pending_reassembly_bytes,
                    &session_routes,
                );
            }
            if routes.len() >= MAX_ROUTES_PER_PORT {
                debug!(
                    "QUIC UDP demux: route limit reached on port {}, dropping new client {}",
                    port, client_addr
                );
                continue;
            }
            let has_pending_route = pending_routes.contains_key(&client_addr);
            if !has_pending_route && is_new_route_rate_limited(&new_route_windows, client_addr.ip())
            {
                debug!(
                    "QUIC UDP demux: new route rate limit reached for {} on port {}",
                    client_addr.ip(),
                    port
                );
                continue;
            }

            let route = self
                .classify_new_route(
                    port,
                    client_addr,
                    data,
                    &pending_routes,
                    &pending_reassembly_bytes,
                    &new_route_windows,
                    &h3_tx,
                    http3_enabled,
                    socket.clone(),
                    shutdown_rx.clone(),
                    quic_cid_tx.clone(),
                )
                .await?;
            let Some((route, datagrams)) = route else {
                continue;
            };
            if !has_pending_route {
                record_new_route_for_ip(&new_route_windows, client_addr.ip());
            }
            routes.insert(client_addr, route.clone());
            insert_session_route(&session_routes, &route);
            if let Some(first_datagram) = datagrams.first() {
                for cid in route_cids(first_datagram) {
                    insert_cid_route(&cid_routes, cid, route.clone());
                }
            }
            for datagram in datagrams {
                if self
                    .dispatch_existing_route(
                        route.clone(),
                        client_addr,
                        datagram,
                        &h3_tx,
                        http3_enabled,
                    )
                    .await
                    == DispatchStatus::Closed
                {
                    routes.remove(&client_addr);
                    remove_session_route(&session_routes, &route);
                    remove_cid_routes_for_route(&cid_routes, &route);
                    break;
                }
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
        http3_enabled: bool,
        socket: Arc<UdpSocket>,
        shutdown_rx: watch::Receiver<bool>,
        quic_cid_tx: mpsc::Sender<UdpSessionQuicCid>,
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
                        pending_reassembly_bytes
                            .fetch_sub(pending.retained_bytes(), Ordering::Relaxed);
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
                    socket,
                    shutdown_rx,
                    quic_cid_tx.clone(),
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
                    && is_new_route_rate_limited(new_route_windows, client_addr.ip())
                {
                    debug!(
                        "QUIC UDP demux: pending route rate limit reached for {} on port {}",
                        client_addr.ip(),
                        port
                    );
                    return Ok(None);
                }
                if is_new_pending_route && pending_routes.len() >= MAX_PENDING_ROUTES_PER_PORT {
                    debug!(
                        "QUIC UDP demux: pending route limit reached on port {}, dropping incomplete ClientHello from {}",
                        port, client_addr
                    );
                    return Ok(None);
                }

                let maybe_client_hello = {
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
                        &pending_reassembly_bytes,
                    ) {
                        drop(pending);
                        if let Some((_, pending)) = pending_routes.remove(&client_addr) {
                            pending_reassembly_bytes
                                .fetch_sub(pending.retained_bytes(), Ordering::Relaxed);
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
                                pending_reassembly_bytes
                                    .fetch_sub(pending.retained_bytes(), Ordering::Relaxed);
                                pending.datagrams
                            })
                            .unwrap_or_else(|| vec![data.clone()]);
                        let session = match self
                            .udp_manager
                            .create_passthrough_session_for_server_with_cid_updates(
                                client_addr,
                                port,
                                server,
                                None,
                                socket,
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
                        pending_reassembly_bytes
                            .fetch_sub(pending.retained_bytes(), Ordering::Relaxed);
                        pending.datagrams
                    })
                    .unwrap_or_else(|| vec![data.clone()]);
                self.route_for_client_hello(
                    port,
                    client_addr,
                    &data,
                    client_hello,
                    http3_enabled,
                    socket,
                    shutdown_rx,
                    quic_cid_tx.clone(),
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
                    .create_passthrough_session(
                        client_addr,
                        port,
                        &data,
                        socket.clone(),
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
                    if h3_tx
                        .try_send(H3Datagram {
                            from: client_addr,
                            data,
                        })
                        .is_err()
                    {
                        debug!(
                            "HTTP/3 shared UDP queue unavailable, dropping undecidable datagram from {}",
                            client_addr
                        );
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
        socket: Arc<UdpSocket>,
        shutdown_rx: watch::Receiver<bool>,
        quic_cid_tx: mpsc::Sender<UdpSessionQuicCid>,
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
                    .create_passthrough_session_for_server_with_cid_updates(
                        client_addr,
                        port,
                        server,
                        Some(server_name.to_string()),
                        socket,
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
                    .create_passthrough_session_for_server_with_cid_updates(
                        client_addr,
                        port,
                        server,
                        Some(server_name.to_string()),
                        socket,
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
                .create_passthrough_session_for_server_with_cid_updates(
                    client_addr,
                    port,
                    server,
                    client_hello.server_name.clone(),
                    socket,
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

        let session = match self
            .udp_manager
            .create_passthrough_session(client_addr, port, data, socket, shutdown_rx)
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
        http3_enabled: bool,
    ) -> DispatchStatus {
        match route {
            RouteKind::Http3(last_activity_ms) => {
                if !http3_enabled {
                    return DispatchStatus::Closed;
                }
                match h3_tx.try_send(H3Datagram {
                    from: client_addr,
                    data,
                }) {
                    Ok(()) => {
                        last_activity_ms.store(udp_activity_now_ms(), Ordering::Relaxed);
                        DispatchStatus::Sent
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!(
                            "HTTP/3 shared UDP queue full, dropping datagram from {}",
                            client_addr
                        );
                        DispatchStatus::Dropped
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => DispatchStatus::Closed,
                }
            }
            RouteKind::Passthrough(session) => {
                match UdpProxyManager::send_to_session_from_client(&session, client_addr, data)
                    .await
                {
                    UdpSessionSendStatus::Sent => DispatchStatus::Sent,
                    UdpSessionSendStatus::Full => {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{NetworkAddressConfig, ServerNameConfig, UDPConfig};
    use std::collections::HashMap;

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
