use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use quinn::{AsyncUdpSocket, Endpoint, UdpPoller};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, IpAddr as StdIpAddr, Ipv4Addr, SocketAddr};
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
use crate::quic_probe::{QuicCryptoFragment, QuicProbeFragmentResult};
use crate::udp_proxy::{UdpProxyManager, UdpSession};

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
    Http3(Arc<Mutex<Instant>>),
    Passthrough(Arc<UdpSession>),
}

struct H3Datagram {
    from: SocketAddr,
    data: Bytes,
}

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
        match UdpSocket::bind(bind_addr).await {
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

fn server_has_http3_on_port(
    config_store: &ConfigStore,
    server: &crate::config_models::ServerConfig,
    port: u16,
) -> bool {
    if !server
        .https
        .as_ref()
        .is_some_and(|https| https.is_on && https.http3_enabled())
    {
        return false;
    }
    if config_store
        .get_global_http3_policy_sync()
        .is_some_and(|policy| policy.is_on && u16::try_from(policy.port).ok() == Some(port))
    {
        return true;
    }
    server.listens_on_https_port(port)
}

fn cleanup_routes(
    udp_manager: &UdpProxyManager,
    routes: &DashMap<SocketAddr, RouteKind>,
    pending_routes: &DashMap<SocketAddr, PendingQuicRoute>,
    pending_reassembly_bytes: &AtomicUsize,
) {
    let now = Instant::now();
    pending_routes
        .retain(|_, pending| now.duration_since(pending.created_at) < PENDING_QUIC_ROUTE_TIMEOUT);
    pending_retained_bytes(pending_routes, pending_reassembly_bytes);
    udp_manager.cleanup_idle_sessions(UDP_SESSION_IDLE_TIMEOUT);
    routes.retain(|_, route| match route {
        RouteKind::Http3(last_activity) => last_activity
            .lock()
            .map(|last| now.duration_since(*last) < H3_ROUTE_IDLE_TIMEOUT)
            .unwrap_or(true),
        RouteKind::Passthrough(session) => session
            .last_activity
            .try_read()
            .map(|last| now.duration_since(*last) < UDP_SESSION_IDLE_TIMEOUT)
            .unwrap_or(true),
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
    cert_hash: u64,
}

pub struct QuicUdpDemuxManager {
    config_store: ConfigStore,
    http3_manager: Arc<Http3ProxyManager>,
    udp_manager: Arc<UdpProxyManager>,
    handled_ports: DashMap<u16, ListenerHandle>,
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
            let cert_hash = self.http3_manager.current_cert_hash_for_demux().await;
            let desired_ports = http3_ports
                .union(&udp_ports)
                .copied()
                .collect::<HashSet<_>>();

            for port in &desired_ports {
                self.spawn_listener(*port, http3_ports.contains(port), cert_hash)
                    .await;
            }
            self.reconcile_listeners(&desired_ports, &http3_ports, cert_hash);
            tokio::select! {
                _ = self.config_store.wait_for_runtime_reload() => {}
                _ = reconcile_tick.tick() => {}
            }
        }
    }

    async fn spawn_listener(self: &Arc<Self>, port: u16, http3_enabled: bool, cert_hash: u64) {
        if let Some(existing) = self.handled_ports.get(&port) {
            let cert_changed = http3_enabled && existing.cert_hash != cert_hash;
            if existing.http3_enabled == http3_enabled && !cert_changed {
                return;
            }
            let _ = existing.shutdown_tx.send(true);
            drop(existing);
            self.handled_ports.remove(&port);
        }

        let listener_id = self.next_listener_id.fetch_add(1, Ordering::Relaxed);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.handled_ports.insert(
            port,
            ListenerHandle {
                id: listener_id,
                shutdown_tx,
                http3_enabled,
                cert_hash,
            },
        );
        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(err) = manager
                .clone()
                .run_listener(port, http3_enabled, cert_hash, shutdown_rx)
                .await
            {
                error!("QUIC UDP demux listener on port {} failed: {}", port, err);
            }
            if manager
                .handled_ports
                .get(&port)
                .is_some_and(|entry| entry.id == listener_id)
            {
                manager.handled_ports.remove(&port);
            }
        });
    }

    fn reconcile_listeners(
        &self,
        desired_ports: &HashSet<u16>,
        http3_ports: &HashSet<u16>,
        cert_hash: u64,
    ) {
        let active_ports = self
            .handled_ports
            .iter()
            .map(|entry| {
                (
                    *entry.key(),
                    entry.value().http3_enabled,
                    entry.value().cert_hash,
                )
            })
            .collect::<Vec<_>>();
        for (port, http3_enabled, active_hash) in active_ports {
            let desired_http3 = http3_ports.contains(&port);
            let keep = desired_ports.contains(&port)
                && http3_enabled == desired_http3
                && (!http3_enabled || active_hash == cert_hash);
            if keep {
                continue;
            }
            if let Some((_, handle)) = self.handled_ports.remove(&port) {
                info!("QUIC UDP demux: stopping listener on port {}", port);
                let _ = handle.shutdown_tx.send(true);
                self.udp_manager.remove_sessions_for_port(port);
            }
        }
    }

    async fn run_listener(
        self: Arc<Self>,
        port: u16,
        http3_enabled: bool,
        _cert_hash: u64,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let socket = Arc::new(bind_udp_with_retry(bind_addr, &mut shutdown_rx).await?);
        let local_addr = socket.local_addr()?;
        let routes = Arc::new(DashMap::<SocketAddr, RouteKind>::new());
        let pending_routes = Arc::new(DashMap::<SocketAddr, PendingQuicRoute>::new());
        let pending_reassembly_bytes = AtomicUsize::new(0);
        let new_route_windows = Arc::new(DashMap::<StdIpAddr, VecDeque<Instant>>::new());
        let (h3_tx, h3_rx) = mpsc::channel(H3_QUEUE_SIZE);

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
            let recv_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("QUIC UDP demux listener on port {} shutting down", port);
                    return Ok(());
                }
                _ = cleanup_tick.tick() => {
                    cleanup_routes(
                        &self.udp_manager,
                        &routes,
                        &pending_routes,
                        &pending_reassembly_bytes,
                    );
                    cleanup_new_route_windows(&new_route_windows);
                    continue;
                }
                result = socket.recv_from(&mut buf) => result,
            };
            let (len, client_addr) = recv_result?;
            let data = Bytes::copy_from_slice(&buf[..len]);

            let now = Instant::now();
            if routes.len() >= ROUTE_CLEANUP_PRESSURE_THRESHOLD && now >= next_pressure_cleanup {
                cleanup_routes(
                    &self.udp_manager,
                    &routes,
                    &pending_routes,
                    &pending_reassembly_bytes,
                );
                cleanup_new_route_windows(&new_route_windows);
                next_pressure_cleanup = now + ROUTE_CLEANUP_PRESSURE_INTERVAL;
            }

            if let Some(route) = routes.get(&client_addr).map(|entry| entry.value().clone()) {
                if self
                    .dispatch_existing_route(route, client_addr, data, &h3_tx, http3_enabled)
                    .await
                    == DispatchStatus::Closed
                {
                    routes.remove(&client_addr);
                }
                continue;
            }

            if routes.len() >= MAX_ROUTES_PER_PORT {
                cleanup_routes(
                    &self.udp_manager,
                    &routes,
                    &pending_routes,
                    &pending_reassembly_bytes,
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
                )
                .await?;
            let Some((route, datagrams)) = route else {
                continue;
            };
            if !has_pending_route {
                record_new_route_for_ip(&new_route_windows, client_addr.ip());
            }
            routes.insert(client_addr, route.clone());
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
    ) -> Result<Option<(RouteKind, Vec<Bytes>)>> {
        match crate::quic_probe::probe_quic_client_hello_fragment_result(&data) {
            QuicProbeFragmentResult::Found(client_hello) => {
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
                )
                .await
                .map(|route| route.map(|route| (route, datagrams)))
            }
            QuicProbeFragmentResult::Incomplete(fragment) => {
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
                )
                .await
                .map(|route| route.map(|route| (route, datagrams)))
            }
            QuicProbeFragmentResult::None => {
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
                if http3_enabled {
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
    ) -> Result<Option<RouteKind>> {
        if let Some(server_name) = client_hello.server_name.as_deref() {
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
                    .create_passthrough_session_for_server(
                        client_addr,
                        port,
                        server,
                        Some(server_name.to_string()),
                        socket,
                        shutdown_rx,
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

            if http3_enabled
                && client_hello_supports_h3(&client_hello)
                && self
                    .config_store
                    .get_l7_server_for_tls_name_sync(server_name)
                    .is_some_and(|server| {
                        server_has_http3_on_port(&self.config_store, &server, port)
                    })
            {
                debug!(
                    "QUIC UDP demux: L7 H3 {} on port {} matched alpn={:?}",
                    server_name, port, client_hello.alpns
                );
                return Ok(Some(RouteKind::Http3(Arc::new(Mutex::new(Instant::now())))));
            }
        }

        if http3_enabled && client_hello_supports_h3(&client_hello) {
            return Ok(Some(RouteKind::Http3(Arc::new(Mutex::new(Instant::now())))));
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
            RouteKind::Http3(last_activity) => {
                if !http3_enabled {
                    return DispatchStatus::Closed;
                }
                match h3_tx.try_send(H3Datagram {
                    from: client_addr,
                    data,
                }) {
                    Ok(()) => {
                        if let Ok(mut last) = last_activity.lock() {
                            *last = Instant::now();
                        }
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
            RouteKind::Passthrough(session) => match session.tx.try_send(data) {
                Ok(()) => {
                    UdpProxyManager::update_session_activity(&session);
                    DispatchStatus::Sent
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    debug!(
                        "UDP passthrough session {} buffer full, dropping packet",
                        client_addr
                    );
                    DispatchStatus::Dropped
                }
                Err(mpsc::error::TrySendError::Closed(_)) => DispatchStatus::Closed,
            },
        }
    }
}
