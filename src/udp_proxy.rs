use bytes::Bytes;
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc, watch};
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
use crate::net_bind::{bind_udp_socket, dual_stack_bind_addrs};

const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_MAX_QUIC_CIDS: usize = 8;
const UDP_METRICS_FLUSH_BYTES: u64 = 1024 * 1024;
const UDP_METRICS_FLUSH_INTERVAL: Duration = Duration::from_secs(1);

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
    pub client_addr: Arc<RwLock<SocketAddr>>,
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
}

pub struct UdpProxyManager {
    config_store: ConfigStore,
    waf_state: Arc<WafStateManager>,
    node_id: i64,
    /// (ClientAddr, ListenPort) -> Session
    sessions: Arc<DashMap<(SocketAddr, u16), Arc<UdpSession>>>,
    handled_ports: DashMap<SocketAddr, ListenerHandle>,
    next_session_id: AtomicU64,
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
    client_addr: Arc<RwLock<SocketAddr>>,
    domain: String,
    last_activity_ms: Arc<AtomicU64>,
    quic_cids: Arc<RwLock<VecDeque<Vec<u8>>>>,
    quic_server_cid_len: Arc<AtomicU8>,
    quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
    downstream_sender: UdpDownstreamSender,
    rx: mpsc::Receiver<QueuedUdpDatagram>,
    metrics_guard: crate::metrics::ActiveRequestMetricsGuard,
}

impl UdpProxyManager {
    pub fn new(
        config_store: ConfigStore,
        waf_state: Arc<WafStateManager>,
        node_id: i64,
    ) -> Arc<Self> {
        Arc::new(Self {
            config_store,
            waf_state,
            node_id,
            sessions: Arc::new(DashMap::new()),
            handled_ports: DashMap::new(),
            next_session_id: AtomicU64::new(1),
        })
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
        self.handled_ports
            .insert(bind_addr, ListenerHandle { shutdown_tx });

        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.clone().run_listener(bind_addr, shutdown_rx).await {
                error!("UDP listener on {} failed: {}", bind_addr, e);
                manager.handled_ports.remove(&bind_addr);
            }
        });
    }

    fn reconcile_listeners(&self, desired_listeners: &std::collections::HashSet<SocketAddr>) {
        let active_listeners: Vec<SocketAddr> = self
            .handled_ports
            .iter()
            .map(|entry| *entry.key())
            .collect();
        for bind_addr in active_listeners {
            if !desired_listeners.contains(&bind_addr) {
                if let Some((_, handle)) = self.handled_ports.remove(&bind_addr) {
                    info!("UDP Proxy Manager: Stopping listener on {}", bind_addr);
                    let _ = handle.shutdown_tx.send(true);
                }
                self.remove_sessions_for_port(bind_addr.port());
            }
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
        info!("UDP Proxy listening on {}", bind_addr);

        let mut buf = vec![0u8; 65535];
        loop {
            let recv_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("UDP listener on port {} shutting down", port);
                    return Ok(());
                }
                res = listen_socket.recv_from(&mut buf) => res,
            };
            let (len, client_addr) = recv_result?;
            let data = Bytes::copy_from_slice(&buf[..len]);

            match self
                .receive_datagram_with_downstream(
                    client_addr,
                    port,
                    data,
                    downstream_sender.clone(),
                    shutdown_rx.clone(),
                )
                .await
            {
                Ok(UdpIngressDatagramStatus::Sent)
                | Ok(UdpIngressDatagramStatus::Blocked)
                | Ok(UdpIngressDatagramStatus::NoRoute) => {}
                Ok(UdpIngressDatagramStatus::Full) => {
                    debug!("UDP session {} buffer full, dropping packet", client_addr);
                }
                Ok(UdpIngressDatagramStatus::Closed) => {
                    debug!("UDP session {} closed, dropping packet", client_addr);
                }
                Err(err) => {
                    debug!(
                        "UDP session creation failed for {} on port {}: {}",
                        client_addr, port, err
                    );
                }
            }
        }
    }

    pub async fn receive_datagram_with_downstream(
        &self,
        client_addr: SocketAddr,
        port: u16,
        data: Bytes,
        downstream_sender: UdpDownstreamSender,
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<UdpIngressDatagramStatus> {
        if crate::l4_defense::is_l4_blocked(&self.config_store, &self.waf_state, client_addr.ip()) {
            return Ok(UdpIngressDatagramStatus::Blocked);
        }

        let key = (client_addr, port);
        let session = if let Some(session) = self.sessions.get(&key) {
            session.clone()
        } else {
            let Some(session) = self
                .create_passthrough_session_with_downstream(
                    client_addr,
                    port,
                    data.as_ref(),
                    downstream_sender,
                    shutdown_rx,
                )
                .await?
            else {
                return Ok(UdpIngressDatagramStatus::NoRoute);
            };
            session
        };

        match Self::send_to_session_from_client(&session, client_addr, data).await {
            UdpSessionSendStatus::Sent => Ok(UdpIngressDatagramStatus::Sent),
            UdpSessionSendStatus::Full => {
                self.record_l4_event(
                    client_addr.ip(),
                    L4DefenseKind::UdpQueueFull,
                    format!("port={} peer={} session={}", port, client_addr, session.id),
                );
                Ok(UdpIngressDatagramStatus::Full)
            }
            UdpSessionSendStatus::Closed => {
                self.sessions
                    .remove_if(&key, |_, existing| existing.id == session.id);
                Ok(UdpIngressDatagramStatus::Closed)
            }
        }
    }

    pub async fn receive_af_xdp_datagram(
        &self,
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
        let b_addr =
            resolve_udp_backend_addr(peer.addr.to_string(), origin_host, client_addr.ip()).await?;

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
            client_addr: Arc::new(RwLock::new(client_addr)),
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
        self.sessions.insert(key, session.clone());

        tokio::spawn(async move {
            let _session_permit = session_permit;
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
            })
            .await;
            let last_client_addr = *client_addr.read().await;
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

    pub async fn update_session_client_addr(session: &UdpSession, client_addr: SocketAddr) {
        let mut current = session.client_addr.write().await;
        if *current != client_addr {
            *current = client_addr;
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
            let _ = tx
                .send(UdpSessionQuicCid {
                    session_id,
                    cid,
                    retired_cid,
                })
                .await;
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
                Self::record_client_short_header_cid(session, item.data.as_ref()).await;
                Self::update_session_client_addr(session, client_addr).await;
                permit.send(item);
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
        } = args;
        let backend_bind_addr = if backend_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let backend_socket = match UdpSocket::bind(backend_bind_addr).await {
            Ok(socket) => socket,
            Err(err) => {
                crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                let current_client_addr = *client_addr.read().await;
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
        if let Err(err) = backend_socket.connect(backend_addr).await {
            crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
            return Err(err.into());
        }
        crate::origin_state::ORIGIN_STATE_MANAGER.record_success(origin_id);
        let mut transfer_metrics = UdpTransferAccumulator::new(Instant::now());
        let mut result: anyhow::Result<()> = Ok(());
        let mut buf = vec![0u8; 65535];
        loop {
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
                    let data = item.data;
                    let len = data.len() as u64;
                    if let Err(err) = backend_socket.send(&data).await {
                        crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                        result = Err(err.into());
                        break;
                    }
                    last_activity_ms.store(udp_activity_now_ms(), Ordering::Relaxed);
                    transfer_metrics.record_upstream(len);
                    transfer_metrics.flush_if_due(server_id, false);
                }
                recv = backend_socket.recv(&mut buf) => {
                    let len = match recv {
                        Ok(packet) => packet,
                        Err(err) => {
                            result = Err(err.into());
                            break;
                        }
                    };
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
                    let current_client_addr = *client_addr.read().await;
                    match downstream_sender.send_to(&buf[..len], current_client_addr).await {
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            debug!(
                                "UDP downstream sender queue full for {}, dropping backend packet",
                                current_client_addr
                            );
                            continue;
                        }
                        Err(err) => {
                            result = Err(err.into());
                            break;
                        }
                    }
                    last_activity_ms.store(udp_activity_now_ms(), Ordering::Relaxed);
                    transfer_metrics.record_downstream(len_u64);
                    transfer_metrics.flush_if_due(server_id, false);
                }
            }
        }
        transfer_metrics.flush_if_due(server_id, true);
        let (downstream_sent, upstream_sent) = transfer_metrics.totals();
        let current_client_addr = *client_addr.read().await;
        let status = if result.is_ok() { 200 } else { 502 };
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
        result
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
    async fn session_client_addr_updates_for_rebinding() {
        let first: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = UdpSession {
            id: 1,
            client_addr: Arc::new(RwLock::new(first)),
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
            tx,
            shutdown_tx,
            shutdown,
        };

        UdpProxyManager::update_session_client_addr(&session, second).await;

        assert_eq!(*session.client_addr.read().await, second);
    }

    #[tokio::test]
    async fn send_to_session_from_client_does_not_update_addr_when_full() {
        let first: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let second: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(QueuedUdpDatagram::new(Bytes::from_static(b"queued")).unwrap())
            .unwrap();
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = UdpSession {
            id: 1,
            client_addr: Arc::new(RwLock::new(first)),
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
        assert_eq!(*session.client_addr.read().await, first);
    }

    #[tokio::test]
    async fn client_short_header_learns_rotated_server_cid_after_queue_reservation() {
        let client_addr: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let (cid_tx, mut cid_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let session = UdpSession {
            id: 7,
            client_addr: Arc::new(RwLock::new(client_addr)),
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
            client_addr: Arc::new(RwLock::new(client_addr)),
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
            client_addr: Arc::new(RwLock::new(first)),
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
            client_addr: Arc::new(RwLock::new(first)),
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
            client_addr: Arc::new(RwLock::new(client_addr)),
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
            client_addr: Arc::new(RwLock::new(client_addr)),
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
    async fn channel_downstream_sender_reports_backpressure_without_waiting() {
        let listen_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(DownstreamUdpDatagram {
            listen_addr,
            peer_addr,
            payload: Bytes::from_static(b"queued"),
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
            client_addr: Arc::new(RwLock::new(peer_addr)),
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
}
