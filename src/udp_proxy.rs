use bytes::Bytes;
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::LazyLock as Lazy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc, watch};
use tokio::time::{MissedTickBehavior, interval};
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
    pub quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
    pub tx: mpsc::Sender<QueuedUdpDatagram>,
    pub shutdown_tx: watch::Sender<bool>,
    pub shutdown: watch::Receiver<bool>,
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
            let desired_listeners = desired_ports
                .iter()
                .flat_map(|port| dual_stack_bind_addrs(*port))
                .collect::<HashSet<_>>();
            for bind_addr in &desired_listeners {
                self.spawn_listener(*bind_addr).await;
            }

            self.reconcile_listeners(&desired_listeners);

            // Cleanup idle sessions (Sticky Session Timeout)
            let timeout = Duration::from_secs(60); // Default 60s idle timeout
            self.sessions.retain(|key, session| {
                let is_alive = udp_activity_is_alive(&session.last_activity_ms, timeout);
                if !is_alive {
                    debug!("Cleaning up idle UDP session: {:?}", key);
                }
                is_alive
            });

            // Re-check config every minute or on notification
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
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
            if server.is_quic_passthrough() {
                if let Some(https) = &server.https
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
            if crate::l4_defense::is_l4_blocked(
                &self.config_store,
                &self.waf_state,
                client_addr.ip(),
            ) {
                continue;
            }
            let data = Bytes::copy_from_slice(&buf[..len]);

            // 1. Get or create session (Session Sticky)
            let key = (client_addr, port);
            let session = if let Some(s) = self.sessions.get(&key) {
                s.clone()
            } else {
                match self
                    .create_passthrough_session(
                        client_addr,
                        port,
                        data.as_ref(),
                        listen_socket.clone(),
                        shutdown_rx.clone(),
                    )
                    .await
                {
                    Ok(Some(session)) => session,
                    Ok(None) => continue,
                    Err(err) => {
                        debug!(
                            "UDP session creation failed for {} on port {}: {}",
                            client_addr, port, err
                        );
                        continue;
                    }
                }
            };

            match Self::send_to_session(&session, data) {
                UdpSessionSendStatus::Sent => {}
                UdpSessionSendStatus::Full => {
                    self.record_l4_event(
                        client_addr.ip(),
                        L4DefenseKind::UdpQueueFull,
                        format!("port={} peer={} session={}", port, client_addr, session.id),
                    );
                    debug!("UDP session {} buffer full, dropping packet", client_addr);
                }
                UdpSessionSendStatus::Closed => {
                    debug!("UDP session {} closed, dropping packet", client_addr);
                    self.sessions
                        .remove_if(&key, |_, existing| existing.id == session.id);
                }
            }
        }
    }

    pub async fn create_passthrough_session(
        &self,
        client_addr: SocketAddr,
        port: u16,
        data: &[u8],
        listen_socket: Arc<UdpSocket>,
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
        self.create_passthrough_session_for_server(
            client_addr,
            port,
            server,
            None,
            listen_socket,
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
        self.create_passthrough_session_for_server_with_cid_updates(
            client_addr,
            port,
            server,
            probed_server_name,
            listen_socket,
            shutdown_rx,
            None,
        )
        .await
    }

    pub async fn create_passthrough_session_for_server_with_cid_updates(
        &self,
        client_addr: SocketAddr,
        port: u16,
        server: Arc<ServerConfig>,
        probed_server_name: Option<String>,
        listen_socket: Arc<UdpSocket>,
        shutdown_rx: watch::Receiver<bool>,
        quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
    ) -> anyhow::Result<Option<Arc<UdpSession>>> {
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
            quic_cid_tx: quic_cid_tx.clone(),
            tx,
            shutdown_tx: session_shutdown_tx,
            shutdown: session_shutdown_rx.clone(),
        });

        let client_ip = client_addr.ip().to_string();
        crate::metrics::record::request_start(
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
        let session_quic_cid_tx = session.quic_cid_tx.clone();
        let sessions = self.sessions.clone();
        self.sessions.insert(key, session.clone());

        tokio::spawn(async move {
            let _session_permit = session_permit;
            let result = Self::handle_session(
                session_id,
                backend_addr,
                listen_port,
                listener_shutdown_rx,
                session_shutdown_rx,
                server_id,
                origin_id,
                client_addr.clone(),
                domain,
                last_activity_ms,
                quic_cids,
                session_quic_cid_tx,
                listen_socket,
                rx,
            )
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

    async fn handle_session(
        session_id: u64,
        backend_addr: SocketAddr,
        _listen_port: u16,
        mut listener_shutdown_rx: watch::Receiver<bool>,
        mut session_shutdown_rx: watch::Receiver<bool>,
        server_id: i64,
        origin_id: i64,
        client_addr: Arc<RwLock<SocketAddr>>,
        domain: String,
        last_activity_ms: Arc<AtomicU64>,
        quic_cids: Arc<RwLock<VecDeque<Vec<u8>>>>,
        quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
        listen_socket: Arc<UdpSocket>,
        mut rx: mpsc::Receiver<QueuedUdpDatagram>,
    ) -> anyhow::Result<()> {
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
                    crate::metrics::METRIC_CATEGORY_UDP,
                    server_id,
                    current_client_addr.ip(),
                    &domain,
                    "-",
                    0,
                    0,
                    502,
                );
                crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
                return Err(err.into());
            }
        };
        if let Err(err) = backend_socket.connect(backend_addr).await {
            crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
            return Err(err.into());
        }
        crate::origin_state::ORIGIN_STATE_MANAGER.record_success(origin_id);
        let mut downstream_sent = 0u64;
        let mut upstream_sent = 0u64;
        let mut result: anyhow::Result<()> = Ok(());
        let mut buf = vec![0u8; 65535];
        let mut idle_tick = interval(Duration::from_secs(5));
        idle_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = listener_shutdown_rx.changed() => {
                    break;
                }
                _ = session_shutdown_rx.changed() => {
                    break;
                }
                _ = idle_tick.tick() => {
                    let idle = !udp_activity_is_alive(&last_activity_ms, UDP_SESSION_IDLE_TIMEOUT);
                    if idle {
                        break;
                    }
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
                    upstream_sent += len;
                    crate::metrics::record::record_transfer(server_id, 0, len, None);
                    crate::metrics::record::record_origin_traffic(server_id, len, 0, None);
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
                    for cid in crate::quic_probe::quic_packet_cids(&buf[..len], 0)
                        .into_iter()
                        .flat_map(|cids| [Some(cids.dcid), cids.scid].into_iter().flatten())
                    {
                        Self::record_session_quic_cid(
                            session_id,
                            &quic_cids,
                            quic_cid_tx.as_ref(),
                            cid,
                        )
                        .await;
                    }
                    let current_client_addr = *client_addr.read().await;
                    if let Err(err) = listen_socket.send_to(&buf[..len], current_client_addr).await {
                        result = Err(err.into());
                        break;
                    }
                    last_activity_ms.store(udp_activity_now_ms(), Ordering::Relaxed);
                    downstream_sent += len_u64;
                    crate::metrics::record::record_transfer(server_id, len_u64, 0, None);
                    crate::metrics::record::record_origin_traffic(server_id, 0, len_u64, None);
                }
            }
        }
        let current_client_addr = *client_addr.read().await;
        let status = if result.is_ok() { 200 } else { 502 };
        crate::metrics::record::record_network_dimensions(
            crate::metrics::METRIC_CATEGORY_UDP,
            server_id,
            current_client_addr.ip(),
            &domain,
            "-",
            downstream_sent as i64,
            upstream_sent as i64,
            status,
        );
        crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
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

        let task = tokio::spawn(UdpProxyManager::handle_session(
            1,
            backend_addr,
            443,
            listener_shutdown_rx,
            session_shutdown_rx,
            1,
            1,
            Arc::new(RwLock::new(client_addr)),
            "udp.example.com".to_string(),
            Arc::new(AtomicU64::new(udp_activity_now_ms())),
            Arc::new(RwLock::new(VecDeque::new())),
            None,
            listen_socket,
            rx,
        ));

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
