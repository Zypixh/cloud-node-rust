use bytes::Bytes;
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc, watch};
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, error, info, warn};

use crate::config::ConfigStore;
use crate::config_models::ServerConfig;
use crate::lb_factory::BackendExtension;

const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_SESSION_QUEUE_SIZE: usize = 4096;
const UDP_SESSION_MAX_QUIC_CIDS: usize = 8;

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
    pub last_activity: Arc<RwLock<Instant>>,
    pub quic_cids: Arc<RwLock<VecDeque<Vec<u8>>>>,
    pub quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
    pub tx: mpsc::Sender<Bytes>,
    pub shutdown: watch::Receiver<bool>,
}

struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
}

pub struct UdpProxyManager {
    config_store: ConfigStore,
    /// (ClientAddr, ListenPort) -> Session
    sessions: Arc<DashMap<(SocketAddr, u16), Arc<UdpSession>>>,
    handled_ports: DashMap<u16, ListenerHandle>,
    next_session_id: AtomicU64,
}

impl UdpProxyManager {
    pub fn new(config_store: ConfigStore) -> Arc<Self> {
        Arc::new(Self {
            config_store,
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
            for port in &desired_ports {
                self.spawn_listener(*port).await;
            }

            self.reconcile_listeners(&desired_ports);

            // Cleanup idle sessions (Sticky Session Timeout)
            let now = Instant::now();
            let timeout = Duration::from_secs(60); // Default 60s idle timeout
            self.sessions.retain(|key, session| {
                if let Ok(last) = session.last_activity.try_read() {
                    let is_alive = now.duration_since(*last) < timeout;
                    if !is_alive {
                        debug!("Cleaning up idle UDP session: {:?}", key);
                    }
                    is_alive
                } else {
                    true // If locked, keep it for now
                }
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

    async fn spawn_listener(self: &Arc<Self>, port: u16) {
        if self.handled_ports.contains_key(&port) {
            return;
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.handled_ports
            .insert(port, ListenerHandle { shutdown_tx });

        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.clone().run_listener(port, shutdown_rx).await {
                error!("UDP listener on port {} failed: {}", port, e);
                manager.handled_ports.remove(&port);
            }
        });
    }

    fn reconcile_listeners(&self, desired_ports: &std::collections::HashSet<u16>) {
        let active_ports: Vec<u16> = self
            .handled_ports
            .iter()
            .map(|entry| *entry.key())
            .collect();
        for port in active_ports {
            if !desired_ports.contains(&port) {
                if let Some((_, handle)) = self.handled_ports.remove(&port) {
                    info!("UDP Proxy Manager: Stopping listener on port {}", port);
                    let _ = handle.shutdown_tx.send(true);
                }
                self.sessions
                    .retain(|(_, session_port), _| *session_port != port);
            }
        }
    }

    async fn run_listener(
        self: Arc<Self>,
        port: u16,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listen_addr = format!("0.0.0.0:{}", port);
        let listen_socket = Arc::new(UdpSocket::bind(&listen_addr).await?);
        info!("UDP Proxy listening on {}", listen_addr);

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
                        warn!(
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
        if server.has_valid_traffic_limit() {
            debug!(
                "UDP server {} is traffic-limited for client {}",
                server.numeric_id(),
                client_addr
            );
            return Ok(None);
        }
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
        let (tx, rx) = mpsc::channel(UDP_SESSION_QUEUE_SIZE);
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
            last_activity: Arc::new(RwLock::new(Instant::now())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_cid_tx: quic_cid_tx.clone(),
            tx,
            shutdown: shutdown_rx.clone(),
        });

        crate::metrics::record::request_start(
            sid,
            client_addr.ip().to_string(),
            user_id,
            user_plan_id,
            plan_id,
            None,
            false,
        );

        let backend_addr = session.backend_addr;
        let listen_port = session.listen_port;
        let shutdown_rx_clone = session.shutdown.clone();
        let server_id = session.server_id;
        let origin_id = session.origin_id;
        let initial_client_addr = client_addr;
        let client_addr = session.client_addr.clone();
        let last_activity = session.last_activity.clone();
        let quic_cids = session.quic_cids.clone();
        let session_quic_cid_tx = session.quic_cid_tx.clone();
        let sessions = self.sessions.clone();
        self.sessions.insert(key, session.clone());

        tokio::spawn(async move {
            let result = Self::handle_session(
                session_id,
                backend_addr,
                listen_port,
                shutdown_rx_clone,
                server_id,
                origin_id,
                client_addr.clone(),
                domain,
                last_activity,
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
        if let Ok(mut last) = session.last_activity.try_write() {
            *last = Instant::now();
        }
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
        match session.tx.try_send(data) {
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
        match session.tx.try_reserve() {
            Ok(permit) => {
                Self::update_session_client_addr(session, client_addr).await;
                permit.send(data);
                Self::update_session_activity(session);
                UdpSessionSendStatus::Sent
            }
            Err(mpsc::error::TrySendError::Full(())) => UdpSessionSendStatus::Full,
            Err(mpsc::error::TrySendError::Closed(())) => UdpSessionSendStatus::Closed,
        }
    }

    pub fn remove_sessions_for_port(&self, port: u16) {
        self.sessions
            .retain(|(_, session_port), _| *session_port != port);
    }

    pub fn cleanup_idle_sessions(&self, timeout: Duration) {
        let now = Instant::now();
        self.sessions.retain(|key, session| {
            let keep = session
                .last_activity
                .try_read()
                .map(|last| now.duration_since(*last) < timeout)
                .unwrap_or(true);
            if !keep {
                debug!("Cleaning up idle UDP session: {:?}", key);
            }
            keep
        });
    }

    async fn handle_session(
        session_id: u64,
        backend_addr: SocketAddr,
        _listen_port: u16,
        mut shutdown_rx: watch::Receiver<bool>,
        server_id: i64,
        origin_id: i64,
        client_addr: Arc<RwLock<SocketAddr>>,
        domain: String,
        last_activity: Arc<RwLock<Instant>>,
        quic_cids: Arc<RwLock<VecDeque<Vec<u8>>>>,
        quic_cid_tx: Option<mpsc::Sender<UdpSessionQuicCid>>,
        listen_socket: Arc<UdpSocket>,
        mut rx: mpsc::Receiver<Bytes>,
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
                crate::metrics::record::record_http_dimensions(
                    server_id,
                    current_client_addr.ip(),
                    &domain,
                    "-",
                    0,
                    0,
                    0,
                    None,
                    None,
                );
                crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
                return Err(err.into());
            }
        };
        if let Err(err) = backend_socket.connect(backend_addr).await {
            crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
            let current_client_addr = *client_addr.read().await;
            crate::metrics::record::record_http_dimensions(
                server_id,
                current_client_addr.ip(),
                &domain,
                "-",
                0,
                0,
                0,
                None,
                None,
            );
            crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
            return Err(err.into());
        }
        crate::origin_state::ORIGIN_STATE_MANAGER.record_success(origin_id);
        let mut downstream_sent = 0u64;
        let mut result: anyhow::Result<()> = Ok(());
        let mut buf = vec![0u8; 65535];
        let mut idle_tick = interval(Duration::from_secs(5));
        idle_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    break;
                }
                _ = idle_tick.tick() => {
                    let idle = last_activity
                        .try_read()
                        .map(|last| last.elapsed() >= UDP_SESSION_IDLE_TIMEOUT)
                        .unwrap_or(false);
                    if idle {
                        break;
                    }
                }
                data = rx.recv() => {
                    let Some(data) = data else {
                        break;
                    };
                    let len = data.len() as u64;
                    if let Err(err) = backend_socket.send(&data).await {
                        crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                        result = Err(err.into());
                        break;
                    }
                    if let Ok(mut last) = last_activity.try_write() {
                        *last = Instant::now();
                    }
                    crate::metrics::record::record_transfer(server_id, 0, len, None);
                    crate::metrics::record::record_origin_traffic(server_id, len, 0, None);
                }
                recv = backend_socket.recv(&mut buf) => {
                    let len = match recv {
                        Ok(len) => len,
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
                    if let Ok(mut last) = last_activity.try_write() {
                        *last = Instant::now();
                    }
                    downstream_sent += len_u64;
                    crate::metrics::record::record_transfer(server_id, len_u64, 0, None);
                    crate::metrics::record::record_origin_traffic(server_id, 0, len_u64, None);
                }
            }
        }
        let current_client_addr = *client_addr.read().await;
        crate::metrics::record::record_http_dimensions(
            server_id,
            current_client_addr.ip(),
            &domain,
            "-",
            downstream_sent as i64,
            0,
            0,
            None,
            None,
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
        let servers = self.config_store.get_all_servers().await;
        for s in servers {
            if s.is_quic_passthrough() {
                continue;
            }
            if let Some(udp) = &s.udp {
                if !udp.is_on {
                    continue;
                }
                for addr in &udp.listen {
                    if addr
                        .port_range
                        .as_deref()
                        .is_some_and(|range| crate::config_models::port_range_contains(range, port))
                    {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
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
        let (_shutdown_tx, shutdown) = watch::channel(false);
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
            last_activity: Arc::new(RwLock::new(Instant::now())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_cid_tx: None,
            tx,
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
        tx.try_send(Bytes::from_static(b"queued")).unwrap();
        let (_shutdown_tx, shutdown) = watch::channel(false);
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
            last_activity: Arc::new(RwLock::new(Instant::now())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_cid_tx: None,
            tx,
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
        tx.try_send(Bytes::from_static(b"queued")).unwrap();
        let (_shutdown_tx, shutdown) = watch::channel(false);
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
            last_activity: Arc::new(RwLock::new(Instant::now())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_cid_tx: None,
            tx,
            shutdown,
        });
        assert_eq!(
            UdpProxyManager::send_to_session(&session, Bytes::from_static(b"next")),
            UdpSessionSendStatus::Full
        );
        assert_eq!(rx.recv().await.as_deref(), Some(&b"queued"[..]));
        assert_eq!(
            UdpProxyManager::send_to_session(&session, Bytes::from_static(b"next")),
            UdpSessionSendStatus::Sent
        );
        assert_eq!(rx.recv().await.as_deref(), Some(&b"next"[..]));
    }

    #[test]
    fn send_to_session_reports_closed() {
        let first: SocketAddr = "127.0.0.1:10000".parse().unwrap();
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let (_shutdown_tx, shutdown) = watch::channel(false);
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
            last_activity: Arc::new(RwLock::new(Instant::now())),
            quic_cids: Arc::new(RwLock::new(VecDeque::new())),
            quic_cid_tx: None,
            tx,
            shutdown,
        };

        assert_eq!(
            UdpProxyManager::send_to_session(&session, Bytes::from_static(b"next")),
            UdpSessionSendStatus::Closed
        );
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

        let manager = UdpProxyManager::new(store);
        let server = manager
            .find_server_for_packet(443, b"not a quic initial")
            .await
            .expect("normal UDP server should match first");
        assert_eq!(server.numeric_id(), 10);
    }
}
