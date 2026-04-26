use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::config::ConfigStore;
use crate::config_models::ServerConfig;

/// Session tracking for UDP sessions
pub struct UdpSession {
    pub client_addr: SocketAddr,
    pub backend_addr: SocketAddr,
    pub server_id: i64,
    pub user_id: i64,
    pub user_plan_id: i64,
    pub plan_id: i64,
    pub last_activity: Arc<RwLock<Instant>>,
    pub tx: mpsc::Sender<Vec<u8>>,
    pub shutdown: watch::Receiver<bool>,
}

struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
}

pub struct UdpProxyManager {
    config_store: ConfigStore,
    /// (ClientAddr, ListenPort) -> Session
    sessions: DashMap<(SocketAddr, u16), Arc<UdpSession>>,
    handled_ports: DashMap<u16, ListenerHandle>,
}

impl UdpProxyManager {
    pub fn new(config_store: ConfigStore) -> Arc<Self> {
        Arc::new(Self {
            config_store,
            sessions: DashMap::new(),
            handled_ports: DashMap::new(),
        })
    }

    pub async fn start_listeners(self: Arc<Self>) {
        debug!(
            "Starting UDP Proxy Manager for v{}...",
            env!("CARGO_PKG_VERSION")
        );

        loop {
            // Check for new servers or port changes
            let servers = self.config_store.get_all_servers().await;
            debug!(
                "UDP Proxy Manager: Found {} servers in config store",
                servers.len()
            );
            let mut desired_ports = std::collections::HashSet::new();
            for server in servers {
                if let Some(udp_cfg) = &server.udp {
                    if udp_cfg.is_on {
                        if udp_cfg.listen.is_empty() {
                            warn!(
                                "UDP Proxy Manager: Server {} has UDP ON but NO listen addresses",
                                server.numeric_id()
                            );
                        }
                        for addr_cfg in &udp_cfg.listen {
                            if let Ok(port) = addr_cfg
                                .port_range
                                .clone()
                                .unwrap_or_default()
                                .parse::<u16>()
                            {
                                desired_ports.insert(port);
                                self.spawn_listener(port).await;
                            }
                        }
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
            let data = buf[..len].to_vec();

            // 1. Find server config
            let server = match self.find_server_by_port(port).await {
                Some(s) => s,
                None => continue,
            };
            if server.has_valid_traffic_limit() {
                debug!(
                    "UDP Proxy: dropping packet from {} for traffic-limited server {}",
                    client_addr,
                    server.numeric_id()
                );
                continue;
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

            // 2. Get or create session (Session Sticky)
            let key = (client_addr, port);
            let session = if let Some(s) = self.sessions.get(&key) {
                s.clone()
            } else {
                // Select backend using the server's load balancer
                let lb = match self.config_store.get_lb_by_id(sid).await {
                    Some(lb) => lb,
                    None => {
                        error!("No load balancer found for server id {}", sid);
                        continue;
                    }
                };

                // Hash based on client IP for sticky session if needed,
                // but for UDP (ClientAddr, Port) is already the session key.
                let peer = match lb.select(b"", 128) {
                    Some(p) => p,
                    None => {
                        error!("No healthy backends for UDP server {}", sid);
                        continue;
                    }
                };
                let b_addr: SocketAddr = peer.addr.to_string().parse()?;

                debug!(
                    "Created new UDP session: {} -> {} (Server {})",
                    client_addr, b_addr, sid
                );
                let (tx, rx) = mpsc::channel(1024);
                let session = Arc::new(UdpSession {
                    client_addr,
                    backend_addr: b_addr,
                    server_id: sid,
                    user_id,
                    user_plan_id,
                    plan_id,
                    last_activity: Arc::new(RwLock::new(Instant::now())),
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

                // Spawn session task for bidirectional forwarding
                let backend_addr = session.backend_addr;
                let shutdown_rx_clone = session.shutdown.clone();
                let server_id = session.server_id;
                let client_addr = session.client_addr;
                
                let listen_socket_inner = listen_socket.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        Self::handle_session(backend_addr, shutdown_rx_clone, server_id, client_addr, listen_socket_inner, rx).await
                    {
                        debug!("UDP session {} -> {} closed: {}", client_addr, backend_addr, e);
                    }
                });

                self.sessions.insert(key, session.clone());
                session
            };

            // 3. Forward data to session task
            if session.tx.try_send(data).is_err() {
                debug!("UDP session {} buffer full, dropping packet", client_addr);
            }

            // 4. Update activity timestamp
            if let Ok(mut last) = session.last_activity.try_write() {
                *last = Instant::now();
            }
        }
    }

    async fn handle_session(
        backend_addr: SocketAddr,
        mut shutdown_rx: watch::Receiver<bool>,
        server_id: i64,
        client_addr: SocketAddr,
        listen_socket: Arc<UdpSocket>,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let backend_socket = UdpSocket::bind("0.0.0.0:0").await?;
        backend_socket.connect(backend_addr).await?;
        let mut downstream_sent = 0u64;
        let mut downstream_received = 0u64;

        let mut buf = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    break;
                }
                // Client -> Backend
                Some(data) = rx.recv() => {
                    let len = data.len() as u64;
                    backend_socket.send(&data).await?;
                    downstream_received += len;
                    // Client -> Backend: Origin Sent = len, Origin Received = 0
                    crate::metrics::record::record_origin_traffic(server_id, len, 0, None);
                }
                // Backend -> Client
                Ok(len) = backend_socket.recv(&mut buf) => {
                    let len_u64 = len as u64;
                    listen_socket.send_to(&buf[..len], client_addr).await?;
                    downstream_sent += len_u64;
                    // Backend -> Client: Origin Sent = 0, Origin Received = len
                    crate::metrics::record::record_origin_traffic(server_id, 0, len_u64, None);
                }
                // Timeout or close (rx closed means manager decided to terminate or buffer full/dropped)
                else => break,
            }
        }
        crate::metrics::record::request_end(
            server_id,
            downstream_sent,
            downstream_received,
            false,
            false,
            false,
            None,
        );
        Ok(())
    }

    async fn find_server_by_port(&self, port: u16) -> Option<Arc<ServerConfig>> {
        let servers = self.config_store.get_all_servers().await;
        for s in servers {
            if let Some(udp) = &s.udp {
                if !udp.is_on {
                    continue;
                }
                for addr in &udp.listen {
                    if addr.port_range.as_deref() == Some(&port.to_string()) {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }
}
