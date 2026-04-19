use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

use crate::config::ConfigStore;
use crate::config_models::ServerConfig;

/// Session tracking for UDP sessions
pub struct UdpSession {
    pub client_addr: SocketAddr,
    pub backend_addr: SocketAddr,
    pub server_id: i64,
    pub last_activity: Arc<RwLock<Instant>>,
    pub tx: mpsc::Sender<Vec<u8>>,
}

pub struct UdpProxyManager {
    config_store: ConfigStore,
    /// (ClientAddr, ListenPort) -> Session
    sessions: DashMap<(SocketAddr, u16), Arc<UdpSession>>,
}

impl UdpProxyManager {
    pub fn new(config_store: ConfigStore) -> Arc<Self> {
        Arc::new(Self {
            config_store,
            sessions: DashMap::new(),
        })
    }

    pub async fn start_listeners(self: Arc<Self>) {
        debug!("Starting UDP Proxy Manager for v{}...", env!("CARGO_PKG_VERSION"));
        let mut handled_ports = std::collections::HashSet::new();

        loop {
            // Check for new servers or port changes
            let servers = self.config_store.get_all_servers().await;
            debug!("UDP Proxy Manager: Found {} servers in config store", servers.len());
            for server in servers {
                if let Some(udp_cfg) = &server.udp {
                    if udp_cfg.is_on {
                        if udp_cfg.listen.is_empty() {
                            warn!("UDP Proxy Manager: Server {} has UDP ON but NO listen addresses", server.numeric_id());
                        }
                        for addr_cfg in &udp_cfg.listen {
                            if let Ok(port) = addr_cfg
                                .port_range
                                .clone()
                                .unwrap_or_default()
                                .parse::<u16>()
                            {
                                if handled_ports.contains(&port) {
                                    continue;
                                }

                                handled_ports.insert(port);
                                let manager = self.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = manager.run_listener(port).await {
                                        error!("UDP listener on port {} failed: {}", port, e);
                                    }
                                });
                            }
                        }
                    } else {
                        debug!("UDP Proxy Manager: Server {} UDP is OFF", server.numeric_id());
                    }
                } else {
                    debug!("UDP Proxy Manager: Server {} has NO UDP config", server.numeric_id());
                }
            }

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

    async fn run_listener(self: Arc<Self>, port: u16) -> anyhow::Result<()> {
        let listen_addr = format!("0.0.0.0:{}", port);
        let listen_socket = Arc::new(UdpSocket::bind(&listen_addr).await?);
        info!("UDP Proxy listening on {}", listen_addr);

        let mut buf = [0u8; 65535];
        loop {
            let (len, client_addr) = listen_socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            // 1. Find server config
            let server = match self.find_server_by_port(port).await {
                Some(s) => s,
                None => continue,
            };
            let sid = server.id.unwrap_or(0);

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
                    last_activity: Arc::new(RwLock::new(Instant::now())),
                    tx,
                });

                // Spawn session task for bidirectional forwarding
                let session_inner = session.clone();
                let listen_socket_inner = listen_socket.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        Self::handle_session(session_inner, listen_socket_inner, rx).await
                    {
                        debug!("UDP session {} -> {} closed: {}", client_addr, b_addr, e);
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
        session: Arc<UdpSession>,
        listen_socket: Arc<UdpSocket>,
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let backend_socket = UdpSocket::bind("0.0.0.0:0").await?;
        backend_socket.connect(session.backend_addr).await?;

        let mut buf = [0u8; 65535];
        loop {
            tokio::select! {
                // Client -> Backend
                Some(data) = rx.recv() => {
                    let len = data.len() as u64;
                    backend_socket.send(&data).await?;
                    // Client -> Backend: Origin Sent = len, Origin Received = 0
                    crate::metrics::record::record_origin_traffic(session.server_id, len, 0);
                }
                // Backend -> Client
                Ok(len) = backend_socket.recv(&mut buf) => {
                    let len_u64 = len as u64;
                    listen_socket.send_to(&buf[..len], session.client_addr).await?;
                    // Backend -> Client: Origin Sent = 0, Origin Received = len
                    crate::metrics::record::record_origin_traffic(session.server_id, 0, len_u64);
                }
                // Timeout or close (rx closed means manager decided to terminate or buffer full/dropped)
                else => break,
            }
        }
        Ok(())
    }

    async fn find_server_by_port(&self, port: u16) -> Option<ServerConfig> {
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
