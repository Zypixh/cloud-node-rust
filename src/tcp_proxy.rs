use crate::config::ConfigStore;
use crate::config_models::ServerConfig;
use crate::ssl::DynamicCertSelector;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

pub struct TcpProxyManager {
    config_store: ConfigStore,
    _cert_selector: Arc<DynamicCertSelector>,
    handled_ports: DashMap<u16, ()>,
}

impl TcpProxyManager {
    pub fn new(config_store: ConfigStore, cert_selector: Arc<DynamicCertSelector>) -> Arc<Self> {
        Arc::new(Self {
            config_store,
            _cert_selector: cert_selector,
            handled_ports: DashMap::new(),
        })
    }

    pub async fn start_listeners(self: Arc<Self>) {
        info!("Starting TCP/TLS Proxy Manager...");
        loop {
            let servers = self.config_store.get_all_servers().await;
            for server in servers {
                // Handle TCP
                if let Some(tcp_cfg) = &server.tcp
                    && tcp_cfg.is_on {
                        for addr_cfg in &tcp_cfg.listen {
                            self.spawn_listener(&server, addr_cfg, false).await;
                        }
                    }
                // Handle TLS (TCP-TLS) — accessed via tcp.tls
                if let Some(tls_cfg) = server.tcp.as_ref().and_then(|t| t.tls.as_ref())
                    && tls_cfg.is_on {
                        for addr_cfg in &tls_cfg.listen {
                            self.spawn_listener(&server, addr_cfg, true).await;
                        }
                    }
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }

    async fn spawn_listener(
        self: &Arc<Self>,
        server: &ServerConfig,
        addr_cfg: &crate::config_models::NetworkAddressConfig,
        is_tls: bool,
    ) {
        if let Ok(port) = addr_cfg
            .port_range
            .clone()
            .unwrap_or_default()
            .parse::<u16>()
        {
            if self.handled_ports.contains_key(&port) {
                return;
            }
            self.handled_ports.insert(port, ());

            let manager = self.clone();
            let server_clone = server.clone();
            tokio::spawn(async move {
                if let Err(e) = manager
                    .clone()
                    .run_tcp_listener(port, server_clone, is_tls)
                    .await
                {
                    error!("TCP listener on port {} failed: {}", port, e);
                    manager.handled_ports.remove(&port);
                }
            });
        }
    }

    async fn run_tcp_listener(
        self: Arc<Self>,
        port: u16,
        server: ServerConfig,
        is_tls: bool,
    ) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        info!("TCP Proxy (TLS={}) listening on {}", is_tls, addr);

        loop {
            let (client_stream, client_addr) = listener.accept().await?;
            let manager = self.clone();
            let server_inner = server.clone();

            tokio::spawn(async move {
                if let Err(e) = manager
                    .handle_connection(client_stream, client_addr, server_inner, is_tls)
                    .await
                {
                    debug!("TCP connection from {} failed: {}", client_addr, e);
                }
            });
        }
    }

    async fn handle_connection(
        self: Arc<Self>,
        client_stream: TcpStream,
        _client_addr: SocketAddr,
        server: ServerConfig,
        _is_tls: bool,
    ) -> anyhow::Result<()> {
        let sid = server.id.unwrap_or(0);
        let lb = self
            .config_store
            .get_lb_by_id(sid)
            .await
            .ok_or_else(|| anyhow::anyhow!("No LB"))?;
        let peer = lb
            .select(b"", 0)
            .ok_or_else(|| anyhow::anyhow!("No backends"))?;
        let backend_stream = TcpStream::connect(peer.addr.to_string()).await?;

        // Metrics: Start connection
        let client_ip = client_stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        crate::metrics::record::request_start(sid, client_ip);

        let res = Self::proxy_bidirectional(sid, client_stream, backend_stream).await;

        // Metrics: End connection
        crate::metrics::record::request_end(sid, 0, 0, false, false, false);
        res
    }

    async fn proxy_bidirectional<C, B>(
        server_id: i64,
        mut client: C,
        mut backend: B,
    ) -> anyhow::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        // For L4, we track bytes copied in each direction
        // copy_bidirectional returns (client_to_backend_bytes, backend_to_client_bytes)
        let (c_to_b, b_to_c) = copy_bidirectional(&mut client, &mut backend).await?;

        // Record Traffic:
        // Downstream Sent = b_to_c (Backend -> Client)
        // Downstream Received = c_to_b (Client -> Backend)
        // Origin Sent = c_to_b
        // Origin Received = b_to_c
        crate::metrics::record::record_origin_traffic(server_id, c_to_b, b_to_c);
        // Note: request_end currently only records downstream bytes_sent.
        // We might need to adjust it or call a new record method for total L4 stats.

        Ok(())
    }
}
