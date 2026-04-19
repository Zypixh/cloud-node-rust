use crate::config::ConfigStore;
use crate::config_models::ServerConfig;
use crate::ssl::DynamicCertSelector;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};
use pingora_core::tls::ssl::{SslMethod, SslConnector};

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
        debug!("Starting TCP/TLS Proxy Manager...");
        loop {
            let servers = self.config_store.get_all_servers().await;
            debug!("TCP Proxy Manager: Found {} servers in config store", servers.len());
            for server in servers {
                // Handle TCP
                if let Some(tcp_cfg) = &server.tcp {
                    if tcp_cfg.is_on {
                        if tcp_cfg.listen.is_empty() {
                            warn!("TCP Proxy Manager: Server {} has TCP ON but NO listen addresses", server.numeric_id());
                        }
                        for addr_cfg in &tcp_cfg.listen {
                            self.spawn_listener(&server, addr_cfg, false).await;
                        }
                    } else {
                        debug!("TCP Proxy Manager: Server {} TCP is OFF", server.numeric_id());
                    }
                } else {
                    debug!("TCP Proxy Manager: Server {} has NO TCP config", server.numeric_id());
                }
                // Handle TLS (TCP-TLS) — accessed via tcp.tls
                if let Some(tls_cfg) = server.tcp.as_ref().and_then(|t| t.tls.as_ref()) {
                    if tls_cfg.is_on {
                        if tls_cfg.listen.is_empty() {
                            warn!("TCP-TLS Proxy Manager: Server {} has TLS ON but NO listen addresses", server.numeric_id());
                        }
                        for addr_cfg in &tls_cfg.listen {
                            self.spawn_listener(&server, addr_cfg, true).await;
                        }
                    } else {
                        debug!("TCP-TLS Proxy Manager: Server {} TLS is OFF", server.numeric_id());
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
            
            // --- OPTIMIZATION: Downstream TCP ---
            let _ = client_stream.set_nodelay(true);
            
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = client_stream.as_raw_fd();
                let on = 1i32;
                unsafe {
                    libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, &on as *const _ as *const libc::c_void, std::mem::size_of::<i32>() as libc::socklen_t);
                }
            }

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
        client_addr: SocketAddr,
        server: ServerConfig,
        is_tls: bool,
    ) -> anyhow::Result<()> {
        let _sid = server.id.unwrap_or(0);
        
        let l4_stream = pingora_core::protocols::l4::stream::Stream::from(client_stream);

        // 1. Handle TLS Termination if needed
        if is_tls {
            let selector = self._cert_selector.clone();
            let mut builder = pingora_core::tls::ssl::SslAcceptor::mozilla_intermediate_v5(
                pingora_core::tls::ssl::SslMethod::tls()
            ).expect("Failed to create SSL acceptor builder");
            
            // Set ALPN for H2
            builder.set_alpn_select_callback(|_, client_alpn| {
                pingora_core::tls::ssl::select_next_proto(b"\x02h2\x08http/1.1", client_alpn)
                    .ok_or(pingora_core::tls::ssl::AlpnError::NOACK)
            });
            let ssl_acceptor = builder.build();
            
            let callbacks: pingora_core::listeners::TlsAcceptCallbacks = Box::new((*selector).clone());
            let res = pingora_core::protocols::tls::server::handshake_with_callback(&ssl_acceptor, l4_stream, &callbacks).await;

            let tls_stream = res.map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;
            
            self.continue_handle_connection(tls_stream, client_addr, server).await
        } else {
            self.continue_handle_connection(l4_stream, client_addr, server).await
        }
    }

    async fn continue_handle_connection<S>(
        self: Arc<Self>,
        client_stream: S,
        _client_addr: SocketAddr,
        server: ServerConfig,
    ) -> anyhow::Result<()> 
    where S: AsyncRead + AsyncWrite + Unpin + Send + 'static
    {
        let sid = server.id.unwrap_or(0);
        if sid == 0 {
            error!("TCP Proxy: Server has NO ID (parsed as 0), cannot find LB. Server config: {:?}", server);
            return Err(anyhow::anyhow!("Server ID missing"));
        }

        let lb = self
            .config_store
            .get_lb_by_id(sid)
            .await
            .ok_or_else(|| {
                error!("TCP Proxy: No load balancer found for server id {}", sid);
                anyhow::anyhow!("No LB")
            })?;
        
        let peer = lb
            .select(b"", 128)
            .ok_or_else(|| {
                error!("TCP Proxy: No healthy backends found for server id {}", sid);
                anyhow::anyhow!("No backends")
            })?;
        
        let backend_ext = peer.ext.get::<crate::lb_factory::BackendExtension>();
        let use_tls_to_backend = backend_ext.map(|e| e.use_tls).unwrap_or(false);
        
        debug!("TCP Proxy: Forwarding connection from {} to {} (Server ID {}, UpstreamTLS={})", _client_addr, peer.addr, sid, use_tls_to_backend);

        let backend_addr = peer.addr.to_string();
        
        if use_tls_to_backend {
            let ext = backend_ext.expect("Checked use_tls above");
            // Determine SNI Host
            let host = if !ext.host.is_empty() {
                ext.host.clone()
            } else {
                server.get_first_host()
            };

            let connector = SslConnector::builder(SslMethod::tls())
                .expect("Failed to create SSL connector builder")
                .build();
            let mut conn_config = connector.configure().expect("Failed to create connect configuration");
            
            if !ext.tls_verify {
                conn_config.set_verify(pingora_core::tls::ssl::SslVerifyMode::NONE);
            } else {
                conn_config.set_verify(pingora_core::tls::ssl::SslVerifyMode::PEER);
            }

            // TODO: Apply ext.client_cert if provided (needs parsing SSLCertConfig to OpenSSL types)

            let backend_stream = TcpStream::connect(&backend_addr).await
                .map_err(|e| {
                    error!("TCP Proxy: Failed to connect to backend {}: {}", backend_addr, e);
                    e
                })?;

            // --- OPTIMIZATION: Upstream TCP ---
            let _ = backend_stream.set_nodelay(true);
            
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = backend_stream.as_raw_fd();
                let on = 1i32;
                unsafe {
                    libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, &on as *const _ as *const libc::c_void, std::mem::size_of::<i32>() as libc::socklen_t);
                }
            }
            
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::io::AsRawFd;
                let fd = backend_stream.as_raw_fd();
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_CONGESTION,
                        "bbr\0".as_ptr() as *const libc::c_void,
                        4
                    );
                }
            }

            let backend_stream = pingora_core::protocols::l4::stream::Stream::from(backend_stream);

            let backend_stream = pingora_core::protocols::tls::client::handshake(conn_config, &host, backend_stream, None).await
                .map_err(|e| {
                    error!("TCP Proxy: TLS handshake with backend {} (SNI: {}) failed: {}", backend_addr, host, e);
                    e
                })?;

            // Metrics: Start connection
            let client_ip = _client_addr.ip().to_string();
            crate::metrics::record::request_start(sid, client_ip);

            let res = Self::proxy_bidirectional(sid, client_stream, backend_stream).await;
            if let Err(ref e) = res {
                debug!("TCP Proxy: Bidirectional copy (TLS upstream) finished with error: {}", e);
            }
            crate::metrics::record::request_end(sid, 0, 0, false, false, false);
            res
        } else {
            let backend_stream = match TcpStream::connect(&backend_addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!("TCP Proxy: Failed to connect to backend {}: {}", backend_addr, e);
                    return Err(e.into());
                }
            };

            // --- OPTIMIZATION: Upstream TCP ---
            let _ = backend_stream.set_nodelay(true);
            
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = backend_stream.as_raw_fd();
                let on = 1i32;
                unsafe {
                    libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, &on as *const _ as *const libc::c_void, std::mem::size_of::<i32>() as libc::socklen_t);
                }
            }

            #[cfg(target_os = "linux")]
            {
                use std::os::unix::io::AsRawFd;
                let fd = backend_stream.as_raw_fd();
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_CONGESTION,
                        "bbr\0".as_ptr() as *const libc::c_void,
                        4
                    );
                }
            }

            // Metrics: Start connection
            let client_ip = _client_addr.ip().to_string();
            crate::metrics::record::request_start(sid, client_ip);

            let res = Self::proxy_bidirectional(sid, client_stream, backend_stream).await;
            if let Err(ref e) = res {
                debug!("TCP Proxy: Bidirectional copy finished with error: {}", e);
            }
            crate::metrics::record::request_end(sid, 0, 0, false, false, false);
            res
        }
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
