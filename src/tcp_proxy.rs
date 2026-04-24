use crate::config::ConfigStore;
use crate::config_models::SSLCertConfig;
use crate::config_models::ServerConfig;
use crate::ssl::DynamicCertSelector;
use base64::Engine;
use dashmap::DashMap;
use pingora_core::tls::ext;
use pingora_core::tls::pkey::PKey;
use pingora_core::tls::ssl::{SslConnector, SslMethod};
use pingora_core::tls::x509::X509;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

struct ListenerHandle {
    is_tls: bool,
    shutdown_tx: watch::Sender<bool>,
}

pub struct TcpProxyManager {
    config_store: ConfigStore,
    _cert_selector: Arc<DynamicCertSelector>,
    handled_ports: DashMap<u16, ListenerHandle>,
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
            debug!(
                "TCP Proxy Manager: Found {} servers in config store",
                servers.len()
            );
            let mut desired_ports = std::collections::HashMap::new();
            for server in servers {
                // Handle TCP
                if let Some(tcp_cfg) = &server.tcp {
                    if tcp_cfg.is_on {
                        if tcp_cfg.listen.is_empty() {
                            warn!(
                                "TCP Proxy Manager: Server {} has TCP ON but NO listen addresses",
                                server.numeric_id()
                            );
                        }
                        for addr_cfg in &tcp_cfg.listen {
                            if let Ok(port) = addr_cfg
                                .port_range
                                .clone()
                                .unwrap_or_default()
                                .parse::<u16>()
                            {
                                desired_ports.insert(port, false);
                            }
                            self.spawn_listener(&server, addr_cfg, false).await;
                        }
                    } else {
                        debug!(
                            "TCP Proxy Manager: Server {} TCP is OFF",
                            server.numeric_id()
                        );
                    }
                } else {
                    debug!(
                        "TCP Proxy Manager: Server {} has NO TCP config",
                        server.numeric_id()
                    );
                }
                // Handle TLS (TCP-TLS) — accessed via tcp.tls
                if let Some(tls_cfg) = server.tcp.as_ref().and_then(|t| t.tls.as_ref()) {
                    if tls_cfg.is_on {
                        if tls_cfg.listen.is_empty() {
                            warn!(
                                "TCP-TLS Proxy Manager: Server {} has TLS ON but NO listen addresses",
                                server.numeric_id()
                            );
                        }
                        for addr_cfg in &tls_cfg.listen {
                            if let Ok(port) = addr_cfg
                                .port_range
                                .clone()
                                .unwrap_or_default()
                                .parse::<u16>()
                            {
                                desired_ports.insert(port, true);
                            }
                            self.spawn_listener(&server, addr_cfg, true).await;
                        }
                    } else {
                        debug!(
                            "TCP-TLS Proxy Manager: Server {} TLS is OFF",
                            server.numeric_id()
                        );
                    }
                }
            }
            self.reconcile_listeners(&desired_ports);
            tokio::select! {
                _ = self.config_store.wait_for_runtime_reload() => {
                    debug!("TCP Proxy Manager: Runtime reload notification received");
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
            }
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
            if let Some(existing) = self.handled_ports.get(&port) {
                if existing.is_tls == is_tls {
                    return;
                }
                let _ = existing.shutdown_tx.send(true);
                drop(existing);
                self.handled_ports.remove(&port);
            }

            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            self.handled_ports.insert(
                port,
                ListenerHandle {
                    is_tls,
                    shutdown_tx,
                },
            );

            let manager = self.clone();
            let server_clone = server.clone();
            tokio::spawn(async move {
                if let Err(e) = manager
                    .clone()
                    .run_tcp_listener(port, server_clone, is_tls, shutdown_rx)
                    .await
                {
                    error!("TCP listener on port {} failed: {}", port, e);
                    manager.handled_ports.remove(&port);
                }
            });
        }
    }

    fn reconcile_listeners(&self, desired_ports: &std::collections::HashMap<u16, bool>) {
        let active_ports: Vec<(u16, bool)> = self
            .handled_ports
            .iter()
            .map(|entry| (*entry.key(), entry.value().is_tls))
            .collect();

        for (port, is_tls) in active_ports {
            match desired_ports.get(&port) {
                Some(desired_tls) if *desired_tls == is_tls => {}
                _ => {
                    if let Some((_, handle)) = self.handled_ports.remove(&port) {
                        info!(
                            "TCP Proxy Manager: Stopping listener on port {} (TLS={})",
                            port, is_tls
                        );
                        let _ = handle.shutdown_tx.send(true);
                    }
                }
            }
        }
    }

    async fn run_tcp_listener(
        self: Arc<Self>,
        port: u16,
        server: ServerConfig,
        is_tls: bool,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        info!("TCP Proxy (TLS={}) listening on {}", is_tls, addr);

        loop {
            let accept_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("TCP listener on port {} shutting down", port);
                    return Ok(());
                }
                res = listener.accept() => res,
            };
            let (client_stream, client_addr) = accept_result?;

            // --- OPTIMIZATION: Downstream TCP ---
            let _ = client_stream.set_nodelay(true);

            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = client_stream.as_raw_fd();
                let on = 1i32;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_KEEPALIVE,
                        &on as *const _ as *const libc::c_void,
                        std::mem::size_of::<i32>() as libc::socklen_t,
                    );
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
        if server.has_valid_traffic_limit() {
            debug!(
                "TCP Proxy: rejecting connection from {} for traffic-limited server {}",
                client_addr,
                server.numeric_id()
            );
            return Ok(());
        }

        let _sid = server.id.unwrap_or(0);

        let l4_stream = pingora_core::protocols::l4::stream::Stream::from(client_stream);

        // 1. Handle TLS Termination if needed
        if is_tls {
            let selector = self._cert_selector.clone();
            let mut builder = pingora_core::tls::ssl::SslAcceptor::mozilla_intermediate_v5(
                pingora_core::tls::ssl::SslMethod::tls(),
            )
            .expect("Failed to create SSL acceptor builder");
            let selector_for_ocsp = selector.clone();
            let _ = builder.set_status_callback(move |ssl| {
                selector_for_ocsp.apply_ocsp_for_ssl_blocking(ssl);
                Ok(ssl.ocsp_status().is_some())
            });

            // Set ALPN for H2
            builder.set_alpn_select_callback(|_, client_alpn| {
                pingora_core::tls::ssl::select_next_proto(b"\x02h2\x08http/1.1", client_alpn)
                    .ok_or(pingora_core::tls::ssl::AlpnError::NOACK)
            });
            let ssl_acceptor = builder.build();

            let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
                Box::new((*selector).clone());
            let res = pingora_core::protocols::tls::server::handshake_with_callback(
                &ssl_acceptor,
                l4_stream,
                &callbacks,
            )
            .await;

            let tls_stream = res.map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;

            self.continue_handle_connection(tls_stream, client_addr, server)
                .await
        } else {
            self.continue_handle_connection(l4_stream, client_addr, server)
                .await
        }
    }

    async fn continue_handle_connection<S>(
        self: Arc<Self>,
        client_stream: S,
        client_addr: SocketAddr,
        server: ServerConfig,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let sid = server.id.unwrap_or(0);
        if sid == 0 {
            error!(
                "TCP Proxy: Server has NO ID (parsed as 0), cannot find LB. Server config: {:?}",
                server
            );
            return Err(anyhow::anyhow!("Server ID missing"));
        }
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

        let lb = self.config_store.get_lb_by_id(sid).await.ok_or_else(|| {
            error!("TCP Proxy: No load balancer found for server id {}", sid);
            anyhow::anyhow!("No LB")
        })?;

        let peer = lb
            .select(b"", 128)
            .ok_or_else(|| {
                error!(
                    "TCP Proxy: No healthy backends found for server id {}. names={:?} reverse_proxy={:?}",
                    sid,
                    server.get_plain_server_names(),
                    server.reverse_proxy
                );
                anyhow::anyhow!("No backends")
            })?;

        let backend_ext = peer.ext.get::<crate::lb_factory::BackendExtension>();
        let use_tls_to_backend = backend_ext.map(|e| e.use_tls).unwrap_or(false);

        debug!(
            "TCP Proxy: Forwarding connection from {} to {} (Server ID {}, UpstreamTLS={})",
            client_addr, peer.addr, sid, use_tls_to_backend
        );

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
            let mut conn_config = connector
                .configure()
                .expect("Failed to create connect configuration");

            if !ext.tls_verify {
                conn_config.set_verify(pingora_core::tls::ssl::SslVerifyMode::NONE);
            } else {
                conn_config.set_verify(pingora_core::tls::ssl::SslVerifyMode::PEER);
            }

            if let Some(client_cert) = &ext.client_cert {
                apply_client_cert(&mut conn_config, client_cert)?;
            }

            // Metrics: Start connection
            let client_ip = client_addr.ip().to_string();
            crate::metrics::record::request_start(sid, client_ip, user_id, user_plan_id, plan_id);

            let toa_config = self.config_store.get_toa_config_sync();
            let backend_stream = match crate::toa::connect_with_toa(
                &backend_addr,
                client_addr,
                toa_config.clone(),
                std::time::Duration::from_secs(10),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "TCP Proxy: Failed to connect to backend {}: {}",
                        backend_addr, e
                    );
                    let domain = server
                        .get_plain_server_names()
                        .first()
                        .cloned()
                        .unwrap_or_default();
                    crate::metrics::record::record_http_dimensions(
                        sid,
                        client_addr.ip(),
                        &domain,
                        "-",
                        0,
                        0,
                        0,
                        None,
                    );
                    crate::metrics::record::request_end(sid, 0, 0, false, false, false);
                    return Err(e.into());
                }
            };
            let toa_local_port = backend_stream
                .local_addr()
                .ok()
                .map(|addr| addr.port())
                .filter(|_| toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false));

            // --- OPTIMIZATION: Upstream TCP ---
            let _ = backend_stream.set_nodelay(true);

            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = backend_stream.as_raw_fd();
                let on = 1i32;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_KEEPALIVE,
                        &on as *const _ as *const libc::c_void,
                        std::mem::size_of::<i32>() as libc::socklen_t,
                    );
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
                        4,
                    );
                }
            }

            let backend_stream = pingora_core::protocols::l4::stream::Stream::from(backend_stream);

            let backend_stream = pingora_core::protocols::tls::client::handshake(
                conn_config,
                &host,
                backend_stream,
                None,
            )
            .await
            .map_err(|e| {
                error!(
                    "TCP Proxy: TLS handshake with backend {} (SNI: {}) failed: {}",
                    backend_addr, host, e
                );
                let domain = server
                    .get_plain_server_names()
                    .first()
                    .cloned()
                    .unwrap_or_default();
                crate::metrics::record::record_http_dimensions(
                    sid,
                    client_addr.ip(),
                    &domain,
                    "-",
                    0,
                    0,
                    0,
                    None,
                );
                crate::metrics::record::request_end(sid, 0, 0, false, false, false);
                e
            })?;

            let res = stream_bidirectional_with_metrics(sid, client_stream, backend_stream).await;
            if let Some(local_port) = toa_local_port {
                if let Err(err) =
                    crate::toa::unregister_toa_port(toa_config.clone(), local_port).await
                {
                    debug!(
                        "TCP Proxy: failed to release TOA sender port {}: {}",
                        local_port, err
                    );
                }
            }

            let (_bytes_received, bytes_sent) = match res {
                Ok((r, s)) => (r, s),
                Err(ref e) => {
                    debug!(
                        "TCP Proxy: Bidirectional copy (TLS upstream) finished with error: {}",
                        e
                    );
                    (0, 0)
                }
            };

            let domain = server
                .get_plain_server_names()
                .first()
                .cloned()
                .unwrap_or_default();
            crate::metrics::record::record_http_dimensions(
                sid,
                client_addr.ip(),
                &domain,
                "-",
                bytes_sent as i64,
                0,
                0,
                None,
            );

            crate::metrics::record::request_end(sid, 0, 0, false, false, false);
            res.map(|_| ())
        } else {
            // Metrics: Start connection
            let client_ip = client_addr.ip().to_string();
            crate::metrics::record::request_start(sid, client_ip, user_id, user_plan_id, plan_id);

            let toa_config = self.config_store.get_toa_config_sync();
            let backend_stream = match crate::toa::connect_with_toa(
                &backend_addr,
                client_addr,
                toa_config.clone(),
                std::time::Duration::from_secs(10),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "TCP Proxy: Failed to connect to backend {}: {}",
                        backend_addr, e
                    );
                    let domain = server
                        .get_plain_server_names()
                        .first()
                        .cloned()
                        .unwrap_or_default();
                    crate::metrics::record::record_http_dimensions(
                        sid,
                        client_addr.ip(),
                        &domain,
                        "-",
                        0,
                        0,
                        0,
                        None,
                    );
                    crate::metrics::record::request_end(sid, 0, 0, false, false, false);
                    return Err(e.into());
                }
            };
            let toa_local_port = backend_stream
                .local_addr()
                .ok()
                .map(|addr| addr.port())
                .filter(|_| toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false));

            // --- OPTIMIZATION: Upstream TCP ---
            let _ = backend_stream.set_nodelay(true);

            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                let fd = backend_stream.as_raw_fd();
                let on = 1i32;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_KEEPALIVE,
                        &on as *const _ as *const libc::c_void,
                        std::mem::size_of::<i32>() as libc::socklen_t,
                    );
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
                        4,
                    );
                }
            }

            let res = stream_bidirectional_with_metrics(sid, client_stream, backend_stream).await;
            if let Some(local_port) = toa_local_port {
                if let Err(err) =
                    crate::toa::unregister_toa_port(toa_config.clone(), local_port).await
                {
                    debug!(
                        "TCP Proxy: failed to release TOA sender port {}: {}",
                        local_port, err
                    );
                }
            }

            let (_bytes_received, bytes_sent) = match res {
                Ok((r, s)) => (r, s),
                Err(ref e) => {
                    debug!("TCP Proxy: Bidirectional copy finished with error: {}", e);
                    (0, 0)
                }
            };

            let domain = server
                .get_plain_server_names()
                .first()
                .cloned()
                .unwrap_or_default();
            crate::metrics::record::record_http_dimensions(
                sid,
                client_addr.ip(),
                &domain,
                "-",
                bytes_sent as i64,
                0,
                0,
                None,
            );

            crate::metrics::record::request_end(sid, 0, 0, false, false, false);
            res.map(|_| ())
        }
    }
}

pub(crate) async fn stream_bidirectional_with_metrics<C, B>(
    server_id: i64,
    client: C,
    backend: B,
) -> anyhow::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (client_reader, client_writer) = tokio::io::split(client);
    let (backend_reader, backend_writer) = tokio::io::split(backend);

    let client_to_backend = async move {
        copy_stream_and_track(client_reader, backend_writer, |n| {
            crate::metrics::record::record_transfer(server_id, 0, n);
            crate::metrics::record::record_origin_traffic(server_id, n, 0);
        })
        .await
    };

    let backend_to_client = async move {
        copy_stream_and_track(backend_reader, client_writer, |n| {
            crate::metrics::record::record_transfer(server_id, n, 0);
            crate::metrics::record::record_origin_traffic(server_id, 0, n);
        })
        .await
    };

    let (c_to_b, b_to_c) = tokio::try_join!(client_to_backend, backend_to_client)?;
    Ok((c_to_b, b_to_c))
}

async fn copy_stream_and_track<R, W, F>(
    mut reader: R,
    mut writer: W,
    mut on_chunk: F,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(u64),
{
    let mut total = 0u64;
    let mut buf = [0u8; 16 * 1024];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        writer.write_all(&buf[..n]).await?;
        let n = n as u64;
        total += n;
        on_chunk(n);
    }
}

fn apply_client_cert(
    conn_config: &mut pingora_core::tls::ssl::ConnectConfiguration,
    client_cert: &SSLCertConfig,
) -> anyhow::Result<()> {
    let cert_pem_raw = client_cert
        .cert_data_json
        .as_ref()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing client certificate PEM"))?;
    let key_pem_raw = client_cert
        .key_data_json
        .as_ref()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing client key PEM"))?;

    let cert_bytes = clean_pem_value(cert_pem_raw);
    let key_bytes = clean_pem_value(key_pem_raw);
    let cert_chain = X509::stack_from_pem(&cert_bytes)?;
    let leaf = cert_chain
        .first()
        .ok_or_else(|| anyhow::anyhow!("client certificate chain is empty"))?;
    let key = PKey::private_key_from_pem(&key_bytes)?;

    ext::ssl_use_certificate(conn_config, leaf)?;
    ext::ssl_use_private_key(conn_config, &key)?;
    for cert in cert_chain.iter().skip(1) {
        ext::ssl_add_chain_cert(conn_config, cert)?;
    }
    Ok(())
}

fn clean_pem_value(raw: &str) -> Vec<u8> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw.trim()) {
        return decoded;
    }
    raw.replace("\\n", "\n").into_bytes()
}
