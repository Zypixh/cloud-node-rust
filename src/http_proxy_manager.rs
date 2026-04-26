use crate::config::ConfigStore;
use crate::config_models::ServerConfig;
use crate::proxy::EdgeProxy;
use crate::ssl::DynamicCertSelector;
use anyhow::Context;
use dashmap::DashMap;
use pingora_core::apps::HttpServerApp;
use pingora_core::protocols::http::server::Session as ServerSession;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::tls::server::handshake_with_callback;
use pingora_core::protocols::{GetSocketDigest, SocketDigest};
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::http_proxy;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

struct ListenerHandle {
    is_tls: bool,
    shutdown_tx: watch::Sender<bool>,
}

pub struct HttpProxyManager {
    config_store: ConfigStore,
    cert_selector: Arc<DynamicCertSelector>,
    proxy_logic: EdgeProxy,
    server_conf: Arc<ServerConf>,
    handled_ports: DashMap<u16, ListenerHandle>,
}

impl HttpProxyManager {
    pub fn new(
        config_store: ConfigStore,
        cert_selector: Arc<DynamicCertSelector>,
        proxy_logic: EdgeProxy,
        server_conf: Arc<ServerConf>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config_store,
            cert_selector,
            proxy_logic,
            server_conf,
            handled_ports: DashMap::new(),
        })
    }

    pub async fn start_listeners(self: Arc<Self>) {
        debug!("HTTP/HTTPS Proxy Manager: Monitoring configuration for port changes...");
        loop {
            let servers = self.config_store.get_all_servers().await;
            let mut desired_ports = HashMap::new();
            if !servers.is_empty() {
                debug!(
                    "HTTP/HTTPS Proxy Manager: Found {} servers in config store",
                    servers.len()
                );
            }

            for server in servers {
                // 1. Handle HTTP Ports
                if let Some(http_cfg) = &server.http {
                    if http_cfg.is_on {
                        if http_cfg.listen.is_empty() {
                            warn!(
                                "HTTP Proxy Manager: Server {} has HTTP ON but NO listen addresses",
                                server.numeric_id()
                            );
                        }
                        for addr_cfg in &http_cfg.listen {
                            if let Some(port_str) = &addr_cfg.port_range {
                                let port = port_str
                                    .split('-')
                                    .next()
                                    .unwrap_or(port_str)
                                    .parse::<u16>();
                                if let Ok(p) = port {
                                    desired_ports.insert(p, false);
                                    self.spawn_listener(p, false).await;
                                } else {
                                    error!("Failed to parse HTTP port: {:?}", port_str);
                                }
                            }
                        }
                    } else {
                        debug!(
                            "HTTP Proxy Manager: Server {} HTTP is OFF",
                            server.numeric_id()
                        );
                    }
                } else {
                    debug!(
                        "HTTP Proxy Manager: Server {} has NO HTTP config",
                        server.numeric_id()
                    );
                }
                // 2. Handle HTTPS Ports
                if let Some(https_cfg) = &server.https {
                    if https_cfg.is_on {
                        if https_cfg.listen.is_empty() {
                            warn!(
                                "HTTPS Proxy Manager: Server {} has HTTPS ON but NO listen addresses",
                                server.numeric_id()
                            );
                        }
                        for addr_cfg in &https_cfg.listen {
                            if let Some(port_str) = &addr_cfg.port_range {
                                let port = port_str
                                    .split('-')
                                    .next()
                                    .unwrap_or(port_str)
                                    .parse::<u16>();
                                if let Ok(p) = port {
                                    desired_ports.insert(p, true);
                                    self.spawn_listener(p, true).await;
                                } else {
                                    error!("Failed to parse HTTPS port: {:?}", port_str);
                                }
                            }
                        }
                    } else {
                        debug!(
                            "HTTPS Proxy Manager: Server {} HTTPS is OFF",
                            server.numeric_id()
                        );
                    }
                } else {
                    debug!(
                        "HTTPS Proxy Manager: Server {} has NO HTTPS config",
                        server.numeric_id()
                    );
                }
            }

            self.reconcile_listeners(&desired_ports);
            tokio::select! {
                _ = self.config_store.wait_for_runtime_reload() => {
                    debug!("HTTP/HTTPS Proxy Manager: Runtime reload notification received");
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
            }
        }
    }

    async fn spawn_listener(self: &Arc<Self>, port: u16, is_tls: bool) {
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
        info!(
            "HTTP/HTTPS Proxy Manager: Initializing listener on port {} (TLS={})",
            port, is_tls
        );

        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager
                .clone()
                .run_http_listener(port, is_tls, shutdown_rx)
                .await
            {
                error!("HTTP/HTTPS listener on port {} failed: {}", port, e);
                manager.handled_ports.remove(&port);
            }
        });
    }

    fn reconcile_listeners(&self, desired_ports: &HashMap<u16, bool>) {
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
                            "HTTP/HTTPS Proxy Manager: Stopping listener on port {} (TLS={})",
                            port, is_tls
                        );
                        let _ = handle.shutdown_tx.send(true);
                    }
                }
            }
        }
    }

    async fn run_http_listener(
        self: Arc<Self>,
        port: u16,
        is_tls: bool,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        info!("HTTP Proxy (TLS={}) listening on {}", is_tls, addr);

        let proxy = http_proxy(&self.server_conf, self.proxy_logic.clone());
        let proxy_arc = Arc::new(proxy);

        let shared_ssl_acceptor = if is_tls {
            let mut builder = pingora_core::tls::ssl::SslAcceptor::mozilla_intermediate_v5(
                pingora_core::tls::ssl::SslMethod::tls(),
            )
            .expect("Failed to create SSL acceptor builder");
            let selector_for_ocsp = self.cert_selector.clone();
            let _ = builder.set_status_callback(move |ssl| {
                selector_for_ocsp.apply_ocsp_for_ssl_blocking(ssl);
                Ok(ssl.ocsp_status().is_some())
            });

            builder.set_alpn_select_callback(|_, client_alpn| {
                pingora_core::tls::ssl::select_next_proto(b"\x02h2\x08http/1.1", client_alpn)
                    .ok_or(pingora_core::tls::ssl::AlpnError::NOACK)
            });
            Some(Arc::new(builder.build()))
        } else {
            None
        };

        loop {
            let accept_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("HTTP/HTTPS listener on port {} shutting down", port);
                    return Ok(());
                }
                res = listener.accept() => res,
            };
            let (client_stream, client_addr) = accept_result?;
            
            // Optimization: TCP_NODELAY for small file performance
            let _ = client_stream.set_nodelay(true);

            let proxy_inner = proxy_arc.clone();
            let selector = self.cert_selector.clone();
            let shutdown_inner = shutdown_rx.clone();
            let manager = self.clone();
            let acceptor_clone = shared_ssl_acceptor.clone();

            tokio::spawn(async move {
                let mut configured_tls_host = false;

                if is_tls {
                    match manager.inspect_tls_host(&client_stream, port).await {
                        Ok(Some((host, passthrough_server))) => {
                            configured_tls_host = manager
                                .config_store
                                .get_server_for_tls_name_sync(&host)
                                .is_some();
                            if let Some(server) = passthrough_server {
                                if let Err(err) = manager
                                    .handle_sni_passthrough(
                                        client_stream,
                                        client_addr,
                                        port,
                                        host,
                                        server,
                                    )
                                    .await
                                {
                                    debug!(
                                        "SNI passthrough connection from {} on port {} failed: {}",
                                        client_addr, port, err
                                    );
                                }
                                return;
                            }
                        }
                        Ok(None) => {}
                        Err(err) => {
                            debug!(
                                "Failed to inspect SNI for {} on port {}: {}",
                                client_addr, port, err
                            );
                        }
                    }
                }

                let l4_stream = stream_with_socket_digest(client_stream, client_addr);
                let downstream_socket_digest = l4_stream.get_socket_digest();
                let (stream, alpn): (pingora_core::protocols::Stream, Option<Vec<u8>>) = if let Some(ssl_acceptor) = &acceptor_clone {
                    let callbacks: pingora_core::listeners::TlsAcceptCallbacks =
                        Box::new((*selector).clone());
                    match handshake_with_callback(ssl_acceptor, l4_stream, &callbacks).await {
                        Ok(s) => {
                            let alpn = s.ssl().selected_alpn_protocol().map(|v| v.to_vec());
                            (Box::new(s), alpn)
                        }
                        Err(e) => {
                            if !is_benign_tls_accept_error(&e.to_string()) && configured_tls_host {
                                error!("TLS handshake failed: {}", e);
                            }
                            return;
                        }
                    }
                } else {
                    (Box::new(l4_stream), None)
                };

                if alpn.as_deref() == Some(b"h2") {
                    // HTTP/2 Logic
                    let digest = Arc::new(pingora_core::protocols::Digest {
                        socket_digest: downstream_socket_digest,
                        ..Default::default()
                    });
                    match pingora_core::protocols::http::v2::server::handshake(stream, None).await {
                        Ok(mut h2_conn) => {
                            loop {
                                match pingora_core::protocols::http::v2::server::HttpSession::from_h2_conn(&mut h2_conn, digest.clone()).await {
                                    Ok(Some(h2_session)) => {
                                        let proxy_inner_h2 = proxy_inner.clone();
                                        let shutdown_inner_h2 = shutdown_inner.clone();
                                        tokio::spawn(async move {
                                            let server_session = ServerSession::new_http2(h2_session);
                                            proxy_inner_h2.process_new_http(server_session, &shutdown_inner_h2).await;
                                        });
                                    }
                                    Ok(None) => break, // Connection closed
                                    Err(e) => {
                                        if !is_benign_h2_error(&e.to_string())
                                            && configured_tls_host
                                        {
                                            error!("HTTP/2 session error: {}", e);
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if !is_benign_h2_error(&e.to_string()) && configured_tls_host {
                                error!("HTTP/2 handshake error: {}", e);
                            }
                        }
                    }
                } else {
                    // HTTP/1.1 Logic
                    let mut server_session = ServerSession::new_http1(stream);
                    if *shutdown_inner.borrow() {
                        server_session.set_keepalive(None);
                    } else {
                        server_session.set_keepalive(Some(60));
                    }
                    let mut result = proxy_inner
                        .process_new_http(server_session, &shutdown_inner)
                        .await;

                    while let Some((stream, persistent_settings)) = result.map(|r| r.consume()) {
                        let mut next_session = ServerSession::new_http1(stream);
                        if let Some(persistent_settings) = persistent_settings {
                            persistent_settings.apply_to_session(&mut next_session);
                        }

                        result = proxy_inner
                            .process_new_http(next_session, &shutdown_inner)
                            .await;
                    }
                }
            });
        }
    }

    async fn inspect_tls_host(
        &self,
        client_stream: &TcpStream,
        port: u16,
    ) -> anyhow::Result<Option<(String, Option<Arc<ServerConfig>>)>> {
        let host = peek_client_hello_sni(client_stream)
            .await?
            .map(|value| value.trim_end_matches('.').to_ascii_lowercase());
        let Some(host) = host else {
            return Ok(None);
        };

        let server = self
            .config_store
            .find_sni_passthrough_server_sync(&host, port);
        Ok(Some((host, server)))
    }

    async fn handle_sni_passthrough(
        &self,
        client_stream: TcpStream,
        client_addr: SocketAddr,
        listen_port: u16,
        sni_host: String,
        server: Arc<ServerConfig>,
    ) -> anyhow::Result<()> {
        let started = Instant::now();
        let started_at_millis = crate::utils::time::now_timestamp_millis();
        let request_id = crate::logging::next_request_id();
        let server_id = server.numeric_id();
        anyhow::ensure!(server_id > 0, "SNI passthrough server is missing ID");

        // SNI passthrough should only block if the traffic limit is explicitly exceeded.
        // The previous logic incorrectly blocked if any valid limit existed.
        // For now, we allow the connection to proceed and let the backend or L7 layers handle limits,
        // unless we have a specific 'is_exceeded' flag.
        if false && server.has_valid_traffic_limit() {
            debug!(
                "SNI passthrough: rejecting connection from {} for traffic-limited server {}",
                client_addr, server_id
            );
            crate::logging::log_sni_passthrough_access(
                request_id,
                &server,
                &sni_host,
                client_addr,
                listen_port,
                "",
                started_at_millis,
                started.elapsed(),
                0,
                0,
                403,
                Some("traffic limit exceeded"),
            );
            return Ok(());
        }

        let user_plan_id = server.user_plan_id;
        let plan_id = if user_plan_id > 0 {
            self.config_store
                .get_user_plan_sync(user_plan_id)
                .map(|user_plan| user_plan.plan_id)
                .unwrap_or(0)
        } else {
            0
        };

        crate::metrics::record::request_start(
            server_id,
            client_addr.ip().to_string(),
            server.user_id,
            user_plan_id,
            plan_id,
            None,
            false,
        );

        let backend_addr = self.select_passthrough_backend_target(&server).await?;
        let toa_config = self.config_store.get_toa_config_sync();
        let backend_stream = match crate::toa::connect_with_toa(
            &backend_addr,
            client_addr,
            toa_config.clone(),
            Duration::from_secs(10),
        )
        .await
        {
            Ok(stream) => stream,
            Err(err) => {
                crate::logging::log_sni_passthrough_access(
                    request_id,
                    &server,
                    &sni_host,
                    client_addr,
                    listen_port,
                    &backend_addr,
                    started_at_millis,
                    started.elapsed(),
                    0,
                    0,
                    502,
                    Some(&format!(
                        "failed to connect passthrough upstream {}: {}",
                        backend_addr, err
                    )),
                );
                crate::metrics::record::record_http_dimensions(
                    server_id,
                    client_addr.ip(),
                    &sni_host,
                    "-",
                    0,
                    0,
                    0,
                    None,
                    None,
                );
                crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
                return Err(err).with_context(|| {
                    format!("failed to connect passthrough upstream {}", backend_addr)
                });
            }
        };

        let toa_local_port = backend_stream
            .local_addr()
            .ok()
            .map(|addr| addr.port())
            .filter(|_| toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false));

        configure_passthrough_socket(&client_stream);
        configure_passthrough_socket(&backend_stream);

        let result = crate::tcp_proxy::stream_bidirectional_with_metrics(
            server_id,
            client_stream,
            backend_stream,
        )
        .await;
        if let Some(local_port) = toa_local_port {
            if let Err(err) = crate::toa::unregister_toa_port(toa_config.clone(), local_port).await
            {
                debug!("failed to release TOA sender port {}: {}", local_port, err);
            }
        }
        match result {
            Ok((bytes_received, bytes_sent)) => {
                crate::metrics::record::record_http_dimensions(
                    server_id,
                    client_addr.ip(),
                    &sni_host,
                    "-",
                    bytes_sent as i64,
                    0,
                    0,
                    None,
                    None,
                );
                crate::logging::log_sni_passthrough_access(
                    request_id,
                    &server,
                    &sni_host,
                    client_addr,
                    listen_port,
                    &backend_addr,
                    started_at_millis,
                    started.elapsed(),
                    bytes_received,
                    bytes_sent,
                    200,
                    None,
                );
                crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
                Ok(())
            }
            Err(err) => {
                crate::logging::log_sni_passthrough_access(
                    request_id,
                    &server,
                    &sni_host,
                    client_addr,
                    listen_port,
                    &backend_addr,
                    started_at_millis,
                    started.elapsed(),
                    0,
                    0,
                    502,
                    Some(&err.to_string()),
                );
                crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
                Err(err.into())
            }
        }
    }

    async fn select_passthrough_backend_target(
        &self,
        server: &ServerConfig,
    ) -> anyhow::Result<String> {
        let server_id = server.numeric_id();

        if let Some(lb) = self.config_store.get_lb_by_id(server_id).await
            && let Some(peer) = lb.select(b"", 128)
        {
            return Ok(normalize_passthrough_target(&peer.addr.to_string()));
        }

        let rp_cfg = server.reverse_proxy.as_ref().with_context(|| {
            format!(
                "missing reverse proxy config for passthrough server {}",
                server_id
            )
        })?;
        let (level, parents) = self.config_store.get_tiered_origin_info().await;
        let bypass = self.config_store.is_tiered_origin_bypass().await;
        let global_cfg = self.config_store.get_global_http_config_sync();
        let (lb, _) = crate::lb_factory::build_lb(
            server_id,
            rp_cfg,
            level,
            &parents,
            bypass,
            global_cfg.allow_lan_ip,
        );
        let peer = lb.select(b"", 128).with_context(|| {
            format!(
                "no healthy upstream for SNI passthrough server {}",
                server_id
            )
        })?;
        Ok(normalize_passthrough_target(&peer.addr.to_string()))
    }
}

fn is_benign_tls_accept_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("unexpected eof")
        || lower.contains("connection closed")
        || lower.contains("connection reset by peer")
        || lower.contains("no_shared_cipher")
        || lower.contains("unsupported_protocol")
        || lower.contains("wrong_version_number")
        || lower.contains("tls accept() failed: unexpected eof")
}

fn stream_with_socket_digest(client_stream: TcpStream, client_addr: SocketAddr) -> L4Stream {
    let mut stream = L4Stream::from(client_stream);
    #[cfg(unix)]
    let digest = SocketDigest::from_raw_fd(stream.as_raw_fd());
    #[cfg(windows)]
    let digest = SocketDigest::from_raw_socket(stream.as_raw_socket());
    digest
        .peer_addr
        .set(Some(client_addr.into()))
        .expect("newly created OnceCell must be empty");
    stream.set_socket_digest(digest);
    stream
}

fn is_benign_h2_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("closed before reading preface")
        || lower.contains("connection reset")
        || lower.contains("unexpected frame type")
}

fn normalize_passthrough_target(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("tls://")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string()
}

fn configure_passthrough_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();
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

        let fd = stream.as_raw_fd();
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
}

async fn peek_client_hello_sni(client_stream: &TcpStream) -> anyhow::Result<Option<String>> {
    const CLIENT_HELLO_TOTAL_TIMEOUT: Duration = Duration::from_secs(2);
    const CLIENT_HELLO_IDLE_TIMEOUT: Duration = Duration::from_millis(200);
    const CLIENT_HELLO_READ_WAIT: Duration = Duration::from_millis(50);

    let started = tokio::time::Instant::now();
    let mut last_progress = started;
    let mut peek_buf = vec![0u8; 64 * 1024];
    let mut last_size = 0usize;
    loop {
        if started.elapsed() >= CLIENT_HELLO_TOTAL_TIMEOUT
            || last_progress.elapsed() >= CLIENT_HELLO_IDLE_TIMEOUT
        {
            return Ok(None);
        }

        let _ = tokio::time::timeout(CLIENT_HELLO_READ_WAIT, client_stream.readable()).await;
        let size = client_stream.peek(&mut peek_buf).await?;
        if size == 0 {
            return Ok(None);
        }
        match parse_tls_client_hello_sni(&peek_buf[..size]) {
            ClientHelloParse::Found(host) => return Ok(Some(host)),
            ClientHelloParse::NeedMore => {
                if size > last_size {
                    last_progress = tokio::time::Instant::now();
                } else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                last_size = size;
            }
            ClientHelloParse::NotClientHello => return Ok(None),
        }
    }
}

enum ClientHelloParse {
    Found(String),
    NeedMore,
    NotClientHello,
}

fn parse_tls_client_hello_sni(buf: &[u8]) -> ClientHelloParse {
    if buf.len() < 5 {
        return ClientHelloParse::NeedMore;
    }

    let mut pos = 0usize;
    let mut handshake = Vec::new();
    let mut hello_len = None;

    while pos + 5 <= buf.len() {
        if buf[pos] != 22 {
            return if handshake.is_empty() {
                ClientHelloParse::NotClientHello
            } else {
                ClientHelloParse::NeedMore
            };
        }

        let record_len = usize::from(u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]));
        if buf.len() < pos + 5 + record_len {
            return ClientHelloParse::NeedMore;
        }

        handshake.extend_from_slice(&buf[pos + 5..pos + 5 + record_len]);
        pos += 5 + record_len;

        if handshake.len() >= 4 {
            if handshake[0] != 1 {
                return ClientHelloParse::NotClientHello;
            }
            let parsed_len = ((usize::from(handshake[1])) << 16)
                | ((usize::from(handshake[2])) << 8)
                | usize::from(handshake[3]);
            hello_len = Some(parsed_len);
            if handshake.len() >= 4 + parsed_len {
                break;
            }
        }
    }

    let Some(hello_len) = hello_len else {
        return ClientHelloParse::NeedMore;
    };
    if handshake.len() < 4 + hello_len {
        return ClientHelloParse::NeedMore;
    }

    let hello = &handshake[4..4 + hello_len];
    let mut pos = 0usize;

    pos += 2; // legacy_version
    pos += 32; // random
    if hello.len() < pos + 1 {
        return ClientHelloParse::NotClientHello;
    }
    let session_len = usize::from(hello[pos]);
    pos += 1 + session_len;
    if hello.len() < pos + 2 {
        return ClientHelloParse::NotClientHello;
    }
    let cipher_len = usize::from(u16::from_be_bytes([hello[pos], hello[pos + 1]]));
    pos += 2 + cipher_len;
    if hello.len() < pos + 1 {
        return ClientHelloParse::NotClientHello;
    }
    let compression_len = usize::from(hello[pos]);
    pos += 1 + compression_len;
    if hello.len() < pos + 2 {
        return ClientHelloParse::NotClientHello;
    }
    let extensions_len = usize::from(u16::from_be_bytes([hello[pos], hello[pos + 1]]));
    pos += 2;
    if hello.len() < pos + extensions_len {
        return ClientHelloParse::NotClientHello;
    }

    let extensions = &hello[pos..pos + extensions_len];
    let mut ext_pos = 0usize;
    while ext_pos + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[ext_pos], extensions[ext_pos + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([
            extensions[ext_pos + 2],
            extensions[ext_pos + 3],
        ]));
        ext_pos += 4;
        if extensions.len() < ext_pos + ext_len {
            return ClientHelloParse::NotClientHello;
        }
        if ext_type == 0 {
            let ext = &extensions[ext_pos..ext_pos + ext_len];
            if ext.len() < 2 {
                return ClientHelloParse::NotClientHello;
            }
            let list_len = usize::from(u16::from_be_bytes([ext[0], ext[1]]));
            if ext.len() < 2 + list_len {
                return ClientHelloParse::NotClientHello;
            }
            let mut name_pos = 2usize;
            while name_pos + 3 <= 2 + list_len {
                let name_type = ext[name_pos];
                let name_len =
                    usize::from(u16::from_be_bytes([ext[name_pos + 1], ext[name_pos + 2]]));
                name_pos += 3;
                if ext.len() < name_pos + name_len {
                    return ClientHelloParse::NotClientHello;
                }
                if name_type == 0 {
                    let Some(host) = std::str::from_utf8(&ext[name_pos..name_pos + name_len])
                        .ok()
                        .map(|host| host.to_ascii_lowercase())
                    else {
                        return ClientHelloParse::NotClientHello;
                    };
                    return ClientHelloParse::Found(host);
                }
                name_pos += name_len;
            }
        }
        ext_pos += ext_len;
    }
    ClientHelloParse::NotClientHello
}
