use crate::config::ConfigStore;
use crate::config_models::ServerConfig;
use crate::proxy::EdgeProxy;
use crate::ssl::DynamicCertSelector;
use anyhow::Context;
use dashmap::DashMap;
use pingora_core::apps::HttpServerApp;
use pingora_core::protocols::http::server::Session as ServerSession;
use pingora_core::protocols::tls::server::handshake_with_callback;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::http_proxy;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

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
                debug!("HTTP/HTTPS Proxy Manager: Found {} servers in config store", servers.len());
            }

            for server in servers {
                // 1. Handle HTTP Ports
                if let Some(http_cfg) = &server.http {
                    if http_cfg.is_on {
                        if http_cfg.listen.is_empty() {
                            warn!("HTTP Proxy Manager: Server {} has HTTP ON but NO listen addresses", server.numeric_id());
                        }
                        for addr_cfg in &http_cfg.listen {
                            if let Some(port_str) = &addr_cfg.port_range {
                                let port = port_str.split('-').next().unwrap_or(port_str).parse::<u16>();
                                if let Ok(p) = port {
                                    desired_ports.insert(p, false);
                                    self.spawn_listener(p, false).await;
                                } else {
                                    error!("Failed to parse HTTP port: {:?}", port_str);
                                }
                            }
                        }
                    } else {
                        debug!("HTTP Proxy Manager: Server {} HTTP is OFF", server.numeric_id());
                    }
                } else {
                    debug!("HTTP Proxy Manager: Server {} has NO HTTP config", server.numeric_id());
                }
                // 2. Handle HTTPS Ports
                if let Some(https_cfg) = &server.https {
                    if https_cfg.is_on {
                        if https_cfg.listen.is_empty() {
                            warn!("HTTPS Proxy Manager: Server {} has HTTPS ON but NO listen addresses", server.numeric_id());
                        }
                        for addr_cfg in &https_cfg.listen {
                            if let Some(port_str) = &addr_cfg.port_range {
                                let port = port_str.split('-').next().unwrap_or(port_str).parse::<u16>();
                                if let Ok(p) = port {
                                    desired_ports.insert(p, true);
                                    self.spawn_listener(p, true).await;
                                } else {
                                    error!("Failed to parse HTTPS port: {:?}", port_str);
                                }
                            }
                        }
                    } else {
                        debug!("HTTPS Proxy Manager: Server {} HTTPS is OFF", server.numeric_id());
                    }
                } else {
                    debug!("HTTPS Proxy Manager: Server {} has NO HTTPS config", server.numeric_id());
                }
            }

            self.reconcile_listeners(&desired_ports);
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
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
        self.handled_ports.insert(port, ListenerHandle { is_tls, shutdown_tx });
        info!("HTTP/HTTPS Proxy Manager: Initializing listener on port {} (TLS={})", port, is_tls);

        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.clone().run_http_listener(port, is_tls, shutdown_rx).await {
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
                        info!("HTTP/HTTPS Proxy Manager: Stopping listener on port {} (TLS={})", port, is_tls);
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

        loop {
            let accept_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("HTTP/HTTPS listener on port {} shutting down", port);
                    return Ok(());
                }
                res = listener.accept() => res,
            };
            let (client_stream, client_addr) = accept_result?;
            let proxy_inner = proxy_arc.clone();
            let selector = self.cert_selector.clone();
            let shutdown_inner = shutdown_rx.clone();
            let manager = self.clone();

            tokio::spawn(async move {
                if is_tls {
                    match manager
                        .find_sni_passthrough_server(&client_stream, port)
                        .await
                    {
                        Ok(Some(server)) => {
                            if let Err(err) = manager
                                .handle_sni_passthrough(client_stream, client_addr, server)
                                .await
                            {
                                debug!(
                                    "SNI passthrough connection from {} on port {} failed: {}",
                                    client_addr,
                                    port,
                                    err
                                );
                            }
                            return;
                        }
                        Ok(None) => {}
                        Err(err) => {
                            debug!(
                                "Failed to inspect SNI for {} on port {}: {}",
                                client_addr,
                                port,
                                err
                            );
                        }
                    }
                }

                let l4_stream = pingora_core::protocols::l4::stream::Stream::from(client_stream);
                let (stream, alpn): (pingora_core::protocols::Stream, Option<Vec<u8>>) = if is_tls {
                    let mut builder = pingora_core::tls::ssl::SslAcceptor::mozilla_intermediate_v5(
                        pingora_core::tls::ssl::SslMethod::tls()
                    ).expect("Failed to create SSL acceptor builder");
                    let selector_for_ocsp = selector.clone();
                    let _ = builder.set_status_callback(move |ssl| {
                        selector_for_ocsp.apply_ocsp_for_ssl_blocking(ssl);
                        Ok(ssl.ocsp_status().is_some())
                    });
                    
                    builder.set_alpn_select_callback(|_, client_alpn| {
                        pingora_core::tls::ssl::select_next_proto(b"\x02h2\x08http/1.1", client_alpn)
                            .ok_or(pingora_core::tls::ssl::AlpnError::NOACK)
                    });
                    let ssl_acceptor = builder.build();
                    
                    let callbacks: pingora_core::listeners::TlsAcceptCallbacks = Box::new((*selector).clone());
                    match handshake_with_callback(&ssl_acceptor, l4_stream, &callbacks).await {
                        Ok(s) => {
                            let alpn = s.ssl().selected_alpn_protocol().map(|v| v.to_vec());
                            (Box::new(s), alpn)
                        },
                        Err(e) => {
                            error!("TLS handshake failed: {}", e);
                            return;
                        }
                    }
                } else {
                    (Box::new(l4_stream), None)
                };

                if alpn.as_deref() == Some(b"h2") {
                    // HTTP/2 Logic
                    let digest = Arc::new(pingora_core::protocols::Digest::default());
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
                                        error!("HTTP/2 session error: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => error!("HTTP/2 handshake error: {}", e),
                    }
                } else {
                    // HTTP/1.1 Logic
                    let server_session = ServerSession::new_http1(stream);
                    proxy_inner.process_new_http(server_session, &shutdown_inner).await;
                }
            });
        }
    }

    async fn find_sni_passthrough_server(
        &self,
        client_stream: &TcpStream,
        port: u16,
    ) -> anyhow::Result<Option<ServerConfig>> {
        let host = peek_client_hello_sni(client_stream)
            .await?
            .map(|value| value.trim_end_matches('.').to_ascii_lowercase());
        let Some(host) = host else {
            return Ok(None);
        };

        let Some(server) = self.config_store.get_server_for_tls_name_sync(&host) else {
            return Ok(None);
        };
        if !server.is_sni_passthrough() || !server.listens_on_https_port(port) {
            return Ok(None);
        }
        Ok(Some(server))
    }

    async fn handle_sni_passthrough(
        &self,
        client_stream: TcpStream,
        client_addr: SocketAddr,
        server: ServerConfig,
    ) -> anyhow::Result<()> {
        if server.has_valid_traffic_limit() {
            debug!(
                "SNI passthrough: rejecting connection from {} for traffic-limited server {}",
                client_addr,
                server.numeric_id()
            );
            return Ok(());
        }

        let server_id = server.numeric_id();
        anyhow::ensure!(server_id > 0, "SNI passthrough server is missing ID");

        let lb = self
            .config_store
            .get_lb_by_id(server_id)
            .await
            .with_context(|| format!("missing upstream load balancer for server {}", server_id))?;
        let peer = lb
            .select(b"", 128)
            .with_context(|| format!("no healthy upstream for SNI passthrough server {}", server_id))?;
        let backend_addr = peer.addr.to_string();
        let backend_stream = TcpStream::connect(&backend_addr)
            .await
            .with_context(|| format!("failed to connect passthrough upstream {}", backend_addr))?;

        let _ = client_stream.set_nodelay(true);
        let _ = backend_stream.set_nodelay(true);

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
        );

        let mut client_stream = client_stream;
        let mut backend_stream = backend_stream;
        let result = copy_bidirectional(&mut client_stream, &mut backend_stream).await;
        match result {
            Ok((client_to_backend, backend_to_client)) => {
                crate::metrics::record::request_end(
                    server_id,
                    backend_to_client,
                    client_to_backend,
                    false,
                    false,
                    false,
                );
                crate::metrics::record::record_origin_traffic(
                    server_id,
                    client_to_backend,
                    backend_to_client,
                );
                Ok(())
            }
            Err(err) => {
                crate::metrics::record::request_end(server_id, 0, 0, false, false, false);
                Err(err.into())
            }
        }
    }
}

async fn peek_client_hello_sni(client_stream: &TcpStream) -> anyhow::Result<Option<String>> {
    let mut peek_buf = vec![0u8; 16 * 1024];
    let size = client_stream.peek(&mut peek_buf).await?;
    if size == 0 {
        return Ok(None);
    }
    Ok(parse_tls_client_hello_sni(&peek_buf[..size]))
}

fn parse_tls_client_hello_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 22 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if buf.len() < 5 + record_len || record_len < 4 {
        return None;
    }

    let handshake = &buf[5..5 + record_len];
    if handshake.first().copied()? != 1 {
        return None;
    }
    let hello_len =
        ((usize::from(handshake[1])) << 16) | ((usize::from(handshake[2])) << 8) | usize::from(handshake[3]);
    if handshake.len() < 4 + hello_len {
        return None;
    }

    let hello = &handshake[4..4 + hello_len];
    let mut pos = 0usize;

    pos += 2; // legacy_version
    pos += 32; // random
    if hello.len() < pos + 1 {
        return None;
    }
    let session_len = usize::from(hello[pos]);
    pos += 1 + session_len;
    if hello.len() < pos + 2 {
        return None;
    }
    let cipher_len = usize::from(u16::from_be_bytes([hello[pos], hello[pos + 1]]));
    pos += 2 + cipher_len;
    if hello.len() < pos + 1 {
        return None;
    }
    let compression_len = usize::from(hello[pos]);
    pos += 1 + compression_len;
    if hello.len() < pos + 2 {
        return None;
    }
    let extensions_len = usize::from(u16::from_be_bytes([hello[pos], hello[pos + 1]]));
    pos += 2;
    if hello.len() < pos + extensions_len {
        return None;
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
            return None;
        }
        if ext_type == 0 {
            let ext = &extensions[ext_pos..ext_pos + ext_len];
            if ext.len() < 2 {
                return None;
            }
            let list_len = usize::from(u16::from_be_bytes([ext[0], ext[1]]));
            if ext.len() < 2 + list_len {
                return None;
            }
            let mut name_pos = 2usize;
            while name_pos + 3 <= 2 + list_len {
                let name_type = ext[name_pos];
                let name_len = usize::from(u16::from_be_bytes([
                    ext[name_pos + 1],
                    ext[name_pos + 2],
                ]));
                name_pos += 3;
                if ext.len() < name_pos + name_len {
                    return None;
                }
                if name_type == 0 {
                    let host = std::str::from_utf8(&ext[name_pos..name_pos + name_len]).ok()?;
                    return Some(host.to_ascii_lowercase());
                }
                name_pos += name_len;
            }
        }
        ext_pos += ext_len;
    }
    None
}
