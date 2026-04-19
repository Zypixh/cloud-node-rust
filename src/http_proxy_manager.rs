use crate::config::ConfigStore;
use crate::proxy::EdgeProxy;
use crate::ssl::DynamicCertSelector;
use dashmap::DashMap;
use pingora_core::apps::HttpServerApp;
use pingora_core::protocols::http::server::Session as ServerSession;
use pingora_core::protocols::tls::server::handshake_with_callback;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::http_proxy;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

pub struct HttpProxyManager {
    config_store: ConfigStore,
    cert_selector: Arc<DynamicCertSelector>,
    proxy_logic: EdgeProxy,
    server_conf: Arc<ServerConf>,
    handled_ports: DashMap<u16, bool>, // port -> is_tls
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
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }

    async fn spawn_listener(self: &Arc<Self>, port: u16, is_tls: bool) {
        if self.handled_ports.contains_key(&port) {
            return;
        }
        self.handled_ports.insert(port, is_tls);
        info!("HTTP/HTTPS Proxy Manager: Initializing listener on port {} (TLS={})", port, is_tls);

        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager.clone().run_http_listener(port, is_tls).await {
                error!("HTTP/HTTPS listener on port {} failed: {}", port, e);
                manager.handled_ports.remove(&port);
            }
        });
    }

    async fn run_http_listener(self: Arc<Self>, port: u16, is_tls: bool) -> anyhow::Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        info!("HTTP Proxy (TLS={}) listening on {}", is_tls, addr);

        let proxy = http_proxy(&self.server_conf, self.proxy_logic.clone());
        let proxy_arc = Arc::new(proxy);

        // Standard Pingora shutdown receiver
        let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        loop {
            let (client_stream, _client_addr) = listener.accept().await?;
            let proxy_inner = proxy_arc.clone();
            let selector = self.cert_selector.clone();
            let shutdown_inner = shutdown_rx.clone();

            tokio::spawn(async move {
                let l4_stream = pingora_core::protocols::l4::stream::Stream::from(client_stream);
                let (stream, alpn): (pingora_core::protocols::Stream, Option<Vec<u8>>) = if is_tls {
                    let mut builder = pingora_core::tls::ssl::SslAcceptor::mozilla_intermediate_v5(
                        pingora_core::tls::ssl::SslMethod::tls()
                    ).expect("Failed to create SSL acceptor builder");
                    
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
}
