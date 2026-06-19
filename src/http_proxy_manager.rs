use crate::config::ConfigStore;
use crate::config_models::{ProxyProtocolConfig, ServerConfig};
use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR};
use crate::net_bind::{bind_tcp_listener_with_retry, dual_stack_bind_addrs};
use crate::proxy::EdgeProxy;
use crate::proxy_protocol;
use crate::ssl::DynamicCertSelector;
use anyhow::Context;
use dashmap::DashMap;
use pingora_core::apps::HttpServerApp;
use pingora_core::protocols::http::server::Session as ServerSession;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::tls::server::handshake;
use pingora_core::protocols::{ALPN, GetSocketDigest, SocketDigest, Ssl};
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::http_proxy;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

/// Returns true if the accept error is transient and the listener should keep running
/// rather than exiting permanently.
fn is_transient_accept_error(err: &std::io::Error) -> bool {
    match err.kind() {
        std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::Interrupted
        | std::io::ErrorKind::WouldBlock => true,
        _ => {
            #[cfg(unix)]
            {
                match err.raw_os_error() {
                    Some(libc::EMFILE) | Some(libc::ENFILE) => true,
                    _ => false,
                }
            }
            #[cfg(not(unix))]
            {
                false
            }
        }
    }
}

struct ListenerHandle {
    is_tls: bool,
    enable_proxy_protocol: bool,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ListenerConfig {
    is_tls: bool,
    enable_proxy_protocol: bool,
}

struct PassthroughBackendTarget {
    addr: String,
    origin_id: i64,
    proxy_protocol: ProxyProtocolConfig,
}

fn record_desired_listener(
    desired_ports: &mut HashMap<SocketAddr, ListenerConfig>,
    bind_addr: SocketAddr,
    config: ListenerConfig,
    server_id: i64,
) {
    match desired_ports.entry(bind_addr) {
        Entry::Vacant(entry) => {
            entry.insert(config);
        }
        Entry::Occupied(entry) if *entry.get() == config => {}
        Entry::Occupied(entry) => {
            warn!(
                "HTTP/HTTPS Proxy Manager: ignoring conflicting listener config on {} for server {} (existing TLS={}, proxy_protocol={}; requested TLS={}, proxy_protocol={})",
                bind_addr,
                server_id,
                entry.get().is_tls,
                entry.get().enable_proxy_protocol,
                config.is_tls,
                config.enable_proxy_protocol
            );
        }
    }
}

pub struct HttpProxyManager {
    config_store: ConfigStore,
    cert_selector: Arc<DynamicCertSelector>,
    proxy_logic: EdgeProxy,
    server_conf: Arc<ServerConf>,
    handled_ports: DashMap<SocketAddr, ListenerHandle>,
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
                let enable_pp = server.enable_proxy_protocol;
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
                                    for bind_addr in dual_stack_bind_addrs(p) {
                                        record_desired_listener(
                                            &mut desired_ports,
                                            bind_addr,
                                            ListenerConfig {
                                                is_tls: false,
                                                enable_proxy_protocol: enable_pp,
                                            },
                                            server.numeric_id(),
                                        );
                                    }
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
                                    for bind_addr in dual_stack_bind_addrs(p) {
                                        record_desired_listener(
                                            &mut desired_ports,
                                            bind_addr,
                                            ListenerConfig {
                                                is_tls: true,
                                                enable_proxy_protocol: enable_pp,
                                            },
                                            server.numeric_id(),
                                        );
                                    }
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

            for (bind_addr, config) in &desired_ports {
                self.spawn_listener(*bind_addr, config.is_tls, config.enable_proxy_protocol)
                    .await;
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

    async fn spawn_listener(
        self: &Arc<Self>,
        bind_addr: SocketAddr,
        is_tls: bool,
        enable_proxy_protocol: bool,
    ) {
        if let Some(existing) = self.handled_ports.get(&bind_addr) {
            if existing.is_tls == is_tls && existing.enable_proxy_protocol == enable_proxy_protocol
            {
                return;
            }
            let _ = existing.shutdown_tx.send(true);
            drop(existing);
            self.handled_ports.remove(&bind_addr);
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.handled_ports.insert(
            bind_addr,
            ListenerHandle {
                is_tls,
                enable_proxy_protocol,
                shutdown_tx,
            },
        );
        info!(
            "HTTP/HTTPS Proxy Manager: Initializing listener on {} (TLS={}, proxy_protocol={})",
            bind_addr, is_tls, enable_proxy_protocol
        );

        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(e) = manager
                .clone()
                .run_http_listener(bind_addr, is_tls, enable_proxy_protocol, shutdown_rx)
                .await
            {
                error!("HTTP/HTTPS listener on {} failed: {}", bind_addr, e);
                manager.handled_ports.remove(&bind_addr);
            }
        });
    }

    fn reconcile_listeners(&self, desired_ports: &HashMap<SocketAddr, ListenerConfig>) {
        let active_ports: Vec<(SocketAddr, ListenerConfig)> = self
            .handled_ports
            .iter()
            .map(|entry| {
                (
                    *entry.key(),
                    ListenerConfig {
                        is_tls: entry.value().is_tls,
                        enable_proxy_protocol: entry.value().enable_proxy_protocol,
                    },
                )
            })
            .collect();

        for (bind_addr, active) in active_ports {
            match desired_ports.get(&bind_addr) {
                Some(desired) if *desired == active => {}
                _ => {
                    if let Some((_, handle)) = self.handled_ports.remove(&bind_addr) {
                        info!(
                            "HTTP/HTTPS Proxy Manager: Stopping listener on {} (TLS={}, proxy_protocol={})",
                            bind_addr, active.is_tls, active.enable_proxy_protocol
                        );
                        let _ = handle.shutdown_tx.send(true);
                    }
                }
            }
        }
    }

    async fn run_http_listener(
        self: Arc<Self>,
        bind_addr: SocketAddr,
        is_tls: bool,
        enable_proxy_protocol: bool,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let port = bind_addr.port();
        let listener = bind_tcp_listener_with_retry(
            bind_addr,
            MEMORY_GOVERNOR.listener_backlog(),
            &mut shutdown_rx,
        )
        .await?;
        info!("HTTP Proxy (TLS={}) listening on {}", is_tls, bind_addr);

        let mut proxy_logic = self.proxy_logic.clone();
        proxy_logic.tls_downstream = is_tls;
        let proxy = http_proxy(&self.server_conf, proxy_logic);
        let proxy_arc = Arc::new(proxy);

        let shared_ssl_acceptor = if is_tls {
            let rustls_config = crate::ssl::build_rustls_server_config(
                Arc::clone(&self.cert_selector),
                vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                false,
            )
            .context("build rustls HTTP server config")?;
            Some(Arc::new(
                pingora_core::listeners::tls::Acceptor::from_server_config(rustls_config),
            ))
        } else {
            None
        };

        loop {
            let accept_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("HTTP/HTTPS listener on {} shutting down", bind_addr);
                    return Ok(());
                }
                res = listener.accept() => res,
            };
            let (client_stream, client_addr) = match accept_result {
                Ok(result) => result,
                Err(err) if is_transient_accept_error(&err) => {
                    warn!(
                        "Transient accept error on {}: {}. Continuing.",
                        bind_addr, err
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(err) => {
                    error!(
                        "Fatal accept error on {}: {}. Listener stopping.",
                        bind_addr, err
                    );
                    return Err(err.into());
                }
            };
            let main_cluster_scope = crate::special_defense::cluster_block_scope_id(
                self.config_store.get_node_cluster_id_sync(),
            );

            if self.proxy_logic.waf_state.is_blocked(client_addr.ip(), 0)
                || (main_cluster_scope != 0
                    && self
                        .proxy_logic
                        .waf_state
                        .is_blocked(client_addr.ip(), main_cluster_scope))
            {
                continue;
            }

            let Some(connection_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::HttpConnection)
            else {
                warn!(
                    "HTTP connection admission limit reached on {}, dropping connection from {}",
                    bind_addr, client_addr
                );
                continue;
            };

            if !is_tls {
                let proxy_inner = proxy_arc.clone();
                let shutdown_inner = shutdown_rx.clone();
                let manager = self.clone();
                let downstream_read_timeout = manager.downstream_read_timeout();
                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    // Resolve the effective client address, consuming any PROXY header.
                    let Some((effective_addr, client_stream)) =
                        maybe_consume_proxy_protocol_header(
                            client_stream,
                            client_addr,
                            enable_proxy_protocol,
                        )
                        .await
                    else {
                        return;
                    };
                    if main_cluster_scope != 0
                        && manager
                            .proxy_logic
                            .waf_state
                            .is_blocked(effective_addr.ip(), main_cluster_scope)
                    {
                        return;
                    }
                    manager
                        .record_empty_connection_if_no_payload(
                            client_stream,
                            effective_addr,
                            proxy_inner,
                            shutdown_inner,
                            downstream_read_timeout,
                        )
                        .await;
                });
                continue;
            }

            // Optimization: TCP_NODELAY for small file performance
            let _ = client_stream.set_nodelay(true);

            let proxy_inner = proxy_arc.clone();
            let shutdown_inner = shutdown_rx.clone();
            let manager = self.clone();
            let acceptor_clone = shared_ssl_acceptor.clone();
            let tls_handshake_timeout = manager.tls_handshake_timeout();
            let downstream_read_timeout = manager.downstream_read_timeout();
            let http2_handshake_timeout = manager.http2_handshake_timeout();

            tokio::spawn(async move {
                let _connection_permit = connection_permit;
                let mut configured_tls_host = false;
                let mut count_tls_handshake_failure = true;

                // For TLS connections, consume any PROXY Protocol header before
                // the TLS handshake so the TLS ClientHello is at byte 0.
                let Some((client_addr, client_stream)) = maybe_consume_proxy_protocol_header(
                    client_stream,
                    client_addr,
                    enable_proxy_protocol,
                )
                .await
                else {
                    return;
                };
                if main_cluster_scope != 0
                    && manager
                        .proxy_logic
                        .waf_state
                        .is_blocked(client_addr.ip(), main_cluster_scope)
                {
                    return;
                }

                if is_tls {
                    match manager.inspect_tls_host(&client_stream, port).await {
                        Ok(Some(route)) => {
                            configured_tls_host = route.has_l7_server;
                            if let Some(server) = route.sni_passthrough_server {
                                if let Err(err) = manager
                                    .handle_sni_passthrough(
                                        client_stream,
                                        client_addr,
                                        port,
                                        route.host,
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
                            count_tls_handshake_failure = false;
                            debug!(
                                "Failed to inspect SNI for {} on port {}: {}",
                                client_addr, port, err
                            );
                        }
                    }
                }

                let l4_stream = stream_with_socket_digest(client_stream, client_addr);
                let downstream_socket_digest = l4_stream.get_socket_digest();
                let (stream, alpn): (pingora_core::protocols::Stream, Option<ALPN>) =
                    if let Some(ssl_acceptor) = &acceptor_clone {
                        match tokio::time::timeout(
                            tls_handshake_timeout,
                            handshake(ssl_acceptor, l4_stream),
                        )
                        .await
                        {
                            Ok(Ok(s)) => {
                                let alpn = s.selected_alpn_proto();
                                (Box::new(s), alpn)
                            }
                            Ok(Err(e)) => {
                                if !is_benign_tls_accept_error(&e.to_string())
                                    && configured_tls_host
                                {
                                    error!("TLS handshake failed: {}", e);
                                }
                                if count_tls_handshake_failure {
                                    manager.record_tls_handshake_failure(client_addr.ip());
                                }
                                return;
                            }
                            Err(_) => {
                                if configured_tls_host {
                                    debug!(
                                        "TLS handshake timed out after {:?}",
                                        tls_handshake_timeout
                                    );
                                }
                                if count_tls_handshake_failure {
                                    manager.record_tls_handshake_failure(client_addr.ip());
                                }
                                return;
                            }
                        }
                    } else {
                        (Box::new(l4_stream), None)
                    };

                if matches!(alpn, Some(ALPN::H2)) {
                    // HTTP/2 Logic
                    let digest = Arc::new(pingora_core::protocols::Digest {
                        socket_digest: downstream_socket_digest,
                        ..Default::default()
                    });
                    match tokio::time::timeout(
                        http2_handshake_timeout,
                        pingora_core::protocols::http::v2::server::handshake(stream, None),
                    )
                    .await
                    {
                        Ok(Ok(mut h2_conn)) => {
                            let h2_stream_semaphore = Arc::new(tokio::sync::Semaphore::new(
                                MEMORY_GOVERNOR.h2_stream_limit_per_connection(),
                            ));
                            loop {
                                match pingora_core::protocols::http::v2::server::HttpSession::from_h2_conn(&mut h2_conn, digest.clone()).await {
                                    Ok(Some(h2_session)) => {
                                        let proxy_inner_h2 = proxy_inner.clone();
                                        let shutdown_inner_h2 = shutdown_inner.clone();
                                        let Some(stream_permit) = Arc::clone(&h2_stream_semaphore)
                                            .try_acquire_owned()
                                            .ok()
                                        else {
                                            debug!("H2 stream admission limit reached for connection, refusing stream");
                                            continue;
                                        };
                                        let Some(global_stream_permit) =
                                            MEMORY_GOVERNOR.try_admit(AdmissionClass::Http2Stream)
                                        else {
                                            debug!("Global H2 stream admission limit reached, refusing stream");
                                            continue;
                                        };
                                        tokio::spawn(async move {
                                            let _stream_permit = stream_permit;
                                            let _global_stream_permit = global_stream_permit;
                                            let server_session =
                                                ServerSession::new_http2(h2_session);
                                            proxy_inner_h2
                                                .process_new_http(
                                                    server_session,
                                                    &shutdown_inner_h2,
                                                )
                                                .await;
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
                        Ok(Err(e)) => {
                            if !is_benign_h2_error(&e.to_string()) && configured_tls_host {
                                error!("HTTP/2 handshake error: {}", e);
                            }
                        }
                        Err(_) => {
                            if configured_tls_host {
                                debug!(
                                    "HTTP/2 handshake timed out after {:?}",
                                    http2_handshake_timeout
                                );
                            }
                        }
                    }
                } else {
                    process_http1_stream(
                        stream,
                        proxy_inner,
                        shutdown_inner,
                        downstream_read_timeout,
                    )
                    .await;
                }
            });
        }
    }

    fn downstream_read_timeout(&self) -> Duration {
        crate::resource_budget::downstream_read_timeout(
            &self.config_store.get_global_http_config_sync(),
        )
    }

    fn tls_handshake_timeout(&self) -> Duration {
        crate::resource_budget::tls_handshake_timeout(
            &self.config_store.get_global_http_config_sync(),
        )
    }

    fn http2_handshake_timeout(&self) -> Duration {
        crate::resource_budget::http2_handshake_timeout(
            &self.config_store.get_global_http_config_sync(),
        )
    }

    fn empty_connection_flood_config(
        &self,
        cluster_id: i64,
    ) -> Option<crate::special_defense::SpecialDefenseConfig> {
        self.config_store
            .get_empty_connection_flood_config_for_cluster_sync(cluster_id)
    }

    async fn record_empty_connection_if_no_payload(
        self: Arc<Self>,
        client_stream: TcpStream,
        client_addr: SocketAddr,
        proxy_inner: Arc<pingora_proxy::HttpProxy<EdgeProxy>>,
        shutdown_inner: watch::Receiver<bool>,
        downstream_read_timeout: Duration,
    ) {
        let cluster_id = self.config_store.get_node_cluster_id_sync();
        let Some(config) = self.empty_connection_flood_config(cluster_id) else {
            process_plain_http_connection(
                client_stream,
                client_addr,
                proxy_inner,
                shutdown_inner,
                downstream_read_timeout,
            )
            .await;
            return;
        };
        let mut first_byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), client_stream.peek(&mut first_byte))
            .await
        {
            Ok(Ok(0)) => {
                self.record_special_defense_hit(
                    cluster_id,
                    "EMPTY_CONNECTION_FLOOD",
                    client_addr.ip(),
                    config,
                );
            }
            Ok(Ok(_)) => {
                process_plain_http_connection(
                    client_stream,
                    client_addr,
                    proxy_inner,
                    shutdown_inner,
                    downstream_read_timeout,
                )
                .await;
            }
            Ok(Err(_)) | Err(_) => {
                self.record_special_defense_hit(
                    cluster_id,
                    "EMPTY_CONNECTION_FLOOD",
                    client_addr.ip(),
                    config,
                );
            }
        }
    }

    fn record_tls_handshake_failure(&self, ip: IpAddr) {
        let node_id = self
            .proxy_logic
            .api_config
            .node_id
            .parse::<i64>()
            .unwrap_or(0);
        crate::special_defense::record_tls_handshake_failure(
            &self.config_store,
            &self.proxy_logic.waf_state,
            node_id,
            ip,
        );
    }

    fn record_special_defense_hit(
        &self,
        cluster_id: i64,
        defense: &str,
        ip: IpAddr,
        config: crate::special_defense::SpecialDefenseConfig,
    ) {
        let node_id = self
            .proxy_logic
            .api_config
            .node_id
            .parse::<i64>()
            .unwrap_or(0);
        crate::special_defense::record_special_defense_hit(
            &self.proxy_logic.waf_state,
            node_id,
            cluster_id,
            defense,
            ip,
            config,
        );
    }

    async fn inspect_tls_host(
        &self,
        client_stream: &TcpStream,
        port: u16,
    ) -> anyhow::Result<Option<crate::config::TlsRouteInspection>> {
        if !self.config_store.has_any_sni_passthrough_sync() {
            return Ok(None);
        }

        let Some(host) = peek_client_hello_sni(client_stream).await? else {
            return Ok(None);
        };
        Ok(self.config_store.inspect_tls_route_sync(&host, port))
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
        let started_at_millis = crate::utils::time::system_timestamp_millis();
        let request_id = crate::logging::next_request_id();
        let server_id = server.numeric_id();
        anyhow::ensure!(server_id > 0, "SNI passthrough server is missing ID");

        if server.has_valid_traffic_limit() {
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

        let client_ip = client_addr.ip().to_string();
        crate::metrics::record::request_start(
            server_id,
            &client_ip,
            server.user_id,
            user_plan_id,
            plan_id,
            None,
            false,
        );

        let backend_target = self.select_passthrough_backend_target(&server).await?;
        let backend_addr = backend_target.addr;
        let origin_id = backend_target.origin_id;
        let proxy_protocol_to_origin = backend_target.proxy_protocol;
        let _origin_connect_permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::OriginConnect)
            .ok_or_else(|| anyhow::anyhow!("origin connect memory admission rejected"))?;
        let toa_config = self.config_store.get_toa_config_sync();
        let mut backend_stream = match crate::toa::connect_with_toa(
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
                crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                crate::rpc::stats::push_origin_health_event(
                    origin_id,
                    false,
                    started.elapsed().as_millis() as i64,
                );
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
        if proxy_protocol_to_origin.enabled() {
            let destination_addr = backend_stream.peer_addr().ok();
            if let Some(header) = proxy_protocol::build_header(
                proxy_protocol_to_origin,
                client_addr,
                destination_addr,
            ) {
                if let Err(err) =
                    tokio::io::AsyncWriteExt::write_all(&mut backend_stream, &header).await
                {
                    crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                    if let Some(local_port) = toa_local_port {
                        if let Err(err) =
                            crate::toa::unregister_toa_port(toa_config.clone(), local_port).await
                        {
                            debug!("failed to release TOA sender port {}: {}", local_port, err);
                        }
                    }
                    crate::rpc::stats::push_origin_health_event(
                        origin_id,
                        false,
                        started.elapsed().as_millis() as i64,
                    );
                    let reason = format!(
                        "failed to write PROXY Protocol header to passthrough upstream {}: {}",
                        backend_addr, err
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
                        0,
                        0,
                        502,
                        Some(&reason),
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
                        format!(
                            "failed to write PROXY Protocol header to passthrough upstream {}",
                            backend_addr
                        )
                    });
                }
            }
            if let Err(err) = tokio::io::AsyncWriteExt::flush(&mut backend_stream).await {
                crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                if let Some(local_port) = toa_local_port {
                    if let Err(err) =
                        crate::toa::unregister_toa_port(toa_config.clone(), local_port).await
                    {
                        debug!("failed to release TOA sender port {}: {}", local_port, err);
                    }
                }
                crate::rpc::stats::push_origin_health_event(
                    origin_id,
                    false,
                    started.elapsed().as_millis() as i64,
                );
                let reason = format!(
                    "failed to flush PROXY Protocol header to passthrough upstream {}: {}",
                    backend_addr, err
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
                    0,
                    0,
                    502,
                    Some(&reason),
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
                    format!(
                        "failed to flush PROXY Protocol header to passthrough upstream {}",
                        backend_addr
                    )
                });
            }
        }
        crate::origin_state::ORIGIN_STATE_MANAGER.record_success(origin_id);
        let connect_latency_ms = started.elapsed().as_millis() as i64;
        crate::rpc::stats::push_origin_health_event(origin_id, true, connect_latency_ms);

        let result = crate::tcp_proxy::stream_tcp_bidirectional_with_metrics(
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
                let bytes_received = err.bytes_received;
                let bytes_sent = err.bytes_sent;
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
                    502,
                    Some(&err.to_string()),
                );
                crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
                crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(origin_id);
                Err(err.into())
            }
        }
    }

    async fn select_passthrough_backend_target(
        &self,
        server: &ServerConfig,
    ) -> anyhow::Result<PassthroughBackendTarget> {
        let server_id = server.numeric_id();

        if let Some(lb) = self.config_store.get_lb_by_id(server_id).await
            && let Some(peer) = lb.select_with_backup(b"", 16, |origin_id| {
                crate::origin_state::ORIGIN_STATE_MANAGER.is_down(origin_id)
            })
        {
            return Ok(PassthroughBackendTarget {
                addr: normalize_passthrough_target(&peer.addr.to_string()),
                origin_id: crate::lb_factory::peer_origin_id(&peer),
                proxy_protocol: peer
                    .ext
                    .get::<crate::lb_factory::BackendExtension>()
                    .map(|ext| ext.proxy_protocol)
                    .unwrap_or_default(),
            });
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
        let (lb, _) = crate::lb_factory::build_lb_blocking_with_global_http(
            server_id,
            rp_cfg.clone(),
            level,
            parents,
            bypass,
            global_cfg.allow_lan_ip,
            Some((*global_cfg).clone()),
        )
        .await?;
        let peer = lb
            .select_with_backup(b"", 16, |origin_id| {
                crate::origin_state::ORIGIN_STATE_MANAGER.is_down(origin_id)
            })
            .with_context(|| {
                format!(
                    "no healthy upstream for SNI passthrough server {}",
                    server_id
                )
            })?;
        Ok(PassthroughBackendTarget {
            addr: normalize_passthrough_target(&peer.addr.to_string()),
            origin_id: crate::lb_factory::peer_origin_id(&peer),
            proxy_protocol: peer
                .ext
                .get::<crate::lb_factory::BackendExtension>()
                .map(|ext| ext.proxy_protocol)
                .unwrap_or_default(),
        })
    }
}

async fn process_plain_http_connection(
    client_stream: TcpStream,
    client_addr: SocketAddr,
    proxy_inner: Arc<pingora_proxy::HttpProxy<EdgeProxy>>,
    shutdown_inner: watch::Receiver<bool>,
    downstream_read_timeout: Duration,
) {
    let _ = client_stream.set_nodelay(true);
    let l4_stream = stream_with_socket_digest(client_stream, client_addr);
    process_http1_stream(
        Box::new(l4_stream),
        proxy_inner,
        shutdown_inner,
        downstream_read_timeout,
    )
    .await;
}

async fn process_http1_stream(
    stream: pingora_core::protocols::Stream,
    proxy_inner: Arc<pingora_proxy::HttpProxy<EdgeProxy>>,
    shutdown_inner: watch::Receiver<bool>,
    downstream_read_timeout: Duration,
) {
    let mut server_session = ServerSession::new_http1(stream);
    server_session.set_read_timeout(Some(downstream_read_timeout));
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
        next_session.set_read_timeout(Some(downstream_read_timeout));

        result = proxy_inner
            .process_new_http(next_session, &shutdown_inner)
            .await;
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

/// If `enable_proxy_protocol` is true, peek the first bytes of `stream` and
/// attempt to parse a PROXY Protocol v1/v2 header.  When a valid header is
/// found the header bytes are consumed from the stream and the reported source
/// address is returned as a new `SocketAddr`. No header is still accepted for
/// compatibility, but malformed or incomplete PROXY headers are rejected.
async fn maybe_consume_proxy_protocol_header(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    enable_proxy_protocol: bool,
) -> Option<(SocketAddr, TcpStream)> {
    if !enable_proxy_protocol {
        return Some((client_addr, stream));
    }

    // Peek up to PROXY_HEADER_PEEK_LEN bytes.  We may need to grow the buffer
    // for v1 headers that are longer than 16 bytes; the spec limits v1 to
    // 108 bytes so 128 is ample.
    let mut peek_buf = [0u8; 128];
    let peek_n =
        match tokio::time::timeout(Duration::from_millis(200), stream.peek(&mut peek_buf)).await {
            Ok(Ok(n)) => n,
            _ => return Some((client_addr, stream)),
        };

    if peek_n == 0 {
        return Some((client_addr, stream));
    }

    match proxy_protocol::parse_proxy_v1_v2(&peek_buf[..peek_n]) {
        Ok(addr) => {
            // Consume the header bytes from the stream.
            let mut discard = vec![0u8; addr.consumed];
            match stream.read_exact(&mut discard).await {
                Ok(_) => {
                    let effective_addr = match (addr.src_ip, addr.src_port) {
                        (Some(ip), Some(port)) => SocketAddr::new(ip, port),
                        _ => client_addr,
                    };
                    debug!(
                        "PROXY protocol: replaced {} with {}",
                        client_addr, effective_addr
                    );
                    Some((effective_addr, stream))
                }
                Err(e) => {
                    debug!("PROXY protocol: failed to drain header bytes: {}", e);
                    None
                }
            }
        }
        Err(proxy_protocol::ProxyProtocolError::Incomplete) => {
            debug!(
                "PROXY protocol: dropping incomplete header from {}",
                client_addr
            );
            None
        }
        Err(proxy_protocol::ProxyProtocolError::Invalid(err)) => {
            debug!(
                "PROXY protocol: dropping invalid header from {}: {}",
                client_addr, err
            );
            None
        }
        Err(proxy_protocol::ProxyProtocolError::NotProxyProtocol) => Some((client_addr, stream)),
    }
}

async fn peek_client_hello_sni(client_stream: &TcpStream) -> anyhow::Result<Option<String>> {
    const CLIENT_HELLO_TOTAL_TIMEOUT: Duration = Duration::from_secs(2);
    const CLIENT_HELLO_IDLE_TIMEOUT: Duration = Duration::from_millis(500);
    const CLIENT_HELLO_READ_WAIT: Duration = Duration::from_millis(25);
    const CLIENT_HELLO_INITIAL_BUF: usize = 2048;
    const CLIENT_HELLO_MAX_BUF: usize = 16 * 1024;

    let started = tokio::time::Instant::now();
    let mut last_progress = started;
    let mut peek_buf = vec![0u8; CLIENT_HELLO_INITIAL_BUF];
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
                if size == peek_buf.len() && peek_buf.len() < CLIENT_HELLO_MAX_BUF {
                    peek_buf.resize((peek_buf.len() * 2).min(CLIENT_HELLO_MAX_BUF), 0);
                    continue;
                }
                if size > last_size {
                    last_progress = tokio::time::Instant::now();
                } else {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                last_size = size;
            }
            ClientHelloParse::NotClientHello => return Ok(None),
        }
    }
}

#[derive(Debug)]
enum ClientHelloParse {
    Found(String),
    NeedMore,
    NotClientHello,
}

fn parse_tls_client_hello_sni(buf: &[u8]) -> ClientHelloParse {
    if buf.len() < 9 {
        return ClientHelloParse::NeedMore;
    }
    if buf[0] != 22 {
        return ClientHelloParse::NotClientHello;
    }

    let first_record_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if buf.len() < 5 + first_record_len {
        return ClientHelloParse::NeedMore;
    }
    let first_record = &buf[5..5 + first_record_len];
    if first_record.len() < 4 {
        return ClientHelloParse::NeedMore;
    }
    if first_record[0] != 1 {
        return ClientHelloParse::NotClientHello;
    }
    let hello_len = ((usize::from(first_record[1])) << 16)
        | ((usize::from(first_record[2])) << 8)
        | usize::from(first_record[3]);
    let needed_handshake_len = 4 + hello_len;

    let hello_storage;
    let hello = if first_record.len() >= needed_handshake_len {
        &first_record[4..needed_handshake_len]
    } else {
        let mut handshake = Vec::with_capacity(needed_handshake_len);
        let mut pos = 0usize;
        while pos + 5 <= buf.len() && handshake.len() < needed_handshake_len {
            if buf[pos] != 22 {
                return ClientHelloParse::NotClientHello;
            }
            let record_len = usize::from(u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]));
            if buf.len() < pos + 5 + record_len {
                return ClientHelloParse::NeedMore;
            }
            handshake.extend_from_slice(&buf[pos + 5..pos + 5 + record_len]);
            pos += 5 + record_len;
        }
        if handshake.len() < needed_handshake_len {
            return ClientHelloParse::NeedMore;
        }
        hello_storage = handshake;
        &hello_storage[4..needed_handshake_len]
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + payload.len());
        record.push(22);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn client_hello_body(host: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);

        let mut extensions = Vec::new();
        if let Some(host) = host {
            let host = host.as_bytes();
            let mut sni_ext = Vec::new();
            sni_ext.extend_from_slice(&((3 + host.len()) as u16).to_be_bytes());
            sni_ext.push(0);
            sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sni_ext.extend_from_slice(host);
            extensions.extend_from_slice(&0u16.to_be_bytes());
            extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_ext);
        }

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        body
    }

    fn client_hello(host: Option<&str>) -> Vec<u8> {
        let body = client_hello_body(host);
        let mut handshake = Vec::with_capacity(4 + body.len());
        handshake.push(1);
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);
        tls_record(&handshake)
    }

    #[test]
    fn parses_single_record_client_hello_sni_lowercase() {
        match parse_tls_client_hello_sni(&client_hello(Some("EXAMPLE.COM"))) {
            ClientHelloParse::Found(host) => assert_eq!(host, "example.com"),
            _ => panic!("expected SNI"),
        }
    }

    #[test]
    fn parses_fragmented_client_hello_sni() {
        let body = client_hello_body(Some("split.example.com"));
        let mut handshake = Vec::new();
        handshake.push(1);
        handshake.push(((body.len() >> 16) & 0xff) as u8);
        handshake.push(((body.len() >> 8) & 0xff) as u8);
        handshake.push((body.len() & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let split_at = 12;
        let mut records = tls_record(&handshake[..split_at]);
        records.extend_from_slice(&tls_record(&handshake[split_at..]));

        match parse_tls_client_hello_sni(&records) {
            ClientHelloParse::Found(host) => assert_eq!(host, "split.example.com"),
            _ => panic!("expected fragmented SNI"),
        }
    }

    #[test]
    fn partial_record_needs_more() {
        let hello = client_hello(Some("partial.example.com"));
        std::assert_matches!(
            parse_tls_client_hello_sni(&hello[..hello.len() - 3]),
            ClientHelloParse::NeedMore
        );
    }

    #[test]
    fn non_tls_is_not_client_hello() {
        std::assert_matches!(
            parse_tls_client_hello_sni(b"GET / HTTP/1.1\r\n"),
            ClientHelloParse::NotClientHello
        );
    }

    #[tokio::test]
    async fn peek_client_hello_sni_does_not_consume_bytes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hello = client_hello(Some("peek.example.com"));
        let expected = hello.clone();

        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(&hello).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let (mut server_stream, _) = listener.accept().await.unwrap();
        let host = peek_client_hello_sni(&server_stream).await.unwrap();
        assert_eq!(host.as_deref(), Some("peek.example.com"));

        let mut actual = Vec::new();
        server_stream.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        client.await.unwrap();
    }
}
