use crate::config::ConfigStore;
use crate::config_models::ServerConfig;
use crate::config_models::{ProxyProtocolConfig, SSLCertConfig};
use crate::firewall::state::WafStateManager;
use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR};
use crate::net_bind::{bind_tcp_listener_with_retry, dual_stack_bind_addrs};
use crate::proxy_protocol;
use crate::ssl::DynamicCertSelector;
use base64::Engine;
use dashmap::DashMap;
use lru::LruCache;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::LazyLock as Lazy;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

struct ListenerHandle {
    is_tls: bool,
    shutdown_tx: watch::Sender<bool>,
}

#[derive(Clone)]
struct ParsedClientCert {
    cert_chain: Arc<Vec<CertificateDer<'static>>>,
    key: Arc<PrivateKeyDer<'static>>,
}

struct TcpForwardContext {
    sid: i64,
    user_id: i64,
    user_plan_id: i64,
    plan_id: i64,
    origin_id: i64,
    backend_addr: String,
    backend_ext: Option<crate::lb_factory::BackendExtension>,
    use_tls_to_backend: bool,
}

static CLIENT_CERT_CACHE: Lazy<Mutex<LruCache<String, ParsedClientCert>>> =
    Lazy::new(|| Mutex::new(LruCache::new(NonZeroUsize::MIN)));

pub struct TcpProxyManager {
    config_store: ConfigStore,
    _cert_selector: Arc<DynamicCertSelector>,
    waf_state: Arc<WafStateManager>,
    node_id: i64,
    handled_ports: DashMap<SocketAddr, ListenerHandle>,
}

impl TcpProxyManager {
    fn tls_handshake_timeout(&self) -> std::time::Duration {
        crate::resource_budget::tls_handshake_timeout(
            &self.config_store.get_global_http_config_sync(),
        )
    }

    pub fn new(
        config_store: ConfigStore,
        cert_selector: Arc<DynamicCertSelector>,
        waf_state: Arc<WafStateManager>,
        node_id: i64,
    ) -> Arc<Self> {
        Arc::new(Self {
            config_store,
            _cert_selector: cert_selector,
            waf_state,
            node_id,
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
            resize_client_cert_cache_for_servers(&servers);
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
                                for bind_addr in dual_stack_bind_addrs(port) {
                                    desired_ports.insert(bind_addr, false);
                                    self.spawn_listener(&server, bind_addr, false).await;
                                }
                            } else {
                                error!(
                                    "Failed to parse TCP port: {:?}",
                                    addr_cfg.port_range.as_deref()
                                );
                            }
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
                                for bind_addr in dual_stack_bind_addrs(port) {
                                    desired_ports.insert(bind_addr, true);
                                    self.spawn_listener(&server, bind_addr, true).await;
                                }
                            } else {
                                error!(
                                    "Failed to parse TCP-TLS port: {:?}",
                                    addr_cfg.port_range.as_deref()
                                );
                            }
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
        server: &Arc<ServerConfig>,
        bind_addr: SocketAddr,
        is_tls: bool,
    ) {
        if let Some(existing) = self.handled_ports.get(&bind_addr) {
            if existing.is_tls == is_tls {
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
                shutdown_tx,
            },
        );

        let manager = self.clone();
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = manager
                .clone()
                .run_tcp_listener(bind_addr, server, is_tls, shutdown_rx)
                .await
            {
                error!("TCP listener on {} failed: {}", bind_addr, e);
                manager.handled_ports.remove(&bind_addr);
            }
        });
    }

    fn reconcile_listeners(&self, desired_ports: &std::collections::HashMap<SocketAddr, bool>) {
        let active_ports: Vec<(SocketAddr, bool)> = self
            .handled_ports
            .iter()
            .map(|entry| (*entry.key(), entry.value().is_tls))
            .collect();

        for (bind_addr, is_tls) in active_ports {
            match desired_ports.get(&bind_addr) {
                Some(desired_tls) if *desired_tls == is_tls => {}
                _ => {
                    if let Some((_, handle)) = self.handled_ports.remove(&bind_addr) {
                        info!(
                            "TCP Proxy Manager: Stopping listener on {} (TLS={})",
                            bind_addr, is_tls
                        );
                        let _ = handle.shutdown_tx.send(true);
                    }
                }
            }
        }
    }

    async fn run_tcp_listener(
        self: Arc<Self>,
        bind_addr: SocketAddr,
        server: Arc<ServerConfig>,
        is_tls: bool,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let listener = bind_tcp_listener_with_retry(
            bind_addr,
            MEMORY_GOVERNOR.listener_backlog(),
            &mut shutdown_rx,
        )
        .await?;
        info!("TCP Proxy (TLS={}) listening on {}", is_tls, bind_addr);

        let shared_ssl_acceptor = if is_tls {
            let rustls_config = crate::ssl::build_rustls_server_config(
                Arc::clone(&self._cert_selector),
                Vec::new(),
                false,
            )
            .map_err(|err| anyhow::anyhow!("build rustls TCP server config: {}", err))?;
            Some(Arc::new(
                pingora_core::listeners::tls::Acceptor::from_server_config(rustls_config),
            ))
        } else {
            None
        };

        loop {
            let accept_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("TCP listener on {} shutting down", bind_addr);
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
            let server = server.clone();
            let acceptor_clone = shared_ssl_acceptor.clone();
            let Some(connection_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::TcpConnection)
            else {
                warn!(
                    "TCP connection admission limit reached on {}, dropping connection from {}",
                    bind_addr, client_addr
                );
                continue;
            };

            tokio::spawn(async move {
                let _connection_permit = connection_permit;
                if let Err(e) = manager
                    .handle_connection(client_stream, client_addr, server, is_tls, acceptor_clone)
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
        server: Arc<ServerConfig>,
        is_tls: bool,
        shared_ssl_acceptor: Option<Arc<pingora_core::listeners::tls::Acceptor>>,
    ) -> anyhow::Result<()> {
        if server.has_valid_traffic_limit() {
            debug!(
                "TCP Proxy: rejecting connection from {} for traffic-limited server {}",
                client_addr,
                server.numeric_id()
            );
            return Ok(());
        }

        let main_cluster_scope = crate::special_defense::cluster_block_scope_id(
            self.config_store.get_node_cluster_id_sync(),
        );
        if self.waf_state.is_blocked(client_addr.ip(), 0)
            || (main_cluster_scope != 0
                && self
                    .waf_state
                    .is_blocked(client_addr.ip(), main_cluster_scope))
        {
            return Ok(());
        }

        let _sid = server.id.unwrap_or(0);

        // Apply PROXY Protocol header parsing before branching on TLS vs plain.
        let Some((client_addr, client_stream)) = maybe_consume_proxy_protocol_header(
            client_stream,
            client_addr,
            server.enable_proxy_protocol,
        )
        .await
        else {
            return Ok(());
        };
        if main_cluster_scope != 0
            && self
                .waf_state
                .is_blocked(client_addr.ip(), main_cluster_scope)
        {
            return Ok(());
        }

        if !is_tls {
            return self
                .continue_handle_raw_tcp_connection(client_stream, client_addr, server)
                .await;
        }

        let l4_stream = pingora_core::protocols::l4::stream::Stream::from(client_stream);
        let Some(ssl_acceptor) = shared_ssl_acceptor else {
            return Err(anyhow::anyhow!("Missing SSL Acceptor for TLS connection"));
        };
        let tls_handshake_timeout = self.tls_handshake_timeout();
        let res = match tokio::time::timeout(
            tls_handshake_timeout,
            pingora_core::protocols::tls::server::handshake(&ssl_acceptor, l4_stream),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => {
                self.record_tls_handshake_failure(client_addr.ip());
                return Err(anyhow::anyhow!(
                    "TLS handshake timed out after {:?}",
                    tls_handshake_timeout
                ));
            }
        };

        let tls_stream = match res {
            Ok(stream) => stream,
            Err(e) => {
                self.record_tls_handshake_failure(client_addr.ip());
                return Err(anyhow::anyhow!("TLS handshake failed: {}", e));
            }
        };

        self.continue_handle_connection(tls_stream, client_addr, server)
            .await
    }

    async fn tcp_forward_context(
        &self,
        client_addr: SocketAddr,
        server: &Arc<ServerConfig>,
    ) -> anyhow::Result<TcpForwardContext> {
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
            .select_with_backup(b"", 16, |origin_id| {
                crate::origin_state::ORIGIN_STATE_MANAGER.is_down(origin_id)
            })
            .ok_or_else(|| {
                error!(
                    "TCP Proxy: No healthy backends found for server id {}. names={:?} reverse_proxy={:?}",
                    sid,
                    server.get_plain_server_names(),
                    server.reverse_proxy
                );
                anyhow::anyhow!("No backends")
            })?;

        let origin_id = crate::lb_factory::peer_origin_id(&peer);
        let backend_ext = peer
            .ext
            .get::<crate::lb_factory::BackendExtension>()
            .cloned();
        let use_tls_to_backend = backend_ext.as_ref().map(|e| e.use_tls).unwrap_or(false);

        debug!(
            "TCP Proxy: Forwarding connection from {} to {} (Server ID {}, UpstreamTLS={})",
            client_addr, peer.addr, sid, use_tls_to_backend
        );

        Ok(TcpForwardContext {
            sid,
            user_id,
            user_plan_id,
            plan_id,
            origin_id,
            backend_addr: peer.addr.to_string(),
            backend_ext,
            use_tls_to_backend,
        })
    }

    async fn continue_handle_connection<S>(
        self: Arc<Self>,
        client_stream: S,
        client_addr: SocketAddr,
        server: Arc<ServerConfig>,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let context = self.tcp_forward_context(client_addr, &server).await?;
        self.continue_handle_generic_stream(client_stream, client_addr, server, context)
            .await
    }

    async fn continue_handle_raw_tcp_connection(
        self: Arc<Self>,
        client_stream: TcpStream,
        client_addr: SocketAddr,
        server: Arc<ServerConfig>,
    ) -> anyhow::Result<()> {
        let context = self.tcp_forward_context(client_addr, &server).await?;
        if context.use_tls_to_backend {
            self.continue_handle_generic_stream(client_stream, client_addr, server, context)
                .await
        } else {
            self.continue_handle_raw_plain_stream(client_stream, client_addr, server, context)
                .await
        }
    }

    async fn continue_handle_generic_stream<S>(
        self: Arc<Self>,
        client_stream: S,
        client_addr: SocketAddr,
        server: Arc<ServerConfig>,
        context: TcpForwardContext,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if context.use_tls_to_backend {
            let origin_connect_permit = MEMORY_GOVERNOR
                .try_admit(AdmissionClass::OriginConnect)
                .ok_or_else(|| anyhow::anyhow!("origin connect memory admission rejected"))?;
            let ext = context.backend_ext.as_ref().expect("Checked use_tls above");
            let host = if !ext.host.is_empty() {
                ext.host.clone()
            } else {
                server.get_first_host()
            };

            let verify_origin_tls = crate::lb_factory::should_verify_origin_tls(ext, &host, None);
            let tls_connector =
                build_upstream_tls_connector(verify_origin_tls, ext.client_cert.as_ref())?;

            self.record_request_start(client_addr, &context);
            let toa_config = self.config_store.get_toa_config_sync();
            let mut backend_stream = match crate::toa::connect_with_toa(
                &context.backend_addr,
                client_addr,
                toa_config.clone(),
                std::time::Duration::from_secs(10),
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    self.record_backend_connect_failure(client_addr, &server, &context);
                    return Err(e.into());
                }
            };
            let toa_local_port = backend_stream
                .local_addr()
                .ok()
                .map(|addr| addr.port())
                .filter(|_| toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false));

            configure_backend_tcp_socket(&backend_stream);
            let proxy_protocol = context
                .backend_ext
                .as_ref()
                .map(|ext| ext.proxy_protocol)
                .unwrap_or_default();
            if proxy_protocol.enabled() {
                if let Err(err) =
                    write_proxy_protocol_header(&mut backend_stream, client_addr, proxy_protocol)
                        .await
                {
                    release_toa_port(toa_config, toa_local_port).await;
                    self.record_backend_connect_failure(client_addr, &server, &context);
                    return Err(err.into());
                }
            }
            let backend_stream = pingora_core::protocols::l4::stream::Stream::from(backend_stream);
            let backend_stream = pingora_core::protocols::tls::client::handshake(
                &tls_connector,
                &host,
                backend_stream,
            )
            .await
            .map_err(|e| {
                error!(
                    "TCP Proxy: TLS handshake with backend {} (SNI: {}) failed: {}",
                    context.backend_addr, host, e
                );
                self.record_backend_connect_failure(client_addr, &server, &context);
                e
            })?;

            crate::origin_state::ORIGIN_STATE_MANAGER.record_success(context.origin_id);
            drop(origin_connect_permit);
            let res =
                stream_bidirectional_with_metrics(context.sid, client_stream, backend_stream).await;
            release_toa_port(toa_config, toa_local_port).await;
            self.finish_tcp_connection(client_addr, &server, &context, &res);
            res.map(|_| ()).map_err(Into::into)
        } else {
            self.continue_handle_generic_plain_stream(client_stream, client_addr, server, context)
                .await
        }
    }

    async fn continue_handle_generic_plain_stream<S>(
        self: Arc<Self>,
        client_stream: S,
        client_addr: SocketAddr,
        server: Arc<ServerConfig>,
        context: TcpForwardContext,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let origin_connect_permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::OriginConnect)
            .ok_or_else(|| anyhow::anyhow!("origin connect memory admission rejected"))?;
        self.record_request_start(client_addr, &context);
        let toa_config = self.config_store.get_toa_config_sync();
        let mut backend_stream = match crate::toa::connect_with_toa(
            &context.backend_addr,
            client_addr,
            toa_config.clone(),
            std::time::Duration::from_secs(10),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                self.record_backend_connect_failure(client_addr, &server, &context);
                return Err(e.into());
            }
        };
        let toa_local_port = backend_stream
            .local_addr()
            .ok()
            .map(|addr| addr.port())
            .filter(|_| toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false));

        configure_backend_tcp_socket(&backend_stream);
        let proxy_protocol = context
            .backend_ext
            .as_ref()
            .map(|ext| ext.proxy_protocol)
            .unwrap_or_default();
        if proxy_protocol.enabled() {
            if let Err(err) =
                write_proxy_protocol_header(&mut backend_stream, client_addr, proxy_protocol).await
            {
                release_toa_port(toa_config, toa_local_port).await;
                self.record_backend_connect_failure(client_addr, &server, &context);
                return Err(err.into());
            }
        }
        crate::origin_state::ORIGIN_STATE_MANAGER.record_success(context.origin_id);
        drop(origin_connect_permit);
        let res =
            stream_bidirectional_with_metrics(context.sid, client_stream, backend_stream).await;
        release_toa_port(toa_config, toa_local_port).await;
        self.finish_tcp_connection(client_addr, &server, &context, &res);
        res.map(|_| ()).map_err(Into::into)
    }

    async fn continue_handle_raw_plain_stream(
        self: Arc<Self>,
        client_stream: TcpStream,
        client_addr: SocketAddr,
        server: Arc<ServerConfig>,
        context: TcpForwardContext,
    ) -> anyhow::Result<()> {
        let origin_connect_permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::OriginConnect)
            .ok_or_else(|| anyhow::anyhow!("origin connect memory admission rejected"))?;
        self.record_request_start(client_addr, &context);
        let toa_config = self.config_store.get_toa_config_sync();
        let mut backend_stream = match crate::toa::connect_with_toa(
            &context.backend_addr,
            client_addr,
            toa_config.clone(),
            std::time::Duration::from_secs(10),
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                self.record_backend_connect_failure(client_addr, &server, &context);
                return Err(e.into());
            }
        };
        let toa_local_port = backend_stream
            .local_addr()
            .ok()
            .map(|addr| addr.port())
            .filter(|_| toa_config.as_ref().map(|cfg| cfg.is_on).unwrap_or(false));

        configure_backend_tcp_socket(&backend_stream);
        let proxy_protocol = context
            .backend_ext
            .as_ref()
            .map(|ext| ext.proxy_protocol)
            .unwrap_or_default();
        if proxy_protocol.enabled() {
            if let Err(err) =
                write_proxy_protocol_header(&mut backend_stream, client_addr, proxy_protocol).await
            {
                release_toa_port(toa_config, toa_local_port).await;
                self.record_backend_connect_failure(client_addr, &server, &context);
                return Err(err.into());
            }
        }
        crate::origin_state::ORIGIN_STATE_MANAGER.record_success(context.origin_id);
        drop(origin_connect_permit);
        let res =
            stream_tcp_bidirectional_with_metrics(context.sid, client_stream, backend_stream).await;
        release_toa_port(toa_config, toa_local_port).await;
        self.finish_tcp_connection(client_addr, &server, &context, &res);
        res.map(|_| ()).map_err(Into::into)
    }

    fn record_request_start(&self, client_addr: SocketAddr, context: &TcpForwardContext) {
        let client_ip = client_addr.ip().to_string();
        crate::metrics::record::request_start(
            context.sid,
            &client_ip,
            context.user_id,
            context.user_plan_id,
            context.plan_id,
            None,
            false,
        );
    }

    fn record_backend_connect_failure(
        &self,
        client_addr: SocketAddr,
        server: &ServerConfig,
        context: &TcpForwardContext,
    ) {
        error!(
            "TCP Proxy: Failed to connect to backend {}",
            context.backend_addr
        );
        let domain = server
            .get_plain_server_names()
            .first()
            .cloned()
            .unwrap_or_default();
        crate::metrics::record::record_network_dimensions(
            crate::metrics::METRIC_CATEGORY_TCP,
            context.sid,
            client_addr.ip(),
            &domain,
            "-",
            0,
            0,
            502,
        );
        crate::metrics::record::request_end(context.sid, 0, 0, false, false, false, None);
        crate::origin_state::ORIGIN_STATE_MANAGER.record_failure(context.origin_id);
    }

    fn finish_tcp_connection(
        &self,
        client_addr: SocketAddr,
        server: &ServerConfig,
        context: &TcpForwardContext,
        result: &Result<RelayOutcome, BidirectionalStreamError>,
    ) {
        let (bytes_received, bytes_sent) = match result {
            Ok(outcome) => {
                if outcome.close_reason != RelayCloseReason::Clean {
                    debug!(
                        "TCP Proxy: Bidirectional relay completed with {:?}",
                        outcome.close_reason
                    );
                }
                (outcome.bytes_received, outcome.bytes_sent)
            }
            Err(e) => {
                debug!(
                    "TCP Proxy: Bidirectional relay finished with hard error: {}",
                    e
                );
                (e.bytes_received, e.bytes_sent)
            }
        };
        let domain = server
            .get_plain_server_names()
            .first()
            .cloned()
            .unwrap_or_default();
        let status = if result.is_ok() { 200 } else { 502 };
        crate::metrics::record::record_network_dimensions(
            crate::metrics::METRIC_CATEGORY_TCP,
            context.sid,
            client_addr.ip(),
            &domain,
            "-",
            bytes_sent as i64,
            bytes_received as i64,
            status,
        );
        crate::metrics::record::request_end(context.sid, 0, 0, false, false, false, None);
    }

    fn record_tls_handshake_failure(&self, ip: std::net::IpAddr) {
        crate::special_defense::record_tls_handshake_failure(
            &self.config_store,
            &self.waf_state,
            self.node_id,
            ip,
        );
    }
}

fn configure_backend_tcp_socket(stream: &TcpStream) {
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

async fn release_toa_port(
    toa_config: Option<crate::config_models::TOAConfig>,
    local_port: Option<u16>,
) {
    if let Some(local_port) = local_port {
        if let Err(err) = crate::toa::unregister_toa_port(toa_config, local_port).await {
            debug!(
                "TCP Proxy: failed to release TOA sender port {}: {}",
                local_port, err
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayCloseReason {
    Clean,
    BenignIo,
    DrainTimeoutAfterBenign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelayOutcome {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub close_reason: RelayCloseReason,
    pub close_detail: Option<RelayIoDetail>,
    pub drain_duration_millis: Option<u64>,
}

impl RelayOutcome {
    fn from_counters(
        bytes_received_counter: &std::sync::atomic::AtomicU64,
        bytes_sent_counter: &std::sync::atomic::AtomicU64,
        close_reason: RelayCloseReason,
    ) -> Self {
        Self {
            bytes_received: bytes_received_counter.load(std::sync::atomic::Ordering::Relaxed),
            bytes_sent: bytes_sent_counter.load(std::sync::atomic::Ordering::Relaxed),
            close_reason,
            close_detail: None,
            drain_duration_millis: None,
        }
    }

    fn with_close_detail(mut self, close_detail: Option<RelayIoDetail>) -> Self {
        self.close_detail = close_detail;
        self
    }

    fn with_drain_duration(mut self, drain_duration: std::time::Duration) -> Self {
        self.drain_duration_millis = Some(drain_duration.as_millis().min(u64::MAX as u128) as u64);
        self
    }

    pub(crate) fn close_note(&self) -> Option<String> {
        let mut note = match self.close_reason {
            RelayCloseReason::Clean => return None,
            RelayCloseReason::BenignIo => String::from("benign relay close"),
            RelayCloseReason::DrainTimeoutAfterBenign => {
                String::from("relay drain timeout after benign close")
            }
        };
        if let Some(detail) = self.close_detail {
            note.push_str(&format!(
                " direction={:?} phase={:?}",
                detail.direction, detail.phase
            ));
            if let Some(raw_os_error) = detail.raw_os_error {
                note.push_str(&format!(" raw_os_error={}", raw_os_error));
            }
        }
        if let Some(drain_duration_millis) = self.drain_duration_millis {
            note.push_str(&format!(" drain_ms={}", drain_duration_millis));
        }
        Some(note)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamDirection {
    ClientToBackend,
    BackendToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayIoPhase {
    Read,
    Write,
    Shutdown,
}

#[derive(Debug, Clone, Copy, Default)]
struct RelayOptions {
    defer_backend_to_client_clean_shutdown: bool,
}

impl RelayOptions {
    fn sni_passthrough() -> Self {
        Self {
            defer_backend_to_client_clean_shutdown: true,
        }
    }

    fn should_defer_clean_shutdown(self, direction: StreamDirection) -> bool {
        self.defer_backend_to_client_clean_shutdown
            && matches!(direction, StreamDirection::BackendToClient)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RelayIoDetail {
    pub direction: StreamDirection,
    pub phase: RelayIoPhase,
    pub raw_os_error: Option<i32>,
}

impl RelayIoDetail {
    fn from_error(direction: StreamDirection, phase: RelayIoPhase, err: &io::Error) -> Self {
        Self {
            direction,
            phase,
            raw_os_error: err.raw_os_error(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct BidirectionalStreamError {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub direction: StreamDirection,
    pub phase: RelayIoPhase,
    pub raw_os_error: Option<i32>,
    source: std::io::Error,
}

impl std::fmt::Display for BidirectionalStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (direction={:?}, phase={:?}, raw_os_error={:?})",
            self.source, self.direction, self.phase, self.raw_os_error
        )
    }
}

impl std::error::Error for BidirectionalStreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl BidirectionalStreamError {
    fn from_direction_error(
        bytes_received_counter: &std::sync::atomic::AtomicU64,
        bytes_sent_counter: &std::sync::atomic::AtomicU64,
        error: DirectionTaskError,
    ) -> Self {
        let raw_os_error = error.source.raw_os_error();
        Self {
            bytes_received: bytes_received_counter.load(std::sync::atomic::Ordering::Relaxed),
            bytes_sent: bytes_sent_counter.load(std::sync::atomic::Ordering::Relaxed),
            direction: error.direction,
            phase: error.phase,
            raw_os_error,
            source: error.source,
        }
    }
}

const STREAM_METRICS_FLUSH_BYTES: u64 = 1024 * 1024;
const RELAY_BENIGN_RESPONSE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const RELAY_BENIGN_UPLOAD_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Debug, Clone, Copy)]
struct DirectionSuccess {
    close_reason: RelayCloseReason,
    close_detail: Option<RelayIoDetail>,
}

#[derive(Debug)]
struct DirectionTaskError {
    direction: StreamDirection,
    phase: RelayIoPhase,
    source: io::Error,
}

impl DirectionTaskError {
    fn new(direction: StreamDirection, phase: RelayIoPhase, source: io::Error) -> Self {
        Self {
            direction,
            phase,
            source,
        }
    }
}

type DirectionTaskResult = Result<DirectionSuccess, DirectionTaskError>;

pub(crate) async fn stream_tcp_bidirectional_with_metrics(
    server_id: i64,
    client: TcpStream,
    backend: TcpStream,
) -> Result<RelayOutcome, BidirectionalStreamError> {
    stream_tcp_bidirectional_with_metrics_options(
        server_id,
        client,
        backend,
        RelayOptions::default(),
    )
    .await
}

pub(crate) async fn stream_sni_passthrough_bidirectional_with_metrics(
    server_id: i64,
    client: TcpStream,
    backend: TcpStream,
) -> Result<RelayOutcome, BidirectionalStreamError> {
    stream_tcp_bidirectional_with_metrics_options(
        server_id,
        client,
        backend,
        RelayOptions::sni_passthrough(),
    )
    .await
}

async fn stream_tcp_bidirectional_with_metrics_options(
    server_id: i64,
    client: TcpStream,
    backend: TcpStream,
    options: RelayOptions,
) -> Result<RelayOutcome, BidirectionalStreamError> {
    #[cfg(target_os = "linux")]
    {
        match zero_copy::stream_bidirectional(server_id, &client, &backend, options).await {
            zero_copy::ZeroCopyOutcome::Completed(result) => return result,
            zero_copy::ZeroCopyOutcome::Fallback => {}
        }
    }

    stream_bidirectional_with_metrics_options(server_id, client, backend, options).await
}

pub(crate) async fn stream_bidirectional_with_metrics<C, B>(
    server_id: i64,
    client: C,
    backend: B,
) -> Result<RelayOutcome, BidirectionalStreamError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    stream_bidirectional_with_metrics_options(server_id, client, backend, RelayOptions::default())
        .await
}

async fn stream_bidirectional_with_metrics_options<C, B>(
    server_id: i64,
    client: C,
    backend: B,
    options: RelayOptions,
) -> Result<RelayOutcome, BidirectionalStreamError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (client_reader, client_writer) = tokio::io::split(client);
    let (backend_reader, backend_writer) = tokio::io::split(backend);
    let bytes_received_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let bytes_sent_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let client_to_backend = copy_stream_and_count(
        server_id,
        StreamDirection::ClientToBackend,
        client_reader,
        backend_writer,
        bytes_received_counter.clone(),
        options,
    );
    let backend_to_client = copy_stream_and_count(
        server_id,
        StreamDirection::BackendToClient,
        backend_reader,
        client_writer,
        bytes_sent_counter.clone(),
        options,
    );

    tokio::pin!(client_to_backend);
    tokio::pin!(backend_to_client);

    let (first_direction, first) = tokio::select! {
        result = &mut client_to_backend => (StreamDirection::ClientToBackend, result),
        result = &mut backend_to_client => (StreamDirection::BackendToClient, result),
    };

    match first {
        Ok(first_success) => match first_success.close_reason {
            RelayCloseReason::Clean => {
                let second = if first_direction == StreamDirection::ClientToBackend {
                    backend_to_client.await
                } else {
                    client_to_backend.await
                };
                finish_relay_after_second(
                    first_success,
                    second,
                    &bytes_received_counter,
                    &bytes_sent_counter,
                )
            }
            RelayCloseReason::BenignIo => {
                let drain_timeout = benign_drain_timeout_after(first_direction);
                let drain_started = std::time::Instant::now();
                let second = if first_direction == StreamDirection::ClientToBackend {
                    tokio::time::timeout(drain_timeout, &mut backend_to_client).await
                } else {
                    tokio::time::timeout(drain_timeout, &mut client_to_backend).await
                };
                match second {
                    Ok(second) => finish_relay_after_second(
                        first_success,
                        second,
                        &bytes_received_counter,
                        &bytes_sent_counter,
                    ),
                    Err(_) => Ok(RelayOutcome::from_counters(
                        &bytes_received_counter,
                        &bytes_sent_counter,
                        RelayCloseReason::DrainTimeoutAfterBenign,
                    )
                    .with_close_detail(first_success.close_detail)
                    .with_drain_duration(drain_started.elapsed())),
                }
            }
            RelayCloseReason::DrainTimeoutAfterBenign => unreachable!(),
        },
        Err(error) => Err(BidirectionalStreamError::from_direction_error(
            &bytes_received_counter,
            &bytes_sent_counter,
            error,
        )),
    }
}

async fn copy_stream_and_count<R, W>(
    server_id: i64,
    direction: StreamDirection,
    mut reader: R,
    mut writer: W,
    counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    options: RelayOptions,
) -> DirectionTaskResult
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    let mut unflushed = 0u64;

    loop {
        let n = match reader.read(&mut buf).await {
            Ok(n) => n,
            Err(err) => {
                record_stream_metrics_delta(server_id, direction, unflushed);
                return direction_error_or_benign(direction, RelayIoPhase::Read, err);
            }
        };
        if n == 0 {
            record_stream_metrics_delta(server_id, direction, unflushed);
            if !options.should_defer_clean_shutdown(direction) {
                if let Err(err) = writer.shutdown().await {
                    return direction_shutdown_error_or_clean(direction, err);
                }
            }
            return Ok(DirectionSuccess {
                close_reason: RelayCloseReason::Clean,
                close_detail: None,
            });
        }

        if let Err(err) = writer.write_all(&buf[..n]).await {
            record_stream_metrics_delta(server_id, direction, unflushed);
            return direction_error_or_benign(direction, RelayIoPhase::Write, err);
        }
        total += n as u64;
        unflushed += n as u64;
        counter.store(total, std::sync::atomic::Ordering::Relaxed);
        if unflushed >= STREAM_METRICS_FLUSH_BYTES {
            record_stream_metrics_delta(server_id, direction, unflushed);
            unflushed = 0;
        }
    }
}

fn finish_relay_after_second(
    first_success: DirectionSuccess,
    second: DirectionTaskResult,
    bytes_received_counter: &std::sync::atomic::AtomicU64,
    bytes_sent_counter: &std::sync::atomic::AtomicU64,
) -> Result<RelayOutcome, BidirectionalStreamError> {
    match second {
        Ok(second_success) => Ok(RelayOutcome::from_counters(
            bytes_received_counter,
            bytes_sent_counter,
            combine_relay_close_reasons(first_success.close_reason, second_success.close_reason),
        )
        .with_close_detail(first_success.close_detail.or(second_success.close_detail))),
        Err(error) => Err(BidirectionalStreamError::from_direction_error(
            bytes_received_counter,
            bytes_sent_counter,
            error,
        )),
    }
}

fn benign_drain_timeout_after(first_direction: StreamDirection) -> std::time::Duration {
    match first_direction {
        // Upload-side benign close can still be followed by a small upstream response.
        StreamDirection::ClientToBackend => RELAY_BENIGN_RESPONSE_DRAIN_TIMEOUT,
        // If the response path is already broken, do not keep the upload side alive for seconds.
        StreamDirection::BackendToClient => RELAY_BENIGN_UPLOAD_DRAIN_TIMEOUT,
    }
}

#[cfg(target_os = "linux")]
fn opposite_direction(direction: StreamDirection) -> StreamDirection {
    match direction {
        StreamDirection::ClientToBackend => StreamDirection::BackendToClient,
        StreamDirection::BackendToClient => StreamDirection::ClientToBackend,
    }
}

fn combine_relay_close_reasons(
    first: RelayCloseReason,
    second: RelayCloseReason,
) -> RelayCloseReason {
    if matches!(
        (first, second),
        (RelayCloseReason::DrainTimeoutAfterBenign, _)
            | (_, RelayCloseReason::DrainTimeoutAfterBenign)
    ) {
        RelayCloseReason::DrainTimeoutAfterBenign
    } else if matches!(
        (first, second),
        (RelayCloseReason::BenignIo, _) | (_, RelayCloseReason::BenignIo)
    ) {
        RelayCloseReason::BenignIo
    } else {
        RelayCloseReason::Clean
    }
}

fn direction_error_or_benign(
    direction: StreamDirection,
    phase: RelayIoPhase,
    err: io::Error,
) -> DirectionTaskResult {
    if is_benign_relay_io_error(&err) {
        let close_detail = RelayIoDetail::from_error(direction, phase, &err);
        Ok(DirectionSuccess {
            close_reason: RelayCloseReason::BenignIo,
            close_detail: Some(close_detail),
        })
    } else {
        Err(DirectionTaskError::new(direction, phase, err))
    }
}

fn direction_shutdown_error_or_clean(
    direction: StreamDirection,
    err: io::Error,
) -> DirectionTaskResult {
    if is_benign_relay_io_error(&err) {
        Ok(DirectionSuccess {
            close_reason: RelayCloseReason::Clean,
            close_detail: None,
        })
    } else {
        Err(DirectionTaskError::new(
            direction,
            RelayIoPhase::Shutdown,
            err,
        ))
    }
}

fn is_benign_relay_io_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    ) || is_benign_relay_raw_os_error(err)
}

#[cfg(unix)]
fn is_benign_relay_raw_os_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == libc::EPIPE
                || code == libc::ECONNRESET
                || code == libc::ENOTCONN
                || code == libc::ECONNABORTED
    )
}

#[cfg(not(unix))]
fn is_benign_relay_raw_os_error(_err: &io::Error) -> bool {
    false
}

fn record_stream_metrics_delta(server_id: i64, direction: StreamDirection, bytes: u64) {
    if bytes == 0 {
        return;
    }
    match direction {
        StreamDirection::ClientToBackend => {
            crate::metrics::record::record_transfer(server_id, 0, bytes, None);
            crate::metrics::record::record_origin_traffic(server_id, bytes, 0, None);
        }
        StreamDirection::BackendToClient => {
            crate::metrics::record::record_transfer(server_id, bytes, 0, None);
            crate::metrics::record::record_origin_traffic(server_id, 0, bytes, None);
        }
    }
}

#[cfg(target_os = "linux")]
mod zero_copy {
    use super::*;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const SPLICE_CHUNK_BYTES: usize = 256 * 1024;
    const PIPE_SIZE_BYTES: libc::c_int = 256 * 1024;
    const POLL_TIMEOUT_MS: libc::c_int = 1000;

    pub(super) enum ZeroCopyOutcome {
        Completed(Result<RelayOutcome, BidirectionalStreamError>),
        Fallback,
    }

    pub(super) async fn stream_bidirectional(
        server_id: i64,
        client: &TcpStream,
        backend: &TcpStream,
        options: RelayOptions,
    ) -> ZeroCopyOutcome {
        let client_fd = client.as_raw_fd();
        let backend_fd = backend.as_raw_fd();
        let client_to_backend = match DirectionFds::new(client_fd, backend_fd) {
            Ok(fds) => fds,
            Err(_) => return ZeroCopyOutcome::Fallback,
        };
        let backend_to_client = match DirectionFds::new(backend_fd, client_fd) {
            Ok(fds) => fds,
            Err(_) => return ZeroCopyOutcome::Fallback,
        };
        let shutdown_fds = match ShutdownFds::new(client_fd, backend_fd) {
            Ok(fds) => Arc::new(fds),
            Err(_) => return ZeroCopyOutcome::Fallback,
        };

        let bytes_received_counter = Arc::new(AtomicU64::new(0));
        let bytes_sent_counter = Arc::new(AtomicU64::new(0));
        let control = Arc::new(RelayControl::default());

        let mut c2b = spawn_direction(
            server_id,
            StreamDirection::ClientToBackend,
            client_to_backend,
            bytes_received_counter.clone(),
            control.clone(),
            options,
        );
        let mut b2c = spawn_direction(
            server_id,
            StreamDirection::BackendToClient,
            backend_to_client,
            bytes_sent_counter.clone(),
            control.clone(),
            options,
        );

        let (first_direction, first) = tokio::select! {
            result = &mut c2b => (
                StreamDirection::ClientToBackend,
                flatten_join_result(StreamDirection::ClientToBackend, result),
            ),
            result = &mut b2c => (
                StreamDirection::BackendToClient,
                flatten_join_result(StreamDirection::BackendToClient, result),
            ),
        };

        let result = if first_direction == StreamDirection::ClientToBackend {
            finish_zero_copy_after_first(
                first,
                StreamDirection::BackendToClient,
                b2c,
                &control,
                &shutdown_fds,
                &bytes_received_counter,
                &bytes_sent_counter,
            )
            .await
        } else {
            finish_zero_copy_after_first(
                first,
                StreamDirection::ClientToBackend,
                c2b,
                &control,
                &shutdown_fds,
                &bytes_received_counter,
                &bytes_sent_counter,
            )
            .await
        };
        ZeroCopyOutcome::Completed(result)
    }

    fn spawn_direction(
        server_id: i64,
        direction: StreamDirection,
        fds: DirectionFds,
        counter: Arc<AtomicU64>,
        control: Arc<RelayControl>,
        options: RelayOptions,
    ) -> tokio::task::JoinHandle<DirectionTaskResult> {
        tokio::task::spawn_blocking(move || {
            splice_direction_and_count(server_id, direction, fds, counter, &control, options)
        })
    }

    fn flatten_join_result(
        direction: StreamDirection,
        result: Result<DirectionTaskResult, tokio::task::JoinError>,
    ) -> DirectionTaskResult {
        result.unwrap_or_else(|err| {
            Err(DirectionTaskError::new(
                direction,
                RelayIoPhase::Read,
                io::Error::new(io::ErrorKind::Other, err.to_string()),
            ))
        })
    }

    async fn finish_zero_copy_after_first(
        first: DirectionTaskResult,
        remaining_direction: StreamDirection,
        mut remaining: tokio::task::JoinHandle<DirectionTaskResult>,
        control: &RelayControl,
        shutdown_fds: &ShutdownFds,
        bytes_received_counter: &AtomicU64,
        bytes_sent_counter: &AtomicU64,
    ) -> Result<RelayOutcome, BidirectionalStreamError> {
        match first {
            Ok(first_success) => match first_success.close_reason {
                RelayCloseReason::Clean => {
                    let second = flatten_join_result(remaining_direction, remaining.await);
                    finish_relay_after_second(
                        first_success,
                        second,
                        bytes_received_counter,
                        bytes_sent_counter,
                    )
                }
                RelayCloseReason::BenignIo => {
                    let drain_timeout = benign_drain_timeout_after(
                        first_success
                            .close_detail
                            .map(|detail| detail.direction)
                            .unwrap_or_else(|| opposite_direction(remaining_direction)),
                    );
                    let drain_started = std::time::Instant::now();
                    match tokio::time::timeout(drain_timeout, &mut remaining).await {
                        Ok(second) => finish_relay_after_second(
                            first_success,
                            flatten_join_result(remaining_direction, second),
                            bytes_received_counter,
                            bytes_sent_counter,
                        ),
                        Err(_) => {
                            control.stop();
                            shutdown_fds.shutdown_all();
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_millis(POLL_TIMEOUT_MS as u64 + 500),
                                remaining,
                            )
                            .await;
                            Ok(RelayOutcome::from_counters(
                                bytes_received_counter,
                                bytes_sent_counter,
                                RelayCloseReason::DrainTimeoutAfterBenign,
                            )
                            .with_close_detail(first_success.close_detail)
                            .with_drain_duration(drain_started.elapsed()))
                        }
                    }
                }
                RelayCloseReason::DrainTimeoutAfterBenign => unreachable!(),
            },
            Err(error) => {
                control.stop();
                shutdown_fds.shutdown_all();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(POLL_TIMEOUT_MS as u64 + 500),
                    remaining,
                )
                .await;
                Err(BidirectionalStreamError::from_direction_error(
                    bytes_received_counter,
                    bytes_sent_counter,
                    error,
                ))
            }
        }
    }

    fn splice_direction_and_count(
        server_id: i64,
        direction: StreamDirection,
        fds: DirectionFds,
        counter: Arc<AtomicU64>,
        control: &RelayControl,
        options: RelayOptions,
    ) -> DirectionTaskResult {
        let mut total = 0u64;
        let mut unflushed = 0u64;

        loop {
            if control.should_stop() {
                record_stream_metrics_delta(server_id, direction, unflushed);
                return Ok(DirectionSuccess {
                    close_reason: RelayCloseReason::BenignIo,
                    close_detail: None,
                });
            }

            let moved_to_pipe =
                match splice_socket_to_pipe(fds.read.fd(), fds.pipe_write.fd(), control) {
                    Ok(n) => n,
                    Err(err) => {
                        record_stream_metrics_delta(server_id, direction, unflushed);
                        return direction_error_or_benign(direction, RelayIoPhase::Read, err);
                    }
                };
            if moved_to_pipe == 0 {
                record_stream_metrics_delta(server_id, direction, unflushed);
                if !options.should_defer_clean_shutdown(direction) {
                    if let Err(err) = shutdown_write(fds.write.fd()) {
                        return direction_error_or_benign(direction, RelayIoPhase::Shutdown, err);
                    }
                }
                return Ok(DirectionSuccess {
                    close_reason: RelayCloseReason::Clean,
                    close_detail: None,
                });
            }

            let mut remaining = moved_to_pipe;
            while remaining > 0 {
                let written = match splice_pipe_to_socket(
                    fds.pipe_read.fd(),
                    fds.write.fd(),
                    remaining,
                    control,
                ) {
                    Ok(n) => n,
                    Err(err) => {
                        record_stream_metrics_delta(server_id, direction, unflushed);
                        return direction_error_or_benign(direction, RelayIoPhase::Write, err);
                    }
                };
                if written == 0 {
                    record_stream_metrics_delta(server_id, direction, unflushed);
                    return Err(DirectionTaskError::new(
                        direction,
                        RelayIoPhase::Write,
                        io::Error::new(
                            io::ErrorKind::WriteZero,
                            "zero-copy splice wrote zero bytes",
                        ),
                    ));
                }
                remaining -= written;
                total += written as u64;
                unflushed += written as u64;
                counter.store(total, Ordering::Relaxed);
                if unflushed >= STREAM_METRICS_FLUSH_BYTES {
                    record_stream_metrics_delta(server_id, direction, unflushed);
                    unflushed = 0;
                }
            }
        }
    }

    fn splice_socket_to_pipe(
        read_fd: RawFd,
        pipe_write_fd: RawFd,
        control: &RelayControl,
    ) -> io::Result<usize> {
        loop {
            match splice_once(read_fd, pipe_write_fd, SPLICE_CHUNK_BYTES) {
                Err(err) if is_would_block(&err) => poll_fd(read_fd, libc::POLLIN, control)?,
                other => return other,
            }
        }
    }

    fn splice_pipe_to_socket(
        pipe_read_fd: RawFd,
        write_fd: RawFd,
        len: usize,
        control: &RelayControl,
    ) -> io::Result<usize> {
        loop {
            match splice_once(pipe_read_fd, write_fd, len) {
                Err(err) if is_would_block(&err) => poll_fd(write_fd, libc::POLLOUT, control)?,
                other => return other,
            }
        }
    }

    fn splice_once(read_fd: RawFd, write_fd: RawFd, len: usize) -> io::Result<usize> {
        loop {
            let n = unsafe {
                libc::splice(
                    read_fd,
                    ptr::null_mut(),
                    write_fd,
                    ptr::null_mut(),
                    len,
                    (libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK) as libc::c_uint,
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
    }

    fn poll_fd(fd: RawFd, events: libc::c_short, control: &RelayControl) -> io::Result<()> {
        loop {
            if control.should_stop() {
                return Err(stop_error());
            }
            let mut poll_fd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut poll_fd, 1, POLL_TIMEOUT_MS) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 {
                continue;
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
    }

    fn is_would_block(err: &io::Error) -> bool {
        matches!(err.raw_os_error(), Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK)
    }

    fn stop_error() -> io::Error {
        io::Error::new(io::ErrorKind::Interrupted, "zero-copy relay stopped")
    }

    fn shutdown_write(fd: RawFd) -> io::Result<()> {
        if unsafe { libc::shutdown(fd, libc::SHUT_WR) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if is_benign_relay_io_error(&err) {
            Ok(())
        } else {
            Err(err)
        }
    }

    #[derive(Default)]
    struct RelayControl {
        stop: AtomicBool,
    }

    impl RelayControl {
        fn stop(&self) {
            self.stop.store(true, Ordering::Relaxed);
        }

        fn should_stop(&self) -> bool {
            self.stop.load(Ordering::Relaxed)
        }
    }

    struct DirectionFds {
        read: OwnedFd,
        write: OwnedFd,
        pipe_read: OwnedFd,
        pipe_write: OwnedFd,
    }

    impl DirectionFds {
        fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Self> {
            let read = dup_fd(read_fd)?;
            let write = dup_fd(write_fd)?;
            let (pipe_read, pipe_write) = create_pipe()?;
            let _ = unsafe { libc::fcntl(pipe_read.fd(), libc::F_SETPIPE_SZ, PIPE_SIZE_BYTES) };
            Ok(Self {
                read,
                write,
                pipe_read,
                pipe_write,
            })
        }
    }

    struct ShutdownFds {
        client: OwnedFd,
        backend: OwnedFd,
    }

    impl ShutdownFds {
        fn new(client_fd: RawFd, backend_fd: RawFd) -> io::Result<Self> {
            Ok(Self {
                client: dup_fd(client_fd)?,
                backend: dup_fd(backend_fd)?,
            })
        }

        fn shutdown_all(&self) {
            unsafe {
                libc::shutdown(self.client.fd(), libc::SHUT_RDWR);
                libc::shutdown(self.backend.fd(), libc::SHUT_RDWR);
            }
        }
    }

    struct OwnedFd(RawFd);

    impl OwnedFd {
        fn fd(&self) -> RawFd {
            self.0
        }
    }

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    fn dup_fd(fd: RawFd) -> io::Result<OwnedFd> {
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(OwnedFd(duplicated))
        }
    }

    fn create_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0; 2];
        let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((OwnedFd(fds[0]), OwnedFd(fds[1])))
        }
    }
}

fn resize_client_cert_cache_for_servers(servers: &[Arc<ServerConfig>]) {
    let mut cert_keys = HashSet::new();
    for server in servers {
        let Some(reverse_proxy) = &server.reverse_proxy else {
            continue;
        };

        for origin in reverse_proxy
            .primary_origins
            .iter()
            .chain(reverse_proxy.backup_origins.iter())
        {
            if let Some(key) = origin.cert.as_ref().and_then(client_cert_key_for_cache) {
                cert_keys.insert(key);
            }
        }
    }

    let capacity = NonZeroUsize::new(cert_keys.len().max(1)).expect("non-zero cache capacity");
    let mut cache = CLIENT_CERT_CACHE
        .lock()
        .expect("client cert cache mutex poisoned");
    if cache.cap() != capacity {
        cache.resize(capacity);
    }
}

fn client_cert_key_for_cache(client_cert: &SSLCertConfig) -> Option<String> {
    let cert_pem_raw = client_cert.cert_data_json.as_ref()?.as_str()?;
    let key_pem_raw = client_cert.key_data_json.as_ref()?.as_str()?;
    let cert_bytes = clean_pem_value(cert_pem_raw);
    let key_bytes = clean_pem_value(key_pem_raw);
    Some(client_cert_cache_key(&cert_bytes, &key_bytes))
}

fn build_upstream_tls_connector(
    verify_origin_tls: bool,
    client_cert: Option<&SSLCertConfig>,
) -> anyhow::Result<pingora_core::tls::TlsConnector> {
    let provider = rustls::crypto::ring::default_provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?;

    let mut roots = RootCertStore::empty();
    if verify_origin_tls {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            roots.add(cert)?;
        }
        if !native.errors.is_empty() {
            warn!(
                "TCP Proxy: ignored {} errors while loading native TLS roots",
                native.errors.len()
            );
        }
    }

    let builder = builder.with_root_certificates(roots);
    let mut config = if let Some(client_cert) = client_cert {
        let parsed = parsed_client_cert(client_cert)?;
        builder.with_client_auth_cert(
            parsed.cert_chain.as_ref().clone(),
            parsed.key.as_ref().clone_key(),
        )?
    } else {
        builder.with_no_client_auth()
    };

    if !verify_origin_tls {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification::new(provider)));
    }

    Ok(pingora_core::tls::TlsConnector::from(Arc::new(config)))
}

fn parsed_client_cert(client_cert: &SSLCertConfig) -> anyhow::Result<ParsedClientCert> {
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
    let cache_key = client_cert_cache_key(&cert_bytes, &key_bytes);
    if let Some(parsed) = CLIENT_CERT_CACHE
        .lock()
        .expect("client cert cache mutex poisoned")
        .get(&cache_key)
        .cloned()
    {
        return Ok(parsed);
    }

    let cert_chain = crate::ssl::parse_cert_chain(&cert_bytes)?;
    if cert_chain.is_empty() {
        return Err(anyhow::anyhow!("client certificate chain is empty"));
    }
    let key = crate::ssl::parse_private_key(&key_bytes)?;
    let parsed = ParsedClientCert {
        cert_chain: Arc::new(cert_chain),
        key: Arc::new(key),
    };
    CLIENT_CERT_CACHE
        .lock()
        .expect("client cert cache mutex poisoned")
        .put(cache_key, parsed.clone());
    Ok(parsed)
}

fn client_cert_cache_key(cert_bytes: &[u8], key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_bytes);
    hasher.update([0]);
    hasher.update(key_bytes);
    hex::encode(hasher.finalize())
}

fn clean_pem_value(raw: &str) -> Vec<u8> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw.trim()) {
        return decoded;
    }
    raw.replace("\\n", "\n").into_bytes()
}

#[derive(Debug)]
struct NoCertificateVerification {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl NoCertificateVerification {
    fn new(provider: rustls::crypto::CryptoProvider) -> Self {
        Self {
            supported: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

async fn write_proxy_protocol_header(
    backend_stream: &mut TcpStream,
    client_addr: SocketAddr,
    config: ProxyProtocolConfig,
) -> io::Result<()> {
    let destination_addr = backend_stream.peer_addr().ok();
    if let Some(header) = proxy_protocol::build_header(config, client_addr, destination_addr) {
        backend_stream.write_all(&header).await?;
        backend_stream.flush().await?;
    }
    Ok(())
}

/// If `enable_proxy_protocol` is true, peek the first bytes of `stream` and
/// attempt to parse a PROXY Protocol v1/v2 header.  When a valid header is
/// found the header bytes are consumed from the stream and the reported source
/// address is returned. No header is still accepted for compatibility, but
/// malformed or incomplete PROXY headers are rejected.
async fn maybe_consume_proxy_protocol_header(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    enable_proxy_protocol: bool,
) -> Option<(SocketAddr, TcpStream)> {
    if !enable_proxy_protocol {
        return Some((client_addr, stream));
    }

    let mut peek_buf = [0u8; 128];
    let peek_n = match tokio::time::timeout(
        std::time::Duration::from_millis(200),
        stream.peek(&mut peek_buf),
    )
    .await
    {
        Ok(Ok(n)) => n,
        _ => return Some((client_addr, stream)),
    };

    if peek_n == 0 {
        return Some((client_addr, stream));
    }

    match proxy_protocol::parse_proxy_v1_v2(&peek_buf[..peek_n]) {
        Ok(addr) => {
            let mut discard = vec![0u8; addr.consumed];
            match stream.read_exact(&mut discard).await {
                Ok(_) => {
                    let effective_addr = match (addr.src_ip, addr.src_port) {
                        (Some(ip), Some(port)) => SocketAddr::new(ip, port),
                        _ => client_addr,
                    };
                    debug!(
                        "TCP PROXY protocol: replaced {} with {}",
                        client_addr, effective_addr
                    );
                    Some((effective_addr, stream))
                }
                Err(e) => {
                    debug!("TCP PROXY protocol: failed to drain header bytes: {}", e);
                    None
                }
            }
        }
        Err(proxy_protocol::ProxyProtocolError::NotProxyProtocol) => Some((client_addr, stream)),
        Err(err) => {
            debug!(
                "TCP PROXY protocol: dropping invalid header from {}: {}",
                client_addr, err
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{HTTPFirewallPolicy, TLSExhaustionAttackConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn configure_tls_exhaustion(store: &ConfigStore) {
        let server = Arc::new(ServerConfig {
            id: Some(91_004),
            cluster_id: 1,
            http_firewall_policy_id: 1,
            ..Default::default()
        });
        store
            .update_config(
                1,
                1,
                1,
                1,
                vec![server],
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                vec![],
                vec![],
                vec![],
                vec![],
                None,
                0,
                1,
                true,
                false,
                std::collections::HashMap::new(),
                false,
                false,
                String::new(),
                std::collections::HashMap::new(),
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
                vec![],
                vec![HTTPFirewallPolicy {
                    id: 1,
                    is_on: true,
                    name: "tls-policy".to_string(),
                    inbound: None,
                    outbound: None,
                    empty_connection_flood: None,
                    tls_exhaustion_attack: Some(TLSExhaustionAttackConfig {
                        is_on: true,
                        max_handshake_fails: 1,
                        period: 60,
                        block_seconds: 60,
                    }),
                    cc_config: None,
                    block_options: None,
                    page_options: None,
                    captcha_options: None,
                    js_cookie_options: None,
                    max_request_body_size: 0,
                    deny_country_html: String::new(),
                    deny_province_html: String::new(),
                    use_local_firewall: false,
                    syn_flood: None,
                    mode: String::new(),
                    candidate_rules: None,
                    candidate_traffic_pct: 0,
                    candidate_version: 0,
                }],
                vec![],
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
                None,
                None,
            )
            .await;
    }

    async fn connected_proxy_streams() -> (TcpStream, TcpStream, TcpStream, TcpStream) {
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        let client_peer =
            tokio::spawn(async move { TcpStream::connect(client_addr).await.unwrap() });
        let backend_peer =
            tokio::spawn(async move { TcpStream::connect(backend_addr).await.unwrap() });
        let (proxy_client, _) = client_listener.accept().await.unwrap();
        let (proxy_backend, _) = backend_listener.accept().await.unwrap();

        (
            proxy_client,
            proxy_backend,
            client_peer.await.unwrap(),
            backend_peer.await.unwrap(),
        )
    }

    #[cfg(unix)]
    fn set_linger_zero(stream: &TcpStream) {
        use std::os::fd::AsRawFd;

        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let result = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const _ as *const libc::c_void,
                std::mem::size_of_val(&linger) as libc::socklen_t,
            )
        };
        assert_eq!(result, 0);
    }

    #[test]
    fn benign_relay_close_records_direction_phase_and_note() {
        let success = direction_error_or_benign(
            StreamDirection::ClientToBackend,
            RelayIoPhase::Write,
            io::Error::new(io::ErrorKind::BrokenPipe, "backend closed upload side"),
        )
        .unwrap();

        assert_eq!(success.close_reason, RelayCloseReason::BenignIo);
        let detail = success.close_detail.unwrap();
        assert_eq!(detail.direction, StreamDirection::ClientToBackend);
        assert_eq!(detail.phase, RelayIoPhase::Write);

        let outcome = RelayOutcome {
            bytes_received: 1024,
            bytes_sent: 64,
            close_reason: RelayCloseReason::BenignIo,
            close_detail: success.close_detail,
            drain_duration_millis: Some(12),
        };
        let note = outcome.close_note().unwrap();
        assert!(note.contains("benign relay close"));
        assert!(note.contains("direction=ClientToBackend"));
        assert!(note.contains("phase=Write"));
        assert!(note.contains("drain_ms=12"));
    }

    #[test]
    fn response_path_benign_uses_short_upload_drain_window() {
        assert_eq!(
            benign_drain_timeout_after(StreamDirection::ClientToBackend),
            RELAY_BENIGN_RESPONSE_DRAIN_TIMEOUT
        );
        assert_eq!(
            benign_drain_timeout_after(StreamDirection::BackendToClient),
            RELAY_BENIGN_UPLOAD_DRAIN_TIMEOUT
        );
        assert!(
            RELAY_BENIGN_UPLOAD_DRAIN_TIMEOUT < RELAY_BENIGN_RESPONSE_DRAIN_TIMEOUT,
            "response-path benign close should not keep upload alive for the full response drain"
        );
        assert!(
            RELAY_BENIGN_UPLOAD_DRAIN_TIMEOUT >= std::time::Duration::from_secs(2),
            "response-path benign close needs enough room for cross-region AnyTLS upload RTT"
        );
    }

    #[test]
    fn benign_shutdown_after_eof_is_clean() {
        let success = direction_shutdown_error_or_clean(
            StreamDirection::BackendToClient,
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "client already closed after response eof",
            ),
        )
        .unwrap();
        assert_eq!(success.close_reason, RelayCloseReason::Clean);
        assert_eq!(success.close_detail, None);
    }

    #[tokio::test]
    async fn tcp_tls_handshake_failure_uses_global_tls_exhaustion_defense() {
        let store = ConfigStore::new();
        configure_tls_exhaustion(&store).await;
        let waf_state = Arc::new(WafStateManager::new());
        let manager = TcpProxyManager::new(
            store,
            Arc::new(DynamicCertSelector::new()),
            waf_state.clone(),
            7,
        );
        let ip = "127.0.0.77".parse().unwrap();
        let cluster_scope = crate::special_defense::cluster_block_scope_id(1);

        manager.record_tls_handshake_failure(ip);
        assert!(!waf_state.is_blocked(ip, cluster_scope));
        manager.record_tls_handshake_failure(ip);
        assert!(waf_state.is_blocked(ip, cluster_scope));
        assert!(!waf_state.is_blocked(ip, 0));
    }

    #[tokio::test]
    async fn tcp_tls_rejects_globally_blocked_ip_before_handshake() {
        let store = ConfigStore::new();
        configure_tls_exhaustion(&store).await;
        let waf_state = Arc::new(WafStateManager::new());
        let manager = TcpProxyManager::new(
            store,
            Arc::new(DynamicCertSelector::new()),
            waf_state.clone(),
            7,
        );
        let server = Arc::new(ServerConfig {
            id: Some(91_003),
            description: String::new(),
            user_id: 0,
            cluster_id: 1,
            is_on: true,
            server_names: vec![],
            http: None,
            https: None,
            tcp: None,
            udp: None,
            web: None,
            reverse_proxy: None,
            grpc: None,
            uam: None,
            traffic_limit: None,
            traffic_limit_status: None,
            http_firewall_policy_id: 0,
            http_firewall_policy: None,
            user_plan_id: 0,
            enable_proxy_protocol: false,
            locations: vec![],
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (proxy_client, client_addr) = listener.accept().await.unwrap();
        manager.record_tls_handshake_failure(client_addr.ip());
        manager.record_tls_handshake_failure(client_addr.ip());
        assert!(waf_state.is_blocked(
            client_addr.ip(),
            crate::special_defense::cluster_block_scope_id(1)
        ));

        manager
            .handle_connection(proxy_client, client_addr, server, true, None)
            .await
            .unwrap();
        drop(client.await.unwrap());
    }

    #[tokio::test]
    async fn raw_tcp_relay_preserves_half_close() {
        let (proxy_client, proxy_backend, mut client, mut backend) =
            connected_proxy_streams().await;
        let relay = tokio::spawn(async move {
            stream_tcp_bidirectional_with_metrics(91_001, proxy_client, proxy_backend)
                .await
                .unwrap()
        });

        let backend_task = tokio::spawn(async move {
            let mut request = Vec::new();
            backend.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request-body");
            backend.write_all(b"backend-response").await.unwrap();
            backend.shutdown().await.unwrap();
        });

        client.write_all(b"request-body").await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"backend-response");

        backend_task.await.unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.close_reason, RelayCloseReason::Clean);
        assert_eq!(outcome.bytes_received, b"request-body".len() as u64);
        assert_eq!(outcome.bytes_sent, b"backend-response".len() as u64);
    }

    #[tokio::test]
    async fn raw_tcp_relay_counts_large_payload() {
        let (proxy_client, proxy_backend, mut client, mut backend) =
            connected_proxy_streams().await;
        let relay = tokio::spawn(async move {
            stream_tcp_bidirectional_with_metrics(91_002, proxy_client, proxy_backend)
                .await
                .unwrap()
        });
        let request = vec![3u8; STREAM_METRICS_FLUSH_BYTES as usize + 8192];
        let response = vec![9u8; STREAM_METRICS_FLUSH_BYTES as usize + 4096];
        let expected_request_len = request.len() as u64;
        let expected_response_len = response.len() as u64;

        let backend_task = tokio::spawn(async move {
            let mut received = Vec::new();
            backend.read_to_end(&mut received).await.unwrap();
            assert_eq!(received.len() as u64, expected_request_len);
            assert!(received.iter().all(|byte| *byte == 3));
            backend.write_all(&response).await.unwrap();
            backend.shutdown().await.unwrap();
        });

        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut received_response = Vec::new();
        client.read_to_end(&mut received_response).await.unwrap();
        assert_eq!(received_response.len() as u64, expected_response_len);
        assert!(received_response.iter().all(|byte| *byte == 9));

        backend_task.await.unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.close_reason, RelayCloseReason::Clean);
        assert_eq!(outcome.bytes_received, expected_request_len);
        assert_eq!(outcome.bytes_sent, expected_response_len);
    }

    #[tokio::test]
    async fn fallback_relay_delivers_backend_response_after_upload_side_closes() {
        let (proxy_client, proxy_backend, client, mut backend) = connected_proxy_streams().await;
        let relay = tokio::spawn(async move {
            stream_bidirectional_with_metrics(91_005, proxy_client, proxy_backend)
                .await
                .unwrap()
        });
        let response = b"early-backend-response";
        let backend_task = tokio::spawn(async move {
            let mut first_chunk = [0u8; 4096];
            let n = backend.read(&mut first_chunk).await.unwrap();
            assert!(n > 0);
            backend.write_all(response).await.unwrap();
            backend.shutdown().await.unwrap();
        });

        let (mut client_reader, mut client_writer) = client.into_split();
        let writer_task = tokio::spawn(async move {
            let chunk = vec![7u8; 64 * 1024];
            loop {
                if client_writer.write_all(&chunk).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        });

        let mut received_response = vec![0u8; response.len()];
        client_reader
            .read_exact(&mut received_response)
            .await
            .unwrap();
        assert_eq!(received_response, response);
        writer_task.abort();
        drop(client_reader);

        backend_task.await.unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(7), relay)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(
                outcome.close_reason,
                RelayCloseReason::BenignIo | RelayCloseReason::DrainTimeoutAfterBenign
            ),
            "unexpected close reason: {:?}",
            outcome.close_reason
        );
        assert!(outcome.bytes_received > 0);
        assert_eq!(outcome.bytes_sent, response.len() as u64);
    }

    #[tokio::test]
    async fn sni_passthrough_defers_backend_eof_until_upload_finishes() {
        let (proxy_client, proxy_backend, client, mut backend) = connected_proxy_streams().await;
        let relay = tokio::spawn(async move {
            stream_bidirectional_with_metrics_options(
                91_007,
                proxy_client,
                proxy_backend,
                RelayOptions::sni_passthrough(),
            )
            .await
            .unwrap()
        });
        let response = b"early-control-response";
        let upload_len = 128 * 1024;
        let backend_task = tokio::spawn(async move {
            backend.write_all(response).await.unwrap();
            backend.shutdown().await.unwrap();
            let mut upload = vec![0u8; upload_len];
            backend.read_exact(&mut upload).await.unwrap();
            assert!(upload.iter().all(|byte| *byte == 5));
        });

        let (mut client_reader, mut client_writer) = client.into_split();
        let mut received_response = vec![0u8; response.len()];
        client_reader
            .read_exact(&mut received_response)
            .await
            .unwrap();
        assert_eq!(received_response, response);

        let mut eof_probe = [0u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                client_reader.read(&mut eof_probe)
            )
            .await
            .is_err(),
            "SNI passthrough should not forward backend EOF while upload is still active"
        );

        let upload = vec![5u8; upload_len];
        client_writer.write_all(&upload).await.unwrap();
        client_writer.shutdown().await.unwrap();
        drop(client_writer);

        let mut tail = Vec::new();
        client_reader.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());

        backend_task.await.unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.close_reason, RelayCloseReason::Clean);
        assert_eq!(outcome.bytes_received, upload_len as u64);
        assert_eq!(outcome.bytes_sent, response.len() as u64);
    }

    #[tokio::test]
    async fn raw_tcp_relay_treats_client_abort_as_non_hard_close() {
        let (proxy_client, proxy_backend, mut client, mut backend) =
            connected_proxy_streams().await;
        let relay = tokio::spawn(async move {
            stream_tcp_bidirectional_with_metrics(91_006, proxy_client, proxy_backend)
                .await
                .unwrap()
        });

        client.write_all(b"partial-upload").await.unwrap();
        #[cfg(unix)]
        set_linger_zero(&client);
        drop(client);

        let mut received = [0u8; 64];
        let n = backend.read(&mut received).await.unwrap();
        assert!(n > 0);
        drop(backend);

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(7), relay)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(
                outcome.close_reason,
                RelayCloseReason::Clean
                    | RelayCloseReason::BenignIo
                    | RelayCloseReason::DrainTimeoutAfterBenign
            ),
            "unexpected close reason: {:?}",
            outcome.close_reason
        );
        assert!(outcome.bytes_received > 0);
    }
}
