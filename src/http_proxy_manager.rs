use crate::config::ConfigStore;
use crate::config_models::{ProxyProtocolConfig, ServerConfig};
use crate::l4_connection_registry::{self, L4ConnectionProtocol};
use crate::l4_defense::L4DefenseKind;
use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR};
use crate::net_bind::{
    bind_tcp_listener_with_retry, dual_stack_bind_addrs, is_transient_accept_error,
};
use crate::proxy::EdgeProxy;
use crate::proxy_protocol;
use crate::ssl::DynamicCertSelector;
use anyhow::Context;
use dashmap::DashMap;
use pingora_core::apps::HttpServerApp;
use pingora_core::listeners::tls::Acceptor as PingoraTlsAcceptor;
use pingora_core::protocols::http::server::Session as ServerSession;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::tls::server::handshake;
use pingora_core::protocols::{ALPN, GetSocketDigest, SocketDigest, Ssl};
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::http_proxy;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::{Context as TaskContext, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{Duration, Instant as TokioInstant};
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

struct ListenerHandle {
    is_tls: bool,
    enable_proxy_protocol: bool,
    shutdown_tx: watch::Sender<bool>,
}

const H2_CHURN_WINDOW: Duration = Duration::from_secs(30);
const H2_CHURN_STREAM_LIMIT: u64 = 200;
const H2_CHURN_HINT_STREAM_LIMIT: u64 = 100;
const H2_L4_EVENT_FLUSH_STREAMS: u64 = 10;

struct H2ConnectionDefenseState {
    _ip: IpAddr,
    _port: u16,
    started_at: TokioInstant,
    window_started_at: TokioInstant,
    last_activity_at: TokioInstant,
    pressure_level: crate::l4_defense::L4PressureLevel,
    accepted_streams: u64,
    rejected_streams: u64,
    errors: u64,
    pending_l4_stream_events: u64,
    churn_hint_reported: bool,
}

impl H2ConnectionDefenseState {
    fn new(ip: IpAddr, port: u16, pressure_level: crate::l4_defense::L4PressureLevel) -> Self {
        let now = TokioInstant::now();
        Self {
            _ip: ip,
            _port: port,
            started_at: now,
            window_started_at: now,
            last_activity_at: now,
            pressure_level,
            accepted_streams: 0,
            rejected_streams: 0,
            errors: 0,
            pending_l4_stream_events: 0,
            churn_hint_reported: false,
        }
    }

    fn record_stream(&mut self) {
        self.refresh_window();
        self.accepted_streams = self.accepted_streams.saturating_add(1);
        self.pending_l4_stream_events = self.pending_l4_stream_events.saturating_add(1);
        self.last_activity_at = TokioInstant::now();
    }

    fn record_reject(&mut self) {
        self.rejected_streams = self.rejected_streams.saturating_add(1);
        self.last_activity_at = TokioInstant::now();
    }

    fn record_error(&mut self) {
        self.errors = self.errors.saturating_add(1);
        self.last_activity_at = TokioInstant::now();
    }

    fn next_idle_deadline(&self) -> TokioInstant {
        self.last_activity_at + self.idle_timeout()
    }

    fn lifetime_deadline(&self) -> TokioInstant {
        self.started_at + self.max_lifetime()
    }

    fn should_close_for_churn(&mut self) -> bool {
        self.refresh_window();
        self.accepted_streams >= H2_CHURN_STREAM_LIMIT
            && self.window_started_at.elapsed() <= H2_CHURN_WINDOW
    }

    fn should_report_churn_hint(&mut self) -> bool {
        self.refresh_window();
        if !self.churn_hint_reported
            && self.accepted_streams >= H2_CHURN_HINT_STREAM_LIMIT
            && self.window_started_at.elapsed() <= H2_CHURN_WINDOW
        {
            self.churn_hint_reported = true;
            return true;
        }
        false
    }

    fn refresh_window(&mut self) {
        if self.window_started_at.elapsed() > H2_CHURN_WINDOW {
            self.window_started_at = TokioInstant::now();
            self.accepted_streams = 0;
            self.rejected_streams = 0;
            self.errors = 0;
            self.pending_l4_stream_events = 0;
            self.churn_hint_reported = false;
        }
    }

    fn take_pending_l4_stream_events_if_due(&mut self) -> Option<u64> {
        if self.pending_l4_stream_events >= H2_L4_EVENT_FLUSH_STREAMS {
            Some(self.take_pending_l4_stream_events())
        } else {
            None
        }
    }

    fn take_pending_l4_stream_events(&mut self) -> u64 {
        let events = self.pending_l4_stream_events;
        self.pending_l4_stream_events = 0;
        events
    }

    fn idle_timeout(&self) -> Duration {
        match self
            .pressure_level
            .max(crate::l4_defense::current_pressure_level())
        {
            crate::l4_defense::L4PressureLevel::Normal
            | crate::l4_defense::L4PressureLevel::Elevated => Duration::from_secs(60),
            crate::l4_defense::L4PressureLevel::High => Duration::from_secs(10),
            crate::l4_defense::L4PressureLevel::Critical => Duration::from_secs(3),
        }
    }

    fn max_lifetime(&self) -> Duration {
        match self
            .pressure_level
            .max(crate::l4_defense::current_pressure_level())
        {
            crate::l4_defense::L4PressureLevel::Normal
            | crate::l4_defense::L4PressureLevel::Elevated => Duration::from_secs(600),
            crate::l4_defense::L4PressureLevel::High => Duration::from_secs(120),
            crate::l4_defense::L4PressureLevel::Critical => Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ListenerConfig {
    is_tls: bool,
    enable_proxy_protocol: bool,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AfXdpHttpPortKind {
    Http,
    Https,
}

struct PassthroughBackendTarget {
    addr: String,
    origin_id: i64,
    proxy_protocol: ProxyProtocolConfig,
}

trait SniPassthroughStream: AsyncRead + AsyncWrite + Unpin {}

impl<T> SniPassthroughStream for T where T: AsyncRead + AsyncWrite + Unpin {}

enum SniPassthroughClient {
    Tcp(TcpStream),
    Stream(Box<dyn SniPassthroughStream + Send>),
}

fn af_xdp_virtual_stream<S>(stream: S, client_addr: SocketAddr) -> L4Stream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::xdp::af_xdp::virtual_l4_stream(stream, client_addr)
}

struct PrefixedStream<S> {
    prefix: io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let prefix_pos = self.prefix.position() as usize;
        let prefix = self.prefix.get_ref();
        if prefix_pos < prefix.len() {
            let available = &prefix[prefix_pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.prefix.set_position((prefix_pos + to_copy) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum TlsHostInspection {
    Route(crate::config::TlsRouteInspection),
    None,
    Probe(TlsProbeKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TlsProbeKind {
    PartialClientHello,
    InvalidProbe,
    PlaintextConnect,
    SlowClientHello,
}

impl TlsProbeKind {
    fn l4_kind(self) -> L4DefenseKind {
        match self {
            Self::PartialClientHello => L4DefenseKind::TlsPartialClientHello,
            Self::InvalidProbe => L4DefenseKind::TlsInvalidProbe,
            Self::PlaintextConnect => L4DefenseKind::TlsPlaintextConnectOnTls,
            Self::SlowClientHello => L4DefenseKind::TlsSlowClientHello,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::PartialClientHello => "partial_client_hello",
            Self::InvalidProbe => "invalid_probe",
            Self::PlaintextConnect => "plaintext_connect",
            Self::SlowClientHello => "slow_client_hello",
        }
    }
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
    plain_proxy: OnceLock<Arc<pingora_proxy::HttpProxy<EdgeProxy>>>,
    tls_proxy: OnceLock<Arc<pingora_proxy::HttpProxy<EdgeProxy>>>,
    tls_acceptor: parking_lot::RwLock<Option<Arc<PingoraTlsAcceptor>>>,
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
            plain_proxy: OnceLock::new(),
            tls_proxy: OnceLock::new(),
            tls_acceptor: parking_lot::RwLock::new(None),
        })
    }

    pub async fn start_listeners(self: Arc<Self>) {
        debug!("HTTP/HTTPS Proxy Manager: Monitoring configuration for port changes...");
        let mut reload_generation = self.config_store.runtime_reload_generation();
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
                generation = self.config_store.wait_for_runtime_reload(reload_generation) => {
                    reload_generation = generation;
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
        shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let worker_count = MEMORY_GOVERNOR.http_accept_worker_count();
        info!(
            "HTTP/HTTPS Proxy Manager: starting {} accept worker(s) on {} (TLS={}, proxy_protocol={})",
            worker_count, bind_addr, is_tls, enable_proxy_protocol
        );
        for worker_id in 1..worker_count {
            let manager = self.clone();
            let worker_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(err) = manager
                    .run_http_listener_worker(
                        bind_addr,
                        is_tls,
                        enable_proxy_protocol,
                        worker_id,
                        worker_shutdown,
                    )
                    .await
                {
                    error!(
                        "HTTP/HTTPS accept worker {} on {} failed: {}",
                        worker_id, bind_addr, err
                    );
                }
            });
        }
        self.run_http_listener_worker(bind_addr, is_tls, enable_proxy_protocol, 0, shutdown_rx)
            .await
    }

    async fn run_http_listener_worker(
        self: Arc<Self>,
        bind_addr: SocketAddr,
        is_tls: bool,
        enable_proxy_protocol: bool,
        worker_id: usize,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let port = bind_addr.port();
        let listener = bind_tcp_listener_with_retry(
            bind_addr,
            MEMORY_GOVERNOR.listener_backlog(),
            &mut shutdown_rx,
        )
        .await?;
        info!(
            "HTTP Proxy accept worker {} (TLS={}) listening on {}",
            worker_id, is_tls, bind_addr
        );

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
        let node_id = self
            .proxy_logic
            .api_config
            .node_id
            .parse::<i64>()
            .unwrap_or(0);

        loop {
            let accept_result = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!(
                        "HTTP/HTTPS accept worker {} on {} shutting down",
                        worker_id, bind_addr
                    );
                    return Ok(());
                }
                res = listener.accept() => res,
            };
            let (client_stream, client_addr) = match accept_result {
                Ok(result) => result,
                Err(err) if is_transient_accept_error(&err) => {
                    debug!(
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
            if crate::l4_defense::is_l4_blocked(
                &self.config_store,
                &self.proxy_logic.waf_state,
                client_addr.ip(),
            ) {
                continue;
            }

            let protocol_label = if is_tls { "https" } else { "http" };
            if matches!(
                crate::l4_defense::record_tcp_accepted_churn(
                    &self.config_store,
                    &self.proxy_logic.waf_state,
                    node_id,
                    client_addr.ip(),
                    || {
                        format!(
                            "bind={} peer={} protocol={} phase=accept pressure={}",
                            bind_addr,
                            client_addr,
                            protocol_label,
                            crate::l4_defense::current_pressure_level().as_str()
                        )
                    },
                ),
                Some(
                    crate::l4_defense::L4DefenseVerdict::Blocked
                        | crate::l4_defense::L4DefenseVerdict::AggregateDropped
                        | crate::l4_defense::L4DefenseVerdict::AlreadyBlocked
                )
            ) {
                continue;
            }
            if matches!(
                crate::l4_defense::record_tcp_connection_churn_under_pressure(
                    &self.config_store,
                    &self.proxy_logic.waf_state,
                    node_id,
                    client_addr.ip(),
                    || {
                        format!(
                            "bind={} peer={} protocol={} phase=accept",
                            bind_addr, client_addr, protocol_label
                        )
                    },
                ),
                Some(
                    crate::l4_defense::L4DefenseVerdict::Blocked
                        | crate::l4_defense::L4DefenseVerdict::AggregateDropped
                        | crate::l4_defense::L4DefenseVerdict::AlreadyBlocked
                )
            ) {
                continue;
            }
            let per_ip_limit = if is_tls && self.config_store.has_any_sni_passthrough_sync() {
                crate::l4_defense::current_sni_tcp_active_limit_per_ip()
            } else {
                crate::l4_defense::current_tcp_active_limit_per_ip()
            };
            let Some(client_permit) =
                crate::l4_defense::try_acquire_tcp_active_ip(client_addr.ip(), per_ip_limit)
            else {
                self.record_l4_event(
                    client_addr.ip(),
                    L4DefenseKind::TcpActiveLimit,
                    format!(
                        "bind={} peer={} protocol={} limit={}",
                        bind_addr, client_addr, protocol_label, per_ip_limit
                    ),
                );
                continue;
            };

            let Some(connection_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::HttpConnection)
            else {
                self.record_l4_event(
                    client_addr.ip(),
                    L4DefenseKind::TcpAdmissionReject,
                    format!(
                        "bind={} peer={} protocol={}",
                        bind_addr, client_addr, protocol_label
                    ),
                );
                debug!(
                    "HTTP connection admission limit reached on {}, dropping connection from {}",
                    bind_addr, client_addr
                );
                continue;
            };

            if !is_tls {
                let proxy_inner = proxy_arc.clone();
                let shutdown_inner = shutdown_rx.clone();
                let manager = self.clone();
                let downstream_read_timeout = crate::l4_defense::clamp_http_read_timeout(
                    manager.downstream_read_timeout(),
                    crate::l4_defense::current_pressure_level(),
                );
                tokio::spawn(async move {
                    let _client_permit = client_permit;
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
                    if crate::l4_defense::is_l4_blocked(
                        &manager.config_store,
                        &manager.proxy_logic.waf_state,
                        effective_addr.ip(),
                    ) {
                        return;
                    }
                    let connection_guard = l4_connection_registry::register(
                        effective_addr.ip(),
                        L4ConnectionProtocol::Http1,
                    );
                    let mut connection_cancel_rx = connection_guard.cancel_receiver();
                    tokio::select! {
                        _ = connection_cancel_rx.changed() => {}
                        _ = manager.record_empty_connection_if_no_payload(
                            client_stream,
                            effective_addr,
                            proxy_inner,
                            shutdown_inner,
                            downstream_read_timeout,
                            port,
                        ) => {}
                    }
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
            let downstream_read_timeout = crate::l4_defense::clamp_http_read_timeout(
                manager.downstream_read_timeout(),
                crate::l4_defense::current_pressure_level(),
            );
            let http2_handshake_timeout = manager.http2_handshake_timeout();

            tokio::spawn(async move {
                let _client_permit = client_permit;
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
                if crate::l4_defense::is_l4_blocked(
                    &manager.config_store,
                    &manager.proxy_logic.waf_state,
                    client_addr.ip(),
                ) {
                    return;
                }
                let connection_guard =
                    l4_connection_registry::register(client_addr.ip(), L4ConnectionProtocol::Http1);
                let mut connection_cancel_rx = connection_guard.cancel_receiver();

                if is_tls {
                    match manager.inspect_tls_host(&client_stream, port).await {
                        Ok(TlsHostInspection::Route(route)) => {
                            configured_tls_host = route.has_l7_server;
                            if let Some(server) = route.sni_passthrough_server {
                                drop(connection_guard);
                                let sni_connection_guard = l4_connection_registry::register(
                                    client_addr.ip(),
                                    L4ConnectionProtocol::SniTcp,
                                );
                                let sni_cancel_rx = sni_connection_guard.cancel_receiver();
                                configure_passthrough_socket(&client_stream);
                                if let Err(err) = manager
                                    .handle_sni_passthrough(
                                        client_stream,
                                        client_addr,
                                        port,
                                        route.host,
                                        server,
                                        Some(sni_cancel_rx),
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
                        Ok(TlsHostInspection::None) => {}
                        Ok(TlsHostInspection::Probe(probe)) => {
                            manager.record_l4_event(
                                client_addr.ip(),
                                probe.l4_kind(),
                                format!(
                                    "port={} peer={} phase=sni_peek probe={}",
                                    port,
                                    client_addr,
                                    probe.as_str()
                                ),
                            );
                            return;
                        }
                        Err(err) => {
                            count_tls_handshake_failure = false;
                            manager.record_l4_event(
                                client_addr.ip(),
                                L4DefenseKind::SniProbeFail,
                                format!("port={} peer={} inspect_error={}", port, client_addr, err),
                            );
                            debug!(
                                "Failed to inspect SNI for {} on port {}: {}",
                                client_addr, port, err
                            );
                        }
                    }
                }

                let l4_stream = stream_with_socket_digest(client_stream, client_addr);
                let downstream_socket_digest = l4_stream.get_socket_digest();
                let effective_tls_handshake_timeout =
                    crate::l4_defense::clamp_tls_handshake_timeout(
                        tls_handshake_timeout,
                        crate::l4_defense::current_pressure_level(),
                    );
                let (stream, alpn): (pingora_core::protocols::Stream, Option<ALPN>) =
                    if let Some(ssl_acceptor) = &acceptor_clone {
                        match tokio::time::timeout(
                            effective_tls_handshake_timeout,
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
                                    debug!("TLS handshake failed: {}", e);
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
                                        effective_tls_handshake_timeout
                                    );
                                }
                                if count_tls_handshake_failure {
                                    manager.record_l4_event(
                                        client_addr.ip(),
                                        L4DefenseKind::TlsSlowClientHello,
                                        format!(
                                            "port={} peer={} timeout_ms={}",
                                            port,
                                            client_addr,
                                            effective_tls_handshake_timeout.as_millis()
                                        ),
                                    );
                                }
                                return;
                            }
                        }
                    } else {
                        (Box::new(l4_stream), None)
                    };

                if matches!(alpn, Some(ALPN::H2)) {
                    drop(connection_guard);
                    let h2_connection_guard = l4_connection_registry::register(
                        client_addr.ip(),
                        L4ConnectionProtocol::Http2,
                    );
                    let h2_cancel_rx = h2_connection_guard.cancel_receiver();
                    process_h2_stream(
                        stream,
                        downstream_socket_digest,
                        proxy_inner,
                        shutdown_inner,
                        manager,
                        client_addr,
                        port,
                        http2_handshake_timeout,
                        h2_cancel_rx,
                        h2_connection_guard,
                        configured_tls_host,
                    )
                    .await
                } else {
                    tokio::select! {
                        _ = connection_cancel_rx.changed() => {
                            debug!("HTTP/1 connection from {} cancelled by L4 registry", client_addr);
                        }
                        _ = process_http1_stream(
                            stream,
                            proxy_inner,
                            shutdown_inner,
                            downstream_read_timeout,
                            manager,
                            client_addr,
                            port,
                            true,
                        ) => {}
                    }
                }
            });
        }
    }

    fn downstream_read_timeout(&self) -> Duration {
        crate::resource_budget::downstream_read_timeout(
            &self.config_store.get_global_http_config_sync(),
        )
    }

    fn proxy_for_tls(&self, is_tls: bool) -> Arc<pingora_proxy::HttpProxy<EdgeProxy>> {
        let cell = if is_tls {
            &self.tls_proxy
        } else {
            &self.plain_proxy
        };
        cell.get_or_init(|| {
            let mut proxy_logic = self.proxy_logic.clone();
            proxy_logic.tls_downstream = is_tls;
            Arc::new(http_proxy(&self.server_conf, proxy_logic))
        })
        .clone()
    }

    fn shared_tls_acceptor(&self) -> anyhow::Result<Arc<PingoraTlsAcceptor>> {
        if let Some(acceptor) = self.tls_acceptor.read().clone() {
            return Ok(acceptor);
        }
        let mut guard = self.tls_acceptor.write();
        if let Some(acceptor) = guard.clone() {
            return Ok(acceptor);
        }
        let rustls_config = crate::ssl::build_rustls_server_config(
            Arc::clone(&self.cert_selector),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            false,
        )
        .context("build rustls HTTP server config")?;
        let acceptor = Arc::new(PingoraTlsAcceptor::from_server_config(rustls_config));
        *guard = Some(acceptor.clone());
        Ok(acceptor)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn af_xdp_http_port_kind_sync(&self, port: u16) -> Option<AfXdpHttpPortKind> {
        let servers = self.config_store.get_all_servers_sync();
        let mut matched = None;
        for server in servers {
            if server.http.as_ref().is_some_and(|http| {
                http.is_on
                    && http.listen.iter().any(|addr| {
                        addr.port_range.as_deref().is_some_and(|range| {
                            crate::config_models::port_range_contains(range, port)
                        })
                    })
            }) {
                matched.get_or_insert(AfXdpHttpPortKind::Http);
            }
            if server.https.as_ref().is_some_and(|https| {
                https.is_on
                    && https.listen.iter().any(|addr| {
                        addr.port_range.as_deref().is_some_and(|range| {
                            crate::config_models::port_range_contains(range, port)
                        })
                    })
            }) {
                return Some(AfXdpHttpPortKind::Https);
            }
        }
        matched
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn af_xdp_is_l4_blocked(&self, ip: IpAddr) -> bool {
        crate::l4_defense::is_l4_blocked(&self.config_store, &self.proxy_logic.waf_state, ip)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn record_af_xdp_l4_event_with_pressure(
        &self,
        ip: IpAddr,
        kind: L4DefenseKind,
        pressure_level: crate::l4_defense::L4PressureLevel,
        detail: impl Into<String>,
    ) -> crate::l4_defense::L4DefenseVerdict {
        let node_id = self
            .proxy_logic
            .api_config
            .node_id
            .parse::<i64>()
            .unwrap_or(0);
        crate::l4_defense::record_l4_event_with_pressure(
            &self.config_store,
            &self.proxy_logic.waf_state,
            node_id,
            ip,
            kind,
            detail,
            pressure_level,
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
        port: u16,
    ) {
        let cluster_id = self.config_store.get_node_cluster_id_sync();
        let config = self.empty_connection_flood_config(cluster_id);
        let pressure_level = crate::l4_defense::current_pressure_level();
        let first_byte_timeout = crate::l4_defense::first_byte_timeout(pressure_level);
        let mut first_byte = [0u8; 1];
        match tokio::time::timeout(first_byte_timeout, client_stream.peek(&mut first_byte)).await {
            Ok(Ok(0)) => {
                if let Some(config) = config {
                    self.record_special_defense_hit(
                        cluster_id,
                        "EMPTY_CONNECTION_FLOOD",
                        client_addr.ip(),
                        config,
                    );
                    if crate::l4_defense::is_l4_blocked(
                        &self.config_store,
                        &self.proxy_logic.waf_state,
                        client_addr.ip(),
                    ) {
                        let drained = crate::l4_connection_registry::drain_ip(client_addr.ip());
                        if drained > 0 {
                            crate::logging::report_node_log(
                                "warn".to_string(),
                                "l4_recovery".to_string(),
                                format!(
                                    "ip={} kind=empty_connection_flood reason=special_defense_block drained_connections={}",
                                    client_addr.ip(),
                                    drained
                                ),
                                0,
                            );
                        }
                    }
                }
            }
            Ok(Ok(_)) => {
                process_plain_http_connection(
                    client_stream,
                    client_addr,
                    proxy_inner,
                    shutdown_inner,
                    downstream_read_timeout,
                    port,
                    self.clone(),
                )
                .await;
            }
            Ok(Err(err)) => {
                debug!(
                    "HTTP first-byte peek failed for {} after {:?}: {}",
                    client_addr, first_byte_timeout, err
                );
            }
            Err(_) => {
                self.record_l4_event(
                    client_addr.ip(),
                    L4DefenseKind::TcpSlowFirstByte,
                    format!(
                        "peer={} timeout_ms={} pressure={}",
                        client_addr,
                        first_byte_timeout.as_millis(),
                        pressure_level.as_str()
                    ),
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
        self.record_l4_event(
            ip,
            L4DefenseKind::TlsHandshakeFail,
            "http_tls_handshake_failure",
        );
    }

    fn record_l4_event(
        &self,
        ip: IpAddr,
        kind: L4DefenseKind,
        detail: impl Into<String>,
    ) -> crate::l4_defense::L4DefenseVerdict {
        let node_id = self
            .proxy_logic
            .api_config
            .node_id
            .parse::<i64>()
            .unwrap_or(0);
        crate::l4_defense::record_l4_event(
            &self.config_store,
            &self.proxy_logic.waf_state,
            node_id,
            ip,
            kind,
            detail,
        )
    }

    fn record_l4_event_weighted(
        &self,
        ip: IpAddr,
        kind: L4DefenseKind,
        amount: u64,
        detail: impl Into<String>,
    ) -> crate::l4_defense::L4DefenseVerdict {
        let node_id = self
            .proxy_logic
            .api_config
            .node_id
            .parse::<i64>()
            .unwrap_or(0);
        crate::l4_defense::record_l4_event_weighted_with_pressure(
            &self.config_store,
            &self.proxy_logic.waf_state,
            node_id,
            ip,
            kind,
            amount,
            detail,
            crate::l4_defense::current_pressure_level(),
        )
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
    ) -> anyhow::Result<TlsHostInspection> {
        if !self.config_store.has_any_sni_passthrough_sync() {
            return Ok(TlsHostInspection::None);
        }

        let timeouts = crate::l4_defense::client_hello_timeouts_for_sni_passthrough(
            crate::l4_defense::current_pressure_level(),
        );
        match peek_client_hello_sni(client_stream, timeouts).await? {
            ClientHelloPeek::Found(host) => Ok(self
                .config_store
                .inspect_tls_route_sync(&host, port)
                .map(TlsHostInspection::Route)
                .unwrap_or(TlsHostInspection::None)),
            ClientHelloPeek::Incomplete { saw_tls_prefix } => {
                Ok(TlsHostInspection::Probe(if saw_tls_prefix {
                    TlsProbeKind::PartialClientHello
                } else {
                    TlsProbeKind::SlowClientHello
                }))
            }
            ClientHelloPeek::NotClientHello { plaintext_connect } => {
                if plaintext_connect {
                    Ok(TlsHostInspection::Probe(TlsProbeKind::PlaintextConnect))
                } else {
                    Ok(TlsHostInspection::Probe(TlsProbeKind::InvalidProbe))
                }
            }
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) async fn handle_af_xdp_http_stream<S>(
        self: Arc<Self>,
        client_stream: S,
        client_addr: SocketAddr,
        listen_port: u16,
        kind: AfXdpHttpPortKind,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !self.config_store.has_any_sni_passthrough_sync() {
            return self
                .handle_af_xdp_l7_http_stream(client_stream, client_addr, listen_port, kind)
                .await;
        }

        let timeouts =
            crate::l4_defense::client_hello_timeouts(crate::l4_defense::current_pressure_level());
        let (peek, client_stream) = if kind == AfXdpHttpPortKind::Https {
            sniff_client_hello_sni(client_stream, timeouts).await?
        } else {
            (
                ClientHelloPeek::NotClientHello {
                    plaintext_connect: false,
                },
                PrefixedStream::new(Vec::new(), client_stream),
            )
        };
        match (kind, peek) {
            (AfXdpHttpPortKind::Http, _) => {
                self.handle_af_xdp_l7_http_stream(
                    client_stream,
                    client_addr,
                    listen_port,
                    AfXdpHttpPortKind::Http,
                )
                .await
            }
            (AfXdpHttpPortKind::Https, ClientHelloPeek::Found(host)) => {
                let Some(TlsHostInspection::Route(route)) = self
                    .config_store
                    .inspect_tls_route_sync(&host, listen_port)
                    .map(TlsHostInspection::Route)
                else {
                    return self
                        .handle_af_xdp_l7_http_stream(
                            client_stream,
                            client_addr,
                            listen_port,
                            AfXdpHttpPortKind::Https,
                        )
                        .await;
                };
                if let Some(server) = route.sni_passthrough_server {
                    let sni_connection_guard = l4_connection_registry::register(
                        client_addr.ip(),
                        L4ConnectionProtocol::SniTcp,
                    );
                    let sni_cancel_rx = sni_connection_guard.cancel_receiver();
                    self.handle_sni_passthrough_stream(
                        client_stream,
                        client_addr,
                        listen_port,
                        route.host,
                        server,
                        Some(sni_cancel_rx),
                    )
                    .await
                } else {
                    self.handle_af_xdp_l7_http_stream(
                        client_stream,
                        client_addr,
                        listen_port,
                        AfXdpHttpPortKind::Https,
                    )
                    .await
                }
            }
            (_, ClientHelloPeek::Incomplete { saw_tls_prefix }) => {
                self.record_l4_event(
                    client_addr.ip(),
                    if saw_tls_prefix {
                        L4DefenseKind::TlsPartialClientHello
                    } else {
                        L4DefenseKind::TlsSlowClientHello
                    },
                    format!(
                        "port={} peer={} phase=af_xdp_sni_peek",
                        listen_port, client_addr
                    ),
                );
                Ok(())
            }
            (_, ClientHelloPeek::NotClientHello { plaintext_connect }) => {
                self.record_l4_event(
                    client_addr.ip(),
                    if plaintext_connect {
                        L4DefenseKind::TlsPlaintextConnectOnTls
                    } else {
                        L4DefenseKind::TlsInvalidProbe
                    },
                    format!(
                        "port={} peer={} phase=af_xdp_sni_peek",
                        listen_port, client_addr
                    ),
                );
                Ok(())
            }
        }
    }

    async fn handle_af_xdp_l7_http_stream<S>(
        self: Arc<Self>,
        client_stream: S,
        client_addr: SocketAddr,
        listen_port: u16,
        kind: AfXdpHttpPortKind,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if crate::l4_defense::is_l4_blocked(
            &self.config_store,
            &self.proxy_logic.waf_state,
            client_addr.ip(),
        ) {
            return Ok(());
        }
        let protocol_label = match kind {
            AfXdpHttpPortKind::Http => "http",
            AfXdpHttpPortKind::Https => "https",
        };
        if matches!(
            crate::l4_defense::record_tcp_connection_churn_under_pressure(
                &self.config_store,
                &self.proxy_logic.waf_state,
                self.proxy_logic
                    .api_config
                    .node_id
                    .parse::<i64>()
                    .unwrap_or(0),
                client_addr.ip(),
                || {
                    format!(
                        "port={} peer={} protocol={} phase=af_xdp_accept",
                        listen_port, client_addr, protocol_label
                    )
                },
            ),
            Some(
                crate::l4_defense::L4DefenseVerdict::Blocked
                    | crate::l4_defense::L4DefenseVerdict::AggregateDropped
                    | crate::l4_defense::L4DefenseVerdict::AlreadyBlocked
            )
        ) {
            return Ok(());
        }
        let Some(client_permit) = crate::l4_defense::try_acquire_tcp_active_ip(
            client_addr.ip(),
            crate::l4_defense::current_tcp_active_limit_per_ip(),
        ) else {
            self.record_l4_event(
                client_addr.ip(),
                L4DefenseKind::TcpActiveLimit,
                format!(
                    "port={} peer={} protocol={}",
                    listen_port, client_addr, protocol_label
                ),
            );
            return Ok(());
        };
        let Some(connection_permit) = MEMORY_GOVERNOR.try_admit(AdmissionClass::HttpConnection)
        else {
            self.record_l4_event(
                client_addr.ip(),
                L4DefenseKind::TcpAdmissionReject,
                format!(
                    "port={} peer={} protocol={}",
                    listen_port, client_addr, protocol_label
                ),
            );
            return Ok(());
        };

        let _client_permit = client_permit;
        let _connection_permit = connection_permit;
        let proxy_inner = self.proxy_for_tls(kind == AfXdpHttpPortKind::Https);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let downstream_read_timeout = crate::l4_defense::clamp_http_read_timeout(
            self.downstream_read_timeout(),
            crate::l4_defense::current_pressure_level(),
        );
        let connection_guard =
            l4_connection_registry::register(client_addr.ip(), L4ConnectionProtocol::Http1);
        let mut connection_cancel_rx = connection_guard.cancel_receiver();

        let l4_stream = af_xdp_virtual_stream(client_stream, client_addr);
        let stream: pingora_core::protocols::Stream = if kind == AfXdpHttpPortKind::Https {
            let acceptor = self.shared_tls_acceptor()?;
            let timeout = crate::l4_defense::clamp_tls_handshake_timeout(
                self.tls_handshake_timeout(),
                crate::l4_defense::current_pressure_level(),
            );
            match tokio::time::timeout(timeout, handshake(&acceptor, l4_stream)).await {
                Ok(Ok(tls_stream)) => {
                    if matches!(tls_stream.selected_alpn_proto(), Some(ALPN::H2)) {
                        let socket_digest = tls_stream.get_socket_digest();
                        drop(connection_guard);
                        let h2_connection_guard = l4_connection_registry::register(
                            client_addr.ip(),
                            L4ConnectionProtocol::Http2,
                        );
                        let h2_cancel_rx = h2_connection_guard.cancel_receiver();
                        let http2_handshake_timeout = self.http2_handshake_timeout();
                        process_h2_stream(
                            Box::new(tls_stream),
                            socket_digest,
                            proxy_inner,
                            shutdown_rx,
                            self.clone(),
                            client_addr,
                            listen_port,
                            http2_handshake_timeout,
                            h2_cancel_rx,
                            h2_connection_guard,
                            true,
                        )
                        .await;
                        return Ok(());
                    }
                    Box::new(tls_stream)
                }
                Ok(Err(err)) => {
                    if !is_benign_tls_accept_error(&err.to_string()) {
                        debug!("AF_XDP TLS handshake failed peer={}: {}", client_addr, err);
                    }
                    self.record_tls_handshake_failure(client_addr.ip());
                    return Ok(());
                }
                Err(_) => {
                    self.record_l4_event(
                        client_addr.ip(),
                        L4DefenseKind::TlsSlowClientHello,
                        format!(
                            "port={} peer={} phase=af_xdp_tls_handshake timeout_ms={}",
                            listen_port,
                            client_addr,
                            timeout.as_millis()
                        ),
                    );
                    return Ok(());
                }
            }
        } else {
            Box::new(l4_stream)
        };

        tokio::select! {
            _ = connection_cancel_rx.changed() => {
                debug!("AF_XDP HTTP/1 connection from {} cancelled by L4 registry", client_addr);
            }
            _ = process_http1_stream(
                stream,
                proxy_inner,
                shutdown_rx,
                downstream_read_timeout,
                self.clone(),
                client_addr,
                listen_port,
                kind == AfXdpHttpPortKind::Https,
            ) => {}
        }
        Ok(())
    }

    async fn handle_sni_passthrough(
        &self,
        client_stream: TcpStream,
        client_addr: SocketAddr,
        listen_port: u16,
        sni_host: String,
        server: Arc<ServerConfig>,
        cancel_rx: Option<watch::Receiver<bool>>,
    ) -> anyhow::Result<()> {
        self.handle_sni_passthrough_inner(
            SniPassthroughClient::Tcp(client_stream),
            client_addr,
            listen_port,
            sni_host,
            server,
            cancel_rx,
        )
        .await
    }

    async fn handle_sni_passthrough_stream<S>(
        &self,
        client_stream: S,
        client_addr: SocketAddr,
        listen_port: u16,
        sni_host: String,
        server: Arc<ServerConfig>,
        cancel_rx: Option<watch::Receiver<bool>>,
    ) -> anyhow::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.handle_sni_passthrough_inner(
            SniPassthroughClient::Stream(Box::new(client_stream)),
            client_addr,
            listen_port,
            sni_host,
            server,
            cancel_rx,
        )
        .await
    }

    async fn handle_sni_passthrough_inner(
        &self,
        client_stream: SniPassthroughClient,
        client_addr: SocketAddr,
        listen_port: u16,
        sni_host: String,
        server: Arc<ServerConfig>,
        cancel_rx: Option<watch::Receiver<bool>>,
    ) -> anyhow::Result<()> {
        let started = Instant::now();
        let started_at_millis = crate::utils::time::now_timestamp_millis();
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
        let origin_connect_permit = MEMORY_GOVERNOR
            .try_admit(AdmissionClass::OriginConnect)
            .ok_or_else(|| anyhow::anyhow!("origin connect memory admission rejected"))?;
        let toa_config = self.config_store.get_toa_config_sync();
        let mut backend_stream = match connect_passthrough_backend_with_retry(
            &backend_addr,
            client_addr,
            toa_config.clone(),
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
                crate::metrics::record::record_network_dimensions(
                    crate::metrics::METRIC_CATEGORY_TCP,
                    server_id,
                    client_addr.ip(),
                    &sni_host,
                    "-",
                    0,
                    0,
                    502,
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
                    crate::metrics::record::record_network_dimensions(
                        crate::metrics::METRIC_CATEGORY_TCP,
                        server_id,
                        client_addr.ip(),
                        &sni_host,
                        "-",
                        0,
                        0,
                        502,
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
                crate::metrics::record::record_network_dimensions(
                    crate::metrics::METRIC_CATEGORY_TCP,
                    server_id,
                    client_addr.ip(),
                    &sni_host,
                    "-",
                    0,
                    0,
                    502,
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
        drop(origin_connect_permit);

        let result = match client_stream {
            SniPassthroughClient::Tcp(client_stream) => {
                crate::tcp_proxy::stream_sni_passthrough_bidirectional_with_metrics_cancelable(
                    server_id,
                    client_stream,
                    backend_stream,
                    cancel_rx,
                )
                .await
            }
            SniPassthroughClient::Stream(client_stream) => {
                crate::tcp_proxy::stream_sni_passthrough_bidirectional_with_metrics_cancelable_stream(
                    server_id,
                    client_stream,
                    backend_stream,
                    cancel_rx,
                )
                .await
            }
        };
        if let Some(local_port) = toa_local_port {
            if let Err(err) = crate::toa::unregister_toa_port(toa_config.clone(), local_port).await
            {
                debug!("failed to release TOA sender port {}: {}", local_port, err);
            }
        }
        match result {
            Ok(outcome) => {
                let bytes_received = outcome.bytes_received;
                let bytes_sent = outcome.bytes_sent;
                let relay_note = outcome.close_note();
                if outcome.close_reason == crate::tcp_proxy::RelayCloseReason::PressureIdleTimeout {
                    self.record_l4_event(
                        client_addr.ip(),
                        L4DefenseKind::TcpPressureIdleClose,
                        format!(
                            "sni={} port={} peer={} backend={}",
                            sni_host, listen_port, client_addr, backend_addr
                        ),
                    );
                }
                crate::metrics::record::record_network_dimensions(
                    crate::metrics::METRIC_CATEGORY_TCP,
                    server_id,
                    client_addr.ip(),
                    &sni_host,
                    "-",
                    bytes_sent as i64,
                    bytes_received as i64,
                    200,
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
                    relay_note.as_deref(),
                );
                crate::metrics::record::request_end(server_id, 0, 0, false, false, false, None);
                Ok(())
            }
            Err(err) => {
                let bytes_received = err.bytes_received;
                let bytes_sent = err.bytes_sent;
                crate::metrics::record::record_network_dimensions(
                    crate::metrics::METRIC_CATEGORY_TCP,
                    server_id,
                    client_addr.ip(),
                    &sni_host,
                    "-",
                    bytes_sent as i64,
                    bytes_received as i64,
                    502,
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
    port: u16,
    manager: Arc<HttpProxyManager>,
) {
    let _ = client_stream.set_nodelay(true);
    let l4_stream = stream_with_socket_digest(client_stream, client_addr);
    process_http1_stream(
        Box::new(l4_stream),
        proxy_inner,
        shutdown_inner,
        downstream_read_timeout,
        manager,
        client_addr,
        port,
        false,
    )
    .await;
}

async fn process_h2_stream(
    stream: pingora_core::protocols::Stream,
    socket_digest: Option<Arc<SocketDigest>>,
    proxy_inner: Arc<pingora_proxy::HttpProxy<EdgeProxy>>,
    shutdown_inner: watch::Receiver<bool>,
    manager: Arc<HttpProxyManager>,
    client_addr: SocketAddr,
    port: u16,
    http2_handshake_timeout: Duration,
    mut h2_cancel_rx: watch::Receiver<bool>,
    _h2_connection_guard: crate::l4_connection_registry::L4ConnectionGuard,
    configured_tls_host: bool,
) {
    let digest = Arc::new(pingora_core::protocols::Digest {
        socket_digest,
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
            let mut h2_state = H2ConnectionDefenseState::new(
                client_addr.ip(),
                port,
                crate::l4_defense::current_pressure_level(),
            );
            loop {
                let idle_deadline = h2_state.next_idle_deadline();
                let lifetime_deadline = h2_state.lifetime_deadline();
                let accept_result = tokio::select! {
                    _ = h2_cancel_rx.changed() => {
                        debug!("HTTP/2 connection from {} cancelled by L4 registry", client_addr);
                        break;
                    }
                    _ = tokio::time::sleep_until(idle_deadline) => {
                        manager.record_l4_event(
                            client_addr.ip(),
                            L4DefenseKind::H2ConnectionAbuse,
                            format!(
                                "port={} peer={} reason=idle_timeout streams={} rejects={}",
                                port,
                                client_addr,
                                h2_state.accepted_streams,
                                h2_state.rejected_streams
                            ),
                        );
                        break;
                    }
                    _ = tokio::time::sleep_until(lifetime_deadline) => {
                        manager.record_l4_event(
                            client_addr.ip(),
                            L4DefenseKind::H2ConnectionAbuse,
                            format!(
                                "port={} peer={} reason=max_lifetime streams={} rejects={}",
                                port,
                                client_addr,
                                h2_state.accepted_streams,
                                h2_state.rejected_streams
                            ),
                        );
                        break;
                    }
                    result = pingora_core::protocols::http::v2::server::HttpSession::from_h2_conn(&mut h2_conn, digest.clone()) => result,
                };
                match accept_result {
                    Ok(Some(h2_session)) => {
                        h2_state.record_stream();
                        if let Some(events) = h2_state.take_pending_l4_stream_events_if_due() {
                            manager.record_l4_event_weighted(
                                client_addr.ip(),
                                L4DefenseKind::H2RequestChurn,
                                events,
                                format!(
                                    "port={} peer={} streams={} increment={} pressure={}",
                                    port,
                                    client_addr,
                                    h2_state.accepted_streams,
                                    events,
                                    crate::l4_defense::current_pressure_level().as_str()
                                ),
                            );
                        }
                        if h2_state.should_close_for_churn() {
                            let pending = h2_state.take_pending_l4_stream_events();
                            if pending > 0 {
                                manager.record_l4_event_weighted(
                                    client_addr.ip(),
                                    L4DefenseKind::H2RequestChurn,
                                    pending,
                                    format!(
                                        "port={} peer={} streams={} increment={} reason=churn_close",
                                        port,
                                        client_addr,
                                        h2_state.accepted_streams,
                                        pending
                                    ),
                                );
                            }
                            manager.record_l4_event(
                                client_addr.ip(),
                                L4DefenseKind::H2RequestChurn,
                                format!(
                                    "port={} peer={} streams={} window_secs={}",
                                    port,
                                    client_addr,
                                    h2_state.accepted_streams,
                                    H2_CHURN_WINDOW.as_secs()
                                ),
                            );
                            break;
                        }
                        let proxy_inner_h2 = proxy_inner.clone();
                        let shutdown_inner_h2 = shutdown_inner.clone();
                        let stream_permit = match Arc::clone(&h2_stream_semaphore)
                            .try_acquire_owned()
                            .ok()
                        {
                            Some(permit) => permit,
                            None => {
                                h2_state.record_reject();
                                manager.record_l4_event(
                                    client_addr.ip(),
                                    L4DefenseKind::H2StreamAdmissionReject,
                                    format!(
                                        "port={} peer={} scope=connection streams={} rejects={}",
                                        port,
                                        client_addr,
                                        h2_state.accepted_streams,
                                        h2_state.rejected_streams
                                    ),
                                );
                                debug!(
                                    "H2 stream admission limit reached for connection, closing connection"
                                );
                                break;
                            }
                        };
                        let global_stream_permit = match MEMORY_GOVERNOR
                            .try_admit(AdmissionClass::Http2Stream)
                        {
                            Some(permit) => permit,
                            None => {
                                h2_state.record_reject();
                                manager.record_l4_event(
                                    client_addr.ip(),
                                    L4DefenseKind::H2StreamAdmissionReject,
                                    format!(
                                        "port={} peer={} scope=global streams={} rejects={}",
                                        port,
                                        client_addr,
                                        h2_state.accepted_streams,
                                        h2_state.rejected_streams
                                    ),
                                );
                                debug!(
                                    "Global H2 stream admission limit reached, closing connection"
                                );
                                break;
                            }
                        };
                        if h2_state.should_report_churn_hint() {
                            debug!(
                                "HTTP/2 churn hint port={} peer={} streams={} pressure={}",
                                port,
                                client_addr,
                                h2_state.accepted_streams,
                                crate::l4_defense::current_pressure_level().as_str()
                            );
                        };
                        tokio::spawn(async move {
                            let _stream_permit = stream_permit;
                            let _global_stream_permit = global_stream_permit;
                            let server_session = ServerSession::new_http2(h2_session);
                            proxy_inner_h2
                                .process_new_http(server_session, &shutdown_inner_h2)
                                .await;
                        });
                    }
                    Ok(None) => break,
                    Err(e) => {
                        h2_state.record_error();
                        if !is_benign_h2_error(&e.to_string()) && configured_tls_host {
                            debug!("HTTP/2 session error: {}", e);
                        }
                        break;
                    }
                }
            }
        }
        Ok(Err(e)) => {
            if !is_benign_h2_error(&e.to_string()) && configured_tls_host {
                debug!("HTTP/2 handshake error: {}", e);
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
}

async fn process_http1_stream(
    stream: pingora_core::protocols::Stream,
    proxy_inner: Arc<pingora_proxy::HttpProxy<EdgeProxy>>,
    shutdown_inner: watch::Receiver<bool>,
    downstream_read_timeout: Duration,
    manager: Arc<HttpProxyManager>,
    client_addr: SocketAddr,
    port: u16,
    is_tls: bool,
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
    if !crate::proxy::take_http_request_parse_mark(client_addr) {
        let kind = if is_tls {
            L4DefenseKind::TlsHandshakeThenNoHttp
        } else {
            L4DefenseKind::HttpEarlyCloseOrTinyRequest
        };
        let node_id = manager
            .proxy_logic
            .api_config
            .node_id
            .parse::<i64>()
            .unwrap_or(0);
        crate::l4_defense::record_completed_handshake_event(
            &manager.config_store,
            &manager.proxy_logic.waf_state,
            node_id,
            client_addr.ip(),
            kind,
            2,
            || {
                format!(
                    "port={} peer={} protocol={} phase=first_request_closed duration_ms=0 payload_len=0 pressure={}",
                    port,
                    client_addr,
                    if is_tls { "https" } else { "http" },
                    crate::l4_defense::current_pressure_level().as_str()
                )
            },
        );
    }

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

async fn connect_passthrough_backend_with_retry(
    backend_addr: &str,
    client_addr: SocketAddr,
    toa_config: Option<crate::config_models::TOAConfig>,
) -> anyhow::Result<TcpStream> {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const RETRY_DELAY: Duration = Duration::from_millis(100);

    match crate::toa::connect_with_toa(
        backend_addr,
        client_addr,
        toa_config.clone(),
        CONNECT_TIMEOUT,
    )
    .await
    {
        Ok(stream) => Ok(stream),
        Err(first_err) => {
            tokio::time::sleep(RETRY_DELAY).await;
            crate::toa::connect_with_toa(
                backend_addr,
                client_addr,
                toa_config,
                CONNECT_TIMEOUT,
            )
            .await
            .map_err(|second_err| {
                second_err.context(format!(
                    "retry failed for upstream {} (first error: {})",
                    backend_addr, first_err
                ))
            })
        }
    }
}

fn normalize_passthrough_target(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("tls://")
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string()
}

fn configure_passthrough_socket(stream: &TcpStream) {
    crate::tcp_proxy::configure_relay_tcp_socket(stream);
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
                    let effective_addr = proxy_protocol::effective_client_addr(client_addr, &addr);
                    if effective_addr == client_addr && addr.src_ip.is_some() {
                        debug!(
                            "PROXY protocol: consumed untrusted header from {}; keeping socket peer",
                            client_addr
                        );
                    } else {
                        debug!(
                            "PROXY protocol: replaced {} with {}",
                            client_addr, effective_addr
                        );
                    }
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

async fn peek_client_hello_sni(
    client_stream: &TcpStream,
    timeouts: crate::l4_defense::ClientHelloTimeouts,
) -> anyhow::Result<ClientHelloPeek> {
    const CLIENT_HELLO_READ_WAIT: Duration = Duration::from_millis(25);
    const CLIENT_HELLO_INITIAL_BUF: usize = 2048;
    const CLIENT_HELLO_MAX_BUF: usize = 16 * 1024;

    let started = tokio::time::Instant::now();
    let mut last_progress = started;
    let mut peek_buf = vec![0u8; CLIENT_HELLO_INITIAL_BUF];
    let mut last_size = 0usize;
    let mut saw_tls_prefix = false;
    loop {
        if started.elapsed() >= timeouts.total || last_progress.elapsed() >= timeouts.idle {
            return Ok(ClientHelloPeek::Incomplete { saw_tls_prefix });
        }

        let _ = tokio::time::timeout(CLIENT_HELLO_READ_WAIT, client_stream.readable()).await;
        let size =
            match tokio::time::timeout(CLIENT_HELLO_READ_WAIT, client_stream.peek(&mut peek_buf))
                .await
            {
                Ok(result) => result?,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            };
        let bytes = &peek_buf[..size];
        saw_tls_prefix |= bytes.first() == Some(&22);
        if size == 0 {
            return Ok(ClientHelloPeek::NotClientHello {
                plaintext_connect: false,
            });
        }
        match parse_tls_client_hello_sni(bytes) {
            ClientHelloParse::Found(host) => return Ok(ClientHelloPeek::Found(host)),
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
            ClientHelloParse::NotClientHello => {
                return Ok(ClientHelloPeek::NotClientHello {
                    plaintext_connect: starts_with_ascii_ci(bytes, b"CONNECT "),
                });
            }
        }
    }
}

async fn sniff_client_hello_sni<S>(
    mut client_stream: S,
    timeouts: crate::l4_defense::ClientHelloTimeouts,
) -> anyhow::Result<(ClientHelloPeek, PrefixedStream<S>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const CLIENT_HELLO_READ_WAIT: Duration = Duration::from_millis(25);
    const CLIENT_HELLO_INITIAL_BUF: usize = 2048;
    const CLIENT_HELLO_MAX_BUF: usize = 16 * 1024;

    let started = tokio::time::Instant::now();
    let mut last_progress = started;
    let mut prefix = Vec::with_capacity(CLIENT_HELLO_INITIAL_BUF);
    let mut read_buf = vec![0u8; CLIENT_HELLO_INITIAL_BUF];
    let mut saw_tls_prefix = false;
    loop {
        if started.elapsed() >= timeouts.total || last_progress.elapsed() >= timeouts.idle {
            let peek = ClientHelloPeek::Incomplete { saw_tls_prefix };
            return Ok((peek, PrefixedStream::new(prefix, client_stream)));
        }

        match parse_tls_client_hello_sni(&prefix) {
            ClientHelloParse::Found(host) => {
                return Ok((
                    ClientHelloPeek::Found(host),
                    PrefixedStream::new(prefix, client_stream),
                ));
            }
            ClientHelloParse::NotClientHello if !prefix.is_empty() => {
                let plaintext_connect = starts_with_ascii_ci(&prefix, b"CONNECT ");
                return Ok((
                    ClientHelloPeek::NotClientHello { plaintext_connect },
                    PrefixedStream::new(prefix, client_stream),
                ));
            }
            ClientHelloParse::NeedMore | ClientHelloParse::NotClientHello => {}
        }

        if prefix.len() >= CLIENT_HELLO_MAX_BUF {
            let peek = ClientHelloPeek::Incomplete { saw_tls_prefix };
            return Ok((peek, PrefixedStream::new(prefix, client_stream)));
        }

        let remaining = CLIENT_HELLO_MAX_BUF - prefix.len();
        let read_len = read_buf.len().min(remaining);
        let n = match tokio::time::timeout(
            CLIENT_HELLO_READ_WAIT,
            client_stream.read(&mut read_buf[..read_len]),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };
        if n == 0 {
            let peek = ClientHelloPeek::NotClientHello {
                plaintext_connect: false,
            };
            return Ok((peek, PrefixedStream::new(prefix, client_stream)));
        }
        if prefix.is_empty() {
            saw_tls_prefix = read_buf.first() == Some(&22);
        }
        prefix.extend_from_slice(&read_buf[..n]);
        last_progress = tokio::time::Instant::now();
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ClientHelloPeek {
    Found(String),
    Incomplete { saw_tls_prefix: bool },
    NotClientHello { plaintext_connect: bool },
}

#[derive(Debug)]
enum ClientHelloParse {
    Found(String),
    NeedMore,
    NotClientHello,
}

fn starts_with_ascii_ci(value: &[u8], prefix: &[u8]) -> bool {
    value.len() >= prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix)
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
        let host = peek_client_hello_sni(
            &server_stream,
            crate::l4_defense::client_hello_timeouts(crate::l4_defense::L4PressureLevel::Normal),
        )
        .await
        .unwrap();
        assert_eq!(host, ClientHelloPeek::Found("peek.example.com".to_string()));

        let mut actual = Vec::new();
        server_stream.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        client.await.unwrap();
    }

    #[tokio::test]
    async fn sniff_client_hello_sni_replays_consumed_prefix() {
        let (mut client, server_stream) = tokio::io::duplex(4096);
        let hello = client_hello(Some("af-xdp.example.com"));
        let expected = hello.clone();

        let writer = tokio::spawn(async move {
            client.write_all(&hello).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let (peek, mut replay_stream) = sniff_client_hello_sni(
            server_stream,
            crate::l4_defense::client_hello_timeouts(crate::l4_defense::L4PressureLevel::Normal),
        )
        .await
        .unwrap();
        assert_eq!(
            peek,
            ClientHelloPeek::Found("af-xdp.example.com".to_string())
        );

        let mut actual = Vec::new();
        replay_stream.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn sniff_client_hello_sni_replays_plaintext_connect_prefix() {
        let (mut client, server_stream) = tokio::io::duplex(4096);
        let request = b"CONNECT example.test:443 HTTP/1.1\r\n\r\n".to_vec();
        let expected = request.clone();

        let writer = tokio::spawn(async move {
            client.write_all(&request).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let (peek, mut replay_stream) = sniff_client_hello_sni(
            server_stream,
            crate::l4_defense::client_hello_timeouts(crate::l4_defense::L4PressureLevel::Normal),
        )
        .await
        .unwrap();
        assert_eq!(
            peek,
            ClientHelloPeek::NotClientHello {
                plaintext_connect: true
            }
        );

        let mut actual = Vec::new();
        replay_stream.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn af_xdp_virtual_stream_replays_bytes_and_sets_peer_digest() {
        let (mut client, server_stream) = tokio::io::duplex(4096);
        let peer: SocketAddr = "203.0.113.8:55000".parse().unwrap();
        let mut stream = af_xdp_virtual_stream(server_stream, peer);

        let writer = tokio::spawn(async move {
            client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            client.flush().await.unwrap();
        });

        let mut buf = [0u8; 18];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"GET / HTTP/1.1\r\n\r\n");
        let digest_peer = stream
            .get_socket_digest()
            .and_then(|digest| digest.peer_addr().cloned())
            .and_then(|addr| addr.as_inet().copied());
        assert_eq!(digest_peer, Some(peer));
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn peek_client_hello_sni_times_out_slow_client_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(&[22]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let started = tokio::time::Instant::now();
        let result = peek_client_hello_sni(
            &server_stream,
            crate::l4_defense::ClientHelloTimeouts {
                total: Duration::from_millis(60),
                idle: Duration::from_millis(30),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            ClientHelloPeek::Incomplete {
                saw_tls_prefix: true
            }
        );
        assert!(started.elapsed() < Duration::from_millis(150));
        client.await.unwrap();
    }

    #[tokio::test]
    async fn peek_client_hello_sni_classifies_plaintext_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
        });

        let (server_stream, _) = listener.accept().await.unwrap();
        let result = peek_client_hello_sni(
            &server_stream,
            crate::l4_defense::client_hello_timeouts(crate::l4_defense::L4PressureLevel::Normal),
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            ClientHelloPeek::NotClientHello {
                plaintext_connect: true
            }
        );
        client.await.unwrap();
    }
}
