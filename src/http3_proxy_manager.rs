use anyhow::{Context, Result};
use bytes::Bytes;
use dashmap::DashMap;
use h3::quic::OpenStreams;
use h3::server::RequestResolver;
use pingora_core::apps::HttpServerApp;
use pingora_core::protocols::http::server::Session as ServerSession;
use pingora_core::server::configuration::ServerConf;
use pingora_proxy::http_proxy_custom;
use quinn::Endpoint;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::{Semaphore, watch};
use tracing::{debug, error, info};

use crate::config::ConfigStore;
use crate::h3_downstream::H3DownstreamSession;
use crate::l4_defense::L4DefenseKind;
use crate::memory_governor::{AdmissionClass, MEMORY_GOVERNOR};
use crate::proxy::EdgeProxy;
use crate::ssl::DynamicCertSelector;

struct ListenerHandle {
    shutdown_tx: watch::Sender<bool>,
}

// EN-15 retry observability: stateless Retry packets issued to unvalidated
// clients, retry() failures, and incoming connections whose address was
// already validated (retry token or NEW_TOKEN). Retry issuance is a normal
// handshake step, not hostile evidence, so it is deliberately NOT recorded
// through record_l4_event (which feeds per-IP auto-block scoring).
static H3_RETRY_ISSUED: AtomicU64 = AtomicU64::new(0);
static H3_RETRY_FAILED: AtomicU64 = AtomicU64::new(0);
static H3_VALIDATED_INCOMING: AtomicU64 = AtomicU64::new(0);
static H3_RETRY_ATTEMPTED: AtomicU64 = AtomicU64::new(0);
static H3_RETRY_LIMITED: AtomicU64 = AtomicU64::new(0);
static H3_IGNORED_INCOMING: AtomicU64 = AtomicU64::new(0);
static H3_REFUSED_INCOMING: AtomicU64 = AtomicU64::new(0);

/// Default node-wide Retry responses/sec ceiling when the policy does
/// not set `retryPps`. One aggregate bucket for the whole node — the
/// XDP dim3 gate is the outer bound; this caps user-space Retry work
/// even on ingress paths that never crossed that gate.
pub const H3_RETRY_DEFAULT_PPS: u64 = 1024;

/// Packed fixed-window budget shared by every H3 listener:
/// (window_epoch_secs << 32) | used. A single compare_exchange reserves
/// one slot, so the ceiling is node-wide and never multiplied by
/// listener/worker count.
static H3_RETRY_WINDOW: AtomicU64 = AtomicU64::new(0);

fn h3_retry_reserve(pps: u64, now_secs: u64) -> bool {
    if pps == 0 {
        return false;
    }
    let mut cur = H3_RETRY_WINDOW.load(Ordering::Relaxed);
    loop {
        let next = if cur >> 32 == now_secs {
            if cur & 0xFFFF_FFFF >= pps {
                return false;
            }
            cur + 1
        } else {
            (now_secs << 32) | 1
        };
        match H3_RETRY_WINDOW.compare_exchange_weak(
            cur,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,
            Err(actual) => cur = actual,
        }
    }
}

pub fn h3_retry_counters() -> (u64, u64, u64, u64, u64, u64, u64) {
    (
        H3_RETRY_ATTEMPTED.load(Ordering::Relaxed),
        H3_RETRY_ISSUED.load(Ordering::Relaxed),
        H3_RETRY_FAILED.load(Ordering::Relaxed),
        H3_RETRY_LIMITED.load(Ordering::Relaxed),
        H3_VALIDATED_INCOMING.load(Ordering::Relaxed),
        H3_IGNORED_INCOMING.load(Ordering::Relaxed),
        H3_REFUSED_INCOMING.load(Ordering::Relaxed),
    )
}

fn h3_retry_required(
    mode: crate::config_models::Http3AddressValidation,
    level: crate::l4_defense::L4PressureLevel,
) -> bool {
    use crate::config_models::Http3AddressValidation::*;
    match mode {
        Always => true,
        Off => false,
        Adaptive => level >= crate::l4_defense::L4PressureLevel::Elevated,
    }
}

pub struct Http3ProxyManager {
    config_store: ConfigStore,
    cert_selector: Arc<DynamicCertSelector>,
    proxy_logic: EdgeProxy,
    server_conf: Arc<ServerConf>,
    handled_ports: DashMap<u16, ListenerHandle>,
}

impl Http3ProxyManager {
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
        let mut reload_generation = self.config_store.runtime_reload_generation();
        loop {
            let desired_ports = self.desired_ports().await;
            for port in &desired_ports {
                self.spawn_listener(*port).await;
            }
            self.reconcile_listeners(&desired_ports);
            reload_generation = self
                .config_store
                .wait_for_runtime_reload(reload_generation)
                .await;
        }
    }

    pub async fn desired_ports(&self) -> HashSet<u16> {
        self.desired_ports_sync()
    }

    pub fn desired_ports_sync(&self) -> HashSet<u16> {
        let mut desired = HashSet::new();
        let Some(policy) = self.config_store.get_global_http3_policy_sync() else {
            return desired;
        };
        if !policy.is_on {
            return desired;
        }

        if policy.port > 0
            && let Ok(port) = u16::try_from(policy.port)
        {
            desired.insert(port);
            return desired;
        }

        for server in self.config_store.get_all_servers_sync() {
            if let Some(https) = &server.https
                && https.is_on
                && !server.is_sni_passthrough()
                && !server.is_quic_passthrough()
                && https.http3_enabled()
            {
                for port in https
                    .listen
                    .iter()
                    .filter_map(|addr| addr.port_range.as_deref())
                    .flat_map(crate::config_models::ports_in_range)
                {
                    desired.insert(port);
                }
            }
        }
        desired
    }

    async fn spawn_listener(self: &Arc<Self>, port: u16) {
        if self.handled_ports.contains_key(&port) {
            return;
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.handled_ports
            .insert(port, ListenerHandle { shutdown_tx });
        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(err) = manager.clone().run_listener(port, shutdown_rx).await {
                error!("HTTP/3 listener on UDP port {} failed: {}", port, err);
            }
            manager.handled_ports.remove(&port);
        });
    }

    fn reconcile_listeners(&self, desired_ports: &HashSet<u16>) {
        let active_ports: Vec<u16> = self
            .handled_ports
            .iter()
            .map(|entry| *entry.key())
            .collect();
        for port in active_ports {
            if desired_ports.contains(&port) {
                continue;
            }
            if let Some((_, handle)) = self.handled_ports.remove(&port) {
                info!(
                    "HTTP/3 Proxy Manager: Stopping listener on UDP port {}",
                    port
                );
                let _ = handle.shutdown_tx.send(true);
            }
        }
    }

    async fn run_listener(
        self: Arc<Self>,
        port: u16,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let server_config = self
            .build_quinn_server_config()
            .await
            .context("build quinn server config")?;
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let endpoint = Endpoint::server(server_config, bind_addr)?;
        info!("HTTP/3 listener active on UDP {}", bind_addr);
        self.run_endpoint(port, endpoint, shutdown_rx).await
    }

    pub async fn run_endpoint(
        self: Arc<Self>,
        port: u16,
        endpoint: Endpoint,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let mut proxy_logic = self.proxy_logic.clone();
        proxy_logic.tls_downstream = true;
        let proxy = Arc::new(http_proxy_custom(
            &self.server_conf,
            proxy_logic,
            crate::origin_h3::OriginH3Connector,
        ));

        loop {
            let connecting = tokio::select! {
                _ = shutdown_rx.changed() => {
                    info!("HTTP/3 listener on UDP port {} shutting down", port);
                    return Ok(());
                }
                incoming = endpoint.accept() => incoming,
            };

            let Some(connecting) = connecting else {
                continue;
            };
            let remote_addr = connecting.remote_address();
            if crate::l4_defense::is_l4_blocked(
                &self.config_store,
                &self.proxy_logic.waf_state,
                remote_addr.ip(),
            ) {
                // Blocked source: explicitly silent — no Retry, no
                // CONNECTION_REFUSED. `Incoming::ignore()` is the
                // no-response API; a bare drop would refuse().
                H3_IGNORED_INCOMING.fetch_add(1, Ordering::Relaxed);
                connecting.ignore();
                continue;
            }

            // EN-15: stateless address validation before any handshake
            // state, admission permits, or tasks are allocated. An
            // unvalidated Initial under the configured policy is answered
            // with a Retry packet; the client completes one round trip and
            // returns with a validated address (quinn guarantees
            // may_retry() whenever remote_address_validated() is false, and
            // enforces anti-amplification internally). A client that
            // answered Retry — or presented a NEW_TOKEN — arrives here with
            // remote_address_validated() == true and is never re-retried,
            // so a valid Retry cannot loop. Post-handshake migration to a
            // new path is validated by quinn's own PATH_CHALLENGE flow and
            // does not re-enter this gate. QUIC passthrough servers never
            // reach this listener (desired_ports excludes them), so no
            // Retry is injected into passthrough traffic.
            if connecting.remote_address_validated() {
                H3_VALIDATED_INCOMING.fetch_add(1, Ordering::Relaxed);
            } else {
                let policy = self.config_store.get_global_http3_policy_sync();
                let mode = policy
                    .as_ref()
                    .map(|p| p.address_validation_mode())
                    .unwrap_or_default();
                if h3_retry_required(mode, crate::l4_defense::current_pressure_level()) {
                    H3_RETRY_ATTEMPTED.fetch_add(1, Ordering::Relaxed);
                    // Aggregate node-wide response budget (dim3 is the
                    // dataplane bound; this bounds user-space Retry work
                    // on ingress that never crossed XDP). Over-budget
                    // Initials are explicitly ignored — refusing would be
                    // another unbudgeted reply.
                    let now_secs = crate::utils::time::now_timestamp() as u64;
                    if !h3_retry_reserve(policy.as_ref().map_or(
                        H3_RETRY_DEFAULT_PPS,
                        |p| p.retry_pps_limit(),
                    ), now_secs)
                    {
                        H3_RETRY_LIMITED.fetch_add(1, Ordering::Relaxed);
                        H3_IGNORED_INCOMING.fetch_add(1, Ordering::Relaxed);
                        connecting.ignore();
                        continue;
                    }
                    match connecting.retry() {
                        Ok(()) => {
                            H3_RETRY_ISSUED.fetch_add(1, Ordering::Relaxed);
                            debug!(
                                "H3 stateless retry issued to {} on UDP port {}",
                                remote_addr, port
                            );
                        }
                        Err(err) => {
                            // Unreachable per quinn's may_retry() guarantee;
                            // the Incoming is consumed either way so no
                            // handshake state is left behind.
                            H3_RETRY_FAILED.fetch_add(1, Ordering::Relaxed);
                            debug!(
                                "H3 retry failed for {} on UDP port {}: {}",
                                remote_addr, port, err
                            );
                        }
                    }
                    continue;
                }
            }
            debug!("HTTP/3 incoming connection on UDP port {}", port);

            let Some(connection_permit) =
                MEMORY_GOVERNOR.try_admit(AdmissionClass::Http3Connection)
            else {
                self.record_l4_event(
                    remote_addr.ip(),
                    L4DefenseKind::H3AdmissionReject,
                    format!("port={} peer={} class=connection", port, remote_addr),
                );
                debug!(
                    "H3 connection admission limit reached, refusing connection from {} on port {}",
                    remote_addr, port
                );
                // Explicit refusal — a validated address gets a definitive
                // CONNECTION_REFUSED instead of an ambiguous timeout.
                H3_REFUSED_INCOMING.fetch_add(1, Ordering::Relaxed);
                connecting.refuse();
                continue;
            };

            // EN-16: listener-pool slot for unattributed H3 traffic.
            let listener_key = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            let Some(listener_permit) =
                MEMORY_GOVERNOR.try_admit_listener(listener_key, AdmissionClass::Http3Connection)
            else {
                self.record_l4_event(
                    remote_addr.ip(),
                    L4DefenseKind::H3AdmissionReject,
                    format!(
                        "port={} peer={} class=connection phase=listener_pool",
                        port, remote_addr
                    ),
                );
                debug!(
                    "H3 listener pool exhausted, refusing connection from {} on port {}",
                    remote_addr, port
                );
                H3_REFUSED_INCOMING.fetch_add(1, Ordering::Relaxed);
                connecting.refuse();
                continue;
            };

            let manager = self.clone();
            let proxy = proxy.clone();
            let shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                let _connection_permit = connection_permit;
                let _listener_permit = listener_permit;
                // Shadow counter for live QUIC connections.
                let _quic_transport = crate::metrics::transport_metrics_guard(
                    crate::metrics::ShadowTransportKind::QuicConnection,
                );
                if let Err(err) = manager
                    .serve_connection(connecting, port, proxy, shutdown)
                    .await
                {
                    debug!(
                        "HTTP/3 connection handling failed on port {}: {}",
                        port, err
                    );
                }
            });
        }
    }

    pub async fn build_quinn_server_config(&self) -> Result<quinn::ServerConfig> {
        self.build_quinn_server_config_scoped(false).await
    }

    /// `af_xdp_scoped` — the endpoint is fed exclusively by the AF_XDP
    /// UDP demux (SharedQuinnUdpSocket); only then does the XDP
    /// transport policy apply to its connections.
    pub async fn build_quinn_server_config_scoped(
        &self,
        af_xdp_scoped: bool,
    ) -> Result<quinn::ServerConfig> {
        let mut rustls_config = crate::ssl::build_rustls_server_config(
            Arc::clone(&self.cert_selector),
            vec![b"h3".to_vec()],
            true,
        )
        .context("build HTTP/3 rustls server config")?;
        rustls_config.max_early_data_size = 0;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_config))?,
        ));
        let per_conn_limit = MEMORY_GOVERNOR.h3_request_limit_per_connection();
        if let Some(transport_config) = Arc::get_mut(&mut server_config.transport) {
            *transport_config = crate::quic_transport::tuned_transport_config(None);
            // T5: an AF_XDP-scoped endpoint (demux-fed only) runs the
            // policy-selected controller; the kernel-socket listener
            // keeps quinn's stock controller — non-XDP contract
            // unchanged (§A.4).
            #[cfg(target_os = "linux")]
            if af_xdp_scoped
                && let Some(factory) = crate::xdp::xdp_quic_cc_factory()
            {
                transport_config.congestion_controller_factory(factory);
            }
            let stream_cap = per_conn_limit.min(u32::MAX as usize) as u32;
            let uni_cap = stream_cap.clamp(32, 256);
            transport_config.max_concurrent_bidi_streams(stream_cap.into());
            transport_config.max_concurrent_uni_streams(uni_cap.into());
        }
        Ok(server_config)
    }

    async fn serve_connection(
        self: Arc<Self>,
        connecting: quinn::Incoming,
        listen_port: u16,
        proxy: Arc<pingora_proxy::HttpProxy<EdgeProxy, crate::origin_h3::OriginH3Connector>>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let conn = connecting.await?;
        let remote_addr = conn.remote_address();
        debug!(
            "HTTP/3 connection accepted on port {} from {}",
            listen_port, remote_addr
        );
        let mut h3_conn = h3::server::builder()
            .build(h3_quinn::Connection::new(conn))
            .await?;
        let per_connection_limit = MEMORY_GOVERNOR.h3_request_limit_per_connection().max(1);
        let stream_semaphore = Arc::new(Semaphore::new(per_connection_limit));
        debug!(
            "HTTP/3 connection ready on port {} from {}",
            listen_port, remote_addr
        );

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let Ok(stream_permit) = stream_semaphore.clone().try_acquire_owned() else {
                        self.record_l4_event(
                            remote_addr.ip(),
                            L4DefenseKind::H3AdmissionReject,
                            format!(
                                "port={} peer={} class=per_connection_stream limit={}",
                                listen_port, remote_addr, per_connection_limit
                            ),
                        );
                        debug!(
                            "HTTP/3 per-connection stream limit reached on port {} from {}",
                            listen_port, remote_addr
                        );
                        continue;
                    };
                    let Some(request_permit) =
                        MEMORY_GOVERNOR.try_admit(AdmissionClass::Http3Request)
                    else {
                        self.record_l4_event(
                            remote_addr.ip(),
                            L4DefenseKind::H3AdmissionReject,
                            format!(
                                "port={} peer={} class=request_pre_spawn",
                                listen_port, remote_addr
                            ),
                        );
                        debug!(
                            "HTTP/3 request admission limit reached before spawn on port {} from {}",
                            listen_port, remote_addr
                        );
                        continue;
                    };
                    debug!(
                        "HTTP/3 request stream accepted on port {} from {}",
                        listen_port, remote_addr
                    );
                    let manager = self.clone();
                    let proxy = proxy.clone();
                    let shutdown = shutdown_rx.clone();
                    tokio::spawn(async move {
                        let _stream_permit = stream_permit;
                        if let Err(err) = manager
                            .handle_request(
                                resolver,
                                listen_port,
                                remote_addr,
                                proxy,
                                shutdown,
                                request_permit,
                            )
                            .await
                        {
                            debug!(
                                "HTTP/3 request handling failed on port {}: {}",
                                listen_port, err
                            );
                        }
                    });
                }
                Ok(None) => return Ok(()),
                Err(err) => {
                    debug!(
                        "HTTP/3 accept loop terminated on port {}: {}",
                        listen_port, err
                    );
                    return Ok(());
                }
            }
        }
    }

    async fn handle_request<C>(
        &self,
        resolver: RequestResolver<C, Bytes>,
        listen_port: u16,
        remote_addr: SocketAddr,
        proxy: Arc<pingora_proxy::HttpProxy<EdgeProxy, crate::origin_h3::OriginH3Connector>>,
        shutdown_rx: watch::Receiver<bool>,
        _request_permit: crate::memory_governor::StaticAdmissionPermit,
    ) -> Result<()>
    where
        C: h3::quic::Connection<Bytes> + Send + 'static,
        <C as OpenStreams<Bytes>>::BidiStream: h3::quic::BidiStream<Bytes> + Send + 'static,
    {
        let (request, mut stream) = resolver.resolve_request().await?;
        let host = Self::request_host(&request, listen_port)
            .context("missing host/authority in HTTP/3 request")?;
        debug!(
            "HTTP/3 request resolved on port {} from {} host={} path={}",
            listen_port,
            remote_addr,
            host,
            request.uri().path()
        );
        let server = self
            .config_store
            .get_l7_server_for_tls_name_sync(authority_host_for_lookup(&host).as_str());
        if !server
            .as_ref()
            .is_some_and(|server| self.server_accepts_http3(server, listen_port))
        {
            let response = http::Response::builder().status(421).body(())?;
            stream.send_response(response).await?;
            stream
                .send_data(Bytes::from_static(b"HTTP/3 is not available for this host"))
                .await?;
            stream.finish().await?;
            return Ok(());
        }
        if self.should_reject_mobile_h3(&request) {
            let response = http::Response::builder().status(421).body(())?;
            stream.send_response(response).await?;
            stream
                .send_data(Bytes::from_static(
                    b"HTTP/3 is not available for this client",
                ))
                .await?;
            stream.finish().await?;
            return Ok(());
        }
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port);
        let h3_session = H3DownstreamSession::new(request, stream, remote_addr, local_addr)?;
        let server_session = ServerSession::new_custom(Box::new(h3_session));
        proxy.process_new_http(server_session, &shutdown_rx).await;
        Ok(())
    }

    fn server_accepts_http3(&self, server: &crate::config_models::ServerConfig, port: u16) -> bool {
        if self
            .config_store
            .get_global_http3_policy_sync()
            .is_some_and(|policy| policy.is_on && u16::try_from(policy.port).ok() == Some(port))
        {
            return server.https.as_ref().is_some_and(|https| https.is_on);
        }
        server.http3_enabled()
    }

    fn should_reject_mobile_h3(&self, request: &http::Request<()>) -> bool {
        let Some(policy) = self.config_store.get_global_http3_policy_sync() else {
            return false;
        };
        if !policy.is_on || policy.support_mobile_browsers {
            return false;
        }
        let user_agent = request
            .headers()
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        crate::proxy::EdgeProxy::is_mobile_user_agent(user_agent)
    }

    fn request_host(request: &http::Request<()>, listen_port: u16) -> Option<String> {
        if let Some(authority) = request.uri().authority() {
            return Some(authority.as_str().to_string());
        }
        let host = request.headers().get("host")?.to_str().ok()?.to_string();
        if host.contains(':') || listen_port == 443 {
            Some(host)
        } else {
            Some(format!("{}:{}", host, listen_port))
        }
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
}

fn authority_host_for_lookup(authority: &str) -> String {
    authority_host_for_resolve(authority)
}

fn authority_host_for_resolve(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_string();
    }
    if authority.matches(':').count() == 1
        && let Some((host, _)) = authority.rsplit_once(':')
    {
        return host.to_string();
    }
    authority.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::Http3AddressValidation;
    use crate::l4_defense::L4PressureLevel;

    #[test]
    fn h3_retry_required_matrix() {
        for level in [
            L4PressureLevel::Normal,
            L4PressureLevel::Elevated,
            L4PressureLevel::High,
            L4PressureLevel::Critical,
        ] {
            assert!(h3_retry_required(Http3AddressValidation::Always, level));
            assert!(!h3_retry_required(Http3AddressValidation::Off, level));
        }
        assert!(!h3_retry_required(
            Http3AddressValidation::Adaptive,
            L4PressureLevel::Normal
        ));
        for level in [
            L4PressureLevel::Elevated,
            L4PressureLevel::High,
            L4PressureLevel::Critical,
        ] {
            assert!(h3_retry_required(Http3AddressValidation::Adaptive, level));
        }
    }

    #[derive(Debug)]
    struct NoVerifier;

    impl rustls::client::danger::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
            ]
        }
    }

    fn test_server_config() -> quinn::ServerConfig {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let certs = rustls_pemfile::certs(
            &mut include_bytes!("../pingora-main/pingora-core/examples/keys/server/cert.pem")
                .as_slice(),
        )
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(
            &mut include_bytes!("../pingora-main/pingora-core/examples/keys/server/key.pem")
                .as_slice(),
        )
        .unwrap()
        .unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::clone_key(&key))
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap(),
        ))
    }

    fn test_client_endpoint() -> quinn::Endpoint {
        let mut tls = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).unwrap(),
        ));
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    // EN-15: a real Retry round trip must terminate — the client returns
    // with a validated address and is accepted without a second retry, and
    // a subsequent connection is validated immediately via NEW_TOKEN.
    #[tokio::test]
    async fn h3_retry_roundtrip_validates_without_loop() {
        let endpoint =
            Endpoint::server(test_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let retries = Arc::new(AtomicU64::new(0));
        let validated = Arc::new(AtomicU64::new(0));
        let server = {
            let retries = retries.clone();
            let validated = validated.clone();
            tokio::spawn(async move {
                let mut accepted = 0u32;
                while accepted < 2 {
                    let Some(incoming) = endpoint.accept().await else {
                        break;
                    };
                    if !incoming.remote_address_validated() {
                        assert!(incoming.may_retry());
                        incoming.retry().expect("retry must be legal");
                        retries.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    validated.fetch_add(1, Ordering::Relaxed);
                    match incoming.await {
                        Ok(conn) => {
                            accepted += 1;
                            conn.closed().await;
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        let client = test_client_endpoint();
        for _ in 0..2 {
            let conn = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                client.connect(addr, "localhost").unwrap(),
            )
            .await
            .expect("connect timed out")
            .expect("connect failed");
            conn.close(0u32.into(), b"done");
            conn.closed().await;
        }
        client.wait_idle().await;
        tokio::time::timeout(std::time::Duration::from_secs(10), server)
            .await
            .expect("server task timed out")
            .expect("server task panicked");
        // First connection: one Retry then a validated retry-token Initial.
        // Second connection: validated immediately via NEW_TOKEN — no Retry.
        assert_eq!(retries.load(Ordering::Relaxed), 1);
        assert_eq!(validated.load(Ordering::Relaxed), 2);
    }

    // EN-15 R3: the aggregate Retry budget is a hard ceiling — reserves
    // stop at pps per window, a later window refills, and pps=0 disables
    // issuance entirely.
    #[test]
    fn h3_retry_budget_bounded() {
        let t0 = 1_700_000_000u64;
        assert!(h3_retry_reserve(2, t0));
        assert!(h3_retry_reserve(2, t0));
        assert!(!h3_retry_reserve(2, t0));
        // Same-window calls stay exhausted; a new window refills.
        assert!(!h3_retry_reserve(2, t0));
        assert!(h3_retry_reserve(2, t0 + 1));
        // pps=0 disables issuance.
        assert!(!h3_retry_reserve(0, t0 + 2));
    }

    // EN-15 R3 wire contract: `ignore()` sends NOTHING — the client sees
    // a handshake stall (elapsed timeout), never a refusal. Verified
    // against real quinn endpoints so wire behavior is observed, not
    // inferred from API names.
    #[tokio::test]
    async fn h3_incoming_ignore_is_silent() {
        let endpoint =
            Endpoint::server(test_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if let Some(incoming) = endpoint.accept().await {
                incoming.ignore();
            }
        });
        let client = test_client_endpoint();
        let stalled = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.connect(addr, "localhost").unwrap(),
        )
        .await;
        // Outer Err = the tokio timeout elapsed — no Retry and no
        // CONNECTION_REFUSED ever reached the client.
        assert!(stalled.is_err(), "ignored Initial must stall: {stalled:?}");
        client.wait_idle().await;
        server.abort();
    }

    // `refuse()` produces a prompt CONNECTION_REFUSED — the inner connect
    // fails fast rather than stalling.
    #[tokio::test]
    async fn h3_incoming_refuse_is_prompt() {
        let endpoint =
            Endpoint::server(test_server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                incoming.refuse();
            }
        });
        let client = test_client_endpoint();
        let refused = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client.connect(addr, "localhost").unwrap(),
        )
        .await
        .expect("refused connect timed out — refuse() did not answer");
        assert!(refused.is_err(), "refused connect should fail");
        client.wait_idle().await;
        server.abort();
    }

    async fn test_manager(
        policy: crate::config_models::HTTP3Policy,
    ) -> Arc<Http3ProxyManager> {
        let store = crate::config::ConfigStore::new();
        store.test_set_http3_policy(policy);
        let cert_selector = Arc::new(DynamicCertSelector::new());
        crate::ssl::sync_certs(
            &cert_selector,
            &[crate::config_models::SSLCertConfig {
                id: 1,
                is_on: true,
                is_default: true,
                cert_data_json: Some(serde_json::json!(include_str!(
                    "../pingora-main/pingora-core/examples/keys/server/cert.pem"
                ))),
                key_data_json: Some(serde_json::json!(include_str!(
                    "../pingora-main/pingora-core/examples/keys/server/key.pem"
                ))),
                dns_names: vec!["localhost".to_string()],
            }],
        )
        .await;
        let api_config = Arc::new(crate::api_config::ApiConfig {
            rpc_endpoints: Vec::new(),
            rpc_disable_update: true,
            node_id: "1".to_string(),
            secret: "h3-test".to_string(),
            billing_count_inbound_traffic: false,
            access_log_pipeline:
                crate::api_config::AccessLogPipelineConfig::default(),
            relay: crate::api_config::RelayConfig::default(),
            kernel_tuning: crate::api_config::KernelTuningConfig::default(),
        });
        let waf_state = Arc::new(crate::firewall::state::WafStateManager::new());
        let proxy_logic = crate::proxy::EdgeProxy {
            config: Arc::new(store.clone()),
            waf_state: waf_state.clone(),
            api_config: api_config.clone(),
            cert_selector: cert_selector.clone(),
            waf_verifier: Arc::new(crate::firewall::verifier::WafVerifier::new(
                &api_config.secret,
            )),
            tls_downstream: false,
        };
        Http3ProxyManager::new(
            store,
            cert_selector,
            proxy_logic,
            Arc::new(ServerConf::default()),
        )
    }

    // EN-15 R3: the PRODUCTION accept loop (run_endpoint) — not a
    // reimplemented fixture. With policy `always` + retryPps=1, the first
    // client is Retried once then validated and accepted; after the
    // policy switches to retryPps=0 a second, fresh-endpoint client is
    // explicitly ignored (no response, connect stalls).
    #[tokio::test]
    async fn h3_run_endpoint_retry_gate_and_budget() {
        let attempted0 = H3_RETRY_ATTEMPTED.load(Ordering::Relaxed);
        let issued0 = H3_RETRY_ISSUED.load(Ordering::Relaxed);
        let manager = test_manager(crate::config_models::HTTP3Policy {
            is_on: true,
            port: 0,
            address_validation: "always".to_string(),
            retry_pps: Some(1),
            ..Default::default()
        })
        .await;
        let server_config = manager.build_quinn_server_config().await.unwrap();
        let endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let runner = {
            let manager = manager.clone();
            tokio::spawn(async move { manager.run_endpoint(addr.port(), endpoint, rx).await })
        };

        // First client: Retry issued under the aggregate budget, then the
        // returning validated Initial is accepted end-to-end.
        let client = test_client_endpoint();
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.connect(addr, "localhost").unwrap(),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed");
        conn.close(0u32.into(), b"done");
        assert!(H3_RETRY_ATTEMPTED.load(Ordering::Relaxed) > attempted0);
        assert!(H3_RETRY_ISSUED.load(Ordering::Relaxed) > issued0);

        // Budget now disables issuance (retryPps=0): a fresh unvalidated
        // endpoint is explicitly ignored — connect stalls with no reply.
        manager.config_store.test_set_http3_policy(
            crate::config_models::HTTP3Policy {
                is_on: true,
                port: 0,
                address_validation: "always".to_string(),
                retry_pps: Some(0),
                ..Default::default()
            },
        );
        let ignored0 = H3_IGNORED_INCOMING.load(Ordering::Relaxed);
        let limited0 = H3_RETRY_LIMITED.load(Ordering::Relaxed);
        let client2 = test_client_endpoint();
        let stalled = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            client2.connect(addr, "localhost").unwrap(),
        )
        .await;
        assert!(stalled.is_err(), "over-budget Initial must be ignored");
        assert!(H3_RETRY_LIMITED.load(Ordering::Relaxed) > limited0);
        assert!(H3_IGNORED_INCOMING.load(Ordering::Relaxed) > ignored0);

        client.wait_idle().await;
        client2.wait_idle().await;
        runner.abort();
    }
}
