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
        loop {
            let desired_ports = self.desired_ports().await;
            for port in &desired_ports {
                self.spawn_listener(*port).await;
            }
            self.reconcile_listeners(&desired_ports);
            self.config_store.wait_for_runtime_reload().await;
        }
    }

    pub async fn desired_ports(&self) -> HashSet<u16> {
        let mut desired = HashSet::new();
        let Some(policy) = self.config_store.get_global_http3_policy_sync() else {
            return desired;
        };
        if !policy.is_on {
            return desired;
        }

        if policy.port > 0 {
            if let Ok(port) = u16::try_from(policy.port) {
                desired.insert(port);
                return desired;
            }
        }

        for server in self.config_store.get_all_servers().await {
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
                continue;
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
                    "H3 connection admission limit reached, rejecting connection from {} on port {}",
                    remote_addr, port
                );
                continue;
            };

            let manager = self.clone();
            let proxy = proxy.clone();
            let shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                let _connection_permit = connection_permit;
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
        let mut rustls_config = crate::ssl::build_rustls_server_config(
            Arc::clone(&self.cert_selector),
            vec![b"h3".to_vec()],
            true,
        )
        .context("build HTTP/3 rustls server config")?;
        rustls_config.max_early_data_size = u32::MAX;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_config))?,
        ));
        let per_conn_limit = MEMORY_GOVERNOR.h3_request_limit_per_connection();
        if let Some(transport_config) = Arc::get_mut(&mut server_config.transport) {
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
