use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Buf, Bytes};
use dashmap::DashMap;
use h3::quic::OpenStreams;
use h3::server::RequestResolver;
use quinn::Endpoint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::config::ConfigStore;
use crate::ssl::DynamicCertSelector;

struct ListenerHandle {
    cert_hash: u64,
    shutdown_tx: watch::Sender<bool>,
}

pub struct Http3ProxyManager {
    config_store: ConfigStore,
    cert_selector: Arc<DynamicCertSelector>,
    handled_ports: DashMap<u16, ListenerHandle>,
}

impl Http3ProxyManager {
    pub fn new(config_store: ConfigStore, cert_selector: Arc<DynamicCertSelector>) -> Arc<Self> {
        Arc::new(Self {
            config_store,
            cert_selector,
            handled_ports: DashMap::new(),
        })
    }

    pub async fn start_listeners(self: Arc<Self>) {
        loop {
            let desired_ports = self.desired_ports().await;
            let cert_hash = self.current_cert_hash().await;
            for port in &desired_ports {
                self.spawn_listener(*port, cert_hash).await;
            }
            self.reconcile_listeners(&desired_ports, cert_hash);
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    async fn desired_ports(&self) -> HashSet<u16> {
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
                && https.http3_enabled()
            {
                for addr in &https.listen {
                    if let Some(port_str) = &addr.port_range
                        && let Some(first) = port_str.split('-').next()
                        && let Ok(port) = first.parse::<u16>()
                    {
                        desired.insert(port);
                    }
                }
            }
        }
        desired
    }

    async fn spawn_listener(self: &Arc<Self>, port: u16, cert_hash: u64) {
        if let Some(existing) = self.handled_ports.get(&port) {
            if existing.cert_hash == cert_hash {
                return;
            }
            let _ = existing.shutdown_tx.send(true);
            drop(existing);
            self.handled_ports.remove(&port);
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.handled_ports
            .insert(port, ListenerHandle { cert_hash, shutdown_tx });
        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(err) = manager.clone().run_listener(port, shutdown_rx).await {
                error!("HTTP/3 listener on UDP port {} failed: {}", port, err);
            }
            manager.handled_ports.remove(&port);
        });
    }

    fn reconcile_listeners(&self, desired_ports: &HashSet<u16>, cert_hash: u64) {
        let active_ports: Vec<(u16, u64)> = self
            .handled_ports
            .iter()
            .map(|entry| (*entry.key(), entry.value().cert_hash))
            .collect();
        for (port, active_hash) in active_ports {
            if desired_ports.contains(&port) && active_hash == cert_hash {
                continue;
            }
            if let Some((_, handle)) = self.handled_ports.remove(&port) {
                info!("HTTP/3 Proxy Manager: Stopping listener on UDP port {}", port);
                let _ = handle.shutdown_tx.send(true);
            }
        }
    }

    async fn run_listener(
        self: Arc<Self>,
        port: u16,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let server_config = self
            .build_quinn_server_config()
            .await
            .context("build quinn server config")?;
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let endpoint = Endpoint::server(server_config, bind_addr)?;
        info!("HTTP/3 listener active on UDP {}", bind_addr);

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

            let config_store = self.config_store.clone();
            tokio::spawn(async move {
                if let Err(err) = Self::serve_connection(connecting, port, config_store).await {
                    error!("HTTP/3 connection handling failed on port {}: {}", port, err);
                }
            });
        }
    }

    async fn build_quinn_server_config(&self) -> Result<quinn::ServerConfig> {
        let (exact, wildcard, default_pair) = self
            .cert_selector
            .export_snapshot_pem()
            .await
            .context("no certificate snapshot available for HTTP/3")?;

        let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
        for (name, (cert_pem, key_pem, ocsp)) in exact {
            if let Some(certified_key) = Self::build_certified_key(&cert_pem, &key_pem, &ocsp)? {
                let _ = resolver.add(&name, certified_key);
            }
        }
        for (name, (cert_pem, key_pem, ocsp)) in wildcard {
            if let Some(certified_key) = Self::build_certified_key(&cert_pem, &key_pem, &ocsp)? {
                let _ = resolver.add(&name, certified_key);
            }
        }

        let default_key = Self::build_certified_key(&default_pair.0, &default_pair.1, &default_pair.2)?
            .context("failed to build default HTTP/3 certified key")?;
        let mut rustls_config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FallbackResolver {
                sni: resolver,
                default: Arc::new(default_key),
            }));
        rustls_config.alpn_protocols = vec![b"h3".to_vec()];
        rustls_config.max_early_data_size = u32::MAX;

        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_config))?));
        let transport = Arc::get_mut(&mut server_config.transport)
            .context("unable to access quinn transport config")?;
        transport.max_concurrent_uni_streams(16_u8.into());
        Ok(server_config)
    }

    fn build_certified_key(
        cert_pem: &[u8],
        key_pem: &[u8],
        ocsp: &[u8],
    ) -> Result<Option<rustls::sign::CertifiedKey>> {
        let mut cert_reader = std::io::BufReader::new(cert_pem);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<_, _>>()?;
        if certs.is_empty() {
            return Ok(None);
        }

        let mut key_reader = std::io::BufReader::new(key_pem);
        let key: PrivateKeyDer<'static> = match rustls_pemfile::private_key(&mut key_reader)? {
            Some(key) => key,
            None => return Ok(None),
        };
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)?;
        let mut certified = rustls::sign::CertifiedKey::new(certs, signing_key);
        if !ocsp.is_empty() {
            certified.ocsp = Some(ocsp.to_vec());
        }
        Ok(Some(certified))
    }

    async fn current_cert_hash(&self) -> u64 {
        let Some((exact, wildcard, default_pair)) = self.cert_selector.export_snapshot_pem().await else {
            return 0;
        };
        let mut hasher = DefaultHasher::new();
        let mut exact_entries = exact.into_iter().collect::<Vec<_>>();
        exact_entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, (cert, key, ocsp)) in exact_entries {
            name.hash(&mut hasher);
            cert.hash(&mut hasher);
            key.hash(&mut hasher);
            ocsp.hash(&mut hasher);
        }
        let mut wildcard_entries = wildcard.into_iter().collect::<Vec<_>>();
        wildcard_entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, (cert, key, ocsp)) in wildcard_entries {
            name.hash(&mut hasher);
            cert.hash(&mut hasher);
            key.hash(&mut hasher);
            ocsp.hash(&mut hasher);
        }
        default_pair.0.hash(&mut hasher);
        default_pair.1.hash(&mut hasher);
        default_pair.2.hash(&mut hasher);
        hasher.finish()
    }

    async fn serve_connection(
        connecting: quinn::Incoming,
        listen_port: u16,
        config_store: ConfigStore,
    ) -> Result<()> {
        let conn = connecting.await?;
        let remote_addr = conn.remote_address();
        let mut h3_conn = h3::server::builder()
            .build(h3_quinn::Connection::new(conn))
            .await?;

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let config_store = config_store.clone();
                    tokio::spawn(async move {
                        if let Err(err) = Self::handle_request(resolver, listen_port, remote_addr, config_store).await {
                            error!("HTTP/3 request handling failed on port {}: {}", listen_port, err);
                        }
                    });
                }
                Ok(None) => return Ok(()),
                Err(err) => {
                    warn!("HTTP/3 accept loop terminated on port {}: {}", listen_port, err);
                    return Ok(());
                }
            }
        }
    }

    async fn handle_request<C>(
        resolver: RequestResolver<C, Bytes>,
        listen_port: u16,
        remote_addr: SocketAddr,
        config_store: ConfigStore,
    ) -> Result<()>
    where
        C: h3::quic::Connection<Bytes> + Send + 'static,
        <C as OpenStreams<Bytes>>::BidiStream: Send + 'static,
    {
        let (request, mut stream) = resolver.resolve_request().await?;
        let host = Self::request_host(&request, listen_port)
            .context("missing host/authority in HTTP/3 request")?;
        if config_store
            .get_server_for_tls_name_sync(host.split(':').next().unwrap_or(&host))
            .is_some_and(|server| server.is_sni_passthrough())
        {
            let response = http::Response::builder().status(421).body(())?;
            stream.send_response(response).await?;
            stream
                .send_data(Bytes::from_static(b"HTTP/3 is not available for this host"))
                .await?;
            stream.finish().await?;
            return Ok(());
        }
        let target_port = request
            .uri()
            .port_u16()
            .unwrap_or(listen_port);
        let path_and_query = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            while chunk.has_remaining() {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                body.extend_from_slice(&bytes);
            }
        }

        let target_url = if host.contains(':') {
            format!("https://{}{}", host, path_and_query)
        } else {
            format!("https://{}:{}{}", host, target_port, path_and_query)
        };

        let mut client_builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(120))
            .resolve(&host, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), target_port));
        if target_port == 443 {
            client_builder = client_builder.resolve(
                &host,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            );
        }
        let client = client_builder.build()?;

        let mut outbound = client.request(request.method().clone(), &target_url);
        outbound = outbound.header("host", host.as_str());
        outbound = outbound.header("x-forwarded-proto", "https");
        outbound = outbound.header("x-cloud-http3-bridge", "1");
        outbound = outbound.header("x-cloud-real-ip", remote_addr.ip().to_string());
        outbound = outbound.header("x-cloud-real-port", remote_addr.port().to_string());
        for (name, value) in request.headers() {
            if matches!(
                name.as_str(),
                "host"
                    | "content-length"
                    | "connection"
                    | "transfer-encoding"
                    | "x-cloud-real-ip"
                    | "x-cloud-real-port"
                    | "x-cloud-http3-bridge"
            ) {
                continue;
            }
            outbound = outbound.header(name, value);
        }
        if !body.is_empty() {
            outbound = outbound.body(body);
        }

        match outbound.send().await {
            Ok(response) => {
                let status = response.status();
                let headers = response.headers().clone();
                let response_body = response.bytes().await.unwrap_or_default();

                let mut builder = http::Response::builder().status(status);
                for (name, value) in &headers {
                    if matches!(name.as_str(), "connection" | "transfer-encoding") {
                        continue;
                    }
                    builder = builder.header(name, value);
                }
                let response = builder.body(())?;
                stream.send_response(response).await?;
                if !response_body.is_empty() {
                    stream.send_data(response_body).await?;
                }
                stream.finish().await?;
            }
            Err(err) => {
                warn!("HTTP/3 bridge upstream request failed: {}", err);
                let response = http::Response::builder().status(502).body(())?;
                stream.send_response(response).await?;
                stream
                    .send_data(Bytes::from_static(b"Bad Gateway"))
                    .await?;
                stream.finish().await?;
            }
        }

        Ok(())
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
}

#[derive(Debug)]
struct FallbackResolver {
    sni: rustls::server::ResolvesServerCertUsingSni,
    default: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for FallbackResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.sni
            .resolve(client_hello)
            .or_else(|| Some(self.default.clone()))
    }
}
