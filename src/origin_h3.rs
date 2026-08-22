use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr as StdSocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::Stream;
use h3::error::Code;
use http::{HeaderMap, Response, Version};
use pingora_core::connectors::http::custom::{Connection, Connector as CustomConnector};
use pingora_core::protocols::http::custom::client::Session as CustomClientSession;
use pingora_core::protocols::http::custom::{BodyWrite, CustomMessageWrite};
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_core::protocols::{Digest, UniqueIDType};
use pingora_core::upstreams::peer::Peer;
use pingora_core::{Error, ErrorType, Result as PingoraResult};
use pingora_http::{RequestHeader, ResponseHeader};
use quinn::{ClientConfig, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::sync::Mutex;

use crate::origin_h3_state::{ORIGIN_H3_STATE_MANAGER, OriginH3Key};

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Clone, Default)]
pub struct OriginH3Connector;

#[async_trait]
impl CustomConnector for OriginH3Connector {
    type Session = OriginH3ClientSession;

    async fn get_http_session<P: Peer + Send + Sync + 'static>(
        &self,
        peer: &P,
    ) -> PingoraResult<(Connection<Self::Session>, bool)> {
        let key = origin_h3_key(peer);
        match connect_h3(peer, key.clone()).await {
            Ok(session) => {
                ORIGIN_H3_STATE_MANAGER.record_success(key);
                Ok((Connection::Session(session), false))
            }
            Err(err) => {
                ORIGIN_H3_STATE_MANAGER.record_failure(key);
                Err(err)
            }
        }
    }

    async fn reused_http_session<P: Peer + Send + Sync + 'static>(
        &self,
        peer: &P,
    ) -> Option<Self::Session> {
        let key = origin_h3_key(peer);
        let (endpoint, connection) = crate::origin_h3_pool::take(&key)?;
        build_h3_session(peer, key, endpoint, connection).await.ok()
    }

    async fn release_http_session<P: Peer + Send + Sync + 'static>(
        &self,
        mut session: Self::Session,
        peer: &P,
        _idle_timeout: Option<Duration>,
    ) {
        let _ = session.finish_custom().await;
        if session.can_reuse_connection() {
            let key = origin_h3_key(peer);
            crate::origin_h3_pool::offer(key, session._endpoint, session._connection);
        }
    }
}

pub struct OriginH3ClientSession {
    send_request: Arc<Mutex<H3SendRequest>>,
    request_stream: Option<Arc<Mutex<H3RequestStream>>>,
    response_header: Option<ResponseHeader>,
    response_finished: bool,
    request_body_finished: bool,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    digest: Digest,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    _endpoint: Endpoint,
    _connection: quinn::Connection,
}

impl OriginH3ClientSession {
    fn can_reuse_connection(&self) -> bool {
        self._connection.close_reason().is_none()
            && self.request_body_finished
            && self.request_stream.is_none()
    }
}

async fn connect_h3<P: Peer + Send + Sync + 'static>(
    peer: &P,
    key: OriginH3Key,
) -> PingoraResult<OriginH3ClientSession> {
    if let Some((endpoint, connection)) = crate::origin_h3_pool::take(&key) {
        return build_h3_session(peer, key, endpoint, connection).await;
    }

    let Some(server_addr) = peer.address().as_inet().copied() else {
        return Error::e_explain(
            ErrorType::ConnectError,
            "HTTP/3 origin requires an IP socket address",
        );
    };

    let bind_addr = match server_addr.ip() {
        IpAddr::V4(_) => StdSocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => StdSocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let mut endpoint = Endpoint::client(bind_addr).map_err(|err| {
        Error::explain(
            ErrorType::ConnectError,
            format!("creating H3 endpoint: {err}"),
        )
    })?;
    endpoint.set_default_client_config(client_config(peer.verify_cert())?);

    let sni = peer.sni();
    let connecting = endpoint.connect(server_addr, sni).map_err(|err| {
        Error::explain(
            ErrorType::ConnectError,
            format!("starting H3 connect: {err}"),
        )
    })?;
    let connection = match peer.connection_timeout() {
        Some(timeout) => tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| {
                Error::explain(ErrorType::ConnectTimedout, "connecting to HTTP/3 origin")
            })?,
        None => connecting.await,
    }
    .map_err(|err| {
        Error::explain(
            ErrorType::ConnectError,
            format!("connecting to HTTP/3 origin: {err}"),
        )
    })?;

    build_h3_session(peer, key, endpoint, connection).await
}

async fn build_h3_session<P: Peer + Send + Sync + 'static>(
    peer: &P,
    _key: OriginH3Key,
    endpoint: Endpoint,
    connection: quinn::Connection,
) -> PingoraResult<OriginH3ClientSession> {
    let Some(server_addr) = peer.address().as_inet().copied() else {
        return Error::e_explain(
            ErrorType::ConnectError,
            "HTTP/3 origin requires an IP socket address",
        );
    };
    let local_addr = endpoint
        .local_addr()
        .unwrap_or_else(|_| StdSocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let h3_conn = h3_quinn::Connection::new(connection.clone());
    let (mut driver, send_request) = h3::client::builder().build(h3_conn).await.map_err(|err| {
        Error::explain(
            ErrorType::ConnectError,
            format!("starting H3 client: {err}"),
        )
    })?;
    tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    Ok(OriginH3ClientSession {
        send_request: Arc::new(Mutex::new(send_request)),
        request_stream: None,
        response_header: None,
        response_finished: false,
        request_body_finished: false,
        read_timeout: peer.get_peer_options().and_then(|opts| opts.read_timeout),
        write_timeout: peer.get_peer_options().and_then(|opts| opts.write_timeout),
        digest: Digest::default(),
        server_addr: server_addr.into(),
        client_addr: local_addr.into(),
        _endpoint: endpoint,
        _connection: connection,
    })
}

fn client_config(verify_cert: bool) -> PingoraResult<ClientConfig> {
    let mut crypto = if verify_cert {
        let mut roots = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        for cert in certs.certs {
            let _ = roots.add(cert);
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth()
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|err| {
        Error::explain(
            ErrorType::ConnectError,
            format!("building H3 TLS config: {err}"),
        )
    })?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(crate::tls_crypto::default_crypto_provider())))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[async_trait]
impl CustomClientSession for OriginH3ClientSession {
    async fn write_request_header(
        &mut self,
        req: Box<RequestHeader>,
        end: bool,
    ) -> PingoraResult<()> {
        let request = build_h3_request(&req)?;
        let mut send_request = self.send_request.lock().await;
        let stream = match self.write_timeout {
            Some(timeout) => tokio::time::timeout(timeout, send_request.send_request(request))
                .await
                .map_err(|_| {
                    Error::explain(ErrorType::WriteTimedout, "sending HTTP/3 request header")
                })?,
            None => send_request.send_request(request).await,
        }
        .map_err(|err| {
            Error::explain(
                ErrorType::WriteError,
                format!("sending HTTP/3 request header: {err}"),
            )
        })?;
        drop(send_request);

        let stream = Arc::new(Mutex::new(stream));
        if end {
            finish_h3_body(stream.clone(), self.write_timeout).await?;
            self.request_body_finished = true;
        }
        self.request_stream = Some(stream);
        Ok(())
    }

    async fn write_request_body(&mut self, data: Bytes, end: bool) -> PingoraResult<()> {
        let Some(stream) = self.request_stream.as_ref().cloned() else {
            return Error::e_explain(
                ErrorType::WriteError,
                "HTTP/3 request stream is not initialized",
            );
        };
        write_h3_body(stream, data, end, self.write_timeout).await
    }

    async fn finish_request_body(&mut self) -> PingoraResult<()> {
        if self.request_body_finished {
            return Ok(());
        }
        let Some(stream) = self.request_stream.as_ref().cloned() else {
            return Ok(());
        };
        finish_h3_body(stream, self.write_timeout).await?;
        self.request_body_finished = true;
        Ok(())
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    async fn read_response_header(&mut self) -> PingoraResult<()> {
        let Some(stream) = self.request_stream.as_ref().cloned() else {
            return Error::e_explain(
                ErrorType::ReadError,
                "HTTP/3 request stream is not initialized",
            );
        };
        let mut stream = stream.lock().await;
        let response = match self.read_timeout {
            Some(timeout) => tokio::time::timeout(timeout, stream.recv_response())
                .await
                .map_err(|_| {
                    Error::explain(ErrorType::ReadTimedout, "reading HTTP/3 response header")
                })?,
            None => stream.recv_response().await,
        }
        .map_err(|err| {
            Error::explain(
                ErrorType::ReadError,
                format!("reading HTTP/3 response header: {err}"),
            )
        })?;
        self.response_header = Some(build_response_header(response)?);
        Ok(())
    }

    async fn read_response_body(&mut self) -> PingoraResult<Option<Bytes>> {
        if self.response_finished {
            return Ok(None);
        }
        let Some(stream) = self.request_stream.as_ref().cloned() else {
            return Error::e_explain(
                ErrorType::ReadError,
                "HTTP/3 request stream is not initialized",
            );
        };
        let mut stream = stream.lock().await;
        let result = match self.read_timeout {
            Some(timeout) => tokio::time::timeout(timeout, stream.recv_data())
                .await
                .map_err(|_| {
                    Error::explain(ErrorType::ReadTimedout, "reading HTTP/3 response body")
                })?,
            None => stream.recv_data().await,
        }
        .map_err(|err| {
            Error::explain(
                ErrorType::ReadError,
                format!("reading HTTP/3 response body: {err}"),
            )
        })?;
        let Some(mut chunk) = result else {
            self.response_finished = true;
            return Ok(None);
        };
        let mut out = BytesMut::with_capacity(chunk.remaining());
        while chunk.has_remaining() {
            out.extend_from_slice(chunk.chunk());
            let remaining = chunk.remaining();
            chunk.advance(remaining);
        }
        Ok(Some(out.freeze()))
    }

    fn response_finished(&self) -> bool {
        self.response_finished
    }

    async fn shutdown(&mut self, _code: u32, _ctx: &str) {
        if let Some(stream) = self.request_stream.as_ref() {
            stream.lock().await.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
    }

    fn response_header(&self) -> Option<&ResponseHeader> {
        self.response_header.as_ref()
    }

    fn was_upgraded(&self) -> bool {
        false
    }

    fn digest(&self) -> Option<&Digest> {
        Some(&self.digest)
    }

    fn digest_mut(&mut self) -> Option<&mut Digest> {
        Some(&mut self.digest)
    }

    fn server_addr(&self) -> Option<&SocketAddr> {
        Some(&self.server_addr)
    }

    fn client_addr(&self) -> Option<&SocketAddr> {
        Some(&self.client_addr)
    }

    async fn read_trailers(&mut self) -> PingoraResult<Option<HeaderMap>> {
        let Some(stream) = self.request_stream.as_ref().cloned() else {
            return Ok(None);
        };
        let mut stream = stream.lock().await;
        stream.recv_trailers().await.map_err(|err| {
            Error::explain(
                ErrorType::ReadError,
                format!("reading HTTP/3 trailers: {err}"),
            )
        })
    }

    fn fd(&self) -> UniqueIDType {
        0
    }

    async fn check_response_end_or_error(&mut self, headers: bool) -> PingoraResult<bool> {
        let no_body = headers
            && self
                .response_header
                .as_ref()
                .is_some_and(|header| matches!(header.status.as_u16(), 204 | 304));
        if no_body {
            self.response_finished = true;
        }
        Ok(no_body)
    }

    fn take_request_body_writer(&mut self) -> Option<Box<dyn BodyWrite>> {
        self.request_stream.as_ref().map(|stream| {
            Box::new(OriginH3BodyWriter {
                stream: stream.clone(),
                write_timeout: self.write_timeout,
                finished: false,
            }) as Box<dyn BodyWrite>
        })
    }

    async fn finish_custom(&mut self) -> PingoraResult<()> {
        self.finish_request_body().await
    }

    fn take_custom_message_reader(
        &mut self,
    ) -> Option<Box<dyn Stream<Item = PingoraResult<Bytes>> + Unpin + Send + Sync + 'static>> {
        Some(Box::new(futures_util::stream::empty()))
    }

    async fn drain_custom_messages(&mut self) -> PingoraResult<()> {
        Ok(())
    }

    fn take_custom_message_writer(&mut self) -> Option<Box<dyn CustomMessageWrite>> {
        Some(Box::new(()))
    }
}

struct OriginH3BodyWriter {
    stream: Arc<Mutex<H3RequestStream>>,
    write_timeout: Option<Duration>,
    finished: bool,
}

#[async_trait]
impl BodyWrite for OriginH3BodyWriter {
    async fn write_all_buf(&mut self, data: &mut Bytes) -> PingoraResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        let bytes = data.split_to(data.len());
        write_h3_body(self.stream.clone(), bytes, false, self.write_timeout).await
    }

    async fn finish(&mut self) -> PingoraResult<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        finish_h3_body(self.stream.clone(), self.write_timeout).await
    }

    async fn cleanup(&mut self) -> PingoraResult<()> {
        Ok(())
    }

    fn upgrade_body_writer(&mut self) {}
}

async fn write_h3_body(
    stream: Arc<Mutex<H3RequestStream>>,
    data: Bytes,
    end: bool,
    write_timeout: Option<Duration>,
) -> PingoraResult<()> {
    let mut stream = stream.lock().await;
    if !data.is_empty() {
        match write_timeout {
            Some(timeout) => tokio::time::timeout(timeout, stream.send_data(data))
                .await
                .map_err(|_| {
                    Error::explain(ErrorType::WriteTimedout, "writing HTTP/3 request body")
                })?,
            None => stream.send_data(data).await,
        }
        .map_err(|err| {
            Error::explain(
                ErrorType::WriteError,
                format!("writing HTTP/3 request body: {err}"),
            )
        })?;
    }
    if end {
        match write_timeout {
            Some(timeout) => tokio::time::timeout(timeout, stream.finish())
                .await
                .map_err(|_| {
                    Error::explain(ErrorType::WriteTimedout, "finishing HTTP/3 request body")
                })?,
            None => stream.finish().await,
        }
        .map_err(|err| {
            Error::explain(
                ErrorType::WriteError,
                format!("finishing HTTP/3 request body: {err}"),
            )
        })?;
    }
    Ok(())
}

async fn finish_h3_body(
    stream: Arc<Mutex<H3RequestStream>>,
    write_timeout: Option<Duration>,
) -> PingoraResult<()> {
    write_h3_body(stream, Bytes::new(), true, write_timeout).await
}

fn build_h3_request(req: &RequestHeader) -> PingoraResult<http::Request<()>> {
    let path = std::str::from_utf8(req.raw_path()).unwrap_or("/");
    let authority = req
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| req.uri.host().unwrap_or("localhost"));
    let uri = format!("https://{authority}{path}")
        .parse::<http::Uri>()
        .map_err(|err| {
            Error::explain(
                ErrorType::InvalidHTTPHeader,
                format!("building HTTP/3 request URI: {err}"),
            )
        })?;
    let mut builder = http::Request::builder()
        .method(req.method.clone())
        .uri(uri)
        .version(Version::HTTP_3);
    for (name, value) in &req.headers {
        if is_h3_forbidden_header(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder.body(()).map_err(|err| {
        Error::explain(
            ErrorType::InvalidHTTPHeader,
            format!("building HTTP/3 request: {err}"),
        )
    })
}

fn build_response_header(response: Response<()>) -> PingoraResult<ResponseHeader> {
    let (parts, _) = response.into_parts();
    let mut header = ResponseHeader::build(parts.status, Some(parts.headers.len()))?;
    header.set_version(Version::HTTP_3);
    for (name, value) in parts.headers {
        if let Some(name) = name
            && !is_h3_forbidden_header(name.as_str())
        {
            header.append_header(name, value)?;
        }
    }
    Ok(header)
}

fn is_h3_forbidden_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn origin_h3_key<P: Peer>(peer: &P) -> OriginH3Key {
    OriginH3Key::Target {
        addr: peer.address().to_string(),
        sni: peer.sni().to_string(),
    }
}

pub fn should_try_origin_h3_for_peer<P: Peer>(peer: &P) -> bool {
    ORIGIN_H3_STATE_MANAGER.should_try_h3(&origin_h3_key(peer))
}
