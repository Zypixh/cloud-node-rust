use std::net::SocketAddr as StdSocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::Stream;
use h3::error::Code;
use http::{HeaderMap, Request, Response, Version};
use pingora_core::protocols::http::custom::server::Session as CustomServerSession;
use pingora_core::protocols::http::custom::CustomMessageWrite;
use pingora_core::protocols::http::HttpTask;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_core::protocols::Digest;
use pingora_core::{Error, ErrorType, Result as PingoraResult};
use pingora_http::{RequestHeader, ResponseHeader};
use tokio::sync::Mutex;

pub struct H3DownstreamSession<S>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    req_header: RequestHeader,
    stream: Mutex<h3::server::RequestStream<S, Bytes>>,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    digest: Digest,
    response_written: Option<ResponseHeader>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    total_drain_timeout: Option<Duration>,
    body_done: bool,
    response_done: bool,
    body_bytes_read: usize,
    body_bytes_sent: usize,
    retry_buffer: Option<BytesMut>,
    retry_buffer_truncated: bool,
}

impl<S> H3DownstreamSession<S>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    pub fn new(
        request: Request<()>,
        stream: h3::server::RequestStream<S, Bytes>,
        remote_addr: StdSocketAddr,
        local_addr: StdSocketAddr,
    ) -> PingoraResult<Self> {
        let req_header = build_request_header(request)?;
        Ok(Self {
            req_header,
            stream: Mutex::new(stream),
            client_addr: remote_addr.into(),
            server_addr: local_addr.into(),
            digest: Digest::default(),
            response_written: None,
            read_timeout: None,
            write_timeout: None,
            total_drain_timeout: None,
            body_done: false,
            response_done: false,
            body_bytes_read: 0,
            body_bytes_sent: 0,
            retry_buffer: None,
            retry_buffer_truncated: false,
        })
    }

    async fn recv_body_chunk(&mut self) -> PingoraResult<Option<Bytes>> {
        if self.body_done {
            return Ok(None);
        }

        let mut stream = self.stream.lock().await;
        let result = if let Some(timeout) = self.read_timeout {
            match tokio::time::timeout(timeout, stream.recv_data()).await {
                Ok(result) => result,
                Err(_) => return Error::e_explain(ErrorType::ReadTimedout, "reading HTTP/3 request body"),
            }
        } else {
            stream.recv_data().await
        };
        drop(stream);

        let Some(mut chunk) = result.map_err(|err| {
            Error::explain(
                ErrorType::ReadError,
                format!("reading HTTP/3 request body: {err}"),
            )
        })? else {
            self.body_done = true;
            return Ok(None);
        };

        let mut out = BytesMut::with_capacity(chunk.remaining());
        while chunk.has_remaining() {
            out.extend_from_slice(chunk.chunk());
            let remaining = chunk.remaining();
            chunk.advance(remaining);
        }
        let bytes = out.freeze();
        self.body_bytes_read = self.body_bytes_read.saturating_add(bytes.len());
        if let Some(buffer) = self.retry_buffer.as_mut() {
            if buffer.len().saturating_add(bytes.len()) <= 64 * 1024 {
                buffer.extend_from_slice(&bytes);
            } else {
                self.retry_buffer_truncated = true;
            }
        }
        Ok(Some(bytes))
    }

    async fn send_response(&mut self, resp: &ResponseHeader, end: bool) -> PingoraResult<()> {
        let response = build_h3_response(resp)?;
        let mut stream = self.stream.lock().await;
        if let Some(timeout) = self.write_timeout {
            tokio::time::timeout(timeout, stream.send_response(response))
                .await
                .map_err(|_| Error::explain(ErrorType::WriteTimedout, "writing HTTP/3 response header"))?
        } else {
            stream.send_response(response).await
        }
        .map_err(|err| {
            Error::explain(
                ErrorType::WriteError,
                format!("writing HTTP/3 response header: {err}"),
            )
        })?;
        drop(stream);

        self.response_written = Some(resp.clone());
        if end {
            self.finish().await?;
        }
        Ok(())
    }

    async fn send_body(&mut self, data: Bytes) -> PingoraResult<()> {
        self.body_bytes_sent = self.body_bytes_sent.saturating_add(data.len());
        let mut stream = self.stream.lock().await;
        if let Some(timeout) = self.write_timeout {
            tokio::time::timeout(timeout, stream.send_data(data))
                .await
                .map_err(|_| Error::explain(ErrorType::WriteTimedout, "writing HTTP/3 response body"))?
        } else {
            stream.send_data(data).await
        }
        .map_err(|err| {
            Error::explain(
                ErrorType::WriteError,
                format!("writing HTTP/3 response body: {err}"),
            )
        })
    }
}

#[async_trait]
impl<S> CustomServerSession for H3DownstreamSession<S>
where
    S: h3::quic::BidiStream<Bytes> + Send + 'static,
{
    fn req_header(&self) -> &RequestHeader {
        &self.req_header
    }

    fn req_header_mut(&mut self) -> &mut RequestHeader {
        &mut self.req_header
    }

    async fn read_body_bytes(&mut self) -> PingoraResult<Option<Bytes>> {
        self.recv_body_chunk().await
    }

    async fn drain_request_body(&mut self) -> PingoraResult<()> {
        let timeout = self.total_drain_timeout;
        let drain = async {
            while self.recv_body_chunk().await?.is_some() {}
            Ok(())
        };
        if let Some(timeout) = timeout {
            tokio::time::timeout(timeout, drain)
                .await
                .map_err(|_| Error::explain(ErrorType::ReadTimedout, "draining HTTP/3 request body"))?
        } else {
            drain.await
        }
    }

    async fn write_response_header(&mut self, resp: Box<ResponseHeader>, end: bool) -> PingoraResult<()> {
        self.send_response(&resp, end).await
    }

    async fn write_response_header_ref(&mut self, resp: &ResponseHeader, end: bool) -> PingoraResult<()> {
        self.send_response(resp, end).await
    }

    async fn write_body(&mut self, data: Bytes, end: bool) -> PingoraResult<()> {
        if !data.is_empty() {
            self.send_body(data).await?;
        }
        if end {
            self.finish().await?;
        }
        Ok(())
    }

    async fn write_trailers(&mut self, trailers: HeaderMap) -> PingoraResult<()> {
        self.stream
            .lock()
            .await
            .send_trailers(trailers)
            .await
            .map_err(|err| Error::explain(ErrorType::WriteError, format!("writing HTTP/3 trailers: {err}")))?;
        self.finish().await
    }

    async fn response_duplex_vec(&mut self, tasks: Vec<HttpTask>) -> PingoraResult<bool> {
        for task in tasks {
            match task {
                HttpTask::Header(resp, end) => self.write_response_header(resp, end).await?,
                HttpTask::Body(Some(data), end) | HttpTask::UpgradedBody(Some(data), end) => {
                    self.write_body(data, end).await?;
                }
                HttpTask::Body(None, end) | HttpTask::UpgradedBody(None, end) => {
                    if end {
                        self.finish().await?;
                    }
                }
                HttpTask::Trailer(Some(trailers)) => self.write_trailers(*trailers).await?,
                HttpTask::Trailer(None) | HttpTask::Done => self.finish().await?,
                HttpTask::Failed(err) => return Err(err),
            }
        }
        Ok(true)
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    fn get_read_timeout(&self) -> Option<Duration> {
        self.read_timeout
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }

    fn get_write_timeout(&self) -> Option<Duration> {
        self.write_timeout
    }

    fn set_total_drain_timeout(&mut self, timeout: Option<Duration>) {
        self.total_drain_timeout = timeout;
    }

    fn get_total_drain_timeout(&self) -> Option<Duration> {
        self.total_drain_timeout
    }

    fn request_summary(&self) -> String {
        let host = self
            .req_header
            .headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-");
        format!("{} {} {host}", self.req_header.method, self.req_header.uri)
    }

    fn response_written(&self) -> Option<&ResponseHeader> {
        self.response_written.as_ref()
    }

    async fn shutdown(&mut self, _code: u32, _ctx: &str) {
        self.stream.lock().await.stop_stream(Code::H3_REQUEST_CANCELLED);
    }

    fn is_body_done(&mut self) -> bool {
        self.body_done
    }

    async fn finish(&mut self) -> PingoraResult<()> {
        if self.response_done {
            return Ok(());
        }
        self.stream
            .lock()
            .await
            .finish()
            .await
            .map_err(|err| Error::explain(ErrorType::WriteError, format!("finishing HTTP/3 response: {err}")))?;
        self.response_done = true;
        Ok(())
    }

    fn is_body_empty(&mut self) -> bool {
        self.req_header
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "0")
    }

    async fn read_body_or_idle(&mut self, _no_body_expected: bool) -> PingoraResult<Option<Bytes>> {
        self.read_body_bytes().await
    }

    fn body_bytes_sent(&self) -> usize {
        self.body_bytes_sent
    }

    fn body_bytes_read(&self) -> usize {
        self.body_bytes_read
    }

    fn digest(&self) -> Option<&Digest> {
        Some(&self.digest)
    }

    fn digest_mut(&mut self) -> Option<&mut Digest> {
        Some(&mut self.digest)
    }

    fn client_addr(&self) -> Option<&SocketAddr> {
        Some(&self.client_addr)
    }

    fn server_addr(&self) -> Option<&SocketAddr> {
        Some(&self.server_addr)
    }

    fn pseudo_raw_h1_request_header(&self) -> Bytes {
        let mut out = BytesMut::new();
        out.extend_from_slice(self.req_header.method.as_str().as_bytes());
        out.extend_from_slice(b" ");
        out.extend_from_slice(self.req_header.raw_path());
        out.extend_from_slice(b" HTTP/3\r\n");
        for (name, value) in &self.req_header.headers {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out.freeze()
    }

    fn enable_retry_buffering(&mut self) {
        self.retry_buffer = Some(BytesMut::new());
        self.retry_buffer_truncated = false;
    }

    fn retry_buffer_truncated(&self) -> bool {
        self.retry_buffer_truncated
    }

    fn get_retry_buffer(&self) -> Option<Bytes> {
        self.retry_buffer.as_ref().map(|buffer| buffer.clone().freeze())
    }

    async fn finish_custom(&mut self) -> PingoraResult<()> {
        self.finish().await
    }

    fn take_custom_message_reader(
        &mut self,
    ) -> Option<Box<dyn Stream<Item = PingoraResult<Bytes>> + Unpin + Send + Sync + 'static>> {
        Some(Box::new(futures_util::stream::empty()))
    }

    fn restore_custom_message_reader(
        &mut self,
        _reader: Box<dyn Stream<Item = PingoraResult<Bytes>> + Unpin + Send + Sync + 'static>,
    ) -> PingoraResult<()> {
        Ok(())
    }

    fn take_custom_message_writer(&mut self) -> Option<Box<dyn CustomMessageWrite>> {
        Some(Box::new(()))
    }

    fn restore_custom_message_writer(&mut self, _writer: Box<dyn CustomMessageWrite>) -> PingoraResult<()> {
        Ok(())
    }
}

fn build_request_header(request: Request<()>) -> PingoraResult<RequestHeader> {
    let (parts, _) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let mut req = RequestHeader::build_no_case(parts.method, path.as_bytes(), Some(parts.headers.len()))?;
    req.set_version(Version::HTTP_3);

    if let Some(authority) = parts.uri.authority()
        && !parts.headers.contains_key(http::header::HOST)
    {
        req.insert_header(http::header::HOST, authority.as_str())?;
    }

    for (name, value) in parts.headers {
        if let Some(name) = name
            && !is_h3_forbidden_response_header(name.as_str())
        {
            req.append_header(name, value)?;
        }
    }

    Ok(req)
}

fn build_h3_response(resp: &ResponseHeader) -> PingoraResult<Response<()>> {
    let mut builder = Response::builder().status(resp.status);
    for (name, value) in &resp.headers {
        if is_h3_forbidden_response_header(name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(|err| Error::explain(ErrorType::InvalidHTTPHeader, format!("building HTTP/3 response: {err}")))
}

fn is_h3_forbidden_response_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "te" | "trailer" | "transfer-encoding" | "upgrade"
    )
}
