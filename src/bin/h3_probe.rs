use bytes::{Buf, Bytes};
use http::Request;
use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
        ]
    }
}

#[derive(Clone)]
struct ProbeConfig {
    requests: usize,
    connections: usize,
    concurrency: usize,
    addr: SocketAddr,
    host: String,
    uri: String,
}

#[derive(Default)]
struct ProbeStats {
    ok: usize,
    failed: usize,
    bytes: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let config = ProbeConfig {
        requests: args.get(1).and_then(|v| v.parse().ok()).unwrap_or(1),
        addr: args
            .get(2)
            .map(String::as_str)
            .unwrap_or("127.0.0.1:443")
            .parse()?,
        host: args
            .get(3)
            .cloned()
            .unwrap_or_else(|| "rke-cache-test.local".to_string()),
        uri: args
            .get(4)
            .cloned()
            .unwrap_or_else(|| "https://rke-cache-test.local/".to_string()),
        connections: args.get(5).and_then(|v| v.parse().ok()).unwrap_or(1),
        concurrency: args.get(6).and_then(|v| v.parse().ok()).unwrap_or(1),
    };

    let start = Instant::now();
    let next = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(config.connections);
    for _ in 0..config.connections {
        let config = config.clone();
        let next = next.clone();
        tasks.push(tokio::spawn(async move { run_connection(config, next).await }));
    }

    let mut stats = ProbeStats::default();
    for task in tasks {
        let result = task.await??;
        stats.ok += result.ok;
        stats.failed += result.failed;
        stats.bytes += result.bytes;
    }

    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "requests={} ok={} failed={} seconds={:.3} rps={:.2} bytes={} connections={} concurrency={}",
        config.requests,
        stats.ok,
        stats.failed,
        elapsed,
        config.requests as f64 / elapsed,
        stats.bytes,
        config.connections,
        config.concurrency
    );

    Ok(())
}

async fn run_connection(
    config: ProbeConfig,
    next: Arc<AtomicUsize>,
) -> anyhow::Result<ProbeStats> {
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerifier))
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))?,
    ));
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint.connect(config.addr, &config.host)?;
    let conn = tokio::time::timeout(Duration::from_secs(10), connecting).await??;
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, send_request) = h3::client::builder()
        .build::<_, _, Bytes>(h3_conn)
        .await?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let send_request = Arc::new(tokio::sync::Mutex::new(send_request));

    let mut workers = Vec::with_capacity(config.concurrency);
    for _ in 0..config.concurrency {
        let send_request = send_request.clone();
        let next = next.clone();
        let config = config.clone();
        workers.push(tokio::spawn(async move {
            let mut stats = ProbeStats::default();
            loop {
                let idx = next.fetch_add(1, Ordering::Relaxed);
                if idx >= config.requests {
                    break;
                }
                match run_request(&send_request, &config.uri).await {
                    Ok((ok, bytes)) => {
                        if ok {
                            stats.ok += 1;
                        } else {
                            stats.failed += 1;
                        }
                        stats.bytes += bytes;
                    }
                    Err(_) => stats.failed += 1,
                }
            }
            stats
        }));
    }

    let mut stats = ProbeStats::default();
    for worker in workers {
        let result = worker.await?;
        stats.ok += result.ok;
        stats.failed += result.failed;
        stats.bytes += result.bytes;
    }

    endpoint.close(0u32.into(), b"done");
    driver_task.abort();
    Ok(stats)
}

async fn run_request(
    send_request: &tokio::sync::Mutex<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>>,
    uri: &str,
) -> anyhow::Result<(bool, usize)> {
    let request = Request::get(uri).header("user-agent", "h3-probe").body(())?;
    let mut sender = send_request.lock().await;
    let mut stream = sender.send_request(request).await?;
    drop(sender);
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let mut bytes_total = 0usize;
    while let Some(mut chunk) = stream.recv_data().await? {
        bytes_total += chunk.remaining();
        chunk.advance(chunk.remaining());
    }
    Ok((response.status().is_success(), bytes_total))
}
