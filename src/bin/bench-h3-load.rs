/// Minimal HTTP/3 (QUIC) load generator for the bench matrix — the h3 side
/// counterpart of `oha`, emitting an oha-compatible JSON summary so the
/// protocol rounds stay comparable.
///
/// Usage:
///   bench-h3-load --host 127.0.0.1 --port 8443 --path /file-1K.bin \
///       --conns 50 --streams 4 --duration 15s [--urls-file path] [--body] \
///       [--out out.json]
///
/// --conns QUIC connections are opened up front; each connection drives
/// --streams concurrent request streams for --duration. With --urls-file,
/// each request picks the next path round-robin (matches oha
/// --urls-from-file behavior closely enough for cache workloads).
use bytes::{Buf, Bytes};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _s: &ServerName<'_>,
        _o: &[u8],
        _t: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn arg_value(args: &[String], flag: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn parse_dur(s: &str) -> Duration {
    let secs: f64 = s.trim_end_matches('s').parse().expect("bad --duration");
    Duration::from_secs_f64(secs)
}

struct Shared {
    ok: AtomicU64,
    err: AtomicU64,
    bytes: AtomicU64,
    latencies_us: parking_lot::Mutex<Vec<u64>>,
    stop: AtomicBool,
}

async fn run_stream(
    send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    path: &str,
    authority: &str,
    read_body: bool,
) -> Result<u64, String> {
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://{authority}{path}"))
        .header("host", authority)
        .body(())
        .map_err(|e| e.to_string())?;
    let mut stream = send.send_request(req).await.map_err(|e| e.to_string())?;
    stream.finish().await.map_err(|e| e.to_string())?;
    let resp = stream.recv_response().await.map_err(|e| e.to_string())?;
    if resp.status() != http::StatusCode::OK {
        return Err(format!("status {}", resp.status()));
    }
    let mut total = 0u64;
    if read_body {
        while let Some(chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
            total += chunk.remaining() as u64;
        }
    } else {
        while let Some(chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
            total += chunk.remaining() as u64;
        }
    }
    let _ = stream;
    Ok(total)
}

/// Churn mode: every iteration opens a fresh QUIC connection for a single
/// request, then drops it — measures handshake+first-request cost.
async fn churn_worker(
    server: SocketAddr,
    endpoint: quinn::Endpoint,
    authority: String,
    path: String,
    shared: Arc<Shared>,
    read_body: bool,
) {
    while !shared.stop.load(Ordering::Relaxed) {
        let start = Instant::now();
        let res = async {
            let connecting = endpoint.connect(server, "localhost").map_err(|e| e.to_string())?;
            let conn = connecting.await.map_err(|e| e.to_string())?;
            let (mut driver, mut send_request) = h3::client::builder()
                .build(h3_quinn::Connection::new(conn.clone()))
                .await
                .map_err(|e| e.to_string())?;
            let drive = tokio::spawn(async move {
                let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            });
            let n = run_stream(&mut send_request, &path, &authority, read_body).await?;
            conn.close(0u32.into(), b"done");
            drive.abort();
            Ok::<u64, String>(n)
        }
        .await;
        match res {
            Ok(n) => {
                shared.ok.fetch_add(1, Ordering::Relaxed);
                shared.bytes.fetch_add(n, Ordering::Relaxed);
                shared.latencies_us.lock().push(start.elapsed().as_micros() as u64);
            }
            Err(_) => {
                shared.err.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn conn_worker(
    server: SocketAddr,
    endpoint: quinn::Endpoint,
    authority: String,
    paths: Arc<Vec<String>>,
    streams: usize,
    shared: Arc<Shared>,
    read_body: bool,
) {
    let connecting = match endpoint.connect(server, "localhost") {
        Ok(c) => c,
        Err(_) => return,
    };
    let conn = match connecting.await {
        Ok(c) => c,
        Err(_) => return,
    };
    let (mut driver, send_request) =
        match h3::client::builder().build(h3_quinn::Connection::new(conn)).await {
            Ok(v) => v,
            Err(_) => return,
        };
    tokio::spawn(async move {
        let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let send = Arc::new(tokio::sync::Mutex::new(send_request));

    let mut tasks = Vec::new();
    for lane in 0..streams {
        let send = Arc::clone(&send);
        let shared = Arc::clone(&shared);
        let authority = authority.clone();
        let paths = Arc::clone(&paths);
        tasks.push(tokio::spawn(async move {
            let mut seq = lane;
            while !shared.stop.load(Ordering::Relaxed) {
                let path = &paths[seq % paths.len()];
                seq = seq.wrapping_add(streams);
                let start = Instant::now();
                let mut guard = send.lock().await;
                let res = run_stream(&mut guard, path, &authority, read_body).await;
                drop(guard);
                match res {
                    Ok(n) => {
                        shared.ok.fetch_add(1, Ordering::Relaxed);
                        shared.bytes.fetch_add(n, Ordering::Relaxed);
                        shared
                            .latencies_us
                            .lock()
                            .push(start.elapsed().as_micros() as u64);
                    }
                    Err(_) => {
                        shared.err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args: Vec<String> = std::env::args().collect();
    let host = arg_value(&args, "--host", "127.0.0.1");
    let port: u16 = arg_value(&args, "--port", "8443").parse()?;
    let conns: usize = arg_value(&args, "--conns", "50").parse()?;
    let streams: usize = arg_value(&args, "--streams", "4").parse()?;
    let dur = parse_dur(&arg_value(&args, "--duration", "15s"));
    let out = arg_value(&args, "--out", "");
    let single_path = arg_value(&args, "--path", "/file-1K.bin");
    let urls_file = arg_value(&args, "--urls-file", "");
    let churn = args.iter().any(|a| a == "--churn");
    let read_body = true;

    let paths: Vec<String> = if urls_file.is_empty() {
        vec![single_path.clone()]
    } else {
        std::fs::read_to_string(&urls_file)?
            .lines()
            .map(|l| {
                let l = l.trim();
                // accept full URLs or bare paths
                if let Some(rest) = l.split("://").nth(1) {
                    match rest.find('/') {
                        Some(i) => rest[i..].to_string(),
                        None => "/".to_string(),
                    }
                } else {
                    l.to_string()
                }
            })
            .filter(|p| !p.is_empty())
            .collect()
    };
    anyhow::ensure!(!paths.is_empty(), "no paths");
    let paths = Arc::new(paths);
    let authority = format!("{host}:{port}");

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(
            rustls::crypto::aws_lc_rs::default_provider().into(),
        )))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.enable_early_data = false;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    let client_cfg = quinn::ClientConfig::new(Arc::new(quic));

    let server = SocketAddr::new(host.parse::<IpAddr>()?, port);
    let mut endpoint = quinn::Endpoint::client(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ))?;
    endpoint.set_default_client_config(client_cfg);
    let endpoint = Arc::new(endpoint);

    let shared = Arc::new(Shared {
        ok: AtomicU64::new(0),
        err: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        latencies_us: parking_lot::Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
    });

    let mut workers = Vec::new();
    for _ in 0..conns {
        if churn {
            workers.push(tokio::spawn(churn_worker(
                server,
                (*endpoint).clone(),
                authority.clone(),
                single_path.clone(),
                Arc::clone(&shared),
                read_body,
            )));
        } else {
            workers.push(tokio::spawn(conn_worker(
                server,
                (*endpoint).clone(),
                authority.clone(),
                Arc::clone(&paths),
                streams,
                Arc::clone(&shared),
                read_body,
            )));
        }
        // stagger connection setup slightly to avoid handshake bursts
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    tokio::time::sleep(dur).await;
    shared.stop.store(true, Ordering::Relaxed);
    for w in workers {
        let _ = tokio::time::timeout(Duration::from_secs(10), w).await;
    }

    let ok = shared.ok.load(Ordering::Relaxed);
    let err = shared.err.load(Ordering::Relaxed);
    let bytes = shared.bytes.load(Ordering::Relaxed);
    let mut lats = std::mem::take(&mut *shared.latencies_us.lock());
    lats.sort_unstable();
    let pct = |p: f64| -> f64 {
        if lats.is_empty() {
            return 0.0;
        }
        let i = ((lats.len() - 1) as f64 * p).round() as usize;
        lats[i] as f64 / 1e6
    };
    let total = ok + err;
    let rps = ok as f64 / dur.as_secs_f64();

    // oha-compatible shape used by the matrix runner.
    let out_json = serde_json::json!({
        "summary": {
            "successRate": if total == 0 { 0.0 } else { ok as f64 / total as f64 },
            "total": dur.as_secs_f64(),
            "slowest": lats.last().copied().unwrap_or(0) as f64 / 1e6,
            "fastest": lats.first().copied().unwrap_or(0) as f64 / 1e6,
            "average": if lats.is_empty() { 0.0 } else { lats.iter().sum::<u64>() as f64 / lats.len() as f64 / 1e6 },
            "requestsPerSec": rps,
            "totalData": bytes,
            "sizePerRequest": if ok == 0 { 0 } else { bytes / ok },
            "sizePerSec": (bytes as f64 / dur.as_secs_f64()) as u64
        },
        "latencyPercentiles": {
            "p10": pct(0.10), "p25": pct(0.25), "p50": pct(0.50),
            "p75": pct(0.75), "p90": pct(0.90), "p95": pct(0.95),
            "p99": pct(0.99), "p99.9": pct(0.999), "p99.99": pct(0.9999),
        },
        "statusCodeDistribution": { "200": ok },
        "errorDistribution": { "h3 error": err },
        "meta": { "protocol": "h3", "conns": conns, "streams": streams }
    });
    let text = serde_json::to_string_pretty(&out_json)?;
    if out.is_empty() {
        println!("{text}");
    } else {
        std::fs::write(&out, &text)?;
        eprintln!("wrote {out}");
    }
    Ok(())
}
