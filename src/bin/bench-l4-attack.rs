/// L4/L7 attack generator for the defense bench. Single-process, async.
///
/// Modes (all target --ip/--port):
///   churn     TCP connect -> immediate close (empty-connection flood)
///   hold      TCP connect -> hold --hold-ms with no bytes -> close (slow first byte)
///   slowhdr   connect -> send partial HTTP headers, drip one header/--drip-ms
///   tinyreq   connect -> send --payload bytes -> close (early close / tiny request)
///   tls-fail  connect -> send garbage -> close (TLS handshake failure / invalid probe)
///   conn-hold open --conns sockets, hold for --duration (per-IP active limit)
///   httpflood full GET loop, conn per request (or --keepalive); status histogram
///   udpflood  UDP datagrams of --payload bytes
///
/// Source IPs rotate across 127.0.0.<src-base>..<src-base+src-count-1> so
/// per-IP defenses isolate attacker IPs from the 127.0.0.1 legit probe.
///
/// Emits a JSON summary on stdout at exit.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[derive(Default)]
struct Stats {
    ops: AtomicU64,
    ok: AtomicU64,
    refused: AtomicU64,
    reset: AtomicU64,
    closed_early: AtomicU64,
    timeouts: AtomicU64,
    errors: AtomicU64,
    codes: Mutex<HashMap<u16, u64>>,
}

struct Args {
    mode: String,
    ip: Ipv4Addr,
    port: u16,
    src_base: u8,
    src_count: u16,
    conns: usize,
    duration: Duration,
    hold: Duration,
    drip: Duration,
    rate: u64,
    payload: usize,
    path: String,
    host: String,
    keepalive: bool,
}

impl Args {
    fn parse_args() -> Args {
        let mut a = Args {
            mode: "churn".into(),
            ip: Ipv4Addr::LOCALHOST,
            port: 8080,
            src_base: 16,
            src_count: 1,
            conns: 32,
            duration: Duration::from_secs(10),
            hold: Duration::from_secs(3),
            drip: Duration::from_millis(500),
            rate: 0,
            payload: 64,
            path: "/file-1K.bin".into(),
            host: "plain.bench".into(),
            keepalive: false,
        };
        let mut it = std::env::args().skip(1);
        while let Some(k) = it.next() {
            let mut v = || it.next().unwrap_or_default();
            match k.as_str() {
                "--mode" => a.mode = v(),
                "--ip" => a.ip = v().parse().unwrap(),
                "--port" => a.port = v().parse().unwrap(),
                "--src-base" => a.src_base = v().parse().unwrap(),
                "--src-count" => a.src_count = v().parse().unwrap(),
                "-c" | "--conns" => a.conns = v().parse().unwrap(),
                "-d" | "--duration" => a.duration = Duration::from_secs_f64(v().parse().unwrap()),
                "--hold-ms" => a.hold = Duration::from_millis(v().parse().unwrap()),
                "--drip-ms" => a.drip = Duration::from_millis(v().parse().unwrap()),
                "--rate" => a.rate = v().parse().unwrap(),
                "--payload" => a.payload = v().parse().unwrap(),
                "--path" => a.path = v(),
                "--host" => a.host = v(),
                "--keepalive" => a.keepalive = true,
                _ => {}
            }
        }
        a
    }
}

fn src_ip(a: &Args, i: u64) -> SocketAddr {
    let last = a.src_base as u32 + (i % a.src_count as u64) as u32;
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(
            127,
            0,
            (last >> 8) as u8,
            (last & 0xff) as u8,
        )),
        0,
    )
}

async fn connect(a: &Args, i: u64) -> std::io::Result<TcpStream> {
    let sock = TcpSocket::new_v4()?;
    sock.bind(src_ip(a, i))?;
    sock.connect(SocketAddr::new(a.ip.into(), a.port)).await
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let a = Args::parse_args();
    let args = &*Box::leak(Box::new(a));
    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    // Stop flag after duration (except conn-hold which manages its own flow).
    {
        let stop = stop.clone();
        let dur = args.duration;
        tokio::spawn(async move {
            tokio::time::sleep(dur).await;
            stop.store(true, Ordering::Relaxed);
        });
    }

    match args.mode.as_str() {
        "conn-hold" => conn_hold(args, &stats, &stop).await,
        _ => {
            let mut workers = Vec::new();
            for w in 0..args.conns {
                let stats = stats.clone();
                let stop = stop.clone();
                let mode = args.mode.clone();
                workers.push(tokio::spawn(worker(w as u64, args, stats, stop, mode)));
            }
            for w in workers {
                let _ = w.await;
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let codes = stats.codes.lock().unwrap().clone();
    let out = serde_json::json!({
        "mode": args.mode,
        "elapsed_s": elapsed,
        "ops": stats.ops.load(Ordering::Relaxed),
        "ok": stats.ok.load(Ordering::Relaxed),
        "refused": stats.refused.load(Ordering::Relaxed),
        "reset": stats.reset.load(Ordering::Relaxed),
        "closed_early": stats.closed_early.load(Ordering::Relaxed),
        "timeouts": stats.timeouts.load(Ordering::Relaxed),
        "errors": stats.errors.load(Ordering::Relaxed),
        "ops_per_sec": stats.ops.load(Ordering::Relaxed) as f64 / elapsed.max(1e-9),
        "status_codes": codes,
    });
    println!("{out}");
}

async fn worker(id: u64, a: &Args, stats: Arc<Stats>, stop: Arc<AtomicBool>, mode: String) {
    let mut i = id * 1_000_003; // spread src-IP rotation across workers
    let mut interval = if a.rate > 0 {
        Some(tokio::time::interval(Duration::from_secs_f64(
            1.0 / a.rate as f64,
        )))
    } else {
        None
    };
    while !stop.load(Ordering::Relaxed) {
        if let Some(t) = interval.as_mut() {
            t.tick().await;
        }
        i = i.wrapping_add(1);
        stats.ops.fetch_add(1, Ordering::Relaxed);
        match mode.as_str() {
            "churn" => op_churn(a, &stats, i).await,
            "hold" => op_hold(a, &stats, i).await,
            "slowhdr" => op_slowhdr(a, &stats, i).await,
            "tinyreq" => op_tinyreq(a, &stats, i).await,
            "tls-fail" => op_tlsfail(a, &stats, i).await,
            "httpflood" => op_httpflood(a, &stats, i, &stop).await,
            "udpflood" => op_udpflood(a, &stats, i).await,
            _ => {}
        }
    }
}

fn bump_code(stats: &Stats, code: u16) {
    *stats.codes.lock().unwrap().entry(code).or_insert(0) += 1;
}

async fn op_churn(a: &Args, s: &Stats, i: u64) {
    match connect(a, i).await {
        Ok(s_) => {
            s.ok.fetch_add(1, Ordering::Relaxed);
            drop(s_); // FIN/RST immediately — empty connection
        }
        Err(e) => classify_conn_err(s, &e),
    }
}

async fn op_hold(a: &Args, s: &Stats, i: u64) {
    match connect(a, i).await {
        Ok(mut st) => {
            s.ok.fetch_add(1, Ordering::Relaxed);
            let mut byte = [0u8; 1];
            tokio::select! {
                _ = tokio::time::sleep(a.hold) => {}
                r = st.read(&mut byte) => {
                    if matches!(r, Ok(0) | Err(_)) {
                        s.closed_early.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        Err(e) => classify_conn_err(s, &e),
    }
}

async fn op_slowhdr(a: &Args, s: &Stats, i: u64) {
    match connect(a, i).await {
        Ok(mut st) => {
            s.ok.fetch_add(1, Ordering::Relaxed);
            let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", a.path, a.host);
            if st.write_all(req.as_bytes()).await.is_err() {
                s.reset.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // Drip headers until server closes or we exhaust patience.
            let deadline = Instant::now() + a.duration.max(Duration::from_secs(8));
            loop {
                let mut rbuf = [0u8; 64];
                tokio::select! {
                    _ = tokio::time::sleep(a.drip) => {}
                    r = st.read(&mut rbuf) => {
                        match r {
                            Ok(0) | Err(_) => { s.closed_early.fetch_add(1, Ordering::Relaxed); return; }
                            Ok(_) => {}
                        }
                    }
                }
                if Instant::now() > deadline {
                    return;
                }
                if st.write_all(b"X-drip: 1\r\n").await.is_err() {
                    s.reset.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
        Err(e) => classify_conn_err(s, &e),
    }
}

async fn op_tinyreq(a: &Args, s: &Stats, i: u64) {
    match connect(a, i).await {
        Ok(mut st) => {
            s.ok.fetch_add(1, Ordering::Relaxed);
            let payload = vec![0x55u8; a.payload.max(1)];
            let _ = st.write_all(&payload).await;
            drop(st);
        }
        Err(e) => classify_conn_err(s, &e),
    }
}

async fn op_tlsfail(a: &Args, s: &Stats, i: u64) {
    match connect(a, i).await {
        Ok(mut st) => {
            s.ok.fetch_add(1, Ordering::Relaxed);
            // Garbage that is not a TLS ClientHello -> handshake fail / probe.
            let mut junk = vec![0xabu8; a.payload.max(16)];
            junk[0] = 0x16; // looks like a handshake record header, bad body
            let _ = st.write_all(&junk).await;
            let _ = tokio::time::timeout(Duration::from_millis(300), st.read(&mut [0u8; 32])).await;
            drop(st);
        }
        Err(e) => classify_conn_err(s, &e),
    }
}

async fn op_httpflood(a: &Args, s: &Stats, i: u64, stop: &AtomicBool) {
    match connect(a, i).await {
        Ok(mut st) => {
            s.ok.fetch_add(1, Ordering::Relaxed);
            let conn_hdr = if a.keepalive { "keep-alive" } else { "close" };
            let req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: bench-flood\r\nConnection: {}\r\n\r\n",
                a.path, a.host, conn_hdr
            );
            // keepalive: keep issuing requests on this connection until it dies.
            let reqs_per_conn = if a.keepalive { 100_000usize } else { 1 };
            let mut buf = vec![0u8; 65536];
            for _ in 0..reqs_per_conn {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                if st.write_all(req.as_bytes()).await.is_err() {
                    s.reset.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let mut have =
                    match tokio::time::timeout(Duration::from_secs(10), st.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => n,
                        Ok(Ok(_)) => {
                            s.closed_early.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        Ok(Err(e)) => {
                            classify_conn_err(s, &e);
                            return;
                        }
                        Err(_) => {
                            s.timeouts.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                let head = String::from_utf8_lossy(&buf[..have.min(64)]);
                let code = head
                    .split_whitespace()
                    .nth(1)
                    .and_then(|c| c.parse::<u16>().ok())
                    .unwrap_or(0);
                bump_code(s, code);
                let close =
                    head.contains("Connection: close") || head.contains("connection: close");
                if a.keepalive && !close {
                    if !a.drip.is_zero() {
                        tokio::time::sleep(a.drip).await;
                    }
                    // Consume exactly this response: headers + body
                    // (content-length or chunked transfer-encoding).
                    let need = loop {
                        if let Some(p) = buf[..have].windows(4).position(|w| w == b"\r\n\r\n") {
                            let hend = p + 4;
                            let htxt = String::from_utf8_lossy(&buf[..hend]);
                            let mut clen = 0usize;
                            let mut chunked = false;
                            for line in htxt.lines() {
                                let l = line.to_ascii_lowercase();
                                if let Some(v) = l.strip_prefix("content-length:") {
                                    clen = v.trim().parse().unwrap_or(0);
                                }
                                if l.starts_with("transfer-encoding:") && l.contains("chunked") {
                                    chunked = true;
                                }
                            }
                            if chunked {
                                // Read until the terminal "0\r\n\r\n" chunk.
                                loop {
                                    if buf[..have].windows(5).any(|w| w == b"0\r\n\r\n") {
                                        break;
                                    }
                                    match tokio::time::timeout(
                                        Duration::from_secs(2),
                                        st.read(&mut buf[have..]),
                                    )
                                    .await
                                    {
                                        Ok(Ok(m)) if m > 0 => have += m,
                                        _ => break,
                                    }
                                }
                                break have;
                            }
                            break hend + clen;
                        }
                        match tokio::time::timeout(
                            Duration::from_secs(2),
                            st.read(&mut buf[have..]),
                        )
                        .await
                        {
                            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break have,
                            Ok(Ok(m)) => have += m,
                        }
                    };
                    while have < need {
                        match tokio::time::timeout(
                            Duration::from_secs(2),
                            st.read(&mut buf[have..]),
                        )
                        .await
                        {
                            Ok(Ok(m)) if m > 0 => have += m,
                            _ => {
                                s.closed_early.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                } else {
                    return;
                }
            }
        }
        Err(e) => classify_conn_err(s, &e),
    }
}

async fn op_udpflood(a: &Args, s: &Stats, i: u64) {
    let sock = match UdpSocket::bind(src_ip(a, i)).await {
        Ok(sock) => sock,
        Err(e) => {
            classify_conn_err(s, &e);
            return;
        }
    };
    let dst = SocketAddr::new(a.ip.into(), a.port);
    if sock.connect(dst).await.is_err() {
        s.errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let payload = vec![0x42u8; a.payload.max(1)];
    // One socket pumps for a bounded burst so rotation covers --src-count IPs.
    for _ in 0..2048 {
        if sock.send(&payload).await.is_ok() {
            s.ok.fetch_add(1, Ordering::Relaxed);
        } else {
            s.errors.fetch_add(1, Ordering::Relaxed);
        }
        tokio::task::yield_now().await;
    }
}

async fn conn_hold(a: &Args, s: &Arc<Stats>, stop: &Arc<AtomicBool>) {
    let mut held = Vec::with_capacity(a.conns);
    for i in 0..a.conns as u64 {
        s.ops.fetch_add(1, Ordering::Relaxed);
        match connect(a, i).await {
            Ok(st) => {
                s.ok.fetch_add(1, Ordering::Relaxed);
                held.push(st);
            }
            Err(e) => classify_conn_err(s, &e),
        }
        if i % 512 == 0 {
            tokio::task::yield_now().await;
        }
    }
    eprintln!(
        "conn-hold established={} failed={}",
        s.ok.load(Ordering::Relaxed),
        s.errors.load(Ordering::Relaxed) + s.refused.load(Ordering::Relaxed)
    );
    while !stop.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    drop(held);
}

fn classify_conn_err(s: &Stats, e: &std::io::Error) {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => {
            s.refused.fetch_add(1, Ordering::Relaxed);
        }
        ConnectionReset | ConnectionAborted => {
            s.reset.fetch_add(1, Ordering::Relaxed);
        }
        TimedOut => {
            s.timeouts.fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            s.errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}
