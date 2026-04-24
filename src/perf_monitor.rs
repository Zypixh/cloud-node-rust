use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Arc;
use sysinfo::{Disks, System};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

const MAX_SAMPLES: usize = 21_600;
const TOP_SERVER_LIMIT: usize = 8;

#[derive(Debug, Clone, Serialize)]
struct Advice {
    level: &'static str,
    title: &'static str,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct TopServer {
    server_id: i64,
    user_id: i64,
    plan_id: i64,
    total_bytes: u64,
    bytes_sent: u64,
    bytes_received: u64,
    total_requests: u64,
    active_connections: i64,
    origin_bytes: u64,
    cache_hit_requests: u64,
    attack_requests: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PerfSample {
    timestamp: i64,
    uptime_seconds: u64,
    cpu_usage: f64,
    cpu_count: usize,
    memory_used: u64,
    memory_total: u64,
    memory_usage: f64,
    swap_used: u64,
    swap_total: u64,
    load1m: f64,
    load5m: f64,
    load15m: f64,
    disk_used: u64,
    disk_total: u64,
    disk_usage: f64,
    traffic_in_bytes: u64,
    traffic_out_bytes: u64,
    traffic_in_bps: u64,
    traffic_out_bps: u64,
    total_requests: u64,
    request_delta: u64,
    request_per_sec: f64,
    active_connections: i64,
    server_count: usize,
    cache_disk_bytes: u64,
    top_servers: Vec<TopServer>,
    advice: Vec<Advice>,
}

#[derive(Default)]
struct MonitorStore {
    samples: VecDeque<PerfSample>,
}

type SharedStore = Arc<RwLock<MonitorStore>>;

pub async fn start(port: u16, clear_on_start: bool) {
    let store = Arc::new(RwLock::new(MonitorStore::default()));
    if clear_on_start {
        store.write().await.samples.clear();
    }

    tokio::spawn(sample_loop(store.clone()));

    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!("Performance monitor failed to bind {}: {}", addr, err);
            return;
        }
    };
    info!(
        "Performance monitor dashboard listening on http://{} (volatile memory only)",
        addr
    );

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let store = store.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, store).await {
                        log_connection_error(err);
                    }
                });
            }
            Err(err) => warn!("Performance monitor accept failed: {}", err),
        }
    }
}

fn log_connection_error(err: std::io::Error) {
    if err.kind() != std::io::ErrorKind::BrokenPipe
        && err.kind() != std::io::ErrorKind::ConnectionReset
    {
        warn!("Performance monitor connection failed: {}", err);
    }
}

async fn sample_loop(store: SharedStore) {
    let started_at = crate::utils::time::now_timestamp();
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut last_traffic_in = 0u64;
    let mut last_traffic_out = 0u64;
    let mut last_requests = 0u64;
    let mut last_timestamp = started_at;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        interval.tick().await;
        sys.refresh_all();

        let now = crate::utils::time::now_timestamp();
        let elapsed = now.saturating_sub(last_timestamp).max(1) as u64;
        let snapshots = crate::metrics::METRICS.take_snapshots();
        let (traffic_out, traffic_in, active_connections) =
            crate::metrics::METRICS.get_node_totals();
        let total_requests = snapshots
            .iter()
            .map(|snap| snap.total_requests)
            .sum::<u64>();
        let request_delta = total_requests.saturating_sub(last_requests);
        let traffic_in_delta = traffic_in.saturating_sub(last_traffic_in);
        let traffic_out_delta = traffic_out.saturating_sub(last_traffic_out);
        let memory_total = sys.total_memory();
        let memory_used = sys.used_memory();
        let load = System::load_average();
        let (disk_used, disk_total) = disk_usage();
        let disk_usage = if disk_total > 0 {
            disk_used as f64 / disk_total as f64
        } else {
            0.0
        };
        let cache_disk_bytes = crate::metrics::storage::STORAGE.total_cache_size();
        let cpu_usage = sys.global_cpu_usage() as f64;
        let memory_usage = if memory_total > 0 {
            memory_used as f64 / memory_total as f64
        } else {
            0.0
        };
        let top_servers = top_servers(&snapshots);
        let request_per_sec = request_delta as f64 / elapsed as f64;
        let traffic_in_bps = traffic_in_delta / elapsed;
        let traffic_out_bps = traffic_out_delta / elapsed;

        let sample = PerfSample {
            timestamp: now,
            uptime_seconds: now.saturating_sub(started_at) as u64,
            cpu_usage,
            cpu_count: sys.cpus().len(),
            memory_used,
            memory_total,
            memory_usage,
            swap_used: sys.used_swap(),
            swap_total: sys.total_swap(),
            load1m: load.one,
            load5m: load.five,
            load15m: load.fifteen,
            disk_used,
            disk_total,
            disk_usage,
            traffic_in_bytes: traffic_in,
            traffic_out_bytes: traffic_out,
            traffic_in_bps,
            traffic_out_bps,
            total_requests,
            request_delta,
            request_per_sec,
            active_connections,
            server_count: snapshots.len(),
            cache_disk_bytes,
            top_servers,
            advice: build_advice(
                cpu_usage,
                sys.cpus().len(),
                memory_usage,
                load.one,
                disk_usage,
                active_connections,
                request_per_sec,
                traffic_in_bps + traffic_out_bps,
                cache_disk_bytes,
                disk_total,
            ),
        };

        last_timestamp = now;
        last_requests = total_requests;
        last_traffic_in = traffic_in;
        last_traffic_out = traffic_out;

        let mut guard = store.write().await;
        guard.samples.push_back(sample);
        while guard.samples.len() > MAX_SAMPLES {
            guard.samples.pop_front();
        }
    }
}

fn disk_usage() -> (u64, u64) {
    let disks = Disks::new_with_refreshed_list();
    let mut total = 0u64;
    let mut used = 0u64;
    for disk in &disks {
        let disk_total = disk.total_space();
        let disk_used = disk_total.saturating_sub(disk.available_space());
        total = total.saturating_add(disk_total);
        used = used.saturating_add(disk_used);
    }
    (used, total)
}

fn top_servers(snapshots: &[crate::metrics::ServerStatusSnapshot]) -> Vec<TopServer> {
    let mut servers = snapshots
        .iter()
        .map(|snap| TopServer {
            server_id: snap.server_id,
            user_id: snap.user_id,
            plan_id: snap.plan_id,
            total_bytes: snap.total_bytes(),
            bytes_sent: snap.bytes_sent,
            bytes_received: snap.bytes_received,
            total_requests: snap.total_requests,
            active_connections: snap.active_connections,
            origin_bytes: snap.origin_bytes_sent + snap.origin_bytes_received,
            cache_hit_requests: snap.count_cached_requests,
            attack_requests: snap.count_attack_requests,
        })
        .collect::<Vec<_>>();
    servers.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
    servers.truncate(TOP_SERVER_LIMIT);
    servers
}

#[allow(clippy::too_many_arguments)]
fn build_advice(
    cpu_usage: f64,
    cpu_count: usize,
    memory_usage: f64,
    load1m: f64,
    disk_usage: f64,
    active_connections: i64,
    request_per_sec: f64,
    bandwidth_bps: u64,
    cache_disk_bytes: u64,
    disk_total: u64,
) -> Vec<Advice> {
    let mut advice = Vec::new();
    if cpu_usage >= 85.0 {
        advice.push(Advice {
            level: "critical",
            title: "CPU 压力过高",
            detail: "建议检查 WAF/缓存规则复杂度、上游重试、TLS 握手量；必要时扩容或拆分热点域名。"
                .to_string(),
        });
    }
    if memory_usage >= 0.85 {
        advice.push(Advice {
            level: "critical",
            title: "内存使用率过高",
            detail: "建议检查缓存元数据、连接数和日志队列；必要时降低缓存容量或提高实例内存。"
                .to_string(),
        });
    }
    if cpu_count > 0 && load1m > cpu_count as f64 * 1.5 {
        advice.push(Advice {
            level: "warning",
            title: "Load 高于 CPU 核心数",
            detail: format!(
                "1分钟负载 {:.2}，CPU 核心 {}；建议检查阻塞 IO、磁盘写入和上游连接耗时。",
                load1m, cpu_count
            ),
        });
    }
    if disk_usage >= 0.85 {
        advice.push(Advice {
            level: "warning",
            title: "磁盘空间偏高",
            detail: "建议清理缓存、日志和 RocksDB 数据，避免缓存写入失败影响回源。".to_string(),
        });
    }
    if active_connections >= 50_000 {
        advice.push(Advice {
            level: "warning",
            title: "连接数很高",
            detail:
                "建议确认 ulimit、somaxconn、tcp_max_syn_backlog、TIME_WAIT 参数和上游连接池容量。"
                    .to_string(),
        });
    }
    if request_per_sec >= 10_000.0 {
        advice.push(Advice {
            level: "info",
            title: "请求速率较高",
            detail: "建议重点观察缓存命中率、WAF 命中率和 Top Server，提前做热点拆分。".to_string(),
        });
    }
    if bandwidth_bps >= 100 * 1024 * 1024 {
        advice.push(Advice {
            level: "info",
            title: "带宽吞吐较高",
            detail: "建议确认网卡队列、多队列 RSS、BBR、回源链路和机器出口带宽上限。".to_string(),
        });
    }
    if disk_total > 0 && cache_disk_bytes as f64 / disk_total as f64 >= 0.5 {
        advice.push(Advice {
            level: "info",
            title: "缓存占用较大",
            detail: "建议按业务配置缓存 TTL、最大对象大小和清理策略，避免挤占系统盘。".to_string(),
        });
    }
    if advice.is_empty() {
        advice.push(Advice {
            level: "ok",
            title: "当前无明显瓶颈",
            detail: "CPU、内存、磁盘、连接数和吞吐量处于常规区间。".to_string(),
        });
    }
    advice
}

async fn handle_connection(mut stream: TcpStream, store: SharedStore) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]);
    let mut parts = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or("/");
    let path = target.split('?').next().unwrap_or(target);
    let query = target.split_once('?').map(|(_, query)| query).unwrap_or("");

    match (method, path) {
        ("GET", "/") => respond(&mut stream, 200, "text/html; charset=utf-8", INDEX_HTML).await,
        ("GET", "/api/samples") => {
            let limit = query_param(query, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(900)
                .min(MAX_SAMPLES);
            let samples = latest_samples(store.clone(), limit).await;
            respond_json(&mut stream, 200, &samples).await
        }
        ("GET", "/api/latest") => {
            let latest = store.read().await.samples.back().cloned();
            respond_json(&mut stream, 200, &latest).await
        }
        ("POST", "/api/clear") | ("GET", "/api/clear") => {
            store.write().await.samples.clear();
            respond_json(&mut stream, 200, &serde_json::json!({"ok": true})).await
        }
        _ => respond(&mut stream, 404, "text/plain; charset=utf-8", "not found").await,
    }
}

async fn latest_samples(store: SharedStore, limit: usize) -> Vec<PerfSample> {
    let guard = store.read().await;
    guard
        .samples
        .iter()
        .rev()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key { Some(v) } else { None }
    })
}

async fn respond_json<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    value: &T,
) -> std::io::Result<()> {
    let body = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    respond(stream, status, "application/json; charset=utf-8", &body).await
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "OK",
    };
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CloudNode Performance Monitor</title>
  <style>
    :root { --bg:#080b0a; --panel:#111916; --panel2:#17241f; --ink:#edf7f1; --muted:#91a49a; --line:#26362f; --green:#56d68f; --amber:#f5bd68; --blue:#79b7ff; --red:#ff7a7a; }
    * { box-sizing:border-box; }
    body { margin:0; color:var(--ink); font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at 18% -10%, #1d4b39 0, transparent 38%), radial-gradient(circle at 100% 0, #263a1e 0, transparent 34%), #080b0a; }
    main { max-width:1440px; margin:0 auto; padding:28px; }
    header { display:flex; align-items:flex-start; justify-content:space-between; gap:18px; margin-bottom:20px; }
    h1 { margin:0; font-size:34px; letter-spacing:-.05em; line-height:1; }
    .sub { color:var(--muted); margin-top:8px; font-size:14px; }
    .toolbar { display:flex; gap:10px; flex-wrap:wrap; justify-content:flex-end; }
    button, select { background:rgba(17,25,22,.9); color:var(--ink); border:1px solid var(--line); border-radius:999px; padding:10px 14px; }
    button:hover, select:hover { border-color:var(--green); cursor:pointer; }
    .grid { display:grid; grid-template-columns: repeat(6, minmax(0,1fr)); gap:14px; }
    .card { background:linear-gradient(180deg, rgba(23,36,31,.92), rgba(14,21,18,.94)); border:1px solid var(--line); border-radius:22px; padding:16px; box-shadow:0 24px 70px rgba(0,0,0,.28); }
    .metric { min-height:112px; }
    .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }
    .value { font-size:28px; font-weight:750; margin-top:10px; letter-spacing:-.04em; white-space:nowrap; }
    .hint { color:var(--muted); font-size:12px; margin-top:6px; }
    .wide { grid-column:span 3; }
    .full { grid-column:span 6; }
    .chart { height:280px; margin-top:12px; }
    canvas { width:100%; height:100%; display:block; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { padding:10px 8px; border-bottom:1px solid var(--line); text-align:right; }
    th:first-child, td:first-child { text-align:left; }
    .advice { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; margin-top:10px; }
    .pill { border:1px solid var(--line); border-radius:16px; padding:12px; background:rgba(255,255,255,.03); }
    .pill.ok { border-color:rgba(86,214,143,.45); }
    .pill.warning { border-color:rgba(245,189,104,.55); }
    .pill.critical { border-color:rgba(255,122,122,.65); }
    .pill h3 { margin:0 0 6px; font-size:14px; }
    .pill p { margin:0; color:var(--muted); font-size:12px; line-height:1.5; }
    @media (max-width: 1000px) { .grid { grid-template-columns:1fr; } .wide,.full { grid-column:span 1; } header { flex-direction:column; } .advice { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>Performance Monitor</h1>
      <div class="sub">仅保留当前进程内的滚动数据，重启后自动清空。刷新周期 1s。</div>
    </div>
    <div class="toolbar">
      <select id="range"><option value="300">5分钟</option><option value="900" selected>15分钟</option><option value="1800">30分钟</option><option value="3600">1小时</option><option value="21600">6小时</option></select>
      <button id="clear">清空当前窗口</button>
    </div>
  </header>
  <section class="grid">
    <div class="card metric"><div class="label">CPU</div><div class="value" id="cpu">-</div><div class="hint" id="load">load -</div></div>
    <div class="card metric"><div class="label">Memory</div><div class="value" id="mem">-</div><div class="hint" id="memBytes">-</div></div>
    <div class="card metric"><div class="label">Bandwidth Out</div><div class="value" id="out">-</div><div class="hint">edge -> client</div></div>
    <div class="card metric"><div class="label">Bandwidth In</div><div class="value" id="in">-</div><div class="hint">client -> edge</div></div>
    <div class="card metric"><div class="label">Requests</div><div class="value" id="rps">-</div><div class="hint" id="totalReq">-</div></div>
    <div class="card metric"><div class="label">Connections</div><div class="value" id="conn">-</div><div class="hint" id="servers">-</div></div>
    <div class="card wide"><div class="label">实时带宽 Bytes/s</div><div class="chart"><canvas id="traffic"></canvas></div></div>
    <div class="card wide"><div class="label">CPU / 内存 / 磁盘 %</div><div class="chart"><canvas id="resource"></canvas></div></div>
    <div class="card wide"><div class="label">请求/s</div><div class="chart"><canvas id="requests"></canvas></div></div>
    <div class="card wide"><div class="label">连接数</div><div class="chart"><canvas id="connections"></canvas></div></div>
    <div class="card full"><div class="label">优化建议</div><div class="advice" id="advice"></div></div>
    <div class="card full"><div class="label">Top Server</div><table><thead><tr><th>Server</th><th>Requests</th><th>Total</th><th>Out</th><th>In</th><th>Origin</th><th>Conns</th><th>Cache Hits</th><th>Attacks</th></tr></thead><tbody id="topServers"></tbody></table></div>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
const fmtBytes = n => n >= 1073741824 ? (n/1073741824).toFixed(2)+' GB' : n >= 1048576 ? (n/1048576).toFixed(2)+' MB' : n >= 1024 ? (n/1024).toFixed(1)+' KB' : Math.round(n)+' B';
const pct = n => (n*100).toFixed(1)+'%';
function draw(canvas, series, colors) {
  const ctx = canvas.getContext('2d'), dpr = devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = Math.max(1,w*dpr); canvas.height = Math.max(1,h*dpr); ctx.scale(dpr,dpr); ctx.clearRect(0,0,w,h);
  const max = Math.max(1, ...series.flatMap(s => s));
  ctx.strokeStyle = '#26362f'; ctx.lineWidth = 1;
  for (let i=0;i<4;i++){ const y=h*i/3; ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke(); }
  series.forEach((data, idx) => { ctx.strokeStyle = colors[idx]; ctx.lineWidth = 2.2; ctx.beginPath(); data.forEach((v,i)=>{ const x = data.length <= 1 ? 0 : i*(w/(data.length-1)); const y = h - (v/max)*(h-8) - 4; i ? ctx.lineTo(x,y) : ctx.moveTo(x,y); }); ctx.stroke(); });
}
function renderAdvice(items) {
  $('advice').innerHTML = (items || []).map(x => `<div class="pill ${x.level}"><h3>${x.title}</h3><p>${x.detail}</p></div>`).join('');
}
function renderTop(rows) {
  $('topServers').innerHTML = (rows || []).map(x => `<tr><td>#${x.server_id}</td><td>${x.total_requests}</td><td>${fmtBytes(x.total_bytes)}</td><td>${fmtBytes(x.bytes_sent)}</td><td>${fmtBytes(x.bytes_received)}</td><td>${fmtBytes(x.origin_bytes)}</td><td>${x.active_connections}</td><td>${x.cache_hit_requests}</td><td>${x.attack_requests}</td></tr>`).join('');
}
async function refresh() {
  const data = await fetch('/api/samples?limit='+$('range').value).then(r=>r.json());
  const last = data[data.length-1]; if (!last) return;
  $('cpu').textContent = last.cpu_usage.toFixed(1)+'%';
  $('load').textContent = `load ${last.load1m.toFixed(2)} / ${last.load5m.toFixed(2)} / ${last.load15m.toFixed(2)} · ${last.cpu_count} cores`;
  $('mem').textContent = pct(last.memory_usage);
  $('memBytes').textContent = `${fmtBytes(last.memory_used)} / ${fmtBytes(last.memory_total)} · cache ${fmtBytes(last.cache_disk_bytes)}`;
  $('out').textContent = fmtBytes(last.traffic_out_bps)+'/s';
  $('in').textContent = fmtBytes(last.traffic_in_bps)+'/s';
  $('rps').textContent = last.request_per_sec.toFixed(1)+'/s';
  $('totalReq').textContent = `total ${last.total_requests}`;
  $('conn').textContent = last.active_connections;
  $('servers').textContent = `${last.server_count} servers · uptime ${Math.floor(last.uptime_seconds/60)}m`;
  draw($('traffic'), [data.map(x=>x.traffic_out_bps), data.map(x=>x.traffic_in_bps)], ['#56d68f','#f5bd68']);
  draw($('resource'), [data.map(x=>x.cpu_usage), data.map(x=>x.memory_usage*100), data.map(x=>x.disk_usage*100)], ['#56d68f','#79b7ff','#f5bd68']);
  draw($('requests'), [data.map(x=>x.request_per_sec)], ['#f5bd68']);
  draw($('connections'), [data.map(x=>x.active_connections)], ['#56d68f']);
  renderAdvice(last.advice);
  renderTop(last.top_servers);
}
$('clear').onclick = async () => { await fetch('/api/clear', {method:'POST'}); await refresh(); };
$('range').onchange = refresh; refresh(); setInterval(refresh, 1000);
</script>
</body>
</html>"#;
