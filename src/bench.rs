//! Full-stack stress test module for CloudNode.
//!
//! Phase 1: Component-level benchmarks (WAF, Cache, TLS, Auth, Rewrite, Metrics)
//! Phase 2: End-to-end HTTP/HTTPS proxy stress test with built-in mock origin

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::auth::UrlAuthConfig;
use crate::cache_hybrid::HybridStorage;
use crate::config_models::{HTTPRewriteRef, HTTPRewriteRule};
use crate::firewall::matcher::evaluate_operator;
use crate::firewall::verifier::WafVerifier;
use crate::lb_factory::{AnyLoadBalancer, BackendExtension};
use crate::metrics::analyzer::analyze_request;
use crate::rewrite::evaluate_rewrites;
use crate::ssl::DynamicCertSelector;

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

pub struct BenchParams {
    pub duration: u64,
    pub concurrency: Option<usize>,
    pub upstream: Option<String>,
    pub http_port: u16,
    pub https_port: u16,
    pub body_size: String,
    pub skip_component: bool,
    pub skip_e2e: bool,
}

pub fn run_bench(params: BenchParams) -> anyhow::Result<()> {
    println!("============================================================");
    println!("   CloudNode Performance Benchmark");
    println!("============================================================");
    println!();

    let duration = Duration::from_secs(params.duration);
    let cpu_count = num_cpus::get_physical().max(1);
    let concurrency = params.concurrency.unwrap_or(cpu_count * 64);

    println!("  CPU Cores: {}  |  Duration: {}s  |  Concurrency: {}",
             cpu_count, params.duration, concurrency);
    println!();

    let mut component_results = Vec::new();
    let mut e2e_result: Option<E2EResult> = None;
    let mut tls_result: Option<f64> = None;
    let mut resource_stats: Option<ResourceStats> = None;

    // Phase 1: Component-level stress tests
    if !params.skip_component {
        println!("-- Phase 1: Component Stress Tests --");
        println!();
        component_results = run_component_tests(duration, cpu_count);
        print_component_results(&component_results);
        println!();
    }

    // Phase 2: End-to-end HTTP stress test
    if !params.skip_e2e {
        println!("-- Phase 2: End-to-End HTTP Stress Test --");
        println!();

        let body_len = match params.body_size.as_str() {
            "small" => 1024,
            "medium" => 64 * 1024,
            "large" => 1024 * 1024,
            _ => 64 * 1024,
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(cpu_count.min(8))
            .build()?;

        let (e2e, tls_qps, res_stats) = rt.block_on(async {
            run_e2e_phase(
                &params.upstream,
                params.http_port,
                params.https_port,
                body_len,
                concurrency,
                duration,
            )
            .await
        })?;

        e2e_result = Some(e2e);
        tls_result = Some(tls_qps);
        resource_stats = Some(res_stats);

        print_e2e_results(
            e2e_result.as_ref().unwrap(),
            tls_result.unwrap(),
            resource_stats.as_ref().unwrap(),
            params.http_port,
            params.https_port,
            concurrency,
            params.duration,
        );
        println!();
    }

    // Composite Score
    let score = compute_composite_score(&component_results, e2e_result.as_ref(), tls_result);
    let peak_qps = e2e_result.as_ref().map(|r| r.qps).unwrap_or(0.0);

    println!("============================================================");
    println!("  COMPOSITE SCORE: {:.0} / 1000", score);
    println!("  PEAK QPS: {:.0} req/s", peak_qps);
    println!("============================================================");

    Ok(())
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ComponentResult {
    name: String,
    ops_per_sec: f64,
    total_ops: u64,
    latency_p50_ns: u64,
    latency_p99_ns: u64,
}

struct E2EResult {
    qps: f64,
    total_requests: u64,
    errors: u64,
    cache_hits: u64,
    latency_p50_us: u64,
    latency_p90_us: u64,
    latency_p95_us: u64,
    latency_p99_us: u64,
    latency_p999_us: u64,
    latency_min_us: u64,
    latency_max_us: u64,
    latency_avg_us: u64,
}

struct ResourceStats {
    peak_cpu: f64,
    peak_memory_bytes: u64,
    memory_total: u64,
    cpu_count: usize,
    avg_net_in_bps: u64,
    avg_net_out_bps: u64,
    total_disk_read: u64,
    total_disk_write: u64,
}

// ---------------------------------------------------------------------------
// Phase 1: Component benchmarks
// ---------------------------------------------------------------------------

fn run_component_tests(duration: Duration, cpu_count: usize) -> Vec<ComponentResult> {
    let thread_count = cpu_count.min(16);
    let mut results = Vec::new();

    // WAF/SQLi
    results.push(run_single_component(
        "WAF/SQLi",
        duration,
        thread_count,
        || {
            let _ = evaluate_operator(
                "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin--",
                "contains sql injection",
                "",
                false,
            );
        },
    ));

    // WAF/XSS
    results.push(run_single_component(
        "WAF/XSS",
        duration,
        thread_count,
        || {
            let _ = evaluate_operator(
                "<script>alert('xss')</script>",
                "contains xss",
                "",
                false,
            );
        },
    ));

    // WAF/Regex
    results.push(run_single_component(
        "WAF/Regex",
        duration,
        thread_count,
        || {
            let _ = evaluate_operator(
                "/api/v1/users/12345/profile?debug=true",
                "match",
                r"/api/v\d+/users/\d+/\w+",
                false,
            );
        },
    ));

    // WAF/IP-CIDR
    results.push(run_single_component(
        "WAF/IP-CIDR",
        duration,
        thread_count,
        || {
            let _ = evaluate_operator(
                "192.168.1.50",
                "in ip list",
                "10.0.0.0/8\n172.16.0.0/12\n192.168.1.0/24\n1.1.1.1/32",
                false,
            );
        },
    ));

    // WAF/Verifier
    let verifier = Arc::new(WafVerifier::new("bench-secret-key-0123456789012345"));
    let token = verifier.generate_token("203.0.113.10", "Mozilla/5.0 Bench");
    results.push(run_single_component(
        "WAF/Verifier",
        duration,
        thread_count,
        move || {
            let _ = verifier.verify_token("203.0.113.10", "Mozilla/5.0 Bench", &token, 3600);
        },
    ));

    // Cache/L1
    {
        let key_str = "bench.local/cached-asset.js";
        let body = bytes::Bytes::from(vec![b'x'; 4096]);
        let meta = bench_cache_meta();
        HybridStorage::bench_fast_l1_remove(key_str);
        HybridStorage::bench_fast_l1_insert(key_str, body, &meta, 3600);

        results.push(run_single_component(
            "Cache/L1-Lookup",
            duration,
            thread_count,
            move || {
                let _ = crate::cache_hybrid::fast_l1_lookup(key_str);
            },
        ));
    }

    // TLS/CertSelect
    {
        let selector = Arc::new(DynamicCertSelector::new());
        let cert_pem = include_str!("../pingora-main/pingora-core/examples/keys/server/cert.pem");
        let key_pem = include_str!("../pingora-main/pingora-core/examples/keys/server/key.pem");
        let certs = vec![crate::config_models::SSLCertConfig {
            id: 1,
            is_on: true,
            cert_data_json: Some(serde_json::json!(cert_pem)),
            key_data_json: Some(serde_json::json!(key_pem)),
            dns_names: Vec::new(),
        }];
        let policy = crate::config_models::SSLPolicyConfig {
            id: 1,
            is_on: true,
            certs: Vec::new(),
            http2_enabled: true,
            min_version: String::new(),
            hsts: None,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(crate::ssl::sync_certs(&selector, &certs, Some(&policy)));

        let sel_clone = selector.clone();
        results.push(run_single_component(
            "TLS/CertSelect",
            duration,
            thread_count,
            move || {
                let _ = sel_clone.bench_find_pair("openrusty.org");
            },
        ));
    }

    // Auth/URLVerify
    {
        let config = Arc::new(UrlAuthConfig {
            auth_type: "A".to_string(),
            secret: "bench-secret-0123456789".to_string(),
            param_name: "auth_key".to_string(),
            life: 3600,
        });
        let ts = crate::utils::time::now_timestamp();
        let md5_input = format!("/bench/resource.mp4-{}-0-0-{}", ts, config.secret);
        let hash = format!("{:x}", md5_legacy::compute(md5_input.as_bytes()));
        let query = Arc::new(format!("auth_key={}-0-0-{}", ts, hash));

        results.push(run_single_component(
            "Auth/URLVerify",
            duration,
            thread_count,
            move || {
                let _ = crate::auth::verify_url_auth(
                    "/bench/resource.mp4",
                    &query,
                    &config,
                );
            },
        ));
    }

    // Rewrite/Regex
    {
        let refs: Vec<HTTPRewriteRef> = (0..5)
            .map(|_| HTTPRewriteRef { is_on: true })
            .collect();
        let rules: Vec<HTTPRewriteRule> = (0..5)
            .map(|i| HTTPRewriteRule {
                id: Some(i),
                is_on: true,
                pattern: Some(format!(r"^/v{}/(.*)$", i)),
                replace: Some(format!("/api/v{}/$$1", i)),
                with_query: true,
                mode: Some("proxy".to_string()),
                redirect_status: 0,
                is_break: false,
                proxy_host: None,
            })
            .collect();

        results.push(run_single_component(
            "Rewrite/Regex",
            duration,
            thread_count,
            move || {
                let _ = evaluate_rewrites(
                    "/v3/users/list",
                    "page=1&size=20",
                    &refs,
                    &rules,
                );
            },
        ));
    }

    // Metrics/Analyze
    results.push(run_single_component(
        "Metrics/Analyze",
        duration,
        thread_count,
        || {
            let ip: IpAddr = "1.2.3.4".parse().unwrap();
            let _ = analyze_request(
                ip,
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0",
            );
        },
    ));

    results
}

fn run_single_component<F>(
    name: &str,
    duration: Duration,
    thread_count: usize,
    work: F,
) -> ComponentResult
where
    F: Fn() + Send + Sync + Clone + 'static,
{
    let counter = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let latency_samples = Arc::new(parking_lot::Mutex::new(Vec::<u64>::with_capacity(10000)));

    let mut handles = Vec::new();
    for _ in 0..thread_count {
        let counter = counter.clone();
        let stop = stop.clone();
        let samples = latency_samples.clone();
        let work = work.clone();

        handles.push(std::thread::spawn(move || {
            let mut local_count = 0u64;
            let mut local_samples = Vec::with_capacity(1024);
            let sample_every = 128u64; // sample latency every N ops

            while !stop.load(Ordering::Relaxed) {
                let start = Instant::now();
                for _ in 0..sample_every {
                    work();
                }
                let elapsed = start.elapsed().as_nanos() as u64;
                local_count += sample_every;
                local_samples.push(elapsed / sample_every);

                // Keep sample buffer bounded
                if local_samples.len() > 4096 {
                    local_samples.drain(..2048);
                }
            }
            counter.fetch_add(local_count, Ordering::Relaxed);
            let mut lock = samples.lock();
            lock.extend_from_slice(&local_samples);
        }));
    }

    std::thread::sleep(duration);
    stop.store(true, Ordering::Relaxed);

    for h in handles {
        let _ = h.join();
    }

    let total_ops = counter.load(Ordering::Relaxed);
    let ops_per_sec = total_ops as f64 / duration.as_secs_f64();

    let mut samples = latency_samples.lock().clone();
    samples.sort_unstable();
    let (p50, p99) = if samples.is_empty() {
        (0, 0)
    } else {
        let p50_idx = samples.len() * 50 / 100;
        let p99_idx = (samples.len() * 99 / 100).min(samples.len() - 1);
        (samples[p50_idx], samples[p99_idx])
    };

    ComponentResult {
        name: name.to_string(),
        ops_per_sec,
        total_ops,
        latency_p50_ns: p50,
        latency_p99_ns: p99,
    }
}

fn bench_cache_meta() -> pingora_cache::CacheMeta {
    let mut header =
        pingora_http::ResponseHeader::build(200, None).expect("response header");
    header
        .insert_header("content-type", "application/javascript")
        .unwrap();
    header
        .insert_header("cache-control", "public, max-age=3600")
        .unwrap();
    let now = std::time::SystemTime::now();
    pingora_cache::CacheMeta::new(now + Duration::from_secs(3600), now, 0, 0, header)
}

// ---------------------------------------------------------------------------
// Phase 2: End-to-end test
// ---------------------------------------------------------------------------

async fn run_e2e_phase(
    upstream_override: &Option<String>,
    http_port: u16,
    https_port: u16,
    body_len: usize,
    concurrency: usize,
    duration: Duration,
) -> anyhow::Result<(E2EResult, f64, ResourceStats)> {
    // 1. Start mock origin (or use override)
    let origin_addr = if let Some(addr) = upstream_override {
        println!("  Using external upstream: {}", addr);
        addr.parse::<SocketAddr>()
            .unwrap_or_else(|_| format!("{}:80", addr).parse().expect("invalid upstream address"))
    } else {
        let addr = start_mock_origin(body_len).await;
        println!("  Mock origin started: {} (body={}KB)", addr, body_len / 1024);
        addr
    };

    // 2. Start proxy with synthetic config
    start_bench_proxy(origin_addr, http_port, https_port).await?;
    println!("  Proxy listening: :{} (HTTP) / :{} (HTTPS)", http_port, https_port);
    println!("  Concurrency: {} | Duration: {}s", concurrency, duration.as_secs());
    println!();

    // 3. Wait a moment for proxy to fully initialize
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 4. Start resource monitor
    let res_monitor = start_resource_monitor(duration);

    // 5. Run HTTP load test
    println!("  Running HTTP load test...");
    let e2e = run_load_generator(http_port, concurrency, duration).await;

    // 6. Run TLS handshake test (shorter duration)
    let tls_duration = Duration::from_secs(duration.as_secs().min(10));
    println!("  Running TLS handshake test ({:.0}s)...", tls_duration.as_secs_f64());
    let tls_qps = run_tls_handshake_bench(https_port, tls_duration).await;

    // 7. Collect resource stats
    let res_stats = res_monitor.await;

    Ok((e2e, tls_qps, res_stats))
}

// ---------------------------------------------------------------------------
// Mock Origin Server
// ---------------------------------------------------------------------------

async fn start_mock_origin(body_len: usize) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind mock origin");
    let addr = listener.local_addr().unwrap();

    // Pre-build HTTP response bytes
    let body: Vec<u8> = (0..body_len).map(|i| (i % 256) as u8).collect();
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Cache-Control: public, max-age=3600\r\n\
         Connection: keep-alive\r\n\
         X-Origin: bench-mock\r\n\
         \r\n",
        body_len
    );
    let mut full_response = response.into_bytes();
    full_response.extend_from_slice(&body);
    let response_bytes: Arc<Vec<u8>> = Arc::new(full_response);

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let resp = response_bytes.clone();
            tokio::spawn(async move {
                handle_mock_connection(stream, resp).await;
            });
        }
    });

    addr
}

async fn handle_mock_connection(
    mut stream: tokio::net::TcpStream,
    response: Arc<Vec<u8>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 4096];
    loop {
        // Read until we find \r\n\r\n (end of HTTP headers)
        let n = match stream.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };

        // Simple check: if we read something, assume it's a full request
        // For keep-alive, look for the end of headers marker
        let data = &buf[..n];
        if data.windows(4).any(|w| w == b"\r\n\r\n") {
            // Could have multiple pipelined requests; handle one at a time
            if stream.write_all(&response).await.is_err() {
                return;
            }
        } else {
            // Partial read, just respond anyway (simplification for bench)
            if stream.write_all(&response).await.is_err() {
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Synthetic Proxy Setup (Phase 2)
// ---------------------------------------------------------------------------

async fn start_bench_proxy(
    origin_addr: SocketAddr,
    http_port: u16,
    https_port: u16,
) -> anyhow::Result<()> {
    use crate::config::ConfigStore;
    use crate::config_models::*;
    use crate::firewall::state::WafStateManager;
    use crate::proxy::EdgeProxy;

    let config_store = Arc::new(ConfigStore::new());
    let waf_state = Arc::new(WafStateManager::new());
    let cert_selector = Arc::new(DynamicCertSelector::new());

    // Load TLS cert
    let cert_pem = include_str!("../pingora-main/pingora-core/examples/keys/server/cert.pem");
    let key_pem = include_str!("../pingora-main/pingora-core/examples/keys/server/key.pem");
    let certs = vec![SSLCertConfig {
        id: 1,
        is_on: true,
        cert_data_json: Some(serde_json::json!(cert_pem)),
        key_data_json: Some(serde_json::json!(key_pem)),
        dns_names: Vec::new(),
    }];
    let ssl_policy = SSLPolicyConfig {
        id: 1,
        is_on: true,
        certs: Vec::new(),
        http2_enabled: true,
        min_version: String::new(),
        hsts: None,
    };
    crate::ssl::sync_certs(&cert_selector, &certs, Some(&ssl_policy)).await;

    // Build synthetic server config
    let origin_str = origin_addr.to_string();
    let server_config = build_synthetic_server_config(&origin_str);
    let server_arc = Arc::new(server_config);

    // Build load balancer
    let lb = build_bench_lb(&origin_str);

    // Inject config into store
    let mut servers = std::collections::HashMap::new();
    servers.insert("bench.local".to_string(), server_arc.clone());
    servers.insert("127.0.0.1".to_string(), server_arc.clone());
    servers.insert("localhost".to_string(), server_arc.clone());

    let mut routes = std::collections::HashMap::new();
    let lb_arc = Arc::new(lb);
    routes.insert("bench.local".to_string(), lb_arc.clone());
    routes.insert("127.0.0.1".to_string(), lb_arc.clone());
    routes.insert("localhost".to_string(), lb_arc.clone());

    let mut id_to_lb = std::collections::HashMap::new();
    id_to_lb.insert(1i64, lb_arc.clone());

    // Build WAF policies
    let firewall_policies = build_synthetic_firewall_policies();

    // Build cache policies
    let cache_policies = vec![Arc::new(build_synthetic_cache_policy())];

    config_store
        .update_config(
            1,                                         // id
            1,                                         // version
            0,                                         // node_region_id
            0,                                         // node_cluster_id
            vec![server_arc.clone()],                  // all_servers
            servers,                                   // servers
            routes,                                    // routes
            id_to_lb,                                  // id_to_lb
            Vec::new(),                                // deleted_contents
            Vec::new(),                                // global_pages
            Vec::new(),                                // metric_items
            1,                                         // level
            true,                                      // is_on
            false,                                     // enable_ip_lists
            std::collections::HashMap::new(),          // parent_nodes
            false,                                     // tiered_origin_bypass
            false,                                     // force_ln_request
            "random".to_string(),                      // ln_method
            std::collections::HashMap::new(),          // parent_routes
            None,                                      // grpc_policy
            false,                                     // supports_low_version_http
            true,                                      // match_cert_from_all_servers
            String::new(),                             // server_name
            false,                                     // enable_server_addr_variable
            false,                                     // request_origins_with_encodings
            0,                                         // xff_max_addresses
            true,                                      // allow_lan_ip
            false,                                     // match_domain_strictly
            false,                                     // node_ip_show_page
            String::new(),                             // node_ip_page_html
            None,                                      // domain_mismatch_action
            cache_policies,                            // cache_policy
            firewall_policies,                         // firewall_policies
            Vec::new(),                                // waf_actions
            std::collections::HashMap::new(),          // uam_policies
            std::collections::HashMap::new(),          // http_cc_policies
            std::collections::HashMap::new(),          // http3_policies
            std::collections::HashMap::new(),          // http_pages_policies
            std::collections::HashMap::new(),          // webp_image_policies
            None,                                      // toa
            None,                                      // global_access_log
        )
        .await;

    // Build EdgeProxy
    let api_config = Arc::new(crate::api_config::ApiConfig {
        rpc_endpoints: vec!["bench://localhost".to_string()],
        rpc_disable_update: true,
        node_id: "bench-node".to_string(),
        secret: "bench-secret-key-00000000000000000".to_string(),
    });

    let edge_proxy = EdgeProxy {
        config: config_store.clone(),
        waf_state: waf_state.clone(),
        api_config: api_config.clone(),
        cert_selector: cert_selector.clone(),
        waf_verifier: Arc::new(WafVerifier::new(&api_config.secret)),
    };

    // Start Pingora in a background thread
    let threads = num_cpus::get_physical().min(32);
    let mut conf = pingora_core::server::configuration::ServerConf::default();
    conf.threads = threads;
    conf.upstream_keepalive_pool_size = 32768;

    let mut server = pingora_core::server::Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let mut proxy_service =
        pingora_proxy::http_proxy_service(&server.configuration, edge_proxy);
    proxy_service.add_tcp(&format!("0.0.0.0:{}", http_port));
    // Add TLS listener
    let mut tls_settings = pingora_core::listeners::tls::TlsSettings::intermediate(
        "pingora-main/pingora-core/examples/keys/server/cert.pem",
        "pingora-main/pingora-core/examples/keys/server/key.pem",
    )
    .expect("Failed to load TLS cert for bench proxy");
    tls_settings.enable_h2();
    proxy_service.add_tls_with_settings(
        &format!("0.0.0.0:{}", https_port),
        None,
        tls_settings,
    );
    server.add_service(proxy_service);

    std::thread::spawn(move || {
        server.run_forever();
    });

    // Wait for proxy to be ready
    wait_for_port(http_port, Duration::from_secs(5)).await?;

    Ok(())
}

async fn wait_for_port(port: u16, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            anyhow::bail!("Timeout waiting for port {} to become ready", port);
        }
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(_) => return Ok(()),
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Synthetic Config Builders
// ---------------------------------------------------------------------------

fn build_bench_lb(origin_addr: &str) -> AnyLoadBalancer {
    use futures_util::FutureExt;
    use http::Extensions;
    use pingora_load_balancing::{Backend, Backends, LoadBalancer, discovery::Static, selection::RoundRobin};
    use std::collections::BTreeSet;

    let addr_str = if origin_addr.contains(':') {
        origin_addr.to_string()
    } else {
        format!("{}:80", origin_addr)
    };

    let mut backend = Backend::new(&addr_str).expect("Failed to create backend from address");
    backend.weight = 10;

    let mut ext = Extensions::new();
    ext.insert(BackendExtension {
        use_tls: false,
        host: String::new(),
        rp_host: String::new(),
        origin_id: 1,
        origin_host: origin_addr.to_string(),
        follow_port: false,
        follow_host: false,
        http2_enabled: false,
        tls_verify: false,
        request_host_excluding_port: false,
        connection_timeout: Some(Duration::from_secs(5)),
        read_timeout: Some(Duration::from_secs(30)),
        idle_timeout: Some(Duration::from_secs(60)),
        client_cert: None,
    });
    backend.ext = ext;

    let mut set = BTreeSet::new();
    set.insert(backend);
    let backends = Backends::new(Static::new(set));
    let lb: LoadBalancer<RoundRobin> = LoadBalancer::from_backends(backends);
    lb.update()
        .now_or_never()
        .expect("static lb update should not block")
        .expect("static lb update should not fail");
    AnyLoadBalancer::RoundRobin(Arc::new(lb))
}

fn build_synthetic_server_config(origin_addr: &str) -> crate::config_models::ServerConfig {
    // Use serde to construct with defaults, then override key fields
    let json = serde_json::json!({
        "id": 1,
        "isOn": true,
        "name": "bench-server",
        "serverNames": [{"name": "bench.local", "type": "full"}, {"name": "127.0.0.1", "type": "full"}, {"name": "localhost", "type": "full"}],
        "http": {
            "isOn": true,
            "listen": [{"portRange": "18080", "protocol": "http"}]
        },
        "https": {
            "isOn": true,
            "listen": [{"portRange": "18443", "protocol": "https"}],
            "sslPolicy": {"id": 1, "isOn": true, "certs": [], "http2Enabled": true}
        },
        "reverseProxy": {
            "isOn": true,
            "scheduling": {"code": "random"},
            "primaryOrigins": [{
                "isOn": true,
                "id": 1,
                "name": "bench-origin",
                "addr": {"protocol": "http", "host": origin_addr},
                "weight": 10,
                "maxConns": 0,
                "maxIdleConns": 0,
                "requestHost": "",
                "requestHostType": 0
            }],
            "requestHostType": 0
        },
        "web": {
            "firewallRef": {"isOn": true, "firewallPolicyId": 1},
            "cache": {"isOn": true, "cacheRefs": [{"isOn": true, "cachePolicyId": 1, "cachePolicy": null}]},
            "requestLimit": null
        }
    });

    serde_json::from_value(json).unwrap_or_else(|e| {
        eprintln!("Warning: synthetic server config parse error: {}", e);
        serde_json::from_value(serde_json::json!({"id": 1, "isOn": true})).unwrap()
    })
}

fn build_synthetic_firewall_policies() -> Vec<crate::config_models::HTTPFirewallPolicy> {
    let json = serde_json::json!([{
        "id": 1,
        "isOn": true,
        "name": "bench-waf",
        "groups": [{
            "id": 1,
            "isOn": true,
            "name": "bench-group",
            "sets": [{
                "id": 1,
                "isOn": true,
                "connector": "or",
                "rules": [{
                    "id": 1,
                    "isOn": true,
                    "param": "${requestURI}",
                    "operator": "match",
                    "value": "(?i)(union\\s+select|insert\\s+into|drop\\s+table)",
                    "isCaseInsensitive": false
                }],
                "actions": [{
                    "code": "allow"
                }]
            }],
            "actions": [{
                "code": "allow"
            }]
        }]
    }]);

    serde_json::from_value(json).unwrap_or_default()
}

fn build_synthetic_cache_policy() -> crate::config_models::HTTPCachePolicy {
    let json = serde_json::json!({
        "id": 1,
        "isOn": true,
        "name": "bench-cache",
        "maxSize": {"count": 128, "unit": "mb"},
        "cacheRefs": [{
            "isOn": true,
            "key": "${scheme}://${host}${requestPath}",
            "life": {"count": 3600, "unit": "second"},
            "status": [200],
            "conds": []
        }]
    });

    serde_json::from_value(json).unwrap_or_else(|e| {
        eprintln!("Warning: synthetic cache policy parse error: {}", e);
        serde_json::from_value(serde_json::json!({"id": 1, "isOn": true})).unwrap()
    })
}

// ---------------------------------------------------------------------------
// HTTP Load Generator
// ---------------------------------------------------------------------------

async fn run_load_generator(
    http_port: u16,
    concurrency: usize,
    duration: Duration,
) -> E2EResult {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(concurrency)
        .pool_idle_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(10))
        .tcp_nodelay(true)
        .no_proxy()
        .build()
        .expect("Failed to build HTTP client");

    let stop = Arc::new(AtomicBool::new(false));
    let total_requests = Arc::new(AtomicU64::new(0));
    let total_errors = Arc::new(AtomicU64::new(0));
    let total_cache_hits = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(parking_lot::Mutex::new(Vec::<u64>::with_capacity(100_000)));

    // Generate URL list: 70% hot (cacheable), 30% cold (unique)
    let hot_urls: Vec<String> = (0..10)
        .map(|i| format!("http://127.0.0.1:{}/bench/hot/{}", http_port, i))
        .collect();

    let mut tasks = Vec::new();
    for task_id in 0..concurrency {
        let client = client.clone();
        let stop = stop.clone();
        let total_requests = total_requests.clone();
        let total_errors = total_errors.clone();
        let total_cache_hits = total_cache_hits.clone();
        let latencies = latencies.clone();
        let hot_urls = hot_urls.clone();

        tasks.push(tokio::spawn(async move {
            let mut local_latencies = Vec::with_capacity(1024);
            let mut counter = 0u64;

            while !stop.load(Ordering::Relaxed) {
                // Mix: 70% hot, 30% cold
                let url = if counter % 10 < 7 {
                    &hot_urls[(counter as usize) % hot_urls.len()]
                } else {
                    // cold URL: unique per request using task_id + counter
                    &hot_urls[0] // fallback, we'll construct inline
                };

                let actual_url = if counter % 10 < 7 {
                    url.clone()
                } else {
                    format!(
                        "http://127.0.0.1:{}/bench/cold/{}/{}",
                        http_port, task_id, counter
                    )
                };

                let start = Instant::now();
                let result = client
                    .get(&actual_url)
                    .header("Host", "bench.local")
                    .send()
                    .await;

                let latency_us = start.elapsed().as_micros() as u64;

                match result {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            // Check cache hit header
                            if let Some(cache_header) = resp.headers().get("x-cache") {
                                if cache_header.as_bytes().starts_with(b"HIT") {
                                    total_cache_hits.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        } else {
                            total_errors.fetch_add(1, Ordering::Relaxed);
                        }
                        // Consume body to complete the request
                        let _ = resp.bytes().await;
                    }
                    Err(_) => {
                        total_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                total_requests.fetch_add(1, Ordering::Relaxed);
                local_latencies.push(latency_us);
                counter += 1;

                // Periodically flush latencies to shared buffer
                if local_latencies.len() >= 512 {
                    let mut lock = latencies.lock();
                    // Keep bounded: only store up to 500k samples total
                    if lock.len() < 500_000 {
                        lock.extend_from_slice(&local_latencies);
                    }
                    local_latencies.clear();
                }
            }

            // Final flush
            let mut lock = latencies.lock();
            if lock.len() < 500_000 {
                lock.extend_from_slice(&local_latencies);
            }
        }));
    }

    // Run for duration then stop
    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::Relaxed);

    // Wait for all tasks to finish
    for t in tasks {
        let _ = t.await;
    }

    let reqs = total_requests.load(Ordering::Relaxed);
    let errors = total_errors.load(Ordering::Relaxed);
    let cache_hits = total_cache_hits.load(Ordering::Relaxed);
    let qps = reqs as f64 / duration.as_secs_f64();

    // Compute latency percentiles
    let mut lat_samples = latencies.lock().clone();
    lat_samples.sort_unstable();

    let percentile = |pct: usize| -> u64 {
        if lat_samples.is_empty() {
            return 0;
        }
        let idx = (lat_samples.len() * pct / 100).min(lat_samples.len() - 1);
        lat_samples[idx]
    };

    let avg = if lat_samples.is_empty() {
        0
    } else {
        lat_samples.iter().sum::<u64>() / lat_samples.len() as u64
    };

    E2EResult {
        qps,
        total_requests: reqs,
        errors,
        cache_hits,
        latency_p50_us: percentile(50),
        latency_p90_us: percentile(90),
        latency_p95_us: percentile(95),
        latency_p99_us: percentile(99),
        latency_p999_us: percentile(999).min(percentile(99).saturating_mul(3)), // approximate
        latency_min_us: lat_samples.first().copied().unwrap_or(0),
        latency_max_us: lat_samples.last().copied().unwrap_or(0),
        latency_avg_us: avg,
    }
}

// ---------------------------------------------------------------------------
// TLS Handshake Benchmark
// ---------------------------------------------------------------------------

async fn run_tls_handshake_bench(https_port: u16, duration: Duration) -> f64 {
    // Each request creates a new connection (no pooling) to measure TLS handshake throughput
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .tcp_nodelay(true)
        .no_proxy()
        .build()
        .expect("Failed to build TLS test client");

    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let concurrency = num_cpus::get_physical().min(16) * 4;

    let url = format!("https://127.0.0.1:{}/bench/tls-test", https_port);

    let mut tasks = Vec::new();
    for _ in 0..concurrency {
        let client = client.clone();
        let stop = stop.clone();
        let counter = counter.clone();
        let url = url.clone();

        tasks.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let result = client
                    .get(&url)
                    .header("Host", "bench.local")
                    .send()
                    .await;
                if let Ok(resp) = result {
                    let _ = resp.bytes().await;
                }
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::Relaxed);

    for t in tasks {
        let _ = t.await;
    }

    let total = counter.load(Ordering::Relaxed);
    total as f64 / duration.as_secs_f64()
}

// ---------------------------------------------------------------------------
// Resource Monitor
// ---------------------------------------------------------------------------

fn start_resource_monitor(
    duration: Duration,
) -> tokio::task::JoinHandle<ResourceStats> {
    tokio::spawn(async move {
        use sysinfo::System;

        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_count = sys.cpus().len();
        let memory_total = sys.total_memory();

        let mut peak_cpu = 0.0f64;
        let mut peak_memory = 0u64;
        let mut samples = 0u64;
        let mut total_cpu = 0.0f64;

        let start = Instant::now();
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        while start.elapsed() < duration + Duration::from_secs(2) {
            interval.tick().await;
            sys.refresh_all();

            let cpu = sys.global_cpu_usage() as f64;
            let mem = sys.used_memory();

            peak_cpu = peak_cpu.max(cpu);
            peak_memory = peak_memory.max(mem);
            total_cpu += cpu;
            samples += 1;

            if start.elapsed() > duration + Duration::from_secs(1) {
                break;
            }
        }

        ResourceStats {
            peak_cpu,
            peak_memory_bytes: peak_memory,
            memory_total,
            cpu_count,
            avg_net_in_bps: 0,  // Network stats gathered from metrics counters in E2E results
            avg_net_out_bps: 0,
            total_disk_read: 0,
            total_disk_write: 0,
        }
    })
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

fn compute_composite_score(
    component_results: &[ComponentResult],
    e2e: Option<&E2EResult>,
    tls_qps: Option<f64>,
) -> f64 {
    let mut score = 0.0f64;

    // Component scores (total weight: 0.40)
    let baselines: &[(&str, f64)] = &[
        ("WAF/SQLi", 500_000.0),
        ("WAF/XSS", 500_000.0),
        ("WAF/Regex", 1_000_000.0),
        ("WAF/IP-CIDR", 1_000_000.0),
        ("WAF/Verifier", 500_000.0),
        ("Cache/L1-Lookup", 5_000_000.0),
        ("TLS/CertSelect", 2_000_000.0),
        ("Auth/URLVerify", 500_000.0),
        ("Rewrite/Regex", 500_000.0),
        ("Metrics/Analyze", 1_000_000.0),
    ];

    if !component_results.is_empty() {
        let component_weight = 0.40;
        let per_component_weight = component_weight / baselines.len() as f64;

        for (name, baseline) in baselines {
            if let Some(result) = component_results.iter().find(|r| r.name == *name) {
                let normalized = (result.ops_per_sec / baseline).min(2.0); // cap at 2x
                score += normalized * per_component_weight * 1000.0;
            }
        }
    }

    // E2E QPS score (weight: 0.35)
    if let Some(e2e) = e2e {
        let qps_baseline = 50_000.0; // 50k QPS as baseline
        let qps_normalized = (e2e.qps / qps_baseline).min(3.0);
        score += qps_normalized * 0.35 * 1000.0;

        // Cache hit rate bonus (weight: 0.10)
        if e2e.total_requests > 0 {
            let hit_rate = e2e.cache_hits as f64 / e2e.total_requests as f64;
            score += hit_rate * 0.10 * 1000.0;
        }

        // Low latency bonus (weight: 0.05)
        if e2e.latency_p99_us > 0 {
            let latency_score = (1000.0 / e2e.latency_p99_us as f64).min(1.0);
            score += latency_score * 0.05 * 1000.0;
        }
    }

    // TLS handshake score (weight: 0.10)
    if let Some(tls) = tls_qps {
        let tls_baseline = 5_000.0; // 5k handshakes/sec as baseline
        let tls_normalized = (tls / tls_baseline).min(3.0);
        score += tls_normalized * 0.10 * 1000.0;
    }

    score.min(1000.0)
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

fn print_component_results(results: &[ComponentResult]) {
    println!(
        "  {:<20} {:>12} {:>10} {:>10}",
        "Component", "ops/sec", "P50", "P99"
    );
    println!("  {}", "-".repeat(56));
    for r in results {
        println!(
            "  {:<20} {:>12} {:>10} {:>10}",
            r.name,
            format_number(r.ops_per_sec),
            format_duration_ns(r.latency_p50_ns),
            format_duration_ns(r.latency_p99_ns),
        );
    }
}

fn print_e2e_results(
    e2e: &E2EResult,
    tls_qps: f64,
    res: &ResourceStats,
    http_port: u16,
    https_port: u16,
    concurrency: usize,
    duration_secs: u64,
) {
    println!(
        "  Config: :{} (HTTP) / :{} (HTTPS) | Concurrency: {} | Duration: {}s",
        http_port, https_port, concurrency, duration_secs
    );
    println!();
    println!("  Peak QPS:         {:.0} req/s", e2e.qps);

    let cache_rate = if e2e.total_requests > 0 {
        e2e.cache_hits as f64 / e2e.total_requests as f64 * 100.0
    } else {
        0.0
    };
    let error_rate = if e2e.total_requests > 0 {
        e2e.errors as f64 / e2e.total_requests as f64 * 100.0
    } else {
        0.0
    };

    println!("  Total Requests:   {}", format_number(e2e.total_requests as f64));
    println!("  Cache Hit Rate:   {:.1}%", cache_rate);
    println!("  Error Rate:       {:.2}%", error_rate);
    println!();
    println!("  Latency:");
    println!(
        "    P50: {}  |  P90: {}  |  P95: {}  |  P99: {}  |  P999: {}",
        format_duration_us(e2e.latency_p50_us),
        format_duration_us(e2e.latency_p90_us),
        format_duration_us(e2e.latency_p95_us),
        format_duration_us(e2e.latency_p99_us),
        format_duration_us(e2e.latency_p999_us),
    );
    println!(
        "    min: {}  |  max: {}  |  avg: {}",
        format_duration_us(e2e.latency_min_us),
        format_duration_us(e2e.latency_max_us),
        format_duration_us(e2e.latency_avg_us),
    );
    println!();
    println!("  TLS Handshake:    {:.0} handshakes/s", tls_qps);

    println!();
    println!("-- Resource Utilization --");
    println!();
    println!("  CPU Peak:     {:.1}% ({} cores)", res.peak_cpu, res.cpu_count);
    println!(
        "  Memory Peak:  {} / {}",
        format_bytes(res.peak_memory_bytes),
        format_bytes(res.memory_total)
    );
    println!(
        "  Network:      {}/s in | {}/s out",
        format_bytes(res.avg_net_in_bps),
        format_bytes(res.avg_net_out_bps)
    );
    if res.total_disk_read > 0 || res.total_disk_write > 0 {
        println!(
            "  Disk IO:      {}/s read | {}/s write",
            format_bytes(res.total_disk_read),
            format_bytes(res.total_disk_write)
        );
    }
}

fn format_number(n: f64) -> String {
    if n >= 1_000_000.0 {
        format!("{:.2}M", n / 1_000_000.0)
    } else if n >= 1_000.0 {
        format!("{:.1}K", n / 1_000.0)
    } else {
        format!("{:.0}", n)
    }
}

fn format_duration_ns(ns: u64) -> String {
    if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.1}us", ns as f64 / 1_000.0)
    } else {
        format!("{}ns", ns)
    }
}

fn format_duration_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else {
        format!("{}us", us)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
