/// Defense-enabled bench node: full EdgeProxy + HttpProxyManager accept-path
/// L4 defense, plus UdpProxyManager / TcpProxyManager for L4 flood testing.
///
/// Topology (defaults, env-overridable):
///   HTTP  :8080  hosts plain.bench|127.0.0.1|localhost, waf.bench, cc.bench, uam.bench
///   HTTPS :8443  (plain.bench cert; TLS-exhaustion/probe defense tests)
///   TCP   :9000  L4 relay -> origin :8081
///   UDP   :8053  L4 relay -> UDP echo :8054 (spawned by the test script)
///
/// Cluster policy (node cluster 1): empty_connection_flood +
/// tls_exhaustion_attack + syn_flood — see env knobs below.
///
/// Kernel offload validation: BENCH_KERNEL_FILTER=auto|xdp|nftables|iptables|off
/// selects the kernel filter backend (auto = production behavior). Every
/// L4METRICS dump includes kernel_filter/xdp/kernel_sync sections so the
/// matrix can attribute blocks to userspace vs kernel dataplanes.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cloud_node_rust::api_config::{AccessLogPipelineConfig, ApiConfig};
use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::config_models::*;
use cloud_node_rust::firewall::state::WafStateManager;
use cloud_node_rust::firewall::verifier::WafVerifier;
use cloud_node_rust::lb_factory;
use cloud_node_rust::proxy::EdgeProxy;
use cloud_node_rust::ssl::DynamicCertSelector;
use pingora_core::server::configuration::ServerConf;
use serde_json::{Value, json};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const SECRET: &str = "bench-defense-secret";
const CLUSTER_ID: i64 = 1;
const DEFENSE_POLICY_ID: i64 = 9001;

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_i32(name: &str, default: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
fn env_str(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .try_init();

    let http_port = env_u16("BENCH_DEFENSE_HTTP_PORT", 8080);
    let tls_port = env_u16("BENCH_DEFENSE_TLS_PORT", 8443);
    let tcp_port = env_u16("BENCH_DEFENSE_TCP_PORT", 9000);
    let udp_port = env_u16("BENCH_DEFENSE_UDP_PORT", 8053);
    let origin_http = env_str("BENCH_ORIGIN_HTTP", "127.0.0.1:8081");
    let origin_udp = env_str("BENCH_ORIGIN_UDP", "127.0.0.1:8054");

    let cc_per_ip_qps = env_i32("BENCH_CC_PER_IP_QPS", 500);
    let cc_block_secs = env_i32("BENCH_CC_BLOCK_SECS", 30);
    let uam_mode = env_str("BENCH_UAM_MODE", "js_cookie");
    let l4_threshold = env_u32("BENCH_L4_EMPTY_THRESHOLD", 200);
    let l4_period = env_i32("BENCH_L4_PERIOD", 10);
    let l4_block_secs = env_i32("BENCH_L4_BLOCK_SECS", 30);
    let tls_fail_threshold = env_u32("BENCH_TLS_FAIL_THRESHOLD", 32);
    let syn_min_attempts = env_u32("BENCH_SYN_MIN_ATTEMPTS", 100);
    // Kernel offload dataplane selection: auto (production behavior),
    // xdp / nftables / iptables to force a specific backend, off to disable.
    let kernel_filter_mode = env_str("BENCH_KERNEL_FILTER", "auto");

    cloud_node_rust::utils::time::init_local_timezone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build bench-defense runtime")?;
    let _guard = runtime.enter();

    cloud_node_rust::metrics::init_http_dimension_worker(10_000);
    cloud_node_rust::proxy::start_request_limit_cleanup_task();
    cloud_node_rust::kernel_syn_defense::start_monitor();

    let config_store = Arc::new(ConfigStore::new());
    cloud_node_rust::kernel_syn_defense::start_synproxy_reconciler(config_store.clone());
    let waf_state = Arc::new(WafStateManager::new());
    waf_state.install_kernel_snapshot_provider();
    let kernel_filter_status = if kernel_filter_mode == "off" {
        cloud_node_rust::firewall::kernel::KernelFilterStatus {
            name: "disabled",
            available: false,
            detail: "BENCH_KERNEL_FILTER=off".to_string(),
        }
    } else {
        let filter =
            runtime.block_on(cloud_node_rust::firewall::kernel::build_filter(Some(
                &kernel_filter_mode,
            )));
        let status = filter.status();
        waf_state.set_kernel_filter(filter);
        status
    };
    info!(
        "kernel offload filter: mode={} name={} available={} detail={}",
        kernel_filter_mode,
        kernel_filter_status.name,
        kernel_filter_status.available,
        kernel_filter_status.detail,
    );
    cloud_node_rust::firewall::state::start_gc_task(waf_state.clone());
    cloud_node_rust::metrics::storage::start_cache_access_flusher();
    cloud_node_rust::metrics::start_pressure_updater();

    let api_config = Arc::new(ApiConfig {
        rpc_endpoints: vec!["http://127.0.0.1:1".to_string()],
        rpc_disable_update: true,
        node_id: "1".to_string(),
        secret: SECRET.to_string(),
        billing_count_inbound_traffic: false,
        access_log_pipeline: AccessLogPipelineConfig::default(),
        relay: Default::default(),
        kernel_tuning: Default::default(),
    });
    let cert_selector = Arc::new(DynamicCertSelector::new());

    // Inject the bench TLS cert into the selector so the :8443 listener can
    // terminate TLS (drives the TLS-exhaustion / probe defense paths).
    let cert_path = env_str("BENCH_TLS_CERT", "/srv/perf-tls/cert.pem");
    let key_path = env_str("BENCH_TLS_KEY", "/srv/perf-tls/key.pem");
    if let (Ok(cert), Ok(key)) = (
        std::fs::read_to_string(&cert_path),
        std::fs::read_to_string(&key_path),
    ) {
        let certs = vec![SSLCertConfig {
            id: 1,
            is_on: true,
            is_default: true,
            cert_data_json: Some(Value::String(cert)),
            key_data_json: Some(Value::String(key)),
            dns_names: vec![
                "*.bench".to_string(),
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ],
        }];
        runtime.block_on(cloud_node_rust::ssl::sync_certs(&cert_selector, &certs));
    } else {
        error!("TLS cert/key unreadable ({cert_path}/{key_path}); :{tls_port} will fail to start");
    }

    let servers_cfg = build_servers(
        http_port,
        tls_port,
        tcp_port,
        udp_port,
        &origin_http,
        &origin_udp,
        cc_per_ip_qps,
        cc_block_secs,
        &uam_mode,
    );

    let mut servers = HashMap::new();
    let mut routes = HashMap::new();
    let mut id_to_lb = HashMap::new();
    let mut all_servers = Vec::new();
    for server in servers_cfg {
        let lb = lb_factory::build_lb(
            server.numeric_id(),
            server
                .reverse_proxy
                .as_ref()
                .context("bench-defense server missing reverse proxy")?,
            1,
            &HashMap::new(),
            false,
            true,
        )
        .0;
        let server = Arc::new(server);
        id_to_lb.insert(server.numeric_id(), lb.clone());
        for name in server.get_plain_server_names() {
            servers.insert(name.clone(), server.clone());
            routes.insert(name, lb.clone());
        }
        all_servers.push(server);
    }

    let cluster_policy = HTTPFirewallPolicy {
        id: DEFENSE_POLICY_ID,
        is_on: true,
        name: "bench l4 cluster defense".to_string(),
        inbound: None,
        outbound: None,
        empty_connection_flood: Some(EmptyConnectionFloodConfig {
            is_on: true,
            max_empty_connections: l4_threshold,
            period: l4_period,
            block_seconds: l4_block_secs,
        }),
        tls_exhaustion_attack: Some(TLSExhaustionAttackConfig {
            is_on: true,
            max_handshake_fails: tls_fail_threshold,
            period: l4_period,
            block_seconds: l4_block_secs,
        }),
        cc_config: None,
        block_options: None,
        page_options: None,
        captcha_options: None,
        js_cookie_options: None,
        max_request_body_size: 0,
        deny_country_html: String::new(),
        deny_province_html: String::new(),
        use_local_firewall: false,
        syn_flood: Some(SynFloodConfig {
            is_on: true,
            min_attempts: syn_min_attempts,
            timeout_seconds: l4_period,
            ignore_local: false,
            is_prior: false,
        }),
        mode: "defense".to_string(),
        candidate_rules: None,
        candidate_traffic_pct: 0,
        candidate_version: 0,
    };

    runtime.block_on(config_store.update_config(
        1,
        1,
        0,
        CLUSTER_ID,
        all_servers,
        servers,
        routes,
        id_to_lb,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        0,
        1,
        true,
        true,
        HashMap::new(),
        false,
        false,
        "random".to_string(),
        HashMap::new(),
        None,
        true,
        false,
        "bench-defense".to_string(),
        false,
        false,
        0,
        true,
        false,
        false,
        String::new(),
        None,
        Some(GlobalHTTPAllConfig {
            allow_lan_ip: true,
            server_name: "bench-defense".to_string(),
            ..Default::default()
        }),
        Vec::new(),
        vec![cluster_policy],
        Vec::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        None,
        None,
    ));

    let proxy_logic = EdgeProxy {
        config: config_store.clone(),
        waf_state: waf_state.clone(),
        api_config: api_config.clone(),
        cert_selector: cert_selector.clone(),
        waf_verifier: Arc::new(WafVerifier::new(SECRET)),
        tls_downstream: false,
    };

    let server_conf = Arc::new(ServerConf {
        threads: num_cpus::get(),
        grace_period_seconds: Some(1),
        graceful_shutdown_timeout_seconds: Some(1),
        ..Default::default()
    });

    let http_manager = cloud_node_rust::http_proxy_manager::HttpProxyManager::new(
        (*config_store).clone(),
        cert_selector.clone(),
        proxy_logic.clone(),
        server_conf.clone(),
    );
    runtime.spawn(async move { http_manager.start_listeners().await });

    let tcp_manager = cloud_node_rust::tcp_proxy::TcpProxyManager::new(
        (*config_store).clone(),
        cert_selector.clone(),
        waf_state.clone(),
        1,
    );
    runtime.spawn(async move { tcp_manager.start_listeners().await });

    let udp_manager = cloud_node_rust::udp_proxy::UdpProxyManager::new(
        (*config_store).clone(),
        waf_state.clone(),
        1,
    );
    runtime.spawn(async move { udp_manager.start_listeners().await });

    // Periodic defense-metrics dump: parsed by run_defense_matrix.sh.
    runtime.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let l4 = cloud_node_rust::l4_defense::metrics_snapshot();
            let syn = cloud_node_rust::kernel_syn_defense::snapshot();
            let kernel = waf_state.kernel_filter_status();
            let xdp = cloud_node_rust::xdp::status_snapshot();
            let pipeline = cloud_node_rust::pipeline_metrics::snapshot();
            eprintln!(
                "L4METRICS {}",
                json!({
                    "events_total": l4.events_total,
                    "blocked_total": l4.blocked_total,
                    "already_blocked_total": l4.already_blocked_total,
                    "active_limit_total": l4.active_limit_total,
                    "admission_reject_total": l4.admission_reject_total,
                    "slow_close_total": l4.slow_close_total,
                    "prefix_blocked_total": l4.prefix_blocked_total,
                    "pressure": cloud_node_rust::l4_defense::current_pressure_level().as_str(),
                    "syn_overflows": syn.listen_overflows_delta,
                    "syn_drops": syn.listen_drops_delta,
                    "syncookies_sent": syn.syncookies_sent_delta,
                    "syn_pressure": syn.pressure_level.as_str(),
                    "kernel_filter": {
                        "name": kernel.name,
                        "available": kernel.available,
                        "detail": kernel.detail,
                    },
                    "xdp": {
                        "enabled": xdp.enabled,
                        "attached": xdp.attached,
                        "attach_mode": xdp.attach_mode,
                        "fallback": xdp.fallback,
                        "fallback_reason": xdp.fallback_reason,
                        "packets": xdp.packets,
                        "pass": xdp.pass,
                        "drop": xdp.drop,
                        "redirect": xdp.redirect,
                        "parse_errors": xdp.parse_errors,
                        "map_miss": xdp.map_miss,
                        "xsk_drops": xdp.xsk_drops,
                        "rate_limited": xdp.rate_limited,
                        "ratelimit_map_full": xdp.ratelimit_map_full,
                        "rate_limit_active": xdp.rate_limit_active,
                        "rate_limit_detail": xdp.rate_limit_detail,
                        "blocked_v4": xdp.exact_blocked_v4,
                        "blocked_v6": xdp.exact_blocked_v6,
                    },
                    "kernel_sync": {
                        "coalesced": pipeline.kernel_sync_coalesced,
                        "reconcile_requested": pipeline.kernel_sync_reconcile_requested,
                        "failed": pipeline.kernel_sync_failed,
                        "xdp_map_sync_failed": pipeline.xdp_map_sync_failed,
                    },
                })
            );
        }
    });

    info!(
        "bench-defense ready: http :{http_port} tls :{tls_port} tcp :{tcp_port} udp :{udp_port} -> origin {origin_http} cc_per_ip_qps={cc_per_ip_qps} l4_empty_threshold={l4_threshold}/{l4_period}s block={l4_block_secs}s tls_fail={tls_fail_threshold} uam_mode={uam_mode}"
    );
    runtime.block_on(std::future::pending::<()>());
    Ok(())
}

fn build_servers(
    http_port: u16,
    tls_port: u16,
    tcp_port: u16,
    udp_port: u16,
    origin_http: &str,
    origin_udp: &str,
    cc_per_ip_qps: i32,
    cc_block_secs: i32,
    uam_mode: &str,
) -> Vec<ServerConfig> {
    let mut out = Vec::new();

    // 100 — plain (no WAF): carries all listeners incl. TLS/TCP.
    let mut plain = bench_server(100, &["127.0.0.1", "localhost", "plain.bench"], origin_http);
    plain.http = Some(http_listen(http_port));
    plain.https = Some(https_listen(tls_port));
    plain.tcp = Some(TCPConfig {
        is_on: true,
        listen: vec![listen_addr(tcp_port)],
        tls: None,
    });
    out.push(plain);

    // 101 — waf.bench: block /deny* and UA containing "attackbot".
    let mut waf = bench_server(101, &["waf.bench"], origin_http);
    waf.http = Some(http_listen(http_port));
    let mut waf_web = base_web();
    waf_web.firewall_ref = Some(HTTPFirewallRef {
        is_on: true,
        ignore_global_rules: false,
        default_captcha_type: String::new(),
        id: 0,
    });
    waf_web.firewall_policy = Some(waf_block_policy());
    waf.web = Some(waf_web);
    out.push(waf);

    // 102 — cc.bench: per-IP QPS CC policy (429 + block_ip).
    let mut cc = bench_server(102, &["cc.bench"], origin_http);
    cc.http = Some(http_listen(http_port));
    let mut cc_web = base_web();
    cc_web.cc_policy = Some(CCPolicy {
        is_on: true,
        max_qps: 0,
        per_ip_max_qps: cc_per_ip_qps,
        max_bandwidth: 0.0,
        show_page: true,
        block_ip: true,
        page_duration: 5,
        block_ip_duration: cc_block_secs,
        no_log: true,
    });
    cc.web = Some(cc_web);
    out.push(cc);

    // 103 — uam.bench: UAM challenge (js_cookie default).
    let mut uam = bench_server(103, &["uam.bench"], origin_http);
    uam.http = Some(http_listen(http_port));
    let mut uam_web = base_web();
    uam_web.uam = Some(UAMConfig {
        is_on: true,
        key_life: 3600,
        mode: Some(uam_mode.to_string()),
        pow_difficulty: Some(5),
        ..Default::default()
    });
    uam.web = Some(uam_web);
    out.push(uam);

    // 104 — udp.bench: UDP relay -> echo upstream.
    let mut udp = bench_server(104, &["udp.bench"], origin_udp);
    udp.udp = Some(UDPConfig {
        is_on: true,
        listen: vec![listen_addr(udp_port)],
    });
    out.push(udp);

    out
}

fn listen_addr(port: u16) -> NetworkAddressConfig {
    NetworkAddressConfig {
        protocol: None,
        host: Some("0.0.0.0".to_string()),
        port_range: Some(port.to_string()),
    }
}
fn http_listen(port: u16) -> HTTPConfig {
    HTTPConfig {
        is_on: true,
        listen: vec![listen_addr(port)],
    }
}
fn https_listen(port: u16) -> HTTPSConfig {
    HTTPSConfig {
        is_on: true,
        listen: vec![listen_addr(port)],
        ssl_policy: None,
        supports_http3: Some(false),
    }
}

fn bench_server(id: i64, names: &[&str], upstream: &str) -> ServerConfig {
    ServerConfig {
        id: Some(id),
        description: format!("bench-defense {id}"),
        user_id: 1,
        cluster_id: CLUSTER_ID,
        is_on: true,
        server_names: names
            .iter()
            .map(|name| ServerNameConfig {
                name: (*name).to_string(),
                r#type: None,
                sub_names: Vec::new(),
            })
            .collect(),
        http: None,
        https: None,
        tcp: None,
        udp: None,
        web: Some(base_web()),
        reverse_proxy: Some(ReverseProxyConfig {
            is_on: true,
            primary_origins: vec![OriginConfig {
                id: 2000 + id,
                name: "bench origin".to_string(),
                addr: Some(FlexibleAddr::String(format!("http://{upstream}"))),
                is_on: true,
                weight: 1,
                health_check: None,
                request_host: String::new(),
                follow_host: true,
                follow_port: false,
                http2_enabled: false,
                http3_enabled: false,
                conn_timeout: None,
                read_timeout: None,
                idle_timeout: None,
                write_timeout: None,
                cert: None,
                tls_security_verify_mode: OriginTlsSecurityVerifyMode::Auto,
                tls_verify: None,
                oss: None,
            }],
            backup_origins: Vec::new(),
            scheduling: Some(SchedulingConfig {
                code: "roundRobin".to_string(),
                options: Value::Null,
            }),
            request_host: String::new(),
            request_host_type: 0,
            request_host_excluding_port: false,
            proxy_protocol: ProxyProtocolConfig::default(),
        }),
        http_firewall_policy_id: DEFENSE_POLICY_ID,
        ..Default::default()
    }
}

fn base_web() -> WebConfig {
    WebConfig {
        is_on: true,
        redirect_to_https: None,
        remote_addr: None,
        request_limit: None,
        cache: None,
        firewall_ref: None,
        firewall_policy: None,
        compression: None,
        pages: Vec::new(),
        enable_global_pages: false,
        shutdown: None,
        auth: None,
        websocket: None,
        max_qps: 0,
        uam: None,
        cc_policy: None,
        webp: None,
        user_agent_config: None,
        referer_config: None,
        host_redirects: Vec::new(),
        rewrite_refs: Vec::new(),
        rewrite_rules: Vec::new(),
        request_header_policy: None,
        response_header_policy: None,
        access_log_ref: None,
        charset: None,
        stat_ref: None,
        optimization: None,
        hls: None,
        root: None,
        prefer_www: None,
        trailing_slash: None,
    }
}

fn waf_block_policy() -> HTTPFirewallPolicy {
    HTTPFirewallPolicy {
        id: 9101,
        is_on: true,
        name: "bench waf block".to_string(),
        inbound: Some(HTTPFirewallInboundConfig {
            is_on: true,
            groups: vec![
                HTTPFirewallRuleGroup {
                    id: 1,
                    is_on: true,
                    name: "deny path".to_string(),
                    code: None,
                    sets: vec![HTTPFirewallRuleSet {
                        id: 1,
                        is_on: true,
                        name: "deny /deny prefix".to_string(),
                        rules: vec![HTTPFirewallRule {
                            param: "${requestPath}".to_string(),
                            operator: "prefix".to_string(),
                            value: "/deny".to_string(),
                            checkpoint_options: None,
                            is_reverse: false,
                            is_case_insensitive: false,
                            param_filters: Vec::new(),
                        }],
                        connector: "and".to_string(),
                        actions: vec![json!({"code": "block", "options": {}})],
                        ignore_local: false,
                        ignore_search_engine: false,
                    }],
                },
                HTTPFirewallRuleGroup {
                    id: 2,
                    is_on: true,
                    name: "deny ua".to_string(),
                    code: None,
                    sets: vec![HTTPFirewallRuleSet {
                        id: 1,
                        is_on: true,
                        name: "deny attackbot ua".to_string(),
                        rules: vec![HTTPFirewallRule {
                            param: "${userAgent}".to_string(),
                            operator: "contains".to_string(),
                            value: "attackbot".to_string(),
                            checkpoint_options: None,
                            is_reverse: false,
                            is_case_insensitive: true,
                            param_filters: Vec::new(),
                        }],
                        connector: "and".to_string(),
                        actions: vec![json!({"code": "block", "options": {}})],
                        ignore_local: false,
                        ignore_search_engine: false,
                    }],
                },
            ],
            region: None,
        }),
        outbound: None,
        empty_connection_flood: None,
        tls_exhaustion_attack: None,
        cc_config: None,
        block_options: None,
        page_options: None,
        captcha_options: None,
        js_cookie_options: None,
        max_request_body_size: 0,
        deny_country_html: String::new(),
        deny_province_html: String::new(),
        use_local_firewall: false,
        syn_flood: None,
        mode: "defense".to_string(),
        candidate_rules: None,
        candidate_traffic_pct: 0,
        candidate_version: 0,
    }
}
