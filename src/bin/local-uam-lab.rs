use std::collections::HashMap;
use std::env;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener,
    TcpStream as StdTcpStream,
};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use cloud_node_rust::api_config::{AccessLogPipelineConfig, ApiConfig};
use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::config_models::{
    FlexibleAddr, GlobalHTTPAllConfig, HTTPConfig, HTTPFirewallInboundConfig, HTTPFirewallPolicy,
    HTTPFirewallRef, HTTPFirewallRule, HTTPFirewallRuleGroup, HTTPFirewallRuleSet,
    NetworkAddressConfig, OriginConfig, OriginTlsSecurityVerifyMode, ProxyProtocolConfig,
    ReverseProxyConfig, SchedulingConfig, ServerConfig, ServerNameConfig, UAMConfig,
    WAFCaptchaOptions, WAFJSCookieOptions, WebConfig,
};
use cloud_node_rust::firewall::state::WafStateManager;
use cloud_node_rust::firewall::verifier::WafVerifier;
use cloud_node_rust::lb_factory;
use cloud_node_rust::proxy::EdgeProxy;
use cloud_node_rust::ssl::DynamicCertSelector;
use pingora_core::server::Server;
use pingora_core::server::configuration::ServerConf;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_PROXY_PORT: u16 = 19080;
const DEFAULT_ORIGIN_PORT: u16 = 19081;
const INDEX_HOST: &str = "lab.localhost";
const SECRET: &str = "local-uam-lab-secret";

#[derive(Clone, Copy)]
enum LabKind {
    Uam {
        mode: &'static str,
    },
    Waf {
        action: &'static str,
        method: Option<&'static str>,
    },
}

#[derive(Clone, Copy)]
struct LabEntry {
    host: &'static str,
    title: &'static str,
    desc: &'static str,
    kind: LabKind,
}

const LAB_ENTRIES: &[LabEntry] = &[
    LabEntry {
        host: "uam-pow.localhost",
        title: "UAM PoW Shield",
        desc: "UAM five-second shield / proof-of-work challenge. Sets UAM-Pass for this host only.",
        kind: LabKind::Uam { mode: "pow" },
    },
    LabEntry {
        host: "waf-slider.localhost",
        title: "WAF Slider",
        desc: "WAF captcha action with slider method. Sets WAF-Pass:slider.",
        kind: LabKind::Waf {
            action: "captcha",
            method: Some("slider"),
        },
    },
    LabEntry {
        host: "waf-click.localhost",
        title: "WAF Click",
        desc: "WAF captcha action with click-sequence method. Sets WAF-Pass:click.",
        kind: LabKind::Waf {
            action: "captcha",
            method: Some("click"),
        },
    },
    LabEntry {
        host: "waf-captcha.localhost",
        title: "WAF Captcha",
        desc: "WAF image captcha method. Sets WAF-Pass:captcha.",
        kind: LabKind::Waf {
            action: "captcha",
            method: Some("captcha"),
        },
    },
    LabEntry {
        host: "waf-jscookie.localhost",
        title: "WAF JS Cookie",
        desc: "WAF JavaScript and cookie roundtrip challenge. Sets WAF-Pass:jscookie.",
        kind: LabKind::Waf {
            action: "js_cookie",
            method: None,
        },
    },
    LabEntry {
        host: "waf-geetest.localhost",
        title: "WAF Geetest Random",
        desc: "WAF geetest-compatible random method selection.",
        kind: LabKind::Waf {
            action: "captcha",
            method: Some("geetest"),
        },
    },
    LabEntry {
        host: "waf-302.localhost",
        title: "WAF GET 302",
        desc: "WAF 302 redirect challenge with WAF-Redirect pass cookie.",
        kind: LabKind::Waf {
            action: "get_302",
            method: None,
        },
    },
    LabEntry {
        host: "waf-307.localhost",
        title: "WAF POST 307",
        desc: "WAF 307 redirect challenge with WAF-Redirect pass cookie.",
        kind: LabKind::Waf {
            action: "post_307",
            method: None,
        },
    },
];

fn main() -> anyhow::Result<()> {
    init_logging();

    let proxy_port = env_u16_opt("LOCAL_UAM_PROXY_PORT").unwrap_or_else(|| {
        pick_available_port(&[DEFAULT_PROXY_PORT, 19180, 28080, 38080])
            .unwrap_or(DEFAULT_PROXY_PORT)
    });
    let origin_port = env_u16_opt("LOCAL_UAM_ORIGIN_PORT").unwrap_or_else(|| {
        pick_available_port_excluding(&[DEFAULT_ORIGIN_PORT, 19181, 28081, 38081], proxy_port)
            .unwrap_or(DEFAULT_ORIGIN_PORT)
    });
    let key_life = env_i32("LOCAL_UAM_KEY_LIFE", 3600);
    let pow_difficulty = env_u8("LOCAL_UAM_POW_DIFFICULTY", 5);

    cloud_node_rust::utils::time::init_local_timezone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build local UAM lab runtime")?;
    let _guard = runtime.enter();

    let origin_addr = format!("127.0.0.1:{origin_port}");
    let origin_listener = runtime.block_on(async {
        TcpListener::bind(&origin_addr)
            .await
            .with_context(|| format!("failed to bind local origin {origin_addr}"))
    })?;
    tokio::spawn(run_origin(
        origin_listener,
        origin_addr.clone(),
        proxy_port,
        key_life,
    ));
    cloud_node_rust::metrics::init_http_dimension_worker(10_000);
    cloud_node_rust::proxy::start_request_limit_cleanup_task();

    let config_store = Arc::new(ConfigStore::new());
    let waf_state = Arc::new(WafStateManager::new());
    cloud_node_rust::firewall::state::start_gc_task(waf_state.clone());

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

    let server_configs = build_lab_servers(proxy_port, origin_port, key_life, pow_difficulty);
    let mut servers = HashMap::new();
    let mut routes = HashMap::new();
    let mut id_to_lb = HashMap::new();
    let mut all_servers = Vec::new();

    for server in server_configs {
        let lb = lb_factory::build_lb(
            server.numeric_id(),
            server
                .reverse_proxy
                .as_ref()
                .context("local lab server missing reverse proxy")?,
            1,
            &HashMap::new(),
            false,
            true,
        )
        .0;
        let server = Arc::new(server);
        if server.numeric_id() > 0 {
            id_to_lb.insert(server.numeric_id(), lb.clone());
        }
        for name in server.get_plain_server_names() {
            servers.insert(name.clone(), server.clone());
            routes.insert(name, lb.clone());
        }
        all_servers.push(server);
    }

    runtime.block_on(config_store.update_config(
        1,
        1,
        0,
        0,
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
        false,
        HashMap::new(),
        false,
        false,
        "random".to_string(),
        HashMap::new(),
        None,
        true,
        false,
        "cloud-node-uam-lab".to_string(),
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
            server_name: "cloud-node-uam-lab".to_string(),
            ..Default::default()
        }),
        Vec::new(),
        Vec::new(),
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
        waf_state,
        api_config: api_config.clone(),
        cert_selector: cert_selector.clone(),
        waf_verifier: Arc::new(WafVerifier::new(api_config.secret.as_str())),
        tls_downstream: false,
    };

    let mut server_conf = ServerConf::default();
    server_conf.threads = 2;
    server_conf.grace_period_seconds = Some(1);
    server_conf.graceful_shutdown_timeout_seconds = Some(1);
    let mut pingora_server = Server::new_with_opt_and_conf(None, server_conf);
    pingora_server.bootstrap();
    let mut proxy_service =
        pingora_proxy::http_proxy_service(&pingora_server.configuration, proxy_logic);
    proxy_service.add_tcp(&format!("127.0.0.1:{proxy_port}"));
    proxy_service.add_tcp(&format!("[::1]:{proxy_port}"));
    pingora_server.add_service(proxy_service);

    info!(
        "local UAM lab ready: proxy=http://127.0.0.1:{proxy_port}/ origin=http://{origin_addr}/ index_host={INDEX_HOST}"
    );
    println!();
    println!("Local UAM lab is running.");
    println!("  Index:  http://{INDEX_HOST}:{proxy_port}/");
    println!("  Direct: http://127.0.0.1:{proxy_port}/");
    println!("  Origin: http://{origin_addr}/");
    println!("  Hosts:  *.localhost entries are isolated per challenge mode");
    println!();
    println!("Open the Proxy URL in a browser. Press Ctrl-C to stop.");

    pingora_server.run_forever();
}

fn build_lab_servers(
    proxy_port: u16,
    origin_port: u16,
    key_life: i32,
    pow_difficulty: u8,
) -> Vec<ServerConfig> {
    let mut servers = Vec::with_capacity(LAB_ENTRIES.len() + 1);
    let mut next_id = 1000;

    servers.push(build_server(
        next_id,
        proxy_port,
        origin_port,
        &[INDEX_HOST, "127.0.0.1", "localhost"],
        None,
        None,
    ));
    next_id += 1;

    for entry in LAB_ENTRIES {
        let web = match entry.kind {
            LabKind::Uam { mode } => web_config_with_uam(mode, key_life, pow_difficulty),
            LabKind::Waf { action, method } => web_config_with_waf(action, method, key_life),
        };
        servers.push(build_server(
            next_id,
            proxy_port,
            origin_port,
            &[entry.host],
            Some(web),
            Some(entry.title),
        ));
        next_id += 1;
    }

    servers
}

fn build_server(
    id: i64,
    proxy_port: u16,
    origin_port: u16,
    names: &[&str],
    web: Option<WebConfig>,
    description: Option<&str>,
) -> ServerConfig {
    ServerConfig {
        id: Some(id),
        description: description.unwrap_or("local UAM lab index").to_string(),
        user_id: 1,
        is_on: true,
        server_names: names
            .iter()
            .map(|name| ServerNameConfig {
                name: (*name).to_string(),
                r#type: None,
                sub_names: Vec::new(),
            })
            .collect(),
        http: Some(HTTPConfig {
            is_on: true,
            listen: vec![NetworkAddressConfig {
                protocol: Some("http".to_string()),
                host: Some("127.0.0.1".to_string()),
                port_range: Some(proxy_port.to_string()),
            }],
        }),
        reverse_proxy: Some(ReverseProxyConfig {
            is_on: true,
            primary_origins: vec![OriginConfig {
                id: 2001,
                name: "local origin".to_string(),
                addr: Some(FlexibleAddr::String(format!(
                    "http://127.0.0.1:{origin_port}"
                ))),
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
        web: Some(web.unwrap_or_else(base_web_config)),
        ..Default::default()
    }
}

fn base_web_config() -> WebConfig {
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

fn web_config_with_uam(mode: &str, key_life: i32, pow_difficulty: u8) -> WebConfig {
    let mut web = base_web_config();
    web.uam = Some(UAMConfig {
        is_on: true,
        key_life,
        mode: Some(mode.to_string()),
        pow_difficulty: Some(pow_difficulty),
        ..Default::default()
    });
    web
}

fn web_config_with_waf(action: &str, method: Option<&str>, life_seconds: i32) -> WebConfig {
    let mut web = base_web_config();
    web.firewall_ref = Some(HTTPFirewallRef {
        is_on: true,
        ignore_global_rules: true,
        default_captcha_type: String::new(),
        id: 0,
    });
    web.firewall_policy = Some(waf_policy(action, method, life_seconds));
    web
}

fn waf_policy(action: &str, method: Option<&str>, life_seconds: i32) -> HTTPFirewallPolicy {
    let options = waf_action_options(action, method, life_seconds);
    HTTPFirewallPolicy {
        id: 5000 + stable_id(action, method),
        is_on: true,
        name: format!("local lab {action} {}", method.unwrap_or("")),
        inbound: Some(HTTPFirewallInboundConfig {
            is_on: true,
            groups: vec![HTTPFirewallRuleGroup {
                id: 1,
                is_on: true,
                name: "lab challenge group".to_string(),
                code: None,
                sets: vec![HTTPFirewallRuleSet {
                    id: 1,
                    is_on: true,
                    name: "match all requests".to_string(),
                    rules: vec![HTTPFirewallRule {
                        param: "${requestPath}".to_string(),
                        operator: "prefix".to_string(),
                        value: "/".to_string(),
                        checkpoint_options: None,
                        is_reverse: false,
                        is_case_insensitive: false,
                        param_filters: Vec::new(),
                    }],
                    connector: "and".to_string(),
                    actions: vec![json!({
                        "code": action,
                        "options": options,
                    })],
                    ignore_local: false,
                    ignore_search_engine: false,
                }],
            }],
            region: None,
        }),
        outbound: None,
        empty_connection_flood: None,
        tls_exhaustion_attack: None,
        cc_config: None,
        block_options: None,
        page_options: None,
        captcha_options: Some(WAFCaptchaOptions {
            method: method.unwrap_or("slider").to_string(),
            life_seconds,
            max_fails: 0,
            fail_block_timeout: 60,
            fail_global: false,
            challenge_difficulty: 5,
            challenge_lang: "en".to_string(),
            ..Default::default()
        }),
        js_cookie_options: Some(WAFJSCookieOptions {
            life_seconds,
            max_fails: 0,
            fail_block_timeout: 60,
            fail_global: false,
        }),
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

fn waf_action_options(action: &str, method: Option<&str>, life_seconds: i32) -> Value {
    match action {
        "captcha" => json!({
            "lifeSeconds": life_seconds,
            "maxFails": 0,
            "failBlockTimeout": 60,
            "failGlobal": false,
            "method": method.unwrap_or("slider"),
            "challengeDifficulty": 5,
            "challengeLang": "en",
        }),
        "js_cookie" => json!({
            "lifeSeconds": life_seconds,
            "maxFails": 0,
            "failBlockTimeout": 60,
            "failGlobal": false,
        }),
        "get_302" | "post_307" => json!({
            "lifeSeconds": life_seconds,
            "maxFails": 0,
            "failBlockTimeout": 60,
            "failGlobal": false,
        }),
        _ => json!({}),
    }
}

fn stable_id(action: &str, method: Option<&str>) -> i64 {
    let mut id = 0i64;
    for b in action.bytes().chain(method.unwrap_or("").bytes()) {
        id = id.wrapping_mul(31).wrapping_add(i64::from(b));
    }
    (id.unsigned_abs() % 10_000) as i64
}

async fn run_origin(listener: TcpListener, addr: String, proxy_port: u16, cookie_life: i32) {
    info!("local origin listening on http://{addr}");

    loop {
        let Ok((mut stream, peer)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            let first_line = request.lines().next().unwrap_or("");
            let path = request_path(first_line);
            let raw_host = header_value(&request, "host").unwrap_or("");
            let host = host_without_port(raw_host);
            let cookie_header = header_value(&request, "cookie").unwrap_or("");

            let (status, reason, extra_headers, body) = if path == "/favicon.ico" {
                (204, "No Content", String::new(), String::new())
            } else if path == "/clear" {
                (
                    303,
                    "See Other",
                    format!("location: /\r\n{}", clear_cookie_headers()),
                    String::new(),
                )
            } else if is_index_host(host) {
                (
                    200,
                    "OK",
                    String::new(),
                    render_index_page(proxy_port, cookie_life),
                )
            } else if let Some(entry) = lab_entry_by_host(host) {
                (
                    200,
                    "OK",
                    String::new(),
                    render_entry_page(
                        entry,
                        proxy_port,
                        cookie_life,
                        raw_host,
                        cookie_header,
                        first_line,
                        &peer.to_string(),
                    ),
                )
            } else {
                (
                    404,
                    "Not Found",
                    String::new(),
                    render_unknown_host_page(proxy_port, raw_host, first_line),
                )
            };

            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\n{extra_headers}content-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn render_index_page(proxy_port: u16, cookie_life: i32) -> String {
    let mut rows = String::new();
    for entry in LAB_ENTRIES {
        let kind = match entry.kind {
            LabKind::Uam { mode } => format!("UAM / {mode}"),
            LabKind::Waf { action, method } => match method {
                Some(method) => format!("WAF / {action} / {method}"),
                None => format!("WAF / {action}"),
            },
        };
        rows.push_str(&format!(
            "<tr><td><a href=\"http://{}:{}/\">{}</a></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            entry.host,
            proxy_port,
            html_escape(entry.title),
            html_escape(&kind),
            html_escape(entry.desc),
            entry.host,
        ));
    }

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Cloud Node UAM/WAF Lab</title>{}</head><body><main><h1>Cloud Node UAM/WAF Lab</h1><p class=\"lead\">UAM exposes only the PoW shield entry. WAF exposes the human-verification methods. Each entry uses a separate <code>*.localhost</code> host, so browser cookies are isolated by host and a passed mode keeps its own {} second cookie.</p><section class=\"panel\"><table><thead><tr><th>Entry</th><th>Mode</th><th>Purpose</th><th>Host</th></tr></thead><tbody>{}</tbody></table></section><p class=\"hint\">Open entries in the same browser profile. After verification, the success page means the proxy accepted that host's pass cookie.</p></main></body></html>",
        lab_css(),
        cookie_life.max(1),
        rows,
    )
}

fn render_entry_page(
    entry: LabEntry,
    proxy_port: u16,
    cookie_life: i32,
    raw_host: &str,
    cookie_header: &str,
    first_line: &str,
    peer: &str,
) -> String {
    let kind = match entry.kind {
        LabKind::Uam { mode } => format!("UAM / {mode}"),
        LabKind::Waf { action, method } => match method {
            Some(method) => format!("WAF / {action} / {method}"),
            None => format!("WAF / {action}"),
        },
    };
    let cookies = render_cookie_status(cookie_header);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title>{}</head><body><main><nav><a href=\"http://{}:{}/\">Index</a><a href=\"/clear\">Clear this host cookies</a><a href=\"/\">Refresh</a></nav><section class=\"panel ok\"><div class=\"status\">Verified</div><h1>{}</h1><p class=\"lead\">Origin reached successfully. The proxy accepted this host's pass cookie for <strong>{}</strong>.</p><dl><dt>Host</dt><dd><code>{}</code></dd><dt>Cookie lifetime</dt><dd>{} seconds</dd><dt>Cookies seen by origin</dt><dd>{}</dd><dt>Request</dt><dd><code>{}</code></dd><dt>Peer</dt><dd><code>{}</code></dd></dl></section><p class=\"hint\">This page is served by the local origin after verification. Other lab modes use different hosts, so their pass cookies do not overwrite this one.</p></main></body></html>",
        html_escape(entry.title),
        lab_css(),
        INDEX_HOST,
        proxy_port,
        html_escape(entry.title),
        html_escape(&kind),
        html_escape(raw_host),
        cookie_life.max(1),
        cookies,
        html_escape(first_line),
        html_escape(peer),
    )
}

fn render_unknown_host_page(proxy_port: u16, raw_host: &str, first_line: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Unknown lab host</title>{}</head><body><main><section class=\"panel\"><h1>Unknown lab host</h1><p class=\"lead\">Use the lab index to open one of the configured challenge hosts.</p><dl><dt>Host</dt><dd><code>{}</code></dd><dt>Request</dt><dd><code>{}</code></dd></dl><p><a href=\"http://{}:{}/\">Open lab index</a></p></section></main></body></html>",
        lab_css(),
        html_escape(raw_host),
        html_escape(first_line),
        INDEX_HOST,
        proxy_port,
    )
}

fn render_cookie_status(cookie_header: &str) -> String {
    let names = [
        "UAM-Pass",
        "UAM-Token",
        "WAF-Pass",
        "WAF-Token",
        "WAF-PoW",
        "WAF-Redirect",
    ];
    let mut badges = String::new();
    for name in names {
        if let Some(value) = cookie_value(cookie_header, name) {
            let suffix = value
                .split_once(":type=")
                .map(|(_, kind)| format!(" <small>{}</small>", html_escape(kind)))
                .unwrap_or_default();
            badges.push_str(&format!(
                "<span class=\"badge on\">{}{} </span>",
                html_escape(name),
                suffix,
            ));
        } else {
            badges.push_str(&format!(
                "<span class=\"badge off\">{} </span>",
                html_escape(name),
            ));
        }
    }
    badges
}

fn clear_cookie_headers() -> String {
    [
        "UAM-Pass",
        "UAM-Token",
        "WAF-Pass",
        "WAF-Token",
        "WAF-PoW",
        "WAF-Redirect",
    ]
    .iter()
    .map(|name| format!("set-cookie: {name}=; Max-Age=0; Path=/; SameSite=Lax\r\n"))
    .collect()
}

fn lab_css() -> &'static str {
    "<style>body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;background:#f6f7f9;color:#1f2937}main{max-width:1120px;margin:0 auto;padding:32px 20px}h1{margin:0 0 12px;font-size:30px;line-height:1.15}a{color:#075985;text-decoration:none}a:hover{text-decoration:underline}.lead{font-size:16px;line-height:1.6;color:#374151}.hint{color:#6b7280}.panel{background:#fff;border:1px solid #d8dee8;border-radius:8px;padding:18px;box-shadow:0 1px 2px rgba(15,23,42,.04)}.panel.ok{border-color:#9ed4b4}.status{display:inline-block;margin-bottom:12px;padding:4px 8px;border-radius:6px;background:#e8f7ee;color:#166534;font-size:13px;font-weight:700}table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:11px 10px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}th{background:#f9fafb;color:#4b5563;font-weight:700}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:5px;padding:2px 4px}nav{display:flex;gap:14px;margin-bottom:18px}dl{display:grid;grid-template-columns:160px minmax(0,1fr);gap:10px 16px;margin:18px 0 0}dt{font-weight:700;color:#4b5563}dd{margin:0;min-width:0}.badge{display:inline-block;margin:0 6px 6px 0;padding:4px 7px;border-radius:6px;border:1px solid;font-size:13px}.badge.on{background:#eff6ff;border-color:#93c5fd;color:#1d4ed8}.badge.off{background:#f9fafb;border-color:#e5e7eb;color:#9ca3af}.badge small{color:#475569}@media(max-width:720px){main{padding:20px 12px}table,thead,tbody,tr,th,td{display:block}thead{display:none}tr{border-bottom:1px solid #e5e7eb;padding:10px 0}td{border:0;padding:6px 0}dl{grid-template-columns:1fr}nav{flex-wrap:wrap}}</style>"
}

fn lab_entry_by_host(host: &str) -> Option<LabEntry> {
    LAB_ENTRIES
        .iter()
        .copied()
        .find(|entry| entry.host.eq_ignore_ascii_case(host))
}

fn is_index_host(host: &str) -> bool {
    host.eq_ignore_ascii_case(INDEX_HOST)
        || host.eq_ignore_ascii_case("127.0.0.1")
        || host.eq_ignore_ascii_case("localhost")
}

fn request_path(first_line: &str) -> &str {
    first_line.split_whitespace().nth(1).unwrap_or("/")
}

fn header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    for line in request.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

fn host_without_port(host: &str) -> &str {
    host.trim()
        .trim_end_matches('.')
        .split(':')
        .next()
        .unwrap_or(host)
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    for part in cookies.split(';') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        if key.trim() == name {
            return Some(value.trim());
        }
    }
    None
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(
            "info,cloud_node_rust::proxy=debug,cloud_node_rust::http_proxy_manager=debug",
        )
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}

fn env_u16_opt(name: &str) -> Option<u16> {
    env::var(name).ok().and_then(|value| value.parse().ok())
}

fn pick_available_port(candidates: &[u16]) -> Option<u16> {
    candidates
        .iter()
        .copied()
        .find(|port| port_is_available_for_localhost(*port))
}

fn pick_available_port_excluding(candidates: &[u16], excluded: u16) -> Option<u16> {
    candidates
        .iter()
        .copied()
        .find(|port| *port != excluded && port_is_available_for_localhost(*port))
}

fn port_is_available_for_localhost(port: u16) -> bool {
    // Browsers may resolve *.localhost to ::1 before 127.0.0.1. Avoid a port
    // when either loopback family is already occupied, otherwise the index
    // link can land on an unrelated IPv6 listener.
    if loopback_port_accepts_connections(port) {
        return false;
    }
    let v4 = StdTcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    let v6 = StdTcpListener::bind((IpAddr::V6(Ipv6Addr::LOCALHOST), port));
    v4.is_ok() && v6.is_ok()
}

fn loopback_port_accepts_connections(port: u16) -> bool {
    let timeout = Duration::from_millis(50);
    [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
    ]
    .into_iter()
    .any(|addr| StdTcpStream::connect_timeout(&addr, timeout).is_ok())
}

fn env_i32(name: &str, default: i32) -> i32 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u8(name: &str, default: u8) -> u8 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
