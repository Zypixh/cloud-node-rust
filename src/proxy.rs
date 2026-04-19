use tracing::debug;
use async_trait::async_trait;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::{Error, ErrorType::*, Result};
use pingora_load_balancing::{LoadBalancer, selection::RoundRobin};
use pingora_proxy::{ProxyHttp, Session};
use std::sync::Arc;
use bytes::Bytes;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;

use crate::api_config::ApiConfig;
use crate::cache::should_cache_response;
use crate::cache_manager::CACHE;
use crate::config::ConfigStore;
use crate::config_models::{HTTPCachePolicy, HTTPCacheRef, ServerConfig};
use crate::firewall::state::WafStateManager;
use crate::rewrite::{RewriteResult, evaluate_host_redirects, evaluate_rewrites};
use std::collections::HashMap;

#[derive(Clone)]
pub struct ProxyCTX {
    pub start_time: std::time::Instant,
    pub request_id: String,
    pub server: Option<ServerConfig>,
    pub lb: Option<Arc<LoadBalancer<RoundRobin>>>,
    pub metrics_recorded: bool,
    pub ttfb: Option<std::time::Duration>,
    pub response_status: u16,
    pub cache_policy: Option<HTTPCachePolicy>,
    pub cache_ref: Option<HTTPCacheRef>,
    pub cache_key: Option<String>,
    pub cache_hit: Option<bool>,
    pub cacheable: bool,
    pub response_headers: HashMap<String, String>,
    pub response_body_len: usize,
    pub response_body_buffer: Vec<u8>,
    pub request_body: Vec<u8>,
    pub waf_policy_id: i64,
    pub waf_group_id: i64,
    pub waf_set_id: i64,
    pub waf_action: Option<String>,
    pub compress_zstd: bool,
    pub compression_type: Option<String>,
    pub compression_level: i8,
    pub custom_page_body: Option<String>,
    pub custom_page_status: u16,
    pub is_websocket: bool,
    pub is_grpc: bool,
    pub max_inspection_size: i64,
    pub no_log: bool,
    pub response_headers_size: usize,
    pub origin_address: String,
    pub origin_status: i32,
    pub is_on: bool,
    pub client_ip: std::net::IpAddr,
}

impl Default for ProxyCTX {
    fn default() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            request_id: String::new(),
            server: None,
            lb: None,
            metrics_recorded: false,
            ttfb: None,
            response_status: 0,
            cache_policy: None,
            cache_ref: None,
            cache_key: None,
            cache_hit: None,
            cacheable: false,
            response_headers: HashMap::new(),
            response_body_len: 0,
            response_body_buffer: Vec::new(),
            request_body: Vec::new(),
            waf_policy_id: 0,
            waf_group_id: 0,
            waf_set_id: 0,
            waf_action: None,
            compress_zstd: false,
            compression_type: None,
            compression_level: 0,
            custom_page_body: None,
            custom_page_status: 0,
            is_websocket: false,
            is_grpc: false,
            max_inspection_size: 512 * 1024, // Default 512K as per PB requirement
            no_log: false,
            response_headers_size: 0,
            origin_address: String::new(),
            origin_status: 0,
            is_on: true,
            client_ip: "127.0.0.1".parse().unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct EdgeProxy {
    pub config: Arc<ConfigStore>,
    pub waf_state: Arc<WafStateManager>,
    pub api_config: Arc<ApiConfig>,
    pub cert_selector: Arc<crate::ssl::DynamicCertSelector>,
}

impl EdgeProxy {
    fn check_waf_challenge(&self, session: &Session, ip_str: &str, ua: &str, ctx: &ProxyCTX) -> bool {
        let verifier = crate::firewall::verifier::WafVerifier::new(&self.api_config.secret);
        
        if let Some(cookies) = session.get_header("cookie").and_then(|v| v.to_str().ok()) {
            let mut current_token = None;
            let mut current_pow = None;

            for part in cookies.split(';') {
                let part = part.trim();
                // 1. Check AES-256-GCM Token
                if let Some(token) = part.strip_prefix("WAF-Token=") {
                    if verifier.verify_token(ip_str, ua, token, 3600) {
                        current_token = Some(token);
                    }
                }
                // 2. Check PoW Solution
                if let Some(pow) = part.strip_prefix("WAF-PoW=") {
                    current_pow = Some(pow);
                }
            }

            if let (Some(token), Some(nonce)) = (current_token, current_pow) {
                // Strict Server-side verify
                if verifier.verify_pow(token, nonce, 4) {
                    if let Ok(ip) = ip_str.parse() {
                        let server_id = ctx.server.as_ref().map(|s| s.numeric_id()).unwrap_or(0);
                        self.waf_state.unblock_ip(ip, server_id, Some("server"), true);
                    }
                    return true;
                }
            }
        }
        false
    }


    async fn respond_waf_action(&self, session: &mut Session, ctx: &mut ProxyCTX, matched: crate::firewall::MatchedAction, ip: String) -> Result<bool> {
        let action = matched.action;
        let global_actions = self.config.get_waf_actions_sync();
        
        match action {
            crate::firewall::ActionResponse::Allow => Ok(false),
            crate::firewall::ActionResponse::Block { mut status, mut body } => {
                let mut final_timeout = matched.timeout_secs.unwrap_or(300);
                let mut scope = matched.scope.as_deref().unwrap_or("server");
                let mut max_timeout = 0;
                let mut fail_global = false;

                // Priority 1: From MatchedAction (Policy/Website Level)
                if let Some(opts) = &matched.block_options {
                    if opts.status_code > 0 { status = opts.status_code; }
                    if !opts.body.is_empty() { body = opts.body.clone(); }
                    if opts.timeout > 0 { final_timeout = opts.timeout as i64; }
                    max_timeout = opts.max_timeout;
                    fail_global = opts.fail_global;
                } 
                // Priority 2: From Global Default WAF Actions
                else if let Some(global) = global_actions.iter().find(|a| a.code == "block") {
                    if let Ok(opts) = serde_json::from_value::<crate::config_models::WAFBlockOptions>(global.options.clone()) {
                        if opts.status_code > 0 { status = opts.status_code; }
                        if !opts.body.is_empty() { body = opts.body; }
                        if opts.timeout > 0 { final_timeout = opts.timeout as i64; }
                        max_timeout = opts.max_timeout;
                        fail_global = opts.fail_global;
                    }
                }

                // Apply randomized timeout logic
                if max_timeout > final_timeout as i32 {
                    use rand::Rng;
                    final_timeout = rand::thread_rng().gen_range(final_timeout..=max_timeout as i64);
                }
                if fail_global { scope = "global"; }

                // Apply Block
                if let Ok(ip_addr) = ip.parse() {
                    self.waf_state.block_ip(
                        ip_addr,
                        ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                        final_timeout,
                        Some(scope),
                        matched.block_c_class,
                        matched.use_local_firewall
                    );

                    // Report to API if ip_list_id is set
                    if matched.ip_list_id > 0 {
                        let ua = session.get_header("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                        let url = format!("{}{}", session.req_header().uri.host().unwrap_or(""), session.req_header().uri.path());
                        let node_id = self.config.get_node_id().await;
                        crate::rpc::ip_report::report_block(crate::rpc::ip_report::IpReportMessage {
                            ip_list_id: matched.ip_list_id,
                            value: ip.clone(),
                            ip_from: ip.clone(),
                            ip_to: "".to_string(),
                            expired_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 + final_timeout,
                            reason: format!("WAF Action: {}", matched.action_code),
                            r#type: "black".to_string(),
                            event_level: matched.event_level,
                            node_id,
                            server_id: ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                            source_node_id: node_id,
                            source_server_id: ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                            source_http_firewall_policy_id: matched.policy_id,
                            source_http_firewall_rule_group_id: matched.group_id,
                            source_http_firewall_rule_set_id: matched.set_id,
                            source_url: url,
                            source_user_agent: ua,
                            source_category: "waf".to_string(),
                        });
                    }
                }

                let resolved_body = crate::firewall::matcher_plus::format_variables(session, &body, &ctx.request_body);
                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                resp.insert_header("content-type", "text/html; charset=utf-8").unwrap();
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(Bytes::from(resolved_body)), true).await?;
                Ok(true)
                }
                crate::firewall::ActionResponse::Page { mut status, mut body, content_type } => {
                // Priority 1: From MatchedAction
                if let Some(opts) = &matched.page_options {
                    if opts.status > 0 { status = opts.status; }
                    if !opts.body.is_empty() { body = opts.body.clone(); }
                }
                // Priority 2: From Global Default
                else if let Some(global) = global_actions.iter().find(|a| a.code == "page") {
                    if let Ok(opts) = serde_json::from_value::<crate::config_models::WAFPageOptions>(global.options.clone()) {
                        if opts.status > 0 { status = opts.status; }
                        if !opts.body.is_empty() { body = opts.body; }
                    }
                }
                let resolved_body = crate::firewall::matcher_plus::format_variables(session, &body, &ctx.request_body);
                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                resp.insert_header("content-type", content_type).unwrap();
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(Bytes::from(resolved_body)), true).await?;
                Ok(true)
                }
                crate::firewall::ActionResponse::Redirect { status, location } => {
                let resolved_url = crate::firewall::matcher_plus::format_variables(session, &location, &ctx.request_body);
                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                resp.insert_header("location", resolved_url).unwrap();
                session.write_response_header(Box::new(resp), true).await?;
                Ok(true)
                }            crate::firewall::ActionResponse::Captcha { mut life_seconds } | 
            crate::firewall::ActionResponse::JsCookie { mut life_seconds } |
            crate::firewall::ActionResponse::Get302 { mut life_seconds } |
            crate::firewall::ActionResponse::Post307 { mut life_seconds } => {
                let ua = session.get_header("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("");
                let verifier = crate::firewall::verifier::WafVerifier::new(&self.api_config.secret);
                let token = verifier.generate_token(&ip, ua);
                
                let (status, is_redirect) = match action {
                    crate::firewall::ActionResponse::Get302 { .. } => (302, true),
                    crate::firewall::ActionResponse::Post307 { .. } => (307, true),
                    _ => (403, false),
                };

                let mut captcha_opts = matched.captcha_options.clone();
                let mut js_opts = matched.js_cookie_options.clone();

                // Fallback to Global Defaults
                if captcha_opts.is_none() {
                    if let Some(global) = global_actions.iter().find(|a| a.code == "captcha") {
                        captcha_opts = serde_json::from_value(global.options.clone()).ok();
                    }
                }
                if js_opts.is_none() {
                    if let Some(global) = global_actions.iter().find(|a| a.code == "js_cookie") {
                        js_opts = serde_json::from_value(global.options.clone()).ok();
                    }
                }

                let mut body_html = String::new();
                let mut template = "<!doctype html><html><head><title>${title}</title><style>${css}</style></head><body>${promptHeader}${body}${promptFooter}</body></html>".to_string();

                if let Some(opts) = &captcha_opts {
                    if opts.life_seconds > 0 { life_seconds = opts.life_seconds as i64; }
                    if let Some(ui) = &opts.ui {
                        if !ui.template.is_empty() { template = ui.template.clone(); }
                        let mut form = format!("<form method='GET' class='waf-form'><input type='hidden' name='__waf_token' value='{}'/><button type='submit' class='verify-btn'>{}</button></form>", token, ui.button_title);
                        if ui.show_request_id { form.push_str(&format!("<p class='request-id'>Request ID: {}</p>", "0")); }
                        
                        body_html = template
                            .replace("${title}", &ui.title)
                            .replace("${css}", &ui.css)
                            .replace("${promptHeader}", &ui.prompt_header)
                            .replace("${promptFooter}", &ui.prompt_footer)
                            .replace("${body}", &form);
                    }
                }

                if body_html.is_empty() {
                    if let Some(opts) = &js_opts { if opts.life_seconds > 0 { life_seconds = opts.life_seconds as i64; } }
                    
                    let pow_script = verifier.get_pow_script(&token, 4); // Difficulty 4
                    body_html = if matches!(action, crate::firewall::ActionResponse::JsCookie { .. }) {
                        format!("<!doctype html><html><body><script>{}</script><script>document.cookie='WAF-Token={}; Path=/; Max-Age={}';</script></body></html>", pow_script, token, life_seconds)
                    } else {
                        format!("<!doctype html><html><head><script>{}</script></head><body><h1>Antigravity Security Verification</h1><p>Solving proof-of-work challenge...</p><form style='display:none'><input type='hidden' name='__waf_token' value='{}'/></form></body></html>", pow_script, token)
                    };
                }

                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                if is_redirect {
                    let mut path_and_query = session.req_header().uri.path().to_string();
                    let connector = if path_and_query.contains('?') { "&" } else { "?" };
                    path_and_query.push_str(&format!("{connector}__waf_token={token}"));
                    resp.insert_header("location", path_and_query).unwrap();
                    session.write_response_header(Box::new(resp), true).await?;
                } else {
                    resp.insert_header("content-type", "text/html; charset=utf-8").unwrap();
                    resp.insert_header("set-cookie", format!("WAF-Token={token}; Path=/; HttpOnly; Max-Age={life_seconds}")).unwrap();
                    session.write_response_header(Box::new(resp), false).await?;
                    session.write_response_body(Some(Bytes::from(body_html)), true).await?;
                }
                Ok(true)
            }
        }
    }
}

#[async_trait]
impl ProxyHttp for EdgeProxy {
    type CTX = ProxyCTX;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCTX::default()
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // --- GLOBAL CLUSTER SETTINGS: Node Enabled (isOn) ---
        ctx.is_on = self.config.get_node_is_on_sync();
        if !ctx.is_on {
            debug!("Node is DISABLED (isOn=false). Rejecting request.");
            session.respond_error(403).await?;
            return Ok(true);
        }

        let host = session.get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(':').next().unwrap_or(v)) // Remove port if present
            .unwrap_or_else(|| session.req_header().uri.host().unwrap_or(""))
            .to_lowercase();
        
        ctx.server = self.config.get_server_sync(&host);
        ctx.lb = self.config.get_upstream_sync(&host);

        let _is_loopback = session.client_addr()
            .and_then(|a| a.as_inet())
            .map(|i| i.ip().is_loopback())
            .unwrap_or(false);

        // L2 Logic: Restore Real IP from L1 node if trusted
        ctx.client_ip = match session.client_addr() {
            Some(pingora_core::protocols::l4::socket::SocketAddr::Inet(addr)) => addr.ip(),
            _ => "127.0.0.1".parse().unwrap(),
        };

        if let Some(edge_ip) = session.get_header("X-Cloud-Real-Ip") {
             if let Ok(ip_str) = edge_ip.to_str() {
                 if let Ok(parsed_ip) = ip_str.parse::<std::net::IpAddr>() {
                     debug!("L2: Restoring real client IP {} from L1 header", parsed_ip);
                     ctx.client_ip = parsed_ip;
                 }
             }
        }
        
        let ip_str = ctx.client_ip.to_string();
        
        let is_test = session.get_header("x-cloud-preheat").is_some();

        // Handle internal cache test (FULL PATH SIMULATION)
        if is_test {
            // 1. Buffer the value from API
            let mut buffered = Vec::new();
            while let Ok(Some(chunk)) = session.read_request_body().await {
                buffered.extend_from_slice(&chunk);
                if buffered.len() >= 2 * 1024 * 1024 { break; }
            }
            ctx.request_body = buffered;
            ctx.no_log = true;

            // 2. Perform direct storage write to ensure Key match and NO PANICS
            // We use the Host header as the raw Key (parity with readCache)
            let hash = format!("{:x}", md5_legacy::compute(&host));
            let root = std::path::Path::new("data/cache");
            let file_path = root.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
            
            if let Some(parent) = file_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            use std::io::Write;
            if let Ok(mut file) = std::fs::File::create(&file_path) {
                let _ = file.write_all(&ctx.request_body);
            }

            let mut headers_json = serde_json::Map::new();
            headers_json.insert("content-type".to_string(), serde_json::Value::String("text/plain".to_string()));
            
            crate::metrics::storage::STORAGE.update_cache_meta(
                &hash, 
                &host, 
                ctx.request_body.len() as u64, 
                3600, 
                Some(serde_json::Value::Object(headers_json)), 
                false, 
                200
            );

            debug!("Internal cache test write success: key={}, hash={}, size={}", host, hash, ctx.request_body.len());

            // 3. Respond and stop to avoid Pingora Phase machine panic
            let mut resp = pingora_http::ResponseHeader::build(200, None).unwrap();
            resp.insert_header("x-cloud-test", "1").unwrap();
            session.write_response_header(Box::new(resp), false).await?;
            session.write_response_body(Some(bytes::Bytes::from("OK")), true).await?;
            return Ok(true); 
        }

        if let Some(server) = &ctx.server {
            if let Some(web) = &server.web {
                if let Some(ws) = &web.websocket {
                    if ws.is_on {
                        ctx.is_websocket = true;
                        ctx.is_grpc = true; // Sync enable gRPC if websocket is on
                    }
                }
            }
            if let Some(grpc) = &server.grpc {
                if grpc.is_on {
                    ctx.is_grpc = true;
                }
            }

            // Apply gRPC message size limits if enabled
            if ctx.is_grpc {
                let grpc_policy = self.config.get_grpc_policy_sync();
                let max_recv = grpc_policy.as_ref().and_then(|p| p.max_receive_message_size.as_ref()).map(|s| s.to_bytes()).unwrap_or(0);
                let final_max_recv = if max_recv <= 0 { 2 * 1024 * 1024 } else { max_recv };
                
                // For gRPC, we increase the inspection limit to allow larger messages
                ctx.max_inspection_size = final_max_recv;
                debug!("gRPC enabled for request, setting max_inspection_size to {} bytes", final_max_recv);
            }
        }

        // --- GLOBAL CLUSTER SETTINGS: Low Version HTTP ---
        let global_cfg = self.config.get_global_http_config_sync();
        if !global_cfg.supports_low_version_http {
            if session.req_header().version < pingora_http::Version::HTTP_11 {
                debug!("Blocking low version HTTP request: {:?}", session.req_header().version);
                session.respond_error(400).await?;
                return Ok(true);
            }
        }

        if ctx.server.is_none() {
            debug!("404 Not Found for host: '{}'. Registered hosts: {:?}", host, self.config.get_all_hosts_sync());
            session.respond_error(404).await?;
            return Ok(true);
        }

        if ctx.lb.is_none() {
            if let Some(server) = &ctx.server {
                debug!("LB missing for host '{}', rebuilding manually.", host);
                let (level, parents) = self.config.get_tiered_origin_info().await;
                let bypass = self.config.is_tiered_origin_bypass().await;
                
                let rp_cfg = match &server.reverse_proxy {
                    Some(rp) => rp,
                    None => {
                        session.respond_error(502).await?;
                        return Ok(true);
                    }
                };

                let server_id = server.numeric_id();
                let global_cfg = self.config.get_global_http_config_sync();
                let (lb_arc, _has_hc) = crate::lb_factory::build_lb(server_id, rp_cfg, level, &parents, bypass, global_cfg.allow_lan_ip);
                ctx.lb = Some(lb_arc.clone());
                
                // Cache it
                let mut servers_map = std::collections::HashMap::new();
                let mut routes_map = std::collections::HashMap::new();
                servers_map.insert(host.clone(), server.clone());
                routes_map.insert(host.clone(), lb_arc);
                self.config.replace_server(server.id.unwrap_or(0), servers_map, routes_map).await;
            }
        }

        if self.waf_state.is_whitelisted(ctx.client_ip, ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0)) {
            return Ok(false);
        }

        let ua = session.get_header("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("");
        if self.check_waf_challenge(session, &ip_str, ua, ctx) {
            return Ok(false);
        }

        // Record request start for global metrics
        ctx.request_id = crate::logging::next_request_id();
        crate::metrics::record::request_start(
            ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
            ip_str.clone(),
        );

        if self.waf_state.is_blocked(ctx.client_ip, ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0)) {
            session.respond_error(403).await?;
            return Ok(true);
        }

        // 1. Mandatory Global Special Defenses
        let global_policies = self.config.get_firewall_policies_sync();
        for gp in &global_policies {
            if !gp.is_on { continue; }
            
            // 1.1 Empty Connection Flood
            if let Some(cfg) = &gp.empty_connection_flood {
                if cfg.is_on {
                    let threshold = cfg.threshold.max(10);
                    let period = if cfg.period > 0 { cfg.period as i64 } else { 60 };
                    let ban = if cfg.ban_duration > 0 { cfg.ban_duration as i64 } else { 3600 };
                    
                    if !self.waf_state.check_special_defense(format!("ECF:{}", ip_str), threshold, period) {
                        self.waf_state.block_ip(ctx.client_ip, 0, ban, Some("global"), false, gp.use_local_firewall);
                        session.respond_error(403).await?;
                        return Ok(true);
                    }
                }
            }

            // 1.2 TLS Exhaustion Attack
            if let Some(cfg) = &gp.tls_exhaustion_attack {
                let is_tls = session.downstream_session.digest().and_then(|d| d.ssl_digest.as_ref()).is_some();
                if cfg.is_on && (is_tls || session.req_header().uri.scheme_str() == Some("https")) {
                    let threshold = cfg.threshold.max(10);
                    let period = if cfg.period > 0 { cfg.period as i64 } else { 60 };
                    let ban = if cfg.ban_duration > 0 { cfg.ban_duration as i64 } else { 3600 };

                    if !self.waf_state.check_special_defense(format!("TLS:{}", ip_str), threshold, period) {
                        self.waf_state.block_ip(ctx.client_ip, 0, ban, Some("global"), true, gp.use_local_firewall);
                        session.respond_error(403).await?;
                        return Ok(true);
                    }
                }
            }
        }

        // 2. Evaluate WAF Policies
        let mut waf_action = None;

        // --- BUFFERING REQUEST BODY (Max 2MB) ---
        if ctx.request_body.is_empty() {
            let content_length = session.get_header("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            
            if content_length > 0 && content_length <= 2 * 1024 * 1024 {
                let mut buffered = Vec::with_capacity(content_length);
                while let Some(chunk) = session.read_request_body().await? {
                    buffered.extend_from_slice(&chunk);
                    if buffered.len() >= content_length {
                        break;
                    }
                }
                ctx.request_body = buffered;
            }
        }
        // --- END BUFFERING ---

        if let Some(server) = &ctx.server 
            && let Some(web) = &server.web 
            && let Some(firewall_ref) = &web.firewall_ref 
            && firewall_ref.is_on {
                
                // 2.1 Site-Level Policy
                if let Some(policy) = &web.firewall_policy {
                    if policy.is_on {
                        // Check Request Body Size
                        if policy.max_request_body_size > 0 {
                            let content_length = session.get_header("content-length")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<i64>().ok())
                                .unwrap_or(0);
                            
                            if content_length > policy.max_request_body_size || (ctx.request_body.len() as i64) > policy.max_request_body_size {
                                waf_action = Some(crate::firewall::MatchedAction {
                                    action: crate::firewall::ActionResponse::Block { status: 413, body: "Request Entity Too Large".to_string() },
                                    policy_id: policy.id,
                                    group_id: 0,
                                    set_id: 0,
                                    action_code: "block".to_string(),
                                    timeout_secs: Some(3600),
                                    max_timeout_secs: None,
                                    life_seconds: None,
                                    max_fails: 0,
                                    fail_block_timeout: 0,
                                    scope: None,
                                    block_c_class: false,
                                    use_local_firewall: false,
                                    next_group_id: None,
                                    next_set_id: None,
                                    allow_scope: None,
                                    tags: vec![],
                                    ip_list_id: 0,
                                    event_level: "error".to_string(),
                                    block_options: None,
                                    page_options: None,
                                    captcha_options: None,
                                    js_cookie_options: None,
                                });
                            }
                        }
                        if waf_action.is_none() {
                            waf_action = crate::firewall::evaluate_policy(policy, session, &ctx.request_body);
                        }
                    }
                }

                // 2.2 Global Policies (if not ignored)
                if waf_action.is_none() && !firewall_ref.ignore_global_rules {
                    for gp in &global_policies {
                        if gp.is_on {
                            if let Some(action) = crate::firewall::evaluate_policy(gp, session, &ctx.request_body) {
                                waf_action = Some(action);
                                break;
                            }
                        }
                    }
                }
            }

        if let Some(matched) = waf_action {
            ctx.waf_policy_id = matched.policy_id;
            ctx.waf_group_id = matched.group_id;
            ctx.waf_set_id = matched.set_id;
            ctx.waf_action = Some(matched.action_code.clone());

            if matched.action_code == "record_ip_white" {
                self.waf_state.unblock_ip(ctx.client_ip, ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0), matched.scope.as_deref(), matched.use_local_firewall);
                return Ok(false);
            }

            if matches!(matched.action_code.as_str(), "block" | "record_ip") {
                let mut final_timeout = matched.timeout_secs.unwrap_or(300);
                if let Some(max_t) = matched.max_timeout_secs {
                    if max_t > final_timeout {
                        final_timeout = rand::thread_rng().gen_range(final_timeout..=max_t);
                    }
                }

                self.waf_state.block_ip(
                    ctx.client_ip,
                    ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0),
                    final_timeout,
                    matched.scope.as_deref(),
                    matched.block_c_class,
                    matched.use_local_firewall
                );
            }
            if self.respond_waf_action(session, ctx, matched.clone(), ip_str.clone()).await? {
                return Ok(true);
            }
        }

        // 3. CC Basic Defense & Rate Limit
        if let Some(server) = &ctx.server
            && let Some(web) = &server.web {
                if let Some(cc) = &web.cc_policy {
                    if cc.is_on {
                        // 3.1 Check Site-wide QPS
                        if cc.max_qps > 0 && !self.waf_state.check_rate_limit(server.id.unwrap_or(0), cc.max_qps as u32) {
                            // 3.2 If site QPS exceeded, check Per-IP QPS
                            if cc.per_ip_max_qps > 0 && !self.waf_state.check_ip_rate_limit(server.id.unwrap_or(0), ctx.client_ip, cc.per_ip_max_qps as u32) {
                                // Block IP if configured
                                if cc.block_ip {
                                    let ban = if cc.block_ip_duration > 0 { cc.block_ip_duration as i64 } else { 3600 };
                                    self.waf_state.block_ip(ctx.client_ip, server.id.unwrap_or(0), ban, Some("server"), false, true);
                                }
                                // Show page if configured
                                if cc.show_page {
                                    ctx.no_log = cc.no_log;
                                    session.respond_error(429).await?;
                                    return Ok(true);
                                }
                            }
                        }
                    }
                }

                let uri_str = session.req_header().uri.path();
                let query = session.req_header().uri.query().unwrap_or("");

                if !web.host_redirects.is_empty() {
                    if let Some((location, status)) = evaluate_host_redirects(&host, uri_str, &web.host_redirects) {
                        let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                        resp.insert_header("location", location).unwrap();
                        session.write_response_header(Box::new(resp), true).await?;
                        return Ok(true);
                    }
                }

                if !web.rewrite_rules.is_empty()
                    && let RewriteResult::Redirect { location, status } = evaluate_rewrites(uri_str, query, &web.rewrite_refs, &web.rewrite_rules) {
                    let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                    resp.insert_header("location", location).unwrap();
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }

        Ok(false)
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        let node_level = self.config.get_node_level_sync();
        let force_ln = self.config.get_force_ln_request_sync();
        let bypass_l2 = self.config.is_tiered_origin_bypass().await;
        
        let mut target_peer = None;

        // --- TIERED ORIGIN (L1 -> L2) LOGIC ---
        if node_level == 1 && !bypass_l2 && (force_ln || ctx.cache_ref.is_some()) {
            if ctx.server.is_some() {
                // Find cluster-specific Parent LB
                // Note: We use cluster_id 0 for default cluster if not specifically mapped
                // In actual GoEdge, cluster_id is more specific.
                if let Some(parent_lb) = self.config.get_parent_upstream_sync(0) {
                    let ln_method = self.config.get_ln_method_sync();
                    
                    let hash_key = if ln_method == "urlMapping" {
                        // Hash by full URL (Scheme + Host + Path + Query)
                        session.req_header().uri.to_string().into_bytes()
                    } else {
                        // Random-like (Round Robin is better for random, but Ketama works with random key)
                        rand::random::<u64>().to_le_bytes().to_vec()
                    };

                    if let Some(peer) = parent_lb.select(&hash_key, 128) {
                        let peer_addr = peer.to_string();
                        let pressure = self.config.get_parent_pressure(&peer_addr);
                        
                        if pressure > 0.9 {
                            debug!("L2 node {} is overloaded (Pressure: {:.2}), trying fallback...", peer_addr, pressure);
                            // Try one more time with a different key to "drift" to another node in the ring
                            let fallback_key = format!("fallback:{:?}", hash_key);
                            if let Some(second_peer) = parent_lb.select(fallback_key.as_bytes(), 128) {
                                debug!("Drifted L2 selection from {} to {}", peer_addr, second_peer.addr);
                                target_peer = Some(second_peer.clone());
                            } else {
                                target_peer = Some(peer.clone());
                            }
                        } else {
                            debug!("Selected L2 upstream: {} (Method: {}, Pressure: {:.2}) for host: {}", peer_addr, ln_method, pressure, session.req_header().uri.host().unwrap_or(""));
                            target_peer = Some(peer.clone());
                        }
                    }
                }
            }
        }

        // --- FALLBACK TO ORIGIN LB ---
        if target_peer.is_none() {
            if let Some(lb) = &ctx.lb {
                if let Some(peer) = lb.select(b"", 128) {
                    target_peer = Some(peer.clone());
                }
            }
        }

        if let Some(peer) = target_peer {
            let peer_addr = peer.to_string();
            let backend_ext = peer.ext.get::<crate::lb_factory::BackendExtension>();
            let is_tls = backend_ext.map(|e| e.use_tls).unwrap_or(peer_addr.contains("443"));

            let host = if let Some(ext) = backend_ext {
                if !ext.host.is_empty() {
                    ext.host.clone()
                } else if ext.follow_host {
                        session.get_header("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_else(|| session.req_header().uri.host().unwrap_or("localhost"))
                        .to_string()
                } else {
                    session.get_header("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_else(|| session.req_header().uri.host().unwrap_or("localhost"))
                        .to_string()
                }
            } else {
                session.get_header("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_else(|| session.req_header().uri.host().unwrap_or("localhost"))
                    .to_string()
            };

            debug!("Selected upstream: {} (TLS={}) for SNI: {}", peer_addr, is_tls, host);
            ctx.origin_address = peer_addr.clone();
            
            let mut peer_obj = HttpPeer::new(peer_addr, is_tls, host);
            
            // --- OPTIMIZATION: L7 TCP & Protocol ---
            // Pingora sets nodelay by default. 
            // For keepalive, we use Pingora's native struct:
            peer_obj.options.tcp_keepalive = Some(pingora_core::protocols::l4::ext::TcpKeepalive {
                idle: std::time::Duration::from_secs(60),
                interval: std::time::Duration::from_secs(10),
                count: 3,
                #[cfg(target_os = "linux")]
                user_timeout: std::time::Duration::from_secs(0),
            });
            
            // Default 60s idle timeout for backend connections
            peer_obj.options.idle_timeout = Some(std::time::Duration::from_secs(60));
            // Connection timeout (L1 -> L2 or L2 -> Origin)
            peer_obj.options.connection_timeout = Some(std::time::Duration::from_secs(10));

            if ctx.is_grpc {
                // Force ALPN to h2 for gRPC
                peer_obj.options.alpn = pingora_core::protocols::ALPN::H2;
            }

            if let Some(ext) = backend_ext {
                if !ext.tls_verify {
                    peer_obj.options.verify_cert = false;
                }
            }
            return Ok(Box::new(peer_obj));
        }

        if ctx.lb.is_none() {
            debug!("LB is missing in context even though server was found. Server ID: {:?}", ctx.server.as_ref().map(|s| s.id));
        } else {
            debug!("No healthy backend selected from LB for context: {:?}", ctx.server.as_ref().map(|s| s.id));
        }
        Err(Error::new(InternalError))
    }

    async fn logging(&self, session: &mut Session, _re: Option<&Error>, ctx: &mut Self::CTX) {
        crate::logging::log_access(session, ctx);
    }

    fn cache_key_callback(&self, _session: &Session, ctx: &mut Self::CTX) -> Result<pingora_cache::CacheKey> {
        if let Some(key) = &ctx.cache_key {
            return Ok(pingora_cache::CacheKey::new("", key.as_str(), ""));
        }
        
        // CRITICAL: If no key was set by request_cache_filter, we MUST return an error.
        // This ensures Pingora absolutely does not attempt any cache lookup or storage.
        Err(pingora::Error::new(pingora::ErrorType::Custom("Cache Disabled for this request")))
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        if let Some(s) = &ctx.server
            && let Some(web) = &s.web
                && let Some(cache) = &web.cache
                    && cache.is_on {
                        if !self.waf_state.check_cache_limit(ctx.client_ip) {
                            tracing::warn!("IP {} exceeded cache-miss frequency limit.", ctx.client_ip);
                            return Ok(());
                        }

                        let mut matched_ref = None;
                        for cache_ref in &cache.cache_refs {
                            if !cache_ref.is_on { continue; }
                            let is_match = if let Some(conds) = &cache_ref.conds {
                                conds.match_request(session)
                            } else if let Some(simple_cond) = &cache_ref.simple_cond {
                                simple_cond.match_request(session)
                            } else { true };

                            if is_match {
                                if cache_ref.is_reverse { 
                                    tracing::debug!("Website Cache Rule matched: SKIP");
                                    return Ok(()); 
                                }
                                matched_ref = Some(cache_ref.clone());
                                tracing::debug!("Website Cache Rule matched: ENABLE");
                                break;
                            }
                        }

                        if matched_ref.is_none() && !cache.disable_policy_refs {
                            let policy_opt = if let Some(p) = &cache.cache_policy { Some(p.clone()) } else { self.config.get_cache_policy_sync() };
                            if let Some(policy) = policy_opt {
                                for cache_ref in &policy.cache_refs {
                                    if !cache_ref.is_on { continue; }
                                    let is_match = if let Some(conds) = &cache_ref.conds { conds.match_request(session) }
                                        else if let Some(simple_cond) = &cache_ref.simple_cond { simple_cond.match_request(session) }
                                        else { true };
                                    if is_match {
                                        if cache_ref.is_reverse {
                                            tracing::debug!("GLOBAL Cluster Policy '{}' rule matched: SKIP", policy.name);
                                            return Ok(());
                                        }
                                        matched_ref = Some(cache_ref.clone());
                                        tracing::debug!("GLOBAL Cluster Policy '{}' rule matched: ENABLE (Path: {})", policy.name, session.req_header().uri.path());
                                        break;
                                    }

                                }
                            }
                        }

                        if let Some(cache_ref) = matched_ref {
                            if cache_ref.always_forward_range_request && session.get_header("range").is_some() { return Ok(()); }
                            if cache_ref.enable_request_cache_pragma {
                                let cc = session.get_header("cache-control").and_then(|v| v.to_str().ok()).unwrap_or("");
                                let pragma = session.get_header("pragma").and_then(|v| v.to_str().ok()).unwrap_or("");
                                if cc.contains("no-cache") || pragma.contains("no-cache") { 
                                    return Ok(()); 
                                }
                            }

                            ctx.cache_policy = cache_ref.cache_policy.clone();
                            ctx.cache_ref = Some(cache_ref.clone());

                            // --- PROTOCOL PARITY: Salted Key Generation ---
                            let mut key = if let Some(key_template) = &cache_ref.key { 
                                if key_template.is_empty() {
                                    crate::cache::matching::format_variables(session, "${scheme}://${host}${requestPath}${isArgs}${args}")
                                } else {
                                    crate::cache::matching::format_variables(session, key_template)
                                }
                            } else { 
                                crate::cache::matching::format_variables(session, "${scheme}://${host}${requestPath}${isArgs}${args}") 
                            };

                            // 1. Method Suffix (EdgeNode parity: "@method:METHOD")
                            let method = session.req_header().method.as_str();
                            if method != "GET" {
                                key.push_str("@method:");
                                key.push_str(method);
                            }

                            // 2. WebP Suffix (if applicable)
                            let accept = session.get_header("accept").and_then(|v| v.to_str().ok()).unwrap_or("");
                            if accept.contains("image/webp") {
                                let path = session.req_header().uri.path().to_lowercase();
                                if path.ends_with(".jpg") || path.ends_with(".jpeg") || path.ends_with(".png") || path.ends_with(".gif") {
                                    key.push_str("@webp");
                                }
                            }

                            // 3. Compression Suffix (EdgeNode parity: "@encoding")
                            let accept_encoding = session.get_header("accept-encoding").and_then(|v| v.to_str().ok()).unwrap_or("");
                            if accept_encoding.contains("br") {
                                key.push_str("@br");
                            } else if accept_encoding.contains("gzip") {
                                key.push_str("@gzip");
                            }

                            ctx.cache_key = Some(key);

                            if !cache_ref.enable_if_none_match { session.req_header_mut().headers.remove("if-none-match"); }
                            if !cache_ref.enable_if_modified_since { session.req_header_mut().headers.remove("if-modified-since"); }

                            session.cache.enable(CACHE.storage, None, None, None, None);
                        } else {
                            tracing::debug!("No cache rule matched for request: {}", session.req_header().uri.path());
                            // CRITICAL: Explicitly disable cache to clear state from Keep-Alive requests
                            session.cache.disable(pingora_cache::NoCacheReason::Custom("RuleDisabled"));
                        }
                    } else {
                         tracing::debug!("Cache is OFF for this server or web config.");
                         session.cache.disable(pingora_cache::NoCacheReason::Custom("CacheConfigOff"));
                    }
        Ok(())
    }

    async fn upstream_response_filter(&self, _session: &mut Session, upstream_response: &mut pingora::http::ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        ctx.origin_status = upstream_response.status.as_u16() as i32;

        if let Some(cache_ref) = &ctx.cache_ref {
            let mut force_cache = false;
            let mut seconds = 0;

            if let Some(expires_cfg) = &cache_ref.expires_time && expires_cfg.is_on {
                if let Some(duration_val) = &expires_cfg.duration {
                    seconds = crate::config_models::parse_life_to_seconds(duration_val);
                    if seconds > 0 {
                        force_cache = true;
                    }
                }
            } else if let Some(life) = &cache_ref.life {
                seconds = crate::config_models::parse_life_to_seconds(life);
                if seconds > 0 {
                    force_cache = true;
                }
            }

            if force_cache {
                // 1. Sanitize Cache-Control (Robust Split-Filter-Join)
                let cc_header = upstream_response.headers.get("cache-control")
                    .and_then(|v| v.to_str().ok());
                
                let blacklist = ["no-cache", "no-store", "private", "must-revalidate", "proxy-revalidate"];
                let mut parts: Vec<String> = vec![];
                
                if let Some(cc_val) = cc_header {
                    for part in cc_val.split(',') {
                        let trimmed = part.trim();
                        if !blacklist.iter().any(|&kw| trimmed.eq_ignore_ascii_case(kw)) {
                            if !trimmed.is_empty() {
                                parts.push(trimmed.to_string());
                            }
                        }
                    }
                }

                if !parts.iter().any(|p| p.to_lowercase().contains("max-age")) {
                    parts.push(format!("max-age={}", seconds));
                }
                
                if !parts.iter().any(|p| p.eq_ignore_ascii_case("public")) {
                    parts.push("public".to_string());
                }

                let new_cc = parts.join(", ");
                upstream_response.insert_header("cache-control", new_cc).unwrap();

                // 2. Remove Pragma: no-cache
                if let Some(pragma) = upstream_response.headers.get("pragma") {
                    if pragma.to_str().unwrap_or("").to_lowercase().contains("no-cache") {
                        upstream_response.remove_header("pragma");
                    }
                }

                // 3. Set Expires
                let expires = chrono::Utc::now() + chrono::Duration::seconds(seconds as i64);
                let expires_str = expires.to_rfc2822().replace("+0000", "GMT");
                upstream_response.insert_header("expires", expires_str).unwrap();
            }
        }
        Ok(())
    }

    async fn response_filter(&self, session: &mut Session, upstream_response: &mut pingora::http::ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        ctx.response_status = upstream_response.status.as_u16();
        ctx.ttfb = Some(ctx.start_time.elapsed());
        ctx.response_headers_size = upstream_response.headers.iter().map(|(n, v)| n.as_str().len() + v.len() + 4).sum();

        // --- SMART LOAD BALANCING FEEDBACK ---
        // 1. L2 Node: Announce pressure to L1
        if session.get_header("X-Cloud-Node-Id").is_some() {
            let pressure = crate::metrics::METRICS.get_node_pressure();
            upstream_response.insert_header("X-Cloud-Node-Pressure", format!("{:.2}", pressure)).unwrap();
        }

        // 2. L1 Node: Learn from L2's pressure announcement
        if let Some(p_header) = upstream_response.headers.get("X-Cloud-Node-Pressure") {
            if let Ok(p_str) = p_header.to_str() {
                if let Ok(p_val) = p_str.parse::<f32>() {
                    // Update the pressure map for this L2 node using the actual upstream address
                    self.config.update_parent_pressure(&ctx.origin_address, p_val);
                }
            }
        }

        // --- GLOBAL CLUSTER SETTINGS: Server Flag ---
        let global_cfg = self.config.get_global_http_config_sync();
        if !global_cfg.server_name.is_empty() {
            upstream_response.insert_header("Server", &global_cfg.server_name).unwrap();
        }

        // 1. Initial Outbound WAF (Status & Headers)
        let outbound_ctx = crate::firewall::OutboundContext {
            status: ctx.response_status,
            headers: &ctx.response_headers,
            body: &[], 
            bytes_sent: 0,
        };

        let mut matched_outbound = None;
        let global_policies = self.config.get_firewall_policies_sync();
        for gp in &global_policies {
            if !gp.is_on { continue; }
            if let Some(action) = crate::firewall::evaluate_outbound_policy(gp, session, &ctx.request_body, &outbound_ctx) {
                matched_outbound = Some(action);
                break;
            }
        }
        if matched_outbound.is_none() {
            if let Some(server) = &ctx.server && let Some(web) = &server.web && let Some(fw_ref) = &web.firewall_ref && fw_ref.is_on {
                if let Some(policy) = &web.firewall_policy {
                    if let Some(action) = crate::firewall::evaluate_outbound_policy(policy, session, &ctx.request_body, &outbound_ctx) {
                        matched_outbound = Some(action);
                    }
                }
            }
        }

        if let Some(action) = matched_outbound {
            if action.action_code == "block" {
                upstream_response.status = pingora::http::StatusCode::FORBIDDEN;
                upstream_response.insert_header("x-waf-blocked", "outbound-header").unwrap();
                ctx.waf_policy_id = action.policy_id;
                ctx.waf_group_id = action.group_id;
                ctx.waf_set_id = action.set_id;
                ctx.waf_action = Some(action.action_code.clone());
            }
        }
        
        // ... (existing X-Cache and Expires logic)
        let phase = session.cache.phase();
        let x_cache = if !session.cache.enabled() && !session.cache.bypassing() {
            "BYPASS".to_string()
        } else {
            match phase {
                pingora_cache::CachePhase::Hit => "HIT".to_string(),
                pingora_cache::CachePhase::Miss => "MISS".to_string(),
                pingora_cache::CachePhase::Stale => "STALE".to_string(),
                pingora_cache::CachePhase::Bypass => "BYPASS".to_string(),
                pingora_cache::CachePhase::Expired => "EXPIRED".to_string(),
                pingora_cache::CachePhase::Revalidated => "REVALIDATED".to_string(),
                pingora_cache::CachePhase::Disabled(reason) => {
                    format!("DISABLED:{}", reason.as_str().to_uppercase())
                }
                _ => phase.as_str().to_uppercase(),
            }
        };
        upstream_response.insert_header("x-cache", x_cache.clone()).unwrap();
        ctx.response_headers.insert("x-cache".to_string(), x_cache);

        if let Some(cache_ref) = &ctx.cache_ref && let Some(expires_cfg) = &cache_ref.expires_time && expires_cfg.is_on && expires_cfg.auto_calculate {
            if expires_cfg.overwrite || upstream_response.headers.get("expires").is_none() {
                let ttl = cache_ref.life.as_ref().map(crate::config_models::parse_life_to_seconds).unwrap_or(3600);
                let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);
                upstream_response.insert_header("expires", expires.to_rfc2822().replace("+0000", "GMT")).unwrap();
                upstream_response.insert_header("cache-control", format!("max-age={}", ttl)).unwrap();
            }
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let global_cfg = self.config.get_global_http_config_sync();

        // 1. Automatic Gzip Back to Origin
        if global_cfg.request_origins_with_encodings {
            if upstream_request.headers.get("accept-encoding").is_none() {
                upstream_request.insert_header("accept-encoding", "gzip, deflate, br").unwrap();
            }
        }

        // 2. L1 Logic: Inject Identity headers when talking to L2
        let (level, _) = self.config.get_tiered_origin_info().await;
        if level == 1 {
            let node_id = &self.api_config.node_id;
            let secret = &self.api_config.secret;
            
            // 2.1 Identification
            upstream_request.insert_header("X-Cloud-Node-Id", node_id).unwrap();
            
            // 2.2 Real IP Propagation
            upstream_request.insert_header("X-Cloud-Real-Ip", ctx.client_ip.to_string()).unwrap();

            // 2.3 Security Token (Simple version of GoEdge token)
            if let Ok(token) = crate::auth::generate_token(node_id, secret, "edge") {
                upstream_request.insert_header("X-Cloud-Access-Token", token).unwrap();
            }
            
            debug!("L1: Injected tiered-origin headers for node {}", node_id);
        }

        // 3. Standard logic: Add X-Forwarded-For with limit
        let ip = ctx.client_ip.to_string();
        if let Some(val) = upstream_request.headers.get("X-Forwarded-For") {
            let mut parts: Vec<String> = val.to_str().unwrap_or("").split(',').map(|s| s.trim().to_string()).collect();
            parts.push(ip);

            // Apply XFF address limit
            let max_xff = global_cfg.xff_max_addresses;
            if max_xff > 0 && parts.len() > max_xff as usize {
                let start = parts.len() - max_xff as usize;
                parts = parts[start..].to_vec();
            }

            upstream_request.insert_header("X-Forwarded-For", parts.join(", ")).unwrap();
        } else {
            upstream_request.insert_header("X-Forwarded-For", ip).unwrap();
        }

        Ok(())
    }

    fn response_body_filter(&self, _session: &mut Session, body: &mut Option<Bytes>, _end_of_stream: bool, ctx: &mut Self::CTX) -> Result<Option<std::time::Duration>> {
        if let Some(chunk) = body {
            let chunk_len = chunk.len();
            ctx.response_body_len += chunk_len;

            // 2. Outbound WAF Body Inspection (Up to max_inspection_size)
            if ctx.response_body_buffer.len() < ctx.max_inspection_size as usize {
                let remaining = (ctx.max_inspection_size as usize).saturating_sub(ctx.response_body_buffer.len());
                let to_copy = std::cmp::min(chunk_len, remaining);
                ctx.response_body_buffer.extend_from_slice(&chunk[..to_copy]);

                // Evaluate policy again with buffered body content
                let outbound_ctx = crate::firewall::OutboundContext {
                    status: ctx.response_status,
                    headers: &ctx.response_headers,
                    body: &ctx.response_body_buffer,
                    bytes_sent: ctx.response_body_len,
                };

                let mut matched_outbound = None;
                let global_policies = self.config.get_firewall_policies_sync();
                for gp in &global_policies {
                    if !gp.is_on { continue; }
                    if let Some(action) = crate::firewall::evaluate_outbound_policy(gp, _session, &ctx.request_body, &outbound_ctx) {
                        matched_outbound = Some(action);
                        break;
                    }
                }
                if matched_outbound.is_none() {
                    if let Some(server) = &ctx.server && let Some(web) = &server.web && let Some(fw_ref) = &web.firewall_ref && fw_ref.is_on {
                        if let Some(policy) = &web.firewall_policy {
                            if let Some(action) = crate::firewall::evaluate_outbound_policy(policy, _session, &ctx.request_body, &outbound_ctx) {
                                matched_outbound = Some(action);
                            }
                        }
                    }
                }

                if let Some(action) = matched_outbound {
                    if action.action_code == "block" {
                        debug!("Outbound WAF Blocked (Body): Policy ID {}", action.policy_id);
                        ctx.waf_policy_id = action.policy_id;
                        ctx.waf_group_id = action.group_id;
                        ctx.waf_set_id = action.set_id;
                        ctx.waf_action = Some(action.action_code.clone());
                        
                        // Clear the chunk to stop response body transmission
                        *body = None;
                        // Return error to terminate connection
                        return Err(Error::explain(Custom("OutboundBlocked"), "Blocked by Outbound WAF"));
                    }
                }
            }
        }
        Ok(None)
    }


    fn response_cache_filter(&self, session: &Session, resp: &pingora_http::ResponseHeader, ctx: &mut Self::CTX) -> Result<pingora_cache::RespCacheable> {
        if let Some(cache_ref) = &ctx.cache_ref {
            let mut hm: HashMap<String, String> = HashMap::new();
            for (k, v) in resp.headers.iter() { hm.insert(k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string()); }
            let body_size = resp.headers.get("content-length").and_then(|v| v.to_str().ok()).and_then(|s: &str| s.parse::<usize>().ok()).unwrap_or(0);
            let host = session.req_header().uri.host().unwrap_or("");
            
            if !should_cache_response(resp.status.as_u16(), cache_ref, session.req_header().method.as_str(), &hm, host, body_size) {
                if resp.status.as_u16() == 206 && cache_ref.allow_partial_content { }
                else { return Ok(pingora_cache::RespCacheable::Uncacheable(pingora_cache::NoCacheReason::Custom("PolicyMismatch"))); }
            }

            let mut max_bytes = i64::MAX;
            if let Some(policy) = &ctx.cache_policy && let Some(cap) = &policy.max_item_size {
                let b = crate::config_models::SizeCapacity::from_json(cap).to_bytes();
                if b > 0 { max_bytes = b; }
            }
            if let Some(cap) = &cache_ref.max_size {
                let b = crate::config_models::SizeCapacity::from_json(cap).to_bytes();
                if b > 0 && b < max_bytes { max_bytes = b; }
            }
            if max_bytes > 0 && (body_size as i64) > max_bytes { return Ok(pingora_cache::RespCacheable::Uncacheable(pingora_cache::NoCacheReason::Custom("FileTooLarge"))); }

            let ttl = cache_ref.life.as_ref().map(crate::config_models::parse_life_to_seconds).unwrap_or(3600);
            
            let mut cached_header = pingora_http::ResponseHeader::build(resp.status.as_u16(), Some(resp.headers.len())).unwrap();
            for (k, v) in resp.headers.iter() {
                // Pingora's internal cache meta validation natively REJECTS saving any response with Set-Cookie.
                // If we reach here, it means our custom `should_cache_response` ALLOWED caching.
                // Therefore, we MUST strip Set-Cookie so Pingora actually saves it to disk.
                if k.as_str().eq_ignore_ascii_case("set-cookie") {
                    continue;
                }
                if k.as_str().eq_ignore_ascii_case("cache-control") {
                    // Force a valid Cache-Control so Pingora doesn't reject it internally
                    cached_header.insert_header("cache-control", format!("public, max-age={}", ttl)).unwrap();
                    continue;
                }
                cached_header.insert_header(k.clone(), v.clone()).unwrap();
            }
            if !cached_header.headers.contains_key("cache-control") {
                cached_header.insert_header("cache-control", format!("public, max-age={}", ttl)).unwrap();
            }
            
            // Add a debug log to trace why it's caching or not
            tracing::debug!("Returning Cacheable for request: {}. ttl={}", host, ttl);
            
            let now = std::time::SystemTime::now();
            let fresh_until = now + std::time::Duration::from_secs(ttl);
            let meta = pingora_cache::CacheMeta::new(fresh_until, now, 0, 0, cached_header);
            
            return Ok(pingora_cache::RespCacheable::Cacheable(meta));
        }
        Ok(pingora_cache::RespCacheable::Uncacheable(pingora_cache::NoCacheReason::Custom("NoPolicy")))
    }
}
