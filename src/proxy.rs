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
    pub max_inspection_size: i64,
    pub no_log: bool,
}

impl Default for ProxyCTX {
    fn default() -> Self {
        Self {
            start_time: std::time::Instant::now(),
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
            max_inspection_size: 512 * 1024, // Default 512K as per PB requirement
            no_log: false,
        }
    }
}

pub struct EdgeProxy {
    pub config: Arc<ConfigStore>,
    pub waf_state: Arc<WafStateManager>,
    pub api_config: Arc<ApiConfig>,
}

impl EdgeProxy {
    fn check_waf_cookies(&self, session: &Session, ip_str: &str, ctx: &ProxyCTX) -> bool {
        if let Some(cookies) = session.get_header("cookie").and_then(|v| v.to_str().ok()) {
            for part in cookies.split(';') {
                let part = part.trim();
                if let Some(token) = part.strip_prefix("WAF-Challenge=") {
                    if crate::auth::verify_waf_challenge_token(
                        ip_str,
                        token,
                        &self.api_config.secret,
                        3600,
                    ) {
                        // Success! Let's proactively unblock this IP in WafStateManager 
                        // so it doesn't get hit by is_blocked next time.
                        if let Ok(ip) = ip_str.parse() {
                            let server_id = ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0);
                            // We don't have the original policy's use_local_firewall flag here, 
                            // but usually challenge success should clear local blocks.
                            self.waf_state.unblock_ip(ip, server_id, Some("server"), true);
                        }
                        return true;
                    }
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
                }

                let resolved_body = crate::firewall::matcher_plus::format_variables(session, &body, &ctx.request_body);
                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                resp.insert_header("Content-Type", "text/html; charset=utf-8").unwrap();
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
                resp.insert_header("Content-Type", content_type).unwrap();
                session.write_response_header(Box::new(resp), false).await?;
                session.write_response_body(Some(Bytes::from(resolved_body)), true).await?;
                Ok(true)
            }
            crate::firewall::ActionResponse::Redirect { status, location } => {
                let resolved_url = crate::firewall::matcher_plus::format_variables(session, &location, &ctx.request_body);
                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                resp.insert_header("Location", resolved_url).unwrap();
                session.write_response_header(Box::new(resp), true).await?;
                Ok(true)
            }
            crate::firewall::ActionResponse::Captcha { mut life_seconds } | 
            crate::firewall::ActionResponse::JsCookie { mut life_seconds } |
            crate::firewall::ActionResponse::Get302 { mut life_seconds } |
            crate::firewall::ActionResponse::Post307 { mut life_seconds } => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
                let ts = (now / 10) * 10;
                let token = crate::auth::generate_waf_challenge_token(&ip, ts, &self.api_config.secret);
                
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
                    body_html = if matches!(action, crate::firewall::ActionResponse::JsCookie { .. }) {
                        format!("<!doctype html><html><body><script>document.cookie='WAF-Challenge={}; Path=/; Max-Age={}'; window.location.reload();</script></body></html>", token, life_seconds)
                    } else {
                        format!("<!doctype html><html><body><h1>Verification Required</h1><form><input type='hidden' name='__waf_token' value='{}'/><button type='submit'>Verify</button></form></body></html>", token)
                    };
                }

                let mut resp = pingora_http::ResponseHeader::build(status as u16, None).unwrap();
                if is_redirect {
                    let mut path_and_query = session.req_header().uri.path().to_string();
                    let connector = if path_and_query.contains('?') { "&" } else { "?" };
                    path_and_query.push_str(&format!("{connector}__waf_token={token}"));
                    resp.insert_header("Location", path_and_query).unwrap();
                    session.write_response_header(Box::new(resp), true).await?;
                } else {
                    resp.insert_header("Content-Type", "text/html; charset=utf-8").unwrap();
                    resp.insert_header("Set-Cookie", format!("WAF-Challenge={token}; Path=/; HttpOnly; Max-Age={life_seconds}")).unwrap();
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
        let host = session.req_header().uri.host().unwrap_or("").to_string();
        ctx.server = self.config.get_server_sync(&host);
        ctx.lb = self.config.get_upstream_sync(&host);

        if ctx.server.is_none() {
            session.respond_error(404).await?;
            return Ok(true);
        }

        let ip = match session.client_addr() {
            Some(pingora_core::protocols::l4::socket::SocketAddr::Inet(addr)) => addr.ip(),
            _ => "127.0.0.1".parse().unwrap(),
        };
        let ip_str = ip.to_string();

        if self.waf_state.is_whitelisted(ip, ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0)) {
            return Ok(false);
        }

        if self.check_waf_cookies(session, &ip_str, ctx) {
            return Ok(false);
        }

        if self.waf_state.is_blocked(ip, ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0)) {
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
                        self.waf_state.block_ip(ip, 0, ban, Some("global"), false, gp.use_local_firewall);
                        session.respond_error(403).await?;
                        return Ok(true);
                    }
                }
            }

            // 1.2 TLS Exhaustion Attack
            if let Some(cfg) = &gp.tls_exhaustion_attack {
                if cfg.is_on && session.req_header().uri.scheme_str() == Some("https") {
                    let threshold = cfg.threshold.max(10);
                    let period = if cfg.period > 0 { cfg.period as i64 } else { 60 };
                    let ban = if cfg.ban_duration > 0 { cfg.ban_duration as i64 } else { 3600 };

                    if !self.waf_state.check_special_defense(format!("TLS:{}", ip_str), threshold, period) {
                        self.waf_state.block_ip(ip, 0, ban, Some("global"), true, gp.use_local_firewall);
                        session.respond_error(403).await?;
                        return Ok(true);
                    }
                }
            }
        }

        // 2. Evaluate WAF Policies
        let mut waf_action = None;
        if let Some(server) = &ctx.server 
            && let Some(web) = &server.web {
                if let Some(policy) = &web.firewall_policy {
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
        
        if waf_action.is_none() {
            for gp in &global_policies {
                if let Some(action) = crate::firewall::evaluate_policy(gp, session, &ctx.request_body) {
                    waf_action = Some(action);
                    break;
                }
            }
        }

        if let Some(matched) = waf_action {
            ctx.waf_policy_id = matched.policy_id;
            ctx.waf_group_id = matched.group_id;
            ctx.waf_set_id = matched.set_id;
            ctx.waf_action = Some(matched.action_code.clone());

            if matched.action_code == "record_ip_white" {
                self.waf_state.unblock_ip(ip, ctx.server.as_ref().and_then(|s| s.id).unwrap_or(0), matched.scope.as_deref(), matched.use_local_firewall);
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
                    ip,
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
                            if cc.per_ip_max_qps > 0 && !self.waf_state.check_ip_rate_limit(server.id.unwrap_or(0), ip, cc.per_ip_max_qps as u32) {
                                // Block IP if configured
                                if cc.block_ip {
                                    let ban = if cc.block_ip_duration > 0 { cc.block_ip_duration as i64 } else { 3600 };
                                    self.waf_state.block_ip(ip, server.id.unwrap_or(0), ban, Some("server"), false, true);
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
                        resp.insert_header("Location", location).unwrap();
                        session.write_response_header(Box::new(resp), true).await?;
                        return Ok(true);
                    }
                }

                if !web.rewrite_rules.is_empty()
                    && let RewriteResult::Redirect { location, status } = evaluate_rewrites(uri_str, query, &web.rewrite_refs, &web.rewrite_rules) {
                    let mut resp = pingora_http::ResponseHeader::build(status, None).unwrap();
                    resp.insert_header("Location", location).unwrap();
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }

        Ok(false)
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        if let Some(lb) = &ctx.lb
            && let Some(peer) = lb.select(b"", 0) {
                let peer_addr = peer.to_string();
                let is_tls = peer_addr.contains("443");
                let host = session.req_header().uri.host().unwrap_or("localhost").to_string();
                return Ok(Box::new(HttpPeer::new(peer_addr, is_tls, host)));
            }
        Err(Error::new(InternalError))
    }

    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<pingora_cache::CacheKey> {
        let key = ctx.cache_key.clone().unwrap_or_else(|| {
             format!("{}:{}", session.req_header().uri.host().unwrap_or(""), session.req_header().uri.path())
        });
        Ok(pingora_cache::CacheKey::new("", "", key))
    }

    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        let ip = match session.client_addr() {
            Some(pingora_core::protocols::l4::socket::SocketAddr::Inet(addr)) => addr.ip(),
            _ => "127.0.0.1".parse().unwrap(),
        };

        if let Some(s) = &ctx.server
            && let Some(web) = &s.web
                && let Some(cache) = &web.cache
                    && cache.is_on {
                        if !self.waf_state.check_cache_limit(ip) {
                            tracing::warn!("IP {} exceeded cache-miss frequency limit.", ip);
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
                                if cache_ref.is_reverse { return Ok(()); }
                                matched_ref = Some(cache_ref.clone());
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
                                        if cache_ref.is_reverse { return Ok(()); }
                                        matched_ref = Some(cache_ref.clone());
                                        break;
                                    }
                                }
                            }
                        }

                        if let Some(cache_ref) = matched_ref {
                            if cache_ref.always_forward_range_request && session.get_header("Range").is_some() { return Ok(()); }
                            if cache_ref.enable_request_cache_pragma {
                                let cc = session.get_header("Cache-Control").and_then(|v| v.to_str().ok()).unwrap_or("");
                                let pragma = session.get_header("Pragma").and_then(|v| v.to_str().ok()).unwrap_or("");
                                if cc.contains("no-cache") || pragma.contains("no-cache") { return Ok(()); }
                            }

                            ctx.cache_policy = cache_ref.cache_policy.clone();
                            ctx.cache_ref = Some(cache_ref.clone());
                            let key = if let Some(key_template) = &cache_ref.key { crate::cache::matching::format_variables(session, key_template) }
                                else { format!("{}:{}", session.req_header().uri.host().unwrap_or(""), session.req_header().uri.path()) };
                            ctx.cache_key = Some(key);

                            if !cache_ref.enable_if_none_match { session.req_header_mut().headers.remove("If-None-Match"); }
                            if !cache_ref.enable_if_modified_since { session.req_header_mut().headers.remove("If-Modified-Since"); }

                            session.cache.enable(CACHE.storage, None, None, None, None);
                        }
                    }
        Ok(())
    }

    async fn upstream_response_filter(&self, _session: &mut Session, upstream_response: &mut pingora::http::ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        if let Some(cache_ref) = &ctx.cache_ref && let Some(expires_cfg) = &cache_ref.expires_time && expires_cfg.is_on {
            if expires_cfg.overwrite || upstream_response.headers.get("Expires").is_none() {
                if let Some(duration_val) = &expires_cfg.duration {
                    let seconds = crate::config_models::parse_life_to_seconds(duration_val);
                    if seconds > 0 {
                        let expires = chrono::Utc::now() + chrono::Duration::seconds(seconds as i64);
                        upstream_response.insert_header("Expires", expires.to_rfc2822().replace("+0000", "GMT")).unwrap();
                        upstream_response.insert_header("Cache-Control", format!("max-age={}", seconds)).unwrap();
                    }
                }
            }
        }
        Ok(())
    }

    async fn response_filter(&self, _session: &mut Session, upstream_response: &mut pingora::http::ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        ctx.response_status = upstream_response.status.as_u16();
        ctx.ttfb = Some(ctx.start_time.elapsed());
        if let Some(cache_ref) = &ctx.cache_ref && let Some(expires_cfg) = &cache_ref.expires_time && expires_cfg.is_on && expires_cfg.auto_calculate {
            if expires_cfg.overwrite || upstream_response.headers.get("Expires").is_none() {
                let ttl = cache_ref.life.as_ref().map(crate::config_models::parse_life_to_seconds).unwrap_or(3600);
                let expires = chrono::Utc::now() + chrono::Duration::seconds(ttl as i64);
                upstream_response.insert_header("Expires", expires.to_rfc2822().replace("+0000", "GMT")).unwrap();
                upstream_response.insert_header("Cache-Control", format!("max-age={}", ttl)).unwrap();
            }
        }
        Ok(())
    }

    fn response_cache_filter(&self, session: &Session, resp: &pingora_http::ResponseHeader, ctx: &mut Self::CTX) -> Result<pingora_cache::RespCacheable> {
        if let Some(cache_ref) = &ctx.cache_ref {
            let mut hm: HashMap<String, String> = HashMap::new();
            for (k, v) in resp.headers.iter() { hm.insert(k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string()); }
            let body_size = resp.headers.get("Content-Length").and_then(|v| v.to_str().ok()).and_then(|s: &str| s.parse::<usize>().ok()).unwrap_or(0);
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
            return Ok(pingora_cache::RespCacheable::Cacheable(crate::cache_manager::create_meta(resp.status.as_u16(), ttl)));
        }
        Ok(pingora_cache::RespCacheable::Uncacheable(pingora_cache::NoCacheReason::Custom("NoPolicy")))
    }
}
