pub mod compiled;
pub mod kernel;
pub mod lists;
pub mod matcher;
pub mod matcher_plus;
pub mod state;
pub mod uam;
pub mod verifier;

use crate::config_models::{
    HTTPFirewallPolicy, HTTPFirewallRegionConfig, HTTPFirewallRule, ServerConfig, WAFBlockOptions,
    WAFCaptchaOptions, WAFJSCookieOptions, WAFPageOptions,
};
use crate::metrics::analyzer;
use ahash::AHasher;
use pingora_proxy::Session;
use serde_json::Value;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::Instant;
use tracing::warn;

#[derive(Debug, Clone)]
pub enum ActionResponse {
    Allow,
    Block {
        status: i32,
        body: String,
    },
    Page {
        status: i32,
        body: String,
        content_type: String,
    },
    Captcha {
        life_seconds: i64,
    },
    JsCookie {
        life_seconds: i64,
    },
    Redirect {
        status: i32,
        location: String,
    },
    Get302 {
        life_seconds: i64,
    },
    Post307 {
        life_seconds: i64,
    },
}

#[derive(Clone)]
pub struct MatchedAction {
    pub action: ActionResponse,
    pub policy_id: i64,
    pub group_id: i64,
    pub set_id: i64,
    pub action_code: String,

    // Config Parameters
    pub timeout_secs: Option<i64>,
    pub max_timeout_secs: Option<i64>,
    pub life_seconds: Option<i64>,
    pub max_fails: Option<i32>,
    pub fail_block_timeout: Option<i64>,
    pub fail_global: Option<bool>,
    pub scope: Option<String>,
    pub block_c_class: bool,
    pub use_local_firewall: bool,
    pub next_group_id: Option<i64>,
    pub next_set_id: Option<i64>,
    pub allow_scope: Option<String>, // "group", "server", "policy"
    pub tags: Vec<String>,
    pub ip_list_id: i64,
    pub event_level: String,

    // Custom Response Options from Policy (matching PB spec)
    pub block_options: Option<WAFBlockOptions>,
    pub page_options: Option<WAFPageOptions>,
    pub captcha_options: Option<WAFCaptchaOptions>,
    pub js_cookie_options: Option<WAFJSCookieOptions>,
    pub chained_actions: Vec<MatchedAction>,
    pub observe_only: bool,
}

pub struct OutboundContext<'a> {
    pub status: u16,
    pub headers: &'a HashMap<String, String>,
    pub body: &'a [u8],
    pub bytes_sent: usize,
}

pub fn pick_ruleset<'a>(
    policy: &'a HTTPFirewallPolicy,
    client_ip: IpAddr,
    path: &str,
) -> (&'a [HTTPFirewallRule], Option<i64>) {
    let Some(candidate_rules) = &policy.candidate_rules else {
        return (&[], None);
    };
    let pct = policy.candidate_traffic_pct.min(100) as u64;
    if pct == 0 {
        return (&[], None);
    }
    let mut hasher = AHasher::default();
    client_ip.hash(&mut hasher);
    path.hash(&mut hasher);
    let bucket = hasher.finish() % 100;
    if bucket < pct {
        (candidate_rules.as_slice(), Some(policy.candidate_version))
    } else {
        (&[], None)
    }
}

pub fn evaluate_policy(
    policy: &HTTPFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
) -> Option<MatchedAction> {
    evaluate_policy_with_server(policy, session, request_body, scheme, None)
}

pub fn evaluate_policy_with_server(
    policy: &HTTPFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchedAction> {
    let started = Instant::now();
    let matched = evaluate_policy_inner(policy, session, request_body, scheme, server);
    crate::metrics::METRICS
        .waf
        .record_legacy_evaluation(matched.is_some(), started.elapsed());
    matched
}

fn evaluate_policy_inner(
    policy: &HTTPFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchedAction> {
    if !policy.is_on || policy.mode == "bypass" {
        return None;
    }

    if let Some(inbound) = &policy.inbound {
        if !inbound.is_on {
            return None;
        }

        let mut current_group_idx = 0;
        let mut next_start_set_id: Option<i64> = None;
        // Bounded flow-control to defuse misconfigured GO_GROUP / GO_SET cycles
        // (e.g. group A → group B → group A). Without a cap a single request
        // can pin a worker thread indefinitely.
        let mut remaining_jumps: usize = inbound.groups.len().saturating_mul(8).max(64);
        while current_group_idx < inbound.groups.len() {
            if remaining_jumps == 0 {
                warn!(
                    "WAF: aborting policy {} due to flow-control jump limit (possible group cycle)",
                    policy.id
                );
                return None;
            }
            remaining_jumps -= 1;
            let group = &inbound.groups[current_group_idx];
            if !group.is_on {
                current_group_idx += 1;
                next_start_set_id = None;
                continue;
            }

            let start_set = next_start_set_id.take();
            if let Some(result) = matcher_plus::match_group_from(
                group,
                session,
                request_body,
                scheme,
                server,
                start_set,
            ) {
                if let Some(set) = result.set {
                    if let Some(mut matched) = perform_actions(&set.actions) {
                        fill_action_context(
                            &mut matched,
                            policy.id,
                            group.id,
                            set.id,
                            policy.use_local_firewall,
                        );
                        fill_action_options(policy, &mut matched);

                        apply_observe_mode(policy, &mut matched);

                        // Flow Control: ALLOW Scope
                        if matched.action_code == "allow" {
                            match matched.allow_scope.as_deref() {
                                Some("group") => {
                                    current_group_idx += 1;
                                    continue;
                                }
                                Some("server") | Some("policy") => return Some(matched),
                                _ => {}
                            }
                        }

                        // Flow Control: GO_GROUP
                        if let Some(next_gid) = matched.next_group_id {
                            if let Some(idx) = inbound.groups.iter().position(|g| g.id == next_gid)
                            {
                                current_group_idx = idx;
                                continue;
                            }
                        }

                        // Flow Control: GO_SET — precise jump to the named set
                        if let Some(next_sid) = matched.next_set_id {
                            let target = inbound.groups.iter().enumerate().find_map(|(idx, g)| {
                                g.sets.iter().any(|s| s.id == next_sid).then_some(idx)
                            });
                            if let Some(idx) = target {
                                current_group_idx = idx;
                                next_start_set_id = Some(next_sid);
                                continue;
                            }
                        }

                        if matched.action_code == "log" {
                            current_group_idx += 1;
                            continue;
                        }

                        return Some(matched);
                    }
                }
                if result.matched {
                    let mut action = default_block_action(policy.id, group.id);
                    apply_observe_mode(policy, &mut action);
                    return Some(action);
                }
            }
            current_group_idx += 1;
        }
    }
    None
}

pub fn inbound_policy_uses_request_body(policy: &HTTPFirewallPolicy) -> bool {
    if !policy.is_on || policy.mode == "bypass" {
        return false;
    }
    let Some(inbound) = &policy.inbound else {
        return false;
    };
    if !inbound.is_on {
        return false;
    }

    inbound.groups.iter().any(|group| {
        group.is_on
            && (group.code.is_some()
                || group.sets.iter().any(|set| {
                    set.is_on
                        && set.rules.iter().any(|rule| {
                            crate::firewall::matcher_plus::expression_uses_request_body(&rule.param)
                                || rule.checkpoint_options.as_ref().is_some_and(
                                    crate::firewall::matcher_plus::value_uses_request_body,
                                )
                        })
                }))
    })
}

pub fn outbound_policy_uses_response_body(policy: &HTTPFirewallPolicy) -> bool {
    if !policy.is_on || policy.mode == "bypass" {
        return false;
    }
    let Some(outbound) = &policy.outbound else {
        return false;
    };
    if !outbound.is_on {
        return false;
    }

    outbound.groups.iter().any(|group| {
        group.is_on
            && group.sets.iter().any(|set| {
                set.is_on
                    && set.rules.iter().any(|rule| {
                        crate::firewall::matcher_plus::expression_uses_response_body(&rule.param)
                            || crate::firewall::matcher_plus::expression_uses_response_body(
                                &rule.value,
                            )
                            || rule.checkpoint_options.as_ref().is_some_and(
                                crate::firewall::matcher_plus::value_uses_response_body,
                            )
                    })
            })
    })
}

pub fn evaluate_outbound_policy(
    policy: &HTTPFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
) -> Option<MatchedAction> {
    evaluate_outbound_policy_with_server(policy, session, request_body, response, scheme, None)
}

pub fn evaluate_outbound_policy_with_server(
    policy: &HTTPFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchedAction> {
    let started = Instant::now();
    let matched =
        evaluate_outbound_policy_inner(policy, session, request_body, response, scheme, server);
    crate::metrics::METRICS
        .waf
        .record_legacy_evaluation(matched.is_some(), started.elapsed());
    matched
}

fn evaluate_outbound_policy_inner(
    policy: &HTTPFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
    scheme: &str,
    server: Option<&ServerConfig>,
) -> Option<MatchedAction> {
    if !policy.is_on || policy.mode == "bypass" {
        return None;
    }

    if let Some(outbound) = &policy.outbound {
        if !outbound.is_on {
            return None;
        }

        for group in &outbound.groups {
            if !group.is_on {
                continue;
            }
            if let Some(result) = matcher_plus::match_group_response_with_server(
                group,
                session,
                request_body,
                response,
                scheme,
                server,
            ) {
                if let Some(set) = result.set {
                    if let Some(mut matched) = perform_actions(&set.actions) {
                        fill_action_context(
                            &mut matched,
                            policy.id,
                            group.id,
                            set.id,
                            policy.use_local_firewall,
                        );
                        fill_action_options(policy, &mut matched);

                        apply_observe_mode(policy, &mut matched);

                        return Some(matched);
                    }
                }
                if result.matched {
                    let mut action = default_block_action(policy.id, group.id);
                    apply_observe_mode(policy, &mut action);
                    return Some(action);
                }
            }
        }
    }
    None
}

pub(crate) fn fill_action_context(
    matched: &mut MatchedAction,
    policy_id: i64,
    group_id: i64,
    set_id: i64,
    use_local_firewall: bool,
) {
    matched.policy_id = policy_id;
    matched.group_id = group_id;
    matched.set_id = set_id;
    matched.use_local_firewall = use_local_firewall;
    for chained in &mut matched.chained_actions {
        fill_action_context(chained, policy_id, group_id, set_id, use_local_firewall);
    }
}

pub(crate) fn fill_action_options(policy: &HTTPFirewallPolicy, matched: &mut MatchedAction) {
    if matched.block_options.is_none() {
        matched.block_options = policy.block_options.clone();
    }
    if matched.page_options.is_none() {
        matched.page_options = policy.page_options.clone();
    }
    match (
        &mut matched.captcha_options,
        policy.captcha_options.as_ref(),
    ) {
        (Some(action), Some(policy)) => merge_captcha_options(action, policy),
        (None, Some(policy)) => {
            let mut inherited = policy.clone();
            inherited.method = inherited_captcha_method(policy);
            matched.captcha_options = Some(inherited);
        }
        _ => {}
    }
    match (
        &mut matched.js_cookie_options,
        policy.js_cookie_options.as_ref(),
    ) {
        (Some(action), Some(policy)) => merge_js_cookie_options(action, policy),
        (None, Some(policy)) => matched.js_cookie_options = Some(policy.clone()),
        _ => {}
    }
    for chained in &mut matched.chained_actions {
        fill_action_options(policy, chained);
    }
}

pub(crate) fn apply_observe_mode(policy: &HTTPFirewallPolicy, matched: &mut MatchedAction) {
    if policy.mode == "observe" {
        matched.observe_only = true;
        if is_blocking_action_code(&matched.action_code) {
            matched.action = ActionResponse::Allow;
        }
    }
    for chained in &mut matched.chained_actions {
        apply_observe_mode(policy, chained);
    }
}

pub(crate) fn is_blocking_action_code(action_code: &str) -> bool {
    // Anything that changes user/WAF state (block, captcha, record into an
    // IP list, etc.) is "blocking" in the sense that observe mode must skip
    // its side effects — observe is supposed to mean "log only, do not
    // alter state". record_ip_white / record_ip_gray were previously not in
    // this list, so an attacker could trigger a rule in observe mode and
    // get themselves added to a whitelist or graylist — an actual
    // observe-mode bypass.
    matches!(
        action_code,
        "block"
            | "page"
            | "record_ip"
            | "record_ip_white"
            | "recordIPWhite"
            | "record_ip_gray"
            | "recordIPGray"
            | "record_ip_grey"
            | "recordIPGrey"
            | "captcha"
            | "js_cookie"
            | "jsCookie"
            | "jscookie"
            | "get_302"
            | "post_307"
    )
}

pub(crate) fn default_block_action(policy_id: i64, group_id: i64) -> MatchedAction {
    MatchedAction {
        action: ActionResponse::Block {
            status: 403,
            body: "Blocked by WAF".to_string(),
        },
        policy_id,
        group_id,
        set_id: 0,
        action_code: "block".to_string(),
        timeout_secs: None,
        max_timeout_secs: None,
        life_seconds: None,
        max_fails: None,
        fail_block_timeout: None,
        fail_global: None,
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
        chained_actions: vec![],
        observe_only: false,
    }
}

fn normalize_action_code(code: &str) -> String {
    match code.trim() {
        "jsCookie" | "js-cookie" | "jscookie" | "JSCookie" => "js_cookie".to_string(),
        other => other.to_ascii_lowercase(),
    }
}

fn captcha_options_from_value(options: Option<&Value>) -> Option<WAFCaptchaOptions> {
    let mut parsed: WAFCaptchaOptions = serde_json::from_str(&options?.to_string()).ok()?;
    normalize_captcha_options(&mut parsed);
    Some(parsed)
}

pub(crate) fn captcha_method_is_default(method: &str) -> bool {
    let trimmed = method.trim();
    if matches!(trimmed, "" | "默认") {
        return true;
    }
    trimmed.eq_ignore_ascii_case("default")
}

fn inherited_captcha_method(policy: &WAFCaptchaOptions) -> String {
    if captcha_options_use_geetest(policy) {
        "geetest".to_string()
    } else {
        policy.method.clone()
    }
}

pub(crate) fn normalize_captcha_options(options: &mut WAFCaptchaOptions) {
    if let Some(config) = &options.geetest_config {
        options.use_geetest = options.use_geetest || config.is_on;
        if options.geetest_id.trim().is_empty() {
            options.geetest_id = config.captcha_id.clone();
        }
        if options.geetest_key.trim().is_empty() {
            options.geetest_key = config.captcha_key.clone();
        }
    }
}

pub(crate) fn captcha_options_use_geetest(options: &WAFCaptchaOptions) -> bool {
    options.use_geetest
        || options
            .geetest_config
            .as_ref()
            .map(|config| config.is_on)
            .unwrap_or(false)
}

fn js_cookie_options_from_value(options: Option<&Value>) -> Option<WAFJSCookieOptions> {
    serde_json::from_str(&options?.to_string()).ok()
}

pub(crate) fn merge_captcha_options(action: &mut WAFCaptchaOptions, policy: &WAFCaptchaOptions) {
    let inherit_method = captcha_method_is_default(&action.method);
    let should_copy_geetest_config = inherit_method
        || action.use_geetest
        || action.method.trim().eq_ignore_ascii_case("geetest");
    if action.life_seconds <= 0 {
        action.life_seconds = policy.life_seconds;
    }
    if action.max_fails <= 0 {
        action.max_fails = policy.max_fails;
    }
    if action.fail_block_timeout <= 0 {
        action.fail_block_timeout = policy.fail_block_timeout;
    }
    action.fail_global = action.fail_global || policy.fail_global;
    if action.count <= 0 {
        action.count = policy.count;
    }
    if inherit_method {
        action.use_geetest = action.use_geetest || captcha_options_use_geetest(policy);
    }
    if should_copy_geetest_config && action.geetest_id.trim().is_empty() {
        action.geetest_id = policy.geetest_id.clone();
    }
    if should_copy_geetest_config && action.geetest_key.trim().is_empty() {
        action.geetest_key = policy.geetest_key.clone();
    }
    if should_copy_geetest_config && action.geetest_config.is_none() {
        action.geetest_config = policy.geetest_config.clone();
        normalize_captcha_options(action);
    }
    if inherit_method {
        action.method = inherited_captcha_method(policy);
    }
    if action.challenge_lang.trim().is_empty() {
        action.challenge_lang = policy.challenge_lang.clone();
    }
    if action.challenge_difficulty == 0 {
        action.challenge_difficulty = policy.challenge_difficulty;
    }
    if action.ui.is_none() {
        action.ui = policy.ui.clone();
    }
}

fn merge_js_cookie_options(action: &mut WAFJSCookieOptions, policy: &WAFJSCookieOptions) {
    if action.life_seconds <= 0 {
        action.life_seconds = policy.life_seconds;
    }
    if action.max_fails <= 0 {
        action.max_fails = policy.max_fails;
    }
    if action.fail_block_timeout <= 0 {
        action.fail_block_timeout = policy.fail_block_timeout;
    }
    action.fail_global = action.fail_global || policy.fail_global;
}

pub(crate) fn parse_action_event_level(options: Option<&Value>) -> String {
    let Some(options) = options else {
        return "error".to_string();
    };
    ["eventLevel", "event_level", "level", "severity"]
        .into_iter()
        .find_map(|key| options.get(key).and_then(normalize_event_level_value))
        .unwrap_or("error")
        .to_string()
}

fn normalize_event_level_value(value: &Value) -> Option<&'static str> {
    if let Some(s) = value.as_str() {
        return normalize_event_level_str(s);
    }
    if let Some(n) = value.as_i64() {
        return normalize_event_level_str(match n {
            0 => "0",
            1 => "1",
            2 => "2",
            3 => "3",
            _ => return None,
        });
    }
    value.as_object().and_then(|object| {
        ["code", "value", "name", "label"]
            .into_iter()
            .find_map(|key| object.get(key).and_then(normalize_event_level_value))
    })
}

fn normalize_event_level_str(value: &str) -> Option<&'static str> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(match value.to_ascii_lowercase().as_str() {
        "critical" | "fatal" | "severe" | "serious" | "2" => "critical",
        "warn" | "warning" | "1" => "warning",
        "notice" | "notify" | "notification" | "info" | "0" => "notice",
        "error" | "err" | "3" => "error",
        _ => match value {
            "严重" => "critical",
            "警告" | "告警" => "warning",
            "通知" | "信息" => "notice",
            "错误" => "error",
            _ => return None,
        },
    })
}

fn parse_action(action: &Value) -> Option<MatchedAction> {
    let code = action
        .get("code")
        .or_else(|| action.get("action"))
        .and_then(Value::as_str)
        .map(normalize_action_code)?;
    let options = action.get("options");

    match code.as_str() {
        "block" => {
            let timeout = options
                .and_then(|v| v.get("timeout"))
                .and_then(Value::as_i64);
            let scope = options
                .and_then(|v| v.get("scope"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let ip_list_id = options
                .and_then(|v| v.get("ipListId"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let event_level = parse_action_event_level(options);
            return Some(MatchedAction {
                action: ActionResponse::Block {
                    status: options
                        .and_then(|v| v.get("status"))
                        .and_then(Value::as_i64)
                        .unwrap_or(403) as i32,
                    body: options
                        .and_then(|v| v.get("body"))
                        .and_then(Value::as_str)
                        .unwrap_or("Blocked by WAF")
                        .to_string(),
                },
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "block".to_string(),
                timeout_secs: timeout,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: options
                    .and_then(|v| v.get("failBlockScopeAll"))
                    .and_then(Value::as_bool),
                scope,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags: vec![],
                ip_list_id,
                event_level,
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "allow" => {
            let scope = options
                .and_then(|v| v.get("scope"))
                .and_then(Value::as_str)
                .unwrap_or("group")
                .to_string();
            return Some(MatchedAction {
                action: ActionResponse::Allow,
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "allow".to_string(),
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: Some(scope),
                tags: vec![],
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "log" => {
            return Some(MatchedAction {
                action: ActionResponse::Allow,
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "log".to_string(),
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags: vec![],
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "tag" => {
            let tags: Vec<String> = options
                .and_then(|v| v.get("tags"))
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();
            return Some(MatchedAction {
                action: ActionResponse::Allow,
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "tag".to_string(),
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags,
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "notify" => {
            return Some(MatchedAction {
                action: ActionResponse::Allow,
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "notify".to_string(),
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags: vec![],
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "record_ip" => {
            let ip_type = options
                .and_then(|v| v.get("type"))
                .and_then(Value::as_str)
                .unwrap_or("black")
                .to_ascii_lowercase();
            let timeout = options
                .and_then(|v| v.get("timeout"))
                .and_then(Value::as_i64);
            let scope = options
                .and_then(|v| v.get("scope"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let ip_list_id = options
                .and_then(|v| v.get("ipListId"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let event_level = parse_action_event_level(options);

            match ip_type.as_str() {
                "black" | "deny" => {
                    return Some(MatchedAction {
                        action: ActionResponse::Block {
                            status: 403,
                            body: "Blocked by WAF".to_string(),
                        },
                        policy_id: 0,
                        group_id: 0,
                        set_id: 0,
                        action_code: "record_ip".to_string(),
                        timeout_secs: timeout,
                        max_timeout_secs: None,
                        life_seconds: None,
                        max_fails: None,
                        fail_block_timeout: None,
                        fail_global: None,
                        scope,
                        block_c_class: false,
                        use_local_firewall: false,
                        next_group_id: None,
                        next_set_id: None,
                        allow_scope: None,
                        tags: vec![],
                        ip_list_id,
                        event_level,
                        block_options: None,
                        page_options: None,
                        captcha_options: None,
                        js_cookie_options: None,
                        chained_actions: vec![],
                        observe_only: false,
                    });
                }
                "white" | "allow" => {
                    return Some(MatchedAction {
                        action: ActionResponse::Allow,
                        policy_id: 0,
                        group_id: 0,
                        set_id: 0,
                        action_code: "record_ip_white".to_string(),
                        timeout_secs: timeout,
                        max_timeout_secs: None,
                        life_seconds: None,
                        max_fails: None,
                        fail_block_timeout: None,
                        fail_global: None,
                        scope,
                        block_c_class: false,
                        use_local_firewall: false,
                        next_group_id: None,
                        next_set_id: None,
                        allow_scope: None,
                        tags: vec![],
                        ip_list_id,
                        event_level,
                        block_options: None,
                        page_options: None,
                        captcha_options: None,
                        js_cookie_options: None,
                        chained_actions: vec![],
                        observe_only: false,
                    });
                }
                "gray" | "grey" => {
                    return Some(MatchedAction {
                        action: ActionResponse::Allow,
                        policy_id: 0,
                        group_id: 0,
                        set_id: 0,
                        action_code: "record_ip_gray".to_string(),
                        timeout_secs: timeout,
                        max_timeout_secs: None,
                        life_seconds: None,
                        max_fails: None,
                        fail_block_timeout: None,
                        fail_global: None,
                        scope,
                        block_c_class: false,
                        use_local_firewall: false,
                        next_group_id: None,
                        next_set_id: None,
                        allow_scope: None,
                        tags: vec![],
                        ip_list_id,
                        event_level,
                        block_options: None,
                        page_options: None,
                        captcha_options: None,
                        js_cookie_options: None,
                        chained_actions: vec![],
                        observe_only: false,
                    });
                }
                _ => {}
            }
        }
        "page" => {
            let status = options
                .and_then(|v| v.get("status"))
                .and_then(Value::as_i64)
                .unwrap_or(403) as i32;
            let body = options
                .and_then(|v| v.get("body"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Some(MatchedAction {
                action: ActionResponse::Page {
                    status,
                    body,
                    content_type: "text/html; charset=utf-8".to_string(),
                },
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "page".to_string(),
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags: vec![],
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "redirect" => {
            let status = options
                .and_then(|v| v.get("status"))
                .and_then(Value::as_i64)
                .unwrap_or(302) as i32;
            let url = options
                .and_then(|v| v.get("url"))
                .and_then(Value::as_str)
                .unwrap_or("/")
                .to_string();
            return Some(MatchedAction {
                action: ActionResponse::Redirect {
                    status,
                    location: url,
                },
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "redirect".to_string(),
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags: vec![],
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "captcha" | "js_cookie" | "get_302" | "post_307" => {
            let life = options
                .and_then(|v| v.get("life"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let max_fails = options
                .and_then(|v| v.get("maxFails"))
                .and_then(Value::as_i64)
                .map(|value| value as i32);
            let fail_timeout = options
                .and_then(|v| v.get("failBlockTimeout"))
                .and_then(Value::as_i64);
            let fail_global = options
                .and_then(|v| v.get("failBlockScopeAll"))
                .and_then(Value::as_bool);
            let action = match code.as_str() {
                "captcha" => ActionResponse::Captcha { life_seconds: life },
                "js_cookie" => ActionResponse::JsCookie { life_seconds: life },
                "get_302" => ActionResponse::Get302 { life_seconds: life },
                _ => ActionResponse::Post307 { life_seconds: life },
            };
            return Some(MatchedAction {
                action,
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: code,
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: Some(life),
                max_fails,
                fail_block_timeout: fail_timeout,
                fail_global,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags: vec![],
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: captcha_options_from_value(options),
                js_cookie_options: js_cookie_options_from_value(options),
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "go_group" => {
            let gid = options
                .and_then(|v| v.get("groupId"))
                .and_then(Value::as_i64);
            return Some(MatchedAction {
                action: ActionResponse::Allow,
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "go_group".to_string(),
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: gid,
                next_set_id: None,
                allow_scope: None,
                tags: vec![],
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        "go_set" => {
            let gid = options
                .and_then(|v| v.get("groupId"))
                .and_then(Value::as_i64);
            let sid = options
                .and_then(|v| v.get("ruleSetId"))
                .and_then(Value::as_i64);
            return Some(MatchedAction {
                action: ActionResponse::Allow,
                policy_id: 0,
                group_id: 0,
                set_id: 0,
                action_code: "go_set".to_string(),
                timeout_secs: None,
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: gid,
                next_set_id: sid,
                allow_scope: None,
                tags: vec![],
                ip_list_id: 0,
                event_level: "".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
        _ => {}
    }
    None
}

fn is_response_action_code(action_code: &str) -> bool {
    matches!(
        action_code,
        "block"
            | "page"
            | "redirect"
            | "record_ip"
            | "captcha"
            | "js_cookie"
            | "jsCookie"
            | "jscookie"
            | "get_302"
            | "post_307"
    )
}

pub(crate) fn perform_actions(actions: &[Value]) -> Option<MatchedAction> {
    let ordered_actions: Vec<MatchedAction> = actions.iter().filter_map(parse_action).collect();
    let primary_index = ordered_actions
        .iter()
        .position(|action| is_response_action_code(&action.action_code))
        .unwrap_or(0);
    let mut primary = ordered_actions.get(primary_index)?.clone();
    primary.chained_actions = ordered_actions;
    Some(primary)
}

pub(crate) const SEARCH_ENGINE_BOTS: &[&str] = &[
    "googlebot",
    "bingbot",
    "baiduspider",
    "yandexbot",
    "sogou",
    "360spider",
    "duckduckbot",
    "facebookexternalhit",
    "twitterbot",
    "slurp",
    "msnbot",
    "yisouspider",
    "bytespider",
];

fn legacy_country_id_to_iso(id: i64) -> Option<&'static str> {
    match id {
        1 => Some("CN"),   // China
        2 => Some("US"),   // United States
        3 => Some("JP"),   // Japan
        4 => Some("KR"),   // South Korea
        5 => Some("GB"),   // United Kingdom
        6 => Some("DE"),   // Germany
        7 => Some("FR"),   // France
        8 => Some("RU"),   // Russia
        9 => Some("SG"),   // Singapore
        10 => Some("AU"),  // Australia
        11 => Some("IN"),  // India
        12 => Some("CA"),  // Canada
        13 => Some("BR"),  // Brazil
        14 => Some("TH"),  // Thailand
        15 => Some("VN"),  // Vietnam
        16 => Some("MY"),  // Malaysia
        17 => Some("PH"),  // Philippines
        18 => Some("ID"),  // Indonesia
        19 => Some("NL"),  // Netherlands
        20 => Some("IT"),  // Italy
        261 => Some("HK"), // Hong Kong
        262 => Some("TW"), // Taiwan
        263 => Some("MO"), // Macau
        264 => Some("CN"), // Mainland China
        _ => None,
    }
}

fn geo_region_matches_id(geo: &analyzer::GeoInfo, id: i64) -> bool {
    geo.region_id == id
        || legacy_province_id_to_name(id).map_or(false, |name| name == geo.region.as_ref())
}

fn legacy_province_id_to_name(id: i64) -> Option<&'static str> {
    match id {
        1 => Some("Beijing"),
        2 => Some("Tianjin"),
        3 => Some("Hebei"),
        4 => Some("Shanxi"),
        5 => Some("Inner Mongolia"),
        6 => Some("Liaoning"),
        7 => Some("Jilin"),
        8 => Some("Heilongjiang"),
        9 => Some("Shanghai"),
        10 => Some("Jiangsu"),
        11 => Some("Zhejiang"),
        12 => Some("Anhui"),
        13 => Some("Fujian"),
        14 => Some("Jiangxi"),
        15 => Some("Shandong"),
        16 => Some("Henan"),
        17 => Some("Hubei"),
        18 => Some("Hunan"),
        19 => Some("Guangdong"),
        20 => Some("Guangxi"),
        21 => Some("Hainan"),
        22 => Some("Chongqing"),
        23 => Some("Sichuan"),
        24 => Some("Guizhou"),
        25 => Some("Yunnan"),
        26 => Some("Tibet"),
        27 => Some("Shaanxi"),
        28 => Some("Gansu"),
        29 => Some("Qinghai"),
        30 => Some("Ningxia"),
        31 => Some("Xinjiang"),
        32 => Some("Hong Kong"),
        33 => Some("Macau"),
        34 => Some("Taiwan"),
        _ => None,
    }
}

pub fn check_region_deny(
    region: &HTTPFirewallRegionConfig,
    client_ip: IpAddr,
    policy_id: i64,
    deny_html_fallback: &str,
    user_agent: &str,
    url: &str,
) -> Option<MatchedAction> {
    if !region.is_on || !region.matches_url(url) {
        return None;
    }
    if region.allow_search_engine
        && crate::client_agent::is_verified_search_engine_ip(client_ip, user_agent)
    {
        return None;
    }
    let geo = analyzer::lookup_geo(client_ip)?;

    let has_allow_countries = !region.allow_country_ids.is_empty();
    let has_deny_countries = !region.deny_country_ids.is_empty();
    let has_allow_provinces = !region.allow_province_ids.is_empty();
    let has_deny_provinces = !region.deny_province_ids.is_empty();

    if has_allow_countries || has_deny_countries {
        let country_iso = geo.country_iso.as_ref();
        let country_blocked = if has_allow_countries {
            !region
                .allow_country_ids
                .iter()
                .any(|&id| legacy_country_id_to_iso(id).map_or(false, |iso| iso == country_iso))
        } else {
            region
                .deny_country_ids
                .iter()
                .any(|&id| legacy_country_id_to_iso(id).map_or(false, |iso| iso == country_iso))
        };
        if country_blocked {
            let html = if !region.deny_country_html.is_empty() {
                region.deny_country_html.clone()
            } else {
                deny_html_fallback.to_string()
            };
            let body = if html.is_empty() {
                "Access denied: your country is not allowed".to_string()
            } else {
                html
            };
            return Some(MatchedAction {
                action: ActionResponse::Block { status: 403, body },
                policy_id,
                group_id: 0,
                set_id: 0,
                action_code: "block".to_string(),
                timeout_secs: Some(3600),
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags: vec!["denyCountry".to_string()],
                ip_list_id: 0,
                event_level: "error".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
    }

    let geo_country_iso = geo.country_iso.as_ref();
    let is_cn = geo_country_iso == "CN";

    if is_cn && (has_allow_provinces || has_deny_provinces) {
        let province_blocked = if has_allow_provinces {
            !region
                .allow_province_ids
                .iter()
                .any(|&id| geo_region_matches_id(&geo, id))
        } else {
            region
                .deny_province_ids
                .iter()
                .any(|&id| geo_region_matches_id(&geo, id))
        };
        if province_blocked {
            let html = if !region.deny_province_html.is_empty() {
                region.deny_province_html.clone()
            } else {
                deny_html_fallback.to_string()
            };
            let body = if html.is_empty() {
                "Access denied: your region is not allowed".to_string()
            } else {
                html
            };
            return Some(MatchedAction {
                action: ActionResponse::Block { status: 403, body },
                policy_id,
                group_id: 0,
                set_id: 0,
                action_code: "block".to_string(),
                timeout_secs: Some(3600),
                max_timeout_secs: None,
                life_seconds: None,
                max_fails: None,
                fail_block_timeout: None,
                fail_global: None,
                scope: None,
                block_c_class: false,
                use_local_firewall: false,
                next_group_id: None,
                next_set_id: None,
                allow_scope: None,
                tags: vec!["denyProvince".to_string()],
                ip_list_id: 0,
                event_level: "error".to_string(),
                block_options: None,
                page_options: None,
                captcha_options: None,
                js_cookie_options: None,
                chained_actions: vec![],
                observe_only: false,
            });
        }
    }

    None
}
