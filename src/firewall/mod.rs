pub mod lists;
pub mod matcher;
pub mod matcher_plus;
pub mod state;
pub mod verifier;

use crate::config_models::{
    HTTPFirewallPolicy, WAFBlockOptions, WAFCaptchaOptions, WAFJSCookieOptions, WAFPageOptions,
};
use pingora_proxy::Session;
use serde_json::Value;
use std::collections::HashMap;

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
    pub max_fails: i32,
    pub fail_block_timeout: i64,
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
}

pub struct OutboundContext<'a> {
    pub status: u16,
    pub headers: &'a HashMap<String, String>,
    pub body: &'a [u8],
    pub bytes_sent: usize,
}

pub fn evaluate_policy(
    policy: &HTTPFirewallPolicy,
    session: &Session,
    request_body: &[u8],
) -> Option<MatchedAction> {
    if !policy.is_on || policy.mode == "bypass" {
        return None;
    }

    if let Some(inbound) = &policy.inbound {
        if !inbound.is_on {
            return None;
        }

        let mut current_group_idx = 0;
        while current_group_idx < inbound.groups.len() {
            let group = &inbound.groups[current_group_idx];
            if !group.is_on {
                current_group_idx += 1;
                continue;
            }

            if let Some(result) = matcher_plus::match_group(group, session, request_body) {
                if let Some(set) = result.set {
                    if let Some(mut matched) = perform_actions(&set.actions) {
                        matched.policy_id = policy.id;
                        matched.group_id = group.id;
                        matched.set_id = set.id;
                        matched.block_options = policy.block_options.clone();
                        matched.page_options = policy.page_options.clone();
                        matched.captcha_options = policy.captcha_options.clone();
                        matched.js_cookie_options = policy.js_cookie_options.clone();
                        matched.use_local_firewall = policy.use_local_firewall;

                        // Handle Observe Mode: Change blocking actions to 'log'
                        if policy.mode == "observe"
                            && (matched.action_code == "block"
                                || matched.action_code == "captcha"
                                || matched.action_code == "jsCookie")
                        {
                            matched.action_code = "log".to_string();
                            // We still return it so it can be logged, but the proxy will continue
                        }

                        // Flow Control: ALLOW Scope
                        if matched.action_code == "allow" {
                            match matched.allow_scope.as_deref() {
                                Some("group") => { /* continue to next group */ }
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

                        // Flow Control: GO_SET
                        if let Some(next_sid) = matched.next_set_id {
                            // Find which group has this set
                            let mut found = false;
                            for (g_idx, g) in inbound.groups.iter().enumerate() {
                                if g.sets.iter().any(|s| s.id == next_sid) {
                                    current_group_idx = g_idx;
                                    // Note: we can't easily jump to a specific set within match_group
                                    // without refactoring it to take a start_set_id.
                                    // For now, we jump to the group, which is usually correct in GoEdge flow.
                                    found = true;
                                    break;
                                }
                            }
                            if found {
                                continue;
                            }
                        }

                        // Flow Control: Continue evaluation if action is just 'log' or 'none' (not implemented as separate case yet)
                        // but specifically for 'log' actions matched.
                        if matched.action_code == "log" {
                            current_group_idx += 1;
                            continue;
                        }

                        // Handle Observe Mode: Change blocking actions to 'log'
                        if policy.mode == "observe"
                            && (matched.action_code == "block"
                                || matched.action_code == "captcha"
                                || matched.action_code == "jsCookie")
                        {
                            matched.action_code = "log".to_string();
                        }

                        return Some(matched);
                    }
                }
                if result.matched {
                    let mut action = default_block_action(policy.id, group.id);
                    if policy.mode == "observe" {
                        action.action_code = "log".to_string();
                    }
                    return Some(action);
                }
            }
            current_group_idx += 1;
        }
    }
    None
}

pub fn evaluate_outbound_policy(
    policy: &HTTPFirewallPolicy,
    session: &Session,
    request_body: &[u8],
    response: &OutboundContext<'_>,
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
            if let Some(result) =
                matcher_plus::match_group_response(group, session, request_body, response)
            {
                if let Some(set) = result.set {
                    if let Some(mut matched) = perform_actions(&set.actions) {
                        matched.policy_id = policy.id;
                        matched.group_id = group.id;
                        matched.set_id = set.id;
                        matched.block_options = policy.block_options.clone();
                        matched.page_options = policy.page_options.clone();
                        matched.captcha_options = policy.captcha_options.clone();
                        matched.js_cookie_options = policy.js_cookie_options.clone();
                        matched.use_local_firewall = policy.use_local_firewall;

                        if policy.mode == "observe"
                            && (matched.action_code == "block"
                                || matched.action_code == "captcha"
                                || matched.action_code == "jsCookie")
                        {
                            matched.action_code = "log".to_string();
                        }

                        return Some(matched);
                    }
                }
                if result.matched {
                    let mut action = default_block_action(policy.id, group.id);
                    if policy.mode == "observe" {
                        action.action_code = "log".to_string();
                    }
                    return Some(action);
                }
            }
        }
    }
    None
}

fn default_block_action(policy_id: i64, group_id: i64) -> MatchedAction {
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
    }
}

fn perform_actions(actions: &[Value]) -> Option<MatchedAction> {
    for action in actions {
        let code = action
            .get("code")
            .or_else(|| action.get("action"))
            .and_then(Value::as_str)
            .map(|s| s.to_ascii_lowercase())?;
        let options = action.get("options");

        match code.as_str() {
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
                    max_fails: 0,
                    fail_block_timeout: 0,
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
                    event_level: "".to_string(),
                    block_options: None,
                    page_options: None,
                    captcha_options: None,
                    js_cookie_options: None,
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
                    max_fails: 0,
                    fail_block_timeout: 0,
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
                    event_level: "".to_string(),
                    block_options: None,
                    page_options: None,
                    captcha_options: None,
                    js_cookie_options: None,
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
                let scope = options.and_then(|v| v.get("scope")).map(|v| v.to_string());
                let ip_list_id = options
                    .and_then(|v| v.get("ipListId"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let event_level = options
                    .and_then(|v| v.get("eventLevel"))
                    .and_then(Value::as_str)
                    .unwrap_or("error")
                    .to_string();

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
                            max_fails: 0,
                            fail_block_timeout: 0,
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
                        });
                    }
                    "white" => {
                        return Some(MatchedAction {
                            action: ActionResponse::Allow,
                            policy_id: 0,
                            group_id: 0,
                            set_id: 0,
                            action_code: "record_ip_white".to_string(),
                            timeout_secs: timeout,
                            max_timeout_secs: None,
                            life_seconds: None,
                            max_fails: 0,
                            fail_block_timeout: 0,
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
                        });
                    }
                    _ => {}
                }
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
                    event_level: "".to_string(),
                    block_options: None,
                    page_options: None,
                    captcha_options: None,
                    js_cookie_options: None,
                });
            }
            "captcha" | "js_cookie" | "get_302" | "post_307" => {
                let life = options
                    .and_then(|v| v.get("lifeSeconds"))
                    .and_then(Value::as_i64)
                    .unwrap_or(600);
                let max_fails = options
                    .and_then(|v| v.get("maxFails"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0) as i32;
                let fail_timeout = options
                    .and_then(|v| v.get("failBlockTimeout"))
                    .and_then(Value::as_i64)
                    .unwrap_or(3600);
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
                    max_fails: 0,
                    fail_block_timeout: 0,
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
                    max_fails: 0,
                    fail_block_timeout: 0,
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
                });
            }
            _ => {}
        }
    }
    None
}
