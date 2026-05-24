use crate::config::ConfigStore;
use crate::firewall::state::WafStateManager;
use crate::rpc::ip_report::{IpReportKind, IpReportMessage};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::warn;

pub(crate) struct SpecialDefenseConfig {
    pub threshold: u32,
    pub period_secs: i64,
    pub block_secs: i64,
    pub use_local_firewall: bool,
    pub policy_name: String,
}

pub(crate) fn global_tls_exhaustion_config(
    config_store: &ConfigStore,
) -> Option<SpecialDefenseConfig> {
    let policies = config_store.get_firewall_policies_sync();
    policies.iter().find_map(|policy| {
        if !policy.is_on {
            return None;
        }
        let config = policy.tls_exhaustion_attack.as_ref()?;
        if !config.is_on || config.max_handshake_fails == 0 {
            return None;
        }
        Some(SpecialDefenseConfig {
            threshold: config.max_handshake_fails,
            period_secs: i64::from(config.period).max(1),
            block_secs: i64::from(config.block_seconds).max(1),
            use_local_firewall: policy.use_local_firewall,
            policy_name: policy.name.clone(),
        })
    })
}

pub(crate) fn record_special_defense_hit(
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    defense: &str,
    ip: IpAddr,
    config: SpecialDefenseConfig,
) {
    let count = waf_state.increase_counter(format!("{}:{}", defense, ip), config.period_secs);
    if count > u64::from(config.threshold) {
        waf_state.block_ip(
            ip,
            0,
            config.block_secs,
            Some("global"),
            false,
            config.use_local_firewall,
        );
        crate::rpc::ip_report::report_item(IpReportMessage {
            ip_list_id: 0,
            value: ip.to_string(),
            ip_from: String::new(),
            ip_to: String::new(),
            expired_at: crate::utils::time::now_timestamp() + config.block_secs.max(1),
            reason: format!("{} special defense block", defense),
            r#type: String::new(),
            list_kind: IpReportKind::Black,
            event_level: "error".to_string(),
            node_id,
            server_id: 0,
            source_node_id: node_id,
            source_server_id: 0,
            source_http_firewall_policy_id: 0,
            source_http_firewall_rule_group_id: 0,
            source_http_firewall_rule_set_id: 0,
            source_url: String::new(),
            source_user_agent: String::new(),
            source_category: "special_defense".to_string(),
        });
        warn!(
            "{} blocked {} for {}s after {} hits in {}s by policy {}",
            defense, ip, config.block_secs, count, config.period_secs, config.policy_name
        );
    }
}

pub(crate) fn record_tls_handshake_failure(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
) {
    let Some(config) = global_tls_exhaustion_config(config_store) else {
        return;
    };
    record_special_defense_hit(waf_state, node_id, "TLS_EXHAUSTION_ATTACK", ip, config);
}
