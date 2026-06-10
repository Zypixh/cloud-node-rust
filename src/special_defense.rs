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

pub(crate) fn cluster_block_scope_id(cluster_id: i64) -> i64 {
    if cluster_id <= 0 { 0 } else { -cluster_id }
}

pub(crate) fn global_tls_exhaustion_config(
    config_store: &ConfigStore,
    cluster_id: i64,
) -> Option<SpecialDefenseConfig> {
    config_store.get_tls_exhaustion_config_for_cluster_sync(cluster_id)
}

pub(crate) fn record_special_defense_hit(
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    cluster_id: i64,
    defense: &str,
    ip: IpAddr,
    config: SpecialDefenseConfig,
) {
    let scope_server_id = cluster_block_scope_id(cluster_id);
    let count = waf_state.increase_counter(
        format!("{}:cluster:{}:{}", defense, cluster_id, ip),
        config.period_secs,
    );
    if count > u64::from(config.threshold) {
        waf_state.block_ip(
            ip,
            scope_server_id,
            config.block_secs,
            Some("cluster"),
            false,
            config.use_local_firewall,
        );
        crate::rpc::ip_report::report_item(IpReportMessage {
            ip_list_id: 0,
            value: ip.to_string(),
            ip_from: String::new(),
            ip_to: String::new(),
            expired_at: crate::utils::time::now_timestamp() + config.block_secs.max(1),
            reason: format!("{} special defense block cluster={}", defense, cluster_id),
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
            source_category: format!("special_defense:cluster:{}", cluster_id),
        });
        warn!(
            "{} blocked {} in cluster {} for {}s after {} hits in {}s by policy {}",
            defense,
            ip,
            cluster_id,
            config.block_secs,
            count,
            config.period_secs,
            config.policy_name
        );
    }
}

pub(crate) fn record_tls_handshake_failure(
    config_store: &ConfigStore,
    waf_state: &Arc<WafStateManager>,
    node_id: i64,
    ip: IpAddr,
) {
    let cluster_id = config_store.get_node_cluster_id_sync();
    let Some(config) = global_tls_exhaustion_config(config_store, cluster_id) else {
        return;
    };
    record_special_defense_hit(
        waf_state,
        node_id,
        cluster_id,
        "TLS_EXHAUSTION_ATTACK",
        ip,
        config,
    );
}
