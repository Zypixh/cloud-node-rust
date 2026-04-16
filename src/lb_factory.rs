use crate::config_models::{ParentNodeConfig, ReverseProxyConfig};
use pingora_load_balancing::{LoadBalancer, health_check, selection::RoundRobin};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Builds a Pingora LoadBalancer from a GoEdge ReverseProxyConfig.
/// Supports Tiered Origin: if level == 1 and parent_nodes are provided,
/// the parent nodes (L2) will be used as the upstreams.
pub fn build_lb(
    rp_cfg: &ReverseProxyConfig,
    level: i32,
    parent_nodes: &HashMap<i64, Vec<ParentNodeConfig>>,
    tiered_origin_bypass: bool,
) -> Arc<LoadBalancer<RoundRobin>> {
    let mut endpoints = Vec::new();
    let mut backup_endpoints = Vec::new();

    // 1. Tiered Origin Logic: Only if L1 AND NOT bypassed
    if level == 1 && !parent_nodes.is_empty() && !tiered_origin_bypass {
        info!("Node is L1, building tiered origin pool from Parent Nodes (L2).");
        for nodes in parent_nodes.values() {
            for node in nodes {
                let target = node.addr.to_address();
                if node.is_backup {
                    backup_endpoints.push(target);
                } else {
                    let w = node.weight.max(1);
                    for _ in 0..w {
                        endpoints.push(target.clone());
                    }
                }
            }
        }
    }

    if tiered_origin_bypass {
        warn!("Tiered origin bypass is ACTIVE. Going direct to origin.");
    }

    // 2. If no L2 primary nodes, check L2 backup nodes
    if endpoints.is_empty() && !backup_endpoints.is_empty() {
        info!("No primary L2 nodes found, using PB backup L2 nodes.");
        endpoints = backup_endpoints;
    }

    // 3. Fallback to primary origins (the real Origin) if L1/L2 mechanism is not applicable
    if endpoints.is_empty() {
        for origin in &rp_cfg.primary_origins {
            if !origin.is_on {
                continue;
            }
            if let Some(addr) = &origin.addr {
                endpoints.push(addr.to_address());
            }
        }
    }

    // 4. Fallback to backup origins
    if endpoints.is_empty() {
        info!("No primary or parent origins found, checking backup origins.");
        for origin in &rp_cfg.backup_origins {
            if !origin.is_on {
                continue;
            }
            if let Some(addr) = &origin.addr {
                endpoints.push(addr.to_address());
            }
        }
    }

    let mut lb = LoadBalancer::try_from_iter(endpoints).expect("Failed to create LoadBalancer");

    // Look for health check configuration in the first origin
    if let Some(origin) = rp_cfg
        .primary_origins
        .iter()
        .find(|o| o.health_check.is_some())
        && let Some(hc_cfg) = &origin.health_check
            && hc_cfg.is_on {
                let host = origin
                    .addr
                    .as_ref()
                    .map(|a| a.host.clone().unwrap_or_default())
                    .unwrap_or_default();
                let use_tls = origin
                    .addr
                    .as_ref()
                    .map(|a| a.protocol.as_ref().map(|p| p == "https").unwrap_or(false))
                    .unwrap_or(false);

                let mut hc = health_check::HttpHealthCheck::new(&host, use_tls);

                // Apply connection timeout if configured
                if let Some(timeout) = &hc_cfg.timeout {
                    hc.peer_template.options.connection_timeout =
                        Some(crate::utils::to_duration(timeout));
                }

                lb.set_health_check(Box::new(hc));
                lb.health_check_frequency = Some(
                    hc_cfg
                        .interval
                        .as_ref()
                        .map(crate::utils::to_duration)
                        .unwrap_or(Duration::from_secs(30)),
                );

                info!(
                    "Enabled HTTP health check for upstream pool. Frequency: {:?}",
                    lb.health_check_frequency
                );
            }

    Arc::new(lb)
}
