use crate::config_models::{ParentNodeConfig, ReverseProxyConfig};
use futures_util::FutureExt;
use http;
use http::Extensions;
use pingora_load_balancing::{
    discovery::Static,
    health_check,
    selection::{Consistent, RoundRobin},
    Backend, Backends, LoadBalancer,
};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Custom metadata stored in Backend Extensions
#[derive(Clone, Debug)]
pub struct BackendExtension {
    pub use_tls: bool,
    pub host: String,    // Per-origin custom host (origin.requestHost)
    pub rp_host: String, // Reverse-proxy-level custom host (reverseProxy.requestHost)
    pub follow_host: bool,
    pub tls_verify: bool, // true = strict/auto, false = none
    pub client_cert: Option<crate::config_models::SSLCertConfig>,
}

/// Builds a Pingora LoadBalancer from a GoEdge ReverseProxyConfig.
/// Supports Tiered Origin: if level == 1 and parent_nodes are provided,
/// the parent nodes (L2) will be used as the upstreams.
pub fn build_lb(
    _server_id: i64,
    rp_cfg: &ReverseProxyConfig,
    _level: i32,
    _parent_nodes: &HashMap<i64, Vec<ParentNodeConfig>>,
    _tiered_origin_bypass: bool,
    allow_lan: bool,
) -> (Arc<LoadBalancer<RoundRobin>>, bool) {
    let mut endpoints = Vec::new();
    let mut has_health_check = false;

    // Build Origin Pool (Direct to primary/backup origins)
    for origin in &rp_cfg.primary_origins {
        if !origin.is_on {
            continue;
        }
        if let Some(addr) = &origin.addr {
            let target = addr.to_address();
            let rp_host = reverse_proxy_request_host(rp_cfg, addr);

            if !allow_lan && is_local_addr(&target) {
                warn!(
                    "LB Builder: Skipping LAN origin {} as it is not allowed in cluster settings.",
                    target
                );
                continue;
            }

            if let Ok(mut backend) = Backend::new(&target) {
                let mut ext = Extensions::new();

                let tls_verify = if let Some(v) = &origin.tls_verify {
                    match v {
                        serde_json::Value::Bool(b) => *b,
                        serde_json::Value::Object(obj) => {
                            obj.get("isOn").and_then(|v| v.as_bool()).unwrap_or(true)
                        }
                        serde_json::Value::Number(n) => n.as_i64().unwrap_or(1) > 0,
                        _ => true,
                    }
                } else {
                    true
                };

                ext.insert(BackendExtension {
                    use_tls: addr.is_https(),
                    host: origin.request_host.clone(),
                    rp_host,
                    follow_host: origin.follow_host,
                    tls_verify,
                    client_cert: origin.cert.clone(),
                });
                backend.ext = ext;
                backend.weight = origin.weight.max(1) as usize;
                endpoints.push(backend);
            }
        }
    }

    if endpoints.is_empty() {
        for origin in &rp_cfg.backup_origins {
            if !origin.is_on {
                continue;
            }
            if let Some(addr) = &origin.addr {
                let target = addr.to_address();
                let rp_host = reverse_proxy_request_host(rp_cfg, addr);

                if !allow_lan && is_local_addr(&target) {
                    warn!(
                        "LB Builder: Skipping LAN backup origin {} as it is not allowed.",
                        target
                    );
                    continue;
                }

                if let Ok(mut backend) = Backend::new(&target) {
                    let mut ext = Extensions::new();

                    let tls_verify = if let Some(v) = &origin.tls_verify {
                        match v {
                            serde_json::Value::Bool(b) => *b,
                            serde_json::Value::Object(obj) => {
                                obj.get("isOn").and_then(|v| v.as_bool()).unwrap_or(true)
                            }
                            serde_json::Value::Number(n) => n.as_i64().unwrap_or(1) > 0,
                            _ => true,
                        }
                    } else {
                        true
                    };

                    ext.insert(BackendExtension {
                        use_tls: addr.is_https(),
                        host: origin.request_host.clone(),
                        rp_host,
                        follow_host: origin.follow_host,
                        tls_verify,
                        client_cert: origin.cert.clone(),
                    });
                    backend.ext = ext;
                    endpoints.push(backend);
                }
            }
        }
    }

    let mut is_fallback = false;
    if endpoints.is_empty() {
        warn!("LB Builder: No upstreams found. Falling back to 127.0.0.1:80");
        if let Ok(b) = Backend::new("127.0.0.1:80") {
            endpoints.push(b);
        }
        is_fallback = true;
    }

    debug!("LB Builder: Creating LB with {} endpoints", endpoints.len());
    let mut set = BTreeSet::new();
    for e in endpoints {
        set.insert(e);
    }
    let backends = Backends::new(Static::new(set));
    let mut lb = LoadBalancer::from_backends(backends);
    lb.update()
        .now_or_never()
        .expect("static load balancer update should not block")
        .expect("static load balancer update should not fail");

    // Skip health check if we are in fallback mode
    if is_fallback {
        return (Arc::new(lb), false);
    }

    // Look for health check configuration in the first origin
    let mut detected_hc = None;
    for origin in &rp_cfg.primary_origins {
        if let Some(hc) = &origin.health_check {
            if hc.is_on {
                detected_hc = Some((origin, hc));
                break;
            } else {
                debug!(
                    "LB Builder: Health check for origin {} is present but OFF",
                    origin.id
                );
            }
        }
    }

    if let Some((origin, hc_cfg)) = detected_hc {
        has_health_check = true;
        let use_tcp = hc_cfg.protocol.as_deref() == Some("tcp");

        if use_tcp {
            debug!("LB Builder: Enabling TCP health check for origins.");
            let mut hc = health_check::TcpHealthCheck::new();
            if let Some(timeout) = &hc_cfg.timeout {
                hc.peer_template.options.connection_timeout =
                    Some(crate::utils::to_duration(timeout));
            }
            // TcpHealthCheck::new() returns a Box<TcpHealthCheck>, so we just need to cast it
            let check: Box<dyn health_check::HealthCheck + Send + Sync + 'static> = hc;
            lb.set_health_check(check);
        } else {
            debug!("LB Builder: Enabling HTTP health check for origins.");
            let host = origin.addr.as_ref().map(|a| a.host()).unwrap_or_default();
            let use_tls = origin.addr.as_ref().map(|a| a.is_https()).unwrap_or(false);

            let mut hc = health_check::HttpHealthCheck::new(&host, use_tls);
            if !hc_cfg.url.is_empty() {
                if let Ok(uri) = hc_cfg.url.parse::<http::Uri>() {
                    if let Some(path_and_query) = uri.path_and_query() {
                        let mut parts = hc.req.uri.clone().into_parts();
                        parts.path_and_query = Some(path_and_query.clone());
                        if let Ok(new_uri) = http::Uri::from_parts(parts) {
                            hc.req.uri = new_uri;
                        }
                    }
                }
            }

            // Apply connection timeout if configured
            if let Some(timeout) = &hc_cfg.timeout {
                hc.peer_template.options.connection_timeout =
                    Some(crate::utils::to_duration(timeout));
            }
            // HttpHealthCheck::new() returns HttpHealthCheck, so we need to Box it
            lb.set_health_check(Box::new(hc));
        }

        lb.health_check_frequency = Some(
            hc_cfg
                .interval
                .as_ref()
                .map(crate::utils::to_duration)
                .unwrap_or(Duration::from_secs(30)),
        );

        debug!(
            "Enabled health check for upstream pool. Frequency: {:?}",
            lb.health_check_frequency
        );
    }

    (Arc::new(lb), has_health_check)
}

pub fn build_parent_lb(
    cluster_id: i64,
    nodes: &[ParentNodeConfig],
    allow_lan: bool,
) -> Arc<LoadBalancer<Consistent>> {
    let mut endpoints = Vec::new();
    for node in nodes {
        let targets = node.to_addresses();
        for target in targets {
            if target.is_empty() {
                continue;
            }

            if !allow_lan && is_local_addr(&target) {
                warn!(
                    "LB Builder: Skipping LAN parent node address {} as it is not allowed.",
                    target
                );
                continue;
            }

            if let Ok(mut backend) = Backend::new(&target) {
                let mut ext = Extensions::new();
                ext.insert(BackendExtension {
                    use_tls: true, // L1 -> L2 always TLS by default in GoEdge
                    host: String::new(),
                    rp_host: String::new(),
                    follow_host: false,
                    tls_verify: false,
                    client_cert: None,
                });
                backend.ext = ext;
                backend.weight = node.weight.max(1) as usize;
                endpoints.push(backend);
            }
        }
    }

    if endpoints.is_empty() {
        if let Ok(b) = Backend::new("127.0.0.1:80") {
            endpoints.push(b);
        }
    }

    debug!(
        "LB Builder: Creating Parent LB for cluster {} with {} endpoints",
        cluster_id,
        endpoints.len()
    );
    let mut set = BTreeSet::new();
    for e in endpoints {
        set.insert(e);
    }
    let backends = Backends::new(Static::new(set));
    let lb = LoadBalancer::from_backends(backends);
    lb.update()
        .now_or_never()
        .expect("static parent load balancer update should not block")
        .expect("static parent load balancer update should not fail");
    Arc::new(lb)
}

fn reverse_proxy_request_host(
    rp_cfg: &ReverseProxyConfig,
    addr: &crate::config_models::FlexibleAddr,
) -> String {
    match rp_cfg.request_host_type {
        // GoEdge requestHostType=1 means send the origin host as upstream Host/SNI.
        1 => origin_addr_host(addr),
        // GoEdge requestHostType=2 means use the reverse-proxy-level custom Host.
        2 if !rp_cfg.request_host.is_empty() => rp_cfg.request_host.clone(),
        _ => String::new(),
    }
}

fn origin_addr_host(addr: &crate::config_models::FlexibleAddr) -> String {
    let host = match addr {
        crate::config_models::FlexibleAddr::Object(obj) => obj.host.clone().unwrap_or_default(),
        crate::config_models::FlexibleAddr::String(s) => s.clone(),
    };
    host.strip_prefix("http://")
        .or_else(|| host.strip_prefix("https://"))
        .or_else(|| host.strip_prefix("tcp://"))
        .or_else(|| host.strip_prefix("tls://"))
        .unwrap_or(&host)
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

fn is_local_addr(addr: &str) -> bool {
    let host = addr.split(':').next().unwrap_or(addr);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => {
                let octets = v6.octets();
                (octets[0] & 0xfe == 0xfc) || v6.is_loopback()
            }
        }
    } else {
        // If it's a hostname like "localhost"
        host.eq_ignore_ascii_case("localhost")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{FlexibleAddr, NetworkAddressConfig};

    fn rp_cfg(request_host_type: i8, request_host: &str) -> ReverseProxyConfig {
        ReverseProxyConfig {
            is_on: true,
            primary_origins: vec![],
            backup_origins: vec![],
            request_host: request_host.to_string(),
            request_host_type,
        }
    }

    #[test]
    fn request_host_type_origin_uses_object_origin_host() {
        let addr = FlexibleAddr::Object(NetworkAddressConfig {
            protocol: Some("https".to_string()),
            host: Some("origin.example.com".to_string()),
            port_range: Some("443".to_string()),
        });

        assert_eq!(
            reverse_proxy_request_host(&rp_cfg(1, ""), &addr),
            "origin.example.com"
        );
    }

    #[test]
    fn request_host_type_origin_strips_scheme_and_port_from_string_origin() {
        let addr = FlexibleAddr::String("https://origin.example.com:443".to_string());

        assert_eq!(
            reverse_proxy_request_host(&rp_cfg(1, ""), &addr),
            "origin.example.com"
        );
    }

    #[test]
    fn request_host_type_custom_uses_configured_request_host() {
        let addr = FlexibleAddr::String("origin.example.com:443".to_string());

        assert_eq!(
            reverse_proxy_request_host(&rp_cfg(2, "custom.example.com"), &addr),
            "custom.example.com"
        );
    }

    #[test]
    fn request_host_type_proxy_server_leaves_host_unset() {
        let addr = FlexibleAddr::String("origin.example.com:443".to_string());

        assert_eq!(reverse_proxy_request_host(&rp_cfg(0, ""), &addr), "");
    }
}
