use std::net::ToSocketAddrs;

pub fn current_pod_ip() -> Option<String> {
    crate::runtime_mode::RuntimeConfig::current()
        .and_then(|config| std::env::var(&config.cluster.pod_ip_env).ok())
        .filter(|value| !value.trim().is_empty())
}

pub fn internal_api_port() -> Option<u16> {
    crate::runtime_mode::RuntimeConfig::current().and_then(|config| {
        config
            .cluster
            .internal_api
            .bind
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
    })
}

pub fn discover_peer_urls() -> Vec<String> {
    let Some(config) = crate::runtime_mode::RuntimeConfig::current() else {
        return Vec::new();
    };
    if !config.is_rke2() {
        return Vec::new();
    }

    let Some(port) = internal_api_port() else {
        return Vec::new();
    };
    let current_ip = current_pod_ip();
    let dns_name = format!(
        "{}.{}.svc.cluster.local:{}",
        config.cluster.service_name, config.cluster.namespace, port
    );

    let mut peers = Vec::new();
    if let Ok(addrs) = dns_name.to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip().to_string();
            if current_ip.as_deref() == Some(ip.as_str()) {
                continue;
            }
            let host = if ip.contains(':') {
                format!("[{}]", ip)
            } else {
                ip
            };
            peers.push(format!("http://{}:{}", host, port));
        }
    }
    peers.sort();
    peers.dedup();
    peers
}
