#[cfg(target_os = "linux")]
use anyhow::Context;
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::path::Path;

use crate::config_models::{NetworkAddressConfig, ServerConfig};
#[cfg(target_os = "linux")]
use crate::runtime_mode::XdpRuntimeMode;
use crate::runtime_mode::{
    RuntimeConfig, XdpAttachMode, XdpConfig, XdpFallbackMode, XdpInterfaceConfig, XdpProxyConfig,
    XdpProxyPortConfig, XdpProxyProtocol,
};

pub fn derive_xdp_config(runtime: &RuntimeConfig) -> anyhow::Result<XdpConfig> {
    if runtime.xdp.proxy.ports.is_empty() {
        anyhow::bail!(
            "cannot derive XDP proxy ports from RuntimeConfig alone; fetch live server config or configure xdp.proxy.ports"
        );
    }
    derive_xdp_config_with_ports(
        runtime,
        dedupe_proxy_ports(runtime.xdp.proxy.ports.clone())?,
    )
}

pub async fn derive_xdp_config_from_live_node(
    runtime: &RuntimeConfig,
) -> anyhow::Result<XdpConfig> {
    #[cfg(target_os = "linux")]
    {
        let payload = crate::kernel_syn_defense::fetch_live_node_config_payload()
            .await
            .context("failed to fetch live node config for XDP auto ports")?;
        derive_xdp_config_for_servers(runtime, &payload.servers)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = runtime;
        anyhow::bail!("XDP automatic takeover is supported on Linux only")
    }
}

pub fn derive_xdp_config_for_servers(
    runtime: &RuntimeConfig,
    servers: &[ServerConfig],
) -> anyhow::Result<XdpConfig> {
    let ports = xdp_proxy_ports_from_servers(servers);
    if ports.is_empty() {
        anyhow::bail!("live node config has no enabled business listen ports for XDP proxy");
    }
    derive_xdp_config_with_ports(runtime, ports)
}

pub fn xdp_proxy_ports_from_servers(servers: &[ServerConfig]) -> Vec<XdpProxyPortConfig> {
    let mut ports = BTreeMap::new();
    for server in servers.iter().filter(|server| server.is_on) {
        if let Some(http) = &server.http
            && http.is_on
        {
            add_listen_ports(&mut ports, XdpProxyProtocol::Http, &http.listen);
        }
        if let Some(https) = &server.https
            && https.is_on
        {
            add_listen_ports(&mut ports, XdpProxyProtocol::Https, &https.listen);
            if https.http3_enabled() {
                add_listen_ports(&mut ports, XdpProxyProtocol::H3, &https.listen);
            }
        }
        if let Some(tcp) = &server.tcp
            && tcp.is_on
        {
            add_listen_ports(&mut ports, XdpProxyProtocol::Tcp, &tcp.listen);
            if let Some(tls) = &tcp.tls
                && tls.is_on
            {
                add_listen_ports(&mut ports, XdpProxyProtocol::Tcp, &tls.listen);
            }
        }
        if let Some(udp) = &server.udp
            && udp.is_on
        {
            add_listen_ports(&mut ports, XdpProxyProtocol::Udp, &udp.listen);
        }
    }
    ports.into_values().collect()
}

fn derive_xdp_config_with_ports(
    _runtime: &RuntimeConfig,
    ports: Vec<XdpProxyPortConfig>,
) -> anyhow::Result<XdpConfig> {
    let interfaces = detect_xdp_interfaces()?;
    if interfaces.is_empty() {
        anyhow::bail!("no Linux network interfaces are eligible for XDP automatic takeover");
    }
    Ok(XdpConfig {
        enabled: true,
        attach_mode: XdpAttachMode::Auto,
        fallback: XdpFallbackMode::FailStart,
        interfaces,
        proxy: XdpProxyConfig {
            protocols: default_xdp_proxy_protocols(),
            ports,
        },
    })
}

fn add_listen_ports(
    ports: &mut BTreeMap<(u8, u16), XdpProxyPortConfig>,
    protocol: XdpProxyProtocol,
    listen: &[NetworkAddressConfig],
) {
    let protocol_order = xdp_proxy_protocol_order(&protocol);
    for addr in listen {
        if let Some(range) = addr.port_range.as_deref() {
            for port in crate::config_models::ports_in_range(range) {
                if port != 0 {
                    ports
                        .entry((protocol_order, port))
                        .or_insert_with(|| XdpProxyPortConfig {
                            protocol: protocol.clone(),
                            port,
                        });
                }
            }
        }
    }
}

fn dedupe_proxy_ports(ports: Vec<XdpProxyPortConfig>) -> anyhow::Result<Vec<XdpProxyPortConfig>> {
    let mut deduped = BTreeMap::new();
    for port in ports {
        if port.port == 0 {
            anyhow::bail!("xdp.proxy.ports entries require a non-zero port");
        }
        deduped
            .entry((xdp_proxy_protocol_order(&port.protocol), port.port))
            .or_insert(port);
    }
    Ok(deduped.into_values().collect())
}

fn default_xdp_proxy_protocols() -> Vec<XdpProxyProtocol> {
    vec![
        XdpProxyProtocol::Http,
        XdpProxyProtocol::Https,
        XdpProxyProtocol::Tcp,
        XdpProxyProtocol::Udp,
        XdpProxyProtocol::H3,
    ]
}

fn xdp_proxy_protocol_order(protocol: &XdpProxyProtocol) -> u8 {
    match protocol {
        XdpProxyProtocol::Http => 0,
        XdpProxyProtocol::Https => 1,
        XdpProxyProtocol::Tcp => 2,
        XdpProxyProtocol::Udp => 3,
        XdpProxyProtocol::H3 => 4,
    }
}

#[cfg(target_os = "linux")]
fn detect_xdp_interfaces() -> anyhow::Result<Vec<XdpInterfaceConfig>> {
    let mut candidates = BTreeSet::new();
    candidates.extend(default_route_interfaces()?);
    for iface in active_interfaces()? {
        candidates.insert(iface);
    }

    let mut interfaces = Vec::new();
    for name in candidates {
        if interfaces.len() >= cloud_node_xdp_common::XDP_MAX_INTERFACES {
            break;
        }
        if !eligible_interface(&name) {
            continue;
        }
        interfaces.push(XdpInterfaceConfig {
            name: name.clone(),
            queues: rx_queues_for_interface(&name),
            mode: XdpRuntimeMode::Proxy,
            local_ips: Vec::new(),
            frame_size: cloud_node_xdp_common::XDP_DEFAULT_FRAME_SIZE,
        });
    }

    if interfaces.is_empty() {
        anyhow::bail!("no eligible Linux interface detected from /proc routes and /sys/class/net");
    }
    Ok(interfaces)
}

#[cfg(not(target_os = "linux"))]
fn detect_xdp_interfaces() -> anyhow::Result<Vec<XdpInterfaceConfig>> {
    anyhow::bail!("XDP automatic takeover is supported on Linux only")
}

#[cfg(target_os = "linux")]
fn default_route_interfaces() -> anyhow::Result<BTreeSet<String>> {
    let mut interfaces = BTreeSet::new();
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() > 2 && fields[1] == "00000000" {
                interfaces.insert(fields[0].to_string());
            }
        }
    }
    if let Ok(content) = std::fs::read_to_string("/proc/net/ipv6_route") {
        for line in content.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() >= 10
                && fields[0] == "00000000000000000000000000000000"
                && fields[1] == "00"
            {
                interfaces.insert(fields[9].to_string());
            }
        }
    }
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn active_interfaces() -> anyhow::Result<BTreeSet<String>> {
    let mut interfaces = BTreeSet::new();
    for entry in std::fs::read_dir("/sys/class/net")
        .context("failed to enumerate /sys/class/net for XDP interfaces")?
    {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        interfaces.insert(name);
    }
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn eligible_interface(name: &str) -> bool {
    if name == "lo" || name.trim().is_empty() || obviously_virtual_interface(name) {
        return false;
    }
    let sys_path = Path::new("/sys/class/net").join(name);
    let Ok(target) = std::fs::read_link(&sys_path) else {
        return false;
    };
    if target.to_string_lossy().contains("/virtual/net/") {
        return false;
    }
    let operstate = std::fs::read_to_string(sys_path.join("operstate")).unwrap_or_default();
    !matches!(operstate.trim(), "down" | "lowerlayerdown" | "notpresent")
}

#[cfg(target_os = "linux")]
fn obviously_virtual_interface(name: &str) -> bool {
    [
        "br-",
        "cni",
        "docker",
        "dummy",
        "flannel",
        "ifb",
        "tap",
        "tun",
        "veth",
        "virbr",
        "wg",
        "zt",
        "tailscale",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

#[cfg(target_os = "linux")]
fn rx_queues_for_interface(name: &str) -> Vec<u32> {
    let queue_dir = Path::new("/sys/class/net").join(name).join("queues");
    let Ok(entries) = std::fs::read_dir(queue_dir) else {
        return vec![0];
    };
    let mut queues = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter_map(|name| name.strip_prefix("rx-")?.parse::<u32>().ok())
        .collect::<Vec<_>>();
    queues.sort_unstable();
    queues.dedup();
    if queues.is_empty() { vec![0] } else { queues }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{HTTPConfig, HTTPSConfig, TCPConfig, UDPConfig};

    fn listen(range: &str) -> NetworkAddressConfig {
        NetworkAddressConfig {
            port_range: Some(range.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn xdp_proxy_ports_cover_enabled_business_listeners() {
        let server = ServerConfig {
            is_on: true,
            http: Some(HTTPConfig {
                is_on: true,
                listen: vec![listen("80")],
            }),
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![listen("443")],
                ssl_policy: None,
                supports_http3: Some(true),
            }),
            tcp: Some(TCPConfig {
                is_on: true,
                listen: vec![listen("9000-9001")],
                tls: Some(HTTPSConfig {
                    is_on: true,
                    listen: vec![listen("9443")],
                    ssl_policy: None,
                    supports_http3: None,
                }),
            }),
            udp: Some(UDPConfig {
                is_on: true,
                listen: vec![listen("53")],
            }),
            ..Default::default()
        };

        let ports = xdp_proxy_ports_from_servers(&[server])
            .into_iter()
            .map(|port| (port.protocol.as_str(), port.port))
            .collect::<Vec<_>>();

        assert_eq!(
            ports,
            vec![
                ("http", 80),
                ("https", 443),
                ("tcp", 9000),
                ("tcp", 9001),
                ("tcp", 9443),
                ("udp", 53),
                ("h3", 443),
            ]
        );
    }
}
