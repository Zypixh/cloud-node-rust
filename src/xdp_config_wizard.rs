use anyhow::{Context, Result};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;

use crate::i18n::{Language, t};
use crate::runtime_mode::{
    RuntimeConfig, XdpAttachMode, XdpConfig, XdpFallbackMode, XdpInterfaceConfig, XdpProxyConfig,
    XdpProxyPortConfig, XdpProxyProtocol, XdpRuntimeMode,
};

#[derive(Debug, Clone)]
pub struct XdpConfigWizard {
    pub xdp: XdpConfig,
}

impl XdpConfigWizard {
    pub fn run_interactive() -> Result<Option<Self>> {
        prompt_menu_language()?;
        println!("\n{}\n", t("xdp.menu.title"));

        let enabled = prompt_yes_no(t("xdp.menu.enable"), true)?;
        let xdp = if enabled {
            prompt_enabled_xdp_config()?
        } else {
            println!("{}", t("xdp.menu.disabled_saved"));
            XdpConfig {
                enabled: false,
                ..Default::default()
            }
        };

        let wizard = XdpConfigWizard { xdp };
        wizard.validate()?;

        if prompt_yes_no(t("xdp.menu.save"), true)? {
            wizard.save_to_file("configs/runtime.yaml")?;
            println!("\n{} {}", t("common.success"), t("xdp.menu.saved"));
            Ok(Some(wizard))
        } else {
            println!("{}", t("xdp.menu.cancelled"));
            Ok(None)
        }
    }

    fn validate(&self) -> Result<()> {
        RuntimeConfig {
            xdp: self.xdp.clone(),
            ..Default::default()
        }
        .validate()
    }

    fn save_to_file(&self, path: &str) -> Result<()> {
        save_xdp_config(Path::new(path), &self.xdp)
    }
}

fn prompt_menu_language() -> Result<()> {
    println!("\n选择语言 / Select language");
    println!("  1. 中文");
    println!("  2. English");

    let default = match Language::current() {
        Language::Chinese => "1",
        Language::English => "2",
    };

    loop {
        let choice = prompt_input("请选择 / Select [1-2]", default)?;
        match choice.trim() {
            "1" | "zh" | "ZH" | "cn" | "CN" | "中文" => {
                Language::set_current(Language::Chinese);
                return Ok(());
            }
            "2" | "en" | "EN" | "English" | "english" => {
                Language::set_current(Language::English);
                return Ok(());
            }
            _ => println!("输入无效，请重试 / Invalid input, please try again"),
        }
    }
}

fn prompt_enabled_xdp_config() -> Result<XdpConfig> {
    let attach_mode = prompt_attach_mode()?;
    let fallback = prompt_fallback_mode()?;
    let mut interfaces = Vec::new();
    let mut proxy_ports = Vec::new();

    loop {
        let interface = prompt_interface()?;
        let proxy_mode = interface.mode == XdpRuntimeMode::Proxy;
        interfaces.push(interface);

        if proxy_mode && prompt_yes_no(t("xdp.menu.proxy_ports"), true)? {
            proxy_ports.extend(prompt_proxy_ports()?);
        }

        if !prompt_yes_no(t("xdp.menu.add_interface"), false)? {
            break;
        }
    }

    Ok(XdpConfig {
        enabled: true,
        attach_mode,
        fallback,
        interfaces,
        proxy: XdpProxyConfig {
            protocols: default_proxy_protocols(),
            ports: proxy_ports,
        },
    })
}

fn prompt_attach_mode() -> Result<XdpAttachMode> {
    println!("\n{}", t("xdp.menu.attach_mode"));
    println!("  1. {}", t("xdp.menu.attach.auto"));
    println!("  2. {}", t("xdp.menu.attach.drv"));
    println!("  3. {}", t("xdp.menu.attach.skb"));

    loop {
        let choice = prompt_input(&format!("{} [1-3]", t("common.select")), "1")?;
        match choice.trim() {
            "1" | "auto" => return Ok(XdpAttachMode::Auto),
            "2" | "drv" | "driver" => return Ok(XdpAttachMode::Drv),
            "3" | "skb" | "generic" => return Ok(XdpAttachMode::Skb),
            _ => println!("{}", t("common.invalid_input")),
        }
    }
}

fn prompt_fallback_mode() -> Result<XdpFallbackMode> {
    println!("\n{}", t("xdp.menu.fallback"));
    println!("  1. {}", t("xdp.menu.fallback.pass"));
    println!("  2. {}", t("xdp.menu.fallback.fail_start"));

    loop {
        let choice = prompt_input(&format!("{} [1-2]", t("common.select")), "1")?;
        match choice.trim() {
            "1" | "pass" => return Ok(XdpFallbackMode::Pass),
            "2" | "fail-start" | "fail_start" => return Ok(XdpFallbackMode::FailStart),
            _ => println!("{}", t("common.invalid_input")),
        }
    }
}

fn prompt_interface() -> Result<XdpInterfaceConfig> {
    let name = prompt_input(t("xdp.menu.interface"), "eth0")?;
    let mode = prompt_interface_mode()?;
    let queues = prompt_queues()?;
    let local_ips = prompt_local_ips()?;
    let frame_size = prompt_frame_size()?;

    Ok(XdpInterfaceConfig {
        name,
        queues,
        mode,
        local_ips,
        frame_size,
    })
}

fn prompt_interface_mode() -> Result<XdpRuntimeMode> {
    println!("\n{}", t("xdp.menu.mode"));
    println!("  1. observe - {}", t("xdp.menu.mode.observe"));
    println!("  2. protect - {}", t("xdp.menu.mode.protect"));
    println!("  3. proxy   - {}", t("xdp.menu.mode.proxy"));

    loop {
        let choice = prompt_input(&format!("{} [1-3]", t("common.select")), "2")?;
        match choice.trim() {
            "1" | "observe" => return Ok(XdpRuntimeMode::Observe),
            "2" | "protect" => return Ok(XdpRuntimeMode::Protect),
            "3" | "proxy" => return Ok(XdpRuntimeMode::Proxy),
            _ => println!("{}", t("common.invalid_input")),
        }
    }
}

fn prompt_queues() -> Result<Vec<u32>> {
    loop {
        let queues = parse_queues(&prompt_input(t("xdp.menu.queues"), "0")?);
        if queues.is_empty() {
            println!("{}", t("xdp.menu.invalid_queue"));
            continue;
        }
        return Ok(queues);
    }
}

fn prompt_local_ips() -> Result<Vec<IpAddr>> {
    let input = prompt_input(t("xdp.menu.local_ips"), "")?;
    parse_ip_list(&input)
}

fn prompt_frame_size() -> Result<u32> {
    loop {
        let input = prompt_input(t("xdp.menu.frame_size"), "2048")?;
        match input.trim().parse::<u32>() {
            Ok(size) if (1024..=4096).contains(&size) && size % 512 == 0 => return Ok(size),
            _ => println!("{}", t("common.invalid_input")),
        }
    }
}

fn prompt_proxy_ports() -> Result<Vec<XdpProxyPortConfig>> {
    let mut proxy_ports = Vec::new();
    loop {
        proxy_ports.push(prompt_proxy_port()?);
        if !prompt_yes_no(t("xdp.menu.add_more"), false)? {
            break;
        }
    }
    Ok(proxy_ports)
}

fn prompt_proxy_port() -> Result<XdpProxyPortConfig> {
    println!("\n{}", t("xdp.menu.protocol"));
    println!("  1. http  - {}", t("xdp.menu.protocol.http"));
    println!("  2. https - {}", t("xdp.menu.protocol.https"));
    println!("  3. tcp   - {}", t("xdp.menu.protocol.tcp"));
    println!("  4. udp   - {}", t("xdp.menu.protocol.udp"));
    println!("  5. h3    - {}", t("xdp.menu.protocol.h3"));

    let protocol = loop {
        let choice = prompt_input(&format!("{} [1-5]", t("common.select")), "3")?;
        match choice.trim() {
            "1" | "http" => break XdpProxyProtocol::Http,
            "2" | "https" => break XdpProxyProtocol::Https,
            "3" | "tcp" => break XdpProxyProtocol::Tcp,
            "4" | "udp" => break XdpProxyProtocol::Udp,
            "5" | "h3" | "http3" | "http/3" => break XdpProxyProtocol::H3,
            _ => println!("{}", t("common.invalid_input")),
        }
    };

    let port = loop {
        let port = prompt_input(t("xdp.menu.port"), default_port_for(&protocol))?;
        match port.trim().parse::<u16>() {
            Ok(0) | Err(_) => println!("{}", t("xdp.menu.invalid_port")),
            Ok(port) => break port,
        }
    };

    Ok(XdpProxyPortConfig { protocol, port })
}

fn default_proxy_protocols() -> Vec<XdpProxyProtocol> {
    vec![
        XdpProxyProtocol::Http,
        XdpProxyProtocol::Https,
        XdpProxyProtocol::Tcp,
        XdpProxyProtocol::Udp,
        XdpProxyProtocol::H3,
    ]
}

fn default_port_for(protocol: &XdpProxyProtocol) -> &'static str {
    match protocol {
        XdpProxyProtocol::Http => "80",
        XdpProxyProtocol::Https => "443",
        XdpProxyProtocol::Tcp => "80",
        XdpProxyProtocol::Udp => "53",
        XdpProxyProtocol::H3 => "443",
    }
}

fn parse_queues(input: &str) -> Vec<u32> {
    input
        .split(',')
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .collect()
}

fn parse_ip_list(input: &str) -> Result<Vec<IpAddr>> {
    input
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.parse::<IpAddr>()
                .with_context(|| format!("{}: {item}", t("xdp.menu.invalid_ip")))
        })
        .collect()
}

fn prompt_input(prompt: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", prompt, default);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();

    Ok(if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    })
}

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool> {
    let default_str = if default {
        format!("{}/{}", t("common.yes").to_uppercase(), t("common.no"))
    } else {
        format!("{}/{}", t("common.yes"), t("common.no").to_uppercase())
    };

    print!("{} [{}]: ", prompt, default_str);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_ascii_lowercase();

    Ok(match trimmed.as_str() {
        "" => default,
        "y" | "yes" | "true" | "1" | "是" | "好" | "确认" | "启用" | "开启" => true,
        "n" | "no" | "false" | "0" | "否" | "不用" | "取消" | "禁用" | "关闭" => false,
        _ => default,
    })
}

fn save_xdp_config(path: &Path, xdp: &XdpConfig) -> Result<()> {
    use std::fs;

    let mut root = if path.exists() {
        let existing = fs::read_to_string(path)?;
        if existing.trim().is_empty() {
            serde_yaml::Mapping::new()
        } else {
            match serde_yaml::from_str::<serde_yaml::Value>(&existing)? {
                serde_yaml::Value::Mapping(mapping) => mapping,
                _ => anyhow::bail!("{} is not a YAML mapping", path.display()),
            }
        }
    } else {
        serde_yaml::Mapping::new()
    };

    root.insert(
        serde_yaml::Value::String("xdp".to_string()),
        serde_yaml::to_value(xdp)?,
    );

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(
        path,
        serde_yaml::to_string(&serde_yaml::Value::Mapping(root))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_queue_list() {
        assert_eq!(parse_queues("0, 2, 4"), vec![0, 2, 4]);
        assert_eq!(parse_queues("bad,1"), vec![1]);
    }

    #[test]
    fn serializes_runtime_compatible_xdp_section() {
        let xdp = XdpConfig {
            enabled: true,
            attach_mode: XdpAttachMode::Drv,
            fallback: XdpFallbackMode::FailStart,
            interfaces: vec![XdpInterfaceConfig {
                name: "eth0".to_string(),
                queues: vec![0, 1],
                mode: XdpRuntimeMode::Proxy,
                local_ips: vec!["192.0.2.10".parse().unwrap()],
                frame_size: 2048,
            }],
            proxy: XdpProxyConfig {
                protocols: default_proxy_protocols(),
                ports: vec![XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Https,
                    port: 443,
                }],
            },
        };

        let yaml = serde_yaml::to_string(&xdp).unwrap();
        let parsed: XdpConfig = serde_yaml::from_str(&yaml).unwrap();
        RuntimeConfig {
            xdp: parsed,
            ..Default::default()
        }
        .validate()
        .unwrap();
    }
}
