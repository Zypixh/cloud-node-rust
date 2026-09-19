use anyhow::Result;
use std::io::{self, Write};
use std::path::Path;

use crate::i18n::{Language, t};
use crate::runtime_mode::{RuntimeConfig, XdpConfig};

#[derive(Debug, Clone)]
pub struct XdpConfigWizard {
    pub xdp: XdpConfig,
}

impl XdpConfigWizard {
    pub fn run_interactive() -> Result<Option<Self>> {
        prompt_menu_language()?;
        println!("\n{}\n", t("xdp.menu.title"));

        let enabled = prompt_yes_no(t("xdp.menu.enable"), true)?;
        let runtime_config = RuntimeConfig::load_default()?;
        let xdp = if enabled {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let xdp = rt.block_on(crate::xdp_auto_config::derive_xdp_config_from_live_node(
                &runtime_config,
            ))?;
            print_auto_config_summary(&xdp);
            xdp
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
            let path = crate::paths::NodePaths::current().api_config_file();
            wizard.save_to_file(&path)?;
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
        }
        .validate()
    }

    fn save_to_file(&self, path: &Path) -> Result<()> {
        save_xdp_config(path, &self.xdp)
    }
}

fn print_auto_config_summary(xdp: &XdpConfig) {
    println!("\n{}", t("xdp.menu.auto_summary"));
    println!("  attachMode: {}", xdp.attach_mode.as_str());
    println!("  fallback:   {}", xdp.fallback.as_str());
    println!(
        "  interfaces: {}",
        xdp.interfaces
            .iter()
            .map(|interface| format!("{} queues={:?}", interface.name, interface.queues))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  ports:      {}",
        xdp.proxy
            .ports
            .iter()
            .map(|port| format!("{}:{}", port.protocol.as_str(), port.port))
            .collect::<Vec<_>>()
            .join(", ")
    );
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

pub fn save_xdp_config(path: &Path, xdp: &XdpConfig) -> Result<()> {
    use std::fs;

    let mut root = read_yaml_mapping(path)?;

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

/// Persist only the `xdp.enabled` flag, preserving everything else already in
/// the file. XDP is on by default; the file exists solely to record an
/// explicit operator override and outranks the `CLOUD_NODE_XDP` env var.
/// The `xdp` section is replaced rather than merged so stale operational
/// fields cannot shadow the auto-derived configuration.
pub fn save_xdp_enabled(path: &Path, enabled: bool) -> Result<()> {
    use std::fs;

    let mut root = read_yaml_mapping(path)?;
    if let Some(value) = root.get_mut(serde_yaml::Value::String("xdp".to_string()))
        && !matches!(value, serde_yaml::Value::Mapping(_) | serde_yaml::Value::Null)
    {
        anyhow::bail!("{}: `xdp` is not a YAML mapping", path.display());
    }
    let mut xdp = serde_yaml::Mapping::new();
    xdp.insert(
        serde_yaml::Value::String("enabled".to_string()),
        serde_yaml::Value::Bool(enabled),
    );
    root.insert(
        serde_yaml::Value::String("xdp".to_string()),
        serde_yaml::Value::Mapping(xdp),
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

/// Like `save_xdp_enabled` but merges into the existing `xdp` mapping instead
/// of replacing it. Used when the file carries an explicit operational
/// configuration (interfaces, ports): that file is the operator's
/// authoritative document and only the `enabled` toggle may be touched.
pub fn merge_xdp_enabled(path: &Path, enabled: bool) -> Result<()> {
    use std::fs;

    let mut root = read_yaml_mapping(path)?;
    let key = serde_yaml::Value::String("xdp".to_string());
    match root.get_mut(&key) {
        Some(serde_yaml::Value::Mapping(xdp)) => {
            xdp.insert(
                serde_yaml::Value::String("enabled".to_string()),
                serde_yaml::Value::Bool(enabled),
            );
        }
        Some(serde_yaml::Value::Null) | None => {
            let mut xdp = serde_yaml::Mapping::new();
            xdp.insert(
                serde_yaml::Value::String("enabled".to_string()),
                serde_yaml::Value::Bool(enabled),
            );
            root.insert(key, serde_yaml::Value::Mapping(xdp));
        }
        Some(_) => anyhow::bail!("{}: `xdp` is not a YAML mapping", path.display()),
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(
        path,
        serde_yaml::to_string(&serde_yaml::Value::Mapping(root))?,
    )?;
    Ok(())
}

fn read_yaml_mapping(path: &Path) -> Result<serde_yaml::Mapping> {
    use std::fs;

    if !path.exists() {
        return Ok(serde_yaml::Mapping::new());
    }
    let existing = fs::read_to_string(path)?;
    if existing.trim().is_empty() {
        return Ok(serde_yaml::Mapping::new());
    }
    match serde_yaml::from_str::<serde_yaml::Value>(&existing)? {
        serde_yaml::Value::Mapping(mapping) => Ok(mapping),
        _ => anyhow::bail!("{} is not a YAML mapping", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_mode::{
        XdpAttachMode, XdpFallbackMode, XdpInterfaceConfig, XdpProxyConfig, XdpProxyPortConfig,
        XdpProxyProtocol, XdpRuntimeMode,
    };

    #[test]
    fn merge_xdp_enabled_preserves_operational_fields() {
        let dir = std::env::temp_dir().join(format!(
            "xdp-merge-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api_node.yaml");
        std::fs::write(
            &path,
            "nodeId: 3\nxdp:\n  enabled: false\n  attachMode: skb\n  interfaces:\n    - name: eth0\n      mode: proxy\n",
        )
        .unwrap();
        super::merge_xdp_enabled(&path, true).unwrap();
        let value: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["xdp"]["enabled"].as_bool(), Some(true));
        assert_eq!(value["xdp"]["attachMode"].as_str(), Some("skb"));
        assert_eq!(
            value["xdp"]["interfaces"][0]["name"].as_str(),
            Some("eth0")
        );
        std::fs::remove_dir_all(&dir).ok();
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
                cpus: Vec::new(),
                mode: XdpRuntimeMode::Proxy,
                local_ips: vec!["192.0.2.10".parse().unwrap()],
                frame_size: 2048,
                udp_forwards: Vec::new(),
                tcp_forwards: Vec::new(),
                fragment_action: crate::runtime_mode::XdpFragmentAction::default(),
                protected_services: Vec::new(),
                xsk_mode: crate::runtime_mode::XdpXskMode::default(),
            }],
            proxy: XdpProxyConfig {
                protocols: vec![
                    XdpProxyProtocol::Http,
                    XdpProxyProtocol::Https,
                    XdpProxyProtocol::Tcp,
                    XdpProxyProtocol::Udp,
                    XdpProxyProtocol::H3,
                ],
                ports: vec![XdpProxyPortConfig {
                    protocol: XdpProxyProtocol::Https,
                    port: 443,
                }],
            },
            rate_limit: None,
            budget: None,
            admission: None,
            ebpf_object: None,
            state_tables: None,
            upstream: None,
            transport: None,
            egress_rate_bps: None,
        };

        let yaml = serde_yaml::to_string(&xdp).unwrap();
        let parsed: XdpConfig = serde_yaml::from_str(&yaml).unwrap();
        RuntimeConfig { xdp: parsed }.validate().unwrap();
    }
}
