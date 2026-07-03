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
            let path = crate::paths::NodePaths::current().runtime_config_file();
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
            ..Default::default()
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
    use crate::runtime_mode::{
        XdpAttachMode, XdpFallbackMode, XdpInterfaceConfig, XdpProxyConfig, XdpProxyPortConfig,
        XdpProxyProtocol, XdpRuntimeMode,
    };

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
