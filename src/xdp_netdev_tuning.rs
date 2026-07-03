use crate::paths::NodePaths;
use crate::runtime_mode::{XdpConfig, XdpFallbackMode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const NODE_LOG_TAG: &str = "xdp_tuning";
const PROFILE: &str = "aggressive";
#[cfg(target_os = "linux")]
const TARGET_TX_QUEUE_LEN: &str = "10000";
#[cfg(target_os = "linux")]
const SYSCTL_TARGETS: &[(&str, &str)] = &[
    ("net.core.netdev_max_backlog", "250000"),
    ("net.core.rmem_max", "134217728"),
    ("net.core.wmem_max", "134217728"),
    ("net.ipv4.tcp_rmem", "4096 87380 134217728"),
    ("net.ipv4.tcp_wmem", "4096 65536 134217728"),
];

#[derive(Clone, Debug)]
pub struct XdpNetdevTuneOptions {
    pub dry_run: bool,
    pub install_tools: bool,
    pub report_node_log: bool,
    pub persist_report: bool,
}

impl Default for XdpNetdevTuneOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            install_tools: false,
            report_node_log: true,
            persist_report: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum XdpTuneStatus {
    Applied,
    AlreadySet,
    Installing,
    DryRun,
    Installed,
    Skipped,
    SkippedFixed,
    SkippedMissing,
    Failed,
    UnsupportedPlatform,
}

impl XdpTuneStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::AlreadySet => "already_set",
            Self::Installing => "installing",
            Self::DryRun => "dry_run",
            Self::Installed => "installed",
            Self::Skipped => "skipped",
            Self::SkippedFixed => "skipped_fixed",
            Self::SkippedMissing => "skipped_missing",
            Self::Failed => "failed",
            Self::UnsupportedPlatform => "unsupported_platform",
        }
    }

    fn is_changed(&self) -> bool {
        matches!(self, Self::Applied | Self::Installed)
    }

    fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    fn log_level(&self) -> &'static str {
        if self.is_failed() { "warn" } else { "info" }
    }
}

impl std::fmt::Display for XdpTuneStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct XdpTuneAction {
    pub interface: Option<String>,
    pub key: String,
    pub old: Option<String>,
    pub target: String,
    pub final_value: Option<String>,
    pub status: XdpTuneStatus,
    pub reason: String,
    pub command: Option<String>,
}

impl XdpTuneAction {
    fn new(
        interface: Option<String>,
        key: impl Into<String>,
        old: Option<String>,
        target: impl Into<String>,
        final_value: Option<String>,
        status: XdpTuneStatus,
        reason: impl Into<String>,
        command: Option<String>,
    ) -> Self {
        Self {
            interface,
            key: key.into(),
            old,
            target: target.into(),
            final_value,
            status,
            reason: reason.into(),
            command,
        }
    }

    fn description(&self) -> String {
        format!(
            "iface={} key={} old={} target={} final={} status={} reason={} command={}",
            quote_field(self.interface.as_deref().unwrap_or("-")),
            quote_field(&self.key),
            quote_field(self.old.as_deref().unwrap_or("-")),
            quote_field(&self.target),
            quote_field(self.final_value.as_deref().unwrap_or("-")),
            self.status,
            quote_field(&self.reason),
            quote_field(self.command.as_deref().unwrap_or("-")),
        )
    }

    fn log(&self, report_node_log: bool) {
        if self.status.is_failed() {
            tracing::warn!("{}", self.description());
        } else if self.status.is_changed()
            || matches!(
                self.status,
                XdpTuneStatus::DryRun | XdpTuneStatus::Installing
            )
        {
            tracing::info!("{}", self.description());
        }
        if report_node_log {
            crate::logging::report_node_log(
                self.status.log_level().to_string(),
                NODE_LOG_TAG.to_string(),
                self.description(),
                0,
            );
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct XdpInterfaceTuneSummary {
    pub interface: String,
    pub driver: Option<String>,
    pub required_lro_off: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct XdpNetdevTuneReport {
    pub generated_at: u64,
    pub profile: String,
    pub dry_run: bool,
    pub ethtool_available: bool,
    pub interfaces: Vec<XdpInterfaceTuneSummary>,
    pub actions: Vec<XdpTuneAction>,
}

impl XdpNetdevTuneReport {
    pub fn changed_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| action.status.is_changed())
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| action.status.is_failed())
            .count()
    }

    pub fn skipped_count(&self) -> usize {
        self.actions
            .iter()
            .filter(|action| {
                matches!(
                    action.status,
                    XdpTuneStatus::Skipped
                        | XdpTuneStatus::SkippedFixed
                        | XdpTuneStatus::SkippedMissing
                )
            })
            .count()
    }

    pub fn summary(&self) -> String {
        format!(
            "profile={} dryRun={} ethtool={} changed={} failed={} skipped={} actions={}",
            self.profile,
            yes_no(self.dry_run),
            yes_no(self.ethtool_available),
            self.changed_count(),
            self.failed_count(),
            self.skipped_count(),
            self.actions.len()
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureState {
    pub value: String,
    pub fixed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureTune {
    pub key: &'static str,
    pub arg: &'static str,
    pub target: &'static str,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Zypper,
    Apk,
}

impl PackageManager {
    fn program(self) -> &'static str {
        match self {
            Self::Apt => "apt-get",
            Self::Dnf => "dnf",
            Self::Yum => "yum",
            Self::Zypper => "zypper",
            Self::Apk => "apk",
        }
    }

    #[cfg(target_os = "linux")]
    fn install_shell_command(self) -> &'static str {
        match self {
            Self::Apt => {
                "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ethtool iproute2"
            }
            Self::Dnf => "dnf install -y ethtool iproute",
            Self::Yum => "yum install -y ethtool iproute",
            Self::Zypper => "zypper --non-interactive install ethtool iproute2",
            Self::Apk => "apk add --no-cache ethtool iproute2",
        }
    }
}

pub fn apply_for_xdp_config(
    config: &XdpConfig,
    options: XdpNetdevTuneOptions,
) -> anyhow::Result<XdpNetdevTuneReport> {
    let interfaces = config
        .interfaces
        .iter()
        .map(|interface| interface.name.clone())
        .filter(|name| !name.trim().is_empty())
        .collect::<Vec<_>>();
    apply_for_interfaces(&interfaces, config.fallback, options)
}

pub fn apply_for_interfaces(
    interfaces: &[String],
    fallback: XdpFallbackMode,
    options: XdpNetdevTuneOptions,
) -> anyhow::Result<XdpNetdevTuneReport> {
    let mut report = XdpNetdevTuneReport {
        generated_at: unix_timestamp(),
        profile: PROFILE.to_string(),
        dry_run: options.dry_run,
        ethtool_available: command_exists("ethtool"),
        interfaces: Vec::new(),
        actions: Vec::new(),
    };

    #[cfg(not(target_os = "linux"))]
    {
        let _ = interfaces;
        let _ = fallback;
        report.actions.push(XdpTuneAction::new(
            None,
            "platform",
            None,
            "linux",
            None,
            XdpTuneStatus::UnsupportedPlatform,
            "XDP netdev tuning is supported on Linux only",
            None,
        ));
        finish_report(&report, &options)?;
        return Ok(report);
    }

    #[cfg(target_os = "linux")]
    {
        if interfaces.is_empty() {
            report.actions.push(XdpTuneAction::new(
                None,
                "interfaces",
                None,
                "non-empty",
                None,
                XdpTuneStatus::SkippedMissing,
                "no XDP interfaces configured",
                None,
            ));
            finish_report(&report, &options)?;
            return Ok(report);
        }

        ensure_ethtool(&mut report, &options);
        let ethtool_ready = report.ethtool_available;
        if !ethtool_ready && fallback.fail_start() && !options.dry_run {
            finish_report(&report, &options)?;
            anyhow::bail!(
                "ethtool is required for XDP netdev tuning; install ethtool or rerun without fail-start"
            );
        }

        let mut required_failures = Vec::new();
        for interface in interfaces {
            tune_interface(interface, ethtool_ready, &options, &mut report);
        }
        tune_sysctls(&options, &mut report);
        tune_irq_affinity(interfaces, &options, &mut report);

        for action in &report.actions {
            let required =
                action.key.ends_with("large-receive-offload") && action.status.is_failed();
            if required {
                required_failures.push(action.description());
            }
        }
        finish_report(&report, &options)?;
        if fallback.fail_start() && !required_failures.is_empty() {
            anyhow::bail!(
                "required XDP netdev tuning failed: {}",
                required_failures.join("; ")
            );
        }
        Ok(report)
    }
}

#[cfg(target_os = "linux")]
fn ensure_ethtool(report: &mut XdpNetdevTuneReport, options: &XdpNetdevTuneOptions) {
    if report.ethtool_available {
        report.actions.push(XdpTuneAction::new(
            None,
            "tool.ethtool",
            Some("present".to_string()),
            "present",
            Some("present".to_string()),
            XdpTuneStatus::AlreadySet,
            "ethtool is available",
            Some("command -v ethtool".to_string()),
        ));
        return;
    }

    if !options.install_tools {
        report.actions.push(XdpTuneAction::new(
            None,
            "tool.ethtool",
            Some("missing".to_string()),
            "present",
            Some("missing".to_string()),
            XdpTuneStatus::SkippedMissing,
            "automatic tool installation disabled",
            Some("command -v ethtool".to_string()),
        ));
        return;
    }

    if !running_as_root() {
        report.actions.push(XdpTuneAction::new(
            None,
            "tool.ethtool",
            Some("missing".to_string()),
            "present",
            Some("missing".to_string()),
            XdpTuneStatus::Failed,
            "cannot install ethtool without root",
            None,
        ));
        return;
    }

    let Some(manager) = detect_package_manager() else {
        report.actions.push(XdpTuneAction::new(
            None,
            "tool.ethtool",
            Some("missing".to_string()),
            "present",
            Some("missing".to_string()),
            XdpTuneStatus::Failed,
            "no supported package manager found",
            None,
        ));
        return;
    };

    let shell = manager.install_shell_command();
    if options.dry_run {
        report.actions.push(XdpTuneAction::new(
            None,
            "tool.ethtool",
            Some("missing".to_string()),
            "present",
            Some("missing".to_string()),
            XdpTuneStatus::DryRun,
            format!("would install with {}", manager.program()),
            Some(shell.to_string()),
        ));
        return;
    }

    report.actions.push(XdpTuneAction::new(
        None,
        "tool.ethtool",
        Some("missing".to_string()),
        "present",
        Some("installing".to_string()),
        XdpTuneStatus::Installing,
        format!("installing with {}", manager.program()),
        Some(shell.to_string()),
    ));
    let status = Command::new("sh").arg("-c").arg(shell).status();
    report.ethtool_available = command_exists("ethtool");
    report.actions.push(XdpTuneAction::new(
        None,
        "tool.ethtool",
        Some("missing".to_string()),
        "present",
        Some(if report.ethtool_available {
            "present".to_string()
        } else {
            "missing".to_string()
        }),
        if report.ethtool_available {
            XdpTuneStatus::Installed
        } else {
            XdpTuneStatus::Failed
        },
        match status {
            Ok(status) if status.success() => "package manager installed ethtool".to_string(),
            Ok(status) => format!("package manager exited with {status}"),
            Err(err) => err.to_string(),
        },
        Some(shell.to_string()),
    ));
}

#[cfg(target_os = "linux")]
fn tune_interface(
    interface: &str,
    ethtool_ready: bool,
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
) {
    let driver = if ethtool_ready {
        ethtool_driver(interface).ok()
    } else {
        None
    };
    let driver_ref = driver.as_deref().unwrap_or("unknown");
    report.interfaces.push(XdpInterfaceTuneSummary {
        interface: interface.to_string(),
        driver: driver.clone(),
        required_lro_off: driver_ref == "hv_netvsc",
    });

    if ethtool_ready {
        tune_features(interface, driver_ref, options, report);
        tune_channels(interface, options, report);
        tune_rings(interface, options, report);
        tune_coalesce(interface, options, report);
    } else {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            "ethtool",
            Some("missing".to_string()),
            "present",
            Some("missing".to_string()),
            XdpTuneStatus::SkippedMissing,
            "skipping ethtool-backed netdev tuning",
            None,
        ));
    }

    tune_link(interface, options, report);
    tune_queue_cpu_masks(interface, options, report);
}

#[cfg(target_os = "linux")]
fn tune_features(
    interface: &str,
    driver: &str,
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
) {
    let features_before = match ethtool_features(interface) {
        Ok(features) => features,
        Err(err) => {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                "features",
                None,
                "readable",
                None,
                XdpTuneStatus::Failed,
                err.to_string(),
                Some(format!("ethtool -k {interface}")),
            ));
            return;
        }
    };

    for tune in feature_tuning_plan(driver) {
        let key = format!("feature.{}", tune.key);
        let Some(state) = features_before.get(tune.key) else {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                key,
                None,
                tune.target,
                None,
                XdpTuneStatus::SkippedMissing,
                "feature not reported by ethtool",
                Some(format!("ethtool -k {interface}")),
            ));
            continue;
        };
        if state.fixed {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                key,
                Some(state.value.clone()),
                tune.target,
                Some(state.value.clone()),
                XdpTuneStatus::SkippedFixed,
                "feature is fixed by the driver",
                Some(format!(
                    "ethtool -K {interface} {} {}",
                    tune.arg, tune.target
                )),
            ));
            continue;
        }
        if state.value == tune.target {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                key,
                Some(state.value.clone()),
                tune.target,
                Some(state.value.clone()),
                XdpTuneStatus::AlreadySet,
                "already matches target",
                Some(format!(
                    "ethtool -K {interface} {} {}",
                    tune.arg, tune.target
                )),
            ));
            continue;
        }
        if options.dry_run {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                key,
                Some(state.value.clone()),
                tune.target,
                Some(state.value.clone()),
                XdpTuneStatus::DryRun,
                if tune.required {
                    "would change required XDP feature"
                } else {
                    "would change feature"
                },
                Some(format!(
                    "ethtool -K {interface} {} {}",
                    tune.arg, tune.target
                )),
            ));
            continue;
        }

        let command = format!("ethtool -K {interface} {} {}", tune.arg, tune.target);
        let status = Command::new("ethtool")
            .arg("-K")
            .arg(interface)
            .arg(tune.arg)
            .arg(tune.target)
            .status();
        let final_features = ethtool_features(interface).unwrap_or_default();
        let final_value = final_features
            .get(tune.key)
            .map(|feature| feature.value.clone());
        let success = status.as_ref().is_ok_and(|status| status.success())
            && final_value.as_deref() == Some(tune.target);
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            key,
            Some(state.value.clone()),
            tune.target,
            final_value,
            if success {
                XdpTuneStatus::Applied
            } else {
                XdpTuneStatus::Failed
            },
            match status {
                Ok(status) if status.success() => "feature updated".to_string(),
                Ok(status) => format!("ethtool exited with {status}"),
                Err(err) => err.to_string(),
            },
            Some(command),
        ));
    }
}

#[cfg(target_os = "linux")]
fn tune_channels(
    interface: &str,
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
) {
    let output = match command_output("ethtool", ["-l", interface]) {
        Ok(output) => output,
        Err(err) => {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                "channels.combined",
                None,
                "max",
                None,
                XdpTuneStatus::SkippedMissing,
                err.to_string(),
                Some(format!("ethtool -l {interface}")),
            ));
            return;
        }
    };
    let channels = parse_ethtool_channels(&output);
    let Some(max) = channels
        .get("max_combined")
        .copied()
        .filter(|value| *value > 0)
    else {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            "channels.combined",
            None,
            "max",
            None,
            XdpTuneStatus::SkippedMissing,
            "combined channel count is not reported",
            Some(format!("ethtool -l {interface}")),
        ));
        return;
    };
    let current = channels.get("current_combined").copied().unwrap_or(0);
    let target = std::cmp::min(max, std::cmp::max(1, num_cpus::get() as u32));
    apply_simple_ethtool_numeric(
        interface,
        "channels.combined",
        current,
        target,
        options,
        report,
        vec![
            "-L".to_string(),
            interface.to_string(),
            "combined".to_string(),
            target.to_string(),
        ],
    );
}

#[cfg(target_os = "linux")]
fn tune_rings(interface: &str, options: &XdpNetdevTuneOptions, report: &mut XdpNetdevTuneReport) {
    let output = match command_output("ethtool", ["-g", interface]) {
        Ok(output) => output,
        Err(err) => {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                "rings",
                None,
                "max",
                None,
                XdpTuneStatus::SkippedMissing,
                err.to_string(),
                Some(format!("ethtool -g {interface}")),
            ));
            return;
        }
    };
    let rings = parse_ethtool_rings(&output);
    for ring in ["rx", "tx"] {
        let max_key = format!("max_{ring}");
        let current_key = format!("current_{ring}");
        let Some(max) = rings.get(&max_key).copied().filter(|value| *value > 0) else {
            continue;
        };
        let current = rings.get(&current_key).copied().unwrap_or(0);
        apply_simple_ethtool_numeric(
            interface,
            &format!("rings.{ring}"),
            current,
            max,
            options,
            report,
            vec![
                "-G".to_string(),
                interface.to_string(),
                ring.to_string(),
                max.to_string(),
            ],
        );
    }
}

#[cfg(target_os = "linux")]
fn tune_coalesce(
    interface: &str,
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
) {
    let output = match command_output("ethtool", ["-c", interface]) {
        Ok(output) => output,
        Err(err) => {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                "coalesce",
                None,
                "low-latency",
                None,
                XdpTuneStatus::SkippedMissing,
                err.to_string(),
                Some(format!("ethtool -c {interface}")),
            ));
            return;
        }
    };
    let settings = parse_key_value_u32(&output);
    let old = ["adaptive-rx", "adaptive-tx", "rx-usecs", "tx-usecs"]
        .iter()
        .filter_map(|key| settings.get(*key).map(|value| format!("{key}={value}")))
        .collect::<Vec<_>>()
        .join(" ");
    let target = "adaptive-rx=off adaptive-tx=off rx-usecs=0 tx-usecs=0";
    let command = format!("ethtool -C {interface} {target}");
    if old.contains("rx-usecs=0")
        && old.contains("tx-usecs=0")
        && old.contains("adaptive-rx=0")
        && old.contains("adaptive-tx=0")
    {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            "coalesce",
            Some(old),
            target,
            Some(target.to_string()),
            XdpTuneStatus::AlreadySet,
            "already low latency",
            Some(command),
        ));
        return;
    }
    if options.dry_run {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            "coalesce",
            Some(old),
            target,
            None,
            XdpTuneStatus::DryRun,
            "would set low-latency coalescing",
            Some(command),
        ));
        return;
    }
    let status = Command::new("ethtool")
        .args([
            "-C",
            interface,
            "adaptive-rx",
            "off",
            "adaptive-tx",
            "off",
            "rx-usecs",
            "0",
            "tx-usecs",
            "0",
        ])
        .status();
    report.actions.push(XdpTuneAction::new(
        Some(interface.to_string()),
        "coalesce",
        Some(old),
        target,
        if status.as_ref().is_ok_and(|status| status.success()) {
            Some(target.to_string())
        } else {
            None
        },
        if status.as_ref().is_ok_and(|status| status.success()) {
            XdpTuneStatus::Applied
        } else {
            XdpTuneStatus::Failed
        },
        match status {
            Ok(status) if status.success() => "coalescing updated".to_string(),
            Ok(status) => format!("ethtool exited with {status}"),
            Err(err) => err.to_string(),
        },
        Some(command),
    ));
}

#[cfg(target_os = "linux")]
fn tune_link(interface: &str, options: &XdpNetdevTuneOptions, report: &mut XdpNetdevTuneReport) {
    if !command_exists("ip") {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            "ip.link",
            Some("ip-missing".to_string()),
            "up txqueuelen=10000",
            None,
            XdpTuneStatus::SkippedMissing,
            "ip command is missing",
            None,
        ));
        return;
    }
    let link = command_output("ip", ["-details", "link", "show", interface]).unwrap_or_default();
    let up = link.contains("<") && link.contains("UP");
    let qlen = parse_qlen(&link);
    let mtu = parse_link_field(&link, "mtu");

    apply_ip_link_action(
        interface,
        "ip.link.up",
        Some(if up { "up" } else { "down" }.to_string()),
        "up",
        options,
        report,
        vec!["link", "set", "dev", interface, "up"],
        up,
    );
    apply_ip_link_action(
        interface,
        "ip.link.txqueuelen",
        qlen.map(|value| value.to_string()),
        TARGET_TX_QUEUE_LEN,
        options,
        report,
        vec![
            "link",
            "set",
            "dev",
            interface,
            "txqueuelen",
            TARGET_TX_QUEUE_LEN,
        ],
        qlen.as_deref() == Some(TARGET_TX_QUEUE_LEN),
    );
    report.actions.push(XdpTuneAction::new(
        Some(interface.to_string()),
        "ip.link.mtu",
        mtu.clone(),
        "detect-only",
        mtu,
        XdpTuneStatus::Skipped,
        "MTU is observed only and is not modified automatically",
        Some(format!("ip -details link show {interface}")),
    ));
}

#[cfg(target_os = "linux")]
fn tune_queue_cpu_masks(
    interface: &str,
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
) {
    let mask = cpu_mask_for_count(num_cpus::get());
    for queue_kind in ["rx", "tx"] {
        let queue_root = Path::new("/sys/class/net").join(interface).join("queues");
        let Ok(entries) = fs::read_dir(&queue_root) else {
            report.actions.push(XdpTuneAction::new(
                Some(interface.to_string()),
                format!("queues.{queue_kind}.cpu_mask"),
                None,
                mask.clone(),
                None,
                XdpTuneStatus::SkippedMissing,
                format!("{} is missing", queue_root.display()),
                None,
            ));
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !name.starts_with(&format!("{queue_kind}-")) {
                continue;
            }
            let file_name = if queue_kind == "rx" {
                "rps_cpus"
            } else {
                "xps_cpus"
            };
            let path = entry.path().join(file_name);
            apply_sysfs_write(
                Some(interface),
                &format!("queue.{name}.{file_name}"),
                &path,
                &mask,
                options,
                report,
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn tune_sysctls(options: &XdpNetdevTuneOptions, report: &mut XdpNetdevTuneReport) {
    for (key, target) in SYSCTL_TARGETS {
        let path = Path::new("/proc/sys").join(key.replace('.', "/"));
        apply_sysfs_write(
            None::<&str>,
            &format!("sysctl.{key}"),
            &path,
            target,
            options,
            report,
        );
    }
}

#[cfg(target_os = "linux")]
fn tune_irq_affinity(
    interfaces: &[String],
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
) {
    let Ok(interrupts) = fs::read_to_string("/proc/interrupts") else {
        report.actions.push(XdpTuneAction::new(
            None,
            "irq.affinity",
            None,
            "balanced",
            None,
            XdpTuneStatus::SkippedMissing,
            "/proc/interrupts is not readable",
            None,
        ));
        return;
    };
    let cpus = std::cmp::max(1, num_cpus::get());
    let mut index = 0usize;
    for line in interrupts.lines() {
        if !interfaces.iter().any(|iface| line.contains(iface)) {
            continue;
        }
        let Some((irq, _)) = line.split_once(':') else {
            continue;
        };
        let irq = irq.trim();
        if irq.is_empty() || !irq.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let target = (index % cpus).to_string();
        index = index.saturating_add(1);
        let path = Path::new("/proc/irq").join(irq).join("smp_affinity_list");
        apply_sysfs_write(
            None::<&str>,
            &format!("irq.{irq}.smp_affinity_list"),
            &path,
            &target,
            options,
            report,
        );
    }
}

#[cfg(target_os = "linux")]
fn apply_simple_ethtool_numeric(
    interface: &str,
    key: &str,
    current: u32,
    target: u32,
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
    args: Vec<String>,
) {
    let command = format!("ethtool {}", args.join(" "));
    if current == target {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            key,
            Some(current.to_string()),
            target.to_string(),
            Some(current.to_string()),
            XdpTuneStatus::AlreadySet,
            "already matches target",
            Some(command),
        ));
        return;
    }
    if options.dry_run {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            key,
            Some(current.to_string()),
            target.to_string(),
            Some(current.to_string()),
            XdpTuneStatus::DryRun,
            "would update ethtool numeric setting",
            Some(command),
        ));
        return;
    }
    let status = Command::new("ethtool").args(&args).status();
    report.actions.push(XdpTuneAction::new(
        Some(interface.to_string()),
        key,
        Some(current.to_string()),
        target.to_string(),
        if status.as_ref().is_ok_and(|status| status.success()) {
            Some(target.to_string())
        } else {
            None
        },
        if status.as_ref().is_ok_and(|status| status.success()) {
            XdpTuneStatus::Applied
        } else {
            XdpTuneStatus::Failed
        },
        match status {
            Ok(status) if status.success() => "setting updated".to_string(),
            Ok(status) => format!("ethtool exited with {status}"),
            Err(err) => err.to_string(),
        },
        Some(command),
    ));
}

#[cfg(target_os = "linux")]
fn apply_ip_link_action(
    interface: &str,
    key: &str,
    old: Option<String>,
    target: &str,
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
    args: Vec<&str>,
    already_set: bool,
) {
    let command = format!("ip {}", args.join(" "));
    if already_set {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            key,
            old.clone(),
            target,
            old,
            XdpTuneStatus::AlreadySet,
            "already matches target",
            Some(command),
        ));
        return;
    }
    if options.dry_run {
        report.actions.push(XdpTuneAction::new(
            Some(interface.to_string()),
            key,
            old.clone(),
            target,
            old,
            XdpTuneStatus::DryRun,
            "would update link setting",
            Some(command),
        ));
        return;
    }
    let status = Command::new("ip").args(args).status();
    report.actions.push(XdpTuneAction::new(
        Some(interface.to_string()),
        key,
        old,
        target,
        if status.as_ref().is_ok_and(|status| status.success()) {
            Some(target.to_string())
        } else {
            None
        },
        if status.as_ref().is_ok_and(|status| status.success()) {
            XdpTuneStatus::Applied
        } else {
            XdpTuneStatus::Failed
        },
        match status {
            Ok(status) if status.success() => "link setting updated".to_string(),
            Ok(status) => format!("ip exited with {status}"),
            Err(err) => err.to_string(),
        },
        Some(command),
    ));
}

#[cfg(target_os = "linux")]
fn apply_sysfs_write(
    interface: Option<&str>,
    key: &str,
    path: &Path,
    target: &str,
    options: &XdpNetdevTuneOptions,
    report: &mut XdpNetdevTuneReport,
) {
    let interface = interface.map(str::to_string);
    let old = fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string());
    if old.as_deref() == Some(target) {
        report.actions.push(XdpTuneAction::new(
            interface,
            key,
            old.clone(),
            target,
            old,
            XdpTuneStatus::AlreadySet,
            "already matches target",
            Some(format!("write {} {}", path.display(), target)),
        ));
        return;
    }
    if !path.exists() {
        report.actions.push(XdpTuneAction::new(
            interface,
            key,
            old,
            target,
            None,
            XdpTuneStatus::SkippedMissing,
            "path is missing",
            Some(format!("write {} {}", path.display(), target)),
        ));
        return;
    }
    if options.dry_run {
        report.actions.push(XdpTuneAction::new(
            interface,
            key,
            old.clone(),
            target,
            old,
            XdpTuneStatus::DryRun,
            "would write sysfs/proc setting",
            Some(format!("write {} {}", path.display(), target)),
        ));
        return;
    }
    let write = fs::write(path, target);
    let final_value = fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string());
    let success = write.is_ok() && final_value.as_deref() == Some(target);
    report.actions.push(XdpTuneAction::new(
        interface,
        key,
        old,
        target,
        final_value,
        if success {
            XdpTuneStatus::Applied
        } else {
            XdpTuneStatus::Failed
        },
        match write {
            Ok(()) => "setting updated".to_string(),
            Err(err) => err.to_string(),
        },
        Some(format!("write {} {}", path.display(), target)),
    ));
}

fn finish_report(
    report: &XdpNetdevTuneReport,
    options: &XdpNetdevTuneOptions,
) -> anyhow::Result<()> {
    for action in &report.actions {
        action.log(options.report_node_log);
    }
    if options.persist_report {
        write_latest_report(report)?;
    }
    Ok(())
}

pub fn write_latest_report(report: &XdpNetdevTuneReport) -> anyhow::Result<()> {
    let path = NodePaths::current().xdp_tuning_file();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

pub fn latest_report() -> Option<XdpNetdevTuneReport> {
    let path = NodePaths::current().xdp_tuning_file();
    let body = fs::read(path).ok()?;
    serde_json::from_slice(&body).ok()
}

pub fn print_report(report: &XdpNetdevTuneReport) {
    println!("XDP netdev tuning");
    println!("  summary: {}", report.summary());
    for interface in &report.interfaces {
        println!(
            "  interface: {} driver={} required_lro_off={}",
            interface.interface,
            interface.driver.as_deref().unwrap_or("-"),
            yes_no(interface.required_lro_off)
        );
    }
    for action in &report.actions {
        if action.status.is_changed()
            || action.status.is_failed()
            || matches!(action.status, XdpTuneStatus::DryRun)
        {
            println!("  {}", action.description());
        }
    }
}

pub fn status_lines() -> Vec<String> {
    let Some(report) = latest_report() else {
        return vec!["  netdev tune:  no report".to_string()];
    };
    vec![
        format!("  netdev tune:  {}", report.summary()),
        format!(
            "  tune report:  {}",
            NodePaths::current().xdp_tuning_file().display()
        ),
    ]
}

pub fn doctor_lines_for_config(config: &XdpConfig) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "  netdev tune:  ethtool={} profile={}",
        yes_no(command_exists("ethtool")),
        PROFILE
    ));
    if let Some(report) = latest_report() {
        lines.push(format!("  tune summary: {}", report.summary()));
    }
    #[cfg(target_os = "linux")]
    for interface in &config.interfaces {
        let driver = ethtool_driver(&interface.name).ok();
        let features = ethtool_features(&interface.name).ok();
        let lro = features
            .as_ref()
            .and_then(|features| features.get("large-receive-offload"))
            .map(|feature| feature.value.as_str())
            .unwrap_or("-");
        lines.push(format!(
            "  tune iface:   {} driver={} lro={}",
            interface.name,
            driver.as_deref().unwrap_or("-"),
            lro
        ));
        if driver.as_deref() == Some("hv_netvsc") && lro == "on" {
            lines.push(
                "  issue:        required lro=off for XDP on hv_netvsc; run cloud-node xdp start or cloud-node xdp tune --apply"
                    .to_string(),
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = config;
    lines
}

#[cfg(target_os = "linux")]
fn ethtool_driver(interface: &str) -> io::Result<String> {
    let output = command_output("ethtool", ["-i", interface])?;
    for line in output.lines() {
        if let Some((key, value)) = line.split_once(':')
            && key.trim() == "driver"
        {
            return Ok(value.trim().to_string());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "ethtool driver output did not contain driver",
    ))
}

#[cfg(target_os = "linux")]
fn ethtool_features(interface: &str) -> io::Result<BTreeMap<String, FeatureState>> {
    command_output("ethtool", ["-k", interface]).map(|output| parse_ethtool_features(&output))
}

pub fn parse_ethtool_features(output: &str) -> BTreeMap<String, FeatureState> {
    let mut features = BTreeMap::new();
    for line in output.lines() {
        let trimmed = line.trim();
        let Some((key, rest)) = trimmed.split_once(':') else {
            continue;
        };
        let value = rest.split_whitespace().next().unwrap_or("").trim();
        if value != "on" && value != "off" {
            continue;
        }
        features.insert(
            key.trim().to_string(),
            FeatureState {
                value: value.to_string(),
                fixed: rest.contains("[fixed]"),
            },
        );
    }
    features
}

pub fn feature_tuning_plan(driver: &str) -> Vec<FeatureTune> {
    let hv_netvsc = driver == "hv_netvsc";
    vec![
        FeatureTune {
            key: "large-receive-offload",
            arg: "lro",
            target: "off",
            required: hv_netvsc,
        },
        FeatureTune {
            key: "generic-receive-offload",
            arg: "gro",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "generic-segmentation-offload",
            arg: "gso",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "tcp-segmentation-offload",
            arg: "tso",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "rx-gro-hw",
            arg: "rx-gro-hw",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "rx-gro-list",
            arg: "rx-gro-list",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "rx-udp-gro-forwarding",
            arg: "rx-udp-gro-forwarding",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "rx-checksumming",
            arg: "rx",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "tx-checksumming",
            arg: "tx",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "scatter-gather",
            arg: "sg",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "rx-vlan-offload",
            arg: "rxvlan",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "tx-vlan-offload",
            arg: "txvlan",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "rx-vlan-filter",
            arg: "rx-vlan-filter",
            target: "off",
            required: false,
        },
        FeatureTune {
            key: "receive-hashing",
            arg: "rxhash",
            target: "on",
            required: false,
        },
    ]
}

pub fn parse_ethtool_channels(output: &str) -> BTreeMap<String, u32> {
    parse_ethtool_sectioned_numbers(output, "max_", "current_")
}

pub fn parse_ethtool_rings(output: &str) -> BTreeMap<String, u32> {
    parse_ethtool_sectioned_numbers(output, "max_", "current_")
}

fn parse_ethtool_sectioned_numbers(
    output: &str,
    max_prefix: &str,
    current_prefix: &str,
) -> BTreeMap<String, u32> {
    let mut values = BTreeMap::new();
    let mut prefix = "";
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Pre-set maximums") {
            prefix = max_prefix;
            continue;
        }
        if trimmed.starts_with("Current hardware settings") {
            prefix = current_prefix;
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let Some(value) = value
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let normalized = key.trim().to_ascii_lowercase().replace(' ', "_");
        values.insert(format!("{prefix}{normalized}"), value);
    }
    values
}

pub fn parse_key_value_u32(output: &str) -> BTreeMap<String, u32> {
    let mut values = BTreeMap::new();
    for line in output.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        let parsed = match value {
            "on" => Some(1),
            "off" => Some(0),
            _ => value.parse::<u32>().ok(),
        };
        if let Some(parsed) = parsed {
            values.insert(key.trim().to_ascii_lowercase().replace(' ', "-"), parsed);
        }
    }
    values
}

pub fn parse_qlen(output: &str) -> Option<String> {
    parse_link_field(output, "qlen")
}

pub fn parse_link_field(output: &str, field: &str) -> Option<String> {
    let parts = output.split_whitespace().collect::<Vec<_>>();
    parts
        .windows(2)
        .find_map(|pair| (pair[0] == field).then(|| pair[1].to_string()))
}

pub fn cpu_mask_for_count(count: usize) -> String {
    let count = count.max(1);
    let groups = count.div_ceil(32);
    let mut parts = Vec::with_capacity(groups);
    for group in 0..groups {
        let remaining = count.saturating_sub(group * 32);
        let bits = remaining.min(32);
        let value = if bits == 32 {
            u32::MAX
        } else {
            (1u32 << bits) - 1
        };
        parts.push(format!("{value:x}"));
    }
    parts.reverse();
    parts.join(",")
}

pub fn select_package_manager(available: &[&str]) -> Option<PackageManager> {
    for manager in [
        PackageManager::Apt,
        PackageManager::Dnf,
        PackageManager::Yum,
        PackageManager::Zypper,
        PackageManager::Apk,
    ] {
        if available
            .iter()
            .any(|program| *program == manager.program())
        {
            return Some(manager);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_package_manager() -> Option<PackageManager> {
    let available = [
        PackageManager::Apt,
        PackageManager::Dnf,
        PackageManager::Yum,
        PackageManager::Zypper,
        PackageManager::Apk,
    ]
    .into_iter()
    .filter(|manager| command_exists(manager.program()))
    .map(|manager| manager.program())
    .collect::<Vec<_>>();
    select_package_manager(&available)
}

fn command_exists(program: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(program).is_file())
}

#[cfg(target_os = "linux")]
fn command_output<const N: usize>(program: &str, args: [&str; N]) -> io::Result<String> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{program} exited with {}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn quote_field(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ethtool_features_and_fixed_flags() {
        let parsed = parse_ethtool_features(
            r#"
Features for eth0:
rx-checksumming: on
tx-scatter-gather-fraglist: off [fixed]
large-receive-offload: on
"#,
        );
        assert_eq!(parsed["rx-checksumming"].value, "on");
        assert!(!parsed["rx-checksumming"].fixed);
        assert_eq!(parsed["tx-scatter-gather-fraglist"].value, "off");
        assert!(parsed["tx-scatter-gather-fraglist"].fixed);
        assert_eq!(parsed["large-receive-offload"].value, "on");
    }

    #[test]
    fn hv_netvsc_requires_lro_off() {
        let plan = feature_tuning_plan("hv_netvsc");
        let lro = plan
            .iter()
            .find(|entry| entry.key == "large-receive-offload")
            .unwrap();
        assert_eq!(lro.target, "off");
        assert!(lro.required);
        assert!(plan.iter().any(|entry| entry.key == "rx-vlan-offload"));
        assert!(plan.iter().any(|entry| entry.key == "tx-vlan-offload"));
        assert!(plan.iter().any(|entry| entry.key == "receive-hashing"));
    }

    #[test]
    fn parses_channels_and_rings() {
        let channels = parse_ethtool_channels(
            r#"
Channel parameters for eth0:
Pre-set maximums:
RX:             0
TX:             0
Combined:       64
Current hardware settings:
RX:             0
TX:             0
Combined:       4
"#,
        );
        assert_eq!(channels["max_combined"], 64);
        assert_eq!(channels["current_combined"], 4);

        let rings = parse_ethtool_rings(
            r#"
Ring parameters for eth0:
Pre-set maximums:
RX:             4096
TX:             4096
Current hardware settings:
RX:             512
TX:             1024
"#,
        );
        assert_eq!(rings["max_rx"], 4096);
        assert_eq!(rings["current_tx"], 1024);
    }

    #[test]
    fn cpu_masks_are_deterministic() {
        assert_eq!(cpu_mask_for_count(1), "1");
        assert_eq!(cpu_mask_for_count(4), "f");
        assert_eq!(cpu_mask_for_count(32), "ffffffff");
        assert_eq!(cpu_mask_for_count(33), "1,ffffffff");
    }

    #[test]
    fn package_manager_selection_is_ordered() {
        assert_eq!(
            select_package_manager(&["yum", "apt-get"]),
            Some(PackageManager::Apt)
        );
        assert_eq!(select_package_manager(&["apk"]), Some(PackageManager::Apk));
        assert_eq!(select_package_manager(&["pacman"]), None);
    }

    #[test]
    fn parses_qlen_from_ip_link() {
        assert_eq!(
            parse_qlen("2: eth0: <UP> mtu 1500 qdisc mq state UP qlen 1000"),
            Some("1000".to_string())
        );
        assert_eq!(
            parse_link_field("2: eth0: <UP> mtu 1500 qdisc mq state UP qlen 1000", "mtu"),
            Some("1500".to_string())
        );
    }

    #[test]
    fn parses_coalesce_keys_with_normalized_names() {
        let parsed = parse_key_value_u32(
            r#"
Adaptive RX: off
Adaptive TX: on
rx-usecs: 0
tx-usecs: 12
"#,
        );
        assert_eq!(parsed["adaptive-rx"], 0);
        assert_eq!(parsed["adaptive-tx"], 1);
        assert_eq!(parsed["rx-usecs"], 0);
        assert_eq!(parsed["tx-usecs"], 12);
    }
}
