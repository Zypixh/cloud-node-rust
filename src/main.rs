#[cfg(target_os = "linux")]
use anyhow::Context;
use chrono::{Local, TimeZone};
use clap::{Parser, Subcommand, ValueEnum};
use cloud_node_rust::i18n::{Language, t};
use cloud_node_rust::xdp_config_wizard::{XdpConfigWizard, save_xdp_config};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs;
use std::future::Future;
use std::io::{self, IsTerminal};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;

use cloud_node_rust::api_config::ApiConfig;
use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::firewall::state::WafStateManager;
use cloud_node_rust::health_manager::GlobalHealthManager;
use cloud_node_rust::kernel_syn_defense;
use cloud_node_rust::l4_connection_registry;
use cloud_node_rust::proxy::EdgeProxy;
use cloud_node_rust::runtime_mode::{
    RuntimeConfig, XdpAttachMode, XdpFallbackMode, XdpRuntimeMode,
};
use cloud_node_rust::ssl::DynamicCertSelector;
use cloud_node_rust::{firewall, log_uploader, logging, rpc, tcp_proxy, udp_proxy};

struct LocalLogTimer;

impl FormatTime for LocalLogTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        write!(
            w,
            "{}",
            cloud_node_rust::utils::time::now_local_millis().format("%Y-%m-%dT%H:%M:%S%.6f%:z")
        )
    }
}

#[derive(Clone)]
struct SharedLogWriter {
    sender: std_mpsc::SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
}

impl SharedLogWriter {
    fn new(file: fs::File, path: PathBuf) -> Self {
        let snapshot = cloud_node_rust::memory_governor::MEMORY_GOVERNOR
            .snapshot(cloud_node_rust::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads());
        let estimated_event_bytes = 1024u64;
        let queue_capacity =
            usize::try_from(snapshot.local_log_queue_budget_bytes / estimated_event_bytes)
                .unwrap_or(usize::MAX)
                .max(1);
        let (sender, receiver) = std_mpsc::sync_channel(queue_capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let worker_dropped = Arc::clone(&dropped);
        std::thread::Builder::new()
            .name("run-log-writer".to_string())
            .spawn(move || run_log_writer(file, path, receiver, worker_dropped))
            .unwrap_or_else(|err| panic!("failed to start run log writer: {err}"));
        Self { sender, dropped }
    }
}

struct SharedLogGuard {
    sender: std_mpsc::SyncSender<Vec<u8>>,
    dropped: Arc<AtomicU64>,
    buffer: Vec<u8>,
}

impl SharedLogGuard {
    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let buffer = std::mem::take(&mut self.buffer);
        match self.sender.try_send(buffer) {
            Ok(()) => Ok(()),
            Err(std_mpsc::TrySendError::Full(_)) | Err(std_mpsc::TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                cloud_node_rust::pipeline_metrics::increment(
                    cloud_node_rust::pipeline_metrics::PipelineCounter::LocalLogDropped,
                );
                Ok(())
            }
        }
    }
}

impl Drop for SharedLogGuard {
    fn drop(&mut self) {
        let _ = self.flush_buffer();
    }
}

impl io::Write for SharedLogGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer()
    }
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = SharedLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogGuard {
            sender: self.sender.clone(),
            dropped: Arc::clone(&self.dropped),
            buffer: Vec::new(),
        }
    }
}

fn run_log_writer(
    mut file: fs::File,
    path: PathBuf,
    receiver: std_mpsc::Receiver<Vec<u8>>,
    _dropped: Arc<AtomicU64>,
) {
    use std::io::Write as _;
    let rotate_bytes = cloud_node_rust::memory_governor::MEMORY_GOVERNOR
        .snapshot(cloud_node_rust::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads())
        .local_log_queue_budget_bytes
        .max(1024 * 1024);
    let mut written = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    let mut pending = Vec::new();
    while let Ok(first) = receiver.recv() {
        pending.extend_from_slice(&first);
        while let Ok(next) = receiver.try_recv() {
            pending.extend_from_slice(&next);
            if pending.len() as u64 >= rotate_bytes {
                break;
            }
        }
        if written.saturating_add(pending.len() as u64) > rotate_bytes {
            let rotated = path.with_extension("log.1");
            let rotation = (|| -> io::Result<()> {
                file.flush()?;
                if rotated.exists() {
                    fs::remove_file(&rotated)?;
                }
                fs::rename(&path, &rotated)?;
                file = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                written = 0;
                Ok(())
            })();
            if rotation.is_err() {
                cloud_node_rust::pipeline_metrics::increment(
                    cloud_node_rust::pipeline_metrics::PipelineCounter::LocalLogRotationFailed,
                );
            }
        }
        if file.write_all(&pending).and_then(|_| file.flush()).is_err() {
            cloud_node_rust::pipeline_metrics::increment(
                cloud_node_rust::pipeline_metrics::PipelineCounter::LocalLogWriteFailed,
            );
        } else {
            written = written.saturating_add(pending.len() as u64);
        }
        pending.clear();
    }
    let _ = file.flush();
}

#[derive(Parser)]
#[command(name = "cloud-node-rust")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "CloudNode - High Performance Cloud Node written in Rust / Rust 编写的高性能云节点", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(
        long,
        global = true,
        help = "Port to start the performance monitor web dashboard / 性能监控面板端口"
    )]
    monitor_port: Option<u16>,

    #[arg(
        long,
        global = true,
        help = "Clear in-memory performance monitor samples on startup / 启动时清空内存性能采样"
    )]
    monitor_clear: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the cloud node in background
    Start,
    /// Stop the background cloud node
    Stop,
    /// Check the status of the cloud node
    Status,
    /// Restart the background cloud node
    Restart,
    /// Install the cloud node as a systemd service and global command
    Install,
    /// Upgrade the installed binary from GitHub Releases
    Upgrade {
        /// Release tag to install, for example v1.1.6. Defaults to latest.
        #[arg(long, default_value = "latest")]
        version: String,

        /// GitHub repository in OWNER/REPO form.
        #[arg(long, default_value = "Zypixh/cloud-node-rust")]
        repo: String,

        /// GitHub base URL used to construct release download URLs.
        #[arg(long, default_value = "https://github.com")]
        github_base_url: String,

        /// Optional GitHub mirror/proxy. If it contains {url}, the original URL replaces it.
        #[arg(long)]
        github_mirror: Option<String>,

        /// Override release asset name instead of auto-detecting CPU/architecture.
        #[arg(long)]
        asset: Option<String>,

        /// Override the binary path to replace. Defaults to the current executable path.
        #[arg(long)]
        install_binary: Option<PathBuf>,

        /// Directory for previous binary backups.
        #[arg(long, default_value = "/var/backups/cloud-node-rust-upgrade")]
        backup_dir: PathBuf,

        /// Confirm all prompts and run non-interactively.
        #[arg(long, alias = "non-interactive")]
        yes: bool,

        /// Download and show actions without replacing files or restarting service.
        #[arg(long)]
        dry_run: bool,

        /// Do not restart/start cloud-node after replacing the binary.
        #[arg(long)]
        no_restart: bool,
    },
    /// Synchronize system clock with NTP servers and optionally set system timezone
    Ntp {
        /// Set system timezone, for example Asia/Shanghai or UTC.
        #[arg(long)]
        timezone: Option<String>,

        /// Do not prompt for or change system timezone.
        #[arg(long)]
        no_timezone: bool,

        /// Confirm defaults and run non-interactively.
        #[arg(long, alias = "non-interactive")]
        yes: bool,

        /// NTP server host or HTTPS time source URL. Can be repeated. Defaults to built-in global sources.
        #[arg(long = "server")]
        servers: Vec<String>,

        /// Per-server NTP timeout in milliseconds.
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
    },
    /// View or change TCP/SNI relay zero-copy mode
    #[command(name = "zerocopy", alias = "zero-copy")]
    ZeroCopy {
        /// Enable Linux splice zero-copy relay.
        #[arg(long)]
        enable: bool,

        /// Disable Linux splice zero-copy relay.
        #[arg(long)]
        disable: bool,

        /// Write the selected value without interactive confirmation.
        #[arg(long, alias = "non-interactive")]
        yes: bool,
    },
    /// Manage and inspect local kernel firewall state
    Firewall {
        #[command(subcommand)]
        command: FirewallCommands,
    },
    /// Inspect runtime L4/TCP defense state
    Defense {
        #[command(subcommand)]
        command: DefenseCommands,
    },
    /// Manage XDP/AF_XDP dataplane state
    Xdp {
        #[command(subcommand)]
        command: XdpCommands,
    },
    /// Test the configuration
    Test,
    /// Internal use only
    #[command(hide = true)]
    _StartInternal,
}

#[derive(Subcommand)]
enum FirewallCommands {
    /// Initialize nftables table, sets, chain and drop rules
    Init,
    /// Clean expired local firewall block records from Mace
    Gc,
    /// List nftables and CloudNode blacklist entries
    List {
        /// Aggregate exact IP rows when total entries exceed this threshold
        #[arg(long, default_value_t = 200)]
        aggregate_threshold: usize,

        /// Always print exact IP rows instead of /24 and /48 aggregation
        #[arg(long)]
        no_aggregate: bool,
    },
}

#[derive(Subcommand)]
enum DefenseCommands {
    /// Print current L4 defense, SYN pressure and active connection state
    Status,
    /// Inspect or request SYNPROXY mode
    Synproxy {
        #[command(subcommand)]
        mode: SynproxyCommands,
    },
}

#[derive(Subcommand)]
enum SynproxyCommands {
    /// Show SYNPROXY runtime status
    Status,
    /// Request SYNPROXY enable
    Enable,
    /// Request SYNPROXY disable
    Disable,
}

#[derive(Subcommand)]
enum XdpCommands {
    /// Print current or last persisted XDP state
    Status,
    /// Validate local XDP runtime configuration and object availability
    Doctor,
    /// Start automatic XDP proxy takeover
    #[command(alias = "attach")]
    Start {
        /// Restrict automatic XDP configuration to this interface. Repeat for multiple interfaces.
        #[arg(long = "interface", action = clap::ArgAction::Append)]
        interfaces: Vec<String>,
        /// Runtime mode for selected interfaces.
        #[arg(long, value_enum)]
        mode: Option<XdpCliRuntimeMode>,
        /// XDP attach mode.
        #[arg(long = "attach-mode", value_enum)]
        attach_mode: Option<XdpCliAttachMode>,
        /// XDP fallback mode.
        #[arg(long, value_enum)]
        fallback: Option<XdpCliFallbackMode>,
        /// Show generated config and tuning plan without writing config or attaching.
        #[arg(long)]
        dry_run: bool,
        /// Skip automatic netdev tuning.
        #[arg(long)]
        no_tune: bool,
        /// Do not install missing helper tools such as ethtool.
        #[arg(long)]
        no_install_tools: bool,
    },
    /// Stop XDP automatic takeover
    #[command(alias = "detach")]
    Stop,
    /// Inspect or apply XDP netdev tuning
    Tune {
        /// Restrict tuning to this interface. Repeat for multiple interfaces.
        #[arg(long = "interface", action = clap::ArgAction::Append)]
        interfaces: Vec<String>,
        /// Apply tuning instead of only showing the plan.
        #[arg(long)]
        apply: bool,
        /// Do not install missing helper tools such as ethtool.
        #[arg(long)]
        no_install_tools: bool,
    },
    /// Dump XDP shadow maps known to this process
    #[command(name = "dump-maps")]
    DumpMaps,
    /// Detach and attach again using configs/runtime.yaml
    Reload,
    /// Attach and poll raw AF_XDP frames for a short Linux dataplane smoke test
    #[command(name = "raw-smoke")]
    RawSmoke {
        /// Poll duration in milliseconds
        #[arg(long, default_value_t = 3000)]
        duration_ms: u64,
        /// Write this file after AF_XDP attach and XSK setup are ready
        #[arg(long)]
        ready_file: Option<PathBuf>,
    },
    /// Attach AF_XDP and verify HTTP/TCP/UDP proxy paths with local backends
    #[command(name = "proxy-smoke")]
    ProxySmoke {
        /// Poll duration in milliseconds
        #[arg(long, default_value_t = 8000)]
        duration_ms: u64,
        /// Write this file after AF_XDP proxy redirect is ready
        #[arg(long)]
        ready_file: Option<PathBuf>,
    },
    /// Verify an in-process XDP reload while AF_XDP proxy bridge is active
    #[command(name = "proxy-reload-smoke")]
    ProxyReloadSmoke {
        /// Poll duration in milliseconds after the replacement bridge is ready
        #[arg(long, default_value_t = 3000)]
        duration_ms: u64,
        /// Write this file after AF_XDP proxy redirect is ready after reload
        #[arg(long)]
        ready_file: Option<PathBuf>,
    },

    /// Interactive XDP configuration wizard / XDP 交互式配置向导
    #[command(name = "configure")]
    Configure,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum XdpCliRuntimeMode {
    Observe,
    Protect,
    Proxy,
}

impl From<XdpCliRuntimeMode> for XdpRuntimeMode {
    fn from(value: XdpCliRuntimeMode) -> Self {
        match value {
            XdpCliRuntimeMode::Observe => Self::Observe,
            XdpCliRuntimeMode::Protect => Self::Protect,
            XdpCliRuntimeMode::Proxy => Self::Proxy,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum XdpCliAttachMode {
    Auto,
    Drv,
    Skb,
}

impl From<XdpCliAttachMode> for XdpAttachMode {
    fn from(value: XdpCliAttachMode) -> Self {
        match value {
            XdpCliAttachMode::Auto => Self::Auto,
            XdpCliAttachMode::Drv => Self::Drv,
            XdpCliAttachMode::Skb => Self::Skb,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum XdpCliFallbackMode {
    Pass,
    FailStart,
}

impl From<XdpCliFallbackMode> for XdpFallbackMode {
    fn from(value: XdpCliFallbackMode) -> Self {
        match value {
            XdpCliFallbackMode::Pass => Self::Pass,
            XdpCliFallbackMode::FailStart => Self::FailStart,
        }
    }
}
fn spawn_staggered<F>(rt: &tokio::runtime::Runtime, delay: Duration, task: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    rt.spawn(async move {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        task.await;
    });
}

fn spawn_xdp_port_sync_task(rt: &tokio::runtime::Runtime, enabled: bool) {
    if !enabled {
        return;
    }
    #[cfg(target_os = "linux")]
    spawn_staggered(rt, Duration::from_secs(30), async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut consecutive_errors = 0u64;
        loop {
            interval.tick().await;
            match sync_xdp_proxy_ports_once().await {
                Ok(Some((old_count, new_count))) => {
                    consecutive_errors = 0;
                    let message = format!(
                        "xdp.proxy.ports synchronized from live node config old_count={old_count} new_count={new_count}"
                    );
                    info!("{message}");
                    logging::report_node_log(
                        "info".to_string(),
                        "xdp_ports".to_string(),
                        message,
                        0,
                    );
                }
                Ok(None) => {
                    consecutive_errors = 0;
                }
                Err(err) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    let message = format!(
                        "xdp.proxy.ports sync failed consecutive={} reason={}",
                        consecutive_errors, err
                    );
                    warn!("{message}");
                    if consecutive_errors == 1 || consecutive_errors % 10 == 0 {
                        logging::report_node_log(
                            "warn".to_string(),
                            "xdp_ports".to_string(),
                            message,
                            0,
                        );
                    }
                }
            }
        }
    });

    #[cfg(not(target_os = "linux"))]
    {
        let _ = rt;
    }
}

#[cfg(target_os = "linux")]
async fn sync_xdp_proxy_ports_once() -> anyhow::Result<Option<(usize, usize)>> {
    let Some(mut runtime_config) = RuntimeConfig::current() else {
        return Ok(None);
    };
    if !runtime_config.xdp.enabled {
        return Ok(None);
    }

    let payload = kernel_syn_defense::fetch_live_node_config_payload()
        .await
        .context("failed to fetch live node config for XDP proxy port sync")?;
    let ports = cloud_node_rust::xdp_auto_config::xdp_proxy_ports_from_servers(&payload.servers);
    if ports == runtime_config.xdp.proxy.ports {
        return Ok(None);
    }

    let old_count = runtime_config.xdp.proxy.ports.len();
    let new_count = ports.len();
    runtime_config.xdp.proxy.ports = ports;
    runtime_config.validate()?;
    let runtime_path = cloud_node_rust::paths::NodePaths::current().runtime_config_file();
    save_xdp_config(&runtime_path, &runtime_config.xdp)
        .with_context(|| format!("failed to save {}", runtime_path.display()))?;
    RuntimeConfig::set_current(runtime_config);
    cloud_node_rust::xdp::reload_from_runtime()
        .await
        .context("failed to reload XDP after proxy port sync")?;
    Ok(Some((old_count, new_count)))
}

fn build_time_display() -> String {
    option_env!("CLOUD_NODE_BUILD_TIMESTAMP")
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|timestamp| Local.timestamp_opt(timestamp, 0).single())
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S %z").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn interactive_available() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn prompt_yes_no(prompt: &str, default: bool) -> anyhow::Result<bool> {
    if !interactive_available() {
        anyhow::bail!(
            "interactive confirmation is unavailable; pass --yes for non-interactive use"
        );
    }

    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    print!("{prompt} {suffix} ");
    use io::Write as _;
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let answer = input.trim();
    if answer.is_empty() {
        return Ok(default);
    }
    Ok(matches!(
        answer,
        "y" | "Y" | "yes" | "YES" | "Yes" | "是" | "好" | "确认" | "启用" | "开启"
    ))
}

fn prompt_text(prompt: &str, default: &str) -> anyhow::Result<String> {
    if !interactive_available() {
        anyhow::bail!("interactive input is unavailable");
    }

    print!("{prompt} [{default}]: ");
    use io::Write as _;
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let value = input.trim();
    if value.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(value.to_string())
    }
}

fn prompt_ntp_timezone() -> anyhow::Result<Option<String>> {
    if !interactive_available() {
        return Ok(None);
    }

    let current = cloud_node_rust::utils::ntp::detect_system_timezone()
        .unwrap_or_else(|| "Asia/Shanghai".to_string());
    println!("{}", t("ntp.title"));
    println!("  {}: {}", t("ntp.current_timezone"), current);
    println!("  {}", t("ntp.keep_timezone"));
    let timezone = prompt_text(t("ntp.timezone_prompt"), &current)?;
    if timezone == current {
        Ok(None)
    } else {
        Ok(Some(timezone))
    }
}

fn api_config_existing_path() -> anyhow::Result<PathBuf> {
    let paths = ApiConfig::default_paths();
    paths
        .into_iter()
        .find(|path| path.exists())
        .ok_or_else(|| anyhow::anyhow!("no config file found in default paths"))
}

fn yaml_string_key(key: &str) -> serde_yaml::Value {
    serde_yaml::Value::String(key.to_string())
}

fn set_yaml_bool(mapping: &mut serde_yaml::Mapping, key: &str, value: bool) {
    mapping.insert(yaml_string_key(key), serde_yaml::Value::Bool(value));
}

fn write_relay_config(path: &Path, zero_copy: bool) -> anyhow::Result<()> {
    let content = fs::read_to_string(path)?;
    let mut value: serde_yaml::Value = serde_yaml::from_str(&content)?;
    let root = value
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a YAML mapping", path.display()))?;

    let relay_key = yaml_string_key("relay");
    if !root.contains_key(&relay_key) {
        root.insert(
            relay_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    let relay = root
        .get_mut(&relay_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .ok_or_else(|| anyhow::anyhow!("relay in {} is not a YAML mapping", path.display()))?;
    set_yaml_bool(relay, "zeroCopy", zero_copy);

    fs::write(path, serde_yaml::to_string(&value)?)?;
    let _ = ApiConfig::load(path)?;
    Ok(())
}

fn run_zerocopy_command(enable: bool, disable: bool, yes: bool) -> anyhow::Result<()> {
    if enable && disable {
        anyhow::bail!("--enable and --disable cannot be used together");
    }

    let path = api_config_existing_path()?;
    let config = ApiConfig::load(&path)?;
    let current = config.relay.normalized();
    println!("{}", t("zerocopy.title"));
    println!(
        "  {:<18} {}",
        format!("{}:", t("zerocopy.config")),
        path.display()
    );
    println!(
        "  {:<18} {}",
        format!("{}:", t("zerocopy.current")),
        if current.zero_copy {
            t("common.enabled")
        } else {
            t("common.disabled")
        }
    );
    println!(
        "  {:<18} auto (current {} bytes)",
        format!("{}:", t("zerocopy.copy_buffer")),
        cloud_node_rust::memory_governor::MEMORY_GOVERNOR.relay_copy_buffer_bytes()
    );

    let requested_zero_copy = if enable {
        Some(true)
    } else if disable {
        Some(false)
    } else if interactive_available() {
        Some(prompt_yes_no(
            "Enable Linux splice zero-copy for TCP/SNI relay?",
            current.zero_copy,
        )?)
    } else {
        None
    };

    let Some(zero_copy) = requested_zero_copy else {
        println!("{}", t("zerocopy.no_change"));
        return Ok(());
    };

    println!(
        "  {:<18} {}",
        format!("{}:", t("zerocopy.new")),
        if zero_copy {
            t("common.enabled")
        } else {
            t("common.disabled")
        }
    );
    println!("  {:<18} auto", format!("{}:", t("zerocopy.copy_buffer")));

    if !yes && (enable || disable) && !prompt_yes_no(t("zerocopy.confirm_write"), true)? {
        anyhow::bail!("zero-copy configuration aborted");
    }

    write_relay_config(&path, zero_copy)?;
    println!("{}", t("zerocopy.updated"));
    println!("{}", t("zerocopy.restart"));
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct FirewallListFlags {
    nf_blocked: bool,
    blacklist: bool,
}

#[derive(Clone, Debug, Default)]
struct FirewallAggregate {
    total: usize,
    nf_blocked: usize,
    blacklist: usize,
    both: usize,
}

fn run_firewall_command(command: FirewallCommands) -> anyhow::Result<()> {
    match command {
        FirewallCommands::Init => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cloud_node_rust::firewall::kernel::ensure_nftables())?;
            println!("{}", t("firewall.initialized"));
        }
        FirewallCommands::Gc => {
            let now = cloud_node_rust::utils::time::now_timestamp();
            let removed = cloud_node_rust::firewall::persistence::cleanup_expired(now);
            let _ = cloud_node_rust::firewall::persistence::flush_pending();
            println!("{}: {}", t("firewall.gc_removed"), removed);
        }
        FirewallCommands::List {
            aggregate_threshold,
            no_aggregate,
        } => run_firewall_list(aggregate_threshold, no_aggregate)?,
    }
    Ok(())
}

fn run_defense_command(command: DefenseCommands) -> anyhow::Result<()> {
    match command {
        DefenseCommands::Status => {
            print_defense_status();
        }
        DefenseCommands::Synproxy { mode } => {
            let mode = match mode {
                SynproxyCommands::Status => kernel_syn_defense::SynproxyMode::Status,
                SynproxyCommands::Enable => kernel_syn_defense::SynproxyMode::Enable,
                SynproxyCommands::Disable => kernel_syn_defense::SynproxyMode::Disable,
            };
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            println!(
                "{}",
                rt.block_on(kernel_syn_defense::synproxy_command(mode))?
            );
        }
    }
    Ok(())
}

fn run_xdp_command(command: XdpCommands) -> anyhow::Result<()> {
    match command {
        XdpCommands::Status => {
            print_xdp_status();
        }
        XdpCommands::Doctor => {
            let mut runtime_config = RuntimeConfig::load_default()?;
            let mut auto_error = None;
            if runtime_config.xdp.enabled && runtime_config.xdp.interfaces.is_empty() {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                match rt.block_on(
                    cloud_node_rust::xdp_auto_config::derive_xdp_config_from_live_node(
                        &runtime_config,
                    ),
                ) {
                    Ok(xdp) => runtime_config.xdp = xdp,
                    Err(err) => auto_error = Some(err.to_string()),
                }
            }
            RuntimeConfig::set_current(runtime_config);
            println!("{}", cloud_node_rust::xdp::doctor_report());
            if let Some(err) = auto_error {
                println!("  auto derive:   failed: {err}");
            }
        }
        XdpCommands::Start {
            interfaces,
            mode,
            attach_mode,
            fallback,
            dry_run,
            no_tune,
            no_install_tools,
        } => {
            let mut runtime_config = RuntimeConfig::load_default()?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let effective_xdp = rt.block_on(
                cloud_node_rust::xdp_auto_config::derive_xdp_config_from_live_node_with_options(
                    &runtime_config,
                    cloud_node_rust::xdp_auto_config::XdpAutoConfigOptions {
                        interfaces,
                        mode: mode.map(Into::into).unwrap_or(XdpRuntimeMode::Proxy),
                        attach_mode: attach_mode.map(Into::into).unwrap_or(XdpAttachMode::Auto),
                        fallback: fallback
                            .map(Into::into)
                            .unwrap_or(XdpFallbackMode::FailStart),
                    },
                ),
            )?;
            runtime_config.xdp = effective_xdp;
            runtime_config.validate()?;
            if !no_tune {
                let report = cloud_node_rust::xdp_netdev_tuning::apply_for_xdp_config(
                    &runtime_config.xdp,
                    cloud_node_rust::xdp_netdev_tuning::XdpNetdevTuneOptions {
                        dry_run,
                        install_tools: !no_install_tools,
                        report_node_log: true,
                        persist_report: !dry_run,
                    },
                )?;
                cloud_node_rust::xdp_netdev_tuning::print_report(&report);
            }
            if !dry_run {
                cloud_node_rust::xdp_auto_config::refresh_xdp_interface_queues(
                    &mut runtime_config.xdp,
                );
                runtime_config.validate()?;
            }
            if dry_run {
                println!(
                    "{}",
                    serde_yaml::to_string(&runtime_config.xdp)
                        .unwrap_or_else(|err| format!("failed to render XDP config: {err}"))
                );
                return Ok(());
            }
            let runtime_path = cloud_node_rust::paths::NodePaths::current().runtime_config_file();
            save_xdp_config(&runtime_path, &runtime_config.xdp)?;
            #[cfg(target_os = "linux")]
            if !is_systemd_invocation() && systemd_service_is_active() {
                run_systemctl("restart")?;
                std::thread::sleep(Duration::from_secs(3));
                if let Some(status) = cloud_node_rust::xdp::persisted_status_snapshot() {
                    print_xdp_status_snapshot(status);
                } else {
                    println!("XDP config saved; cloud-node.service restarted.");
                }
                return Ok(());
            }
            RuntimeConfig::set_current(runtime_config);
            rt.block_on(cloud_node_rust::xdp::attach_from_runtime())?;
            print_xdp_status();
        }
        XdpCommands::Stop => {
            let mut runtime_config = RuntimeConfig::load_default()?;
            RuntimeConfig::set_current(runtime_config.clone());
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cloud_node_rust::xdp::detach())?;
            runtime_config.xdp.enabled = false;
            let runtime_path = cloud_node_rust::paths::NodePaths::current().runtime_config_file();
            save_xdp_config(&runtime_path, &runtime_config.xdp)?;
            RuntimeConfig::set_current(runtime_config);
            print_xdp_status();
        }
        XdpCommands::Tune {
            interfaces,
            apply,
            no_install_tools,
        } => {
            let runtime_config = RuntimeConfig::load_default()?;
            let interface_names = if interfaces.is_empty() {
                if runtime_config.xdp.interfaces.is_empty() {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    rt.block_on(
                        cloud_node_rust::xdp_auto_config::derive_xdp_config_from_live_node(
                            &runtime_config,
                        ),
                    )?
                    .interfaces
                    .into_iter()
                    .map(|interface| interface.name)
                    .collect::<Vec<_>>()
                } else {
                    runtime_config
                        .xdp
                        .interfaces
                        .iter()
                        .map(|interface| interface.name.clone())
                        .collect::<Vec<_>>()
                }
            } else {
                interfaces
            };
            let report = cloud_node_rust::xdp_netdev_tuning::apply_for_interfaces(
                &interface_names,
                runtime_config.xdp.fallback,
                cloud_node_rust::xdp_netdev_tuning::XdpNetdevTuneOptions {
                    dry_run: !apply,
                    install_tools: apply && !no_install_tools,
                    report_node_log: true,
                    persist_report: apply,
                },
            )?;
            cloud_node_rust::xdp_netdev_tuning::print_report(&report);
        }
        XdpCommands::DumpMaps => {
            let runtime_config = RuntimeConfig::load_default()?;
            RuntimeConfig::set_current(runtime_config);
            println!(
                "{}",
                serde_json::to_string_pretty(&cloud_node_rust::xdp::dump_maps())?
            );
        }
        XdpCommands::Reload => {
            let runtime_config = RuntimeConfig::load_default()?;
            RuntimeConfig::set_current(runtime_config);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(cloud_node_rust::xdp::reload_from_runtime())?;
            print_xdp_status();
        }
        XdpCommands::RawSmoke {
            duration_ms,
            ready_file,
        } => {
            let runtime_config = RuntimeConfig::load_default()?;
            RuntimeConfig::set_current(runtime_config);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let duration = Duration::from_millis(duration_ms.max(1));
            let report = rt.block_on(cloud_node_rust::xdp::raw_smoke(duration, ready_file))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        XdpCommands::ProxySmoke {
            duration_ms,
            ready_file,
        } => {
            let runtime_config = RuntimeConfig::load_default()?;
            RuntimeConfig::set_current(runtime_config);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let duration = Duration::from_millis(duration_ms.max(1));
            let report = rt.block_on(cloud_node_rust::xdp::proxy_smoke(duration, ready_file))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        XdpCommands::ProxyReloadSmoke {
            duration_ms,
            ready_file,
        } => {
            let runtime_config = RuntimeConfig::load_default()?;
            RuntimeConfig::set_current(runtime_config);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let duration = Duration::from_millis(duration_ms.max(1));
            let report = rt.block_on(cloud_node_rust::xdp::proxy_reload_smoke(
                duration, ready_file,
            ))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        XdpCommands::Configure => {
            let _ = XdpConfigWizard::run_interactive()?;
        }
    }
    Ok(())
}

fn print_xdp_status() {
    let status = if RuntimeConfig::current().is_some() {
        cloud_node_rust::xdp::status_snapshot()
    } else {
        cloud_node_rust::xdp::persisted_status_snapshot()
            .unwrap_or_else(cloud_node_rust::xdp::status_snapshot)
    };
    print_xdp_status_snapshot(status);
}

fn print_xdp_status_snapshot(status: cloud_node_rust::xdp::XdpStatusSnapshot) {
    println!("{}", t("xdp.status.title"));
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.enabled")),
        xdp_yes_no(status.enabled)
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.available")),
        xdp_yes_no(status.available)
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.attached")),
        xdp_yes_no(status.attached)
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.attach_mode")),
        status.attach_mode
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.fallback")),
        status.fallback
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.fallback_why")),
        if status.fallback_reason.is_empty() {
            "-"
        } else {
            &status.fallback_reason
        }
    );
    println!(
        "  {:<14} {} {}={} {}={}",
        format!("{}:", t("xdp.status.proxy_ports")),
        status.proxy_ports,
        t("xdp.status.supported"),
        status.proxy_supported_ports,
        t("xdp.status.unsupported"),
        status.proxy_unsupported_ports
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.proxy_ready")),
        xdp_yes_no(status.proxy_ready)
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.redirect")),
        xdp_yes_no(status.proxy_redirect_enabled)
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.tcp_dataplane")),
        xdp_yes_no(status.tcp_dataplane_ready)
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.tcp_why")),
        if status.tcp_dataplane_detail.is_empty() {
            "-"
        } else {
            &status.tcp_dataplane_detail
        }
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.proxy_why")),
        if status.proxy_fallback_reason.is_empty() {
            "-"
        } else {
            &status.proxy_fallback_reason
        }
    );
    println!(
        "  {:<14} configured={} ready={}",
        format!("{}:", t("xdp.status.xsk_queues")),
        status.xsk_configured_queues,
        status.xsk_ready_queues
    );
    println!(
        "  {:<14} {}",
        format!("{}:", t("xdp.status.ebpf_object")),
        status.ebpf_object
    );
    println!(
        "  {:<14} block_v4={} block_v6={} allow_v4={} allow_v6={} block_nets={} allow_nets={} block_ranges={} allow_ranges={}",
        format!("{}:", t("xdp.status.maps")),
        status.exact_blocked_v4,
        status.exact_blocked_v6,
        status.exact_allowed_v4,
        status.exact_allowed_v6,
        status.blocked_networks,
        status.allowed_networks,
        status.blocked_ranges,
        status.allowed_ranges
    );
    println!(
        "  {:<14} packets={} pass={} drop={} redirect={} parse_errors={} map_miss={} xsk_drops={}",
        format!("{}:", t("xdp.status.counters")),
        status.packets,
        status.pass,
        status.drop,
        status.redirect,
        status.parse_errors,
        status.map_miss,
        status.xsk_drops
    );
    if status.interfaces.is_empty() {
        println!("  {:<14} -", format!("{}:", t("xdp.status.interfaces")));
    } else {
        for interface in status.interfaces {
            println!(
                "  {:<14} {} mode={} queues={:?} attached={} xsk_ready={} frameSize={} detail={}",
                format!("{}:", t("xdp.status.interface")),
                interface.name,
                interface.mode,
                interface.queues,
                xdp_yes_no(interface.attached),
                xdp_yes_no(interface.xsk_ready),
                interface.frame_size,
                interface.detail
            );
            for queue in interface.xsk_queues {
                println!(
                    "    {:<12} {}:{} configured={} socket={} registered={} ready={} detail={}",
                    format!("{}:", t("xdp.status.xsk_queue")),
                    queue.interface,
                    queue.queue,
                    xdp_yes_no(queue.configured),
                    xdp_yes_no(queue.socket_created),
                    xdp_yes_no(queue.registered),
                    xdp_yes_no(queue.ready),
                    queue.detail
                );
            }
        }
    }
    for line in cloud_node_rust::xdp_netdev_tuning::status_lines() {
        println!("{line}");
    }
}

fn xdp_yes_no(value: bool) -> &'static str {
    if value {
        t("common.yes")
    } else {
        t("common.no")
    }
}

fn print_defense_status() {
    let syn = kernel_syn_defense::snapshot();
    let active = l4_connection_registry::snapshot();
    let metrics = cloud_node_rust::l4_defense::metrics_snapshot();
    let pressure = cloud_node_rust::l4_defense::current_pressure_level();

    println!("{}", t("defense.title"));
    println!(
        "  {:<20} {}",
        format!("{}:", t("defense.runtime_scope")),
        t("defense.current_snapshot")
    );
    println!(
        "  {:<20} {}",
        format!("{}:", t("defense.effective_pressure")),
        pressure.as_str()
    );
    println!(
        "  syn pressure:       level={} listen_overflows={} listen_drops={} syncookies={} req_q_full_do_cookies={} req_q_full_drop={}",
        syn.pressure_level.as_str(),
        syn.listen_overflows_delta,
        syn.listen_drops_delta,
        syn.syncookies_sent_delta,
        syn.req_q_full_do_cookies_delta,
        syn.req_q_full_drop_delta
    );
    if let Ok(counters) = kernel_syn_defense::read_tcp_ext_counters() {
        println!(
            "  syn counters:       listen_overflows={} listen_drops={} syncookies={} req_q_full_do_cookies={} req_q_full_drop={}",
            counters.listen_overflows,
            counters.listen_drops,
            counters.syncookies_sent,
            counters.req_q_full_do_cookies,
            counters.req_q_full_drop
        );
    }
    println!(
        "  active connections: total={} http1={} http2={} sni_tcp={}",
        active.total, active.http1, active.http2, active.sni_tcp
    );
    println!(
        "  events:             total={} allowed={} blocked={} already_blocked={} disabled={}",
        metrics.events_total,
        metrics.allowed_total,
        metrics.blocked_total,
        metrics.already_blocked_total,
        metrics.disabled_total
    );
    println!(
        "  categories:         active_limit={} admission_reject={} slow_close={} completed_handshake={} tls_probe={} h2={} syn={} quic={}",
        metrics.active_limit_total,
        metrics.admission_reject_total,
        metrics.slow_close_total,
        metrics.completed_handshake_total,
        metrics.tls_probe_total,
        metrics.h2_defense_total,
        metrics.syn_pressure_total,
        metrics.quic_pressure_total
    );
    println!(
        "  aggregate:          distinct_ips_recent={} prefix_pressure={} top_prefix={} top_prefix_events={} prefix_blocked={} aggregate_drop={} exact_counter_saturated={}",
        metrics.distinct_ips_recent,
        metrics.prefix_pressure_level.as_str(),
        if metrics.top_prefix.is_empty() {
            "-"
        } else {
            &metrics.top_prefix
        },
        metrics.top_prefix_events,
        metrics.prefix_blocked_total,
        metrics.aggregate_drop_total,
        metrics.exact_counter_saturated_total
    );
    println!(
        "  top event kind:     {}",
        if metrics.top_event_kind.is_empty() {
            "-"
        } else {
            metrics.top_event_kind
        }
    );
}

fn run_firewall_list(aggregate_threshold: usize, no_aggregate: bool) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let nf_ips = rt.block_on(cloud_node_rust::firewall::kernel::nftables_blocked_ips())?;
    let nf_ips = nf_ips.into_iter().collect::<BTreeSet<_>>();
    let expired_cleaned = cloud_node_rust::firewall::persistence::cleanup_expired(
        cloud_node_rust::utils::time::now_timestamp(),
    );
    let (black_ips, black_targets) = load_blacklist_snapshot();

    let mut exact = BTreeMap::<IpAddr, FirewallListFlags>::new();
    for ip in &nf_ips {
        exact.entry(*ip).or_default().nf_blocked = true;
    }
    for ip in &black_ips {
        exact.entry(*ip).or_default().blacklist = true;
    }

    println!("{}", t("firewall.title"));
    println!("  {}: {}", t("firewall.nft_exact"), nf_ips.len());
    println!("  {}: {}", t("firewall.blacklist_exact"), black_ips.len());
    println!(
        "  {}: {}",
        t("firewall.blacklist_targets"),
        black_targets.len()
    );
    println!("  {}: {}", t("firewall.expired_cleaned"), expired_cleaned);
    println!();

    let aggregate = !no_aggregate && exact.len() > aggregate_threshold.max(1);
    if aggregate {
        print_firewall_aggregates(&exact);
    } else {
        print_firewall_exact_rows(&exact);
    }

    if !black_targets.is_empty() {
        println!();
        println!("{}", t("firewall.targets_header"));
        for target in black_targets {
            println!("{}\tnftables=-\tblacklist={}", target, yes_no(true));
        }
    }

    Ok(())
}

fn load_blacklist_snapshot() -> (BTreeSet<IpAddr>, Vec<String>) {
    let now = cloud_node_rust::utils::time::now_timestamp();
    let mut ips = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for record in cloud_node_rust::firewall::persistence::load_active_blacklist_records(now) {
        if let Ok(ip) = record.target.parse::<IpAddr>() {
            ips.insert(ip);
        } else {
            targets.insert(record.target);
        }
    }
    (ips, targets.into_iter().collect())
}

fn print_firewall_exact_rows(exact: &BTreeMap<IpAddr, FirewallListFlags>) {
    let mut printed = false;
    for (label, is_v4) in [("IPv4", true), ("IPv6", false)] {
        let rows = exact
            .iter()
            .filter(|(ip, _)| ip.is_ipv4() == is_v4)
            .collect::<Vec<_>>();
        if rows.is_empty() {
            continue;
        }
        printed = true;
        println!("{}", label);
        println!("{}", t("firewall.ip_header"));
        for (ip, flags) in rows {
            println!(
                "{}\t{}\t{}",
                ip,
                yes_no(flags.nf_blocked),
                yes_no(flags.blacklist)
            );
        }
        println!();
    }
    if !printed {
        println!("{}", t("firewall.no_entries"));
    }
}

fn print_firewall_aggregates(exact: &BTreeMap<IpAddr, FirewallListFlags>) {
    let mut v4 = BTreeMap::<Ipv4Addr, FirewallAggregate>::new();
    let mut v6 = BTreeMap::<Ipv6Addr, FirewallAggregate>::new();

    for (ip, flags) in exact {
        match ip {
            IpAddr::V4(ip) => record_firewall_aggregate(v4.entry(v4_24(*ip)).or_default(), *flags),
            IpAddr::V6(ip) => record_firewall_aggregate(v6.entry(v6_48(*ip)).or_default(), *flags),
        }
    }

    if !v4.is_empty() {
        println!("{}", t("firewall.v4_aggregates"));
        println!("{}", t("firewall.aggregate_header"));
        for (network, stats) in v4 {
            println!(
                "{}/24\t{}\t{}\t{}\t{}",
                network, stats.total, stats.nf_blocked, stats.blacklist, stats.both
            );
        }
        println!();
    }

    if !v6.is_empty() {
        println!("{}", t("firewall.v6_aggregates"));
        println!("{}", t("firewall.aggregate_header"));
        for (network, stats) in v6 {
            println!(
                "{}/48\t{}\t{}\t{}\t{}",
                network, stats.total, stats.nf_blocked, stats.blacklist, stats.both
            );
        }
    }
}

fn record_firewall_aggregate(stats: &mut FirewallAggregate, flags: FirewallListFlags) {
    stats.total += 1;
    if flags.nf_blocked {
        stats.nf_blocked += 1;
    }
    if flags.blacklist {
        stats.blacklist += 1;
    }
    if flags.nf_blocked && flags.blacklist {
        stats.both += 1;
    }
}

fn v4_24(ip: Ipv4Addr) -> Ipv4Addr {
    let mut octets = ip.octets();
    octets[3] = 0;
    Ipv4Addr::from(octets)
}

fn v6_48(ip: Ipv6Addr) -> Ipv6Addr {
    let mut segments = ip.segments();
    segments[3..].fill(0);
    Ipv6Addr::from(segments)
}

fn yes_no(value: bool) -> &'static str {
    if value {
        t("common.yes")
    } else {
        t("common.no")
    }
}

fn run_ntp_command(
    timezone: Option<String>,
    no_timezone: bool,
    yes: bool,
    servers: Vec<String>,
    timeout_ms: u64,
) -> anyhow::Result<()> {
    let timezone = if no_timezone {
        None
    } else if timezone.is_some() {
        timezone
    } else if yes {
        None
    } else {
        prompt_ntp_timezone()?
    };

    if let Some(timezone) = timezone {
        cloud_node_rust::utils::ntp::set_system_timezone(&timezone)?;
        println!("{} {}", t("ntp.timezone_set"), timezone);
    }
    cloud_node_rust::utils::time::init_local_timezone();

    let servers = if servers.is_empty() {
        cloud_node_rust::utils::ntp::default_servers_as_strings()
    } else {
        servers
    };
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(cloud_node_rust::utils::ntp::sync_once(&servers, timeout))?;
    let adjusted_millis =
        cloud_node_rust::utils::ntp::apply_system_clock_offset(result.offset_millis)?;
    println!("{}", result.system_clock_log_message(adjusted_millis));
    Ok(())
}

#[derive(Clone, Debug)]
struct RunningInstance {
    pid: u32,
    pid_path: PathBuf,
}

fn process_exists(pid: u32) -> bool {
    let exists = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
    exists || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(any(target_os = "linux", test))]
fn process_basename(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    Some(name.strip_suffix(" (deleted)").unwrap_or(&name).to_string())
}

#[cfg(any(target_os = "linux", test))]
fn first_cmdline_arg_basename(cmdline: &[u8]) -> Option<String> {
    let arg0 = cmdline
        .split(|byte| *byte == 0)
        .find(|arg| !arg.is_empty())?;
    let arg0 = String::from_utf8_lossy(arg0);
    process_basename(Path::new(arg0.as_ref()))
}

#[cfg(any(target_os = "linux", test))]
fn cmdline_contains_management_command(cmdline: &[u8]) -> bool {
    cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .skip(1)
        .filter_map(|arg| std::str::from_utf8(arg).ok())
        .any(|arg| {
            matches!(
                arg,
                "stop"
                    | "status"
                    | "restart"
                    | "install"
                    | "test"
                    | "ntp"
                    | "zerocopy"
                    | "zero-copy"
                    | "firewall"
                    | "defense"
                    | "xdp"
            )
        })
}

#[cfg(any(target_os = "linux", test))]
fn is_cloud_node_binary_name(name: &str) -> bool {
    matches!(name, "cloud-node-rust" | "cloud-node")
}

#[cfg(target_os = "linux")]
fn is_cloud_node_process(pid: u32) -> bool {
    if let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) {
        if !process_basename(&exe)
            .as_deref()
            .is_some_and(is_cloud_node_binary_name)
        {
            return false;
        }
        return fs::read(format!("/proc/{pid}/cmdline"))
            .map(|cmdline| !cmdline_contains_management_command(&cmdline))
            .unwrap_or(true);
    }

    let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };

    first_cmdline_arg_basename(&cmdline)
        .as_deref()
        .is_some_and(is_cloud_node_binary_name)
        && !cmdline_contains_management_command(&cmdline)
}

#[cfg(not(target_os = "linux"))]
fn is_cloud_node_process(_pid: u32) -> bool {
    true
}

fn read_pid(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn find_cloud_node_process_by_cwd(pid_path: PathBuf) -> Option<RunningInstance> {
    let current_pid = std::process::id();
    let root =
        fs::canonicalize(cloud_node_rust::paths::NodePaths::current().runtime_root()).ok()?;

    for entry in fs::read_dir("/proc").ok()? {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if pid == current_pid || !process_exists(pid) || !is_cloud_node_process(pid) {
            continue;
        }

        let Ok(cwd) = fs::read_link(format!("/proc/{pid}/cwd")) else {
            continue;
        };
        if fs::canonicalize(cwd).ok().as_ref() == Some(&root) {
            return Some(RunningInstance { pid, pid_path });
        }
    }

    None
}

fn check_running() -> Option<RunningInstance> {
    use std::os::unix::io::AsRawFd;

    let node_paths = cloud_node_rust::paths::NodePaths::current();
    let mut pid_paths = node_paths.pid_file_candidates();

    for path in &pid_paths {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let fd = file.as_raw_fd();

        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if ret == 0 {
            unsafe { libc::flock(fd, libc::LOCK_UN) };
            if let Some(pid) = read_pid(path)
                && !process_exists(pid)
            {
                let _ = fs::remove_file(path);
            }
            continue;
        }

        let err = io::Error::last_os_error();
        if (err.raw_os_error() == Some(libc::EWOULDBLOCK)
            || err.raw_os_error() == Some(libc::EAGAIN))
            && let Some(pid) = read_pid(path)
        {
            if process_exists(pid) && is_cloud_node_process(pid) {
                return Some(RunningInstance {
                    pid,
                    pid_path: path.clone(),
                });
            }
            let _ = fs::remove_file(path);
        }
    }

    find_cloud_node_process_by_cwd(pid_paths.remove(0))
}

fn send_signal(pid: u32, signal: libc::c_int) -> io::Result<()> {
    if unsafe { libc::kill(pid as libc::pid_t, signal) } == 0 {
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(err)
        }
    }
}

fn wait_for_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_exists(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    !process_exists(pid)
}

fn stop_running_instance(instance: RunningInstance) -> anyhow::Result<()> {
    println!("{} (PID: {})...", t("stop.stopping"), instance.pid);
    send_signal(instance.pid, libc::SIGTERM)?;

    if !wait_for_exit(instance.pid, Duration::from_secs(20)) {
        eprintln!("{} (PID: {})...", t("stop.force"), instance.pid);
        send_signal(instance.pid, libc::SIGKILL)?;
        if !wait_for_exit(instance.pid, Duration::from_secs(5)) {
            anyhow::bail!(
                "CloudNode process {} did not exit after SIGKILL",
                instance.pid
            );
        }
    }

    if read_pid(&instance.pid_path) == Some(instance.pid) {
        let _ = fs::remove_file(&instance.pid_path);
    }
    println!("{}", t("stop.stopped"));
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_systemd_invocation() -> bool {
    std::env::var_os("INVOCATION_ID").is_some()
        || std::env::var_os("SYSTEMD_EXEC_PID").is_some()
        || std::env::var_os("JOURNAL_STREAM").is_some()
}

#[cfg(target_os = "linux")]
fn systemd_service_is_active() -> bool {
    Command::new("systemctl")
        .arg("is-active")
        .arg("--quiet")
        .arg("cloud-node.service")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn systemd_service_exists() -> bool {
    Command::new("systemctl")
        .arg("cat")
        .arg("cloud-node.service")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn run_systemctl(action: &str) -> anyhow::Result<bool> {
    if is_systemd_invocation() {
        return Ok(false);
    }

    let should_use_systemd = match action {
        "start" | "restart" => systemd_service_exists(),
        "stop" => systemd_service_is_active(),
        _ => systemd_service_exists(),
    };
    if !should_use_systemd {
        return Ok(false);
    }

    println!(
        "{}: systemctl {action} cloud-node.service",
        t("systemd.managed")
    );
    let status = Command::new("systemctl")
        .arg(action)
        .arg("cloud-node.service")
        .status()?;
    if !status.success() {
        anyhow::bail!("systemctl {action} cloud-node.service failed with {status}");
    }
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn run_systemctl(_action: &str) -> anyhow::Result<bool> {
    Ok(false)
}

#[derive(Debug)]
struct UpgradeOptions {
    version: String,
    repo: String,
    github_base_url: String,
    github_mirror: Option<String>,
    asset: Option<String>,
    install_binary: Option<PathBuf>,
    backup_dir: PathBuf,
    yes: bool,
    dry_run: bool,
    no_restart: bool,
}

const XDP_EBPF_OBJECT_NAME: &str = "cloud-node-xdp-ebpf.o";
#[cfg(target_os = "linux")]
const CLOUD_NODE_SYSTEMD_SERVICE: &str = "cloud-node.service";
#[cfg(target_os = "linux")]
const CLOUD_NODE_SYSTEMD_SERVICE_PATH: &str = "/etc/systemd/system/cloud-node.service";
const CLOUD_NODE_WRAPPER_PATH: &str = "/usr/bin/cloud-node";

#[derive(Debug)]
struct ExtractedReleasePayload {
    binary: PathBuf,
    xdp_ebpf_object: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
struct XdpObjectRepair {
    source: PathBuf,
    dest: PathBuf,
}

fn normalize_release_version(version: &str) -> String {
    let trimmed = version.trim();
    if trimmed.eq_ignore_ascii_case("latest") {
        "latest".to_string()
    } else if trimmed.starts_with('v') {
        trimmed.to_string()
    } else {
        format!("v{trimmed}")
    }
}

fn release_download_url(github_base_url: &str, repo: &str, version: &str, asset: &str) -> String {
    let base = github_base_url.trim_end_matches('/');
    if version == "latest" {
        format!("{base}/{repo}/releases/latest/download/{asset}")
    } else {
        format!("{base}/{repo}/releases/download/{version}/{asset}")
    }
}

fn apply_github_mirror(download_url: &str, github_mirror: Option<&str>) -> String {
    let Some(mirror) = github_mirror
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return download_url.to_string();
    };
    if mirror.contains("{url}") {
        return mirror.replace("{url}", download_url);
    }
    format!("{}/{}", mirror.trim_end_matches('/'), download_url)
}

fn cpuinfo_has_flag(cpuinfo: &str, flag: &str) -> bool {
    cpuinfo
        .split(|ch: char| ch.is_ascii_whitespace() || ch == ':')
        .any(|part| part == flag)
}

fn select_release_asset(
    arch: &str,
    cpuinfo: &str,
    glibc_older_than_228: bool,
) -> anyhow::Result<&'static str> {
    match arch {
        "x86_64" | "amd64" => {
            if glibc_older_than_228 {
                anyhow::bail!(
                    "x86_64 systems with glibc older than 2.28 are not supported by official release assets"
                );
            }
            if !cpuinfo_has_flag(cpuinfo, "sse4_2") {
                anyhow::bail!(
                    "x86_64 CPU without SSE4.2 is not supported by official release assets"
                );
            }
            if cpuinfo_has_flag(cpuinfo, "avx512f") {
                Ok("cloud-node-rust-linux-x64-v4-avx512.tar.gz")
            } else if cpuinfo_has_flag(cpuinfo, "avx2") {
                Ok("cloud-node-rust-linux-x64-v3-avx2.tar.gz")
            } else {
                Ok("cloud-node-rust-linux-x64-v2-sse4.2.tar.gz")
            }
        }
        "aarch64" | "arm64" => {
            if cpuinfo.to_ascii_lowercase().contains("neoverse-n1") {
                Ok("cloud-node-rust-linux-arm64-neoverse-n1.tar.gz")
            } else {
                Ok("cloud-node-rust-linux-arm64-generic.tar.gz")
            }
        }
        other => anyhow::bail!("unsupported architecture for official release assets: {other}"),
    }
}

#[cfg(target_os = "linux")]
fn glibc_is_older_than_228() -> bool {
    let Ok(output) = Command::new("ldd").arg("--version").output() else {
        return false;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let Some(first_line) = stdout.lines().next() else {
        return false;
    };
    let Some(version) = first_line.split_whitespace().find(|part| {
        part.chars().next().is_some_and(|ch| ch.is_ascii_digit()) && part.contains('.')
    }) else {
        return false;
    };
    let mut parts = version.split('.');
    let major = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(999);
    let minor = parts
        .next()
        .and_then(|value| {
            value
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>()
                .parse::<u32>()
                .ok()
        })
        .unwrap_or(999);
    major < 2 || (major == 2 && minor < 28)
}

#[cfg(not(target_os = "linux"))]
fn glibc_is_older_than_228() -> bool {
    false
}

fn detect_release_asset() -> anyhow::Result<&'static str> {
    let arch = std::env::consts::ARCH;
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    select_release_asset(arch, &cpuinfo, glibc_is_older_than_228())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

async fn download_to_file(url: &str, target: &Path) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(600))
        .user_agent(format!("cloud-node-rust/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut response = client.get(url).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("download failed with HTTP status {}", response.status());
    }

    let mut file = tokio::fs::File::create(target).await?;
    while let Some(chunk) = response.chunk().await? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    Ok(())
}

fn archive_path_parts(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn extract_release_payload(
    archive_path: &Path,
    target_dir: &Path,
) -> anyhow::Result<ExtractedReleasePayload> {
    let archive_file = fs::File::open(archive_path)?;
    let gz = flate2::read::GzDecoder::new(archive_file);
    let mut archive = tar::Archive::new(gz);
    let binary = target_dir.join("cloud-node");
    let xdp_ebpf_object = target_dir.join(XDP_EBPF_OBJECT_NAME);
    let mut found_binary = false;
    let mut found_xdp_ebpf_object = false;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let parts = archive_path_parts(&path);
        if parts == ["cloud-node"] {
            entry.unpack(&binary)?;
            if !binary.is_file() {
                anyhow::bail!("release archive cloud-node entry is not a regular file");
            }
            found_binary = true;
        } else if parts == ["data", XDP_EBPF_OBJECT_NAME] {
            entry.unpack(&xdp_ebpf_object)?;
            if !xdp_ebpf_object.is_file() {
                anyhow::bail!("release archive XDP eBPF object entry is not a regular file");
            }
            found_xdp_ebpf_object = true;
        }
    }

    if !found_binary {
        anyhow::bail!("release archive does not contain cloud-node");
    }

    Ok(ExtractedReleasePayload {
        binary,
        xdp_ebpf_object: found_xdp_ebpf_object.then_some(xdp_ebpf_object),
    })
}

fn prompt_upgrade_confirmation() -> anyhow::Result<bool> {
    prompt_yes_no(t("upgrade.proceed"), false)
}

fn backup_current_binary(
    install_binary: &Path,
    backup_dir: &Path,
    version: &str,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(backup_dir)?;
    let file_name = install_binary
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cloud-node");
    let backup_path = backup_dir.join(format!("{file_name}.{version}.{}.backup", unix_timestamp()));
    fs::copy(install_binary, &backup_path)?;
    Ok(backup_path)
}

fn replace_binary(source: &Path, install_binary: &Path) -> anyhow::Result<()> {
    let parent = install_binary
        .parent()
        .ok_or_else(|| anyhow::anyhow!("install binary has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let new_path = install_binary.with_extension("upgrade-new");
    fs::copy(source, &new_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&new_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&new_path, perms)?;
    }

    fs::rename(&new_path, install_binary)?;
    Ok(())
}

fn runtime_dir_candidate(path: &Path) -> bool {
    path != Path::new("/") && (path.join("configs").exists() || path.join("data").exists())
}

fn normalize_config_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let unquoted = if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0] as char;
        let last = trimmed.as_bytes()[trimmed.len() - 1] as char;
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            &trimmed[1..trimmed.len() - 1]
        } else {
            trimmed
        }
    } else {
        trimmed
    };
    let unquoted = unquoted.trim();
    (!unquoted.is_empty()).then(|| PathBuf::from(unquoted))
}

fn split_config_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(quote_char) = quote {
            if ch == quote_char {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }

    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        words.push(current);
    }

    words
}

fn service_env_cloud_node_home_from_text(service: &str) -> Option<PathBuf> {
    for line in service.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("Environment=") else {
            continue;
        };
        for word in split_config_words(rest) {
            if let Some(value) = word.strip_prefix("CLOUD_NODE_HOME=") {
                return normalize_config_path(value);
            }
        }
    }
    None
}

fn service_working_directory_from_text(service: &str) -> Option<PathBuf> {
    for line in service.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("WorkingDirectory=") else {
            continue;
        };
        if let Some(first_word) = split_config_words(rest).into_iter().next() {
            return normalize_config_path(&first_word);
        }
        return normalize_config_path(rest);
    }
    None
}

#[cfg(target_os = "linux")]
fn cloud_node_service_text() -> Option<String> {
    if let Ok(output) = Command::new("systemctl")
        .arg("cat")
        .arg(CLOUD_NODE_SYSTEMD_SERVICE)
        .output()
        && output.status.success()
        && !output.stdout.is_empty()
    {
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    fs::read_to_string(CLOUD_NODE_SYSTEMD_SERVICE_PATH).ok()
}

#[cfg(not(target_os = "linux"))]
fn cloud_node_service_text() -> Option<String> {
    None
}

fn parse_script_cd_workdir(script: &str) -> Option<PathBuf> {
    for line in script.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("cd") else {
            continue;
        };
        if !rest.chars().next().is_some_and(char::is_whitespace) {
            continue;
        }
        let mut value = rest.trim_start();
        if let Some((before, _)) = value.split_once("&&") {
            value = before;
        }
        if let Some((before, _)) = value.split_once(';') {
            value = before;
        }
        return normalize_config_path(value);
    }
    None
}

fn script_cd_workdir(path: &Path) -> Option<PathBuf> {
    let script = fs::read_to_string(path).ok()?;
    let dir = parse_script_cd_workdir(&script)?;
    if !dir.is_dir() {
        return None;
    }
    fs::canonicalize(&dir).ok().or(Some(dir))
}

fn runtime_root_from_inputs(
    cloud_node_home: Option<PathBuf>,
    service_env_home: Option<PathBuf>,
    service_workdir: Option<PathBuf>,
    wrapper_workdir: Option<PathBuf>,
    cwd: Option<PathBuf>,
    install_binary: &Path,
) -> anyhow::Result<PathBuf> {
    if let Some(root) = cloud_node_home {
        return Ok(root);
    }
    if let Some(root) = service_env_home {
        return Ok(root);
    }
    if let Some(root) = service_workdir {
        return Ok(root);
    }
    if let Some(root) = wrapper_workdir {
        return Ok(root);
    }
    if let Some(root) = cwd
        && runtime_dir_candidate(&root)
    {
        return Ok(root);
    }
    install_binary
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow::anyhow!("install binary has no parent directory"))
}

fn runtime_root_for_upgrade(install_binary: &Path) -> anyhow::Result<PathBuf> {
    let service_text = cloud_node_service_text();
    runtime_root_from_inputs(
        std::env::var_os("CLOUD_NODE_HOME").map(PathBuf::from),
        service_text
            .as_deref()
            .and_then(service_env_cloud_node_home_from_text),
        service_text
            .as_deref()
            .and_then(service_working_directory_from_text),
        script_cd_workdir(Path::new(CLOUD_NODE_WRAPPER_PATH)),
        std::env::current_dir().ok(),
        install_binary,
    )
}

fn install_xdp_ebpf_object_to_runtime(
    source: &Path,
    runtime_root: &Path,
) -> anyhow::Result<PathBuf> {
    let data_dir = runtime_root.join("data");
    fs::create_dir_all(&data_dir)?;
    let dest = data_dir.join(XDP_EBPF_OBJECT_NAME);
    let new_path = data_dir.join(format!("{XDP_EBPF_OBJECT_NAME}.upgrade-new"));
    fs::copy(source, &new_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&new_path)?.permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&new_path, perms)?;
    }

    fs::rename(&new_path, &dest)?;
    Ok(dest)
}

fn install_xdp_ebpf_object(
    source: Option<&Path>,
    install_binary: &Path,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(source) = source else {
        return Ok(None);
    };
    let runtime_root = runtime_root_for_upgrade(install_binary)?;
    install_xdp_ebpf_object_to_runtime(source, &runtime_root).map(Some)
}

fn repair_missing_xdp_ebpf_object(
    runtime_root: &Path,
    install_binary: &Path,
    cwd: &Path,
) -> anyhow::Result<Option<XdpObjectRepair>> {
    let dest = runtime_root.join("data").join(XDP_EBPF_OBJECT_NAME);
    if dest.is_file() {
        return Ok(None);
    }

    let mut candidates = Vec::new();
    if let Some(binary_parent) = install_binary.parent() {
        candidates.push(binary_parent.join("data").join(XDP_EBPF_OBJECT_NAME));
    }
    candidates.push(PathBuf::from("/usr/bin/data").join(XDP_EBPF_OBJECT_NAME));
    candidates.push(cwd.join("data").join(XDP_EBPF_OBJECT_NAME));

    for source in candidates {
        if source == dest || !source.is_file() {
            continue;
        }
        let repaired_dest = install_xdp_ebpf_object_to_runtime(&source, runtime_root)?;
        return Ok(Some(XdpObjectRepair {
            source,
            dest: repaired_dest,
        }));
    }

    Ok(None)
}

fn repair_missing_xdp_ebpf_object_for_current_runtime(
    node_paths: &cloud_node_rust::paths::NodePaths,
) {
    let dest = node_paths.data_dir().join(XDP_EBPF_OBJECT_NAME);
    if dest.is_file() {
        return;
    }

    let install_binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("cloud-node"));
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match repair_missing_xdp_ebpf_object(node_paths.runtime_root(), &install_binary, &cwd) {
        Ok(Some(repair)) => warn!(
            "XDP eBPF object was missing at {}; copied misplaced object from {}",
            repair.dest.display(),
            repair.source.display()
        ),
        Ok(None) => warn!(
            "XDP eBPF object missing at {}; no misplaced copy found in binary data dir, /usr/bin/data, or current working directory data dir; install {} before enabling XDP",
            dest.display(),
            XDP_EBPF_OBJECT_NAME
        ),
        Err(err) => warn!(
            "XDP eBPF object repair failed for {}: {}",
            dest.display(),
            err
        ),
    }
}

fn restart_after_upgrade(install_binary: &Path) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if systemd_service_exists() {
        if systemd_service_is_active() {
            run_systemctl("restart")?;
        } else {
            println!("{}", t("upgrade.service_stopped"));
        }
        return Ok(());
    }

    if check_running().is_some() {
        println!("{}", t("upgrade.restarting"));
        let status = Command::new(install_binary).arg("restart").status()?;
        if !status.success() {
            anyhow::bail!("{} restart failed with {status}", install_binary.display());
        }
    } else {
        println!("{}", t("upgrade.node_stopped"));
    }
    Ok(())
}

fn upgrade_binary(options: UpgradeOptions) -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!("upgrade command is currently supported only on Linux release assets");
    }

    let version = normalize_release_version(&options.version);
    let asset = match options.asset {
        Some(asset) => asset,
        None => detect_release_asset()?.to_string(),
    };
    let install_binary = options.install_binary.unwrap_or(std::env::current_exe()?);
    let install_binary = install_binary.canonicalize().unwrap_or(install_binary);
    let original_url =
        release_download_url(&options.github_base_url, &options.repo, &version, &asset);
    let download_url = apply_github_mirror(&original_url, options.github_mirror.as_deref());

    println!("{}", t("upgrade.summary"));
    println!(
        "  {:<17} {}",
        format!("{}:", t("upgrade.current_version")),
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "  {:<17} {version}",
        format!("{}:", t("upgrade.target_version"))
    );
    println!(
        "  {:<17} {}",
        format!("{}:", t("upgrade.repository")),
        options.repo
    );
    println!("  {:<17} {asset}", format!("{}:", t("upgrade.asset")));
    println!(
        "  {:<17} {download_url}",
        format!("{}:", t("upgrade.download_url"))
    );
    println!(
        "  {:<17} {}",
        format!("{}:", t("upgrade.install_binary")),
        install_binary.display()
    );
    println!(
        "  {:<17} {}",
        format!("{}:", t("upgrade.backup_dir")),
        options.backup_dir.display()
    );
    println!(
        "  {:<17} {}",
        format!("{}:", t("upgrade.restart")),
        if options.no_restart {
            t("common.no")
        } else {
            t("common.yes")
        }
    );

    if options.dry_run {
        println!("{}", t("upgrade.dry_run"));
        return Ok(());
    }

    if !options.yes && !prompt_upgrade_confirmation()? {
        anyhow::bail!("upgrade aborted");
    }

    let tmp_dir = std::env::temp_dir().join(format!(
        "cloud-node-upgrade-{}-{}",
        std::process::id(),
        unix_timestamp()
    ));
    fs::create_dir_all(&tmp_dir)?;
    let archive_path = tmp_dir.join(&asset);

    let result = (|| -> anyhow::Result<()> {
        println!("{}", t("upgrade.downloading"));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(download_to_file(&download_url, &archive_path))?;

        println!("{}", t("upgrade.extracting"));
        let payload = extract_release_payload(&archive_path, &tmp_dir)?;

        let backup_path = backup_current_binary(&install_binary, &options.backup_dir, &version)?;
        println!("{}: {}", t("upgrade.backup"), backup_path.display());

        replace_binary(&payload.binary, &install_binary)?;
        println!("{}: {}", t("upgrade.installed"), install_binary.display());
        match install_xdp_ebpf_object(payload.xdp_ebpf_object.as_deref(), &install_binary)? {
            Some(path) => println!("{}: {}", t("upgrade.xdp_object_installed"), path.display()),
            None => println!("{}", t("upgrade.xdp_object_missing")),
        }

        if !options.no_restart {
            restart_after_upgrade(&install_binary)?;
        }

        Ok(())
    })();

    let _ = fs::remove_dir_all(&tmp_dir);
    result
}

#[cfg(test)]
mod upgrade_tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn normalizes_release_versions() {
        assert_eq!(normalize_release_version("latest"), "latest");
        assert_eq!(normalize_release_version("LATEST"), "latest");
        assert_eq!(normalize_release_version("v1.1.6"), "v1.1.6");
        assert_eq!(normalize_release_version("1.1.6"), "v1.1.6");
    }

    #[test]
    fn builds_release_download_urls() {
        assert_eq!(
            release_download_url(
                "https://github.com/",
                "Zypixh/cloud-node-rust",
                "latest",
                "cloud-node-rust-linux-x64-v3-avx2.tar.gz"
            ),
            "https://github.com/Zypixh/cloud-node-rust/releases/latest/download/cloud-node-rust-linux-x64-v3-avx2.tar.gz"
        );
        assert_eq!(
            release_download_url(
                "https://github.com",
                "Zypixh/cloud-node-rust",
                "v1.1.6",
                "cloud-node-rust-linux-arm64-generic.tar.gz"
            ),
            "https://github.com/Zypixh/cloud-node-rust/releases/download/v1.1.6/cloud-node-rust-linux-arm64-generic.tar.gz"
        );
    }

    #[test]
    fn applies_github_mirror_urls() {
        let url = "https://github.com/Zypixh/cloud-node-rust/releases/latest/download/cloud-node-rust-linux-x64-v2-sse4.2.tar.gz";
        assert_eq!(apply_github_mirror(url, None), url);
        assert_eq!(
            apply_github_mirror(url, Some("https://gh-proxy.example")),
            "https://gh-proxy.example/https://github.com/Zypixh/cloud-node-rust/releases/latest/download/cloud-node-rust-linux-x64-v2-sse4.2.tar.gz"
        );
        assert_eq!(
            apply_github_mirror(url, Some("https://mirror.example/?target={url}")),
            "https://mirror.example/?target=https://github.com/Zypixh/cloud-node-rust/releases/latest/download/cloud-node-rust-linux-x64-v2-sse4.2.tar.gz"
        );
    }

    #[test]
    fn selects_x64_release_assets_by_cpu_flags() {
        assert_eq!(
            select_release_asset("x86_64", "flags: sse4_2 avx2", false).unwrap(),
            "cloud-node-rust-linux-x64-v3-avx2.tar.gz"
        );
        assert_eq!(
            select_release_asset("x86_64", "flags: sse4_2 avx512f avx2", false).unwrap(),
            "cloud-node-rust-linux-x64-v4-avx512.tar.gz"
        );
        assert_eq!(
            select_release_asset("x86_64", "flags: sse4_2", false).unwrap(),
            "cloud-node-rust-linux-x64-v2-sse4.2.tar.gz"
        );
        assert!(select_release_asset("x86_64", "flags: avx2", false).is_err());
        assert!(select_release_asset("x86_64", "flags: sse4_2", true).is_err());
    }

    #[test]
    fn selects_arm_release_assets_by_cpuinfo() {
        assert_eq!(
            select_release_asset("aarch64", "CPU part: neoverse-n1", false).unwrap(),
            "cloud-node-rust-linux-arm64-neoverse-n1.tar.gz"
        );
        assert_eq!(
            select_release_asset("aarch64", "processor: 0", false).unwrap(),
            "cloud-node-rust-linux-arm64-generic.tar.gz"
        );
    }

    #[test]
    fn extracts_release_payload_with_xdp_object() {
        let temp_root = std::env::temp_dir().join(format!(
            "cloud-node-release-payload-test-{}-{}",
            std::process::id(),
            unix_timestamp()
        ));
        let archive_path = temp_root.join("release.tar.gz");
        let extract_dir = temp_root.join("extract");
        fs::create_dir_all(&temp_root).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        let result = (|| -> anyhow::Result<()> {
            let file = fs::File::create(&archive_path)?;
            let encoder = GzEncoder::new(file, Compression::default());
            let mut archive = tar::Builder::new(encoder);

            append_test_tar_file(&mut archive, "cloud-node", b"binary")?;
            append_test_tar_file(&mut archive, "data/cloud-node-xdp-ebpf.o", b"ebpf-object")?;
            archive.finish()?;
            let encoder = archive.into_inner()?;
            encoder.finish()?;

            let payload = extract_release_payload(&archive_path, &extract_dir)?;
            assert_eq!(fs::read(payload.binary)?, b"binary");
            let object = payload.xdp_ebpf_object.expect("missing xdp object");
            assert_eq!(fs::read(object)?, b"ebpf-object");
            Ok(())
        })();

        let _ = fs::remove_dir_all(&temp_root);
        result.unwrap();
    }

    #[test]
    fn parses_service_and_wrapper_runtime_paths() {
        let service = r#"
[Service]
Environment="FOO=bar" "CLOUD_NODE_HOME=/srv/cloud node" BAZ=qux
WorkingDirectory='/opt/cloud-node'
"#;
        assert_eq!(
            service_env_cloud_node_home_from_text(service),
            Some(PathBuf::from("/srv/cloud node"))
        );
        assert_eq!(
            service_working_directory_from_text(service),
            Some(PathBuf::from("/opt/cloud-node"))
        );
        assert_eq!(
            parse_script_cd_workdir(
                "#!/bin/bash\ncd \"/var/lib/cloud-node\" && exec /var/lib/cloud-node/cloud-node \"$@\"\n"
            ),
            Some(PathBuf::from("/var/lib/cloud-node"))
        );
    }

    #[test]
    fn runtime_root_priority_matches_upgrade_runtime() {
        let temp_root = test_temp_root("runtime-root-priority");
        let result = (|| -> anyhow::Result<()> {
            let home = temp_root.join("home");
            let service_env = temp_root.join("service-env");
            let service_workdir = temp_root.join("service-workdir");
            let wrapper_workdir = temp_root.join("wrapper-workdir");
            let cwd = temp_root.join("cwd");
            let empty_cwd = temp_root.join("empty-cwd");
            let bin_dir = temp_root.join("bin");
            let install_binary = bin_dir.join("cloud-node");
            fs::create_dir_all(cwd.join("configs"))?;
            fs::create_dir_all(&empty_cwd)?;
            fs::create_dir_all(&bin_dir)?;

            assert_eq!(
                runtime_root_from_inputs(
                    Some(home.clone()),
                    Some(service_env.clone()),
                    Some(service_workdir.clone()),
                    Some(wrapper_workdir.clone()),
                    Some(cwd.clone()),
                    &install_binary
                )?,
                home
            );
            assert_eq!(
                runtime_root_from_inputs(
                    None,
                    Some(service_env.clone()),
                    Some(service_workdir.clone()),
                    Some(wrapper_workdir.clone()),
                    Some(cwd.clone()),
                    &install_binary
                )?,
                service_env
            );
            assert_eq!(
                runtime_root_from_inputs(
                    None,
                    None,
                    Some(service_workdir.clone()),
                    Some(wrapper_workdir.clone()),
                    Some(cwd.clone()),
                    &install_binary
                )?,
                service_workdir
            );
            assert_eq!(
                runtime_root_from_inputs(
                    None,
                    None,
                    None,
                    Some(wrapper_workdir.clone()),
                    Some(cwd.clone()),
                    &install_binary
                )?,
                wrapper_workdir
            );
            assert_eq!(
                runtime_root_from_inputs(None, None, None, None, Some(cwd), &install_binary)?,
                temp_root.join("cwd")
            );
            assert_eq!(
                runtime_root_from_inputs(None, None, None, None, Some(empty_cwd), &install_binary)?,
                bin_dir
            );

            Ok(())
        })();

        let _ = fs::remove_dir_all(&temp_root);
        result.unwrap();
    }

    #[test]
    fn usr_bin_install_uses_discovered_runtime_root_for_xdp_object() {
        let temp_root = test_temp_root("usr-bin-xdp-object");
        let result = (|| -> anyhow::Result<()> {
            let runtime_root = temp_root.join("runtime");
            let cwd = temp_root.join("cwd");
            fs::create_dir_all(runtime_root.join("data"))?;
            fs::create_dir_all(&cwd)?;

            let resolved = runtime_root_from_inputs(
                None,
                None,
                None,
                Some(runtime_root.clone()),
                Some(cwd),
                Path::new("/usr/bin/cloud-node"),
            )?;
            assert_eq!(resolved, runtime_root);
            assert_ne!(resolved, PathBuf::from("/usr/bin"));

            let source = temp_root.join(XDP_EBPF_OBJECT_NAME);
            fs::write(&source, b"ebpf-object")?;
            let dest = install_xdp_ebpf_object_to_runtime(&source, &resolved)?;
            assert_eq!(
                dest,
                temp_root.join("runtime/data").join(XDP_EBPF_OBJECT_NAME)
            );
            assert_eq!(fs::read(dest)?, b"ebpf-object");

            Ok(())
        })();

        let _ = fs::remove_dir_all(&temp_root);
        result.unwrap();
    }

    #[test]
    fn repairs_missing_xdp_object_from_misplaced_binary_data_dir() {
        let temp_root = test_temp_root("repair-xdp-object");
        let result = (|| -> anyhow::Result<()> {
            let runtime_root = temp_root.join("runtime");
            let bin_dir = temp_root.join("bin");
            let cwd = temp_root.join("cwd");
            let install_binary = bin_dir.join("cloud-node");
            let misplaced = bin_dir.join("data").join(XDP_EBPF_OBJECT_NAME);
            fs::create_dir_all(misplaced.parent().unwrap())?;
            fs::create_dir_all(&cwd)?;
            fs::write(&misplaced, b"misplaced-ebpf-object")?;

            let repair = repair_missing_xdp_ebpf_object(&runtime_root, &install_binary, &cwd)?
                .expect("expected repair from binary data dir");
            assert_eq!(repair.source, misplaced);
            assert_eq!(
                repair.dest,
                runtime_root.join("data").join(XDP_EBPF_OBJECT_NAME)
            );
            assert_eq!(fs::read(repair.dest)?, b"misplaced-ebpf-object");

            Ok(())
        })();

        let _ = fs::remove_dir_all(&temp_root);
        result.unwrap();
    }

    fn test_temp_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("cloud-node-{name}-{}-{nanos}", std::process::id()))
    }

    fn append_test_tar_file(
        archive: &mut tar::Builder<GzEncoder<fs::File>>,
        path: &str,
        body: &[u8],
    ) -> anyhow::Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_path(path)?;
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append(&header, body)?;
        archive.get_mut().flush()?;
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    Language::set_current(Language::detect());

    match cli.command {
        None => {
            // Default: Foreground
            run_node(cli.monitor_port, cli.monitor_clear)?;
        }
        Some(Commands::Start) => {
            if let Some(instance) = check_running() {
                println!("{} (PID: {})", t("status.already_running"), instance.pid);
                return Ok(());
            }

            if run_systemctl("start")? {
                return Ok(());
            }

            let node_paths = cloud_node_rust::paths::NodePaths::current();
            node_paths.ensure_runtime_dirs().ok();

            // Single-fork daemonize
            unsafe {
                let pid1 = libc::fork();
                if pid1 < 0 {
                    eprintln!("fork failed: {}", std::io::Error::last_os_error());
                    std::process::exit(1);
                }
                if pid1 > 0 {
                    // Parent: report and exit
                    println!("{} (PID: {})", t("start.started"), pid1);
                    return Ok(());
                }

                // Child: detach from terminal
                libc::setsid();

                // The tracing subscriber writes application logs to logs/run.log.
                // Keep daemon stdout detached and reserve stderr for fatal errors.
                let devnull =
                    libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR);
                if devnull >= 0 {
                    libc::dup2(devnull, libc::STDIN_FILENO);
                    libc::dup2(devnull, libc::STDOUT_FILENO);
                    if devnull > libc::STDOUT_FILENO {
                        libc::close(devnull);
                    }
                }

                let log_path =
                    CString::new(node_paths.run_log_file().to_string_lossy().as_bytes())?;
                let log_fd = libc::open(
                    log_path.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                    0o644,
                );
                if log_fd >= 0 {
                    libc::dup2(log_fd, libc::STDERR_FILENO);
                    if log_fd > libc::STDERR_FILENO {
                        libc::close(log_fd);
                    }
                }

                // Run directly in the daemon child
                if let Err(e) = run_node(cli.monitor_port, cli.monitor_clear) {
                    eprintln!("CloudNode fatal error: {}", e);
                    libc::_exit(1);
                }
            }
        }
        Some(Commands::_StartInternal) => {
            run_node(cli.monitor_port, cli.monitor_clear)?;
        }
        Some(Commands::Stop) => {
            if !run_systemctl("stop")? {
                if let Some(instance) = check_running() {
                    stop_running_instance(instance)?;
                } else {
                    println!("{}", t("stop.not_running"));
                }
            }
        }
        Some(Commands::Status) => {
            println!("{}: {}", t("status.version"), env!("CARGO_PKG_VERSION"));
            println!("{}: {}", t("status.build_time"), build_time_display());
            if let Some(instance) = check_running() {
                println!("{} (PID: {})", t("status.running"), instance.pid);
            } else {
                println!("{}", t("status.stopped"));
            }
        }
        Some(Commands::Restart) => {
            #[cfg(target_os = "linux")]
            if !is_systemd_invocation() && systemd_service_exists() {
                if systemd_service_is_active() {
                    run_systemctl("restart")?;
                } else {
                    if let Some(instance) = check_running() {
                        stop_running_instance(instance)?;
                    }
                    run_systemctl("start")?;
                }
                return Ok(());
            }

            if !run_systemctl("restart")? {
                if let Some(instance) = check_running() {
                    stop_running_instance(instance)?;
                }
                Command::new(std::env::current_exe()?)
                    .arg("start")
                    .status()?;
            }
        }
        Some(Commands::Install) => {
            #[cfg(target_os = "linux")]
            {
                let exe_path = std::env::current_exe()?.canonicalize()?;
                let work_dir = std::env::current_dir()?.canonicalize()?;

                // 1. Create global command wrapper
                let bin_path = "/usr/bin/cloud-node";
                let wrapper_script = format!(
                    "#!/bin/bash\ncd {}\n{} \"$@\"\n",
                    work_dir.display(),
                    exe_path.display()
                );

                if let Err(e) = fs::write(bin_path, wrapper_script) {
                    eprintln!(
                        "Failed to create global command at {}. Please run with sudo. Error: {}",
                        bin_path, e
                    );
                    std::process::exit(1);
                }

                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = fs::metadata(bin_path) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(bin_path, perms);
                }

                println!("{}", t("install.global_ok"));

                // 2. Create Systemd service
                let service_path = "/etc/systemd/system/cloud-node.service";
                let service_content = format!(
                    "[Unit]\n\
Description=CloudNode High Performance Cloud Node\n\
After=network.target\n\n\
[Service]\n\
Type=simple\n\
WorkingDirectory={}\n\
Environment=CLOUD_NODE_HOME={}\n\
ExecStart={}\n\
ExecStop={} stop\n\
TimeoutStopSec=35\n\
KillMode=process\n\
Restart=on-failure\n\
RestartSec=10\n\
LimitNOFILE=1048576\n\n\
[Install]\n\
WantedBy=multi-user.target\n",
                    work_dir.display(),
                    work_dir.display(),
                    exe_path.display(),
                    exe_path.display()
                );

                if let Err(e) = fs::write(service_path, service_content) {
                    eprintln!(
                        "Failed to create systemd service at {}. Error: {}",
                        service_path, e
                    );
                } else {
                    let _ = Command::new("systemctl").arg("daemon-reload").status();
                    let _ = Command::new("systemctl")
                        .arg("enable")
                        .arg("cloud-node")
                        .status();
                    println!("{}", t("install.service_ok"));
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                println!("{}", t("install.linux_only"));
            }
        }
        Some(Commands::Upgrade {
            version,
            repo,
            github_base_url,
            github_mirror,
            asset,
            install_binary,
            backup_dir,
            yes,
            dry_run,
            no_restart,
        }) => {
            upgrade_binary(UpgradeOptions {
                version,
                repo,
                github_base_url,
                github_mirror,
                asset,
                install_binary,
                backup_dir,
                yes,
                dry_run,
                no_restart,
            })?;
        }
        Some(Commands::Ntp {
            timezone,
            no_timezone,
            yes,
            servers,
            timeout_ms,
        }) => {
            run_ntp_command(timezone, no_timezone, yes, servers, timeout_ms)?;
        }
        Some(Commands::ZeroCopy {
            enable,
            disable,
            yes,
        }) => {
            run_zerocopy_command(enable, disable, yes)?;
        }
        Some(Commands::Firewall { command }) => {
            run_firewall_command(command)?;
        }
        Some(Commands::Defense { command }) => {
            run_defense_command(command)?;
        }
        Some(Commands::Xdp { command }) => {
            run_xdp_command(command)?;
        }
        Some(Commands::Test) => {
            println!("{}", t("test.start"));
            let api_config = ApiConfig::load_default()?;
            let runtime_config = RuntimeConfig::load_default()?;
            let relay = api_config.relay.normalized();
            println!(
                "{}: {}",
                t("test.relay_zero_copy"),
                if relay.zero_copy {
                    t("common.enabled")
                } else {
                    t("common.disabled")
                }
            );
            println!(
                "{}: auto (current {} bytes)",
                t("test.relay_copy_buffer"),
                cloud_node_rust::memory_governor::MEMORY_GOVERNOR.relay_copy_buffer_bytes()
            );
            println!("{}: {:?}", t("test.runtime_mode"), runtime_config.mode());
            println!(
                "XDP: enabled={} attachMode={} fallback={} interfaces={}",
                yes_no(runtime_config.xdp.enabled),
                runtime_config.xdp.attach_mode.as_str(),
                runtime_config.xdp.fallback.as_str(),
                runtime_config.xdp.interfaces.len()
            );
            println!("{}", t("test.valid"));
        }
    }
    Ok(())
}

fn spawn_xdp_health_fallback_task(rt: &tokio::runtime::Runtime, waf_state: Arc<WafStateManager>) {
    spawn_staggered(rt, Duration::from_secs(10), async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut consecutive_failures = 0u8;
        loop {
            interval.tick().await;
            let current = waf_state.kernel_filter_status();
            if current.name != "xdp" {
                consecutive_failures = 0;
                continue;
            }

            let status = cloud_node_rust::xdp::status_snapshot();
            let Some(reason) = xdp_health_fallback_reason(&status) else {
                consecutive_failures = 0;
                continue;
            };
            consecutive_failures = consecutive_failures.saturating_add(1);
            if consecutive_failures < 3 {
                continue;
            }

            warn!(
                "XDP health check failed repeatedly; switching L4 kernel enforcement to non-XDP fallback: {}",
                reason
            );
            let fallback = cloud_node_rust::firewall::kernel::build_non_xdp_fallback_filter().await;
            let fallback_status = fallback.status();
            waf_state.set_kernel_filter(fallback);
            warn!(
                "L4 kernel enforcement backend is now {} available={} detail={}",
                fallback_status.name, fallback_status.available, fallback_status.detail
            );
            consecutive_failures = 0;
        }
    });
}

fn xdp_health_fallback_reason(status: &cloud_node_rust::xdp::XdpStatusSnapshot) -> Option<String> {
    if !status.enabled {
        return None;
    }
    if !status.available {
        return Some(if status.fallback_reason.is_empty() {
            "XDP is unavailable".to_string()
        } else {
            status.fallback_reason.clone()
        });
    }
    if !status.fallback_reason.is_empty() {
        return Some(status.fallback_reason.clone());
    }
    if status.proxy_ports == 0 {
        return None;
    }
    if status.xsk_configured_queues == 0 {
        return Some("XDP proxy has no configured AF_XDP queues".to_string());
    }
    if status.xsk_ready_queues < status.xsk_configured_queues {
        return Some(format!(
            "AF_XDP queues not ready: ready={} configured={}",
            status.xsk_ready_queues, status.xsk_configured_queues
        ));
    }
    if !status.proxy_redirect_enabled || !status.proxy_ready {
        return Some(if status.proxy_fallback_reason.is_empty() {
            "AF_XDP proxy redirect is not ready".to_string()
        } else {
            status.proxy_fallback_reason.clone()
        });
    }
    None
}

fn run_node(monitor_port: Option<u16>, monitor_clear: bool) -> anyhow::Result<()> {
    let node_paths = cloud_node_rust::paths::NodePaths::current();
    node_paths.ensure_runtime_dirs().ok();

    // 0. Ensure single instance and write PID using flock
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    let pid_path = node_paths.pid_file();
    let pid_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&pid_path)?;
    let fd = pid_file.as_raw_fd();

    // Try to get an exclusive lock
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
        {
            if let Ok(content) = fs::read_to_string(&pid_path) {
                eprintln!(
                    "Error: Another instance is already running (PID: {})",
                    content.trim()
                );
            } else {
                eprintln!("Error: Another instance is already running.");
            }
            std::process::exit(1);
        } else {
            return Err(anyhow::anyhow!("Failed to lock PID file: {}", err));
        }
    }

    // Write current PID to the file
    pid_file.set_len(0)?;
    let mut pid_writer = &pid_file;
    write!(pid_writer, "{}", std::process::id())?;
    pid_writer.flush()?;

    // Keep the PID file open to maintain the lock
    std::mem::forget(pid_file);

    init_logging(&node_paths);

    info!("Starting CloudNode Rust v{}...", env!("CARGO_PKG_VERSION"));

    #[cfg(target_family = "unix")]
    {
        unsafe {
            let mut rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
                let target = 1048576;
                let old_cur = rlim.rlim_cur;

                if rlim.rlim_max < target {
                    rlim.rlim_max = target;
                }
                if rlim.rlim_cur < target {
                    rlim.rlim_cur = target;
                }

                if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) == 0 {
                    if old_cur < target {
                        info!(
                            "Successfully raised RLIMIT_NOFILE (file descriptor limit) from {} to {}",
                            old_cur, target
                        );
                    } else {
                        info!(
                            "RLIMIT_NOFILE (file descriptor limit) is already {} (>= {})",
                            old_cur, target
                        );
                    }
                } else {
                    let err = std::io::Error::last_os_error();
                    warn!(
                        "Failed to raise RLIMIT_NOFILE to {}. Current limit: cur={}, max={}. Error: {}. (You may need 'ulimit -n 1048576' or root privileges)",
                        target, rlim.rlim_cur, rlim.rlim_max, err
                    );
                }
            } else {
                warn!("Failed to get RLIMIT_NOFILE");
            }
        }
    }

    // Create the runtime to spawn background tasks
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let _guard = rt.enter();

    if let Some(port) = monitor_port {
        spawn_staggered(&rt, Duration::ZERO, async move {
            cloud_node_rust::perf_monitor::start(port, monitor_clear).await;
        });
    }

    // 1. Load API Config
    let api_config = ApiConfig::load_default().expect("Failed to load configs/api_node.yaml");
    cloud_node_rust::tcp_proxy::configure_relay_from_api(&api_config);
    let numeric_node_id = api_config.node_id.parse::<i64>().unwrap_or(0);
    logging::set_numeric_node_id(numeric_node_id);
    let access_log_pipeline = api_config.access_log_pipeline.normalized();
    let (log_tx, log_rx) = tokio::sync::mpsc::channel(access_log_pipeline.queue_capacity);
    let (node_log_tx, node_log_rx) = tokio::sync::mpsc::channel(
        cloud_node_rust::memory_governor::MEMORY_GOVERNOR.node_log_queue_capacity(),
    );
    logging::init_global_log_bus(
        log_tx,
        node_log_tx,
        access_log_pipeline.queue_capacity,
        Duration::from_millis(access_log_pipeline.warning_interval_ms),
    );
    let mut runtime_config =
        RuntimeConfig::load_default().expect("Failed to load configs/runtime.yaml");
    if runtime_config.is_rke2() {
        info!(
            "RKE2 runtime mode enabled for cluster {} in namespace {}.",
            runtime_config.cluster.name, runtime_config.cluster.namespace
        );
    } else {
        info!("Standalone runtime mode enabled.");
    }
    RuntimeConfig::set_current(runtime_config.clone());
    repair_missing_xdp_ebpf_object_for_current_runtime(&node_paths);
    if runtime_config.xdp.enabled {
        match cloud_node_rust::xdp_netdev_tuning::apply_for_xdp_config(
            &runtime_config.xdp,
            cloud_node_rust::xdp_netdev_tuning::XdpNetdevTuneOptions {
                dry_run: false,
                install_tools: false,
                report_node_log: true,
                persist_report: true,
            },
        ) {
            Ok(report) => {
                info!("XDP netdev tuning completed: {}", report.summary());
                let before_interfaces = runtime_config.xdp.interfaces.clone();
                cloud_node_rust::xdp_auto_config::refresh_xdp_interface_queues(
                    &mut runtime_config.xdp,
                );
                runtime_config.validate()?;
                RuntimeConfig::set_current(runtime_config.clone());
                if before_interfaces != runtime_config.xdp.interfaces {
                    let runtime_path = node_paths.runtime_config_file();
                    match save_xdp_config(&runtime_path, &runtime_config.xdp) {
                        Ok(()) => {
                            info!(
                                "XDP interface queues refreshed after netdev tuning and saved to {}",
                                runtime_path.display()
                            );
                            logging::report_node_log(
                                "info".to_string(),
                                "xdp_tuning".to_string(),
                                "key=\"xdp.interfaces.queues\" old=\"runtime\" target=\"current-rx-queues\" final=\"saved\" status=\"applied\" reason=\"refreshed after netdev tuning\"".to_string(),
                                0,
                            );
                        }
                        Err(err) => {
                            warn!(
                                "Failed to save refreshed XDP interface queues to {}: {}",
                                runtime_path.display(),
                                err
                            );
                            logging::report_node_log(
                                "warn".to_string(),
                                "xdp_tuning".to_string(),
                                format!(
                                    "key=\"xdp.interfaces.queues\" old=\"runtime\" target=\"current-rx-queues\" final=\"memory-only\" status=\"failed\" reason=\"{}\"",
                                    err.to_string().replace('"', "\\\"")
                                ),
                                0,
                            );
                        }
                    }
                }
            }
            Err(err) => {
                if runtime_config.xdp.fallback.fail_start() {
                    return Err(err.context("XDP netdev tuning failed"));
                }
                warn!("XDP netdev tuning skipped: {}", err);
            }
        }
    }
    if let Err(err) = rt.block_on(cloud_node_rust::xdp::initialize_from_runtime()) {
        if runtime_config.xdp.fallback.fail_start() {
            return Err(err.context("XDP initialization failed"));
        }
        warn!("XDP initialization skipped: {}", err);
    }
    spawn_xdp_port_sync_task(&rt, runtime_config.xdp.enabled);
    if runtime_config.is_rke2() {
        cloud_node_rust::cache_manager::CACHE
            .storage
            .apply_cluster_cache_config(&runtime_config.cluster.cache)?;
    }
    cloud_node_rust::cluster::runtime::start(&runtime_config);
    let api_config_arc = Arc::new(api_config.clone());
    cloud_node_rust::client_agent::load_client_agent_ip_index();
    cloud_node_rust::client_agent::start_client_agent_queue(api_config_arc.clone());
    cloud_node_rust::kernel_syn_defense::start_monitor();

    // 2. Initialize Managers
    let config_store = Arc::new(ConfigStore::new());
    cloud_node_rust::kernel_syn_defense::start_synproxy_reconciler(config_store.clone());
    let waf_state = Arc::new(WafStateManager::new());
    waf_state.install_kernel_snapshot_provider();
    let initial_kernel_filter = rt.block_on(cloud_node_rust::firewall::kernel::build_filter(None));
    if initial_kernel_filter.available() {
        waf_state.set_kernel_filter(initial_kernel_filter);
    }
    spawn_xdp_health_fallback_task(&rt, waf_state.clone());
    let restored_blocks = waf_state.restore_runtime_blocks_from_disk();
    if restored_blocks > 0 {
        info!(
            "Firewall runtime state initialized: restored_active={}",
            restored_blocks
        );
    }
    cloud_node_rust::firewall::persistence::start_flush_task();
    cloud_node_rust::firewall::state::start_gc_task(waf_state.clone());
    let ip_list_manager = Arc::new(firewall::lists::GlobalIpListManager::new(waf_state.clone()));
    let health_manager = GlobalHealthManager::new(16);
    let cert_selector = Arc::new(DynamicCertSelector::new());

    let hm_start = health_manager.clone();
    spawn_staggered(&rt, Duration::from_secs(2), async move {
        hm_start.start().await;
    });

    // 3. Start Background Syncers
    let cs = config_store.clone();
    let ac = api_config.clone();
    let il = ip_list_manager.clone();
    let hm = health_manager.clone();
    let ds = cert_selector.clone();
    let ws = waf_state.clone();
    spawn_staggered(&rt, Duration::ZERO, async move {
        rpc::start_config_syncer(cs, ac, il, hm, ds, ws).await;
    });

    let ac_ns = api_config.clone();
    let cs_ns = config_store.clone();
    spawn_staggered(&rt, Duration::from_secs(1), async move {
        rpc::start_node_stream(ac_ns, cs_ns).await;
    });

    let ac_i = api_config.clone();
    let cs_i = config_store.clone();
    let il_i = ip_list_manager.clone();
    spawn_staggered(&rt, Duration::from_secs(5), async move {
        rpc::start_ip_list_syncer(ac_i, cs_i, il_i).await;
    });

    cloud_node_rust::metrics::analyzer::initialize_geoip_readers();

    let ac_geoip = api_config.clone();
    spawn_staggered(&rt, Duration::from_secs(6), async move {
        rpc::start_ip_library_syncer(ac_geoip).await;
    });

    let ac_a = api_config.clone();
    spawn_staggered(&rt, Duration::from_secs(8), async move {
        rpc::start_api_node_syncer(ac_a).await;
    });

    let ac_us = api_config.clone();
    let cs_us = config_store.clone();
    let hm_us = health_manager.clone();
    let ds_us = cert_selector.clone();
    spawn_staggered(&rt, Duration::from_secs(9), async move {
        rpc::start_updating_server_list_syncer(ac_us, cs_us, hm_us, ds_us).await;
    });

    cloud_node_rust::metrics::init_http_dimension_worker(
        cloud_node_rust::memory_governor::MEMORY_GOVERNOR.metrics_queue_capacity(),
    );

    // Reporters
    let ac_s = api_config.clone();
    let cs_s = config_store.clone();
    spawn_staggered(&rt, Duration::from_secs(5), async move {
        rpc::start_metrics_reporter(cs_s, ac_s).await;
    });

    let ac_nv = api_config.clone();
    let cs_nv = config_store.clone();
    spawn_staggered(&rt, Duration::from_secs(7), async move {
        rpc::start_node_value_reporter(cs_nv, ac_nv).await;
    });

    let ac_bw = api_config.clone();
    let cs_bw = (*config_store).clone();
    spawn_staggered(&rt, Duration::from_secs(10), async move {
        rpc::start_bandwidth_reporter(cs_bw, ac_bw).await;
    });

    let ac_ds = api_config.clone();
    let cs_ds = (*config_store).clone();
    spawn_staggered(&rt, Duration::from_secs(11), async move {
        rpc::start_daily_stat_reporter(cs_ds, ac_ds).await;
    });

    let ac_ms = api_config.clone();
    let cs_ms = config_store.clone();
    spawn_staggered(&rt, Duration::from_secs(12), async move {
        rpc::start_metric_stat_reporter(cs_ms, ac_ms).await;
    });

    let ac_ti = api_config.clone();
    spawn_staggered(&rt, Duration::from_secs(14), async move {
        rpc::start_top_ip_stat_reporter(ac_ti).await;
    });

    let ac_ma = api_config.clone();
    let cs_ma = (*config_store).clone();
    spawn_staggered(&rt, Duration::from_secs(15), async move {
        rpc::start_metrics_aggregator_reporter(cs_ma, ac_ma).await;
    });

    let ac_ir = api_config.clone();
    spawn_staggered(&rt, Duration::from_secs(20), async move {
        rpc::start_ip_report_service(ac_ir).await;
    });

    let ac_ca = api_config_arc.clone();
    spawn_staggered(&rt, Duration::from_secs(21), async move {
        rpc::start_client_agent_ip_syncer(ac_ca).await;
    });

    spawn_staggered(&rt, Duration::from_secs(21), async move {
        cloud_node_rust::metrics::start_persistence_flusher().await;
    });

    let ac_ocsp = api_config.clone();
    let ds_ocsp = cert_selector.clone();
    spawn_staggered(&rt, Duration::from_secs(22), async move {
        rpc::start_ocsp_syncer(ac_ocsp, ds_ocsp).await;
    });

    // Log Uploader
    if api_config.kernel_tuning.normalized().enabled {
        cloud_node_rust::kernel_tuning::apply_runtime_tuning_and_report();
    } else {
        info!("Runtime kernel tuning disabled by api_config.kernelTuning.enabled=false");
        logging::report_node_log(
            "info".to_string(),
            "kernel_tuning".to_string(),
            "key=\"kernelTuning.enabled\" old=\"-\" target=\"false\" final=\"false\" status=\"disabled\" reason=\"disabled by api_config\"".to_string(),
            0,
        );
    }
    report_l4_performance_summary(&api_config);

    let uploader = log_uploader::LogUploader::new(log_rx, api_config.clone(), access_log_pipeline);
    spawn_staggered(&rt, Duration::from_secs(10), async move {
        uploader.start().await;
    });

    let node_uploader = log_uploader::NodeLogUploader::new(
        node_log_rx,
        api_config.clone(),
        100,
        Duration::from_secs(5),
    );
    spawn_staggered(&rt, Duration::from_secs(12), async move {
        node_uploader.start().await;
    });

    spawn_staggered(&rt, Duration::from_secs(16), async move {
        cloud_node_rust::utils::ntp::start_auto_ntp_syncer().await;
    });

    // 4. Initialize Pingora Server with multi-threading
    let mut conf = pingora_core::server::configuration::ServerConf::default();
    conf.threads = cloud_node_rust::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads();
    conf.upstream_keepalive_pool_size =
        cloud_node_rust::memory_governor::MEMORY_GOVERNOR.pingora_keepalive_pool_size(conf.threads);
    conf.grace_period_seconds = Some(5);
    conf.graceful_shutdown_timeout_seconds = Some(5);
    let mut my_server = pingora_core::server::Server::new_with_opt_and_conf(None, conf);
    let mem_plan =
        cloud_node_rust::memory_plan::current_memory_plan(my_server.configuration.threads);
    info!(
        "Pingora server configured with {} threads, upstream keepalive pool per thread={}, memory plan={}",
        my_server.configuration.threads,
        my_server.configuration.upstream_keepalive_pool_size,
        mem_plan.summary
    );
    my_server.bootstrap();

    // 5. Setup Dynamic HTTP/HTTPS Proxy Manager
    let proxy_logic = EdgeProxy {
        config: config_store.clone(),
        waf_state: waf_state.clone(),
        api_config: api_config_arc.clone(),
        cert_selector: cert_selector.clone(),
        waf_verifier: Arc::new(cloud_node_rust::firewall::verifier::WafVerifier::new(
            &api_config_arc.secret,
        )),
        tls_downstream: false,
    };
    let http_manager = cloud_node_rust::http_proxy_manager::HttpProxyManager::new(
        (*config_store).clone(),
        cert_selector.clone(),
        proxy_logic.clone(),
        my_server.configuration.clone(),
    );
    let xdp_http_manager = http_manager.clone();
    cloud_node_rust::proxy::start_request_limit_cleanup_task();
    cloud_node_rust::origin_state::start_origin_state_cleanup_task();
    cloud_node_rust::metrics::storage::start_cache_access_flusher();
    // cloud_node_rust::cache_hybrid::start_cache_profiler();
    cloud_node_rust::metrics::start_pressure_updater();
    cloud_node_rust::memory_reclaim::start_reclaim_monitor();
    cloud_node_rust::cache_hybrid::start_cache_janitor();
    tokio::spawn(cloud_node_rust::cache_hybrid::start_cache_purger(
        cloud_node_rust::cache_manager::CACHE.storage,
        cloud_node_rust::paths::NodePaths::current().cache_dir(),
    ));
    spawn_staggered(&rt, Duration::from_secs(1), async move {
        http_manager.start_listeners().await;
    });

    let http3_manager = cloud_node_rust::http3_proxy_manager::Http3ProxyManager::new(
        (*config_store).clone(),
        cert_selector.clone(),
        proxy_logic,
        my_server.configuration.clone(),
    );

    // UDP & TCP
    let udp_manager = udp_proxy::UdpProxyManager::new(
        (*config_store).clone(),
        waf_state.clone(),
        numeric_node_id,
    );
    let quic_udp_demux = cloud_node_rust::quic_udp_demux::QuicUdpDemuxManager::new(
        (*config_store).clone(),
        http3_manager,
        udp_manager.clone(),
    );
    let xdp_quic_udp_demux = quic_udp_demux.clone();
    let tcp_manager = tcp_proxy::TcpProxyManager::new(
        (*config_store).clone(),
        cert_selector.clone(),
        waf_state.clone(),
        numeric_node_id,
    );
    let xdp_tcp_manager = tcp_manager.clone();
    spawn_staggered(&rt, Duration::from_secs(2), async move {
        quic_udp_demux.start_listeners().await;
    });
    spawn_staggered(&rt, Duration::from_secs(2), async move {
        cloud_node_rust::xdp::af_xdp::start_proxy_bridge(
            xdp_quic_udp_demux,
            xdp_tcp_manager,
            xdp_http_manager,
        )
        .await;
    });
    spawn_staggered(&rt, Duration::from_secs(2), async move {
        tcp_manager.start_listeners().await;
    });

    info!("CloudNode (PID {}) is ready.", std::process::id());
    my_server.run_forever();
    #[allow(unreachable_code)]
    Ok(())
}

fn init_logging(node_paths: &cloud_node_rust::paths::NodePaths) {
    // Initialize logging with custom filter to silence hardcoded frame-level noise.
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    cloud_node_rust::utils::time::init_local_timezone();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info,pingora_proxy::proxy_cache=off")
    });

    let stdout_layer = tracing_subscriber::fmt::layer().with_timer(LocalLogTimer);
    let file_layer = match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(node_paths.run_log_file())
    {
        Ok(file) => Some(
            tracing_subscriber::fmt::layer()
                .with_timer(LocalLogTimer)
                .with_ansi(false)
                .with_writer(SharedLogWriter::new(file, node_paths.run_log_file())),
        ),
        Err(err) => {
            eprintln!(
                "Failed to open run log file {}: {}",
                node_paths.run_log_file().display(),
                err
            );
            None
        }
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();
}

fn report_l4_performance_summary(api_config: &ApiConfig) {
    let relay = api_config.relay.normalized();
    let governor = &cloud_node_rust::memory_governor::MEMORY_GOVERNOR;
    let message = format!(
        "zero_copy={} tcp_copy_buffer_bytes={} tcp_accept_workers={} udp_demux_workers={} udp_socket_buffer_bytes={}",
        relay.zero_copy,
        governor.relay_copy_buffer_bytes(),
        governor.tcp_accept_worker_count(),
        governor.udp_demux_worker_count(),
        governor.udp_socket_buffer_size()
    );
    info!("L4 performance summary: {}", message);
    logging::report_node_log("info".to_string(), "l4_performance".to_string(), message, 0);

    if !relay.zero_copy {
        let recommendation = "TCP pure L4 forwarding can reduce CPU by enabling zero-copy: cloud-node zerocopy --enable";
        info!("{}", recommendation);
        logging::report_node_log(
            "info".to_string(),
            "l4_performance".to_string(),
            recommendation.to_string(),
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FirewallAggregate, FirewallListFlags, cmdline_contains_management_command,
        first_cmdline_arg_basename, is_cloud_node_binary_name, process_basename,
        record_firewall_aggregate, v4_24, v6_48,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::Path;

    #[test]
    fn cloud_node_binary_names_accept_real_binaries() {
        assert!(is_cloud_node_binary_name("cloud-node"));
        assert!(is_cloud_node_binary_name("cloud-node-rust"));
        assert!(!is_cloud_node_binary_name("bash"));
        assert!(!is_cloud_node_binary_name("install-rust-cloud-node.sh"));
    }

    #[test]
    fn process_basename_strips_linux_deleted_suffix() {
        assert_eq!(
            process_basename(Path::new("/opt/cloud-node-rust/cloud-node-rust (deleted)"))
                .as_deref(),
            Some("cloud-node-rust")
        );
    }

    #[test]
    fn cmdline_detection_uses_argv0_not_wrapper_arguments() {
        assert_eq!(
            first_cmdline_arg_basename(b"/opt/cloud-node-rust/cloud-node-rust\0start\0").as_deref(),
            Some("cloud-node-rust")
        );
        assert_eq!(
            first_cmdline_arg_basename(b"bash\0/usr/bin/cloud-node\0status\0").as_deref(),
            Some("bash")
        );
    }

    #[test]
    fn cmdline_detection_excludes_short_lived_management_commands() {
        assert!(cmdline_contains_management_command(
            b"/opt/cloud-node-rust/cloud-node-rust\0status\0"
        ));
        assert!(cmdline_contains_management_command(
            b"/opt/cloud-node-rust/cloud-node-rust\0test\0"
        ));
        assert!(cmdline_contains_management_command(
            b"/opt/cloud-node-rust/cloud-node-rust\0defense\0status\0"
        ));
        assert!(!cmdline_contains_management_command(
            b"/opt/cloud-node-rust/cloud-node-rust\0start\0"
        ));
        assert!(!cmdline_contains_management_command(
            b"/opt/cloud-node-rust/cloud-node-rust\0--monitor-port\08888\0"
        ));
    }

    #[test]
    fn firewall_list_aggregate_helpers_count_sources() {
        assert_eq!(
            v4_24(Ipv4Addr::new(203, 0, 113, 99)),
            Ipv4Addr::new(203, 0, 113, 0)
        );
        assert_eq!(
            v6_48("2001:db8:abcd:12::1".parse::<Ipv6Addr>().unwrap()),
            "2001:db8:abcd::".parse::<Ipv6Addr>().unwrap()
        );

        let mut stats = FirewallAggregate::default();
        record_firewall_aggregate(
            &mut stats,
            FirewallListFlags {
                nf_blocked: true,
                blacklist: false,
            },
        );
        record_firewall_aggregate(
            &mut stats,
            FirewallListFlags {
                nf_blocked: true,
                blacklist: true,
            },
        );

        assert_eq!(stats.total, 2);
        assert_eq!(stats.nf_blocked, 2);
        assert_eq!(stats.blacklist, 1);
        assert_eq!(stats.both, 1);
    }
}
