use chrono::{Local, TimeZone};
use clap::{Parser, Subcommand};
use std::ffi::{CString, OsStr};
use std::fs;
use std::future::Future;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
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
use cloud_node_rust::proxy::EdgeProxy;
use cloud_node_rust::runtime_mode::RuntimeConfig;
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
    file: Arc<Mutex<fs::File>>,
}

impl SharedLogWriter {
    fn new(file: fs::File) -> Self {
        Self {
            file: Arc::new(Mutex::new(file)),
        }
    }
}

struct SharedLogGuard {
    file: Arc<Mutex<fs::File>>,
    buffer: Vec<u8>,
}

impl SharedLogGuard {
    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "run log lock poisoned"))?;
        use io::Write as _;
        file.write_all(&self.buffer)?;
        file.flush()?;
        self.buffer.clear();
        Ok(())
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
            file: Arc::clone(&self.file),
            buffer: Vec::new(),
        }
    }
}

#[derive(Parser)]
#[command(name = "cloud-node-rust")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "CloudNode - High Performance Cloud Node written in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(
        long,
        global = true,
        help = "Port to start the performance monitor web dashboard"
    )]
    monitor_port: Option<u16>,

    #[arg(
        long,
        global = true,
        help = "Clear in-memory performance monitor samples on startup"
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
    /// Synchronize internal time offset with NTP servers and optionally set system timezone
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

        /// NTP server host. Can be repeated. Defaults to built-in global servers.
        #[arg(long = "server")]
        servers: Vec<String>,

        /// Per-server NTP timeout in milliseconds.
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
    },
    /// Test the configuration
    Test,
    /// Internal use only
    #[command(hide = true)]
    _StartInternal,
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

fn build_time_display() -> String {
    option_env!("CLOUD_NODE_BUILD_TIMESTAMP")
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|timestamp| Local.timestamp_opt(timestamp, 0).single())
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S %z").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn prompt_ntp_timezone() -> anyhow::Result<Option<String>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Ok(None);
    }

    let current = cloud_node_rust::utils::ntp::detect_system_timezone()
        .unwrap_or_else(|| "Asia/Shanghai".to_string());
    println!("Current timezone: {}", current);
    println!("Enter a timezone to set, or press Enter to keep current.");
    print!("Timezone [{}]: ", current);
    use io::Write as _;
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let timezone = input.trim();
    if timezone.is_empty() {
        Ok(None)
    } else {
        Ok(Some(timezone.to_string()))
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
        println!("System timezone set to {}", timezone);
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
    println!("{}", result.log_message());
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
        .any(|arg| matches!(arg, "stop" | "status" | "restart" | "install" | "test"))
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
    println!("Stopping CloudNode (PID: {})...", instance.pid);
    send_signal(instance.pid, libc::SIGTERM)?;

    if !wait_for_exit(instance.pid, Duration::from_secs(20)) {
        eprintln!(
            "CloudNode did not stop within 20s, forcing shutdown (PID: {})...",
            instance.pid
        );
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
    println!("CloudNode stopped.");
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

    println!("CloudNode is managed by systemd, running: systemctl {action} cloud-node.service");
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

fn extract_release_binary(archive_path: &Path, target_dir: &Path) -> anyhow::Result<PathBuf> {
    let archive_file = fs::File::open(archive_path)?;
    let gz = flate2::read::GzDecoder::new(archive_file);
    let mut archive = tar::Archive::new(gz);
    let binary = target_dir.join("cloud-node");

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path.file_name() == Some(OsStr::new("cloud-node")) {
            entry.unpack(&binary)?;
            if !binary.is_file() {
                anyhow::bail!("release archive cloud-node entry is not a regular file");
            }
            return Ok(binary);
        }
    }

    anyhow::bail!("release archive does not contain cloud-node");
}

fn prompt_upgrade_confirmation() -> anyhow::Result<bool> {
    if !io::stdin().is_terminal() {
        anyhow::bail!(
            "interactive confirmation is unavailable; pass --yes for non-interactive upgrade"
        );
    }

    println!("Proceed with upgrade? [y/N] ");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(
        input.trim(),
        "y" | "Y" | "yes" | "YES" | "Yes" | "是" | "好" | "确认"
    ))
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

fn restart_after_upgrade(install_binary: &Path) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    if systemd_service_exists() {
        if systemd_service_is_active() {
            run_systemctl("restart")?;
        } else {
            println!("cloud-node.service is installed but not active; leaving it stopped.");
        }
        return Ok(());
    }

    if check_running().is_some() {
        println!("Restarting CloudNode with upgraded binary...");
        let status = Command::new(install_binary).arg("restart").status()?;
        if !status.success() {
            anyhow::bail!("{} restart failed with {status}", install_binary.display());
        }
    } else {
        println!("CloudNode is not running; leaving it stopped.");
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

    println!("CloudNode upgrade summary:");
    println!("  current version: {}", env!("CARGO_PKG_VERSION"));
    println!("  target version:  {version}");
    println!("  repository:      {}", options.repo);
    println!("  asset:           {asset}");
    println!("  download URL:    {download_url}");
    println!("  install binary:  {}", install_binary.display());
    println!("  backup dir:      {}", options.backup_dir.display());
    println!(
        "  restart:         {}",
        if options.no_restart { "no" } else { "yes" }
    );

    if options.dry_run {
        println!("Dry run only; no files will be changed.");
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
        println!("Downloading release asset...");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(download_to_file(&download_url, &archive_path))?;

        println!("Extracting release archive...");
        let extracted_binary = extract_release_binary(&archive_path, &tmp_dir)?;

        let backup_path = backup_current_binary(&install_binary, &options.backup_dir, &version)?;
        println!("Previous binary backup: {}", backup_path.display());

        replace_binary(&extracted_binary, &install_binary)?;
        println!("Installed upgraded binary: {}", install_binary.display());

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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // Default: Foreground
            run_node(cli.monitor_port, cli.monitor_clear)?;
        }
        Some(Commands::Start) => {
            if let Some(instance) = check_running() {
                println!("CloudNode is already running (PID: {})", instance.pid);
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
                    println!("CloudNode started in background (PID: {})", pid1);
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
                    println!("CloudNode is not running.");
                }
            }
        }
        Some(Commands::Status) => {
            println!("CloudNode version: {}", env!("CARGO_PKG_VERSION"));
            println!("Build time: {}", build_time_display());
            if let Some(instance) = check_running() {
                println!("CloudNode is running (PID: {})", instance.pid);
            } else {
                println!("CloudNode is stopped.");
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

                println!("Successfully registered global command: cloud-node");

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
                    println!(
                        "Successfully registered systemd service. You can now use: systemctl start cloud-node"
                    );
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                println!("Install command is currently only supported on Linux.");
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
        Some(Commands::Test) => {
            println!("Testing configuration...");
            let _ = ApiConfig::load_default()?;
            let runtime_config = RuntimeConfig::load_default()?;
            println!("Runtime mode: {:?}", runtime_config.mode());
            println!("Configuration is valid.");
        }
    }
    Ok(())
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

    #[cfg(target_os = "linux")]
    auto_tune_kernel_params();

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
    let runtime_config =
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
    if runtime_config.is_rke2() {
        cloud_node_rust::cache_manager::CACHE
            .storage
            .apply_cluster_cache_config(&runtime_config.cluster.cache)?;
    }
    cloud_node_rust::cluster::runtime::start(&runtime_config);
    let api_config_arc = Arc::new(api_config.clone());
    cloud_node_rust::client_agent::load_client_agent_ip_index();
    cloud_node_rust::client_agent::start_client_agent_queue(api_config_arc.clone());

    // 2. Initialize Managers
    let config_store = Arc::new(ConfigStore::new());
    let waf_state = Arc::new(WafStateManager::new());
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
    cloud_node_rust::proxy::start_request_limit_cleanup_task();
    cloud_node_rust::origin_state::start_origin_state_cleanup_task();
    cloud_node_rust::metrics::storage::start_cache_access_flusher();
    // cloud_node_rust::cache_hybrid::start_cache_profiler();
    cloud_node_rust::metrics::start_pressure_updater();
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
    let udp_manager = udp_proxy::UdpProxyManager::new((*config_store).clone());
    let quic_udp_demux = cloud_node_rust::quic_udp_demux::QuicUdpDemuxManager::new(
        (*config_store).clone(),
        http3_manager,
        udp_manager,
    );
    spawn_staggered(&rt, Duration::from_secs(2), async move {
        quic_udp_demux.start_listeners().await;
    });

    let tcp_manager = tcp_proxy::TcpProxyManager::new(
        (*config_store).clone(),
        cert_selector.clone(),
        waf_state.clone(),
        api_config_arc.node_id.parse::<i64>().unwrap_or(0),
    );
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
                .with_writer(SharedLogWriter::new(file)),
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

#[cfg(target_os = "linux")]
fn auto_tune_kernel_params() {
    info!("Starting automatic kernel parameter tuning...");

    let params = [
        KernelParamTune::exact("net.core.somaxconn", "65535"),
        KernelParamTune::exact("net.ipv4.tcp_max_syn_backlog", "65535"),
        KernelParamTune::exact("net.core.netdev_max_backlog", "250000"),
        KernelParamTune::exact("net.ipv4.ip_local_port_range", "1024 65535"),
        KernelParamTune::exact("net.ipv4.tcp_tw_reuse", "1"),
        KernelParamTune::exact("net.ipv4.tcp_fin_timeout", "10"),
        KernelParamTune::exact("net.ipv4.tcp_slow_start_after_idle", "0"),
        KernelParamTune::exact("net.ipv4.tcp_mtu_probing", "1"),
        KernelParamTune::exact("net.core.rmem_max", "134217728"),
        KernelParamTune::exact("net.core.wmem_max", "134217728"),
        KernelParamTune::exact("net.ipv4.tcp_rmem", "4096 87380 134217728"),
        KernelParamTune::exact("net.ipv4.tcp_wmem", "4096 65536 134217728"),
        KernelParamTune::exact_optional("net.core.default_qdisc", "fq"),
        KernelParamTune::exact_optional("net.ipv4.tcp_congestion_control", "bbr"),
    ];

    for param in params {
        tune_kernel_param(param);
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct KernelParamTune {
    key: &'static str,
    target: &'static str,
    optional: bool,
}

#[cfg(target_os = "linux")]
impl KernelParamTune {
    const fn exact(key: &'static str, target: &'static str) -> Self {
        Self {
            key,
            target,
            optional: false,
        }
    }

    const fn exact_optional(key: &'static str, target: &'static str) -> Self {
        Self {
            key,
            target,
            optional: true,
        }
    }
}

#[cfg(target_os = "linux")]
fn tune_kernel_param(param: KernelParamTune) {
    let path = format!("/proc/sys/{}", param.key.replace('.', "/"));
    let path_ref = std::path::Path::new(&path);

    if !path_ref.exists() {
        tracing::debug!(
            "Kernel tuning skipped: {} is not available on this system",
            param.key
        );
        return;
    }

    let current = match fs::read_to_string(path_ref) {
        Ok(value) => normalize_sysctl_value(&value),
        Err(err) => {
            warn!("Kernel tuning failed to read {}: {}", param.key, err);
            return;
        }
    };

    let target = param.target;
    if current == target {
        tracing::debug!("Kernel tuning already satisfied: {}={}", param.key, current);
        return;
    }

    match fs::write(path_ref, target) {
        Ok(_) => match fs::read_to_string(path_ref) {
            Ok(updated) => {
                let updated = normalize_sysctl_value(&updated);
                if updated == target {
                    info!(
                        "Kernel tuning applied successfully: {} {} -> {}",
                        param.key, current, updated
                    );
                } else if param.optional {
                    tracing::debug!(
                        "Kernel tuning optional value {} remained {} after writing {}",
                        param.key,
                        updated,
                        target
                    );
                } else {
                    warn!(
                        "Kernel tuning wrote {} but value is {} (expected {})",
                        param.key, updated, target
                    );
                }
            }
            Err(err) => {
                warn!(
                    "Kernel tuning wrote {} but failed to verify new value: {}",
                    param.key, err
                );
            }
        },
        Err(err) => {
            if param.optional {
                tracing::debug!(
                    "Kernel tuning optional value skipped for {} (current={}, target={}): {}",
                    param.key,
                    current,
                    target,
                    err
                );
            } else {
                warn!(
                    "Kernel tuning failed for {} (current={}, target={}): {}",
                    param.key, current, target, err
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn normalize_sysctl_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::{
        cmdline_contains_management_command, first_cmdline_arg_basename, is_cloud_node_binary_name,
        process_basename,
    };
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
        assert!(!cmdline_contains_management_command(
            b"/opt/cloud-node-rust/cloud-node-rust\0start\0"
        ));
        assert!(!cmdline_contains_management_command(
            b"/opt/cloud-node-rust/cloud-node-rust\0--monitor-port\08888\0"
        ));
    }
}
