use clap::{Parser, Subcommand};
use std::fs;
use std::future::Future;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;

use cloud_node_rust::api_config::ApiConfig;
use cloud_node_rust::config::ConfigStore;
use cloud_node_rust::firewall::state::WafStateManager;
use cloud_node_rust::health_manager::GlobalHealthManager;
use cloud_node_rust::proxy::EdgeProxy;
use cloud_node_rust::ssl::DynamicCertSelector;
use cloud_node_rust::{firewall, log_uploader, logging, rpc, tcp_proxy, udp_proxy};

const PID_FILE: &str = "../data/cloud-node.pid";

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

#[derive(Parser)]
#[command(name = "cloud-node-rust")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "CloudNode - High Performance Edge Node written in Rust", long_about = None)]
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
    /// Start the edge node in background
    Start,
    /// Stop the background edge node
    Stop,
    /// Check the status of the edge node
    Status,
    /// Restart the background edge node
    Restart,
    /// Install the edge node as a systemd service and global command
    Install,
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

fn check_running() -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let file = fs::File::open(PID_FILE).ok()?;
    let fd = file.as_raw_fd();

    // Try to get an exclusive lock without blocking
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        // We got the lock, so it's NOT running
        unsafe { libc::flock(fd, libc::LOCK_UN) };
        return None;
    }

    // If it failed with EWOULDBLOCK, someone else has the lock
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN) {
        // It is running. Read the PID.
        if let Ok(content) = fs::read_to_string(PID_FILE) {
            return content.trim().parse::<u32>().ok();
        }
    }

    None
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // Default: Foreground
            run_node(cli.monitor_port, cli.monitor_clear)?;
        }
        Some(Commands::Start) => {
            if let Some(pid) = check_running() {
                println!("CloudNode is already running (PID: {})", pid);
                return Ok(());
            }

            let executable = std::env::current_exe()?;
            let mut command = Command::new(executable);
            command.arg("_start-internal");
            if let Some(port) = cli.monitor_port {
                command.arg("--monitor-port").arg(port.to_string());
            }
            if cli.monitor_clear {
                command.arg("--monitor-clear");
            }
            let child = command
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?;

            println!("CloudNode started in background (PID: {})", child.id());
        }
        Some(Commands::_StartInternal) => {
            run_node(cli.monitor_port, cli.monitor_clear)?;
        }
        Some(Commands::Stop) => {
            if let Some(pid) = check_running() {
                println!("Stopping CloudNode (PID: {})...", pid);
                let _ = Command::new("kill").arg(pid.to_string()).status();
                // We don't necessarily need to remove the file, flock will handle it, 
                // but for cleanliness we can try.
                let _ = fs::remove_file(PID_FILE);
            } else {
                println!("CloudNode is not running.");
            }
        }
        Some(Commands::Status) => {
            if let Some(pid) = check_running() {
                println!("CloudNode is running (PID: {})", pid);
            } else {
                println!("CloudNode is stopped.");
            }
        }
        Some(Commands::Restart) => {
            let _ = Command::new(std::env::current_exe()?).arg("stop").status();
            std::thread::sleep(Duration::from_secs(1));
            let _ = Command::new(std::env::current_exe()?).arg("start").status();
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
                     Description=CloudNode High Performance Edge Node\n\
                     After=network.target\n\n\
                     [Service]\n\
                     Type=forking\n\
                     PIDFile={}/../data/cloud-node.pid\n\
                     WorkingDirectory={}\n\
                     ExecStart={} start\n\
                     ExecStop={} stop\n\
                     ExecReload={} restart\n\
                     Restart=always\n\
                     RestartSec=10\n\
                     LimitNOFILE=1048576\n\n\
                     [Install]\n\
                     WantedBy=multi-user.target\n",
                    work_dir.display(),
                    work_dir.display(),
                    exe_path.display(),
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
        Some(Commands::Test) => {
            println!("Testing configuration...");
            let _ = ApiConfig::load_default()?;
            println!("Configuration is valid.");
        }
    }
    Ok(())
}

fn run_node(monitor_port: Option<u16>, monitor_clear: bool) -> anyhow::Result<()> {
    // Ensure data directory exists
    fs::create_dir_all("../data").ok();

    // 0. Ensure single instance and write PID using flock
    use std::io::Write;
    use std::os::unix::io::AsRawFd;

    let pid_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(PID_FILE)?;
    let fd = pid_file.as_raw_fd();

    // Try to get an exclusive lock
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN) {
            if let Ok(content) = fs::read_to_string(PID_FILE) {
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

    // Initialize logging with custom filter to silence hardcoded frame-level noise
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    cloud_node_rust::utils::time::init_local_timezone();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,pingora_proxy::proxy_cache=off"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_timer(LocalLogTimer))
        .init();

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
    let api_config = ApiConfig::load_default().expect("Failed to load api_node.yaml");
    let api_config_arc = Arc::new(api_config.clone());

    // 2. Initialize Managers
    let config_store = Arc::new(ConfigStore::new());
    let waf_state = Arc::new(WafStateManager::new());
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
    spawn_staggered(&rt, Duration::ZERO, async move {
        rpc::start_config_syncer(cs, ac, il, hm, ds).await;
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
    spawn_staggered(&rt, Duration::from_secs(9), async move {
        rpc::start_updating_server_list_syncer(ac_us, cs_us).await;
    });

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
    spawn_staggered(&rt, Duration::from_secs(15), async move {
        rpc::start_metrics_aggregator_reporter(ac_ma).await;
    });

    let ac_ir = api_config.clone();
    spawn_staggered(&rt, Duration::from_secs(20), async move {
        rpc::start_ip_report_service(ac_ir).await;
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
    let (log_tx, log_rx) = tokio::sync::mpsc::channel(100000);
    let (node_log_tx, node_log_rx) = tokio::sync::mpsc::channel(10000);
    logging::init_global_log_bus(log_tx, node_log_tx);

    let uploader =
        log_uploader::LogUploader::new(log_rx, api_config.clone(), 100, Duration::from_secs(5));
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

    // 4. Initialize Pingora Server with multi-threading
    let mut conf = pingora_core::server::configuration::ServerConf::default();
    conf.threads = num_cpus::get_physical().min(32);
    conf.upstream_keepalive_pool_size = 32768;
    let mut my_server = pingora_core::server::Server::new_with_opt_and_conf(None, conf);
    info!("Pingora server configured with {} threads.", my_server.configuration.threads);
    my_server.bootstrap();

    // 5. Setup Dynamic HTTP/HTTPS Proxy Manager
    let http_manager = cloud_node_rust::http_proxy_manager::HttpProxyManager::new(
        (*config_store).clone(),
        cert_selector.clone(),
        EdgeProxy {
            config: config_store.clone(),
            waf_state: waf_state.clone(),
            api_config: api_config_arc.clone(),
            cert_selector: cert_selector.clone(),
        },
        my_server.configuration.clone(),
    );
    cloud_node_rust::proxy::start_request_limit_cleanup_task();
    // cloud_node_rust::metrics::storage::start_cache_access_flusher();
    // cloud_node_rust::cache_hybrid::start_cache_profiler();
    cloud_node_rust::metrics::storage::load_cache_meta_index();
    cloud_node_rust::metrics::start_pressure_updater();
    cloud_node_rust::cache_hybrid::start_cache_janitor();
    spawn_staggered(&rt, Duration::from_secs(1), async move {
        http_manager.start_listeners().await;
    });

    let http3_manager = cloud_node_rust::http3_proxy_manager::Http3ProxyManager::new(
        (*config_store).clone(),
        cert_selector.clone(),
    );
    spawn_staggered(&rt, Duration::from_secs(2), async move {
        http3_manager.start_listeners().await;
    });

    // UDP & TCP
    let udp_manager = udp_proxy::UdpProxyManager::new((*config_store).clone());
    spawn_staggered(&rt, Duration::from_secs(2), async move {
        udp_manager.start_listeners().await;
    });

    let tcp_manager =
        tcp_proxy::TcpProxyManager::new((*config_store).clone(), cert_selector.clone());
    spawn_staggered(&rt, Duration::from_secs(2), async move {
        tcp_manager.start_listeners().await;
    });

    info!("CloudNode (PID {}) is ready.", std::process::id());
    my_server.run_forever();
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(target_os = "linux")]
fn auto_tune_kernel_params() {
    info!("Starting automatic kernel parameter tuning...");

    let params = [
        ("net.core.somaxconn", "32768"),
        ("net.ipv4.tcp_max_syn_backlog", "16384"),
        ("net.core.netdev_max_backlog", "16384"),
        ("net.ipv4.ip_local_port_range", "1024 65535"),
        ("net.ipv4.tcp_tw_reuse", "1"),
        ("net.ipv4.tcp_fin_timeout", "15"),
        ("net.ipv4.tcp_slow_start_after_idle", "0"),
        ("net.ipv4.tcp_mtu_probing", "1"),
    ];

    for (key, target) in params {
        tune_kernel_param(key, target);
    }
}

#[cfg(target_os = "linux")]
fn tune_kernel_param(key: &str, target: &str) {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    let path_ref = std::path::Path::new(&path);

    if !path_ref.exists() {
        info!(
            "Kernel tuning skipped: {} is not available on this system",
            key
        );
        return;
    }

    let current = match fs::read_to_string(path_ref) {
        Ok(value) => value.trim().to_string(),
        Err(err) => {
            warn!("Kernel tuning failed to read {}: {}", key, err);
            return;
        }
    };

    if current == target {
        info!("Kernel tuning already satisfied: {}={}", key, current);
        return;
    }

    match fs::write(path_ref, target) {
        Ok(_) => match fs::read_to_string(path_ref) {
            Ok(updated) => {
                let updated = updated.trim().to_string();
                if updated == target {
                    info!(
                        "Kernel tuning applied successfully: {} {} -> {}",
                        key, current, updated
                    );
                } else {
                    warn!(
                        "Kernel tuning wrote {} but value is {} (expected {})",
                        key, updated, target
                    );
                }
            }
            Err(err) => {
                warn!(
                    "Kernel tuning wrote {} but failed to verify new value: {}",
                    key, err
                );
            }
        },
        Err(err) => {
            warn!(
                "Kernel tuning failed for {} (current={}, target={}): {}",
                key, current, target, err
            );
        }
    }
}
