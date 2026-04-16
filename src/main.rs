use clap::{Parser, Subcommand};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub mod pb {
    tonic::include_proto!("pb");
}

pub mod api_config;
pub mod auth;
pub mod cache;
pub mod cache_hybrid;
pub mod cache_manager;
pub mod client_agent;
pub mod config;
pub mod config_models;
pub mod firewall;
pub mod headers;
pub mod health_manager;
pub mod lb_factory;
pub mod log_uploader;
pub mod logging;
pub mod metrics;
pub mod proxy;
pub mod rewrite;
pub mod rpc;
pub mod ssl;
pub mod tcp_proxy;
pub mod udp_proxy;
pub mod utils;

use crate::api_config::ApiConfig;
use crate::config::ConfigStore;
use crate::firewall::state::WafStateManager;
use crate::health_manager::GlobalHealthManager;
use crate::proxy::EdgeProxy;
use crate::ssl::DynamicCertSelector;

#[derive(Parser)]
#[command(name = "cloud-node")]
#[command(about = "CloudNode - High Performance Edge Node written in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the edge node
    Start,
    /// Test the configuration
    Test,
    /// Reload the configuration
    Reload,
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

fn main() -> anyhow::Result<()> {
    // 0. Ensure single instance
    if let Err(e) = crate::utils::ensure_single_instance("data/cloud-node.pid") {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Start) {
        Commands::Start => {
            info!("Starting CloudNode Rust...");

            // Create the runtime to spawn background tasks
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let _guard = rt.enter();

            // 1. Load API Config
            let api_config = ApiConfig::load_default().expect("Failed to load api_node.yaml");
            let api_config_arc = Arc::new(api_config.clone());

            // 2. Initialize Managers
            let config_store = Arc::new(ConfigStore::new());
            let waf_state = Arc::new(WafStateManager::new());
            let ip_list_manager = Arc::new(crate::firewall::lists::GlobalIpListManager::new(waf_state.clone()));
            let health_manager = GlobalHealthManager::new(16);
            let cert_selector = Arc::new(DynamicCertSelector::new());

            let hm_start = health_manager.clone();
            spawn_staggered(&rt, Duration::from_secs(2), async move {
                hm_start.start().await;
            });

            // 3. Start Background Syncers (Phase 1)
            let cs = config_store.clone();
            let ac = api_config.clone();
            let il = ip_list_manager.clone();
            let hm = health_manager.clone();
            let ds = cert_selector.clone();
            spawn_staggered(&rt, Duration::ZERO, async move {
                crate::rpc::start_config_syncer(cs, ac, il, hm, ds).await;
            });
            info!("Background config_syncer task spawned");

            let ac_i = api_config.clone();
            let il_i = ip_list_manager.clone();
            spawn_staggered(&rt, Duration::from_secs(5), async move {
                crate::rpc::start_ip_list_syncer(ac_i, il_i).await;
            });

            let ac_a = api_config.clone();
            spawn_staggered(&rt, Duration::from_secs(8), async move {
                crate::rpc::start_api_node_syncer(ac_a).await;
            });

            // Start Updating Server List Syncer
            let ac_ul = api_config.clone();
            let cs_ul = config_store.clone();
            spawn_staggered(&rt, Duration::from_secs(12), async move {
                crate::rpc::start_updating_server_list_syncer(ac_ul, cs_ul).await;
            });

            // Start Metrics & Bandwidth Reporters (Phase 1.2)
            let ac_m = api_config.clone();
            spawn_staggered(&rt, Duration::from_secs(16), async move {
                crate::rpc::start_metrics_aggregator_reporter(ac_m).await;
            });

            let ac_s = api_config.clone();
            let cs_s = config_store.clone();
            spawn_staggered(&rt, Duration::from_secs(20), async move {
                crate::rpc::start_metrics_reporter(cs_s, ac_s).await;
            });

            let ac_b = api_config.clone();
            spawn_staggered(&rt, Duration::from_secs(24), async move {
                crate::rpc::start_bandwidth_reporter(ac_b).await;
            });

            let ac_d = api_config.clone();
            spawn_staggered(&rt, Duration::from_secs(28), async move {
                crate::rpc::start_daily_stat_reporter(ac_d).await;
            });

            let ac_v = api_config.clone();
            let cs_v = config_store.clone();
            spawn_staggered(&rt, Duration::from_secs(32), async move {
                crate::rpc::start_node_value_reporter(cs_v, ac_v).await;
            });

            spawn_staggered(&rt, Duration::from_secs(36), async move {
                crate::metrics::start_persistence_flusher().await;
            });

            spawn_staggered(&rt, Duration::from_secs(40), async move {
                crate::cache_hybrid::start_cache_purger(crate::cache_manager::CACHE.storage, std::path::PathBuf::from("data/cache")).await;
            });

            let ac_ms = api_config.clone();
            let cs_ms = config_store.as_ref().clone();
            spawn_staggered(&rt, Duration::from_secs(44), async move {
                crate::rpc::start_metric_stat_reporter(ac_ms, cs_ms).await;
            });

            let ac_ti = api_config.clone();
            spawn_staggered(&rt, Duration::from_secs(48), async move {
                crate::rpc::start_top_ip_stat_reporter(ac_ti).await;
            });

            let ac_sc = api_config.clone();
            spawn_staggered(&rt, Duration::from_secs(52), async move {
                crate::rpc::start_script_syncer(ac_sc).await;
            });

            // Start OCSP Syncer (Phase 1.4)
            let ac_o = api_config.clone();
            let ds_o = cert_selector.clone();
            spawn_staggered(&rt, Duration::from_secs(56), async move {
                crate::rpc::start_ocsp_syncer(ac_o, ds_o).await;
            });

            // Start IP Library Syncer (Phase 3.1)
            let ac_il = api_config.clone();
            spawn_staggered(&rt, Duration::from_secs(60), async move {
                crate::rpc::start_ip_library_syncer(ac_il).await;
            });

            // Start Log Uploader (Phase 1.3)
            let (log_tx, log_rx) = tokio::sync::mpsc::channel(10000);
            let (node_log_tx, node_log_rx) = tokio::sync::mpsc::channel(1000);
            crate::logging::init_global_log_bus(log_tx, node_log_tx);

            let uploader = crate::log_uploader::LogUploader::new(
                log_rx,
                api_config.clone(),
                100,
                Duration::from_secs(5),
            );
            spawn_staggered(&rt, Duration::from_secs(10), async move {
                uploader.start().await;
            });

            let node_uploader = crate::log_uploader::NodeLogUploader::new(
                node_log_rx,
                api_config.clone(),
                50,
                Duration::from_secs(10),
            );
            spawn_staggered(&rt, Duration::from_secs(14), async move {
                node_uploader.start().await;
            });

            // 4. Initialize Pingora Server
            let mut my_server = pingora_core::server::Server::new(None).unwrap();
            my_server.bootstrap();

            // 5. Setup HTTP/HTTPS Proxy Service
            let mut proxy_service = pingora_proxy::http_proxy_service(
                &my_server.configuration,
                EdgeProxy {
                    config: config_store.clone(),
                    waf_state: waf_state.clone(),
                    api_config: api_config_arc.clone(),
                },
            );

            // Add TCP listeners (HTTP on 80, HTTPS on 443)
            proxy_service.add_tcp("0.0.0.0:80");

            // Phase 6: TLS/SSL Support
            let mut tls_settings = pingora_core::listeners::tls::TlsSettings::with_callbacks(
                Box::new((*cert_selector).clone()),
            )
            .unwrap();
            let _ = &mut tls_settings;
            proxy_service.add_tls_with_settings("0.0.0.0:443", None, tls_settings);

            my_server.add_service(proxy_service);

            // LoadBalancer active health checks are already driven by GlobalHealthManager.

            // Phase 7: UDP Proxy Service
            let udp_manager = crate::udp_proxy::UdpProxyManager::new((*config_store).clone());
            spawn_staggered(&rt, Duration::from_secs(18), async move {
                udp_manager.start_listeners().await;
            });

            // Phase 8: TCP/TLS Proxy Service
            let tcp_manager = crate::tcp_proxy::TcpProxyManager::new(
                (*config_store).clone(),
                cert_selector.clone(),
            );
            spawn_staggered(&rt, Duration::from_secs(22), async move {
                tcp_manager.start_listeners().await;
            });

            // Start WAF State flusher
            let ws_f = waf_state.clone();
            spawn_staggered(&rt, Duration::from_secs(26), async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    ws_f.flush_to_disk();
                }
            });

            info!("CloudNode is ready and listening on 0.0.0.0:80/443");
            my_server.run_forever();
        }
        Commands::Test => {
            info!("Testing configuration...");
        }
        Commands::Reload => {
            info!("Reloading configuration...");
        }
    }

    Ok(())
}
