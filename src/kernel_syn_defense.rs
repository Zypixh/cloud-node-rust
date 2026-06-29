use crate::config::ConfigStore;
use crate::config_models::{NodeConfigPayload, ServerConfig};
use crate::l4_defense::L4PressureLevel;
use async_trait::async_trait;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

static LISTEN_OVERFLOWS_DELTA: AtomicU64 = AtomicU64::new(0);
static LISTEN_DROPS_DELTA: AtomicU64 = AtomicU64::new(0);
static SYNCOOKIES_SENT_DELTA: AtomicU64 = AtomicU64::new(0);
static REQ_Q_FULL_DO_COOKIES_DELTA: AtomicU64 = AtomicU64::new(0);
static REQ_Q_FULL_DROP_DELTA: AtomicU64 = AtomicU64::new(0);
static PRESSURE_LEVEL: AtomicU64 = AtomicU64::new(0);
static STARTED: LazyLock<()> = LazyLock::new(|| ());
static SYNPROXY_RECONCILER_STARTED: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
const NFT_BIN: &str = "nft";
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "cloud_node_synproxy";
#[cfg(target_os = "linux")]
const NFT_PREROUTING_CHAIN: &str = "prerouting";
#[cfg(target_os = "linux")]
const NFT_INPUT_CHAIN: &str = "input";
const NFT_PORT_SET: &str = "protected_tcp_ports";
const NFT_COMMENT_NOTRACK: &str = "cloud-node synproxy notrack";
const NFT_COMMENT_SYNPROXY: &str = "cloud-node synproxy";
const NFT_COMMENT_DROP_INVALID: &str = "cloud-node synproxy drop invalid";
#[cfg(target_os = "linux")]
const SYNPROXY_RECONCILE_RETRY: Duration = Duration::from_secs(60);

const SYNPROXY_SYSCTLS: [SynproxySysctl; 3] = [
    SynproxySysctl {
        key: "net.ipv4.tcp_syncookies",
        target: "1",
    },
    SynproxySysctl {
        key: "net.ipv4.tcp_timestamps",
        target: "1",
    },
    SynproxySysctl {
        key: "net.netfilter.nf_conntrack_tcp_loose",
        target: "0",
    },
];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KernelSynPressureSnapshot {
    pub listen_overflows_delta: u64,
    pub listen_drops_delta: u64,
    pub syncookies_sent_delta: u64,
    pub req_q_full_do_cookies_delta: u64,
    pub req_q_full_drop_delta: u64,
    pub pressure_level: L4PressureLevel,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpExtCounters {
    pub listen_overflows: u64,
    pub listen_drops: u64,
    pub syncookies_sent: u64,
    pub req_q_full_do_cookies: u64,
    pub req_q_full_drop: u64,
}

pub fn start_monitor() {
    let _ = *STARTED;
    static SPAWNED: AtomicU64 = AtomicU64::new(0);
    if SPAWNED
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    tokio::spawn(async {
        monitor_loop().await;
    });
}

pub fn start_synproxy_reconciler(config_store: Arc<ConfigStore>) {
    if SYNPROXY_RECONCILER_STARTED
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    tokio::spawn(async move {
        synproxy_reconcile_loop(config_store).await;
    });
}

pub fn snapshot() -> KernelSynPressureSnapshot {
    KernelSynPressureSnapshot {
        listen_overflows_delta: LISTEN_OVERFLOWS_DELTA.load(Ordering::Relaxed),
        listen_drops_delta: LISTEN_DROPS_DELTA.load(Ordering::Relaxed),
        syncookies_sent_delta: SYNCOOKIES_SENT_DELTA.load(Ordering::Relaxed),
        req_q_full_do_cookies_delta: REQ_Q_FULL_DO_COOKIES_DELTA.load(Ordering::Relaxed),
        req_q_full_drop_delta: REQ_Q_FULL_DROP_DELTA.load(Ordering::Relaxed),
        pressure_level: decode_pressure(PRESSURE_LEVEL.load(Ordering::Relaxed)),
    }
}

pub fn current_pressure_level() -> L4PressureLevel {
    decode_pressure(PRESSURE_LEVEL.load(Ordering::Relaxed))
}

async fn monitor_loop() {
    let mut previous = read_tcp_ext_counters().ok();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let current = match read_tcp_ext_counters() {
            Ok(counters) => counters,
            Err(err) => {
                debug!("kernel SYN pressure monitor skipped: {}", err);
                continue;
            }
        };
        let Some(prev) = previous.replace(current.clone()) else {
            continue;
        };
        let delta = TcpExtCounters {
            listen_overflows: current
                .listen_overflows
                .saturating_sub(prev.listen_overflows),
            listen_drops: current.listen_drops.saturating_sub(prev.listen_drops),
            syncookies_sent: current.syncookies_sent.saturating_sub(prev.syncookies_sent),
            req_q_full_do_cookies: current
                .req_q_full_do_cookies
                .saturating_sub(prev.req_q_full_do_cookies),
            req_q_full_drop: current.req_q_full_drop.saturating_sub(prev.req_q_full_drop),
        };
        let level = pressure_from_delta(&delta);
        LISTEN_OVERFLOWS_DELTA.store(delta.listen_overflows, Ordering::Relaxed);
        LISTEN_DROPS_DELTA.store(delta.listen_drops, Ordering::Relaxed);
        SYNCOOKIES_SENT_DELTA.store(delta.syncookies_sent, Ordering::Relaxed);
        REQ_Q_FULL_DO_COOKIES_DELTA.store(delta.req_q_full_do_cookies, Ordering::Relaxed);
        REQ_Q_FULL_DROP_DELTA.store(delta.req_q_full_drop, Ordering::Relaxed);
        let old = PRESSURE_LEVEL.swap(encode_pressure(level), Ordering::Relaxed);
        if level >= L4PressureLevel::High || old != encode_pressure(level) {
            crate::logging::report_node_log(
                if level >= L4PressureLevel::High {
                    "warn".to_string()
                } else {
                    "info".to_string()
                },
                "tcp_syn_pressure".to_string(),
                format!(
                    "level={} listen_overflows_delta={} listen_drops_delta={} syncookies_sent_delta={} req_q_full_do_cookies_delta={} req_q_full_drop_delta={}",
                    level.as_str(),
                    delta.listen_overflows,
                    delta.listen_drops,
                    delta.syncookies_sent,
                    delta.req_q_full_do_cookies,
                    delta.req_q_full_drop
                ),
                0,
            );
        }
    }
}

pub fn read_tcp_ext_counters() -> anyhow::Result<TcpExtCounters> {
    #[cfg(target_os = "linux")]
    {
        parse_tcp_ext_counters(&std::fs::read_to_string("/proc/net/netstat")?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(TcpExtCounters::default())
    }
}

pub fn parse_tcp_ext_counters(input: &str) -> anyhow::Result<TcpExtCounters> {
    let mut last_header: Option<Vec<&str>> = None;
    for line in input.lines() {
        let Some(rest) = line.strip_prefix("TcpExt:") else {
            continue;
        };
        let fields = rest.split_whitespace().collect::<Vec<_>>();
        if let Some(header) = last_header.take() {
            let values = fields;
            let map = header
                .into_iter()
                .zip(values.into_iter())
                .filter_map(|(key, value)| value.parse::<u64>().ok().map(|value| (key, value)))
                .collect::<HashMap<_, _>>();
            return Ok(TcpExtCounters {
                listen_overflows: *map.get("ListenOverflows").unwrap_or(&0),
                listen_drops: *map.get("ListenDrops").unwrap_or(&0),
                syncookies_sent: *map.get("SyncookiesSent").unwrap_or(&0),
                req_q_full_do_cookies: *map.get("TCPReqQFullDoCookies").unwrap_or(&0),
                req_q_full_drop: *map.get("TCPReqQFullDrop").unwrap_or(&0),
            });
        }
        last_header = Some(fields);
    }
    anyhow::bail!("TcpExt counters not found")
}

pub fn pressure_from_delta(delta: &TcpExtCounters) -> L4PressureLevel {
    let hard = delta
        .listen_drops
        .saturating_add(delta.listen_overflows)
        .saturating_add(delta.req_q_full_drop);
    let cookies = delta
        .syncookies_sent
        .saturating_add(delta.req_q_full_do_cookies);
    if hard >= 10_000 || cookies >= 50_000 {
        L4PressureLevel::Critical
    } else if hard >= 1_000 || cookies >= 10_000 {
        L4PressureLevel::High
    } else if hard >= 100 || cookies >= 1_000 {
        L4PressureLevel::Elevated
    } else {
        L4PressureLevel::Normal
    }
}

fn encode_pressure(level: L4PressureLevel) -> u64 {
    match level {
        L4PressureLevel::Normal => 0,
        L4PressureLevel::Elevated => 1,
        L4PressureLevel::High => 2,
        L4PressureLevel::Critical => 3,
    }
}

fn decode_pressure(value: u64) -> L4PressureLevel {
    match value {
        1 => L4PressureLevel::Elevated,
        2 => L4PressureLevel::High,
        3 => L4PressureLevel::Critical,
        _ => L4PressureLevel::Normal,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SynproxyMode {
    Enable,
    Disable,
    Status,
}

pub async fn synproxy_command(mode: SynproxyMode) -> anyhow::Result<String> {
    #[cfg(not(target_os = "linux"))]
    {
        return match mode {
            SynproxyMode::Status => Ok(format!(
                "CloudNode SYNPROXY status\n  platform: unsupported (Linux only)\n  syn pressure: {}\n  l4 pressure: {}",
                snapshot().pressure_level.as_str(),
                crate::l4_defense::current_pressure_level().as_str()
            )),
            SynproxyMode::Enable | SynproxyMode::Disable => {
                anyhow::bail!("SYNPROXY management is only supported on Linux")
            }
        };
    }

    #[cfg(target_os = "linux")]
    {
        let runner = SystemCommandRunner;
        let sysctl = ProcSysctlStore;
        return synproxy_command_with(mode, &runner, &sysctl).await;
    }
}

#[cfg(target_os = "linux")]
async fn synproxy_command_with(
    mode: SynproxyMode,
    runner: &impl CommandRunner,
    sysctl: &impl SynproxySysctlStore,
) -> anyhow::Result<String> {
    match mode {
        SynproxyMode::Status => synproxy_status_output(runner, sysctl).await,
        SynproxyMode::Enable => {
            let payload = fetch_live_node_config_payload().await?;
            let ports = synproxy_ports_from_payload(&payload);
            if ports.is_empty() {
                anyhow::bail!("live node config has no enabled TCP-facing listen ports");
            }
            let reports = apply_synproxy_sysctls(sysctl);
            ensure_synproxy_enabled(runner, &ports).await?;
            Ok(format_synproxy_apply_output("enabled", &ports, &reports))
        }
        SynproxyMode::Disable => {
            disable_synproxy_rules(runner).await?;
            Ok("CloudNode SYNPROXY disabled: removed managed nftables rules".to_string())
        }
    }
}

#[cfg(target_os = "linux")]
async fn synproxy_reconcile_loop(config_store: Arc<ConfigStore>) {
    loop {
        config_store.wait_for_runtime_reload().await;
        loop {
            if reconcile_synproxy_from_store(&config_store).await {
                break;
            }
            tokio::select! {
                _ = config_store.wait_for_runtime_reload() => {
                    continue;
                }
                _ = tokio::time::sleep(SYNPROXY_RECONCILE_RETRY) => {}
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn synproxy_reconcile_loop(_config_store: Arc<ConfigStore>) {}

#[cfg(target_os = "linux")]
async fn reconcile_synproxy_from_store(config_store: &ConfigStore) -> bool {
    let active = empty_connection_flood_active(config_store);
    let servers = config_store.get_all_servers_sync();
    let ports = synproxy_ports_from_arc_servers(&servers);
    let runner = SystemCommandRunner;
    let sysctl = ProcSysctlStore;

    let result = if active && !ports.is_empty() {
        let reports = apply_synproxy_sysctls(&sysctl);
        ensure_synproxy_enabled(&runner, &ports)
            .await
            .map(|_| reports)
    } else {
        disable_synproxy_rules(&runner).await.map(|_| Vec::new())
    };

    match result {
        Ok(reports) if active && !ports.is_empty() => {
            info!(
                "SYNPROXY auto protection active for ports {:?}; sysctls={}",
                ports,
                sysctl_report_summary(&reports)
            );
            crate::logging::report_node_log(
                "info".to_string(),
                "synproxy".to_string(),
                format!(
                    "status=\"enabled\" source=\"empty_connection_flood\" ports=\"{}\" sysctls=\"{}\"",
                    format_ports(&ports),
                    sysctl_report_summary(&reports)
                ),
                0,
            );
            true
        }
        Ok(_) => {
            info!(
                "SYNPROXY auto protection inactive: empty_connection_flood={} ports={}",
                active,
                format_ports(&ports)
            );
            crate::logging::report_node_log(
                "info".to_string(),
                "synproxy".to_string(),
                format!(
                    "status=\"disabled\" source=\"empty_connection_flood\" active=\"{}\" ports=\"{}\"",
                    active,
                    format_ports(&ports)
                ),
                0,
            );
            true
        }
        Err(err) => {
            warn!("SYNPROXY auto reconcile failed: {}", err);
            crate::logging::report_node_log(
                "warn".to_string(),
                "synproxy".to_string(),
                format!("status=\"failed\" reason=\"{}\"", err),
                0,
            );
            false
        }
    }
}

pub fn empty_connection_flood_active(config_store: &ConfigStore) -> bool {
    let cluster_id = config_store.get_node_cluster_id_sync();
    config_store
        .get_empty_connection_flood_config_for_cluster_sync(cluster_id)
        .is_some()
}

pub fn synproxy_ports_from_arc_servers(servers: &[Arc<ServerConfig>]) -> BTreeSet<u16> {
    let plain = servers
        .iter()
        .map(|server| server.as_ref().clone())
        .collect::<Vec<_>>();
    synproxy_ports_from_servers(&plain)
}

pub fn synproxy_ports_from_payload(payload: &NodeConfigPayload) -> BTreeSet<u16> {
    synproxy_ports_from_servers(&payload.servers)
}

pub fn synproxy_ports_from_servers(servers: &[ServerConfig]) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for server in servers.iter().filter(|server| server.is_on) {
        if let Some(http) = &server.http
            && http.is_on
        {
            collect_listen_ports(&mut ports, &http.listen);
        }
        if let Some(https) = &server.https
            && https.is_on
        {
            collect_listen_ports(&mut ports, &https.listen);
        }
        if let Some(tcp) = &server.tcp
            && tcp.is_on
        {
            collect_listen_ports(&mut ports, &tcp.listen);
            if let Some(tls) = &tcp.tls
                && tls.is_on
            {
                collect_listen_ports(&mut ports, &tls.listen);
            }
        }
    }
    ports
}

fn collect_listen_ports(
    ports: &mut BTreeSet<u16>,
    listen: &[crate::config_models::NetworkAddressConfig],
) {
    for addr in listen {
        if let Some(range) = addr.port_range.as_deref() {
            ports.extend(crate::config_models::ports_in_range(range));
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, program: &str, args: &[String]) -> io::Result<CommandOutput>;
}

pub struct SystemCommandRunner;

#[async_trait]
impl CommandRunner for SystemCommandRunner {
    async fn run(&self, program: &str, args: &[String]) -> io::Result<CommandOutput> {
        let output = tokio::process::Command::new(program)
            .args(args)
            .output()
            .await?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SynproxySysctl {
    pub key: &'static str,
    pub target: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SynproxySysctlStatus {
    Applied,
    AlreadySet,
    Missing,
    ReadFailed,
    WriteFailed,
    VerifyFailed,
    VerifyMismatch,
}

impl SynproxySysctlStatus {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn as_str(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::AlreadySet => "already_set",
            Self::Missing => "missing",
            Self::ReadFailed => "read_failed",
            Self::WriteFailed => "write_failed",
            Self::VerifyFailed => "verify_failed",
            Self::VerifyMismatch => "verify_mismatch",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynproxySysctlReport {
    pub key: String,
    pub old: Option<String>,
    pub target: String,
    pub final_value: Option<String>,
    pub status: SynproxySysctlStatus,
    pub reason: String,
}

pub trait SynproxySysctlStore {
    fn exists(&self, key: &str) -> bool;
    fn read(&self, key: &str) -> io::Result<String>;
    fn write(&self, key: &str, value: &str) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
pub struct ProcSysctlStore;

#[cfg(target_os = "linux")]
impl ProcSysctlStore {
    fn path_for_key(key: &str) -> std::path::PathBuf {
        std::path::PathBuf::from("/proc/sys").join(key.replace('.', "/"))
    }
}

#[cfg(target_os = "linux")]
impl SynproxySysctlStore for ProcSysctlStore {
    fn exists(&self, key: &str) -> bool {
        Self::path_for_key(key).exists()
    }

    fn read(&self, key: &str) -> io::Result<String> {
        std::fs::read_to_string(Self::path_for_key(key))
    }

    fn write(&self, key: &str, value: &str) -> io::Result<()> {
        std::fs::write(Self::path_for_key(key), value)
    }
}

pub fn read_synproxy_sysctls(store: &impl SynproxySysctlStore) -> Vec<SynproxySysctlReport> {
    SYNPROXY_SYSCTLS
        .iter()
        .map(|param| read_synproxy_sysctl(store, *param))
        .collect()
}

pub fn apply_synproxy_sysctls(store: &impl SynproxySysctlStore) -> Vec<SynproxySysctlReport> {
    SYNPROXY_SYSCTLS
        .iter()
        .map(|param| apply_synproxy_sysctl(store, *param))
        .collect()
}

fn read_synproxy_sysctl(
    store: &impl SynproxySysctlStore,
    param: SynproxySysctl,
) -> SynproxySysctlReport {
    if !store.exists(param.key) {
        return SynproxySysctlReport {
            key: param.key.to_string(),
            old: None,
            target: param.target.to_string(),
            final_value: None,
            status: SynproxySysctlStatus::Missing,
            reason: "sysctl is not available on this kernel".to_string(),
        };
    }
    match store.read(param.key) {
        Ok(value) => {
            let value = normalize_sysctl_value(&value);
            SynproxySysctlReport {
                key: param.key.to_string(),
                old: Some(value.clone()),
                target: param.target.to_string(),
                final_value: Some(value.clone()),
                status: if value == param.target {
                    SynproxySysctlStatus::AlreadySet
                } else {
                    SynproxySysctlStatus::VerifyMismatch
                },
                reason: "current runtime value".to_string(),
            }
        }
        Err(err) => SynproxySysctlReport {
            key: param.key.to_string(),
            old: None,
            target: param.target.to_string(),
            final_value: None,
            status: SynproxySysctlStatus::ReadFailed,
            reason: err.to_string(),
        },
    }
}

fn apply_synproxy_sysctl(
    store: &impl SynproxySysctlStore,
    param: SynproxySysctl,
) -> SynproxySysctlReport {
    if !store.exists(param.key) {
        return SynproxySysctlReport {
            key: param.key.to_string(),
            old: None,
            target: param.target.to_string(),
            final_value: None,
            status: SynproxySysctlStatus::Missing,
            reason: "sysctl is not available on this kernel".to_string(),
        };
    }
    let old = match store.read(param.key) {
        Ok(value) => normalize_sysctl_value(&value),
        Err(err) => {
            return SynproxySysctlReport {
                key: param.key.to_string(),
                old: None,
                target: param.target.to_string(),
                final_value: None,
                status: SynproxySysctlStatus::ReadFailed,
                reason: err.to_string(),
            };
        }
    };
    let target = normalize_sysctl_value(param.target);
    if old == target {
        return SynproxySysctlReport {
            key: param.key.to_string(),
            old: Some(old.clone()),
            target,
            final_value: Some(old),
            status: SynproxySysctlStatus::AlreadySet,
            reason: "already matches target".to_string(),
        };
    }
    if let Err(err) = store.write(param.key, param.target) {
        return SynproxySysctlReport {
            key: param.key.to_string(),
            old: Some(old.clone()),
            target,
            final_value: Some(old),
            status: SynproxySysctlStatus::WriteFailed,
            reason: err.to_string(),
        };
    }
    match store.read(param.key) {
        Ok(value) => {
            let final_value = normalize_sysctl_value(&value);
            let matches = final_value == target;
            SynproxySysctlReport {
                key: param.key.to_string(),
                old: Some(old),
                target,
                final_value: Some(final_value),
                status: if matches {
                    SynproxySysctlStatus::Applied
                } else {
                    SynproxySysctlStatus::VerifyMismatch
                },
                reason: if matches {
                    "runtime value updated".to_string()
                } else {
                    "runtime value differs after write".to_string()
                },
            }
        }
        Err(err) => SynproxySysctlReport {
            key: param.key.to_string(),
            old: Some(old),
            target,
            final_value: None,
            status: SynproxySysctlStatus::VerifyFailed,
            reason: err.to_string(),
        },
    }
}

fn normalize_sysctl_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SynproxyNftStatus {
    pub table_exists: bool,
    pub protected_ports: BTreeSet<u16>,
    pub has_notrack_rule: bool,
    pub has_synproxy_rule: bool,
    pub has_drop_invalid_rule: bool,
}

impl SynproxyNftStatus {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn enabled(&self) -> bool {
        self.table_exists
            && self.has_notrack_rule
            && self.has_synproxy_rule
            && self.has_drop_invalid_rule
            && !self.protected_ports.is_empty()
    }
}

#[cfg(target_os = "linux")]
async fn fetch_live_node_config_payload() -> anyhow::Result<NodeConfigPayload> {
    use std::io::Read;

    let api_config = crate::api_config::ApiConfig::load_default()?;
    let client = crate::rpc::client::SharedRpcClient::get(&api_config).await?;
    let client = client.as_rpc_client();
    let mut service = client.node_service();
    let resp = crate::rpc::track_rpc(service.find_current_node_config(tonic::Request::new(
        crate::pb::FindCurrentNodeConfigRequest {
            version: -1,
            compress: true,
            node_task_version: 0,
            use_data_map: true,
        },
    )))
    .await?;
    let resp = resp.into_inner();
    if resp.node_json.is_empty() {
        anyhow::bail!("control plane returned an empty node config");
    }
    let mut node_json = resp.node_json;
    if resp.is_compressed {
        let compressed = node_json;
        node_json = tokio::task::spawn_blocking(move || {
            let mut decompressor = brotli::Decompressor::new(&compressed[..], 4096);
            let mut decoded = Vec::new();
            decompressor.read_to_end(&mut decoded).map(|_| decoded)
        })
        .await??;
    }
    Ok(serde_json::from_slice::<NodeConfigPayload>(&node_json)?)
}

#[cfg(target_os = "linux")]
async fn ensure_synproxy_enabled(
    runner: &impl CommandRunner,
    ports: &BTreeSet<u16>,
) -> anyhow::Result<()> {
    if ports.is_empty() {
        anyhow::bail!("cannot enable SYNPROXY without protected ports");
    }
    run_nft(runner, &["--version"]).await?;
    run_nft_allow_exists(runner, &["add", "table", NFT_FAMILY, NFT_TABLE]).await?;
    run_nft_allow_exists(
        runner,
        &[
            "add",
            "chain",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_PREROUTING_CHAIN,
            "{",
            "type",
            "filter",
            "hook",
            "prerouting",
            "priority",
            "raw",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
    )
    .await?;
    run_nft_allow_exists(
        runner,
        &[
            "add",
            "chain",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_INPUT_CHAIN,
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "filter",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ],
    )
    .await?;
    run_nft_allow_exists(
        runner,
        &[
            "add",
            "set",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_PORT_SET,
            "{",
            "type",
            "inet_service",
            ";",
            "}",
        ],
    )
    .await?;
    run_nft_ignore_missing(
        runner,
        &["flush", "set", NFT_FAMILY, NFT_TABLE, NFT_PORT_SET],
    )
    .await?;
    let mut add_element = vec![
        "add".to_string(),
        "element".to_string(),
        NFT_FAMILY.to_string(),
        NFT_TABLE.to_string(),
        NFT_PORT_SET.to_string(),
        "{".to_string(),
    ];
    for (idx, port) in ports.iter().enumerate() {
        if idx > 0 {
            add_element.push(",".to_string());
        }
        add_element.push(port.to_string());
    }
    add_element.push("}".to_string());
    run_nft_owned(runner, &add_element).await?;

    let status = nft_status(runner).await?;
    if !status.has_notrack_rule {
        run_nft(runner, &notrack_rule_args()).await?;
    }
    let status = nft_status(runner).await?;
    if !status.has_synproxy_rule {
        run_nft(runner, &synproxy_rule_args()).await?;
    }
    let status = nft_status(runner).await?;
    if !status.has_drop_invalid_rule {
        run_nft(runner, &drop_invalid_rule_args()).await?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn disable_synproxy_rules(runner: &impl CommandRunner) -> anyhow::Result<()> {
    let status = match nft_status(runner).await {
        Ok(status) => status,
        Err(err) if is_missing_nft_object_error(&err.to_string()) => return Ok(()),
        Err(err) => return Err(err),
    };
    if !status.table_exists {
        return Ok(());
    }
    for (chain, comment) in [
        (NFT_PREROUTING_CHAIN, NFT_COMMENT_NOTRACK),
        (NFT_INPUT_CHAIN, NFT_COMMENT_SYNPROXY),
        (NFT_INPUT_CHAIN, NFT_COMMENT_DROP_INVALID),
    ] {
        delete_rules_by_comment(runner, chain, comment).await?;
    }
    run_nft_ignore_missing(
        runner,
        &["flush", "set", NFT_FAMILY, NFT_TABLE, NFT_PORT_SET],
    )
    .await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn delete_rules_by_comment(
    runner: &impl CommandRunner,
    chain: &str,
    comment: &str,
) -> anyhow::Result<()> {
    let output = run_nft(
        runner,
        &["-a", "list", "chain", NFT_FAMILY, NFT_TABLE, chain],
    )
    .await;
    let output = match output {
        Ok(output) => output,
        Err(err) if is_missing_nft_object_error(&err.to_string()) => return Ok(()),
        Err(err) => return Err(err),
    };
    let mut handles = parse_rule_handles_by_comment(&output, comment);
    handles.sort_unstable();
    handles.dedup();
    for handle in handles.into_iter().rev() {
        run_nft_ignore_missing(
            runner,
            &[
                "delete",
                "rule",
                NFT_FAMILY,
                NFT_TABLE,
                chain,
                "handle",
                &handle.to_string(),
            ],
        )
        .await?;
    }
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_rule_handles_by_comment(input: &str, comment: &str) -> Vec<u64> {
    input
        .lines()
        .filter(|line| contains_nft_comment(line, comment))
        .filter_map(|line| {
            line.rsplit_once("handle")
                .and_then(|(_, handle)| handle.split_whitespace().next())
                .and_then(|handle| handle.parse::<u64>().ok())
        })
        .collect()
}

#[cfg(target_os = "linux")]
async fn nft_status(runner: &impl CommandRunner) -> anyhow::Result<SynproxyNftStatus> {
    let output = match run_nft(runner, &["list", "table", NFT_FAMILY, NFT_TABLE]).await {
        Ok(output) => output,
        Err(err) if is_missing_nft_object_error(&err.to_string()) => {
            return Ok(SynproxyNftStatus::default());
        }
        Err(err) => return Err(err),
    };
    Ok(parse_nft_status(&output))
}

pub fn parse_nft_status(input: &str) -> SynproxyNftStatus {
    let mut status = SynproxyNftStatus {
        table_exists: input.contains(&format!("table {NFT_FAMILY} {NFT_TABLE}")),
        has_notrack_rule: contains_nft_comment(input, NFT_COMMENT_NOTRACK),
        has_synproxy_rule: contains_nft_comment(input, NFT_COMMENT_SYNPROXY),
        has_drop_invalid_rule: contains_nft_comment(input, NFT_COMMENT_DROP_INVALID),
        protected_ports: BTreeSet::new(),
    };
    let Some(set_pos) = input.find(&format!("set {NFT_PORT_SET}")) else {
        return status;
    };
    let set_block = &input[set_pos..];
    if let Some(elements_pos) = set_block.find("elements")
        && let Some(open_pos) = set_block[elements_pos..].find('{')
    {
        let after_open = &set_block[elements_pos + open_pos + 1..];
        if let Some(close_pos) = after_open.find('}') {
            for token in after_open[..close_pos].split(|c: char| !c.is_ascii_digit()) {
                if let Ok(port) = token.parse::<u16>() {
                    status.protected_ports.insert(port);
                }
            }
        }
    }
    status
}

fn contains_nft_comment(input: &str, comment: &str) -> bool {
    input.contains(&format!("comment \"{comment}\""))
}

#[cfg(target_os = "linux")]
fn notrack_rule_args() -> [&'static str; 24] {
    [
        "add",
        "rule",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_PREROUTING_CHAIN,
        "tcp",
        "dport",
        "@protected_tcp_ports",
        "tcp",
        "flags",
        "&",
        "(",
        "fin",
        "|",
        "syn",
        "|",
        "rst",
        "|",
        "ack",
        ")",
        "==",
        "syn",
        "notrack",
        "comment",
    ]
}

#[cfg(target_os = "linux")]
fn synproxy_rule_args() -> [&'static str; 20] {
    [
        "add",
        "rule",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_INPUT_CHAIN,
        "ct",
        "state",
        "invalid,untracked",
        "tcp",
        "dport",
        "@protected_tcp_ports",
        "synproxy",
        "mss",
        "1460",
        "wscale",
        "7",
        "timestamp",
        "sack-perm",
        "comment",
        NFT_COMMENT_SYNPROXY,
    ]
}

#[cfg(target_os = "linux")]
fn drop_invalid_rule_args() -> [&'static str; 13] {
    [
        "add",
        "rule",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_INPUT_CHAIN,
        "ct",
        "state",
        "invalid",
        "tcp",
        "dport",
        "@protected_tcp_ports",
        "drop",
        "comment",
    ]
}

#[cfg(target_os = "linux")]
async fn run_nft(runner: &impl CommandRunner, args: &[&str]) -> anyhow::Result<String> {
    run_nft_owned(
        runner,
        &args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>(),
    )
    .await
}

#[cfg(target_os = "linux")]
async fn run_nft_owned(runner: &impl CommandRunner, args: &[String]) -> anyhow::Result<String> {
    let args = with_rule_comment(args);
    let output = runner
        .run(NFT_BIN, &args)
        .await
        .map_err(|err| anyhow::anyhow!("failed to execute nft; is nftables installed? {}", err))?;
    if output.success {
        return Ok(output.stdout);
    }
    anyhow::bail!("{}", describe_nft_failure(&output.stderr));
}

#[cfg(target_os = "linux")]
fn with_rule_comment(args: &[String]) -> Vec<String> {
    let mut out = args.to_vec();
    if out.last().map(String::as_str) == Some("comment") {
        let comment = if out.iter().any(|arg| arg == NFT_PREROUTING_CHAIN) {
            NFT_COMMENT_NOTRACK
        } else if out.iter().any(|arg| arg == "drop") {
            NFT_COMMENT_DROP_INVALID
        } else {
            NFT_COMMENT_SYNPROXY
        };
        out.push(comment.to_string());
    }
    out
}

#[cfg(target_os = "linux")]
async fn run_nft_allow_exists(runner: &impl CommandRunner, args: &[&str]) -> anyhow::Result<()> {
    match run_nft(runner, args).await {
        Ok(_) => Ok(()),
        Err(err) if is_exists_nft_error(&err.to_string()) => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "linux")]
async fn run_nft_ignore_missing(runner: &impl CommandRunner, args: &[&str]) -> anyhow::Result<()> {
    match run_nft(runner, args).await {
        Ok(_) => Ok(()),
        Err(err) if is_missing_nft_object_error(&err.to_string()) => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "linux")]
fn describe_nft_failure(stderr: &str) -> String {
    let message = stderr.trim();
    if message.contains("Operation not permitted") || message.contains("Permission denied") {
        format!("nftables permission denied; run as root or grant CAP_NET_ADMIN: {message}")
    } else if message.contains("No such file or directory")
        || message.contains("unknown")
        || message.contains("Could not process rule")
    {
        format!(
            "nftables SYNPROXY rule failed; check kernel support/modules nf_synproxy_core, nft_synproxy and nf_conntrack: {message}"
        )
    } else {
        message.to_string()
    }
}

#[cfg(target_os = "linux")]
fn is_exists_nft_error(message: &str) -> bool {
    message.contains("File exists") || message.contains("already exists")
}

#[cfg(target_os = "linux")]
fn is_missing_nft_object_error(message: &str) -> bool {
    message.contains("No such file")
        || message.contains("No such file or directory")
        || message.contains("does not exist")
        || message.contains("No such file or directory")
        || message.contains("Could not process rule")
}

#[cfg(target_os = "linux")]
async fn synproxy_status_output(
    runner: &impl CommandRunner,
    sysctl: &impl SynproxySysctlStore,
) -> anyhow::Result<String> {
    let nft = nft_status(runner).await?;
    let sysctls = read_synproxy_sysctls(sysctl);
    let counters = read_tcp_ext_counters().unwrap_or_default();
    Ok(format!(
        "CloudNode SYNPROXY status\n  nft table: {}\n  enabled: {}\n  protected ports: {}\n  rules: notrack={} synproxy={} drop_invalid={}\n  sysctls: {}\n  syn counters: listen_overflows={} listen_drops={} syncookies={} req_q_full_do_cookies={} req_q_full_drop={}\n  syn pressure: {}\n  l4 pressure: {}",
        if nft.table_exists {
            "present"
        } else {
            "missing"
        },
        nft.enabled(),
        format_ports(&nft.protected_ports),
        nft.has_notrack_rule,
        nft.has_synproxy_rule,
        nft.has_drop_invalid_rule,
        sysctl_report_summary(&sysctls),
        counters.listen_overflows,
        counters.listen_drops,
        counters.syncookies_sent,
        counters.req_q_full_do_cookies,
        counters.req_q_full_drop,
        snapshot().pressure_level.as_str(),
        crate::l4_defense::current_pressure_level().as_str()
    ))
}

#[cfg(target_os = "linux")]
fn format_synproxy_apply_output(
    action: &str,
    ports: &BTreeSet<u16>,
    sysctls: &[SynproxySysctlReport],
) -> String {
    format!(
        "CloudNode SYNPROXY {action}\n  protected ports: {}\n  sysctls: {}\n  syn pressure: {}\n  l4 pressure: {}",
        format_ports(ports),
        sysctl_report_summary(sysctls),
        snapshot().pressure_level.as_str(),
        crate::l4_defense::current_pressure_level().as_str()
    )
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn format_ports(ports: &BTreeSet<u16>) -> String {
    if ports.is_empty() {
        "-".to_string()
    } else {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sysctl_report_summary(reports: &[SynproxySysctlReport]) -> String {
    reports
        .iter()
        .map(|report| {
            format!(
                "{}={} target={} status={}",
                report.key,
                report.final_value.as_deref().unwrap_or("-"),
                report.target,
                report.status.as_str()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_models::{
        EmptyConnectionFloodConfig, HTTPConfig, HTTPFirewallPolicy, HTTPSConfig,
        NetworkAddressConfig, TCPConfig,
    };
    use std::cell::RefCell;
    use std::collections::HashSet;
    #[cfg(target_os = "linux")]
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeSysctlStore {
        values: RefCell<HashMap<String, String>>,
        missing: HashSet<String>,
        write_errors: HashMap<String, io::ErrorKind>,
    }

    impl FakeSysctlStore {
        fn with_value(self, key: &str, value: &str) -> Self {
            self.values
                .borrow_mut()
                .insert(key.to_string(), value.to_string());
            self
        }

        fn missing(mut self, key: &str) -> Self {
            self.missing.insert(key.to_string());
            self
        }

        fn write_error(mut self, key: &str, kind: io::ErrorKind) -> Self {
            self.write_errors.insert(key.to_string(), kind);
            self
        }
    }

    impl SynproxySysctlStore for FakeSysctlStore {
        fn exists(&self, key: &str) -> bool {
            !self.missing.contains(key)
        }

        fn read(&self, key: &str) -> io::Result<String> {
            self.values
                .borrow()
                .get(key)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn write(&self, key: &str, value: &str) -> io::Result<()> {
            if let Some(kind) = self.write_errors.get(key) {
                return Err(io::Error::from(*kind));
            }
            self.values
                .borrow_mut()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Default)]
    struct FakeRunner {
        outputs: Mutex<Vec<(String, CommandOutput)>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    #[cfg(target_os = "linux")]
    impl FakeRunner {
        fn push(&self, needle: &str, output: CommandOutput) {
            self.outputs
                .lock()
                .unwrap()
                .push((needle.to_string(), output));
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[cfg(target_os = "linux")]
    #[async_trait]
    impl CommandRunner for FakeRunner {
        async fn run(&self, _program: &str, args: &[String]) -> io::Result<CommandOutput> {
            self.calls.lock().unwrap().push(args.to_vec());
            let joined = args.join(" ");
            let mut outputs = self.outputs.lock().unwrap();
            if let Some(pos) = outputs
                .iter()
                .position(|(needle, _)| joined.contains(needle))
            {
                return Ok(outputs.remove(pos).1);
            }
            Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn parses_tcp_ext_netstat_pairs() {
        let input = "TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPReqQFullDoCookies TCPReqQFullDrop\nTcpExt: 10 20 30 40 50\n";
        let counters = parse_tcp_ext_counters(input).unwrap();
        assert_eq!(counters.syncookies_sent, 10);
        assert_eq!(counters.listen_overflows, 20);
        assert_eq!(counters.listen_drops, 30);
        assert_eq!(counters.req_q_full_do_cookies, 40);
        assert_eq!(counters.req_q_full_drop, 50);
    }

    #[test]
    fn pressure_from_delta_scales() {
        assert_eq!(
            pressure_from_delta(&TcpExtCounters::default()),
            L4PressureLevel::Normal
        );
        assert_eq!(
            pressure_from_delta(&TcpExtCounters {
                listen_drops: 100,
                ..Default::default()
            }),
            L4PressureLevel::Elevated
        );
        assert_eq!(
            pressure_from_delta(&TcpExtCounters {
                listen_overflows: 1_000,
                ..Default::default()
            }),
            L4PressureLevel::High
        );
        assert_eq!(
            pressure_from_delta(&TcpExtCounters {
                req_q_full_drop: 10_000,
                ..Default::default()
            }),
            L4PressureLevel::Critical
        );
    }

    #[test]
    fn synproxy_ports_cover_http_https_tcp_and_tcp_tls_ranges() {
        let server = ServerConfig {
            is_on: true,
            http: Some(HTTPConfig {
                is_on: true,
                listen: vec![listen("80")],
            }),
            https: Some(HTTPSConfig {
                is_on: true,
                listen: vec![listen("443-444")],
                ssl_policy: None,
                supports_http3: None,
            }),
            tcp: Some(TCPConfig {
                is_on: true,
                listen: vec![listen("9000")],
                tls: Some(HTTPSConfig {
                    is_on: true,
                    listen: vec![listen("9443")],
                    ssl_policy: None,
                    supports_http3: None,
                }),
            }),
            ..Default::default()
        };
        assert_eq!(
            synproxy_ports_from_servers(&[server]),
            BTreeSet::from([80, 443, 444, 9000, 9443])
        );
    }

    #[tokio::test]
    async fn empty_connection_flood_active_requires_cluster_policy() {
        let store = ConfigStore::new();
        let server = Arc::new(ServerConfig {
            id: Some(1),
            is_on: true,
            cluster_id: 12,
            http_firewall_policy_id: 1,
            ..Default::default()
        });
        store
            .update_config(
                1,
                1,
                0,
                12,
                vec![server],
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                0,
                1,
                true,
                false,
                HashMap::new(),
                false,
                false,
                "random".to_string(),
                HashMap::new(),
                None,
                true,
                false,
                String::new(),
                false,
                false,
                0,
                false,
                false,
                false,
                String::new(),
                None,
                None,
                Vec::new(),
                vec![empty_connection_policy(true, 3)],
                Vec::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                None,
                None,
            )
            .await;
        assert!(empty_connection_flood_active(&store));
    }

    #[test]
    fn synproxy_sysctl_apply_is_idempotent_and_reports_errors() {
        let store = FakeSysctlStore::default()
            .with_value("net.ipv4.tcp_syncookies", "0\n")
            .with_value("net.ipv4.tcp_timestamps", "1\n")
            .with_value("net.netfilter.nf_conntrack_tcp_loose", "1\n");
        let reports = apply_synproxy_sysctls(&store);
        assert_eq!(reports[0].status, SynproxySysctlStatus::Applied);
        assert_eq!(reports[1].status, SynproxySysctlStatus::AlreadySet);
        assert_eq!(reports[2].status, SynproxySysctlStatus::Applied);

        let missing = FakeSysctlStore::default()
            .with_value("net.ipv4.tcp_syncookies", "1")
            .with_value("net.ipv4.tcp_timestamps", "1")
            .missing("net.netfilter.nf_conntrack_tcp_loose");
        let reports = apply_synproxy_sysctls(&missing);
        assert_eq!(reports[2].status, SynproxySysctlStatus::Missing);

        let denied = FakeSysctlStore::default()
            .with_value("net.ipv4.tcp_syncookies", "0")
            .with_value("net.ipv4.tcp_timestamps", "1")
            .with_value("net.netfilter.nf_conntrack_tcp_loose", "0")
            .write_error("net.ipv4.tcp_syncookies", io::ErrorKind::PermissionDenied);
        let reports = apply_synproxy_sysctls(&denied);
        assert_eq!(reports[0].status, SynproxySysctlStatus::WriteFailed);
    }

    #[test]
    fn parses_nft_status_ports_and_managed_rules() {
        let status = parse_nft_status(
            r#"
table inet cloud_node_synproxy {
  set protected_tcp_ports {
    type inet_service
    elements = { 80, 443, 9443 }
  }
  chain prerouting {
    tcp dport @protected_tcp_ports notrack comment "cloud-node synproxy notrack"
  }
  chain input {
    ct state invalid,untracked tcp dport @protected_tcp_ports synproxy comment "cloud-node synproxy"
    ct state invalid tcp dport @protected_tcp_ports drop comment "cloud-node synproxy drop invalid"
  }
}
"#,
        );
        assert!(status.enabled());
        assert_eq!(status.protected_ports, BTreeSet::from([80, 443, 9443]));
    }

    #[test]
    fn parses_rule_handles_by_exact_comment() {
        let handles = parse_rule_handles_by_comment(
            r#"
tcp dport @protected_tcp_ports notrack comment "cloud-node synproxy notrack" # handle 7
ct state invalid tcp dport @protected_tcp_ports drop comment "cloud-node synproxy drop invalid" # handle 8
"#,
            NFT_COMMENT_DROP_INVALID,
        );
        assert_eq!(handles, vec![8]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn enable_generates_managed_nft_commands_without_duplicates() {
        let runner = FakeRunner::default();
        runner.push(
            "list table inet cloud_node_synproxy",
            CommandOutput {
                success: true,
                stdout: "table inet cloud_node_synproxy { set protected_tcp_ports { type inet_service elements = { 443 } } }".to_string(),
                stderr: String::new(),
            },
        );
        runner.push(
            "list table inet cloud_node_synproxy",
            CommandOutput {
                success: true,
                stdout: format!(
                    "table inet cloud_node_synproxy {{ set protected_tcp_ports {{ type inet_service elements = {{ 443 }} }} chain prerouting {{ comment \"{}\" }} }}",
                    NFT_COMMENT_NOTRACK
                ),
                stderr: String::new(),
            },
        );
        runner.push(
            "list table inet cloud_node_synproxy",
            CommandOutput {
                success: true,
                stdout: format!(
                    "table inet cloud_node_synproxy {{ set protected_tcp_ports {{ type inet_service elements = {{ 443 }} }} chain prerouting {{ comment \"{}\" }} chain input {{ comment \"{}\" }} }}",
                    NFT_COMMENT_NOTRACK, NFT_COMMENT_SYNPROXY
                ),
                stderr: String::new(),
            },
        );
        ensure_synproxy_enabled(&runner, &BTreeSet::from([443]))
            .await
            .unwrap();
        let calls = runner.calls();
        assert!(calls.iter().any(|call| {
            call.join(" ")
                .contains("add element inet cloud_node_synproxy protected_tcp_ports { 443 }")
        }));
        assert!(calls.iter().any(|call| {
            call.join(" ")
                .contains("synproxy mss 1460 wscale 7 timestamp sack-perm")
        }));
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.join(" ").contains(NFT_COMMENT_NOTRACK))
                .count(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn disable_deletes_only_managed_rule_handles() {
        let runner = FakeRunner::default();
        runner.push(
            "list table inet cloud_node_synproxy",
            CommandOutput {
                success: true,
                stdout: "table inet cloud_node_synproxy {}".to_string(),
                stderr: String::new(),
            },
        );
        runner.push(
            "list chain inet cloud_node_synproxy prerouting",
            CommandOutput {
                success: true,
                stdout: format!(
                    "tcp dport @protected_tcp_ports notrack comment \"{}\" # handle 11\n",
                    NFT_COMMENT_NOTRACK
                ),
                stderr: String::new(),
            },
        );
        runner.push(
            "list chain inet cloud_node_synproxy input",
            CommandOutput {
                success: true,
                stdout: format!(
                    "ct state invalid,untracked comment \"{}\" # handle 12\nct state invalid comment \"{}\" # handle 13\n",
                    NFT_COMMENT_SYNPROXY, NFT_COMMENT_DROP_INVALID
                ),
                stderr: String::new(),
            },
        );
        runner.push(
            "list chain inet cloud_node_synproxy input",
            CommandOutput {
                success: true,
                stdout: format!(
                    "ct state invalid comment \"{}\" # handle 13\n",
                    NFT_COMMENT_DROP_INVALID
                ),
                stderr: String::new(),
            },
        );
        disable_synproxy_rules(&runner).await.unwrap();
        let joined = runner
            .calls()
            .into_iter()
            .map(|call| call.join(" "))
            .collect::<Vec<_>>();
        assert!(joined.iter().any(|call| {
            call.contains("delete rule inet cloud_node_synproxy prerouting handle 11")
        }));
        assert!(
            joined
                .iter()
                .any(|call| call.contains("delete rule inet cloud_node_synproxy input handle 12"))
        );
        assert!(
            joined
                .iter()
                .any(|call| call.contains("delete rule inet cloud_node_synproxy input handle 13"))
        );
    }

    #[test]
    fn status_summary_contains_operational_fields() {
        let status = parse_nft_status(
            "table inet cloud_node_synproxy { set protected_tcp_ports { elements = { 443 } } }",
        );
        let sysctls = vec![SynproxySysctlReport {
            key: "net.ipv4.tcp_syncookies".to_string(),
            old: Some("1".to_string()),
            target: "1".to_string(),
            final_value: Some("1".to_string()),
            status: SynproxySysctlStatus::AlreadySet,
            reason: String::new(),
        }];
        assert_eq!(format_ports(&status.protected_ports), "443");
        assert!(sysctl_report_summary(&sysctls).contains("net.ipv4.tcp_syncookies=1"));
    }

    fn listen(port_range: &str) -> NetworkAddressConfig {
        NetworkAddressConfig {
            protocol: None,
            host: None,
            port_range: Some(port_range.to_string()),
        }
    }

    fn empty_connection_policy(is_on: bool, max_empty_connections: u32) -> HTTPFirewallPolicy {
        HTTPFirewallPolicy {
            id: 1,
            is_on: true,
            name: "l4-test-policy".to_string(),
            inbound: None,
            outbound: None,
            empty_connection_flood: Some(EmptyConnectionFloodConfig {
                is_on,
                max_empty_connections,
                period: 10,
                block_seconds: 60,
            }),
            tls_exhaustion_attack: None,
            cc_config: None,
            block_options: None,
            page_options: None,
            captcha_options: None,
            js_cookie_options: None,
            max_request_body_size: 0,
            deny_country_html: String::new(),
            deny_province_html: String::new(),
            use_local_firewall: false,
            syn_flood: None,
            mode: String::new(),
            candidate_rules: None,
            candidate_traffic_pct: 0,
            candidate_version: 0,
        }
    }
}
