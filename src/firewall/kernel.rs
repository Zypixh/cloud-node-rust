use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Clone, Debug, Default)]
pub struct KernelFilterRange {
    pub from: u128,
    pub to: u128,
    pub v6: bool,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default)]
pub struct KernelFilterSnapshot {
    pub blocked_ips: Vec<(IpAddr, i64)>,
    pub allowed_ips: Vec<(IpAddr, i64)>,
    pub blocked_networks: Vec<(IpNet, i64)>,
    pub allowed_networks: Vec<(IpNet, i64)>,
    pub blocked_ranges: Vec<KernelFilterRange>,
    pub allowed_ranges: Vec<KernelFilterRange>,
}

#[derive(Clone, Debug, Default)]
pub struct KernelFilterStatus {
    pub name: &'static str,
    pub available: bool,
    pub detail: String,
}

pub trait KernelFilter: Send + Sync {
    fn block(&self, ip: IpAddr, ttl_secs: i64);
    fn unblock(&self, ip: IpAddr);
    fn block_network(&self, _net: IpNet, _ttl_secs: i64) {}
    fn block_many(&self, entries: &[(IpAddr, i64)]) {
        for (ip, ttl_secs) in entries {
            self.block(*ip, *ttl_secs);
        }
    }
    fn unblock_many(&self, ips: &[IpAddr]) {
        for ip in ips {
            self.unblock(*ip);
        }
    }
    fn unblock_network(&self, net: IpNet);
    fn block_range(&self, _from: u128, _to: u128, _v6: bool, _ttl_secs: i64) {}
    fn unblock_range(&self, from: u128, to: u128, v6: bool);
    fn sync_snapshot(&self, _snapshot: &KernelFilterSnapshot) {}
    fn available(&self) -> bool;
    fn name(&self) -> &'static str;
    fn status(&self) -> KernelFilterStatus {
        KernelFilterStatus {
            name: self.name(),
            available: self.available(),
            detail: String::new(),
        }
    }
}

pub struct NoopFilter;

impl KernelFilter for NoopFilter {
    fn block(&self, _ip: IpAddr, _ttl_secs: i64) {}
    fn unblock(&self, _ip: IpAddr) {}
    fn unblock_network(&self, _net: IpNet) {}
    fn unblock_range(&self, _from: u128, _to: u128, _v6: bool) {}
    fn available(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str {
        "noop"
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use serde_json::Value;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::OnceLock;
    use std::time::Duration;
    use tokio::process::Command;
    use tokio::sync::mpsc;

    const NFT_TABLE: &str = "cloud_node";
    const NFT_CHAIN: &str = "input";
    const NFT_BLOCKED_V4_SET: &str = "blocked_v4";
    const NFT_BLOCKED_V6_SET: &str = "blocked_v6";
    const NFT_QUEUE_CAPACITY: usize = 8192;
    const NFT_BATCH_LIMIT: usize = 1024;
    const NFT_BATCH_WINDOW: Duration = Duration::from_millis(50);

    #[derive(Clone, Copy)]
    enum NftOp {
        Block { ip: IpAddr, ttl_secs: i64 },
        Unblock { ip: IpAddr },
    }

    static NFT_TX: OnceLock<mpsc::Sender<NftOp>> = OnceLock::new();

    pub struct NftablesFilter;
    pub struct IptablesFilter;

    impl NftablesFilter {
        pub async fn probe() -> bool {
            Command::new("nft")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false)
        }

        pub async fn ensure_ready() -> anyhow::Result<()> {
            run_nft_allow_exists(&["add", "table", "inet", NFT_TABLE]).await?;
            run_nft_allow_exists(&[
                "add",
                "set",
                "inet",
                NFT_TABLE,
                NFT_BLOCKED_V4_SET,
                "{",
                "type",
                "ipv4_addr",
                ";",
                "flags",
                "timeout",
                ";",
                "}",
            ])
            .await?;
            run_nft_allow_exists(&[
                "add",
                "set",
                "inet",
                NFT_TABLE,
                NFT_BLOCKED_V6_SET,
                "{",
                "type",
                "ipv6_addr",
                ";",
                "flags",
                "timeout",
                ";",
                "}",
            ])
            .await?;
            run_nft_allow_exists(&[
                "add", "chain", "inet", NFT_TABLE, NFT_CHAIN, "{", "type", "filter", "hook",
                "input", "priority", "-100", ";", "policy", "accept", ";", "}",
            ])
            .await?;
            ensure_nft_rule(
                "ip saddr @blocked_v4 drop",
                &[
                    "add",
                    "rule",
                    "inet",
                    NFT_TABLE,
                    NFT_CHAIN,
                    "ip",
                    "saddr",
                    "@blocked_v4",
                    "drop",
                ],
            )
            .await?;
            ensure_nft_rule(
                "ip6 saddr @blocked_v6 drop",
                &[
                    "add",
                    "rule",
                    "inet",
                    NFT_TABLE,
                    NFT_CHAIN,
                    "ip6",
                    "saddr",
                    "@blocked_v6",
                    "drop",
                ],
            )
            .await?;

            run_nft(&["list", "set", "inet", NFT_TABLE, NFT_BLOCKED_V4_SET]).await?;
            run_nft(&["list", "set", "inet", NFT_TABLE, NFT_BLOCKED_V6_SET]).await?;
            Ok(())
        }

        pub async fn blocked_ips() -> anyhow::Result<Vec<IpAddr>> {
            let mut ips = BTreeSet::new();
            for set_name in [NFT_BLOCKED_V4_SET, NFT_BLOCKED_V6_SET] {
                let output = Command::new("nft")
                    .args(["-j", "list", "set", "inet", NFT_TABLE, set_name])
                    .output()
                    .await?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("No such file or directory")
                        || stderr.contains("No such file")
                        || stderr.contains("does not exist")
                    {
                        continue;
                    }
                    anyhow::bail!("nft list set {} failed: {}", set_name, stderr.trim());
                }
                let value: Value = serde_json::from_slice(&output.stdout)?;
                collect_ip_values(&value, &mut ips);
            }
            Ok(ips.into_iter().collect())
        }
    }

    impl IptablesFilter {
        pub async fn probe() -> bool {
            Command::new("iptables")
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false)
        }
    }

    impl KernelFilter for NftablesFilter {
        fn block(&self, ip: IpAddr, ttl_secs: i64) {
            enqueue_nft_op(NftOp::Block { ip, ttl_secs });
        }

        fn unblock(&self, ip: IpAddr) {
            enqueue_nft_op(NftOp::Unblock { ip });
        }

        fn unblock_network(&self, net: IpNet) {
            tokio::spawn(async move {
                let Ok(ips) = NftablesFilter::blocked_ips().await else {
                    return;
                };
                for ip in ips.into_iter().filter(|ip| net.contains(ip)) {
                    let ip_str = ip.to_string();
                    let set_name = nft_set_for_ip(ip);
                    let args = [
                        "delete", "element", "inet", NFT_TABLE, set_name, "{", &ip_str, "}",
                    ];
                    if let Err(err) = run_nft_ignore_missing(&args).await {
                        tracing::warn!("nftables unblock failed for {}: {}", ip_str, err);
                    }
                }
            });
        }

        fn unblock_range(&self, from: u128, to: u128, v6: bool) {
            tokio::spawn(async move {
                let Ok(ips) = NftablesFilter::blocked_ips().await else {
                    return;
                };
                for ip in ips.into_iter().filter(|ip| ip_in_range(*ip, from, to, v6)) {
                    let ip_str = ip.to_string();
                    let set_name = nft_set_for_ip(ip);
                    let args = [
                        "delete", "element", "inet", NFT_TABLE, set_name, "{", &ip_str, "}",
                    ];
                    if let Err(err) = run_nft_ignore_missing(&args).await {
                        tracing::warn!("nftables unblock failed for {}: {}", ip_str, err);
                    }
                }
            });
        }

        fn available(&self) -> bool {
            true
        }

        fn name(&self) -> &'static str {
            "nftables"
        }
    }

    impl KernelFilter for IptablesFilter {
        fn block(&self, ip: IpAddr, ttl_secs: i64) {
            let ip_str = ip.to_string();
            let ttl = ttl_secs.to_string();
            tokio::spawn(async move {
                let out = Command::new("iptables")
                    .args([
                        "-I",
                        "INPUT",
                        "-s",
                        &ip_str,
                        "-j",
                        "DROP",
                        "-m",
                        "comment",
                        "--comment",
                        &format!("waf_ttl={}", ttl),
                    ])
                    .output()
                    .await;
                if let Ok(out) = out {
                    if !out.status.success() {
                        tracing::trace!(
                            stderr = %String::from_utf8_lossy(&out.stderr),
                            "iptables block failed"
                        );
                    }
                }
            });
        }

        fn unblock(&self, ip: IpAddr) {
            let ip_str = ip.to_string();
            tokio::spawn(async move {
                let out = Command::new("iptables")
                    .args(["-D", "INPUT", "-s", &ip_str, "-j", "DROP"])
                    .output()
                    .await;
                if let Ok(out) = out {
                    if !out.status.success() {
                        tracing::trace!(
                            stderr = %String::from_utf8_lossy(&out.stderr),
                            "iptables unblock failed"
                        );
                    }
                }
            });
        }

        fn unblock_network(&self, _net: IpNet) {}
        fn unblock_range(&self, _from: u128, _to: u128, _v6: bool) {}

        fn available(&self) -> bool {
            true
        }

        fn name(&self) -> &'static str {
            "iptables"
        }
    }

    fn nft_set_for_ip(ip: IpAddr) -> &'static str {
        match ip {
            IpAddr::V4(_) => NFT_BLOCKED_V4_SET,
            IpAddr::V6(_) => NFT_BLOCKED_V6_SET,
        }
    }

    fn enqueue_nft_op(op: NftOp) {
        let sender = NFT_TX.get_or_init(|| {
            let (tx, rx) = mpsc::channel(NFT_QUEUE_CAPACITY);
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn(nft_worker(rx));
                }
                Err(err) => {
                    tracing::warn!("nftables worker not started: {}", err);
                }
            }
            tx
        });
        if sender.try_send(op).is_err() {
            tracing::warn!("nftables sync queue full; kernel firewall update skipped");
            crate::logging::report_node_log(
                "warn".to_string(),
                "firewall_kernel_sync".to_string(),
                "status=\"queue_full\" reason=\"nftables bounded queue is full\"".to_string(),
                0,
            );
        }
    }

    async fn nft_worker(mut rx: mpsc::Receiver<NftOp>) {
        while let Some(first) = rx.recv().await {
            let mut pending = HashMap::<IpAddr, NftOp>::new();
            merge_nft_op(&mut pending, first);
            let delay = tokio::time::sleep(NFT_BATCH_WINDOW);
            tokio::pin!(delay);
            loop {
                tokio::select! {
                    _ = &mut delay => break,
                    op = rx.recv() => {
                        match op {
                            Some(op) => {
                                merge_nft_op(&mut pending, op);
                                if pending.len() >= NFT_BATCH_LIMIT {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            if let Err(err) = flush_nft_ops(pending).await {
                tracing::warn!("nftables batch sync failed: {}", err);
                crate::logging::report_node_log(
                    "warn".to_string(),
                    "firewall_kernel_sync".to_string(),
                    format!("status=\"failed\" reason=\"{}\"", err),
                    0,
                );
            }
        }
    }

    fn merge_nft_op(pending: &mut HashMap<IpAddr, NftOp>, op: NftOp) {
        let ip = match op {
            NftOp::Block { ip, .. } | NftOp::Unblock { ip } => ip,
        };
        pending.insert(ip, op);
    }

    async fn flush_nft_ops(pending: HashMap<IpAddr, NftOp>) -> anyhow::Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        NftablesFilter::ensure_ready().await?;
        for op in pending.into_values() {
            match op {
                NftOp::Block { ip, ttl_secs } => {
                    let ip_str = ip.to_string();
                    let ttl = format!("{}s", ttl_secs.max(1));
                    let set_name = nft_set_for_ip(ip);
                    let args = [
                        "add", "element", "inet", NFT_TABLE, set_name, "{", &ip_str, "timeout",
                        &ttl, "}",
                    ];
                    if let Err(err) = run_nft_allow_exists(&args).await {
                        tracing::warn!("nftables block failed for {}: {}", ip_str, err);
                    }
                }
                NftOp::Unblock { ip } => {
                    let ip_str = ip.to_string();
                    let set_name = nft_set_for_ip(ip);
                    let args = [
                        "delete", "element", "inet", NFT_TABLE, set_name, "{", &ip_str, "}",
                    ];
                    if let Err(err) = run_nft_ignore_missing(&args).await {
                        tracing::warn!("nftables unblock failed for {}: {}", ip_str, err);
                    }
                }
            }
        }
        Ok(())
    }

    async fn ensure_nft_rule(needle: &str, args: &[&str]) -> anyhow::Result<()> {
        let output = Command::new("nft")
            .args(["list", "chain", "inet", NFT_TABLE, NFT_CHAIN])
            .output()
            .await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && stdout.contains(needle) {
            return Ok(());
        }
        run_nft(args).await.map(|_| ())
    }

    async fn run_nft(args: &[&str]) -> anyhow::Result<String> {
        let output = Command::new("nft").args(args).output().await?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
    }

    async fn run_nft_allow_exists(args: &[&str]) -> anyhow::Result<()> {
        match run_nft(args).await {
            Ok(_) => Ok(()),
            Err(err) => {
                let message = err.to_string();
                if message.contains("File exists") || message.contains("already exists") {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn run_nft_ignore_missing(args: &[&str]) -> anyhow::Result<()> {
        match run_nft(args).await {
            Ok(_) => Ok(()),
            Err(err) => {
                let message = err.to_string();
                if message.contains("No such file")
                    || message.contains("No such file or directory")
                    || message.contains("does not exist")
                    || message.contains("Could not process rule")
                {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    fn collect_ip_values(value: &Value, ips: &mut BTreeSet<IpAddr>) {
        match value {
            Value::String(value) => {
                if let Ok(ip) = value.parse::<IpAddr>() {
                    ips.insert(ip);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_ip_values(item, ips);
                }
            }
            Value::Object(map) => {
                for value in map.values() {
                    collect_ip_values(value, ips);
                }
            }
            _ => {}
        }
    }

    fn ip_in_range(ip: IpAddr, from: u128, to: u128, v6: bool) -> bool {
        match (ip, v6) {
            (IpAddr::V4(v4), false) => {
                let n = u32::from_be_bytes(v4.octets()) as u128;
                n >= from && n <= to
            }
            (IpAddr::V6(v6_addr), true) => {
                let n = u128::from_be_bytes(v6_addr.octets());
                n >= from && n <= to
            }
            _ => false,
        }
    }
}

pub async fn build_filter(mode: Option<&str>) -> Box<dyn KernelFilter> {
    match mode {
        #[cfg(target_os = "linux")]
        Some("xdp") => match crate::xdp::build_kernel_filter().await {
            Some(filter) => filter,
            None => Box::new(NoopFilter),
        },
        #[cfg(target_os = "linux")]
        Some("nftables") => {
            if linux::NftablesFilter::probe().await {
                match linux::NftablesFilter::ensure_ready().await {
                    Ok(()) => return Box::new(linux::NftablesFilter),
                    Err(err) => tracing::warn!("nftables kernel firewall unavailable: {}", err),
                }
            }
            Box::new(NoopFilter)
        }
        #[cfg(target_os = "linux")]
        Some("iptables") => {
            if linux::IptablesFilter::probe().await {
                return Box::new(linux::IptablesFilter);
            }
            Box::new(NoopFilter)
        }
        #[cfg(target_os = "linux")]
        Some("auto") | None => {
            if let Some(filter) = crate::xdp::build_kernel_filter().await {
                return filter;
            }
            if linux::NftablesFilter::probe().await {
                match linux::NftablesFilter::ensure_ready().await {
                    Ok(()) => return Box::new(linux::NftablesFilter),
                    Err(err) => tracing::warn!("nftables kernel firewall unavailable: {}", err),
                }
            }
            if linux::IptablesFilter::probe().await {
                return Box::new(linux::IptablesFilter);
            }
            Box::new(NoopFilter)
        }
        _ => Box::new(NoopFilter),
    }
}

pub async fn ensure_nftables() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::NftablesFilter::ensure_ready().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("nftables is only supported on Linux")
    }
}

pub async fn nftables_blocked_ips() -> anyhow::Result<Vec<IpAddr>> {
    #[cfg(target_os = "linux")]
    {
        linux::NftablesFilter::blocked_ips().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn nftables_batch_sync_trait_defaults_are_compatible() {
        let filter = NoopFilter;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        filter.block_many(&[(ip, 60)]);
        filter.unblock_many(&[ip]);
        assert!(!filter.available());
    }
}
