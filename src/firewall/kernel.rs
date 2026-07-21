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
    fn allow(&self, ip: IpAddr, ttl_secs: i64) {
        self.unblock(ip);
        let _ = ttl_secs;
    }
    fn unallow(&self, _ip: IpAddr) {}
    fn block_network(&self, _net: IpNet, _ttl_secs: i64) {}
    fn allow_network(&self, net: IpNet, ttl_secs: i64) {
        self.unblock_network(net);
        let _ = ttl_secs;
    }
    fn unallow_network(&self, _net: IpNet) {}
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
    fn allow_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
        self.unblock_range(from, to, v6);
        let _ = ttl_secs;
    }
    fn unallow_range(&self, _from: u128, _to: u128, _v6: bool) {}
    fn unblock_range(&self, from: u128, to: u128, v6: bool);
    fn sync_snapshot(&self, snapshot: &KernelFilterSnapshot) {
        let now = crate::utils::time::now_timestamp();
        for (ip, expires_at) in &snapshot.blocked_ips {
            let ttl_secs = expires_at.saturating_sub(now);
            if ttl_secs > 0 {
                self.block(*ip, ttl_secs);
            }
        }
        for (net, expires_at) in &snapshot.blocked_networks {
            let ttl_secs = expires_at.saturating_sub(now);
            if ttl_secs > 0 {
                self.block_network(*net, ttl_secs);
            }
        }
        for range in &snapshot.blocked_ranges {
            let ttl_secs = range.expires_at.saturating_sub(now);
            if ttl_secs > 0 {
                self.block_range(range.from, range.to, range.v6, ttl_secs);
            }
        }
        for (ip, expires_at) in &snapshot.allowed_ips {
            let ttl_secs = expires_at.saturating_sub(now);
            if ttl_secs > 0 {
                self.allow(*ip, ttl_secs);
            }
        }
        for (net, expires_at) in &snapshot.allowed_networks {
            let ttl_secs = expires_at.saturating_sub(now);
            if ttl_secs > 0 {
                self.allow_network(*net, ttl_secs);
            }
        }
        for range in &snapshot.allowed_ranges {
            let ttl_secs = range.expires_at.saturating_sub(now);
            if ttl_secs > 0 {
                self.allow_range(range.from, range.to, range.v6, ttl_secs);
            }
        }
    }
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
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::process::Stdio;
    use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;
    use tokio::sync::Notify;

    const NFT_TABLE: &str = "cloud_node";
    const NFT_CHAIN: &str = "input";
    const NFT_BLOCKED_V4_SET: &str = "blocked_v4";
    const NFT_BLOCKED_V6_SET: &str = "blocked_v6";
    const NFT_BLOCKED_V4_INTERVAL_SET: &str = "blocked_v4_intervals";
    const NFT_BLOCKED_V6_INTERVAL_SET: &str = "blocked_v6_intervals";
    const NFT_ALLOWED_V4_SET: &str = "allowed_v4";
    const NFT_ALLOWED_V6_SET: &str = "allowed_v6";
    const NFT_ALLOWED_V4_INTERVAL_SET: &str = "allowed_v4_intervals";
    const NFT_ALLOWED_V6_INTERVAL_SET: &str = "allowed_v6_intervals";
    const IPTABLES_CHAIN: &str = "CLOUD_NODE";
    const NFT_BATCH_WINDOW: Duration = Duration::from_millis(50);
    const NFT_QUEUE_WARNING_INTERVAL_SECS: i64 = 10;
    const IPTABLES_BATCH_WINDOW: Duration = Duration::from_millis(50);
    const IPTABLES_QUEUE_WARNING_INTERVAL_SECS: i64 = 10;
    const KERNEL_SYNC_RETRY_DELAY: Duration = Duration::from_secs(1);

    fn kernel_queue_capacity() -> usize {
        let snapshot = crate::memory_governor::MEMORY_GOVERNOR.snapshot(
            crate::memory_governor::MEMORY_GOVERNOR.pingora_worker_threads(),
        );
        let estimated_entry_bytes = std::mem::size_of::<(KernelTarget, KernelOp)>()
            .saturating_mul(4)
            .max(1) as u64;
        usize::try_from(snapshot.kernel_sync_queue_budget_bytes / estimated_entry_bytes)
            .unwrap_or(usize::MAX)
            .max(1)
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum KernelTarget {
        Ip(IpAddr),
        Network(IpNet),
        Range { from: u128, to: u128, v6: bool },
    }

    impl KernelTarget {
        fn is_v6(self) -> bool {
            match self {
                Self::Ip(ip) => ip.is_ipv6(),
                Self::Network(net) => net.addr().is_ipv6(),
                Self::Range { v6, .. } => v6,
            }
        }
    }

    #[derive(Clone, Copy)]
    enum KernelOp {
        Block {
            target: KernelTarget,
            ttl_secs: i64,
        },
        Unblock {
            target: KernelTarget,
        },
        Allow {
            target: KernelTarget,
            ttl_secs: i64,
        },
        Unallow {
            target: KernelTarget,
        },
    }

    impl KernelOp {
        fn target(self) -> KernelTarget {
            match self {
                Self::Block { target, .. }
                | Self::Unblock { target }
                | Self::Allow { target, .. }
                | Self::Unallow { target } => target,
            }
        }
    }

    #[derive(Default)]
    struct DesiredRules {
        blocked: HashMap<KernelTarget, i64>,
        allowed: HashMap<KernelTarget, i64>,
    }

    impl DesiredRules {
        fn replace_from_snapshot(&mut self, snapshot: KernelFilterSnapshot) {
            self.blocked.clear();
            self.allowed.clear();
            insert_snapshot_targets(&mut self.blocked, snapshot.blocked_ips, KernelTarget::Ip);
            insert_snapshot_targets(&mut self.allowed, snapshot.allowed_ips, KernelTarget::Ip);
            insert_snapshot_targets(
                &mut self.blocked,
                snapshot.blocked_networks,
                KernelTarget::Network,
            );
            insert_snapshot_targets(
                &mut self.allowed,
                snapshot.allowed_networks,
                KernelTarget::Network,
            );
            for range in snapshot.blocked_ranges {
                insert_target_expiry(
                    &mut self.blocked,
                    KernelTarget::Range {
                        from: range.from,
                        to: range.to,
                        v6: range.v6,
                    },
                    range.expires_at,
                );
            }
            for range in snapshot.allowed_ranges {
                insert_target_expiry(
                    &mut self.allowed,
                    KernelTarget::Range {
                        from: range.from,
                        to: range.to,
                        v6: range.v6,
                    },
                    range.expires_at,
                );
            }
        }

        fn apply_ops(&mut self, ops: HashMap<KernelTarget, KernelOp>) {
            let now = crate::utils::time::now_timestamp();
            for op in ops.into_values() {
                match op {
                    KernelOp::Block { target, ttl_secs } => {
                        self.blocked.insert(target, now.saturating_add(ttl_secs.max(1)));
                    }
                    KernelOp::Unblock { target } => {
                        self.blocked.remove(&target);
                    }
                    KernelOp::Allow { target, ttl_secs } => {
                        self.allowed.insert(target, now.saturating_add(ttl_secs.max(1)));
                    }
                    KernelOp::Unallow { target } => {
                        self.allowed.remove(&target);
                    }
                }
            }
        }

        fn retain_active(&mut self, now: i64) {
            self.blocked.retain(|_, expires_at| *expires_at > now);
            self.allowed.retain(|_, expires_at| *expires_at > now);
        }
    }

    fn insert_snapshot_targets<T, F>(
        destination: &mut HashMap<KernelTarget, i64>,
        entries: Vec<(T, i64)>,
        target: F,
    ) where
        F: Fn(T) -> KernelTarget,
    {
        for (value, expires_at) in entries {
            insert_target_expiry(destination, target(value), expires_at);
        }
    }

    fn insert_target_expiry(
        destination: &mut HashMap<KernelTarget, i64>,
        target: KernelTarget,
        expires_at: i64,
    ) {
        destination
            .entry(target)
            .and_modify(|current| *current = (*current).max(expires_at))
            .or_insert(expires_at);
    }

    #[derive(Default)]
    struct NftPending {
        snapshot: Option<KernelFilterSnapshot>,
        ops: HashMap<KernelTarget, KernelOp>,
        force_reconcile: bool,
    }

    struct NftSyncQueue {
        pending: Mutex<NftPending>,
        notify: Notify,
    }

    enum NftWork {
        Snapshot(KernelFilterSnapshot),
        Ops(HashMap<KernelTarget, KernelOp>),
        Reconcile,
    }

    #[derive(Default)]
    struct IptablesPending {
        snapshot: Option<KernelFilterSnapshot>,
        ops: HashMap<KernelTarget, KernelOp>,
        force_reconcile: bool,
    }

    struct IptablesSyncQueue {
        pending: Mutex<IptablesPending>,
        notify: Notify,
    }

    enum IptablesWork {
        Snapshot(KernelFilterSnapshot),
        Ops(HashMap<KernelTarget, KernelOp>),
        Reconcile,
    }

    static NFT_QUEUE: OnceLock<Arc<NftSyncQueue>> = OnceLock::new();
    static NFT_QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);
    static NFT_QUEUE_LAST_WARNING: AtomicI64 = AtomicI64::new(0);
    static IPTABLES_QUEUE: OnceLock<Arc<IptablesSyncQueue>> = OnceLock::new();
    static IPTABLES_QUEUE_DROPPED: AtomicU64 = AtomicU64::new(0);
    static IPTABLES_QUEUE_LAST_WARNING: AtomicI64 = AtomicI64::new(0);
    static IP6TABLES_AVAILABLE: AtomicBool = AtomicBool::new(false);
    static KERNEL_SNAPSHOT_PROVIDER: OnceLock<
        std::sync::Mutex<Option<std::sync::Arc<dyn Fn() -> KernelFilterSnapshot + Send + Sync>>>,
    > = OnceLock::new();

    pub fn set_kernel_snapshot_provider(
        provider: Option<std::sync::Arc<dyn Fn() -> KernelFilterSnapshot + Send + Sync>>,
    ) {
        let slot = KERNEL_SNAPSHOT_PROVIDER.get_or_init(|| std::sync::Mutex::new(None));
        if let Ok(mut guard) = slot.lock() {
            *guard = provider;
        }
    }

    fn load_owner_snapshot() -> Option<KernelFilterSnapshot> {
        let slot = KERNEL_SNAPSHOT_PROVIDER.get_or_init(|| std::sync::Mutex::new(None));
        let provider = slot.lock().ok()?.clone()?;
        Some(provider())
    }

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
            for (set_name, address_type, interval) in [
                (NFT_BLOCKED_V4_SET, "ipv4_addr", false),
                (NFT_BLOCKED_V6_SET, "ipv6_addr", false),
                (NFT_ALLOWED_V4_SET, "ipv4_addr", false),
                (NFT_ALLOWED_V6_SET, "ipv6_addr", false),
                (NFT_BLOCKED_V4_INTERVAL_SET, "ipv4_addr", true),
                (NFT_BLOCKED_V6_INTERVAL_SET, "ipv6_addr", true),
                (NFT_ALLOWED_V4_INTERVAL_SET, "ipv4_addr", true),
                (NFT_ALLOWED_V6_INTERVAL_SET, "ipv6_addr", true),
            ] {
                let flags = if interval { "interval,timeout" } else { "timeout" };
                run_nft_allow_exists(&[
                    "add",
                    "set",
                    "inet",
                    NFT_TABLE,
                    set_name,
                    "{",
                    "type",
                    address_type,
                    ";",
                    "flags",
                    flags,
                    ";",
                    "}",
                ])
                .await?;
            }
            run_nft_allow_exists(&[
                "add", "chain", "inet", NFT_TABLE, NFT_CHAIN, "{", "type", "filter", "hook",
                "input", "priority", "-100", ";", "policy", "accept", ";", "}",
            ])
            .await?;
            run_nft_script(&format!(
                "flush chain inet {NFT_TABLE} {NFT_CHAIN}\n\
                 add rule inet {NFT_TABLE} {NFT_CHAIN} ip saddr @{NFT_ALLOWED_V4_SET} return\n\
                 add rule inet {NFT_TABLE} {NFT_CHAIN} ip saddr @{NFT_ALLOWED_V4_INTERVAL_SET} return\n\
                 add rule inet {NFT_TABLE} {NFT_CHAIN} ip6 saddr @{NFT_ALLOWED_V6_SET} return\n\
                 add rule inet {NFT_TABLE} {NFT_CHAIN} ip6 saddr @{NFT_ALLOWED_V6_INTERVAL_SET} return\n\
                 add rule inet {NFT_TABLE} {NFT_CHAIN} ip saddr @{NFT_BLOCKED_V4_SET} drop\n\
                 add rule inet {NFT_TABLE} {NFT_CHAIN} ip saddr @{NFT_BLOCKED_V4_INTERVAL_SET} drop\n\
                 add rule inet {NFT_TABLE} {NFT_CHAIN} ip6 saddr @{NFT_BLOCKED_V6_SET} drop\n\
                 add rule inet {NFT_TABLE} {NFT_CHAIN} ip6 saddr @{NFT_BLOCKED_V6_INTERVAL_SET} drop\n"
            ))
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

        pub async fn ensure_ready() -> anyhow::Result<()> {
            ensure_iptables_chain("iptables").await?;
            let v6_available = Command::new("ip6tables")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .map(|status| status.success())
                .unwrap_or(false);
            IP6TABLES_AVAILABLE.store(v6_available, Ordering::Release);
            if v6_available {
                ensure_iptables_chain("ip6tables").await?;
            } else {
                tracing::warn!("ip6tables unavailable; IPv6 fallback firewall rules disabled");
            }
            Ok(())
        }
    }

    impl KernelFilter for NftablesFilter {
        fn block(&self, ip: IpAddr, ttl_secs: i64) {
            enqueue_nft_op(KernelOp::Block {
                target: KernelTarget::Ip(ip),
                ttl_secs,
            });
        }

        fn unblock(&self, ip: IpAddr) {
            enqueue_nft_op(KernelOp::Unblock {
                target: KernelTarget::Ip(ip),
            });
        }

        fn allow(&self, ip: IpAddr, ttl_secs: i64) {
            enqueue_nft_op(KernelOp::Allow {
                target: KernelTarget::Ip(ip),
                ttl_secs,
            });
        }

        fn unallow(&self, ip: IpAddr) {
            enqueue_nft_op(KernelOp::Unallow {
                target: KernelTarget::Ip(ip),
            });
        }

        fn block_network(&self, net: IpNet, ttl_secs: i64) {
            enqueue_nft_op(KernelOp::Block {
                target: KernelTarget::Network(net),
                ttl_secs,
            });
        }

        fn unblock_network(&self, net: IpNet) {
            enqueue_nft_op(KernelOp::Unblock {
                target: KernelTarget::Network(net),
            });
        }

        fn allow_network(&self, net: IpNet, ttl_secs: i64) {
            enqueue_nft_op(KernelOp::Allow {
                target: KernelTarget::Network(net),
                ttl_secs,
            });
        }

        fn unallow_network(&self, net: IpNet) {
            enqueue_nft_op(KernelOp::Unallow {
                target: KernelTarget::Network(net),
            });
        }

        fn block_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
            enqueue_nft_op(KernelOp::Block {
                target: KernelTarget::Range { from, to, v6 },
                ttl_secs,
            });
        }

        fn unblock_range(&self, from: u128, to: u128, v6: bool) {
            enqueue_nft_op(KernelOp::Unblock {
                target: KernelTarget::Range { from, to, v6 },
            });
        }

        fn allow_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
            enqueue_nft_op(KernelOp::Allow {
                target: KernelTarget::Range { from, to, v6 },
                ttl_secs,
            });
        }

        fn unallow_range(&self, from: u128, to: u128, v6: bool) {
            enqueue_nft_op(KernelOp::Unallow {
                target: KernelTarget::Range { from, to, v6 },
            });
        }

        fn sync_snapshot(&self, snapshot: &KernelFilterSnapshot) {
            enqueue_nft_snapshot(snapshot.clone());
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
            enqueue_iptables_op(KernelOp::Block {
                target: KernelTarget::Ip(ip),
                ttl_secs,
            });
        }

        fn unblock(&self, ip: IpAddr) {
            enqueue_iptables_op(KernelOp::Unblock {
                target: KernelTarget::Ip(ip),
            });
        }

        fn allow(&self, ip: IpAddr, ttl_secs: i64) {
            enqueue_iptables_op(KernelOp::Allow {
                target: KernelTarget::Ip(ip),
                ttl_secs,
            });
        }

        fn unallow(&self, ip: IpAddr) {
            enqueue_iptables_op(KernelOp::Unallow {
                target: KernelTarget::Ip(ip),
            });
        }

        fn block_network(&self, net: IpNet, ttl_secs: i64) {
            enqueue_iptables_op(KernelOp::Block {
                target: KernelTarget::Network(net),
                ttl_secs,
            });
        }

        fn unblock_network(&self, net: IpNet) {
            enqueue_iptables_op(KernelOp::Unblock {
                target: KernelTarget::Network(net),
            });
        }

        fn allow_network(&self, net: IpNet, ttl_secs: i64) {
            enqueue_iptables_op(KernelOp::Allow {
                target: KernelTarget::Network(net),
                ttl_secs,
            });
        }

        fn unallow_network(&self, net: IpNet) {
            enqueue_iptables_op(KernelOp::Unallow {
                target: KernelTarget::Network(net),
            });
        }

        fn block_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
            enqueue_iptables_op(KernelOp::Block {
                target: KernelTarget::Range { from, to, v6 },
                ttl_secs,
            });
        }

        fn unblock_range(&self, from: u128, to: u128, v6: bool) {
            enqueue_iptables_op(KernelOp::Unblock {
                target: KernelTarget::Range { from, to, v6 },
            });
        }

        fn allow_range(&self, from: u128, to: u128, v6: bool, ttl_secs: i64) {
            enqueue_iptables_op(KernelOp::Allow {
                target: KernelTarget::Range { from, to, v6 },
                ttl_secs,
            });
        }

        fn unallow_range(&self, from: u128, to: u128, v6: bool) {
            enqueue_iptables_op(KernelOp::Unallow {
                target: KernelTarget::Range { from, to, v6 },
            });
        }

        fn sync_snapshot(&self, snapshot: &KernelFilterSnapshot) {
            enqueue_iptables_snapshot(snapshot.clone());
        }

        fn available(&self) -> bool {
            true
        }

        fn name(&self) -> &'static str {
            "iptables"
        }
    }

    fn enqueue_nft_op(op: KernelOp) {
        let queue = nft_sync_queue();
        let target = op.target();
        let accepted = {
            let mut pending = queue
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if pending.ops.len() >= kernel_queue_capacity() && !pending.ops.contains_key(&target) {
                // Preserve the latest desired image via authoritative reconcile instead of
                // silently dropping a unique target update under burst pressure.
                pending.force_reconcile = true;
                pending.ops.clear();
                false
            } else {
                pending.ops.insert(target, op);
                true
            }
        };
        if accepted {
            queue.notify.notify_one();
        } else {
            queue.notify.notify_one();
            warn_nft_queue_full();
        }
    }

    fn enqueue_nft_snapshot(snapshot: KernelFilterSnapshot) {
        let queue = nft_sync_queue();
        {
            let mut pending = queue
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.snapshot = Some(snapshot);
            pending.ops.clear();
        }
        queue.notify.notify_one();
    }

    fn nft_sync_queue() -> &'static Arc<NftSyncQueue> {
        NFT_QUEUE.get_or_init(|| {
            let queue = Arc::new(NftSyncQueue {
                pending: Mutex::new(NftPending::default()),
                notify: Notify::new(),
            });
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn(nft_worker(Arc::clone(&queue)));
                }
                Err(err) => {
                    tracing::warn!("nftables worker not started: {}", err);
                }
            }
            queue
        })
    }

    fn warn_nft_queue_full() {
        crate::pipeline_metrics::increment(crate::pipeline_metrics::PipelineCounter::KernelSyncCoalesced);
        NFT_QUEUE_DROPPED.fetch_add(1, Ordering::Relaxed);
        let now = crate::utils::time::now_timestamp();
        let last = NFT_QUEUE_LAST_WARNING.load(Ordering::Relaxed);
        if now.saturating_sub(last) < NFT_QUEUE_WARNING_INTERVAL_SECS
            || NFT_QUEUE_LAST_WARNING
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let dropped = NFT_QUEUE_DROPPED.swap(0, Ordering::AcqRel);
        tracing::warn!(
            dropped,
            capacity = kernel_queue_capacity(),
            "nftables sync queue full; converting unique updates into authoritative reconcile"
        );
        crate::logging::report_node_log(
            "warn".to_string(),
            "firewall_kernel_sync".to_string(),
            format!(
                "status=\"queue_full\" dropped=\"{}\" capacity=\"{}\"",
                dropped, kernel_queue_capacity()
            ),
            0,
        );
    }

    fn take_nft_work(queue: &NftSyncQueue) -> Option<NftWork> {
        let mut pending = queue
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(snapshot) = pending.snapshot.take() {
            pending.force_reconcile = false;
            pending.ops.clear();
            return Some(NftWork::Snapshot(snapshot));
        }
        if pending.force_reconcile {
            pending.force_reconcile = false;
            pending.ops.clear();
            return Some(NftWork::Reconcile);
        }
        if pending.ops.is_empty() {
            return None;
        }
        Some(NftWork::Ops(std::mem::take(&mut pending.ops)))
    }

    async fn nft_worker(queue: Arc<NftSyncQueue>) {
        let mut desired = DesiredRules::default();
        let mut retry_pending = false;
        loop {
            let expiry = tokio::time::sleep(next_expiry_delay(&desired));
            tokio::pin!(expiry);
            tokio::select! {
                _ = queue.notify.notified() => {}
                _ = &mut expiry => retry_pending = true,
            }
            tokio::time::sleep(NFT_BATCH_WINDOW).await;
            let mut changed = retry_pending;
            retry_pending = false;
            while let Some(work) = take_nft_work(&queue) {
                match work {
                    NftWork::Snapshot(snapshot) => desired.replace_from_snapshot(snapshot),
                    NftWork::Ops(pending) => desired.apply_ops(pending),
                    NftWork::Reconcile => {
                        if let Some(snapshot) = load_owner_snapshot() {
                            desired.replace_from_snapshot(snapshot);
                        } else {
                            // No owner provider yet; keep current desired image and
                            // re-apply it so batch apply recovers after queue saturation.
                        }
                    }
                }
                changed = true;
            }
            if changed && let Err(err) = replace_nft_rules(&mut desired).await {
                crate::pipeline_metrics::increment(
                    crate::pipeline_metrics::PipelineCounter::KernelSyncFailed,
                );
                tracing::warn!("nftables batch sync failed: {}", err);
                crate::logging::report_node_log(
                    "warn".to_string(),
                    "firewall_kernel_sync".to_string(),
                    format!("status=\"failed\" reason=\"{}\"", err),
                    0,
                );
                tokio::time::sleep(KERNEL_SYNC_RETRY_DELAY).await;
                retry_pending = true;
                queue.notify.notify_one();
                continue;
            }
        }
    }

    async fn replace_nft_rules(desired: &mut DesiredRules) -> anyhow::Result<()> {
        let now = crate::utils::time::now_timestamp();
        desired.retain_active(now);

        let mut script = format!(
            "flush set inet {NFT_TABLE} {NFT_BLOCKED_V4_SET}\n\
             flush set inet {NFT_TABLE} {NFT_BLOCKED_V6_SET}\n\
             flush set inet {NFT_TABLE} {NFT_BLOCKED_V4_INTERVAL_SET}\n\
             flush set inet {NFT_TABLE} {NFT_BLOCKED_V6_INTERVAL_SET}\n\
             flush set inet {NFT_TABLE} {NFT_ALLOWED_V4_SET}\n\
             flush set inet {NFT_TABLE} {NFT_ALLOWED_V6_SET}\n\
             flush set inet {NFT_TABLE} {NFT_ALLOWED_V4_INTERVAL_SET}\n\
             flush set inet {NFT_TABLE} {NFT_ALLOWED_V6_INTERVAL_SET}\n"
        );
        append_nft_exact_set(
            &mut script,
            NFT_BLOCKED_V4_SET,
            &exact_ip_entries(&desired.blocked, false),
            now,
        );
        append_nft_exact_set(
            &mut script,
            NFT_BLOCKED_V6_SET,
            &exact_ip_entries(&desired.blocked, true),
            now,
        );
        append_nft_interval_set(
            &mut script,
            NFT_BLOCKED_V4_INTERVAL_SET,
            &canonical_intervals(&desired.blocked, false, now),
            false,
            now,
        );
        append_nft_interval_set(
            &mut script,
            NFT_BLOCKED_V6_INTERVAL_SET,
            &canonical_intervals(&desired.blocked, true, now),
            true,
            now,
        );
        append_nft_exact_set(
            &mut script,
            NFT_ALLOWED_V4_SET,
            &exact_ip_entries(&desired.allowed, false),
            now,
        );
        append_nft_exact_set(
            &mut script,
            NFT_ALLOWED_V6_SET,
            &exact_ip_entries(&desired.allowed, true),
            now,
        );
        append_nft_interval_set(
            &mut script,
            NFT_ALLOWED_V4_INTERVAL_SET,
            &canonical_intervals(&desired.allowed, false, now),
            false,
            now,
        );
        append_nft_interval_set(
            &mut script,
            NFT_ALLOWED_V6_INTERVAL_SET,
            &canonical_intervals(&desired.allowed, true, now),
            true,
            now,
        );
        run_nft_script(&script).await
    }

    fn exact_ip_entries(
        rules: &HashMap<KernelTarget, i64>,
        v6: bool,
    ) -> BTreeMap<IpAddr, i64> {
        rules
            .iter()
            .filter_map(|(target, expires_at)| match target {
                KernelTarget::Ip(ip) if ip.is_ipv6() == v6 => Some((*ip, *expires_at)),
                _ => None,
            })
            .collect()
    }

    fn append_nft_exact_set(
        script: &mut String,
        set_name: &str,
        entries: &BTreeMap<IpAddr, i64>,
        now: i64,
    ) {
        if entries.is_empty() {
            return;
        }
        script.push_str(&format!("add element inet {NFT_TABLE} {set_name} {{ "));
        for (index, (ip, expires_at)) in entries.iter().enumerate() {
            if index > 0 {
                script.push_str(", ");
            }
            let ttl_secs = expires_at.saturating_sub(now).max(1);
            script.push_str(&format!("{ip} timeout {ttl_secs}s"));
        }
        script.push_str(" }\n");
    }

    #[derive(Clone, Copy, Debug)]
    struct TimedInterval {
        from: u128,
        to: u128,
        expires_at: i64,
    }

    fn canonical_intervals(
        rules: &HashMap<KernelTarget, i64>,
        v6: bool,
        now: i64,
    ) -> Vec<TimedInterval> {
        let family_max = if v6 { u128::MAX } else { u32::MAX as u128 };
        let mut events = BTreeMap::<u128, Vec<(i64, i64)>>::new();
        for (target, expires_at) in rules {
            if *expires_at <= now || target.is_v6() != v6 {
                continue;
            }
            let Some((from, to)) = target_interval(*target) else {
                continue;
            };
            events.entry(from).or_default().push((*expires_at, 1));
            if to < family_max {
                events
                    .entry(to + 1)
                    .or_default()
                    .push((*expires_at, -1));
            }
        }

        let mut active = BTreeMap::<i64, i64>::new();
        let mut segment_start = None;
        let mut result = Vec::new();
        for (position, deltas) in events {
            let before = active.keys().next_back().copied();
            for (expires_at, delta) in deltas {
                let remove = {
                    let count = active.entry(expires_at).or_default();
                    *count += delta;
                    *count <= 0
                };
                if remove {
                    active.remove(&expires_at);
                }
            }
            let after = active.keys().next_back().copied();
            if before == after {
                continue;
            }
            if let (Some(from), Some(expires_at)) = (segment_start, before)
                && position > 0
            {
                result.push(TimedInterval {
                    from,
                    to: position - 1,
                    expires_at,
                });
            }
            segment_start = after.map(|_| position);
        }
        if let (Some(from), Some(expires_at)) =
            (segment_start, active.keys().next_back().copied())
        {
            result.push(TimedInterval {
                from,
                to: family_max,
                expires_at,
            });
        }
        result
    }

    fn target_interval(target: KernelTarget) -> Option<(u128, u128)> {
        match target {
            KernelTarget::Ip(_) => None,
            KernelTarget::Range { from, to, .. } => (from <= to).then_some((from, to)),
            KernelTarget::Network(net) => {
                let prefix_len = net.prefix_len() as u32;
                let (network, bits) = match net {
                    IpNet::V4(net) => (
                        u32::from_be_bytes(net.network().octets()) as u128,
                        32,
                    ),
                    IpNet::V6(net) => (u128::from_be_bytes(net.network().octets()), 128),
                };
                let host_bits = bits - prefix_len;
                let host_mask = if host_bits == 128 {
                    u128::MAX
                } else if host_bits == 0 {
                    0
                } else {
                    (1u128 << host_bits) - 1
                };
                Some((network, network | host_mask))
            }
        }
    }

    fn append_nft_interval_set(
        script: &mut String,
        set_name: &str,
        entries: &[TimedInterval],
        v6: bool,
        now: i64,
    ) {
        if entries.is_empty() {
            return;
        }
        script.push_str(&format!("add element inet {NFT_TABLE} {set_name} {{ "));
        for (index, entry) in entries.iter().enumerate() {
            if index > 0 {
                script.push_str(", ");
            }
            let from = numeric_ip(entry.from, v6);
            let to = numeric_ip(entry.to, v6);
            let ttl_secs = entry.expires_at.saturating_sub(now).max(1);
            if entry.from == entry.to {
                script.push_str(&format!("{from} timeout {ttl_secs}s"));
            } else {
                script.push_str(&format!("{from}-{to} timeout {ttl_secs}s"));
            }
        }
        script.push_str(" }\n");
    }

    fn numeric_ip(value: u128, v6: bool) -> IpAddr {
        if v6 {
            IpAddr::V6(std::net::Ipv6Addr::from(value))
        } else {
            IpAddr::V4(std::net::Ipv4Addr::from(value as u32))
        }
    }

    fn enqueue_iptables_op(op: KernelOp) {
        let queue = iptables_sync_queue();
        let target = op.target();
        let accepted = {
            let mut pending = queue
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if pending.ops.len() >= kernel_queue_capacity()
                && !pending.ops.contains_key(&target)
            {
                pending.force_reconcile = true;
                pending.ops.clear();
                false
            } else {
                pending.ops.insert(target, op);
                true
            }
        };
        if accepted {
            queue.notify.notify_one();
        } else {
            queue.notify.notify_one();
            warn_iptables_queue_full();
        }
    }

    fn enqueue_iptables_snapshot(snapshot: KernelFilterSnapshot) {
        let queue = iptables_sync_queue();
        {
            let mut pending = queue
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            pending.snapshot = Some(snapshot);
            pending.ops.clear();
        }
        queue.notify.notify_one();
    }

    fn iptables_sync_queue() -> &'static Arc<IptablesSyncQueue> {
        IPTABLES_QUEUE.get_or_init(|| {
            let queue = Arc::new(IptablesSyncQueue {
                pending: Mutex::new(IptablesPending::default()),
                notify: Notify::new(),
            });
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn(iptables_worker(Arc::clone(&queue)));
                }
                Err(err) => {
                    tracing::warn!("iptables worker not started: {}", err);
                }
            }
            queue
        })
    }

    fn warn_iptables_queue_full() {
        crate::pipeline_metrics::increment(crate::pipeline_metrics::PipelineCounter::KernelSyncCoalesced);
        IPTABLES_QUEUE_DROPPED.fetch_add(1, Ordering::Relaxed);
        let now = crate::utils::time::now_timestamp();
        let last = IPTABLES_QUEUE_LAST_WARNING.load(Ordering::Relaxed);
        if now.saturating_sub(last) < IPTABLES_QUEUE_WARNING_INTERVAL_SECS
            || IPTABLES_QUEUE_LAST_WARNING
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let dropped = IPTABLES_QUEUE_DROPPED.swap(0, Ordering::AcqRel);
        tracing::warn!(
            dropped,
            capacity = kernel_queue_capacity(),
            "iptables sync queue full; converting unique updates into authoritative reconcile"
        );
        crate::logging::report_node_log(
            "warn".to_string(),
            "firewall_kernel_sync".to_string(),
            format!(
                "backend=\"iptables\" status=\"queue_full\" dropped=\"{}\" capacity=\"{}\"",
                dropped,
                kernel_queue_capacity()
            ),
            0,
        );
    }

    fn take_iptables_work(queue: &IptablesSyncQueue) -> Option<IptablesWork> {
        let mut pending = queue
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(snapshot) = pending.snapshot.take() {
            pending.force_reconcile = false;
            pending.ops.clear();
            return Some(IptablesWork::Snapshot(snapshot));
        }
        if pending.force_reconcile {
            pending.force_reconcile = false;
            pending.ops.clear();
            return Some(IptablesWork::Reconcile);
        }
        if pending.ops.is_empty() {
            return None;
        }
        Some(IptablesWork::Ops(std::mem::take(&mut pending.ops)))
    }

    fn next_expiry_delay(desired: &DesiredRules) -> Duration {
        let now = crate::utils::time::now_timestamp();
        let next = desired
            .blocked
            .values()
            .chain(desired.allowed.values())
            .filter(|expires_at| **expires_at > now)
            .min()
            .copied();
        match next {
            Some(expires_at) => Duration::from_secs(expires_at.saturating_sub(now).max(1) as u64),
            None => Duration::from_secs(3600),
        }
    }

    async fn iptables_worker(queue: Arc<IptablesSyncQueue>) {
        let mut desired = DesiredRules::default();
        let mut retry_pending = false;
        loop {
            let expiry = tokio::time::sleep(next_expiry_delay(&desired));
            tokio::pin!(expiry);
            tokio::select! {
                _ = queue.notify.notified() => {}
                _ = &mut expiry => retry_pending = true,
            }
            tokio::time::sleep(IPTABLES_BATCH_WINDOW).await;
            let mut changed = retry_pending;
            retry_pending = false;
            while let Some(work) = take_iptables_work(&queue) {
                match work {
                    IptablesWork::Snapshot(snapshot) => desired.replace_from_snapshot(snapshot),
                    IptablesWork::Ops(pending) => desired.apply_ops(pending),
                    IptablesWork::Reconcile => {
                        if let Some(snapshot) = load_owner_snapshot() {
                            desired.replace_from_snapshot(snapshot);
                        }
                    }
                }
                changed = true;
            }
            if changed && let Err(err) = replace_iptables_rules(&mut desired).await {
                crate::pipeline_metrics::increment(
                    crate::pipeline_metrics::PipelineCounter::KernelSyncFailed,
                );
                tracing::warn!("iptables batch sync failed: {}", err);
                crate::logging::report_node_log(
                    "warn".to_string(),
                    "firewall_kernel_sync".to_string(),
                    format!("backend=\"iptables\" status=\"failed\" reason=\"{}\"", err),
                    0,
                );
                tokio::time::sleep(KERNEL_SYNC_RETRY_DELAY).await;
                retry_pending = true;
                queue.notify.notify_one();
                continue;
            }
        }
    }

    async fn replace_iptables_rules(desired: &mut DesiredRules) -> anyhow::Result<()> {
        let now = crate::utils::time::now_timestamp();
        desired.retain_active(now);
        let v4_script = iptables_restore_script(desired, false);
        run_process_script("iptables-restore", &["--noflush", "--wait"], &v4_script).await?;
        if IP6TABLES_AVAILABLE.load(Ordering::Acquire) {
            let v6_script = iptables_restore_script(desired, true);
            run_process_script("ip6tables-restore", &["--noflush", "--wait"], &v6_script).await?;
        }
        Ok(())
    }

    fn iptables_restore_script(desired: &DesiredRules, v6: bool) -> String {
        let mut script = format!("*filter\n-F {IPTABLES_CHAIN}\n");
        append_iptables_rules(&mut script, &desired.allowed, v6, "RETURN");
        append_iptables_rules(&mut script, &desired.blocked, v6, "DROP");
        script.push_str("COMMIT\n");
        script
    }

    fn append_iptables_rules(
        script: &mut String,
        rules: &HashMap<KernelTarget, i64>,
        v6: bool,
        verdict: &str,
    ) {
        let mut rendered = rules
            .iter()
            .filter(|(target, _)| target.is_v6() == v6)
            .filter_map(|(target, expires_at)| {
                let matcher = match *target {
                    KernelTarget::Ip(ip) => format!("-s {ip}"),
                    KernelTarget::Network(net) => format!("-s {net}"),
                    KernelTarget::Range { from, to, v6 } if from <= to => format!(
                        "-m iprange --src-range {}-{}",
                        numeric_ip(from, v6),
                        numeric_ip(to, v6)
                    ),
                    KernelTarget::Range { .. } => return None,
                };
                Some(format!(
                    "-A {IPTABLES_CHAIN} {matcher} -m comment --comment cloud_node_expires={expires_at} -j {verdict}\n"
                ))
            })
            .collect::<Vec<_>>();
        rendered.sort_unstable();
        for rule in rendered {
            script.push_str(&rule);
        }
    }

    async fn ensure_iptables_chain(binary: &str) -> anyhow::Result<()> {
        run_iptables_allow_exists(binary, &["-w", "-N", IPTABLES_CHAIN]).await?;
        let check = Command::new(binary)
            .args(["-w", "-C", "INPUT", "-j", IPTABLES_CHAIN])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await?;
        if !check.success() {
            run_iptables(binary, &["-w", "-I", "INPUT", "1", "-j", IPTABLES_CHAIN]).await?;
        }
        remove_legacy_iptables_rules(binary).await?;
        Ok(())
    }

    async fn remove_legacy_iptables_rules(binary: &str) -> anyhow::Result<()> {
        let save_binary = if binary == "ip6tables" {
            "ip6tables-save"
        } else {
            "iptables-save"
        };
        let restore_binary = if binary == "ip6tables" {
            "ip6tables-restore"
        } else {
            "iptables-restore"
        };
        let output = Command::new(save_binary).args(["-t", "filter"]).output().await?;
        if !output.status.success() {
            anyhow::bail!(
                "{}: {}",
                save_binary,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let rules = String::from_utf8_lossy(&output.stdout);
        let legacy_deletes = rules
            .lines()
            .filter(|line| line.starts_with("-A INPUT ") && line.contains("waf_ttl="))
            .map(|line| line.replacen("-A INPUT ", "-D INPUT ", 1))
            .collect::<Vec<_>>();
        if legacy_deletes.is_empty() {
            return Ok(());
        }
        let mut script = String::from("*filter\n");
        for rule in legacy_deletes {
            script.push_str(&rule);
            script.push('\n');
        }
        script.push_str("COMMIT\n");
        run_process_script(restore_binary, &["--noflush", "--wait"], &script).await
    }

    async fn run_iptables(binary: &str, args: &[&str]) -> anyhow::Result<()> {
        let output = Command::new(binary).args(args).output().await?;
        if output.status.success() {
            Ok(())
        } else {
            anyhow::bail!(
                "{}: {}",
                binary,
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
    }

    async fn run_iptables_allow_exists(binary: &str, args: &[&str]) -> anyhow::Result<()> {
        match run_iptables(binary, args).await {
            Ok(()) => Ok(()),
            Err(err) if err.to_string().contains("Chain already exists") => Ok(()),
            Err(err) => Err(err),
        }
    }

    async fn run_process_script(
        binary: &str,
        args: &[&str],
        script: &str,
    ) -> anyhow::Result<()> {
        let mut child = Command::new(binary)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("{} stdin unavailable", binary))?;
        stdin.write_all(script.as_bytes()).await?;
        drop(stdin);
        let output = child.wait_with_output().await?;
        if output.status.success() {
            Ok(())
        } else {
            anyhow::bail!(
                "{}: {}",
                binary,
                String::from_utf8_lossy(&output.stderr).trim()
            )
        }
    }

    async fn run_nft_script(script: &str) -> anyhow::Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("nft stdin unavailable"))?;
        stdin.write_all(script.as_bytes()).await?;
        drop(stdin);
        let output = child.wait_with_output().await?;
        if output.status.success() {
            Ok(())
        } else {
            anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
        }
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

}

pub fn set_kernel_snapshot_provider(
    provider: Option<std::sync::Arc<dyn Fn() -> KernelFilterSnapshot + Send + Sync>>,
) {
    #[cfg(target_os = "linux")]
    {
        linux::set_kernel_snapshot_provider(provider);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = provider;
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
                match linux::IptablesFilter::ensure_ready().await {
                    Ok(()) => return Box::new(linux::IptablesFilter),
                    Err(err) => tracing::warn!("iptables kernel firewall unavailable: {}", err),
                }
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
                match linux::IptablesFilter::ensure_ready().await {
                    Ok(()) => return Box::new(linux::IptablesFilter),
                    Err(err) => tracing::warn!("iptables kernel firewall unavailable: {}", err),
                }
            }
            Box::new(NoopFilter)
        }
        _ => Box::new(NoopFilter),
    }
}

pub async fn build_non_xdp_fallback_filter() -> Box<dyn KernelFilter> {
    #[cfg(target_os = "linux")]
    {
        if linux::NftablesFilter::probe().await {
            match linux::NftablesFilter::ensure_ready().await {
                Ok(()) => return Box::new(linux::NftablesFilter),
                Err(err) => tracing::warn!("nftables fallback firewall unavailable: {}", err),
            }
        }
        if linux::IptablesFilter::probe().await {
            match linux::IptablesFilter::ensure_ready().await {
                Ok(()) => return Box::new(linux::IptablesFilter),
                Err(err) => tracing::warn!("iptables fallback firewall unavailable: {}", err),
            }
        }
    }
    Box::new(NoopFilter)
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
