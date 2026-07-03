use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    English,
    Chinese,
}

static CURRENT_LANGUAGE: AtomicU8 = AtomicU8::new(0);

impl Language {
    pub fn parse(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
        if normalized.starts_with("zh") {
            return Some(Language::Chinese);
        }
        match normalized.as_str() {
            "en" | "eng" | "english" => Some(Language::English),
            "cn" | "chinese" | "中文" | "汉语" => Some(Language::Chinese),
            _ => None,
        }
    }

    pub fn detect() -> Self {
        for name in ["CLOUD_NODE_LANG", "LC_ALL", "LANGUAGE", "LANG"] {
            if let Ok(lang) = std::env::var(name)
                && let Some(lang) = Self::parse(&lang)
            {
                return lang;
            }
        }
        Language::English
    }

    pub fn set_current(lang: Language) {
        CURRENT_LANGUAGE.store(lang.as_u8(), Ordering::Relaxed);
    }

    pub fn current() -> Self {
        match CURRENT_LANGUAGE.load(Ordering::Relaxed) {
            1 => Language::English,
            2 => Language::Chinese,
            _ => Language::detect(),
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Language::English => 1,
            Language::Chinese => 2,
        }
    }
}

const STRINGS: &[(&str, &str, &str)] = &[
    // CLI commands and options
    (
        "app.about",
        "CloudNode - High Performance Cloud Node written in Rust",
        "CloudNode - Rust 编写的高性能云节点",
    ),
    (
        "cmd.start",
        "Start the cloud node in background",
        "后台启动云节点",
    ),
    (
        "cmd.stop",
        "Stop the background cloud node",
        "停止后台云节点",
    ),
    (
        "cmd.status",
        "Check the status of the cloud node",
        "检查云节点状态",
    ),
    (
        "cmd.restart",
        "Restart the background cloud node",
        "重启后台云节点",
    ),
    (
        "cmd.install",
        "Install the cloud node as a systemd service",
        "将云节点安装为 systemd 服务",
    ),
    (
        "cmd.upgrade",
        "Upgrade the installed binary from GitHub Releases",
        "从 GitHub Releases 升级已安装的二进制文件",
    ),
    (
        "cmd.ntp",
        "Synchronize system clock with NTP servers",
        "与 NTP 服务器同步系统时钟",
    ),
    (
        "cmd.zerocopy",
        "View or change TCP/SNI relay zero-copy mode",
        "查看或更改 TCP/SNI 中继零拷贝模式",
    ),
    (
        "cmd.firewall",
        "Manage and inspect local kernel firewall state",
        "管理和检查本地内核防火墙状态",
    ),
    (
        "cmd.defense",
        "Inspect runtime L4/TCP defense state",
        "检查运行时 L4/TCP 防御状态",
    ),
    (
        "cmd.xdp",
        "Manage XDP/AF_XDP dataplane state",
        "管理 XDP/AF_XDP 数据面状态",
    ),
    ("cmd.test", "Test the configuration", "测试配置"),
    // Generic CLI output
    ("common.yes", "yes", "是"),
    ("common.no", "no", "否"),
    ("common.enabled", "enabled", "已启用"),
    ("common.disabled", "disabled", "已禁用"),
    ("common.unknown", "unknown", "未知"),
    ("common.error", "Error", "错误"),
    ("common.success", "Success", "成功"),
    (
        "common.invalid_input",
        "Invalid input, please try again",
        "输入无效，请重试",
    ),
    ("common.select", "Select", "请选择"),
    ("common.cancelled", "Cancelled.", "已取消。"),
    ("common.none", "none", "无"),
    // Top-level command output
    ("status.version", "CloudNode version", "CloudNode 版本"),
    ("status.build_time", "Build time", "构建时间"),
    (
        "status.running",
        "CloudNode is running",
        "CloudNode 正在运行",
    ),
    (
        "status.stopped",
        "CloudNode is stopped.",
        "CloudNode 已停止。",
    ),
    (
        "status.already_running",
        "CloudNode is already running",
        "CloudNode 已在运行",
    ),
    (
        "start.started",
        "CloudNode started in background",
        "CloudNode 已在后台启动",
    ),
    ("stop.stopped", "CloudNode stopped.", "CloudNode 已停止。"),
    (
        "stop.not_running",
        "CloudNode is not running.",
        "CloudNode 未运行。",
    ),
    ("stop.stopping", "Stopping CloudNode", "正在停止 CloudNode"),
    (
        "stop.force",
        "CloudNode did not stop within 20s, forcing shutdown",
        "CloudNode 20 秒内未停止，正在强制关闭",
    ),
    (
        "install.global_ok",
        "Successfully registered global command: cloud-node",
        "已成功注册全局命令：cloud-node",
    ),
    (
        "install.service_ok",
        "Successfully registered systemd service. You can now use: systemctl start cloud-node",
        "已成功注册 systemd 服务。现在可以使用：systemctl start cloud-node",
    ),
    (
        "install.linux_only",
        "Install command is currently only supported on Linux.",
        "install 命令当前仅支持 Linux。",
    ),
    (
        "systemd.managed",
        "CloudNode is managed by systemd, running",
        "CloudNode 由 systemd 管理，正在执行",
    ),
    ("test.start", "Testing configuration...", "正在测试配置..."),
    ("test.valid", "Configuration is valid.", "配置有效。"),
    ("test.relay_zero_copy", "Relay zero-copy", "中继零拷贝"),
    (
        "test.relay_copy_buffer",
        "Relay copy buffer",
        "中继复制缓冲区",
    ),
    ("test.runtime_mode", "Runtime mode", "运行模式"),
    // NTP and zero-copy
    ("ntp.title", "CloudNode NTP", "CloudNode NTP"),
    ("ntp.current_timezone", "current timezone", "当前时区"),
    (
        "ntp.keep_timezone",
        "press Enter to keep current, or type a timezone such as Asia/Shanghai",
        "按回车保留当前时区，或输入 Asia/Shanghai 等时区",
    ),
    ("ntp.timezone_prompt", "Timezone", "时区"),
    (
        "ntp.timezone_set",
        "System timezone set to",
        "系统时区已设置为",
    ),
    (
        "zerocopy.title",
        "CloudNode zero-copy relay",
        "CloudNode 零拷贝中继",
    ),
    ("zerocopy.config", "config", "配置文件"),
    ("zerocopy.current", "current zero-copy", "当前零拷贝"),
    ("zerocopy.new", "new zero-copy", "新的零拷贝"),
    ("zerocopy.copy_buffer", "copy buffer", "复制缓冲区"),
    (
        "zerocopy.no_change",
        "No change requested. Use --enable or --disable in non-interactive mode.",
        "未请求变更。非交互模式请使用 --enable 或 --disable。",
    ),
    (
        "zerocopy.confirm_write",
        "Write this relay configuration?",
        "写入此中继配置？",
    ),
    (
        "zerocopy.updated",
        "Relay configuration updated.",
        "中继配置已更新。",
    ),
    (
        "zerocopy.restart",
        "Restart cloud-node for running listeners to use the new relay mode.",
        "请重启 cloud-node，使运行中的监听器使用新的中继模式。",
    ),
    ("upgrade.proceed", "Proceed with upgrade?", "继续升级？"),
    (
        "upgrade.service_stopped",
        "cloud-node.service is installed but not active; leaving it stopped.",
        "cloud-node.service 已安装但未运行，将保持停止状态。",
    ),
    (
        "upgrade.restarting",
        "Restarting CloudNode with upgraded binary...",
        "正在使用升级后的二进制重启 CloudNode...",
    ),
    (
        "upgrade.node_stopped",
        "CloudNode is not running; leaving it stopped.",
        "CloudNode 未运行，将保持停止状态。",
    ),
    (
        "upgrade.summary",
        "CloudNode upgrade summary:",
        "CloudNode 升级摘要：",
    ),
    ("upgrade.current_version", "current version", "当前版本"),
    ("upgrade.target_version", "target version", "目标版本"),
    ("upgrade.repository", "repository", "仓库"),
    ("upgrade.asset", "asset", "资源包"),
    ("upgrade.download_url", "download URL", "下载地址"),
    ("upgrade.install_binary", "install binary", "安装路径"),
    ("upgrade.backup_dir", "backup dir", "备份目录"),
    ("upgrade.restart", "restart", "重启"),
    (
        "upgrade.dry_run",
        "Dry run only; no files will be changed.",
        "仅演练，不会修改文件。",
    ),
    (
        "upgrade.downloading",
        "Downloading release asset...",
        "正在下载发布资源包...",
    ),
    (
        "upgrade.extracting",
        "Extracting release archive...",
        "正在解压发布归档...",
    ),
    ("upgrade.backup", "Previous binary backup", "旧二进制备份"),
    (
        "upgrade.installed",
        "Installed upgraded binary",
        "已安装升级后的二进制",
    ),
    (
        "upgrade.xdp_object_installed",
        "Installed XDP eBPF object",
        "已安装 XDP eBPF 对象",
    ),
    (
        "upgrade.xdp_object_missing",
        "Release archive does not contain data/cloud-node-xdp-ebpf.o; XDP attach will remain unavailable until the object is installed.",
        "发布包不包含 data/cloud-node-xdp-ebpf.o；安装该对象前 XDP attach 仍不可用。",
    ),
    // Firewall / defense
    (
        "firewall.initialized",
        "nftables initialized: table=inet cloud_node sets=blocked_v4,blocked_v6",
        "nftables 已初始化：table=inet cloud_node sets=blocked_v4,blocked_v6",
    ),
    (
        "firewall.gc_removed",
        "firewall gc removed expired RocksDB records",
        "防火墙 GC 已删除过期 RocksDB 记录",
    ),
    (
        "firewall.title",
        "CloudNode firewall blacklist",
        "CloudNode 防火墙黑名单",
    ),
    (
        "firewall.nft_exact",
        "nftables exact IPs",
        "nftables 精确 IP",
    ),
    (
        "firewall.blacklist_exact",
        "blacklist exact IPs",
        "黑名单精确 IP",
    ),
    (
        "firewall.blacklist_targets",
        "blacklist CIDR/range targets",
        "黑名单 CIDR/范围目标",
    ),
    (
        "firewall.expired_cleaned",
        "expired RocksDB records cleaned",
        "已清理过期 RocksDB 记录",
    ),
    (
        "firewall.no_entries",
        "No exact IP entries found.",
        "未找到精确 IP 条目。",
    ),
    (
        "firewall.ip_header",
        "IP\tnftables\tblacklist",
        "IP\tnf拉黑\t黑名单",
    ),
    (
        "firewall.targets_header",
        "Blacklist CIDR/range targets",
        "黑名单 CIDR/范围目标",
    ),
    (
        "firewall.v4_aggregates",
        "IPv4 /24 aggregates",
        "IPv4 /24 聚合",
    ),
    (
        "firewall.v6_aggregates",
        "IPv6 /48 aggregates",
        "IPv6 /48 聚合",
    ),
    (
        "firewall.aggregate_header",
        "CIDR\ttotal\tnftables\tblacklist\tboth",
        "CIDR\t总数\tnf拉黑\t黑名单\t两者都有",
    ),
    (
        "defense.title",
        "CloudNode L4 defense status",
        "CloudNode L4 防御状态",
    ),
    ("defense.runtime_scope", "runtime scope", "运行时范围"),
    (
        "defense.current_snapshot",
        "current process snapshot",
        "当前进程快照",
    ),
    (
        "defense.effective_pressure",
        "effective pressure",
        "有效压力等级",
    ),
    // XDP commands
    (
        "xdp.status",
        "Print current or last persisted XDP state",
        "打印当前或最后持久化的 XDP 状态",
    ),
    (
        "xdp.doctor",
        "Validate local XDP runtime configuration and object availability",
        "验证本地 XDP 运行时配置和对象可用性",
    ),
    (
        "xdp.attach",
        "Start automatic XDP proxy takeover",
        "启动 XDP 自动代理接管",
    ),
    (
        "xdp.detach",
        "Stop XDP automatic takeover",
        "停止 XDP 自动接管",
    ),
    (
        "xdp.dump_maps",
        "Dump XDP shadow maps known to this process",
        "转储 XDP shadow maps",
    ),
    (
        "xdp.reload",
        "Detach and attach again using configs/runtime.yaml",
        "使用 configs/runtime.yaml 重新附加",
    ),
    (
        "xdp.configure",
        "Preview and save automatic XDP configuration",
        "预览并保存 XDP 自动配置",
    ),
    // XDP status
    (
        "xdp.status.title",
        "CloudNode XDP status",
        "CloudNode XDP 状态",
    ),
    ("xdp.status.enabled", "enabled", "已启用"),
    ("xdp.status.available", "available", "可用"),
    ("xdp.status.attached", "attached", "已附加"),
    ("xdp.status.attach_mode", "attach mode", "附加模式"),
    ("xdp.status.fallback", "fallback", "回退模式"),
    ("xdp.status.fallback_why", "fallback why", "回退原因"),
    ("xdp.status.proxy_ports", "proxy ports", "代理端口"),
    ("xdp.status.supported", "supported", "支持"),
    ("xdp.status.unsupported", "unsupported", "不支持"),
    ("xdp.status.proxy_ready", "proxy ready", "代理就绪"),
    ("xdp.status.redirect", "redirect", "重定向"),
    ("xdp.status.tcp_dataplane", "tcp dataplane", "TCP 数据面"),
    ("xdp.status.tcp_why", "tcp why", "TCP 原因"),
    ("xdp.status.proxy_why", "proxy why", "代理原因"),
    ("xdp.status.xsk_queues", "xsk queues", "XSK 队列"),
    ("xdp.status.ebpf_object", "eBPF object", "eBPF 对象"),
    ("xdp.status.maps", "maps", "映射表"),
    ("xdp.status.counters", "counters", "计数器"),
    ("xdp.status.interfaces", "interfaces", "接口"),
    ("xdp.status.interface", "interface", "接口"),
    ("xdp.status.xsk_queue", "xsk queue", "XSK 队列"),
    // XDP menu / wizard
    (
        "xdp.menu.title",
        "=== XDP Automatic Takeover Configuration ===",
        "=== XDP 自动接管配置 ===",
    ),
    ("xdp.menu.enable", "Enable XDP?", "启用 XDP？"),
    (
        "xdp.menu.auto_summary",
        "Automatic XDP proxy takeover preview:",
        "XDP 自动代理接管预览：",
    ),
    (
        "xdp.menu.attach_mode",
        "Select attach mode:",
        "选择附加模式：",
    ),
    (
        "xdp.menu.attach.auto",
        "auto - Auto-detect driver/SKB mode",
        "auto - 自动检测 driver/SKB 模式",
    ),
    (
        "xdp.menu.attach.drv",
        "drv - Native XDP driver mode (fastest)",
        "drv - 原生 XDP 驱动模式（最快）",
    ),
    (
        "xdp.menu.attach.skb",
        "skb - Generic SKB mode",
        "skb - 通用 SKB 模式",
    ),
    (
        "xdp.menu.fallback",
        "Select fallback mode:",
        "选择回退模式：",
    ),
    (
        "xdp.menu.fallback.pass",
        "pass - Fail open to the original socket dataplane",
        "pass - 失败时放行到原 socket 数据面",
    ),
    (
        "xdp.menu.fallback.fail_start",
        "fail-start - Refuse startup if XDP is unavailable",
        "fail-start - XDP 不可用时拒绝启动",
    ),
    (
        "xdp.menu.interface",
        "Enter network interface name (e.g. eth0):",
        "输入网络接口名称（例如 eth0）：",
    ),
    ("xdp.menu.mode", "Select interface mode:", "选择接口模式："),
    (
        "xdp.menu.mode.observe",
        "Observe - Monitor only, no filtering",
        "观察 - 仅监控，不过滤",
    ),
    (
        "xdp.menu.mode.protect",
        "Protect - Filter traffic (block/allow)",
        "防护 - 过滤流量（阻止/允许）",
    ),
    (
        "xdp.menu.mode.proxy",
        "Proxy - Redirect to userspace",
        "代理 - 重定向到用户空间",
    ),
    (
        "xdp.menu.queues",
        "Enter queue IDs (comma-separated, e.g. 0,1,2,3):",
        "输入队列 ID（逗号分隔，例如 0,1,2,3）：",
    ),
    (
        "xdp.menu.local_ips",
        "Enter local IPs for proxy filtering (comma-separated, blank for none):",
        "输入用于代理过滤的本机 IP（逗号分隔，留空表示无）：",
    ),
    (
        "xdp.menu.frame_size",
        "Enter AF_XDP frame size (1024-4096, multiple of 512):",
        "输入 AF_XDP frame size（1024-4096，且为 512 的倍数）：",
    ),
    (
        "xdp.menu.add_interface",
        "Add another interface?",
        "继续添加接口？",
    ),
    (
        "xdp.menu.proxy_ports",
        "Configure proxy ports?",
        "配置代理端口？",
    ),
    ("xdp.menu.protocol", "Select protocol:", "选择协议："),
    ("xdp.menu.protocol.http", "HTTP", "HTTP"),
    ("xdp.menu.protocol.https", "HTTPS", "HTTPS"),
    ("xdp.menu.protocol.tcp", "TCP", "TCP"),
    ("xdp.menu.protocol.udp", "UDP", "UDP"),
    ("xdp.menu.protocol.h3", "HTTP/3", "HTTP/3"),
    ("xdp.menu.port", "Enter port number:", "输入端口号："),
    ("xdp.menu.add_more", "Add more ports?", "添加更多端口？"),
    (
        "xdp.menu.save",
        "Save configuration to configs/runtime.yaml?",
        "保存配置到 configs/runtime.yaml？",
    ),
    (
        "xdp.menu.saved",
        "Configuration saved successfully!",
        "配置保存成功！",
    ),
    (
        "xdp.menu.cancelled",
        "Configuration cancelled.",
        "配置已取消。",
    ),
    (
        "xdp.menu.disabled_saved",
        "XDP will be disabled in configs/runtime.yaml.",
        "将会在 configs/runtime.yaml 中禁用 XDP。",
    ),
    (
        "xdp.menu.invalid_queue",
        "Please enter at least one valid queue ID.",
        "请至少输入一个有效队列 ID。",
    ),
    (
        "xdp.menu.invalid_port",
        "Please enter a valid port from 1 to 65535.",
        "请输入 1 到 65535 的有效端口。",
    ),
    ("xdp.menu.invalid_ip", "Invalid IP address", "无效 IP 地址"),
];

pub fn t(key: &str) -> &str {
    let lang = Language::current();
    for &(k, en, zh) in STRINGS {
        if k == key {
            return if lang == Language::Chinese { zh } else { en };
        }
    }
    key
}
