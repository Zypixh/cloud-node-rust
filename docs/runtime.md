# 运行时说明

CloudNode Rust 的运行时由一个主进程和多个异步后台任务组成。主进程负责监听网络端口、维护配置快照、处理请求和启动上报任务；后台任务负责控制面同步、缓存维护、证书更新、统计上报和本地监控。

## 启动流程

启动过程大致如下：

1. 创建 `configs`、`data`、`logs` 目录。
2. 通过 `data/cloud-node.pid` 和 `flock` 保证单实例运行。
3. 初始化日志系统。
4. 加载 `configs/api_node.yaml`。
5. 初始化 `ConfigStore`、WAF 状态、证书选择器、健康检查管理器。
6. 启动控制面同步任务。
7. 启动 HTTP、HTTPS、HTTP/3、TCP、UDP 等监听器。
8. 如 `configs/runtime.yaml` 显式启用 XDP，则初始化 XDP/AF_XDP manager、maps、XSK queues 和 fallback 状态。
9. 启动缓存、统计、日志上传和证书同步后台任务。
10. 如指定 `--monitor-port`，启动本地性能监控页面。

默认不带子命令时以前台方式运行。已注册 systemd unit 时，`start/restart` 会优先委托给 `systemctl`；未注册 systemd 时，`start` 子命令会以单 fork 方式进入后台。

## CLI 命令

```bash
cloud-node start
cloud-node stop
cloud-node restart
cloud-node status
cloud-node install
cloud-node upgrade
cloud-node ntp
cloud-node firewall list
cloud-node firewall init
cloud-node xdp status
cloud-node xdp doctor
cloud-node xdp attach
cloud-node xdp detach
cloud-node test
```

全局参数：

```bash
cloud-node --monitor-port 8888
cloud-node --monitor-port 8888 --monitor-clear
```

命令说明：

- `start`：启动节点；已注册 systemd unit 时委托 `systemctl start`，否则使用内置后台进程管理。
- `stop`：停止后台节点。
- `restart`：先停止再启动。
- `status`：读取 PID 文件和文件锁判断节点状态。
- `install`：注册 `/usr/bin/cloud-node` wrapper 和 systemd service。
- `upgrade`：从 GitHub Release 下载匹配当前 CPU/架构的最新版或指定版本，确认后备份并替换当前二进制。
- `ntp`：交互式或非交互式设置系统时区，并按内置 NTP 源校准系统时钟；守护进程自动 NTP 只校准程序内部偏移。
- `firewall init`：初始化本地 `nftables` table/set/chain/drop rule。
- `firewall list`：合并展示本地 `nftables` 精确 IP 和 RocksDB 本地运行时黑名单；条目较多时按 IPv4 `/24`、IPv6 `/48` 聚合。
- `firewall gc`：清理 RocksDB 中已过期的本地运行时封禁记录。
- `xdp status`：查看当前或上次持久化的 XDP/AF_XDP attach、XSK、map 和 counter 状态。
- `xdp doctor`：校验本地 runtime XDP 配置、eBPF 对象、权限和 proxy 能力。
- `xdp attach` / `xdp detach` / `xdp reload`：按 `configs/runtime.yaml` 管理当前进程的 XDP attachment。
- `xdp dump-maps`：输出当前进程维护的 XDP shadow maps 和 proxy 端口状态。
- `test`：验证 `configs/api_node.yaml` 是否可解析。

`upgrade` 默认使用交互式确认，并在成功替换后重启正在运行的 `cloud-node.service` 或内置后台进程：

```bash
cloud-node upgrade
```

自动化场景可通过参数完整输入，跳过交互确认：

```bash
cloud-node upgrade --yes
cloud-node upgrade --version v1.1.7 --yes
cloud-node upgrade --version latest --github-mirror https://gh-proxy.example --yes
cloud-node upgrade --version v1.1.7 --github-base-url https://github.example.com --repo Zypixh/cloud-node-rust --yes
```

常用参数：

- `--version`：目标版本，默认 `latest`；可传 `v1.1.7` 或 `1.1.7`。
- `--repo`：GitHub 仓库，默认 `Zypixh/cloud-node-rust`。
- `--github-base-url`：GitHub 或 GitHub Enterprise 基础地址，默认 `https://github.com`。
- `--github-mirror`：下载镜像/代理地址；如果包含 `{url}`，会用原始 GitHub 下载地址替换该占位符。
- `--asset`：手动指定 release asset 文件名，覆盖自动 CPU/架构选择。
- `--install-binary`：手动指定要替换的本地二进制路径，默认当前执行文件。
- `--backup-dir`：旧二进制备份目录，默认 `/var/backups/cloud-node-rust-upgrade`。
- `--yes` / `--non-interactive`：跳过确认，适合脚本和控制面调用。
- `--no-restart`：只替换二进制，不重启服务。
- `--dry-run`：只打印升级计划，不下载、不替换、不重启。

## 进程和目录

默认运行目录采用 GoEdge/FlexCDN 风格的三类目录：

- `configs/api_node.yaml`：API 节点连接配置。
- `data/cloud-node.pid`：后台进程 PID 文件。
- `data/state.json`：部分运行状态持久化。
- `data/cloud-node-xdp-ebpf.o`：`cargo xtask build-ebpf` 生成的 XDP eBPF 对象。
- `data/blocked_ips.json`：旧版本地封禁快照，仅作为一次性迁移输入；迁移到 RocksDB 成功后会自动删除。
- `data/metrics.db`：统计、缓存元数据和本地运行时防火墙封禁状态持久化。
- `data/cache`：默认磁盘缓存目录。
- `data/GeoLite2-City.mmdb`、`data/GeoLite2-ASN.mmdb`：GeoIP 数据库。
- `logs/run.log`：节点运行日志；systemd 和内置后台模式都会追加写入。

生产部署时应保持工作目录稳定。旧版 `../data/*`、根目录 `api_node.yaml` 和工作目录下的 GeoIP 文件仅作为迁移 fallback 读取。

## 异步任务

运行时主要依赖 Tokio 和 Pingora 的异步执行模型。后台任务包含：

- API 节点连接和配置同步。
- 站点配置周期更新。
- 节点任务同步。
- 缓存任务同步和缓存清理。
- 证书和 OCSP 同步。
- 源站健康检查和失败状态自动恢复。
- 访问日志和节点日志上传。
- 实时统计、日统计、Top IP 和节点值上报。
- 本地性能监控采样。

请求热路径避免执行慢速磁盘 I/O、同步 DNS、全表扫描和大对象深拷贝。WebP 图片转换只在缓存写入前执行一次，后续同一 WebP 变体命中缓存时不再重复转换。L2 磁盘缓存命中会优先使用内存索引；小对象返回内存命中以保持 Fast L1 晋升，大对象按块从文件读取，压缩对象支持流式 zstd 解压，避免大文件一次性读入内存。HTML/CSS/JS 优化、加密等响应体转换有大小边界，超过阈值时直接透传。

WAF CC 计数器使用固定窗口滚动桶，单次更新不再对同一 key 的历史时间戳列表做线性 retain。动态 WAF 状态表会受内存治理容量约束；容量满且清理后仍无法释放空间时，新的 per-IP rate limiter、滚动计数器和带宽计数器会 fail-open 并限频告警，避免把状态内存耗尽扩大成全站误拦截。L4 强防的高置信事件另有独立保留计数器，通用滚动计数器容量满时不会让 TCP/UDP/H3 admission reject、单 IP 活跃连接超限、QUIC pending/reassembly reject 等事件 fail-open。UDP/QUIC 会话活动时间使用原子时间戳更新，TLS 证书快照和 OCSP 数据走无锁读路径，上游 TLS 连接器和客户端证书解析结果会复用，减少高并发握手路径的重复初始化。

项目提供 `targeted_hotspots_bench` 用于服务器侧观察 Fast L1、响应体 CPU 处理、TLS selector、UA analyzer cache 和 WAF verifier 等热点。常规开发验证使用 `cargo check --all-targets`，bench 建议只在目标服务器上运行。

## L4 防御和进程日志

进程日志定位为系统和组件健康日志，不承载单次访问结果。可预期的请求级和连接级结果，例如上游超时、拒连、reset、下游断开、错误页回写失败、请求解析失败、客户端 TLS/HTTP2 握手失败，默认不打印 `error`/`warn`，由访问日志的状态码、源站信息、`errors` 字段和指标承接。真正的监听器退出、bind/accept 连续致命失败、worker 异常停止、存储或配置不可恢复错误仍保留进程 `error`。

L4 自动防御复用已有 `emptyConnectionFlood` 配置作为总开关。开启条件是集群全局防火墙策略里 `emptyConnectionFlood.isOn=true` 且 `maxEmptyConnections>0`；关闭时节点仍执行本地 admission、drop、timeout 和指标，但不会自动上报黑名单。

防御覆盖所有外部入口：

- HTTP/HTTPS：accept 前检查集群黑名单，使用共享 TCP-like per-IP active tracker，pressure 下缩短首包、TLS ClientHello 和 HTTP header deadline。
- TCP/TCP-TLS/SNI passthrough：连接 admission、单 IP 活跃连接、慢首包、慢 ClientHello、压力态 idle close 都进入 L4 事件；源站连接失败和源站超时不作为攻击。
- UDP passthrough：新 session flood、admission reject 和 session queue full 计入事件；正常 idle cleanup 不计攻击。
- QUIC passthrough/HY2/HTTP/3：QUIC incomplete ClientHello、pending/reassembly budget reject、new route flood、H3 admission reject 计入事件；有效 QUIC ClientHello 命中 `@quic` passthrough server 时不要求 ALPN 是 H3，也不计 H3 reject。

XDP protect/proxy 启用时，WAF 封禁快照会同步到 XDP maps，白名单优先于封禁。proxy 命中端口的包进入 AF_XDP 后仍复用 L4 防御、QUIC demux、H3 manager、SNI 透传和 UDP session 防护；XSK 未就绪、attach 失败或 reload 降级时保持原 socket 路径可用。

压力态分为 `Normal`、`Elevated`、`High`、`Critical`，由连接 admission、内存、FD-equivalent、UDP queued bytes、QUIC route/pending/reassembly 和前缀/集群 surge 综合计算。`memory_plan` 摘要会输出 `l4_pressure`、`prefix_pressure`、`tcp_like_per_ip_limit`、`fd_used_pct`、`zero_copy_active`、`udp_queued`、`l4_top_kind`、`l4_top_prefix`、`l4_counter_saturated` 等字段；节点状态上报包含 `resourceGovernor` 和 `l4Defense` JSON，便于压测期间观察防御收紧情况。

PROXY Protocol 入站只信任 loopback、private 或 link-local immediate peer。公网客户端伪造 PROXY header 时，节点会消费该头保持协议兼容，但不会用头里的地址替换真实 socket IP，因此不会绕过 L4 计数、WAF、访问日志和黑名单上报。

## 配置热更新

控制面下发配置后，运行时会更新 `ConfigStore`，并重建以下数据：

- Host 和 wildcard Host 路由。
- 端口监听和协议配置。
- 源站负载均衡器。
- 缓存策略。
- WAF 策略和封禁状态。
- 证书和 SNI 映射。
- 访问日志和全局开关。

证书快照按当前全局证书和当前启用服务的 HTTPS SSLPolicy 重建。服务级证书不会持久化为全局证书；局部服务更新后会重新收集当前配置中的证书，因此证书删除、服务删除和单服务多证书变更都会在下一次同步后反映到 TLS SNI 选择器。

热路径读取的是快照和引用，避免每个请求重新解析完整配置。HTTP/3 的集群级策略只决定集群是否具备 H3 listener 能力；网站 HTTPS 配置必须显式开启 H3，运行时才会发布 `Alt-Svc` 并允许该 Host 走 H3。

## 控制面长连接

节点启动后会同时进行周期配置同步和 `nodeStream` 长连接维护。`nodeStream` 使用控制面 `pb.NodeService/nodeStream` 双向流，用于接收控制面实时消息并回传执行结果。

当前支持的消息动作包括：

- `connectedAPINode`：记录已连接 API 节点 ID，触发节点状态上报和任务同步。
- `newNodeTask` / `NewNodeTask` / `configChanged`：立即触发节点任务同步。
- `writeCache`：将控制面下发的缓存预热内容写入本地请求路径。
- `readCache`：读取缓存元数据并回复是否命中。
- `statCache`：统计本地缓存大小和对象数量。
- `cleanCache`：清理本地缓存文件和缓存元数据。
- `getStat`：回传 CPU、内存、负载、流量和连接数。
- `changeAPINode`：切换运行时 API endpoint，并触发重连。
- `checkSystemdService`：检查 `cloud-node` systemd service 是否已启用。
- `checkLocalFirewall`：检查本地 `nftables` 可用性并回复版本或错误。

未知消息会回复 `unhandled`，不会静默丢弃。HTTP 明文 endpoint 下，运行时使用底层 HTTP/2 gRPC frame 实现保持流打开，行为更接近 Go 客户端：请求流打开后即开始心跳，不把“服务端响应头已返回”作为建流成功的前置条件。

## 负载均衡和回源

L7 回源由 `lb_factory` 构建 Pingora `LoadBalancer`。运行时会根据源站配置、父节点配置、TLS 选项、SNI、Host 策略、健康检查结果和源站失败状态选择上游。

回源请求会在自定义请求头策略之后写入边缘节点观测到的标准转发头：`X-Real-IP`、`X-Forwarded-Host`、`X-Forwarded-Proto` 和 `X-Forwarded-For`。其中 `X-Forwarded-Proto` 会根据下游是否 HTTPS、HTTP/3 或 L1→L2 HTTP/3 bridge 写入 `https` 或 `http`。

源站调度支持 Random 和 RoundRobin。控制面未显式下发 scheduling 或 code 为空时默认使用 Random；源站 `weight` 按单个源站生效，数值越大，被选择的比例越高。源站连续失败会进入短暂 down 状态，超时后自动恢复探测。

HTTPS 源站的 `http2Enabled` 按单个源站生效。开启后该源站回源 ALPN 会使用 H2/H1；未开启时保持普通 HTTPS 回源。

HTTPS/TLS 源站的 `tlsSecurityVerifyMode` 按单个源站生效，支持 `auto`、`force` 和 `skip`。`force` 始终校验证书和主机名，`skip` 不校验证书和主机名；`auto` 会在回源 SNI/Host 能安全对应源站地址或显式源站 Host 时启用校验，避免把下游访问域名错误用于校验无关源站证书。旧版 `tlsVerify` 仅作为兼容字段读取。

多级分发场景中，L1 节点可以回源到 L2 父节点。父节点压力通过响应头或控制面信息更新，调度时用于辅助选择。

## 本地性能监控

通过 `--monitor-port` 启动本地监控页：

```bash
cloud-node --monitor-port 8888
```

监控页展示：

- 请求速率、连接数、错误趋势。
- HTTP 状态码和缓存命中。
- L4/L7 流量统计。
- 磁盘缓存、内存缓存和缓存策略。
- 系统 CPU、内存和磁盘状态。
- 热点站点和异常建议。

监控数据保存在进程内存中，重启后不会持久化。使用 `--monitor-clear` 可以在启动时清空采样。

## 关闭和重启

未注册 systemd 时，`stop` 会通过 PID 文件和 Linux `/proc` 识别当前运行实例，先发送 `SIGTERM` 并等待进程退出；超时未退出时会发送 `SIGKILL`，确认进程结束后才清理匹配的 PID 文件。`restart` 会等待旧进程真实退出后再执行 `start`，避免旧进程仍占用 80/443 或持有数据目录锁时启动新实例。

`status` 会清理陈旧 PID 文件；如果 PID 文件丢失但同一工作目录下仍有 cloud-node 进程，Linux 环境会继续识别为运行中，避免进程仍在监听端口但 CLI 误报 stopped。

systemd 安装模式使用 `Type=simple` 直接托管前台进程，`TimeoutStopSec=35` 限制停止等待时间，并设置 `CLOUD_NODE_HOME` 指向运行目录。Pingora 的 SIGTERM graceful shutdown 宽限期设置为 5 秒，避免 `systemctl stop cloud-node` 长时间停留在 deactivating。

如果进程异常退出，systemd 安装模式下会按 `Restart=on-failure` 自动拉起。排障时优先查看：

- `systemctl status cloud-node`
- `journalctl -u cloud-node`
- `logs/run.log`
