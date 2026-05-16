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
8. 启动缓存、统计、日志上传和证书同步后台任务。
9. 如指定 `--monitor-port`，启动本地性能监控页面。

默认不带子命令时以前台方式运行。`start` 子命令会以单 fork 方式进入后台。

## CLI 命令

```bash
cloud-node start
cloud-node stop
cloud-node restart
cloud-node status
cloud-node install
cloud-node test
```

全局参数：

```bash
cloud-node --monitor-port 8888
cloud-node --monitor-port 8888 --monitor-clear
```

命令说明：

- `start`：后台启动节点。
- `stop`：停止后台节点。
- `restart`：先停止再启动。
- `status`：读取 PID 文件和文件锁判断节点状态。
- `install`：注册 `/usr/bin/cloud-node` wrapper 和 systemd service。
- `test`：验证 `configs/api_node.yaml` 是否可解析。

## 进程和目录

默认运行目录采用 GoEdge/FlexCDN 风格的三类目录：

- `configs/api_node.yaml`：API 节点连接配置。
- `data/cloud-node.pid`：后台进程 PID 文件。
- `data/state.json`：部分运行状态持久化。
- `data/blocked_ips.json`：本地封禁 IP 持久化。
- `data/metrics.db`：统计和缓存元数据持久化。
- `data/cache`：默认磁盘缓存目录。
- `data/GeoLite2-City.mmdb`、`data/GeoLite2-ASN.mmdb`：GeoIP 数据库。
- `logs/run.log`：后台进程 stdout/stderr。

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

请求热路径避免执行慢速磁盘 I/O、同步 DNS、全表扫描和大对象深拷贝。WebP 图片转换只在缓存写入前执行一次，后续同一 WebP 变体命中缓存时不再重复转换。对 HTML/CSS/JS 优化、加密等仍可能在响应阶段执行的 CPU 密集型能力，需要在后续版本继续隔离到专用 worker 或 blocking 线程池。

项目提供 `targeted_hotspots_bench` 用于服务器侧观察 Fast L1、响应体 CPU 处理、TLS selector、UA analyzer cache 和 WAF verifier 等热点。常规开发验证使用 `cargo check --all-targets`，bench 建议只在目标服务器上运行。

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

热路径读取的是快照和引用，避免每个请求重新解析完整配置。

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

`stop` 会通过 PID 文件和 Linux `/proc` 识别当前运行实例，先发送 `SIGTERM` 并等待进程退出；超时未退出时会发送 `SIGKILL`，确认进程结束后才清理匹配的 PID 文件。`restart` 会等待旧进程真实退出后再执行 `start`，避免旧进程仍占用 80/443 或持有数据目录锁时启动新实例。

`status` 会清理陈旧 PID 文件；如果 PID 文件丢失但同一工作目录下仍有 cloud-node 进程，Linux 环境会继续识别为运行中，避免进程仍在监听端口但 CLI 误报 stopped。

systemd 安装模式使用 `Type=simple` 直接托管前台进程，`TimeoutStopSec=35` 限制停止等待时间。Pingora 的 SIGTERM graceful shutdown 宽限期设置为 5 秒，避免 `systemctl stop cloud-node` 长时间停留在 deactivating。

如果进程异常退出，systemd 安装模式下会按 `Restart=always` 自动拉起。排障时优先查看：

- `systemctl status cloud-node`
- `journalctl -u cloud-node`
- `logs/run.log`
