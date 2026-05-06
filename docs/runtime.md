# 运行时说明

CloudNode Rust 的运行时由一个主进程和多个异步后台任务组成。主进程负责监听网络端口、维护配置快照、处理请求和启动上报任务；后台任务负责控制面同步、缓存维护、证书更新、统计上报和本地监控。

## 启动流程

启动过程大致如下：

1. 创建 `../data` 目录。
2. 通过 `../data/cloud-node.pid` 和 `flock` 保证单实例运行。
3. 初始化日志系统。
4. 加载 `api_node.yaml`。
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
- `test`：验证 `api_node.yaml` 是否可解析。

## 进程和目录

默认运行目录假设二进制位于项目或安装目录内，并使用相对路径保存状态：

- `../data/cloud-node.pid`：后台进程 PID 文件。
- `../data/cloud-node-stderr.log`：后台进程 stderr。
- `../data/state.json`：部分运行状态持久化。
- `../data/blocked_ips.json`：本地封禁 IP 持久化。
- `../data/metrics.db`：统计和缓存元数据持久化。
- `../data/cache`：部分缓存测试和默认数据目录。
- `configs/cache/disk`：默认磁盘缓存目录。

生产部署时应保持工作目录稳定，不要只移动二进制而忽略相对目录。

## 异步任务

运行时主要依赖 Tokio 和 Pingora 的异步执行模型。后台任务包含：

- API 节点连接和配置同步。
- 站点配置周期更新。
- 节点任务同步。
- 缓存任务同步和缓存清理。
- 证书和 OCSP 同步。
- 源站健康检查。
- 访问日志和节点日志上传。
- 实时统计、日统计、Top IP 和节点值上报。
- 本地性能监控采样。

请求热路径避免执行慢速磁盘 I/O、同步 DNS、全表扫描和大对象深拷贝。对不可避免的 CPU 密集型能力，需要在后续版本继续隔离到专用 worker 或 blocking 线程池。

## 配置热更新

控制面下发配置后，运行时会更新 `ConfigStore`，并重建以下数据：

- Host 和 wildcard Host 路由。
- 端口监听和协议配置。
- 源站负载均衡器。
- 缓存策略。
- WAF 策略和封禁状态。
- 证书和 SNI 映射。
- 访问日志和全局开关。

热路径读取的是快照和引用，避免每个请求重新解析完整配置。

## 负载均衡和回源

L7 回源由 `lb_factory` 构建 Pingora `LoadBalancer`。运行时会根据源站配置、父节点配置、TLS 选项、SNI、Host 策略和健康检查结果选择上游。

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

`stop` 使用 PID 文件找到后台进程并发送 `kill`。`restart` 执行 `stop` 后等待 1 秒再执行 `start`。

如果进程异常退出，systemd 安装模式下会按 `Restart=always` 自动拉起。排障时优先查看：

- `systemctl status cloud-node`
- `journalctl -u cloud-node`
- `../data/cloud-node-stderr.log`
