# 部署与运维

本文件说明 CloudNode Rust 的构建、安装、运行、监控和排障建议。

## 构建

GitHub Release workflow 会在 `v*` tag 上执行正式发布构建。`main` 分支只在 `.cargo/`、`pingora-main/`、`toa-main/`、`toa-sender/` 和 `vendor/` 这些基础框架或底层依赖变化时预热 release 缓存；普通业务代码、`build.rs`、Cargo 清单、proto 和测试变更不会触发 main 预热。

普通构建：

```bash
cargo clean
cargo build --release
```

针对 x86_64 v3 优化：

```bash
cargo clean
RUSTFLAGS="-C target-cpu=x86-64-v3 -C opt-level=3 -C lto=fat" cargo build --release
```

针对 ARM64 Neoverse N1 优化：

```bash
cargo clean
RUSTFLAGS="-C target-cpu=neoverse-n1 -C opt-level=3 -C lto=fat" cargo build --release
```

不要在不支持对应指令集的机器上运行高阶 CPU 构建产物。

XDP/AF_XDP eBPF 对象需要额外构建：

```bash
cargo clean
cargo xtask build-ebpf
```

构建结果会写入 `data/cloud-node-xdp-ebpf.o`。没有该对象时，`cloud-node xdp doctor` 会报告不可用，默认不会影响普通 socket 数据面。

## 安装

安装命令：

```bash
sudo ./target/release/cloud-node-rust install
```

安装会执行两件事：

- 写入 `/usr/bin/cloud-node` wrapper。
- 写入 `/etc/systemd/system/cloud-node.service` 并启用服务。

安装后的常用命令：

```bash
cloud-node start
cloud-node stop
cloud-node restart
cloud-node status
cloud-node upgrade
cloud-node ntp
cloud-node xdp status
cloud-node xdp doctor
```

systemd unit 会以 `Type=simple` 托管前台节点进程，用于开机自启、日志和状态排障。已注册 systemd unit 时，`cloud-node start/restart` 会优先委托给 `systemctl`；未注册 systemd 时才使用内置后台进程管理。节点自身会同时把运行日志追加到 `logs/run.log`。

启用 XDP/AF_XDP 前，确认服务具备 root 或 `CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`，并在 `configs/runtime.yaml` 中显式配置接口和队列。建议先执行：

```bash
cloud-node xdp doctor
cloud-node xdp attach
cloud-node xdp status
```

如果生产环境要求 XDP 不可用时拒绝启动，把 `xdp.fallback` 设置为 `fail-start`；默认 `pass` 会回退到原监听器。

## 内置 NTP 命令

已安装 Rust 版后，可以用内置 NTP 命令交互式设置系统时区并校准系统时钟：

```bash
sudo cloud-node ntp
```

非交互设置时区并校时：

```bash
sudo cloud-node ntp --timezone Asia/Hong_Kong --yes
```

只校时、不修改时区：

```bash
sudo cloud-node ntp --no-timezone --yes
```

守护进程启动后的自动 NTP 同步只修正程序内部时间偏移，并通过节点日志上报偏差；显式执行 `cloud-node ntp` 才会修改系统时钟。

如果服务器或机房禁用了 UDP/123，命令会在内置 NTP 源全部超时后自动回退到 HTTPS Date 时间源，继续通过 TCP/443 获取时间参考。

## 内置升级命令

已安装 Rust 版后，可以直接使用二进制内置升级命令从 GitHub Release 拉取最新版：

```bash
sudo cloud-node upgrade
```

默认行为：

- 自动选择当前 CPU/架构匹配的官方 release 包。
- 默认目标版本为 `latest`。
- 显示升级摘要并交互确认。
- 替换前把旧二进制备份到 `/var/backups/cloud-node-rust-upgrade/`。
- 替换成功后，如果 `cloud-node.service` 正在运行则重启 systemd 服务；未使用 systemd 时会重启内置后台进程。

非交互升级到最新版：

```bash
sudo cloud-node upgrade --yes
```

升级到指定版本：

```bash
sudo cloud-node upgrade --version v1.1.6 --yes
```

使用 GitHub 镜像/代理站：

```bash
sudo cloud-node upgrade --github-mirror https://gh-proxy.example --yes
```

如果镜像站需要把原始 URL 放到模板中，可使用 `{url}` 占位符：

```bash
sudo cloud-node upgrade --github-mirror 'https://mirror.example/download?url={url}' --yes
```

使用 GitHub Enterprise 或自建镜像作为基础站点：

```bash
sudo cloud-node upgrade \
  --github-base-url https://github.example.com \
  --repo Zypixh/cloud-node-rust \
  --version v1.1.6 \
  --yes
```

上线前查看升级计划：

```bash
sudo cloud-node upgrade --dry-run
```

只替换二进制，不立即重启：

```bash
sudo cloud-node upgrade --yes --no-restart
```

## 从 Go 原版迁移安装 Rust 版

仓库提供迁移安装脚本：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash
```

脚本会执行以下步骤：

- 第一步询问界面语言，支持中文和英文；自动化场景优先使用 `CLOUD_NODE_LANG=zh` 或 `CLOUD_NODE_LANG=en`。为兼容旧命令也接受 `LANGUAGE=zh`/`LANGUAGE=en`，并能识别系统常见的 gettext locale 列表（例如 `LANGUAGE=en_HK:en`）。
- 默认交互式选择操作：覆盖/升级旧 Go 原版为 Rust 版、全新安装 Rust 版、从备份恢复 Go 原版。自动化场景必须显式传 `--install` 或 `--fresh`。
- 查找当前 `cloud-node` 命令、`cloud-node.service` 的 `ExecStart` 和常见安装路径。
- 将找到的旧二进制、`/usr/bin/cloud-node` 和 systemd unit 备份到 `/var/backups/cloud-node-rust-migration/<timestamp>/`。
- 从 Go 原版迁移时备份文件带有 `go-original` 标识；升级已有 Rust 版时备份文件带有 `rust-current` 标识。
- 根据系统架构选择 GitHub 最新 Rust Release 包；`--upgrade` 默认解析并下载当前最新 Release。
- 将 Rust 二进制和 `data/cloud-node-xdp-ebpf.o` 原子替换到现有运行目录；目录识别优先使用 service `WorkingDirectory`、`/usr/bin/cloud-node` wrapper 中的 `cd` 目录、旧二进制所在目录和常见旧目录，只有没有可识别旧目录时才默认安装到 `/opt/cloud-node-rust/cloud-node-rust`。
- 执行 Rust 二进制内置的 `install` 命令，重新注册 `/usr/bin/cloud-node` wrapper 和 `cloud-node.service`，并设置 `CLOUD_NODE_HOME` 指向运行目录。
- 交互询问是否从 `https://github.com/P3TERX/GeoLite.mmdb` 下载 `GeoLite2-City.mmdb`、`GeoLite2-ASN.mmdb` 和 `GeoLite2-Country.mmdb`。
- 安装/升级完成后交互询问是否立即重启或启动服务；自动化 `--yes` 场景保持原有 preserve 行为，迁移前服务运行则自动重启。

显式 `--install` / `--upgrade` 要求找到现有 `cloud-node`，避免在未备份原版的情况下误装；其中 `--upgrade` 等价于升级现有节点到最新 Rust Release。升级时会保留既有运行目录名称，例如 `/root/cloud-node` 不会被改成 `/opt/cloud-node-rust`，并会从旧运行目录迁移 `configs/api_node.yaml`、旧版根目录 `api_node.yaml` 和运行状态数据。全新安装使用 `--fresh`，会自动允许没有旧节点的环境。

全新安装会默认创建 `/root/cloud-node`，并交互输入 API 连接配置，生成 `/root/cloud-node/configs/api_node.yaml`。

上线前建议先 dry-run：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --dry-run
```

安装指定版本：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --version v1.1.2 --yes
```

## 1.1.2 说明

1.1.2 聚焦 WAF 正确性、HTTP/3 可用性和 RKE2 多副本部署：修复内置 WAF preset 漏匹配、缓存命中绕过 WAF、chunked/无 Content-Length 请求体 WAF 失效、IP 名单同步版本推进错误，并补齐 RKE2 内部服务、Leader 选举、Longhorn 缓存分片和健康探针。

本版本同时优化 Basic Auth、rewrite replacement、模板渲染、访问日志上传和防火墙网络名单匹配热路径；完整更新见 [1.1.2 发布说明](../release-notes/v1.1.2.md)。

## 1.1.1 说明

1.1.1 聚焦数据面性能和可靠性：缓存 L2 大对象命中改为文件分块读取，压缩对象支持流式 zstd 解压，小对象继续走内存命中以保持 Fast L1 晋升；WAF CC 计数器改为固定窗口滚动桶，避免攻击流量下按请求数线性扫描时间戳。

本版本同时优化访问日志、指标、UDP/QUIC 活动时间、上游 TLS 连接器和证书选择热路径；访问日志上传在中间 chunk 失败时会重新入队当前失败 chunk 与尚未发送的后续 chunk，避免批量日志丢失。

## 1.1.0 说明

1.1.0 新增 `@quic` UDP 域名透传：节点会解析 QUIC Initial 中的 TLS SNI，并在同一 UDP 端口上和 HTTP/3 共享监听；同时修复配置任务完成闭环，避免控制面任务未确认时本地跳过版本导致节点状态停留在同步中。

本版本重新整理 systemd 生命周期管理：新安装的服务使用 `Type=simple` 直接托管前台进程；`stop` 会等待真实退出并在必要时强制结束；`restart` 不再固定等待 1 秒，而是确认旧进程退出后再启动。

升级现有 Rust 节点到最新版：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --upgrade --yes
```

全新安装：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --fresh
```

全新安装的一条非交互命令：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --fresh --yes --api-endpoint http://127.0.0.1:8001 --node-id your-node-id --secret your-node-secret --geoip
```

非交互下载 GeoIP 库：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo env CLOUD_NODE_LANG=zh bash -s -- --geoip --yes
```

GeoIP 文件默认写入节点 `data/` 目录，因为运行时会优先从 `data/GeoLite2-City.mmdb` 和 `data/GeoLite2-ASN.mmdb` 读取。旧版工作目录 GeoIP 文件仍作为迁移 fallback。 如需指定目录：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --geoip --geoip-dir /opt/cloud-node-rust/data --yes
```

指定安装目录或禁止自动启动：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --install-dir /opt/cloud-node-rust --no-start --yes
```

列出可用备份：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --list-backups
```

从最近一次备份恢复 Go 原版：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --restore
```

非交互恢复指定备份：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --restore --restore-backup /var/backups/cloud-node-rust-migration/20260509-120000 --yes
```

恢复时脚本会停止当前服务，恢复 `go-original` 二进制、`/usr/bin/cloud-node` 和 systemd unit，并将当前 Rust 文件备份到 `restore-current-*` 目录。手动回滚也可以停止服务后恢复备份目录中的文件，再执行 `systemctl daemon-reload` 与 `systemctl start cloud-node`。

## 运行前检查

上线前建议确认：

- `configs/api_node.yaml` 存在且 nodeId、secret 正确。
- API 节点 RPC endpoint 可达。
- 运行目录权限正确。
- `data` 和 `logs` 可写。
- 缓存目录可写且容量充足。
- GeoIP 数据文件存在。
- 监听端口没有被其它进程占用。
- systemd `LimitNOFILE` 足够大。

## 监控

启动本地监控页：

```bash
cloud-node --monitor-port 8888
```

生产环境建议只暴露在内网或通过本机 SSH 隧道访问，不建议直接公网暴露。

重点观察：

- 请求速率和错误率。
- 活跃连接数。
- 上游连接失败。
- 缓存命中率。
- 磁盘缓存容量。
- CPU 和内存。
- WAF 拦截量。
- 日志上传失败次数。

## 日志

常见日志来源：

- systemd 日志：`journalctl -u cloud-node`
- 本地运行日志：`logs/run.log`
- 控制面节点日志：由 NodeLogUploader 上报。
- 访问日志：由 LogUploader 批量上报。

节点日志防刷：

- 相同 `type`（或无 type 时的 `tag`+`serverId`）在限流窗口内只上报一次，并用 `count` 累计被合并次数。
- API/连通性类失败（如 `apiNodeListFailed`、`ocspListFailed`、`updatingServerSyncFailed`）默认 10 分钟窗口；其它节点日志默认 5 分钟。
- 上传失败时 NodeLogUploader 指数退避（上限 5 分钟），重试队列按 `type` 合并，避免 API 宕机恢复后对控制面数据库造成日志洪峰。
- 状态里的 `pipelines.nodeLogThrottled` 可观察被抑制次数。

排障时优先看：

```bash
systemctl status cloud-node
journalctl -u cloud-node -n 200 --no-pager
tail -n 200 logs/run.log
```

## 性能建议

高并发场景建议：

- 使用 release 构建。
- 选择匹配 CPU 的 release 包。
- 提高文件句柄限制。
- 调整 listen backlog 和 SYN backlog。
- 将缓存目录放到高 IOPS 磁盘。
- 避免对大 body 开启详细访问日志。
- 谨慎开启 JS/CSS/HTML 优化等 CPU 密集型能力；WebP 会写入独立缓存变体，仍建议配合缓存策略和图片大小限制使用。
- 对大流量站点启用合适的缓存策略，减少回源。

## 缓存运维

缓存相关建议：

- 独立磁盘或分区存放磁盘缓存。
- 监控磁盘剩余空间。
- 避免多个节点共享同一个本地缓存目录。
- 控制缓存对象数量，避免极端小文件造成元数据压力。
- 定期检查 Mace 指标和缓存清理日志。
- 开启 WebP 时确认站点 WebP 规则、缓存策略和响应状态码同时满足要求；否则节点会按普通响应处理，不会为了不可缓存响应重复转换。

## 常见问题

### 节点启动后没有流量

检查：

- 控制面是否已下发站点配置。
- 监听端口是否成功绑定。
- DNS 是否解析到节点。
- 防火墙或安全组是否放行。
- Host 是否命中站点域名。

### 控制端显示节点在线但没有实时命令

检查：

- 周期配置同步是否成功。
- `nodeStream` 是否能保持连接。
- 控制端是否向该节点下发 `connectedAPINode` 或其它 stream 消息。
- 节点日志中是否出现 `Node stream transport opened`。
- API endpoint 是否发生运行时切换。

节点在线状态和 `nodeStream` 是两条路径：在线状态可以通过 `updateNodeStatus` 上报成功，而实时命令需要控制端在 `nodeStream` 上实际发送消息。

### HTTPS 握手失败

检查：

- 证书是否同步。
- SNI 是否匹配。
- 共享 443 是否进入了 SNI 透传。
- TLS 噪音是否来自非 TLS 流量探测。

### 回源 403 或 404

检查：

- upstream Host 是否符合源站要求。
- SNI 是否符合源站证书。
- request header policy 是否生效。
- 源站是否限制节点 IP。

### 缓存命中率低

检查：

- cacheRefs 是否命中 URL 和 method。
- 响应状态码是否允许缓存。
- Cache-Control 是否跳过缓存。
- 是否存在 Set-Cookie。
- Range 请求策略是否允许。
- 缓存目录是否可写。

### 访问日志不完整

检查：

- 全局和站点访问日志开关。
- 日志通道是否过载。
- 控制面 RPC 是否可达。
- 是否启用了 body 记录导致消息过大。
- 上传端是否出现 retry 或 ResourceExhausted 日志。

## 升级建议

升级前：

1. 备份当前二进制和配置。
2. 确认 release 包和系统架构匹配。
3. 在测试节点验证控制面配置同步。
4. 低峰期替换二进制并重启。
5. 观察监控页、访问日志、错误率和缓存命中率。

回滚时恢复旧二进制并重启服务即可。缓存目录和统计数据库通常可以保留，但跨版本如果缓存格式发生变化，应按 release notes 处理。
