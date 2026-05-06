# 部署与运维

本文件说明 CloudNode Rust 的构建、安装、运行、监控和排障建议。

## 构建

普通构建：

```bash
cargo build --release
```

针对 x86_64 v3 优化：

```bash
RUSTFLAGS="-C target-cpu=x86-64-v3 -C opt-level=3 -C lto=fat" cargo build --release
```

针对 ARM64 Neoverse N1 优化：

```bash
RUSTFLAGS="-C target-cpu=neoverse-n1 -C opt-level=3 -C lto=fat" cargo build --release
```

不要在不支持对应指令集的机器上运行高阶 CPU 构建产物。

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
sudo systemctl start cloud-node
sudo systemctl stop cloud-node
sudo systemctl restart cloud-node
sudo systemctl status cloud-node
```

也可以直接使用：

```bash
cloud-node start
cloud-node stop
cloud-node restart
cloud-node status
```

## 运行前检查

上线前建议确认：

- `api_node.yaml` 存在且 nodeId、secret 正确。
- API 节点 RPC endpoint 可达。
- 运行目录权限正确。
- `../data` 可写。
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
- 后台 stderr：`../data/cloud-node-stderr.log`
- 控制面节点日志：由 NodeLogUploader 上报。
- 访问日志：由 LogUploader 批量上报。

排障时优先看：

```bash
systemctl status cloud-node
journalctl -u cloud-node -n 200 --no-pager
tail -n 200 ../data/cloud-node-stderr.log
```

## 性能建议

高并发场景建议：

- 使用 release 构建。
- 选择匹配 CPU 的 release 包。
- 提高文件句柄限制。
- 调整 listen backlog 和 SYN backlog。
- 将缓存目录放到高 IOPS 磁盘。
- 避免对大 body 开启详细访问日志。
- 谨慎开启 WebP、JS/CSS/HTML 优化等 CPU 密集型能力。
- 对大流量站点启用合适的缓存策略，减少回源。

## 缓存运维

缓存相关建议：

- 独立磁盘或分区存放磁盘缓存。
- 监控磁盘剩余空间。
- 避免多个节点共享同一个本地缓存目录。
- 控制缓存对象数量，避免极端小文件造成元数据压力。
- 定期检查 RocksDB 指标和缓存清理日志。

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
