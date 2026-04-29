# CloudNode Rust

`CloudNode Rust` 是一个基于 Cloudflare [Pingora](https://github.com/cloudflare/pingora) 构建的高性能 CDN 边缘代理节点，面向多级分发、缓存加速、站点安全、日志统计和控制面协议对接场景。

当前仓库已完成 HTTP、HTTPS、HTTP/2、HTTP/3、gRPC、WebSocket、TCP、UDP、`@sni_passthrough`、混合缓存、访问日志、统计上报、自定义错误页、性能监控页等全链路接入，持续围绕生产环境运行时行为做深度对齐。

## 当前能力

- 多协议代理
  - HTTP/1.1、HTTP/2、HTTP/3
  - gRPC、WebSocket
  - TCP、TCP-TLS、UDP
  - 共享 `443` 端口下的 `@sni_passthrough`

- 缓存与内容处理
  - Memory + Disk 混合缓存
  - RocksDB 元数据持久化
  - WebP 转换
  - HLS 播放列表与分片处理
  - 大文件与高并发切片场景下的全异步磁盘 I/O

- 安全与站点能力
  - WAF、UAM、CC、防盗链、User-Agent / Referer 规则
  - 站点关停页、自定义页面、全局页面回退
  - `redirectToHttps`
  - 请求限速、带宽限制、流量限制页面

- 统计与日志
  - 访问日志、节点日志、节点值、IP 上报
  - 带宽统计、日统计、域名统计、Top IP
  - L7 / L4 统计对齐
  - 缓存命中标签、HTTP/3 传输标识

- 运维与可观测性
  - 本地性能监控网页 `--monitor-port`
  - 动态证书与 OCSP 同步
  - 配置热更新
  - 共享 `443` 端口的 TLS / HTTP2 噪音日志收敛

## 构建与发布

### 本地编译

```bash
cargo build --release
```

### 高性能编译示例

```bash
# x86_64 v3
RUSTFLAGS="-C target-cpu=x86-64-v3 -C opt-level=3 -C lto=fat" cargo build --release

# ARM64
RUSTFLAGS="-C target-cpu=neoverse-n1 -C opt-level=3 -C lto=fat" cargo build --release
```

### GitHub Release 自动产物

当前 Release workflow 会自动构建以下 Linux 产物：

- `linux-x64-v2-sse4.2`
- `linux-x64-v3-avx2`
- `linux-x64-v4-avx512`
- `linux-arm64-generic`
- `linux-arm64-neoverse-n1`
- `linux-x64-legacy-glibc217`

其中：

- `linux-x64-legacy-glibc217` 面向老系统兼容，目标覆盖 `CentOS 7.6`、`Debian 10` 等较老环境
- 其余产物偏向性能优先，需要匹配对应 CPU / glibc 条件

## 运行方式

### 安装

```bash
sudo ./cloud-node install
```

### 常用命令

```bash
cloud-node start
cloud-node stop
cloud-node restart
cloud-node status
cloud-node test
```

### 性能监控网页

```bash
cloud-node --monitor-port 8888
```

或：

```bash
cargo run -- --monitor-port 8888
```

## 系统要求

- Linux
- 推荐内核 `5.x+`
- 若启用大规模磁盘缓存与高并发流媒体分发，建议使用更高的文件句柄上限和更充足的内存

## 项目说明

### 关于协议对齐

本项目并非简单的 Pingora 代理样例，而是面向生产环境的完整实现，包括：

- 配置同步与热更新
- 页面与变量能力
- 日志上报格式对齐
- 统计聚合口径一致
- L7 / L4 计费与趋势数据

仓库中的实现细节以运行时兼容性为优先目标，而非最小化示例。

### 关于老系统兼容包

为了兼顾新旧环境，Release 同时提供：

- 面向新环境的性能优化包
- 面向旧环境的 `glibc 2.17` 兼容包

如果部署环境是 `CentOS 7.x`、`Debian 10` 一类老系统，优先使用 `legacy` 包。

## 致谢

感谢 Cloudflare 开源 Pingora，为本项目提供了高质量的网络框架基础。

同时感谢 **FlexCDN** 在协议对齐、运行时行为验证和长期工程实践上的参考与支持。本仓库不少兼容性修正、页面能力、日志字段和统计口径的整理，都直接受益于 FlexCDN 的历史经验。

## 开源协议

本项目基于 Apache License 2.0 协议开源。
