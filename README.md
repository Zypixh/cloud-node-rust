# CloudNode Rust

CloudNode Rust 是一个基于 [Pingora](https://github.com/cloudflare/pingora) 构建的高性能 CDN 边缘节点。它面向生产环境中的站点加速、多级分发、动态配置、边缘安全、访问日志和统计上报场景，而不是一个最小化代理示例。

项目的核心目标是用 Rust 运行时承载完整边缘节点能力：从控制面协议同步配置，到 L7/L4 代理、缓存、WAF、证书、日志、统计和本地可观测性，尽量让节点在高并发和复杂站点策略下保持稳定、可解释、可运维。

## 核心特性

- **多协议边缘代理**：HTTP/1.1、HTTP/2、HTTP/3、gRPC、WebSocket、TCP、TCP-TLS、UDP。
- **共享端口接入**：支持共享 `443` 端口下的 TLS、HTTP/2、HTTP/3、`@sni_passthrough` 和 `@quic` 流量分流。
- **XDP/AF_XDP 旁路**：Linux 上可显式启用 XDP protect/proxy 模式，支持 HTTP、HTTPS、TCP、UDP、SNI、QUIC 和 H3 命中端口旁路，并保留 socket fallback。
- **混合缓存系统**：Memory + Disk 缓存，Mace 元数据索引，多缓存策略匹配，支持大文件和高并发切片分发。
- **站点安全能力**：WAF、UAM、CC、防盗链、访问限制、请求限制、带宽和流量限制、自定义拦截页面。
- **L4 自适应强防**：复用 `emptyConnectionFlood` 开关覆盖 HTTP/HTTPS/TCP/SNI/UDP/QUIC/H3 的慢连接、队列和 admission 攻击防御，支持集群级 IP 上报拉黑。
- **内容处理能力**：WebP 转换、HTML/CSS/JS 优化、HLS 播放列表和分片处理、自定义错误页和模板变量。
- **动态运行时**：配置热更新、动态证书、OCSP 同步、源站健康检查、多级回源和父节点压力感知。
- **日志与统计**：访问日志、节点日志、L7/L4 指标、日统计、域名统计、Top IP、缓存命中和攻击统计。
- **本地可观测性**：内置性能监控页面，展示请求、连接、缓存、系统资源和异常趋势。

## 适用场景

- 需要以 Rust/Pingora 承载 CDN 边缘节点能力。
- 需要控制面下发 PB 配置，节点侧进行热更新和运行时兼容。
- 需要同时处理 HTTP 站点流量、四层转发、SNI 透传和 UDP 服务。
- 需要在边缘层完成缓存加速、WAF 防护、访问日志和统计上报。
- 需要面向大文件、HLS、图片分发或高并发小文件场景做性能优化。

## 快速开始

准备 `configs/api_node.yaml`：

```yaml
rpc.endpoints: [ "http://127.0.0.1:8001" ]
nodeId: "your-node-id"
secret: "your-node-secret"
```

从 Go 原版节点迁移到 GitHub 最新 Rust Release，或全新安装：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | bash
```

全新安装的一条非交互命令示例：

```bash
curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | bash -s -- --fresh --yes --api-endpoint http://127.0.0.1:8001 --node-id your-node-id --secret your-node-secret --geoip
```

## 文档

详细文档位于 [docs](docs/README.md)：

- [架构概览](docs/architecture.md)
- [运行时说明](docs/runtime.md)
- [功能说明](docs/features.md)
- [配置说明](docs/configuration.md)
- [XDP/AF_XDP 旁路数据面](docs/xdp-af-xdp.md)
- [部署与运维](docs/operations.md)
- [RKE2 部署文档](docs/rke2-deployment.md)
- [gRPC API 使用文档](docs/grpc-api.md)

发布说明：

- [1.2.1](release-notes/v1.2.1.md)
- [1.2.0](release-notes/v1.2.0.md)
- [1.1.9](release-notes/v1.1.9.md)
- [1.1.8](release-notes/v1.1.8.md)
- [1.1.7](release-notes/v1.1.7.md)
- [1.1.6](release-notes/v1.1.6.md)
- [1.1.5](release-notes/v1.1.5.md)
- [1.1.4](release-notes/v1.1.4.md)
- [1.1.3](release-notes/v1.1.3.md)
- [1.1.2](release-notes/v1.1.2.md)
- [1.1.1](release-notes/v1.1.1.md)
- [1.1.0](release-notes/v1.1.0.md)
- [1.0.9](release-notes/v1.0.9.md)
- [1.0.8](release-notes/v1.0.8.md)
- [1.0.7](release-notes/v1.0.7.md)
- [1.0.6](release-notes/v1.0.6.md)

## 构建产物

Release workflow 面向不同 CPU 和系统环境提供多个 Linux 产物：

- `linux-x64-v2-sse4.2`
- `linux-x64-v3-avx2`
- `linux-x64-v4-avx512`
- `linux-arm64-generic`
- `linux-arm64-neoverse-n1`

选择建议：

- 新系统和新 CPU 优先选择匹配微架构的性能包。
- 自行编译时可以根据机器设置 `RUSTFLAGS`，但需要确认目标 CPU 指令集和运行环境一致。

高性能编译示例：

```bash
RUSTFLAGS="-C target-cpu=x86-64-v3 -C opt-level=3 -C lto=fat" cargo build --release
```

## 系统要求

- Linux。
- 推荐内核 `5.x+`。
- XDP/AF_XDP proxy 为可选 Linux-only 能力，需 root 或 `CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`，默认关闭。
- 大规模并发场景建议提高 `LimitNOFILE`、`somaxconn`、`tcp_max_syn_backlog`、本地端口范围和 conntrack 容量；SYN flood 和 pre-accept 半连接耗尽仍需要内核、nftables/ipset、云防火墙或上游清洗配合。
- 启用 GeoIP、缓存和证书能力时，需要确保数据文件、缓存目录和运行目录权限正确。

## 项目状态

CloudNode Rust 已接入主要边缘节点能力，并持续优化以下方向：

- 控制面 PB 协议兼容。
- 请求热路径锁竞争和分配开销。
- 高并发日志与统计上报。
- 缓存命中路径和大文件磁盘 I/O。
- WAF、内容处理和图片处理的 CPU 隔离。
- 针对 Fast L1、TLS selector、UA analyzer、WAF verifier 和响应体 CPU 处理的持续 benchmark 验证。

## 致谢

感谢 Cloudflare 开源 Pingora，为本项目提供了高质量的网络框架基础。

同时感谢 FlexCDN 在协议设计、生产行为验证和长期工程实践上的参考与支持。

## 开源协议

本项目基于 Apache License 2.0 协议开源。
