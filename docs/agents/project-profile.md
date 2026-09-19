# Agent 工程背景（cloud-node-rust）

本文件汇总 agent 在本仓库工作时需要、但无法从代码快速推导出来的工程背景。
入口约束见仓库根目录 [AGENTS.md](../../AGENTS.md)。

## 项目形态

- 根 crate `cloud-node-rust`，Rust edition 2024，由 `rust-toolchain.toml` 固定到 1.98.1。
- 生产领域：基于 Pingora 的高性能 CDN 边缘节点，覆盖 HTTP/1.1、HTTP/2、HTTP/3、QUIC、
  TCP/UDP 代理、TLS/证书、WAF、缓存、指标、日志、配置热重载和本地可观测性。
- 主源码树在 `src/`；`crates/` 下是工作区成员，`benches/` 下是 Criterion 基准，
  `tests/` 下是集成测试，`xtask/` 是独立工具 manifest。
- 工作区配置：`members = ["crates/cloud-node-transport"]`；
  `exclude = ["crates/cloud-node-xdp-ebpf", "pingora-main", "xtask"]`
  ——被排除的三者各有独立构建体系（eBPF 需要自己的 nightly/bpfeb 工具链，
  pingora-main 有自己的工作区根），改动时不要试图把它们并入根工作区。

## 源码模块地图

`src/` 下按职责划分，修改前先定位对应模块：

| 领域 | 模块 |
| --- | --- |
| 配置与控制面 | `config.rs`、`config_models.rs`、`config_apply.rs`、`api_config.rs`、`rpc/`、`client_agent.rs`、`cluster/` |
| L7 代理 | `proxy.rs`、`http_proxy_manager.rs`、`http3_proxy_manager.rs`、`h3_downstream.rs`、`rewrite.rs`、`headers.rs`、`pages/` |
| L4 代理 | `tcp_proxy.rs`、`udp_proxy.rs`、`l4_connection_registry.rs`、`l4_defense.rs`、`proxy_protocol.rs`、`toa.rs` |
| 缓存 | `cache/`、`cache_hybrid.rs`、`cache_manager.rs`、`compiled.rs` |
| 安全 | `firewall/`、`local_firewall.rs`、`special_defense.rs`、`kernel_syn_defense.rs`、`auth.rs`、`client_ip.rs` |
| XDP / AF_XDP | `xdp/`、`xdp_auto_config.rs`、`xdp_config_wizard.rs`、`xdp_netdev_tuning.rs`、`crates/cloud-node-xdp-*` |
| 内存治理 | `memory_governor.rs`、`memory_plan.rs`、`memory_reclaim.rs`、`memory_shed.rs`、`memory_ticket.rs`、`resource_budget.rs` |
| QUIC / 传输 | `quic_transport.rs`、`quic_udp_demux.rs`、`quic_cc.rs`、`quic_probe.rs`、`transport_clock.rs`、`crates/cloud-node-transport` |
| 回源 | `origin_h3.rs`、`origin_h3_pool.rs`、`origin_h3_state.rs`、`origin_state.rs`、`oss_origin.rs`、`lb_factory.rs`、`health_manager.rs` |
| 可观测性 | `metrics.rs`、`metrics/`、`logging.rs`、`log_uploader.rs`、`perf_monitor.rs`、`pipeline_metrics.rs` |
| 运行时 | `runtime_mode.rs`、`adaptive_cpu.rs`、`kernel_tuning.rs`、`paths.rs`、`net_bind.rs`、`ssl.rs`、`tls_crypto.rs` |

`pingora-main/`、`toa-main/`、`toa-sender/`、`vendor/` 是 vendored checkout 或受控
fork，除非任务明确指向它们，不要修改。

`vendor/smoltcp-edge/` 是 smoltcp 0.14.0 的受控 fork（通过 `[patch.crates-io]` 重定向），
在 `socket/tcp.rs` 上有传输钩子和最小 wire repr 改动。每一处偏离都记录在
`vendor/smoltcp-edge/DIVERGENCE.md`——修改前必须先读它。

## 依赖信号

优先复用已有依赖和既有模式，不要为了一个小功能引入新 crate：

- 异步运行时：`tokio`、`futures-util`、`tokio-stream`、`async-stream`、`async-trait`。
- 网络 / 代理：`pingora*`、`h2`、`h3`、`h3-quinn`、`quinn`、`socket2`、`reqwest`、`tonic`。
- 共享状态：`Arc`、`DashMap`、`parking_lot`、`tokio::sync`、`arc-swap`、`moka`、`lru`。
- 字节与载荷：`bytes::Bytes`、`http`、`prost`、`serde`、`serde_json`、`serde_yaml`。
- 安全 / 加密 / TLS：`rustls`、`rustls-native-certs`、`rustls-pemfile`、`x509-parser`、`aes*`、`hmac`、`sha*`、`libc`。
- 可观测性：`tracing`、`tracing-subscriber`。
- 性能与基准：`criterion`；release profile 使用激进优化。

注意 `quinn-proto` 被**精确锁定**（`=0.11.17`）以便为 `congestion::Controller`
实现命名 `RttEstimator`——升级它会破坏这处依赖，改动前先读 `Cargo.toml` 里的注释。

## 仓库特定优先级

- **保持配置与控制面兼容**。未知 legacy key、可空字段、数值/字符串宽松输入、
  serde camelCase 序列化名都可能是刻意的。不要把"看起来没用到的字段"当成死代码清理。
- **保持热重载行为**。不要让运行期配置快照出现不一致或部分应用的中间态。
- **请求热路径保持 allocation-aware**。警惕 per-request 的 `String`、`Vec`、正则构造、
  `format!`、深 `clone`、阻塞 I/O 和粗粒度锁。
- **尊重协议边界**。HTTP、TLS、QUIC、TCP、UDP、SNI 透传、PROXY protocol 和缓存行为
  会通过共享端口互相影响（尤其是共享 `443` 端口分流）。
- **测试的环境敏感性**。依赖真实 API 配置或网络状态的测试是环境敏感的；除非任务本身
  就是对接真实服务，否则优先写本地确定性测试。
- **平台差异**。生产目标是 Linux，本地开发可能在 macOS。XDP/AF_XDP、`kernel_tuning`、
  `libpcap`、`libelf` 相关路径在 macOS 上不可用，不要假设它们能本地验证。

## 常用检索模式

```bash
# 公开行为面
rg -n "pub (async )?fn|impl .* for|trait " src

# async 任务生命周期与取消
rg -n "tokio::spawn|spawn_blocking|select!|timeout|watch::|mpsc::" src

# 锁与共享状态
rg -n "DashMap|ArcSwap|Mutex|RwLock|parking_lot|tokio::sync" src

# 热路径分配
rg -n "format!|to_string\(|to_owned\(|clone\(|Vec::new|String::new|Regex::new" src

# 生产代码中的 panic
rg -n "unwrap\(|expect\(|panic!|todo!|unimplemented!" src

# 配置兼容性
rg -n "serde\(|deserialize_|rename|default|alias|skip_serializing" src/config_models.rs src/
```

## 验证默认值

- 大多数源码改动从 `cargo check --all-targets` 开始。
- 有对应模块/函数名的测试时，按名字跑定向测试。
- 热路径模块在声称性能改善前，先跑 `benches/` 下对应的 bench。
- 协议改动必须显式论证连接生命周期、超时、取消和关闭路径——测试很可能覆盖不全整个矩阵。
- 本地与 CI 的 CPU baseline 不同（见 `AGENTS.md`），本地通过不等于 CI 通过。
