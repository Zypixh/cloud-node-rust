# XDP/AF_XDP 旁路数据面

本功能提供 Linux-only、默认启用、可回退的 XDP/AF_XDP 数据面。XDP 程序负责在网卡入口提前执行 allow/block/proxy 决策；AF_XDP 负责把命中代理端口的队列包送到用户态；用户态继续复用现有 HTTP、HTTPS、TCP、UDP、SNI、QUIC 和 HTTP/3 路由与防护逻辑。

网卡、队列、attach mode、proxy 端口等全部由代码在本机自动推导：接口取自默认路由与活跃物理网卡，proxy 端口取自当前生效的监听配置。attach 失败、XSK 未就绪或协议/端口未命中时，节点保持原 socket/Pingora/Tokio 路径，并在 `xdp status`/doctor 中给出明确的 fallback 原因。

## 适用范围

- 仅 Linux 生产环境启用。
- 需要 root，或至少具备 `CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`。
- XDP 默认启用；RKE2 集群模式下强制关闭（AF_XDP 会独占网卡队列，影响 Kubernetes 网络）。
- 标准 MTU 是当前主要验收目标；proxy 模式遇到 jumbo/multi-buffer 风险时会在 doctor 或启动阶段拒绝或回退。
- `fallback: pass`（默认）会 fail-open 到原 socket 路径并记录 fallback 原因；`fallback: fail-start` 会在无法满足 XDP 启动条件时返回错误。

## 构建

普通节点构建仍使用原 Cargo 命令。XDP eBPF 对象需要额外构建：

```bash
cargo xtask build-ebpf
```

该命令会构建 `crates/cloud-node-xdp-ebpf`，并把对象复制到：

```text
data/cloud-node-xdp-ebpf.o
```

## 本地配置

XDP 只需要一个开关，优先级为：默认值（启用）< `CLOUD_NODE_XDP` 环境变量 < 配置文件显式值。

```text
configs/runtime.yaml   # 可选；不存在时不会自动生成
```

- 不配置任何文件也不设环境变量 → XDP 启用，其余全部自动推导。
- `CLOUD_NODE_XDP=0` / `false` / `off` / `disabled` → 关闭（`1`/`true`/`on`/`enabled` 为开启）。
- 文件中的 `xdp.enabled` 显式值是最终裁决，覆盖环境变量：

```yaml
xdp:
  enabled: false   # 显式关闭，即使 CLOUD_NODE_XDP=1 也保持关闭
```

`cloud-node xdp start` 写入 `xdp.enabled: true`，`cloud-node xdp stop` 写入 `xdp.enabled: false`；两者都保留文件中的其他内容，不会把推导出的运行时状态写回配置。

除 `enabled` 之外的字段（`attachMode`、`fallback`、`interfaces`、`proxy`、`rateLimit`、`sniBlocklist`）仍可在文件中显式提供以覆盖自动推导结果，但正常部署不需要；自动推导的状态只存在于内存，不会写回 `runtime.yaml`。

字段说明（显式覆盖时）：

- `attachMode`：`auto`、`drv`、`skb`。`auto` 优先尝试驱动模式，失败后按实现策略回退。
- `fallback`：`pass` 或 `fail-start`，默认 `pass`。
- `interfaces[].name`：要 attach 的本机网卡名。
- `interfaces[].queues`：要绑定 AF_XDP 的队列号。
- `interfaces[].mode`：`observe`、`protect`、`proxy`。
- `interfaces[].localIps`：proxy 模式下可限制只旁路目标为这些本机 IP 的包；为空表示不启用本机 IP 过滤。
- `interfaces[].frameSize`：UMEM frame size，默认 `2048`。
- `proxy.protocols`：允许进入 AF_XDP proxy 数据面的协议族。
- `proxy.ports`：显式发布到 eBPF map 的协议和端口。

## 模式

- `observe`：附着 XDP 并采样状态，不主动丢包或代理。
- `protect`：同步 allow/block map，命中封禁时在 XDP 层 drop。
- `proxy`：在 protect 能力基础上，把命中端口和队列的包 redirect 到 AF_XDP；未命中或 XSK 未就绪时 pass。

白名单优先级高于封禁。WAF 运行时 IP、CIDR 和 range 快照会通过 reconciler 写入 XDP shadow maps，过期条目由用户态 sweeper 清理。

## CLI

```bash
cloud-node xdp doctor
cloud-node xdp status
cloud-node xdp attach
cloud-node xdp detach
cloud-node xdp reload
cloud-node xdp dump-maps
```

诊断和测试命令：

```bash
cloud-node xdp raw-smoke --duration-ms 5000
cloud-node xdp proxy-smoke --duration-ms 15000
cloud-node xdp proxy-reload-smoke --duration-ms 3000
```

`status` 会输出 attach 状态、attach mode、fallback 原因、XSK queue ready 状态、proxy 端口支持情况、XDP pass/drop/redirect、parse errors、map miss 和 XSK drops。节点状态上报 JSON 同步包含 `xdp` 字段。

## 协议路径

- HTTP/HTTPS：AF_XDP TCP stream 包装为虚拟 stream 后接入现有 HTTP/HTTPS 代理入口。
- TCP 和 SNI 透传：复用现有 L4 路由、连接防护、PROXY protocol 和 relay 逻辑。
- UDP：AF_XDP datagram 与 `UdpSocket` datagram 共用 UDP 路由、队列、防护和指标。
- QUIC/H3：AF_XDP datagram 进入共享 QUIC demux，复用 H3 manager、CID route、pending route 防护和 `@quic` 透传逻辑。

proxy 模式命中端口后内核 socket 不再收到该包；未命中、降级或 detach 后原监听器继续承载流量。

## 回退与热更新

- attach 或 XSK 创建失败时，默认 `pass` 回退到原 socket 路径。
- map 更新失败不会立即中断 socket 路径，状态中会记录 fallback reason。
- 配置 reload 时，如果接口、队列和 proxy 端口未变化，运行时保留现有 AF_XDP bridge，避免队列重复绑定。
- `detach` 会撤销当前进程管理的 XDP attach，并将状态标记为 detached。

## 集成测试

Linux root 环境可运行：

```bash
cargo check --all-targets
cargo xtask build-ebpf
bash scripts/xdp-netns-smoke.sh
```

脚本会创建 veth/netns，验证 exact/CIDR allow/block、XSK missing pass、raw AF_XDP redirect、HTTP/HTTPS/TCP/UDP/SNI/QUIC/H3 proxy smoke、reload 保活和 detach 清理。

本地用户态单测：

```bash
cargo test --lib af_xdp
```

