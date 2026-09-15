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

普通节点构建仍使用原 Cargo 命令。XDP eBPF 对象在 Linux 目标上由 `build.rs` 自动编译并内嵌进二进制；`cargo xtask build-ebpf` 仍可单独构建到 `data/cloud-node-xdp-ebpf.o`，用于调试或 `xdp.ebpfObject` 显式外部对象热替换。

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

除 `enabled` 之外的字段（`attachMode`、`fallback`、`interfaces`、`proxy`、`rateLimit`）仍可在文件中显式提供以覆盖自动推导结果，但正常部署不需要；自动推导的状态只存在于内存，不会写回 `runtime.yaml`。

字段说明（显式覆盖时）：

- `attachMode`：`auto`、`drv`、`skb`。`auto` 优先尝试驱动模式，失败后按实现策略回退。
- `fallback`：`pass` 或 `fail-start`，默认 `pass`。
- `interfaces[].name`：要 attach 的本机网卡名。
- `interfaces[].queues`：要绑定 AF_XDP 的队列号。
- `interfaces[].mode`：`observe`、`protect`、`proxy`。
- `interfaces[].localIps`：proxy 模式下可限制只旁路目标为这些本机 IP 的包；为空表示不启用本机 IP 过滤。
- `interfaces[].frameSize`：UMEM frame size，默认 `2048`。
- `interfaces[].xskMode`（EN-12）：AF_XDP bind 模式探测策略，默认 `auto`。
  - `auto`：先尝试 zero-copy bind，驱动不支持时显式回退 copy——落地模式记录到每队列状态 `xsk_mode`，探测失败原因写入 `detail`。
  - `copy`：从不尝试 zero-copy，直接按 copy 模式 bind。
  - `zero-copy`：强制 zero-copy；驱动不支持时该队列 socket 创建显式失败（状态可见），不静默降级。
- `proxy.protocols`：允许进入 AF_XDP proxy 数据面的协议族。
- `proxy.ports`：显式发布到 eBPF map 的协议和端口。
- `interfaces[].udpForwards[]` / `interfaces[].tcpForwards[]`：L4 直通转发（XDP_TX NAT）规则，字段 `listen`、`backend`、`nextHopMac`（可空，自动按邻居表解析）、`serverId`、`snat`、`challenge`。
  - `snat: false`（默认）：纯 DNAT，保留客户端源 IP。要求网络不过滤源 IP——多数云厂商的 vSwitch 按端口绑定源 IP 做 anti-spoof，会把这种帧丢掉（已实测：帧计数发出但对端不可达）。
  - `snat: true`：源改写为 `(listen IP, 节点分配端口 40000-60999)`，回包经 `XDP_SNAT_REV` 反向绑定还原客户端 tuple。可在 anti-spoof 云上工作；代价是 backend 看到的源是本节点而非真实客户端。端口分配失败会计 `snat_alloc_fail` 并回落用户态路径（不丢包）。
  - SNAT 模式下 backend 拿不到真实客户端 IP；如需保留可叠加 PROXY 协议（未实现）。
  - `challenge: true`（默认 false，EN-14/ADR-001）：SYNPROXY 式无状态 cookie 挑战。SYN 只换回应答式 SYN-ACK（cookie ISN），不产生任何状态；客户端证明 ACK 通过 keyed-hash 校验后才分配 pending/SNAT/CT 并向 backend 重放 SYN，序号差经 `seq_delta` 常量拼接。
    - **适用范围**：仅 TCP + `snat: true` + IPv4。UDP、纯 DNAT（无可见后端 SYN-ACK 可拼接）、IPv6 规则配置该标志会被**显式拒绝**（规则加载失败并给出原因），不会静默降级为有界准入。
    - **TCP 选项 profile（限定）**：挑战 SYN-ACK 与重放 SYN 均只携带 MSS——被挑战连接两端协商不到 window scale / SACK / timestamps / ECN（有意的保守互操作 profile，见 ADR-001 决策 2）。后果：接收窗口上限 64KB（长肥管道吞吐受限）、无 SACK 快速重传增强、无 PAWS。**需要完整选项协商的高吞吐 TCP 服务不应开启 challenge**；该标志面向 SYN 洪泛防护场景，而不是通用转发路径。
    - 挑战响应受 `budget.challengePps` 聚合限额（默认继承 `newFlowPerSec`）；超额 SYN 记 `challengeRejected` 并丢弃。cookie 密钥为 `XDP_COOKIE_KEY` 双槽（cur/prev）128-bit，校验接受当前与前一时间槽；轮换时上一代密钥签发的 cookie 仍可完成准入，已拼接流不受影响。

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

## 内核程序布局（tail-call）

主程序 `cloud_node_xdp` 按 family/proto 经 `XDP_DISPATCH`（prog array，8 槽位）尾调用到各 NAT 子程序——每个 SNAT-capable handler 约 10KiB BPF 指令，拆分后单个程序才能通过旧内核（6.1 已实测）的 verifier 状态预算：

| 槽位 | 程序 | 覆盖 |
|---|---|---|
| 0 | `xdp_nat_dispatch` | UDP/IPv4 forward + reply |
| 1 | （保留空槽，原 SNI blocklist 已移除） | — |
| 2 | `xdp_nat_tcp_dispatch` | TCP/IPv4 forward + reply |
| 3 | `xdp_nat_udp6_dispatch` | UDP/IPv6 reply，forward 尾调用槽位 5 |
| 4 | `xdp_nat_tcp6_dispatch` | TCP/IPv6 reply，forward 尾调用槽位 6 |
| 5 | `xdp_nat_udp6_fwd` | UDP/IPv6 forward |
| 6 | `xdp_nat_tcp6_fwd` | TCP/IPv6 forward |

槽位为空（旧 .o 缺符号）时 tail-call 落空返回，流量显式走 redirect/PASS 路径，attach 时会有 warning。

## Pinned map 迁移

`/sys/fs/bpf/cloud-node-xdp/` 下的 map pin 跨重启复用。attach 前会逐张比对内核报告的 spec（type/key size/value size/max_entries）与当前 .o 定义；不一致的 pin 会被删除并重建（有 warn 日志），其运行时内容——conntrack、计费快照——丢弃后由流量自然重建。正常升级无需手工清理；手工迁移时可整体删除该目录后重启。

## 性能基线

veth + kernel 6.1 + SKB 模式下 AF_PACKET 注入实测（32B payload，注入器单核上限约 250k pps，数字反映相对差异而非驱动模式上限）：

| 场景 | `snat: false` | `snat: true` | SNAT 开销 |
|---|---|---|---|
| 固定五元组（conntrack-hit 稳态转发） | ~175k pps | ~152-183k pps（4 次中位 ~164k） | ≈5-13% |
| 3 万源端口轮换（每包新流建 CT） | ~121k pps | ~119k pps | ≈2% |
| echo 往返（forward + reverse 全路径） | ~194k pps | ~176k pps | ≈9% |

要点：

- SNAT 稳态每包多一次源地址/源端口重写和 checksum 增量更新，开销个位数到 10% 出头；默认关闭、按 forward 逐条开启。
- 新流建立（CT insert + SNAT 时一次 `NOEXIST` 端口认领）比稳态慢约 30%，SNAT 分配相对 CT insert 开销很小。
- 端口分配失败计数 `snat_alloc_fail` 并显式回落（该包走原路径），不丢包不静默。

OrbStack 7.0 / veth / SKB 复测（注入器 ~1.0M pps）：固定五元组 `snat: false` 1,011k pps 全量转发且 peer 侧 rx 确认 100% 送达；`snat: true` 933k pps（SNAT 开销 ≈8%，与 6.1 实测一致）。洪峰窗口 VM 全局 busy ≈9.7%（7 核摊薄，softirq ≈7.9% ≈ 单核 55%）。

SNAT 端口空间为每个监听元组 21000 个端口（`XDP_SNAT_PORT_BASE`=40000 起，共 `XDP_SNAT_PORT_SPAN`=21000）。高并发轮换流实测（OrbStack 7.0 / veth，注入器上限 ~1.1M pps）：

| 并发流数（轮换） | 结果 |
|---|---|
| 1 万（< 容量） | `snat_bound`=10,000，转发 ≈100%（~800-860k pps），`snat_alloc_fail` ≈0 |
| 3 万（> 容量） | `snat_bound`=21,000（端口空间打满），约 70% 转发、30% `snat_alloc_fail` 显式回落 |

`snat_alloc` 以流元组哈希为基址做至多 8 次线性探测，每次尝试混入 `bpf_get_prandom_u32()` 重新随机基址——仅靠元组哈希会让同一流每次重试命中同一窗口，落在被占区域的流会永远失败（实测曾致约 39% 分配失败、`snat_bound` 停在 ~6k）。并发流超过端口容量是设计上限：超出部分走显式 PASS 回落并计入 `snat_alloc_fail`，可通过观测该计数器定位。

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

