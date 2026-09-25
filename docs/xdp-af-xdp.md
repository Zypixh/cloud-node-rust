# XDP/AF_XDP 旁路数据面

本功能提供 Linux-only、默认启用、可回退的 XDP/AF_XDP 数据面。XDP 程序负责在网卡入口提前执行 allow/block/proxy 决策；AF_XDP 负责把命中代理端口的队列包送到用户态；用户态继续复用现有 HTTP、HTTPS、TCP、UDP、SNI、QUIC 和 HTTP/3 路由与防护逻辑。

网卡、队列、attach mode、proxy 端口等全部由代码在本机自动推导：接口取自默认路由与活跃物理网卡，proxy 端口取自当前生效的监听配置。attach 失败、XSK 未就绪或协议/端口未命中时，节点保持原 socket/Pingora/Tokio 路径，并在 `xdp status`/doctor 中给出明确的 fallback 原因。

## 适用范围

- 仅 Linux 生产环境启用。
- 需要 root，或至少具备 `CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`。
- XDP 默认启用；启用后固定为双向数据面（入向代理 + 出向 AF_XDP 回源），没有内核出向选项。
- 标准 MTU 是当前主要验收目标；proxy 模式遇到 jumbo/multi-buffer 风险时会在 doctor 或启动阶段拒绝或回退。
- `fallback: pass`（默认）会 fail-open 到原 socket 路径并记录 fallback 原因；`fallback: fail-start` 会在无法满足 XDP 启动条件时返回错误。

## 构建

普通节点构建仍使用原 Cargo 命令。XDP eBPF 对象在 Linux 目标上由 `build.rs` 自动编译并内嵌进二进制；`cargo xtask build-ebpf` 仍可单独构建到 `data/cloud-node-xdp-ebpf.o`，用于调试或 `xdp.ebpfObject` 显式外部对象热替换。

## 本地配置

XDP 只需要一个开关，优先级为：默认值（启用）< `CLOUD_NODE_XDP` 环境变量 < 配置文件显式值。

```text
configs/api_node.yaml   # 唯一的本地配置文件；xdp 段与 API 连接信息同文件
```

- 不配置任何文件也不设环境变量 → XDP 启用，其余全部自动推导。
- `CLOUD_NODE_XDP=0` / `false` / `off` / `disabled` → 关闭（`1`/`true`/`on`/`enabled` 为开启）。
- 文件中的 `xdp.enabled` 显式值是最终裁决，覆盖环境变量：

```yaml
xdp:
  enabled: false   # 显式关闭，即使 CLOUD_NODE_XDP=1 也保持关闭
```

`cloud-node xdp start` 写入 `xdp.enabled: true`，`cloud-node xdp stop` 写入 `xdp.enabled: false`；两者都保留文件中的其他内容，不会把推导出的运行时状态写回配置。

除 `enabled` 之外的字段（`attachMode`、`fallback`、`interfaces`、`proxy`、`rateLimit`）仍可在文件中显式提供以覆盖自动推导结果，但正常部署不需要；自动推导的状态只存在于内存，不会写回 `api_node.yaml`。

字段说明（显式覆盖时）：

- `attachMode`：`auto`、`drv`、`skb`。`auto` 优先尝试驱动模式，失败后按实现策略回退。
- `fallback`：`pass` 或 `fail-start`，默认 `pass`。
- `interfaces[].name`：要 attach 的本机网卡名。
- `interfaces[].queues`：要绑定 AF_XDP 的队列号。
- `interfaces[].mode`：`observe`、`protect`、`proxy`。
- `interfaces[].localIps`：proxy 模式下可限制只旁路目标为这些本机 IP 的包；为空表示不启用本机 IP 过滤。
- `interfaces[].frameSize`：UMEM frame size，默认 `2048`。
- `interfaces[].xskMode`（EN-12）：AF_XDP bind 模式策略，默认 `auto`。
  - 前置门控（`auto`/`zero-copy`）：运行时先验证网卡驱动有原生 XSK 支持（`xsk_driver_native_floor`，如 virtio_net 需内核 ≥6.11、主流服务器网卡 ≥5.4）；不满足时队列 socket 创建显式拒绝并写入状态——内核模拟的 generic 路径不是受支持数据面（曾在 Debian 6.1 + virtio_net 生产负载下 TX 饱和、SNI 断流）。
  - `auto`：先尝试 zero-copy bind，失败时回退到驱动 copy 路径（virtio_net 自 6.13 起声明 ZEROCOPY 但还要求 hypervisor 协商 VIRTIO_F_ACCESS_PLATFORM，不满足则落 copy；6.11–6.12 的 virtio_net 只有 copy 模式）；落地模式记录到每队列状态 `xsk_mode`。
  - `copy`：显式诊断/测试选项，直接按 copy 模式 bind 且跳过驱动门控——在无驱动 XSK 的环境（veth、netns 冒烟）会落到 generic 路径，不用于生产。
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

### Attach / reload 生命周期（prepare-before-commit）

`attach` 分两个阶段：

1. **Prepare（不触碰运行中数据面）**：map 预算检查 → pinned map ABI 检查 → 加载新对象（兼容 pin 复用）→ map spec 审计 → root 程序与全部 dispatch 子程序的 verifier 加载。任何一步失败都直接报错，**旧程序保持 attach**，流量不受影响。
2. **Commit**：先 detach 旧 links/子程序 pin/dispatch pin → 重新 pin dispatch map 与子程序 → 写 dispatch 槽位 → adopt flow state → 同步策略/localIP/端口/XSK 索引 → 清计数器 → 逐接口 attach 新 link 并 pin。commit 窗口约毫秒级，期间流量走内核路径。

- **Pinned state map ABI 不兼容**：attach 拒绝并列出具体 map 名，旧数据面保持运行；不会删除 pin 后声称无损升级。确认接受状态丢失时执行 `cloud-node xdp detach --purge-state`（显式删除全部 pinned state map 并打 warn 日志），再 attach。
- **reload**：旧 manager 的 kernel links 与 AF_XDP socket 在新代 prepare 期间保持服务；新代 commit 完成后再释放旧代句柄，新 socket 绑定同一队列（socket 创建自带重试，吸收旧 worker 退出窗口）。prepare 失败则恢复旧 manager 继续服务；commit 中途失败则清理半成品 pin 并让旧代重新 attach。
- **AF_XDP 流在 reload 时的语义**：smoltcp 会话绑定在旧 socket 上，无法迁移到内核路径，也无法跨 socket 迁移到新代——handover 时旧 socket 关闭、会话终止（有显式日志与状态记录）。同一（ifindex, queue）上两个 XSK socket 无法共存，这是 AF_XDP 的硬约束；排空不是把旧流"改成 PASS"——活跃 smoltcp TCP 不能透明移交内核。
- 接口从配置中移除时，detach 会扫描 pin 目录下所有 `link-*`，旧代遗留 pin 不会挂在已不受管理的接口上。

### 状态表容量（`xdp.stateTables`）

- attach 在 prepare 阶段先算 eBPF map 的**预占内核内存投影**（hash 条目按 key+value+64B、per-CPU 值乘可能 CPU 数、LPM/ringbuf 按最坏情形），超过 `memory_governor` 的 kernel-BPF 预算即显式拒绝——不静默超配。
- **`stateTables` 缺省时自动缩放**：若默认表规模超预算（小内存节点），按同一比例收缩全部可缩表（CT/pending/SNAT/计费/限流/QUIC DCID/ACL），每表下限 1024 条，缩放值与 knob 语义一致（`ctMaxEntries` 同时约束 TCP/UDP CT，`aclBlocked` 同时约束 4 张 block 表——组内取最小值）。缩放结果打 warn 日志并记录在 status 的实际投影中；已有同构 pin 时优先沿用 pin 尺寸，保证重启后规模稳定。下限都放不下时 attach 显式报错，说明节点过小。
- **显式 `stateTables` 永不静默收缩**：超出预算即 attach 失败——运维的显式选择必须响地失败。
- commit 阶段摘除旧 link 后内核 link 销毁存在 RCU 宽限，`bpf_link_create` 遇 `EBUSY` 有界重试（20×50ms），重试耗尽仍失败则走 commit 失败回滚。

## QUIC 终止 vs 透传

- **终止型**（`h3` proxy 端口）：QUIC 由 quinn 端点正常终止——Retry/地址验证走 `http3Policy.addressValidation` + `retryPps` 聚合预算；超限 Initial 显式 `ignore`（客户端重试恢复），准入拒绝显式 `refuse`。
- **透传型**（`@quic` 服务器）：demux 只做 UDP 转发，**不会**注入节点自生成的 Retry——Retry token 绑定的是真实后端地址，节点伪造会让合法客户端失败。
- **迁移**：短包头包无法被 eBPF 无状态解析，靠 RSS 队列亲和 + 用户态共享 `CidRoutes` 表（跨队列）按 DCID 路由到既有 session；`NEW_CONNECTION_ID`/`RETIRE_CONNECTION_ID` 更新经 `apply_session_cid_update` 同步进路由表。合法迁移保持连接。
- **跨队列 CID 路由**：eBPF 不做跨队列 XSK 转发——XSKMAP redirect 要求目标 XSK 绑定在**当前 ingress (netdev, rx_queue)** 上，跨队列重定向会被内核丢弃。此前按 DCID pin 目标 XSK 的方案在包被 RSS 哈希到错误队列时必然丢包，已整体移除（`XDP_QUIC_DCID` map 及 `upsert_quic_dcid` 链路删除）。现行语义：包固定经 `XDP_XSK_INDEX` 投递到当前 ingress 队列的 XSK，queue reactor 解出 DCID 后交给共享 `quic_udp_demux`/`CidRoutes` 路由到正确 session——跨队列归路由在用户态完成，不依赖内核 redirect。
- `PATH_CHALLENGE`/`PATH_RESPONSE` 是 quinn 内部的迁移验证，不是也不替代 ACL/封禁策略。

## 内核程序布局（tail-call）

主程序 `cloud_node_xdp` 按 family/proto 经 `XDP_DISPATCH`（prog array）尾调用到各 NAT 子程序——每个 SNAT-capable handler 约 10KiB BPF 指令，拆分后单个程序才能通过旧内核（6.1 已实测）的 verifier 状态预算：

| 槽位 | 程序 | 覆盖 |
|---|---|---|
| 0 | `xdp_nat_dispatch` | UDP/IPv4 forward + reply |
| 1 | （保留空槽，原 SNI blocklist 已移除） | — |
| 2 | `xdp_nat_tcp_dispatch` | TCP/IPv4 forward + reply |
| 3 | `xdp_nat_udp6_dispatch` | UDP/IPv6 reply，forward 尾调用槽位 5 |
| 4 | `xdp_nat_tcp6_dispatch` | TCP/IPv6 reply，forward 尾调用槽位 6 |
| 5 | `xdp_nat_udp6_fwd` | UDP/IPv6 forward |
| 6 | `xdp_nat_tcp6_fwd` | TCP/IPv6 forward |
| 7 | `xdp_nat_udp4_work` | UDP/IPv4 工作子程序 |
| 8 | `xdp_nat_tcp4_work` | TCP/IPv4 工作子程序 |
| 9 | `xdp_nat_udp6_work` | UDP/IPv6 工作子程序 |
| 10 | `xdp_nat_tcp6_work` | TCP/IPv6 工作子程序 |
| 11 | `xdp_tcp4_challenge` | EN-14 无状态 cookie challenge/splice（超出 TCP4 work 的栈预算，独立尾调用） |

槽位为空（旧 .o 缺符号）时 tail-call 落空返回，流量显式走 redirect/PASS 路径，attach 时会有 warning。

## Pinned map 迁移

`/sys/fs/bpf/cloud-node-xdp/` 下的 map pin 跨重启复用。attach 前逐张比对内核报告的 spec（type/key size/value size/max_entries）与当前 .o 定义：

- **兼容**：pin 复用，conntrack/SNAT/计费状态无损交接（`adopt_flow_state` bump `XDP_OWNER_EPOCH`）。
- **不兼容的非状态 map**（dispatch 表、计数器、规则表）：删除重建，有 warn 日志，内容本就每次 attach 重建。
- **不兼容的状态 map**（`XDP_TCP_CT`/`XDP_UDP_CT`/`XDP_PENDING`/`XDP_SNAT_REV`/`XDP_FLOW_ACCT`/`XDP_FLOW_EVENTS`/`XDP_OWNER_EPOCH`/`XDP_FLOW_SEQ`/`XDP_COOKIE_KEY`）：attach **拒绝**并报出具体 map 名，运行中数据面不受影响。这是显式的迁移边界——确认接受状态丢失后运行 `cloud-node xdp detach --purge-state` 再 attach。

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

