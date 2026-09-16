# EN-20: T4 阶段一 — AF_XDP 出向 dial 通路 + 内核守卫

Base: `9ab7adc`（T3 之后）
规范: `tasks/xdp-transport-next-steps-2026-09-15.md` v3 §8 T4（T4-1~T4-5）
环境: `vps-110` 构建+测试（2GB RAM，链接经 swapfile 完成）。本机仅编辑+传输。
范围: `vendor/smoltcp-edge`（主动 connect + SYN 选项）、`src/xdp/af_xdp/`
（dial.rs 新模块、bridge、tcp_reactor）、`src/xdp/dial_guard.rs`（新）、
`src/xdp/linux.rs`、`src/xdp/mod.rs`、`src/runtime_mode.rs`、
`crates/cloud-node-xdp-common` + `crates/cloud-node-xdp-ebpf`（XDP_OUT_CT）。

## 交付

### T4-2 smoltcp-edge 主动 connect + 受控 SYN 选项

- `TcpRepr.extra_options: &[u8]`：仅 SYN 段拼接，header_len/emit
  双计数；options 预算恒定 40B。
- `socket.set_syn_extra_options()`：**前置校验**——选项 TLV 走查
  （kind/len 一致性）+ 剩余预算检查，`SynOptionsError` 显式拒绝，
  emit 处不再静默截断。TOA（kind 254）等任意受控选项可注入。
- fork 测试：SYN 携带注入选项、非法/超预算选项拒绝、RST 清除后
  重传 SYN 不带旧选项。194 项 socket/tcp 测试全过。

### T4-3 reactor dialed 会话生命周期

- `AfXdpTcpDialRequest`（remote/local/route/syn_extra_options/oneshot
  reply）；`AfXdpTcpSession` 增 dialed 字段（reply channel + deadline）。
- `AfXdpTcpReactor::dial()`：建 socket → `set_nagle_enabled(false)` →
  装 `CubicRef` 外部控制器 → `set_syn_extra_options` → `connect()`；
  重复流/会话上限/选项非法/connect 失败全部显式 `io::Error`。
- pump 分支：Established/CloseWait → `AfXdpTcpStream` 回投成功；
  Closed/Listen → ConnectionRefused；4s deadline → abort+TimedOut；
  dialed 会话**永不**启动 proxy 任务。
- reap/Drop 释放 owner claim + XDP_OUT_CT 行 + 未决 dial 失败通知。

### T4-4 eBPF XDP_OUT_CT 出向流表

- `XdpOutCtKey`（family/proto + 本地/对端 IP:port；v4 地址
  `v4_embed` 前四字节编码，两侧一致）写入 `XDP_OUT_CT` hash map。
- TCPv4/v6、UDPv4/v6 四个 worker 在 local 命中但入向 CT 未中时查
  XDP_OUT_CT：命中 → `xsk_redirect_current` 进本队列 XSK 并计
  `out_ct_hit`；未中走既有路径。ICMP 内层匹配留待 T4-7/PMTU。
- userspace：`out_ct_key`/`upsert_out_ct`/`remove_out_ct` +
  `XdpManager` 包装；pin 分类入 state pin（换代语义同其他流表）；
  `/status` 增 `outCtHit`。
- **插入先于 SYN 发出**；关闭/失败拨号删除；`set_dial_registry`
  换代时 `drain()` 排空旧代全部行，Drop 兜底——陈旧行不会把回包
  导进已撤 XSK。

### 出向路由与邻居解析（linux.rs）

- `resolve_outbound_route(target)`：`ip -j route get` 取
  dev/prefsrc/gateway → `ip -j neigh show` 取可用 MAC（拒绝
  INCOMPLETE/FAILED/缺失）→ `ip -j link show` 取本端 MAC。
  不猜 L2 地址，全部显式错误。
- `XdpOutboundRoute` → `AfXdpRouteMeta` 线序方向换算在 dial.rs
  注释明确（destination=对端网关 MAC，source=本端 MAC 的入向约定）。

### Dial registry 与队列 demux（af_xdp/dial.rs + bridge.rs）

- `AfXdpDialRegistry`：flow→owner 表 + 每队列有界请求通道
  （`AF_XDP_REACTOR_REQUEST_QUEUE=1024`、drain 预算 256/轮）+
  保留源端口段（旋转游标，claim 即分配，span 耗尽显式 AddrInUse）。
- `dial_tcp` 事务序：路由解析 → owner 端口 claim → XDP_OUT_CT
  插入 → 有界 try_send → oneshot 等回执；**每个失败点回滚已建状态**。
- 跨队列 demux：回包落非属主队列时经 `InjectTcp` 转发属主 reactor；
  `QueueFull`/`OwnerGone` 显式错误，OwnerGone 自清注册。
- 同轮 Dial 先于 InjectTcp 处理，保序。

### T4-5 内核守卫（dial_guard.rs 新模块）

- `xdp.upstream.mode=afxdp`（默认 `kernel`）时 bridge 发布 registry
  前必须装好守卫；**守卫失败=显式错误，registry 不发布**，
  `af_xdp_dial_tcp` 走明确报错而非静默 kernel 回退。
- 校验 `dialPortRange`（默认 40000-49999，可配）落在
  `ip_local_port_range` 内 → `ip_local_reserved_ports` 幂等并集
  写入+回读验证 → nftables `inet cloud_node_dial_guard` 表：
  input base chain + 具名计数器 + TCP/UDP dport span DROP。
- 拆除：swap/disable 路径清 nft 表 + sysctl 反钉（保留外部条目）；
  sweeper 周期刷新具名计数器 → `/status` 出 `upstreamMode`/
  `dialPortRange`/`dialGuardInstalled`/`dialGuardHits`/
  `dialGuardDetail`。

## 验证（vps-110）

- `cargo build --lib`：通过（13 警告均为未接线调用方死代码，
  T4-6 消费后消除）。
- `cargo test --lib xdp`：**150 pass / 0 fail**（含 11 项
  dial_guard 测试 + 既有 dial/registry/CT-key 测试）。
- dial_guard 覆盖：范围校验（空/越界/畸形 sysctl）、pin 幂等+
  外部条目保留、unpin 只删己段、nft 安装命令面、nft 错误显式上抛、
  计数器 JSON 解析、缺失表幂等拆除、ensure 失败不触 nft。

## 遗留 / 设计限制

- T4-6 连接面接管未完成：`toa`/`l4_connect`/`udp_proxy` 尚未消费
  `af_xdp_dial_tcp`——默认 `kernel` 模式行为不变，afxdp 为显式开关。
- ICMP 内层 XDP_OUT_CT 匹配（T4-7 PMTU）未实现。
- 守卫拆装用独立 nft 表，未与 synproxy 表合并（刻意隔离生命周期）。
- `XdpOutboundRoute`/`resolve_outbound_route`/`dial_tcp` 的
  dead_code 警告是 T4-6 未接线的预期信号。
- 真 NIC/zero-copy 出向验收需硬件环境；VPS 上 nft/sysctl 端到端
  安装验证属 T4-8。
