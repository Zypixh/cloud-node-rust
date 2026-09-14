# EN-09: 有界半开准入与流状态机（pending/validated 分层）

Base commit: `863383b` (EN-08)
eBPF object: `data/cloud-node-xdp-ebpf.o` sha256 `00f0e34ee5350401152ae20381220f07520b6fa9d6db6cfb0d494b1b21056618`
ABI: v8
环境: OrbStack x86 VM, kernel 7.0.14-orbstack, 7 CPU, netns/veth 拓扑 (en2-a 10.99.0.5 <-> en2-b 10.99.0.6)

## 设计

把 TCP 直连转发的"半开"状态从权威 CT 表分离到独立有界表：

- `XDP_PENDING` (HashMap, 65536 项硬上限)：裸 SYN 准入的流。`last_seen_ns` 冻结为准入时刻 = 绝对期限。
- `XDP_TCP_CT` (HashMap, 262144 项)：仅存放有握手证据的已建立流。
- `XDP_PENDING_CAP` (Array×1)：承载 `pending_ttl_ns`（`xdp.admission.tcpPendingMs`，默认 3000）。

状态子机：

```
                    绝对期限到期 (pending_ttl_ns)
   ┌─────────┐  ─────────────────────────────►  移除 → 重新准入(新 incarnation)
   │ PENDING │  后端回复命中(SNAT_REV 或直连 reply) ► PENDING_ACKED
   └─────────┘                                    │
        ▲  客户端 ACK&&!SYN                        │ 客户端 ACK&&!SYN
        │  (snat_port==0 时直接晋升)               ▼
        └──────────────────────────── 晋升: XDP_TCP_CT OPEN + 删除 pending
```

关键语义：

1. **隔离性**：SYN 洪泛只能填满 XDP_PENDING；权威 CT 表的 262144 项对已建立流永远可用。
2. **绝对期限**：pending 命中的任何方向（重传 SYN、ACK、后端回复）都不刷新 `last_seen_ns`。过期条目在查表路径上删除，以 incarnation+1 重新准入——旧事件不会污染重用 tuple。
3. **晋升证据**：SNAT 流要求 PENDING_ACKED（回复路径观测到后端流量）+ 客户端 ACK&&!SYN，盲 ACK 不能晋升。纯 DNAT 流回包对节点不可见（nonlocal 过境），客户端 ACK 即晋升。
4. **有界回退**：pending 表满 → `pendingLimited` 计数 + 包走常规判决路径（PASS/redirect），不产生状态、不驱逐既有条目、不静默放行。
5. **CT 满时晋升失败**：计数 `tcpFwdMapFull`，条目保持 pending 并按原绝对期限消亡——不崩溃、不泄漏。

## 改动面

- common: `XdpUdpCtValue._pad`→`incarnation`；`XdpPendingCap._pad`→`pending_ttl_ns`；`XdpCounters`+`pending_limited`（216B）；`XDP_CT_STATE_PENDING`/`PENDING_ACKED`；ABI v8。
- eBPF: `XDP_PENDING`/`XDP_PENDING_CAP` maps；`pending_touch()`（inline(never)，3 参无栈传参）；4 个 TCP work 程序的 reply/forward 路径接入 pending 查表与晋升；SNAT 回复路径对 pending 命中标记 PENDING_ACKED。
- 用户态: `xdp.admission` 配置 + `sync_pending_cap`；`sweep_nat_maps` 增加 pending 绝对期限回收与 SNAT 孤儿活性并集；`pendingLimited` 计数器透传（status/dump-maps/atomic）。

## 验证

- 单元测试：102 xdp 测试通过（含 EN-07/08 回归）。
- Verifier：全部 11 程序被 kernel 7.0 接受；对象内 0 个 r11 引用。
- 矩阵：T01 28/28、T02、T03、T04 全过。
- EN-09 专用探针 `scripts/edge/en09_pending_probe.py` 5/5 通过（`docs/edge-node-evidence/EN-09/probe.json`）：
  - A: SYN → pending=1, CT=0, tcpFwdTx=1
  - B: 窗口内重传仍是 1 项；过绝对期限后新 SYN 重新准入（仍 1 项）
  - C: SYN→SYN-ACK→ACK → pending=0, CT=1, snatReplyTx=1
  - D: SNAT 流上盲 ACK 不晋升（pending=1, CT 不变）
  - E: 70k 随机源 SYN 洪泛 → pending 精确封顶 65536，pendingLimited=4464，CT=0

## 仍存在的限制

- 纯 DNAT（snat:false）流无法观测 SYN-ACK，客户端 ACK 即晋升——这是该模式的固有可见性限制，已在 `pending_touch` 注释和 configuration.md 说明。
- pending 表容量为固定 map 上界，非运行时配置；`tcpPendingMs` 只控制绝对期限。
- 半开表隔离的是"新建握手前状态"；已建立流的 CT 满（262144）仍走既有 `tcpFwdMapFull` 路径。

## 审批说明

无新增降级。pending-full 的回退是显式有界判决（计数 + 常规路径），非静默行为变更；与既有 CT-map-full 回退语义一致。
