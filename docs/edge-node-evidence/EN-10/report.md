# EN-10: 连接所有者反馈与存量流

Base commit: `1e712b6` (EN-12)
eBPF object: `data/cloud-node-xdp-ebpf.o` sha256 `b776ddfe9249c5e78358d6458f6b563aab44e9f1690e327b72f7e096dd1d8208`（ABI v9）
环境: OrbStack x86 VM, kernel 7.0.14-orbstack, netns/veth 拓扑 (en2-a 10.99.0.5 <-> en2-b 10.99.0.6)

## 交付内容

### 1. eBPF FlowEvent 发布通道（ABI v9）

- `XDP_FLOW_EVENTS`：RingBuf，256 KiB 有界，`XdpFlowEvent` 88B/条。
- `XDP_OWNER_EPOCH`：Array×1，用户态在每次 attach 时写入严格递增的代次。
- `XDP_FLOW_SEQ`：PerCpuArray 序号，事件按 `(flow_incarnation, owner_epoch, seq)` 全序。
- 发射点：pending 准入（ADMITTED）、握手晋级（VALIDATED）、CLOSING 转换（CLOSED）、
  流表满拒绝（REJECTED）。
- 环满 → `flow_event_lost++`（`XdpCounters` 新字段），**绝不阻塞数据面**。
  事件通道为 advisory；权威状态始终在内核 CT/pending map。

### 2. 存量流接管（分代 + pin）

- 状态 map 全部 pin：`XDP_TCP_CT`/`XDP_UDP_CT`/`XDP_PENDING`/`XDP_SNAT_REV`/
  `XDP_FLOW_ACCT` + 三个新 map。reload/重启后按 spec 匹配复用；
  `drop_stale_pinned_maps` + EN-16 spec 审计防 ABI 错位。
- attach 时扫描状态 map → `importedFlows` 计数。
- 每代 manager 写 `XDP_OWNER_EPOCH`；事件带 epoch 戳，陈旧代次事件被丢弃。

### 3. 用户态消费与有界 ledger

- 每代 generation 独立消费任务（`run_flow_event_consumer`），通过
  `open_pinned_flow_events` 独立打开 pinned ring（不持 manager 锁）。
- 代次失配或 manager 不再是 current → 显式退出（旧 worker 无法续租新流）。
- 有界 `FlowEventLedger`：按 `(incarnation, epoch, seq)` 排序，陈旧事件拒绝
  （`eventsStale++`）；容量满优先逐出 terminal（CLOSED/REJECTED）条目
  （`eventsEvicted`）。**事件永不创建信任状态**——未知流不会被"学习"为可信。
- drain 后触发节流 persist（`claim_status_write_slot`），跨进程
  `xdp dump-maps` 可读 pinned epoch + 持久化快照。

### 4. 可观测性

状态文件与 `dump-maps` 透出：

```json
"flowFeedback": {
  "ownerEpoch": 2, "importedFlows": 2,
  "eventsReceived": 0, "eventsStale": 0, "eventsEvicted": 0
},
"flowEventLost": 0
```

## 验证

### 探针 `scripts/edge/en10_flow_probe.py`（全 3 阶段通过，见 `probe-result.json`）

| 阶段 | 结果 |
|---|---|
| A 冷启动 | `importedFlows=0`（干净起点）、`ownerEpoch=1`、4 条生命周期事件被消费（TCP+UDP admit/validate）、`flowEventLost=0`、`eventsStale/Evicted=0`；TCP CT=1、UDP CT=1、SNAT 端口分配正常 |
| B 持久性 | 进程停止后 10 个 pin map 全存活，2 条 CT 条目保留（`ctEntriesAfterStop=2`） |
| C 重启接管 | `importedFlows=2`、`ownerEpoch=2`（换代）；存量 TCP/UDP 流**无需重新准入即恢复转发**：`tcpFwdTx+3`、`udpFwdTx+3`（counterDeltas 含 packets+8/tx+6）；事件通道在新代次独立工作 |

### 验收映射

- **第三 ACK 后首批数据不被同步空窗误杀**：EN-09 数据面晋级语义不变
  （PENDING→PENDING_ACKED→OPEN），事件仅旁路反馈；探针 phase A/C 的
  `data_ack` 序列转发成功（`tcpFwdTx` 递增）。
- **reload 不切断已导入连接**：phase C 直接证明——进程重启后 pinned CT
  条目被接管（`importedFlows=2`），同 tuple 流量继续转发。
- **未知流不被轻易"学习"为可信**：ledger 仅 advisory mirror；信任状态
  只能由数据面握手证据产生（内核 map 权威）。
- **旧 worker 无法续租新流**：消费任务按 generation 运行，代次戳在每条
  事件上；manager 换代后旧任务退出、旧代次事件 stale 丢弃。
- **事件丢失/满队列保守策略**：RingBuf 有界 256KiB；满 →
  `flow_event_lost` 计数透出，数据面不阻塞、不静默。

### 其他验证

- eBPF verifier：对象通过（build-node ARM64 `cargo xtask build-ebpf` 产出；
  x86-build 上 attach/T01 矩阵通过）。
- 单测：`FlowEventLedger` 排序（incarnation/epoch/seq）+ terminal-first
  逐出；全量 662 lib 测试通过。
- ARM64（build-node）与 x86（x86-build）最终源码编译均通过。

## 排查记录（探针修正，非实现改动）

初版探针 phase C 报 `tcpFwdTxDelta=0/udpFwdTxDelta=0`：

1. **跨进程计数不可见**：`xdp dump-maps` 是独立进程，读不到 daemon 的
   原子计数 → `flowFeedback` 改为读 pinned `XDP_OWNER_EPOCH` + daemon
   持久化状态文件，消费 drain 后触发节流 persist。
2. **残留 pin 污染断言**：历史运行的 pin 被 adopt，phase A 看到
   `importedFlows=1/epoch=16` → 探针起点清理 `XDP_BPF_PIN_DIR`（仅探针
   自有状态目录）保证确定性。
3. **发送时机贴 attach 边界**：phase C 加 3s settle 并把全量
   `counterDeltas` 录入结果以便诊断。

## 设计限制

- 事件通道为 advisory：重启间隙内发生的生命周期转换（进程停止期间无
  eBPF 运行，不会丢未决事件；但 map 内状态本身以 pin 为准）不构成账本
  缺口——账本每代重建，`importedFlows` 是接管基线。
- RingBuf 满只计数不反压（设计要求：事件绝不阻塞数据面）；突发生命周期
  转换率超过消费速度时 `flowEventLost` 上升，CT map 仍完整。
- CLOSED 事件在 CLOSING 转换点发射；sweeper 按空闲超时回收的条目不逐条
  发射 EXPIRED（保留 kind 供后续扩展）。
