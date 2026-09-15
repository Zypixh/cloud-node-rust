# EN-14: TCP 无状态 cookie 挑战 + 序号拼接（挑战规则不落盘未验证状态）

> **2026-09-15 验收更新**（REVIEW-2026-09-15）：当前 ABI **v16**。
> 复验工件：eBPF 对象 `3b8549a9c1ea9c2107db834aeb76b627c03df10bca9b1ef53bee9660297423ba`，
> 节点二进制 `3bda83370ccf7132c58e6a4e5fb6fb328a16e161cbe13a567b87ca035419d1b0`（.120）。
> 升级探针 16 阶段全过：零 key fail-closed、forge 故障回滚、MSS=536 回退、
> 真实内核 TCP 端到端（echo+FIN+RST）。下方原始记录保留工件旧值不溯改。
> 详见 `../REVIEW-2026-09-15/R1-R3-validation.md`。

Base: 工作树（EN-13 ADR-001 实现），ABI v15
eBPF 对象 sha256: `e549c8352a5d6ba7329ec6b5467d9f2f67a79732518db7ebd2389d3a8f501338`
节点二进制 sha256: `b8c0ab7c45b2f13bca1e237f9b9f236fe5ea4aa8e268d4a7c4df7b2ecbee3532`
环境: VPS `.120`（隔离 netns/veth `en14-a`<->`en14-ns`），Debian 12，**kernel 6.1.0-10-amd64**（严格 verifier：无 BTF 子程序 tail_call、栈深度合并上限 512B、spill 槽按存储时类型追踪）
探针: `scripts/edge/en14_cookie_probe.py`

## 架构

`challenge && snat` 规则下的无状态握手：

1. 客户 SYN → dim3 挑战预算 → `cookie_make_v4`（SipHash(tuple, listen_addr, 时间槽)，
   低 3 位嵌 MSS 索引）→ 原地把 SYN 改写为 SYN-ACK（XDP_TX），**不创建任何状态**。
2. 客户证明 ACK（ack == cookie+1）→ `cookie_check_v4`（cur/prev key × 当前/上一时间槽
   四路掩码比较）→ 此刻才支付 dim1/dim6 准入预算、SNAT 认领、pending SPLICE_WAIT
   记录、向后端 replay SYN（保留 client ISN）。
3. 后端 SYN-ACK → `tcp_splice_anchor_v4`：pending → 权威 CT（OPEN + SPLICE_DONE），
   `seq_delta = splice_isn - b_isn`，删除 pending，向后端锻造握手 ACK
   （seq=c_isn+1, ack=b_isn+1），被消费的 SYN-ACK 不转发。
4. 之后数据路径走常规 CT：`splice_delta` 双向翻译序号（client 侧活在挑战空间）。

### 512B 栈约束 → slot-11 tail-call worker

`parse → NAT → challenge → forge → checksum` 合并帧在 6.1 上实测 672B，
超过 512B 上限。解决方式不是削减语义而是程序边界：

- `XDP_DISPATCH` ProgramArray 新增槽 11 = `xdp_tcp4_challenge`。
- 调用方把跨界状态（forge_seq/ack/mss/flags/win/src_port/next_hop、
  incarnation、server_id、forge_op）停进 `NatScratch`（440B），
  在 `try_nat_tcp4_work` **程序作用域** tail_call——内核禁止无 BTF
  子程序内 tail_call。
- worker 重新 `work_ctx()` 读取偏移并重新查 map（map 指针不能跨
  tail-call 边界），splice gate 在 worker 内复检——并发 CPU 可能
  在中间锚定/过期同一记录。
- 槽位缺失（旧对象）→ `challenge_rejected++` + XDP_DROP，明确且
  可观测，绝不把未验证的包放进常规路径。

### 6.1 verifier 对标量→包指针的严格性

`work_ctx` 里 map 加载的偏移量若先被 spill 再做界检查，spill 槽的
跟踪类型在**存储时刻**固定，检查后的收窄不会追溯——重载出来仍是
`umax=65535/0xffffffff`，6.1 拒绝 var-off 包访问。且调用方建立的
任何界都会变成 LLVM range 元数据，把 callee 内的检查折叠成 no-op。

修法：偏移在**加载点**用 `& 0x7ff` 掩码（`bound_work_offsets` +
`work_ctx` + `maybe_redirect` 同一模式）。AND 是不可折叠的单条 ALU，
执行后原始值即死，任何下游 spill/reload 都自带 `umax<=0x7ff`。
合法偏移恒 <512B，掩码对真实值是恒等；损坏的 scratch 只会得到
有界的错误偏移，解析失败被拒——不会越界。

同理，锻造/修补路径里所有**变量偏移**的包读写走
`bpf_xdp_load_bytes`/`bpf_xdp_store_bytes`（标量偏移，无需指针范围
证明），IP/TCP 校验和在栈缓冲上算完再一次性 store——消掉了
`csum_diff` 包指针模式和 adjust_tail 后的二次读写。

### splice-gate 前置

backend→client 方向的 SNAT 应答路径原本先做 client 向改写再查
splice——worker 拿到的帧 eth.src 已是节点 MAC、ip.dst 已是 client，
锻造的 ACK 会错用 client 地址。现 splice-gate 提前到 ct_key 构建后、
任何改写前：worker 在**原始** backend→VIP 帧上锻造
（eth.src=backend next-hop、ip.dst=VIP 完好）。

### cookie 时间槽

`cookie_slot = now >> 32`（~4.3s/槽），验证接受当前+上一槽（~8.6s
窗口）——覆盖真实 RTT 与重传周期，有界不可无限重放。重传 SYN 落新
槽得新 cookie 是正确语义（客户 ACK 最新一个即被接受）。

## 探针结果（全部通过）

| 阶段 | 验证 | 结果 |
|---|---|---|
| A | SYN→挑战 SYN-ACK（ack=c_isn+1，MSS 选项），**pending/ct/snat 全 0** | PASS |
| F | 重传 SYN 再获合法挑战（同槽同 cookie） | PASS |
| B | 坏 cookie ACK → challengeRejected++，零状态 | PASS |
| C | 合法 cookie → pending SPLICE_WAIT + SNAT 端口(42544) + SYN replay(seq=c_isn→backend) | PASS |
| D | 后端 SYN-ACK → CT OPEN+SPLICE_DONE、seq_delta=cookie−b_isn、pending 消费、向后端锻造 ACK(seq=c_isn+1,ack=b_isn+1) | PASS |
| E | 数据双向：client ack 译出挑战空间、backend seq 译入挑战空间 | PASS |
| G | keyring 置零后新 SYN **无挑战**且计数拒绝；已建流不受影响 | PASS |
| H | 300 SYN 洪泛 → 全部预算内拒绝（challengeRejected=302），状态表零增长 | PASS |

计数器终态: packets=10 后洪泛, challengeSent=2, challengeRejected=302,
snatBound=1, tcpFwdTx=4, snatReplyTx=1, drop/pass 均显式计数。

## 边界与限制

- veth/netns 证据；真实 NIC 多队列、大流量洪泛下的挑战吞吐属外部硬件验收。
- cookie 有效窗口 ~8.6s（cur+prev 槽）；超过窗口的迟到 ACK 被拒并计数——
  有界设计取舍，不是无限宽限。
- 挑战应答（SYN-ACK forge）在 XDP_TX 上支付 dim3 预算——洪泛期挑战发送
  自身有界（H 阶段 300 SYN 全部预算拒绝、无状态泄漏）。
- 非 SYN/非证明包在挑战规则上无状态时返回 Ok(None) 交常规路径——
  与既有"非本路径流量"语义一致。
