# R1/R2/R3 — EN-14 修复验收 + EN-15 预算验收

日期: 2026-09-15。环境: `.120` (ser591614511633) 探针执行, `.110` (ser790960344190)
构建+测试, 均 Debian 12 / kernel 6.1.0-10-amd64 / 2c/2GiB。本机仅编辑+传输。

## 被测工件

| 工件 | SHA-256 | 位置 |
|---|---|---|
| eBPF 对象 | `3b8549a9c1ea9c2107db834aeb76b627c03df10bca9b1ef53bee9660297423ba` | `.120:/root/cloud-node-dev/data/cloud-node-xdp-ebpf.o` |
| 节点二进制 | `3bda83370ccf7132c58e6a4e5fb6fb328a16e161cbe13a567b87ca035419d1b0` | `.120:/root/cloud-node-dev/target/debug/cloud-node-rust` |
| eBPF 源 main.rs | `c88c792684565c00a77807fcfa9d74193c976f9e47f91dd87d92c927d838a22b` | 三端一致（.110/.120/Mac） |

`.110` 独立重建同一源码得到相同 eBPF 对象哈希（构建可复现）。`.110` 用户态
二进制 `a98fd3fd…` 与 `.120` `3bda8337…` 字节不同（不同 build 目录的构建
非确定性），但内嵌 eBPF 对象相同、源码 manifest 校验一致。

## 探针修复（探针自身缺陷，非 eBPF 回归）

`tcp_frame()` 原先把 TCP checksum 字段留 0 发送。节点对改写包做**增量**校验和
维护（`csum_apply_diff`），输入字段必须是合法值；0 输入使输出为 `~(diff)`
而非合法校验和 —— 表现为"翻译后数据包 csum 错"的假阳性。修复后
`tcp_frame` 计算真实 pseudo-header+segment 校验和（与真实客户端一致）。
证据：`wire_csum == ~(required_diff)` 在双向三帧上精确成立
（`0xca8a=~0x3575`、`0x3575=~0xca8a`）。

## EN-14 探针全阶段（`en14-probe-r6.json`，result=PASS）

| 阶段 | 覆盖 | 结果 |
|---|---|---|
| 0_isolation | 隔离 netns/veth + pin 目录隔离断言 | pass |
| A_challenge_synack | 首 SYN→挑战 SYN-ACK，零状态创建，SipHash cookie 校验，mss=1460→idx3，帧 checksum 合法 | pass |
| F_syn_retx | 重传 SYN→同 cookie 挑战（时间槽内） | pass |
| B_bad_cookie | 伪造 cookie ACK 拒绝，零状态泄漏 | pass |
| C_cookie_admit_replay | 合法 cookie→pending(state=2)+SNAT 端口声明+SYN replay 至 backend | pass |
| D_splice_anchor | backend SYN-ACK→CT 创建、splice_delta、锻造握手 ACK（VIP→backend，双 checksum 合法） | pass |
| E_data_translation | 双向数据序号翻译 + **合法输入 checksum 下输出 checksum 双向合法** | pass |
| M_mss_fallback | 无选项 SYN→cookie idx0；畸形 MSS(len=3)→idx0；锻造回复 MSS=536 | pass |
| G_key_removed_failclosed | key 置零→新 SYN 无挑战；零 key 伪造 cookie ACK 拒绝；存量 splice 流继续转发数据 | pass |
| I_forge_fault_rollback | FAIL_FORGE 注入→显式拒绝、pending+SNAT 回滚、challengeWorkerErr 计数 | pass |
| J_splice_fault_recovery | splice 锻造故障→可恢复重试 | pass |
| K_alloc_fault_points | FAIL_CT_INSERT/FAIL_PENDING_INSERT/FAIL_SNAT_ALLOC 各点回滚 | pass |
| H_syn_flood_bounded | 有效 key+显式小预算 300 SYN 洪泛：预算内挑战、超额受限、窗口 refill | pass |
| R_real_kernel_tcp | 真实内核 TCP 双端：真实 ISN、挑战准入、双向数据 echo("echo:en14-real")、FIN、RST | pass |

pin 隔离：`prod_pin_dir_untouched=true`（生产 `/sys/fs/bpf/cloud-node-xdp`
未被触碰，探针用 `/sys/fs/bpf/en14-probe-<pid>`）。

### R1.1 零 key fail-closed ✓
G 阶段证明：(a) keyring 全零时新 SYN 无挑战发出；(b) 用已知全零 key 计算的
cookie ACK 被拒绝（零 key 不是合法 key）；(c) 已建立 splice 流在 key 缺失期间
继续数据转发；(d) `challengeRejected` 计数递增可观测。

### R1.2 forge 状态清理 ✓
`tb[16..20]`（checksum+urgent）显式清零（`forge_challenge_synack_v4`/
`forge_to_backend_v4`）；D 阶段锻造 ACK 与 A/F 挑战帧均通过独立 checksum
校验；I 阶段注入 FAIL_FORGE → 显式失败，无半成品包发出。

### R2.2 worker 错误路径 ✓
`Err` → 显式 `XDP_DROP`（非 PASS）；admit 状态回滚（pending 删除+SNAT 释放）；
新增 `challenge_worker_err` 计数器与 `XDP_DECISION_INTERNAL_ERR` 生命周期
事件；FAIL_{CT_INSERT,PENDING_INSERT,SNAT_ALLOC,FORGE} 四个注入点全覆盖
（I/J/K 阶段），无半锻造帧投递、无状态泄漏。

### R2.3 MSS 回退 536 ✓
`tcp_syn_mss_idx` 对 doff≤5/未知 kind/len≠4/截断选项全部返回
`MSS_IDX_FALLBACK=0`（MSS_TAB[0]=536）。M 阶段实测：无选项 SYN 与
kind=2/len=3 畸形 MSS 均产生 idx0 cookie；携带选项字段的入包收到的锻造
SYN-ACK MSS=536（`02 04 02 18`）。不再有 1460 默认放大路径。

### R2.4 真实内核 TCP ✓
R 阶段在隔离 netns 内运行真实 socket 双端：内核 ISN、SYN 重传、挑战/cookie
准入、SYN replay+splice 锚定、双向数据 echo、FIN 正常拆除、RST 中止拆除、
CT 状态确认。

## R3：EN-15 Retry 预算（cargo test，.110）

`.110` 全量 `cargo test`：**753 passed / 0 failed**（test.log 完整保留于
`/root/cloud-node-dev/test.log`）。EN-15 定向测试：

- `h3_retry_budget_bounded`：`retryPps` 聚合上限，窗口 refill
- `h3_incoming_ignore_is_silent`：`ignore()` 客户端握手超时（静默）
- `h3_incoming_refuse_is_prompt`：`refuse()` 立即连接失败（显式拒绝）
- `h3_run_endpoint_retry_gate_and_budget`：生产 `run_endpoint` accept 循环，
  `retryPps=1` 窗口内恰好一个 Retry，`retryPps=0` 未验证连接被 ignore

计数器透出：attempted/issued/limited/ignored/refused → perf-monitor 快照。
文档：`docs/configuration.md` `http3Policy.retryPps`/`addressValidation`。

## 遗留/限制（如实记录）

- EN-14 IPv6 challenge 未实现（v6 规则在配置同步时显式拒绝，非静默）。
- R2.4 覆盖核心握手/数据/拆除；"第三 ACK 带数据"、"重复/乱序"、
  "密钥轮换中存量流"子项属深度变体，当前探针未逐一展开——列入后续。
- ADR-001 主动剥离 window scaling/SACK/TS/ECN：单连接单方向 64KiB 窗口
  上限为已知取舍，非实测吞吐。
- `.110` 全量测试为同一源码基线的独立验证；用户态二进制字节哈希与 .120
  不同属构建非确定性，不影响结论。
