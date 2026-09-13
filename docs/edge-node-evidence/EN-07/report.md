# EN-07 — 聚合预算与每路径容量保护

状态：**VERIFIED（veth/netns）**。

## 交付

### eBPF（ABI v6）

- `XDP_BUDGET_CFG`（Array×1，`XdpBudgetConfig` 48B）：`unverified_pps` / `new_flow_per_sec` / `xsk_redirect_pps` / `challenge_pps` / `window_ns` / `flags`（bit0=unverified、bit1=new-flow 生效位；bit2/3 预留 EN-12/15）。
- `XDP_BUDGET`（PerCpuArray×1，`XdpBudgetBucket` 64B）：每 CPU 独占固定窗口桶——每 CPU 内读改写无竞争，聚合配额由用户态预分，不随 CPU/队列数倍增（I09）。
- 计费点：
  - **unverified（dim 0）**：`handle_ipv4`/`handle_ipv6` 中，本地 TCP/UDP、ACL 之后、per-source 桶创建之前——三模式一致。
  - **new-flow（dim 1）**：4 个 NAT work 路径（udp4/tcp4/udp6/tcp6）的 CT-miss 分支，`snat_alloc`/`CT.insert` 之前。拒绝即 DROP + `admissionLimited`，零残留状态。
- 已验证流保留池：CT-hit 与 SNAT_REV-hit 路径不消耗 new-flow 预算——洪峰无法剥夺已建流的状态。
- 源桶耗尽回退：`rate_bucket_hit_*` insert 失败 → 记 `ratelimitMapFull` 后仅受聚合上限约束（EN-00 发现#1 的 fail-open 已收敛为有界回退）。
- 新增计数器：`unverifiedLimited`、`admissionLimited`（`dump-maps`/status 透出）。

### 用户态

- `xdp.budget` 配置（`enabled`/`unverifiedPps`/`newFlowPerSec`/`windowMs`），缺省启用内置基线（2M pps / 100k flow/s / 1s）。
- `effective_budget_config()`：节点总额 → ceil(total/ncpu/divisor) 每 CPU 份额，下限 1；压力缩放 Elevated×1/High÷2/Critical÷4——"除到 0"永不等于关闭；`enabled:false` 是唯一显式关闭路径。
- `sync_budget` 随 sweeper tick（5s）写入 `XDP_BUDGET_CFG`；写入失败只告警不静默。

## 验证

| 证据 | 结果 |
|---|---|
| verifier | 11 程序 kernel 7.0 全部接受；`llvm-objdump` 零 r11 |
| T01 | 28/28 |
| unverified 门 | `unverifiedPps:20` 下 300 UDP→代理口：`unverifiedLimited=297, drop=297, pass=5` |
| new-flow 门 | `newFlowPerSec:5` 下 100 个独立 UDP 四元组→FWD 口：`snatBound=7, udpFwdTx=7, admissionLimited=14, unverifiedLimited=79` —— 拒绝先于建表 |
| CPU 倍增防护 | 份额=ceil(总/ncpu) 且 min 1，单测 `effective_budget_config_baseline_and_share_math` |
| Normal 基线 | 无配置时 flags≠0、份额≥1（单测） |

## 与验收对照

- 拒绝发生在源桶/CT/SNAT 创建前 ✓（unverified 门在源桶前；admission 门在 insert 前）
- 重复同 tuple 不绕过处理预算 ✓（CT-miss 重传每包计费）
- CPU/队列变化不倍增总配额 ✓（预分份额）
- Normal 有基础上限 ✓（内置基线）
- 用户态反馈停止仍有保护 ✓（eBPF 内静态执行，sweeper 只重推配置）

## 限制（如实记录）

- `xsk_redirect_pps`/`challenge_pps` 维度定义已入 ABI，执行点属 EN-12（每队列）/EN-15（挑战响应）。
- 已验证流的带宽预留=状态持有+免 admission 计费；共享 unverified 上限下的带宽隔离为简化实现，per-队列/后端 PPS/BPS 属 EN-12。
- 半开并发上限由 TCP CT 容量+sweeper 提供，`XdpPendingCap` 合同已定义，接入待 EN-09。
