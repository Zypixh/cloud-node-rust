# EN-07 — 分层预算与每服务公平

状态：**VERIFIED（veth/netns，ABI v13）**。

## 交付

### eBPF

- `XDP_BUDGET_CFG`（Array×1，`XdpBudgetConfig` 72B）：`unverified_pps` / `new_flow_per_sec` / `xsk_redirect_pps` / `challenge_pps` / `verified_pps` / `control_pps` / `service_flow_pps` / `window_ns` / `flags`（bit0-6 生效位）。
- `XDP_BUDGET`（PerCpuArray×1，`XdpBudgetBucket` 96B，6 个聚合维度）：每 CPU 独占固定窗口桶——读改写无竞争，聚合配额由用户态按 possible-CPU 数预分（ceil、下限 1），CPU/队列数变化不倍增总配额。
- `XDP_SVC_BUDGET`（PerCpuHashMap `u32→XdpSvcBucket`，256 项/CPU，dim6）：按**监听 dst port** 分桶的每服务新建准入额度。分布式洪泛只耗尽目标服务自身份额；兄弟服务不受影响。
- 计费点：
  - dim0 unverified：handle 阶段（三模式，ACL 之后、源桶之前）。
  - dim1 new-flow：全部 4 条 NAT 准入路径（udp4/tcp4/udp6_fwd/tcp6_fwd）的 CT-miss 分支，`snat_alloc`/insert 之前——拒绝零残留。**补齐了 v6 路径此前缺失的计费点**（v4/v6 对称）。
  - dim2 xsk-redirect：AF_XDP 重定向。
  - dim4 verified：CT-hit / SNAT_REV-hit 路径（独占池，unverified 洪泛永不挤占已建流）。
  - dim5 control：ICMP/ND/PMTU 必要控制报文。
  - dim6 per-service：dim1 通过之后、状态创建之前——先聚合门、再服务门，两级都不放行即 DROP。
- 服务表容量耗尽是有界可观测回退：insert 失败计 `svcBudgetFull`，包仍受聚合 dim1 信封约束——不是静默绕过。
- 计数器透出：`unverifiedLimited` / `admissionLimited` / `verifiedLimited` / `controlLimited` / `serviceLimited` / `svcBudgetFull`（`dump-maps` 与 status）。

### 用户态

- `xdp.budget` 增加 `verifiedPps` / `xskRedirectPps` / `controlPps` / `serviceFlowPps`；`serviceFlowPps` 缺省等于 `newFlowPerSec`——单服务节点行为不变，多服务节点获得可调公平下限。
- `effective_budget_config()`：全部维度按 `ceil(total/ncpu)` 预分、下限 1；`enabled:false` 是唯一显式关闭路径；flags=0b1110111。
- map-spec 表新增 `XDP_SVC_BUDGET`（PerCpuHash, key u32, value 16B, 256 项）；pinned map 审计按 ABI 拒绝不匹配布局。

## 验证

| 证据 | 结果 |
|---|---|
| verifier | 全部程序 kernel 7.0.14-orbstack 接受；对象 sha256 `ec673d6c` |
| 单测 | 107 xdp / 668 lib 全过；`effective_budget_config` 覆盖 dim6 缺省与份额数学 |
| 服务预算探针 | `en07_svc_budget_probe.py` 4/4 阶段（serviceFlowPps=64，7 CPU → 份额 10） |
| EN-08/09/10/11/12 回归 | 全绿（见 manifest） |

探针实测（veth/netns）：

- **A 基线**：UDP:8543 + TCP:8443 少量新流正常准入，`serviceLimited=0`。
- **B 服务洪泛**：400 个独立 tuple 打 :8543 → `udpFwdTx=56`（份额+窗口边界内），`serviceLimited=344`，`admissionLimited=0`——dim6 封顶但未归零，聚合信封未被消耗。
- **C 兄弟公平**：4 个新 SYN 打 :8443 全部准入（pending 表有记录），`serviceLimited/admissionLimited` 增量均 0——:8543 的洪泛没消耗 :8443 的额度。
- **D 已建流不受影响**：已准入 tuple 重发继续转发（`udpFwdTx=2`，`serviceLimited=0`）——CT-hit 路径不再付准入/服务计费。

## 与验收对照

- 未验证/新状态/服务/AF_XDP/已验证/控制六维有总上限 ✓
- 拒绝先于源桶/CT/SNAT/pending 创建 ✓
- 同 tuple 重复包持续付费 ✓（CT-miss 每包计费；CT-hit 走 dim4 不走 dim1）
- 配额不随 CPU/队列数倍增 ✓（预分份额，下限 1）
- 正常流量保留池 ✓（dim4 独占 + dim0 退款；探针 C/D 实测兄弟服务与存量流不受洪泛影响）
- 用户态反馈停止仍有保护 ✓（eBPF 内静态执行）
- 细粒度控制不可用时回退明确可观测 ✓（`svcBudgetFull` 计数 + 聚合信封兜底）

## 限制（如实记录）

- 服务键仅为报文 dst port——同端口不同 VIP 共享一个桶；如需按 VIP 隔离是未来扩展。
- `XDP_SVC_BUDGET` 容量（256/CPU）外的服务回落到聚合 dim1 信封——`svcBudgetFull` 计数，非静默。
- 固定窗口在边界处是近似公平，非精确令牌桶。
- `challenge_pps`（dim3）为 EN-15 预留；每后端 PPS/BPS 属 EN-16 范围。
- 证据环境为 veth/netns；真实 NIC 多队列下的每 CPU 分布验证待真实网卡环境。
