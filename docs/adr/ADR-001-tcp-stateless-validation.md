# ADR-001 — TCP 无状态验证：各路径握手所有者与选定方案

状态：Accepted（EN-13）；实现属 EN-14。

## 背景

`ee4d744`/`dbea12d` 之后的 TCP 准入为"有界准入 + 握手锚点"：SYN 创建
有界 pending（绝对期限、序号锚点、SNAT 需观测后端 SYN-ACK 才可晋级）。
剩余缺口：未验证 SYN 仍会被转发到后端并占用 pending/SNAT 资源——随机源
SYN 洪泛下后端 TCB 与节点临时状态仍有成本。EN-13/14 要求为每条 TCP
承载路径明确"强验证"或"有界准入"的归属。

## 三条路径的握手所有者

| 路径 | 所有者 | 验证能力 |
|---|---|---|
| kernel socket（非 XDP 接管端口、XDP 未就绪回退） | 内核 TCP 栈 | 本地终止=强验证；洪泛防护由既有 `kernel_syn_defense` nft SYNPROXY 提供 |
| AF_XDP（smoltcp reactor 终止） | 用户态协议栈 | 本地终止=强验证；半开由每 worker 会话预算+完成队列有界化 |
| NAT direct-forward（`tcpForwards`） | eBPF 数据面 | 需要 XDP 内建挑战——本 ADR 的对象 |

### 纯 DNAT 的根本限制

纯 DNAT（`snat: false`）下后端回复不经过节点（nonlocal 过境），节点
**无法观测后端 ISN**，因此 cookie 挑战后无法做序号拼接——SYNPROXY 在
该拓扑下不成立。纯 DNAT 路径保持"有界准入"并如实声明，不认证为强验证。
强制要求强验证的服务必须使用 `snat: true`（回复路径可见）。

## 选定方案：SNAT 转发的 cookie 挑战 + 序号拼接（SYNPROXY 模型）

对配置 `challenge: true` 的 TCP 转发规则（要求 `snat: true`）：

```
client                node(XDP)                backend
  |-- SYN(c_isn) ----->|                        |
  |                    | cookie = SipHash24(key,|  (不建任何状态)
  |                    |   tuple, slot)|mss_idx |
  |<-- SYN-ACK(s_isn=cookie, MSS) --|           |
  |-- ACK(seq=c_isn+1, ack=s_isn+1)->|          |
  |                    | 验证 cookie 通过：       |
  |                    | dim1+dim6 计费 → 建      |
  |                    | pending(SPLICING) +     |
  |                    | SNAT 端口认领            |
  |                    |-- SYN replay(c_isn) --->|
  |                    |<-- SYN-ACK(b_isn) ------|
  |                    | 消费不回传；记录          |
  |                    | delta = s_isn - b_isn   |
  |<-- nothing         |-- ACK(b_isn+1) ------->|  (后端握手完成)
  |-- data ------------| seq 不变, ack-delta --->|
  |<-------------------| <--- seq+delta, ack 不变|
```

### 关键决策

1. **cookie = SipHash-2-4(密钥, client_ip|client_port|listen_ip|listen_port, slot) | mss_idx(3bit)**。
   SipHash-2-4 是标准 keyed hash（非自研密码），内核 syncookie 同构。
   密钥为 `XDP_COOKIE_KEY` 双槽（cur/prev）128-bit，用户态生成并轮换；
   校验接受当前 slot 与前一 slot（~64-128s 窗口）。
2. **挑战 SYN-ACK 不含 TS/SACK/wscale/ECN**，replay SYN 同样剥离
   TS/SACK/wscale/ECN 并保留客户端 MSS——双向选项规范化后，序号拼接
   只需一个常量 `delta = s_isn - b_isn`：
   - client→backend：`ack -= delta`（seq 不变，客户端序号空间一致）
   - backend→client：`seq += delta`
   无 TS echo 换算、无 SACK 块换算、无窗口缩放换算。代价是被挑战连接
   协商不到 TS/SACK/wscale/ECN——有意的保守互操作 profile，已记录。
3. **状态创建时机 = cookie 验证通过**（ACK 到达）而非 SYN 到达：
   随机源 SYN 只触发一次无状态挑战响应（dim3 `challenge_pps` 限额），
   不分配 pending/SNAT/CT——"随机源 SYN 不分配昂贵会话"验收点。
   合法新建在 ACK 处支付 dim1+dim6——拒绝先于任何状态写入。
4. **第三 ACK 携带数据**：cookie 有效但 splice 未完成前到达的数据
   被消费不回传——客户端 TCP 重传恢复（标准丢包语义）。SYN-ACK
   重传同理：重传 SYN 重新获得挑战（无状态，天然幂等）。
5. **后端 SYN-ACK 被消费**，节点代答 ACK 完成后端握手；客户端侧的
   SYN-ACK 已由挑战发出——与 nft SYNPROXY 的 splice 语义一致。
6. **默认关闭**：`challenge` 为 per-rule 显式开关，未配置路径保持
   现有有界准入，行为零变化；能力矩阵在服务状态/证据中逐条标注
   "strong-challenge" vs "bounded-admission"。

### 与既有 nft SYNPROXY 的关系

`kernel_syn_defense` 的 SYNPROXY 只作用于内核 socket 端口
（`protected_tcp_ports`）——XDP 接管的转发端口不进内核 INPUT 链，
两套机制作用域不相交，不叠加。若某端口同时被 XDP tcpForwards 接管与
SYNPROXY 保护，XDP 在内核之前处理 → XDP 挑战生效，nft 规则对该流量
不可达。规则生成器必须以 XDP 接管端口集为准剔除重叠（配置检查项）。

### Linux 能力核查

- 内核自测试 `xdp_synproxy_kern.c` 证明了 XDP 生成/校验 syncookie 的
  可行性（它把验证后的 ACK 交给内核 syncookie 路径而非拼接——拼接是
  本方案超出示例的部分，也是 nft SYNPROXY 已验证的模型）。
- `bpf_xdp_adjust_tail`（收缩挑战包选项空间）、`bpf_csum_diff`
  （增量校验和）在目标内核（≥5.10，OrbStack 7.0 实测）可用。
- SipHash-2-4 为 ~64 条直线指令/16B 输入，无循环，verifier 友好。

## 影响与撤回

- ABI v14：`XdpUdpCtValue` +`seq_delta`/`splice_state`/`mss_idx`
  （56→64B），`XdpUdpFwdRule` +`challenge` flag，`XdpCookieKey` +
  `XDP_COOKIE_KEY` map，`XdpCounters` +`challenge_sent`/
  `challenge_rejected`/`splice_*`，`XDP_BUDGET` dim3 启用。
- 撤回：`challenge: false`（默认）即回到既有有界准入；运行时关闭
  后存量 spliced 流的 delta 翻译仍继续（状态在 CT 中，不漂移）。
- 失败发布/旧代兼容：ABI bump + map-spec 审计拒绝不匹配 pin；
  旧对象无 challenge flag → 行为与今天完全一致。

## 验证计划（EN-14 证据）

- veth/netns 双端实测：netns 内**真实内核 TCP 客户端**连接被挑战
  端口 → 完整握手 + 双向数据一致性（挑战 SYN-ACK 必须被真实协议栈
  接受——这是对 cookie/选项/校验和最严格的验证）。
- 负路径：伪造源 SYN 只产生 challenge_sent（无 pending/SNAT/CT）；
  坏 cookie ACK 计 `challenge_rejected` 且不建状态；dim3 用尽时
  挑战响应被限额（计数可观测）。
- 重传 SYN 幂等、ACK 携带数据、FIN/RST 半关闭、splice 后序号
  翻译的双端抓包核对。
