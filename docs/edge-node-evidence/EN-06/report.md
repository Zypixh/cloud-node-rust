# EN-06 — 独立受保护服务与路径策略

状态：**VERIFIED（veth/netns 拓扑）**。commit 基线见 manifest。

## 范围

ProtectedServices、防护作用域与 AF_XDP redirect 解耦、ACL 优先级、方向识别、observe/protect/proxy 一致性、XSK readiness、per-VIP 分片覆盖。

## 交付

### 1. ProtectedServices 配置（`src/runtime_mode.rs`）

- `XdpProtectedService { ip, redirect, fragmentAction }`：per-VIP 防护策略。
- `redirect`（默认 true）独立于防护：false 时 VIP 仍在 XDP 分类/ACL/限流/分片策略之下，但代理端口流量交还内核栈。
- `fragmentAction` 覆盖接口级 `fragmentAction`（LOCAL map value bits[2:1]）。
- 校验：`ip` 必须列在 `localIps`（否则拒绝启动）、禁止重复项。

### 2. LOCAL map 值编码（`xdp-common`，ABI v4）

`XdpLocalValue` flags 位：
- bit0 = `LOCAL_FLAG_REDIRECT`（1=允许 redirect，0=防护但交还内核）
- bits[2:1] = fragment 覆盖（0=继承接口，1=pass，2=drop）

用户态 `local_ip_flags()`（`src/xdp/linux.rs`）从 `protectedServices` + 接口 `localIps` 合成。未列出 protectedServices 的 VIP 保持默认（redirect=1、继承接口分片策略）——与 EN-06 前语义一致。

### 3. eBPF 判定顺序（`crates/cloud-node-xdp-ebpf/src/main.rs`）

`handle_ipv4`/`handle_ipv6` 顺序（每条路径终结动作明确）：

1. `parse_frame` 分类 + `local_flags` 一并返回（`u32::MAX` 哨兵 = 非本地）
2. 分类为 malformed → `drop` + `malformed`（分类丢弃先于 ACL——无效包不消耗 ACL 判定）
3. 本地地址：
   - 分片 → `local_fragment_action()`（接口默认 + per-VIP 覆盖），动作 pass/drop
   - ACL 精确 + CIDR：observe → `aclWouldBlock` 计数后放行；protect/proxy → `aclBlocked` + drop
   - `mode==2`（proxy）→ `dispatch_local` tail-call NAT 派发
4. `redirect_from_scratch`：仅当 `local_flags & REDIRECT` 且 proxy bridge ready 才进 AF_XDP；否则显式 PASS（`nonlocalPass`/`pass` 计数区分）

### 4. 计数器与可观测（ABI v4）

新增 `aclWouldBlock`（observe 模式白名单级证据）、`nonlocalPass`（非本地/非 redirect 显式放行）。`dump-maps`、`xdp status`、运行时快照全部透出。

### 5. NAT 程序架构重构（verifier 驱动）

dispatch→work→fwd 三段 tail-call：dispatcher 仅解析+暂存 `XDP_NAT_SCRATCH`，work 程序做重活（CT/FWD/SNAT），fwd 程序处理已有流转发。每个程序独立过 verifier，消除主程序 1M insn 状态爆炸与 R11 溢出栈传参。

## 验证证据

| 证据 | 结果 |
|---|---|
| verifier（kernel 7.0） | 11 个 XDP 程序全部加载成功；`llvm-objdump` 零 r11 引用 |
| T01 矩阵 | 28/28 通过；全矩阵 38 例 0 失败 |
| UDP DNAT+SNAT 双向 | `snatBound=1, udpFwdTx, snatReplyTx=1, tx`；后端见到 SNAT 源 `10.99.0.5:56027`，客户端收到回包 `R:SNAT-TEST` |
| TCP DNAT+SNAT 双向 | `tcpFwdTx=11, snatReplyTx=5`（完整握手+数据+关闭双向） |
| redirect:false | proxy bridge ready 下代理端口 UDP×3 → `redirect=0, pass`；同接口 `udpFwdTx` 照常（NAT 与 redirect 独立） |
| proxy readiness 生命周期 | `xskReadyQueues=1` 与 `proxyRedirectEnabled` 分离上报；bridge 未起时显式 PASS 而非黑盒丢包 |

## 已知限制（未降级，如实记录）

- T08（attach/reload/crash）partial：reload 保活已测，崩溃注入待 EN-29/30。
- T14（配置代次/LKG）pending：EN-25/26 前置。
- observe 模式 `aclWouldBlock` 的 e2e：ACL 为运行时动态注入（`state.blocked_ips`），eBPF 分支已实现并计数；动态注入的端到端用例随 EN-09 map 生命周期任务补。
- 同端口不同 VIP 串扰：eBPF 判定以 dst-IP flags 为单位，redirect:false VIP 不影响同端口其他 VIP——单元测试覆盖 `local_ip_flags` 合成；多 VIP e2e 待多地址拓扑。
- 测试期间发现环境陈旧状态（`veth-en03` 残留同子网接口劫持回程路由）已清理，非产品缺陷。

## 回归保护

- `runtime_mode` 单测：protectedServices 反序列化、localIps 校验、重复拒绝。
- `local_ip_flags` 位编码单测。
- 分类镜像 `classify_frame` 与 eBPF 同序同规则（EN-05）。
- T01 矩阵断言全部翻转为分类语义（malformed/unsupported/fragmented/control）。
