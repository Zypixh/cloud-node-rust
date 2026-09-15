# Devin 下一轮：先修正 EN-14/15 正确性与验证，再推进性能

日期：2026-09-15。审阅基线：`e3fb282`，主要审阅 `a5bb2e1` 与 `e3fb282`。本文件既是静态审阅记录，也是可直接传给 Devin 的下一轮任务指令。

用户手动启动 Devin；Codex 不启动代理。本轮静态审阅没有编译、运行测试或访问 VPS。以下源码缺陷和测试缺口不等于已经完成运行时复现；修复者必须在隔离 VPS 上补反例和通过证据。

## 1. 本轮结论与范围

已有 verifier/veth 报告和 QUIC 库级握手测试有价值，但不足以确认 EN-13～16 全部完成。下一轮按 R0→R1→R2→R3→R4 顺序执行，不直接开始 EN-17 热路径优化或 EN-25～29 发布改造。不要重写架构，也不要重做无关历史工作。

继续遵守 `tasks/devin-vps-continuation.md`：Mac 只编辑/传输，所有编译、cargo check/test、eBPF 构建、脚本测试和压测仅在两台获授权 VPS 的隔离环境运行。本机 VM 同样禁止。两台各 2c2g，每台最多一个 Cargo 构建，复用远端缓存。凭据沿用私密文件，不写日志/仓库/命令行参数。

上一轮报告明确运行了本机 `cargo test --lib`，违反用户约束。静态盘点也发现本机 `target/` 已重新产生，约 5.6 GiB；Cargo registry cache/src 约 52/322 MiB。该占用是本次观察值，不是新增清理成果。由执行者确认无使用者后再次清理获授权可再生产物，更新清理证据；保留源码、工具链与其他任务。

## 2. R0：先让验证入口真实失败、真正隔离

### 已确认的问题

- `scripts/edge/vps_remote_build.sh:21,24`：`#!/bin/sh` + `set -eu` 下，`cargo ... | tail ...` 的退出状态来自 tail。构建失败且旧对象仍在，或测试失败时，脚本仍可能打印 done 并返回 0。不能据此认定既有测试都失败，但该脚本成功不是充分证据。
- `scripts/edge/vps_sync.sh:30,41`：清单生成/校验用 `|| true` 吞掉失败；远端只打印非 OK 行数，随后仍输出 SYNCED。损坏、漏传、缺失校验工具不能可靠阻止后续构建。
- 远端构建脚本没有显式授权主机/任务目录核验和构建互斥锁；设置 jobs=1 只限制单次 Cargo 内部并发，不能防止两个构建同时启动。
- 同步脚本对固定目录直接 `mkdir -p` 后 `rsync --delete`，没有任务所有权证明；源码清单与 rsync 过滤分开维护，存在漂移风险。
- `scripts/edge/en14_cookie_probe.py:55,375,442,625`：测试直接清理 `/sys/fs/bpf/cloud-node-xdp`。这是节点默认 pin 目录，netns 不自动隔离 bpffs。若同机有既有实例，该清理会移除其 pinned 对象/链接，可能影响业务，不能因测试网卡是 veth 就认为安全。

### 交付和验收

1. 让每个构建、测试、清单生成、摘要校验的失败都返回非零；保留完整日志，只截取显示内容，不丢真实退出码。可用 Bash pipefail 或显式捕获每步状态，不在成功路径兜底 `|| true`。
2. 本机入口只同步与 SSH；远端入口在任何工具链调用前核实 Linux、已登记主机身份、任务目录所有权，持有单主机构建锁并限制资源。
3. 同一份源码清单驱动传输与内容校验，包含必要 dirty/untracked 源码，排除凭据/产物。删除只作用于已核实的任务目录；用临时路径、trap 清理，避免公共 `/tmp/cn-files.txt` 冲突。
4. 测试使用独立 pin 空间；可采用私有 mount namespace/bpffs 或明确可配置的任务 pin 根。只清理本任务创建且持有所有权的对象；固定默认生产 pin 目录不允许递归删除。开始前验证隔离，结束后恢复/清理。
5. 仅在 VPS 验证负路径：故意令构建/测试命令失败、破坏一个同步文件、让两个构建争锁、放入其他实例的保护标记。必须分别非零退出/拒绝竞争，并保持非任务资源不变。保留真实成功基线和失败样例的命令、退出码与摘要。

## 3. R1：EN-14 两个优先修复的源码缺陷

### R1.1 [P1] 全零当前密钥仍参与 cookie 验证

位置：`crates/cloud-node-xdp-ebpf/src/main.rs:4695–4734`，`cookie_make_v4` 与 `cookie_check_v4`。

生成端在 `cur == [0;16]` 时拒绝发挑战；校验端却无条件使用 cur 做当前/上一时间槽的 hash，仅对 prev 做非零检查。因而“keyring 清空后 fail-closed”只覆盖 SYN，不覆盖 ACK：在全零 key 且时间槽匹配的条件下，用已知零 key 计算的证明可通过校验，并进入预算后的 pending/SNAT 创建。这里不声称普通非零 key 能被破解；问题是明确的无密钥失败状态没有关闭校验。

修复：定义 keyring 的有效状态与生命周期；无效 key 不得参与验证，无有效 key 时新证明必须拒绝。清空、初始化失败、轮换过渡、旧 key 宽限的行为要一致，存量 CT 不受新挑战禁用影响。

VPS 反例：全零 key 下新 SYN、新 tuple 的有效形状 ACK，以及用该已知无效 key 构造的 ACK 都应被拒，pending/CT/SNAT 不增长；另测有效 cur、有效 prev、过期槽、轮换及存量数据。不能只用随机坏 ACK 替代这个反例。

### R1.2 [P1] 跨包复用的 TCP 造包缓冲保留旧 checksum

位置：同文件 `forge_challenge_synack_v4:4964–4983`、`forge_to_backend_v4:5044–5058`；共享 `XDP_NAT_SCRATCH.forge_tb` 是 per-CPU map 内容。

两处填写头字段后调用 `tcp_pseudo_csum`，再将结果写入 `tb[16..18]`。下一次复用同 CPU 缓冲时，没有在计算前清零这两个字节。`tcp_pseudo_csum` 的前提恰是 checksum 字段已清零。旧 checksum 会被计入新计算，除偶然特殊值外，后续造包的 TCP checksum 将不正确。

当前探针 `decode_tcp:281` 把 checksum 解出后丢弃；发送器使用 raw AF_PACKET 构造客户端和后端帧，不需要真实 TCP 栈接受这些回复。因此字段与 map 断言通过不能排除此问题。

修复：每次造包完整初始化所有参与 checksum 的字段，明确 reserved/urgent/options 的值；不依赖 per-CPU map 初始为零。复核字节序、奇偶长度、重用和错误路径。

VPS 验收：同一 CPU 连续生成多次 SYN-ACK、SYN replay、最终 ACK，独立重算 IP/TCP checksum；同/异 tuple 和不同头长都覆盖。再用真实内核 TCP 客户端与后端完成多连接、双向应用字节校验。记录抓包位置与 offload 状态，避免把抓包 offload 表象误判为 checksum 错误。

## 4. R2：修复测试盲区，并闭合 TCP 协议与失败路径

### R2.1 [P1] H 阶段未独立验证挑战预算

位置：`scripts/edge/en14_cookie_probe.py:568–603`。

G 清空 keyring；H 紧接着发 300 SYN，没有恢复有效 key，也没有设置/断言明确的 token rate、burst 与 refill。两阶段都使用合并的 challengeRejected 计数。故当前结果只能证明该无密钥场景下无新状态，不能证明 300 次拒绝全部来自挑战限额，更不能证明有效 key 下的可用性。

修复：各阶段隔离初始状态。H 使用有效 key、显式小额度和可控时间窗，分别断言预算内有挑战、超额受限、补充额度后恢复、状态仍有界；区分拒绝原因。G 在 key 缺失期间实际传输已有连接数据，不能只检查 CT 条目存在。

### R2.2 [P1] 挑战 worker 的内部错误返回 PASS

位置：`crates/cloud-node-xdp-ebpf/src/main.rs:593–602`。

`xdp_tcp4_challenge` 已是被选定的 challenge/splice 路径，但 `Err` 分支直接 XDP_PASS。造包函数先改写 L2/L3/TCP，再调用可能失败的 load/store/adjust_tail；失败时可能把原包或部分改写包交给内核。该错误处理不满足受保护服务的明确失败策略，不能照搬未知协议的解析回退。

修复：确定受保护路径出错时的 verdict、原因计数、状态回滚与回收；失败不得任意 PASS，也不能把已改写包送到错误承载。检查 worker `None`、SNAT 分配失败、pending/CT 插入失败、forge 失败的完整调用链，而不是只改一个返回值。

验收：隔离故障注入覆盖每个失败点；确认无错误承载投递、无泄漏、无错误 VERIFIED 晋级。特别核对“CT 已晋级但后端 ACK 锻造/发送失败”的恢复。

### R2.3 [P1] MSS 解析回退可能扩大客户端通告值

位置：同文件 `tcp_syn_mss_idx:4813–4858` 与 `mss_to_idx:4871–4881`。

只识别最前面的 MSS 或最多两个前导 NOP；更靠后的合法 MSS 被当成缺失并默认 1460。无 MSS 的 IPv4 SYN 也返回 1460；小于表内最小值 536 的通告被映射为 536。这些值未必小于等于客户端接收上限。verifier 通过不能替代协议正确性。

修复：采用 verifier 可接受的有界选项处理和协议正确的缺省/量化；不把未知/未支持选项当成允许扩大 MSS。明确节点、客户端、后端和 MTU 的各自限制，必要时保守拒绝不支持 profile。

验收：缺 MSS、MSS 后置、多个前导选项、小 MSS、畸形选项、PMTU/重传；验证后端实际分段与客户端可接收，不只对比某个索引。

### R2.4 端到端补证与设计约束

现有 8 阶段是 raw 帧/状态探针，尚不能代替 ADR 承诺的真实内核 TCP 应用传输。增加双端真实 TCP 验证，并按任务卡覆盖：第三 ACK 带数据、重放 SYN 丢失、后端 SYN-ACK/最终 ACK 丢失、重复/乱序、FIN/RST/半关闭、窗口更新、密钥轮换、存量流与新流并存。

重点待复现：SYN replay 发出后，`PENDING_SPLICING` 命中会丢弃后续客户端包；当前相关代码没有独立 replay 重传机制。必须证明首个后端 SYN 丢失时存在有界恢复路径。不能只声称“TCP 自己会重传”——节点承担的握手消息也需要所有者负责。

检查 tail-call 前后并发：worker 重查后应重新验证期限、incarnation、当前状态及后端 ACK 锚点；用明确竞态反例决定修复，不把注释中的“重新查表”当成完整一致性证明。

ADR-001 主动剥离 window scaling/SACK/TS/ECN，是能力和性能取舍，不是透明无损优化。未协商 window scaling 时，单连接单方向受约 65535 字节通告窗口限制；50ms RTT 下仅窗口约束对应约 10.5 Mbit/s 的理想量级，这不是实测吞吐。高性能目标必须单独比较该 profile 的 RTT/丢包/多连接表现，决定补齐选项还是明确限制用途，不能把整个服务默认降为该 profile 后宣称达标。

## 5. R3：EN-15 补聚合响应预算与真实应用路径验证

### [P1] Retry 分支缺明确的聚合响应预算

位置：`src/http3_proxy_manager.rs:238–267`。

策略满足时直接 `connecting.retry()`，早于连接/listener permit。这里没有新的 node/listener Retry PPS、字节或工作量额度扣除。Quinn 防放大约束和“每 Initial 至多一个回复”不等于整机/监听器的聚合成本上限；未认证新 Initial 的总数仍由来流驱动。已有 XDP dim3 不能自动限制用户态生成的这些 Retry，尤其不能假设所有内核接入都经过相同 XDP 策略。

实现共享响应预算和合理 reserve；多 listener/worker 总额度不能倍增。超限行为必须明确，避免转为另一种无预算回复。记录 attempted/issued/limited/failed 等准确指标，日志采样有界。验证上游 Incoming 缓冲/解析已有开销及其上限，文档改为“在应用 accept/连接 permit/task 分配之前”，不要声称收到 Initial 完全不占任何状态。

### [P2] continue 不是 Quinn 的静默忽略

位置：`src/http3_proxy_manager.rs:214–221,271–284` 等 Incoming 提前退出分支。

锁定的 Quinn 0.11.11 `Incoming::Drop` 会调用 `endpoint.refuse`；`ignore()` 才是不发回复的 API。报告声称被封禁源静默丢弃，但代码仅 continue，会走隐式拒绝。应明确封禁/响应超额场景的实际 wire 行为；需要静默时显式 ignore，而不是依赖 Drop。以隔离抓包验证，无需根据 API 名称猜测。

### 集成与迁移验收

`h3_retry_roundtrip_validates_without_loop:710` 创建独立 Quinn endpoint/accept 循环，没有调用生产 `run_endpoint`，没有验证真实 H3 请求、adaptive 压力接线、共享端口分流、准入耗尽或生产指标。保留这个库 API 回归，同时补生产 manager 的端到端测试。

核对锁定 API 的结果：未 validated ⇒ may_retry 为真，原注释这一点成立，不要为形式上缺一次 may_retry 调用制造缺陷。

Retry 判定放在当前应用层 SNI 分派之前，使用 listener/全局策略是合理方案；不要把它扩大为“任何 QUIC 实现都无法在 Initial 中解析 ClientHello”。本轮可保留现有粒度，用 ADR 明确。

PATH_CHALLENGE 证明新地址可达，不等于执行 L4 黑名单/权限撤销。报告中的“等价验证”需更正；当前 QUIC 未接入统一连接注册表的生命周期/封禁缺口，要明确实现方案与验收归属。迁移测试覆盖合法 NAT rebinding、非法路径、封禁目标地址、连接/许可清理和透传不注入 Retry。

## 6. R4：统一证据和状态，随后继续原计划

- EN-12：把非标准 DONE 改为 IMPLEMENTED，保留已验证 veth/copy 切片；真实 NIC zero-copy 继续列外部条件。
- EN-13：ADR 与实验已有实现，但真实 TCP 端到端/各承载合同的必要证据未闭合，保持 IN_PROGRESS。
- EN-14：标 IMPLEMENTED，并列本轮发现；verifier 和已有探针成功作为子证据保留。修复和相关必要验收结束前不得整体 VERIFIED。
- EN-15：标 IMPLEMENTED；已有 Quinn API 回归通过不等于生产 Retry/迁移/预算全部验收。
- EN-16：保持 IN_PROGRESS；报告还留有“无迟滞”等旧说明，与新代码不一致。更新当前事实、补 listener 洪泛隔离/恢复证据，明确 ADR-002 只承认 listener/class 粒度，不宣称多租户完成。动态池公平性须测“一个 listener 已占满，再出现其他 listener”的反例。
- 修正文档中的 cookie 时间窗旧值、ABI/结构大小旧值、缺失的 key rotation 交付、历史未提交字样；以当前实际代码为准。
- `.110 685 pass` 目前来自执行者反馈；仓库 EN-15 报告仍只指向“见执行状态”，未附对应完整命令/退出码/原始日志。本轮归档实际日志和被测源码摘要，不否认已报告结果，也不把摘要当作独立复测。
- 使用统一 task status、profile 子验收、prerequisites、源码/对象/节点二进制 SHA、配置、工具链、host、命令与退出码。历史报告保留，纠正不被断言支持的结论。

交付本轮 `docs/edge-node-evidence/REVIEW-2026-09-15/`，每个 R 项列修复提交/源码摘要、反例、实际 VPS 结果与未完成条件；更新各 EN 报告、manifest 和 `tasks/edge-node-execution-status.md` 的当前摘要。不要在修复前预写通过。

完成 R0～R4 后，继续 EN-17，再按原依赖推进 EN-18～24、EN-25～29 和集成门槛。硬件缺失不阻断独立代码工作，但不得把 2c2g VPS 结果换算成生产 NIC 线速或 Cloudflare 级容量。

现在从 R0 开始，自主完成可执行修复与远端验收。已有授权的常规开发、隔离构建测试与缓存清理不反复确认；禁止部署生产接口。结束时只汇报关键修复、远端结果、尚存阻塞和下一步。
