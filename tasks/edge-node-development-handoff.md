# 交给其他模型的开发说明

日期：2026-09-13。目标：将现有 CloudNode Rust 边缘节点做到生产级。首期覆盖 XDP、防护、代理、缓存、可观测和可靠性；不扩展到全球控制面、BGP、权威 DNS 或产品平台。

先读 [目标架构](../docs/edge-node-production-architecture.md)，再读 [34 项开发计划](edge-node-production-plan.md)。这两份文档是目标设计和待执行计划，不是已实现能力说明。现状基线为 0ca5cbd02b11f644943b25c05cdae55bd338b69b，开发前必须核对最新工作树。

## 1. 可以直接复制的总指令

```text
请在本仓库实施生产级边缘节点计划，本轮只执行指定任务 ID。

必读：
1. docs/edge-node-production-architecture.md
2. tasks/edge-node-production-plan.md
3. tasks/edge-node-development-handoff.md
4. 当前适用的 AGENTS.md；如存在，读取 .agents/skills/rust-1.0.1/SKILL.md 及所需引用。

本轮任务：EN-00（首次执行的默认任务；之后由任务负责人替换为已满足依赖的 ID）。

工作方式：
- 先检查 git status、当前 commit、已完成依赖和相关代码，保留其他人的改动。
- 区分已有实现、静态推断、已测结果和目标设计，不照抄历史计划中的过期判断。
- 按指定任务完成必要实现、兼容适配、测试、证据和运行文档；不只交计划或空接口。
- EN-00 是基线盘点任务，应交付盘点与实际验证，不顺手完成其他任务的行为变更。
- 遵守架构 I01～I15。不能通过 fail-open、关闭防护、删除协议、跳过计费或清空状态达标。
- 每个高基数结构和流量驱动任务都说明容量、时间/字节预算、满额行为、所有者与回收。
- 共享 ABI、配置 schema、路径选择和故障语义变更必须说明所有消费者如何兼容。
- 状态、解析、缓存一致性和失败路径必须有能发现真实错误的测试，不只测试当前实现写法。
- 真正的 XDP/AF_XDP 验证在 Linux 和隔离环境执行；macOS 编译不能证明 verifier/网卡行为。
- 只在明确的测试网卡、namespace、目录和配置上压测，不根据旧文档里的地址操作外部机器。
- 一个大型任务拆成小的可审阅变更，当前轮不擅自扩大为整个阶段。
- 不自动部署、不修改真实生产网卡、不创建新的全球控制面；本轮授权的是指定开发任务。
- 若发现架构前提与源码或规范冲突，提交最小 ADR 修正与证据，继续不依赖该决策的工作。
- 缺少硬件时完成独立工作，明确留下外部验收，不声称测试通过。

交付：
1. 本轮任务 ID、问题、最终行为和涉及文件。
2. 状态/配置/ABI/预算/故障行为的改变及兼容方式。
3. 实际运行的命令、退出码、测试结果与未运行项原因。
4. docs/edge-node-evidence/EN-xx/ 中的证据 manifest 和报告。
5. 回退方法、剩余条件和下一项满足依赖的任务。
6. 更新 tasks/edge-node-production-plan.md 中本任务状态。

只有全部验收完成才能标 VERIFIED；仅写完代码标 IMPLEMENTED。
首次任务 EN-00 结束后不要把整个架构或计划标成已完成。
```

## 2. 开发任务选择规则

首次给开发模型 EN-00。后续每轮明确一个 ID，附上依赖的 VERIFIED 证据；对必须共同开发的接口，可先交契约子 PR，但不能绕过最终集成验收。

示例：EN-07 依赖 EN-03 与 EN-06；任务是建表前聚合预算与每路径容量保护，不是同时实现 TCP cookie、全球黑名单和缓存重构。

L 任务允许拆成 EN-xx/01、EN-xx/02 等子交付编号；父任务验收不因子 PR 合并自动通过。保持一个集成者维护共享 contract、ABI 和运行配置。不要让多个模型同时直接编辑未拆分的 src/xdp.rs。

## 3. 可以直接复制的独立审阅指令

```text
请审阅生产级边缘节点任务 EN-xx 的当前实现和证据，先检查实际 diff，
再对照 docs/edge-node-production-architecture.md 与对应任务卡。

重点寻找能复现的反例：
- 临时流/无效包是否被升级为可信；期限是否被任意流量延长。
- 源地址轮换、map 满和队列满是否能绕过聚合保护。
- CPU/队列/worker 增加是否重复发放整机预算。
- reload、worker 崩溃、旧事件或 tuple 重用是否切错连接所有者。
- 配置是否跨代读取；tail-call 是否使用本包同代策略。
- 取消、超时、失败和半关闭是否泄漏 task、FD、permit、UMEM 或 SNAT。
- 缓存 key、purge、并发 fill 和崩溃恢复是否有跨租户/旧内容复活。
- 观测和计费是否把尝试当交付，或隐藏丢失与重复。
- 性能是否在保留相同协议和防护语义时测量，生成器是否成为瓶颈。

报告只列有代码依据的可操作发现，注明文件/符号、触发条件、影响和修复建议。
未发现问题也要列实际检查范围与缺少的测试证据；不把代码审阅等同于实机认证。
不要因为旧计划声称“已确认”就跳过对当前 API、内核约束和实际代码的核对。
```

## 4. 证据报告模板

每个任务创建 report.md，至少包含以下内容；manifest.json 使用相同语义的机器可读字段。

```text
task_id:
status: TODO | IN_PROGRESS | IMPLEMENTED | VERIFIED
start_commit:
end_commit:
working_tree_dirty:
patch_digest:
contract_versions:
changed_paths:
implemented_behavior:
compatibility_and_migrations:
resource_bounds_and_full_behavior:
failure_and_rollback_behavior:
invariants_covered: [Ixx]
tests_covered: [Txx]
commands_and_exit_codes:
environment_and_path_profile:
workload_and_generator_limits:
results_and_raw_artifact_paths:
unrun_checks_and_reasons:
open_issues:
review_evidence:
next_eligible_tasks:
```

结果不允许只写 pass。性能测试填数值、单位、重复次数和波动；协议测试填具体语料与断言；故障测试填注入点、观测结果、恢复时间与残留资源。

## 5. 验证命令与边界

以下是仓库已有验证入口，按实际修改选择；不是要求每个小改动反复执行全部测试。

```bash
cargo check --all-targets
cargo test --lib af_xdp
cargo xtask build-ebpf
bash scripts/xdp-netns-smoke.sh
```

Linux netns 脚本需要对应权限和隔离环境。构建工具链、eBPF 对象来源和 verifier 结果必须记录。涉及 vendored Pingora 的修改额外运行相应 crate 的检查与测试。压测脚本的参数以当前代码和 --help 为准，不复制历史报告的真实节点地址。

既有 scripts/perf/run_perf_matrix.sh、run_defense_matrix.sh 和 src/bin/bench-* 是扩展入口。EN-02 需要补足真实 eBPF verdict、队列故障和混合业务测试；当前这些命令不意味着已经覆盖架构 T01～T18。

## 6. 容易导致错误实现的捷径

- “命中 CT 直接放行”：缺少验证、期限、所有者与最终资源预算。
- “每 CPU 都设整机上限”：总额度会倍增；per-CPU 是存储方式，不是全局性证明。
- “换 LRU 就能防 map 满”：可能让攻击驱逐正常连接；先明确表是否允许丢失。
- “失败后 PASS 保证可用”：无法把已有 smoltcp/NAT 传输状态自动交给内核。
- “只允许首片”：后续分片已丢弃，首片却还在消耗状态/重组资源。
- “Quinn 0.11 没 Retry”：当前锁定版本需重新查证 API；终止和透传不是同一接入方式。
- “XSKMAP 按 CID 直接选别的 RX 队列”：违反普通 AF_XDP 网卡/队列匹配约束。
- “一个 ArcSwap 保证全系统事务”：无法自动覆盖 BPF map、listener、XSK 与在途连接。
- “rename 完成就是断电持久”：还需定义同步和恢复顺序。
- “purge 删除文件就成功”：还需挡住内存 HIT、旧 fill、重启和其他进程。
- “队列有条数限制就不会 OOM”：还要约束消息字节、单连接和整机总额。
- “峰值 PPS 等于生产性能”：还需要合法成功率、P99、资源、故障和长期运行证据。

## 7. 最终交付的判断

一个任务完成不等于一个阶段完成，一个阶段完成不等于所有运行模式可上线。最终通过 EN-33 给出明确的获证 PathProfile、容量、协议边界、操作手册和已知限制。

本轮文档制定没有修改运行代码、没有启动其他模型开发、没有运行真实网卡压测，也没有对已有节点做配置或部署操作。
