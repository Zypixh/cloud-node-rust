# EN-00 — 基线盘点与支持矩阵

- task_id: EN-00
- status: VERIFIED（自查；待独立审阅复核）
- start_commit: 0ca5cbd02b11f644943b25c05cdae55bd338b69b
- end_commit: 0ca5cbd02b11f644943b25c05cdae55bd338b69b（盘点期间无代码变更）
- working_tree_dirty: 仅新增证据目录与既有未跟踪文档（docs/README.md 修改、两份 tasks/docs 计划文件）；无运行代码变更
- 日期: 2026-09-13

## 1. 仓库基线

- 分支 `devin/1789195453-ci-and-conn-close`，HEAD 与文档基线一致（`git rev-parse HEAD` = `0ca5cbd…`）。
- 规模锚点：`src/xdp.rs` = 10,901 行；`crates/cloud-node-xdp-ebpf/src/main.rs` = 2,491 行；`src/memory_governor.rs` = 3,819 行。`src/xdp.rs` 的单文件体量确认 EN-04 拆分必要性。
- 工作树根 Cargo.toml 非 workspace；`crates/cloud-node-xdp-ebpf` 独立 crate（自身 lock/target），`cargo xtask build-ebpf` 存在于 `xtask/src/main.rs:42`。

## 2. 构建工具链（实测）

| 项 | 版本 | 证据 |
|---|---|---|
| rustc/cargo | 1.98.1 stable（2026-09-01）；nightly-aarch64 + nightly-x86_64 已装 | `rustc --version`、`rustup toolchain list` |
| eBPF 构建 | `build.rs` Linux target 自动 `cargo +nightly build --target bpfel-unknown-none -Z build-std=core`；产物经 `aya::include_bytes_aligned!` 内嵌 | build.rs:87-152 |
| bpf-linker | 0.11.1（build-node arm64 有；x86-build 缺失 → 主构建回落内嵌预编译 `data/cloud-node-xdp-ebpf.o` 并打 cargo:warning） | `bpf-linker --version`、x86-build 构建日志 |
| aya / aya-ebpf | aya 0.14.0 / aya-ebpf 0.2.1 | Cargo.toml / ebpf Cargo.toml |
| Quinn | **0.11.11**（lockfile 锁定） | Cargo.lock `quinn` entry |
| smoltcp | 0.14.0（no default features；std+async+ipv4/ipv6+tcp/udp） | Cargo.toml |
| tokio | 1.53.1 | Cargo.toml |
| Pingora | vendored `pingora-main/*`（rustls features） | Cargo.toml path deps |

**已知构建风险（记录非断言）**：eBPF 工具链缺失时 build.rs 回落到 `data/cloud-node-xdp-ebpf.o` 预编译对象——有 warning 但无对象身份/ABI 校验，与架构 §11"正式构建不隐式嵌入不明版本旧对象"存在差距（归 EN-29）。

## 3. 八类风险逐项复核（对照源码）

| # | 架构 §1.2 风险 | 复核结论 | 证据 |
|---|---|---|---|
| 1 | 源地址限流默认未配置；map 满放行；无回收 | **属实**。`rate_limit: Option<XdpRateLimitSettings>` 默认 None；`XDP_RATE_V4/V6` 为普通 `HashMap`（262,144 上限），insert 失败 → `counter_ratelimit_map_full()` + `return false`（放行）；全仓未见对 RATE map 的 GC/sweeper | runtime_mode.rs:268；ebpf main.rs:96-101, 1155-1162, 772；xdp.rs 无 rate sweeper |
| 2 | TCP NAT SYN 直接 OPEN；非关闭态 2h 空闲；无半开生命周期 | **属实**。SYN 建立 CT 时 `v.state = XDP_CT_STATE_OPEN`；userspace sweeper 参数：udp_idle=180s、tcp_idle=7200s、closing_grace=120s；状态机仅 OPEN/CLOSING 两态 | ebpf main.rs:1365, 1624, 1946, 2232；common lib.rs:349-352；xdp.rs:1513-1519 |
| 3 | 非法解析统一 PASS；无分类 | **属实**。`parse_frame` 的 Err → `counter_parse_error()` + `XDP_PASS`；IPv4 分片（frag_offset≠0 或 MF）同走 Err→PASS；无 MALFORMED/UNSUPPORTED/FRAGMENTED/CONTROL 区分 | ebpf main.rs:199-203, 249-251 |
| 4 | 共享 Array 计数器读改写竞争；RATE 跨 CPU 竞争；TCP/UDP 共桶 | **属实**。`XDP_COUNTERS` 为**普通 `Array<XdpCounters>`（非 per-CPU）**，多 CPU `saturating_add` 共享同一 value → 丢计数；rate bucket 注释自承认 race（"tolerates drift"）；TCP SYN 与 UDP 共用同一 `XDP_RATE_V4/V6` 桶 | ebpf main.rs:82-83, 1138-1142 |
| 5 | XSK 故障可能关 redirect 回退 PASS；受保护服务与 XSK readiness 共开关 | **属实**。`disable_proxy_redirect_for_fallback` → `proxy_redirect_enabled=false` + `disable_proxy_redirect`（清 proxy port map）；`maybe_redirect` 中无 XSK → `fallback_pass ? PASS : DROP` | xdp.rs:692-724, 805-821；ebpf main.rs:709-727 |
| 6 | QUIC DCID 跨队列选 XSK 违反 XSKMAP 约束 | **属实**。`maybe_redirect` 用 `quic_dcid_xsk_index` 返回的 XSK index 直接 `XDP_XSKS.redirect(xsk_index)`；该 index 可指向非本 RX 队列绑定的 socket——普通 XSKMAP 不满足跨队列语义 | ebpf main.rs:697, 707, 718 |
| 7 | AF_XDP 帧拷贝 + 全会话扫描；FLOW_ACCT 高基数 per-CPU；GC 全表+线性成员判断 | **属实**。`frame.to_vec()`（xdp.rs:3604）、`Bytes::copy_from_slice` payload（7968, 8371, 8387）；`sessions.values_mut()` 每轮扫描（6548）；`XDP_FLOW_ACCT` = `PerCpuHashMap<4-tuple>`；`sweep_nat_maps` 对 UDP_CT/TCP_CT/SNAT_REV/FLOW_ACCT 全表迭代，`stale.contains()` 线性成员判断 | 见各行号 |
| 8 | 文档历史差异（Quinn Retry、XDP 默认值、存储引擎、内核版本） | **属实（部分）**。Quinn 0.11.11 源码确认 `Incoming::retry()/may_retry()/remote_address_validated()/refuse()/ignore()` 全部存在——旧"Quinn 0.11 没 Retry"结论作废；当前 `http3_proxy_manager.rs:257` 直接 `connecting.await`，**未使用任何 Retry/地址验证**。XDP 现状默认值见 §5。存储/内核版本差异需随 EN 任务逐项核 | quinn-0.11.11/src/incoming.rs:44-93；http3_proxy_manager.rs:257-262 |

## 4. 部署边界确认

| 路径 | 状态 | 证据 |
|---|---|---|
| 内核 socket | 完整生产路径：Pingora 监听 + kernel_syn_defense（nftables `cloud_node_synproxy` SYNPROXY reconciler）——**仅保护内核路径流量，不覆盖 AF_XDP** | kernel_syn_defense.rs:26-94；main.rs:3343 |
| XDP/AF_XDP | `xdp.enabled` 默认启用，优先级 默认→env→文件；attachMode auto/drv/skb；eBPF 内嵌 binary；RKE2 强制关闭 | runtime_mode.rs 测试 `xdp_enabled_precedence_default_env_file`、`xdp_enabled_forced_off_in_rke2_mode`；build.rs:62 |
| RKE2 | `runtime.mode=rke2` 要求 cluster.enabled/type/name/namespace/serviceName/localMetaDir 齐备（显式校验，非静默） | runtime_mode.rs:505-530 |
| 已验证能力 | skb/generic 模式：attach、dispatch pin 存活、AF_XDP HTTP/HTTPS/TCP/UDP 端到端、UDP+TCP SNAT forward 双向改写（veth+netns，kernel 7.0.14，2026-09-13 实测） | 本任务命令记录 §8 |
| 未验证能力 | native/drv attach、AF_XDP zero-copy、multi-buffer/jumbo、内核 6.1 上的最新对象（环境无原生驱动网卡；标为外部验收输入） | 环境限制见 §7 |

## 5. Quinn 锁定 API 核对

`quinn-0.11.11/src/incoming.rs`（本地 registry 源码实读）：

```
44:  pub fn refuse(mut self)
52:  pub fn retry(mut self) -> Result<(), RetryError>
63:  pub fn ignore(mut self)
85:  pub fn remote_address_validated(&self) -> bool
93:  pub fn may_retry(&self) -> bool
```

→ EN-15 的 Retry 可行性前提成立；当前实现 `connecting.await`（无验证）。纠正旧文档结论。

## 6. 现有测试与验证入口

| 入口 | 状态 | 本轮实测 |
|---|---|---|
| `cargo test --lib` | 644 tests：**642 pass / 0 fail / 2 ignored**（macOS aarch64） | ✅ 已运行，exit 0 |
| `cargo test --lib xdp` | 93 xdp 相关测试全过 | ✅ 已运行（前序会话） |
| `cargo +nightly build -p cloud-node-xdp-ebpf --target bpfel-unknown-none` | eBPF 对象编译通过（build-node, bpf-linker 0.11.1）；产物 7 个 XDP 程序、18 个 map | ✅ 已运行 |
| `scripts/xdp-netns-smoke.sh` | 存在，有 cleanup/netns 隔离；本轮未跑（EN-02 范围） | 未运行：属 EN-02 工具化验收 |
| `xdp proxy-smoke` | veth+netns 实测通过（HTTP/HTTPS/TCP/UDP + UDP/TCP SNAT forward） | ✅ 已运行 |
| `scripts/perf/run_perf_matrix.sh`、`run_defense_matrix.sh`、`bench-*` | 存在；参数/拓扑未本轮验证 | 未运行：EN-02/EN-31 |
| vendored Pingora crate 测试 | 未运行 | 未运行：本轮未触碰 |

## 7. 测试环境 profile（实际可用机器）

| 机器 | 架构 | 内核 | CPU/内存 | 网卡 | cgroup | 能力边界 |
|---|---|---|---|---|---|---|
| x86-build（OrbStack VM） | x86_64 | 7.0.14-orbstack | 7 vCPU VirtualApple / 6GB | eth0=veth（virtio 语义，部分校验和卸载） | v2 | generic/SKB only；无 native/zero-copy |
| build-node（OrbStack VM） | aarch64 | 7.0.14-orbstack | 7 vCPU | eth0=veth | v2 | eBPF 构建机（bpf-linker 已装） |
| macOS 本机 | aarch64 | Darwin 27 | — | — | — | 仅编译/单测；不能证明 verifier/网卡行为 |

**缺失输入（保留为外部验收条件）**：native-capable 物理 NIC（mlx5/i40e/ice/ixgbe/bnxt）、内核 6.1 Debian 实机、多队列 RSS 硬件、独立发包机。生产目标 NIC/MTU/NUMA/连接规模待定（EN-31 输入）。

## 8. T18 支持矩阵（证据等级：E=实测 / C=代码证据 / P=路径存在未验 / N=缺失）

| 能力 | 等级 | 说明 |
|---|---|---|
| XDP generic/SKB attach + ACL + tail-call NAT | E | veth/eth0 实测（2026-09-13） |
| XDP native/drv | P | `XdpMode::Driver` 代码路径在；无硬件验证 |
| XDP offload | N | aya 支持但 enum 未暴露 |
| AF_XDP copy 模式代理（TCP/UDP/HTTP/HTTPS） | E | veth+netns 全链路实测 |
| AF_XDP zero-copy | P | 需 native 驱动；未验 |
| QUIC/H3 终结（AF_XDP） | E | proxy-smoke H3 端口注册实测；迁移/Retry 未实现（C） |
| QUIC DCID 跨队列 steering | C（有缺陷） | 代码存在但违反 XSKMAP 队列约束（风险 6） |
| SNAT forward（UDP/TCP, v4） | E | AF_PACKET 抓包确认双向改写 |
| IPv6 forward | C | 代码路径在（slot 3-6）；本轮未实发 v6 流量 |
| 源地址限流 | C（有缺陷） | 固定窗口、fail-open 满表、无 GC（风险 1/4） |
| 分片/畸形分类处理 | N | 统一 Err→PASS（风险 3） |
| ACK/RST/FIN 无流拦截 | N | 非 SYN 直达 userspace reactor（本轮已确认） |
| 内核 SYNPROXY（内核路径） | C | nftables reconciler 存在；不覆盖 AF_XDP |
| RKE2 模式 | E | 强制 XDP off + 配置校验（单测） |
| 缓存 purge barrier / process lock | C | `cache/purge_barrier.rs`、`cache/process_lock.rs` 存在；一致性验证属 EN-23/24 |
| MemoryGovernor 统一账本 | C | AdmissionClass/Permit 体系存在；BPF/UMEM 未入账（EN-16） |
| eBPF 对象内嵌 | E | build.rs 嵌入 + status 显示来源；删 .o 后 attach 实测通过 |
| dispatch pin 存活 | E | 进程退出后 7→6 槽存活（SNI 移除后）、转发仍工作（实测） |

## 9. 命令与退出码（本轮实际执行）

```text
git rev-parse HEAD                                    → 0ca5cbd…（=文档基线）exit 0
rustc --version / rustup toolchain list               → 1.98.1 + nightly       exit 0
cargo test --lib                                      → 642 pass / 2 ignored   exit 0
ssh x86-build@orb cargo +nightly build --release      → eBPF 编译成功          exit 0
  --target bpfel-unknown-none -Z build-std=core        （crate 目录内）
llvm-nm/readelf on built object                       → 7 programs, 18 maps,   exit 0
                                                       0 SNI symbols
xdp proxy-smoke（veth vxdp0 ↔ peer netns vxdp1）      → HTTP/HTTPS/TCP/UDP 全通 exit 0
AF_PACKET sniffer forward 验证                        → UDP/TCP SNAT 双向改写   exit 0
```

## 10. 开放问题与后续

- 原生驱动 NIC 缺失 → native/zero-copy/kernel-6.1 验证为外部验收输入（EN-31）。
- `x86-build` 缺 bpf-linker → 预编译 .o 回落路径已工作但无身份校验（EN-29）。
- A 节点（10.0.160.13，前期真机验证机）当前网络不可达；本轮 veth/netns 证据等级低于物理网卡，矩阵已标注。
- 风险 1/2/3/4/5/6/7 均复核属实 → 对应 EN-05/06/07/08/09/12 任务。
- 我此前提议的"XDP_PROXY_CT 无流即丢"方案与本计划 §9 警告冲突（禁止首轮裸 CT），已废弃，防御严格化归入 EN-05→09 序列。

## 11. 回退

本任务仅新增 `docs/edge-node-evidence/` 证据文件，无代码/配置变更；回退 = 删除该目录。

## 12. 下一项满足依赖的任务

EN-00 完成 → EN-01（共享合同）与 EN-02（测试工具）可并行启动（不重叠文件集）。
