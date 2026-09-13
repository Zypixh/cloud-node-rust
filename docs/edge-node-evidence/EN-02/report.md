# EN-02 — 分层测试与证据工具

- **task_id**: EN-02
- **status**: VERIFIED（27 个 runnable case 在真实 XDP 上执行并断言通过；pending 行如实标记未覆盖，不算完成）
- **start_commit**: `63cc10c`（EN-01 后）
- **end_commit**: 见同 commit manifest/git log
- **patch_digest**: `scripts/edge/{pktgen.py,runner.py,matrix.json,README.md}`（新）；`src/xdp.rs`（dump-maps 增加 pinned `XDP_COUNTERS` 读取 + 显式 pin）
- **working_tree_dirty**: 提交前仅本任务文件

## 交付

| 交付物 | 位置 | 说明 |
|---|---|---|
| 可重放报文语料 | `scripts/edge/pktgen.py` | 27 个确定性 case：IPv4/6、VLAN/QinQ、IPv6 dest-opts/fragment 扩展头、first/non-first/atomic 分片、截断、坏校验和、ICMP/PTB、TCP 全异常 flag 组合、SYN/ACK/FIN/RST、UDP、QUIC Initial/短头。`--write-pcap` 落盘 pcap corpus；同一 case 名字节级确定 |
| 双端观察 | `pktgen.py count` + runner | AF_PACKET 在节点侧接口统计到达帧（proto/端口过滤），与 dataplane 计数器差值对照区分“送达 vs 丢弃” |
| 混合合法/异常流量 | `runner.py --count/--pps` + 语料 | 任意 case × count × pps；矩阵内 flood case 与合法 case 交错 |
| 统一 JSON 结果 | `runner.py --out` | `{ebpf_sha256, topology, tests[].cases[].{send, observed, counter_delta, assertions, ok}}` |
| 真实 eBPF 执行 | netns+veth+真 attach | 语料帧过真实加载的 XDP 程序，断言 pinned `XDP_COUNTERS` 差值——不是 Rust 镜像函数 |
| 失败退出码传播 | runner | 0=全过 / 1=断言失败 / 3=环境前置失败；case 级 RuntimeError 记入结果并计失败 |
| BPF 摘要+收发记录 | 结果 JSON | `ebpf_sha256`（实际加载文件）、`sent_packets`/`achieved_pps`、`observed` 帧数 |
| 双拓扑 | `--topology netns\|external` | netns 单机功能；external 只发包+读对端状态文件（独立发包机容量拓扑） |
| T01–T18 追踪 | `matrix.json` | 每条含 status/prerequisites/cases/pending_reason/owner |

## 顺带修复（本任务暴露的真实缺陷）

`xdp attach` 在 x86-build 上复现失败：`invalid value size 128, expected 56`。

- **根因 1（环境）**：本机 `data/cloud-node-xdp-ebpf.o` 是 6 月的陈旧预构建对象（未被 git 跟踪），rsync 覆盖 VM 上的新对象；embed 后 attach 按旧 ABI（XdpCounters=56B）建图，用户态读 128B 被拒。已用 build-node 重建 fresh 对象（sha256 `1adcae05…`）部署。**遗留**：`data/*.o` 作为无版本标识的本地 fallback 是已知风险——EN-29 产物身份任务需覆盖（已在报告 open_issues 记录）。
- **根因 2（真 bug）**：`XDP_COUNTERS` 为 `PinningType::None`，从不 pin → 其他进程无法跨进程读取 dataplane 计数，runner 的断言数据源不存在。已加 `map_pin_path("XDP_COUNTERS")`；detach 后保留 pin（最终计数可查），布局由 `drop_stale_pinned_maps` spec 表兜底（表中已有该条目）。
- dump-maps 新增 `"counters"` 字段：Linux 上从 pinned map 直读，读不到为 `null`（显式，不伪装 0）。

## 实测结果（x86-build，kernel 7.0，veth/netns，protect 模式）

`runner.py --only T01,T02,T03,T04,T06 --mode protect` → rc=0，27/27：

| 测试 | 覆盖 | 结果 |
|---|---|---|
| T01 | 17 case：全部报文类过真实 eBPF，断言 `packets`/`pass`/`drop` 差值 | 17/17 |
| T02 | SYN/ACK/RST/FIN 无流探针（当前契约=protect 下 PASS） | 4/4 |
| T03 | UDP、QUIC Initial、QUIC 短头 | 3/3 |
| T04 | syn_flood/udp_flood 2000 包 @5000pps，验证计数完整性（未配限流 → 全 PASS，如实记录当前 fail-open 空缺） | 2/2 |
| T06 | udp 500 包观测 xskDrops 可观测性 | 1/1 |

代表性数据：syn_flood sent=2000 achieved_pps=4992.8，counter delta packets=2001 pass=2001（含 1 个拓扑余量包）。

当前契约断言刻意保守（protect 模式无 ACL/限流时全 PASS）——EN-05..EN-09 收紧后翻转对应断言，矩阵不变。

## 验证命令

| 命令 | 退出码 |
|---|---|
| `python3 -m py_compile scripts/edge/*.py` | 0 |
| `cargo check --lib` | 0 |
| `runner.py --list` | 0（18 条全部列出，runnable/pending 标注正确） |
| `runner.py --only T01..T06 --mode protect`（x86-build） | 0 |
| `runner.py --only T01`（缺少 node bin 时） | 3（前置失败正确退出） |

## 未覆盖与原因

- T05/T07/T09–T15/T17/T18 为 pending：依赖 EN-09/13/14/16/18/20/23/24/25/29/31/33 的功能或容量环境；矩阵已登记计划入口与 owner，不标 runnable。
- external 拓扑路径已实现但未在真双机环境执行（单台 VM 无第二张网卡对）；netns 路径已实跑。
- 本任务不改生产数据面语义（除 dump-maps 只读字段 + COUNTERS pin）；断言按当前文档化契约编写，收紧行为属后续任务。
