# EN-24: T4-8 — AF_XDP 出向链路端到端真实流量验证 + T3-10 债务清理

Base: `9f168f0`（`xdp dial-smoke` + PTB/out-CT 在线验证，EN-23）+
`8c6aeb5`（dial-smoke `--reload-at-ms` + Cubic 对照测试）
规范: `tasks/xdp-transport-next-steps-2026-09-15.md` §8 T4-8（EN-20/21/22 只覆盖编译+单元/集成测试，本报告补齐真实流量）
环境: `devin-build-90`（103.79.184.90），kernel `6.1.0-41-amd64`，bpftool `v7.1.0`，
bpf-linker `0.11.1`（LLVM 21），`cloud-node-rust 1.2.7` release 构建
（仓库 `[profile.release]` lto=fat / codegen-units=1 / panic=abort，未改动）。
eBPF 对象 `data/cloud-node-xdp-ebpf.o`，`xdp-verify` 在本机 **17/17 prog 通过
kernel 6.1 verifier**（`/tmp/t48-evidence/xdp-verify.txt`）。

## 拓扑（隔离环境，未触碰生产 bpffs）

```
host netns                     peer netns "cn-peer"
cndial0 (veth) <-------------> cndial1
10.210.0.1  fd00:210::1        10.210.0.2  fd00:210::2
XDP drv/proxy, AF_XDP q0       TCP/UDP echo :18080/:18081 + HTTP
```

- pin dir 隔离：`CLOUD_NODE_XDP_PIN_DIR=/sys/fs/bpf/cn-t48`；
  `CLOUD_NODE_HOME=/tmp/t48-home`；对象路径经
  `CLOUD_NODE_XDP_EBPF_OBJECT_PATH` 覆盖。
- 运行时配置：`xdp.upstream.mode=afxdp`，`dialPortStart=40000`，
  `dialPortEnd=40999`；接口 `cndial0` mode=proxy queues=[0]，
  localIps=[10.210.0.1, fd00:210::1]。
- attach 实测：`prog/xdp id 205 name cloud_node_xdp ... jited`
  —— 原生 `drv` 挂载（`/tmp/t48-evidence/attach-mode.txt`）。
- v4/v6 连通：peer 侧 `ss -tln` 确认监听
  （`peer-listen.txt`）；v6 初次 ping 失败为 DAD 延迟，随后
  `fd00:210::1→fd00:210::2` 正常（`ping6.txt`）。

## 验证项与证据

### 1. 真实 AF_XDP 外拨 + SYN/SYN-ACK 走 XDP_OUT_CT —— PASS

`xdp dial-smoke --target 10.210.0.2:18080`（run1，
`/tmp/t48-evidence/dial-run1.json`）：

- `local=10.210.0.1:40598` → `10.210.0.2:18080`，
  `sent=received=18000`，`ioError=null`，`outCtHit=21`，
  `dialGuardInstalled=true`。
- peer 侧 pcap 首帧为 `10.210.0.1.40598 > 10.210.0.2.18080: Flags [S],
  options [mss 1460,wscale 0,sackOK,eol]`——smoltcp 选项签名
  （wscale 0 + eol 非内核典型），SYN 由 userspace 栈经 AF_XDP 发出；
  回程 SYN-ACK 被捕获，`out_ct_hit` 随之增长。
- 存活会话中直读 `XDP_OUT_CT`：恰一行
  `local=10.210.0.1:40290 remote=10.210.0.2:18080 fam=4 proto=6`
  （`icmp-timeline.txt`）。

### 2. 内核 socket 双端对照 —— PASS

- peer netns：`ss -tn` 见 `ESTAB 10.210.0.2:18080 → 10.210.0.1:40598`
  （`ss-peer.txt`）。
- host netns：`ss -tn` **无对应条目**（`ss-host.txt` 为空）——
  本端由 AF_XDP 流全权持有，无内核 socket。

### 3. 全程无本端 RST —— PASS

7 份 pcap（peer-icmp 2340 帧、peer3 3756、peer4 10972、peer-reload 等）
中 `src host 10.210.0.1` 的 RST 计数**全部为 0**——包括会话被 reload
冻结的窗口（见 §8 缺陷）也无 RST 外泄（守卫兜住）。

### 4. detach/reattach 窗口 + 守卫丢弃 —— PASS

- `bpftool net detach`（link-attach 场景 `ip link set xdp off` 被拒，
  改用 link detach）：detach 窗口内注入 8 个指向保留端口的源站报文，
  `dial_guard_hits` 计数 **1→9**（`guard-during-detach.txt`/
  `guard-detach-window.txt`），报文被 nft 丢弃、无 RST。
- link detach 后 manager 检测 link 丢失整体卸载 prog；新一轮
  dial-smoke 自动重挂（prog id 247）并立刻恢复收发（run4，
  `sent=received` 全额回声）——reattach 恢复确认。

### 5. 非 PTB ICMP error 不杀会话 + PTB 收敛 —— PASS

45s 会话（40290）中按序注入（`/tmp/t48-evidence/dial-icmp.json`）：

- 01:32:22.86 注入 ICMP type3/code3（非 PTB unreachable，引用真实
  四元组）→ `out_ct_icmp` 0→1，会话继续；
- 01:32:31.03 注入 ICMP type3/code4 PTB mtu=1000 → `out_ct_icmp`→2；
- 终态 `outCtHit=478`，`sent=received=444000`，`ioError=null`。
- wire 分段直方图：PTB 前 `len=1460×88 + 1080×44`，PTB 后
  **`len=960×256` + 160×69**（960 = 1000−40 IP/TCP 头）——
  `apply_pmtu`→`set_path_mtu`→MSS 收敛在 wire 级确认。
- 计数器时序（`ctr-before/after-unreach/after-ptb.txt`）：
  packets/hit 74/74 → 90/89 → 162/160，`out_ct_icmp` 0→1→2。
  早前一次"计数不动"为读取了 stale map 快照 + 注入时机早于
  OUT_CT 行建立，修正后确定性命中。

### 6. 守卫端到端生命周期 —— PASS（一处行为差异见下）

- **安装**：`nft-guard.txt`——`table inet cloud_node_dial_guard`
  含 `dial_guard_hits` 计数器与 `tcp/udp dport 40000-40999 drop`
  规则；`sysctl-reserved.txt`——
  `ip_local_reserved_ports=40000-40999`。
- **幂等重装**：多次 dial-smoke/`xdp reload` 间重复 ensure 均成功
  （`nft_allow_exists` 容错），计数器跨安装延续（观测到 hits=4
  延续至下一轮）。
- **拆除**：manager 释放路径执行 `release_dial_guard`——reload
  换代窗口中实测 table 一度消失后被新代重建（释放+重装两个方向
  都有 wire/对象证据）。
- **差异（记录，非降级）**：`xdp stop` 由新进程执行时不拆守卫
  （新进程的 `dial_guard` 槽为空，无 report 可释放）；
  table+sysctl 跨进程退出存活，下次 ensure 幂等再认领。
  语义上属 fail-closed 兜底（节点停机期保留 span 丢弃、防止
  内核 RST），但属于"孤儿后再认领"模型，无独立 CLI 清理入口，
  已在遗留事项中登记。

### 7. T3-10：veth 双栈协议矩阵 —— PASS

`scripts/xdp-netns-smoke.sh`（新增 `XDP_SMOKE_SKIP_BUILD=1` /
`XDP_SMOKE_PROFILE=release` 复用 release 产物）全量通过
（`netns-matrix.log`，"smoke completed"）：

- doctor / 协议暴露检查 / proxy doctor / proxy-reload-smoke /
  raw dataplane smoke / localIps bypass / application proxy smoke /
  attach→reload→detach→连通性保持→clean detach。
- 应用层计数：`httpRequests=2, httpsRequests=4, tcpConnections=2,
  udpDatagrams=2, sniConnections=2, quicRequests=2, h3Requests=2`；
  `h2(fd00:200::1)=2`。
- 双栈采样：v4 `10.200.0.1:443/9443` 与 v6 `[fd00:200::1]:443/9443`
  TCP+UDP 均落 AF_XDP；`tcpDiag` 中 `ccImpl=smoltcp-edge`、
  `class=https`、`proxyStarted=true`（真实代理会话经 userspace 栈）。
- 独立 v6 外拨（`dial-v6.json`）：`[fd00:210::1]:40735 →
  [fd00:210::2]:18080`，`sent=received=26000`，`outCtHit=29`，
  本端无 v6 内核 socket。

### 8. T3-10：CubicRef vs 上游 Cubic 同 ACK 轨迹 —— PASS（附解释）

新测试 `crates/cloud-node-transport/tests/cubic_ref_vs_upstream.rs`：
两遍法——先用 CubicRef 生成受链路容量约束的共享 ACK/丢包调度，再以
**完全相同的 ACK 轨迹**驱动上游 `congestion::cubic::Cubic`
（workspace smoltcp-edge vendor），逐事件落 CSV。

- 产物 `/tmp/t48-evidence/cubic-compare.csv`（7240 行）：
  `steps=7239, rounds=142, final_ref=75271B, final_up=82044B,
  max_ratio=1.67@step0`。
- 解释：step0 的 1.67× 为初始 cwnd 常数差（ref 5MSS vs 上游 3MSS 起点
  之比），非动态发散；全程锯齿同步、终值比 ~0.92——两者在同一 ACK
  轨迹下收敛到同一数量级，符合"参考实现同轨迹对齐"的验收口径。
- 期间发现并修复测试模型缺陷：慢启动 `n=cwnd/MSS` 造成 ACK 几何爆炸
  （两个 `cubic_ref_vs_upstream` 进程跑飞 CPU），改为瓶颈容量模型 +
  总步数保险丝，测试 0.03s 完成。

## 发现的缺陷（显式报告，未降级掩盖）

### F1 违反：reload 换代时活跃 AF_XDP 会话被提前冻结（BLOCKING）

`xdp dial-smoke --reload-at-ms 6000`（`dial-reload.json` +
`peer-reload.pcap`）：

- `reloadStartedMs=6003`（manager 换代 publish 点）起收发**冻结在
  42000B**——`receivedAtReloadStart=received=42000`；wire 上最后
  一帧 01:33:59.134 与 publish 时刻吻合，先于 commit 完成
  （`reloadFinishedMs=9743`）~3.7s。
- 会话成为**僵尸 socket**：其后 24s `ioError=null`（写端无错误），
  wire 无 FIN/RST——应用层表现为静默挂起。
- 机制：`replace_manager_from_runtime` 在 `initialize_inner` commit
  前已 publish 新 manager；旧 worker 的 `manager_is_current` staleness
  检查在 publish 即退出 → AF_XDP 轮询线程停转 → TX 队列不再排空；
  `release_for_handover` 在 commit 时再释放旧 XSK 句柄；会话状态无法
  迁移到内核路径（smoltcp socket 不可移交），也没有被主动 RST/FIN 或
  向调用方报错——**静默终止**。
- `proxy-reload-smoke` 的对照证据：新代 bridge 在数秒内
  `proxyReady/redirectEnabled/tcpDataplaneReady` 全部恢复——缺陷
  仅限于**存量会话**，新建流在 reload 后正常。
- F1 合同要求"旧 worker 不被提前停"。当前实现与合同不符，需二选一：
  (a) 实现存量 userspace 流跨代迁移/移交；(b) 把合同明确改为
  "reload 即终止存量 AF_XDP 流"，并补主动 RST/FIN + `ioError` 上报 +
  计数器/日志可观测性 + 回归测试。当前状态两者皆不满足，按
  no-unapproved-degradation 记录为既有缺陷，不在本任务内擅自修改语义。

## 遗留 / 限制

- **v6 PTB 未做在线注入**：v6 eBPF out-CT/ICMP 路径已过 verifier
  （17/17）且 v6 数据面经矩阵+dial-v6 实测；ICMPv6 type2 PTB 的活体
  收敛未单独注入（v4 已证明同一 `apply_pmtu` 机制）。
- **zero-copy 未验证**：veth/virtio 环境无 AF_XDP ZC 能力；当前为
  copy 模式证据，ZC 声明需 i40e/ice/mlx5 类硬件另行复测。
- **守卫孤儿模型**：`xdp stop`（新进程）不清理既有 guard 对象；
  fail-closed 语义可接受，但建议登记独立清理入口或文档化。
- **Cubic step0 比值**：1.67× 为初始常数差非发散（见 §8 解释）。
- 远端测试设施按需保留/已清理：`cn-peer` netns + veth 对、
  `/tmp/t48-*` 证据目录、`/sys/fs/bpf/cn-t48` pin 均在隔离路径下；
  生产 `/sys/fs/bpf` 未触碰。

## 证据清单（`/tmp/t48-evidence/`）

| 文件 | 内容 |
|---|---|
| `xdp-verify.txt` | 17/17 prog 过 6.1 verifier |
| `dial-run{1..8}.json` | 各次外拨报告（计数器/tcpDiag） |
| `dial-v6.json` | v6 外拨 26KB 回声 |
| `dial-icmp.json` | 45s 会话 + 2 次 ICMP 注入，outCtIcmp=2 |
| `dial-reload.json` | F1 冻结证据（sent=received 冻结于 reloadStart） |
| `peer*.pcap` `peer-icmp.pcap` `peer-reload.pcap` | 双侧抓包，RST=0 |
| `icmp-timeline.txt` `ctr-*.txt` | 活会话 OUT_CT 行 + 计数器时序 |
| `nft-guard.txt` `sysctl-reserved.txt` `guard-*.txt` | 守卫安装/丢弃计数 |
| `ss-peer.txt` `ss-host.txt` | 双端 socket 对照 |
| `netns-matrix.log` | 双栈协议矩阵全量输出 |
| `cubic-compare.csv` | 7240 行同轨迹 cwnd 对照 |
| `attach-mode.txt` | drv 原生挂载确认 |

## 结论

EN-20/21/22 欠下的真实流量验证已补齐：外拨、OUT_CT、双端 socket、
无 RST、detach/reattach、守卫生命周期、ICMP/PTB、双栈协议矩阵、
Cubic 同轨迹对照全部有 wire/计数器级证据。唯一阻塞性发现为 F1
reload 存量会话静默冻结，已按合同显式上报，待用户裁决修复方向
（迁移 vs 明确终止语义）。
