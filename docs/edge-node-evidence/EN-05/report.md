# EN-05 有界解析与分片策略 — 验证报告

基线提交：`df7d125`（EN-04 之后的工作树）。本任务在不改变合法流量语义的前提下，把
eBPF 与用户态 AF_XDP 解析路径统一为显式分类模型，并为每类终态提供独立计数器。

## 分类模型

`crates/cloud-node-xdp-ebpf/src/main.rs` 与 `src/xdp/af_xdp/parser.rs` 现在产出
相同的五类判定（共享常量 `XDP_CLASS_*` 在 `cloud-node-xdp-common`）：

| 类 | 语义 | XDP 动作 | 计数器 |
|---|---|---|---|
| `MALFORMED` | 确定性非法：版本错、IHL<20、tot_len<IHL、声明长度超过实际帧、TCP doff<20/越界、NULL/SYN+FIN/SYN+RST flags、UDP len<8/越过数据报边界、>2 VLAN | DROP | `malformed` + `drop` |
| `UNSUPPORTED` | 合法但解析器不支持：>2 层 VLAN 的载荷、IPv6 扩展链超深/未识别扩展头、非 TCP/UDP/ICMP 协议（GRE 等） | PASS | `unsupported` + `pass` |
| `FRAGMENTED` | 任何 IP 分片（含首片、atomic） | 按策略 PASS 或 DROP | `fragmented` + `pass`/`drop` |
| `CONTROL` | ICMP / ICMPv6（ND、PTB/PMTU 必须交给内核栈） | PASS | `control` + `pass` |
| `SUPPORTED` | TCP/UDP 合法包 | 原有路径（rate-limit → local-IP → NAT tail-call → redirect/PASS） | 原有计数器 |

关键语义：

- 首片**不再**独立创建可信 L4 状态：`handle_ipv4`/`handle_ipv6` 在 ACL 之后、
  rate-limit/redirect/NAT 之前按 FRAGMENTED 分类直接返回——不建 rate bucket、
  不进 redirect、不建 conntrack。
- 分片处置按 VIP/安全域解析：per-VIP 覆盖（`XDP_LOCAL_*` map 值 bits[2:1]）优先于
  接口级 `fragment_action`（`XdpInterfacePolicy` 字段，原 padding 位启用）。
- 合法 ECN（ECE/CWR）、TCP options（MSS/SACK/TFO）、扩展头链 ≤ 深度上限均不误伤——
  tcp_syn_ecn / tcp_syn_options / ipv6_dest_opts 语料断言 `malformed==0`。
- 每个终态可观测：`malformed`/`unsupported`/`fragmented`/`control` 进入
  `XdpCounters`（per-CPU）、`xdp status`、`xdp dump-maps`。

## 配置面

`XdpInterfaceConfig` 新增 `fragment_action`（pass/drop，默认 pass 保持现状语义）与
`fragment_overrides`（per-VIP 地址→动作）；`runtime_mode.rs` 校验取值、地址族与重复项；
`xdp_auto_config` 生成默认字段；`linux.rs` 把策略编码进 `XDP_INTERFACE_POLICY` 与
`XDP_LOCAL_*` map 值。

## 验证过程发现的两个真实缺陷

1. **陈旧 eBPF 对象嵌入**：`build.rs` 在无 nightly 的构建机上回退嵌入
   `data/cloud-node-xdp-ebpf.o`，而 verifier 日志三次完全一致暴露了"源码已改、
   嵌入未变"。处置：每次迭代显式校验嵌入产物 sha 与源 mtime。这本身是需要记录的
   运维教训——报告文件保留原始 verifier 输出。
2. **`read_u8` 16 字节边距误伤合法短包**：初版 `read_u8` 用 `offset+16<=end` 留边距，
   导致 TCP flags 字节距帧尾 <16B 的合法包（54B SYN、QinQ、IPv6 SYN）全部被
   MALFORMED 丢弃——T01 实跑直接暴露（tcp_syn_options 因帧更长反而通过，精确定位了
   边界效应）。修复为经 `ptr_at::<u8>` 的单字节精确边界（`offset+1>end`），该形状在
   本文件中被 verifier 稳定接受。

## 实测结果（OrbStack x86 VM，kernel 7.0.14，veth+netns，attach=skb）

```
runner.py --mode proxy --only T01  → ok:true
runner.py --mode proxy（全矩阵）   → ok:true
  T01 28 cases + T02 4 + T03 3 + T04 2 + T06 1 = 38/38 通过
  T05/T07–T18 按矩阵属主跳过（EN-09/EN-24.. 前置未就绪）
ebpf_sha256 = 3ecef86b7ef2140067266e70741d293e3a0449c686e4c885c4936f6adc54ae09
```

抽样断言（counter delta per case）：

- `tcp_syn` → pass/redirect 路径，malformed=0
- `tcp_null_flags`/`tcp_syn_fin`/`tcp_syn_rst` → malformed=1, drop=1
- `tcp_syn_ecn`/`tcp_syn_options` → malformed=0（合法标志/选项不误伤）
- `frag_first`/`frag_nonfirst`/`frag_atomic`/`ipv6_fragment` → fragmented=1，
  默认 pass 策略下 pass=1，无 L4 状态建立
- `ipv6_dest_opts`（≤深度上限）→ pass=1, malformed=0
- `ipv6_ext_chain_deep` → unsupported=1, pass=1
- `icmp`/`icmp_ptb`/`icmpv6_ns`/`icmpv6_ptb` → control=1, pass=1
- `gre` → unsupported=1, pass=1
- `vlan3_tcp_syn` → unsupported=1, pass=1
- `ipv4_truncated`/`tcp_doff_short`/`udp_len_short` → malformed=1, drop=1

Verifier：全程序加载无拒绝；netns 拓扑下无 out-of-bounds。

用户态镜像分类器 `classify_frame`（`src/xdp/af_xdp/parser.rs`）与 eBPF 同序同规则，
`src/xdp/tests.rs` 单测覆盖 v4/v6/VLAN/分片/畸形样例；`af_xdp_attack_pcap_samples_
parse_without_state_growth` 确认攻击语料不产生状态增长。

## 其余环境说明

- macOS：`cargo test --lib xdp` 99 项通过；`cargo check` 无新告警。
- 语法测试期间发现 netns 内核对端自发 ICMPv6 NS 会污染 per-case delta，
  runner 现在在拓扑建立时对双端 `disable_ipv6=1`（原始注入帧不受内核 IPv6
  状态影响，v6 用例照常）。

## 遗留限制（如实记录）

- `fragment_action` 默认 pass：保持接入期语义；drop 策略的逐服务启用属 EN-06/07
  的 policy 工作，本任务只交付可配置能力与正确分类。
- IPv6 扩展链深度上限内继续解析，超限 → UNSUPPORTED（PASS）而非 DROP——合法但
  无法有界判定的流量交给内核栈，属有界解析的设计取舍，非降级。
- Kernel 6.1 native-attach 的 verifier 通过性未实测（环境为 7.0.14 skb）；T18
  平台矩阵仍由 EN-30..33 覆盖。
