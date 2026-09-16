# EN-22: T4-7 — AF_XDP 出向流 PMTU/ICMP 错误处理 + RFC 4821 黑洞回退

Base: `d6348ad`（T4-6 之后）
规范: `tasks/xdp-transport-next-steps-2026-09-15.md` §8 T4-7
环境: 本机 macOS `cargo check`（交叉门控验证）+ `vps-110` Linux 构建与全量测试。
范围: `crates/cloud-node-xdp-ebpf/src/main.rs`、
`crates/cloud-node-xdp-common/src/lib.rs`、`src/xdp/linux.rs`、
`src/xdp/mod.rs`、`src/xdp/af_xdp/{mod,parser,dial,bridge,tcp_reactor}.rs`、
`src/origin_h3.rs`、`src/http_proxy_manager.rs`、`src/xdp/tests.rs`、
`vendor/smoltcp-edge/src/socket/tcp.rs`、`vendor/smoltcp-edge/DIVERGENCE.md`。

## 数据通路

```
ICMP error (inbound, any queue)
  └─ eBPF: l4_sanity → L4Class::Control → budget_charge(5)
       └─ try_out_ct_icmp_v4/v6: 解析被引用内层包 → XDP_OUT_CT 命中?
            ├─ 命中: counter out_ct_icmp + xsk_redirect_current → XSK
            └─ 未命中/不可解析: control_pass() → kernel 路径不变
  └─ userspace bridge: parse_proxy_frame 落 None 分支
       └─ parse_icmp_error_frame → AfXdpIcmpError { flow, proto, mtu }
            └─ AfXdpDialRegistry::notify_icmp(flow, mtu)
                 ├─ UDP owner → AfXdpUdpIngress::IcmpError → socket channel
                 └─ TCP owner → AfXdpReactorRequest::PmtuUpdate → reactor
                      └─ AfXdpTcpReactor::apply_pmtu → socket.set_path_mtu
```

## eBPF 侧

- `try_out_ct_icmp_v4`（main.rs:1767）：仅 AF_XDP proxy mode
  （`policy.mode == 2`）；仅错误型 ICMP（3/4/5/11/12）；内层 IPv4 头
  支持 IHL 选项；内层 L4 限 TCP/UDP；五元组查 `XDP_OUT_CT`。
- `try_out_ct_icmp_v6`（main.rs:1824）：ICMPv6 error types 1–4；
  内层扩展头走与活流量相同的 `ipv6_transport_offset` 有界遍历。
- 两个挂点在两个 worker 的 `L4Class::Control` 分支内——ICMP 仍先过
  EN-07 的独立 budget，未命中回 `control_pass()` 不改变 kernel 处理。
- `counter_out_ct_icmp()` 专用计数器；`XdpCounters.out_ct_icmp`
  （ABI 304→312B，断言已同步），userspace 聚合/`/status` 全链路透传
  （`outCtIcmp`）。

## Userspace 解析器（parser.rs）

- `parse_icmp_error_frame`：L2 → IPv4/IPv6 → ICMP error 校验 →
  提取被引用内层 5 元组（`flow.local` = 内层 source = 本节点 dialed
  endpoint）+ MTU（v4 frag-needed 的 next-hop MTU；v6 PTB 的 MTU 字段）。
- 回 `None`：echo/info 消息、畸形包、非 TCP/UDP 内层、内层 4 端口字节
  不完整、IPv6 扩展头遍历失败——此类帧不进入 demux，可观测性仅经
  既有 unparseable debug 路径。

## TCP PMTU（tcp_reactor.rs + smoltcp-edge）

- `AfXdpTcpReactor::apply_pmtu(flow, mtu)`：`Some(mtu)` →
  `socket.set_path_mtu(mtu)`；`None`（非 PTB 错误）→ debug 日志，
  会话继续（kernel 语义：unreachable 不杀活会话）；未知流 → debug
  日志 no-op。
- smoltcp `set_path_mtu`：存 IP datagram 尺寸 cap，下限
  `headers + MIN_REMOTE_MSS`（防 bogus 小报告楔死）；解除黑洞探测；
  `on_mss_update` 通知 ext 控制器新有效 MSS。
- `effective_send_mss` = `min(interface_mss, remote_mss, cap-headers,
  probe_floor)`；cap 项下限 `MIN_REMOTE_MSS`，但结果不再整体 floor
  （修：初版 `mss.max(MIN_REMOTE_MSS)` 把 `remote_mss=6` 的测试连接
  静默放宽到 48，破坏上游 12 个重传测试——已修正并重跑全绿）。
- RFC 4821 黑洞探测：连续 2 次 RTO 且无 cumulative ACK 推进 →
  `pmtu_probe_floor` 生效（MSS ≤ 512）；任何 cum-ACK 推进解除；
  已有 ICMP cap 时不探测（报告即答案）。

## UDP PMTU/错误（dial.rs）

- `AfXdpUdpSocket.path_mtu`：PTB 学习缓存，下限按协议族（v4=576/
  v6=1280）。
- `check_payload_cap`：超 cap 的 send/try_send 返回
  `io::Error::from_raw_os_error(EMSGSIZE)`——与 kernel 语义一致，
  quinn DPLPMTUD 依赖该 errno（`io::ErrorKind::MessageTooLarge`
  在当前工具链仍 unstable，未使用）。
- `AfXdpUdpIngress::IcmpError` 一次性透出：PTB → EMSGSIZE +
  更新缓存；其他错误 → `HostUnreachable`；随后 datagram 正常到达，
  流保持存活。ingress/egress channel 关闭 → `UnexpectedEof`/
  `BrokenPipe` 显式错误。
- `notify_icmp` 队列满时 warn 日志（非静默丢弃）；channel 关闭
  自动 release 流记录。

## 顺带修复

- `AfXdpUdpPoller::poll_writable`（origin_h3.rs）：channel 关闭返回
  Err 后未清 `pending`——再次 poll 会对已完成 future 重复 poll 导致
  panic；已修复（Err 分支同样 `*pending = None`）。
- `http_proxy_manager.rs`：macOS 非泛型实例化路径下 `af_xdp_virtual_stream`
  等死代码警告——按既有模式改 `cfg_attr(not(linux), allow(dead_code))`。

## 验证

- `vps-110` `cargo check`：0 error（仅既有 `XdpProxyConfig` 未用导入
  警告）。
- `vps-110` `cargo test --lib`（vendor/smoltcp-edge 目录内）：
  **681 pass / 0 fail**（675 + 4 个 T4-7 测试 + 2 个既有 ext 测试）。
- `vps-110` `cargo test --lib xdp`（根 crate，
  `RUSTFLAGS="-C debuginfo=line-tables-only"`）：**165 pass / 0 fail**
  （153 + 12 个新测试：ICMP parser ×6、UDP socket PMTU/one-shot/closed
  ×4、notify_icmp 路由、reactor apply_pmtu）。
- `vps-110` `cargo test --lib` 全量：**744 pass / 0 fail / 2 ignored**。
- eBPF 对象随 build.rs 用 pinned toolchain 重建（142,440B，
  较上版 +2,944B）；`XdpCounters` ABI 断言 312B 两侧一致。
- 本机 macOS `cargo check` 通过。

## 边界与限制

- eBPF verifier 实测加载、真实 NIC 上的 PTB 触发与黑洞恢复属于
  T4-8 硬件验证范围——本次为软件路径验证。
- ICMP error 在 eBPF 只按内层 5 元组匹配重定向；userspace 解析是
  authoritative gate，二次校验防误投。
- 非 PTB 的 ICMP error 到 TCP 仅记录 debug——与 kernel 一致，
  不断开会话。
