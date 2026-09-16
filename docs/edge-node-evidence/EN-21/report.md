# EN-21: T4-6 — 四个回源连接面 AF_XDP 接管

Base: `8d5df01`（T4 阶段一之后）
规范: `tasks/xdp-transport-next-steps-2026-09-15.md` v3 §8 T4-6
环境: 本机 macOS `cargo check`（交叉门控验证）+ `vps-110` Linux 构建与全量测试。
范围: `src/toa.rs`、`src/tcp_proxy.rs`、`src/http_proxy_manager.rs`、
`src/proxy.rs`、`src/udp_proxy.rs`、`src/origin_h3.rs`、
`src/xdp/af_xdp/{dial,bridge,parser,mod,tcp_reactor}.rs`、`src/xdp/linux.rs`、
`src/xdp/mod.rs`、`src/xdp/tests.rs`。

## 接管面总览

| 回源面 | 入口 | AF_XDP 选择条件 | 失败语义 |
|--------|------|------------------|-----------|
| TCP proxy | `toa::connect_upstream`（tcp_proxy ×3） | `xdp.upstream.mode=afxdp` | 显式 `io::Error`，无 kernel 回退 |
| SNI passthrough | `toa::connect_upstream`（http_proxy_manager ×2） | 同上 | 同上 |
| Pingora HTTP 回源 | `UpstreamL4Connector`（`L4Connect`）→ `connect_upstream` | 同上 | `ConnectError`/`ConnectTimedout` |
| UDP proxy | `connect_backend_udp_socket` → `af_xdp_dial_udp` | 同上 | 显式 `io::Error` |
| HTTP/3 回源 (quinn) | `create_h3_endpoint` → `af_xdp_dial_udp` + `AsyncUdpSocket` | 同上 | `ConnectError` |

`afxdp_upstream_selected()` 为唯一开关消费点；mode 未选 afxdp 时全部走原 kernel 路径，行为不变。选 afxdp 但无 live registry/bridge 时返回 `NotConnected` 显式错误——无静默降级。

## TCP 面

- `UpstreamL4Stream` 枚举：`Kernel(TcpStream)` / `AfXdp(AfXdpTcpStream)`，
  暴露 `local_addr`/`peer_addr`/`kernel_toa_port`/`configure_relay_socket`/
  `into_pingora_stream`。
- `connect_upstream`：afxdp 模式 → 解析地址 → 可选 TOA SYN 选项
  （`toa_syn_option_bytes`，kind 254 经 smoltcp `set_syn_extra_options`
  前置校验）→ `af_xdp_dial_tcp`；否则原 `connect_with_toa`。
- relay dispatch `stream_tcp_backend_bidirectional_with_metrics_options`：
  Kernel 变体保留原内核 zero-copy/splice 路径；AfXdp 变体无内核 fd，
  走 userspace relay——结构性差异、显式、非隐藏降级。
- `write_proxy_protocol_header` 泛化为 `AsyncWrite + Unpin`，PROXY 协议头
  对两类流同等生效。
- Pingora `UpstreamL4Connector`：超时→`ConnectTimedout`，其余→
  `ConnectError`；peer 的 timeout/ALPN/TLS verify/H2 协商保持原语义；
  socket digest 保留目的端信息。

## UDP 面

- `UpstreamUdpSocket` 枚举（Kernel/AfXdp）：`send`/`recv`/`local_addr`/
  `defunct`。
- `af_xdp_dial_udp(remote, preferred_port)`：路由解析 → 队列选择 →
  bounded 回复 channel → 源端口 claim → `XDP_OUT_CT` 插入；
  失败路径全部回滚。
- `claim_flow` 支持 `preferred_port`：范围内且精确元组空闲则优先复用
  （保留 `recent_upstream_ports` 端口固定语义）；同端口不同对端可复用；
  精确元组占用或越界则正常扫描；耗尽→`AddrInUse`。
- bridge：入向 UDP 回包按元组查 dial registry，命中则投递到 owner
  channel（跨队列 userspace demux），channel 关闭即释放注册；满则丢
  （UDP loss 语义）。
- UDP 会话循环：AfXdp `defunct()` → 会话永久终止；kernel ICMP/send
  错误保持既有 transient 语义。

## QUIC 面（HTTP/3 回源）

- `AfXdpQuinnUdpSocket` 实现 `quinn::AsyncUdpSocket`：
  - `try_send` → `AfXdpUdpSocket::try_send`（bounded channel 满→
    `WouldBlock`，closed→`BrokenPipe`）；destination/segment_size 校验，
    ECN codepoint 透传。
  - `poll_recv` → `Mutex` 化 ingress channel 的 `poll_recv`，
    `RecvMeta` 填 addr/len/stride/ecn/dst_ip。
  - `create_io_poller` → `reserve_owned` pending-future poller
    （`Send+Sync` 经 `Mutex` 达成）。
  - `may_fragment()=false`：userspace dataplane 不产生 IP 分片，
    quinn 保持 PMTUD armed。
- `Endpoint::new_with_abstract_socket` + `TokioRuntime` 构造端点；
  dial/构造失败→`ConnectError`。

## ECN 端到端透传

- `encode_udp_reply_frame` 加 `ecn` 参数：IPv4 TOS=ecn，IPv6
  TC[1:0]→byte1[5:4]；`send_udp_datagram` 透传。
- `AfXdpL4Packet.ecn`：parser 提取 IPv4 TOS/IPv6 TC 低 2 位；
  `AfXdpUdpDatagram{payload, ecn}` 携带至 dialed socket；
  quinn `RecvMeta.ecn` 经 `EcnCodepoint::from_bits` 还原。
  QUIC 拥塞反馈标记全程不丢。

## 测试与验证

- `vps-110` `cargo check`：0 error；警告仅剩既有项
  （`XdpProxyConfig` 未用 import、smoltcp cfg 提示）。
- `cargo test --lib xdp`：153 passed / 0 failed。
- `cargo test --lib` 全量：733 passed / 0 failed / 2 ignored。
- 新增/更新测试：preferred-port pinning（首用端口/异对端复用/同元组
  回退扫描/越界回退）、UDP owner demux 携带 ECN、`toa` T4-6 测试×4、
  reactor dial 测试×4、registry claim/release/inject/耗尽测试。
- 本机 macOS `cargo check` 通过（linux-only 代码全部正确门控）。

## 直连审计

生产回源路径无残留 `TcpStream::connect`/`UdpSocket::bind` 旁路：
tcp_proxy ×3、http_proxy_manager ×2、proxy.rs（Pingora L4）、
udp_proxy、origin_h3 全部经 funnel。剩余命中均为测试代码、NTP 管理面、
lab/smoke 工具——非代理数据面。

## 已知限制（设计内、非降级）

- AF_XDP 虚拟 TCP 流无内核 fd，relay 为 userspace 拷贝路径——结构性
  差异，已在 dispatch 处显式分支。
- AF_XDP UDP channel 关闭 = 流永久失效（`defunct`/`UnexpectedEof`），
  与 kernel UDP transient 错误语义不同——有意设计。
- 硬件相关原生/零拷贝能力留待 T4-8 VPS 流量验证；本阶段证据为
  软件层（编译+单元/集成测试）。
