# EN-15: 终止型 QUIC 无状态地址验证（Retry）+ 迁移边界

Base: 工作树（EN-16 hysteresis/stateTables 之后）
锁定的 quinn API（v0.11.11 / quinn-proto v0.11.17）：`Incoming::{retry, may_retry,
remote_address_validated, remote_address, accept, refuse, ignore}`；
`ServerConfig` 无 use_retry 开关——retry 能力默认可用（随机化握手 token key
由 `with_crypto` 生成），`retry_token_lifetime` 默认 15s。

## 设计

Retry 判定位于 `run_endpoint` accept 循环内、L4 block 检查之后、
**任何握手状态/准入许可/任务分配之前**（`src/http3_proxy_manager.rs`）。
注意边界语义：到判定点为止 quinn 已完成 UDP/Initial 解析并构造出
`Incoming` 对象——本门避免的是握手状态与任务分配，不是解析成本本身。

1. `is_l4_blocked` → 显式 `connecting.ignore()`：线上零响应
   （不是隐式 Drop——quinn 0.11 中 `Incoming::drop` 会发 CONNECTION_REFUSED，
   对被封禁源那是有损放大且语义错误）。
2. `remote_address_validated()` == true → 直接走常规准入
   （Retry token 或 NEW_TOKEN 已验证，永不二次 Retry → 有效 Retry 无循环）。
3. 未验证 + 策略要求 + 聚合预算有余 → `connecting.retry()`：发 Retry 包、
   Incoming 被消费、零状态残留。伪造 Initial 每个最多换一个小 Retry 包——有界。
4. 未验证 + 策略要求 + **预算耗尽** → 显式 `connecting.ignore()`
   （`h3_retry_limited` 计数），与 keyless/策略放行互不混淆。
5. 未验证 + 策略放行 → 走既有 bounded 准入（连接许可 + listener-pool 许可）；
   准入失败显式 `connecting.refuse()`（`h3_refused_incoming` 计数）。

策略 `http3Policy.addressValidation`（控制面同步，wire 兼容缺省）：

- `adaptive`（默认）：`current_pressure_level() >= Elevated` 时才 Retry——
  正常零 RTT 开销，洪泛下压力升级后伪造 Initial 不再消耗握手状态。
- `always`：所有未验证地址一律 Retry。
- `off`：操作者显式声明的无 Retry 模式（较低防护，仍受准入界限保护）。

聚合预算 `http3Policy.retryPps`（wire 兼容缺省 1024/s，`0` 关闭 Retry）：
固定窗口原子计数器，**全节点共享**——不随 listener/worker 数量放大；
每窗口内尝试计数 `h3_retry_attempted` 无界记录、发放计数有界。

## 边界

- **迁移**：握手后客户端换路径由 quinn 内部 PATH_CHALLENGE 验证
  （`ServerConfig::migration` 默认启用），不回到本门——本门只管初始验证。
- **透传**：`is_quic_passthrough()` 的服务器不进入 `desired_ports`，
  结构上保证不向透传 QUIC 注入 Retry。
- **放大**：Retry 是小包、每 Initial 至多一个、且仅对未被封禁地址发送；
  quinn 内部另有 anti-amplification 限制。
- **可观测**：`h3_retry_counters()` = attempted / issued / failed /
  limited / validated / ignored / refused 七个原子计数，透出到
  perf-monitor 快照 + debug 日志。Retry 是正常握手步骤而非
  敌意证据，刻意**不**进 `record_l4_event`（那会喂 per-IP 自动封禁
  评分，可能误伤合法客户端）。

## 验证

- `cargo test --lib`（本机 macOS，673 pass）：新增
  `h3_retry_required_matrix`（三模式 × 四压力级全矩阵）、
  `http3_policy_address_validation_defaults_and_parses`（缺省/大小写/
  别名/未知值→adaptive）、
  `h3_retry_roundtrip_validates_without_loop`（真实 quinn endpoint +
  真实 quinn client：首连接恰好 1 次 Retry 后 validated 接受；
  第二连接经 NEW_TOKEN 直接 validated——retry 计数仍为 1，无循环）。
- `cargo test --lib`（.110 Linux）：见执行状态记录。

## 遗留/限制

- Retry token key 是 endpoint 进程内随机 key：节点重启后旧 token 失效，
  客户端收到 CONNECTION_CLOSE 后以全新 Initial 重连（标准 quinn 行为）。
  进程内不轮换：retry token 生命周期 15s、NEW_TOKEN 默认 2 周，静态
  per-process key 满足验收；如需热轮换可用 `ServerConfig::token_key`
  注入外部管理的 `HandshakeTokenKey`——当前不在交付内。
- `adaptive` 依赖压力检测先升到 Elevated：洪泛开始到有压力之间有
  一个由准入预算兜底的窗口——伪造 Initial 始终有界，只是界限构成不同。
- QUIC demux/AF_XDP 旁路路径的伪造 Initial 由 quic pending-route 与
  reassembly 预算有界（EN-16 计数），不在本 Retry 门内。
- 任务卡"按服务回到无 Retry 模式"在结构上不可行：Retry 判定发生在
  SNI/ALPN 可用之前（TLS 握手前），无法在 Initial 阶段按服务区分。
  旋钮粒度为 listener（端口）/全局策略——这是 QUIC 协议约束，不是实现省略。
- 迁移后的新地址不经过 L4 per-IP block 复检。PATH_CHALLENGE 只验证
  **路径可达性**（新地址确实属于该连接的对端），**不是** L4 授权/
  黑名单语义的等价物：迁移到一个已被 L4 封禁的地址不会被本门拦截
  （quinn 内部路径验证放行），这是如实记录的设计限制而非等价防护。
  连接注册表不登记 QUIC 连接（仅 HTTP1/H2/TCP/SNI），tuple 式 drain
  结构性碰不到 QUIC——合法迁移不因此被杀，满足"不因 tuple 变化被杀"
  验收；代价是被封禁 IP 的既有 QUIC 连接也不会被主动 drain。
