<!--
PR 描述模板。四段式结果报告是 AGENTS.md 的硬要求，
不要删字段；没有内容就写"无"，留空会被当成没做。
-->

## 改动摘要

<!-- 一句话说清改了什么、为什么改。 -->

## 影响面

- [ ] 请求热路径（L7 / L4 / XDP / 缓存）
- [ ] 配置模型或热重载路径
- [ ] 协议行为（HTTP / TLS / QUIC / TCP / UDP / SNI / PROXY protocol）
- [ ] vendored 代码（`pingora-main/` `toa-main/` `toa-sender/` `vendor/`，需在下方说明理由）
- [ ] 需要同步更新 `docs/`

## 验证

<!-- 贴实际跑过的命令和结果。不要写"应该没问题""理论上可以"。 -->

- [ ] `cargo check --all-targets`
- [ ] `cargo test --lib --bins`
- [ ] `cargo clippy --all-targets -- -D clippy::correctness -D clippy::suspicious`
- [ ] 热路径改动：`benches/` 对应 bench 的前后数据
- [ ] 协议改动：连接生命周期 / 超时 / 取消 / 关闭路径的论证
- [ ] 涉及构建配置或依赖：按 CI baseline（`RUSTFLAGS=-C target-cpu=x86-64-v2`）复核

## 结果报告（必填）

**已修复的问题**

<!-- -->

**仍存在的问题**

<!-- 没有就写"无"，不要留空 -->

**设计限制**

<!-- -->

**经审批的降级**

<!--
没有就写"无"。
任何降级都必须写明：触发条件与受影响范围、原行为、降级后行为、
对正确性/一致性/可用性/可观测性的影响、恢复条件，并确认已获得明确审批。
判定标准和审批要求见 docs/agents/no-unapproved-degradation.md。
-->

## 署名确认

- [ ] 本分支所有提交的作者与提交者均为本人身份，不含 AI 工具或 bot 署名
      （CI 的 Commit Hygiene 检查会复核这一点）
