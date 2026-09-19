# 警告与 lint 策略

本文件约束编译期警告的处置方式，对人和 AI agent 同样有效。
入口约束见 [AGENTS.md](../../AGENTS.md)。

## 规则

**警告必须消除根因，不得用屏蔽的方式压下去。**

编译器警告和 clippy 诊断指向的是真实的代码问题。把它 `allow` 掉不是修复，
只是把问题从"每次构建都能看见"变成"永远看不见"——这与
[禁止未审批降级](no-unapproved-degradation.md) 里"不得通过 catch/默认值掩盖根因"
是同一条原则。

禁止新增的手段：

| 手段 | 例子 |
| --- | --- |
| 属性级屏蔽 | `#[allow(dead_code)]`、`#[allow(unused_mut)]` |
| 模块/ crate 级屏蔽 | `#![allow(clippy::result_large_err)]` |
| 条件化屏蔽 | `#[cfg_attr(not(target_os = "linux"), allow(dead_code))]` |
| 构建期压制 | `--cap-lints`、`RUSTFLAGS="-A warnings"`、`-A unused` |
| 清单降级 | `[lints.rust]` / `[lints.clippy]` 里写 `= "allow"` |

## 为什么这条规则不是洁癖

`8b1ceb1 warnings: zero-warning release prep — fix all rustc/clippy diagnostics`
是本仓库自己的先例：它把构建做成零警告，但同时**新增了 8 处屏蔽**
（6 个 `#[allow(clippy::too_many_arguments)]`、1 个 `#[allow(unused_mut)]`、
以及 `vendor/libinjectionrs` 的 crate 级屏蔽）。警告消失了，问题没有。

存量屏蔽一共 **78 处**：`#[allow(...)]` 43、`cfg_attr(..., allow(...))` 33、
`#![allow(...)]` 2。其中一部分确实掩盖了真问题：

- **`src/proxy.rs:355` `proxy_protocol_ip`** —— `#[allow(dead_code)]` 挂在它上面，
  注释写着"Set by `maybe_consume_proxy_protocol_header` when wired through"。
  全仓库搜索：这个字段除构造时的 `None` 外**没有任何赋值**，却在
  `src/proxy.rs:8005` 被读进 `if let Some(pp_ip) = ctx.proxy_protocol_ip` 分支。
  也就是说那个分支永远不可达——PROXY protocol 解析出的客户端 IP 从未经由这条路径生效。
  要么补上接线，要么删字段并删分支，**不能继续用 `allow` 挂着**。
- **`src/bin/bench-proxy.rs:140`** —— `fn _t(_: Bytes) {}`，注释直接写着
  "Silence unused import lint when feature-gated pieces shift"。这是纯粹的屏蔽。
- **`src/xdp/mod.rs:350` `live_workers`、`:585` `proxy_workers_starting`** —— 两者都
  有实际读取点（`live_workers` 在 `:403` 的 `while` 里，`proxy_workers_starting`
  有访问器 `:988`）。`allow` 看起来已经失效：它不再压制任何东西，却会在将来真正的
  `dead_code` 出现时替它兜底。
- **`src/tcp_proxy.rs`（3 个函数）、`src/xdp/af_xdp/bridge.rs:475` `start_udp_bridge`**
  —— 定义了、`pub use` 导出了，但全仓库无调用点。

另有两类**不应盲目"修掉"**：

- **9 处 `clippy::await_holding_lock` 全部在 `#[tokio::test]` 里**，持锁的是一个测试间
  串行化用的 `Mutex`，需要跨 await 持有整个测试生命周期。这是正当用法，不是生产路径的
  死锁风险；要消除应该让测试锁不再需要跨 await，而不是删掉 `allow` 了事。
- **33 处 `cfg_attr(not(target_os = "linux"), allow(dead_code))`** 表达的是真实的平台差异。
  正确做法是把条件写在**条目**上（`#[cfg(target_os = "linux")]`），
  而不是写在 lint 上。这样等价、可读，且不留屏蔽。

## 存量债务

存量 78 处**不追溯**，同署名禁令的处理方式：已合入的代码不为了合规而重写。
但它们是一份待清偿的清单——触碰某个文件时顺手清掉该文件的屏蔽是受欢迎的，
专门开一个清偿提交更好。

## 例外与审批

确有必要的例外（例如 rustc 自身误报、第三方宏展开产生的无法本地消除的诊断），
在该提交的信息里写明：

```
Warning-Suppression-Approved: <理由，说明为什么无法消除根因>
```

检查器会放行该提交，并把它打印出来——例外是可见的，不是隐形的。

审批只授权所描述的范围。**首选替代方案优先级：**

1. 消除根因（删死代码、补接线、改设计）。
2. 用 `#[cfg(...)]` 表达条件编译，而不是 `cfg_attr(..., allow(...))`。
3. `#[expect(lint, reason = "…")]` —— 它本身是自我检查的：lint 不再触发时会反过来报
   `unfulfilled_lint_expectation`，所以不会像 `allow` 一样无限期烂在代码里。
4. 最后才是 `Warning-Suppression-Approved` 例外。

## 豁免范围（有意保留的缺口）

`pingora-main/`、`toa-main/`、`toa-sender/`、`vendor/` 不参与检查。
[AGENTS.md 硬约束 2](../../AGENTS.md) 本就禁止修改它们，而要求第三方代码零警告
等于要求长期维护一个 fork。**要给 vendored 代码打补丁，走硬约束 2 的审批**，
由那条规则兜底，不靠这里。

## 门禁

| 层 | 位置 |
| --- | --- |
| 脚本 | `scripts/git-hooks/check-suppression.sh` |
| CI | `.github/workflows/commit-hygiene.yml` 的 `no-new-suppression` job |

只检查 diff 里**新增**的行，所以存量 78 处不会让 CI 变红。
手工复核：

```bash
bash scripts/git-hooks/check-suppression.sh --range origin/main..HEAD
```

**扫描范围（有意收窄）**：只认**语法位置**，不认裸词——匹配"形态"，不匹配"提及"。
这条边界是被自己的门禁打回来才划清的：不加约束时，一条*说明屏蔽问题*的提交会被自己拦下
（文档表格里的 `#[allow(dead_code)]` 示例、检查器自身源码里出现的 `--cap-lints`）。

| 扫描对象 | 判定条件 |
| --- | --- |
| `.rs` 文件 | 去掉缩进后**行首**即 `#[allow(` / `#![allow(` / `#[cfg_attr(` 且行内含 `allow(` |
| `Cargo.toml`、`.cargo/config.toml`、workflow YAML | flag 出现在引号内（`"--cap-lints"`、`"-A warnings"`）或 `= "allow"` 形式 |
| `.md`、`.sh`、其他 | 不扫描 —— 文档和检查器自身会大量引用这些符号 |

因此，一条把 `#[allow(...)]` 改成 `#[expect(...)]` 的提交能正常通过，
而一条真的新增屏蔽的提交会被拦下。

## 尚未做到的一步

真正的终局是让 CI 把警告当错误：在 `ci.yml` 的 `RUSTFLAGS` 里追加 `-D warnings`
（现有值是 `-C target-cpu=x86-64-v2`），这样任何新警告直接构建失败，不再依赖复查。

**前置条件是代码库当前必须真的零警告。** 这一步还没有做，因为无法在改动中的工作区
可靠地验证这一点——需要一次干净的完整构建来确认。确认之后再加，否则 CI 会立刻全红。
