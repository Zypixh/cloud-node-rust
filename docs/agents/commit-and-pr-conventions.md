# 提交与 PR 规范

本文件约束所有进入本仓库的提交与拉取请求，对人和 AI agent 同样有效。
入口约束见根目录 [AGENTS.md](../../AGENTS.md)。

规范不是凭空制定的：下面的格式约定是从 `main` 上已有的 700+ 次提交里归纳出来的，
署名禁令则来自实际发生过的污染（见 [§2](#2-署名禁令与历史污染)）。

## 1. 身份

规范身份只有一个：

```
Zypixh <moying8259@gmail.com>
```

`git config` 必须设置成它。同一个人的其他等价身份由 [`.mailmap`](../../.mailmap)
在展示层归并，不要靠改历史来统一。

## 2. 署名禁令与历史污染

**作者、提交者只能是人；提交信息里不得出现第三方署名。**

本仓库已经真实发生过两类污染，这不是假设风险：

| 来源 | 表现 | 数量 | 时间 |
| --- | --- | --- | --- |
| Devin | `Generated with [Devin](https://devin.ai)` + `Co-Authored-By: Devin <…+devin-ai-integration[bot]@…>` | 88 个提交 | 2026-09-11 ~ 09-17 |
| Cursor | 作者/提交者直接写成 `Cursor Agent <cursoragent@cursor.com>`、`cursor[bot] <…+cursor[bot]@…>` | 39 个提交 | 2026-08-18 ~ 08-26 |

（Devin 那批全是普通提交，没有合并提交被污染；统计口径是不区分大小写地匹配
`devin-ai-integration` 或 `Generated with [Devin]`。）

这两类都被推送到了 `main`。**历史不重写**——已发布的历史改写会破坏所有克隆、
fork、标签和 release 校验，代价远大于收益。禁令只对将来的提交生效。

具体禁止：

- `Co-Authored-By:` / `Co-Developed-By:` trailer 里出现非 Zypixh 身份；
- `Generated with …` / `Created with …` / `Written by …` 一类生成器署名行；
- 工具或 bot 身份（`@cursor.com`、`devin-ai-integration`、`*[bot]@users.noreply.github.com`、
  `anthropic.com`、`claude.ai`、`openai.com` 等）出现在任何位置；
- `🤖` 之类的机器人标记；
- 把工具身份设为 `user.name` / `user.email`。

`Co-Authored-By: Zypixh` 是冗余的（作者本来就是本人），但不算违规。

**刻意不按裸词匹配。** 本仓库正文里合法出现 `cursor`（如 `sweep_cursor()`）、
`claude`、`codex` 一类词汇，检查器只拦截"署名形态"的行，不拦正文用词。
改动检查器时务必保持这个性质，否则会大面积误伤正文。

## 3. 提交信息格式

### 标题行

```
<scope>: <摘要>
```

- `scope` 小写，用仓库既有的领域词。已有高频 scope：
  `fix`(98) `perf`(56) `edge`(42) `feat`(40) `ci`(40) `docs`(33) `xdp`(23)
  `chore`(17) `memory-governance`(16) `release`(15) `installer` `afxdp` `governor`
  `h3` `firewall` `defense` `transport` `refactor` `test` `bench`。
- 首选单冒号形式；conventional 括号形式 `feat(xdp): …` 也接受（已有 155 次）。
- 摘要用中文或英文都行（历史两者都有），**要说清做了什么**。
- 长度：历史中位数 60 字符，p90 是 81。标题只占一行。
- 禁止 `Release <tag>` 这类零信息量标题，要带上版本对应的实际内容。
- 破折号 `—` 后接"为什么"是本仓库的常见写法，鼓励沿用。

### 正文

标题之外必须给出**可核验的事实**，而不是复述改动。历史里高质量提交的共有结构：

1. **根因**：原来的行为是什么、为什么错（引用具体函数名/字段名）。
2. **行为改变**：现在怎么算、边界条件是什么。
3. **实测数据**：带数字的前后对比，注明测量环境。
4. **`Tests:` 段**：说明覆盖了什么，尤其是负路径。

空正文的提交只允许出现在 `release-notes:` 这类纯文档提交上。

## 4. 分支与 PR

- 目标分支：`main`。
- 分支命名：`<主题或工具>/<短横线 slug>`。历史上出现过 `cursor/…`、`devin/…`。
  **分支名可以带工具名，提交署名不行**——分支是临时的，提交是永久的。
- 每个 PR 必须填 `.github/pull_request_template.md`，其中四段式结果报告（已修复 /
  仍存在 / 设计限制 / 经审批的降级）是硬要求，来自
  [no-unapproved-degradation.md](no-unapproved-degradation.md)。
- 性能与协议改动必须贴实测命令与输出，不接受"理论上更快"。

## 5. 门禁

| 层 | 位置 | 性质 |
| --- | --- | --- |
| 本地钩子 | `scripts/git-hooks/commit-msg` | 可被 `--no-verify` 绕过 |
| CI | `.github/workflows/commit-hygiene.yml` | 不可绕过 |

两者调用同一个 `scripts/git-hooks/check-attribution.sh`，规则只有一份，不会漂移。

本地安装（每个克隆一次）：

```bash
git config core.hooksPath scripts/git-hooks
```

CI 在两种事件上运行：PR 到 `main`，以及 push 到 `main`。检查范围取
`merge-base(base, head)..head`，即只算本次改动引入的提交。

### 已知缺口

**`main` 目前没有分支保护。** 因此直接 push 时 CI 检查只会让状态变红，
不会阻断推送——它是一道可见性告警，不是硬门禁。要变成硬门禁需要两步：

1. 在 GitHub 仓库设置里启用 `main` 的分支保护；
2. 把 `Attribution / commit-message check` 设为必需状态检查。

这会让"直接 push 到 `main`"不再可用，需要改走 PR 流程——是否切换由仓库所有者决定。

## 6. 违规处置

- **还没推送**：直接 `git commit --amend` 或 `git rebase -i` 修掉。
- **已经推送到 `main`**：不要重写历史。记录下来，修正 `git config` 里的工具身份，
  确认门禁生效，往后不再发生。
- **发现某个 agent 工具默认带署名**：在它的配置里关掉，或先确认它不会提交；
  不要只在事后手工清理。
