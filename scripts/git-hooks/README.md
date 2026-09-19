# Git 钩子

## 安装

钩子不随仓库分发，每个克隆需要做一次：

```bash
git config core.hooksPath scripts/git-hooks
```

验证：

```bash
git config --get core.hooksPath   # -> scripts/git-hooks
```

## 内容

| 文件 | 作用 |
| --- | --- |
| `commit-msg` | git 调用的钩子入口，`git commit` 时检查提交信息 |
| `check-attribution.sh` | 署名规则；本地钩子与 CI（`.github/workflows/commit-hygiene.yml`）共用，避免两套标准漂移 |
| `check-suppression.sh` | 禁止新增屏蔽警告的手段；同样由本地复核与 CI 共用 |

## 手工检查

```bash
# 检查一条提交信息草稿
bash scripts/git-hooks/check-attribution.sh --message-file .git/COMMIT_EDITMSG

# 检查一段提交范围
bash scripts/git-hooks/check-attribution.sh --range origin/main..HEAD
bash scripts/git-hooks/check-suppression.sh --range origin/main..HEAD
```

## 绕过与关闭

```bash
git commit --no-verify              # 跳过一次
git config --unset core.hooksPath   # 彻底关闭本地钩子
```

绕过只影响本地钩子，CI 的 Commit Hygiene 检查仍会拦下不合规的提交。

## 规则

完整规则见 [docs/agents/commit-and-pr-conventions.md](../../docs/agents/commit-and-pr-conventions.md)。
