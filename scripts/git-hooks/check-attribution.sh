#!/usr/bin/env bash
#
# 提交署名检查 —— 本地 commit-msg 钩子与 CI 共用同一份规则。
#
# 规则（完整说明见 docs/agents/commit-and-pr-conventions.md）：
#   1. 作者与提交者只能是本人身份，不得是 AI 工具或 bot 身份。
#   2. 提交信息里不得出现第三方署名 trailer；唯一的例外是本人 Zypixh。
#
# 用法：
#   check-attribution.sh --message-file <路径>      # 本地钩子模式，检查单条信息
#   check-attribution.sh --range <base>..<head>     # CI 模式，检查一段提交
#
set -euo pipefail

# --- 允许的身份 --------------------------------------------------------------
# 同一个人的等价身份；.mailmap 负责在展示层归并，这里负责放行。
readonly ALLOWED_AUTHOR_EMAILS=(
  'moying8259@gmail.com'
  '79520628+Zypixh@users.noreply.github.com'
  'zypixh@users.noreply.github.com'
  'Zypixh@users.noreply.github.com'
)

# 提交者额外放行 GitHub 网页端合并产生的身份（noreply@github.com），
# 否则通过 UI 合并 PR 会被误判。
readonly ALLOWED_COMMITTER_EMAILS=(
  "${ALLOWED_AUTHOR_EMAILS[@]}"
  'noreply@github.com'
)

# --- 禁止的署名形态 ----------------------------------------------------------
# 刻意不按裸词匹配：本仓库的正文里合法出现 cursor（sweep_cursor()）、
# claude、codex 一类词汇，只拦截"署名形态"的行。
#
# 形如 `Co-Authored-By: <identity>` 的 trailer：除 Zypixh 外一律拦截。
readonly TRAILER_RE='^[[:space:]]*co-(authored|developed)-by[[:space:]]*:'
# 形如 `Generated with [Devin](https://devin.ai)` 的生成器署名：一律拦截。
readonly GENERATED_RE='^[[:space:]]*(generated|created|made|written|produced)[[:space:]]+(with|by)[[:space:]]'
# 工具/bot 身份特征串。
readonly IDENTITY_RE='(anthropic\.com|claude\.ai|@cursor\.com|cursoragent|devin-ai-integration|@devin\.ai|\[bot\]@users\.noreply\.github\.com|@openai\.com|copilot@)'
# 身份特征串只在"签名行"上才算违规：形如 `Word: …` 的 trailer 行。
# 不这么限定的话，一条说明署名问题的提交（正文里会引用 cursoragent@cursor.com、
# devin-ai-integration 这些串）会被自己的检查器拦下——这个 bug 真的发生过。
readonly TRAILER_SHAPE_RE='^[[:space:]]*[A-Za-z][A-Za-z0-9-]*:[[:space:]]'

readonly ROBOT_RE='🤖'

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

email_allowed() {
  local email="$1"; shift
  local candidate
  for candidate in "$@"; do
    [ "$email" = "$candidate" ] && return 0
  done
  return 1
}

# 检查提交信息正文。返回非 0 表示存在问题。
check_message() {
  local message="$1" label="$2" failed=0 line

  while IFS= read -r line; do
    [ -n "$line" ] || continue

    if printf '%s' "$line" | grep -qiE "$GENERATED_RE"; then
      red "  ✗ $label: 生成器署名不被允许 -> $line"
      failed=1
    fi

    if printf '%s' "$line" | grep -qiE "$TRAILER_RE"; then
      if ! printf '%s' "$line" | grep -q 'Zypixh'; then
        red "  ✗ $label: 第三方署名 trailer（只允许 Zypixh）-> $line"
        failed=1
      fi
    fi

    if printf '%s' "$line" | grep -qE "$TRAILER_SHAPE_RE" &&
       printf '%s' "$line" | grep -qiE "$IDENTITY_RE"; then
      red "  ✗ $label: 签名行出现工具/bot 身份 -> $line"
      failed=1
    fi

    case "$line" in
      *"$ROBOT_RE"*)
        red "  ✗ $label: 出现机器人标记 -> $line"
        failed=1
        ;;
    esac
  done <<< "$message"

  return $failed
}

# 检查一个提交对象的作者、提交者和信息。
check_commit() {
  local sha="$1" failed=0
  local an ae cn ce subject body short

  an=$(git log -1 --format='%an' "$sha")
  ae=$(git log -1 --format='%ae' "$sha")
  cn=$(git log -1 --format='%cn' "$sha")
  ce=$(git log -1 --format='%ce' "$sha")
  subject=$(git log -1 --format='%s' "$sha")
  body=$(git log -1 --format='%B' "$sha")
  short=$(git rev-parse --short "$sha")

  if ! email_allowed "$ae" "${ALLOWED_AUTHOR_EMAILS[@]}"; then
    red "  ✗ $short: 作者不是本人身份 -> $an <$ae>"
    failed=1
  fi

  if ! email_allowed "$ce" "${ALLOWED_COMMITTER_EMAILS[@]}"; then
    red "  ✗ $short: 提交者不是本人身份 -> $cn <$ce>"
    failed=1
  fi

  if ! check_message "$body" "$short"; then
    failed=1
  fi

  if [ "$failed" -ne 0 ]; then
    red "      $subject"
  fi

  return $failed
}

usage() {
  cat >&2 <<'EOF'
用法:
  check-attribution.sh --message-file <路径>
  check-attribution.sh --range <base>..<head>
EOF
  exit 2
}

main() {
  [ $# -ge 1 ] || usage

  case "$1" in
    --message-file)
      [ $# -eq 2 ] || usage
      local file="$2"
      [ -f "$file" ] || { red "找不到提交信息文件: $file"; exit 2; }
      # 钩子看到的还是待提交的草稿，注释行（以 # 开头）由 git 自己剔除。
      if ! check_message "$(grep -v '^#' "$file")" "commit-msg"; then
        echo >&2
        red "提交被拒绝：提交信息含不被允许的署名。"
        echo "规则见 docs/agents/commit-and-pr-conventions.md" >&2
        echo "确认无误可临时绕过：git commit --no-verify" >&2
        exit 1
      fi
      green "✓ 提交信息署名检查通过"
      ;;

    --range)
      [ $# -eq 2 ] || usage
      local range="$2" rev failed=0 total=0 single=""

      # 新建分支或首次推送时 before 是全 0，范围无法解析，退化为只检查 head。
      # 注意不能用 `rev-parse --verify "$range"` 判定：范围表达式本身不是单个对象。
      if ! git rev-list --max-count=1 "$range" >/dev/null 2>&1; then
        single="${range##*..}"
        if git rev-parse --quiet --verify "$single^{commit}" >/dev/null 2>&1; then
          echo "范围 ${range} 无法解析（首次推送或强制推送），退化为只检查 ${single}。"
        else
          red "范围 $range 无法解析，且 head 也不存在。"
          exit 2
        fi
      fi

      if [ -n "$single" ]; then
        total=1
        check_commit "$single" || failed=1
      else
        while IFS= read -r rev; do
          total=$((total + 1))
          if ! check_commit "$rev"; then
            failed=$((failed + 1))
          fi
        done < <(git rev-list "$range")
      fi

      echo
      if [ "$failed" -ne 0 ]; then
        red "署名检查失败：$total 个提交中有 $failed 个不合规。"
        echo "规则见 docs/agents/commit-and-pr-conventions.md" >&2
        exit 1
      fi
      green "✓ 署名检查通过：$total 个提交全部合规"
      ;;

    *)
      usage
      ;;
  esac
}

main "$@"
