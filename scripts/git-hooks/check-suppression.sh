#!/usr/bin/env bash
#
# 警告屏蔽检查 —— 禁止新增"把警告按下去"的手段。
#
# 规则（完整说明见 docs/agents/warning-and-lint-policy.md）：
#   警告必须消除根因，不得用 #[allow(...)] / cfg_attr(..., allow(...)) /
#   #![allow(...)] / --cap-lints / RUSTFLAGS -A / Cargo [lints] = "allow"
#   之类的方式压下去。
#
# 只检查"新增"的屏蔽，存量 78 处不追溯（见策略文档的"存量债务"一节）。
# 确有必要的例外，在该提交的信息里写：
#   Warning-Suppression-Approved: <理由>
#
# 用法：
#   check-suppression.sh --patch-file <路径> [--message-file <路径>]
#   check-suppression.sh --range <base>..<head>
#
set -euo pipefail

readonly APPROVAL_RE='^[[:space:]]*Warning-Suppression-Approved:[[:space:]]*[^[:space:]]'

# 豁免：vendored / 上游代码。AGENTS.md 硬约束 2 本就禁止修改它们，
# 而要求第三方代码零警告等于要求长期维护一个 fork。这是一个**有意保留的缺口**：
# 真要给 vendored 代码打补丁，走硬约束 2 的审批，不靠这里兜底。
readonly EXEMPT_PATH_RE='^(pingora-main|toa-main|toa-sender|vendor)/'

# 判定逻辑集中在 awk 里，一次遍历完成 —— 逐行 fork grep 在真实 diff 上会慢到超时。
# 输入是 unified diff；输出是 "文件<TAB>违规新增行"。
#
# 只认**语法位置**，不认裸词。这一点是被自己的门禁打回来才改对的：不加约束时，
# 一条说明屏蔽问题的提交（文档表格里的 `#[allow(dead_code)]` 示例、检查器自身的
# awk 源码里出现的 --cap-lints）会被自己拦下。规则与 check-attribution.sh 同源：
# 匹配"形态"，不匹配"提及"。
#
#   - Rust 屏蔽：仅 .rs 文件，且去掉缩进后**行首**就是属性。
#   - 构建配置压制：仅 Cargo.toml / .cargo/config.toml / workflow YAML，
#     且 flag 必须出现在引号内或 `= "allow"` 形式。
#   .md 与 .sh 不参与扫描 —— 文档和检查器自身会大量引用这些符号。
readonly SCAN_AWK='
  /^\+\+\+ / {
    file = $0
    sub(/^\+\+\+ [ab]\//, "", file)
    sub(/[[:space:]]+$/, "", file)
    next
  }
  /^\+/ && !/^\+\+\+/ {
    if (file ~ exempt) next
    line = substr($0, 2)
    trimmed = line
    sub(/^[ \t]+/, "", trimmed)

    # Rust 属性屏蔽：行首即属性
    if (file ~ /[.]rs$/ &&
        (trimmed ~ /^#!?\[allow[(]/ ||
         (trimmed ~ /^#\[cfg_attr[(]/ && trimmed ~ /allow[(]/))) {
      print file "\t" line
      next
    }

    # 构建配置压制：仅限构建配置文件，且必须在值的位置
    if (file ~ /(^|\/)(Cargo[.]toml|config[.]toml)$/ ||
        file ~ /[.]github\/workflows\/.*[.]ya?ml$/) {
      if (line ~ /"[^"]*(--cap-lints|[ \t]-A[ \t])/ ||
          line ~ /=[ \t]*"allow"/) {
        print file "\t" line
      }
    }
  }
'

# 被豁免的路径不参与扫描，所以把豁免前缀直接注入 awk。
scan() {
  awk -v exempt="$EXEMPT_PATH_RE" "$SCAN_AWK"
}

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*" >&2; }

report() {
  local hits="$1" label="$2" file line
  while IFS=$'\t' read -r file line; do
    [ -n "$line" ] || continue
    red "  ✗ $label: 新增屏蔽 -> $line"
    echo "      文件: $file" >&2
  done <<< "$hits"
}

# 检查一段 diff。$1=patch 文本，$2=标签
check_patch() {
  local hits
  [ -n "$1" ] || return 0
  hits=$(printf '%s\n' "$1" | scan)
  [ -n "$hits" ] || return 0
  report "$hits" "$2"
  return 1
}

check_commit() {
  local sha="$1" short message patch

  short=$(git rev-parse --short "$sha")
  message=$(git log -1 --format='%B' "$sha")
  patch=$(git diff-tree --no-commit-id -p -U0 -r "$sha")

  [ -n "$patch" ] || return 0

  if printf '%s' "$message" | grep -qE -e "$APPROVAL_RE"; then
    yellow "  ! $short: 该提交声明了经审批的屏蔽 -> $(printf '%s' "$message" | grep -E -e "$APPROVAL_RE" | head -1 | sed 's/^[[:space:]]*//')"
    return 0
  fi

  if ! check_patch "$patch" "$short"; then
    red "      $(git log -1 --format='%s' "$sha")"
    return 1
  fi
  return 0
}

usage() {
  cat >&2 <<'EOF'
用法:
  check-suppression.sh --range <base>..<head>
  check-suppression.sh --patch-file <路径> [--message-file <路径>]
EOF
  exit 2
}

main() {
  [ $# -ge 1 ] || usage

  case "$1" in
    --patch-file)
      local patch_file="$2" message_file=""
      [ -f "$patch_file" ] || { red "找不到 patch 文件: $patch_file"; exit 2; }
      if [ "${3:-}" = "--message-file" ]; then
        message_file="$4"
      fi
      if [ -n "$message_file" ] && [ -f "$message_file" ] &&
         grep -qE -e "$APPROVAL_RE" "$message_file"; then
        yellow "已声明经审批的屏蔽，跳过检查。"
        exit 0
      fi
      if ! check_patch "$(cat "$patch_file")" "patch"; then
        echo >&2
        red "检查失败：新增了屏蔽警告的手段。"
        echo "先消除根因；确有必要的例外需在提交信息里写明" >&2
        echo "Warning-Suppression-Approved: <理由>" >&2
        echo "规则见 docs/agents/warning-and-lint-policy.md" >&2
        exit 1
      fi
      green "✓ 未新增屏蔽手段"
      ;;

    --range)
      local range="$2" rev failed=0 total=0 single=""

      if ! git rev-list --max-count=1 "$range" >/dev/null 2>&1; then
        single="${range##*..}"
        if git rev-parse --quiet --verify "$single^{commit}" >/dev/null 2>&1; then
          echo "范围 ${range} 无法解析，退化为只检查 ${single}。"
        else
          red "范围 ${range} 无法解析，且 head 也不存在。"
          exit 2
        fi
      fi

      if [ -n "$single" ]; then
        total=1
        check_commit "$single" || failed=1
      else
        # 只看非合并提交：合并提交的 combined diff 无法可靠归因新增行。
        while IFS= read -r rev; do
          total=$((total + 1))
          if ! check_commit "$rev"; then
            failed=$((failed + 1))
          fi
        done < <(git rev-list --no-merges "$range")
      fi

      echo
      if [ "$failed" -ne 0 ]; then
        red "屏蔽检查失败：$total 个提交中有 $failed 个新增了屏蔽。"
        echo "规则见 docs/agents/warning-and-lint-policy.md" >&2
        exit 1
      fi
      green "✓ 屏蔽检查通过：$total 个提交未新增屏蔽手段"
      ;;

    *)
      usage
      ;;
  esac
}

main "$@"
