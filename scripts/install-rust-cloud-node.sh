#!/usr/bin/env bash
set -euo pipefail

# CloudNode Rust installer / CloudNode Rust 安装脚本
#
# Single unified flow / 统一流程:
#   detect existing deployment -> backup -> download release -> stop legacy
#   -> install binary + eBPF object -> install GeoIP (always) -> register
#   service -> start/restart -> verify.
#   检测现有部署 -> 备份 -> 下载 Release -> 停止旧进程 -> 安装二进制和
#   eBPF 对象 -> 安装 GeoIP（默认必装）-> 注册服务 -> 启动/重启 -> 校验。
#
# When no existing cloud-node is found the script performs a fresh install
# and asks for the API connection config (or takes it from flags).
# 未检测到现有 cloud-node 时按全新安装处理，交互式询问 API 连接配置
# （或通过参数传入）。

REPO="${REPO:-Zypixh/cloud-node-rust}"
VERSION="${VERSION:-latest}"
SERVICE_NAME="${SERVICE_NAME:-cloud-node}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/cloud-node-rust-migration}"
INSTALL_DIR="${INSTALL_DIR:-}"
INSTALL_BINARY="${INSTALL_BINARY:-}"
AUTO_START="${AUTO_START:-yes}"
GEOIP_DIR="${GEOIP_DIR:-}"
GEOIP_BASE_URL="${GEOIP_BASE_URL:-}"
ACTION="install"
RESTORE_BACKUP="${RESTORE_BACKUP:-}"
API_ENDPOINTS="${API_ENDPOINTS:-}"
NODE_ID="${NODE_ID:-}"
NODE_SECRET="${NODE_SECRET:-}"
TIMEZONE="${TIMEZONE:-}"
ASSUME_YES=0
DRY_RUN=0
# XDP dataplane is enabled by default (bidirectional: inbound proxy +
# outbound AF_XDP upstream). --no-xdp / ENABLE_XDP=no opts out explicitly.
# When XDP is enabled the dataplane is always bidirectional — there is no
# kernel-outbound mode to select.
ENABLE_XDP="${ENABLE_XDP:-yes}"
XDP_IFACE="${XDP_IFACE:-}"

# Backwards-compatible environment mappings from the previous installer.
case "${START_MODE:-}" in
    always|preserve) AUTO_START="yes" ;;
    never) AUTO_START="no" ;;
esac
case "${MODE:-}" in
    restore) ACTION="restore" ;;
    list-backups) ACTION="list-backups" ;;
esac

usage() {
    cat <<'USAGE'
CloudNode Rust installer / CloudNode Rust 安装脚本

Installs or upgrades cloud-node to a Rust release, or performs a fresh
install when no existing deployment is found.
安装或升级 cloud-node 到 Rust 版本；未检测到现有部署时执行全新安装。

Usage / 用法:
  sudo scripts/install-rust-cloud-node.sh
  sudo scripts/install-rust-cloud-node.sh --restore

Run directly from GitHub / 直接从 GitHub 运行:
  curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --yes --api-endpoint http://127.0.0.1:8001 --node-id your-node-id --secret your-node-secret

Options / 选项:
  --restore              Restore the Go original from a previous backup.
                         从备份恢复 Go 原版。
  --restore-backup DIR   Restore from this backup dir. Default: latest backup.
                         从指定备份目录恢复；默认最近备份。
  --list-backups         List available backup dirs and exit.
                         列出可用备份目录后退出。
  --repo OWNER/REPO      GitHub repo. Default: Zypixh/cloud-node-rust
                         GitHub 仓库；默认 Zypixh/cloud-node-rust。
  --version VERSION      Release tag, for example v1.3.0. Default: latest
                         Release 标签，例如 v1.3.0；默认 latest。
  --service NAME         systemd service name. Default: cloud-node
                         systemd 服务名；默认 cloud-node。
  --install-dir DIR      Runtime working directory. Default: existing runtime
                         dir, /root/cloud-node on fresh installs.
                         运行目录；默认沿用现有目录，全新安装为 /root/cloud-node。
  --install-binary PATH  Installed binary path. Default: INSTALL_DIR/cloud-node-rust
                         二进制安装路径；默认 INSTALL_DIR/cloud-node-rust。
  --backup-root DIR      Backup root. Default: /var/backups/cloud-node-rust-migration
                         备份根目录；默认 /var/backups/cloud-node-rust-migration。
  --geoip-dir DIR        GeoIP target dir. Default: INSTALL_DIR/data
                         GeoIP 目标目录；默认 INSTALL_DIR/data。
  --api-endpoint URL     API RPC endpoint for fresh install. Can be repeated.
                         全新安装的 API RPC 地址；可重复。
  --api-endpoints LIST   Comma-separated API RPC endpoints for fresh install.
                         全新安装的 API RPC 地址列表（逗号分隔）。
  --node-id ID           nodeId for fresh install. / 全新安装的 nodeId。
  --secret SECRET        secret for fresh install. / 全新安装的 secret。
  --timezone TZ          Set system timezone on fresh install, e.g. Asia/Shanghai.
                         全新安装时设置系统时区，例如 Asia/Shanghai。
  --xdp                  Enable the XDP dataplane (default). Bidirectional:
                         inbound proxy + outbound AF_XDP upstream.
                         启用 XDP 数据面（默认）。双向：入向代理 + 出向 AF_XDP 回源。
  --no-xdp               Disable the XDP dataplane explicitly.
                         显式禁用 XDP 数据面。
  --xdp-iface NAME       Bind XDP to interface NAME. Default: auto-detect the
                         default-route interface.
                         XDP 绑定的网卡名；默认自动探测默认路由网卡。
  --no-start             Do not start/restart the service after install.
                         安装后不启动/重启服务。
  --dry-run              Print actions without changing files.
                         只打印动作，不改动文件。
  --yes                  Do not prompt for confirmation.
                         不进行交互确认。
  --non-interactive      Alias for --yes. / 等同 --yes。
  -h, --help             Show this help. / 显示本帮助。

Environment variables with the same names are also supported:
  REPO, VERSION, SERVICE_NAME, INSTALL_DIR, INSTALL_BINARY, BACKUP_ROOT,
  AUTO_START, GEOIP_DIR, GEOIP_BASE_URL, RESTORE_BACKUP, API_ENDPOINTS,
  NODE_ID, NODE_SECRET, TIMEZONE, ENABLE_XDP, XDP_IFACE.
USAGE
}

setup_colors() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        BOLD="$(printf '\033[1m')"
        DIM="$(printf '\033[2m')"
        RED="$(printf '\033[31m')"
        GREEN="$(printf '\033[32m')"
        YELLOW="$(printf '\033[33m')"
        BLUE="$(printf '\033[34m')"
        CYAN="$(printf '\033[36m')"
        RESET="$(printf '\033[0m')"
    else
        BOLD=""
        DIM=""
        RED=""
        GREEN=""
        YELLOW=""
        BLUE=""
        CYAN=""
        RESET=""
    fi
}

setup_colors

setup_prompt_input() {
    if [ -t 0 ]; then
        PROMPT_INPUT="/dev/stdin"
    elif [ -r /dev/tty ] && [ -w /dev/tty ] && { [ -t 1 ] || [ -t 2 ]; }; then
        PROMPT_INPUT="/dev/tty"
    elif [ -t 2 ] && [ -r /dev/fd/2 ]; then
        PROMPT_INPUT="/dev/fd/2"
    elif [ -t 2 ] && [ -r /proc/self/fd/2 ]; then
        PROMPT_INPUT="/proc/self/fd/2"
    else
        PROMPT_INPUT=""
    fi
}

setup_prompt_input

prompt_available() {
    [ -n "$PROMPT_INPUT" ]
}

read_prompt() {
    local __var="$1"
    prompt_available || return 1
    IFS= read -r "$__var" < "$PROMPT_INPUT"
}

read_prompt_secret() {
    local __var="$1"
    local __input=""
    local __char=""
    prompt_available || return 1
    while IFS= read -rsn1 __char <&3; do
        if [ -z "$__char" ]; then
            break
        fi
        # Handle backspace / delete
        if [ "$__char" = $'\x7f' ] || [ "$__char" = $'\x08' ]; then
            if [ -n "$__input" ]; then
                __input="${__input%?}"
                printf '\b \b' >&2
            fi
        else
            __input="${__input}${__char}"
            printf '*' >&2
        fi
    done 3< "$PROMPT_INPUT"
    printf '\n' >&2
    printf -v "$__var" '%s' "$__input"
}

# Bilingual output helpers / 双语输出辅助
# Every user-facing message prints Chinese and English together.
# 所有面向用户的消息同时输出中文和英文。
bi() {
    printf '%s | %s\n' "$1" "$2"
}

title() {
    printf '\n%s%s%s\n' "$BOLD" "CloudNode Rust Installer / 安装脚本" "$RESET"
    printf '%s\n\n' "============================================================"
}

section() {
    printf '\n%s== %s ==%s\n' "$CYAN" "$1" "$RESET"
}

kv() {
    printf '  %s%-22s%s %s\n' "$DIM" "$1" "$RESET" "$2"
}

log() {
    if [ "$#" -ge 2 ]; then
        printf '%s[cloud-node]%s %s | %s\n' "$BLUE" "$RESET" "$1" "$2"
    else
        printf '%s[cloud-node]%s %s\n' "$BLUE" "$RESET" "$1"
    fi
}

ok() {
    if [ "$#" -ge 2 ]; then
        printf '%s[ok]%s %s | %s\n' "$GREEN" "$RESET" "$1" "$2"
    else
        printf '%s[ok]%s %s\n' "$GREEN" "$RESET" "$1"
    fi
}

warn() {
    if [ "$#" -ge 2 ]; then
        printf '%s[warn]%s %s | %s\n' "$YELLOW" "$RESET" "$1" "$2"
    else
        printf '%s[warn]%s %s\n' "$YELLOW" "$RESET" "$1"
    fi
}

die() {
    if [ "$#" -ge 2 ]; then
        printf '%s[error]%s %s | %s\n' "$RED" "$RESET" "$1" "$2" >&2
    else
        printf '%s[error]%s %s\n' "$RED" "$RESET" "$1" >&2
    fi
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1" "缺少必需命令: $1"
}

run() {
    log "+ $*"
    if [ "$DRY_RUN" -eq 0 ]; then
        "$@"
    fi
}

systemctl_available() {
    command -v systemctl >/dev/null 2>&1 || return 1
    systemctl show-environment >/dev/null 2>&1
}

ask_yes_no() {
    local prompt_zh="$1"
    local prompt_en="$2"
    local default_answer="${3:-no}"
    local prompt_suffix=""
    local answer=""

    if [ "$default_answer" = "yes" ]; then
        prompt_suffix="[Y/n]"
    else
        prompt_suffix="[y/N]"
    fi

    printf '%s | %s %s ' "$prompt_zh" "$prompt_en" "$prompt_suffix"
    read_prompt answer || answer=""
    answer="${answer:-$default_answer}"
    case "$answer" in
        y|Y|yes|YES|Yes|是|好|确认)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

prompt_text() {
    local prompt_zh="$1"
    local prompt_en="$2"
    local default_value="${3:-}"
    local secret="${4:-no}"
    local answer=""

    printf '%s | %s' "$prompt_zh" "$prompt_en" >&2
    if [ -n "$default_value" ]; then
        printf ' %s[%s]%s' "$DIM" "$default_value" "$RESET" >&2
    fi
    printf ': ' >&2

    if [ "$secret" = "yes" ] && prompt_available; then
        read_prompt_secret answer || answer=""
    else
        read_prompt answer || answer=""
    fi
    printf '%s\n' "${answer:-$default_value}"
}

yaml_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '"%s"' "$value"
}

trim_spaces() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

detect_system_timezone() {
    local timezone=""
    if command -v timedatectl >/dev/null 2>&1; then
        timezone="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
        timezone="$(trim_spaces "$timezone")"
        if [ -n "$timezone" ]; then
            printf '%s\n' "$timezone"
            return
        fi
    fi
    if [ -r /etc/timezone ]; then
        timezone="$(trim_spaces "$(head -n 1 /etc/timezone 2>/dev/null || true)")"
        if [ -n "$timezone" ]; then
            printf '%s\n' "$timezone"
            return
        fi
    fi
    if [ -L /etc/localtime ]; then
        timezone="$(readlink /etc/localtime 2>/dev/null || true)"
        timezone="${timezone#/usr/share/zoneinfo/}"
        timezone="$(trim_spaces "$timezone")"
        if [ -n "$timezone" ] && [ "$timezone" != "/etc/localtime" ]; then
            printf '%s\n' "$timezone"
        fi
    fi
}

validate_timezone_name() {
    local timezone="$1"
    case "$timezone" in
        ""|/*|*..*|*\\*|*" "*|*$'\t'*|*$'\n'*)
            return 1
            ;;
    esac
    [ -f "/usr/share/zoneinfo/$timezone" ]
}

apply_timezone() {
    local zoneinfo=""
    [ -n "$TIMEZONE" ] || return 0

    zoneinfo="/usr/share/zoneinfo/$TIMEZONE"
    validate_timezone_name "$TIMEZONE" || die "invalid timezone or missing zoneinfo file: $TIMEZONE" "时区无效或缺少 zoneinfo 文件: $TIMEZONE"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "+ timedatectl set-timezone $TIMEZONE || ln -sfn $zoneinfo /etc/localtime"
        log "+ write /etc/timezone"
        return
    fi

    if command -v timedatectl >/dev/null 2>&1 && timedatectl set-timezone "$TIMEZONE"; then
        ok "system timezone set to $TIMEZONE" "系统时区已设置为 $TIMEZONE"
        return
    fi

    ln -sfn "$zoneinfo" /etc/localtime
    printf '%s\n' "$TIMEZONE" > /etc/timezone
    ok "system timezone set to $TIMEZONE" "系统时区已设置为 $TIMEZONE"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --restore)
            ACTION="restore"
            shift
            ;;
        --restore-backup)
            RESTORE_BACKUP="${2:?missing restore backup dir}"
            ACTION="restore"
            shift 2
            ;;
        --list-backups)
            ACTION="list-backups"
            shift
            ;;
        --repo)
            REPO="${2:?missing repo}"
            shift 2
            ;;
        --version)
            VERSION="${2:?missing version}"
            shift 2
            ;;
        --service)
            SERVICE_NAME="${2:?missing service name}"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="${2:?missing install dir}"
            shift 2
            ;;
        --install-binary)
            INSTALL_BINARY="${2:?missing install binary}"
            shift 2
            ;;
        --backup-root)
            BACKUP_ROOT="${2:?missing backup root}"
            shift 2
            ;;
        --geoip-dir)
            GEOIP_DIR="${2:?missing geoip dir}"
            shift 2
            ;;
        --api-endpoint)
            if [ -n "$API_ENDPOINTS" ]; then
                API_ENDPOINTS="${API_ENDPOINTS},${2:?missing api endpoint}"
            else
                API_ENDPOINTS="${2:?missing api endpoint}"
            fi
            shift 2
            ;;
        --api-endpoints)
            API_ENDPOINTS="${2:?missing api endpoints}"
            shift 2
            ;;
        --node-id)
            NODE_ID="${2:?missing node id}"
            shift 2
            ;;
        --secret)
            NODE_SECRET="${2:?missing secret}"
            shift 2
            ;;
        --timezone)
            TIMEZONE="${2:?missing timezone}"
            shift 2
            ;;
        --xdp)
            ENABLE_XDP="yes"
            shift
            ;;
        --no-xdp)
            ENABLE_XDP="no"
            shift
            ;;
        --xdp-iface)
            XDP_IFACE="${2:?missing interface name}"
            shift 2
            ;;
        --xdp-upstream)
            die "--xdp-upstream was removed: enabled XDP is always bidirectional (AF_XDP upstream); disable XDP entirely with --no-xdp" \
                "--xdp-upstream 已移除：启用的 XDP 固定为双向（AF_XDP 出向）；如需关闭请使用 --no-xdp"
            ;;
        --no-start)
            AUTO_START="no"
            shift
            ;;
        --start)
            AUTO_START="yes"
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --yes|--non-interactive)
            ASSUME_YES=1
            shift
            ;;
        # Accepted for backwards compatibility with older one-line commands;
        # GeoIP is now always installed and modes are unified.
        --geoip|--fresh|--new|--install|--upgrade|--allow-fresh|--no-timezone)
            shift
            ;;
        --no-geoip)
            warn "--no-geoip is ignored: GeoIP databases are always installed" "--no-geoip 已忽略：GeoIP 数据库为默认必装"
            shift
            ;;
        --lang)
            # Output is always bilingual; the flag is consumed silently.
            if [ "$#" -ge 2 ]; then
                shift 2
            else
                shift
            fi
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1" "未知参数: $1"
            ;;
    esac
done

title

if [ "$ACTION" != "list-backups" ]; then
    [ "$(uname -s)" = "Linux" ] || [ "$DRY_RUN" -eq 1 ] || die "this installer supports Linux only" "本安装脚本仅支持 Linux"
fi

need_cmd mktemp
need_cmd date
need_cmd cp
need_cmd mkdir
need_cmd install
need_cmd uname
if [ "$ACTION" = "install" ]; then
    need_cmd curl
    need_cmd tar
fi

if [ "$ACTION" != "list-backups" ] && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "root is required; run with sudo" "需要 root 权限；请使用 sudo 运行"
fi

service_cat() {
    if systemctl_available; then
        systemctl cat "$SERVICE_NAME" 2>/dev/null || true
    fi
}

systemd_value() {
    local key="$1"
    service_cat | sed -n "s/^[[:space:]]*${key}=//p" | tail -n 1
}

first_exec_token() {
    local line="$1"
    line="${line#-}"
    line="${line#+}"
    line="${line#!}"
    line="${line#@}"
    printf '%s\n' "$line" | awk '{print $1}'
}

find_existing_cloud_node() {
    local cmd_path=""
    local exec_line=""
    local exec_path=""

    exec_line="$(systemd_value ExecStart)"
    if [ -n "$exec_line" ]; then
        exec_path="$(first_exec_token "$exec_line")"
        if [ -n "$exec_path" ] && [ -e "$exec_path" ]; then
            printf '%s\n' "$exec_path"
            return
        fi
    fi

    if command -v cloud-node >/dev/null 2>&1; then
        cmd_path="$(command -v cloud-node)"
        if [ -n "$cmd_path" ]; then
            printf '%s\n' "$cmd_path"
            return
        fi
    fi

    for candidate in \
        /usr/bin/cloud-node \
        /usr/local/bin/cloud-node \
        /usr/sbin/cloud-node \
        /opt/cloud-node/cloud-node \
        /opt/cloud-node/bin/cloud-node
    do
        if [ -e "$candidate" ]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
}

resolve_wrapper_binary() {
    local path="$1"
    local line=""
    local token=""
    local candidate=""
    [ -r "$path" ] || return 0
    if ! head -c 2 "$path" 2>/dev/null | grep -q '^#!'; then
        return 0
    fi
    while IFS= read -r line; do
        line="$(trim_spaces "$line")"
        case "$line" in
            ''|\#*)
                continue
                ;;
            cd\ *|export\ *|set\ *|umask\ *|ulimit\ *)
                continue
                ;;
        esac
        line="${line%%&&*}"
        line="${line%%;*}"
        line="$(trim_spaces "$line")"
        token="$(printf '%s\n' "$line" | awk '{print $1}')"
        token="${token%\"}"
        token="${token#\"}"
        token="${token%\'}"
        token="${token#\'}"
        case "$token" in
            ''|exec|sudo|env|nice|nohup|bash|sh|dash|zsh)
                continue
                ;;
        esac
        if [ -x "$token" ] || [ -f "$token" ]; then
            candidate="$token"
            break
        fi
        if command -v "$token" >/dev/null 2>&1; then
            candidate="$(command -v "$token")"
            break
        fi
    done < "$path"
    [ -n "$candidate" ] || return 0
    printf '%s\n' "$candidate"
}

detect_runtime() {
    local path="$1"
    local probe_path="$path"
    local wrapper_target=""
    if [ ! -f "$path" ]; then
        printf 'non-regular-file\n'
        return
    fi
    wrapper_target="$(resolve_wrapper_binary "$path" || true)"
    if [ -n "$wrapper_target" ] && [ -f "$wrapper_target" ]; then
        probe_path="$wrapper_target"
    fi
    if command -v strings >/dev/null 2>&1 && strings "$probe_path" 2>/dev/null | grep -q 'Go buildinf:'; then
        printf 'go\n'
    elif command -v strings >/dev/null 2>&1 && strings "$probe_path" 2>/dev/null | grep -qE 'cloud-node-rust|rustc version'; then
        printf 'rust\n'
    else
        printf 'unknown\n'
    fi
}

is_cloud_node_path() {
    local path="$1"
    case "$path" in
        */cloud-node|*/cloud-node-rust|/usr/bin/cloud-node|/usr/local/bin/cloud-node|/usr/sbin/cloud-node)
            return 0
            ;;
    esac
    return 1
}

unique_lines() {
    awk 'NF && !seen[$0]++'
}

read_lines_into() {
    local __arr_name="$1"
    local __line=""
    eval "$__arr_name=()"
    while IFS= read -r __line; do
        eval "$__arr_name+=(\"\$__line\")"
    done
}

discover_legacy_units() {
    local unit=""
    local unit_file=""
    local exec_line=""
    local exec_path=""
    local units=()

    if ! systemctl_available; then
        return 0
    fi

    units+=("${SERVICE_NAME}.service")
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        units+=("$unit")
    done < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null \
        | awk '{print $1}' \
        | grep -E '^(cloud-node|edge-node|flexcdn|goedge)(-rust)?\.service$' || true)

    for unit_file in \
        /etc/systemd/system/*.service \
        /lib/systemd/system/*.service \
        /usr/lib/systemd/system/*.service
    do
        [ -e "$unit_file" ] || continue
        unit="$(basename "$unit_file")"
        case "$unit" in
            cloud-node*.service|edge-node*.service|flexcdn*.service|goedge*.service)
                units+=("$unit")
                ;;
        esac
    done

    for unit in "${units[@]}"; do
        unit="${unit%.service}.service"
        exec_line="$(systemctl show -p ExecStart --value "$unit" 2>/dev/null || true)"
        if [ -z "$exec_line" ]; then
            if [ -f "/etc/systemd/system/$unit" ]; then
                exec_line="$(sed -n 's/^[[:space:]]*ExecStart=//p' "/etc/systemd/system/$unit" | tail -n 1)"
            elif [ -f "/lib/systemd/system/$unit" ]; then
                exec_line="$(sed -n 's/^[[:space:]]*ExecStart=//p' "/lib/systemd/system/$unit" | tail -n 1)"
            elif [ -f "/usr/lib/systemd/system/$unit" ]; then
                exec_line="$(sed -n 's/^[[:space:]]*ExecStart=//p' "/usr/lib/systemd/system/$unit" | tail -n 1)"
            fi
        fi
        exec_path="$(first_exec_token "$exec_line")"
        if [ "$unit" = "${SERVICE_NAME}.service" ] \
            || is_cloud_node_path "$exec_path" \
            || { [ -n "$EXISTING_BINARY" ] && [ "$exec_path" = "$EXISTING_BINARY" ]; }; then
            printf '%s\n' "$unit"
        fi
    done | unique_lines
}

discover_legacy_pids() {
    local path=""
    local workdir=""
    local pid_file=""
    local pid=""
    local candidates=()

    [ -n "${EXISTING_BINARY:-}" ] && candidates+=("$EXISTING_BINARY")
    [ -n "${EXISTING_BINARY_WORKDIR:-}" ] && candidates+=("$EXISTING_BINARY_WORKDIR/cloud-node" "$EXISTING_BINARY_WORKDIR/cloud-node-rust")
    [ -n "${EXISTING_RUNTIME_DIR:-}" ] && candidates+=("$EXISTING_RUNTIME_DIR/cloud-node" "$EXISTING_RUNTIME_DIR/cloud-node-rust")
    candidates+=(
        /usr/bin/cloud-node
        /usr/local/bin/cloud-node
        /usr/sbin/cloud-node
        /root/cloud-node/cloud-node
        /root/cloud-node/cloud-node-rust
        /opt/cloud-node/cloud-node
        /opt/cloud-node/bin/cloud-node
        /opt/cloud-node-rust/cloud-node-rust
    )

    for path in "${candidates[@]}"; do
        [ -n "$path" ] || continue
        [ -e "$path" ] || continue
        if command -v pgrep >/dev/null 2>&1; then
            while IFS= read -r pid; do
                [ -n "$pid" ] || continue
                printf '%s\n' "$pid"
            done < <(pgrep -f "(^|[ /])$(printf '%s' "$path" | sed 's/[.[\*^$()+?{|]/\\&/g')( |$)" 2>/dev/null || true)
        fi
    done

    for workdir in "$EXISTING_RUNTIME_DIR" "$EXISTING_BINARY_WORKDIR" "$INSTALL_DIR" /root/cloud-node /opt/cloud-node /opt/cloud-node-rust; do
        [ -n "$workdir" ] || continue
        for pid_file in \
            "$workdir/data/cloud-node.pid" \
            "$workdir/data/node.pid" \
            "$workdir/cloud-node.pid" \
            "$workdir/bin/cloud-node.pid"
        do
            [ -f "$pid_file" ] || continue
            pid="$(trim_spaces "$(head -n 1 "$pid_file" 2>/dev/null || true)")"
            case "$pid" in
                ''|*[!0-9]*)
                    continue
                    ;;
            esac
            if [ -d "/proc/$pid" ]; then
                printf '%s\n' "$pid"
            fi
        done
    done | unique_lines
}

wait_for_pids_exit() {
    local timeout_secs="${1:-15}"
    local pid=""
    local remaining="$timeout_secs"
    shift || true
    [ "$#" -gt 0 ] || return 0
    while [ "$remaining" -gt 0 ]; do
        local alive=0
        for pid in "$@"; do
            [ -n "$pid" ] || continue
            if [ -d "/proc/$pid" ]; then
                alive=1
                break
            fi
        done
        [ "$alive" -eq 0 ] && return 0
        sleep 1
        remaining=$((remaining - 1))
    done
    return 1
}

signal_pids() {
    local signal="$1"
    shift || true
    local pid=""
    for pid in "$@"; do
        [ -n "$pid" ] || continue
        if [ -d "/proc/$pid" ]; then
            run kill "-$signal" "$pid" || true
        fi
    done
}

legacy_ports_still_held() {
    local ports=("80" "443")
    local port=""
    local holders=""
    if ! command -v ss >/dev/null 2>&1; then
        return 1
    fi
    for port in "${ports[@]}"; do
        holders="$(ss -ltnup "sport = :$port" 2>/dev/null | grep -E 'cloud-node|cloud_node' || true)"
        if [ -n "$holders" ]; then
            return 0
        fi
    done
    return 1
}

wait_for_ports_release() {
    local timeout_secs="${1:-15}"
    local remaining="$timeout_secs"
    while [ "$remaining" -gt 0 ]; do
        if ! legacy_ports_still_held; then
            return 0
        fi
        sleep 1
        remaining=$((remaining - 1))
    done
    return 1
}

stop_legacy_deployment() {
    local units=()
    local active_units=()
    local pids=()
    local unit=""
    local binary_stop_ok=0

    read_lines_into units < <(discover_legacy_units || true)
    read_lines_into pids < <(discover_legacy_pids || true)

    if systemctl_available; then
        for unit in "${units[@]}"; do
            [ -n "$unit" ] || continue
            if systemctl is-active --quiet "$unit" 2>/dev/null; then
                active_units+=("$unit")
            fi
        done
    fi

    if [ "${#active_units[@]}" -eq 0 ] && [ "${#pids[@]}" -eq 0 ]; then
        log "no running legacy cloud-node process detected" "未检测到运行中的旧 cloud-node 进程"
        return 0
    fi

    LEGACY_WAS_RUNNING=1

    section "停止旧节点 / Stop Legacy Node"
    if [ "${#active_units[@]}" -gt 0 ]; then
        kv "legacy units" "${active_units[*]}"
    fi
    if [ "${#pids[@]}" -gt 0 ]; then
        kv "legacy pids" "${pids[*]}"
    fi

    if [ -n "${EXISTING_BINARY:-}" ] && [ -x "$EXISTING_BINARY" ]; then
        if [ "$DRY_RUN" -eq 0 ]; then
            log "trying legacy stop command: $EXISTING_BINARY stop"
            if command -v timeout >/dev/null 2>&1; then
                if timeout 15s "$EXISTING_BINARY" stop >/dev/null 2>&1; then
                    binary_stop_ok=1
                    ok "legacy binary stop succeeded" "旧二进制 stop 成功"
                else
                    warn "legacy binary stop failed or timed out; continuing with systemd/process stop" "旧二进制 stop 失败或超时；继续用 systemd/进程方式停止"
                fi
            elif "$EXISTING_BINARY" stop >/dev/null 2>&1; then
                binary_stop_ok=1
                ok "legacy binary stop succeeded" "旧二进制 stop 成功"
            else
                warn "legacy binary stop failed; continuing with systemd/process stop" "旧二进制 stop 失败；继续用 systemd/进程方式停止"
            fi
        else
            log "+ $EXISTING_BINARY stop"
        fi
    fi

    if systemctl_available; then
        for unit in "${active_units[@]}"; do
            [ -n "$unit" ] || continue
            run systemctl stop "$unit" || warn "failed to stop $unit" "停止 $unit 失败"
        done
    fi

    read_lines_into pids < <(discover_legacy_pids || true)
    if [ "${#pids[@]}" -gt 0 ]; then
        signal_pids TERM "${pids[@]}"
        if [ "$DRY_RUN" -eq 0 ]; then
            wait_for_pids_exit 10 "${pids[@]}" || true
            read_lines_into pids < <(discover_legacy_pids || true)
            if [ "${#pids[@]}" -gt 0 ]; then
                warn "forcing kill of remaining legacy pids: ${pids[*]}" "强制结束剩余旧进程: ${pids[*]}"
                signal_pids KILL "${pids[@]}"
                wait_for_pids_exit 5 "${pids[@]}" || true
            fi
        fi
    fi

    if [ "$DRY_RUN" -eq 0 ]; then
        if ! wait_for_ports_release 15; then
            die "legacy cloud-node still holds ports 80/443 after stop; aborting before overwrite. Restore with: $0 --restore --restore-backup $BACKUP_DIR" \
                "旧 cloud-node 停止后仍占用 80/443 端口；覆盖前中止。可用以下命令恢复: $0 --restore --restore-backup $BACKUP_DIR"
        fi
        ok "legacy cloud-node stopped" "旧 cloud-node 已停止"
    fi
}

unregister_legacy_services() {
    local units=()
    local unit=""
    local unit_file=""
    local dropin_dir=""
    local backed_up=0
    local dest=""

    read_lines_into units < <(discover_legacy_units || true)
    [ "${#units[@]}" -gt 0 ] || return 0

    section "注销旧服务 / Unregister Legacy Services"
    for unit in "${units[@]}"; do
        [ -n "$unit" ] || continue
        if systemctl_available; then
            if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
                run systemctl disable "$unit" || warn "failed to disable $unit" "禁用 $unit 失败"
            fi
        fi

        for unit_file in \
            "/etc/systemd/system/$unit" \
            "/lib/systemd/system/$unit" \
            "/usr/lib/systemd/system/$unit"
        do
            [ -e "$unit_file" ] || continue
            backed_up=1
            dest="$BACKUP_DIR/legacy-units$unit_file"
            run mkdir -p "$(dirname "$dest")"
            run cp -a "$unit_file" "$dest"
            # Only remove admin-managed units under /etc; leave vendor units in /lib.
            case "$unit_file" in
                /etc/systemd/system/*)
                    run rm -f "$unit_file"
                    ;;
            esac
        done

        dropin_dir="/etc/systemd/system/${unit}.d"
        if [ -d "$dropin_dir" ]; then
            backed_up=1
            dest="$BACKUP_DIR/legacy-units$dropin_dir"
            run mkdir -p "$(dirname "$dest")"
            run cp -a "$dropin_dir" "$dest"
            run rm -rf "$dropin_dir"
        fi
    done

    if systemctl_available; then
        run systemctl daemon-reload || true
        run systemctl reset-failed || true
    fi
    if [ "$backed_up" -eq 1 ]; then
        ok "legacy service registration removed (backed up under $BACKUP_DIR/legacy-units)" "旧服务注册已移除（已备份到 $BACKUP_DIR/legacy-units）"
    fi
}

validate_rust_service_registration() {
    local exec_line=""
    local exec_path=""
    local wrapper=""

    if [ ! -x "$INSTALL_BINARY" ]; then
        die "installed binary is missing or not executable: $INSTALL_BINARY" "已安装二进制缺失或不可执行: $INSTALL_BINARY"
    fi

    wrapper="/usr/bin/cloud-node"
    if [ ! -e "$wrapper" ]; then
        die "global cloud-node command was not registered at $wrapper" "全局 cloud-node 命令未注册到 $wrapper"
    fi

    if systemctl_available; then
        if ! systemctl cat "${SERVICE_NAME}.service" >/dev/null 2>&1; then
            die "systemd service ${SERVICE_NAME}.service was not registered" "systemd 服务 ${SERVICE_NAME}.service 未注册"
        fi
        exec_line="$(systemctl show -p ExecStart --value "${SERVICE_NAME}.service" 2>/dev/null || true)"
        exec_path="$(first_exec_token "$exec_line")"
        if [ -z "$exec_path" ]; then
            die "systemd service ${SERVICE_NAME}.service has empty ExecStart" "systemd 服务 ${SERVICE_NAME}.service 的 ExecStart 为空"
        fi
        if [ "$exec_path" != "$INSTALL_BINARY" ] && [ "$exec_path" != "$wrapper" ]; then
            # Accept either direct binary or wrapper that ultimately points at INSTALL_BINARY.
            local resolved=""
            resolved="$(resolve_wrapper_binary "$exec_path" || true)"
            if [ "$resolved" != "$INSTALL_BINARY" ] && [ "$exec_path" != "$INSTALL_BINARY" ]; then
                warn "ExecStart=$exec_path does not match $INSTALL_BINARY; continuing because install completed" "ExecStart=$exec_path 与 $INSTALL_BINARY 不一致；安装已完成故继续"
            fi
        fi
    fi
    ok "service registration validated" "服务注册校验通过"
}

verify_service_started() {
    local timeout_secs="${1:-20}"
    local remaining="$timeout_secs"
    local active=0

    if [ "$DRY_RUN" -eq 1 ]; then
        log "+ verify ${SERVICE_NAME} is active"
        return 0
    fi

    if systemctl_available; then
        while [ "$remaining" -gt 0 ]; do
            if systemctl is-active --quiet "$SERVICE_NAME"; then
                active=1
                break
            fi
            sleep 1
            remaining=$((remaining - 1))
        done
        if [ "$active" -ne 1 ]; then
            warn "service ${SERVICE_NAME} did not become active within ${timeout_secs}s" "服务 ${SERVICE_NAME} 在 ${timeout_secs}s 内未进入 active 状态"
            if command -v journalctl >/dev/null 2>&1; then
                journalctl -u "$SERVICE_NAME" -n 30 --no-pager || true
            fi
            die "start verification failed; restore with: $0 --restore --restore-backup $BACKUP_DIR" "启动校验失败；可用以下命令恢复: $0 --restore --restore-backup $BACKUP_DIR"
        fi
        ok "service ${SERVICE_NAME} is active" "服务 ${SERVICE_NAME} 已运行"
        return 0
    fi

    if [ -x "$INSTALL_BINARY" ]; then
        if (cd "$INSTALL_DIR" && "$INSTALL_BINARY" status >/dev/null 2>&1); then
            ok "cloud-node status reports running" "cloud-node status 显示运行中"
            return 0
        fi
        die "cloud-node status check failed; restore with: $0 --restore --restore-backup $BACKUP_DIR" "cloud-node status 检查失败；可用以下命令恢复: $0 --restore --restore-backup $BACKUP_DIR"
    fi
}

sha256_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{print $1}'
    else
        printf 'unavailable'
    fi
}

human_bytes() {
    awk -v b="${1:-0}" 'BEGIN {
        split("B KiB MiB GiB", u, " ");
        i = 1;
        while (b >= 1024 && i < 4) { b /= 1024; i++ }
        printf "%.1f%s", b, u[i]
    }'
}

tty_progress() {
    [ "$DRY_RUN" -eq 0 ] && [ -t 2 ] && [ -z "${NO_PROGRESS:-}" ]
}

spinner_frame() {
    local idx="$1"
    local frames=""
    case "${LANG:-}${LC_ALL:-}${LC_CTYPE:-}" in
        *UTF-8*|*utf-8*|*utf8*|*UTF8*)
            frames="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            ;;
        *)
            frames="|/-\\"
            ;;
    esac
    # Braille frames are multibyte; index by character, not byte.
    printf '%s' "$frames" | cut -c "$((idx % 10 + 1))"
}

draw_progress() {
    local have="${1:-0}"
    local total="${2:-0}"
    local spin_idx="${3:-0}"
    local started="${4:-$(date +%s)}"
    case "$have" in ''|*[!0-9]*) have=0 ;; esac
    case "$total" in ''|*[!0-9]*) total=0 ;; esac
    local spin=""
    local bar=""
    local line=""
    local elapsed=0
    local rate=""

    spin="$(spinner_frame "$spin_idx")"
    elapsed=$(( $(date +%s) - started ))
    if [ "$elapsed" -gt 0 ] && [ "$have" -gt 0 ]; then
        rate="$(human_bytes "$((have / elapsed))")/s"
    fi

    if [ "$total" -gt 0 ] 2>/dev/null; then
        local pct=$((have * 100 / total))
        [ "$pct" -gt 100 ] && pct=100
        local width=26
        local filled=$((pct * width / 100))
        local i=0
        bar="["
        while [ "$i" -lt "$width" ]; do
            if [ "$i" -lt "$filled" ]; then
                bar="${bar}="
            elif [ "$i" -eq "$filled" ] && [ "$pct" -lt 100 ]; then
                bar="${bar}>"
            else
                bar="${bar} "
            fi
            i=$((i + 1))
        done
        bar="${bar}]"
        line=$(printf '%s %s %3d%% %s/%s %s' \
            "$spin" "$bar" "$pct" \
            "$(human_bytes "$have")" "$(human_bytes "$total")" "$rate")
    else
        line=$(printf '%s %s %s' "$spin" "$(human_bytes "$have")" "$rate")
    fi
    printf '\r%s%-78.78s%s' "$CYAN" "$line" "$RESET" >&2
}

download_with_progress() {
    local url="$1"
    local dest="$2"
    local label="${3:-$(basename "$url")}"

    if ! tty_progress; then
        log "downloading: $url"
        curl -fL --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 20 -C - -o "$dest" "$url"
        return $?
    fi

    local total=""
    total="$(curl -fsIL --connect-timeout 10 "$url" 2>/dev/null \
        | sed -n 's/^[Cc]ontent-[Ll]ength:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
        | tail -n 1 || true)"
    total="${total:-0}"

    printf '%s[cloud-node]%s %s\n' "$BLUE" "$RESET" "$label" >&2
    curl -fL --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 20 -C - -o "$dest" "$url" &
    local curl_pid=$!
    local started
    started="$(date +%s)"
    local spin_idx=0
    local have=0

    while kill -0 "$curl_pid" 2>/dev/null; do
        # $dest does not exist until curl's first write — tolerate that
        # window instead of letting the failed read trip `set -e`.
        have=0
        if [ -f "$dest" ]; then
            have="$(wc -c < "$dest" | tr -d '[:space:]')"
        fi
        draw_progress "$have" "$total" "$spin_idx" "$started"
        spin_idx=$((spin_idx + 1))
        sleep 0.12
    done

    local rc=0
    wait "$curl_pid" || rc=$?
    have=0
    if [ -f "$dest" ]; then
        have="$(wc -c < "$dest" | tr -d '[:space:]')"
    fi
    if [ "$rc" -eq 0 ]; then
        draw_progress "$have" "$total" "$spin_idx" "$started"
        printf '\r%80s\r' "" >&2
        ok "downloaded $label ($(human_bytes "$have"))" "已下载 $label ($(human_bytes "$have"))"
    else
        printf '\n' >&2
    fi
    return "$rc"
}

# Retries a download across whole-invocation attempts. `-C -` resume in
# download_with_progress makes each attempt continue from partial bytes,
# so transient resets (CURLE_SEND_ERROR etc.) do not strand the install.
download_checked() {
    local url="$1"
    local dest="$2"
    local label="$3"
    local attempts="${4:-4}"
    local attempt=0
    until download_with_progress "$url" "$dest" "$label"; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge "$attempts" ]; then
            die "download failed after $attempts attempts: $label" "下载失败（已尝试 $attempts 次）: $label"
        fi
        warn "download of $label failed; retrying ($attempt/$attempts)" "$label 下载失败；重试 ($attempt/$attempts)"
        sleep 2
    done
}

sanitize_path() {
    printf '%s' "$1" | sed 's#/#_#g; s#^_##'
}

script_cd_workdir() {
    local path="$1"
    local line=""
    local dir=""
    [ -r "$path" ] || return 0
    line="$(sed -n 's/^[[:space:]]*cd[[:space:]]\{1,\}\(.*\)$/\1/p' "$path" 2>/dev/null | head -n 1)"
    [ -n "$line" ] || return 0
    line="${line%%&&*}"
    line="${line%%;*}"
    line="$(trim_spaces "$line")"
    line="${line%\"}"
    line="${line#\"}"
    line="${line%\'}"
    line="${line#\'}"
    [ -d "$line" ] || return 0
    dir="$(cd "$line" 2>/dev/null && pwd -P)" || return 0
    printf '%s\n' "$dir"
}

existing_binary_workdir() {
    local path="$1"
    local dir=""
    [ -n "$path" ] || return 0

    dir="$(script_cd_workdir "$path")"
    if [ -n "$dir" ]; then
        printf '%s\n' "$dir"
        return
    fi

    case "$path" in
        /usr/bin/cloud-node|/usr/local/bin/cloud-node|/usr/sbin/cloud-node)
            return 0
            ;;
    esac

    if [ -f "$path" ]; then
        dir="$(dirname "$path")"
        if [ -d "$dir" ]; then
            (cd "$dir" 2>/dev/null && pwd -P) || true
        fi
    fi
}

first_existing_runtime_dir() {
    local dir=""
    for dir in "$@"; do
        [ -n "$dir" ] || continue
        [ "$dir" != "/" ] || continue
        if [ -e "$dir/configs/api_node.yaml" ] \
            || [ -e "$dir/api_node.yaml" ] \
            || [ -e "$dir/cloud-node-rust" ] \
            || [ -e "$dir/cloud-node" ]; then
            printf '%s\n' "$dir"
            return
        fi
    done
}

find_existing_api_config() {
    local dir=""
    for dir in "$@"; do
        [ -n "$dir" ] || continue
        if [ -e "$dir/configs/api_node.yaml" ] || [ -e "$dir/api_node.yaml" ]; then
            printf '%s\n' "$dir"
            return
        fi
    done
}

existing_api_config_path() {
    [ -n "$EXISTING_API_CONFIG_DIR" ] || return 1
    if [ -e "$EXISTING_API_CONFIG_DIR/configs/api_node.yaml" ]; then
        printf '%s\n' "$EXISTING_API_CONFIG_DIR/configs/api_node.yaml"
    elif [ -e "$EXISTING_API_CONFIG_DIR/api_node.yaml" ]; then
        printf '%s\n' "$EXISTING_API_CONFIG_DIR/api_node.yaml"
    else
        return 1
    fi
}

# configs/api_node.yaml is the ONLY node config file — it carries both API
# credentials and the xdp: dataplane section. Older installs may still have
# configs/runtime.yaml / runtime.yml (and top-level variants); the runtime
# no longer reads them, so they are migrated (xdp: block only) and deleted.

# Prints every legacy runtime config file still on disk, one per line.
legacy_runtime_config_files() {
    local dir=""
    local seen=" "
    for dir in \
        "$INSTALL_DIR" \
        "$EXISTING_API_CONFIG_DIR" \
        "$EXISTING_RUNTIME_DIR" \
        "$EXISTING_BINARY_WORKDIR"; do
        [ -n "$dir" ] || continue
        case "$seen" in *" $dir "*) continue ;; esac
        seen="$seen$dir "
        for f in "$dir/configs/runtime.yaml" "$dir/configs/runtime.yml" \
                 "$dir/runtime.yaml" "$dir/runtime.yml"; do
            [ -e "$f" ] && printf '%s\n' "$f"
        done
    done
}

# Any config that already defines xdp: stays authoritative — api_node.yaml
# first, then any legacy runtime.yaml/yml whose xdp: block will be moved
# into api_node.yaml by migrate_legacy_runtime_xdp.
existing_config_has_xdp() {
    local cfg=""
    cfg="$(existing_api_config_path || true)"
    if [ -n "$cfg" ] && grep -q '^xdp:' "$cfg" 2>/dev/null; then
        return 0
    fi
    while IFS= read -r cfg; do
        [ -n "$cfg" ] || continue
        if grep -q '^xdp:' "$cfg" 2>/dev/null; then
            return 0
        fi
    done < <(legacy_runtime_config_files)
    return 1
}

glibc_is_older_than_228() {
    local version=""
    local major=""
    local minor=""
    if ! command -v ldd >/dev/null 2>&1; then
        return 1
    fi
    version="$(ldd --version 2>/dev/null | head -n 1 | sed -E 's/.* ([0-9]+)\.([0-9]+).*/\1 \2/')"
    major="$(printf '%s\n' "$version" | awk '{print $1}')"
    minor="$(printf '%s\n' "$version" | awk '{print $2}')"
    case "$major:$minor" in
        ''|*[!0-9:]*)
            return 1
            ;;
    esac
    [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 28 ]; }
}

cpu_has_flag() {
    local flag="$1"
    [ -r /proc/cpuinfo ] && grep -qw "$flag" /proc/cpuinfo
}

detect_asset_name() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            if glibc_is_older_than_228; then
                die "x86_64 systems with glibc older than 2.28 are not supported by official release assets" "glibc 低于 2.28 的 x86_64 系统不受官方 Release 包支持"
            elif ! cpu_has_flag sse4_2; then
                die "x86_64 CPU without SSE4.2 is not supported by official release assets" "不支持 SSE4.2 的 x86_64 CPU 不受官方 Release 包支持"
            elif cpu_has_flag avx512f; then
                printf 'cloud-node-rust-linux-x64-v4-avx512.tar.gz\n'
            elif cpu_has_flag avx2; then
                printf 'cloud-node-rust-linux-x64-v3-avx2.tar.gz\n'
            else
                printf 'cloud-node-rust-linux-x64-v2-sse4.2.tar.gz\n'
            fi
            ;;
        aarch64|arm64)
            if [ -r /proc/cpuinfo ] && grep -qi 'neoverse-n1' /proc/cpuinfo; then
                printf 'cloud-node-rust-linux-arm64-neoverse-n1.tar.gz\n'
            else
                printf 'cloud-node-rust-linux-arm64-generic.tar.gz\n'
            fi
            ;;
        *)
            die "unsupported architecture: $arch" "不支持的架构: $arch"
            ;;
    esac
}

normalize_version() {
    if [ "$VERSION" = "latest" ]; then
        printf 'latest'
    elif printf '%s' "$VERSION" | grep -q '^v'; then
        printf '%s' "$VERSION"
    else
        printf 'v%s' "$VERSION"
    fi
}

download_url_for() {
    local version="$1"
    local asset="$2"
    if [ "$version" = "latest" ]; then
        printf 'https://github.com/%s/releases/latest/download/%s\n' "$REPO" "$asset"
    else
        printf 'https://github.com/%s/releases/download/%s/%s\n' "$REPO" "$version" "$asset"
    fi
}

geoip_url_for() {
    local name="$1"
    if [ -n "$GEOIP_BASE_URL" ]; then
        printf '%s/%s\n' "${GEOIP_BASE_URL%/}" "$name"
    else
        # GeoIP databases are vendored in this repository under geoip/ and are
        # the canonical source for installs. Updates are controlled by the
        # repository owner.
        printf 'https://github.com/%s/raw/main/geoip/%s\n' "$REPO" "$name"
    fi
}

default_route_iface() {
    command -v ip >/dev/null 2>&1 || return 0
    ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

nic_driver() {
    local iface="$1"
    local driver=""
    if command -v ethtool >/dev/null 2>&1; then
        driver="$(ethtool -i "$iface" 2>/dev/null | sed -n 's/^driver:[[:space:]]*//p' | head -n 1)"
    fi
    if [ -z "$driver" ] && [ -e "/sys/class/net/$iface/device/driver" ]; then
        driver="$(basename "$(readlink "/sys/class/net/$iface/device/driver" 2>/dev/null || true)" 2>/dev/null || true)"
    fi
    printf '%s' "${driver:-unknown}"
}

nic_xdp_verdict() {
    # Driver allowlist for native (drv) XDP attach; everything else only gets
    # generic/skb mode at best. Advisory only — the runtime still probes the
    # real attach path.
    case "$1" in
        i40e|ice|ixgbe|ixgbevf|iavf|mlx4_en|mlx5_core|bnxt_en|qede|sfc|sfc_ef100|nfp|nfp_netvf|virtio_net|ena|gve|mvneta|mvpp2|stmmac|enetc|atlantic|axgbe|amd-xgbe|bcmgenet|cpsw|am65-cpsw|fec|dpaa2-eth|xilinx_axienet|netdevsim)
            printf 'native'
            ;;
        veth|tun|tap)
            printf 'conditional'
            ;;
        *)
            printf 'generic'
            ;;
    esac
}

nic_afxdp_zc() {
    # AF_XDP zero-copy capable drivers (subset of native-XDP drivers).
    case "$1" in
        i40e|ice|ixgbe|mlx5_core|bnxt_en|stmmac|sfc|sfc_ef100)
            return 0
            ;;
    esac
    return 1
}

nic_is_virtual_noise() {
    case "$1" in
        lo|docker*|br-*|virbr*|cni*|flannel*|cali*|kube*|podman*|veth*|tun*|tap*|wg*|zt*|tailscale*|vxlan*|macvlan*|ifb*|gre*|gretap*|erspan*|ip6tnl*|sit*|bonding_masters)
            return 0
            ;;
    esac
    return 1
}

nic_xdp_attached() {
    # Best-effort detection of an already-attached XDP program and its mode.
    local out=""
    out="$(ip -d link show dev "$1" 2>/dev/null || true)"
    case "$out" in
        *xdpoffload*) printf 'offload' ;;
        *xdpdrv*) printf 'native' ;;
        *xdpgeneric*) printf 'generic' ;;
        *prog/xdp*|*" xdp "*) printf 'native' ;;
        *) return 1 ;;
    esac
    return 0
}

report_nic_xdp() {
    local kernel=""
    local kmajor=0
    local kminor=0
    local iface=""
    local driver=""
    local state=""
    local verdict=""
    local attached=""
    local default_iface=""
    local real_nics=0
    local native_nics=0
    local marker=""

    section "网卡 XDP 能力检测 / NIC XDP Capability"

    kernel="$(uname -r 2>/dev/null || true)"
    kmajor="$(printf '%s' "$kernel" | cut -d. -f1)"
    kminor="$(printf '%s' "$kernel" | cut -d. -f2)"
    case "$kmajor$kminor" in ''|*[!0-9]*) kmajor=0; kminor=0 ;; esac
    if [ "$kmajor" -gt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -ge 4 ]; }; then
        ok "kernel $kernel" "内核 $kernel 满足 AF_XDP 要求"
    elif [ "$kmajor" -gt 4 ] || { [ "$kmajor" -eq 4 ] && [ "$kminor" -ge 18 ]; }; then
        warn "kernel $kernel supports AF_XDP but >= 5.4 is recommended" "内核 $kernel 支持 AF_XDP，建议 >= 5.4"
    else
        warn "kernel $kernel is too old for AF_XDP (need >= 4.18)" "内核 $kernel 过旧，AF_XDP 需要 >= 4.18"
    fi

    if [ ! -d /sys/class/net ]; then
        warn "no /sys/class/net; NIC detection unavailable" "无 /sys/class/net；无法检测网卡"
        return 0
    fi

    default_iface="$(default_route_iface)"

    for path in /sys/class/net/*; do
        iface="$(basename "$path")"
        if nic_is_virtual_noise "$iface" && [ "$iface" != "$default_iface" ]; then
            continue
        fi
        driver="$(nic_driver "$iface")"
        state="$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || printf 'unknown')"
        verdict="$(nic_xdp_verdict "$driver")"
        attached="$(nic_xdp_attached "$iface" || true)"
        marker=""
        [ "$iface" = "$default_iface" ] && marker=" *"
        real_nics=$((real_nics + 1))

        case "$verdict" in
            native)
                native_nics=$((native_nics + 1))
                if nic_afxdp_zc "$driver"; then
                    ok "  $iface$marker  driver=$driver  state=$state  native XDP (drv) + AF_XDP zero-copy" "  $iface$marker  驱动=$driver  状态=$state  支持 native XDP (drv) + AF_XDP 零拷贝"
                else
                    ok "  $iface$marker  driver=$driver  state=$state  native XDP (drv); AF_XDP copy-mode" "  $iface$marker  驱动=$driver  状态=$state  支持 native XDP (drv)；AF_XDP 为拷贝模式"
                fi
                ;;
            conditional)
                warn "  $iface$marker  driver=$driver  state=$state  native XDP depends on kernel (veth/tun need >= 5.11)" "  $iface$marker  驱动=$driver  状态=$state  native XDP 依赖内核版本（veth/tun 需 >= 5.11）"
                ;;
            *)
                warn "  $iface$marker  driver=$driver  state=$state  no native XDP; generic/skb mode only" "  $iface$marker  驱动=$driver  状态=$state  不支持 native XDP；仅 generic/skb 模式"
                ;;
        esac
        if [ -n "$attached" ]; then
            kv "    attached xdp" "$attached"
        fi
    done

    if [ "$real_nics" -eq 0 ]; then
        warn "no physical NIC detected" "未检测到物理网卡"
    elif [ "$native_nics" -eq 0 ]; then
        warn "no NIC supports native XDP; use xdp.attachMode: auto or skb" "没有网卡支持 native XDP；xdp.attachMode 请使用 auto 或 skb"
    fi
    if [ -n "$default_iface" ]; then
        kv "default route iface" "$default_iface"
    fi
}

download_geoip_files() {
    local names="GeoLite2-City.mmdb GeoLite2-ASN.mmdb GeoLite2-Country.mmdb"
    local name=""
    local url=""
    local target=""
    local tmp_target=""
    local sums_file=""
    local expected=""

    section "安装 GeoIP 数据库 / Install GeoIP Databases"
    run mkdir -p "$GEOIP_DIR"

    # Fetch the checksum manifest from the same source for integrity
    # verification. Missing manifest only warns; a checksum mismatch aborts.
    if [ "$DRY_RUN" -eq 0 ]; then
        if curl -fsSL --retry 2 --connect-timeout 15 -o "$TMP_DIR/geoip-SHA256SUMS.txt" "$(geoip_url_for SHA256SUMS.txt)" 2>/dev/null; then
            sums_file="$TMP_DIR/geoip-SHA256SUMS.txt"
        else
            warn "GeoIP checksum manifest unavailable; skipping integrity verification" "GeoIP 校验清单不可用；跳过完整性校验"
        fi
    fi

    for name in $names; do
        url="$(geoip_url_for "$name")"
        target="$GEOIP_DIR/$name"
        tmp_target="$TMP_DIR/$name"
        if [ -e "$target" ]; then
            run cp -a "$target" "$BACKUP_DIR/$name.geoip-original"
        fi
        if [ "$DRY_RUN" -eq 0 ]; then
            download_checked "$url" "$tmp_target" "$name"
            if [ -n "$sums_file" ]; then
                expected="$(awk -v f="$name" '$2 == f {print $1}' "$sums_file" | head -n 1)"
                if [ -z "$expected" ]; then
                    warn "no checksum entry for $name; skipping verification" "$name 无校验条目；跳过校验"
                elif [ "$(sha256_file "$tmp_target")" != "$expected" ]; then
                    die "GeoIP checksum mismatch for $name; aborting before install" "$name 校验和不匹配；安装前中止"
                fi
            fi
            install -m 0644 "$tmp_target" "$target"
        else
            log "+ curl -fL --retry 3 --connect-timeout 20 -o $tmp_target $url"
            log "+ install -m 0644 $tmp_target $target"
        fi
    done
    ok "GeoIP databases installed to $GEOIP_DIR" "GeoIP 数据库已安装到 $GEOIP_DIR"
}

collect_api_config() {
    # Only needed when no existing api_node.yaml can be migrated (fresh install).
    if [ -n "$EXISTING_API_CONFIG_DIR" ]; then
        return
    fi

    if prompt_available && [ "$ASSUME_YES" -eq 0 ]; then
        section "API 连接配置 / API Connection Config"
        if [ -z "$API_ENDPOINTS" ]; then
            API_ENDPOINTS="$(prompt_text \
                "API RPC 地址，多个用逗号分隔" \
                "API RPC endpoints, comma separated" \
                "http://127.0.0.1:8001")"
        fi
        if [ -z "$NODE_ID" ]; then
            NODE_ID="$(prompt_text "nodeId" "nodeId")"
        fi
        if [ -z "$NODE_SECRET" ]; then
            NODE_SECRET="$(prompt_text "secret" "secret" "" "yes")"
        fi
    fi

    [ -n "$API_ENDPOINTS" ] || die "no existing api_node.yaml found; fresh install requires --api-endpoint or --api-endpoints" "未找到可迁移的 api_node.yaml；全新安装需要 --api-endpoint 或 --api-endpoints"
    [ -n "$NODE_ID" ] || die "no existing api_node.yaml found; fresh install requires --node-id" "未找到可迁移的 api_node.yaml；全新安装需要 --node-id"
    [ -n "$NODE_SECRET" ] || die "no existing api_node.yaml found; fresh install requires --secret" "未找到可迁移的 api_node.yaml；全新安装需要 --secret"
}

# Interactive XDP dataplane choice. Default is enabled (bidirectional:
# inbound proxy + outbound AF_XDP upstream). Skipped when an existing
# config already defines an xdp: section — that config stays authoritative.
collect_xdp_choice() {
    if [ "$IS_FRESH" -eq 0 ] && existing_config_has_xdp; then
        return 0
    fi
    if prompt_available && [ "$ASSUME_YES" -eq 0 ]; then
        if ask_yes_no \
            "启用 XDP 数据面？（双向：入向代理 + 出向 AF_XDP 回源）" \
            "Enable XDP dataplane? (bidirectional: inbound proxy + outbound AF_XDP upstream)" \
            "yes"; then
            ENABLE_XDP="yes"
        else
            ENABLE_XDP="no"
        fi
    fi
    if [ "$ENABLE_XDP" = "yes" ]; then
        log "XDP dataplane: enabled (bidirectional)" "XDP 数据面：启用（双向）"
    else
        log "XDP dataplane: disabled" "XDP 数据面：禁用"
    fi
}

migrate_runtime_layout() {
    local config_path="$INSTALL_DIR/configs/api_node.yaml"
    local config_candidate=""
    local source_dir=""
    local legacy_data_dir="$INSTALL_DIR/../data"
    local config_candidates=()
    local data_dirs=()

    add_config_candidates() {
        local dir="$1"
        [ -n "$dir" ] || return 0
        config_candidates+=("$dir/configs/api_node.yaml" "$dir/api_node.yaml")
    }

    add_data_dir() {
        local dir="$1"
        [ -n "$dir" ] || return 0
        data_dirs+=("$dir")
    }

    run mkdir -p "$INSTALL_DIR/configs" "$INSTALL_DIR/data" "$INSTALL_DIR/logs"

    add_config_candidates "$INSTALL_DIR"
    add_config_candidates "$EXISTING_RUNTIME_DIR"
    add_config_candidates "$EXISTING_BINARY_WORKDIR"
    add_config_candidates /root/cloud-node
    add_config_candidates /opt/cloud-node
    add_config_candidates /opt/cloud-node-rust

    if [ ! -e "$config_path" ]; then
        for config_candidate in "${config_candidates[@]}"; do
            if [ -e "$config_candidate" ]; then
                run cp -a "$config_candidate" "$config_path"
                run cp -a "$config_candidate" "$BACKUP_DIR/api_node.yaml.migrated-original"
                break
            fi
        done
    fi

    add_data_dir "$INSTALL_DIR/data"
    if [ -n "$EXISTING_RUNTIME_DIR" ]; then
        add_data_dir "$EXISTING_RUNTIME_DIR/data"
    fi
    if [ -n "$EXISTING_BINARY_WORKDIR" ]; then
        add_data_dir "$EXISTING_BINARY_WORKDIR/data"
    fi
    add_data_dir "$legacy_data_dir"
    add_data_dir /root/cloud-node/data
    add_data_dir /opt/cloud-node/data
    add_data_dir /opt/cloud-node-rust/data

    for source_dir in "${data_dirs[@]}"; do
        if [ -e "$source_dir/state.json" ] && [ ! -e "$INSTALL_DIR/data/state.json" ]; then
            run cp -a "$source_dir/state.json" "$INSTALL_DIR/data/state.json"
        fi
        if [ -e "$source_dir/metrics.db" ] && [ ! -e "$INSTALL_DIR/data/metrics.db" ]; then
            run cp -a "$source_dir/metrics.db" "$INSTALL_DIR/data/metrics.db"
        fi
        if [ -e "$source_dir/metrics.mace" ] && [ ! -e "$INSTALL_DIR/data/metrics.mace" ]; then
            run cp -a "$source_dir/metrics.mace" "$INSTALL_DIR/data/metrics.mace"
        fi
    done
}

# Emits the xdp: YAML block into api_node.yaml. Enabled (default) means the
# bidirectional dataplane: inbound XDP/AF_XDP proxy plus node-originated
# upstream TCP via the AF_XDP dial path — the runtime forces that whenever
# xdp.enabled=true, so no upstream.mode key is written (it would be dead
# config). Disabled writes an explicit enabled: false so the runtime
# default-on is overridden observably.
write_xdp_config_block() {
    local iface="$XDP_IFACE"
    if [ "$ENABLE_XDP" != "yes" ]; then
        printf 'xdp:\n'
        printf '  enabled: false\n'
        return
    fi
    [ -n "$iface" ] || iface="$(default_route_iface || true)"
    printf 'xdp:\n'
    printf '  enabled: true\n'
    printf '  attachMode: auto\n'
    if [ -n "$iface" ]; then
        # mode: proxy is required — the default interface mode is
        # observe (XDP statistics only, no AF_XDP sockets). Queues are
        # written explicitly from sysfs so strict older binaries (which
        # reject empty queue lists) also accept this file; newer builds
        # re-derive from sysfs at startup anyway. Proxy ports are filled
        # at runtime by the 30s port-sync task.
        printf '  interfaces:\n'
        printf '    - name: %s\n' "$(yaml_quote "$iface")"
        printf '      mode: proxy\n'
        printf '      queues: %s\n' "$(iface_queues_spec "$iface")"
    else
        # Empty interfaces lets ensure_current_xdp_auto_config derive the
        # full dataplane (interface, mode=proxy, queues) at startup.
        printf '  interfaces: []\n'
    fi
}

write_api_node_config() {
    local config_path="$INSTALL_DIR/configs/api_node.yaml"
    local endpoint=""
    local endpoint_array=()
    local first=1
    local list="[ "

    # Only write a new config when nothing could be migrated.
    if [ -n "$EXISTING_API_CONFIG_DIR" ] || [ -e "$config_path" ]; then
        return 0
    fi

    IFS=',' read -r -a endpoint_array <<< "$API_ENDPOINTS"
    for endpoint in "${endpoint_array[@]}"; do
        endpoint="$(trim_spaces "$endpoint")"
        [ -n "$endpoint" ] || continue
        if [ "$first" -eq 0 ]; then
            list="${list}, "
        fi
        list="${list}$(yaml_quote "$endpoint")"
        first=0
    done
    list="${list} ]"
    [ "$first" -eq 0 ] || die "fresh install requires at least one non-empty API endpoint" "全新安装至少需要一个非空 API 地址"

    run mkdir -p "$INSTALL_DIR/configs"
    if [ -e "$config_path" ]; then
        run cp -a "$config_path" "$BACKUP_DIR/api_node.yaml.config-original"
    fi

    if [ "$DRY_RUN" -eq 0 ]; then
        {
            printf 'rpc.endpoints: %s\n' "$list"
            printf 'nodeId: %s\n' "$(yaml_quote "$NODE_ID")"
            printf 'secret: %s\n' "$(yaml_quote "$NODE_SECRET")"
            printf 'relay:\n'
            printf '  zeroCopy: false\n'
        } > "$config_path"
        chmod 0600 "$config_path" 2>/dev/null || true
    else
        log "+ write $config_path"
        printf '  rpc.endpoints: %s\n' "$list"
        printf '  nodeId: %s\n' "$(yaml_quote "$NODE_ID")"
        printf '  secret: ******\n'
        printf '  relay.zeroCopy: false\n'
    fi
}

# Enabled XDP is always bidirectional — the AF_XDP upstream dial path
# requires the nftables dial guard (the reserved source-port DROP rule
# lives in an inet table managed via the nft binary). Without it every
# outbound dial would RST during XDP detach windows (reload/upgrade/
# rollback), so the runtime fails closed. The installer does the same: it
# tries to install nftables, and when that is impossible it ABORTS with
# remediation — the only alternative is disabling XDP entirely.
ensure_upstream_prereqs() {
    [ "$ENABLE_XDP" = "yes" ] || return 0
    if command -v nft >/dev/null 2>&1; then
        return 0
    fi
    log "nftables not found; the bidirectional XDP dial path needs the nft dial guard — attempting install" \
        "未检测到 nftables；双向 XDP 拨号路径需要 nft 守护规则——尝试安装"
    if [ "$DRY_RUN" -eq 0 ]; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null 2>&1 || true
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q nftables >/dev/null 2>&1 || true
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q nftables >/dev/null 2>&1 || true
        elif command -v pacman >/dev/null 2>&1; then
            pacman -S --noconfirm --needed nftables >/dev/null 2>&1 || true
        fi
    else
        log "dry-run: would try to install nftables via the system package manager" \
            "dry-run：将尝试通过系统包管理器安装 nftables"
        return 0
    fi
    if command -v nft >/dev/null 2>&1; then
        ok "nftables installed; AF_XDP dial guard available" "已安装 nftables，AF_XDP 拨号守护可用"
        return 0
    fi
    # Fail closed — bidirectional XDP was requested but its prerequisite
    # cannot be met. Tell the operator both ways forward: install
    # nftables, or explicitly disable XDP.
    die "nftables is required for the AF_XDP upstream dial path and could not be installed. Install nftables (e.g. 'apt-get install nftables') and re-run, or disable XDP entirely with --no-xdp / ENABLE_XDP=no" \
        "AF_XDP 出向拨号路径需要 nftables 且自动安装失败。请手动安装 nftables（如 'apt-get install nftables'）后重跑，或用 --no-xdp / ENABLE_XDP=no 完全禁用 XDP"
}

# Legacy deployments keep dataplane config in configs/runtime.yaml /
# runtime.yml. Those files are obsolete — the runtime only reads
# configs/api_node.yaml now. For each legacy file: if it carries an xdp:
# block and api_node.yaml does not, move the block over verbatim (explicit
# enabled: false and tuned interfaces survive). All other keys
# (runtime.mode, cluster.*, ...) are dropped by design — the runtime no
# longer parses them.
migrate_legacy_runtime_xdp() {
    local rt=""
    local api_cfg="$INSTALL_DIR/configs/api_node.yaml"
    while IFS= read -r rt; do
        [ -n "$rt" ] || continue
        grep -q '^xdp:' "$rt" 2>/dev/null || continue
        if [ ! -e "$api_cfg" ]; then
            warn "$rt has an xdp: block but $api_cfg does not exist — skipping the move; a fresh xdp block will be written" \
                "$rt 含 xdp: 配置块但 $api_cfg 不存在——跳过迁移，将写入新的 xdp 配置"
            continue
        fi
        if grep -q '^xdp:' "$api_cfg" 2>/dev/null; then
            warn "$rt has an xdp: block but $api_cfg already defines one — api_node.yaml stays authoritative, the legacy block is discarded" \
                "$rt 含 xdp: 配置块，但 $api_cfg 已有 xdp 配置——以 api_node.yaml 为准，丢弃旧配置块"
            continue
        fi
        if [ "$DRY_RUN" -eq 0 ]; then
            run mkdir -p "$INSTALL_DIR/configs"
            run cp -a "$api_cfg" "$BACKUP_DIR/api_node.yaml.pre-runtime-xdp-move"
            awk '
                /^xdp:[[:space:]]*$/ { inblk=1; print; next }
                inblk && /^[[:alnum:]_.]/ { inblk=0 }
                inblk { print }
            ' "$rt" >> "$api_cfg"
            chmod 0600 "$api_cfg" 2>/dev/null || true
        else
            log "+ move xdp block $rt -> $api_cfg"
        fi
        warn "moved xdp: block from $rt into api_node.yaml — runtime.yaml is obsolete; api_node.yaml now carries both API credentials and the XDP dataplane config" \
            "已将 xdp: 配置块从 $rt 移入 api_node.yaml——runtime.yaml 已废弃；api_node.yaml 现同时保存 API 连接信息与 XDP 数据面配置"
    done < <(legacy_runtime_config_files)
}

# Deletes every obsolete runtime.yaml/runtime.yml found on disk (each is
# backed up first). Non-xdp content (runtime.mode, cluster.*) is dropped
# intentionally — the runtime no longer parses it.
remove_legacy_runtime_configs() {
    local rt=""
    while IFS= read -r rt; do
        [ -n "$rt" ] || continue
        if [ "$DRY_RUN" -eq 0 ]; then
            run cp -a "$rt" "$BACKUP_DIR/$(sanitize_path "$rt").removed"
            run rm -f "$rt"
            warn "removed obsolete runtime config $rt (backup in $BACKUP_DIR)" \
                "已移除废弃的运行时配置 ${rt}（备份于 ${BACKUP_DIR}）"
        else
            log "+ rm -f $rt (backup first)"
        fi
    done < <(legacy_runtime_config_files)
}

# "[0,1,...]" queue list for an interface, counted from sysfs rx-*
# entries. Falls back to [0] — every netdev has at least one RX queue.
iface_queues_spec() {
    local name="$1" n i out="[" sep=""
    n=$(ls "/sys/class/net/$name/queues" 2>/dev/null | grep -c '^rx-' || true)
    [ "${n:-0}" -ge 1 ] 2>/dev/null || n=1
    for ((i = 0; i < n; i++)); do
        out+="$sep$i"
        sep=","
    done
    printf '%s]\n' "$out"
}

# Existing xdp interface entries written by older installers may lack
# `mode:` (defaults to observe — no AF_XDP) and `queues:` (crashed strict
# binaries). Inject mode: proxy + sysfs-derived queues only where the keys
# are absent; explicit values stay untouched.
repair_xdp_interface_entries() {
    local rt="$1"
    [ -e "$rt" ] || return 0
    grep -q '^  interfaces:' "$rt" 2>/dev/null || return 0
    if [ "$DRY_RUN" -ne 0 ]; then
        log "+ repair xdp.interfaces entries missing mode/queues in $rt"
        return 0
    fi
    run cp -a "$rt" "$BACKUP_DIR/$(basename "$rt").pre-iface-repair"
    awk '
        function rxq(name,   cmd, n, out, i) {
            cmd = "ls /sys/class/net/" name "/queues 2>/dev/null | grep -c ^rx-"
            cmd | getline n; close(cmd)
            if (n + 0 < 1) n = 1
            out = "["
            for (i = 0; i < n; i++) out = out (i ? "," : "") i
            return out "]"
        }
        /^[[:alnum:]_.]/ {
            if (seen && !hasmode) printf "      mode: proxy\n"
            if (seen && !hasq) printf "      queues: %s\n", rxq(pname)
            inblk = 0; iniface = 0; seen = 0
        }
        /^xdp:[[:space:]]*$/ { inblk = 1 }
        inblk && /^  interfaces:[[:space:]]*$/ { iniface = 1 }
        iniface && /^    - name:/ {
            if (seen && !hasmode) printf "      mode: proxy\n"
            if (seen && !hasq) printf "      queues: %s\n", rxq(pname)
            seen = 1; hasmode = 0; hasq = 0
            pname = $0
            sub(/^.*name:[[:space:]]*/, "", pname)
            gsub(/["'"'"'[:space:]]/, "", pname)
        }
        iniface && seen && /^  [^ -]/ {
            if (!hasmode) printf "      mode: proxy\n"
            if (!hasq) printf "      queues: %s\n", rxq(pname)
            iniface = 0; seen = 0
        }
        iniface && seen && /^      mode:/ { hasmode = 1 }
        iniface && seen && /^      queues:/ { hasq = 1 }
        { print }
        END {
            if (seen && !hasmode) printf "      mode: proxy\n"
            if (seen && !hasq) printf "      queues: %s\n", rxq(pname)
        }
    ' "$rt" > "$rt.iface-repaired" && mv "$rt.iface-repaired" "$rt"
}

# Writes the xdp: block into configs/api_node.yaml — the single config
# file the runtime parses. An api_node.yaml that already has an xdp: key
# is authoritative — only its interface entries are repaired for missing
# mode/queues keys.
write_xdp_config() {
    local config_path="$INSTALL_DIR/configs/api_node.yaml"
    if grep -q '^xdp:' "$config_path" 2>/dev/null; then
        repair_xdp_interface_entries "$config_path"
        return 0
    fi
    run mkdir -p "$INSTALL_DIR/configs"
    if [ "$DRY_RUN" -eq 0 ]; then
        write_xdp_config_block >> "$config_path"
        chmod 0600 "$config_path" 2>/dev/null || true
    else
        log "+ append xdp block to $config_path"
        write_xdp_config_block | sed 's/^/  /'
    fi
    if [ "$ENABLE_XDP" = "yes" ]; then
        ok "wrote xdp.enabled=true (bidirectional) to $config_path" \
            "已在 $config_path 写入 xdp.enabled=true（双向 XDP）"
    else
        ok "wrote xdp.enabled=false to $config_path" "已在 $config_path 写入 xdp.enabled=false"
    fi
}

manifest_value() {
    local backup_dir="$1"
    local key="$2"
    local manifest="$backup_dir/manifest.current.txt"
    if [ ! -f "$manifest" ]; then
        manifest="$backup_dir/manifest.go-original.txt"
    fi
    [ -f "$manifest" ] || return 0
    sed -n "s/^${key}=//p" "$manifest" | tail -n 1
}

backup_dirs() {
    local backup=""
    [ -d "$BACKUP_ROOT" ] || return 0
    for backup in "$BACKUP_ROOT"/*; do
        [ -d "$backup" ] || continue
        if [ -f "$backup/manifest.current.txt" ] || [ -f "$backup/manifest.go-original.txt" ] || ls "$backup"/*.go-original "$backup"/*.rust-current >/dev/null 2>&1; then
            printf '%s\n' "$backup"
        fi
    done | sort -r
}

restore_backup_dirs() {
    local backup=""
    [ -d "$BACKUP_ROOT" ] || return 0
    for backup in "$BACKUP_ROOT"/*; do
        [ -d "$backup" ] || continue
        if [ -f "$backup/manifest.go-original.txt" ] || ls "$backup"/*.go-original >/dev/null 2>&1; then
            printf '%s\n' "$backup"
        fi
    done | sort -r
}

list_backups() {
    local backup=""
    local created=""
    local version=""
    local existing=""
    section "可用备份 / Available Backups"
    if ! backup_dirs | grep -q .; then
        bi "  未找到备份目录：$BACKUP_ROOT" "  No backups found under: $BACKUP_ROOT"
        return
    fi
    while IFS= read -r backup; do
        [ -d "$backup" ] || continue
        created="$(manifest_value "$backup" created_at)"
        version="$(manifest_value "$backup" version)"
        existing="$(manifest_value "$backup" existing_binary)"
        printf '  %s\n' "$backup"
        [ -n "$created" ] && kv "created" "$created"
        [ -n "$version" ] && kv "rust version" "$version"
        [ -n "$existing" ] && kv "go original" "$existing"
    done < <(backup_dirs)
}

choose_restore_backup() {
    local backups=()
    local idx=0
    local choice=""
    local backup=""

    if [ -n "$RESTORE_BACKUP" ]; then
        printf '%s\n' "$RESTORE_BACKUP"
        return
    fi

    read_lines_into backups < <(restore_backup_dirs)
    [ "${#backups[@]}" -gt 0 ] || die "no backups found under $BACKUP_ROOT" "$BACKUP_ROOT 下未找到备份"

    if [ "$ASSUME_YES" -eq 1 ] || ! prompt_available; then
        printf '%s\n' "${backups[0]}"
        return
    fi

    # Display output goes to stderr; only the chosen path is printed to stdout
    # so the caller's command substitution captures a clean value.
    section "选择恢复备份 / Choose Restore Backup" >&2
    idx=1
    for backup in "${backups[@]}"; do
        printf '  %s%d)%s %s\n' "$BOLD" "$idx" "$RESET" "$backup" >&2
        idx=$((idx + 1))
    done
    printf '\n输入序号 | Enter choice %s[1]%s: ' "$DIM" "$RESET" >&2
    read_prompt choice || choice=""
    choice="${choice:-1}"
    case "$choice" in
        ''|*[!0-9]*)
            choice=1
            ;;
    esac
    if [ "$choice" -lt 1 ] || [ "$choice" -gt "${#backups[@]}" ]; then
        choice=1
    fi
    printf '%s\n' "${backups[$((choice - 1))]}"
}

restore_file() {
    local source="$1"
    local target="$2"
    local label="$3"
    local target_dir=""
    local current_name=""

    if [ ! -e "$source" ]; then
        warn "missing backup for $label: $source" "$label 的备份缺失: $source"
        return
    fi

    target_dir="${target%/*}"
    if [ "$target_dir" = "$target" ] || [ -z "$target_dir" ]; then
        target_dir="."
    fi
    run mkdir -p "$target_dir"

    if [ -e "$target" ]; then
        current_name="$(sanitize_path "$target").rust-current"
        run cp -a "$target" "$RESTORE_CURRENT_DIR/$current_name"
    fi
    run cp -a "$source" "$target"
}

restore_go_original() {
    local backup_dir=""
    local existing_binary=""
    local existing_source=""
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local service_was_active=0

    backup_dir="$(choose_restore_backup)"
    [ -d "$backup_dir" ] || die "restore backup dir does not exist: $backup_dir" "恢复备份目录不存在: $backup_dir"

    section "恢复摘要 / Restore Summary"
    kv "backup" "$backup_dir"
    kv "service" "$SERVICE_NAME"

    if [ "$ASSUME_YES" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        ask_yes_no "确认从该备份恢复 Go 原版吗？" "Restore Go original from this backup?" "no" || die "aborted" "已中止"
    fi

    RESTORE_CURRENT_DIR="$BACKUP_ROOT/restore-current-$(date +%Y%m%d-%H%M%S)"
    run mkdir -p "$RESTORE_CURRENT_DIR"

    if systemctl_available && systemctl is-active --quiet "$SERVICE_NAME"; then
        service_was_active=1
        run systemctl stop "$SERVICE_NAME"
    fi

    existing_binary="$(manifest_value "$backup_dir" existing_binary)"
    if [ -n "$existing_binary" ] && [ "$existing_binary" != "not found" ]; then
        existing_source="$backup_dir/$(sanitize_path "$existing_binary").go-original"
        restore_file "$existing_source" "$existing_binary" "original Go binary"
    fi

    restore_file "$backup_dir/usr_bin_cloud-node.go-original" "/usr/bin/cloud-node" "/usr/bin/cloud-node"
    restore_file "$backup_dir/${SERVICE_NAME}.service.go-original" "$service_file" "systemd service"

    # Restore any legacy unit files captured during migration unregister.
    if [ -d "$backup_dir/legacy-units/etc/systemd/system" ]; then
        local legacy_src=""
        local legacy_dst=""
        for legacy_src in "$backup_dir/legacy-units/etc/systemd/system"/*; do
            [ -e "$legacy_src" ] || continue
            legacy_dst="/etc/systemd/system/$(basename "$legacy_src")"
            if [ -d "$legacy_src" ]; then
                run mkdir -p "$legacy_dst"
                run cp -a "$legacy_src/." "$legacy_dst/"
            else
                restore_file "$legacy_src" "$legacy_dst" "legacy unit $legacy_dst"
            fi
        done
    fi

    if systemctl_available; then
        run systemctl daemon-reload
    fi

    # Restore always preserves prior run state: restart only if it was running.
    if [ "$service_was_active" -eq 1 ] && systemctl_available; then
        run systemctl start "$SERVICE_NAME"
    fi

    ok "restore completed" "恢复完成"
    log "current Rust files backed up at: $RESTORE_CURRENT_DIR" "当前 Rust 文件已备份到: $RESTORE_CURRENT_DIR"
}

confirm_install() {
    if [ "$ASSUME_YES" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
        return
    fi
    ask_yes_no "确认开始安装吗？" "Proceed with install?" "yes" || die "aborted" "已中止"
}

if [ "$ACTION" = "list-backups" ]; then
    list_backups
    exit 0
fi

if [ "$ACTION" = "restore" ]; then
    restore_go_original
    exit 0
fi

EXISTING_BINARY="$(find_existing_cloud_node || true)"
SERVICE_WORKDIR="$(systemd_value WorkingDirectory || true)"
EXISTING_BINARY_WORKDIR="$(existing_binary_workdir "$EXISTING_BINARY" || true)"
EXISTING_RUNTIME_DIR="$(first_existing_runtime_dir \
    "$SERVICE_WORKDIR" \
    "$EXISTING_BINARY_WORKDIR" \
    /root/cloud-node \
    /opt/cloud-node \
    /opt/cloud-node-rust \
    || true)"
if [ -z "$INSTALL_DIR" ]; then
    if [ -n "$EXISTING_RUNTIME_DIR" ]; then
        INSTALL_DIR="$EXISTING_RUNTIME_DIR"
    elif [ -n "$EXISTING_BINARY" ]; then
        INSTALL_DIR="/opt/cloud-node-rust"
    else
        INSTALL_DIR="/root/cloud-node"
    fi
fi
if [ -z "$INSTALL_BINARY" ]; then
    INSTALL_BINARY="$INSTALL_DIR/cloud-node-rust"
fi
if [ -z "$GEOIP_DIR" ]; then
    GEOIP_DIR="$INSTALL_DIR/data"
fi

EXISTING_API_CONFIG_DIR="$(find_existing_api_config \
    "$INSTALL_DIR" \
    "$EXISTING_RUNTIME_DIR" \
    "$EXISTING_BINARY_WORKDIR" \
    /root/cloud-node \
    /opt/cloud-node \
    /opt/cloud-node-rust \
    || true)"

IS_FRESH=0
if [ -z "$EXISTING_API_CONFIG_DIR" ]; then
    IS_FRESH=1
fi

collect_api_config
collect_xdp_choice

BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
ASSET_NAME="$(detect_asset_name)"
NORMALIZED_VERSION="$(normalize_version)"
DOWNLOAD_URL="$(download_url_for "$NORMALIZED_VERSION" "$ASSET_NAME")"
EXISTING_RUNTIME="not-found"
CURRENT_BACKUP_SUFFIX="current"
if [ -n "$EXISTING_BINARY" ]; then
    EXISTING_RUNTIME="$(detect_runtime "$EXISTING_BINARY")"
fi
case "$EXISTING_RUNTIME" in
    go)
        CURRENT_BACKUP_SUFFIX="go-original"
        ;;
    rust)
        CURRENT_BACKUP_SUFFIX="rust-current"
        ;;
    *)
        CURRENT_BACKUP_SUFFIX="current"
        ;;
esac

SERVICE_WAS_ACTIVE=0
LEGACY_WAS_RUNNING=0
if systemctl_available && systemctl is-active --quiet "$SERVICE_NAME"; then
    SERVICE_WAS_ACTIVE=1
    LEGACY_WAS_RUNNING=1
fi
if [ "$LEGACY_WAS_RUNNING" -eq 0 ] && discover_legacy_pids | grep -q .; then
    LEGACY_WAS_RUNNING=1
fi
if [ "$LEGACY_WAS_RUNNING" -eq 0 ] && systemctl_available; then
    while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            LEGACY_WAS_RUNNING=1
            break
        fi
    done < <(discover_legacy_units || true)
fi

section "安装摘要 / Install Summary"
kv "repository" "$REPO"
kv "version" "$NORMALIZED_VERSION"
kv "asset" "$ASSET_NAME"
kv "existing cloud-node" "${EXISTING_BINARY:-not found}"
kv "existing runtime" "$EXISTING_RUNTIME"
kv "fresh install" "$IS_FRESH"
kv "legacy running" "$LEGACY_WAS_RUNNING"
kv "install dir" "$INSTALL_DIR"
kv "install binary" "$INSTALL_BINARY"
kv "config dir" "$INSTALL_DIR/configs"
kv "data dir" "$INSTALL_DIR/data"
kv "logs dir" "$INSTALL_DIR/logs"
kv "backup dir" "$BACKUP_DIR"
kv "service" "$SERVICE_NAME"
kv "auto start" "$AUTO_START"
kv "GeoIP dir" "$GEOIP_DIR"
if [ "$IS_FRESH" -eq 1 ]; then
    kv "api endpoints" "$API_ENDPOINTS"
    kv "nodeId" "$NODE_ID"
    kv "secret" "******"
    kv "timezone" "${TIMEZONE:-keep current}"
fi

if [ "$EXISTING_RUNTIME" = "rust" ]; then
    ok "existing Rust cloud-node will be upgraded to the selected release" "现有 Rust 节点将升级到所选版本"
elif [ "$EXISTING_RUNTIME" = "go" ]; then
    ok "existing Go cloud-node will be migrated to the Rust release" "现有 Go 节点将迁移到 Rust 版本"
elif [ "$EXISTING_RUNTIME" = "unknown" ]; then
    warn "existing binary runtime is unknown; it will still be backed up before install" "现有二进制运行时未知；安装前仍会备份"
fi

confirm_install
# Install/verify the nftables dial-guard prerequisite before touching
# anything — when it cannot be satisfied the install aborts here with
# remediation, leaving the existing deployment fully intact.
ensure_upstream_prereqs
apply_timezone

TMP_DIR="$(mktemp -d)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

run mkdir -p "$BACKUP_DIR"

if [ -n "$EXISTING_BINARY" ] && [ -e "$EXISTING_BINARY" ]; then
    backup_name="$(sanitize_path "$EXISTING_BINARY").$CURRENT_BACKUP_SUFFIX"
    run cp -a "$EXISTING_BINARY" "$BACKUP_DIR/$backup_name"
fi

if [ -e /usr/bin/cloud-node ]; then
    run cp -a /usr/bin/cloud-node "$BACKUP_DIR/usr_bin_cloud-node.$CURRENT_BACKUP_SUFFIX"
fi

if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
    run cp -a "/etc/systemd/system/${SERVICE_NAME}.service" "$BACKUP_DIR/${SERVICE_NAME}.service.$CURRENT_BACKUP_SUFFIX"
fi

if systemctl_available && systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
    if [ "$DRY_RUN" -eq 0 ]; then
        systemctl cat "$SERVICE_NAME" > "$BACKUP_DIR/${SERVICE_NAME}.service.cat.$CURRENT_BACKUP_SUFFIX.txt"
    else
        log "+ systemctl cat $SERVICE_NAME > $BACKUP_DIR/${SERVICE_NAME}.service.cat.$CURRENT_BACKUP_SUFFIX.txt"
    fi
fi

if [ "$DRY_RUN" -eq 0 ]; then
    {
        printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'repo=%s\n' "$REPO"
        printf 'version=%s\n' "$NORMALIZED_VERSION"
        printf 'asset=%s\n' "$ASSET_NAME"
        printf 'fresh_install=%s\n' "$IS_FRESH"
        printf 'existing_binary=%s\n' "${EXISTING_BINARY:-not found}"
        printf 'existing_runtime_guess=%s\n' "$EXISTING_RUNTIME"
        printf 'backup_suffix=%s\n' "$CURRENT_BACKUP_SUFFIX"
        if [ -n "$EXISTING_BINARY" ] && [ -f "$EXISTING_BINARY" ]; then
            printf 'existing_sha256=%s\n' "$(sha256_file "$EXISTING_BINARY")"
        fi
        printf 'install_dir=%s\n' "$INSTALL_DIR"
        printf 'install_binary=%s\n' "$INSTALL_BINARY"
        printf 'config_dir=%s\n' "$INSTALL_DIR/configs"
        printf 'data_dir=%s\n' "$INSTALL_DIR/data"
        printf 'logs_dir=%s\n' "$INSTALL_DIR/logs"
        printf 'geoip_dir=%s\n' "$GEOIP_DIR"
        if [ "$IS_FRESH" -eq 1 ]; then
            printf 'api_config=%s\n' "$INSTALL_DIR/configs/api_node.yaml"
            printf 'api_endpoints=%s\n' "$API_ENDPOINTS"
            printf 'node_id=%s\n' "$NODE_ID"
            printf 'timezone=%s\n' "${TIMEZONE:-keep current}"
        fi
    } > "$BACKUP_DIR/manifest.current.txt"
    if [ "$CURRENT_BACKUP_SUFFIX" = "go-original" ]; then
        cp -a "$BACKUP_DIR/manifest.current.txt" "$BACKUP_DIR/manifest.go-original.txt"
    fi
else
    log "+ write $BACKUP_DIR/manifest.current.txt"
fi

if [ "$DRY_RUN" -eq 0 ]; then
    download_checked "$DOWNLOAD_URL" "$TMP_DIR/$ASSET_NAME" "$ASSET_NAME"
    tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR"
    [ -f "$TMP_DIR/cloud-node" ] || die "release archive does not contain cloud-node" "Release 包中不含 cloud-node"
    if [ ! -f "$TMP_DIR/data/cloud-node-xdp-ebpf.o" ]; then
        warn "release archive does not contain data/cloud-node-xdp-ebpf.o; the binary will use its embedded eBPF object (the file is only needed for explicit xdp.ebpfObject overrides)" "Release 包中不含 data/cloud-node-xdp-ebpf.o；二进制将使用内嵌 eBPF 对象（该文件仅用于显式 xdp.ebpfObject 覆盖）"
    fi
else
    log "+ curl -fL --retry 3 --connect-timeout 20 -o $TMP_DIR/$ASSET_NAME $DOWNLOAD_URL"
    log "+ tar -xzf $TMP_DIR/$ASSET_NAME -C $TMP_DIR"
fi

# Stop and unregister the old deployment BEFORE overwriting binaries/unit files.
# This avoids restarting with a mixed Go process + Rust ExecStop/unit state.
stop_legacy_deployment
unregister_legacy_services

run mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/configs" "$INSTALL_DIR/data" "$INSTALL_DIR/logs"
migrate_runtime_layout
if [ "$DRY_RUN" -eq 0 ]; then
    install -m 0755 "$TMP_DIR/cloud-node" "$INSTALL_BINARY.new"
    mv -f "$INSTALL_BINARY.new" "$INSTALL_BINARY"
    if [ -f "$TMP_DIR/data/cloud-node-xdp-ebpf.o" ]; then
        install -m 0644 "$TMP_DIR/data/cloud-node-xdp-ebpf.o" "$INSTALL_DIR/data/cloud-node-xdp-ebpf.o.new"
        mv -f "$INSTALL_DIR/data/cloud-node-xdp-ebpf.o.new" "$INSTALL_DIR/data/cloud-node-xdp-ebpf.o"
    fi
else
    log "+ install -m 0755 $TMP_DIR/cloud-node $INSTALL_BINARY.new"
    log "+ mv -f $INSTALL_BINARY.new $INSTALL_BINARY"
    log "+ install -m 0644 $TMP_DIR/data/cloud-node-xdp-ebpf.o $INSTALL_DIR/data/cloud-node-xdp-ebpf.o"
fi

write_api_node_config
# Carry the xdp: block out of any legacy runtime.yaml/yml into
# api_node.yaml, write a fresh xdp block when none exists, then delete the
# obsolete runtime config files (backed up first). Order matters: migrate
# before write so an existing explicit xdp choice stays authoritative.
migrate_legacy_runtime_xdp
write_xdp_config
remove_legacy_runtime_configs

if [ "$DRY_RUN" -eq 0 ]; then
    (cd "$INSTALL_DIR" && "$INSTALL_BINARY" install)
else
    log "+ cd $INSTALL_DIR && $INSTALL_BINARY install"
fi

if [ "$DRY_RUN" -eq 0 ]; then
    validate_rust_service_registration
else
    log "+ validate service registration"
fi

download_geoip_files

if systemctl_available; then
    run systemctl daemon-reload
fi

if [ "$AUTO_START" = "yes" ]; then
    if [ "$DRY_RUN" -eq 0 ]; then
        if systemctl_available; then
            run systemctl restart "$SERVICE_NAME" || run systemctl start "$SERVICE_NAME"
        elif [ "$LEGACY_WAS_RUNNING" -eq 1 ] || [ "$SERVICE_WAS_ACTIVE" -eq 1 ]; then
            log "+ cd $INSTALL_DIR && $INSTALL_BINARY restart"
            (cd "$INSTALL_DIR" && "$INSTALL_BINARY" restart) || (cd "$INSTALL_DIR" && "$INSTALL_BINARY" start)
        else
            log "+ cd $INSTALL_DIR && $INSTALL_BINARY start"
            (cd "$INSTALL_DIR" && "$INSTALL_BINARY" start)
        fi
        verify_service_started 20
    else
        log "+ systemctl restart $SERVICE_NAME (or binary start)"
        log "+ verify ${SERVICE_NAME} is active"
    fi
fi

report_nic_xdp

ok "done" "完成"
log "previous binary backup: $BACKUP_DIR" "旧二进制备份: $BACKUP_DIR"
log "Rust binary installed at: $INSTALL_BINARY" "Rust 二进制已安装到: $INSTALL_BINARY"
if [ "$AUTO_START" != "yes" ]; then
    log "service was not started. To start later: systemctl start ${SERVICE_NAME} or cd ${INSTALL_DIR} && ${INSTALL_BINARY} start" "服务未启动。需要时执行: systemctl start ${SERVICE_NAME} 或 cd ${INSTALL_DIR} && ${INSTALL_BINARY} start"
fi
if [ "$LEGACY_WAS_RUNNING" -eq 1 ] || [ -n "${EXISTING_BINARY:-}" ]; then
    log "to roll back to the pre-migration backup: $0 --restore --restore-backup $BACKUP_DIR" "如需回滚到迁移前备份: $0 --restore --restore-backup $BACKUP_DIR"
fi
