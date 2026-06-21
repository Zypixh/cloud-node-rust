#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-Zypixh/cloud-node-rust}"
VERSION="${VERSION:-latest}"
SERVICE_NAME="${SERVICE_NAME:-cloud-node}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/cloud-node-rust-migration}"
INSTALL_DIR="${INSTALL_DIR:-}"
INSTALL_BINARY="${INSTALL_BINARY:-}"
START_MODE="${START_MODE:-preserve}"
LANGUAGE="${LANGUAGE:-}"
DOWNLOAD_GEOIP="${DOWNLOAD_GEOIP:-ask}"
GEOIP_DIR="${GEOIP_DIR:-}"
MODE="${MODE:-ask}"
RESTORE_BACKUP="${RESTORE_BACKUP:-}"
API_ENDPOINTS="${API_ENDPOINTS:-}"
NODE_ID="${NODE_ID:-}"
NODE_SECRET="${NODE_SECRET:-}"
TIMEZONE="${TIMEZONE:-}"
ASSUME_YES=0
DRY_RUN=0
ALLOW_FRESH=0
SKIP_TIMEZONE=0

usage() {
    cat <<'USAGE'
Install or upgrade the Rust CloudNode release over an existing cloud-node deployment,
or perform a fresh install on a new server.

The script:
  1. Asks for the interface language when running interactively.
  2. Finds the current cloud-node systemd ExecStart binary or command.
  3. Backs it up under a timestamped directory.
  4. Downloads the requested Rust release from GitHub; latest is the default.
  5. Optionally downloads GeoLite2 mmdb files from P3TERX/GeoLite.mmdb.
  6. Installs the Rust binary and re-registers the cloud-node command/service.

Usage:
  sudo scripts/install-rust-cloud-node.sh
  sudo scripts/install-rust-cloud-node.sh --fresh
  sudo scripts/install-rust-cloud-node.sh --restore

Run directly from GitHub:
  curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/Zypixh/cloud-node-rust/main/scripts/install-rust-cloud-node.sh | sudo bash -s -- --fresh --yes --api-endpoint http://127.0.0.1:8001 --node-id your-node-id --secret your-node-secret --geoip

Options:
  --install              Install, migrate, or upgrade to the Rust release.
                         Explicit mode; fails if no existing cloud-node is found.
  --upgrade              Alias for --install --version latest; upgrade an existing Rust node to latest.
  --fresh                Fresh install under /root/cloud-node and create configs/api_node.yaml.
  --restore              Restore the Go original from a previous backup.
  --restore-backup DIR   Restore from this backup dir. Default: latest backup.
  --list-backups         List available backup dirs and exit.
  --repo OWNER/REPO       GitHub repo. Default: Zypixh/cloud-node-rust
  --version VERSION      Release tag, for example v1.0.7. Default: latest
  --service NAME         systemd service name. Default: cloud-node
  --install-dir DIR      Runtime working directory. Default: existing runtime dir, or /opt/cloud-node-rust
  --install-binary PATH  Installed Rust binary path. Default: INSTALL_DIR/cloud-node-rust
  --backup-root DIR      Backup root. Default: /var/backups/cloud-node-rust-migration
  --lang zh|en           Interface language. Default: ask interactively.
  --geoip                Download GeoLite2 mmdb files from P3TERX/GeoLite.mmdb.
  --no-geoip             Do not download GeoLite2 mmdb files.
  --geoip-dir DIR        GeoIP target dir. Default: INSTALL_DIR/data.
  --api-endpoint URL     API RPC endpoint for fresh install. Can be repeated.
  --api-endpoints LIST   Comma-separated API RPC endpoints for fresh install.
  --node-id ID           nodeId for fresh install.
  --secret SECRET        secret for fresh install.
  --timezone TZ          Set system timezone during fresh install, e.g. Asia/Shanghai.
  --no-timezone          Do not prompt for or change system timezone during fresh install.
  --start                Restart/start service after install without prompting.
  --no-start             Do not restart/start service after install.
  --allow-fresh          Allow install when no existing cloud-node is found.
  --dry-run              Print actions without changing files.
  --yes                  Do not prompt for confirmation.
  --non-interactive      Alias for --yes.
  -h, --help             Show this help.

Environment variables with the same names are also supported:
  REPO, VERSION, SERVICE_NAME, INSTALL_DIR, INSTALL_BINARY, BACKUP_ROOT,
  START_MODE, LANGUAGE, DOWNLOAD_GEOIP, GEOIP_DIR, MODE, RESTORE_BACKUP,
  API_ENDPOINTS, NODE_ID, NODE_SECRET, TIMEZONE.
USAGE
}

is_zh() {
    [ "$LANGUAGE" = "zh" ] || [ "$LANGUAGE" = "zh_CN" ] || [ "$LANGUAGE" = "cn" ]
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

die_need_mode() {
    if is_zh; then
        die "默认模式需要交互式选择；请传 --fresh 全新安装，或传 --install/--upgrade 升级现有节点"
    else
        die "default mode needs an interactive choice; pass --fresh for a new install or --install/--upgrade to upgrade an existing node"
    fi
}

title() {
    printf '\n%s%s%s\n' "$BOLD" "CloudNode Rust Installer" "$RESET"
    printf '%s\n\n' "============================================================"
}

section() {
    printf '\n%s== %s ==%s\n' "$CYAN" "$1" "$RESET"
}

kv() {
    printf '  %s%-22s%s %s\n' "$DIM" "$1" "$RESET" "$2"
}

log() {
    printf '%s[cloud-node]%s %s\n' "$BLUE" "$RESET" "$*"
}

ok() {
    printf '%s[ok]%s %s\n' "$GREEN" "$RESET" "$*"
}

warn() {
    printf '%s[warn]%s %s\n' "$YELLOW" "$RESET" "$*"
}

die() {
    printf '%s[error]%s %s\n' "$RED" "$RESET" "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
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

prompt_language() {
    if [ -n "$LANGUAGE" ]; then
        case "$LANGUAGE" in
            zh|zh_CN|cn)
                LANGUAGE="zh"
                return
                ;;
            en|en_US)
                LANGUAGE="en"
                return
                ;;
            *)
                die "unsupported language: $LANGUAGE"
                ;;
        esac
    fi

    if [ "$ASSUME_YES" -eq 1 ]; then
        LANGUAGE="zh"
        return
    fi

    if prompt_available; then
        title
        printf '%s\n' "请选择语言 / Select language"
        printf '  %s1)%s 中文\n' "$BOLD" "$RESET"
        printf '  %s2)%s English\n' "$BOLD" "$RESET"
        printf '\n输入序号 / Enter choice %s[1]%s: ' "$DIM" "$RESET"
        read_prompt lang_choice || lang_choice=""
        case "${lang_choice:-1}" in
            1|zh|ZH|中文)
                LANGUAGE="zh"
                ;;
            2|en|EN|English|english)
                LANGUAGE="en"
                ;;
            *)
                LANGUAGE="zh"
                ;;
        esac
    else
        LANGUAGE="zh"
    fi
}

prompt_mode() {
    case "$MODE" in
        install|fresh|restore|list-backups)
            return
            ;;
        ask)
            ;;
        *)
            die "invalid MODE: $MODE"
            ;;
    esac

    if [ "$ASSUME_YES" -eq 1 ] || ! prompt_available; then
        die_need_mode
    fi

    section "$(is_zh && printf '选择操作' || printf 'Choose Action')"
    if is_zh; then
        printf '  %s1)%s 安装/升级现有 cloud-node 到最新 Rust 版\n' "$BOLD" "$RESET"
        printf '  %s2)%s 全新安装 Rust 版到 /root/cloud-node\n' "$BOLD" "$RESET"
        printf '  %s3)%s 从备份恢复 Go 原版\n' "$BOLD" "$RESET"
        printf '\n输入序号 %s[1]%s: ' "$DIM" "$RESET"
    else
        printf '  %s1)%s Install/upgrade existing cloud-node to latest Rust\n' "$BOLD" "$RESET"
        printf '  %s2)%s Fresh install to /root/cloud-node\n' "$BOLD" "$RESET"
        printf '  %s3)%s Restore Go original from backup\n' "$BOLD" "$RESET"
        printf '\nEnter choice %s[1]%s: ' "$DIM" "$RESET"
    fi
    read_prompt mode_choice || die_need_mode
    case "${mode_choice:-1}" in
        1|install|INSTALL)
            MODE="install"
            ;;
        2|fresh|FRESH|new|NEW)
            MODE="fresh"
            ;;
        3|restore|RESTORE)
            MODE="restore"
            ;;
        *)
            MODE="install"
            ;;
    esac
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

    if is_zh; then
        printf '%s %s ' "$prompt_zh" "$prompt_suffix"
    else
        printf '%s %s ' "$prompt_en" "$prompt_suffix"
    fi
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

    if is_zh; then
        printf '%s' "$prompt_zh" >&2
    else
        printf '%s' "$prompt_en" >&2
    fi
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

collect_fresh_timezone_config() {
    local current_timezone=""
    if [ "$MODE" != "fresh" ] || [ "$SKIP_TIMEZONE" -eq 1 ]; then
        return
    fi

    current_timezone="$(detect_system_timezone || true)"
    if [ -z "$current_timezone" ]; then
        current_timezone="UTC"
    fi

    if [ -z "$TIMEZONE" ] && prompt_available && [ "$ASSUME_YES" -eq 0 ]; then
        section "$(is_zh && printf '系统时区' || printf 'System Timezone')"
        if is_zh; then
            printf '当前检测到的时区：%s\n' "$current_timezone"
            printf '可填写例如 Asia/Shanghai、Asia/Hong_Kong、UTC；留空保持当前设置。\n'
        else
            printf 'Detected timezone: %s\n' "$current_timezone"
            printf 'Examples: Asia/Shanghai, Asia/Hong_Kong, UTC. Leave blank to keep current.\n'
        fi
        TIMEZONE="$(prompt_text \
            "系统时区" \
            "System timezone" \
            "$current_timezone")"
    fi

    if [ -n "$TIMEZONE" ] && ! validate_timezone_name "$TIMEZONE"; then
        die "invalid timezone or missing zoneinfo file: $TIMEZONE"
    fi
}

apply_fresh_timezone() {
    local zoneinfo=""
    if [ "$MODE" != "fresh" ] || [ "$SKIP_TIMEZONE" -eq 1 ] || [ -z "$TIMEZONE" ]; then
        return
    fi

    zoneinfo="/usr/share/zoneinfo/$TIMEZONE"
    validate_timezone_name "$TIMEZONE" || die "invalid timezone or missing zoneinfo file: $TIMEZONE"

    if [ "$DRY_RUN" -eq 1 ]; then
        log "+ timedatectl set-timezone $TIMEZONE || ln -sfn $zoneinfo /etc/localtime"
        log "+ write /etc/timezone"
        return
    fi

    if command -v timedatectl >/dev/null 2>&1 && timedatectl set-timezone "$TIMEZONE"; then
        ok "system timezone set to $TIMEZONE"
        return
    fi

    ln -sfn "$zoneinfo" /etc/localtime
    printf '%s\n' "$TIMEZONE" > /etc/timezone
    ok "system timezone set to $TIMEZONE"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --install)
            MODE="install"
            shift
            ;;
        --upgrade)
            MODE="install"
            VERSION="latest"
            shift
            ;;
        --fresh|--new)
            MODE="fresh"
            ALLOW_FRESH=1
            shift
            ;;
        --restore)
            MODE="restore"
            shift
            ;;
        --restore-backup)
            RESTORE_BACKUP="${2:?missing restore backup dir}"
            MODE="restore"
            shift 2
            ;;
        --list-backups)
            MODE="list-backups"
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
        --lang)
            LANGUAGE="${2:?missing language}"
            shift 2
            ;;
        --geoip)
            DOWNLOAD_GEOIP="yes"
            shift
            ;;
        --no-geoip)
            DOWNLOAD_GEOIP="no"
            shift
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
        --no-timezone)
            SKIP_TIMEZONE=1
            shift
            ;;
        --start)
            START_MODE="always"
            shift
            ;;
        --no-start)
            START_MODE="never"
            shift
            ;;
        --allow-fresh)
            ALLOW_FRESH=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --yes)
            ASSUME_YES=1
            shift
            ;;
        --non-interactive)
            ASSUME_YES=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

prompt_language

prompt_mode

if [ "$MODE" = "fresh" ]; then
    ALLOW_FRESH=1
    if [ -z "$INSTALL_DIR" ]; then
        INSTALL_DIR="/root/cloud-node"
    fi
fi

if [ "$MODE" != "list-backups" ]; then
    [ "$(uname -s)" = "Linux" ] || [ "$DRY_RUN" -eq 1 ] || die "this installer supports Linux only"
fi

need_cmd mktemp
need_cmd date
need_cmd cp
need_cmd mkdir
need_cmd install
need_cmd uname
if [ "$MODE" = "install" ] || [ "$MODE" = "fresh" ]; then
    need_cmd curl
    need_cmd tar
fi

if [ "$MODE" != "list-backups" ] && [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    die "root is required; run with sudo"
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

detect_runtime() {
    local path="$1"
    if [ ! -f "$path" ]; then
        printf 'non-regular-file\n'
        return
    fi
    if command -v strings >/dev/null 2>&1 && strings "$path" 2>/dev/null | grep -q 'Go buildinf:'; then
        printf 'go\n'
    elif command -v strings >/dev/null 2>&1 && strings "$path" 2>/dev/null | grep -q 'cloud-node-rust'; then
        printf 'rust\n'
    else
        printf 'unknown\n'
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
                die "x86_64 systems with glibc older than 2.28 are not supported by official release assets"
            elif ! cpu_has_flag sse4_2; then
                die "x86_64 CPU without SSE4.2 is not supported by official release assets"
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
            die "unsupported architecture: $arch"
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
    printf 'https://github.com/P3TERX/GeoLite.mmdb/raw/download/%s\n' "$name"
}

download_geoip_files() {
    local names="GeoLite2-City.mmdb GeoLite2-ASN.mmdb GeoLite2-Country.mmdb"
    local name=""
    local url=""
    local target=""
    local tmp_target=""

    run mkdir -p "$GEOIP_DIR"
    for name in $names; do
        url="$(geoip_url_for "$name")"
        target="$GEOIP_DIR/$name"
        tmp_target="$TMP_DIR/$name"
        if [ -e "$target" ]; then
            run cp -a "$target" "$BACKUP_DIR/$name.geoip-original"
        fi
        if [ "$DRY_RUN" -eq 0 ]; then
            log "downloading GeoIP: $url"
            curl -fL --retry 3 --connect-timeout 20 -o "$tmp_target" "$url"
            install -m 0644 "$tmp_target" "$target"
        else
            log "+ curl -fL --retry 3 --connect-timeout 20 -o $tmp_target $url"
            log "+ install -m 0644 $tmp_target $target"
        fi
    done
}

collect_fresh_api_config() {
    if [ "$MODE" != "fresh" ]; then
        return
    fi

    if prompt_available && [ "$ASSUME_YES" -eq 0 ]; then
        section "$(is_zh && printf 'API 连接配置' || printf 'API Connection Config')"
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

    [ -n "$API_ENDPOINTS" ] || die "fresh install requires --api-endpoint or --api-endpoints"
    [ -n "$NODE_ID" ] || die "fresh install requires --node-id"
    [ -n "$NODE_SECRET" ] || die "fresh install requires --secret"
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
        if [ -e "$source_dir/blocked_ips.json" ] && [ ! -e "$INSTALL_DIR/data/blocked_ips.json" ]; then
            run cp -a "$source_dir/blocked_ips.json" "$INSTALL_DIR/data/blocked_ips.json"
        fi
        if [ -e "$source_dir/metrics.db" ] && [ ! -e "$INSTALL_DIR/data/metrics.db" ]; then
            run cp -a "$source_dir/metrics.db" "$INSTALL_DIR/data/metrics.db"
        fi
    done
}

write_api_node_config() {
    local config_path="$INSTALL_DIR/configs/api_node.yaml"
    local endpoint=""
    local endpoint_array=()
    local first=1
    local list="[ "

    if [ "$MODE" != "fresh" ]; then
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
    [ "$first" -eq 0 ] || die "fresh install requires at least one non-empty API endpoint"

    run mkdir -p "$INSTALL_DIR/configs"
    if [ -e "$config_path" ]; then
        run cp -a "$config_path" "$BACKUP_DIR/api_node.yaml.config-original"
    fi

    if [ "$DRY_RUN" -eq 0 ]; then
        {
            printf 'rpc.endpoints: %s\n' "$list"
            printf 'nodeId: %s\n' "$(yaml_quote "$NODE_ID")"
            printf 'secret: %s\n' "$(yaml_quote "$NODE_SECRET")"
        } > "$config_path"
        chmod 0600 "$config_path" 2>/dev/null || true
    else
        log "+ write $config_path"
        printf '  rpc.endpoints: %s\n' "$list"
        printf '  nodeId: %s\n' "$(yaml_quote "$NODE_ID")"
        printf '  secret: ******\n'
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
    section "$(is_zh && printf '可用备份' || printf 'Available Backups')"
    if ! backup_dirs | grep -q .; then
        if is_zh; then
            printf '  未找到备份目录：%s\n' "$BACKUP_ROOT"
        else
            printf '  No backups found under: %s\n' "$BACKUP_ROOT"
        fi
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

    mapfile -t backups < <(restore_backup_dirs)
    [ "${#backups[@]}" -gt 0 ] || die "no backups found under $BACKUP_ROOT"

    if [ "$ASSUME_YES" -eq 1 ] || ! prompt_available; then
        printf '%s\n' "${backups[0]}"
        return
    fi

    section "$(is_zh && printf '选择恢复备份' || printf 'Choose Restore Backup')"
    idx=1
    for backup in "${backups[@]}"; do
        printf '  %s%d)%s %s\n' "$BOLD" "$idx" "$RESET" "$backup"
        idx=$((idx + 1))
    done
    if is_zh; then
        printf '\n输入序号 %s[1]%s: ' "$DIM" "$RESET"
    else
        printf '\nEnter choice %s[1]%s: ' "$DIM" "$RESET"
    fi
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
        warn "missing backup for $label: $source"
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
    [ -d "$backup_dir" ] || die "restore backup dir does not exist: $backup_dir"

    section "$(is_zh && printf '恢复摘要' || printf 'Restore Summary')"
    kv "backup" "$backup_dir"
    kv "service" "$SERVICE_NAME"
    kv "start mode" "$START_MODE"

    if [ "$ASSUME_YES" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        ask_yes_no "确认从该备份恢复 Go 原版吗？" "Restore Go original from this backup?" "no" || die "aborted"
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

    if systemctl_available; then
        run systemctl daemon-reload
    fi

    case "$START_MODE" in
        always)
            if systemctl_available; then
                run systemctl restart "$SERVICE_NAME"
            fi
            ;;
        preserve)
            if [ "$service_was_active" -eq 1 ] && systemctl_available; then
                run systemctl start "$SERVICE_NAME"
            fi
            ;;
        never)
            ;;
        *)
            die "invalid START_MODE: $START_MODE"
            ;;
    esac

    ok "restore completed"
    log "current Rust files backed up at: $RESTORE_CURRENT_DIR"
}

confirm_install() {
    if [ "$ASSUME_YES" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
        return
    fi
    ask_yes_no "确认开始安装 Rust CloudNode 吗？" "Proceed with Rust CloudNode install?" "no" || die "aborted"
}

if [ "$MODE" = "list-backups" ]; then
    list_backups
    exit 0
fi

if [ "$MODE" = "restore" ]; then
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
if [ "$MODE" = "fresh" ]; then
    ALLOW_FRESH=1
fi
if [ -z "$INSTALL_DIR" ]; then
    if [ "$MODE" = "fresh" ]; then
        INSTALL_DIR="/root/cloud-node"
    elif [ -n "$EXISTING_RUNTIME_DIR" ]; then
        INSTALL_DIR="$EXISTING_RUNTIME_DIR"
    else
        INSTALL_DIR="/opt/cloud-node-rust"
    fi
fi
if [ -z "$INSTALL_BINARY" ]; then
    INSTALL_BINARY="$INSTALL_DIR/cloud-node-rust"
fi
if [ -z "$GEOIP_DIR" ]; then
    GEOIP_DIR="$INSTALL_DIR/data"
fi

case "$DOWNLOAD_GEOIP" in
    ask|yes|no)
        ;;
    *)
        die "invalid DOWNLOAD_GEOIP: $DOWNLOAD_GEOIP"
        ;;
esac

if [ "$DOWNLOAD_GEOIP" = "ask" ]; then
    if [ "$ASSUME_YES" -eq 1 ] || ! prompt_available; then
        DOWNLOAD_GEOIP="no"
    elif ask_yes_no \
        "是否从 https://github.com/P3TERX/GeoLite.mmdb 下载 GeoIP 库？" \
        "Download GeoIP databases from https://github.com/P3TERX/GeoLite.mmdb?" \
        "no"
    then
        DOWNLOAD_GEOIP="yes"
    else
        DOWNLOAD_GEOIP="no"
    fi
fi

collect_fresh_api_config
collect_fresh_timezone_config

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
if [ -z "$EXISTING_BINARY" ] && [ "$ALLOW_FRESH" -eq 0 ]; then
    die "no existing cloud-node was found; pass --allow-fresh for a new install"
fi

section "$(is_zh && printf '安装摘要' || printf 'Install Summary')"
kv "mode" "$MODE"
kv "repository" "$REPO"
kv "version" "$NORMALIZED_VERSION"
kv "asset" "$ASSET_NAME"
kv "existing cloud-node" "${EXISTING_BINARY:-not found}"
kv "existing runtime" "$EXISTING_RUNTIME"
kv "install dir" "$INSTALL_DIR"
kv "install binary" "$INSTALL_BINARY"
kv "config dir" "$INSTALL_DIR/configs"
kv "data dir" "$INSTALL_DIR/data"
kv "logs dir" "$INSTALL_DIR/logs"
kv "backup dir" "$BACKUP_DIR"
kv "service" "$SERVICE_NAME"
kv "start mode" "$START_MODE"
kv "download GeoIP" "$DOWNLOAD_GEOIP"
if [ "$DOWNLOAD_GEOIP" = "yes" ]; then
    kv "GeoIP dir" "$GEOIP_DIR"
fi
if [ "$MODE" = "fresh" ]; then
    kv "api endpoints" "$API_ENDPOINTS"
    kv "nodeId" "$NODE_ID"
    kv "secret" "******"
    if [ "$SKIP_TIMEZONE" -eq 1 ]; then
        kv "timezone" "keep current"
    else
        kv "timezone" "${TIMEZONE:-keep current}"
    fi
fi

if [ "$EXISTING_RUNTIME" = "rust" ] && [ "$NORMALIZED_VERSION" = "latest" ]; then
    ok "existing Rust cloud-node will be upgraded to the latest release."
elif [ "$EXISTING_RUNTIME" = "rust" ]; then
    ok "existing Rust cloud-node will be upgraded to the selected release."
elif [ "$EXISTING_RUNTIME" = "unknown" ]; then
    warn "existing binary runtime is unknown; it will still be backed up before install."
fi

confirm_install
apply_fresh_timezone

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
        printf 'mode=%s\n' "$MODE"
        printf 'repo=%s\n' "$REPO"
        printf 'version=%s\n' "$NORMALIZED_VERSION"
        printf 'asset=%s\n' "$ASSET_NAME"
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
        printf 'download_geoip=%s\n' "$DOWNLOAD_GEOIP"
        printf 'geoip_dir=%s\n' "$GEOIP_DIR"
        if [ "$MODE" = "fresh" ]; then
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

SERVICE_WAS_ACTIVE=0
if systemctl_available && systemctl is-active --quiet "$SERVICE_NAME"; then
    SERVICE_WAS_ACTIVE=1
fi

log "downloading: $DOWNLOAD_URL"
if [ "$DRY_RUN" -eq 0 ]; then
    curl -fL --retry 3 --connect-timeout 20 -o "$TMP_DIR/$ASSET_NAME" "$DOWNLOAD_URL"
    tar -xzf "$TMP_DIR/$ASSET_NAME" -C "$TMP_DIR"
    [ -f "$TMP_DIR/cloud-node" ] || die "release archive does not contain cloud-node"
else
    log "+ curl -fL --retry 3 --connect-timeout 20 -o $TMP_DIR/$ASSET_NAME $DOWNLOAD_URL"
    log "+ tar -xzf $TMP_DIR/$ASSET_NAME -C $TMP_DIR"
fi

run mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/configs" "$INSTALL_DIR/data" "$INSTALL_DIR/logs"
migrate_runtime_layout
if [ "$DRY_RUN" -eq 0 ]; then
    install -m 0755 "$TMP_DIR/cloud-node" "$INSTALL_BINARY.new"
    mv -f "$INSTALL_BINARY.new" "$INSTALL_BINARY"
else
    log "+ install -m 0755 $TMP_DIR/cloud-node $INSTALL_BINARY.new"
    log "+ mv -f $INSTALL_BINARY.new $INSTALL_BINARY"
fi

write_api_node_config

if [ "$DRY_RUN" -eq 0 ]; then
    (cd "$INSTALL_DIR" && "$INSTALL_BINARY" install)
else
    log "+ cd $INSTALL_DIR && $INSTALL_BINARY install"
fi

if [ "$DOWNLOAD_GEOIP" = "yes" ]; then
    download_geoip_files
fi

if systemctl_available; then
    run systemctl daemon-reload
fi

RESTART_SERVICE=0
case "$START_MODE" in
    always)
        RESTART_SERVICE=1
        ;;
    preserve)
        if [ "$ASSUME_YES" -eq 0 ] && prompt_available; then
            if [ "$SERVICE_WAS_ACTIVE" -eq 1 ]; then
                if ask_yes_no "安装/升级已完成，是否现在重启 ${SERVICE_NAME} 进程？" "Install/upgrade completed. Restart ${SERVICE_NAME} now?" "yes"; then
                    RESTART_SERVICE=1
                fi
            else
                if ask_yes_no "安装/升级已完成，是否现在启动 ${SERVICE_NAME} 进程？" "Install/upgrade completed. Start ${SERVICE_NAME} now?" "no"; then
                    RESTART_SERVICE=1
                fi
            fi
        elif [ "$SERVICE_WAS_ACTIVE" -eq 1 ]; then
            RESTART_SERVICE=1
        fi
        ;;
    never)
        ;;
    *)
        die "invalid START_MODE: $START_MODE"
        ;;
esac

if [ "$RESTART_SERVICE" -eq 1 ]; then
    if [ "$DRY_RUN" -eq 0 ]; then
        if systemctl_available; then
            if [ "$SERVICE_WAS_ACTIVE" -eq 1 ]; then
                run systemctl restart "$SERVICE_NAME"
            else
                run systemctl start "$SERVICE_NAME"
            fi
        elif [ "$SERVICE_WAS_ACTIVE" -eq 1 ]; then
            log "+ cd $INSTALL_DIR && $INSTALL_BINARY restart"
            (cd "$INSTALL_DIR" && "$INSTALL_BINARY" restart)
        else
            log "+ cd $INSTALL_DIR && $INSTALL_BINARY start"
            (cd "$INSTALL_DIR" && "$INSTALL_BINARY" start)
        fi
    elif systemctl_available; then
        if [ "$SERVICE_WAS_ACTIVE" -eq 1 ]; then
            log "+ systemctl restart $SERVICE_NAME"
        else
            log "+ systemctl start $SERVICE_NAME"
        fi
    elif [ "$SERVICE_WAS_ACTIVE" -eq 1 ]; then
        log "+ cd $INSTALL_DIR && $INSTALL_BINARY restart"
    else
        log "+ cd $INSTALL_DIR && $INSTALL_BINARY start"
    fi
fi

log "done"
log "previous binary backup: $BACKUP_DIR"
log "Rust binary installed at: $INSTALL_BINARY"
