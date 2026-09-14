#!/bin/sh
# Sync cloud-node-rust source to an authorized VPS task dir.
# Usage: vps_sync.sh <host>   (host must be in the authorized list)
# Transfers source only: excludes .git, targets, credentials, runtime data.
# Never builds locally. Remote task dir: /root/cloud-node-dev
set -eu
case "${1:-}" in
  162.251.92.110|162.251.92.120) HOST="$1" ;;
  *) echo "refusing unauthorized host: ${1:-<none>}" >&2; exit 2 ;;
esac
PD="${EDGE_DEV_PRIVATE_DIR:-$HOME/.codex/devin-edge-supervision.2C8iXj}"
SSH="$PD/vps-ssh"
SCP="$PD/vps-scp"
cd "$(dirname "$0")/../.."
[ -d src ] || { echo "not in cloud-node-rust" >&2; exit 2; }

$SSH "$HOST" 'mkdir -p /root/cloud-node-dev'

# Manifest of every file that will be shipped (remote integrity check).
MANIFEST=$(mktemp)
find . -type f \
  ! -path './.git/*' ! -name '.git' \
  ! -path './target/*' ! -path './*/target/*' \
  ! -path './data/*' ! -path './node_modules/*' \
  ! -name '*.o' ! -name '*.pyc' ! -name '*.pcap' \
  ! -name 'credentials*' ! -name '.env*' \
  \( ! -name '*.key' ! -name '*.pem' -o -path './pingora-main/*' \) \
  ! -name 'build.log' ! -name 'SOURCE-SHA256.txt' \
  | sed 's|^\./||' | sort > /tmp/cn-files.txt
xargs shasum -a 256 < /tmp/cn-files.txt > "$MANIFEST" 2>/dev/null || true
echo "files: $(wc -l < /tmp/cn-files.txt | tr -d ' ')"

rsync -az --delete -e "$SSH" \
  --exclude='.git' --exclude='target/' --exclude='*.o' --exclude='*.pyc' \
  --exclude='credentials*' --exclude='.env*' \
  --include='pingora-main/***' --exclude='*.key' --exclude='*.pem' \
  --exclude='data/' --exclude='node_modules/' --exclude='*.pcap' \
  --exclude='build.log' --exclude='SOURCE-SHA256.txt' \
  ./ "root@$HOST:/root/cloud-node-dev/"
$SCP "$MANIFEST" "root@$HOST:/root/cloud-node-dev/SOURCE-SHA256.txt"
$SSH "$HOST" 'cd /root/cloud-node-dev && shasum -a 256 -c SOURCE-SHA256.txt 2>&1 | grep -cv ": OK" || true'
echo "SYNCED -> $HOST:/root/cloud-node-dev"
