#!/bin/bash
# Sync cloud-node-rust source to an authorized VPS task dir.
# Usage: vps_sync.sh <host>   (host must be in the authorized list)
#
# R0 contract:
# - One file list drives rsync --files-from, the SHA256 manifest, and the
#   remote extra-file sweep — no separately maintained exclude rules.
# - Remote deletions only happen inside an owned task dir
#   (.cn-task-owner marker required).
# - Manifest generation and remote checksum verification fail hard.
# - Temp files live under a private mktemp dir; trap cleans them.
set -euo pipefail
case "${1:-}" in
  162.251.92.110|162.251.92.120) HOST="$1" ;;
  *) echo "refusing unauthorized host: ${1:-<none>}" >&2; exit 2 ;;
esac
PD="${EDGE_DEV_PRIVATE_DIR:-$HOME/.codex/devin-edge-supervision.2C8iXj}"
SSH="$PD/vps-ssh"
SCP="$PD/vps-scp"
cd "$(dirname "$0")/../.."
[ -d src ] || { echo "not in cloud-node-rust" >&2; exit 2; }

TASK_DIR=/root/cloud-node-dev
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
LIST="$TMPD/cn-files.txt"
MANIFEST="$TMPD/SOURCE-SHA256.txt"

# Single source of truth: every file that will be shipped.
find . -type f \
  ! -path './.git/*' ! -name '.git' \
  ! -path './target/*' ! -path './*/target/*' \
  ! -path './data/*' ! -path './node_modules/*' \
  ! -name '*.o' ! -name '*.pyc' ! -name '*.pcap' \
  ! -name 'credentials*' ! -name '.env*' \
  \( ! -name '*.key' ! -name '*.pem' -o -path './pingora-main/*' \) \
  ! -name 'build.log' ! -name 'test.log' ! -name 'SOURCE-SHA256.txt' \
  | sed 's|^\./||' | LC_ALL=C sort > "$LIST"
count=$(wc -l < "$LIST" | tr -d ' ')
[ "$count" -gt 100 ] || { echo "manifest too small ($count files) — refusing" >&2; exit 3; }
echo "files: $count"

# Manifest generation is not allowed to fail silently.
while IFS= read -r f; do shasum -a 256 "$f"; done < "$LIST" > "$MANIFEST"
[ "$(wc -l < "$MANIFEST" | tr -d ' ')" = "$count" ] || {
    echo "manifest incomplete" >&2; exit 3; }

# Task-dir ownership gate: a pre-existing dir without our marker is not
# ours — refuse before any transfer or deletion.
$SSH "$HOST" 'D=/root/cloud-node-dev
# Registered-host gate: a host we have never enrolled has no marker.
# Enrollment happens once through this authenticated channel; afterwards
# the marker must exist or the host is not ours to mutate.
M=/root/.cn-authorized-vps
if [ ! -f "$M" ]; then
  [ -d "$D" ] && { echo "refusing: task dir exists on unenrolled host" >&2; exit 3; }
  uname -s | grep -qx Linux || { echo "not Linux" >&2; exit 64; }
  echo cn-edge-validation > "$M"
fi
if [ -d "$D" ] && [ ! -f "$D/.cn-task-owner" ]; then
  echo "refusing: $D exists without .cn-task-owner marker" >&2; exit 3
fi
mkdir -p "$D" && echo cn-edge-validation > "$D/.cn-task-owner"'

# Transfer exactly the listed files.
rsync -az --files-from="$LIST" -e "$SSH" ./ "root@$HOST:$TASK_DIR/"
$SCP "$LIST" "root@$HOST:$TASK_DIR/cn-files.txt" >/dev/null
$SCP "$MANIFEST" "root@$HOST:$TASK_DIR/SOURCE-SHA256.txt" >/dev/null

# Remote: sweep extras not in the shipped list (manifest-driven delete,
# only inside the owned task dir), then verify every checksum. Any
# mismatch is a hard failure.
$SSH "$HOST" 'set -e; cd /root/cloud-node-dev
TD=$(mktemp -d); trap "rm -rf $TD" EXIT
find . -type f \
  ! -path "./target/*" ! -path "./*/target/*" ! -path "./data/*" \
  ! -name ".cn-task-owner" ! -name ".build.lock" \
  ! -name "cn-files.txt" ! -name "SOURCE-SHA256.txt" ! -name "*.log" \
  | sed "s|^\./||" | LC_ALL=C sort > "$TD/present.txt"
LC_ALL=C comm -23 "$TD/present.txt" cn-files.txt > "$TD/extras.txt"
while IFS= read -r f; do rm -f -- "$f"; done < "$TD/extras.txt"
extras=$(wc -l < "$TD/extras.txt" | tr -d " ")
# Checksum failure is a hard failure: capture the real rc, emit
# diagnostics, exit nonzero — never collapse to a count of bad lines.
rc=0
shasum -a 256 -c SOURCE-SHA256.txt > "$TD/verify.txt" 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "VERIFY FAILED: shasum rc=$rc" >&2
  grep -v ": OK$" "$TD/verify.txt" | head -20 >&2
  exit 4
fi
echo "verified: all checksums OK, $extras extras removed"'
echo "SYNCED -> $HOST:$TASK_DIR"
