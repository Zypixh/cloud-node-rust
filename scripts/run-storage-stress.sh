#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULT_DIR="${RESULT_DIR:-$ROOT/target/storage-stress-results}"
mkdir -p "$RESULT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$RESULT_DIR/storage-stress-$STAMP.log"

echo "Storage stress run @ $STAMP" | tee "$LOG"
echo "Branch: $(git branch --show-current)" | tee -a "$LOG"
echo "Commit: $(git rev-parse --short HEAD)" | tee -a "$LOG"
echo | tee -a "$LOG"

run_bench() {
  local name="$1"
  shift
  echo "=== bench: $name ===" | tee -a "$LOG"
  cargo bench --bench "$name" -- --noplot "$@" 2>&1 | tee -a "$LOG"
  echo | tee -a "$LOG"
}

echo "Building release benches..." | tee -a "$LOG"
cargo build --release --benches 2>&1 | tee -a "$LOG"

run_bench storage_bench
run_bench metrics_bench
run_bench hotpath_bench

echo "Results saved to $LOG"
