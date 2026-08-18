#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RESULT_DIR="${RESULT_DIR:-$ROOT/target/storage-stress-results}"
mkdir -p "$RESULT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$RESULT_DIR/storage-mace-$STAMP.log"

echo "Mace storage stress run @ $STAMP" | tee "$LOG"
echo "Branch: $(git branch --show-current)" | tee -a "$LOG"
echo "Commit: $(git rev-parse --short HEAD)" | tee -a "$LOG"
echo | tee -a "$LOG"

SAMPLE_SIZE="${SAMPLE_SIZE:-30}"
MEASUREMENT_TIME="${MEASUREMENT_TIME:-5}"

echo "=== Mace storage_bench ===" | tee -a "$LOG"
cargo bench --bench storage_bench -- --noplot \
  --sample-size "$SAMPLE_SIZE" \
  --measurement-time "$MEASUREMENT_TIME" \
  2>&1 | tee -a "$LOG"

echo | tee -a "$LOG"
echo "=== metrics_bench (hot path regression) ===" | tee -a "$LOG"
cargo bench --bench metrics_bench -- --noplot \
  --sample-size "$SAMPLE_SIZE" \
  --measurement-time "$MEASUREMENT_TIME" \
  2>&1 | tee -a "$LOG"

echo | tee -a "$LOG"
echo "Results saved to $LOG"
