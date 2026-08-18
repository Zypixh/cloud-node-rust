#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# RocksDB's C++ bindings need g++ and libstdc++ on the linker path (rust-lld cannot
# resolve -lstdc++ with the default cc+lld setup on Ubuntu 24.04).
export CC="${CC:-gcc}"
export CXX="${CXX:-g++}"
export CXXFLAGS="${CXXFLAGS:--mpclmul -msse4.2}"
export RUSTFLAGS="${RUSTFLAGS:-} -C linker=g++ -C link-arg=-L/usr/lib/gcc/x86_64-linux-gnu/13"

RESULT_DIR="${RESULT_DIR:-$ROOT/target/storage-stress-results}"
mkdir -p "$RESULT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$RESULT_DIR/storage-compare-$STAMP.log"

echo "Storage compare run @ $STAMP" | tee "$LOG"
echo "Branch: $(git branch --show-current)" | tee -a "$LOG"
echo "Commit: $(git rev-parse --short HEAD)" | tee -a "$LOG"
echo | tee -a "$LOG"

SAMPLE_SIZE="${SAMPLE_SIZE:-30}"
MEASUREMENT_TIME="${MEASUREMENT_TIME:-5}"

echo "Building release benches (includes rust-rocksdb for comparison)..." | tee -a "$LOG"
cargo build --release --bench storage_bench 2>&1 | tee -a "$LOG"

echo "=== Mace vs RocksDB storage_bench ===" | tee -a "$LOG"
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
echo "Filter mace:   rg '/mace' $LOG"
echo "Filter rocksdb: rg '/rocksdb' $LOG"
