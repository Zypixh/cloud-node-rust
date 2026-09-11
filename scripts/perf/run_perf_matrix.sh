#!/usr/bin/env bash
# Full performance matrix for bench-proxy (Pingora + cache) fronting a local nginx origin.
#
# Topology:  loadgen -> bench-proxy :8080 -> nginx :8081 -> /srv/perf-origin
#
# Usage:
#   scripts/perf/run_perf_matrix.sh [results-dir]
#
# Requires: nginx site perf-origin on 127.0.0.1:8081, target/release/bench-proxy,
#           oha, python3, curl.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS="${1:-$REPO/perf-results/$(date +%Y%m%d-%H%M%S)}"
PROXY_BIN="$REPO/target/release/bench-proxy"
SAMPLER="$REPO/scripts/perf/pid_sampler.py"
LOAD_MATRIX="$REPO/scripts/http_load_matrix.py"
ORIGIN="http://127.0.0.1:8081"
PROXY="http://127.0.0.1:8080"
DUR="${DUR:-15s}"
DUR_S="${DUR%s}"
# D-group request cap: unique miss keys at ~256KB each. Keep below both the
# L2 disk budget and available scratch space (default 32768 * 256KB ~= 8GB).
MISS_REQUESTS="${MISS_REQUESTS:-32768}"

mkdir -p "$RESULTS/urls"
# Canonicalize before use so every output path is absolute.
RESULTS="$(cd "$RESULTS" && pwd -P)"

# Isolated node home: bench-proxy resolves data/, metrics.mace and the cache
# root under CLOUD_NODE_HOME. Never touch the repository's own runtime state.
BENCH_HOME="$RESULTS/node-home"
mkdir -p "$BENCH_HOME"

# ---- URL sets ---------------------------------------------------------------
for f in 1K 10K 100K 1M 10M; do
    echo "$PROXY/file-$f.bin" > "$RESULTS/urls/proxy-$f.txt"
done
seq 0 1999 | awk -v p="$PROXY" '{print p "/many/" $1 ".bin"}' > "$RESULTS/urls/proxy-many.txt"
echo "$ORIGIN/file-1K.bin" > "$RESULTS/urls/origin-1K.txt"

# ---- start bench-proxy ------------------------------------------------------
pkill -9 -x bench-proxy 2>/dev/null || true; sleep 1
rm -rf "$BENCH_HOME/data"
( cd "$BENCH_HOME" && setsid env CLOUD_NODE_HOME="$BENCH_HOME" "$PROXY_BIN" \
    > "$RESULTS/bench-proxy.log" 2>&1 < /dev/null & )
PROXY_PID=""
READY=0
for _ in $(seq 1 50); do
    PROXY_PID=$(pgrep -x bench-proxy | head -1 || true)
    if [ -n "$PROXY_PID" ] && curl -sf -o /dev/null "$PROXY/index.html"; then
        READY=1
        break
    fi
    sleep 0.2
done
if [ -z "$PROXY_PID" ] || [ "$READY" != 1 ]; then
    echo "proxy failed readiness check"
    cat "$RESULTS/bench-proxy.log"
    exit 1
fi
# Sample every nginx worker; the sampler aggregates them under one name.
mapfile -t NGINX_WORKERS < <(pgrep -f 'nginx: worker' || true)
echo "proxy pid=$PROXY_PID nginx workers=${NGINX_WORKERS[*]:-none}"

run() { # name, extra oha args...
    local name="$1"; shift
    echo "=== $name"
    local sampler_args=(--pid "$PROXY_PID" --name proxy)
    local w
    for w in "${NGINX_WORKERS[@]}"; do
        sampler_args+=(--pid "$w" --name nginx)
    done
    python3 "$SAMPLER" "${sampler_args[@]}" \
        --duration "$DUR_S" --interval 0.5 --out "$RESULTS/$name.sys.json" &
    local spid=$!
    sleep 0.3
    oha -z "$DUR" --no-tui --output-format json "$@" > "$RESULTS/$name.oha.json" 2>"$RESULTS/$name.oha.err"
    wait $spid
    python3 - "$RESULTS/$name.oha.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
s=d.get("summary",{})
print(f"  qps={s.get('requestsPerSec','?')}  p50={d.get('latencyPercentiles',{}).get('p50','?')}s  p99={d.get('latencyPercentiles',{}).get('p99','?')}s  success={s.get('successRate','?')}")
PY
}

warm() { oha -n 300 -c 20 --no-tui "$1" >/dev/null 2>&1; }

# ---- A. origin baseline ------------------------------------------------------
run A-origin-1k-c200 -c 200 "$ORIGIN/file-1K.bin"

# ---- B. warm-cache QPS saturation sweep --------------------------------------
warm "$PROXY/file-1K.bin"
for c in 50 200 500 1000; do
    run B-hit-1k-c$c -c $c "$PROXY/file-1K.bin"
done

# ---- C. warm-cache size gradient ---------------------------------------------
for f in 10K 100K 1M 10M; do
    warm "$PROXY/file-$f.bin"
    run C-hit-$f-c200 -c 200 "$PROXY/file-$f.bin"
done

# ---- D. cache-miss stream -----------------------------------------------------
# Unique key per request (rand-regex path) so every request is a real miss:
# the L1/L2 caches can never serve a key twice. The nginx /miss/ location maps
# any sub-path to a fixed 256KB body, so this exercises the full
# origin-fetch + disk-write + metadata-publish pipeline. -n bounds total
# bytes written to the isolated cache volume.
run D-miss-256k-c200 -c 200 -n "$MISS_REQUESTS" \
    --rand-regex-url "$PROXY/miss/[a-z0-9]{16}"

# ---- E. connection churn vs keep-alive ----------------------------------------
run E-hit-1k-churn-c200 -c 200 --disable-keepalive "$PROXY/file-1K.bin" 2>/dev/null || true
python3 "$LOAD_MATRIX" --host 127.0.0.1 --port 8080 --path /file-1K.bin \
    --mode churn --concurrency 200 --duration "$DUR_S" \
    > "$RESULTS/E-churn-pymatrix.json" 2>/dev/null || true
python3 "$LOAD_MATRIX" --host 127.0.0.1 --port 8080 --path /file-1K.bin \
    --mode keepalive --concurrency 200 --duration "$DUR_S" \
    > "$RESULTS/E-keepalive-pymatrix.json" 2>/dev/null || true

# ---- F. mixed small files (warm, 2000 keys fits in cache) ---------------------
oha -n 4000 -c 50 --no-tui --urls-from-file "$RESULTS/urls/proxy-many.txt" >/dev/null 2>&1  # warm all
run F-hit-many-c200 -c 200 --urls-from-file "$RESULTS/urls/proxy-many.txt"

echo "results in $RESULTS"
kill "$PROXY_PID" 2>/dev/null || true
