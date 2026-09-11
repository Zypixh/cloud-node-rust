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
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS="${1:-$REPO/perf-results/$(date +%Y%m%d-%H%M%S)}"
PROXY_BIN="$REPO/target/release/bench-proxy"
SAMPLER="$REPO/scripts/perf/pid_sampler.py"
LOAD_MATRIX="$REPO/scripts/http_load_matrix.py"
ORIGIN="http://127.0.0.1:8081"
PROXY="http://127.0.0.1:8080"
DUR="${DUR:-15s}"
DUR_S="${DUR%s}"

mkdir -p "$RESULTS" "$RESULTS/urls"
cd "$RESULTS"

# ---- URL sets ---------------------------------------------------------------
for f in 1K 10K 100K 1M 10M; do
    echo "$PROXY/file-$f.bin" > "urls/proxy-$f.txt"
done
seq 0 4095 | awk -v p="$PROXY" '{print p "/miss/" $1 ".bin"}' > urls/proxy-miss.txt
seq 0 1999 | awk -v p="$PROXY" '{print p "/many/" $1 ".bin"}' > urls/proxy-many.txt
echo "$ORIGIN/file-1K.bin" > urls/origin-1K.txt

# ---- start bench-proxy ------------------------------------------------------
pkill -9 -x bench-proxy 2>/dev/null; sleep 1
# single instance owns data/metrics.mace + data/cache; wipe stale state
rm -rf "$REPO/data/cache" "$REPO/data/metrics.mace"
( cd "$REPO" && setsid "$PROXY_BIN" > "$RESULTS/bench-proxy.log" 2>&1 < /dev/null & )
for i in $(seq 1 50); do
    PROXY_PID=$(pgrep -x bench-proxy | head -1)
    [ -n "$PROXY_PID" ] && curl -sf -o /dev/null "$PROXY/index.html" && break
    sleep 0.2
done
if [ -z "${PROXY_PID:-}" ]; then echo "proxy failed to start"; cat "$RESULTS/bench-proxy.log"; exit 1; fi
NGINX_PID=$(pgrep -f 'nginx: master' | head -1)
NGINX_WORKER=$(pgrep -f 'nginx: worker' | head -1)
echo "proxy pid=$PROXY_PID nginx worker=$NGINX_WORKER"

run() { # name, extra oha args...
    local name="$1"; shift
    echo "=== $name"
    python3 "$SAMPLER" --pid "$PROXY_PID" --name proxy \
        ${NGINX_WORKER:+--pid "$NGINX_WORKER" --name nginx} \
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

# ---- D. cache-miss stream (1GB keyspace > 512MB cache) ------------------------
run D-miss-256k-c200 -c 200 --urls-from-file urls/proxy-miss.txt

# ---- E. connection churn vs keep-alive ----------------------------------------
run E-hit-1k-churn-c200 -c 200 --disable-keepalive "$PROXY/file-1K.bin" 2>/dev/null || true
python3 "$LOAD_MATRIX" --host 127.0.0.1 --port 8080 --path /file-1K.bin \
    --mode churn --concurrency 200 --duration "$DUR_S" \
    > "$RESULTS/E-churn-pymatrix.json" 2>/dev/null || true
python3 "$LOAD_MATRIX" --host 127.0.0.1 --port 8080 --path /file-1K.bin \
    --mode keepalive --concurrency 200 --duration "$DUR_S" \
    > "$RESULTS/E-keepalive-pymatrix.json" 2>/dev/null || true

# ---- F. mixed small files (warm, 2000 keys fits in cache) ---------------------
oha -n 4000 -c 50 --no-tui --urls-from-file urls/proxy-many.txt >/dev/null 2>&1  # warm all
run F-hit-many-c200 -c 200 --urls-from-file urls/proxy-many.txt

echo "results in $RESULTS"
kill $PROXY_PID 2>/dev/null
