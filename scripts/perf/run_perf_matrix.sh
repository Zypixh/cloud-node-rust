#!/usr/bin/env bash
# Full performance matrix for bench-proxy (Pingora + cache) fronting a local nginx origin.
#
# Topology:  loadgen -> bench-proxy -> nginx :8081 -> /srv/perf-origin
#            (origin stays plain HTTP/1.1 regardless of the downstream protocol)
#
# Usage:
#   PROTO=h1|h1s|h2|h3 scripts/perf/run_perf_matrix.sh [results-dir]
#
#   h1  = cleartext HTTP/1.1 on :8080            (oha)
#   h1s = HTTP/1.1 over TLS on :8443             (oha --insecure)
#   h2  = HTTP/2 over TLS on :8443 (ALPN h2)     (oha --http-version 2 -p $STREAMS_PER_CONN)
#   h3  = HTTP/3 over QUIC on :8443/udp          (bench-h3-load, --conns x --streams)
#
# h2/h3 measure with STREAMS_PER_CONN (default 4) multiplexed streams per
# connection; the -c values passed below then mean *in-flight concurrency* and
# are divided across that many connections. TLS rounds need BENCH_TLS_CERT and
# BENCH_TLS_KEY PEMs (generated under $RESULTS/tls if missing).
#
# Requires: nginx site perf-origin on 127.0.0.1:8081, target/release/bench-proxy,
#           oha, python3, curl.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS="${1:-$REPO/perf-results/$(date +%Y%m%d-%H%M%S)}"
PROTO="${PROTO:-h1}"
PROXY_BIN="$REPO/target/release/bench-proxy"
H3_BIN="$REPO/target/release/bench-h3-load"
SAMPLER="$REPO/scripts/perf/pid_sampler.py"
LOAD_MATRIX="$REPO/scripts/http_load_matrix.py"
ORIGIN="http://127.0.0.1:8081"
STREAMS_PER_CONN="${STREAMS_PER_CONN:-4}"
case "$PROTO" in
    h1)  PROXY="http://127.0.0.1:8080" ;;
    h1s) PROXY="https://127.0.0.1:8443" ;;
    h2)  PROXY="https://127.0.0.1:8443" ;;
    h3)  PROXY="https://127.0.0.1:8443" ;;
    *)   echo "unknown PROTO=$PROTO (h1|h1s|h2|h3)"; exit 1 ;;
esac
DUR="${DUR:-15s}"
DUR_S="${DUR%s}"
# D2-group keyspace: a fixed set of 256KB origin files larger than L1 (512MB)
# but smaller than L2, so after warmup this group measures the disk-hit path.
MISS_KEYS="${MISS_KEYS:-4096}"
# D-group request cap: unique miss keys at ~256KB each; bounds total bytes
# written to the isolated cache volume (default 32768 * 256KB ~= 8GB).
MISS_REQUESTS="${MISS_REQUESTS:-32768}"
# Cap the bench L2 budget so a miss-stream run cannot grow the cache volume
# without bound. The purger enforces this asynchronously; it only needs to be
# well under the free scratch space.
BENCH_DISK_MAX_BYTES="${BENCH_DISK_MAX_BYTES:-$((16 * 1024 * 1024 * 1024))}"

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
seq 0 $((MISS_KEYS - 1)) | awk -v p="$PROXY" '{print p "/miss/" $1 ".bin"}' > "$RESULTS/urls/proxy-miss.txt"
echo "$ORIGIN/file-1K.bin" > "$RESULTS/urls/origin-1K.txt"
# h1 (cleartext, :8080) copies used only for cache warmup — the cache is
# protocol-agnostic, so warming over h1 is identical work with zero TLS cost.
seq 0 1999 | awk '{print "http://127.0.0.1:8080/many/" $1 ".bin"}' > "$RESULTS/urls/proxy-many-warm.txt"
seq 0 $((MISS_KEYS - 1)) | awk '{print "http://127.0.0.1:8080/miss/" $1 ".bin"}' > "$RESULTS/urls/proxy-miss-warm.txt"
# h3-only D-group keyspace: unique random keys larger than the L2 budget so
# repeats after a full pass still miss (bench-h3-load is duration-bounded, so
# the request-count cap used for oha does not apply).
if [ "$PROTO" = h3 ]; then
    awk 'BEGIN{srand(7); for(i=0;i<100000;i++){s="";for(j=0;j<16;j++)s=s sprintf("%x",int(rand()*16)); print "https://127.0.0.1:8443/miss/" s ".bin"}}' \
        > "$RESULTS/urls/proxy-miss-rand.txt"
fi

# TLS material for h1s/h2/h3 rounds (self-signed, SAN covers 127.0.0.1).
TLS_DIR="$RESULTS/tls"
if [ "$PROTO" != h1 ]; then
    mkdir -p "$TLS_DIR"
    if [ ! -s "$TLS_DIR/cert.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
            -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
            -subj '/CN=localhost' \
            -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
    fi
    export BENCH_TLS_CERT="$TLS_DIR/cert.pem" BENCH_TLS_KEY="$TLS_DIR/key.pem"
fi

# The D miss group needs nginx to answer any /miss/<rand> path with a body —
# a wildcard location, documented in docs/perf-test-plan.md. Fail fast rather
# than record 404s as "misses".
if ! curl -sf -o /dev/null "$ORIGIN/miss/__preflight__.bin"; then
    cat >&2 <<'EOF'
error: nginx /miss/ wildcard is not configured — rand-regex misses would all 404.
Add to the perf-origin server block and reload nginx:

    location /miss/ { alias /srv/perf-origin/miss-payload-256K.bin; }

EOF
    exit 1
fi

# ---- start bench-proxy ------------------------------------------------------
pkill -9 -x bench-proxy 2>/dev/null || true; sleep 1
rm -rf "$BENCH_HOME/data"
( cd "$BENCH_HOME" && setsid env CLOUD_NODE_HOME="$BENCH_HOME" \
    BENCH_DISK_MAX_BYTES="$BENCH_DISK_MAX_BYTES" "$PROXY_BIN" \
    > "$RESULTS/bench-proxy.log" 2>&1 < /dev/null & )
PROXY_PID=""
READY=0
for _ in $(seq 1 50); do
    PROXY_PID=$(pgrep -x bench-proxy | head -1 || true)
    # -k: TLS rounds serve a self-signed cert; h1 ignores the flag anyway via
    # https URL only — for h3 this still probes the TCP TLS listener on :8443.
    if [ -n "$PROXY_PID" ] && curl -skf -o /dev/null "$PROXY/index.html"; then
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

run() { # name, extra loadgen args... — duration-bounded
    local name="$1"; shift
    run_impl "$name" "$DUR_S" -z "$DUR" "$@"
}

run_n() { # name, request-count bound, extra loadgen args...
    local name="$1"; shift
    local count="$1"; shift
    run_impl "$name" 0 -n "$count" "$@"
}

# run_impl normalizes the caller args for the selected PROTO:
#   -c N           -> in-flight concurrency. h2/h3 divide it across
#                     STREAMS_PER_CONN streams per connection.
#   --disable-keepalive -> h1/h1s: oha conn-per-request; h3: --churn
#                     (fresh QUIC conn per request); h2: SKIPPED (oha
#                     cannot churn h2 conns).
#   --rand-regex-url -> h3 cannot expand regexes: substituted with the
#                     pregenerated 100k-unique-key file (bigger than L2).
run_impl() { # name, sample_secs (0 = sample until load exits), loadgen args...
    local name="$1" sample_secs="$2"; shift 2
    echo "=== $name"

    local conc=200 churn=0 bounded_n="" dur_arg="$DUR_S"
    local rest=() rand_regex=0
    while [ $# -gt 0 ]; do
        case "$1" in
            -c) conc="$2"; shift 2 ;;
            -z) dur_arg="${2%s}"; shift 2 ;;
            -n) bounded_n="$2"; shift 2 ;;
            --disable-keepalive) churn=1; shift ;;
            --rand-regex-url) rand_regex=1; rand_url="$2"; shift 2 ;;
            *) rest+=("$1"); shift ;;
        esac
    done

    local sampler_args=(--pid "$PROXY_PID" --name proxy)
    local w
    for w in "${NGINX_WORKERS[@]}"; do
        sampler_args+=(--pid "$w" --name nginx)
    done
    # For request-count bounded runs the sampler watches a generous ceiling
    # and is stopped with SIGTERM when the load exits, so the reported CPU
    # average covers exactly the loaded interval.
    local sampler_duration="$sample_secs"
    [ "$sampler_duration" -eq 0 ] && sampler_duration=86400
    python3 "$SAMPLER" "${sampler_args[@]}" \
        --duration "$sampler_duration" --interval 0.5 --out "$RESULTS/$name.sys.json" &
    local spid=$!
    sleep 0.3

    # Origin-direct runs (A group) always use plain h1 — the origin speaks
    # only HTTP/1.1; they are the per-round reference baseline.
    local direct_origin=0 a
    for a in "${rest[@]+"${rest[@]}"}"; do
        case "$a" in "$ORIGIN"/*) direct_origin=1 ;; esac
    done

    if [ "$PROTO" = h3 ] && [ "$direct_origin" = 0 ]; then
        local conns=$(( conc / STREAMS_PER_CONN )); [ "$conns" -lt 1 ] && conns=1
        local h3_args=(--host 127.0.0.1 --port 8443 --conns "$conns"
            --streams "$STREAMS_PER_CONN" --duration "${dur_arg}s")
        local i path
        for i in "${!rest[@]}"; do
            case "${rest[$i]}" in
                --urls-from-file) h3_args+=(--urls-file "${rest[$((i+1))]}") ;;
                http*://*|//*)
                    local u="${rest[$i]}"; u="${u#*://}"; path="/${u#*/}"
                    h3_args+=(--path "$path") ;;
            esac
        done
        if [ "$rand_regex" = 1 ]; then
            h3_args+=(--urls-file "$RESULTS/urls/proxy-miss-rand.txt")
        fi
        if [ "$churn" = 1 ]; then
            h3_args+=(--churn --streams 1 --conns "$conc")
        fi
        "$H3_BIN" "${h3_args[@]}" > "$RESULTS/$name.oha.json" 2>"$RESULTS/$name.oha.err"
    elif [ "$PROTO" = h2 ] && [ "$churn" = 1 ]; then
        echo '  (skipped: oha cannot churn h2 connections)' > "$RESULTS/$name.oha.err"
        echo '{"summary":{"requestsPerSec":0,"successRate":0},"latencyPercentiles":{}}' \
            > "$RESULTS/$name.oha.json"
    else
        local conns="$conc"
        local proto_args=()
        if [ "$direct_origin" = 0 ]; then
            case "$PROTO" in
                h1s) proto_args=(--insecure) ;;
                h2)  proto_args=(--insecure --http-version 2 -p "$STREAMS_PER_CONN")
                     conns=$(( conc / STREAMS_PER_CONN )); [ "$conns" -lt 1 ] && conns=1 ;;
            esac
        fi
        local oha_args=(-z "${dur_arg}s" -c "$conns")
        [ -n "$bounded_n" ] && oha_args=(-n "$bounded_n" -c "$conns")
        [ "$rand_regex" = 1 ] && rest+=(--rand-regex-url "$rand_url")
        oha "${oha_args[@]}" \
            "${proto_args[@]+"${proto_args[@]}"}" "${rest[@]}" \
            --no-tui --output-format json \
            > "$RESULTS/$name.oha.json" 2>"$RESULTS/$name.oha.err"
    fi
    if [ "$sample_secs" -eq 0 ]; then
        kill -TERM "$spid" 2>/dev/null || true
    fi
    wait $spid || true
    python3 - "$RESULTS/$name.oha.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
s=d.get("summary",{})
print(f"  qps={s.get('requestsPerSec','?')}  p50={d.get('latencyPercentiles',{}).get('p50','?')}s  p99={d.get('latencyPercentiles',{}).get('p99','?')}s  success={s.get('successRate','?')}")
PY
}

# Cache is protocol-agnostic — always warm over h1 on :8080.
warm() { # url (any scheme) — path portion only
    local u="${1#*://}"; u="/${u#*/}"
    oha -n 300 -c 20 --no-tui "http://127.0.0.1:8080$u" >/dev/null 2>&1
}

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
# the L1/L2 caches can never serve a key twice. The nginx /miss/ wildcard
# location maps any sub-path to a fixed 256KB body, so this exercises the
# full origin-fetch + disk-write + metadata-publish pipeline. The run is
# bounded by request count (oha rejects `-n` together with `-z`):
# MISS_REQUESTS * 256KB bounds the bytes written to the isolated cache volume.
run_n D-miss-256k-c200 "$MISS_REQUESTS" -c 200 \
    --rand-regex-url "$PROXY/miss/[a-z0-9]{16}"

# ---- D2. fixed-keyspace disk-hit stream ----------------------------------------
# Same 256KB bodies but a fixed keyspace that fits in L2 (1.1GB < L2 budget)
# while exceeding L1 (512MB). After the first pass these are L2 disk hits —
# this group measures the disk-hit path, NOT misses. Do not relabel.
# Warm every key sequentially over h1 first; a random warm would leave tail
# keys uncached and contaminate the disk-hit measurement with fill misses.
xargs -P 32 -n 1 -a "$RESULTS/urls/proxy-miss-warm.txt" curl -sf -o /dev/null
run D2-l2hit-256k-c200 -c 200 --urls-from-file "$RESULTS/urls/proxy-miss.txt"

# ---- E. connection churn vs keep-alive ----------------------------------------
# h3 churn = fresh QUIC conn per request (bench-h3-load --churn); h2 churn is
# skipped (oha cannot churn h2); h1s churn = TLS handshake per request.
run E-hit-1k-churn-c200 -c 200 --disable-keepalive "$PROXY/file-1K.bin" 2>/dev/null || true
if [ "$PROTO" = h1 ]; then
    python3 "$LOAD_MATRIX" --host 127.0.0.1 --port 8080 --path /file-1K.bin \
        --mode churn --concurrency 200 --duration "$DUR_S" \
        > "$RESULTS/E-churn-pymatrix.json" 2>/dev/null || true
    python3 "$LOAD_MATRIX" --host 127.0.0.1 --port 8080 --path /file-1K.bin \
        --mode keepalive --concurrency 200 --duration "$DUR_S" \
        > "$RESULTS/E-keepalive-pymatrix.json" 2>/dev/null || true
fi

# ---- F. mixed small files (warm, 2000 keys fits in cache) ---------------------
oha -n 4000 -c 50 --no-tui --urls-from-file "$RESULTS/urls/proxy-many-warm.txt" >/dev/null 2>&1  # warm all (h1)
run F-hit-many-c200 -c 200 --urls-from-file "$RESULTS/urls/proxy-many.txt"

echo "results in $RESULTS"
kill "$PROXY_PID" 2>/dev/null || true
