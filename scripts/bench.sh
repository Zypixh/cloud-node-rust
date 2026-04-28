#!/bin/bash
# Local benchmark script for iteratively testing proxy performance on macOS.
# Usage:
#   ./scripts/bench.sh              # Quick test (100 URLs, warm cache)
#   ./scripts/bench.sh full         # Full test (10000 URLs, cold+warm)
#   ./scripts/bench.sh cold         # Cold cache only
set -e

BENCH_DIR="/tmp/bench-origin"
URLS="/tmp/urls-bench.txt"
SMALL_URLS="/tmp/urls-bench-small.txt"
N_URLS=${N_URLS:-10000}
SMALL_N=${SMALL_N:-100}

# --- Setup ---
setup() {
    echo "=== Setting up benchmark data ==="
    mkdir -p "$BENCH_DIR"

    # Generate test files if needed
    if [ ! -f "$BENCH_DIR/0.bin" ]; then
        echo "Generating ${N_URLS} x 4KB test files..."
        for i in $(seq 0 $((N_URLS - 1))); do
            dd if=/dev/urandom of="$BENCH_DIR/$i.bin" bs=4096 count=1 2>/dev/null
        done
    fi

    # Generate URL lists
    > "$URLS"
    for i in $(seq 0 $((N_URLS - 1))); do
        echo "http://127.0.0.1:8080/$i.bin" >> "$URLS"
    done

    > "$SMALL_URLS"
    for i in $(seq 0 $((SMALL_N - 1))); do
        echo "http://127.0.0.1:8080/$i.bin" >> "$SMALL_URLS"
    done

    echo "URLs: $(wc -l < "$URLS") (full), $(wc -l < "$SMALL_URLS") (small)"
}

# --- Start services ---
start_services() {
    echo "=== Starting origin server ==="
    cd "$BENCH_DIR"
    python3 -m http.server 8081 &>/dev/null &
    ORIGIN_PID=$!
    cd - > /dev/null
    echo "Origin PID: $ORIGIN_PID"

    echo "=== Building proxy ==="
    cargo build --release --bin bench-proxy 2>&1 | tail -1

    echo "=== Starting proxy ==="
    pkill -f bench-proxy 2>/dev/null || true
    sleep 1
    ./target/release/bench-proxy &>/tmp/bench-proxy.log &
    PROXY_PID=$!
    sleep 2

    # Health check
    if ! curl -s -o /dev/null http://127.0.0.1:8080/0.bin; then
        echo "ERROR: Proxy failed to start"
        cat /tmp/bench-proxy.log
        exit 1
    fi
    echo "Proxy healthy (PID: $PROXY_PID)"
}

# --- Stop services ---
stop_services() {
    echo "=== Stopping services ==="
    kill $PROXY_PID 2>/dev/null || true
    kill $ORIGIN_PID 2>/dev/null || true
    pkill -f bench-proxy 2>/dev/null || true
    pkill -f "http.server 8081" 2>/dev/null || true
}

# --- Run benchmark ---
run_bench() {
    local label="$1"
    local urls="$2"
    local conn="$3"
    local duration="$4"

    echo ""
    echo "=== $label (-c $conn, ${duration}s) ==="
    oha -z "$duration" -c "$conn" --urls-from-file "$urls" 2>&1 | \
        grep -E "Success rate|Requests/sec|Average|50.00%|90.00%|99.00%|Error distribution" | \
        head -10
}

# --- Main ---
case "${1:-quick}" in
    quick)
        setup
        start_services
        # Warm cache
        echo "=== Warming cache ==="
        oha -n 200 -c 10 --urls-from-file "$SMALL_URLS" 2>&1 | grep "Success\|Requests/sec"
        sleep 1
        # Benchmark
        run_bench "Warm cache" "$SMALL_URLS" 50 10
        stop_services
        ;;
    full)
        setup
        start_services
        run_bench "Cold cache" "$URLS" 50 15
        echo "=== Warming cache ==="
        oha -n 200 -c 10 --urls-from-file "$SMALL_URLS" 2>&1 | grep "Success\|Requests/sec"
        sleep 1
        run_bench "Warm cache" "$SMALL_URLS" 50 10
        stop_services
        ;;
    cold)
        setup
        start_services
        run_bench "Cold cache" "$URLS" 50 15
        stop_services
        ;;
    *)
        echo "Usage: $0 {quick|full|cold}"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
