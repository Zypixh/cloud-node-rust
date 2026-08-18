#!/bin/sh
set -u

ROOT=/root/cloud-node-rust-test
RESULTS="$ROOT/perf-results"
NAMESPACE=cloud-node-perf
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$RESULTS/direct-$timestamp"
mkdir -p "$run_dir"

run_json() {
    label="$1"
    shift
    set +e
    "$@" >"$run_dir/$label.json" 2>"$run_dir/$label.stderr"
    status=$?
    printf '%s\n' "$status" >"$run_dir/$label.status"
    return 0
}

wait_pod() {
    pod="$1"
    kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=180s
}

start_proxy() {
    profile="$1"
    pod="bench-proxy-direct-$profile"
    manifest="$run_dir/$profile-proxy.yaml"
    sed -e "s/__POD_NAME__/$pod/g" \
        -e "s/__PROFILE__/$profile/g" \
        -e "s/__BINARY__/bench-proxy-$profile/g" \
        "$ROOT/scripts/rke2-perf-proxy-pod.yaml" >"$manifest"
    kubectl -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=true >/dev/null 2>&1 || true
    kubectl -n "$NAMESPACE" apply -f "$manifest" >/dev/null
    wait_pod "$pod"
    pod_ip=$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.status.podIP}')
    printf '%s\n' "$pod_ip" >"$run_dir/$profile-pod-ip"
    kubectl -n "$NAMESPACE" get pod "$pod" -o wide >"$run_dir/$profile-pod.txt"
    curl -fsS --max-time 5 "http://$pod_ip:8080/1k.bin" >/dev/null
}

recover() {
    profile="$1"
    pod_ip="$2"
    if curl -fsS --max-time 5 "http://$pod_ip:8080/1k.bin" >/dev/null; then
        printf 'ok\n' >>"$run_dir/$profile-recovery.log"
    else
        printf 'failed\n' >>"$run_dir/$profile-recovery.log"
    fi
}

stop_proxy() {
    profile="$1"
    pod="bench-proxy-direct-$profile"
    kubectl -n "$NAMESPACE" logs "pod/$pod" -c proxy --tail=500 \
        >"$run_dir/$profile-proxy.log" 2>&1 || true
    kubectl -n "$NAMESPACE" get pod "$pod" -o json \
        >"$run_dir/$profile-pod.json" 2>/dev/null || true
    kubectl -n "$NAMESPACE" delete pod "$pod" --ignore-not-found --wait=true >/dev/null 2>&1 || true
}

kubectl create namespace "$NAMESPACE" >/dev/null 2>&1 || true
for profile in debug release; do
    start_proxy "$profile"
    pod_ip=$(cat "$run_dir/$profile-pod-ip")
    for path in 1k.bin 1m.bin; do
        run_json "${profile}-baseline-${path}" python3 "$ROOT/scripts/http_load_matrix.py" \
            --host "$pod_ip" --port 8080 --path "/$path" --mode keepalive \
            --duration 15 --concurrency 64 --timeout 3
    done
    for mode in slow-header malformed oversized-header; do
        for concurrency in 128 256; do
            run_json "${profile}-${mode}-c${concurrency}" \
                python3 "$ROOT/scripts/http_load_matrix.py" \
                --host "$pod_ip" --port 8080 --mode "$mode" \
                --duration 15 --concurrency "$concurrency" --timeout 3
            recover "$profile" "$pod_ip"
        done
    done
    run_json "${profile}-post-attack-c64" python3 "$ROOT/scripts/http_load_matrix.py" \
        --host "$pod_ip" --port 8080 --path /1k.bin --mode keepalive \
        --duration 15 --concurrency 64 --timeout 3
    recover "$profile" "$pod_ip"
    stop_proxy "$profile"
done
printf '%s\n' "$run_dir" >"$RESULTS/latest-direct"
