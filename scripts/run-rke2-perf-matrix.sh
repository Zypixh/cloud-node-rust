#!/bin/sh
set -u

ROOT=/root/cloud-node-rust-test
RESULTS="$ROOT/perf-results"
NAMESPACE=cloud-node-perf
KUBECTL="kubectl"

mkdir -p "$RESULTS"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$RESULTS/$timestamp"
mkdir -p "$run_dir/http" "$run_dir/mace" "$run_dir/samples"

run_json() {
    label="$1"
    shift
    set +e
    "$@" >"$run_dir/$label.json" 2>"$run_dir/$label.stderr"
    status=$?
    printf '%s\n' "$status" >"$run_dir/$label.status"
    return 0
}

sample_resources() {
    label="$1"
    {
        date -u +%FT%TZ
        kubectl -n "$NAMESPACE" top pod --containers 2>&1 || true
        kubectl top node hz-rke2-01 2>&1 || true
        kubectl -n "$NAMESPACE" get pod -o wide 2>&1 || true
        ss -s 2>&1 || true
        free -h 2>&1 || true
        df -h / 2>&1 || true
    } >>"$run_dir/samples/$label.log"
}

wait_pod() {
    pod="$1"
    kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$pod" --timeout=180s
}

wait_mace_pod() {
    pod="$1"
    deadline=$(( $(date +%s) + 180 ))
    while :; do
        phase=$(kubectl -n "$NAMESPACE" get pod "$pod" \
            -o jsonpath='{.status.phase}' 2>/dev/null || true)
        case "$phase" in
            Succeeded|Failed) return 0 ;;
        esac
        [ "$(date +%s)" -ge "$deadline" ] && return 1
        sleep 1
    done
}

start_proxy() {
    profile="$1"
    manifest="$run_dir/$profile-proxy.yaml"
    sed -e "s/__POD_NAME__/bench-proxy-$profile/g" \
        -e "s/__PROFILE__/$profile/g" \
        -e "s/__BINARY__/bench-proxy-$profile/g" \
        "$ROOT/scripts/rke2-perf-proxy-pod.yaml" >"$manifest"
    kubectl -n "$NAMESPACE" delete pod "bench-proxy-$profile" --ignore-not-found --wait=true >/dev/null 2>&1 || true
    kubectl apply -f "$manifest" >/dev/null
    wait_pod "bench-proxy-$profile"
    kubectl -n "$NAMESPACE" logs "pod/bench-proxy-$profile" -c proxy --tail=20 \
        >"$run_dir/${profile}-proxy.log" 2>&1 || true
    kubectl -n "$NAMESPACE" port-forward "pod/bench-proxy-$profile" 18080:8080 \
        --address 127.0.0.1 >"$run_dir/${profile}-port-forward.log" 2>&1 &
    pf_pid=$!
    sleep 2
    curl -fsS --max-time 5 http://127.0.0.1:18080/1k.bin >/dev/null
}

stop_proxy() {
    if [ "${pf_pid:-}" != "" ]; then
        kill "$pf_pid" >/dev/null 2>&1 || true
        wait "$pf_pid" >/dev/null 2>&1 || true
        pf_pid=""
    fi
}

delete_proxy() {
    profile="$1"
    stop_proxy
    kubectl -n "$NAMESPACE" delete pod "bench-proxy-$profile" --ignore-not-found --wait=true \
        >/dev/null 2>&1 || true
}

run_http_profile() {
    profile="$1"
    start_proxy "$profile"
    for path in /1k.bin /64k.bin /1m.bin; do
        path_name=$(printf '%s' "$path" | tr -cd '[:alnum:]')
        for mode in keepalive churn; do
            for concurrency in 1 16 64 256 512; do
                label="http/${profile}-${path_name}-${mode}-c${concurrency}"
                run_json "$label" python3 "$ROOT/scripts/http_load_matrix.py" \
                    --host 127.0.0.1 --port 18080 --path "$path" --mode "$mode" \
                    --duration 15 --concurrency "$concurrency" --timeout 3
            done
        done
    done
    for mode in slow-header malformed oversized-header; do
        for concurrency in 128 256; do
            label="http/${profile}-${mode}-c${concurrency}"
            run_json "$label" python3 "$ROOT/scripts/http_load_matrix.py" \
                --host 127.0.0.1 --port 18080 --mode "$mode" \
                --duration 15 --concurrency "$concurrency" --timeout 3
            curl -fsS --max-time 5 http://127.0.0.1:18080/1k.bin >/dev/null || \
                printf '%s\n' "recovery_failed_after_$mode" >>"$run_dir/${profile}-recovery.log"
        done
    done
    for concurrency in 64 256; do
        label="http/${profile}-keepalive-1m-long-c${concurrency}"
        run_json "$label" python3 "$ROOT/scripts/http_load_matrix.py" \
            --host 127.0.0.1 --port 18080 --path /1m.bin --mode keepalive \
            --duration 300 --concurrency "$concurrency" --timeout 3 &
        load_pid=$!
        while kill -0 "$load_pid" >/dev/null 2>&1; do
            sample_resources "${profile}-long-c${concurrency}"
            sleep 5
        done
        wait "$load_pid" >/dev/null 2>&1 || true
    done
    curl -fsS --max-time 5 http://127.0.0.1:18080/1k.bin >/dev/null
    delete_proxy "$profile"
    kubectl -n "$NAMESPACE" logs "pod/bench-proxy-$profile" -c proxy --tail=200 \
        >"$run_dir/${profile}-proxy-final.log" 2>&1 || true
}

run_mace_profile() {
    profile="$1"
    for mode in put get mixed merge; do
        if [ "$mode" = "put" ]; then
            batches="1 32 256"
            workers="1 4 16"
        elif [ "$mode" = "merge" ]; then
            batches="1 32"
            workers="1 4 16"
        else
            batches="1"
            workers="1 4 16"
        fi
        for batch in $batches; do
            for worker in $workers; do
                pod="mace-$profile-${mode}-w${worker}-b${batch}"
                manifest="$run_dir/$pod.yaml"
                sed -e "s/__POD_NAME__/$pod/g" \
                    -e "s/__PROFILE__/$profile/g" \
                    -e "s/__BINARY__/mace-perf-$profile/g" \
                    -e "s/__MODE__/$mode/g" \
                    -e "s/__DURATION__/15/g" \
                    -e "s/__WORKERS__/$worker/g" \
                    -e "s/__BATCH_SIZE__/$batch/g" \
                    "$ROOT/scripts/rke2-perf-mace-pod.yaml" >"$manifest"
                kubectl apply -f "$manifest" >/dev/null
                wait_mace_pod "$pod" >/dev/null 2>&1 || true
                kubectl -n "$NAMESPACE" logs "pod/$pod" -c mace \
                    >"$run_dir/mace/${profile}-${mode}-w${worker}-b${batch}.json" 2>"$run_dir/mace/${profile}-${mode}-w${worker}-b${batch}.stderr" || true
                kubectl -n "$NAMESPACE" get pod "$pod" -o json \
                    >"$run_dir/mace/${profile}-${mode}-w${worker}-b${batch}.pod.json" 2>/dev/null || true
                kubectl -n "$NAMESPACE" delete pod "$pod" --wait=true >/dev/null 2>&1 || true
            done
        done
    done
    pod="mace-$profile-reopen-w1-b1"
    sed -e "s/__POD_NAME__/$pod/g" \
        -e "s/__PROFILE__/$profile/g" \
        -e "s/__BINARY__/mace-perf-$profile/g" \
        -e "s/__MODE__/reopen/g" \
        -e "s/__DURATION__/1/g" \
        -e "s/__WORKERS__/1/g" \
        -e "s/__BATCH_SIZE__/1/g" \
        "$ROOT/scripts/rke2-perf-mace-pod.yaml" >"$run_dir/mace-reopen-$profile.yaml"
    kubectl apply -f "$run_dir/mace-reopen-$profile.yaml" >/dev/null
    wait_mace_pod "$pod" >/dev/null 2>&1 || true
    kubectl -n "$NAMESPACE" logs "pod/$pod" -c mace \
        >"$run_dir/mace/${profile}-reopen.json" 2>"$run_dir/mace/${profile}-reopen.stderr" || true
    kubectl -n "$NAMESPACE" delete pod "$pod" --wait=true >/dev/null 2>&1 || true
}

set +e
kubectl create namespace "$NAMESPACE" >/dev/null 2>&1 || true
if [ "${MACE_ONLY:-0}" = "1" ]; then
    run_mace_profile "${MACE_PROFILE:-release}"
else
    run_http_profile debug
    run_mace_profile debug
    run_http_profile release
    run_mace_profile release
fi
kubectl -n "$NAMESPACE" get pods -o wide >"$run_dir/final-pods.txt" 2>&1 || true
printf '%s\n' "$run_dir" >"$RESULTS/latest"
