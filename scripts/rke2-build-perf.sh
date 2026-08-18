#!/bin/sh
set -u

ROOT=/root/cloud-node-rust-test
ARTIFACTS="$ROOT/perf-artifacts"
STATUS=/tmp/cloud-node-perf-build.status
TOOLCHAIN="$ROOT/.rustup/toolchains/1.96.0-x86_64-unknown-linux-gnu/bin"

export PATH="$TOOLCHAIN:$ROOT/.cargo/bin:$PATH"
export CARGO_HOME="$ROOT/.cargo"

mkdir -p "$ARTIFACTS"
rm -f "$STATUS"

build_profile() {
    profile="$1"
    target="$ROOT/target-perf-$profile"
    log="/tmp/cloud-node-perf-$profile.log"
    time_log="/tmp/cloud-node-perf-$profile.time"

    rm -rf "$target"
    rm -f "$log" "$time_log"
    export CARGO_TARGET_DIR="$target"
    export CARGO_BUILD_JOBS=1
    export CARGO_INCREMENTAL=0
    start=$(date +%s)

    if [ "$profile" = "release" ]; then
        cargo build --release --bin bench-proxy --bin mace-perf --locked --offline >"$log" 2>&1
        status=$?
    else
        cargo build --bin bench-proxy --bin mace-perf --locked --offline >"$log" 2>&1
        status=$?
    fi

    end=$(date +%s)
    printf 'start=%s\nend=%s\nelapsed_seconds=%s\nstatus=%s\n' \
        "$start" "$end" "$((end - start))" "$status" >"$time_log"
    printf '%s=%s\n' "$profile" "$status" >>"$STATUS"

    if [ "$status" -ne 0 ]; then
        return "$status"
    fi

    install -m 0755 "$target/$profile/bench-proxy" "$ARTIFACTS/bench-proxy-$profile"
    install -m 0755 "$target/$profile/mace-perf" "$ARTIFACTS/mace-perf-$profile"
    return 0
}

cd "$ROOT" || exit 1
build_profile debug || exit $?
build_profile release || exit $?
printf 'complete=0\n' >>"$STATUS"
