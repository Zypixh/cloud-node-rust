#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/configs/runtime.yaml"
BACKUP_FILE=""
NS_NAME="${XDP_SMOKE_NS:-cn-xdp-smoke}"
HOST_IF="${XDP_SMOKE_HOST_IF:-cnxdp0}"
PEER_IF="${XDP_SMOKE_PEER_IF:-cnxdp1}"
HOST_ADDR="${XDP_SMOKE_HOST_ADDR:-10.200.0.1/24}"
HOST_BYPASS_ADDR="${XDP_SMOKE_HOST_BYPASS_ADDR:-10.200.0.3/24}"
PEER_ADDR="${XDP_SMOKE_PEER_ADDR:-10.200.0.2/24}"
PING_ADDR="${XDP_SMOKE_PING_ADDR:-10.200.0.2}"
HOST_IP="${HOST_ADDR%/*}"
HOST_BYPASS_IP="${HOST_BYPASS_ADDR%/*}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT_DIR/target}"
NODE_BIN="$TARGET_DIR/debug/cloud-node-rust"
H3_PROBE_BIN="$TARGET_DIR/debug/h3_probe"
PIDS_TO_KILL=()

log() {
    printf 'xdp-smoke: %s\n' "$*"
}

die() {
    printf 'xdp-smoke: ERROR: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cleanup() {
    set +e
    for pid in "${PIDS_TO_KILL[@]:-}"; do
        kill -- "-$pid" >/dev/null 2>&1
        kill "$pid" >/dev/null 2>&1
        wait "$pid" >/dev/null 2>&1
    done
    ip link set "$HOST_IF" down >/dev/null 2>&1
    ip link delete "$HOST_IF" >/dev/null 2>&1
    ip netns delete "$NS_NAME" >/dev/null 2>&1
    if [[ -n "$BACKUP_FILE" && -f "$BACKUP_FILE" ]]; then
        cp "$BACKUP_FILE" "$CONFIG_FILE"
        rm -f "$BACKUP_FILE"
    fi
}
trap cleanup EXIT

[[ "$(uname -s)" == "Linux" ]] || die "Linux is required for XDP/AF_XDP smoke tests"
[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "root or CAP_NET_ADMIN/CAP_BPF/CAP_NET_RAW is required"
require_cmd ip
require_cmd cargo
require_cmd ethtool
require_cmd ping
require_cmd python3
require_cmd setsid

disable_offloads() {
    ethtool -K "$1" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
}

disable_netns_offloads() {
    ip netns exec "$NS_NAME" ethtool -K "$1" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
}

run_raw_smoke() {
    local label="$1"
    local target_ip="$2"
    local expect_redirect="$3"
    local raw_output_file
    local raw_ready_file
    local raw_pid
    local raw_output

    log "running raw AF_XDP dataplane smoke: $label"
    raw_output_file="$(mktemp)"
    raw_ready_file="$(mktemp)"
    rm -f "$raw_ready_file"
    setsid "$NODE_BIN" xdp raw-smoke --duration-ms 5000 --ready-file "$raw_ready_file" >"$raw_output_file" 2>&1 &
    raw_pid=$!
    PIDS_TO_KILL+=("$raw_pid")
    for _ in $(seq 1 100); do
        if [[ -f "$raw_ready_file" ]]; then
            break
        fi
        if ! kill -0 "$raw_pid" >/dev/null 2>&1; then
            raw_output="$(cat "$raw_output_file" 2>/dev/null || true)"
            rm -f "$raw_output_file" "$raw_ready_file"
            printf '%s\n' "$raw_output"
            die "raw smoke exited before AF_XDP became ready: $label"
        fi
        sleep 0.05
    done
    [[ -f "$raw_ready_file" ]] || die "raw smoke did not become ready: $label"

    ip netns exec "$NS_NAME" python3 - "$target_ip" <<'PY'
import socket
import sys
import time

target = sys.argv[1]

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.sendto(b"cloud-node-xdp-udp-smoke", (target, 443))
udp.close()

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.settimeout(0.2)
try:
    tcp.connect((target, 9443))
except OSError:
    pass
finally:
    tcp.close()
PY

    if ! wait "$raw_pid"; then
        raw_output="$(cat "$raw_output_file" 2>/dev/null || true)"
        rm -f "$raw_output_file" "$raw_ready_file"
        printf '%s\n' "$raw_output"
        die "raw smoke command failed: $label"
    fi
    raw_output="$(cat "$raw_output_file")"
    rm -f "$raw_output_file" "$raw_ready_file"
    printf '%s\n' "$raw_output"
    RAW_SMOKE_OUTPUT="$raw_output" python3 - "$label" "$expect_redirect" <<'PY'
import json
import os
import sys

label = sys.argv[1]
expect_redirect = sys.argv[2] == "yes"
report = json.loads(os.environ["RAW_SMOKE_OUTPUT"])
if report.get("proxyReady") is not True:
    raise SystemExit(f"{label}: proxyReady was not true")
if int(report.get("xskReadyQueues", 0)) < 1:
    raise SystemExit(f"{label}: no XSK queues were ready")
udp = int(report.get("udp", 0))
tcp = int(report.get("tcp", 0))
redirect = int(report.get("redirect", 0))
if not bool(report.get("tcpDataplaneReady")):
    raise SystemExit(f"{label}: tcpDataplaneReady was false")
if expect_redirect:
    if redirect < 1:
        raise SystemExit(f"{label}: did not observe XDP_REDIRECT counter increments")
    if udp < 1:
        raise SystemExit(f"{label}: did not observe redirected UDP frames")
    if tcp < 1:
        raise SystemExit(f"{label}: did not observe redirected TCP frames")
else:
    if redirect != 0:
        raise SystemExit(f"{label}: localIps bypass still incremented XDP_REDIRECT redirect={redirect}")
    if udp != 0 or tcp != 0:
        raise SystemExit(f"{label}: localIps bypass leaked into AF_XDP udp={udp} tcp={tcp}")
PY
}

run_proxy_smoke() {
    local label="$1"
    local target_ip="$2"
    local proxy_output_file
    local proxy_ready_file
    local proxy_pid
    local proxy_output

    log "running AF_XDP application proxy smoke: $label"
    proxy_output_file="$(mktemp)"
    proxy_ready_file="$(mktemp)"
    rm -f "$proxy_ready_file"
    setsid "$NODE_BIN" xdp proxy-smoke --duration-ms 15000 --ready-file "$proxy_ready_file" >"$proxy_output_file" 2>&1 &
    proxy_pid=$!
    PIDS_TO_KILL+=("$proxy_pid")
    for _ in $(seq 1 160); do
        if [[ -f "$proxy_ready_file" ]]; then
            break
        fi
        if ! kill -0 "$proxy_pid" >/dev/null 2>&1; then
            proxy_output="$(cat "$proxy_output_file" 2>/dev/null || true)"
            rm -f "$proxy_output_file" "$proxy_ready_file"
            printf '%s\n' "$proxy_output"
            die "proxy smoke exited before AF_XDP became ready: $label"
        fi
        sleep 0.05
    done
    [[ -f "$proxy_ready_file" ]] || die "proxy smoke did not become ready: $label"

    ip netns exec "$NS_NAME" python3 - "$target_ip" <<'PY'
import socket
import ssl
import sys
import time

target = sys.argv[1]

def recv_all(sock):
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)

def recv_until(sock, needle):
    chunks = []
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
        joined = b"".join(chunks)
        if needle in joined:
            return joined
    return b"".join(chunks)

tcp_payload = b"cloud-node-xdp-tcp-proxy-smoke"
expected_tcp = b"xdp-tcp-smoke:" + tcp_payload
tcp_response = b""
for attempt in range(1, 6):
    tcp = socket.create_connection((target, 9443), timeout=3)
    tcp.settimeout(3)
    tcp.sendall(tcp_payload)
    tcp.shutdown(socket.SHUT_WR)
    tcp_response = recv_all(tcp)
    tcp.close()
    if expected_tcp in tcp_response:
        break
    time.sleep(1.0)
else:
    raise SystemExit(f"TCP AF_XDP proxy response mismatch: {tcp_response!r}")
time.sleep(2.0)

tls_context = ssl.create_default_context()
tls_context.check_hostname = False
tls_context.verify_mode = ssl.CERT_NONE
https_raw = socket.create_connection((target, 9444), timeout=3)
https_raw.settimeout(3)
https = tls_context.wrap_socket(https_raw, server_hostname="xdp-smoke-https.local")
https.settimeout(3)
https.sendall(
    b"GET /xdp-proxy-smoke HTTP/1.1\r\n"
    b"Host: xdp-smoke-https.local\r\n"
    b"Connection: close\r\n\r\n"
)
https_response = recv_all(https)
https.close()
if b"xdp-https-smoke" not in https_response:
    raise SystemExit(f"HTTPS AF_XDP proxy response missing smoke body: {https_response!r}")
time.sleep(2.0)

sni_raw = socket.create_connection((target, 9444), timeout=3)
sni_raw.settimeout(3)
sni = tls_context.wrap_socket(sni_raw, server_hostname="xdp-smoke-sni.local")
sni.settimeout(3)
sni.sendall(
    b"GET /xdp-sni-smoke HTTP/1.1\r\n"
    b"Host: xdp-smoke-sni.local\r\n"
    b"Connection: close\r\n\r\n"
)
sni_response = recv_until(sni, b"xdp-sni-smoke")
sni.close()
if b"xdp-sni-smoke" not in sni_response:
    raise SystemExit(f"SNI AF_XDP passthrough response missing smoke body: {sni_response!r}")
time.sleep(2.0)

http = socket.create_connection((target, 9080), timeout=3)
http.settimeout(3)
http.sendall(
    b"GET /xdp-proxy-smoke HTTP/1.1\r\n"
    b"Host: xdp-smoke-http.local\r\n"
    b"Connection: close\r\n\r\n"
)
http_response = recv_all(http)
http.close()
if b"xdp-http-smoke" not in http_response:
    raise SystemExit(f"HTTP AF_XDP proxy response missing smoke body: {http_response!r}")

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(3)
udp_payload = b"cloud-node-xdp-udp-proxy-smoke"
udp.sendto(udp_payload, (target, 443))
udp_response, _ = udp.recvfrom(4096)
udp.close()
expected_udp = b"xdp-udp-smoke:" + udp_payload
if udp_response != expected_udp:
    raise SystemExit(f"UDP AF_XDP proxy response mismatch: {udp_response!r}")
PY

    h3_output="$(ip netns exec "$NS_NAME" "$H3_PROBE_BIN" 1 "$target_ip:8443" \
        xdp-smoke-h3.local https://xdp-smoke-h3.local/xdp-proxy-smoke 1 1)"
    printf '%s\n' "$h3_output"
    grep -q 'ok=1 failed=0' <<<"$h3_output" \
        || die "H3 AF_XDP proxy smoke failed: $h3_output"

    quic_output="$(ip netns exec "$NS_NAME" "$H3_PROBE_BIN" 1 "$target_ip:8443" \
        xdp-smoke-quic.local https://xdp-smoke-quic.local/xdp-quic-smoke 1 1)"
    printf '%s\n' "$quic_output"
    grep -q 'ok=1 failed=0' <<<"$quic_output" \
        || die "QUIC AF_XDP passthrough smoke failed: $quic_output"

    if ! wait "$proxy_pid"; then
        proxy_output="$(cat "$proxy_output_file" 2>/dev/null || true)"
        rm -f "$proxy_output_file" "$proxy_ready_file"
        printf '%s\n' "$proxy_output"
        die "proxy smoke command failed: $label"
    fi
    proxy_output="$(cat "$proxy_output_file")"
    rm -f "$proxy_output_file" "$proxy_ready_file"
    printf '%s\n' "$proxy_output"
    PROXY_SMOKE_OUTPUT="$proxy_output" python3 - "$label" <<'PY'
import json
import os
import sys

label = sys.argv[1]
report = json.loads(os.environ["PROXY_SMOKE_OUTPUT"])
if report.get("proxyReady") is not True:
    raise SystemExit(f"{label}: proxyReady was not true")
if report.get("proxyRedirectEnabled") is not True:
    raise SystemExit(f"{label}: proxyRedirectEnabled was not true")
if report.get("tcpDataplaneReady") is not True:
    raise SystemExit(f"{label}: tcpDataplaneReady was not true")
if int(report.get("redirect", 0)) < 6:
    raise SystemExit(f"{label}: expected redirect counter to include app smoke traffic")
app = report.get("app") or {}
if int(app.get("httpRequests", 0)) < 1:
    raise SystemExit(f"{label}: HTTP backend did not receive traffic")
if int(app.get("httpsRequests", 0)) < 1:
    raise SystemExit(f"{label}: HTTPS backend did not receive traffic")
if int(app.get("tcpConnections", 0)) < 1:
    raise SystemExit(f"{label}: TCP backend did not receive traffic")
if int(app.get("udpDatagrams", 0)) < 1:
    raise SystemExit(f"{label}: UDP backend did not receive traffic")
if int(app.get("h3Requests", 0)) < 1:
    raise SystemExit(f"{label}: H3 backend did not receive traffic")
if int(app.get("sniConnections", 0)) < 1:
    raise SystemExit(f"{label}: SNI passthrough backend did not receive traffic")
if int(app.get("quicRequests", 0)) < 1:
    raise SystemExit(f"{label}: QUIC passthrough backend did not receive traffic")
PY
}

run_proxy_reload_smoke() {
    local label="$1"
    local reload_output_file
    local reload_ready_file
    local reload_output

    log "running AF_XDP proxy reload smoke: $label"
    reload_output_file="$(mktemp)"
    reload_ready_file="$(mktemp)"
    rm -f "$reload_ready_file"
    if ! "$NODE_BIN" xdp proxy-reload-smoke --duration-ms 3000 --ready-file "$reload_ready_file" >"$reload_output_file" 2>&1; then
        reload_output="$(cat "$reload_output_file" 2>/dev/null || true)"
        rm -f "$reload_output_file" "$reload_ready_file"
        printf '%s\n' "$reload_output"
        die "proxy reload smoke command failed: $label"
    fi
    [[ -f "$reload_ready_file" ]] || die "proxy reload smoke did not become ready after reload: $label"
    reload_output="$(cat "$reload_output_file")"
    rm -f "$reload_output_file" "$reload_ready_file"
    printf '%s\n' "$reload_output"
    PROXY_RELOAD_SMOKE_OUTPUT="$reload_output" python3 - "$label" <<'PY'
import json
import os
import sys

label = sys.argv[1]
report = json.loads(os.environ["PROXY_RELOAD_SMOKE_OUTPUT"])
before = report.get("beforeReload") or {}
after = report.get("afterReload") or {}
if report.get("bridgePreserved") is not True:
    raise SystemExit(f"{label}: active bridge was not preserved for unchanged AF_XDP queues")
if report.get("managerReplaced") is not False:
    raise SystemExit(f"{label}: unchanged AF_XDP reload should not replace the active manager")
for phase, section in (("before", before), ("after", after)):
    if section.get("proxyReady") is not True:
        raise SystemExit(f"{label}: {phase} reload proxyReady was not true")
    if section.get("proxyRedirectEnabled") is not True:
        raise SystemExit(f"{label}: {phase} reload proxyRedirectEnabled was not true")
    if section.get("tcpDataplaneReady") is not True:
        raise SystemExit(f"{label}: {phase} reload tcpDataplaneReady was not true")
    if int(section.get("xskReadyQueues", 0)) < 1:
        raise SystemExit(f"{label}: {phase} reload had no ready XSK queue")
    if section.get("fallbackReason"):
        raise SystemExit(f"{label}: {phase} reload fallbackReason={section.get('fallbackReason')!r}")
if int(after.get("redirect", 0)) < int(before.get("redirect", 0)):
    raise SystemExit(f"{label}: redirect counter moved backwards across reload")
if int(after.get("xskDrops", 0)) != 0:
    raise SystemExit(f"{label}: xskDrops after reload was non-zero")
PY
}

cd "$ROOT_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
    mkdir -p "$(dirname "$CONFIG_FILE")"
    printf 'runtime:\n  mode: standalone\n' > "$CONFIG_FILE"
fi
BACKUP_FILE="$(mktemp)"
cp "$CONFIG_FILE" "$BACKUP_FILE"

log "building eBPF object"
cargo xtask build-ebpf
[[ -f "$ROOT_DIR/data/cloud-node-xdp-ebpf.o" ]] || die "missing data/cloud-node-xdp-ebpf.o"

log "building smoke binaries"
cargo build -q --bin cloud-node-rust --bin h3_probe
[[ -x "$NODE_BIN" ]] || die "missing node binary: $NODE_BIN"
[[ -x "$H3_PROBE_BIN" ]] || die "missing H3 smoke client: $H3_PROBE_BIN"

log "creating veth/netns $NS_NAME"
ip netns delete "$NS_NAME" >/dev/null 2>&1 || true
ip link delete "$HOST_IF" >/dev/null 2>&1 || true
ip netns add "$NS_NAME"
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip link set "$PEER_IF" netns "$NS_NAME"
ip addr add "$HOST_ADDR" dev "$HOST_IF"
ip addr add "$HOST_BYPASS_ADDR" dev "$HOST_IF"
disable_offloads "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS_NAME" ip addr add "$PEER_ADDR" dev "$PEER_IF"
disable_netns_offloads "$PEER_IF"
ip netns exec "$NS_NAME" ip link set "$PEER_IF" up
ip netns exec "$NS_NAME" ip link set lo up

cat > "$CONFIG_FILE" <<YAML
runtime:
  mode: standalone

xdp:
  enabled: true
  attachMode: skb
  fallback: fail-start
  interfaces:
    - name: $HOST_IF
      queues: [0]
      mode: protect
      localIps:
        - $HOST_IP
      frameSize: 2048
  proxy:
    protocols: ["http", "https", "tcp", "udp", "h3"]
    ports:
      - protocol: http
        port: 9080
      - protocol: udp
        port: 443
      - protocol: h3
        port: 8443
      - protocol: tcp
        port: 9443
      - protocol: https
        port: 9444
YAML

log "running doctor"
doctor_output="$("$NODE_BIN" xdp doctor)"
printf '%s\n' "$doctor_output"
grep -q "enabled:       yes" <<<"$doctor_output" || die "doctor did not read enabled XDP config"
grep -q "mode=protect" <<<"$doctor_output" || die "doctor did not read protect-mode interface config"

log "checking dataplane exposes all configured proxy protocols"
maps_output="$("$NODE_BIN" xdp dump-maps)"
printf '%s\n' "$maps_output"
grep -q '"ready": true' <<<"$maps_output" || die "TCP dataplane did not report supported"
grep -q '"localIpFilter": true' <<<"$maps_output" || die "dump-maps did not report local IP filtering"
grep -q "\"$HOST_IP\"" <<<"$maps_output" || die "dump-maps did not include configured local IP"
supported_count="$(grep -o '"dataplaneSupported": true' <<<"$maps_output" | wc -l | tr -d ' ')"
[[ "$supported_count" -eq 5 ]] || die "expected all five proxy protocols to be dataplane supported, got $supported_count"

cat > "$CONFIG_FILE" <<YAML
runtime:
  mode: standalone

xdp:
  enabled: true
  attachMode: skb
  fallback: fail-start
  interfaces:
    - name: $HOST_IF
      queues: [0]
      mode: proxy
      localIps:
        - $HOST_IP
      frameSize: 2048
  proxy:
    protocols: ["http", "https", "tcp", "udp", "h3"]
    ports:
      - protocol: http
        port: 9080
      - protocol: udp
        port: 443
      - protocol: h3
        port: 8443
      - protocol: tcp
        port: 9443
      - protocol: https
        port: 9444
YAML

log "running proxy doctor"
proxy_doctor_output="$("$NODE_BIN" xdp doctor)"
printf '%s\n' "$proxy_doctor_output"
grep -q "dataplane:     AF_XDP proxy ports supported=5 total=5" <<<"$proxy_doctor_output" \
    || die "proxy doctor did not expose full proxy dataplane support"

run_proxy_reload_smoke "active bridge reload exits old bridge and restores redirect"
sleep 5
run_raw_smoke "default full proxy dataplane" "$HOST_IP" yes
run_raw_smoke "localIps bypass keeps unlisted destination on socket path" "$HOST_BYPASS_IP" no
sleep 5
run_proxy_smoke "HTTP HTTPS TCP UDP SNI QUIC H3 application proxy dataplane" "$HOST_IP"

cat > "$CONFIG_FILE" <<YAML
runtime:
  mode: standalone

xdp:
  enabled: true
  attachMode: skb
  fallback: fail-start
  interfaces:
    - name: $HOST_IF
      queues: [0]
      mode: protect
      localIps:
        - $HOST_IP
      frameSize: 2048
  proxy:
    protocols: ["http", "https", "tcp", "udp", "h3"]
    ports:
      - protocol: http
        port: 9080
      - protocol: udp
        port: 443
      - protocol: h3
        port: 8443
      - protocol: tcp
        port: 9443
      - protocol: https
        port: 9444
YAML

log "attaching XDP"
attach_output="$("$NODE_BIN" xdp attach)"
printf '%s\n' "$attach_output"
grep -q "attached:      yes" <<<"$attach_output" || die "XDP did not attach to $HOST_IF"
grep -q "xsk queues:    configured=0 ready=0" <<<"$attach_output" \
    || die "protect-mode attach should not create AF_XDP queues"

log "reloading XDP attachment"
reload_output="$("$NODE_BIN" xdp reload)"
printf '%s\n' "$reload_output"
grep -q "attached:      yes" <<<"$reload_output" || die "XDP reload did not attach to $HOST_IF"
grep -q "xsk queues:    configured=0 ready=0" <<<"$reload_output" \
    || die "protect-mode reload should not create AF_XDP queues"
grep -q "fallback why:  -" <<<"$reload_output" || die "XDP reload left a fallback reason"

log "verifying veth connectivity remains available for unmatched traffic"
ip netns exec "$NS_NAME" ping -c 1 -W 1 "$HOST_IP" >/dev/null \
    || die "ping from netns to host failed after XDP attach"

log "detaching XDP"
detach_output="$("$NODE_BIN" xdp detach)"
printf '%s\n' "$detach_output"

log "smoke completed"
