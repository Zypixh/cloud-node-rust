#!/usr/bin/env bash
# Short AF_XDP relay-leak validation: FIN-churn + RST-churn against the
# proxy-smoke TCP port, then inspect the diagnostic counters in the report.
# Expected after the CloseWait/terminal-reap fix:
#   relayDone ~= relayStart (no permanent 128-task wedge)
#   sessions returns toward ~0 after churn
set -euo pipefail

ROOT="${1:-/root/edge-fix}"
BIN="$ROOT/target/debug/cloud-node-rust"
NS="${CHURN_NS:-ptb}"
HOST_IF="${CHURN_IF:-veth0}"
TARGET_IP="${CHURN_TARGET:-10.250.0.1}"
CYCLES="${CHURN_CYCLES:-1500}"
WORKERS="${CHURN_WORKERS:-8}"
DURATION_MS="${CHURN_DURATION_MS:-90000}"
READY=/tmp/churn-ready.$$
REPORT=/tmp/churn-report.json
NODE_ERR=/tmp/churn-node.err

[[ -x "$BIN" ]] || { echo "missing node binary: $BIN" >&2; exit 1; }

mkdir -p "$ROOT/configs"
cat > "$ROOT/configs/runtime.yaml" <<YAML
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
        - $TARGET_IP
      frameSize: 2048
  proxy:
    protocols: ["tcp", "http", "https", "udp", "h3"]
    ports:
      - protocol: tcp
        port: 9443
      - protocol: http
        port: 9080
      - protocol: https
        port: 9444
      - protocol: udp
        port: 443
      - protocol: h3
        port: 8443
YAML

ethtool -K "$HOST_IF" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NS" ethtool -K veth1 tx off rx off tso off gso off gro off >/dev/null 2>&1 || true

rm -f "$READY" "$REPORT" "$NODE_ERR"
cd "$ROOT"
setsid "$BIN" xdp proxy-smoke --duration-ms "$DURATION_MS" --ready-file "$READY" \
    >"$REPORT" 2>"$NODE_ERR" &
NODE_PID=$!

for _ in $(seq 1 400); do
    [[ -f "$READY" ]] && break
    kill -0 "$NODE_PID" 2>/dev/null || {
        echo "node exited before ready:" >&2
        cat "$NODE_ERR" "$REPORT" >&2
        exit 1
    }
    sleep 0.05
done
[[ -f "$READY" ]] || { echo "node never became ready" >&2; exit 1; }
echo "node ready, churning ${CYCLES}x2 @${WORKERS} workers -> $TARGET_IP:9443"

ip netns exec "$NS" python3 /root/afxdp_churn_probe.py \
    "$TARGET_IP" 9443 "$CYCLES" "$WORKERS"

echo "churn done; waiting for node report (duration-bounded)"
wait "$NODE_PID" || true
sleep 1
python3 - "$REPORT" <<'PY'
import json, sys
raw = open(sys.argv[1]).read().strip()
start = raw.find("{")
report = json.loads(raw[start:]) if start >= 0 else {}
diag = report.get("tcpDiag") or {}
proxy = report.get("tcpProxyDiag") or {}
sessions = diag.get("sessions") or {}
out = {
    "accepted": diag.get("accepted"),
    "sessions": sessions.get("total") if isinstance(sessions, dict) else sessions,
    "entered": proxy.get("entered"),
    "prepared": proxy.get("prepared"),
    "contextOk": proxy.get("contextOk"),
    "backendConnectStart": proxy.get("backendConnectStart"),
    "backendConnectOk": proxy.get("backendConnectOk"),
    "backendConnectFail": proxy.get("backendConnectFail"),
    "relayStart": proxy.get("relayStart"),
    "relayDone": proxy.get("relayDone"),
    "relayErrors": proxy.get("relayErrors"),
    "redirect": report.get("redirect"),
    "drop": report.get("drop"),
    "xskDrops": report.get("xskDrops"),
}
rs, rd = proxy.get("relayStart") or 0, proxy.get("relayDone") or 0
out["relayLeak"] = rs - rd
out["verdict"] = "PASS" if out["relayLeak"] < 64 else "LEAK"
print(json.dumps(out, indent=2, sort_keys=True))
PY
