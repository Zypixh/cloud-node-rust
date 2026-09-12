#!/usr/bin/env bash
# Defense performance matrix: WAF / CC / UAM (L7) + L4 attack defense.
#
# Topology: oha / bench-l4-attack / hping3  ->  bench-defense (root)
#             :8080 HTTP, :8443 TLS, :9000 TCP relay, :8053 UDP relay
#           ->  nginx :8081 (http origin), socat echo :8054 (udp origin)
#
# Each attack phase sources from a distinct 127.0.0.x pool so per-IP blocks
# never poison the legit probe (always 127.0.0.1) or later phases.
#
# Usage: sudo bash scripts/perf/run_defense_matrix.sh [out_dir]
set -u
cd "$(dirname "$0")/../.."
ROOT=$(pwd)
TS=$(date +%Y%m%d-%H%M%S)
OUT=${1:-perf-results/${TS}-defense}
mkdir -p "$OUT"
LOG="$OUT/bench-defense.log"
ATK=./target/release/bench-l4-attack
NODE=./target/release/bench-defense
SAMPLER=scripts/perf/pid_sampler.py
NODE_PID=""

say() { echo "[$(date +%H:%M:%S)] $*"; }

node_pid() { pgrep -nf 'release/bench-defens[e]'; }

start_node() {
    say "starting bench-defense -> $LOG"
    sudo nohup env BENCH_CC_PER_IP_QPS="${BENCH_CC_PER_IP_QPS:-500}" \
        BENCH_CC_BLOCK_SECS="${BENCH_CC_BLOCK_SECS:-30}" \
        BENCH_L4_BLOCK_SECS="${BENCH_L4_BLOCK_SECS:-30}" \
        "$NODE" >"$LOG" 2>&1 &
    for _ in $(seq 40); do
        curl -sf -o /dev/null -H 'Host: plain.bench' http://127.0.0.1:8080/index.html && break
        sleep 0.5
    done
    NODE_PID=$(node_pid)
    say "bench-defense pid=$NODE_PID"
}

stop_node() {
    [ -n "$NODE_PID" ] && sudo kill "$NODE_PID" 2>/dev/null
}

hw_snapshot() {
    {
        echo "=== lscpu ==="; lscpu | grep -E 'Model name|^CPU\(s\)|MHz|L1d|L2|L3|Thread|Core|Socket'
        echo "=== mem ==="; free -h; sudo lshw -short -C memory 2>/dev/null | tail -n +3 || true
        echo "=== disk ==="; lsblk -d -o NAME,SIZE,ROTA,MODEL 2>/dev/null; df -h / /srv 2>/dev/null
        echo "=== kernel/os ==="; uname -a; lsb_release -d 2>/dev/null
        echo "=== sysctl ==="; sysctl net.ipv4.ip_local_port_range net.ipv4.tcp_syncookies net.netfilter.nf_conntrack_max net.ipv4.tcp_max_syn_backlog 2>/dev/null
        echo "=== tools ==="; oha --version | head -1; nginx -v 2>&1; hping3 -V 2>&1 | head -1; nft --version
    } > "$OUT/hw.txt"
}

l4_snap() { grep '^L4METRICS ' "$LOG" | tail -1 | sed 's/^L4METRICS //'; }

l4_diff() {
    # args: before_json after_json out_file
    python3 - "$1" "$2" "$3" <<'EOF'
import json, sys
b = json.loads(sys.argv[1]) if sys.argv[1].strip().startswith('{') else {}
a = json.loads(sys.argv[2]) if sys.argv[2].strip().startswith('{') else {}
d = {k: (a.get(k, 0) - b.get(k, 0)) for k in a if isinstance(a.get(k), (int, float))}
d['pressure_after'] = a.get('pressure'); d['syn_pressure_after'] = a.get('syn_pressure')
with open(sys.argv[3], 'w') as f: json.dump({'before': b, 'after': a, 'delta': d}, f, indent=1)
EOF
}

nstat_snap() { nstat -az 2>/dev/null | grep -E 'TcpExt(Syncookies|ListenOverflows|ListenDrops|TCPBacklogDrop|TCPSynRetrans|TCPReqQFullDrop|TCPTimeWaitOverflow|PfMemallocDrop|EmbryonicRsts|TCPAbortOnTimeout|TCPTimeouts)' ; }

cpu_sample() { # name duration_secs
    local name=$1 dur=$2
    python3 "$SAMPLER" --pid "$NODE_PID" --name node --duration "$dur" \
        --interval 0.5 --out "$OUT/$name.cpu.json" >/dev/null 2>&1 &
    echo $!
}

# Legit probe = keepalive request stream from 127.0.0.1. A conn-per-request
# client (oha) trips the per-IP accept-churn defense (~80 conn/s/IP) and would
# poison every later phase; keepalive keeps accepts at a handful of conns.
legit_probe() { # name host dur [drip_ms]
    local name=$1 host=$2 dur=$3 drip=${4:-0}
    "$ATK" --mode httpflood --keepalive --host "$host" --src-base 1 --src-count 1 \
        -c 8 -d "$dur" --drip-ms "$drip" --rate 2 --path /file-1K.bin \
        > "$OUT/$name.legit.json" 2>/dev/null
}

blocked_check() { # name src_ip -> writes name.blocked.json {attacker_code, legit_code}
    local name=$1 src=$2
    local ac lc
    ac=$(curl -s -o /dev/null -w '%{http_code}' -m 3 --interface "$src" \
        -H 'Host: plain.bench' http://127.0.0.1:8080/index.html || true)
    lc=$(curl -s -o /dev/null -w '%{http_code}' -m 3 \
        -H 'Host: plain.bench' http://127.0.0.1:8080/index.html || true)
    printf '{"attacker_src":"%s","attacker_code":"%s","legit_code":"%s"}\n' "$src" "$ac" "$lc" \
        > "$OUT/$name.blocked.json"
}

# run_l4 name src_base src_count -- attack args... ; legit probe runs concurrently
run_l4() {
    local name=$1 base=$2 cnt=$3; shift 3
    say "=== $name ==="
    local before after sp
    before=$(l4_snap); nstat_snap > "$OUT/$name.nstat.before"
    sp=$(cpu_sample "$name" 45)
    "$ATK" "$@" --src-base "$base" --src-count "$cnt" \
        > "$OUT/$name.attack.json" 2>"$OUT/$name.attack.err" &
    local atkpid=$!
    sleep 2  # let attack ramp before legit probe
    legit_probe "$name" plain.bench 15
    wait $atkpid
    blocked_check "$name" "127.0.0.$base"
    after=$(l4_snap); nstat_snap > "$OUT/$name.nstat.after"
    l4_diff "$before" "$after" "$OUT/$name.l4.json"
    kill $sp 2>/dev/null; wait $sp 2>/dev/null
    say "$name done: $(cat "$OUT/$name.attack.json" | head -c 200)"
}

hw_snapshot

if [ -n "$(node_pid)" ]; then say "restarting existing node"; sudo kill "$(node_pid)"; sleep 1; fi
start_node

########## L7 / WAF group ##########

# Throughput measurement clients use dedicated src pools (never 127.0.0.1)
# so per-IP defense state can't poison the legit probes that follow.
say "=== waf-overhead: plain vs waf rule eval ==="
sp=$(cpu_sample waf-plain 25)
"$ATK" --mode httpflood --keepalive --host plain.bench --src-base 224 --src-count 1 \
    -c 32 -d 20 --drip-ms 0 --path /file-1K.bin > "$OUT/waf-plain.attack.json" 2>/dev/null
kill $sp 2>/dev/null; wait $sp 2>/dev/null
sp=$(cpu_sample waf-rules 25)
"$ATK" --mode httpflood --keepalive --host waf.bench --src-base 225 --src-count 1 \
    -c 32 -d 20 --drip-ms 0 --path /file-1K.bin > "$OUT/waf-rules.attack.json" 2>/dev/null
kill $sp 2>/dev/null; wait $sp 2>/dev/null

say "=== waf-block-qps: blocked-request serving rate ==="
sp=$(cpu_sample waf-block 20)
"$ATK" --mode httpflood --keepalive --host waf.bench --src-base 226 --src-count 1 \
    -c 32 -d 15 --drip-ms 0 --path /deny/x > "$OUT/waf-block.attack.json" 2>/dev/null
kill $sp 2>/dev/null; wait $sp 2>/dev/null

say "=== cc-flood: single attacker IP over per-IP qps limit ==="
before=$(l4_snap)
sp=$(cpu_sample cc-flood 35)
# keepalive conns: high req rate per IP without tripping L4 accept-churn
"$ATK" --mode httpflood --keepalive --host cc.bench --src-base 64 --src-count 1 \
    -c 8 -d 25 --drip-ms 0 --path /file-1K.bin > "$OUT/cc-flood.attack.json" 2>/dev/null &
atkpid=$!
sleep 3
legit_probe cc-flood cc.bench 15 3   # ~333 req/s < 500/IP limit mid-attack
wait $atkpid
after=$(l4_snap); l4_diff "$before" "$after" "$OUT/cc-flood.l4.json"
kill $sp 2>/dev/null; wait $sp 2>/dev/null
# verify the attacker IP is banned while legit still passes
blocked_check cc-flood 127.0.0.64
curl -s -o /dev/null -w '%{http_code}' -m 3 --interface 127.0.0.64 -H 'Host: cc.bench' \
    http://127.0.0.1:8080/file-10K.bin > "$OUT/cc-flood.ban-code" || true

say "=== cc-dist: distributed srcs under per-IP limit (slowloris-style CC) ==="
sp=$(cpu_sample cc-dist 30)
"$ATK" --mode httpflood --host cc.bench --src-base 96 --src-count 16 \
    -c 128 -d 15 > "$OUT/cc-dist.attack.json" 2>/dev/null &
atkpid=$!
sleep 2
legit_probe cc-dist cc.bench 15 3
wait $atkpid
kill $sp 2>/dev/null; wait $sp 2>/dev/null

say "=== uam-absorb: challenge page absorption ==="
sp=$(cpu_sample uam-absorb 30)
"$ATK" --mode httpflood --host uam.bench --src-base 128 --src-count 8 \
    -c 128 -d 15 > "$OUT/uam-absorb.attack.json" 2>/dev/null &
atkpid=$!
"$ATK" --mode httpflood --keepalive --host uam.bench --src-base 227 --src-count 1 \
    -c 32 -d 15 --drip-ms 0 --path /file-1K.bin > "$OUT/uam-absorb.challenge-qps.json" 2>/dev/null &
ohapid=$!
sleep 2
legit_probe uam-absorb plain.bench 12
wait $atkpid $ohapid
kill $sp 2>/dev/null; wait $sp 2>/dev/null

########## L4 group (each phase a fresh src pool) ##########

run_l4 l4-churn       32  8 --mode churn    --port 8080 -c 96  -d 18
sleep 10  # TIME_WAIT drain
run_l4 l4-hold        48  8 --mode hold     --port 8080 -c 200 -d 18 --hold-ms 4000
run_l4 l4-slowhdr     144 8 --mode slowhdr  --port 8080 -c 100 -d 18 --drip-ms 300
sleep 10
run_l4 l4-tinyreq     160 8 --mode tinyreq  --port 8080 -c 96  -d 18 --payload 16
run_l4 l4-tlsfail     176 8 --mode tls-fail --port 8443 -c 64  -d 18 --payload 64
run_l4 l4-connhold    192 4 --mode conn-hold --port 8080 -c 3000 -d 18

say "=== l4-synflood (hping3 --rand-source vs kernel SYNPROXY) ==="
before=$(l4_snap); nstat_snap > "$OUT/l4-synflood.nstat.before"
sp=$(cpu_sample l4-synflood 40)
sudo timeout 15 hping3 -S -p 8080 --flood --rand-source 127.0.0.1 \
    > "$OUT/l4-synflood.hping3.log" 2>&1 &
hpid=$!
sleep 3
legit_probe l4-synflood plain.bench 15
wait $hpid
after=$(l4_snap); nstat_snap > "$OUT/l4-synflood.nstat.after"
l4_diff "$before" "$after" "$OUT/l4-synflood.l4.json"
kill $sp 2>/dev/null; wait $sp 2>/dev/null

say "=== l4-udpflood ==="
before=$(l4_snap)
sp=$(cpu_sample l4-udpflood 30)
"$ATK" --mode udpflood --port 8053 --src-base 208 --src-count 8 \
    -c 6 --payload 256 -d 15 > "$OUT/l4-udpflood.attack.json" 2>/dev/null &
atkpid=$!
sleep 2
# legit UDP probe: 100 echo round-trips
{ echo "udp_legit:"; ok=0; for i in $(seq 100); do
    r=$(echo probe | timeout 1 socat - UDP4:127.0.0.1:8053,sourceport=$((30000+i%500)) 2>/dev/null)
    [ "$r" = "probe" ] && ok=$((ok+1))
  done; echo "ok=$ok/100"; } > "$OUT/l4-udpflood.legit.txt"
wait $atkpid
after=$(l4_snap); l4_diff "$before" "$after" "$OUT/l4-udpflood.l4.json"
kill $sp 2>/dev/null; wait $sp 2>/dev/null

say "=== done. results in $OUT ==="
