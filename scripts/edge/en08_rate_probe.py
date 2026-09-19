#!/usr/bin/env python3
"""EN-08 evidence probe: source-bucket prefix fairness, bounded GC, and
rate-map exhaustion fallback, exercised against the real eBPF dataplane.

Topology: veth pair en2-a (host, node VIP 10.99.0.5, XDP attached) <->
en2-b (netns en2-ns, 10.99.0.6). The full node runs in the foreground so
the sweeper (rate-map GC, rate-cfg sync) is live.

The per-source limiter is pressure-gated in userspace (disabled at Normal
pressure). Debug builds honor CLOUD_NODE_XDP_TEST_PRESSURE=elevated so the
real config -> sync -> eBPF path is exercised without host memory pressure.
Rate-map entry counts are read with bpftool by map id (maps are process-
owned and intentionally unpinned).

Usage (root, Linux):
    sudo python3 scripts/edge/en08_rate_probe.py \
        --node-bin target/debug/cloud-node-rust --out /tmp/en08.json

Subcommand (internal): --send ... runs inside the netns as the frame
sender.
"""

import argparse
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time

NS = "en2-ns"
HOST_IF = "en2-a"
PEER_IF = "en2-b"
HOST_IP = "10.99.0.5"
PEER_IP = "10.99.0.6"
PIN_DIR = "/sys/fs/bpf/cloud-node-xdp"
BPFTOOL_CANDIDATES = [
    "/usr/lib/linux-tools-5.15.0-191/bpftool",
    "bpftool",
]
DPORT = 443
RATE_V4_MAX = 262_144


def sh(cmd, check=True, capture=True, netns=None, cwd=None):
    if netns:
        cmd = ["ip", "netns", "exec", NS] + cmd
    p = subprocess.run(cmd, capture_output=capture, text=True, cwd=cwd)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"{' '.join(map(str, cmd))} rc={p.returncode}: "
            f"{p.stderr.strip() or p.stdout.strip()}")
    return p


def bpftool():
    for cand in BPFTOOL_CANDIDATES:
        if subprocess.run(["which", cand],
                          capture_output=True).returncode == 0 \
                or os.path.exists(cand):
            return cand
    raise RuntimeError("bpftool not found (apt install linux-tools-generic)")


def setup_netns():
    teardown_netns()
    sh(["ip", "netns", "add", NS])
    sh(["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", PEER_IF])
    sh(["ip", "link", "set", PEER_IF, "netns", NS])
    sh(["ip", "addr", "add", "10.99.0.5/24", "dev", HOST_IF])
    sh(["ip", "link", "set", HOST_IF, "up"])
    sh(["ip", "netns", "exec", NS, "ip", "addr", "add", "10.99.0.6/24",
        "dev", PEER_IF])
    sh(["ip", "netns", "exec", NS, "ip", "link", "set", PEER_IF, "up"])
    sh(["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])
    for iface, ns in ((HOST_IF, None), (PEER_IF, NS)):
        sh(["sysctl", "-qw", f"net.ipv6.conf.{iface}.disable_ipv6=1"],
           check=False, netns=ns)
    out = sh(["ip", "-o", "link", "show", "dev", HOST_IF]).stdout
    return out.split("link/ether")[1].split()[0]


def teardown_netns():
    for cmd in (["ip", "link", "delete", HOST_IF],
                ["ip", "netns", "delete", NS]):
        subprocess.run(cmd, capture_output=True)


def write_node_config(path, udp_pps, window_ms, pfx4, gc_after):
    body = f"""xdp:
  enabled: true
  attachMode: skb
  fallback: fail-start
  interfaces:
    - name: {HOST_IF}
      queues: [0]
      mode: protect
      localIps:
        - {HOST_IP}
      frameSize: 2048
  proxy:
    protocols: ["tcp", "udp"]
    ports:
      - protocol: tcp
        port: 443
      - protocol: udp
        port: 443
  rateLimit:
    udpPps: {udp_pps}
    tcpSynPps: 0
    windowMs: {window_ms}
    prefixV4Len: {pfx4}
    prefixV6Len: 0
    gcAfterWindows: {gc_after}
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def write_api_config(path):
    # Appends the API stub to api_node.yaml — write_node_config already
    # wrote the xdp: section of the same file.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write('nodeId: "0"\nsecret: "en08-probe"\n'
                '"rpc.endpoints":\n  - "http://127.0.0.1:9/"\n'
                '"rpc.disableUpdate": true\n'
                'kernelTuning:\n  enabled: false\n')


def counters(node_bin, cwd):
    out = sh([node_bin, "xdp", "dump-maps"], cwd=cwd).stdout
    return json.loads(out).get("counters", {})


def delta(before, after):
    return {k: int(after.get(k, 0)) - int(before.get(k, 0))
            for k in set(before) | set(after)}


def map_id(name):
    out = sh([bpftool(), "map", "show"]).stdout
    for m in re.finditer(r"^(\d+):\s+\S+\s+name\s+(\S+)", out, re.M):
        if m.group(2) == name:
            return int(m.group(1))
    raise RuntimeError(f"bpf map {name} not found")


def rate_map_entries(name):
    out = sh([bpftool(), "map", "dump", "id", str(map_id(name))]).stdout
    return out.count("key:")


def send_frames(frames):
    """Run inside netns: send raw frames on PEER_IF."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((PEER_IF, 0))
    for f in frames:
        s.send(f)


def csum16(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def udp_frame(dst_mac, src_ip, dst_ip=HOST_IP, sport=41000):
    src_mac = bytes([0x02, random.randrange(256), random.randrange(256),
                     random.randrange(256), random.randrange(256),
                     random.randrange(256)])
    payload = b"en08-probe"
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack(">HHHH", sport, DPORT, udp_len, 0)
    tot = 20 + udp_len
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, random.randrange(65536),
                     0, 64, 17, 0, socket.inet_aton(src_ip),
                     socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack(">H", csum16(ip)) + ip[12:]
    eth = bytes.fromhex(dst_mac.replace(":", "")) + src_mac + b"\x08\x00"
    return eth + ip + udp_hdr + payload


def run_sender(mode, dst_mac, a, b):
    """Sender entry point executed under `ip netns exec`."""
    frames = []
    if mode == "same24":
        for _ in range(a):
            ip = f"10.99.0.{random.randrange(1, 255)}"
            frames.append(udp_frame(dst_mac, ip))
    elif mode == "perip":
        for i in range(a):
            ip = f"10.97.{i}.7"
            for _ in range(b):
                frames.append(udp_frame(dst_mac, ip))
    elif mode == "churn":
        seen = set()
        while len(frames) < a:
            ip = f"10.{random.randrange(96, 112)}." \
                 f"{random.randrange(256)}.{random.randrange(1, 255)}"
            if ip in seen:
                continue
            seen.add(ip)
            frames.append(udp_frame(dst_mac, ip))
    elif mode == "legit":
        for _ in range(a):
            frames.append(udp_frame(dst_mac, PEER_IP, sport=45000))
    send_frames(frames)
    print(json.dumps({"sent": len(frames)}))


def flood(script, mode, dst_mac, a, b=0):
    return sh(["python3", script, "--send", mode, dst_mac, str(a), str(b)],
              netns=NS)


def start_node(node_bin, home, cwd, udp_pps, window_ms, pfx4, gc_after):
    write_node_config(os.path.join(cwd, "configs", "api_node.yaml"),
                      udp_pps, window_ms, pfx4, gc_after)
    write_node_config(os.path.join(home, "configs", "api_node.yaml"),
                      udp_pps, window_ms, pfx4, gc_after)
    write_api_config(os.path.join(home, "configs", "api_node.yaml"))
    # The node loads the eBPF object from $CLOUD_NODE_HOME/data/.
    obj_src = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(node_bin)),
        "..", "..", "data", "cloud-node-xdp-ebpf.o"))
    os.makedirs(os.path.join(home, "data"), exist_ok=True)
    if os.path.exists(obj_src):
        import shutil
        shutil.copyfile(obj_src,
                        os.path.join(home, "data", "cloud-node-xdp-ebpf.o"))
    env = dict(os.environ, CLOUD_NODE_HOME=home, RUST_LOG="info",
               CLOUD_NODE_XDP_TEST_PRESSURE="elevated")
    log = open(os.path.join(cwd, "node.log"), "w")
    proc = subprocess.Popen([os.path.abspath(node_bin)],
                            cwd=cwd, env=env, stdout=log, stderr=log,
                            start_new_session=True)
    deadline = time.time() + 40
    while time.time() < deadline:
        if os.path.exists(f"{PIN_DIR}/link-{HOST_IF}"):
            # Let the skb attach settle before the first flood.
            time.sleep(2)
            return proc
        if proc.poll() is not None:
            raise RuntimeError(f"node exited rc={proc.returncode}; "
                               f"see {cwd}/node.log")
        time.sleep(0.3)
    proc.kill()
    raise RuntimeError("node did not attach XDP within 40s")


def stop_node(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-bin", required=False)
    ap.add_argument("--out", default="/tmp/en08-rate-probe.json")
    ap.add_argument("--workdir", default="/tmp/en08-probe")
    ap.add_argument("--send", nargs=4, metavar=("MODE", "MAC", "A", "B"),
                    help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.send:
        mode, mac, a, b = args.send
        run_sender(mode, mac, int(a), int(b))
        return 0

    if os.geteuid() != 0:
        print("en08_rate_probe: must run as root", file=sys.stderr)
        return 2

    if args.node_bin is None:
        print("en08_rate_probe: --node-bin required", file=sys.stderr)
        return 2
    args.node_bin = os.path.abspath(args.node_bin)
    script = os.path.abspath(__file__)
    home = os.path.join(args.workdir, "home")
    cwd = args.workdir
    os.makedirs(home, exist_ok=True)
    result = {"phases": [], "ok": True}
    proc = None

    try:
        dst_mac = setup_netns()

        # ===== Run 1: /24 prefix fairness ==============================
        proc = start_node(args.node_bin, home, cwd,
                          udp_pps=200, window_ms=1000, pfx4=24, gc_after=2)
        before = counters(args.node_bin, cwd)
        entries_before = rate_map_entries("XDP_RATE_V4")
        flood(script, "same24", dst_mac, 3000)
        time.sleep(0.4)
        after = counters(args.node_bin, cwd)
        entries_after = rate_map_entries("XDP_RATE_V4")
        d = delta(before, after)
        ok = (d.get("rateLimited", 0) >= 2000
              and d.get("pass", 0) <= 1200
              and entries_after - entries_before <= 8)
        result["phases"].append({
            "phase": "A_prefix24_shared_bucket",
            "delta": d,
            "rate_v4_entries_delta": entries_after - entries_before,
            "ok": ok,
            "note": "3000 pkts from random 10.99.0.0/24 sources share one "
                    "bucket keyed 10.99.0.0/24 (udpPps=200, windowMs=1000)",
        })
        stop_node(proc)
        proc = None

        # ===== Run 2: per-address buckets + bounded GC =================
        proc = start_node(args.node_bin, home, cwd,
                          udp_pps=200, window_ms=1000, pfx4=0, gc_after=2)
        before = counters(args.node_bin, cwd)
        entries_before = rate_map_entries("XDP_RATE_V4")
        flood(script, "perip", dst_mac, 5, 600)
        time.sleep(0.4)
        after = counters(args.node_bin, cwd)
        entries_after = rate_map_entries("XDP_RATE_V4")
        d = delta(before, after)
        ok = (d.get("rateLimited", 0) >= 1000
              and entries_after - entries_before >= 5)
        result["phases"].append({
            "phase": "B_perip_buckets",
            "delta": d,
            "rate_v4_entries_delta": entries_after - entries_before,
            "ok": ok,
            "note": "5 distinct sources x 600 pkts: each gets its own "
                    "bucket; ~1000 pass, ~2000 limited",
        })

        # Bounded GC: 12k fresh buckets go stale (horizon = 1s*2 = 2s)
        # and are reaped at <=8192 removals per 5s sweep tick.
        flood(script, "churn", dst_mac, 12000)
        time.sleep(0.3)
        samples = [rate_map_entries("XDP_RATE_V4")]
        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(5)
            samples.append(rate_map_entries("XDP_RATE_V4"))
            if samples[-1] == 0:
                break
        ok = samples[-1] == 0 and samples[0] >= 10000
        result["phases"].append({
            "phase": "C_bounded_gc",
            "rate_v4_entries_timeline": samples,
            "ok": ok,
            "note": "12k churn buckets reaped by bounded sweeps once idle "
                    "past the GC horizon (windowMs x gcAfterWindows)",
        })

        # A fresh low-rate source still passes after GC — no damage.
        before = counters(args.node_bin, cwd)
        flood(script, "legit", dst_mac, 5)
        time.sleep(0.3)
        d = delta(before, counters(args.node_bin, cwd))
        ok = d.get("pass", 0) + d.get("redirect", 0) >= 5
        result["phases"].append({
            "phase": "C2_legit_after_gc",
            "delta": d,
            "ok": ok,
        })
        stop_node(proc)
        proc = None

        # ===== Run 3: source-map exhaustion =============================
        # windowMs=60000 x gcAfter=2 -> 120s horizon: nothing goes stale
        # during the fill, so the 262144-entry table can actually fill.
        proc = start_node(args.node_bin, home, cwd,
                          udp_pps=200000, window_ms=60000, pfx4=0,
                          gc_after=2)
        time.sleep(1)
        before = counters(args.node_bin, cwd)
        flood(script, "churn", dst_mac, 280000)
        after = counters(args.node_bin, cwd)
        entries = rate_map_entries("XDP_RATE_V4")
        d = delta(before, after)
        ok = (d.get("ratelimitMapFull", 0) >= 1
              and entries >= RATE_V4_MAX)
        result["phases"].append({
            "phase": "D_map_full_aggregate_fallback",
            "delta": d,
            "rate_v4_entries": entries,
            "ok": ok,
            "note": "280k distinct sources vs 262144-entry map: insert "
                    "failures are counted and the packet falls back to "
                    "the aggregate unverified budget",
        })

        # Post-fill disposition: a fresh source is not silently dropped —
        # counted map-full, then evaluated by the aggregate budget only.
        before = counters(args.node_bin, cwd)
        flood(script, "legit", dst_mac, 10)
        time.sleep(0.3)
        d = delta(before, counters(args.node_bin, cwd))
        ok = d.get("packets", 0) >= 10 and (
            d.get("pass", 0) + d.get("redirect", 0)
            + d.get("unverifiedLimited", 0) >= 10)
        result["phases"].append({
            "phase": "D2_post_full_disposition",
            "delta": d,
            "ok": ok,
            "note": "every post-fill packet lands on an explicit verdict "
                    "counter — no silent drop and no fail-open bypass",
        })
    finally:
        if proc is not None:
            stop_node(proc)
        teardown_netns()
        result["ok"] = all(p.get("ok", False) for p in result["phases"]) \
            and bool(result["phases"])
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)
        print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
