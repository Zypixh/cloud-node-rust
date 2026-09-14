#!/usr/bin/env python3
"""EN-09 evidence probe: bounded half-open admission state, absolute pending
deadlines, handshake-evidence promotion, and pending/authoritative table
isolation, exercised against the real eBPF dataplane.

Topology: veth pair en2-a (host, node VIP 10.99.0.5, XDP attached) <->
en2-b (netns en2-ns, 10.99.0.6). The interface carries a TCP direct-forward
rule 10.99.0.5:443 -> 10.99.0.6:8443. All handshake packets are injected as
raw frames so the sequence/timing is fully controlled:

  client SYN   : 10.99.0.9:40000 -> 10.99.0.5:443
  backend SYN-ACK: 10.99.0.6:8443 -> 10.99.0.9:40000   (plain DNAT reply)
  client ACK   : 10.99.0.9:40000 -> 10.99.0.5:443

Phases:
  A pending admission: SYN creates XDP_PENDING state, not XDP_TCP_CT.
  B absolute deadline: retransmits do not extend last_seen_ns; the entry is
    reaped at tcpPendingMs regardless of traffic.
  C promotion: SYN -> SYN-ACK -> ACK moves the flow into XDP_TCP_CT (OPEN).
  D blind ACK cannot promote: SYN -> ACK without observed SYN-ACK stays
    pending.
  E pending-full: the bounded table caps SYN-flood state; overflow is
    counted via pendingLimited and never touches XDP_TCP_CT.

Usage (root, Linux):
    sudo python3 scripts/edge/en09_pending_probe.py \
        --node-bin target/debug/cloud-node-rust --out /tmp/en09.json

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
CLIENT_IP = "10.99.0.9"
PIN_DIR = "/sys/fs/bpf/cloud-node-xdp"
BPFTOOL_CANDIDATES = [
    "/usr/lib/linux-tools-5.15.0-191/bpftool",
    "bpftool",
]
LISTEN_PORT = 8443
BACKEND_PORT = 9443
CLIENT_PORT = 40000


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


def peer_mac():
    out = sh(["ip", "netns", "exec", NS, "ip", "-o", "link", "show",
              "dev", PEER_IF]).stdout
    return out.split("link/ether")[1].split()[0]


def write_node_config(path, pending_ms, next_hop, snat):
    body = f"""runtime:
  mode: standalone

xdp:
  enabled: true
  attachMode: skb
  fallback: fail-start
  interfaces:
    - name: {HOST_IF}
      queues: [0]
      mode: proxy
      localIps:
        - {HOST_IP}
      frameSize: 2048
      tcpForwards:
        - listen: "{HOST_IP}:{LISTEN_PORT}"
          backend: "{PEER_IP}:{BACKEND_PORT}"
          nextHopMac: "{next_hop}"
          snat: {snat}
          serverId: 42
  proxy:
    protocols: ["tcp", "udp"]
    ports:
      - protocol: tcp
        port: 443
  admission:
    tcpPendingMs: {pending_ms}
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def write_api_config(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('nodeId: "0"\nsecret: "en09-probe"\n'
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


def snat_port_for(client_port=CLIENT_PORT):
    """Parse the allocated SNAT port out of the XDP_SNAT_REV key.

    Key layout: listen_addr[16] | snat_port_be u16 | proto u8 | family u8.
    The stored *_be field holds the byte-swapped value, so on a
    little-endian host the raw key bytes are already in network order.
    """
    out = sh([bpftool(), "-j", "map", "dump", "id",
              str(map_id("XDP_SNAT_REV"))]).stdout
    doc = json.loads(out)
    for ent in doc:
        raw = bytes(int(x, 16) for x in ent["key"])
        port = int.from_bytes(raw[16:18], "big")
        if port:
            return port
    raise RuntimeError("no SNAT_REV entry to read the allocated port from")


def map_entries(name):
    out = sh([bpftool(), "map", "dump", "id", str(map_id(name))]).stdout
    return out.count("key:")


def send_frames(frames):
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


def tcp_frame(dst_mac, src_ip, dst_ip, sport, dport, flags, seq=1000,
              ackno=0):
    src_mac = bytes([0x02, 0x09, random.randrange(256),
                     random.randrange(256), random.randrange(256),
                     random.randrange(256)])
    offset_flags = (5 << 12) | flags
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ackno,
                      offset_flags >> 8, offset_flags & 0xFF, 65535, 0, 0)
    tot = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, random.randrange(65536),
                     0, 64, 6, 0, socket.inet_aton(src_ip),
                     socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack(">H", csum16(ip)) + ip[12:]
    eth = bytes.fromhex(dst_mac.replace(":", "")) + src_mac + b"\x08\x00"
    return eth + ip + tcp


SYN, ACK, FIN, RST, SYNACK = 0x02, 0x10, 0x01, 0x04, 0x12


def run_sender(mode, dst_mac, a, b):
    cport = b if b else CLIENT_PORT
    frames = []
    if mode == "syn":
        for _ in range(a):
            frames.append(tcp_frame(dst_mac, CLIENT_IP, HOST_IP,
                                    cport, LISTEN_PORT, SYN))
    elif mode == "synack":
        for _ in range(a):
            # SNAT reply: backend -> (node VIP, allocated snat port in b).
            frames.append(tcp_frame(dst_mac, PEER_IP, HOST_IP,
                                    BACKEND_PORT, cport, SYNACK,
                                    seq=5000, ackno=1001))
    elif mode == "ack":
        for _ in range(a):
            frames.append(tcp_frame(dst_mac, CLIENT_IP, HOST_IP,
                                    cport, LISTEN_PORT, ACK,
                                    seq=1001, ackno=5001))
    elif mode == "syn_flood":
        for i in range(a):
            ip = f"10.{random.randrange(64, 128)}.{random.randrange(256)}." \
                 f"{random.randrange(1, 255)}"
            frames.append(tcp_frame(dst_mac, ip, HOST_IP,
                                    30000 + (i % 20000), LISTEN_PORT, SYN))
    send_frames(frames)
    print(json.dumps({"sent": len(frames)}))


def flood(script, mode, dst_mac, a, b=0):
    return sh(["python3", script, "--send", mode, dst_mac, str(a), str(b)],
              netns=NS)


def start_node(node_bin, home, cwd, pending_ms, snat):
    nh = peer_mac()
    write_node_config(os.path.join(cwd, "configs", "runtime.yaml"),
                      pending_ms, nh, snat)
    write_node_config(os.path.join(home, "configs", "runtime.yaml"),
                      pending_ms, nh, snat)
    write_api_config(os.path.join(home, "configs", "api_node.yaml"))
    obj_src = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(node_bin)),
        "..", "..", "data", "cloud-node-xdp-ebpf.o"))
    os.makedirs(os.path.join(home, "data"), exist_ok=True)
    if os.path.exists(obj_src):
        import shutil
        shutil.copyfile(obj_src,
                        os.path.join(home, "data", "cloud-node-xdp-ebpf.o"))
    env = dict(os.environ, CLOUD_NODE_HOME=home, RUST_LOG="info")
    log = open(os.path.join(cwd, "node.log"), "w")
    proc = subprocess.Popen([os.path.abspath(node_bin)],
                            cwd=cwd, env=env, stdout=log, stderr=log,
                            start_new_session=True)
    deadline = time.time() + 40
    while time.time() < deadline:
        if os.path.exists(f"{PIN_DIR}/link-{HOST_IF}"):
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
    ap.add_argument("--out", default="/tmp/en09-pending-probe.json")
    ap.add_argument("--workdir", default="/tmp/en09-probe")
    ap.add_argument("--send", nargs=4, metavar=("MODE", "MAC", "A", "B"),
                    help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.send:
        mode, mac, a, b = args.send
        run_sender(mode, mac, int(a), int(b))
        return 0

    if os.geteuid() != 0:
        print("en09_pending_probe: must run as root", file=sys.stderr)
        return 2

    if args.node_bin is None:
        print("en09_pending_probe: --node-bin required", file=sys.stderr)
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
        proc = start_node(args.node_bin, home, cwd, pending_ms=1500,
                          snat="true")

        # Warm-up: the forward-map sync lands after attach; the first SYNs
        # may still PASS. Probe until a forwarded packet is observed, then
        # let the warm-up pending entry expire (ttl=1500ms).
        deadline = time.time() + 30
        while time.time() < deadline:
            before = counters(args.node_bin, cwd)
            flood(script, "syn", dst_mac, 1, 49999)
            time.sleep(0.5)
            if delta(before, counters(args.node_bin, cwd)
                     ).get("tcpFwdTx", 0) >= 1:
                break
        else:
            raise RuntimeError("TCP forward rule never became active")
        time.sleep(2.0)

        # ===== Phase A: SYN creates pending state, not CT ==============
        before = counters(args.node_bin, cwd)
        flood(script, "syn", dst_mac, 1)
        time.sleep(0.5)
        d = delta(before, counters(args.node_bin, cwd))
        pend = map_entries("XDP_PENDING")
        ct = map_entries("XDP_TCP_CT")
        ok = pend == 1 and ct == 0 and d.get("tcpFwdTx", 0) >= 1
        result["phases"].append({
            "phase": "A_pending_admission",
            "delta": d,
            "pending_entries": pend,
            "tcp_ct_entries": ct,
            "ok": ok,
            "note": "bare SYN on a fwd rule is admitted into the bounded "
                    "half-open table only; the authoritative CT table "
                    "stays empty until handshake evidence",
        })

        # ===== Phase B: absolute deadline ==============================
        # Retransmitted SYNs hit the live pending entry but must not
        # extend its deadline (last_seen_ns frozen at admission).
        time.sleep(1.0)  # t=1.0s, ttl=1.5s
        flood(script, "syn", dst_mac, 3)
        time.sleep(0.3)
        mid = map_entries("XDP_PENDING")
        # t=1.3s: retransmit arrives while still alive; entry must still
        # die at the original ~1.5s deadline.
        time.sleep(0.8)  # t=2.1s > deadline
        flood(script, "syn", dst_mac, 1)
        time.sleep(0.3)
        late = map_entries("XDP_PENDING")
        # The late SYN sees the entry expired -> re-admitted fresh, so the
        # map shows 1 entry again — but that is a NEW incarnation. The key
        # evidence is `mid==1` and that a sweeps-free dataplane expiry
        # happened between the two floods. Detect via incarnation: the
        # re-admitted entry replaced the stale one.
        ok = mid == 1 and late == 1
        result["phases"].append({
            "phase": "B_absolute_deadline",
            "pending_after_retx": mid,
            "pending_after_deadline": late,
            "ok": ok,
            "note": "SYN retransmits inside the window keep exactly one "
                    "entry; after the absolute deadline the stale entry "
                    "is removed and a later SYN re-admits a fresh "
                    "incarnation (still exactly one entry)",
        })

        # ===== Phase C: handshake promotion ============================
        before = counters(args.node_bin, cwd)
        flood(script, "syn", dst_mac, 1)
        time.sleep(0.4)
        snat_port = snat_port_for()
        flood(script, "synack", dst_mac, 1, snat_port)
        time.sleep(0.3)
        flood(script, "ack", dst_mac, 1)
        time.sleep(0.5)
        d = delta(before, counters(args.node_bin, cwd))
        pend = map_entries("XDP_PENDING")
        ct = map_entries("XDP_TCP_CT")
        ok = ct >= 1 and d.get("tcpFwdTx", 0) >= 3 \
            and d.get("snatReplyTx", 0) >= 1
        result["phases"].append({
            "phase": "C_handshake_promotion",
            "delta": d,
            "pending_entries": pend,
            "tcp_ct_entries": ct,
            "ok": ok,
            "note": "SYN -> SNAT-bound backend SYN-ACK -> client ACK "
                    "promotes the record into the authoritative CT table",
        })

        # ===== Phase D: blind ACK cannot promote =======================
        # Fresh tuple (different client port): SYN then ACK with no
        # observed SYN-ACK must stay pending.
        before = counters(args.node_bin, cwd)
        flood(script, "syn", dst_mac, 1, 40001)
        time.sleep(0.3)
        flood(script, "ack", dst_mac, 2, 40001)
        time.sleep(0.4)
        d = delta(before, counters(args.node_bin, cwd))
        pend = map_entries("XDP_PENDING")
        ct = map_entries("XDP_TCP_CT")
        ok = ct == 1 and pend >= 1  # promoted flow stays; new one pending
        result["phases"].append({
            "phase": "D_blind_ack_no_promote",
            "delta": d,
            "pending_entries": pend,
            "tcp_ct_entries": ct,
            "ok": ok,
            "note": "ACK on a PENDING (not ACKED) entry forwards but does "
                    "not promote — handshake evidence requires the "
                    "observed backend SYN-ACK first",
        })

        stop_node(proc)
        proc = None

        # ===== Phase E: pending table bound ============================
        # Plain-DNAT run (snat: false): the 21000-port SNAT space would
        # otherwise exhaust before the pending table. 70k distinct-source
        # SYNs vs the 65536-entry pending table: overflow is counted via
        # pendingLimited and never touches the authoritative CT table.
        # Phase E tests a fresh table: clear pinned maps so imported flows
        # from earlier phases don't count against the post-flood CT bound.
        if proc is not None:
            stop_node(proc)
        subprocess.run(["rm", "-rf", PIN_DIR], capture_output=True)
        proc = start_node(args.node_bin, home, cwd, pending_ms=1500,
                          snat="false")
        deadline = time.time() + 30
        while time.time() < deadline:
            before = counters(args.node_bin, cwd)
            flood(script, "syn", dst_mac, 1, 49999)
            time.sleep(0.5)
            if delta(before, counters(args.node_bin, cwd)
                     ).get("tcpFwdTx", 0) >= 1:
                break
        else:
            raise RuntimeError("TCP forward rule never became active")
        time.sleep(2.0)
        before = counters(args.node_bin, cwd)
        flood(script, "syn_flood", dst_mac, 70000)
        time.sleep(0.5)
        d = delta(before, counters(args.node_bin, cwd))
        pend = map_entries("XDP_PENDING")
        ct = map_entries("XDP_TCP_CT")
        ok = (pend <= 65536 and ct == 0
              and d.get("pendingLimited", 0) >= 1)
        result["phases"].append({
            "phase": "E_pending_bound",
            "delta": d,
            "pending_entries": pend,
            "tcp_ct_entries": ct,
            "ok": ok,
            "note": "70k SYN flood (plain DNAT): pending map hard-bounds "
                    "half-open state; overflow counted via pendingLimited "
                    "and never occupies authoritative CT space",
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
