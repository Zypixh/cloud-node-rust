#!/usr/bin/env python3
"""EN-11 evidence probe: multi-VIP disambiguation, SNAT port lifecycle,
and bidirectional flow accounting against the real eBPF dataplane.

Topology: veth pair en2-a (host, node VIPs 10.99.0.5 + 10.99.0.7, XDP
attached) <-> en2-b (netns en2-ns, 10.99.0.6). Both VIPs forward UDP
:8543 and TCP :8443 to the SAME backend 10.99.0.6:9543/9443 — the
multi-VIP same-backend ambiguity case from the EN-11 acceptance.

Phases:
  A udp conflict: client tuple -> VIP1 establishes a CT binding; the same
    client tuple -> VIP2 must be rejected (natConflict), not rebound.
    VIP1 traffic afterwards still forwards on the original binding.
  B tcp pending conflict: SYN -> VIP1 (SNAT) creates a pending entry and
    claims a port; the same tuple -> VIP2 must be rejected while the
    pending entry and the SNAT binding stay owned by VIP1.
  C pending expiry releases the SNAT port: after tcpPendingMs elapses a
    retransmitted SYN re-admits; XDP_SNAT_REV still holds exactly one
    binding for the tuple (the expired claim was released in-datapath).
  D billing: FLOW_ACCT entry for the UDP flow carries the VIP1 server_id
    with both tx (client->backend) and rx (backend->client) bytes.

Usage (root, Linux):
    sudo python3 scripts/edge/en11_nat_probe.py \
        --node-bin target/debug/cloud-node-rust --out /tmp/en11.json
"""

import argparse
import json
import os
import random
import re
import socket
import struct
import subprocess
import time

NS = "en11-ns"
HOST_IF = "en11-a"
PEER_IF = "en11-b"
VIP1 = "10.99.0.5"
VIP2 = "10.99.0.7"
PEER_IP = "10.99.0.6"
CLIENT_IP = "10.99.0.9"
PIN_DIR = "/sys/fs/bpf/cloud-node-xdp"
BPFTOOL_CANDIDATES = [
    "/usr/lib/linux-tools-5.15.0-191/bpftool",
    "bpftool",
]
TCP_LISTEN = 8443
TCP_BACKEND = 9443
UDP_LISTEN = 8543
UDP_BACKEND = 9543
CLIENT_PORT = 40000
UDP_CLIENT_PORT = 41000
PENDING_MS = 1200


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
    raise RuntimeError("bpftool not found")


def setup_netns():
    teardown_netns()
    sh(["ip", "netns", "add", NS])
    sh(["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", PEER_IF])
    sh(["ip", "link", "set", PEER_IF, "netns", NS])
    sh(["ip", "addr", "add", f"{VIP1}/24", "dev", HOST_IF])
    sh(["ip", "addr", "add", f"{VIP2}/24", "dev", HOST_IF])
    sh(["ip", "link", "set", HOST_IF, "up"])
    sh(["ip", "netns", "exec", NS, "ip", "addr", "add", f"{PEER_IP}/24",
        "dev", PEER_IF])
    sh(["ip", "netns", "exec", NS, "ip", "link", "set", PEER_IF, "up"])
    sh(["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])
    for iface, ns in ((HOST_IF, None), (PEER_IF, NS)):
        sh(["sysctl", "-qw", f"net.ipv6.conf.{iface}.disable_ipv6=1"],
           check=False, netns=ns)


def teardown_netns():
    for cmd in (["ip", "link", "delete", HOST_IF],
                ["ip", "netns", "delete", NS]):
        subprocess.run(cmd, capture_output=True)


def peer_mac():
    out = sh(["ip", "netns", "exec", NS, "ip", "-o", "link", "show",
              "dev", PEER_IF]).stdout
    return out.split("link/ether")[1].split()[0]


def write_node_config(path, next_hop):
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
        - {VIP1}
        - {VIP2}
      frameSize: 2048
      tcpForwards:
        - listen: "{VIP1}:{TCP_LISTEN}"
          backend: "{PEER_IP}:{TCP_BACKEND}"
          nextHopMac: "{next_hop}"
          snat: true
          serverId: 42
        - listen: "{VIP2}:{TCP_LISTEN}"
          backend: "{PEER_IP}:{TCP_BACKEND}"
          nextHopMac: "{next_hop}"
          snat: true
          serverId: 45
      udpForwards:
        - listen: "{VIP1}:{UDP_LISTEN}"
          backend: "{PEER_IP}:{UDP_BACKEND}"
          nextHopMac: "{next_hop}"
          snat: true
          serverId: 43
        - listen: "{VIP2}:{UDP_LISTEN}"
          backend: "{PEER_IP}:{UDP_BACKEND}"
          nextHopMac: "{next_hop}"
          snat: true
          serverId: 44
  proxy:
    protocols: ["tcp", "udp"]
    ports:
      - protocol: tcp
        port: 443
  admission:
    tcpPendingMs: {PENDING_MS}
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def write_api_config(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('nodeId: "0"\nsecret: "en11-probe"\n'
                '"rpc.endpoints":\n  - "http://127.0.0.1:9/"\n'
                '"rpc.disableUpdate": true\n'
                'kernelTuning:\n  enabled: false\n')


def dump_maps(node_bin, cwd):
    out = sh([node_bin, "xdp", "dump-maps"], cwd=cwd).stdout
    return json.loads(out)


def map_id(name):
    out = sh([bpftool(), "map", "show"]).stdout
    for m in re.finditer(r"^(\d+):\s+\S+\s+name\s+(\S+)", out, re.M):
        if m.group(2) == name:
            return int(m.group(1))
    raise RuntimeError(f"bpf map {name} not found")


def map_entries(name):
    out = sh([bpftool(), "map", "dump", "id", str(map_id(name))]).stdout
    return out.count("key:")


def snat_rev_count(proto):
    out = sh([bpftool(), "map", "dump", "-j", "id",
              str(map_id("XDP_SNAT_REV"))]).stdout
    return sum(1 for item in json.loads(out)
               if bytes(int(b, 16) for b in item["key"])[18] == proto)


def udp_snat_port():
    """Claimed SNAT port for the UDP flow (proto=17) in XDP_SNAT_REV."""
    out = sh([bpftool(), "map", "dump", "-j", "id",
              str(map_id("XDP_SNAT_REV"))]).stdout
    for item in json.loads(out):
        key = bytes(int(b, 16) for b in item["key"])
        if key[18] == 17:
            return struct.unpack(">H", key[16:18])[0]
    raise RuntimeError("no UDP SNAT binding found")


def flow_acct_entries():
    """Decode XDP_FLOW_ACCT per-cpu values -> list of dicts (summed)."""
    out = sh([bpftool(), "map", "dump", "-j", "id",
              str(map_id("XDP_FLOW_ACCT"))]).stdout
    entries = []
    for item in json.loads(out):
        total = {"rx_bytes": 0, "tx_bytes": 0, "rx_pkts": 0, "tx_pkts": 0,
                 "server_id": 0}
        for cpu_val in item.get("values", []):
            v = cpu_val["value"]
            raw = (bytes.fromhex(v.removeprefix("0x")) if isinstance(v, str)
                   else bytes(int(b, 16) for b in v))
            if len(raw) < 48:
                continue
            (rx_b, tx_b, rx_p, tx_p, _seen,
             sid) = struct.unpack("<QQQQQq", raw[:48])
            total["rx_bytes"] += rx_b
            total["tx_bytes"] += tx_b
            total["rx_pkts"] += rx_p
            total["tx_pkts"] += tx_p
            # Idle CPUs hold an all-zero slot; attribution comes from the
            # CPU that actually handled the flow.
            if rx_b or tx_b:
                total["server_id"] = sid
        entries.append(total)
    return entries


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


def ip_frame(dst_mac, proto, src_ip, dst_ip, l4):
    src_mac = bytes([0x02, 0x0b, random.randrange(256),
                     random.randrange(256), random.randrange(256),
                     random.randrange(256)])
    tot = 20 + len(l4)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, random.randrange(65536),
                     0, 64, proto, 0, socket.inet_aton(src_ip),
                     socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack(">H", csum16(ip)) + ip[12:]
    eth = bytes.fromhex(dst_mac.replace(":", "")) + src_mac + b"\x08\x00"
    return eth + ip + l4


def tcp_frame(dst_mac, src_ip, dst_ip, sport, dport, flags, seq=1000,
              ackno=0, payload=b""):
    offset_flags = (5 << 12) | flags
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ackno,
                      offset_flags >> 8, offset_flags & 0xFF, 65535, 0, 0)
    return ip_frame(dst_mac, 6, src_ip, dst_ip, tcp + payload)


def udp_frame(dst_mac, src_ip, dst_ip, sport, dport, payload=b"x"):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    return ip_frame(dst_mac, 17, src_ip, dst_ip, udp + payload)


SYN, ACK, FIN, RST, SYNACK = 0x02, 0x10, 0x01, 0x04, 0x12


def run_sender(mode, dst_mac, a):
    frames = []
    if mode == "udp_vip1":
        frames = [udp_frame(dst_mac, CLIENT_IP, VIP1,
                            UDP_CLIENT_PORT, UDP_LISTEN, b"en11")
                  for _ in range(a)]
    elif mode == "udp_vip2":
        frames = [udp_frame(dst_mac, CLIENT_IP, VIP2,
                            UDP_CLIENT_PORT, UDP_LISTEN, b"en11")
                  for _ in range(a)]
    elif mode == "udp_reply":
        # SNAT reply: backend -> (VIP1, claimed node port passed as a).
        frames = [udp_frame(dst_mac, PEER_IP, VIP1,
                            UDP_BACKEND, a, b"ack")]
    elif mode == "syn_vip1":
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT, TCP_LISTEN, SYN)
                  for _ in range(a)]
    elif mode == "syn_vip2":
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP2,
                            CLIENT_PORT, TCP_LISTEN, SYN)
                  for _ in range(a)]
    send_frames(frames)
    print(json.dumps({"sent": len(frames)}))


def send(script, mode, dst_mac, a):
    return sh(["python3", script, "--send", mode, dst_mac, str(a)], netns=NS)


def clean_pins():
    subprocess.run(["rm", "-rf", PIN_DIR], capture_output=True)


def start_node(node_bin, home, cwd):
    nh = peer_mac()
    write_node_config(os.path.join(cwd, "configs", "runtime.yaml"), nh)
    write_node_config(os.path.join(home, "configs", "runtime.yaml"), nh)
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
    deadline = time.time() + 60
    while time.time() < deadline:
        if os.path.exists(f"{PIN_DIR}/link-{HOST_IF}"):
            time.sleep(2)
            return proc
        if proc.poll() is not None:
            raise RuntimeError(f"node exited rc={proc.returncode}; "
                               f"see {cwd}/node.log")
        time.sleep(0.3)
    raise RuntimeError("timed out waiting for XDP attach")


def stop_node(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def counters(node_bin, cwd):
    return dump_maps(node_bin, cwd).get("counters") or {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-bin")
    ap.add_argument("--out")
    ap.add_argument("--send", nargs=3, metavar=("MODE", "DST_MAC", "N"),
                    help=argparse.SUPPRESS)
    ap.add_argument("--home", default="/tmp/en11-home")
    ap.add_argument("--work", default="/tmp/en11-run")
    args = ap.parse_args()

    if args.send:
        mode, dst_mac, a = args.send
        run_sender(mode, dst_mac, int(a))
        return

    node_bin = os.path.abspath(args.node_bin)
    result = {"ok": False, "phases": {}}
    proc = None
    try:
        clean_pins()
        setup_netns()
        proc = start_node(node_bin, args.home, args.work)
        script = os.path.abspath(__file__)

        # ---- Phase A: UDP multi-VIP conflict --------------------------
        # Forward rules sync asynchronously after attach — retry the first
        # VIP1 send until the dataplane forwards it (bounded).
        c0 = counters(node_bin, args.work)
        udp_fwd_a = 0
        for _ in range(20):
            send(script, "udp_vip1", peer_mac(), 3)
            time.sleep(0.5)
            c1 = counters(node_bin, args.work)
            udp_fwd_a = c1.get("udpFwdTx", 0) - c0.get("udpFwdTx", 0)
            if udp_fwd_a > 0:
                break

        send(script, "udp_vip2", peer_mac(), 2)
        time.sleep(1.0)
        c2 = counters(node_bin, args.work)
        conflict_delta = c2.get("natConflict", 0) - c1.get("natConflict", 0)
        fwd_delta_vip2 = c2.get("udpFwdTx", 0) - c1.get("udpFwdTx", 0)
        ct_after_conflict = map_entries("XDP_UDP_CT")

        # VIP1 traffic still forwards on the original binding.
        send(script, "udp_vip1", peer_mac(), 2)
        time.sleep(1.0)
        c3 = counters(node_bin, args.work)
        fwd_vip1_after = c3.get("udpFwdTx", 0) - c2.get("udpFwdTx", 0)

        result["phases"]["A_udp_conflict"] = {
            "vip1FwdDelta": udp_fwd_a,
            "vip2ConflictDelta": conflict_delta,
            "vip2FwdDelta": fwd_delta_vip2,
            "ctEntriesAfterConflict": ct_after_conflict,
            "vip1FwdDeltaAfter": fwd_vip1_after,
            "ok": (udp_fwd_a >= 3 and conflict_delta >= 2
                   and fwd_delta_vip2 == 0 and ct_after_conflict == 1
                   and fwd_vip1_after >= 2),
        }

        # ---- Phase B: TCP pending conflict ----------------------------
        c4 = counters(node_bin, args.work)
        snat_bound_b = 0
        for _ in range(10):
            send(script, "syn_vip1", peer_mac(), 1)
            time.sleep(0.4)
            c5 = counters(node_bin, args.work)
            snat_bound_b = c5.get("snatBound", 0) - c4.get("snatBound", 0)
            if map_entries("XDP_PENDING") >= 1:
                break
        pending_after_syn = map_entries("XDP_PENDING")
        snat_rev_after_syn = snat_rev_count(6)

        send(script, "syn_vip2", peer_mac(), 2)
        time.sleep(0.6)
        c6 = counters(node_bin, args.work)
        conflict_tcp = c6.get("natConflict", 0) - c5.get("natConflict", 0)
        pending_after = map_entries("XDP_PENDING")
        snat_rev_after = snat_rev_count(6)
        snat_bound_vip2 = c6.get("snatBound", 0) - c5.get("snatBound", 0)

        result["phases"]["B_tcp_pending_conflict"] = {
            "snatBoundVip1": snat_bound_b,
            "pendingAfterSyn": pending_after_syn,
            "snatRevAfterSyn": snat_rev_after_syn,
            "vip2ConflictDelta": conflict_tcp,
            "vip2SnatBoundDelta": snat_bound_vip2,
            "pendingAfterVip2": pending_after,
            "snatRevAfterVip2": snat_rev_after,
            "ok": (snat_bound_b >= 1 and pending_after_syn == 1
                   and snat_rev_after_syn == 1 and conflict_tcp >= 2
                   and snat_bound_vip2 == 0 and pending_after == 1
                   and snat_rev_after == 1),
        }

        # ---- Phase C: pending expiry releases the SNAT port -----------
        time.sleep(PENDING_MS / 1000.0 + 0.5)
        c7 = counters(node_bin, args.work)
        send(script, "syn_vip1", peer_mac(), 1)
        time.sleep(0.8)
        c8 = counters(node_bin, args.work)
        # Re-admission claims a new port; the expired claim must have been
        # released in-datapath, so SNAT_REV still holds exactly one entry.
        snat_rev_after_renew = snat_rev_count(6)
        pending_after_renew = map_entries("XDP_PENDING")
        snat_bound_total = c8.get("snatBound", 0) - c4.get("snatBound", 0)

        result["phases"]["C_expiry_port_release"] = {
            "snatBoundTotal": snat_bound_total,
            "snatRevAfterRenew": snat_rev_after_renew,
            "pendingAfterRenew": pending_after_renew,
            "ok": (snat_bound_total >= 2 and snat_rev_after_renew == 1
                   and pending_after_renew == 1),
        }

        # ---- Phase D: bidirectional accounting + server attribution ---
        # The UDP flow is SNAT'd: replies arrive at the node-claimed port
        # (a local address), exercising the snat_rev lookup path.
        snat_port = udp_snat_port()
        send(script, "udp_reply", peer_mac(), snat_port)
        time.sleep(1.0)
        acct = flow_acct_entries()
        udp_acct = [e for e in acct if e["server_id"] == 43]
        billed = (len(udp_acct) == 1 and udp_acct[0]["tx_bytes"] > 0
                  and udp_acct[0]["rx_bytes"] > 0)
        result["phases"]["D_billing"] = {
            "acctEntries": len(acct),
            "vip1Flow": udp_acct,
            "ok": billed,
        }

        result["ok"] = all(p["ok"] for p in result["phases"].values())
    finally:
        if proc is not None:
            stop_node(proc)
        teardown_netns()

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
