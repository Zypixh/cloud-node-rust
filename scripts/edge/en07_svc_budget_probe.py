#!/usr/bin/env python3
"""EN-07 evidence probe: per-service (listen-port) new-flow fairness
against the real eBPF dataplane (ABI v13, XDP_SVC_BUDGET dim6).

Topology: veth pair en7-a (host, VIP 10.99.0.5, XDP attached) <->
en7-b (netns en7-ns, 10.99.0.6). Two services share the VIP:
UDP :8543 -> backend :9543, TCP :8443 -> backend :9443.

Phases:
  A baseline: a small number of fresh flows on both services are
    admitted; serviceLimited stays 0 below the cap.
  B service flood: a burst of distinct-tuple UDP packets to :8543 far
    above the per-service share is capped — serviceLimited counts the
    rejections while a bounded number still forward (udpFwdTx).
  C fairness: fresh SYNs to the sibling service :8443 are still
    admitted (pending entries created) and the aggregate new-flow
    envelope was not drained (admissionLimited stays 0) — the flood on
    one service did not consume sibling headroom.
  D established flow unaffected: re-sending the tuple admitted in
    phase A keeps forwarding — the CT-hit path never pays the
    admission/service charge again.

Usage (root, Linux):
    sudo python3 scripts/edge/en07_svc_budget_probe.py \
        --node-bin target/debug/cloud-node-rust --out /tmp/en07.json
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

NS = "en7-ns"
HOST_IF = "en7-a"
PEER_IF = "en7-b"
VIP1 = "10.99.0.5"
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
# Per-service cap chosen so the per-CPU share (ceil(64/ncpu)) is small
# while the aggregate new-flow cap stays far above the flood size.
SVC_FLOW_PPS = 64
NEW_FLOW_PER_SEC = 1_000_000
FLOOD_N = 400


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
      frameSize: 2048
      tcpForwards:
        - listen: "{VIP1}:{TCP_LISTEN}"
          backend: "{PEER_IP}:{TCP_BACKEND}"
          nextHopMac: "{next_hop}"
          snat: true
          serverId: 42
      udpForwards:
        - listen: "{VIP1}:{UDP_LISTEN}"
          backend: "{PEER_IP}:{UDP_BACKEND}"
          nextHopMac: "{next_hop}"
          snat: true
          serverId: 43
  proxy:
    protocols: ["tcp", "udp"]
    ports:
      - protocol: tcp
        port: 443
  budget:
    enabled: true
    newFlowPerSec: {NEW_FLOW_PER_SEC}
    serviceFlowPps: {SVC_FLOW_PPS}
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def write_api_config(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('nodeId: "0"\nsecret: "en07-probe"\n'
                '"rpc.endpoints":\n  - "http://127.0.0.1:9/"\n'
                '"rpc.disableUpdate": true\n'
                'kernelTuning:\n  enabled: false\n')


def dump_maps(node_bin, cwd):
    out = sh([node_bin, "xdp", "dump-maps"], cwd=cwd).stdout
    return json.loads(out)


def counters(node_bin, cwd):
    return dump_maps(node_bin, cwd).get("counters") or {}


def map_id(name):
    out = sh([bpftool(), "map", "show"]).stdout
    for m in re.finditer(r"^(\d+):\s+\S+\s+name\s+(\S+)", out, re.M):
        if m.group(2) == name:
            return int(m.group(1))
    raise RuntimeError(f"bpf map {name} not found")


def pending_client_ports():
    """Client source ports currently holding XDP_PENDING entries."""
    out = sh([bpftool(), "map", "dump", "-j", "id",
              str(map_id("XDP_PENDING"))]).stdout
    ports = set()
    for item in json.loads(out):
        key = bytes(int(b, 16) for b in item["key"])
        ports.add(struct.unpack(">H", key[32:34])[0])
    return ports


def clean_pins():
    subprocess.run(["rm", "-rf", PIN_DIR], capture_output=True)


def send(script, mode, dst_mac, a):
    return sh(["python3", script, "--send", mode, dst_mac, str(a)],
              netns=NS)


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


SYN = 0x02


def run_sender(mode, dst_mac, a):
    frames = []
    if mode == "udp_flow":
        # a = client port: one distinct-tuple UDP packet per call.
        frames = [udp_frame(dst_mac, CLIENT_IP, VIP1, a, UDP_LISTEN,
                            b"en07")]
    elif mode == "udp_flood":
        # a = base client port: FLOOD_N distinct-tuple packets to :8543.
        frames = [udp_frame(dst_mac, CLIENT_IP, VIP1, a + i, UDP_LISTEN,
                            b"en07flood") for i in range(FLOOD_N)]
    elif mode == "syn_p":
        # a = client port: fresh SYN to the sibling TCP service.
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1, a, TCP_LISTEN, SYN)]
    send_frames(frames)
    print(json.dumps({"sent": len(frames)}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-bin")
    ap.add_argument("--out")
    ap.add_argument("--send", nargs=3, metavar=("MODE", "DST_MAC", "N"),
                    help=argparse.SUPPRESS)
    ap.add_argument("--home", default="/tmp/en07-home")
    ap.add_argument("--work", default="/tmp/en07-run")
    args = ap.parse_args()

    if args.send:
        mode, dst_mac, a = args.send
        run_sender(mode, dst_mac, int(a))
        return

    node_bin = os.path.abspath(args.node_bin)
    result = {"ok": False, "phases": {},
              "config": {"serviceFlowPps": SVC_FLOW_PPS,
                         "newFlowPerSec": NEW_FLOW_PER_SEC,
                         "floodN": FLOOD_N}}
    proc = None
    try:
        clean_pins()
        setup_netns()
        proc = start_node(node_bin, args.home, args.work)
        script = os.path.abspath(__file__)
        mac = peer_mac()

        # ---- Phase A: baseline admissions below the cap --------------
        c0 = counters(node_bin, args.work)
        # Retry until forward rules sync (bounded), keep the admitted
        # client port for phase D.
        udp_fwd_a = 0
        for _ in range(20):
            send(script, "udp_flow", mac, 40000)
            time.sleep(0.5)
            c1 = counters(node_bin, args.work)
            udp_fwd_a = c1.get("udpFwdTx", 0) - c0.get("udpFwdTx", 0)
            if udp_fwd_a > 0:
                break
        # A few fresh flows on the sibling TCP service.
        for port in (41000, 41001, 41002):
            send(script, "syn_p", mac, port)
        time.sleep(1.0)
        pending_a = pending_client_ports()
        cA = counters(node_bin, args.work)
        svc_lim_a = cA.get("serviceLimited", 0)
        result["phases"]["A_baseline"] = {
            "udpFwdDelta": udp_fwd_a,
            "tcpPending": sorted(pending_a & {41000, 41001, 41002}),
            "serviceLimited": svc_lim_a,
            "ok": (udp_fwd_a >= 1
                   and {41000, 41001, 41002} <= pending_a
                   and svc_lim_a == 0),
        }

        # ---- Phase B: single-service flood is capped ------------------
        cB0 = counters(node_bin, args.work)
        send(script, "udp_flood", mac, 42000)
        time.sleep(1.0)
        cB = counters(node_bin, args.work)
        svc_lim_delta = cB.get("serviceLimited", 0) \
            - cB0.get("serviceLimited", 0)
        fwd_delta = cB.get("udpFwdTx", 0) - cB0.get("udpFwdTx", 0)
        adm_lim_delta = cB.get("admissionLimited", 0) \
            - cB0.get("admissionLimited", 0)
        # Capped, not zeroed: some admissions forward, the majority of
        # the 400-packet burst is rejected by the per-service bucket.
        result["phases"]["B_service_flood"] = {
            "serviceLimitedDelta": svc_lim_delta,
            "udpFwdDelta": fwd_delta,
            "admissionLimitedDelta": adm_lim_delta,
            "ok": (svc_lim_delta >= 100
                   and 1 <= fwd_delta <= SVC_FLOW_PPS
                   and adm_lim_delta == 0),
        }

        # ---- Phase C: sibling service still admits --------------------
        cC0 = counters(node_bin, args.work)
        for port in (41100, 41101, 41102, 41103):
            send(script, "syn_p", mac, port)
        time.sleep(1.0)
        pending_c = pending_client_ports()
        cC = counters(node_bin, args.work)
        svc_lim_c = cC.get("serviceLimited", 0) \
            - cC0.get("serviceLimited", 0)
        adm_lim_c = cC.get("admissionLimited", 0) \
            - cC0.get("admissionLimited", 0)
        siblings = {41100, 41101, 41102, 41103}
        result["phases"]["C_sibling_fairness"] = {
            "tcpPending": sorted(pending_c & siblings),
            "serviceLimitedDelta": svc_lim_c,
            "admissionLimitedDelta": adm_lim_c,
            "ok": (siblings <= pending_c
                   and adm_lim_c == 0),
        }

        # ---- Phase D: established flow keeps forwarding ---------------
        cD0 = counters(node_bin, args.work)
        send(script, "udp_flow", mac, 40000)
        send(script, "udp_flow", mac, 40000)
        time.sleep(1.0)
        cD = counters(node_bin, args.work)
        fwd_d = cD.get("udpFwdTx", 0) - cD0.get("udpFwdTx", 0)
        svc_lim_d = cD.get("serviceLimited", 0) \
            - cD0.get("serviceLimited", 0)
        result["phases"]["D_established_unaffected"] = {
            "udpFwdDelta": fwd_d,
            "serviceLimitedDelta": svc_lim_d,
            "ok": fwd_d >= 2 and svc_lim_d == 0,
        }

        result["ok"] = all(p["ok"] for p in result["phases"].values())
    finally:
        if proc is not None:
            stop_node(proc)
        teardown_netns()

    if args.out:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
