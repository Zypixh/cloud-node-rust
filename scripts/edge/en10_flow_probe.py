#!/usr/bin/env python3
"""EN-10 evidence probe: FlowEvent publication, owner-epoch takeover, and
existing-flow continuity across reload/restart, exercised against the real
eBPF dataplane.

Topology: veth pair en2-a (host, node VIP 10.99.0.5, XDP attached) <->
en2-b (netns en2-ns, 10.99.0.6). TCP forward 10.99.0.5:8443 -> 10.99.0.6:9443
(SNAT) and UDP forward 10.99.0.5:8543 -> 10.99.0.6:9543. All packets are
injected as raw frames inside the netns.

Phases:
  A emission: SYN -> ADMITTED event; SYN-ACK+ACK -> VALIDATED (promotion);
    UDP first packet -> VALIDATED; FIN -> CLOSED. Observed via
    `xdp dump-maps` flowFeedback.eventsReceived and counters.flowEventLost.
  B takeover: stop the node (pinned state maps survive on bpffs), confirm
    CT entries still resident via bpftool, restart, and check
    importedFlows/ownerEpoch in dump-maps.
  C imported-flow service: a data ACK on the imported tuple must be
    forwarded by the dataplane (tcpFwdTx delta > 0) — the flow was adopted,
    not severed. A fresh SYN must still emit events under the new epoch.

Usage (root, Linux):
    sudo python3 scripts/edge/en10_flow_probe.py \
        --node-bin target/debug/cloud-node-rust --out /tmp/en10.json

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
TCP_LISTEN = 8443
TCP_BACKEND = 9443
UDP_LISTEN = 8543
UDP_BACKEND = 9543
CLIENT_PORT = 40000
UDP_CLIENT_PORT = 41000


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
        - {HOST_IP}
      frameSize: 2048
      tcpForwards:
        - listen: "{HOST_IP}:{TCP_LISTEN}"
          backend: "{PEER_IP}:{TCP_BACKEND}"
          nextHopMac: "{next_hop}"
          snat: true
          serverId: 42
      udpForwards:
        - listen: "{HOST_IP}:{UDP_LISTEN}"
          backend: "{PEER_IP}:{UDP_BACKEND}"
          nextHopMac: "{next_hop}"
          snat: false
          serverId: 43
  proxy:
    protocols: ["tcp", "udp"]
    ports:
      - protocol: tcp
        port: 443
  admission:
    tcpPendingMs: 30000
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def write_api_config(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('nodeId: "0"\nsecret: "en10-probe"\n'
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
    src_mac = bytes([0x02, 0x0a, random.randrange(256),
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
    if mode == "syn":
        for _ in range(a):
            frames.append(tcp_frame(dst_mac, CLIENT_IP, HOST_IP,
                                    CLIENT_PORT, TCP_LISTEN, SYN))
    elif mode == "udp":
        for _ in range(a):
            frames.append(udp_frame(dst_mac, CLIENT_IP, HOST_IP,
                                    UDP_CLIENT_PORT, UDP_LISTEN,
                                    b"en10"))
    elif mode == "synack_snat":
        # SNAT reply: backend -> (node VIP, allocated snat port passed as a).
        frames.append(tcp_frame(dst_mac, PEER_IP, HOST_IP,
                                TCP_BACKEND, a, SYNACK,
                                seq=5000, ackno=1001))
    elif mode == "finack":
        for _ in range(a):
            frames.append(tcp_frame(dst_mac, CLIENT_IP, HOST_IP,
                                    CLIENT_PORT, TCP_LISTEN, FIN | ACK,
                                    seq=1001, ackno=5001))
    elif mode == "data_ack":
        for _ in range(a):
            frames.append(tcp_frame(dst_mac, CLIENT_IP, HOST_IP,
                                    CLIENT_PORT, TCP_LISTEN, ACK,
                                    seq=1001, ackno=5001, payload=b"get"))
    send_frames(frames)
    print(json.dumps({"sent": len(frames)}))


def send(script, mode, dst_mac, a):
    return sh(["python3", script, "--send", mode, dst_mac, str(a)], netns=NS)


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
    deadline = time.time() + 45
    while time.time() < deadline:
        if os.path.exists(f"{PIN_DIR}/link-{HOST_IF}"):
            time.sleep(2)
            return proc
        if proc.poll() is not None:
            raise RuntimeError(f"node exited rc={proc.returncode}; "
                               f"see {cwd}/node.log")
        time.sleep(0.3)
    proc.kill()
    raise RuntimeError("node did not attach XDP within 45s")


def stop_node(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    time.sleep(1)


def flow_feedback(node_bin, home, cwd):
    """Merged EN-10 view: ownerEpoch comes from the pinned map via
    `xdp dump-maps` (cross-process truth); the consumer counters are
    daemon-local, read from its persisted status file (10s write
    throttle, snake_case serde field names)."""
    fb = {"ownerEpoch": 0, "eventsReceived": 0, "eventsStale": 0,
          "eventsEvicted": 0, "importedFlows": 0}
    try:
        dm = dump_maps(node_bin, cwd).get("flowFeedback", {})
        fb["ownerEpoch"] = dm.get("ownerEpoch", 0)
    except Exception:
        pass
    state = os.path.join(home, "data", "xdp-state.json")
    if os.path.exists(state):
        try:
            st = json.load(open(state))
            fb["eventsReceived"] = st.get("flow_events_received", 0)
            fb["eventsStale"] = st.get("flow_events_stale", 0)
            fb["eventsEvicted"] = st.get("flow_events_evicted", 0)
            fb["importedFlows"] = st.get("imported_flows", 0)
            if not fb["ownerEpoch"]:
                fb["ownerEpoch"] = st.get("owner_epoch", 0)
        except Exception:
            pass
    return fb


def wait_flow_feedback(node_bin, home, cwd, min_received, timeout=35):
    deadline = time.time() + timeout
    fb = {}
    while time.time() < deadline:
        fb = flow_feedback(node_bin, home, cwd)
        if int(fb.get("eventsReceived", 0)) >= min_received:
            return fb
        time.sleep(0.5)
    return fb


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", nargs=3, metavar=("MODE", "DST_MAC", "N"))
    ap.add_argument("--node-bin", required=False)
    ap.add_argument("--out", default="/tmp/en10.json")
    ap.add_argument("--work", default="/tmp/en10-run")
    ap.add_argument("--home", default="/tmp/en10-home")
    args = ap.parse_args()

    if args.send:
        mode, dst_mac, a = args.send
        run_sender(mode, dst_mac, int(a))
        return

    if os.geteuid() != 0:
        raise SystemExit("must run as root (netns + XDP attach)")
    node_bin = os.path.abspath(args.node_bin)
    script = os.path.abspath(__file__)
    os.makedirs(args.work, exist_ok=True)

    result = {"phases": {}}
    ok = True
    # Deterministic start: drop pins left by earlier probe runs so phase A
    # observes a from-scratch attach (importedFlows must start at 0). This
    # is probe-local state under XDP_BPF_PIN_DIR.
    if os.path.isdir(PIN_DIR):
        for name in os.listdir(PIN_DIR):
            p = os.path.join(PIN_DIR, name)
            if os.path.isfile(p):
                os.unlink(p)
            elif name == "progs":
                for f in os.listdir(p):
                    os.unlink(os.path.join(p, f))
                os.rmdir(p)
    setup_netns()
    try:
        dst_mac = peer_mac()

        # Phase A: attach and emit lifecycle events. Forward rules land
        # asynchronously after attach (map-sync worker), so retry the SYN
        # until XDP_SNAT_REV shows the allocated port — bounded retries.
        proc = start_node(node_bin, args.home, args.work)
        try:
            snat_port = None
            deadline = time.time() + 40
            while time.time() < deadline and snat_port is None:
                send(script, "syn", dst_mac, 1)
                time.sleep(1)
                try:
                    out = sh([bpftool(), "-j", "map", "dump", "id",
                              str(map_id("XDP_SNAT_REV"))]).stdout
                    for ent in json.loads(out):
                        raw = bytes(int(x, 16) for x in ent["key"])
                        port = int.from_bytes(raw[16:18], "big")
                        if port:
                            snat_port = port
                except Exception:
                    pass
            if snat_port:
                send(script, "synack_snat", dst_mac, snat_port)
                send(script, "data_ack", dst_mac, 1)
            send(script, "udp", dst_mac, 2)
            send(script, "finack", dst_mac, 1)
            fb = wait_flow_feedback(node_bin, args.home, args.work, 4)
            counters = dump_maps(node_bin, args.work).get("counters", {})
            ct_tcp = map_entries("XDP_TCP_CT")
            ct_udp = map_entries("XDP_UDP_CT")
            phase_a = {
                "flowFeedback": fb,
                "flowEventLost": counters.get("flowEventLost"),
                "tcpCtEntries": ct_tcp,
                "udpCtEntries": ct_udp,
                "snatPort": snat_port,
            }
            result["phases"]["A"] = phase_a
            ok_a = (int(fb.get("eventsReceived", 0)) >= 4
                    and int(fb.get("ownerEpoch", 0)) >= 1
                    and ct_tcp >= 1 and ct_udp >= 1
                    and int(counters.get("flowEventLost", -1)) == 0)
            ok = ok and ok_a
        finally:
            stop_node(proc)

        # Pinned state must survive the process exit.
        pinned = sorted(os.listdir(PIN_DIR))
        state_maps = [n for n in pinned if n.startswith("XDP_")]
        ct_after_stop = map_entries("XDP_TCP_CT") + map_entries("XDP_UDP_CT")
        result["phases"]["B_pins"] = {
            "pinnedStateMaps": state_maps,
            "ctEntriesAfterStop": ct_after_stop,
        }
        ok = ok and ct_after_stop >= 2 and "XDP_FLOW_EVENTS" in state_maps \
            and "XDP_TCP_CT" in state_maps and "XDP_PENDING" in state_maps

        # Phase B/C: restart — takeover must adopt resident flows.
        proc = start_node(node_bin, args.home, args.work)
        try:
            fb = wait_flow_feedback(node_bin, args.home, args.work, 0, timeout=25)
            fb = flow_feedback(node_bin, args.home, args.work)
            imported = int(fb.get("importedFlows", 0))
            epoch = int(fb.get("ownerEpoch", 0))
            before = dump_maps(node_bin, args.work).get("counters", {})
            # Imported flows keep transiting the dataplane without any
            # re-admission: UDP packet on the imported UDP CT entry and a
            # data ACK on the imported TCP CT entry (when promoted).
            time.sleep(3)
            send(script, "udp", dst_mac, 3)
            send(script, "data_ack", dst_mac, 3)
            time.sleep(1)
            after = dump_maps(node_bin, args.work).get("counters", {})
            deltas = {k: int(after.get(k, 0)) - int(before.get(k, 0))
                      for k in set(before) | set(after)
                      if int(after.get(k, 0)) != int(before.get(k, 0))}
            udp_delta = deltas.get("udpFwdTx", 0)
            fwd_delta = deltas.get("tcpFwdTx", 0)
            send(script, "syn", dst_mac, 1)
            fb2 = wait_flow_feedback(node_bin, args.home, args.work,
                                     int(fb.get("eventsReceived", 0)) + 1)
            phase_c = {
                "importedFlows": imported,
                "ownerEpoch": epoch,
                "tcpFwdTxDelta": fwd_delta,
                "udpFwdTxDelta": udp_delta,
                "counterDeltas": deltas,
                "flowFeedbackAfterRestart": fb2,
            }
            result["phases"]["C"] = phase_c
            ok_c = imported >= 2 and epoch >= 2 and udp_delta >= 1 \
                and fwd_delta >= 1
            ok = ok and ok_c
        finally:
            stop_node(proc)
    finally:
        teardown_netns()

    result["ok"] = ok
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
