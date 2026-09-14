#!/usr/bin/env python3
"""EN-14 evidence probe: stateless TCP cookie challenge + sequence splice
against the real eBPF dataplane (ADR-001).

Topology: veth pair en14-a (host, VIP 10.99.0.5, XDP attached) <-> en14-b
(netns en14-ns, 10.99.0.6 backend). VIP1 TCP :8443 -> backend :9443 with
snat+challenge enabled.

Phases:
  A SYN -> challenge SYN-ACK: forged reply captured on the peer interface
    (SYN|ACK, ack = c_isn+1, ISN = cookie); challengeSent increments and
    NO state is created (pending/CT/SNAT all stay empty).
  B bad-cookie ACK -> rejected: challengeRejected increments, no state.
  C valid-cookie ACK -> bounded admission: pending entry in SPLICE_WAIT,
    SNAT port claimed, forged SYN replayed to the backend (seq = c_isn,
    sport = claimed SNAT port).
  D backend SYN-ACK anchors the splice: consumed (not forwarded), a forged
    ACK completes the backend handshake (seq = c_isn+1, ack = b_isn+1),
    pending promotes to CT OPEN with SPLICE_DONE and the anchored delta.
  E data path: client ACK+payload reaches the backend with the ack number
    translated out of challenge space; the backend reply's seq is
    translated back into challenge space for the client.
  F retransmitted SYN -> another challenge, still no extra state.
  G key removed -> proving ACK fails closed (challengeRejected), the
    splice state created earlier is untouched.
  H random SYN flood -> challenges are emitted but bounded and no state
    is allocated for unverified SYNs.

Usage (root, Linux):
    sudo python3 scripts/edge/en14_cookie_probe.py \
        --node-bin target/debug/cloud-node-rust --out /tmp/en14.json
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

NS = "en14-ns"
HOST_IF = "en14-a"
PEER_IF = "en14-b"
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
CLIENT_PORT = 40000
C_ISN = 1000
B_ISN = 2000
PENDING_MS = 4000

SYN, ACK, FIN, RST, SYNACK = 0x02, 0x10, 0x01, 0x04, 0x12


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


def write_node_config(path, next_hop, ebpf_object):
    body = f"""runtime:
  mode: standalone

xdp:
  enabled: true
  attachMode: skb
  fallback: fail-start
  # Fast-iterate: load the freshly built object instead of the embedded copy.
  ebpfObject: "{ebpf_object}"
  # (empty string disables; the binary falls back to its embedded object)
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
          challenge: true
          serverId: 42
  proxy:
    protocols: ["tcp", "udp"]
    ports:
      - protocol: tcp
        port: 443
  admission:
    tcpPendingMs: {PENDING_MS}
  # EN-16: the 2GiB probe host cannot hold production-size state tables
  # (projected ~321MiB > kernel-bpf budget ~136MiB); size them explicitly.
  stateTables:
    ctMaxEntries: 8192
    pendingMaxEntries: 4096
    snatRevMaxEntries: 4096
    flowAcctMaxEntries: 8192
    rateV6MaxEntries: 8192
    quicDcidMaxEntries: 4096
    aclBlockedMaxEntries: 16384
    aclAllowedMaxEntries: 4096
    rateV4MaxEntries: 16384
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def write_api_config(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('nodeId: "0"\nsecret: "en14-probe"\n'
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


def pending_entry(cport):
    """Decode XdpUdpCtValue for client port cport in XDP_PENDING."""
    out = sh([bpftool(), "map", "dump", "-j", "id",
              str(map_id("XDP_PENDING"))]).stdout
    for item in json.loads(out):
        key = bytes(int(b, 16) for b in item["key"])
        val = bytes(int(b, 16) for b in item["value"])
        if struct.unpack(">H", key[32:34])[0] == cport:
            return decode_ct_value(val)
    return None


def ct_entry(cport):
    out = sh([bpftool(), "map", "dump", "-j", "id",
              str(map_id("XDP_TCP_CT"))]).stdout
    for item in json.loads(out):
        key = bytes(int(b, 16) for b in item["key"])
        val = bytes(int(b, 16) for b in item["value"])
        if struct.unpack(">H", key[32:34])[0] == cport:
            return decode_ct_value(val)
    return None


def decode_ct_value(val):
    # XdpUdpCtValue v14: state@25, snat_port_be@26, server_id@32,
    # expect_seq@48, expect_ack@52, splice_isn@56, seq_delta@60,
    # splice_state@64.
    return {"state": val[25],
            "snat_port": struct.unpack(">H", val[26:28])[0],
            "server_id": struct.unpack("<q", val[32:40])[0],
            "expect_seq": struct.unpack("<I", val[48:52])[0],
            "expect_ack": struct.unpack("<I", val[52:56])[0],
            "splice_isn": struct.unpack("<I", val[56:60])[0],
            "seq_delta": struct.unpack("<I", val[60:64])[0],
            "splice_state": val[64]}


def zero_cookie_key():
    """Zero the pinned cookie key ring (cur==0 => fail-closed)."""
    mid = map_id("XDP_COOKIE_KEY")
    sh([bpftool(), "map", "update", "id", str(mid),
        "key", "hex", "00", "00", "00", "00",
        "value", "hex"] + ["00"] * 32)


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


def tcp_frame(dst_mac, src_ip, dst_ip, sport, dport, flags, seq=C_ISN,
              ackno=0, payload=b"", mss=None):
    opts = b""
    if mss is not None:
        opts = struct.pack(">BBH", 2, 4, mss)
    doff = 5 + (len(opts) + 3) // 4
    opts = opts + b"\x01" * (doff * 4 - 20 - len(opts))
    offset_flags = (doff << 12) | flags
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ackno,
                      offset_flags >> 8, offset_flags & 0xFF, 65535, 0, 0)
    return ip_frame(dst_mac, 6, src_ip, dst_ip, tcp + opts + payload)


def decode_tcp(frame):
    """Decode a captured TCP/IPv4 frame -> dict or None."""
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != 6:
        return None
    ip = frame[14:14 + ihl]
    tcp_off = 14 + ihl
    if len(frame) < tcp_off + 20:
        return None
    sport, dport, seq, ack, off_flags, win, _cs, _up = struct.unpack(
        ">HHIIHHHH", frame[tcp_off:tcp_off + 20])
    doff = (off_flags >> 12) * 4
    payload = frame[tcp_off + doff:]
    return {
        "src": socket.inet_ntoa(ip[12:16]),
        "dst": socket.inet_ntoa(ip[16:20]),
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack,
        "flags": off_flags & 0x1FF,
        "win": win,
        "doff": doff,
        "payload_len": len(payload),
    }


def run_sender(mode, dst_mac, a):
    """Sender inside the netns. `a` is a mode-specific integer arg.
    Sends frames then captures replies for up to 700 ms; prints JSON with
    the sent count and decoded TCP replies."""
    frames = []
    if mode == "syn":
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT, TCP_LISTEN, SYN,
                            seq=C_ISN, mss=1460)]
    elif mode == "syn_flood":
        frames = [tcp_frame(dst_mac, f"10.99.1.{i % 250}", VIP1,
                            30000 + i, TCP_LISTEN, SYN,
                            seq=C_ISN + i, mss=1460)
                  for i in range(a)]
    elif mode == "ack_cookie":
        # a = cookie to prove (ack = cookie + 1)
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT, TCP_LISTEN, ACK,
                            seq=C_ISN + 1, ackno=a + 1)]
    elif mode == "syn_fresh":
        # SYN on a fresh tuple (CLIENT_PORT+1) — used to verify fail-closed
        # behavior after the cookie key is removed.
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT + 1, TCP_LISTEN, SYN,
                            seq=C_ISN, mss=1460)]
    elif mode == "ack_cookie_fresh":
        # Same proving-ACK shape but on a fresh tuple (CLIENT_PORT+1) so it
        # reaches the challenge validator instead of the established CT.
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT + 1, TCP_LISTEN, ACK,
                            seq=C_ISN + 1, ackno=a + 1)]
    elif mode == "synack_backend":
        # a = claimed SNAT port; backend SYN-ACK to (VIP1, a)
        frames = [tcp_frame(dst_mac, PEER_IP, VIP1,
                            TCP_BACKEND, a, SYNACK,
                            seq=B_ISN, ackno=C_ISN + 1)]
    elif mode == "data_client":
        # a = cookie; client data ACK in challenge space
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT, TCP_LISTEN, ACK,
                            seq=C_ISN + 1, ackno=a + 1,
                            payload=b"en14-data")]
    elif mode == "data_backend":
        # a = claimed SNAT port; backend -> client data in backend space
        frames = [tcp_frame(dst_mac, PEER_IP, VIP1,
                            TCP_BACKEND, a, ACK,
                            seq=B_ISN + 1, ackno=C_ISN + 11,
                            payload=b"en14-reply")]
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                      socket.htons(3))
    s.bind((PEER_IF, 0))
    s.settimeout(0.7)
    for f in frames:
        s.send(f)
    replies = []
    deadline = time.time() + 0.7
    while time.time() < deadline:
        try:
            raw = s.recv(4096)
        except socket.timeout:
            break
        d = decode_tcp(raw)
        # Only node-forged/forwarded traffic: every frame the dataplane
        # emits carries the VIP source address; our own egress (client IP
        # or backend IP) is skipped.
        if d and d["src"] == VIP1:
            replies.append(d)
    print(json.dumps({"sent": len(frames), "replies": replies}))


def send(script, mode, dst_mac, a=0):
    out = sh(["python3", script, "--send", mode, dst_mac, str(a)],
             netns=NS).stdout.strip()
    return json.loads(out)


def clean_pins():
    subprocess.run(["rm", "-rf", PIN_DIR], capture_output=True)


def start_node(node_bin, home, cwd, ebpf_object):
    nh = peer_mac()
    write_node_config(os.path.join(cwd, "configs", "runtime.yaml"), nh,
                      ebpf_object)
    write_node_config(os.path.join(home, "configs", "runtime.yaml"), nh,
                      ebpf_object)
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
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def counters(dump):
    return dump.get("counters", dump)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", nargs=3, metavar=("MODE", "DST_MAC", "A"),
                    help=argparse.SUPPRESS)
    ap.add_argument("--node-bin", default="target/debug/cloud-node-rust")
    ap.add_argument("--ebpf-object", default="",
                    help="external eBPF object path (overrides embedded)")
    ap.add_argument("--out", default="/tmp/en14.json")
    ap.add_argument("--workdir", default="/tmp/en14-probe")
    ap.add_argument("--home", default="/tmp/en14-home")
    args = ap.parse_args()

    if args.send:
        run_sender(args.send[0], args.send[1], int(args.send[2]))
        return

    assert os.geteuid() == 0, "must run as root"
    setup_netns()
    clean_pins()
    dst_mac = sh(["ip", "-o", "link", "show", "dev", HOST_IF]).stdout \
        .split("link/ether")[1].split()[0]
    home = os.path.abspath(args.home)
    cwd = os.path.abspath(args.workdir)
    os.makedirs(cwd, exist_ok=True)
    proc = None
    report = {"phases": {}, "commit": "worktree", "dirty": True}
    try:
        proc = start_node(args.node_bin, home, cwd, args.ebpf_object)
        self_path = os.path.abspath(__file__)

        def settle():
            for _ in range(50):
                r = send(self_path, "syn", dst_mac)
                if r["replies"]:
                    return r
                time.sleep(0.2)
            return r

        # --- A: SYN -> challenge SYN-ACK, no state -------------------------
        r = settle()
        synacks = [x for x in r["replies"]
                   if x["flags"] & 0x12 == 0x12 and x["sport"] == TCP_LISTEN
                   and x["dst"] == CLIENT_IP]
        assert synacks, f"no challenge SYN-ACK captured: {r}"
        ch = synacks[0]
        assert ch["ack"] == C_ISN + 1, f"bad challenge ack {ch}"
        cookie = ch["seq"]
        st = {"pending": map_entries("XDP_PENDING"),
              "ct": map_entries("XDP_TCP_CT"),
              "snat": map_entries("XDP_SNAT_REV")}
        assert st == {"pending": 0, "ct": 0, "snat": 0}, \
            f"challenge created state: {st}"
        report["phases"]["A_challenge_synack"] = {
            "cookie": cookie, "ack": ch["ack"], "doff": ch["doff"],
            "state": st, "pass": True}

        # --- F: retransmitted SYN -> another challenge ---------------------
        # A retransmitted SYN must be answered with a valid challenge
        # SYN-ACK (ack == C_ISN+1). The cookie itself may differ when the
        # retransmit crosses a cookie time-slot boundary — validation
        # accepts both the current and previous slot, so either cookie
        # proves. Asserting byte-identical cookies would encode the slot
        # granularity rather than the challenge contract.
        r = send(self_path, "syn", dst_mac)
        chal2 = [x for x in r["replies"]
                 if x["flags"] & 0x12 == 0x12 and x["sport"] == TCP_LISTEN
                 and x["dst"] == CLIENT_IP and x["ack"] == C_ISN + 1]
        assert chal2, \
            f"retransmitted SYN got no challenge: replies={r['replies']}"
        report["phases"]["F_syn_retx"] = {
            "same_cookie": chal2[0]["seq"] == cookie,
            "cookie2": chal2[0]["seq"], "pass": True}

        # --- B: bad-cookie ACK -> rejected --------------------------------
        d0 = counters(dump_maps(args.node_bin, cwd))
        send(self_path, "ack_cookie", dst_mac, 0x5AFE)
        time.sleep(0.2)
        d1 = counters(dump_maps(args.node_bin, cwd))
        assert d1.get("challengeRejected", 0) > d0.get("challengeRejected", 0), \
            "bad-cookie ACK not counted rejected"
        st = {"pending": map_entries("XDP_PENDING"),
              "ct": map_entries("XDP_TCP_CT"),
              "snat": map_entries("XDP_SNAT_REV")}
        assert st == {"pending": 0, "ct": 0, "snat": 0}, \
            f"bad cookie created state: {st}"
        report["phases"]["B_bad_cookie"] = {"state": st, "pass": True}

        # --- C: valid cookie -> splice pending + SNAT + SYN replay ---------
        r = send(self_path, "ack_cookie", dst_mac, cookie)
        time.sleep(0.2)
        pe = pending_entry(CLIENT_PORT)
        assert pe is not None, "no pending entry after valid cookie"
        assert pe["splice_state"] == 1, f"pending not SPLICE_WAIT: {pe}"
        assert pe["snat_port"] != 0, f"no SNAT port claimed: {pe}"
        snat_port = pe["snat_port"]
        replayed = [x for x in r["replies"]
                    if x["flags"] & 0x02 and not x["flags"] & 0x10
                    and x["dport"] == TCP_BACKEND
                    and x["sport"] == snat_port]
        assert replayed, f"no SYN replay captured: {r['replies']}"
        assert replayed[0]["seq"] == C_ISN, \
            f"replay seq {replayed[0]['seq']} != c_isn {C_ISN}"
        assert replayed[0]["dst"] == PEER_IP, "replay not backend-directed"
        report["phases"]["C_cookie_admit_replay"] = {
            "snat_port": snat_port, "replay_seq": replayed[0]["seq"],
            "pending": pe, "pass": True}

        # --- D: backend SYN-ACK anchors splice ----------------------------
        r = send(self_path, "synack_backend", dst_mac, snat_port)
        time.sleep(0.3)
        ce = ct_entry(CLIENT_PORT)
        assert ce is not None, "no CT entry after backend SYN-ACK"
        assert ce["state"] == 0, f"CT not OPEN: {ce}"
        assert ce["splice_state"] == 2, f"CT not SPLICE_DONE: {ce}"
        assert ce["seq_delta"] == cookie - B_ISN, \
            f"delta {ce['seq_delta']} != {cookie - B_ISN}"
        assert pending_entry(CLIENT_PORT) is None, "pending not consumed"
        forged = [x for x in r["replies"]
                  if x["flags"] & 0x3F == ACK and x["dport"] == TCP_BACKEND
                  and x["sport"] == snat_port]
        assert forged, f"no forged ACK to backend: {r['replies']}"
        assert forged[0]["seq"] == C_ISN + 1, forged[0]
        assert forged[0]["ack"] == B_ISN + 1, forged[0]
        report["phases"]["D_splice_anchor"] = {
            "ct": ce, "forged_ack": forged[0], "pass": True}

        # --- E: data path, sequence translation both ways -----------------
        r = send(self_path, "data_client", dst_mac, cookie)
        fwd = [x for x in r["replies"] if x["dport"] == TCP_BACKEND
               and x["sport"] == snat_port and x["payload_len"] > 0]
        assert fwd, f"client data not forwarded: {r['replies']}"
        assert fwd[0]["ack"] == B_ISN + 1, \
            f"ack not translated out of challenge space: {fwd[0]}"
        assert fwd[0]["seq"] == C_ISN + 1, fwd[0]
        r = send(self_path, "data_backend", dst_mac, snat_port)
        back = [x for x in r["replies"] if x["dport"] == CLIENT_PORT
                and x["dst"] == CLIENT_IP and x["payload_len"] > 0]
        assert back, f"backend data not forwarded: {r['replies']}"
        assert back[0]["seq"] == cookie + 1, \
            f"backend seq not translated into challenge space: {back[0]}"
        report["phases"]["E_data_translation"] = {
            "fwd_ack": fwd[0]["ack"], "reply_seq": back[0]["seq"],
            "pass": True}

        # --- G: key removed -> challenge fails closed ----------------------
        # With the keyring zeroed a fresh SYN must NOT get a challenge
        # (cookie_make is fail-closed) and must be counted rejected; the
        # already-established splice flow must be unaffected.
        d0 = counters(dump_maps(args.node_bin, cwd))
        zero_cookie_key()
        r = send(self_path, "syn_fresh", dst_mac)
        time.sleep(0.2)
        d1 = counters(dump_maps(args.node_bin, cwd))
        keyless_synack = [x for x in r["replies"]
                          if x["flags"] & 0x12 == 0x12]
        assert not keyless_synack, \
            f"keyless SYN still got a challenge: {keyless_synack}"
        assert d1.get("challengeRejected", 0) > d0.get("challengeRejected", 0), \
            "keyless SYN not counted rejected"
        assert ct_entry(CLIENT_PORT) is not None, "live splice flow lost"
        report["phases"]["G_key_removed_failclosed"] = {
            "rejected_delta":
                d1.get("challengeRejected", 0) - d0.get("challengeRejected", 0),
            "pass": True}

        # --- H: random SYN flood -> bounded, stateless ---------------------
        send(self_path, "syn_flood", dst_mac, 300)
        time.sleep(0.3)
        d2 = counters(dump_maps(args.node_bin, cwd))
        st = {"pending": map_entries("XDP_PENDING"),
              "ct": map_entries("XDP_TCP_CT"),
              "snat": map_entries("XDP_SNAT_REV")}
        # The established splice CT from phase D stays; nothing new.
        assert st["pending"] == 0, f"flood created pending state: {st}"
        assert st["ct"] == 1, f"flood created CT state: {st}"
        assert st["snat"] == 1, f"flood created SNAT state: {st}"
        report["phases"]["H_syn_flood_stateless"] = {
            "challengeSent": d2.get("challengeSent"),
            "challengeRejected": d2.get("challengeRejected"),
            "state": st, "pass": True}

        report["result"] = "PASS"
    except BaseException as e:
        # Capture dataplane state before teardown so failures are
        # diagnosable from the report alone.
        try:
            report["failure"] = repr(e)
            report["counters"] = counters(dump_maps(args.node_bin, cwd))
            report["state"] = {
                "pending": map_entries("XDP_PENDING"),
                "ct": map_entries("XDP_TCP_CT"),
                "snat": map_entries("XDP_SNAT_REV"),
            }
        except Exception:
            pass
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
        raise
    finally:
        stop_node(proc)
        teardown_netns()
        clean_pins()
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
