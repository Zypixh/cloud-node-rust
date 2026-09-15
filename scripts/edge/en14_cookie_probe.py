#!/usr/bin/env python3
"""EN-14 evidence probe: stateless TCP cookie challenge + sequence splice
against the real eBPF dataplane (ADR-001).

Topology: veth pair en14-a (host, VIP 10.99.0.5, XDP attached) <-> en14-b
(netns en14-ns, 10.99.0.6 backend). VIP1 TCP :8443 -> backend :9443 with
snat+challenge enabled.

Phases:
  A SYN -> challenge SYN-ACK: forged reply captured on the peer interface
    (SYN|ACK, ack = c_isn+1, ISN = cookie); challengeSent increments and
    NO state is created (pending/CT/SNAT all stay empty). The cookie is
    verified against a locally computed SipHash under the installed key.
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
  G key removed -> fresh SYN gets no challenge, an ACK carrying a cookie
    forged under the KNOWN-ZERO key is still rejected (fail-closed), and
    the established splice flow keeps transferring data.
  I forge fault injection (XDP_PENDING_CAP_FAIL_FORGE): challenge-path
    SYN and admit-path ACK are dropped with challengeWorkerErr counted,
    no pending/SNAT state leaks; clearing the flag lets the same ACK
    re-admit (bounded recovery).
  J splice-anchor forge fault: backend SYN-ACK under FAIL_FORGE is
    dropped with pending SPLICE_WAIT untouched (no partial splice);
    retransmitted SYN-ACK anchors once the flag clears.
  H random SYN flood under a restored key and an explicit small dim3
    budget -> challenges bounded by the budget, excess counted rejected,
    refill restores challenges, no state allocated for unverified SYNs.

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
# Separate address for the real-kernel-TCP client: replies crafted to
# CLIENT_IP must NOT resolve to a local socket (or the kernel RSTs them
# and disturbs the raw-frame phases' CT state).
REAL_CLIENT_IP = "10.99.0.10"
# bpffs is NOT isolated by netns: the production default pin dir must
# never be cleaned by a probe. This task pins under a unique per-run
# root via CLOUD_NODE_XDP_PIN_DIR and only that exact dir is removed.
BPF_PIN_ROOT = "/sys/fs/bpf"
PROD_PIN_DIR = "/sys/fs/bpf/cloud-node-xdp"
PIN_DIR = f"{BPF_PIN_ROOT}/en14-probe-{os.getpid()}"
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
# Explicit dim3 challenge budget for phase H (per-second ceiling applied
# over WINDOW_MS accounting windows; per-CPU shared by userspace).
CHALLENGE_PPS = 40
WINDOW_MS = 500
# Known keys installed by the probe itself so captured cookies can be
# verified against a local SipHash — end-to-end crypto check, not just
# "a SYN-ACK arrived".
KNOWN_KEY = bytes(range(0xA0, 0xB0))
KNOWN_KEY2 = bytes(range(0xC0, 0xD0))
KNOWN_KEY3 = bytes(range(0xE0, 0xF0))
ZERO_KEY = b"\x00" * 16
# XDP_PENDING_CAP.flags fault-injection bits (ABI v16).
FAIL_CT_INSERT = 1 << 0
FAIL_PENDING_INSERT = 1 << 1
FAIL_SNAT_ALLOC = 1 << 2
FAIL_FORGE = 1 << 3

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
    # Client address for the real-kernel-TCP phase: a real socket needs a
    # local address to bind. It is deliberately NOT CLIENT_IP so raw
    # crafted frames never match a local socket (which would trigger
    # kernel RSTs that disturb splice state).
    sh(["ip", "netns", "exec", NS, "ip", "addr", "add",
        f"{REAL_CLIENT_IP}/24", "dev", PEER_IF])
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
  # Explicit small dim3 budget so phase H can assert challenge limiting
  # against a known ceiling instead of a merged counter.
  budget:
    challengePps: {CHALLENGE_PPS}
    windowMs: {WINDOW_MS}
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
    out = sh([os.path.abspath(node_bin), "xdp", "dump-maps"],
             cwd=cwd).stdout
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


def set_cookie_key(cur, prev=b"\x00" * 16):
    """Write the cookie key ring (XdpCookieKey: cur[16] prev[16])."""
    assert len(cur) == 16 and len(prev) == 16
    mid = map_id("XDP_COOKIE_KEY")
    sh([bpftool(), "map", "update", "id", str(mid),
        "key", "hex", "00", "00", "00", "00",
        "value", "hex"] + [f"{b:02x}" for b in cur + prev])


def zero_cookie_key():
    """Zero the pinned cookie key ring (cur==0 => fail-closed)."""
    set_cookie_key(ZERO_KEY)


def pending_cap_flags(set_to=None, or_mask=None):
    """Read-modify-write XDP_PENDING_CAP.flags preserving the capacity
    fields the node synced (max_pending u64, ttl u64, flags u64)."""
    mid = map_id("XDP_PENDING_CAP")
    out = sh([bpftool(), "map", "dump", "-j", "id", str(mid)]).stdout
    val = bytes(int(b, 16) for b in json.loads(out)[0]["value"])
    assert len(val) == 24, f"XDP_PENDING_CAP value {len(val)}B != 24"
    maxp, ttl, flags = struct.unpack("<QQQ", val)
    if set_to is not None:
        flags = set_to
    elif or_mask is not None:
        flags |= or_mask
    newv = struct.pack("<QQQ", maxp, ttl, flags)
    sh([bpftool(), "map", "update", "id", str(mid),
        "key", "hex", "00", "00", "00", "00",
        "value", "hex"] + [f"{b:02x}" for b in newv])
    return flags


def pending_cap_ttl(ns):
    """Set XDP_PENDING_CAP.pending_ttl_ns (absolute half-open deadline).
    Returns the previous value so the probe can restore it."""
    mid = map_id("XDP_PENDING_CAP")
    out = sh([bpftool(), "map", "dump", "-j", "id", str(mid)]).stdout
    val = bytes(int(b, 16) for b in json.loads(out)[0]["value"])
    assert len(val) == 24, f"XDP_PENDING_CAP value {len(val)}B != 24"
    maxp, ttl, flags = struct.unpack("<QQQ", val)
    newv = struct.pack("<QQQ", maxp, ns, flags)
    sh([bpftool(), "map", "update", "id", str(mid),
        "key", "hex", "00", "00", "00", "00",
        "value", "hex"] + [f"{b:02x}" for b in newv])
    return ttl


# --- cookie model: mirrors siphash24_16/cookie_pack/cookie_slot in the
# eBPF source so captured cookies can be verified against the keyring ---
M64 = 0xFFFFFFFFFFFFFFFF


def _rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M64


def siphash24_16(key16, w0, w1):
    k0 = int.from_bytes(key16[:8], "little")
    k1 = int.from_bytes(key16[8:], "little")
    v = [k0 ^ 0x736f6d6570736575, k1 ^ 0x646f72616e646f6d,
         k0 ^ 0x6c7967656e657261, k1 ^ 0x7465646279746573]

    def sip():
        v[0] = (v[0] + v[1]) & M64
        v[1] = _rotl(v[1], 13)
        v[1] ^= v[0]
        v[0] = _rotl(v[0], 32)
        v[2] = (v[2] + v[3]) & M64
        v[3] = _rotl(v[3], 16)
        v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & M64
        v[3] = _rotl(v[3], 21)
        v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & M64
        v[1] = _rotl(v[1], 17)
        v[1] ^= v[2]
        v[2] = _rotl(v[2], 32)

    v[3] ^= w0
    sip(); sip()
    v[0] ^= w0
    v[3] ^= w1
    sip(); sip()
    v[0] ^= w1
    b = 16 << 56
    v[3] ^= b
    sip(); sip()
    v[0] ^= b
    v[2] ^= 0xFF
    sip(); sip(); sip(); sip()
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def cookie_slot(now_ns):
    # matches cookie_slot(): ~4.3s slots
    return (now_ns >> 32) & 0xFFFFFFFF


def cookie_expected(key16, client_ip, client_port, listen_ip, listen_port,
                    slot):
    client_be = int.from_bytes(socket.inet_aton(client_ip), "big")
    listen_be = int.from_bytes(socket.inet_aton(listen_ip), "big")
    # eBPF cookie_pack(client_be, src_port.to_be(), dst_port): src_port
    # round-trips to the host port number; dst_port keeps the wire
    # (network-order) value re-read in native order — the byte swap.
    listen_port_swapped = int.from_bytes(
        struct.pack(">H", listen_port), "little")
    tup = (client_be << 32) | (client_port << 16) | listen_port_swapped
    w1 = (listen_be << 32) | slot
    return siphash24_16(key16, tup, w1) & 0xFFFFFFFF


def cookie_matches(cookie_val, key16, client_port):
    """Validate a captured cookie against the current or previous slot —
    validation accepts both, so the probe must too."""
    slot = cookie_slot(time.monotonic_ns())
    for s in (slot, (slot - 1) & 0xFFFFFFFF):
        exp = cookie_expected(key16, CLIENT_IP, client_port, VIP1,
                              TCP_LISTEN, s)
        if (cookie_val & ~7) == (exp & ~7):
            return True
    return False


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
              ackno=0, payload=b"", mss=None, raw_opts=None):
    if raw_opts is not None:
        opts = raw_opts
    elif mss is not None:
        opts = struct.pack(">BBH", 2, 4, mss)
    else:
        opts = b""
    doff = 5 + (len(opts) + 3) // 4
    opts = opts + b"\x01" * (doff * 4 - 20 - len(opts))
    offset_flags = (doff << 12) | flags
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ackno,
                      offset_flags >> 8, offset_flags & 0xFF, 65535, 0, 0)
    seg = tcp + opts + payload
    # A real client transmits a valid checksum; the dataplane maintains it
    # incrementally across rewrites, so the input field must be genuine —
    # csum16() returns the complement value to store.
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + \
        struct.pack(">BBH", 0, 6, len(seg))
    seg = seg[:16] + struct.pack(">H", csum16(pseudo + seg)) + seg[18:]
    return ip_frame(dst_mac, 6, src_ip, dst_ip, seg)


def decode_tcp(frame):
    """Decode a captured TCP/IPv4 frame -> dict or None. Independently
    recomputes the IP and TCP checksums so a forge-path checksum defect
    (e.g. stale scratch bytes folded in) fails the probe — the raw-socket
    sender never needs a real TCP stack to accept the replies, so field
    assertions alone cannot catch it."""
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
    ip_tot = struct.unpack(">H", ip[2:4])[0]
    seg = frame[tcp_off:14 + ip_tot]
    payload = frame[tcp_off + doff:14 + ip_tot]
    # IP header checksum over the header as received (field included):
    # a valid header sums to 0.
    ip_ok = csum16(ip) == 0
    # TCP checksum = pseudo-header + segment as received; valid => 0.
    pseudo = ip[12:20] + struct.pack(">BBH", 0, 6, len(seg))
    tcp_ok = csum16(pseudo + seg) == 0
    out = {
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
        "ip_csum_ok": ip_ok,
        "tcp_csum_ok": tcp_ok,
    }
    out["raw"] = frame[:14 + ihl + doff + len(payload)].hex()
    return out


def run_sender(mode, dst_mac, a):
    """Sender inside the netns. `a` is a mode-specific integer arg.
    Sends frames then captures replies for up to 700 ms; prints JSON with
    the sent count and decoded TCP replies."""
    frames = []
    if mode == "syn":
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT, TCP_LISTEN, SYN,
                            seq=C_ISN, mss=1460)]
    elif mode == "syn_p":
        # a = client port — parameterized fresh-tuple SYN so isolated
        # phases never disturb the primary flow.
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            a, TCP_LISTEN, SYN,
                            seq=C_ISN, mss=1460)]
    elif mode == "ack_cookie_p":
        # a = (client_port << 32) | cookie — proving ACK on an explicit
        # fresh tuple.
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            a >> 32, TCP_LISTEN, ACK,
                            seq=C_ISN + 1, ackno=(a & 0xFFFFFFFF) + 1)]
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
    elif mode == "syn_nomss":
        # a = client port — SYN with NO options (doff=5): parser must take
        # the conservative 536 fallback (cookie idx 0), not a default 1460.
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            a, TCP_LISTEN, SYN, seq=C_ISN)]
    elif mode == "syn_badmss":
        # a = client port — SYN with a malformed MSS option (kind=2, len=3
        # truncated): parser must reject it and fall back to idx 0 (536).
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            a, TCP_LISTEN, SYN, seq=C_ISN,
                            raw_opts=b"\x02\x03\xff\xbe")]
    elif mode == "data_client":
        # a = cookie; client data ACK in challenge space
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT, TCP_LISTEN, ACK,
                            seq=C_ISN + 1, ackno=a + 1,
                            payload=b"en14-data")]
    elif mode == "data_client_b":
        # Checksum-differential variant: different ack arg + payload so the
        # ack-translation diff term changes while addr/port terms stay fixed.
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT, TCP_LISTEN, ACK,
                            seq=C_ISN + 1, ackno=a + 0x401,
                            payload=b"en14-DATX")]
    elif mode == "data_p":
        # a = (client_port << 32) | cookie — parameterized-tuple data ACK
        # carrying a valid cookie proof in ackno. Triple duty: the same
        # wire shape serves as (a) the admitting ACK *with payload*,
        # (b) a client data packet arriving while the splice is in flight
        # (must be consumed), and (c) post-splice client data.
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            a >> 32, TCP_LISTEN, ACK,
                            seq=C_ISN + 1, ackno=(a & 0xFFFFFFFF) + 1,
                            payload=b"en14-pdat")]
    elif mode == "data_ooo":
        # a = (seq_off << 32) | cookie — out-of-order client data on the
        # MAIN spliced tuple: seq is offset past the anchored position so
        # the stateless splice delta is exercised on a non-in-order
        # segment (duplicates reuse data_client with the same seq).
        frames = [tcp_frame(dst_mac, CLIENT_IP, VIP1,
                            CLIENT_PORT, TCP_LISTEN, ACK,
                            seq=C_ISN + 1 + (a >> 32),
                            ackno=(a & 0xFFFFFFFF) + 1,
                            payload=b"en14-ooo")]
    elif mode == "data_backend":
        # a = claimed SNAT port; backend -> client data in backend space
        frames = [tcp_frame(dst_mac, PEER_IP, VIP1,
                            TCP_BACKEND, a, ACK,
                            seq=B_ISN + 1, ackno=C_ISN + 11,
                            payload=b"en14-reply")]
    elif mode == "real_tcp":
        # Real kernel TCP on BOTH ends: a listening socket on the backend
        # tuple and a real client socket bound to the client address.
        # Exercises the full challenge -> admit -> splice -> translate
        # path through actual TCP stacks (real ISNs, retransmission,
        # FIN teardown), not crafted frames.
        import threading
        result = {"mode": "real_tcp"}
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((PEER_IP, TCP_BACKEND))
        srv.listen(4)
        srv.settimeout(15)
        seen = {}

        def serve():
            try:
                conn, addr = srv.accept()
                seen["peer"] = addr[1]
                data = conn.recv(64)
                conn.sendall(b"echo:" + data)
                # Wait for the peer to close so the FIN exchange runs
                # through the splice in both directions.
                conn.settimeout(10)
                try:
                    conn.recv(64)
                except socket.timeout:
                    pass
                conn.close()
                seen["served"] = True
            except Exception as e:  # noqa: BLE001 — surface in report
                seen["error"] = repr(e)

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.settimeout(15)
        c.bind((REAL_CLIENT_IP, 0))
        c.connect((VIP1, TCP_LISTEN))
        result["client_port"] = c.getsockname()[1]
        c.sendall(b"en14-real")
        result["reply"] = c.recv(64).decode(errors="replace")
        c.close()
        t.join(timeout=10)
        result["backend"] = seen
        # Second connection closed with RST (SO_LINGER=0): exercises the
        # abortive teardown path against live splice state.
        c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c2.settimeout(15)
        c2.bind((REAL_CLIENT_IP, 0))
        c2.connect((VIP1, TCP_LISTEN))
        result["client_port2"] = c2.getsockname()[1]
        c2.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                      struct.pack("ii", 1, 0))
        c2.close()
        srv.close()
        print(json.dumps(result))
        return
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
    print(json.dumps({"sent": len(frames), "replies": replies,
                      "sent_hex": [f.hex() for f in frames[:4]]}))


def send(script, mode, dst_mac, a=0):
    out = sh(["python3", script, "--send", mode, dst_mac, str(a)],
             netns=NS).stdout.strip()
    return json.loads(out)


def clean_pins():
    # Remove ONLY this run's unique pin dir. The production default
    # (/sys/fs/bpf/cloud-node-xdp) and anything not created by this run
    # are never touched — bpffs is shared across netns boundaries.
    if not PIN_DIR.startswith(f"{BPF_PIN_ROOT}/en14-probe-") \
            or PIN_DIR == PROD_PIN_DIR:
        raise RuntimeError(f"refusing to clean unexpected pin dir {PIN_DIR}")
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
    env = dict(os.environ, CLOUD_NODE_HOME=home, RUST_LOG="info",
               CLOUD_NODE_XDP_PIN_DIR=PIN_DIR)
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
    assert PIN_DIR != PROD_PIN_DIR \
        and PIN_DIR.startswith(f"{BPF_PIN_ROOT}/en14-probe-"), \
        f"pin dir isolation violated: {PIN_DIR}"
    # All children (node, xdp dump-maps, senders) inherit the task pin
    # root so nothing under the production default dir is read or written.
    os.environ["CLOUD_NODE_XDP_PIN_DIR"] = PIN_DIR
    prod_pins_before = os.path.exists(PROD_PIN_DIR)
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

        # --- phase isolation: dataplane must start with zero flow state --
        st0 = {"pending": map_entries("XDP_PENDING"),
               "ct": map_entries("XDP_TCP_CT"),
               "snat": map_entries("XDP_SNAT_REV")}
        assert st0 == {"pending": 0, "ct": 0, "snat": 0}, \
            f"pre-run state not isolated: {st0}"
        report["phases"]["0_isolation"] = {"state": st0, "pass": True}
        # Install a KNOWN key so every captured cookie is verified against
        # a local SipHash — not merely "some SYN-ACK arrived".
        set_cookie_key(KNOWN_KEY)

        # --- A: SYN -> challenge SYN-ACK, no state -------------------------
        r = settle()
        synacks = [x for x in r["replies"]
                   if x["flags"] & 0x12 == 0x12 and x["sport"] == TCP_LISTEN
                   and x["dst"] == CLIENT_IP]
        assert synacks, f"no challenge SYN-ACK captured: {r}"
        ch = synacks[0]
        assert ch["ack"] == C_ISN + 1, f"bad challenge ack {ch}"
        assert ch["ip_csum_ok"] and ch["tcp_csum_ok"], \
            f"challenge frame checksum invalid: {ch}"
        # The cookie must be exactly SipHash(key, tuple, slot) — verified
        # end-to-end under the probe-installed key.
        assert cookie_matches(ch["seq"], KNOWN_KEY, CLIENT_PORT), \
            f"challenge cookie {ch['seq']} does not match keyed hash"
        assert ch["seq"] & 7 == 3, \
            f"mss idx {ch['seq'] & 7} != 3 (mss=1460)"
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
        assert chal2[0]["tcp_csum_ok"], f"rechallenge csum: {chal2[0]}"
        assert cookie_matches(chal2[0]["seq"], KNOWN_KEY, CLIENT_PORT), \
            f"rechallenge cookie {chal2[0]['seq']} not keyed-valid"
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
        assert replayed[0]["ip_csum_ok"] and replayed[0]["tcp_csum_ok"], \
            f"replay checksum invalid: {replayed[0]}"
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
        assert forged[0]["ip_csum_ok"] and forged[0]["tcp_csum_ok"], \
            f"forged ACK checksum invalid: {forged[0]}"
        report["phases"]["D_splice_anchor"] = {
            "ct": ce, "forged_ack": forged[0], "pass": True}

        # --- E: data path, sequence translation both ways -----------------
        r = send(self_path, "data_client", dst_mac, cookie)
        report["phases"]["E_raw_c2b"] = r["replies"]
        report["phases"]["E_sent_c2b"] = r.get("sent_hex")
        fwd = [x for x in r["replies"] if x["dport"] == TCP_BACKEND
               and x["sport"] == snat_port and x["payload_len"] > 0]
        # Second c->b frame + b->c reply captured BEFORE assertions so the
        # checksum differential isolates which field's diff is wrong.
        r = send(self_path, "data_client_b", dst_mac, cookie)
        report["phases"]["E_raw_c2b_2"] = r["replies"]
        report["phases"]["E_sent_c2b_2"] = r.get("sent_hex")
        r = send(self_path, "data_backend", dst_mac, snat_port)
        report["phases"]["E_raw_b2c"] = r["replies"]
        report["phases"]["E_sent_b2c"] = r.get("sent_hex")
        assert fwd, f"client data not forwarded: {report['phases']['E_raw_c2b']}"
        assert fwd[0]["ack"] == B_ISN + 1, \
            f"ack not translated out of challenge space: {fwd[0]}"
        assert fwd[0]["seq"] == C_ISN + 1, fwd[0]
        assert fwd[0]["tcp_csum_ok"], f"translated data csum: {fwd[0]}"
        back = [x for x in r["replies"] if x["dport"] == CLIENT_PORT
                and x["dst"] == CLIENT_IP and x["payload_len"] > 0]
        assert back, f"backend data not forwarded: {r['replies']}"
        assert back[0]["tcp_csum_ok"], f"reply csum: {back[0]}"
        assert back[0]["seq"] == cookie + 1, \
            f"backend seq not translated into challenge space: {back[0]}"
        report["phases"]["E_data_translation"] = {
            "fwd_ack": fwd[0]["ack"], "reply_seq": back[0]["seq"],
            "pass": True}

        # --- M: malformed/absent MSS -> conservative 536 fallback ----------
        # R2.3: the cookie's low 3 bits carry the negotiated MSS index;
        # index 0 == 536. Absent options (doff=5) and a malformed MSS
        # option (kind=2, len=3) must both land on the fallback — never on
        # the previous oversized 1460 default.
        m_out = {}
        r = send(self_path, "syn_nomss", dst_mac, CLIENT_PORT + 10)
        sa = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12 and x["dport"] == CLIENT_PORT + 10]
        assert sa, f"nomss SYN got no challenge: {r['replies']}"
        assert sa[0]["seq"] & 7 == 0, \
            f"nomss cookie mss idx {sa[0]['seq'] & 7} != 0: {sa[0]}"
        m_out["nomss_idx"] = sa[0]["seq"] & 7
        m_out["nomss_doff"] = sa[0]["doff"]
        r = send(self_path, "syn_badmss", dst_mac, CLIENT_PORT + 11)
        sa = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12 and x["dport"] == CLIENT_PORT + 11]
        assert sa, f"badmss SYN got no challenge: {r['replies']}"
        assert sa[0]["seq"] & 7 == 0, \
            f"badmss cookie mss idx {sa[0]['seq'] & 7} != 0: {sa[0]}"
        m_out["badmss_idx"] = sa[0]["seq"] & 7
        # The forged SYN-ACK echoes the fallback MSS (536 = 0x0218) in its
        # option bytes when the ingress frame carried an option field.
        if sa[0]["doff"] == 24:
            raw = bytes.fromhex(sa[0]["raw"])
            ihl = (raw[14] & 0x0F) * 4
            opt = raw[14 + ihl + 20:14 + ihl + 24]
            assert opt == b"\x02\x04\x02\x18", \
                f"forged SYN-ACK MSS option {opt.hex()} != 536"
            m_out["badmss_reply_mss"] = 536
        report["phases"]["M_mss_fallback"] = {**m_out, "pass": True}

        # --- G: key removed -> challenge fails closed ----------------------
        # With the keyring zeroed: (a) a fresh SYN must NOT get a challenge
        # (cookie_make is fail-closed); (b) an ACK carrying a cookie forged
        # under the KNOWN-ZERO key must still be rejected — an absent key
        # is not a valid key; (c) the established splice flow keeps
        # transferring data (existing CT state is unaffected by key loss).
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
        # (b) zero-key forged cookie counterexample: the attacker knows
        # the all-zero key and computes a perfectly-shaped proof for a
        # FRESH tuple. It must still be rejected.
        slot = cookie_slot(time.monotonic_ns())
        forged_cookie = cookie_expected(
            ZERO_KEY, CLIENT_IP, CLIENT_PORT + 1, VIP1, TCP_LISTEN, slot)
        send(self_path, "ack_cookie_p", dst_mac,
             ((CLIENT_PORT + 1) << 32) | forged_cookie)
        time.sleep(0.2)
        d2 = counters(dump_maps(args.node_bin, cwd))
        assert d2.get("challengeRejected", 0) > d1.get("challengeRejected", 0), \
            "zero-key forged cookie was not rejected"
        assert pending_entry(CLIENT_PORT + 1) is None, \
            "zero-key cookie created pending state"
        # (c) the spliced flow still carries data while the keyring is empty.
        r = send(self_path, "data_client", dst_mac, cookie)
        fwd = [x for x in r["replies"] if x["dport"] == TCP_BACKEND
               and x["sport"] == snat_port and x["payload_len"] > 0]
        assert fwd, "established flow stopped forwarding while keyless"
        report["phases"]["G_key_removed_failclosed"] = {
            "rejected_delta":
                d2.get("challengeRejected", 0) - d0.get("challengeRejected", 0),
            "zero_key_cookie_rejected": True,
            "live_flow_forwarded": True,
            "pass": True}

        # --- I: forge fault injection — explicit DROP + rollback -----------
        # Restore the keyring first: G left it zeroed, and I's challenge
        # must be issued normally so the forge fault — not keyless
        # rejection — is what gets exercised.
        set_cookie_key(KNOWN_KEY)
        # XDP_PENDING_CAP_FAIL_FORGE makes the forge helpers fail; the
        # worker must emit a counted DROP (never PASS a half-forged frame)
        # and roll back admission state.
        flags0 = pending_cap_flags()
        pending_cap_flags(or_mask=FAIL_FORGE)
        d0 = counters(dump_maps(args.node_bin, cwd))
        r = send(self_path, "syn_p", dst_mac, CLIENT_PORT + 2)
        time.sleep(0.2)
        d1 = counters(dump_maps(args.node_bin, cwd))
        forge_synack = [x for x in r["replies"]
                        if x["flags"] & 0x12 == 0x12]
        assert not forge_synack, \
            f"SYN-ACK emitted despite injected forge fault: {forge_synack}"
        assert d1.get("challengeWorkerErr", 0) > \
            d0.get("challengeWorkerErr", 0), \
            "challenge-path forge fault not counted as worker error"
        # Admit path: get a valid cookie for a fresh tuple first (fault
        # cleared), then prove the rollback.
        pending_cap_flags(set_to=flags0)
        r = send(self_path, "syn_p", dst_mac, CLIENT_PORT + 3)
        ch3 = [x for x in r["replies"]
               if x["flags"] & 0x12 == 0x12 and x["dport"] == CLIENT_PORT + 3]
        assert ch3 and cookie_matches(ch3[0]["seq"], KNOWN_KEY,
                                      CLIENT_PORT + 3), \
            f"no valid challenge for admit-path test: {r['replies']}"
        cookie3 = ch3[0]["seq"]
        snat_before = map_entries("XDP_SNAT_REV")
        pending_cap_flags(or_mask=FAIL_FORGE)
        d0 = counters(dump_maps(args.node_bin, cwd))
        send(self_path, "ack_cookie_p", dst_mac,
             ((CLIENT_PORT + 3) << 32) | cookie3)
        time.sleep(0.2)
        d1 = counters(dump_maps(args.node_bin, cwd))
        assert d1.get("challengeWorkerErr", 0) > \
            d0.get("challengeWorkerErr", 0), \
            "admit-path forge fault not counted as worker error"
        assert pending_entry(CLIENT_PORT + 3) is None, \
            "forge fault leaked a pending record"
        assert map_entries("XDP_SNAT_REV") == snat_before, \
            "forge fault leaked a SNAT binding"
        # Recovery: clearing the flag lets the same proof re-admit.
        pending_cap_flags(set_to=flags0)
        send(self_path, "ack_cookie_p", dst_mac,
             ((CLIENT_PORT + 3) << 32) | cookie3)
        time.sleep(0.2)
        pe3 = pending_entry(CLIENT_PORT + 3)
        assert pe3 is not None and pe3["splice_state"] == 1, \
            f"re-admission after fault did not recover: {pe3}"
        snat3 = pe3["snat_port"]
        report["phases"]["I_forge_fault_rollback"] = {
            "worker_err_counted": True,
            "no_state_leak": True,
            "readmit_recovered": True,
            "pass": True}

        # --- J: splice-anchor forge fault -> no partial splice, retried ---
        pending_cap_flags(or_mask=FAIL_FORGE)
        d0 = counters(dump_maps(args.node_bin, cwd))
        send(self_path, "synack_backend", dst_mac, snat3)
        time.sleep(0.2)
        d1 = counters(dump_maps(args.node_bin, cwd))
        assert d1.get("challengeWorkerErr", 0) > \
            d0.get("challengeWorkerErr", 0), \
            "splice forge fault not counted as worker error"
        pe3 = pending_entry(CLIENT_PORT + 3)
        assert pe3 is not None and pe3["splice_state"] == 1, \
            f"forge fault left partial splice state: {pe3}"
        assert ct_entry(CLIENT_PORT + 3) is None, \
            "forge fault promoted CT without an emitted ACK"
        # Backend retransmission after the fault clears anchors cleanly.
        pending_cap_flags(set_to=flags0)
        send(self_path, "synack_backend", dst_mac, snat3)
        time.sleep(0.3)
        ce3 = ct_entry(CLIENT_PORT + 3)
        assert ce3 is not None and ce3["splice_state"] == 2, \
            f"splice did not recover on SYN-ACK retransmit: {ce3}"
        report["phases"]["J_splice_fault_recovery"] = {
            "no_partial_splice": True, "retrans_anchored": True,
            "pass": True}

        # --- K: remaining allocation fault points ------------------------
        # Each XDP_PENDING_CAP flag is exercised independently: the
        # failing allocation must leak no state and must be recoverable
        # once the flag clears.
        k = {}

        # K1 pending-insert fault: valid cookie proof, pending insert
        # forced to fail -> pending_limited++, SNAT binding rolled back,
        # no pending record.
        port = CLIENT_PORT + 11
        r = send(self_path, "syn_p", dst_mac, port)
        ch = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12 and x["dport"] == port]
        assert ch and cookie_matches(ch[0]["seq"], KNOWN_KEY, port), \
            f"K1 no valid challenge: {r['replies']}"
        ck = ch[0]["seq"]
        snat0 = map_entries("XDP_SNAT_REV")
        pending_cap_flags(set_to=flags0 | FAIL_PENDING_INSERT)
        d0 = counters(dump_maps(args.node_bin, cwd))
        send(self_path, "ack_cookie_p", dst_mac, (port << 32) | ck)
        time.sleep(0.2)
        d1 = counters(dump_maps(args.node_bin, cwd))
        assert d1.get("pendingLimited", 0) > d0.get("pendingLimited", 0), \
            "pending-insert fault not counted"
        assert pending_entry(port) is None, "pending-insert fault leaked pending"
        assert map_entries("XDP_SNAT_REV") == snat0, \
            "pending-insert fault leaked SNAT binding"
        k["pending_insert"] = {"leaks": 0, "counted": True}

        # K2 snat-alloc fault: the SNAT claim is forced to fail -> the
        # proof ACK is not admitted, no pending record appears, and the
        # alloc failure is counted.
        port = CLIENT_PORT + 12
        pending_cap_flags(set_to=flags0)
        r = send(self_path, "syn_p", dst_mac, port)
        ch = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12 and x["dport"] == port]
        assert ch, f"K2 no challenge: {r['replies']}"
        ck = ch[0]["seq"]
        pending_cap_flags(set_to=flags0 | FAIL_SNAT_ALLOC)
        d0 = counters(dump_maps(args.node_bin, cwd))
        send(self_path, "ack_cookie_p", dst_mac, (port << 32) | ck)
        time.sleep(0.2)
        d1 = counters(dump_maps(args.node_bin, cwd))
        assert d1.get("snatAllocFail", 0) > d0.get("snatAllocFail", 0), \
            "snat-alloc fault not counted"
        assert pending_entry(port) is None, "snat-alloc fault leaked pending"
        k["snat_alloc"] = {"leaks": 0, "counted": True}

        # K3 ct-insert fault at splice anchor: admit cleanly first, then
        # force the authoritative CT insert to fail -> the forged ACK is
        # dropped, pending stays SPLICE_WAIT, no CT entry; after clearing,
        # a backend SYN-ACK retransmit anchors.
        port = CLIENT_PORT + 13
        pending_cap_flags(set_to=flags0)
        r = send(self_path, "syn_p", dst_mac, port)
        ch = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12 and x["dport"] == port]
        assert ch, f"K3 no challenge: {r['replies']}"
        ck = ch[0]["seq"]
        send(self_path, "ack_cookie_p", dst_mac, (port << 32) | ck)
        time.sleep(0.2)
        pe = pending_entry(port)
        assert pe is not None and pe["splice_state"] == 1, \
            f"K3 admit failed: {pe}"
        pending_cap_flags(set_to=flags0 | FAIL_CT_INSERT)
        d0 = counters(dump_maps(args.node_bin, cwd))
        send(self_path, "synack_backend", dst_mac, pe["snat_port"])
        time.sleep(0.2)
        d1 = counters(dump_maps(args.node_bin, cwd))
        assert d1.get("tcpFwdMapFull", 0) > d0.get("tcpFwdMapFull", 0), \
            "ct-insert fault not counted"
        assert ct_entry(port) is None, "ct-insert fault promoted CT"
        pe = pending_entry(port)
        assert pe is not None and pe["splice_state"] == 1, \
            f"ct-insert fault corrupted pending: {pe}"
        pending_cap_flags(set_to=flags0)
        send(self_path, "synack_backend", dst_mac, pe["snat_port"])
        time.sleep(0.3)
        ce = ct_entry(port)
        assert ce is not None and ce["splice_state"] == 2, \
            f"K3 splice did not recover: {ce}"
        k["ct_insert"] = {"no_partial": True, "recovered": True}
        report["phases"]["K_alloc_fault_points"] = {**k, "pass": True}

        # --- H: SYN flood under a valid key and an explicit small budget ---
        # Restore a valid keyring (rotation shape: cur=KNOWN_KEY2,
        # prev=KNOWN_KEY) then flood: challenges must be bounded by the
        # configured dim3 budget, the excess counted rejected, and the
        # next window must refill the allowance.
        set_cookie_key(KNOWN_KEY2, KNOWN_KEY)
        d0 = counters(dump_maps(args.node_bin, cwd))
        send(self_path, "syn_flood", dst_mac, 300)
        time.sleep(0.3)
        d2 = counters(dump_maps(args.node_bin, cwd))
        sent_delta = d2.get("challengeSent", 0) - d0.get("challengeSent", 0)
        rej_delta = d2.get("challengeRejected", 0) \
            - d0.get("challengeRejected", 0)
        # Per-CPU share = ceil(40/ncpu); the burst can straddle at most two
        # windows. Generous bound keeps the assertion about the limit, not
        # about CPU scheduling.
        budget_max = CHALLENGE_PPS * 2
        assert sent_delta >= 1, "no challenges emitted under valid key"
        assert sent_delta <= budget_max, \
            f"flood challenges {sent_delta} exceeded budget {budget_max}"
        assert rej_delta >= 300 - sent_delta, \
            f"excess flood SYNs not counted rejected: {rej_delta}"
        st = {"pending": map_entries("XDP_PENDING"),
              "ct": map_entries("XDP_TCP_CT"),
              "snat": map_entries("XDP_SNAT_REV")}
        # The established CTs (main splice + phase J + phase K3) stay;
        # the flood must not grow any table.
        assert st["pending"] == 0, f"flood created pending state: {st}"
        assert st["ct"] == 3, f"flood created CT state: {st}"
        assert st["snat"] == 3, f"flood created SNAT state: {st}"
        # Refill: after a fresh accounting window a new SYN is challenged.
        time.sleep(WINDOW_MS / 1000 + 0.3)
        r = send(self_path, "syn_p", dst_mac, CLIENT_PORT + 9)
        refill = [x for x in r["replies"]
                  if x["flags"] & 0x12 == 0x12
                  and x["dport"] == CLIENT_PORT + 9]
        assert refill, "challenge budget did not refill after the window"
        assert cookie_matches(refill[0]["seq"], KNOWN_KEY2, CLIENT_PORT + 9) \
            or cookie_matches(refill[0]["seq"], KNOWN_KEY, CLIENT_PORT + 9), \
            f"refill cookie not keyed-valid: {refill[0]}"
        report["phases"]["H_syn_flood_bounded"] = {
            "challengeSent": sent_delta,
            "challengeRejected": rej_delta,
            "budgetPps": CHALLENGE_PPS,
            "refill_challenge": True,
            "state": st, "pass": True}

        # --- N: third-ACK-with-data admit --------------------------------
        # A real client's completing ACK may carry payload (the kernel can
        # merge the first send into it). The admit path must still create
        # the splice; the payload itself is consumed and recovered by the
        # client's own retransmit once the splice is anchored.
        port = CLIENT_PORT + 20
        r = send(self_path, "syn_p", dst_mac, port)
        ch = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12 and x["dport"] == port]
        assert ch and (
            cookie_matches(ch[0]["seq"], KNOWN_KEY2, port)
            or cookie_matches(ch[0]["seq"], KNOWN_KEY, port)), \
            f"N no valid challenge: {r['replies']}"
        ck_n = ch[0]["seq"]
        r = send(self_path, "data_p", dst_mac, (port << 32) | ck_n)
        time.sleep(0.2)
        pe_n = pending_entry(port)
        assert pe_n is not None and pe_n["splice_state"] == 1, \
            f"data-carrying admit ACK not admitted: {pe_n}"
        replay_n = [x for x in r["replies"]
                    if x["flags"] & 0x02 and not x["flags"] & 0x10
                    and x["dport"] == TCP_BACKEND]
        assert replay_n, "no SYN replay for data-carrying admit"
        # The admit packet itself must not reach the backend: the only
        # emitted frame is the forged SYN replay (payload_len == 0).
        leaked = [x for x in r["replies"]
                  if x["dport"] == TCP_BACKEND and x["payload_len"] > 0]
        assert not leaked, f"admit-ACK payload leaked to backend: {leaked}"
        # While the splice is in flight client data is consumed — never
        # forwarded to a SYN-RECV backend with un-anchored seq space.
        r = send(self_path, "data_p", dst_mac, (port << 32) | ck_n)
        consumed = [x for x in r["replies"]
                    if x["dport"] == TCP_BACKEND and x["payload_len"] > 0]
        assert not consumed, \
            f"data forwarded during SPLICE_WAIT: {consumed}"
        send(self_path, "synack_backend", dst_mac, pe_n["snat_port"])
        time.sleep(0.3)
        ce_n = ct_entry(port)
        assert ce_n is not None and ce_n["splice_state"] == 2, \
            f"splice did not anchor after data-admit: {ce_n}"
        # The client's retransmitted payload now flows through the splice.
        r = send(self_path, "data_p", dst_mac, (port << 32) | ck_n)
        fwd_n = [x for x in r["replies"]
                 if x["dport"] == TCP_BACKEND and x["payload_len"] > 0]
        assert fwd_n and fwd_n[0]["tcp_csum_ok"], \
            f"retransmitted admit payload not forwarded: {r['replies']}"
        report["phases"]["N_ack_with_data"] = {
            "admitted": True, "payload_consumed_during_splice": True,
            "payload_forwarded_post_splice": True, "pass": True}

        # --- O: duplicate admit ACK is idempotent ------------------------
        # A retransmitted admitting ACK hits the existing pending record
        # (PENDING_SPLICING -> consume): no second SNAT port, no second
        # SYN replay, no second pending entry.
        port = CLIENT_PORT + 21
        r = send(self_path, "syn_p", dst_mac, port)
        ch = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12 and x["dport"] == port]
        assert ch, f"O no challenge: {r['replies']}"
        ck_o = ch[0]["seq"]
        send(self_path, "ack_cookie_p", dst_mac, (port << 32) | ck_o)
        time.sleep(0.2)
        pe_o = pending_entry(port)
        assert pe_o is not None and pe_o["splice_state"] == 1, \
            f"O admit failed: {pe_o}"
        snat0 = map_entries("XDP_SNAT_REV")
        r = send(self_path, "ack_cookie_p", dst_mac, (port << 32) | ck_o)
        time.sleep(0.2)
        dup_replay = [x for x in r["replies"]
                      if x["flags"] & 0x02 and not x["flags"] & 0x10
                      and x["dport"] == TCP_BACKEND]
        assert not dup_replay, \
            f"duplicate admit ACK produced a second SYN replay: {dup_replay}"
        assert map_entries("XDP_SNAT_REV") == snat0, \
            "duplicate admit ACK allocated a second SNAT port"
        assert pending_entry(port) is not None, "dup admit removed pending"
        send(self_path, "synack_backend", dst_mac, pe_o["snat_port"])
        time.sleep(0.3)
        assert ct_entry(port) is not None, "O splice did not anchor"
        report["phases"]["O_dup_admit_idempotent"] = {
            "snat_ports_stable": True, "no_dup_replay": True, "pass": True}

        # --- P: backend-handshake loss -> TTL-bounded re-admit ------------
        # If the replayed SYN or the backend SYN-ACK is lost, the pending
        # entry sits in SPLICE_WAIT with an absolute deadline. A client
        # packet arriving after the deadline expires the stale entry, the
        # still-valid cookie re-admits, and a fresh SYN is replayed — the
        # splice then completes. Recovery is bounded by pending_ttl_ns,
        # not by an unbounded retransmit loop.
        port = CLIENT_PORT + 22
        old_ttl = pending_cap_ttl(600_000_000)
        try:
            r = send(self_path, "syn_p", dst_mac, port)
            ch = [x for x in r["replies"]
                  if x["flags"] & 0x12 == 0x12 and x["dport"] == port]
            assert ch, f"P no challenge: {r['replies']}"
            ck_p = ch[0]["seq"]
            send(self_path, "ack_cookie_p", dst_mac, (port << 32) | ck_p)
            time.sleep(0.2)
            pe_p = pending_entry(port)
            assert pe_p is not None and pe_p["splice_state"] == 1, \
                f"P admit failed: {pe_p}"
            # Backend SYN-ACK is deliberately never sent (handshake lost).
            time.sleep(1.0)  # past the 600 ms absolute deadline
            r = send(self_path, "data_p", dst_mac, (port << 32) | ck_p)
            time.sleep(0.2)
            pe_p2 = pending_entry(port)
            assert pe_p2 is not None and pe_p2["splice_state"] == 1, \
                f"post-TTL re-admit failed: {pe_p2}"
            replay_p = [x for x in r["replies"]
                        if x["flags"] & 0x02 and not x["flags"] & 0x10
                        and x["dport"] == TCP_BACKEND]
            assert replay_p, "no fresh SYN replay after TTL re-admit"
            send(self_path, "synack_backend", dst_mac, pe_p2["snat_port"])
            time.sleep(0.3)
            ce_p = ct_entry(port)
            assert ce_p is not None and ce_p["splice_state"] == 2, \
                f"P splice did not anchor after re-admit: {ce_p}"
            r = send(self_path, "data_p", dst_mac, (port << 32) | ck_p)
            fwd_p = [x for x in r["replies"]
                     if x["dport"] == TCP_BACKEND and x["payload_len"] > 0]
            assert fwd_p, "P data not forwarded after recovery"
        finally:
            pending_cap_ttl(old_ttl)
        report["phases"]["P_handshake_loss_ttl_recovery"] = {
            "readmitted_after_ttl": True, "splice_completed": True,
            "pass": True}

        # --- Q: key rotation — in-flight proof + established flows -------
        # H left the ring at cur=K2, prev=K1. Mint a challenge under K2,
        # rotate the ring to cur=K3/prev=K2, then prove the K2 cookie still
        # admits via the prev slot. Established splices (main tuple, minted
        # under K1 — now out of the ring) keep forwarding: CT state is
        # key-independent.
        port = CLIENT_PORT + 23
        r = send(self_path, "syn_p", dst_mac, port)
        ch = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12 and x["dport"] == port]
        assert ch and cookie_matches(ch[0]["seq"], KNOWN_KEY2, port), \
            f"Q challenge not minted under K2: {r['replies']}"
        ck_q = ch[0]["seq"]
        set_cookie_key(KNOWN_KEY3, KNOWN_KEY2)
        send(self_path, "ack_cookie_p", dst_mac, (port << 32) | ck_q)
        time.sleep(0.2)
        pe_q = pending_entry(port)
        assert pe_q is not None and pe_q["splice_state"] == 1, \
            f"prev-key cookie not admitted after rotation: {pe_q}"
        r = send(self_path, "data_client", dst_mac, cookie)
        fwd_q = [x for x in r["replies"]
                 if x["dport"] == TCP_BACKEND and x["payload_len"] > 0]
        assert fwd_q, \
            "established flow stopped forwarding after key rotation"
        r = send(self_path, "syn_p", dst_mac, CLIENT_PORT + 24)
        ch = [x for x in r["replies"]
              if x["flags"] & 0x12 == 0x12
              and x["dport"] == CLIENT_PORT + 24]
        assert ch and cookie_matches(ch[0]["seq"], KNOWN_KEY3,
                                     CLIENT_PORT + 24), \
            f"post-rotation challenge not minted under K3: {r['replies']}"
        report["phases"]["Q_key_rotation"] = {
            "prev_key_admit": True, "live_flow_forwarded": True,
            "new_key_mints": True, "pass": True}

        # --- S: duplicate / out-of-order data on the spliced flow --------
        # Splice translation is a stateless seq/ack delta: reordered and
        # duplicated segments must forward with correct translation —
        # reordering is the peer stacks' problem, not the dataplane's.
        r = send(self_path, "data_client", dst_mac, cookie)
        dup = [x for x in r["replies"]
               if x["dport"] == TCP_BACKEND and x["payload_len"] > 0]
        assert dup and dup[0]["tcp_csum_ok"], \
            f"duplicate segment not forwarded: {r['replies']}"
        r = send(self_path, "data_ooo", dst_mac, (20 << 32) | cookie)
        ooo = [x for x in r["replies"]
               if x["dport"] == TCP_BACKEND and x["payload_len"] > 0]
        assert ooo, f"out-of-order segment not forwarded: {r['replies']}"
        assert ooo[0]["seq"] == C_ISN + 21 \
            and ooo[0]["ack"] == B_ISN + 1 and ooo[0]["tcp_csum_ok"], \
            f"ooo translation wrong: {ooo[0]}"
        report["phases"]["S_dup_ooo_data"] = {
            "dup_forwarded": True, "ooo_forwarded": True,
            "ooo_seq": ooo[0]["seq"], "ooo_ack": ooo[0]["ack"],
            "pass": True}

        # --- R: real kernel TCP end-to-end -------------------------------
        # A real client socket + real backend listener in the netns drive
        # the complete path: challenge, cookie proof, SYN replay, splice
        # anchor, bidirectional byte translation, FIN teardown, plus an
        # RST-closed connection. This is the kernel-TCP acceptance the
        # raw-frame phases cannot provide (real ISNs, real retransmit and
        # checksum enforcement on both ends).
        out = sh(["python3", self_path, "--send", "real_tcp", dst_mac, "0"],
                 netns=NS).stdout.strip()
        rt = json.loads(out)
        assert rt.get("reply") == "echo:en14-real", \
            f"real TCP echo failed: {rt}"
        assert rt.get("backend", {}).get("served"), \
            f"backend did not serve the real connection: {rt}"
        ce_rt = ct_entry(rt["client_port"])
        assert ce_rt is not None and ce_rt["splice_state"] == 2, \
            f"real client flow not spliced: {ce_rt}"
        report["phases"]["R_real_kernel_tcp"] = {
            "client_port": rt["client_port"],
            "reply": rt["reply"],
            "backend_peer_snat_port": rt["backend"].get("peer"),
            "rst_conn_port": rt.get("client_port2"),
            "pass": True}

        report["result"] = "PASS"
        report["prod_pin_dir_untouched"] = \
            os.path.exists(PROD_PIN_DIR) == prod_pins_before
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
