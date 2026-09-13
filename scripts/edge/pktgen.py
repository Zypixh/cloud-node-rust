#!/usr/bin/env python3
"""EN-02 packet corpus builder / sender / observer for edge-node XDP tests.

Deterministic, stdlib-only. Every case produces byte-identical frames so a
result is replayable: the same corpus version must produce the same verdicts.

Modes:
  list                          — print case names
  build CASE [--write-pcap F]   — emit frames as hex / pcap corpus file
  send  IFACE CASE [opts]       — transmit frames on an interface (AF_PACKET)
  count IFACE [opts]            — observe frames on an interface (AF_PACKET)

Send path is deliberately dumb: raw frames, caller supplies the topology
(veth pair, physical NIC, remote sender host — see scripts/edge/runner.py).
"""
import argparse
import json
import socket
import struct
import sys
import time

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1

# ---------------------------------------------------------------- builders


def csum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    acc = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def eth(dst: bytes, src: bytes, payload: bytes, etype: int = 0x0800,
        vlans: tuple = ()) -> bytes:
    hdr = dst + src
    for tag in vlans:
        hdr += struct.pack("!HH", 0x8100, tag)
    hdr += struct.pack("!H", etype)
    return hdr + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64,
         ident: int = 0x1234, flags: int = 0, frag_off: int = 0,
         tot_len: int = None, dont_csum: bool = False) -> bytes:
    """flags is the 3-bit flag field (MF=1, DF=2); frag_off in 8-byte units."""
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    total = tot_len if tot_len is not None else 20 + len(payload)
    hdr_wo = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident,
        (flags << 13) | frag_off, ttl, proto, 0, src_b, dst_b,
    )
    chk = 0 if dont_csum else csum16(hdr_wo)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, ident,
        (flags << 13) | frag_off, ttl, proto, chk, src_b, dst_b,
    )
    return hdr + payload


def ipv6(src: str, dst: str, next_hdr: int, payload: bytes, hop: int = 64,
         exts: list = None) -> bytes:
    """exts: list of (next_header_after, ext_body) prepended before payload."""
    body = payload
    nh = next_hdr
    for ext_nh, ext_body in reversed(exts or []):
        # ext_body already contains its own "next header" byte; chain here.
        body = ext_body + body
        nh = ext_nh
    src_b = socket.inet_pton(socket.AF_INET6, src)
    dst_b = socket.inet_pton(socket.AF_INET6, dst)
    return struct.pack("!IHBB16s16s", 6 << 28, len(body), nh, hop,
                       src_b, dst_b) + body


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if ":" in src:
        return socket.inet_pton(socket.AF_INET6, src) + \
            socket.inet_pton(socket.AF_INET6, dst) + \
            struct.pack("!I3xB", length, proto)
    return socket.inet_aton(src) + socket.inet_aton(dst) + \
        struct.pack("!BBH", 0, proto, length)


def tcp(sport: int, dport: int, flags: int, seq: int = 0, ack: int = 0,
        win: int = 65535, options: bytes = b"", payload: bytes = b"",
        src: str = "10.99.0.6", dst: str = "10.99.0.5") -> bytes:
    doff = 5 + (len(options) + 3) // 4
    options = options + b"\x00" * ((doff - 5) * 4 - len(options))
    hdr_wo = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                         doff << 4, flags, win, 0, 0) + options
    pseudo = _pseudo(src, dst, 6, len(hdr_wo) + len(payload))
    chk = csum16(pseudo + hdr_wo + payload)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                      doff << 4, flags, win, chk, 0) + options
    return hdr + payload


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG = 1, 2, 4, 8, 16, 32


def udp(sport: int, dport: int, payload: bytes = b"x",
        src: str = "10.99.0.6", dst: str = "10.99.0.5") -> bytes:
    length = 8 + len(payload)
    hdr_wo = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = _pseudo(src, dst, 17, length)
    chk = csum16(pseudo + hdr_wo + payload)
    return struct.pack("!HHHH", sport, dport, length, chk) + payload


def quic_initial(dcid: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08",
                 scid: bytes = b"\x0a\x0b\x0c\x0d",
                 sport: int = 50000, dport: int = 443,
                 src: str = "10.99.0.6", dst: str = "10.99.0.5") -> bytes:
    """Minimal QUIC long-header Initial shape (unprotected fields only)."""
    first = 0xC0 | 0x00  # long header, Initial type
    version = struct.pack("!I", 0x00000001)
    token = b""
    pn = b"\x00\x00\x00\x01"
    payload = pn + b"\x06" + b"\x00" * 1200  # pad to >=1200 like real Initials
    hdr = bytes([first]) + version + bytes([len(dcid)]) + dcid + \
        bytes([len(scid)]) + scid + bytes([len(token)]) + \
        _varint(len(payload)) + payload
    return udp(sport, dport, hdr, src=src, dst=dst)


def _varint(v: int) -> bytes:
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", 0x4000 | v)
    if v < 1073741824:
        return struct.pack("!I", 0x8000 | v)
    return struct.pack("!Q", 0xC000000000000000 | v)


def ipv6_ext_dest_opts(payload_next: int) -> bytes:
    # Dest-opts header: next_hdr byte + len + 6 bytes padding options.
    return struct.pack("!BB", payload_next, 0) + b"\x01\x04\x00\x00\x00\x00"


def ipv6_frag_ext(payload_next: int, ident: int = 0xABCD,
                  more: bool = False, off: int = 0) -> bytes:
    frag_field = (off << 3) | (1 if more else 0)
    return struct.pack("!BBHI", payload_next, 0, frag_field, ident)


# ------------------------------------------------------------------- cases
# Each case returns list of frames (bytes). Deterministic: same name → same
# bytes. Frame MACs default to a fixed pair; runner topologies that need real
# MACs override via --src-mac/--dst-mac (e.g. veth learnt addresses).

SRC_MAC = bytes.fromhex("02000000aa01")
DST_MAC = bytes.fromhex("02000000bb01")

C_IP4_SRC, C_IP4_DST = "10.99.0.6", "10.99.0.5"
C_IP6_SRC, C_IP6_DST = "fd00::6", "fd00::5"


def _wrap_v4(payload: bytes) -> list:
    return [eth(DST_MAC, SRC_MAC, payload, 0x0800)]


def _wrap_v6(payload: bytes) -> list:
    return [eth(DST_MAC, SRC_MAC, payload, 0x86DD)]


def _v4(proto: int, payload: bytes, **kw) -> bytes:
    return ipv4(C_IP4_SRC, C_IP4_DST, proto, payload, **kw)


def _v6(nh: int, payload: bytes, **kw) -> bytes:
    return ipv6(C_IP6_SRC, C_IP6_DST, nh, payload, **kw)


def case_tcp_syn() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN, seq=1000)))


def case_tcp_syn_flood() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN, seq=1000)))


def case_tcp_ack_no_flow() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_ACK, seq=1000, ack=2000)))


def case_tcp_rst_no_flow() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_RST, seq=1)))


def case_tcp_fin_no_flow() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_FIN | TCP_ACK, seq=1, ack=1)))


def case_tcp_null_flags() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, 0)))


def case_tcp_xmas() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_FIN | TCP_PSH | TCP_URG)))


def case_tcp_syn_fin() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN | TCP_FIN)))


def case_tcp_syn_rst() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN | TCP_RST)))


def case_udp() -> list:
    return _wrap_v4(_v4(17, udp(41000, 443, b"edge-udp-probe")))


def case_udp_flood() -> list:
    return _wrap_v4(_v4(17, udp(41000, 443, b"edge-udp-probe")))


def case_quic_initial() -> list:
    return _wrap_v4(_v4(17, quic_initial()))


def case_quic_short_header() -> list:
    # First bit 0 → short header; DCID bytes follow immediately.
    return _wrap_v4(_v4(17, udp(41000, 443, b"\x40" + b"\x01" * 8 + b"\x00" * 20)))


def case_frag_first() -> list:
    # MF set, offset 0, full UDP header in first fragment.
    return _wrap_v4(_v4(17, udp(41000, 443, b"frag-data"), flags=1, ident=0x777))


def case_frag_nonfirst() -> list:
    # offset != 0: payload-only fragment, no L4 header visible.
    return _wrap_v4(_v4(17, b"\xde\xad\xbe\xef" * 4, flags=0, frag_off=2, ident=0x777))


def case_frag_atomic() -> list:
    # RFC 6946 atomic: MF=0 but offset=0 fragment that is the whole datagram —
    # here modeled as a lone fragment with nonzero ident and MF=0.
    return _wrap_v4(_v4(17, udp(41000, 443, b"atomic"), flags=0, frag_off=0,
                        ident=0x888))


def case_ipv4_truncated() -> list:
    # Header claims more than the frame carries.
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN), tot_len=60)[:40])


def case_ipv4_bad_csum() -> list:
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN), dont_csum=True))


def case_vlan_tcp_syn() -> list:
    return [eth(DST_MAC, SRC_MAC, _v4(6, tcp(41000, 443, TCP_SYN)),
                0x0800, vlans=(100,))]


def case_qinq_tcp_syn() -> list:
    return [eth(DST_MAC, SRC_MAC, _v4(6, tcp(41000, 443, TCP_SYN)),
                0x0800, vlans=(10, 100))]


def case_ipv6_tcp_syn() -> list:
    return _wrap_v6(_v6(6, tcp(41000, 443, TCP_SYN,
                              src=C_IP6_SRC, dst=C_IP6_DST)))


def case_ipv6_dest_opts() -> list:
    ext = ipv6_ext_dest_opts(6)
    return _wrap_v6(_v6(60, ext + tcp(41000, 443, TCP_SYN,
                                      src=C_IP6_SRC, dst=C_IP6_DST)))


def case_ipv6_fragment() -> list:
    ext = ipv6_frag_ext(6, more=True)
    return _wrap_v6(_v6(44, ext + tcp(41000, 443, TCP_SYN,
                                      src=C_IP6_SRC, dst=C_IP6_DST)))


def case_icmp() -> list:
    # Echo request, checksum correct.
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"edge-icmp"
    body = body[:2] + struct.pack("!H", csum16(body)) + body[4:]
    return _wrap_v4(_v4(1, body))


def case_icmp_ptb() -> list:
    # Fragmentation-needed PTB towards the node: type 3 code 4.
    body = struct.pack("!BBH I", 3, 4, 0, 1400) + _v4(17, b"\x00" * 8)
    body = body[:2] + struct.pack("!H", csum16(body)) + body[4:]
    return _wrap_v4(_v4(1, body))


def case_tcp_syn_ecn() -> list:
    # SYN|ECE|CWR — legal ECN negotiation, must not be treated as malformed.
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN | 0x40 | 0x80)))


def case_tcp_syn_options() -> list:
    # SYN carrying MSS + TFO-cookie-shaped options (doff=8).
    opts = b"\x02\x04\x05\xb4" + b"\x22\x08" + b"\x01" * 6
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN, options=opts)))


def case_tcp_doff_short() -> list:
    # doff=4 < 5: header length below the TCP minimum — deterministic-illegal.
    seg = struct.pack("!HHIIBBHHH", 41000, 443, 0, 0, 4 << 4, TCP_SYN,
                      65535, 0, 0)
    return _wrap_v4(_v4(6, seg))


def case_udp_len_short() -> list:
    # UDP length field below the 8-byte header — deterministic-illegal.
    hdr = struct.pack("!HHHH", 41000, 443, 4, 0)
    return _wrap_v4(_v4(17, hdr))


def case_udp_len_over() -> list:
    # UDP length field beyond the datagram — deterministic-illegal.
    hdr = struct.pack("!HHHH", 41000, 443, 4000, 0)
    return _wrap_v4(_v4(17, hdr + b"x" * 4))


def case_vlan3_tcp_syn() -> list:
    # Three stacked VLAN tags exceed the bounded two-tag walk: legal frame,
    # classified UNSUPPORTED and passed, never dropped.
    return [eth(DST_MAC, SRC_MAC, _v4(6, tcp(41000, 443, TCP_SYN)),
                0x0800, vlans=(10, 100, 200))]


def case_icmpv6_ns() -> list:
    # Neighbor Solicitation — mandatory control traffic.
    body = struct.pack("!BBH", 135, 0, 0) + b"\x00" * 4 + \
        socket.inet_pton(socket.AF_INET6, C_IP6_DST)
    body = body[:2] + struct.pack("!H", csum16(
        _pseudo(C_IP6_SRC, C_IP6_DST, 58, len(body)) + body)) + body[4:]
    return _wrap_v6(_v6(58, body))


def case_icmpv6_ptb() -> list:
    # Packet Too Big — the PMTU contract requires it reaches the stack.
    body = struct.pack("!BBHI", 2, 0, 0, 1400) + b"\x00" * 48
    body = body[:2] + struct.pack("!H", csum16(
        _pseudo(C_IP6_SRC, C_IP6_DST, 58, len(body)) + body)) + body[4:]
    return _wrap_v6(_v6(58, body))


def case_ipv6_frag_nonfirst() -> list:
    ext = ipv6_frag_ext(6, off=185)
    return _wrap_v6(_v6(44, ext + b"\xde\xad\xbe\xef" * 4))


def case_ipv6_ext_chain_deep() -> list:
    # 9 chained destination-options headers exceed the 8-iteration bound:
    # legal per RFC 8200, classified UNSUPPORTED and passed.
    chain = b""
    nh = 60
    for _ in range(9):
        chain = struct.pack("!BB", 60, 0) + b"\x00" * 6 + chain
    return _wrap_v6(_v6(60, chain + b"\x00" * 8))


def case_gre() -> list:
    # GRE — a protocol this dataplane does not terminate: UNSUPPORTED, pass.
    return _wrap_v4(_v4(47, b"\x00" * 20))


def case_tcp_legit_synack_flow() -> list:
    """Minimal 3-packet exchange shape: SYN, SYN-ACK-looking, ACK+data.
    Sent as frames it is not a real handshake — real handshakes run through
    the interactive topology in runner.py; this case exists for corpus/pcap
    completeness."""
    return _wrap_v4(_v4(6, tcp(41000, 443, TCP_SYN, seq=1000)))


CASES = {
    # T01 packet classification corpus
    "t01.tcp_syn": case_tcp_syn,
    "t01.tcp_null_flags": case_tcp_null_flags,
    "t01.tcp_xmas": case_tcp_xmas,
    "t01.tcp_syn_fin": case_tcp_syn_fin,
    "t01.tcp_syn_rst": case_tcp_syn_rst,
    "t01.frag_first": case_frag_first,
    "t01.frag_nonfirst": case_frag_nonfirst,
    "t01.frag_atomic": case_frag_atomic,
    "t01.ipv4_truncated": case_ipv4_truncated,
    "t01.ipv4_bad_csum": case_ipv4_bad_csum,
    "t01.vlan_tcp_syn": case_vlan_tcp_syn,
    "t01.qinq_tcp_syn": case_qinq_tcp_syn,
    "t01.ipv6_tcp_syn": case_ipv6_tcp_syn,
    "t01.ipv6_dest_opts": case_ipv6_dest_opts,
    "t01.ipv6_fragment": case_ipv6_fragment,
    "t01.icmp": case_icmp,
    "t01.icmp_ptb": case_icmp_ptb,
    "t01.tcp_syn_ecn": case_tcp_syn_ecn,
    "t01.tcp_syn_options": case_tcp_syn_options,
    "t01.tcp_doff_short": case_tcp_doff_short,
    "t01.udp_len_short": case_udp_len_short,
    "t01.udp_len_over": case_udp_len_over,
    "t01.vlan3_tcp_syn": case_vlan3_tcp_syn,
    "t01.icmpv6_ns": case_icmpv6_ns,
    "t01.icmpv6_ptb": case_icmpv6_ptb,
    "t01.ipv6_frag_nonfirst": case_ipv6_frag_nonfirst,
    "t01.ipv6_ext_chain_deep": case_ipv6_ext_chain_deep,
    "t01.gre": case_gre,
    # T02 admission / state probes
    "t02.syn": case_tcp_syn,
    "t02.syn_flood": case_tcp_syn_flood,
    "t02.ack_no_flow": case_tcp_ack_no_flow,
    "t02.rst_no_flow": case_tcp_rst_no_flow,
    "t02.fin_no_flow": case_tcp_fin_no_flow,
    # T03 UDP/QUIC probes
    "t03.udp": case_udp,
    "t03.udp_flood": case_udp_flood,
    "t03.quic_initial": case_quic_initial,
    "t03.quic_short_header": case_quic_short_header,
    # T04 capacity probes reuse the flood cases with --pps/--count
}

# ------------------------------------------------------------------ pcap


def write_pcap(path: str, frames: list) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 65535,
                            LINKTYPE_ETHERNET))
        base = 1_700_000_000
        for i, frame in enumerate(frames):
            f.write(struct.pack("<IIII", base, i * 1000, len(frame),
                                len(frame)))
            f.write(frame)


# -------------------------------------------------------------- send/count


def send_frames(iface: str, frames: list, count: int, pps: float,
                src_mac: str, dst_mac: str) -> dict:
    if src_mac or dst_mac:
        sm = bytes.fromhex(src_mac.replace(":", "")) if src_mac else None
        dm = bytes.fromhex(dst_mac.replace(":", "")) if dst_mac else None
        frames = [(dm or f[:6]) + (sm or f[6:12]) + f[12:] for f in frames]
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((iface, 0))
    total = len(frames) * count
    sent = 0
    start = time.monotonic()
    interval = 1.0 / pps if pps > 0 else 0.0
    next_tick = start
    for _ in range(count):
        for frame in frames:
            if interval:
                next_tick += interval
                delay = next_tick - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            sent += sock.send(frame)
    elapsed = time.monotonic() - start
    sock.close()
    return {"sent_packets": count * len(frames), "sent_bytes": sent,
            "elapsed_s": round(elapsed, 3),
            "achieved_pps": round(count * len(frames) / elapsed, 1)
            if elapsed else 0}


def count_frames(iface: str, seconds: float, proto: str = "any",
                 dst_port: int = 0) -> dict:
    """Observe frames on iface for `seconds`; report total + per-proto counts.
    Best-effort dual-end observation point — the runner compares this with
    dataplane counters to distinguish delivered vs dropped."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((iface, 0))
    sock.settimeout(0.1)
    end = time.monotonic() + seconds
    seen = {"total": 0, "ipv4": 0, "ipv6": 0, "tcp": 0, "udp": 0,
            "icmp": 0, "other": 0, "match": 0}
    while time.monotonic() < end:
        try:
            frame, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        seen["total"] += 1
        etype = struct.unpack("!H", frame[12:14])[0]
        if etype == 0x8100 and len(frame) > 16:
            etype = struct.unpack("!H", frame[16:18])[0]
        ipproto = None
        l4 = None
        if etype == 0x0800 and len(frame) >= 34:
            seen["ipv4"] += 1
            ipproto = frame[23]
            l4 = 34
        elif etype == 0x86DD and len(frame) >= 54:
            seen["ipv6"] += 1
            ipproto = frame[20]
            l4 = 54
        if ipproto == 6:
            seen["tcp"] += 1
        elif ipproto == 17:
            seen["udp"] += 1
        elif ipproto == 1 or ipproto == 58:
            seen["icmp"] += 1
        elif ipproto is not None:
            seen["other"] += 1
        ok = proto in ("any", "") or (
            (proto == "tcp" and ipproto == 6)
            or (proto == "udp" and ipproto == 17)
            or (proto == "icmp" and ipproto in (1, 58))
        )
        if ok and dst_port and l4 is not None and len(frame) >= l4 + 4:
            dport = struct.unpack("!H", frame[l4 + 2:l4 + 4])[0]
            ok = dport == dst_port
        if ok:
            seen["match"] += 1
    sock.close()
    return seen


def main() -> int:
    ap = argparse.ArgumentParser(description="edge-node packet corpus tool")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    b = sub.add_parser("build")
    b.add_argument("case", choices=sorted(CASES))
    b.add_argument("--write-pcap")
    s = sub.add_parser("send")
    s.add_argument("iface")
    s.add_argument("case", choices=sorted(CASES))
    s.add_argument("--count", type=int, default=1)
    s.add_argument("--pps", type=float, default=0, help="0 = unthrottled")
    s.add_argument("--src-mac", default="")
    s.add_argument("--dst-mac", default="")
    c = sub.add_parser("count")
    c.add_argument("iface")
    c.add_argument("--seconds", type=float, default=3)
    c.add_argument("--proto", default="any")
    c.add_argument("--dst-port", type=int, default=0)
    args = ap.parse_args()

    if args.cmd == "list":
        for name in sorted(CASES):
            print(name)
        return 0
    if args.cmd == "build":
        frames = CASES[args.case]()
        if args.write_pcap:
            write_pcap(args.write_pcap, frames)
            print(json.dumps({"case": args.case, "frames": len(frames),
                              "pcap": args.write_pcap}))
        else:
            for f in frames:
                print(f.hex())
        return 0
    if args.cmd == "send":
        frames = CASES[args.case]()
        result = send_frames(args.iface, frames, args.count, args.pps,
                             args.src_mac, args.dst_mac)
        result["case"] = args.case
        print(json.dumps(result))
        return 0
    if args.cmd == "count":
        print(json.dumps(count_frames(args.iface, args.seconds,
                                      args.proto, args.dst_port)))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
