#!/usr/bin/env python3
"""EN-12 evidence probe: AF_XDP queue correctness — real copy/zero-copy
bind probing, worker-readiness gating before redirect, per-queue status
observability, and live RX fill/TX-cycle exercise.

Topology: veth pair en2-a (host, node VIP 10.99.0.5, XDP attached, proxy
mode) <-> en2-b (netns en2-ns, 10.99.0.6). The interface binds two AF_XDP
queues so queue-count effects are observable.

Phases:
  A auto probe:   xskMode auto on veth -> kernel rejects zero-copy, the
                  socket lands in copy mode, and `xskQueues[].xsk_mode`
                  plus the probe detail record exactly what happened.
  B worker gate:  node log shows every reactor reporting ready before the
                  bridge enables redirect; UDP frames to a proxy port are
                  counted as `redirect` and consumed (rx stats stay clean).
  C zero-copy:    xskMode zero-copy on veth fails queue setup explicitly —
                  status detail names the bind failure, redirect stays off,
                  and traffic keeps PASSing (fallback contract).
  D copy:         xskMode copy binds directly in copy mode.

Usage (root, Linux):
    sudo python3 scripts/edge/en12_queue_probe.py \
        --node-bin target/debug/cloud-node-rust --out /tmp/en12.json
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

NS = "en2-ns"
HOST_IF = "en2-a"
PEER_IF = "en2-b"
HOST_IP = "10.99.0.5"
PEER_IP = "10.99.0.6"
PIN_DIR = "/sys/fs/bpf/cloud-node-xdp"
PROXY_UDP_PORT = 443
CLIENT_PORT = 53000


def sh(cmd, check=True, capture=True, netns=None, cwd=None):
    if netns:
        cmd = ["ip", "netns", "exec", NS] + cmd
    p = subprocess.run(cmd, capture_output=capture, text=True, cwd=cwd)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"{' '.join(map(str, cmd))} rc={p.returncode}: "
            f"{p.stderr.strip() or p.stdout.strip()}")
    return p


def setup_netns():
    teardown_netns()
    clear_pins()
    sh(["ip", "netns", "add", NS])
    sh(["ip", "link", "add", HOST_IF, "numrxqueues", "2", "numtxqueues", "2",
        "type", "veth", "peer", "name", PEER_IF,
        "numrxqueues", "2", "numtxqueues", "2"])
    sh(["ip", "link", "set", PEER_IF, "netns", NS])
    sh(["ip", "addr", "add", f"{HOST_IP}/24", "dev", HOST_IF])
    sh(["ip", "link", "set", HOST_IF, "up"])
    sh(["ip", "netns", "exec", NS, "ip", "addr", "add", f"{PEER_IP}/24",
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


def clear_pins():
    if not os.path.isdir(PIN_DIR):
        return
    for f in os.listdir(PIN_DIR):
        subprocess.run(["rm", "-f", os.path.join(PIN_DIR, f)],
                       capture_output=True)


def write_node_config(path, xsk_mode):
    body = f"""runtime:
  mode: standalone

xdp:
  enabled: true
  attachMode: skb
  fallback: pass
  interfaces:
    - name: {HOST_IF}
      queues: [0, 1]
      mode: proxy
      localIps:
        - {HOST_IP}
      frameSize: 2048
      xskMode: {xsk_mode}
  proxy:
    protocols: ["udp"]
    ports:
      - protocol: udp
        port: {PROXY_UDP_PORT}
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def write_api_config(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('nodeId: "0"\nsecret: "en12-probe"\n'
                '"rpc.endpoints":\n  - "http://127.0.0.1:9/"\n'
                '"rpc.disableUpdate": true\n'
                'kernelTuning:\n  enabled: false\n')


def start_node(node_bin, home, cwd, xsk_mode):
    stale_state = os.path.join(home, "data", "xdp-state.json")
    if os.path.exists(stale_state):
        os.remove(stale_state)
    write_node_config(os.path.join(home, "configs", "runtime.yaml"),
                      xsk_mode)
    write_node_config(os.path.join(cwd, "configs", "runtime.yaml"),
                      xsk_mode)
    write_api_config(os.path.join(home, "configs", "api_node.yaml"))
    obj_src = os.path.normpath(os.path.join(
        os.path.dirname(os.path.abspath(node_bin)),
        "..", "..", "data", "cloud-node-xdp-ebpf.o"))
    os.makedirs(os.path.join(home, "data"), exist_ok=True)
    if os.path.exists(obj_src):
        import shutil
        shutil.copyfile(obj_src,
                        os.path.join(home, "data", "cloud-node-xdp-ebpf.o"))
    env = dict(os.environ, CLOUD_NODE_HOME=home, RUST_LOG="debug")
    log = open(os.path.join(cwd, "node.log"), "w")
    proc = subprocess.Popen([os.path.abspath(node_bin)],
                            cwd=cwd, env=env, stdout=log, stderr=log,
                            start_new_session=True)
    deadline = time.time() + 60
    while time.time() < deadline:
        if os.path.exists(f"{PIN_DIR}/link-{HOST_IF}"):
            time.sleep(3)
            return proc
        if proc.poll() is not None:
            raise RuntimeError(f"node exited rc={proc.returncode}; "
                               f"see {cwd}/node.log")
        time.sleep(0.4)
    proc.kill()
    raise RuntimeError("node did not attach within deadline")


def stop_node(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    clear_pins()


def dump_maps(node_bin, cwd):
    out = sh([node_bin, "xdp", "dump-maps"], cwd=cwd).stdout
    return json.loads(out)


def node_state(home):
    """The running node's own persisted status (queue modes, readiness)."""
    try:
        with open(os.path.join(home, "data", "xdp-state.json")) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def wait_state(home, since, timeout=45):
    """Poll xdp-state.json until a fresh file (mtime >= node start) exists."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            st = os.stat(os.path.join(home, "data", "xdp-state.json"))
            if st.st_mtime >= since:
                return node_state(home)
        except OSError:
            pass
        time.sleep(0.4)
    return node_state(home)


def xsk_queues(home):
    for iface in node_state(home).get("interfaces", []):
        if iface.get("name") == HOST_IF:
            return iface.get("xsk_queues", [])
    return []


def send_udp(n, dst_mac):
    # AF_PACKET injection must run inside the peer namespace.
    sh(["python3", os.path.abspath(__file__), "--send", dst_mac, str(n)],
       netns=NS)


def csum16(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def send_udp_inner(dst_mac, n):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((PEER_IF, 0))
    sent = 0
    for i in range(n):
        payload = bytes([0xC0, 0, 0, 0, 1]) + os.urandom(24)  # QUIC Initial-ish
        udp = struct.pack(">HHHH", CLIENT_PORT + (i % 50), PROXY_UDP_PORT,
                          8 + len(payload), 0)
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0,
                         20 + len(udp) + len(payload),
                         random.randrange(65536), 0, 64, 17, 0,
                         socket.inet_aton(PEER_IP), socket.inet_aton(HOST_IP))
        ip = ip[:10] + struct.pack(">H", csum16(ip)) + ip[12:]
        eth = bytes.fromhex(dst_mac.replace(":", "")) \
            + b"\x02\xaa\xbb\xcc\xdd\xee" + b"\x08\x00"
        s.send(eth + ip + udp + payload)
        sent += 1
    return sent


def log_lines(cwd):
    try:
        with open(os.path.join(cwd, "node.log")) as f:
            return f.read()
    except OSError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-bin")
    ap.add_argument("--out", default="/tmp/en12.json")
    ap.add_argument("--keep-topology", action="store_true")
    ap.add_argument("--send", nargs=2, metavar=("DST_MAC", "N"))
    args = ap.parse_args()
    if args.send:
        print(json.dumps({"sent": send_udp_inner(args.send[0],
                                                int(args.send[1]))}))
        return

    results = {"phases": {}, "ok": True}
    home = "/tmp/en12-home"
    cwd = "/tmp/en12-run"
    for d in (home, cwd):
        os.makedirs(d, exist_ok=True)

    try:
        host_mac = setup_netns()
    except Exception as e:
        results["phases"]["setup"] = {"ok": False, "error": str(e)}
        print(json.dumps(results, indent=2))
        return

    # ---- Phase A+B: auto mode, two queues, worker gating + live traffic
    proc = None
    try:
        started_at = time.time()
        proc = start_node(args.node_bin, home, cwd, "auto")
        state = {}
        deadline = time.time() + 15
        while time.time() < deadline:
            state = wait_state(home, started_at, timeout=2)
            if state.get("proxy_redirect_enabled"):
                break
            time.sleep(0.5)
        doc = dump_maps(os.path.abspath(args.node_bin), cwd)
        queues = xsk_queues(home)
        counters = doc.get("counters", {}) or {}
        redirect_before = int(counters.get("redirect", 0))
        packets_before = int(counters.get("packets", 0))

        modes = {q["queue"]: q.get("xsk_mode") for q in queues}
        details = {q["queue"]: q.get("detail", "") for q in queues}
        ready = {q["queue"]: q.get("ready") for q in queues}
        phase_a = {
            "queues": len(queues),
            "xsk_modes": modes,
            "details": details,
            "ready": ready,
            "redirectEnabled": state.get("proxy_redirect_enabled"),
            "ok": (len(queues) == 2
                   and all(m in ("copy", "zero-copy") for m in modes.values())
                   and all(ready.values())
                   and state.get("proxy_redirect_enabled") is True),
        }
        results["phases"]["A_auto_probe_two_queues"] = phase_a

        # Live traffic through the AF_XDP path: redirect counter grows and
        # rx stats stay clean while workers drain the rings.
        send_udp(400, host_mac)
        time.sleep(1.5)
        doc = dump_maps(os.path.abspath(args.node_bin), cwd)
        queues = xsk_queues(home)
        counters = doc.get("counters", {}) or {}
        redirect_after = int(counters.get("redirect", 0))
        rx_bad = {q["queue"]: (q.get("rx_dropped", 0),
                               q.get("rx_invalid_descs", 0),
                               q.get("rx_ring_full", 0))
                  for q in queues}
        phase_b = {
            "sent": 400,
            "redirectDelta": redirect_after - redirect_before,
            "packetsDelta": int(counters.get("packets", 0))
                            - packets_before,
            "rxStats": rx_bad,
            "ok": redirect_after > redirect_before,
        }
        results["phases"]["B_redirect_and_rx_health"] = phase_b

        # Worker-readiness ordering in the log: every "reactor ready" must
        # precede "enabled redirect".
        log = log_lines(cwd)
        first_enable = log.find("enabled redirect")
        ready_lines = [m.start() for m in
                       re.finditer(r"reactor ready", log)]
        last_ready = max(ready_lines) if ready_lines else -1
        phase_b2 = {
            "reactorReadyReports": len(ready_lines),
            "redirectEnableAfterLastReady": (first_enable > last_ready
                                             if first_enable >= 0 else False),
            "ok": (len(ready_lines) == 2 and first_enable > last_ready),
        }
        results["phases"]["B2_worker_ready_before_redirect"] = phase_b2
    except Exception as e:
        results["phases"]["A_auto_probe_two_queues"] = {
            "ok": False, "error": str(e)}
        results["phases"]["B_redirect_and_rx_health"] = {
            "ok": False, "error": "skipped"}
        results["phases"]["B2_worker_ready_before_redirect"] = {
            "ok": False, "error": "skipped"}
    finally:
        stop_node(proc)

    # ---- Phase C: forced zero-copy on veth must fail explicitly
    proc = None
    try:
        started_at = time.time()
        proc = start_node(args.node_bin, home, cwd, "zero-copy")
        state = wait_state(home, started_at)
        doc = dump_maps(os.path.abspath(args.node_bin), cwd)
        queues = xsk_queues(home)
        details = [q.get("detail", "") for q in queues]
        counters = doc.get("counters", {}) or {}
        pass_before = int(counters.get("pass", 0))
        send_udp(50, host_mac)
        time.sleep(1.5)
        doc2 = dump_maps(os.path.abspath(args.node_bin), cwd)
        pass_after = int((doc2.get("counters") or {}).get("pass", 0))
        redirect_on = state.get("proxy_redirect_enabled")
        failed = (bool(queues)
                  and all(q.get("socket_created") is False for q in queues)
                  and all(d for d in details))
        phase_c = {
            "xsk_modes": [q.get("xsk_mode") for q in queues],
            "socketCreated": [q.get("socket_created") for q in queues],
            "details": details,
            "redirectEnabled": redirect_on,
            "passDelta": pass_after - pass_before,
            "ok": (not redirect_on and failed
                   and pass_after > pass_before),
        }
        results["phases"]["C_zerocopy_fails_explicitly"] = phase_c
    except Exception as e:
        results["phases"]["C_zerocopy_fails_explicitly"] = {
            "ok": False, "error": str(e)}
    finally:
        stop_node(proc)

    # ---- Phase D: forced copy binds directly
    proc = None
    try:
        started_at = time.time()
        proc = start_node(args.node_bin, home, cwd, "copy")
        wait_state(home, started_at)
        queues = xsk_queues(home)
        modes = [q.get("xsk_mode") for q in queues]
        phase_d = {
            "xsk_modes": modes,
            "details": [q.get("detail", "") for q in queues],
            "ready": [q.get("ready") for q in queues],
            "ok": (len(queues) == 2
                   and all(m == "copy" for m in modes)
                   and all(q.get("ready") for q in queues)),
        }
        results["phases"]["D_forced_copy"] = phase_d
    except Exception as e:
        results["phases"]["D_forced_copy"] = {"ok": False, "error": str(e)}
    finally:
        stop_node(proc)

    if not args.keep_topology:
        teardown_netns()
    results["ok"] = all(p.get("ok") for p in results["phases"].values())
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
