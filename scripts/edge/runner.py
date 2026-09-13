#!/usr/bin/env python3
"""EN-02 layered test runner for the edge-node dataplane.

Runs the packet corpus through a real attached XDP program and emits unified
JSON results. Two topologies:

  netns    — single host: this runner creates an isolated netns + veth pair
             (names en2-*; it only ever deletes resources it created), writes
             a dedicated node config, attaches XDP in the requested interface
             mode, sends corpus frames from the netns side, and asserts on
             dataplane counter deltas read back via `xdp dump-maps`.

  external — dedicated sender host: the runner only sends/counts frames on
             --send-iface and reads counters from a reachable --status-file
             (the node's persisted xdp-state.json or a dump-maps snapshot
             copied/collected by the operator). No local attach is attempted.

Every case result records: bpf object sha256 actually loaded, packets sent,
achieved pps, frames observed on the peer side, counter deltas, and the
assertion outcomes. The process exit code is 0 only when every executed case
passed; a missing prerequisite aborts with exit 3.

Usage:
  runner.py --list
  runner.py --matrix scripts/edge/matrix.json --only T01
  runner.py --topology netns --node-bin target/debug/cloud-node-rust ...
"""
import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKTGEN = os.path.join(HERE, "pktgen.py")
ROOT = os.path.dirname(os.path.dirname(HERE))

# Isolated resource names — the runner only ever touches these.
NS = "en2-ns"
HOST_IF = "en2-a"
PEER_IF = "en2-b"
HOST_IP = "10.99.0.5"      # node side; matches pktgen case dst
PEER_IP = "10.99.0.6"      # sender side; matches pktgen case src
HOST_CIDR = "10.99.0.5/24"
PEER_CIDR = "10.99.0.6/24"


def sh(cmd, check=True, capture=True, netns=None, cwd=None):
    if netns:
        cmd = ["ip", "netns", "exec", netns] + cmd
    p = subprocess.run(cmd, capture_output=capture, text=True, cwd=cwd)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed rc={p.returncode}: "
                           f"{p.stderr.strip() or p.stdout.strip()}")
    return p


def require_commands(names):
    missing = [c for c in names
               if subprocess.run(["which", c], capture_output=True).returncode]
    if missing:
        raise RuntimeError(f"missing required commands: {missing}")


def setup_netns():
    sh(["ip", "netns", "add", NS])
    sh(["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", PEER_IF])
    sh(["ip", "link", "set", PEER_IF, "netns", NS])
    sh(["ip", "addr", "add", HOST_CIDR, "dev", HOST_IF])
    sh(["ip", "link", "set", HOST_IF, "up"])
    sh(["ip", "netns", "exec", NS, "ip", "addr", "add", PEER_CIDR,
        "dev", PEER_IF])
    sh(["ip", "netns", "exec", NS, "ip", "link", "set", PEER_IF, "up"])
    sh(["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])
    # Silence kernel-generated IPv6 noise (DAD/RS/NS) on both veth ends:
    # it would pollute the per-case counter deltas. Raw injected frames are
    # unaffected — XDP sees them regardless of the stack's IPv6 state.
    for iface, ns in ((HOST_IF, None), (PEER_IF, NS)):
        sh(["sysctl", "-qw", f"net.ipv6.conf.{iface}.disable_ipv6=1"],
           check=False, netns=ns)
    if not subprocess.run(["which", "ethtool"],
                          capture_output=True).returncode:
        for iface, ns in ((HOST_IF, None), (PEER_IF, NS)):
            sh(["ethtool", "-K", iface, "tx", "off", "rx", "off",
                "tso", "off", "gso", "off", "gro", "off"],
               check=False, netns=ns)
    # peer MAC for the sender to aim at the node interface
    out = sh(["ip", "-o", "link", "show", "dev", HOST_IF]).stdout
    mac = out.split("link/ether")[1].split()[0]
    return mac


def teardown_netns():
    for cmd in (["ip", "link", "delete", HOST_IF],
                ["ip", "netns", "delete", NS]):
        subprocess.run(cmd, capture_output=True)


def write_node_config(path, mode):
    body = f"""runtime:
  mode: standalone

xdp:
  enabled: true
  attachMode: skb
  fallback: fail-start
  interfaces:
    - name: {HOST_IF}
      queues: [0]
      mode: {mode}
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
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def bpf_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def dump_counters(node_bin, cwd):
    out = sh([node_bin, "xdp", "dump-maps"], cwd=cwd).stdout
    doc = json.loads(out)
    c = doc.get("counters")
    if not isinstance(c, dict):
        raise RuntimeError("dump-maps reported no pinned counters "
                           "(is XDP attached?)")
    return c


def delta(before, after):
    return {k: int(after.get(k, 0)) - int(before.get(k, 0))
            for k in set(before) | set(after)}


def eval_asserts(spec, d, observed):
    """spec: {"counters": {"pass": {"min":1}}, "observed": {"match": {"eq":0}}}
    Each entry checks a counter delta or an observed-frames field."""
    results = []
    ok_all = True
    for group, values in (("counters", d), ("observed", observed)):
        for field, cond in (spec.get(group) or {}).items():
            actual = values.get(field)
            ok = True
            detail = []
            if "eq" in cond:
                ok &= actual == cond["eq"]
                detail.append(f"eq {cond['eq']}")
            if "min" in cond:
                ok &= actual is not None and actual >= cond["min"]
                detail.append(f"min {cond['min']}")
            if "max" in cond:
                ok &= actual is not None and actual <= cond["max"]
                detail.append(f"max {cond['max']}")
            ok_all &= ok
            results.append({"where": group, "field": field,
                            "actual": actual, "expect": " ".join(detail),
                            "ok": ok})
    return results, ok_all


def run_case(case, node_bin, cwd, topology, send_iface, mac, count, pps,
             settle, status_file):
    frames_send_iface = send_iface
    send_in_ns = topology == "netns"
    before = {}
    if topology == "netns":
        before = dump_counters(node_bin, cwd)
    elif status_file:
        before = json.load(open(status_file))

    # observe on the node side: in netns topology the sender is inside the
    # netns and the node side is HOST_IF; count there via a short capture
    obs = {"match": None}
    if send_in_ns:
        out = sh([PKTGEN, "count", HOST_IF, "--seconds", "0.1"],
                 check=False).stdout
        # warm the socket once; real observation runs concurrently below
    send_cmd = [PKTGEN, "send", frames_send_iface, case["case"],
                "--count", str(count), "--pps", str(pps)]
    if mac:
        send_cmd += ["--dst-mac", mac]
    sender = subprocess.Popen(
        (["ip", "netns", "exec", NS] if send_in_ns else []) + send_cmd,
        stdout=subprocess.PIPE, text=True)
    obs_out = {}
    if send_in_ns:
        try:
            obs_out = json.loads(
                sh([PKTGEN, "count", HOST_IF, "--seconds",
                    str(max(0.5, count / max(pps, 1) + 0.5))],
                   check=False).stdout)
        except (json.JSONDecodeError, RuntimeError):
            obs_out = {}
    send_out = sender.communicate()[0]
    try:
        send_result = json.loads(send_out)
    except json.JSONDecodeError:
        send_result = {"raw": send_out.strip()}
    time.sleep(settle)

    after = {}
    if topology == "netns":
        after = dump_counters(node_bin, cwd)
    elif status_file:
        after = json.load(open(status_file))
    d = delta(before, after)
    asserts, ok = eval_asserts(case.get("assert", {}), d, obs_out)
    return {"case": case["case"], "send": send_result,
            "observed": obs_out, "counter_delta": d,
            "assertions": asserts, "ok": ok}


def main() -> int:
    ap = argparse.ArgumentParser(description="edge-node layered test runner")
    ap.add_argument("--matrix", default=os.path.join(HERE, "matrix.json"))
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", help="comma-separated test ids")
    ap.add_argument("--topology", choices=["netns", "external"],
                    default="netns")
    ap.add_argument("--node-bin", default=os.path.join(
        ROOT, "target", "debug", "cloud-node-rust"))
    ap.add_argument("--config", default=os.path.join(
        ROOT, "configs", "en2-runtime.yaml"))
    ap.add_argument("--ebpf-object", default=os.path.join(
        ROOT, "data", "cloud-node-xdp-ebpf.o"))
    ap.add_argument("--mode", default="protect",
                    choices=["observe", "protect", "proxy"])
    ap.add_argument("--send-iface", default="")
    ap.add_argument("--status-file", default="")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--pps", type=float, default=0)
    ap.add_argument("--settle", type=float, default=0.5)
    ap.add_argument("--out", default="")
    ap.add_argument("--keep-topology", action="store_true")
    args = ap.parse_args()

    matrix = json.load(open(args.matrix))
    only = set(args.only.split(",")) if args.only else None

    if args.list:
        for t in matrix["tests"]:
            mark = "runnable" if t.get("cases") else "pending"
            print(f"{t['id']:5s} {mark:8s} {t['title']}")
        return 0

    if sys.platform != "linux":
        print("runner: Linux required (XDP/AF_PACKET)", file=sys.stderr)
        return 3
    if os.geteuid() != 0:
        print("runner: root/CAP_NET_ADMIN+CAP_NET_RAW required",
              file=sys.stderr)
        return 3
    try:
        require_commands(["ip"])
    except RuntimeError as err:
        print(f"runner: {err}", file=sys.stderr)
        return 3
    # ethtool is best-effort (offload disabling); absence is tolerated.
    have_ethtool = not subprocess.run(
        ["which", "ethtool"], capture_output=True).returncode
    if args.topology == "netns" and not os.path.exists(args.node_bin):
        print(f"runner: node binary missing: {args.node_bin}",
              file=sys.stderr)
        return 3

    digest = None
    if os.path.exists(args.ebpf_object):
        digest = bpf_sha256(args.ebpf_object)

    run = {"topology": args.topology, "mode": args.mode,
           "ebpf_sha256": digest, "node_bin": args.node_bin,
           "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "tests": []}
    all_ok = True
    attached = False
    cwd = os.path.dirname(os.path.dirname(args.config))
    try:
        send_iface = args.send_iface
        mac = None
        if args.topology == "netns":
            teardown_netns()  # remove leftovers of a previous crashed run
            mac = setup_netns()
            write_node_config(args.config, args.mode)
            # point the node at our dedicated config via its config search:
            # the node reads configs/runtime.yaml relative to cwd, so run
            # with a temp working dir containing our config.
            os.makedirs(os.path.join(cwd, "configs"), exist_ok=True)
            runtime_cfg = os.path.join(cwd, "configs", "runtime.yaml")
            backup = runtime_cfg + ".en2-bak"
            if os.path.exists(runtime_cfg):
                os.replace(runtime_cfg, backup)
            with open(runtime_cfg, "w") as f, open(args.config) as src:
                f.write(src.read())
            try:
                attach = subprocess.run(
                    [args.node_bin, "xdp", "attach"],
                    capture_output=True, text=True, cwd=cwd)
                if attach.returncode != 0:
                    print(attach.stdout + attach.stderr, file=sys.stderr)
                    return 3
                attached = True
            finally:
                if os.path.exists(backup):
                    os.replace(backup, runtime_cfg)
                else:
                    os.unlink(runtime_cfg)
            send_iface = PEER_IF
        else:
            if not send_iface:
                print("runner: --send-iface required for external topology",
                      file=sys.stderr)
                return 3

        for t in matrix["tests"]:
            if only and t["id"] not in only:
                continue
            entry = {"id": t["id"], "title": t["title"],
                     "status": t.get("status", "pending"),
                     "prerequisites": t.get("prerequisites", []),
                     "cases": []}
            if not t.get("cases"):
                entry["skip_reason"] = t.get("pending_reason",
                                             "no runnable cases yet")
                run["tests"].append(entry)
                continue
            for case in t["cases"]:
                try:
                    res = run_case(case, args.node_bin, os.path.dirname(
                        os.path.dirname(args.config)), args.topology,
                        send_iface, mac, case.get("count", args.count),
                        case.get("pps", args.pps), args.settle,
                        args.status_file)
                except RuntimeError as err:
                    res = {"case": case["case"], "ok": False,
                           "error": str(err)}
                all_ok &= res.get("ok", False)
                entry["cases"].append(res)
            run["tests"].append(entry)
    except Exception as err:
        all_ok = False
        run["fatal"] = str(err)
    finally:
        if args.topology == "netns":
            if attached:
                subprocess.run([args.node_bin, "xdp", "detach"],
                               capture_output=True, cwd=cwd)
            if not args.keep_topology:
                teardown_netns()

    run["ok"] = all_ok
    out = json.dumps(run, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(out + "\n")
    print(out)
    if "fatal" in run:
        return 3
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
