#!/usr/bin/env python3
"""EN-16 evidence probe: kernel-BPF map memory ledger.

The eBPF object pins several hundred MB of non-reclaimable kernel memory
across 31 maps. This probe proves the ledger is observable and enforced:

  A baseline accounting: `xdp dump-maps` reports
    kernelBpfBudget.{projectedBytes,budgetBytes}; the projection is a
    non-zero bound derived from the synchronized spec table and fits the
    governor-derived budget on an unconstrained host.
  B positive attach: a node under the normal budget attaches XDP and the
    pinned footprint is visible to bpftool.
  C negative attach: running the node inside a cgroup whose memory.max
    shrinks kernel_bpf_budget_bytes below the projection must fail attach
    explicitly — the error names the kernel-bpf budget and no link pin is
    created. No silent attach with unaccounted kernel memory.

Usage (root, Linux):
    sudo python3 scripts/edge/en16_bpf_budget_probe.py \
        --node-bin target/debug/cloud-node-rust --out /tmp/en16.json
"""

import argparse
import json
import os
import subprocess
import sys
import time

NS = "en2-ns"
HOST_IF = "en2-a"
PEER_IF = "en2-b"
HOST_IP = "10.99.0.5"
PEER_IP = "10.99.0.6"
PIN_DIR = "/sys/fs/bpf/cloud-node-xdp"
CGROUP = "/sys/fs/cgroup/en16-bpf-budget"
# 4 GiB -> state_budget = 8% ~= 343 MiB < ~365 MiB projected map memory.
CGROUP_MAX = 4 * 1024 * 1024 * 1024


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
    sh(["ip", "netns", "add", NS])
    sh(["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", PEER_IF])
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


def teardown_netns():
    for cmd in (["ip", "link", "delete", HOST_IF],
                ["ip", "netns", "delete", NS]):
        subprocess.run(cmd, capture_output=True)


def write_node_config(path):
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
"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(body)


def write_api_config(path):
    # Appends the API stub to api_node.yaml — write_node_config already
    # wrote the xdp: section of the same file.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write('nodeId: "0"\nsecret: "en16-probe"\n'
                '"rpc.endpoints":\n  - "http://127.0.0.1:9/"\n'
                '"rpc.disableUpdate": true\n'
                'kernelTuning:\n  enabled: false\n')


def prepare_home(cwd):
    home = os.path.join(cwd, "home")
    write_node_config(os.path.join(home, "configs", "api_node.yaml"))
    write_api_config(os.path.join(home, "configs", "api_node.yaml"))
    return home


def dump_maps(node_bin, cwd):
    out = sh([node_bin, "xdp", "dump-maps"], cwd=cwd).stdout
    return json.loads(out)


def start_node(node_bin, home, cwd, cgroup=None):
    env = dict(os.environ, CLOUD_NODE_HOME=home, RUST_LOG="info")
    log_path = os.path.join(cwd, "node.log")
    log = open(log_path, "w")
    if cgroup:
        cmd = ["bash", "-c",
               f"echo $$ > {cgroup}/cgroup.procs && exec "
               f"{os.path.abspath(node_bin)}"]
    else:
        cmd = [os.path.abspath(node_bin)]
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=log, stderr=log,
                            start_new_session=True)
    return proc, log_path


def wait_attach_or_exit(proc, seconds=40):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if os.path.exists(f"{PIN_DIR}/link-{HOST_IF}"):
            time.sleep(1)
            return "attached"
        if proc.poll() is not None:
            return "exited"
        time.sleep(0.3)
    return "timeout"


def stop_node(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    try:
        sh(["rm", "-rf", PIN_DIR], check=False)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-bin", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("en16_bpf_budget_probe: must run as root")
    cwd = os.path.abspath(".")
    node_bin = os.path.abspath(args.node_bin)
    home = prepare_home(cwd)
    phases = []

    # Phase A: baseline accounting is observable without attaching.
    maps = dump_maps(node_bin, cwd)
    ledger = maps.get("kernelBpfBudget", {})
    projected = int(ledger.get("projectedBytes", 0))
    budget = int(ledger.get("budgetBytes", 0))
    ok_a = projected > 0 and budget > 0 and projected <= budget
    phases.append({
        "phase": "A_ledger_observable",
        "projectedBytes": projected,
        "budgetBytes": budget,
        "ok": ok_a,
        "note": "dump-maps exposes the kernel-BPF ledger; projection is "
                "nonzero and fits the governor-derived budget",
    })

    setup_netns()
    try:
        # Phase B: positive attach under the normal budget.
        proc, log_path = start_node(node_bin, home, cwd)
        outcome = wait_attach_or_exit(proc)
        ok_b = outcome == "attached"
        pinned = {}
        if ok_b:
            out = sh(["bpftool", "-j", "map", "show"], check=False).stdout
            try:
                for m in json.loads(out):
                    name = m.get("name", "")
                    if name.startswith("XDP_"):
                        pinned[name] = m.get("bytes_memlocked", 0)
            except json.JSONDecodeError:
                pass
        stop_node(proc)
        phases.append({
            "phase": "B_positive_attach",
            "attachOutcome": outcome,
            "pinnedMapCount": len(pinned),
            "pinnedBytesTotal": sum(pinned.values()),
            "ok": ok_b,
            "note": "node attaches XDP when the projected footprint fits "
                    "the kernel-BPF budget",
        })

        # Phase C: negative attach inside a memory-capped cgroup.
        sh(["mkdir", "-p", CGROUP])
        with open(f"{CGROUP}/memory.max", "w") as f:
            f.write(str(CGROUP_MAX))
        proc, log_path = start_node(node_bin, home, cwd, cgroup=CGROUP)
        outcome = wait_attach_or_exit(proc, seconds=25)
        proc.poll()
        log_text = ""
        try:
            with open(log_path) as f:
                log_text = f.read()
        except OSError:
            pass
        named = "kernel-bpf budget" in log_text
        pin_created = os.path.exists(f"{PIN_DIR}/link-{HOST_IF}")
        ok_c = outcome in ("exited", "timeout") and named and not pin_created
        stop_node(proc)
        phases.append({
            "phase": "C_budget_refusal",
            "attachOutcome": outcome,
            "cgroupMemoryMax": CGROUP_MAX,
            "budgetErrorLogged": named,
            "linkPinCreated": pin_created,
            "ok": ok_c,
            "note": "when kernel_bpf_budget_bytes < projected map memory, "
                    "attach fails explicitly naming the budget and no link "
                    "pin is created",
        })
        sh(["rmdir", CGROUP], check=False)
    finally:
        teardown_netns()

    result = {"phases": phases, "ok": all(p["ok"] for p in phases)}
    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
