#!/usr/bin/env python3
"""Sample CPU% and RSS for a set of PIDs while a load run is in flight.

Usage: pid_sampler.py --pid 1234 --name proxy [--pid 5678 --name nginx --pid 5679 --name nginx] \
    --duration 15 --interval 0.5 --out run.json

Multiple PIDs may share one --name; their CPU% and RSS are aggregated so a
multi-worker process (e.g. nginx worker_processes auto) is reported as a
single series instead of sampling only the first worker.
"""
import argparse
import json
import time

CLK = 100.0  # USER_HZ on Linux


def read_stat(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        # fields after comm (which may contain spaces/parens): find last ')'
        return int(parts[13]) + int(parts[14])  # utime + stime (jiffies)
    except FileNotFoundError:
        return None


def read_rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS"):
                    return int(line.split()[1])
    except FileNotFoundError:
        pass
    return 0


def total_cpu_jiffies():
    with open("/proc/stat") as f:
        fields = f.readline().split()[1:]
    return sum(int(x) for x in fields)


import signal


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", action="append", type=int, required=True)
    ap.add_argument("--name", action="append", default=None)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    # Request-count bounded runs (oha -n) may finish before --duration. The
    # driver sends SIGTERM when the load ends; finalize and write what was
    # sampled so the CPU average covers exactly the loaded interval.
    stopped = False

    def _stop(_sig, _frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    names = args.name or [f"pid{p}" for p in args.pid]
    if len(names) != len(args.pid):
        ap.error("--name must be given once per --pid")
    # name -> [pids]; order preserved, duplicates merged.
    groups = {}
    for pid, name in zip(args.pid, names):
        groups.setdefault(name, []).append(pid)

    prev_proc = {p: read_stat(p) for p in args.pid}
    prev_total = total_cpu_jiffies()
    prev_t = time.monotonic()

    series = {n: [] for n in groups}
    rss_peak = {n: 0 for n in groups}
    deadline = prev_t + args.duration
    while time.monotonic() < deadline and not stopped:
        time.sleep(args.interval)
        now = time.monotonic()
        now_total = total_cpu_jiffies()
        dtotal = now_total - prev_total
        dt = now - prev_t
        for name, pids in groups.items():
            cpu_jiffies = 0
            rss_kb = 0
            missing = False
            for pid in pids:
                cur = read_stat(pid)
                if cur is None or prev_proc.get(pid) is None:
                    missing = True
                    continue
                cpu_jiffies += cur - prev_proc[pid]
                prev_proc[pid] = cur
                rss_kb += read_rss_kb(pid)
            if missing or dtotal <= 0:
                continue
            cpu_pct = cpu_jiffies / CLK / dt * 100.0
            rss_peak[name] = max(rss_peak[name], rss_kb)
            series[name].append(
                {"t": round(now, 1), "cpu_pct": round(cpu_pct, 1), "rss_kb": rss_kb}
            )
        prev_total = now_total
        prev_t = now

    summary = {}
    for name in groups:
        cpus = [s["cpu_pct"] for s in series[name]]
        summary[name] = {
            "cpu_pct_avg": round(sum(cpus) / len(cpus), 1) if cpus else 0.0,
            "cpu_pct_max": round(max(cpus), 1) if cpus else 0.0,
            "rss_mb_peak": round(rss_peak[name] / 1024.0, 1),
            "samples": len(cpus),
        }
    with open(args.out, "w") as f:
        json.dump({"summary": summary, "series": series}, f, indent=1)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
