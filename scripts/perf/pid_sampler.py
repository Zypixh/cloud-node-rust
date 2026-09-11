#!/usr/bin/env python3
"""Sample CPU% and RSS for a set of PIDs while a load run is in flight.

Usage: pid_sampler.py --pid 1234 [--pid 5678] --duration 15 --interval 0.5 --out run.json
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", action="append", type=int, required=True)
    ap.add_argument("--name", action="append", default=None)
    ap.add_argument("--duration", type=float, required=True)
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    names = args.name or [f"pid{p}" for p in args.pid]
    prev_proc = {p: read_stat(p) for p in args.pid}
    prev_total = total_cpu_jiffies()
    prev_t = time.monotonic()

    series = {n: [] for n in names}
    rss_peak = {n: 0 for n in names}
    deadline = prev_t + args.duration
    while time.monotonic() < deadline:
        time.sleep(args.interval)
        now = time.monotonic()
        now_total = total_cpu_jiffies()
        dtotal = now_total - prev_total
        dt = now - prev_t
        for name, pid in zip(names, args.pid):
            cur = read_stat(pid)
            if cur is None or prev_proc.get(pid) is None or dtotal <= 0:
                continue
            cpu_pct = (cur - prev_proc[pid]) / CLK / dt * 100.0
            rss = read_rss_kb(pid)
            rss_peak[name] = max(rss_peak[name], rss)
            series[name].append({"t": round(now, 1), "cpu_pct": round(cpu_pct, 1), "rss_kb": rss})
            prev_proc[pid] = cur
        prev_total = now_total
        prev_t = now

    summary = {}
    for name in names:
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
