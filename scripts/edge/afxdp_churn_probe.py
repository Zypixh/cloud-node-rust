#!/usr/bin/env python3
"""AF_XDP TCP relay-leak churn probe.

Phase A (FIN churn): connect -> send -> shutdown(WR) -> read to EOF -> close.
    Exercises the CloseWait -> ingress EOF path. The relay task must observe
    EOF and exit; relayDone should track relayStart.

Phase B (RST churn): connect -> send -> recv once -> SO_LINGER=0 close.
    Exercises the peer-RST -> Closed -> session reap path. Upstream sockets
    and admission permits must release with the task.

Usage: afxdp_churn_probe.py <target_ip> <port> <cycles_per_phase> [concurrency]
Run inside the peer netns against the AF_XDP proxy port.
"""
import socket
import struct
import sys
import threading
import time


def fin_cycle(target, port, errors):
    try:
        s = socket.create_connection((target, port), timeout=5)
        s.settimeout(5)
        s.sendall(b"churn-fin")
        s.shutdown(socket.SHUT_WR)
        while s.recv(4096):
            pass
        s.close()
    except OSError:
        errors[0] += 1


def rst_cycle(target, port, errors):
    try:
        s = socket.create_connection((target, port), timeout=5)
        s.settimeout(5)
        s.sendall(b"churn-rst")
        try:
            s.recv(64)
        except OSError:
            pass
        s.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
        )
        s.close()
    except OSError:
        errors[0] += 1


def run_phase(name, fn, target, port, cycles, workers):
    errors = [0]
    done = [0]
    lock = threading.Lock()

    def worker():
        while True:
            with lock:
                i = done[0]
                done[0] += 1
            if i >= cycles:
                return
            fn(target, port, errors)

    t0 = time.monotonic()
    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dt = time.monotonic() - t0
    print(
        f"{name}: cycles={cycles} errors={errors[0]} "
        f"elapsed={dt:.1f}s rate={cycles / max(dt, 0.001):.1f}/s",
        flush=True,
    )


def main():
    target, port = sys.argv[1], int(sys.argv[2])
    cycles = int(sys.argv[3]) if len(sys.argv) > 3 else 1500
    workers = int(sys.argv[4]) if len(sys.argv) > 4 else 8
    run_phase("fin", fin_cycle, target, port, cycles, workers)
    time.sleep(2)
    run_phase("rst", rst_cycle, target, port, cycles, workers)


if __name__ == "__main__":
    main()
