#!/usr/bin/env python3
"""Small dependency-free HTTP/1.1 load and pressure client for the RKE2 matrix."""

import argparse
import asyncio
import json
import time
from collections import Counter


def percentile(values, fraction):
    if not values:
        return 0.0
    values = sorted(values)
    index = round((len(values) - 1) * fraction)
    return values[min(index, len(values) - 1)]


async def read_response(reader):
    status_line = await reader.readline()
    if not status_line:
        raise ConnectionResetError("empty status line")
    parts = status_line.decode("latin1", "replace").split()
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    headers = {}
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        if b":" in line:
            key, value = line.decode("latin1", "replace").split(":", 1)
            headers[key.lower().strip()] = value.strip()
    length = int(headers.get("content-length", "0") or 0)
    body = await reader.readexactly(length) if length else b""
    return status, len(body), headers


async def request(host, port, path, keepalive, timeout):
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    connection = "keep-alive" if keepalive else "close"
    request_bytes = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: perf.local\r\n"
        f"Connection: {connection}\r\n"
        f"Accept: */*\r\n\r\n"
    ).encode()
    writer.write(request_bytes)
    await asyncio.wait_for(writer.drain(), timeout)
    result = await asyncio.wait_for(read_response(reader), timeout)
    if not keepalive:
        writer.close()
        await writer.wait_closed()
    return result, writer


async def worker(args, samples, errors, counter, stop_at):
    connection = None
    reader = None
    writer = None
    while time.perf_counter() < stop_at:
        started = time.perf_counter()
        try:
            if args.mode == "churn" or writer is None:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(args.host, args.port), args.timeout
                )
            request_bytes = (
                f"GET {args.path} HTTP/1.1\r\n"
                f"Host: perf.local\r\n"
                f"Connection: {'keep-alive' if args.mode == 'keepalive' else 'close'}\r\n"
                f"Accept: */*\r\n\r\n"
            ).encode()
            writer.write(request_bytes)
            await asyncio.wait_for(writer.drain(), args.timeout)
            status, body_bytes, _ = await asyncio.wait_for(
                read_response(reader), args.timeout
            )
            samples.append((time.perf_counter() - started) * 1000.0)
            counter["requests"] += 1
            counter["bytes"] += body_bytes
            counter[f"status_{status}"] += 1
            if status == args.expected_status:
                counter["success"] += 1
            else:
                counter["http_errors"] += 1
            if args.mode == "churn":
                writer.close()
                await writer.wait_closed()
                writer = None
        except asyncio.CancelledError:
            break
        except asyncio.TimeoutError:
            errors["timeout"] += 1
            if writer is not None:
                writer.close()
                writer = None
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            errors["reset"] += 1
            if writer is not None:
                writer.close()
                writer = None
        except Exception as exc:  # noqa: BLE001 - classify all pressure failures
            errors[type(exc).__name__] += 1
            if writer is not None:
                writer.close()
                writer = None
    if writer is not None:
        writer.close()
        await writer.wait_closed()


async def slow_header_worker(args, errors, counter, stop_at):
    while time.perf_counter() < stop_at:
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(args.host, args.port), args.timeout
            )
            writer.write(b"GET / HTTP/1.1\r\nHost: slow.perf\r\n")
            await asyncio.wait_for(writer.drain(), args.timeout)
            await asyncio.sleep(args.slow_delay)
            writer.write(b"Connection: close\r\n\r\n")
            await asyncio.wait_for(writer.drain(), args.timeout)
            counter["completed"] += 1
        except Exception as exc:  # noqa: BLE001
            errors[type(exc).__name__] += 1
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()


async def malformed_worker(args, errors, counter, stop_at):
    payloads = [b"NOT HTTP\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n", b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n"]
    index = 0
    while time.perf_counter() < stop_at:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(args.host, args.port), args.timeout
            )
            writer.write(payloads[index % len(payloads)])
            await asyncio.wait_for(writer.drain(), args.timeout)
            await asyncio.wait_for(reader.read(256), args.timeout)
            counter["completed"] += 1
            index += 1
        except Exception as exc:  # noqa: BLE001
            errors[type(exc).__name__] += 1
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()


async def oversized_header_worker(args, errors, counter, stop_at):
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Host: oversized.perf\r\n"
        + b"X-Oversized: "
        + (b"a" * args.oversized_bytes)
        + b"\r\nConnection: close\r\n\r\n"
    )
    while time.perf_counter() < stop_at:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(args.host, args.port), args.timeout
            )
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), args.timeout)
            await asyncio.wait_for(reader.read(256), args.timeout)
            counter["completed"] += 1
        except Exception as exc:  # noqa: BLE001 - classify all pressure failures
            errors[type(exc).__name__] += 1
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()


async def run(args):
    samples = []
    errors = Counter()
    counter = Counter()
    stop_at = time.perf_counter() + args.duration
    tasks = []
    for _ in range(args.concurrency):
        if args.mode == "slow-header":
            task = slow_header_worker(args, errors, counter, stop_at)
        elif args.mode == "malformed":
            task = malformed_worker(args, errors, counter, stop_at)
        elif args.mode == "oversized-header":
            task = oversized_header_worker(args, errors, counter, stop_at)
        else:
            task = worker(args, samples, errors, counter, stop_at)
        tasks.append(asyncio.create_task(task))
    await asyncio.gather(*tasks)
    elapsed = args.duration
    result = {
        "host": args.host,
        "port": args.port,
        "path": args.path,
        "mode": args.mode,
        "duration_secs": elapsed,
        "concurrency": args.concurrency,
        "requests": counter["requests"],
        "success": counter["success"],
        "bytes": counter["bytes"],
        "requests_per_sec": counter["requests"] / elapsed,
        "bytes_per_sec": counter["bytes"] / elapsed,
        "errors": dict(errors),
        "counter": dict(counter),
        "latency_ms": {
            "p50": percentile(samples, 0.50),
            "p95": percentile(samples, 0.95),
            "p99": percentile(samples, 0.99),
            "max": max(samples) if samples else 0.0,
        },
    }
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--path", default="/1k.bin")
    parser.add_argument(
        "--mode",
        choices=["keepalive", "churn", "slow-header", "malformed", "oversized-header"],
        default="keepalive",
    )
    parser.add_argument("--duration", type=float, default=15.0)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--slow-delay", type=float, default=0.5)
    parser.add_argument("--expected-status", type=int, default=200)
    parser.add_argument("--oversized-bytes", type=int, default=131072)
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
