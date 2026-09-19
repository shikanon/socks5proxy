#!/usr/bin/env python3
"""Bounded namespace benchmark; results describe one host, not an Internet path."""

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import random
import subprocess
import time


def serve(directory, address):
    root = pathlib.Path(directory)
    rng = random.Random(20260920)
    for size in (1048576, 8388608):
        (root / f"bench-{size}.bin").write_bytes(rng.randbytes(size))

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

        def do_POST(self):
            remaining = int(self.headers.get("Content-Length", "0"))
            digest = hashlib.sha256()
            while remaining:
                block = self.rfile.read(min(65536, remaining))
                if not block:
                    self.send_error(400)
                    return
                remaining -= len(block)
                digest.update(block)
            body = digest.hexdigest().encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    http.server.ThreadingHTTPServer((address, 8080), Handler).serve_forever()


def cpu_seconds(pids):
    ticks = os.sysconf("SC_CLK_TCK")
    total = 0
    for pid in pids:
        fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        total += int(fields[11]) + int(fields[12])
    return total / ticks


def measure(args):
    root = pathlib.Path(args.directory)
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    cases = [(1048576, "download"), (8388608, "download"), (8388608, "upload")]
    for size, direction in cases:
        source = root / f"bench-{size}.bin"
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        received = root / "bench-received"
        curl = ["ip", "netns", "exec", args.namespace, "curl", "-sS", "--fail",
                "--connect-timeout", "5", "--max-time", "40",
                "-o", str(received), "-w", "%{json}"]
        if args.proxy:
            curl += ["--noproxy", "", "--proxy", args.proxy]
        if direction == "upload":
            curl += ["-H", "Expect:", "-X", "POST", "--data-binary", "@" + str(source)]
        curl += [f"http://198.51.100.2:8080/bench-{size}.bin"]
        before = cpu_seconds(args.pids)
        started = time.monotonic()
        result = subprocess.run(curl, capture_output=True, text=True, timeout=45)
        elapsed = time.monotonic() - started
        cpu = cpu_seconds(args.pids) - before
        try:
            metrics = json.loads(result.stdout)
        except ValueError:
            metrics = {"unparsed_output": result.stdout}
        data = received.read_bytes() if received.exists() else b""
        valid = ((len(data) == size and hashlib.sha256(data).hexdigest() == expected)
                 if direction == "download" else data.decode(errors="replace") == expected)
        sample = {
            "environment": "single-host Linux network namespaces, lossless veth",
            "transport": args.transport, "obfs": args.obfs, "mtu": args.mtu,
            "round": args.round, "direction": direction, "bytes": size,
            "exit": result.returncode, "hash_ok": valid, "wall_seconds": elapsed,
            "tunnel_process_cpu_seconds": cpu, "curl": metrics, "stderr": result.stderr,
        }
        with output.open("a") as stream:
            stream.write(json.dumps(sample) + "\n")
        print(json.dumps({k: sample[k] for k in (
            "transport", "round", "direction", "bytes", "exit", "hash_ok",
            "wall_seconds", "tunnel_process_cpu_seconds")}), flush=True)
        if result.returncode != 0 or not valid:
            raise SystemExit("benchmark failed; failed sample retained")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    server = sub.add_parser("serve")
    server.add_argument("directory")
    server.add_argument("address")
    bench = sub.add_parser("measure")
    for name in ("directory", "namespace", "output", "transport", "obfs", "round"):
        bench.add_argument("--" + name, required=True)
    bench.add_argument("--mtu", type=int, required=True)
    bench.add_argument("--pids", type=int, nargs="+", required=True)
    bench.add_argument("--proxy")
    args = p.parse_args()
    if args.action == "serve":
        serve(args.directory, args.address)
    else:
        measure(args)
