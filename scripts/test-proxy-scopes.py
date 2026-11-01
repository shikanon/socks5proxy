#!/usr/bin/env python3
"""Exercise built CLIs, destination routing, CONNECT, SOCKS5 and PAC JavaScript."""
import argparse
import contextlib
import http.client
import http.server
import json
import os
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def running_process(command):
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                status = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("CLI did not stop within five seconds")
            if status != 0:
                log.seek(0)
                raise AssertionError(log.read().decode(errors="replace"))


def wait_ready(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert process.poll() is None, "CLI exited before listening"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise AssertionError("CLI did not listen within five seconds")


@contextlib.contextmanager
def running_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class Origin(http.server.BaseHTTPRequestHandler):
    visits = 0

    def do_GET(self):
        type(self).visits += 1
        body = b"origin-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Bridge(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.count_lock:
            self.server.count += 1
        with socket.create_connection(self.server.destination, timeout=3) as remote:
            remote.settimeout(3)
            self.request.settimeout(3)

            def copy(source, destination):
                try:
                    while True:
                        data = source.recv(32768)
                        if not data:
                            break
                        destination.sendall(data)
                except OSError:
                    pass
                finally:
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            forward = threading.Thread(target=copy, args=(self.request, remote))
            forward.start()
            copy(remote, self.request)
            forward.join(timeout=4)


class BridgeServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, destination):
        super().__init__(("127.0.0.1", 0), Bridge)
        self.destination = destination
        self.count = 0
        self.count_lock = threading.Lock()


def read_exact(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        assert chunk, "unexpected SOCKS EOF"
        result += chunk
    return result


def request(port, mode, host, target_port, connect=False):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        address = f"{host}:{target_port}"
        if mode == "socks5":
            sock.sendall(b"\x05\x01\x00")
            assert read_exact(sock, 2) == b"\x05\x00"
            name = host.encode("ascii")
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", target_port))
            reply = read_exact(sock, 10)
            if reply[1] != 0:
                return reply[1], b""
        elif connect:
            sock.sendall(f"CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n".encode())
            response = http.client.HTTPResponse(sock, method="CONNECT")
            response.begin()
            status = response.status
            response.close()
            if status != 200:
                return status, b""
        path = "/" if mode == "socks5" or connect else f"http://{address}/"
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(sock)
        response.begin()
        return response.status, response.read()


def check_pac(port, proxy_port, mode, runtime):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    connection.request("GET", "/proxy.pac")
    response = connection.getresponse()
    assert response.status == 200
    assert response.getheader("Content-Type") == "application/x-ns-proxy-autoconfig"
    pac = response.read().decode()
    connection.close()
    directive = f"{'SOCKS5' if mode == 'socks5' else 'PROXY'} 127.0.0.1:{proxy_port}"
    cases = [
        ["localhost", directive], ["LOCALHOST.", directive],
        ["a.b.localhost", directive], ["localhost.evil", "DIRECT"],
        ["api1.example.com", directive], ["api12.example.com", "DIRECT"],
        ["api.example.com", "DIRECT"], ["xn--bcher-kva.example", directive],
        ["else.test", "DIRECT"], ["127.0.0.1", "DIRECT"],
    ]
    program = """
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const data = JSON.parse(fs.readFileSync(0, 'utf8'));
const sandbox = {};
vm.runInNewContext(data.pac, sandbox, {timeout: 1000});
for (const [host, expected] of data.cases) {
  assert.strictEqual(sandbox.FindProxyForURL('https://' + host + '/private', host), expected, host);
}
"""
    environment = dict(os.environ, ELECTRON_RUN_AS_NODE="1")
    subprocess.run([runtime, "-e", program], input=json.dumps({"pac": pac, "cases": cases}),
                   text=True, env=environment, check=True, timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--js-runtime", default=shutil.which("node"))
    parser.add_argument("--version", default=None)
    args = parser.parse_args()
    assert args.js_runtime, "Node.js-compatible runtime is required to execute PAC"
    for binary in (args.client, args.server):
        version = subprocess.check_output([binary, "-version"], text=True).strip()
        assert version and (args.version is None or version == args.version), version
    for invalid in (
        ["-proxy-scope", "rules"],
        ["-proxy-scope", "all", "-proxy-domains", "*.localhost"],
        ["-mode", "tunnel", "-proxy-scope", "rules", "-proxy-domains", "*.localhost"],
        ["-pac-listen", "0.0.0.0:8090"],
    ):
        result = subprocess.run([args.client, "-server", "127.0.0.1:1", "-passwd", "smoke"] + invalid,
                                capture_output=True, timeout=3)
        assert result.returncode != 0, invalid
    with contextlib.ExitStack() as stack:
        origin = stack.enter_context(running_server(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)))
        target_port = origin.server_port
        remote_port = unused_port()
        server = stack.enter_context(running_process([
            args.server, "-local", f"127.0.0.1:{remote_port}", "-passwd", "smoke",
        ]))
        wait_ready(remote_port, server)
        bridge = BridgeServer(("127.0.0.1", remote_port))
        bridge_port = bridge.server_address[1]
        with running_server(bridge):
            for mode in ("http", "socks5"):
                port, pac_port = unused_port(), unused_port()
                client = stack.enter_context(running_process([
                    args.client, "-local", f"127.0.0.1:{port}", "-server", f"127.0.0.1:{bridge_port}",
                    "-passwd", "smoke", "-recv", mode, "-proxy-scope", "rules",
                    "-proxy-domains", "*.localhost,api?.example.*,bücher.example",
                    "-pac-listen", f"127.0.0.1:{pac_port}",
                ]))
                wait_ready(pac_port, client)
                check_pac(pac_port, port, mode, args.js_runtime)
                before = bridge.count
                assert request(port, mode, "127.0.0.1", target_port) == (200, b"origin-ok")
                assert bridge.count == before, "unmatched target unexpectedly used remote"
                assert request(port, mode, "localhost", target_port) == (200, b"origin-ok")
                assert bridge.count == before + 1, "matched target did not use remote"
                if mode == "http":
                    assert request(port, mode, "127.0.0.1", target_port, connect=True) == (200, b"origin-ok")
                    assert bridge.count == before + 1
                    assert request(port, mode, "localhost", target_port, connect=True) == (200, b"origin-ok")
                    assert bridge.count == before + 2
            port = unused_port()
            client = stack.enter_context(running_process([
                args.client, "-local", f"127.0.0.1:{port}", "-server", f"127.0.0.1:{bridge_port}",
                "-passwd", "smoke", "-proxy-scope", "all",
            ]))
            wait_ready(port, client)
            before = bridge.count
            assert request(port, "http", "127.0.0.1", target_port) == (200, b"origin-ok")
            assert bridge.count == before + 1
        # Remote port is now unavailable; direct traffic must still work.
        for mode in ("http", "socks5"):
            port = unused_port()
            client = stack.enter_context(running_process([
                args.client, "-local", f"127.0.0.1:{port}", "-server", f"127.0.0.1:{bridge_port}",
                "-passwd", "smoke", "-recv", mode, "-proxy-scope", "rules",
                "-proxy-domains", "*.localhost",
            ]))
            wait_ready(port, client)
            assert request(port, mode, "127.0.0.1", target_port) == (200, b"origin-ok")
            before = Origin.visits
            status, _ = request(port, mode, "localhost", target_port)
            assert status == (502 if mode == "http" else 5), status
            assert Origin.visits == before, "matched failure silently fell back to direct"
    print("CLI scopes/PAC passed: HTTP, CONNECT, SOCKS5, remote/direct, no fallback, version and shutdown")


if __name__ == "__main__":
    main()
