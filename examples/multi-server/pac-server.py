#!/usr/bin/env python3
"""Serve split community rules and strict wrapper only, from the private runtime directory."""
import argparse
import hashlib
import http.server
from pathlib import Path
import signal
import urllib.parse

BASE = Path(__file__).resolve().parent


class PAC(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_pac(False)

    def do_HEAD(self):
        self.send_pac(True)

    def send_pac(self, head):
        if urllib.parse.urlsplit(self.path).path != '/proxy.pac':
            self.send_error(404)
            return
        data = (BASE / 'proxy.pac').read_bytes() + b'\n' + (BASE / 'direct-first.js').read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-ns-proxy-autoconfig')
        self.send_header('Cache-Control', 'no-store, max-age=0')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('ETag', '"' + hashlib.sha256(data).hexdigest() + '"')
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        # Do not log arbitrary request URLs, which may contain credentials.
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8090)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Invalid port')
    server = http.server.ThreadingHTTPServer(('127.0.0.1', args.port), PAC)
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, 'pthread_sigmask'):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
