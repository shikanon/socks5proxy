#!/usr/bin/env python3
"""Serve one PAC file on loopback only; never expose directory contents or secrets."""
import argparse
import hashlib
import http.server
import ipaddress
import signal
from pathlib import Path
import urllib.parse

DEFAULT = Path(__file__).resolve().parents[1] / 'examples/community-pac/proxy.pac'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pac', type=Path, default=DEFAULT)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8090)
    args = parser.parse_args()
    if not ipaddress.ip_address(args.host).is_loopback or ':' in args.host:
        parser.error('host must be an IPv4 loopback address')
    if not 1 <= args.port <= 65535:
        parser.error('invalid port')
    if not args.pac.is_file():
        parser.error('PAC file is missing; run build-community-pac.py')

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self): self.send_pac(False)
        def do_HEAD(self): self.send_pac(True)
        def send_pac(self, head):
            if urllib.parse.urlsplit(self.path).path != '/proxy.pac':
                self.send_error(404)
                return
            data = args.pac.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-ns-proxy-autoconfig')
            self.send_header('Cache-Control', 'no-store, max-age=0')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('ETag', '"' + hashlib.sha256(data).hexdigest() + '"')
            self.end_headers()
            if not head: self.wfile.write(data)
    server = http.server.ThreadingHTTPServer((args.host,args.port), Handler)
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, 'pthread_sigmask'):
        # Some launcher environments block these signals across exec; the server
        # owns them and must receive them for normal shutdown.
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == '__main__': main()
