#!/usr/bin/env python3
"""IPv6 services and probes for the isolated Linux TUN acceptance test."""

import argparse
import functools
import hashlib
import http.server
import pathlib
import socket
import struct
import threading
import urllib.request

TARGET = "2001:db8:2::2"
QUERY = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x1c\x00\x01"
)


def udp_socket(port):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    # Linux IPV6_MTU_DISCOVER=DONT and IPV6_MTU=1280 permit source
    # fragmentation of the 4096-byte UDP payload in both directions.
    sock.setsockopt(socket.IPPROTO_IPV6, 23, 0)
    sock.setsockopt(socket.IPPROTO_IPV6, 24, 1280)
    sock.bind((TARGET, port))
    return sock


def dns_response(query):
    answer = (
        b"\xc0\x0c" + query[-4:] + struct.pack("!IH", 60, 16)
        + socket.inet_pton(socket.AF_INET6, TARGET)
    )
    return query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01" + b"\x00" * 4 + query[12:] + answer


def serve_udp(sock, dns=False):
    while True:
        query, peer = sock.recvfrom(65535)
        sock.sendto(dns_response(query) if dns else query, peer)


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("Truncated DNS stream")
        data.extend(chunk)
    return bytes(data)


def serve_tcp_dns(sock):
    while True:
        conn, _ = sock.accept()
        with conn:
            conn.settimeout(3)
            try:
                size = struct.unpack("!H", receive_exact(conn, 2))[0]
                response = dns_response(receive_exact(conn, size))
                conn.sendall(struct.pack("!H", len(response)) + response)
            except (OSError, EOFError):
                continue


class IPv6HTTPServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def serve(directory):
    dns = udp_socket(53)
    echo = udp_socket(9000)
    tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    tcp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((TARGET, 53))
    tcp.listen(16)
    for function, args in (
        (serve_udp, (dns, True)),
        (serve_udp, (echo,)),
        (serve_tcp_dns, (tcp,)),
    ):
        threading.Thread(target=function, args=args, daemon=True).start()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    with IPv6HTTPServer((TARGET, 8080), handler) as server:
        print("IPv6 HTTP, DNS and UDP echo ready", flush=True)
        server.serve_forever()


def check(payload_file):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://[{TARGET}]:8080/payload.bin", timeout=20) as response:
        received = response.read()
    expected = pathlib.Path(payload_file).read_bytes()
    assert len(received) == 1024 * 1024
    assert hashlib.sha256(received).digest() == hashlib.sha256(expected).digest()
    print("IPv6 HTTP 1 MiB SHA256 passed", flush=True)

    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
        udp.settimeout(5)
        udp.sendto(QUERY, (TARGET, 53))
        response, _ = udp.recvfrom(512)
        assert response == dns_response(QUERY)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as tcp:
            tcp.settimeout(5)
            tcp.connect((TARGET, 53))
            tcp.sendall(struct.pack("!H", len(QUERY)) + QUERY)
            size = struct.unpack("!H", receive_exact(tcp, 2))[0]
            assert receive_exact(tcp, size) == dns_response(QUERY)
        print("IPv6 UDP and TCP DNS passed", flush=True)

        udp.setsockopt(socket.IPPROTO_IPV6, 23, 0)
        udp.setsockopt(socket.IPPROTO_IPV6, 24, 1280)
        for size in (1, 512, 1232, 4096):
            payload = bytes(i % 251 for i in range(size))
            udp.sendto(payload, (TARGET, 9000))
            response, _ = udp.recvfrom(65535)
            assert response == payload, (size, len(response))
            print(f"IPv6 UDP echo bytes: {size}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve", "check"))
    parser.add_argument("path")
    arguments = parser.parse_args()
    if arguments.action == "serve":
        serve(arguments.path)
    else:
        check(arguments.path)
