#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(id -u)" -ne 0 ]]; then
  echo "This integration test requires Linux root privileges." >&2
  exit 77
fi

for command in go ip iptables openssl python3 curl ping sha256sum; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 77
  }
done

if [[ ! -c /dev/net/tun ]]; then
  echo "/dev/net/tun is unavailable." >&2
  exit 77
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
transport_mode="${TUNNEL_TRANSPORT:-quic}"
obfs_mode="${TUNNEL_OBFS:-random}"
configured_mtu="${TUNNEL_TEST_MTU:-1280}"
packet_mtu="$configured_mtu"
[[ "$transport_mode" == "quic" ]] && packet_mtu=1150
work_dir="$(mktemp -d)"
suffix="$$"
client_ns="s5pc-${suffix}"
server_ns="s5ps-${suffix}"
target_ns="s5pt-${suffix}"
client_pid=""
server_pid=""
target_pid=""
dns_pid=""

cleanup() {
  set +e
  if [[ -n "$client_pid" ]]; then
    if [[ "$transport_mode" == "proxy" ]]; then
      kill -TERM "$client_pid" 2>/dev/null
    else
      kill -INT "$client_pid" 2>/dev/null
    fi
  fi
  [[ -n "$server_pid" ]] && kill -TERM "$server_pid" 2>/dev/null
  [[ -n "$target_pid" ]] && kill "$target_pid" 2>/dev/null
  [[ -n "$dns_pid" ]] && kill "$dns_pid" 2>/dev/null
  wait "$client_pid" "$server_pid" "$target_pid" "$dns_pid" 2>/dev/null
  ip netns del "$client_ns" 2>/dev/null
  ip netns del "$server_ns" 2>/dev/null
  ip netns del "$target_ns" 2>/dev/null
  rm -rf "$work_dir"
}
trap cleanup EXIT

cd "$root_dir"
CGO_ENABLED=0 go build -o "$work_dir/client" ./cmd/client
CGO_ENABLED=0 go build -o "$work_dir/server" ./cmd/server

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$work_dir/server.key" \
  -out "$work_dir/server.crt" \
  -days 1 \
  -subj "/CN=192.0.2.1" \
  -addext "subjectAltName=IP:192.0.2.1" >/dev/null 2>&1

token="$(openssl rand -hex 32)"
printf '%s\n' "$token" > "$work_dir/client.token"
printf 'integration:%s\n' "$(printf '%s' "$token" | sha256sum | awk '{print $1}')" > "$work_dir/clients.tokens"
chmod 600 "$work_dir/client.token" "$work_dir/clients.tokens" "$work_dir/server.key"

ip netns add "$client_ns"
ip netns add "$server_ns"
ip netns add "$target_ns"
ip link add s5pc0 type veth peer name s5ps0
ip link set s5pc0 netns "$client_ns"
ip link set s5ps0 netns "$server_ns"
ip link add s5ps1 type veth peer name s5pt0
ip link set s5ps1 netns "$server_ns"
ip link set s5pt0 netns "$target_ns"

ip -n "$client_ns" link set lo up
ip -n "$client_ns" addr add 192.0.2.2/24 dev s5pc0
ip -n "$client_ns" link set s5pc0 mtu 1228 up
ip -n "$client_ns" route add default via 192.0.2.1

ip -n "$server_ns" link set lo up
ip -n "$server_ns" addr add 192.0.2.1/24 dev s5ps0
ip -n "$server_ns" addr add 198.51.100.1/24 dev s5ps1
ip -n "$server_ns" link set s5ps0 mtu 1228 up
ip -n "$server_ns" link set s5ps1 up

ip -n "$target_ns" link set lo up
ip -n "$target_ns" addr add 198.51.100.2/24 dev s5pt0
ip -n "$target_ns" link set s5pt0 up
ip -n "$target_ns" route add default via 198.51.100.1

ip netns exec "$server_ns" iptables -A FORWARD -i s5ps0 -o s5ps1 -j DROP

python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(bytes(range(256))*4096)' "$work_dir/payload.bin"
ip netns exec "$target_ns" python3 "$root_dir/scripts/benchmark-tunnel.py" \
  serve "$work_dir" 198.51.100.2 >"$work_dir/target.log" 2>&1 &
target_pid="$!"
ip netns exec "$target_ns" python3 -c '
import select, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.51.100.2", 53))
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("198.51.100.2", 53))
tcp.listen()
echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
echo.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER=IP_PMTUDISC_DONT
echo.bind(("198.51.100.2", 9000))
while True:
    for ready in select.select([s, echo, tcp], [], [])[0]:
        if ready is tcp:
            c, _ = tcp.accept()
            with c:
                c.settimeout(2)
                f = c.makefile("rb")
                size = struct.unpack("!H", f.read(2))[0]
                query = f.read(size)
                response = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]
                c.sendall(struct.pack("!H", len(response)) + response)
                f.close()
            continue
        query, peer = ready.recvfrom(65535)
        response = query
        if ready is s:
            response = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]
        ready.sendto(response, peer)
' >"$work_dir/dns.log" 2>&1 &
dns_pid="$!"

if ip netns exec "$client_ns" curl -fsS --connect-timeout 1 --max-time 3 \
  http://198.51.100.2:8080/ >/dev/null 2>&1; then
  echo "Direct client traffic unexpectedly reached the target." >&2
  exit 1
fi
# Snapshot only after both ends of each veth are up.
ip -n "$client_ns" route show >"$work_dir/client-routes-before"

if [[ "$transport_mode" == "proxy" ]]; then
  : "${TUNNEL_BENCH_OUTPUT:?proxy comparison requires TUNNEL_BENCH_OUTPUT}"
  ip netns exec "$server_ns" "$work_dir/server" \
    -mode proxy -local 192.0.2.1:1443 -type "$obfs_mode" -passwd "$token" \
    >"$work_dir/server.log" 2>&1 &
  server_pid="$!"
  sleep 0.5
  ip netns exec "$client_ns" "$work_dir/client" \
    -mode proxy -local 127.0.0.1:18889 -server 192.0.2.1:1443 \
    -type "$obfs_mode" -passwd "$token" -recv socks5 \
    >"$work_dir/client.log" 2>&1 &
  client_pid="$!"
  sleep 0.5
  python3 "$root_dir/scripts/benchmark-tunnel.py" measure \
    --directory "$work_dir" --namespace "$client_ns" \
    --output "$TUNNEL_BENCH_OUTPUT" --transport socks5 --obfs "$obfs_mode" \
    --mtu 1228 --round "${TUNNEL_BENCH_ROUND:-1}" \
    --pids "$client_pid" "$server_pid" --proxy socks5h://127.0.0.1:18889
  exit
fi

start_server() {
  ip netns exec "$server_ns" "$work_dir/server" \
  -mode tunnel \
  -transport "$transport_mode" \
  -local 192.0.2.1:1443 \
  -cert "$work_dir/server.crt" \
  -key "$work_dir/server.key" \
  -token-file "$work_dir/clients.tokens" \
  -outbound-interface s5ps1 \
  -state-dir "$work_dir/server-state" \
  -mtu "$configured_mtu" \
  -obfs-allow none,simple,random >"$work_dir/server.log" 2>&1 &
  server_pid="$!"
}
start_server

sleep 1
ip netns exec "$client_ns" "$work_dir/client" \
  -mode tunnel \
  -transport "$transport_mode" \
  -server 192.0.2.1:1443 \
  -server-name 192.0.2.1 \
  -ca "$work_dir/server.crt" \
  -client-id integration \
  -token-file "$work_dir/client.token" \
  -state-dir "$work_dir/client-state" \
  -mtu "$configured_mtu" \
  -linux-dns=false \
  -dns 1.1.1.1 \
  -obfs "$obfs_mode" >"$work_dir/client.log" 2>&1 &
client_pid="$!"

connected="false"
for _ in $(seq 1 20); do
  if ip netns exec "$client_ns" curl -fsS --connect-timeout 1 --max-time 3 \
    http://198.51.100.2:8080/ >/dev/null 2>&1; then
    connected="true"
    break
  fi
  sleep 0.5
done

if [[ "$connected" != "true" ]]; then
  echo "Tunnel HTTP integration test failed." >&2
  cat "$work_dir/server.log" >&2
  cat "$work_dir/client.log" >&2
  exit 1
fi

if [[ -n "${TUNNEL_BENCH_OUTPUT:-}" ]]; then
  python3 "$root_dir/scripts/benchmark-tunnel.py" measure \
    --directory "$work_dir" --namespace "$client_ns" \
    --output "$TUNNEL_BENCH_OUTPUT" --transport "$transport_mode" \
    --obfs "$obfs_mode" --mtu "$packet_mtu" --round "${TUNNEL_BENCH_ROUND:-1}" \
    --pids "$client_pid" "$server_pid"
fi

ip netns exec "$client_ns" curl -fsS --connect-timeout 2 --max-time 20 \
  http://198.51.100.2:8080/payload.bin -o "$work_dir/received.bin"
[[ "$(sha256sum "$work_dir/payload.bin" | cut -d' ' -f1)" == \
   "$(sha256sum "$work_dir/received.bin" | cut -d' ' -f1)" ]]
ip netns exec "$client_ns" ping -n -c 3 -W 2 -M do -s "$((packet_mtu - 28))" 198.51.100.2

ip netns exec "$client_ns" python3 -c '
import socket, struct
query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(query, ("198.51.100.2", 53))
response, _ = s.recvfrom(512)
assert response[:2] == b"\x12\x34"
with socket.create_connection(("198.51.100.2", 53), timeout=2) as tcp:
    tcp.sendall(struct.pack("!H", len(query)) + query)
    with tcp.makefile("rb") as f:
        size = struct.unpack("!H", f.read(2))[0]
        response = f.read(size)
    assert response[:2] == b"\x12\x34"
print("UDP and TCP DNS passed")
s.setsockopt(socket.IPPROTO_IP, 10, 0)
for size in (1, 512, 1122, 4096):
    payload = bytes(i % 251 for i in range(size))
    s.sendto(payload, ("198.51.100.2", 9000))
    response, _ = s.recvfrom(65535)
    assert response == payload, (size, len(response))
    print("UDP echo bytes:", size)
'

kill -TERM "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
if [[ -e "$work_dir/server-state/server-network-state.json" ]]; then
  echo "Server network state was not restored on shutdown." >&2
  cat "$work_dir/server.log" >&2
  exit 1
fi
if ip netns exec "$server_ns" iptables-save | grep -q socks5proxy-tunnel; then
  echo "Server firewall rules were not restored on shutdown." >&2
  exit 1
fi
sleep 1
if ip netns exec "$client_ns" curl -fsS --connect-timeout 1 --max-time 3 \
  http://198.51.100.2:8080/ >/dev/null 2>&1; then
  echo "Client traffic leaked after the tunnel server stopped." >&2
  exit 1
fi

# Restart the same endpoint and require the existing client to reconnect
# without changing its routes or consuming packets in the old relay.
start_server
connected="false"
for _ in $(seq 1 20); do
  if ip netns exec "$client_ns" curl -fsS --connect-timeout 1 --max-time 3 \
    http://198.51.100.2:8080/ >/dev/null; then
    connected="true"
    break
  fi
  sleep 0.5
done
if [[ "$connected" != "true" ]]; then
  echo "Tunnel reconnect or payload verification failed." >&2
  cat "$work_dir/server.log" "$work_dir/client.log" >&2
  exit 1
fi
ip netns exec "$client_ns" curl -fsS --connect-timeout 2 --max-time 20 \
  http://198.51.100.2:8080/payload.bin -o "$work_dir/reconnected.bin"
[[ "$(sha256sum "$work_dir/payload.bin" | cut -d' ' -f1)" == \
   "$(sha256sum "$work_dir/reconnected.bin" | cut -d' ' -f1)" ]]

kill -INT "$client_pid"
wait "$client_pid" 2>/dev/null || true
client_pid=""
if ip -n "$client_ns" route show | grep -Eq '(^0\.0\.0\.0/1|^128\.0\.0\.0/1)'; then
  echo "Client tunnel routes were not restored on shutdown." >&2
  exit 1
fi
ip -n "$client_ns" route show >"$work_dir/client-routes-after"
if ! cmp -s "$work_dir/client-routes-before" "$work_dir/client-routes-after"; then
  echo "Client routes differ from the original snapshot after shutdown." >&2
  diff -u "$work_dir/client-routes-before" "$work_dir/client-routes-after" >&2 || true
  cat "$work_dir/client.log" >&2
  exit 1
fi

echo "Tunnel integration test passed: transport=$transport_mode obfs=$obfs_mode"
