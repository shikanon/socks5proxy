#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(id -u)" -ne 0 ]]; then
  echo "This integration test requires Linux root privileges." >&2
  exit 77
fi

for command in go ip iptables openssl python3 curl; do
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
  [[ -n "$client_pid" ]] && kill -INT "$client_pid" 2>/dev/null
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
ip -n "$client_ns" link set s5pc0 up
ip -n "$client_ns" route add default via 192.0.2.1

ip -n "$server_ns" link set lo up
ip -n "$server_ns" addr add 192.0.2.1/24 dev s5ps0
ip -n "$server_ns" addr add 198.51.100.1/24 dev s5ps1
ip -n "$server_ns" link set s5ps0 up
ip -n "$server_ns" link set s5ps1 up

ip -n "$target_ns" link set lo up
ip -n "$target_ns" addr add 198.51.100.2/24 dev s5pt0
ip -n "$target_ns" link set s5pt0 up
ip -n "$target_ns" route add default via 198.51.100.1

ip netns exec "$server_ns" iptables -A FORWARD -i s5ps0 -o s5ps1 -j DROP

ip netns exec "$target_ns" python3 -m http.server 8080 \
  --bind 198.51.100.2 >"$work_dir/target.log" 2>&1 &
target_pid="$!"
ip netns exec "$target_ns" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.51.100.2", 53))
while True:
    query, peer = s.recvfrom(512)
    response = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]
    s.sendto(response, peer)
' >"$work_dir/dns.log" 2>&1 &
dns_pid="$!"

if ip netns exec "$client_ns" curl -fsS --connect-timeout 1 \
  http://198.51.100.2:8080/ >/dev/null 2>&1; then
  echo "Direct client traffic unexpectedly reached the target." >&2
  exit 1
fi

ip netns exec "$server_ns" "$work_dir/server" \
  -mode tunnel \
  -local 192.0.2.1:1443 \
  -cert "$work_dir/server.crt" \
  -key "$work_dir/server.key" \
  -token-file "$work_dir/clients.tokens" \
  -outbound-interface s5ps1 \
  -state-dir "$work_dir/server-state" \
  -obfs-allow none,simple,random >"$work_dir/server.log" 2>&1 &
server_pid="$!"

sleep 1
ip netns exec "$client_ns" "$work_dir/client" \
  -mode tunnel \
  -server 192.0.2.1:1443 \
  -server-name 192.0.2.1 \
  -ca "$work_dir/server.crt" \
  -client-id integration \
  -token-file "$work_dir/client.token" \
  -state-dir "$work_dir/client-state" \
  -dns 1.1.1.1 \
  -obfs random >"$work_dir/client.log" 2>&1 &
client_pid="$!"

connected="false"
for _ in $(seq 1 20); do
  if ip netns exec "$client_ns" curl -fsS --connect-timeout 1 \
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

ip netns exec "$client_ns" python3 -c '
import socket
query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(query, ("198.51.100.2", 53))
response, _ = s.recvfrom(512)
assert response[:2] == b"\x12\x34"
'

kill -TERM "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
sleep 1
if ip netns exec "$client_ns" curl -fsS --connect-timeout 1 \
  http://198.51.100.2:8080/ >/dev/null 2>&1; then
  echo "Client traffic leaked after the tunnel server stopped." >&2
  exit 1
fi

kill -INT "$client_pid"
wait "$client_pid" 2>/dev/null || true
client_pid=""
if ip -n "$client_ns" route show | grep -Eq '(^0\.0\.0\.0/1|^128\.0\.0\.0/1)'; then
  echo "Client tunnel routes were not restored on shutdown." >&2
  exit 1
fi

echo "Tunnel integration test passed."
