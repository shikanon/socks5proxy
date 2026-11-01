#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(id -u)" -ne 0 ]]; then
  echo "This integration test requires Linux root privileges." >&2
  exit 77
fi

for command in go ip iptables iptables-save sysctl realpath openssl python3 curl ping sha256sum; do
  command -v "$command" >/dev/null || {
    echo "Missing required command: $command" >&2
    exit 77
  }
done

if [[ ! -c /dev/net/tun ]]; then
  echo "/dev/net/tun is unavailable." >&2
  exit 77
fi

root_dir="$(dirname "$(dirname "$(realpath "${BASH_SOURCE[0]}")")")"
transport_mode="${TUNNEL_TRANSPORT:-quic}"
ipv6="${TUNNEL_IPV6:-false}"
endpoint_ipv6="${TUNNEL_ENDPOINT_IPV6:-false}"
watchdog="${TUNNEL_WATCHDOG:-false}"
watchdog_args=(-disconnect-policy block)
if [[ "$watchdog" == "true" ]]; then
  [[ "$transport_mode" != "proxy" ]] || { echo "Watchdog acceptance requires tunnel mode." >&2; exit 1; }
  watchdog_args=(-disconnect-policy direct -fallback-timeout 3s -health-interval 500ms -reconnect-interval 500ms -daemon)
elif [[ "$watchdog" != "false" ]]; then
  echo "TUNNEL_WATCHDOG must be true or false." >&2
  exit 1
fi
ipv6_args=()
endpoint="192.0.2.1:1443"
server_name="192.0.2.1"
physical_mtu=1228
if [[ "$ipv6" == "true" ]]; then
  for command in ip6tables ip6tables-save; do
    command -v "$command" >/dev/null || exit 77
  done
  ipv6_args=(-ipv6 -dns6 2001:db8:2::2)
  physical_mtu=1280
elif [[ "$ipv6" != "false" ]]; then
  echo "TUNNEL_IPV6 must be true or false." >&2
  exit 1
fi
if [[ "$endpoint_ipv6" == "true" ]]; then
  [[ "$ipv6" == "true" ]] || { echo "IPv6 endpoint test requires TUNNEL_IPV6=true." >&2; exit 1; }
  endpoint="[2001:db8:1::1]:1443"
  server_name="2001:db8:1::1"
elif [[ "$endpoint_ipv6" != "false" ]]; then
  echo "TUNNEL_ENDPOINT_IPV6 must be true or false." >&2
  exit 1
fi
[[ "$ipv6" == "true" && "$transport_mode" == "proxy" ]] && {
  echo "IPv6 acceptance requires a tunnel transport." >&2
  exit 1
}
obfs_mode="${TUNNEL_OBFS:-random}"
if [[ "$transport_mode" == "tcp-table" ]]; then
  obfs_mode="${TUNNEL_OBFS:-none}"
fi
configured_mtu="${TUNNEL_TEST_MTU:-1280}"
packet_mtu="$configured_mtu"
[[ "$transport_mode" == "quic" && "$ipv6" == "false" ]] && packet_mtu=1150
work_dir="$(mktemp -d)"
suffix="$$"
client_ns="s5pc-${suffix}"
server_ns="s5ps-${suffix}"
target_ns="s5pt-${suffix}"
client_pid=""
server_pid=""
target_pid=""
dns_pid=""
ipv6_pid=""

cleanup() {
  local status="$?"
  set +e
  if [[ "$status" -ne 0 ]]; then
    for log in server client ipv6-target; do
      [[ -f "$work_dir/$log.log" ]] && cat "$work_dir/$log.log" >&2
    done
  fi
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
  [[ -n "$ipv6_pid" ]] && kill "$ipv6_pid" 2>/dev/null
  wait "$client_pid" "$server_pid" "$target_pid" "$dns_pid" "$ipv6_pid" 2>/dev/null
  ip netns del "$client_ns" 2>/dev/null
  ip netns del "$server_ns" 2>/dev/null
  ip netns del "$target_ns" 2>/dev/null
  rm -rf "$work_dir"
}
trap cleanup EXIT

CGO_ENABLED=0 go -C "$root_dir" build -o "$work_dir/client" ./cmd/client
CGO_ENABLED=0 go -C "$root_dir" build -o "$work_dir/server" ./cmd/server

if [[ "$transport_mode" == "quic" || "$transport_mode" == "tcp" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$work_dir/server.key" \
    -out "$work_dir/server.crt" \
    -days 1 \
    -subj "/CN=192.0.2.1" \
    -addext "subjectAltName=IP:192.0.2.1,IP:2001:db8:1::1" >/dev/null 2>&1
  chmod 600 "$work_dir/server.key"
fi

token="$(openssl rand -hex 32)"
printf '%s\n' "$token" > "$work_dir/client.token"
printf 'integration:%s\n' "$(printf '%s' "$token" | sha256sum | awk '{print $1}')" > "$work_dir/clients.tokens"
chmod 600 "$work_dir/client.token" "$work_dir/clients.tokens"

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
ip -n "$client_ns" link set s5pc0 mtu "$physical_mtu" up
ip -n "$client_ns" route add default via 192.0.2.1

ip -n "$server_ns" link set lo up
ip -n "$server_ns" addr add 192.0.2.1/24 dev s5ps0
ip -n "$server_ns" addr add 198.51.100.1/24 dev s5ps1
ip -n "$server_ns" link set s5ps0 mtu "$physical_mtu" up
ip -n "$server_ns" link set s5ps1 up

ip -n "$target_ns" link set lo up
ip -n "$target_ns" addr add 198.51.100.2/24 dev s5pt0
ip -n "$target_ns" link set s5pt0 up
ip -n "$target_ns" route add default via 198.51.100.1

if [[ "$watchdog" == "true" ]]; then
  ip netns exec "$server_ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$server_ns" iptables -t nat -A POSTROUTING -s 192.0.2.0/24 -o s5ps1 -j MASQUERADE
else
  ip netns exec "$server_ns" iptables -A FORWARD -i s5ps0 -o s5ps1 -j DROP
fi
if [[ "$ipv6" == "true" ]]; then
  ip -n "$client_ns" -6 addr add 2001:db8:1::2/64 dev s5pc0 nodad
  ip -n "$server_ns" -6 addr add 2001:db8:1::1/64 dev s5ps0 nodad
  ip -n "$server_ns" -6 addr add 2001:db8:2::1/64 dev s5ps1 nodad
  ip -n "$target_ns" -6 addr add 2001:db8:2::2/64 dev s5pt0 nodad
  ip -n "$client_ns" -6 route add default via 2001:db8:1::1
  ip -n "$target_ns" -6 route add default via 2001:db8:2::1
  if [[ "$watchdog" == "true" ]]; then
    ip netns exec "$server_ns" sysctl -qw net.ipv6.conf.all.forwarding=1
  else
    ip netns exec "$server_ns" ip6tables -A FORWARD -i s5ps0 -o s5ps1 -j DROP
  fi
fi

python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(bytes(range(256))*4096)' "$work_dir/payload.bin"
ip netns exec "$target_ns" python3 "$root_dir/scripts/benchmark-tunnel.py" \
  serve "$work_dir" 198.51.100.2 >"$work_dir/target.log" 2>&1 &
target_pid="$!"
ip netns exec "$target_ns" python3 -c '
import select, socket, struct
def dns_response(query):
    answer = b"\xc0\x0c" + query[-4:] + struct.pack("!IH", 60, 4) + socket.inet_aton("198.51.100.2")
    return query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00" + query[12:] + answer
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
                response = dns_response(query)
                c.sendall(struct.pack("!H", len(response)) + response)
                f.close()
            continue
        query, peer = ready.recvfrom(65535)
        response = query
        if ready is s:
            response = dns_response(query)
        ready.sendto(response, peer)
' >"$work_dir/dns.log" 2>&1 &
dns_pid="$!"
ipv6_url="http://[2001:db8:2::2]:8080"
if [[ "$ipv6" == "true" ]]; then
  ip netns exec "$target_ns" python3 "$root_dir/scripts/test-tunnel-ipv6.py" \
    serve "$work_dir" >"$work_dir/ipv6-target.log" 2>&1 &
  ipv6_pid="$!"
  if [[ "$watchdog" == "false" ]] && ip netns exec "$client_ns" curl -g --noproxy '*' -fsS --connect-timeout 1 --max-time 3 \
    "$ipv6_url/" >/dev/null 2>&1; then
    echo "Direct IPv6 traffic unexpectedly reached the target." >&2
    exit 1
  fi
fi

if [[ "$watchdog" == "false" ]] && ip netns exec "$client_ns" curl -fsS --connect-timeout 1 --max-time 3 \
  http://198.51.100.2:8080/ >/dev/null 2>&1; then
  echo "Direct client traffic unexpectedly reached the target." >&2
  exit 1
fi
# Snapshot only after both ends of each veth are up.
ip -n "$client_ns" route show >"$work_dir/client-routes-before"
snapshot_server() {
  local label="$1"
  # -S also emits default policies for tables that have not been materialized
  # by the kernel yet; iptables-save would make a later empty NAT table differ.
  ip netns exec "$server_ns" iptables -S >"$work_dir/server-firewall-$label"
  ip netns exec "$server_ns" iptables -t nat -S >>"$work_dir/server-firewall-$label"
  ip netns exec "$server_ns" sysctl -n net.ipv4.ip_forward >"$work_dir/server-forward-$label"
  if [[ "$ipv6" == "true" ]]; then
    ip netns exec "$server_ns" ip6tables -S >"$work_dir/server-firewall6-$label"
    ip netns exec "$server_ns" ip6tables -t nat -S >>"$work_dir/server-firewall6-$label"
    ip netns exec "$server_ns" sysctl -n net.ipv6.conf.all.forwarding \
      net.ipv6.conf.s5ps1.accept_ra >"$work_dir/server-forward6-$label"
  fi
}
snapshot_server before
if [[ "$ipv6" == "true" ]]; then
  ip -n "$client_ns" -6 route show >"$work_dir/client-routes6-before"
fi

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
  -local "$endpoint" \
  -cert "$work_dir/server.crt" \
  -key "$work_dir/server.key" \
  -token-file "$work_dir/clients.tokens" \
  -table-file "$work_dir/token-table.json" \
  -table-token-length 8 \
  -client-id integration \
  -outbound-interface s5ps1 \
  -dns 198.51.100.2 \
  -state-dir "$work_dir/server-state" \
  -mtu "$configured_mtu" \
  "${ipv6_args[@]}" \
  -obfs-allow none,simple,random >"$work_dir/server.log" 2>&1 &
  server_pid="$!"
}
start_server

sleep 1
ip netns exec "$client_ns" "$work_dir/client" \
  -mode tunnel \
  -transport "$transport_mode" \
  -server "$endpoint" \
  -server-name "$server_name" \
  -ca "$work_dir/server.crt" \
  -client-id integration \
  -token-file "$work_dir/client.token" \
  -table-file "$work_dir/token-table.json" \
  -state-dir "$work_dir/client-state" \
  -mtu "$configured_mtu" \
  "${ipv6_args[@]}" \
  -linux-dns=false \
  -dns 198.51.100.2 \
  "${watchdog_args[@]}" \
  -obfs "$obfs_mode" >"$work_dir/client.log" 2>&1 &
client_pid="$!"

wait_mode() {
  python3 - "$work_dir/client-state" "$1" <<'PY'
import json, pathlib, sys, time
path = pathlib.Path(sys.argv[1]) / "client-status.json"
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    try:
        status = json.loads(path.read_text())
        if status["mode"] == sys.argv[2]:
            print("watchdog:", status)
            break
    except (OSError, ValueError):
        pass
    time.sleep(0.1)
else:
    raise SystemExit(f"watchdog did not reach {sys.argv[2]}")
PY
}
if [[ "$watchdog" == "true" ]]; then
  wait_mode tunnel
fi

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

verify_ipv6() {
  ip netns exec "$client_ns" python3 "$root_dir/scripts/test-tunnel-ipv6.py" check "$work_dir/payload.bin"
  ip netns exec "$client_ns" ping -6 -n -c 3 -W 2 -M do -s 1232 2001:db8:2::2
}
if [[ "$ipv6" == "true" ]]; then
  ip -n "$client_ns" -6 route show >"$work_dir/client-routes6-connected"
  ip -n "$client_ns" route show >"$work_dir/client-routes-connected"
  endpoint_route="$(ip -n "$client_ns" route get "$server_name")"
  [[ "$endpoint_route" == *"dev s5pc0"* ]] || {
    echo "Outer endpoint lost its physical bypass: $endpoint_route" >&2
    exit 1
  }
  verify_ipv6
fi

# Silent loss leaves the server and TCP socket alive: transport FIN detection
# cannot substitute for a verified application heartbeat.
verify_direct() {
  wait_mode direct
  [[ ! -e "$work_dir/client-state/network-state.json" ]]
  [[ "$(ip -n "$client_ns" route get 198.51.100.2)" == *"dev s5pc0"* ]]
  ip -n "$client_ns" route show >"$work_dir/client-routes-direct"
  cmp "$work_dir/client-routes-before" "$work_dir/client-routes-direct"
  ip netns exec "$client_ns" curl --noproxy '*' -fsS --max-time 5 \
    http://198.51.100.2:8080/payload.bin -o "$work_dir/direct.bin"
  cmp "$work_dir/payload.bin" "$work_dir/direct.bin"
  if [[ "$ipv6" == "true" ]]; then
    [[ "$(ip -n "$client_ns" -6 route get 2001:db8:2::2)" == *"dev s5pc0"* ]]
    ip -n "$client_ns" -6 route show >"$work_dir/client-routes6-direct"
    cmp "$work_dir/client-routes6-before" "$work_dir/client-routes6-direct"
    ip netns exec "$client_ns" curl -g --noproxy '*' -fsS --max-time 5 \
      "$ipv6_url/payload.bin" -o "$work_dir/direct6.bin"
    cmp "$work_dir/payload.bin" "$work_dir/direct6.bin"
  fi
  echo "Direct physical IPv4/IPv6 payload and route restoration verified."
}
outer_drop() {
  local action="$1" proto="tcp" firewall="iptables"
  [[ "$transport_mode" == "quic" ]] && proto="udp"
  [[ "$endpoint_ipv6" == "true" ]] && firewall="ip6tables"
  # Drop at the peer so the client's UDP send succeeds and only the watchdog
  # can detect silence; local OUTPUT DROP can report EPERM immediately.
  ip netns exec "$server_ns" "$firewall" "$action" INPUT -p "$proto" --dport 1443 -j DROP
}
if [[ "$watchdog" == "true" ]]; then
  forwarding_drop() {
    local action="$1"
    ip netns exec "$server_ns" iptables "$action" FORWARD -s 10.255.0.0/24 -j DROP
    if [[ "$ipv6" == "true" ]]; then
      ip netns exec "$server_ns" ip6tables "$action" FORWARD -s fd00:5:5::/64 -j DROP
    fi
  }
  # Outer heartbeats remain live, but the IP forwarding path is broken.
  # Insertion before the tunnel's ACCEPT rules leaves physical direct intact.
  forwarding_drop -I
  start_loss="$(date +%s)"
  verify_direct
  [[ "$(( $(date +%s) - start_loss ))" -le 8 ]]
  # Stay direct through more than one complete authentication/probe attempt.
  for _ in $(seq 1 35); do
    [[ ! -e "$work_dir/client-state/network-state.json" ]]
    [[ "$(ip -n "$client_ns" route get 198.51.100.2)" == *"dev s5pc0"* ]]
    sleep 0.2
  done
  forwarding_drop -D
  wait_mode tunnel
  ip netns exec "$client_ns" curl --noproxy '*' -fsS --max-time 5 \
    http://198.51.100.2:8080/payload.bin -o "$work_dir/after-forwarding.bin"
  cmp "$work_dir/payload.bin" "$work_dir/after-forwarding.bin"
  echo "Live heartbeat with broken forwarding, stable direct mode and recovery verified."
  outer_drop -A
  start_loss="$(date +%s)"
  verify_direct
  [[ "$(( $(date +%s) - start_loss ))" -le 8 ]]
  # Keep the outage in place while killing the worker. The independent parent
  # must restore the dead child's state before spawning a replacement.
  outer_drop -D
  wait_mode tunnel
  child_pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$work_dir/client-state/client-status.json")"
  outer_drop -A
  kill -KILL "$child_pid"
  verify_direct
  kill -0 "$client_pid"
  outer_drop -D
  wait_mode tunnel
  new_child_pid="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' "$work_dir/client-state/client-status.json")"
  [[ "$new_child_pid" != "$child_pid" ]]
  ip netns exec "$client_ns" curl --noproxy '*' -fsS --max-time 5 \
    http://198.51.100.2:8080/payload.bin -o "$work_dir/after-crash.bin"
  cmp "$work_dir/payload.bin" "$work_dir/after-crash.bin"
  echo "Silent loss, reconnection and supervised child SIGKILL verified."
fi

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
snapshot_server stopped
for state in firewall forward; do
  cmp "$work_dir/server-$state-before" "$work_dir/server-$state-stopped"
done
if [[ "$ipv6" == "true" ]]; then
  for state in firewall6 forward6; do
    cmp "$work_dir/server-$state-before" "$work_dir/server-$state-stopped"
  done
  if [[ "$watchdog" == "false" ]] && ip netns exec "$client_ns" curl -g --noproxy '*' -fsS --connect-timeout 1 --max-time 3 \
    "$ipv6_url/" >/dev/null 2>&1; then
    echo "IPv6 traffic leaked after the tunnel server stopped." >&2
    exit 1
  fi
fi
if [[ "$watchdog" == "true" ]]; then
  verify_direct
else
  sleep 1
fi
if [[ "$watchdog" == "false" ]] && ip netns exec "$client_ns" curl -fsS --connect-timeout 1 --max-time 3 \
  http://198.51.100.2:8080/ >/dev/null 2>&1; then
  echo "Client traffic leaked after the tunnel server stopped." >&2
  exit 1
fi

# Restart the same endpoint and require the existing client to reconnect
# without changing its routes or consuming packets in the old relay.
start_server
if [[ "$watchdog" == "true" ]]; then
  wait_mode tunnel
fi
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
if [[ "$ipv6" == "true" ]]; then
  verify_ipv6
  ip -n "$client_ns" -6 route show >"$work_dir/client-routes6-reconnected"
  ip -n "$client_ns" route show >"$work_dir/client-routes-reconnected"
  cmp "$work_dir/client-routes6-connected" "$work_dir/client-routes6-reconnected"
  cmp "$work_dir/client-routes-connected" "$work_dir/client-routes-reconnected"
fi

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

if [[ "$ipv6" == "true" ]]; then
  ip -n "$client_ns" -6 route show >"$work_dir/client-routes6-after"
  cmp "$work_dir/client-routes6-before" "$work_dir/client-routes6-after"
fi

echo "Tunnel integration test passed: transport=$transport_mode obfs=$obfs_mode ipv6=$ipv6 endpoint_ipv6=$endpoint_ipv6 watchdog=$watchdog"
