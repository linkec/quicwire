#!/usr/bin/env bash
# 在独立 network namespace 内验证真实 TUN，不修改宿主机路由。
set -euo pipefail
binary=$(realpath "${1:-target/debug/quicwire}")
[[ $EUID -eq 0 ]] || { echo '需要 root 创建测试 network namespace' >&2; exit 1; }
work=$(mktemp -d)
server_ns="qws-$$"
client_ns="qwc-$$"
server_pid=''
client_pid=''
cleanup() {
  status=$?
  trap - EXIT
  if (( status != 0 )); then cat "$work"/*.log 2>/dev/null || true; fi
  for pid in "$client_pid" "$server_pid"; do
    if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  ip netns del "$client_ns" 2>/dev/null || true
  ip netns del "$server_ns" 2>/dev/null || true
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
ip netns add "$server_ns"
ip netns add "$client_ns"
ip -n "$server_ns" link add outer0 type veth peer name outer1 netns "$client_ns"
ip -n "$client_ns" link set outer1 name outer0
ip -n "$server_ns" address add 192.0.2.1/30 dev outer0
ip -n "$client_ns" address add 192.0.2.2/30 dev outer0
for ns in "$server_ns" "$client_ns"; do
  ip -n "$ns" link set lo up
  ip -n "$ns" link set outer0 up
done
server_public=$("$binary" keygen --out "$work/server.key")
client_public=$("$binary" keygen --out "$work/client.key")
cat > "$work/server.toml" <<EOF
mode = "server"
bind = "192.0.2.1:4433"
private_key_file = "server.key"
peer_public_key = "$client_public"
tun_name = "qw0"
tun_address = "10.77.0.1/30"
peer_address = "10.77.0.2"
mtu = 1100
EOF
cat > "$work/client.toml" <<EOF
mode = "client"
bind = "192.0.2.2:0"
endpoint = "192.0.2.1:4433"
private_key_file = "client.key"
peer_public_key = "$server_public"
tun_name = "qw0"
tun_address = "10.77.0.2/30"
peer_address = "10.77.0.1"
mtu = 1100
EOF
start_server() {
  ip netns exec "$server_ns" "$binary" run --config "$work/server.toml" >> "$work/server.log" 2>&1 &
  server_pid=$!
}
wait_connected() {
  for attempt in $(seq 1 30); do
    if ip netns exec "$client_ns" ping -c 1 -W 1 10.77.0.1 >/dev/null 2>&1; then return; fi
    sleep 0.2
  done
  echo '隧道未在限定时间恢复' >&2; return 1
}
start_server
ip netns exec "$client_ns" "$binary" run --config "$work/client.toml" > "$work/client.log" 2>&1 &
client_pid=$!
wait_connected
ip netns exec "$client_ns" ping -c 3 -W 2 -M do -s 1072 10.77.0.1
ip netns exec "$server_ns" ping -c 3 -W 2 10.77.0.2
if ip netns exec "$client_ns" ping -c 1 -W 1 -M do -s 1073 10.77.0.1; then
  echo '超 MTU 包意外成功' >&2; exit 1
fi
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=''
if ip -n "$server_ns" link show qw0; then echo '退出后 TUN 未清理' >&2; exit 1; fi
start_server
wait_connected
echo '双向 TUN、MTU 边界、退出清理及服务端重启恢复验证通过'
