#!/usr/bin/env bash
# 在独立 network namespace 内验证真实 TUN，不修改宿主机路由。
set -euo pipefail
mtu="${QUICWIRE_TEST_MTU:-1100}"
[[ "$mtu" =~ ^[0-9]+$ ]] && (( mtu >= 576 && mtu <= 1100 )) || exit 1
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
binary=$(realpath "${1:-target/debug/quicwire}")
[[ $EUID -eq 0 ]] || { echo '需要 root 创建测试 network namespace' >&2; exit 1; }
work=$(mktemp -d)
server_ns="qws-$$"
client_ns="qwc-$$"
server_pid=''
client_pid=''
payload_pid=''
cleanup() {
  status=$?
  trap - EXIT
  if (( status != 0 )); then cat "$work"/*.log 2>/dev/null || true; fi
  for pid in "$payload_pid" "$client_pid" "$server_pid"; do
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
mtu = $mtu
tun_offload = ${QUICWIRE_TEST_OFFLOAD:-true}
EOF
cat > "$work/client.toml" <<EOF
mode = "client"
selection_policy = "${QUICWIRE_TEST_SELECTION_POLICY:-balanced}"
bind = "192.0.2.2:0"
endpoint = "192.0.2.1:4433"
private_key_file = "client.key"
peer_public_key = "$server_public"
tun_name = "qw0"
tun_address = "10.77.0.2/30"
peer_address = "10.77.0.1"
mtu = $mtu
tun_offload = ${QUICWIRE_TEST_OFFLOAD:-true}
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
if [[ "${QUICWIRE_TEST_MULTIPATH:-false}" == true || "${QUICWIRE_TEST_FEC:-0}" != 0 ]]; then
  sed -i 's/bind = "192.0.2.1:4433"/listen = ["192.0.2.1:4433-4436"]/' "$work/server.toml"
  sed -i 's/endpoint = "192.0.2.1:4433"/endpoints = ["192.0.2.1:4433-4436"]/' "$work/client.toml"
  cat >> "$work/client.toml" <<EOF_MP
max_sessions = 4
active_sessions = 2
standby_rotate_secs = 5
EOF_MP
fi
if [[ "${QUICWIRE_TEST_FEC:-0}" != 0 ]]; then
  sed -i 's/endpoints = \["192.0.2.1:4433-4436"\]/endpoints = [{address="192.0.2.1:4433-4434"}, {address="192.0.2.1:4435-4436", backup=true}]/' "$work/client.toml"
  echo "fec = ${QUICWIRE_TEST_FEC}" >> "$work/server.toml"
  echo "fec = ${QUICWIRE_TEST_FEC}" >> "$work/client.toml"
  echo "fec_repair_shards = ${QUICWIRE_TEST_FEC_SHARDS:-1}" >> "$work/server.toml"
  echo "fec_repair_shards = ${QUICWIRE_TEST_FEC_SHARDS:-1}" >> "$work/client.toml"
fi
if [[ "${QUICWIRE_TEST_FEC_ROLES:-false}" == true ]]; then
  python3 "$script_dir/fec-role-check.py" "$binary" "$server_ns" "$client_ns" "$work"
  exit 0
fi
if [[ "${QUICWIRE_TEST_EXCLUSIVE:-false}" == true ]]; then
  python3 "$script_dir/exclusive-check.py" "$binary" "$server_ns" "$client_ns" "$work"
  exit 0
fi
if [[ "${QUICWIRE_TEST_LIFECYCLE:-false}" == true ]]; then
  python3 "$script_dir/lifecycle-check.py" "$binary" "$server_ns" "$client_ns" "$work"
  exit 0
fi
start_server
ip netns exec "$client_ns" "$binary" run --config "$work/client.toml" > "$work/client.log" 2>&1 &
client_pid=$!
wait_connected
if [[ "${QUICWIRE_TEST_MULTIPATH:-false}" == true ]]; then
  python3 "$script_dir/multipath-check.py" "$binary" "$server_ns" "$client_ns" "$work"
fi
ip netns exec "$client_ns" ping -c 3 -W 2 -M do -s "$((mtu-28))" 10.77.0.1
ip netns exec "$server_ns" ping -c 3 -W 2 10.77.0.2
if ip netns exec "$client_ns" ping -c 1 -W 1 -M do -s "$((mtu-27))" 10.77.0.1; then
  echo '超 MTU 包意外成功' >&2; exit 1
fi
# 大 TCP 写入触发 GSO；回传检查 GRO 内容，UDP 覆盖 IPv4 分片。
for side in server client; do
  if [[ "$side" == server ]]; then
    target_ns="$server_ns"; source_ns="$client_ns"; target_ip=10.77.0.1
  else
    target_ns="$client_ns"; source_ns="$server_ns"; target_ip=10.77.0.2
  fi
  rm -f "$work/payload-ready"
  ip netns exec "$target_ns" python3 "$script_dir/payload-check.py" server "$target_ip" "$work/payload-ready" &
  payload_pid=$!
  for attempt in $(seq 1 100); do
    [[ -f "$work/payload-ready" ]] && break
    kill -0 "$payload_pid" 2>/dev/null || { echo '内容校验服务启动失败' >&2; exit 1; }
    sleep 0.05
  done
  [[ -f "$work/payload-ready" ]] || { echo '内容校验服务启动超时' >&2; exit 1; }
  ip netns exec "$source_ns" python3 "$script_dir/payload-check.py" client "$target_ip"
  wait "$payload_pid"
  payload_pid=''
done
python3 "$script_dir/routing-check.py" "$server_ns" "$client_ns" "$work"
if [[ "${QUICWIRE_TEST_FEC:-0}" != 0 ]]; then
  python3 "$script_dir/fec-check.py" "$binary" "$server_ns" "$client_ns" "$work"
fi
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=''
if ip -n "$server_ns" link show qw0; then echo '退出后 TUN 未清理' >&2; exit 1; fi
start_server
wait_connected
echo '双向 TUN、MTU 边界、退出清理及服务端重启恢复验证通过'
