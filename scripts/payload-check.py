#!/usr/bin/env python3
"""在独立网络 namespace 中校验 TCP 大写入和 UDP 分片的数据完整性。"""
import pathlib
import os
import socket
import sys

role, address = sys.argv[1:3]
port = 39271
block = bytes(range(256)) * 256
sizes = [1, 19, 511, 1000, 1072, 3000, 8000]

def exact(sock, length):
    out = bytearray()
    while len(out) < length:
        data = sock.recv(length - len(out))
        if not data:
            raise RuntimeError("TCP 提前断开")
        out.extend(data)
    return bytes(out)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    tcp.settimeout(15)
    udp.settimeout(15)
    # IP_PMTUDISC_DONT：显式覆盖 MTU 以上 UDP payload 的 IPv4 分片路径。
    udp.setsockopt(socket.IPPROTO_IP, 10, 0)
    if role == 'server':
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((address, port))
        tcp.listen(1)
        udp.bind((address, port))
        pathlib.Path(sys.argv[3]).write_text("ready")
        with tcp.accept()[0] as conn:
            expected = os.environ.get('QUICWIRE_TEST_EXPECT_PEER')
            if expected:
                assert conn.getpeername()[0] == expected, 'TCP 路由或 NAT 源地址不符'
            conn.settimeout(15)
            for _ in range(64):
                data = exact(conn, len(block))
                assert data == block, 'TCP 接收内容损坏'
                conn.sendall(data)
        for size in sizes:
            data, peer = udp.recvfrom(65535)
            if expected:
                assert peer[0] == expected, 'UDP 路由或 NAT 源地址不符'
            assert data == (block[:size]), 'UDP 接收内容损坏'
            udp.sendto(data, peer)
    else:
        if len(sys.argv) > 3:
            tcp.bind((sys.argv[3], 0))
            udp.bind((sys.argv[3], 0))
        tcp.connect((address, port))
        for _ in range(64):
            tcp.sendall(block)
            assert exact(tcp, len(block)) == block, 'TCP 回传内容损坏'
        for size in sizes:
            udp.sendto(block[:size], (address, port))
            assert udp.recvfrom(65535)[0] == block[:size], 'UDP 回传内容损坏'
        print('TCP 4 MiB 双向内容及 UDP MTU 内／IPv4 分片回传校验通过')
