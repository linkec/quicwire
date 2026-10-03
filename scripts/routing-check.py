#!/usr/bin/env python3
"""在现有隔离测试 namespace 中验证跨网段路由和真实 SNAT 回程。"""
import os
import pathlib
import subprocess
import sys
import time

server, client, work = sys.argv[1:4]
work = pathlib.Path(work)
external = 'qwr-' + str(os.getpid())
script = str(pathlib.Path(__file__).with_name('payload-check.py'))
process = None
created = False

def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout

def ns(name, *args):
    return run('ip', 'netns', 'exec', name, *args)

def payload(expected):
    global process
    ready = work / 'routing-ready'
    ready.unlink(missing_ok=True)
    process = subprocess.Popen(['ip', 'netns', 'exec', external, 'env',
        'QUICWIRE_TEST_EXPECT_PEER=' + expected, 'python3', script,
        'server', '198.18.0.2', str(ready)])
    for _ in range(100):
        if ready.exists(): break
        if process.poll() is not None: raise RuntimeError('路由测试服务提前退出')
        time.sleep(.05)
    if not ready.exists(): raise RuntimeError('路由测试服务未就绪')
    print(ns(client, 'python3', script, 'client', '198.18.0.2', '10.88.0.2'), end='')
    assert process.wait(timeout=20) == 0
    process = None

try:
    run('ip', 'netns', 'add', external)
    created = True
    run('ip', '-n', server, 'link', 'add', 'routed0', 'type', 'veth', 'peer', 'name', 'internet0', 'netns', external)
    run('ip', '-n', server, 'address', 'add', '198.18.0.1/30', 'dev', 'routed0')
    run('ip', '-n', external, 'address', 'add', '198.18.0.2/30', 'dev', 'internet0')
    for name, device in [(server, 'routed0'), (external, 'internet0'), (external, 'lo')]:
        run('ip', '-n', name, 'link', 'set', device, 'up')
    run('ip', '-n', client, 'address', 'add', '10.88.0.2/32', 'dev', 'lo')
    run('ip', '-n', client, 'route', 'add', '198.18.0.0/30', 'via', '10.77.0.1', 'dev', 'qw0')
    run('ip', '-n', server, 'route', 'add', '10.88.0.2/32', 'via', '10.77.0.2', 'dev', 'qw0')
    run('ip', '-n', external, 'route', 'add', '10.88.0.2/32', 'via', '198.18.0.1')
    ns(server, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
    print(ns(client, 'ping', '-c', '3', '-W', '2', '-I', '10.88.0.2', '198.18.0.2'), end='')
    print(ns(external, 'ping', '-c', '3', '-W', '2', '10.88.0.2'), end='')
    payload('10.88.0.2')
    # 删除互联网端到私网的回程路由，随后只能经连接跟踪反向 SNAT 返回。
    run('ip', '-n', external, 'route', 'del', '10.88.0.2/32', 'via', '198.18.0.1')
    ns(server, 'iptables', '-t', 'nat', '-A', 'POSTROUTING', '-s', '10.88.0.2/32',
       '-o', 'routed0', '-j', 'MASQUERADE')
    print(ns(client, 'ping', '-c', '3', '-W', '2', '-I', '10.88.0.2', '198.18.0.2'), end='')
    payload('198.18.0.1')
    print('跨网段双向 ICMP、TCP/UDP 内容、分片及真实 NAT 回程验证通过')
finally:
    if process is not None:
        process.terminate()
        process.wait(timeout=5)
    if created:
        subprocess.run(['ip', 'netns', 'del', external], check=False)
    for name, args in [
        (client, ['address', 'del', '10.88.0.2/32', 'dev', 'lo']),
        (client, ['route', 'del', '198.18.0.0/30']),
        (server, ['route', 'del', '10.88.0.2/32']),
    ]:
        subprocess.run(['ip', '-n', name, *args], check=False, capture_output=True)
    subprocess.run(['ip', 'netns', 'exec', server, 'iptables', '-t', 'nat', '-D', 'POSTROUTING',
        '-s', '10.88.0.2/32', '-o', 'routed0', '-j', 'MASQUERADE'], check=False, capture_output=True)
