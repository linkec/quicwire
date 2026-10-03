#!/usr/bin/env python3
"""在隔离 namespace 验证互斥组约束，包括整组故障、恢复及 TTL。"""
import concurrent.futures
import json
import pathlib
import subprocess
import sys
import time

binary, server_ns, client_ns, directory = sys.argv[1:]
work = pathlib.Path(directory)
base = (work / 'client.toml').read_text().replace(
    'endpoint = "192.0.2.1:4433"',
    'endpoints = [{address="192.0.2.1:4433-4434",exclusive_group="direct"}, '
    '{address="192.0.2.1:4435-4436",exclusive_group="jp"}]')
(work / 'server.toml').write_text((work / 'server.toml').read_text().replace(
    'bind = "192.0.2.1:4433"', 'listen = ["192.0.2.1:4433-4436"]'))
processes, logs = [], []
readers = concurrent.futures.ThreadPoolExecutor(max_workers=1)


def run(ns, args, check=True):
    return subprocess.run(['ip', 'netns', 'exec', ns, *args], text=True,
                          capture_output=True, check=check, timeout=15).stdout


def status(side='client'):
    s = json.loads(run(client_ns if side == 'client' else server_ns,
                       [binary, 'status', '--config', str(work / (side + '.toml')), '--json']))
    if side == 'client':
        groups = [p['exclusive_group'] for p in s['paths'] if p['state'] == 'active']
        assert len(groups) == len(set(groups)), ('同组重复激活', s)
        assert s['connected'] <= 4, s
    return s


def wait(predicate, seconds=20):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            last = status()
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            time.sleep(.1)
            continue
        if predicate(last):
            return last
        time.sleep(.1)
    raise AssertionError(last)


def start(side):
    log = open(work / (side + '.log'), 'a')
    logs.append(log)
    p = subprocess.Popen(['ip', 'netns', 'exec', client_ns if side == 'client' else server_ns,
                          binary, 'run', '--config', str(work / (side + '.toml'))], stdout=log, stderr=log)
    processes.append(p)
    return p


def configure(ttl):
    (work / 'client.toml').write_text(base + f'''\nmax_sessions = 4
active_sessions = 2
reserve_sessions = 2
standby_rotate_secs = 5
stable_session_ttl_secs = {ttl}
switch_threshold_percent = {99.9999 if ttl else 5}
ttl_max_degradation_percent = 20
''')


def ping(count):
    out = run(client_ns, ['ping', '-n', '-c', str(count), '-i', '.02', '-W', '2', '10.77.0.1'])
    assert ' 0% packet loss' in out and 'DUP!' not in out, out


rule = ['-p', 'udp', '-d', '192.0.2.1', '--dport', '4435:4436', '-j', 'DROP']
try:
    # 同一个 IP 的两个互斥组，JP 更慢；不能把两个快直连同时激活。
    run(client_ns, ['tc', 'qdisc', 'add', 'dev', 'outer0', 'root', 'handle', '1:', 'prio', 'bands', '3', 'priomap', *(['0'] * 16)])
    run(client_ns, ['tc', 'qdisc', 'add', 'dev', 'outer0', 'parent', '1:1', 'handle', '10:', 'netem', 'delay', '10ms'])
    run(client_ns, ['tc', 'qdisc', 'add', 'dev', 'outer0', 'parent', '1:3', 'handle', '30:', 'netem', 'delay', '60ms'])
    for port in [4435, 4436]:
        run(client_ns, ['tc', 'filter', 'add', 'dev', 'outer0', 'protocol', 'ip', 'parent', '1:', 'prio', str(port), 'u32', 'match', 'ip', 'dport', str(port), '0xffff', 'flowid', '1:3'])
    configure(0)
    start('server')
    client = start('client')
    initial = wait(lambda s: s['healthy'] == 4 and s['active'] == 2)
    assert {p['slot'] for p in initial['paths'] if p['state'] == 'active'} == {0, 1}, initial
    wait(lambda s: status('server')['active'] == 2)
    ping(80)
    for _ in range(40):
        s = status()
        assert s['active'] == 2, s
        time.sleep(.1)
    print('同 IP 分组：较慢 JP 仍保留激活，两条快直连不能同时激活，通过', flush=True)
    run(client_ns, ['iptables', '-I', 'OUTPUT', *rule])
    ping(180)
    down = wait(lambda s: s['active'] == 1 and s['healthy'] == 2)
    assert down['degraded'] and '互斥组' in down['reason'], down
    wait(lambda s: status('server')['active'] == 1)
    for _ in range(30):
        assert status()['active'] == 1
        time.sleep(.1)
    run(client_ns, ['iptables', '-D', 'OUTPUT', *rule])
    wait(lambda s: s['active'] == 2 and s['healthy'] == 4)
    ping(80)
    print('整组黑洞时严格单副本、双向控制同步、业务无丢包/重复，恢复后跨组双发，通过', flush=True)
    # 改慢当前 direct，使同组备用通过质量切换替代它。
    slow = next(p for p in status()['paths'] if p['state'] == 'active' and p['exclusive_group'] == 'direct')
    port = slow['remote'].rsplit(':', 1)[1]
    run(client_ns, ['tc', 'filter', 'add', 'dev', 'outer0', 'protocol', 'ip', 'parent', '1:', 'prio', '10', 'u32', 'match', 'ip', 'dport', port, '0xffff', 'flowid', '1:3'])
    wait(lambda s: s['active'] == 2 and all(p['id'] != slow['id'] or p['state'] != 'active' for p in s['paths']))
    ping(80)
    print('质量切换只更换组内路径，保留另一组激活，通过', flush=True)
    run(client_ns, ['tc', 'filter', 'del', 'dev', 'outer0', 'parent', '1:', 'prio', '10'])
    client.terminate(); client.wait(timeout=8); processes.remove(client)
    configure(5)
    start('client')
    initial = wait(lambda s: s['healthy'] == 4 and s['active'] == 2)
    assert {p['exclusive_group'] for p in initial['paths'] if p['reserved']} == {'direct', 'jp'}, initial
    # 本轮只统计已建立隧道内的 TTL 接替；重启后的激活控制确认尚在途。
    wait(lambda s: {p['id'] for p in s['paths'] if p['state'] == 'active'} ==
         {p['id'] for p in status('server')['paths'] if p['state'] == 'active'})
    future = readers.submit(ping, 600)
    rotated = wait(lambda s: s['ttl_rotations'] >= 2 and s['healthy'] == 4, 25)
    # 继续在业务流量期间检查约束，不能只检查最终结果。
    while not future.done():
        status(); time.sleep(.1)
    future.result()
    for old in initial['paths']:
        matches = [p for p in rotated['paths'] if p['slot'] == old['slot'] and p['id'] != old['id']]
        for new in matches:
            assert new['exclusive_group'] == old['exclusive_group'] and new['local'] != old['local'], (old, new)
    print('预留覆盖不同组、TTL 接替与新五元组保持分组，600 个业务包无丢包/重复，通过', flush=True)
finally:
    for p in reversed(processes):
        if p.poll() is None:
            p.terminate()
        p.wait(timeout=8)
    readers.shutdown(wait=True)
    for log in logs:
        log.close()
