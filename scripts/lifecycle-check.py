#!/usr/bin/env python3
"""仅在 smoke 脚本创建的隔离命名空间中验证评分和 TTL 生命周期。"""
import json
import pathlib
import subprocess
import sys
import time

binary, server_ns, client_ns, directory = sys.argv[1:]
work = pathlib.Path(directory)
client_base = (work / 'client.toml').read_text().replace(
    'endpoint = "192.0.2.1:4433"', 'endpoints = ["192.0.2.1:4433-4434"]')
server_config = (work / 'server.toml').read_text().replace(
    'bind = "192.0.2.1:4433"', 'listen = ["192.0.2.1:4433-4434"]')
(work / 'server.toml').write_text(server_config)
processes = []
logs = []


def run(ns, args, timeout=30):
    return subprocess.run(['ip', 'netns', 'exec', ns, *args], text=True,
                          capture_output=True, check=True, timeout=timeout).stdout


def status(side='client'):
    ns = client_ns if side == 'client' else server_ns
    return json.loads(run(ns, [binary, 'status', '--config',
                              str(work / (side + '.toml')), '--json']))


def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            last = status()
            if predicate(last):
                return last
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(.1)
    raise AssertionError(last)


def start(ns, side):
    log = open(work / (side + '.log'), 'a')
    logs.append(log)
    p = subprocess.Popen(['ip', 'netns', 'exec', ns, binary, 'run', '--config',
                          str(work / (side + '.toml'))], stdout=log, stderr=log)
    processes.append(p)
    return p


def stop(p):
    p.terminate()
    p.wait(timeout=8)
    processes.remove(p)


def client(threshold, ttl=0, degradation=10, standby=0):
    (work / 'client.toml').write_text(client_base + f'''
max_sessions = 2
active_sessions = 1
reserve_sessions = 1
switch_threshold_percent = {threshold}
stable_session_ttl_secs = {ttl}
ttl_degradation_percent = {degradation}
standby_rotate_secs = {standby}
''')
    p = start(client_ns, 'client')
    initial = wait(lambda s: s['healthy'] == 2 and s['active'] == 1, 20)
    active = next(path for path in initial['paths'] if path['state'] == 'active')
    assert active['slot'] == 0 and active['remote'].endswith(':4433'), initial
    # 客户端选定后控制消息仍在途；等对端确认同一条路径，才统计切换期丢包。
    wait(lambda _: any(path['id'] == active['id'] and path['state'] == 'active'
                       for path in status('server')['paths']))
    return p, initial, active


def ping_async(count):
    return subprocess.Popen(['ip', 'netns', 'exec', client_ns, 'ping', '-n', '-c',
                             str(count), '-i', '.05', '-W', '2', '10.77.0.1'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def finish_ping(p):
    out, err = p.communicate(timeout=25)
    assert p.returncode == 0 and ' 0% packet loss' in out and 'DUP!' not in out, (out, err)
    print(out.split('---')[-1], flush=True)


try:
    # 第一配置槽位 110ms，其余 100ms。第一条完成握手通常更晚，仍必须先激活。
    run(client_ns, ['tc', 'qdisc', 'add', 'dev', 'outer0', 'root', 'handle', '1:',
                   'prio', 'bands', '3', 'priomap', *(['0'] * 16)])
    run(client_ns, ['tc', 'qdisc', 'add', 'dev', 'outer0', 'parent', '1:1',
                   'handle', '10:', 'netem', 'delay', '100ms'])
    run(client_ns, ['tc', 'qdisc', 'add', 'dev', 'outer0', 'parent', '1:3',
                   'handle', '30:', 'netem', 'delay', '110ms'])
    run(client_ns, ['tc', 'filter', 'add', 'dev', 'outer0', 'protocol', 'ip',
                   'parent', '1:', 'prio', '1', 'u32', 'match', 'ip', 'protocol',
                   '17', '0xff', 'match', 'ip', 'dport', '4433', '0xffff', 'flowid', '1:3'])
    start(server_ns, 'server')
    p, initial, active = client(20)
    time.sleep(10)
    assert next(x for x in status()['paths'] if x['state'] == 'active')['id'] == active['id']
    print('启动选配置第一条慢路径；20% 门槛下约 10ms 的改善不切换，通过', flush=True)
    stop(p)

    p, initial, active = client(5)
    ping = ping_async(260)
    improved = wait(lambda s: any(x['slot'] == 1 and x['state'] == 'active'
                                 for x in s['paths']))
    assert improved['reason'] == '备用路径质量持续改善', improved
    finish_ping(ping)
    print('5% 评分阈值经观察后切到较快路径，期间业务无丢包/重复，通过', flush=True)
    stop(p)

    p, initial, active = client(99, ttl=5, degradation=50, standby=5)
    reserve = next(x for x in initial['paths'] if x['reserved'])
    ping = ping_async(320)
    time.sleep(7)
    deferred = status()
    assert deferred['ttl_rotations'] == 0, deferred
    assert '未达门槛' in deferred['ttl_waiting_reason'], deferred
    assert any(x['id'] == reserve['id'] and x['reserved'] for x in deferred['paths']), deferred
    print('TTL 到期且劣化不足时延期；快速备用跨越普通轮转期仍预留，通过', flush=True)
    run(client_ns, ['tc', 'qdisc', 'change', 'dev', 'outer0', 'parent', '1:3',
                   'handle', '30:', 'netem', 'delay', '180ms'])
    rotated = wait(lambda s: s['ttl_rotations'] >= 1 and s['healthy'] == 2
                   and all(x['id'] != active['id'] for x in s['paths']), 20)
    new = next(x for x in rotated['paths'] if x['slot'] == 0)
    assert new['local'] != active['local'], rotated
    assert next(x for x in rotated['paths'] if x['state'] == 'active')['id'] == reserve['id']
    finish_ping(ping)
    print('TTL 劣化达标后备用接替，确认后更换旧会话源端口，业务无丢包/重复，通过', flush=True)
finally:
    for p in reversed(processes):
        p.terminate()
        try:
            p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    for log in logs:
        log.close()
