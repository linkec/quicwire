#!/usr/bin/env python3
"""隔离 namespace 中验证手动主备、真实主路黑洞、接管开关及 TTL。"""
import json
import pathlib
import subprocess
import sys
import time

binary, server_ns, client_ns, directory = sys.argv[1:]
work = pathlib.Path(directory)
base = (work / 'client.toml').read_text().replace('standby_rotate_secs = 5', 'standby_rotate_secs = 60')
processes, logs = [], []


def run(ns, args, check=True):
    return subprocess.run(['ip', 'netns', 'exec', ns, *args], text=True,
                          capture_output=True, check=check, timeout=15)


def status(side='client'):
    return json.loads(run(client_ns if side == 'client' else server_ns,
                         [binary, 'status', '--config', str(work / (side + '.toml')), '--json']).stdout)


def wait(predicate, seconds=25):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            last = status()
            if predicate(last):
                return last
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(.1)
    raise AssertionError(last)


def start(side):
    log = open(work / (side + '.log'), 'a')
    logs.append(log)
    process = subprocess.Popen(['ip', 'netns', 'exec', client_ns if side == 'client' else server_ns,
                                binary, 'run', '--config', str(work / (side + '.toml'))], stdout=log, stderr=log)
    processes.append(process)
    return process


def ping():
    for ns, target in [(client_ns, '10.77.0.1'), (server_ns, '10.77.0.2')]:
        result = run(ns, ['ping', '-n', '-c', '20', '-i', '.02', '-W', '1', target])
        assert ' 0% packet loss' in result.stdout and 'DUP!' not in result.stdout, result.stdout


def synchronized(s):
    remote = status('server')
    return s['fec_primary'] is not None and s['fec_primary'] == remote['fec_primary'] and remote['active'] == s['active']


rule = ['-p', 'udp', '-d', '192.0.2.1', '--dport', '4433:4434', '-j', 'DROP']
blocked = False
try:
    start('server')
    for failover in [False, True]:
        (work / 'client.toml').write_text(base + f'\nfec_backup_failover = {str(failover).lower()}\n'
                                        'stable_session_ttl_secs = 5\nreserve_sessions = 2\n'
                                        'switch_threshold_percent = 99\nttl_max_degradation_percent = 1000\n')
        client = start('client')
        initial = wait(lambda s: s['active'] == 2 and s['healthy'] == 4 and synchronized(s))
        ping()
        current = status()
        for p in current['paths']:
            if p['endpoint_backup']:
                assert p['tx_copies'] == 0, p
            else:
                assert p['fec_tx_packets'] == 0, p
        # 黑洞只作用于本脚本的隔离 namespace，不影响任何宿主隧道。
        run(client_ns, ['iptables', '-I', 'OUTPUT', *rule])
        blocked = True
        if failover:
            wait(lambda s: s['fec_failover_active'] and s['active'] == 2 and synchronized(s))
            ping()
        else:
            wait(lambda s: s['active'] == 0 and status('server')['active'] == 0)
            result = run(client_ns, ['ping', '-c', '2', '-W', '1', '10.77.0.1'], check=False)
            assert result.returncode != 0 and ' 100% packet loss' in result.stdout, result.stdout
            assert all(p['tx_copies'] == 0 for p in status()['paths'] if p['endpoint_backup'])
        run(client_ns, ['iptables', '-D', 'OUTPUT', *rule])
        blocked = False
        wait(lambda s: s['active'] == 2 and not s['fec_failover_active'] and s['healthy'] == 4 and synchronized(s))
        ping()
        before_ttl = status()['ttl_rotations']
        rotated = wait(lambda s: s['ttl_rotations'] > before_ttl and s['active'] == 2 and s['healthy'] == 4 and synchronized(s))
        assert all(p['endpoint_backup'] == (int(p['remote'].rsplit(':', 1)[1]) >= 4435) for p in rotated['paths'])
        ping()
        print(f'FEC 主备：failover={failover}，双向分工、主路黑洞、恢复回切、TTL 角色保持通过', flush=True)
        client.terminate()
        client.wait(timeout=8)
        processes.remove(client)
finally:
    if blocked:
        run(client_ns, ['iptables', '-D', 'OUTPUT', *rule], check=False)
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=8)
    for log in logs:
        log.close()
