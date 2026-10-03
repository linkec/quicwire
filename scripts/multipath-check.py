#!/usr/bin/env python3
"""仅在调用者创建的 network namespace 中验证多路径及故障注入。"""
import json, subprocess, sys, time
binary, server_ns, client_ns, work = sys.argv[1:]
def run(ns, args, check=True):
    return subprocess.run(['ip', 'netns', 'exec', ns, *args], text=True, capture_output=True, check=check, timeout=12)
def status(side):
    ns = client_ns if side == 'client' else server_ns
    return json.loads(run(ns, [binary, 'status', '--config', f'{work}/{side}.toml', '--json']).stdout)
def wait(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        s = status('client')
        assert s['connected'] <= 4, s
        if predicate(s): return s
        time.sleep(.15)
    raise AssertionError(status('client'))
def ping(count=30):
    result = run(client_ns, ['ping', '-n', '-c', str(count), '-i', '0.02', '-W', '1', '10.77.0.1'])
    assert ' 0% packet loss' in result.stdout and 'DUP!' not in result.stdout, result.stdout
    return result.stdout
initial = wait(lambda s: s['healthy'] == 4 and s['active'] == 2)
active = {p['id'] for p in initial['paths'] if p['state'] == 'active'}
standby = {p['id']: p for p in initial['paths'] if p['state'] == 'standby'}
rotated = wait(lambda s: s['rotations'] > initial['rotations'] and s['healthy'] == 4, 10)
assert active.issubset({p['id'] for p in rotated['paths']}), '激活连接不应因备用到龄被重建'
removed = [p for key,p in standby.items() if key not in {p['id'] for p in rotated['paths']}]
assert removed, (initial, rotated)
for old in removed:
    new = next(p for p in rotated['paths'] if p['remote'] == old['remote'])
    assert new['local'] != old['local'], '五元组未变化'
ping()
assert status('server')['counters']['duplicates'] > 0
assert status('client')['counters']['duplicates'] > 0
# 静默下来后，成功入队的有效包应全部写入 TUN；重复副本不能重复计有效包。
wait(lambda _: all((lambda c: c['rx_effective_packets'] == c['rx_packets'] and c['rx_packets'] > 0)(status(side)['counters']) for side in ['server', 'client']))
for side in ['server', 'client']:
    snapshot = status(side)
    assert snapshot['counters']['rx_effective_bytes'] == snapshot['counters']['rx_bytes'], snapshot
    assert sum(p['rx_effective_packets'] for p in snapshot['paths']) <= snapshot['counters']['rx_effective_packets'], snapshot
print('两端有效接收包与 TUN 交付计数一致，重复副本单独统计，通过', flush=True)

print('四条连接、双向双副本去重、备用到龄更换源端口通过', flush=True)

# 给一条仍然连通的激活路径增加延迟，验证质量改善切换而非只做故障切换。
slow=next(p for p in status('client')['paths'] if p['state']=='active')
slow_port=slow['remote'].rsplit(':',1)[1]
try:
    run(client_ns,['tc','qdisc','add','dev','outer0','root','handle','1:','prio','bands','3'])
    run(client_ns,['tc','qdisc','add','dev','outer0','parent','1:3','handle','30:','netem','delay','80ms'])
    run(client_ns,['tc','filter','add','dev','outer0','protocol','ip','parent','1:','prio','1','u32','match','ip','protocol','17','0xff','match','ip','dport',slow_port,'0xffff','flowid','1:3'])
    improved=wait(lambda s:s['active']==2 and any(p['id']==slow['id'] and p['state']=='standby' for p in s['paths']),15)
    assert improved['reason']=='备用路径质量持续改善',improved
    ping()
    print('激活路径增添 80ms 延迟后，经防抖替换为更低延迟备用路径通过',flush=True)
finally:
    run(client_ns,['tc','qdisc','del','dev','outer0','root'],False)

rules=[]
def block(port):
    rule=['-p','udp','-d','192.0.2.1','--dport',str(port),'-j','DROP']
    run(client_ns,['iptables','-I','OUTPUT',*rule]); rules.append(rule)
def clear():
    while rules: run(client_ns,['iptables','-D','OUTPUT',*rules.pop()],False)
try:
    now=status('client'); failed=next(p for p in now['paths'] if p['state']=='active')
    block(int(failed['remote'].rsplit(':',1)[1]))
    # 另一条激活路径应持续交付；不等待故障检测完毕才开始流量。
    ping(150)
    wait(lambda s:s['active']==2 and all(p['id']!=failed['id'] or p['state']!='active' for p in s['paths']))
    clear();wait(lambda s:s['healthy']==4 and s['active']==2)
    print('单激活路径黑洞期间 ping 无丢包/重复，备用自动补齐通过', flush=True)
    block('4433:4436')
    wait(lambda s:s['active']==0,10)
    clear();wait(lambda s:s['healthy']==4 and s['active']==2,20);ping()
    print('全部路径中断、降级可见与恢复通过',flush=True)
finally:
    clear()

# RTT 高于一个探测周期时，较早探测的响应仍应有效，不能被新 nonce 覆盖。
try:
    run(client_ns,['tc','qdisc','add','dev','outer0','root','netem','delay','600ms'])
    time.sleep(5)
    high=wait(lambda s:s['healthy']==4 and s['active']==2 and all(p['probe_rtt_ms']>500 for p in s['paths']),15)
    ping(10)
    print('约 600ms RTT 下多轮未决探测匹配和连通性通过',flush=True)
finally:
    run(client_ns,['tc','qdisc','del','dev','outer0','root'],False)
