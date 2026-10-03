#!/usr/bin/env python3
"""仅在 linux-smoke 创建的独立命名空间中注入随机丢包，验证双向恢复与内容。"""
import json, pathlib, subprocess, sys, time
binary, server, client, work = sys.argv[1:]
def run(ns, args):
    return subprocess.check_output(['ip','netns','exec',ns]+args,text=True)
def status(ns, side):
    return json.loads(run(ns,[binary,'status','--config',work+'/'+side+'.toml','--json']))
receiver = r'''
import socket,struct,hashlib,json,sys,pathlib
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((sys.argv[1],19566));s.settimeout(3)
pathlib.Path(sys.argv[2]).touch();seen=set();invalid=0
while True:
 try: p,_=s.recvfrom(2048)
 except socket.timeout: break
 if len(p)!=516: invalid+=1;continue
 seq=struct.unpack('!I',p[:4])[0]
 if seq>=1000 or p[4:]!=hashlib.sha256(p[:4]).digest()*16:invalid+=1
 seen.add(seq)
print(json.dumps(dict(received=len(seen),invalid=invalid)))
'''
sender = r'''
import socket,struct,hashlib,time,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for seq in range(1000):
 p=struct.pack('!I',seq);s.sendto(p+hashlib.sha256(p).digest()*16,(sys.argv[1],19566));time.sleep(.001)
'''
for ns in (server,client):
    run(ns,['tc','qdisc','add','dev','outer0','root','netem','loss','8%'])
try:
    for src,dst,side,address in [(client,server,'server','10.77.0.1'),(server,client,'client','10.77.0.2')]:
        before=status(dst,side)['counters']['fec_recovered_packets']
        ready=pathlib.Path(work)/('fec-ready-'+side)
        proc=subprocess.Popen(['ip','netns','exec',dst,'python3','-c',receiver,address,str(ready)],stdout=subprocess.PIPE,text=True)
        try:
            for _ in range(100):
                if ready.exists():break
                if proc.poll() is not None:raise RuntimeError('FEC 接收进程退出')
                time.sleep(.02)
            assert ready.exists(),'FEC 接收进程未就绪'
            run(src,['python3','-c',sender,address])
            out,_=proc.communicate(timeout=10);result=json.loads(out)
            recovered=status(dst,side)['counters']['fec_recovered_packets']-before
            assert proc.returncode==0 and result['invalid']==0 and result['received']>750 and recovered>0,(result,recovered)
            print(json.dumps(dict(direction=side,injected_loss=.08,fec_recovered=recovered,**result)),flush=True)
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
finally:
    for ns in (server,client):run(ns,['tc','qdisc','del','dev','outer0','root'])
