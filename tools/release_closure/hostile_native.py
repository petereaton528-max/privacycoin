"""Real native-node repeated malformed-transaction peer regression (loopback).
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,json,os,socket,subprocess,threading,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
os.umask(0o077);a.work.mkdir(mode=0o700,exist_ok=False)
from apps.network_v1.candidate_client import Client
from apps.network_v1.candidate_rpc import Node
from apps.network_v1.candidate_profile import identity
c=Client(a.work/'Fixture',a.root/'candidate-native/full',a.root)
c.create('Disposable',b'DISPOSABLE HOSTILE FIXTURE PASSWORD');profile=c.profile;c.close()
profile_path=a.work/'public-profile.json';profile_path.write_text(json.dumps(profile));network,genesis,context=identity(profile)
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(4);listener.settimeout(.2)
stop=threading.Event();counts={};errors=[]
def server():
    while not stop.is_set():
        try:s,_=listener.accept()
        except socket.timeout:continue
        except OSError:break
        try:
            with s:
                s.settimeout(2)
                def read(n):
                    data=b''
                    while len(data)<n:
                        chunk=s.recv(n-len(data))
                        if not chunk:raise EOFError()
                        data+=chunk
                    return data
                h=read(20);size=int.from_bytes(h[16:],'big');assert size<=1048576
                q=json.loads(read(size));cmd=q['command'];counts[cmd]=counts.get(cmd,0)+1
                value=dict(network=network,genesis=genesis,profile=context)
                if cmd=='inventory':value['blocks']=[]
                elif cmd=='pool':value['transactions']=['f'*64]
                elif cmd=='get_transaction':value['transaction']='00'
                else:raise AssertionError(cmd)
                raw=json.dumps(value).encode();s.sendall(h[:16]+len(raw).to_bytes(4,'big')+raw)
        except Exception as error:errors.append(type(error).__name__)
thread=threading.Thread(target=server);thread.start();rpc=port();p2p=port();proc=None;result={}
try:
    with (a.work/'native.log').open('x') as log:
        proc=subprocess.Popen([str(a.root/'candidate-native/full/draft-node'),'--candidate-profile',str(profile_path),'--data-dir',str(a.work/'Node'),'--rpc-port',str(rpc),'--p2p-port',str(p2p),'--peer-port',str(listener.getsockname()[1])],stdout=log,stderr=log)
        end=time.monotonic()+20
        while True:
            try:n=Node(rpc,profile);break
            except (ValueError,OSError):
                if time.monotonic()>end:raise TimeoutError('node startup')
                time.sleep(.05)
        end=time.monotonic()+3
        while time.monotonic()<end:time.sleep(.05)
        assert counts.get('pool',0)>=5 and counts.get('get_transaction')==1,counts
        assert n.rpc('status')['height']==0 and not n.rpc('pool')['transactions']
        # Shutdown can close the RPC stream before its acknowledgement; the
        # natural process exit is authoritative, not an assumed reply frame.
        try:n.rpc('shutdown')
        except (ValueError,OSError):pass
        proc.wait(15);assert proc.returncode==0
    assert (a.work/'native.log').read_text().count('PEER:')==1
    assert not errors,errors
    result=dict(result='PASS',pool_queries=counts['pool'],invalid_body_fetches=counts['get_transaction'],retained_pool=0,height=0,native_exit=proc.returncode,real_native=True,simulated_hostile_peer=True,external_network=False,checks=['repeated malformed transaction fetched once','native state unchanged','bounded sanitized error log','graceful owned shutdown'])
finally:
    if proc and proc.poll() is None:proc.terminate();proc.wait(15)
    stop.set();listener.close();thread.join(3)
    result['fixture_thread_closed']=not thread.is_alive();a.report.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
