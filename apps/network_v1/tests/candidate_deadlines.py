"""Actual native stalled-frame deadline and shutdown regression (local only).
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,json,socket,subprocess,time,struct,threading
from pathlib import Path
from apps.network_v1.candidate_profile import load
from apps.network_v1.candidate_rpc import Node

def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--profile',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    a.work.mkdir(mode=0o700,exist_ok=False);profile=load(a.profile);checks=[];results=[]
    for mode in ('candidate','legacy'):
        binary=a.binary if mode=='candidate' else a.binary.parent/'draft-legacy-node'
        if not binary.exists():continue
        reservations=[]
        for _ in range(3):
            s=socket.socket();s.bind(('127.0.0.1',0));reservations.append(s)
        rpc,p2p,peer=[s.getsockname()[1] for s in reservations]
        silent=reservations.pop();silent.listen();silent.settimeout(8)
        for s in reservations:s.close()
        args=[str(binary),'--data-dir',str(a.work/mode),'--rpc-port',str(rpc),'--p2p-port',str(p2p),'--peer-port',str(peer)]
        if mode=='candidate':args+=['--candidate-profile',str(a.profile)]
        streams=[]
        with (a.work/(mode+'.log')).open('x') as log:
            proc=subprocess.Popen(args,stdout=log,stderr=log)
            try:
                connection,_=silent.accept();streams.append(connection)
                connection.settimeout(3)
                def read(n):
                    data=b''
                    while len(data)<n:
                        part=connection.recv(n-len(data));assert part;data+=part
                    return data
                header=read(20);request=json.loads(read(int.from_bytes(header[16:],'big')))
                # The outbound peer reads no response. A partial RPC header also
                # holds the independent listener; neither may prevent shutdown.
                partial=socket.create_connection(('127.0.0.1',rpc),timeout=3);streams.append(partial);partial.sendall(b'P')
                partial.settimeout(7);began=time.monotonic();data=partial.recv(4096);elapsed=time.monotonic()-began
                assert elapsed<6.5 and data, (mode,elapsed)
                checks.append(mode+' incomplete frame expires within bounded deadline')
                # A legitimate connector may still be authenticating after five
                # seconds. Return a matching inventory after six seconds and
                # require this very session to receive it (not a retry).
                time.sleep(max(0,6-elapsed))
                response={k:request[k] for k in ('network','genesis','profile')};response['blocks']=[]
                raw=json.dumps(response).encode();connection.sendall(header[:16]+struct.pack('>I',len(raw))+raw)
                followup,_=silent.accept();streams.append(followup);followup.settimeout(3)
                connection=followup
                next_header=read(20);next_request=json.loads(read(int.from_bytes(next_header[16:],'big')))
                assert next_request['command']=='pool',next_request['command']
                checks.append(mode+' six-second authenticated-connector response accepted without retry')
                if mode=='candidate':assert Node(rpc,profile).rpc('status')['height']==0
                partial2=socket.create_connection(('127.0.0.1',rpc),timeout=3);streams.append(partial2);partial2.sendall(b'P')
                began=time.monotonic();proc.terminate();proc.wait(timeout=3);elapsed=time.monotonic()-began
                assert proc.returncode==0
                checks.append(mode+' graceful shutdown with silent outbound peer and incomplete inbound frame')
                results.append(dict(mode=mode,shutdown_seconds=elapsed,exit=proc.returncode))
            finally:
                if proc.poll() is None:proc.kill();proc.wait()
                for s in streams:s.close()
                silent.close()
    a.report.write_text(json.dumps(dict(result='PASS',checks=checks,runs=results,real_native=True,external_network=False),indent=2)+'\n')
if __name__=='__main__':main()
