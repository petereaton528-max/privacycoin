"""Bounded diagnostic on campaign-owned failed fixtures; no new payment."""
from common import *
from n1_runtime import N1Runtime
from client import retrieve
from tor_transport import TransportError
import argparse,time

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);a=p.parse_args()
    if not a.home.is_relative_to(NATIVE/'build/privacy-network-n1'):raise ValueError('campaign fixtures only')
    r=None;start=time.monotonic();events=[]
    try:
        r=N1Runtime(a.home);bundle=load_json(next((a.home/'onion-client').glob('*.upload')))['bundle']
        for i in range(60):
            if time.monotonic()-start>240:break
            try:
                raw=retrieve(bundle,r.transport);events.append(dict(trial=i,result='PASS',bytes=len(raw)));print('PASS',i,flush=True)
            except TransportError as error:events.append(dict(trial=i,result=error.state,code=error.code));print('FAIL',i,error.state,error.code,flush=True);break
    finally:
        if r:r.close()
        result='PASS_60_RECOVERIES' if len(events)==60 and all(e['result']=='PASS' for e in events) else 'INCOMPLETE_WITH_BLOCKERS'
        out=ROOT/'docs/evidence/privacy-network-n1'/('probe-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(dict(result=result,events=events,seconds=time.monotonic()-start,private_fixture=str(a.home),scope='Existing N1 campaign fixture, repeated actual Tor recovery, no payment created'))+b'\n');print(result,out.name)
    if result!='PASS_60_RECOVERIES':sys.exit(1)
