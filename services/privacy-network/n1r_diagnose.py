"""Bounded fresh-fixture failure reproduction; no quote/payment/mining."""
from common import *
from n1_runtime import N1Runtime
from n1_diagnostics import Diagnostics
from tor_transport import TransportError
import time,argparse
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'

def main():
    p=argparse.ArgumentParser();p.add_argument('--experimental',action='store_true');a=p.parse_args()
    home=private_dir(NATIVE/'build/privacy-network-n1-repair'/('diagnose-'+str(time.time_ns())))
    trace=Diagnostics(home/'client-diagnostics');r=None;events=[];start=time.monotonic();result={}
    try:
        r=N1Runtime(home,a.experimental,trace)
        for i in range(200):
            if time.monotonic()-start>240:break
            before=time.monotonic()
            try:r.transport(80,'health');events.append(dict(trial=i,result='PASS',ms=(time.monotonic()-before)*1000))
            except TransportError as error:events.append(dict(trial=i,result=error.state,code=error.code,ms=(time.monotonic()-before)*1000));break
        result['result']='PASS_200_HEALTH' if len(events)==200 and all(x['result']=='PASS' for x in events) else 'REPRODUCED_FAILURE'
    except Exception as error:result.update(result='REPRODUCED_STARTUP_FAILURE',error_type=type(error).__name__)
    finally:
        if r:r.close()
        result.update(events=events,seconds=time.monotonic()-start,private_fixture=str(home),experimental=a.experimental,client_trace=[json.loads(x) for x in (home/'client-diagnostics').read_bytes().splitlines()],bridge_trace=[json.loads(x) for x in (home/'bridge-diagnostics').read_bytes().splitlines()] if (home/'bridge-diagnostics').exists() else [],scope='fresh private Tor health only, no mining/payment, traces contain no request bodies/headers/destinations')
        out=OUT/('diagnose-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(result)+b'\n');print(result['result'],len(events),out.name,flush=True)
if __name__=='__main__':main()
