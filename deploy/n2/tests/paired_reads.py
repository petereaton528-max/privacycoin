"""Frozen-workload paired local/Tor read comparison on this task's paid fixture."""
from pathlib import Path
import json,signal,sys,time
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
from common import *
from n1_runtime import N1Runtime
from client import retrieve
def main():
    c.harden();signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    out=ROOT/'docs/evidence/privacy-network-n2';source=sorted(out.glob('integration-*.json'))[-1];home=Path(json.loads(source.read_bytes())['private_fixture'])
    assert home.is_relative_to(NATIVE/'build/privacycoin-n2-preparation')
    r=None;metrics=[];result='FAIL';start=time.monotonic()
    def timed(name,fn):
        t=time.monotonic()
        try:v=fn();metrics.append(dict(operation=name,ms=(time.monotonic()-t)*1000,result='PASS'));return v
        except Exception:metrics.append(dict(operation=name,ms=(time.monotonic()-t)*1000,result='FAIL'));raise
    try:
        for i in range(3):
            r=timed('warm_complete_runtime',lambda:N1Runtime(home));timed('initial_post_readiness_request',lambda:r.transport(80,'health'))
            if i<2:timed('shutdown',r.close)
        b=load_json(next((home/'onion-client').glob('*.upload')))['bundle'];local=dict(b,version=1,port=r.local.config['ports'][0]);local.pop('transport')
        for trial in range(20):
            for mode in (['local','tor'] if trial%2==0 else ['tor','local']):
                timed(mode+'_health',lambda:r.transport(80,'health') if mode=='tor' else call(r.local.config['ports'][0],'health'))
                plain=timed(mode+'_download_decrypt',lambda:retrieve(b,r.transport) if mode=='tor' else retrieve(local));assert digest(plain)==b['plain_hash']
        result='PASS'
    finally:
        if r:r.close()
        (out/('paired-reads-'+str(time.time_ns())+'.json')).write_text(json.dumps(dict(result=result,metrics=metrics,seconds=time.monotonic()-start,private_fixture=str(home),scope='LOCAL same paid object, three warm starts and twenty alternating matched direct/onion pairs; direct V1 only in-memory benchmark control, never fallback; no mining or new payment'),indent=2))
    if result!='PASS':sys.exit(1)
if __name__=='__main__':main()
