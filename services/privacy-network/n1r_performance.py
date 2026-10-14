"""Matched repeated reads; every failed operation is retained with duration."""
from common import *
from n1_runtime import N1Runtime
from n1_diagnostics import Diagnostics
from tor_transport import TransportError
from client import retrieve
import argparse,time
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'
def main():
    c.harden();p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);a=p.parse_args();assert a.home.is_relative_to(NATIVE/'build/privacy-network-n1-repair')
    r=None;metrics=[];connections=[];start=time.monotonic();report={};trace=Diagnostics(a.home/('performance-trace-'+str(time.time_ns())))
    def timed(name,fn):
        t=time.monotonic()
        try:value=fn();metrics.append(dict(operation=name,result='PASS',ms=(time.monotonic()-t)*1000));return value
        except Exception as error:
            metrics.append(dict(operation=name,result='FAIL',ms=(time.monotonic()-t)*1000,error_type=type(error).__name__,code=error.code if isinstance(error,TransportError) else 'PRIVATE_DIAGNOSTIC'));raise
    try:
        for trial in range(3):
            r=timed('warm_complete_runtime',lambda:N1Runtime(a.home,diagnostics=trace));timed('initial_post_readiness_request',lambda:r.transport(80,'health'))
            if trial<2:timed('shutdown',r.close)
        data=load_json(next((a.home/'onion-client').glob('*.upload')));bundle=data['bundle'];cipher=decode(data['ciphertext'])
        local=dict(bundle,version=1,port=r.local.config['ports'][0]);local.pop('transport')
        for trial in range(20):
            for mode in (['local','tor'] if trial%2==0 else ['tor','local']):
                if mode=='tor':timed('tor_health',lambda:r.transport(80,'health'));connections.append(r.transport.last_timing)
                else:timed('local_health',lambda:call(r.local.config['ports'][0],'health'))
                plain=timed(mode+'_download_decrypt',lambda:retrieve(bundle,r.transport) if mode=='tor' else retrieve(local))
                assert digest(plain)==bundle['plain_hash']
            timed('decrypt_only',lambda:crypt(cipher,bytes.fromhex(bundle['key']),aad(bundle['provider'],bundle['quote']),True))
        report['result']='PASS'
    except Exception as error:report.update(result='FAIL',error_type=type(error).__name__)
    finally:
        if r:r.close()
        report.update(metrics=metrics,connections=connections,seconds=time.monotonic()-start,private_fixture=str(a.home),scope='Same provider and existing object, paired health-pinned decrypting retrieval; explicit in-memory V1 direct control only, never production fallback; all failures retained')
        out=OUT/('performance-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(report)+b'\n');print(report['result'],out.name,flush=True)
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
