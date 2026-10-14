"""Read-only paired resource measurements on an existing owned N1 fixture.

No new quote/payment, no mining; exact stored object reused, new process lifecycle.
"""
from common import *
from n1_runtime import N1Runtime
from client import retrieve
from tor_transport import TransportError
import argparse,time,platform,statistics,math

def main():
    p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);a=p.parse_args()
    if not a.home.is_relative_to(NATIVE/'build/privacy-network-n1'):raise ValueError('campaign fixtures only')
    r=None;metrics=[];resources=[];start=time.monotonic();report={}
    def timed(name,fn):
        t=time.perf_counter();value=fn();metrics.append(dict(operation=name,ms=(time.perf_counter()-t)*1000));return value
    try:
        for trial in range(3):
            r=timed('warm_complete_runtime',lambda:N1Runtime(a.home));timed('initial_post_readiness_request',lambda:r.transport(80,'health'))
            if trial<2:timed('shutdown',r.close)
        data=load_json(next((a.home/'onion-client').glob('*.upload')));bundle=data['bundle'];cipher=decode(data['ciphertext'])
        connections=[];local_bundle=dict(bundle,version=1,port=r.local.config['ports'][0]);local_bundle.pop('transport')
        for trial in range(10):
            for mode in (['local','tor'] if trial%2==0 else ['tor','local']):
                if mode=='tor':timed('tor_health',lambda:r.transport(80,'health'));connections.append(r.transport.last_timing)
                else:timed('local_health',lambda:call(r.local.config['ports'][0],'health'))
                if mode=='tor':plain=timed('tor_download_decrypt',lambda:retrieve(bundle,r.transport))
                else:
                    plain=timed('local_download_decrypt',lambda:retrieve(local_bundle))
                assert digest(plain)==bundle['plain_hash']
            timed('decrypt_only',lambda:crypt(cipher,bytes.fromhex(bundle['key']),aad(bundle['provider'],bundle['quote']),True))
        for name,process in [('node',r.local.node.p),('provider',r.local.children[0]),('bridge',r.bridge)]+[(n.config.parent.name,n.process) for n in r.tor.nodes]:
            raw=Path(f'/proc/{process.pid}/status').read_text();stat=Path(f'/proc/{process.pid}/stat').read_text().split();resources.append(dict(process=name,rss_kib=next(int(x.split()[1]) for x in raw.splitlines() if x.startswith('VmRSS:')),cpu_seconds=(int(stat[13])+int(stat[14]))/os.sysconf('SC_CLK_TCK')))
        report.update(result='PASS_READONLY_PERFORMANCE',connections=connections,object_bytes=len(cipher),plaintext_bytes=bundle['plain_bytes'],database_bytes=(r.local.base/'provider-0/state.sqlite').stat().st_size)
    except Exception as error:
        report.update(result='INCOMPLETE_WITH_BLOCKERS',failure_type=type(error).__name__,failure_code=error.code if isinstance(error,TransportError) else 'PRIVATE_DIAGNOSTIC_REQUIRED')
    finally:
        if r:r.close()
        report.update(metrics=metrics,resources=resources,seconds=time.monotonic()-start,private_fixture=str(a.home),platform=platform.platform(),cpu=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),scope='Private loopback actual Tor network only; sequential warm paired trials, no quote/payment/mining, no Internet-performance claim; explicit in-memory benchmark V1 direct bundle to SAME owned provider, both retrieval paths health-pin and decrypt, never a production V2 fallback')
        out=ROOT/'docs/evidence/privacy-network-n1'/('performance-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(report)+b'\n');print(report['result'],out.name)
    if report['result']!='PASS_READONLY_PERFORMANCE':sys.exit(1)
if __name__=='__main__':main()
