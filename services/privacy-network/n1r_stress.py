"""Bounded repeated retrieval and lifecycle tests on NEW N1-R fixtures only."""
from common import *
from n1_runtime import N1Runtime
from n1_diagnostics import Diagnostics,emit
from tor_transport import OnionTransport,TransportError
from client import retrieve
import argparse,time
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'

def main():
    c.harden();p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);p.add_argument('--reads',type=int,default=100);p.add_argument('--provider-restarts',type=int,default=0);p.add_argument('--tor-restarts',type=int,default=0);p.add_argument('--soak-seconds',type=int,default=0);p.add_argument('--tor-debug',action='store_true');p.add_argument('--experimental-upstream-tor',action='store_true');a=p.parse_args()
    assert a.home.is_relative_to(NATIVE/'build/privacy-network-n1-repair')
    assert 0<=a.reads<=1000 and 0<=a.provider_restarts<=20 and 0<=a.tor_restarts<=20 and 0<=a.soak_seconds<=3600
    r=None;events=[];samples=[];start=time.monotonic();report={};trace=Diagnostics(a.home/('stress-trace-'+str(time.time_ns())))
    def operation(name,fn,**fields):
        t=time.monotonic()
        try:
            value=fn();events.append(dict(operation=name,result='PASS',ms=(time.monotonic()-t)*1000,**fields))
            if name=='startup':report['startup_finished_monotonic_ns']=time.monotonic_ns()
            return value
        except Exception as error:
            event=dict(operation=name,result='FAIL',ms=(time.monotonic()-t)*1000,error_type=type(error).__name__,code=error.code if isinstance(error,TransportError) else 'PRIVATE_DIAGNOSTIC',**fields)
            if r:
                event.update(bridge_alive=r.bridge.poll() is None,provider_alive=r.local.children[0].poll() is None,tor_alive=[n.process.poll() is None for n in r.tor.nodes])
                try:event['direct_diagnostic_health']=call(r.local.config['ports'][0],'health')['devnet_only']
                except Exception:event['direct_diagnostic_health']=False
            events.append(event);raise
    def check_read():
        result=retrieve(bundle,r.transport)
        if digest(result)!=bundle['plain_hash']:raise AssertionError('integrity')
        return len(result)
    def ready():
        probe=OnionTransport(r.tor.hostname,r.transport.binding['provider'],r.tor.socks_port,timeout=2,diagnostics=trace)
        end=time.monotonic()+60;attempts=0
        while time.monotonic()<end:
            attempts+=1
            try:probe(80,'health');return
            except TransportError:time.sleep(.2)
        raise AssertionError('health-only reconnection deadline')
    def sample():
        parts=[]
        for name,process in [('node',r.local.node.p),('provider',r.local.children[0]),('bridge',r.bridge)]+[(n.config.parent.name,n.process) for n in r.tor.nodes]:
            stat=Path(f'/proc/{process.pid}/stat').read_text().split();status=Path(f'/proc/{process.pid}/status').read_text()
            parts.append(dict(role=name,pid=process.pid,rss_kib=next(int(x.split()[1]) for x in status.splitlines() if x.startswith('VmRSS:')),cpu_seconds=(int(stat[13])+int(stat[14]))/os.sysconf('SC_CLK_TCK'),fds=len(list(Path(f'/proc/{process.pid}/fd').iterdir()))))
        samples.append(dict(elapsed=time.monotonic()-start,processes=parts,fixture_bytes=sum(p.stat().st_size for p in a.home.rglob('*') if p.is_file() and not p.is_symlink())))
    try:
        r=operation('startup',lambda:N1Runtime(a.home,a.experimental_upstream_tor,diagnostics=trace));bundle=load_json(next((a.home/'onion-client').glob('*.upload')))['bundle']
        if a.tor_debug:
            for node in r.tor.nodes:
                path=node.config.parent/('debug-'+str(time.time_ns())+'.log')
                node.control('SETCONF Log="debug file '+str(path)+'"')
        r.local.session.close();sample()
        for i in range(a.reads):
            operation('read',check_read,trial=i)
            if a.tor_debug and any(p.stat().st_size>10*1024*1024 for p in (a.home/'tor').glob('*/debug-*.log')):raise AssertionError('bounded private diagnostic log limit')
            if i%25==0:sample();print('READ',i,flush=True)
        usage=call(r.local.config['ports'][0],'usage',r.client.admin)
        for i in range(a.provider_restarts):
            emit(trace,'provider_restart',attempt=i);r.local.stop_provider(0,crash=i%2==0);operation('provider_start',lambda:r.local.start_provider(0),trial=i);operation('provider_reconnect',ready,trial=i);operation('provider_recovery_read',check_read,trial=i)
            assert call(r.local.config['ports'][0],'usage',r.client.admin)['stored_bytes']==usage['stored_bytes'];print('PROVIDER',i,flush=True)
        for i in range(a.tor_restarts):
            old=[n.process.pid for n in r.tor.nodes];hostname=r.tor.hostname
            for node in reversed(r.tor.nodes):node.close()
            assert all(not Path('/proc/'+str(pid)).exists() for pid in old)
            operation('tor_restart',r.tor.start,trial=i);operation('tor_reconnect',ready,trial=i);operation('tor_recovery_read',check_read,trial=i)
            assert hostname==r.tor.hostname;print('TOR',i,flush=True)
        if a.soak_seconds:
            soak_start=time.monotonic();iteration=0
            while time.monotonic()-soak_start<a.soak_seconds:
                operation('soak_read',check_read,trial=iteration);operation('soak_health',lambda:r.transport(80,'health'),trial=iteration)
                if iteration and iteration%60==0:
                    r.stop_bridge(crash=True);r.start_bridge();operation('soak_bridge_reconnect',ready,trial=iteration)
                if iteration and iteration%120==0:
                    r.local.stop_provider(0,crash=True);r.local.start_provider(0);operation('soak_provider_reconnect',ready,trial=iteration)
                sample();iteration+=1
                if iteration%6==0:print('SOAK',round(time.monotonic()-soak_start),iteration,flush=True)
                time.sleep(min(10,max(0,a.soak_seconds-(time.monotonic()-soak_start))))
            report['soak_elapsed']=time.monotonic()-soak_start
        sample();report['result']='PASS'
    except KeyboardInterrupt:report.update(result='INTERRUPTED',error_type='KeyboardInterrupt')
    except Exception as error:report.update(result='FAIL',error_type=type(error).__name__)
    finally:
        if r:r.close()
        transport_attempts=[json.loads(line) for line in trace.path.read_bytes().splitlines() if json.loads(line)['event'] in ('request_error','connection_retry')]
        for event in transport_attempts:event['phase']='readiness' if event['monotonic_ns']<=report.get('startup_finished_monotonic_ns',0) else 'workload'
        report['transport_attempts']=transport_attempts
        report.update(events=events,samples=samples,seconds=time.monotonic()-start,private_fixture=str(a.home),requested=dict(reads=a.reads,provider_restarts=a.provider_restarts,tor_restarts=a.tor_restarts,soak_seconds=a.soak_seconds),scope='Actual isolated Tor and already paid new N1-R object, read-only no new payments/mining; direct health only for failure diagnosis, never fallback file retrieval')
        out=OUT/('stress-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(report)+b'\n');print(report['result'],out.name,flush=True)
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
