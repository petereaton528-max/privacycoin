"""Separate Alice/Bob OS processes and actual runtime SIGKILL cleanup."""
from common import *
from runtime import Runtime
import argparse,select,subprocess,time

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--child',type=Path);args=parser.parse_args();c.harden()
    if args.child:
        r=Runtime(args.child)
        try:
            print(f.canonical(dict(ports=r.config['ports']+[r.node.rpc],children=[p.pid for p in r.children.values()]+[r.node.p.pid])).decode(),flush=True);sys.stdin.buffer.read(1)
        finally:r.close()
        return
    out=ROOT/'docs/evidence/privacy-network-v01'/('lifecycle-'+str(time.time_ns())+'.json');checks=[];r=None;worker=None;host=None;base=NATIVE/'build/privacy-network-v01'/('lifecycle-'+str(time.time_ns()));metrics={};start=time.monotonic()
    def check(name,value=True):assert value,name;checks.append(name);print('PASS',name,flush=True)
    def read(p):assert select.select([p.stdout],[],[],90)[0];return f.decode(p.stdout.readline(16385))
    def cpu(pid):
        values=Path(f'/proc/{pid}/stat').read_text().split();return sum(int(values[i]) for i in (13,14,15,16))/os.sysconf('SC_CLK_TCK')
    report={}
    try:
        r=Runtime(base);r.mine(80);plain=os.urandom(16384);source=base/'input';c.write_private(source,plain);r.session.close();bundle=base/'bob.retrieval';password=token();home=private_dir(base/'alice-process');control=load_json(base/'provider-0/control')
        config=dict(wallets=str(r.wallets),node=r.node.rpc,provider=r.config['ports'][0],client=str(home),wallet_password=r.config['password'],admin=control['admin'],source=str(source),bundle=str(bundle),bundle_password=password,consent='CONFIRM')
        worker=subprocess.Popen([sys.executable,str(Path(__file__).with_name('worker.py')),'--role','alice'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        t=time.monotonic();cpu_before={i:cpu(p.pid) for i,p in r.children.items()};worker.stdin.write(f.canonical(config)+b'\n');worker.stdin.flush();state=read(worker);check('separate Alice process submits actual PC',state['state']=='SUBMITTED_NOT_SETTLED');r.mine(10);worker.stdin.write(b'CONTINUE\n');worker.stdin.flush();check('separate Alice process uploads encrypted object',read(worker)['stored']);worker.stdin.close();worker.wait(timeout=20);check('Alice process exits before Bob starts',worker.returncode==0)
        check('provider remains independently online after Alice exit',call(r.config['ports'][0],'health')['devnet_only'])
        bobconfig=dict(bundle=str(bundle),bundle_password=password,destination=str(base/'bob-output'))
        result=subprocess.run([sys.executable,str(Path(__file__).with_name('worker.py')),'--role','bob'],input=f.canonical(bobconfig)+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
        resultdata=f.decode(result.stdout);check('separate Bob process without wallet configuration retrieves exact content',result.returncode==0 and resultdata['sha256']==digest(plain) and c.read_private(base/'bob-output')==plain)
        check('provider database contains ciphertext, not source bytes',plain not in (base/'provider-0/state.sqlite').read_bytes())
        metrics=dict(service_observation_seconds=time.monotonic()-t,provider_cpu_including_waited_helpers_seconds={i:cpu(p.pid)-cpu_before[i] for i,p in r.children.items()},plain_bytes=len(plain),cipher_bytes=len(plain)+44)
        r.close();r=None
        crashbase=base/'crash-runtime';host=subprocess.Popen([sys.executable,__file__,'--child',str(crashbase)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);ready=read(host);host.kill();host.wait(timeout=10)
        from launcher_host import port_used
        end=time.monotonic()+15
        while any(port_used(p) for p in ready['ports']) and time.monotonic()<end:time.sleep(.05)
        check('SIGKILL runtime parent stops only its owned provider/node children',not any(port_used(p) for p in ready['ports']))
        host=subprocess.Popen([sys.executable,__file__,'--child',str(crashbase)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);read(host);host.stdin.close();host.wait(timeout=20);check('runtime restart and ordinary EOF shutdown preserve usable state',host.returncode==0)
        report['result']='PASS_PROCESS_LIFECYCLE'
    except Exception as error:report.update(result='INCOMPLETE_WITH_BLOCKERS',failure_type=type(error).__name__,failure_label=str(error) if isinstance(error,AssertionError) else 'Private inspection required')
    finally:
        for p in (worker,host):
            if p and p.poll() is None:p.terminate();p.wait(timeout=20)
        if r:r.close()
        report.update(checks=checks,passed=len(checks),seconds=time.monotonic()-start,metrics=metrics,scope='Actual separate Alice and Bob processes, private inherited pipes; same trusted OS/UID, no sandbox/anonymous-routing claim. Parent-death Linux signal tested on owned processes only.')
        out.write_bytes(f.canonical(report)+b'\n');print(report['result'],len(checks),out.name)
    if report['result']!='PASS_PROCESS_LIFECYCLE':sys.exit(1)
if __name__=='__main__':main()
