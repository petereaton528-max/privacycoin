"""Seven-trial baseline/candidate full-wallet measurements, disposable fixture.

No historical experiments rerun, no secret-bearing worker streams published.
"""
from pathlib import Path
import importlib.util,json,os,resource,subprocess,sys,time,statistics,hashlib,threading
ROOT=Path(__file__).resolve().parents[2]
RUN=ROOT/'build/phase6a-local';OUT=ROOT/'docs/evidence/phase6a'
def load(name,rel):
    spec=importlib.util.spec_from_file_location(name,ROOT/rel);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
h=load('h','tests/phase4/gates.py');w=h.w;f=w.foundation
def summary(a):
    m=statistics.median(a);return dict(median=m,mad=statistics.median(abs(x-m) for x in a),min=min(a),max=max(a),samples=a)
def worker(mode,op,port,trial):
    c=load('candidate','src/phase6a/wallet.py') if mode=='candidate' else None
    store=c if c else f
    password=f.read_private(RUN/'fixture.password');wallet=RUN/'A.wallet'
    start=time.perf_counter();cpu=time.process_time();before=resource.getrusage(resource.RUSAGE_CHILDREN)
    x=store.load(wallet,password) if op!='create' else None
    if op=='create':store.save(RUN/f'{mode}-created-{trial}.wallet',f.full(),password)
    elif op=='backup':store.write_private(RUN/f'{mode}-backup-{trial}.wallet-backup',f.seal(f.recovery(x),password,'recovery'))
    elif op=='restore':
        x=f.restore(f.open_sealed(f.read_private(RUN/'baseline-recovery.wallet-backup'),password,'recovery'))
        store.save(RUN/f'{mode}-restored-{trial}.wallet',x,password)
    elif op in ('sync','rescan','balance','send'):
        state=w.snapshot(port)
        if c:
            result=c.observe(x,port)[1] if op!='send' else None
            if op=='send':
                plan=c.prepare(x,state,f.address(f.load(RUN/'B.wallet',password),0),123456789,1000000,1000000)
                c.execute(x,plan,lambda _:True,lambda:w.snapshot(port),lambda tx:dict(accepted=tx['id']))
        else:
            result=w.scan(x,state)
            if op=='send':w.build(x,state,f.address(f.load(RUN/'B.wallet',password),0),123456789,1000000)
        if op in ('sync','rescan'):
            store.write_private(RUN/f'{mode}-{op}-{trial}.phase6a-cache',f.seal(dict(version=1,profile=w.PROFILE,scan=result),password,'phase6a-cache'))
    elif op not in ('open','startup'):raise ValueError('operation')
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    print(json.dumps(dict(wall_ms=(time.perf_counter()-start)*1000,cpu_ms=(time.process_time()-cpu+after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime)*1000)))
def peak_tree(pid):
    total=0
    try:
        root=Path('/proc')/str(pid)
        total=int(next(x.split()[1] for x in (root/'status').read_text().splitlines() if x.startswith('VmRSS:')))*1024
        for child in (root/'task'/str(pid)/'children').read_text().split():total+=peak_tree(int(child))
    except (OSError,StopIteration):pass
    return total
def main(mode):
    OUT.mkdir(parents=True,exist_ok=True);target=OUT/f'performance-{mode}.json';assert not target.exists()
    RUN.mkdir(parents=True,exist_ok=True);RUN.chmod(0o700)
    if mode=='baseline':
        assert not (RUN/'fixture.password').exists()
        password=os.urandom(32).hex().encode();f.write_private(RUN/'fixture.password',password)
        for name in 'ABC':f.save(RUN/f'{name}.wallet',f.full(),password)
        f.write_private(RUN/'baseline-recovery.wallet-backup',f.seal(f.recovery(f.load(RUN/'A.wallet',password)),password,'recovery'))
    password=f.read_private(RUN/'fixture.password');node=h.Node(RUN,'node');started=node.start()
    try:
        if mode=='baseline':
            addresses={n:f.address(f.load(RUN/f'{n}.wallet',password),0) for n in 'ABC'}
            stamp=int(time.time())-120*150
            for i in range(90):stamp+=120;node.mine(addresses['ABC'[i%3]],stamp)
            f.write_private(RUN/'fixture-public.json',f.canonical(dict(timestamp=stamp,tip=node.status()['tip'])))
        state=w.snapshot(node.rpc);metrics={}
        for op in ('create','open','backup','restore','startup','sync','rescan','balance','send'):
            rows=[]
            for trial in range(7):
                t=time.perf_counter();p=subprocess.Popen([sys.executable,str(Path(__file__)),mode,op,str(node.rpc),str(trial)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                peak=0
                while p.poll() is None:peak=max(peak,peak_tree(p.pid));time.sleep(.005)
                raw,err=p.communicate();assert p.returncode==0,'worker rejected '+op
                row=json.loads(raw);row.update(process_ms=(time.perf_counter()-t)*1000,aggregate_rss_bytes=peak);rows.append(row)
            metrics[op]={key:summary([r[key] for r in rows]) for key in rows[0]};print(mode,op,'7 trials',flush=True)
        result=dict(result='PASS',mode=mode,input_checkpoint='e4af3940b5f9b3a022f76dc17946c7d65e8377cd',height=state['height'],tip=state['tip'],trials=7,metrics=metrics,node_startup_ms=started,
                    storage_bytes={n:(RUN/n).stat().st_size for n in ('A.wallet','baseline-recovery.wallet-backup')},
                    methodology='Full snapshot/rescan; sync recovers new canonical observations but is not suffix-only optimization. Warm filesystem, fresh worker per trial; wall excludes user consent wait; CPU includes reaped helpers; concurrent RSS sampled every 5ms. Startup process_ms includes Python import. Send signs without broadcast in a disposable dry run.',
                    host=dict(kernel=os.uname().release,memory_kib=Path('/proc/meminfo').read_text().splitlines()[0],free_disk_bytes=os.statvfs(RUN).f_bavail*os.statvfs(RUN).f_frsize),
                    inputs_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ('src/wallet/wallet.py','src/phase4/wallet.py','tests/phase6a/performance.py')})
        target.write_text(json.dumps(result,indent=2)+'\n')
    finally:node.stop(crash=True)
if __name__=='__main__':
    if len(sys.argv)>2:worker(sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4]))
    else:main(sys.argv[1])
