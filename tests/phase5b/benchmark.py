"""Matched native real-chain scales, repeated trials and explicit missing gates."""
from pathlib import Path
import importlib.util,json,shutil,subprocess,sys,time,statistics,os,tempfile,zlib,hashlib,ctypes,mmap
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('phase5b_gates',ROOT/'tests/phase5b/gates.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
e=g.module('frozen_experiment','tests/phase5a/experiment.py');w=g.w;f=g.f;v=g.v;s=g.s;t=g.t
RUN=ROOT/'build/phase5b-workload';BENCH=ROOT/'build/phase5b-benchmark';OUT=g.OUT
def stats(values):return e.stats(values)
def measure(mode,wallet,pwd,certificate,anchor,data,node,cache=None,publish=None,fallback='none'):
    command=[sys.executable,str(ROOT/'tests/phase5b/measure.py'),'--wallet',str(wallet),'--password',str(pwd),'--anchor-certificate',str(certificate[0]),'--data-certificate',str(certificate[1]),
        '--anchor',str(anchor.server_address[1]),'--data',str(data.server_address[1]),'--rpc',str(node.rpc),'--mode',mode,'--fallback',fallback]
    if cache:command+=['--cache',str(cache)]
    if publish:command+=['--publish',str(publish)]
    def server_cpu():
        total=time.process_time()
        for running in g.h.g.nodes:
            if running.p and running.p.poll() is None:
                fields=Path('/proc/'+str(running.p.pid)+'/stat').read_text().split();total+=(int(fields[13])+int(fields[14]))/os.sysconf('SC_CLK_TCK')
        return total
    start=time.perf_counter();server_start=server_cpu();p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180);server_cpu_ms=(server_cpu()-server_start)*1000
    if p.returncode:raise ValueError('isolated measurement failed: '+p.stderr.decode()[-1000:])
    result=json.loads(p.stdout);result['process_wall_ms']=(time.perf_counter()-start)*1000;result['server_cpu_ms']=server_cpu_ms;result['command']=command;return result
def summary(samples):
    return {k:stats([s[k] for s in samples]) if all(s[k] is not None for s in samples) else dict(status='NOT_INSTRUMENTED') for k in ('wall_ms','cpu_ms','cpu_percent','aggregate_peak_rss_bytes','wallet_load_ms','lifecycle_ms','downloaded_application_bytes','downloaded_tls_payload_bytes','preprocess_ms','server_cpu_ms','process_wall_ms')}
def cold_file(path):
    # Real file-cold control, never claim the entire OS/SSD cache was flushed.
    with path.open('rb') as file:
        os.posix_fadvise(file.fileno(),0,0,os.POSIX_FADV_DONTNEED)
        size=os.fstat(file.fileno()).st_size
        if not size:return dict(bytes=0,resident_pages=0,total_pages=0)
        mapping=mmap.mmap(file.fileno(),0,access=mmap.ACCESS_COPY);buffer=ctypes.c_char.from_buffer(mapping);pages=(size+mmap.PAGESIZE-1)//mmap.PAGESIZE;vec=(ctypes.c_ubyte*pages)()
        libc=ctypes.CDLL(None,use_errno=True);libc.mincore.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
        if libc.mincore(ctypes.addressof(buffer),size,vec)!=0:raise OSError(ctypes.get_errno())
        resident=sum(bool(x&1) for x in vec);del buffer;mapping.close();return dict(bytes=size,resident_pages=resident,total_pages=pages)
def database_backup(source,destination):
    # Unmodified pinned LMDB utility; no system shared-library dependency.
    destination.mkdir(mode=0o700)
    subprocess.run([str(ROOT/'build/monero-linux/phase5b/privacycoin-sync-mdb-copy'),str(source),str(destination)],check=True)
def prepare():
    BENCH.mkdir(parents=True,exist_ok=True);BENCH.chmod(0o700)
    source=g.h.Node(RUN,'node');source.start(ttl=1);reference=g.h.Node(BENCH,'reference');reference.start(ttl=1)
    try:
        public=json.loads((RUN/'progress.json').read_text());targets={json.loads((RUN/name).read_text())['state']['height']:name for name in public['scales']};ids=source.call('chain')['chain']
        current=reference.status()['height']
        if current in targets:
            path=BENCH/targets[current].replace('.json','-node')
            if not path.exists():database_backup(reference.path,path)
        for height in range(current+1,len(ids)):
            b=source.call('get_block',hash=ids[height]);reference.call('submit',block=b['block'],transactions=b['transactions'])
            if height in targets:
                path=BENCH/targets[height].replace('.json','-node')
                if not path.exists():database_backup(reference.path,path)
                print('INDEPENDENT VALIDATION SNAPSHOT',height,flush=True)
        assert reference.status()==source.status()
    finally:source.stop(crash=True);reference.stop(crash=True)
def main():
    if sys.argv[-1]=='prepare':prepare();return
    public=json.loads((RUN/'progress.json').read_text());results=[];policies=[];started=time.time()
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase5b-bench-') as temp:
        base=Path(temp);base.chmod(0o700);anchorcert,key=g.cert(base);datadir=base/'data-tls';datadir.mkdir(mode=0o700);datacert,datakey=g.cert(datadir);certificate=(anchorcert,datacert);pwd=RUN/'fixture.password';walletpath=RUN/'A.wallet';wallet=f.load(walletpath,f.read_private(pwd))
        for name in public['scales']:
            fixture=json.loads((RUN/name).read_text());outputs=len(fixture['model']);scale=base/str(outputs);scale.mkdir(mode=0o700)
            A=g.h.Node(scale,'anchor');B=g.h.Node(scale,'data');template=BENCH/name.replace('.json','-node');shutil.copytree(template,A.path);shutil.copytree(template,B.path)
            servers=[]
            try:
                A.start(ttl=1);B.start(ttl=1);time.sleep(1.1)
                assert A.status()==B.status() and A.status()['tip']==fixture['tip']
                anchor,at=s.start(A.rpc,'anchor',scale/'anchor-index/pages.sqlite',anchorcert,key);data,dt=s.start(B.rpc,'data',scale/'data-index/pages.sqlite',datacert,datakey);servers=[(anchor,at),(data,dt)]
                reference_state=w.snapshot(A.rpc);baseline=w.scan(wallet,reference_state);fingerprint=hashlib.sha256(f.canonical(g.canonical(baseline))).hexdigest();expected_balance=w.balance(wallet,reference_state,baseline);cache=scale/'owned.phase5b-cache'
                ae=g.endpoint(anchor,anchorcert,'anchor');de=g.endpoint(data,datacert,'data');before_checks=len(g.checks)
                for owner in 'ABC':
                    other=f.load(RUN/(owner+'.wallet'),f.read_private(pwd));recovered=g.compare(str(outputs)+' larger '+owner,other,A,ae,de)
                    assert {(x['global_index'],x['amount'],x['spent']) for x in recovered['scan']['owned']}=={(i,x['amount'],x['spent']) for i,x in enumerate(fixture['model']) if x['owner']==owner}
                g.compare(str(outputs)+' restored',f.restore(f.recovery(wallet)),A,ae,de)
                g.compare(str(outputs)+' view',f.view_export(wallet),A,ae,de)
                # Uncached preprocessing is measured, then repeated warm trials.
                # Reset the public index so this really measures first indexing,
                # despite the correctness checks above warming its pages.
                data.service.db.execute('DELETE FROM pages');data.service.db.commit()
                first=measure('pruned',walletpath,pwd,certificate,anchor,data,A,publish=cache);assert first['owned_fingerprint']==fingerprint and first['balance']==expected_balance
                conditions=[dict(name='local',rate=None,latency=0),dict(name='256KiB-20ms',rate=256*1024,latency=.02),dict(name='1MiB-0ms',rate=1024*1024,latency=0),dict(name='1MiB-20ms',rate=1024*1024,latency=.02),dict(name='10MiB-80ms',rate=10*1024*1024,latency=.08)]
                row=dict(outputs=outputs,height=fixture['state']['height'],tip=fixture['tip'],fingerprint=fingerprint,reference_balance=expected_balance,correctness_checks=g.checks[before_checks:],shape_counts={str(shape):sum((x['inputs'],x['outputs'])==shape for x in fixture['intents'].values()) for shape in {(x['inputs'],x['outputs']) for x in fixture['intents'].values()}},uncached=first,conditions=[])
                for condition in conditions:
                    for server,_ in servers:server.rate=condition['rate'];server.latency=condition['latency']
                    samples={mode:[] for mode in ('full','pruned','incremental')}
                    for trial in range(7):
                        for mode in ('full','pruned','incremental') if trial%2==0 else ('incremental','pruned','full'):
                            sample=measure('pruned' if mode=='incremental' else mode,walletpath,pwd,certificate,anchor,data,A,cache if mode=='incremental' else None)
                            assert sample['owned_fingerprint']==fingerprint and sample['balance']==expected_balance;samples[mode].append(sample)
                    aggregate={mode:summary(values) for mode,values in samples.items()}
                    comparison=dict(byte_reduction=aggregate['full']['downloaded_application_bytes']['median']/aggregate['pruned']['downloaded_application_bytes']['median'],speedup=aggregate['full']['wall_ms']['median']/aggregate['pruned']['wall_ms']['median'])
                    row['conditions'].append(dict(condition=condition,summary=aggregate,comparison=comparison,samples=samples))
                    print('BENCH',outputs,condition['name'],'bytes',round(comparison['byte_reduction'],3),'speedup',round(comparison['speedup'],3),flush=True)
                for server,_ in servers:server.rate=None;server.latency=0
                originals=[measure('original',walletpath,pwd,certificate,anchor,data,A) for _ in range(7)];assert all(x['owned_fingerprint']==fingerprint for x in originals);row['original_full_rpc']=dict(summary=summary(originals),samples=originals,transport='unauthenticated loopback RPC; not remote-safe, bytes not instrumented')
                # Matched frozen Phase 5A controls retain their original weaker
                # anchor/protocol and persistent-worker lifecycle explicitly.
                state=fixture['state'];q=dict(op='scan',**w.request(wallet,state));anchorbytes=f.canonical(t.p.manifest(state));old_modes={}
                with t.p.Worker() as worker:
                    projected=worker.call(dict(op='project',chain=state['chain']))['chain']
                    for mode,records in [('full',state['chain']),('pruned',projected)]:
                        payload=zlib.compress(t.p.pack(records,mode=='pruned'),6);values=[]
                        for trial in range(7):
                            def operation():
                                raw=zlib.decompress(e.Download(payload,1024*1024)());e.Download(anchorbytes,1024*1024)();verified,images=t.p.authenticate(raw,t.p.manifest(state),worker)
                                return worker.call(dict(q,chain=verified,images=images))
                            scan,wall,cpu=e.timer(operation);assert hashlib.sha256(f.canonical(g.canonical(scan))).hexdigest()==fingerprint;values.append(dict(wall_ms=wall,cpu_ms=cpu))
                        old_modes[mode]=dict(application_bytes=len(payload)+len(anchorbytes)+8,uncompressed_application_bytes=len(t.p.pack(records,mode=='pruned'))+len(anchorbytes)+8,wall_ms=stats([x['wall_ms'] for x in values]),cpu_ms=stats([x['cpu_ms'] for x in values]))
                row['phase5a_control']=dict(modes=old_modes,limitations='no TLS, externally trusted record manifest rather than canonical block manifest, persistent worker; lifecycle/guarantee differences prevent a claim of equal security')
                ratio=row['conditions'][2]['summary']['pruned']['wall_ms']['median']/old_modes['pruned']['wall_ms']['median']-1
                policies.append(dict(outputs=outputs,comparison='integrated pruned vs frozen Phase5A 1MiB/s no RTT control',regression=ratio,status='APPROVAL_REQUIRED' if ratio>.20 else 'FLAG' if ratio>.10 else 'PASS',justification='includes TLS, bounded paged transport, canonical block verification and worker lifecycle; explanatory, not a waiver'))
                row['storage']=dict(public_sqlite_bytes=data.service.index.stat().st_size,encrypted_wallet_cache_bytes=cache.stat().st_size,sqlite_page_count=data.service.db.execute('PRAGMA page_count').fetchone()[0],sqlite_freelist=data.service.db.execute('PRAGMA freelist_count').fetchone()[0])
                # Confirm actual file page residency; file-cold != system-cold.
                cold=[];warm=[]
                for trial in range(7):
                    control=cold_file(cache);sample=measure('pruned',walletpath,pwd,certificate,anchor,data,A,cache);cold.append(dict(control=control,sample=sample));warm.append(measure('pruned',walletpath,pwd,certificate,anchor,data,A,cache))
                row['file_cold_cache']=cold;row['warm_cache']=warm;row['true_file_cold_verified']=all(x['control']['resident_pages']==0 for x in cold)
                data.mutate=lambda q,header,payload:(header,payload[:-1])
                fallback=[measure('pruned',walletpath,pwd,certificate,anchor,data,A,fallback='full') for _ in range(7)];assert all(x['fallback_full'] and x['owned_fingerprint']==fingerprint for x in fallback);row['fallback']=dict(summary=summary(fallback),samples=fallback)
                results.append(row);OUT.mkdir(parents=True,exist_ok=True);(OUT/'performance-progress.json').write_text(json.dumps(dict(result='IN_PROGRESS',scales=results),indent=2)+'\n')
            finally:
                for server,thread in servers:server.shutdown();thread.join();server.server_close();server.service.close()
                A.stop(crash=True);B.stop(crash=True)
    (OUT/'performance.json').write_text(json.dumps(dict(result='MEASURED',scales=results,regression_policy=policies,elapsed_seconds=time.time()-started,additional_packages=[],remote_network='UNRESOLVED: loopback paced controls only',cold_storage='file-specific page eviction/residency observed; no system-wide/SSD cache flush claimed'),indent=2)+'\n')
if __name__=='__main__':main()
