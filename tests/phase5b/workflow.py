"""Largest-scale client lifecycle with encrypted atomic publication every run."""
from pathlib import Path
import importlib.util,json,time,tempfile,shutil,hashlib,os
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('workflow_benchmark',ROOT/'tests/phase5b/benchmark.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
g=b.g;f=g.f;w=g.w;s=g.s;OUT=ROOT/'docs/evidence/phase5b-r/wsl2'
def main():
    started=time.time();fixture=json.loads((b.RUN/'scale-6536.json').read_text())
    with tempfile.TemporaryDirectory(prefix='phase5br-workflow-') as temp:
        base=Path(temp);base.chmod(0o700);cert,key=g.cert(base);directory=base/'tls-data';directory.mkdir(mode=0o700);dc,dk=g.cert(directory)
        A=g.h.Node(base,'anchor');B=g.h.Node(base,'data');servers=[]
        original=b.subprocess.run
        def run(command,*args,**kwargs):
            if isinstance(command,list) and len(command)>1 and command[1]==str(ROOT/'tests/phase5b/measure.py'):
                command=list(command);command[1]=str(ROOT/'tests/phase5b/workflow_measure.py')
            return original(command,*args,**kwargs)
        try:
            for node in (A,B):shutil.copytree(b.BENCH/'scale-6536-node',node.path);node.start(ttl=1)
            time.sleep(1.1);assert A.status()==B.status() and A.status()['tip']==fixture['tip']
            anchor,at=s.start(A.rpc,'anchor',base/'anchor-index/pages.sqlite',cert,key,rate=1024*1024);data,dt=s.start(B.rpc,'data',base/'data-index/pages.sqlite',dc,dk,rate=1024*1024);servers=[(anchor,at),(data,dt)]
            pwd=b.RUN/'fixture.password';walletpath=b.RUN/'A.wallet';wallet=f.load(walletpath,f.read_private(pwd));state=w.snapshot(A.rpc);full=w.scan(wallet,state);fingerprint=hashlib.sha256(f.canonical(g.canonical(full))).hexdigest();balance=w.balance(wallet,state,full)
            b.subprocess.run=run;cache=base/'working.phase5b-cache';first=b.measure('pruned',walletpath,pwd,(cert,dc),anchor,data,A,publish=cache)
            first['command'][1]=str(ROOT/'tests/phase5b/workflow_measure.py');assert first['owned_fingerprint']==fingerprint and first['balance']==balance
            samples={name:[] for name in ('full_rescan','pruned_rescan','unchanged_incremental','pruned_manifest_miss')}
            for trial in range(7):
                modes=list(samples) if trial%2==0 else list(reversed(samples))
                for name in modes:
                    if name=='pruned_manifest_miss':anchor.service.manifests.clear();anchor.service.manifest_bytes=0
                    sample=b.measure('full' if name=='full_rescan' else 'pruned',walletpath,pwd,(cert,dc),anchor,data,A,cache=cache if name=='unchanged_incremental' else None,publish=cache)
                    sample['command'][1]=str(ROOT/'tests/phase5b/workflow_measure.py')
                    def rss(pid):return int(Path('/proc/'+str(pid)+'/statm').read_text().split()[1])*os.sysconf('SC_PAGE_SIZE')
                    sample['server_memory_after_trial']=dict(native_nodes_bytes=[rss(n.p.pid) for n in (A,B)],controller_sidecars_bytes=rss(os.getpid()),scope='Instantaneous post-trial RSS, not a startup/peak metric. Controller also holds correctness-oracle fixtures.')
                    assert sample['owned_fingerprint']==fingerprint and sample['balance']==balance
                    opened=f.open_sealed(f.read_private(cache),f.read_private(pwd),g.v.CACHE_KIND);g.v.validate_cache(opened,wallet)
                    assert opened['tip']==state['tip'];samples[name].append(sample)
            summaries={name:dict(b.summary(values),complete_process_cpu_ms=b.stats([v['complete_process_cpu_ms'] for v in values])) for name,values in samples.items()}
            report=dict(result='PASS',outputs=6536,height=state['height'],owned_fingerprint=fingerprint,reference_balance=balance,conditions='Paced loopback 1MiB/s, no added delay; not remote',first_index_and_publish=first,samples=samples,summary=summaries,
                measured_operations=29,scope='Every trial seals and atomically persists the encrypted cache. process_wall_ms includes process startup, wallet load, cache decrypt when used, sync and publication. wall_ms excludes wallet/cache loading. Forced manifest miss keeps data index warm; it is not OS/disk cold. Client pipeline benchmark; advisory CLI lock acquisition is not timed. Complete process CPU includes imports and reaped native children.',elapsed_seconds=time.time()-started)
            OUT.mkdir(parents=True,exist_ok=True);(OUT/'published-workflow.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS encrypted published workflow 29 measured operations',flush=True)
        finally:
            b.subprocess.run=original
            for server,thread in servers:server.shutdown();thread.join();server.server_close();server.service.close()
            A.stop(crash=True);B.stop(crash=True)
if __name__=='__main__':main()
