"""Largest-chain 20-block catch-up, distinct from unchanged-cache refresh."""
from pathlib import Path
import importlib.util,json,shutil,tempfile,hashlib,time
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('phase5b_benchmark',ROOT/'tests/phase5b/benchmark.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
g=b.g;v=g.v;w=g.w;f=g.f;s=g.s

def main():
    public=json.loads((b.RUN/'progress.json').read_text());name=public['scales'][-1];fixture=json.loads((b.RUN/name).read_text());started=time.time()
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase5b-catchup-') as temp:
        base=Path(temp);base.chmod(0o700);certificate,key=g.cert(base);directory=base/'data-tls';directory.mkdir(mode=0o700);dc,dk=g.cert(directory)
        A=g.h.Node(base,'anchor');B=g.h.Node(base,'data');template=b.BENCH/name.replace('.json','-node');shutil.copytree(template,A.path);shutil.copytree(template,B.path);servers=[]
        try:
            startup=dict(anchor_ms=A.start(ttl=1),data_ms=B.start(ttl=1));time.sleep(1.1);assert A.status()==B.status() and A.status()['tip']==fixture['tip']
            anchor,at=s.start(A.rpc,'anchor',base/'anchor-index/pages.sqlite',certificate,key);data,dt=s.start(B.rpc,'data',base/'data-index/pages.sqlite',dc,dk);servers=[(anchor,at),(data,dt)]
            pwd=b.RUN/'fixture.password';walletpath=b.RUN/'A.wallet';password=f.read_private(pwd);wallet=f.load(walletpath,password)
            state=w.snapshot(A.rpc);full=w.scan(wallet,state);fingerprint=hashlib.sha256(f.canonical(g.canonical(full))).hexdigest();balance=w.balance(wallet,state,full)
            initial,_=v.run(wallet,g.endpoint(anchor,certificate,'anchor'),g.endpoint(data,dc,'data'));cache=initial['cache'];cut=state['height']-20
            # Controlled old cache: canonical manifests plus independently full-
            # scanned prefix. Live append/reorg publication is tested in gates.py.
            cache['blocks']=cache['blocks'][:cut];cache['records']=[r for r in cache['records'] if r['height']<=cut];cache['height']=cut;cache['tip']=cache['blocks'][-1]['id']
            prefix=dict(chain=[r for r in state['chain'] if r['height']<=cut],images=[x for r in cache['records'] for x in r['images']],pool_images=[],pool=[],orphan_images=[],height=cut,tip=cache['tip'])
            cache['owned']=w.scan(wallet,prefix)['owned'];v.validate_cache(cache,wallet);path=base/'old.phase5b-cache';f.write_private(path,f.seal(cache,password,v.CACHE_KIND))
            expected_new=len(fixture['model'])-cache['blocks'][-1]['outputs'];conditions=[]
            for condition in [dict(name='local',rate=None,latency=0),dict(name='256KiB-20ms',rate=256*1024,latency=.02),dict(name='1MiB-0ms',rate=1024*1024,latency=0),dict(name='1MiB-20ms',rate=1024*1024,latency=.02),dict(name='10MiB-80ms',rate=10*1024*1024,latency=.08)]:
                for server,_ in servers:server.rate=condition['rate'];server.latency=condition['latency']
                samples={mode:[] for mode in ('full','pruned')}
                for trial in range(7):
                    for mode in ('full','pruned') if trial%2==0 else ('pruned','full'):
                        result=b.measure(mode,walletpath,pwd,(certificate,dc),anchor,data,A,path)
                        assert result['owned_fingerprint']==fingerprint and result['balance']==balance
                        assert result['components']['common_height']==cut and result['components']['new_outputs']==expected_new>0
                        samples[mode].append(result)
                summary={mode:b.summary(values) for mode,values in samples.items()};comparison=dict(byte_reduction=summary['full']['downloaded_application_bytes']['median']/summary['pruned']['downloaded_application_bytes']['median'],speedup=summary['full']['wall_ms']['median']/summary['pruned']['wall_ms']['median'])
                conditions.append(dict(condition=condition,samples=samples,summary=summary,comparison=comparison));print('CATCHUP',condition['name'],comparison,flush=True)
            report=dict(result='PASS',outputs=len(fixture['model']),from_height=cut,to_height=state['height'],new_outputs=expected_new,conditions=conditions,owned_fingerprint=fingerprint,reference_balance=balance,node_startup=startup,elapsed_seconds=time.time()-started,cache_control='Old canonical prefix reconstructed with independent full prefix scanning; real append/reorg correctness separately exercised by live gates',network='Paced loopback, not actual remote network')
            (g.OUT/'incremental-new-tail.json').write_text(json.dumps(report,indent=2)+'\n')
        finally:
            for server,thread in servers:server.shutdown();thread.join();server.server_close();server.service.close()
            A.stop(crash=True);B.stop(crash=True)
if __name__=='__main__':main()
