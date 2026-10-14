"""Matched executable CLI supplement; frozen full path vs local safety facade.

The preimplementation operation baseline is retained separately. This supplement
was captured after implementation using unchanged, hash-verified input revision
CLI sources, and is not mislabeled preimplementation evidence.
"""
from pathlib import Path
import importlib.util,json,os,sys,tempfile,shutil,subprocess,time,resource,hashlib
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('perf',ROOT/'tests/phase6a/performance.py');p=importlib.util.module_from_spec(spec);sys.modules['perf']=p;spec.loader.exec_module(p)
f=p.f;w=p.w;h=p.h;RUN=p.RUN;OUT=p.OUT
def main():
    target=OUT/'cli-performance.json';assert not target.exists();rows={};transaction_sizes={}
    password=f.read_private(RUN/'fixture.password');wallet=f.load(RUN/'A.wallet',password);destination=f.address(f.load(RUN/'B.wallet',password),0)
    secret=[password]+[bytes.fromhex(wallet[k]) for k in ('seed','view')]+[bytes.fromhex(x) for x in f.crypto('derive',wallet['seed'])[:2]]
    with tempfile.TemporaryDirectory(prefix='privacycoin-6a-cli-perf-') as d:
        base=Path(d);base.chmod(0o700);pf=base/'password';f.write_private(pf,password);backup=base/'recovery.wallet-backup';f.write_private(backup,f.seal(f.recovery(wallet),password,'recovery'))
        for mode in ('baseline','candidate'):
            for op in ('restore','sync','rescan','send'):
                samples=[];sizes=[]
                for trial in range(7):
                    trialdir=base/f'{mode}-{op}-{trial}';trialdir.mkdir(mode=0o700);wf=trialdir/'A.wallet'
                    if op!='restore':f.save(wf,wallet,password)
                    node=None
                    if op!='restore':
                        shutil.copytree(RUN/'node',trialdir/'node');node=h.Node(trialdir,'node');node.start()
                    try:
                        cli=ROOT/('scripts/phase4/privacycoin-wallet' if mode=='baseline' else 'scripts/phase6a/privacycoin-wallet')
                        argv=[sys.executable,str(cli),op,'--wallet',str(wf),'--password-file',str(pf)]
                        if op=='restore':argv+=['--file',str(backup)]
                        else:argv+=['--rpc-port',str(node.rpc)]
                        if op=='send':
                            argv+=['--destination',destination,'--amount','123456789','--fee','1000000']
                            if mode=='candidate':argv+=['--max-fee','1000000']
                        before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.perf_counter()
                        proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                        proc.stdin.write(b'CONFIRM\n');proc.stdin.close();peak=0
                        while proc.poll() is None:peak=max(peak,p.peak_tree(proc.pid));time.sleep(.005)
                        stdout=proc.stdout.read();stderr=proc.stderr.read();elapsed=(time.perf_counter()-start)*1000
                        after=resource.getrusage(resource.RUSAGE_CHILDREN);assert proc.returncode==0,mode+'/'+op
                        for value in secret:assert value not in stdout+stderr and value.hex().encode() not in stdout+stderr
                        if op=='send':
                            assert len(node.call('pool')['transactions'])==1
                            # The final JSON object follows the interactive prompt.
                            last=stdout.decode().rsplit('{',1)[1];info=json.loads('{'+last);sizes.append(info['bytes'])
                        if op=='restore':assert f.load(wf,password)==wallet
                        samples.append(dict(process_ms=elapsed,cpu_ms=(after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime)*1000,aggregate_rss_bytes=peak))
                    finally:
                        if node:node.stop(crash=True)
                rows[mode+'/'+op]={key:p.summary([x[key] for x in samples]) for key in samples[0]}
                if sizes:transaction_sizes[mode]=sizes
                print('CLI performance',mode,op,'7 trials',flush=True)
    comparisons={}
    for op in ('restore','sync','rescan','send'):
        for metric,a in rows['baseline/'+op].items():
            b=rows['candidate/'+op][metric];change=b['median']/a['median']-1
            comparisons[op+'/'+metric]=dict(change_percent=100*change,classification='APPROVAL_REQUIRED' if change>.2 else 'FLAG' if change>.1 else 'PASS')
    report=dict(result='APPROVAL_REQUIRED' if any(x['classification']=='APPROVAL_REQUIRED' for x in comparisons.values()) else 'PASS_WITH_FLAGS' if any(x['classification']=='FLAG' for x in comparisons.values()) else 'PASS',
                metrics=rows,regression=comparisons,transaction_bytes=transaction_sizes,trials=7,height=90,
                methodology='Actual CLI processes. Identical copied 90-block node per trial; unchanged full V1 reference. Encrypted cache publication included for sync/rescan/send. Restore decrypts backup and atomically publishes wallet; full scan measured separately. Candidate send receives explicit CONFIRM; user think-time excluded; construction/broadcast included for both. CPU includes reaped process/helpers; aggregate RSS sampled every 5ms. Warm OS cache. No fake PoW or public remote endpoint.',
                provenance='Supplement after implementation; original full CLI/source unchanged from authoritative input. Preimplementation seven-trial operation baseline retained separately.',
                inputs_sha256={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in [ROOT/'src/wallet/wallet.py',ROOT/'src/phase4/wallet.py',ROOT/'src/phase6a/wallet.py',Path(__file__)]})
    target.write_text(json.dumps(report,indent=2)+'\n');print('CLI performance',report['result'],flush=True)
if __name__=='__main__':main()
