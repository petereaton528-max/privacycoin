"""Isolated wallet process measurement; output contains fingerprints only."""
from pathlib import Path
import importlib.util,argparse,hashlib,json,resource,time,threading,os
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('measured_wallet',ROOT/'src/phase5b/wallet.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
t=v.t;f=v.f;w=v.w
def usage():
    r=resource.getrusage(resource.RUSAGE_CHILDREN);return time.process_time()+r.ru_utime+r.ru_stime
def main():
    p=argparse.ArgumentParser();p.add_argument('--wallet',type=Path,required=True);p.add_argument('--password',type=Path,required=True);p.add_argument('--anchor-certificate',type=Path,required=True);p.add_argument('--data-certificate',type=Path,required=True)
    p.add_argument('--anchor',type=int,required=True);p.add_argument('--data',type=int,required=True);p.add_argument('--rpc',type=int,required=True);p.add_argument('--mode',choices=['full','pruned','original'],required=True)
    p.add_argument('--cache',type=Path);p.add_argument('--publish',type=Path);p.add_argument('--fallback',choices=['none','full'],default='none');a=p.parse_args()
    peak=[0];done=threading.Event()
    def sample():
        while not done.is_set():
            pending=[os.getpid()];rss=0
            while pending:
                pid=pending.pop()
                try:
                    rss+=int(Path('/proc/'+str(pid)+'/statm').read_text().split()[1])*os.sysconf('SC_PAGE_SIZE')
                    pending.extend(map(int,Path('/proc/'+str(pid)+'/task/'+str(pid)+'/children').read_text().split()))
                except (FileNotFoundError,ProcessLookupError):pass
            peak[0]=max(peak[0],rss);done.wait(.005)
    thread=threading.Thread(target=sample,daemon=True);thread.start();lifecycle=time.perf_counter();load=time.perf_counter()
    password=f.read_private(a.password);wallet=f.load(a.wallet,password);load_ms=(time.perf_counter()-load)*1000
    cache=f.open_sealed(f.read_private(a.cache),password,v.CACHE_KIND) if a.cache else None
    anchor=t.Endpoint('127.0.0.1',a.anchor,a.anchor_certificate,'anchor');data=t.Endpoint('127.0.0.1',a.data,a.data_certificate,'data')
    cpu=usage();start=time.perf_counter();used=False
    if a.mode=='original':
        state=w.snapshot(a.rpc);scan=w.scan(wallet,state);result=dict(balance=w.balance(wallet,state,scan),scan=scan,measurements={})
    else:
        result,used=v.run(wallet,anchor,None if a.mode=='full' else data,cache,fallback=a.fallback)
        if a.publish:f.write_private(a.publish,f.seal(result['cache'],password,v.CACHE_KIND),replace=True)
    wall=(time.perf_counter()-start)*1000;cpu_ms=(usage()-cpu)*1000;done.set();thread.join()
    digest=hashlib.sha256(f.canonical(sorted(result['scan']['owned'],key=lambda x:(x['pending'],x['global_index'])))).hexdigest()
    print(json.dumps(dict(mode=a.mode,owned_fingerprint=digest,balance=result['balance'],wall_ms=wall,cpu_ms=cpu_ms,cpu_percent=cpu_ms/wall*100,
        aggregate_peak_rss_bytes=peak[0],wallet_load_ms=load_ms,lifecycle_ms=(time.perf_counter()-lifecycle)*1000,
        downloaded_application_bytes=anchor.downloaded+data.downloaded if a.mode!='original' else None,downloaded_tls_payload_bytes=anchor.wire_downloaded+data.wire_downloaded if a.mode!='original' else None,
        requests=anchor.calls+data.calls,preprocess_ms=sum(anchor.preprocess+data.preprocess),cache_hits=sum(data.hits),fallback_full=used,components=result['measurements'])))
if __name__=='__main__':main()
