"""Steady equal-chain resource cost of three versus four configured peers."""
from pathlib import Path
import importlib.util,json,os,time,tempfile
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('phase5d_research',ROOT/'tests/phase5d/research.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
h=r.h;f=r.f;OUT=r.OUT
def main():
    if (OUT/'peer-cost.json').exists():raise ValueError('Do not overwrite evidence')
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase5d-peer-cost-') as tmp:
        base=Path(tmp);os.chmod(base,0o700);pwd=base/'a.password';password=os.urandom(32).hex().encode();f.write_private(pwd,password);h.g.cli('create',base/'a.wallet',pwd);wallet=f.load(base/'a.wallet',password)
        a=h.Node(base,'anchor');nodes=[h.Node(base,'three'),h.Node(base,'four')];proxies=[];rows=[]
        try:
            a.start();timestamp=int(time.time())-1200
            for i in range(3):a.mine(f.address(wallet,0),timestamp+120*i)
            for n in nodes:n.start(peers=[a]);h.g.converge(a,n);n.stop()
            groups=[[r.Proxy(a) for _ in range(count)] for count in (3,4)];proxies=[p for group in groups for p in group]
            for n,group in zip(nodes,groups):n.start(peers=group)
            time.sleep(.5)
            for trial in range(40):
                t=time.perf_counter();cpus=[r.cpu(n.p.pid) for n in nodes];wire=[sum(p.received+p.sent for p in group) for group in groups]
                time.sleep(.25);elapsed=time.perf_counter()-t
                rows.append(dict(trial=trial,window_seconds=elapsed,node_cpu_seconds=[r.cpu(n.p.pid)-c for n,c in zip(nodes,cpus)],rss_bytes=[r.rss(n.p.pid) for n in nodes],application_frame_bytes=[sum(p.received+p.sent for p in group)-b for group,b in zip(groups,wire)]))
            assert all(n.status()==a.status() for n in nodes)
            result=dict(result='PASS',paired_windows=40,peer_counts=[3,4],rows=rows,commands=h.g.commands,measurement='Both clients validate identical three-block chain before measurement, then query withholding peers; no new blocks. /proc CPU tick resolution and asynchronous polling are explicit.',limitations=['Absolute RSS difference includes allocator/process variation; no native allocation instrumentation','Poisoned inventory payload exaggerates traffic; not a clean production peer-throughput comparison','One pair of processes, 40 time windows; not 40 independent process samples'])
            encoded=json.dumps(result,indent=2)+'\n'
            for secret in [password.decode(),wallet['seed'],wallet['view']]+f.crypto('derive',wallet['seed'])[:2]:assert secret not in encoded
            (OUT/'peer-cost.json').write_text(encoded);print('PASS 40 paired equal-chain resource windows',flush=True)
        finally:
            for n in h.g.nodes:n.stop()
            for p in proxies:p.shutdown();p.server_close()
if __name__=='__main__':main()
