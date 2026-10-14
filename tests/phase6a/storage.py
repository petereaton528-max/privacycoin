"""Seven actual facade-cache encrypted publication sizes; no private contents."""
from pathlib import Path
import importlib.util,sys,tempfile,json
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('storage_gates',ROOT/'tests/phase6a/gates.py');g=importlib.util.module_from_spec(spec);sys.modules['storage_gates']=g;spec.loader.exec_module(g)
c=g.c;f=g.f;w=g.w;h=g.h;RUN=g.RUN;OUT=g.OUT
def main():
    target=OUT/'facade-storage.json';assert not target.exists()
    password=f.read_private(RUN/'fixture.password');wallet=f.load(RUN/'A.wallet',password)
    node=h.Node(RUN,'node');node.start()
    try:
        state,result,balance,work=c.observe(wallet,node.rpc)
        cache=dict(version=1,profile=w.PROFILE,wallet_id=f.wallet_id(wallet),tip=state['tip'],height=state['height'],work=work,scan=result)
        sizes=[]
        with tempfile.TemporaryDirectory(prefix='privacycoin-6a-storage-') as d:
            for trial in range(7):
                path=Path(d)/f'{trial}.phase6a-cache';c.write_private(path,f.seal(cache,password,c.CACHE_KIND))
                read=c.read_cache(path,wallet,password);assert read['tip']==state['tip'];sizes.append(path.stat().st_size)
        target.write_text(json.dumps(dict(result='PASS',trials=7,height=state['height'],encrypted_facade_cache_bytes=sizes,scope='Actual encrypted publication with facade identity/work schema; no secret/ownership contents published'),indent=2)+'\n')
        print('PASS facade storage 7 trials',min(sizes),max(sizes))
    finally:node.stop(crash=True)
if __name__=='__main__':main()
