"""Bounded protocol/canonical fixtures contain no wallet recovery material."""
from pathlib import Path
import importlib.util,json,zlib,struct,random,time,hashlib,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('gates','tests/phase5b/gates.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
t=g.t;f=g.f;checks=[]
def check(name,condition=True):
    if not condition:raise AssertionError(name)
    checks.append(name)
def reject(name,fn):
    try:fn()
    except (ValueError,OSError,KeyError,TypeError,OverflowError,RecursionError):check(name);return
    raise AssertionError(name)
class Sock:
    def __init__(self,data):self.data=data
    def recv(self,n):part=self.data[:min(n,3)];self.data=self.data[len(part):];return part
def main():
    source=(ROOT/'src/phase5a/scan.cpp').read_text().replace('int main(','int phase5a_unused_entry(')
    check('frozen scanner copy differs only by entry name',source==(ROOT/'src/phase5b/scan_reference.inc').read_text())
    # Validate Linux measurement ABI against the installed kernel headers.
    with tempfile.TemporaryDirectory(prefix='sync-abi-') as temp:
        code=Path(temp)/'offset.cpp';exe=Path(temp)/'offset'
        code.write_text('#include <linux/tcp.h>\n#include <cstddef>\n#include <iostream>\nint main(){std::cout<<offsetof(tcp_info,tcpi_bytes_received);}\n')
        subprocess.run(['g++',str(code),'-o',str(exe)],check=True);check('Linux TCP_INFO bytes-received offset 128',subprocess.check_output([str(exe)])==b'128')
    for n in (1,2,3,10,8192,65536):
        body=b'a'*n;check('partial socket reads '+str(n),t.frame(Sock(struct.pack('>I',n)+body),65536)==body)
    for size in (0,65537,2**32-1):reject('frame bound '+str(size),lambda size=size:t.frame(Sock(struct.pack('>I',size)),65536))
    for raw in (b'',b'x',zlib.compress(b'abc')[:-1],zlib.compress(b'a')+b'x',zlib.compress(b'x'*(t.MAX_PLAIN+1))):reject('inflate malformed '+hashlib.sha256(raw).hexdigest()[:8],lambda raw=raw:t.inflate(raw))
    check('inflate exact plain bound',len(t.inflate(zlib.compress(b'x'*t.MAX_PLAIN)))==t.MAX_PLAIN)
    reject('duplicate JSON fields',lambda:t.decode(b'{"version":1,"version":2}'))
    # A cache hit must recheck the live validating-node snapshot, including
    # pool revision and process identity. Public-only disposable fake records.
    original=g.s.w.rpc;calls=[];current=dict(tip='01'*32,height=702,revision=1,instance='fixture-1')
    def rpc(port,command,**fields):
        calls.append(command)
        if command=='snapshot_id':return dict(current)
        if any(fields[k]!=current[k] for k in ('tip','revision','instance')):raise ValueError('changed')
        return dict(current,blocks=[],next=fields['offset']+fields['count'],pool_ids=[],orphan_images=[])
    with tempfile.TemporaryDirectory(prefix='manifest-cache-unit-') as temp:
        directory=Path(temp)/'index';directory.mkdir(mode=0o700);service=g.s.Service(1,'anchor',directory/'pages.sqlite')
        try:
            g.s.w.rpc=rpc
            def query(**changes):return dict(version=1,role='anchor',profile=g.w.PROFILE,nonce='ab'*32,command='sync_manifest',offset=1,count=32,**{k:current[k] for k in ('tip','revision','instance')},**changes)
            first,body=service.response(query());second,cached=service.response(query())
            check('manifest cache preserves payload without a new hit flag',not first['cache_hit'] and not second['cache_hit'] and body==cached)
            check('manifest cache hit checks live snapshot',calls==['snapshot_id','sync_manifest','snapshot_id'])
            for value in (True,1.0):
                q=query();q['revision']=value;reject('cached revision type '+type(value).__name__,lambda q=q:service.response(q))
            stale=query();current['tip']='02'*32
            reject('manifest cached stale-tip request rejected',lambda:service.response(stale))
            def miss(name):
                previous=calls.count('sync_manifest');service.response(query());check(name,calls.count('sync_manifest')==previous+1)
            miss('manifest reorg invalidates cache')
            current['revision']+=1;miss('manifest pool revision invalidates cache')
            current['instance']='fixture-2';miss('manifest node restart invalidates cache')
            for name,value in [('offset',True),('count',True),('offset',0),('count',33)]:
                q=query();q[name]=value;reject('manifest cached range '+name+' '+str(value),lambda q=q:service.response(q))
            for offset in range(1,100):
                q=query();q['offset']=offset;service.response(q)
            check('manifest cache bounded',len(service.manifests)<=64 and service.manifest_bytes<=16*1024*1024)
        finally:g.s.w.rpc=original;service.close()
    valid=t.p.pack([dict(height=1,coinbase=True,id='00'*32,transaction='00',prunable_hash='00'*32)],True)
    rng=random.Random(50205)
    begin=time.perf_counter()
    for i in range(1000):
        mutated=bytearray(valid);which=i%5
        if which==0:mutated=mutated[:rng.randrange(len(mutated))]
        elif which==1:mutated+=b'\0'
        elif which==2:mutated[4]=rng.randrange(2,256)
        elif which==3:mutated[6:10]=b'\xff'*4
        else:mutated[10+8]=rng.randrange(2,256)
        reject('bounded envelope mutation '+str(i),lambda mutated=mutated:t.p.unpack(bytes(mutated)))
    g.OUT.mkdir(parents=True,exist_ok=True);(g.OUT/'unit-results.json').write_text(json.dumps(dict(result='PASS',checks=checks,total_checks=len(checks),structured_mutations=1000,mutation_wall_ms=(time.perf_counter()-begin)*1000),indent=2)+'\n');print('PASS',len(checks),'unit checks',flush=True)
if __name__=='__main__':main()
