"""Bounded structured mutation across public and encrypted parsers; no secrets in corpus."""
from pathlib import Path
import importlib.util,tempfile,os,time,json,copy
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('phase4_utilities',ROOT/'tests/phase4/gates.py');h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
w=h.w;f=h.f
def main():
    checks=[];latencies=[];shapes=[]
    def reject(label,fn):
        t=time.perf_counter()
        try:fn()
        except (ValueError,OSError):checks.append(label);latencies.append((time.perf_counter()-t)*1000);return
        raise AssertionError(label)
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase4-mutations-') as d:
        base=Path(d);os.chmod(base,0o700);A=f.full();B=f.full();address=f.address(A,0);destination=f.address(B,0);node=h.Node(base,'node');node.start();stamp=int(time.time())-120*150
        for _ in range(100):stamp+=120;node.mine(address,stamp)
        peak=0
        for inputs,outputs in [(1,2),(2,4),(4,8),(8,16)]:
            state=w.snapshot(node.rpc);owned=w.scan(A,state)['owned'];available=[x for x in owned if not x['spent'] and not x['pending'] and x['unlock']<=state['height']+1]
            selected=[x['global_index'] for x in sorted(available,key=lambda x:x['amount'],reverse=True)[:inputs]]
            p=w.build(A,state,recipients=[dict(address=destination,amount=1000000+i) for i in range(outputs-1)],sources=selected)
            info=w.helper(dict(op='inspect',transaction=p['transaction']));assert info['inputs']==inputs and info['outputs']==outputs
            for case in ['authorization','commitment','range','ciphertext','ring','outside-ring','destination','version','fee','excess-fee','image','immature']+(['duplicate-image'] if inputs>1 else []):
                raw=w.helper(dict(op='mutate',transaction=p['transaction'],case=case,index=95))['transaction'];reject(str(inputs)+'/'+str(outputs)+' '+case,lambda raw=raw:node.call('submit_tx',transaction=raw))
            admission=node.call('submit_tx',transaction=p['transaction']);stamp+=120;node.mine(address,stamp);assert not node.call('pool')['transactions']
            shapes.append(dict(inputs=inputs,outputs=outputs,bytes=p['bytes'],fee=p['fee'],construction_ms=p['construction_ms'],validation_ms=admission['validation_ms']));checks.append('valid maximum/bounded shape '+str(inputs)+'/'+str(outputs))
        before=node.status();block=node.call('get_block',hash=before['tip'])['block']
        for size in (0,1,2,4,8,16,32,64,len(block)//2-1):reject('block truncation '+str(size),lambda size=size:node.call('submit',block=block[:size*2]))
        for label,raw in [('trailing',block+'00'),('varint','ff'*128),('unknown-version','ff'+block[2:]),('noncanonical','9200'+block[2:]),('oversize','00'*300001)]:reject('block '+label,lambda raw=raw:node.call('submit',block=raw))
        for i in range(48):
            pos=(i*7919)%(len(p['transaction'])//2);raw=p['transaction'][:pos*2]+format(int(p['transaction'][pos*2:pos*2+2],16)^128,'02x')+p['transaction'][pos*2+2:];reject('transaction bit '+str(i),lambda raw=raw:node.call('submit_tx',transaction=raw))
            resident=int(next(x.split()[1] for x in Path('/proc/'+str(node.p.pid)+'/status').read_text().splitlines() if x.startswith('VmRSS:')))*1024;peak=max(peak,resident)
        assert node.status()==before and max(latencies)<5000
        for raw in ['',address[:-1],address+'0',address.upper(),address.replace('PCdv1','PCmn1'),address[:10]+'g'+address[11:],address[:-1]+('0' if address[-1]!='0' else '1')]:reject('address malformed '+str(len(checks)),lambda raw=raw:f.parse_address(raw))
        password=os.urandom(32).hex().encode();sealed=f.seal(A,password,'wallet')
        for n in (0,1,8,32,len(sealed)-1):reject('wallet truncated '+str(n),lambda n=n:f.open_sealed(sealed[:n],password,'wallet'))
        for i in range(12):
            raw=bytearray(sealed);raw[(i*7919)%len(raw)]^=128;reject('wallet ciphertext mutation '+str(i),lambda raw=bytes(raw):f.open_sealed(raw,password,'wallet'))
        reject('incorrect wallet password',lambda:f.open_sealed(sealed,b'incorrect-disposable-password','wallet'))
        for version in (0,2,255,2**32):
            value=copy.deepcopy(A);value['version']=version;reject('wallet unsupported version '+str(version),lambda value=value:f.validate(value))
            value=copy.deepcopy(A);value['schemes']=[version,1,1];reject('future unsupported scheme '+str(version),lambda value=value:f.validate(value))
        for key in ('view','public','seed'):
            value=copy.deepcopy(A);value[key]=value[key][:-2];reject('truncated key '+key,lambda value=value:f.validate(value))
        node.stop()
    record=dict(result='PASS',checks=checks,checks_passed=len(checks),shape_matrix=shapes,max_rejection_ms=max(latencies),max_sampled_node_rss_bytes=peak,crashes=0,hangs=0,timeout_limit_ms=5000,corpus='Deterministic mutation recipes and public shape/count metadata only; no raw wallet or secret material persisted',limitations='Structured mutation, not coverage-guided fuzzing; sampled RSS does not capture every transient allocation.')
    (h.OUT/'mutation-results.json').write_text(json.dumps(record,indent=2)+'\n');print('PASS structured mutation checks',len(checks),flush=True)
if __name__=='__main__':
    try:main()
    finally:
        for node in h.g.nodes:
            try:node.stop(crash=True)
            except Exception:pass
