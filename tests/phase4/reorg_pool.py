"""Nonconflicting orphan reinsertion and exact pending/reorg accounting."""
from pathlib import Path
import importlib.util,tempfile,os,time,json,shutil
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('hardening',ROOT/'tests/phase4/gates.py');h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
w=h.w;f=h.f
def main():
    checks=[]
    def check(name,ok):
        assert ok,name;checks.append(name);print('PASS',name,flush=True)
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase4-orphan-') as d:
        base=Path(d);os.chmod(base,0o700);wa=f.full();wb=f.full();a=f.address(wa,0);b=f.address(wb,0);A=h.Node(base,'A');B=h.Node(base,'B');A.start();stamp=int(time.time())-120*110
        for _ in range(80):stamp+=120;A.mine(a,stamp)
        A.stop();shutil.copytree(A.path,B.path);A.start();B.start()
        common=w.snapshot(A.rpc);old=w.balance(wa,common,w.scan(wa,common));p=w.build(wa,common,b,123456789);A.call('submit_tx',transaction=p['transaction']);A.mine(a,stamp+120)
        check('orphan candidate initially consumes ownership',any(x['spent'] for x in w.scan(wa,w.snapshot(A.rpc))['owned']))
        B.mine(b,stamp+120);B.mine(b,stamp+240);A.stop();A.start(peer=B);h.g.converge(A,B)
        restored=w.snapshot(A.rpc);balance=w.balance(wa,restored,w.scan(wa,restored))
        check('nonconflicting orphan transaction reinserted',p['id'] in A.call('pool')['transactions'])
        check('reorg restores canonical inputs and pool reservations',balance['balance']==old['balance'] and balance['reserved_inputs']>0 and balance['reorg_restored_outputs']>0)
        check('orphan pending change remains recoverable',balance['pending_change']>0 and balance['pending_outgoing']==123456789 and balance['pending_fees']==p['fee'])
        B.stop();B.start(peer=A)
        for _ in range(400):
            if p['id'] in B.call('pool')['transactions']:break
            time.sleep(.025)
        check('reinserted orphan relayed and independently admitted',p['id'] in B.call('pool')['transactions'])
        A.mine(a,stamp+360);B.stop();B.start(peer=A);h.g.converge(A,B)
        final=w.snapshot(A.rpc);received=w.scan(wb,final)['owned'];check('orphan payment remined exactly once',sum(x['transaction']==p['id'] for x in received)==1 and not A.call('pool')['transactions']);check('restored key image consumed exactly once',len(final['images'])==1)
        check('both nodes exact post-reorg wallet state',w.balance(wa,final,w.scan(wa,final))==w.balance(wa,w.snapshot(B.rpc),w.scan(wa,w.snapshot(B.rpc))))
        A.stop();A.start();check('post-reorg durable restart preserves tip images',w.snapshot(A.rpc)['images']==final['images'] and A.status()['tip']==final['tip'])
        instance=A.call('snapshot_id')['instance'];A.stop();A.start();check('restart changes snapshot instance token',A.call('snapshot_id')['instance']!=instance)
        try:A.call('history',offset=1,count=32,tip=final['tip'],revision=0,instance=instance)
        except ValueError:checks.append('obsolete instance snapshot rejected')
        else:raise AssertionError('obsolete instance accepted')
        A.stop();B.stop()
    (h.OUT/'orphan-pool-results.json').write_text(json.dumps(dict(result='PASS',checks=checks,checks_passed=len(checks)),indent=2)+'\n')
if __name__=='__main__':
    try:main()
    finally:
        for node in h.g.nodes:
            try:node.stop(crash=True)
            except Exception:pass
