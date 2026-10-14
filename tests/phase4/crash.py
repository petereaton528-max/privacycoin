"""SIGKILL at real LMDB acceptance/admission/reorg boundaries."""
from pathlib import Path
import importlib.util,tempfile,os,time,shutil,json
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('hardening_gates',ROOT/'tests/phase4/gates.py');h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
w=h.w;f=h.f
def main():
    checks=[]
    def check(name,ok):
        assert ok,name;checks.append(name);print('PASS',name,flush=True)
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase4-crash-') as d:
        base=Path(d);os.chmod(base,0o700);A=f.full();B=f.full();address=f.address(A,0);destination=f.address(B,0);stamp=int(time.time())-120*110;node=h.Node(base,'funding');node.start()
        for _ in range(80):stamp+=120;node.mine(address,stamp)
        state=w.snapshot(node.rpc);p=w.build(A,state,destination,123456789);old=node.status();D,C,sub=f.parse_address(address);R,P=f.crypto('output',D,C,sub,0);candidate=node.call('template',reward_key=P,R=R,timestamp=stamp+120)
        node.stop();checkpoint=base/'checkpoint';shutil.copytree(node.path,checkpoint)
        def trigger(n,fn):
            try:fn()
            except (OSError,ValueError):pass
            n.p.wait(timeout=30);check('actual SIGKILL '+stage,n.p.returncode==-9);n.stop();n.start()
        for stage in ('before_pool_commit','after_pool_commit','before_block_commit','after_block_commit','mining'):
            n=h.Node(base,stage);shutil.copytree(checkpoint,n.path);n.start(crash=stage)
            if 'pool' in stage:trigger(n,lambda:n.call('submit_tx',transaction=p['transaction']))
            elif stage=='mining':trigger(n,lambda:n.mine(address,stamp+120))
            else:trigger(n,lambda:n.call('submit',block=candidate['block']))
            if 'pool' in stage:check('atomic pool recovery '+stage,n.status()==old and (p['id'] in n.call('pool')['transactions'])==(stage=='after_pool_commit'))
            else:check('atomic chain recovery '+stage,n.status()['height']==old['height']+(stage=='after_block_commit'))
            check('recovered canonical wallet state '+stage,w.balance(A,w.snapshot(n.rpc),w.scan(A,w.snapshot(n.rpc)))['balance']>0);n.stop()
        # A single longer winning block causes a reorg only after its parent is
        # already present; kill before publishing that new canonical selection.
        left=h.Node(base,'left');right=h.Node(base,'right');shutil.copytree(checkpoint,left.path);shutil.copytree(checkpoint,right.path);left.start();right.start()
        left.mine(address,stamp+120);left.mine(address,stamp+240);leftold=left.status();left.stop()
        blocks=[]
        for i in range(3):
            right.mine(destination,stamp+120*(i+1));blocks.append(right.call('get_block',hash=right.status()['tip']))
        right.stop();left.start(crash='reorg_publish');stage='reorg_publish'
        # Import ancestors without selecting them (shorter/equal work).
        for block in blocks[:2]:left.call('submit',block=block['block'],transactions=block['transactions'])
        trigger(left,lambda:left.call('submit',block=blocks[2]['block'],transactions=blocks[2]['transactions']))
        check('reorg crash retains old atomically committed tip',left.status()==leftold)
        left.call('submit',block=blocks[2]['block'],transactions=blocks[2]['transactions']);check('reorg retry converges to greater work',left.status()['tip']==blocks[2]['hash']);left.stop()
    (h.OUT/'crash-results.json').write_text(json.dumps(dict(result='PASS',checks=checks,checks_passed=len(checks)),indent=2)+'\n')
if __name__=='__main__':
    try:main()
    finally:
        for node in h.g.nodes:
            try:node.stop(crash=True)
            except Exception:pass
