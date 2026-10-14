"""Real orphan-image paging and stale-anchor rejection in fresh owned nodes."""
import argparse,importlib.util,json,os,shutil,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--report',type=Path,required=True);p.add_argument('--fixture',type=int,choices=range(1,6),default=1);a=p.parse_args()
    root=Path(__file__).resolve().parents[3];base=Path('/home/privacydev/pc-v1-fixtures-rc5-metadata-reorg'+str(a.fixture))
    if base.exists() or a.report.exists():raise ValueError('NEW_DISPOSABLE_FIXTURE_REQUIRED')
    os.umask(0o077);base.mkdir(mode=0o700)
    spec=importlib.util.spec_from_file_location('metadata_test_native',root/'tests/phase4/gates.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
    w=h.w;f=h.f;checks=[];nodes=[];report={};stage='wallet_setup';diagnostics={}
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS',name,flush=True)
    try:
        alice=f.full();bob=f.full();address=f.address(alice,0);receiver=f.address(bob,0)
        stage='initial_node_start';A=h.Node(base,'A');B=h.Node(base,'B');C=h.Node(base,'C');nodes=[A,B,C];A.start();stamp=int(time.time())-120*120
        stage='mining_80'
        for _ in range(80):stamp+=120;A.mine(address,stamp)
        stage='cold_clone_restart';A.stop();shutil.copytree(A.path,B.path);shutil.copytree(A.path,C.path);A.start();B.start();C.start()
        stage='two_input_payment'
        state=w.snapshot(A.rpc);payment=w.build(alice,state,receiver,123456789,sources=[0,1]);A.call('submit_tx',transaction=payment['transaction']);A.mine(address,stamp+120)
        stage='competing_branch';B.mine(receiver,stamp+120);B.mine(receiver,stamp+240);A.stop();A.start(peer=B);h.g.converge(A,B);B.stop()
        stage='metadata_comparison'
        # Each API snapshot is internally anchored, but two successive snapshots
        # can legitimately differ while final peer messages update the pool.
        # Compare only when one anchor covers the entire pair; never retry a
        # stable-anchor mismatch or hide a real ownership discrepancy.
        for attempt in range(10):
            before=A.call('snapshot_id');legacy=w.snapshot(A.rpc);bounded=w.snapshot(A.rpc,bounded=True);after=A.call('snapshot_id')
            if all(before[k]==after[k] for k in ('tip','revision','instance')):break
            time.sleep(.1)
        else:raise ValueError('comparison anchor remained active')
        materialized=dict(bounded,chain=list(bounded['chain']))
        diagnostics=dict(different_fields=[k for k in legacy if legacy[k]!=materialized[k]],legacy_orphan_count=len(legacy['orphan_images']),paged_orphan_count=len(bounded['orphan_images']))
        check('bounded metadata equals legacy after real two-input orphan reorganization',materialized==legacy and len(legacy['orphan_images'])==2)
        check('orphan input reservations and restored ownership retained',w.balance(alice,bounded,w.scan(alice,bounded))['reorg_restored_outputs']==2)
        anchor=A.call('snapshot_id');fields={k:anchor[k] for k in ('tip','revision','instance')}
        first=A.call('orphan_images_page',count=1,after='',**fields)
        second=A.call('orphan_images_page',count=1,after=first['after'],**fields)
        check('native orphan metadata spans ordered bounded pages',not first['done'] and second['done'] and first['images']+second['images']==legacy['orphan_images'])
        for count,after in ((0,''),(1025,''),(1,'not-an-image')):
            try:A.call('orphan_images_page',count=count,after=after,**fields)
            except ValueError:check('invalid native image page rejected '+str(count),True)
            else:raise AssertionError('INVALID_PAGE_ACCEPTED')
        C.mine(address,stamp+120);blob=C.call('get_block',hash=C.status()['tip'])['block'];old=A.call('snapshot_id')
        A.call('submit',block=blob);new=A.call('snapshot_id')
        check('new losing branch invalidates metadata revision without changing canonical tip',new['tip']==old['tip'] and new['revision']>old['revision'])
        try:A.call('orphan_images_page',count=1,after='',**{k:old[k] for k in fields})
        except ValueError:check('obsolete orphan graph snapshot is rejected',True)
        else:raise AssertionError('STALE_GRAPH_SNAPSHOT_ACCEPTED')
        before=w.snapshot(A.rpc,bounded=True);A.stop();A.start();after=w.snapshot(A.rpc,bounded=True)
        check('restart preserves canonical and orphan metadata',dict(before,chain=list(before['chain']))==dict(after,chain=list(after['chain'])))
        report=dict(result='PASS_REAL_ONE_HOST_METADATA_REORGANIZATION',checks=checks,physical_hosts=1,public_tor=False)
    except Exception as error:report=dict(result='FAIL',checks=checks,failure_type=type(error).__name__,stage=stage,diagnostics=diagnostics)
    finally:
        for node in reversed(nodes):node.stop()
        with a.report.open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps(report));raise SystemExit(0 if report['result'].startswith('PASS') else 1)

if __name__=='__main__':main()
