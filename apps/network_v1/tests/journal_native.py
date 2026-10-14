"""130 real disposable payments, archival, lost acknowledgement, restore/reorg.

No historical data, Tor, external peers or real-value funds. Single physical host.
"""
import argparse,importlib.util,json,os,shutil,time
from pathlib import Path
from unittest.mock import patch
from apps.network_v1.desktop_backend import Session,c,f

def main():
    p=argparse.ArgumentParser();p.add_argument('--fixture-root',type=Path,required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--authorize-disposable-test-mining-payment',action='store_true');a=p.parse_args()
    if not a.authorize_disposable_test_mining_payment or a.fixture_root.exists() or a.report.exists() or not str(a.fixture_root).startswith('/home/privacydev/pc-v1-fixtures-rc5-journal-native'):raise ValueError('NEW_AUTHORIZED_ISOLATED_FIXTURE_REQUIRED')
    os.umask(0o077);a.fixture_root.mkdir(mode=0o700);root=Path(__file__).resolve().parents[3]
    spec=importlib.util.spec_from_file_location('journal_native_gates',root/'tests/phase4/gates.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
    checks=[];nodes=[];session=None;start=time.monotonic();deadline=start+900;stage='setup';measurements={}
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS',name,flush=True)
    try:
        import secrets
        password=secrets.token_hex(24).encode();alice=f.full();bob=f.full();address=f.address(alice,0);receiver=f.address(bob,0)
        wallets=a.fixture_root/'wallets';wallets.mkdir(mode=0o700);wallet_file=wallets/'alice.wallet';c.save(wallet_file,alice,password);c.save(wallets/'bob.wallet',bob,password)
        A=h.Node(a.fixture_root,'A');B=h.Node(a.fixture_root,'B');nodes=[A,B];A.start();stamp=int(time.time())-120*512
        stage='mature_rewards'
        for _ in range(80):stamp+=120;A.mine(address,stamp)
        session=Session(wallets,A.rpc);session.unlock(wallet_file,password);payments=[];amount=1000000
        stage='129_real_payments'
        for i in range(129):
            if time.monotonic()>deadline:raise TimeoutError('bounded native journal experiment')
            approval=session.dispatch(dict(command='prepare',destination=receiver,amount=amount,fee=None,max_fee=10**12))
            result=session.dispatch(dict(command='confirm',token=approval['token'],consent='CONFIRM'))
            txid=session.journal['attempts'][-1]['transaction_id'];payments.append(txid)
            stamp+=120;A.mine(address,stamp)
            # Retain a CLOSED consistent fork source before payment128. This
            # permits testing archived reorganization without mining a long fork.
            if i==126:A.stop();shutil.copytree(A.path,B.path);A.start();session.port=A.rpc
            if (i+1)%16==0:print('CONFIRMED_DISPOSABLE_PAYMENTS',i+1,flush=True)
        refreshed=session.refresh();check('129 real private payments cross old lifetime cap',refreshed['outgoing_total']==129 and refreshed['unknown_attempts']==0)
        check('active state bounded and first128 retained in encrypted archive',len(session.journal['attempts'])==1 and len(session.journal['archives'])==1 and len(list(session.store().attempts(session.journal)))==129)
        state=h.w.snapshot(A.rpc,bounded=True);balance=h.w.balance(bob,state,h.w.scan(bob,state))
        check('recipient owns actual129 confirmed amounts',balance['total_balance']==129*amount)
        stage='lost_broadcast_ack'
        approval=session.dispatch(dict(command='prepare',destination=receiver,amount=amount,fee=None,max_fee=10**12));request=dict(command='confirm',token=approval['token'],consent='CONFIRM');rpc=h.w.rpc;calls=[]
        # Session uses its own imported wallet module: patch that actual adapter.
        import backend
        actual_rpc=backend.w.rpc
        def uncertain(port,method,**kwargs):
            result=actual_rpc(port,method,**kwargs)
            if method=='submit_tx':calls.append(1);raise OSError('isolated acknowledgement loss after actual node acceptance')
            return result
        with patch.object(backend.w,'rpc',side_effect=uncertain):
            try:session.dispatch(request)
            except OSError:pass
            else:raise AssertionError('FAULT_NOT_INJECTED')
            try:session.dispatch(request)
            except ValueError:pass
            else:raise AssertionError('DUPLICATE_APPROVAL_ACCEPTED')
        check('real broadcast occurred once and txid persisted before lost ack',len(calls)==1 and session.journal['attempts'][-1]['transaction_id'] is not None and session.journal['attempts'][-1]['status']=='UNKNOWN')
        session.close();session.unlock(wallet_file,password);pending=session.refresh()
        check('restart reconciles original uncertain broadcast to node pool',session.journal['attempts'][-1]['status']=='PENDING' and pending['outgoing_total']==130)
        stamp+=120;A.mine(address,stamp);session.refresh()
        check('uncertain original becomes confirmed without repayment',session.journal['attempts'][-1]['status']=='CONFIRMED' and len(calls)==1)
        stage='backup_restore_restart'
        session.dispatch(dict(command='backup',name='current'));session.dispatch(dict(command='restore',name='restored',backup='current',password=password.decode()))
        restored=session.refresh();check('encrypted companion backup restores all130 attempts and ownership',restored['outgoing_total']==130 and restored['unknown_attempts']==0 and f.wallet_id(session.wallet)==f.wallet_id(alice))
        A.stop();A.start();session.port=A.rpc;session.close();session.unlock(wallets/'restored.wallet',password)
        check('node plus wallet restart retains130 reconciled attempts',session.refresh()['outgoing_total']==130 and session.refresh()['unknown_attempts']==0)
        stage='archived_real_reorg';B.start()
        # Selection is by accumulated work, not height. Advancing the fork's
        # clock can change difficulty, so bound the work-building loop explicitly.
        target_work=int(A.status()['work'])
        for _ in range(16):
            stamp+=120;B.mine(receiver,stamp)
            if int(B.status()['work'])>target_work:break
        check('bounded fork accumulates greater work',int(B.status()['work'])>target_work)
        fork_tip=B.status()['tip'];A.stop();A.start(peer=B);h.g.converge(A,B);B.stop();session.port=A.rpc
        check('node independently adopts greater-work isolated fork',A.status()['tip']==fork_tip)
        reorg=session.refresh();statuses={a['transaction_id']:a['status'] for a in reorg['outgoing']}
        # A valid orphan may be resurrected into the node's pool. PENDING is
        # reconciled evidence, not UNKNOWN and not permission to repay it.
        check('archived orphan reconciles against actual pool or uncertainty',statuses[payments[127]] in ('PENDING','UNKNOWN'))
        check('unresolved archives block signing when not in canonical chain or pool',not reorg['unknown_attempts'] or not reorg['balance']['signing_available'])
        try:session.dispatch(request)
        except ValueError:check('old broadcast approval remains unusable after reorganization',True)
        else:raise AssertionError('OLD_APPROVAL_REPLAYED')
        A.stop();A.start();session.port=A.rpc;session.close();session.unlock(wallets/'restored.wallet',password)
        restarted=session.refresh();statuses={a['transaction_id']:a['status'] for a in restarted['outgoing']}
        check('archived orphan status is retained through final node and wallet restart',statuses[payments[127]] in ('PENDING','UNKNOWN') and restarted['outgoing_total']==130)
        measurements=dict(seconds=round(time.monotonic()-start,3),height=A.status()['height'],root_bytes=session.journal_path.stat().st_size,archive_bytes=sum(p.stat().st_size for p in session.store().directory.glob('*.page')),active_attempts=len(session.journal['attempts']),archived_pages=len(session.journal['archives']),payments_submitted=130)
        report=dict(result='PASS_REAL_NATIVE_JOURNAL_LIFECYCLE',checks=checks,measurements=measurements,physical_hosts=1,public_tor=False,historical_n2_access=False)
    except Exception as error:report=dict(result='FAIL',checks=checks,stage=stage,failure_type=type(error).__name__,seconds=round(time.monotonic()-start,3),fixtures_retained=True)
    finally:
        if session:session.close()
        for node in reversed(nodes):node.stop()
        with a.report.open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps(report));raise SystemExit(0 if report['result'].startswith('PASS') else 1)
if __name__=='__main__':main()
