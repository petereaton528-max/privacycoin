"""Bounded real long-chain wallet test; only new copies of CLOSED RC4 fixture."""
import argparse,hashlib,json,os,resource,secrets,shutil,subprocess,sys,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--report',type=Path,required=True);p.add_argument('--fixture',type=int,default=1);a=p.parse_args()
    if not 1<=a.fixture<=10:raise ValueError('BOUNDED_FIXTURE_NUMBER')
    root=Path(__file__).resolve().parents[3];base=Path('/home/privacydev/pc-v1-fixtures-rc5-long-wallet'+str(a.fixture))
    source=Path('/home/privacydev/pc-v1-fixtures-rc4-growth1/chain/data.mdb')
    if base.exists() or a.report.exists():raise ValueError('NEW_FIXTURE_REQUIRED')
    assert subprocess.run(['fuser',str(source)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==1,'SOURCE_MUST_BE_CLOSED'
    os.umask(0o077);base.mkdir(mode=0o700);(base/'chain').mkdir(mode=0o700)
    digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    before=digest(source);shutil.copyfile(source,base/'chain/data.mdb')
    from apps.network_v1.desktop_backend import Session,c,f
    from apps.network_v1.wallet_transfer import export,import_wallet
    from apps.network_v1.index import Native,Index
    w=c.w;node=None;alice=None;bob=None;index=None;checks=[];metrics={}
    original_helper=w.helper;helper_bytes={};helper_calls={}
    def measured_helper(q,**kw):
        op=q['op'];helper_bytes[op]=max(helper_bytes.get(op,0),len(f.canonical(q)));helper_calls[op]=helper_calls.get(op,0)+1
        return original_helper(q,**kw)
    w.helper=measured_helper
    def check(name,ok=True):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS',name,flush=True)
    def status():return w.rpc(35181,'status')
    def start():
        nonlocal node
        began=time.monotonic()
        node=subprocess.Popen([str(root/'build/monero-linux/phase4/privacycoin-hardened-devnet'),'--data-dir',str(base/'chain'),'--rpc-port','35181','--p2p-port','35182'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=began+1000
        while time.monotonic()<deadline:
            if node.poll() is not None:raise ValueError('OWNED_NODE_FAILED')
            try:result=status();return result,round(time.monotonic()-began,3)
            except (OSError,ValueError):time.sleep(.25)
        raise TimeoutError('BOUNDED_RELOAD')
    def stop():
        if node and node.poll() is None:
            node.terminate()
            try:node.wait(15)
            except subprocess.TimeoutExpired:node.kill();node.wait(5)
    try:
        old,metrics['initial_reload_seconds']=start();check('10000_block_copy_fully_revalidated',old['height']==10000)
        password='Disposable-'+secrets.token_hex(24)
        alice=Session(base/'alice',35181);bob=Session(base/'bob',35181)
        address=alice.dispatch(dict(command='create',name='Alice',password=password))['address']
        receiver=bob.dispatch(dict(command='create',name='Bob',password=password))['address']
        native=Native(root/'build/network-v1/pc-public-tools')
        stamp=native.describe(w.rpc(35181,'get_block',hash=old['tip'])['block'])['timestamp']
        def mine(n):
            nonlocal stamp
            for _ in range(n):
                stamp+=120;D,C,sub=f.parse_address(address);R,P=f.crypto('output',D,C,sub,0)
                w.rpc(35181,'mine',reward_key=P,R=R,timestamp=stamp)
        mine(75);began=time.monotonic();view=alice.refresh();metrics['full_wallet_scan_seconds']=round(time.monotonic()-began,3)
        check('mature_and_locked_actual_rewards_on_long_chain',view['node']['height']==10075 and view['balance']['spendable']>0 and view['balance']['locked_coinbase']>0)
        anchored=c.snapshot(35181)
        check('raw_history_spooled_privately_not_materialized',isinstance(anchored['chain'],w.ChainRecords))
        prefix=dict(anchored,chain=anchored['chain'][:600])
        paged=w.scan(alice.wallet,prefix)
        direct=original_helper(dict(op='scan',**w.request(alice.wallet,prefix)))
        check('batched_ownership_and_global_indices_match_native_monolithic_reference',all(paged[k]==direct[k] for k in ('owned','eligible','record_outputs','scanned_outputs','undecodable_owned_outputs')))
        prepared=alice.dispatch(dict(command='prepare',destination=receiver,amount=1000000,fee=188000,max_fee=500000))
        alice.dispatch(dict(command='confirm',token=prepared['token'],consent='CONFIRM'))
        try:alice.dispatch(dict(command='prepare',destination=receiver,amount=1000000,fee=188000,max_fee=500000))
        except ValueError:check('unreconciled_submission_blocks_duplicate_payment')
        else:raise AssertionError('DUPLICATE_ALLOWED')
        pending=bob.refresh();check('real_receiver_observes_pending_PC',pending['balance']['pending_incoming']>=1000000)
        export(alice,base/'pending.pc-recovery');saved=alice.journal
        imported=import_wallet(alice,base/'pending.pc-recovery','Recovered',password,'portable','IMPORT SAME TESTNET WALLET')
        check('portable_recovery_preserves_identity_and_submitted_journal',imported['address']==address and alice.journal==saved)
        mine(12);confirmed=bob.refresh();funded=alice.refresh()
        check('actual_payment_confirms_with_private_recipient_balance',confirmed['balance']['spendable']>=1000000 and all(x['status']=='CONFIRMED' for x in alice.journal['attempts']))
        expected=confirmed['balance']['spendable'];tip=status()['tip'];height=status()['height']
        index=Index(base/'public-index.sqlite',native);began=time.monotonic();index.refresh(35181);metrics['initial_index_seconds']=round(time.monotonic()-began,3)
        check('explorer_rebuild_covers_long_chain',index.state()['tip']['height']==height)
        index.close();index=None
        export(bob,base/'bob.pc-recovery');bob.close();alice.close();stop()
        reloaded,metrics['restart_seconds']=start();check('restart_same_chain_tip_height',reloaded['tip']==tip and reloaded['height']==height)
        restored=import_wallet(bob,base/'bob.pc-recovery','Restored',password,'portable','IMPORT SAME TESTNET WALLET')
        began=time.monotonic();observed=bob.refresh();metrics['restored_scan_seconds']=round(time.monotonic()-began,3)
        check('recovered_receiver_retains_real_balance_and_identity',observed['balance']['spendable']==expected and restored['address']==receiver)
        metrics.update(node_database_bytes=(base/'chain/data.mdb').stat().st_size,wallet_bytes=bob.file.stat().st_size,backup_bytes=(base/'bob.pc-recovery').stat().st_size,
                       python_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,children_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        check('bounded_storage_and_memory',metrics['node_database_bytes']<128*1024*1024 and metrics['python_peak_rss_kib']<1500000)
        check('closed_source_unchanged',digest(source)==before)
        metrics.update(max_private_helper_request_bytes=helper_bytes,private_helper_calls=helper_calls)
        check('bounded_scan_and_sparse_build_requests',helper_bytes.get('scan',0)<1100000 and helper_bytes.get('build',0)<1100000)
        report=dict(result='PASS_REAL_LONG_WALLET_ONE_HOST',checks=checks,measurements=metrics,physical_hosts=1,public_tor=False)
    except Exception as error:report=dict(result='FAIL',failure_type=type(error).__name__,checks=checks,measurements=metrics)
    finally:
        if index:index.close()
        if alice:alice.close()
        if bob:bob.close()
        stop()
        w.helper=original_helper
    with a.report.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report));raise SystemExit(0 if report['result'].startswith('PASS') else 1)

if __name__=='__main__':main()
