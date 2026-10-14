"""Explicit disposable real-core integration. No original N2 data/ports/Tor.

Creates NEW private fixtures, mines test blocks and makes one valueless PC payment.
Own processes only. Whitelisted outcome report; secrets never become evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[3]


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--fixture-root',type=Path,required=True)
    p.add_argument('--helper',type=Path,required=True)
    p.add_argument('--report',type=Path,required=True)
    p.add_argument('--native-root',type=Path,help='Nonsecret source/artifact path for candidate binaries')
    p.add_argument('--authorize-disposable-test-mining-payment',action='store_true')
    a=p.parse_args()
    if not a.authorize_disposable_test_mining_payment or a.fixture_root.exists() or a.report.exists():
        raise SystemExit('NEW_DISPOSABLE_FIXTURE_AND_EXPLICIT_CONSENT_REQUIRED')
    if not a.fixture_root.is_absolute() or '/home/privacydev/pc-v1-fixtures-' not in str(a.fixture_root) or '..' in a.fixture_root.parts:
        raise SystemExit('PRIVATE_NEW_FIXTURE_PATH_REQUIRED')
    os.umask(0o077)
    if a.native_root:
        os.environ['PC_DEVNET_NATIVE_ROOT']=str(a.native_root)
        os.environ['PC_DEVNET_BUILD_MANIFEST']=str(a.native_root/'build/v1-native-manifest.json')
    sys.path.insert(0,str(ROOT/'services/privacy-network'))
    from runtime import Runtime,OwnedNode
    from common import c,f,Session,load_json
    from client import restore_bundle
    from provider import Provider
    from apps.network_v1.index import Index,Native
    from apps.network_v1.payments import Payments
    from apps.network_v1.__main__ import mine
    from apps.network_v1.rpc import rpc
    checks=[];r=None;other=None;clone=None;index=None
    def check(name,ok=True):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS',name,flush=True)
    def rejects(name,fn):
        try:fn()
        except ValueError:check(name);return
        raise AssertionError(name)
    def sync(left,right):
        end=time.monotonic()+30
        while time.monotonic()<end:
            if left.status()==right.status():return
            time.sleep(.05)
        raise AssertionError('isolated synchronization timeout')
    report=dict(scope='ONE_HOST_NEW_PRIVATE_DISPOSABLE_REAL_CORE; NOT_N2_R1_OR_PHYSICAL_HOST_ACCEPTANCE',
                public_network=False,n2_r1_ready=False,checks=checks)
    try:
        r=Runtime(a.fixture_root)
        check('fresh independent fixture node starts with frozen genesis',r.node.status()['height']==0)
        r.mine(80)
        check('bounded real RandomX fixture mining to height 80',r.node.status()['height']==80)
        other=OwnedNode(a.fixture_root,'second-node');other.start(peer=r.node);sync(r.node,other)
        check('second process independently validates and synchronizes real chain')
        other.stop();r.mine(1);other.start(peer=r.node);sync(r.node,other)
        check('isolated peer disconnect restart reconnect and catch-up')
        other.stop();r.mine(1);other.start()
        stamp=int(time.time())-120*500+other.status()['height']*120
        for i in range(2):other.mine(r.address,stamp+120*(i+1))
        r.node.stop();r.node.start(peer=other);sync(r.node,other)
        check('higher-work competing branch triggers validated reorganization',rpc(r.node.rpc,'status')['reorganizations']>=1)
        other.stop()
        native=Native(a.helper);index=Index(a.fixture_root/'public-index.sqlite',native);index.refresh(r.node.rpc)
        block=r.node.status()['tip'];details=native.describe(r.node.call('get_block',hash=block)['block'])
        wallet=r.session.wallet;spend=f.crypto('derive',wallet['seed'])[0]
        signature=native.call('claim '+' '.join(map(str,(wallet['view'],wallet['public'],wallet['count'],details['R'],details['output_key'],0,spend,block,'FixtureMiner'))))
        index.claim(block,'FixtureMiner',signature)
        replay=Index(a.fixture_root/'public-replay.sqlite',native)
        try:
            replay.refresh(r.node.rpc);replay.import_claims(index.export_claims())
            check('independent index replays actual native signed proof document',replay.leaderboard()==index.leaderboard())
        finally:replay.close()
        check('native coinbase ownership proof accepted and ranked',index.leaderboard()['entries'][0]['blocks']==1)
        rejects('native proof cannot be rebound to another alias',lambda:index.claim(block,'Imposter',signature))
        index.close();index=None
        client=r.client(0)
        app=Payments(a.fixture_root/'payment-app',client,c)
        request=app.request('order1',37);qid=request['quote']
        check('idempotent real PC payment request returns original quote',app.request('order1',37)['quote']==qid)
        rejects('same business intent rejects changed quote parameters',lambda:app.request('order1',38))
        r.session.refresh();app.authorize('order1',r.session,'CONFIRM')
        status=client.status(qid)
        check('provider independently persists mempool timing witness',status['first_seen_at'] is not None and status['accepted_at'] is None)
        witness=status['first_seen_at'];r.stop_provider(0);r.start_provider(0)
        r.mine(10);status=client.status(qid)
        check('disposable Provider restart preserves witness and confirms payment',status['state']=='CONFIRMED_LOCAL' and status['first_seen_at']==witness)
        legacy=c.w.snapshot(r.node.rpc);paged=c.snapshot(r.node.rpc)
        check('paged metadata wallet equals complete legacy ownership anchor',bool(legacy['images']) and c.fingerprint(legacy)==c.fingerprint(paged) and legacy['orphan_images']==paged['orphan_images'])
        metadata=c.w.rpc(r.node.rpc,'history',offset=1,count=1,metadata_only=1)
        chain_metadata=rpc(r.node.rpc,'chain',metadata_only=1)
        check('metadata history and explorer omit growing aggregate images',metadata['metadata_paged'] is True and metadata['images']==metadata['orphan_images']==chain_metadata['images']==[])
        rejects('confirmed intent cannot authorize duplicate PC payment',lambda:app.authorize('order1',r.session,'CONFIRM'))
        payload=b'Privacy Coin V1 paid storage fixture.'
        check('example payload length',len(payload)==37)
        check('application independently observes settlement',app.observe('order1')['entitled'])
        app.deliver('order1',payload)
        check('same encrypted upload is idempotent',app.deliver('order1',payload)['idempotent'])
        events=app.events('order1');check('durable callback outbox survives adapter reopen',Payments(a.fixture_root/'payment-app',client,c).events('order1')==events)
        app.acknowledge('order1',events[0]['id']);app.acknowledge('order1',events[0]['id'])
        check('callback acknowledgement idempotent',not app.events('order1'))
        bob_password=os.urandom(32).hex().encode();bundle=a.fixture_root/'bob.bundle'
        app.export_recovery('order1',bundle,bob_password)
        result=restore_bundle(bundle,bob_password,a.fixture_root/'bob-restored.txt')
        check('real PC example encrypted storage independent Bob recovery',result['sha256']==hashlib.sha256(payload).hexdigest())
        r.session.dispatch(dict(command='backup',name='V1Recovery'))
        address=r.address;r.session.dispatch(dict(command='restore',name='V1Recovered',backup='V1Recovery',password=r.config['password']))
        check('wallet recovery preserves public identity and submission journal',f.address(r.session.wallet,0)==address and len(r.session.journal['attempts'])>=1)
        mine(r.node.rpc,f,r.session.wallet,a.helper,1)
        check('new stoppable worker mines valid private reward output',r.node.status()['height']==94)
        # A bounded high-target worker is terminated; node remains alive/unchanged.
        D,C=f.crypto('address',r.session.wallet['view'],r.session.wallet['public'],0);R,P=f.crypto('output',D,C,0,0)
        t=rpc(r.node.rpc,'template',control=True,reward_key=P,R=R)
        worker=subprocess.Popen([str(a.helper)],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            worker.stdin.write(('mine-template '+t['block']+' '+t['seed']+' '+str(2**127)+' 4096\n').encode());worker.stdin.close()
            time.sleep(.2);worker.terminate();worker.wait(timeout=5)
        finally:
            if worker.poll() is None:worker.kill();worker.wait()
        check('owned CPU worker cancellation does not stop node',r.node.status()['height']==94)
        # Coordinated COLD backup of THESE DISPOSABLE fixtures only.
        r.session.close();r.stop_provider(0);r.stop_provider(1);r.node.stop()
        backup=a.fixture_root/'cold-backup';backup.mkdir(mode=0o700)
        con=sqlite3.connect(a.fixture_root/'provider-0/state.sqlite');out=sqlite3.connect(backup/'provider.sqlite')
        try:con.backup(out);check('isolated SQLite backup integrity',out.execute('PRAGMA integrity_check').fetchall()==[('ok',)])
        finally:out.close();con.close()
        clone=OwnedNode(a.fixture_root,'restored-node')
        clone.path.mkdir(mode=0o700)
        shutil.copyfile(r.node.path/'data.mdb',clone.path/'data.mdb');(clone.path/'data.mdb').chmod(0o600)
        clone.start();check('cold LMDB copy reopens and revalidates same chain',clone.status()['height']==94)
        restored=backup/'provider';restored.mkdir(mode=0o700)
        c.write_private(restored/'control',c.read_private(a.fixture_root/'provider-0/control'))
        shutil.copyfile(backup/'provider.sqlite',restored/'state.sqlite');(restored/'state.sqlite').chmod(0o600)
        provider=Provider(restored,clone.rpc)
        try:
            original=load_json(a.fixture_root/'provider-0/control')
            check('paired control preserves Provider identity in disposable restore',provider.control['id']==original['id'])
            q=client.record(qid)['quote'];row=provider.execute('status',dict(quote=qid),q['owner'])
            check('restored Provider independently retains confirmed stored order',row['state']=='CONFIRMED_LOCAL' and row['stored_bytes']==81)
        finally:provider.close()
        report['result']='PASS_DISPOSABLE_REAL_CORE_ONLY'
    except BaseException as error:
        report['result']='FAIL';report['failure_type']=type(error).__name__
        print('INTEGRATION_FAIL; secret-bearing exception details withheld',flush=True)
    finally:
        if index:index.close()
        if clone:clone.stop()
        if other:other.stop()
        if r:r.close()
        a.report.parent.mkdir(parents=True,exist_ok=True)
        with a.report.open('x') as out:json.dump(report,out,indent=2);out.write('\n')
    if report['result']=='FAIL':raise SystemExit(1)


if __name__=='__main__':main()
