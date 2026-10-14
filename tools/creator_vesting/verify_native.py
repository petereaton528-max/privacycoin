"""Real native ledger, RingCT, wallet recovery and fork tests; no network services.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,importlib.util,json,os,secrets,select,subprocess,time
from pathlib import Path
from .policy import *
from .wallet import CandidateWallet
from tools.creator_model.binding import DraftBinding
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
class Native:
    def __init__(self,binary):self.p=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);self.binary=binary
    def call(self,**q):
        self.p.stdin.write(json.dumps(q).encode()+b'\n');self.p.stdin.flush()
        if not select.select([self.p.stdout],[],[],90)[0]:raise TimeoutError('OFFLINE_NATIVE_PIPE_DEADLINE')
        result=json.loads(self.p.stdout.readline())
        if 'error' in result:raise ValueError(result['error'])
        return result
    def close(self):
        if self.p.poll() is None:
            self.p.stdin.close()
            try:self.p.wait(15)
            except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(10)
        if self.p.returncode:raise ValueError('NATIVE_EXIT')
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--native-root',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if a.work.exists() or a.report.exists() or not str(a.work).startswith('/home/privacydev/pc-vesting-fixture-'):raise ValueError('FRESH_ISOLATED_FIXTURE_REQUIRED')
    os.umask(0o077);a.work.mkdir(mode=0o700);checks=[];began=time.monotonic();natives=[];failure=None;final=None
    def check(name,condition):
        if not condition:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    def reject(name,fn,contains=None):
        try:fn()
        except ValueError as e:
            if contains and contains not in str(e):raise
            check(name,True);return
        raise AssertionError(name)
    build=json.loads((a.build/'BUILD.json').read_text())
    for name in ('ledger','wallet'):
        check('exact built '+name+' hash',hashlib.sha256((a.build/('draft-'+name)).read_bytes()).hexdigest()==build[name]['binary_sha256'])
    w=load('vesting_private_wallet',ROOT/'src/phase4/wallet.py');f=w.foundation
    f.HELPER=a.native_root/'build/monero-linux/phase2/privacycoin-wallet-crypto'
    w.HELPER=a.build/'draft-wallet'
    master=secrets.token_hex(32);password=secrets.token_bytes(32);tag=hashlib.sha256(b'OfflineVestingFixture/NO-MAINNET').hexdigest();initial=DraftBinding(f,tag,'a'*64);owner=initial.wallet(master)
    address=initial.address(owner);D,C,sub=initial.parse(address)
    A=Native(a.build/'draft-ledger');natives.append(A)
    try:
        genesis=A.call(op='genesis',D=D,C=C)
        binding=DraftBinding(f,tag,genesis['hash']);adapter=CandidateWallet(w,w.HELPER,binding)
        def open_(n,path,g=genesis):return n.call(op='open',path=str(path),block=g['block'],hash=g['hash'])
        open_(A,a.work/'A');s=A.call(op='status')
        check('native Genesis supply and separate mining counter',s['height']==0 and int(s['creator'])==TOTAL and int(s['mining'])==0 and int(s['total'])==TOTAL)
        initial_scan=adapter.scan(owner,A.call(op='history'))
        check('native height-zero indexing and initial liquid versus locked',len(initial_scan['owned'])==17 and [x['global_index'] for x in initial_scan['owned']]==list(range(17)) and initial_scan['available']==LIQUID and initial_scan['locked']==LOCKED)
        reject('duplicate Genesis rejected',lambda:A.call(op='submit',block=genesis['block']),'duplicate block')
        A.call(op='close')
        for mutation in ('amount','overflow','duplicate','unlock','header','policy'):
            bad=A.call(op='genesis',D=D,C=C,mutation=mutation)
            reject('native malformed Genesis '+mutation,lambda bad=bad:open_(A,a.work/('bad-'+mutation),bad))
        wrong=dict(genesis,hash='a'*64)
        reject('wrong expected Genesis hash rejected',lambda:open_(A,a.work/'wrong-hash',wrong))
        another=A.call(op='genesis',D=D,C=C)
        reject('persisted database rejects different valid Genesis',lambda:open_(A,a.work/'A',another),'incompatible network')
        open_(A,a.work/'A')
        stamp=int(time.time())-120*500;blocks=[]
        def mine(n):
            nonlocal stamp
            stamp+=120;R,P=f.crypto('output',D,C,0,0)
            return n.call(op='mine',P=P,R=R,timestamp=stamp)['block']
        for _ in range(80):blocks.append(mine(A))
        from tools.creator_model.model import schedule as emissions
        s=A.call(op='status');check('80 actual native RandomX blocks preserve mining-only subsidy schedule',s['height']==80 and int(s['mining'])==emissions([80])['points'][80] and int(s['total'])==int(s['mining'])+TOTAL)
        B=Native(a.build/'draft-ledger');natives.append(B);open_(B,a.work/'B')
        for blob in blocks:B.call(op='submit',block=blob)
        check('independent native block verification and synchronization',A.call(op='status')['tip']==B.call(op='status')['tip'])
        state=A.call(op='history');recipient=binding.wallet(secrets.token_hex(32));d,c,sub=binding.parse(binding.address(recipient))
        def transaction(source,height,helper=w.HELPER,genesis_hash=genesis['hash'],fee=10**9):
            q=dict(op='build',draft_genesis=genesis_hash,**w.request(owner,dict(state,height=height-1)),sources=[dict(source=source,ring=sorted([source]+list(range(17,32))))],destinations=[dict(D=d,C=c,sub=sub,amount=10**12)],fee=fee,dedicated_change=True)
            return w.helper(q,helper)['transaction']
        liquid_tx=transaction(0,81)
        A.call(op='probe',transaction=liquid_tx,height=81);check('actual RingCT spend of liquid creator output',True)
        # Exact current consensus/relay distinction, using signed valid proofs.
        low=transaction(0,81,fee=1)
        A.call(op='probe',transaction=low,height=81);check('positive one-atomic fee valid under current consensus',True)
        reject('one-atomic valid transaction rejected by relay floor',lambda:A.call(op='payment',transaction=low),'minimum relay fee')
        fee=100*len(bytes.fromhex(low))
        for _ in range(4):
            edge=transaction(0,81,fee=fee);required=100*len(bytes.fromhex(edge))
            if required==fee:break
            fee=required
        check('exact serialized-byte fee boundary converges',required==fee)
        timings=[]
        for _ in range(5):
            start=time.monotonic();A.call(op='probe',transaction=edge,height=81);timings.append(round((time.monotonic()-start)*1000,3))
        with (a.work/'FEE_EVIDENCE.json').open('x') as stream:json.dump(dict(serialized_bytes=len(bytes.fromhex(edge)),relay_floor_atomic=fee,default_fee_atomic=10**9,validation_ms=timings,scope='Valid one-input RingCT transaction; not adversarial worst-case'),stream,indent=2)
        for tranche in schedule()[1:]:
            i,h=tranche['index'],tranche['height'];tx=transaction(i,h)
            reject('native premature vesting spend '+str(i),lambda tx=tx,h=h:A.call(op='probe',transaction=tx,height=h-1),'immature ring member')
            A.call(op='probe',transaction=tx,height=h);A.call(op='probe',transaction=tx,height=h+1)
            check('actual native CLSAG and commitment validation at/after unlock '+str(i),True)
            before=adapter.scan(owner,dict(state,height=h-1));after=adapter.scan(owner,dict(state,height=h));rollback=adapter.scan(owner,dict(state,height=h-1))
            check('wallet exact boundary and height rollback '+str(i),after['available']-before['available']==tranche['atomic'] and rollback['available']==before['available'])
        # Native builder must also refuse a premature real source.
        reject('native wallet builder rejects premature tranche',lambda:transaction(1,65700-1))
        reject('native wallet rejects changed Genesis context',lambda:transaction(0,81,genesis_hash='a'*64))
        old=a.native_root/'build/monero-linux/phase4/privacycoin-hardened-crypto'
        dev_tx=transaction(0,81,old)
        reject('native ledger rejects actual Devnet-domain transaction',lambda:A.call(op='probe',transaction=dev_tx,height=81),'transaction network/profile domain')
        mutated=w.helper(dict(op='mutate',transaction=liquid_tx,case='excess-fee'))['transaction']
        reject('native excessive fee rejected',lambda:A.call(op='probe',transaction=mutated,height=81),'fee bounds')
        for case in ('authorization','commitment','range','ciphertext'):
            bad=w.helper(dict(op='mutate',transaction=liquid_tx,case=case))['transaction']
            reject('native invalid proof '+case,lambda bad=bad:A.call(op='probe',transaction=bad,height=81))
        A.call(op='payment',transaction=liquid_tx)
        reject('duplicate submission rejected without second spend',lambda:A.call(op='payment',transaction=liquid_tx))
        paid_block=mine(A);paid=A.call(op='history')
        check('creator payment confirmed by actual native block',len(paid['images'])==1)
        received=adapter.scan(recipient,paid);check('actual recipient ownership and exact received amount',sum(x['amount'] for x in received['owned'])==10**12)
        fork1=mine(B);fork2=mine(B);A.call(op='submit',block=fork1);A.call(op='submit',block=fork2)
        orphaned=A.call(op='history');check('native higher-work reorg removes payment confirmation',len(orphaned['images'])==0 and A.call(op='status')['tip']==B.call(op='status')['tip'])
        check('wallet does not retain orphaned payment credit',adapter.scan(recipient,orphaned)['owned']==[])
        reconfirm=mine(A);B.call(op='import',transaction=liquid_tx);B.call(op='submit',block=reconfirm)
        final=A.call(op='status');check('native reorg payment reconciled once on canonical chain',len(A.call(op='history')['images'])==1 and final['tip']==B.call(op='status')['tip'] and final['work']==B.call(op='status')['work'])
        reject('confirmed payment replay rejected',lambda:A.call(op='payment',transaction=liquid_tx))
        recovery=a.work/'encrypted-recovery';f.write_private(recovery,binding.seal(master,password))
        restored=binding.restore(f.read_private(recovery),password)
        check('encrypted fresh wallet recovery rescans identical ownership',adapter.scan(owner,A.call(op='history'))['owned']==adapter.scan(restored,A.call(op='history'))['owned'])
        reject('wrong recovery password',lambda:binding.restore(f.read_private(recovery),b'wrong password'))
        reject('wrong recovery Genesis',lambda:initial.restore(f.read_private(recovery),password))
        reject('Devnet address rejected by draft parser',lambda:binding.parse(f.address(owner,0)))
        reject('draft address rejected by actual Devnet parser',lambda:f.parse_address(binding.address(owner)))
        A.call(op='close');open_(A,a.work/'A');check('native LMDB reload revalidates final chain supply',A.call(op='status')==dict(final,ok=True))
        B.call(op='close');open_(B,a.work/'B');check('independent restarted native databases agree',A.call(op='status')==B.call(op='status'))
        check('private recovery permissions',recovery.stat().st_mode&0o777==0o600)
    except BaseException as error:
        failure=type(error).__name__+': '+str(error);print('FAIL '+failure,flush=True)
    finally:
        exits=[]
        for n in natives:
            try:n.close()
            except BaseException as error:
                if failure is None:failure=type(error).__name__
            exits.append(n.p.poll())
        result=dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=round(time.monotonic()-began,3),native_exit_codes=exits,final_chain=final,real_native_consensus=True,unlock_boundary_scope='Actual native transaction validator at explicit heights on an 80-block state; NOT a mined million-block chain or boundary reorganization.',mainnet_activated=False,network_services=False,physical_hosts=False,full_gui_test=False)
        with a.report.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    if failure:raise SystemExit(1)
if __name__=='__main__':main()
