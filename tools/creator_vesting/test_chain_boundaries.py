"""Actual mined native forks on a separately identified accelerated fixture.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,secrets,time
from pathlib import Path
from tools.creator_vesting.verify_native import Native,load,ROOT
from tools.creator_model.binding import DraftBinding
from tools.creator_vesting.wallet import CandidateWallet
from tools.creator_model.model import schedule as emissions
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--native-root',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if a.work.exists() or a.report.exists() or not str(a.work).startswith('/home/privacydev/pc-candidate-profile-'):raise ValueError('NEW_DISPOSABLE_PATH_REQUIRED')
    os.umask(0o077);a.work.mkdir(mode=0o700);nodes=[];checks=[];observations=[];began=time.monotonic();failure=None;final=None
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    def reject(name,fn,expected):
        try:fn()
        except ValueError as error:
            if expected not in str(error):raise
            check(name,True);return
        raise AssertionError(name)
    w=load('real_boundary_wallet',ROOT/'src/phase4/wallet.py');f=w.foundation;f.HELPER=a.native_root/'build/monero-linux/phase2/privacycoin-wallet-crypto';w.HELPER=a.build/'draft-wallet'
    A=Native(a.build/'draft-ledger');B=Native(a.build/'draft-ledger');nodes=[A,B]
    try:
        policy=A.call(op='policy');check('explicit non-economic accelerated policy interval 80',policy['interval']==80 and 'ACCELERATED-NON-ECONOMIC' in policy['commitment'])
        tag=hashlib.sha256(policy['commitment'].encode()).hexdigest();binding=DraftBinding(f,tag,'a'*64);owner=binding.wallet(secrets.token_hex(32));D,C,_=binding.parse(binding.address(owner));g=A.call(op='genesis',D=D,C=C);binding=DraftBinding(f,tag,g['hash']);adapter=CandidateWallet(w,w.HELPER,binding,80)
        for label,node in [('A',A),('B',B)]:node.call(op='open',path=str(a.work/label),block=g['block'],hash=g['hash'])
        recipient=binding.wallet(secrets.token_hex(32));d,c,sub=binding.parse(binding.address(recipient));transactions=[];stamp=int(time.time())-2000*120
        def mine(node,**extra):
            nonlocal stamp
            stamp+=120;R,P=f.crypto('output',D,C,0,0);return node.call(op='mine',P=P,R=R,timestamp=stamp,**extra)['block']
        def synchronize(node,blocks):
            for raw in transactions:node.call(op='import',transaction=raw)
            for raw in blocks[1:]:
                try:node.call(op='submit',block=raw)
                except ValueError as error:
                    if 'duplicate block' not in str(error):raise
        for payment_number,tranche in enumerate((1,8,16),1):
            h=tranche*80
            while A.call(op='status')['height']<h-2:mine(A)
            synchronize(B,A.call(op='blocks')['blocks']);check('fork parent synchronized '+str(tranche),A.call(op='status')['tip']==B.call(op='status')['tip'])
            state=A.call(op='history')
            q=dict(op='build',draft_genesis=g['hash'],**w.request(owner,dict(state,height=h-1)),sources=[dict(source=tranche,ring=[tranche]+list(range(17,32)))],destinations=[dict(D=d,C=c,sub=sub,amount=10**12)],fee=10**9,dedicated_change=True)
            tx=w.helper(q)['transaction'];transactions.append(tx)
            invalid=mine(A,forced_transaction=tx,candidate_only=True)
            reject('actual PoW block before unlock rejected '+str(tranche),lambda:A.call(op='submit',block=invalid),'immature ring member')
            check('rejected premature block does not advance canonical state '+str(tranche),A.call(op='status')['height']==h-2)
            mine(A);before=A.call(op='history');before_scan=adapter.scan(owner,before)
            output=next(x for x in before_scan['owned'] if x['height']==0 and x['output_index']==tranche)
            check('actual canonical height immediately before release is locked '+str(tranche),before['height']==h-1 and output['unlock']==h and output['unlock']>before['height'])
            A.call(op='payment',transaction=tx);mine(A);at=A.call(op='history');mine(A);after=A.call(op='history')
            check('valid spend included at exact release and retained after '+str(tranche),at['height']==h and after['height']==h+1 and len(at['images'])==payment_number)
            confirmed=len(after['images']);credit=sum(x['amount'] for x in adapter.scan(recipient,after)['owned'])
            # Competing branch is rooted below the boundary and contains no new payment.
            fork=[mine(B) for _ in range(4)]
            for raw in fork:A.call(op='submit',block=raw)
            orphaned=A.call(op='history');orphan_credit=sum(x['amount'] for x in adapter.scan(recipient,orphaned)['owned'])
            check('real higher-work reorg crosses release boundary '+str(tranche),A.call(op='status')['tip']==B.call(op='status')['tip'] and orphaned['height']==h+2 and len(orphaned['images'])==confirmed-1 and orphan_credit==credit-10**12)
            check('orphaned transaction is reconciled as pending '+str(tranche),tx in A.call(op='pool')['transactions'])
            reconfirm=mine(A);B.call(op='import',transaction=tx);B.call(op='submit',block=reconfirm)
            final=A.call(op='status');check('reconfirmation restores exactly one credit '+str(tranche),len(A.call(op='history')['images'])==confirmed and sum(x['amount'] for x in adapter.scan(recipient,A.call(op='history'))['owned'])==credit)
            check('canonical tip/work and exact supply agree '+str(tranche),final==B.call(op='status') and int(final['creator'])==159627169409884823 and int(final['mining'])==emissions([h+3])['points'][h+3] and int(final['total'])==int(final['creator'])+int(final['mining']))
            observations.append(dict(tranche=tranche,boundary=h,before_height=before['height'],at_height=at['height'],after_height=after['height'],reorg_height=orphaned['height'],final=final))
        for node,label in [(A,'A'),(B,'B')]:
            node.call(op='close');node.call(op='open',path=str(a.work/label),block=g['block'],hash=g['hash'])
            check('native restart revalidates mined boundary chain '+label,node.call(op='status')==final)
    except BaseException as error:failure=type(error).__name__+': '+str(error);print('FAIL '+failure,flush=True)
    finally:
        for node in nodes:node.close()
        result=dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=round(time.monotonic()-began,3),boundaries=observations,final=final,exit_codes=[node.p.returncode for node in nodes],scope='Actual RandomX PoW, block/transaction verification and canonical higher-work reorgs on distinct accelerated 80-block vesting network; no artificial heights or validation bypass. Not full 65700-interval chain evidence.',tor=False,mainnet=False)
        a.report.write_text(json.dumps(result,indent=2)+'\n')
    if failure:raise SystemExit(1)
if __name__=='__main__':main()
