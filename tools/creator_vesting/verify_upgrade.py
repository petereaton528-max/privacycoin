"""Real native, non-economic rule-transition mining/transaction/fork rehearsal.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,secrets,time
from pathlib import Path
from .verify_native import Native,load,ROOT
from .wallet import CandidateWallet
from .policy import TOTAL
from tools.creator_model.binding import DraftBinding
from tools.creator_model.model import schedule

def main():
    p=argparse.ArgumentParser()
    for name in ('build','old','baseline','native-root','work','report'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();assert not a.work.exists() and not a.report.exists() and a.work.name.startswith('pc-upgrade-fixture-')
    os.umask(0o077);a.work.mkdir(mode=0o700);checks=[];nodes=[];failure=None;final=None;start=time.monotonic()
    def check(name,ok=True):
        assert ok,name
        checks.append(name);print('PASS '+name,flush=True)
    def reject(name,fn,reason=None):
        try:fn()
        except ValueError as error:
            if reason:assert reason in str(error),str(error)
            check(name);return
        raise AssertionError(name)
    def node(path):
        n=Native(path);nodes.append(n);return n
    w=load('upgrade_wallet',ROOT/'src/phase4/wallet.py');f=w.foundation
    f.HELPER=a.native_root/'build/monero-linux/phase2/privacycoin-wallet-crypto';w.HELPER=a.build/'draft-wallet'
    master=secrets.token_hex(32);tag=hashlib.sha256(b'PC/MOCK-UPGRADE/84/NO-VALUE').hexdigest();temp=DraftBinding(f,tag,'a'*64);owner=temp.wallet(master);D,C,sub=temp.parse(temp.address(owner))
    A=node(a.build/'draft-ledger');B=node(a.build/'draft-ledger');old=node(a.old/'draft-ledger');base=node(a.baseline/'draft-ledger')
    try:
        check('mock schedule explicit; ordinary candidate has no activation',A.call(op='policy')['activation']==84 and base.call(op='policy').get('activation',0)==0)
        g=A.call(op='genesis',D=D,C=C);binding=DraftBinding(f,tag,g['hash']);adapter=CandidateWallet(w,w.HELPER,binding)
        recipient=binding.wallet(secrets.token_hex(32));d,c,sub=binding.parse(binding.address(recipient))
        def open_(n,name):return n.call(op='open',path=str(a.work/name),block=g['block'],hash=g['hash'])
        for n,name in ((A,'A'),(B,'B'),(old,'Old')):open_(n,name)
        reject('normal candidate refuses mock-upgrade Genesis',lambda:open_(base,'WrongNetwork'),'draft genesis domain')
        stamp=int(time.time())-120*500
        def mine(n,**extra):
            nonlocal stamp
            stamp+=120;R,P=f.crypto('output',D,C,0,0)
            return n.call(op='mine',R=R,P=P,timestamp=stamp,**extra)['block']
        blocks=[]
        for _ in range(80):blocks.append(mine(A))
        state=A.call(op='history')
        def tx(source,target,helper=w.HELPER):
            ring=sorted({source,*range(17,33)})[:16] if source>=17 else [source,*range(17,32)]
            return w.helper(dict(op='build',draft_genesis=g['hash'],**w.request(owner,dict(state,height=target-1)),sources=[dict(source=source,ring=ring)],destinations=[dict(D=d,C=c,sub=sub,amount=10**12)],fee=10**9,dedicated_change=True),helper)['transaction']
        v1=tx(0,81);A.call(op='payment',transaction=v1);blocks.append(mine(A))
        check('native V1 mining and private payment before activation',int(blocks[-1][:2],16)==18 and adapter.scan(recipient,A.call(op='history'))['available']==0)
        v2=tx(17,84);late_v1=tx(18,83)
        reject('early V2 signed transaction rejected from pool',lambda:A.call(op='payment',transaction=v2),'transaction network/profile domain')
        forced=mine(A,forced_transaction=v2,candidate_only=True)
        reject('actual mined block containing early V2 rejected',lambda:A.call(op='submit',block=forced),'transaction network/profile domain')
        blocks.append(mine(A)) # 82
        early=mine(A,forced_version=19,candidate_only=True)
        reject('early block rule version rejected',lambda:A.call(op='submit',block=early),'unsupported block version')
        blocks.append(mine(A)) # 83
        for n in (B,old):
            n.call(op='import',transaction=v1)
            for raw in (blocks if n is old else blocks[:-1]):n.call(op='submit',block=raw)
        check('unupgraded node validates identical preactivation chain',old.call(op='status')['tip']==A.call(op='status')['tip'])
        reject('V1 signed transaction rejected at activation',lambda:A.call(op='payment',transaction=late_v1),'transaction network/profile domain')
        unsupported='03'+v2[2:]
        reject('unsupported transaction serialization rejected',lambda:A.call(op='payment',transaction=unsupported))
        reject('old wallet refuses construction for unsupported activation',lambda:tx(17,84,a.old/'draft-wallet'))
        reject('upgrade cannot bypass creator vesting in wallet construction',lambda:tx(1,84))
        for mutation in ('authorization','commitment','range','ciphertext','excess-fee'):
            bad=w.helper(dict(op='mutate',transaction=v2,case=mutation))['transaction']
            reject('V2 preserves proof and fee validation '+mutation,lambda bad=bad:A.call(op='payment',transaction=bad))
        for version in (18,20):
            bad=mine(A,forced_version=version,candidate_only=True)
            reject('wrong block version at activation '+str(version),lambda bad=bad:A.call(op='submit',block=bad),'unsupported block version')
        A.call(op='payment',transaction=v2);block84=mine(A)
        check('exact height 84 activates V2 native block and payment',A.call(op='status')['height']==84 and int(block84[:2],16)==19)
        reject('old node refuses activated block without following fork',lambda:old.call(op='submit',block=block84),'unsupported activated')
        reject('old node refuses mining unsupported rules',lambda:mine(old),'unsupported activated')
        check('old node remains at last supported height',old.call(op='status')['height']==83)
        old.call(op='close');open_(old,'Old');check('old node restart preserves supported history',old.call(op='status')['height']==83)
        old.call(op='close');upgrade=node(a.build/'draft-ledger');open_(upgrade,'Old');upgrade.call(op='import',transaction=v2);upgrade.call(op='submit',block=block84);upgrade.call(op='close')
        reject('downgrade refuses persisted activated history',lambda:open_(old,'Old'),'unsupported activated')
        check('wallet identifies both versioned confirmations',sum(x['amount'] for x in adapter.scan(recipient,A.call(op='history'))['owned'] if not x['spent'])==2*10**12)
        # Both branches share block 82. A late V1 block at 83 is validated
        # while A's current tip already runs V2. B crosses 84 and wins at 85,
        # removing the actual V2 payment without changing activation semantics.
        b83=mine(B);b84=mine(B);b85=mine(B)
        A.call(op='submit',block=b83)
        check('historical V1 fork block accepted after local V2 activation',int(b83[:2],16)==18 and A.call(op='status')['height']==84)
        A.call(op='submit',block=b84);A.call(op='submit',block=b85)
        check('actual higher-work reorganization across activation',A.call(op='status')['tip']==B.call(op='status')['tip'] and A.call(op='status')['height']==85)
        check('orphaned V2 payment loses credit and returns to pool',v2 in A.call(op='pool')['transactions'] and sum(x['amount'] for x in adapter.scan(recipient,A.call(op='history'))['owned'] if not x['spent'])==10**12)
        block86=mine(A);B.call(op='import',transaction=v2);B.call(op='submit',block=block86)
        check('V2 reconfirms exactly once on winning branch',A.call(op='status')['tip']==B.call(op='status')['tip'] and sum(x['amount'] for x in adapter.scan(recipient,A.call(op='history'))['owned'] if not x['spent'])==2*10**12)
        reject('confirmed V2 replay rejected',lambda:A.call(op='payment',transaction=v2))
        password=secrets.token_bytes(32);recovery=binding.seal(master,password);restored=binding.restore(recovery,password)
        check('unchanged wallet recovery rescans both historical rules',adapter.scan(owner,A.call(op='history'))['owned']==adapter.scan(restored,A.call(op='history'))['owned'])
        reject('cross-network recovery refused',lambda:DraftBinding(f,'b'*64,g['hash']).restore(recovery,password))
        final=A.call(op='status');check('creator vesting and mining supply unaffected',int(final['creator'])==TOTAL and int(final['mining'])==schedule([86])['points'][86] and int(final['total'])==TOTAL+int(final['mining']))
        A.call(op='close');open_(A,'A');B.call(op='close');open_(B,'B')
        check('restart revalidates historical V1 and V2 and fork branches',A.call(op='status')['tip']==B.call(op='status')['tip']==final['tip'])
    except BaseException as error:failure=type(error).__name__+': '+str(error);print('FAIL '+failure,flush=True)
    finally:
        for n in nodes:n.close()
        a.report.write_text(json.dumps(dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=time.monotonic()-start,final=final,real_native=True,real_RandomX=True,real_RingCT=True,activation=84,external_network=False,production_activation=False,native_exits=[n.p.returncode for n in nodes]),indent=2)+'\n')
    if failure:raise SystemExit(1)
if __name__=='__main__':main()
