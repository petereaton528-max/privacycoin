"""Negative native compatibility: old fixed-rule miners can form an obsolete fork."""
import argparse,hashlib,json,os,secrets,time
from pathlib import Path
from .verify_native import Native,load,ROOT
from tools.creator_model.binding import DraftBinding
def main():
    p=argparse.ArgumentParser()
    for name in ('build','unaware','native-root','work','report'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();assert not a.work.exists() and a.work.name.startswith('pc-upgrade-fixture-') and not a.report.exists()
    os.umask(0o077);a.work.mkdir(mode=0o700);checks=[];failure=None;began=time.monotonic()
    w=load('unaware_wallet',ROOT/'src/phase4/wallet.py');f=w.foundation;f.HELPER=a.native_root/'build/monero-linux/phase2/privacycoin-wallet-crypto'
    binding=DraftBinding(f,hashlib.sha256(b'non-economic-unaware-fixture').hexdigest(),'a'*64);wallet=binding.wallet(secrets.token_hex(32));D,C,_=binding.parse(binding.address(wallet))
    new=Native(a.build/'draft-ledger');old=Native(a.unaware/'draft-ledger')
    def check(name,ok=True):assert ok,name;checks.append(name)
    def reject(name,fn):
        try:fn()
        except ValueError:check(name);return
        raise AssertionError(name)
    try:
        g=new.call(op='genesis',D=D,C=C)
        def open_(n,name):return n.call(op='open',path=str(a.work/name),block=g['block'],hash=g['hash'])
        open_(new,'New');open_(old,'Old');stamp=int(time.time())-400*120
        def mine(n):
            nonlocal stamp
            stamp+=120;R,P=f.crypto('output',D,C,0,0);return n.call(op='mine',R=R,P=P,timestamp=stamp)['block']
        for _ in range(83):old.call(op='submit',block=mine(new))
        check('unaware fixed-V1 and upgraded validator share height 83',new.call(op='status')['tip']==old.call(op='status')['tip'])
        v2=mine(new);reject('unaware node rejects unknown V2 block',lambda:old.call(op='submit',block=v2))
        obsolete=mine(old);check('unaware node can still mine obsolete V1 at activation',int(obsolete[:2],16)==18 and old.call(op='status')['height']==84)
        reject('upgraded node rejects obsolete-rule fork',lambda:new.call(op='submit',block=obsolete))
        check('hard fork is not resolved by P2P negotiation',new.call(op='status')['tip']!=old.call(op='status')['tip'])
        old.call(op='close');new.call(op='close')
        reject('upgraded binary fails closed on obsolete persisted fork',lambda:open_(new,'Old'))
        open_(old,'Old');check('failed upgrade leaves old database readable under old rules',old.call(op='status')['height']==84)
    except BaseException as error:failure=type(error).__name__+': '+str(error)
    finally:
        new.close();old.close();a.report.write_text(json.dumps(dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=time.monotonic()-began,native_exits=[new.p.returncode,old.p.returncode],requires_coordinated_upgrade=True,obsolete_database_requires_safe_resync=True,production_activation=False),indent=2)+'\n')
    if failure:raise SystemExit(1)
if __name__=='__main__':main()
