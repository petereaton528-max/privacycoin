"""Cross-version ordinary candidate replay using quiescent disposable evidence copies."""
import argparse,fcntl,hashlib,json,os,secrets,shutil,time
from pathlib import Path
from .verify_native import Native,load,ROOT
from tools.creator_model.binding import DraftBinding

def main():
    p=argparse.ArgumentParser()
    for name in ('build','baseline','native-root','source-profile','work','report'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();assert not a.work.exists() and a.work.name.startswith('pc-upgrade-fixture-') and not a.report.exists()
    os.umask(0o077);a.work.mkdir(mode=0o700);src=a.source_profile/'A/chain';profile=json.loads((a.source_profile/'public-profile.json').read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    before={p.name:sha(p) for p in src.iterdir() if p.is_file()}
    with (src/'node.lock').open('r+b') as lock:
        fcntl.lockf(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        shutil.copytree(src,a.work/'New');shutil.copytree(src,a.work/'Old')
    assert before=={p.name:sha(p) for p in src.iterdir() if p.is_file()}
    new=Native(a.build/'draft-ledger');old=Native(a.baseline/'draft-ledger');checks=[];failure=None;began=time.monotonic()
    def check(name,condition):assert condition,name;checks.append(name)
    try:
        for n,name in ((new,'New'),(old,'Old')):n.call(op='open',path=str(a.work/name),block=profile['block'],hash=profile['genesis'])
        check('new native revalidates prior 210-block 130-payment history',new.call(op='status')==old.call(op='status') and new.call(op='status')['height']==210)
        w=load('upgrade_compat_wallet',ROOT/'src/phase4/wallet.py');f=w.foundation;f.HELPER=a.native_root/'build/monero-linux/phase2/privacycoin-wallet-crypto'
        binding=DraftBinding(f,profile['network_tag'],profile['genesis']);wallet=binding.wallet(secrets.token_hex(32));D,C,sub=binding.parse(binding.address(wallet))
        for sender,receiver,label in ((new,old,'old accepts new V1 block'),(old,new,'new accepts old V1 block')):
            R,P=f.crypto('output',D,C,int(sub),0);raw=sender.call(op='mine',R=R,P=P,timestamp=0)['block'];receiver.call(op='submit',block=raw)
            check(label,int(raw[:2],16)==18 and sender.call(op='status')==receiver.call(op='status'))
        for n,name in ((new,'New'),(old,'Old')):n.call(op='close');n.call(op='open',path=str(a.work/name),block=profile['block'],hash=profile['genesis'])
        check('old and new restart at identical supply and tip',new.call(op='status')==old.call(op='status'))
    except BaseException as error:failure=type(error).__name__+': '+str(error)
    finally:
        new.close();old.close()
        unchanged=before=={p.name:sha(p) for p in src.iterdir() if p.is_file()};assert unchanged
        a.report.write_text(json.dumps(dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=time.monotonic()-began,source_database_unchanged=unchanged,native_exits=[new.p.returncode,old.p.returncode]),indent=2)+'\n')
    if failure:raise SystemExit(1)
if __name__=='__main__':main()
