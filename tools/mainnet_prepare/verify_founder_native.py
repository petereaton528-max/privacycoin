"""Disposable founder custody -> real native 17-output ownership/recovery.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,secrets,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--native-root',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    os.umask(0o077)
    if a.work.exists() or not a.work.name.startswith('pc-disposable-founder-'):raise ValueError('FRESH_DISPOSABLE_ONLY')
    a.work.mkdir(mode=0o700);checks=[];clients=[];start=time.monotonic()
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    from . import founder as f
    os.environ['PC_OFFLINE_BINDING']=str(a.native_root/'candidate-native/full/BINDING.json')
    from apps.network_v1.candidate_client import Client
    from tools.creator_model.binding import GenesisAddress
    try:
        password=secrets.token_bytes(32);pub=f.create(a.work/'original',password,purpose='DISPOSABLE_TEST')
        for n in (1,2):f.backup(a.work/'original',a.work/('backup'+str(n)),password)
        restored=f.recover(a.work/'backup2',a.work/'recovered',password)
        check('independent encrypted recovery exact approved public recipient',restored==pub)
        payload=f.decrypt(a.work/'recovered/founder.encrypted',password);wallet,_=f.keys(payload['master_seed'])
        c=Client(a.work/'pc-candidate-profile-founder-native',a.native_root/'candidate-native/full',a.native_root);clients.append(c)
        g=c.node.call(op='genesis',D=pub['public_spend'],C=pub['public_view'])
        profile=dict(format='PC_OFFLINE_MAINNET_CANDIDATE_V1',network_tag=c.tag,commitment=c.policy['commitment'],genesis=g['hash'],block=g['block'],launchable=False)
        c.set_profile(profile);c.wallet=wallet
        history=c.node.call(op='history');scan=c.scan(history)
        check('real native disposable Genesis all 17 outputs recognized',len(scan['owned'])==17)
        check('exact initial available and locked creator amounts',scan['available']==15962716940988482 and scan['locked']==143664452468896341 and sum(o['amount'] for o in scan['owned'])==159627169409884823)
        public=c.node.call(op='verify_genesis',block=g['block'],hash=g['hash'])
        check('native exact vesting amounts and heights',[(o['atomic'],o['unlock']) for o in public['outputs']]==[(15962716940988482,0)]+[(8979028279306022 if i<=5 else 8979028279306021,i*65700) for i in range(1,17)])
        final=GenesisAddress(f.f,f.context(),g['hash'],'PCmn1-');D,C,sub=final.parse(final.address(wallet))
        check('pre-Genesis recipient remains controlled after G binding',(D,C,sub)==(pub['public_spend'],pub['public_view'],False))
        c.close();clients.remove(c)
        second=Client(a.work/'pc-candidate-profile-founder-fresh',a.native_root/'candidate-native/full',a.native_root);clients.append(second)
        second.set_profile(profile);second.wallet=f.keys(f.decrypt(a.work/'backup1',password)['master_seed'])[0]
        recovered=second.scan(second.node.call(op='history'))
        check('independent native process identical recovered output ownership',recovered['owned']==scan['owned'] and recovered['available']==scan['available'] and recovered['locked']==scan['locked'])
    finally:
        for client in reversed(clients):client.close()
    result=dict(result='PASS',checks=checks,seconds=round(time.monotonic()-start,3),production_keys=False,production_genesis=False,tor=False,scope='Approved key-domain with disposable keys; pre-existing disposable native consensus fixture, not production Genesis',native_ledger_sha256=hashlib.sha256((a.native_root/'candidate-native/full/draft-ledger').read_bytes()).hexdigest())
    a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
