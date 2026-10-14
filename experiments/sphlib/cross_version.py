"""Old shipped crypto <-> sphlib: isolated mining, fork and private transfers.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,importlib.util,json,os,shutil,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def main():
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True)
    p.add_argument('--old-archive',type=Path,required=True);a=p.parse_args()
    os.umask(0o077);os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:2])
    home=a.base/'cross-version';home.mkdir(mode=0o700,exist_ok=False)
    spec=importlib.util.spec_from_file_location('sphlib_gate',ROOT/'tests/phase4/gates.py')
    h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
    w=h.w;f=h.f;checks=[];old={};start=time.monotonic()
    with zipfile.ZipFile(a.old_archive) as z:
        manifest=json.loads(z.read('V1_MANIFEST.json'))
        for name,rel in [('node','build/monero-linux/phase4/privacycoin-hardened-devnet'),('helper','build/monero-linux/phase4/privacycoin-hardened-crypto')]:
            b=z.read(rel);assert hashlib.sha256(b).hexdigest()==manifest['files'][rel]
            dest=home/('old-'+name);dest.write_bytes(b);dest.chmod(0o700);old[name]=dest
    class Node(h.Node):
        def __init__(self,name,binary):super().__init__(home,name);self.binary=binary
        def start(self,*args,**kwargs):
            h.g.NODE=self.binary
            return super().start(*args,**kwargs)
    A=Node('old-data',old['node']);B=Node('new-data',a.base/'build-clean/phase4/privacycoin-hardened-devnet')
    def check(name,ok=True):
        assert ok,name;checks.append(name);print('PASS',name,flush=True)
    try:
        wa=f.full();wb=f.full();addr=f.address(wa,0);recipient=f.address(wb,0)
        A.start();stamp=int(time.time())-120*500
        for _ in range(80):stamp+=120;A.mine(addr,stamp)
        A.stop();shutil.copytree(A.path,B.path);A.start();B.start()
        check('new node reloads quiescent old-version LMDB and identical frozen tip',A.status()==B.status())
        B.mine(addr,stamp+120);A.mine(addr,stamp+120);A.mine(addr,stamp+240)
        B.stop();B.start(peer=A);h.g.converge(A,B)
        check('new node independently validates old-version higher-work fork and reorganization',B.call('status')['reorganizations']>=1 and A.status()==B.status())
        A.stop();B.mine(addr,stamp+360);A.start(peer=B);h.g.converge(A,B)
        check('old node independently validates new-version mined block and catches up')
        one=w.build(wa,w.snapshot(B.rpc),recipient,123456789)
        B.call('submit_tx',transaction=one['transaction']);B.mine(addr,stamp+480);h.g.converge(A,B)
        check('old node accepts new constructed private transaction and key image',one['id'] in A.call('get_block',hash=A.status()['tip'])['transaction_ids'] if 'transaction_ids' in A.call('get_block',hash=A.status()['tip']) else w.snapshot(A.rpc)['images']==w.snapshot(B.rpc)['images'])
        previous=w.HELPER;w.HELPER=old['helper']
        try:two=w.build(wa,w.snapshot(A.rpc),recipient,234567891)
        finally:w.HELPER=previous
        A.call('submit_tx',transaction=two['transaction']);A.mine(addr,stamp+600);h.g.converge(A,B)
        final=w.snapshot(B.rpc);received=w.scan(wb,final)['owned']
        check('new node accepts old constructed private transaction and exact received amounts',sorted(x['amount'] for x in received)==[123456789,234567891])
        check('old and new wallet scan ownership and balances identical',w.balance(wb,w.snapshot(A.rpc),w.scan(wb,w.snapshot(A.rpc)))==w.balance(wb,final,w.scan(wb,final)))
        B.stop();B.start();check('new persisted mixed-version chain reloads with identical tip',A.status()==B.status())
        report=dict(result='PASS',checks=checks,checks_passed=len(checks),seconds=round(time.monotonic()-start,3),
            old_archive_sha256=hashlib.sha256(a.old_archive.read_bytes()).hexdigest(),old_binary_sha256={n:hashlib.sha256(p.read_bytes()).hexdigest() for n,p in old.items()},
            new_binary_sha256=hashlib.sha256(B.binary.read_bytes()).hexdigest(),height=B.status()['height'],tip=B.status()['tip'],
            same_host_loopback=True,physical_host_validation=False,historical_n2_access=False,original_wallets_used=False)
        (a.base/'cross-version.json').write_text(json.dumps(report,indent=2)+'\n')
    finally:
        A.stop(crash=True);B.stop(crash=True)
if __name__=='__main__':main()
