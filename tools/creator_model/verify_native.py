"""Explicit real-native oracle, synthetic genesis and encrypted recovery checks.
No nodes, sockets, Mainnet, real founder identities, or original wallet files.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,importlib.util,json,os,secrets,subprocess,tempfile,time
from pathlib import Path
from tools.creator_model.model import report,schedule,YEAR_BLOCKS
from tools.creator_model.binding import DraftBinding
ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def main():
    p=argparse.ArgumentParser();p.add_argument('--native-root',type=Path,required=True);p.add_argument('--oracle',type=Path,required=True);p.add_argument('--genesis-helper',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if a.report.exists():raise ValueError('NEW_EVIDENCE_REQUIRED')
    os.umask(0o077);checks=[];began=time.monotonic()
    def check(name,condition=True):
        if not condition:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    def rejects(name,fn):
        try:fn()
        except (ValueError,subprocess.CalledProcessError):check(name);return
        raise AssertionError(name)
    binary_hashes={}
    for helper in (a.oracle,a.genesis_helper):
        build=json.loads((helper.parent/'BUILD.json').read_text());actual=hashlib.sha256(helper.read_bytes()).hexdigest()
        if actual!=build['binary_sha256']:raise ValueError('NATIVE_DRAFT_BINARY_CHANGED')
        binary_hashes[helper.name]=actual
    manifest=json.loads((a.native_root/'V1_MANIFEST.json').read_text())
    for member in ('build/monero-linux/phase2/privacycoin-wallet-crypto','build/monero-linux/phase4/privacycoin-hardened-crypto'):
        if hashlib.sha256((a.native_root/member).read_bytes()).hexdigest()!=manifest['files'][member]:raise ValueError('NATIVE_WALLET_HASH_CHANGED')
    model=report();out=subprocess.run([str(a.oracle)],capture_output=True,check=True,timeout=60).stdout.decode().splitlines()
    native={};tail=None
    for line in out:
        height,value=line.split()
        if height=='tail':tail=int(value)
        else:native[int(height)]=int(value)
    expected=schedule(native.keys())
    check('actual native subsidy oracle matches every requested checkpoint through 51 target years',native==expected['points'])
    check('native first tail height matches exact Python recurrence',tail==model['tail_first_height']==2134600)
    check('native four-year cumulative mining and floor allocation',native[1051200]==model['M4_atomic'] and native[1051200]//100==159627169409884823)
    check('native 1461-day calendar-target alternative',native[1051920]==model['calendar_1461_days']['mining_atomic'])
    check('native wide supply and saturating tail beyond uint64',native[50*YEAR_BLOCKS]>2**64-1)
    w=load('creator_proto_wallet',ROOT/'src/phase4/wallet.py');f=w.foundation
    f.HELPER=a.native_root/'build/monero-linux/phase2/privacycoin-wallet-crypto';w.HELPER=a.native_root/'build/monero-linux/phase4/privacycoin-hardened-crypto'
    master=secrets.token_hex(32);password=('Disposable-'+secrets.token_hex(20)).encode();tag=hashlib.sha256(b'PrivacyCoin/creator-offline-fixture-v1').hexdigest()
    initial=DraftBinding(f,tag,'a'*64);wallet=initial.wallet(master);address=initial.address(wallet);D,C,_=initial.parse(address);R,P=f.crypto('output',D,C,0,0)
    allocation=model['allocations']['B_one_percent_mining']['atomic'];digest=hashlib.sha256(b'UNAPPROVED_SYNTHETIC_CREATOR_TEST_ONLY').hexdigest()
    request=f'{allocation} {digest} {P} {R}\n'.encode()
    def native_genesis(raw):return subprocess.run([str(a.genesis_helper)],input=raw,capture_output=True,check=True,timeout=5).stdout
    raw=native_genesis(request);draft=json.loads(raw)
    check('actual native allocation genesis canonical roundtrip and deterministic bytes',raw==native_genesis(request) and draft['native_canonical_roundtrip'] and not draft['launchable'])
    check('creator amount and locked maturity explicitly serialized once',draft['creator_atomic']==allocation and draft['unlock_height']==60)
    check('synthetic genesis hash is distinct from retained Devnet',draft['genesis_hash']!='a0d9ba16f1f6b2fb2f480197ff9dec17468db0d5e6df9cfcb4b2b2a91ecffc87')
    for label,bad in zip(('negative allocation','allocation overflow','trailing input'),(request.replace(str(allocation).encode(),b'-1',1),request.replace(str(allocation).encode(),b'18446744073709551616',1),request+b'extra\n')):
        rejects('native draft rejects '+label,lambda bad=bad:native_genesis(bad))
    binding=DraftBinding(f,tag,draft['genesis_hash'])
    check('recipient derivation avoids genesis circularity',binding.address(binding.wallet(master))==address)
    other=DraftBinding(f,'b'*64,draft['genesis_hash']);other_wallet=other.wallet(master)
    check('same recovery seed gives independent actual native keys across draft network IDs',wallet['public']!=other_wallet['public'] and wallet['view']!=other_wallet['view'])
    rejects('actual Devnet parser rejects draft address',lambda:f.parse_address(address))
    rejects('draft parser rejects Devnet address',lambda:binding.parse(f.address(wallet,0)))
    rejects('different draft network rejects address',lambda:other.parse(address))
    check('actual native transaction-marker hashes are context separated',len({binding.transaction_marker(),other.transaction_marker(),f.crypto('hash',b'PrivacyCoinDev01/private-spend-v1-hardening'.hex())[0]})==3)
    sealed=binding.seal(master,password)
    with tempfile.TemporaryDirectory(prefix='pc-creator-recovery-') as private:
        encrypted=Path(private)/'disposable.pc-recovery';f.write_private(encrypted,sealed)
        recovered=binding.restore(f.read_private(encrypted),password)
    check('encrypted network/genesis-bound recovery preserves actual native wallet keys',recovered['public']==wallet['public'] and recovered['view']==wallet['view'])
    rejects('wrong recovery password rejected',lambda:binding.restore(sealed,b'Wrong-password-123456'))
    rejects('different genesis rejects recovery even with same network and password',lambda:initial.restore(sealed,password))
    rejects('different network rejects encrypted recovery',lambda:other.restore(sealed,password))
    rejects('actual Devnet wallet recovery format rejects draft payload',lambda:f.restore(dict(format='PC_DRAFT_RECOVERY_V1',network_tag=tag)))
    record=dict(transaction=draft['coinbase_bytes'],height=0,coinbase=True)
    state=dict(chain=[record],images=[],pool_images=[],height=58)
    scanned=w.scan(wallet,state);check('actual wallet scanner recognizes synthetic height-zero creator amount and index',len(scanned['owned'])==1 and scanned['owned'][0]['amount']==allocation and scanned['owned'][0]['global_index']==0)
    check('genesis creator output remains locked before candidate height 60',scanned['eligible']==[] and scanned['owned'][0]['unlock']==60)
    state['height']=59;restored_scan=w.scan(recovered,state)
    check('restored wallet rescans identical amount and eligible index at maturity',restored_scan['owned'][0]['amount']==allocation and restored_scan['eligible']==[0])
    # Runtime selector stays fail closed. No constructor loads this genesis.
    with tempfile.TemporaryDirectory(prefix='pc-creator-network-refusal-') as private:
        path=Path(private)/'must-not-exist'
        refusal=subprocess.run([str(a.native_root/'build/monero-linux/phase4/privacycoin-hardened-devnet'),'--data-dir',str(path),'--development-network','mainnet'],capture_output=True,timeout=5)
        check('actual native executable rejects Mainnet selector before creating a database',refusal.returncode!=0 and not path.exists())
    from src.network_identity import selected
    rejects('production Mainnet selector remains disabled',lambda:selected('mainnet'))
    result=dict(result='PASS_OFFLINE_NATIVE_DRAFT_COMPONENTS_ONLY',checks=checks,seconds=round(time.monotonic()-began,3),native_checkpoints=len(native),binary_sha256=binary_hashes,creator_allocation_atomic=allocation,founder_address_selected=False,production_ledger_allocation_implemented=False,actual_mainnet_transaction_building=False,native_genesis_database_recovery=False,services_started=False,mainnet_activated=False,scope='Actual native reward function, draft block serialization/hash and native wallet ownership scan/recovery; SQLite accounting unit tests are a model, not consensus. No real founder keys generated. Synthetic raw block/keys not exported.')
    with a.report.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(result=result['result'],checks=len(checks))),flush=True)
if __name__=='__main__':main()
