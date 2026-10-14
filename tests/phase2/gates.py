"""Real executable Phase 2 gates. Disposable secrets stay in private temp files.

Only public fingerprints, test names, commands and artifact hashes enter evidence.
"""
from pathlib import Path
import copy
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import shutil

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT/'docs/evidence/phase2/wsl2'
spec = importlib.util.spec_from_file_location('wallet', ROOT/'src/wallet/wallet.py')
w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)
PASSWORD = b'disposable-test-password-only'
SECRETS = [PASSWORD]
def remember(wallet):
    for name in ('seed', 'view'):
        if wallet[name]:
            SECRETS.extend([wallet[name].encode(), bytes.fromhex(wallet[name])])
    if wallet['seed']:
        b = w.crypto('derive', wallet['seed'])[0]; SECRETS.extend([b.encode(), bytes.fromhex(b)])
    return wallet

def fixture(n=0):
    return remember(w.full(hashlib.sha256(('PrivacyCoin disposable Phase2 test '+str(n)).encode()).hexdigest(), 4))

def reject(test, fn, *args):
    with test.assertRaises((ValueError, OSError, TypeError, KeyError)):
        fn(*args)

class Foundation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a, cls.b = fixture(), fixture(1)
        cls.o = w.output(w.address(cls.a, 1), 7, 3)

    def test_deterministic_seed_keys_addresses_id(self):
        restored = w.restore(w.recovery(self.a))
        restored_again = w.restore(w.recovery(self.a))
        self.assertEqual(restored, restored_again)
        self.assertEqual(self.a, restored)
        self.assertEqual(w.wallet_id(self.a), w.wallet_id(restored))
        for i in range(4): self.assertEqual(w.address(self.a, i), w.address(restored, i))

    def test_csprng_independent_wallets(self):
        wallets = [remember(w.full()) for _ in range(12)]
        self.assertEqual(len({w.wallet_id(x) for x in wallets}), 12)

    def test_distinct_disposable_seeds(self):
        self.assertNotEqual(w.wallet_id(self.a), w.wallet_id(self.b))

    def test_primary_and_subaddress_canonical_roundtrip(self):
        addresses = [w.address(self.a, i) for i in range(4)]
        self.assertEqual(len(set(addresses)), 4)
        for i, a in enumerate(addresses):
            D, C, sub = w.parse_address(a)
            self.assertEqual(D+' '+C, ' '.join(w.crypto('address', self.a['view'], self.a['public'], i)))
            self.assertEqual(sub, int(i!=0))

    def altered_address(self, pos, value):
        raw = bytearray.fromhex(w.address(self.a, 1)[6:]); raw[pos] = value
        raw[-4:] = bytes.fromhex(w.crypto('hash', raw[:-4].hex())[0])[:4]
        return 'PCdv1-'+raw.hex()

    def test_wrong_network(self): reject(self, w.parse_address, self.altered_address(1, 2))
    def test_unknown_address_version(self): reject(self, w.parse_address, self.altered_address(0, 2))
    def test_future_address_scheme(self): reject(self, w.parse_address, self.altered_address(2, 255))
    def test_future_ownership_scheme(self): reject(self, w.parse_address, self.altered_address(3, 255))
    def test_future_viewing_scheme(self): reject(self, w.parse_address, self.altered_address(4, 255))
    def test_unknown_address_kind(self): reject(self, w.parse_address, self.altered_address(5, 2))

    def test_malformed_addresses(self):
        for s in ['', '4Monero', w.address(self.a, 1).upper(), w.address(self.a, 1)+'00', w.address(self.a, 1)[:-2], 'PCdv1-'+'z'*148]:
            reject(self, w.parse_address, s)

    def test_altered_checksum(self):
        a=w.address(self.a,1); reject(self,w.parse_address,a[:-1]+('0' if a[-1]!='0' else '1'))

    def test_invalid_point_and_scalar(self):
        for p in ['00'*32, '01'+'00'*31, 'ff'*32, 'ab'*31]: reject(self,w.crypto,'check',p)
        reject(self,w.crypto,'address','ff'*32,self.a['public'],0)

    def test_invalid_recovery_material(self):
        for seed in ['00'*32, '12'*31, 'zz'*32, None, 'AB'*32]: reject(self,w.full,seed if seed is not None else 'invalid')
        for key, val in [('version',2),('network','monero'),('schemes',[1,2,1]),('count',10001),('count',True),('seed','00')]:
            r=w.recovery(self.a);r[key]=val;reject(self,w.restore,r)

    def test_unknown_wallet_versions_schemes(self):
        for key,val in [('version',255),('version',True),('schemes',[1,255,1]),('schemes',[True,1,1]),('network','mainnet')]:
            a=copy.deepcopy(self.a);a[key]=val;reject(self,w.validate,a)

    def test_truncated_and_inconsistent_serialized_keys(self):
        for key in ['seed','view','public']:
            a=copy.deepcopy(self.a);a[key]=a[key][:-2];reject(self,w.validate,a)
        a=copy.deepcopy(self.a);a['view']=self.b['view'];reject(self,w.validate,a)

    def test_view_authority_minimal(self):
        v=w.view_export(self.a); self.assertIsNone(v['seed']);self.assertEqual(v['outputs'],[])
        self.assertEqual(w.address(self.a,3),w.address(v,3));self.assertEqual(w.wallet_id(self.a),w.wallet_id(v))
        reject(self,w.recovery,v)

    def test_view_cannot_prove_ownership(self):
        v=w.view_export(self.a);reject(self,w.prove,v,self.o)
        # Bypassing Python authority label cannot replace b with a or another b.
        for secret in [v['view'],w.crypto('derive',self.b['seed'])[0]]:
            reject(self,w.crypto,'prove',v['view'],v['public'],v['count'],self.o['R'],self.o['P'],self.o['index'],secret)

    def test_forged_full_authority_rejected(self):
        v=w.view_export(self.a);v['authority']='full';reject(self,w.validate,v)
        v['seed']=self.b['seed'];reject(self,w.validate,v)

    def test_full_primary_and_subaddress_authority(self):
        for i in range(4): self.assertEqual(w.prove(self.a,w.output(w.address(self.a,i),1,i)), 'verified')

    def test_single_output_detection(self):
        self.assertEqual(w.owner(self.a,self.o),1);self.assertEqual(w.owner(self.b,self.o),-1)

    def test_address_range_recovery_hint(self):
        outside=w.output(w.address(self.a,5),1)
        a=copy.deepcopy(self.a);self.assertEqual(w.owner(a,outside),-1)
        a['count']=6;self.assertEqual(w.owner(a,outside),5)
        restored=w.restore(w.recovery(a));self.assertEqual(w.owner(restored,outside),5)

    def test_many_multiple_wallet_restore_view_false_positives(self):
        outputs=[w.output(w.address(self.a if i%2==0 else self.b,i%4),i+1,i) for i in range(64)]
        for wallet, parity in [(self.a,0),(self.b,1),(w.restore(w.recovery(self.a)),0),(w.view_export(self.a),0)]:
            matches=[i for i,o in enumerate(outputs) if w.owner(wallet,o)>=0]
            self.assertEqual(matches,list(range(parity,64,2)))
        foreign=fixture(2);self.assertFalse(any(w.owner(foreign,o)>=0 for o in outputs))

    def test_output_future_scheme_network_and_point_rejected(self):
        for key,val in [('version',2),('ownership',255),('viewing',255),('network','main'),('index',-1),('amount',True),('P','00'*32),('R','ff'*32)]:
            o=dict(self.o);o[key]=val;reject(self,w.owner,self.a,o)

    def test_replay_deduplicated_and_amount_untrusted(self):
        a=copy.deepcopy(self.a);w.scan(a,[self.o,self.o]);self.assertEqual(len(a['outputs']),1)
        changed=dict(self.o,amount=999);w.scan(a,[changed]);self.assertEqual(len(a['outputs']),1)
        self.assertIsNone(w.summary(a)['spendable_balance'])

    def test_encryption_randomized_authenticated(self):
        first=w.seal(self.a,PASSWORD,'wallet');second=w.seal(self.a,PASSWORD,'wallet');self.assertNotEqual(first,second)
        self.assertEqual(w.open_sealed(first,PASSWORD,'wallet'),self.a)
        for secret in SECRETS: self.assertNotIn(secret,first)

    def test_wrong_password(self): reject(self,w.open_sealed,w.seal(self.a,PASSWORD,'wallet'),b'wrong-password-for-test','wallet')

    def test_separate_view_capability_password(self):
        viewer_password=b'disposable-scan-only-password';SECRETS.append(viewer_password)
        capability=w.seal(w.view_export(self.a),viewer_password,'view')
        self.assertEqual(w.open_sealed(capability,viewer_password,'view')['authority'],'view')
        reject(self,w.open_sealed,capability,PASSWORD,'view')
        reject(self,w.open_sealed,w.seal(self.a,PASSWORD,'wallet'),viewer_password,'wallet')

    def test_corrupted_truncated_wallet(self):
        raw=w.seal(self.a,PASSWORD,'wallet')
        for bad in [b'',raw[:20],raw[:-1],b'{}',raw+b'junk']: reject(self,w.open_sealed,bad,PASSWORD,'wallet')
        obj=w.decode(raw);obj['ciphertext']=('00' if obj['ciphertext'][:2]!='00' else '01')+obj['ciphertext'][2:]
        reject(self,w.open_sealed,w.canonical(obj),PASSWORD,'wallet')

    def test_header_authentication_and_kdf_bounds(self):
        raw=w.seal(self.a,PASSWORD,'wallet')
        for key,val in [('version',2),('kind','view'),('network','main'),('kdf','argon2id-unbounded'),('nonce','00'*24),('salt','00'*16)]:
            obj=w.decode(raw);obj[key]=val;reject(self,w.open_sealed,w.canonical(obj),PASSWORD,'wallet')
        reject(self,w.open_sealed,raw,PASSWORD,'recovery')

    def test_duplicate_fields_and_extra_fields(self):
        reject(self,w.decode,b'{"version":1,"version":2}')
        a=dict(self.a,spend='malicious');reject(self,w.validate,a)

    def test_persistence_restart_cache(self):
        with tempfile.TemporaryDirectory(prefix='pc-phase2-') as directory:
            path=Path(directory)/'a.wallet';a=copy.deepcopy(self.a);w.scan(a,[self.o]);w.save(path,a,PASSWORD)
            self.assertEqual(w.load(path,PASSWORD),a);self.assertEqual(path.stat().st_mode & 0o777,0o600)
            reject(self,w.save,path,a,PASSWORD)

    def test_private_permissions_symlink_and_invalid_cache(self):
        with tempfile.TemporaryDirectory(prefix='pc-phase2-') as directory:
            path=Path(directory)/'a.wallet';w.save(path,self.a,PASSWORD);path.chmod(0o644);reject(self,w.load,path,PASSWORD)
            path.chmod(0o600);link=path.with_name('link.wallet');link.symlink_to(path);reject(self,w.load,link,PASSWORD)
            bad=copy.deepcopy(self.b);bad['outputs']=[self.o];reject(self,w.validate,bad)

    def test_interrupted_persistence_real_sigkill(self):
        with tempfile.TemporaryDirectory(prefix='pc-phase2-') as directory:
            path=Path(directory)/'a.wallet';w.save(path,self.a,PASSWORD)
            for stage,count in [('before_publish',4),('after_publish',5)]:
                # Child receives password over stdin, no secret argv/environment.
                code = ('import sys,os,signal;sys.path.insert(0,sys.argv[1]);import wallet as w;'
                        'p=sys.stdin.buffer.read();a=w.load(sys.argv[2],p);a["count"]=5;'
                        'w.save(sys.argv[2],a,p,True,lambda stage: os.kill(os.getpid(),signal.SIGKILL) '
                        'if stage==sys.argv[3] else None)')
                p=subprocess.run([sys.executable,'-c',code,str(ROOT/'src/wallet'),str(path),stage],input=PASSWORD,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.assertEqual(p.returncode,-signal.SIGKILL);self.assertEqual(w.load(path,PASSWORD)['count'],count)
            for p in Path(directory).glob('.pcwallet-*.tmp'):
                self.assertNotIn(self.a['seed'].encode(),p.read_bytes())

def demo():
    checks=[];commands=[]
    def check(name,condition):
        if not condition: raise AssertionError(name)
        checks.append(name)
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase2-live-') as directory:
        d=Path(directory); password=d/'demo.password';password.write_bytes(os.urandom(32).hex().encode());password.chmod(0o600)
        SECRETS.append(password.read_bytes())
        viewer_password=d/'viewer.password';viewer_password.write_bytes(os.urandom(32).hex().encode());viewer_password.chmod(0o600)
        SECRETS.append(viewer_password.read_bytes())
        A,B,V=d/'A.wallet',d/'B.wallet',d/'view.wallet'
        def cli(command, wallet=None, expect=0, password_path=None, **args):
            cmd=[sys.executable,str(ROOT/'scripts/phase2/privacycoin-wallet'),command]
            if wallet: cmd += ['--wallet',str(wallet),'--password-file',str(password_path or (viewer_password if wallet==V else password))]
            for key,val in args.items():cmd += ['--'+key.replace('_','-'),str(val)]
            p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
            commands.append(dict(argv=cmd,exit_code=p.returncode))
            if p.returncode!=expect:raise AssertionError('CLI command failed: '+command)
            return json.loads(p.stdout) if p.stdout else None
        a=cli('create',A);b=cli('create',B);remember(w.load(A,password.read_bytes()));remember(w.load(B,password.read_bytes()))
        check('A/B independent CSPRNG wallets',a['wallet_id']!=b['wallet_id'])
        addresses={}
        for name,wallet in [('A',A),('B',B)]:
            addresses[name]=[cli('address',wallet,index=i)['address'] for i in range(3)]
        check('multiple canonical Privacy Coin addresses',all(w.parse_address(x) for rows in addresses.values() for x in rows))
        recovery=d/'A.wallet-backup';cli('backup',A,file=recovery)
        outputs=[]
        for i in range(12):
            f=d/f'output-{i}.json';cli('fixture-output',file=f,destination=addresses['A' if i%2==0 else 'B'][i%3],amount=i+1,index=i)
            outputs.extend(json.loads(f.read_text()))
        all_outputs=d/'public-fixtures.json';all_outputs.write_text(json.dumps(outputs))
        a=cli('scan',A,file=all_outputs);b=cli('scan',B,file=all_outputs)
        check('A identifies exactly A outputs',a['detected_outputs']==6 and a['detected_fixture_amount']==36)
        check('B identifies exactly B outputs',b['detected_outputs']==6 and b['detected_fixture_amount']==42)
        a_loaded=w.load(A,password.read_bytes());b_loaded=w.load(B,password.read_bytes())
        check('A exact output identity set', {w.output_id(o) for o in a_loaded['outputs']}=={w.output_id(o) for o in outputs[::2]})
        check('B exact output identity set', {w.output_id(o) for o in b_loaded['outputs']}=={w.output_id(o) for o in outputs[1::2]})
        check('fresh process restart retains A state',cli('balance',A)==a)
        capability=d/'A.capability'
        cli('view-export',A,expect=1,file=capability,export_password_file=password)
        check('view export rejects full password reuse',not capability.exists())
        cli('view-export',A,file=capability,export_password_file=viewer_password);cli('view-import',V,file=capability)
        cli('balance',A,expect=1,password_path=viewer_password);check('viewer password cannot unlock full wallet',True)
        cli('balance',V,expect=1,password_path=password);check('full wallet password does not unlock delegated view file',True)
        v=cli('scan',V,file=all_outputs)
        check('fresh view wallet detects A only',v['detected_outputs']==6 and v['detected_fixture_amount']==36 and v['authority']=='view')
        check('view exact A output identity set',{w.output_id(o) for o in w.load(V,viewer_password.read_bytes())['outputs']}=={w.output_id(o) for o in outputs[::2]})
        first=d/'one-public-output.json';first.write_text(json.dumps([outputs[0]]))
        check('full wallet proves one-time ownership',cli('ownership-proof',A,file=first)['ownership_proof']=='verified')
        cli('ownership-proof',V,expect=1,file=first);check('view-only ownership/spend authority rejected',True)
        cli('backup',V,expect=1,file=d/'forbidden.wallet-backup');check('view-only full recovery export rejected',True)
        before=w.load(A,password.read_bytes());remember(before)
        A.unlink();A.with_name(A.name+'.lock').unlink();check('A local working state destroyed',not A.exists())
        restored=cli('restore',A,file=recovery)
        check('restored key identity and address range',restored['wallet_id']==a['wallet_id'] and restored['address_count']==3)
        for i,expected in enumerate(addresses['A']):check('restored address '+str(i),cli('address',A,index=i)['address']==expected)
        check('recovery excludes rebuildable history',cli('balance',A)['detected_outputs']==0)
        after=cli('scan',A,file=all_outputs);check('restore plus rescan identical state',after==a)
        check('restored secret hierarchy identical',w.load(A,password.read_bytes())==before)
        # Capture fingerprints only; no backup, capability, password or raw keys.
        return dict(result='PASS',checks=checks,checks_passed=len(checks),commands=commands,
                    wallet_A_id=a['wallet_id'],wallet_B_id=b['wallet_id'],
                    address_fingerprints={k:[hashlib.sha256(x.encode()).hexdigest() for x in v] for k,v in addresses.items()},
                    public_fixture_sha256=hashlib.sha256(all_outputs.read_bytes()).hexdigest(),
                    transaction_implementation='none; upstream one-time key authority proof only')

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    previous=[OUT/name for name in ['unit-results.json','live-results.json'] if (OUT/name).exists()]
    if previous:
        archive=OUT/'attempts'/str(time.time_ns());archive.mkdir(parents=True)
        for path in previous:shutil.copy2(path,archive/path.name)
    started=time.monotonic();result=unittest.TestResult();suite=unittest.defaultTestLoader.loadTestsFromTestCase(Foundation)
    names=[x.id() for x in suite];suite.run(result)
    record=dict(result='PASS' if result.wasSuccessful() else 'FAIL',tests_run=result.testsRun,
                tests_passed=result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
                names=names,skipped=[(x.id(),reason) for x,reason in result.skipped],
                failures=[x.id() for x,_ in result.failures],errors=[x.id() for x,_ in result.errors],
                duration_seconds=time.monotonic()-started,
                helper_sha256=hashlib.sha256(w.HELPER.read_bytes()).hexdigest(),
                cli_sha256=hashlib.sha256((ROOT/'src/wallet/wallet.py').read_bytes()).hexdigest())
    # Tracebacks are deliberately not evidence: assertion diffs may expose keys.
    if not result.wasSuccessful():
        raw=w.canonical(record)
        assert not any(secret in raw for secret in SECRETS)
        (OUT/'unit-results.json').write_bytes(raw+b'\n')
        print(json.dumps(record,indent=2));raise SystemExit(1)
    live=demo()
    encoded=[('unit-results.json',w.canonical(record)),('live-results.json',w.canonical(live))]
    for _,raw in encoded:
        for secret in SECRETS:
            if secret and secret in raw:raise AssertionError('secret detected in evidence')
    for name,raw in encoded:(OUT/name).write_bytes(raw+b'\n')
    print('PASS',record['tests_passed'],'foundation tests;',live['checks_passed'],'live CLI checks; no secret streams recorded')

if __name__=='__main__':main()
