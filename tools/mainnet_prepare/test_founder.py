"""Disposable-only tests; never invoke owner key creation.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json,os,secrets,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from . import founder as x

class FounderTests(unittest.TestCase):
    def setUp(self):
        os.umask(0o077)
        self.tmp=tempfile.TemporaryDirectory(prefix='pc-disposable-founder-',dir='/home/privacydev')
        self.home=Path(self.tmp.name);self.pw=secrets.token_bytes(32)
        self.profile=self.home/'original'
        self.pub=x.create(self.profile,self.pw,purpose='DISPOSABLE_TEST')
    def tearDown(self):self.tmp.cleanup()
    def reject(self,fn):
        with self.assertRaises((ValueError,OSError,TypeError)):fn()
    def test_two_complete_backups_independent_recovery(self):
        hashes=[x.backup(self.profile,self.home/('backup'+str(i)),self.pw) for i in (1,2)]
        self.assertNotEqual(*hashes)
        for i in (1,2):self.assertEqual(x.recover(self.home/('backup'+str(i)),self.home/('recovered'+str(i)),self.pw),self.pub)
        self.assertEqual(sorted(p.name for p in self.profile.iterdir()),['PUBLIC-RECIPIENT.json','founder.encrypted'])
    def test_wrong_password_no_profile(self):
        self.reject(lambda:x.recover(self.profile/'founder.encrypted',self.home/'bad',b'wrong-password-long-enough'))
        self.assertFalse((self.home/'bad').exists())
    def test_corrupt_and_truncated_backup(self):
        raw=x.read(self.profile/'founder.encrypted')
        for i,data in enumerate((raw[:-20],raw[:len(raw)//2],raw[:-2]+b'xx')):
            path=self.home/str(i);x.write(path,data);self.reject(lambda:x.decrypt(path,self.pw))
    def test_authenticated_ciphertext_tamper(self):
        value=json.loads(x.read(self.profile/'founder.encrypted'));key=next(k for k in value if 'cipher' in k)
        value[key]=('0' if value[key][0]!='0' else '1')+value[key][1:]
        path=self.home/'tampered';x.write(path,x.f.canonical(value));self.reject(lambda:x.decrypt(path,self.pw))
    def test_network_and_spec_mismatch(self):
        value=x.decrypt(self.profile/'founder.encrypted',self.pw)
        for key in ('network_tag','specification_sha256'):
            bad=dict(value);bad[key]='0'*64;self.reject(lambda:x.validate(bad))
    def test_public_key_mismatch(self):
        value=x.decrypt(self.profile/'founder.encrypted',self.pw);value['public']=dict(public_spend='0'*64,public_view='0'*64)
        self.reject(lambda:x.validate(value))
    def test_no_overwrite(self):
        before=x.read(self.profile/'founder.encrypted')
        self.reject(lambda:x.create(self.profile,self.pw,purpose='DISPOSABLE_TEST'))
        self.reject(lambda:x.recover(self.profile/'founder.encrypted',self.profile,self.pw))
        self.reject(lambda:x.backup(self.profile,self.profile/'founder.encrypted',self.pw))
        self.assertEqual(before,x.read(self.profile/'founder.encrypted'))
    def test_symlink_directory_and_file(self):
        link=self.home/'link';link.symlink_to(self.profile,target_is_directory=True)
        self.reject(lambda:x.read(link/'founder.encrypted'))
        file=self.home/'file';file.symlink_to(self.profile/'founder.encrypted');self.reject(lambda:x.read(file))
    def test_hardlink(self):
        file=self.home/'hardlink';os.link(self.profile/'founder.encrypted',file);self.reject(lambda:x.read(file))
    def test_permissions(self):
        self.assertEqual(self.profile.stat().st_mode&0o777,0o700)
        for file in self.profile.iterdir():self.assertEqual(file.stat().st_mode&0o777,0o600)
        self.profile.chmod(0o755);self.reject(lambda:x.read(self.profile/'founder.encrypted'));self.profile.chmod(0o700)
    def test_repository_and_windows_destinations(self):
        self.reject(lambda:x.directory(x.ROOT));self.reject(lambda:x.directory(Path('/mnt/c/Users')))
        (self.home/'.git').mkdir();self.reject(lambda:x.directory(self.home))
    def test_no_genesis_no_address_no_plaintext_secret(self):
        self.assertIsNone(self.pub['genesis']);self.assertIsNone(self.pub['receiving_address']);self.assertFalse(self.pub['recipient_approved'])
        secret=x.decrypt(self.profile/'founder.encrypted',self.pw)['master_seed'].encode()
        for file in self.profile.iterdir():self.assertNotIn(secret,file.read_bytes());self.assertNotIn(self.pw,file.read_bytes())
    def test_unique_os_random_keys(self):
        other=x.create(self.home/'other',self.pw,purpose='DISPOSABLE_TEST')
        self.assertNotEqual(self.pub['public_spend'],other['public_spend']);self.assertNotEqual(self.pub['public_view'],other['public_view'])
    def test_entropy_failure_has_no_fallback(self):
        with patch.object(x.secrets,'token_hex',side_effect=OSError('unavailable')):
            self.reject(lambda:x.create(self.home/'no-entropy',self.pw,purpose='DISPOSABLE_TEST'))
        self.assertFalse((self.home/'no-entropy').exists())
    def test_unknown_purpose_and_schema(self):
        self.reject(lambda:x.create(self.home/'unknown',self.pw,purpose='UNKNOWN'))
        value=x.decrypt(self.profile/'founder.encrypted',self.pw);value['unexpected']=True
        self.reject(lambda:x.validate(value))
    def test_no_genesis_circularity(self):
        value=x.decrypt(self.profile/'founder.encrypted',self.pw)
        from tools.creator_model.binding import GenesisAddress
        for g in ('b'*64,'c'*64):
            b=GenesisAddress(x.f,x.context(),g,'PCmn1-');w=b.wallet(value['master_seed'])
            D,C,sub=b.parse(b.address(w));self.assertEqual((D,C,sub),(self.pub['public_spend'],self.pub['public_view'],False))
            self.assertEqual(len(b.address(w)),293)
    def test_devnet_recovery_rejected(self):
        raw=x.f.seal(dict(master_seed=secrets.token_hex(32)),self.pw,'wallet');path=self.home/'devnet';x.write(path,raw)
        self.reject(lambda:x.decrypt(path,self.pw))
    def test_password_and_terminal_guards(self):
        self.reject(lambda:x.create(self.home/'short',b'short',purpose='DISPOSABLE_TEST'))
        with patch('sys.stdin.isatty',return_value=False):self.reject(lambda:x.password())

if __name__=='__main__':unittest.main()
