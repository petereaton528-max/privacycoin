"""Real secure-file and encrypted-object backup container tests.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,importlib.util,os,tempfile,unittest,zipfile
from pathlib import Path
from apps.network_v1 import portable_backup as b
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('backup_secure',ROOT/'src/phase6a/wallet.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
class Portable(unittest.TestCase):
    def test_default_folder_in_normal_home_preserves_parent_permissions(self):
        self.home.chmod(0o750)
        folder=b.default_directory(c,self.home)
        self.assertEqual(self.home.stat().st_mode&0o777,0o750)
        self.assertEqual(folder.stat().st_mode&0o777,0o700)
        self.assertEqual(b.default_directory(c,self.home),folder)
        b.pack(c,folder/'backup',b'ciphertext',[])
        with self.assertRaisesRegex(ValueError,'private directory required'):b.pack(c,self.home/'unsafe',b'ciphertext',[])
    def test_default_folder_refuses_existing_shared_folder_without_chmod(self):
        folder=self.home/'PrivacyCoin-Backups';folder.mkdir();folder.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'private directory required'):b.default_directory(c,self.home)
        self.assertEqual(folder.stat().st_mode&0o777,0o755)
    def test_default_folder_refuses_symlink(self):
        (self.home/'PrivacyCoin-Backups').symlink_to(self.home,target_is_directory=True)
        with self.assertRaises(OSError):b.default_directory(c,self.home)
    def test_default_folder_refuses_writable_shared_home(self):
        self.home.chmod(0o770)
        with self.assertRaisesRegex(ValueError,'BACKUP_PRIVATE_FOLDER_REQUIRED'):b.default_directory(c,self.home)
        self.assertFalse((self.home/'PrivacyCoin-Backups').exists())
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='pc-backup-test-');self.home=Path(self.tmp.name);self.path=self.home/'backup'
    def tearDown(self):self.tmp.cleanup()
    def test_complete_encrypted_roundtrip(self):
        root=c.f.seal({'test':'root'},b'disposable-password','backup-test');page=c.f.seal({'test':'page'},b'disposable-password','page-test');digest=hashlib.sha256(page).hexdigest()
        b.pack(c,self.path,root,[(digest,page)])
        with b.opened(c,self.path) as p:
            self.assertEqual(c.f.open_sealed(c.read_private(p),b'disposable-password','backup-test'),{'test':'root'})
            self.assertEqual(c.read_private(Path(str(p)+'.pages')/(digest+'.page')),page)
        self.assertFalse(Path(str(self.path)+'.pages').exists());self.assertEqual(self.path.stat().st_mode&0o777,0o600)
    def test_publication_failure_leaves_no_destination_or_temporary(self):
        def pages():yield 'a'*64,b'page';raise RuntimeError('interrupted')
        with self.assertRaises(RuntimeError):b.pack(c,self.path,b'root',pages())
        self.assertEqual(list(self.home.iterdir()),[])
    def test_existing_backup_is_never_overwritten(self):
        b.pack(c,self.path,b'original',[]);before=self.path.read_bytes()
        with self.assertRaises(FileExistsError):b.pack(c,self.path,b'new',[])
        self.assertEqual(self.path.read_bytes(),before);self.assertEqual(len(list(self.home.iterdir())),1)
    def test_legacy_envelope_supported(self):
        c.write_private(self.path,b'legacy');
        with b.opened(c,self.path) as p:self.assertEqual(p,self.path)
    def test_unsafe_archive_entries_rejected(self):
        for name in ('../wallet','/absolute','pages/not-a-digest.page'):
            with self.subTest(name=name):
                with zipfile.ZipFile(self.path,'w') as z:z.writestr('recovery',b'root');z.writestr(name,b'bad')
                self.path.chmod(0o600)
                with self.assertRaises(ValueError):
                    with b.opened(c,self.path):pass
    def test_compression_bomb_refused(self):
        with zipfile.ZipFile(self.path,'w',compression=zipfile.ZIP_DEFLATED) as z:z.writestr('recovery',b'0'*10000)
        self.path.chmod(0o600)
        with self.assertRaises(ValueError):
            with b.opened(c,self.path):pass
    def test_symlink_refused(self):
        original=self.home/'original';c.write_private(original,b'root');self.path.symlink_to(original)
        with self.assertRaises(OSError):
            with b.opened(c,self.path):pass
    def test_over_capacity_not_published(self):
        with self.assertRaises(ValueError):b.pack(c,self.path,b'0'*(b.MAX_ENTRY+1),[])
        self.assertFalse(self.path.exists())
    def test_excessive_entry_count_rejected_before_zip_allocation(self):
        import struct
        from unittest.mock import patch
        b.pack(c,self.path,b'root',[]);raw=bytearray(self.path.read_bytes())
        end=raw.rfind(b'PK\x05\x06');struct.pack_into('<HH',raw,end+8,60000,60000);self.path.write_bytes(raw)
        with patch.object(b.zipfile,'ZipFile',side_effect=AssertionError('allocated entries')):
            with self.assertRaisesRegex(ValueError,'BACKUP_DIRECTORY_BOUND'):
                with b.opened(c,self.path):pass
if __name__=='__main__':unittest.main()
