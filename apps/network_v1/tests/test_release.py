import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile

from apps.network_v1.index import Index
from apps.network_v1.release import archive, verify, install, source_files, upstream_files
from experiments.sphlib.stage import replacements


class ReleaseTests(unittest.TestCase):
    def test_unused_restrictive_fixtures_excluded_without_changing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            values={'CMakeLists.txt':b'public', 'external/rapidjson/license.txt':b'KEEP NOTICE',
                    'external/rapidjson/include/rapidjson/document.h':b'public header',
                    'external/rapidjson/bin/jsonchecker/fail1.json':b'RESTRICTED FIXTURE',
                    'external/rapidjson/bin/jsonchecker/readme.txt':b'RESTRICTED NOTICE',
                    'external/rapidjson/test/unittest/jsoncheckertest.cpp':b'UNUSED TEST'}
            values.update({n:b for n,b in replacements().items() if n in ('src/crypto/jh.c','src/crypto/jh.h','src/crypto/keccak.c','src/crypto/keccak.h')})
            for name,raw in values.items():
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
            files=upstream_files(root)
            self.assertEqual(len(files),3+len(replacements()))
            self.assertEqual(files['.upstream/monero/external/rapidjson/license.txt'],b'KEEP NOTICE')
            for name,raw in values.items():self.assertEqual((root/name).read_bytes(),raw)

    def test_unverified_unused_builder_helpers_excluded_but_production_crypto_retained(self):
        from apps.network_v1.release import upstream_files,UPSTREAM_SOURCE_EXCLUSIONS
        with tempfile.TemporaryDirectory(prefix='pc-license-builder-scope-') as tmp:
            root=Path(tmp)
            values={n:b'historical helper preserved locally' for n in UPSTREAM_SOURCE_EXCLUSIONS}
            values.update({'CMakeLists.txt':b'public fixture',
                'src/crypto/crypto-ops.c':b'delivered production source',
                'src/crypto/crypto_ops_builder/README.md':b'keep attribution',
                'src/crypto/crypto_ops_builder/ref10/README.md':b'keep upstream grant'})
            values.update({n:b for n,b in replacements().items() if n in ('src/crypto/jh.c','src/crypto/jh.h','src/crypto/keccak.c','src/crypto/keccak.h')})
            for n,b in values.items():
                p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
            files=upstream_files(root)
            for n in UPSTREAM_SOURCE_EXCLUSIONS:self.assertNotIn('.upstream/monero/'+n,files)
            self.assertIn('.upstream/monero/src/crypto/crypto-ops.c',files)
            self.assertIn('.upstream/monero/src/crypto/crypto_ops_builder/README.md',files)
            for n,b in values.items():self.assertEqual((root/n).read_bytes(),b)
            (root/'src/crypto/jh.c').write_bytes(b'unreviewed replacement')
            with self.assertRaisesRegex(ValueError,'UNREVIEWED_CRYPTO_UPSTREAM'):upstream_files(root)
    @unittest.skipUnless(os.name=='posix','POSIX no-follow installation')
    def test_new_private_parent_under_readable_home_and_symlink_rejection(self):
        from apps.network_v1.release import create_private_parent
        with tempfile.TemporaryDirectory(dir=Path.home(),prefix='pc-v1-install-parent-') as tmp:
            base=Path(tmp);base.chmod(0o755);destination=base/'private'/'candidate'
            create_private_parent(destination);self.assertEqual((base/'private').stat().st_mode&0o777,0o700)
            link=base/'alias';link.symlink_to(base/'private',target_is_directory=True)
            with self.assertRaises(OSError):create_private_parent(link/'unexpected'/'candidate')
            self.assertFalse((base/'private/unexpected').exists())
            base.chmod(0o777)
            with self.assertRaises(ValueError):create_private_parent(base/'unsafe'/'candidate')
    def test_browser_assets_in_source_inclusion(self):
        files=source_files()
        for name in ('index.html','app.js','style.css'):
            self.assertIn('apps/network_v1/web/'+name,files)
        self.assertIn(b'/app.js',files['apps/network_v1/web/index.html'])

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path.home(),prefix='pc-v1-release-fixture-')
        self.root=Path(self.temp.name);self.root.chmod(0o700)
    def tearDown(self):self.temp.cleanup()

    def test_determinism_integrity_collision_traversal(self):
        a=self.root/'a.zip';b=self.root/'b.zip'
        files={'apps/demo.py':b'print("public")\n','docs/demo.md':b'Public source\n'}
        self.assertEqual(archive(a,files,'source'),archive(b,dict(reversed(list(files.items()))),'source'))
        self.assertEqual(verify(a)['kind'],'source')
        with self.assertRaises(ValueError):archive(self.root/'collision.zip',{'X.py':b'a','x.py':b'b'},'source')
        with self.assertRaises(ValueError):archive(self.root/'path.zip',{'../secret.py':b'a'},'source')
        with self.assertRaises(ValueError):archive(self.root/'secret.zip',{'wallet.wallet':b'a'},'source')
        # A tampered member changes payload but leaves original manifest intact.
        c=self.root/'tampered.zip'
        with zipfile.ZipFile(a) as src,zipfile.ZipFile(c,'x') as dst:
            for name in src.namelist():dst.writestr(name,b'changed' if name.endswith('.py') else src.read(name))
        with self.assertRaises(ValueError):verify(c)

    def test_foreign_database_rejected_without_modification(self):
        p=self.root/'provider.sqlite';db=sqlite3.connect(p)
        db.execute('CREATE TABLE config(version INTEGER)');db.commit();db.close()
        before=hashlib.sha256(p.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):Index(p,None)
        self.assertEqual(before,hashlib.sha256(p.read_bytes()).hexdigest())

    @unittest.skipUnless(os.name=='posix','Private installer requires POSIX/WSL')
    def test_install_no_clobber_and_interruption(self):
        from src.phase6a import wallet as c
        from unittest.mock import patch
        artifact=self.root/'source.zip';archive(artifact,{'demo.py':b'print(1)\n','public-large.dat':b'x'*(5*1024*1024)},'source')
        destination=self.root/'installed';install(artifact,destination)
        self.assertTrue((destination/'INSTALL_COMPLETE.json').is_file())
        self.assertEqual((destination/'public-large.dat').stat().st_size,5*1024*1024)
        with self.assertRaises(ValueError):install(artifact,destination)
        interrupted=self.root/'interrupted';writer=c.write_private
        def fault(path,raw,*args,**kw):
            if Path(path).name=='demo.py':raise OSError('SYNTHETIC_INTERRUPTION')
            return writer(path,raw,*args,**kw)
        with patch.object(c,'write_private',side_effect=fault):
            with self.assertRaises(OSError):install(artifact,interrupted)
        self.assertFalse((interrupted/'INSTALL_COMPLETE.json').exists())
        with self.assertRaises(ValueError):install(artifact,interrupted)
        target=self.root/'link';target.symlink_to(destination,target_is_directory=True)
        with self.assertRaises(ValueError):install(artifact,target)


if __name__=='__main__':unittest.main()
