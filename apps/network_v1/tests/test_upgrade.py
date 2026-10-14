"""Upgrade metadata tests, separate from actual installed upgrade acceptance."""
import json,os,tempfile,unittest
from pathlib import Path

@unittest.skipUnless(os.name=='posix','POSIX data locks and private files')
class UpgradeTests(unittest.TestCase):
    def setUp(self):
        from apps.network_v1.desktop_backend import c
        from apps.network_v1.upgrade import BINARIES,compatible,digest
        from apps.network_v1.rpc import NETWORK,GENESIS,PROFILE,VERSION
        self.c=c;self.compatible=compatible;self.tmp=tempfile.TemporaryDirectory(dir=Path.home(),prefix='pc-v1-rc5-upgrade-');self.base=Path(self.tmp.name);self.base.chmod(0o700)
        self.roots=[self.base/'old',self.base/'new'];self.binaries=BINARIES
        for i,root in enumerate(self.roots):
            root.mkdir(mode=0o700);hashes={}
            for name in BINARIES:
                p=root/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);c.write_private(p,b'public-test-binary')
                hashes[name]=digest(c,p)
            m=dict(format=1,kind='linux-x86_64',version='1.0.0-testnet-candidate.4' if i==0 else VERSION,network=NETWORK,genesis=GENESIS,profile=PROFILE,files=hashes)
            c.write_private(root/'V1_MANIFEST.json',c.f.canonical(m));c.write_private(root/'INSTALL_COMPLETE.json',c.f.canonical(dict(kind=m['kind'],version=m['version'])))
        self.data=self.base/'data';self.data.mkdir(mode=0o700);(self.data/'wallets').mkdir(mode=0o700)
        marker=dict(version=1,role='ISOLATED_V1_DESKTOP',rpc=34381,p2p=34382)
        if NETWORK=='PrivacyCoinDev02':marker.update(network=NETWORK,profile=PROFILE)
        c.write_private(self.data/'PRODUCT_V1.json',c.f.canonical(marker))
    def tearDown(self):self.tmp.cleanup()
    def check(self):return self.compatible(*self.roots,self.data)
    def test_same_native_binary_no_data_migration_and_active_old_lock(self):
        before=self.c.read_private(self.data/'PRODUCT_V1.json');self.assertTrue(self.check()['compatible'])
        self.assertEqual(self.c.read_private(self.data/'PRODUCT_V1.json'),before)
        with self.c.lock(self.data/'desktop'):
            with self.assertRaises(BlockingIOError):self.check()
    def test_changed_binary_tamper_wrong_network_and_symlink_reject(self):
        from apps.network_v1.upgrade import digest
        p=self.roots[1]/self.binaries[0];self.c.write_private(p,b'changed',replace=True)
        with self.assertRaises(ValueError):self.check()
        m=self.c.f.decode(self.c.read_private(self.roots[1]/'V1_MANIFEST.json'));m['files'][self.binaries[0]]=digest(self.c,p)
        self.c.write_private(self.roots[1]/'V1_MANIFEST.json',self.c.f.canonical(m),replace=True)
        with self.assertRaisesRegex(ValueError,'BINARY_CHANGE'):self.check()
        m['genesis']='f'*64;self.c.write_private(self.roots[1]/'V1_MANIFEST.json',self.c.f.canonical(m),replace=True)
        with self.assertRaises(ValueError):self.check()
        link=self.base/'alias';link.symlink_to(self.data,target_is_directory=True)
        with self.assertRaises((OSError,ValueError)):self.compatible(*self.roots,link)

if __name__=='__main__':unittest.main()
