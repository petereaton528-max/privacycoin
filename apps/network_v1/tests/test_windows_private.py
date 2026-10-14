"""Actual owner-only NTFS I/O; opaque public test bytes, no native crypto claim.

Fresh fixtures are deliberately retained for inspection. No host policy changes.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

@unittest.skipUnless(os.name=='nt','Actual Windows NTFS adapter')
class WindowsPrivateTests(unittest.TestCase):
    def setUp(self):
        from src.phase6a import wallet as c
        self.c=c;self.w=c.win
        self.root=Path(tempfile.gettempdir())/('pc-v1-win-private-'+uuid.uuid4().hex)
        self.w.mkdir(self.root,exclusive=True);self.file=self.root/'opaque'
    def test_create_replace_no_overwrite_and_rss(self):
        self.c.harden();self.c.write_private(self.file,b'public original')
        self.assertEqual(self.c.read_private(self.file),b'public original')
        with self.assertRaises(ValueError):self.c.write_private(self.file,b'public second')
        self.c.write_private(self.file,b'public replacement',replace=True)
        self.assertEqual(self.c.read_private(self.file),b'public replacement')
        self.assertGreater(self.w.rss_kib(),0)
        with self.assertRaises(OSError):self.w.mkdir(self.root,exclusive=True)
    def test_missing_size_bounds_and_hardlink_rejection(self):
        with self.assertRaises(OSError):self.c.read_private(self.file)
        with self.assertRaises(ValueError):self.w.write_private(self.file,b'12345',limit=4)
        self.w.write_private(self.file,b'12345',limit=5)
        with self.assertRaises(ValueError):self.w.read_private(self.file,limit=4)
        alias=self.root/'alias';os.link(self.file,alias)
        with self.assertRaises(ValueError):self.c.read_private(self.file)
        with self.assertRaises(ValueError):self.c.write_private(alias,b'public',replace=True)
    def test_shared_directory_and_extra_ace_rejected(self):
        shared=self.root/'shared';shared.mkdir()
        # Inherits our private ACL, then deliberately grants Everyone access to
        # this fresh EMPTY directory and public dummy. Never sensitive fixtures.
        self.assertEqual(subprocess.run(['icacls',str(shared),'/grant','*S-1-1-0:(R)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode,0)
        with self.assertRaises(ValueError):
            with self.c.directory(shared):pass
        self.c.write_private(self.file,b'public dummy')
        self.assertEqual(subprocess.run(['icacls',str(self.file),'/grant','*S-1-1-0:(R)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode,0)
        with self.assertRaises(ValueError):self.c.read_private(self.file)
    def test_paths_rejected(self):
        for value in ('relative','\\\\server\\share\\file',str(self.root/'..'/'escape'),str(self.root/'CON.txt'),str(self.root/'trailing.'),str(self.root/'file:stream')):
            with self.assertRaises((ValueError,OSError)):self.w.path(value)
    def test_junction_rejected(self):
        target=self.root/'target';self.w.mkdir(target)
        junction=self.root/'junction'
        # All paths are fresh UUID fixtures; arguments remain structured.
        code='param($link,$target) New-Item -ItemType Junction -Path $link -Target $target | Out-Null'
        script=self.root/'junction.ps1';script.write_text(code,encoding='utf-8')
        result=subprocess.run(['powershell','-NoProfile','-File',str(script),str(junction),str(target)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result.returncode:self.skipTest('Host does not permit fixture junction creation')
        with self.assertRaises(ValueError):
            with self.c.directory(junction):pass
        with self.assertRaises(ValueError):self.c.write_private(junction/'escape',b'public')
    def test_lock_exclusive_and_release(self):
        with self.c.lock(self.file):
            with self.assertRaises(OSError):
                with self.c.lock(self.file):pass
        with self.c.lock(self.file):pass
    def test_native_product_private_session_without_network_or_mining(self):
        from apps.network_v1.desktop_backend import Product
        product=Product(self.root/'product',rpc_port=45781,p2p=45782)
        try:
            result=product.session.dispatch(dict(command='hello'))
            self.assertEqual(result['wallets'],[])
            self.assertIsNone(product.node);self.assertIsNone(product.miner);self.assertFalse(product.network_enabled)
            with self.assertRaises(OSError):Product(self.root/'product',rpc_port=45781,p2p=45782)
        finally:product.close()
    def test_interrupted_publication_and_abrupt_lock_release(self):
        child='''import os,sys
from pathlib import Path
from src.phase6a import wallet as c
p=Path(sys.argv[1]);stage=sys.argv[2]
with c.lock(p):
 c.write_private(p,b'public new',replace=True,fault=lambda at:os._exit(73) if at==stage else None)
'''
        for stage in ('during_write','before_publish','after_publish'):
            target=self.root/stage;self.c.write_private(target,b'public old')
            result=subprocess.run([sys.executable,'-B','-c',child,str(target),stage],cwd=Path(__file__).resolve().parents[3],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
            self.assertEqual(result.returncode,73)
            self.assertEqual(self.c.read_private(target),b'public new' if stage=='after_publish' else b'public old')
            with self.c.lock(target):pass
    def test_native_desktop_pipe_hello_and_shutdown_without_wsl(self):
        from apps.network_v1.desktop import ProductBridge
        bridge=ProductBridge(str(Path(__file__).resolve().parents[3]),str(self.root/'pipe-product'),45881,45882)
        try:
            self.assertTrue(bridge.native_windows)
            self.assertEqual(bridge.call('hello')['wallets'],[])
            state=bridge.call('product_status')
            self.assertEqual(state['node']['state'],'STOPPED');self.assertEqual(state['mining']['state'],'DISABLED')
            self.assertEqual(state['tor']['state'],'DISABLED')
        finally:bridge.close()
        self.assertIsNotNone(bridge.process.poll())
    def test_native_tk_shell_is_labeled_preview_not_wallet_acceptance(self):
        import time
        from apps.network_v1.desktop import ProductBridge,Desktop,safe_root
        root=safe_root();root.withdraw();app=None
        bridge=ProductBridge(str(Path(__file__).resolve().parents[3]),str(self.root/'tk-product'),45981,45982)
        try:
            app=Desktop(root,bridge);deadline=time.monotonic()+10
            while app.busy and time.monotonic()<deadline:root.update();time.sleep(.01)
            self.assertFalse(app.busy);self.assertFalse(app.last_error)
            self.assertIn('Windows native preview',root.title())
            self.assertFalse(app.opened)
        finally:
            if app:app.shutdown()
            else:bridge.close();root.destroy()
    def test_windows_manifest_requires_private_adapter_and_exact_pins(self):
        import hashlib
        from unittest.mock import patch
        from apps.network_v1 import desktop_backend
        import launcher_host as host
        required=['src/phase6a/wallet.py','src/phase6a/windows_private.py','src/phase4/wallet.py','src/phase4/node.cpp','src/phase4/ledger.cpp','src/phase4/crypto.cpp','src/wallet/wallet.py','src/wallet/crypto.cpp','tests/phase4/CMakeLists.txt']
        # Opaque public stand-ins test manifest validation only. No executable
        # is run, and no simulated cryptographic acceptance is claimed.
        source={}
        for name in required:
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'public source stand-in');source[name]=hashlib.sha256(p.read_bytes()).hexdigest()
        pins={};helper=None
        for name,phase in [('privacycoin-hardened-devnet','phase4'),('privacycoin-hardened-crypto','phase4'),('privacycoin-wallet-crypto','phase2')]:
            p=self.root/'build/monero-windows'/phase/(name+'.exe');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'public binary stand-in');pins[name]=hashlib.sha256(p.read_bytes()).hexdigest()
            if phase=='phase2':helper=p
        manifest=self.root/'manifest.json';record=dict(version=1,kind='V1_LOCAL_SOURCE_BUILD',source_sha256=source,binary_sha256=pins)
        self.c.write_private(manifest,self.c.f.canonical(record))
        with patch.object(host,'NATIVE',self.root),patch.object(host.f,'HELPER',helper),patch.object(host.f,'sodium'),patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(manifest)):
            host.requirements(allow_native_linux=True)
            del source['src/phase6a/windows_private.py'];self.c.write_private(manifest,self.c.f.canonical(record),replace=True)
            with self.assertRaises(host.StartupError):host.requirements(allow_native_linux=True)
    def test_private_windows_install_large_public_artifact_without_launch(self):
        from apps.network_v1.release import archive,install,create_private_parent
        payload=b'public artifact\n'*(350000)  # >4MiB, bounded, no executable.
        package=self.root/'public-test.zip';destination=self.root/'programs'/'fresh'
        archive(package,{'runtime/public.dat':payload},'windows-native-component-test')
        create_private_parent(destination);install(package,destination)
        self.assertTrue(self.w.read_private(destination/'runtime/public.dat',limit=64*1024*1024)==payload)
        marker=self.c.f.decode(self.c.read_private(destination/'INSTALL_COMPLETE.json'))
        self.assertFalse(marker['services_started'])
        with self.assertRaises(ValueError):install(package,destination)
    def test_windows_upgrade_preflight_public_standins_preserve_originals(self):
        from apps.network_v1 import desktop_backend
        from apps.network_v1.release import archive,install
        from apps.network_v1.upgrade import compatible,BINARIES
        from apps.network_v1.rpc import VERSION
        import hashlib
        package=self.root/'public-upgrade.zip';payload={name:b'public nonexecutable binary stand-in' for name in BINARIES}
        archive(package,payload,'windows-native-x86_64')
        old=self.root/'old';new=self.root/'new';install(package,old);install(package,new)
        product=desktop_backend.Product(self.root/'data',rpc_port=46081,p2p=46082)
        with self.assertRaises(OSError):compatible(old,new,self.root/'data')
        product.close()
        before={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in old.rglob('*') if p.is_file()}
        result=compatible(old,new,self.root/'data')
        self.assertTrue(result['compatible']);self.assertEqual(result['to_version'],VERSION);self.assertFalse(result['migration_performed'])
        self.assertTrue(all(hashlib.sha256(p.read_bytes()).hexdigest()==h for p,h in before.items()))
        self.c.write_private(new/BINARIES[0],b'changed public stand-in',replace=True)
        with self.assertRaises(ValueError):compatible(old,new,self.root/'data')

if __name__=='__main__':unittest.main()
