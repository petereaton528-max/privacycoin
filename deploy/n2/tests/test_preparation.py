"""Bounded laptop-only deployment tests; no public Tor, real hosts or OS changes."""
from pathlib import Path
import contextlib,hashlib,importlib.util,io,json,os,socket,subprocess,sys,tempfile,time,unittest,zipfile
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
import bundle,role
role.bootstrap()
from common import c,f,private_dir,save_json,load_json,NATIVE
from tor_runtime import TOR
from unittest.mock import patch

class Cases(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='privacycoin-n2-test-',dir=NATIVE/'build');self.home=Path(self.tmp.name);self.home.chmod(0o700)
    def tearDown(self):self.tmp.cleanup()
    def cfg(self):return dict(version=1,devnet_only=True,role='provider',home=str(self.home/'privacycoin-n2-provider'),node_rpc=19481,node_p2p=19480,provider_port=19482,bridge_port=19483,socks_port=19450,peer_port=None)
    def test_valid_provider(self):self.assertEqual(role.validate(self.cfg(),'provider')['role'],'provider')
    def test_unknown_config_field(self):
        q=self.cfg();q['password']='NOT_A_SECRET_FIXTURE'
        with self.assertRaises(ValueError):role.validate(q,'provider')
    def test_production_flag(self):
        q=self.cfg();q['devnet_only']=False
        with self.assertRaises(ValueError):role.validate(q,'provider')
    def test_boolean_version(self):
        q=self.cfg();q['version']=True
        with self.assertRaises(ValueError):role.validate(q,'provider')
    def test_duplicate_ports(self):
        q=self.cfg();q['provider_port']=q['node_rpc']
        with self.assertRaises(ValueError):role.validate(q,'provider')
    def test_overflow_port(self):
        q=self.cfg();q['node_rpc']=65536
        with self.assertRaises(ValueError):role.validate(q,'provider')
    def test_boolean_port(self):
        q=self.cfg();q['node_rpc']=True
        with self.assertRaises(ValueError):role.validate(q,'provider')
    def test_peer_self_rejected(self):
        q=self.cfg();q['peer_port']=q['node_p2p']
        with self.assertRaises(ValueError):role.validate(q,'provider')
    def test_original_home_rejected(self):
        q=self.cfg();q['home']=str(Path.home()/'.local/share/privacycoin-network-v01')
        with self.assertRaises(ValueError):role.validate(q,'provider')
    def test_path_traversal(self):
        for p in ('relative','/tmp/../alice','/tmp/a\nDisableNetwork0','/tmp/a b'):
            with self.subTest(p=p),self.assertRaises(ValueError):role.checked_path(p)
    def test_parent_symlink_before_creation(self):
        link=self.home/'alias';link.symlink_to(self.home,target_is_directory=True)
        with self.assertRaises(ValueError):role.prepare(link/'privacycoin-n2-should-not-exist')
        self.assertFalse((self.home/'privacycoin-n2-should-not-exist').exists())
    def test_occupied_port(self):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind(('127.0.0.1',0));s.listen()
            with self.assertRaises(OSError):role.free_ports([s.getsockname()[1]])
    def test_free_port(self):role.free_ports([0])
    def test_reusable_time_wait_port(self):
        server=socket.socket();server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind(('127.0.0.1',0));port=server.getsockname()[1];server.listen()
        client=socket.create_connection(('127.0.0.1',port));accepted,_=server.accept();accepted.sendall(b'x');accepted.close();server.close()
        self.assertEqual(client.recv(1),b'x');self.assertEqual(client.recv(1),b'');client.close()
        role.free_ports([port])
    def test_prepare_no_overwrite(self):
        home=self.home/'privacycoin-n2-new'
        role.prepare(home)
        before=(home/'provider.json').read_bytes()
        with self.assertRaises(ValueError):role.prepare(home)
        self.assertEqual(before,(home/'provider.json').read_bytes())
    def test_disabled_tor_config(self):
        home=self.home/'privacycoin-n2-disabled';role.prepare(home,TOR)
        raw=(home/'tor-disabled/torrc.DISABLED').read_text()
        self.assertIn('DisableNetwork 1\n',raw);self.assertNotIn('TestingTorNetwork',raw)
        self.assertEqual((home/'provider.json').stat().st_mode&0o777,0o600)
    def test_provider_config_private(self):
        path=self.home/'config';save_json(path,self.cfg());path.chmod(0o644)
        with self.assertRaises(ValueError):role.config(path,'provider')
    def test_config_symlink(self):
        path=self.home/'config';save_json(path,self.cfg());link=self.home/'link';link.symlink_to(path)
        with self.assertRaises((ValueError,OSError)):role.config(link,'provider')
    def test_missing_tor(self):
        with self.assertRaises(ValueError):role.tor_binary(self.home/'missing')
    def test_old_tor_version(self):
        fake=subprocess.CompletedProcess([],0,b'Tor version 0.4.8.0.\n',b'')
        with patch('subprocess.run',return_value=fake),self.assertRaises(ValueError):role.tor_binary(TOR)
    def test_wrong_python_rejected_before_wallet_bootstrap(self):
        with patch.object(sys,'argv',['role.py','linux-check']),patch.object(sys,'version_info',(3,11,0)),patch.object(role,'bootstrap') as boot:
            with self.assertRaises(ValueError):role.main()
            boot.assert_not_called()
    def test_actual_tor_version(self):self.assertEqual(role.tor_binary(TOR),TOR)
    def test_client_wrong_role(self):
        with self.assertRaises(ValueError):role.validate(self.cfg(),'client')
    def test_manifest_bad_hash(self):
        m=dict(version=1,source_base_commit='test',scope='non-secret test',files={'source.py':'Z'*64})
        with self.assertRaises(ValueError):bundle.validate_manifest(m)
    def test_archive_path_rejection(self):
        for name in ('../escape','/absolute','C:/escape','x\\y','x/./y','x//y'):
            with self.subTest(name=name),self.assertRaises(ValueError):bundle.safe_name(name)
    def test_archive_traversal(self):
        p=self.home/'bad.zip'
        with zipfile.ZipFile(p,'x') as z:z.writestr('../escape','x')
        with self.assertRaises(ValueError):bundle.inspect(p)
    def test_archive_case_collision(self):
        p=self.home/'bad.zip'
        with zipfile.ZipFile(p,'x') as z:z.writestr('x.py','a');z.writestr('X.py','b')
        with self.assertRaises(ValueError):bundle.inspect(p)
    def pack_fixture(self,raw,extras=()):
        root=self.home/'source';(root/'src').mkdir(parents=True);(root/'src/example.py').write_bytes(raw)
        for name in ('SECURITY.md','docs/design/DEPENDENCIES.md','docs/evidence/phase0/source-acquisition.json','docs/evidence/phase0/monero-release-tag.json'):
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'{}\n')
        upstream=self.home/'upstream';upstream.mkdir();(upstream/'CMakeLists.txt').write_bytes(b'# public fixture\n')
        for name in extras:
            p=upstream/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'public build fixture\n')
        def git(args):return b'src/example.py\0' if 'ls-files' in args else b'0'*40+b'\n'
        output=self.home/'packed.zip'
        with patch.object(bundle,'ROOT',root),patch('subprocess.check_output',side_effect=git):bundle.pack(output,upstream)
        return bundle.inspect(output)
    def test_pack_source_marker_literal_is_not_a_key(self):
        m=self.pack_fixture(b"guard = b'-----BEGIN PRIVATE KEY-----'\n")
        self.assertIn('src/example.py',m['files'])
    def test_pack_actual_pem_header_rejected(self):
        with self.assertRaises(ValueError):self.pack_fixture(b'-----BEGIN PRIVATE KEY-----\nNONSECRET_NEGATIVE_FIXTURE\n')
    def test_pack_required_public_build_inputs(self):
        names=('src/daemonizer/posix_daemonizer.inl','src/blocks/checkpoints.dat','src/blocks/testnet_blocks.dat','src/blocks/stagenet_blocks.dat','external/supercop/crypto_sign/ed25519/amd64-64-24k/ge25519_base_niels.data','external/supercop/crypto_sign/ed25519/amd64-64-24k/copyright')
        m=self.pack_fixture(b'# public source\n',names)
        for name in names:self.assertIn('.upstream/monero/'+name,m['files'])
    def test_duplicate_json(self):
        with self.assertRaises(ValueError):bundle.decode(b'{"a":1,"a":2}')
    def test_hash_verification_and_extract(self):
        p=self.home/'good.zip';raw=b'print("public fixture")\n';m=dict(version=1,source_base_commit='test',scope='non-secret test',files={'source.py':bundle.sha(raw)})
        with zipfile.ZipFile(p,'x') as z:z.writestr('source.py',raw);z.writestr('N2_SOURCE_MANIFEST.json',json.dumps(m))
        dest=self.home/'extract';bundle.extract(p,dest);bundle.verify_tree(dest)
        with self.assertRaises(ValueError):bundle.extract(p,dest)
        (dest/'source.py').write_bytes(b'corruption')
        with self.assertRaises(ValueError):bundle.verify_tree(dest)
    def test_symlink_destination(self):
        p=self.home/'good.zip';m=dict(version=1,source_base_commit='test',scope='non-secret test',files={'source.py':bundle.sha(b'x')})
        with zipfile.ZipFile(p,'x') as z:z.writestr('source.py',b'x');z.writestr('N2_SOURCE_MANIFEST.json',json.dumps(m))
        link=self.home/'link';link.symlink_to(self.home,target_is_directory=True)
        with self.assertRaises(ValueError):bundle.extract(p,link/'new')
    def test_default_native_requirements(self):
        from launcher_host import requirements
        requirements()
    def test_manifest_missing_sources(self):
        from launcher_host import requirements,StartupError
        path=self.home/'manifest';path.write_text(json.dumps(dict(version=1,kind='N2_LOCAL_SOURCE_BUILD',source_sha256={},binary_sha256={})))
        with patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(path)),self.assertRaises(StartupError):requirements()
    def manifest_fixture(self):
        required=['src/phase6a/wallet.py','src/phase4/wallet.py','src/phase4/node.cpp','src/phase4/ledger.cpp','src/phase4/crypto.cpp','src/wallet/wallet.py','src/wallet/crypto.cpp','tests/phase4/CMakeLists.txt']
        bins=['phase4/privacycoin-hardened-devnet','phase4/privacycoin-hardened-crypto','phase2/privacycoin-wallet-crypto']
        record=dict(version=1,kind='N2_LOCAL_SOURCE_BUILD',source_sha256={n:bundle.sha((NATIVE/n).read_bytes()) for n in required},binary_sha256={Path(n).name:bundle.sha((NATIVE/'build/monero-linux'/n).read_bytes()) for n in bins})
        path=self.home/'manifest';c.write_private(path,f.canonical(record));return path,record
    def test_valid_native_manifest(self):
        from launcher_host import requirements
        path,_=self.manifest_fixture()
        with patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(path)):requirements()
    def test_boolean_manifest_version(self):
        from launcher_host import requirements,StartupError
        path,r=self.manifest_fixture();r['version']=True;c.write_private(path,f.canonical(r),replace=True)
        with patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(path)),self.assertRaises(StartupError):requirements()
    def test_duplicate_manifest_field(self):
        from launcher_host import requirements
        path=self.home/'manifest';c.write_private(path,b'{"version":1,"version":2}')
        with patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(path)),self.assertRaises(ValueError):requirements()
    def test_modified_binary_manifest(self):
        from launcher_host import requirements,StartupError
        path,r=self.manifest_fixture();r['binary_sha256']['privacycoin-wallet-crypto']='0'*64;c.write_private(path,f.canonical(r),replace=True)
        with patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(path)),self.assertRaises(StartupError):requirements()
    def test_modified_source_manifest(self):
        from launcher_host import requirements,StartupError
        path,r=self.manifest_fixture();r['source_sha256']['src/phase4/node.cpp']='0'*64;c.write_private(path,f.canonical(r),replace=True)
        with patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(path)),self.assertRaises(StartupError):requirements()
    def test_public_permissions_manifest(self):
        from launcher_host import requirements
        path,_=self.manifest_fixture();path.chmod(0o644)
        with patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(path)),self.assertRaises(ValueError):requirements()
    def test_manifest_traversal(self):
        from launcher_host import requirements,StartupError
        path,r=self.manifest_fixture();r['source_sha256']['../outside']='0'*64;c.write_private(path,f.canonical(r),replace=True)
        with patch.dict(os.environ,PC_DEVNET_BUILD_MANIFEST=str(path)),self.assertRaises(StartupError):requirements()
    def test_no_secret_output(self):
        home=self.home/'privacycoin-n2-output';stream=io.StringIO()
        with contextlib.redirect_stdout(stream):role.prepare(home)
        self.assertNotIn('password',stream.getvalue());self.assertFalse((home/'provider/control').exists())
    def test_no_activation_implementation(self):
        raw=Path(role.__file__).read_text();self.assertNotIn('DisableNetwork 0',raw);self.assertNotIn('start_mining',raw)

def main():
    c.harden();start=time.monotonic();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    out=ROOT/'docs/evidence/privacy-network-n2'/('units-'+str(time.time_ns())+'.json')
    out.write_text(json.dumps(dict(result='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),failed_cases=[t.id() for t,_ in result.failures+result.errors],seconds=time.monotonic()-start,scope='LOCAL PREPARATION ONLY; Windows preflight execution blocked separately'),indent=2))
    if not result.wasSuccessful():sys.exit(1)
if __name__=='__main__':main()
