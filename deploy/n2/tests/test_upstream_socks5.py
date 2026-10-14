"""Offline-only SOCKS policy, lifecycle, guarded installation and native Tor."""
from test_startup_diagnostics import *
import threading,zipfile,hashlib,tempfile
import n2_upstream_socks5 as u,n2_install_upstream as installer
OUT=ROOT/'docs/evidence/privacy-network-n2-upstream-socks5'

class Socks:
    def __init__(self,reply=b'\x05\x00',delay=0):
        self.reply=reply;self.delay=delay;self.received=[];self.sock=socket.socket();self.sock.bind(('127.0.0.1',0));self.sock.listen();self.sock.settimeout(.1)
        self.value='127.0.0.1:'+str(self.sock.getsockname()[1]);self.stop=threading.Event();self.thread=threading.Thread(target=self.serve);self.thread.start()
    def serve(self):
        while not self.stop.is_set():
            try:conn,_=self.sock.accept()
            except TimeoutError:continue
            except OSError:break
            with conn:
                conn.settimeout(1)
                try:
                    self.received.append(conn.recv(3));self.stop.wait(self.delay)
                    if self.reply:conn.sendall(self.reply)
                except OSError:pass
    def __enter__(self):return self
    def __exit__(self,*_):self.stop.set();self.sock.close();self.thread.join(2)

class ProxyCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):c.harden();cls.home=private_dir(NATIVE/'build/privacycoin-n2-upstream-socks5'/str(time.time_ns()))
    def diag(self):return d.Diagnostics(self.home)
    def test_target(self):self.assertEqual(u.endpoint('127.0.0.1:22308'),('127.0.0.1',22308))
    def test_reject_endpoint_forms(self):
        for value in ('localhost:22308','https://127.0.0.1:22308','user:secret@127.0.0.1:22308','8.8.8.8:22308','127.0.0.1:80','127.0.0.1:65536','127.0.0.1:022308','127.0.0.1:22308\nSocks5Proxy other','[::1]:22308','127.0.0.1:22308\n',None):
            with self.subTest(value=value),self.assertRaises(u.ProxyFailure):u.endpoint(value)
    def test_recursive_ports(self):
        for port in (19510,19520,19530,19550,19501,19560,19481):
            with self.subTest(port=port),self.assertRaises(u.ProxyFailure):u.endpoint('127.0.0.1:'+str(port),[19481])
    def test_greeting_only_no_destination_no_credentials(self):
        with Socks() as server:
            policy=u.Policy(server.value,self.diag());policy.check(force=True)
            self.assertEqual(server.received,[b'\x05\x01\x00'])
    def test_refused(self):
        with self.assertRaisesRegex(u.ProxyFailure,'UPSTREAM_REFUSED'):u.Policy('127.0.0.1:'+str(h.g.port()),self.diag()).check(True)
    def test_auth_required(self):
        with Socks(b'\x05\x02') as server,self.assertRaisesRegex(u.ProxyFailure,'UPSTREAM_AUTH_REQUIRED'):u.Policy(server.value,self.diag()).check(True)
    def test_malformed_reply(self):
        for response in (b'\x04\x00',b'\x05\xff',b'\x05',b''):
            with Socks(response) as server,self.assertRaisesRegex(u.ProxyFailure,'UPSTREAM_PROTOCOL'):u.Policy(server.value,self.diag()).check(True)
    def test_partial_reply_deadline(self):
        begin=time.monotonic()
        with Socks(b'\x05',delay=2) as server,self.assertRaisesRegex(u.ProxyFailure,'UPSTREAM_TIMEOUT'):u.Policy(server.value,self.diag()).check(True)
        self.assertLess(time.monotonic()-begin,1.8)
    def test_health_monitor_not_cached_forever(self):
        with Socks() as server:policy=u.Policy(server.value,self.diag());policy.check(True)
        policy.next_check=0
        with self.assertRaises(u.ProxyFailure):policy.check()
    def test_mandatory_config_no_alternative(self):
        p=u.Policy('127.0.0.1:22308',self.diag());lines=p.lines(start.template(self.home,True))
        self.assertEqual(lines.count('Socks5Proxy 127.0.0.1:22308'),1);self.assertIn('DisableNetwork 1',lines);self.assertIn('SafeLogging 1',lines)
        with self.assertRaises(u.ProxyFailure):p.lines(lines)
    def test_policy_error_not_swallowed_by_bootstrap(self):
        tor=types.SimpleNamespace(process=types.SimpleNamespace(poll=lambda:None),control=lambda _:(_ for _ in ()).throw(u.ProxyFailure('UPSTREAM_LOST')))
        with self.assertRaisesRegex(u.ProxyFailure,'UPSTREAM_LOST'):d.wait_bootstrap(tor,[],self.diag(),seconds=.2)
    def test_proxy_checked_before_tor_start(self):
        policy=types.SimpleNamespace(check=lambda **_:(_ for _ in ()).throw(u.ProxyFailure('UPSTREAM_REFUSED')))
        tor=u.UpstreamTor(TOR,self.home/'unused',self.diag(),policy)
        with patch.object(d.DiagnosticTor,'start') as launch,self.assertRaises(u.ProxyFailure):tor.start()
        launch.assert_not_called()
    def test_native_tor_config_and_control_network_disabled(self):
        home=private_dir(self.home/('tor-'+str(time.time_ns())));config=home/'torrc';diag=self.diag()
        with Socks() as server:
            policy=u.Policy(server.value,diag)
            write_config(config,policy.lines([f'DataDirectory {home}','DisableNetwork 1','RunAsDaemon 0','SafeLogging 1','SocksPort 0',f'ControlPort 127.0.0.1:{h.g.port()}','CookieAuthentication 1']))
            tor=u.UpstreamTor(TOR,config,diag,policy)
            try:
                tor.start();end=time.monotonic()+5
                while True:
                    try:raw=tor.control('GETCONF Socks5Proxy DisableNetwork');break
                    except (OSError,ValueError):
                        if time.monotonic()>end:raise
                        time.sleep(.05)
                self.assertIn(('Socks5Proxy='+server.value).encode(),raw);self.assertIn(b'DisableNetwork=1',raw)
                self.assertNotEqual(d.bootstrap(tor.control('GETINFO status/bootstrap-phase'))['progress'],100)
            finally:tor.close()
            self.assertIsNotNone(tor.process.poll());self.assertFalse(tor.reader.is_alive())
        self.assertNotIn(server.value.encode(),c.read_private(diag.path))

class ProxyLifecycle(unittest.TestCase):
    setUpClass=classmethod(Lifecycle.setUpClass.__func__)
    fixture=Lifecycle.fixture
    def run_proxy(self,mode,consent='ACTIVATE PUBLIC ONION',check=False):
        home=self.fixture();write_config(home/'tor/torrc.ACTIVE',['DisableNetwork 1','# old evidence'])
        preserve={p:p.read_bytes() for p in (home/'plan.json',home/'tor/torrc.DISABLED',home/'tor/torrc.ACTIVE',home/'wallet-sentinel')}
        v=dict(provider_port=19482,node_rpc=19481,node_p2p=19480);owned=[];real=subprocess.Popen
        def own(*a,**kw):
            process=real(*a,**kw)
            if a[0][0]==sys.executable:owned.append(process)
            return process
        def factory(binary,config,diag,policy):
            def control(_):
                if mode=='bootstrap-loss':raise u.ProxyFailure('UPSTREAM_LOST')
                return reply(100,'done')
            return types.SimpleNamespace(process=types.SimpleNamespace(poll=lambda:None),start=lambda:None,control=control,close=lambda:None)
        def foreground(*_):
            if mode=='foreground-loss':raise u.ProxyFailure('UPSTREAM_REFUSED')
        with Socks() as server,patch.object(start.base,'verify',return_value=(v,TOR)),patch.object(start.base,'call',return_value={'provider':'1'*64,'devnet_only':True}),patch.object(w,'rpc',return_value={'genesis':w.GENESIS}),patch('builtins.input',return_value=consent),patch.object(start,'UpstreamTor',side_effect=factory),patch.object(start,'foreground',side_effect=foreground),patch.object(start.subprocess,'Popen',side_effect=own):
            result=start.run(home/'plan.json',check,server.value)
        self.assertTrue(all(p.poll() is not None for p in owned))
        for path,data in preserve.items():self.assertEqual(path.read_bytes(),data)
        configs=list((home/'tor').glob('torrc.UPSTREAM.*'));self.assertEqual(len(configs),1)
        self.assertIn(b'DisableNetwork 1',c.read_private(configs[0]));self.assertIn(b'Socks5Proxy ',c.read_private(configs[0]))
        return result,owned,home
    def test_check_only_no_services_old_config_preserved(self):self.assertEqual(self.run_proxy('ready',check=True)[0],'OFFLINE_CHECK_OK')
    def test_decline_no_services(self):
        result,owned,_=self.run_proxy('ready',consent='NO');self.assertEqual(result,'NO_ACTIVATION_AUTHORIZATION');self.assertFalse(owned)
    def test_mock_ready_owned_real_tls_cleanup(self):self.assertEqual(self.run_proxy('ready')[0],'TOR_READY')
    def test_bootstrap_upstream_loss_cleanup(self):self.assertEqual(self.run_proxy('bootstrap-loss')[0],'UPSTREAM_LOST')
    def test_foreground_upstream_loss_cleanup(self):self.assertEqual(self.run_proxy('foreground-loss')[0],'UPSTREAM_REFUSED')
    def test_actual_foreground_monitor_failure(self):
        policy=types.SimpleNamespace(check=lambda:(_ for _ in ()).throw(u.ProxyFailure('UPSTREAM_LOST')))
        with self.assertRaises(u.ProxyFailure):start.foreground(None,[],None,policy)

    def test_unavailable_before_consent_no_services(self):
        home=self.fixture();v=dict(provider_port=19482,node_rpc=19481,node_p2p=19480)
        with patch.object(start.base,'verify',return_value=(v,TOR)),patch('builtins.input') as consent,patch.object(start.subprocess,'Popen') as child:
            result=start.run(home/'plan.json',upstream_socks5='127.0.0.1:'+str(h.g.port()))
        self.assertEqual(result,'UPSTREAM_REFUSED');consent.assert_not_called();child.assert_not_called()
        self.assertFalse((home/'public-endpoints.json').exists())

class InstallCases(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.home=Path(self.temp.name);self.source=self.home/'source';self.source.mkdir()
        old=subprocess.check_output(['git','--git-dir='+str(ROOT/'.phase0-git'),'--work-tree='+str(ROOT),'show','5820678:'+installer.LAUNCHER],cwd=ROOT)
        self.assertEqual(installer.sha(old),installer.OLD)
        target=self.source/installer.LAUNCHER;target.parent.mkdir(parents=True);target.write_bytes(old);self.old=old
        self.entries={installer.LAUNCHER:b'# new launcher\n','deploy/n2/common/n2_upstream_socks5.py':b'# policy\n'}
    def archive(self,entries=None):
        entries=entries or self.entries;path=self.home/('patch-'+str(time.time_ns())+'.zip')
        with zipfile.ZipFile(path,'w') as z:
            for name,data in entries.items():z.writestr(name,data)
            z.writestr('N2_UPSTREAM_MANIFEST.json',json.dumps(dict(files={name:installer.sha(data) for name,data in entries.items()})))
        return path,installer.sha(path.read_bytes())
    def test_install_backup_idempotent_preserves_state(self):
        wallet=self.source/'wallet-sentinel';wallet.write_bytes(b'NOT-A-SECRET-FIXTURE');archive,sha=self.archive()
        self.assertEqual(installer.apply(archive,self.source,sha),2);self.assertEqual(installer.apply(archive,self.source,sha),0)
        self.assertEqual((self.source/installer.BACKUP).read_bytes(),self.old);self.assertEqual(wallet.read_bytes(),b'NOT-A-SECRET-FIXTURE')
        self.assertEqual((self.source/installer.BACKUP).stat().st_mode&0o077,0)
    def test_hash_reject(self):
        archive,_=self.archive()
        with self.assertRaisesRegex(ValueError,'PATCH_HASH'):installer.apply(archive,self.source,'0'*64)
    def test_conflict_all_validated_before_write(self):
        target=self.source/'deploy/n2/common/n2_upstream_socks5.py';target.write_bytes(b'newer work');archive,sha=self.archive()
        with self.assertRaises(ValueError):installer.apply(archive,self.source,sha)
        self.assertEqual((self.source/installer.LAUNCHER).read_bytes(),self.old);self.assertFalse((self.source/installer.BACKUP).exists())
    def test_newer_launcher_rejected(self):
        (self.source/installer.LAUNCHER).write_bytes(b'newer work');archive,sha=self.archive()
        with self.assertRaises(ValueError):installer.apply(archive,self.source,sha)
    def test_bound_source_launcher_rejected(self):
        (self.source/'N2_SOURCE_MANIFEST.json').write_text(json.dumps(dict(files={installer.LAUNCHER:installer.OLD})));archive,sha=self.archive()
        with self.assertRaisesRegex(ValueError,'SOURCE_MANIFEST_BOUND'):installer.apply(archive,self.source,sha)
    def test_traversal_rejected(self):
        archive,sha=self.archive({**self.entries,'deploy/n2/common/../../escape.py':b'bad'})
        with self.assertRaisesRegex(ValueError,'PATCH_PATH'):installer.apply(archive,self.source,sha)
    def test_symlink_rejected(self):
        (self.source/'deploy/n2/common/n2_upstream_socks5.py').symlink_to(self.home/'outside');archive,sha=self.archive()
        with self.assertRaisesRegex(ValueError,'SYMLINK'):installer.apply(archive,self.source,sha)

def main():
    import test_deployment_patch as deploy,test_p2p_channel as p2p,n1r_unit as n1
    classes=(ProxyCases,ProxyLifecycle,InstallCases,Cases,Lifecycle,deploy.Cases,p2p.Cases,n1.Cases,n1.BridgeCases,n1.RepairCases)
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in classes)
    suite.addTest(n1.AdditionalBridgeCases('test_partial_body_cannot_block_worker_indefinitely'))
    begin=time.monotonic()
    with contextlib.redirect_stdout(io.StringIO()):result=unittest.TextTestRunner(verbosity=2).run(suite)
    report=dict(result='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),seconds=time.monotonic()-begin,public_tor=False,native_tor_network_disabled=True,cases=[cls.__name__+'.'+name for cls in classes for name in unittest.defaultTestLoader.getTestCaseNames(cls)],failure_details=[dict(test=str(test),trace=trace) for test,trace in result.failures+result.errors])
    (OUT/('checks-'+str(time.time_ns())+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    if not result.wasSuccessful():raise SystemExit(1)
if __name__=='__main__':main()
