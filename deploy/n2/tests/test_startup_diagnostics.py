"""Offline fault schedules and official Tor with DisableNetwork 1 only."""
from pathlib import Path
import sys,unittest,time,json,os,types,subprocess,io,contextlib,socket
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
import n2_tor_diagnostics as d,n2_start_diagnostic as start,n2_tls
from common import c,private_dir,save_json,load_json,NATIVE,w
from tor_runtime import TOR,write_config
from runtime import h
OUT=ROOT/'docs/evidence/privacy-network-n2-startup-diagnostics'

def reply(progress=10,stage='conn',summary='safe'):
    return f'250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={progress} TAG={stage} SUMMARY="{summary}"\r\n250 OK\r\n'.encode()
class Clock:
    def __init__(self):self.t=0
    def now(self):return self.t
    def sleep(self,seconds):self.t+=seconds
class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c.harden();cls.home=private_dir(NATIVE/'build/privacycoin-n2-startup-diagnostics'/str(time.time_ns()))
    def diag(self):return d.Diagnostics(self.home)
    def wait(self,error=None,raw=None,exitcode=None,children=()):
        diag=self.diag();clock=Clock()
        tor=types.SimpleNamespace(process=types.SimpleNamespace(poll=lambda:exitcode),control=lambda _:raw or reply())
        if error:tor.control=lambda _:(_ for _ in ()).throw(error)
        return d.wait_bootstrap(tor,children,diag,seconds=1,clock=clock.now,sleep=clock.sleep)
    def test_control_redaction(self):
        self.assertEqual(d.bootstrap(reply(50,'loading_descriptors','SECRET-cookie-key-PROGRESS=100'))['progress'],50)
        self.assertEqual(d.bootstrap(reply(10,'untrusted_tag'))['stage'],'OTHER')
    def test_control_requires_complete_success(self):
        with self.assertRaises(d.Failure):d.bootstrap(b'250 SUMMARY="PROGRESS=100"\r\n')
        with self.assertRaises(d.Failure):d.bootstrap(reply(101))
    def test_control_refusal_distinct_from_bootstrap(self):
        with self.assertRaisesRegex(d.Failure,'TOR_CONTROL_UNAVAILABLE'):self.wait(error=ConnectionRefusedError())
    def test_cookie_absence_distinct(self):
        with self.assertRaisesRegex(d.Failure,'TOR_CONTROL_UNAVAILABLE'):self.wait(error=FileNotFoundError())
    def test_control_timeout_distinct(self):
        with self.assertRaisesRegex(d.Failure,'TOR_CONTROL_UNAVAILABLE'):self.wait(error=TimeoutError())
    def test_control_auth_fails_closed(self):
        with self.assertRaisesRegex(d.Failure,'TOR_CONTROL_AUTH'):self.wait(error=ValueError('TOR_CONTROL_AUTH'))
    def test_control_permission_fails_closed(self):
        with self.assertRaisesRegex(d.Failure,'TOR_CONTROL_PERMISSION'):self.wait(error=PermissionError())
    def test_valid_stalled_progress_is_real_bootstrap_timeout(self):
        with self.assertRaisesRegex(d.Failure,'TOR_BOOTSTRAP_TIMEOUT'):self.wait(raw=reply(50))
    def test_control_failure_at_deadline_not_bootstrap_timeout(self):
        clock=Clock();diag=self.diag();calls=[]
        def control(_):
            calls.append(1)
            if len(calls)>1:raise ConnectionRefusedError()
            return reply(50)
        tor=types.SimpleNamespace(process=types.SimpleNamespace(poll=lambda:None),control=control)
        with self.assertRaisesRegex(d.Failure,'TOR_CONTROL_UNAVAILABLE'):d.wait_bootstrap(tor,[],diag,seconds=1,clock=clock.now,sleep=clock.sleep)
    def test_control_malformed_is_not_ready(self):
        with self.assertRaisesRegex(d.Failure,'TOR_CONTROL_UNAVAILABLE'):self.wait(raw=b'250 OK\r\n')
    def test_done_ready(self):self.wait(raw=reply(100,'done'))
    def test_progress100_other_stage_not_ready(self):
        with self.assertRaisesRegex(d.Failure,'TOR_BOOTSTRAP_TIMEOUT'):self.wait(raw=reply(100,'conn'))
    def test_tor_exit_distinct(self):
        with self.assertRaisesRegex(d.Failure,'TOR_PROCESS_EXIT'):self.wait(exitcode=23)
    def test_tls_p2p_exit_distinct(self):
        with self.assertRaisesRegex(d.Failure,'TLS_P2P_EXIT'):self.wait(children=[('p2p',types.SimpleNamespace(poll=lambda:7))])
    def test_tls_resource_exit_distinct(self):
        with self.assertRaisesRegex(d.Failure,'TLS_RESOURCE_EXIT'):self.wait(children=[('resource',types.SimpleNamespace(poll=lambda:0))])
    def test_no_timeout_extension(self):
        with self.assertRaises(ValueError):d.wait_bootstrap(None,[],self.diag(),seconds=181)
    def test_disabled_template_matches_existing_operator(self):
        home=private_dir(self.home/'privacycoin-n2-template');private_dir(home/'provider');save_json(home/'provider/control',{'id':'3'*64})
        save_json(home/'provider.json',dict(version=1,devnet_only=True,role='provider',home=str(home),node_rpc=19481,node_p2p=19480,provider_port=19482,bridge_port=19483,socks_port=19450,peer_port=None))
        side=self.home/'template-side';start.base.configure(home/'provider.json',side,TOR)
        self.assertEqual(c.read_private(side/'tor/torrc.DISABLED'),('\n'.join(start.template(side,True))+'\n').encode())
    def test_untrusted_log_redacted(self):
        diag=self.diag();secret=b'PRIVATE-test-secret-do-not-export'
        for line in (b'[warn] Clock skew '+secret,b'certificate has expired '+secret,b'network is unreachable '+secret,b'connection refused '+secret,b'Bootstrapped 10% (conn): '+secret,b'junk '+secret):d.log_observation(line,diag)
        raw=c.read_private(diag.path);self.assertNotIn(secret,raw)
        for code in ('TOR_CLOCK_SIGNAL','TOR_CERTIFICATE_SIGNAL','TOR_NETWORK_UNREACHABLE_SIGNAL','TOR_CONNECTION_REFUSED_SIGNAL','TOR_LOG_BOOTSTRAP'):self.assertIn(code.encode(),raw)
    def test_diagnostics_permissions_and_bounds(self):
        diag=self.diag()
        for i in range(1000):diag.event('TOR_WAIT')
        self.assertLessEqual(diag.path.stat().st_size,131072);self.assertLessEqual(diag.count,512)
        self.assertEqual(diag.home.stat().st_mode&0o077,0);self.assertEqual(diag.path.stat().st_mode&0o077,0)
        diag.finish('TOR_BOOTSTRAP_TIMEOUT');self.assertEqual(load_json(diag.home/'summary.json')['result'],'TOR_BOOTSTRAP_TIMEOUT')
    def test_unknown_fields_and_code_rejected(self):
        diag=self.diag()
        with self.assertRaises(ValueError):diag.event('SECRET')
        with self.assertRaises(TypeError):diag.event('TOR_WAIT',password='secret')
    def test_config_failure_classified(self):
        diag=self.diag();tor=d.DiagnosticTor(TOR,self.home/'not-used',diag)
        with patch.object(d.subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stdout=b'secret',stderr=b'private')):
            with self.assertRaisesRegex(d.Failure,'TOR_CONFIG_INVALID'):tor.verify()
        self.assertNotIn(b'secret',c.read_private(diag.path))
    def test_verify_timeout_classified(self):
        tor=d.DiagnosticTor(TOR,self.home/'not-used',self.diag())
        with patch.object(d.subprocess,'run',side_effect=subprocess.TimeoutExpired('secret',10)):
            with self.assertRaisesRegex(d.Failure,'TOR_VERIFY_TIMEOUT'):tor.verify()
    def test_live_pipe_redacts_stdout_and_stderr(self):
        diag=self.diag();fake=self.home/'fake-output-process';secret='FIXTURE-BEARER-SECRET-DO-NOT-LOG'
        c.write_private(fake,('#!/usr/bin/python3\nimport sys\nprint("Bootstrapped 10% (conn): '+secret+'",flush=True)\nprint("[warn] connection refused '+secret+'",file=sys.stderr,flush=True)\n').encode());fake.chmod(0o700)
        tor=d.DiagnosticTor(fake,self.home/'unused-config',diag)
        try:
            with patch.object(tor,'verify',return_value=None):tor.start()
            tor.process.wait(timeout=3)
        finally:tor.close()
        raw=c.read_private(diag.path);self.assertNotIn(secret.encode(),raw);self.assertIn(b'TOR_LOG_BOOTSTRAP',raw);self.assertIn(b'TOR_CONNECTION_REFUSED_SIGNAL',raw)
    def test_ready_after_deadline_is_rejected(self):
        clock=Clock();diag=self.diag()
        def late(_):clock.t+=2;return reply(100,'done')
        tor=types.SimpleNamespace(process=types.SimpleNamespace(poll=lambda:None),control=late)
        with self.assertRaisesRegex(d.Failure,'TOR_BOOTSTRAP_TIMEOUT'):d.wait_bootstrap(tor,[],diag,seconds=1,clock=clock.now,sleep=clock.sleep)
    def test_actual_official_tor_disabled_network_lifecycle(self):
        home=private_dir(self.home/('disabled-tor-'+str(time.time_ns())));diag=self.diag();config=home/'torrc'
        write_config(config,[f'DataDirectory {home}','DisableNetwork 1','RunAsDaemon 0','SafeLogging 1','SocksPort 0',f'ControlPort 127.0.0.1:{h.g.port()}','CookieAuthentication 1'])
        tor=d.DiagnosticTor(TOR,config,diag)
        try:
            tor.start();until=time.monotonic()+5
            while True:
                try:observed=d.bootstrap(tor.control('GETINFO status/bootstrap-phase'));break
                except (OSError,ValueError):
                    if time.monotonic()>until:raise
                    time.sleep(.05)
            self.assertNotEqual(observed['progress'],100)
            with self.assertRaisesRegex(d.Failure,'TOR_BOOTSTRAP_TIMEOUT'):d.wait_bootstrap(tor,[],diag,seconds=.3)
        finally:tor.close()
        self.assertIsNotNone(tor.process.poll());self.assertFalse(tor.reader.is_alive())
        self.assertIn(b'DisableNetwork 1',c.read_private(config))

class Lifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c.harden();cls.home=private_dir(NATIVE/'build/privacycoin-n2-startup-diagnostics'/('lifecycle-'+str(time.time_ns())))
        for purpose in ('p2p','resource'):
            key=cls.home/('keys-'+purpose);n2_tls.generate(key,purpose);public=key/'public.json';n2_tls.enroll(key,public,load_json(public)['sha256'],purpose)
    def fixture(self):
        import shutil
        from n1_unit import address
        home=private_dir(self.home/('run-'+str(time.time_ns())));private_dir(home/'tor');expected=start.template(home,True);write_config(home/'tor/torrc.DISABLED',expected)
        for purpose in ('p2p','resource'):
            shutil.copytree(self.home/('keys-'+purpose),home/('tls-'+purpose));private_dir(home/'tor'/(purpose+'-onion'));c.write_private(home/'tor'/(purpose+'-onion')/'hostname',address().encode())
        save_json(home/'plan.json',{'resource':True,'provider_id':'1'*64});c.write_private(home/'wallet-sentinel',os.urandom(64))
        return home
    def run_case(self,mode='ready',consent='ACTIVATE PUBLIC ONION',check_only=False):
        home=self.fixture();before=c.read_private(home/'wallet-sentinel');children=[];real=subprocess.Popen;fake=None
        def factory(binary,config,diag):
            nonlocal fake
            def launch():
                if mode=='config':raise d.Failure('TOR_CONFIG_INVALID')
            fake=types.SimpleNamespace(process=types.SimpleNamespace(poll=lambda:23 if mode=='exit' else None),start=launch,verify=lambda:None,control=lambda _:reply(100,'done'),close=lambda:None)
            if mode=='cleanup':fake.close=lambda:(_ for _ in ()).throw(ValueError('do not reveal this error'))
            return fake
        def own(*args,**kw):
            if mode=='tls' and args[0][0]==sys.executable and not children:args=([sys.executable,'-c','raise SystemExit(7)'],)
            p=real(*args,**kw)
            if args[0][0]==sys.executable:children.append(p)
            return p
        v=dict(provider_port=19482,node_rpc=19481,node_p2p=19480)
        with patch.object(start.base,'verify',return_value=(v,TOR)),patch.object(start.base,'call',return_value={'provider':'1'*64,'devnet_only':True}),patch.object(w,'rpc',return_value={'genesis':w.GENESIS}),patch('builtins.input',return_value=consent),patch.object(start,'DiagnosticTor',side_effect=factory),patch.object(start,'foreground',return_value=None),patch.object(start.subprocess,'Popen',side_effect=own):result=start.run(home/'plan.json',check_only)
        self.assertTrue(all(p.poll() is not None for p in children));self.assertEqual(before,c.read_private(home/'wallet-sentinel'))
        if children:self.assertIn(b'DisableNetwork 1',c.read_private(home/'tor/torrc.ACTIVE'))
        if mode!='ready' or consent!='ACTIVATE PUBLIC ONION':self.assertFalse((home/'public-endpoints.json').exists()) if mode!='cleanup' else None
        return result,children,home
    def test_declined_consent_starts_no_children(self):
        result,children,_=self.run_case(consent='NO');self.assertEqual(result,'NO_ACTIVATION_AUTHORIZATION');self.assertFalse(children)
    def test_offline_check_starts_no_services(self):
        result,children,home=self.run_case(check_only=True);self.assertEqual(result,'OFFLINE_CHECK_OK');self.assertFalse(children);self.assertFalse((home/'tor/torrc.ACTIVE').exists())
    def test_mock_tor_success_real_tls_owned_cleanup(self):
        result,children,home=self.run_case();self.assertEqual(result,'TOR_READY');self.assertEqual(len(children),2);self.assertTrue((home/'public-endpoints.json').exists())
    def test_tor_config_failure_restores_disabled(self):self.assertEqual(self.run_case('config')[0],'TOR_CONFIG_INVALID')
    def test_tor_exit_restores_disabled(self):self.assertEqual(self.run_case('exit')[0],'TOR_PROCESS_EXIT')
    def test_actual_tls_child_exit_distinct(self):self.assertEqual(self.run_case('tls')[0],'TLS_P2P_EXIT')
    def test_tor_cleanup_failure_does_not_skip_tls_cleanup(self):self.assertEqual(self.run_case('cleanup')[0],'CLEANUP_FAILED')

def main():
    begin=time.monotonic()
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in (Cases,Lifecycle))
    with contextlib.redirect_stdout(io.StringIO()):result=unittest.TextTestRunner(verbosity=2).run(suite)
    names=[cls.__name__+'.'+name for cls in (Cases,Lifecycle) for name in unittest.defaultTestLoader.getTestCaseNames(cls)]
    (OUT/('units-'+str(time.time_ns())+'.json')).write_bytes((json.dumps(dict(result='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),seconds=time.monotonic()-begin,fixture=str(Cases.home),cases=names,public_tor=False),indent=2)+'\n').encode())
    if not result.wasSuccessful():raise SystemExit(1)
if __name__=='__main__':main()
