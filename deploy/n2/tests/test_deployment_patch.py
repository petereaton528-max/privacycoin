"""Isolated patch, credential and resource/TLS boundary acceptance."""
from pathlib import Path
import sys,unittest,os,json,time,threading,socket,hashlib,tempfile,zipfile
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
import n2_tls,n2_operator as op,n2_transport as nt,n2_apply_patch as installer
from common import *
from tor_runtime import TOR
from runtime import h
OUT=ROOT/'docs/evidence/privacy-network-n2-deployment-patch'

class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c.harden();cls.home=private_dir(NATIVE/'build/privacycoin-n2-deployment-patch'/('units-'+str(time.time_ns())))
        for who in ('a','b'):
            for purpose in ('p2p','resource'):n2_tls.generate(cls.home/(who+'-'+purpose),purpose)
        for purpose in ('p2p','resource'):
            for who,peer in (('a','b'),('b','a')):
                public=cls.home/(peer+'-'+purpose)/'public.json';pin=load_json(public)['sha256']
                n2_tls.enroll(cls.home/(who+'-'+purpose),public,pin,purpose)
    def test_no_identity_overwrite(self):
        before=c.read_private(self.home/'a-p2p/own.key')
        with self.assertRaises(ValueError):n2_tls.generate(self.home/'a-p2p','p2p')
        self.assertEqual(before,c.read_private(self.home/'a-p2p/own.key'))
    def test_wrong_pin(self):
        d=private_dir(self.home/'wrong-pin')
        with self.assertRaises(ValueError):n2_tls.enroll(d,self.home/'b-p2p/public.json','0'*64,'p2p')
        self.assertFalse((d/'peer.pem').exists())
    def test_wrong_purpose(self):
        d=private_dir(self.home/'wrong-purpose');p=self.home/'b-p2p/public.json'
        with self.assertRaises(ValueError):n2_tls.enroll(d,p,load_json(p)['sha256'],'resource')
    def test_public_exchange_contains_no_private_key(self):
        for p in self.home.glob('?-*/public.json'):self.assertNotIn(b'PRIVATE KEY',c.read_private(p))
    def test_resource_proxy_rejects_direct(self):
        with self.assertRaises(ValueError):nt.ResourceProxy(n2_tls.channel(self.home/'a-resource','connector',h.g.port(),h.g.port()))
    def test_proxy_preserves_official_tor_isolation_format(self):
        from n1_unit import address
        proxy=nt.ResourceProxy(n2_tls.channel(self.home/'a-resource','connector',h.g.port(),80,address(),h.g.port()))
        thread=threading.Thread(target=proxy.run);thread.start();auth=b'\x01\x09<torS0X>0\x20'+os.urandom(32)
        try:
            with patch.object(nt,'isolated_connect',side_effect=ValueError('TEST_STOP_BEFORE_TOR')) as connect:
                with socket.create_connection(('127.0.0.1',proxy.v['listen_port']),timeout=2) as s:
                    s.sendall(b'\x05\x01\x02');self.assertEqual(s.recv(2),b'\x05\x02')
                    s.sendall(auth);self.assertEqual(s.recv(2),b'\x01\x00')
                    host=address().encode();s.sendall(b'\x05\x01\x00\x03'+bytes([len(host)])+host+b'\x00\x50');self.assertEqual(s.recv(2),b'')
                connect.assert_called_once();self.assertEqual(connect.call_args.args[2],auth)
        finally:proxy.close();thread.join(timeout=2)
    def test_private_tls_permissions(self):
        self.assertEqual((self.home/'a-resource/own.key').stat().st_mode&0o077,0)
        n2_tls.verify_identity(self.home/'a-resource','resource')
        with self.assertRaises(ValueError):n2_tls.verify_identity(self.home/'a-resource','p2p')
    def test_existing_provider_offline_idempotent(self):
        d=private_dir(self.home/'privacycoin-n2-existing');private_dir(d/'provider')
        save_json(d/'provider/control',dict(id='1'*64,password='disposable-control-secret'))
        c.write_private(d/'wallet-sentinel',os.urandom(80));c.write_private(d/'node-sentinel',os.urandom(80))
        v=dict(version=1,devnet_only=True,role='provider',home=str(d),node_rpc=19481,node_p2p=19480,provider_port=19482,bridge_port=19483,socks_port=19450,peer_port=None);save_json(d/'provider.json',v)
        before={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in d.rglob('*') if p.is_file()}
        side=self.home/'operator';plan=op.configure(d/'provider.json',side,TOR);self.assertEqual(plan,op.configure(d/'provider.json',side,TOR))
        self.assertEqual(before,{p:hashlib.sha256(p.read_bytes()).hexdigest() for p in d.rglob('*') if p.is_file()})
        raw=c.read_private(side/'tor/torrc.DISABLED');self.assertIn(b'DisableNetwork 1',raw);self.assertNotIn(b'19481',raw);self.assertNotIn(b'19482',raw)
        with self.assertRaises(ValueError):op.configure(d/'provider.json',side,TOR,False)
        with patch('builtins.input',return_value='NO'),patch.object(op,'call',return_value={'provider':'1'*64,'devnet_only':True}),patch.object(w,'rpc',return_value={'genesis':w.GENESIS}):
            # Missing credentials fails BEFORE any activation too.
            with self.assertRaises(Exception):op.run(plan)
        self.assertFalse((side/'tor/torrc.ACTIVE').exists())
        with patch.object(n2_tls,'channel',return_value={}),patch('builtins.input',return_value='NO'),patch.object(op,'call',return_value={'provider':'1'*64,'devnet_only':True}),patch.object(w,'rpc',return_value={'genesis':w.GENESIS}),patch.object(op.OwnedTor,'start') as start:
            with self.assertRaisesRegex(ValueError,'NO_ACTIVATION_AUTHORIZATION'):op.run(plan)
            start.assert_not_called()
    def test_channel_purpose_separation(self):
        with self.assertRaisesRegex(ValueError,'CHANNEL_PURPOSE_MISMATCH'):n2_tls.channel(self.home/'a-p2p','acceptor',h.g.port(),h.g.port(),purpose='resource')
    def test_offline_links_validate_before_write_and_repeat(self):
        from n1_unit import address
        side=private_dir(self.home/'links');plan=side/'plan.json';save_json(plan,{})
        public=self.home/'peer-endpoints.json';record=dict(version=1,devnet_only=True,p2p_onion=address(),resource_onion=address())
        save_json(public,record)
        with patch.object(op,'verify',return_value=({'home':'/not-used'},TOR)):
            with self.assertRaisesRegex(ValueError,'SEPARATE_ENDPOINTS_REQUIRED'):op.links(plan,public,self.home/'a-p2p',self.home/'a-resource')
            self.assertFalse((side/'p2p-client.json').exists())
            op.links(plan,public,self.home/'a-p2p');before=c.read_private(side/'p2p-client.json')
            op.links(plan,public,self.home/'a-p2p');self.assertEqual(before,c.read_private(side/'p2p-client.json'))
    def test_operator_owned_tls_lifecycle_without_tor_activation(self):
        from n1_unit import address
        import shutil,types
        d=private_dir(self.home/'privacycoin-n2-lifecycle');private_dir(d/'provider');save_json(d/'provider/control',dict(id='2'*64))
        save_json(d/'provider.json',dict(version=1,devnet_only=True,role='provider',home=str(d),node_rpc=19481,node_p2p=19480,provider_port=19482,bridge_port=19483,socks_port=19450,peer_port=None))
        side=self.home/'lifecycle-operator';plan=op.configure(d/'provider.json',side,TOR)
        for purpose in ('p2p','resource'):shutil.copytree(self.home/('a-'+purpose),side/('tls-'+purpose))
        for purpose in ('p2p','resource'):c.write_private(side/'tor'/(purpose+'-onion')/'hostname',address().encode())
        fake=types.SimpleNamespace(start=lambda:None,close=lambda:None,control=lambda _:b'PROGRESS=100',process=types.SimpleNamespace(poll=lambda:None))
        children=[];original=op.subprocess.Popen
        def own(*args,**kw):
            process=original(*args,**kw)
            if args[0][0]==sys.executable:children.append(process)
            return process
        with patch.object(op,'OwnedTor',return_value=fake),patch.object(op.subprocess,'Popen',side_effect=own),patch.object(op,'call',return_value={'provider':'2'*64,'devnet_only':True}),patch.object(w,'rpc',return_value={'genesis':w.GENESIS}),patch('builtins.input',side_effect=['ACTIVATE PUBLIC ONION','EXIT']):op.run(plan)
        self.assertEqual(len(children),2);self.assertTrue(all(p.poll() is not None for p in children))
        self.assertIn(b'DisableNetwork 1',c.read_private(side/'tor/torrc.ACTIVE'))
    def test_resource_admin_filter_before_upstream(self):
        a,b=socket.socketpair()
        try:
            raw=b'POST /cleanup HTTP/1.1\r\nHost: test:80\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}';a.sendall(raw)
            with self.assertRaises(ValueError):nt.message(b,time.monotonic()+1,host='test')
        finally:a.close();b.close()
    def test_resource_partial_header_deadline(self):
        a,b=socket.socketpair()
        try:
            a.sendall(b'POST ')
            with self.assertRaises(TimeoutError):nt.message(b,time.monotonic()+.03,host='test')
        finally:a.close();b.close()
    def test_resource_duplicate_length(self):
        a,b=socket.socketpair()
        try:
            a.sendall(b'POST /health HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}')
            with self.assertRaises(ValueError):nt.message(b,time.monotonic()+1,host='test')
        finally:a.close();b.close()
    def test_patch_additive_and_conflict(self):
        d=private_dir(self.home/'source');z=self.home/'patch.zip';name='deploy/n2/common/example.py';raw=b'# public fixture\n'
        with zipfile.ZipFile(z,'w') as out:
            out.writestr(name,raw);out.writestr('N2_PATCH_MANIFEST.json',json.dumps(dict(files={name:hashlib.sha256(raw).hexdigest()})))
        sha=hashlib.sha256(z.read_bytes()).hexdigest();self.assertEqual(installer.apply(z,d,sha),1);self.assertEqual(installer.apply(z,d,sha),0)
        (d/name).write_bytes(b'preserve newer legitimate work')
        with self.assertRaises(ValueError):installer.apply(z,d,sha)
        self.assertEqual((d/name).read_bytes(),b'preserve newer legitimate work')
    def test_patch_bad_hash(self):
        z=self.home/'bad.zip';z.write_bytes(b'bad')
        with self.assertRaises(ValueError):installer.apply(z,self.home,'0'*64)
    def test_patch_unsafe_paths(self):
        for number,name in enumerate(('deploy/n2/common/../escape.py','deploy/n2/common//alias.py','/deploy/n2/common/absolute.py')):
            z=self.home/('unsafe'+str(number)+'.zip');raw=b'# fixture'
            with zipfile.ZipFile(z,'w') as out:
                out.writestr(name,raw);out.writestr('N2_PATCH_MANIFEST.json',json.dumps(dict(files={name:hashlib.sha256(raw).hexdigest()})))
            with self.assertRaises(ValueError):installer.apply(z,self.home,hashlib.sha256(z.read_bytes()).hexdigest())

def main():
    start=time.monotonic();r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    (OUT/('units-'+str(time.time_ns())+'.json')).write_text(json.dumps(dict(result='PASS' if r.wasSuccessful() else 'FAIL',tests=r.testsRun,errors=len(r.errors),failures=len(r.failures),seconds=time.monotonic()-start,private_fixture=str(Cases.home)),indent=2))
    if not r.wasSuccessful():sys.exit(1)
if __name__=='__main__':main()
