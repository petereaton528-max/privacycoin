"""Transport boundary tests, including a malicious peer and fail-closed SOCKS."""
from pathlib import Path
import sys,unittest,socket,threading,time,json,ssl,hashlib
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/tests'),str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network')]
import p2p_channel as pc
from p2p_connectivity import certificates,configuration,request
from common import c,f,w,private_dir,NATIVE
from runtime import OwnedNode,h
import types
import subprocess

class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        c.harden();cls.home=private_dir(NATIVE/'build/privacycoin-n2-connectivity'/('units-'+str(time.time_ns())))
        cls.keys,pin=certificates(cls.home/'tls');cls.pin=staticmethod(pin)
    def value(self):return configuration(self.keys,self.pin,'connector',h.g.port(),h.g.port())
    def framed(self,value,magic=pc.MAGIC):
        raw=f.canonical(value);return magic+len(raw).to_bytes(4,'big')+raw
    def parsed(self,raw,request=True):
        a,b=socket.socketpair()
        try:a.sendall(raw);a.shutdown(socket.SHUT_WR);return pc.frame(b,time.monotonic()+1,request)
        finally:a.close();b.close()
    def query(self):return dict(network=w.NETWORK,genesis=w.GENESIS,profile=w.PROFILE,command='inventory')
    def test_exact_frame_preserved(self):
        raw=self.framed(self.query());self.assertEqual(self.parsed(raw),raw)
    def test_rpc_magic_rejected(self):
        with self.assertRaises(ValueError):self.parsed(self.framed(self.query(),b'PrivacyCoinRPC04'))
    def test_admin_command_rejected(self):
        with self.assertRaises(ValueError):self.parsed(self.framed(dict(self.query(),command='mine')))
    def test_genesis_rejected(self):
        with self.assertRaises(ValueError):self.parsed(self.framed(dict(self.query(),genesis='0'*64)))
    def test_response_identity_rejected(self):
        with self.assertRaises(ValueError):self.parsed(self.framed(dict(self.query(),profile='wrong')),False)
    def test_oversize_frame(self):
        with self.assertRaises(ValueError):self.parsed(pc.MAGIC+(pc.LIMIT+1).to_bytes(4,'big'))
    def test_truncated_header(self):
        with self.assertRaises(ValueError):self.parsed(b'partial')
    def test_duplicate_json(self):
        raw=b'{"network":1,"network":2}'
        with self.assertRaises(ValueError):self.parsed(pc.MAGIC+len(raw).to_bytes(4,'big')+raw)
    def test_absolute_deadline(self):
        a,b=socket.socketpair()
        try:
            with self.assertRaises(TimeoutError):pc.read(a,1,time.monotonic()+.03)
        finally:a.close();b.close()
    def test_configuration_helper_and_owned_cli_shutdown(self):
        value=configuration(self.keys,self.pin,'acceptor',h.g.port(),h.g.port());output=self.home/'cli.json'
        args=[sys.executable,str(ROOT/'deploy/n2/common/configure_p2p.py'),'--role','acceptor','--listen-port',str(value['listen_port']),'--target-port',str(value['target_port']),'--cert',value['cert'],'--key',value['key'],'--ca',value['ca'],'--peer-cert',str(self.keys/'client.pem'),'--output',str(output)]
        result=subprocess.run(args,capture_output=True,timeout=10);self.assertEqual(result.returncode,0)
        from common import load_json
        self.assertEqual(load_json(output),value);self.assertEqual(output.stat().st_mode&0o077,0)
        with (self.home/'cli-log').open('xb') as log:
            child=subprocess.Popen([sys.executable,str(ROOT/'deploy/n2/common/p2p_channel.py'),'--config',str(output)],stdout=log,stderr=log)
            try:
                deadline=time.monotonic()+5
                while b'LOCAL_P2P_CHANNEL_LISTENING' not in (self.home/'cli-log').read_bytes() and time.monotonic()<deadline:time.sleep(.02)
                self.assertIn(b'LOCAL_P2P_CHANNEL_LISTENING',(self.home/'cli-log').read_bytes())
                child.terminate();child.wait(timeout=15);self.assertEqual(child.returncode,0)
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=5)
    def test_no_arbitrary_endpoint(self):
        with self.assertRaises(ValueError):pc.validate(dict(self.value(),endpoint='example.com'))
    def test_no_public_acceptor(self):
        with self.assertRaises(ValueError):pc.validate(dict(self.value(),role='acceptor',endpoint='0.0.0.0'))
    def test_port_boolean_rejected(self):
        with self.assertRaises(ValueError):pc.validate(dict(self.value(),listen_port=True))
    def test_future_config_version(self):
        with self.assertRaises(ValueError):pc.validate(dict(self.value(),version=2))
    def test_symlink_key_rejected(self):
        link=self.home/'linked.key';link.symlink_to(self.keys/'client.key')
        with self.assertRaises(ValueError):pc.validate(dict(self.value(),key=str(link)))
    def test_publicly_readable_key_rejected(self):
        key=self.keys/'client.key';key.chmod(0o644)
        try:
            with self.assertRaises(ValueError):pc.validate(self.value())
        finally:key.chmod(0o600)
    def test_socks_error_has_no_fallback_or_dns(self):
        import base64
        pk=b'\x11'*32;raw=pk+hashlib.sha3_256(b'.onion checksum'+pk+b'\x03').digest()[:2]+b'\x03'
        onion=base64.b32encode(raw).decode().lower()+'.onion';v=dict(self.value(),endpoint=onion,socks_port=19450)
        with patch.object(socket,'create_connection',side_effect=ConnectionRefusedError()) as connect,patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS')):
            with self.assertRaises(ConnectionRefusedError):pc.connect(v,time.monotonic()+1)
            self.assertEqual(connect.call_count,1);self.assertEqual(connect.call_args.args[0],('127.0.0.1',19450))
    def test_onion_virtual_port_80_allowed_without_privileged_local_bind(self):
        import base64
        pk=b'\x22'*32;raw=pk+hashlib.sha3_256(b'.onion checksum'+pk+b'\x03').digest()[:2]+b'\x03'
        onion=base64.b32encode(raw).decode().lower()+'.onion'
        self.assertEqual(pc.validate(dict(self.value(),endpoint=onion,socks_port=19450,target_port=80))['target_port'],80)
    def test_malicious_peer_invalid_block_bytes_never_imported(self):
        # An authenticated but dishonest peer is still untrusted ledger input.
        fake=socket.socket();fake.bind(('127.0.0.1',0));fake.listen(4);fake.settimeout(.2)
        end=threading.Event();observed=[];node=OwnedNode(self.home,'malicious-receiver')
        def serve():
            while not end.is_set():
                try:s,_=fake.accept()
                except socket.timeout:continue
                except OSError:break
                with s:
                    try:
                        q=f.decode(pc.frame(s,time.monotonic()+2,True)[20:]);cmd=q['command'];observed.append(cmd)
                        response=dict(network=w.NETWORK,genesis=w.GENESIS,profile=w.PROFILE)
                        if cmd=='inventory':response['blocks']=['1'*64]
                        elif cmd=='get_block':response.update(block='ff',transactions=[])
                        else:response['transactions']=[]
                        raw=f.canonical(response);pc.write(s,pc.MAGIC+len(raw).to_bytes(4,'big')+raw,time.monotonic()+2)
                    except (OSError,ValueError):pass
        thread=threading.Thread(target=serve);thread.start();channels=[]
        try:
            sv=configuration(self.keys,self.pin,'acceptor',h.g.port(),fake.getsockname()[1]);cv=configuration(self.keys,self.pin,'connector',h.g.port(),sv['listen_port'])
            for v in (sv,cv):
                obj=pc.Channel(v);t=threading.Thread(target=obj.run);t.start();channels.append((obj,t))
            node.start(peer=types.SimpleNamespace(p2p=cv['listen_port']));deadline=time.monotonic()+10
            while observed.count('get_block')<3 and time.monotonic()<deadline:time.sleep(.05)
            self.assertGreaterEqual(observed.count('get_block'),3)
            self.assertEqual(node.status(),dict(height=0,tip=w.GENESIS,work='0'))
        finally:
            node.stop()
            for obj,t in channels:obj.close();t.join(timeout=15)
            end.set();fake.close();thread.join(timeout=3)

def main():
    start=time.monotonic();r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    out=ROOT/'docs/evidence/privacy-network-n2-connectivity'/('units-'+str(time.time_ns())+'.json')
    out.write_text(json.dumps(dict(result='PASS' if r.wasSuccessful() else 'FAIL',tests=r.testsRun,failures=len(r.failures),errors=len(r.errors),skipped=len(r.skipped),seconds=time.monotonic()-start,private_fixture=str(Cases.home)),indent=2))
    if not r.wasSuccessful():sys.exit(1)
if __name__=='__main__':main()
