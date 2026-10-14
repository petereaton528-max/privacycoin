"""Transport framing/fault tests. Stub SOCKS peer; NOT actual Tor/PC acceptance."""
from common import *
from tor_transport import *
from tor_runtime import available,prepare_public,OwnedTor,TOR,tor_path,PrivateNetwork
from unittest.mock import patch
import unittest,socketserver,threading,contextlib,tempfile,time,io
import subprocess,http.client
from http.server import BaseHTTPRequestHandler,HTTPServer

def address():
    key=b'\x01'*32;version=b'\x03';check=hashlib.sha3_256(b'.onion checksum'+key+version).digest()[:2]
    return base64.b32encode(key+check+version).decode().lower()+'.onion'

class Peer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
    def __init__(self,mode='ok'):
        self.mode=mode;self.commands=[];self.authorities=[];self.destinations=[];self.provider='a'*64
        outer=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(1)
                try:
                    if self.rfile.read(3)!=b'\x05\x01\x00':return
                    if outer.mode=='socks-refuse':self.wfile.write(b'\x05\xff');return
                    self.wfile.write(b'\x05\x00')
                    if self.rfile.read(4)!=b'\x05\x01\x00\x03':return
                    length=self.rfile.read(1)[0];name=self.rfile.read(length).decode();port=int.from_bytes(self.rfile.read(2),'big');outer.destinations.append((name,port))
                    if outer.mode=='socks-error':self.wfile.write(b'\x05\x04\x00\x01'+b'\0'*6);return
                    self.wfile.write(b'\x05\x00\x00\x01'+b'\0'*6)
                    first=self.rfile.readline().decode();command=first.split()[1];headers={}
                    while True:
                        line=self.rfile.readline()
                        if line==b'\r\n':break
                        k,v=line.decode().split(':',1);headers[k.lower()]=v.strip()
                    self.rfile.read(int(headers['content-length']));outer.commands.append(command);outer.authorities.append(headers.get('authorization'))
                    if outer.mode=='lost-response' and command!='/health':return
                    if outer.mode=='timeout':time.sleep(.5);return
                    body=f.canonical(dict(ok=True,result=dict(provider=outer.provider,devnet_only=True) if command=='/health' else dict(accepted=True)))
                    if outer.mode=='malformed':body=b'not JSON'
                    if outer.mode=='long':response=b'HTTP/1.1 200 OK\r\nX: '+b'x'*17000
                    else:response=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n'+(b'Transfer-Encoding: chunked\r\n' if outer.mode=='chunked' else b'')+b'\r\n'+body
                    self.wfile.write(response)
                except (OSError,IndexError):pass
        super().__init__(('127.0.0.1',0),Handler)
    def __enter__(self):self.thread=threading.Thread(target=self.serve_forever,daemon=True);self.thread.start();return self
    def __exit__(self,*_):self.shutdown();self.server_close();self.thread.join(2)
    def transport(self,**kw):return OnionTransport(address(),self.provider,self.server_address[1],**kw)

class Cases(unittest.TestCase):
    def test_valid_onion_checksum(self):self.assertEqual(onion_address(address()),address())
    def test_invalid_destinations(self):
        for value in ['localhost','example.com','http://'+address(),address().upper(),address()+':80',address()+'/',address().replace('a','b',1),'x'*10000,None]:
            with self.subTest(value_type=type(value).__name__),self.assertRaises(ValueError):onion_address(value)
    def test_unknown_runtime(self):
        with self.assertRaises(ValueError):available('/nonexistent-n1-runtime')
    def test_config_path_injection_rejected(self):
        for path in ['/tmp/tor\nDisableNetwork 0','/tmp/tor space','../tor','/tmp/../tor']:
            with self.subTest(path_type='unsafe'),self.assertRaises(ValueError):tor_path(path)
    def test_corrupted_port_config_cannot_inject_torrc(self):
        for value in ['19050\nDisableNetwork 0',True,19051]:
            with self.subTest(type=type(value).__name__),tempfile.TemporaryDirectory(prefix='pn-n1-') as temp:
                home=private_dir(Path(temp)/'network');save_json(home/'ports',dict(orports=[value]*5,dirports=[19052]*5,socks=19053,control=[19054]*7))
                with self.assertRaises(ValueError):PrivateNetwork(home,19055)
                self.assertFalse((home/'auth0').exists())
        with tempfile.TemporaryDirectory(prefix='pn-n1-') as temp:
            home=private_dir(Path(temp)/'network');save_json(home/'ports',dict(version=999,relays=8,orports=[],dirports=[],socks=19053,control=[]))
            with self.assertRaises(ValueError):PrivateNetwork(home,19055)
            self.assertFalse((home/'auth0').exists())
    def test_endpoint_binding_copy_cannot_redirect(self):
        with Peer() as peer:
            t=peer.transport();copy=t.binding;copy['host']='example.com';self.assertEqual(t.binding['host'],address())
    def test_concurrent_queue_obeys_request_deadline(self):
        with Peer() as peer:
            t=peer.transport(timeout=.1);t.guard.acquire();start=time.monotonic()
            try:
                with self.assertRaises(TransportError) as e:t(80,'health')
                self.assertEqual(e.exception.code,'REQUEST_BUSY_DEADLINE');self.assertLess(time.monotonic()-start,.3);self.assertEqual(peer.commands,[])
            finally:t.guard.release()
    def test_domain_socks_and_no_dns(self):
        with Peer() as peer,patch('socket.getaddrinfo',side_effect=AssertionError('local DNS forbidden')):
            t=peer.transport();self.assertTrue(t(80,'health')['devnet_only']);self.assertEqual(peer.destinations,[(address(),80)]);self.assertEqual(t.state,'CONNECTED')
    def test_wrong_provider_never_sends_authority(self):
        with Peer() as peer:
            t=OnionTransport(address(),'b'*64,peer.server_address[1])
            with self.assertRaises(TransportError):t(80,'upload','c'*64,quote='d'*64,ciphertext='')
            self.assertEqual(peer.authorities,[None]);self.assertEqual(t.state,'FAILED')
    def test_lost_upload_response_is_unknown_no_retry(self):
        with Peer('lost-response') as peer:
            t=peer.transport(timeout=1)
            with self.assertRaises(TransportError) as e:t(80,'upload','c'*64,quote='d'*64,ciphertext='')
            self.assertEqual(e.exception.state,'UNKNOWN');self.assertEqual(peer.commands,['/health','/upload'])
    def test_socks_refusal_fails_no_http(self):
        with Peer('socks-refuse') as peer:
            t=peer.transport(timeout=1)
            with self.assertRaises(TransportError) as e:t(80,'health')
            self.assertEqual(e.exception.state,'FAILED');self.assertEqual(peer.commands,[])
    def test_routing_failure_no_fallback(self):
        with Peer('socks-error') as peer:
            t=peer.transport(timeout=1)
            with self.assertRaises(TransportError):t(80,'health')
            self.assertEqual(peer.commands,[]);self.assertEqual(len(peer.destinations),1)
    def test_missing_proxy_fails(self):
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        t=OnionTransport(address(),'a'*64,port,timeout=.1)
        with self.assertRaises(TransportError):t(80,'health')
        self.assertEqual(t.state,'FAILED')
    def test_deadline_bounds_response(self):
        with Peer('timeout') as peer:
            t=peer.transport(timeout=.1);start=time.monotonic()
            with self.assertRaises(TransportError):t(80,'health')
            self.assertLess(time.monotonic()-start,.4);self.assertEqual(t.state,'UNKNOWN')
    def test_cancellation_before_connect(self):
        with Peer() as peer:
            event=threading.Event();event.set();t=peer.transport(cancel=event)
            with self.assertRaises(TransportError) as e:t(80,'health')
            self.assertEqual(e.exception.code,'CANCELLED');self.assertEqual(peer.commands,[])
    def test_cancellation_after_request(self):
        with Peer('timeout') as peer:
            event=threading.Event();t=peer.transport(cancel=event);timer=threading.Timer(.05,event.set);timer.start()
            try:
                with self.assertRaises(TransportError) as e:t(80,'health')
                self.assertEqual(e.exception.state,'UNKNOWN')
            finally:timer.join()
    def test_response_bounds_and_framing(self):
        for mode in ('malformed','long','chunked'):
            with self.subTest(mode=mode),Peer(mode) as peer:
                with self.assertRaises(TransportError):peer.transport(timeout=1)(80,'health')
    def test_invalid_operation_never_connects(self):
        with Peer() as peer:
            with self.assertRaises(ValueError):peer.transport()(80,'../download')
            self.assertEqual(peer.commands,[])
    def test_endpoint_port_cannot_change(self):
        with Peer() as peer:
            with self.assertRaises(ValueError):peer.transport()(81,'health')
            self.assertEqual(peer.commands,[])
    def test_capability_header_injection(self):
        with Peer() as peer:
            with self.assertRaises(ValueError):peer.transport()(80,'status','secret\r\nHost: bad')
            self.assertEqual(peer.commands,[])
    def test_error_redaction(self):
        with Peer('malformed') as peer:
            with self.assertRaises(TransportError) as e:peer.transport()(80,'upload','c'*64)
            self.assertNotIn('c'*64,str(e.exception));self.assertNotIn(address(),str(e.exception))
    def test_public_template_disabled(self):
        with tempfile.TemporaryDirectory(prefix='pn-n1-') as temp:
            home=Path(temp)/'disabled';path=prepare_public(home,19381)
            self.assertIn('DisableNetwork 1',path.read_text());self.assertIn('127.0.0.1:19381',path.read_text());OwnedTor(TOR,path).verify()
            self.assertFalse((home/'onion/hostname').exists())

class BridgeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.forwarded=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                raw=self.rfile.read(int(self.headers['Content-Length']));cls.forwarded.append((self.path,self.headers['Host'],self.headers.get('Authorization'),raw))
                body=f.canonical(dict(ok=True,result=dict(mock_transport_peer=True)));self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        cls.upstream=HTTPServer(('127.0.0.1',0),Handler);cls.thread=threading.Thread(target=cls.upstream.serve_forever,daemon=True);cls.thread.start()
        with socket.socket() as s:s.bind(('127.0.0.1',0));cls.port=s.getsockname()[1]
        cls.process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('onion_bridge.py')),'--port',str(cls.port),'--upstream',str(cls.upstream.server_port),'--onion',address()],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        end=time.monotonic()+10
        while time.monotonic()<end:
            try:
                with socket.create_connection(('127.0.0.1',cls.port),timeout=.1):return
            except OSError:time.sleep(.02)
        cls.tearDownClass();raise AssertionError('bridge readiness')
    @classmethod
    def tearDownClass(cls):
        if cls.process.poll() is None:cls.process.terminate();cls.process.wait(timeout=5)
        cls.upstream.shutdown();cls.upstream.server_close();cls.thread.join(2)
    def request(self,path='/health',body=b'{}',extra=None,timeout=2):
        headers={'Host':address()+':80','Content-Type':'application/json'};headers.update(extra or {})
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1',self.port,timeout=timeout)) as conn:
            conn.request('POST',path,body=body,headers=headers);r=conn.getresponse();r.read();return r.status
    def test_static_upstream_host_rewrite_and_capability_header(self):
        self.assertEqual(self.request('/status',extra={'Authorization':'Bearer '+'c'*64}),200)
        self.assertEqual(self.forwarded[-1][1],'127.0.0.1:'+str(self.upstream.server_port));self.assertEqual(self.forwarded[-1][2],'Bearer '+'c'*64)
    def test_wrong_host_rejected(self):self.assertEqual(self.request(extra={'Host':'example.com'}),400)
    def test_browser_origin_rejected(self):self.assertEqual(self.request(extra={'Origin':'null'}),400)
    def test_browser_fetch_rejected(self):self.assertEqual(self.request(extra={'Sec-Fetch-Site':'same-origin'}),400)
    def test_chunking_rejected(self):self.assertEqual(self.request(extra={'Transfer-Encoding':'chunked'}),400)
    def test_malformed_body_rejected(self):self.assertEqual(self.request(body=b'not-json'),400)
    def test_traversal_or_query_paths_rejected(self):
        for path in ['/../download','/download?token=secret','http://example.com/health']:
            with self.subTest(path=path):self.assertEqual(self.request(path),400)
    def test_bad_capability_header_rejected(self):self.assertEqual(self.request(extra={'Authorization':'Bearer invalid'}),400)
    def test_size_bound_rejected_before_reading(self):self.assertEqual(self.request(extra={'Content-Length':str(LIMIT+1)}),400)
    def test_idle_connection_cannot_block_worker_indefinitely(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=1) as idle:
            time.sleep(.05);self.assertEqual(self.request(timeout=7),200)
    def test_partial_header_cannot_block_worker_indefinitely(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=1) as idle:
            idle.sendall(b'POST /health HTTP/1.1\r\nHost: ');time.sleep(.05);self.assertEqual(self.request(timeout=7),200)

def main():
    c.harden();start=time.monotonic();suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in (Cases,BridgeCases)]);result=unittest.TextTestRunner(verbosity=2).run(suite)
    out=ROOT/'docs/evidence/privacy-network-n1';out.mkdir(parents=True,exist_ok=True)
    (out/('unit-'+str(time.time_ns())+'.json')).write_bytes(f.canonical(dict(tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),failed_cases=[t.id() for t,_ in result.failures+result.errors],skipped=len(result.skipped),seconds=time.monotonic()-start,scope='SOCKS stub and actual loopback HTTP bridge fault tests, not actual Tor or payments'))+b'\n')
    if not result.wasSuccessful():sys.exit(1)
if __name__=='__main__':main()
