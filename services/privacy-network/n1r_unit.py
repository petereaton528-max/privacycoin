"""N1-R minimized regressions plus unchanged N1 boundary cases."""
from common import *
from tor_runtime import PrivateNetwork,OwnedTor,TOR
from n1_unit import Cases,BridgeCases
import unittest,tempfile,socket,socketserver,threading,time,argparse
from unittest.mock import Mock,patch
from runtime import Runtime,OwnedNode
from n1_diagnostics import Diagnostics
from n1_runtime import N1Runtime
from n1_unit import address
from tor_transport import OnionTransport,TransportError

class AdditionalBridgeCases(BridgeCases):
    def test_partial_body_cannot_block_worker_indefinitely(self):
        before=len(self.forwarded)
        with socket.create_connection(('127.0.0.1',self.port),timeout=1) as idle:
            idle.sendall(('POST /upload HTTP/1.1\r\nHost: '+address()+':80\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{').encode())
            time.sleep(.05);self.assertEqual(self.request(timeout=7),200)
        self.assertFalse(any(x[0]=='/upload' for x in self.forwarded[before:]))

class RepairCases(unittest.TestCase):
    def test_socks_retry_wire_isolation_and_deadline(self):
        modes=[];requests=[];tokens=[]
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(1);greeting=self.rfile.read(3);modes.append(greeting[-1]);self.wfile.write(b'\x05'+greeting[-1:])
                if greeting[-1]==2:
                    self.assert_auth()
                self.rfile.read(4);length=self.rfile.read(1)[0];self.rfile.read(length+2)
                if len(modes)==1:time.sleep(.25);return
                self.wfile.write(b'\x05\x00\x00\x01'+b'\0'*6)
                request=self.rfile.readline();requests.append(request)
                headers={}
                while True:
                    line=self.rfile.readline()
                    if line==b'\r\n':break
                    key,value=line.split(b':',1);headers[key.lower()]=value.strip()
                self.rfile.read(int(headers[b'content-length']))
                body=f.canonical(dict(ok=True,result=dict(provider='a'*64,devnet_only=True)))
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
            def assert_auth(self):
                if self.rfile.read(1)!=b'\x01':raise ValueError('auth framing')
                user=self.rfile.read(self.rfile.read(1)[0]);token=self.rfile.read(self.rfile.read(1)[0]);tokens.append((user,token));self.wfile.write(b'\x01\x00')
        server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler);server.daemon_threads=True;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            t=OnionTransport(address(),'a'*64,server.server_address[1],timeout=1)
            with patch('tor_transport.CONNECT_ATTEMPT_SECONDS',.05):
                self.assertTrue(t(80,'health')['devnet_only']);self.assertTrue(t(80,'health')['devnet_only'])
            self.assertEqual(modes,[0,2,2]);self.assertEqual(len(requests),2)
            self.assertEqual(tokens[0][0],b'<torS0X>0');self.assertEqual(len(tokens[0][1]),32);self.assertEqual(tokens[0],tokens[1])
        finally:server.shutdown();server.server_close();thread.join(2)
    def test_cancellation_during_reconnect_sends_no_second_request(self):
        cancel=Mock();cancel.wait.return_value=True
        t=OnionTransport(address(),'a'*64,19000,timeout=1,cancel=cancel)
        with patch.object(t,'_request',side_effect=TransportError('FAILED','SOCKS_CONNECT_REJECTED_1')) as request,self.assertRaises(TransportError) as failure:t(80,'health')
        self.assertEqual(failure.exception.code,'CANCELLED');self.assertEqual(request.call_count,1)
    def test_retry_isolates_stale_pre_http_circuit(self):
        t=OnionTransport(address(),'a'*64,19000,timeout=40)
        with patch.object(t,'_request',side_effect=[TransportError('FAILED','SOCKS_CONNECT_TimeoutError'),dict(provider='a'*64,devnet_only=True)]) as request:
            self.assertTrue(t(80,'health')['devnet_only'])
            self.assertFalse(request.call_args_list[0].kwargs.get('isolate',False))
            self.assertTrue(request.call_args_list[1].kwargs.get('isolate',False))
            self.assertEqual(request.call_args_list[0].args[-1],request.call_args_list[1].args[-1])
    def test_transient_socks_general_failure_reconnects_before_http_only(self):
        t=OnionTransport(address(),'a'*64,19000,timeout=1)
        health=dict(provider='a'*64,devnet_only=True)
        with patch.object(t,'_request',side_effect=[TransportError('FAILED','SOCKS_CONNECT_REJECTED_1'),health,dict(read=True)]) as request:
            self.assertEqual(t(80,'download','c'*64,quote='d'*64),dict(read=True))
            self.assertEqual(request.call_count,3)
            self.assertIsNone(request.call_args_list[0].args[1]);self.assertIsNone(request.call_args_list[1].args[1])
            self.assertEqual(request.call_args_list[2].args[0],'download')
    def test_persistent_socks_general_failure_is_bounded_three_attempts(self):
        t=OnionTransport(address(),'a'*64,19000,timeout=1)
        with patch.object(t,'_request',side_effect=TransportError('FAILED','SOCKS_CONNECT_REJECTED_1')) as request,self.assertRaises(TransportError):t(80,'health')
        self.assertEqual(request.call_count,3)
    def test_unknown_http_result_is_never_automatically_retried(self):
        t=OnionTransport(address(),'a'*64,19000,timeout=1)
        with patch.object(t,'_request',side_effect=TransportError('UNKNOWN','HTTP_HEADER_OSError')) as request,self.assertRaises(TransportError):t(80,'health')
        self.assertEqual(request.call_count,1)
    def test_bridge_start_waits_for_actual_http_readiness(self):
        with tempfile.TemporaryDirectory(prefix='pn-n1r-') as tmp:
            home=private_dir(Path(tmp)/'runtime');provider=private_dir(home/'provider-0');save_json(provider/'control',dict(id='a'*64))
            runtime=object.__new__(N1Runtime);runtime.home=home;runtime.bridge=None;runtime.port=19000;runtime.diagnostics=None;runtime.tor=Mock(hostname=address());runtime.local=Mock(base=home,config=dict(ports=[19001]))
            process=Mock(pid=12345);process.poll.return_value=None
            reply=Mock(status=200);reply.read.return_value=f.canonical(dict(ok=True,result=dict(provider='a'*64,devnet_only=True)))
            first=Mock();first.request.side_effect=ConnectionRefusedError();second=Mock();second.getresponse.return_value=reply
            with patch('n1_runtime.subprocess.Popen',return_value=process),patch('n1_runtime.time.sleep'),patch('n1_runtime.http.client.HTTPConnection',side_effect=[first,second]) as connect:
                runtime.start_bridge();self.assertEqual(connect.call_count,2)
    def test_private_queue_budget_has_consensus_compression_headroom(self):
        with tempfile.TemporaryDirectory(prefix='pn-n1r-') as tmp:
            network=PrivateNetwork(Path(tmp)/'tor',19876)
            try:
                for node in network.nodes:self.assertIn('MaxMemInQueues 256 MB',node.config.read_text())
                for node in network.nodes[:5]:
                    self.assertIn('V3AuthVotingInterval 300',node.config.read_text())
                    self.assertIn('V3AuthVoteDelay 20',node.config.read_text())
                    self.assertIn('V3AuthDistDelay 20',node.config.read_text())
                    self.assertIn('V3AuthNIntervalsValid 5',node.config.read_text())
            finally:network.close()
    def test_duplicate_provider_start_preserves_owned_process(self):
        runtime=object.__new__(Runtime);child=Mock();child.poll.return_value=None;runtime.children={0:child}
        runtime.base=Path('/tmp');runtime.config=dict(ports=[12345]);runtime.node=Mock(rpc=12346)
        with patch('runtime.subprocess.Popen',side_effect=AssertionError('unexpected duplicate launch')) as popen,self.assertRaises(ValueError):runtime.start_provider(0)
        popen.assert_not_called();self.assertIs(runtime.children[0],child)
    def test_duplicate_node_start_preserves_owned_process(self):
        node=object.__new__(OwnedNode);child=Mock();child.poll.return_value=None;node.p=child
        node.path=Path('/tmp');node.rpc=12345;node.p2p=12346
        with patch('runtime.requirements'),patch('runtime.subprocess.Popen',side_effect=AssertionError('unexpected duplicate launch')) as popen,self.assertRaises(ValueError):node.start()
        popen.assert_not_called();self.assertIs(node.p,child)
    def test_diagnostics_reject_secret_fields_and_bound_storage(self):
        with tempfile.TemporaryDirectory(prefix='pn-n1r-') as tmp:
            path=private_dir(Path(tmp)/'private')/'trace';trace=Diagnostics(path,limit=300)
            with self.assertRaises(ValueError):trace.event('request',password='never written')
            for i in range(10):trace.event('request_start',trace='0'*16,operation='health',attempt=i)
            self.assertLessEqual(path.stat().st_size,300);self.assertEqual(path.stat().st_mode&0o077,0)
    def test_additional_relays_are_not_clients_or_hidden_services(self):
        with tempfile.TemporaryDirectory(prefix='pn-n1r-') as tmp:
            network=PrivateNetwork(Path(tmp)/'tor',19876,experimental_upstream=True)
            try:
                self.assertEqual(len(network.nodes),10)
                for node in network.nodes[3:8]:
                    config=node.config.read_text()
                    self.assertNotIn('ClientOnly 1',config)
                    self.assertNotIn('HiddenServiceDir',config)
                    self.assertIn('ORPort 127.0.0.1:',config)
                    self.assertIn('AssumeReachable 1',config)
                self.assertIn('/service/onion',str(network.onion_home))
            finally:network.close()
    def test_control_reply_waits_for_complete_multiline_response(self):
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.rfile.readline();self.wfile.write(b'250 OK\r\n');self.wfile.flush()
                self.rfile.readline();self.wfile.write(b'250-status/bootstrap-phase=NOTICE ');self.wfile.flush();time.sleep(.05)
                self.wfile.write(b'BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n250 OK\r\n');self.wfile.flush()
        server=socketserver.TCPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='pn-n1r-') as tmp:
                home=private_dir(Path(tmp)/'control');c.write_private(home/'control_auth_cookie',b'x'*32)
                c.write_private(home/'torrc',('ControlPort 127.0.0.1:'+str(server.server_address[1])+'\n').encode())
                response=OwnedTor(TOR,home/'torrc').control('GETINFO status/bootstrap-phase')
                self.assertIn(b'PROGRESS=100',response);self.assertTrue(response.endswith(b'250 OK\r\n'))
        finally:server.shutdown();server.server_close();thread.join(2)

def main():
    c.harden();p=argparse.ArgumentParser();p.add_argument('--minimal',action='store_true');a=p.parse_args();start=time.monotonic()
    classes=(RepairCases,) if a.minimal else (Cases,BridgeCases,RepairCases)
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in classes)
    if not a.minimal:suite.addTest(AdditionalBridgeCases('test_partial_body_cannot_block_worker_indefinitely'))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    out=ROOT/'docs/evidence/privacy-network-n1-repair'/('unit-'+str(time.time_ns())+'.json')
    out.write_bytes(f.canonical(dict(tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),failed_cases=[t.id() for t,_ in result.failures+result.errors],seconds=time.monotonic()-start,minimal=a.minimal,result='PASS' if result.wasSuccessful() else 'FAIL'))+b'\n');print(out.name)
    if not result.wasSuccessful():sys.exit(1)
if __name__=='__main__':main()
