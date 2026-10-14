"""Public admission guards; offline protocol tests, not external Tor evidence.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import base64,hashlib,os,socket,ssl,subprocess,tempfile,time,unittest,threading
from pathlib import Path
from apps.network_v1 import onion
from apps.network_v1.public_network import Directory,PublicChannel,proof,read_json,send_json,HELLO
from apps.network_v1.peer_uri import parse,format_link
from src.network_identity import selected

def descriptor(index=1):
    from apps.network_v1.rpc import NETWORK,GENESIS,PROFILE
    raw=hashlib.sha256(str(index).encode()).digest()
    name=base64.b32encode(raw+hashlib.sha3_256(b'.onion checksum'+raw+b'\x03').digest()[:2]+b'\x03').decode().lower()+'.onion'
    return dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,onion=name,certificate_sha256=hashlib.sha256(raw).hexdigest())

class PublicGuards(unittest.TestCase):
    def test_real_tls_unknown_wire_version_rejected_before_native_access(self):
        with tempfile.TemporaryDirectory(prefix='pc-public-version-') as d:
            home=Path(d);home.chmod(0o700);key,cert=home/'key',home/'cert'
            subprocess.run([onion.openssl_binary(),'req','-x509','-newkey','ed25519','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=disposable'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            key.chmod(0o600);cert.chmod(0o600);own=descriptor();own['certificate_sha256']=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
            with socket.socket() as target:
                target.bind(('127.0.0.1',0));target.listen();target.settimeout(.1)
                with socket.socket() as slot:slot.bind(('127.0.0.1',0));port=slot.getsockname()[1]
                ch=PublicChannel(port,target.getsockname()[1],own=lambda:own,key=key,certificate=cert,directory=Directory())
                thread=threading.Thread(target=ch.run);thread.start()
                try:
                    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
                    with socket.create_connection(('127.0.0.1',port),timeout=2) as raw:
                        with ctx.wrap_socket(raw,server_hostname=None) as secure:
                            onion.pinned(secure,own);secure.sendall(b'PCOPEN99');self.assertEqual(secure.recv(1),b'')
                    end=time.monotonic()+2
                    while not ch.errors and time.monotonic()<end:time.sleep(.01)
                    self.assertEqual(ch.errors.get('REJECTED'),1);self.assertFalse(ch.identity_leases);self.assertFalse(ch.directory.values)
                    with self.assertRaises(TimeoutError):target.accept()
                finally:ch.close();thread.join(1)
                self.assertFalse(thread.is_alive())
    def test_real_tls_identity_cannot_hoard_inbound_sessions(self):
        from apps.network_v1.tests.local_socks import Socks
        def port():
            with socket.socket() as stream:stream.bind(('127.0.0.1',0));return stream.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix='pc-public-leases-') as d:
            home=Path(d);home.chmod(0o700);identities=[]
            for index in (1,2):
                key,cert=home/('key'+str(index)),home/('cert'+str(index))
                subprocess.run([onion.openssl_binary(),'req','-x509','-newkey','ed25519','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=disposable'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
                key.chmod(0o600);cert.chmod(0o600);value=descriptor(index);value['certificate_sha256']=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest();identities.append((value,key,cert))
            own,key,cert=identities[0];remote,rkey,rcert=identities[1];number=port()
            server=PublicChannel(number,port(),own=lambda:own,key=key,certificate=cert,directory=Directory())
            thread=threading.Thread(target=server.run);thread.start();socks=Socks({own['onion']:number},seed=1)
            clients=[]
            try:
                for _ in range(2):clients.append(PublicChannel(port(),80,peer=own,socks=socks.port,own=lambda:remote,key=rkey,certificate=rcert,directory=Directory()))
                clients[0].connect()
                with self.assertRaises((ValueError,OSError)):clients[1].connect()
                self.assertEqual(len(server.identity_leases),1)
                clients[0].close();end=time.monotonic()+2
                while server.identity_leases and time.monotonic()<end:time.sleep(.01)
                self.assertFalse(server.identity_leases)
            finally:
                for client in clients:client.close()
                server.close();thread.join(1);socks.close()
    def test_wallet_filename_entrypoint_without_project_pythonpath(self):
        import sys
        root=Path(__file__).resolve().parents[3]
        env=dict(os.environ);env.pop('PYTHONPATH',None)
        with tempfile.TemporaryDirectory(prefix='pc-public-wallet-entry-') as home:
            result=subprocess.run([sys.executable,str(root/'src/phase4/wallet.py'),'--help'],cwd=home,env=env,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0)
    def test_cancel_closes_real_stalled_tls_handshake(self):
        with tempfile.TemporaryDirectory(prefix='pc-public-stalled-tls-') as d:
            home=Path(d);home.chmod(0o700);key,cert=home/'key',home/'cert'
            subprocess.run([onion.openssl_binary(),'req','-x509','-newkey','ed25519','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=disposable'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=5)
            key.chmod(0o600);cert.chmod(0o600)
            with socket.socket() as port:port.bind(('127.0.0.1',0));number=port.getsockname()[1]
            ch=PublicChannel(number,number+1 if number<65535 else number-1,own=lambda:descriptor(),key=key,certificate=cert,directory=Directory())
            runner=threading.Thread(target=ch.run);runner.start();source=socket.create_connection(('127.0.0.1',number),timeout=2)
            try:
                end=time.monotonic()+2
                while not ch.threads and time.monotonic()<end:time.sleep(.01)
                began=time.monotonic();ch.close();runner.join(1)
                self.assertLess(time.monotonic()-began,2);self.assertFalse(runner.is_alive())
                self.assertFalse(any(t.is_alive() for t in ch.threads));self.assertFalse(ch.active)
            finally:source.close();ch.close()
    def test_rejected_retry_cannot_extend_backoff(self):
        ch=PublicChannel.__new__(PublicChannel);ch.reuse_lock=threading.Lock();ch.guard=threading.Lock()
        ch.next_attempt=time.monotonic()+10;ch.failures=2
        before=ch.next_attempt
        for _ in range(30):
            with self.assertRaisesRegex(ValueError,'PUBLIC_BACKOFF'):ch.outbound(None)
        self.assertEqual(ch.next_attempt,before);self.assertEqual(ch.failures,2)
    def test_privileged_rpc_and_other_network_frames_rejected(self):
        pc,*_=onion.dependencies()
        from apps.network_v1.rpc import NETWORK,GENESIS,PROFILE
        for change in ({'command':'submit_tx'},{'command':'shutdown'},{'network':'PrivacyCoinWrong'},{'profile':'wrong'}):
            left,right=socket.socketpair()
            try:
                value=dict(network=NETWORK,genesis=GENESIS,profile=PROFILE,command='status');value.update(change)
                raw=pc.f.canonical(value)
                left.sendall(NETWORK.encode()+len(raw).to_bytes(4,'big')+raw)
                with self.assertRaises(ValueError):pc.frame(right,time.monotonic()+1,True)
            finally:left.close();right.close()
    def test_explicit_upstream_guard_and_unavailable_proxy(self):
        from apps.network_v1.upstream import validate,directive,probe
        self.assertEqual(directive(dict(host='::1',port=22307)),'Socks5Proxy [::1]:22307')
        for value in (dict(host='example.com',port=22307),dict(host='8.8.8.8',port=22307),dict(host='0.0.0.0',port=22307),dict(host='127.0.0.1\nDisableNetwork 0',port=22307),dict(host='127.0.0.1',port=True),dict(host='127.0.0.1',port=22)):
            with self.assertRaises(ValueError):validate(value)
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
            with self.assertRaises(OSError):probe(dict(host='127.0.0.1',port=port))
    def test_local_upstream_handshake_fragmentation_and_authentication_failure(self):
        from apps.network_v1.upstream import probe
        for reply in (b'\x05\x00',b'\x05\x02',b'\x05\xff',b'\x04\x00',b''):
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);number=listener.getsockname()[1]
            greetings=[]
            def server():
                with listener.accept()[0] as stream:
                    stream.settimeout(2);greetings.append(stream.recv(3))
                    for byte in reply:stream.sendall(bytes([byte]))
            thread=threading.Thread(target=server);thread.start()
            try:
                if reply==b'\x05\x00':probe(dict(host='127.0.0.1',port=number))
                else:
                    with self.assertRaises(ValueError):probe(dict(host='127.0.0.1',port=number))
            finally:thread.join(3);listener.close()
            self.assertFalse(thread.is_alive());self.assertEqual(greetings,[b'\x05\x01\x00'])
    def test_native_magic_length_and_separation(self):
        a=selected('legacy-dev01');b=selected('open-dev02')
        self.assertEqual((len(a[0]),len(b[0])),(16,16));self.assertNotEqual(a[0],b[0]);self.assertNotEqual(a[2],b[2])
        self.assertEqual(a[1],b[1]) # retained genesis; no new Mainnet claim
        for value in ('mainnet','testnet','',None):
            if value is not None:
                with self.assertRaises(ValueError):selected(value)
    def test_public_link_roundtrip_no_ticket(self):
        value=descriptor();link=format_link(value)
        self.assertEqual(parse(link),value);self.assertNotIn('ticket',link)
        for bad in (link+'&ticket=secret',link+'&pin='+value['certificate_sha256'],link.replace('pcnode:','https:'),link+'#x',link.replace('?','/?'),link.replace('network=','network=wrong'),link+' ',link.replace('://','://user@')):
            with self.subTest(case=bad[:20]),self.assertRaises(ValueError):parse(bad)
    def test_bounded_directory_and_pin_conflicts(self):
        directory=Directory([descriptor()]);self.assertEqual(directory.catalog(),[])
        directory.add(descriptor(),verified=True);self.assertEqual(directory.catalog(),[descriptor()])
        for index in range(2,40):directory.add(descriptor(index))
        self.assertLessEqual(len(directory.candidates()),32)
        with self.assertRaises(ValueError):directory.add(dict(descriptor(),certificate_sha256='f'*64))
    def test_one_gossip_source_cannot_fill_directory(self):
        directory=Directory()
        for index in range(1,8):directory.add(descriptor(index),source='one-peer')
        self.assertEqual(len(directory.candidates()),2)
        directory.add(descriptor(1),verified=True)
        self.assertFalse(directory.add(descriptor(8),source='one-peer'))
        self.assertTrue(directory.add(descriptor(9),source='other-peer'))
    def test_network_genesis_protocol_and_schema_rejections(self):
        value=descriptor()
        for key,data in [('network','wrong'),('genesis','f'*64),('profile','wrong'),('version',2),('version',True),('onion','127.0.0.1'),('certificate_sha256','x'*64)]:
            with self.subTest(key=key),self.assertRaises(ValueError):Directory([dict(value,**{key:data})])
        with self.assertRaises(ValueError):Directory([dict(value,ticket='not-needed')])
    def test_fragmented_json_exact_read_and_bound(self):
        pc,*_=onion.dependencies();left,right=socket.socketpair()
        try:
            raw=pc.f.canonical({'value':'ordinary public data'});framed=len(raw).to_bytes(4,'big')+raw
            for byte in framed:left.sendall(bytes([byte]))
            self.assertEqual(read_json(pc,right,time.monotonic()+1),{'value':'ordinary public data'})
            left.sendall((16385).to_bytes(4,'big'))
            with self.assertRaises(ValueError):read_json(pc,right,time.monotonic()+1)
        finally:left.close();right.close()
    def test_eof_and_expired_deadline(self):
        pc,*_=onion.dependencies();left,right=socket.socketpair();left.close()
        try:
            with self.assertRaises(ValueError):read_json(pc,right,time.monotonic()+1)
            with self.assertRaises(TimeoutError):pc.read(right,1,time.monotonic()-1)
        finally:right.close()
    def test_real_ed25519_proof_replay_and_wrong_identity(self):
        with tempfile.TemporaryDirectory(prefix='pc-public-proof-test-') as d:
            home=Path(d);key=home/'key';cert=home/'cert'
            subprocess.run([onion.openssl_binary(),'req','-x509','-newkey','ed25519','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=disposable'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=5)
            message=HELLO+os.urandom(32)+b'public descriptor'
            signature=proof(key,None,message);proof(None,cert.read_bytes(),message,signature)
            for wrong in (message+b'changed',HELLO+os.urandom(32)+b'public descriptor'):
                with self.assertRaises(ValueError):proof(None,cert.read_bytes(),wrong,signature)
            with self.assertRaises(ValueError):proof(None,cert.read_bytes(),message,b'0'*64)
            with self.assertRaises(ValueError):proof(None,b'not a certificate',message,signature)

if __name__=='__main__':unittest.main()
