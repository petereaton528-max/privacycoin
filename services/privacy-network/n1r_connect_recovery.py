"""Real private Tor recovery after one test-only pre-HTTP SOCKS rejection."""
from common import *
from n1_runtime import N1Runtime
from n1_diagnostics import Diagnostics
from tor_transport import OnionTransport
from client import retrieve
import socket,socketserver,threading,select,time,argparse
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'

class RejectOnce(socketserver.ThreadingTCPServer):
    daemon_threads=True
    def __init__(self,upstream):
        self.rejected=0;self.forwarded=0;self.lock=threading.Lock();outer=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(2)
                with outer.lock:
                    reject=outer.rejected==0
                    if reject:outer.rejected+=1
                    else:outer.forwarded+=1
                if reject:
                    if self.rfile.read(3)!=b'\x05\x01\x00':return
                    self.wfile.write(b'\x05\x00');self.wfile.flush()
                    if self.rfile.read(4)!=b'\x05\x01\x00\x03':return
                    self.rfile.read(self.rfile.read(1)[0]+2)
                    self.wfile.write(b'\x05\x01\x00\x01'+b'\0'*6);return
                with socket.socket() as remote:
                    remote.settimeout(2);remote.connect(('127.0.0.1',upstream))
                    deadline=time.monotonic()+40;total=0
                    while time.monotonic()<deadline:
                        ready,_,_=select.select([self.connection,remote],[],[],min(.2,max(0,deadline-time.monotonic())))
                        for source in ready:
                            part=source.recv(65536)
                            if not part:return
                            total+=len(part)
                            if total>4*MAX_CIPHER+32768:return
                            (remote if source is self.connection else self.connection).sendall(part)
        super().__init__(('127.0.0.1',0),Handler);self.handle_error=lambda *_:None

def main():
    c.harden();p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);a=p.parse_args()
    assert a.home.is_relative_to(NATIVE/'build/privacy-network-n1-repair')
    r=proxy=thread=None;checks=[];report={};started=time.monotonic()
    try:
        trace=Diagnostics(a.home/('reconnect-trace-'+str(time.time_ns())))
        r=N1Runtime(a.home,diagnostics=trace);r.local.session.close()
        bundle=load_json(next((a.home/'onion-client').glob('*.upload')))['bundle']
        proxy=RejectOnce(r.tor.socks_port);thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
        t=OnionTransport(r.tor.hostname,bundle['provider'],proxy.server_address[1],diagnostics=trace)
        assert digest(retrieve(bundle,t))==bundle['plain_hash'];checks.append('real Tor format-0 isolated retry retrieves exact hash after pre-HTTP rejection')
        assert proxy.rejected==1 and t._isolation is not None;checks.append('exactly one rejected handshake triggers bounded circuit isolation')
        assert proxy.forwarded==3;checks.append('two pinned health checks and one download reached actual Tor after rejected connection')
        for i in range(10):assert digest(retrieve(bundle,t))==bundle['plain_hash']
        checks.append('ten subsequent actual isolated Tor reads retain exact integrity')
        assert r.local.session.wallet is None;checks.append('no unlocked signer or new payment needed for transport recovery')
        report['result']='PASS'
    except Exception as error:report.update(result='FAIL',error_type=type(error).__name__)
    finally:
        if proxy:proxy.shutdown();proxy.server_close();thread.join(5)
        if r:r.close()
        report.update(checks=checks,passed=len(checks),seconds=time.monotonic()-started,private_fixture=str(a.home),scope='Real isolated Tor and existing paid ciphertext; test-only loopback SOCKS rejection, no payment/mining, no direct fallback')
        out=OUT/('connect-recovery-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(report)+b'\n');print(report['result'],out.name)
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
