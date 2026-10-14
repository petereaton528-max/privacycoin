"""Real Tor upload acknowledgement loss; test-only owned loopback fault relay."""
from common import *
from n1_runtime import N1Runtime
from n1_diagnostics import Diagnostics
from tor_transport import TransportError
from client import Client,retrieve
import socket,socketserver,threading,time,argparse
OUT=ROOT/'docs/evidence/privacy-network-n1-repair'

class DropOnce(socketserver.TCPServer):
    allow_reuse_address=True
    def __init__(self,port,upstream):
        self.dropped=0;self.errors=[];outer=self
        def message(sock):
            raw=b''
            while b'\r\n\r\n' not in raw:
                part=sock.recv(1)
                if not part or len(raw)>=16384:raise ValueError('bounded framing')
                raw+=part
            length=int(next(x.split(b':',1)[1] for x in raw.split(b'\r\n') if x.lower().startswith(b'content-length:')))
            f.integer(length,0,2*MAX_CIPHER+8192)
            body=b''
            while len(body)<length:
                part=sock.recv(min(65536,length-len(body)))
                if not part:raise ValueError('truncated')
                body+=part
            return raw+body
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(40)
                with socket.socket() as backend:
                    backend.settimeout(40);backend.connect(('127.0.0.1',upstream))
                    request=message(self.request);backend.sendall(request);response=message(backend)
                    if request.startswith(b'POST /upload ') and outer.dropped==0:
                        outer.dropped=1;return # Actual reply bytes withheld after real provider commit.
                    self.request.sendall(response)
        super().__init__(('127.0.0.1',port),Handler);self.handle_error=lambda *_:self.errors.append(sys.exc_info()[0].__name__)

def main():
    c.harden();p=argparse.ArgumentParser();p.add_argument('--home',type=Path,required=True);p.add_argument('--resume-only',action='store_true');a=p.parse_args();assert a.home.is_relative_to(NATIVE/'build/privacy-network-n1-repair')
    r=None;proxy=None;thread=None;checks=[];report={};start=time.monotonic()
    def check(name,condition=True):assert condition,name;checks.append(name);print('PASS',name,flush=True)
    try:
        r=N1Runtime(a.home,diagnostics=Diagnostics(a.home/('fault-trace-'+str(time.time_ns()))))
        plain=b'N1-R actual Tor lost upload acknowledgement fixture\n'
        if a.resume_only:
            candidates=[load_json(p)['quote'] for p in r.client.home.glob('*.intent') if load_json(p)['quote']['quota']==len(plain)+44 and load_json(p)['payment']!='NOT_AUTHORIZED']
            assert len(candidates)==1;q=candidates[0];data=load_json(r.client.home/(q['id']+'.upload'));cipher=decode(data['ciphertext']);bundle=data['bundle'];check('resume existing paid intent without another authorization or mining')
        else:
            q=r.client.quote(len(plain));cipher,bundle=r.client.encrypt(q['id'],plain)
            r.local.session.refresh();r.client.pay(q['id'],r.local.session,'CONFIRM');check('explicit new disposable payment is only MEMPOOL_ONLY',r.client.status(q['id'])['state']=='MEMPOOL_ONLY');r.local.mine(10)
        check('independent provider locally confirms exact payment',r.client.status(q['id'])['state']=='CONFIRMED_LOCAL')
        before=call(r.local.config['ports'][0],'usage',r.client.admin)['stored_bytes']
        original=r.port;r.stop_bridge();r.port=r.local.h.g.port();r.start_bridge();proxy=DropOnce(original,r.port);thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
        try:r.client.upload(q['id']);raise AssertionError('lost acknowledgement must not succeed')
        except TransportError as error:check('real lost Tor upload response remains UNKNOWN',error.state=='UNKNOWN')
        check('fault relay dropped exactly one upload response',proxy.dropped==1)
        check('provider durably committed exactly one ciphertext before lost acknowledgement',call(r.local.config['ports'][0],'usage',r.client.admin)['stored_bytes']==before+len(cipher))
        client=Client(r.client.home,80,r.client.admin,r.transport);r.local.session.close()
        try:client.pay(q['id'],r.local.session,'CONFIRM');raise AssertionError('second approval accepted')
        except ValueError:check('restarted client cannot silently authorize another payment')
        r.local.stop_provider(0,crash=True);r.local.start_provider(0)
        check('provider restart reconciles original paid entitlement',client.status(q['id'])['state']=='CONFIRMED_LOCAL')
        check('explicit identical ciphertext retry is idempotent',client.upload(q['id'])['idempotent'])
        check('retry allocates no duplicate resource',call(r.local.config['ports'][0],'usage',client.admin)['stored_bytes']==before+len(cipher))
        check('Bob retrieves original exact hash without unlocked signer',digest(retrieve(bundle,r.transport))==digest(plain) and r.local.session.wallet is None)
        report['result']='PASS'
    except Exception as error:report.update(result='FAIL',error_type=type(error).__name__,code=error.code if isinstance(error,TransportError) else 'PRIVATE_DIAGNOSTIC')
    finally:
        if proxy:proxy.shutdown();proxy.server_close();thread.join(5)
        if r:r.close()
        report.update(checks=checks,passed=len(checks),seconds=time.monotonic()-start,private_fixture=str(a.home),proxy_errors=proxy.errors if proxy else [],scope='Real PC private payment, actual private Tor, test-only TCP relay withholds committed upload reply, no automatic retry/replacement payment')
        out=OUT/('faults-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(report)+b'\n');print(report['result'],out.name,flush=True)
    if report['result']!='PASS':sys.exit(1)
if __name__=='__main__':main()
