"""Open consensus participation over Onion + TLS 1.3. No resource/admin route.

Onion services authenticate the destination; TLS cert pins bind advertised peers.
Incoming consensus participants need no shared CA or administrator enrollment.
Existing mutually authenticated N2/Provider transports remain unchanged.
"""
import hashlib
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
DISCOVERY=b'PCV1D001'

def openssl_binary():
    if os.name!='nt':
        bundled=ROOT/'runtime/bin/openssl'
        return str(bundled) if bundled.is_file() and not bundled.is_symlink() else 'openssl'
    value=ROOT/'runtime/bin/pc-tls-tools.exe'
    if not value.is_file() or value.is_symlink():raise ValueError('BUNDLED_TLS_TOOL_REQUIRED')
    return str(value)


def pinned(secure,peer):
    raw=secure.getpeercert(binary_form=True)
    if not raw or len(raw)>16384 or hashlib.sha256(raw).hexdigest()!=peer['certificate_sha256']:raise ValueError('PEER_CERTIFICATE_PIN')
    # Exact pin is the trust root, but expiry still matters. Parse only the
    # PUBLIC peer certificate; keep all tool diagnostics out of application logs.
    result=subprocess.run([openssl_binary(),'x509','-noout','-startdate','-enddate'],input=ssl.DER_cert_to_PEM_cert(raw).encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3)
    if result.returncode or len(result.stdout)>512:raise ValueError('PEER_CERTIFICATE_DATES')
    dates=dict(s.split('=',1) for s in result.stdout.decode('ascii').splitlines());now=time.time()
    if not ssl.cert_time_to_seconds(dates['notBefore'])<=now<ssl.cert_time_to_seconds(dates['notAfter']):raise ValueError('PEER_CERTIFICATE_EXPIRED_OR_NOT_YET_VALID')


def discover(peer,socks):
    """Authenticated transport hints, never chain state or enrollment."""
    pc,*_=dependencies();peer=descriptor(peer);end=time.monotonic()+10
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
    with pc.connect(dict(endpoint=peer['onion'],socks_port=socks,target_port=80),end) as raw:
        with ctx.wrap_socket(raw,server_hostname=None) as secure:
            pinned(secure,peer)
            pc.write(secure,DISCOVERY,end);n=int.from_bytes(pc.read(secure,4,end),'big')
            if not 1<=n<=16384:raise ValueError('DISCOVERY_BOUND')
            value=pc.f.decode(pc.read(secure,n,end))
            if not isinstance(value,list) or len(value)>8:raise ValueError('DISCOVERY_BOUND')
            return [descriptor(v) for v in value]


def dependencies():
    sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
    import p2p_channel as pc
    from tor_runtime import OwnedTor, write_config, tor_path
    return pc,OwnedTor,write_config,tor_path


def descriptor(value):
    from .rpc import NETWORK,GENESIS,PROFILE
    pc,*_=dependencies()
    if not isinstance(value,dict) or set(value)!={'version','network','genesis','profile','onion','certificate_sha256'} or type(value['version']) is not int or value['version']!=1:
        raise ValueError('PEER_DESCRIPTOR_SCHEMA')
    if (value['network'],value['genesis'],value['profile'])!=(NETWORK,GENESIS,PROFILE): raise ValueError('PEER_NETWORK')
    pc.onion_address(value['onion']); pc.f.unhex(value['certificate_sha256'],32)
    return value


class Channel:
    def __init__(self, listen, target, *, certificate=None, key=None, peer=None, socks=None, catalog=None):
        self.pc,*_=dependencies(); self.peer=descriptor(peer) if peer else None
        self.pc.port(listen);self.pc.port(target,1 if peer else 1024)
        if listen==target: raise ValueError('LOOP')
        self.target=target; self.socks=socks;self.catalog=catalog or (lambda:[]);self.stop=threading.Event();self.slots=threading.BoundedSemaphore(4);self.threads=[]
        self.guard=threading.Lock();self.failures=0;self.next_attempt=0.;self.forwarded=0;self.last_success=None
        self.ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if peer else ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        if peer:
            self.pc.port(socks); self.ctx.check_hostname=False;self.ctx.verify_mode=ssl.CERT_NONE
            # Standard CA validation is replaced by an exact advertised cert pin
            # after handshake, before ANY application bytes are sent.
        else:
            for p in (certificate,key): self.pc.c.read_private(Path(p))
            self.ctx.load_cert_chain(str(certificate),str(key));self.ctx.num_tickets=0
        self.listener=socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:self.listener.bind(('127.0.0.1',listen));self.listener.listen(4);self.listener.settimeout(.2)
        except BaseException:self.listener.close();raise

    def handle(self, source):
        target=None; secure=None
        try:
            end=time.monotonic()+10;source.settimeout(10)
            if self.peer:
                with self.guard:
                    if time.monotonic()<self.next_attempt:raise ValueError('BACKOFF')
                target=self.pc.connect(dict(endpoint=self.peer['onion'],socks_port=self.socks,target_port=80),end)
                secure=self.ctx.wrap_socket(target,server_hostname=None)
                pinned(secure,self.peer)
                self.pc.write(secure,self.pc.frame(source,end,True),end)
                self.pc.write(source,self.pc.frame(secure,end,False),end)
                with self.guard:self.failures=0;self.next_attempt=0.;self.forwarded+=1;self.last_success=time.monotonic()
            else:
                secure=self.ctx.wrap_socket(source,server_side=True)
                prefix=self.pc.read(secure,8,end)
                if prefix==DISCOVERY:
                    raw=self.pc.f.canonical([descriptor(p) for p in self.catalog()][:8]);self.pc.write(secure,len(raw).to_bytes(4,'big')+raw,end);return
                class Buffered:
                    def __init__(self):self.prefix=prefix
                    def settimeout(self,value):secure.settimeout(value)
                    def recv(self,n):
                        if self.prefix:part=self.prefix[:n];self.prefix=self.prefix[n:];return part
                        return secure.recv(n)
                raw=self.pc.frame(Buffered(),end,True)
                target=socket.create_connection(('127.0.0.1',self.target),timeout=5)
                self.pc.write(target,raw,end);self.pc.write(secure,self.pc.frame(target,end,False),end)
        except Exception:
            # Delay retry eligibility; never sleep while holding a request slot.
            if self.peer:
                with self.guard:
                    if time.monotonic()>=self.next_attempt:
                        self.failures=min(self.failures+1,6);self.next_attempt=time.monotonic()+min(30,2**(self.failures-1))
        finally:
            for s in (source,secure,target):
                if s:
                    try:s.close()
                    except OSError:pass
            self.slots.release()

    def run(self):
        while not self.stop.is_set():
            try:s,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            if not self.slots.acquire(False):s.close();continue
            self.threads=[t for t in self.threads if t.is_alive()]
            t=threading.Thread(target=self.handle,args=(s,),daemon=True);self.threads.append(t);t.start()

    def close(self):
        self.stop.set();self.listener.close()
        for t in self.threads:t.join(11)


class TorSession:
    def __init__(self, home, binary, node_p2p, socks, control, ingress, peers=()):
        self.pc,OwnedTor,write_config,tor_path=dependencies()
        from tor_runtime import config_path
        self.home=tor_path(home);self.binary=Path(binary);self.node_p2p=node_p2p;self.socks=socks;self.ingress=ingress;self.channels=[];self.threads=[]
        if len(peers)>8:raise ValueError('PEER_BOUND')
        for n in (node_p2p,socks,control,ingress): self.pc.port(n)
        if len({node_p2p,socks,control,ingress,*[n for n,_ in peers]})!=4+len(peers):raise ValueError('PORT_COLLISION')
        self.peers=[(n,descriptor(v)) for n,v in peers]
        if os.name=='nt':self.pc.c.win.mkdir(self.home)
        else:self.home.mkdir(mode=0o700,exist_ok=True)
        with self.pc.c.directory(self.home):pass
        onion=self.home/'identity'
        if os.name=='nt':self.pc.c.win.mkdir(onion)
        else:onion.mkdir(mode=0o700,exist_ok=True)
        with self.pc.c.directory(onion):pass
        self.cert=self.home/'public.crt';self.key=self.home/'private.key'
        if self.cert.exists()!=self.key.exists():raise ValueError('INCOMPLETE_TLS_IDENTITY')
        if not self.key.exists():
            subprocess.run([openssl_binary(),'req','-x509','-newkey','ed25519','-nodes','-keyout',str(self.key),'-out',str(self.cert),'-days','365','-subj','/CN=pc-consensus-onion'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            if os.name!='nt':self.cert.chmod(0o600);self.key.chmod(0o600)
        for p in (self.cert,self.key):self.pc.c.read_private(p)
        self.lines=[f'DataDirectory {config_path(self.home)}','DisableNetwork 1','RunAsDaemon 0','SafeLogging 1','NumCPUs 1','MaxMemInQueues 64 MB',f'SocksPort 127.0.0.1:{socks}',f'ControlPort 127.0.0.1:{control}','CookieAuthentication 1',f'HiddenServiceDir {config_path(onion)}','HiddenServiceVersion 3',f'HiddenServicePort 80 127.0.0.1:{ingress}']
        self.config=self.home/'torrc';write_config(self.config,self.lines)
        self.owned=OwnedTor(binary,self.config);self.owned.verify();self.state='DISABLED';self.progress=0

    def start(self, consent):
        if consent!='CONNECT VIA TOR':raise ValueError('EXPLICIT_TOR_CONSENT_REQUIRED')
        if self.owned.process is not None and self.owned.process.poll() is None:raise ValueError('TOR_ALREADY_RUNNING')
        _,_,write_config,_=dependencies()
        # Recheck on every activation/retry before binding connectors or changing
        # DisableNetwork. Merely preparing a config never activates public Tor.
        from tor_policy import require_current
        try:
            require_current(self.owned.binary)
            # A crashed Tor process can leave the owned listeners alive. Reap
            # those before rebinding, and register each channel immediately so
            # a later constructor failure cannot leak earlier connectors.
            if self.channels:self.close()
            self.make_channels()
            for ch in self.channels:
                t=threading.Thread(target=ch.run,daemon=True);t.start();self.threads.append(t)
            write_config(self.config,[s.replace('DisableNetwork 1','DisableNetwork 0') for s in self.lines]);self.owned.start();self.state='BOOTSTRAPPING'
        except BaseException:self.close();raise

    def make_channels(self):
        self.channels.append(Channel(self.ingress,self.node_p2p,certificate=self.cert,key=self.key,catalog=lambda:[self.public_descriptor(),*[p for _,p in self.peers]][:8]))
        for n,v in self.peers:self.channels.append(Channel(n,80,peer=v,socks=self.socks))

    def status(self):
        if self.owned.process is not None:
            if self.owned.process.poll() is not None:self.state='DISCONNECTED';self.progress=0
            else:
                try:
                    raw=self.owned.control('GETINFO status/bootstrap-phase');match=re.search(rb'PROGRESS=(\d+)',raw)
                    self.progress=int(match[1]) if match else 0;self.state='TOR_READY' if self.progress==100 else 'BOOTSTRAPPING'
                except Exception:
                    started=getattr(self.owned,'started_at',None)
                    self.state='CONTROL_STARTING' if started is not None and time.monotonic()-started<10 else 'CONTROL_UNAVAILABLE';self.progress=0
        now=time.monotonic()
        recent=sum(1 for ch in self.channels if ch.peer and ch.last_success is not None and now-ch.last_success<60)
        return dict(state=self.state,bootstrap_percent=self.progress,tor_exit_code=self.owned.process.poll() if self.owned.process is not None else None,route='ONION_ONLY_NO_DIRECT_FALLBACK',peer_count=len(self.peers),recent_authenticated_peers=recent,forwarded_requests=sum(ch.forwarded for ch in self.channels),synchronization='UNVERIFIED_GLOBAL_FRESHNESS',consensus_peer_admission='OPEN_NOT_ADMIN_ENROLLED')

    def public_descriptor(self):
        from .rpc import NETWORK,GENESIS,PROFILE
        if self.status()['state']!='TOR_READY':raise ValueError('TOR_NOT_READY')
        endpoint=self.pc.c.read_private(self.home/'identity/hostname').decode().strip()
        der=ssl.PEM_cert_to_DER_cert(self.pc.c.read_private(self.cert).decode())
        return descriptor(dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,onion=endpoint,certificate_sha256=hashlib.sha256(der).hexdigest()))

    def close(self):
        error=None
        for item in [self.owned,*self.channels]:
            try:item.close()
            except Exception as failure:
                if error is None:error=failure
        for t in self.threads:t.join(1)
        self.channels=[];self.threads=[]
        _,_,write_config,_=dependencies();write_config(self.config,self.lines);self.state='DISABLED';self.progress=0
        if error:raise error
