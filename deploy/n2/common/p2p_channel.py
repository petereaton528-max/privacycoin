"""Bounded mTLS adapter for unchanged Devnet P2P frames. Never forwards RPC.

Local node -> loopback connector -> TLS (+ optional Tor SOCKS) -> loopback
acceptor -> local node P2P. No public listener or automatic Tor activation.
"""
from pathlib import Path
import argparse,hashlib,json,signal,socket,ssl,sys,threading,time
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
from common import c,f,w,load_json
from tor_transport import onion_address
MAGIC=w.NETWORK.encode();LIMIT=1024*1024
COMMANDS={'inventory','get_block','status','pool','get_transaction'}

def port(n,minimum=1024):
    if type(n) is not int or not minimum<=n<=65535:raise ValueError('PORT')
    return n

def validate(v):
    names={'version','role','listen_port','target_port','endpoint','socks_port','cert','key','ca','peer_sha256'}
    if not isinstance(v,dict) or set(v)!=names or type(v['version']) is not int or v['version']!=1 or v['role'] not in ('acceptor','connector'):raise ValueError('CHANNEL_SCHEMA')
    port(v['listen_port']);port(v['target_port'],1 if v['endpoint']!='127.0.0.1' and v['role']=='connector' else 1024)
    if v['listen_port']==v['target_port']:raise ValueError('SELF_TARGET')
    f.unhex(v['peer_sha256'],32)
    for name in ('cert','key','ca'):
        p=Path(v[name])
        if not p.is_absolute() or '..' in p.parts or any(x.is_symlink() for x in (p,*p.parents)):raise ValueError('PRIVATE_PATH')
        c.read_private(p)
    if v['endpoint']=='127.0.0.1':
        if v['socks_port'] is not None:raise ValueError('UNEXPECTED_PROXY')
    else:
        if v['role']!='connector':raise ValueError('ACCEPTOR_LOCAL_ONLY')
        onion_address(v['endpoint']);port(v['socks_port'])
    return v

def context(v):
    server=v['role']=='acceptor'
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=v['ca']);ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_cert_chain(v['cert'],v['key'])
    if server:ctx.num_tickets=0
    return ctx

def read(s,n,end):
    data=bytearray()
    while len(data)<n:
        left=end-time.monotonic()
        if left<=0:raise TimeoutError('CHANNEL_DEADLINE')
        s.settimeout(left);part=s.recv(n-len(data))
        if not part:raise ValueError('CHANNEL_EOF')
        data.extend(part)
    return bytes(data)

def write(s,raw,end):
    left=end-time.monotonic()
    if left<=0:raise TimeoutError('CHANNEL_DEADLINE')
    s.settimeout(left);s.sendall(raw)

def frame(s,end,request):
    head=read(s,20,end)
    if head[:16]!=MAGIC:raise ValueError('P2P_MAGIC_ONLY')
    n=int.from_bytes(head[16:],'big')
    if not 0<n<=LIMIT:raise ValueError('P2P_FRAME_BOUND')
    raw=read(s,n,end);value=f.decode(raw)
    if not isinstance(value,dict) or (value.get('network'),value.get('genesis'),value.get('profile'))!=(w.NETWORK,w.GENESIS,w.PROFILE):raise ValueError('NETWORK_GENESIS_PROFILE')
    if request and value.get('command') not in COMMANDS:raise ValueError('P2P_COMMAND_ONLY')
    return head+raw

def pinned(s,v):
    if hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()!=v['peer_sha256']:raise ValueError('PEER_CERTIFICATE_PIN')

def connect(v,end):
    if v['endpoint']=='127.0.0.1':return socket.create_connection(('127.0.0.1',v['target_port']),timeout=max(.001,end-time.monotonic()))
    # Numeric loopback proxy and domain-form SOCKS: no local DNS or fallback.
    s=socket.create_connection(('127.0.0.1',v['socks_port']),timeout=max(.001,end-time.monotonic()))
    try:
        write(s,b'\x05\x01\x00',end)
        if read(s,2,end)!=b'\x05\x00':raise ValueError('SOCKS_AUTH')
        host=v['endpoint'].encode('ascii');write(s,b'\x05\x01\x00\x03'+bytes([len(host)])+host+v['target_port'].to_bytes(2,'big'),end)
        h=read(s,4,end)
        if h[:3]!=b'\x05\x00\x00':raise ValueError('SOCKS_REJECTED')
        size={1:4,4:16}.get(h[3])
        if h[3]==3:size=read(s,1,end)[0]
        if size is None:raise ValueError('SOCKS_FRAME')
        read(s,size+2,end);return s
    except BaseException:s.close();raise

class Channel:
    def __init__(self,v):
        self.v=validate(v);self.ctx=context(v);self.stop=threading.Event()
        self.slots=threading.BoundedSemaphore(8);self.threads=[];self.counts={'forwarded':0,'rejected':0};self.guard=threading.Lock()
        self.listener=socket.socket();self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:self.listener.bind(('127.0.0.1',v['listen_port']));self.listener.listen(8);self.listener.settimeout(.2)
        except BaseException:self.listener.close();raise
    def handle(self,source):
        end=time.monotonic()+12;target=None;secure=None
        try:
            source.settimeout(12)
            if self.v['role']=='acceptor':
                secure=self.ctx.wrap_socket(source,server_side=True);pinned(secure,self.v)
                request=frame(secure,end,True)
                target=socket.create_connection(('127.0.0.1',self.v['target_port']),timeout=max(.001,end-time.monotonic()))
                write(target,request,end);response=frame(target,end,False);write(secure,response,end)
            else:
                request=frame(source,end,True) # RPC rejected before remote connection
                target=connect(self.v,end);target.settimeout(max(.001,end-time.monotonic()))
                secure=self.ctx.wrap_socket(target,server_hostname='pcp2p.local');pinned(secure,self.v)
                write(secure,request,end);response=frame(secure,end,False);write(source,response,end)
            with self.guard:self.counts['forwarded']+=1
        except (OSError,ValueError,TimeoutError):
            with self.guard:self.counts['rejected']+=1
        finally:
            for s in (secure,target,source):
                if s:
                    try:s.close()
                    except OSError:pass
            self.slots.release()
    def run(self):
        while not self.stop.is_set():
            try:s,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:
                if self.stop.is_set():break
                raise
            if not self.slots.acquire(blocking=False):s.close();continue
            self.threads=[t for t in self.threads if t.is_alive()]
            t=threading.Thread(target=self.handle,args=(s,));self.threads.append(t);t.start()
    def close(self):
        self.stop.set();self.listener.close()
        for t in self.threads:t.join(timeout=13)

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True,type=Path);a=p.parse_args();c.harden()
    channel=Channel(load_json(a.config))
    signal.signal(signal.SIGTERM,lambda *_:channel.stop.set())
    try:
        print('LOCAL_P2P_CHANNEL_LISTENING; not peer-ready or chain-fresh; no public listener',flush=True)
        channel.run()
    finally:channel.close()
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):print('P2P channel stopped/rejected; private diagnostic details withheld.',file=sys.stderr);sys.exit(1)
