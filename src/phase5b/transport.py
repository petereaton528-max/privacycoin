"""Bounded TLS framing for opt-in development sync. No wallet secrets in requests."""
from pathlib import Path
import importlib.util,json,socket,ssl,struct,time,zlib,secrets,hashlib
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
p=module('frozen_pruned_protocol','src/phase5a/sync.py');w=p.w;f=p.f
MAX_WIRE=2*1024*1024;MAX_PLAIN=4*1024*1024;VERSION=1

def read(sock,n):
    out=bytearray()
    while len(out)<n:
        if hasattr(sock,'sync_deadline'):
            remaining=sock.sync_deadline-time.monotonic()
            if remaining<=0:raise ValueError('sync response deadline')
            sock.settimeout(remaining)
        part=sock.recv(n-len(out))
        if not part:raise ValueError('truncated sync frame')
        out+=part
    return bytes(out)
def frame(sock,limit):
    n=struct.unpack('>I',read(sock,4))[0]
    if n==0 or n>limit:raise ValueError('sync frame bounds')
    return read(sock,n)
def inflate(raw):
    if len(raw)>MAX_WIRE:raise ValueError('compressed bound')
    decoder=zlib.decompressobj();out=decoder.decompress(raw,MAX_PLAIN+1)
    if len(out)>MAX_PLAIN or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof:raise ValueError('invalid/oversized compressed stream')
    return out
def decode(raw):return json.loads(raw,object_pairs_hook=f.unique)

class Endpoint:
    def __init__(self,host,port,certificate,role):
        if role not in ('anchor','data') or type(port) is not int or not 1<=port<=65535:raise ValueError('endpoint role/port')
        self.host=host;self.port=port;self.role=role;self.context=ssl.create_default_context(cafile=str(certificate));self.context.minimum_version=ssl.TLSVersion.TLSv1_3
        self.context.maximum_version=ssl.TLSVersion.TLSv1_3
        pem=Path(certificate).read_text()
        if len(pem)>65536 or pem.count('-----BEGIN CERTIFICATE-----')!=1:raise ValueError('one explicit endpoint certificate required')
        self.certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).digest()
        self.downloaded=0;self.uploaded=0;self.wire_downloaded=0;self.calls=0;self.preprocess=[];self.hits=[];self.tls=[]
    def call(self,command,**fields):
        nonce=secrets.token_hex(32);request=f.canonical(dict(version=VERSION,role=self.role,profile=w.PROFILE,nonce=nonce,command=command,**fields))
        if len(request)>8192:raise ValueError('request bound')
        with socket.create_connection((self.host,self.port),timeout=30) as raw:
            raw.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            with self.context.wrap_socket(raw,server_hostname='localhost') as sock:
                if not secrets.compare_digest(self.certificate_sha256,hashlib.sha256(sock.getpeercert(binary_form=True)).digest()):raise ValueError('endpoint certificate pin mismatch')
                sock.sync_deadline=time.monotonic()+30;sock.settimeout(30);sock.sendall(struct.pack('>I',len(request))+request);self.uploaded+=4+len(request)
                headerraw=frame(sock,65536);payload=frame(sock,MAX_WIRE);self.downloaded+=8+len(headerraw)+len(payload);self.calls+=1;self.tls.append(sock.cipher()[0])
                # Linux stable TCP_INFO ABI: tcpi_bytes_received is offset 128.
                # Includes TLS handshake/ciphertext, excludes TCP/IP headers and
                # retransmitted packets. Benchmark validates offsetof locally.
                info=sock.getsockopt(socket.IPPROTO_TCP,socket.TCP_INFO,136)
                if len(info)<136:raise ValueError('unsupported Linux TCP accounting ABI')
                self.wire_downloaded+=struct.unpack_from('=Q',info,128)[0]
        header=decode(headerraw)
        if type(header.get('version')) is not int or (header.get('version'),header.get('role'),header.get('profile'),header.get('nonce'))!=(VERSION,self.role,w.PROFILE,nonce):raise ValueError('sync identity/replay')
        if header.get('error'):raise ValueError('sync service rejected request')
        self.preprocess.append(header.get('preprocess_ms',0));self.hits.append(header.get('cache_hit',False))
        return header,inflate(payload)

def worker():
    result=p.Worker.__new__(p.Worker)
    import subprocess
    result.p=subprocess.Popen([str(ROOT/'build/monero-linux/phase5b/privacycoin-sync-crypto')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    return result
