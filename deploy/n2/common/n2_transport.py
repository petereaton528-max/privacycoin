"""Resource-only mTLS terminator and pinned onion-only local SOCKS gateway."""
from pathlib import Path
import sys
if __name__=='__main__':
    import role
    role.bootstrap()
import argparse,http.client,json,socket,time
import p2p_channel as pc
from common import c,f,load_json
from tor_transport import onion_address,LIMIT
ALLOWED={'health','quote','status','upload','download'} # deliberately no usage/cleanup/admin

def isolated_connect(v,end,auth):
    if auth is None:return pc.connect(v,end)
    # Preserve the existing official Tor SOCKS isolation token on safe retries.
    # It is a circuit-isolation value, never a wallet password or identity.
    s=socket.create_connection(('127.0.0.1',v['socks_port']),timeout=max(.001,end-time.monotonic()))
    try:
        pc.write(s,b'\x05\x01\x02',end)
        if pc.read(s,2,end)!=b'\x05\x02':raise ValueError('SOCKS_ISOLATION_METHOD')
        pc.write(s,auth,end)
        if pc.read(s,2,end)!=b'\x01\x00':raise ValueError('SOCKS_ISOLATION_REJECTED')
        host=v['endpoint'].encode('ascii');pc.write(s,b'\x05\x01\x00\x03'+bytes([len(host)])+host+v['target_port'].to_bytes(2,'big'),end)
        head=pc.read(s,4,end)
        if head[:3]!=b'\x05\x00\x00':raise ValueError('SOCKS_REJECTED')
        size={1:4,4:16}.get(head[3])
        if head[3]==3:size=pc.read(s,1,end)[0]
        if size is None:raise ValueError('SOCKS_FRAME')
        pc.read(s,size+2,end);return s
    except BaseException:s.close();raise

def message(s,end,response=False,host=None):
    data=bytearray()
    while not data.endswith(b'\r\n\r\n'):
        if len(data)>=8192:raise ValueError('HEADER_BOUND')
        data.extend(pc.read(s,1,end))
    lines=bytes(data).decode('ascii').split('\r\n');first=lines[0];headers={}
    for line in lines[1:-2]:
        k,v=line.split(':',1);k=k.lower()
        if k in headers:raise ValueError('DUPLICATE_HEADER')
        headers[k]=v.strip()
    if 'transfer-encoding' in headers or 'content-length' not in headers:raise ValueError('HTTP_FRAMING')
    n=int(headers['content-length'])
    if not 0<=n<=LIMIT:raise ValueError('BODY_BOUND')
    if not response:
        method,path,version=first.split(' ')
        if method!='POST' or version!='HTTP/1.1' or path not in {'/'+x for x in ALLOWED} or headers.get('host')!=host+':80' or headers.get('content-type')!='application/json' or any(k in headers for k in ('origin','sec-fetch-site')):raise ValueError('RESOURCE_ONLY')
        if 'authorization' in headers:
            value=headers['authorization']
            if not value.startswith('Bearer '):raise ValueError('BEARER')
            f.unhex(value[7:],32)
    elif not first.startswith(('HTTP/1.1 ','HTTP/1.0 ')):raise ValueError('HTTP_RESPONSE')
    raw=pc.read(s,n,end);f.decode(raw)
    return bytes(data)+raw,first,headers,raw

class ResourceChannel(pc.Channel):
    def close(self):
        self.stop.set();self.listener.close();end=time.monotonic()+41
        for t in self.threads:t.join(timeout=max(0,end-time.monotonic()))

class ResourceServer(ResourceChannel):
    def __init__(self,v,hostname_file):
        if v['role']!='acceptor':raise ValueError('ACCEPTOR_REQUIRED')
        self.hostname_file=hostname_file;super().__init__(v)
    def handle(self,source):
        secure=None;end=time.monotonic()+40
        try:
            source.settimeout(10);secure=self.ctx.wrap_socket(source,server_side=True);pc.pinned(secure,self.v)
            host=onion_address(c.read_private(self.hostname_file).decode().strip())
            _,first,headers,body=message(secure,end,host=host)
            forwarded={'Content-Type':'application/json'}
            if 'authorization' in headers:forwarded['Authorization']=headers['authorization']
            connection=http.client.HTTPConnection('127.0.0.1',self.v['target_port'],timeout=max(.001,end-time.monotonic()))
            try:
                connection.request('POST',first.split(' ')[1],body=body,headers=forwarded)
                reply=connection.getresponse();raw=reply.read(LIMIT+1)
                if len(raw)>LIMIT:raise ValueError('RESPONSE_BOUND')
                f.decode(raw);response=f'HTTP/1.1 {reply.status} Result\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n'.encode()+raw
                pc.write(secure,response,end)
            finally:connection.close()
            with self.guard:self.counts['forwarded']+=1
        except (OSError,ValueError,TimeoutError):
            with self.guard:self.counts['rejected']+=1
        finally:
            (secure or source).close();self.slots.release()

class ResourceProxy(ResourceChannel):
    def __init__(self,v):
        if v['role']!='connector' or v['endpoint']=='127.0.0.1':raise ValueError('ONION_ONLY')
        onion_address(v['endpoint']);super().__init__(v)
    def handle(self,source):
        target=None;secure=None;end=time.monotonic()+40
        try:
            # Existing OnionTransport talks SOCKS to this bounded gateway.
            greeting=pc.read(source,3,end);auth=None
            if greeting not in (b'\x05\x01\x00',b'\x05\x01\x02'):raise ValueError('SOCKS_METHOD')
            pc.write(source,b'\x05'+greeting[2:],end)
            if greeting[-1]==2:
                if pc.read(source,2,end)!=b'\x01\x09' or pc.read(source,9,end)!=b'<torS0X>0' or pc.read(source,1,end)!=b'\x20':raise ValueError('ISOLATION_FORMAT')
                auth=b'\x01\x09<torS0X>0\x20'+pc.read(source,32,end);pc.write(source,b'\x01\x00',end)
            if pc.read(source,4,end)!=b'\x05\x01\x00\x03':raise ValueError('DOMAIN_ONLY')
            n=pc.read(source,1,end)[0];host=pc.read(source,n,end).decode('ascii');port=int.from_bytes(pc.read(source,2,end),'big')
            if host!=self.v['endpoint'] or port!=80:raise ValueError('EXACT_ONION_REQUIRED')
            target=isolated_connect(self.v,end,auth);target.settimeout(max(.001,end-time.monotonic()))
            secure=self.ctx.wrap_socket(target,server_hostname='pcp2p.local');pc.pinned(secure,self.v)
            pc.write(source,b'\x05\x00\x00\x01'+b'\x00'*6,end)
            raw,_,_,_=message(source,end,host=host);pc.write(secure,raw,end)
            raw,_,_,_=message(secure,end,True);pc.write(source,raw,end)
            with self.guard:self.counts['forwarded']+=1
        except (OSError,ValueError,TimeoutError):
            with self.guard:self.counts['rejected']+=1
        finally:
            for s in (secure,target,source):
                if s:
                    try:s.close()
                    except OSError:pass
            self.slots.release()

def main():
    import signal
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['resource-server','resource-proxy']);p.add_argument('--config',type=Path,required=True);p.add_argument('--hostname-file',type=Path);a=p.parse_args();c.harden()
    v=load_json(a.config);obj=ResourceServer(v,a.hostname_file) if a.mode=='resource-server' else ResourceProxy(v)
    signal.signal(signal.SIGTERM,lambda *_:obj.stop.set())
    try:print('LOCAL_TLS_RESOURCE_LISTENER; not remote readiness',flush=True);obj.run()
    finally:obj.close()
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):raise SystemExit('Resource transport stopped/rejected; private details withheld.')
