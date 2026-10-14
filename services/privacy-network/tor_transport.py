"""SOCKS5 domain-name transport: no destination DNS or direct fallback.

Tor implements onion authentication/routing. This file only implements standard
SOCKS5 and bounded HTTP/1.1 framing; it never handles wallet or file-encryption keys.
"""
from common import f,identity,MAX_CIPHER
import base64,hashlib,re,socket,time,threading
from n1_diagnostics import emit
import secrets

LIMIT=2*MAX_CIPHER+8192
COMMANDS={'health','quote','status','upload','download','usage','cleanup'}
CONNECT_ATTEMPT_SECONDS=10

def onion_address(host):
    if not isinstance(host,str) or not re.fullmatch('[a-z2-7]{56}\\.onion',host):raise ValueError('INVALID_ONION')
    raw=base64.b32decode(host[:-6].upper())
    if raw[-1:]!=b'\x03' or raw[32:34]!=hashlib.sha3_256(b'.onion checksum'+raw[:32]+b'\x03').digest()[:2]:raise ValueError('INVALID_ONION_CHECKSUM')
    return host

class TransportError(ValueError):
    def __init__(self,state,code):self.state=state;self.code=code;super().__init__(state+': '+code)

class OnionTransport:
    def __init__(self,host,provider,socks_port,port=80,timeout=40,cancel=None,diagnostics=None):
        onion_address(host);identity(provider);f.integer(socks_port,1024,65535);f.integer(port,1,65535)
        if not isinstance(timeout,(int,float)) or isinstance(timeout,bool) or not 0<timeout<=120:raise ValueError('deadline')
        self._binding=dict(kind='tor-onion-v3',host=host,port=port,provider=provider)
        self.socks_port=socks_port;self.timeout=timeout;self.cancel=cancel or threading.Event();self.state='DISCONNECTED'
        self.last_timing=None
        self.guard=threading.Lock()
        self.diagnostics=diagnostics
        self._isolation=None
    @property
    def binding(self):return dict(self._binding)
    def __call__(self,port,command,bearer=None,**fields):
        if port!=self.binding['port'] or command not in COMMANDS:raise ValueError('ENDPOINT_OR_OPERATION')
        if bearer is not None:identity(bearer)
        # Serialize transport state and bind every bearer operation to the pinned
        # onion endpoint's reported provider identity before disclosing authority.
        deadline=time.monotonic()+self.timeout
        while not self.guard.acquire(timeout=min(.1,max(0,deadline-time.monotonic()))):
            if self.cancel.is_set() or time.monotonic()>=deadline:raise TransportError('FAILED','CANCELLED' if self.cancel.is_set() else 'REQUEST_BUSY_DEADLINE')
        try:
            health=self._connect_request('health',None,{},deadline)
            if not isinstance(health,dict) or health.get('provider')!=self.binding['provider'] or health.get('devnet_only') is not True:
                self.state='FAILED';raise TransportError('FAILED','PROVIDER_IDENTITY_MISMATCH')
            if command=='health':return health
            return self._connect_request(command,bearer,fields,deadline)
        finally:self.guard.release()
    def _connect_request(self,command,bearer,fields,deadline):
        # Tor's transient general SOCKS failure is reported before HTTP_SEND.
        # Reconnect only in that known pre-request state, never after ambiguous
        # transmission, and keep the SAME caller deadline and pinned endpoint.
        for attempt in range(3):
            if attempt:self._isolation=secrets.token_bytes(32)
            try:return self._request(command,bearer,fields,deadline,isolate=self._isolation is not None)
            except TransportError as error:
                if error.state!='FAILED' or error.code not in ('SOCKS_CONNECT_REJECTED_1','SOCKS_CONNECT_TimeoutError') or attempt==2:raise
                pause=min(.05*(2**attempt),max(0,deadline-time.monotonic()))
                if pause<=0:raise
                emit(self.diagnostics,'connection_retry',operation=command,stage='SOCKS_CONNECT',code=error.code,attempt=attempt+2)
                if self.cancel.wait(pause):
                    self.state='FAILED';raise TransportError('FAILED','CANCELLED') from None
    def _request(self,command,bearer,fields,deadline,isolate=False):
        self.state='CONNECTING';sent=False;s=None;stage='CONNECT_PROXY';started=time.monotonic();self.last_timing=None;trace=secrets.token_hex(8)
        connect_end=min(deadline,started+CONNECT_ATTEMPT_SECONDS)
        emit(self.diagnostics,'request_start',trace=trace,operation=command,stage=stage)
        def remaining():
            if self.cancel.is_set():raise InterruptedError()
            value=deadline-time.monotonic()
            if stage=='SOCKS_CONNECT':value=min(value,connect_end-time.monotonic())
            if value<=0:raise TimeoutError()
            return min(value,.2)
        def receive(n):
            result=b''
            while len(result)<n:
                s.settimeout(remaining())
                try:part=s.recv(n-len(result))
                except socket.timeout:continue
                if not part:raise OSError('closed')
                result+=part
            return result
        def send(data):
            view=memoryview(data)
            while view:
                s.settimeout(remaining())
                try:size=s.send(view)
                except socket.timeout:continue
                if not size:raise OSError('closed')
                view=view[size:]
        try:
            remaining();s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(min(1,max(.001,deadline-time.monotonic())))
            # Numeric loopback proxy only; never resolve the onion with the OS.
            s.connect(('127.0.0.1',self.socks_port));proxy_ready=time.monotonic();stage='SOCKS_AUTH'
            send(b'\x05\x01'+(b'\x02' if isolate else b'\x00'))
            if receive(2)!=(b'\x05\x02' if isolate else b'\x05\x00'):raise TransportError('FAILED','SOCKS_AUTH_UNSUPPORTED')
            if isolate:
                # Official Tor SOCKS format 0: application isolation token,
                # NOT wallet credentials, proxy access authentication or a
                # communication identity. No control-port NEWNYM/global effect.
                username=b'<torS0X>0';token=self._isolation
                send(b'\x01'+bytes([len(username)])+username+bytes([len(token)])+token)
                if receive(2)!=b'\x01\x00':raise TransportError('FAILED','SOCKS_ISOLATION_REJECTED')
            emit(self.diagnostics,'socks_authenticated',trace=trace,operation=command)
            host=self.binding['host'].encode('ascii');port=self.binding['port']
            stage='SOCKS_CONNECT';send(b'\x05\x01\x00\x03'+bytes([len(host)])+host+port.to_bytes(2,'big'))
            head=receive(4)
            if head[:3]!=b'\x05\x00\x00':raise TransportError('FAILED','SOCKS_CONNECT_REJECTED_'+str(head[1]))
            size={1:4,4:16}.get(head[3])
            if head[3]==3:size=receive(1)[0]
            if size is None:raise OSError('SOCKS framing')
            receive(size+2);onion_ready=time.monotonic();self.state='CONNECTED'
            emit(self.diagnostics,'onion_connected',trace=trace,operation=command,elapsed_ms=(onion_ready-started)*1000)
            body=f.canonical(fields)
            if len(body)>LIMIT:raise ValueError('REQUEST_BOUND')
            headers=f'POST /{command} HTTP/1.1\r\nHost: {self.binding["host"]}:{port}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n'
            if bearer is not None:headers+='Authorization: Bearer '+bearer+'\r\n'
            if self.diagnostics is not None:headers+='X-PC-Trace: '+trace+'\r\n'
            stage='HTTP_SEND';sent=True;send(headers.encode('ascii')+b'\r\n'+body)
            stage='HTTP_HEADER'
            raw=b''
            while not raw.endswith(b'\r\n\r\n'):
                if len(raw)>=16384:raise ValueError('HEADER_BOUND')
                raw+=receive(1)
            lines=raw.decode('ascii').split('\r\n');status=lines.pop(0).split(' ')
            if len(status)<2 or status[0] not in ('HTTP/1.0','HTTP/1.1'):raise ValueError('HTTP_FRAMING')
            headers={}
            for line in lines:
                if not line:continue
                k,v=line.split(':',1);k=k.lower()
                if k in headers:raise ValueError('DUPLICATE_HEADER')
                headers[k]=v.strip()
            if 'transfer-encoding' in headers or headers.get('content-type')!='application/json':raise ValueError('HTTP_FRAMING')
            length=int(headers['content-length']);f.integer(length,0,LIMIT)
            stage='HTTP_BODY';reply=f.decode(receive(length))
            if status[1]!='200' or reply.get('ok') is not True:
                # Provider error text may be attacker controlled: do not echo it.
                raise TransportError('CONNECTED','PROVIDER_REJECTED_RECONCILE')
            self.last_timing=dict(proxy_tcp_ms=(proxy_ready-started)*1000,socks_onion_connect_ms=(onion_ready-proxy_ready)*1000,application_ms=(time.monotonic()-onion_ready)*1000,total_ms=(time.monotonic()-started)*1000)
            emit(self.diagnostics,'request_complete',trace=trace,operation=command,state='CONNECTED',elapsed_ms=(time.monotonic()-started)*1000,bytes=length)
            return reply['result']
        except TransportError as error:
            emit(self.diagnostics,'request_error',trace=trace,operation=command,stage=stage,state=error.state,code=error.code,elapsed_ms=(time.monotonic()-started)*1000)
            self.state=error.state;raise
        except Exception as error:
            self.state='UNKNOWN' if sent else 'FAILED'
            emit(self.diagnostics,'request_error',trace=trace,operation=command,stage=stage,state=self.state,code=type(error).__name__,elapsed_ms=(time.monotonic()-started)*1000)
            raise TransportError(self.state,'CANCELLED' if self.cancel.is_set() else stage+'_'+type(error).__name__) from None
        finally:
            if s is not None:s.close()
