"""Explicit loopback-only upstream policy. No credentials, DNS or CONNECT probes."""
import re,socket,time
from n2_tor_diagnostics import CODES,DiagnosticTor

CODES.update('UPSTREAM_CONFIG_INVALID UPSTREAM_REQUIRED UPSTREAM_READY UPSTREAM_REFUSED UPSTREAM_TIMEOUT UPSTREAM_PROTOCOL UPSTREAM_AUTH_REQUIRED UPSTREAM_LOST'.split())

class ProxyFailure(RuntimeError):
    # Deliberately not ValueError/OSError: bootstrap control-error handling must
    # not swallow an upstream policy failure and continue operating.
    def __init__(self,code):self.code=code;super().__init__(code)

def endpoint(value,forbidden=()):
    if not isinstance(value,str) or not re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{3,4}',value):raise ProxyFailure('UPSTREAM_CONFIG_INVALID')
    port=int(value.split(':')[1])
    if not 1024<=port<=65535 or port in {19510,19520,19530,19550,19501,19560,*forbidden}:raise ProxyFailure('UPSTREAM_CONFIG_INVALID')
    return ('127.0.0.1',port)

class Policy:
    def __init__(self,value,diag,forbidden=(),clock=time.monotonic):
        self.address=endpoint(value,forbidden);self.value=value;self.diag=diag;self.clock=clock;self.next_check=0
        self.diag.event('UPSTREAM_REQUIRED')
    def check(self,force=False):
        if not force and self.clock()<self.next_check:return
        # Absolute deadline includes connection and fragmented reply, not a
        # timeout reset after each byte. Greeting only: never an external target.
        deadline=self.clock()+1.0
        try:
            with socket.create_connection(self.address,timeout=1.0) as sock:
                sock.settimeout(max(.001,deadline-self.clock()));sock.sendall(b'\x05\x01\x00')
                reply=b''
                while len(reply)<2:
                    remaining=deadline-self.clock()
                    if remaining<=0:raise TimeoutError()
                    sock.settimeout(remaining);chunk=sock.recv(2-len(reply))
                    if not chunk:raise ProxyFailure('UPSTREAM_PROTOCOL')
                    reply+=chunk
                if self.clock()>=deadline:raise TimeoutError()
                if reply==b'\x05\x02':raise ProxyFailure('UPSTREAM_AUTH_REQUIRED')
                if reply!=b'\x05\x00':raise ProxyFailure('UPSTREAM_PROTOCOL')
        except ConnectionRefusedError:raise ProxyFailure('UPSTREAM_REFUSED') from None
        except TimeoutError:raise ProxyFailure('UPSTREAM_TIMEOUT') from None
        except OSError:raise ProxyFailure('UPSTREAM_LOST') from None
        self.next_check=self.clock()+1.0;self.diag.event('UPSTREAM_READY')
    def lines(self,expected):
        # expected is the internally constructed N2 template, never arbitrary
        # operator text. Keep SafeLogging, cookie auth, loopback and TLS mappings.
        if any(line.startswith('Socks5Proxy') for line in expected):raise ProxyFailure('UPSTREAM_CONFIG_INVALID')
        return [*expected,'Socks5Proxy '+self.value]

class UpstreamTor(DiagnosticTor):
    def __init__(self,binary,config,diag,policy):super().__init__(binary,config,diag);self.policy=policy
    def start(self):self.policy.check(force=True);super().start()
    def control(self,command):self.policy.check();return super().control(command)
