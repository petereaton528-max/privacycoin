"""Local-only disposable PC + private Tor network. Never activates public Tor."""
from common import *
from runtime import Runtime,h
from tor_runtime import PrivateNetwork,available
from tor_transport import OnionTransport
from client import Client
from launcher_host import child_parent_guard
from n1_diagnostics import emit
import subprocess,time

class N1Runtime:
    def __init__(self,home,experimental_upstream=False,diagnostics=None):
        self.home=private_dir(home);self.local=None;self.tor=None;self.bridge=None
        self.diagnostics=diagnostics
        try:
            available()  # Missing runtime fails before any node/provider is started.
            self.local=Runtime(self.home/'devnet')
            ports=self.home/'bridge-port'
            if not ports.exists():save_json(ports,dict(port=h.g.port()))
            self.port=load_json(ports)['port']
            self.tor=PrivateNetwork(self.home/'tor',self.port,experimental_upstream=experimental_upstream,diagnostics=diagnostics);self.tor.start();self.start_bridge()
            control=load_json(self.local.base/'provider-0/control')
            self.transport=OnionTransport(self.tor.hostname,control['id'],self.tor.socks_port,timeout=5,diagnostics=diagnostics)
            self.client=Client(self.home/'onion-client',80,control['admin'],self.transport)
            # Onion descriptors/introduction circuits can lag circuit bootstrap.
            # Only health is retried; never payment, allocation or upload.
            end=time.monotonic()+110
            attempt=0
            while time.monotonic()<end:
                attempt+=1
                try:
                    self.transport(80,'health');emit(diagnostics,'onion_service_ready',attempt=attempt);break
                except ValueError:
                    emit(diagnostics,'readiness_retry',operation='health',attempt=attempt,state=self.transport.state);time.sleep(.5)
            else:raise ValueError('PRIVATE_ONION_READINESS_TIMEOUT')
            self.transport.timeout=40
            save_json(self.home/'endpoint',dict(**self.transport.binding,socks_port=self.tor.socks_port),True)
        except BaseException:self.close();raise
    def start_bridge(self):
        if self.bridge is not None and self.bridge.poll() is None:raise ValueError('BRIDGE_ALREADY_OWNED')
        args=[sys.executable,str(Path(__file__).with_name('onion_bridge.py')),'--port',str(self.port),'--upstream',str(self.local.config['ports'][0]),'--onion',self.tor.hostname]
        if self.diagnostics is not None:args+=['--diagnostics',str(self.home/'bridge-diagnostics')]
        parent=os.getpid();self.bridge=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent))
        # A live PID is not a listening, correctly configured bridge. This local
        # health-only probe carries no bearer, file or payment and is NEVER a
        # fallback for an onion application request. Onion readiness is separate.
        expected=load_json(self.local.base/'provider-0/control')['id'];end=time.monotonic()+10
        while time.monotonic()<end:
            if self.bridge.poll() is not None:raise ValueError('BRIDGE_STARTUP_FAILED')
            connection=http.client.HTTPConnection('127.0.0.1',self.port,timeout=.5)
            try:
                connection.request('POST','/health',body=b'{}',headers={'Host':self.tor.hostname+':80','Content-Type':'application/json'})
                response=connection.getresponse();raw=response.read(4097)
                if len(raw)>4096:raise ValueError('BRIDGE_READINESS_BOUND')
                reply=f.decode(raw)
                if response.status==200 and reply.get('ok') is True and reply.get('result',{}).get('provider')==expected and reply['result'].get('devnet_only') is True:
                    if self.bridge.poll() is not None:raise ValueError('BRIDGE_STARTUP_FAILED')
                    emit(self.diagnostics,'bridge_process_started',pid=self.bridge.pid);return
            except (OSError,ValueError):pass
            finally:connection.close()
            time.sleep(.02)
        self.stop_bridge();raise ValueError('BRIDGE_READINESS_TIMEOUT')
    def stop_bridge(self,crash=False):
        if self.bridge is not None and self.bridge.poll() is None:
            self.bridge.kill() if crash else self.bridge.terminate();self.bridge.wait(timeout=5)
            emit(self.diagnostics,'bridge_process_stopped',pid=self.bridge.pid)
    def close(self):
        self.stop_bridge()
        if self.tor:self.tor.close();self.tor=None
        if self.local:self.local.close();self.local=None
