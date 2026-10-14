"""Owned disposable runtime, no automatic mining and no original user-store access."""
from common import *
import subprocess,time,signal
from launcher_host import child_parent_guard,requirements
h=native('pn_nodes','tests/phase4/gates.py')

class OwnedNode(h.Node):
    def start(self,peer=None):
        if self.p is not None and self.p.poll() is None:raise ValueError('NODE_ALREADY_OWNED')
        requirements();parent=os.getpid()
        cmd=[str(NATIVE/'build/monero-linux/phase4/privacycoin-hardened-devnet'),'--data-dir',str(self.path),'--rpc-port',str(self.rpc),'--p2p-port',str(self.p2p)]
        if peer:cmd+=['--peer-port',str(peer.p2p)]
        self.p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent))
        end=time.monotonic()+60
        try:
            while time.monotonic()<end:
                if self.p.poll() is not None:raise ValueError('owned node startup failed')
                try:self.status();return
                except (OSError,ValueError):time.sleep(.05)
            raise ValueError('owned node readiness timeout')
        except Exception:self.stop();raise
    def stop(self,crash=False):
        if self.p is not None and self.p.poll() is None:
            self.p.kill() if crash else self.p.terminate()
            try:self.p.wait(timeout=10)
            except subprocess.TimeoutExpired:self.p.kill();self.p.wait(timeout=5)

class Runtime:
    def __init__(self,base=None):
        c.harden();os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:2])
        self.base=private_dir(base or Path.home()/'.local/share/privacycoin-network-v01')
        self.guard=c.lock(self.base/'runtime');self.guard.__enter__();self.children={};self.session=None
        self.h=h;self.node=OwnedNode(self.base,'node')
        try:self.setup()
        except BaseException:self.close();raise
    def setup(self):
        self.node.start()
        config_path=self.base/'runtime-config'
        if config_path.exists():self.config=load_json(config_path)
        else:
            self.config=dict(ports=[self.h.g.port(),self.h.g.port()],password=token());save_json(config_path,self.config)
        self.wallets=private_dir(self.base/'alice-wallets');self.session=Session(self.wallets,self.node.rpc)
        command='open' if (self.wallets/'DisposableAlice.wallet').exists() else 'create'
        self.address=self.session.dispatch(dict(command=command,name='DisposableAlice',password=self.config['password']))['address']
        for i in range(2):self.start_provider(i)
    def start_provider(self,i,**options):
        if i in self.children and self.children[i].poll() is None:raise ValueError('PROVIDER_ALREADY_OWNED')
        home=self.base/('provider-'+str(i));port=self.config['ports'][i]
        cmd=[sys.executable,str(Path(__file__).with_name('provider.py')),'--home',str(home),'--node',str(self.node.rpc),'--port',str(port)]
        for key,value in options.items():cmd+=['--'+key.replace('_','-'),str(value)]
        parent=os.getpid()
        child=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent));self.children[i]=child
        end=time.monotonic()+40
        while time.monotonic()<end:
            if child.poll() is not None:raise ValueError('provider startup failed')
            try:call(port,'health');return
            except (OSError,ValueError):time.sleep(.05)
        raise ValueError('provider readiness timeout')
    def stop_provider(self,i,crash=False):
        child=self.children.pop(i,None)
        if child is not None and child.poll() is None:
            child.kill() if crash else child.terminate();child.wait(timeout=10)
    def client(self,i,home=None):
        from client import Client
        control=load_json(self.base/('provider-'+str(i))/'control')
        return Client(home or self.base/('client-'+str(i)),self.config['ports'][i],control['admin'])
    def mine(self,blocks):
        f.integer(blocks,1,100)
        stamp=int(time.time())-120*500+self.node.status()['height']*120
        for _ in range(blocks):stamp+=120;self.node.mine(self.address,stamp)
    def close(self):
        if self.session:self.session.close()
        for i in list(self.children):self.stop_provider(i)
        self.node.stop();self.guard.__exit__(None,None,None)
