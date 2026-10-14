"""Preparation roles only: no public Tor activation or automatic mining/spending."""
from pathlib import Path
import argparse,hashlib,json,os,platform,signal,socket,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]

def bootstrap():
    # Source location / build provenance are non-secret configuration, never keys.
    manifest=ROOT/'build/n2-native-manifest.json'
    if manifest.exists():
        from bundle import verify_tree,decode
        source=verify_tree(ROOT)
        if decode(manifest.read_bytes())['source_sha256']!=source['files']:raise ValueError('BUILD_NOT_BOUND_TO_PACKAGE')
        os.environ['PC_DEVNET_NATIVE_ROOT']=str(ROOT)
        os.environ['PC_DEVNET_BUILD_MANIFEST']=str(manifest)
    from launcher_host import requirements
    requirements()

def validate(value,role):
    expected={'version','devnet_only','role','home','node_rpc','node_p2p','provider_port','bridge_port','socks_port','peer_port'} if role=='provider' else {'version','devnet_only','role','profile'}
    if not isinstance(value,dict) or set(value)!=expected or type(value['version']) is not int or value['version']!=1 or value['devnet_only'] is not True or value['role']!=role:raise ValueError('CONFIG_SCHEMA')
    if role=='client':
        checked_path(value['profile']);return value
    checked_path(value['home'])
    if 'privacycoin-n2' not in Path(value['home']).name:raise ValueError('N2_PRIVATE_HOME_NAME_REQUIRED')
    ports=[]
    for field in ('node_rpc','node_p2p','provider_port','bridge_port','socks_port'):
        port=value[field]
        if type(port) is not int or not 1024<=port<=65535:raise ValueError('PORT')
        ports.append(port)
    if len(set(ports))!=len(ports):raise ValueError('DISTINCT_PORTS_REQUIRED')
    if value['peer_port'] is not None and (type(value['peer_port']) is not int or not 1024<=value['peer_port']<=65535 or value['peer_port'] in ports):raise ValueError('PEER_PORT')
    return value

def checked_path(value):
    import re
    if not isinstance(value,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',value) or '..' in Path(value).parts:raise ValueError('ABSOLUTE_LINUX_PATH_REQUIRED')
    if any(x in ('privacycoin-network-v01','privacycoin-devnet-gui','Alice','Bob','Bob-restored') for x in Path(value).parts):raise ValueError('ORIGINAL_STORE_PROHIBITED')
    if any(p.is_symlink() for p in (Path(value),*Path(value).parents)):raise ValueError('SYMLINK_PATH_PROHIBITED')
    return Path(value)

def config(path,role):
    from common import load_json
    return validate(load_json(path),role)

def free_ports(ports):
    held=[]
    try:
        for port in ports:
            s=socket.socket();held.append(s)
            # Match native/HTTP listeners: TIME_WAIT is not an occupied listener.
            # SO_REUSEPORT is deliberately NOT enabled; live listeners still fail.
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',port))
    finally:
        for s in held:s.close()

def tor_binary(path):
    # Explicitly operator-provisioned executable; never downloads or runs a daemon.
    p=checked_path(str(path))
    if not p.is_file() or not os.access(p,os.X_OK):raise ValueError('TOR_RUNTIME_MISSING')
    r=subprocess.run([str(p),'--version'],capture_output=True,timeout=10)
    import re
    match=re.search(rb'Tor version (\d+)\.(\d+)\.(\d+)\.(\d+)',r.stdout)
    if r.returncode or not match or tuple(map(int,match.groups()))<(0,4,9,1):raise ValueError('TOR_0_4_9_1_OR_NEWER_REQUIRED')
    return p

def prepare(home,tor=None):
    from common import private_dir,save_json,c
    from tor_runtime import prepare_public,OwnedTor
    home=checked_path(str(home))
    if 'privacycoin-n2' not in home.name or home.exists() or home.is_symlink():raise ValueError('NEW_N2_HOME_REQUIRED')
    home=private_dir(home)
    record=dict(version=1,devnet_only=True,role='provider',home=str(home),node_rpc=19481,node_p2p=19480,provider_port=19482,bridge_port=19483,socks_port=19450,peer_port=None)
    save_json(home/'provider.json',record)
    path=prepare_public(home/'tor-disabled',record['bridge_port'],record['socks_port'])
    if tor:OwnedTor(tor_binary(tor),path).verify()
    c.write_private(home/'README.txt',b'PREPARATION ONLY. Independent isolated ledger is NOT a shared cross-host chain. Public Tor activation is not implemented. No mining, payment, firewall change or service installation. Read docs/privacy-network/n2/.\n')
    print('PREPARED_DISABLED; provider config:',home/'provider.json')

def provider(value,once=False):
    from common import private_dir,c,load_json,call,NATIVE,w
    from launcher_host import child_parent_guard
    home=private_dir(value['home']);owned=[];guard=c.lock(home/'n2-role');guard.__enter__()
    start=time.monotonic()
    def child(args):
        parent=os.getpid();p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent));owned.append(p);return p
    def ready(p,fn,seconds):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if p.poll() is not None:raise ValueError('OWNED_CHILD_EXITED')
            try:
                signal.alarm(2)
                return fn()
            except (OSError,ValueError,TimeoutError):time.sleep(.05)
            finally:signal.alarm(0)
        raise ValueError('READINESS_TIMEOUT')
    try:
        free_ports([value[k] for k in ('node_rpc','node_p2p','provider_port','bridge_port','socks_port')])
        data=private_dir(home/'node')
        args=[str(NATIVE/'build/monero-linux/phase4/privacycoin-hardened-devnet'),'--data-dir',str(data),'--rpc-port',str(value['node_rpc']),'--p2p-port',str(value['node_p2p'])]
        if value['peer_port'] is not None:args+=['--peer-port',str(value['peer_port'])]
        p=child(args);status=ready(p,lambda:w.rpc(value['node_rpc'],'status'),60)
        if status.get('genesis')!=w.GENESIS:raise ValueError('WRONG_NODE_NETWORK')
        private_dir(home/'provider')
        p=child([sys.executable,str(ROOT/'services/privacy-network/provider.py'),'--home',str(home/'provider'),'--node',str(value['node_rpc']),'--port',str(value['provider_port'])])
        health=ready(p,lambda:call(value['provider_port'],'health'),40)
        if health.get('devnet_only') is not True or health.get('provider')!=load_json(home/'provider/control')['id']:raise ValueError('WRONG_PROVIDER')
        print(json.dumps(dict(state='LOCAL_PROVIDER_READY',devnet_only=True,provider=health['provider'],height=status['height'],full_sync=True,public_onion=False,chain_information_sources='NONE' if value['peer_port'] is None else 'ONE_CONFIGURED_LOOPBACK_PEER_UNATTESTED',cross_host='PENDING',seconds=time.monotonic()-start)),flush=True)
        print('No Tor/bridge started. Independent node database is NOT proof of shared chain, source diversity or global freshness. No mining/payment automatic.',flush=True)
        if not once:
            while input('Enter EXIT to stop only owned node/provider: ').strip()!='EXIT':pass
    finally:
        for p in reversed(owned):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
        guard.__exit__(None,None,None)

def client(value):
    from common import load_json,f,c,w
    from tor_transport import OnionTransport
    profile=load_json(value['profile']);f.fields(profile,'version devnet_only home node_rpc socks_port onion provider quote_admin')
    if profile['version']!=1 or profile['devnet_only'] is not True:raise ValueError('PROFILE')
    home=checked_path(profile['home'])
    if 'privacycoin-n2' not in home.name:raise ValueError('NEW_N2_CLIENT_HOME_REQUIRED')
    f.integer(profile['node_rpc'],1024,65535);f.integer(profile['socks_port'],1024,65535);f.unhex(profile['quote_admin'],32)
    try:signal.alarm(5);state=w.rpc(profile['node_rpc'],'status')
    finally:signal.alarm(0)
    if state.get('genesis')!=w.GENESIS:raise ValueError('WRONG_NODE')
    t=OnionTransport(profile['onion'],profile['provider'],profile['socks_port'])
    t(80,'health') # no direct/DNS fallback; actual pinned provider readiness
    print('Tor provider reachable; independently verify SAME chain and timely admission before any purchase. Global freshness UNKNOWN.')
    # Reuse exact existing consent, journal and recovery flow.
    import n1_remote
    previous=sys.argv
    try:sys.argv=[n1_remote.__file__,'--profile',value['profile']];n1_remote.main()
    finally:sys.argv=previous

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','provider','client','linux-check']);p.add_argument('--config',type=Path);p.add_argument('--home',type=Path);p.add_argument('--tor',type=Path);p.add_argument('--once',action='store_true');a=p.parse_args()
    if os.name!='posix' or os.getuid()==0:raise ValueError('NONROOT_LINUX_REQUIRED')
    if sys.version_info[:2]!=(3,12):raise ValueError('TESTED_PYTHON_3_12_REQUIRED')
    bootstrap()
    from common import c
    c.harden();signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError()))
    if a.action=='prepare':prepare(a.home,a.tor)
    elif a.action=='linux-check':
        print(json.dumps(dict(state='PASS_NATIVE_REQUIREMENTS',user_is_nonroot=os.getuid()!=0,architecture=platform.machine(),python=platform.python_version(),public_onion=False,tor='NOT_STARTED')))
        if os.getuid()==0:raise ValueError('NONROOT_REQUIRED')
    elif a.action=='provider':provider(config(a.config,'provider'),a.once)
    else:client(config(a.config,'client'))
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt,EOFError):print('N2 preparation rejected/stopped. Check configuration, permissions, build/dependencies and local ports. Private details withheld. No automatic payment or Tor activation.');sys.exit(1)
