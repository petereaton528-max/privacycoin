"""One managed local Devnet session. Inherited control pipe; no secret protocol.

Only terminates its own Popen child. Existing valid nodes are attached, never
shut down. A private advisory lock prevents two managed launchers sharing data.
Local OS/UID and unauthenticated loopback RPC remain trusted.
"""
from pathlib import Path
import argparse,ctypes,hashlib,json,os,signal,socket,subprocess,sys,time
from backend import c,w,f,NATIVE,SOURCE,DEFAULT_HOME

class StartupError(Exception):pass

def child_parent_guard(parent_pid):
    # This host is single-threaded Linux/WSL. Fail closed before exec if the
    # parent-death signal cannot be installed; close the fork/prctl race too.
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(1,signal.SIGTERM,0,0,0)!=0 or os.getppid()!=parent_pid:
        os._exit(125)
def port_used(port):
    with socket.socket() as s:s.settimeout(.3);return s.connect_ex(('127.0.0.1',port))==0
def checked_node(port):
    signal.alarm(3)
    try:
        status=w.rpc(port,'status');genesis=w.rpc(port,'get_block',hash=w.GENESIS)
        if status.get('genesis')!=w.GENESIS or not isinstance(genesis.get('block'),str):raise ValueError()
        return status
    finally:signal.alarm(0)
def requirements(allow_native_linux=False):
    windows=os.name=='nt'
    if windows:
        if not allow_native_linux:raise StartupError('LEGACY_LAUNCHER_WSL2_REQUIRED')
    elif 'wsl2' not in Path('/proc/sys/kernel/osrelease').read_text().lower() and not (allow_native_linux and sys.platform=='linux'):raise StartupError('WSL2_REQUIRED')
    manifest=os.environ.get('PC_DEVNET_BUILD_MANIFEST') # non-secret, opt-in N2 local rebuild provenance
    if allow_native_linux and not manifest:raise StartupError('EXPLICIT_BUILD_MANIFEST_REQUIRED')
    if manifest:
        record=f.decode(c.read_private(Path(manifest)))
        if set(record)!={'version','kind','source_sha256','binary_sha256'} or type(record['version']) is not int or record['version']!=1 or record['kind'] not in ('N2_LOCAL_SOURCE_BUILD','V1_LOCAL_SOURCE_BUILD'):raise StartupError('BUILD_MANIFEST_SCHEMA')
        from pathlib import PurePosixPath
        required={'src/phase6a/wallet.py','src/phase4/wallet.py','src/phase4/node.cpp','src/phase4/ledger.cpp','src/phase4/crypto.cpp','src/wallet/wallet.py','src/wallet/crypto.cpp','tests/phase4/CMakeLists.txt'}
        if windows:required.add('src/phase6a/windows_private.py')
        if not required.issubset(record['source_sha256']):raise StartupError('BUILD_SOURCE_INCOMPLETE')
        for name,sha in record['source_sha256'].items():
            rel=PurePosixPath(name)
            if rel.is_absolute() or '..' in rel.parts or '\\' in name:raise StartupError('BUILD_SOURCE_PATH')
            if hashlib.sha256((NATIVE/name).read_bytes()).hexdigest()!=sha:raise StartupError('BUILD_SOURCE_CHANGED')
        pinned=record['binary_sha256']
        expected={'privacycoin-hardened-devnet','privacycoin-hardened-crypto','privacycoin-wallet-crypto'}
        if set(pinned)!=expected:raise StartupError('BUILD_BINARY_SET')
        helper=NATIVE/('build/monero-windows/phase2/privacycoin-wallet-crypto.exe' if windows else 'build/monero-linux/phase2/privacycoin-wallet-crypto')
        if not helper.is_file() or hashlib.sha256(helper.read_bytes()).hexdigest()!=pinned[helper.name.removesuffix('.exe')]:raise StartupError('WALLET_HELPER_CHANGED')
    else:
        pinned=json.loads((SOURCE/'docs/evidence/overnight-v1/audit.json').read_bytes())['binary_sha256']
    for name in ('privacycoin-hardened-devnet','privacycoin-hardened-crypto'):
        path=NATIVE/('build/monero-windows/phase4/'+name+'.exe' if windows else 'build/monero-linux/phase4/'+name)
        if not path.is_file() or not os.access(path,os.X_OK) or hashlib.sha256(path.read_bytes()).hexdigest()!=pinned[name]:raise StartupError('NATIVE_BINARY_MISSING_OR_CHANGED')
    if not f.HELPER.is_file() or not os.access(f.HELPER,os.X_OK):raise StartupError('WALLET_HELPER_MISSING')
    f.sodium() # Load required existing encryption dependency without handling keys.
def main():
    c.harden();signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError()))
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    p=argparse.ArgumentParser();p.add_argument('--data',type=Path,default=DEFAULT_HOME/'node');p.add_argument('--port',type=int,default=48081);p.add_argument('--p2p-port',type=int,default=48080);a=p.parse_args()
    f.integer(a.port,1024,65535);f.integer(a.p2p_port,1024,65535);requirements()
    a.data.mkdir(parents=True,mode=0o700,exist_ok=True)
    try:guard=c.lock(a.data/'.launcher');guard.__enter__()
    except (BlockingIOError,ValueError,OSError):raise StartupError('SESSION_ALREADY_OPEN_OR_UNSAFE_DATA') from None
    child=None
    try:
        if port_used(a.port):
            try:status=checked_node(a.port)
            except Exception:raise StartupError('RPC_PORT_IN_USE_OR_WRONG_NETWORK') from None
            owned=False
        else:
            if port_used(a.p2p_port):raise StartupError('P2P_PORT_IN_USE')
            parent_pid=os.getpid()
            child=subprocess.Popen([str(NATIVE/'build/monero-linux/phase4/privacycoin-hardened-devnet'),'--data-dir',str(a.data),'--rpc-port',str(a.port),'--p2p-port',str(a.p2p_port)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent_pid))
            end=time.monotonic()+60
            while time.monotonic()<end:
                if child.poll() is not None:raise StartupError('NODE_START_FAILED')
                try:status=checked_node(a.port);break
                except (OSError,ValueError,TimeoutError):time.sleep(.05)
            else:raise StartupError('NODE_READY_TIMEOUT')
            owned=True
        print(json.dumps(dict(ok=True,owned_node=owned,network=w.NETWORK,genesis=w.GENESIS,profile=w.PROFILE,height=status['height'],full_sync=True)),flush=True)
        # EOF is cancellation; no commands, tokens, secrets or unauthenticated socket.
        sys.stdin.buffer.read(1)
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        guard.__exit__(None,None,None)
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as error:
        code=str(error) if isinstance(error,StartupError) else 'LOCAL_STARTUP_FAILED'
        print(json.dumps(dict(ok=False,code=code)),flush=True);sys.exit(1)
