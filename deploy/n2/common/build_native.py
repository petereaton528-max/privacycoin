"""Explicit user-run, two-worker native build from inspected bundle sources only."""
from pathlib import Path
import argparse,hashlib,json,os,platform,signal,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(Path(__file__).parent))
from bundle import verify_tree

def run_owned(args,out,seconds):
    child=subprocess.Popen(args,stdout=out,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        if child.wait(timeout=seconds):raise ValueError('BUILD_OPERATION_FAILED; inspect local log')
    finally:
        # Own session/group only, including compiler descendants on cancellation.
        try:os.killpg(child.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.wait(timeout=5)

def main():
    p=argparse.ArgumentParser();p.add_argument('--build',action='store_true',help='Explicitly authorize local compilation, no packages installed');a=p.parse_args()
    if platform.system()!='Linux' or platform.machine()!='x86_64' or os.getuid()==0:raise ValueError('Ubuntu non-root x86_64 required')
    manifest=verify_tree(ROOT)
    if not a.build:print('Source manifest PASS. No compilation; review dependencies then run --build.');return
    os.umask(0o077);build=ROOT/'build/monero-linux';build.mkdir(parents=True,exist_ok=True)
    if (ROOT/'build/n2-native-manifest.json').exists():raise ValueError('Existing completed build; use a new extraction for rebuild')
    args=['cmake','-S',str(ROOT/'.upstream/monero'),'-B',str(build),'-G','Unix Makefiles','-DCMAKE_BUILD_TYPE=Release','-DARCH=default','-DARCH_ID=x86_64','-DMANUAL_SUBMODULES=ON','-DBUILD_TESTS=ON','-DBUILD_DOCUMENTATION=OFF','-DBUILD_DEBUG_UTILITIES=OFF','-DUSE_DEVICE_TREZOR=OFF','-DUSE_READLINE=OFF','-DSTATIC=OFF','-DCMAKE_DISABLE_FIND_PACKAGE_Git=ON','-DBoost_NO_BOOST_CMAKE=ON','-DPYTHON3_FOUND='+sys.executable,'-DCMAKE_PROJECT_monero_INCLUDE='+str(ROOT/'tests/phase4/inject.cmake')]
    started=time.monotonic()
    # Explicit longer build bound; one supervisor, at most two compile workers.
    signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt()))
    with (build/'n2-configure.log').open('xb') as out:run_owned(args,out,180)
    with (build/'n2-build.log').open('xb') as out:run_owned(['cmake','--build',str(build),'--target','privacycoin-hardened-devnet','privacycoin-hardened-crypto','privacycoin-wallet-crypto','-j2'],out,1800)
    verify_tree(ROOT)
    names=['phase4/privacycoin-hardened-devnet','phase4/privacycoin-hardened-crypto','phase2/privacycoin-wallet-crypto']
    record=dict(version=1,kind='N2_LOCAL_SOURCE_BUILD',source_sha256=manifest['files'],binary_sha256={Path(n).name:hashlib.sha256((build/n).read_bytes()).hexdigest() for n in names})
    target=ROOT/'build/n2-native-manifest.json'
    with target.open('xb') as stream:stream.write(json.dumps(record,sort_keys=True).encode()+b'\n')
    print('LOCAL_SOURCE_BUILD_COMPLETE',round(time.monotonic()-started,3),'seconds; not bit-identical or independent build certification.')
if __name__=='__main__':main()
