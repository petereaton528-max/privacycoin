"""Bounded Windows build from pinned source into NEW directory; no cache writes."""
import argparse,hashlib,json,os,subprocess,sys,zipfile
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--dependencies',type=Path,required=True);p.add_argument('--reference-archive',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--c-compiler',type=Path);a=p.parse_args()
    root=Path(__file__).resolve().parents[2];out=a.out.resolve();dep=a.dependencies.resolve()
    if os.name!='nt' or out.exists():raise ValueError('NEW_WINDOWS_BUILD_REQUIRED')
    upstream=dep/'.upstream/monero';tools=dep/'.tools/msys64/mingw64/bin';cmake=dep/'.tools/python/cmake/data/bin/cmake.exe'
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    if sha(a.reference_archive)!='b2a91f64c48923970005882e22128415905909192b29c8c3dfa86f79ce96d021':raise ValueError('FROZEN_RC4_SOURCE_ARCHIVE_REQUIRED')
    with zipfile.ZipFile(a.reference_archive) as archive:manifest=json.loads(archive.read('V1_MANIFEST.json'))
    reference={n.removeprefix('.upstream/monero/'):h for n,h in manifest['files'].items() if n.startswith('.upstream/monero/')}
    if not reference or any(not (upstream/n).is_file() or sha(upstream/n)!=h for n,h in reference.items()):raise ValueError('PINNED_ARCHIVE_UPSTREAM_MISMATCH')
    commit='22578c3f7d7b4b6dd85ff7daa42a827d97cc53d0'
    out.mkdir(parents=True);env=dict(os.environ);env['PATH']=str(tools)+os.pathsep+env.get('PATH','')
    flags='-ffile-prefix-map="'+str(root)+'"=/pc/source -ffile-prefix-map="'+str(upstream)+'"=/pc/upstream -ffile-prefix-map="'+str(out)+'"=/pc/build -frandom-seed=privacycoin-v1'
    cc=a.c_compiler.resolve() if a.c_compiler else tools/'gcc.exe'
    cflags=flags
    if a.c_compiler:
        # Clang C frontend, existing MinGW headers/CRT/libgcc and GNU linker.
        # C++ stays GCC, preserving the ABI of installed Boost dependencies.
        cflags+=' --target=x86_64-w64-windows-gnu --sysroot="'+str(tools.parent)+'" -rtlib=libgcc -unwindlib=libgcc -fuse-ld="'+str(tools/'ld.exe')+'"'
    env.update(SOURCE_DATE_EPOCH='1791676800',TZ='UTC',ZERO_AR_DATE='1')
    config=[str(cmake),'-S',str(upstream),'-B',str(out),'-G','MinGW Makefiles','-DCMAKE_POLICY_VERSION_MINIMUM=3.5','-DCMAKE_BUILD_TYPE=Release','-DARCH=default','-DARCH_ID=x86_64','-DMANUAL_SUBMODULES=ON',
            '-DCMAKE_C_COMPILER='+str(cc),'-DCMAKE_CXX_COMPILER='+str(tools/'g++.exe'),'-DCMAKE_MAKE_PROGRAM=mingw32-make.exe','-DCMAKE_C_FLAGS='+cflags,'-DCMAKE_CXX_FLAGS='+flags,
            '-DCMAKE_AR='+str(tools/'ar.exe'),'-DCMAKE_RANLIB='+str(tools/'ranlib.exe'),'-DCMAKE_C_COMPILER_AR='+str(tools/'ar.exe'),'-DCMAKE_C_COMPILER_RANLIB='+str(tools/'ranlib.exe'),
            '-DBUILD_TESTS=ON','-DBUILD_DOCUMENTATION=OFF','-DBUILD_DEBUG_UTILITIES=OFF','-DUSE_DEVICE_TREZOR=OFF','-DUSE_READLINE=OFF','-DSTATIC=OFF','-DBoost_NO_BOOST_CMAKE=ON',
            '-DCMAKE_PREFIX_PATH='+str(tools.parent),'-DCMAKE_DISABLE_FIND_PACKAGE_Git=ON','-DPYTHON3_FOUND='+sys.executable,'-DCMAKE_PROJECT_monero_INCLUDE='+str(root/'apps/network_v1/native/inject.cmake')]
    build=[str(cmake),'--build',str(out),'--target','privacycoin-hardened-devnet','privacycoin-hardened-crypto','privacycoin-wallet-crypto','pc-public-tools','-j2','--','MAKE=mingw32-make.exe']
    rows=[]
    translation=[str(cmake),'-S',str(upstream/'translations'),'-B',str(out/'translations'),'-G','MinGW Makefiles',*[x for x in config if x.startswith(('-DCMAKE_C_COMPILER=','-DCMAKE_CXX_COMPILER=','-DCMAKE_MAKE_PROGRAM=','-DCMAKE_C_FLAGS=','-DCMAKE_CXX_FLAGS=','-DCMAKE_AR=','-DCMAKE_RANLIB='))],'-DLRELEASE_PATH=']
    for name,command,timeout in [('configure',config,180),('translation-configure',translation,180),('compile',build,2400)]:
        with (out/(name+'.log')).open('xb') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
        rows.append(dict(name=name,command=command,returncode=result.returncode))
        if result.returncode:break
    paths=['phase4/privacycoin-hardened-devnet.exe','phase4/privacycoin-hardened-crypto.exe','phase2/privacycoin-wallet-crypto.exe','v1/pc-public-tools.exe']
    report=dict(result='PASS_CLEAN_WINDOWS_BUILD_ONLY' if len(rows)==3 and rows[-1]['returncode']==0 else 'FAIL',commands=rows,upstream_commit=commit,
                verified_reference_archive_sha256=sha(a.reference_archive),verified_upstream_files=len(reference),
                binary_sha256={n:sha(out/n) for n in paths if (out/n).is_file()},tool_sha256={p.name:sha(p) for p in (cmake,cc,tools/'g++.exe')},
                runtime_and_package_verified=False,security_policy_changed=False)
    (out/'build.json').write_text(json.dumps(report,indent=2)+'\n');print(report['result']);raise SystemExit(report['result']=='FAIL')

if __name__=='__main__':main()
