"""Explicit offline CMake build in NEW output directory; two compiler workers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import shlex


def binding(root, out):
    paths=['phase4/privacycoin-hardened-devnet','phase4/privacycoin-hardened-crypto','phase2/privacycoin-wallet-crypto']
    sources=[p for p in (root/'src').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    sources += [root/'tests/phase4/CMakeLists.txt',root/'scripts/devnet-gui/launcher_host.py',root/'apps/network_v1/native/public_tools.cpp']
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    value=dict(version=1,kind='V1_LOCAL_SOURCE_BUILD',source_sha256={p.relative_to(root).as_posix():sha(p) for p in sources},binary_sha256={Path(n).name:sha(out/n) for n in paths})
    fd=os.open(out/'v1-native-manifest.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[2]
    if a.out.exists() or a.out.is_symlink():raise ValueError('NEW_BUILD_DIRECTORY_REQUIRED')
    # Require the reviewed substitution tree. A source archive assembled by
    # release.upstream_files already contains it; stage.py prepares old inputs.
    import importlib.util
    spec=importlib.util.spec_from_file_location('sphlib_stage',root/'experiments/sphlib/stage.py')
    stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)
    for name,data in stage.replacements().items():
        if not (a.upstream/name).is_file() or (a.upstream/name).read_bytes()!=data:
            raise ValueError('REVIEWED_SPHLIB_UPSTREAM_REQUIRED:'+name)
    a.out.mkdir(mode=0o700,parents=True)
    # __FILE__/assert paths and compiler object seeds must not encode checkout
    # locations. Apply to every upstream and project compilation unit.
    maps=[(root,'/pc/source'),(a.out.resolve(),'/pc/build'),(a.upstream.resolve(),'/pc/upstream')]
    flags=shlex.join(['-ffile-prefix-map='+str(p)+'='+label for p,label in maps]+['-frandom-seed=privacycoin-v1'])
    env=dict(os.environ,SOURCE_DATE_EPOCH='1791676800',TZ='UTC',LC_ALL='C',ZERO_AR_DATE='1')
    config=['cmake','-S',str(a.upstream),'-B',str(a.out),'-G','Unix Makefiles',
            '-DCMAKE_BUILD_TYPE=Release','-DARCH=default','-DARCH_ID=x86_64','-DMANUAL_SUBMODULES=ON',
            '-DCMAKE_C_FLAGS='+flags,'-DCMAKE_CXX_FLAGS='+flags,
            '-DBUILD_TESTS=ON','-DBUILD_DOCUMENTATION=OFF','-DBUILD_DEBUG_UTILITIES=OFF',
            '-DUSE_DEVICE_TREZOR=OFF','-DUSE_READLINE=OFF','-DSTATIC=OFF',
            '-DCMAKE_DISABLE_FIND_PACKAGE_Git=ON','-DBoost_NO_BOOST_CMAKE=ON',
            '-DPYTHON3_FOUND='+sys.executable,'-DCMAKE_PROJECT_monero_INCLUDE='+str(root/'apps/network_v1/native/inject.cmake')]
    build=['cmake','--build',str(a.out),'--target','privacycoin-hardened-devnet','privacycoin-hardened-crypto','privacycoin-wallet-crypto','pc-public-tools','-j2']
    for name,command,timeout in [('configure',config,180),('compile',build,1800)]:
        with (a.out/(name+'.log')).open('xb') as out:
            result=subprocess.run(command,stdout=out,stderr=subprocess.STDOUT,timeout=timeout,env=env)
        if result.returncode:raise ValueError(name.upper()+'_FAILED_LOCAL_LOG_RETAINED')
    paths=['phase4/privacycoin-hardened-devnet','phase4/privacycoin-hardened-crypto','phase2/privacycoin-wallet-crypto','v1/pc-public-tools']
    report=dict(result='PASS_CLEAN_BUILD_NOT_INDEPENDENT_REPRODUCIBILITY',configure=config,compile=build,
                environment={k:env[k] for k in ('SOURCE_DATE_EPOCH','TZ','LC_ALL','ZERO_AR_DATE')},
                toolchain={x:subprocess.check_output([x,'--version'],env=env).decode().splitlines()[0] for x in ('c++','cc','cmake','ld','ar')},
                binary_sha256={n:hashlib.sha256((a.out/n).read_bytes()).hexdigest() for n in paths})
    (a.out/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    binding(root,a.out)
    print('CLEAN_LINUX_BUILD_PASS; independent bit reproducibility still unverified')


if __name__=='__main__':main()
