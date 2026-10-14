"""New Windows artifacts from existing locked MinGW cache, no cache writes.

Historical native libs are reused; this is not independent reproducibility proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess


def main():
    p=argparse.ArgumentParser();p.add_argument('--cache-source',type=Path,required=True);p.add_argument('--cache-build',type=Path,help='Reviewed ABI-matched clean build instead of historical cache');p.add_argument('--out',type=Path,required=True);p.add_argument('--static-runtime',action='store_true',help='Link available static third-party runtimes; no security-policy changes');a=p.parse_args()
    r=Path(__file__).resolve().parents[2];cache=a.cache_build or a.cache_source/'build/monero-native'
    if os.name!='nt' or a.out.exists():raise ValueError('NEW_WINDOWS_BUILD_DIRECTORY_REQUIRED')
    if a.static_runtime and not a.cache_build:raise ValueError('STATIC_RUNTIME_REQUIRES_REVIEWED_ABI_MATCHED_CACHE_BUILD')
    a.out.mkdir(mode=0o700,parents=True)
    tool=a.cache_source/'.tools/msys64/mingw64/bin'
    env=dict(os.environ);env['PATH']=str(tool)+os.pathsep+env.get('PATH','')
    env.update(SOURCE_DATE_EPOCH='1791676800',TZ='UTC',ZERO_AR_DATE='1')
    def target_libraries(name):
        target_name=name.removesuffix('.exe') if a.cache_build else 'privacycoin-devnet'
        linkfile=next(cache.rglob(target_name+'.dir/linkLibs.rsp'))
        tokens=shlex.split(linkfile.read_text())
        libraries=[str(cache/t) if not t.startswith('-') and not Path(t).is_absolute() else t for t in tokens]
        if a.static_runtime:
            for i,name in enumerate(libraries):
                if name.endswith('.dll.a'):
                    target=Path(name[:-6]+'.a')
                    if not target.is_file():raise ValueError('STATIC_RUNTIME_LIBRARY_UNAVAILABLE')
                    libraries[i]=str(target)
            # DLLs normally resolve these dependencies internally. Group static
            # archives to resolve their circular references without stubs.
            libraries=['-Wl,--start-group',*libraries,'-lz','-lexpat','-lintl','-liconv','-Wl,--end-group']
        return libraries
    include=[a.cache_source/'.upstream/monero'/x for x in ('src','contrib/epee/include','external','external/rapidjson/include','external/easylogging++','external/supercop/include','external/db_drivers/liblmdb','external/randomx/src','src/platform/mingw')]+[cache/'generated_include',r/'src']
    common=[str(tool/'g++.exe'),'-std=c++17','-O2','-fstack-protector-strong','-DWIN32_LEAN_AND_MEAN','-D_WIN32_WINNT=0x0601','-DBOOST_NO_AUTO_PTR','-DSIGKILL=9',*['-I'+str(x) for x in include]]
    if a.static_runtime:common+=['-static','-static-libgcc','-static-libstdc++']
    targets={'pc-public-tools.exe':[r/'apps/network_v1/native/public_tools.cpp'],
             'privacycoin-hardened-devnet.exe':[r/'src/phase4/ledger.cpp',r/'src/phase4/node.cpp'],
             'privacycoin-hardened-crypto.exe':[r/'src/phase4/crypto.cpp'],
             'privacycoin-wallet-crypto.exe':[r/'src/wallet/crypto.cpp']}
    report=dict(kind='WINDOWS_CACHE_LINKED_NOT_CLEAN_REBUILD',static_runtime=a.static_runtime,targets={},failures=[],commands=[],source_date_epoch=env['SOURCE_DATE_EPOCH'],tool_sha256={n:hashlib.sha256((tool/n).read_bytes()).hexdigest() for n in ('g++.exe','ld.exe')})
    sha=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
    # The historical archive contains a pre-const change_addr ABI. Compile the
    # pinned current implementation rather than changing transaction semantics
    # or the current header to match that stale archive. Cache stays read-only.
    tx_source=a.cache_source/'.upstream/monero/src/cryptonote_core/cryptonote_tx_utils.cpp'
    tx_object=a.out/'cryptonote_tx_utils.cpp.obj'
    if not a.cache_build:
        command=[*common,'-ffunction-sections','-fdata-sections','-c',str(tx_source),'-o',str(tx_object)]
        with (a.out/'current-tx-utils.log').open('xb') as log:
            result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
        if result.returncode:raise ValueError('CURRENT_PINNED_TX_IMPLEMENTATION_BUILD_FAILED')
        report['cache_abi_repair']={'source_sha256':sha(tx_source),'object_sha256':sha(tx_object),'reason':'historical archive change_addr lacks const; current pinned implementation rebuilt'}
    report['cache_build']=str(cache)
    report['library_sha256']={}
    for name,sources in targets.items():
        libraries=target_libraries(name)
        report['library_sha256'].update({str(Path(n)):sha(Path(n)) for n in libraries if Path(n).is_file()})
        extra=[str(tx_object),'-Wl,--gc-sections'] if name=='privacycoin-hardened-crypto.exe' and not a.cache_build else []
        command=[*common,*map(str,sources),'-o',str(a.out/name),'-Wl,--dynamicbase,--nxcompat,--high-entropy-va,--no-insert-timestamp',*extra,*libraries]
        with (a.out/(name+'.log')).open('xb') as log:
            result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
        report['commands'].append(dict(command=command,returncode=result.returncode))
        if result.returncode:report['failures'].append(name)
        else:report['targets'][name]={'sha256':sha(a.out/name),'sources':{str(x.relative_to(r)):sha(x) for x in sources}}
        print(name,'BUILD_FAIL' if result.returncode else 'BUILD_PASS',flush=True)
    report['result']='PASS_BUILD_ONLY' if not report['failures'] else 'INCOMPLETE'
    (a.out/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    if report['failures']:raise SystemExit(1)


if __name__=='__main__':main()
