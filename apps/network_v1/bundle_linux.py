"""Offline Ubuntu 24.04 x86_64 validation bundle, from inspected local runtimes.

No downloads, installs, services, wallet data or public-network operations.
Distribution remains blocked by the project's licensing and release gates.
"""
import argparse,hashlib,json,os,platform,re,shutil,subprocess,sys
from pathlib import Path
from .release import source_files,archive,verify,provenance

def application_runtime_file(path):
    # The desktop/SDK use SQLite and noninteractive Python. Omitting unused
    # DBM and Readline extensions also omits their native dependency closures.
    return (not any(x in ('__pycache__','test','tests','ensurepip','dbm') for x in path.parts)
            and not path.name.startswith(('_dbm.','_gdbm.','readline.')))

def main():
    p=argparse.ArgumentParser();p.add_argument('--native-root',type=Path,required=True);p.add_argument('--gui-root',type=Path,required=True);p.add_argument('--tor',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if sys.platform!='linux' or platform.machine()!='x86_64' or 'VERSION_ID="24.04"' not in Path('/etc/os-release').read_text():raise ValueError('UBUNTU_2404_X86_64_ONLY')
    if a.out.exists() or not a.out.is_absolute():raise ValueError('NEW_ABSOLUTE_OUTPUT_REQUIRED')
    expected='cde224752e7f234fc6d0edd0711e43cd95eabae4fdb923cf8a1ab6b59e66ba8e'
    sha=lambda raw:hashlib.sha256(raw).hexdigest()
    if sha(a.tor.read_bytes())!=expected:raise ValueError('REVIEWED_TOR_RUNTIME_REQUIRED')
    os.umask(0o077);a.out.mkdir(mode=0o700)
    files=source_files();executables=[];origins={};pending=[];copied=set();packages={}
    def add(name,path,execute=False):
        path=path.resolve(strict=True)
        if not path.is_file() or path.stat().st_size>64*1024*1024:raise ValueError('RUNTIME_FILE_BOUND')
        raw=path.read_bytes()
        if name in files and files[name]!=raw:raise ValueError('RUNTIME_NAME_COLLISION')
        files[name]=raw;origins[name]=dict(local_path=str(path),sha256=sha(raw))
        if execute:executables.append(name)
        if raw[:4]==b'\x7fELF' and path not in copied:copied.add(path);pending.append(path)
    for path in Path('/usr/lib/python3.12').rglob('*'):
        if path.is_file() and application_runtime_file(path):add('runtime/python/lib/python3.12/'+path.relative_to('/usr/lib/python3.12').as_posix(),path)
    add('runtime/python/bin/python3',Path(sys.executable),True)
    for subtree in ('usr/lib/python3.12','usr/lib/python3.12/lib-dynload','usr/share/tcltk'):
        folder=a.gui_root/subtree
        if not folder.exists():continue
        for path in folder.rglob('*'):
            if path.is_file() and application_runtime_file(path):
                name=('runtime/python/lib/python3.12/' if subtree.startswith('usr/lib/python') else 'runtime/tcltk/')+path.relative_to(folder).as_posix()
                if subtree.endswith('lib-dynload'):name='runtime/python/lib/python3.12/lib-dynload/'+path.relative_to(folder).as_posix()
                add(name,path)
    for name in ('phase4/privacycoin-hardened-devnet','phase4/privacycoin-hardened-crypto','phase2/privacycoin-wallet-crypto'):add('build/monero-linux/'+name,a.native_root/'build/monero-linux'/name,True)
    add('build/network-v1/pc-public-tools',a.native_root/'build/network-v1/pc-public-tools',True)
    add('runtime/bin/openssl',Path('/usr/bin/openssl'),True);add('runtime/bin/tor',a.tor,True)
    # ldd inspects only already trusted local ELF files. No arbitrary downloaded
    # binary is accepted; dependency paths must resolve under these fixed roots.
    search=str(a.gui_root/'usr/lib/x86_64-linux-gnu')+':'+str(a.gui_root/'usr/lib')
    while pending:
        path=pending.pop();r=subprocess.run(['ldd',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=dict(os.environ,LD_LIBRARY_PATH=search),timeout=10)
        text=r.stdout.decode()
        if r.returncode or 'not found' in text:raise ValueError('RUNTIME_DEPENDENCY_UNAVAILABLE')
        for line in text.splitlines():
            m=re.match(r'\s*(\S+) => (/\S+) \(',line)
            if not m:continue
            name,location=m.groups()
            # libc and the dynamic loader are the declared OS ABI, not bundled.
            if name in ('libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libresolv.so.2','libutil.so.1'):continue
            dep=Path(location).resolve(strict=True)
            if not any(dep.is_relative_to(root) for root in (Path('/usr/lib'),Path('/lib').resolve(),a.gui_root.resolve())):raise ValueError('UNTRUSTED_DEPENDENCY_PATH')
            add('runtime/lib/'+name,dep)
    # Tcl loads its script library dynamically, so include its registered runtime
    # data and shared libraries even when not directly named by a Python ELF.
    for path in (a.gui_root/'usr/lib/x86_64-linux-gnu').glob('libt[ck]*.so*'):
        if path.is_file():add('runtime/lib/'+path.name,path)
    for name,origin in origins.items():
        q=subprocess.run(['dpkg-query','-S',origin['local_path']],capture_output=True,text=True)
        if q.returncode:continue
        package=q.stdout.split(': /',1)[0].splitlines()[0]
        if package in packages:continue
        version=subprocess.run(['dpkg-query','-W','-f=${Version}',package],capture_output=True,text=True)
        copyright=Path('/usr/share/doc')/package.split(':')[0]/'copyright'
        packages[package]=dict(installed_version=version.stdout,provenance='LOCAL_DPKG_METADATA_NOT_FRESH_ARCHIVE_AUTHENTICATION')
        if copyright.is_file():files['runtime/notices/'+package.replace(':','_')+'.txt']=copyright.read_bytes()
    notices=a.gui_root/'usr/share/doc'
    for path in notices.glob('*/copyright'):
        files['runtime/notices/gui-'+path.parent.name+'.txt']=path.read_bytes()
    tor_notice=a.tor.parents[1]/'share/doc/tor/copyright'
    if not tor_notice.is_file():raise ValueError('TOR_NOTICE_REQUIRED')
    files['runtime/notices/tor.txt']=tor_notice.read_bytes()
    files['SOURCE_REVISION.json']=(json.dumps(provenance(source_files()),indent=2)+'\n').encode()
    source_hashes={n:sha(raw) for n,raw in files.items() if n.startswith('src/') or n in ('tests/phase4/CMakeLists.txt','scripts/devnet-gui/launcher_host.py','apps/network_v1/native/public_tools.cpp')}
    files['build/v1-native-manifest.json']=(json.dumps(dict(version=1,kind='V1_LOCAL_SOURCE_BUILD',source_sha256=source_hashes,binary_sha256={Path(n).name:sha(files[n]) for n in executables if n.startswith('build/monero-linux/')}),indent=2)+'\n').encode()
    files['Launch-PC.sh']=b'''#!/bin/sh
set -eu
umask 077
APP=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Use the bundled interpreter's deliberate configuration, not developer paths
# or inherited interactive/optimization settings. No secrets are configured here.
unset PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTHONSAFEPATH PYTHONPLATLIBDIR PYTHONUSERBASE PYTHONEXECUTABLE PYTHONOPTIMIZE PYTHONVERBOSE PYTHONWARNINGS PYTHONPYCACHEPREFIX PYTHONHOME
export PYTHONHOME="$APP/runtime/python"
export PYTHONNOUSERSITE=1
export LD_LIBRARY_PATH="$APP/runtime/lib"
export TCL_LIBRARY="$APP/runtime/tcltk/tcl8.6"
export TK_LIBRARY="$APP/runtime/tcltk/tk8.6"
export PATH="$APP/runtime/bin:/usr/bin:/bin"
cd -- "$APP"
exec "$APP/runtime/python/bin/python3" -B -m apps.network_v1.desktop "$@"
'''
    executables.append('Launch-PC.sh')
    files['Install-PC.sh']=files['Launch-PC.sh'].replace(b'-m apps.network_v1.desktop',b'-m apps.network_v1.setup')
    executables.append('Install-PC.sh')
    files['BUNDLED-LINUX-START.txt']=b'''Experimental TESTNET, unsigned, no monetary value. Ubuntu 24.04 x86_64 graphical desktop required.
1. Obtain this archive and its SHA-256 through the owner's authenticated release channel.
2. Extract into a NEW directory. Do not extract over an old application or wallet.
3. In the file manager, select Install-PC.sh and choose Run as Program.
4. Choose the original ZIP, paste its trusted SHA-256, and choose Verify and install.
5. Choose Launch application. Wallet data stays separate from application files.
Use the installed Launch-PC.sh afterwards. Do not run Launch-PC.sh directly from the bootstrap extraction: private installation is required.
Tor and mining remain OFF until consent. No public seed catalog is bundled.
No native Windows/backend, clean-host acceptance, publisher signature or public-release readiness is claimed.
To remove program files, close the application and remove only its installed program directory with the file manager. Preserve the separate wallet data and backups.
'''
    files['runtime/PROVENANCE.json']=(json.dumps(dict(scope='LOCAL_VALIDATION_BUNDLE_NOT_PUBLIC_RELEASE',os_abi='Ubuntu 24.04 x86_64 glibc + graphical desktop',files=origins,packages=packages,tor_sha256=expected,signature=None,license_approval=False,clean_host_acceptance=False),indent=2)+'\n').encode()
    name='privacycoin-rc5-scalability-linux-ubuntu24-bundled-validation.zip'
    digest=archive(a.out/name,files,'linux-x86_64',executables);verify(a.out/name)
    (a.out/'SHA256SUMS').write_text(digest+'  '+name+'\n')
    print('OFFLINE_DEPENDENCY_INCLUSIVE_LINUX_VALIDATION_ARCHIVE_CREATED')

if __name__=='__main__':main()
