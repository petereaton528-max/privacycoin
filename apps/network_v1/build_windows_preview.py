"""Self-contained unsigned Windows engineering preview, not release acceptance.

Explicit local authenticated input roots only. No downloads, policy changes,
private state, site-packages, toolchains or machine-specific paths in runtime.
"""
import argparse,hashlib,json,os,re,subprocess,sys,zipfile
from pathlib import Path
from .release import archive,source_files,provenance,verify

def main():
    p=argparse.ArgumentParser()
    for name in ('python','toolchain','core','tor','tls','sodium','notices','out'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    if os.name!='nt' or a.out.exists() or any(not x.is_absolute() for x in vars(a).values()):raise ValueError('NEW_ABSOLUTE_WINDOWS_BUILD_REQUIRED')
    root=Path(__file__).resolve().parents[2];a.out.mkdir()
    sha=lambda raw:hashlib.sha256(raw).hexdigest()
    files=source_files();files['SOURCE_REVISION.json']=(json.dumps(provenance(files),indent=2)+'\n').encode()
    inputs={};runtime={}
    def add(path,name):
        if path.is_symlink() or not path.is_file():raise ValueError('REGULAR_INPUT_REQUIRED')
        raw=path.read_bytes();runtime[name]=raw;inputs[str(path)]=sha(raw)
    python_dlls=[x for x in a.python.glob('python3*.dll') if re.fullmatch(r'python3[0-9]{2}\.dll',x.name)]
    if len(python_dlls)!=1:raise ValueError('ONE_STANDARD_PYTHON_ABI_REQUIRED')
    python_dll=python_dlls[0].name
    for name in ('python.exe','pythonw.exe','python3.dll',python_dll,'vcruntime140.dll','vcruntime140_1.dll','LICENSE.txt'):
        add(a.python/name,'runtime/python/'+name)
    for folder in ('DLLs','Lib','tcl'):
        for path in sorted((a.python/folder).rglob('*')):
            rel=path.relative_to(a.python)
            if any(n.casefold() in ('site-packages','__pycache__','test','tests','idlelib','ensurepip','venv','turtledemo','demos') for n in rel.parts):continue
            if not path.is_file() or path.is_symlink():continue
            if folder=='Lib' and path.suffix!='.py':continue
            if folder=='DLLs' and path.suffix.lower() not in ('.pyd','.dll'):continue
            add(path,'runtime/python/'+rel.as_posix())
    # _pth is Python's documented isolated distribution mechanism. No import
    # site, user site, cwd, registry or PYTHONPATH injection in child -m commands.
    # CPython3.12 on this Windows host normalizes a slash-terminated '..' pair
    # differently from Windows separators. Use the native spelling, tested in
    # the extracted archive; never bake a developer/install absolute path here.
    runtime['runtime/python/'+python_dll.removesuffix('.dll')+'._pth']=b'.\nDLLs\nLib\n..\\..\n'
    binding=dict(version=1,kind='V1_LOCAL_SOURCE_BUILD',source_sha256={n:sha(raw) for n,raw in files.items() if n.startswith('src/') or n in ('tests/phase4/CMakeLists.txt','scripts/devnet-gui/launcher_host.py')},binary_sha256={})
    for name,folder in (('privacycoin-hardened-devnet','phase4'),('privacycoin-hardened-crypto','phase4'),('privacycoin-wallet-crypto','phase2')):
        path=a.core/(name+'.exe');add(path,'build/monero-windows/'+folder+'/'+path.name);binding['binary_sha256'][name]=inputs[str(path)]
    add(a.core/'pc-public-tools.exe','build/network-v1/pc-public-tools.exe')
    add(a.tor,'runtime/bin/tor.exe');add(a.tls,'runtime/bin/pc-tls-tools.exe');add(a.sodium,'runtime/lib/libsodium-26.dll')
    # Retain supplier notices; owner BSD grant does not clear runtime rights.
    for path in a.notices.iterdir():
        if path.is_file() and not path.is_symlink():add(path,'third-party/native-runtime/'+path.name)
    files.update(runtime)
    files['third-party/native-runtime/PROJECT-LICENSE-STATUS.md']=files['docs/network-v1/LICENSE_STATUS.md']
    files['build/v1-native-manifest.json']=(json.dumps(binding,indent=2)+'\n').encode()
    commands=[];compiler=a.toolchain/'bin/gcc.exe';source=root/'apps/network_v1/native/desktop_entry.c'
    env=dict(os.environ,PATH=str(a.toolchain/'bin')+os.pathsep+os.environ['PATH'])
    for name,entry in (('PrivacyCoin.exe',None),('Setup-PrivacyCoin.exe',r'apps\network_v1\native_install.py')):
        command=[str(compiler),'-O2','-Wall','-Wextra','-static','-static-libgcc','-municode','-mwindows','-Wl,--no-insert-timestamp',str(source),'-o',str(a.out/name)]
        if entry:command.insert(1,'-DPC_ENTRY=L"'+entry.replace('\\','\\\\')+'"')
        with (a.out/(name+'.build.txt')).open('xb') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=45)
        if result.returncode:raise ValueError('LAUNCHER_BUILD_FAILED')
        commands.append(command)
    files['PrivacyCoin.exe']=(a.out/'PrivacyCoin.exe').read_bytes()
    files['NATIVE-PREVIEW.txt']=b'''EXPERIMENTAL TESTNET NATIVE WINDOWS ENGINEERING PREVIEW. UNSIGNED.
No WSL, separately installed Python or Tor is required by this bundle.
This is NOT an accepted native wallet/mining release. Current coin executables
are blocked by Code Integrity on the development host; no bypass is permitted.
Tor and mining stay OFF until explicit consent. No public bootstrap catalog.
Wallet data: LocalAppData/PrivacyCoinV1-testnet, outside installed binaries.
Uninstall: close application, remove ONLY the installed application directory.
Keep wallet data and complete encrypted recovery sets; no automatic deletion.
Update: install a NEW directory; use only documented compatible upgrade checks.
Failed installs remain incomplete. Never use historical N2 data or identities.
Verify the externally supplied SHA-256 before opening unsigned setup.
'''
    payload=a.out/'NATIVE_PAYLOAD.zip';digest=archive(payload,files,'windows-native-preview-x86_64');verify(payload)
    setup=dict(source_files());setup.update(runtime)
    setup.update({'Setup-PrivacyCoin.exe':(a.out/'Setup-PrivacyCoin.exe').read_bytes(),'NATIVE_PAYLOAD.zip':payload.read_bytes(),'START-HERE.txt':files['NATIVE-PREVIEW.txt']})
    name='privacycoin-rc5-windows-native-self-contained-preview.zip';outer=archive(a.out/name,setup,'windows-native-preview-installer-x86_64');verify(a.out/name)
    record=dict(result='BUILT_NOT_YET_INSTALLATION_ACCEPTED',kind='WINDOWS_NATIVE_ENGINEERING_PREVIEW',version='1.0.0-testnet-candidate.5',native_windows_ready=False,public_release_ready=False,build_python_version=sys.version,bundled_python_abi=python_dll,python_inputs=inputs,commands=commands,launcher_source_sha256=sha(source.read_bytes()),compiler_sha256=sha(compiler.read_bytes()),payload_sha256=digest,archive_sha256=outer,site_packages_bundled=False,policy_changed=False,signed=False,original_n2_accessed=False)
    (a.out/'BUILD.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    (a.out/'SHA256SUMS').write_text(outer+'  '+name+'\n'+digest+'  NATIVE_PAYLOAD.zip\n',encoding='ascii')
    print(json.dumps({k:record[k] for k in ('result','archive_sha256','payload_sha256')}))

if __name__=='__main__':main()
