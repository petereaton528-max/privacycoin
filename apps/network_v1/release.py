"""Deterministic source/runtime archives. No runtime stores, no release upload.

Packaging determinism does NOT imply independently reproducible native binaries.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile
import uuid
import subprocess
import io

from .rpc import VERSION, NETWORK, GENESIS, PROFILE, unique

ROOT=Path(__file__).resolve().parents[2]
EXT={'.py','.cpp','.c','.cc','.h','.hpp','.cxx','.hh','.hxx','.ipp','.inl','.txx','.tcc','.inc','.cmake','.S','.s','.asm','.txt','.in','.md','.sh','.json','.def','.map','.rc','.pc','.proto','.html','.css','.js','.svg','.qrc','.ui','.ts','.xml','.dox','.exp','.bat','.ps1','.cmd','.toml'}
SECRET_EXT={'.wallet','.seed','.key','.keys','.password','.credential','.capability','.backup','.bundle','.intent','.upload','.gui-state','.page','.sqlite','.mdb','.payment-intent','.pc-recovery','.phase6a-cache'}
SECRET_NAMES={'control','control_auth_cookie','hs_ed25519_secret_key','credential'}
# Historical uncommitted operator tools are preserved locally, but are not V1
# runtime/build dependencies or approved source-publication inputs.
SOURCE_EXCLUSIONS={'deploy/n2/common/n2_read_only_evidence.py',
                   'deploy/n2/common/n2_rotate_admin.py',
                   'deploy/n2/tests/test_admin_rotation.py',
                   'deploy/n2/tests/test_read_only_evidence.py'}

# Unverified helper provenance outside the licensed ref10/ISC subtrees. The
# production crypto target compiles the delivered crypto-ops.c/data.c directly;
# none of these historical standalone generator helpers is a build input.
# Preserve the originals and generated-code attribution locally.
UPSTREAM_SOURCE_EXCLUSIONS={
    'src/crypto/crypto_ops_builder/'+n for n in (
        'api.h','crypto_int32.h','crypto_sign.h','crypto_uint32.h',
        'crypto_verify_32.h','randombytes.c','sha512-blocks.c','sha512.h','verify.c')}


def safe_name(name):
    p=PurePosixPath(name)
    if not name or any(ord(x)<32 for x in name) or '\\' in name or ':' in name or p.is_absolute() or any(x in ('','.','..') for x in name.split('/')):
        raise ValueError('ARCHIVE_PATH')
    return p


def source_files():
    result={}
    # Explicit product source roots, never recursive whole-repository history.
    for folder in ('apps/network_v1','src','tests','scripts/devnet-gui','services/privacy-network','deploy/n2/common','deploy/n2/tests','docs/network-v1','experiments/sphlib'):
        for p in (ROOT/folder).rglob('*'):
            if '__pycache__' in p.parts or p.is_symlink():continue
            legal=re.fullmatch(r'(?i)(license|copying|copyright|notice|authors)(?:[._-].*)?',p.name)
            if p.is_file() and (p.suffix in EXT or legal or not p.suffix and folder in ('scripts','deploy')) and p.suffix not in SECRET_EXT:
                name=p.relative_to(ROOT).as_posix()
                if name not in SOURCE_EXCLUSIONS:result[name]=p.read_bytes()
    for name in ('README.md','SECURITY.md','LICENSE','LICENSE_SCOPE.md','CONTRIBUTING.md'):
        if (ROOT/name).is_file():result[name]=(ROOT/name).read_bytes()
    for phase in ('phase2','phase3','phase4'):
        name='scripts/'+phase+'/privacycoin-wallet'
        result[name]=(ROOT/name).read_bytes()
    for name in ('docs/design/DEPENDENCIES.md','docs/design/LICENSE_PROVENANCE.md','docs/protocol/MINING_CONSENSUS.md','docs/protocol/DEVNET_GENESIS.md'):
        result[name]=(ROOT/name).read_bytes()
    for p in ROOT.iterdir():
        if p.is_file() and re.fullmatch(r'(?i)(license|copying|copyright|notice)(?:[._-].*)?',p.name):result[p.name]=p.read_bytes()
    for n in ('.gitignore','.gitattributes'):result[n]=(ROOT/n).read_bytes()
    return result


def provenance(files):
    """Record exact app commit AND any explicit worktree overlay, never hide dirt."""
    marker=ROOT/'.git'
    if not marker.exists():
        value=json.loads((ROOT/'SOURCE_REVISION.json').read_bytes(),object_pairs_hook=unique)
        if value['source_sha256']!={n:hashlib.sha256(raw).hexdigest() for n,raw in sorted(files.items())}:raise ValueError('ARCHIVED_SOURCE_CHANGED_WITHOUT_GIT_PROVENANCE')
        return value
    command=['git']
    if marker.is_file():
        directory=marker.read_text().strip().removeprefix('gitdir: ')
        if os.name=='posix' and re.match(r'^[A-Za-z]:[/\\]',directory):directory='/mnt/'+directory[0].lower()+'/'+directory[3:].replace('\\','/')
        command+=['--git-dir='+directory,'--work-tree='+str(ROOT)]
    commit=subprocess.check_output([*command,'rev-parse','HEAD'],cwd=ROOT).decode().strip()
    overlay=[];representations=[];names=sorted(files)
    result=subprocess.run([*command,'cat-file','--batch'],cwd=ROOT,input=''.join(commit+':'+n+'\n' for n in names).encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True)
    blobs=io.BytesIO(result.stdout)
    for name in names:
        header=blobs.readline()
        if header.endswith(b' missing\n'):overlay.append(name);continue
        fields=header.split()
        if len(fields)!=3 or fields[1]!=b'blob':raise ValueError('GIT_SOURCE_BLOB')
        original=blobs.read(int(fields[2]));assert blobs.read(1)==b'\n';raw=files[name]
        if original!=raw:
            if original.replace(b'\r\n',b'\n')==raw.replace(b'\r\n',b'\n'):representations.append(name)
            else:overlay.append(name)
    return dict(source_commit=commit,worktree_overlay=sorted(overlay),eol_representation_only=sorted(representations),upstream_commit='22578c3f7d7b4b6dd85ff7daa42a827d97cc53d0',inclusion_files=sorted(files),source_sha256={n:hashlib.sha256(raw).hexdigest() for n,raw in sorted(files.items())},signed=False)


def upstream_files(upstream):
    result={}
    for p in upstream.rglob('*'):
        rel=p.relative_to(upstream)
        if rel.as_posix() in UPSTREAM_SOURCE_EXCLUSIONS:continue
        # Unused upstream unit-test fixtures carry the restrictive JSON license.
        # Monero uses RapidJSON headers without adding its standalone test build.
        # Preserve the original checkout and RapidJSON license notices verbatim.
        if rel.as_posix().startswith('external/rapidjson/bin/jsonchecker/') or rel.as_posix()=='external/rapidjson/test/unittest/jsoncheckertest.cpp':continue
        if any(x in ('.git','__pycache__','build') or x.startswith('.failed') for x in rel.parts) or p.is_symlink():continue
        public_blob=rel.as_posix() in {'src/blocks/checkpoints.dat','src/blocks/testnet_blocks.dat','src/blocks/stagenet_blocks.dat'}
        public_curve=rel.as_posix().startswith('external/supercop/crypto_sign/ed25519/') and p.name.startswith('ge25519_base_') and p.suffix=='.data'
        named=re.fullmatch(r'(?i)(license|copying|copyright|notice|authors|readme)(?:[._-].*)?',p.name) or p.name in ('Makefile','.gitmodules','.gitignore','.gitattributes')
        if p.is_file() and (p.suffix in EXT or named or public_blob or public_curve):
            result['.upstream/monero/'+rel.as_posix()]=p.read_bytes()
    if '.upstream/monero/CMakeLists.txt' not in result:raise ValueError('PINNED_UPSTREAM_REQUIRED')
    # This branch distributes the reviewed independent sphlib substitution,
    # never the held inherited implementations. Do not modify the input tree.
    from experiments.sphlib.stage import EXPECTED, replacements
    replacement=replacements()
    for name,digest in EXPECTED.items():
        key='.upstream/monero/src/crypto/'+name
        if key not in result:raise ValueError('CRYPTO_UPSTREAM_REQUIRED:'+name)
        if hashlib.sha256(result[key]).hexdigest() not in (digest,hashlib.sha256(replacement['src/crypto/'+name]).hexdigest()):
            raise ValueError('UNREVIEWED_CRYPTO_UPSTREAM:'+name)
    result.update({'.upstream/monero/'+name:data for name,data in replacement.items()})
    return result


def archive(path, files, kind, executable=()):
    if path.exists():raise ValueError('NO_RELEASE_OVERWRITE')
    # A local inspection archive may be BLOCKED, but must carry accurate terms
    # and an evidence-bound record. This grants no publication authorization.
    from .licensing import assessment
    files=dict(files)
    files.pop('LICENSE_COMPLIANCE.json',None)
    files['LICENSE_COMPLIANCE.json']=(json.dumps(assessment(files,kind),sort_keys=True,indent=2)+'\n').encode()
    if len(files)>16000 or sum(map(len,files.values()))>320*1024*1024:raise ValueError('SOURCE_BOUNDS')
    if len(set(n.casefold() for n in files))!=len(files):raise ValueError('CASE_COLLISION')
    for n in files:
        safe_name(n)
        if PurePosixPath(n).suffix.casefold() in SECRET_EXT or PurePosixPath(n).name.casefold() in SECRET_NAMES:raise ValueError('SECRET_FILE_TYPE')
    manifest=dict(format=1,version=VERSION,kind=kind,network=NETWORK,genesis=GENESIS,profile=PROFILE,
                  public_release='BLOCKED',n2_r1_ready=False,
                  binary_reproducibility='INDEPENDENT_CROSS_HOST_UNVERIFIED; SEE_DETACHED_BUILD_EVIDENCE',signed=False,
                  executable=sorted(executable),files={n:hashlib.sha256(b).hexdigest() for n,b in sorted(files.items())})
    files=dict(files,**{'V1_MANIFEST.json':(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()})
    path.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(path,'x',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for n,raw in sorted(files.items()):
            item=zipfile.ZipInfo(n,(2026,1,1,0,0,0));item.create_system=3
            item.external_attr=(stat.S_IFREG|(0o700 if n in executable else 0o600))<<16
            item.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(item,raw,compresslevel=6)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(path, *, source_companion=False):
    with zipfile.ZipFile(path) as z:
        items=z.infolist();names=[x.filename for x in items]
        if len(items)>16001 or len(set(n.casefold() for n in names))!=len(names) or sum(x.file_size for x in items)>321*1024*1024:raise ValueError('ARCHIVE_BOUNDS')
        for item in items:
            safe_name(item.filename)
            if PurePosixPath(item.filename).suffix.casefold() in SECRET_EXT or PurePosixPath(item.filename).name.casefold() in SECRET_NAMES:raise ValueError('SECRET_FILE_TYPE')
            if item.is_dir() or stat.S_ISLNK(item.external_attr>>16) or item.flag_bits&1:raise ValueError('ARCHIVE_TYPE')
        m=json.loads(z.read('V1_MANIFEST.json'),object_pairs_hook=unique)
        expected=(VERSION,NETWORK,GENESIS,PROFILE)
        if source_companion:
            # Corresponding-source bytes can legitimately predate a development
            # network label. Never use this path for binary installation.
            from src.network_identity import selected
            legacy=selected('legacy-dev01')
            allowed={expected,('1.0.0-testnet-candidate.5',*legacy)}
            if m['kind']!='source' or m['executable']:raise ValueError('SOURCE_COMPANION_ONLY')
        else:allowed={expected}
        if m['format']!=1 or (m['version'],m['network'],m['genesis'],m['profile']) not in allowed or set(names)!=set(m['files'])|{'V1_MANIFEST.json'}:raise ValueError('MANIFEST')
        for n,h in m['files'].items():
            if hashlib.sha256(z.read(n)).hexdigest()!=h:raise ValueError('ARTIFACT_HASH')
        return m


def install(path, destination):
    """New private destination only; Windows I/O does not imply native readiness."""
    from src.phase6a import wallet as c
    c.harden();destination=Path(destination)
    if not destination.is_absolute() or destination.exists() or destination.is_symlink() or any('privacycoin-n2' in x.lower() for x in destination.parts):raise ValueError('NEW_DESTINATION')
    with c.directory(destination.parent):pass
    m=verify(path)
    if os.name=='nt':c.win.mkdir(destination,exclusive=True)
    else:destination.mkdir(mode=0o700)
    with zipfile.ZipFile(path) as z:
        for n in ['V1_MANIFEST.json',*m['files']]:
            target=destination/n
            if os.name=='nt':
                cursor=destination
                for component in target.parent.relative_to(destination).parts:
                    cursor/=component;c.win.mkdir(cursor)
            else:target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            raw=z.read(n)
            if len(raw)<=c.MAX_FILE:
                c.write_private(target,raw)
            else:
                # Public source/binary artifacts can exceed the wallet's 4 MiB
                # secret-file bound. Do not change that security bound globally.
                if len(raw)>64*1024*1024:raise ValueError('ARTIFACT_FILE_BOUND')
                if os.name=='nt':c.win.write_private(target,raw,limit=64*1024*1024)
                else:
                    with c.directory(target.parent) as parent:
                        temporary='.pc-v1-artifact-'+uuid.uuid4().hex
                        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                        try:
                            with os.fdopen(fd,'wb') as out:
                                out.write(raw);out.flush();os.fsync(out.fileno())
                            os.link(temporary,target.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
                            os.unlink(temporary,dir_fd=parent);os.fsync(parent)
                        finally:
                            try:os.unlink(temporary,dir_fd=parent)
                            except FileNotFoundError:pass
            if os.name!='nt' and n in m['executable']:target.chmod(0o700)
    c.write_private(destination/'INSTALL_COMPLETE.json',c.f.canonical(dict(version=VERSION,kind=m['kind'],services_started=False)))
    return m


def create_private_parent(destination):
    from src.phase6a import wallet as c
    if not destination.is_absolute() or '..' in destination.parts:raise ValueError('ABSOLUTE_INSTALL_DESTINATION')
    parent=destination.parent
    if parent.exists():
        with c.directory(parent):pass
        return
    if os.name=='nt':
        c.win.mkdir(parent,exclusive=True)
        return
    # A normal home may be0755. Its new child can still be private; require
    # ownership/no shared write and walk every component without symlinks.
    directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in parent.parent.parts[1:]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory);directory=next_fd
        info=os.fstat(directory)
        if info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError('OWNED_NONWRITABLE_INSTALL_ANCESTOR')
        try:os.mkdir(parent.name,mode=0o700,dir_fd=directory)
        except FileExistsError:pass
    finally:os.close(directory)
    with c.directory(parent):pass


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['pack','verify','install'])
    p.add_argument('--archive',type=Path);p.add_argument('--destination',type=Path)
    p.add_argument('--create-private-parent',action='store_true')
    p.add_argument('--native-root',type=Path);p.add_argument('--helper',type=Path);p.add_argument('--upstream',type=Path);p.add_argument('--out',type=Path)
    a=p.parse_args()
    if a.action=='verify':print(json.dumps(dict(result='PASS_ARCHIVE_INTEGRITY_ONLY',kind=verify(a.archive)['kind'])));return
    if a.action=='install':
        if a.create_private_parent:
            create_private_parent(a.destination)
        install(a.archive,a.destination);print('INSTALLED_NEW_PRIVATE_DIRECTORY; no services started');return
    base=source_files()
    base['SOURCE_REVISION.json']=(json.dumps(provenance(base),sort_keys=True,indent=2)+'\n').encode()
    complete=dict(base,**upstream_files(a.upstream))
    revision=json.loads(base['SOURCE_REVISION.json'])
    report=dict(version=VERSION,release='BLOCKED_ENGINEERING_CANDIDATE',source_commit=revision['source_commit'],worktree_overlay=revision['worktree_overlay'],native_windows=False,published=False,archives={})
    for kind,files in [('source',complete),('linux-x86_64',dict(complete)),('windows-wsl2-x86_64',dict(complete))]:
        executable=['scripts/'+phase+'/privacycoin-wallet' for phase in ('phase2','phase3','phase4')]
        if kind!='source':
            for rel in ('build/monero-linux/phase4/privacycoin-hardened-devnet','build/monero-linux/phase4/privacycoin-hardened-crypto','build/monero-linux/phase2/privacycoin-wallet-crypto'):
                files[rel]=(a.native_root/rel).read_bytes();executable.append(rel)
            files['build/network-v1/pc-public-tools']=a.helper.read_bytes();executable.append('build/network-v1/pc-public-tools')
            binding=dict(version=1,kind='V1_LOCAL_SOURCE_BUILD',
                         source_sha256={n:hashlib.sha256(b).hexdigest() for n,b in files.items() if n.startswith('src/') or n in ('tests/phase4/CMakeLists.txt','scripts/devnet-gui/launcher_host.py','apps/network_v1/native/public_tools.cpp')},
                         binary_sha256={PurePosixPath(n).name:hashlib.sha256(files[n]).hexdigest() for n in executable if n.startswith('build/monero-linux/')})
            files['build/v1-native-manifest.json']=(json.dumps(binding,sort_keys=True,indent=2)+'\n').encode()
        target=a.out/('privacycoin-network-'+VERSION+'-'+kind+'.zip')
        report['archives'][target.name]=dict(sha256=archive(target,files,kind,executable),files=len(files))
        verify(target)
    with (a.out/'RELEASE.json').open('x') as out:json.dump(report,out,indent=2);out.write('\n')
    print('SOURCE_LINUX_WINDOWS_WSL2_CANDIDATES_PACKAGED; PUBLIC_RELEASE_BLOCKED')


if __name__=='__main__':main()
