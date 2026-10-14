"""Allowlisted source-only USB bundle, hash verification and bounded safe extraction."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,re,stat,subprocess,zipfile
ROOT=Path(__file__).resolve().parents[3]
LIMIT=256*1024*1024
MAX_FILES=15000
def sha(raw):return hashlib.sha256(raw).hexdigest()
def safe_name(name):
    p=PurePosixPath(name)
    if not name or '\\' in name or ':' in name or p.is_absolute() or any(x in ('','..','.') for x in name.split('/')):raise ValueError('UNSAFE_ARCHIVE_PATH')
    return p
def decode(raw):
    def unique(items):
        result={}
        for k,v in items:
            if k in result:raise ValueError('DUPLICATE_JSON_KEY')
            result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique)
def validate_manifest(m):
    if set(m)!={'version','source_base_commit','scope','files'} or type(m['version']) is not int or m['version']!=1 or not 1<=len(m['files'])<=MAX_FILES:raise ValueError('MANIFEST_SCHEMA')
    for name,expected in m['files'].items():
        safe_name(name)
        if not isinstance(expected,str) or len(expected)!=64 or any(x not in '0123456789abcdef' for x in expected):raise ValueError('HASH')
    return m
def verify_tree(root):
    root=Path(root);m=validate_manifest(decode((root/'N2_SOURCE_MANIFEST.json').read_bytes()));total=0
    for name,expected in m['files'].items():
        p=root/name
        if any(x.is_symlink() for x in [p,*list(p.parents)[:len(PurePosixPath(name).parts)-1]]) or not p.is_file():raise ValueError('UNSAFE_SOURCE')
        raw=p.read_bytes();total+=len(raw)
        if total>LIMIT or sha(raw)!=expected:raise ValueError('SOURCE_INTEGRITY')
    return m
def inspect(path):
    with zipfile.ZipFile(path) as z:
        items=z.infolist();names=[i.filename for i in items]
        if len(items)>MAX_FILES+1 or len(set(n.casefold() for n in names))!=len(names) or sum(i.file_size for i in items)>LIMIT:raise ValueError('ARCHIVE_BOUND_OR_COLLISION')
        for i in items:
            safe_name(i.filename)
            if i.is_dir() or stat.S_ISLNK(i.external_attr>>16) or i.flag_bits&1:raise ValueError('ARCHIVE_TYPE')
        m=validate_manifest(decode(z.read('N2_SOURCE_MANIFEST.json')))
        if set(names)!=set(m['files'])|{'N2_SOURCE_MANIFEST.json'}:raise ValueError('ARCHIVE_FILE_SET')
        for n,h in m['files'].items():
            if sha(z.read(n))!=h:raise ValueError('ARCHIVE_HASH')
        return m
def extract(path,dest):
    m=inspect(path);dest=Path(dest)
    if dest.exists() or dest.is_symlink():raise ValueError('NEW_DESTINATION_REQUIRED')
    if any(p.is_symlink() for p in dest.parents):raise ValueError('SYMLINK_DESTINATION')
    dest.mkdir(mode=0o700,parents=True)
    with zipfile.ZipFile(path) as z:
        for n in ['N2_SOURCE_MANIFEST.json',*m['files']]:
            p=dest/n;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            with p.open('xb') as out:out.write(z.read(n))
            p.chmod(0o600)
    verify_tree(dest);return m
def pack(output,upstream):
    output=Path(output)
    if output.exists():raise ValueError('NO_ARCHIVE_OVERWRITE')
    git=['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}']
    tracked=subprocess.check_output(git+['ls-files','-z']).decode().split('\0')
    paths={}
    prefixes=('src/','tests/phase0/','tests/phase1/','tests/phase2/','tests/phase3/','tests/phase4/','scripts/devnet-gui/','services/privacy-network/')
    # Explicit source extensions; never wallet/database/bundle/journal/runtime files.
    source_ext={'.py','.cpp','.c','.cc','.h','.hpp','.cxx','.hh','.hxx','.ipp','.inl','.txx','.tcc','.inc','.cmake','.S','.s','.asm','.txt','.in','.md','.sh','.json','.def','.map','.rc','.pc','.proto','.html','.css','.svg','.qrc','.ui','.ts','.xml','.dox','.exp','.bat'}
    for name in tracked:
        if name and name.startswith(prefixes) and Path(name).suffix in source_ext:paths[name]=ROOT/name
    for folder in ('deploy/n2','docs/privacy-network/n2'):
        for p in (ROOT/folder).rglob('*'):
            if p.is_file() and p.suffix in source_ext|{'.ps1','.cmd'} and '__pycache__' not in p.parts:paths[p.relative_to(ROOT).as_posix()]=p
    # Redacted preparation evidence, never private fixture contents. Detached
    # archive hash/audit are excluded to avoid a self-referential package hash.
    for folder in ('privacy-network-n2','privacy-network-n2-connectivity'):
        for p in (ROOT/'docs/evidence'/folder).rglob('*.json'):
            if p.name not in ('audit.json','bundle.json'):paths[p.relative_to(ROOT).as_posix()]=p
    for name in ('SECURITY.md','docs/design/DEPENDENCIES.md','docs/evidence/phase0/source-acquisition.json','docs/evidence/phase0/monero-release-tag.json'):
        paths[name]=ROOT/name
    upstream=Path(upstream)
    if not (upstream/'CMakeLists.txt').is_file():raise ValueError('PINNED_UPSTREAM_SOURCE_MISSING')
    for p in upstream.rglob('*'):
        rel=p.relative_to(upstream)
        if any(x in ('.git','__pycache__','build') for x in rel.parts) or any(x.startswith('.failed') for x in rel.parts):continue
        public_build_fixtures={'src/blocks/checkpoints.dat','src/blocks/testnet_blocks.dat','src/blocks/stagenet_blocks.dat'}
        public_curve_table=rel.as_posix().startswith('external/supercop/crypto_sign/ed25519/') and p.name.startswith('ge25519_base_') and p.suffix=='.data'
        license_or_readme=re.fullmatch(r'(?i)(license|copying|copyright|notice|authors|readme)(?:[._-].*)?',p.name) is not None
        if p.is_file() and (p.suffix in source_ext or license_or_readme or public_curve_table or rel.as_posix() in public_build_fixtures or p.name in ('Makefile','.gitmodules','.gitignore','.gitattributes')):paths['.upstream/monero/'+rel.as_posix()]=p
    if len(paths)>MAX_FILES:raise ValueError('SOURCE_BOUND')
    files={};size=0
    output.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(output,'x',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name,p in sorted(paths.items()):
            safe_name(name)
            if p.is_symlink():raise ValueError('SOURCE_SYMLINK')
            raw=p.read_bytes();size+=len(raw)
            if size>LIMIT or raw.startswith(b'\x7fELF') or raw.startswith(b'MZ') or re.search(rb'(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----',raw):raise ValueError('NON_SOURCE_OR_BOUND')
            files[name]=sha(raw);z.writestr(name,raw)
        m=dict(version=1,source_base_commit=subprocess.check_output(git+['rev-parse','HEAD']).decode().strip(),scope='N2 preparation working-source snapshot; no binaries or runtime data; upstream plus disclosed local build fixtures; not independent source authentication',files=files)
        z.writestr('N2_SOURCE_MANIFEST.json',json.dumps(m,sort_keys=True,indent=2))
    inspect(output)
    result=dict(archive=str(output),sha256=sha(output.read_bytes()),bytes=output.stat().st_size,uncompressed_bytes=size,files=len(files),source_base_commit=m['source_base_commit'])
    output.with_suffix('.sha256').write_text(result['sha256']+'  '+output.name+'\n')
    print(json.dumps(result));return result
def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['pack','inspect','extract','verify']);p.add_argument('path',type=Path);p.add_argument('--upstream',type=Path);p.add_argument('--destination',type=Path);a=p.parse_args()
    if a.action=='pack':pack(a.path,a.upstream)
    elif a.action=='inspect':print('PASS_SOURCE_ARCHIVE',len(inspect(a.path)['files']))
    elif a.action=='extract':print('PASS_SAFE_EXTRACTION',len(extract(a.path,a.destination)['files']))
    else:print('PASS_SOURCE_TREE',len(verify_tree(a.path)['files']))
if __name__=='__main__':main()
