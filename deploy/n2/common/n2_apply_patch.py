"""Standalone guarded additive patch installer. Never overwrites existing files."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,zipfile,tempfile
def apply(archive,destination,expected):
    archive=Path(archive);destination=Path(destination)
    if archive.stat().st_size>8*1024**2 or hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise ValueError('PATCH_HASH')
    if not destination.is_dir() or any(p.is_symlink() for p in (destination,*destination.parents)):raise ValueError('SOURCE_DIRECTORY')
    with zipfile.ZipFile(archive) as z:
        infos=z.infolist();names=[i.filename for i in infos]
        if len(names)!=len(set(n.casefold() for n in names)) or sum(i.file_size for i in infos)>8*1024**2 or any(i.flag_bits&1 or (i.external_attr>>16)&0o170000==0o120000 for i in infos):raise ValueError('PATCH_BOUND')
        m=json.loads(z.read('N2_PATCH_MANIFEST.json'))
        if set(names)!=set(m['files'])|{'N2_PATCH_MANIFEST.json'}:raise ValueError('PATCH_ENTRIES')
        pending=[]
        for name,sha in m['files'].items():
            p=PurePosixPath(name)
            if str(p)!=name or p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or not name.startswith(('deploy/n2/common/','docs/privacy-network/n2/')) or p.suffix not in ('.py','.md'):raise ValueError('PATCH_PATH')
            data=z.read(name)
            if hashlib.sha256(data).hexdigest()!=sha:raise ValueError('ENTRY_HASH')
            target=destination/name
            if any(x.is_symlink() for x in (target,*target.parents)):raise ValueError('SYMLINK')
            if target.exists():
                if target.read_bytes()!=data:raise ValueError('EXISTING_FILE_CONFLICT')
            else:pending.append((target,data))
        # Validate ALL entries before mutation; interrupted application is resumable.
        for target,data in pending:
            target.parent.mkdir(parents=True,exist_ok=True)
            fd,temp=tempfile.mkstemp(prefix='.n2-patch-',dir=target.parent)
            try:
                with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
                os.link(temp,target) # atomic no-clobber publication
            finally:os.unlink(temp)
    return len(pending)
def main():
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--expect-sha256',required=True);a=p.parse_args()
    print('Additive patch files installed:',apply(a.archive,a.source,a.expect_sha256))
if __name__=='__main__':main()
