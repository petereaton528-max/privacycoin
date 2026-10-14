"""Guarded source-only update; exact old launcher backup; no runtime writes."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,tempfile,zipfile

LAUNCHER='deploy/n2/common/n2_start_diagnostic.py'
OLD='ec5db74ce137d2f11a2a763f5c760d99e5a3a8d9c569ab13a436a5aefec652ab'
BACKUP='.n2-patch-backups/upstream-5820678/n2_start_diagnostic.py'
def sha(data):return hashlib.sha256(data).hexdigest()
def safe(path):
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('SYMLINK')
def publish(target,data,replace=False):
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,temp=tempfile.mkstemp(prefix='.n2-upstream-',dir=target.parent)
    try:
        with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
        if replace:os.replace(temp,target)
        else:os.link(temp,target)
    finally:
        if os.path.exists(temp):os.unlink(temp)
def apply(archive,source,expected):
    archive=Path(archive);source=Path(source);safe(source)
    if not source.is_dir():raise ValueError('SOURCE_DIRECTORY')
    if archive.stat().st_size>8*1024**2 or sha(archive.read_bytes())!=expected:raise ValueError('PATCH_HASH')
    with zipfile.ZipFile(archive) as z:
        infos=z.infolist();names=[i.filename for i in infos]
        if len(names)!=len(set(n.casefold() for n in names)) or sum(i.file_size for i in infos)>8*1024**2 or any(i.flag_bits&1 or (i.external_attr>>16)&0o170000==0o120000 for i in infos):raise ValueError('PATCH_BOUND')
        manifest=json.loads(z.read('N2_UPSTREAM_MANIFEST.json'))
        if set(names)!=set(manifest['files'])|{'N2_UPSTREAM_MANIFEST.json'} or LAUNCHER not in manifest['files']:raise ValueError('PATCH_ENTRIES')
        pending=[];old=None
        for name,digest in manifest['files'].items():
            p=PurePosixPath(name)
            if str(p)!=name or p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or not name.startswith(('deploy/n2/common/','docs/privacy-network/n2/')) or p.suffix not in ('.py','.md'):raise ValueError('PATCH_PATH')
            data=z.read(name)
            if sha(data)!=digest:raise ValueError('ENTRY_HASH')
            target=source/name;safe(target)
            if target.exists():
                previous=target.read_bytes()
                if previous==data:continue
                if name!=LAUNCHER or sha(previous)!=OLD:raise ValueError('EXISTING_FILE_CONFLICT')
                # Never invalidate a source manifest binding this launcher.
                for mpath in source.glob('N2*MANIFEST.json'):
                    safe(mpath)
                    if name in json.loads(mpath.read_bytes()).get('files',{}):raise ValueError('SOURCE_MANIFEST_BOUND')
                old=previous
            elif name==LAUNCHER:raise ValueError('DIAGNOSTIC_BASE_REQUIRED')
            pending.append((target,data,name==LAUNCHER))
        backup=source/BACKUP;safe(backup)
        if backup.exists() and sha(backup.read_bytes())!=OLD:raise ValueError('BACKUP_CONFLICT')
        # Validate every path/conflict before touching source. A source backup is
        # not a wallet backup. Run with all operator sessions stopped.
        if old is not None and not backup.exists():publish(backup,old)
        for target,data,replace in pending:
            safe(target)
            if replace and sha(target.read_bytes())!=OLD:raise ValueError('SOURCE_CHANGED')
            publish(target,data,replace)
    return len(pending)
def main():
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--expect-sha256',required=True);a=p.parse_args()
    print('Source patch files installed:',apply(a.archive,a.source,a.expect_sha256))
if __name__=='__main__':main()
