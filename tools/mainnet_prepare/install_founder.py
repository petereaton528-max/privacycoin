"""Offline owner-only installer. No secrets, network, services or elevation.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,stat,zipfile
from pathlib import Path,PurePosixPath

def install(archive,destination,expected):
    os.umask(0o077)
    if os.name!='posix' or os.getuid()==0:raise ValueError('UNPRIVILEGED_LINUX_REQUIRED')
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise ValueError('ARCHIVE_CHECKSUM_MISMATCH')
    if not destination.is_absolute() or '..' in destination.parts or str(destination).startswith('/mnt/') or destination.exists() or destination.is_symlink():raise ValueError('FRESH_NATIVE_DESTINATION_REQUIRED')
    for p in (destination.parent,*destination.parent.parents):
        if p.is_symlink():raise ValueError('SYMLINK_PATH')
    s=destination.parent.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077:raise ValueError('PRIVATE_INSTALL_PARENT_REQUIRED')
    with zipfile.ZipFile(archive) as z:
        infos=z.infolist();names=[i.filename for i in infos]
        if len(names)>16000 or len(names)!=len(set(names)) or sum(i.file_size for i in infos)>321*1024*1024:raise ValueError('ARCHIVE_BOUNDS')
        for i in infos:
            p=PurePosixPath(i.filename)
            if not i.filename or p.is_absolute() or '..' in p.parts or '\\' in i.filename or ':' in i.filename or i.is_dir() or stat.S_ISLNK(i.external_attr>>16):raise ValueError('ARCHIVE_PATH')
        m=json.loads(z.read('FOUNDER_MANIFEST.json'))
        if set(names)!=set(m['files'])|{'FOUNDER_MANIFEST.json','V1_MANIFEST.json'}:raise ValueError('MANIFEST_MEMBERS')
        for n,h in m['files'].items():
            if hashlib.sha256(z.read(n)).hexdigest()!=h:raise ValueError('MEMBER_CHECKSUM')
        destination.mkdir(mode=0o700)
        for i in infos:
            target=destination/i.filename;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with target.open('xb') as out:out.write(z.read(i));out.flush();os.fsync(out.fileno())
            target.chmod(0o700 if i.filename in m['executable'] else 0o600)
    return dict(status='INSTALLED',source_commit=m['source_commit'],services_started=False,keys_generated=False)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('archive',type=Path);p.add_argument('destination',type=Path);p.add_argument('--sha256',required=True);a=p.parse_args()
    print(json.dumps(install(a.archive,a.destination,a.sha256)))
