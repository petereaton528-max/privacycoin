"""Single-file container of existing authenticated encrypted recovery objects.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import contextlib,os,re,secrets,stat,struct,tempfile,zipfile
from pathlib import Path

MAX_TOTAL=256*1024*1024
MAX_ENTRY=4*1024*1024

def default_directory(c,home=None):
    """Create only our dedicated private leaf; never chmod an existing folder."""
    home=Path.home() if home is None else Path(home)
    if os.name!='posix' or not home.is_absolute() or '..' in home.parts:raise ValueError('BACKUP_PRIVATE_FOLDER_REQUIRED')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in home.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
        info=os.fstat(fd)
        if info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError('BACKUP_PRIVATE_FOLDER_REQUIRED')
        try:os.mkdir('PrivacyCoin-Backups',mode=0o700,dir_fd=fd);os.fsync(fd)
        except FileExistsError:pass
    finally:os.close(fd)
    destination=home/'PrivacyCoin-Backups'
    with c.directory(destination):pass
    return destination

def directory_bound(stream,size):
    # Check classic EOCD BEFORE ZipFile allocates per-entry Python objects.
    # Our bounded writer never needs ZIP64 or multiple volumes.
    stream.seek(max(0,size-65557));start=stream.tell();tail=stream.read(65557)
    pos=tail.rfind(b'PK\x05\x06')
    if pos<0 or len(tail)-pos<22:raise ValueError('BACKUP_DIRECTORY')
    _,disk,cd_disk,local,total,length,offset,comment=struct.unpack('<4s4H2LH',tail[pos:pos+22])
    if disk or cd_disk or local!=total or not 1<=total<=4097 or length>1048576 or offset+length!=start+pos or pos+22+comment!=len(tail):raise ValueError('BACKUP_DIRECTORY_BOUND')
    stream.seek(0)

def pack(c,destination,root,pages):
    """Publish a complete private archive atomically without overwriting backups.

    Entries are already encrypted/authenticated by the wallet's existing scheme.
    Names/counts/sizes are metadata, not hidden by this container. Linux/WSL only.
    """
    if os.name!='posix':raise ValueError('BACKUP_REQUIRES_SUPPORTED_LINUX_WSL_RUNTIME')
    destination=Path(destination);temporary='.pc-backup-'+secrets.token_hex(16)
    with c.directory(destination.parent) as parent:
        fd=os.open(temporary,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            with os.fdopen(fd,'w+b') as stream:
                total=0;seen=set()
                with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_STORED) as archive:
                    for name,raw in [('recovery',root)]:
                        if len(raw)>MAX_ENTRY:raise ValueError('BACKUP_ENTRY_BOUND')
                        archive.writestr(name,raw);total+=len(raw);seen.add(name)
                    for digest,raw in pages:
                        if not re.fullmatch('[0-9a-f]{64}',digest) or digest in seen:raise ValueError('BACKUP_PAGE_ID')
                        seen.add(digest);total+=len(raw)
                        if len(raw)>MAX_ENTRY or total>MAX_TOTAL-1048576 or len(seen)>4097:raise ValueError('BACKUP_CAPACITY')
                        archive.writestr('pages/'+digest+'.page',raw)
                stream.flush();os.fsync(stream.fileno())
                stream.seek(0)
                with zipfile.ZipFile(stream) as archive:
                    if archive.testzip() is not None:raise ValueError('BACKUP_WRITE_VERIFICATION')
            os.link(temporary,destination.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
            os.fsync(parent)
        finally:os.unlink(temporary,dir_fd=parent)

@contextlib.contextmanager
def opened(c,path):
    """Read legacy envelope or unpack bounded ciphertext to a private temp dir.

    No archive-supplied destination paths, compression bombs, links or duplicate
    entries. Existing envelope/page authentication is performed by the caller.
    """
    path=Path(path)
    if os.name!='posix':raise ValueError('BACKUP_REQUIRES_SUPPORTED_LINUX_WSL_RUNTIME')
    with c.directory(path.parent) as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_nlink!=1 or info.st_size>MAX_TOTAL:raise ValueError('BACKUP_PRIVATE_FILE')
            if stream.read(4)!=b'PK\x03\x04':
                yield path;return
            directory_bound(stream,info.st_size)
            with zipfile.ZipFile(stream) as archive,tempfile.TemporaryDirectory(prefix='pc-encrypted-recovery-') as folder:
                entries=archive.infolist();names=[x.filename for x in entries]
                if not 1<=len(entries)<=4097 or len(set(names))!=len(names) or 'recovery' not in names:raise ValueError('BACKUP_SCHEMA')
                if sum(x.file_size for x in entries)>MAX_TOTAL:raise ValueError('BACKUP_CAPACITY')
                home=Path(folder);pages=home/'recovery.pages';pages.mkdir(mode=0o700)
                for entry in entries:
                    if entry.compress_type!=zipfile.ZIP_STORED or entry.flag_bits&1 or entry.file_size>MAX_ENTRY or entry.file_size!=entry.compress_size:raise ValueError('BACKUP_ENTRY_BOUND')
                    if entry.filename=='recovery':target=home/'recovery'
                    elif re.fullmatch(r'pages/[0-9a-f]{64}\.page',entry.filename):target=pages/entry.filename.split('/')[1]
                    else:raise ValueError('BACKUP_ENTRY_NAME')
                    c.write_private(target,archive.read(entry))
                yield home/'recovery'
