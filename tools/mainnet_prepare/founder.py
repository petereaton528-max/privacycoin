"""Owner-operated, offline, pre-Genesis key custody. No node/Genesis/address API.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,getpass,hashlib,json,os,platform,resource,secrets,stat,sys
from contextlib import contextmanager
from pathlib import Path
from src.wallet import wallet as f
from tools.creator_model.binding import DraftBinding
from .binding import approved,APPROVED_IDENTITY_SHA256,IDENTITY
ROOT=Path(__file__).resolve().parents[2]
FORMAT='PC_FOUNDER_PREGENESIS_V1'

def context():
    approved();spec=json.loads(IDENTITY.read_text())
    return spec['resolved_policy']['wallet_network_tag']

def kind():return 'PrivacyCoin/Mainnet/V1/founder-pre-genesis/v1/'+APPROVED_IDENTITY_SHA256+'/'+context()

def keys(master):
    # G is deliberately absent from child-key derivation. This internal sentinel
    # is never serialized, displayed as an address or accepted as Genesis.
    b=DraftBinding(f,context(),'a'*64);w=b.wallet(master)
    D,C,sub=b.parse(b.address(w,0))
    if sub:raise ValueError('PRIMARY_RECIPIENT_REQUIRED')
    return w,dict(public_spend=D,public_view=C)

def directory(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or str(path).startswith('/mnt/') or path==ROOT or ROOT in path.parents:
        raise ValueError('PRIVATE_NATIVE_PATH_OUTSIDE_PACKAGE_REQUIRED')
    for item in (path,*path.parents):
        if item.is_symlink():raise ValueError('SYMLINK_PATH_REJECTED')
        if (item/'.git').exists() or (item/'.phase0-git').exists():raise ValueError('REPOSITORY_DESTINATION_REJECTED')
    s=path.stat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077:raise ValueError('OWNER_ONLY_DIRECTORY_0700_REQUIRED')
    return path

@contextmanager
def private_directory(path):
    path=directory(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt
        s=os.fstat(fd)
        if s.st_uid!=os.getuid() or s.st_mode&0o077:raise ValueError('PRIVATE_DIRECTORY_REQUIRED')
        yield fd
    finally:os.close(fd)

def read(path):
    path=Path(path)
    with private_directory(path.parent) as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077 or s.st_nlink!=1 or s.st_size>f.MAX_FILE:raise ValueError('PRIVATE_REGULAR_FILE_REQUIRED')
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(s.st_size+1)
            if len(raw)!=s.st_size:raise ValueError('FILE_CHANGED')
            return raw
        finally:os.close(fd)

def write(path,raw):
    path=Path(path)
    if not isinstance(raw,bytes) or len(raw)>f.MAX_FILE:raise ValueError('FILE_BOUND')
    with private_directory(path.parent) as parent:
        name='.encrypted-'+secrets.token_hex(16)+'.tmp'
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.link(name,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
            os.unlink(name,dir_fd=parent);os.fsync(parent)
        finally:
            try:os.unlink(name,dir_fd=parent)
            except FileNotFoundError:pass

def validate(payload):
    f.fields(payload,'format specification_sha256 network_tag stage master_seed count public purpose')
    if (payload['format'],payload['specification_sha256'],payload['network_tag'],payload['stage'])!=(FORMAT,APPROVED_IDENTITY_SHA256,context(),'PRE_GENESIS'):
        raise ValueError('FOUNDER_IDENTITY_OR_STAGE_MISMATCH')
    if type(payload['count']) is not int or payload['count']!=2 or payload['purpose'] not in ('OWNER','DISPOSABLE_TEST'):raise ValueError('FOUNDER_FORMAT')
    _,public=keys(payload['master_seed'])
    if payload['public']!=public:raise ValueError('RECOVERED_PUBLIC_KEYS_MISMATCH')
    return payload

def public(payload):
    return dict(format='PC_FOUNDER_PUBLIC_RECIPIENT_REVIEW_V1',specification_sha256=APPROVED_IDENTITY_SHA256,network_tag=context(),**payload['public'],subaddress=False,genesis=None,receiving_address=None,recipient_approved=False,purpose=payload['purpose'])

def decrypt(path,password):return validate(f.open_sealed(read(path),password,kind()))

def publish(profile,payload,password):
    profile=Path(profile);directory(profile.parent)
    if profile.exists() or profile.is_symlink():raise ValueError('FRESH_PROFILE_REQUIRED')
    raw=f.seal(validate(payload),password,kind())
    if f.open_sealed(raw,password,kind())!=payload:raise ValueError('ENCRYPTION_READBACK_FAILED')
    with private_directory(profile.parent) as parent:
        os.mkdir(profile.name,mode=0o700,dir_fd=parent);os.fsync(parent)
    # Incomplete profiles are preserved, never silently reused after a failure.
    write(profile/'founder.encrypted',raw)
    if decrypt(profile/'founder.encrypted',password)!=payload:raise ValueError('PERSISTED_RECOVERY_MISMATCH')
    write(profile/'PUBLIC-RECIPIENT.json',f.canonical(public(payload)))
    return public(payload)

def create(profile,password,*,purpose):
    if purpose not in ('OWNER','DISPOSABLE_TEST'):raise ValueError('EXPLICIT_PURPOSE_REQUIRED')
    if not isinstance(password,bytes) or not 20<=len(password)<=1024:raise ValueError('PASSWORD_MINIMUM_20_BYTES')
    directory(Path(profile).parent)
    if Path(profile).exists():raise ValueError('FRESH_PROFILE_REQUIRED')
    master=secrets.token_hex(32);_,recipient=keys(master)
    return publish(profile,dict(format=FORMAT,specification_sha256=APPROVED_IDENTITY_SHA256,network_tag=context(),stage='PRE_GENESIS',master_seed=master,count=2,public=recipient,purpose=purpose),password)

def backup(profile,destination,password):
    payload=decrypt(Path(profile)/'founder.encrypted',password)
    raw=f.seal(payload,password,kind());write(destination,raw)
    if decrypt(destination,password)!=payload:raise ValueError('BACKUP_READBACK_FAILED')
    return hashlib.sha256(raw).hexdigest()

def recover(source,profile,password):return publish(profile,decrypt(source,password),password)

def integrity():
    manifest=ROOT/'FOUNDER_MANIFEST.json'
    if not manifest.is_file() or manifest.is_symlink():raise ValueError('INSTALLED_FOUNDER_PACKAGE_REQUIRED')
    record=json.loads(manifest.read_text())
    for name,expected in record['files'].items():
        if not isinstance(name,str) or Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('PACKAGE_PATH')
        p=ROOT/name
        if any(x.is_symlink() for x in (p,*p.parents)) or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise ValueError('PACKAGE_INTEGRITY_FAILED')
    approved()
    if platform.system()!='Linux' or platform.machine()!='x86_64':raise ValueError('LINUX_X86_64_REQUIRED')
    if f.crypto('check','58'+'66'*31)!=['valid']:raise ValueError('NATIVE_CRYPTO_SELF_CHECK')
    return dict(status='PASS',specification_sha256=APPROVED_IDENTITY_SHA256,source_commit=record['source_commit'],files_verified=len(record['files']),platform='Linux x86-64',native_public_point_check='PASS',services_started=False,network_probe_performed=False,offline_status='OWNER_MUST_VERIFY_HOST_DISCONNECTION')

def password(confirm=False):
    if not sys.stdin.isatty() or not sys.stderr.isatty():raise ValueError('LOCAL_INTERACTIVE_TERMINAL_REQUIRED')
    first=getpass.getpass('Wallet encryption password (hidden): ').encode()
    if not 20<=len(first)<=1024:raise ValueError('PASSWORD_MINIMUM_20_BYTES')
    if confirm and first!=getpass.getpass('Repeat password (hidden): ').encode():raise ValueError('PASSWORDS_DIFFER')
    return first

def main():
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if os.name!='posix' or os.getuid()==0:raise ValueError('UNPRIVILEGED_LINUX_REQUIRED')
    p=argparse.ArgumentParser(description='Offline founder pre-Genesis custody; never prints private keys. No node or Genesis operation.')
    p.add_argument('action',choices=['preflight','create','backup','recover','verify'])
    p.add_argument('--profile',type=Path);p.add_argument('--file',type=Path);p.add_argument('--private-parent',type=Path);p.add_argument('--offline-confirmed',action='store_true');a=p.parse_args()
    verified=integrity()
    if a.action=='preflight':
        if a.private_parent:directory(a.private_parent)
        print(json.dumps(verified));return
    if not a.offline_confirmed:raise ValueError('OWNER_OFFLINE_ATTESTATION_REQUIRED')
    if a.action=='create':
        if not a.profile:p.error('--profile required')
        secret=password(True)
        if input('Type CREATE OWNER FOUNDER WALLET OFFLINE to proceed: ')!='CREATE OWNER FOUNDER WALLET OFFLINE':raise ValueError('CREATION_NOT_CONFIRMED')
        result=create(a.profile,secret,purpose='OWNER')
    elif a.action=='backup':
        if not a.profile or not a.file:p.error('--profile and --file required')
        result=dict(status='BACKUP_VERIFIED',sha256=backup(a.profile,a.file,password()))
    elif a.action=='recover':
        if not a.profile or not a.file:p.error('--profile and --file required')
        result=recover(a.file,a.profile,password())
    else:
        if not a.file:p.error('--file required')
        result=dict(status='RECOVERY_VERIFIED',sha256=hashlib.sha256(read(a.file)).hexdigest(),public=public(decrypt(a.file,password())))
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):
        # Library/native exceptions may contain sensitive values: never echo them.
        print('Operation stopped. No overwrite or automatic retry. Check private-directory permissions, package integrity, password and complete original backup. Preserve any partial profile; use a fresh destination.',file=sys.stderr)
        raise SystemExit(1)
