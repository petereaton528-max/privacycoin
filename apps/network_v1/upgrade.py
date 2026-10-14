"""Compatible same-native-binary update preflight. No database/wallet migration."""
import hashlib
import os
from pathlib import Path
import stat
from .rpc import GENESIS,NETWORK,PROFILE,VERSION
from .wallet_transfer import path

BINARIES=tuple('build/monero-windows/'+phase+'/'+name+'.exe' for phase,name in [('phase4','privacycoin-hardened-devnet'),('phase4','privacycoin-hardened-crypto'),('phase2','privacycoin-wallet-crypto')]) if os.name=='nt' else ('build/monero-linux/phase4/privacycoin-hardened-devnet','build/monero-linux/phase4/privacycoin-hardened-crypto','build/monero-linux/phase2/privacycoin-wallet-crypto')

def digest(c,value):
    value=path(value)
    if os.name=='nt':return hashlib.sha256(c.win.read_private(value,limit=64*1024*1024)).hexdigest()
    with c.directory(value.parent) as parent:
        fd=os.open(value.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077 or s.st_nlink!=1 or s.st_size>64*1024*1024:raise ValueError('PRIVATE_PROGRAM_FILE_REQUIRED')
            result=hashlib.sha256()
            with os.fdopen(fd,'rb',closefd=False) as stream:
                for block in iter(lambda:stream.read(1024*1024),b''):result.update(block)
            return result.hexdigest()
        finally:os.close(fd)

def compatible(old_root,new_root,data):
    from backend import c,f
    roots=(path(old_root),path(new_root));data=path(data)
    values=[]
    for root in roots:
        marker=f.decode(c.read_private(root/'INSTALL_COMPLETE.json'))
        m=f.decode(c.read_private(root/'V1_MANIFEST.json'))
        kinds=('windows-native-x86_64',) if os.name=='nt' else ('linux-x86_64','windows-wsl2-x86_64')
        if m.get('format')!=1 or (m.get('network'),m.get('genesis'),m.get('profile'))!=(NETWORK,GENESIS,PROFILE) or m.get('kind') not in kinds or marker.get('version')!=m.get('version') or marker.get('kind')!=m.get('kind'):raise ValueError('INSTALLED_NETWORK_IDENTITY_REQUIRED')
        hashes={name:digest(c,root/name) for name in BINARIES}
        if any(m['files'].get(n)!=v for n,v in hashes.items()):raise ValueError('PROGRAM_HASH_MISMATCH')
        values.append((m,hashes))
    if values[1][0]['version']!=VERSION:raise ValueError('TARGET_VERSION_REQUIRED')
    if values[0][1]!=values[1][1]:raise ValueError('BINARY_CHANGE_REQUIRES_REVIEWED_MIGRATION_NOT_SUPPORTED')
    # The old application must be closed. OS lock acquisition is authoritative,
    # not PID reuse or a listening-port inference. Never delete its lock files.
    with c.lock(data/'desktop'):
        marker=f.decode(c.read_private(data/'PRODUCT_V1.json'))
        f.fields(marker,'version role rpc p2p'+(' network profile' if NETWORK=='PrivacyCoinDev02' else ''))
        if NETWORK=='PrivacyCoinDev02' and (marker['network'],marker['profile'])!=(NETWORK,PROFILE):raise ValueError('V1_DATA_NETWORK_IDENTITY_REQUIRED')
        if type(marker['version']) is not int or marker['version']!=1 or marker['role']!='ISOLATED_V1_DESKTOP':raise ValueError('V1_DATA_IDENTITY_REQUIRED')
        rpc=marker['rpc'];p2p=marker['p2p']
        if type(rpc) is not int or not 1024<=rpc<=65490 or type(p2p) is not int or not 1024<=p2p<=65535 or p2p in {rpc-1,rpc,*range(rpc+3,rpc+18)}:raise ValueError('DATA_PORTS')
        with c.directory(data/'wallets'):pass
        chain=data/'chain'
        if chain.exists():
            with c.lock(chain/'supervisor'):
                identity=f.decode(c.read_private(chain/'V1_OWNED_DATA.json'))
                expected=dict(version=1,profile=PROFILE,genesis=GENESIS,binary_sha256=values[1][1][BINARIES[0]])
                if identity!=expected:raise ValueError('CHAIN_MARKER_MISMATCH')
    return dict(compatible=True,from_version=values[0][0]['version'],to_version=VERSION,rpc=marker['rpc'],p2p=marker['p2p'],data=str(data),migration_performed=False,
                warning='Same native binaries and network only. Preserve the previous installation and a current encrypted recovery backup. No wallet or database was copied or rewritten.')
