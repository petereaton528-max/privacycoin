"""Bounded discovery from explicit operator bootstrap manifests, no public scan.

Does not start Tor or connect. V1 descriptors are public Onion/TLS identities;
they require no N2 enrollment. Neither seed catalogs nor gossip authorize chain
state. Historical mutually authenticated N2 service channels remain separate.
"""
import os,re,stat
from pathlib import Path

from .rpc import GENESIS, NETWORK, PROFILE

def read_catalog(path):
    """Bounded PUBLIC package metadata; never a wallet/config secret reader."""
    path=Path(path)
    if not path.is_absolute():raise ValueError('BOOTSTRAP_PATH')
    if os.name=='nt':
        from src.phase6a import windows_private as private
        with private.directory(path.parent,require_private=False):
            handle=private.opened(path,0x80000000,3)
            try:
                info=private.information(handle);size=(info.size_high<<32)|info.size_low
                if info.attributes&0x10 or info.links!=1 or size>16384:raise ValueError('BOOTSTRAP_BOUND_OR_TYPE')
                buffer=private.C.create_string_buffer(size+1);count=private.DWORD()
                if not private.read(handle,buffer,size+1,private.C.byref(count),None) or count.value!=size:raise ValueError('BOOTSTRAP_CHANGED')
                return buffer.raw[:size]
            finally:private.close(handle)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):raise ValueError('BOOTSTRAP_LINK')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>16384:raise ValueError('BOOTSTRAP_BOUND_OR_TYPE')
        raw=os.read(fd,16385)
        if len(raw)!=info.st_size:raise ValueError('BOOTSTRAP_CHANGED')
        return raw
    finally:os.close(fd)

def initial_peers(path,read,decode):
    """Reviewed package seed hints for a NEW profile only; never connects.

    An empty shipped list means no operational seeds, not a working network.
    Missing legacy catalogs are supported; malformed present data fails closed.
    """
    try:raw=read(path)
    except FileNotFoundError:return []
    if len(raw)>16384:raise ValueError('BOOTSTRAP_BOUND')
    catalogs=decode(raw)
    if catalogs==[]:return []
    return bootstrap(catalogs)


def bootstrap(manifests, current=()):
    """Merge reviewed, replaceable public seed catalogs; never connect here.

    Neither a seed nor a certificate pin can authorize chain state. Conflicting
    identities require an explicit operator decision, never last-writer wins.
    """
    from .onion import descriptor
    if not isinstance(manifests,list) or not 1<=len(manifests)<=8:raise ValueError('BOOTSTRAP_BOUND')
    if not isinstance(current,(list,tuple)) or len(current)>8:raise ValueError('PEER_BOUND')
    found={}
    def add(value):
        value=descriptor(value);prior=found.get(value['onion'])
        if prior and prior!=value:raise ValueError('PEER_PIN_CONFLICT')
        found[value['onion']]=dict(value)
        if len(found)>8:raise ValueError('PEER_BOUND')
    for value in current:add(value)
    for catalog in manifests:
        if not isinstance(catalog,dict) or set(catalog)!={'version','network','genesis','profile','peers'} or type(catalog['version']) is not int or catalog['version']!=1 or (catalog['network'],catalog['genesis'],catalog['profile'])!=(NETWORK,GENESIS,PROFILE):raise ValueError('BOOTSTRAP_NETWORK')
        if not isinstance(catalog['peers'],list) or len(catalog['peers'])>8:raise ValueError('PEER_BOUND')
        for value in catalog['peers']:add(value)
    return list(found.values())


def discover(manifests):
    found = {}
    if not isinstance(manifests, list) or len(manifests) > 8:
        raise ValueError('BOOTSTRAP_BOUND')
    for m in manifests:
        if not isinstance(m, dict) or set(m) != {'version','network','genesis','profile','peers'} or m['version'] != 1 or (m['network'],m['genesis'],m['profile']) != (NETWORK,GENESIS,PROFILE):
            raise ValueError('BOOTSTRAP_NETWORK')
        if not isinstance(m['peers'], list) or len(m['peers']) > 8:
            raise ValueError('PEER_BOUND')
        for p in m['peers']:
            if not isinstance(p, dict) or set(p) != {'onion','p2p_cert_sha256'} or not isinstance(p['onion'], str) or not re.fullmatch(r'[a-z2-7]{56}\.onion', p['onion']) or not isinstance(p['p2p_cert_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', p['p2p_cert_sha256']):
                raise ValueError('ONION_AND_PIN_REQUIRED')
            # Full v3 checksum and TLS validity still checked by existing N2 tools
            # before activation; this method only bounds discovery candidates.
            prior = found.get(p['onion'])
            if prior and prior != p:
                raise ValueError('PEER_PIN_CONFLICT')
            found[p['onion']] = dict(p)
            if len(found) > 8:
                raise ValueError('NATIVE_MAX_EIGHT_PEERS')
    return list(found.values())
