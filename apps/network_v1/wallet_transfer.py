"""Explicit encrypted recovery transfer. No network, spending or plaintext export."""
import os
from pathlib import Path
from .rpc import NETWORK, GENESIS, PROFILE

KIND='network-v1-portable-recovery'

def path(value):
    p=Path(value)
    if not p.is_absolute() or '..' in p.parts or any('privacycoin-n2' in part.lower() for part in p.parts):
        raise ValueError('PRIVATE_NON_N2_PATH_REQUIRED')
    return p

def validate(c,wallet,journal,cache):
    from backend import validate_journal
    f=c.f;f.validate(wallet);validate_journal(journal,wallet)
    if cache is not None:
        f.fields(cache,'version profile wallet_id tip height work scan')
        if type(cache['version']) is not int or cache['version']!=1 or cache['profile']!=PROFILE or cache['wallet_id']!=f.wallet_id(wallet):raise ValueError('RECOVERY_CACHE_IDENTITY')
        f.unhex(cache['tip'],32);f.integer(cache['height'],0,2**64-1);f.integer(cache['work'],1,2**256-1)
        if not isinstance(cache['scan'],dict):raise ValueError('RECOVERY_CACHE_SCHEMA')

def export(session,destination):
    c=session_module(session);f=c.f
    if not session.wallet:raise ValueError('OPEN_WALLET_REQUIRED')
    validate(c,session.wallet,session.journal,session.previous)
    target=path(destination);archive=Path(str(target)+'.journal-archive')
    if os.path.lexists(target) or os.path.lexists(archive):raise ValueError('NEW_RECOVERY_DESTINATION_REQUIRED')
    value=dict(version=2 if session.journal['version']==2 else 1,network=NETWORK,genesis=GENESIS,profile=PROFILE,
               recovery=f.recovery(session.wallet),journal=session.journal,cache=session.previous)
    raw=f.seal(value,session.password,KIND)
    # Validate the actual encrypted artifact before publishing it.
    decoded=f.open_sealed(raw,session.password,KIND)
    restored=f.restore(decoded['recovery']);validate(c,restored,decoded['journal'],decoded['cache'])
    session.store().copy_to(session.journal,archive)
    c.write_private(target,raw)
    return dict(exported=True,encrypted=True,contains_submission_journal=True,
                off_device_copy_verified=False,warning='Keep the encrypted file AND any adjacent .journal-archive directory together; keep the password separately. A same-device copy is not a disaster-recovery backup.')

def session_module(session):
    # Resolve the same reviewed key/file implementation used by Session.
    import backend
    return backend.c

def import_wallet(session,source,name,password,format,consent):
    if consent!='IMPORT SAME TESTNET WALLET':raise ValueError('IMPORT_CONSENT_REQUIRED')
    if not isinstance(password,str) or not 12<=len(password)<=1024:raise ValueError('PASSWORD_LENGTH')
    c=session_module(session);f=c.f;source=path(source);secret=password.encode()
    if format=='portable':
        value=f.open_sealed(c.read_private(source),secret,KIND)
        f.fields(value,'version network genesis profile recovery journal cache')
        if type(value['version']) is not int or value['version'] not in (1,2) or (value['network'],value['genesis'],value['profile'])!=(NETWORK,GENESIS,PROFILE):raise ValueError('RECOVERY_NETWORK')
        wallet=f.restore(value['recovery']);journal=value['journal'];cache=value['cache']
        if value['version']==1 and journal.get('version')!=1:raise ValueError('RECOVERY_JOURNAL_VERSION')
        archive_source=Path(str(source)+'.journal-archive')
    elif format=='backup-v1':
        from backend import recovery_bundle
        wallet,value=recovery_bundle(source,secret);journal=value['journal'];cache=value['cache']
        archive_source=Path(str(source)+'.journal-archive')
        if cache is None:raise ValueError('LEGACY_PROFILE_ANCHOR_REQUIRED_USE_PORTABLE_EXPORT')
    elif format=='wallet-v1':
        # Raw wallet alone cannot prove absence of an unknown submission. Require
        # authenticated sidecars and lock the source against another local Session.
        with c.lock(source):
            wallet=c.load(source,secret)
            journal=f.open_sealed(c.read_private(Path(str(source)+'.gui-state')),secret,'gui-pilot-state')
            cache=c.read_cache(Path(str(source)+'.phase6a-cache'),wallet,secret)
            archive_source=Path(str(source)+'.gui-archive')
    else:raise ValueError('RECOVERY_FORMAT')
    validate(c,wallet,journal,cache)
    from backend import j,validate_journal
    store=j.Store(c,f,wallet,secret,archive_source,validate_journal)
    for _ in store.pages(journal):pass
    destination=session.path(name);jp=Path(str(destination)+'.gui-state');cp=Path(str(destination)+'.phase6a-cache')
    archive_destination=Path(str(destination)+'.gui-archive')
    # Prepare everything before modifying the new alias. Publish authority last.
    sealed_journal=f.seal(journal,secret,'gui-pilot-state')
    sealed_cache=f.seal(cache,secret,c.CACHE_KIND) if cache is not None else None
    sealed_wallet=f.seal(wallet,secret,'wallet')
    with c.lock(destination):
        if any(os.path.lexists(p) for p in (destination,jp,cp,archive_destination)):raise ValueError('NEW_ALIAS_REQUIRED_OR_INTERRUPTED_IMPORT')
        store.copy_to(journal,archive_destination)
        c.write_private(jp,sealed_journal)
        if sealed_cache is not None:c.write_private(cp,sealed_cache)
        c.write_private(destination,sealed_wallet)
    return session.unlock(destination,secret)
