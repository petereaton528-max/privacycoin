"""Local wallet safety facade. Frozen V1 crypto/ledger/backup formats unchanged.

No remote host option, key-image exchange, payment proofs or pruned mode.
Python secret copies cannot be reliably erased. Windows file I/O uses strict NTFS
ACLs; full native Windows desktop/runtime acceptance is a separate requirement.
"""
from pathlib import Path
from dataclasses import dataclass
from contextlib import contextmanager
import argparse, hashlib, importlib.util, json, os, signal, stat, sys, types, uuid
if os.name=='posix':import fcntl,resource
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('frozen_phase4_wallet',ROOT/'src/phase4/wallet.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
f=w.foundation
MAX_FILE=f.MAX_FILE
CACHE_KIND='phase6a-cache'
win=None
if os.name=='nt':
    _spec=importlib.util.spec_from_file_location('phase6a_windows_private',Path(__file__).with_name('windows_private.py'))
    win=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(win)

def harden():
    if win is not None:return win.harden()
    if os.name!='posix':raise ValueError('native POSIX required')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))

@contextmanager
def directory(path):
    """Walk without symlink following; forbid dot traversal and shared leaf dir."""
    if win is not None:
        with win.directory(path) as parent:yield parent
        return
    path=Path(path)
    if '..' in path.parts:raise ValueError('parent traversal rejected')
    path=path.absolute();fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=nxt
        s=os.fstat(fd)
        if s.st_uid!=os.getuid() or s.st_mode&0o077:raise ValueError('private directory required')
        yield fd
    finally:os.close(fd)

def checked(fd):
    if win is not None:
        import msvcrt
        win.checked(msvcrt.get_osfhandle(fd),MAX_FILE);return os.fstat(fd)
    s=os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077 or s.st_nlink!=1 or s.st_size>MAX_FILE:
        raise ValueError('private regular file required')
    return s

def read_private(path):
    if win is not None:return win.read_private(path,MAX_FILE)
    path=Path(path)
    with directory(path.parent) as parent:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            expected=checked(fd).st_size
            # Allocate for this checked regular file, not the entire 4MiB ceiling
            # for each small archived page. Growth/truncation fails closed.
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(expected+1)
            if len(raw)!=expected or len(raw)>MAX_FILE:raise ValueError('file changed or bound')
            return raw
        finally:os.close(fd)

def write_private(path,raw,replace=False,fault=None):
    """Encrypted bytes only; publish atomically in an existing 0700 directory."""
    if win is not None:return win.write_private(path,raw,replace,fault,MAX_FILE)
    if not isinstance(raw,bytes) or len(raw)>MAX_FILE:raise ValueError('write bound')
    path=Path(path)
    with directory(path.parent) as parent:
        try:
            fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:pass
        else:
            try:checked(fd)
            finally:os.close(fd)
            if not replace:raise ValueError('no overwrite')
        name='.pcwallet-'+uuid.uuid4().hex+'.tmp'
        fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw)
                if fault:fault('during_write')
                stream.flush();os.fsync(stream.fileno())
            if fault:fault('before_publish')
            if replace:os.replace(name,path.name,src_dir_fd=parent,dst_dir_fd=parent)
            else:
                os.link(name,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
                os.unlink(name,dir_fd=parent)
            os.fsync(parent)
            if fault:fault('after_publish')
        finally:
            try:os.unlink(name,dir_fd=parent)
            except FileNotFoundError:pass

@contextmanager
def lock(path):
    if win is not None:
        with win.lock(path):yield
        return
    path=Path(path)
    with directory(path.parent) as parent:
        fd=os.open(path.name+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
        try:
            checked(fd);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
        finally:os.close(fd)

def save(path,wallet,password,replace=False,fault=None):
    f.validate(wallet);write_private(path,f.seal(wallet,password,'wallet'),replace,fault)

def load(path,password):return f.validate(f.open_sealed(read_private(path),password,'wallet'))

def fingerprint(state):
    # Byte-identical to the original canonical JSON, streamed over disk history.
    digest=hashlib.sha256();digest.update(b'{')
    for n,key in enumerate(sorted(('chain','images','pool','pool_images','height','tip'))):
        if n:digest.update(b',')
        digest.update(f.canonical(key)+b':')
        if key=='chain':
            digest.update(b'[')
            for i,record in enumerate(state[key]):
                if i:digest.update(b',')
                digest.update(f.canonical(record))
            digest.update(b']')
        else:digest.update(f.canonical(state[key]))
    digest.update(b'}');return digest.hexdigest()

def snapshot(port):return w.snapshot(port,bounded=True)

def qualified(wallet,state,result,minimum_confirmations=10,stale=False):
    f.integer(minimum_confirmations,1,1024)
    balance=w.balance(wallet,state,result)
    full=wallet['authority']=='full'
    owned=[x for x in result['owned'] if not x['pending']]
    confirmed=[x for x in owned if state['height']-x['height']+1>=minimum_confirmations]
    balance.update(schema_version=1,profile=w.PROFILE,verification_scope='local ownership/amount checks; chain selection and completeness supplied by configured validating node',
        chain_trust='STALE_OR_ROLLBACK' if stale else 'TRUSTED_LOCAL_VALIDATING_ANCHOR',
        global_freshness='UNKNOWN',minimum_confirmations=minimum_confirmations,
        sufficient_confirmation_is='local policy, not finality',
        sufficiently_confirmed_unspent=sum(x['amount'] for x in confirmed if not x['spent']) if full and not stale else None,
        spent_status='KNOWN_RELATIVE_TO_CONFIGURED_CHAIN' if full and not stale else 'UNKNOWN',
        outgoing_status='KNOWN_RELATIVE_TO_CONFIGURED_CHAIN' if full and not stale else 'UNKNOWN',
        signing_available=full and not stale,observation_complete_relative_to_anchor=True,
        scan_progress=dict(records_processed=len(state['chain']),records_expected=len(state['chain']),complete=True))
    if not full or stale:
        balance['balance']=None;balance['spendable']=None
        balance['total_balance']=None;balance['unlocked_balance']=None
    if stale:
        balance['observation_complete_relative_to_anchor']=False
        balance['warning']='Node work/tip is behind or conflicts with saved observation; manual trusted-node reconciliation required'
    if not full:balance['warning']='Incoming viewing only; outgoing and spent status unavailable without separately authenticated information'
    return balance

def observe(wallet,port,previous=None,minimum_confirmations=10):
    state=snapshot(port);status=w.rpc(port,'status')
    if (state['height'],state['tip'])!=(status['height'],status['tip']):raise ValueError('snapshot changed')
    work=int(status['work'])
    stale=bool(previous and (work<previous['work'] or (work==previous['work'] and state['tip']!=previous['tip'])))
    result=w.scan(wallet,state)
    if result.get('undecodable_owned_outputs'):raise ValueError('incomplete ownership scan')
    final=snapshot(port)
    if fingerprint(state)!=fingerprint(final):raise ValueError('snapshot changed')
    return state,result,qualified(wallet,state,result,minimum_confirmations,stale),work

def cache_anchor(wallet,state,work):
    # Only the authenticated high-water anchor is consumed on restart. Full
    # ownership scans are always recomputed; persisting their growing output and
    # decoy lists needlessly exhausted the 4MiB private-file safety bound. Retain
    # the v1 schema (empty scan is already supported), bounds and old-cache reader.
    # Neither signing data nor payment intentions are discarded here.
    return dict(version=1,profile=w.PROFILE,wallet_id=f.wallet_id(wallet),
                tip=state['tip'],height=state['height'],work=work,scan={})

def read_cache(path,wallet,password):
    cache=f.open_sealed(read_private(path),password,CACHE_KIND)
    f.fields(cache,'version profile wallet_id tip height work scan')
    if type(cache['version']) is not int or cache['version']!=1 or cache['profile']!=w.PROFILE or cache['wallet_id']!=f.wallet_id(wallet):raise ValueError('cache identity')
    f.unhex(cache['tip'],32);f.integer(cache['height'],0,2**64-1);f.integer(cache['work'],1,2**256-1)
    if not isinstance(cache['scan'],dict):raise ValueError('cache schema')
    # Cached scan/balance is never used for balance or signing; always full rescan.
    return cache

@dataclass(frozen=True)
class Plan:
    payload:bytes
    def intent(self):return f.decode(self.payload)
    def display(self):
        q=self.intent()
        return {k:q[k] for k in ('destination','network','scheme','amount','fee','change','input_count','height','tip','max_fee')}

def prepare(wallet,state,destination,amount,fee,max_fee,scanned=None):
    if wallet['authority']!='full':raise ValueError('view-only cannot spend')
    f.integer(amount,1,2**64-1);f.integer(max_fee,1,10**12);f.parse_address(destination)
    result=scanned if scanned is not None else w.scan(wallet,state)
    if result.get('undecodable_owned_outputs'):raise ValueError('scan incomplete')
    available=[x for x in result['owned'] if not x['pending'] and not x['spent'] and not x['reserved'] and x['unlock']<=state['height']+1]
    if fee is not None:f.integer(fee,1,max_fee)
    sufficient=[x for x in available if x['amount']>amount+(fee if fee is not None else w.estimate_fee(1,2))]
    if sufficient:selected=[min(sufficient,key=lambda x:x['amount'])]
    else:
        selected=[]
        for x in sorted(available,key=lambda x:x['amount'],reverse=True):
            selected.append(x)
            if len(selected)>8:raise ValueError('input limit')
            if sum(y['amount'] for y in selected)>amount+(fee if fee is not None else w.estimate_fee(len(selected),2)):break
    cost=fee if fee is not None else w.estimate_fee(len(selected),2)
    f.integer(cost,1,max_fee)
    change=sum(x['amount'] for x in selected)-amount-cost
    if not selected or change<=0:raise ValueError('insufficient unlocked funds')
    if len(result['eligible'])<16:raise ValueError('anonymity readiness')
    return Plan(f.canonical(dict(destination=destination,network='privacycoin-devnet',scheme=1,amount=amount,fee=cost,max_fee=max_fee,change=change,
        sources=[x['global_index'] for x in selected],input_count=len(selected),height=state['height'],tip=state['tip'],state_fingerprint=fingerprint(state))))

def execute(wallet,plan,consent,get_state,submit):
    if wallet['authority']!='full':raise ValueError('view-only cannot spend')
    confirmed_payload=plan.payload
    if consent(plan.display()) is not True:raise ValueError('payment not confirmed')
    if plan.payload!=confirmed_payload:raise ValueError('plan changed during confirmation')
    q=plan.intent();state=get_state()
    if fingerprint(state)!=q['state_fingerprint']:raise ValueError('confirmed chain/pool changed')
    scanned=w.scan(wallet,state)
    expected=prepare(wallet,state,q['destination'],q['amount'],q['fee'],q['max_fee'],scanned)
    if expected.payload!=plan.payload:raise ValueError('confirmed plan changed')
    # Reuse the frozen constructor with the freshly validated scan, avoiding a
    # redundant scan. No shared module mutation and no primitive changes.
    build=types.FunctionType(w.build.__code__,dict(w.build.__globals__,scan=lambda *_:scanned),argdefs=w.build.__defaults__)
    payment=build(wallet,state,q['destination'],q['amount'],q['fee'],sources=q['sources'])
    if payment['fee']>q['max_fee'] or payment['selected_sources']!=q['sources']:raise ValueError('constructed plan mismatch')
    if sum(x['amount'] for x in payment['receipts'] if x['change'])!=q['change']:raise ValueError('change mismatch')
    if fingerprint(get_state())!=q['state_fingerprint']:raise ValueError('chain changed before broadcast')
    response=submit(payment)
    return dict(transaction_id=response['accepted'],bytes=payment['bytes'],fee=payment['fee'],submitted=True)

def restore_drill(wallet,backup,password,port,destination):
    original=load(wallet,password)
    restored=f.restore(f.open_sealed(read_private(backup),password,'recovery'))
    if f.wallet_id(original)!=f.wallet_id(restored):raise ValueError('backup belongs to another wallet')
    state=snapshot(port);a=w.scan(original,state);b=w.scan(restored,state)
    normalize=lambda r:r['owned']
    if normalize(a)!=normalize(b):raise ValueError('recovery scan mismatch')
    if fingerprint(snapshot(port))!=fingerprint(state):raise ValueError('chain changed')
    save(destination,restored,password)
    return dict(result='PASS',height=state['height'],tip=state['tip'],profile=w.PROFILE,
                scope='same configured local chain; no global freshness proof',report_contains_secrets=False)

def main():
    harden()
    p=argparse.ArgumentParser(description='Experimental local V1 wallet safety; full scan default')
    p.add_argument('command',choices=['create','open','startup','address','backup','restore','restore-drill','view-export','view-import','sync','rescan','balance','send'])
    p.add_argument('--wallet',type=Path,required=True);p.add_argument('--password-file',type=Path,required=True)
    p.add_argument('--file',type=Path);p.add_argument('--restore-wallet',type=Path);p.add_argument('--export-password-file',type=Path)
    p.add_argument('--rpc-port',type=int,default=48081);p.add_argument('--index',type=int,default=0)
    p.add_argument('--destination');p.add_argument('--amount',type=int);p.add_argument('--fee',type=int);p.add_argument('--max-fee',type=int)
    p.add_argument('--minimum-confirmations',type=int,default=10)
    args=p.parse_args();password=read_private(args.password_file).rstrip(b'\r\n')
    with lock(args.wallet):
        if args.command=='create':save(args.wallet,f.full(),password);print(json.dumps(dict(result='CREATED')));return
        if args.command in ('restore','view-import'):
            obj=f.open_sealed(read_private(args.file),password,'recovery' if args.command=='restore' else 'view')
            wallet=f.restore(obj) if args.command=='restore' else f.validate(obj)
            if args.command=='view-import' and wallet['authority']!='view':raise ValueError('authority mismatch')
            save(args.wallet,wallet,password);print(json.dumps(dict(result='RESTORED',requires_full_rescan=True)));return
        wallet=load(args.wallet,password)
        if args.command in ('open','startup'):print(json.dumps(dict(authority=wallet['authority'],balance=None,requires_full_rescan=True)));return
        if args.command=='address':
            f.integer(args.index,0,9999);wallet['count']=max(wallet['count'],args.index+1)
            save(args.wallet,wallet,password,True);print(json.dumps(dict(address=f.address(wallet,args.index),index=args.index)));return
        if args.command=='backup':write_private(args.file,f.seal(f.recovery(wallet),password,'recovery'));print(json.dumps(dict(result='BACKUP_CREATED')));return
        if args.command=='view-export':
            vp=read_private(args.export_password_file).rstrip(b'\r\n')
            if vp==password:raise ValueError('separate view password required')
            write_private(args.file,f.seal(f.view_export(wallet),vp,'view'));print(json.dumps(dict(result='INCOMING_VIEW_EXPORTED',spent_status='UNKNOWN')));return
        if args.command=='restore-drill':print(json.dumps(restore_drill(args.wallet,args.file,password,args.rpc_port,args.restore_wallet)));return
        cachepath=Path(str(args.wallet)+'.phase6a-cache')
        try:previous=read_cache(cachepath,wallet,password)
        except FileNotFoundError:previous=None
        state,result,balance,work=observe(wallet,args.rpc_port,previous,args.minimum_confirmations)
        if balance['chain_trust']=='STALE_OR_ROLLBACK':print(json.dumps(balance));return
        cache=cache_anchor(wallet,state,work)
        write_private(cachepath,f.seal(cache,password,CACHE_KIND),replace=True)
        if args.command=='send':
            plan=prepare(wallet,state,args.destination,args.amount,args.fee,args.max_fee,result)
            def consent(display):
                print(json.dumps(dict(payment_confirmation=display)),flush=True)
                return input('Type CONFIRM to sign and broadcast: ')=='CONFIRM'
            balance=execute(wallet,plan,consent,lambda:snapshot(args.rpc_port),lambda tx:w.rpc(args.rpc_port,'submit_tx',transaction=tx['transaction']))
        print(json.dumps(balance))
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):
        print('Local wallet operation rejected; no verified result. Check credentials, format, authority, private paths and node state.',file=sys.stderr);sys.exit(1)
