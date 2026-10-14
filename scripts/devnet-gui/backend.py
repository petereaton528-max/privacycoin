"""Explicitly invoked disposable-devnet adapter. No HTTP listener or secret logging."""
from pathlib import Path
import argparse, importlib.util, json, os, re, secrets, sqlite3, sys, time
from collections import deque
from contextlib import closing

SOURCE = Path(__file__).resolve().parents[2]
# Non-secret deployment path only. Historical launchers retain their exact default.
NATIVE = Path(os.environ.get('PC_DEVNET_NATIVE_ROOT', str(SOURCE) if os.name=='nt' else '/home/privacydev/privacycoin-dev/Privacy_Coin'))
if not NATIVE.is_absolute() or '..' in NATIVE.parts:
    raise ValueError('absolute native source root required')

def native(name, relative):
    for rel in ('src/phase6a/wallet.py', 'src/phase4/wallet.py', 'src/phase3/wallet.py', 'src/wallet/wallet.py'):
        if (SOURCE/rel).read_bytes().replace(b'\r\n', b'\n') != (NATIVE/rel).read_bytes().replace(b'\r\n', b'\n'):
            raise ValueError('native source mismatch')
    spec = importlib.util.spec_from_file_location(name, NATIVE/relative)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

c = native('gui_wallet', 'src/phase6a/wallet.py'); f = c.f; w = c.w
DEFAULT_HOME = Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'PrivacyCoinV1-testnet' if os.name=='nt' else Path.home()/'.local/share/privacycoin-devnet-gui'
_spec=importlib.util.spec_from_file_location('gui_journal_store',Path(__file__).with_name('journal.py'))
j=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(j)

def validate_journal(journal,wallet):
    if type(journal.get('version')) is not int or journal['version'] not in (1,2):raise ValueError('journal version')
    f.fields(journal,'version wallet_id attempts'+(' archives' if journal['version']==2 else ''))
    if journal['wallet_id']!=f.wallet_id(wallet):raise ValueError('journal identity')
    if journal['version']==2:
        refs=journal['archives']
        if not isinstance(refs,list) or len(refs)>j.MAX_PAGES or len(set(refs))!=len(refs):raise ValueError('journal archive bound')
        for digest in refs:f.unhex(digest,32)
    if not isinstance(journal['attempts'],list) or len(journal['attempts'])>128:raise ValueError('journal bound')
    tokens=set()
    for a in journal['attempts']:
        f.fields(a,'token status transaction_id destination amount fee created')
        if a['status'] not in ('UNKNOWN','SUBMITTED','PENDING','CONFIRMED'):raise ValueError('attempt state')
        f.unhex(a['token'],32)
        if a['token'] in tokens:raise ValueError('duplicate attempt')
        tokens.add(a['token']);f.integer(a['created'],0,2**63-1)
        if a['transaction_id'] is not None:f.unhex(a['transaction_id'],32)
        f.parse_address(a['destination']);f.integer(a['amount'],1,2**64-1);f.integer(a['fee'],1,10**12)
    return journal

def recovery_bundle(path,password):
    bundle=f.open_sealed(c.read_private(path),password,'gui-pilot-backup')
    f.fields(bundle,'version recovery journal cache')
    if type(bundle['version']) is not int or bundle['version'] not in (1,2):raise ValueError('backup version')
    wallet=f.restore(bundle['recovery']);validate_journal(bundle['journal'],wallet)
    if bundle['version']==1 and bundle['journal']['version']!=1:raise ValueError('backup journal version')
    store=j.Store(c,f,wallet,password,Path(str(path)+'.journal-archive'),validate_journal)
    for _ in store.pages(bundle['journal']):pass
    if bundle['cache'] is not None:
        cache=bundle['cache'];f.fields(cache,'version profile wallet_id tip height work scan')
        if type(cache['version']) is not int or cache['version']!=1 or cache['profile']!=w.PROFILE or cache['wallet_id']!=f.wallet_id(wallet):raise ValueError('cache identity')
        f.unhex(cache['tip'],32);f.integer(cache['height'],0,2**64-1);f.integer(cache['work'],1,2**256-1)
        if not isinstance(cache['scan'],dict):raise ValueError('cache schema')
    return wallet,bundle

class Session:
    def __init__(self, home=DEFAULT_HOME, port=48081):
        c.harden(); self.home = Path(home)
        if os.name=='nt':c.win.mkdir(self.home)
        else:self.home.mkdir(parents=True,mode=0o700,exist_ok=True)
        with c.directory(self.home): pass
        self.port = self.check_port(port); self.wallet = None; self.guard = None; self.plan = None
    @staticmethod
    def check_port(port):
        f.integer(port, 1024, 65535); return port
    def path(self, name, suffix='.wallet'):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', name): raise ValueError('name')
        return self.home/(name+suffix)
    def close(self):
        self.plan = None; self.wallet = None
        self.password = None
        if self.guard: self.guard.__exit__(None, None, None); self.guard = None
    def persist(self):
        c.write_private(self.journal_path, f.seal(self.journal, self.password, 'gui-pilot-state'), replace=True)
    def store(self):return j.Store(c,f,self.wallet,self.password,Path(str(self.file)+'.gui-archive'),validate_journal)
    def reconcile(self,state,stale=False):
        # Chain membership is disk-indexed once. Never materialize an ever-growing
        # archived journal or all chain identifiers in Python memory.
        recent=deque(maxlen=128);unknown=0;total=0
        with closing(sqlite3.connect('')) as db:
            db.execute('PRAGMA cache_size=-1024');db.execute('CREATE TABLE seen(id TEXT PRIMARY KEY) WITHOUT ROWID')
            db.executemany('INSERT OR IGNORE INTO seen VALUES(?)',((x['id'],) for x in state['chain'] if not x.get('pending')))
            pool={x['id'] for x in state['pool']}
            store=self.store() if hasattr(self,'file') else None
            attempts=store.attempts(self.journal) if store else iter(self.journal['attempts'])
            active={a['token']:a for a in self.journal['attempts']}
            for attempt in attempts:
                txid=attempt['transaction_id']
                status='UNKNOWN' if stale else 'CONFIRMED' if txid and db.execute('SELECT 1 FROM seen WHERE id=?',(txid,)).fetchone() else 'PENDING' if txid in pool else 'UNKNOWN'
                if attempt['token'] in active and not stale:active[attempt['token']]['status']=status
                recent.append(dict({k:v for k,v in attempt.items() if k!='token'},status=status));unknown+=status=='UNKNOWN';total+=1
        if not stale:self.persist()
        return list(recent),unknown,total
    def unlock(self, path, password):
        self.close()
        guard = c.lock(path); guard.__enter__()
        try:
            wallet = c.load(path, password)
            jp = Path(str(path)+'.gui-state')
            try: journal = f.open_sealed(c.read_private(jp), password, 'gui-pilot-state')
            except FileNotFoundError:
                if os.path.lexists(Path(str(path)+'.gui-archive')):raise ValueError('missing journal root')
                journal = dict(version=1, wallet_id=f.wallet_id(wallet), attempts=[])
            validate_journal(journal,wallet)
            for _ in j.Store(c,f,wallet,password,Path(str(path)+'.gui-archive'),validate_journal).pages(journal):pass
            self.wallet = wallet; self.password = password; self.file = path
            self.guard = guard; self.journal_path = jp; self.journal = journal
            self.previous = None
            try: self.previous = c.read_cache(Path(str(path)+'.phase6a-cache'),wallet,password)
            except FileNotFoundError: pass
            return dict(address=f.address(wallet,0), authority=wallet['authority'], path=str(path), balance=None)
        except Exception:
            guard.__exit__(None, None, None); self.wallet = None; self.guard = None; self.password = None
            raise
    def observation(self):
        state, scan, balance, work = c.observe(self.wallet, self.port, self.previous)
        if balance['chain_trust'] != 'STALE_OR_ROLLBACK' and work > 0:
            # Frozen Phase 6A cache requires positive cumulative work. Genesis
            # has work zero; observe it, but never publish an unreadable cache.
            previous = c.cache_anchor(self.wallet,state,work)
            c.write_private(Path(str(self.file)+'.phase6a-cache'),f.seal(previous,self.password,c.CACHE_KIND),replace=True)
            self.previous = previous
        return state, scan, balance, work
    def refresh(self,offset=0):
        f.integer(offset,0,2**64-1)
        self.plan = None
        state, scan, balance, work = self.observation()
        # Reconcile only against a fresh, consistent local anchor. Missing evidence
        # never proves non-submission or authorizes a replacement payment.
        outgoing,unknown,outgoing_total=self.reconcile(state,balance['chain_trust']=='STALE_OR_ROLLBACK')
        total=len(scan['owned']);offset=min(offset,max(total-1,0)//100*100);end=max(0,total-offset)
        history = [dict(transaction_id=x['transaction'],amount=x['amount'],status='PENDING' if x['pending'] else 'IMMATURE' if x['coinbase'] and x['unlock']>state['height']+1 else 'LOCKED' if x['unlock']>state['height']+1 else 'CHAIN_OBSERVED',coinbase=x['coinbase'],spent=x['spent'],height=x['height']) for x in scan['owned'][max(0,end-100):end]]
        if balance['chain_trust']=='STALE_OR_ROLLBACK':
            for item in history:item['status']='UNVERIFIED';item['spent']=None
            for item in outgoing:item['status']='UNKNOWN'
        if unknown:
            balance['spendable']=None;balance['signing_available']=False
            balance['warning']=(balance.get('warning','')+' Unresolved submission may reserve funds outside this node observation. Reconcile original journal; no replacement signing.').strip()
        return dict(balance=balance, node=dict(height=state['height'],tip=state['tip'],work=work,endpoint='127.0.0.1:'+str(self.port),sync='FULL_SCAN_COMPLETE_RELATIVE_TO_ANCHOR' if balance['chain_trust']!='STALE_OR_ROLLBACK' else 'STALE_OR_UNVERIFIED_ANCHOR',global_freshness='UNKNOWN'),history=history,outgoing=outgoing,outgoing_total=outgoing_total,archived_pages=len(self.journal.get('archives',[])),unknown_attempts=unknown,history_page=dict(offset=offset,total=total,limit=100,next_offset=offset+100 if offset+100<total else None,previous_offset=max(0,offset-100) if offset else None))
    def dispatch(self, request):
        if not isinstance(request,dict): raise ValueError('request')
        schemas = dict(hello='',connect='port',create='name password',open='name password',close='',refresh='',history_page='offset',prepare='destination amount fee max_fee',confirm='token consent',backup='name',restore='name backup password')
        command = request.get('command')
        if command not in schemas or set(request) != {'command',*schemas[command].split()}: raise ValueError('schema')
        if command == 'hello':
            return dict(network='privacycoin-devnet',production_safe=False,full_sync=True,home=str(self.home),wallets=sorted(p.stem for p in self.home.glob('*.wallet')),backups=sorted(p.stem for p in self.home.glob('*.backup')),rss_kib=c.win.rss_kib() if os.name=='nt' else int(next(s.split()[1] for s in Path('/proc/self/status').read_text().splitlines() if s.startswith('VmRSS:'))))
        if command == 'connect':
            self.port = self.check_port(request['port']); self.plan = None
            return dict(endpoint='127.0.0.1:'+str(self.port), balance=None)
        if command == 'close': self.close(); return dict(closed=True,balance=None)
        if command in ('create','open','restore'):
            self.close()
            password = request['password']
            if not isinstance(password,str) or not 12 <= len(password) <= 1024: raise ValueError('password length')
            password = password.encode('utf-8'); path = self.path(request['name'])
            if command == 'create':
                with c.lock(path):
                    if any(os.path.lexists(Path(str(path)+suffix)) for suffix in ('.gui-state','.phase6a-cache','.gui-archive')):raise ValueError('orphan sidecar')
                    c.save(path,f.full(),password)
            elif command == 'restore':
                backup_path=self.path(request['backup'],'.backup');recovered,bundle=recovery_bundle(backup_path,password)
                with c.lock(path):
                    # Publish reservation/high-water sidecars BEFORE the wallet.
                    # A cut leaves no wallet or a complete conservative restore.
                    if os.path.lexists(path) or any(os.path.lexists(Path(str(path)+suffix)) for suffix in ('.gui-state','.phase6a-cache','.gui-archive')):raise ValueError('no overwrite')
                    j.Store(c,f,recovered,password,Path(str(backup_path)+'.journal-archive'),validate_journal).copy_to(bundle['journal'],Path(str(path)+'.gui-archive'))
                    c.write_private(Path(str(path)+'.gui-state'),f.seal(bundle['journal'],password,'gui-pilot-state'))
                    if bundle['cache'] is not None:c.write_private(Path(str(path)+'.phase6a-cache'),f.seal(bundle['cache'],password,c.CACHE_KIND))
                    c.save(path,recovered,password)
            return self.unlock(path,password)
        if self.wallet is None: raise ValueError('locked')
        if command == 'refresh': return self.refresh()
        if command == 'history_page':return self.refresh(request['offset'])
        if command == 'backup':
            path = self.path(request['name'],'.backup')
            if os.path.lexists(path) or os.path.lexists(Path(str(path)+'.journal-archive')):raise ValueError('no overwrite backup')
            self.store().copy_to(self.journal,Path(str(path)+'.journal-archive'))
            bundle=dict(version=2 if self.journal['version']==2 else 1,recovery=f.recovery(self.wallet),journal=self.journal,cache=self.previous)
            c.write_private(path,f.seal(bundle,self.password,'gui-pilot-backup'))
            return dict(backup=str(path),archive_directory=str(path)+'.journal-archive' if self.journal.get('archives') else None,warning='Keep encrypted backup + password AND its .journal-archive companion folder when present. Includes recovery, every archived/current attempt and chain high-water mark. Older backups cannot contain later submissions. Keep original files.')
        if command == 'prepare':
            self.plan = None
            if any(a['transaction_id'] is None for a in self.journal['attempts']):raise ValueError('unresolved attempt without transaction identifier')
            state,scan,balance,_ = self.observation()
            if not balance['signing_available']: raise ValueError('unverified')
            _,unknown,_=self.reconcile(state)
            if unknown or any(a['status'] in ('UNKNOWN','SUBMITTED') for a in self.journal['attempts']):raise ValueError('unresolved attempt')
            self.journal=self.store().archive(self.journal,lambda root:c.write_private(self.journal_path,f.seal(root,self.password,'gui-pilot-state'),replace=True))
            plan = c.prepare(self.wallet,state,request['destination'],request['amount'],request['fee'],request['max_fee'],scan)
            token = secrets.token_hex(32); self.plan = (token,time.monotonic()+120,plan)
            return dict(token=token,review=plan.display(),expires_seconds=120)
        if command == 'confirm':
            stored = self.plan; self.plan = None
            if not stored or request['token'] != stored[0] or request['consent'] != 'CONFIRM' or time.monotonic()>stored[1]: raise ValueError('approval')
            plan = stored[2]; intent = plan.display()
            if len(self.journal['attempts'])>=128 or any(a['token']==stored[0] for a in self.store().attempts(self.journal)):raise ValueError('attempt capacity or duplicate approval')
            attempt = dict(token=stored[0],status='UNKNOWN',transaction_id=None,destination=intent['destination'],amount=intent['amount'],fee=intent['fee'],created=int(time.time()))
            self.journal['attempts'].append(attempt); self.persist()
            def submit(payment):
                attempt['transaction_id'] = payment['id']; self.persist()
                response = w.rpc(self.port,'submit_tx',transaction=payment['transaction'])
                if response.get('accepted') != payment['id']: raise ValueError('submission acknowledgement')
                attempt['status'] = 'SUBMITTED'; self.persist(); return response
            result = c.execute(self.wallet,plan,lambda _:True,lambda:c.snapshot(self.port),submit)
            return result
        raise ValueError('unsupported')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--home',type=Path,default=DEFAULT_HOME);parser.add_argument('--port',type=int,default=48081)
    args=parser.parse_args(); session=Session(args.home,args.port)
    try:
        while True:
            raw=sys.stdin.buffer.readline(16385)
            if not raw: break
            if len(raw)>16384 or not raw.endswith(b'\n'): break
            try:
                result=session.dispatch(f.decode(raw)); response=dict(ok=True,result=result)
            except Exception:
                session.plan=None
                response=dict(ok=False,error='Operation rejected. Check password, private file, authority, fee/balance, unresolved attempt and node consistency. No verified result.')
            print(json.dumps(response,separators=(',',':')),flush=True)
    finally: session.close()

if __name__=='__main__':
    try: main()
    except Exception: sys.exit(1)
