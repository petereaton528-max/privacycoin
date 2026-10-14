"""Single-process loopback provider; SQLite FULL transactions hold ciphertext."""
from common import *
import argparse,contextlib,signal,sqlite3,time,stat
from http.server import BaseHTTPRequestHandler,HTTPServer

class Rejected(ValueError):pass
class Provider:
    def __init__(self,home,node,capacity=4*MAX_CIPHER,retention=3600,quote_ttl=120,fault=None,payment_wait=3600):
        self.home=private_dir(home);self.node=node;self.capacity=f.integer(capacity,44,16*MAX_CIPHER);self.retention=f.integer(retention,1,3600);self.ttl=f.integer(quote_ttl,1,600);self.fault=fault;self.payment_wait=f.integer(payment_wait,1,3600)
        self.guard=c.lock(self.home/'provider');self.guard.__enter__()
        path=self.home/'control'
        if not path.exists():save_json(path,dict(id=token(),admin=token(),password=token()))
        self.control=load_json(path);f.fields(self.control,'id admin password')
        for value in self.control.values():identity(value)
        dbpath=self.home/'state.sqlite'
        if dbpath.exists() or dbpath.is_symlink():
            fd=os.open(dbpath,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                s=os.fstat(fd)
                if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o077 or s.st_nlink!=1 or s.st_size>32*1024*1024:raise Rejected('UNSAFE_DATABASE')
            finally:os.close(fd)
        self.db=sqlite3.connect(dbpath);self.db.row_factory=sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL');self.db.execute('PRAGMA journal_mode=DELETE');self.db.execute('PRAGMA max_page_count=8192')
        # Explicit transaction includes all DDL: interrupted V1 migration rolls back.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('CREATE TABLE IF NOT EXISTS config(version INTEGER,capacity INTEGER,retention INTEGER,ttl INTEGER,payment_wait INTEGER)')
            cfg=self.db.execute('SELECT * FROM config').fetchone()
            if cfg is None:
                self.db.execute('INSERT INTO config VALUES(2,?,?,?,?)',(capacity,retention,quote_ttl,payment_wait))
                self.db.execute('''CREATE TABLE quotes(id TEXT PRIMARY KEY,recipient TEXT UNIQUE,wallet BLOB,owner TEXT,retriever TEXT,price INTEGER,quota INTEGER,expires REAL,retention INTEGER,state TEXT,accepted REAL,tx TEXT,work TEXT,tip TEXT,blob BLOB,hash TEXT,first_seen REAL,payment_deadline REAL,timing TEXT,payment_state TEXT)''')
            elif tuple(cfg)==(1,capacity,retention,quote_ttl):
                self.db.execute('ALTER TABLE config ADD COLUMN payment_wait INTEGER')
                for column in ('first_seen REAL','payment_deadline REAL','timing TEXT','payment_state TEXT'):self.db.execute('ALTER TABLE quotes ADD COLUMN '+column)
                self.db.execute("UPDATE quotes SET timing='LEGACY_UNPROVEN',payment_state='UNKNOWN'")
                self.crash('migration-before-commit')
                self.db.execute('UPDATE config SET version=2,payment_wait=?',(payment_wait,))
            elif tuple(cfg)!=(2,capacity,retention,quote_ttl,payment_wait):raise Rejected('CONFIG_OR_VERSION_MISMATCH')
            self.db.commit()
        except BaseException:
            self.db.rollback();self.db.close();self.guard.__exit__(None,None,None);raise
        # A crash cannot partially commit quota and object: ciphertext lives in the same DB.
        if self.db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise Rejected('CORRUPT_STORE')
    def close(self):self.db.close();self.guard.__exit__(None,None,None)
    def crash(self,stage):
        if self.fault==stage:os.kill(os.getpid(),signal.SIGKILL)
    def auth(self,raw,expected):
        if not isinstance(raw,str) or not secrets.compare_digest(digest(raw.encode()),expected):raise Rejected('UNAUTHORIZED')
    def cleanup(self):
        now=time.time()
        self.db.execute("UPDATE quotes SET state='EXPIRED',blob=NULL WHERE (accepted IS NULL AND first_seen IS NULL AND expires<=?) OR (accepted IS NULL AND first_seen IS NOT NULL AND payment_deadline<=?) OR (accepted IS NOT NULL AND accepted+retention<=?)",(now,now,now))
    def usage(self):
        now=time.time()
        row=self.db.execute('''SELECT COALESCE(SUM(quota),0),COALESCE(SUM(length(blob)),0) FROM quotes WHERE
            (accepted IS NOT NULL AND accepted+retention>?) OR
            (accepted IS NULL AND first_seen IS NOT NULL AND payment_deadline>?) OR
            (accepted IS NULL AND first_seen IS NULL AND expires>?)''',(now,now,now)).fetchone()
        return dict(reserved_bytes=row[0],stored_bytes=row[1],capacity=self.capacity)
    def reconcile(self,row):
        if row['accepted'] is not None and time.time()>=row['accepted']+row['retention']:return dict(row)
        try:
            wallet=f.open_sealed(row['wallet'],self.control['password'].encode(),'resource-invoice-wallet')
            previous=dict(work=int(row['work']),tip=row['tip']) if row['work'] is not None else None
            signal.alarm(30)
            state,scan,balance,work=c.observe(wallet,self.node,previous)
            if balance['chain_trust']=='STALE_OR_ROLLBACK':status='UNKNOWN_RECONCILE';observation='UNKNOWN';tx=row['tx']
            else:
                paid=[x for x in scan['owned'] if not x['coinbase'] and x['address_index']==0 and x['amount']==row['price']]
                # Only the provider's completed independent observation proves timely
                # admission. Client clocks, block timestamps and asserted receipts do not.
                now=time.time()
                if row['first_seen'] is None and row['accepted'] is None and paid and now<row['expires']:
                    tx=sorted(paid,key=lambda x:(x['height'],x['transaction']))[0]['transaction']
                    self.db.execute("UPDATE quotes SET first_seen=?,payment_deadline=?,timing='PROVIDER_OBSERVED',tx=?,work=?,tip=? WHERE id=?",(now,row['expires']+self.payment_wait,tx,str(work),state['tip'],row['id']))
                    self.crash('witness-before-commit');self.db.commit();self.crash('witness-after-commit')
                    row=dict(self.db.execute('SELECT * FROM quotes WHERE id=?',(row['id'],)).fetchone())
                if row['tx'] is not None:paid=[x for x in paid if x['transaction']==row['tx']]
                sufficient=[x for x in paid if not x['pending'] and state['height']-x['height']+1>=10 and x['unlock']<=state['height']+1]
                tx=sufficient[0]['transaction'] if sufficient else row['tx']
                observation='CONFIRMED_LOCAL' if sufficient else 'INCLUDED_LOCKED' if any(not x['pending'] for x in paid) else 'MEMPOOL_ONLY' if paid else 'QUOTED_UNPAID'
                eligible=row['accepted'] is not None or (row['first_seen'] is not None and now<row['payment_deadline'])
                status='CONFIRMED_LOCAL' if sufficient and eligible else 'REVOKED_RECONCILE' if row['accepted'] is not None else 'UNKNOWN_RECONCILE' if row['first_seen'] is not None and not paid else observation
                if sufficient and eligible and row['accepted'] is None:self.crash('redemption-before-commit')
                self.db.execute('UPDATE quotes SET work=?,tip=? WHERE id=?',(str(work),state['tip'],row['id']))
            cutoff=row['payment_deadline'] if row['first_seen'] is not None else row['expires']
            if row['accepted'] is None and time.time()>=cutoff:status='EXPIRED'
            accepted=row['accepted'] if row['accepted'] is not None else time.time() if status=='CONFIRMED_LOCAL' else None
            self.db.execute('UPDATE quotes SET state=?,accepted=?,tx=?,payment_state=? WHERE id=?',(status,accepted,tx,observation,row['id']))
        except (OSError,ValueError,TimeoutError):
            self.db.execute("UPDATE quotes SET state='UNKNOWN_RECONCILE',payment_state='UNKNOWN' WHERE id=?",(row['id'],))
        finally:signal.alarm(0)
        self.cleanup()
        return dict(self.db.execute('SELECT * FROM quotes WHERE id=?',(row['id'],)).fetchone())
    def execute(self,command,q,bearer):
        schemas=dict(health='',quote='quota',status='quote',upload='quote ciphertext',download='quote',usage='',cleanup='')
        if command not in schemas or set(q)!=set(schemas[command].split()):raise Rejected('SCHEMA')
        if command=='health':return dict(provider=self.control['id'],devnet_only=True,global_freshness='UNKNOWN')
        if command in ('quote','usage','cleanup'):self.auth(bearer,digest(self.control['admin'].encode()))
        with self.db:
            self.cleanup()
            if command in ('usage','cleanup'):
                return self.usage()
            if command=='quote':
                quota=f.integer(q['quota'],44,MAX_CIPHER);used=self.usage()['reserved_bytes']
                if used+quota>self.capacity or self.db.execute('SELECT COUNT(*) FROM quotes').fetchone()[0]>=64:raise Rejected('QUOTA_EXHAUSTED')
                wallet=f.full(count=2);recipient=f.address(wallet,0);qid=token();owner=token();retriever=token();price=1000000
                sealed=f.seal(wallet,self.control['password'].encode(),'resource-invoice-wallet')
                expires=time.time()+self.ttl
                self.db.execute('INSERT INTO quotes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(qid,recipient,sealed,digest(owner.encode()),digest(retriever.encode()),price,quota,expires,self.retention,'QUOTED_UNPAID',None,None,None,None,None,None,None,expires+self.payment_wait,'UNOBSERVED','QUOTED_UNPAID'))
                return dict(id=qid,provider=self.control['id'],recipient=recipient,amount_atomic=price,quota=quota,expires=expires,payment_deadline=expires+self.payment_wait,retention=self.retention,confirmations=10,owner=owner,retriever=retriever)
            row=self.db.execute('SELECT * FROM quotes WHERE id=?',(identity(q['quote']),)).fetchone()
            if row is None:raise Rejected('NOT_FOUND')
            self.auth(bearer,row['retriever'] if command=='download' else row['owner'])
            row=self.reconcile(row)
            if command=='status':
                expired=row['state']=='EXPIRED';reason='RETENTION' if row['accepted'] is not None else 'PAYMENT_CONFIRMATION_WINDOW' if row['first_seen'] is not None else 'QUOTATION'
                recovery='PAID_NO_ENTITLEMENT' if expired and row['accepted'] is None and row['payment_state']=='CONFIRMED_LOCAL' else 'RECONCILE' if row['payment_state']=='UNKNOWN' or row['state'] in ('UNKNOWN_RECONCILE','REVOKED_RECONCILE') else 'NONE'
                return dict(state=row['state'],payment_state=row['payment_state'],quote_state='EXPIRED' if time.time()>=row['expires'] else 'OPEN',quote_deadline=row['expires'],payment_deadline=row['payment_deadline'],first_seen_at=row['first_seen'],timing_evidence=row['timing'],entitlement_expires_at=None if row['accepted'] is None else row['accepted']+row['retention'],expiration_reason=reason if expired else None,recovery=recovery,payment_transaction=row['tx'],quota=row['quota'],stored_bytes=len(row['blob'] or b''),retention=row['retention'],accepted_at=row['accepted'],global_freshness='UNKNOWN')
            if row['state']!='CONFIRMED_LOCAL':raise Rejected(row['state'])
            if command=='upload':
                raw=decode(q['ciphertext'])
                if not 44<=len(raw)<=row['quota'] or raw[:4]!=b'PN01':raise Rejected('CIPHERTEXT_FRAME_OR_QUOTA')
                if time.time()>=row['accepted']+row['retention']:raise Rejected('EXPIRED')
                hashed=digest(raw)
                if row['blob'] is not None:
                    if row['hash']!=hashed:raise Rejected('ENTITLEMENT_ALREADY_CONSUMED')
                    return dict(stored=True,idempotent=True,bytes=len(raw),hash=hashed)
                self.db.execute('UPDATE quotes SET blob=?,hash=? WHERE id=?',(raw,hashed,row['id']));self.crash('upload-before-commit')
                # Explicit commit before acknowledgement; crash after commit is safely retryable.
                self.db.commit();self.crash('upload-after-commit')
                return dict(stored=True,idempotent=False,bytes=len(raw),hash=hashed)
            if row['blob'] is None:raise Rejected('OBJECT_NOT_UPLOADED')
            if digest(row['blob'])!=row['hash']:raise Rejected('CORRUPT_OBJECT')
            if time.time()>=row['accepted']+row['retention']:raise Rejected('EXPIRED')
            return dict(ciphertext=encode(row['blob']),bytes=len(row['blob']),hash=row['hash'])

def serve(home,node,port,**kwargs):
    c.harden();f.integer(port,1024,65535);signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError()))
    provider=Provider(home,node,**kwargs)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            start=time.perf_counter();self.connection.settimeout(5)
            try:
                if self.headers.get('Host')!=f'127.0.0.1:{port}' or len(self.headers.get_all('Host',[]))!=1 or len(self.headers.get_all('Authorization',[]))>1 or self.headers.get('Origin') or self.headers.get('Sec-Fetch-Site') or self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type')!='application/json' or len(self.headers.get_all('Content-Length',[]))!=1:raise Rejected('HTTP_BOUNDARY')
                size=int(self.headers['Content-Length']);f.integer(size,0,2*MAX_CIPHER+4096)
                raw=self.rfile.read(size)
                if len(raw)!=size:raise Rejected('TRUNCATED')
                value=f.decode(raw);header=self.headers.get('Authorization','');bearer=header[7:] if header.startswith('Bearer ') else None
                result=provider.execute(self.path.removeprefix('/'),value,bearer);reply=dict(ok=True,result=result);status=200
            except Exception as error:
                code=str(error) if isinstance(error,Rejected) else 'REJECTED_OR_UNKNOWN_RECONCILE'
                reply=dict(ok=False,code=code);status=400
            body=f.canonical(reply);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers()
            try:self.wfile.write(body)
            except (OSError,TimeoutError):pass
    server=HTTPServer(('127.0.0.1',port),Handler)
    try:server.serve_forever(poll_interval=.2)
    finally:server.server_close();provider.close()
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--home',type=Path,required=True);parser.add_argument('--node',type=int,required=True);parser.add_argument('--port',type=int,required=True);parser.add_argument('--capacity',type=int,default=4*MAX_CIPHER);parser.add_argument('--retention',type=int,default=3600);parser.add_argument('--quote-ttl',type=int,default=120);parser.add_argument('--payment-wait',type=int,default=3600);parser.add_argument('--fault',choices=['redemption-before-commit','upload-before-commit','upload-after-commit','witness-before-commit','witness-after-commit','migration-before-commit']);a=parser.parse_args()
    try:serve(a.home,a.node,a.port,capacity=a.capacity,retention=a.retention,quote_ttl=a.quote_ttl,fault=a.fault,payment_wait=a.payment_wait)
    except Exception:sys.exit(1)
