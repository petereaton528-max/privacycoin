"""Local PC payer and independent Bob retrieval. No network-facing signer API."""
from common import *
import time

class Client:
    def __init__(self,home,port,admin,transport=None):
        self.home=private_dir(home);self.port=port;self.admin=admin
        self.transport=transport;self.binding=getattr(transport,'binding',None)
    def request(self,*args,**fields):return (self.transport or call)(*args,**fields)
    def path(self,qid):return self.home/(identity(qid)+'.intent')
    def record(self,qid):
        record=load_json(self.path(qid))
        if record.get('transport')!=self.binding:raise ValueError('intent transport mismatch')
        return record
    def quote(self,plain_size):
        f.integer(plain_size,1,MAX_PLAIN);health=self.request(self.port,'health');q=self.request(self.port,'quote',self.admin,quota=plain_size+44)
        f.fields(q,'id provider recipient amount_atomic quota expires payment_deadline retention confirmations owner retriever')
        for field in ('id','provider','owner','retriever'):identity(q[field])
        f.parse_address(q['recipient'])
        if q['provider']!=health['provider'] or type(q['amount_atomic']) is not int or q['amount_atomic']!=1000000 or q['quota']!=plain_size+44 or q['confirmations']!=10 or not time.time()<q['expires']<=time.time()+601:raise ValueError('invoice policy')
        f.integer(q['retention'],1,3600)
        if not q['expires']<q['payment_deadline']<=q['expires']+3600:raise ValueError('payment confirmation window')
        record=dict(quote=q,payment='NOT_AUTHORIZED')
        if self.binding is not None:record['transport']=self.binding
        save_json(self.path(q['id']),record);return q
    def pay(self,qid,session,consent):
        with c.lock(self.path(qid)):
            return self._pay(qid,session,consent)
    def _pay(self,qid,session,consent):
        record=self.record(qid);q=record['quote']
        if consent!='CONFIRM' or record['payment']!='NOT_AUTHORIZED' or time.time()>=q['expires']:raise ValueError('consent/attempt/expiry')
        plan=session.dispatch(dict(command='prepare',destination=q['recipient'],amount=q['amount_atomic'],fee=188000,max_fee=500000))
        if time.time()>=q['expires']:raise ValueError('quote expired during review; no authorization created')
        # Durable at-most-one attempt; cancellation/timeout never creates replacement authority.
        record['payment']='AUTHORIZED_UNKNOWN';record['authorized_at']=time.time();save_json(self.path(qid),record,True)
        result=session.dispatch(dict(command='confirm',token=plan['token'],consent=consent))
        record['payment']='SUBMITTED_NOT_SETTLED';record['submitted_at']=time.time();save_json(self.path(qid),record,True)
        # Prompt independent observation. This is not a client-issued settlement
        # receipt: only the provider's own completed scan records timely admission.
        try:self.status(qid)
        except (OSError,ValueError):pass
        return result
    def status(self,qid):
        q=self.record(qid)['quote'];return self.request(self.port,'status',q['owner'],quote=qid)
    def encrypt(self,qid,plain):
        record=self.record(qid);q=record['quote'];key=os.urandom(32)
        if len(plain)+44!=q['quota']:raise ValueError('quoted size mismatch')
        cipher=crypt(plain,key,aad(q['provider'],qid))
        bundle=dict(version=1,provider=q['provider'],port=self.port,quote=qid,retriever=q['retriever'],key=key.hex(),plain_hash=digest(plain),cipher_hash=digest(cipher),plain_bytes=len(plain))
        if self.binding is not None:bundle.update(version=2,transport=self.binding)
        # Persist original ciphertext for exact same-payload retries, never encrypt a retry afresh.
        save_json(self.home/(qid+'.upload'),dict(ciphertext=encode(cipher),bundle=bundle));return cipher,bundle
    def upload(self,qid):
        q=self.record(qid)['quote'];data=load_json(self.home/(qid+'.upload'))
        return self.request(self.port,'upload',q['owner'],quote=qid,ciphertext=data['ciphertext'])
    def export(self,qid,path,password):
        data=load_json(self.home/(identity(qid)+'.upload'))
        c.write_private(Path(path),f.seal(data['bundle'],password,'privacy-network-retrieval-v01'))

def retrieve(bundle,transport=None):
    version=bundle.get('version')
    if type(version) is not int or version not in (1,2):raise ValueError('bundle version')
    f.fields(bundle,'version provider port quote retriever key plain_hash cipher_hash plain_bytes'+(' transport' if version==2 else ''))
    if (version==1 and transport is not None) or (version==2 and (transport is None or getattr(transport,'binding',None)!=bundle['transport'])):raise ValueError('retrieval transport mismatch')
    request=transport or call
    for name in ('provider','quote','retriever','key','plain_hash','cipher_hash'):identity(bundle[name])
    f.integer(bundle['plain_bytes'],1,MAX_PLAIN)
    if request(bundle['port'],'health')['provider']!=bundle['provider']:raise ValueError('provider identity mismatch')
    reply=request(bundle['port'],'download',bundle['retriever'],quote=bundle['quote']);raw=decode(reply['ciphertext'])
    if digest(raw)!=bundle['cipher_hash']:raise ValueError('ciphertext substitution')
    plain=crypt(raw,bytes.fromhex(bundle['key']),aad(bundle['provider'],bundle['quote']),True)
    if len(plain)!=bundle['plain_bytes'] or digest(plain)!=bundle['plain_hash']:raise ValueError('plaintext integrity')
    return plain

def restore_bundle(path,password,destination,transport=None):
    bundle=f.open_sealed(c.read_private(Path(path)),password,'privacy-network-retrieval-v01')
    plain=retrieve(bundle,transport)
    # Existing descriptor-based atomic no-clobber private writer. Plaintext only at Bob's explicit destination.
    c.write_private(Path(destination),plain)
    return dict(bytes=len(plain),sha256=digest(plain))
