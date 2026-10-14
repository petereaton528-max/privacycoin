"""Non-launchable offline Mainnet-candidate wallet and owned native ledger.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,importlib.util,json,os,re,secrets,threading,time
from pathlib import Path
from tools.creator_model.binding import DraftBinding,GenesisAddress
from tools.creator_vesting.wallet import CandidateWallet
from tools.creator_vesting.verify_native import Native
ROOT=Path(__file__).resolve().parents[2]
def amount(text):
    if not isinstance(text,str) or not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]{1,12})?',text):raise ValueError('USE_PC_WITH_AT_MOST_12_DECIMALS')
    whole,_,fraction=text.partition('.');return int(whole)*10**12+int(fraction.ljust(12,'0') or '0')
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class Client:
    def __init__(self,home,build,native_root,*,node=None,profile=None):
        self.home=Path(home);self.build=Path(build);self.native_root=Path(native_root);self.lock=threading.RLock();self.wallet=None;self.password=None;self.name=None;self.prepared=None
        if not self.home.is_absolute() or '..' in self.home.parts or any('privacycoin-n2' in p.lower() for p in self.home.parts) or not any(p.startswith('pc-candidate-profile-') or p in ('privacycoin-mainnet-candidate-offline','privacycoin-mainnet-v1') for p in self.home.parts):raise ValueError('ISOLATED_CANDIDATE_DIRECTORY_REQUIRED')
        self.c=load('candidate_secure_files',ROOT/'src/phase6a/wallet.py');self.w=load('candidate_private_wallet',ROOT/'src/phase4/wallet.py');self.f=self.w.foundation
        self.f.HELPER=Path(native_root)/'build/monero-linux/phase2/privacycoin-wallet-crypto';self.w.HELPER=self.build/'draft-wallet'
        self.home.mkdir(mode=0o700,parents=True,exist_ok=True)
        with self.c.directory(self.home):pass
        self.guard=self.c.lock(self.home/'candidate.lock');self.guard.__enter__()
        self.node=None
        try:
            receipt=json.loads((self.build/'BUILD.json').read_text())
            from apps.network_v1.candidate_profile import verify_build
            verify_build(receipt)
            for name in ('ledger','wallet'):
                if hashlib.sha256((self.build/('draft-'+name)).read_bytes()).hexdigest()!=receipt[name]['binary_sha256']:raise ValueError('CANDIDATE_BINARY_INTEGRITY')
            self.external=node is not None
            self.node=node or Native(self.build/'draft-ledger');self.policy=self.node.call(op='policy')
            if self.policy['interval'] not in (65700,80) or self.policy['total']!=159627169409884823 or self.policy['liquid']!=15962716940988482:raise ValueError('CANDIDATE_POLICY')
            self.tag=hashlib.sha256(('PC/CANDIDATE-OFFLINE/'+self.policy['commitment']).encode()).hexdigest()
            self.profile=None
            from tools.mainnet_prepare.production import selected,profile as final_profile
            self.production=selected()
            if (self.home/'profile.json').exists():self.set_profile(json.loads(self.c.read_private(self.home/'profile.json')))
            elif self.production:
                self.set_profile(final_profile())
                self.c.write_private(self.home/'profile.json',self.f.canonical(self.profile))
            if self.external:
                from apps.network_v1.candidate_profile import validate
                profile=validate(profile)
                if self.profile is not None and self.profile!=profile:raise ValueError('PINNED_PROFILE_MISMATCH')
                self.set_profile(profile)
                if not (self.home/'profile.json').exists():self.c.write_private(self.home/'profile.json',self.f.canonical(profile))
        except BaseException:self.close();raise
    def set_profile(self,profile):
        from tools.mainnet_prepare.production import selected
        if selected():
            from .candidate_profile import validate
            validate(profile)
        if set(profile)!={'format','network_tag','commitment','genesis','block','launchable'} or profile['format']!='PC_OFFLINE_MAINNET_CANDIDATE_V1' or profile['launchable'] is not False or profile['network_tag']!=self.tag or profile['commitment']!=self.policy['commitment']:raise ValueError('CANDIDATE_NETWORK_MISMATCH')
        self.node.call(op='open',path=str(self.home/'chain'),block=profile['block'],hash=profile['genesis'])
        self.profile=profile
        from apps.network_v1.candidate_profile import bound_context
        address_prefix=bound_context()[2]
        self.binding=GenesisAddress(self.f,self.tag,profile['genesis'],address_prefix) if self.external or selected() else DraftBinding(self.f,self.tag,profile['genesis'])
        self.adapter=CandidateWallet(self.w,self.w.HELPER,self.binding,self.policy['interval'])
    def path(self,name):
        if not isinstance(name,str) or not re.fullmatch('[A-Za-z0-9_-]{1,40}',name):raise ValueError('WALLET_NAME')
        return self.home/(name+'.candidate-wallet')
    def recovery_marker(self,name):return self.path(name).with_suffix('.candidate-restore-pending')
    def create(self,name,password):
        with self.lock:
            if not isinstance(password,bytes) or len(password)<12:raise ValueError('PASSWORD_MINIMUM_12_BYTES')
            path=self.path(name)
            if path.exists() or self.recovery_marker(name).exists():raise ValueError('NEW_WALLET_REQUIRED')
            master=secrets.token_hex(32)
            if self.profile is None:
                provisional=DraftBinding(self.f,self.tag,'a'*64);wallet=provisional.wallet(master);D,C,_=provisional.parse(provisional.address(wallet));g=self.node.call(op='genesis',D=D,C=C)
                profile=dict(format='PC_OFFLINE_MAINNET_CANDIDATE_V1',network_tag=self.tag,commitment=self.policy['commitment'],genesis=g['hash'],block=g['block'],launchable=False)
                self.set_profile(profile);self.c.write_private(self.home/'profile.json',self.f.canonical(profile))
            self.c.write_private(path,self.binding.seal(master,password));return self.open(name,password)
    def open(self,name,password):
        with self.lock:
            if self.recovery_marker(name).exists() and not getattr(self,'_restoring',False):raise ValueError('INCOMPLETE_RECOVERY_USE_ORIGINAL_BACKUP_AND_NEW_NAME')
            if self.profile is None:raise ValueError('CANDIDATE_PROFILE_REQUIRED')
            wallet=self.binding.restore(self.c.read_private(self.path(name)),password)
            self.wallet=wallet;self.password=password;self.name=name;self.prepared=None
            self.intent_path=self.home/(name+'.candidate-intent')
            self.intent=self.f.open_sealed(self.c.read_private(self.intent_path),password,self.binding.kind+'/intent') if self.intent_path.exists() else None
            from apps.network_v1.candidate_journal import Journal
            self.journal=Journal(self,self.home/(name+'.candidate-journal'))
            if self.intent and not self.journal.path.exists():self.journal.save(self.intent)
            return self.refresh()
    def refresh(self):
        with self.lock:
            if self.wallet is None:raise ValueError('WALLET_LOCKED')
            state=self.node.call(op='history');scan=self.scan(state);status=self.node.call(op='status')
            from apps.network_v1.candidate_journal import digest
            pool=[r['transaction'] for r in state['pool']] if 'pool' in state else self.node.call(op='pool')['transactions']
            self.payment_count,self.unresolved,self.intent=self.journal.reconcile({digest(r['transaction']) for r in state['chain']},{digest(raw) for raw in pool})
            return dict(address=self.binding.address(self.wallet),height=state['height'],total=sum(x['amount'] for x in scan['owned'] if not x['spent'] and not x['pending']),available=scan['available'],locked=scan['locked'],reserved=sum(x['amount'] for x in scan['owned'] if x['reserved'] and not x['spent']),payment=self.intent['state'] if self.intent else 'NONE',node=status,interval=self.policy['interval'],network=('Privacy Coin Mainnet V1 (release candidate)' if self.production else 'OFFLINE MAINNET CANDIDATE'),tor='DISABLED')
    def scan(self,state):
        # One snapshot only. Native instance/revision/tip invalidates Node history
        # on pool changes, restart and reorg; no stale balance across snapshots.
        if getattr(self,'_scan_wallet',None) is not self.wallet or getattr(self,'_scan_state',None) is not state:
            self._scan_result=self.adapter.scan(self.wallet,state);self._scan_wallet=self.wallet;self._scan_state=state
        return self._scan_result
    def persist_intent(self):self.journal.save(self.intent)
    def payments(self,offset=0,count=50):
        with self.lock:
            if type(offset) is not int or offset<0 or type(count) is not int or not 1<=count<=50:raise ValueError('PAYMENT_HISTORY_PAGE')
            from apps.network_v1.candidate_journal import digest
            self.refresh();state=self.node.call(op='history');chain={digest(r['transaction']) for r in state['chain']};pool={digest(r['transaction']) for r in state['pool']} if 'pool' in state else {digest(raw) for raw in self.node.call(op='pool')['transactions']};rows=[]
            for i,item in enumerate(self.journal.store.attempts(self.journal.root)):
                if i>=offset+count:break
                if i>=offset:rows.append(dict(id=item['id'],amount=item['amount'],fee=item['fee'],state='CONFIRMED' if digest(item['transaction']) in chain else 'PENDING' if digest(item['transaction']) in pool else 'UNKNOWN'))
            return rows
    def prepare(self,address,amount,fee=1000000000):
        with self.lock:
            self.refresh()
            if self.unresolved:raise ValueError('RECONCILE_OUTSTANDING_PAYMENT_FIRST')
            self.f.integer(amount,1,2**64-1);self.f.integer(fee,1,10**12);D,C,sub=self.binding.parse(address)
            state=self.node.call(op='history');scan=self.scan(state)
            candidates=[x for x in scan['owned'] if not x['spent'] and not x['reserved'] and x['unlock']<=state['height'] and x['amount']>amount+fee]
            if not candidates:raise ValueError('INSUFFICIENT_AVAILABLE_FUNDS')
            source=candidates[0]['global_index'];decoys=[i for i in scan['eligible'] if i!=source][:15]
            if len(decoys)!=15:raise ValueError('WAIT_FOR_15_ELIGIBLE_RING_DECOYS')
            selections=[dict(source=source,ring=sorted([source]+decoys))]
            construction=self.w.construction_state(state,scan,selections)
            q=dict(op='build',draft_genesis=self.profile['genesis'],**self.w.request(self.wallet,construction),sources=selections,destinations=[dict(D=D,C=C,sub=sub,amount=amount)],fee=fee,dedicated_change=True)
            built=self.w.helper(q)
            if fee<100*built['bytes']:raise ValueError('FEE_BELOW_ACTUAL_RELAY_FLOOR')
            self.prepared=dict(transaction=built['transaction'],id=built['id'],amount=amount,fee=fee,address=address,state='PREPARED')
            return {k:self.prepared[k] for k in ('id','amount','fee','address')}
    def confirm(self,transaction_id):
        with self.lock:
            if not self.prepared or self.prepared['id']!=transaction_id:raise ValueError('CONFIRMATION_MISMATCH')
            self.intent=dict(self.prepared,state='UNKNOWN');self.persist_intent();self.prepared=None
            # Unknown is durable before submission. Never auto-retry a failed response.
            result=self.node.call(op='payment',transaction=self.intent['transaction']);self.intent['state']='PENDING';self.persist_intent();return result
    def backup(self,path):
        with self.lock:
            if self.wallet is None:raise ValueError('WALLET_LOCKED')
            envelope=dict(format='PC_CANDIDATE_PORTABLE_V2',profile=self.profile,recovery=self.c.read_private(self.path(self.name)).hex(),intent=self.intent,journal=self.journal.root)
            raw=self.f.seal(envelope,self.password,'pc-offline-candidate-portable/v1')
            if self.f.open_sealed(raw,self.password,'pc-offline-candidate-portable/v1')!=envelope:raise ValueError('BACKUP_VERIFICATION')
            from apps.network_v1.portable_backup import pack
            def pages():
                for digest in self.journal.root.get('archives',[]):
                    self.journal.store.read(digest)
                    data=self.c.read_private(self.journal.store.directory/(digest+'.page'))
                    if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('BACKUP_PAGE_CHANGED')
                    yield digest,data
            pack(self.c,Path(path),raw,pages())
    def restore(self,path,name,password):
        from apps.network_v1.portable_backup import opened
        with self.lock:
            self._restoring=True
            try:
                with opened(self.c,path) as source:return self._restore(source,name,password)
            except BaseException:
                self.lock_wallet();raise
            finally:self._restoring=False
    def _restore(self,path,name,password):
        with self.lock:
            if self.path(name).exists() or self.recovery_marker(name).exists():raise ValueError('NEW_WALLET_REQUIRED')
            data=self.f.open_sealed(self.c.read_private(Path(path)),password,'pc-offline-candidate-portable/v1')
            v2=data.get('format')=='PC_CANDIDATE_PORTABLE_V2'
            if set(data)!=({'format','profile','recovery','intent','journal'} if v2 else {'format','profile','recovery','intent'}) or data['format'] not in ('PC_CANDIDATE_PORTABLE_V1','PC_CANDIDATE_PORTABLE_V2'):raise ValueError('RECOVERY_FORMAT')
            if self.profile is not None and data['profile']!=self.profile:raise ValueError('CANDIDATE_GENESIS_MISMATCH')
            binding=DraftBinding(self.f,self.tag,data['profile']['genesis']);restored=binding.restore(bytes.fromhex(data['recovery']),password)
            if v2:
                from apps.network_v1.candidate_journal import Journal
                Journal.inspect_backup(self,self.binding if self.profile is not None else binding,restored,password,data['journal'],Path(str(path)+'.pages'))
            # Durable gate before any destination wallet/history publication.
            # A failed or interrupted restore cannot reopen partial authority.
            marker=self.recovery_marker(name)
            self.c.write_private(marker,b'{"format":"PC_INCOMPLETE_RECOVERY_V1"}')
            self.set_profile(data['profile'])
            if not (self.home/'profile.json').exists():self.c.write_private(self.home/'profile.json',self.f.canonical(self.profile))
            self.c.write_private(self.path(name),bytes.fromhex(data['recovery']))
            if data['intent'] is not None:self.c.write_private(self.home/(name+'.candidate-intent'),self.f.seal(data['intent'],password,self.binding.kind+'/intent'))
            result=self.open(name,password)
            if v2:
                self.journal.validate(data['journal'],self.wallet)
                destination=self.journal.store.directory;self.journal.store.directory=Path(str(path)+'.pages')
                try:self.journal.store.copy_to(data['journal'],destination)
                finally:self.journal.store.directory=destination
                self.journal.publish(data['journal']);result=self.refresh()
            with self.c.directory(self.home) as directory:
                os.unlink(marker.name,dir_fd=directory);os.fsync(directory)
            return result
    def mine_one(self,timestamp=None,cancel=None,progress=None):
        with self.lock:
            if self.wallet is None:raise ValueError('WALLET_LOCKED')
            D,C,sub=self.binding.parse(self.binding.address(self.wallet));R,P=self.f.crypto('output',D,C,int(sub),0)
            if self.external and timestamp is None:return self.node.call(op='mine_async',P=P,R=R,cancel=cancel,progress=progress)
            return self.node.call(op='mine',P=P,R=R,**({'timestamp':timestamp} if timestamp is not None else {'timestamp':0}))
    def lock_wallet(self):
        with self.lock:
            self.wallet=None;self.password=None;self.prepared=None;self.name=None;self.journal=None;self.intent=None
            self._scan_wallet=None;self._scan_state=None;self._scan_result=None
    def close(self):
        if getattr(self,'node',None):self.node.close();self.node=None
        self.lock_wallet()
        if getattr(self,'guard',None):self.guard.__exit__(None,None,None);self.guard=None
