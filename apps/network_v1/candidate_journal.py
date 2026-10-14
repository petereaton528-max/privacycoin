"""Reuse immutable encrypted journal pages for candidate payment history.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
from pathlib import Path
import hashlib
def digest(raw):return hashlib.sha256(raw.encode('ascii')).hexdigest()
class Journal:
    @classmethod
    def inspect_backup(cls,client,binding,wallet,password,root,directory):
        """Authenticate all referenced history before publishing a restored wallet.

        Read-only; no wallet, journal root or destination directory is created.
        This does not replace final copy verification or promise atomic multi-file
        recovery if storage fails after successful inspection.
        """
        from types import SimpleNamespace
        probe=cls.__new__(cls);probe.client=SimpleNamespace(binding=binding)
        probe.f=client.f;probe.c=client.c;probe.validate(root,wallet)
        module=__import__('importlib.util',fromlist=['util'])
        source=Path(__file__).resolve().parents[2]/'scripts/devnet-gui/journal.py'
        spec=module.spec_from_file_location('candidate_backup_pages',source);m=module.module_from_spec(spec);spec.loader.exec_module(m)
        store=m.Store(client.c,client.f,wallet,password,directory,probe.validate)
        ids=set()
        for item in store.attempts(root):
            if item['id'] in ids:raise ValueError('RECOVERY_DUPLICATE_PAYMENT')
            ids.add(item['id'])
    def __init__(self,client,path):
        self.client=client;self.path=Path(path);self.f=client.f;self.c=client.c
        module=__import__('importlib.util',fromlist=['util'])
        source=Path(__file__).resolve().parents[2]/'scripts/devnet-gui/journal.py'
        spec=module.spec_from_file_location('candidate_pages',source);m=module.module_from_spec(spec);spec.loader.exec_module(m)
        self.kind=client.binding.kind+'/journal'
        self.store=m.Store(self.c,self.f,client.wallet,client.password,Path(str(path)+'.pages'),self.validate)
        self.root=self.f.open_sealed(self.c.read_private(path),client.password,self.kind) if path.exists() else dict(version=2,wallet_id=self.f.wallet_id(client.wallet),archives=[],attempts=[])
        self.validate(self.root,client.wallet)
    def validate(self,root,wallet):
        if set(root)!=({'version','wallet_id','attempts'} if root.get('version')==1 else {'version','wallet_id','attempts','archives'}) or type(root['version']) is not int or root['version'] not in (1,2) or root['wallet_id']!=self.f.wallet_id(wallet):raise ValueError('CANDIDATE_JOURNAL_IDENTITY')
        refs=root.get('archives',[])
        if not isinstance(refs,list) or len(refs)>4096 or len(set(refs))!=len(refs):raise ValueError('JOURNAL_PAGE_BOUND')
        for ref in refs:self.f.unhex(ref,32)
        if not isinstance(root['attempts'],list) or len(root['attempts'])>128:raise ValueError('JOURNAL_ACTIVE_BOUND')
        ids=set()
        for item in root['attempts']:
            if set(item)!={'transaction','transaction_id','id','amount','fee','address','state','status'} or item['status']!=item['state'] or item['state'] not in ('UNKNOWN','PENDING','CONFIRMED') or item['id']!=item['transaction_id'] or item['id'] in ids:raise ValueError('JOURNAL_ATTEMPT')
            ids.add(item['id']);self.f.unhex(item['id'],32);self.f.unhex(item['transaction'],len(item['transaction'])//2)
            self.f.integer(item['amount'],1,2**64-1);self.f.integer(item['fee'],1,10**12);self.client.binding.parse(item['address'])
        return root
    def publish(self,root):
        self.validate(root,self.client.wallet)
        self.c.write_private(self.path,self.f.seal(root,self.client.password,self.kind),replace=self.path.exists());self.root=root
    def save(self,intent):
        item=dict(intent,status=intent['state'],transaction_id=intent['id'])
        for entry in self.root['attempts']:
            if entry['id']==item['id']:
                if entry['transaction']!=item['transaction']:raise ValueError('JOURNAL_ID_COLLISION')
                entry.update(item);self.publish(self.root);return
        # All retained entries are checked; an archived ID is never submitted again.
        if any(entry['id']==item['id'] for entry in self.store.attempts(self.root)):raise ValueError('PAYMENT_ALREADY_RECORDED')
        self.root=self.store.archive(self.root,self.publish)
        self.root['attempts'].append(item);self.publish(self.root)
    def reconcile(self,chain,pool):
        total=0;unresolved=0;last=None;changed=False
        for item in self.store.attempts(self.root):
            current='CONFIRMED' if digest(item['transaction']) in chain else 'PENDING' if digest(item['transaction']) in pool else 'UNKNOWN'
            total+=1;unresolved+=current!='CONFIRMED';last={**item,'state':current,'status':current}
            if item in self.root['attempts'] and item['state']!=current:item.update(state=current,status=current);changed=True
        if changed:self.publish(self.root)
        return total,unresolved,last
