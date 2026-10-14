"""Private immutable journal pages. The encrypted root is published last.

No payment submission, deletion, finality assumption or automatic replay here.
Unreferenced pages from an interrupted publication are harmless and retained.
"""
import hashlib,os
from pathlib import Path

ACTIVE_LIMIT=128
PAGE_LIMIT=128
MAX_PAGES=4096
PAGE_KIND='gui-journal-page-v1'

class Store:
    def __init__(self,c,f,wallet,password,directory,validate):
        self.c=c;self.f=f;self.wallet=wallet;self.password=password
        self.directory=Path(directory);self.validate=validate
    @staticmethod
    def references(root):return root.get('archives',[])
    def create_directory(self,path,exclusive=False):
        if os.name=='nt':return self.c.win.mkdir(path,exclusive)
        path=Path(path)
        with self.c.directory(path.parent) as parent:
            try:os.mkdir(path.name,mode=0o700,dir_fd=parent)
            except FileExistsError:
                if exclusive:raise
            os.fsync(parent)
        with self.c.directory(path):pass
    def read(self,digest):
        self.f.unhex(digest,32)
        raw=self.c.read_private(self.directory/(digest+'.page'))
        if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('journal page digest')
        page=self.f.open_sealed(raw,self.password,PAGE_KIND)
        self.validate(page,self.wallet)
        if page['version']!=1 or not page['attempts']:raise ValueError('journal page schema')
        # Pages retain the original confirmation evidence, but current chain
        # reconciliation can turn any archived payment back into UNKNOWN.
        if any(a['status']!='CONFIRMED' or a['transaction_id'] is None for a in page['attempts']):raise ValueError('journal page eligibility')
        return page
    def pages(self,root):
        references=self.references(root)
        if references:
            with self.c.directory(self.directory):pass
        for digest in references:yield self.read(digest)
    def attempts(self,root):
        for page in self.pages(root):yield from page['attempts']
        yield from root['attempts']
    def archive(self,root,publish):
        """Caller must first reconcile against a fresh consistent observation."""
        if len(root['attempts'])<ACTIVE_LIMIT:return root
        confirmed=[a for a in root['attempts'] if a['status']=='CONFIRMED' and a['transaction_id'] is not None]
        if not confirmed:raise ValueError('active journal full; wait for reconciliation')
        references=self.references(root)
        if len(references)>=MAX_PAGES:raise ValueError('journal archive capacity; preserve all evidence')
        # A new private directory, or an existing owner-only non-symlink one.
        self.create_directory(self.directory)
        # Interrupted root publication retains orphan pages. Bound physical
        # entries too: repeated failures must not create unlimited ciphertext.
        with self.c.directory(self.directory) as directory:
            with os.scandir(directory) as entries:
                for count,_ in enumerate(entries,1):
                    if count>=MAX_PAGES+1:raise ValueError('journal directory capacity; preserve all evidence')
        page=dict(version=1,wallet_id=self.f.wallet_id(self.wallet),attempts=confirmed)
        self.validate(page,self.wallet)
        raw=self.f.seal(page,self.password,PAGE_KIND);digest=hashlib.sha256(raw).hexdigest()
        self.c.write_private(self.directory/(digest+'.page'),raw)
        updated=dict(version=2,wallet_id=root['wallet_id'],archives=[*references,digest],attempts=[a for a in root['attempts'] if a not in confirmed])
        self.validate(updated,self.wallet)
        publish(updated)  # atomic encrypted root publication after page fsync
        return updated
    def copy_to(self,root,destination):
        if not self.references(root):return
        destination=Path(destination);self.create_directory(destination,exclusive=True)
        for digest in self.references(root):
            self.read(digest)  # authenticate every page before publishing a copy
            raw=self.c.read_private(self.directory/(digest+'.page'))
            if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('changed journal page')
            self.c.write_private(destination/(digest+'.page'),raw)
