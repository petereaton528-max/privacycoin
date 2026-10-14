"""Non-launchable supply-state prototype, NOT a blockchain implementation.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import json,os,re,sqlite3
from pathlib import Path
from .model import natural,subsidy
class DraftAccounting:
    def __init__(self,path,genesis,allocation,*,create=False,network_tag='d'*64):
        self.path=Path(path);allocation=natural(allocation)
        if not self.path.is_absolute() or self.path.is_symlink() or any('privacycoin-n2' in x.lower() for x in self.path.parts):raise ValueError('ISOLATED_DRAFT_PATH_REQUIRED')
        if not re.fullmatch('[0-9a-f]{64}',genesis):raise ValueError('GENESIS_ID')
        if not re.fullmatch('[0-9a-f]{64}',network_tag):raise ValueError('DRAFT_NETWORK_ID')
        if create and self.path.exists():raise ValueError('NO_GENESIS_REISSUANCE')
        if not create and not self.path.is_file():raise ValueError('EXISTING_DRAFT_REQUIRED')
        if create:
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600);os.close(fd)
        self.db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True)
        try:
            if create:
                self.db.execute('PRAGMA application_id=1346585682')
                self.db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY CHECK(id=1),genesis TEXT NOT NULL,network_tag TEXT NOT NULL,allocation TEXT NOT NULL,mined TEXT NOT NULL,total TEXT NOT NULL,height INTEGER NOT NULL)')
                self.db.execute('INSERT INTO state VALUES(1,?,?,?,?,?,0)',(genesis,network_tag,str(allocation),'0',str(allocation)));self.db.commit()
            if self.db.execute('PRAGMA application_id').fetchone()[0]!=1346585682:raise ValueError('NOT_DRAFT_ACCOUNTING_DATABASE')
            self.genesis=genesis;self.network_tag=network_tag;self.allocation=allocation;self.state()
        except BaseException:self.db.close();raise
    def state(self):
        row=self.db.execute('SELECT genesis,network_tag,allocation,mined,total,height FROM state WHERE id=1').fetchone()
        if not row or row[0]!=self.genesis or row[1]!=self.network_tag or row[2]!=str(self.allocation):raise ValueError('DRAFT_GENESIS_NETWORK_MISMATCH')
        mined,total=map(int,row[3:5]);natural(mined);natural(total)
        if total!=self.allocation+mined or type(row[5]) is not int or row[5]<0:raise ValueError('SUPPLY_INVARIANT')
        return dict(genesis=row[0],network_tag=row[1],allocation=self.allocation,mined=mined,total=total,height=row[5])
    def append(self,height,reward,creator_issuance=0):
        if type(creator_issuance) is not int or creator_issuance!=0:raise ValueError('CREATOR_ISSUANCE_ONLY_IN_GENESIS')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE');state=self.state()
            if type(height) is not int or height!=state['height']+1 or type(reward) is not int or reward!=subsidy(state['mined']):raise ValueError('DRAFT_BLOCK_ACCOUNTING')
            mined=natural(state['mined']+reward);total=natural(mined+self.allocation)
            self.db.execute('UPDATE state SET mined=?,total=?,height=? WHERE id=1',(str(mined),str(total),height))
        return self.state()
    def close(self):self.db.close()
