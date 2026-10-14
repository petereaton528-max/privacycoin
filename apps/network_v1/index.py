"""Rebuildable public index. Atomic chain replacement, opt-in output-ownership claims.

Ownership proves control of a coinbase output, not physical mining or hashrate.
The local validating node remains the chain trust boundary.
"""
import datetime
import contextlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import threading

from .rpc import GENESIS, rpc


def hex32(v):
    if not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v):
        raise ValueError('HASH')
    return v


def alias_name(v):
    if not isinstance(v, str) or not re.fullmatch('[A-Za-z0-9_-]{1,48}', v):
        raise ValueError('ALIAS')
    return v


class Native:
    def __init__(self, executable):
        self.executable = str(executable)

    def call(self, command):
        p = subprocess.run([self.executable], input=command.encode() + b'\n',
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12)
        if p.returncode or len(p.stdout) > 65536:
            raise ValueError('PUBLIC_NATIVE_REJECTED')
        return p.stdout.decode().strip()

    def describe(self, raw):
        if not isinstance(raw, str) or not re.fullmatch('[0-9a-f]{2,600000}', raw) or len(raw) % 2:
            raise ValueError('BLOCK_BYTES')
        return json.loads(self.call('describe-block ' + raw))

    def verify(self, key, block, alias, signature):
        hex32(key); hex32(block); alias_name(alias)
        if not isinstance(signature, str) or not re.fullmatch('[0-9a-f]{128}', signature):
            raise ValueError('SIGNATURE')
        return self.call('verify-claim ' + ' '.join((key, block, alias, signature))) == 'verified'


class Index:
    def __init__(self, path, native):
        path = Path(path)
        if path.is_symlink() or any(p.is_symlink() for p in path.parents) or any('privacycoin-n2' in p.lower() for p in path.parts):
            raise ValueError('PUBLIC_INDEX_PATH_UNSAFE')
        exists = path.exists()
        if exists:
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('PUBLIC_INDEX_FILE_UNSAFE')
                header = os.read(fd, 100)
                if header[:16] != b'SQLite format 3\0' or header[68:72] != (0x50435631).to_bytes(4, 'big'):
                    raise ValueError('NOT_A_V1_PUBLIC_INDEX')
            finally:
                os.close(fd)
        self.native = native
        self.lock = threading.RLock()
        self.refresh_lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA cache_size=-2048')
        with self.db:
            self.db.execute('PRAGMA application_id=1346590257')
            self.db.execute('PRAGMA user_version=1')
            self.db.execute('CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY,hash TEXT UNIQUE,parent TEXT,timestamp INTEGER,reward TEXT,work TEXT,output_key TEXT,R TEXT,transaction_count INTEGER)')
            self.db.execute('CREATE TABLE IF NOT EXISTS claims(block TEXT PRIMARY KEY,alias TEXT,signature TEXT)')
            self.db.execute('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT)')

    def refresh(self, port, call=rpc, stop=None, force=False):
        def snapshot():
            page = call(port, 'chain',metadata_only=1); ids = page['chain']; tip = page.get('tip')
            if not isinstance(ids,list) or not 1<=len(ids)<=1024:raise ValueError('CHAIN_LIMIT_OR_IDENTITY')
            if 'next' in page:
                if type(page.get('total')) is not int or type(page['next']) is not int or not 1<=page['total']<2**64 or page['next']!=len(ids) or not 1<=len(ids)<=1024 or page['next']>page['total']:
                    raise ValueError('CHAIN_PAGE_BOUNDS')
                hex32(tip)
            yield from ids
            while 'next' in page and page['next'] < page['total']:
                if stop is not None and stop.is_set():raise ValueError('INDEX_CANCELLED')
                offset=page['next']; total=page['total']
                page=call(port,'chain',offset=offset,count=1024,tip=tip,metadata_only=1)
                if page.get('tip')!=tip or type(page.get('total')) is not int or page.get('total')!=total or type(page.get('next')) is not int or page.get('next')!=offset+len(page['chain']) or page['next']>total or not 0<len(page['chain'])<=1024:
                    raise ValueError('CHAIN_PAGE_CHANGED')
                yield from page['chain']
        # SQLite's unnamed temporary database is deleted on close. Stage on disk
        # with bounded page caches, keeping the published index readable while
        # parsing. Cancellation/reorg/error never publishes a partial suffix.
        with self.refresh_lock, contextlib.closing(sqlite3.connect('')) as stage:
            stage.execute('PRAGMA cache_size=-2048')
            stage.execute('CREATE TABLE chain(height INTEGER PRIMARY KEY,hash TEXT UNIQUE)')
            stage.execute('CREATE TABLE suffix(height INTEGER PRIMARY KEY,hash TEXT,parent TEXT,timestamp INTEGER,reward TEXT,work TEXT,output_key TEXT,R TEXT,transaction_count INTEGER)')
            common=0;length=0;parent=None
            for height,h in enumerate(snapshot()):
                hex32(h)
                if height==0 and h!=GENESIS:raise ValueError('CHAIN_LIMIT_OR_IDENTITY')
                if stop is not None and stop.is_set():raise ValueError('INDEX_CANCELLED')
                try:stage.execute('INSERT INTO chain VALUES(?,?)',(height,h))
                except sqlite3.IntegrityError:raise ValueError('CHAIN_LIMIT_OR_IDENTITY') from None
                with self.lock:
                    cached=self.db.execute('SELECT hash,parent FROM blocks WHERE height=?',(height,)).fetchone()
                if not force and common==height and cached and cached['hash']==h and (height==0 or cached['parent']==parent):
                    common+=1
                else:
                    b=call(port,'get_block',hash=h)
                    if stop is not None and stop.is_set():raise ValueError('INDEX_CANCELLED')
                    d=self.native.describe(b['block'])
                    if d['hash']!=h or b['height']!=height or (height and d['parent']!=parent):raise ValueError('CHAIN_INCONSISTENT')
                    ts=d['timestamp'];reward=d.get('reward',0) if height else 0
                    if type(ts) is not int or not 0<=ts<=253402300799:raise ValueError('TIMESTAMP')
                    if type(reward) is not int or not 0<=reward<2**64 or not str(b['work']).isdigit():raise ValueError('PUBLIC_AMOUNT')
                    stage.execute('INSERT INTO suffix VALUES(?,?,?,?,?,?,?,?,?)',(height,h,d['parent'],ts,str(reward),str(b['work']),d.get('output_key'),d.get('R'),d['transaction_count']))
                length=height+1;parent=h
            if not length:raise ValueError('CHAIN_LIMIT_OR_IDENTITY')
            checked=0
            for height,h in enumerate(snapshot()):
                row=stage.execute('SELECT hash FROM chain WHERE height=?',(height,)).fetchone()
                if row is None or row[0]!=h:raise ValueError('CHAIN_CHANGED_RETRY_LATER')
                checked=height+1
            if checked!=length:raise ValueError('CHAIN_CHANGED_RETRY_LATER')
            if stop is not None and stop.is_set():raise ValueError('INDEX_CANCELLED')
            with self.lock,self.db:
                self.db.execute('DELETE FROM blocks WHERE height>=?',(common,))
                self.db.executemany('INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?,?)',stage.execute('SELECT * FROM suffix ORDER BY height'))
                self.db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',('indexed_at',datetime.datetime.now(datetime.timezone.utc).isoformat()))
            return length

    def claim(self, block, alias, signature):
        hex32(block); alias_name(alias)
        with self.lock:
            row = self.db.execute('SELECT * FROM blocks WHERE hash=? AND height>0', (block,)).fetchone()
            if row is None or not self.native.verify(row['output_key'], block, alias, signature):
                raise ValueError('OWNERSHIP_PROOF_REQUIRED')
            prior = self.db.execute('SELECT alias FROM claims WHERE block=?', (block,)).fetchone()
            if prior and prior['alias'] != alias:
                raise ValueError('CLAIM_CONFLICT')
            with self.db:
                self.db.execute('INSERT OR IGNORE INTO claims VALUES(?,?,?)', (block, alias, signature))

    def blocks(self, offset=0, limit=25):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('PAGE')
        with self.lock:
            return [dict(x) for x in self.db.execute('SELECT height,hash,parent,timestamp,reward,work,transaction_count FROM blocks ORDER BY height DESC LIMIT ? OFFSET ?', (limit, offset))]

    def block(self, block):
        hex32(block)
        with self.lock:
            row = self.db.execute('SELECT height,hash,parent,timestamp,reward,work,transaction_count FROM blocks WHERE hash=?', (block,)).fetchone()
            return dict(row) if row else None

    def state(self):
        with self.lock:
            tip = self.db.execute('SELECT height,hash,work FROM blocks ORDER BY height DESC LIMIT 1').fetchone()
            time = self.db.execute('SELECT value FROM meta WHERE key=?', ('indexed_at',)).fetchone()
            return dict(tip=dict(tip) if tip else None, indexed_at=time[0] if time else None,
                        global_freshness='UNKNOWN', source='ONE_LOCAL_VALIDATING_NODE',
                        public_release='BLOCKED', n2_r1_ready=False)

    def leaderboard(self, day=None):
        if day is not None:
            try:
                date = datetime.date.fromisoformat(day)
            except (ValueError, TypeError):
                raise ValueError('UTC_DAY') from None
            if date.isoformat() != day:
                raise ValueError('UTC_DAY')
            start = int(datetime.datetime.combine(date, datetime.time(), datetime.timezone.utc).timestamp())
        with self.lock:
            tip=self.db.execute('SELECT MAX(height) FROM blocks').fetchone()[0] or 0
            query = 'SELECT c.alias,b.hash,b.timestamp,b.reward,b.height FROM claims c JOIN blocks b ON b.hash=c.block WHERE b.height>0'
            args = ()
            if day:
                query += ' AND b.timestamp>=? AND b.timestamp<?'
                args = (start, start+86400)
            grouped = {}
            for row in self.db.execute(query, args):
                record = grouped.setdefault(row['alias'], dict(alias=row['alias'], blocks=0, confirmed_blocks=0,provisional_blocks=0,reward_atomic='0', block_hashes=[]))
                record['blocks'] += 1
                record['confirmed_blocks' if tip-row['height']+1>=10 else 'provisional_blocks']+=1
                record['reward_atomic'] = str(int(record['reward_atomic']) + int(row['reward']))
                record['block_hashes'].append(row['hash'])
            return dict(day=day, time_basis='UTC_ON_CHAIN_TIMESTAMP', metric='VOLUNTARY_COINBASE_OUTPUT_OWNERSHIP_COUNT',
                        hashrate='NOT_MEASURED', identity='SELF_SELECTED_ALIAS_NOT_UNIQUE_PERSON',confirmation_policy='10_LOCAL_CANONICAL_CONFIRMATIONS; COUNTS_INCLUDE_LABELED_PROVISIONAL',
                        entries=sorted(grouped.values(), key=lambda x: (-x['blocks'], x['alias'])))

    def export_claims(self):
        from .rpc import NETWORK,GENESIS,PROFILE
        with self.lock:
            rows=[dict(x) for x in self.db.execute('SELECT block,alias,signature FROM claims ORDER BY block')]
            if len(rows)>2048:raise ValueError('CLAIM_DOCUMENT_BOUND')
            return dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,claims=rows)

    def import_claims(self,document):
        from .rpc import NETWORK,GENESIS,PROFILE
        if not isinstance(document,dict) or set(document)!={'version','network','genesis','profile','claims'} or document['version']!=1 or (document['network'],document['genesis'],document['profile'])!=(NETWORK,GENESIS,PROFILE) or not isinstance(document['claims'],list) or len(document['claims'])>2048:raise ValueError('CLAIM_DOCUMENT')
        with self.lock:
            checked={}
            for item in document['claims']:
                if not isinstance(item,dict) or set(item)!={'block','alias','signature'}:raise ValueError('CLAIM_SCHEMA')
                block=hex32(item['block']);alias_name(item['alias'])
                if block in checked and checked[block]!=item:raise ValueError('CLAIM_CONFLICT')
                row=self.db.execute('SELECT output_key FROM blocks WHERE hash=? AND height>0',(block,)).fetchone()
                if row is None or not self.native.verify(row['output_key'],block,item['alias'],item['signature']):raise ValueError('INDEX_CANONICAL_BLOCK_BEFORE_IMPORT')
                prior=self.db.execute('SELECT alias,signature FROM claims WHERE block=?',(block,)).fetchone()
                if prior and dict(prior)!={k:item[k] for k in ('alias','signature')}:raise ValueError('CLAIM_CONFLICT')
                checked[block]=item
            with self.db:self.db.executemany('INSERT OR IGNORE INTO claims VALUES(?,?,?)',[(x['block'],x['alias'],x['signature']) for x in checked.values()])
            return len(checked)

    def backup(self, destination):
        """Only this rebuildable PUBLIC index, never a node/wallet/Provider backup."""
        p = Path(destination)
        with p.open('xb'):
            pass
        try:
            with self.lock, contextlib.closing(sqlite3.connect(p)) as target:
                self.db.backup(target)
                if target.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise ValueError('INDEX_BACKUP_INTEGRITY')
        except BaseException:
            # Retain failed destination for inspection; never label it successful.
            raise

    def close(self):
        self.db.close()
