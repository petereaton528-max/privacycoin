import datetime
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from apps.network_v1.index import Index
from apps.network_v1.peers import discover
from apps.network_v1.rpc import GENESIS, NETWORK, PROFILE, rpc
from apps.network_v1.sdk import Client
from apps.network_v1.server import Server

A, B, C = '1'*64, '2'*64, '3'*64


class NativeFixture:
    def describe(self, raw):
        return json.loads(raw)
    def verify(self, key, block, alias, sig):
        return sig == block+'/'+alias


class ChainFixture:
    def __init__(self, chain):
        self.chain = chain
        self.unstable = False
        self.count = 0
    def __call__(self, _port, command, **q):
        if command == 'chain':
            self.count += 1
            ids = self.chain if not self.unstable or self.count % 2 else [GENESIS]
            return dict(chain=ids)
        h = self.chain.index(q['hash'])
        d = dict(hash=q['hash'], parent=self.chain[h-1] if h else '0'*64,
                 timestamp=1767225600+h*86400, reward=1000000000001,
                 output_key='a'*64, R='b'*64, transaction_count=0)
        return dict(block=json.dumps(d), height=h, work=str(h))


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.index = Index(Path(self.temp.name)/'public.sqlite', NativeFixture())
    def tearDown(self):
        self.index.close(); self.temp.cleanup()

    def test_reorg_and_utc_leaderboard_and_restore(self):
        self.index.refresh(1, ChainFixture([GENESIS,A,B]))
        self.index.claim(A,'alice',A+'/alice'); self.index.claim(B,'alice',B+'/alice')
        self.assertEqual(self.index.leaderboard()['entries'][0]['blocks'],2)
        self.assertEqual(self.index.leaderboard('2026-01-02')['entries'][0]['blocks'],1)
        self.index.refresh(1, ChainFixture([GENESIS,A,C]))
        self.assertEqual(self.index.leaderboard()['entries'][0]['blocks'],1)
        self.assertIsNone(self.index.block(B))
        self.index.refresh(1, ChainFixture([GENESIS,A,B]))
        self.assertEqual(self.index.leaderboard()['entries'][0]['blocks'],2)
        dest=Path(self.temp.name)/'backup.sqlite';self.index.backup(dest)
        restored=Index(dest,NativeFixture())
        try:self.assertEqual(restored.leaderboard(),self.index.leaderboard())
        finally:restored.close()
        with self.assertRaises(FileExistsError):self.index.backup(dest)

    def test_no_partial_refresh_or_bad_claim(self):
        self.index.refresh(1, ChainFixture([GENESIS,A]))
        prior=self.index.state()
        with self.assertRaises(ValueError):self.index.refresh(1,ChainFixture([GENESIS]+[B]*2048))
        unstable=ChainFixture([GENESIS,A,B]);unstable.unstable=True
        with self.assertRaises(ValueError):self.index.refresh(1,unstable)
        self.assertEqual(self.index.state(),prior)
        with self.assertRaises(ValueError):self.index.claim(A,'alice','wrong')
        self.index.claim(A,'alice',A+'/alice')
        with self.assertRaises(ValueError):self.index.claim(A,'bob',A+'/bob')
        with self.assertRaises(ValueError):self.index.claim(B,'bob',B+'/bob')
        with self.assertRaises(ValueError):self.index.leaderboard('2026-02-30')

    def test_http_boundary_sdk_no_secret_rpc(self):
        self.index.refresh(1,ChainFixture([GENESIS,A]))
        server=Server(0,self.index);thread=threading.Thread(target=server.serve_forever);thread.start()
        port=server.server_port
        try:
            sdk=Client(f'http://127.0.0.1:{port}')
            self.assertEqual(sdk.network()['network'],NETWORK)
            self.assertEqual(len(sdk.blocks()['blocks']),2)
            self.assertNotIn('output_key',sdk.block(A))
            for path,code in [('/api/v1/blocks?limit=101',400),('/api/v1/blocks?limit=1&limit=2',400),('/api/v1/wallet',404),('/../index.py',404)]:
                c=http.client.HTTPConnection('127.0.0.1',port);c.request('GET',path);res=c.getresponse();self.assertEqual(res.status,code);res.read();c.close()
            c=http.client.HTTPConnection('127.0.0.1',port);c.request('GET','/',headers={'Host':'evil.invalid'});self.assertEqual(c.getresponse().status,403);c.close()
            c=http.client.HTTPConnection('127.0.0.1',port);c.request('POST','/api/v1/pay',body='secret-not-logged');self.assertEqual(c.getresponse().status,405);c.close()
            server.tokens=0
            c=http.client.HTTPConnection('127.0.0.1',port);c.request('GET','/api/v1/network');self.assertEqual(c.getresponse().status,429);c.close()
        finally:server.shutdown();server.server_close();thread.join()

    def test_rpc_and_bootstrap_fail_closed(self):
        for cmd in ('submit_tx','shutdown','start_mining','wallet','usage'):
            with self.assertRaises(ValueError):rpc(29881,cmd)
        with self.assertRaises(ValueError):Client('http://example.com')
        m=dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,peers=[dict(onion='a'*56+'.onion',p2p_cert_sha256='b'*64)])
        self.assertEqual(len(discover([m,m])),1)
        m['peers'][0]['p2p_cert_sha256']='x'
        with self.assertRaises(ValueError):discover([m])


if __name__=='__main__':unittest.main()
