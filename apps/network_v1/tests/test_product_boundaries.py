import http.client
from pathlib import Path
import tempfile
import threading
import unittest
from apps.network_v1.index import Index
from apps.network_v1.sdk import Client,APIError
from apps.network_v1.server import Server
from apps.network_v1.tests.test_application import NativeFixture,ChainFixture,A,B,C,GENESIS


class ProductBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.index=Index(Path(self.temp.name)/'index.sqlite',NativeFixture())
    def tearDown(self):self.index.close();self.temp.cleanup()
    def test_proofs_replay_confirmation_duplicate_and_atomic_rejection(self):
        chain=[GENESIS,A,B];self.index.refresh(1,ChainFixture(chain));self.index.claim(A,'alice',A+'/alice');doc=self.index.export_claims()
        other=Index(Path(self.temp.name)/'other.sqlite',NativeFixture())
        try:
            other.refresh(1,ChainFixture(chain));self.assertEqual(other.import_claims(doc),1);self.assertEqual(other.import_claims(doc),1)
            self.assertEqual(other.leaderboard(),self.index.leaderboard());self.assertEqual(other.leaderboard()['entries'][0]['provisional_blocks'],1)
            bad=dict(doc,claims=[doc['claims'][0],dict(block=B,alias='mallory',signature='wrong')])
            with self.assertRaises(ValueError):other.import_claims(bad)
            self.assertEqual(other.export_claims(),doc)
            more=chain+[f'{n:064x}' for n in range(10,21)];other.refresh(1,ChainFixture(more));self.assertEqual(other.leaderboard()['entries'][0]['confirmed_blocks'],1)
            other.refresh(1,ChainFixture([GENESIS,C]));self.assertEqual(other.leaderboard()['entries'],[])
            other.refresh(1,ChainFixture(more));self.assertEqual(other.leaderboard()['entries'][0]['confirmed_blocks'],1)
        finally:other.close()
    def test_origin_and_sdk_error_authority_boundary(self):
        self.index.refresh(1,ChainFixture([GENESIS,A]));server=Server(0,self.index);thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            for path in ('/','/app.js','/style.css'):
                c=http.client.HTTPConnection('127.0.0.1',server.server_port);c.request('GET',path);reply=c.getresponse();self.assertEqual(reply.status,200);self.assertTrue(reply.read());c.close()
            for headers in ({'Origin':'https://evil.invalid'},{'Sec-Fetch-Site':'cross-site'}):
                c=http.client.HTTPConnection('127.0.0.1',server.server_port);c.request('GET','/api/v1/network',headers=headers);reply=c.getresponse();self.assertEqual(reply.status,403);reply.read();c.close()
            api=Client('http://127.0.0.1:'+str(server.server_port))
            with self.assertRaises(APIError) as captured:api.get('/api/v1/wallet')
            self.assertEqual(captured.exception.status,404);self.assertFalse(captured.exception.retryable)
            with self.assertRaises(APIError):api.get('//evil.invalid/')
            with self.assertRaises(ValueError):Client('https://example.invalid')
        finally:server.shutdown();server.server_close();thread.join()


if __name__=='__main__':unittest.main()
