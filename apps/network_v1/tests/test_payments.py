import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from apps.network_v1.payments import Payments


@unittest.skipUnless(os.name=='posix','Secret-bearing local wallet facade requires POSIX/WSL')
class PaymentTests(unittest.TestCase):
    def setUp(self):
        from src.phase6a import wallet as c
        self.c=c
        self.temp=tempfile.TemporaryDirectory(dir=Path.home(),prefix='pc-v1-payment-fixture-')
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        class Client:
            def __init__(self):
                self.count=0;self.state='MEMPOOL_ONLY';self.home=self_root;self.fail=False
            def quote(self,size):
                self.count+=1
                if self.fail:raise OSError('SYNTHETIC_TIMEOUT')
                return dict(id='1'*64)
            def pay(self,*args):raise OSError('SYNTHETIC_UNKNOWN_SUBMISSION')
            def status(self,qid):return dict(state=self.state)
            def encrypt(self,qid,plain):
                c.write_private(self.home/(qid+'.upload'),c.f.canonical(dict(bundle=dict(plain_hash=hashlib.sha256(plain).hexdigest()))))
            def upload(self,qid):return dict(idempotent=True)
            def export(self,qid,path,password):
                material=c.f.decode(c.read_private(self.home/(qid+'.upload')))
                c.write_private(Path(path),c.f.seal(material['bundle'],password,'privacy-network-retrieval-v01'))
        self_root=self.root
        self.client=Client();self.app=Payments(self.root/'app',self.client,c)
    def tearDown(self):self.temp.cleanup()

    def test_unknown_quote_reservation_no_retry_after_restart(self):
        self.client.fail=True
        with self.assertRaises(OSError):self.app.request('business',3)
        self.client.fail=False;reopened=Payments(self.root/'app',self.client,self.c)
        with self.assertRaises(ValueError):reopened.request('business',3)
        self.assertEqual(self.client.count,1)
        with self.assertRaises(ValueError):reopened.request('business',4)

    def test_unknown_payment_no_reauthorization_and_durable_events(self):
        self.app.request('business',3)
        with self.assertRaises(OSError):self.app.authorize('business',object(),'CONFIRM')
        reopened=Payments(self.root/'app',self.client,self.c)
        with self.assertRaises(ValueError):reopened.authorize('business',object(),'CONFIRM')
        self.assertFalse(reopened.observe('business')['entitled'])
        self.client.state='CONFIRMED_LOCAL';self.assertTrue(reopened.observe('business')['entitled'])
        self.client.state='REVOKED_RECONCILE';self.assertFalse(reopened.observe('business')['entitled'])
        events=reopened.events('business');self.assertEqual(len(events),3)
        reopened.acknowledge('business',events[0]['id']);reopened.acknowledge('business',events[0]['id'])
        self.assertEqual(len(reopened.events('business')),2)

    def test_missing_original_ciphertext_never_reencrypted(self):
        self.app.request('business',3);self.app.deliver('business',b'abc')
        with self.assertRaises(ValueError):self.app.deliver('business',b'xyz')
        (self.root/('1'*64+'.upload')).unlink()
        with self.assertRaises(ValueError):self.app.deliver('business',b'abc')
        self.assertFalse((self.root/('1'*64+'.upload')).exists())

    def test_sdk_encrypted_recovery_export_offline_and_no_clobber(self):
        self.app.request('business',3)
        target=self.root/'retrieval.backup';password=b'disposable fixture password'
        with self.assertRaises(ValueError):self.app.export_recovery('business',target,password)
        self.app.deliver('business',b'abc');self.client.state='REVOKED_RECONCILE'
        result=self.app.export_recovery('business',target,password)
        self.assertTrue(result['encrypted_recovery_exported'])
        raw=self.c.read_private(target)
        material=self.c.f.open_sealed(raw,password,'privacy-network-retrieval-v01')
        self.assertEqual(material['plain_hash'],hashlib.sha256(b'abc').hexdigest())
        with self.assertRaises(ValueError):self.c.f.open_sealed(raw,b'incorrect','privacy-network-retrieval-v01')
        with self.assertRaises((ValueError,FileExistsError)):self.app.export_recovery('business',target,password)
        self.assertEqual(self.c.read_private(target),raw)
        upload=self.client.home/('1'*64+'.upload')
        self.c.write_private(upload,self.c.f.canonical(dict(bundle=dict(plain_hash='0'*64))),replace=True)
        other=self.root/'tampered.backup'
        with self.assertRaisesRegex(ValueError,'ORIGINAL_UPLOAD_REQUIRED'):self.app.export_recovery('business',other,password)
        self.assertFalse(other.exists())

if __name__=='__main__':unittest.main()
