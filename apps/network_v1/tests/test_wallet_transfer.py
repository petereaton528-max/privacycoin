"""Real local encryption/publication tests; synthetic journal is not chain evidence."""
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

@unittest.skipUnless(os.name=='posix','Reviewed POSIX wallet storage; Windows port unavailable')
class TransferTests(unittest.TestCase):
    def setUp(self):
        from apps.network_v1.desktop_backend import Session,c,f
        from apps.network_v1.wallet_transfer import export,import_wallet
        self.c=c;self.f=f;self.export=export;self.restore=import_wallet
        self.tmp=tempfile.TemporaryDirectory(dir=Path.home(),prefix='pc-v1-rc5-recovery-test-')
        self.base=Path(self.tmp.name);self.base.chmod(0o700)
        self.session=Session(self.base/'wallets',34181);self.password='Test-only-'+secrets.token_hex(24)
        self.address=self.session.dispatch(dict(command='create',name='Original',password=self.password))['address']
        from apps.network_v1.rpc import PROFILE,GENESIS
        self.session.previous=dict(version=1,profile=PROFILE,wallet_id=f.wallet_id(self.session.wallet),tip=GENESIS,height=10000,work=10000,scan={})
        self.session.journal['attempts']=[dict(token=secrets.token_hex(32),status='UNKNOWN',transaction_id=None,destination=self.address,amount=1,fee=1,created=100)]
        self.bundle=self.base/'portable.pc-recovery';self.export(self.session,self.bundle)
    def tearDown(self):self.session.close();self.tmp.cleanup()
    def load(self,name='Imported',**kw):
        q=dict(source=self.bundle,name=name,password=self.password,format='portable',consent='IMPORT SAME TESTNET WALLET');q.update(kw)
        return self.restore(self.session,**q)
    def test_identity_unknown_journal_highwater_and_no_overwrite(self):
        before=self.c.read_private(self.session.file);journal=self.session.journal
        self.assertEqual(self.load()['address'],self.address)
        self.assertTrue(self.session.journal==journal);self.assertEqual(self.session.previous['height'],10000)
        with self.assertRaises(ValueError):self.session.dispatch(dict(command='prepare',destination=self.address,amount=1,fee=1,max_fee=1))
        self.assertTrue(self.c.read_private(self.base/'wallets/Original.wallet')==before)
        with self.assertRaises((ValueError,OSError)):self.load()
        with self.assertRaises(ValueError):self.export(self.session,self.bundle)

    def test_cache_anchor_stays_bounded_and_preserves_legacy_highwater(self):
        from unittest.mock import patch
        state=dict(tip=self.session.previous['tip'],height=10000)
        scan={'owned':[{'amount':1,'transaction':'f'*64}]*60000,'eligible':list(range(60000))}
        path=Path(str(self.session.file)+'.phase6a-cache')
        journal=self.session.journal.copy()
        with patch.object(self.c,'observe',return_value=(state,scan,{'chain_trust':'TRUSTED_LOCAL_VALIDATING_ANCHOR'},10000)):
            observed=self.session.observation()
        self.assertIs(observed[1],scan)
        anchor=self.c.read_cache(path,self.session.wallet,self.session.password)
        self.assertLess(path.stat().st_size,2048);self.assertEqual(anchor['scan'],{})
        self.assertEqual((anchor['height'],anchor['work']),(10000,10000))
        self.assertTrue(self.session.journal==journal)
        legacy=dict(anchor,scan={'owned':[{'amount':7}],'eligible':[0]})
        self.c.write_private(path,self.c.f.seal(legacy,self.session.password,self.c.CACHE_KIND),replace=True)
        self.assertEqual(self.c.read_cache(path,self.session.wallet,self.session.password),legacy)

    def test_private_command_schema_and_archived_prediction_rejected(self):
        from apps.network_v1.desktop_backend import Product
        product=Product.__new__(Product);product.session=self.session
        for command in ('prediction_enable','prediction_view','prediction_bet','prediction_disable'):
            with self.assertRaisesRegex(ValueError,'PREDICTION_ARCHIVED'):
                product.dispatch(dict(command=command))
        for value in (dict(command='wallet_export'),dict(command='wallet_import'),dict(command='upgrade_check'),dict(command='wallet_export',destination=str(self.bundle),unexpected=True)):
            with self.assertRaisesRegex(ValueError,'SCHEMA'):product.dispatch(value)
    def test_wrong_password_corruption_network_and_source_symlink(self):
        with self.assertRaises(ValueError):self.load(password='Wrong-'+secrets.token_hex(24))
        bad=self.base/'damaged';raw=self.c.read_private(self.bundle);self.c.write_private(bad,raw[:-1])
        with self.assertRaises(ValueError):self.load(source=bad)
        from apps.network_v1.wallet_transfer import KIND
        value=self.f.open_sealed(raw,self.password.encode(),KIND);value['genesis']='f'*64
        foreign=self.base/'foreign';self.c.write_private(foreign,self.f.seal(value,self.password.encode(),KIND))
        with self.assertRaisesRegex(ValueError,'RECOVERY_NETWORK'):self.load(source=foreign)
        link=self.base/'link';link.symlink_to(self.bundle)
        with self.assertRaises(OSError):self.load(source=link)
        self.assertFalse((self.base/'wallets/Imported.wallet').exists())
    def test_interruption_before_authority_retains_reservations_and_refuses_retry(self):
        writer=self.c.write_private
        def interrupted(p,raw,*args,**kw):
            if Path(p).name=='Interrupted.wallet':raise OSError('TEST_CUT_BEFORE_AUTHORITY')
            return writer(p,raw,*args,**kw)
        with patch.object(self.c,'write_private',side_effect=interrupted):
            with self.assertRaises(OSError):self.load(name='Interrupted')
        self.assertFalse((self.base/'wallets/Interrupted.wallet').exists())
        self.assertTrue((self.base/'wallets/Interrupted.wallet.gui-state').exists())
        with self.assertRaises(ValueError):self.load(name='Interrupted')
    def test_export_interruption_has_no_partial_publication(self):
        writer=self.c.write_private;target=self.base/'interrupted.pc-recovery'
        def interrupted(p,raw,*args,**kw):
            def cut(stage):
                if stage=='before_publish':raise OSError('TEST_CUT_EXPORT')
            return writer(p,raw,*args,**dict(kw,fault=cut))
        with patch.object(self.c,'write_private',side_effect=interrupted):
            with self.assertRaises(OSError):self.export(self.session,target)
        self.assertFalse(target.exists())
    def test_raw_wallet_requires_authenticated_sidecars(self):
        source=self.session.file;self.session.close()
        with self.assertRaises(FileNotFoundError):self.load(source=source,format='wallet-v1')

if __name__=='__main__':unittest.main()
