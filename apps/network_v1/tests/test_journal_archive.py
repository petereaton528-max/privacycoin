"""Real private encryption/files, synthetic chain membership; no funds or RPC.

Native payment/reorg integration is separately tested. Fixtures are retained.
"""
import hashlib,os,secrets,tempfile,tracemalloc,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

@unittest.skipUnless(os.name=='posix','Private wallet backend is POSIX')
class JournalArchiveTests(unittest.TestCase):
    def setUp(self):
        from apps.network_v1.desktop_backend import Session,c,f
        import backend as b
        self.b=b;self.c=c;self.f=f;self.password=secrets.token_hex(24).encode()
        parent=Path.home()/'pc-v1-fixtures-rc5-journal-units';parent.mkdir(mode=0o700,exist_ok=True)
        self.home=Path(tempfile.mkdtemp(prefix='case-',dir=parent));self.s=Session(self.home,48081)
        self.wallet=f.full();self.file=self.home/'alice.wallet';c.save(self.file,self.wallet,self.password);self.s.unlock(self.file,self.password)
        self.address=f.address(self.wallet,0);self.ids=[]
    def tearDown(self):self.s.close()
    def attempts(self,start=0,count=128,status='CONFIRMED'):
        result=[]
        for i in range(start,start+count):
            txid=hashlib.sha256((self.f.wallet_id(self.wallet)+str(i)).encode()).hexdigest();self.ids.append(txid)
            result.append(dict(token=secrets.token_hex(32),status=status,transaction_id=txid,destination=self.address,amount=1,fee=1,created=i))
        return result
    def seed(self,count=128):
        self.s.journal=dict(version=1,wallet_id=self.f.wallet_id(self.wallet),attempts=self.attempts(count=count));self.s.persist()
    def archive(self,publish=None):
        if publish is None:publish=lambda root:self.c.write_private(self.s.journal_path,self.f.seal(root,self.password,'gui-pilot-state'),replace=True)
        self.s.journal=self.s.store().archive(self.s.journal,publish)
    def state(self,ids=None,pool=()):
        return dict(chain=[dict(id=x,pending=False) for x in (self.ids if ids is None else ids)],pool=[dict(id=x) for x in pool],height=999,tip='f'*64)
    def observe(self,state):
        self.s.observation=lambda:(state,dict(owned=[]),dict(chain_trust='TRUSTED_LOCAL_VALIDATING_ANCHOR',signing_available=True,spendable=100000),1)
    def prepare(self):
        self.observe(self.state())
        plan=SimpleNamespace(display=lambda:dict(destination=self.address,amount=1,fee=1))
        with patch.object(self.c,'prepare',return_value=plan):return self.s.dispatch(dict(command='prepare',destination=self.address,amount=1,fee=1,max_fee=10))
    def test_legacy_full_journal_archives_before_new_prepare(self):
        self.seed();self.prepare()
        self.assertEqual(self.s.journal['version'],2);self.assertEqual(len(self.s.journal['attempts']),0)
        self.assertEqual(len(self.s.journal['archives']),1);self.assertEqual(len(list(self.s.store().attempts(self.s.journal))),128)
        self.s.close();self.s.unlock(self.file,self.password);self.assertEqual(self.s.refresh()['outgoing_total'],128)
    def test_unresolved_never_archived_or_permitted_to_pay(self):
        self.seed();self.s.journal['attempts'][0].update(status='UNKNOWN',transaction_id=None);self.s.persist()
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(self.s.journal['version'],1);self.assertEqual(len(self.s.journal['attempts']),128)
    def test_pending_active_bound_waits_for_confirmation(self):
        self.seed();self.observe(self.state(ids=[],pool=self.ids))
        with self.assertRaises(ValueError):self.s.dispatch(dict(command='prepare',destination=self.address,amount=1,fee=1,max_fee=10))
        self.assertTrue(all(a['status']=='PENDING' for a in self.s.journal['attempts']))
    def test_archived_reorganization_blocks_even_when_outside_recent_window(self):
        self.seed();self.archive();self.s.journal['attempts']=self.attempts(128);self.s.persist();self.archive()
        self.observe(self.state(self.ids[1:]));page=self.s.refresh()
        self.assertEqual(page['unknown_attempts'],1);self.assertEqual(len(page['outgoing']),128)
        self.assertFalse(page['balance']['signing_available']);self.assertIsNone(page['balance']['spendable'])
        with patch.object(self.c,'prepare') as prepare:
            with self.assertRaises(ValueError):self.s.dispatch(dict(command='prepare',destination=self.address,amount=1,fee=1,max_fee=10))
            prepare.assert_not_called()
    def test_page_then_root_interruption_preserves_old_root_and_orphan_page(self):
        self.seed();before=self.c.read_private(self.s.journal_path)
        def fail(_):raise OSError('isolated before root publication')
        with self.assertRaises(OSError):self.archive(fail)
        self.assertTrue(self.c.read_private(self.s.journal_path)==before)
        self.assertEqual(len(list(self.s.store().directory.glob('*.page'))),1)
        self.s.close();self.s.unlock(self.file,self.password);self.archive()
        self.assertEqual(len(list(self.s.store().attempts(self.s.journal))),128)
        self.assertEqual(len(list(self.s.store().directory.glob('*.page'))),2)
    def test_root_committed_then_interrupted_recovers_new_state(self):
        self.seed()
        def publish(root):
            def fault(stage):
                if stage=='after_publish':raise OSError('isolated after durable root')
            self.c.write_private(self.s.journal_path,self.f.seal(root,self.password,'gui-pilot-state'),replace=True,fault=fault)
        with self.assertRaises(OSError):self.archive(publish)
        self.s.close();self.s.unlock(self.file,self.password)
        self.assertEqual(self.s.journal['version'],2);self.assertEqual(len(list(self.s.store().attempts(self.s.journal))),128)
    def test_missing_or_corrupt_page_fails_closed(self):
        self.seed();self.archive();digest=self.s.journal['archives'][0];p=self.s.store().directory/(digest+'.page');raw=self.c.read_private(p)
        p.rename(p.with_suffix('.retained'))
        with self.assertRaises(FileNotFoundError):self.s.store().read(digest)
        self.c.write_private(p,raw[:-1]+bytes([raw[-1]^1]))
        with self.assertRaises(ValueError):self.s.store().read(digest)
    def test_foreign_wallet_page_and_wrong_password_rejected(self):
        self.seed();self.archive();store=self.s.store();digest=self.s.journal['archives'][0]
        wrong=self.b.j.Store(self.c,self.f,self.wallet,secrets.token_bytes(32),store.directory,self.b.validate_journal)
        with self.assertRaises(ValueError):wrong.read(digest)
        page=store.read(digest);page['wallet_id']=self.f.wallet_id(self.f.full());raw=self.f.seal(page,self.password,self.b.j.PAGE_KIND);other=hashlib.sha256(raw).hexdigest();self.c.write_private(store.directory/(other+'.page'),raw)
        with self.assertRaises(ValueError):store.read(other)
    def test_companion_backup_roundtrip_and_missing_folder_rejection(self):
        self.seed();self.archive();original=self.s.journal.copy();backup=self.s.dispatch(dict(command='backup',name='safe'))
        self.assertTrue(Path(backup['archive_directory']).is_dir())
        self.s.dispatch(dict(command='restore',name='restored',backup='safe',password=self.password.decode()))
        self.assertTrue(self.s.journal==original);self.assertEqual(self.f.wallet_id(self.s.wallet),self.f.wallet_id(self.wallet))
        folder=Path(backup['archive_directory']);folder.rename(folder.with_name('retained-pages'))
        with self.assertRaises(FileNotFoundError):self.b.recovery_bundle(Path(backup['backup']),self.password)
    def test_backup_root_failure_leaves_no_publish_and_preserves_source(self):
        self.seed();self.archive();write=self.c.write_private
        def cut(path,*args,**kwargs):
            if Path(path).suffix=='.backup':raise OSError('isolated backup root cut')
            return write(path,*args,**kwargs)
        with patch.object(self.c,'write_private',side_effect=cut),self.assertRaises(OSError):self.s.dispatch(dict(command='backup',name='cut'))
        self.assertFalse((self.home/'cut.backup').exists());self.assertTrue((self.home/'cut.backup.journal-archive').is_dir())
        self.assertEqual(len(list(self.s.store().attempts(self.s.journal))),128)
        with self.assertRaises(ValueError):self.s.dispatch(dict(command='backup',name='cut'))
        self.s.dispatch(dict(command='backup',name='safe'))
    def test_restore_failure_publishes_no_wallet_and_preserves_backup(self):
        self.seed();self.archive();self.s.dispatch(dict(command='backup',name='safe'));save=self.c.save
        with patch.object(self.c,'save',side_effect=OSError('isolated authority cut')),self.assertRaises(OSError):self.s.dispatch(dict(command='restore',name='cut',backup='safe',password=self.password.decode()))
        self.assertFalse((self.home/'cut.wallet').exists());self.assertTrue((self.home/'cut.wallet.gui-state').exists())
        self.s.dispatch(dict(command='restore',name='safealias',backup='safe',password=self.password.decode()))
    def test_duplicate_confirm_and_uncertain_rpc_reconcile_after_restart(self):
        self.seed();approval=self.prepare();txid=hashlib.sha256(b'isolated uncertain payment').hexdigest();calls=[]
        def execute(wallet,plan,consent,get_state,submit):return submit(dict(id=txid,transaction={}))
        def broadcast(*args,**kwargs):
            saved=self.f.open_sealed(self.c.read_private(self.s.journal_path),self.password,'gui-pilot-state')
            self.assertEqual(saved['attempts'][-1]['transaction_id'],txid);self.assertEqual(saved['attempts'][-1]['status'],'UNKNOWN');calls.append(1);raise OSError('acknowledgment lost')
        request=dict(command='confirm',token=approval['token'],consent='CONFIRM')
        with patch.object(self.c,'execute',side_effect=execute),patch.object(self.b.w,'rpc',side_effect=broadcast):
            with self.assertRaises(OSError):self.s.dispatch(request)
            with self.assertRaises(ValueError):self.s.dispatch(request)
        self.assertEqual(len(calls),1);self.s.close();self.s.unlock(self.file,self.password)
        with self.assertRaises(ValueError):self.prepare()
        self.ids.append(txid);self.prepare();self.assertEqual(self.s.journal['attempts'][-1]['status'],'CONFIRMED')
    def test_private_page_permissions_symlink_and_archive_capacity(self):
        self.seed();self.archive();store=self.s.store();digest=self.s.journal['archives'][0];path=store.directory/(digest+'.page')
        self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertEqual(store.directory.stat().st_mode&0o777,0o700)
        path.rename(path.with_suffix('.retained'));path.symlink_to(path.with_suffix('.retained'))
        with self.assertRaises(OSError):store.read(digest)
        self.s.journal['archives']=['a'*64]*(self.b.j.MAX_PAGES+1)
        with self.assertRaises(ValueError):self.b.validate_journal(self.s.journal,self.wallet)
    def test_1024_attempts_bounded_active_pages_and_recent_output(self):
        self.seed();self.archive()
        for i in range(1,8):self.s.journal['attempts']=self.attempts(i*128);self.s.persist();self.archive()
        self.assertEqual(len(self.s.journal['attempts']),0);self.assertEqual(len(self.s.journal['archives']),8)
        self.observe(self.state());tracemalloc.start();page=self.s.refresh();_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
        self.assertEqual(page['outgoing_total'],1024);self.assertEqual(page['unknown_attempts'],0);self.assertEqual(len(page['outgoing']),128)
        self.assertLess(peak,4*1024*1024);self.assertLess(self.s.journal_path.stat().st_size,4096)
        self.assertTrue(all(p.stat().st_size<128*1024 for p in self.s.store().directory.glob('*.page')))
    def test_private_read_rejects_file_size_change_without_raising_file_bound(self):
        self.seed();checked=self.c.checked
        def changed(fd):
            actual=checked(fd);return SimpleNamespace(st_size=actual.st_size-1)
        with patch.object(self.c,'checked',side_effect=changed),self.assertRaises(ValueError):self.c.read_private(self.s.journal_path)
    def test_portable_export_import_retains_archives_and_rejects_missing_companion(self):
        from apps.network_v1.wallet_transfer import export,import_wallet
        self.seed();self.archive();target=self.home/'portable.pc-recovery'
        export(self.s,target)
        imported=import_wallet(self.s,target,'portablealias',self.password.decode(),'portable','IMPORT SAME TESTNET WALLET')
        self.assertEqual(imported['address'],self.address)
        self.assertEqual(len(list(self.s.store().attempts(self.s.journal))),128)
        folder=Path(str(target)+'.journal-archive');folder.rename(folder.with_name('retained-portable-pages'))
        with self.assertRaises(FileNotFoundError):import_wallet(self.s,target,'missingalias',self.password.decode(),'portable','IMPORT SAME TESTNET WALLET')
        self.assertFalse((self.home/'missingalias.wallet').exists())
    def test_missing_root_with_broken_archive_symlink_fails_closed(self):
        self.seed();root=self.s.journal_path;self.s.close()
        root.rename(root.with_name('retained-root'))
        Path(str(self.file)+'.gui-archive').symlink_to(self.home/'absent-directory',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'missing journal root'):self.s.unlock(self.file,self.password)
    def test_repeated_unpublished_pages_reach_physical_bound_without_deletion(self):
        self.seed();store=self.s.store();store.create_directory(store.directory)
        self.c.write_private(store.directory/'retained-orphan-one',b'evidence')
        self.c.write_private(store.directory/'retained-orphan-two',b'evidence')
        before=self.c.read_private(self.s.journal_path)
        with patch.object(self.b.j,'MAX_PAGES',1),self.assertRaisesRegex(ValueError,'directory capacity'):self.archive()
        self.assertTrue(self.c.read_private(self.s.journal_path)==before)
        self.assertEqual(len(list(store.directory.iterdir())),2)

if __name__=='__main__':unittest.main()
