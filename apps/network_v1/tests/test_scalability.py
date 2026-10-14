"""Bounded adapters and atomic public index; synthetic scope is explicit."""
import json,os,tempfile,threading,tracemalloc,unittest
from pathlib import Path
from unittest.mock import patch
from apps.network_v1.index import Index
from apps.network_v1.tests.test_application import ChainFixture,NativeFixture,GENESIS

class IndexScaleTests(unittest.TestCase):
    def test_large_database_reopens_and_cancelled_reorg_preserves_published_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'public.sqlite';index=Index(path,NativeFixture())
            index.refresh(1,ChainFixture([GENESIS,'1'*64]))
            with index.db:
                index.db.execute('CREATE TABLE padding(value BLOB)')
                index.db.execute('INSERT INTO padding VALUES(zeroblob(33554432))')
            index.close();self.assertGreater(path.stat().st_size,32*1024*1024)
            index=Index(path,NativeFixture())
            try:
                before=index.state();cancel=threading.Event()
                old=ChainFixture([GENESIS,'2'*64])
                def call(p,c,**q):
                    if c=='get_block':cancel.set()
                    return old(p,c,**q)
                with self.assertRaisesRegex(ValueError,'INDEX_CANCELLED'):index.refresh(1,call,stop=cancel)
                self.assertEqual(before,index.state())
                self.assertEqual(index.db.execute('PRAGMA integrity_check').fetchall()[0][0],'ok')
            finally:index.close()

    def test_ten_thousand_paged_metadata_has_bounded_python_memory(self):
        def identity(h):return GENESIS if not h else f'{h:064x}'
        def call(p,c,**q):
            if c=='chain':
                start=q.get('offset',0);end=min(10001,start+1024)
                return dict(chain=[identity(h) for h in range(start,end)],tip=identity(10000),total=10001,next=end)
            h=0 if q['hash']==GENESIS else int(q['hash'],16)
            return dict(height=h,work=str(h),block=json.dumps(dict(hash=identity(h),parent=identity(h-1) if h else '0'*64,timestamp=1700000000+h,reward=1,output_key='a'*64,R='b'*64,transaction_count=0)))
        with tempfile.TemporaryDirectory() as tmp:
            index=Index(Path(tmp)/'public.sqlite',NativeFixture());tracemalloc.start()
            try:
                self.assertEqual(index.refresh(1,call),10001)
                _,peak=tracemalloc.get_traced_memory()
                self.assertLess(peak,4*1024*1024)
                self.assertEqual(index.state()['tip']['height'],10000)
            finally:tracemalloc.stop();index.close()

@unittest.skipUnless(os.name=='posix','Wallet private storage runtime is POSIX')
class WalletScaleTests(unittest.TestCase):
    def test_spooled_history_fingerprint_matches_legacy_and_interleaved_readers(self):
        from apps.network_v1.desktop_backend import c,f
        import hashlib
        rows=[dict(transaction=str(i),id=f'{i:064x}') for i in range(600)]
        store=c.w.ChainRecords();store.extend(rows)
        try:
            self.assertEqual(len(store),600);self.assertEqual(store[-1],rows[-1]);self.assertEqual(store[2:5],rows[2:5])
            a=iter(store);b=iter(store)
            self.assertEqual(next(a),next(b));self.assertEqual(next(a),next(b))
            state=dict(chain=rows,images=[],pool=[],pool_images=[],height=100,tip='a'*64)
            expected=hashlib.sha256(f.canonical(state)).hexdigest()
            self.assertEqual(c.fingerprint(state),expected)
            state['chain']=store;self.assertEqual(c.fingerprint(state),expected)
            self.assertEqual(os.fstat(store.file.fileno()).st_mode&0o777,0o600)
        finally:store.file.close()

    def test_batch_offsets_image_reconciliation_and_sparse_construction(self):
        from apps.network_v1.desktop_backend import c
        w=c.w;wallet=dict(view='a',public='b',count=2,authority='view')
        state=dict(chain=[dict(transaction=str(i),height=1,coinbase=True) for i in range(600)],images=[],pool_images=[],height=100)
        sizes=[]
        def helper(q):
            sizes.append(len(q['chain']));n=len(q['chain'])*2
            return dict(owned=[dict(global_index=n-1,amount=1)],eligible=list(range(n)),record_outputs=[2]*len(q['chain']),scanned_outputs=n,scan_ms=1,undecodable_owned_outputs=0)
        with patch.object(w,'helper',side_effect=helper):result=w.scan(wallet,state)
        self.assertEqual(sizes,[256,256,88]);self.assertEqual(result['eligible'],list(range(1200)))
        self.assertEqual([x['global_index'] for x in result['owned']],[511,1023,1199])
        subset=w.construction_state(state,result,[dict(source=1199,ring=[0,1199])])
        self.assertEqual([x['global_offset'] for x in subset['chain']],[0,1198])
        with self.assertRaises(ValueError):w.construction_state(state,result,[dict(source=1200,ring=[1200])])
        with patch.object(w,'helper',return_value=dict(record_outputs=[],scanned_outputs=0)):
            with self.assertRaisesRegex(ValueError,'incomplete output index scan'):w.scan(wallet,state)

if __name__=='__main__':unittest.main()
