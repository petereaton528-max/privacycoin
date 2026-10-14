"""Paging and consent regressions; synthetic adapters are not real-chain proof."""
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock,patch
from apps.network_v1.index import Index
from apps.network_v1.tests.test_application import ChainFixture,NativeFixture,GENESIS


class GrowthInterfaceTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','Private process backend requires POSIX')
    def test_explicit_miner_stop_does_not_report_expected_signal_as_rejection(self):
        from apps.network_v1.desktop_backend import Product
        product=Product.__new__(Product);child=Mock();product.miner=child
        product.last_mining={'state':'RUNNING'};product.stop=Mock()
        product.status=lambda:dict(mining=product.last_mining)
        result=product.dispatch(dict(command='mine_stop'))
        product.stop.assert_called_once_with(child)
        self.assertIsNone(product.miner);self.assertEqual(result['mining']['state'],'STOPPED')

    def test_idle_index_reuses_validated_prefix_and_explicit_rebuild_reparses(self):
        chain=[GENESIS]+[f'{n:064x}' for n in range(1,20)];native=NativeFixture();native.describe=Mock(wraps=native.describe)
        with tempfile.TemporaryDirectory() as tmp:
            index=Index(Path(tmp)/'index.sqlite',native)
            try:
                index.refresh(1,ChainFixture(chain));self.assertEqual(native.describe.call_count,20)
                index.refresh(1,ChainFixture(chain));self.assertEqual(native.describe.call_count,20)
                index.refresh(1,ChainFixture(chain+['f'*64]));self.assertEqual(native.describe.call_count,21)
                index.refresh(1,ChainFixture(chain),force=True);self.assertEqual(native.describe.call_count,41)
                self.assertIsNone(index.block('f'*64))
            finally:index.close()
    def test_paginated_index_over_old_limit_and_changed_page(self):
        chain=[GENESIS]+[f'{n:064x}' for n in range(1,2301)]
        old=ChainFixture(chain)
        def call(port,command,**q):
            if command!='chain':return old(port,command,**q)
            offset=q.get('offset',0);end=min(len(chain),offset+1024)
            return dict(chain=chain[offset:end],tip=chain[-1],next=end,total=len(chain))
        with tempfile.TemporaryDirectory() as tmp:
            index=Index(Path(tmp)/'index.sqlite',NativeFixture())
            try:
                self.assertEqual(index.refresh(1,call),2301)
                def bad(port,command,**q):
                    result=call(port,command,**q)
                    if command=='chain' and q.get('offset'):result['tip']='f'*64
                    return result
                with self.assertRaisesRegex(ValueError,'CHAIN_PAGE_CHANGED'):index.refresh(1,bad)
                self.assertIsNotNone(index.block(chain[-1]))
                for change in ({'next':0},{'total':True},{'next':99999}):
                    with self.assertRaises(ValueError):index.refresh(1,lambda p,c,**q:dict(call(p,c,**q),**change) if c=='chain' else call(p,c,**q))
            finally:index.close()

    @unittest.skipUnless(os.name=='posix','Private process backend requires POSIX')
    def test_tor_retry_needs_session_consent_and_obeys_backoff(self):
        from apps.network_v1.desktop_backend import Product
        product=Product.__new__(Product);product.network_enabled=False
        product.tor=types.SimpleNamespace(owned=types.SimpleNamespace(process=Mock()),start=Mock(side_effect=OSError('isolated failure')))
        product.tor.owned.process.poll.return_value=1
        product.node=Mock();product.node.poll.return_value=None;product.tor_retry_at=0.;product.tor_retries=0
        product.maintain_tor();product.tor.start.assert_not_called()
        product.network_enabled=True
        with patch('apps.network_v1.desktop_backend.time.monotonic',return_value=10):
            product.maintain_tor();product.maintain_tor()
        product.tor.start.assert_called_once_with('CONNECT VIA TOR');self.assertEqual(product.tor_retry_at,12)
        product.network_enabled=False
        with patch('apps.network_v1.desktop_backend.time.monotonic',return_value=50):product.maintain_tor()
        product.tor.start.assert_called_once()

    @unittest.skipUnless(os.name=='posix','Private process backend requires POSIX')
    def test_reloading_process_is_not_ready_and_does_not_launch_index(self):
        from apps.network_v1.desktop_backend import Product
        product=Product.__new__(Product);product.network_enabled=False;product.node=Mock();product.node.poll.return_value=None
        product.index=None;product.miner=None;product.tor=None;product.rpc=32481;product.last_mining={'state':'DISABLED'};product.spawn=Mock()
        with patch('apps.network_v1.desktop_backend.rpc',side_effect=ValueError('not ready')):
            value=product.status()
        self.assertEqual(value['node']['state'],'STARTING_OR_UNAVAILABLE');self.assertEqual(value['index'],'STOPPED');product.spawn.assert_not_called()


if __name__=='__main__':unittest.main()
