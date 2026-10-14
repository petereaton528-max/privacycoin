"""Cache invalidation units; real balance checks are in candidate_network.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import unittest
from types import SimpleNamespace
from apps.network_v1.candidate_client import Client
from apps.network_v1.candidate_rpc import Node
class Cache(unittest.TestCase):
    def test_wallet_identity_and_snapshot_invalidate_scan(self):
        c=Client.__new__(Client);c.wallet={};calls=[]
        c.adapter=SimpleNamespace(scan=lambda w,s:(calls.append((w,s)) or {'available':len(calls)}))
        state={};self.assertEqual(c.scan(state),c.scan(state));self.assertEqual(len(calls),1)
        c.wallet={};self.assertEqual(c.scan(state)['available'],2)
        self.assertEqual(c.scan({})['available'],3)
    def test_tip_pool_revision_and_restart_invalidate_history(self):
        n=Node.__new__(Node);snap=dict(tip='a',revision=1,instance='first',height=0);calls=[]
        def rpc(cmd,**kw):
            calls.append(cmd)
            if cmd=='snapshot_id':return dict(snap)
            if cmd=='history':return dict(next=1,records=[dict(transaction='00',height=0,coinbase=True,images=[])],orphan_images=[])
            if cmd=='pool_page':return dict(entries=[])
            raise AssertionError(cmd)
        n.rpc=rpc;first=n.history();self.assertIs(n.history(),first);self.assertEqual(calls.count('history'),1)
        for key,value in [('revision',2),('tip','b'),('instance','restart')]:
            old=n.history();snap[key]=value;self.assertIsNot(n.history(),old)
        n.close();self.assertIsNone(n._history)
if __name__=='__main__':unittest.main()
