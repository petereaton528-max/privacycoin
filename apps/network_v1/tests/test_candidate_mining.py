"""Mining controller cancellation/ownership units; native work tested separately.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import threading,unittest
from apps.network_v1.candidate_rpc import Node
class Mining(unittest.TestCase):
    def test_unknown_errors_do_not_echo_private_text(self):
        from apps.network_v1.candidate_gui import safe_error
        self.assertNotIn('private-test-material',safe_error(ValueError('private-test-material')))
    def test_incomplete_recovery_has_specific_safe_action(self):
        from apps.network_v1.candidate_gui import safe_error
        self.assertIn('NEW wallet name',safe_error(ValueError('INCOMPLETE_RECOVERY_USE_ORIGINAL_BACKUP_AND_NEW_NAME')))
    def test_pre_cancel_has_no_rpc_side_effect(self):
        n=Node.__new__(Node);n.rpc=lambda *a,**k:self.fail('started RPC')
        cancel=threading.Event();cancel.set();self.assertTrue(n.call(op='mine_async',cancel=cancel,P='',R='')['stopped'])
    def test_cancel_stops_only_owned_job(self):
        n=Node.__new__(Node);calls=[];cancel=threading.Event()
        def rpc(cmd,**kw):
            calls.append((cmd,kw))
            if cmd=='status':return dict(mined=0,mining_hashes=1,mining_job=7,mining=1,mining_error='',height=0)
            if cmd=='mine_private':return dict(job=7)
            if cmd=='stop_mining':self.assertEqual(kw,{'job':7});return dict(stopped=1)
            self.fail(cmd)
        n.rpc=rpc
        self.assertTrue(n.call(op='mine_async',cancel=cancel,progress=lambda _:cancel.set(),P='',R='')['stopped'])
        self.assertEqual(sum(cmd=='mine_private' for cmd,_ in calls),1)
    def test_changed_job_never_cancelled_as_new_owner(self):
        n=Node.__new__(Node);started=[False];stops=[]
        def rpc(cmd,**kw):
            if cmd=='status':return dict(mined=0,mining_hashes=0,mining_job=8 if started[0] else 6,mining=1)
            if cmd=='mine_private':started[0]=True;return dict(job=7)
            if cmd=='stop_mining':stops.append(kw['job']);raise ValueError('ownership changed')
        n.rpc=rpc
        with self.assertRaisesRegex(ValueError,'MINING_JOB_CHANGED'):n.call(op='mine_async',P='',R='')
        self.assertEqual(stops,[7])
if __name__=='__main__':unittest.main()
