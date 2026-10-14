"""Oversized synthetic ownership; never relax signing or private IPC limits."""
import json,os,unittest
from unittest.mock import Mock

@unittest.skipUnless(os.name=='posix','Private backend requires POSIX')
class HistoryPagingTests(unittest.TestCase):
    def session(self):
        from apps.network_v1.desktop_backend import Session
        session=Session.__new__(Session);session.port=1;session.persist=Mock();session.plan=None
        session.journal=dict(attempts=[dict(status='UNKNOWN',transaction_id=None,amount=1,fee=1,token='not-public')])
        owned=[dict(transaction=f'{i:064x}',amount=i+1,pending=False,coinbase=True,unlock=1,spent=False,height=i) for i in range(60000)]
        state=dict(chain=[],pool=[],height=60000,tip='f'*64)
        def observe():return state,dict(owned=owned),dict(chain_trust='TRUSTED_LOCAL_VALIDATING_ANCHOR',spendable=60000,signing_available=True),1
        session.observation=observe;return session
    def test_page_response_is_bounded_and_unknown_journal_still_blocks_spending(self):
        session=self.session();page=session.refresh()
        self.assertEqual(len(page['history']),100);self.assertEqual(page['history'][0]['amount'],59901)
        self.assertEqual(page['history_page']['total'],60000);self.assertEqual(page['history_page']['next_offset'],100)
        self.assertLess(len(json.dumps(page).encode()),100000)
        self.assertEqual(page['unknown_attempts'],1);self.assertIsNone(page['balance']['spendable']);self.assertFalse(page['balance']['signing_available'])
        self.assertNotIn('token',page['outgoing'][0])
        second=session.refresh(100)
        self.assertEqual(second['history'][-1]['amount'],59900);self.assertEqual(second['history_page']['previous_offset'],0)
        last=session.refresh(59900);self.assertEqual(last['history'][0]['amount'],1);self.assertIsNone(last['history_page']['next_offset'])
    def test_invalid_offset_does_not_scan_and_reorg_clamps_page(self):
        session=self.session()
        for value in (-1,True,'1',2**64):
            with self.assertRaises(ValueError):session.refresh(value)
        self.assertEqual(session.refresh(2**64-1)['history_page']['offset'],59900)

if __name__=='__main__':unittest.main()
