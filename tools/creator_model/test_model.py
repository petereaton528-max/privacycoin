"""Exact accounting/math tests; native oracle and wallet tests are separate.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import tempfile,unittest
from pathlib import Path
from .model import report,subsidy,schedule,pc,natural,FOUR_YEAR_BLOCKS
from .accounting import DraftAccounting
class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.model=report()
    def test_known_exact_rewards_and_tail_boundaries(self):
        self.assertEqual(subsidy(0),35184372088831);self.assertEqual(subsidy(subsidy(0)),35184304979968)
        boundary=(2**64-1)-((600000000000+1)<<19)
        self.assertEqual(subsidy(boundary),600000000001);self.assertEqual(subsidy(boundary+1),600000000000)
        self.assertEqual(subsidy(2**64+500),600000000000);self.assertEqual(self.model['tail_first_height'],2134600)
    def test_exact_four_year_allocations_floor_not_round(self):
        m=self.model['M4_atomic'];self.assertEqual(m,15962716940988482356)
        for name,denominator in [('B_one_percent_mining',100),('C_one_percent_total',99)]:
            a=self.model['allocations'][name]['atomic'];self.assertLessEqual(a*denominator,m);self.assertLess(m,(a+1)*denominator)
        self.assertEqual(pc(m//100),'159627.169409884823');self.assertNotEqual(m//100,m//99)
    def test_annual_sum_total_and_additive_supply_conservation(self):
        cumulative=0
        for row in self.model['year_by_year']:
            cumulative+=row['mining_year_atomic'];self.assertEqual(cumulative,row['mining_cumulative_atomic'])
            for value in row['scenarios'].values():self.assertEqual(value['total_issued_atomic'],cumulative+value['creator_atomic'])
    def test_year_window_calendar_and_coupling_are_distinct(self):
        self.assertEqual(FOUR_YEAR_BLOCKS,1051200);self.assertEqual(self.model['calendar_1461_days']['target_blocks'],1051920)
        self.assertGreater(self.model['calendar_1461_days']['B_allocation_atomic'],self.model['allocations']['B_one_percent_mining']['atomic'])
        self.assertGreater(self.model['counter_coupling_comparison']['mining_shortfall_M4_atomic'],0)
    def test_initial_concentration_and_long_run_dilution(self):
        early=self.model['early_concentration'];self.assertEqual(early[0]['B_creator_percent_issued']['decimal'],'100.000000000000')
        shares=[int(row['scenarios']['B_one_percent_mining']['creator_percent_issued']['numerator'])*10**18//int(row['scenarios']['B_one_percent_mining']['creator_percent_issued']['denominator']) for row in self.model['year_by_year']]
        self.assertTrue(all(a>b for a,b in zip(shares,shares[1:])))
    def test_invalid_amounts_no_float_and_bounded_work(self):
        for value in (-1,True,1.0,2**256):
            with self.assertRaises(ValueError):natural(value)
        for heights in ([True],[1.5],[-1],[100000000]):
            with self.assertRaises(ValueError):schedule(heights)
    def test_small_schedule_matches_direct_integer_recurrence(self):
        mined=0;points={0:0}
        for height in range(1,1001):mined+=max(((2**64-1)-min(mined,2**64-1))//524288,600000000000);points[height]=mined
        self.assertEqual(schedule([0,1,2,60,1000])['points'],{n:points[n] for n in [0,1,2,60,1000]})
class AccountingTests(unittest.TestCase):
    def test_once_only_supply_restart_and_wrong_genesis(self):
        with tempfile.TemporaryDirectory(prefix='pc-creator-accounting-') as home:
            p=Path(home)/'draft.sqlite';allocation=159627169409884823;g='a'*64
            state=DraftAccounting(p,g,allocation,create=True)
            self.assertEqual(state.state()['total'],allocation)
            for height in range(1,101):state.append(height,subsidy(state.state()['mined']))
            before=state.state()
            with self.assertRaises(ValueError):state.append(101,subsidy(before['mined']),creator_issuance=allocation)
            with self.assertRaises(ValueError):state.append(100,subsidy(before['mined']))
            state.close();state=DraftAccounting(p,g,allocation);self.assertEqual(state.state(),before);state.close()
            with self.assertRaises(ValueError):DraftAccounting(p,g,allocation,create=True)
            with self.assertRaises(ValueError):DraftAccounting(p,'b'*64,allocation)
            with self.assertRaises(ValueError):DraftAccounting(p,g,allocation,network_tag='e'*64)
    def test_interrupted_transaction_rolls_back_and_corruption_rejected(self):
        with tempfile.TemporaryDirectory(prefix='pc-creator-accounting-') as home:
            p=Path(home)/'draft.sqlite';state=DraftAccounting(p,'a'*64,100,create=True);before=state.state()
            state.db.execute('BEGIN IMMEDIATE');state.db.execute("UPDATE state SET total='101'");state.close()
            state=DraftAccounting(p,'a'*64,100);self.assertEqual(state.state(),before)
            state.db.execute("UPDATE state SET total='101'");state.db.commit()
            with self.assertRaises(ValueError):state.state()
            state.close()
    def test_foreign_database_and_unsafe_paths_rejected(self):
        import sqlite3
        with tempfile.TemporaryDirectory(prefix='pc-creator-accounting-') as home:
            p=Path(home)/'foreign.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE unrelated(x)');db.close()
            with self.assertRaises(ValueError):DraftAccounting(p,'a'*64,100)
            with self.assertRaises(ValueError):DraftAccounting(Path(home)/'privacycoin-n2'/'state.sqlite','a'*64,100,create=True)
if __name__=='__main__':unittest.main()
