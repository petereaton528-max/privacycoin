"""Pure arithmetic tests; actual consensus tests are separate.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import unittest
from .policy import *
class PolicyTests(unittest.TestCase):
    def test_exact_split(self):
        self.assertEqual(LIQUID,15962716940988482);self.assertEqual(LOCKED,143664452468896341);self.assertEqual(LIQUID+LOCKED,TOTAL)
    def test_tranches_and_remainder(self):
        rows=schedule();self.assertEqual(sum(x['atomic'] for x in rows),TOTAL)
        self.assertEqual([x['atomic'] for x in rows[1:6]],[8979028279306022]*5)
        self.assertEqual([x['atomic'] for x in rows[6:]],[8979028279306021]*11)
        self.assertEqual(rows[-1]['height'],1051200)
    def test_all_unlock_boundaries(self):
        amount=LIQUID;self.assertEqual(unlocked(0),LIQUID)
        for row in schedule()[1:]:
            self.assertEqual(unlocked(row['height']-1),amount);amount+=row['atomic']
            self.assertEqual(unlocked(row['height']),amount);self.assertEqual(unlocked(row['height']+1),amount)
    def test_reorganization_height_rollback(self):
        self.assertGreater(unlocked(65700),unlocked(65699));self.assertEqual(unlocked(1051200),TOTAL)
    def test_invalid_height(self):
        for h in (-1,True,1.0,2**64):
            with self.assertRaises(ValueError):unlocked(h)
if __name__=='__main__':unittest.main()
