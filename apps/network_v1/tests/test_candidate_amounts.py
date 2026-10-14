"""Exact candidate GUI amount parsing guards; native tests are separate.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import unittest
from apps.network_v1.candidate_client import amount
class Amounts(unittest.TestCase):
    def test_atomic_precision(self):
        self.assertEqual(amount('0.000000000001'),1)
        self.assertEqual(amount('159627.169409884823'),159627169409884823)
        self.assertEqual(amount('1'),10**12)
    def test_ambiguous_or_non_decimal_rejected(self):
        for text in ('NaN','1e3','-1','1.0000000000001','.1','01','1,000',' 1'):
            with self.assertRaises(ValueError):amount(text)
if __name__=='__main__':unittest.main()
