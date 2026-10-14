"""Approval/domain guards; native semantics tested separately.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import copy,json,tempfile,unittest
from pathlib import Path
from . import binding as b
from .prepare import proposal,prepare
class Binding(unittest.TestCase):
    def test_exact_approved_supply(self):
        a=b.approved()['approved'];self.assertEqual(a['creator_total_atomic'],a['creator_liquid_atomic']+5*a['first_five_tranche_atomic']+11*a['last_eleven_tranche_atomic'])
        self.assertEqual(a['vesting_interval']*a['vesting_releases'],1051200)
    def test_pending_not_defaulted(self):
        self.assertTrue(all(v is None for v in b.approved()['pending'].values()))
        self.assertFalse(proposal()['launchable'])
        with self.assertRaisesRegex(ValueError,'RETIRED'):prepare('/nonexistent',None)
    def test_no_production_switch(self):
        for change in ({'purpose':'PRODUCTION'},{'production_approvals':True},{'network':'PrivacyCoinMainnet'},{'domain':'PrivacyCoin/mainnet'},{'address_prefix':'PCmn1-'}):
            with self.assertRaises(ValueError):b.validate(dict(b.test_config(),**change))
    def test_exact_schema_and_fee_types(self):
        v=b.test_config();v['fee_policy']['consensus_min_atomic']=True
        with self.assertRaises(ValueError):b.validate(v)
        with self.assertRaises(ValueError):b.validate(dict(b.test_config(),extra=True))
    def test_every_context_field_bound(self):
        a=b.test_config();old=b.context(a)
        for field,new in [('network','PCBindingTest002'),('domain',a['domain']+'/other'),('address_prefix','PCbt2-')]:
            v=copy.deepcopy(a);v[field]=new;self.assertNotEqual(b.context(v)[1],old[1])
    def test_native_wire_magic_width(self):
        for name in ('PCBindingTest01','PCBindingTest0001'):
            with self.assertRaisesRegex(ValueError,'16_BYTES'):b.validate(dict(b.test_config(),network=name))
    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input';p.write_text('{"format":1,"format":2}')
            with self.assertRaisesRegex(ValueError,'DUPLICATE'):b.load(p.resolve())
if __name__=='__main__':unittest.main()
