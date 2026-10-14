"""Draft arithmetic and namespace guards; no Mainnet runtime claim.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import unittest
from tools.mainnet_prepare.prepare import proposal,subsidy
from src.network_identity import selected
class MainnetPreparation(unittest.TestCase):
    def test_unapproved_draft_independent_namespaces(self):
        p=proposal();self.assertEqual(len(p['network_magic'].encode()),16)
        self.assertNotIn(p['network_magic'],[selected(x)[0] for x in ('legacy-dev01','open-dev02')])
        self.assertNotEqual(p['wallet_envelope_network'],'privacycoin-devnet');self.assertNotEqual(p['address_prefix'],'PCdv1-')
        self.assertNotEqual(p['wallet_key_domain'],'PrivacyCoin/devnet/wallet/v1/');self.assertEqual(p['creator_allocation_atomic'],0)
        for selector in ('mainnet','PrivacyCoinMN001'):
            with self.assertRaises(ValueError):selected(selector)
    def test_existing_reward_vectors_and_tail_boundary(self):
        self.assertEqual(subsidy(0),35184372088831);self.assertEqual(subsidy(subsidy(0)),35184304979968)
        boundary=(2**64-1)-((600000000000+1)<<19)
        self.assertEqual(subsidy(boundary),600000000001);self.assertEqual(subsidy(boundary+1),600000000000)
        self.assertEqual(subsidy(2**64+1),600000000000)
if __name__=='__main__':unittest.main()
