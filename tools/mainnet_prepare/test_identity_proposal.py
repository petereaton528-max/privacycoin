"""Exact approval/proposal isolation regressions; no network or private data.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json,unittest
from pathlib import Path
import tempfile
from unittest.mock import patch
from . import binding as b
from .identity_proposal import proposal,KNOWN_MAGIC

class Identity(unittest.TestCase):
    def test_checked_in_public_proposal_correspondence(self):
        p=json.loads(Path(__file__).with_name('production_identity_proposal.json').read_text())
        resolved=p.pop('resolved_policy');self.assertEqual(p,proposal())
        self.assertEqual(resolved['wallet_network_tag'],hashlib.sha256(('PC/CANDIDATE-OFFLINE/'+resolved['commitment_ascii']).encode()).hexdigest())
        self.assertEqual(bytes.fromhex(resolved['commitment_hex']).decode(),resolved['commitment_ascii'])
    def test_approved_fees_not_pending(self):
        p=b.approved();self.assertNotIn('fee_policy',p['pending'])
        self.assertEqual(p['approved_fee_policy'],dict(relay_atomic_per_byte=100,wallet_default_atomic=10**9,consensus_min_atomic=1,consensus_max_atomic=10**12))
        self.assertNotIn('network_identifier_and_domains',p['pending'])
        self.assertEqual(p['approved_production_identity']['sha256'],b.APPROVED_IDENTITY_SHA256)
    def test_immutable_bytes_reject_even_cosmetic_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'identity.json';p.write_bytes(b.IDENTITY.read_bytes()+b'\n')
            with patch.object(b,'IDENTITY',p),self.assertRaisesRegex(ValueError,'IMMUTABLE_IDENTITY_MISMATCH'):b.approved()
    def test_identity_approval_does_not_authorize_pending_actions(self):
        p=b.approved()
        self.assertEqual(set(p['pending']),{'founder_public_recipient','production_genesis_bytes_and_hash','founder_key_generation','publication','mainnet_activation'})
        self.assertTrue(all(v is None for v in p['pending'].values()))
    def test_names_and_exact_width(self):
        p=proposal();self.assertEqual(p['naming']['human_network_identifier'],'PrivacyCoinMainnet')
        self.assertEqual(len(bytes.fromhex(p['wire_magic_hex'])),16)
        self.assertEqual(bytes.fromhex(p['wire_magic_hex']).decode(),p['native_consensus_network'])
    def test_known_names_distinct(self):
        self.assertNotIn(proposal()['native_consensus_network'],KNOWN_MAGIC.values())
    def test_detached_final_approval_required_for_production(self):
        from . import production
        p=proposal();self.assertIs(p['approved'],False);self.assertIs(p['launchable'],False)
        self.assertEqual(b.validate(p['binding']),production.config())
        with patch.object(production,'config',side_effect=ValueError('FINAL_APPROVAL_REQUIRED')):
            for fn in (b.validate,b.context,b.header,b.digest):
                with self.assertRaisesRegex(ValueError,'FINAL_APPROVAL_REQUIRED'):fn(p['binding'])
    def test_exact_commitments(self):
        p=proposal();self.assertEqual(p['binding_sha256'],hashlib.sha256(b.canonical(p['binding'])).hexdigest())
        self.assertEqual(bytes.fromhex(p['policy_text_hex']).decode(),p['policy_text_ascii'])
        self.assertEqual(p,proposal())
    def test_all_tranches(self):
        o=proposal()['creator_outputs'];self.assertEqual(len(o),17)
        self.assertEqual(sum(v['atomic'] for v in o),159627169409884823)
        self.assertEqual([v['unlock_height'] for v in o],[i*65700 for i in range(17)])
        self.assertEqual([v['atomic'] for v in o[1:6]],[8979028279306022]*5)
        self.assertEqual([v['atomic'] for v in o[6:]],[8979028279306021]*11)
    def test_fee_limits_preserved(self):
        f=b.test_config()['fee_policy'];self.assertLessEqual(50000*f['relay_atomic_per_byte'],f['wallet_default_atomic'])
        self.assertLess(f['consensus_min_atomic'],f['relay_atomic_per_byte'])
if __name__=='__main__':unittest.main()
