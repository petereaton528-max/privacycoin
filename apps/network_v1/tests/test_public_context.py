"""Selector guard unit tests; native bound-context TLS tests run separately.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import os,unittest
from unittest.mock import patch
from apps.network_v1.public_network import require_public_context,PublicTorSession
from apps.network_v1 import onion
from src import network_identity as ni

class Context(unittest.TestCase):
    def test_current_validated_context(self):
        self.assertEqual(require_public_context(),(ni.NETWORK,ni.GENESIS,ni.PROFILE))
    def test_production_and_legacy_reject_before_state_creation(self):
        for name in ('mainnet','PrivacyCoinMainnet','legacy-dev01',''):
            with patch.dict(os.environ,PC_DEVELOPMENT_NETWORK=name),patch.object(onion.TorSession,'__init__') as parent:
                with self.assertRaisesRegex(ValueError,'EXPLICIT_OPEN'):PublicTorSession(connector_base=32090)
                parent.assert_not_called()
    def test_changed_runtime_identity_rejected(self):
        with patch.object(ni,'NETWORK','PCBindingTest999'):
            with self.assertRaisesRegex(ValueError,'CONTEXT_MISMATCH'):require_public_context()
    def test_missing_profile_not_accepted_by_prefix(self):
        with patch.dict(os.environ,PC_DEVELOPMENT_NETWORK='candidate-lab',PC_CANDIDATE_PROFILE='/nonexistent/pc-profile.json'):
            with self.assertRaises((ValueError,OSError)):require_public_context()
if __name__=='__main__':unittest.main()
