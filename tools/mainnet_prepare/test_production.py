"""Final immutable binding and cross-network rejection; no network/custody.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import copy,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from . import production as p,binding as b
class Production(unittest.TestCase):
    def test_exact_frozen_genesis(self):
        spec,artifact=p.frozen();self.assertEqual(artifact['hash'],p.G)
        self.assertEqual(len(bytes.fromhex(artifact['block'])),949)
        self.assertEqual(b.digest(p.config()),spec['binding_sha256'])
        self.assertEqual(b.context(p.config()),(spec['native_consensus_network'],spec['bound_domain_ascii'],'PCmn1-'))
    def test_byte_mutation_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for name in p.PINS:(root/name).write_bytes((p.ROOT/name).read_bytes())
            (root/'FINAL_GENESIS_APPROVAL.json').write_bytes((p.ROOT/'FINAL_GENESIS_APPROVAL.json').read_bytes())
            (root/'APPROVED_GENESIS.bin').write_bytes(b'bad')
            with patch.object(p,'ROOT',root),self.assertRaisesRegex(ValueError,'FROZEN'):p.frozen()
    def test_wrong_production_context_rejected(self):
        for key,value in [('network','PrivacyCoinDev02'),('domain','other'),('address_prefix','PCdv1-'),('production_approvals',True)]:
            with self.assertRaises(ValueError):b.validate(dict(p.config(),**{key:value}))
    def test_final_native_pins(self):
        header=b.header(p.config()).decode()
        self.assertIn('PC_FINAL_GENESIS_HASH "'+p.G+'"',header)
        self.assertIn('PC_FINAL_GENESIS_HEX "'+p.profile()['block']+'"',header)
    def test_profile_and_network_rejection(self):
        from apps.network_v1.candidate_profile import validate,bound_context
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/'binding.json';file.write_bytes(b.canonical(p.config()))
            with patch.dict(os.environ,PC_OFFLINE_BINDING=str(file)):
                bound_context.cache_clear();self.assertEqual(validate(p.profile()),p.profile())
                for key,value in [('genesis','a'*64),('block','00'),('network_tag','b'*64),('launchable',True)]:
                    with self.assertRaises(ValueError):validate(dict(p.profile(),**{key:value}))
            bound_context.cache_clear()
    def test_owner_custody_is_reported_not_audit(self):
        a=json.loads((p.ROOT/'FINAL_GENESIS_APPROVAL.json').read_bytes())
        self.assertEqual(a['ownership_evidence_classification'],'OWNER_REPORTED')
        self.assertFalse(a['mainnet_activation_authorized']);self.assertFalse(a['independent_security_review'])
if __name__=='__main__':unittest.main()
