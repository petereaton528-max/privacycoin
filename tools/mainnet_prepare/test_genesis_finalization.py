"""Focused public Genesis checks with real native disposable components only.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import copy,hashlib,json,os,unittest
from pathlib import Path
from . import genesis_finalization as g
from .disposable_genesis import construct

class GenesisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from src.wallet import wallet as f
        root=Path(os.environ['PC_GENESIS_TEST_NATIVE_ROOT']);f.HELPER=root/'build/monero-linux/phase2/privacycoin-wallet-crypto'
        cls.helper=root/'candidate-native/full/draft-ledger';cls.digest=hashlib.sha256(cls.helper.read_bytes()).hexdigest()
        cls.checked=construct(cls.helper,cls.digest,f);cls.artifact=cls.checked['artifact'];cls.plan=cls.checked['public_plan']
        cls.policy=g.native_call(cls.helper,cls.digest,dict(op='policy'))
    def verify(self,artifact,**kwargs):return g.process(self.helper,kwargs.get('digest',self.digest),artifact,expected_commitment=kwargs.get('commitment',self.plan['commitment']))
    def reject(self,fn):
        with self.assertRaises(ValueError):fn()
    def test_canonical_reconstruction_and_native_ownership(self):
        result=self.verify(self.artifact)
        self.assertEqual(result['artifact'],self.artifact);self.assertEqual(self.checked['disposable_ownership_scan'],'17_NATIVE_OUTPUTS_PASS')
        self.assertFalse(result['production_approved']);self.assertFalse(result['recipient_ownership_proven']);self.assertTrue(result['external_commitment_pin_checked'])
    def test_exact_supply_unlocks(self):
        outputs=self.plan['outputs'];self.assertEqual(sum(x['atomic'] for x in outputs),159627169409884823)
        self.assertEqual([x['unlock'] for x in outputs],[i*65700 for i in range(17)])
        self.assertEqual(self.checked['mining_atomic'],0)
    def test_wrong_hash_and_noncanonical_bytes(self):
        for artifact in (dict(self.artifact,hash='0'*64),dict(self.artifact,block=self.artifact['block']+'00')):self.reject(lambda:self.verify(artifact))
    def test_wrong_network_pin(self):self.reject(lambda:self.verify(self.artifact,commitment='wrong-network'))
    def test_wrong_helper_hash(self):self.reject(lambda:self.verify(self.artifact,digest='0'*64))
    def test_bad_public_codec(self):
        for raw in ('','A0','zz','0','00'*6001):self.reject(lambda:self.verify(dict(block=raw,hash=self.artifact['hash'])))
        self.reject(lambda:json.loads('{"hash":"a","hash":"b"}',object_pairs_hook=g.unique))
    def test_native_rejects_tranche_mutations(self):
        for index in (0,1,5,6,8,16):
            for field in ('atomic','unlock'):
                plan=copy.deepcopy(self.plan);plan['outputs'][index][field]+=1
                self.reject(lambda:g.native_call(self.helper,self.digest,dict(op='reconstruct_genesis',**plan)))
    def test_native_rejects_count_duplicate_and_binding(self):
        plans=[]
        plan=copy.deepcopy(self.plan);plan['outputs'].pop();plans.append(plan)
        plan=copy.deepcopy(self.plan);plan['outputs'][1]['key']=plan['outputs'][0]['key'];plans.append(plan)
        plan=copy.deepcopy(self.plan);plan['commitment']='wrong-network';plans.append(plan)
        for plan in plans:self.reject(lambda:g.native_call(self.helper,self.digest,dict(op='reconstruct_genesis',**plan)))
    def test_independent_python_supply_and_schedule_guards(self):
        original=g.native_call(self.helper,self.digest,dict(op='verify_genesis',**self.artifact))
        for field in ('creator_atomic','mining_atomic'):
            bad=copy.deepcopy(original);bad[field]+=1;self.reject(lambda:g.check_plan(bad,self.policy))
        for field,value in (('atomic',True),('unlock',-1),('key','0'*63)):
            bad=copy.deepcopy(original);bad['outputs'][0][field]=value;self.reject(lambda:g.check_plan(bad,self.policy))
    def test_approved_policy_guards(self):
        original=g.native_call(self.helper,self.digest,dict(op='verify_genesis',**self.artifact))
        for field in ('activation','interval','total','liquid'):
            bad=dict(self.policy);bad[field]+=1;self.reject(lambda:g.check_plan(original,bad))

if __name__=='__main__':unittest.main()
