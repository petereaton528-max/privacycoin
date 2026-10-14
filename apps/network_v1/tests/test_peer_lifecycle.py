"""Deterministic controller policy tests; real transport tested separately.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import threading,unittest
from unittest.mock import patch
from apps.network_v1.public_network import Directory,PeerService
from apps.network_v1.tests.test_public_network import descriptor

class PeerLifecycle(unittest.TestCase):
    def setUp(self):self.now=100.;self.directory=Directory(clock=lambda:self.now)
    def test_source_quota_remains_after_verification(self):
        for index in (1,2):self.assertTrue(self.directory.add(descriptor(index),source='one',verified=True))
        self.assertFalse(self.directory.add(descriptor(3),source='one',verified=True))
        self.assertTrue(self.directory.add(descriptor(4),source='other'))
    def test_bound_expiry_and_no_repeat_refresh_by_unverified_claim(self):
        for index in range(40):self.directory.add(descriptor(index),source='source-'+str(index))
        self.assertEqual(len(self.directory.candidates()),32)
        self.now+=1700;self.directory.add(descriptor(0))
        self.now+=101;self.assertFalse(self.directory.candidates())
    def test_explicit_seeds_survive_unverified_hint_expiry(self):
        d=Directory([descriptor(i) for i in range(8)],clock=lambda:self.now)
        self.now+=1801;self.assertEqual(len(d.candidates()),8)
        self.assertEqual(len(d.select(set(),8)),8)
    def test_verified_catalog_ages_out_without_discarding_seed(self):
        d=Directory([descriptor()],clock=lambda:self.now);d.add(descriptor(),verified=True)
        self.assertEqual(len(d.catalog()),1);self.now+=601
        self.assertEqual(d.catalog(),[]);self.assertEqual(len(d.candidates()),1)
    def test_backoff_not_extended_by_add_and_recovers(self):
        self.directory.add(descriptor());self.directory.retire(descriptor()['onion'])
        self.assertEqual(self.directory.select(set(),8),[])
        self.directory.add(descriptor());self.now+=59
        self.assertEqual(self.directory.select(set(),8),[])
        self.now+=1;self.assertEqual(len(self.directory.select(set(),8)),1)
    def test_selection_zero_and_preview_do_not_change_fairness(self):
        for index in range(5):self.directory.add(descriptor(index))
        self.assertEqual(self.directory.select(set(),0),[])
        a=self.directory.select(set(),1,reserve=False)
        self.assertEqual(a,self.directory.select(set(),1));self.now+=1
        self.assertNotEqual(a,self.directory.select(set(),1))
    def test_source_diversity_with_existing_assignments(self):
        self.directory.add(descriptor(1),source='one');self.directory.add(descriptor(2),source='one')
        self.directory.add(descriptor(3),source='other')
        chosen=self.directory.select({descriptor(1)['onion']},8)
        self.assertEqual(len(chosen),2)
    def test_pin_change_rejected_during_cooldown(self):
        self.directory.add(descriptor());self.directory.retire(descriptor()['onion'])
        with self.assertRaises(ValueError):self.directory.add(dict(descriptor(),certificate_sha256='f'*64))
    def test_failed_slot_closed_before_same_port_reassignment(self):
        service=PeerService(25001,25002,25100,25003,lambda:descriptor(99),'unused','unused',[descriptor(1)])
        service.directory.add(descriptor(2));closed=[]
        class Channel:
            def __init__(self,listen,target,**kwargs):
                self.peer=kwargs['peer'];self.guard=threading.Lock();self.failures=0;self.forwarded=0;self.connections=0;self.end=threading.Event();self.listen=listen
            def run(self):self.end.wait(2)
            def close(self):closed.append(self.listen);self.end.set()
        with patch('apps.network_v1.public_network.PublicChannel',Channel):
            try:
                service.reconcile(100);first=service.slots[0][0];first.failures=3
                service.reconcile(101)
                self.assertIn(first.listen,closed);self.assertNotIn(first.peer['onion'],service.assigned)
                self.assertLessEqual(len(service.slots),8);self.assertEqual(service.rotations,1)
            finally:service.close()

    def test_healthy_rotation_is_bounded_and_preserves_other_slots(self):
        service=PeerService(25001,25002,25100,25003,lambda:descriptor(99),'unused','unused',[descriptor(i) for i in range(8)])
        service.directory.add(descriptor(8));closed=[]
        class Channel:
            def __init__(self,listen,target,**kwargs):
                self.peer=kwargs['peer'];self.guard=threading.Lock();self.failures=0;self.forwarded=0;self.connections=0;self.end=threading.Event()
            def run(self):self.end.wait(2)
            def close(self):closed.append(self.peer['onion']);self.end.set()
        with patch('apps.network_v1.public_network.PublicChannel',Channel):
            try:
                service.reconcile(100);before=set(service.assigned);self.assertEqual(len(before),8)
                service.reconcile(401);self.assertEqual(service.rotations,1);self.assertEqual(len(service.assigned),8)
                self.assertEqual(len(before & service.assigned),7)
                service.reconcile(402);self.assertEqual(service.rotations,1)
            finally:service.close()

if __name__=='__main__':unittest.main()
