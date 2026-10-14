import os
from pathlib import Path
import tempfile
import unittest
from apps.network_v1.prediction import Prediction,UNIT


@unittest.skipUnless(os.name=='posix','Private simulation ledger requires POSIX or WSL')
class PredictionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.now=1000
        self.ledger=Prediction(Path(self.temp.name)/'prediction',lambda:self.now)
        self.operator=self.ledger.c.read_private(self.ledger.home/'operator').decode()
        self.a=self.ledger.register(self.operator);self.b=self.ledger.register(self.operator);self.c=self.ledger.register(self.operator)
    def tearDown(self):self.temp.cleanup()
    def event(self):
        return self.ledger.create(self.operator,question='Does the fixture resolve YES?',criteria='Operator verifies fixture evidence',source='Local fixture',close=1100,resolve=1200,cancellation='VOID refunds all stakes',authority='Local test operator')
    def resolve(self,e,side):
        self.now=1101;self.ledger.adjudicate(self.operator,e,'PROPOSE',outcome=side,evidence='Bounded test evidence')
        return self.ledger.adjudicate(self.operator,e,'FINALIZE',outcome=side,consent='CONFIRM SIMULATION SETTLEMENT')
    def test_conservation_rounding_duplicate_and_restart(self):
        e=self.event();self.ledger.participate(self.a,e,'YES',2,'a');self.ledger.participate(self.b,e,'YES',1,'b');self.ledger.participate(self.c,e,'NO',5,'c')
        self.assertTrue(self.ledger.participate(self.a,e,'YES',2,'a')['duplicate'])
        with self.assertRaises(ValueError):self.ledger.participate(self.a,e,'NO',2,'a')
        self.resolve(e,'YES');self.ledger=Prediction(self.ledger.home,lambda:self.now)
        self.assertEqual(sum(self.ledger.view(p)['balance'] for p in (self.a,self.b,self.c)),300000)
        self.assertTrue(self.ledger.adjudicate(self.operator,e,'FINALIZE',outcome='YES',consent='CONFIRM SIMULATION SETTLEMENT')['duplicate'])
        self.assertEqual(sum(self.ledger.view(p)['balance'] for p in (self.a,self.b,self.c)),300000)
    def test_authority_deadline_privacy_dispute_void(self):
        e=self.event()
        with self.assertRaises(ValueError):self.ledger.adjudicate(self.a,e,'VOID',evidence='x',consent='CONFIRM SIMULATION SETTLEMENT')
        self.ledger.participate(self.a,e,'YES',19,'first');self.now=1100
        with self.assertRaises(ValueError):self.ledger.participate(self.b,e,'NO',20,'late')
        view=self.ledger.view(self.b);self.assertEqual(view['events'][0]['state'],'CLOSED_PENDING_RESOLUTION');self.assertIsNone(view['events'][0]['my_participation']);self.assertFalse(view['pc_mode_enabled']);self.assertEqual(view['unit'],UNIT)
        self.ledger.adjudicate(self.operator,e,'PROPOSE',outcome='NO',evidence='Evidence')
        self.ledger.adjudicate(self.operator,e,'DISPUTE',evidence='Conflicting evidence')
        with self.assertRaises(ValueError):self.ledger.adjudicate(self.operator,e,'FINALIZE',outcome='NO',consent='CONFIRM SIMULATION SETTLEMENT')
        self.ledger.adjudicate(self.operator,e,'VOID',evidence='Recorded cancellation',consent='CONFIRM SIMULATION SETTLEMENT');self.assertEqual(self.ledger.view(self.a)['balance'],100000)
    def test_no_winner_empty_event_cross_event_and_insufficient(self):
        e=self.event();other=self.event();overdue=self.event();self.ledger.participate(self.a,e,'YES',100000,'same')
        with self.assertRaises(ValueError):self.ledger.participate(self.a,other,'YES',1,'same')
        with self.assertRaises(ValueError):self.ledger.participate(self.b,other,'YES',True,'invalid')
        self.resolve(e,'NO');self.assertEqual(self.ledger.view(self.a)['balance'],100000)
        self.ledger.adjudicate(self.operator,other,'PROPOSE',outcome='YES',evidence='empty event')
        self.ledger.adjudicate(self.operator,other,'FINALIZE',outcome='YES',consent='CONFIRM SIMULATION SETTLEMENT')
        self.assertEqual(sum(self.ledger.view(p)['balance'] for p in (self.a,self.b,self.c)),300000)
        self.now=1201
        with self.assertRaises(ValueError):self.ledger.adjudicate(self.operator,overdue,'PROPOSE',outcome='YES',evidence='late evidence')
        self.assertEqual(next(x for x in self.ledger.view(self.a)['events'] if x['id']==overdue)['state'],'RESOLUTION_OVERDUE_VOID_REQUIRED')
    def test_symlink_and_interrupted_atomic_write(self):
        e=self.event();raw=self.ledger.path.read_bytes();real=self.ledger.c.write_private
        def fail(*a,**k):raise OSError('isolated interruption')
        self.ledger.c.write_private=fail
        try:
            with self.assertRaises(OSError):self.ledger.participate(self.a,e,'YES',10,'interrupted')
        finally:self.ledger.c.write_private=real
        self.assertEqual(self.ledger.path.read_bytes(),raw)
        self.ledger.participate(self.a,e,'YES',10,'interrupted')
        self.assertEqual(self.ledger.view(self.a)['balance'],99990)
        link=Path(self.temp.name)/'alias';link.symlink_to(self.ledger.home,target_is_directory=True)
        with self.assertRaises((ValueError,OSError)):Prediction(link)


if __name__=='__main__':unittest.main()
