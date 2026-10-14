"""Offline resource-accounting tests; not public Tor capacity evidence.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import socket,threading,unittest
from apps.network_v1.public_network import Budget,PublicChannel

class PublicBudgets(unittest.TestCase):
    def test_rejection_storm_does_not_extend_recovery(self):
        now=[0.];b=Budget(8,1,lambda:now[0])
        self.assertTrue(b.take(8))
        for _ in range(10000):self.assertFalse(b.take())
        now[0]=1.;self.assertTrue(b.take());self.assertFalse(b.take())
    def test_idle_capacity_and_backward_clock_are_bounded(self):
        now=[10.];b=Budget(4,2,lambda:now[0]);self.assertTrue(b.take(4))
        now[0]=9.;self.assertFalse(b.take());now[0]=10.;self.assertFalse(b.take())
        now[0]=1000.;self.assertFalse(b.take(5));self.assertTrue(b.take(4))
        self.assertFalse(b.take(-1));self.assertFalse(b.take())
    def test_concurrent_consumption_is_atomic(self):
        b=Budget(8,1,lambda:0.);results=[]
        ts=[threading.Thread(target=lambda:results.append(b.take())) for _ in range(64)]
        for t in ts:t.start()
        for t in ts:t.join()
        self.assertEqual(sum(results),8)
    def test_rejected_connection_never_enters_tls_and_releases_ownership(self):
        ch=PublicChannel.__new__(PublicChannel);ch.peer=None
        ch.handshakes=Budget(0,1,lambda:0.);ch.active=set();ch.active_guard=threading.Lock()
        ch.guard=threading.Lock();ch.errors={};ch.slots=threading.BoundedSemaphore(1)
        ch.inbound=lambda _:self.fail('TLS/native path reached despite exhausted admission budget')
        for _ in range(20):
            left,right=socket.socketpair();self.assertTrue(ch.slots.acquire(False))
            try:ch.handle(left);self.assertEqual(right.recv(1),b'')
            finally:right.close()
            self.assertFalse(ch.active)
        self.assertEqual(ch.errors,{'RESOURCE_LIMIT':20})

if __name__=='__main__':unittest.main()
