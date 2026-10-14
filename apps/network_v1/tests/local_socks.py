"""Owned loopback SOCKS fixture, never Tor or Internet. Not a product route.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import random,socket,threading,time
from pathlib import Path

def owned_rss(pids):
    """Best-effort sampling; an exiting child is not a workload failure."""
    owned=set(pids);rss=0
    for pid in list(owned):
        try:owned.update(int(v) for v in Path('/proc',str(pid),'task',str(pid),'children').read_text().split())
        except (FileNotFoundError,ProcessLookupError):pass
    for pid in owned:
        try:
            lines=Path('/proc',str(pid),'status').read_text().splitlines()
            rss+=int(next((s.split()[1] for s in lines if s.startswith('VmRSS:')),'0'))
        except (FileNotFoundError,ProcessLookupError):pass
    return rss

class Socks:
    def __init__(self,mapping,*,seed=0,connect_delay=0,tls_delay=0,jitter=0,chunk=4096,refuse=0):
        self.mapping=mapping;self.seed=seed;self.connect_delay=connect_delay;self.tls_delay=tls_delay
        self.jitter=jitter;self.chunk=chunk;self.refuse=refuse;self.accepted=0
        self.drop_after=None;self.available=lambda name:True
        self.stop=threading.Event();self.guard=threading.Lock();self.active=set();self.workers=[]
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(16);self.listener.settimeout(.1)
        self.port=self.listener.getsockname()[1];self.thread=threading.Thread(target=self.run);self.thread.start()
    @staticmethod
    def read(stream,n):
        data=b''
        while len(data)<n:
            part=stream.recv(n-len(data))
            if not part:raise EOFError()
            data+=part
        return data
    def own(self,stream):
        with self.guard:self.active.add(stream)
        return stream
    def pump(self,source,target,seed):
        randomizer=random.Random(seed)
        delivered=0
        try:
            if self.stop.wait(self.tls_delay):return
            while not self.stop.is_set():
                raw=source.recv(self.chunk)
                if not raw:break
                delivered+=len(raw)
                if self.drop_after is not None and delivered>self.drop_after:break
                if self.stop.wait(randomizer.random()*self.jitter):break
                target.sendall(raw)
        except (OSError,EOFError):pass
        finally:
            try:target.shutdown(socket.SHUT_WR)
            except OSError:pass
    def handle(self,source,sequence):
        target=None
        try:
            source.settimeout(40)
            if self.read(source,3)!=b'\x05\x01\x00':raise ValueError('FIXTURE_AUTH')
            source.sendall(b'\x05');source.sendall(b'\x00')
            head=self.read(source,5)
            if head[:4]!=b'\x05\x01\x00\x03':raise ValueError('FIXTURE_DOMAIN_ONLY')
            name=self.read(source,head[4]).decode('ascii')
            if self.read(source,2)!=b'\x00\x50':raise ValueError('FIXTURE_PORT')
            if self.stop.wait(self.connect_delay):return
            if sequence<=self.refuse or name not in self.mapping or not self.available(name):
                source.sendall(b'\x05\x04\x00\x01');return
            target=self.own(socket.create_connection(('127.0.0.1',self.mapping[name]),timeout=2));target.settimeout(40)
            for byte in b'\x05\x00\x00\x01'+bytes(6):source.sendall(bytes([byte]))
            reverse=threading.Thread(target=self.pump,args=(target,source,self.seed+sequence*2))
            reverse.start();self.pump(source,target,self.seed+sequence*2+1);reverse.join(41)
        except (OSError,EOFError,ValueError):pass
        finally:
            for stream in (source,target):
                if stream:
                    with self.guard:self.active.discard(stream)
                    stream.close()
    def run(self):
        while not self.stop.is_set():
            try:source,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            with self.guard:self.accepted+=1;sequence=self.accepted
            self.own(source);self.workers=[t for t in self.workers if t.is_alive()]
            if len(self.workers)>=16:
                with self.guard:self.active.discard(source)
                source.close();continue
            thread=threading.Thread(target=self.handle,args=(source,sequence));self.workers.append(thread);thread.start()
    def close(self):
        self.stop.set();self.listener.close();self.thread.join(2)
        with self.guard:
            for stream in self.active:
                try:stream.shutdown(socket.SHUT_RDWR)
                except OSError:pass
        for thread in self.workers:thread.join(2)
        if self.thread.is_alive() or any(t.is_alive() for t in self.workers):raise RuntimeError('FIXTURE_LEAK')
