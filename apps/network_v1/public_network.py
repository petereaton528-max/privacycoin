"""Ticket-free public development transport; native validation remains authoritative.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib, json, os, secrets, socket, ssl, subprocess, tempfile, threading, time
from pathlib import Path
from . import onion

HELLO=b'PCOPEN02'
MAX_PEERS=8
MAX_CANDIDATES=32

class Budget:
    """Constant-memory ingress token bucket; rejection never moves recovery time.

    Shared across identities/connections: Tor loopback addresses and claimed peer
    identities are not suitable resource-accounting authorities.
    """
    def __init__(self,capacity,rate,clock=time.monotonic):
        self.capacity=capacity;self.rate=rate;self.clock=clock
        self.tokens=capacity;self.updated=clock();self.lock=threading.Lock()
    def take(self,amount=1):
        with self.lock:
            now=self.clock()
            elapsed=max(0,now-self.updated);self.updated=max(now,self.updated)
            self.tokens=min(self.capacity,self.tokens+elapsed*self.rate)
            if amount<0 or amount>self.tokens:return False
            self.tokens-=amount;return True

def read_json(pc, stream, end):
    size=int.from_bytes(pc.read(stream,4,end),'big')
    if not 1<=size<=16384:raise ValueError('PUBLIC_FRAME_BOUND')
    return pc.f.decode(pc.read(stream,size,end))

def send_json(pc,stream,value,end):
    raw=pc.f.canonical(value)
    if not 1<=len(raw)<=16384:raise ValueError('PUBLIC_FRAME_BOUND')
    pc.write(stream,len(raw).to_bytes(4,'big')+raw,end)

def proof(key,certificate,message,signature=None):
    """Existing OpenSSL Ed25519; keys never leave their private file."""
    with tempfile.TemporaryDirectory(prefix='pc-public-proof-') as d:
        home=Path(d);msg=home/'challenge';msg.write_bytes(message)
        args=[onion.openssl_binary(),'pkeyutl','-rawin','-in',str(msg)]
        if signature is None:
            result=subprocess.run(args+['-sign','-inkey',str(key)],capture_output=True,timeout=3)
            if result.returncode or len(result.stdout)!=64:raise ValueError('PUBLIC_IDENTITY_PROOF')
            return result.stdout
        if len(signature)!=64 or len(certificate)>16384:raise ValueError('PUBLIC_IDENTITY_PROOF')
        pub=subprocess.run([onion.openssl_binary(),'x509','-pubkey','-noout'],input=certificate,capture_output=True,timeout=3)
        if pub.returncode or len(pub.stdout)>4096:raise ValueError('PUBLIC_CERTIFICATE')
        (home/'public').write_bytes(pub.stdout);(home/'signature').write_bytes(signature)
        checked=subprocess.run(args+['-verify','-pubin','-inkey',str(home/'public'),'-sigfile',str(home/'signature')],capture_output=True,timeout=3)
        if checked.returncode:raise ValueError('PUBLIC_IDENTITY_PROOF')

class Directory:
    """Bounded hints, not consensus authority or a claim of Sybil resistance."""
    def __init__(self,initial=(),clock=time.monotonic):
        self.clock=clock;self.lock=threading.RLock();self.values={};self.verified=set();self.origins={};self.records={}
        for value in initial:
            self.add(value,source='seed:'+value['onion'])
    def prune(self):
        now=self.clock()
        for name in list(self.values):
            record=self.records[name]
            if name in self.verified and now-record['verified_at']>600:self.verified.discard(name)
            if not record['seed'] and name not in self.verified and now-record['added']>1800:self.remove(name)
    def remove(self,name):
        with self.lock:
            self.values.pop(name,None);self.records.pop(name,None);self.origins.pop(name,None);self.verified.discard(name)
    def add(self,value,verified=False,source=None):
        value=onion.descriptor(value)
        with self.lock:
            self.prune()
            old=self.values.get(value['onion'])
            if old and old!=value:raise ValueError('PEER_PIN_CONFLICT')
            # An inbound claim or one gossiping peer cannot fill every slot.
            # This limits address poisoning; it is not a Sybil-resistance proof.
            if not old and source is not None and sum(v==source for v in self.origins.values())>=2:return False
            if not old and len(self.values)>=MAX_CANDIDATES:return False
            self.values[value['onion']]=dict(value)
            if not old:
                self.origins[value['onion']]=source or 'manual:'+value['onion']
                self.records[value['onion']]=dict(added=self.clock(),verified_at=0.,selected_at=-1.,retry_at=0.,retirements=0,seed=bool(source and source.startswith('seed:')))
            if verified:
                self.verified.add(value['onion']);self.records[value['onion']]['verified_at']=self.clock()
            return not old
    def catalog(self):
        with self.lock:
            self.prune();return [dict(v) for k,v in self.values.items() if k in self.verified][:MAX_PEERS]
    def candidates(self):
        with self.lock:
            self.prune();return [dict(v) for v in self.values.values()]
    def retire(self,name):
        with self.lock:
            if name not in self.records:return
            record=self.records[name];record['retirements']=min(4,record['retirements']+1)
            record['retry_at']=self.clock()+min(600,30*2**record['retirements'])
            self.verified.discard(name)
    def select(self,active,limit,reserve=True):
        with self.lock:
            if limit<=0:return []
            self.prune();now=self.clock();counts={};chosen=[]
            for name in active:
                origin=self.origins.get(name);counts[origin]=counts.get(origin,0)+1
            for name in sorted(self.values,key=lambda n:(self.records[n]['selected_at'],n)):
                record=self.records[name];origin=self.origins[name]
                if name in active or record['retry_at']>now or counts.get(origin,0)>=2:continue
                chosen.append(dict(self.values[name]));counts[origin]=counts.get(origin,0)+1
                if reserve:record['selected_at']=now
                if len(chosen)>=limit:break
            return chosen

class PublicChannel(onion.Channel):
    """Bounded persistent TLS sessions, challenge authentication, no run tickets.

    Outbound sessions are serialized per peer; never shared across peer/pin contexts.
    Session lifetime 60 seconds/64 frames/2 MiB. Each connection attempt has separate
    SOCKS, TLS and application allowances, each at most 12 seconds, overall 36.
    """
    def __init__(self,*args,own,key,certificate,directory,**kwargs):
        super().__init__(*args,certificate=certificate,key=key,**kwargs)
        if self.peer:self.peer=dict(self.peer)
        self.peer_context=self.context_key(self.peer) if self.peer else None
        self.own=own;self.key=Path(key);self.cert=Path(certificate);self.directory=directory
        self.reuse_lock=threading.Lock();self.cached=None;self.cached_context=None;self.cached_at=0.;self.cached_frames=0;self.cached_bytes=0
        self.active=set();self.active_guard=threading.Lock();self.errors={};self.connections=0
        self.identity_leases=set()
        # Reconnecting or changing certificate cannot reset these budgets.
        self.handshakes=Budget(8,1)
        self.requests=Budget(64,16)
        self.traffic=Budget(4*1024*1024,512*1024)
    @staticmethod
    def context_key(peer):
        return tuple(peer[k] for k in ('onion','certificate_sha256','network','genesis','profile'))
    def track(self,stream):
        with self.active_guard:self.active.add(stream)
        return stream
    def drop(self,stream):
        if stream:
            with self.active_guard:self.active.discard(stream)
            try:stream.close()
            except OSError:pass
    def invalidate(self):
        self.drop(self.cached);self.cached=None;self.cached_context=None
    def connect(self):
        overall=time.monotonic()+36
        raw=self.track(self.pc.connect(dict(endpoint=self.peer['onion'],socks_port=self.socks,target_port=80),min(overall,time.monotonic()+12)))
        try:
            raw.settimeout(min(12,max(.001,overall-time.monotonic())))
            secure=self.ctx.wrap_socket(raw,server_hostname=None,do_handshake_on_connect=False);self.track(secure);self.drop(raw)
            secure.do_handshake()
            onion.pinned(secure,self.peer)
            end=min(overall,time.monotonic()+12)
            self.pc.write(secure,HELLO,end);challenge=self.pc.read(secure,32,end)
            own=onion.descriptor(self.own())
            message=HELLO+challenge+self.pc.f.canonical(own)
            sig=proof(self.key,None,message)
            send_json(self.pc,secure,dict(descriptor=own,certificate=self.cert.read_text(),signature=sig.hex()),end)
            response=read_json(self.pc,secure,end)
            if set(response)!={'descriptor','peers'} or response['descriptor']!=self.peer:raise ValueError('PUBLIC_HANDSHAKE_IDENTITY')
            self.directory.add(self.peer,verified=True)
            if not isinstance(response['peers'],list) or len(response['peers'])>8:raise ValueError('PUBLIC_PEER_BOUND')
            for hint in response['peers']:self.directory.add(hint,source=self.peer['onion'])
            self.connections+=1
            self.cached=secure;self.cached_at=time.monotonic();self.cached_frames=0;self.cached_bytes=0
            self.cached_context=self.context_key(own)
            return secure
        except BaseException:
            self.drop(raw)
            if 'secure' in locals():self.drop(secure)
            raise
    def outbound(self,source):
        # Acquire before reading native request; no uncontrolled retry or tx replay.
        if not self.reuse_lock.acquire(timeout=1):raise ValueError('PUBLIC_PEER_BUSY')
        try:
            with self.guard:
                if time.monotonic()<self.next_attempt:raise ValueError('PUBLIC_BACKOFF')
            if self.context_key(onion.descriptor(self.peer))!=self.peer_context:raise ValueError('PUBLIC_SECURITY_CONTEXT_CHANGED')
            if self.cached and self.context_key(onion.descriptor(self.own()))!=self.cached_context:self.invalidate()
            if self.cached and (time.monotonic()-self.cached_at>=60 or self.cached_frames>=64 or self.cached_bytes>=2*1024*1024):self.invalidate()
            end=time.monotonic()+12
            request=self.pc.frame(source,end,True)
            if self.cached and self.cached_bytes+len(request)>2*1024*1024:self.invalidate()
            secure=self.cached or self.connect()
            end=time.monotonic()+12
            self.pc.write(secure,request,end)
            response=self.pc.frame(secure,end,False)
            if self.cached_bytes+len(request)+len(response)>2*1024*1024:raise ValueError('PUBLIC_SESSION_BYTE_BOUND')
            self.pc.write(source,response,end)
            self.cached_frames+=1;self.cached_bytes+=len(request)+len(response)
            with self.guard:self.forwarded+=1;self.last_success=time.monotonic();self.failures=0;self.next_attempt=0
        except BaseException as error:
            if not isinstance(error,ValueError) or str(error)!='PUBLIC_BACKOFF':
                self.invalidate()
                with self.guard:
                    if time.monotonic()>=self.next_attempt:
                        self.failures=min(6,self.failures+1);self.next_attempt=time.monotonic()+min(30,2**(self.failures-1))
            raise
        finally:self.reuse_lock.release()
    def inbound(self,source):
        end=time.monotonic()+12;source.settimeout(12)
        secure=self.track(self.ctx.wrap_socket(source,server_side=True,do_handshake_on_connect=False))
        leased=None
        try:
            secure.do_handshake()
            end=time.monotonic()+12
            if self.pc.read(secure,8,end)!=HELLO:raise ValueError('PUBLIC_PROTOCOL_VERSION')
            challenge=secrets.token_bytes(32);self.pc.write(secure,challenge,end)
            remote=read_json(self.pc,secure,end)
            if not isinstance(remote,dict) or set(remote)!={'descriptor','certificate','signature'}:raise ValueError('PUBLIC_HANDSHAKE_SCHEMA')
            peer=onion.descriptor(remote['descriptor'])
            cert=remote['certificate']
            if not isinstance(cert,str) or len(cert)>16384 or not isinstance(remote['signature'],str) or len(remote['signature'])!=128:raise ValueError('PUBLIC_PROOF_BOUND')
            der=ssl.PEM_cert_to_DER_cert(cert)
            if hashlib.sha256(der).hexdigest()!=peer['certificate_sha256']:raise ValueError('PUBLIC_PROOF_PIN')
            proof(None,cert.encode(),HELLO+challenge+self.pc.f.canonical(peer),bytes.fromhex(remote['signature']))
            with self.active_guard:
                if peer['certificate_sha256'] in self.identity_leases:raise ValueError('PUBLIC_IDENTITY_SESSION_LIMIT')
                leased=peer['certificate_sha256'];self.identity_leases.add(leased)
            self.directory.add(peer,source='inbound')  # Candidate only; callback must prove reachability.
            # Possession authenticates the TLS identity, not claimed Onion ownership.
            # Do not gossip unverified inbound descriptors; outbound confirmation is required.
            send_json(self.pc,secure,dict(descriptor=onion.descriptor(self.own()),peers=self.directory.catalog()),end)
            born=time.monotonic();used=0
            for _ in range(64):
                if self.stop.is_set() or time.monotonic()-born>=60 or used>=2*1024*1024:break
                end=min(born+60,time.monotonic()+12)
                request=self.pc.frame(secure,end,True)
                if used+len(request)>2*1024*1024:raise ValueError('PUBLIC_SESSION_BYTE_BOUND')
                if not self.requests.take() or not self.traffic.take(len(request)):raise ValueError('PUBLIC_RESOURCE_BUDGET')
                target=self.track(socket.create_connection(('127.0.0.1',self.target),timeout=3))
                try:
                    self.pc.write(target,request,end);response=self.pc.frame(target,end,False)
                    if used+len(request)+len(response)>2*1024*1024:raise ValueError('PUBLIC_SESSION_BYTE_BOUND')
                    if not self.traffic.take(len(response)):raise ValueError('PUBLIC_RESOURCE_BUDGET')
                    self.pc.write(secure,response,end);used+=len(request)+len(response)
                finally:self.drop(target)
        finally:
            if leased:
                with self.active_guard:self.identity_leases.discard(leased)
            self.drop(secure)
    def handle(self,source):
        self.track(source)
        try:
            # Before TLS or OpenSSL proof subprocesses; no sleeping worker queue.
            if not self.peer and not self.handshakes.take():raise ValueError('PUBLIC_RESOURCE_BUDGET')
            if self.peer:self.outbound(source)
            else:self.inbound(source)
        except Exception as error:
            # Fixed categories only, never raw exceptions or peer payloads.
            category='RESOURCE_LIMIT' if isinstance(error,ValueError) and str(error)=='PUBLIC_RESOURCE_BUDGET' else 'TIMEOUT' if isinstance(error,TimeoutError) else 'REJECTED' if isinstance(error,ValueError) else 'CONNECTION_LOST'
            with self.guard:self.errors[category]=min(100000,self.errors.get(category,0)+1)
        finally:self.drop(source);self.slots.release()
    def close(self):
        self.stop.set();self.listener.close()
        with self.active_guard:active=list(self.active)
        for stream in active:
            try:stream.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            self.drop(stream)
        for thread in self.threads:thread.join(4)
        self.cached=None

class PeerService:
    """Transport controller shared by product Tor and local SOCKS integration tests."""
    def __init__(self,ingress,node_p2p,connector_base,socks,own,key,certificate,initial=()):
        self.directory=Directory(initial);self.ingress=ingress;self.node_p2p=node_p2p
        self.connector_base=connector_base;self.socks=socks;self.own=own;self.key=key;self.certificate=certificate
        self.channels=[];self.threads=[];self.stop=threading.Event();self.assigned=set();self.manager=None;self.manager_failures=0;self.own_onion=None
        self.lifecycle=threading.RLock();self.slots={};self.rotations=0;self.retired_forwarded=0;self.retired_connections=0;self.last_rotation=0.
    def reconcile(self,now=None):
        now=time.monotonic() if now is None else now
        with self.lifecycle:
            if self.stop.is_set():return
            own=onion.descriptor(self.own());self.own_onion=own['onion'];self.directory.remove(self.own_onion)
            pending=self.directory.select(self.assigned|{self.own_onion},8-len(self.slots))
            # Free failed slots, or rotate a long-held slot when alternatives exist.
            alternatives=self.directory.select(self.assigned|{self.own_onion},1,reserve=False)
            known={v['onion'] for v in self.directory.candidates()}
            for number,(ch,thread,born) in list(self.slots.items()):
                with ch.guard:failed=ch.failures>=3;age=now-born
                if ch.peer['onion']==self.own_onion or ch.peer['onion'] not in known or failed or (age>=300 and alternatives and now-self.last_rotation>=30):
                    ch.close();thread.join(1)
                    if thread.is_alive():raise RuntimeError('PUBLIC_RETIRED_LISTENER_NOT_CLOSED')
                    self.retired_forwarded+=ch.forwarded;self.retired_connections+=ch.connections;self.directory.retire(ch.peer['onion']);self.assigned.discard(ch.peer['onion'])
                    self.channels.remove(ch);self.threads.remove(thread);del self.slots[number];self.rotations+=1;self.last_rotation=now
                    # Rotate one healthy slot at a time; keep other independent paths.
                    if not failed:break
            pending+=self.directory.select(self.assigned|{v['onion'] for v in pending}|{self.own_onion},8-len(self.slots)-len(pending))
            for peer in pending:
                if self.stop.is_set():break
                number=next(n for n in range(8) if n not in self.slots)
                ch=PublicChannel(self.connector_base+number,80,peer=peer,socks=self.socks,own=self.own,key=self.key,certificate=self.certificate,directory=self.directory)
                thread=threading.Thread(target=ch.run,daemon=True);self.channels.append(ch);self.threads.append(thread)
                self.slots[number]=(ch,thread,now);self.assigned.add(peer['onion'])
                try:thread.start()
                except BaseException:
                    ch.close();self.channels.remove(ch);self.threads.remove(thread);del self.slots[number];self.assigned.discard(peer['onion']);raise
    def start(self):
        def start_channel(ch):
            self.channels.append(ch);t=threading.Thread(target=ch.run,daemon=True);self.threads.append(t);t.start()
        start_channel(PublicChannel(self.ingress,self.node_p2p,own=self.own,key=self.key,certificate=self.certificate,directory=self.directory))
        def maintain():
            while not self.stop.wait(.2):
                try:
                    self.reconcile()
                except Exception:self.manager_failures=min(100000,self.manager_failures+1)
        self.manager=threading.Thread(target=maintain,daemon=True);self.manager.start()
    def close(self):
        self.stop.set()
        if self.manager:
            self.manager.join(20)
            if self.manager.is_alive():raise RuntimeError('PUBLIC_MANAGER_NOT_CLOSED')
        with self.lifecycle:
            for ch in self.channels:ch.close()
            for t in self.threads:t.join(1)

    def status(self):
        now=time.monotonic()
        return dict(known_peers=sum(p['onion']!=self.own_onion for p in self.directory.candidates()),authenticated_peer_identities=len(self.directory.verified-{self.own_onion}),
            recent_authenticated_peers=sum(bool(ch.peer and ch.last_success and now-ch.last_success<60) for ch in self.channels),
            forwarded_requests=self.retired_forwarded+sum(ch.forwarded for ch in self.channels),transport_connections=self.retired_connections+sum(ch.connections for ch in self.channels),rotations=self.rotations,
            admission='TICKET_FREE_PUBLIC_DEVELOPMENT',manager_failures=self.manager_failures,sybil_resistance='NOT_ESTABLISHED')

def require_public_context():
    """Revalidate the selected network before creating any transport state.

    Bound review identities are accepted through the strict profile loader,
    never by a string prefix or by trusting a peer's advertised identity.
    Production selectors remain unavailable.
    """
    from src import network_identity as ni
    import os
    selector=os.environ.get('PC_DEVELOPMENT_NETWORK','legacy-dev01')
    if selector not in ('open-dev02','candidate-lab','mainnet-v1'):
        raise ValueError('EXPLICIT_OPEN_DEVELOPMENT_NETWORK_REQUIRED')
    expected=ni.selected(selector)
    if (ni.NETWORK,ni.GENESIS,ni.PROFILE)!=expected:
        raise ValueError('TRANSPORT_CONTEXT_MISMATCH')
    return expected

class PublicTorSession(onion.TorSession):
    """Public-admission lifecycle: fixed native slots, automatic bounded gossip.

    No private tickets, central enrollment or wallet identity. Seed descriptors are
    hints; only TLS-pinned outbound handshakes promote hints to advertised peers.
    Different operators' seeds are recommended; no Sybil resistance is claimed.
    """
    def __init__(self,*args,connector_base,upstream=None,**kwargs):
        require_public_context()
        super().__init__(*args,**kwargs)
        if type(connector_base) is not int or not 1024<=connector_base<=65528:raise ValueError('PUBLIC_CONNECTOR_PORTS')
        self.connector_base=connector_base;self.directory=Directory([p for _,p in self.peers])
        self.own_pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.pc.c.read_private(self.cert).decode())).hexdigest()
        from .upstream import validate,directive
        self.upstream=validate(upstream) if upstream is not None else None
        if self.upstream is not None:
            self.lines.append(directive(self.upstream))
            _,_,write_config,_=onion.dependencies();write_config(self.config,self.lines)
    def make_channels(self):
        self.service=PeerService(self.ingress,self.node_p2p,self.connector_base,self.socks,self.public_descriptor,self.key,self.cert,self.directory.candidates())
        self.directory=self.service.directory
        self.service.start()
    def start(self,consent):
        if consent!='CONNECT VIA TOR':raise ValueError('EXPLICIT_TOR_CONSENT_REQUIRED')
        if self.owned.process is not None and self.owned.process.poll() is None:raise ValueError('TOR_ALREADY_RUNNING')
        if self.upstream is not None:
            from .upstream import probe
            probe(self.upstream) # Refuse before starting Tor; no direct fallback.
        if getattr(self,'service',None):self.service.close();self.service=None
        super().start(consent)
    def close(self):
        if getattr(self,'service',None):self.service.close();self.service=None
        super().close()
    def status(self):
        value=super().status()
        if getattr(self,'service',None):value.update(self.service.status())
        value.update(admission='TICKET_FREE_PUBLIC_DEVELOPMENT',
                     bootstrap='NO_OPERATIONAL_SEEDS' if not self.directory.candidates() else 'UNTRUSTED_REPLACEABLE_HINTS',
                     sybil_resistance='NOT_ESTABLISHED')
        return value
