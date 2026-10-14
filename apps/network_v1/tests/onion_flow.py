"""Owned loopback SOCKS/TLS or actual isolated TestingTorNetwork, never public Tor."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import sys
import threading
import time
import types


def main():
    p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);p.add_argument('--native-root',type=Path,required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--tor',type=Path,required=True);p.add_argument('--private-tor',action='store_true');a=p.parse_args()
    if a.fixture.exists() or a.report.exists() or not str(a.fixture).startswith('/home/privacydev/pc-v1-fixtures-'):raise ValueError('NEW_ISOLATED_PATHS_REQUIRED')
    os.umask(0o077);a.fixture.mkdir(mode=0o700)
    os.environ['PC_DEVNET_NATIVE_ROOT']=str(a.native_root);os.environ['PC_DEVNET_BUILD_MANIFEST']=str(a.native_root/'build/v1-native-manifest.json')
    from apps.network_v1.onion import Channel,TorSession,discover,descriptor,dependencies
    from apps.network_v1.rpc import NETWORK,GENESIS,PROFILE
    pc,*_=dependencies()
    from runtime import OwnedNode
    from tor_runtime import PrivateNetwork
    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    def request(n,cmd='status'):
        with socket.create_connection(('127.0.0.1',n),timeout=12) as sock:
            raw=pc.f.canonical(dict(network=NETWORK,genesis=GENESIS,profile=PROFILE,command=cmd));pc.write(sock,NETWORK.encode()+len(raw).to_bytes(4,'big')+raw,time.monotonic()+12)
            return pc.f.decode(pc.frame(sock,time.monotonic()+12,False)[20:])
    checks=[];channels=[];nodes=[];network=None;fake=None;managed=None
    def check(label,condition=True):
        if not condition:raise AssertionError(label)
        checks.append(label);print('PASS',label,flush=True)
    def start(ch):
        t=threading.Thread(target=ch.run,daemon=True);t.start();channels.append((ch,t));return ch
    try:
        ingress=port();A=OwnedNode(a.fixture,'A');B=OwnedNode(a.fixture,'B');nodes=[A,B];A.start()
        managed=TorSession(a.fixture/'disabled-managed-tor',a.tor,A.p2p,port(),port(),ingress)
        try:managed.start('WRONG CONSENT')
        except ValueError:check('public Tor activation without explicit consent rejected')
        else:raise AssertionError('consent')
        managed.owned.start();end=time.monotonic()+10
        while True:
            try:control_reply=managed.owned.control('GETINFO status/bootstrap-phase');break
            except (OSError,ValueError):
                if time.monotonic()>end:raise
                time.sleep(.05)
        check('actual disabled Tor process control authentication',b'250' in control_reply);managed.owned.close()
        before=managed.key.read_bytes();managed=TorSession(managed.home,a.tor,A.p2p,managed.socks,port(),ingress);check('TLS identity persists across session reconstruction',managed.key.read_bytes()==before)
        # Real listener fault, before OwnedTor.start can execute. Never enable
        # public Tor: force a later connector bind to fail during construction.
        from unittest.mock import patch
        from .test_network_stability import peer as test_peer
        available=port()
        with socket.socket() as collision:
            collision.bind(('127.0.0.1',0));blocked=collision.getsockname()[1]
            managed.peers=[(available,test_peer(1)),(blocked,test_peer(2))]
            with patch.object(managed.owned,'start',side_effect=AssertionError('MUST_NOT_START_PUBLIC_TOR')):
                try:managed.start('CONNECT VIA TOR')
                except OSError:pass
                else:raise AssertionError('expected owned bind conflict')
            for n in (ingress,available):
                with socket.socket() as probe:probe.bind(('127.0.0.1',n))
            check('actual partial-start bind failure frees all prior listeners',not managed.channels)
        managed.peers=[]
        catalog=[];server=start(Channel(ingress,A.p2p,certificate=managed.cert,key=managed.key,catalog=lambda:catalog))
        if a.private_tor:
            network=PrivateNetwork(a.fixture/'private-tor',ingress,binary=a.tor,experimental_upstream=True);network.start();endpoint=network.hostname;socks=network.socks_port
        else:
            raw=b'\x11'*32;endpoint=base64.b32encode(raw+hashlib.sha3_256(b'.onion checksum'+raw+b'\x03').digest()[:2]+b'\x03').decode().lower()+'.onion'
            fake=socket.socket();fake.bind(('127.0.0.1',0));fake.listen(8);fake.settimeout(.2);socks=fake.getsockname()[1];stop=threading.Event()
            def relay(source):
                target=None
                try:
                    end=time.monotonic()+15
                    assert pc.read(source,3,end)==b'\x05\x01\x00';pc.write(source,b'\x05\x00',end);assert pc.read(source,4,end)==b'\x05\x01\x00\x03'
                    n=pc.read(source,1,end)[0];assert pc.read(source,n,end).decode()==endpoint;assert pc.read(source,2,end)==b'\x00P'
                    target=socket.create_connection(('127.0.0.1',ingress),timeout=5);pc.write(source,b'\x05\x00\x00\x01'+b'\x00'*6,end)
                    while not stop.is_set() and time.monotonic()<end:
                        ready,_,_=select.select([source,target],[],[],.2)
                        for stream in ready:
                            data=stream.recv(65536)
                            if not data:return
                            (target if stream is source else source).sendall(data)
                except Exception:pass
                finally:
                    source.close()
                    if target:target.close()
            def accept():
                while not stop.is_set():
                    try:s,_=fake.accept()
                    except socket.timeout:continue
                    except OSError:break
                    threading.Thread(target=relay,args=(s,),daemon=True).start()
            threading.Thread(target=accept,daemon=True).start()
        import ssl
        peer=descriptor(dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,onion=endpoint,certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(managed.cert.read_text())).hexdigest()));catalog.append(peer)
        connector=start(Channel(port(),80,peer=peer,socks=socks));end=time.monotonic()+90
        while True:
            try:observed=request(connector.listener.getsockname()[1]);break
            except Exception:
                if time.monotonic()>end:raise
                time.sleep(1)
        check('Onion domain SOCKS + pinned TLS actual P2P response',observed['tip']==GENESIS)
        check('bounded authenticated discovery returns public descriptors',discover(peer,socks)==[peer])
        B.start(peer=types.SimpleNamespace(p2p=connector.listener.getsockname()[1]));address=pc.f.address(pc.f.full(),0);stamp=int(time.time())-120*500
        for _ in range(3):stamp+=120;A.mine(address,stamp)
        end=time.monotonic()+40
        while A.status()!=B.status() and time.monotonic()<end:time.sleep(.1)
        check('two real validating processes synchronize over transport',A.status()==B.status())
        try:request(connector.listener.getsockname()[1],'submit_tx')
        except Exception:check('privileged RPC refused by P2P frame boundary')
        else:raise AssertionError('RPC route')
        bad=dict(peer,certificate_sha256='0'*64);wrong=start(Channel(port(),80,peer=bad,socks=socks))
        try:request(wrong.listener.getsockname()[1])
        except Exception:check('incorrect TLS pin fails closed')
        else:raise AssertionError('pin')
        check('retry backoff is bounded and active',wrong.failures==1 and wrong.next_attempt>time.monotonic())
        B.stop();B.start(peer=types.SimpleNamespace(p2p=connector.listener.getsockname()[1]));end=time.monotonic()+15
        while True:
            try:reconnected=request(connector.listener.getsockname()[1]);break
            except Exception:
                if time.monotonic()>end:raise
                time.sleep(.2)
        check('reconnection uses same authenticated transport',reconnected['tip']==A.status()['tip'])
        if network:network.close();network=None
        if fake:stop.set();fake.close();fake=None
        try:request(connector.listener.getsockname()[1])
        except Exception:check('proxy outage fails closed without direct fallback')
        else:raise AssertionError('fallback')
        report=dict(result='PASS_ISOLATED_TOR_ONION_FLOW' if a.private_tor else 'PASS_LOOPBACK_SOCKS_TLS_FLOW_NOT_TOR_ROUTING',checks=checks,public_tor=False,physical_hosts='NOT_TESTED',mode='ACTUAL_TESTING_TOR_NETWORK' if a.private_tor else 'EMULATED_SOCKS_REAL_TLS_AND_NODES')
    except Exception as error:report=dict(result='FAIL_OR_EXTERNAL_TOR_BLOCKER',failure_type=type(error).__name__,checks=checks,public_tor=False,physical_hosts='NOT_TESTED')
    finally:
        for ch,t in channels:ch.close();t.join(1)
        for n in nodes:n.stop()
        if network:network.close()
        if fake:stop.set();fake.close()
        if managed:managed.close()
    a.report.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));sys.exit(0 if report['result'].startswith('PASS') else 1)


if __name__=='__main__':main()
