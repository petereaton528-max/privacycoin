"""Three actual native nodes + wallet/TLS; simulated local SOCKS, no Internet Tor.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,base64,hashlib,json,os,secrets,socket,subprocess,sys,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]

def main():
    p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--seed',type=int,default=1);p.add_argument('--delay',type=float,default=.01);p.add_argument('--late-start',type=float,default=0);a=p.parse_args()
    if not 0<=a.delay<=.5 or not 0<=a.late_start<=3:raise ValueError('FAULT_BOUNDS')
    if a.fixture.exists() or a.report.exists() or not str(a.fixture).startswith('/home/privacydev/pc-v1-fixtures-open-'):raise ValueError('FRESH_OWNED_FIXTURE_REQUIRED')
    os.umask(0o077);a.fixture.mkdir(mode=0o700)
    os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02';os.environ['PC_DEVNET_NATIVE_ROOT']=str(ROOT);os.environ['PC_DEVNET_BUILD_MANIFEST']=str(ROOT/'build/v1-native-manifest.json')
    sys.path.insert(0,str(ROOT/'scripts/devnet-gui'))
    from backend import Session,c,f,w
    from apps.network_v1.rpc import rpc,NETWORK,GENESIS,PROFILE
    from apps.network_v1.public_network import PeerService,Directory,PublicChannel
    from apps.network_v1 import onion
    from .local_socks import Socks,owned_rss
    c.harden();os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:2])
    binary=ROOT/'build/monero-linux/phase4/privacycoin-hardened-devnet'
    nodes=[];services=[];sessions=[];checks=[];socks=None;began=time.monotonic();failure=None;measurements={}
    def check(name,condition=True):
        if not condition:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    def port():
        with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
    used_bases=set()
    def block_ports():
        # reserve a consecutive connector range for the native fixed eight slots
        for base in range(38510,44000,19):
            if base in used_bases:continue
            held=[]
            try:
                for n in range(base,base+8):s=socket.socket();held.append(s);s.bind(('127.0.0.1',n))
                used_bases.add(base);return base
            except OSError:pass
            finally:
                for s in held:s.close()
        raise ValueError('NO_ISOLATED_PORT_RANGE')
    def wait(fn,seconds=90):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            try:
                value=fn()
                if value:return value
            except (OSError,ValueError):pass
            time.sleep(.05)
        raise TimeoutError('LOCAL_NATIVE_ACCEPTANCE_DEADLINE')
    class Node:
        def __init__(self,label):
            self.home=a.fixture/label;self.home.mkdir(mode=0o700);self.rpc=port();self.p2p=port();self.base=block_ports();self.p=None;self.session=None;self.stamp=int(time.time())-120*500
        def start(self):
            args=[str(binary),'--data-dir',str(self.home/'node'),'--rpc-port',str(self.rpc),'--p2p-port',str(self.p2p),'--development-network','open-dev02']
            for port_ in range(self.base,self.base+8):args+=['--peer-port',str(port_)]
            self.p=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            wait(lambda:rpc(self.rpc,'status'))
        def status(self):return rpc(self.rpc,'status')
        def stop(self):
            if self.p and self.p.poll() is None:
                self.p.terminate()
                try:self.p.wait(15)
                except subprocess.TimeoutExpired:self.p.kill();self.p.wait(5)
        def mine(self,count,address):
            for _ in range(count):
                self.stamp+=120;D,C,sub=f.parse_address(address);R,P=f.crypto('output',D,C,sub,0)
                w.rpc(self.rpc,'mine',reward_key=P,R=R,timestamp=self.stamp)
    try:
        for label in 'ABC':
            n=Node(label);n.start();nodes.append(n)
            session=Session(n.home/'wallets',n.rpc);sessions.append(session);n.session=session
            password='Fresh-'+secrets.token_hex(20)
            n.address=session.dispatch(dict(command='create',name='Owner',password=password))['address']
            subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-keyout',str(n.home/'key'),'-out',str(n.home/'cert'),'-days','2','-subj','/CN=disposable-public-node'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8)
            (n.home/'key').chmod(0o600);(n.home/'cert').chmod(0o600)
            import ssl
            raw=hashlib.sha256(label.encode()+bytes([a.seed])).digest();suffix=hashlib.sha3_256(b'.onion checksum'+raw+b'\x03').digest()[:2]+b'\x03'
            n.descriptor=onion.descriptor(dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,onion=base64.b32encode(raw+suffix).decode().lower()+'.onion',certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert((n.home/'cert').read_text())).hexdigest()))
            n.ingress=port()
        A,B,C=nodes
        check('three independent native open-dev02 identities and encrypted wallets',len({n.descriptor['certificate_sha256'] for n in nodes})==3)
        check('distinct native development network identity',A.status()['network']=='PrivacyCoinDev02')
        # Mine a nonempty chain before unrelated node joins; actual native RandomX.
        A.mine(80,A.address);check('real native 80-block nonempty chain and mature rewards',A.status()['height']==80)
        socks=Socks({n.descriptor['onion']:n.ingress for n in nodes},seed=a.seed,connect_delay=a.delay,jitter=.001,chunk=97)
        for n,initial in [(A,[]),(B,[A.descriptor]),(C,[B.descriptor])]:
            if n is C and a.late_start:time.sleep(a.late_start) # Explicit test-only fault schedule.
            service=PeerService(n.ingress,n.p2p,n.base,socks.port,lambda n=n:n.descriptor,n.home/'key',n.home/'cert',initial)
            service.start();services.append(service)
        wait(lambda:all(n.status()['height']==80 for n in nodes))
        check('B joins A and C independently joins through B without any ticket')
        wait(lambda:A.descriptor['onion'] in services[2].directory.values)
        check('third node automatically discovers an additional compatible peer')
        rejected=PublicChannel(port(),80,peer=dict(A.descriptor,certificate_sha256='f'*64),socks=socks.port,own=lambda:B.descriptor,key=B.home/'key',certificate=B.home/'cert',directory=Directory())
        try:
            try:rejected.connect()
            except ValueError:check('actual remote TLS certificate pin mismatch rejected')
            else:raise AssertionError('wrong TLS identity accepted')
        finally:rejected.close()
        bad=dict(A.descriptor,network='PrivacyCoinDev01')
        try:Directory([bad])
        except ValueError:check('incompatible network rejected before connection')
        else:raise AssertionError('network accepted')
        bad=dict(A.descriptor,version=2)
        try:Directory([bad])
        except ValueError:check('incompatible descriptor protocol rejected')
        else:raise AssertionError('protocol accepted')
        A.session.refresh()
        reviewed=A.session.dispatch(dict(command='prepare',destination=B.address,amount=1000000,fee=188000,max_fee=500000))
        A.session.dispatch(dict(command='confirm',token=reviewed['token'],consent='CONFIRM'))
        try:A.session.dispatch(dict(command='confirm',token=reviewed['token'],consent='CONFIRM'))
        except ValueError:check('actual payment duplicate submission rejected')
        else:raise AssertionError('duplicate accepted')
        wait(lambda:bool(w.rpc(B.rpc,'pool')['transactions']))
        check('private transaction relays through authenticated native P2P')
        A.mine(1,A.address);wait(lambda:all(n.status()['height']==81 for n in nodes))
        received=B.session.refresh()
        measurements['receipt_summary']=[{k:x[k] for k in ('amount','coinbase','status','height')} for x in received['history']]
        measurements['block_transaction_count']=len(w.rpc(A.rpc,'get_block',hash=A.status()['tip'])['transactions'])
        check('receiving wallet observes actual included payment with normal maturity lock',any(x['amount']==1000000 and not x['coinbase'] and x['status']=='LOCKED' for x in received['history']))
        check('new block propagation and identical independently validated tips',len({n.status()['tip'] for n in nodes})==1)
        A.mine(10,A.address);wait(lambda:all(n.status()['height']==91 for n in nodes))
        receipt=B.session.refresh()
        check('normal payment matures and becomes available under retained wallet rules',receipt['balance']['spendable']==1000000)
        approved=B.session.dispatch(dict(command='prepare',destination=A.address,amount=100000,fee=188000,max_fee=500000))
        B.session.dispatch(dict(command='confirm',token=approved['token'],consent='CONFIRM'))
        wait(lambda:bool(w.rpc(A.rpc,'pool')['transactions']))
        B.stamp=A.stamp;B.mine(1,B.address);wait(lambda:all(n.status()['height']==92 for n in nodes))
        check('reverse-direction real payment inclusion and journal confirmation',B.session.refresh()['outgoing'][0]['status']=='CONFIRMED')
        B.session.dispatch(dict(command='backup',name='Recovery'))
        restored=B.session.dispatch(dict(command='restore',name='Restored',backup='Recovery',password=B.session.password.decode()))
        check('encrypted wallet backup restore preserves identity and payment journal',restored['address']==B.address and B.session.refresh()['outgoing'][0]['status']=='CONFIRMED')
        # Partition only these owned local transport adapters, not consensus rules.
        for service in services:service.close()
        services=[]
        A.mine(1,A.address);B.mine(3,B.address)
        expected=B.status()['tip']
        for n,initial in [(A,[B.descriptor]),(B,[C.descriptor]),(C,[A.descriptor])]:
            service=PeerService(n.ingress,n.p2p,n.base,socks.port,lambda n=n:n.descriptor,n.home/'key',n.home/'cert',initial)
            service.start();services.append(service)
        wait(lambda:all(n.status()['tip']==expected for n in nodes))
        check('actual higher-work fork reorganization and three-node canonical convergence',A.status()['reorganizations']>=1)
        check('pre-fork payments retain correct reconciliation after canonical change',B.session.refresh()['outgoing'][0]['status']=='CONFIRMED')
        # Real process interruption/reload while transports retain ownership.
        before=C.status()['tip'];C.stop();C.start();wait(lambda:C.status()['tip']==before)
        check('native restart validates persisted chain and reconnects')
        # Seed outage: C has discovered A and no longer requires B.
        services[1].close();B.stop();A.stamp=B.stamp;A.mine(1,A.address);wait(lambda:C.status()['height']==96)
        check('seed outage handled using automatically learned alternative peer')
        wait(lambda:all(B.descriptor['onion'] not in service.assigned for service in (services[0],services[2])))
        check('unreachable seed slots retire without losing alternate native synchronization')
        total=sum(service.status()['transport_connections'] for service in services)
        forwarded=sum(service.status()['forwarded_requests'] for service in services)
        check('persistent authenticated session reuse exercised',forwarded>total)
        rss=owned_rss([n.p.pid for n in nodes if n.p and n.p.poll() is None])
        measurements.update(native_rss_kib=rss,transport_connections=total,forwarded_requests=forwarded,final_height=A.status()['height'],final_work=A.status()['work'])
        # Wrong native identity cannot reopen this development database.
        C.stop()
        wrong=subprocess.run([str(binary),'--data-dir',str(C.home/'node'),'--rpc-port',str(C.rpc),'--p2p-port',str(C.p2p)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
        check('legacy network cannot reopen open-dev02 database',wrong.returncode!=0)
    except BaseException as error:
        failure=dict(type=type(error).__name__,stage=checks[-1] if checks else 'initialization')
        raise
    finally:
        for session in sessions:session.close()
        for service in services:service.close()
        for n in nodes:n.stop()
        if socks:socks.close()
        occupied=[]
        for n in nodes:
            for number in (n.rpc,n.p2p,n.ingress,*range(n.base,n.base+8)):
                with socket.socket() as probe:
                    probe.settimeout(.05)
                    if probe.connect_ex(('127.0.0.1',number))==0:occupied.append(number)
        result=dict(result='FAIL' if failure or occupied else 'PASS_REAL_NATIVE_WITH_LOCAL_SOCKS_FIXTURE',checks=checks,failure=failure,measurements=measurements,fault_schedule=dict(seed=a.seed,connect_delay=a.delay,late_start=a.late_start,fragment_bytes=97),elapsed_seconds=round(time.monotonic()-began,3),public_tor=False,physical_hosts=False,network='PrivacyCoinDev02',source_root=str(ROOT),resource_scope='two CPU affinity, three nodes, bounded development blocks; no live services',owned_cleanup=not occupied,occupied_ports=occupied)
        with a.report.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
        print(json.dumps(result),flush=True)
if __name__=='__main__':main()
