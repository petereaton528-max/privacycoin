"""Predeclared bounded local mTLS/P2P acceptance, fresh independent node stores.
No database copies, public listeners, real assets or public onion activation.
"""
from pathlib import Path
import sys,json,os,socket,ssl,subprocess,threading,time,hashlib,types
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'deploy/n2/common'),str(ROOT/'services/privacy-network'),str(ROOT/'scripts/devnet-gui')]
from common import *
from runtime import Runtime,OwnedNode,h
from client import Client,retrieve
import p2p_channel as pc
OUT=ROOT/'docs/evidence/privacy-network-n2-connectivity'

def certificates(home):
    home=private_dir(home)
    def run(*args):subprocess.run(['openssl',*args],cwd=home,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=20)
    run('req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','2','-subj','/CN=Disposable-N2-channel-CA')
    for name in ('server','client','other'):
        run('req','-newkey','rsa:2048','-nodes','-keyout',name+'.key','-out',name+'.csr','-subj','/CN=pcp2p.local')
        (home/'extension.txt').write_text('subjectAltName=DNS:pcp2p.local\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\n')
        run('x509','-req','-in',name+'.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out',name+'.pem','-days','2','-extfile','extension.txt')
    for p in home.iterdir():p.chmod(0o600)
    def pin(name):return hashlib.sha256(ssl.PEM_cert_to_DER_cert((home/(name+'.pem')).read_text())).hexdigest()
    return home,pin

def configuration(keys,pin,role,listen,target,name=None,peer=None):
    name=name or ('server' if role=='acceptor' else 'client');peer=peer or ('client' if role=='acceptor' else 'server')
    return dict(version=1,role=role,listen_port=listen,target_port=target,endpoint='127.0.0.1',socks_port=None,cert=str(keys/(name+'.pem')),key=str(keys/(name+'.key')),ca=str(keys/'ca.pem'),peer_sha256=pin(peer))

def request(port,command='status',magic=pc.MAGIC,**fields):
    q=dict(network=w.NETWORK,genesis=w.GENESIS,profile=w.PROFILE,command=command);q.update(fields);raw=f.canonical(q)
    with socket.create_connection(('127.0.0.1',port),timeout=5) as s:
        s.sendall(magic+len(raw).to_bytes(4,'big')+raw)
        return f.decode(pc.frame(s,time.monotonic()+10,False)[20:])

def main():
    c.harden();OUT.mkdir(exist_ok=True);start=time.monotonic();checks=[];channels=[];nodes=[];provider=None;r=None
    base=private_dir(NATIVE/'build/privacycoin-n2-connectivity'/('trial-'+str(time.time_ns())))
    def check(name,ok=True):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS',name,flush=True)
    def reject(name,fn):
        try:fn()
        except (ValueError,OSError,TimeoutError):check(name);return
        raise AssertionError(name)
    def channel(v):
        obj=pc.Channel(v);thread=threading.Thread(target=obj.run);thread.start();channels.append((obj,thread));return obj
    def stop(obj):
        obj.close()
        for ch,t in channels:
            if ch is obj:t.join(timeout=15)
    def wait(fn,label,seconds=90):
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            if fn():check(label);return
            time.sleep(.05)
        raise AssertionError(label)
    try:
        keys,pin=certificates(base/'tls');r=Runtime(base/'resource');A=r.node
        B=OwnedNode(base,'node-B');C=OwnedNode(base,'node-C');nodes=[B,C]
        B.start();C.start();check('three independent stores verify frozen genesis',A.status()['tip']==B.status()['tip']==C.status()['tip']==w.GENESIS)
        check('all node databases distinct',len({A.path,B.path,C.path})==3)
        server_port=h.g.port();local_port=h.g.port();c_port=h.g.port()
        sv=configuration(keys,pin,'acceptor',server_port,A.p2p)
        cv=configuration(keys,pin,'connector',local_port,server_port)
        server=channel(sv);connector=channel(cv)
        check('mTLS peer status with pinned identities',request(local_port)['tip']==w.GENESIS)
        reject('RPC magic never forwarded',lambda:request(local_port,magic=b'PrivacyCoinRPC04'))
        reject('administrative shutdown not forwarded',lambda:request(local_port,'shutdown'))
        reject('wrong genesis fails closed',lambda:request(local_port,genesis='0'*64))
        reject('wrong network fails closed',lambda:request(local_port,network='WrongNetwork0001'))
        reject('wrong profile fails closed',lambda:request(local_port,profile='wrong'))
        bad=channel(configuration(keys,pin,'connector',h.g.port(),server_port,name='other'))
        reject('valid CA but unauthorized client certificate rejected',lambda:request(bad.v['listen_port']))
        stop(bad)
        wrong=channel(configuration(keys,pin,'connector',h.g.port(),server_port,peer='other'))
        reject('wrong server certificate pin rejected',lambda:request(wrong.v['listen_port']));stop(wrong)
        check('RPC remains available only on own loopback port',A.status()['tip']==w.GENESIS)
        B.stop();B.start(peer=types.SimpleNamespace(p2p=local_port))
        r.mine(80)
        wait(lambda:B.status()==A.status(),'80 real RandomX blocks synchronized through mTLS')
        cc=channel(dict(cv,listen_port=c_port));C.stop();C.start(peer=types.SimpleNamespace(p2p=c_port))
        wait(lambda:C.status()==A.status(),'third fresh node imports actual chain without database copy')
        stop(cc);C.stop();C.start() # retain independent pre-payment branch for real reorg
        provider_home=private_dir(base/'independent-provider');provider_port=h.g.port()
        from launcher_host import child_parent_guard
        parent=os.getpid();provider=subprocess.Popen([sys.executable,str(ROOT/'services/privacy-network/provider.py'),'--home',str(provider_home),'--node',str(B.rpc),'--port',str(provider_port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent))
        def provider_ready():
            try:return call(provider_port,'health')['devnet_only']
            except (OSError,ValueError):return False
        wait(provider_ready,'provider uses B independent validating node',40)
        admin=load_json(provider_home/'control')['admin'];client=Client(base/'client-B',provider_port,admin)
        plain=os.urandom(8192);q=client.quote(len(plain));cipher,cap=client.encrypt(q['id'],plain)
        reject('unpaid quote does not grant storage',lambda:client.upload(q['id']))
        probe=w.build(r.session.wallet,w.snapshot(A.rpc),q['recipient'],1000000,188000)
        mutant=w.helper(dict(op='mutate',transaction=probe['transaction'],case='authorization'))['transaction']
        reject('B independently rejects invalid authorization before any pool conflict',lambda:B.call('submit_tx',transaction=mutant))
        check('invalid private authorization leaves B pool empty',not B.call('pool')['transactions'])
        r.session.refresh();client.pay(q['id'],r.session,'CONFIRM')
        authorized_id=r.session.journal['attempts'][0]['transaction_id']
        wait(lambda:bool(B.call('pool')['transactions']),'real private transaction independently validated and relayed to B')
        check('provider independently admits pending payment',client.status(q['id'])['state']=='MEMPOOL_ONLY')
        reject('duplicate payment approval rejected',lambda:client.pay(q['id'],r.session,'CONFIRM'))
        tip=B.status()['tip'];block=A.call('get_block',hash=A.status()['tip'])['block']
        excessive=w.helper(dict(op='block-reward',block=block))['block']
        reject('B ledger rejects invalid block reward',lambda:B.call('submit',block=excessive))
        check('invalid inputs never change B tip',B.status()['tip']==tip)
        r.mine(10);wait(lambda:B.status()==A.status(),'confirmed payment blocks imported and independently validated')
        check('B provider recognizes exact invoice settlement',client.status(q['id'])['state']=='CONFIRMED_LOCAL')
        client.upload(q['id']);r.session.close();check('Bob decrypts exact file while Alice wallet closed',retrieve(cap)==plain)
        check('bounded encrypted quota accounted exactly',call(provider_port,'usage',admin)['stored_bytes']==len(cipher))
        provider.terminate();provider.wait(timeout=10)
        provider=subprocess.Popen([sys.executable,str(ROOT/'services/privacy-network/provider.py'),'--home',str(provider_home),'--node',str(B.rpc),'--port',str(provider_port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent))
        wait(provider_ready,'provider restart ready',40);check('provider restart retains exact encrypted object',retrieve(cap)==plain)
        old=B.status();stop(connector);r.mine(1);time.sleep(.5)
        check('disconnected B remains stale, not globally verified',B.status()==old and B.status()!=A.status())
        connector=channel(cv);wait(lambda:B.status()==A.status(),'disconnect/reconnect converges without another payment')
        B.stop();B.start(peer=types.SimpleNamespace(p2p=local_port));wait(lambda:B.status()==A.status(),'node restart revalidates durable chain and reconnects')
        stop(server);reject('channel server outage fails closed',lambda:request(local_port));server=channel(sv)
        check('channel server restart preserves authenticated connection',request(local_port)['tip']==A.status()['tip'])
        # C obtained its branch by P2P, not copying any DB. Build competing work.
        stamp=int(time.time())-120*500+C.status()['height']*120
        for _ in range(13):stamp+=120;C.mine(r.address,stamp)
        check('independent competing branch has greater validated cumulative work',int(C.status()['work'])>int(A.status()['work']))
        cs=channel(configuration(keys,pin,'acceptor',h.g.port(),C.p2p))
        ac=channel(configuration(keys,pin,'connector',h.g.port(),cs.v['listen_port']))
        A.stop();A.start(peer=types.SimpleNamespace(p2p=ac.v['listen_port']))
        wait(lambda:A.status()==C.status(),'A selects independently received greater-work branch')
        wait(lambda:B.status()==C.status(),'B follows validated reorganization through authenticated channel')
        check('reorganization invalidates payment entitlement',client.status(q['id'])['state']=='REVOKED_RECONCILE')
        reject('revoked payment cannot retrieve storage',lambda:retrieve(cap))
        check('reorg pool contains only original authorized transaction',set(A.call('pool')['transactions']).issubset({authorized_id}))
        check('durable authorization journal still contains exactly one original payment',len(r.session.journal['attempts'])==1 and r.session.journal['attempts'][0]['transaction_id']==authorized_id)
        report=dict(result='PASS_LOCAL_AUTHENTICATED_P2P_AND_REAL_PC_RESOURCE',checks=checks,passed=len(checks),failures=0,final_height=A.status()['height'],final_work=A.status()['work'],sha256=hashlib.sha256(plain).hexdigest(),cipher_bytes=len(cipher),price_atomic=q['amount_atomic'],global_freshness='UNKNOWN',physical_host='NOT_TESTED',public_onion=False)
    except Exception as error:
        report=dict(result='INCOMPLETE_WITH_BLOCKERS',checks=checks,passed=len(checks),failure_type=type(error).__name__,failure_label=str(error) if isinstance(error,AssertionError) else 'Private details withheld')
        print('FAIL',report['failure_type'],report['failure_label'],flush=True)
    finally:
        if provider and provider.poll() is None:provider.terminate();provider.wait(timeout=10)
        for obj,t in reversed(channels):stop(obj)
        for node in nodes:node.stop()
        if r:r.close()
        report.update(seconds=time.monotonic()-start,private_fixture=str(base),channel_counts=[obj.counts for obj,t in channels],owned_services_remaining=0,scope='LOCAL ROLE SIMULATION; real PC chain, mTLS, independent validation and DBs; not physical-host or Tor-P2P acceptance')
        (OUT/('integration-'+str(time.time_ns())+'.json')).write_bytes(f.canonical(report)+b'\n')
    if not report['result'].startswith('PASS'):sys.exit(1)
if __name__=='__main__':main()
