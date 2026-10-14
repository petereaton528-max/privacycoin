"""Real private Tor + mTLS resource flow with disposable PC; never public Tor."""
from test_deployment_patch import *
from runtime import Runtime
from tor_runtime import PrivateNetwork
from tor_transport import OnionTransport
from client import Client,retrieve

def main():
    c.harden();start=time.monotonic();base=private_dir(NATIVE/'build/privacycoin-n2-deployment-patch'/('integration-'+str(time.time_ns())))
    r=None;tor=None;channels=[];checks=[];report={}
    def check(label,value=True):
        if not value:raise AssertionError(label)
        checks.append(label);print('PASS',label,flush=True)
    def reject(label,fn):
        try:fn()
        except (ValueError,OSError):check(label);return
        raise AssertionError(label)
    def channel(obj):
        t=threading.Thread(target=obj.run);t.start();channels.append((obj,t));return obj
    try:
        r=Runtime(base/'devnet');r.mine(80)
        homes={who:base/('tls-'+who) for who in ('a','b')}
        for home in homes.values():n2_tls.generate(home,'resource')
        for who,peer in (('a','b'),('b','a')):
            p=homes[peer]/'public.json';n2_tls.enroll(homes[who],p,load_json(p)['sha256'],'resource')
        port=h.g.port();tor=PrivateNetwork(base/'private-tor',port)
        server=channel(nt.ResourceServer(n2_tls.channel(homes['b'],'acceptor',port,r.local_port if hasattr(r,'local_port') else r.config['ports'][0]),tor.onion_home/'hostname'))
        tor.start();proxy_port=h.g.port()
        proxy=channel(nt.ResourceProxy(n2_tls.channel(homes['a'],'connector',proxy_port,80,tor.hostname,tor.socks_port)))
        control=load_json(r.base/'provider-0/control');transport=OnionTransport(tor.hostname,control['id'],proxy_port,timeout=5)
        until=time.monotonic()+90;attempts=0
        while True:
            try:transport(80,'health');break
            except (ValueError,OSError):
                attempts+=1
                if time.monotonic()>=until:raise AssertionError('Tor/TLS resource readiness')
                time.sleep(.2)
        transport.timeout=40;check('actual Tor plus pinned mutual TLS provider identity')
        transport._isolation=os.urandom(32);check('existing Tor circuit-isolation retry format preserved',transport(80,'health')['provider']==control['id'])
        client=Client(base/'alice-client',80,control['admin'],transport);plain=os.urandom(2048);q=client.quote(len(plain));cipher,bundle=client.encrypt(q['id'],plain)
        reject('no payment cannot allocate storage over Tor TLS',lambda:client.upload(q['id']))
        r.session.refresh();client.pay(q['id'],r.session,'CONFIRM');check('provider pending observation is not settlement',client.status(q['id'])['state']=='MEMPOOL_ONLY')
        reject('duplicate payment approval rejected',lambda:client.pay(q['id'],r.session,'CONFIRM'))
        r.mine(10);check('real PC payment independently confirmed by provider',client.status(q['id'])['state']=='CONFIRMED_LOCAL')
        client.upload(q['id']);check('exact duplicate upload idempotent',client.upload(q['id'])['idempotent'])
        r.session.close();check('Bob retrieves and decrypts through Tor TLS with Alice locked',retrieve(bundle,transport)==plain)
        reject('resource administration not exposed',lambda:transport(80,'cleanup',control['admin']))
        # Existing local admin remains local and intact.
        check('local-only usage remains accessible to operator',call(r.config['ports'][0],'usage',control['admin'])['stored_bytes']==len(cipher))
        r.stop_provider(0);r.start_provider(0);check('provider restart preserves paid ciphertext',retrieve(bundle,transport)==plain)
        bad=dict(bundle,key='0'*64);reject('wrong file key rejected by authenticated decryption',lambda:retrieve(bad,transport))
        tor.close();tor=None;reject('Tor outage has no direct or TLS downgrade fallback',lambda:transport(80,'health'))
        report.update(result='PASS_PRIVATE_TOR_MTLS_REAL_PC_STORAGE',hash=hashlib.sha256(plain).hexdigest(),cipher_bytes=len(cipher),price_atomic=q['amount_atomic'],readiness_failed_attempts=attempts)
    except Exception as e:
        safe=str(e) if isinstance(e,AssertionError) or str(e).startswith('PRIVATE_TOR_') or type(e).__name__=='TransportError' else 'Private details withheld'
        report.update(result='INCOMPLETE_WITH_BLOCKERS',failure_type=type(e).__name__,failure_label=safe)
    finally:
        for obj,t in reversed(channels):obj.close();t.join(timeout=41)
        if tor:tor.close()
        if r:r.close()
        report.update(checks=checks,passed=len(checks),seconds=time.monotonic()-start,private_fixture=str(base),public_tor=False,cross_host=False,owned_services_remaining=0)
        (OUT/('integration-'+str(time.time_ns())+'.json')).write_bytes(f.canonical(report)+b'\n');print(report['result'])
    if not report['result'].startswith('PASS'):sys.exit(1)
if __name__=='__main__':main()
