"""Actual private Tor circuits + real PC settlement, isolated fresh fixtures.

Startup phase bound: 360s (node 60, Tor 180, onion readiness 110); each request
<=40s. No public Tor, external service, original wallet or automatic user payment.
"""
from common import *
from n1_runtime import N1Runtime
from client import Client,retrieve,restore_bundle
from tor_transport import OnionTransport,TransportError
import time,concurrent.futures,statistics,subprocess,argparse
OUT=ROOT/'docs/evidence/privacy-network-n1'
FIXTURE=NATIVE/'build/privacy-network-n1'
STARTING_HEAD='70a8f16893f9025ea1f869313ed410b5b1e95c54'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--experimental-upstream-tor',action='store_true');options=parser.parse_args()
    c.harden();OUT.mkdir(parents=True,exist_ok=True);base=FIXTURE/('test-'+str(time.time_ns()));r=None;checks=[];metrics=[];start=time.monotonic();report={};resources=[]
    def check(name,condition=True):assert condition,name;checks.append(name);print('PASS',name,flush=True)
    def rejects(name,fn):
        try:fn()
        except (ValueError,OSError):check(name);return
        raise AssertionError(name)
    def timed(name,fn):
        t=time.perf_counter();result=fn();metrics.append(dict(operation=name,ms=(time.perf_counter()-t)*1000));return result
    def wait_ready():
        # Retry only read-only health after Tor's introduction circuit backoff.
        probe=OnionTransport(r.tor.hostname,r.transport.binding['provider'],r.tor.socks_port,timeout=2)
        end=time.monotonic()+60
        while time.monotonic()<end:
            try:probe(80,'health');return
            except TransportError:time.sleep(.2)
        raise AssertionError('owned Tor/provider reconnection deadline')
    try:
        r=timed('startup_cold_private_network',lambda:N1Runtime(base,options.experimental_upstream_tor))
        check('real Tor client and onion service bootstrapped',all(b'PROGRESS=100' in n.control('GETINFO status/bootstrap-phase') for n in r.tor.nodes[-2:]))
        check('onion endpoint health pinned to independent provider',r.transport(80,'health')['provider']==r.transport.binding['provider'])
        # Inspect actual TCP endpoints owned by Tor in /proc, not proxy variables.
        endpoints=[]
        for n in r.tor.nodes:
            inodes={p.readlink().as_posix()[8:-1] for p in Path(f'/proc/{n.process.pid}/fd').iterdir() if p.is_symlink() and p.readlink().as_posix().startswith('socket:[')}
            for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                parts=line.split()
                if parts[9] in inodes:endpoints.append((parts[1],parts[2]))
        check('sampled real Tor TCP sockets have loopback-only endpoints',bool(endpoints) and all(a.startswith('0100007F:') and (b.startswith('0100007F:') or b=='00000000:0000') for a,b in endpoints))
        expected=10 if options.experimental_upstream_tor else 7
        check(str(expected)+' Tor processes are campaign owned',len(r.tor.nodes)==expected and all(n.process.poll() is None for n in r.tor.nodes))
        r.local.mine(80);check('fresh disposable real RandomX funding chain ready',r.local.node.status()['height']>=80)
        client=r.client
        plain=b'N1 disposable private Tor resource trial\n'*100
        for trial in range(3):
            # Alternating paired transport order; independent quotes/payments, same
            # file size and existing recipient/fee/confirmation policy.
            modes=['local','tor'] if trial%2==0 else ['tor','local']
            for mode in modes:
                a=client if mode=='tor' else r.local.client(0,base/'paired-local')
                q=timed(mode+'_quote',lambda:a.quote(len(plain)));cipher,bundle=timed(mode+'_encrypt',lambda:a.encrypt(q['id'],plain))
                rejects(mode+' unpaid upload rejected '+str(trial),lambda:a.upload(q['id']))
                r.local.session.refresh();timed(mode+'_payment_construct_submit_admit',lambda:a.pay(q['id'],r.local.session,'CONFIRM'))
                status=a.status(q['id']);check(mode+' mempool not settlement '+str(trial),status['state']=='MEMPOOL_ONLY' and status['accepted_at'] is None)
                rejects(mode+' duplicate approval rejected '+str(trial),lambda:a.pay(q['id'],r.local.session,'CONFIRM'))
                timed(mode+'_mine10',lambda:r.local.mine(10));status=timed(mode+'_confirm',lambda:a.status(q['id']))
                check(mode+' genuine exact PC independently confirmed '+str(trial),status['state']=='CONFIRMED_LOCAL' and status['stored_bytes']==0)
                response=timed(mode+'_upload',lambda:a.upload(q['id']));check(mode+' exact ciphertext bytes accounted '+str(trial),response['bytes']==len(cipher))
                check(mode+' identical duplicate upload is idempotent '+str(trial),a.upload(q['id'])['idempotent'])
                recovered=timed(mode+'_download_decrypt',lambda:retrieve(bundle,r.transport if mode=='tor' else None))
                check(mode+' retrieved plaintext exact SHA256 '+str(trial),digest(recovered)==digest(plain))
                if mode=='tor' and trial==0:qid=q['id'];original_bundle=bundle;original_cipher=cipher
        # Six 4144-byte allocations fit 4MiB; no extra allocation on retries.
        usage=call(r.local.config['ports'][0],'usage',client.admin)
        check('bounded durable quota exact after six independently paid objects',usage['stored_bytes']==6*(len(plain)+44))
        bad=OnionTransport(r.tor.hostname,token(),r.tor.socks_port,timeout=5)
        rejects('wrong pinned provider cannot receive bearer capability',lambda:bad(80,'status',token(),quote=qid))
        check('wrong provider failure state explicit',bad.state=='FAILED')
        wrong=dict(original_bundle,retriever=token());rejects('wrong retrieval capability rejected over Tor',lambda:retrieve(wrong,r.transport))
        wrong=dict(original_bundle,key=token());rejects('wrong encryption key fails local AEAD',lambda:retrieve(wrong,r.transport))
        wrong=dict(original_bundle,cipher_hash=token());rejects('ciphertext substitution rejected',lambda:retrieve(wrong,r.transport))
        rejects('Tor bundle cannot silently downgrade to direct transport',lambda:retrieve(original_bundle))
        rejects('direct bundle cannot be upgraded without bound authority',lambda:retrieve(dict(original_bundle,version=1),r.transport))
        rejects('wrong transport cannot reuse payment intent',lambda:Client(client.home,80,client.admin,bad).pay(qid,r.local.session,'CONFIRM'))
        password=token().encode();bundlefile=base/'bob.bundle';timed('encrypted_bundle_export',lambda:client.export(qid,bundlefile,password))
        rejects('wrong bundle password rejected',lambda:restore_bundle(bundlefile,b'wrong-password',base/'wrong',r.transport))
        r.local.session.close();check('Alice signer locked before Bob recovery',r.local.session.wallet is None)
        timed('bob_recover',lambda:restore_bundle(bundlefile,password,base/'bob-output',r.transport));check('Bob recovers with no spending authority',digest(c.read_private(base/'bob-output'))==digest(plain))
        # New independent client transports; server remains single writer.
        def bob(_):return retrieve(original_bundle,OnionTransport(r.tor.hostname,original_bundle['provider'],r.tor.socks_port))
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(bob,range(2)))
        check('concurrent Bob retrieval preserves object and quota',all(x==plain for x in results))
        r.stop_bridge(crash=True);t=OnionTransport(r.tor.hostname,original_bundle['provider'],r.tor.socks_port,timeout=2)
        rejects('bridge crash fails closed without direct fallback',lambda:t(80,'health'));r.start_bridge();timed('bridge_reconnect',wait_ready)
        check('bridge restart recovers stored object',retrieve(original_bundle,r.transport)==plain)
        r.local.stop_provider(0,crash=True);rejects('provider crash not reported as successful retrieval',lambda:retrieve(original_bundle,r.transport));r.local.start_provider(0);wait_ready()
        check('provider restart preserves settlement object and quota',retrieve(original_bundle,r.transport)==plain and call(r.local.config['ports'][0],'usage',client.admin)['stored_bytes']==usage['stored_bytes'])
        # Node loss leaves financial observation UNKNOWN, never fabricated verified.
        r.local.node.stop();status=client.status(qid);check('node outage keeps settlement UNKNOWN',status['payment_state']=='UNKNOWN')
        rejects('node outage prevents protected retrieval',lambda:retrieve(original_bundle,r.transport));r.local.node.start()
        check('node restart safely reconciles existing PC payment',client.status(qid)['state']=='CONFIRMED_LOCAL')
        tor_client=r.tor.nodes[-2];tor_client.process.kill();tor_client.process.wait(timeout=5)
        rejects('Tor process termination fails closed',lambda:r.transport(80,'health'));tor_client.start()
        timed('tor_client_reconnect',wait_ready)
        check('owned Tor restart retains onion endpoint and object',retrieve(original_bundle,r.transport)==plain)
        for name,p in [('provider',r.local.children[0]),('tor-client',r.tor.nodes[-2].process),('tor-service',r.tor.nodes[-1].process)]:
            data=Path(f'/proc/{p.pid}/status').read_text();rss=next(int(x.split()[1]) for x in data.splitlines() if x.startswith('VmRSS:'));stat=Path(f'/proc/{p.pid}/stat').read_text().split();resources.append(dict(process=name,rss_kib=rss,cpu_seconds=(int(stat[13])+int(stat[14]))/os.sysconf('SC_CLK_TCK')))
        hostname=r.tor.hostname;before=usage['stored_bytes'];owned=[n.process.pid for n in r.tor.nodes]+[r.bridge.pid]+[p.pid for p in r.local.children.values()]+[r.local.node.p.pid]
        timed('owned_shutdown',r.close);check('owned processes terminated on shutdown',all(not Path('/proc/'+str(pid)).exists() for pid in owned))
        r=timed('startup_warm_private_network',lambda:N1Runtime(base,options.experimental_upstream_tor))
        check('whole runtime restart preserves onion identity and original entitlement',r.tor.hostname==hostname and retrieve(original_bundle,r.transport)==plain)
        check('whole runtime restart retains exact storage accounting',call(r.local.config['ports'][0],'usage',r.client.admin)['stored_bytes']==before)
        report['fixture_bytes']=sum(p.stat().st_size for p in base.rglob('*') if p.is_file() and not p.is_symlink())
        report['result']='PASS_REAL_PRIVATE_TOR_AND_PC'
    except Exception as error:
        report.update(result='INCOMPLETE_WITH_BLOCKERS',failure_type=type(error).__name__,failure_label=str(error) if isinstance(error,(AssertionError,TransportError)) else 'Private fixture diagnostic required')
        print('FAIL',report['failure_type'],report['failure_label'],flush=True)
    finally:
        if r:r.close()
        report.update(starting_head=STARTING_HEAD,experimental_upstream_tor=options.experimental_upstream_tor,checks=checks,passed=len(checks),seconds=time.monotonic()-start,metrics=metrics,resources=resources,private_fixture=str(base),scope='Actual Tor 0.4.9.11 isolated loopback testing network, real PC devnet and independent provider process; not public Tor, physical-host independence or human acceptance',paid_trials=sum(1 for x in checks if 'genuine exact PC independently confirmed' in x),amount_atomic_per_service=1000000,fee_atomic=188000,plaintext_bytes=len(b'N1 disposable private Tor resource trial\n'*100),retention_seconds=3600)
        out=OUT/('integration-'+str(time.time_ns())+'.json');out.write_bytes(f.canonical(report)+b'\n');print('Evidence',out.name,report['result'],len(checks),flush=True)
    if report['result']!='PASS_REAL_PRIVATE_TOR_AND_PC':sys.exit(1)
if __name__=='__main__':main()
