"""Bounded real-Devnet acceptance. Every fixture payment explicitly uses CONFIRM."""
from common import *
from runtime import Runtime,OwnedNode
from client import Client,retrieve,restore_bundle
import concurrent.futures,sqlite3,time,shutil,statistics,math,signal

OUT=ROOT/'docs/evidence/privacy-network-v01'
def main():
    c.harden();OUT.mkdir(parents=True,exist_ok=True);out=OUT/('attempt-'+str(time.time_ns())+'.json')
    checks=[];trials=[];r=None;fork=None;start=time.monotonic();base=NATIVE/'build/privacy-network-v01'/('acceptance-'+str(time.time_ns()))
    def check(label,value=True):
        if not value:raise AssertionError(label)
        checks.append(label);print('PASS',label,flush=True)
    def rejects(label,fn):
        try:fn()
        except Exception:check(label);return
        raise AssertionError(label)
    def paid(client,qid):
        r.session.refresh();client.pay(qid,r.session,'CONFIRM');check('submission is mempool only',client.status(qid)['state']=='MEMPOOL_ONLY');r.mine(10);check('independent receiver confirms exact invoice payment',client.status(qid)['state']=='CONFIRMED_LOCAL')
    def send_to(address,amount):
        r.session.refresh();plan=r.session.dispatch(dict(command='prepare',destination=address,amount=amount,fee=188000,max_fee=500000));return r.session.dispatch(dict(command='confirm',token=plan['token'],consent='CONFIRM'))
    report={}
    try:
        r=Runtime(base);check('two real independent provider processes',len({p.pid for p in r.children.values()})==2)
        r.mine(80);check('bounded 80 real RandomX funding blocks',r.node.status()['height']==80)
        a=r.client(0);b=r.client(1);plain=os.urandom(32768)
        q=a.quote(len(plain));cipher,bundle=a.encrypt(q['id'],plain)
        rejects('no payment cannot allocate storage',lambda:a.upload(q['id']))
        rejects('missing explicit consent never authorizes',lambda:a.pay(q['id'],r.session,'NO'))
        outsider=f.address(f.full(),0);send_to(outsider,1000000);r.mine(10)
        check('real wrong recipient payment does not satisfy quote',a.status(q['id'])['state']=='QUOTED_UNPAID')
        send_to(q['recipient'],999999);r.mine(10)
        check('real insufficient payment does not satisfy quote',a.status(q['id'])['state']=='QUOTED_UNPAID')
        paid(a,q['id']);rejects('duplicate payment approval rejected durably',lambda:a.pay(q['id'],r.session,'CONFIRM'))
        rejects('malformed ciphertext framing rejected',lambda:call(a.port,'upload',q['owner'],quote=q['id'],ciphertext=encode(b'bad')))
        rejects('ciphertext beyond quoted quota rejected',lambda:call(a.port,'upload',q['owner'],quote=q['id'],ciphertext=encode(cipher+b'x')))
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:a.upload(q['id']),range(8)))
        check('eight concurrent retries consume exactly one object',sum(not x['idempotent'] for x in results)==1)
        rejects('different ciphertext cannot reuse entitlement',lambda:call(a.port,'upload',q['owner'],quote=q['id'],ciphertext=encode(cipher[:-1]+bytes([cipher[-1]^1]))))
        rejects('cross-provider entitlement reuse rejected',lambda:call(b.port,'upload',q['owner'],quote=q['id'],ciphertext=encode(cipher)))
        rejects('unauthorized retrieval denied',lambda:call(a.port,'download',quote=q['id']))
        rejects('incorrect retrieval bearer denied',lambda:call(a.port,'download',token(),quote=q['id']))
        check('provider usage exact one ciphertext',call(a.port,'usage',a.admin)['stored_bytes']==len(cipher))
        r.session.close();check('Bob retrieves while Alice wallet closed',retrieve(bundle)==plain)
        password=token().encode();export=base/'bob.bundle';a.export(q['id'],export,password);dest=base/'bob-output';check('encrypted private bundle restores exact hash',restore_bundle(export,password,dest)['sha256']==digest(plain))
        rejects('download cannot overwrite existing file',lambda:restore_bundle(export,password,dest));check('existing output untouched',c.read_private(dest)==plain)
        rejects('wrong bundle password rejected',lambda:restore_bundle(export,b'wrong-password-long',base/'wrong-output'))
        tampered=dict(bundle,key=token());rejects('wrong file key rejects AEAD',lambda:retrieve(tampered))
        rejects('modified authenticated ciphertext rejects',lambda:crypt(cipher[:-1]+bytes([cipher[-1]^1]),bytes.fromhex(bundle['key']),aad(q['provider'],q['id']),True))
        check('fresh randomized encryption has distinct nonces',len({crypt(b'x',os.urandom(32),b'test')[4:28] for _ in range(100)})==100)
        a=Client(a.home,a.port,a.admin);check('client restart recovers same encrypted upload and entitlement',a.upload(q['id'])['idempotent'])
        r.stop_provider(0,crash=True);r.start_provider(0);check('provider SIGKILL restart retains exact object',retrieve(bundle)==plain)
        r.node.stop();check('node outage yields UNKNOWN, never settlement',a.status(q['id'])['state']=='UNKNOWN_RECONCILE');rejects('no access accepted on uncertain node observation',lambda:retrieve(bundle));r.node.start();check('node restart reconciles original settled payment',retrieve(bundle)==plain)
        # HTTP/browser/DNS-rebinding protections with actual server.
        for headers in ({'Origin':'https://malicious.invalid'},{'Host':'malicious.invalid'},{'Sec-Fetch-Site':'cross-site'}):
            conn=http.client.HTTPConnection('127.0.0.1',a.port,timeout=5);allheaders={'Content-Type':'application/json',**headers};conn.request('POST','/health',body=b'{}',headers=allheaders);response=conn.getresponse();check('HTTP trust boundary '+next(iter(headers)),response.status!=200);response.read();conn.close()
        rejects('quotation requires enrollment credential',lambda:call(a.port,'quote',quota=100))
        rejects('quote size bounds enforced',lambda:call(a.port,'quote',a.admin,quota=MAX_CIPHER+1))
        # Restore Alice only for subsequent explicitly approved test payments.
        r.session.dispatch(dict(command='open',name='DisposableAlice',password=r.config['password']))
        for provider in (0,1):
            client=r.client(provider)
            for trial in range(3):
                data=os.urandom(4096*(trial+1));t=time.perf_counter();quote=client.quote(len(data));quote_ms=(time.perf_counter()-t)*1000
                t=time.perf_counter();enc,cap=client.encrypt(quote['id'],data);encrypt_ms=(time.perf_counter()-t)*1000
                r.session.refresh();t=time.perf_counter();client.pay(quote['id'],r.session,'CONFIRM');payment_ms=(time.perf_counter()-t)*1000
                t=time.perf_counter();r.mine(10);confirmation_ms=(time.perf_counter()-t)*1000
                t=time.perf_counter();observed=client.status(quote['id']);status_ms=(time.perf_counter()-t)*1000;check('benchmark correct settlement '+str(provider)+str(trial),observed['state']=='CONFIRMED_LOCAL')
                t=time.perf_counter();reply=client.upload(quote['id']);upload_ms=(time.perf_counter()-t)*1000
                t=time.perf_counter();result=retrieve(cap);download_decrypt_ms=(time.perf_counter()-t)*1000;check('real paid roundtrip '+str(provider)+str(trial),result==data)
                trials.append(dict(provider=provider,plain_bytes=len(data),cipher_bytes=len(enc),price_atomic=quote['amount_atomic'],fee_atomic=188000,retention_seconds=quote['retention'],quote_ms=quote_ms,encryption_ms=encrypt_ms,payment_construct_submit_ms=payment_ms,explicit_ten_test_blocks_ms=confirmation_ms,receiver_observation_ms=status_ms,upload_ms=upload_ms,download_decrypt_ms=download_decrypt_ms,upload_bytes_per_second=len(enc)/(upload_ms/1000),download_bytes_per_second=len(enc)/(download_decrypt_ms/1000)))
                if provider==1:last_b=cap;last_b_plain=data
        r.stop_provider(0);check('provider B works while A stopped with separate database',retrieve(last_b)==last_b_plain);r.start_provider(0)
        # Saturation reserves unpaid quotes too; no oversubscription.
        while True:
            try:a.quote(MAX_PLAIN)
            except Exception:break
        usage=call(a.port,'usage',a.admin);check('quota reservation never exceeds capacity',usage['reserved_bytes']<=usage['capacity']);rejects('full provider refuses further allocation',lambda:a.quote(MAX_PLAIN))
        # Faults use B, whose capacity remains available.
        qf=b.quote(2048);cf,capf=b.encrypt(qf['id'],b'f'*2048);r.session.refresh();b.pay(qf['id'],r.session,'CONFIRM');r.mine(10)
        r.stop_provider(1);r.start_provider(1,fault='redemption-before-commit');rejects('actual kill before entitlement commit loses no payment safety',lambda:b.status(qf['id']));check('owned provider actually SIGKILLed',r.children[1].wait(timeout=5)==-9);r.stop_provider(1);r.start_provider(1);check('restart independently reconstructs same entitlement',b.status(qf['id'])['state']=='CONFIRMED_LOCAL')
        r.stop_provider(1);r.start_provider(1,fault='upload-before-commit');rejects('actual kill during upload returns uncertainty',lambda:b.upload(qf['id']));r.children[1].wait(timeout=5);r.stop_provider(1);r.start_provider(1,fault='upload-after-commit');check('uncommitted upload did not consume quota',b.status(qf['id'])['stored_bytes']==0)
        rejects('lost response after committed upload is ambiguous',lambda:b.upload(qf['id']));r.children[1].wait(timeout=5);r.stop_provider(1);r.start_provider(1);check('same ciphertext retry reconciles committed upload once',b.upload(qf['id'])['idempotent']);check('post-crash ciphertext exact',retrieve(capf)==b'f'*2048)
        # Corrupt local B object deliberately in isolated owned DB, then detect it.
        r.stop_provider(1)
        with sqlite3.connect(base/'provider-1/state.sqlite') as db:db.execute('UPDATE quotes SET blob=? WHERE id=?',(b'PN01'+b'\0'*(len(cf)-4),qf['id']))
        r.start_provider(1);rejects('corrupted stored object rejected',lambda:retrieve(capf))
        # Real greater-work reorg after a confirmed B invoice. Clone BEFORE its payment.
        r.node.stop();shutil.copytree(base/'node',base/'fork');r.node.start();qr=b.quote(1024);cr,capr=b.encrypt(qr['id'],b'r'*1024);paid(b,qr['id']);b.upload(qr['id'])
        fork=OwnedNode(base,'fork');fork.start();stamp=int(time.time())-120*500+fork.status()['height']*120
        for _ in range(11):stamp+=120;fork.mine(r.address,stamp)
        check('fork has greater real validated work',int(fork.status()['work'])>int(r.node.status()['work']))
        r.node.stop();r.node.start(peer=fork);end=time.monotonic()+30
        while r.node.status()['tip']!=fork.status()['tip'] and time.monotonic()<end:time.sleep(.05)
        check('real reorg invalidates paid entitlement',b.status(qr['id'])['state']=='REVOKED_RECONCILE');rejects('reorganized payment cannot retrieve resource',lambda:retrieve(capr))
        report['result']='PASS_REAL_PC_ACCEPTANCE'
    except Exception as error:
        report.update(result='INCOMPLETE_WITH_BLOCKERS',failure_type=type(error).__name__,failure_label=str(error) if isinstance(error,AssertionError) else 'Details withheld; inspect owned fixture privately')
        print('FAIL',report['failure_type'],report['failure_label'],flush=True)
    finally:
        resources=[]
        if r:
            for i,p in r.children.items():
                try:
                    values={line.split(':')[0]:line.split(':')[1].strip() for line in Path(f'/proc/{p.pid}/status').read_text().splitlines() if ':' in line}
                    resources.append(dict(provider=i,rss_kib=int(values['VmRSS'].split()[0]),database_bytes=(base/f'provider-{i}/state.sqlite').stat().st_size))
                except (OSError,KeyError):pass
        if fork:fork.stop()
        if r:r.close()
        report.update(checks=checks,passed=len(checks),seconds=time.monotonic()-start,trials=trials,resource_samples=resources,private_fixture=str(base),scope='Actual pinned PC node/private transactions and independent HTTP provider processes. Scripted test CONFIRM consent, not human acceptance. Deterministic fault locations, fresh keys. No original user data. No live Tor or public network.')
        raw=f.canonical(report)
        # Never publish fixture secrets/capabilities. Public report is an explicit whitelist.
        if r:
            hidden=[r.config['password'].encode()]
            for i in (0,1):
                if (base/f'provider-{i}/control').exists():hidden+=list(x.encode() for x in load_json(base/f'provider-{i}/control').values())
            assert all(secret not in raw for secret in hidden)
        out.write_bytes(raw+b'\n');print('Evidence:',out.name,report['result'],len(checks))
    if report['result']!='PASS_REAL_PC_ACCEPTANCE':sys.exit(1)
if __name__=='__main__':main()
