"""Expiry protocol tests: real PC, new private fixtures, bounded actual crashes."""
from common import *
from runtime import Runtime
from client import Client,retrieve
from provider import Provider
from launcher_host import child_parent_guard
from unittest.mock import patch
import subprocess,time,sqlite3,types,shutil
OUT=ROOT/'docs/evidence/privacy-network-repair'

def main():
    start=time.monotonic();checks=[];r=None;children=[];ports={};base=NATIVE/'build/privacy-network-repair'/('tests-'+str(time.time_ns()));out=OUT/('tests-'+str(time.time_ns())+'.json');report={}
    def check(label,condition=True):assert condition,label;checks.append(label);print('PASS',label,flush=True)
    def rejects(label,fn):
        try:fn()
        except Exception:check(label);return
        raise AssertionError(label)
    def start_provider(name,ttl=3,wait=30,fault=None,home=None):
        home=home or base/name
        if home not in ports:ports[home]=r.h.g.port()
        port=ports[home];parent=os.getpid()
        cmd=[sys.executable,str(Path(__file__).with_name('provider.py')),'--home',str(home),'--node',str(r.node.rpc),'--port',str(port),'--quote-ttl',str(ttl),'--payment-wait',str(wait)]
        if fault:cmd+=['--fault',fault]
        p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent));children.append(p)
        end=time.monotonic()+20
        while time.monotonic()<end:
            if p.poll() is not None:
                if fault=='migration-before-commit':return p,None
                raise AssertionError('owned short provider startup')
            try:call(port,'health');return p,Client(base/(name+'-client'),port,load_json(home/'control')['admin'])
            except (OSError,ValueError):time.sleep(.025)
        raise AssertionError('owned provider readiness timeout')
    def stop(p):
        if p.poll() is None:p.terminate();p.wait(timeout=10)
    def wait_until(t):time.sleep(max(0,t-time.time()+.08))
    def raw_payment(recipient,amount=1000000):
        r.session.refresh();plan=r.session.dispatch(dict(command='prepare',destination=recipient,amount=amount,fee=188000,max_fee=500000));return r.session.dispatch(dict(command='confirm',token=plan['token'],consent='CONFIRM'))
    try:
        r=Runtime(base);r.mine(80)
        p,a=start_provider('timely');q=a.quote(117);cipher,bundle=a.encrypt(q['id'],b'x'*117);r.session.refresh();a.pay(q['id'],r.session,'CONFIRM');s=a.status(q['id'])
        check('real mempool observation is not an entitlement',s['state']=='MEMPOOL_ONLY' and s['accepted_at'] is None)
        check('provider persists timely exact transaction and independent wall time',s['first_seen_at']<q['expires'] and s['payment_transaction'] is not None)
        first=s['first_seen_at'];deadline=s['payment_deadline'];stop(p);wait_until(q['expires'])
        r.session.close();r.session.dispatch(dict(command='open',name='DisposableAlice',password=r.config['password']))
        p,a=start_provider('timely');r.mine(10);s=a.status(q['id'])
        check('wallet/provider restart and late confirmation preserve valid entitlement',s['state']=='CONFIRMED_LOCAL' and s['quote_state']=='EXPIRED' and s['first_seen_at']==first)
        check('confirmation and retention deadlines are distinct',s['payment_deadline']==deadline and s['entitlement_expires_at']==s['accepted_at']+3600)
        a.upload(q['id']);check('real encrypted upload retrieval after quote expiry exact hash',retrieve(bundle)==b'x'*117)
        accepted=s['accepted_at']
        for _ in range(3):assert a.status(q['id'])['accepted_at']==accepted and a.upload(q['id'])['idempotent']
        check('duplicate reconciliation never extends retention or reallocates object')
        check('one ciphertext quota counted once after reconciliation',call(a.port,'usage',a.admin)['stored_bytes']==len(cipher))
        rejects('original intent cannot be authorized again after wallet restart',lambda:a.pay(q['id'],r.session,'CONFIRM'));stop(p)

        p,a=start_provider('unpaid');q=a.quote(64);a.encrypt(q['id'],b'u'*64);wait_until(q['expires']);s=a.status(q['id'])
        check('unpaid expired quote stays expired without timing witness',s['state']=='EXPIRED' and s['first_seen_at'] is None)
        check('unpaid expiry releases reservation',call(a.port,'usage',a.admin)['reserved_bytes']==0)
        rejects('client prevents payment approval after quote expiry',lambda:a.pay(q['id'],r.session,'CONFIRM'))
        raw_payment(q['recipient']);r.mine(10);s=a.status(q['id'])
        check('real late payment is reported paid without entitlement',s['state']=='EXPIRED' and s['payment_state']=='CONFIRMED_LOCAL' and s['recovery']=='PAID_NO_ENTITLEMENT')
        rejects('late confirmed payment does not revive expired upload',lambda:a.upload(q['id']));stop(p)

        p,a=start_provider('unobserved');q=a.quote(64);a.encrypt(q['id'],b'n'*64);raw_payment(q['recipient']);wait_until(q['expires']);r.mine(10);s=a.status(q['id'])
        check('submitted before expiry but never independently observed has unproven timing',s['state']=='EXPIRED' and s['first_seen_at'] is None and s['recovery']=='PAID_NO_ENTITLEMENT');stop(p)

        p,a=start_provider('window',wait=1);q=a.quote(64);a.encrypt(q['id'],b'w'*64);r.session.refresh();a.pay(q['id'],r.session,'CONFIRM');s=a.status(q['id']);check('short payment-window has timely witness',s['first_seen_at'] is not None)
        wait_until(q['payment_deadline']);r.mine(10);s=a.status(q['id'])
        check('payment confirmation deadline remains bounded',s['state']=='EXPIRED' and s['expiration_reason']=='PAYMENT_CONFIRMATION_WINDOW' and s['recovery']=='PAID_NO_ENTITLEMENT')
        check('expired payment-window releases quota',call(a.port,'usage',a.admin)['reserved_bytes']==0);stop(p)

        p,a=start_provider('wrong');q=a.quote(64);raw_payment(r.address);raw_payment(q['recipient'],999999);s=a.status(q['id']);check('wrong recipient and insufficient amount cannot establish timely admission',s['first_seen_at'] is None)
        wait_until(q['expires']);r.mine(10);s=a.status(q['id']);check('expired wrong or insufficient payment never grants resources',s['state']=='EXPIRED' and s['accepted_at'] is None);stop(p)

        for fault,eligible in [('witness-before-commit',False),('witness-after-commit',True)]:
            p,a=start_provider(fault,fault=fault);q=a.quote(64);cipher,bundle=a.encrypt(q['id'],b'c'*64);r.session.refresh();a.pay(q['id'],r.session,'CONFIRM');p.wait(timeout=10)
            check('actual SIGKILL '+fault,p.returncode==-9)
            with sqlite3.connect(base/fault/'state.sqlite') as db:
                saved=db.execute('SELECT first_seen,work,tip FROM quotes WHERE id=?',(q['id'],)).fetchone()
                check('witness and chain high-water observation commit together '+fault,(saved[0] is not None)==eligible and (saved[1] is not None)==eligible and (saved[2] is not None)==eligible)
            wait_until(q['expires']);p,a=start_provider(fault);r.mine(10);s=a.status(q['id'])
            check('durable witness governs post-crash admission '+fault,(s['state']=='CONFIRMED_LOCAL')==eligible and (s['first_seen_at'] is not None)==eligible)
            if eligible:a.upload(q['id']);check('post-witness-crash paid object retrieves exactly',retrieve(bundle)==b'c'*64)
            else:rejects('lost uncommitted witness cannot fabricate admission',lambda:a.upload(q['id']))
            stop(p)

        p,a=start_provider('acceptance',fault='redemption-before-commit');q=a.quote(64);a.encrypt(q['id'],b'a'*64);r.session.refresh();a.pay(q['id'],r.session,'CONFIRM');wait_until(q['expires']);r.mine(10)
        rejects('actual late settlement before entitlement commit has ambiguous reply',lambda:a.status(q['id']));p.wait(timeout=10);check('late settlement crash actually SIGKILLs owned provider',p.returncode==-9)
        p,a=start_provider('acceptance');s=a.status(q['id']);check('durable witness recovers settlement after crash without second payment',s['state']=='CONFIRMED_LOCAL');a.upload(q['id']);stop(p)

        # Real accelerated block times remain unrelated to wall-clock admission.
        a=r.client(0);q=a.quote(64);a.encrypt(q['id'],b't'*64);r.session.refresh();a.pay(q['id'],r.session,'CONFIRM');r.mine(10);s=a.status(q['id'])
        check('accelerated test timestamps do not determine invoice expiry',s['state']=='CONFIRMED_LOCAL' and s['first_seen_at']<q['expires'])

        p,a=start_provider('review-expiry');q=a.quote(64);r.session.refresh();original=r.session.dispatch;before=len(r.session.journal['attempts'])
        def delayed_prepare(request):
            result=original(request)
            if request['command']=='prepare':wait_until(q['expires'])
            return result
        with patch.object(r.session,'dispatch',side_effect=delayed_prepare):rejects('quote expiring during real prepare cannot authorize',lambda:a.pay(q['id'],r.session,'CONFIRM'))
        check('expired prepare creates no journal attempt or client authorization',len(r.session.journal['attempts'])==before and load_json(a.path(q['id']))['payment']=='NOT_AUTHORIZED');stop(p)

        # Build an actual V1 fixture from frozen public source, not original user DB.
        old=types.ModuleType('frozen_v01_provider');source=subprocess.check_output(['git',f'--git-dir={ROOT/".phase0-git"}',f'--work-tree={ROOT}','show','24d223e:services/privacy-network/provider.py']);exec(compile(source,'frozen_v01_provider','exec'),old.__dict__)
        home=base/'legacy';v1=old.Provider(home,r.node.rpc,quote_ttl=3);control=load_json(home/'control');q=v1.execute('quote',dict(quota=108),control['admin']);raw_payment(q['recipient']);initial=v1.execute('status',dict(quote=q['id']),q['owner']);assert initial['state']=='MEMPOOL_ONLY';wait_until(q['expires']);r.mine(10);v1.execute('status',dict(quote=q['id']),q['owner']);v1.close()
        p,_=start_provider('legacy',home=home,wait=3600,fault='migration-before-commit');p.wait(timeout=10)
        with sqlite3.connect(home/'state.sqlite') as db:check('SIGKILL during schema migration rolls back V1 atomically',db.execute('SELECT version FROM config').fetchone()[0]==1 and len(db.execute('PRAGMA table_info(quotes)').fetchall())==16)
        p,a=start_provider('legacy',home=home,wait=3600);s=call(a.port,'status',q['owner'],quote=q['id'])
        check('legacy expired paid row migrates without invented timing or entitlement',s['state']=='EXPIRED' and s['payment_state']=='CONFIRMED_LOCAL' and s['timing_evidence']=='LEGACY_UNPROVEN' and s['recovery']=='PAID_NO_ENTITLEMENT')
        check('legacy amount and payment wallet retained after migration',s['payment_transaction'] is not None and s['accepted_at'] is None);stop(p)

        home=base/'legacy-valid';v1=old.Provider(home,r.node.rpc);q=v1.execute('quote',dict(quota=108),v1.control['admin']);raw_payment(q['recipient']);r.mine(10);assert v1.execute('status',dict(quote=q['id']),q['owner'])['state']=='CONFIRMED_LOCAL';raw=b'PN01'+os.urandom(104);v1.execute('upload',dict(quote=q['id'],ciphertext=encode(raw)),q['owner']);v1.close()
        p,a=start_provider('legacy-valid',ttl=120,home=home,wait=3600);s=call(a.port,'status',q['owner'],quote=q['id']);reply=call(a.port,'download',q['retriever'],quote=q['id'])
        check('existing accepted V1 object and entitlement survive supported migration',s['state']=='CONFIRMED_LOCAL' and decode(reply['ciphertext'])==raw);stop(p)
        report['result']='PASS_REPAIR_BOUNDARIES'
    except Exception as error:
        report.update(result='INCOMPLETE_WITH_BLOCKERS',failure_type=type(error).__name__,failure_label=str(error) if isinstance(error,AssertionError) else 'Private fixture inspection needed');print(report,flush=True)
    finally:
        for child in children:stop(child)
        if r:r.close()
        report.update(passed=len(checks),checks=checks,seconds=time.monotonic()-start,scope='Actual private PC transactions except explicit frozen-code migration fixtures, which also use real payment. Wall-clock waits bounded. No original manual store mutation. No replacement original payment.',private_fixture=str(base));out.write_bytes(f.canonical(report)+b'\n');print(report['result'],len(checks),out.name)
    if report['result']!='PASS_REPAIR_BOUNDARIES':sys.exit(1)
if __name__=='__main__':main()
