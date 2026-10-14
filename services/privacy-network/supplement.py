"""Expiry, ambiguous payment, concurrency and lifecycle supplements, real PC."""
from common import *
from runtime import Runtime
from client import Client,retrieve
from provider import Provider
from launcher_host import child_parent_guard
from unittest.mock import patch
import concurrent.futures,subprocess,time,signal,sqlite3
OUT=ROOT/'docs/evidence/privacy-network-v01'
def main():
    c.harden();checks=[];r=None;extra=None;start=time.monotonic();out=OUT/('supplement-'+str(time.time_ns())+'.json');base=NATIVE/'build/privacy-network-v01'/('supplement-'+str(time.time_ns()));metrics=[]
    def check(label,value=True):assert value,label;checks.append(label);print('PASS',label,flush=True)
    def rejects(label,fn):
        try:fn()
        except Exception:check(label);return
        raise AssertionError(label)
    def start_extra(name,ttl,retention):
        home=base/name;port=r.h.g.port();parent=os.getpid();p=subprocess.Popen([sys.executable,str(Path(__file__).with_name('provider.py')),'--home',str(home),'--node',str(r.node.rpc),'--port',str(port),'--quote-ttl',str(ttl),'--retention',str(retention)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,preexec_fn=lambda:child_parent_guard(parent))
        end=time.monotonic()+40
        while time.monotonic()<end:
            if p.poll() is not None:raise ValueError('extra startup')
            try:call(port,'health');break
            except Exception:time.sleep(.05)
        else:raise ValueError('extra timeout')
        return p,Client(base/(name+'-client'),port,load_json(home/'control')['admin'])
    report={}
    try:
        r=Runtime(base);r.mine(80);a=r.client(0)
        q=a.quote(1024);enc,bundle=a.encrypt(q['id'],b'x'*1024);r.session.refresh();original=r.session.dispatch
        def lost(request):
            result=original(request)
            if request['command']=='confirm':raise OSError('test lost result')
            return result
        with patch.object(r.session,'dispatch',side_effect=lost):rejects('actual submitted payment with lost client result is ambiguous',lambda:a.pay(q['id'],r.session,'CONFIRM'))
        check('durable client records AUTHORIZED_UNKNOWN',load_json(a.path(q['id']))['payment']=='AUTHORIZED_UNKNOWN')
        a=Client(a.home,a.port,a.admin);rejects('restarted client cannot silently authorize replacement',lambda:a.pay(q['id'],r.session,'CONFIRM'));check('provider sees original actual mempool payment',a.status(q['id'])['state']=='MEMPOOL_ONLY');r.mine(10);check('provider reconciles original payment after lost response',a.status(q['id'])['state']=='CONFIRMED_LOCAL');a.upload(q['id']);check('resource obtainable without second payment',retrieve(bundle)==b'x'*1024)
        q2=a.quote(256);e2,b2=a.encrypt(q2['id'],b'y'*256);r.session.refresh()
        def contender(_):
            try:a.pay(q2['id'],r.session,'CONFIRM');return True
            except Exception:return False
        before=len(w.rpc(r.node.rpc,'pool')['transactions'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:accepted=list(pool.map(contender,range(2)))
        check('concurrent explicit approvals authorize only one actual payment',sum(accepted)==1 and len(w.rpc(r.node.rpc,'pool')['transactions'])==before+1);r.mine(10)
        rejects('path traversal identifier rejected',lambda:call(a.port,'download',q2['retriever'],quote='../../control'))
        # Malicious-invoice mutation tests are explicitly isolated, not settlement mocks.
        import client as cm
        health=call(a.port,'health')
        for field,value in [('amount_atomic',2**63),('recipient','not-PC'),('quota',MAX_CIPHER+1)]:
            bad=dict(q2);bad[field]=value
            with patch.object(cm,'call',side_effect=[health,bad]):rejects('malicious invoice '+field+' rejected before spending',lambda:a.quote(256))
        extra,short=start_extra('expiry-quote',1,60);qe=short.quote(64);short.encrypt(qe['id'],b'e'*64);time.sleep(1.1)
        check('real wall-clock quotation expires',short.status(qe['id'])['state']=='EXPIRED');rejects('expired quote never grants upload',lambda:short.upload(qe['id']));rejects('client cannot approve expired quotation',lambda:short.pay(qe['id'],r.session,'CONFIRM'));extra.terminate();extra.wait(timeout=10);extra=None
        extra,short=start_extra('expiry-content',120,3);qt=short.quote(64);et,bt=short.encrypt(qt['id'],b't'*64);r.session.refresh();short.pay(qt['id'],r.session,'CONFIRM');r.mine(10);check('short-retention payment independently confirmed',short.status(qt['id'])['state']=='CONFIRMED_LOCAL');short.upload(qt['id']);check('short-retention content initially available',retrieve(bt)==b't'*64);time.sleep(3.1);rejects('expired content retrieval rejected',lambda:retrieve(bt));usage=call(short.port,'cleanup',short.admin);check('expired ciphertext logically removed and reservation released',usage['stored_bytes']==0 and usage['reserved_bytes']==0);extra.terminate();extra.wait(timeout=10);extra=None
        for trial in range(3):
            raw=os.urandom(65536);t0=time.perf_counter();quote=a.quote(len(raw));t=time.perf_counter();cipher,cap=a.encrypt(quote['id'],raw);enc_ms=(time.perf_counter()-t)*1000;r.session.refresh();a.pay(quote['id'],r.session,'CONFIRM');t=time.perf_counter();r.mine(10);blocks_ms=(time.perf_counter()-t)*1000;check('timed paid entitlement '+str(trial),a.status(quote['id'])['state']=='CONFIRMED_LOCAL');entitlement_ms=(time.perf_counter()-t0)*1000;a.upload(quote['id']);t=time.perf_counter();plain=crypt(cipher,bytes.fromhex(cap['key']),aad(quote['provider'],quote['id']),True);decrypt_ms=(time.perf_counter()-t)*1000;check('timed exact plaintext '+str(trial),plain==raw);metrics.append(dict(plain_bytes=len(raw),cipher_bytes=len(cipher),price_atomic=1000000,quote_to_entitlement_ms=entitlement_ms,encryption_ms=enc_ms,decryption_only_ms=decrypt_ms,explicit_ten_test_blocks_ms=blocks_ms))
        # Constructor filesystem negative paths, no user files or content disclosure.
        unsafe=private_dir(base/'unsafe');(unsafe/'state.sqlite').symlink_to(base/'provider-0/state.sqlite');rejects('symlink database rejected',lambda:Provider(unsafe,r.node.rpc))
        with sqlite3.connect(base/'provider-1/state.sqlite') as db:db.execute('UPDATE config SET version=999')
        r.stop_provider(1);rejects('unknown future provider version fails closed',lambda:r.start_provider(1))
        report['result']='PASS_SUPPLEMENT'
    except Exception as error:report.update(result='INCOMPLETE_WITH_BLOCKERS',failure_type=type(error).__name__,failure_label=str(error) if isinstance(error,AssertionError) else 'Private fixture inspection required')
    finally:
        if extra and extra.poll() is None:extra.terminate();extra.wait(timeout=10)
        if r:r.close()
        report.update(checks=checks,passed=len(checks),seconds=time.monotonic()-start,trials=metrics,private_fixture=str(base),scope='Actual PC transactions except explicitly labeled invoice mutation fixtures. Real 1s quote / 3s retention deadlines. No original wallet state or secrets in report. New isolated encrypted fixture state retained.')
        out.write_bytes(f.canonical(report)+b'\n');print(report['result'],len(checks),out.name)
    if report['result']!='PASS_SUPPLEMENT':sys.exit(1)
if __name__=='__main__':main()
