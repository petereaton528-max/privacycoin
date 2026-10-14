"""Guided flow and qualified error presentation; actual disposable paid object."""
from common import *
from runtime import Runtime
from client import restore_bundle
from demo import finish_store,explain_status
from unittest.mock import patch
import io,contextlib,time
if __name__=='__main__':
    r=None;checks=[];out=ROOT/'docs/evidence/privacy-network-repair'/('ui-'+str(time.time_ns())+'.json')
    try:
        r=Runtime(NATIVE/'build/privacy-network-repair'/('ui-'+str(time.time_ns())));r.mine(80);client=r.client(0);plain=os.urandom(117);q=client.quote(len(plain));client.encrypt(q['id'],plain);r.session.refresh();client.pay(q['id'],r.session,'CONFIRM');r.mine(10);password=token()
        with contextlib.redirect_stdout(io.StringIO()),patch('demo.getpass.getpass',return_value=password):finish_store(r,client,q['id'])
        assert r.session.wallet is None;checks.append('guided paid store locks Alice after export')
        bundle=r.base/(q['id']+'.retrieval');raw=c.read_private(bundle);restored=restore_bundle(bundle,password.encode(),r.base/'bob-output');assert restored['sha256']==digest(plain);checks.append('guided encrypted export restores exact Bob content')
        with contextlib.redirect_stdout(io.StringIO()),patch('demo.getpass.getpass',side_effect=AssertionError('must preserve existing bundle')):finish_store(r,client,q['id'])
        assert c.read_private(bundle)==raw;checks.append('guided repeated reconcile preserves bundle and one allocation')
        for state,expected in [(dict(state='EXPIRED',payment_state='CONFIRMED_LOCAL',recovery='PAID_NO_ENTITLEMENT'),'PAYMENT CONFIRMED BUT NO ENTITLEMENT'),(dict(state='EXPIRED',payment_state='QUOTED_UNPAID',expiration_reason='QUOTATION'),'does not prove payment failed'),(dict(state='UNKNOWN_RECONCILE',payment_state='UNKNOWN'),'UNKNOWN')]:
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream):explain_status(state)
            assert expected in stream.getvalue();checks.append('qualified guided status '+state['payment_state'])
        report=dict(result='PASS_GUIDED_REPAIR',passed=len(checks),checks=checks,scope='Real disposable payment/encrypted recovery plus isolated status rendering cases. Scripted passwords, not human acceptance.')
    finally:
        if r:r.close()
    out.write_bytes(f.canonical(report)+b'\n');print(report['result'],len(checks))
