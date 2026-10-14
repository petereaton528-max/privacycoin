"""Actual paid GUI-equivalent guided helper, reconcile without another payment."""
from common import *
from runtime import Runtime
from client import retrieve
from demo import finish_store
from unittest.mock import patch
import time
def main():
    r=None;checks=[];out=ROOT/'docs/evidence/privacy-network-v01'/('demo-flow-'+str(time.time_ns())+'.json')
    try:
        r=Runtime(NATIVE/'build/privacy-network-v01'/('demo-flow-'+str(time.time_ns())));r.mine(80);client=r.client(0);plain=b'Disposable private resource demonstration\n'*16;q=client.quote(len(plain));client.encrypt(q['id'],plain);r.session.refresh();client.pay(q['id'],r.session,'CONFIRM');r.mine(10);password=token()
        with patch('demo.getpass.getpass',return_value=password):finish_store(r,client,q['id'])
        path=r.base/(q['id']+'.retrieval');raw=c.read_private(path);bundle=f.open_sealed(raw,password.encode(),'privacy-network-retrieval-v01')
        assert r.session.wallet is None;checks.append('guided finish locks Alice spending wallet')
        assert retrieve(bundle)==plain;checks.append('guided exported private bundle retrieves exact original')
        with patch('demo.getpass.getpass',side_effect=AssertionError('must not prompt again')):finish_store(r,client,q['id'])
        assert c.read_private(path)==raw;checks.append('reconcile repeats idempotent upload and preserves existing encrypted bundle')
        unpaid=client.quote(64)
        with patch('demo.getpass.getpass',side_effect=AssertionError('must not ask backup password')):finish_store(r,client,unpaid['id'])
        assert load_json(client.path(unpaid['id']))['payment']=='NOT_AUTHORIZED' and not (r.base/(unpaid['id']+'.retrieval')).exists();checks.append('unpaid reconcile never authorizes a payment or exports unavailable resource')
        report=dict(result='PASS_GUIDED_FLOW',checks=checks,passed=len(checks),scope='Actual disposable PC payment, scripted getpass responses. Not human acceptance. Secret password/key/bearers not included.')
    finally:
        if r:r.close()
    out.write_bytes(f.canonical(report)+b'\n');print(report['result'],len(checks))
if __name__=='__main__':main()
