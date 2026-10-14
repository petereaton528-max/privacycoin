"""Real payment observed before deadline, confirmed after: regression corpus."""
from common import *
from runtime import Runtime
import time,sqlite3,argparse
def main():
    p=argparse.ArgumentParser();p.add_argument('--stage',choices=['before','after'],required=True);a=p.parse_args()
    out=ROOT/f'docs/evidence/privacy-network-repair/late-confirmation-{a.stage}.json';assert not out.exists();r=None
    try:
        r=Runtime(NATIVE/'build/privacy-network-repair'/('reproducer-'+str(time.time_ns())));r.mine(80);r.session.refresh();client=r.client(0)
        q=client.quote(117);client.encrypt(q['id'],b'x'*117);client.pay(q['id'],r.session,'CONFIRM')
        initial=client.status(q['id']);assert initial['state']=='MEMPOOL_ONLY'
        # A shortened persisted quote deadline simulates elapsed human interaction;
        # actual node/wallet and receiver scans remain real, never synthetic payment.
        r.stop_provider(0)
        with sqlite3.connect(r.base/'provider-0/state.sqlite') as db:db.execute('UPDATE quotes SET expires=? WHERE id=?',(time.time()+.25,q['id']))
        r.start_provider(0);time.sleep(.3);r.mine(10);final=client.status(q['id'])
        passed=final['state']=='CONFIRMED_LOCAL'
        result=dict(result='PASS' if passed else 'FAIL_REPRODUCED',initial_state=initial['state'],final_state=final['state'],expected_state='CONFIRMED_LOCAL',actual_private_payment=True,scope='Fresh isolated real PC payment, independently observed in pool before quote cutoff; persisted deadline shortened only in fixture; actual confirmation after deadline. No original quote/wallet mutation or replacement payment.')
        out.write_bytes(f.canonical(result)+b'\n');print(result)
        if a.stage=='after':assert passed
    finally:
        if r:r.close()
if __name__=='__main__':main()
