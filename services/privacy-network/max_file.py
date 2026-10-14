"""Real paid maximum-size object and durable restart boundary."""
from common import *
from runtime import Runtime
from client import retrieve
import time

if __name__=='__main__':
    start=time.perf_counter();checks=[];r=None
    name='maximum-'+str(time.time_ns())
    try:
        r=Runtime(NATIVE/'build/privacy-network-v01'/name);r.mine(80);r.session.refresh()
        client=r.client(0);plain=os.urandom(MAX_PLAIN);q=client.quote(len(plain));cipher,bundle=client.encrypt(q['id'],plain)
        client.pay(q['id'],r.session,'CONFIRM');r.mine(10)
        assert client.status(q['id'])['state']=='CONFIRMED_LOCAL';checks.append('real paid maximum-size entitlement')
        client.upload(q['id']);assert retrieve(bundle)==plain;checks.append('one MiB exact authenticated roundtrip')
        r.stop_provider(0,crash=True);r.start_provider(0)
        assert retrieve(bundle)==plain;checks.append('maximum-size ciphertext survives actual provider kill')
        used=call(client.port,'usage',client.admin);assert used['stored_bytes']==MAX_CIPHER;checks.append('maximum-size quota accounting exact')
        result=dict(result='PASS_MAXIMUM',passed=len(checks),checks=checks,seconds=time.perf_counter()-start,plain_bytes=len(plain),cipher_bytes=len(cipher),sha256=digest(plain),private_fixture=str(r.base))
    finally:
        if r:r.close()
    destination=ROOT/'docs/evidence/privacy-network-v01'/(name+'.json');destination.write_text(json.dumps(result,sort_keys=True)+'\n',encoding='utf-8');print('PASS_MAXIMUM',len(checks))
