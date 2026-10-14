"""Real settled invoice whose deadline crosses during receiver verification."""
from common import *
from runtime import Runtime
from provider import Provider
from unittest.mock import patch
import argparse,sqlite3,time
def main():
    p=argparse.ArgumentParser();p.add_argument('--stage',choices=['before','after'],required=True);a=p.parse_args();out=ROOT/f'docs/evidence/privacy-network-v01/expiry-race-{a.stage}.json';assert not out.exists();r=None;provider=None
    try:
        base=NATIVE/'build/privacy-network-v01'/('expiry-race-'+a.stage+'-'+str(time.time_ns()));r=Runtime(base);r.mine(80);client=r.client(0);quote=client.quote(64);r.session.refresh();client.pay(quote['id'],r.session,'CONFIRM');r.mine(10);r.stop_provider(0)
        provider=Provider(base/'provider-0',r.node.rpc)
        with provider.db:provider.db.execute('UPDATE quotes SET expires=? WHERE id=?',(time.time()+.5,quote['id']))
        original=c.observe
        def slow(*args,**kwargs):time.sleep(.75);return original(*args,**kwargs)
        with patch.object(c,'observe',side_effect=slow):state=provider.execute('status',dict(quote=quote['id']),quote['owner'])['state']
        passed=state=='EXPIRED';out.write_bytes(f.canonical(dict(result='PASS' if passed else 'FAIL_REPRODUCED',observed_state=state,scope='Actual real PC payment; disposable persisted deadline injected 0.5s ahead, 0.75s delay wraps real receiver scan. No synthetic settlement or user state.'))+b'\n');print(a.stage,state)
        if a.stage=='after':assert passed
    finally:
        if provider:provider.close()
        if r:r.close()
if __name__=='__main__':main()
