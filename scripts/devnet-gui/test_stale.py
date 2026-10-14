"""Focused stale-history qualification; real cloned anchor, synthetic prior journal entry."""
from pathlib import Path
import json, os, secrets, shutil, tempfile
from backend import Session,c,f,w,native,NATIVE,SOURCE
def main():
    out=SOURCE/'docs/evidence/devnet-gui-v1/stale-history.json';assert not out.exists()
    h=native('stale_gui_node','tests/phase4/gates.py');fixture=NATIVE/'build/phase6a-local'
    with tempfile.TemporaryDirectory(prefix='privacycoin-gui-stale-') as temp:
        base=Path(temp);os.chmod(base,0o700);home=base/'wallets';home.mkdir(mode=0o700)
        shutil.copytree(fixture/'node',base/'node');node=h.Node(base,'node');node.start()
        password=c.read_private(fixture/'fixture.password');wallet=c.load(fixture/'A.wallet',password);c.save(home/'A.wallet',wallet,password)
        s=Session(home,node.rpc)
        try:
            s.dispatch(dict(command='open',name='A',password=password.decode()));s.refresh()
            # Synthetic journal entry deliberately uses a known chain ID. This
            # tests stale status qualification, NOT actual outgoing provenance.
            s.journal['attempts'].append(dict(token=secrets.token_hex(32),status='CONFIRMED',transaction_id=w.snapshot(node.rpc)['chain'][0]['id'],destination=f.address(wallet,0),amount=1,fee=1,created=1));s.persist()
            s.previous['work']+=1;result=s.refresh()
            assert result['balance']['balance'] is None and not result['balance']['signing_available']
            assert result['outgoing'][0]['status']=='UNKNOWN' and result['unknown_attempts']==1
            assert all(x['status']=='UNVERIFIED' and x['spent'] is None for x in result['history'])
            assert result['node']['sync']=='STALE_OR_UNVERIFIED_ANCHOR'
            assert s.journal['attempts'][0]['status']=='CONFIRMED'
            report=dict(result='PASS_FOCUSED_STALE_QUALIFICATION',checks=['stale balance null; signing disabled','stale outgoing status UNKNOWN','stale owned-output/spent statuses UNVERIFIED/null','node sync explicitly stale','durable historical journal retained'],scope='Real cloned disposable anchor; synthetic prior outgoing journal entry tests qualification only. Does not claim a new real private payment.')
            out.write_bytes(json.dumps(report,indent=2).encode()+b'\n');print('PASS focused stale history qualification')
        finally:s.close();node.stop(crash=True)
if __name__=='__main__':main()
