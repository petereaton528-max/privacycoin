"""Focused actual Tk rendering checks for the final stale-history qualification."""
from pathlib import Path
import json,os
from gui import App,safe_root
from test_gui import wait

class PublicFixture:
    def call(self,command,**_):return dict(home='synthetic private store',wallets=[],network='privacycoin-devnet')
    def close(self):pass

def main():
    assert os.name=='nt';out=Path(__file__).resolve().parents[2]/'docs/evidence/devnet-gui-v1/display.json';assert not out.exists()
    root=safe_root();root.withdraw();app=App(root,PublicFixture());wait(root,app)
    try:
        balance=dict(authority='full',chain_trust='STALE_OR_ROLLBACK',spent_status='UNKNOWN',signing_available=False,minimum_confirmations=10,scan_progress=dict(records_processed=1,records_expected=1),balance=None,spendable=None)
        result=dict(balance=balance,node=dict(endpoint='127.0.0.1:48081',height=1,tip='0'*64,work=1),history=[dict(status='UNVERIFIED',amount=1,coinbase=False,spent=None,transaction_id='1'*64)],outgoing=[dict(status='UNKNOWN',amount=1,fee=1,transaction_id=None)],unknown_attempts=1)
        app.observed(result);overview=app.overview.get('1.0','end');history=app.history.get('1.0','end')
        assert 'UNKNOWN / unavailable' in overview and 'STALE_OR_ROLLBACK' in overview
        assert 'UNVERIFIED' in history and 'UNKNOWN transaction identity' in history and 'CONFIRMED' not in history
        assert app.send_button.instate(['disabled'])
        result['balance']['chain_trust']='TRUSTED_LOCAL_VALIDATING_ANCHOR';result['balance']['signing_available']=True;result['balance']['balance']=0;result['balance']['spendable']=0;result['outgoing'][0]['status']='CONFIRMED';result['unknown_attempts']=0
        app.observed(result);assert 'CHAIN_INCLUDED (local)' in app.history.get('1.0','end')
        report=dict(result='PASS_FOCUSED_TK_QUALIFICATION',checks=['null balance rendered UNKNOWN','stale history rendered UNVERIFIED/UNKNOWN','stale signing disabled','included outgoing labeled local chain inclusion, not finality'],scope='Synthetic public fixture with actual Windows Tk widgets; real node/payment cases recorded separately.')
        out.write_bytes(json.dumps(report,indent=2).encode()+b'\n');print('PASS focused Tk qualification')
    finally:app.shutdown()
if __name__=='__main__':main()
