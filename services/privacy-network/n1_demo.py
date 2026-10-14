"""Guided N1 private-network demonstration, with no public onion activation."""
from common import *
from n1_runtime import N1Runtime
from client import restore_bundle
from tor_transport import TransportError
from tor_runtime import TOR
from demo import explain_status
import argparse,getpass,time

def finish(r,qid):
    state=r.client.status(qid);explain_status(state)
    if state['state']!='CONFIRMED_LOCAL':print('No entitlement now. Preserve intent; do not repay.');return
    result=r.client.upload(qid);print('Stored ciphertext bytes:',result['bytes'])
    target=r.home/(qid+'.retrieval')
    if not target.exists():
        password=getpass.getpass('New encrypted Bob bundle password (12+ bytes): ').encode()
        if password!=getpass.getpass('Confirm bundle password: ').encode():raise ValueError('password confirmation')
        r.client.export(qid,target,password)
    print('Private encrypted Bob bundle:',target,'Keep its password separate.')
    r.local.session.close();print('Alice wallet locked. Use option 2 to retrieve, or n1_retrieve.py in another terminal.')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--home',type=Path,default=Path.home()/'.local/share/privacycoin-network-n1');a=parser.parse_args();r=None
    # Never let a typo reopen either original user store.
    for protected in ('privacycoin-network-v01','privacycoin-devnet-gui'):
        original=Path.home()/'.local/share'/protected
        if a.home.resolve()==original or a.home.resolve().is_relative_to(original):raise ValueError('original store prohibited')
    print('PRIVACY NETWORK N1 - DISPOSABLE DEVNET ONLY')
    print('N1 INCOMPLETE_WITH_BLOCKERS: intermittent Tor failures remain. Do not use real assets or assume paid service availability.')
    if not TOR.is_file():
        print('Tor runtime missing. Follow docs/privacy-network/n1/TOR_TRANSPORT.md to verify/extract the signed Ubuntu package. No service started.')
        raise SystemExit(1)
    print('Real Tor, isolated loopback testing network. NOT public Tor anonymity or cross-host acceptance.')
    print('CONNECTING: isolated test-network startup may take up to six minutes. No mining/payment is automatic.')
    try:
        r=N1Runtime(a.home);print('CONNECTED to pinned Provider 1 through private Tor onion service.')
        print('Original V0.1 wallet, chain and intent stores are untouched. N1 private store:',r.home)
        while True:
            choice=input('\n1 Store / 2 Bob retrieve / 3 Mine / 4 Status / 5 Provider restart / 6 Reconcile original N1 intent / 0 Exit: ').strip()
            try:
                if choice=='0':break
                if choice=='3':
                    count=int(input('Blocks (1-100; fresh funding needs 80): '))
                    if input('Type MINE DEVNET to authorize bounded CPU mining: ')=='MINE DEVNET':r.local.mine(count);print('Height',r.local.node.status()['height'])
                elif choice=='4':print(r.transport.state,r.transport(80,'health'),'Height',r.local.node.status()['height'])
                elif choice=='5':r.local.stop_provider(0);r.local.start_provider(0);print('Provider restarted; durable state preserved.')
                elif choice=='2':
                    source=Path(input('Private encrypted Bob bundle WSL path: ').strip());password=getpass.getpass('Bundle password: ').encode();dest=Path(input('NEW output under private 0700 WSL directory: ').strip())
                    result=restore_bundle(source,password,dest,r.transport);print('Recovered verified plaintext:',result)
                elif choice=='6':finish(r,identity(input('Original N1 quote ID: ').strip()))
                elif choice=='1':
                    path=Path(input('Small disposable file WSL path (/mnt/d/...): ').strip())
                    if not path.is_file() or path.is_symlink() or not 1<=path.stat().st_size<=MAX_PLAIN:raise ValueError('file bound')
                    with path.open('rb') as stream:plain=stream.read(MAX_PLAIN+1)
                    if not 1<=len(plain)<=MAX_PLAIN:raise ValueError('file bound')
                    q=r.client.quote(len(plain));r.client.encrypt(q['id'],plain)
                    print('Quote:',q['id'],'Provider 1; ciphertext quota:',q['quota'],'Retention:',q['retention'],'seconds')
                    print('Price 1,000,000 atomic PC (0.000001 PC); fee 188,000; total 1,188,000; max fee 500,000.')
                    print('Recipient:',q['recipient'],'Ten local confirmations; global freshness UNKNOWN.')
                    print('Admission deadline UTC:',time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime(q['expires'])),'Confirmation deadline UTC:',time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime(q['payment_deadline'])))
                    print('Provider must independently admit payment before quote expiry. Timeouts preserve intent; never pay twice.')
                    print('A missed admission can leave confirmed PC without service; no automatic refund exists. This N1 transport is incomplete.')
                    if input('Type CONFIRM to approve this one real disposable PC payment: ')!='CONFIRM':print('No payment authorized.');continue
                    if r.local.session.wallet is None:r.local.session.dispatch(dict(command='open',name='DisposableAlice',password=r.local.config['password']))
                    r.local.session.refresh();r.client.pay(q['id'],r.local.session,'CONFIRM');print('Submitted, NOT settled. Original intent:',r.client.path(q['id']))
                    while True:
                        state=r.client.status(q['id']);explain_status(state)
                        if state['state'] in ('CONFIRMED_LOCAL','EXPIRED'):break
                        action=input('WAIT / MINE 10 (explicit confirmation mining) / EXIT (preserve intent): ')
                        if action=='EXIT':break
                        if action=='MINE 10':r.local.mine(10)
                        elif action=='WAIT':time.sleep(1)
                    if state['state']=='CONFIRMED_LOCAL':finish(r,q['id'])
                else:print('Choose 0-6.')
            except TransportError as error:print(error.state,error.code,'Preserve intent; reconcile later. No fallback or replacement payment.')
            except Exception:print('Rejected or UNKNOWN. Check input, private paths, funds, provider/node and original intent. No automatic retry.')
    finally:
        if r:r.close()

if __name__=='__main__':
    try:main()
    except (EOFError,KeyboardInterrupt):print('Closed. Owned processes stopped; private data retained.')
    except Exception:print('Startup failed. Owned processes stopped; private data retained. See N1 setup requirements.');sys.exit(1)
