"""Opt-in remote Tor client, using an existing trusted local disposable node.

Does NOT start Tor, publish an onion service, connect nodes, mine or discover peers.
Configuration and quote enrollment capability are private files, not CLI secrets.
"""
from common import *
from client import Client,restore_bundle
from tor_transport import OnionTransport,TransportError
from demo import explain_status
import argparse,getpass

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--profile',type=Path,required=True);a=p.parse_args()
    config=load_json(a.profile);f.fields(config,'version devnet_only home node_rpc socks_port onion provider quote_admin')
    if type(config['version']) is not int or config['version']!=1 or config['devnet_only'] is not True:raise ValueError('disposable profile required')
    home=Path(config['home']);original=Path.home()/'.local/share'
    for name in ('privacycoin-network-v01','privacycoin-devnet-gui'):
        if home.resolve()==original/name or home.resolve().is_relative_to(original/name):raise ValueError('original store prohibited')
    private_dir(home);transport=OnionTransport(config['onion'],config['provider'],config['socks_port']);client=Client(home/'intents',80,identity(config['quote_admin']),transport)
    session=Session(home/'wallets',config['node_rpc'])
    print('DISPOSABLE DEVNET ONLY. N1 INCOMPLETE_WITH_BLOCKERS; cross-host acceptance PENDING. Remote access does not imply independent chain validation or anonymity.')
    print('CONNECTED' if transport(80,'health') else 'FAILED')
    try:
        while True:
            choice=input('1 Create/open N1Disposable wallet / 2 Store / 3 Reconcile+upload / 4 Bob retrieve / 0 Exit: ').strip()
            try:
                if choice=='0':break
                if choice=='1':
                    password=getpass.getpass('Disposable wallet password: ')
                    if not password:raise ValueError('password')
                    command='open' if (session.home/'N1Disposable.wallet').exists() else 'create'
                    if command=='create' and password!=getpass.getpass('Confirm password: '):raise ValueError('password')
                    opened=session.dispatch(dict(command=command,name='N1Disposable',password=password));print('Disposable receive address:',opened['address'])
                    print('Fund only from your explicitly connected isolated Devnet. No mining is automatic.')
                elif choice=='2':
                    if session.wallet is None:raise ValueError('wallet locked')
                    path=Path(input('Explicit small disposable file path: ').strip())
                    if path.is_symlink() or not path.is_file() or not 1<=path.stat().st_size<=MAX_PLAIN:raise ValueError('file')
                    with path.open('rb') as stream:plain=stream.read(MAX_PLAIN+1)
                    if not 1<=len(plain)<=MAX_PLAIN:raise ValueError('bound')
                    q=client.quote(len(plain));client.encrypt(q['id'],plain)
                    print('Quote',q['id'],'Recipient',q['recipient'],'Price',q['amount_atomic'],'atomic PC; fee 188000; total 1188000; cap 500000.')
                    print('Retain intent. Ten local confirmations; provider must independently admit before quote expiry.')
                    if input('Type CONFIRM for this single real disposable PC payment: ')=='CONFIRM':session.refresh();client.pay(q['id'],session,'CONFIRM');print('SUBMITTED, NOT SETTLED. Use reconciliation; never repay after timeout.')
                elif choice=='3':
                    qid=identity(input('Original quote ID: ').strip());state=client.status(qid);explain_status(state)
                    if state['state']!='CONFIRMED_LOCAL':continue
                    result=client.upload(qid);print('Ciphertext stored',result['bytes']);dest=home/(qid+'.retrieval')
                    if not dest.exists():
                        password=getpass.getpass('New encrypted Bob bundle password: ').encode()
                        if password!=getpass.getpass('Confirm password: ').encode():raise ValueError('password')
                        client.export(qid,dest,password)
                    print('Private encrypted bundle:',dest);session.close();print('Alice locked.')
                elif choice=='4':
                    source=Path(input('Encrypted bundle path: ').strip());password=getpass.getpass('Password: ').encode();dest=Path(input('New output under private 0700 directory: ').strip());print(restore_bundle(source,password,dest,transport))
            except TransportError as error:print(error.state,error.code,'Preserve intent; no retry or new payment.')
            except Exception:print('Rejected or UNKNOWN. Check inputs, original intent and local node. Secrets withheld.')
    finally:session.close()
if __name__=='__main__':
    try:main()
    except (Exception,EOFError,KeyboardInterrupt):print('Remote client closed or setup unavailable. No public service or payment started automatically.');sys.exit(1)
