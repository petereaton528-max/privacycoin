"""Guided local Windows/WSL product demonstration. No automatic approval/mining."""
from common import *
from client import restore_bundle
from runtime import Runtime
import argparse,getpass,time

def explain_status(state):
    print('Provider observes:',state['state'],'Payment:',state.get('payment_state','UNKNOWN'),'Global freshness UNKNOWN')
    if state.get('first_seen_at') is not None:
        print('Timely payment independently recorded. Confirmation deadline:',time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime(state['payment_deadline'])))
    if state.get('recovery')=='PAID_NO_ENTITLEMENT':
        print('PAYMENT CONFIRMED BUT NO ENTITLEMENT. Timely admission is unproven or the confirmation window elapsed. Preserve the original intent; do not pay again. Manual operator resolution is required; no automatic refund exists.')
    elif state['state']=='EXPIRED':print('Expired:',state.get('expiration_reason','UNKNOWN'),'. This does not prove payment failed. No replacement payment will be created.')

def finish_store(r,client,qid):
    state=client.status(qid)
    if state['state']!='CONFIRMED_LOCAL':
        explain_status(state);print('No current entitlement. Preserve intent; no replacement payment was created.');return
    result=client.upload(qid);print('Ciphertext durably stored:',result['bytes'],'bytes')
    bundlepath=r.base/(qid+'.retrieval')
    if not bundlepath.exists():
        password=getpass.getpass('New retrieval-bundle password (12–1024 bytes): ').encode()
        if password!=getpass.getpass('Confirm bundle password: ').encode():raise ValueError('password mismatch')
        client.export(qid,bundlepath,password)
    print('Private encrypted Bob bundle:',bundlepath,'Keep its password separate. No wallet authority included.')
    r.session.close();print('Alice wallet is now locked. Bob can use option 2 or standalone retrieve.py while this service window stays open.')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--home',type=Path);a=parser.parse_args();r=None
    print('PRIVACY NETWORK V0.1 — DEVNET ONLY. No anonymity or real assets.\nOnly a separate disposable network is used. Original Alice/Bob wallets are untouched.')
    try:
        r=Runtime(a.home);print('Two independent providers ready. Shared local validating node, height',r.node.status()['height'])
        print('Private pilot data:',r.base)
        while True:
            print('\n1 Store a file  2 Retrieve an encrypted capability (Bob)  3 Restart provider  4 Explicit test mining  5 Exit  6 Reconcile retained intent (NO new payment)')
            choice=input('Choose: ').strip()
            try:
                if choice=='5':break
                if choice=='4':
                    count=int(input('Bounded disposable blocks (1–100): '))
                    if input('Type MINE DEVNET to authorize test-only CPU mining: ')=='MINE DEVNET':r.mine(count);print('Height:',r.node.status()['height'])
                elif choice=='3':
                    i=int(input('Provider 1 or 2: '))-1;f.integer(i,0,1);r.stop_provider(i);r.start_provider(i);print('Restarted with durable data.')
                elif choice=='2':
                    source=Path(input('Private encrypted retrieval bundle (WSL path): ').strip());password=getpass.getpass('Bundle password: ').encode()
                    destination=Path(input('NEW output file under a private WSL directory: ').strip())
                    result=restore_bundle(source,password,destination);print('Verified and saved:',result)
                elif choice=='6':
                    i=int(input('Original provider 1 or 2: '))-1;f.integer(i,0,1)
                    qid=input('Original public quotation ID from the retained intent filename: ').strip()
                    finish_store(r,r.client(i),identity(qid))
                elif choice=='1':
                    i=int(input('Provider 1 or 2: '))-1;f.integer(i,0,1);client=r.client(i)
                    path=Path(input('Explicit disposable file path (Windows D: is /mnt/d/…): ').strip())
                    if not path.is_file() or path.is_symlink() or not 1<=path.stat().st_size<=MAX_PLAIN:raise ValueError('file bound')
                    with path.open('rb') as stream:plain=stream.read(MAX_PLAIN+1)
                    if not 1<=len(plain)<=MAX_PLAIN:raise ValueError('file bound')
                    q=client.quote(len(plain));cipher,bundle=client.encrypt(q['id'],plain)
                    print('Quote:',q['id'],'Provider:',i+1,'Storage bytes:',q['quota'],'Retention seconds:',q['retention'])
                    print('Provider must independently observe this payment before',time.strftime('%H:%M:%S UTC',time.gmtime(q['expires'])),'. A timely observed payment then has until',time.strftime('%H:%M:%S UTC',time.gmtime(q['payment_deadline'])),'to meet local confirmations. Retention starts only at entitlement acceptance.')
                    print('Recipient:',q['recipient']);print('Price 1000000 atomic (0.000001 PC); fee 188000, total 1188000; max fee 500000. Ten local confirmations, not global finality.')
                    if input('Type CONFIRM to authorize this real disposable PC payment, or Cancel: ')!='CONFIRM':print('No payment sent. Quote remains reserved until expiry.');continue
                    if r.session.wallet is None:r.session.dispatch(dict(command='open',name='DisposableAlice',password=r.config['password']))
                    r.session.refresh();client.pay(q['id'],r.session,'CONFIRM');print('Submitted, NOT settled. Intent retained at',client.path(q['id']))
                    while True:
                        state=client.status(q['id']);explain_status(state)
                        if state['state']=='CONFIRMED_LOCAL':break
                        if state['state']=='EXPIRED':break
                        action=input('Enter WAIT, MINE 10 (explicit test confirmation blocks), or EXIT (preserve intent; do not repay): ')
                        if action=='EXIT':break
                        if action=='MINE 10':r.mine(10)
                        elif action=='WAIT':time.sleep(1)
                    if state['state']!='CONFIRMED_LOCAL':continue
                    finish_store(r,client,q['id'])
                else:print('Choose 1–6.')
            except Exception:print('Operation rejected or UNKNOWN. Preserve intent; do not blindly pay again. Check input, funds, expiry, provider/node and private paths. No secret or traceback displayed.')
    finally:
        if r:r.close()
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt,EOFError):print('Pilot closed or startup failed. Owned processes stopped; private data retained. No automatic retry.')
