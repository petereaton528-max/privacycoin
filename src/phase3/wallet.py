"""Phase 3 chain wallet. Frozen Phase 2 encrypted keys; separate encrypted scan cache.

Private subprocess streams and decrypted cache contents must never be evidence.
"""
from pathlib import Path
import argparse
import importlib.util
import json
import secrets
import socket
import struct
import subprocess
import sys
import getpass
import os
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('foundation',ROOT/'src/wallet/wallet.py')
foundation=importlib.util.module_from_spec(spec);spec.loader.exec_module(foundation)
HELPER=ROOT/'build/monero-linux/phase3/privacycoin-spend-crypto'
NETWORK='PrivacyCoinDev01'
GENESIS='a0d9ba16f1f6b2fb2f480197ff9dec17468db0d5e6df9cfcb4b2b2a91ecffc87'
PROFILE=NETWORK+'/private-spend-v1/epoch17/'+GENESIS

def helper(q):
    p=subprocess.run([str(HELPER)],input=foundation.canonical(q)+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
    if p.returncode:
        raise ValueError('private transaction cryptographic request rejected')
    return json.loads(p.stdout,object_pairs_hook=foundation.unique)

def rpc(port,command,**fields):
    q=dict(network=NETWORK,genesis=GENESIS,profile=PROFILE,command=command,**fields)
    raw=foundation.canonical(q)
    def read(s,n):
        result=b''
        while len(result)<n:
            part=s.recv(n-len(result))
            if not part: raise ValueError('truncated node response')
            result+=part
        return result
    with socket.create_connection(('127.0.0.1',port),timeout=120) as s:
        magic=b'PrivacyCoinRPC03';s.sendall(magic+struct.pack('>I',len(raw))+raw)
        if read(s,16)!=magic:raise ValueError('incompatible RPC')
        n=struct.unpack('>I',read(s,4))[0]
        if n>1024*1024:raise ValueError('RPC size')
        result=json.loads(read(s,n),object_pairs_hook=foundation.unique)
    if result.get('network')!=NETWORK or result.get('genesis')!=GENESIS or result.get('profile')!=PROFILE:
        raise ValueError('incompatible network/genesis/profile')
    if 'error' in result:raise ValueError(result['error'])
    return result

def snapshot(port):
    for _ in range(3):
        info=rpc(port,'chain');records=[]
        for height,h in enumerate(info['chain'][1:],1):
            b=rpc(port,'get_block',hash=h)
            if b['height']!=height:raise ValueError('chain ordering')
            records.append(dict(transaction=b['coinbase'],height=height,coinbase=True))
            records.extend(dict(transaction=t,height=height,coinbase=False) for t in b['transactions'])
        if rpc(port,'status')['tip']==info['tip']:
            return dict(chain=records,images=info['images'],height=info['height'],tip=info['tip'])
    raise ValueError('chain changed while scanning; retry')

def request(w,state,full=True):
    q=dict(view=w['view'],public=w['public'],count=w['count'],**state)
    if full and w['authority']=='full':q['spend']=foundation.crypto('derive',w['seed'])[0]
    return q

def scan(w,state):
    return helper(dict(op='scan',**request(w,state)))

def balance(w,state,result):
    owned=result['owned'];total=sum(x['amount'] for x in owned)
    if w['authority']=='view':
        return dict(authority='view',height=state['height'],tip=state['tip'],incoming_total=total,spendable=None,spent_status='unknown without key images',outputs=len(owned))
    unspent=[x for x in owned if not x['spent']]
    return dict(authority='full',height=state['height'],tip=state['tip'],balance=sum(x['amount'] for x in unspent),
                spendable=sum(x['amount'] for x in unspent if x['unlock']<=state['height']+1),outputs=len(owned))

def build(w,state,destination,amount,fee,source=None):
    if w['authority']!='full':raise ValueError('view-only authority cannot spend')
    foundation.integer(amount,1,2**64-1);foundation.integer(fee,1,10**12)
    D,C,sub=foundation.parse_address(destination);result=scan(w,state)
    available=[x for x in result['owned'] if not x['spent'] and x['unlock']<=state['height']+1 and x['amount']>amount+fee]
    if source is not None:available=[x for x in available if x['global_index']==source]
    if not available:raise ValueError('no single mature output covers payment, fee and nonzero change')
    source=available[0]['global_index'];others=[i for i in result['eligible'] if i!=source]
    if len(others)<15:raise ValueError('fewer than 16 mature ring outputs; no weak fallback')
    ring=sorted([source]+secrets.SystemRandom().sample(others,15))
    return helper(dict(op='build',**request(w,state),D=D,C=C,sub=bool(sub),amount=amount,fee=fee,source=source,ring=ring))

def main():
    # Reuse the frozen key/backup/view workflow verbatim.
    if len(sys.argv)>1 and sys.argv[1] in ('create','address','backup','restore','view-export','view-import'):
        foundation.main();return
    if os.name!='posix':raise ValueError('authorized runtime is native WSL POSIX')
    p=argparse.ArgumentParser(description='Privacy Coin experimental private devnet wallet')
    p.add_argument('command',choices=['sync','rescan','balance','send'])
    p.add_argument('--wallet',type=Path,required=True);p.add_argument('--password-file',type=Path)
    p.add_argument('--rpc-port',type=int,default=48081);p.add_argument('--destination')
    p.add_argument('--amount',type=int);p.add_argument('--fee',type=int,default=1000000)
    p.add_argument('--file',type=Path,help='write public signed transaction instead of submitting')
    args=p.parse_args();password=foundation.read_private(args.password_file).rstrip(b'\r\n') if args.password_file else getpass.getpass('Wallet password: ').encode()
    import fcntl
    fd=os.open(str(args.wallet)+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);w=foundation.load(args.wallet,password);state=snapshot(args.rpc_port)
        result=scan(w,state);cache=dict(version=1,profile=PROFILE,wallet_id=foundation.wallet_id(w),tip=state['tip'],height=state['height'],scan=result)
        cachepath=Path(str(args.wallet)+'.phase3-cache')
        foundation.write_private(cachepath,foundation.seal(cache,password,'phase3-cache'),replace=True)
        if args.command=='send':
            payment=build(w,state,args.destination,args.amount,args.fee)
            if args.file:
                foundation.write_private(args.file,foundation.canonical(dict(version=1,profile=PROFILE,transaction=payment['transaction'])))
                result=dict(id=payment['id'],bytes=payment['bytes'],submitted=False)
            else:
                accepted=rpc(args.rpc_port,'submit_tx',transaction=payment['transaction'])['accepted']
                result=dict(id=accepted,bytes=payment['bytes'],submitted=True)
            print(json.dumps(result))
        else:print(json.dumps(balance(w,state,result)))
    finally:os.close(fd)

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,TypeError,KeyError):
        print('wallet request rejected',file=sys.stderr);sys.exit(1)
