"""Phase 4 private wallet. Decrypted ownership/cache data never become evidence."""
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
import signal
import tempfile
import threading
import bisect
from array import array
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('foundation',ROOT/'src/wallet/wallet.py')
foundation=importlib.util.module_from_spec(spec);spec.loader.exec_module(foundation)
HELPER=ROOT/('build/monero-windows/phase4/privacycoin-hardened-crypto.exe' if os.name=='nt' else 'build/monero-linux/phase4/privacycoin-hardened-crypto')
# This wallet is also loaded by filename from standalone service/CLI processes.
# Resolve the owned selector explicitly; never depend on PYTHONPATH or cwd.
identity_spec=importlib.util.spec_from_file_location('pc_network_identity',ROOT/'src/network_identity.py')
identity_module=importlib.util.module_from_spec(identity_spec);identity_spec.loader.exec_module(identity_module)
NETWORK,GENESIS,PROFILE=identity_module.NETWORK,identity_module.GENESIS,identity_module.PROFILE

def helper(q,executable=None):
    p=subprocess.run([str(executable or HELPER)],input=foundation.canonical(q)+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    if p.returncode:raise ValueError('private transaction cryptographic request rejected')
    return json.loads(p.stdout,object_pairs_hook=foundation.unique)

def rpc(port,command,**fields):
    raw=foundation.canonical(dict(network=NETWORK,genesis=GENESIS,profile=PROFILE,command=command,**fields))
    def read(s,n):
        result=b''
        while len(result)<n:
            part=s.recv(n-len(result))
            if not part:raise ValueError('truncated node response')
            result+=part
        return result
    with socket.create_connection(('127.0.0.1',port),timeout=180) as s:
        s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);magic=b'PrivacyCoinRPC04';s.sendall(magic+struct.pack('>I',len(raw))+raw)
        if read(s,16)!=magic:raise ValueError('incompatible RPC')
        n=struct.unpack('>I',read(s,4))[0]
        if n>1024*1024:raise ValueError('RPC size')
        result=json.loads(read(s,n),object_pairs_hook=foundation.unique)
    if (result.get('network'),result.get('genesis'),result.get('profile'))!=(NETWORK,GENESIS,PROFILE):raise ValueError('incompatible network/genesis/profile')
    if 'error' in result:raise ValueError(result['error'])
    return result

class ChainRecords:
    """Private anonymous spool; raw chain history does not accumulate in RAM.

    Compact offsets cost eight bytes per record. Payload is public chain data,
    not keys. The open descriptor is automatically closed with its snapshot.
    """
    def __init__(self):
        self.file=tempfile.TemporaryFile(mode='w+b');self.offsets=array('Q',[0]);self.lock=threading.Lock()
    def extend(self,records):
        for record in records:
            raw=foundation.canonical(record)
            with self.lock:
                self.file.seek(self.offsets[-1]);self.file.write(raw);self.offsets.append(self.file.tell())
    def __len__(self):return len(self.offsets)-1
    def __getitem__(self,index):
        if isinstance(index,slice):return [self[i] for i in range(*index.indices(len(self)))]
        if index<0:index+=len(self)
        if not 0<=index<len(self):raise IndexError(index)
        with self.lock:
            self.file.seek(self.offsets[index]);raw=self.file.read(self.offsets[index+1]-self.offsets[index])
        return json.loads(raw,object_pairs_hook=foundation.unique)
    def __iter__(self):
        for index in range(len(self)):yield self[index]
    def close(self):
        if getattr(self,'file',None) is not None:self.file.close()
    def __del__(self):
        self.close()

def snapshot(port,crash=None,*,bounded=False):
    for _ in range(3):
        first=rpc(port,'history',offset=1,count=32,**({'metadata_only':1} if bounded else {}));records=ChainRecords() if bounded else [];records.extend(first['records']);offset=first['next'];tip=first['tip'];revision=first['revision'];instance=first['instance']
        try:
            if type(offset) is not int or not 1<=offset<=first['height']+1 or (first['height'] and offset<=1):raise ValueError('invalid history progress')
            while offset<=first['height']:
                page=rpc(port,'history',offset=offset,count=32,tip=tip,revision=revision,instance=instance)
                if (page['tip'],page['revision'],page['instance'])!=(tip,revision,instance) or type(page['next']) is not int or not offset<page['next']<=first['height']+1:raise ValueError('invalid history progress')
                records.extend(page['records']);offset=page['next']
            images=first['images'];orphan=first['orphan_images']
            if first.get('metadata_paged') is True:
                # The validated canonical transactions already carry all spent
                # images. Derive the complete sorted set locally, never ask the
                # node to repeat it in every growing history/chain response.
                images=sorted({image for record in records for image in record['images']})
                orphan=[];after=''
                while True:
                    page=rpc(port,'orphan_images_page',after=after,count=1024,tip=tip,revision=revision,instance=instance)
                    values=page['images']
                    if (page['tip'],page['revision'],page['instance'])!=(tip,revision,instance) or type(page['done']) is not bool or not isinstance(values,list) or len(values)>1024:raise ValueError('invalid image page')
                    for image in values:
                        foundation.unhex(image,32)
                        if image<=after:raise ValueError('invalid image page order')
                        after=image
                    if page['after']!=after or (not page['done'] and len(values)!=1024):raise ValueError('invalid image page progress')
                    orphan.extend(values)
                    if page['done']:break
            pool=[]
            for start in range(0,len(first['pool_ids']),8):pool.extend(rpc(port,'pool_page',offset=start,count=8,tip=tip,revision=revision,instance=instance)['entries'])
            final=rpc(port,'snapshot_id')
            if (final['tip'],final['revision'],final['instance'])!=(tip,revision,instance):continue
            if crash=='during_rescan':os.kill(os.getpid(),signal.SIGKILL)
            records.extend(dict(transaction=x['transaction'],height=first['height']+1,coinbase=False,pending=True,images=x['images'],id=x['id']) for x in pool)
            chain=records
            return dict(chain=chain,images=images,pool_images=[i for x in pool for i in x['images']],pool=pool,orphan_images=orphan,height=first['height'],tip=tip)
        except ValueError:continue
    raise ValueError('chain or pool changed while scanning; retry')

def request(w,state,full=True):
    q=dict(view=w['view'],public=w['public'],count=max(2,w['count']),
           **{k:state[k] for k in ('chain','images','pool_images','height')})
    if full and w['authority']=='full':q['spend']=foundation.crypto('derive',w['seed'])[0]
    return q

def scan(w,state):
    # Bound native parsing/ownership work independently of total chain length.
    # Key images are reconciled against the complete anchored snapshot in Python;
    # never trust a persisted scan, or declare an incomplete scan spendable.
    result=dict(owned=[],eligible=[],record_outputs=[],scan_ms=0,
                scanned_outputs=0,undecodable_owned_outputs=0)
    spent=set(state['images']);reserved=set(state['pool_images'])
    batch=[];size=0;offset=0
    def consume():
        nonlocal offset
        local=dict(chain=batch,images=[],pool_images=[],height=state['height'])
        part=helper(dict(op='scan',**request(w,local)))
        counts=part['record_outputs']
        if len(counts)!=len(batch) or any(type(n) is not int or not 0<=n<=16 for n in counts) or sum(counts)!=part['scanned_outputs']:
            raise ValueError('incomplete output index scan')
        for x in part['owned']:
            x['global_index']+=offset
            if w['authority']=='full':
                x['spent']=x['image'] in spent;x['reserved']=x['image'] in reserved
        result['owned'].extend(part['owned'])
        result['eligible'].extend(i+offset for i in part['eligible'])
        result['record_outputs'].extend(counts)
        for k in ('scan_ms','scanned_outputs','undecodable_owned_outputs'):result[k]+=part[k]
        offset+=part['scanned_outputs']
    for record in state['chain']:
        if 'global_offset' in record:raise ValueError('unexpected snapshot output offset')
        n=len(foundation.canonical(record))
        if n>1024*1024:raise ValueError('transaction record size')
        if batch and (size+n>1024*1024 or len(batch)>=256):consume();batch=[];size=0
        batch.append(record);size+=n
    if batch:consume()
    return result

def construction_state(state,result,selections):
    # Include only transactions supplying the chosen real inputs and decoys.
    # Explicit offsets preserve on-chain ring members even across omitted history.
    counts=result['record_outputs']
    if len(counts)!=len(state['chain']):raise ValueError('incomplete construction index')
    wanted=sorted({i for s in selections for i in s['ring']})
    records=[];offset=0;cursor=0
    for record,count in zip(state['chain'],counts):
        end=offset+count
        if cursor<len(wanted) and wanted[cursor]<offset:raise ValueError('invalid ring index')
        if cursor<len(wanted) and wanted[cursor]<end:
            records.append(dict(record,global_offset=offset))
            while cursor<len(wanted) and wanted[cursor]<end:cursor+=1
        offset=end
    if cursor!=len(wanted) or len(records)>128:raise ValueError('invalid construction subset')
    return dict(chain=records,images=state['images'],pool_images=state['pool_images'],height=state['height'])

def balance(w,state,result):
    canonical=[x for x in result['owned'] if not x['pending']];pending=[x for x in result['owned'] if x['pending']]
    if w['authority']=='view':return dict(authority='view',height=state['height'],tip=state['tip'],incoming_total=sum(x['amount'] for x in canonical),pending_incoming=sum(x['amount'] for x in pending),balance=None,spendable=None,spent_status='unknown without authenticated key images')
    unspent=[x for x in canonical if not x['spent']];unlocked=[x for x in unspent if x['unlock']<=state['height']+1];known={x['image'] for x in canonical}
    outgoing={x['id'] for x in state.get('pool',[]) if known.intersection(x['images'])}
    canonical_outgoing={x.get('id') for x in state['chain'] if not x.get('pending') and known.intersection(x.get('images',[]))}
    change=[x for x in pending if x['transaction'] in outgoing and x['address_index']==1]
    reserved=sum(x['amount'] for x in unspent if x['reserved']);pending_owned=sum(x['amount'] for x in pending);fees=sum(x['fee'] for x in state.get('pool',[]) if x['id'] in outgoing)
    return dict(authority='full',height=state['height'],tip=state['tip'],balance=sum(x['amount'] for x in unspent),total_balance=sum(x['amount'] for x in unspent),
        unlocked_balance=sum(x['amount'] for x in unlocked),spendable=sum(x['amount'] for x in unlocked if not x['reserved']),reserved_inputs=reserved,
        pending_incoming=pending_owned-sum(x['amount'] for x in change),pending_change=sum(x['amount'] for x in change),
        pending_outgoing=reserved-sum(x['amount'] for x in pending if x['transaction'] in outgoing)-fees,pending_fees=fees,projected_balance=sum(x['amount'] for x in unspent)-reserved+pending_owned,
        locked_coinbase=sum(x['amount'] for x in unspent if x['coinbase'] and x['unlock']>state['height']+1),locked_normal=sum(x['amount'] for x in unspent if not x['coinbase'] and x['unlock']>state['height']+1),
        spent_outputs=sum(x['spent'] for x in canonical),outputs=len(canonical),pending_outputs=len(pending),
        change_outputs=sum(x['transaction'] in canonical_outgoing and x['address_index']==1 for x in canonical),reorg_restored_outputs=sum(x['image'] in state.get('orphan_images',[]) for x in unspent))

def estimate_fee(inputs,outputs):return (900+700*inputs+140*outputs)*100

def build(w,state,destination=None,amount=None,fee=None,source=None,recipients=None,sources=None,dedicated_change=True):
    if w['authority']!='full':raise ValueError('view-only authority cannot spend')
    recipients=recipients if recipients is not None else [dict(address=destination,amount=amount)]
    if not 1<=len(recipients)<=15:raise ValueError('recipient count')
    dests=[];total=0
    for recipient in recipients:
        value=foundation.integer(recipient['amount'],1,2**64-1);D,C,sub=foundation.parse_address(recipient['address']);total+=value;dests.append(dict(D=D,C=C,sub=bool(sub),amount=value))
    if total>=2**64:raise ValueError('payment overflow')
    if fee is not None:foundation.integer(fee,1,10**12)
    result=scan(w,state);available=[x for x in result['owned'] if not x['pending'] and not x['spent'] and not x['reserved'] and x['unlock']<=state['height']+1]
    indices=sources if sources is not None else ([source] if source is not None else None)
    if indices is not None:
        if len(set(indices))!=len(indices):raise ValueError('duplicate source')
        by_index={x['global_index']:x for x in available}
        if any(i not in by_index for i in indices):raise ValueError('selected output unavailable')
        selected=[by_index[i] for i in indices]
    else:
        sufficient=[x for x in available if x['amount']>total+(fee if fee is not None else estimate_fee(1,len(dests)+1))]
        if sufficient:selected=[min(sufficient,key=lambda x:x['amount'])]
        else:
            selected=[]
            for x in sorted(available,key=lambda x:x['amount'],reverse=True):
                selected.append(x)
                if len(selected)>8:raise ValueError('more than eight inputs required')
                if sum(y['amount'] for y in selected)>total+(fee if fee is not None else estimate_fee(len(selected),len(dests)+1)):break
    if not 1<=len(selected)<=8:raise ValueError('insufficient unlocked funds')
    fee=fee if fee is not None else estimate_fee(len(selected),len(dests)+1)
    if sum(x['amount'] for x in selected)<=total+fee:raise ValueError('insufficient funds for fee and nonzero change')
    selections=[]
    for x in selected:
        index=x['global_index'];eligible=result['eligible'];position=bisect.bisect_left(eligible,index)
        if position==len(eligible) or eligible[position]!=index:raise ValueError('source absent from mature output index')
        if len(eligible)<16:raise ValueError('fewer than 16 mature outputs; no privacy fallback')
        # Uniform sampling without a second chain-sized list for every input.
        sampled=secrets.SystemRandom().sample(range(len(eligible)-1),15)
        selections.append(dict(source=index,ring=sorted([index]+[eligible[i+(i>=position)] for i in sampled])))
    subset=construction_state(state,result,selections)
    # Only selected real key images affect construction; avoid resending the
    # chain-wide spent set. Fresh scan and native checks both enforce availability.
    selected_images={x['image'] for x in selected}
    subset['images']=[i for i in subset['images'] if i in selected_images]
    subset['pool_images']=[i for i in subset['pool_images'] if i in selected_images]
    payment=helper(dict(op='build',**request(w,subset),sources=selections,destinations=dests,fee=fee,dedicated_change=dedicated_change))
    if fee<100*payment['bytes']:raise ValueError('fee estimate below exact byte relay floor')
    payment.update(fee=fee,inputs=len(selected),outputs=len(dests)+1);return payment

def main():
    if len(sys.argv)>1 and sys.argv[1] in ('create','address','backup','restore','view-export','view-import'):foundation.main();return
    if os.name!='posix':raise ValueError('authorized runtime is native WSL POSIX')
    p=argparse.ArgumentParser(description='Privacy Coin experimental hardened private devnet wallet')
    p.add_argument('command',choices=['sync','rescan','balance','send','send-many']);p.add_argument('--wallet',type=Path,required=True);p.add_argument('--password-file',type=Path)
    p.add_argument('--rpc-port',type=int,default=48081);p.add_argument('--destination');p.add_argument('--recipients-file',type=Path);p.add_argument('--amount',type=int);p.add_argument('--fee',type=int)
    p.add_argument('--file',type=Path);p.add_argument('--test-crash-stage',choices=['before_cache_publish','after_cache_publish','during_rescan'])
    args=p.parse_args();password=foundation.read_private(args.password_file).rstrip(b'\r\n') if args.password_file else getpass.getpass('Wallet password: ').encode()
    import fcntl
    fd=os.open(str(args.wallet)+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);wallet=foundation.load(args.wallet,password);state=snapshot(args.rpc_port,args.test_crash_stage);result=scan(wallet,state)
        cache=dict(version=1,profile=PROFILE,wallet_id=foundation.wallet_id(wallet),tip=state['tip'],height=state['height'],scan=result)
        def fault(stage):
            if args.test_crash_stage==dict(before_publish='before_cache_publish',after_publish='after_cache_publish').get(stage):os.kill(os.getpid(),signal.SIGKILL)
        foundation.write_private(Path(str(args.wallet)+'.phase4-cache'),foundation.seal(cache,password,'phase4-cache'),replace=True,fault=fault)
        if args.command in ('send','send-many'):
            recipients=json.loads(foundation.read_private(args.recipients_file)) if args.command=='send-many' else None
            payment=build(wallet,state,args.destination,args.amount,args.fee,recipients=recipients)
            if args.file:
                foundation.write_private(args.file,foundation.canonical(dict(version=1,profile=PROFILE,transaction=payment['transaction'])));response=dict(id=payment['id'],bytes=payment['bytes'],fee=payment['fee'],submitted=False)
            else:response=dict(id=rpc(args.rpc_port,'submit_tx',transaction=payment['transaction'])['accepted'],bytes=payment['bytes'],fee=payment['fee'],submitted=True)
            print(json.dumps(response))
        else:print(json.dumps(balance(wallet,state,result)))
    finally:os.close(fd)

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,TypeError,KeyError):print('wallet request rejected',file=sys.stderr);sys.exit(1)
