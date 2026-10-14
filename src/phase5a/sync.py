"""Research-only download-all protocol and local incremental cache. No CLI integration."""
from pathlib import Path
import importlib.util,json,struct,subprocess,select
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('research_frozen_wallet',ROOT/'src/phase4/wallet.py')
w=importlib.util.module_from_spec(s);s.loader.exec_module(w);f=w.foundation
HELPER=ROOT/'build/monero-linux/phase5a/privacycoin-sync-research'
VERSION=1

class Worker:
    def __init__(self,reference=False):
        self.p=subprocess.Popen([str(HELPER)]+(['--reference'] if reference else []),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    def call(self,q):
        self.p.stdin.write(f.canonical(q)+b'\n');self.p.stdin.flush()
        if not select.select([self.p.stdout],[],[],180)[0]:self.p.kill();raise ValueError('research adapter timeout')
        line=self.p.stdout.readline()
        if not line:raise ValueError('research adapter rejected request')
        return json.loads(line,object_pairs_hook=f.unique)
    def close(self):
        self.p.stdin.close();self.p.wait(timeout=20);self.p.stdout.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

def pack(records,pruned=False):
    # Exact transport includes format, mode, count and all record metadata.
    out=bytearray(b'PC5A'+bytes([VERSION,int(pruned)])+struct.pack('>I',len(records)))
    for r in records:
        body=bytes.fromhex(r['transaction'])
        out+=struct.pack('>QBI',r['height'],int(r['coinbase']),len(body))+bytes.fromhex(r['id'])+body
        if pruned:out+=bytes.fromhex(r['prunable_hash'])
    return bytes(out)

def unpack(data):
    if len(data)>16*1024*1024:raise ValueError('envelope byte bound')
    if len(data)<10 or data[:4]!=b'PC5A' or data[4]!=VERSION or data[5] not in (0,1):raise ValueError('unsupported envelope')
    count=struct.unpack_from('>I',data,6)[0]
    if count>10000:raise ValueError('count bound')
    offset=10;records=[]
    for _ in range(count):
        if offset+45>len(data):raise ValueError('truncated record')
        height,cb,size=struct.unpack_from('>QBI',data,offset);offset+=13
        if cb not in (0,1) or size>50000:raise ValueError('record bound')
        identity=data[offset:offset+32].hex();offset+=32
        end=offset+size
        if end>len(data):raise ValueError('truncated transaction')
        r=dict(height=height,coinbase=bool(cb),id=identity,transaction=data[offset:end].hex());offset=end
        if data[5]:
            if offset+32>len(data):raise ValueError('truncated hash')
            r['prunable_hash']=data[offset:offset+32].hex();offset+=32
        records.append(r)
    if offset!=len(data):raise ValueError('trailing data')
    return records

def manifest(state):
    return dict(version=VERSION,profile=w.PROFILE,height=state['height'],tip=state['tip'],
        records=[{k:r[k] for k in ('id','height','coinbase')} for r in state['chain'] if not r.get('pending')])

def checkpoint(advertised,anchor):
    if any(advertised.get(k)!=anchor.get(k) for k in ('version','profile','height','tip')):raise ValueError('checkpoint differs from independent anchor')

def authenticate(data,anchor,worker,advertised=None):
    if advertised is not None:checkpoint(advertised,anchor)
    if anchor.get('version')!=VERSION or anchor.get('profile')!=w.PROFILE:raise ValueError('anchor version/profile')
    records=unpack(data)
    if [{k:r[k] for k in ('id','height','coinbase')} for r in records]!=anchor['records']:raise ValueError('history differs from independent manifest')
    # project cannot verify pruned input; scan checks every reconstructed tx hash.
    # A separate verify operation uses the same parser without wallet secrets.
    checked=worker.call(dict(op='verify',chain=records))
    return records,checked['images']

def delta_anchor(anchor,height):
    return dict(anchor,records=[r for r in anchor['records'] if r['height']>height])

def merge(cache,delta,images,height):
    # All images from authenticated full history, not arbitrary server KI lists.
    owned=[dict(x) for x in cache['owned']]+[dict(x) for x in delta['owned']]
    image_set=set(images)
    for x in owned:
        if x.get('image') is not None:x['spent']=x['image'] in image_set
    return dict(owned=owned,scanned_outputs=cache['scanned_outputs']+delta['scanned_outputs'],
        eligible=[],undecodable_owned_outputs=cache['undecodable_owned_outputs']+delta['undecodable_owned_outputs'])

def rollback(cache,height):
    # A checkpoint at height h stores the exact output count at that boundary.
    return dict(cache,owned=[dict(x) for x in cache['owned'] if x['height']<=height])
