"""Opt-in verified pruned sync. Full private spending remains on frozen wallet path."""
from pathlib import Path
import argparse,importlib.util,json,os,sys,time,signal
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('phase5b_transport',ROOT/'src/phase5b/transport.py');t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
w=t.w;f=t.f
CACHE_KIND='phase5b-cache';CACHE_VERSION=1
def identity(s):return tuple(s[k] for k in ('tip','height','revision','instance'))
def anchor_call(endpoint,command,**fields):return t.decode(endpoint.call(command,**fields)[1])

def validate_cache(cache,wallet):
    if not isinstance(cache,dict) or type(cache.get('version')) is not int or type(cache.get('count')) is not int or (cache.get('version'),cache.get('profile'),cache.get('wallet_id'),cache.get('count'),cache.get('schemes'),cache.get('authority'))!=(1,w.PROFILE,f.wallet_id(wallet),wallet['count'],wallet['schemes'],wallet['authority']):raise ValueError('cache identity/scheme')
    if type(cache.get('blocks')) is not list or len(cache['blocks'])>1024 or type(cache.get('owned')) is not list:raise ValueError('cache bounds')
    if type(cache.get('records')) is not list or len(cache['records'])>9216:raise ValueError('cache record bounds')
    previous=0;outputs=0
    for b in cache['blocks']:
        if type(b['height']) is not int or b['height']!=previous+1 or type(b['outputs']) is not int or not outputs<=b['outputs']<=8192 or type(b['id']) is not str or len(b['id'])!=64:raise ValueError('cache boundary')
        previous=b['height'];outputs=b['outputs']
    if cache.get('height')!=previous or cache.get('tip')!=(cache['blocks'][-1]['id'] if previous else w.GENESIS):raise ValueError('cache checkpoint')
    if len(cache['owned'])>outputs or len({x['global_index'] for x in cache['owned']})!=len(cache['owned']):raise ValueError('cache ownership bounds')
    if any(x['height']>previous or x['pending'] for x in cache['owned']):raise ValueError('cache provenance')
    positions={};offset=0;cursor=0
    for block in cache['blocks']:
        count=0
        while cursor<len(cache['records']) and cache['records'][cursor]['height']==block['height']:
            record=cache['records'][cursor];size=record['outputs']
            if type(size) is not int or not 1<=size<=16 or type(record['coinbase']) is not bool or record['coinbase']!=(count==0) or type(record['fee']) is not int or not 0<=record['fee']<=10**12 or record['id'] in positions:raise ValueError('cached record shape')
            if type(record['images']) is not list or len(record['images'])>8 or any(type(x) is not str or len(x)!=64 for x in record['images']):raise ValueError('cached image shape')
            positions[record['id']]=(offset,size,block['height'],record['coinbase']);offset+=size;cursor+=1;count+=1
        if count!=block['records'] or offset!=block['outputs']:raise ValueError('cached output count')
    if cursor!=len(cache['records']):raise ValueError('cached record ordering')
    for x in cache['owned']:
        start,size,height,coinbase=positions[x['transaction']]
        if type(x['output_index']) is not int or not 0<=x['output_index']<size or x['global_index']!=start+x['output_index'] or x['height']!=height or x['coinbase']!=coinbase or x['unlock']!=height+(60 if coinbase else 10):raise ValueError('cached ownership position')
        if type(x['amount']) is not int or not 0<=x['amount']<2**64:raise ValueError('cached amount')
    return cache

def synchronize(wallet,anchor,data,cache=None,force=False,fault=None):
    begin=time.perf_counter();head=anchor_call(anchor,'snapshot_id');height=head['height']
    if type(height) is not int or not 0<=height<1024:raise ValueError('chain bound')
    if cache is not None:validate_cache(cache,wallet)
    if force:cache=None
    with t.worker() as worker:
        blocks=[];expected=[];previous=w.GENESIS;offset=1;pool_ids=[];orphan_images=[]
        while offset<=height:
            page=anchor_call(anchor,'sync_manifest',offset=offset,count=32,**{k:head[k] for k in ('tip','revision','instance')})
            if identity(page)!=identity(head) or page['next']<=offset or page['next']>min(height+1,offset+32) or len(page['blocks'])!=page['next']-offset:raise ValueError('anchor range/snapshot')
            parsed=worker.call(dict(op='manifest',blocks=page['blocks'],previous=previous,start=offset))
            blocks.extend(parsed['blocks']);expected.extend(parsed['records']);previous=blocks[-1]['id'];offset=page['next']
            if offset==len(page['blocks'])+1:pool_ids=page['pool_ids'];orphan_images=page['orphan_images']
        if previous!=head['tip']:raise ValueError('manifest tip mismatch')
        common=0
        if cache:
            for old,new in zip(cache['blocks'],blocks):
                if old['id']!=new['id']:break
                common+=1
        kept=[dict(x) for x in (cache['owned'] if cache else []) if x['height']<=common]
        metadata=[dict(x) for x in (cache['records'] if cache else []) if x['height']<=common]
        output_offset=cache['blocks'][common-1]['outputs'] if cache and common else 0
        for b in blocks[:common]:b['outputs']=cache['blocks'][b['height']-1]['outputs']
        offset=common+1;new_outputs=0;owned=kept;verify_ms=0;scan_ms=0;scan_authority=None
        while offset<=height:
            if data is None:
                page=anchor_call(anchor,'history',offset=offset,count=32,**{k:head[k] for k in ('tip','revision','instance')});records=page['records'];next_height=page['next']
                if identity(page)!=identity(head):raise ValueError('full reference snapshot changed')
            else:
                header,payload=data.call('history',offset=offset,count=32,tip=head['tip']);next_height=header['next']
                if type(header.get('height')) is not int or type(header.get('offset')) is not int or header.get('tip')!=head['tip'] or header.get('height')!=height or header.get('offset')!=offset:raise ValueError('data checkpoint/range')
                records=t.p.unpack(payload)
                if any('prunable_hash' not in r for r in records):raise ValueError('pruned mode expected')
            if type(next_height) is not int or not offset<next_height<=min(height+1,offset+32):raise ValueError('noncontiguous range')
            wanted=[x for x in expected if offset<=x['height']<next_height]
            if [{k:r[k] for k in ('id','height','coinbase')} for r in records]!=wanted:raise ValueError('incomplete/reordered block transaction set')
            stamp=time.perf_counter();details=worker.call(dict(op='metadata',chain=records));verify_ms+=(time.perf_counter()-stamp)*1000
            # Per-operation authority only: no cross-wallet cache, persistence
            # or server disclosure. The native scanner still checks keys/page.
            if scan_authority is None:scan_authority=w.request(wallet,{})
            request=dict(scan_authority,op='scan',chain=records,images=[],pool_images=[],height=height,offset=output_offset)
            scanned=worker.call(request)
            if scanned['undecodable_owned_outputs']!=0 or scanned['scanned_outputs']!=details['outputs']:raise ValueError('owned decode/output boundary failure')
            owned.extend(scanned['owned']);scan_ms+=scanned['scan_ms'];metadata.extend(details['records']);new_outputs+=details['outputs']
            for h in range(offset,next_height):
                output_offset+=sum(r['outputs'] for r in details['records'] if r['height']==h);blocks[h-1]['outputs']=output_offset
            if output_offset>8192:raise ValueError('output resource bound')
            offset=next_height
            if fault=='during_scan':os.kill(os.getpid(),signal.SIGKILL)
        if [{k:r[k] for k in ('id','height','coinbase')} for r in metadata]!=expected:raise ValueError('cached history completeness mismatch')
        images=[x for r in metadata for x in r['images']];spent=set(images)
        pool=[]
        for start in range(0,len(pool_ids),8):
            page=anchor_call(anchor,'pool_page',offset=start,count=8,**{k:head[k] for k in ('tip','revision','instance')})
            if identity(page)!=identity(head):raise ValueError('pool snapshot changed')
            pool.extend(page['entries'])
        if [r['id'] for r in pool]!=pool_ids:raise ValueError('pool completeness/order')
        pending_images={x for r in pool for x in r['images']}
        for x in owned:
            if wallet['authority']=='full':x['spent']=x['image'] in spent;x['reserved']=x['image'] in pending_images
        canonical_owned=[dict(x, reserved=False if wallet['authority']=='full' else None) for x in owned]
        pending=[]
        if pool:
            pending_state=dict(chain=[dict(r,pending=True) for r in pool],images=images,pool_images=list(pending_images),height=height)
            # Frozen scanner preserves pending semantics exactly; global indexes
            # shifted after canonical outputs, never used for chain spendability.
            pending=w.scan(wallet,pending_state)['owned']
            for x in pending:x['global_index']+=output_offset
        final=anchor_call(anchor,'snapshot_id')
        if identity(final)!=identity(head):raise ValueError('anchor changed before cache publication')
        state=dict(chain=metadata+[dict(r,pending=True) for r in pool],images=images,pool_images=list(pending_images),pool=pool,orphan_images=orphan_images,height=height,tip=head['tip'])
        result=dict(owned=owned+pending,eligible=[],scanned_outputs=output_offset,undecodable_owned_outputs=0)
        cache=dict(version=1,profile=w.PROFILE,wallet_id=f.wallet_id(wallet),schemes=wallet['schemes'],count=wallet['count'],authority=wallet['authority'],
            blocks=blocks,records=metadata,owned=canonical_owned,tip=head['tip'],height=height)
        validate_cache(cache,wallet)
        return dict(cache=cache,balance=w.balance(wallet,state,result),state=state,scan=result,
            measurements=dict(wall_ms=(time.perf_counter()-begin)*1000,verify_ms=verify_ms,native_scan_ms=scan_ms,new_outputs=new_outputs,common_height=common))

def run(wallet,anchor,data,cache=None,force=False,fallback='none',fault=None):
    if fallback not in ('none','full'):raise ValueError('fallback policy')
    if data is not None and anchor.certificate_sha256==data.certificate_sha256:raise ValueError('anchor and data roles require separate certificate pins')
    try:return synchronize(wallet,anchor,data,cache,force,fault),False
    except (ValueError,OSError,KeyError,TypeError,OverflowError):
        if fallback!='full':raise ValueError('verified sync failed; cache unchanged') from None
        return synchronize(wallet,anchor,None,None,True,fault),True

def main():
    if len(sys.argv)>1 and sys.argv[1] in ('create','address','backup','restore','view-export','view-import'):f.main();return
    p=argparse.ArgumentParser(description='Experimental verified compressed pruned wallet sync')
    p.add_argument('command',choices=['sync','rescan','balance']);p.add_argument('--wallet',type=Path,required=True);p.add_argument('--password-file',type=Path,required=True)
    p.add_argument('--sync-mode',choices=['full','pruned'],default='full');p.add_argument('--rpc-port',type=int,default=48081)
    p.add_argument('--anchor-port',type=int);p.add_argument('--anchor-host',default='127.0.0.1');p.add_argument('--anchor-certificate',type=Path)
    p.add_argument('--data-port',type=int);p.add_argument('--data-host',default='127.0.0.1');p.add_argument('--data-certificate',type=Path);p.add_argument('--fallback',choices=['none','full'],default='none')
    p.add_argument('--test-crash-stage',choices=['during_scan','before_publish','after_publish'])
    args=p.parse_args();password=f.read_private(args.password_file).rstrip(b'\r\n');wallet=f.load(args.wallet,password)
    if args.sync_mode=='full':
        state=w.snapshot(args.rpc_port);print(json.dumps(w.balance(wallet,state,w.scan(wallet,state))));return
    if any(x is None for x in (args.anchor_port,args.anchor_certificate,args.data_port,args.data_certificate)):raise ValueError('explicit independently trusted anchor and pinned data endpoint required')
    import fcntl
    lock=os.open(str(args.wallet)+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);cachepath=Path(str(args.wallet)+'.phase5b-cache');cache=None;invalid_cache=False
        if cachepath.exists() and args.command!='rescan':
            try:cache=f.open_sealed(f.read_private(cachepath),password,CACHE_KIND);validate_cache(cache,wallet)
            except (ValueError,OSError,KeyError,TypeError):
                if args.fallback!='full':raise ValueError('invalid cache; use explicit full fallback or rescan')
                invalid_cache=True
        anchor=t.Endpoint(args.anchor_host,args.anchor_port,args.anchor_certificate,'anchor');data=t.Endpoint(args.data_host,args.data_port,args.data_certificate,'data')
        if invalid_cache:result=synchronize(wallet,anchor,None,None,True,args.test_crash_stage);used=True
        else:result,used=run(wallet,anchor,data,cache,args.command=='rescan',args.fallback,args.test_crash_stage)
        def fault(stage):
            if args.test_crash_stage==stage:os.kill(os.getpid(),signal.SIGKILL)
        f.write_private(cachepath,f.seal(result['cache'],password,CACHE_KIND),replace=True,fault=fault)
        print(json.dumps(dict(result['balance'],sync_mode='verified-pruned',fallback_full=used,trust='configured validating anchor; no independent global completeness/freshness',
            measurements=result['measurements'],downloaded_application_bytes=anchor.downloaded+data.downloaded,downloaded_tls_payload_bytes=anchor.wire_downloaded+data.wire_downloaded)))
    finally:os.close(lock)
if __name__=='__main__':
    try:main()
    except Exception:print('wallet sync failed; no verified result published',file=sys.stderr);sys.exit(1)
