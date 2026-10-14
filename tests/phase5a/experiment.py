"""Bounded real-chain research. Secret-bearing fixtures stay under native build/."""
from pathlib import Path
import importlib.util,json,os,sys,time,hashlib,subprocess,resource,statistics,copy,threading,socket,struct,zlib,shutil,tempfile
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
h=module('frozen_phase4_harness','tests/phase4/gates.py');g=h.g;w=h.w;f=h.f
s=module('isolated_sync','src/phase5a/sync.py')
OUT=ROOT/'docs/evidence/phase5a/wsl2';RUN=ROOT/'build/phase5a-workload';checks=[]
def check(name,ok=True):
    if not ok:raise AssertionError(name)
    checks.append(name);print('PASS',name,flush=True)
def write(name,value):
    OUT.mkdir(parents=True,exist_ok=True);(OUT/name).write_text(json.dumps(value,indent=2)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fixture():return json.loads((RUN/'public.json').read_text())
def wallets():
    password=f.read_private(RUN/'fixture.password');return {n:f.load(RUN/(n+'.wallet'),password) for n in 'ABC'}

def workload():
    if (RUN/'public.json').exists():raise ValueError('completed fixture already exists; use experiments')
    RUN.mkdir(parents=True,exist_ok=True);os.chmod(RUN,0o700);password=os.urandom(32).hex().encode()
    f.write_private(RUN/'fixture.password',password);ws={n:f.full() for n in 'ABC'}
    for n,v in ws.items():v['count']=4;f.save(RUN/(n+'.wallet'),v,password)
    addresses={n:f.address(v,0) for n,v in ws.items()};owners={}
    for n,v in ws.items():
        for i in range(4):owners[f.parse_address(f.address(v,i))[:2]]=n
    node=h.Node(RUN,'node');node.start();timestamp=int(time.time())-120*600;rewards={};intents={};checkpoint=None
    try:
        for i in range(100):
            timestamp+=120;node.mine(addresses['ABC'[i%3]],timestamp);rewards[node.status()['tip']]='ABC'[i%3]
        for i in range(300):
            sender='ABC'[i%3];state=w.snapshot(node.rpc)
            # Four distinct address slots, three recipients and change. Vary
            # requested recipient counts; exact receipts are independent truth.
            recipients=[dict(address=f.address(ws['ABC'[(i+j+1)%3]],j%4),amount=100000+i*10+j) for j in range(1+(i%4))]
            kwargs={}
            if i%25==0:
                scan=w.scan(ws[sender],state);available=[x for x in scan['owned'] if not x['spent'] and x['unlock']<=state['height']+1]
                if len(available)>=2:kwargs['sources']=[x['global_index'] for x in sorted(available,key=lambda x:x['amount'],reverse=True)[:2]]
            p=w.build(ws[sender],state,recipients=recipients,**kwargs);node.call('submit_tx',transaction=p['transaction'])
            intents[p['id']]=dict(sender=sender,sources=p['selected_sources'],fee=p['fee'],inputs=p['inputs'],outputs=p['outputs'],
                receipts=[dict(index=r['index'],amount=r['amount'],owner=owners[(r['D'],r['C'])]) for r in p['receipts']])
            timestamp+=120;node.mine(addresses['ABC'[i%3]],timestamp);rewards[node.status()['tip']]='ABC'[i%3]
            if i==279:checkpoint=w.snapshot(node.rpc)
            if i%10==9:print('WORKLOAD',i+1,'/300',flush=True)
        state=w.snapshot(node.rpc);blockids=node.call('chain')['chain'];model=[];spent=set()
        for identity in blockids[1:]:
            b=node.call('get_block',hash=identity);model.append(dict(owner=rewards[identity],amount=b['reward'],height=b['height'],coinbase=True))
            for raw in b['transactions']:
                r=next(r for r in state['chain'] if r['transaction']==raw);intent=intents[r['id']]
                for index in intent['sources']:
                    check('independent source '+str(index),index not in spent and model[index]['owner']==intent['sender']);spent.add(index)
                for receipt in sorted(intent['receipts'],key=lambda x:x['index']):model.append(dict(owner=receipt['owner'],amount=receipt['amount'],height=b['height'],coinbase=False))
        for i,x in enumerate(model):x['spent']=i in spent
        public=dict(state=state,checkpoint=checkpoint,model=model,intents=intents,final=node.status(),timestamp=timestamp,blockids=blockids)
        f.write_private(RUN/'public.json',f.canonical(public))
        check('real workload >=400 blocks,300 private tx,1000 outputs',state['height']>=400 and len(intents)>=300 and len(model)>1000)
        write('workload.json',dict(result='PASS',height=state['height'],tip=state['tip'],private_transactions=len(intents),outputs=len(model),
            shapes=sorted(set((x['inputs'],x['outputs']) for x in intents.values())),public_fixture_sha256=sha(RUN/'public.json'),
            checks=checks,commands=g.commands,ground_truth=[dict(index=i,**x) for i,x in enumerate(model)],
            fixture_policy='Encrypted random wallets/password 0600 under native ignored build/; no keys, addresses or raw helper streams in evidence'))
    finally:node.stop()

def stats(values):
    return dict(trials=len(values),median=statistics.median(values),min=min(values),max=max(values),
        mad=statistics.median(abs(x-statistics.median(values)) for x in values),samples=values)
def timer(fn):
    def cpu():
        usage=resource.getrusage(resource.RUSAGE_CHILDREN);total=time.process_time()+usage.ru_utime+usage.ru_stime
        for pid in Path('/proc/self/task/'+str(os.getpid())+'/children').read_text().split():
            try:
                fields=Path('/proc/'+pid+'/stat').read_text().split();total+=(int(fields[13])+int(fields[14]))/os.sysconf('SC_CLK_TCK')
            except FileNotFoundError:pass
        return total
    begin=time.perf_counter();before=cpu();r=fn()
    return r,(time.perf_counter()-begin)*1000,(cpu()-before)*1000
def key(r):return sorted(r['owned'],key=lambda x:x['global_index'])
def one_shot(q,exe):
    # GNU time gives per-process peak RSS/CPU, avoiding cumulative children RSS.
    p=subprocess.run(['/usr/bin/time','-f','RESOURCE %U %S %M',str(exe)],input=f.canonical(q)+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    if p.returncode:raise ValueError('scanner rejected')
    line=next(x for x in p.stderr.decode().splitlines() if x.startswith('RESOURCE '));_,u,k,rss=line.split()
    return json.loads(p.stdout),dict(cpu_ms=(float(u)+float(k))*1000,peak_rss_bytes=int(rss)*1024)

class Download:
    """Actual loopback framed transfer, optional paced throughput. No TLS claims."""
    def __init__(self,payload,rate=None):self.payload=payload;self.rate=rate
    def __call__(self):
        server=socket.socket();server.bind(('127.0.0.1',0));server.listen();port=server.getsockname()[1];errors=[]
        def serve():
            try:
                with server.accept()[0] as conn:
                    request=conn.recv(1)
                    if request!=b'A':raise ValueError('request')
                    data=struct.pack('>I',len(self.payload))+self.payload;begin=time.perf_counter()
                    for offset in range(0,len(data),8192):
                        conn.sendall(data[offset:offset+8192])
                        if self.rate:time.sleep(max(0,(min(offset+8192,len(data))/self.rate)-(time.perf_counter()-begin)))
            except Exception as e:errors.append(type(e).__name__)
            finally:server.close()
        thread=threading.Thread(target=serve);thread.start()
        with socket.create_connection(('127.0.0.1',port),timeout=60) as client:
            client.sendall(b'A');header=b''
            while len(header)<4:header+=client.recv(4-len(header))
            size=struct.unpack('>I',header)[0];data=bytearray()
            while len(data)<size:
                part=client.recv(min(65536,size-len(data)))
                if not part:raise ValueError('truncated transfer')
                data+=part
        thread.join();assert not errors;return bytes(data)

def reorg():
    data=fixture();ws=wallets();addresses={n:f.address(v,0) for n,v in ws.items()}
    A=h.Node(RUN,'node');timestamp=data['timestamp'];
    with tempfile.TemporaryDirectory(prefix='privacycoin-sync-reorg-') as temp:
        base=Path(temp);os.chmod(base,0o700);B=h.Node(base,'node-B');shutil.copytree(A.path,B.path)
        try:
            A.start();B.start();state=w.snapshot(A.rpc);check('fork starts at frozen workload',state['tip']==data['state']['tip'])
            payment=w.build(ws['A'],state,recipients=[dict(address=addresses['B'],amount=123456)])
            A.call('submit_tx',transaction=payment['transaction']);A.mine(addresses['A'],timestamp+120)
            losing=w.snapshot(A.rpc);cache=w.scan(ws['A'],losing);check('losing branch consumes owned inputs',any(x['spent'] for x in cache['owned'] if x['global_index'] in payment['selected_sources']))
            B.mine(addresses['C'],timestamp+120);B.mine(addresses['C'],timestamp+240);winning=w.snapshot(B.rpc)
            check('greater-work alternative excludes payment',payment['id'] not in {r['id'] for r in winning['chain']})
            A.stop(crash=True);A.start(peer=B);g.converge(A,B);check('real node greater-work convergence',A.status()==B.status())
            # Pool reinsertion is tentative: experiment uses canonical history only.
            current=w.snapshot(A.rpc);current['chain']=[r for r in current['chain'] if not r.get('pending')];current['pool']=[];current['pool_images']=[]
            with s.Worker() as worker:
                projection=worker.call(dict(op='project',chain=current['chain']))['chain'];anchor=s.manifest(current)
                records,images=s.authenticate(s.pack(projection,True),anchor,worker)
                for n,v in ws.items():
                    earlier=w.scan(v,losing);prefix=s.rollback(earlier,state['height']);prefix['scanned_outputs']=sum(1 for x in data['model'])
                    suffix=[r for r in records if r['height']>state['height']]
                    d=worker.call(dict(op='scan',**w.request(v,dict(current,chain=suffix)),offset=prefix['scanned_outputs']))
                    recovered=s.merge(prefix,d,images,current['height']);expected=w.scan(v,current)
                    check(n+' rollback/replacement exact owned state',key(recovered)==key(expected))
                    if n=='A':check('orphan spend restores inputs',all(not x['spent'] for x in recovered['owned'] if x['global_index'] in payment['selected_sources']))
            A.stop(crash=True);A.start();again=w.snapshot(A.rpc);check('node restart tip persists after reorg',again['tip']==winning['tip'])
            write('reorg.json',dict(result='PASS',checks=checks,check_count=len(checks),common_height=state['height'],losing_tip=losing['tip'],winning_tip=winning['tip'],final=A.status(),commands=g.commands,
                scope='Canonical owned state only; pending orphan reinsertion is frozen Phase 4 behavior and excluded from the research cache'))
        finally:A.stop();B.stop()

def experiments():
    data=fixture();state=data['state'];old=data['checkpoint'];ws=wallets();wallet=ws['A'];anchor=s.manifest(state);oldanchor=s.manifest(old)
    secrets=[f.read_private(RUN/'fixture.password')]
    for v in ws.values():secrets.extend(bytes.fromhex(v[k]) for k in ('seed','view'));secrets.extend(bytes.fromhex(x) for x in f.crypto('derive',v['seed'])[:2])
    q=dict(op='scan',**w.request(wallet,state));metrics={};resources={};cold=[];warm=[]
    baseline=w.helper(q)
    with s.Worker() as worker,s.Worker(reference=True) as reference:
        projected=worker.call(dict(op='project',chain=state['chain']))['chain'];pruned=s.pack(projected,True);full=s.pack(state['chain'])
        for label,payload in [('full',full),('pruned',pruned)]:
            records,images=s.authenticate(payload,anchor,worker);scan=worker.call(dict(q,chain=records,images=images))
            check(label+' exact full-wallet scan',key(scan)==key(baseline) and scan['scanned_outputs']==len(data['model']))
        for n,v in ws.items():
            request=dict(op='scan',**w.request(v,state));a=w.helper(request);b=worker.call(dict(request,chain=projected))
            check(n+' native exact full/pruned equality',key(a)==key(b))
            check(n+' independent ground truth',[(x['global_index'],x['amount'],x['spent']) for x in key(b)]==[(i,x['amount'],x['spent']) for i,x in enumerate(data['model']) if x['owner']==n])
            viewwallet=dict(v,authority='view',seed=None)
            av=w.helper(dict(op='scan',**w.request(viewwallet,state)));bv=worker.call(dict(op='scan',**w.request(viewwallet,dict(state,chain=projected))))
            check(n+' view-only exact and no spent authority',key(av)==key(bv) and all(x['spent'] is None and 'image' not in x for x in bv['owned']))
        scaling={}
        for height in (200,300,400):
            subset=[r for r in state['chain'] if r['height']<=height];request=dict(q,chain=subset,height=height,images=[i for r in subset for i in r.get('images',[])])
            times={'frozen':[],'candidate':[]}
            for trial in range(7):
                a,wall,_=timer(lambda:w.helper(request));times['frozen'].append(wall)
                b,wall,_=timer(lambda:worker.call(request));times['candidate'].append(wall)
                check('scaling height '+str(height)+' trial '+str(trial),key(a)==key(b))
            scaling[str(height)]=dict(outputs=a['scanned_outputs'],wall_ms={k:stats(v) for k,v in times.items()})
        for trial in range(7):
            # Alternate order to reduce thermal/order bias. Worker is persistent.
            operations=[('frozen_full',lambda:one_shot(q,w.HELPER)),('reference_warm_full',lambda:reference.call(q)),('candidate_cold',lambda:one_shot(q,s.HELPER)),
                ('candidate_warm_full',lambda:worker.call(q)),('candidate_warm_pruned',lambda:worker.call(dict(q,chain=projected)))]
            if trial%2:operations.reverse()
            for name,fn in operations:
                result,wall,cpu=timer(fn)
                if isinstance(result,tuple):result,usage=result;resources.setdefault(name,[]).append(usage)
                check(name+' trial '+str(trial)+' equality',key(result)==key(baseline))
                metrics.setdefault(name+'_wall_ms',[]).append(wall);metrics.setdefault(name+'_cpu_ms',[]).append(cpu);metrics.setdefault(name+'_native_ms',[]).append(result['scan_ms'])
            _,wall,_=timer(lambda:one_shot(dict(op='empty'),s.HELPER));cold.append(wall)
            _,wall,_=timer(lambda:worker.call(dict(op='empty')));warm.append(wall)
            viewwallet=dict(wallet,authority='view',seed=None)
            result,wall,cpu=timer(lambda:worker.call(dict(op='scan',**w.request(viewwallet,dict(state,chain=projected)))))
            metrics.setdefault('ownership_view_wall_ms',[]).append(wall);metrics.setdefault('ownership_view_native_ms',[]).append(result['scan_ms']);metrics.setdefault('ownership_view_cpu_ms',[]).append(cpu)
            _,wall,cpu=timer(lambda:f.load(RUN/'A.wallet',f.read_private(RUN/'fixture.password')))
            metrics.setdefault('warm_wallet_load_ms',[]).append(wall);metrics.setdefault('warm_wallet_load_cpu_ms',[]).append(cpu)
            fresh,wall,cpu=timer(lambda:json.loads(subprocess.check_output([sys.executable,str(ROOT/'scripts/phase5a/startup.py'),str(RUN/'A.wallet'),str(RUN/'fixture.password')])))
            metrics.setdefault('cold_wallet_start_wall_ms',[]).append(wall);metrics.setdefault('cold_wallet_load_ms',[]).append(fresh['load_ms']);metrics.setdefault('cold_wallet_cpu_ms',[]).append(cpu)
            resources.setdefault('cold_wallet',[]).append(dict(peak_rss_bytes=fresh['peak_rss_bytes']))
        # Practical incremental baseline scans only new full transactions, then
        # applies all authenticated public KIs to cached owned outputs.
        cached=w.scan(wallet,old);delta=[r for r in state['chain'] if r['height']>old['height']]
        pd=[r for r in projected if r['height']>old['height']];offset=cached['scanned_outputs'];dq=dict(q,chain=delta)
        for trial in range(7):
            def frozen_incremental():
                r=reference.call(dq)
                for x in r['owned']:x['global_index']+=offset
                return s.merge(cached,r,state['images'],state['height'])
            def candidate_incremental():
                r=worker.call(dict(dq,chain=pd,offset=offset));return s.merge(cached,r,state['images'],state['height'])
            for name,fn in [('incremental_full',frozen_incremental),('incremental_pruned',candidate_incremental)]:
                r,wall,cpu=timer(fn);check(name+' trial '+str(trial),key(r)==key(baseline));metrics.setdefault(name+'_wall_ms',[]).append(wall);metrics.setdefault(name+'_cpu_ms',[]).append(cpu)
            _,wall,cpu=timer(lambda:s.merge(dict(cached,owned=[dict(x) for x in cached['owned']]),dict(owned=[],scanned_outputs=0,undecodable_owned_outputs=0),state['images'],state['height']))
            metrics.setdefault('spent_update_ms',[]).append(wall)
        incremental_transport={};da=s.delta_anchor(anchor,old['height']);anchorbytes_delta=f.canonical(da)
        for name,payload in [('full',s.pack(delta)),('pruned',s.pack(pd,True))]:
            samples=[]
            for trial in range(7):
                def incremental_e2e():
                    received=Download(payload,1024*1024)();Download(anchorbytes_delta,1024*1024)()
                    records,images=s.authenticate(received,da,worker)
                    scanned=worker.call(dict(dq,chain=records,offset=offset))
                    return s.merge(cached,scanned,old['images']+images,state['height'])
                result,wall,cpu=timer(incremental_e2e);check(name+' incremental transport '+str(trial),key(result)==key(baseline));samples.append(wall)
            incremental_transport[name]=dict(application_download_bytes=len(payload)+len(anchorbytes_delta)+8,end_to_end_ms=stats(samples))
        def restore():
            recovered=f.restore(f.recovery(wallet));recovered['count']=wallet['count'];return worker.call(dict(op='scan',**w.request(recovered,dict(state,chain=projected))))
        for trial in range(7):
            result,wall,cpu=timer(restore);check('seed recovery trial '+str(trial),key(result)==key(baseline));metrics.setdefault('seed_recovery_scan_wall_ms',[]).append(wall);metrics.setdefault('seed_recovery_cpu_ms',[]).append(cpu)
        # End-to-end authentication + scanning with equal anchor download costs.
        # Anchor is independently supplied; streaming it here measures cost only.
        anchorbytes=f.canonical(anchor)
        transport={}
        for mode,payload in [('full',full),('pruned',pruned),('full_zlib',zlib.compress(full,6)),('pruned_zlib',zlib.compress(pruned,6))]:
            values=[]
            for trial in range(7):
                def end_to_end():
                    transferred=Download(payload,1024*1024)();Download(anchorbytes,1024*1024)()
                    if mode.endswith('_zlib'):transferred=zlib.decompress(transferred)
                    records,images=s.authenticate(transferred,anchor,worker)
                    return worker.call(dict(q,chain=records,images=images))
                result,wall,cpu=timer(end_to_end);check(mode+' E2E '+str(trial),key(result)==key(baseline));values.append(wall)
            transport[mode]=dict(application_download_bytes=len(payload)+len(anchorbytes)+8,request_bytes=2,end_to_end_ms=stats(values))
        # Persist only public index plus encrypted local ownership cache.
        f.write_private(RUN/'pruned.index',pruned,replace=True);f.write_private(RUN/'owned.phase5a-cache',f.seal(baseline,f.read_private(RUN/'fixture.password'),'phase5a-cache'),replace=True)
        restarted=f.open_sealed(f.read_private(RUN/'owned.phase5a-cache'),f.read_private(RUN/'fixture.password'),'phase5a-cache')
        check('encrypted cache restart exact',key(restarted)==key(baseline))
        # Rollback to authenticated common prefix, rescan replacement suffix.
        prefix=s.rollback(baseline,old['height']);prefix['scanned_outputs']=cached['scanned_outputs']
        check('rollback owned prefix exact',key(prefix)==key(cached) or [(x['global_index'],x['amount']) for x in key(prefix)]==[(x['global_index'],x['amount']) for x in key(cached)])
        negative={
            'omitted output transaction':s.pack(projected[:-1],True),
            'stale response':s.pack([r for r in projected if r['height']<=old['height']],True),
            'reordered data':s.pack(list(reversed(projected)),True),
            'incomplete history':s.pack(projected[1:],True),
            'truncated envelope':pruned[:-1],
            'trailing envelope':pruned+b'\0',
            'unknown version':pruned[:4]+b'\xff'+pruned[5:],
            'excessive record count':pruned[:6]+b'\xff'*4+pruned[10:],
        }
        for name,payload in negative.items():
            with s.Worker() as test:
                try:s.authenticate(payload,anchor,test)
                except ValueError:check('reject '+name)
                else:raise AssertionError('accepted '+name)
        # Same identity metadata, modified actual base/hash: C++ rejects.
        for label,field in [('modified transaction','transaction'),('modified proof hash','prunable_hash')]:
            changed=copy.deepcopy(projected);i=next(i for i,r in enumerate(changed) if not r['coinbase']);v=changed[i][field];changed[i][field]=('01' if v[:2]!='01' else '02')+v[2:]
            with s.Worker() as test:
                try:s.authenticate(s.pack(changed,True),anchor,test)
                except ValueError:check('reject '+label)
                else:raise AssertionError(label)
        for field,value in [('tip','00'*32),('height',state['height']+1),('profile','wrong-network'),('version',255)]:
            misleading=dict(anchor,**{field:value})
            try:s.checkpoint(misleading,anchor)
            except ValueError:check('reject misleading checkpoint '+field)
            else:raise AssertionError('misleading checkpoint accepted')
        # Explicit boundary: a stale but self-consistent anchor is accepted;
        # completeness/freshness relative to global chain is not established.
        stale=[r for r in projected if r['height']<=old['height']]
        s.authenticate(s.pack(stale,True),oldanchor,worker);check('self-consistent stale history needs independent fresh anchor')
        result=dict(result='PASS',checks=checks,check_count=len(checks),height=state['height'],outputs=len(data['model']),
            metrics={k:stats(v) for k,v in metrics.items()},cold_process_start_ms=stats(cold),warm_worker_request_ms=stats(warm),resources=resources,
            scaling=scaling,transport=transport,incremental_transport=incremental_transport,incremental_bytes=dict(full=len(s.pack(delta)),pruned=len(s.pack(pd,True)),manifest=len(f.canonical(s.delta_anchor(anchor,old['height'])))),
            storage=dict(pruned_index_bytes=(RUN/'pruned.index').stat().st_size,encrypted_owned_cache_bytes=(RUN/'owned.phase5a-cache').stat().st_size,
                full_index_bytes=len(full),anchor_bytes=len(anchorbytes)),
            workload_sha256=sha(RUN/'public.json'),artifacts={str(p.relative_to(ROOT)):sha(p) for p in [s.HELPER,w.HELPER,g.NODE]},
            trust='Ordered manifest independently supplied by fully validating local node; no independent SPV/global completeness or freshness proof',
            worker_memory_status=[line for line in Path('/proc/'+str(worker.p.pid)+'/status').read_text().splitlines() if line.startswith(('VmRSS:','VmHWM:'))],
            cache_temperature='Process cold/warm only; OS filesystem page cache not flushed',additional_packages_installed=[])
        encoded=f.canonical(result)
        for secret in secrets:check('no ephemeral secret in evidence '+hashlib.sha256(secret).hexdigest()[:8],secret not in encoded and secret.hex().encode() not in encoded)
        result['checks']=checks;result['check_count']=len(checks);write('experiment.json',result)
        print('EXPERIMENT COMPLETE',len(checks),flush=True)

if __name__=='__main__':
    action=sys.argv[1]
    try:{'workload':workload,'experiments':experiments,'reorg':reorg}[action]()
    except Exception as e:
        write('failure-'+action+'-'+str(time.time_ns())+'.json',dict(result='FAIL',stage=action,error_type=type(e).__name__,passed_checks=checks))
        raise
