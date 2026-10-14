"""Controlled stage timing and ablation; never record arguments or secret locals."""
from pathlib import Path
import importlib.util,json,time,tempfile,shutil,hashlib,zlib,cProfile,pstats,tracemalloc,statistics,struct
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('profile_benchmark',ROOT/'tests/phase5b/benchmark.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
g=b.g;v=g.v;t=g.t;w=g.w;f=g.f;s=g.s;OUT=ROOT/'docs/evidence/phase5b-r/wsl2'
class Trace:
    def __init__(self):self.spans={};self.undo=[]
    def wrap(self,obj,name,label):
        original=getattr(obj,name)
        def wrapped(*args,**kwargs):
            start=time.perf_counter();cpu=time.thread_time()
            try:return original(*args,**kwargs)
            finally:
                group=label+':'+args[1]['op'] if label=='native_pipe_all_operations' else (label+':'+args[1] if label=='server_database_rpc' else label)
                row=self.spans.setdefault(group,dict(calls=0,wall_ms=0,cpu_ms=0));row['calls']+=1;row['wall_ms']+=(time.perf_counter()-start)*1000;row['cpu_ms']+=(time.thread_time()-cpu)*1000
        setattr(obj,name,wrapped);self.undo.append((obj,name,original))
    def close(self):
        for obj,name,original in reversed(self.undo):setattr(obj,name,original)

def main(label):
    assert label in ('before','after');OUT.mkdir(parents=True,exist_ok=True)
    source_hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('src/phase5b/wallet.py','src/phase5b/server.py','src/phase5b/transport.py','src/phase5b/crypto.cpp','tests/phase5b/profile.py')}
    if label=='before':
        import subprocess
        for name in ('src/phase5b/wallet.py','src/phase5b/server.py'):
            raw=subprocess.check_output(['git','--git-dir='+str(ROOT/'.phase0-git'),'show','731d2d8a5396cbe8efe996c6ae79dcd528dfb795:'+name])
            assert (ROOT/name).read_bytes().replace(b'\r\n',b'\n')==raw.replace(b'\r\n',b'\n'),'before profile requires original WIP implementation'
    fixture=json.loads((b.RUN/'scale-6536.json').read_text())
    with tempfile.TemporaryDirectory(prefix='phase5br-profile-') as temp:
        base=Path(temp);base.chmod(0o700);cert,key=g.cert(base);directory=base/'data-tls';directory.mkdir(mode=0o700);dc,dk=g.cert(directory)
        node=g.h.Node(base,'node');shutil.copytree(b.BENCH/'scale-6536-node',node.path);servers=[]
        try:
            startup=node.start(ttl=1);time.sleep(1.1)
            anchor,at=s.start(node.rpc,'anchor',base/'a-index/pages.sqlite',cert,key);data,dt=s.start(node.rpc,'data',base/'d-index/pages.sqlite',dc,dk);servers=[(anchor,at),(data,dt)]
            password=f.read_private(b.RUN/'fixture.password');wallet=f.load(b.RUN/'A.wallet',password);state=w.snapshot(node.rpc);full=w.scan(wallet,state);fingerprint=hashlib.sha256(f.canonical(g.canonical(full))).hexdigest();balance=w.balance(wallet,state,full)
            ae=g.endpoint(anchor,cert,'anchor');de=g.endpoint(data,dc,'data');initial,_=v.run(wallet,ae,de);assert g.canonical(initial['scan'])==g.canonical(full)
            # Timed end-to-end repetitions are uninstrumented, isolated children.
            for server,_ in servers:server.rate=1024*1024
            samples=[b.measure('pruned',b.RUN/'A.wallet',b.RUN/'fixture.password',(cert,dc),anchor,data,node) for _ in range(7)]
            assert all(x['owned_fingerprint']==fingerprint and x['balance']==balance for x in samples)
            for server,_ in servers:server.rate=None
            trace=Trace()
            for obj,name,group in [(w,'request','wallet_request_and_spend_derivation'),(f,'crypto','foundation_helper_process'),(f,'canonical','python_canonical_serialization'),(t,'inflate','decompression'),(t,'decode','json_decode'),(t,'read','tls_response_reads_including_server_wait'),(t.p.Worker,'call','native_pipe_all_operations'),(v,'validate_cache','cache_schema_validation'),(s.Service,'response','server_response_including_rpc_sqlite_compression'),(s.w,'rpc','server_database_rpc'),(zlib,'compress','compression_all_threads')]:trace.wrap(obj,name,group)
            class Cursor:
                def __init__(self,cursor):self.cursor=cursor
                def fetchone(self):return self.cursor.fetchone()
            class Database:
                def __init__(self,db):self.db=db
                def execute(self,*args):return Cursor(self.db.execute(*args))
                def commit(self):return self.db.commit()
                def __getattr__(self,name):return getattr(self.db,name)
            trace.wrap(Database,'execute','sqlite_execute');trace.wrap(Database,'commit','sqlite_commit');trace.wrap(Cursor,'fetchone','sqlite_fetchone')
            original_db=data.service.db;data.service.db=Database(original_db)
            def node_io():
                if not Path('/proc/self/io').exists():return None
                return {k:int(value) for k,value in (row.split(':') for row in Path('/proc/'+str(node.p.pid)+'/io').read_text().splitlines())}
            io_before=node_io()
            class Context:
                def __init__(self,context):self.context=context
                def wrap_socket(self,*args,**kwargs):
                    start=time.perf_counter();result=self.context.wrap_socket(*args,**kwargs);row=trace.spans.setdefault('tls_handshake',dict(calls=0,wall_ms=0,cpu_ms=0));row['calls']+=1;row['wall_ms']+=(time.perf_counter()-start)*1000;return result
            ea=g.endpoint(anchor,cert,'anchor');ed=g.endpoint(data,dc,'data');ea.context=Context(ea.context);ed.context=Context(ed.context)
            profiler=cProfile.Profile();profiler.enable();start=time.perf_counter()
            try:profiled,_=v.run(wallet,ea,ed)
            finally:profiled_ms=(time.perf_counter()-start)*1000;profiler.disable();trace.close();data.service.db=original_db
            io_after=node_io();io_delta={key:io_after[key]-value for key,value in io_before.items()} if io_before is not None else dict(status='PLATFORM_UNAVAILABLE',reason='This WSL kernel does not expose /proc/self/io or process IO counters; not reported as zero disk IO.')
            assert g.canonical(profiled['scan'])==g.canonical(full)
            functions=[]
            for (filename,line,name),(cc,nc,tt,ct,callers) in pstats.Stats(profiler).stats.items():
                functions.append(dict(file=filename,line=line,function=name,calls=nc,self_ms=tt*1000,inclusive_ms=ct*1000))
            functions.sort(key=lambda x:x['inclusive_ms'],reverse=True)
            # Causal ablation: derive identical scan authority once per sync.
            original=w.request;derive_start=time.perf_counter();authority=original(wallet,{});initial_authority_ms=(time.perf_counter()-derive_start)*1000
            def once(subject,substate,full=True):
                assert subject is wallet and full;return dict(authority,**substate)
            ablation=[]
            try:
                w.request=once
                for i in range(7):
                    start=time.perf_counter();result,_=v.run(wallet,g.endpoint(anchor,cert,'anchor'),g.endpoint(data,dc,'data'));elapsed=(time.perf_counter()-start)*1000
                    assert g.canonical(result['scan'])==g.canonical(full) and result['balance']==balance;ablation.append(elapsed)
            finally:w.request=original
            # Separate local control, same lifecycle, no tracing, with/without
            # repeated derivation. Never compare traced timing to child timings.
            ordinary=[]
            for i in range(7):
                start=time.perf_counter();result,_=v.run(wallet,g.endpoint(anchor,cert,'anchor'),g.endpoint(data,dc,'data'));ordinary.append((time.perf_counter()-start)*1000);assert result['balance']==balance
            manifest_ablation={}
            if hasattr(anchor.service,'manifests'):
                pairs=[]
                for i in range(7):
                    pair={}
                    for mode in ('forced_miss','warm_hit'):
                        if mode=='forced_miss':anchor.service.manifests.clear();anchor.service.manifest_bytes=0
                        start=time.perf_counter();result,_=v.run(wallet,g.endpoint(anchor,cert,'anchor'),g.endpoint(data,dc,'data'));pair[mode]=(time.perf_counter()-start)*1000
                        assert g.canonical(result['scan'])==g.canonical(full) and result['balance']==balance
                    pairs.append(pair)
                manifest_ablation=dict(pairs=pairs,forced_miss_ms=b.stats([p['forced_miss'] for p in pairs]),warm_hit_ms=b.stats([p['warm_hit'] for p in pairs]),scope='Paired same-code cache miss/hit, data index warm, real snapshot checked in both. Miss precedes hit to populate cache; not OS/disk cold.',exact_state_equivalence=True)
            cache=initial['cache'];cachepath=base/'cache.phase5b-cache';cache_ops={name:[] for name in ('seal','atomic_write_fsync','read','decrypt','validate','json_serialize','json_deserialize')}
            for i in range(7):
                def timed(name,operation):
                    start=time.perf_counter();result=operation();cache_ops[name].append((time.perf_counter()-start)*1000);return result
                raw=timed('seal',lambda:f.seal(cache,password,v.CACHE_KIND));timed('atomic_write_fsync',lambda:f.write_private(cachepath,raw,replace=True));raw=timed('read',lambda:f.read_private(cachepath));opened=timed('decrypt',lambda:f.open_sealed(raw,password,v.CACHE_KIND));timed('validate',lambda:v.validate_cache(opened,wallet));plain=timed('json_serialize',lambda:f.canonical(cache));timed('json_deserialize',lambda:json.loads(plain))
            # Allocation tracing is a separate experiment; native allocations
            # are not mislabeled as Python allocations.
            tracemalloc.start();allocated,_=v.run(wallet,g.endpoint(anchor,cert,'anchor'),g.endpoint(data,dc,'data'));current,peak=tracemalloc.get_traced_memory();allocation_rows=[dict(file=str(x.traceback[0].filename),bytes=x.size,blocks=x.count) for x in tracemalloc.take_snapshot().statistics('filename')[:10]];tracemalloc.stop();assert g.canonical(allocated['scan'])==g.canonical(full)
            # Exact download-only ablations on the same canonical public data.
            with t.p.Worker() as worker:projected=worker.call(dict(op='project',chain=state['chain']))['chain']
            byte_rows=[]
            for offset in range(1,state['height']+1,32):
                records=[r for r in projected if offset<=r['height']<offset+32];old=t.p.pack(records,True)
                compact=bytearray(b'PC5R'+struct.pack('>I',len(records)))
                for r in records:
                    body=bytes.fromhex(r['transaction']);compact+=struct.pack('>QBI',r['height'],int(r['coinbase']),len(body))+body+bytes.fromhex(r['prunable_hash'])
                manifest=w.rpc(node.rpc,'sync_manifest',offset=offset,count=32,**{k:w.rpc(node.rpc,'snapshot_id')[k] for k in ('tip','revision','instance')})
                original_manifest=f.canonical(manifest)
                for record in manifest['blocks']:record.pop('id')
                byte_rows.append(dict(old_data=len(zlib.compress(old,6)),without_duplicate_record_ids=len(zlib.compress(compact,6)),old_manifest=len(zlib.compress(original_manifest,6)),without_duplicate_block_ids=len(zlib.compress(f.canonical(manifest),6))))
            report=dict(result='PASS',label=label,outputs=6536,height=state['height'],owned_fingerprint=fingerprint,reference_balance=balance,node_startup_ms=startup,untraced_1MiB_samples=samples,untraced_1MiB_summary=b.summary(samples),profiled_ms=profiled_ms,stage_spans=trace.spans,stage_accounting='Nested inclusive times overlap; do not sum. Read includes server wait; server spans cover warm index/RPC. CPU is current-thread only. TLS handshake is wall time.',python_profile=functions[:45],derivation_ablation=dict(ordinary_local_ms=b.stats(ordinary),once_local_ms=b.stats(ablation),initial_authority_ms=initial_authority_ms,scope='Causal ablation excludes one initial authority derivation from each once-local sample; final integrated measurements must include it.',exact_state_equivalence=True),cache_operations_ms={name:b.stats(values) for name,values in cache_ops.items()},allocation=dict(python_current_bytes=current,python_peak_bytes=peak,top_files=allocation_rows,native_allocation_counts='NOT_INSTRUMENTED; aggregate RSS recorded in isolated samples'),redundant_field_byte_ablation=dict(totals={name:sum(row[name] for row in byte_rows) for name in byte_rows[0]},scope='Payload compression only, excludes unchanged frame/nonce/TLS overhead. Prediction, not end-to-end acceptance evidence'),database='Real fully validating native LMDB node; read RPC stages include in-memory ledger serving, not isolated disk IO. SQLite query time is NOT_SEPARATELY_INSTRUMENTED in this trace. Cache persistence measured separately.',network='Paced loopback only')
            report['native_node_io_delta']=io_delta
            report['source_sha256']=source_hashes
            report['manifest_cache_ablation']=manifest_ablation
            report['database']='Real fully validating native LMDB node serves loaded chain state in RAM. RPC stages include memory copies, serialization and IPC, not isolated disk reads. Warm SQLite execute/fetch measured separately; no warm commit is expected. Native process IO deltas and cache persistence are separate controls.'
            (OUT/('profile-'+label+'.json')).write_text(json.dumps(report,indent=2)+'\n');print('PROFILE',label,'request',trace.spans.get('wallet_request_and_spend_derivation'),'ablation',report['derivation_ablation'],'byte_ablation',report['redundant_field_byte_ablation']['totals'],flush=True)
        finally:
            for server,thread in servers:server.shutdown();thread.join();server.server_close();server.service.close()
            node.stop(crash=True)
