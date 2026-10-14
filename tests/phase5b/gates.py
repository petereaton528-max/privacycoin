"""Live TLS/adversarial/cache gates. Disposable secrets never become evidence."""
from pathlib import Path
import importlib.util,json,os,shutil,subprocess,sys,tempfile,time,hashlib,zlib,copy
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
h=module('frozen_harness','tests/phase4/gates.py');v=module('verified_wallet','src/phase5b/wallet.py');s=module('tls_sidecar','src/phase5b/server.py')
w=v.w;f=v.f;t=v.t;h.g.NODE=ROOT/'build/monero-linux/phase5b/privacycoin-sync-devnet'
OUT=ROOT/'docs/evidence/phase5b/wsl2';checks=[]
class LargeFixtureNode(h.Node):
    """Allow bounded full revalidation at larger scales; no acceptance change."""
    def start(self,*args,**kwargs):
        begin=time.perf_counter()
        try:
            try:return super().start(*args,**kwargs)
            except AssertionError as error:
                if str(error)!='startup timeout':raise
            while time.perf_counter()-begin<180:
                if self.p.poll() is not None:
                    self.log.seek(0);raise AssertionError('large fixture node startup failed: '+self.log.read().decode(errors='replace')[-2000:])
                try:self.call('status');return (time.perf_counter()-begin)*1000
                except (ValueError,OSError):time.sleep(.1)
            raise AssertionError('large fixture startup exceeded 180 seconds')
        except BaseException:self.stop(crash=True);raise
h.Node=LargeFixtureNode
def check(name,condition=True):
    if not condition:raise AssertionError(name)
    checks.append(name);print('PASS',name,flush=True)
def reject(name,fn):
    try:fn()
    except (ValueError,OSError,KeyError,TypeError,OverflowError):check(name);return
    raise AssertionError(name+' unexpectedly accepted')
def cert(base):
    key=base/'tls.key';certificate=base/'tls.crt'
    subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-keyout',str(key),'-out',str(certificate),'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    key.chmod(0o600);return certificate,key
def endpoint(server,certificate,role):return t.Endpoint('127.0.0.1',server.server_address[1],certificate,role)
def canonical(result):return sorted(result['owned'],key=lambda x:(x['pending'],x['global_index']))
def compare(label,wallet,node,anchor,data,cache=None,force=False):
    state=w.snapshot(node.rpc);full=w.scan(wallet,state);result,used=v.run(wallet,anchor,data,cache,force)
    check(label+' exact recovered owned records',canonical(result['scan'])==canonical(full))
    check(label+' exact balances',result['balance']==w.balance(wallet,state,full))
    check(label+' no fallback',not used);return result
def cli(wallet,password,anchor,data,certificate,**flags):
    cmd=[sys.executable,str(ROOT/'scripts/phase5b/privacycoin-wallet'),'sync','--wallet',str(wallet),'--password-file',str(password),'--sync-mode','pruned',
        '--anchor-port',str(anchor.server_address[1]),'--data-port',str(data.server_address[1]),'--anchor-certificate',str(certificate[0]),'--data-certificate',str(certificate[1])]
    for k,value in flags.items():cmd+=['--'+k.replace('_','-'),str(value)]
    h.g.commands.append(cmd)
    return subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
def main():
    OUT.mkdir(parents=True,exist_ok=True);started=time.time();servers=[];nodes=[];measurements={}
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase5b-') as temp:
        base=Path(temp);base.chmod(0o700);fixture=ROOT/'build/phase5a-workload'
        password=f.read_private(fixture/'fixture.password').rstrip(b'\r\n');pwd=base/'fixture.password';f.write_private(pwd,password)
        wallets={n:f.load(fixture/(n+'.wallet'),password) for n in 'ABC'}
        certificate,key=cert(base);datadir=base/'data-tls';datadir.mkdir(mode=0o700);datacert,datakey=cert(datadir);certificates=(certificate,datacert)
        try:
            A=h.Node(base,'anchor-node');B=h.Node(base,'data-node');nodes=[A,B]
            shutil.copytree(fixture/'node',A.path);shutil.copytree(fixture/'node',B.path)
            measurements['anchor_startup_ms']=A.start(ttl=1);measurements['data_startup_ms']=B.start(ttl=1);time.sleep(1.1)
            A.stop();A.start(ttl=3600)
            check('independent validating databases identical checkpoint',A.status()==B.status())
            anchor,at=s.start(A.rpc,'anchor',base/'anchor-index/pages.sqlite',certificate,key);servers.append((anchor,at))
            data,dt=s.start(B.rpc,'data',base/'data-index/pages.sqlite',datacert,datakey);servers.append((data,dt))
            ae=endpoint(anchor,certificate,'anchor');de=endpoint(data,datacert,'data')
            reject('data certificate cannot impersonate anchor',lambda:endpoint(data,certificate,'anchor').call('snapshot_id'))
            reject('shared anchor data certificate refused',lambda:v.run(wallets['A'],ae,endpoint(anchor,certificate,'data')))
            results={n:compare('initial '+n,value,A,ae,de) for n,value in wallets.items()}
            view=f.view_export(wallets['A']);vr=compare('view only',view,A,ae,de)
            unrelated=f.full(count=4);empty=compare('unrelated wallet',unrelated,A,ae,de);check('unrelated wallet detects no outputs',not empty['scan']['owned'])
            sparse=dict(wallets['A'],count=128);compare('sparse 128-address horizon',sparse,A,ae,de)
            check('view authority never gets spend status',vr['balance']['balance'] is None and all(x['spent'] is None and 'image' not in x for x in vr['scan']['owned']))
            reject('view only cannot build spend',lambda:w.build(view,w.snapshot(A.rpc),f.address(wallets['B'],0),1000000))
            restored=f.restore(f.recovery(wallets['A']))
            compare('seed restore',restored,A,ae,de)
            cached=compare('unchanged incremental',wallets['A'],A,ae,de,results['A']['cache'])
            check('unchanged cache scans zero outputs',cached['measurements']['new_outputs']==0)
            compare('forced full rescan',wallets['A'],A,ae,de,cached['cache'],True)
            # Every mutation traverses actual TLS, bounded decompression and the
            # real native hash/parser/scanner before any cache publication.
            cases={}
            def malicious(case):
                def mutate(q,header,payload):
                    header=dict(header)
                    if case=='stale-tip':header['tip']='00'*32
                    elif case=='wrong-height':header['height']+=1
                    elif case=='incomplete-range':header['next']+=1
                    elif case=='replayed-checkpoint':header['nonce']='00'*32
                    elif case=='unknown-version':header['version']=2
                    elif case=='wrong-profile':header['profile']='other'
                    elif case=='corrupted-compression':return header,payload[:-1]
                    elif case=='compression-bomb':return header,zlib.compress(b'x'*(t.MAX_PLAIN+1))
                    elif case=='trailing-compressed-stream':return header,payload+zlib.compress(b'x')
                    else:
                        records=t.p.unpack(t.inflate(payload));records=copy.deepcopy(records)
                        if case=='omitted-output-record':records.pop(0)
                        elif case=='missing-private-transaction':
                            i=next((i for i,r in enumerate(records) if not r['coinbase']),None)
                            if i is None:return header,payload
                            records.pop(i)
                        elif case=='reordered':records.reverse()
                        elif case=='duplicate':records.append(records[-1])
                        elif case=='modified-body':records[0]['transaction']='00'+records[0]['transaction'][2:]
                        elif case=='modified-prunable-hash':records[-1]['prunable_hash']='ff'*32
                        elif case=='block-metadata':records[0]['height']+=1
                        elif case=='coinbase-metadata':records[0]['coinbase']=not records[0]['coinbase']
                        payload=zlib.compress(t.p.pack(records,True))
                    return header,payload
                return mutate
            for case in ('omitted-output-record','missing-private-transaction','incomplete-range','stale-tip','wrong-height','reordered','corrupted-compression','block-metadata','coinbase-metadata','replayed-checkpoint','modified-body','modified-prunable-hash','duplicate','unknown-version','wrong-profile','compression-bomb','trailing-compressed-stream'):
                data.mutate=malicious(case)
                reject('malicious data '+case,lambda:v.run(wallets['A'],ae,de,None,True));cases[case]='REJECTED'
            data.mutate=malicious('omitted-output-record')
            fallback,used=v.run(wallets['A'],ae,de,None,True,'full')
            check('explicit fallback uses trusted full source',used and fallback['balance']==results['A']['balance'])
            data.mutate=None
            # Authenticated anchor data is trusted for chain choice, but raw
            # manifest corruption, ordering and stale bound metadata fail.
            def bad_anchor(q,header,payload):
                body=t.decode(t.inflate(payload))
                if q['command']=='sync_manifest':body['blocks'][0]['block']='00'+body['blocks'][0]['block'][2:]
                return header,zlib.compress(f.canonical(body))
            anchor.mutate=bad_anchor;reject('corrupted trusted block manifest',lambda:v.run(wallets['A'],ae,de));anchor.mutate=None
            wrong=base/'wrong';wrong.mkdir();wrongcert,_=cert(wrong)
            reject('TLS untrusted endpoint certificate',lambda:t.Endpoint('127.0.0.1',data.server_address[1],wrongcert,'data').call('history',offset=1,count=32,tip=A.status()['tip']))
            badpin=endpoint(data,datacert,'data');badpin.certificate_sha256=b'\0'*32
            reject('TLS exact leaf pin mismatch',lambda:badpin.call('history',offset=1,count=32,tip=A.status()['tip']))
            for keyname,value in [('version',2),('profile','other'),('authority','view'),('wallet_id','00'*32),('count',999),('schemes',[2,1,1])]:
                bad=copy.deepcopy(cached['cache']);bad[keyname]=value;reject('cache binding '+keyname,lambda bad=bad:v.validate_cache(bad,wallets['A']))
            local=base/'A.wallet';f.save(local,wallets['A'],password)
            p=cli(local,pwd,anchor,data,certificates);check('real CLI first sync',p.returncode==0)
            cachepath=Path(str(local)+'.phase5b-cache');original=cachepath.read_bytes()
            check('encrypted cache restricts permissions',cachepath.stat().st_mode&0o777==0o600)
            p=cli(local,pwd,anchor,data,certificates);check('real CLI wallet restart',p.returncode==0 and json.loads(p.stdout)['measurements']['new_outputs']==0)
            for stage in ('during_scan','before_publish','after_publish'):
                # Rescan is needed to exercise during_scan on unchanged chain.
                cachepath.unlink();p=cli(local,pwd,anchor,data,certificates,test_crash_stage=stage)
                check('SIGKILL cache '+stage,p.returncode==-9)
                check('atomic cache '+stage,cachepath.exists()==(stage=='after_publish'))
                p=cli(local,pwd,anchor,data,certificates);check('restart after '+stage,p.returncode==0 and json.loads(p.stdout)['balance']==results['A']['balance']['balance'])
            cachepath.write_bytes(original[:-9]);p=cli(local,pwd,anchor,data,certificates);check('corrupt encrypted cache fail closed',p.returncode!=0 and cachepath.read_bytes()==original[:-9])
            p=cli(local,pwd,anchor,data,certificates,fallback='full');check('corrupt cache explicit full recovery',p.returncode==0 and json.loads(p.stdout)['fallback_full'])
            data.mutate=malicious('omitted-output-record');cachepath.unlink();p=cli(local,pwd,anchor,data,certificates);check('malicious CLI publishes no cache',p.returncode!=0 and not cachepath.exists());data.mutate=None
            # Append/pending/reorg are real accepted private transactions.
            payment=w.build(wallets['A'],w.snapshot(A.rpc),f.address(wallets['B'],3),1000000000,fee=1000000)
            A.call('submit_tx',transaction=payment['transaction'])
            pending=compare('pending private payment',wallets['A'],A,ae,de,results['A']['cache'])
            check('pending payment really reserves spendable inputs',pending['balance']['reserved_inputs']>0 and pending['balance']['pending_outgoing']>0)
            compare('pending recipient',wallets['B'],A,ae,de,results['B']['cache'])
            timestamp=int(time.time())-240;A.mine(f.address(wallets['C'],0),timestamp)
            data.mutate=None;reject('data source behind anchored append',lambda:v.run(wallets['A'],ae,de,pending['cache']))
            anchor.service.port=B.rpc
            stale,used=v.run(wallets['A'],ae,de)
            check('documented boundary honest-but-stale configured anchor accepted',not used and stale['state']['height']<A.status()['height'])
            anchor.service.port=A.rpc
            B.stop();B.start(peer=A,ttl=3600);h.g.converge(A,B)
            appended=compare('private append',wallets['A'],A,ae,de,pending['cache'])
            check('append scans suffix only',0<appended['measurements']['new_outputs']<appended['scan']['scanned_outputs'])
            A.stop(crash=True);A.start(ttl=3600)
            compare('node crash restart',wallets['A'],A,ae,de,appended['cache'])
            # Two independent canonical branches; the losing spend disappears.
            B.stop();A.stop();branch=base/'branch';shutil.copytree(A.path,branch)
            A.start(ttl=3600)
            pa=w.build(wallets['A'],w.snapshot(A.rpc),f.address(wallets['B'],0),2000000000,fee=1000000)
            A.call('submit_tx',transaction=pa['transaction']);A.mine(f.address(wallets['A'],0),timestamp+120)
            B.path=branch;B.start(ttl=3600);B.mine(f.address(wallets['C'],0),timestamp+120);B.mine(f.address(wallets['C'],0),timestamp+240)
            # Data source must match A until it switches to B's winning chain.
            data.service.port=A.rpc
            losing=compare('losing spend branch',wallets['A'],A,ae,de,appended['cache'])
            A.stop();A.start(peer=B,ttl=3600);h.g.converge(A,B);data.service.port=B.rpc
            winning=compare('greater work rollback replacement',wallets['A'],A,ae,de,losing['cache'])
            check('reorg prefix rolls back',winning['measurements']['common_height']<losing['state']['height'])
            for n in 'BC':compare('reorg '+n,wallets[n],A,ae,de,results[n]['cache'])
            check('TLS accounting includes more than framed application bytes',ae.wire_downloaded+de.wire_downloaded>ae.downloaded+de.downloaded)
            measurements.update(application_download_bytes=ae.downloaded+de.downloaded,downloaded_tls_payload_bytes=ae.wire_downloaded+de.wire_downloaded,server_preprocess_ms=sum(ae.preprocess+de.preprocess),data_cache_hits=sum(de.hits),tls_ciphers=sorted(set(ae.tls+de.tls)),initial_height=results['A']['state']['height'],initial_outputs=results['A']['scan']['scanned_outputs'])
            report=dict(result='PASS',checks=checks,total_checks=len(checks),adversarial=cases,measurements=measurements,commands=h.g.commands,elapsed_seconds=time.time()-started,trust='chain choice and freshness depend on configured validating anchor',live_environment='WSL2 Ubuntu; loopback TLS, not actual remote network')
            forbidden=[password,f.read_private(key),f.read_private(datakey)]
            for value in list(wallets.values())+[unrelated]:
                forbidden.extend(bytes.fromhex(value[k]) for k in ('seed','view'));forbidden.extend(bytes.fromhex(x) for x in f.crypto('derive',value['seed'])[:2])
            raw=f.canonical(report)
            check('actual generated secret encodings absent from evidence',not any(value in raw or value.hex().encode() in raw for value in forbidden))
            report['total_checks']=len(checks)
            (OUT/'live-gates.json').write_text(json.dumps(report,indent=2)+'\n')
        finally:
            for server,thread in servers:server.shutdown();thread.join();server.server_close();server.service.close()
            for node in nodes:node.stop(crash=True)
if __name__=='__main__':
    try:main()
    except Exception as error:
        OUT.mkdir(parents=True,exist_ok=True);(OUT/('failure-'+str(time.time_ns())+'.json')).write_text(json.dumps(dict(result='FAIL',error_type=type(error).__name__,checks=checks),indent=2)+'\n');raise
