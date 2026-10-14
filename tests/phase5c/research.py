"""Bounded loopback attacks against unchanged native artifacts. No public traffic."""
from pathlib import Path
import importlib.util,json,socket,socketserver,struct,threading,time,tempfile,hashlib,resource,os
ROOT=Path(__file__).resolve().parents[2]
def module(name,p):
    s=importlib.util.spec_from_file_location(name,ROOT/p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
h=module('research_h','tests/phase4/gates.py');v=module('research_v','src/phase5b/wallet.py')
h.g.NODE=ROOT/'build/monero-linux/phase5b/privacycoin-sync-devnet'
checks=[];trials=[];commands=[]
def check(name,ok):
    assert ok,name
    checks.append(name);print('PASS',name,flush=True)
def read(s,n):
    b=b''
    while len(b)<n:
        part=s.recv(n-len(b))
        if not part:raise OSError('EOF')
        b+=part
    return b
class Proxy(socketserver.ThreadingTCPServer):
    daemon_threads=True;allow_reuse_address=True
    def __init__(self,target):
        super().__init__(('127.0.0.1',0),Handler);self.target=target;self.mode='stale';self.requests=0;self.bytes=0
        self.p2p=self.server_address[1];self.delay=0;threading.Thread(target=self.serve_forever,daemon=True).start()
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(2);head=read(self.request,20);q=json.loads(read(self.request,struct.unpack('!I',head[16:])[0]));self.server.requests+=1
            if self.server.mode=='honest':
                time.sleep(self.server.delay)
                with socket.create_connection(('127.0.0.1',self.server.target.p2p),timeout=3) as s:
                    body=json.dumps(q).encode();s.sendall(head[:16]+struct.pack('!I',len(body))+body);rh=read(s,20);body=read(s,struct.unpack('!I',rh[16:])[0]);self.request.sendall(rh+body);self.server.bytes+=len(rh)+len(body);return
            r={k:q[k] for k in ('network','genesis','profile')}
            if q['command']=='inventory':
                r['blocks']=[q['genesis']]
                # Deliberate peer-list poison: this protocol has no peer import path.
                r['peers']=[{'host':'127.0.0.1','port':i,'id':str(i)} for i in range(10000,10250)]
                if self.server.mode=='malformed':r['blocks']=['not-a-block-hash']
            elif q['command']=='pool':r['transactions']=[]
            else:r['error']='withheld'
            body=json.dumps(r).encode();self.request.sendall(head[:16]+struct.pack('!I',len(body))+body);self.server.bytes+=20+len(body)
        except (OSError,ValueError):pass
class Endpoint:
    """In-process adapter tests verifier trust boundary, NOT TLS or remote transport."""
    def __init__(self,node):self.node=node
    def call(self,cmd,**fields):
        if cmd=='history' and 'revision' not in fields:
            current=self.node.call('snapshot_id')
            page=self.node.call('pruned_history',offset=fields['offset'],count=fields['count'],**{k:current[k] for k in ('tip','revision','instance')})
            return dict(tip=current['tip'],height=current['height'],offset=fields['offset'],next=page['next']),v.t.p.pack(page['records'],True)
        return {},json.dumps(self.node.call(cmd,**fields)).encode()
class OmitEndpoint(Endpoint):
    def call(self,cmd,**fields):
        header,payload=super().call(cmd,**fields)
        if cmd=='history':
            records=v.t.p.unpack(payload)
            return header,v.t.p.pack(records[1:],True)
        return header,payload
def main():
    cpu=time.process_time();began=time.perf_counter();out=ROOT/'docs/evidence/phase5c/wsl2';out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase5c-') as tmp:
        base=Path(tmp);os.chmod(base,0o700)
        # Disposable public address obtained from a disposable deterministic vector;
        # secret is never serialized into observations or persisted.
        f=h.f;password=os.urandom(32).hex().encode();p=base/'a.password';f.write_private(p,password)
        h.g.cli('create',base/'a.wallet',p);wallet=f.load(base/'a.wallet',password)
        address=f.address(wallet,0);honest=h.Node(base,'honest');honest.start()
        timestamp=int(time.time())-1200
        for i in range(3):honest.mine(address,timestamp+120*i)
        fresh=honest.status();check('real three-block independently validated ground truth',fresh['height']==3)
        proxies=[Proxy(honest) for _ in range(3)]
        try:
            for honest_routes in (0,1):
                for trial in range(3):
                    for i,p in enumerate(proxies):p.mode='honest' if i<honest_routes else 'stale'
                    victim=h.Node(base,f'victim-{honest_routes}-{trial}');start=time.perf_counter();startup=victim.start(peers=proxies);t=time.perf_counter();samples=[]
                    while time.perf_counter()-t<1.2:
                        samples.append(victim.status());time.sleep(.05)
                    isolated=victim.status()['height']==0
                    check(f'conditional isolation routes={honest_routes} trial={trial}',isolated==(honest_routes==0))
                    row=dict(honest_routes=honest_routes,trial=trial,startup_ms=startup,isolated=isolated,isolation_time_ms=0 if isolated else None,isolation_time_definition='All configured routes adversarial at process start; not measured peer takeover',observed_window_ms=(time.perf_counter()-t)*1000,height_lag=fresh['height']-victim.status()['height'])
                    if isolated:
                        endpoint=Endpoint(victim);cache=v.synchronize(wallet,endpoint,endpoint)['cache']
                        check(f'stale valid anchor accepted {trial}',cache['height']==0)
                        # Compare with independently validated fresh source; do not pick
                        # a winner from unauthenticated claimed heights/work.
                        row['crosscheck_alarm']=victim.status()!=honest.status()
                        row['same_stale_anchor_alarm']=victim.status()!=victim.status()
                        check(f'independent view detects disagreement {trial}',row['crosscheck_alarm'] and not row['same_stale_anchor_alarm'])
                        proxies[0].mode='honest';rt=time.perf_counter();h.g.converge(honest,victim);row['reconnection_ms']=(time.perf_counter()-rt)*1000
                        check(f'reconnection converges work/hash/height {trial}',victim.status()==fresh)
                        cache=v.synchronize(wallet,endpoint,endpoint,cache=cache)['cache']
                        check(f'wallet recovers after anchor reconnect {trial}',cache['height']==fresh['height'])
                    else:
                        # A quiet honest chain also fails a progress-only heuristic.
                        h.g.converge(honest,victim);quiet=victim.status();qt=time.perf_counter();time.sleep(1.2)
                        row['quiet_chain_progress_alarm']=quiet==victim.status();row['quiet_window_ms']=(time.perf_counter()-qt)*1000
                        check(f'quiet-chain heuristic false alarm {trial}',row['quiet_chain_progress_alarm'])
                    row['rss_bytes']=int(Path(f'/proc/{victim.p.pid}/statm').read_text().split()[1])*os.sysconf('SC_PAGE_SIZE')
                    trials.append(row);victim.stop()
            # Malformed inventory is rejected; independent honest route still works.
            proxies[0].mode='honest';proxies[1].mode='malformed';proxies[2].mode='stale'
            victim=h.Node(base,'malformed');victim.start(peers=proxies);h.g.converge(honest,victim);check('malformed and poisoned inventory cannot replace honest validated chain',victim.status()==fresh);victim.stop()
            # Independently validated nonempty competing branches; honest route
            # delayed by 300ms per response. Consensus, not advertised work, wins.
            for p in proxies:p.mode='stale'
            victim=h.Node(base,'fork');victim.start(peers=proxies)
            for i in range(2):victim.mine(address,timestamp+60+120*i)
            check('nonempty valid stale branch differs from oracle',victim.status()['height']==2 and victim.status()['tip']!=fresh['tip'])
            endpoint=Endpoint(victim);cache=v.synchronize(wallet,endpoint,endpoint)['cache']
            check('wallet accepts internally valid competing stale anchor',cache['height']==2)
            rt=time.perf_counter();proxies[0].delay=.3;proxies[0].mode='honest';h.g.converge(honest,victim)
            fork_reconnect_ms=(time.perf_counter()-rt)*1000
            recovered=v.synchronize(wallet,endpoint,endpoint,cache=cache)
            reference=v.synchronize(wallet,Endpoint(honest),None)
            check('wallet reorg matches independent full scan',recovered['balance']==reference['balance'] and recovered['cache']['owned']==reference['cache']['owned'])
            try:v.synchronize(wallet,Endpoint(honest),OmitEndpoint(honest))
            except ValueError:check('fresh anchor rejects selectively omitted transaction record',True)
            else:raise AssertionError('omitted record accepted')
            check('matching honest views no disagreement alarm',victim.status()==honest.status())
            victim.stop();totals=dict(requests=sum(p.requests for p in proxies),response_bytes=sum(p.bytes for p in proxies),delayed_fork_reconnect_ms=fork_reconnect_ms,delay_per_honest_response_ms=300)
        finally:
            for p in proxies:p.shutdown();p.server_close()
            for n in h.g.nodes:n.stop()
        commands=h.g.commands
        result=dict(result='PASS',scope='loopback actual TCP and native consensus; NAT analogue is no incoming honest route, not real NAT; no public endpoints',checks=checks,check_count=len(checks),trials=trials,traffic=totals,commands=commands,ground_truth=fresh,elapsed_seconds=time.perf_counter()-began,controller_cpu_seconds=time.process_time()-cpu,controller_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,limitations=['No real remote network','No probabilistic Internet attack estimate','No independent security review','No full Monero Nyx/Moros reproduction','Verifier adapter bypasses TLS deliberately; transport gates remain archived'],defenses={'operator_fixed_honest_route':'NARROW','independent_validating_view_disagreement':'NARROW','progress_timeout_as_freshness_proof':'KILL'})
        encoded=json.dumps(result,indent=2)+'\n'
        # Check actual randomly generated recovery material before evidence publication.
        for k in ('seed','view'):
            if wallet.get(k):assert wallet[k] not in encoded
        (out/'results.json').write_text(encoded)
if __name__=='__main__':main()
