"""Paired randomized, loopback-only research; active node source is untouched."""
from pathlib import Path
import importlib.util,json,os,random,time,tempfile,socket,socketserver,struct,threading,resource,subprocess,statistics,tracemalloc,hashlib
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('phase5c_reuse',ROOT/'tests/phase5c/research.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
h=c.h;f=h.f
OUT=ROOT/'docs/evidence/phase5d/wsl2';SEED=51004
checks=[]
def check(label,ok):
    assert ok,label
    checks.append(label)
def cpu(pid):
    fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
    return (int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK')
def rss(pid):return int(Path(f'/proc/{pid}/statm').read_text().split()[1])*os.sysconf('SC_PAGE_SIZE')
class Proxy(socketserver.ThreadingTCPServer):
    daemon_threads=True;allow_reuse_address=True
    def __init__(self,target):
        super().__init__(('127.0.0.1',0),Handler);self.target=target;self.honest=False;self.delay=0;self.received=0;self.sent=0;self.requests=0;self.active=0;self.lock=threading.Lock()
        self.p2p=self.server_address[1];threading.Thread(target=self.serve_forever,daemon=True).start()
    def drain(self):
        until=time.monotonic()+4
        while self.active and time.monotonic()<until:time.sleep(.01)
        assert self.active==0,'proxy handler drain'
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        p=self.server
        with p.lock:p.active+=1
        try:
            self.request.settimeout(3);head=c.read(self.request,20);n=struct.unpack('!I',head[16:])[0]
            if n>1024*1024:raise ValueError('bounded request')
            raw=c.read(self.request,n);q=json.loads(raw);p.received+=20+n;p.requests+=1;time.sleep(p.delay)
            if p.honest:
                with socket.create_connection(('127.0.0.1',p.target.p2p),timeout=3) as s:
                    s.sendall(head+raw);rh=c.read(s,20);body=c.read(s,struct.unpack('!I',rh[16:])[0])
            else:
                r={k:q[k] for k in ('network','genesis','profile')}
                if q['command']=='inventory':r.update(blocks=[q['genesis']],peers=[{'port':10000+i,'id':str(i)} for i in range(250)])
                elif q['command']=='pool':r['transactions']=[]
                else:r['error']='withheld'
                body=json.dumps(r).encode();rh=head[:16]+struct.pack('!I',len(body))
            self.request.sendall(rh+body);p.sent+=20+len(body)
        except (OSError,ValueError):pass
        finally:
            with p.lock:p.active-=1
def warning(local,other):
    if other is None:return 'UNKNOWN'
    if local!=other:return 'DISAGREEMENT'
    return 'AGREES_WITH_CONFIGURED_ANCHOR'
def concentration(labels):return max(labels.count(x) for x in set(labels))/len(labels)>=2/3
def checkpoint_warning(node,observation):
    local=node.status()
    if local['height']<observation['height']:return 'BEHIND_TRUSTED_OBSERVATION'
    if observation['tip'] not in node.call('chain')['chain']:return 'CONFLICTS_WITH_TRUSTED_OBSERVATION'
    return 'CONTAINS_TRUSTED_OBSERVATION'
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def signed_tests(base,fresh):
    """Standard OpenSSL Ed25519 only, isolated observation signing, not consensus."""
    key=base/'observer.key';pub=base/'observer.pub';msg=base/'observation';sig=base/'signature'
    def run(args):return subprocess.run(['openssl']+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    run(['genpkey','-algorithm','ED25519','-out',str(key)]);os.chmod(key,0o600)
    run(['pkey','-in',str(key),'-pubout','-out',str(pub)])
    def sign(data):
        msg.write_bytes(canon(data));run(['pkeyutl','-sign','-inkey',str(key),'-rawin','-in',str(msg),'-out',str(sig)]);return sig.read_bytes()
    def verify(data,signature,now,last_seq=0):
        if data['profile']!=h.w.PROFILE or data['sequence']<=last_seq or not 0<=now-data['issued']<=30:return False
        msg.write_bytes(canon(data));sig.write_bytes(signature)
        p=subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(pub),'-rawin','-in',str(msg),'-sigfile',str(sig)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return p.returncode==0
    data=dict(profile=h.w.PROFILE,sequence=10,issued=1000,chain=fresh);signature=sign(data);cases=[];timings=[]
    for i in range(40):
        t=time.process_time();child=resource.getrusage(resource.RUSAGE_CHILDREN);ct=child.ru_utime+child.ru_stime
        good=verify(data,signature,1001);after=resource.getrusage(resource.RUSAGE_CHILDREN);timings.append((time.process_time()-t+after.ru_utime+after.ru_stime-ct)*1000);check('signed authentic '+str(i),good)
        for label,d,s,now,seq in [('mutation',dict(data,chain=dict(fresh,height=999)),signature,1001,0),('wrong-profile',dict(data,profile='wrong'),signature,1001,0),('expired',data,signature,1031,0),('future-clock',data,signature,999,0),('replayed-sequence',data,signature,1001,10),('bad-signature',data,bytes([signature[0]^1])+signature[1:],1001,0)]:
            ok=not verify(d,s,now,seq);check(label+' '+str(i),ok);cases.append(dict(case=label,rejected=ok))
    stale=dict(data,chain=dict(fresh,height=0,tip=h.w.GENESIS,work='0'))
    check('compromised observer can sign a current stale claim',verify(stale,sign(stale),1001))
    return dict(public_signer_fingerprint=hashlib.sha256(pub.read_bytes()).hexdigest(),negative_cases=cases,parent_plus_child_cpu_ms=timings,wire_observation_bytes=len(canon(data))+len(signature),boundary='Pinned signer authentication/30s clock window/monotone sequence; not global freshness; sequence persistence and clock integrity are external assumptions')
def main():
    OUT.mkdir(parents=True,exist_ok=True)
    if (OUT/'results.json').exists():raise ValueError('Refuse to overwrite prior research results; archive explicitly')
    rng=random.Random(SEED);rows=[];monitor=[];start=time.perf_counter();parent_cpu=time.process_time()
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase5d-') as tmp:
        base=Path(tmp);os.chmod(base,0o700);password=os.urandom(32).hex().encode();pwd=base/'a.password';f.write_private(pwd,password)
        h.g.cli('create',base/'a.wallet',pwd);wallet=f.load(base/'a.wallet',password);address=f.address(wallet,0)
        oracle=h.Node(base,'oracle');oracle.start();timestamp=int(time.time())-1200
        for i in range(3):oracle.mine(address,timestamp+120*i)
        fresh=oracle.status();signed=signed_tests(base,fresh)
        scenarios=['partial']*20+['sybil']*8+['partition']*8+['all-adversarial']*4;rng.shuffle(scenarios)
        proxies=[Proxy(oracle) for _ in range(4)]
        try:
            for trial,scenario in enumerate(scenarios):
                pools=[[dict(source=src,operator=('attacker' if j<bad else 'honest-'+str(j)),honest=j>=bad) for j in range(20)] for src,bad in zip('ABC',(18,8,4))]
                if scenario in ('sybil','all-adversarial'):
                    pools=[[dict(x,honest=False,operator='attacker') for x in pool] for pool in pools]
                initial=rng.sample(pools[0],3);diverse=[rng.choice(p) for p in pools]
                persisted=dict(source='persisted',operator='saved-operator',honest=rng.random()>=.2,available=rng.random()>=.2)
                plans={'baseline':initial,'source-diverse':diverse,'persistent-peer':initial+[persisted]};order=list(plans);rng.shuffle(order)
                for policy in order:
                    selected=plans[policy]
                    for p in proxies:p.drain()
                    for i,p in enumerate(proxies):
                        p.honest=i<len(selected) and selected[i]['honest'] and selected[i].get('available',True) and scenario not in ('partition','all-adversarial')
                        p.delay=rng.choice((0,.005,.02))
                    reachable=any(p.honest for p in proxies[:len(selected)])
                    before_rx=sum(p.received for p in proxies);before_tx=sum(p.sent for p in proxies);victim=h.Node(base,f'victim-{trial}-{policy}')
                    startup=victim.start(peers=proxies[:len(selected)]);tcpu=cpu(victim.p.pid);t=time.perf_counter()
                    while time.perf_counter()-t<2:
                        local=victim.status()
                        if local==fresh:break
                        time.sleep(.025)
                    elapsed=(time.perf_counter()-t)*1000;isolated=local!=fresh
                    check(f'actual isolation matches selected reachability {trial} {policy}',isolated== (not reachable))
                    row=dict(trial=trial,scenario=scenario,policy=policy,selected=selected,honest_reachable=reachable,isolated=isolated,isolation_time_ms=0 if isolated else None,observation_ms=elapsed,startup_ms=startup,height_lag=fresh['height']-local['height'],node_cpu_seconds=cpu(victim.p.pid)-tcpu,node_rss_bytes=rss(victim.p.pid))
                    tracemalloc.start();mcpu=time.process_time();mt=time.perf_counter();other=oracle.status()
                    label=warning(local,other);mono=dict(trial=trial,policy=policy,cpu_ms=(time.process_time()-mcpu)*1000,wall_ms=(time.perf_counter()-mt)*1000,allocated_peak_bytes=tracemalloc.get_traced_memory()[1],application_response_bytes=len(json.dumps(other).encode()),stale_detected=label=='DISAGREEMENT',concentration_alarm=concentration([x['operator'] for x in selected]),wallet_label=label)
                    tracemalloc.stop();monitor.append(mono);check('view detects actual stale '+str(trial)+policy,mono['stale_detected']==isolated)
                    row['checkpoint_warning']=checkpoint_warning(victim,fresh)
                    check('trusted current checkpoint constrains stale view '+str(trial)+policy,(row['checkpoint_warning']=='BEHIND_TRUSTED_OBSERVATION')==isolated)
                    check('no independent view remains unknown '+str(trial)+policy,warning(local,None)=='UNKNOWN')
                    row['observation_received_bytes']=sum(p.received for p in proxies)-before_rx;row['observation_sent_bytes']=sum(p.sent for p in proxies)-before_tx
                    if isolated:
                        stale_agreement=warning(local,local);row['correlated_stale_detected']=stale_agreement=='DISAGREEMENT'
                        check('correlated stale agreement cannot prove freshness '+str(trial)+policy,stale_agreement=='AGREES_WITH_CONFIGURED_ANCHOR')
                        row['old_checkpoint_warning']=checkpoint_warning(victim,dict(height=0,tip=h.w.GENESIS))
                        check('old valid checkpoint cannot establish freshness '+str(trial)+policy,row['old_checkpoint_warning']=='CONTAINS_TRUSTED_OBSERVATION')
                        if scenario=='partition':
                            victim.stop();row['partition_restart_ms']=victim.start(peers=proxies[:len(selected)]);check('restart does not escape partition '+str(trial)+policy,victim.status()==local)
                        rt=time.perf_counter();proxies[0].honest=True;h.g.converge(oracle,victim);row['recovery_ms']=(time.perf_counter()-rt)*1000
                        check('validated recovery '+str(trial)+policy,victim.status()==fresh)
                    row['total_received_bytes']=sum(p.received for p in proxies)-before_rx;row['total_sent_bytes']=sum(p.sent for p in proxies)-before_tx
                    victim.stop();rows.append(row)
                print('TRIAL',trial+1,'of 40',scenario,flush=True)
            # Independent comparison must treat benign lag as disagreement rather
            # than proof of attack. Quiet views should not cause a warning.
            controls=[]
            for i in range(40):
                quiet=warning(fresh,dict(fresh));lag=warning(dict(fresh,height=2),fresh)
                benign_ops=['honest-NAT']*3 if i<20 else ['one','two','three']
                controls.append(dict(quiet_warning=quiet!='AGREES_WITH_CONFIGURED_ANCHOR',benign_lag_disagreement=lag=='DISAGREEMENT',concentration_alarm=concentration(benign_ops)))
                check('quiet honest view no alarm '+str(i),quiet=='AGREES_WITH_CONFIGURED_ANCHOR')
            summary={}
            for policy in plans:
                subset=[r for r in rows if r['policy']==policy];summary[policy]=dict(trials=len(subset),isolated=sum(r['isolated'] for r in subset),sent_bytes=sum(r['total_sent_bytes'] for r in subset),received_bytes=sum(r['total_received_bytes'] for r in subset),median_node_cpu_seconds=statistics.median(r['node_cpu_seconds'] for r in subset),median_node_rss_bytes=statistics.median(r['node_rss_bytes'] for r in subset))
            secret_encodings=[password.decode()]+[wallet[k] for k in ('seed','view') if wallet.get(k)]+f.crypto('derive',wallet['seed'])[:2]
            result=dict(result='PASS',parent='ca81bb697134aaad3976bdf23d7a19eebd1105bf',randomization_seed=SEED,check_count=len(checks),checks=checks,rows=rows,monitors=monitor,controls=controls,signed_observations=signed,summary=summary,commands=h.g.commands,wall_seconds=time.perf_counter()-start,controller_cpu_seconds=time.process_time()-parent_cpu,controller_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,child_cpu_seconds=resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime+resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime,ground_truth=fresh,limitations=['Actual loopback TCP, synthetic source labels and controlled candidate selection; no real discovery/NAT/Internet','No peer takeover dynamics or Internet probability','No independent external audit','Signed checkpoint signer/clock/sequence persistence are trust assumptions','No active P2P change'])
            encoded=json.dumps(result,indent=2)+'\n'
            for secret in secret_encodings:check('secret encoding absent',secret not in encoded)
            result['secret_encodings_checked']=len(secret_encodings);result['check_count']=len(checks)
            (OUT/'results.json').write_text(json.dumps(result,indent=2)+'\n')
        finally:
            for n in h.g.nodes:n.stop()
            for p in proxies:p.shutdown();p.server_close()
if __name__=='__main__':
    try:main()
    except Exception as exc:
        OUT.mkdir(parents=True,exist_ok=True);(OUT/('failure-'+str(time.time_ns())+'.json')).write_text(json.dumps(dict(result='FAIL',exception_type=type(exc).__name__,checks_completed=len(checks)))+'\n');raise
