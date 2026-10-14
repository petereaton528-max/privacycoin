"""Real Phase 4 workload; ephemeral secrets stay in a private temporary directory."""
from pathlib import Path
import importlib.util,json,os,sys,tempfile,time,subprocess,traceback,shutil
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
g=module('frozen_gate_utilities','tests/phase3/gates.py')
w=module('hardened_wallet','src/phase4/wallet.py');f=w.foundation
g.w=w;g.NODE=ROOT/'build/monero-linux/phase4/privacycoin-hardened-devnet';g.CLI=ROOT/'scripts/phase4/privacycoin-wallet'
OUT=ROOT/'docs/evidence/phase4/wsl2';check=g.check;rejects=g.rejects
class Node(g.Node):
    def start(self,peer=None,peers=(),ttl=3600,crash=None):
        cmd=[str(g.NODE),'--data-dir',str(self.path),'--rpc-port',str(self.rpc),'--p2p-port',str(self.p2p),'--pool-ttl',str(ttl)]
        for p in ([peer] if peer else [])+list(peers):cmd+=['--peer-port',str(p.p2p)]
        if crash:cmd+=['--test-crash-stage',crash]
        g.commands.append(cmd);self.log=tempfile.TemporaryFile();t=time.perf_counter();self.p=subprocess.Popen(cmd,stdout=self.log,stderr=self.log)
        for _ in range(2400):
            if self.p.poll() is not None:
                self.log.seek(0);raise AssertionError('node startup: '+self.log.read().decode(errors='replace')[-2000:])
            try:self.call('status');return (time.perf_counter()-t)*1000
            except (ValueError,OSError):time.sleep(.025)
        raise AssertionError('startup timeout')

def main():
    OUT.mkdir(parents=True,exist_ok=True);started=time.time();transactions={};rewards={};observations=[];metrics={}
    for name in ('live-results.json','live-failure.json'):
        previous=OUT/name
        if previous.exists():
            archive=OUT/'attempts'/str(time.time_ns());archive.mkdir(parents=True);shutil.move(str(previous),archive/name)
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase4-') as temp:
        base=Path(temp);os.chmod(base,0o700);password=os.urandom(32).hex().encode();vp=os.urandom(32).hex().encode()
        g.secret_values.extend([password,vp]);pwd=base/'full.password';vpass=base/'view.password';f.write_private(pwd,password);f.write_private(vpass,vp)
        files={n:base/(n+'.wallet') for n in ('A','B','C','V')}
        for n in ('A','B','C'):g.cli('create',files[n],pwd)
        wallets={n:f.load(files[n],password) for n in ('A','B','C')}
        for value in wallets.values():
            value['count']=4
            g.secret_values.extend(bytes.fromhex(value[k]) for k in ('seed','view'))
            g.secret_values.extend(bytes.fromhex(x) for x in f.crypto('derive',value['seed'])[:2])
        addresses={n:f.address(value,0) for n,value in wallets.items()};owners={}
        for n,value in wallets.items():
            for i in range(4):owners[f.parse_address(f.address(value,i))[:2]]=n
        backup=base/'A.backup';g.cli('backup',files['A'],pwd,file=backup)
        capability=base/'view.capability';g.cli('view-export',files['A'],pwd,file=capability,export_password_file=vpass);g.cli('view-import',files['V'],vpass,file=capability);view=f.load(files['V'],vp)
        nodes=[Node(base,'node-'+n) for n in ('A','B','C')];A,B,C=nodes
        metrics['empty_startup_ms']=A.start(peers=[B,C]);B.start(peers=[A,C]);C.start(peers=[A,B]);check('three independent real nodes same frozen genesis',len({x.status()['tip'] for x in nodes})==1 and A.status()['tip']==w.GENESIS)
        timestamp=int(time.time())-120*500
        def mine(node,owner):
            nonlocal timestamp
            timestamp+=120;node.mine(addresses[owner],timestamp);tip=node.status()['tip'];rewards[tip]=owner;return tip
        def converge():
            for other in (B,C):g.converge(A,other)
        def payment(sender,recipients,**kwargs):
            state=w.snapshot(A.rpc);p=w.build(wallets[sender],state,recipients=[dict(address=addresses[n],amount=v) for n,v in recipients],**kwargs)
            receipts=[dict(index=r['index'],amount=r['amount'],owner=owners[(r['D'],r['C'])],change=r['change']) for r in p['receipts']]
            transactions[p['id']]=dict(sender=sender,fee=p['fee'],sources=p['selected_sources'],receipts=receipts,bytes=p['bytes'],construction_ms=p['construction_ms'])
            return p
        def assert_accounting(label):
            state=w.snapshot(A.rpc);model=[];spent=set();active_transactions=[]
            chain=A.call('chain')['chain']
            for identity in chain:
                block=A.call('get_block',hash=identity);height=block['height']
                if height==0:continue
                owner=rewards[identity];model.append(dict(owner=owner,amount=block['reward'],unlock=height+60,coinbase=True,change=False))
                for raw in block['transactions']:
                    # Match canonical raw hash through the node's chain snapshot.
                    record=next(x for x in state['chain'] if not x.get('pending') and x['transaction']==raw);identity=record['id'];intent=transactions[identity];active_transactions.append(identity)
                    for index in intent['sources']:
                        check(label+' independent source '+str(index),index not in spent and model[index]['owner']==intent['sender'] and model[index]['unlock']<=height);spent.add(index)
                    for r in sorted(intent['receipts'],key=lambda r:r['index']):model.append(dict(owner=r['owner'],amount=r['amount'],unlock=height+10,coinbase=False,change=r['change']))
            result={}
            for n in wallets:
                scanned=w.scan(wallets[n],state);actual=w.balance(wallets[n],state,scanned);owned=[(i,x) for i,x in enumerate(model) if x['owner']==n];unspent=[(i,x) for i,x in owned if i not in spent]
                expected=dict(balance=sum(x['amount'] for i,x in unspent),unlocked_balance=sum(x['amount'] for i,x in unspent if x['unlock']<=state['height']+1),locked_coinbase=sum(x['amount'] for i,x in unspent if x['coinbase'] and x['unlock']>state['height']+1),locked_normal=sum(x['amount'] for i,x in unspent if not x['coinbase'] and x['unlock']>state['height']+1),spent_outputs=sum(i in spent for i,x in owned),outputs=len(owned),change_outputs=sum(x['change'] for i,x in owned))
                check(label+' exact independent '+n,all(actual[k]==v for k,v in expected.items()))
                check(label+' exact per-output '+n,{(x['global_index'],x['amount'],x['spent']) for x in scanned['owned'] if not x['pending']}=={(i,x['amount'],i in spent) for i,x in owned})
                result[n]=expected
            check(label+' total balances equal issued supply',sum(x['balance'] for x in result.values())==int(A.call('status')['issued']))
            observations.append(dict(label=label,height=state['height'],tip=state['tip'],balances=result,canonical_private_transactions=len(active_transactions)));return state
        for h in range(100):mine(A,'ABC'[h%3])
        converge();check('100 real RandomX funding blocks three-node sync',all(x.status()==A.status() for x in nodes))
        state=w.snapshot(A.rpc);sa=w.scan(wallets['A'],state);maxfund=max(x['amount'] for x in sa['owned'] if not x['spent'] and x['unlock']<=101)
        p=payment('A',[('B',maxfund),('C',maxfund//2)])
        check('automatic multi-input multi-recipient and change',p['inputs']>=2 and p['outputs']==3)
        ins=w.helper(dict(op='inspect',transaction=p['transaction']));check('all transfer amounts confidential',ins['public_amounts']==[0]*3)
        conflict=payment('A',[('B',maxfund//2)],sources=p['selected_sources'])
        for case in ('authorization','commitment','range','ciphertext','ring','outside-ring','destination','version','fee','excess-fee','image','immature','duplicate-image'):
            raw=w.helper(dict(op='mutate',transaction=p['transaction'],case=case,index=90))['transaction'];rejects('multi-input reject '+case,lambda raw=raw:A.call('submit_tx',transaction=raw))
        A.call('submit_tx',transaction=p['transaction']);rejects('mempool exact duplicate',lambda:A.call('submit_tx',transaction=p['transaction']));rejects('mempool conflicting ownership',lambda:A.call('submit_tx',transaction=conflict['transaction']))
        for node in (B,C):
            for _ in range(400):
                if p['id'] in node.call('pool')['transactions']:break
                time.sleep(.025)
            check('private mempool relay '+str(node.rpc),p['id'] in node.call('pool')['transactions'])
        pending=w.snapshot(A.rpc)
        for n in wallets:
            bal=w.balance(wallets[n],pending,w.scan(wallets[n],pending));check('nonnegative pending '+n,bal['pending_outgoing']>=0 and bal['pending_incoming']>=0)
        check('sender pool reservations and automatic pending change',w.balance(wallets['A'],pending,w.scan(wallets['A'],pending))['pending_change']>0)
        A.stop();A.start(peers=[B,C]);check('durable pool survives node restart',p['id'] in A.call('pool')['transactions'])
        mine(A,'A');converge();check('mined pool entry removed everywhere',all(not x.call('pool')['transactions'] for x in nodes));rejects('already spent ownership rejected',lambda:A.call('submit_tx',transaction=conflict['transaction']))
        assert_accounting('first generalized payment')
        rejects('insufficient funds',lambda:payment('C',[('B',2**63)]));rejects('view-only never spends',lambda:w.build(view,w.snapshot(A.rpc),addresses['B'],1))
        # Comfortable laptop workload: 220 additional real private transactions,
        # one per block, not a throughput/production-scale claim.
        workload_start=time.perf_counter()
        for i in range(220):
            sender='ABC'[i%3];targets=[('ABC'[(i+1)%3],100000000+i)]
            if i%5==0:targets.append(('ABC'[(i+2)%3],50000000+i))
            if i%11==0:targets=[(sender,75000000+i)]
            kwargs={}
            if i%17==0:
                current=w.snapshot(A.rpc);s=w.scan(wallets[sender],current);available=[x for x in s['owned'] if not x['pending'] and not x['spent'] and not x['reserved'] and x['unlock']<=current['height']+1]
                kwargs['sources']=[x['global_index'] for x in sorted(available,key=lambda x:x['amount'],reverse=True)[:2]]
            tx=payment(sender,targets,**kwargs);A.call('submit_tx',transaction=tx['transaction']);mine(A,'ABC'[(i+2)%3])
            if i==40:C.stop()
            if i==70:C.start(peers=[A,B]);g.converge(A,C);check('delayed peer catches up private chain',C.status()==A.status())
            if i%40==39:print('WORKLOAD',i+1,'private payments',flush=True)
        metrics['220_payment_workload_seconds']=time.perf_counter()-workload_start;converge();assert_accounting('long private chain')
        check('hundreds of blocks and private transactions',A.status()['height']>=300 and len(transactions)>=221)
        before=g.cli('sync',files['A'],pwd,rpc_port=A.rpc);A.stop(crash=True);A.start(peers=[B,C]);check('SIGKILL node chain recovery',g.cli('rescan',files['A'],pwd,rpc_port=A.rpc)==before)
        files['A'].unlink();Path(str(files['A'])+'.phase4-cache').unlink();g.cli('restore',files['A'],pwd,file=backup);check('recovery address identity',f.address(f.load(files['A'],password),0)==addresses['A']);check('restore rescan exact balance',g.cli('rescan',files['A'],pwd,rpc_port=A.rpc)==before)
        check('view-only detects canonical incoming outputs',len(w.scan(view,w.snapshot(A.rpc))['owned'])==len(w.scan(wallets['A'],w.snapshot(A.rpc))['owned']))
        # Partition all three nodes from one common chain; competing authorized
        # spends are valid locally, only the greater-work branch survives.
        for node in nodes:node.stop()
        for node in nodes:node.start()
        common=w.snapshot(A.rpc);one=payment('A',[('B',123456789)]);two=payment('A',[('C',234567890)],sources=one['selected_sources'])
        A.call('submit_tx',transaction=one['transaction']);B.call('submit_tx',transaction=two['transaction']);mine(A,'A');mine(B,'B');mine(B,'B')
        check('partition creates two valid competing private branches',A.status()['tip']!=B.status()['tip'] and int(B.status()['work'])>int(A.status()['work']))
        A.stop();C.stop();A.start(peers=[B,C]);C.start(peers=[A,B]);converge();check('three-node greater-work private reorg convergence',all(x.status()==A.status() for x in nodes));rejects('losing branch spend conflicts after reorg',lambda:A.call('submit_tx',transaction=one['transaction']));assert_accounting('winning spend reorg')
        # Structured deterministic malformed serialization corpus, real parser.
        sample=two['transaction'];mutants=[('truncated-'+str(n),sample[:n*2]) for n in (0,1,2,10,31,64,100,len(sample)//2-1)]+[('trailing',sample+'00'),('unknown-version','03'+sample[2:]),('noncanonical-varint','8200'+sample[2:]),('length-bomb','02'+'ff'*100),('odd-hex','0')]
        for i in range(80):
            pos=2+(i*7919)%(len(sample)//2-2);mutants.append(('bit-mutation-'+str(i),sample[:pos*2]+format(int(sample[pos*2:pos*2+2],16)^128,'02x')+sample[pos*2+2:]))
        latency=[];tip=A.status()
        for label,raw in mutants:
            t=time.perf_counter();rejects('serialized mutation '+label,lambda raw=raw:A.call('submit_tx',transaction=raw));latency.append((time.perf_counter()-t)*1000)
        check('mutation corpus no crash hang or chain corruption',A.status()==tip and max(latency)<5000);metrics['mutation_max_ms']=max(latency)
        # Wallet cache/rescan kill points use actual CLI SIGKILL, then canonical
        # rescan rebuilds state rather than trusting a torn cache.
        expected=g.cli('balance',files['A'],pwd,rpc_port=A.rpc)
        for stage in ('before_cache_publish','after_cache_publish','during_rescan'):
            cmd=[sys.executable,str(g.CLI),'rescan','--wallet',str(files['A']),'--password-file',str(pwd),'--rpc-port',str(A.rpc),'--test-crash-stage',stage]
            proc=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180);check('wallet actual crash '+stage,proc.returncode==-9);check('wallet deterministic crash recovery '+stage,g.cli('rescan',files['A'],pwd,rpc_port=A.rpc)==expected)
        # Pool expiry is explicit policy; use an independent short-TTL node.
        for node in nodes:node.stop()
        A.start(ttl=1);expiring=payment('B',[('C',34567890)]);A.call('submit_tx',transaction=expiring['transaction']);time.sleep(1.1);check('mempool expiry cleanup',not A.call('pool')['transactions'] and A.call('status')['pool_expired']>=1)
        A.stop();A.start();check('expired pool absent after restart',not A.call('pool')['transactions'])
        final=A.status();metrics['elapsed_seconds']=time.time()-started
        evidence=dict(result='PASS',checks=g.checks,check_count=len(g.checks),metrics=metrics,final=final,ground_truth=observations,synthetic_transaction_intents=transactions,commands=g.commands,privacy='Disposable synthetic amounts and labels intentionally disclosed for independent accounting; no reusable public keys, seeds or viewing/spending secrets recorded.')
        raw=json.dumps(evidence,indent=2)
        for secret in g.secret_values:
            assert secret.hex() not in raw and (not all(32<=x<127 for x in secret) or secret.decode() not in raw)
        (OUT/'live-results.json').write_text(raw+'\n');print('PASS Phase 4 live checks',len(g.checks),flush=True)
if __name__=='__main__':
    try:main()
    except Exception as e:
        OUT.mkdir(parents=True,exist_ok=True);(OUT/'live-failure.json').write_text(json.dumps(dict(result='FAIL',type=type(e).__name__,message=str(e),passed_checks=g.checks),indent=2)+'\n');traceback.print_exc();sys.exit(1)
    finally:
        for node in g.nodes:
            try:node.stop(crash=True)
            except Exception:pass
