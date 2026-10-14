"""Extend the existing real chain; retain independent public accounting truth."""
from pathlib import Path
import importlib.util,json,shutil,os,time,sys,hashlib
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('phase5b_gates',ROOT/'tests/phase5b/gates.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
w=g.w;f=g.f;RUN=ROOT/'build/phase5b-workload';OUT=g.OUT
def save(name,data):f.write_private(RUN/name,f.canonical(data),replace=True)
def main():
    old=ROOT/'build/phase5a-workload';RUN.mkdir(parents=True,exist_ok=True);RUN.chmod(0o700)
    if not (RUN/'node').exists():
        shutil.copytree(old/'node',RUN/'node')
        for n in ('A.wallet','B.wallet','C.wallet','fixture.password'):shutil.copy2(old/n,RUN/n)
    password=f.read_private(RUN/'fixture.password');ws={n:f.load(RUN/(n+'.wallet'),password) for n in 'ABC'}
    owners={f.parse_address(f.address(value,i))[:2]:n for n,value in ws.items() for i in range(value['count'])}
    node=g.h.Node(RUN,'node');node.start(ttl=1);time.sleep(1.1)
    node.stop();node.start(ttl=3600)
    try:
        state=w.snapshot(node.rpc)
        if (RUN/'progress.json').exists():
            public=json.loads((RUN/'progress.json').read_text())
            if public['tip']!=state['tip']:
                candidates=[json.loads(path.read_text()) for path in RUN.glob('scale-*.json')]
                latest=next((x for x in candidates if x['tip']==state['tip']),None)
                assert latest is not None,'Interrupted after acceptance without complete public receipts: explicit reconciliation required'
                public.update(intents=latest['intents'],extra=latest['extra'],timestamp=public['timestamp']+60,tip=state['tip'])
            # Reconcile receipts against canonical acceptance, never assume pool
            # admission implies mining. Preserve the failed TTL fixture evidence.
            frozen=json.loads((old/'public.json').read_text());model=frozen['model'];ids=node.call('chain')['chain'];canonical={r['id'] for r in state['chain'] if not r['coinbase']}
            excluded=sorted(set(public['intents'])-canonical)
            for r in state['chain']:
                height=r['height']
                if height<=frozen['state']['height']:continue
                if r['coinbase']:
                    owner='C' if height<=402 else 'ABC'[(height-403)%3];reward=node.call('get_block',hash=ids[height])['reward'];model.append(dict(owner=owner,amount=reward,height=height,coinbase=True,spent=False))
                else:
                    intent=public['intents'][r['id']]
                    for index in intent['sources']:
                        assert not model[index]['spent'] and model[index]['owner']==intent['sender'];model[index]['spent']=True
                    for receipt in sorted(intent['receipts'],key=lambda x:x['index']):model.append(dict(owner=receipt['owner'],amount=receipt['amount'],height=height,coinbase=False,spent=False))
            public['model']=model;public['intents']={key:value for key,value in public['intents'].items() if key in canonical}
            if excluded:
                OUT.mkdir(parents=True,exist_ok=True);(OUT/'fixture-reconciliation.json').write_text(json.dumps(dict(result='RECONCILED',excluded_unmined_fixture_transactions=excluded,reason='one-second cleanup TTL inadvertently remained active during workload mining; corrected to existing 3600-second policy',consensus_changed=False),indent=2)+'\n')
            if public['extra']>=100 and not public['scales']:
                for n,wallet in ws.items():
                    actual=w.scan(wallet,state)['owned'];assert {(x['global_index'],x['amount'],x['spent']) for x in actual}=={(j,x['amount'],x['spent']) for j,x in enumerate(model) if x['owner']==n}
                filename='scale-'+str(len(model))+'.json';save(filename,dict(state=state,model=model,intents=public['intents'],extra=public['extra'],tip=state['tip']));public['scales'].append(filename)
            save('progress.json',public)
        else:
            frozen=json.loads((old/'public.json').read_text());model=frozen['model'];intents=frozen['intents']
            for r in state['chain']:
                if r['height']>frozen['state']['height']:
                    assert r['coinbase'],'unexpected Phase 5A live suffix'
                    b=node.call('get_block',hash=node.call('chain')['chain'][r['height']]);model.append(dict(owner='C',amount=b['reward'],height=r['height'],coinbase=True,spent=False))
            public=dict(model=model,intents=intents,tip=state['tip'],extra=0,timestamp=max(frozen['timestamp']+240,int(time.time())-18000),scales=[])
        start=time.perf_counter()
        for i in range(public['extra'],300):
            sender='ABC'[i%3];state=w.snapshot(node.rpc)
            recipients=[dict(address=f.address(ws['ABC'[(i+j+1)%3]],j%4),amount=100000+i*10+j) for j in range(15)]
            payment=w.build(ws[sender],state,recipients=recipients,fee=2000000)
            receipts=[dict(index=r['index'],amount=r['amount'],owner=owners[(r['D'],r['C'])]) for r in payment['receipts']]
            for index in payment['selected_sources']:
                assert not public['model'][index]['spent'] and public['model'][index]['owner']==sender
                public['model'][index]['spent']=True
            node.call('submit_tx',transaction=payment['transaction']);public['timestamp']+=60;node.mine(f.address(ws[sender],i%4),public['timestamp'])
            status=node.status();reward=node.call('get_block',hash=status['tip'])['reward']
            assert payment['transaction'] in node.call('get_block',hash=status['tip'])['transactions'],'admitted private transaction was not mined'
            public['model'].append(dict(owner=sender,amount=reward,height=status['height'],coinbase=True,spent=False))
            for r in sorted(receipts,key=lambda x:x['index']):public['model'].append(dict(owner=r['owner'],amount=r['amount'],height=status['height'],coinbase=False,spent=False))
            public['intents'][payment['id']]=dict(sender=sender,sources=payment['selected_sources'],fee=payment['fee'],inputs=payment['inputs'],outputs=payment['outputs'],receipts=receipts)
            public.update(tip=status['tip'],extra=i+1)
            if i in (99,219,299):
                snapshot=w.snapshot(node.rpc);scale=dict(state=snapshot,model=public['model'],intents=public['intents'],extra=i+1,tip=status['tip'])
                filename='scale-'+str(len(public['model']))+'.json';save(filename,scale);public['scales'].append(filename)
                # Independent construction receipts/selected sources vs full scan.
                for n,wallet in ws.items():
                    actual=w.scan(wallet,snapshot)['owned'];expected={(j,x['amount'],x['spent']) for j,x in enumerate(public['model']) if x['owner']==n}
                    assert {(x['global_index'],x['amount'],x['spent']) for x in actual}==expected
                print('SCALE',len(public['model']),'height',status['height'],flush=True)
            save('progress.json',public)
            if i%10==9:print('WORKLOAD',i+1,'/300',round(time.perf_counter()-start,1),'seconds',flush=True)
        snapshot=w.snapshot(node.rpc)
        for n,wallet in ws.items():
            actual=w.scan(wallet,snapshot)['owned'];assert {(x['global_index'],x['amount'],x['spent']) for x in actual}=={(j,x['amount'],x['spent']) for j,x in enumerate(public['model']) if x['owner']==n}
        OUT.mkdir(parents=True,exist_ok=True);report=OUT/'larger-workload.json'
        if report.exists():
            attempt=OUT/'attempts'/str(time.time_ns());attempt.mkdir(parents=True);shutil.copy2(report,attempt/report.name)
        report.write_text(json.dumps(dict(result='PASS',height=node.status()['height'],tip=node.status()['tip'],outputs=len(public['model']),private_transactions=len(public['intents']),scales=public['scales'],additional_transaction_attempts=public['extra'],additional_private_transactions_mined=len(public['intents'])-len(frozen['intents']),ground_truth=public['model'],producer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),truth='independent constructor receipts and consumed source indexes, checked against full wallet scans; real accepted/mature mandatory-private transactions'),indent=2)+'\n')
    finally:node.stop(crash=True)
if __name__=='__main__':main()
