"""Disposable local safety/recovery gates; publish only whitelisted evidence."""
from pathlib import Path
import importlib.util,json,os,sys,tempfile,subprocess,time,copy,hashlib,shutil,errno
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
c=module('local_safety','src/phase6a/wallet.py');w=c.w;f=c.f
h=module('live_utils','tests/phase4/gates.py')
OUT=ROOT/'docs/evidence/phase6a';RUN=ROOT/'build/phase6a-local';checks=[];secrets=[]
def check(name,condition=True):
    if not condition:raise AssertionError(name)
    checks.append(name);print('PASS',name,flush=True)
def reject(name,fn):
    try:fn()
    except (ValueError,OSError,TypeError,KeyError,AttributeError):check(name);return
    raise AssertionError(name)
def remember(wallet):
    for key in ('seed','view'):
        if wallet[key]:secrets.extend([wallet[key].encode(),bytes.fromhex(wallet[key])])
    if wallet['seed']:
        for value in f.crypto('derive',wallet['seed'])[:2]:secrets.extend([value.encode(),bytes.fromhex(value)])
def child(source):
    p=subprocess.run([sys.executable,'-c',source],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    return p
def main():
    OUT.mkdir(parents=True,exist_ok=True);assert not (OUT/'gates.json').exists()
    with tempfile.TemporaryDirectory(prefix='privacycoin-6a-') as d:
        base=Path(d);base.chmod(0o700);password=os.urandom(32).hex().encode();secrets.append(password)
        wallet=f.full(count=4);remember(wallet);file=base/'A.wallet';c.save(file,wallet,password)
        backup=f.seal(f.recovery(wallet),password,'recovery');bf=base/'A.wallet-backup';c.write_private(bf,backup)
        check('supported v1 wallet/recovery/envelope compatibility',f.load(file,password)==c.load(file,password) and f.restore(f.open_sealed(backup,password,'recovery'))==wallet)
        restored=f.restore(f.open_sealed(backup,password,'recovery'));check('correct seed identity and address range',all(f.address(restored,i)==f.address(wallet,i) for i in range(4)))
        wrong=f.full(count=4);remember(wrong);check('wrong valid seed yields another identity, cannot infer intended wallet',f.wallet_id(wrong)!=f.wallet_id(wallet))
        reject('wrong password',lambda:c.load(file,os.urandom(32)))
        for name,raw in [('truncated',backup[:-20]),('bit-flipped',backup[:-9]+bytes([backup[-9]^1])+backup[-8:]),('malformed',b'{')]:
            reject(name+' backup',lambda raw=raw:f.open_sealed(raw,password,'recovery'))
        envelope=json.loads(backup)
        for key,value in [('version',2),('version',0),('network','other'),('kdf','weaker'),('aead','none')]:
            altered=dict(envelope);altered[key]=value
            reject('envelope '+key+' '+str(value),lambda altered=altered:f.open_sealed(f.canonical(altered),password,'recovery'))
        for key,value in [('version',2),('version',0),('schemes',[2,1,1]),('network','other')]:
            r=f.recovery(wallet);r[key]=value;reject('recovery '+key+' '+str(value),lambda r=r:f.restore(r))
        reject('duplicate JSON fields',lambda:f.decode(b'{"version":1,"version":2}'))
        reject('no-clobber wallet',lambda:c.save(file,wrong,password))
        check('no-clobber leaves original valid',c.load(file,password)==wallet)
        public=base/'public';public.write_bytes(backup);public.chmod(0o644)
        reject('world-readable private file',lambda:c.read_private(public))
        symbolic=base/'symlink';symbolic.symlink_to(file);reject('leaf symlink',lambda:c.read_private(symbolic))
        hard=base/'hardlink';os.link(file,hard);reject('hardlinked private file',lambda:c.read_private(hard));hard.unlink()
        fifo=base/'fifo';os.mkfifo(fifo,0o600);reject('FIFO rejects without blocking',lambda:c.read_private(fifo))
        alias=base/'alias';alias.symlink_to(base,target_is_directory=True)
        reject('ancestor symlink',lambda:c.read_private(alias/'A.wallet'))
        reject('parent traversal',lambda:c.read_private(base/'..'/base.name/'A.wallet'))
        reject('write oversized object',lambda:c.write_private(base/'large',b'0'*(f.MAX_FILE+1)))
        for stage in ('during_write','before_publish','after_publish'):
            target=base/(stage+'.wallet');c.save(target,wallet,password)
            prog=f"import sys;sys.path.insert(0,{str(ROOT/'src/phase6a')!r});import wallet as c,os,signal; p={str(target)!r};pw=c.read_private({str(base/'password')!r});w=c.load(p,pw);c.save(p,w,pw,True,lambda s:os.kill(os.getpid(),signal.SIGKILL) if s=={stage!r} else None)"
            if not (base/'password').exists():c.write_private(base/'password',password)
            p=child(prog);check('actual SIGKILL wallet save '+stage,p.returncode==-9)
            check('restart valid encrypted wallet '+stage,c.load(target,password)==wallet)
            target=base/(stage+'-restored.wallet')
            prog=f"import sys;sys.path.insert(0,{str(ROOT/'src/phase6a')!r});import wallet as c,os,signal;pw=c.read_private({str(base/'password')!r});w=c.f.restore(c.f.open_sealed(c.read_private({str(bf)!r}),pw,'recovery'));c.save({str(target)!r},w,pw,fault=lambda s:os.kill(os.getpid(),signal.SIGKILL) if s=={stage!r} else None)"
            p=child(prog);check('actual SIGKILL restore '+stage,p.returncode==-9)
            check('restore absent or complete '+stage,not target.exists() or c.load(target,password)==wallet)
        for operation in ('fsync','replace'):
            old=file.read_bytes()
            with patch.object(c.os,operation,side_effect=OSError(errno.ENOSPC,'injected')):
                reject('disk error '+operation,lambda:c.save(file,wrong,password,True))
            check('disk error preserves original '+operation,file.read_bytes()==old)
        view=f.view_export(wallet);check('incoming view has no seed',view['seed'] is None)
        reject('view cannot export full recovery',lambda:f.recovery(view))
        reject('view cannot prepare spending',lambda:c.prepare(view,{},'',1,1,1))
        with patch.object(c,'read_private',return_value=backup):
            bad=f.seal(dict(version=2),password,c.CACHE_KIND)
        cachefile=base/'bad-cache';c.write_private(cachefile,bad)
        reject('unknown/inconsistent cache schema',lambda:c.read_cache(cachefile,wallet,password))
        # Live frozen ledger: baseline fixture is copied, never changed.
        fixture_pw=f.read_private(RUN/'fixture.password');secrets.append(fixture_pw)
        wallets={n:f.load(RUN/f'{n}.wallet',fixture_pw) for n in 'ABC'}
        for value in wallets.values():remember(value)
        nodes=[]
        for n in 'AB':
            target=base/('node-'+n);shutil.copytree(RUN/'node',target);nodes.append(h.Node(base,'node-'+n))
        A,B=nodes;A.start();B.start()
        try:
            state=w.snapshot(A.rpc);scan=w.scan(wallets['A'],state);address=f.address(wallets['B'],0)
            expected_rewards=[A.call('get_block',hash=identity)['reward'] for height,identity in enumerate(A.call('chain')['chain']) if height and (height-1)%3==0]
            check('independent coinbase ownership/amount ground truth',len(scan['owned'])==30 and sum(x['amount'] for x in scan['owned'])==sum(expected_rewards))
            balance=c.qualified(wallets['A'],state,scan)
            check('balance trust/freshness explicitly qualified',balance['global_freshness']=='UNKNOWN' and balance['chain_trust']=='TRUSTED_LOCAL_VALIDATING_ANCHOR' and balance['locked_coinbase']>0)
            vb=c.qualified(f.view_export(wallets['A']),state,w.scan(f.view_export(wallets['A']),state))
            check('view balance/spent/outgoing unknown',vb['balance'] is None and vb['spendable'] is None and vb['spent_status']=='UNKNOWN')
            plan=c.prepare(wallets['A'],state,address,123456789,1000000,1000000)
            for label,alter in [('destination',lambda q:q.update(destination=f.address(wallets['C'],0))),('fee',lambda q:q.update(fee=1000001)),('inputs',lambda q:q.update(sources=[99])),('change',lambda q:q.update(change=1))]:
                q=plan.intent();alter(q);badplan=c.Plan(plan.payload)
                def tamper_after_display(display):
                    object.__setattr__(badplan,'payload',f.canonical(q));return True
                with patch.object(w,'helper',side_effect=AssertionError('signing reached')):
                    # Scanning uses helper too: provide the real scan while instrumenting construction.
                    with patch.object(w,'scan',return_value=scan):
                        reject('changed confirmed '+label+' never signs',lambda:c.execute(wallets['A'],badplan,tamper_after_display,lambda:state,lambda _:None))
            with patch.object(w,'helper',side_effect=AssertionError('signing reached')):
                reject('rejected consent never signs',lambda:c.execute(wallets['A'],plan,lambda _:False,lambda:state,lambda _:None))
                changed=copy.deepcopy(state);changed['height']+=1
                reject('changed chain before signing',lambda:c.execute(wallets['A'],plan,lambda _:True,lambda:changed,lambda _:None))
            reject('fee ceiling before signing',lambda:c.prepare(wallets['A'],state,address,1,1000001,1000000))
            reject('insufficient funds before signing',lambda:c.prepare(wallets['A'],state,address,2**63,1000000,1000000))
            for dest in ('invalid',address[:-2],address.replace('PCdv1-','PCdv2-')):
                reject('invalid/wrong namespace destination '+str(len(dest)),lambda dest=dest:c.prepare(wallets['A'],state,dest,1,1000000,1000000))
            # Three fresh recovery directories, real private payments, independent receipts.
            stamp=json.loads((RUN/'fixture-public.json').read_text())['timestamp']
            transactions=[]
            for n in 'ABC':
                directory=base/('recovery-'+n);directory.mkdir(mode=0o700);original=directory/'original.wallet';backupfile=directory/'recovery.wallet-backup'
                c.save(original,wallets[n],fixture_pw);c.write_private(backupfile,f.seal(f.recovery(wallets[n]),fixture_pw,'recovery'))
                fresh=w.snapshot(A.rpc);plan=c.prepare(wallets[n],fresh,f.address(wallets['ABC'[('ABC'.index(n)+1)%3]],0),123456789,1000000,1000000)
                captured=[]
                def submit(tx):captured.append(tx);return A.call('submit_tx',transaction=tx['transaction'])
                response=c.execute(wallets[n],plan,lambda _:True,lambda:w.snapshot(A.rpc),submit)
                tx=captured[0];transactions.append(tx)
                check('confirmed real private payment '+n,response['submitted'] and tx['id'] in A.call('pool')['transactions'])
                pending=w.snapshot(A.rpc);pb=c.qualified(wallets[n],pending,w.scan(wallets[n],pending))
                check('pending/reserved separate '+n,pb['pending_fees']==1000000 and pb['reserved_inputs']>0)
                stamp+=120;A.mine(f.address(wallets['A'],0),stamp)
                drill=c.restore_drill(original,backupfile,fixture_pw,A.rpc,directory/'drill.wallet')
                check('independent fresh restore drill '+n,drill['result']=='PASS')
                original.unlink();c.save(original,f.restore(f.open_sealed(c.read_private(backupfile),fixture_pw,'recovery')),fixture_pw)
                fresh=w.snapshot(A.rpc);expected=w.scan(wallets[n],fresh)['owned'];actual=w.scan(c.load(original,fixture_pw),fresh)['owned']
                check('state loss/restart exact per-output restoration '+n,expected==actual)
            for tx in transactions:
                fresh=w.snapshot(A.rpc)
                for receipt in tx['receipts']:
                    found=[]
                    for wallet in wallets.values():found.extend(x for x in w.scan(wallet,fresh)['owned'] if x['transaction']==tx['id'] and x['output_index']==receipt['index'])
                    check('private construction receipt amount/ownership',len(found)==1 and found[0]['amount']==receipt['amount'])
            offline=w.snapshot(A.rpc)
            for _ in range(20):stamp+=120;A.mine(f.address(wallets['C'],0),stamp)
            current=w.snapshot(A.rpc)
            check('20-block offline suffix new outputs exact',current['height']-offline['height']==20 and len(w.scan(wallets['C'],current)['owned'])-len(w.scan(wallets['C'],offline)['owned'])==20)
            highwork=int(A.call('status')['work']);stale=w.snapshot(B.rpc)
            _,_,badbalance,_=c.observe(wallets['A'],B.rpc,dict(work=highwork,tip=current['tip']))
            check('stale local anchor cannot claim spendable balance',badbalance['spendable'] is None and not badbalance['signing_available'])
            # B builds a real greater-work replacement branch; A's mined payments roll back.
            for _ in range(28):stamp+=120;B.mine(f.address(wallets['B'],0),stamp)
            check('replacement actually greater work',int(B.call('status')['work'])>highwork)
            A.stop();A.start(peer=B);h.g.converge(A,B)
            after=w.snapshot(A.rpc);reference=w.snapshot(B.rpc)
            canonical=lambda s:[{k:v for k,v in x.items() if k!='reserved'} for x in w.scan(wallets['A'],s)['owned'] if not x['pending']]
            check('real reorg exact independent-node canonical full scan',after['tip']==reference['tip'] and canonical(after)==canonical(reference))
            _,_,good,_=c.observe(wallets['A'],A.rpc,dict(work=highwork,tip=current['tip']))
            check('greater-work reorg accepted with qualified balances',good['signing_available'] and good['global_freshness']=='UNKNOWN')
        finally:
            for node in nodes:node.stop(crash=True)
        report=dict(result='PASS',checks=checks,check_count=len(checks),scope='Automated local devnet; not independent participant drills or security review',
                    independent_security_review='NOT_PERFORMED',independent_participant_drills=0,phase5='INCOMPLETE_WITH_BLOCKERS',phase6a='IN_PROGRESS',secret_encodings_checked=len(secrets),
                    input_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ('src/phase6a/wallet.py','tests/phase6a/gates.py')})
        raw=f.canonical(report)
        for secret in secrets:
            assert secret not in raw and secret.hex().encode() not in raw,'Secret in evidence'
        (OUT/'gates.json').write_bytes(raw+b'\n')
        print('PASS safety/recovery gates',len(checks),flush=True)
if __name__=='__main__':main()
