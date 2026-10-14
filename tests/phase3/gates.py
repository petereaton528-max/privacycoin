"""Real two-node private-spend gates. All secret-bearing files live in /tmp 0700.
Only whitelisted public observations and timings become evidence.
"""
from pathlib import Path
import importlib.util
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import shutil
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('private_wallet',ROOT/'src/phase3/wallet.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
f=w.foundation
OUT=ROOT/'docs/evidence/phase3/wsl2'
NODE=ROOT/'build/monero-linux/phase3/privacycoin-private-devnet'
CLI=ROOT/'scripts/phase3/privacycoin-wallet'
checks=[];secret_values=[];nodes=[];commands=[];metrics={}

def check(name,condition=True):
    if not condition:raise AssertionError(name)
    checks.append(name);print('PASS',name,flush=True)

def rejects(name,fn):
    try:fn()
    except (ValueError,subprocess.CalledProcessError):check(name);return
    raise AssertionError(name)

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

class Node:
    def __init__(self,base,name):
        self.path=base/name;self.rpc=port();self.p2p=port();self.p=None;self.log=None;nodes.append(self)
    def start(self,peer=None):
        cmd=[str(NODE),'--data-dir',str(self.path),'--rpc-port',str(self.rpc),'--p2p-port',str(self.p2p)]
        if peer:cmd+=['--peer-port',str(peer.p2p)]
        commands.append(cmd);self.log=tempfile.TemporaryFile();t=time.perf_counter();self.p=subprocess.Popen(cmd,stdout=self.log,stderr=self.log)
        for _ in range(1200):
            if self.p.poll() is not None:raise AssertionError('node startup')
            try:self.call('status');return (time.perf_counter()-t)*1000
            except (ValueError,OSError):time.sleep(.025)
        raise AssertionError('startup timeout')
    def call(self,cmd,**args):return w.rpc(self.rpc,cmd,**args)
    def stop(self,crash=False):
        if self.p and self.p.poll() is None:
            if crash:self.p.kill()
            else:self.call('shutdown')
            self.p.wait(timeout=30)
        if self.log:self.log.close();self.log=None
    def status(self):
        s=self.call('status');return {k:s[k] for k in ('height','tip','work')}
    def mine(self,address,timestamp):
        D,C,sub=f.parse_address(address);R,P=f.crypto('output',D,C,sub,0)
        return self.call('mine',reward_key=P,R=R,timestamp=timestamp)

def converge(a,b):
    t=time.perf_counter()
    for _ in range(2400):
        if a.status()==b.status():return (time.perf_counter()-t)*1000
        time.sleep(.025)
    raise AssertionError('sync convergence')

def cli(cmd,wallet,password,**args):
    command=[sys.executable,str(CLI),cmd,'--wallet',str(wallet),'--password-file',str(password)]
    for k,v in args.items():command+=['--'+k.replace('_','-'),str(v)]
    commands.append(command)
    p=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    if p.returncode:raise ValueError('CLI request rejected')
    return json.loads(p.stdout)

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    for name in ('live-results.json','live-failure.json'):
        old=OUT/name
        if old.exists():
            dest=OUT/'attempts'/str(time.time_ns());dest.mkdir(parents=True);shutil.copy2(old,dest/name)
            if name=='live-failure.json':old.unlink()
    with tempfile.TemporaryDirectory(prefix='privacycoin-phase3-') as temp:
        base=Path(temp);os.chmod(base,0o700)
        password=b'Phase3 disposable full password 2026';vp=b'Phase3 distinct view password 2026'
        secret_values.extend([password,vp]);pwd=base/'full.password';viewpwd=base/'view.password'
        f.write_private(pwd,password);f.write_private(viewpwd,vp)
        files={n:base/(n+'.wallet') for n in ('A','B','C','V')}
        for n in ('A','B','C'):cli('create',files[n],pwd)
        wallets={n:f.load(files[n],password) for n in ('A','B','C')}
        for value in wallets.values():
            secret_values.extend(bytes.fromhex(value[k]) for k in ('seed','view'))
            secret_values.extend(bytes.fromhex(x) for x in f.crypto('derive',value['seed'])[:2])
        addresses={n:f.address(value,0) for n,value in wallets.items()}
        sub=f.address(wallets['B'],1);check('distinct A B C primary and B subaddress',len(set(addresses.values())|{sub})==4)
        backup=base/'A.wallet-backup';cli('backup',files['A'],pwd,file=backup)
        cap=base/'A.capability';cli('view-export',files['A'],pwd,file=cap,export_password_file=viewpwd)
        cli('view-import',files['V'],viewpwd,file=cap);view=f.load(files['V'],vp)
        check('view capability has no seed or spend authority',view['seed'] is None and view['authority']=='view')
        A=Node(base,'node-A');B=Node(base,'node-B')
        metrics['startup_ms']=A.start();B.start(peer=A);check('two real nodes frozen genesis',A.status()==B.status() and A.status()['tip']==w.GENESIS)
        timestamp=int(time.time())-120*110
        mine_start=time.perf_counter()
        for h in range(1,81):
            timestamp+=120;A.mine(addresses['A'] if h%5 else addresses['B'],timestamp)
        metrics['funding_80_blocks_seconds']=time.perf_counter()-mine_start
        metrics['small_chain_sync_ms']=converge(A,B)
        check('80 real RandomX blocks synchronize identical height tip work',A.status()==B.status() and A.status()['height']==80)
        state=w.snapshot(A.rpc);scanA=w.scan(wallets['A'],state);scanB=w.scan(wallets['B'],state);scanC=w.scan(wallets['C'],state)
        check('real chain coinbase ownership separation',len(scanA['owned'])==64 and len(scanB['owned'])==16 and not scanC['owned'])
        check('maturity enforced by spendable output set',any(x['unlock']>81 for x in scanA['owned']) and len(scanA['eligible'])==21)
        balanceA=w.balance(wallets['A'],state,scanA);check('positive mature spendable wallet balance',balanceA['spendable']>0)
        check('view scan detects identical A output set',w.scan(view,state)['owned'][0]['global_index']==scanA['owned'][0]['global_index'])
        rejects('view-only native build cannot spend',lambda:w.helper(dict(op='build',**w.request(view,state),source=0,amount=1,fee=1,ring=list(range(16)),D=f.parse_address(sub)[0],C=f.parse_address(sub)[1],sub=True)))
        rejects('view-only wallet builder cannot spend',lambda:w.build(view,state,sub,123456789,1000000))
        rejects('view-only CLI cannot spend',lambda:cli('send',files['V'],viewpwd,rpc_port=A.rpc,destination=sub,amount=123456789))
        payment=w.build(wallets['A'],state,sub,123456789,1000000,source=0)
        conflict=w.build(wallets['A'],state,sub,987654321,1000000,source=0)
        inspection=w.helper(dict(op='inspect',transaction=payment['transaction']))
        other_inspection=w.helper(dict(op='inspect',transaction=conflict['transaction']))
        check('distinct payments have distinct one-time keys',set(inspection['one_time_keys']).isdisjoint(other_inspection['one_time_keys']))
        check('same ownership generates same anti-double-spend marker',inspection['image']==other_inspection['image'])
        check('public transaction v2 RingCT6 zero plaintext output amounts',inspection['version']==2 and inspection['scheme']==6 and inspection['public_amounts']==[0,0])
        check('recipient reusable keys absent from public transaction',all(x not in payment['transaction'] for x in f.parse_address(sub)[:2]))
        check('canonical transaction independent construction bytes',payment['transaction']!=conflict['transaction'])
        metrics.update(transaction_bytes=payment['bytes'],transaction_construction_ms=payment['construction_ms'],wallet_scan_ms=scanA['scan_ms'])
        metrics['standalone_native_primitive_probes']=w.helper(dict(op='benchmark'))
        for case in ('authorization','commitment','range','ciphertext','ring','outside-ring','destination','version','fee','excess-fee','image','immature'):
            mutant=w.helper(dict(op='mutate',transaction=payment['transaction'],case=case,index=65))['transaction']
            rejects('reject '+case,lambda mutant=mutant:A.call('submit_tx',transaction=mutant))
        for case,raw in [('truncated',payment['transaction'][:-2]),('trailing',payment['transaction']+'00'),('corrupt','ff'*200),('noncanonical', '8200'+payment['transaction'][2:]),('odd hex','0'),('oversize','00'*50001)]:
            rejects('reject serialized '+case,lambda raw=raw:A.call('submit_tx',transaction=raw))
        check('adversarial mutations leave chain and pool untouched',A.status()['tip']==state['tip'] and not A.call('pool')['transactions'])
        # B remains a valid independent branch at the common height.
        B.stop();B.start()
        t=time.perf_counter();accepted=A.call('submit_tx',transaction=payment['transaction'])['accepted'];metrics['transaction_validation_rpc_ms']=(time.perf_counter()-t)*1000
        check('first valid private spend accepted',accepted==payment['id'])
        rejects('pool duplicate key image conflict',lambda:A.call('submit_tx',transaction=conflict['transaction']))
        issued_before=int(A.call('status')['issued'])
        D,C,subkind=f.parse_address(addresses['A']);R,P=f.crypto('output',D,C,subkind,0)
        candidate=A.call('template',reward_key=P,R=R,timestamp=timestamp+120)
        for case in ('authorization','commitment','range','ciphertext','immature'):
            mutant=w.helper(dict(op='mutate',transaction=payment['transaction'],case=case,index=65))['transaction']
            malformed=w.helper(dict(op='block-transaction',block=candidate['block'],transaction=mutant))['block']
            if case=='authorization':rejects('block requires committed transaction body',lambda:A.call('submit',block=malformed))
            rejects('direct block rejects '+case,lambda malformed=malformed,mutant=mutant:A.call('submit',block=malformed,transactions=[mutant]))
        duplicate=w.helper(dict(op='block-duplicate',block=candidate['block']))['block']
        rejects('direct block duplicate key image replay',lambda:A.call('submit',block=duplicate,transactions=[payment['transaction']]))
        excessive=w.helper(dict(op='block-reward',block=candidate['block']))['block']
        rejects('reject excessive subsidy plus fee in private block',lambda:A.call('submit',block=excessive))
        timestamp+=120;A.mine(addresses['A'],timestamp)
        block=A.call('get_block',hash=A.status()['tip']);check('private transaction mined in real block',block['transactions']==[payment['transaction']])
        check('coinbase receives exact subsidy plus fee',block['reward']==int(A.call('status')['issued'])-issued_before+1000000)
        state1=w.snapshot(A.rpc);a1=w.scan(wallets['A'],state1);b1=w.scan(wallets['B'],state1);c1=w.scan(wallets['C'],state1)
        receipt=[x for x in b1['owned'] if x['transaction']==payment['id']]
        check('B detects exact hidden payment',len(receipt)==1 and receipt[0]['amount']==123456789)
        check('C detects none of B payment',not c1['owned'])
        check('A marks spent input and detects confidential change',a1['owned'][0]['spent'] and len([x for x in a1['owned'] if x['transaction']==payment['id']])==1)
        rejects('exact chain replay',lambda:A.call('submit_tx',transaction=payment['transaction']))
        rejects('independent valid conflicting spend',lambda:A.call('submit_tx',transaction=conflict['transaction']))
        altered=w.helper(dict(op='mutate',transaction=payment['transaction'],case='fee'))['transaction']
        rejects('altered replay',lambda:A.call('submit_tx',transaction=altered))
        before=cli('sync',files['A'],pwd,rpc_port=A.rpc);beforeB=cli('balance',files['B'],pwd,rpc_port=A.rpc)
        check('encrypted persistent chain cache exists',Path(str(files['A'])+'.phase3-cache').exists())
        cache=f.open_sealed(f.read_private(Path(str(files['A'])+'.phase3-cache')),password,'phase3-cache')
        check('cache bound to current wallet and chain',cache['tip']==state1['tip'] and cache['wallet_id']==f.wallet_id(wallets['A']))
        A.stop();A.start();check('node restart persisted identical private chain',A.status()['tip']==state1['tip'])
        check('wallet restart balance identical',cli('balance',files['A'],pwd,rpc_port=A.rpc)==before)
        A.stop(crash=True);A.start();check('SIGKILL recovery identical tip and spend state',A.status()['tip']==state1['tip'] and w.scan(wallets['A'],w.snapshot(A.rpc))['owned'][0]['spent'])
        files['A'].unlink();Path(str(files['A'])+'.phase3-cache').unlink();cli('restore',files['A'],pwd,file=backup)
        check('restored A keys and address identical',f.address(f.load(files['A'],password),0)==addresses['A'])
        check('restore rescan reproduces wallet balance',cli('rescan',files['A'],pwd,rpc_port=A.rpc)==before)
        # A's spend and B's conflicting spend are both valid on their own branch.
        check('competing valid spend accepted on independent branch',B.call('submit_tx',transaction=conflict['transaction'])['accepted']==conflict['id'])
        B.mine(addresses['B'],timestamp);B.mine(addresses['B'],timestamp+120)
        check('fork has greater valid cumulative work',int(B.status()['work'])>int(A.status()['work']))
        A.stop();A.start(peer=B);metrics['spend_reorg_sync_ms']=converge(A,B)
        check('greater-work spend branch wins and nodes converge',A.status()==B.status() and A.status()['height']==82)
        winning=w.snapshot(A.rpc);bs=w.scan(wallets['B'],winning);ascan=w.scan(wallets['A'],winning)
        check('orphan receipt removed and winning receipt recovered',not any(x['transaction']==payment['id'] for x in bs['owned']) and any(x['transaction']==conflict['id'] and x['amount']==987654321 for x in bs['owned']))
        check('one canonical key image survives reorg',winning['images']==[inspection['image']] and ascan['owned'][0]['spent'])
        check('orphan spend not returned as conflicting valid pool entry',not A.call('pool')['transactions'])
        rejects('losing spend rejected on winning branch',lambda:A.call('submit_tx',transaction=payment['transaction']))
        check('wallet scanners converge across both nodes',w.balance(wallets['B'],winning,bs)==w.balance(wallets['B'],w.snapshot(B.rpc),w.scan(wallets['B'],w.snapshot(B.rpc))))
        viewscan=w.scan(view,winning);check('view-only incoming scan remains available',len(viewscan['owned'])==len(ascan['owned']) and all(x['spent'] is None for x in viewscan['owned']))
        # Real CLI transaction construction/submission after the reorg.
        send=cli('send',files['A'],pwd,rpc_port=A.rpc,destination=addresses['B'],amount=22222222)
        check('CLI sends valid private payment',send['submitted'] and send['id'] in A.call('pool')['transactions'])
        A.mine(addresses['A'],timestamp+240)
        # Peer pulls canonical transaction bodies together with blocks.
        B.stop();B.start(peer=A);converge(A,B)
        finalstate=w.snapshot(B.rpc);finalB=w.scan(wallets['B'],finalstate)
        check('second CLI payment detected by B after two-node sync',any(x['transaction']==send['id'] and x['amount']==22222222 for x in finalB['owned']))
        check('C remains unrelated after all payments',not w.scan(wallets['C'],finalstate)['owned'])
        # Spend a received confidential output after its ten-block age floor.
        timestamp+=240
        while A.status()['height']<90:
            timestamp+=120;A.mine(addresses['A'],timestamp)
        converge(A,B);B.stop();B.start()  # independent branch before the spend
        before_received=w.snapshot(A.rpc);bs_before=w.scan(wallets['B'],before_received)
        received=next(x for x in bs_before['owned'] if x['transaction']==conflict['id'])
        confidential=w.build(wallets['B'],before_received,addresses['A'],111111111,1000000,source=received['global_index'])
        check('received confidential output constructs a real subsequent spend',confidential['id']!=conflict['id'])
        A.call('submit_tx',transaction=confidential['transaction']);timestamp+=120;A.mine(addresses['A'],timestamp)
        cs=w.snapshot(A.rpc);sc=w.scan(wallets['B'],cs)
        check('received confidential output spent and change detected',next(x for x in sc['owned'] if x['transaction']==conflict['id'])['spent'] and any(x['transaction']==confidential['id'] for x in sc['owned']))
        whole=sum(w.balance(wallets[n],cs,w.scan(wallets[n],cs))['balance'] for n in ('A','B'))
        check('all confidential and coinbase balances equal total issued supply',whole==int(A.call('status')['issued']))
        B.mine(addresses['B'],timestamp);B.mine(addresses['B'],timestamp+120)
        A.stop();A.start(peer=B);converge(A,B)
        rewound=w.snapshot(A.rpc);sb=w.scan(wallets['B'],rewound)
        check('reorg restores previously spent confidential ownership',not next(x for x in sb['owned'] if x['transaction']==conflict['id'])['spent'])
        check('reorg removes orphan spend marker',w.helper(dict(op='inspect',transaction=confidential['transaction']))['image'] not in rewound['images'])
        check('valid orphan transaction restored to pool',confidential['id'] in A.call('pool')['transactions'])
        A.mine(addresses['A'],timestamp+240)
        B.stop();B.start(peer=A);converge(A,B)
        finalstate=w.snapshot(A.rpc);finalB=w.scan(wallets['B'],finalstate)
        check('restored orphan spend remined and consumed exactly once',next(x for x in finalB['owned'] if x['transaction']==conflict['id'])['spent'] and len(finalstate['images'])==3)
        whole=sum(w.balance(wallets[n],finalstate,w.scan(wallets[n],finalstate))['balance'] for n in ('A','B'))
        check('supply conservation survives private-output reorg',whole==int(A.call('status')['issued']))
        final=A.status();A.stop();B.stop();A.start();B.start();check('both nodes restart to identical final tip',A.status()==B.status()==final)
        metrics['node_rss_kib']=int(next(x.split()[1] for x in Path('/proc/'+str(A.p.pid)+'/status').read_text().splitlines() if x.startswith('VmRSS:')))
        check('restart rescan reproduces final recipient state',w.scan(wallets['B'],w.snapshot(A.rpc))['owned']==finalB['owned'])
        for node in nodes:node.stop()
        record=dict(result='PASS',checks_passed=len(checks),checks=checks,profile=w.PROFILE,final_chain=final,measurements=metrics,
                    commands=commands,node_sha256=hashlib.sha256(NODE.read_bytes()).hexdigest(),helper_sha256=hashlib.sha256(w.HELPER.read_bytes()).hexdigest(),
                    development_only=True,secret_handling='No helper streams, wallet files, masks, seeds, or decrypted scan cache retained')
        raw=f.canonical(record)
        for secret in secret_values:
            if secret in raw or secret.hex().encode() in raw:raise AssertionError('secret leak')
        (OUT/'live-results.json').write_bytes(raw+b'\n');print('PASS live checks',len(checks),flush=True)

if __name__=='__main__':
    try:main()
    except BaseException as error:
        for node in nodes:
            try:node.stop(crash=True)
            except Exception:pass
        record=dict(result='FAIL',completed_checks=checks,error_type=type(error).__name__,failed_check=str(error) if isinstance(error,AssertionError) else 'runtime request failed')
        (OUT/'live-failure.json').write_bytes(f.canonical(record)+b'\n');print(json.dumps(record));sys.exit(1)
