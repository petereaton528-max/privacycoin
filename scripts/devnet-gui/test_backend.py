"""Disposable real-node integration and deterministic injected failures; no secrets exported."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, signal, statistics, subprocess, sys, tempfile, time
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from backend import Session, c, f, w, native, SOURCE, NATIVE
from bridge import Bridge

checks=[]
def check(name,condition=True):
    if not condition:raise AssertionError(name)
    checks.append(name);print('PASS '+name,flush=True)
def rejects(name,fn):
    try:fn()
    except Exception:check(name);return
    raise AssertionError(name)
def call(s,command,**kw):return s.dispatch(dict(command=command,**kw))
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    args.out.mkdir(parents=True,exist_ok=True);resultfile=args.out/'backend.json';assert not resultfile.exists()
    h=native('gui_test_nodes','tests/phase4/gates.py'); metrics={};secrets=[]
    with tempfile.TemporaryDirectory(prefix='privacycoin-gui-test-') as temp:
        base=Path(temp);os.chmod(base,0o700);home=base/'wallets';home.mkdir(mode=0o700)
        node=h.Node(base,'node');node.start();s=Session(home,node.rpc);password=os.urandom(24).hex();secrets.append(password.encode())
        try:
            alice=call(s,'create',name='Alice',password=password);aw=s.wallet.copy()
            secrets.extend(bytes.fromhex(aw[k]) for k in ('seed','view'))
            secrets.extend(bytes.fromhex(x) for x in f.crypto('derive',aw['seed'])[:2])
            check('create private encrypted full wallet, no keys returned',alice['authority']=='full' and not {'seed','view','private'}.intersection(alice))
            check('wallet mode 0600 and store 0700',os.stat(home/'Alice.wallet').st_mode&0o777==0o600 and os.stat(home).st_mode&0o777==0o700)
            check('no unscanned balance on open',alice['balance'] is None)
            r=call(s,'refresh');call(s,'open',name='Alice',password=password)
            check('genesis zero-work observation remains reopenable',r['node']['height']==0 and not Path(str(home/'Alice.wallet')+'.phase6a-cache').exists())
            bob=call(s,'create',name='Bob',password=password);bw=s.wallet.copy();secrets.extend(bytes.fromhex(bw[k]) for k in ('seed','view'))
            call(s,'open',name='Alice',password=password)
            stamp=int(time.time())-120*500
            def mine(owner,count=1):
                nonlocal stamp
                for _ in range(count):stamp+=120;node.mine(owner,stamp)
            mine(alice['address']);r=call(s,'refresh')
            check('mined funds immature and not spendable',r['balance']['locked_coinbase']>0 and r['balance']['spendable']==0)
            request=dict(destination=bob['address'],amount=1000000,fee=188000,max_fee=500000)
            rejects('immature payment rejected',lambda:call(s,'prepare',**request))
            mine(alice['address'],79);r=call(s,'refresh')
            check('actual full scan and qualified anchor only',r['node']['height']==80 and r['balance']['spendable']>0 and r['balance']['global_freshness']=='UNKNOWN')
            chain=w.snapshot(node.rpc);oracle=w.scan(aw,chain)
            check('mined balance agrees independent reward oracle',r['balance']['total_balance']==sum(x['amount'] for x in oracle['owned'] if not x['spent']))
            rejects('fee cap rejects before signing',lambda:call(s,'prepare',**dict(request,max_fee=1)))
            rejects('insufficient balance rejects',lambda:call(s,'prepare',**dict(request,amount=2**63)))
            rejects('wrong network recipient rejects',lambda:call(s,'prepare',**dict(request,destination='not-an-address')))
            rejects('backend rejects unknown authorization fields',lambda:s.dispatch(dict(command='prepare',**request,approved=True)))
            rejects('backend cannot confirm without prepared token',lambda:call(s,'confirm',token='0'*64,consent='CONFIRM'))
            t=time.perf_counter();p=call(s,'prepare',**request);metrics['prepare_ms']=(time.perf_counter()-t)*1000
            check('review does not broadcast',not node.call('pool')['transactions'])
            rejects('backend rejects missing literal approval',lambda:call(s,'confirm',token=p['token'],consent='YES'))
            p=call(s,'prepare',**request);call(s,'refresh')
            rejects('refresh invalidates prior approval',lambda:call(s,'confirm',token=p['token'],consent='CONFIRM'))
            p=call(s,'prepare',**request);s.plan=(s.plan[0],time.monotonic()-1,s.plan[2])
            rejects('expired approval rejected',lambda:call(s,'confirm',token=p['token'],consent='CONFIRM'))
            p=call(s,'prepare',**request);t=time.perf_counter();sent=call(s,'confirm',token=p['token'],consent='CONFIRM');metrics['private_sign_submit_ms']=(time.perf_counter()-t)*1000
            check('explicitly approved real private A to B submission',sent['submitted'] and sent['transaction_id'] in node.call('pool')['transactions'])
            rejects('duplicate confirmation cannot broadcast twice',lambda:call(s,'confirm',token=p['token'],consent='CONFIRM'))
            r=call(s,'refresh');check('pending outgoing reserves inputs',r['balance']['reserved_inputs']>0 and r['outgoing'][0]['status']=='PENDING')
            call(s,'open',name='Bob',password=password);r=call(s,'refresh');check('pending incoming not spendable',r['balance']['pending_incoming']==request['amount'] and r['balance']['spendable']==0)
            mine(alice['address'],2);r=call(s,'refresh');check('receiver independent ownership equals sent amount',r['balance']['balance']==request['amount'] and len([x for x in r['history'] if x['transaction_id']==sent['transaction_id']])==1)
            check('few confirmations not sufficiently confirmed',r['balance']['sufficiently_confirmed_unspent']==0)
            call(s,'open',name='Alice',password=password);r=call(s,'refresh');before=r['balance']['balance'];backup=call(s,'backup',name='Alice-recovery')
            rejects('backup no clobber',lambda:call(s,'backup',name='Alice-recovery'))
            restored=call(s,'restore',name='Restored',backup='Alice-recovery',password=password);r=call(s,'refresh')
            check('encrypted backup restore independent full scan identity and balance',restored['address']==alice['address'] and r['balance']['balance']==before)
            check('GUI backup retains approved submission history',r['outgoing'][0]['transaction_id']==sent['transaction_id'])
            rejects('restore no clobber',lambda:call(s,'restore',name='Restored',backup='Alice-recovery',password=password))
            rejects('invalid wallet password',lambda:call(s,'open',name='Alice',password=password+'wrong'))
            rejects('path traversal rejected',lambda:call(s,'create',name='../outside',password=password))
            c.write_private(home/'Corrupt.wallet',b'{truncated')
            rejects('malformed wallet rejects',lambda:call(s,'open',name='Corrupt',password=password))
            for name,raw in [('Truncated',c.read_private(home/'Alice-recovery.backup')[:50]),('Corrupted',b'{"version":1}'),('Future',f.seal(dict(version=99,recovery={},journal={},cache=None),password.encode(),'gui-pilot-backup'))]:
                c.write_private(home/(name+'.backup'),raw)
                rejects(name+' backup rejects without destination',lambda name=name:call(s,'restore',name='Invalid',backup=name,password=password))
                check(name+' backup leaves no wallet',not (home/'Invalid.wallet').exists())
            # Same immutable engine supports incoming-view authority; GUI does not add key export.
            c.save(home/'View.wallet',f.view_export(aw),password.encode());call(s,'open',name='View',password=password);r=call(s,'refresh')
            check('incoming view has UNKNOWN spent balance and no signing',r['balance']['balance'] is None and r['balance']['spent_status']=='UNKNOWN' and not r['balance']['signing_available'])
            rejects('view-only backend cannot prepare',lambda:call(s,'prepare',**request))
            call(s,'open',name='Alice',password=password)
            with patch.object(c,'observe',side_effect=ValueError('inconsistent snapshot')):rejects('inconsistent snapshot never returns balance',lambda:call(s,'refresh'))
            saved=s.previous.copy();s.previous=dict(saved,work=saved['work']+1);r=call(s,'refresh')
            check('stale work returns null balances and disables signing',r['balance']['balance'] is None and not r['balance']['signing_available'])
            s.previous=saved
            # A real greater-work fork; disconnected outgoing must never retain confirmation.
            fork=h.Node(base,'fork');fork.start()
            try:
                for _ in range(node.status()['height']+1):stamp+=120;fork.mine(bob['address'],stamp)
                # Restart same data directory attached to fork; actual P2P import.
                node.stop();node.start(peer=fork);h.g.converge(node,fork)
                r=call(s,'refresh');check('real greater-work reorganization observed',r['node']['tip']==fork.status()['tip'] and r['balance']['balance']==0)
                check('orphaned payment not shown confirmed',r['outgoing'][0]['status']!='CONFIRMED')
            finally:fork.stop()
            node.stop();rejects('node disconnected gives no verified result',lambda:call(s,'refresh'));node.start()
            # A genuinely fresh disposable payer for unrelated failure scenarios.
            # Do not evade Alice's unknown orphaned-payment record with seed-only restore.
            fault=call(s,'create',name='FaultPayer',password=password)
            mine(fault['address'],80);call(s,'refresh');call(s,'backup',name='Fault-recovery')
            call(s,'restore',name='FaultRestored',backup='Fault-recovery',password=password);call(s,'refresh')
            p=call(s,'prepare',**request)
            with patch.object(w,'rpc',side_effect=lambda port,cmd,**kw: (_ for _ in ()).throw(OSError('lost ack')) if cmd=='submit_tx' else original_rpc(port,cmd,**kw)):
                original_rpc=rpc_original
                rejects('failed submission recorded UNKNOWN',lambda:call(s,'confirm',token=p['token'],consent='CONFIRM'))
            s.close();call(s,'open',name='FaultRestored',password=password);r=call(s,'refresh')
            check('restart preserves UNKNOWN journal and blocks replacement',r['unknown_attempts']==1)
            rejects('UNKNOWN payment cannot silently reauthorize',lambda:call(s,'prepare',**request))
            call(s,'backup',name='Unknown-recovery');call(s,'restore',name='UnknownRestored',backup='Unknown-recovery',password=password);r=call(s,'refresh')
            check('backup restore preserves UNKNOWN payment reservation',r['unknown_attempts']==1)
            rejects('restored UNKNOWN payment cannot silently reauthorize',lambda:call(s,'prepare',**request))
            # Backend process interface: real pipe roundtrips, no secrets in output.
            s.close();bridge=Bridge(home,node.rpc)
            try:
                r=bridge.call('open',name='Bob',password=password);check('persistent pipe open works',r['address']==bob['address'])
                response=json.dumps(bridge.call('refresh')).encode()
                check('pipe responses contain no known test secrets',all(x not in response and x.hex().encode() not in response for x in secrets))
                rejects('pipe malformed command rejected',lambda:bridge.call('export_seed'))
            finally:bridge.close()
            call(s,'restore',name='Concurrent',backup='Fault-recovery',password=password);s.close()
            bridge=Bridge(home,node.rpc)
            try:
                bridge.call('open',name='Concurrent',password=password);bridge.call('refresh')
                p=bridge.call('prepare',**request);pool_before=len(node.call('pool')['transactions'])
                def confirm(_):
                    try:return bridge.call('confirm',token=p['token'],consent='CONFIRM')['submitted']
                    except ValueError:return False
                with ThreadPoolExecutor(max_workers=2) as executor:answers=list(executor.map(confirm,range(2)))
                check('concurrent duplicate approval broadcasts at most once',sum(answers)==1 and len(node.call('pool')['transactions'])==pool_before+1)
                rejects('second process cannot unlock held wallet',lambda:call(s,'open',name='Concurrent',password=password))
            finally:bridge.close()
            # Actual SIGKILL during encrypted save, restore, signing and possible submission.
            for stage in ('restore_before_publish','unknown_before_sign','signed_before_submit','submitted_before_ack'):
                dst='Crash'+stage.split('_')[0]
                child=subprocess.Popen([sys.executable,str(Path(__file__).with_name('test_crash_worker.py')),str(home),str(node.rpc),stage,dst,bob['address']],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                out,_=child.communicate(password.encode()+b'\n',timeout=180)
                check('actual SIGKILL '+stage,child.returncode==-signal.SIGKILL and not out)
                if stage.startswith('restore'):
                    check('interrupted restore has no partial destination',not (home/(dst+'.wallet')).exists())
                else:
                    call(s,'open',name=dst,password=password);r=call(s,'refresh')
                    check('crash restart preserves submission reservation '+stage,len(r['outgoing'])==1)
                    if stage!='submitted_before_ack':
                        check('unreconciled crash is UNKNOWN '+stage,r['unknown_attempts']==1)
                        rejects('crash retry rejects '+stage,lambda:call(s,'prepare',**request))
                    else:check('lost acknowledgement reconciles to PENDING',r['outgoing'][0]['status']=='PENDING')
                    s.close()
            # Disk failure: existing file unchanged and no partial destination.
            original=c.read_private(home/'Bob.wallet')
            with patch.object(c.os,'fsync',side_effect=OSError('disk error')):
                rejects('disk fsync error rejects atomic save',lambda:c.save(home/'Bob.wallet',bw,password.encode(),replace=True))
            check('failed save preserves encrypted wallet bytes',c.read_private(home/'Bob.wallet')==original)
            c.save(home/'BadJournal.wallet',bw,password.encode());c.write_private(home/'BadJournal.wallet.gui-state',b'not-an-envelope')
            rejects('corrupted journal prevents wallet opening',lambda:call(s,'open',name='BadJournal',password=password))
            c.save(home/'FutureJournal.wallet',bw,password.encode());c.write_private(home/'FutureJournal.wallet.gui-state',f.seal(dict(version=2,wallet_id=f.wallet_id(bw),attempts=[]),password.encode(),'gui-pilot-state'))
            rejects('future journal version has no downgrade',lambda:call(s,'open',name='FutureJournal',password=password))
            trials=[]
            for _ in range(7):
                t=time.perf_counter();b=Bridge(home,node.rpc);hello=b.call('hello');launch=(time.perf_counter()-t)*1000
                t=time.perf_counter();b.call('open',name='Bob',password=password);opening=(time.perf_counter()-t)*1000
                t=time.perf_counter();b.call('refresh');pipe_scan=(time.perf_counter()-t)*1000;b.close()
                t=time.perf_counter();c.observe(bw,node.rpc);direct_scan=(time.perf_counter()-t)*1000
                trials.append(dict(backend_launch_ms=launch,open_ms=opening,pipe_refresh_ms=pipe_scan,direct_observe_ms=direct_scan,backend_rss_kib=hello['rss_kib']))
            metrics['trials']=trials;metrics['persistent_wallet_bytes']=sum(p.stat().st_size for p in home.iterdir() if p.is_file())
            evidence=dict(result='PASS_DECLARED_BACKEND_CASES',checks=checks,metrics=metrics,actual_pow_blocks=True,real_private_payment=True,actual_sigkill_stages=4,scope='Disposable loopback; not formal proof or independent audit. Full scan includes encryption/cache/journal overhead; direct observe excludes persistence.')
            raw=json.dumps(evidence,indent=2).encode();check('evidence excludes disposable secret encodings',all(x not in raw and x.hex().encode() not in raw for x in secrets))
            resultfile.write_bytes(json.dumps(evidence,indent=2).encode()+b'\n')
        finally:s.close();node.stop(crash=True)

rpc_original=w.rpc
if __name__=='__main__':main()
