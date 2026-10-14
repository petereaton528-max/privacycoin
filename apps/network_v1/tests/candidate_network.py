"""Real candidate native nodes, ticket-free TLS, local SOCKS fixture only.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,base64,hashlib,json,os,secrets,socket,ssl,subprocess,sys,time
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--build',type=Path,required=True);p.add_argument('--native-root',type=Path,required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--payments',type=int,default=3);p.add_argument('--initial-blocks',type=int,default=80);a=p.parse_args()
    if not 1<=a.payments<=130:raise ValueError('PAYMENT_TEST_BOUND')
    if not 80<=a.initial_blocks<=400:raise ValueError('CHAIN_TEST_BOUND')
    if a.work.exists() or a.report.exists() or not a.work.name.startswith('pc-candidate-profile-'):raise ValueError('FRESH_PROFILE_REQUIRED')
    os.umask(0o077);a.work.mkdir(mode=0o700);profile_path=a.work/'public-profile.json'
    # Separate offline fixture authority. Other nodes receive only the public manifest.
    setup="from pathlib import Path;import sys;from apps.network_v1.candidate_client import Client;c=Client(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3]));c.create('Creator',b'DISPOSABLE TEST PASSWORD ONLY');Path(sys.argv[4]).write_text(c.f.canonical(c.profile).decode());c.close()"
    subprocess.run([sys.executable,'-B','-c',setup,str(a.work/'A'),str(a.build),str(a.native_root),str(profile_path)],check=True,timeout=40)
    os.environ['PC_DEVELOPMENT_NETWORK']='candidate-lab';os.environ['PC_CANDIDATE_PROFILE']=str(profile_path)
    os.environ['PC_DEVNET_NATIVE_ROOT']=str(a.native_root);os.environ['PC_DEVNET_BUILD_MANIFEST']=str(a.native_root/'build/v1-native-manifest.json')
    from apps.network_v1.candidate_profile import load,identity
    from apps.network_v1.candidate_rpc import Node
    from apps.network_v1.candidate_client import Client
    from apps.network_v1.public_network import PeerService
    from apps.network_v1.tests.local_socks import Socks
    profile=load(profile_path);network,genesis,context=identity(profile)
    nodes=[];clients=[];services=[];checks=[];socks=None;failure=None;start=time.monotonic();stamp=int(time.time())-120*600;timings=[];fees=[];window=None;owned=None
    def check(name,ok=True):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    reserved=set()
    def port():
        for _ in range(100):
            with socket.socket() as s:s.bind(('127.0.0.1',0));value=s.getsockname()[1]
            if value not in reserved:reserved.add(value);return value
        raise ValueError('NO_FRESH_PORT')
    def connector_range():
        # Keep connector blocks below Linux ephemeral allocation and skip any
        # active listener or TIME_WAIT reservation. Never stop another owner.
        for base in range(21000,26000,17):
            if any(p in reserved for p in range(base,base+8)):continue
            held=[]
            try:
                for n in range(base,base+8):s=socket.socket();held.append(s);s.bind(('127.0.0.1',n))
                reserved.update(range(base,base+8));return base
            except OSError:pass
            finally:
                for s in held:s.close()
        raise ValueError('NO_FRESH_CONNECTOR_RANGE')
    def wait(fn):
        end=time.monotonic()+90
        while time.monotonic()<end:
            try:
                value=fn()
                if value:return value
            except (ValueError,OSError):pass
            time.sleep(.05)
        raise TimeoutError('BOUNDED_NATIVE_INTEGRATION')
    try:
        used=[]
        for index,label in enumerate('ABC'):
            home=a.work/label;home.mkdir(mode=0o700,exist_ok=True);rpc=port();p2p=port();ingress=port()
            base=connector_range()
            args=[str(a.build/'draft-node'),'--candidate-profile',str(profile_path),'--data-dir',str(home/'chain'),'--rpc-port',str(rpc),'--p2p-port',str(p2p)]
            for n in range(base,base+8):args+=['--peer-port',str(n)]
            log=(home/'native.log').open('x');process=subprocess.Popen(args,stdout=log,stderr=log);nodes.append((process,log,args))
            backend=wait(lambda:Node(rpc,profile));client=Client(home,a.build,a.native_root,node=backend,profile=profile);clients.append(client)
            if index==0:client.open('Creator',b'DISPOSABLE TEST PASSWORD ONLY')
            else:client.create('Independent',('Test-'+secrets.token_hex(20)).encode())
            subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-keyout',str(home/'key'),'-out',str(home/'cert'),'-days','2','-subj','/CN=disposable-candidate-peer'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8)
            raw=secrets.token_bytes(32);onion=base64.b32encode(raw+hashlib.sha3_256(b'.onion checksum'+raw+b'\x03').digest()[:2]+b'\x03').decode().lower()+'.onion'
            descriptor=dict(version=1,network=network,genesis=genesis,profile=context,onion=onion,certificate_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert((home/'cert').read_text())).hexdigest())
            used.append((home,p2p,ingress,base,descriptor));(home/'key').chmod(0o600);(home/'cert').chmod(0o600)
        A,B,C=clients
        check('shared explicit Genesis, separate independent wallets',len({c.refresh()['address'] for c in clients})==3 and A.refresh()['total']==159627169409884823 and B.refresh()['total']==0)
        check('height-zero history contains all 17 allocation outputs',len(A.adapter.scan(A.wallet,A.node.call(op='history'))['owned'])==17)
        versions=A.node.rpc('status')
        check('native status separates consensus, transaction and proof versions',tuple(versions[k] for k in ('consensus_rules','transaction_format','proof_scheme','block_rules_version'))==(1,2,6,18))
        for _ in range(a.initial_blocks):stamp+=120;A.mine_one(stamp)
        socks=Socks({r[4]['onion']:r[2] for r in used},seed=17,connect_delay=.02,jitter=.002,chunk=97)
        for i,(home,p2p,ingress,base,descriptor) in enumerate(used):
            service=PeerService(ingress,p2p,base,socks.port,lambda d=descriptor:d,home/'key',home/'cert',[] if i==0 else [used[i-1][4]])
            services.append(service);service.start()
        wait(lambda:all(c.node.rpc('status')['height']==a.initial_blocks for c in clients))
        check('three real candidate nodes synchronize through ticket-free TLS and SOCKS')
        inventory=A.node.rpc('inventory');offset=0;ids=[]
        while offset<inventory['total']:
            page=A.node.rpc('inventory',offset=offset,count=7,cursor=inventory['cursor']);ids.extend(page['blocks']);offset=page['next']
        check('bounded cached inventory pages preserve complete native ordering',ids==inventory['blocks'] and len(set(ids))==len(ids))
        wait(lambda:used[0][4]['onion'] in services[2].directory.values)
        check('third node discovers additional peer without enrollment')
        recipient=C.refresh()['address']
        state=A.node.call(op='history');scan=A.adapter.scan(A.wallet,state)
        source=next(x['global_index'] for x in scan['owned'] if not x['spent'] and x['unlock']<=state['height'] and x['amount']>10**12+1)
        selection=[dict(source=source,ring=sorted([source]+[i for i in scan['eligible'] if i!=source][:15]))]
        D,Ckey,sub=A.binding.parse(recipient)
        low=A.w.helper(dict(op='build',draft_genesis=genesis,**A.w.request(A.wallet,A.w.construction_state(state,scan,selection)),sources=selection,destinations=[dict(D=D,C=Ckey,sub=sub,amount=10**12)],fee=1,dedicated_change=True))
        try:A.node.call(op='payment',transaction=low['transaction'])
        except ValueError:check('valid signed below-floor transaction refused without entering pool',not A.node.rpc('pool')['transactions'])
        else:raise AssertionError('relay fee guard absent')
        oldblock=A.node.rpc('get_block',hash=A.node.rpc('status')['tip'])['block']
        try:A.node.rpc('submit',block=oldblock,transactions=[low['transaction']])
        except ValueError:
            try:A.node.rpc('get_transaction',hash=low['id'])
            except ValueError:check('mismatched block bodies rejected without retaining transaction')
            else:raise AssertionError('rejected block leaked staged body')
        else:raise AssertionError('unmatched block transaction accepted')
        for i in range(a.payments):
            plan=A.prepare(recipient,10**12);size=len(A.prepared['transaction'])//2;t=time.monotonic();accepted=A.confirm(plan['id']);timings.append(time.monotonic()-t)
            fees.append(dict(bytes=size,fee_atomic=plan['fee'],minimum_relay_atomic=100*size,verify_ms=accepted['verify_ms']))
            wait(lambda:len(C.node.rpc('pool')['transactions'])==1)
            stamp+=120;A.mine_one(stamp)
            wait(lambda:C.node.rpc('status')['tip']==A.node.rpc('status')['tip'])
            check('relay and canonical payment '+str(i+1),A.refresh()['payment']=='CONFIRMED' and C.refresh()['total']==(i+1)*10**12)
        check('all payment intents retained and reconciled',A.payment_count==a.payments and not A.unresolved)
        if a.payments>128:check('confirmed history durably archived past 128 attempts',len(A.journal.root['archives'])==1 and len(A.journal.root['attempts'])==a.payments-128)
        if a.payments==3:
            # A valid small archived-history fixture from three REAL confirmed
            # transactions. Does not claim natural 128-attempt rollover here.
            store=A.journal.store;page=dict(version=1,wallet_id=A.journal.root['wallet_id'],attempts=A.journal.root['attempts'])
            A.journal.validate(page,A.wallet);raw=A.f.seal(page,A.password,'gui-journal-page-v1');digest=hashlib.sha256(raw).hexdigest()
            store.create_directory(store.directory);A.c.write_private(store.directory/(digest+'.page'),raw)
            A.journal.publish(dict(version=2,wallet_id=page['wallet_id'],archives=[digest],attempts=[]))
            check('small real-payment archive fixture remains reconciled',A.refresh()['payment']=='CONFIRMED' and A.payment_count==3)
        backup=a.work/'portable';A.backup(backup)
        recovered=Client(a.work/'Recovered',a.build,a.native_root,node=Node(A.node.port,profile),profile=profile);clients.append(recovered)
        from apps.network_v1.portable_backup import opened
        with opened(A.c,backup) as source:material=A.f.open_sealed(A.c.read_private(source),A.password,'pc-offline-candidate-portable/v1')
        check('complete backup is one file without sidecar',backup.is_file() and not Path(str(backup)+'.pages').exists())
        material['journal']['archives']=['f'*64]
        incomplete=a.work/'incomplete-backup';A.c.write_private(incomplete,A.f.seal(material,A.password,'pc-offline-candidate-portable/v1'))
        try:recovered.restore(incomplete,'Recovered',b'DISPOSABLE TEST PASSWORD ONLY')
        except (ValueError,OSError):check('missing archived backup refused before wallet publication',not recovered.path('Recovered').exists() and recovered.wallet is None)
        else:raise AssertionError('incomplete payment recovery accepted')
        original_write=recovered.c.write_private
        def interrupted_write(path,*args,**kw):
            if Path(path).name=='Interrupted.candidate-journal':raise OSError('controlled disposable restore interruption')
            return original_write(path,*args,**kw)
        recovered.c.write_private=interrupted_write
        try:
            try:recovered.restore(backup,'Interrupted',b'DISPOSABLE TEST PASSWORD ONLY')
            except OSError:pass
            else:raise AssertionError('restore interruption not reached')
        finally:recovered.c.write_private=original_write
        try:recovered.open('Interrupted',b'DISPOSABLE TEST PASSWORD ONLY')
        except ValueError:check('interrupted recovery remains durably locked',recovered.recovery_marker('Interrupted').exists() and recovered.wallet is None)
        else:raise AssertionError('partial restored wallet opened')
        recovered.close();recovered=Client(a.work/'Recovered',a.build,a.native_root,node=Node(A.node.port,profile),profile=profile);clients.append(recovered)
        try:recovered.open('Interrupted',b'DISPOSABLE TEST PASSWORD ONLY')
        except ValueError:check('fresh client refuses persisted incomplete recovery',recovered.wallet is None)
        else:raise AssertionError('reopen bypassed recovery marker')
        recovered.restore(backup,'Recovered',b'DISPOSABLE TEST PASSWORD ONLY')
        check('recovery retains payment history and owner balances',recovered.payment_count==a.payments and recovered.refresh()['total']==A.refresh()['total'])
        check('bounded history returns accurate original payments',len(recovered.payments(0,50))==min(a.payments,50) and all(r['state']=='CONFIRMED' for r in recovered.payments(0,50)))
        wrong=recipient.replace(genesis,'0'*64,1)
        try:A.prepare(wrong,10**12)
        except ValueError:check('cross-Genesis address rejected before signing')
        else:raise AssertionError('cross-Genesis accepted')
        # Restart one owned native process, preserving its independent database.
        process,log,args=nodes[2];process.terminate();process.wait(15);log.close();log=(a.work/'C'/'restart.log').open('x')
        process=subprocess.Popen(args,stdout=log,stderr=log);nodes[2]=(process,log,args)
        wait(lambda:C.node.rpc('status')['tip']==A.node.rpc('status')['tip'])
        check('candidate native restart preserves tip, supply and recovered wallet',C.refresh()['total']==a.payments*10**12)
        mined_before=A.node.rpc('status')['mined'];progress=[];A.mine_one(progress=progress.append)
        wait(lambda:all(c.node.rpc('status')['tip']==A.node.rpc('status')['tip'] for c in clients[:3]))
        check('asynchronous private mining validates and propagates real reward',A.node.rpc('status')['mined']==mined_before+1 and bool(progress))
        import threading
        cancelled=threading.Event();cancelled.set();before=A.node.rpc('status')['height'];A.mine_one(cancel=cancelled)
        check('cancelled mining job never starts new work',A.node.rpc('status')['height']==before and not A.node.rpc('status')['mining'])
        import tkinter as tk
        from apps.network_v1.candidate_gui import Window
        root=tk.Tk();root.withdraw();window=Window(root,recovered);window.refresh()
        end=time.monotonic()+30
        while window.busy and time.monotonic()<end:root.update();time.sleep(.01)
        check('real Tk GUI displays recovered full-node available and locked balances',not window.busy and not window.last_error and window.last['total']==A.refresh()['total'] and window.last['locked']>=143664452468896341)
        window.shutdown();window=None
        final=[c.node.rpc('status') for c in clients[:3]]
        check('all final canonical tips and supply counters match',len({(s['tip'],s['work'],s['issued'],s['creator_issued'],s['total_issued']) for s in final})==1)
        from apps.network_v1.candidate_runtime import Runtime
        owned=Runtime(a.work/'Owned',a.build,profile_path,rpc_port=port(),p2p_port=port(),connector_base=connector_range())
        pid=owned.process.pid
        check('owned runtime starts pinned candidate without wallet-derived Genesis',owned.rpc('status')['height']==0)
        try:owned.connect_tor(a.native_root/'runtime/bin/tor',[],None,'NOT AUTHORIZED')
        except ValueError:check('Tor activation rejects missing explicit consent before preparation',owned.tor is None and not (a.work/'Owned'/'tor').exists())
        else:raise AssertionError('Tor consent bypass')
        owned.close();check('owned runtime exits cleanly without touching independent nodes',owned.process.returncode==0 and all(p.poll() is None for p,_,_ in nodes))
    except BaseException as error:failure=type(error).__name__+': '+str(error);print('FAIL '+failure,flush=True)
    finally:
        if owned:owned.close()
        if window:window.shutdown()
        for c in clients:c.close()
        for service in services:service.close()
        if socks:socks.close()
        exits=[]
        for process,log,args in nodes:
            if process.poll() is None:process.terminate()
            try:process.wait(15)
            except subprocess.TimeoutExpired:process.kill();process.wait();failure=failure or 'OWNED_PROCESS_FORCED_STOP'
            exits.append(process.returncode);log.close()
        report=dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=round(time.monotonic()-start,3),native_exit_codes=exits,payment_count=len(timings),payment_submit_seconds=timings,fee_measurements=fees,real_native=True,real_tls=True,simulated_local_socks=True,internet_tor=False,mainnet=False)
        with a.report.open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    if failure:raise SystemExit(1)
if __name__=='__main__':main()
