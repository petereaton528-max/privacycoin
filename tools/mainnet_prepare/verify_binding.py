"""Real native Genesis reconstruction, full-node/wallet/GUI binding checks.
Only disposable local state; never starts Tor.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,copy,hashlib,json,os,secrets,socket,time
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--root',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    os.umask(0o077)
    if a.work.exists() or not a.work.name.startswith('pc-candidate-profile-binding-'):raise ValueError('FRESH_DISPOSABLE_WORK_REQUIRED')
    a.work.mkdir(mode=0o700);os.environ['PC_OFFLINE_BINDING']=str(a.build/'BINDING.json')
    from apps.network_v1.candidate_client import Client
    from apps.network_v1.candidate_runtime import Runtime
    from apps.network_v1.candidate_profile import bound_context,verify_build
    from tools.creator_vesting.verify_native import Native
    checks=[];clients=[];nodes=[];began=time.monotonic();failure=None;gui_executed=False
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    def reject(name,call):
        try:call()
        except (ValueError,OSError):check(name,True);return
        raise AssertionError(name)
    try:
        c=Client(a.work/'creator',a.build,a.root);clients.append(c)
        password=secrets.token_bytes(32);initial=c.create('Disposable',password)
        check('real native 17-output wallet allocation and vesting',initial['total']==159627169409884823 and initial['available']==15962716940988482 and initial['locked']==143664452468896341)
        public=c.node.call(op='verify_genesis',block=c.profile['block'],hash=c.profile['genesis'])
        request=dict(op='reconstruct_genesis',R=public['R'],outputs=public['outputs'],commitment=public['commitment'])
        other=Native(a.build/'draft-ledger');nodes.append(other)
        replay=other.call(**request)
        check('independent native canonical reconstruction identical bytes and hash',replay['block']==public['block'] and replay['hash']==public['hash'])
        from tools.mainnet_prepare.genesis_artifact import process
        checked=process(a.build/'draft-ledger',hashlib.sha256((a.build/'draft-ledger').read_bytes()).hexdigest(),{k:public[k] for k in ('block','hash')})
        check('pinned public-artifact verifier separate-process roundtrip',checked['artifact']['hash']==public['hash'] and not checked['production_approved'])
        check('supply verified without claiming public recipient ownership',replay['creator_atomic']==159627169409884823 and replay['mining_atomic']==0 and replay['recipient_ownership_proven'] is False)
        for key,value in [('atomic',1),('unlock',1),('key',public['outputs'][1]['key'])]:
            bad=copy.deepcopy(request);bad['outputs'][0][key]=value;reject('reject public plan '+key,lambda bad=bad:other.call(**bad))
        bad=copy.deepcopy(request);bad['outputs'].pop();reject('reject missing tranche',lambda:other.call(**bad))
        reject('reject mismatched artifact hash',lambda:other.call(op='verify_genesis',block=public['block'],hash='0'*64))
        reject('reject incompatible commitment',lambda:other.call(**dict(request,commitment='wrong-network')))
        backup=a.work/'encrypted-backup';c.backup(backup)
        profile=a.work/'public-profile.json';profile.write_text(json.dumps(c.profile));profile.chmod(0o600)
        # Reserve-check a fresh bounded port set without touching existing nodes.
        ports=list(range(31481,31483))+list(range(31490,31498))
        for port in ports:
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',port));s.listen(1)
        runtime=Runtime(a.work/'node',a.build,profile,31481,31482,31490);nodes.append(runtime)
        rc=Client(a.work/'recovered',a.build,a.root,node=runtime,profile=c.profile);clients.append(rc)
        result=rc.restore(backup,'Restored',password)
        check('full-node encrypted recovery recognizes height-zero allocation',all(result[k]==initial[k] for k in ('total','available','locked','height')))
        check('bound address prefix and native network identity',result['address'].startswith('PCbt1-') and runtime.identity[0]=='PCBindingTest001')
        reject('Devnet/laboratory address rejected',lambda:rc.binding.parse('PClab1-'+result['address'][len('PCbt1-'):]))
        wrong=copy.deepcopy(json.loads((a.build/'BUILD.json').read_text()));wrong['binding_sha256']='0'*64
        reject('compiled/runtime binding mismatch rejected',lambda:verify_build(wrong))
        fresh=Client(a.work/'bad-recovery',a.build,a.root);clients.append(fresh)
        reject('wrong backup password rejected',lambda:fresh.restore(backup,'NoWallet',b'incorrect-password'))
        check('wrong recovery publishes no wallet',not fresh.path('NoWallet').exists())
        # Actual Tk window and rendering with real full-node wallet state.
        import tkinter as tk
        from apps.network_v1.candidate_gui import Window
        root=tk.Tk();window=Window(root,rc)
        try:
            window.show(result);root.update();gui_executed=True
            check('real GUI renders bound wallet balances',window.address.get()==result['address'] and '159627.169409884823' in window.summary.get())
        finally:root.after_cancel(window.poll_id);root.destroy()
        rc.mine_one();state=rc.refresh()
        check('native CPU mining unaffected creator counter',state['height']==1 and int(state['node']['creator_issued'])==159627169409884823 and int(state['node']['issued'])==35184372088831)
        tip=state['node']['tip'];rc.close();clients.remove(rc);nodes.remove(runtime)
        restarted=Runtime(a.work/'node',a.build,profile,31481,31482,31490);nodes.append(restarted)
        again=Client(a.work/'recovered',a.build,a.root,node=restarted,profile=c.profile);clients.append(again)
        state=again.open('Restored',password)
        check('persistent chain wallet supply survive restart',state['height']==1 and state['node']['tip']==tip and state['total']==159627169409884823+35184372088831 and state['available']==15962716940988482)
    except BaseException as e:failure=type(e).__name__+': '+str(e);raise
    finally:
        for c in reversed(clients):c.close()
        for n in reversed(nodes):n.close()
        result=dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=round(time.monotonic()-began,3),native=True,gui=gui_executed,tor=False,production_keys=False)
        a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if __name__=='__main__':main()
