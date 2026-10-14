"""Final extracted client: real native local peers, disposable wallets and Tk.
No external networking and no founder custody. No Genesis generation.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,socket,subprocess,time
from pathlib import Path
def main():
    p=argparse.ArgumentParser();p.add_argument('--installed',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    os.umask(0o077);a.work.mkdir(mode=0o700,exist_ok=False)
    root=a.installed;build=root/'candidate-native/full'
    os.environ.update(PC_OFFLINE_BINDING=str(build/'BINDING.json'),PC_CANDIDATE_PROFILE=str(build/'PROFILE.json'),PC_DEVELOPMENT_NETWORK='mainnet-v1',PC_DEVNET_NATIVE_ROOT=str(root))
    from .production import profile,G
    from .genesis_finalization import native_call,process
    from apps.network_v1.candidate_client import Client
    from apps.network_v1.candidate_rpc import Node
    from apps.network_v1.public_network import require_public_context
    from tools.creator_model.binding import GenesisAddress
    cfg=profile();checks=[];procs=[];clients=[];logs=[];began=time.monotonic();failure=None
    def check(name,ok):
        if not ok:raise AssertionError(name)
        checks.append(name);print('PASS '+name,flush=True)
    def reject(name,fn):
        try:fn()
        except (ValueError,OSError):check(name,True);return
        raise AssertionError(name)
    def wait(fn,seconds=45):
        until=time.monotonic()+seconds
        while not fn():
            if any(p.poll() is not None for p in procs):raise ValueError('OWNED_NODE_EXIT')
            if time.monotonic()>until:raise TimeoutError('LOCAL_SYNC_TIMEOUT')
            time.sleep(.1)
    try:
        for port in (32481,32482,32491,32492):
            with socket.socket() as s:s.bind(('127.0.0.1',port))
        helper=build/'draft-ledger';digest=hashlib.sha256(helper.read_bytes()).hexdigest()
        native=process(helper,digest,dict(block=cfg['block'],hash=G),expected_commitment=cfg['commitment'])
        check('final native Genesis/supply/seventeen output verification',native['creator_atomic']==159627169409884823 and native['mining_atomic']==0 and len(native['public_plan']['outputs'])==17)
        reject('production native refuses another Genesis',lambda:native_call(helper,digest,dict(op='genesis')))
        reject('production native refuses substituted Genesis',lambda:native_call(helper,digest,dict(op='verify_genesis',block=cfg['block'],hash='a'*64)))
        for label,rpc,p2p,peer in [('A',32481,32482,32492),('B',32491,32492,32482)]:
            home=a.work/label;home.mkdir(mode=0o700)
            log=(home/'node.log').open('xb');logs.append(log)
            procs.append(subprocess.Popen([str(build/'draft-node'),'--candidate-profile',str(build/'PROFILE.json'),'--data-dir',str(home/'chain'),'--rpc-port',str(rpc),'--p2p-port',str(p2p),'--peer-port',str(peer)],stdout=log,stderr=log,start_new_session=True))
        def ready():
            try:Node(32481,cfg);Node(32491,cfg);return True
            except (OSError,ValueError):return False
        wait(ready,20)
        A=Client(a.work/'wallet-A',build,root,node=Node(32481,cfg),profile=cfg);clients.append(A)
        B=Client(a.work/'wallet-B',build,root,node=Node(32491,cfg),profile=cfg);clients.append(B)
        password=b'disposable-release-test-only-password'
        sa=A.create('DisposableA',password);sb=B.create('DisposableB',password)
        check('independent ordinary wallets own no creator allocation',sa['total']==sb['total']==0 and sa['address']!=sb['address'])
        check('G-bound Mainnet address and transport identity',len(sa['address'])==293 and sa['address'].startswith('PCmn1-'+G) and require_public_context()[1]==G)
        reject('wrong password rejected',lambda:A.open('DisposableA',b'incorrect-password'))
        reject('Devnet address rejected',lambda:A.binding.parse('PCdv1-'+sa['address'][6:]))
        reject('wrong Genesis address rejected',lambda:GenesisAddress(A.f,A.tag,'b'*64,'PCmn1-').parse(sa['address']))
        stamp=int(time.time())-120*100
        for i in range(80):A.mine_one(timestamp=stamp+120*i)
        wait(lambda:B.node.call(op='status')['height']==80)
        check('native mining and initial full-node sync',A.node.call(op='status')['tip']==B.node.call(op='status')['tip'])
        check('mining rewards mature and private wallet scans',A.refresh()['available']>10**12)
        plan=A.prepare(sb['address'],10**12);A.confirm(plan['id'])
        reject('duplicate confirmation rejected',lambda:A.confirm(plan['id']))
        A.mine_one(timestamp=stamp+120*80)
        wait(lambda:B.node.call(op='status')['height']==81)
        check('private payment confirmed and received',A.refresh()['payment']=='CONFIRMED' and B.refresh()['total']==10**12)
        backup=a.work/'complete-backup';A.backup(backup)
        recovered=Client(a.work/'wallet-recovered',build,root,node=Node(32481,cfg),profile=cfg);clients.append(recovered)
        rs=recovered.restore(backup,'Recovered',password)
        check('independent complete encrypted recovery balance/history/address',rs['address']==sa['address'] and rs['total']==A.refresh()['total'] and recovered.payments()==A.payments())
        import tkinter as tk
        from apps.network_v1.candidate_gui import Window
        gui=tk.Tk();window=Window(gui,recovered)
        try:
            window.show(rs);gui.update();window.copy();gui.update()
            check('real Tk production view and complete address copy',gui.clipboard_get()==rs['address'] and 'Mainnet V1' in gui.title())
        finally:gui.after_cancel(window.poll_id);gui.destroy()
        final=A.node.call(op='status')
        check('separate creator/miner supply and equal canonical tips',int(final['creator_issued'])==159627169409884823 and int(final['issued'])>0 and final['tip']==B.node.call(op='status')['tip'])
        for c in clients:c.close()
        clients=[]
        for proc in procs:proc.terminate()
        for proc in procs:proc.wait(15)
        procs=[]
        # Reload by the native ledger revalidates actual stored blocks and PoW.
        from tools.creator_vesting.verify_native import Native
        node=Native(helper)
        try:
            node.call(op='open',path=str(a.work/'A/chain'),block=cfg['block'],hash=G)
            restored=node.call(op='status')
            check('native persisted chain reload and issuance',restored['tip']==final['tip'] and restored['creator']==final['creator_issued'] and restored['mining']==final['issued'])
        finally:node.close()
    except BaseException as error:failure=type(error).__name__+': '+str(error);raise
    finally:
        for c in clients:c.close()
        for proc in procs:
            if proc.poll() is None:proc.terminate()
        for proc in procs:
            try:proc.wait(15)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(5)
        for log in logs:log.close()
        remaining=[]
        for port in (32481,32482,32491,32492):
            with socket.socket() as s:
                if s.connect_ex(('127.0.0.1',port))==0:remaining.append(port)
        result=dict(status='FAIL' if failure or remaining else 'PASS',failure=failure,checks=checks,seconds=round(time.monotonic()-began,3),remaining_test_listeners=remaining,internet_tor=False,founder_custody_accessed=False,scope='Installed real native local peers and disposable ordinary wallets on isolated approved-G copies; no public network')
        a.report.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if __name__=='__main__':main()
