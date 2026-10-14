"""Installed bound full nodes, actual localhost P2P only; no Tor activation.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];INST=Path('/home/privacydev/pc-production-binding-review-final-20261014/client')
sys.path.insert(0,str(INST));os.environ['PC_OFFLINE_BINDING']=str(INST/'candidate-native/full/BINDING.json');os.environ['PC_DEVNET_NATIVE_ROOT']=str(INST)
from apps.network_v1.candidate_rpc import Node
from apps.network_v1.candidate_profile import load
from apps.network_v1.candidate_client import load as module
from tools.creator_vesting.verify_native import Native
os.umask(0o077);home=Path('/home/privacydev/pc-candidate-profile-binding-peers-final-20261014');home.mkdir(mode=0o700,exist_ok=False)
profile=Path('/home/privacydev/pc-candidate-profile-binding-installed-final-20261014/public-profile.json');cfg=load(profile)
binary=INST/'candidate-native/full/draft-node';receipt=json.loads((INST/'candidate-native/full/BUILD.json').read_text());assert hashlib.sha256(binary.read_bytes()).hexdigest()==receipt['node']['binary_sha256']
processes=[];logs=[];checks=[];failure=None;start=time.monotonic();helper=None
def check(name,ok):
    if not ok:raise AssertionError(name)
    checks.append(name)
try:
    for name,rpc,p2p,peer in [('A',32181,32182,32192),('B',32191,32192,32182)]:
        log=(home/(name+'.log')).open('xb');logs.append(log)
        p=subprocess.Popen([str(binary),'--candidate-profile',str(profile),'--data-dir',str(home/name),'--rpc-port',str(rpc),'--p2p-port',str(p2p),'--peer-port',str(peer)],stdout=log,stderr=log,start_new_session=True);processes.append(p)
    end=time.monotonic()+15
    while True:
        if any(p.poll() is not None for p in processes):raise ValueError('OWNED_NODE_EXIT')
        try:A=Node(32181,cfg);B=Node(32191,cfg);break
        except (ValueError,OSError):
            if time.monotonic()>end:raise
            time.sleep(.05)
    check('independent bound full nodes start at approved creator supply',A.call(op='status')['creator_issued']==B.call(op='status')['creator_issued']=='159627169409884823')
    helper=Native(INST/'candidate-native/full/draft-ledger');g=helper.call(op='verify_genesis',block=cfg['block'],hash=cfg['genesis'])
    wallet=module('bound_p2p_wallet',INST/'src/phase4/wallet.py');f=wallet.foundation;f.HELPER=INST/'build/monero-linux/phase2/privacycoin-wallet-crypto'
    R,P=f.crypto('output',g['R'],g['outputs'][0]['key'],0,0)
    A.call(op='mine',R=R,P=P,timestamp=int(time.time())-240)
    end=time.monotonic()+30
    while B.call(op='status')['height']!=1:
        if time.monotonic()>end:raise TimeoutError('BOUND_NATIVE_SYNC')
        time.sleep(.05)
    check('actual native P2P block synchronization and identical tips',A.call(op='status')['tip']==B.call(op='status')['tip'])
    try:Node(32191,dict(cfg,genesis='a'*64))
    except ValueError:check('native RPC rejects incompatible pinned Genesis',True)
    else:raise AssertionError('wrong Genesis admitted')
    final=A.call(op='status');check('separate issuance after P2P validation',final['issued']=='35184372088831' and final['total_issued']=='159662353781973654')
except BaseException as e:failure=type(e).__name__+': '+str(e);raise
finally:
    if helper:helper.close()
    for p in processes:
        if p.poll() is None:p.terminate()
    for p in processes:
        try:p.wait(15)
        except subprocess.TimeoutExpired:p.kill();p.wait(5)
    for log in logs:log.close()
    result=dict(result='FAIL' if failure else 'PASS',failure=failure,checks=checks,seconds=round(time.monotonic()-start,3),exit_codes=[p.returncode for p in processes],scope='Real native localhost P2P; not Internet Tor; owned graceful termination')
    (ROOT/'docs/evidence/network-v1-production-binding-20261014/FINAL_P2P.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
