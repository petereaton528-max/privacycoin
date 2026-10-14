"""Actual installed-package checks; only fresh private local state.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,secrets,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))

def smoke(base):
    os.umask(0o077);base.mkdir(parents=True,exist_ok=False)
    os.environ.update(PC_DEVNET_NATIVE_ROOT=str(ROOT),PC_DEVNET_BUILD_MANIFEST=str(ROOT/'build/v1-native-manifest.json'))
    sys.path.insert(0,str(ROOT/'services/privacy-network'))
    from common import c,f,w,native
    from backend import Session
    h=native('installed_sphlib_nodes','tests/phase4/gates.py')
    c.harden();os.sched_setaffinity(0,sorted(os.sched_getaffinity(0))[:2])
    node=h.Node(base,'node');session=None;checks=[]
    def check(name,ok):assert ok,name;checks.append(name)
    try:
        node.start();check('installed backend starts at unchanged genesis',node.status()['height']==0 and node.status()['tip']==w.GENESIS)
        wallet_home=base/'wallets';wallet_home.mkdir(mode=0o700)
        session=Session(wallet_home,node.rpc);password=secrets.token_hex(32)
        created=session.dispatch(dict(command='create',name='Isolated',password=password))
        session.dispatch(dict(command='backup',name='Recovery'))
        original_id=f.wallet_id(session.wallet);session.close()
        restored=session.dispatch(dict(command='restore',name='Restored',backup='Recovery',password=password))
        check('installed real wallet encrypted backup restores same ownership',f.wallet_id(session.wallet)==original_id and restored['address']==created['address'])
        # No mining/payment here: their complete flows already passed integration.
        node.stop();node.start();check('installed node cold restart retains genesis and empty chain',node.status()['height']==0 and node.status()['tip']==w.GENESIS)
        return dict(result='PASS',checks=checks,mining=False,payments=False,tor_started=False,original_n2_access=False)
    finally:
        if session:session.close()
        node.stop(crash=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True)
    p.add_argument('--directory',type=Path);p.add_argument('--smoke',action='store_true');a=p.parse_args()
    if a.smoke:
        report=smoke(a.base);print(json.dumps(report));return
    from apps.network_v1.release import install,create_private_parent
    rows=[]
    for name in ('privacycoin-rc5-linux-sphlib.zip','privacycoin-rc5-wsl2-sphlib.zip'):
        parent=a.base/name.removesuffix('.zip');dest=parent/'app'
        create_private_parent(dest);start=time.monotonic();install(a.directory/name,dest)
        env=dict(os.environ,PYTHONHOME=str(dest/'runtime/python'),PYTHONNOUSERSITE='1',LD_LIBRARY_PATH=str(dest/'runtime/lib'))
        for n in ('PYTHONPATH','PYTHONSTARTUP','PYTHONINSPECT','PYTHONSAFEPATH','PYTHONPLATLIBDIR','PYTHONOPTIMIZE','PC_DEVNET_NATIVE_ROOT','PC_DEVNET_BUILD_MANIFEST'):env.pop(n,None)
        python=dest/'runtime/python/bin/python3'
        commands=[['-m','unittest','apps.network_v1.tests.test_licensing','apps.network_v1.tests.test_release','apps.network_v1.tests.test_application','-v'],
                  ['-m','experiments.sphlib.install_validate','--smoke','--base',str(parent/'private-smoke')]]
        outcomes=[]
        for args in commands:
            cmd=[str(python),'-B',*args]
            result=subprocess.run(cmd,cwd=dest,env=env,capture_output=True,timeout=120)
            text=(result.stdout+result.stderr).decode(errors='replace')
            assert result.returncode==0,text
            outcomes.append(dict(command=cmd,exit=result.returncode,output=text))
        rows.append(dict(package=name,sha256=hashlib.sha256((a.directory/name).read_bytes()).hexdigest(),destination=str(dest),seconds=round(time.monotonic()-start,3),outcomes=outcomes))
        print('INSTALLED_SPHLIB_PASS',name,flush=True)
    (a.directory/'installation-validation.json').write_text(json.dumps(dict(result='PASS',packages=rows,unfamiliar_user_acceptance=False,physical_host_validation=False),indent=2)+'\n')
if __name__=='__main__':main()
