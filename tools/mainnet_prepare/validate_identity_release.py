"""Focused final extracted-package validation; preserve previous test profiles.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,json,os,subprocess,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--installed',type=Path,required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--work',type=Path,required=True);a=p.parse_args()
    i=a.installed;python=str(i/'runtime/python/bin/python3');build=i/'candidate-native/full'
    env=dict(os.environ,PYTHONHOME=str(i/'runtime/python'),PYTHONNOUSERSITE='1',LD_LIBRARY_PATH=str(i/'runtime/lib'),TCL_LIBRARY=str(i/'runtime/tcltk/tcl8.6'),TK_LIBRARY=str(i/'runtime/tcltk/tk8.6'),PC_DEVNET_NATIVE_ROOT=str(i),PC_DEVELOPMENT_NETWORK='open-dev02')
    env.pop('PC_OFFLINE_BINDING',None);env.pop('PC_CANDIDATE_PROFILE',None)
    tests=['tools.mainnet_prepare.test_binding','tools.mainnet_prepare.test_identity_proposal','apps.network_v1.tests.test_public_context','apps.network_v1.tests.test_public_network','apps.network_v1.tests.test_public_budgets','apps.network_v1.tests.test_portable_backup']
    commands=[('INSTALLED_UNIT',['-m','unittest',*tests,'-v']),('INSTALLED_BINDING',['-m','tools.mainnet_prepare.verify_binding','--build',str(build),'--root',str(i),'--work',str(a.work),'--report',str(a.report/'INSTALLED_BINDING.json')]),('INSTALLED_TRANSPORT',['-m','tools.mainnet_prepare.verify_bound_transport','--installed',str(i),'--profile',str(a.work/'public-profile.json'),'--work',str(a.work)+'-transport','--report',str(a.report/'INSTALLED_TRANSPORT.json')])]
    for name,args in commands:
        began=time.monotonic()
        with (a.report/(name+'.log')).open('x') as log:
            result=subprocess.run([python,'-B',*args],cwd=i,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
        value=dict(exit=result.returncode,seconds=round(time.monotonic()-began,3),installed=str(i),command=[python,'-B',*args])
        (a.report/(name+'-EXIT.json')).write_text(json.dumps(value,indent=2)+'\n');print(name+' '+json.dumps(value),flush=True)
        if result.returncode:raise SystemExit(result.returncode)
if __name__=='__main__':main()
