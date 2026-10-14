"""Run only affected suites against the exact extracted review artifact.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import json,os,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
INST=Path('/home/privacydev/pc-production-binding-review-final-20261014/client')
REPORT=ROOT/'docs/evidence/network-v1-production-binding-20261014'
env=dict(os.environ,PYTHONHOME=str(INST/'runtime/python'),PYTHONNOUSERSITE='1',LD_LIBRARY_PATH=str(INST/'runtime/lib'),TCL_LIBRARY=str(INST/'runtime/tcltk/tcl8.6'),TK_LIBRARY=str(INST/'runtime/tcltk/tk8.6'),PC_DEVNET_NATIVE_ROOT=str(INST),PC_DEVELOPMENT_NETWORK='open-dev02')
env.pop('PC_OFFLINE_BINDING',None)
python=str(INST/'runtime/python/bin/python3')
tests=['tools.mainnet_prepare.test_binding','apps.network_v1.tests.test_candidate_amounts','apps.network_v1.tests.test_candidate_cache','apps.network_v1.tests.test_candidate_mining','apps.network_v1.tests.test_public_budgets','apps.network_v1.tests.test_public_network','apps.network_v1.tests.test_portable_backup']
commands=[('FINAL_UNIT',['-m','unittest',*tests,'-v']),('FINAL_BINDING',['-m','tools.mainnet_prepare.verify_binding','--build',str(INST/'candidate-native/full'),'--root',str(INST),'--work','/home/privacydev/pc-candidate-profile-binding-installed-final-20261014','--report',str(REPORT/'FINAL_BINDING.json')]),('FINAL_CONSENSUS',['-m','tools.creator_vesting.verify_native','--build',str(INST/'candidate-native/full'),'--native-root',str(INST),'--work','/home/privacydev/pc-vesting-fixture-bound-installed-final-20261014','--report',str(REPORT/'FINAL_CONSENSUS.json')])]
for name,args in commands:
    start=time.monotonic()
    with (REPORT/(name+'.log')).open('x') as log:
        result=subprocess.run([python,'-B',*args],cwd=INST,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240)
    value=dict(exit=result.returncode,seconds=round(time.monotonic()-start,3),installed=str(INST),command=[python,'-B',*args])
    (REPORT/(name+'-EXIT.json')).write_text(json.dumps(value,indent=2)+'\n')
    print(name+' '+json.dumps(value),flush=True)
    if result.returncode:raise SystemExit(result.returncode)
