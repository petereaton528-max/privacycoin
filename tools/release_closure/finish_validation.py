"""Resume only checks not executed by the initial installed validation runner.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import json,os,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];e=ROOT/'docs/evidence/network-v1-release-closure-20261013';t=Path('/home/privacydev/pc-owner-review-private-20261013/client')
env=dict(os.environ,PYTHONHOME=str(t/'runtime/python'),PYTHONPATH=str(t),PYTHONNOUSERSITE='1',LD_LIBRARY_PATH=str(t/'runtime/lib'),PC_DEVELOPMENT_NETWORK='open-dev02',PC_DEVNET_NATIVE_ROOT=str(t),PC_DEVNET_BUILD_MANIFEST=str(t/'build/v1-native-manifest.json'))
commands=[('consensus-final',['-m','tools.creator_vesting.verify_native','--build',str(t/'candidate-native/full'),'--native-root',str(t),'--work','/home/privacydev/pc-vesting-fixture-release-closure-20261013','--report',str(e/'CONSENSUS.json')]),('hostile-native',[str(ROOT/'tools/release_closure/hostile_native.py'),'--root',str(t),'--work','/home/privacydev/pc-candidate-profile-hostile-closure-20261013','--report',str(e/'HOSTILE.json')])]
results=[]
for name,args in commands:
    start=time.monotonic()
    with (e/(name+'.log')).open('x') as log:r=subprocess.run([str(t/'runtime/python/bin/python3'),'-B',*args],cwd=t,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
    results.append(dict(name=name,exit=r.returncode,seconds=time.monotonic()-start));print(name,r.returncode,flush=True)
    (e/'FINISH.json').write_text(json.dumps(results,indent=2)+'\n')
    if r.returncode:raise SystemExit(r.returncode)
