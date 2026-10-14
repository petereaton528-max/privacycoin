"""Offline installed regression for public ingress budgets; no external Tor.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json,os,shutil,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parents[1]
base=Path('/home/privacydev/pc-upgrade-installed-20261013')
target=Path('/home/privacydev/pc-public-budgets-final-installed-20261013')
e=root/'docs/evidence/network-v1-public-budgets-20261013/final'
os.umask(0o077);e.mkdir(parents=True,exist_ok=True)
assert not target.exists()
manifest=json.loads((base/'V1_MANIFEST.json').read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert all(sha(base/n)==h for n,h in manifest['files'].items())
shutil.copytree(base,target)
for name in ('apps/network_v1/public_network.py','apps/network_v1/tests/test_public_budgets.py','apps/network_v1/candidate_journal.py','apps/network_v1/candidate_client.py','apps/network_v1/tests/candidate_network.py'):
    shutil.copyfile(root/name,target/name);manifest['files'][name]=sha(target/name)
(target/'V1_MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
env=dict(os.environ,PYTHONHOME=str(target/'runtime/python'),LD_LIBRARY_PATH=str(target/'runtime/lib'),TCL_LIBRARY=str(target/'runtime/tcltk/tcl8.6'),TK_LIBRARY=str(target/'runtime/tcltk/tk8.6'),PC_DEVELOPMENT_NETWORK='open-dev02',PYTHONNOUSERSITE='1',PC_DEVNET_NATIVE_ROOT=str(target),PC_DEVNET_BUILD_MANIFEST=str(target/'build/v1-native-manifest.json'))
env.pop('PYTHONPATH',None)
commands=[('guards',['-m','unittest','apps.network_v1.tests.test_public_budgets','apps.network_v1.tests.test_public_network','apps.network_v1.tests.test_peer_lifecycle','-v']),('native',['-m','apps.network_v1.tests.candidate_network','--build',str(target/'candidate-native/full'),'--native-root',str(target),'--work','/home/privacydev/pc-candidate-profile-public-budgets-final-20261013','--report',str(target/'budget-native-results.json'),'--payments','3','--initial-blocks','80'])]
results=[]
for name,args in commands:
    start=time.monotonic()
    with (e/(name+'.log')).open('x') as log:
        r=subprocess.run([str(target/'runtime/python/bin/python3'),'-B',*args],cwd=target,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=240)
    results.append(dict(name=name,exit=r.returncode,seconds=time.monotonic()-start))
    (e/'RESULTS.json').write_text(json.dumps(dict(checks=results,external_tor=False,installed=str(target)),indent=2)+'\n')
    if r.returncode:raise SystemExit(r.returncode)
shutil.copyfile(target/'budget-native-results.json',e/'NATIVE.json')
