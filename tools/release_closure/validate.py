"""Final extracted owner-review artifact checks, local disposable services only.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,shutil,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--destination',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);a=p.parse_args()
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT));os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02'
from apps.network_v1.release import install
os.umask(0o077);a.evidence.mkdir(parents=True,exist_ok=False);install(a.archive,a.destination)
t=a.destination;env=dict(os.environ,PYTHONHOME=str(t/'runtime/python'),PYTHONNOUSERSITE='1',LD_LIBRARY_PATH=str(t/'runtime/lib'),TCL_LIBRARY=str(t/'runtime/tcltk/tcl8.6'),TK_LIBRARY=str(t/'runtime/tcltk/tk8.6'),PC_DEVNET_NATIVE_ROOT=str(t),PC_DEVNET_BUILD_MANIFEST=str(t/'build/v1-native-manifest.json'));env['PYTHONPATH']=str(t)
commands=[('guards',['-m','unittest','apps.network_v1.tests.test_public_budgets','apps.network_v1.tests.test_public_network','apps.network_v1.tests.test_peer_lifecycle','apps.network_v1.tests.test_portable_backup','apps.network_v1.tests.test_candidate_cache','apps.network_v1.tests.test_candidate_mining','-v']),('native',['-m','apps.network_v1.tests.candidate_network','--build',str(t/'candidate-native/full'),'--native-root',str(t),'--work','/home/privacydev/pc-candidate-profile-release-closure-final-20261013','--report',str(a.evidence/'NATIVE.json'),'--payments','3','--initial-blocks','80']),('consensus',['-m','tools.creator_vesting.verify_native','--build',str(t/'candidate-native/full'),'--native-root',str(t),'--work','/home/privacydev/pc-vesting-fixture-release-closure-final-20261013','--report',str(a.evidence/'CONSENSUS.json')])]
commands.append(('hostile',[str(t/'tools/release_closure/hostile_native.py'),'--root',str(t),'--work','/home/privacydev/pc-candidate-profile-hostile-final-20261013','--report',str(a.evidence/'HOSTILE.json')]))
results=[]
for name,args in commands:
    start=time.monotonic()
    with (a.evidence/(name+'.log')).open('x') as log:r=subprocess.run([str(t/'runtime/python/bin/python3'),'-B',*args],cwd=t,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=300)
    results.append(dict(name=name,exit=r.returncode,seconds=time.monotonic()-start));print(name,r.returncode,flush=True)
    (a.evidence/'RESULTS.json').write_text(json.dumps(dict(archive_sha256=hashlib.sha256(a.archive.read_bytes()).hexdigest(),installed=str(t),checks=results,external_tor=False,mainnet=False),indent=2)+'\n')
    if r.returncode:raise SystemExit(r.returncode)
manifest=json.loads((t/'V1_MANIFEST.json').read_text());assert all(hashlib.sha256((t/n).read_bytes()).hexdigest()==h for n,h in manifest['files'].items())
print('Final installed files unchanged; all checks passed')
