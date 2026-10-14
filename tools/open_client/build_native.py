"""Build selected native sources into a NEW directory using retained licensed libs.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,shlex,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--cache',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
config=a.cache/'CMakeFiles/privacycoin-hardened-devnet.dir'
flags={}
for line in (config/'flags.make').read_text().splitlines():
    if ' = ' in line:
        key,value=line.split(' = ',1);flags[key]=shlex.split(value)
commands=[];objects=[]
for name in ('ledger','node'):
    src=ROOT/('src/phase4/'+name+'.cpp');obj=a.output/(name+'.o')
    command=['/usr/bin/c++',*flags['CXX_DEFINES'],*flags['CXX_INCLUDES'],*flags['CXX_FLAGS'],'-c',str(src),'-o',str(obj)]
    commands.append(command)
    with (a.output/(name+'.log')).open('w') as log:subprocess.run(command,cwd=a.cache,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
    objects.append(str(obj))
link=shlex.split((config/'link.txt').read_text());replaced=[];index=0
while index<len(link):
    value=link[index]
    if value=='-o':replaced+=['-o',str(a.output/'privacycoin-hardened-devnet')];index+=2;continue
    if value.endswith('.o'):
        if objects:replaced.append(objects.pop(0))
    else:replaced.append(value)
    index+=1
commands.append(replaced)
with (a.output/'link.log').open('w') as log:subprocess.run(replaced,cwd=a.cache,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
deps={str((a.cache/v).resolve()):sha((a.cache/v).resolve()) for v in link if v.endswith('.a') and (a.cache/v).is_file()}
record=dict(commands=commands,dependencies_sha256=deps,source_sha256={str(p.relative_to(ROOT)):sha(p) for p in [ROOT/'src/phase4/ledger.h',ROOT/'src/phase4/ledger.cpp',ROOT/'src/phase4/node.cpp']},binary_sha256=sha(a.output/'privacycoin-hardened-devnet'),scope='Fresh node compilation and link; retained integrated sphlib libraries; no cache output overwritten')
(a.output/'BUILD.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(dict(result='PASS',output=str(a.output),binary_sha256=record['binary_sha256'])))
