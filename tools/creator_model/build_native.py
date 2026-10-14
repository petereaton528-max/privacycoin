"""Build independent native monetary oracle into a fresh private directory.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,shlex,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--cache',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--source',choices=('native_emission','allocation_genesis'),default='native_emission');a=p.parse_args()
a.output.mkdir(mode=0o700,parents=True,exist_ok=False);config=a.cache/'CMakeFiles/pc-public-tools.dir';flags={}
for line in (config/'flags.make').read_text().splitlines():
    if ' = ' in line:
        key,value=line.split(' = ',1);flags[key]=shlex.split(value)
src=ROOT/('tools/creator_model/'+a.source+'.cpp');obj=a.output/'oracle.o';binary=a.output/a.source
compile=['/usr/bin/c++',*flags['CXX_DEFINES'],*flags['CXX_INCLUDES'],*flags['CXX_FLAGS'],'-c',str(src),'-o',str(obj)]
link=shlex.split((config/'link.txt').read_text());command=[];i=0
while i<len(link):
    value=link[i]
    if value=='-o':command+=['-o',str(binary)];i+=2;continue
    command.append(str(obj) if value.endswith('.o') else value);i+=1
for name,args in [('compile',compile),('link',command)]:
    with (a.output/(name+'.log')).open('x') as stream:subprocess.run(args,cwd=a.cache,stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=120)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
record=dict(commands=[compile,command],source_sha256=sha(src),binary_sha256=sha(binary),dependencies_sha256={str((a.cache/v).resolve()):sha((a.cache/v).resolve()) for v in link if v.endswith('.a') and (a.cache/v).is_file()},scope='Offline draft/oracle only; no native coin binary changed')
(a.output/'BUILD.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(dict(binary=str(binary),sha256=record['binary_sha256'])))
