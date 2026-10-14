"""Bounded offline growth-test build; reuses read-only pinned upstream libraries.

This is deliberately labeled cache-linked, not a clean/reproducible release build.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def main():
    p=argparse.ArgumentParser();p.add_argument('--cache',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    root=Path(__file__).resolve().parents[3]
    a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
    config=a.cache/'CMakeFiles/privacycoin-hardened-devnet.dir'
    flags={}
    for line in (config/'flags.make').read_text().splitlines():
        if ' = ' in line:
            key,value=line.split(' = ',1);flags[key]=shlex.split(value)
    link=shlex.split((config/'link.txt').read_text());pivot=link.index('-o')
    libs=[str(a.cache/x) if not x.startswith(('-', '/')) else x for x in link[pivot+2:]]
    args=[link[0],'-I'+str(root/'src'),*flags['CXX_DEFINES'],*flags['CXX_INCLUDES'],*flags['CXX_FLAGS'],
          '-Wl,--wrap=__cxa_throw','-Wl,-u,__wrap___cxa_throw','-Wl,-z,relro,-z,now,-z,noexecstack',str(root/'src/phase4/ledger.cpp')]
    commands=[]
    for name,source in [('growth-test',root/'apps/network_v1/tests/growth.cpp'),('storage-edges',root/'apps/network_v1/tests/storage_edges.cpp'),('privacycoin-hardened-devnet',root/'src/phase4/node.cpp')]:
        command=[*args,str(source),'-o',str(a.out/name),*libs];commands.append(command)
        with (a.out/(name+'.log')).open('xb') as log:
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=240,check=True)
    report=dict(kind='CACHE_LINKED_TEST_BUILD_NOT_RELEASE_REPRODUCIBILITY',commands=commands,
                source_sha256={str(x.relative_to(root)):hashlib.sha256(x.read_bytes()).hexdigest() for x in (root/'src/phase4').glob('*') if x.is_file()},
                binaries={n:hashlib.sha256((a.out/n).read_bytes()).hexdigest() for n in ('growth-test','storage-edges','privacycoin-hardened-devnet')})
    (a.out/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    print('CACHE_LINKED_GROWTH_BUILD_PASS')


if __name__=='__main__':main()
