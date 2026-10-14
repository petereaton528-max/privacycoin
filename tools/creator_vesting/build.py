"""Build draft wallet/ledger; optional shared-profile laboratory full node.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,shlex,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--cache',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--accelerated',action='store_true');p.add_argument('--candidate-only',action='store_true');p.add_argument('--with-node',action='store_true');p.add_argument('--mock-upgrade',action='store_true');p.add_argument('--mock-v1-only',action='store_true');p.add_argument('--mock-unaware',action='store_true');p.add_argument('--binding',type=Path);a=p.parse_args()
if a.mock_unaware and (not a.mock_upgrade or a.mock_v1_only):p.error('unaware fixture requires mock upgrade and excludes scheduled-halt fixture')
if a.mock_v1_only and not a.mock_upgrade:p.error('old-rule fixture requires mock upgrade identity')
if a.mock_upgrade and (a.accelerated or a.with_node or not a.candidate_only):p.error('mock upgrade requires candidate-only pipe build, no network listener or accelerated vesting')
a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
records={}
binding_flags=[]
if a.binding:
    if a.accelerated or a.mock_upgrade or not a.candidate_only:raise ValueError('BOUND_BUILD_REQUIRES_EXACT_V1_CANDIDATE_ONLY')
    import sys
    sys.path.insert(0,str(ROOT))
    from tools.mainnet_prepare.binding import load,header,digest,canonical
    config=load(a.binding)
    binding_header=a.output/'binding.h';binding_header.write_bytes(header(config))
    (a.output/'BINDING.json').write_bytes(canonical(config))
    binding_flags=['-include',str(binding_header)]
    records['binding_sha256']=digest(config)
    records['binding_header_sha256']=sha(binding_header)
for name,target,inputs in [('ledger','privacycoin-hardened-devnet',['src/phase4/ledger.cpp','tools/creator_vesting/native.cpp']),('node','privacycoin-hardened-devnet',['src/phase4/ledger.cpp','src/phase4/node.cpp']),('wallet','privacycoin-hardened-crypto',['src/phase4/crypto.cpp']),('legacy-node','privacycoin-hardened-devnet',['src/phase4/ledger.cpp','src/phase4/node.cpp']),('legacy-wallet','privacycoin-hardened-crypto',['src/phase4/crypto.cpp'])]:
    if a.candidate_only and name.startswith('legacy-'):continue
    if name=='node' and not a.with_node:continue
    folder=a.cache/'CMakeFiles'/ (target+'.dir');flags={}
    for line in (folder/'flags.make').read_text().splitlines():
        if ' = ' in line:
            key,value=line.split(' = ',1);flags[key]=shlex.split(value)
    objects=[];commands=[]
    for source in inputs:
        obj=a.output/(name+'-'+Path(source).stem+'.o');objects.append(str(obj))
        cmd=['/usr/bin/c++',*(['-DPC_OFFLINE_CREATOR_VESTING']+(['-DPC_OFFLINE_ACCELERATED_VESTING'] if a.accelerated else []) if not name.startswith('legacy-') else []),*(['-DPC_OFFLINE_MOCK_UPGRADE'] if a.mock_upgrade else []),*(['-DPC_OFFLINE_MOCK_V1_ONLY'] if a.mock_v1_only else []),*(['-DPC_OFFLINE_MOCK_UNAWARE'] if a.mock_unaware else []),'-I'+str(ROOT/'src'),*flags['CXX_DEFINES'],*flags['CXX_INCLUDES'],*flags['CXX_FLAGS'],'-c',str(ROOT/source),'-o',str(obj)]
        cmd[1:1]=binding_flags
        with (a.output/(obj.stem+'.log')).open('x') as log:subprocess.run(cmd,cwd=a.cache,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
        commands.append(cmd)
    link=shlex.split((folder/'link.txt').read_text());cmd=[];inserted=False;i=0;binary=a.output/('draft-'+name)
    while i<len(link):
        v=link[i]
        if v.endswith('.o'):
            if not inserted:cmd+=objects;inserted=True
        elif v=='-o':cmd+=['-o',str(binary)];i+=1
        else:cmd.append(v)
        i+=1
    with (a.output/(name+'-link.log')).open('x') as log:subprocess.run(cmd,cwd=a.cache,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
    commands.append(cmd)
    records[name]=dict(binary_sha256=sha(binary),commands=commands,source_sha256={source:sha(ROOT/source) for source in inputs},dependencies_sha256={str((a.cache/v).resolve()):sha((a.cache/v).resolve()) for v in link if v.endswith(('.a','.so')) and (a.cache/v).is_file()})
records['policy_sha256']=sha(ROOT/'src/consensus/creator_vesting_draft.h');records['ledger_header_sha256']=sha(ROOT/'src/phase4/ledger.h');records['accelerated']=a.accelerated;records['scope']='Non-production shared-profile node with loopback RPC/P2P; external transport requires separate explicit activation' if a.with_node else 'Offline pipe executable only; no listener, Mainnet selector or public networking'
records['rule_versions_sha256']=sha(ROOT/'src/consensus/rule_versions.h');records['mock_upgrade']=a.mock_upgrade;records['mock_v1_only']=a.mock_v1_only;records['mock_unaware']=a.mock_unaware
(a.output/'BUILD.json').write_text(json.dumps(records,indent=2)+'\n');print('Built offline draft ledger and wallet')
