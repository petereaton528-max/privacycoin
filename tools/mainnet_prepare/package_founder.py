"""Build an offline-only custody subset of verified runtime/source archives.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,re,shutil,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'out/production-identity-review-20261014'
HELPER='build/monero-linux/phase2/privacycoin-wallet-crypto'
SHA=lambda b:hashlib.sha256(b).hexdigest()
OVERLAYS=['tools/mainnet_prepare/'+n for n in ('founder.py','founder_entry.py','install_founder.py','test_founder.py','verify_founder_native.py','validate_founder_package.py','package_founder.py','FOUNDER_OFFLINE.md','binding.py','approved_policy.json','production_identity_proposal.json')]+['src/wallet/wallet.py','tools/creator_model/binding.py']

def read(path):
    with zipfile.ZipFile(path) as z:return {n:z.read(n) for n in z.namelist()}

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--commit',required=True);a=p.parse_args()
    if not re.fullmatch('[0-9a-f]{40}',a.commit) or a.out.exists():raise ValueError('FRESH_OUTPUT_AND_SOURCE_COMMIT_REQUIRED')
    os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02'
    receipt=json.loads((BASE/'RELEASE.json').read_text())
    for n,h in receipt['archives'].items():
        if SHA((BASE/n).read_bytes())!=h:raise ValueError('BASE_ARCHIVE_CHANGED')
    original=read(BASE/'privacycoin-binding-review-linux-wsl2.zip');sources=read(BASE/'privacycoin-binding-review-source.zip')
    files={n:v for n,v in original.items() if n.startswith(('runtime/python/','runtime/lib/','docs/')) or n in ('LICENSE','LICENSE_SCOPE.md','CONTRIBUTING.md','CORRESPONDING_SOURCE.json','OPEN_NATIVE_BUILD.json',HELPER)}
    # Retain every dependency notice and source companion; omit node/Tor/miner
    # executables, GUI launchers and all runtime/profile/private state.
    for n,v in original.items():
        if n.startswith('runtime/') and ('LICENSE' in n.upper() or 'NOTICE' in n.upper()):files[n]=v
    for n in OVERLAYS:files[n]=(ROOT/n).read_bytes();sources[n]=files[n]
    files['founder_entry.py']=(ROOT/'tools/mainnet_prepare/founder_entry.py').read_bytes()
    files['FOUNDER_OFFLINE.md']=(ROOT/'tools/mainnet_prepare/FOUNDER_OFFLINE.md').read_bytes()
    files['Founder-Wallet.sh']=b'''#!/bin/sh
set -eu
umask 077
ulimit -c 0
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
unset PYTHONPATH PYTHONSTARTUP PYTHONINSPECT LD_PRELOAD LD_AUDIT
export PYTHONHOME="$HERE/runtime/python"
export LD_LIBRARY_PATH="$HERE/runtime/lib"
export PYTHONNOUSERSITE=1
cd "$HERE"
exec "$HERE/runtime/python/bin/python3" -I -B "$HERE/founder_entry.py" "$@"
'''
    inventory=json.loads(files['docs/network-v1/LICENSE_INVENTORY.json'])
    required=inventory['component_requirements_by_kind']['linux-x86_64']['files']
    excluded={n:h for n,h in required.items() if n not in files and n.startswith('build/') and n!=HELPER}
    for n in excluded:del required[n]
    scope=dict(scope='Offline founder custody subset; no node, Tor, miner or GUI executable',omitted_native_components=excluded,retained_helper_sha256=SHA(files[HELPER]),source_commit=a.commit,base_archives=receipt['archives'],unchanged_runtime_files={n:SHA(v) for n,v in files.items() if n.startswith('runtime/')},production_keys_generated=False)
    files['FOUNDER_SCOPE.json']=(json.dumps(scope,indent=2)+'\n').encode()
    inventory.setdefault('distribution_scope_evidence',[]).append('FOUNDER_SCOPE.json')
    files['docs/network-v1/LICENSE_INVENTORY.json']=(json.dumps(inventory,indent=2)+'\n').encode()
    sources['FOUNDER_SCOPE.json']=files['FOUNDER_SCOPE.json']
    # Source archive retains its original full distribution inventory; this is
    # an equal-access superset, never deleting inherited license obligations.
    revision=dict(source_commit=a.commit,base_archives=receipt['archives'],overlays={n:SHA(files[n]) for n in OVERLAYS},identity_sha256=SHA(files['tools/mainnet_prepare/production_identity_proposal.json']))
    for group in (files,sources):group['FOUNDER_SOURCE.json']=(json.dumps(revision,indent=2)+'\n').encode()
    a.out.mkdir(parents=True,exist_ok=False)
    from apps.network_v1.licensing import assessment,require_redistributable,inspect_set
    def pack(name,group,manifest):
        manifest=dict(manifest);manifest['files']={n:SHA(v) for n,v in sorted(group.items())}
        group=dict(group);group['V1_MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
        with zipfile.ZipFile(a.out/name,'x') as z:
            for n,v in sorted(group.items()):
                i=zipfile.ZipInfo(n,(1980,1,1,0,0,0));i.external_attr=(0o100700 if n in manifest['executable'] else 0o100600)<<16;i.compress_type=zipfile.ZIP_DEFLATED;z.writestr(i,v)
    sm=json.loads(sources.pop('V1_MANIFEST.json'));sources.pop('LICENSE_COMPLIANCE.json',None)
    report=assessment(sources,'source');require_redistributable(report);sources['LICENSE_COMPLIANCE.json']=(json.dumps(report,indent=2)+'\n').encode()
    source='privacycoin-founder-offline-source.zip';binary='privacycoin-founder-offline-linux-wsl2.zip';pack(source,sources,sm)
    gnu='privacycoin-rc5-gnu-corresponding-source-inspection.zip';shutil.copyfile(BASE/gnu,a.out/gnu)
    refs=json.loads(files['CORRESPONDING_SOURCE.json']);refs.update(source_commit=a.commit,archives={n:SHA((a.out/n).read_bytes()) for n in (source,gnu)})
    files['CORRESPONDING_SOURCE.json']=(json.dumps(refs,indent=2)+'\n').encode()
    result=assessment(files,'linux-x86_64');require_redistributable(result);files['LICENSE_COMPLIANCE.json']=(json.dumps(result,indent=2)+'\n').encode()
    bm=json.loads(original['V1_MANIFEST.json']);bm['executable']=[n for n in bm['executable'] if n in files]+['Founder-Wallet.sh']
    fm=dict(format=1,version='1.0.0-founder-offline.1',source_commit=a.commit,executable=bm['executable'],files={n:SHA(v) for n,v in sorted(files.items())})
    files['FOUNDER_MANIFEST.json']=(json.dumps(fm,indent=2)+'\n').encode();pack(binary,files,bm)
    compliance=inspect_set(a.out/binary,a.out);require_redistributable(compliance['license_assessment'])
    for n in ('install_founder.py','FOUNDER_OFFLINE.md'):shutil.copyfile(ROOT/'tools/mainnet_prepare'/n,a.out/n)
    sums={n:SHA((a.out/n).read_bytes()) for n in (binary,source,gnu,'install_founder.py','FOUNDER_OFFLINE.md')}
    (a.out/'SHA256SUMS').write_text(''.join(h+'  '+n+'\n' for n,h in sums.items()))
    (a.out/'RELEASE.json').write_text(json.dumps(dict(source=revision,sha256=sums,compliance=compliance,scope=scope),indent=2)+'\n')
    print(json.dumps(sums))
if __name__=='__main__':main()
