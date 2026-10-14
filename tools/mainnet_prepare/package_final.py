"""Unsigned Mainnet RC: reviewed archive allowlist + explicit frozen overlays.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,shutil,subprocess,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'out/finalization-review-20261014'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
OVERLAYS=['apps/network_v1/'+n for n in ('candidate_client.py','candidate_profile.py','candidate_runtime.py','candidate_gui.py','production_gui.py','public_network.py')]
OVERLAYS+=['src/network_identity.py','src/phase4/ledger.cpp','src/phase4/crypto.cpp','src/phase4/node.cpp','tools/creator_vesting/native.cpp','tools/creator_vesting/build.py']
OVERLAYS+=['tools/creator_model/binding.py','tools/mainnet_prepare/CUSTODY_STATUS.json','docs/evidence/network-v1-final-production-20261014/INTERNAL_SECURITY_REVIEW.md']
OVERLAYS+=['tools/mainnet_prepare/'+n for n in ('production.py','binding.py','approved_policy.json','production_identity_proposal.json','FOUNDER_RECIPIENT_APPROVAL.json','FINAL_GENESIS_APPROVAL.json','APPROVED_GENESIS.bin','APPROVED_GENESIS.json','APPROVED_PUBLIC_RECIPIENT.json','test_binding.py','test_identity_proposal.py','test_production.py','test_final_wallet.py','verify_final_client.py','bind_founder_client.py','founder.py','package_final.py','MAINNET_RC.md')]
def read(path):
    with zipfile.ZipFile(path) as z:return {n:z.read(n) for n in z.namelist()}
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--build',type=Path,required=True);p.add_argument('--install-parent',type=Path,required=True);p.add_argument('--commit',required=True);a=p.parse_args()
    os.umask(0o077);os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02'
    if a.out.exists() or a.install_parent.exists():raise ValueError('FRESH_PACKAGE_AND_INSTALL_REQUIRED')
    receipt=json.loads((BASE/'RELEASE.json').read_bytes())
    for name,pin in receipt['archives'].items():
        if sha((BASE/name).read_bytes())!=pin:raise ValueError('REVIEW_BASE_CHANGED')
    files=read(BASE/'privacycoin-finalization-review-linux-wsl2.zip');source=read(BASE/'privacycoin-finalization-review-source.zip')
    for name in OVERLAYS:files[name]=(ROOT/name).read_bytes();source[name]=files[name]
    native=json.loads((a.build/'BUILD.json').read_bytes())
    for name in ('ledger','wallet','node'):
        raw=(a.build/('draft-'+name)).read_bytes()
        if sha(raw)!=native[name]['binary_sha256']:raise ValueError('NATIVE_BINARY_HASH')
        if any(sha((ROOT/n).read_bytes())!=h for n,h in native[name]['source_sha256'].items()):raise ValueError('NATIVE_SOURCE_HASH')
        if any(sha(Path(n).read_bytes())!=h for n,h in native[name]['dependencies_sha256'].items()):raise ValueError('NATIVE_DEPENDENCY_HASH')
        files['candidate-native/full/draft-'+name]=raw
    for name in ('BUILD.json','binding.h','BINDING.json','PROFILE.json'):
        files['candidate-native/full/'+name]=(a.build/name).read_bytes();source['candidate-native/full/'+name]=files['candidate-native/full/'+name]
    version='1.0.0-mainnet-rc1'
    metadata=dict(version=version,source_commit=a.commit,production_bound=True,genesis_final=True,publication_authorized=False,activation_authorized=False,independent_security_review=False,source_overlays={n:sha(files[n]) for n in OVERLAYS},native={n:native[n]['binary_sha256'] for n in ('ledger','wallet','node')},base_archives=receipt['archives'])
    for group in (files,source):
        group['FINAL_PRODUCTION_BUILD.json']=(json.dumps(metadata,indent=2)+'\n').encode()
        group['SOURCE_REVISION.json']=group['FINAL_PRODUCTION_BUILD.json']
        group['README.md']=files['tools/mainnet_prepare/MAINNET_RC.md']
        group['OWNER-START.txt']=b'Read README.md. Approved Mainnet Genesis; unsigned release candidate; no publication or activation authorized. Installation starts no service. Use Launch-PC.sh only for approved offline owner review; do not Connect Tor or mine before launch authorization.\n'
    files['Launch-PC.sh']=b'''#!/bin/sh
set -eu
umask 077
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONHOME="$HERE/runtime/python"
export PYTHONNOUSERSITE=1
export LD_LIBRARY_PATH="$HERE/runtime/lib"
export TCL_LIBRARY="$HERE/runtime/tcltk/tcl8.6"
export TK_LIBRARY="$HERE/runtime/tcltk/tk8.6"
cd "$HERE"
exec "$HERE/runtime/python/bin/python3" -B -m apps.network_v1.production_gui "$@"
'''
    source['Launch-PC.sh']=files['Launch-PC.sh']
    # Replace obsolete top-level status receipts; retained historical evidence is labelled.
    for group in (files,source):
        group['RELEASE_CANDIDATE.json']=group['FINAL_PRODUCTION_BUILD.json']
        group['FINALIZATION.md']=group['README.md']
        group['PRODUCTION_REVIEW.md']=group['README.md']
    from apps.network_v1.licensing import assessment,require_redistributable,inspect_set
    from apps.network_v1.release import install,verify
    a.out.mkdir(mode=0o700)
    def pack(name,original,kind):
        group=dict(original);manifest=json.loads(group.pop('V1_MANIFEST.json'))
        group.pop('LICENSE_COMPLIANCE.json',None)
        assessment_result=assessment(group,kind);require_redistributable(assessment_result)
        group['LICENSE_COMPLIANCE.json']=(json.dumps(assessment_result,indent=2)+'\n').encode()
        manifest['files']={n:sha(raw) for n,raw in sorted(group.items())}
        group['V1_MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
        def emit(path):
            with zipfile.ZipFile(path,'x') as z:
                for n,raw in sorted(group.items()):
                    if n.startswith('/') or '..' in Path(n).parts:raise ValueError('ARCHIVE_PATH')
                    info=zipfile.ZipInfo(n,(1980,1,1,0,0,0));info.external_attr=(0o100700 if n in manifest['executable'] else 0o100600)<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,raw)
        emit(a.out/name);emit(a.out/(name+'.repro'))
        if sha((a.out/name).read_bytes())!=sha((a.out/(name+'.repro')).read_bytes()):raise ValueError('ARCHIVE_REPRODUCIBILITY')
        return manifest
    src='privacycoin-mainnet-rc1-source.zip';binary='privacycoin-mainnet-rc1-linux-wsl2.zip';gnu='privacycoin-rc5-gnu-corresponding-source-inspection.zip'
    sm=pack(src,source,'source');shutil.copyfile(BASE/gnu,a.out/gnu)
    refs=json.loads(files['CORRESPONDING_SOURCE.json']);refs.update(source_commit=a.commit,archives={n:sha((a.out/n).read_bytes()) for n in (src,gnu)})
    files['CORRESPONDING_SOURCE.json']=(json.dumps(refs,indent=2)+'\n').encode();bm=pack(binary,files,'linux-x86_64')
    verify(a.out/src,source_companion=True);compliance=inspect_set(a.out/binary,a.out);require_redistributable(compliance['license_assessment'])
    staging=a.out/'public-source-staging';staging.mkdir(mode=0o700)
    with zipfile.ZipFile(a.out/src) as z:
        for n in z.namelist():
            dest=staging/n;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(z.read(n))
    a.install_parent.mkdir(mode=0o700);destination=a.install_parent/'client';install(a.out/binary,destination)
    if any(sha((destination/n).read_bytes())!=h for n,h in bm['files'].items()):raise ValueError('INSTALLED_MANIFEST')
    sums={n:sha((a.out/n).read_bytes()) for n in (binary,src,gnu)}
    metadata.update(archives=sums,installed=str(destination),compliance=compliance,archive_reproducibility='PASS_TWO_BYTE_IDENTICAL_PACKS',source_files=len(sm['files']))
    (a.out/'RELEASE.json').write_text(json.dumps(metadata,indent=2)+'\n');(a.out/'SHA256SUMS').write_text(''.join(h+'  '+n+'\n' for n,h in sums.items()))
    print(json.dumps(dict(installed=str(destination),archives=sums)))
if __name__=='__main__':main()
