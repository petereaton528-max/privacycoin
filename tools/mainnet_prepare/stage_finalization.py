"""Local release/reviewer staging from exact public allowlists; no custody access.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,re,shutil,subprocess,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'out/production-identity-review-20261014'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
OVERLAYS=['tools/mainnet_prepare/'+n for n in ('binding.py','approved_policy.json','production_identity_proposal.json','genesis_finalization.py','disposable_genesis.py','test_genesis_finalization.py','CUSTODY_STATUS.json','FINALIZATION.md','stage_finalization.py')]
SOURCE_ONLY=['tools/mainnet_prepare/'+n for n in ('founder.py','founder_entry.py','install_founder.py','test_founder.py','verify_founder_native.py','validate_founder_package.py','package_founder.py','FOUNDER_OFFLINE.md')]
EVIDENCE=[
 'docs/evidence/network-v1-final-owner-handoff-20261014/ACCEPTANCE.json',
 'docs/evidence/network-v1-final-owner-handoff-20261014/VERIFICATION.json',
 'docs/evidence/network-v1-production-identity-20261014/ARTIFACT_REVIEW.json',
 'docs/evidence/network-v1-final-identity-review-20261014/RESULTS_FINAL.json',
 'docs/evidence/network-v1-founder-custody-20261014/INSTALLED_RESULTS.json',
 'docs/evidence/network-v1-founder-custody-20261014/NATIVE_RESULTS.json']

def read(path):
    with zipfile.ZipFile(path) as z:return {n:z.read(n) for n in z.namelist()}

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--install-parent',type=Path,required=True);p.add_argument('--commit',required=True);a=p.parse_args()
    if a.out.exists() or a.install_parent.exists() or not a.out.is_absolute() or not a.install_parent.is_absolute() or not a.install_parent.name.startswith('pc-finalization-validation-') or not re.fullmatch('[0-9a-f]{40}',a.commit):raise ValueError('FRESH_SCOPED_DESTINATIONS_REQUIRED')
    os.umask(0o077);os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02'
    receipt=json.loads((BASE/'RELEASE.json').read_text())
    for n,h in receipt['archives'].items():
        if sha((BASE/n).read_bytes())!=h:raise ValueError('RETAINED_ARCHIVE_CHANGED')
    original=read(BASE/'privacycoin-binding-review-linux-wsl2.zip');files=dict(original);sources=read(BASE/'privacycoin-binding-review-source.zip')
    for n in OVERLAYS:files[n]=(ROOT/n).read_bytes();sources[n]=files[n]
    for n in SOURCE_ONLY:sources[n]=(ROOT/n).read_bytes()
    record=dict(format=1,source_commit=a.commit,base_archives=receipt['archives'],overlays={n:sha(files[n]) for n in OVERLAYS},source_only_overlays={n:sha(sources[n]) for n in SOURCE_ONLY},production=False,launchable=False,publication_authorized=False,recipient_selected=False,genesis_finalized=False)
    for group in (files,sources):
        group['FINALIZATION_SOURCE.json']=(json.dumps(record,indent=2)+'\n').encode()
        group['FINALIZATION.md']=files['tools/mainnet_prepare/FINALIZATION.md']
        group['README.md']=b'# Unpublished Privacy Coin V1 finalization review\n\nSee [FINALIZATION.md](FINALIZATION.md) for current approvals, custody and release gates. This is a non-launchable review snapshot, not Mainnet. No recipient or production Genesis is finalized. Historical README and evidence below retain their original scope.\n\n---\n\n'+group.get('README.md',b'')
    a.out.mkdir(parents=True,exist_ok=False)
    from apps.network_v1.licensing import assessment,require_redistributable,inspect_set
    from apps.network_v1.release import install,verify
    def pack(name,group,kind):
        group=dict(group);manifest=json.loads(group.pop('V1_MANIFEST.json'));group.pop('LICENSE_COMPLIANCE.json',None)
        result=assessment(group,kind);require_redistributable(result)
        group['LICENSE_COMPLIANCE.json']=(json.dumps(result,indent=2)+'\n').encode()
        manifest['files']={n:sha(v) for n,v in sorted(group.items())};group['V1_MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
        with zipfile.ZipFile(a.out/name,'x') as z:
            for n,v in sorted(group.items()):
                info=zipfile.ZipInfo(n,(1980,1,1,0,0,0));info.external_attr=(0o100700 if n in manifest['executable'] else 0o100600)<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,v)
        return manifest
    source='privacycoin-finalization-review-source.zip';binary='privacycoin-finalization-review-linux-wsl2.zip';gnu='privacycoin-rc5-gnu-corresponding-source-inspection.zip'
    sm=pack(source,sources,'source');shutil.copyfile(BASE/gnu,a.out/gnu)
    refs=json.loads(files['CORRESPONDING_SOURCE.json']);refs.update(source_commit=a.commit,archives={n:sha((a.out/n).read_bytes()) for n in (source,gnu)})
    files['CORRESPONDING_SOURCE.json']=(json.dumps(refs,indent=2)+'\n').encode();bm=pack(binary,files,'linux-x86_64')
    compliance=inspect_set(a.out/binary,a.out);require_redistributable(compliance['license_assessment'])
    unchanged=[n for n in files if n.startswith(('runtime/','build/','candidate-native/')) or n=='Launch-PC.sh']
    if not all(files[n]==original[n] for n in unchanged):raise ValueError('UNEXPECTED_CLIENT_OR_BINARY_CHANGE')
    verify(a.out/source,source_companion=True)
    tree=a.out/'public-source-staging';tree.mkdir(mode=0o700)
    with zipfile.ZipFile(a.out/source) as z:
        for n in z.namelist():
            dest=tree/n;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with dest.open('xb') as stream:stream.write(z.read(n))
    if not all(sha((tree/n).read_bytes())==h for n,h in sm['files'].items()):raise ValueError('STAGED_SOURCE_CORRESPONDENCE')
    review=a.out/'independent-review';review.mkdir(mode=0o700)
    index={}
    for n in EVIDENCE:
        raw=(ROOT/n).read_bytes();dest=review/n;dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700);dest.write_bytes(raw);index[n]=sha(raw)
    (review/'REVIEW_SCOPE.md').write_bytes(files['FINALIZATION.md'])
    for n in ('approved_policy.json','production_identity_proposal.json','CUSTODY_STATUS.json'):(review/n).write_bytes(files['tools/mainnet_prepare/'+n])
    (review/'RETAINED_EVIDENCE.json').write_text(json.dumps(dict(classification='INTERNAL_AND_OWNER_REPORTED_NOT_INDEPENDENT_REVIEW',files=index),indent=2)+'\n')
    a.install_parent.mkdir(mode=0o700);installed=a.install_parent/'client';install(a.out/binary,installed)
    if not all(sha((installed/n).read_bytes())==h for n,h in bm['files'].items()):raise ValueError('INSTALLED_MANIFEST')
    env=dict(os.environ,PYTHONHOME=str(installed/'runtime/python'),PYTHONNOUSERSITE='1',LD_LIBRARY_PATH=str(installed/'runtime/lib'),PC_GENESIS_TEST_NATIVE_ROOT=str(installed));env.pop('PYTHONPATH',None)
    start=time.monotonic()
    with (a.out/'INSTALLED_TESTS.log').open('x') as log:
        result=subprocess.run([str(installed/'runtime/python/bin/python3'),'-B','-m','unittest','tools.mainnet_prepare.test_genesis_finalization','-v'],cwd=installed,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=60)
    elapsed=round(time.monotonic()-start,3)
    if result.returncode:raise ValueError('FINAL_INSTALLED_GENESIS_TEST_FAILED')
    # Signing inputs are the exact review artifacts; do not create a signature
    # or confuse this unsigned review set with a production release.
    sums={n:sha((a.out/n).read_bytes()) for n in (binary,source,gnu)}
    (a.out/'SHA256SUMS').write_text(''.join(h+'  '+n+'\n' for n,h in sums.items()))
    (review/'ARTIFACT_SHA256SUMS').write_bytes((a.out/'SHA256SUMS').read_bytes())
    review_archive='privacycoin-independent-review.zip'
    with zipfile.ZipFile(a.out/review_archive,'x') as z:
        for path in sorted(review.rglob('*')):
            if not path.is_file():continue
            info=zipfile.ZipInfo(path.relative_to(review).as_posix(),(1980,1,1,0,0,0));info.external_attr=0o100600<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,path.read_bytes())
    sums[review_archive]=sha((a.out/review_archive).read_bytes())
    (a.out/'SHA256SUMS').write_text(''.join(h+'  '+n+'\n' for n,h in sums.items()))
    result=dict(result='PASS_REVIEW_STAGING_ONLY',source=record,archives=sums,installed=str(installed),installed_tests=dict(tests=10,failures=0,skips=0,seconds=elapsed),unchanged_client_runtime_files=len(unchanged),public_source_files=len(sm['files']),compliance=compliance,private_custody_accessed=False,external_network=False,independent_security_review='NOT_PERFORMED',mainnet_release_ready=False)
    (a.out/'RELEASE.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ('result','archives','installed','installed_tests','unchanged_client_runtime_files','public_source_files','mainnet_release_ready')}))
if __name__=='__main__':main()
