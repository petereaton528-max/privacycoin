"""Local review packaging: existing allowlist, verified overlays and bound native.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,shutil,sys,zipfile,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT));os.environ['PC_DEVELOPMENT_NETWORK']='open-dev02'
BASE=ROOT/'out/owner-backup-fix-final-20261013';OUT=ROOT/'out/production-binding-review-final-20261014';BUILD=Path('/home/privacydev/pc-bound-native-final-20261014')
sha=lambda b:hashlib.sha256(b).hexdigest()
def read(p):
    with zipfile.ZipFile(p) as z:return {n:z.read(n) for n in z.namelist()}
def main():
    global OUT,BUILD
    p=argparse.ArgumentParser()
    p.add_argument('--output',type=Path,required=True);p.add_argument('--install-parent',type=Path,required=True)
    p.add_argument('--build',type=Path,default=BUILD);p.add_argument('--version',required=True)
    args=p.parse_args();OUT=args.output;BUILD=args.build
    if not OUT.is_absolute() or not args.install_parent.is_absolute() or not re.fullmatch(r'1\.0\.0-[a-z0-9.-]+',args.version):raise ValueError('REVIEW_PACKAGE_ARGUMENTS')
    commit=os.environ.get('PC_REVIEW_SOURCE_COMMIT','')
    if not re.fullmatch('[0-9a-f]{40}',commit):raise ValueError('EXACT_REVIEWED_SOURCE_COMMIT_REQUIRED')
    receipt=json.loads((BASE/'RELEASE.json').read_text())
    assert all(sha((BASE/n).read_bytes())==h for n,h in receipt['archives'].items())
    files=read(BASE/'privacycoin-owner-review-0.4.0-backupfix-linux-wsl2.zip')
    sources=read(ROOT/'out/mainnet-review-handoff-20261014/privacycoin-reviewed-source-with-tor-fix.zip')
    overlays=['apps/network_v1/candidate_client.py','apps/network_v1/candidate_profile.py','apps/network_v1/candidate_runtime.py','src/consensus/creator_vesting_draft.h','src/phase4/node.cpp','tools/creator_vesting/build.py','tools/creator_vesting/native.cpp','tools/creator_vesting/verify_native.py']
    overlays += ['tools/mainnet_prepare/'+n for n in ('prepare.py','approved_policy.json','binding.py','test_binding.py','verify_binding.py','genesis_artifact.py','PRODUCTION_REVIEW.md','package_binding.py','validate_installed.py','verify_local_peers.py')]
    overlays += ['tools/mainnet_prepare/identity_proposal.py','tools/mainnet_prepare/test_identity_proposal.py','tools/mainnet_prepare/validate_identity_release.py','tools/mainnet_prepare/verify_bound_transport.py','apps/network_v1/public_network.py','apps/network_v1/tests/test_public_context.py']
    overlays += ['tools/mainnet_prepare/production_identity_proposal.json']
    overlays += ['services/privacy-network/tor_runtime.py','apps/network_v1/onion.py','apps/network_v1/candidate_gui.py','apps/network_v1/tests/test_tor_worker.py']
    for n in overlays:
        raw=(ROOT/n).read_bytes();files[n]=raw;sources[n]=raw
    native=json.loads((BUILD/'BUILD.json').read_text())
    for name in ('node','ledger','wallet'):
        raw=(BUILD/('draft-'+name)).read_bytes();assert sha(raw)==native[name]['binary_sha256']
        assert all(sha((ROOT/n).read_bytes())==h for n,h in native[name]['source_sha256'].items())
        files['candidate-native/full/draft-'+name]=raw
        assert all(sha(Path(n).read_bytes())==h for n,h in native[name]['dependencies_sha256'].items())
    for name in ('BUILD.json','binding.h','BINDING.json'):
        files['candidate-native/full/'+name]=(BUILD/name).read_bytes();sources['candidate-native/full/'+name]=(BUILD/name).read_bytes()
    metadata=dict(version=args.version,production=False,launchable=False,source_overlay_commit=commit,base_source_sha256=sha((BASE/'privacycoin-owner-review-backupfix-source.zip').read_bytes()),binding_sha256=native['binding_sha256'],modified_source={n:sha(files[n]) for n in overlays},native_binary_sha256={n:native[n]['binary_sha256'] for n in ('node','ledger','wallet')},source_note='Exact reviewed base plus listed overlays; not a whole worktree export')
    for group in (files,sources):
        group['RELEASE_CANDIDATE.json']=(json.dumps(metadata,indent=2)+'\n').encode()
        group['SOURCE_REVISION.json']=(json.dumps(metadata,indent=2)+'\n').encode()
        group['PRODUCTION_REVIEW.md']=(ROOT/'tools/mainnet_prepare/PRODUCTION_REVIEW.md').read_bytes()
    files['Launch-PC.sh']=b'''#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONHOME="$HERE/runtime/python"
export PYTHONNOUSERSITE=1
export LD_LIBRARY_PATH="$HERE/runtime/lib"
export TCL_LIBRARY="$HERE/runtime/tcltk/tcl8.6"
export TK_LIBRARY="$HERE/runtime/tcltk/tk8.6"
export PC_DEVNET_NATIVE_ROOT="$HERE"
export PC_OFFLINE_BINDING="$HERE/candidate-native/full/BINDING.json"
cd "$HERE"
exec "$HERE/runtime/python/bin/python3" -B -m apps.network_v1.candidate_gui --home "$HOME/.local/share/pc-candidate-profile-binding-review-20261014" --build "$HERE/candidate-native/full" --native-root "$HERE" --authorize-disposable-profile --start-node "$@"
'''
    files['OWNER-START.txt']=b'Nonproduction offline binding review. No production keys or Genesis. Existing profiles preserved. Launch-PC.sh requires an explicit compatible disposable --profile. Do not click Connect Tor in this authorization. See PRODUCTION_REVIEW.md.\n'
    from apps.network_v1.licensing import assessment,require_redistributable
    for group,kind in ((files,'linux-x86_64'),(sources,'source')):
        result=assessment(group,kind);require_redistributable(result);group['LICENSE_COMPLIANCE.json']=(json.dumps(result,indent=2)+'\n').encode()
    OUT.mkdir(exist_ok=False)
    def pack(name,group):
        manifest=json.loads(group.pop('V1_MANIFEST.json'));manifest['files']={n:sha(v) for n,v in sorted(group.items())}
        group['V1_MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
        with zipfile.ZipFile(OUT/name,'x',compression=zipfile.ZIP_DEFLATED) as z:
            for n,raw in sorted(group.items()):
                if n.startswith('/') or '..' in Path(n).parts:raise ValueError('PACKAGE_PATH')
                info=zipfile.ZipInfo(n,(1980,1,1,0,0,0));info.external_attr=(0o100700 if n in manifest.get('executable',[]) else 0o100600)<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,raw)
    source='privacycoin-binding-review-source.zip';binary='privacycoin-binding-review-linux-wsl2.zip';pack(source,sources)
    gnu='privacycoin-rc5-gnu-corresponding-source-inspection.zip';shutil.copyfile(BASE/gnu,OUT/gnu)
    refs=json.loads(files['CORRESPONDING_SOURCE.json']);refs.update(source_commit=commit,archives={n:sha((OUT/n).read_bytes()) for n in (source,gnu)});files['CORRESPONDING_SOURCE.json']=(json.dumps(refs,indent=2)+'\n').encode()
    pack(binary,files)
    from apps.network_v1.licensing import inspect_set
    assessment_result=inspect_set(OUT/binary,OUT);require_redistributable(assessment_result['license_assessment'])
    from apps.network_v1.release import install
    parent=args.install_parent;parent.mkdir(mode=0o700,exist_ok=False)
    destination=parent/'client';install(OUT/binary,destination)
    assert all(sha((destination/n).read_bytes())==h for n,h in json.loads((destination/'V1_MANIFEST.json').read_text())['files'].items())
    metadata.update(archives={n:sha((OUT/n).read_bytes()) for n in (source,binary,gnu)},installed=str(destination),compliance=assessment_result)
    (OUT/'RELEASE.json').write_text(json.dumps(metadata,indent=2)+'\n');(OUT/'SHA256SUMS').write_text(''.join(h+'  '+n+'\n' for n,h in metadata['archives'].items()))
    print(json.dumps(dict(installed=str(destination),archives=metadata['archives'])))
if __name__=='__main__':main()
