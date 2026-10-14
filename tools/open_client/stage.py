"""Explicit source/runtime staging; excludes historical worktree and private state.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
GIT=['git','--git-dir=/mnt/d/grok Projects/Privacy_Coin/.phase0-git/worktrees/Privacy_Coin_V1_20261011','--work-tree='+str(ROOT)]
CHANGED=['src/network_identity.py','src/phase4/ledger.h','src/phase4/node.cpp','src/phase4/wallet.py','apps/network_v1/rpc.py','apps/network_v1/run_node.py','apps/network_v1/onion.py','apps/network_v1/public_network.py','apps/network_v1/peer_uri.py','apps/network_v1/desktop_backend.py','apps/network_v1/desktop.py','apps/network_v1/tests/open_network.py','apps/network_v1/tests/test_public_network.py','apps/network_v1/upstream.py']
p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);p.add_argument('--native',type=Path,required=True);p.add_argument('--destination',type=Path,required=True);a=p.parse_args()
os.umask(0o077)
CHANGED+=['apps/network_v1/Launch-Open-PC.sh','apps/network_v1/sdk.py','apps/network_v1/licensing.py','docs/network-v1/SDK_SOURCE_SCOPE.md','apps/network_v1/tests/test_private_packaging.py','apps/network_v1/tests/first_use.py','apps/network_v1/tests/gui_payments.py','apps/network_v1/tests/local_socks.py','apps/network_v1/upgrade.py','apps/network_v1/tests/test_upgrade.py','apps/network_v1/Setup-Open-PC.sh','docs/network-v1/OPEN_DEV02.md']
CHANGED+=['apps/network_v1/release.py']
CHANGED+=['apps/network_v1/tests/test_peer_lifecycle.py','apps/network_v1/tests/test_mainnet_preparation.py','tools/mainnet_prepare/prepare.py','tools/mainnet_prepare/build.py','tools/mainnet_prepare/genesis.cpp']
a.destination.mkdir(mode=0o700,parents=True,exist_ok=False)
sha=lambda raw:hashlib.sha256(raw).hexdigest()
manifest=json.loads((a.base/'V1_MANIFEST.json').read_text())
for name,digest in manifest['files'].items():
    raw=(a.base/name).read_bytes()
    if sha(raw)!=digest:raise ValueError('BASE_ARTIFACT_CHANGED')
    target=a.destination/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o700 if name in manifest['executable'] else 0o600)
# Overlay committed product source, then only the explicitly reviewed changes.
names=subprocess.check_output(GIT+['ls-files','apps/network_v1','scripts/devnet-gui','src/phase4','src/phase6a','services/privacy-network'],cwd=ROOT,text=True).splitlines()
for name in names:
    raw=subprocess.check_output(GIT+['show','HEAD:'+name],cwd=ROOT)
    target=a.destination/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);target.write_bytes(raw)
for name in CHANGED:
    target=a.destination/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);target.write_bytes((ROOT/name).read_bytes())
entry=a.destination/'Launch-PC.sh'
entry.write_text('#!/bin/sh\nset -eu\nAPP=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec /bin/sh "$APP/apps/network_v1/Launch-Open-PC.sh" "$@"\n');entry.chmod(0o700)
setup=a.destination/'Setup-PC.sh'
setup.write_text('#!/bin/sh\nset -eu\nAPP=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec /bin/sh "$APP/apps/network_v1/Setup-Open-PC.sh" "$@"\n');setup.chmod(0o700)
manifest['executable']=sorted(set(manifest['executable'])|{'Launch-PC.sh','Setup-PC.sh'})
manifest['network']='PrivacyCoinDev02';manifest['profile']='PrivacyCoinDev02/private-spend-v1-hardening/epoch18/'+manifest['genesis']
binary=a.destination/'build/monero-linux/phase4/privacycoin-hardened-devnet';binary.write_bytes(a.native.read_bytes());binary.chmod(0o700)
native_record=json.loads((a.native.parent/'BUILD.json').read_text())
if native_record['binary_sha256']!=sha(binary.read_bytes()):raise ValueError('NATIVE_BUILD_RECEIPT_HASH')
for name,digest in native_record['source_sha256'].items():
    if sha((ROOT/name).read_bytes())!=digest:raise ValueError('NATIVE_BUILD_SOURCE_CHANGED')
for name,digest in native_record['dependencies_sha256'].items():
    if sha(Path(name).read_bytes())!=digest:raise ValueError('NATIVE_LINK_LIBRARY_CHANGED')
(a.destination/'OPEN_NATIVE_BUILD.json').write_bytes((a.native.parent/'BUILD.json').read_bytes())
inventory_path=a.destination/'docs/network-v1/LICENSE_INVENTORY.json'
inventory=json.loads(inventory_path.read_text());member=binary.relative_to(a.destination).as_posix()
for kind in ('linux-x86_64','windows-wsl2-x86_64'):
    bindings=inventory['component_requirements_by_kind'][kind]['files']
    if bindings[member]!=manifest['files'][member]:raise ValueError('BASE_COMPONENT_BINDING_CHANGED')
    bindings[member]=native_record['binary_sha256']
    bindings['OPEN_NATIVE_BUILD.json']=sha((a.destination/'OPEN_NATIVE_BUILD.json').read_bytes())
inventory['development_rebuild']=dict(binary=member,build_evidence='OPEN_NATIVE_BUILD.json',scope='Original node sources rebuilt; retained licensed static libraries and runtime/source companion unchanged')
inventory_path.write_text(json.dumps(inventory,indent=2)+'\n')
build=json.loads((a.destination/'build/v1-native-manifest.json').read_text());build['binary_sha256'][binary.name]=sha(binary.read_bytes());build['kind']='V1_LOCAL_SOURCE_BUILD'
# The existing launcher checks every listed source, not merely the node hash.
build['source_sha256']={n:sha((a.destination/n).read_bytes()) for n in set(build['source_sha256'])|set(CHANGED)}
(a.destination/'build/v1-native-manifest.json').write_text(json.dumps(build,indent=2)+'\n')
receipt=dict(base_source_commit='785ed1c0981bda4651d7044de29c076f0abe5910',product_head=subprocess.check_output(GIT+['rev-parse','HEAD'],cwd=ROOT,text=True).strip(),modified_source={n:sha((ROOT/n).read_bytes()) for n in CHANGED},network='open-dev02',genesis_policy='Retained genesis, distinct native network/profile and database binding; shared development transaction cryptography, no Mainnet profile')
(a.destination/'OPEN_CLIENT_BUILD.json').write_text(json.dumps(receipt,indent=2)+'\n')
manifest['files']={p.relative_to(a.destination).as_posix():sha(p.read_bytes()) for p in a.destination.rglob('*') if p.is_file() and p.name!='V1_MANIFEST.json'}
(a.destination/'V1_MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(dict(staged=str(a.destination),files=len(manifest['files']))))
