"""Bind the compatible substitution to NEW source/Linux package scopes only.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,sys
from pathlib import Path
from stage import EXPECTED,replacements
ROOT=Path(__file__).resolve().parents[2]
sha=lambda b:hashlib.sha256(b).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--base',type=Path,required=True);a=p.parse_args()
    core=json.loads((a.base/'core-validation.json').read_text());cross=json.loads((a.base/'cross-version.json').read_text())
    assert core['result']==cross['result']=='PASS'
    new=replacements();source_bind={'.upstream/monero/'+n:sha(b) for n,b in new.items()}
    original=dict(EXPECTED)
    record=dict(format=1,baseline_commit='f26d0c28c68884bf890aa15068349295cd866cc8',
        upstream='https://github.com/pornin/sphlib',upstream_commit='15b6b8d8f3e4a43c58ba102d712fa6b8a3317035',
        license='MIT',copyright='Projet RNRT SAPHIR; original per-file years retained',
        original_adapter_license='BSD-3-Clause',original_adapter_copyright='Copyright (c) 2026 petereaton528-max',
        inherited_implementation_sha256_excluded=original,source_files=source_bind,
        linux_binary_sha256=core['binary_sha256'],
        compatibility_evidence='docs/evidence/network-v1-sphlib-20261012/',
        modified_vendor_source='jh_sph.c: single legacy partial-bit padding expression; exact delta in PROVENANCE.json',
        source_and_linux_scope_only=True,windows_binaries_substituted=False,public_release_authorized=False)
    dest=ROOT/'docs/network-v1/SPHLIB_SUBSTITUTION.json';dest.write_text(json.dumps(record,indent=2)+'\n')
    licensepath=ROOT/'docs/network-v1/third-party/licenses/SPHLIB-MIT.txt'
    licensepath.write_bytes((ROOT/'experiments/sphlib/vendor/LICENSE').read_bytes())
    inventorypath=ROOT/'docs/network-v1/LICENSE_INVENTORY.json';inventory=json.loads(inventorypath.read_text())
    for kind in ('source','linux-x86_64','windows-wsl2-x86_64'):
        inventory['distribution_obligations_by_kind'][kind]=[]
    # Global holds remain for unchanged historical Windows previews.
    inventory['substitution_scope']=record
    inventory['distribution_scope_evidence']+=['docs/network-v1/SPHLIB_SUBSTITUTION.md','docs/network-v1/SPHLIB_SUBSTITUTION.json']
    inventory['distribution_scope_evidence']=sorted(set(inventory['distribution_scope_evidence']))
    licensebinding={'docs/network-v1/third-party/licenses/SPHLIB-MIT.txt':sha(licensepath.read_bytes())}
    requirements=inventory['component_requirements_by_kind']
    requirements['source']={'files':{**source_bind,**licensebinding}}
    for kind in ('linux-x86_64','windows-wsl2-x86_64'):
        files=requirements[kind]['files'];files.update(licensebinding)
        for name,digest in core['binary_sha256'].items():
            target='build/network-v1/pc-public-tools' if name=='v1/pc-public-tools' else 'build/monero-linux/'+name
            files[target]=digest
    for row in inventory['source_files']:
        if row['path'] in source_bind:
            name=Path(row['path']).name
            row.update(sha256=source_bind[row['path']],category='original_interface_adapter_to_permissive_third_party',
                component='PC sphlib compatibility adapter',license='BSD-3-Clause for original adapter; MIT sphlib implementation remains separate',
                copyright_notices=['Copyright (c) 2026 petereaton528-max'],modified='Independent adapter replacing held inherited implementation; no inherited rounds/constants copied',
                distributed='Source and rebuilt Linux/WSL2 only; old Windows implementation remains held',
                basis='SPHLIB_SUBSTITUTION.json plus exact compatibility and clean-build evidence',disposition='RETAIN_NEW_ADAPTER_AND_MIT_VENDOR_NOTICES')
    known={r['path'] for r in inventory['source_files']}
    for prefix,files in [('.upstream/monero/',new),('',{p.relative_to(ROOT).as_posix():p.read_bytes() for p in (ROOT/'experiments/sphlib').rglob('*') if p.is_file() and '__pycache__' not in p.parts})]:
        for name,data in files.items():
            path=prefix+name
            if path in known:continue
            vendor=('/pc_sphlib/' in path or '/vendor/' in path) and not path.endswith('/PROVENANCE.json')
            inventory['source_files'].append(dict(path=path,sha256=sha(data),category='third_party_permissive_source' if vendor else 'original_project_compatibility_experiment',
                component='sphlib 3.0' if vendor else 'PC sphlib adapter and verification',license='MIT' if vendor else 'BSD-3-Clause',
                copyright='Projet RNRT SAPHIR; embedded years retained' if vendor else 'petereaton528-max for eligible original portions',
                modified='One documented JH legacy-tail expression only' if name.endswith('jh_sph.c') else False,
                distributed='source',linkage='native static' if name.endswith(('.c','.h')) else 'not applicable',basis='Pinned PROVENANCE.json; independently written verification and adapters'))
    inventorypath.write_text(json.dumps(inventory,indent=2)+'\n')
    blockerspath=ROOT/'docs/network-v1/REDISTRIBUTION_BLOCKERS.json';blockers=json.loads(blockerspath.read_text())
    for row in blockers['rows']:
        if row['path'] in source_bind:
            row.update(disposition='LEGACY_BYTES_EXCLUDED_REPLACED_BY_INDEPENDENT_SPHLIB_ADAPTER',
                source_bundle_hold=False,binary_hold=True,
                binary_hold_by_kind={'linux-x86_64':False,'windows-wsl2-x86_64':False,'windows-native-preview-x86_64':True},
                replacement_sha256=source_bind[row['path']],evidence='SPHLIB_SUBSTITUTION.json; original permission remains unresolved for old archives/Windows objects',owner_relicense=False)
    blockerspath.write_text(json.dumps(blockers,indent=2)+'\n')
    print('NEW_SOURCE_LINUX_SUBSTITUTION_SCOPE_BOUND; OLD_WINDOWS_HOLDS_RETAINED')
if __name__=='__main__':main()
