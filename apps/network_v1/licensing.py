# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 petereaton528-max
"""Bound explicit licensing records to local archives; fail closed for release.

This checks supplied evidence. It does not determine copyright title or grant
vendor permission, and it never turns a local inspection into public approval.
"""
import hashlib
import json

REQUIRED = ('LICENSE', 'LICENSE_SCOPE.md', 'CONTRIBUTING.md',
            'docs/network-v1/LICENSE_STATUS.md',
            'docs/network-v1/LICENSE_INVENTORY.json',
            'docs/network-v1/THIRD_PARTY_NOTICES.md',
            'docs/network-v1/REDISTRIBUTION.md')
TEXT_ROOT = 'docs/network-v1/third-party/licenses/'
TEXTS = ('GPL-2.txt', 'GPL-3.txt', 'LGPL-2.1.txt', 'LGPL-3.txt', 'Apache-2.0.txt')

# Frozen, reviewed original-code subset. Changing these inputs requires a new
# scope review, not just an assertion in a package-supplied inventory. Normalize
# checkout line endings only; all other source changes fail closed.
SDK_SOURCE = {
    'LICENSE':'c95157302ec67f7fbcfd1a7989b124ec17020c1d06b7a8bb24593eb7384b989f',
    'apps/network_v1/__init__.py':'b4964fc9f8726d866ec754e6ac55ef969c242ea502aba889ff1a617a880ffbe9',
    'apps/network_v1/sdk.py':'6d992a61f29c827dd2685acd432c5470c787fbdebf805f9cc26ac538e9528347',
}
SDK_DOCUMENTS = ('docs/network-v1/SDK_SOURCE_SCOPE.md','SOURCE_REVISION.json')


def sdk_assessment(files):
    issues=[]
    for name,digest in SDK_SOURCE.items():
        if name not in files or hashlib.sha256(files[name].replace(b'\r\n',b'\n')).hexdigest()!=digest:
            issues.append('SDK_REVIEWED_SOURCE_CORRESPONDENCE:'+name)
    for name in SDK_DOCUMENTS:
        if name not in files:issues.append('SDK_SCOPE_DOCUMENT_REQUIRED:'+name)
    if set(files)-set(SDK_SOURCE)-set(SDK_DOCUMENTS):
        issues.append('SDK_UNREVIEWED_EXTRA_CONTENT')
    return dict(format=1,kind='sdk-source',project_license='BSD-3-Clause',
        owner_license_approved=True,copyright='Copyright (c) 2026 petereaton528-max',
        scope='Frozen standalone original Python read SDK source only; no runtimes or native core',
        required_document_sha256={n:hashlib.sha256(b).hexdigest() for n,b in sorted(files.items())},
        redistribution_ready=not issues,unresolved=sorted(issues),
        public_release_authorized=False,legal_clearance_claimed=False)


def assessment(files, kind):
    if kind=='sdk-source':return sdk_assessment(files)
    missing = [n for n in (*REQUIRED, *(TEXT_ROOT+n for n in TEXTS)) if n not in files]
    issues = list(missing)
    inventory = None
    if 'docs/network-v1/LICENSE_INVENTORY.json' in files:
        inventory = json.loads(files['docs/network-v1/LICENSE_INVENTORY.json'])
        scoped=inventory.get('distribution_obligations_by_kind')
        if scoped is None:
            issues += inventory['unresolved_distribution_obligations']
        else:
            issues += scoped.get(kind, ['UNREVIEWED_DISTRIBUTION_KIND'])
            # The scoped inventory is a reviewed attestation, bound with its
            # full per-file evidence. It cannot omit evidence from a package.
            for n in inventory.get('distribution_scope_evidence',[]):
                if n not in files:issues.append('DISTRIBUTION_SCOPE_EVIDENCE_REQUIRED:'+n)
            for n in inventory.get('excluded_unverified_source_files',[]):
                if n in files:issues.append('EXCLUDED_UNVERIFIED_SOURCE_PRESENT:'+n)
        # New reviewed inventories bind runtime bytes AND their notices. A
        # package-wide license file cannot stand in for component correspondence.
        requirements=inventory.get('component_requirements_by_kind',{}).get(kind,{})
        for n,digest in requirements.get('files',{}).items():
            if n not in files or hashlib.sha256(files[n]).hexdigest()!=digest:
                issues.append('COMPONENT_LICENSE_CORRESPONDENCE:'+n)
        if requirements.get('source_members'):
            try:
                refs=json.loads(files.get('CORRESPONDING_SOURCE.json',b'{}'))
                for name,record in requirements['source_members'].items():
                    if refs.get('archives',{}).get(name)!=record['sha256']:
                        issues.append('COMPONENT_SOURCE_PAIR_REQUIRED:'+name)
            except (ValueError,TypeError,AttributeError):
                issues.append('INVALID_CORRESPONDING_SOURCE_MANIFEST')
    if kind != 'source':
        if 'CORRESPONDING_SOURCE.json' not in files:
            issues.append('EXACT_CORRESPONDING_SOURCE_MANIFEST_REQUIRED')
        if 'windows-native' in kind and (inventory is None or 'distribution_obligations_by_kind' not in inventory):
            issues.append('WINDOWS_VENDOR_PASS_THROUGH_AND_STATIC_RUNTIME_REVIEW_REQUIRED')
    return dict(format=1, project_license='BSD-3-Clause',
                owner_license_approved=True, copyright='Copyright (c) 2026 petereaton528-max',
                scope='Original eligible contributions only; retain component exceptions',
                kind=kind, required_document_sha256={n:hashlib.sha256(files[n]).hexdigest()
                    for n in (*REQUIRED, *(TEXT_ROOT+n for n in TEXTS)) if n in files},
                redistribution_ready=not issues, unresolved=sorted(set(issues)),
                public_release_authorized=False, legal_clearance_claimed=False)


def require_redistributable(record):
    if record.get('redistribution_ready') is not True or record.get('unresolved'):
        raise ValueError('DISTRIBUTION_COMPLIANCE_BLOCKED')


def inspect(path):
    from .release import verify
    import zipfile
    manifest = verify(path)
    with zipfile.ZipFile(path) as z:
        if 'LICENSE_COMPLIANCE.json' not in manifest['files']:
            raise ValueError('LICENSE_RECORD_MISSING')
        files = {n:z.read(n) for n in manifest['files'] if n != 'LICENSE_COMPLIANCE.json'}
        actual = json.loads(z.read('LICENSE_COMPLIANCE.json'))
        if actual != assessment(files, manifest['kind']):
            raise ValueError('LICENSE_RECORD_CORRESPONDENCE')
        return actual


def inspect_set(path, source_directory):
    """Check local equal-access delivery materials; never assert public access.

    This verifies supplied source bytes, not copyright title or reproduction of
    a vendor build. Historical archives without member bindings retain their
    original assessment; new inventories carry exact component member hashes.
    """
    from pathlib import Path
    import zipfile
    from .release import verify
    record=inspect(path)
    with zipfile.ZipFile(path) as z:
        inventory=json.loads(z.read('docs/network-v1/LICENSE_INVENTORY.json'))
        refs=json.loads(z.read('CORRESPONDING_SOURCE.json'))
    required=inventory.get('component_requirements_by_kind',{}).get(record['kind'],{}).get('source_members',{})
    checked={}
    archives=refs.get('archives')
    if not isinstance(archives,dict) or not archives:raise ValueError('SOURCE_ARCHIVE_SET_REQUIRED')
    for name,digest in archives.items():
        if not isinstance(name,str) or '/' in name or '\\' in name or ':' in name or name in ('.','..'):
            raise ValueError('UNSAFE_SOURCE_ARCHIVE_NAME')
        candidate=Path(source_directory)/name
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError('SOURCE_ARCHIVE_MISSING')
        h=hashlib.sha256()
        with candidate.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
        if h.hexdigest()!=digest:raise ValueError('SOURCE_ARCHIVE_HASH_MISMATCH')
        verify(candidate,source_companion=True)
        with zipfile.ZipFile(candidate) as z:
            for member,expected in required.get(name,{}).get('members',{}).items():
                try: actual=hashlib.sha256(z.read(member)).hexdigest()
                except KeyError:raise ValueError('CORRESPONDING_SOURCE_MEMBER_MISSING') from None
                if actual!=expected:raise ValueError('CORRESPONDING_SOURCE_MEMBER_MISMATCH')
        checked[name]=digest
    if set(required)-set(checked):raise ValueError('COMPONENT_SOURCE_PAIR_MISSING')
    return dict(result='PASS_LOCAL_SOURCE_DELIVERY_CORRESPONDENCE',archives=checked,
                license_assessment=record,public_access_verified=False)


if __name__ == '__main__':
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument('archive')
    p.add_argument('--require-redistributable',action='store_true')
    p.add_argument('--source-directory',help='Verify local paired archives and exact required source members')
    args=p.parse_args()
    value=inspect_set(args.archive,args.source_directory) if args.source_directory else inspect(args.archive)
    print(json.dumps(value,indent=2))
    if args.require_redistributable:
        require_redistributable(value.get('license_assessment',value))
