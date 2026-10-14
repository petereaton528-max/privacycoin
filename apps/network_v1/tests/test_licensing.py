# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 petereaton528-max
import json
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from apps.network_v1.licensing import assessment, inspect, inspect_set, require_redistributable
from apps.network_v1.release import archive, verify


class LicensingTests(unittest.TestCase):
    def test_actual_component_license_texts_match_reviewed_byte_bindings(self):
        root=Path(__file__).resolve().parents[3]
        inventory=json.loads((root/'docs/network-v1/LICENSE_INVENTORY.json').read_bytes())
        for kind in ('source','linux-x86_64','windows-wsl2-x86_64'):
            for name,digest in inventory['component_requirements_by_kind'][kind]['files'].items():
                if name.startswith('docs/network-v1/third-party/licenses/'):
                    self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),digest,name)

    def test_component_bytes_and_exception_notices_are_required(self):
        from apps.network_v1.licensing import REQUIRED,TEXT_ROOT,TEXTS
        files={n:b'legal' for n in (*REQUIRED,*(TEXT_ROOT+n for n in TEXTS))}
        library='runtime/lib/libexample.so';notice=TEXT_ROOT+'GCC-Runtime-Exception-3.1.txt'
        files[library]=b'reviewed runtime';files[notice]=b'reviewed exception'
        inventory=dict(distribution_obligations_by_kind={'linux-x86_64':[]},component_requirements_by_kind={
            'linux-x86_64':dict(files={n:hashlib.sha256(files[n]).hexdigest() for n in (library,notice)})})
        files['docs/network-v1/LICENSE_INVENTORY.json']=json.dumps(inventory).encode()
        files['CORRESPONDING_SOURCE.json']=b'{}'
        require_redistributable(assessment(files,'linux-x86_64'))
        files[library]+=b' changed'
        self.assertIn('COMPONENT_LICENSE_CORRESPONDENCE:'+library,assessment(files,'linux-x86_64')['unresolved'])
        files.pop(notice)
        self.assertIn('COMPONENT_LICENSE_CORRESPONDENCE:'+notice,assessment(files,'linux-x86_64')['unresolved'])

    def test_source_delivery_checks_exact_archive_and_members(self):
        from apps.network_v1.licensing import REQUIRED,TEXT_ROOT,TEXTS
        with tempfile.TemporaryDirectory(prefix='pc-source-delivery-') as d:
            root=Path(d);source=root/'supplier.zip'
            digest=archive(source,{'supplier/source.c':b'covered source'},'source')
            files={n:b'legal' for n in (*REQUIRED,*(TEXT_ROOT+n for n in TEXTS))}
            members={'supplier/source.c':hashlib.sha256(b'covered source').hexdigest()}
            inventory=dict(distribution_obligations_by_kind={'linux-x86_64':[]},component_requirements_by_kind={
                'linux-x86_64':dict(source_members={'supplier.zip':dict(sha256=digest,members=members)})})
            files['docs/network-v1/LICENSE_INVENTORY.json']=json.dumps(inventory).encode()
            files['CORRESPONDING_SOURCE.json']=json.dumps(dict(archives={'supplier.zip':digest})).encode()
            binary=root/'binary.zip';archive(binary,files,'linux-x86_64')
            result=inspect_set(binary,root)
            self.assertEqual(result['archives'],{'supplier.zip':digest})
            self.assertFalse(result['public_access_verified'])
            members['supplier/source.c']='0'*64
            files['docs/network-v1/LICENSE_INVENTORY.json']=json.dumps(inventory).encode()
            bad=root/'bad.zip';archive(bad,files,'linux-x86_64')
            with self.assertRaisesRegex(ValueError,'SOURCE_MEMBER_MISMATCH'):inspect_set(bad,root)
            source.write_bytes(source.read_bytes()+b'changed')
            with self.assertRaisesRegex(ValueError,'SOURCE_ARCHIVE_HASH_MISMATCH'):inspect_set(binary,root)

    def test_source_pair_metadata_cannot_escape_delivery_directory(self):
        from apps.network_v1.licensing import REQUIRED,TEXT_ROOT,TEXTS
        files={n:b'legal' for n in (*REQUIRED,*(TEXT_ROOT+n for n in TEXTS))}
        inventory=dict(distribution_obligations_by_kind={'linux-x86_64':[]},component_requirements_by_kind={
            'linux-x86_64':dict(source_members={'supplier.zip':dict(sha256='a'*64,members={})})})
        files['docs/network-v1/LICENSE_INVENTORY.json']=json.dumps(inventory).encode()
        files['CORRESPONDING_SOURCE.json']=b'{"archives":{}}'
        self.assertIn('COMPONENT_SOURCE_PAIR_REQUIRED:supplier.zip',assessment(files,'linux-x86_64')['unresolved'])
        with tempfile.TemporaryDirectory(prefix='pc-source-path-') as d:
            for i,name in enumerate(('../supplier.zip','..\\supplier.zip','C:source.zip')):
                files['CORRESPONDING_SOURCE.json']=json.dumps(dict(archives={name:'a'*64})).encode()
                p=Path(d)/str(i);archive(p,files,'linux-x86_64')
                with self.assertRaisesRegex(ValueError,'UNSAFE_SOURCE_ARCHIVE_NAME'):inspect_set(p,d)

    def test_sdk_subset_does_not_inherit_unrelated_native_holds(self):
        from apps.network_v1.licensing import SDK_SOURCE,SDK_DOCUMENTS
        root=Path(__file__).resolve().parents[3]
        files={n:(root/n).read_bytes() for n in SDK_SOURCE}
        files.update({SDK_DOCUMENTS[0]:(root/SDK_DOCUMENTS[0]).read_bytes(),SDK_DOCUMENTS[1]:b'{}'})
        require_redistributable(assessment(files,'sdk-source'))
        self.assertFalse(assessment(files,'sdk-source')['public_release_authorized'])
        files['runtime/unreviewed.dll']=b'not approved'
        self.assertIn('SDK_UNREVIEWED_EXTRA_CONTENT',assessment(files,'sdk-source')['unresolved'])
        files.pop('runtime/unreviewed.dll');files['apps/network_v1/sdk.py']+=b'\n# changed'
        self.assertFalse(assessment(files,'sdk-source')['redistribution_ready'])

    def test_noninteractive_bundle_excludes_readline_without_excluding_sqlite(self):
        from apps.network_v1.bundle_linux import application_runtime_file
        for n in ('readline.cpython-312-x86_64-linux-gnu.so','_gdbm.cpython-312.so','_dbm.cpython-312.so'):
            self.assertFalse(application_runtime_file(Path('lib-dynload')/n))
        for n in ('_sqlite3.cpython-312.so','_tkinter.cpython-312.so','ssl.py'):
            self.assertTrue(application_runtime_file(Path(n)))

    def test_scoped_inventory_does_not_transfer_windows_vendor_hold_to_linux(self):
        from apps.network_v1.licensing import REQUIRED,TEXT_ROOT,TEXTS
        files={n:b'legal' for n in (*REQUIRED,*(TEXT_ROOT+n for n in TEXTS))}
        files['docs/network-v1/LICENSE_INVENTORY.json']=json.dumps(dict(
            distribution_obligations_by_kind={'linux-x86_64':['CRYPTO_PERMISSION_REQUIRED'],
                'windows-native-preview-x86_64':['CRYPTO_PERMISSION_REQUIRED','VENDOR_TERMS_REQUIRED']},
            distribution_scope_evidence=['review.json'])).encode()
        files['CORRESPONDING_SOURCE.json']=b'{}'
        linux=assessment(files,'linux-x86_64')
        self.assertIn('DISTRIBUTION_SCOPE_EVIDENCE_REQUIRED:review.json',linux['unresolved'])
        files['review.json']=b'public scope evidence'
        self.assertEqual(assessment(files,'linux-x86_64')['unresolved'],['CRYPTO_PERMISSION_REQUIRED'])
        self.assertIn('VENDOR_TERMS_REQUIRED',assessment(files,'windows-native-preview-x86_64')['unresolved'])
        self.assertIn('UNREVIEWED_DISTRIBUTION_KIND',assessment(files,'arbitrary-kind')['unresolved'])

    def test_missing_terms_cannot_pass(self):
        record=assessment({},'source')
        self.assertFalse(record['redistribution_ready'])
        self.assertIn('LICENSE',record['unresolved'])
        with self.assertRaisesRegex(ValueError,'COMPLIANCE_BLOCKED'):
            require_redistributable(record)

    def test_inventory_uncertainty_is_not_cleared_by_notice(self):
        from apps.network_v1.licensing import REQUIRED,TEXT_ROOT,TEXTS
        files={n:b'legal' for n in (*REQUIRED,*(TEXT_ROOT+n for n in TEXTS))}
        files['docs/network-v1/LICENSE_INVENTORY.json']=json.dumps(dict(unresolved_distribution_obligations=['RIGHTS_UNVERIFIED'])).encode()
        self.assertEqual(assessment(files,'source')['unresolved'],['RIGHTS_UNVERIFIED'])
        self.assertIn('EXACT_CORRESPONDING_SOURCE_MANIFEST_REQUIRED',assessment(files,'linux-x86_64')['unresolved'])

    def test_manifest_binds_licensing_and_detects_correspondence_tampering(self):
        with tempfile.TemporaryDirectory(prefix='pc-license-test-') as d:
            p=Path(d)/'test.zip'
            archive(p,{'example.txt':b'not a runtime'},'source')
            self.assertFalse(inspect(p)['redistribution_ready'])
            self.assertIn('LICENSE_COMPLIANCE.json',verify(p)['files'])
            with self.assertRaisesRegex(ValueError,'NO_RELEASE_OVERWRITE'):
                archive(p,{},'source')

    def test_eligible_license_material_is_selected(self):
        from apps.network_v1.release import source_files
        files=source_files()
        for n in ('LICENSE','LICENSE_SCOPE.md','CONTRIBUTING.md','docs/network-v1/third-party/licenses/GPL-3.txt'):
            self.assertIn(n,files)
        self.assertIn(b'Copyright (c) 2026 petereaton528-max',files['LICENSE'])

    def test_rehashed_forged_approval_still_rejected(self):
        with tempfile.TemporaryDirectory(prefix='pc-license-forgery-') as d:
            original=Path(d)/'original.zip';forged=Path(d)/'forged.zip'
            archive(original,{'example.txt':b'public fixture'},'source')
            with zipfile.ZipFile(original) as z:files={n:z.read(n) for n in z.namelist()}
            record=json.loads(files['LICENSE_COMPLIANCE.json'])
            record['redistribution_ready']=True;record['unresolved']=[]
            files['LICENSE_COMPLIANCE.json']=json.dumps(record).encode()
            manifest=json.loads(files['V1_MANIFEST.json'])
            manifest['files']['LICENSE_COMPLIANCE.json']=hashlib.sha256(files['LICENSE_COMPLIANCE.json']).hexdigest()
            files['V1_MANIFEST.json']=json.dumps(manifest).encode()
            with zipfile.ZipFile(forged,'x') as z:
                for n,b in files.items():z.writestr(n,b)
            with self.assertRaisesRegex(ValueError,'LICENSE_RECORD_CORRESPONDENCE'):
                inspect(forged)


if __name__=='__main__':unittest.main()
