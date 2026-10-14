"""New journal pages and runtime authority must never enter release archives."""
from pathlib import Path
import tempfile
import unittest
from apps.network_v1.release import archive

class PrivatePackagingTests(unittest.TestCase):
    def test_archival_and_recovery_material_rejected_before_publication(self):
        with tempfile.TemporaryDirectory(prefix='pc-v1-public-pack-test-') as home:
            for name in ('private.page','private.PAGE','password.credential','wallet.gui-state','wallet.pc-recovery','data.mdb','state.sqlite','control','CONTROL','tor/control_auth_cookie','identity/hs_ed25519_secret_key','credential'):
                target=Path(home)/'must-not-exist.zip'
                with self.assertRaises(ValueError):archive(target,{name:b'public dummy stand-in'},'source')
                self.assertFalse(target.exists())
    def test_public_metadata_archive_still_valid(self):
        from apps.network_v1.release import verify
        with tempfile.TemporaryDirectory(prefix='pc-v1-public-pack-test-') as home:
            target=Path(home)/'public.zip';archive(target,{'docs/NOTICE.md':b'public documentation'},'source')
            self.assertEqual(set(verify(target)['files']),{'docs/NOTICE.md','LICENSE_COMPLIANCE.json'})
    def test_import_verification_also_rejects_private_payload_names(self):
        import zipfile
        from apps.network_v1.release import verify
        with tempfile.TemporaryDirectory(prefix='pc-v1-public-pack-test-') as home:
            target=Path(home)/'untrusted.zip'
            with zipfile.ZipFile(target,'x') as z:z.writestr('tor/CONTROL_AUTH_COOKIE',b'public dummy stand-in')
            with self.assertRaises(ValueError):verify(target)

    def test_legacy_source_companion_does_not_relax_binary_identity(self):
        import json,zipfile
        from apps.network_v1.release import verify
        from src.network_identity import selected
        with tempfile.TemporaryDirectory(prefix='pc-v1-source-companion-') as home:
            base=Path(home)/'base.zip';archive(base,{'docs/NOTICE.md':b'public source notice'},'source')
            with zipfile.ZipFile(base) as z:files={n:z.read(n) for n in z.namelist()}
            manifest=json.loads(files['V1_MANIFEST.json'])
            manifest.update(zip(('network','genesis','profile'),selected('legacy-dev01')))
            manifest['version']='1.0.0-testnet-candidate.5'
            def write(name,kind):
                manifest['kind']=kind
                files['V1_MANIFEST.json']=json.dumps(manifest).encode()
                target=Path(home)/name
                with zipfile.ZipFile(target,'x') as z:
                    for key,raw in files.items():z.writestr(key,raw)
                return target
            source=write('source.zip','source')
            self.assertEqual(verify(source,source_companion=True)['kind'],'source')
            if selected()[0]!='PrivacyCoinDev01':
                with self.assertRaises(ValueError):verify(source)
            binary=write('binary.zip','linux-x86_64')
            with self.assertRaises(ValueError):verify(binary,source_companion=True)

if __name__=='__main__':unittest.main()
