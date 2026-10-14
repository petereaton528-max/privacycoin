"""Installer boundaries, not native coin or clean-host acceptance."""
import os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from apps.network_v1 import native_bootstrap

class NativeInstall(unittest.TestCase):
    def test_bootstrap_passes_explicit_native_root(self):
        with patch('apps.network_v1.desktop.main') as desktop,patch.object(sys,'argv',['preview','--home','private-test-path']):
            native_bootstrap.main();desktop.assert_called_once()
            self.assertEqual(sys.argv[1:3],['--backend-root',str(native_bootstrap.ROOT)])
            self.assertEqual(sys.argv[3:],['--home','private-test-path'])

    @unittest.skipUnless(os.name=='nt','Windows installation boundary')
    def test_existing_n2_relative_and_parent_traversal_rejected_before_mkdir(self):
        from apps.network_v1 import native_install
        from src.phase6a import windows_private
        with tempfile.TemporaryDirectory(prefix='pc-v1-installer-boundary-') as raw,patch.object(windows_private,'mkdir') as mkdir:
            for target in (Path(raw),Path(raw)/'privacycoin-n2-desktop'/'new',Path('relative'),Path(raw)/'..'/'new'):
                with self.subTest(kind='unsafe destination'),self.assertRaises(ValueError):native_install.install(target)
            mkdir.assert_not_called()

    @unittest.skipUnless(os.name=='nt','Windows installation boundary')
    def test_only_fixed_bundled_payload_installed(self):
        from apps.network_v1 import native_install
        from src.phase6a import windows_private
        with tempfile.TemporaryDirectory(prefix='pc-v1-installer-boundary-') as raw,patch.object(windows_private,'mkdir') as mkdir,patch('apps.network_v1.release.install') as unpack:
            target=Path(raw)/'private'/'new';native_install.install(target)
            mkdir.assert_called_once_with(target.parent)
            unpack.assert_called_once_with(native_install.ROOT/'NATIVE_PAYLOAD.zip',target)

if __name__=='__main__':unittest.main()
