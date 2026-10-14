"""Synthetic archive/authentication failures; no network or service activation."""
import hashlib
import importlib.util
import lzma
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'services/privacy-network'))
import provision_tor as p


class TorProvisionTests(unittest.TestCase):
    def test_project_key_pin_prevents_metadata_fetch(self):
        for fingerprints in (['F'*40],[p.TOR_FINGERPRINT,'F'*40]):
            output=''.join('pub:::::::::\nfpr:::::::::'+fingerprint+':\n' for fingerprint in fingerprints).encode()
            with tempfile.TemporaryDirectory() as tmp:
                with patch.object(p,'fetch',return_value=b'UNTRUSTED_KEY') as fetch,patch.object(p.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=output)),patch.object(p,'authenticate') as auth:
                    with self.assertRaisesRegex(RuntimeError,'fingerprint mismatch'):p.project_metadata(Path(tmp))
                self.assertEqual(fetch.call_count,1);auth.assert_not_called()

    def test_project_signature_failure_prevents_index_fetch(self):
        output=('pub:::::::::\nfpr:::::::::'+p.TOR_FINGERPRINT+':\n').encode()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(p,'fetch',side_effect=[b'KEY_FIXTURE',b'BAD_RELEASE']) as fetch,patch.object(p.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=output)),patch.object(p,'authenticate',side_effect=RuntimeError('signature failed')):
                with self.assertRaisesRegex(RuntimeError,'signature'):p.project_metadata(Path(tmp))
            self.assertEqual(fetch.call_count,2)

    def test_signed_index_digest_and_decompression_framing(self):
        data=b'Package: tor\nArchitecture: amd64\n\n';raw=lzma.compress(data)
        release=' '+hashlib.sha256(raw).hexdigest()+' '+str(len(raw))+' universe/binary-amd64/Packages.xz\n'
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(p,'authenticate',return_value=(None,release)),patch.object(p,'fetch',side_effect=[b'SIGNED_FIXTURE',raw]):
                _,packages=p.fresh_metadata(root)
                self.assertEqual(packages.read_bytes(),data)
            for bad in (raw+b'extra',b'corrupt'):
                with patch.object(p,'authenticate',return_value=(None,release)),patch.object(p,'fetch',side_effect=[b'SIGNED_FIXTURE',bad]):
                    with self.assertRaisesRegex(RuntimeError,'hash mismatch'):p.fresh_metadata(root)

    def test_signature_failure_prevents_package_index_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(p,'fetch',return_value=b'INVALID_SIGNATURE') as fetch,patch.object(p,'authenticate',side_effect=RuntimeError('signature verification failed')):
                with self.assertRaisesRegex(RuntimeError,'signature'):p.fresh_metadata(Path(tmp))
            self.assertEqual(fetch.call_count,1)

    @unittest.skipUnless(os.name=='posix','POSIX destination validation')
    def test_destination_no_clobber_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory(dir=Path.home(),prefix='pc-v1-provision-test-') as tmp:
            root=Path(tmp);root.chmod(0o700)
            destination=root/'new';p.private_target(destination)
            self.assertEqual(destination.stat().st_mode&0o777,0o700)
            with self.assertRaises(FileExistsError):p.private_target(destination)
            link=root/'alias';link.symlink_to(destination,target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,'Unsafe'):p.private_target(link/'child')
            self.assertFalse((destination/'child').exists())


if __name__=='__main__':unittest.main()
