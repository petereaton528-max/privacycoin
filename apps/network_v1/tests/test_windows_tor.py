"""Native Tor path/ownership routing; mocked routing is not Tor acceptance."""
import os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from apps.network_v1 import desktop_backend as db,onion
onion.dependencies()
import tor_runtime

class TorPortability(unittest.TestCase):
    def test_config_injection_and_relative_paths_rejected(self):
        for value in ('relative','/tmp/a\nDisableNetwork 0','/tmp/a\rHiddenServiceDir x','/tmp/a\tvalue'):
            with self.subTest(kind='unsafe path'),self.assertRaises(ValueError):tor_runtime.tor_path(value)

    def test_config_path_preserves_posix_rule_and_quotes_windows(self):
        with tempfile.TemporaryDirectory(prefix='pc-v1-tor-path-') as raw:
            value=Path(raw)/'identity'
            encoded=tor_runtime.config_path(value)
            self.assertEqual(encoded,'"'+value.as_posix()+'"' if os.name=='nt' else str(value))

    @unittest.skipUnless(os.name=='nt','actual Windows NTFS path semantics')
    def test_windows_spaces_supported_quotes_rejected(self):
        with tempfile.TemporaryDirectory(prefix='pc-v1-tor-path-') as raw:
            value=Path(raw)/'Private Identity'
            self.assertEqual(tor_runtime.config_path(value),'"'+value.as_posix()+'"')
            with self.assertRaises(ValueError):tor_runtime.config_path(Path(raw)/'a"bad')

    @unittest.skipUnless(os.name=='nt','Windows bundled executable boundary')
    def test_windows_openssl_has_no_path_fallback(self):
        with tempfile.TemporaryDirectory(prefix='pc-v1-tor-tools-') as raw,patch.object(onion,'ROOT',Path(raw)):
            with self.assertRaisesRegex(ValueError,'BUNDLED_TLS_TOOL_REQUIRED'):onion.openssl_binary()
            binary=Path(raw)/'runtime/bin/pc-tls-tools.exe';binary.parent.mkdir(parents=True);binary.write_bytes(b'PUBLIC_NONEXECUTABLE_PATH_TEST')
            self.assertEqual(onion.openssl_binary(),str(binary))

    @unittest.skipUnless(os.name=='nt','Windows ANSI filesystem encoding')
    def test_windows_config_roundtrips_system_encoding(self):
        with tempfile.TemporaryDirectory(prefix='pc-v1-tor-path-') as raw:
            value=Path(raw)/'Tor 数据'
            try:expected=value.as_posix().encode('mbcs',errors='strict')
            except UnicodeError:self.skipTest('Chinese unavailable in this system encoding')
            import re
            encoded=tor_runtime.config_path(value)[1:-1]
            decoded=re.sub(rb'\\([0-7]{3})',lambda m:bytes([int(m[1],8)]),encoded.encode('ascii'))
            self.assertEqual(decoded,expected)
            self.assertNotIn('\n',encoded)

    @unittest.skipUnless(os.name=='nt','Windows ANSI filesystem encoding')
    def test_unrepresentable_filename_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix='pc-v1-tor-path-') as raw:
            value=Path(raw)/'Tor \U0001f680'
            try:value.as_posix().encode('mbcs',errors='strict')
            except UnicodeError:
                with self.assertRaisesRegex(ValueError,'SYSTEM_ENCODING_UNSUPPORTED'):tor_runtime.config_path(value)
            else:self.skipTest('System code page supports this name')

    @unittest.skipUnless(os.name=='nt','Windows owned job routing')
    def test_owned_tor_uses_job_and_clears_process_on_close(self):
        fake=Mock(pid=12345);fake.poll.return_value=None
        owned=tor_runtime.OwnedTor(Path(sys.executable),Path(tempfile.gettempdir())/'public-routing-only.torrc')
        with patch.object(owned,'verify'),patch('apps.network_v1.windows_owned.spawn',return_value=fake) as spawn,patch('apps.network_v1.windows_owned.stop') as stop:
            owned.start();self.assertIs(owned.process,fake);self.assertEqual(spawn.call_count,1)
            self.assertNotIn('preexec_fn',spawn.call_args.kwargs)
            owned.close();stop.assert_called_once_with(fake);self.assertIsNone(owned.process)

if __name__=='__main__':unittest.main()
