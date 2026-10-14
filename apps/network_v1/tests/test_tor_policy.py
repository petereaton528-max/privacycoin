"""Version gating tests do not activate Tor or imply runtime authenticity."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[3] / 'services/privacy-network'
sys.path.insert(0, str(PATH))
import tor_policy


class TorPolicyTests(unittest.TestCase):
    def test_stable_floor_and_strict_output(self):
        for version in ('0.4.9.14', '0.4.9.15', '0.4.10.1'):
            self.assertEqual(tor_policy.version_policy('Tor version '+version+'.\nBuild information'), version)
        for output in ('', 'Tor version 0.4.9.11.', 'Tor version 0.4.9.13.',
                       'Tor version 0.4.9.14-alpha.', 'Tor version 0.4.9.14-rc.',
                       'Tor version 00.4.9.14.', 'Tor version 0.4.9.14. extra',
                       'Tor version 0.4.9.14.\n'+'x'*4096, None):
            with self.assertRaises(ValueError):tor_policy.version_policy(output)

    def test_probe_failure_is_closed_and_diagnostics_are_not_echoed(self):
        for failure in (OSError('PRIVATE_SYSTEM_DETAIL'), subprocess.TimeoutExpired('tor',10)):
            with patch.object(tor_policy.subprocess,'run',side_effect=failure):
                with self.assertRaisesRegex(ValueError,'^TOR_VERSION_CHECK_FAILED$'):tor_policy.require_current('/unused')
        for result in (types.SimpleNamespace(returncode=1,stdout=b'PRIVATE'),
                       types.SimpleNamespace(returncode=0,stdout=b'\xff')):
            with patch.object(tor_policy.subprocess,'run',return_value=result):
                with self.assertRaisesRegex(ValueError,'^TOR_VERSION_CHECK_FAILED$'):tor_policy.require_current('/unused')

    @unittest.skipUnless(sys.platform=='linux','Production Tor/session backend requires Linux')
    def test_outdated_runtime_cannot_bind_or_enable_network(self):
        from apps.network_v1.onion import TorSession
        session=TorSession.__new__(TorSession)
        session.owned=types.SimpleNamespace(binary='/unused-tor',process=None,start=Mock(),close=Mock())
        stale=Mock();session.channels=[stale];session.threads=[]
        session.config=Path('/unused-torrc');session.lines=['DisableNetwork 1']
        writer=Mock()
        with patch('apps.network_v1.onion.dependencies',return_value=(None,None,writer,None)), \
             patch('apps.network_v1.onion.Channel') as channel, \
             patch.object(tor_policy,'require_current',side_effect=ValueError('TOR_SECURITY_UPDATE_REQUIRED')):
            with self.assertRaisesRegex(ValueError,'TOR_SECURITY_UPDATE_REQUIRED'):session.start('CONNECT VIA TOR')
        writer.assert_called_once_with(session.config,['DisableNetwork 1']);channel.assert_not_called();session.owned.start.assert_not_called()
        stale.close.assert_called_once();session.owned.close.assert_called_once();self.assertEqual(session.channels,[])


if __name__=='__main__':unittest.main()
