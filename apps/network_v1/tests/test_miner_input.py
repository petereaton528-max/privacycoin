"""Private desktop input pipe, separate from interactive console prompting."""
import io
import unittest
from unittest.mock import Mock,patch
from apps.network_v1.__main__ import wallet_password

class MinerInputTests(unittest.TestCase):
    def test_private_pipe_never_reads_console(self):
        with io.TextIOWrapper(io.BytesIO(b'public dummy\n')) as pipe,patch('sys.stdin',pipe),patch('getpass.getpass',side_effect=AssertionError('console forbidden')):
            self.assertEqual(wallet_password(),b'public dummy')
    def test_unterminated_and_oversized_input_rejected(self):
        for raw in (b'no newline',b'x'*4096+b'\n'):
            with io.TextIOWrapper(io.BytesIO(raw)) as pipe,patch('sys.stdin',pipe),patch('getpass.getpass',side_effect=AssertionError('console forbidden')):
                with self.assertRaises(ValueError):wallet_password()
    def test_interactive_console_uses_hidden_prompt(self):
        console=Mock();console.isatty.return_value=True
        with patch('sys.stdin',console),patch('getpass.getpass',return_value='public dummy') as prompt:
            self.assertEqual(wallet_password(),b'public dummy');prompt.assert_called_once()

if __name__=='__main__':unittest.main()
