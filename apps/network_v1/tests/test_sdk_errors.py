"""Structured SDK errors never echo untrusted response bodies."""
import unittest
from email.message import Message
from unittest.mock import Mock
from apps.network_v1.sdk import Client,APIError
class SDKErrors(unittest.TestCase):
    def test_bad_json_and_encoding(self):
        for raw in [b'private-marker-invalid-json',b'\xff']:
            client=Client();response=Mock();response.read.return_value=raw
            headers=Message();headers['Content-Type']='application/json';response.headers=headers
            response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
            client.opener.open=Mock(return_value=response)
            with self.assertRaises(APIError) as caught:client.network()
            self.assertEqual(caught.exception.code,'API_JSON');self.assertNotIn('private-marker',str(caught.exception))
    def test_invalid_argument_types_are_controlled(self):
        client=Client()
        for value in [None,1,{},True]:
            with self.assertRaises(ValueError):client.block(value)
        for value in [1,{},True]:
            with self.assertRaises(ValueError):client.leaderboard(value)
