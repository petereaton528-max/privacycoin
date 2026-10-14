"""Regression boundaries for reviewed seeds and partial/crashed Tor lifecycle."""
import base64
import hashlib
import os
from pathlib import Path
import types
import unittest
import tempfile
import sys
from unittest.mock import Mock,MagicMock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'services/privacy-network'))
import tor_policy

from apps.network_v1.rpc import NETWORK,GENESIS,PROFILE


def peer(n):
    key=bytes([n])*32;version=b'\x03'
    onion=base64.b32encode(key+hashlib.sha3_256(b'.onion checksum'+key+version).digest()[:2]+version).decode().lower()+'.onion'
    return dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,onion=onion,certificate_sha256=f'{n:064x}')


def catalog(*peers):return dict(version=1,network=NETWORK,genesis=GENESIS,profile=PROFILE,peers=list(peers))


@unittest.skipUnless(os.name=='posix','Production private-file/Tor backend is POSIX only')
class NetworkStabilityTests(unittest.TestCase):
    def test_tor_provision_requires_consent_and_failure_preserves_settings(self):
        from apps.network_v1.desktop_backend import Product
        product=Product.__new__(Product);product.settings=dict(tor_binary=None,peers=[])
        product.tor=None;product.home=Path('/unused-private');product.stop=Mock()
        child=Mock();child.wait.return_value=1;product.spawn=Mock(return_value=child)
        for request in (dict(command='tor_provision'),dict(command='tor_provision',consent='NO'),dict(command='tor_provision',consent='DOWNLOAD VERIFIED TOR',url='https://example.invalid')):
            with self.assertRaises(ValueError):product.dispatch(request)
        product.spawn.assert_not_called()
        with self.assertRaisesRegex(ValueError,'TOR_PROVISIONING_FAILED'):product.dispatch(dict(command='tor_provision',consent='DOWNLOAD VERIFIED TOR'))
        product.stop.assert_called_once_with(child);self.assertEqual(product.settings,dict(tor_binary=None,peers=[]))
        self.assertIn('--source',product.spawn.call_args.args[0]);self.assertEqual(product.spawn.call_args.args[0][-1],'torproject')

    def test_replaceable_seeds_conflicts_checksum_bounds(self):
        from apps.network_v1.peers import bootstrap
        a,b=peer(1),peer(2)
        self.assertEqual(bootstrap([catalog(a),catalog(b,a)]),[a,b])
        self.assertEqual(bootstrap([catalog(b)]),[b])
        for bad in ([dict(catalog(a),version=True)],[catalog(dict(a,onion='a'*56+'.onion'))],
                    [catalog(a,dict(a,certificate_sha256='f'*64))],[catalog(*[peer(n) for n in range(1,10)])]):
            with self.assertRaises((ValueError,TypeError)):bootstrap(bad)
        self.assertEqual(a,peer(1))

    def session(self):
        from apps.network_v1.onion import TorSession
        session=TorSession.__new__(TorSession)
        session.owned=types.SimpleNamespace(binary=Path('/unused-tor'),process=None,close=Mock(),start=Mock())
        session.channels=[];session.threads=[];session.ingress=31000;session.node_p2p=31001
        session.cert=Path('/unused-public.crt');session.key=Path('/unused-private.key');session.socks=31002
        session.peers=[(31003,peer(1)),(31004,peer(2))];session.lines=['DisableNetwork 1'];session.config=Path('/unused-torrc')
        return session

    def test_partial_constructor_failure_closes_registered_channels(self):
        session=self.session();ingress=Mock();connector=Mock()
        with patch('tor_policy.require_current',return_value='0.4.9.14'),patch('apps.network_v1.onion.dependencies',return_value=(None,None,Mock(),None)),patch('apps.network_v1.onion.Channel',side_effect=[ingress,connector,OSError('owned bind failure')]):
            with self.assertRaises(OSError):session.start('CONNECT VIA TOR')
        ingress.close.assert_called_once();connector.close.assert_called_once()
        self.assertEqual(session.channels,[]);self.assertEqual(session.state,'DISABLED')

    def test_crashed_tor_restart_reaps_prior_listeners(self):
        session=self.session();old=Mock();session.channels=[old]
        session.peers=[];new=Mock()
        with patch('tor_policy.require_current',return_value='0.4.9.14'),patch('apps.network_v1.onion.dependencies',return_value=(None,None,Mock(),None)),patch('apps.network_v1.onion.Channel',return_value=new):
            session.start('CONNECT VIA TOR');old.close.assert_called_once()
            session.close()
        new.close.assert_called_once();self.assertEqual(session.state,'DISABLED')

    def test_tor_close_failure_still_closes_channels(self):
        session=self.session();first=Mock();second=Mock();session.channels=[first,second]
        session.owned.close.side_effect=OSError('owned close failure')
        with patch('apps.network_v1.onion.dependencies',return_value=(None,None,Mock(),None)):
            with self.assertRaises(OSError):session.close()
        first.close.assert_called_once();second.close.assert_called_once();self.assertEqual(session.channels,[])

    def test_dead_first_seed_does_not_monopolize_discovery(self):
        from apps.network_v1.desktop_backend import Product
        product=Product.__new__(Product);product.settings=dict(peers=[peer(1),peer(2)]);product.discovery_cursor=0
        product.tor=types.SimpleNamespace(socks=31010,status=lambda:dict(state='TOR_READY'))
        with patch('apps.network_v1.onion.discover',side_effect=[OSError('dead seed'),[peer(2)]]) as discover:
            with self.assertRaises(OSError):product.dispatch(dict(command='discover_peers'))
            result=product.dispatch(dict(command='discover_peers'))
        self.assertEqual(result['candidates'],[peer(2)])
        self.assertEqual(discover.call_args_list[1].args[0],peer(2))

    def test_shutdown_failure_cannot_leave_owned_node_or_lock(self):
        from apps.network_v1.desktop_backend import Product
        product=Product.__new__(Product);product.session=types.SimpleNamespace(close=Mock())
        product.resource=None;product.miner='miner';product.index='index';product.node='node';product.guard=MagicMock()
        product.tor=types.SimpleNamespace(close=Mock(side_effect=OSError('owned Tor close failure')));product.stop=Mock()
        with self.assertRaises(OSError):product.close()
        self.assertEqual([c.args[0] for c in product.stop.call_args_list],['miner','index','node'])
        product.guard.__exit__.assert_called_once_with(None,None,None)

    def test_config_failure_does_not_change_memory_or_start_connections(self):
        from apps.network_v1.desktop_backend import Product
        product=Product.__new__(Product);product.settings=dict(tor_binary=None,peers=[peer(1)])
        product.settings_file=Path('/unused-new-config');product.node=None
        with patch('apps.network_v1.desktop_backend.c.write_private',side_effect=OSError('private write failure')):
            with self.assertRaises(OSError):product.dispatch(dict(command='peer_add',descriptor=peer(2)))
        self.assertEqual(product.settings,dict(tor_binary=None,peers=[peer(1)]))

    def test_pin_does_not_override_expired_certificate(self):
        from apps.network_v1.onion import pinned
        raw=b'PUBLIC_TEST_CERTIFICATE';value=dict(peer(1),certificate_sha256=hashlib.sha256(raw).hexdigest())
        secure=Mock();secure.getpeercert.return_value=raw
        expired=types.SimpleNamespace(returncode=0,stdout=b'notBefore=Jan  1 00:00:00 2010 GMT\nnotAfter=Jan  1 00:00:00 2011 GMT\n')
        with patch('apps.network_v1.onion.ssl.DER_cert_to_PEM_cert',return_value='PUBLIC'),patch('apps.network_v1.onion.subprocess.run',return_value=expired):
            with self.assertRaisesRegex(ValueError,'EXPIRED'):pinned(secure,value)

    def test_import_persists_without_network_and_reopen_validates(self):
        from apps.network_v1.desktop_backend import Product,c,f
        with tempfile.TemporaryDirectory(dir=Path.home(),prefix='pc-v1-fixtures-rc3-config-') as tmp:
            home=Path(tmp)/'product';product=Product(home,31481,31482)
            try:
                source=home/'reviewed.json';c.write_private(source,f.canonical([catalog(peer(1)),catalog(peer(2))]))
                result=product.dispatch(dict(command='bootstrap_import',path=str(source)))
                self.assertTrue(result['no_connection_started']);self.assertIsNone(product.node);self.assertIsNone(product.tor)
                self.assertEqual(product.settings['peers'],[peer(1),peer(2)])
            finally:product.close()
            reopened=Product(home,31481,31482)
            try:self.assertEqual(reopened.settings['peers'],[peer(1),peer(2)])
            finally:reopened.close()
            settings=f.decode(c.read_private(home/'network.json'));settings['peers'][0]['version']=True
            c.write_private(home/'network.json',f.canonical(settings),replace=True)
            with self.assertRaises(ValueError):Product(home,31481,31482)


if __name__=='__main__':unittest.main()
