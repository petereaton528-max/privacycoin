"""Public seed hints, private configuration persistence, no network activation."""
import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
from apps.network_v1.peers import initial_peers,read_catalog
from apps.network_v1.tests.test_network_stability import peer,catalog

class PackagedBootstrap(unittest.TestCase):
    def test_multiple_catalogs_merge_as_untrusted_hints(self):
        raw=json.dumps([catalog(peer(1)),catalog(peer(2),peer(1))]).encode()
        self.assertEqual(initial_peers('/unused',lambda _:raw,json.loads),[peer(1),peer(2)])
        for raw in (b'[]',):self.assertEqual(initial_peers('/unused',lambda _:raw,json.loads),[])
        def absent(_):raise FileNotFoundError()
        self.assertEqual(initial_peers('/unused',absent,json.loads),[])

    def test_bad_present_catalog_fails_closed(self):
        for raw in (b' ' *16385,b'not-json',b'{}',json.dumps([dict(catalog(peer(1)),network='OTHER')]).encode(),json.dumps([catalog(peer(1),dict(peer(1),certificate_sha256='f'*64))]).encode()):
            with self.subTest(kind='invalid catalog'),self.assertRaises(ValueError):initial_peers('/unused',lambda _:raw,json.loads)

    def test_public_file_read_is_bounded_and_rejects_hardlinks(self):
        with tempfile.TemporaryDirectory(prefix='pc-v1-public-catalog-') as raw:
            path=Path(raw)/'catalog.json';path.write_bytes(b'[]');self.assertEqual(read_catalog(path),b'[]')
            path.write_bytes(b'x'*16385)
            with self.assertRaises(ValueError):read_catalog(path)
            path.write_bytes(b'[]');alias=Path(raw)/'hardlink';os.link(path,alias)
            with self.assertRaises(ValueError):read_catalog(alias)
        with self.assertRaises(ValueError):read_catalog(Path('relative'))

    def test_new_profile_pins_package_hints_existing_profile_keeps_its_settings(self):
        from apps.network_v1 import desktop_backend as db
        with tempfile.TemporaryDirectory(prefix='pc-v1-catalog-profile-') as raw:
            base=Path(raw);package=base/'package';config=package/'apps/network_v1/bootstrap-catalogs.json';config.parent.mkdir(parents=True)
            config.write_bytes(json.dumps([catalog(peer(1)),catalog(peer(2))]).encode())
            tor=package/'runtime/bin/tor.exe';tor.parent.mkdir(parents=True);tor.write_bytes(b'PUBLIC_NONEXECUTABLE_TEST_STANDIN')
            home=base/'private-profile'
            with patch.object(db,'ROOT',package),patch.object(db.shutil,'which',return_value=str(tor)),patch.object(db.Product,'spawn') as spawn:
                product=db.Product(home,31481,31482)
                try:
                    self.assertEqual(product.settings['peers'],[peer(1),peer(2)]);status=product.status()
                    self.assertEqual(status['configured_peers'],2);self.assertEqual(status['tor']['state'],'DISABLED');self.assertEqual(status['mining']['state'],'DISABLED')
                finally:product.close()
                config.write_bytes(b'MALFORMED_CHANGED_PACKAGE_CATALOG')
                reopened=db.Product(home,31481,31482)
                try:self.assertEqual(reopened.settings['peers'],[peer(1),peer(2)])
                finally:reopened.close()
                spawn.assert_not_called()

    def test_removed_old_tor_keeps_wallet_profile_openable_and_saved_config_intact(self):
        from apps.network_v1 import desktop_backend as db
        with tempfile.TemporaryDirectory(prefix='pc-v1-tor-upgrade-') as raw:
            base=Path(raw);home=base/'private-profile';product=db.Product(home,31481,31482);product.close()
            config=home/'network.json';old=dict(tor_binary=str(base/'removed-old-app/tor.exe'),peers=[]);saved=db.f.canonical(old);db.c.write_private(config,saved)
            product=db.Product(home,31481,31482)
            try:
                status=product.status();self.assertFalse(status['tor_runtime_configured']);self.assertTrue(status['tor_runtime_warning']);self.assertEqual(status['tor']['state'],'DISABLED')
                self.assertEqual(db.c.read_private(config),saved)
                self.assertEqual(product.dispatch(dict(command='hello'))['wallets'],[])
                replacement=base/'new-reviewed-tor.exe';replacement.write_bytes(b'PUBLIC_NONEXECUTABLE_TEST_STANDIN')
                product.dispatch(dict(command='tor_configure',binary=str(replacement)))
                self.assertIsNone(product.status()['tor_runtime_warning']);self.assertEqual(product.settings['tor_binary'],str(replacement))
            finally:product.close()

if __name__=='__main__':unittest.main()
