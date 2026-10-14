"""Disposable in-memory recovery, real native keys and approved G; no custody.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import os,secrets,unittest
from pathlib import Path
from . import founder
from .production import G
from .bind_founder_client import seal_for_client
from tools.creator_model.binding import GenesisAddress
class FinalWallet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ['PC_DEVNET_NATIVE_ROOT'])
        founder.f.HELPER=root/'build/monero-linux/phase2/privacycoin-wallet-crypto'
    def test_g_bound_encryption_independent_recovery(self):
        master=secrets.token_hex(32);password=secrets.token_bytes(32)
        wallet,public=founder.keys(master);raw=seal_for_client(founder,master,password,G,public)
        restored=GenesisAddress(founder.f,founder.context(),G,'PCmn1-').restore(raw,password)
        self.assertEqual(restored,wallet)
        self.assertEqual(len(GenesisAddress(founder.f,founder.context(),G,'PCmn1-').address(restored)),293)
    def test_wrong_password_corruption_and_network_reject(self):
        master=secrets.token_hex(32);password=secrets.token_bytes(32);_,pub=founder.keys(master)
        raw=seal_for_client(founder,master,password,G,pub);binding=GenesisAddress(founder.f,founder.context(),G,'PCmn1-')
        for data,key in [(raw,b'wrong-password'),(raw[:-1],password),(raw[:-1]+bytes([raw[-1]^1]),password)]:
            with self.assertRaises(ValueError):binding.restore(data,key)
        with self.assertRaises(ValueError):GenesisAddress(founder.f,founder.context(),'a'*64,'PCmn1-').restore(raw,password)
    def test_wrong_recipient_reject(self):
        master=secrets.token_hex(32);_,pub=founder.keys(secrets.token_hex(32))
        with self.assertRaises(ValueError):seal_for_client(founder,master,secrets.token_bytes(32),G,pub)
if __name__=='__main__':unittest.main()
