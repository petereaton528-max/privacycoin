"""Explicit development-network selection; never an official Mainnet profile.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import os

GENESIS = 'a0d9ba16f1f6b2fb2f480197ff9dec17468db0d5e6df9cfcb4b2b2a91ecffc87'

def selected(value=None):
    value = os.environ.get('PC_DEVELOPMENT_NETWORK', 'legacy-dev01') if value is None else value
    if value not in ('legacy-dev01', 'open-dev02'):
        raise ValueError('UNSUPPORTED_DEVELOPMENT_NETWORK_NO_MAINNET_PROFILE')
    network = 'PrivacyCoinDev01' if value == 'legacy-dev01' else 'PrivacyCoinDev02'
    return network, GENESIS, network + '/private-spend-v1-hardening/epoch18/' + GENESIS

NETWORK, _, PROFILE = selected()
