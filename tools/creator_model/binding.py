"""Offline DRAFT-only keys/address/recovery binding using retained native crypto.
No production selector, signing interface, network, real founder or launch route.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import re
DEV_GENESIS='a0d9ba16f1f6b2fb2f480197ff9dec17468db0d5e6df9cfcb4b2b2a91ecffc87'
class DraftBinding:
    def __init__(self,foundation,network_tag,genesis):
        for value in (network_tag,genesis):
            if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value) or value=='0'*64:raise ValueError('DRAFT_CONTEXT_ID')
        if genesis==DEV_GENESIS:raise ValueError('DEVELOPMENT_GENESIS_FORBIDDEN')
        self.f=foundation;self.tag=network_tag;self.genesis=genesis
        self.kind='pc-draft-recovery/v1/'+network_tag+'/'+genesis
    def wallet(self,master_seed,count=2):
        seed=self.f.unhex(master_seed,32)
        if not any(seed):raise ValueError('ZERO_DRAFT_SEED')
        # Domain is fixed before genesis creation: avoids recipient/genesis/key
        # circularity. Genesis additionally binds recovery/database/handshake.
        child=self.f.crypto('hash',(b'PrivacyCoin/DRAFT/wallet/v1/'+bytes.fromhex(self.tag)+b'\0'+seed).hex())[0]
        return self.f.full(child,count)
    def address(self,wallet,index=0):
        original=self.f.address(wallet,index);raw=bytes.fromhex(original[6:])
        payload=bytes([1,254,1,1,1])+raw[5:-4]
        check=bytes.fromhex(self.f.crypto('hash',(bytes.fromhex(self.tag)+payload).hex())[0])[:4]
        return 'PCdraft1-'+self.tag+'-'+(payload+check).hex()
    def parse(self,address):
        prefix='PCdraft1-'+self.tag+'-'
        if not isinstance(address,str) or not address.startswith(prefix):raise ValueError('DRAFT_ADDRESS_NETWORK')
        raw=self.f.unhex(address[len(prefix):],74)
        if raw[:5]!=bytes([1,254,1,1,1]) or raw[5] not in (0,1):raise ValueError('DRAFT_ADDRESS_HEADER')
        if raw[-4:]!=bytes.fromhex(self.f.crypto('hash',(bytes.fromhex(self.tag)+raw[:-4]).hex())[0])[:4]:raise ValueError('DRAFT_ADDRESS_CHECKSUM')
        D,C=raw[6:38].hex(),raw[38:70].hex();self.f.crypto('check',D);self.f.crypto('check',C)
        return D,C,bool(raw[5])
    def seal(self,master_seed,password,count=2):
        self.wallet(master_seed,count)
        return self.f.seal(dict(format='PC_DRAFT_RECOVERY_V1',network_tag=self.tag,genesis=self.genesis,master_seed=master_seed,count=count,launchable=False),password,self.kind)
    def restore(self,raw,password):
        value=self.f.open_sealed(raw,password,self.kind)
        self.f.fields(value,'format network_tag genesis master_seed count launchable')
        if (value['format'],value['network_tag'],value['genesis'],value['launchable'])!=('PC_DRAFT_RECOVERY_V1',self.tag,self.genesis,False):raise ValueError('DRAFT_RECOVERY_CONTEXT')
        return self.wallet(value['master_seed'],value['count'])
    def transaction_marker(self):
        return self.f.crypto('hash',(b'PrivacyCoin/DRAFT/private-spend/v1/'+bytes.fromhex(self.tag)+bytes.fromhex(self.genesis)).hex())[0]

class GenesisAddress(DraftBinding):
    """Existing full-node address codec, shared with the identity review.

    This does not select a network or authorize production. The caller supplies
    the prefix from its validated binding. All bytes retain the prior codec.
    """
    def __init__(self,foundation,network_tag,genesis,address_prefix):
        super().__init__(foundation,network_tag,genesis)
        self.address_prefix=address_prefix
    def address(self,wallet,index=0):
        return self.address_prefix+self.genesis+'-'+super().address(wallet,index)
    def parse(self,address):
        prefix=self.address_prefix+self.genesis+'-'
        if not isinstance(address,str) or not address.startswith(prefix):raise ValueError('CANDIDATE_ADDRESS_GENESIS')
        return super().parse(address[len(prefix):])
