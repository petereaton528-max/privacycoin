"""Explicit public laboratory manifest; never selects production Mainnet.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json,re,os,functools
from pathlib import Path
DOMAIN='PrivacyCoin/UNAPPROVED-CREATOR-VESTING-DRAFT/v1'
NETWORK='PrivacyCoinLab01'
@functools.lru_cache(maxsize=1)
def bound_context():
    path=os.environ.get('PC_OFFLINE_BINDING')
    if not path:return NETWORK,DOMAIN,'PClab1-',None
    from tools.mainnet_prepare.binding import load,context,digest
    value=load(path)
    return (*context(value),digest(value))

def verify_build(receipt):
    expected=bound_context()[3]
    if receipt.get('binding_sha256')!=expected:raise ValueError('COMPILED_BINDING_MISMATCH')
def validate(value):
    from tools.mainnet_prepare.production import selected,profile
    if selected():
        if value!=profile():raise ValueError('FINAL_MAINNET_PROFILE_MISMATCH')
        return dict(value)
    if not isinstance(value,dict) or set(value)!={'format','network_tag','commitment','genesis','block','launchable'}:raise ValueError('CANDIDATE_PROFILE_SCHEMA')
    if value['format']!='PC_OFFLINE_MAINNET_CANDIDATE_V1' or value['launchable'] is not False:raise ValueError('NONPRODUCTION_PROFILE_REQUIRED')
    if not isinstance(value['commitment'],str) or not re.fullmatch(re.escape(bound_context()[1])+r'/policy/[0-9a-f]{64}',value['commitment']):raise ValueError('FULL_VESTING_POLICY_REQUIRED')
    for name in ('network_tag','genesis'):
        if not isinstance(value[name],str) or not re.fullmatch('[0-9a-f]{64}',value[name]):raise ValueError('CANDIDATE_ID')
    if value['network_tag']!=hashlib.sha256(('PC/CANDIDATE-OFFLINE/'+value['commitment']).encode()).hexdigest():raise ValueError('CANDIDATE_TAG')
    if not isinstance(value['block'],str) or not re.fullmatch('[0-9a-f]{2,12000}',value['block']) or len(value['block'])%2:raise ValueError('CANDIDATE_GENESIS_BYTES')
    return dict(value)
def load(path):
    path=Path(path)
    if not path.is_absolute() or path.is_symlink() or path.stat().st_size>16384:raise ValueError('CANDIDATE_PROFILE_PATH')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('DUPLICATE_PROFILE_FIELD')
            result[k]=v
        return result
    return validate(json.loads(path.read_text(),object_pairs_hook=unique))
def identity(value):
    value=validate(value)
    network,domain,_,_=bound_context()
    return network,value['genesis'],domain+'/'+value['genesis']
