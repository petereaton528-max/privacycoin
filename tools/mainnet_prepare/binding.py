"""Strict offline binding compiler. No key generation or activation authority.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json,re
from pathlib import Path
POLICY=Path(__file__).with_name('approved_policy.json')
IDENTITY=Path(__file__).with_name('production_identity_proposal.json')
APPROVED_IDENTITY_SHA256='67036217d08417ca8d996f2fd807d0a171b5d849e53fb7901225feeffddbaa04'
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def approved():
    value=json.loads(POLICY.read_text(encoding='utf-8'))
    identity=value.get('approved_production_identity',{})
    if identity.get('status')!='OWNER_APPROVED_FINAL_IDENTITY' or identity.get('sha256')!=APPROVED_IDENTITY_SHA256 or IDENTITY.is_symlink() or hashlib.sha256(IDENTITY.read_bytes()).hexdigest()!=APPROVED_IDENTITY_SHA256:
        raise ValueError('APPROVED_IMMUTABLE_IDENTITY_MISMATCH')
    a=value['approved']
    assert a['creator_total_atomic']==159627169409884823
    assert a['creator_liquid_atomic']+a['creator_locked_atomic']==a['creator_total_atomic']
    assert 5*a['first_five_tranche_atomic']+11*a['last_eleven_tranche_atomic']==a['creator_locked_atomic']
    return value
def test_config():
    return dict(format='PC_PRODUCTION_BINDING_V1',purpose='DISPOSABLE_OFFLINE_TEST',policy_sha256=hashlib.sha256(canonical(approved()['approved'])).hexdigest(),network='PCBindingTest001',domain='PrivacyCoin/PRODUCTION-BINDING-TEST/20261014/v1',address_prefix='PCbt1-',fee_policy=approved()['approved_fee_policy'],production_approvals=None)
def validate(value):
    if not isinstance(value,dict) or set(value)!=set(test_config()):raise ValueError('BINDING_SCHEMA')
    if value['format']!='PC_PRODUCTION_BINDING_V1':raise ValueError('BINDING_FORMAT')
    if value['purpose']=='PRODUCTION_RESERVED':
        from .production import config
        if canonical(value)!=canonical(config()):raise ValueError('IMMUTABLE_PRODUCTION_BINDING_MISMATCH')
        return value
    if value['purpose']!='DISPOSABLE_OFFLINE_TEST' or value['production_approvals'] is not None:raise ValueError('PRODUCTION_INPUTS_AND_AUTHORIZATION_NOT_FINALIZED')
    if value['policy_sha256']!=test_config()['policy_sha256']:raise ValueError('APPROVED_MONETARY_POLICY_MISMATCH')
    patterns={'network':r'PCBindingTest[A-Za-z0-9]{1,32}', 'domain':r'PrivacyCoin/PRODUCTION-BINDING-TEST/[A-Za-z0-9/_-]{1,100}', 'address_prefix':r'PCbt[1-9][0-9]*-'}
    for k,p in patterns.items():
        if not isinstance(value[k],str) or not re.fullmatch(p,value[k]):raise ValueError('DISPOSABLE_DOMAIN_REQUIRED')
    if len(value['network'].encode('ascii'))!=16:raise ValueError('NATIVE_P2P_MAGIC_REQUIRES_16_BYTES')
    if canonical(value['fee_policy'])!=canonical(test_config()['fee_policy']):raise ValueError('UNAPPROVED_FEE_CHANGE')
    return value
def load(path):
    path=Path(path)
    if not path.is_absolute() or path.is_symlink() or path.stat().st_size>8192:raise ValueError('BINDING_FILE')
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise ValueError('DUPLICATE_BINDING_FIELD')
            d[k]=v
        return d
    return validate(json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=unique))
def digest(value):return hashlib.sha256(canonical(validate(value))).hexdigest()
def context(value):
    value=validate(value)
    # Bind ALL policy/domain fields, including approved fee values, so
    # equal text names cannot alias different compiled security contexts.
    return value['network'],value['domain']+'/binding/'+digest(value),value['address_prefix']
def header(value):
    network,domain,_=context(value)
    text='#pragma once\n#define PC_BOUND_DOMAIN '+json.dumps(domain)+'\n#define PC_BOUND_NETWORK '+json.dumps(network)+'\n'
    if value['purpose']=='PRODUCTION_RESERVED':
        from .production import profile,G
        text+='#define PC_FINAL_GENESIS_HASH '+json.dumps(G)+'\n#define PC_FINAL_GENESIS_HEX '+json.dumps(profile()['block'])+'\n'
        text+='#define PC_FINAL_NETWORK_TAG '+json.dumps(profile()['network_tag'])+'\n'
    return text.encode()
