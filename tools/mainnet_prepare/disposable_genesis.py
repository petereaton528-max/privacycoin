"""Closed disposable construction fixture: no recipient input or production mode.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,secrets
from .genesis_finalization import native_call,process
from tools.creator_model.binding import DraftBinding

def construct(helper,expected,foundation):
    policy=native_call(helper,expected,dict(op='policy'))
    if not policy.get('commitment','').startswith('PrivacyCoin/PRODUCTION-BINDING-TEST/'):
        raise ValueError('DISPOSABLE_COMPILED_IDENTITY_REQUIRED')
    tag=hashlib.sha256(('PC/CANDIDATE-OFFLINE/'+policy['commitment']).encode()).hexdigest()
    binding=DraftBinding(foundation,tag,'a'*64)
    wallet=binding.wallet(secrets.token_hex(32));D,C,sub=binding.parse(binding.address(wallet))
    if sub:raise ValueError('PRIMARY_DISPOSABLE_RECIPIENT_REQUIRED')
    reply=native_call(helper,expected,dict(op='genesis',D=D,C=C))
    artifact={k:reply[k] for k in ('block','hash')}
    verified=process(helper,expected,artifact,expected_commitment=policy['commitment'])
    # Native scan uses temporary viewing material only through private pipes.
    # No key material leaves this function or is saved as evidence.
    for i,out in enumerate(verified['public_plan']['outputs']):
        found=foundation.crypto('scan',wallet['view'],wallet['public'],2,verified['public_plan']['R'],out['key'],i)
        if found!=['0']:raise ValueError('DISPOSABLE_RECIPIENT_OWNERSHIP')
    verified['disposable_ownership_scan']='17_NATIVE_OUTPUTS_PASS'
    verified['recipient_scope']='EPHEMERAL_DISPOSABLE_ONLY'
    return verified
