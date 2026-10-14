"""Public identity specification only. Not a production build/launch selector.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
from .binding import approved,canonical,test_config

# These are proposals, not owner-approved constants in native consensus.
MAGIC='PCMainnetV1_0001'
PREFIX='PCmn1-'
KNOWN_MAGIC={
    'historical native / N2 legacy chain':'PrivacyCoinDev01',
    'ticket-free Dev02':'PrivacyCoinDev02',
    'vesting laboratory':'PrivacyCoinLab01',
    'bound offline review':'PCBindingTest001',
    'prior zero-allocation proposal (never activated)':'PrivacyCoinMN001',
}

def proposal():
    record=approved()
    cfg=dict(test_config(),purpose='PRODUCTION_RESERVED',network=MAGIC,
             domain=record['approved_naming']['protocol_namespace'],address_prefix=PREFIX)
    digest=hashlib.sha256(canonical(cfg)).hexdigest()
    domain=cfg['domain']+'/binding/'+digest
    a=record['approved']
    outputs=[dict(index=0,atomic=a['creator_liquid_atomic'],unlock_height=0)]
    for i in range(1,17):
        outputs.append(dict(index=i,atomic=a['first_five_tranche_atomic'] if i<=5 else a['last_eleven_tranche_atomic'],unlock_height=i*a['vesting_interval']))
    text=domain+'|'+str(a['creator_total_atomic'])+''.join('|{index}:{unlock_height}:{atomic}'.format(**o) for o in outputs)
    assert len(MAGIC.encode('ascii'))==16 and MAGIC not in KNOWN_MAGIC.values()
    assert sum(o['atomic'] for o in outputs)==a['creator_total_atomic']
    # cn_fast_hash is the retained native Keccak-256, NOT hashlib.sha3_256.
    return dict(format='PC_MAINNET_IDENTITY_PROPOSAL_V1',approved=False,launchable=False,
      naming=record['approved_naming'],binding=cfg,binding_sha256=digest,
      wire_magic_ascii=MAGIC,wire_magic_hex=MAGIC.encode().hex(),native_consensus_network=MAGIC,
      bound_domain_ascii=domain,bound_domain_hex=domain.encode().hex(),
      policy_text_ascii=text,policy_text_hex=text.encode().hex(),creator_outputs=outputs,
      derived_fields={
        'H':'native crypto::cn_fast_hash (Keccak-256); lowercase hex where hex() appears',
        'C':'bound_domain_ascii + /policy/ + hex(H(UTF8(policy_text_ascii)))',
        'T':'hex(SHA256(UTF8(PC/CANDIDATE-OFFLINE/ + C)))',
        'G':'native canonical block hash of separately approved Genesis; NOT assigned here',
        'native_transaction_domain':'UTF8(bound_domain_ascii + / + G); consensus V1',
        'private_transaction_nonce':'00 || H(native_transaction_domain), exactly 33 bytes',
        'coinbase_extra_nonce':'native_transaction_domain; Genesis uses C',
        'wallet_child_seed':'H(UTF8(PrivacyCoin/DRAFT/wallet/v1/) || unhex(T) || 00 || master_seed_32)',
        'address':'PCmn1- + G + -PCdraft1- + T + - + hex(payload || check)',
        'address_payload':'01fe010101 || subaddress_flag_1 || public_D_32 || public_C_32 (70 bytes)',
        'address_check':'first 4 bytes of H(unhex(T) || payload)',
        'recovery_kind':'pc-draft-recovery/v1/ + T + / + G; encrypted PC_DRAFT_RECOVERY_V1 payload',
        'database_identity':'bound_domain_ascii + / + G',
        'P2P_compatibility':'exact tuple (native_consensus_network, G, database_identity); mandatory onion/TLS peer identity checks remain separate',
      },known_identity_comparison=KNOWN_MAGIC,
      limitations=[
        'All proposed strings are exact UTF-8/ASCII without a trailing NUL. || means concatenation.',
        'Retained DRAFT/CANDIDATE codec labels are deliberate compatibility constants, not authorization or weak keys. No new cryptographic primitive is introduced.',
        'G, final recipient and final canonical bytes remain unassigned. No complete production address or database path can yet be instantiated.',
        'Runtime/compiler rejects PRODUCTION_RESERVED. A separate reviewed approval gate is still required; never edit launch flags.',
        'The frozen binding preimage includes production_approvals:null. Future approval is external evidence, not a mutable remote consensus setting.',
        'Known-identity comparison is scoped to this reviewed source inventory; not a proof of global uniqueness.',
      ])

def resolve_policy(helper,expected):
    helper=Path(helper)
    if not helper.is_absolute() or helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest()!=expected:
        raise ValueError('VERIFIED_HELPER_REQUIRED')
    value=proposal()
    result=subprocess.run([str(helper)],input=('hash '+value['policy_text_hex']+'\n').encode(),capture_output=True,timeout=15,check=True)
    digest=result.stdout.decode().strip()
    if not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('NATIVE_HASH_RESPONSE')
    commitment=value['bound_domain_ascii']+'/policy/'+digest
    value['resolved_policy']=dict(native_helper_sha256=expected,commitment_ascii=commitment,commitment_hex=commitment.encode().hex(),wallet_network_tag=hashlib.sha256(('PC/CANDIDATE-OFFLINE/'+commitment).encode()).hexdigest())
    return value

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--helper',type=Path);p.add_argument('--helper-sha256');a=p.parse_args()
    if bool(a.helper)!=bool(a.helper_sha256):p.error('helper and helper-sha256 required together')
    value=resolve_policy(a.helper,a.helper_sha256) if a.helper else proposal()
    with a.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(value,f,indent=2);f.write('\n')
    print('PROPOSAL_ONLY; production_approved=false; no keys or Genesis created')
if __name__=='__main__':main()
