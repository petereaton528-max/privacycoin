"""Strict public canonical Genesis review. No recipient selection or generation.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
from .binding import approved,APPROVED_IDENTITY_SHA256

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('DUPLICATE_PUBLIC_FIELD')
        result[key]=value
    return result

def hex_value(value,size=None):
    if not isinstance(value,str) or not value or len(value)%2 or not re.fullmatch('[0-9a-f]+',value) or (size is not None and len(value)!=size*2):raise ValueError('CANONICAL_HEX_REQUIRED')

def native_call(helper,expected,value):
    helper=Path(helper)
    if not helper.is_absolute() or helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest()!=expected:raise ValueError('VERIFIED_HELPER_REQUIRED')
    result=subprocess.run([str(helper)],input=json.dumps(value).encode()+b'\n',capture_output=True,timeout=15,check=True)
    if len(result.stdout)>20000:raise ValueError('HELPER_OUTPUT_BOUND')
    reply=json.loads(result.stdout,object_pairs_hook=unique)
    if not isinstance(reply,dict) or 'error' in reply:raise ValueError('NATIVE_GENESIS_REJECTED')
    return reply

def check_plan(inspected,policy):
    a=approved()['approved']
    if any(type(policy.get(k)) is not int for k in ('activation','interval','total','liquid')) or (policy.get('activation'),policy.get('interval'),policy.get('total'),policy.get('liquid'))!=(0,a['vesting_interval'],a['creator_total_atomic'],a['creator_liquid_atomic']):raise ValueError('APPROVED_POLICY_MISMATCH')
    if inspected.get('commitment')!=policy.get('commitment'):raise ValueError('NATIVE_POLICY_BINDING_MISMATCH')
    if type(inspected.get('creator_atomic')) is not int or type(inspected.get('mining_atomic')) is not int or inspected['creator_atomic']!=a['creator_total_atomic'] or inspected['mining_atomic']!=0:raise ValueError('GENESIS_SUPPLY_MISMATCH')
    hex_value(inspected.get('R'),32)
    outputs=inspected.get('outputs')
    if not isinstance(outputs,list) or len(outputs)!=17:raise ValueError('EXACTLY_SEVENTEEN_OUTPUTS_REQUIRED')
    seen=set();total=0
    for i,out in enumerate(outputs):
        if not isinstance(out,dict) or set(out)!={'key','atomic','unlock'}:raise ValueError('TRANCHE_SCHEMA')
        hex_value(out['key'],32)
        amount=a['creator_liquid_atomic'] if i==0 else a['first_five_tranche_atomic'] if i<=5 else a['last_eleven_tranche_atomic']
        if type(out['atomic']) is not int or type(out['unlock']) is not int or out['atomic']!=amount or out['unlock']!=i*a['vesting_interval']:raise ValueError('APPROVED_TRANCHE_MISMATCH')
        if out['key'] in seen:raise ValueError('DUPLICATE_CREATOR_OUTPUT')
        seen.add(out['key']);total+=out['atomic']
    if total!=a['creator_total_atomic']:raise ValueError('CREATOR_SUM_MISMATCH')

def process(helper,expected,artifact,*,expected_commitment):
    if not isinstance(artifact,dict) or set(artifact)!={'block','hash'}:raise ValueError('PUBLIC_ARTIFACT_SCHEMA')
    if any(not isinstance(v,str) for v in artifact.values()) or len(artifact['block'])>12000:raise ValueError('PUBLIC_ARTIFACT_BOUND')
    hex_value(artifact['block']);hex_value(artifact['hash'],32)
    if not isinstance(expected_commitment,str) or not expected_commitment:raise ValueError('EXTERNAL_NETWORK_PIN_REQUIRED')
    def call(value):return native_call(helper,expected,value)
    policy=call(dict(op='policy'))
    if policy.get('commitment')!=expected_commitment:raise ValueError('EXPECTED_NETWORK_BINDING_MISMATCH')
    inspected=call(dict(op='verify_genesis',**artifact));check_plan(inspected,policy)
    plan={k:inspected[k] for k in ('commitment','R','outputs')}
    rebuilt=call(dict(op='reconstruct_genesis',**plan));check_plan(rebuilt,policy)
    if any(rebuilt[k]!=artifact[k] for k in ('block','hash')):raise ValueError('GENESIS_RECONSTRUCTION_MISMATCH')
    return dict(format='PC_PUBLIC_GENESIS_FINAL_REVIEW_V1',scope='NONPRODUCTION_REVIEW_ONLY',artifact=artifact,public_plan=plan,creator_atomic=inspected['creator_atomic'],mining_atomic=inspected['mining_atomic'],recipient_ownership_proven=False,production_approved=False,helper_sha256=expected,approved_identity_sha256=APPROVED_IDENTITY_SHA256,external_commitment_pin_checked=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--helper',type=Path,required=True);p.add_argument('--helper-sha256',required=True);p.add_argument('--artifact',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--expected-commitment',required=True);a=p.parse_args()
    if a.artifact.is_symlink() or a.artifact.stat().st_size>16384:raise ValueError('PUBLIC_ARTIFACT_FILE')
    result=process(a.helper,a.helper_sha256,json.loads(a.artifact.read_text(),object_pairs_hook=unique),expected_commitment=a.expected_commitment)
    with a.output.open('x',encoding='utf-8') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print('CANONICAL_BYTES_SUPPLY_BINDING_PASS; ownership=UNVERIFIED; production_approved=false')
if __name__=='__main__':main()
