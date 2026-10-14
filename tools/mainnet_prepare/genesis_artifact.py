"""Verify/reconstruct an existing PUBLIC offline Genesis artifact; no keys.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,subprocess
from pathlib import Path
def process(helper,expected,artifact):
    helper=Path(helper)
    if not helper.is_absolute() or helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest()!=expected:raise ValueError('VERIFIED_HELPER_REQUIRED')
    if not isinstance(artifact,dict) or set(artifact)!={'block','hash'}:raise ValueError('PUBLIC_ARTIFACT_SCHEMA')
    if any(not isinstance(v,str) for v in artifact.values()) or len(artifact['block'])>12000 or len(artifact['hash'])!=64:raise ValueError('PUBLIC_ARTIFACT_BOUND')
    def call(value):
        result=subprocess.run([str(helper)],input=json.dumps(value).encode()+b'\n',capture_output=True,timeout=15,check=True)
        if len(result.stdout)>20000:raise ValueError('HELPER_OUTPUT_BOUND')
        reply=json.loads(result.stdout)
        if 'error' in reply:raise ValueError('NATIVE_GENESIS_REJECTED')
        return reply
    inspected=call(dict(op='verify_genesis',**artifact))
    plan={k:inspected[k] for k in ('commitment','R','outputs')}
    rebuilt=call(dict(op='reconstruct_genesis',**plan))
    if any(rebuilt[k]!=artifact[k] for k in ('block','hash')):raise ValueError('GENESIS_RECONSTRUCTION_MISMATCH')
    return dict(format='PC_PUBLIC_GENESIS_RECONSTRUCTION_V1',scope='NONPRODUCTION_REVIEW_ONLY',artifact=artifact,public_plan=plan,creator_atomic=inspected['creator_atomic'],mining_atomic=inspected['mining_atomic'],recipient_ownership_proven=False,production_approved=False,helper_sha256=expected)
def main():
    p=argparse.ArgumentParser();p.add_argument('--helper',type=Path,required=True);p.add_argument('--helper-sha256',required=True);p.add_argument('--artifact',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.artifact.is_symlink() or a.artifact.stat().st_size>16384:raise ValueError('PUBLIC_ARTIFACT_FILE')
    result=process(a.helper,a.helper_sha256,json.loads(a.artifact.read_text()))
    with a.output.open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
    print('PUBLIC_CANONICAL_RECONSTRUCTION_PASS; recipient_ownership=UNVERIFIED; production_approved=false')
if __name__=='__main__':main()
