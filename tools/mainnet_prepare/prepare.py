"""Deterministic UNAPPROVED proposal; cannot select/launch any live network.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,subprocess
from pathlib import Path
def proposal():
    from tools.mainnet_prepare.binding import approved
    return dict(status='MONETARY_POLICY_APPROVED_PRODUCTION_INPUTS_PENDING',decision=approved(),launchable=False)

def subsidy(issued):return max(((2**64-1)-min(issued,2**64-1))>>19,600000000000)

def prepare(helper,expected):
    # The historical zero-output generator cannot satisfy the approved policy.
    # Refuse before invoking it or writing a misleading production artifact.
    raise ValueError('ZERO_ALLOCATION_GENERATOR_RETIRED_USE_REVIEWED_BOUND_GENESIS_WORKFLOW')

def economics():
    issued=0;rows=[];tail=None
    for height in range(1,5_000_001):
        reward=subsidy(issued);issued+=reward
        if tail is None and reward==600000000000:tail=height
        if height in (262800,525600,1314000,2628000):rows.append(dict(blocks=height,nominal_365_day_years=height/262800,issued_atomic=issued,next_reward_atomic=subsidy(issued)))
    return dict(initial_reward_atomic=subsidy(0),second_reward_atomic=subsidy(subsidy(0)),tail_first_height=tail,annual_tail_atomic=262800*600000000000,snapshots=rows,warning='Not a hard cap: tail continues indefinitely; nominal target time, not wall-clock guarantees; all values unapproved')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--helper',type=Path,required=True);p.add_argument('--expected-helper-sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    value=prepare(a.helper,a.expected_helper_sha256);value['economics']=economics()
    with a.output.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(status=value['status'],output=str(a.output),proposal_sha256=value['proposal_sha256'],genesis_hash=value['genesis_hash'],activated=False,launchable=False)))
