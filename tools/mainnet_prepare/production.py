"""Frozen Mainnet V1 public inputs. No construction, custody or activation API.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).parent
G='6233402308514d2d979a9efa9c6bd2f9843741598f1e5b18239cde16ba0d2b54'
PINS={
 'FINAL_GENESIS_APPROVAL.json':'a174fce6ad56e071de27e04ea276e7e4075457dbe997a4d51b630411135cc55b',
 'APPROVED_GENESIS.bin':'ada8aa42012556f8a045e212d94fffaec47ebccc345900216539d4cdb36a6001',
 'APPROVED_GENESIS.json':'7c43e779b46da9472c7588cba4b2fef823aa2ef61fc3956c7471f04afad46555',
 'APPROVED_PUBLIC_RECIPIENT.json':'c405c6529043fa287d61eead0a6c2ad6b6a1020c9acf2e414957ec3efe643069',
 'production_identity_proposal.json':'67036217d08417ca8d996f2fd807d0a171b5d849e53fb7901225feeffddbaa04',
 'approved_policy.json':'a398624590f31b503cdea9590c501bc54a57e269ae66d1200daf4cf0ba6bbdc2',
 'FOUNDER_RECIPIENT_APPROVAL.json':'9088bbb8e1d9df95ef795c09006ec9ebb4e1b9e3c9396124dbd35319842d515f'}
def frozen():
    raw={}
    for name,pin in PINS.items():
        path=ROOT/name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise ValueError('FROZEN_PRODUCTION_INPUT_MISMATCH')
        raw[name]=path.read_bytes()
    approval=json.loads((ROOT/'FINAL_GENESIS_APPROVAL.json').read_bytes())
    if (approval['status']!='OWNER_APPROVED_FINAL_GENESIS' or approval['genesis_hash']!=G
            or approval['canonical_sha256']!=PINS['APPROVED_GENESIS.bin']
            or approval['specification_sha256']!=PINS['production_identity_proposal.json']
            or approval['recipient_sha256']!=PINS['APPROVED_PUBLIC_RECIPIENT.json']):raise ValueError('FINAL_OWNER_APPROVAL_REQUIRED')
    artifact=json.loads(raw['APPROVED_GENESIS.json'])
    if len(raw['APPROVED_GENESIS.bin'])!=949 or bytes.fromhex(artifact['block'])!=raw['APPROVED_GENESIS.bin'] or artifact['hash']!=G:raise ValueError('FINAL_GENESIS_MISMATCH')
    return json.loads(raw['production_identity_proposal.json']),artifact
def config():return frozen()[0]['binding']
def profile():
    spec,artifact=frozen()
    # Existing storage envelope is retained, never an activation authority.
    return dict(format='PC_OFFLINE_MAINNET_CANDIDATE_V1',network_tag=spec['resolved_policy']['wallet_network_tag'],commitment=spec['resolved_policy']['commitment_ascii'],genesis=G,block=artifact['block'],launchable=False)
def selected():
    import os
    from .binding import load
    path=os.environ.get('PC_OFFLINE_BINDING')
    return bool(path and load(path)['purpose']=='PRODUCTION_RESERVED')
