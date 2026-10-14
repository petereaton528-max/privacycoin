"""Owner-only read-only pre-Genesis custody -> NEW G-bound client wallet.
Never executed by the agent against production custody.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse,hashlib,json,os,resource,sys
from pathlib import Path
def seal_for_client(founder,master,secret,genesis,public):
    from tools.creator_model.binding import GenesisAddress
    binding=GenesisAddress(founder.f,founder.context(),genesis,'PCmn1-')
    encrypted=binding.seal(master,secret)
    recovered=binding.restore(encrypted,secret)
    if binding.parse(binding.address(recovered))!=(public['public_spend'],public['public_view'],False):raise ValueError('G_BOUND_RECOVERY')
    return encrypted
def main():
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    p=argparse.ArgumentParser();p.add_argument('--founder-tool',type=Path,required=True);p.add_argument('--wallet-file',type=Path,required=True);p.add_argument('--destination',type=Path,required=True);p.add_argument('--offline-confirmed',action='store_true');a=p.parse_args()
    if not a.offline_confirmed or not sys.stdin.isatty():raise ValueError('OWNER_INTERACTIVE_OFFLINE_REQUIRED')
    # This script belongs to the production package, whose hashes the owner verifies.
    root=Path(__file__).resolve().parents[2]
    spec=json.loads((root/'tools/mainnet_prepare/production_identity_proposal.json').read_bytes())
    artifact=(root/'tools/mainnet_prepare/APPROVED_GENESIS.json').read_bytes()
    if hashlib.sha256(artifact).hexdigest()!='7c43e779b46da9472c7588cba4b2fef823aa2ef61fc3956c7471f04afad46555':raise ValueError('FINAL_GENESIS_PIN')
    if hashlib.sha256((root/'tools/mainnet_prepare/production_identity_proposal.json').read_bytes()).hexdigest()!='67036217d08417ca8d996f2fd807d0a171b5d849e53fb7901225feeffddbaa04':raise ValueError('IDENTITY_PIN')
    recipient=json.loads((root/'tools/mainnet_prepare/APPROVED_PUBLIC_RECIPIENT.json').read_bytes())
    if hashlib.sha256((root/'tools/mainnet_prepare/APPROVED_PUBLIC_RECIPIENT.json').read_bytes()).hexdigest()!='c405c6529043fa287d61eead0a6c2ad6b6a1020c9acf2e414957ec3efe643069':raise ValueError('RECIPIENT_PIN')
    if not a.founder_tool.is_absolute() or any(x.is_symlink() for x in (a.founder_tool,*a.founder_tool.parents)):raise ValueError('INSTALLED_TOOL')
    sys.path.insert(0,str(a.founder_tool))
    from tools.mainnet_prepare import founder
    from tools.creator_model.binding import GenesisAddress
    founder.integrity();founder.directory(a.destination.parent)
    if a.destination.exists() or a.destination.is_symlink() or a.destination.name!='privacycoin-mainnet-v1':raise ValueError('FRESH_MAINNET_DESTINATION_REQUIRED')
    secret=founder.password();payload=founder.decrypt(a.wallet_file,secret)
    if payload['purpose']!='OWNER' or payload['public']!={k:recipient[k] for k in ('public_spend','public_view')}:raise ValueError('FOUNDER_MISMATCH')
    artifact=json.loads(artifact)
    encrypted=seal_for_client(founder,payload['master_seed'],secret,artifact['hash'],recipient)
    with founder.private_directory(a.destination.parent) as parent:os.mkdir(a.destination.name,0o700,dir_fd=parent)
    # Only a new encrypted wallet is written. Original and backups stay untouched.
    founder.write(a.destination/'Founder.candidate-wallet',encrypted)
    print('G_BOUND_FOUNDER_CLIENT_WALLET_CREATED; originals unchanged; open Founder with existing password; make a new complete client backup after opening')
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):
        print('Binding stopped. No original custody file was modified. Preserve any partial destination and inspect locally. No automatic retry or secret diagnostics.',file=sys.stderr);raise SystemExit(1)
