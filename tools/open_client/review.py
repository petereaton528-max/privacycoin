"""Scoped review receipt without changing Windows script execution policy.
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026 petereaton528-max
"""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
GIT=['git','--git-dir=/mnt/d/grok Projects/Privacy_Coin/.phase0-git/worktrees/Privacy_Coin_V1_20261011','--work-tree='+str(ROOT)]
def git(*args):return subprocess.check_output(GIT+list(args),cwd=ROOT)
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
assert git('branch','--show-current').strip()==b'v1/candidate-20261011'
assert not git('diff','--cached','--name-only')
network=['src/network_identity.py','src/phase4/ledger.h','src/phase4/node.cpp','src/phase4/wallet.py','apps/network_v1/rpc.py','apps/network_v1/run_node.py','apps/network_v1/onion.py','apps/network_v1/public_network.py','apps/network_v1/peer_uri.py','apps/network_v1/upstream.py','apps/network_v1/tests/open_network.py','apps/network_v1/tests/test_public_network.py','apps/network_v1/tests/local_socks.py']
client=['apps/network_v1/desktop.py','apps/network_v1/desktop_backend.py','apps/network_v1/upgrade.py','apps/network_v1/sdk.py','apps/network_v1/licensing.py','apps/network_v1/Launch-Open-PC.sh','apps/network_v1/Setup-Open-PC.sh','apps/network_v1/tests/first_use.py','apps/network_v1/tests/gui_payments.py','apps/network_v1/tests/test_private_packaging.py','apps/network_v1/tests/test_upgrade.py','docs/network-v1/OPEN_DEV02.md','docs/network-v1/SDK_SOURCE_SCOPE.md']
client+=sorted(x.relative_to(ROOT).as_posix() for x in (ROOT/'tools/open_client').iterdir() if x.is_file())
owned=network+client;records={};protected={}
for name in owned:
    raw=(ROOT/name).read_bytes()
    assert not re.search(rb'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----\s+[A-Za-z0-9+/]{20}|gh[pousr]_[A-Za-z0-9]{30}',raw),name
    records[name]=hashlib.sha256(raw).hexdigest()
for entry in git('ls-files','-m','-z').split(b'\0')+git('ls-files','--others','--exclude-standard','-z').split(b'\0'):
    if not entry:continue
    name=entry.decode();file=ROOT/name
    if name not in owned and not name.startswith('docs/evidence/network-v1-open-client-20261013/') and file.is_file():protected[name]=hashlib.sha256(file.read_bytes()).hexdigest()
record=dict(repository=str(ROOT),branch='v1/candidate-20261011',baseline_head=git('rev-parse','HEAD').decode().strip(),network=network,client=client,reviewed_sha256=records,protected_worktree_sha256=protected,secret_pattern_findings=0,scope='Explicit product paths, protected unrelated dirty files hashed only')
with a.output.open('x') as stream:json.dump(record,stream,indent=2);stream.write('\n')
print(json.dumps(dict(reviewed=len(owned),protected=len(protected))))
