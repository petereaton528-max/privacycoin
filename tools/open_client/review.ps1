# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 petereaton528-max
param([string]$Output)
$ErrorActionPreference='Stop'
if ((git rev-parse --show-toplevel).Replace('\','/') -ne 'D:/grok Projects/Privacy_Coin_V1_20261011') { throw 'Wrong repository' }
if ((git branch --show-current) -ne 'v1/candidate-20261011') { throw 'Wrong branch' }
if (@(git diff --cached --name-only).Count -ne 0) { throw 'Unexpected staged content' }
$network=@('src/network_identity.py','src/phase4/ledger.h','src/phase4/node.cpp','src/phase4/wallet.py','apps/network_v1/rpc.py','apps/network_v1/run_node.py','apps/network_v1/onion.py','apps/network_v1/public_network.py','apps/network_v1/peer_uri.py','apps/network_v1/upstream.py','apps/network_v1/tests/open_network.py','apps/network_v1/tests/test_public_network.py','apps/network_v1/tests/local_socks.py')
$client=@('apps/network_v1/desktop.py','apps/network_v1/desktop_backend.py','apps/network_v1/upgrade.py','apps/network_v1/sdk.py','apps/network_v1/licensing.py','apps/network_v1/Launch-Open-PC.sh','apps/network_v1/Setup-Open-PC.sh','apps/network_v1/tests/first_use.py','apps/network_v1/tests/gui_payments.py','apps/network_v1/tests/test_private_packaging.py','apps/network_v1/tests/test_upgrade.py','docs/network-v1/OPEN_DEV02.md','docs/network-v1/SDK_SOURCE_SCOPE.md')
$client+=@(Get-ChildItem -LiteralPath tools/open_client -File | ForEach-Object { 'tools/open_client/'+$_.Name })
$owned=$network+$client
$records=@{}
foreach ($name in $owned) {
    $raw=[IO.File]::ReadAllText((Join-Path (Get-Location) $name))
    if ($raw -match '-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----\s+[A-Za-z0-9+/]{20}' -or $raw -match '(?i)gh[pousr]_[A-Za-z0-9]{30}') { throw "Sensitive pattern: $name" }
    $records[$name]=(Get-FileHash -LiteralPath $name -Algorithm SHA256).Hash.ToLower()
}
$protected=@{}
$historical=@(git ls-files -m)+@(git ls-files --others --exclude-standard)
foreach ($name in $historical) {
    if ($name -in $owned -or $name.StartsWith('docs/evidence/network-v1-open-client-20261013/')) { continue }
    if (Test-Path -LiteralPath $name -PathType Leaf) { $protected[$name]=(Get-FileHash -LiteralPath $name -Algorithm SHA256).Hash.ToLower() }
}
$record=@{repository=(git rev-parse --show-toplevel);branch=(git branch --show-current);baseline_head=(git rev-parse HEAD);network=$network;client=$client;reviewed_sha256=$records;protected_worktree_sha256=$protected;secret_pattern_findings=0;scope='Explicit current product paths; preserved historical paths are hash-only, never staged'}
if (Test-Path -LiteralPath $Output) { throw 'Review receipt already exists' }
[IO.File]::WriteAllText($Output,($record | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output ('Reviewed '+$owned.Count+' source/tool paths; preserved '+$protected.Count+' unrelated paths')
