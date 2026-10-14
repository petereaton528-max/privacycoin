# Privacy Coin Mainnet V1 — unsigned release candidate

Linux x86-64 and Ubuntu under WSL2/WSLg. This client is bound to the owner's final
Mainnet Genesis `6233402308514d2d979a9efa9c6bd2f9843741598f1e5b18239cde16ba0d2b54`.
It is not the earlier disposable Devnet preview. No Mainnet activation or public
publication is authorized by this package. Do not connect Tor or mine until launch
authorization. Installation starts no service. No founder secrets are included.

## Installation and offline owner review

Keep the binary, source and GNU corresponding-source archives together. Verify
`SHA256SUMS` against the separately authenticated delivery. Extract the source ZIP
into a fresh directory and use its existing installer:

```bash
python3 -m apps.network_v1.release install \
  --archive /ABSOLUTE/PATH/privacycoin-mainnet-rc1-linux-wsl2.zip \
  --destination "$HOME/pc-mainnet-rc1/client" --create-private-parent
"$HOME/pc-mainnet-rc1/client/Launch-PC.sh"
```

Run the install command from the extracted source directory. A fresh owner-only
installation destination is required. Do not use sudo or disable OS protections.
WSL2/Ubuntu/WSLg installation, if absent, requires separate administrator approval;
native Windows is not a supported initial target.

The launcher opens a locally owned full node and GUI, with Tor off and mining
stopped. Mainnet data defaults to `~/.local/share/privacycoin-mainnet-v1`; it does
not reuse N2, Devnet or any previous owner-review profile. Create an ordinary
encrypted wallet, copy its 293-character address, make a complete encrypted backup,
restore into a different wallet name and verify the public identity. A new ordinary
wallet owns none of the seventeen creator outputs. Recovery refuses other networks
and other Genesis identities. Passwords/keys/backups must never be sent to support.

Mining is voluntary, bounded and single-worker. Coinbase maturity is 60 blocks,
ordinary maturity 10, ring size 16; unlocked funds also require eligible decoys.
Fees are shown before confirmation; default 0.001 PC subject to size. Relay policy
is 100 atomic units/serialized byte, distinct from consensus acceptance 1 atomic
through 1 PC. UNKNOWN outcomes require reconciliation, not another payment.

After separately authorized launch, Connect Tor accepts public `pcnode` bootstrap
links without tickets and an optional explicit upstream SOCKS5 route. Empty seeds
do not magically discover a network: operators must publish verified public seed
descriptors at launch. Seeds assist discovery, never authorize consensus admission.
No seed service or Internet connectivity was activated during package preparation.

## Founder custody migration — owner-operated, never automatic

The pre-Genesis wallet and encrypted backups remain unchanged. A separate owner-only
script `tools/mainnet_prepare/bind_founder_client.py` can derive the approved G-bound
client wallet into a NEW `privacycoin-mainnet-v1` directory from an existing founder
wallet, using its password locally. It requires the original verified founder-tool
installation, `--offline-confirmed` and an interactive hidden password prompt.
Do not run it against an existing destination; do not delete an ordinary wallet
profile to make room. Use a separate new owner-only parent if necessary and launch
with `--home /NEW/PARENT/privacycoin-mainnet-v1`.

Example (owner only, with actual trusted paths):

```bash
python3 tools/mainnet_prepare/bind_founder_client.py \
  --founder-tool "$HOME/pc-founder-install-v1/tool" \
  --wallet-file "$HOME/pc-founder-private-v1/original/founder.encrypted" \
  --destination /NEW/OWNER_ONLY_PARENT/privacycoin-mainnet-v1 --offline-confirmed
```

No agent execution against real custody is authorized. Open wallet name `Founder`
in the new client, check allocation/vesting, then create a complete client backup.
Original pre-Genesis backups remain useful for key recovery; they do not contain
future client payment journals. Retain both generations. Owner reported original
and independent-installation ownership proofs for all seventeen Genesis outputs;
physical backup independence remains unverified, with temporary single-computer
risk explicitly accepted.

## Updates, uninstall, release integrity

Use side-by-side installs and complete encrypted backup/recovery into a separate
profile. No silent in-place database migration or automatic updater is provided.
Remove only an explicitly selected installation directory to uninstall; preserve
wallet/data/backup directories. Do not copy active LMDB/SQLite files as a backup.

Source staging is allowlisted, has no public remote and has not been published.
Historical evidence inside source retains its original dates/scope. Current
authority is `FINAL_PRODUCTION_BUILD.json` and the final delivery report.
Preserve third-party notices and the accompanying GNU source archive when releasing.
Do not sign using a wallet key. After separate signing authorization, use an
owner-controlled release-signing key, sign exact final SHA256SUMS, distribute its
full fingerprint by an authenticated independent channel, and verify with gpgv
before checksum/installation verification. No signing private key was created/read.

## Security disclosure

Internal tests, native regression tests and owner A/B acceptance are not an
independent audit. Independent review of consensus inflation/vesting/Genesis,
privacy proofs and RNG, wallet secrets/recovery and public peer resource controls
remains outstanding. Python memory erasure, host/WSL compromise, eclipse/Sybil
resistance and Internet-scale abuse are not guaranteed by functional tests.
Consult the final internal review findings; confirmed critical defects must be
resolved, not waived implicitly. No launch recommendation follows from packaging.
