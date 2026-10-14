# Privacy Coin 1.0.0-mainnet-rc1

## Current status - October 14, 2026

**Owner-authorized initial Mainnet activation occurred on October 14, 2026.**
The owner reports that the first production block was mined at **height 1**.
This is an **early single-node Mainnet**: independent public peer connectivity,
continuous availability and decentralization remain **unverified**.

See [MAINNET_STATUS.md](MAINNET_STATUS.md) for the launch record and public initial
seed, and the [signed RC1 release](https://github.com/petereaton528-max/privacycoin/releases/tag/v1.0.0-mainnet-rc1)
for the exact archives and signed checksums. RC1 remains an early unaudited release candidate.

The original RC1 release notes describe their pre-activation publication checkpoint.
Their "Mainnet not activated" language is historical; the subsequent owner-authorized
activation is recorded in MAINNET_STATUS.md. The original release notes and signed
artifacts are unchanged.

**AI-assisted internal review only. No independent third-party security audit has been performed.**

Privacy Coin is new. Material risks include wallet fund loss, privacy leakage,
unquantified anonymity, hostile peers and resource exhaustion, software or consensus
bugs, compromised dependencies/devices, backup failure and low initial network/hash
power. Internal tests and owner acceptance are not security certification. No price,
profitability, anonymity or absence-of-inflation guarantee is made. Review
SECURITY_DISCLOSURE.txt and KNOWN_LIMITATIONS.md before considering use.

Supported: Linux x86-64 and Ubuntu WSL2/WSLg. Native Windows is not supported.
Frozen approved Genesis: 6233402308514d2d979a9efa9c6bd2f9843741598f1e5b18239cde16ba0d2b54.
No founder credentials or signing private keys are included.

## Verify downloads

Official public release-signing fingerprint:
8BB1C05FC06715B93E80ED0B2B5E024E03ACBF0D
UID: Privacy Coin Releases (Ed25519; no email).
Confirm this fingerprint through an independently authenticated owner channel.
A key uploaded beside a download is not an independent trust anchor.

Download all three ZIP archives, SHA256SUMS, SHA256SUMS.asc and
release-signing-public.gpg into a fresh directory, then on a trusted Ubuntu host:

```sh
mkdir -m 700 public-verification
gpg --homedir ./public-verification --show-keys --with-fingerprint release-signing-public.gpg
gpgv --homedir ./public-verification --keyring "$(pwd)/release-signing-public.gpg" SHA256SUMS.asc SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

Expect the full fingerprint above, a good signature, and three OK checks.
STOP on any mismatch. The existing detached signature authenticates ONLY
privacycoin-mainnet-rc1-linux-wsl2.zip, privacycoin-mainnet-rc1-source.zip and
privacycoin-rc5-gnu-corresponding-source-inspection.zip through SHA256SUMS.
It does NOT cover these release notes, public Git history, GitHub-generated source
archives or other supplements. No unsigned supplement is described as signed.
The Git tag is an unsigned publication pointer, not an OpenPGP-signed tag.

## Install and review offline

Extract the exact signed source companion into a new directory. From there:

```sh
python3 -m apps.network_v1.release install --archive /ABSOLUTE/PATH/privacycoin-mainnet-rc1-linux-wsl2.zip --destination "$HOME/pc-mainnet-rc1/client" --create-private-parent
"$HOME/pc-mainnet-rc1/client/Launch-PC.sh"
```

Do not use sudo or bypass OS protections. A fresh owner-only destination is required.
Launcher opens the local node and GUI; Tor and mining remain stopped by default.
The owner has authorized the initial Mainnet activation described above. Connecting
Tor and starting bounded mining remain explicit user actions; installation does not
start them automatically. Consult MAINNET_STATUS.md for the public seed and current
limitations before choosing to participate.
Use encrypted wallet backups and independent recovery; never send keys/passwords/
backups to support. UNKNOWN payments require reconciliation, not blind retry.
Do not migrate founder custody without its separate owner-only procedure.

## Source, policy and licenses

Packaged source overlays: 429badad910e26fcbfc2d387bd3b03a0c234917d;
validated engineering checkpoint b23b09c; internal decision d3486f6.
The public repository is a curated snapshot, not the private development Git history.
PUBLICATION_FILES.json records the original reviewed staging; PUBLICATION_CURRENT_FILES.json
records the publication tree plus documentation/public-signature additions.
Historical prepared/unsigned/inactive receipts retain their original scope;
release/PUBLICATION_AUTHORIZATION.json records this publication approval only.
Exact source and GNU corresponding-source archives accompany the binary; GitHub's
automatic source ZIP is not their substitute. Retain LICENSE, LICENSE_SCOPE.md,
third-party notices and all applicable source-delivery terms when redistributing.

Monetary/vesting/Genesis disclosure: tools/mainnet_prepare/approved_policy.json,
production_identity_proposal.json, APPROVED_GENESIS.json and FINAL_GENESIS_APPROVAL.json.
Creator allocation: 159627169409884823 atomic, 10% initially available and 90% in
16 releases at 65700-block intervals; no recurring founder levy. 10^12 atomic/PC,
120-second target, perpetual 0.6 PC tail after audited integer decay, no lifetime cap.
Coinbase maturity 60, ordinary maturity 10, ring size 16. Default fee 0.001 PC;
relay 100 atomic/byte is policy, not the consensus minimum (1 atomic through 1 PC).
No policy, immutable identity or Genesis is changed by this publication.
