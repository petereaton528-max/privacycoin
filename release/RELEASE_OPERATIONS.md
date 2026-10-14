> Historical preparation record below. RC1 publication is now authorized by
> PUBLICATION_AUTHORIZATION.json. Official fingerprint:
> 8BB1C05FC06715B93E80ED0B2B5E024E03ACBF0D. The manifest signature exists;
> the Git tag and supplementary documentation are unsigned. Mainnet activation
> remains unauthorized. Do not generate another signing key or Genesis.

# Owner-gated release operations (not executed)

Current approval permits preparation only. It does not authorize signing-key generation/use,
GitHub repository creation/push/upload/tag/release, Tor activation or Mainnet nodes.

## Signing identity and verification

Use a SEPARATE owner-controlled OpenPGP release-signing identity, for example
"Privacy Coin Release Signing", with an owner-selected contact and full fingerprint.
Never use founder/wallet keys. No signing key or fingerprint has been selected here.
Owner must separately authorize key creation/use and retain offline recovery material.
After that authorization, in a trusted environment with the chosen existing key:

```sh
gpg --local-user "$OWNER_APPROVED_RELEASE_FINGERPRINT" --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
gpg --export "$OWNER_APPROVED_RELEASE_FINGERPRINT" > release-signing-public.gpg
gpg --show-keys --with-fingerprint release-signing-public.gpg
gpgv --keyring ./release-signing-public.gpg SHA256SUMS.asc SHA256SUMS
sha256sum --check SHA256SUMS
```

Place all listed exact artifacts beside SHA256SUMS. Publish the full fingerprint
through an independently authenticated channel; a colocated public key does not
by itself authenticate the download. Verify offline on a separate trusted installation.
Signs bind bytes, not security quality. Sign the final release/preparation manifest
separately if publishing the curated source-stage ZIP and disclosure supplements.
Do not regenerate or edit the approved three original archives.

## GitHub publication - separate approval required

Owner selects public repository URL, release tag and signing identity. Suggested
version/tag: 1.0.0-mainnet-rc1 / v1.0.0-mainnet-rc1 (not created). Use THIS isolated
staged source tree, never the dirty authoritative or original N2 repository.
Review PUBLICATION_FILES.json and excluded-file list. After publication authorization,
initialize a new Git repository in that source directory, stage only listed files
plus PUBLICATION_FILES.json, inspect staged names, and commit with the authorized
owner identity. Add only the explicitly approved remote URL. Create/sign a tag,
push and upload only after their explicit approval. No remote is configured here.

Release assets: exact RC1 binary, exact source companion, exact GNU corresponding-source
companion, original SHA256SUMS, detached signature and public signing key; include the
risk disclosure, owner decision and publication manifest. Do not label it independently
audited. Retain original engineering/overlay commit and archive composition in provenance.
The curated repository's first publication commit will have a different hash.
Use PUBLICATION_MANIFEST.json, not GitHub-generated source alone, for exact source correspondence.
Keep corresponding sources publicly available alongside binaries and license notices.

## Mainnet activation - separate approval required

Do not execute now. After owner authorizes activation, use the approved-G installed
client on a supported trusted host. Do not copy any prior Devnet/N2 database or wallet.
In the GUI configure this host's verified SOCKS5 endpoint and independently checked
public pcnode seed descriptors. Click Connect Tor explicitly; verify approved network,
Genesis and recent authenticated peer activity, not just Tor bootstrap 100%.
Publish verified public descriptors only after permission to operate public endpoints.
Seeds help discovery and do not issue joining tickets or confer consensus authority.
Never expose local RPC publicly; no unattended service/autostart installation is implied.
Start bounded CPU mining explicitly in the GUI only after activation approval.
Monitor canonical progress and resource use. Stop only affected owned processes on
actual safety failure, preserve evidence, and reconcile uncertain payments before any retry.
Founder client migration and distributions remain owner-only; never include custody files
in releases. No founder transfer is an automatic launch step. No new Genesis is constructed.
