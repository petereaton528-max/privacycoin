# Source and binary redistribution

The owner approved BSD-3-Clause for eligible original contributions on 2026-10-12.
See the root LICENSE and LICENSE_SCOPE.md. Third-party terms remain separate.
Local compliance-inspection archives are not authorized public releases.

## Corresponding-source mechanism

For a later authorized binary download, provide the exact covered corresponding
sources beside that binary, with equally clear access, at no additional charge.
Use GPLv3 section 6(d) where applicable and an appropriate LGPL/GPLv2 mechanism
for their covered components. Do not rely on a checksum, upstream homepage,
generic source link or unsupported written offer. Preserve access while required
by the applicable distribution terms. This project makes no written source offer
on behalf of an upstream vendor.

The local `out/network-v1-license-compliance1/corresponding-source/` acquisition
set contains exact versions authenticated by signed Ubuntu indexes where available.
Its REQUIRED.json and ACQUISITION.json distinguish complete acquisitions from
missing components; distro sources include orig archives, Debian/Ubuntu patches
and build rules. The GNU compiler/runtime source may be much larger than the
runtime binary. Preserve the full covered source and necessary build inputs.
Signed source identity is evidence of correspondence to a distro package, not an
independent reproduction of the vendor build or proof that every requirement is
satisfied. If any required source remains missing, affected binaries stay BLOCKED.

For LGPL dynamic libraries, preserve the ability and permission to replace/relink
modified covered libraries, and do not prohibit reverse engineering for debugging
those modifications. For static LGPL combinations, provide compliant application
relinking materials or sufficient rebuildable application source and all required
inputs/rights under the applicable version. Directory separation alone does not
resolve the combined-work question. The GCC Runtime Library Exception applies
only to its covered files and eligible builds, not arbitrary GNU libraries.

## Assembly and review

1. Use explicit source/runtime selection, including LICENSE, LICENSE_SCOPE.md,
   CONTRIBUTING.md, component inventory, complete required texts and notices.
2. Bind sources, vendor patches, build recipes and relinking materials to exact
   binary hashes. Do not rewrite an old source-binding hash after changing code.
3. Keep modified Python runtime selection documented: tests, site-packages,
   developer tools and unused bindings are omitted as recorded by each manifest;
   current payloads may retain upstream helper tools. No interpreter source change
   is implied by subset packaging. Keep actual PSF/Tcl/Tk and bundled notices.
4. Windows Microsoft Distributable Code retains its conditional, Windows-only
   redistribution terms in the actual Python LICENSE. Those conditions apply to
   that code, not independent PC source. Do not distribute on other platforms or
   remove notices; complete downstream pass-through review before public binaries.
5. Run focused packaging/compliance tests, inspect exact archive manifests and
   perform sensitive-file/secret checks. A known-secret scan cannot prove the
   absence of unknown secrets. Never include historical N2 identities or data.
6. Recheck `LICENSE_COMPLIANCE.json`: a BLOCKED inspection archive must not be
   represented as redistribution-ready. Publisher approval is a separate gate.

`python -m apps.network_v1.licensing ARCHIVE.zip` validates the bound licensing
record and manifest, reporting unresolved prerequisites. It cannot resolve legal
interpretation or substitute for an exact component/source audit. Independent
security review and public-network authorization remain separate.

For new exact-component inventories, also run:
`python -m apps.network_v1.licensing ARCHIVE.zip --source-directory DIRECTORY`.
This checks adjacent archive SHA-256, package manifests and every bound supplier
source member. Keep the source directory user-controlled; symlinked archives and
path-bearing archive names are rejected. The result verifies local delivery
materials, never public availability or legal permission for held crypto/vendor
code. `--require-redistributable` still rejects any remaining licensing hold.
See CRYPTO_RIGHTS_AND_RUNTIME_DISPOSITION.md for the current exact disposition.
