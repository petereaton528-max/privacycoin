# sphlib substitution scope ? source and rebuilt Linux/WSL2

The approved sphlib substitution, integrated into `v1/candidate-20261011`, replaces the four held inherited
implementations with independently licensed sphlib 3.0 and original PC adapters.
See SPHLIB_SUBSTITUTION.md and SPHLIB_SUBSTITUTION.json for exact rights,
compatibility evidence, source and rebuilt-binary hashes. MIT notices and
Projet RNRT SAPHIR copyrights are retained; the inherited files are not relicensed.
Post-integration evidence: `docs/evidence/network-v1-sphlib-integration-20261012/`.

For the newly bound substitution artifacts only:
OWNER_LICENSE_APPROVED=true; PROJECT_LICENSE_APPLIED=true;
SOURCE_DISTRIBUTION_LICENSE_READY=true; LINUX_BINARY_REDISTRIBUTION_READY=true;
WSL2_BINARY_REDISTRIBUTION_READY=true, with paired GNU sources and notices.
WINDOWS_BINARY_REDISTRIBUTION_READY=false; THIRD_PARTY_COMPLIANCE_VERIFIED=false
for the complete cross-platform set. Old archives and unchanged native Windows
objects retain their crypto holds. Microsoft runtime terms and Code Integrity
remain separate Windows blockers. PUBLIC_RELEASE_AUTHORIZED=false.

These are scoped redistribution-material findings, not independent legal or
security opinions, public-testnet readiness, universal architecture proof, or
permission to deploy. The main V1 branch remains unchanged pending integration.

The following records describe earlier, preserved artifact scopes.

---

# Current licensing status - owner grant applied, scoped redistribution holds

Latest file-specific disposition: CRYPTO_RIGHTS_AND_RUNTIME_DISPOSITION.md and
CRYPTO_SOURCE_PROVENANCE.json. The four selected source hashes and full pinned
path histories are verified; original JH/2011 Keccak permission coverage remains
unestablished. GNU_RUNTIME_COMPLIANCE.json binds actual libraries, notices and
49 corresponding-source members. The packaged Tor build5 now has its own
byte-identical linker-map proof; the earlier build8 map did not cover that
artifact. Microsoft conditions remain a separate native-Windows hold.

The owner approved BSD-3-Clause on 2026-10-12 with the public attribution
`Copyright (c) 2026 petereaton528-max`. Root LICENSE and LICENSE_SCOPE.md implement
that grant for eligible original contributions. Third-party and uncertain material
is explicitly excepted; no exclusive ownership of the repository is claimed.

OWNER_LICENSE_APPROVED=true; PROJECT_LICENSE_APPLIED=true.
THIRD_PARTY_COMPLIANCE_VERIFIED=false; SOURCE_DISTRIBUTION_LICENSE_READY=false;
LINUX_BINARY_REDISTRIBUTION_READY=false; WINDOWS_BINARY_REDISTRIBUTION_READY=false;
PUBLIC_RELEASE_AUTHORIZED=false. These cautious distribution states remain until
all applicable inherited-source exceptions and binary obligations are resolved.

Complete GPL2/GPL3/LGPL2.1/LGPL3/Apache2 texts and retained upstream notices are
included in third-party/. Exact GNU-covered Ubuntu sources have been acquired
where recorded. Four byte-identical native rebuilds with maps show no extracted
gettext/iconv archive members. These findings replace the earlier static-link
uncertainty for those four hashes, not for arbitrary future builds.

See LICENSE_INVENTORY.json, REDISTRIBUTION.md and the implementation evidence.
Windows Microsoft runtime pass-through review, inherited per-file source rights,
complete binary/source coverage and affected combined-work interpretations remain
specific blockers. No publisher signature, legal opinion or release authorization
is implied. Historical records below retain their original candidate scope.

See REDISTRIBUTION_HOLDS.md and REDISTRIBUTION_BLOCKERS.json for the current
file/artifact dispositions: 338 of 351 prior directory flags retained under
original terms; four selected JH/Keccak files still held for source and native binaries.
Nine unverified unused builder helpers are excluded from the new source selector;
originals and old archives remain preserved.
New noninteractive Linux/WSL bundles exclude Readline; legacy archives retain
their GPL combination hold. Six byte-identical native maps cover core/Tor/TLS.
Microsoft downstream terms apply only to native Windows, not Linux/WSL or source.
STANDALONE_SDK_SOURCE_LICENSE_READY=true for the hash-pinned existing BSD read SDK
subset; this is not SOURCE_DISTRIBUTION_LICENSE_READY for the complete product.
PUBLIC_RELEASE_AUTHORIZED=false for every artifact.

---

# License status - public distribution blocked

## Native self-contained preview additions

The Windows preview now redistributes the official full Python3.13.16 runtime,
including PSF/Tcl/Tk/Microsoft runtime notices in runtime/python/LICENSE.txt.
Microsoft runtime restrictions remain applicable; this is a Windows-only package.
Selected Python input files are explicitly enumerated and hashed. site-packages,
tests and developer tooling are excluded. Published Python package hashes and
PSF executable/DLL signatures are authenticated; this does not grant project rights.

Tor0.4.9.14 signed source, libevent2.1.13 stable, static OpenSSL/zlib/MinGW runtime,
libsodium and retained upstream components have copied verbatim notices under
third-party/native-runtime. Original source/acquisition/build records are retained
in local engineering artifacts. GNU runtime exceptions and applicable source or
relinking obligations must be reviewed for the actual static linkage. No blanket
license-compatibility or legal-clearance claim is made. The owner still must approve
the original project grant and actual redistribution obligations before publication.

## Current RC5 dependency-inclusive Linux validation bundle

Native Windows static-engine validation is now a separate engineering artifact.
It is not a Windows desktop release. Its notice set covers the existing MinGW,
Boost, OpenSSL, libsodium and other selected runtime inputs, plus pinned upstream
notices. Static linking differs from earlier dynamic builds: review the actual
link inputs and applicable source/relinking conditions before distribution. The
presence of notices and a successful build do not establish legal clearance.

The latest reviewed Linux validation bundle **redistributes** Python/Tk, Tor and
selected non-glibc shared libraries. The historical prerequisite-only description
below applies to older sealed packages, not this bundle. Current actual contents,
hashes, local origin paths and notices are in `runtime/PROVENANCE.json`,
`runtime/notices/` and the external evidence beside the package. These records
do not grant a project license or certify complete legal compliance.

Actual system-origin runtime files were matched byte-for-byte against packages
authenticated by signed Ubuntu base/updates/security metadata. Base noble is an
immutable signed distribution, not a fresh update feed. Updates/security require
the recorded freshness check. GUI provisioned files and the authenticated Tor
binary have separate provenance; project binaries derive from reviewed source.
Published-file authenticity is distinct from vulnerability review or licensing.

Unused Python DBM bindings and DBM package are excluded from the private
application runtime; PC and its SDK use SQLite, not DBM/shelve. Berkeley DB/GDBM
libraries therefore are not included solely for those unused bindings. This is
dependency minimization, not relicensing. All retained component notices remain.
This private runtime is not offered as a general-purpose Python distribution.

Owner approval of the project grant and applicable redistribution/source
obligations remains required. No owner identity, publisher signature, blanket
license or independent legal/security approval has been invented.

## Preserved earlier candidate audit

No blanket Privacy Coin project license grant was found at the inspected authority
root. This assignment does not invent the owner's licensing permission. Project
source is prepared for review, not declared fully licensed for public redistribution.
The owner must select/approve an applicable project license before public release.

Pinned upstream Monero/RandomX/other dependencies retain their original per-file
copyright/license/NOTICE files in the source archive. Read docs/design/DEPENDENCIES.md
and .upstream/monero/LICENSE and submodule notices. No Tor binary is redistributed:
use an independently reviewed existing/system Tor installation. Libraries remain
dynamically linked; runtime-dependencies.json records actual versions and linkage.
Neither checksum verification nor our self-review establishes license compliance.

Candidate.3 audit: `third-party/INVENTORY.json` hashes the14 standalone notices in
the actual pinned source archive. Nine exact host-library copyright texts are
included under third-party/runtime; these libraries remain system prerequisites,
not bundled DLL/shared-object redistribution. LICENSE_PROVENANCE.md is now included
with the source package. Embedded per-file notices and differing component terms
remain applicable. Project license selection is an owner action, not a coding fix.
