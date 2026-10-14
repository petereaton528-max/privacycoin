# sphlib substitution notices

New substitution source/Linux/WSL2 artifacts use sphlib 3.0, written by Thomas
Pornin on behalf of Projet RNRT SAPHIR, pinned at
`15b6b8d8f3e4a43c58ba102d712fa6b8a3317035`. Copyright (c) 2007-2011 Projet RNRT
SAPHIR, with original per-file notices and years retained. sphlib is used under
its original MIT permission; it disclaims warranty and liability. Complete terms:
`third-party/licenses/SPHLIB-MIT.txt` and `experiments/sphlib/vendor/LICENSE`.
The one documented JH partial-bit adaptation retains legacy API behavior.
PC's original interface adapters are BSD-3-Clause; this does not relicense sphlib.

See SPHLIB_SUBSTITUTION.md/JSON. Unchanged GNU-covered runtime files retain their
existing license, source-delivery and replaceability obligations. No Windows
binary has been substituted: old crypto and Microsoft holds remain there.
The notices below describe previous archives, which remain preserved and held.

---

# Current third-party distribution notices

The root BSD-3-Clause license covers eligible original Privacy Coin contributions,
not all incorporated or bundled code. Retain original upstream copyrights and
license terms. See LICENSE_INVENTORY.json and the root LICENSE_SCOPE.md.

Selected JH source derives from Hongjun Wu's January 2011 optimized implementation;
selected Keccak source derives from Markku-Juhani O. Saarinen's November 2011
baseline, with CryptoNote/Monero adaptations. Neither is owner-relicensed.
See CRYPTO_RIGHTS_AND_RUNTIME_DISPOSITION.md and exact hashes/history in
CRYPTO_SOURCE_PROVENANCE.json. Their unresolved original permission scope still
blocks complete source/binary redistribution; an attribution is not a grant.
The separate sphlib MIT implementation is only an identified alternative and
is not incorporated into PC. No cryptographic implementation has been replaced.

Current RC5 Linux inspection packages redistribute Python/Tk, Tor and selected
shared libraries. Current native Windows previews redistribute Python/Tk and
Microsoft runtime code, Tor, native engines and libsodium. The prerequisite-only
statements below describe earlier sealed packages and are not current clearance.

Complete additional GNU/Apache texts: third-party/licenses/. Verbatim source
notices: third-party/upstream/. Runtime package copyright texts remain in
runtime/notices/ (Linux) and third-party/native-runtime/ plus
runtime/python/LICENSE.txt (Windows). Embedded source-file notices remain binding.

Principal terms: Monero/epee/RandomX BSD-3-Clause with embedded exceptions; LMDB
OpenLDAP-2.8; libsodium ISC; OpenSSL3 Apache-2.0; SQLite public-domain engine;
Tor BSD-style; libevent BSD-family; zlib permissive; Python PSF/historical licenses;
Tcl/Tk permissive; Boost BSL-1.0; GNU Readline GPL3+; selected Linux libraries LGPL;
GCC covered runtime files GPL with Runtime Library Exception; MinGW components
retain their own terms. Disabled trezor-common source remains LGPL3. RapidJSON,
SUPERCOP and inherited crypto need per-component/per-file treatment.

Native crypto and RandomX embedded notices are additionally retained under
third-party/compiled-notices/, including Brian Gladman AES attribution and
OpenAES terms. Each notice records its exact source hash. Argon2-derived source
retains its CC0 reference; a complete CC0 text is included with the other terms.
These notices supplement, rather than replace, parent and per-file grants.

The full upstream notices are retained, not replaced by this summary. Source and
relinking obligations, vendor conditions, component versions and uncertainty are
recorded in REDISTRIBUTION.md and LICENSE_INVENTORY.json. Authenticity and an
inventory do not establish blanket distribution compliance.

---

## Preserved historical notices (candidate-specific scope)

# Third-party build inputs

Pinned Monero 22578c3f7d7b4b6dd85ff7daa42a827d97cc53d0 and recursive locked source
selection: docs/design/DEPENDENCIES.md. Original LICENSE/COPYING/NOTICE/AUTHORS files
are retained beside included upstream source. Existing cryptography and RandomX
are reused; no source-license notices removed or replaced.

Python standard library/Tk and host system compiler/linker, Boost, OpenSSL,
libsodium, libunbound, libevent, glibc and libstdc++ are prerequisites, not a bundled
private runtime. Actual versions/linkage are recorded in the detached RC2 evidence.
Tor 0.4.9.11 used for isolated tests is an existing operator-supplied runtime;
its binary and private network identities are not included in these artifacts.

Candidate.3 exact notice inventory: [third-party/INVENTORY.json](third-party/INVENTORY.json).
The9 runtime COPYRIGHT texts are copied verbatim from installed Ubuntu package
documentation; they do not license downstream project code. Four native binaries
reuse candidate.2 outputs because their complete source/build bindings are unchanged.
Their prior three-build, same-host byte repeatability evidence remains valid;
independent cross-host reproducibility remains UNVERIFIED.

RC5 correction: native Linux outputs derive from RC4/RC5 clean builds, not the
older candidate.2 binaries. Final platform-header rebuild retains all four RC4
hashes. Windows native engineering builds use existing MinGW/Clang tools and
are not a packaged native desktop. No additional runtime DLL redistribution is
authorized by this record. Current notices remain required per component.

RC5 hardening distribution selection excludes unused RapidJSON JSON_checker
fixtures (`external/rapidjson/bin/jsonchecker/`) and the associated standalone
`test/unittest/jsoncheckertest.cpp`, whose JSON license has a use restriction.
The original checkout and all license notices remain unchanged. Monero includes
the RapidJSON headers without building RapidJSON's standalone test project;
no product target consumes these fixtures. This exclusion does not supply the
missing owner license grant or turn other component licenses into a blanket grant.

## RC5 file-specific redistribution dispositions

See [REDISTRIBUTION_HOLDS.md](REDISTRIBUTION_HOLDS.md) and
REDISTRIBUTION_BLOCKERS.json for exact inherited source exceptions and native
GNU/Microsoft scope. The Ed25519 public-domain statement and complete GCC Runtime
Library Exception 3.1 are retained under third-party/. New noninteractive Linux
bundles omit the unused GPL Readline binding and library; historical bundles and
notices are preserved. These findings do not relicense third-party code.
