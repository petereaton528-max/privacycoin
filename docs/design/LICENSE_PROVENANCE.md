# Phase 0 license and provenance review

Scope: the exact source pins in [DEPENDENCIES.md](DEPENDENCIES.md) and the native Windows package lock. Production node/wallet/crypto/consensus source remains unmodified in `.upstream/monero`; the [three notification/logging/HTTP test fixture deltas](../evidence/phase0/test-source-deltas.json) have original/modified hashes and dated modification notices, preserving every original attribution. This repository retains 14 [verbatim upstream notice files](../evidence/phase0/notice-inventory.json) and 50 [build dependency notice files](../evidence/phase0/build-notice-inventory.json), each with SHA256 digests. Embedded source-file notices remain in their original source; an inventory of standalone licenses alone is not a complete distribution license bundle.

## Redistribution obligations

| Material | License and obligations |
| --- | --- |
| Monero, CryptoNote-derived code, RingCT/CLSAG/Bulletproofs+, epee | Predominantly BSD-3-Clause. Preserve original copyright, conditions and disclaimers in source and binary distribution materials; no implied endorsement. Preserve original CryptoNote and other contributor notices, including per-file exceptions. |
| RandomX | BSD-3-Clause for tevador/Monero code. Preserve both attributions and disclaimers. Bundled Argon2/Blake2 carry additional embedded notices; keep those files and their notices, not only the top-level license. |
| LMDB | OpenLDAP Public License 2.8 plus COPYRIGHT. Retain terms/attribution, follow modification and distribution provisions, and reproduce required license materials. |
| RapidJSON | MIT main code; BSD-3-Clause msinttypes and GoogleTest; additional component licenses in `license.txt`. The JSON_checker material has the restrictive JSON license, including its use restriction. It is not part of the selected runtime build; source redistribution still requires preserving its terms or an explicit reviewed exclusion. Do not describe the entire archive as MIT-only. |
| GoogleTest, both baseline-bundled and recursive copy | BSD-3-Clause, preserve copyright/license/disclaimer in source and binary materials. |
| SUPERCOP | Per-implementation notices/public-domain statements; no single blanket license assumption. Current Windows autodetection selects the baseline `cn` backend, not a SUPERCOP implementation. Any later backend selection requires an exact compiled-file license review. |
| trezor-common | LGPL-3.0 license file; not built (`USE_DEVICE_TREZOR=OFF`). Distribution of this source still requires LGPL/GPL notices and corresponding-source obligations as applicable; enabling generated/integrated code requires separate linkage review. |
| ethereum-lists/tokens | MIT, recursive data dependency of disabled Trezor; preserve notice on redistribution. |
| Easylogging++, qrcodegen, OpenAES and other in-tree helpers | Preserve their embedded per-file notices and disclaimers. Easylogging++/qrcodegen are MIT; OpenAES has BSD-style terms. Keccak, Groestl, JH, Skein, Ed25519/AES code and inherited crypto helpers must retain their original individual notices and public-domain statements where present. |

For downstream changes, keep upstream notices intact and record changed files, patch purpose, upstream revision and author in a downstream change log. Licenses that require prominent modification/date notices must receive them. The BSD license does not itself impose a universal modification-notice requirement; project provenance policy does. Do not substitute a new project copyright for upstream authorship.

## Windows build dependencies

The [package lock](../evidence/phase0/windows-packages.json) records reported license identifiers for every acquired package; [package metadata](../evidence/phase0/package-metadata/mingw-w64-x86_64-libsodium.BUILDINFO) preserves build inputs/recipe hashes. Reported identifiers must be checked against exact source and compiled/linked files before distribution.

- OpenSSL: Apache-2.0, retain license and applicable NOTICE/attribution and modification notices.
- libsodium: ISC, retain copyright and permission notice.
- ZeroMQ: MPL-2.0 covered-file obligations, including corresponding source for distributed modified covered files and modification notices; separate licenses apply to unrelated application code.
- Boost: BSL-1.0, preserve required copyright/license in source distributions.
- Unbound: BSD family and component notices; preserve each required notice.
- GCC/runtime: GPL plus GCC Runtime Library Exception where applicable; compiler/tools distribution has its own corresponding-source obligations. The exception is not a blanket exemption for every bundled tool/library.
- MinGW CRT/headers, ICU, zlib, zstd, bzip2, xz, libffi, iconv, gettext, GMP and supporting DLLs: individual licenses in the lock and package source. LGPL components require corresponding-source and relinking/replacement rights as applicable; distributing DLLs rather than statically linking does not remove notices/source obligations.
- CMake: BSD-3-Clause plus bundled third-party notices; Python: PSF and bundled notices; python-zstandard: its license and embedded zstd notices. Acquisition tools are part of reproducibility provenance even when not linked into the node.

The package audit retains 29 historical recipes matching the packages' `.BUILDINFO` hashes and 85 [recipe-local patch/input files](../evidence/phase0/recipe-inputs.json), verified against their immutable Git blobs. Those recipes contain source URLs/checksums, patch identities, component license declarations and source-installation steps. [Native linkage evidence](../evidence/phase0/native-linkage.json) traverses PE imports and verifies all 19 bundled DLLs byte-for-byte against the locked package archives, recording package owners, licenses and recipe commits. Windows OS/API-set imports are recorded separately. Static Monero/RandomX libraries retain their original per-file notices in the verified baseline; the recipe and notice inventory covers acquired tools as well as runtime dependencies.

This satisfies the scoped Phase 0 obligation/provenance record, with explicit limits: vendor package builds have not been independently rebuilt or attested, and an exhaustive static-file distribution SBOM is not produced. No binaries are being published here. Before source or binary redistribution, assemble the precise compiled-file/dependency notice bundle and satisfy all corresponding-source/linkage duties. The retained notice inventory is evidence of preservation, not final legal clearance. Do not remove attribution to make the project appear independent of its upstream foundation.
