# Locked dependency baseline

Date: 2026-10-07. Phase 0 source families are selected at immutable commits. Build-package artifacts are SHA256-locked, with exact historical recipe commits and retained recipe-local inputs. Identities alone do not establish runtime correctness or independently attest the package vendor's build.

## Upstream source and recursive submodules

Selected Monero release: `v0.18.5.3`, authenticated annotated tag object `a759b82b13ebb48eaf3ef3a8a4e01391a7b13eec`. GitHub's saved verification reports a valid signature. The [tag evidence](../evidence/phase0/monero-release-tag.json) names the commit below; this is recorded verification evidence, not a local independently established signer trust chain. The release label is explanatory; acquisition uses only the full commit.

| Repository URL | Exact commit | License | Purpose | Reuse |
| --- | --- | --- | --- | --- |
| [monero-project/monero](https://github.com/monero-project/monero) | `22578c3f7d7b4b6dd85ff7daa42a827d97cc53d0` | BSD-3-Clause plus per-file exceptions | Node/wallet, RingCT/CLSAG/Bulletproofs+, serialization and consensus baseline | Production source unchanged; three disclosed notification/logging/HTTP fixture patches and two test-only forced includes; host/consensus changes later |
| [tevador/RandomX](https://github.com/tevador/RandomX) | `12f2c2ffe2108d6cf54c391fee33c8bc3646cdab` | BSD-3-Clause plus bundled notices | CPU-oriented PoW | Unchanged algorithm/library; host integration adapted later |
| [Tencent/rapidjson](https://github.com/Tencent/rapidjson) | `129d19ba7f496df5e33658527a7158c79b99c21c` | MIT plus BSD/JSON/component exceptions | JSON parsing | Unchanged; exclude non-runtime tools from future binary distribution |
| [google/googletest](https://github.com/google/googletest) | `0a439623f75c029912728d80cb7f1b8b48739ca4` | BSD-3-Clause | RapidJSON recursive test dependency | Unchanged; not runtime-linked |
| [monero-project/supercop](https://github.com/monero-project/supercop) | `633500ad8c8759995049ccd022107d1fa8a1bbc9` | Per-implementation notices/public domain | Optional wallet crypto backends | Unchanged; not selected on this Windows build |
| [trezor/trezor-common](https://github.com/trezor/trezor-common) | `bff7fdfe436c727982cc553bdfb29a9021b423b0` | LGPL-3.0 file; review generated-file exceptions | Hardware-wallet protocol definitions | Unchanged source, disabled build; later enablement separately reviewed |
| [ethereum-lists/tokens](https://github.com/ethereum-lists/tokens) | `88414ef852e21279f217d2f3f8fd439cd7c5fd9f` | MIT | Recursive data for disabled Trezor | Unchanged; not runtime-linked |

The [source manifest](../evidence/phase0/source-acquisition.json) also records archive SHA256, true Git tree identities, repository paths and verified blobs. Export-ignored files are restored at the same commit. Recursive source pins are the gitlink identities in the selected parent trees. No source silently follows HEAD.

Bundled in-tree security-critical code shares the exact Monero commit above: `src/crypto` (hash/curve/legacy PoW helpers), `src/ringct` (commitments, CLSAG, Bulletproofs/Bulletproofs+), wallet/key derivation, `contrib/epee` (parsing/TLS/transport), `external/db_drivers/liblmdb` (storage), Easylogging++ and `tests/gtest`. They have no separate gitlink; the parent commit pins their bytes. RandomX's Argon2/Blake2 and RapidJSON's embedded helpers likewise share their parent commit. Preserve per-file licenses. Reuse remains unchanged for this baseline build; all subsequent protocol deltas require review.

## Required Windows build inputs

[WINDOWS_BUILD.md](WINDOWS_BUILD.md) specifies environment and exact commands. [python-tools.json](../evidence/phase0/python-tools.json) pins the CMake/zstandard wheel URLs and SHA256; CPython 3.12.10 x64 is the current prerequisite. [windows-packages.json](../evidence/phase0/windows-packages.json) pins all 36 native packages, complete filenames, version/release and hashes. [.PKGINFO/.BUILDINFO evidence](../evidence/phase0/package-metadata/mingw-w64-x86_64-libsodium.BUILDINFO) includes package recipe hashes and declared build inputs. Binary identity must not be presented as a verified source-build correspondence.

Named upstream release commits were resolved and saved in [build-source-commits.json](../evidence/phase0/build-source-commits.json). These identify the source releases. The package recipes below separately pin actual source archive checksums and packaging changes; a release tag is not proof that the package vendor built that tree. [Recipe-local inputs](../evidence/phase0/recipe-inputs.json) retain 85 original files with Git-blob and SHA256 verification. [Native linkage](../evidence/phase0/native-linkage.json) maps all 19 recursive bundled DLLs to their locked archive bytes, owner, reported license and exact recipe.

| Build dependency repository | Exact upstream release commit | License | Purpose / reuse |
| --- | --- | --- | --- |
| [cmake](https://github.com/Kitware/CMake) | `859ca5c4d7396a011a462878179bc173e1283731` | BSD-3-Clause + bundled | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [python](https://github.com/python/cpython) | `0cc81280367df838c4b199f8f0378837165071c2` | PSF + bundled | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [zstandard-python](https://github.com/indygreg/python-zstandard) | `7a77a7510b8ce068e4a103d29aea1b5ec829d8b6` | BSD-3-Clause + embedded zstd | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [boost](https://github.com/boostorg/boost) | `afdfa32505af73e3d208144b3f623f0096cb62b6` | BSL-1.0 | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [openssl](https://github.com/openssl/openssl) | `c8bd5a57108599ac650bbae77fcabe3109dab2e8` | Apache-2.0 | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [libsodium](https://github.com/jedisct1/libsodium) | `77e1ce5d6dee871c49ef211222ba18ef0c486bda` | ISC | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [zeromq](https://github.com/zeromq/libzmq) | `622fc6dde99ee172ebaa9c8628d85a7a1995a21d` | MPL-2.0 | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [unbound](https://github.com/NLnetLabs/unbound) | `13b6717f1716810523ffb60f971a6c9c5e8ce127` | BSD + bundled | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [gtest](https://github.com/google/googletest) | `063de7e9578f82b369302001269680b4b1553359` | BSD-3-Clause | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |
| [gcc](https://github.com/gcc-mirror/gcc) | `78d4ac73dd391005b895a6148cd9831e28e1208b` | GPL + runtime exception | Source release identity; locked package unchanged, recipe deltas retained; no independent binary-build attestation |

| Native package | Version/release | Reported license |
| --- | --- | --- |
| `mingw-w64-x86_64-binutils` | `2.47-3` | spdx:GPL-3.0-or-later AND GPL-2.0-or-later AND LGPL-3.0-or-later AND LGPL-2.0-or-later |
| `mingw-w64-x86_64-boost` | `1.92.0-3` | spdx:BSL-1.0 |
| `mingw-w64-x86_64-boost-libs` | `1.92.0-3` | spdx:BSL-1.0 |
| `mingw-w64-x86_64-bzip2` | `1.0.8-4` | custom |
| `mingw-w64-x86_64-cc-libs` | `16.2.0-4` | spdx:GPL-3.0-or-later WITH GCC-exception-3.1 AND GFDL-1.3-or-later |
| `mingw-w64-x86_64-crt` | `14.0.0.r426.g4564ee4b5-1` | spdx:ZPL-2.1 |
| `mingw-w64-x86_64-expat` | `2.8.5-1` | spdx:MIT |
| `mingw-w64-x86_64-gcc` | `16.2.0-4` | spdx:GPL-3.0-or-later WITH GCC-exception-3.1 AND GFDL-1.3-or-later |
| `mingw-w64-x86_64-gettext-runtime` | `1.0-1` | spdx:GPL-3.0-or-later AND LGPL-2.1-or-later |
| `mingw-w64-x86_64-gmp` | `6.3.0-2` | LGPL3; GPL |
| `mingw-w64-x86_64-gtest` | `1.18.0-1` | spdx:BSD-3-Clause |
| `mingw-w64-x86_64-headers` | `14.0.0.r426.g4564ee4b5-1` | spdx:ZPL-2.1 AND LGPL-2.1-or-later |
| `mingw-w64-x86_64-icu` | `78.3-4` | spdx:ICU |
| `mingw-w64-x86_64-isl` | `0.28-1` | spdx:MIT |
| `mingw-w64-x86_64-ldns` | `1.9.2-1` | spdx:BSD-3-Clause |
| `mingw-w64-x86_64-libatomic` | `16.2.0-4` | spdx:GPL-3.0-or-later WITH GCC-exception-3.1 AND GFDL-1.3-or-later |
| `mingw-w64-x86_64-libgcc` | `16.2.0-4` | spdx:GPL-3.0-or-later WITH GCC-exception-3.1 AND GFDL-1.3-or-later |
| `mingw-w64-x86_64-libiconv` | `1.19-1` | spdx:LGPL-2.1-or-later; documentation:spdx:GPL-3.0-or-later |
| `mingw-w64-x86_64-libquadmath` | `16.2.0-4` | spdx:LGPL-2.1-or-later AND GFDL-1.2-or-later |
| `mingw-w64-x86_64-libsodium` | `1.0.22-3` | spdx:ISC |
| `mingw-w64-x86_64-libstdc++` | `16.2.0-4` | spdx:GPL-3.0-or-later WITH GCC-exception-3.1 AND GFDL-1.3-or-later |
| `mingw-w64-x86_64-libwinpthread` | `14.0.0.r426.g4564ee4b5-1` | spdx:MIT AND BSD-3-Clause-Clear |
| `mingw-w64-x86_64-make` | `4.4.1-5` | spdx:GPL-3.0-or-later |
| `mingw-w64-x86_64-mpc` | `1.4.1-1` | spdx:LGPL-3.0-or-later |
| `mingw-w64-x86_64-mpfr` | `4.2.2-3` | spdx:LGPL-3.0-or-later |
| `mingw-w64-x86_64-ninja` | `1.13.2-1` | spdx:Apache-2.0 |
| `mingw-w64-x86_64-openssl` | `3.6.5-1` | spdx:Apache-2.0 |
| `mingw-w64-x86_64-pkgconf` | `1~3.0.7-1` | spdx:ISC |
| `mingw-w64-x86_64-tzdata` | `2026e-1` | custom: public domain |
| `mingw-w64-x86_64-unbound` | `1.26.1-1` | spdx:BSD-3-Clause |
| `mingw-w64-x86_64-windows-default-manifest` | `20260815-1` | custom:Public Domain |
| `mingw-w64-x86_64-winpthreads` | `14.0.0.r426.g4564ee4b5-1` | spdx:MIT AND BSD-3-Clause-Clear |
| `mingw-w64-x86_64-xz` | `5.8.4-1` | spdx:0BSD AND LGPL-2.1-or-later AND GPL-2.0-or-later |
| `mingw-w64-x86_64-zeromq` | `4.3.5-5` | spdx:MPL-2.0 |
| `mingw-w64-x86_64-zlib` | `1.3.2-2` | spdx:Zlib |
| `mingw-w64-x86_64-zstd` | `1.5.7-2` | spdx:BSD-3-Clause OR GPL-2.0-or-later |

## Immutable Windows package recipes

Each recipe below was selected by matching the SHA256 recorded in the actual package's `.BUILDINFO`, among historical pre-build Git commits. All 29 distinct recipe hashes resolved, covering all 36 binary packages. The commit pins the source URLs/checksums, packaging patches and build recipe; it is not evidence that this machine rebuilt the dependency binary. Never replace these with the current package-repository branch.

| Recipe repository / path | Exact commit | Reuse |
| --- | --- | --- |
| [mingw-w64-binutils](https://github.com/msys2/MINGW-packages) | `b5f92242f8f46d43e9e87689d986c0df22e5fb3f` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-boost](https://github.com/msys2/MINGW-packages) | `54beb7c24b2c067d7feff288be944c2bbadec361` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-bzip2](https://github.com/msys2/MINGW-packages) | `4660b7d07063b222cfe8f7c20d465e6948f1ba41` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-gcc](https://github.com/msys2/MINGW-packages) | `982b29084494c55c69d5e7c776df531af77ce35c` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-crt](https://github.com/msys2/MINGW-packages) | `6c5d16ee3b3e0dd9a5387878709ad55ea0887d6d` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-expat](https://github.com/msys2/MINGW-packages) | `e94790aa0ab491dd9510c9c84ee0a31828520e0c` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-gettext](https://github.com/msys2/MINGW-packages) | `efb77424dfbeaaa22d96621274765d7ab5a3344f` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-gmp](https://github.com/msys2/MINGW-packages) | `19a497b647dea2939e4fe9cc2ad5818f83b1632f` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-gtest](https://github.com/msys2/MINGW-packages) | `7c4718926c0d96bbb235e4efdc064c0cdb634530` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-headers](https://github.com/msys2/MINGW-packages) | `6c5d16ee3b3e0dd9a5387878709ad55ea0887d6d` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-icu](https://github.com/msys2/MINGW-packages) | `107d46979abb4ebb4dd635d5ac2c24a738fbcea8` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-isl](https://github.com/msys2/MINGW-packages) | `ac40a7415269822a6b730fb54bd4703851c69d42` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-ldns](https://github.com/msys2/MINGW-packages) | `dddad08b8555a03c34b987a9a21145c364d1e2c5` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-libiconv](https://github.com/msys2/MINGW-packages) | `045d46aedb9fdbd93b0900b1e20c1a6c73f23072` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-libsodium](https://github.com/msys2/MINGW-packages) | `82bcf47d0ae2621e1cd00fb82c8ee5db02b91955` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-winpthreads](https://github.com/msys2/MINGW-packages) | `6c5d16ee3b3e0dd9a5387878709ad55ea0887d6d` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-make](https://github.com/msys2/MINGW-packages) | `6d51a3b212eeca775d5b9b4b89773e2331e6397c` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-mpc](https://github.com/msys2/MINGW-packages) | `192b41f75879a0e16ec5418b39b881fe63e8aff0` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-mpfr](https://github.com/msys2/MINGW-packages) | `82bcf47d0ae2621e1cd00fb82c8ee5db02b91955` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-ninja](https://github.com/msys2/MINGW-packages) | `ae49baed5796ecb5c6b9f314068cff14b933abf1` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-openssl](https://github.com/msys2/MINGW-packages) | `ea8fd74f46dcd41e996349621ca42a8a94f31548` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-pkgconf](https://github.com/msys2/MINGW-packages) | `7ad3d7962badbe382571299757c9a68333d8c173` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-tzdata](https://github.com/msys2/MINGW-packages) | `9b34161df9746b9bcd4c2719762e0b9012535329` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-unbound](https://github.com/msys2/MINGW-packages) | `73fefb6ef7340f62ae3666dfb4c6ed56f6278613` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-windows-default-manifest](https://github.com/msys2/MINGW-packages) | `1fbd5b465469fd68a1dc95ea901d29595bf0d390` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-xz](https://github.com/msys2/MINGW-packages) | `bcf3f933e6c743a5d58b563d0e7da81b32ae35ae` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-zeromq](https://github.com/msys2/MINGW-packages) | `72f950d88ac5e5d29e23ded555db81e4b3077ccf` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-zlib](https://github.com/msys2/MINGW-packages) | `6430831b570304e48982fce7d65af399b801ceab` | Exact MSYS2 binary package unchanged; recipe/source review |
| [mingw-w64-zstd](https://github.com/msys2/MINGW-packages) | `72f950d88ac5e5d29e23ded555db81e4b3077ccf` | Exact MSYS2 binary package unchanged; recipe/source review |

## Admission, evidence boundaries and future candidates

[STATUS.md](../../STATUS.md) reports actual closure gates and the exact two-test external DNS classification, governed by [PHASE0_EXTERNAL_TESTS.md](PHASE0_EXTERNAL_TESTS.md). Source archives, recipe/input identities, package versions/bytes, retained notices and native linkage are evidenced. No independent rebuild of vendor packages, complete distribution SBOM, or bit-for-bit binary reproducibility is claimed. Source/binary redistribution still requires the precise notice and corresponding-source bundle described in [LICENSE_PROVENANCE.md](LICENSE_PROVENANCE.md). A dependency name or signed release does not establish a test pass.

FCMP++/CARROT are not imported or enabled. Any later admission requires exact spec/source/transitive pins, audit-to-code/finding mapping and fresh integration vectors. Orchard/Halo 2/Pasta and Seraphis/Jamtis remain studied alternatives. Tor/I2P and wallet backup integrations remain later selections. No generic library with a matching proof-system name may be substituted without wire/transcript/curve compatibility review.

Windows x64 is the required Phase 0 build machine. Linux/ARM and RandomX fast/light, AES and JIT/interpreter parity are later portability validation; none may define a different consensus hash. Current mode evidence is explicitly recorded. The [license review](LICENSE_PROVENANCE.md) and [mining profile](../protocol/MINING_CONSENSUS.md) enumerate downstream consensus boundaries and remaining obligations.
