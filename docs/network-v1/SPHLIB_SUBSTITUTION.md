# Adopted sphlib compatibility substitution

The owner-approved substitution was integrated into `v1/candidate-20261011`
through scoped commits `3c781d8`, `1f3090b` and `0824ea0`. The verified experiment
remains available at `experiment/sphlib-20261012`, based on `f26d0c2`.
Post-integration evidence and exact new package hashes are recorded in
`docs/evidence/network-v1-sphlib-integration-20261012/`. Old packages, historical
N2 deployment and the permission status of the inherited bytes are unchanged.

## Rights and implementation origin

The selected independent implementation is sphlib 3.0, Thomas Pornin's repository,
commit `15b6b8d8f3e4a43c58ba102d712fa6b8a3317035`. Its complete MIT permission
and Projet RNRT SAPHIR copyrights remain in `experiments/sphlib/vendor/` and
`third-party/licenses/SPHLIB-MIT.txt`. The per-file embedded notices remain
verbatim. This is redistribution under those original terms, not owner
relicensing of sphlib or of the inherited Wu/Saarinen source.

`vendor/PROVENANCE.json` binds the pinned downloads and actual adapted bytes.
Only JH's final padding-byte expression is adapted: retain low bits beyond the
declared bit length, matching the inherited one-shot API on noncanonical input.
Canonical partial-bit messages and all byte messages remain standard round-three
JH. This adaptation was derived from the observed API mismatch and the licensed
sphlib padding routine. No inherited rounds, constants or implementation bodies
were copied. New interface adapters carry the owner's BSD-3-Clause notice.

The adapters select sphlib's portable byte-access path (`SPH_UNALIGNED=0`). The
default x86 path triggered an undefined-behavior sanitizer alignment error on
misaligned data. That failed run is retained; it is not a passing result.

## Exact interface and consensus mapping

| Existing interface | Required semantics | Substitute |
|---|---|---|
| `jh_hash` | Round-three JH, 42 rounds; 224/256/384/512-bit output; bit length; high bits first; invalid digest length returns 2 | sphlib variants, including documented legacy noncanonical-tail adaptation |
| `keccak(...,32)` | Legacy Keccak-256, 136-byte rate, suffix `0x01`, final rate byte OR `0x80`; first 32 serialized state bytes | Licensed sphlib sponge/permutation, explicit legacy close |
| `keccak(...,200)` / `keccak1600` | Same 136-byte-rate absorption, **all 200 bytes of state**, not a 1600-bit-capacity hash or SHA3 | Explicit complete state export after lane uncomplementation |
| `keccakf(state,n)` | First n round constants, n=0..24; numeric host lanes | sphlib single-round macro with restored lane layout |
| incremental API | 136-byte blocks; 32-byte digest; nullable finish output; repeated finish stable; update after finish fails | Converted sphlib state with the original functional context field layout and finalized flag |

The other accepted whole-lane one-shot digest sizes 40,48,56,64,72,80,88,96
use rate `200 - 2*bytes` and are also compared. Invalid sizes remain rejected.
Internal lane complementation is an implementation detail: exported states and
digests use explicit little-endian bytes. No FIPS SHA3 `0x06` suffix is introduced.
There is no new domain prefix in either adapter.

`hash.c` calls the 200-byte absorption and 24-round permutation; `cn_fast_hash`
takes the first 32 bytes. These hashes cover transaction/block IDs, Merkle
trees, key derivation, RingCT/CLSAG/Bulletproof transcript inputs and wallet
operations. Their callers' existing serialization and domain strings are
unchanged. `hash-extra-jh.c` always passes `8*length` and 256 output bits; JH is
also a CryptoNight final hash. RandomX itself is unchanged; block hashing and
seed selection still depend on unchanged Keccak results. HMAC-Keccak uses the
incremental interface; the context layout and mixed-version continuation are
tested. No context is promoted to a supported on-disk wallet format.

## Reproduction and scope

Run `experiments/sphlib/compare.py --reference PATH --out NEW_PRIVATE_DIRECTORY`
under Linux. The reference is the read-only pinned Monero source. The script
uses the previously hash-verified author KAT archive locally; that archive is
not copied into a distribution. It compares independent upstream known answers,
boundary/random inputs through 1 MiB, misalignment, overlap, partial bits,
incremental chunks, repeated/null finish, complete states, permutation rounds,
32-bit JH arithmetic and undefined-behavior checks.

`stage.py --archive OLD_SOURCE_ARCHIVE --out NEW_UPSTREAM_DIRECTORY` verifies
the four selected baseline hashes, creates a new private source tree and applies
only the new adapters and licensed vendor subset. It never edits its input.
`apps/network_v1/build_clean.py` requires that reviewed substitution tree.
The release source selector performs the same substitution without mutating
the checkout and rejects unknown source versions.

`validate_core.py` and `cross_version.py` run only on fresh owned data and
loopback ports. Their exact commands, outputs and hashes are retained in the
new evidence directory. Cached unchanged upstream regression objects may be
relinked against the newly built crypto archive; that is labeled explicitly.

Executed x86_64 tests are not proof of every architecture. Actual 32-bit and
big-endian operating systems, physical-host recovery, external security review
and historical N2 raw blocks remain unverified where not accessible. Frozen
genesis and retained public consensus vectors can be checked independently;
operator-reported N2 tips alone cannot reconstruct historical block contents.

## Distribution boundary

Only packages built with these exact replacement sources and rebuilt Linux
executables may receive the scoped four-file hold disposition. Old source and
binary archives remain held under their original records. Windows binaries are
not substituted in this experiment: their inherited crypto rights, Microsoft
runtime conditions and Code Integrity execution restrictions remain separate.
GNU source/notice obligations are retained, not removed by the permissive hash
implementation. No package is approved for public publication by this work.
