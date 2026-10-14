# Verification strategy

Phase 0 includes upstream RandomX tests and a C++ evidence harness in `tests/phase0`, linked to the pinned upstream libraries. Phase 1 adds implementation and real node/mining/sync/reorg gates. Phase 2 adds wallet authority, address, encryption, recovery and real CLI tests in `tests/phase2/gates.py`. [STATUS.md](../STATUS.md) records executed results. Documentation checks validate links and structure only. The remaining broad suites describe later acceptance work unless explicitly recorded as executed.

## Phase 2 execution and evidence

On native WSL ext4, run `python3 scripts/phase2/build.py build`, then `python3 tests/phase2/gates.py`. Deterministic disposable test material and ephemeral random live secrets remain in private process memory or 0600 temporary files outside the repository. Tests suppress key-bearing assertion diffs and check generated evidence against all known test secrets before saving. Live tests create A/B, match exact output sets, delegate view-only authority with a separate password, reject ownership proof, destroy A, restore and rescan, and compare identical state. SIGKILL injection tests the old/new atomic persistence boundary.

`python3 scripts/phase2/build.py regression` reuses frozen executables and the exact existing DNS filter. `live-regression` runs unmodified Phase 1 integration and shorter/greater-work reorg scripts with only their build-module evidence destination routed into Phase 2. All original scripts and evidence remain unchanged. `scripts/phase2/review.py` verifies frozen inputs, genesis/reward determinism, environment, source/artifact identity and closure. All new evidence is under `docs/evidence/phase2/wsl2`.

The Linux wallet tests have no platform skips. Native Windows wallet persistence is explicitly UNSUPPORTED_PENDING_ACL_DURABILITY_REVIEW and fails securely; Windows live execution is NOT_EXECUTED under the unchanged Smart App Control policy. Upstream WSL physical HDD/SSD probes retain their original environment self-skips, and the exact two frozen DNS exclusions remain separately disclosed. No new upstream test exclusion is introduced.

## Deterministic devnet design

Record genesis bytes/hash, network identity, parameter set, full source/dependency/compiler pins, known test-only seeds, fixed clock inputs, node topology, scheduler event order, mining input/nonce fixtures and expected state commitments. Wallet/proof randomness is supplied by a fixture-only provider. Normal wallets always use OS entropy and cannot invoke fixture generation.

Byte-for-byte replay requires fixed proof randomness, mining nonce order and delivery schedule as well as a fixed seed. A live network is nondeterministic; reproduce its logical invariants separately from scheduled replay. Fixture keys are public and never security evidence. Replaying a fixture must not contact external seed nodes.

## Required suites

| Suite | Meaningful acceptance property |
| --- | --- |
| Canonical encoding | One encoding per object; malformed lengths, scalars, points, versions and trailing bytes rejected |
| Upstream crypto vectors | Unchanged proof/key/PoW paths agree with pinned reference; enclosing-domain mutations fail |
| Conservation / issuance | Checked integer model agrees with committed state; overflow and hidden-inflation vectors rejected |
| Ownership / spend identity | Forged authority fails; duplicate spends fail transaction/block/branch-wide and across proof versions |
| Consensus / sync | Greatest validated work wins; peers converge after partitions; invalid high-work claims rejected |
| Mining / templates | CPU solo mining needs no pool or secrets; templates bind parent/seed/root, cancel stale work and include only verified conflict-free transactions |
| DAA / RandomX seeds | Startup/lag/cut/zero-span/overflow/target-endian boundaries and branch-derived seed changes agree with exact fixtures and reference modes |
| Coinbase / tail / limits | Reward equals subsidy plus fees; fees never increase issued supply; tail/saturation, maturity ±1, genesis allocation and byte/weight caps verified |
| Regtest / mining privacy | Real RandomX and full validation at isolated fixed difficulty; miners get no plaintext ordinary amounts, payment identities, wallet balances or secret keys |
| Crash / reorg | Interrupted application leaves complete old/new state; rollback equals genesis rebuild; wallet rewinds correctly |
| Wallet backup / view | Fresh restore recovers derivable funds; corrupt backups fail; viewing capability cannot sign or overstate spendable balance |
| Privacy policy | No transparent normal form, reduced-ring fallback, secret remote scan export or configured proxy bypass |
| Remote node / relay | Omission, stale data, excessive fees, malformed responses and stem failures remain bounded and cannot induce unchecked signing |
| Migration | Activation/reorg, old-backup import, interrupted conversion and cross-family repeat-spend cases preserve value |
| Resource / fuzz | Invalid and worst-case valid inputs obey documented CPU/memory/disk bounds; sanitizer failures are triaged |

Use property tests against an independent integer/state model, differential upstream verification for unchanged components, negative proof vectors, packet capture for transport policy, sanitizers for native code and crash injection for persistent state. Avoid tests that merely repeat implementation logic. Batch verification, caches and optimized crypto must preserve independent-verification acceptance.

Measure privacy separately from correctness: simulate known-real outputs, poisoned decoys, small anonymity sets, timing/age distributions, repeated merges and fee/shape classes. Report statistical methodology and limits. Self-generated test traffic does not prove real-world anonymity.

Record exact commands, fixtures, expected versus observed results and known failures in each checkpoint. Once relevant tests pass, expand testing only for new changes or unresolved concerns. Performance evidence includes hardware/toolchain, warm/cold state, worst-case valid inputs and peak resources; it never substitutes for correctness.

The binding [mining specification](../docs/protocol/MINING_CONSENSUS.md) defines vector contents and boundary cases. Phase 0 now publishes actual upstream-generated digest/template/genesis artifacts and 44 implementation-linked mining/consensus checks. This is unit-level evidence, not an implemented mining CLI or running chain. Fixed-difficulty regtest never substitutes for dynamic-difficulty scenarios.

The final [Phase 0 external-test policy](../docs/design/PHASE0_EXTERNAL_TESTS.md) separates exactly two live public-donation DNS availability fixtures from deterministic local evidence. Their classification requires a fresh unchanged pristine upstream reproduction, independent DNS diagnostics, and a passing 21-check companion calling real upstream TXT/OpenAlias/address-validation code with synthetic resolver results. This companion does not test live DNSSEC authentication. Every other unit test and every mining/crypto/serialization gate must pass; no blanket network-test skip is allowed. [STATUS.md](../STATUS.md) records actual closure and execution results. Phase 2 is authorized; Phase 3 remains unstarted.
