# Implementation boundary

No project node, wallet or devnet is implemented here. Phase 0 acquires pinned upstream source into ignored `.upstream/monero` and compiles it using its existing CMake build. Production source is unchanged; three fixture-only patches are disclosed with hashes/notices. `consensus/development_profile.h` supplies reusable bindings and boundary rules for the already accepted development profile, called by `tests/phase0`; it is not a Phase 1 ledger. [STATUS.md](../STATUS.md) governs closure; advancing to Phase 1 requires a separate user instruction even after Phase 0 completes.

The selected private baseline is a pinned Monero-derived C++/CMake stack. Planned responsibilities are consensus, crypto adapters, chain storage, mempool, P2P/sync, relay/transport, wallet/key storage, CLI node/wallet and a deterministic devnet harness. Preserve coherent upstream boundaries rather than reorganizing reviewed code solely to match this list.

The Phase 1 public harness is isolated and disposable. It is not a public mode of the private currency. Do not add experimental cryptographic primitives or a full node rewrite here.
