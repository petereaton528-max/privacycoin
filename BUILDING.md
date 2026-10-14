# RC1 source and build correspondence

Download and verify all three files in release/SHA256SUMS. The GNU corresponding-source
ZIP is part of the source delivery, not an optional binary substitute. Retain all notices.
Supported target: Linux x86-64 / Ubuntu WSL2. Native Windows is not supported.

Exact production receipt: release/EXACT_RC1_BUILD.json. Component provenance:
SOURCE_REVISION.json, source-baselines/, provenance/, LICENSE_SCOPE.md and
docs/network-v1/THIRD_PARTY_NOTICES.md. This public snapshot has a new Git commit,
not the original private engineering history. Private profiles are not build inputs.

## Native compilation

Use retained .upstream/monero sources and the dependencies documented in its README.md.
Include the Privacy Coin targets from tests/phase4/CMakeLists.txt in that CMake build;
a plain upstream Monero executable is not Privacy Coin. These link retained cryptonote,
ringct, RandomX, LMDB and sodium libraries. Exact target flags, compile/link commands
and dependency hashes are in candidate-native/full/BUILD.json and OPEN_NATIVE_BUILD.json.
Relocate recorded absolute source/cache paths consistently for your build machine.
Do not silently substitute newer dependencies.

With that configured dependency cache, use the actual binding entry point:

```sh
python3 tools/creator_vesting/build.py --cache /absolute/path/to/configured-cmake-cache --output /absolute/path/to/new-native-output --candidate-only --with-node --binding candidate-native/full/BINDING.json
```

The output BUILD.json records commands and hashes. Do not enable accelerated vesting
or mock upgrades for production. Final assembly is tools/mainnet_prepare/package_final.py;
consult its CLI and retained receipts for component inputs. This publication adds no
rebuild and makes no new clean-machine or bit-identical compiler claim. Deterministic
archive packing is distinct from native compilation on arbitrary toolchains.

Never regenerate Genesis. Verify tools/mainnet_prepare/APPROVED_GENESIS.bin is 949 bytes,
SHA-256 ada8aa42012556f8a045e212d94fffaec47ebccc345900216539d4cdb36a6001.
Building or installing does not authorize Mainnet activation. README.md documents the
signed prebuilt package and release/RELEASE_OPERATIONS.md the separate activation gate.
