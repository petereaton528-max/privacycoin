# Scope of the Privacy Coin license

Copyright (c) 2026 petereaton528-max

The root LICENSE is the BSD-3-Clause grant for original Privacy Coin contributions
over which the owner has the necessary rights. The owner approved this grant and
public attribution on 2026-10-12. It is not a claim of exclusive ownership of the
repository, a replacement for third-party terms, or a grant of rights the owner
does not possess.

`docs/network-v1/LICENSE_INVENTORY.json` identifies the reviewed source selection,
original project integration, inherited source, runtime components, build-only
tools and unresolved provenance. The original portions of the project-specific
application, SDK, local wallet/node adapters, optional Provider integration,
tests, scripts and documentation listed there use BSD-3-Clause. Existing embedded
notices and mixed-origin exceptions take precedence for their respective portions.
New source may use an SPDX header; existing source need not be mechanically
rewritten or rebuilt merely to add one. The inventory is a scope record, not an
automatic license detector or proof of copyright title.

The grant does **not** relicense `.upstream/`, copied dependency notices,
`docs/network-v1/third-party/`, third-party runtime files, vendor binaries,
generated dependency code, inherited cryptographic implementations, or material
flagged uncertain. Their original licenses and attributions remain applicable.
Historical operational evidence, private data and unrelated unreviewed worktree
changes are not automatically approved for distribution.

Read `docs/network-v1/THIRD_PARTY_NOTICES.md` and
`docs/network-v1/REDISTRIBUTION.md` before assembling a distribution. Some binary
dependencies have GPL/LGPL source and relinking requirements; some Windows runtime
code has vendor-specific conditions. No blanket BSD-only binary claim is made.

BSD-3-Clause permits independent development and commercial redistribution under
its terms. No centralized developer account, exclusive permission or copyright
assignment is required for independently developed compatible applications.
Project publication authorization and security/release gates are separate from
the rights granted by the license.

The independently written PC compatibility adapters and verification code under
`experiments/sphlib/` are eligible original BSD-3-Clause contributions. Their
copies delivered at the four replacement `.upstream/monero/src/crypto/` interface
paths carry the same explicit BSD headers. The separate `vendor/` and
`pc_sphlib/` source remains MIT, with all Projet RNRT SAPHIR notices preserved.
This adds no grant for the original inherited Wu/Saarinen implementations.
