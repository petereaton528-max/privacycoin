# Contributing to Privacy Coin

This is experimental testnet software. Start with [installation/build
instructions](docs/network-v1/INSTALL.md), [developer interfaces](docs/network-v1/DEVELOPERS.md)
and [build provenance](docs/design/DEPENDENCIES.md). If a referenced platform
is blocked, retain that result; do not weaken host security or claim it passed.

Use an isolated branch/worktree and fresh test data. Make a focused change with
its rationale, supported platforms, exact tests and known limitations. Run the
relevant tests under `apps/network_v1/tests/` and the affected `tests/` phase.
For licensing/packaging changes run `python -m unittest
apps.network_v1.tests.test_licensing`; ordinary license edits do not require
repeating expensive long-chain tests. Do not add wallets, databases, journals,
credentials, Onion keys or historical private evidence to a pull request.

Original contributions submitted for inclusion are offered under BSD-3-Clause,
unless a specific existing file/component license requires otherwise. By
submitting, affirm that you have the right to contribute on those terms and
identify third-party material, source/version, changes and license. Keep your own
copyright attribution and all upstream notices. This policy requires neither
copyright assignment nor a CLA and grants no authority to relicense someone else's
contribution outside its license. Do not import code with uncertain rights or
remove attribution. Update the dependency inventory and distribution source set
when relevant. Do not assume all material in this repository is BSD-3-Clause.

Consensus, issuance, privacy and key-handling changes require focused review and
regressions; never hide such changes inside refactoring or packaging. Preserve
Tor-first routing, explicit mining consent, payment reconciliation and optional
service isolation. Synthetic tests do not establish physical-host validation or
independent security review. Follow [SECURITY.md](SECURITY.md); do not put secrets
or exploit details into public reports. No dedicated private reporting endpoint
is currently verified: arrange a private channel with the maintainer before
sharing sensitive details. No inbox or security team is implied by this guide.

Public bug reports should contain sanitized reproduction steps, version,
platform, expected/actual behavior and relevant non-sensitive evidence. Pull
requests are subject to technical/security/license review, without a centralized
developer account requirement for using the API or SDK independently.
