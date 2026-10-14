# RC1 final owner security and release decision

Date: 2026-10-14. Assessment type: zero-budget, AI-assisted INTERNAL review by the implementing agent. NOT independent, NOT a professional audit, NOT security certification.

## Decision: CONDITIONAL GO for owner release consideration

The exact RC1 below is a technically integrated, tested candidate for the owner's explicit risk decision. This assessment found no confirmed CRITICAL/HIGH exploit in the inspected paths and the bounded tests. It does not establish that none exists. Material unknowns below can include undiscovered critical defects. Missing paid-audit funding is not classified as a software defect. An independent audit is recommended, but its absence is disclosed rather than represented as a test failure or silently waived.

Publication and Mainnet activation remain NOT AUTHORIZED. No release signing key, public node, remote repository, tag or release was created. No immutable economic, network, recipient or Genesis parameter changed. No product rebuild was necessary or performed during this review. Approval of Genesis is not approval of release.

## Exact assessed release

Engineering/evidence checkpoint: b23b09c8090be129da9bdea56c2a2c2d5c361874.
Packaged source/overlay commit: 429badad910e26fcbfc2d387bd3b03a0c234917d.
The archive is an explicit, hash-verified composition of retained source/dependency artifacts plus the declared Git overlays, not a claim that every archived historical file equals a clean checkout of that commit. RELEASE.json records composition; the source ZIP is the exact review input.

Directory: out/mainnet-final-rc1-final-20261014

| Artifact | SHA-256 |
|---|---|
| privacycoin-mainnet-rc1-linux-wsl2.zip | 05333811876e579f175bcda70498130bb37983cc5aa6031f5293991e8fae4dc1 |
| privacycoin-mainnet-rc1-source.zip | aadf2b614fc6c58073c3179388811bd871bd0944020894097bdfdf81c4beeeb6 |
| privacycoin-rc5-gnu-corresponding-source-inspection.zip | 4723b07b7135d3966d6c9cd141bf47a1fca57ac03e9781c33d761c9ae4291c9d |

Native ledger: 1fd8c401ccc8cb64c13f307da0f72c6831d4b1aa9abe5c68678ca0bd21917d11.
Native node: 352e3c4eca1b49e88318e994e458b12fbf6d650de776363fa1554f4cbd81a0ca.
Native wallet: a73a93cd2d648fa13f16b78e494460ff27b4989aefcc25ef428f0b8c7e4497d2.

Canonical Genesis: 949 bytes; SHA-256 ada8aa42012556f8a045e212d94fffaec47ebccc345900216539d4cdb36a6001; native hash 6233402308514d2d979a9efa9c6bd2f9843741598f1e5b18239cde16ba0d2b54.
Identity specification: 67036217d08417ca8d996f2fd807d0a171b5d849e53fb7901225feeffddbaa04.
Recipient record: c405c6529043fa287d61eead0a6c2ad6b6a1020c9acf2e414957ec3efe643069.
Approved policy record: a398624590f31b503cdea9590c501bc54a57e269ae66d1200daf4cf0ba6bbdc2.

IDENTITY_INTEGRITY.json rechecks all three archive hashes, installed native binaries, native translation-unit receipts, explicit overlays and frozen public inputs. REVIEWED_SOURCE.json confirms the 22 inspected local source files equal the archived source bytes. Retained build receipts additionally pin policy, rules, ledger/binding headers and linked dependencies. These checks do not prove compiler or dependency integrity against a compromised build host.

## Prior audit status and reuse

The previously completed assessment was a collection of bounded reviews, not a comprehensive line-by-line cryptographic audit:

- docs/research/overnight-v1/INTERNAL_REVIEW.md: Tk/private-pipe UI review and seven corrected defect classes; not consensus/crypto review. Historical 128-attempt limitation was superseded by journal archival work.
- tools/release_closure/SECURITY_REVIEW.md: scoped threat/reviewer handoff, not an independent completed audit.
- tools/mainnet_prepare/PRODUCTION_REVIEW.md: historical production design and fee/review record; older approval/runtime statements are superseded by frozen approvals and final production implementation.
- docs/evidence/network-v1-final-production-20261014/INTERNAL_SECURITY_REVIEW.md: final-production delta review, packaging correction and explicit limitations.

Their valid findings and executed tests were reused. Historical private A/B acceptance, later ticket-free A/B 82-block/payment/reconnect acceptance and owner GUI acceptance were not rerun. This decision adds exact-RC1 source tracing and negative native proof/issuance tests; it does not relabel historical evidence as an independent audit.

## Coverage and evidence

| Area | Actual reviewed enforcement and evidence | Exclusion / residual |
|---|---|---|
| Inflation / Genesis | ledger.cpp Ledger constructor and validate: exact compiled G/bytes, 17 outputs, no non-Genesis generation inputs; amount(i)/unlock(i), separate creator and mining counters; checked fee/subsidy arithmetic in development_profile.h; frozen public input pins | Not a formal supply proof across every possible execution; real founder control is OWNER-REPORTED |
| Vesting / maturity / forks | validate_transaction checks every ring member unlock; block validation selects rules at branch height; native branch state, work selection and reload; retained actual reorg tests at tranches 1/8/16 and original-policy 87 checks | No fresh million-block final-chain run; unchanged rules justify reuse |
| RingCT / CLSAG / Bulletproofs+ | ledger.cpp validate_transaction: canonical parsing, fixed scheme/ring/proof counts, strict points, reconstruct rings/message/key image, call BOTH verRctSemanticsSimple and verRctNonSemanticsSimple; pinned upstream rctSigs.cpp sum/fee/range and CLSAG call chain inspected; actual mutated proofs rejected | Not a mathematical proof, whole upstream audit, timing/side-channel audit or privacy guarantee |
| Replay / malformed transactions | Branch key-image and transaction sets; overflow/duplicate ring checks; block-body ID matching and failed import rollback; final binary rejects malformed, corrupted and replayed examples | Selected adversarial cases, not exhaustive fuzzing; confirmed replay test uses same transaction rather than every distinct double-spend construction |
| Wallet / encrypted recovery | secrets/os.urandom; fixed Argon2id 3/64MiB and XChaCha20-Poly1305 random nonce/authenticated header; G/tag-bound recovery; secure file/no-clobber checks; backup authenticates referenced journal pages before restore; UNKNOWN blocks new payment preparation | Python copies/plaintext memory, hostile host/admin, swap/dumps, stolen passwords, hardware entropy and supply-chain compromise remain outside protection |
| Public P2P / Tor | Native P2P read-only command allowlist; profile/G/network checks; bounded frames/deadlines; one remote validation job and measured idle duty cycle; per-peer cooldown; TLS pin and signed challenge, explicit upstream SOCKS/no direct fallback; bounded peers/session/traffic | Limits do not establish fairness, worst-case single-proof latency, Sybil/eclipse immunity or public-load resilience |
| Production separation | Exact frozen binding/profile; native G pinned before ledger creation; wallet builders require final G; address/recovery/storage/P2P all use committed context | Retained DRAFT and privacycoin-devnet envelope labels are compatibility strings; isolation comes from authenticated kind/tag/G, not their display text |
| Release integrity | Binary/source/GNU archives, installed hashes, reviewed source equality, source/dependency receipts; retained duplicate native builds and ZIP reproducibility | Same environment/cache reproducibility, not an independently bootstrapped toolchain; no signature yet |

## Findings and disposition

### Confirmed CRITICAL/HIGH findings

None established by this assessment. This means none found/reproduced within the stated coverage, not a claim that all critical paths are proven safe. There is no new confirmed release-critical defect requiring an RC1 rebuild in this session.

### Resolved findings retained

- Initial finalization package omitted GenesisAddress from an older base archive; fixed in 6ff78ed, absent from the exact assessed RC1.
- Final approval JSON byte pin/working-tree encoding mismatch corrected before RC1 in 429badad; exact Genesis/specification unchanged.
- Previously fixed GUI backup permissions, restart preflight/socket lifecycle and reconnect defects retain owner/native evidence; no repeated acceptance requested.
- Diagnostic-only launcher invocation omitted its library environment; actual launcher environment passed three cycles. This was not an RC1 defect.

### Noncritical findings and material UNKNOWN risks (not waived)

1. MEDIUM availability/resource limitation: ledger cleanup_pool removes expired pool entries but retains their uncommitted transaction bodies/staging entries until confirmation or process reload. Staging has an 8192-entry cap, so retention is finite (at most roughly 409.6 MB raw bodies plus overhead), but a prolonged unconfirmed workload can consume that capacity and reject new imports. Source path is confirmed; sustained remote exploitation and real-time exhaustion were not reproduced. Fees are not paid for never-confirmed valid transactions. This is not an inflation bypass. Do not advertise indefinite unattended hostile-load resilience. Normal quiescent node restart/reload preserves committed chain and persisted eligible pool, but is an operational mitigation, not a code fix. Reclassify and stop release if realistic testing establishes a cheaply repeatable high-impact remote attack.
2. PRIVACY UNKNOWN: wallet decoys are uniformly sampled from eligible outputs in phase4/wallet.py, not a demonstrated production spend-age model. Early sparse activity, known founder/coinbase amounts, timing, change and decoy correlations can reduce anonymity. Ring size 16 does not prove sixteen equally plausible spenders. No quantified anonymity guarantee is supportable. No new sampler or immutable cryptographic change is introduced here.
3. NETWORK UNKNOWN: cheap fresh identities, finite peer slots, shared native request serialization and long-chain inventory work may still permit censorship, eclipse or resource exhaustion. Invalid proofs cost no paid fee. Rate limits mitigate specific paths but do not certify an Internet-scale adversary model.
4. CRYPTO/CONSENSUS UNKNOWN: no independent proof-system integration audit, extended sanitizer/fuzz campaign, formal verification or independent compiler rebuild. Hidden parsing, integer, concurrency or dependency flaws could be critical. The fixed transaction nonce is a public domain marker; native transaction construction retains independent randomness.
5. WALLET/OPERATIONS: loopback RPC trusts the local host and is not authenticated against hostile local processes. Do not expose RPC or share an unlocked wallet host with untrusted software. UNKNOWN transactions must be reconciled, never blindly retried. Backups from before a payment cannot know its later journal. Multi-file recovery is not an atomic filesystem transaction; preserve original backup and use a fresh destination after an interruption.
6. CUSTODY: founder's two restored backups and 17-output proofs are OWNER-REPORTED; both backups are on one physical computer. Physical disaster independence remains unverified and risk was explicitly accepted. No custody files were inspected.
7. RELEASE: unsigned distribution, trust bootstrap for signing fingerprints, seed availability/diversity and incident response are operational prerequisites. Native Windows is unsupported; supported platforms are Linux x86-64 and Ubuntu WSL2/WSLg. No profitability, market value or privacy certification is promised.

These are disclosed constraints/unknowns, not an automatic paid-audit veto. The owner must explicitly accept the stated risk envelope or defer release. Any subsequently confirmed CRITICAL/HIGH finding invalidates this conditional recommendation until fixed and retested; disclosure alone does not fix it.

## Executed results

New focused fixture: tools/mainnet_prepare/review_rc1_negative.py against the unchanged installed RC1. NEGATIVE.json: 25 checks PASS, zero failed/skipped, 9.750 seconds. Includes three binary identity checks, valid-proof positive control, 14 transaction mutation/format rejections, inflated coinbase rejection, unchanged canonical supply after rejection, duplicate pool/replay rejection, creator counter, incorrect backup password and preserved original disposable wallet. All owned native pipes closed. No external socket, Tor activation, founder custody or previous profile used.

Retained exact-installed RC1 evidence: 72 focused tests PASS; 16 native wallet/GUI/mining/sync/recovery checks PASS (33.887 s); six real TLS/local SOCKS checks PASS (1.020 s); three normal GUI launch/close cycles PASS (3.131 s). They were not rerun. Earlier failed intermediate artifacts remain preserved and are not counted as passing final RC1.

A later archive-only verification could not start the WSL dispatcher (Wsl/CallMsi/Install/ERROR_NOT_FOUND). The native test had already exited 0 with its report. Windows ZIP/hash APIs completed the remaining header checks, all PASS. This environment error was not reproduced as a client defect; no WSL/system repair or service restart was attempted. Current launcher availability was not retested after that dispatcher error.

The new negative fixture mines only its fresh local disposable chain to supply valid proof inputs. It never creates another Genesis or uses a founder wallet. No claim of a new external Tor or physical test is made.

## Public disclosure: publish verbatim alongside binaries

Privacy Coin is a new cryptocurrency. Its current security review is AI-assisted and internal only. No independent third-party professional security audit has occurred. Internal tests and owner acceptance cover selected functional and failure cases; they do not establish cryptographic soundness, anonymity, absence of inflation bugs, resistance to hostile networks, or safety of funds. Material risks include loss or theft of funds, privacy loss, consensus or software failures, network disruption, compromised devices/dependencies and backup failure. The early network has limited activity and hash power; no market value or mining profitability is guaranteed. The transparent one-time creator allocation and vesting are documented in the approved Genesis and policy. Users must review the release decision and known limitations, verify signed hashes, protect recovery material and avoid risking funds they cannot afford to lose. No official launch has occurred merely because this candidate and disclosure exist.

## Exact owner-gated publication and activation sequence (NOT EXECUTED)

1. Owner explicitly accepts or declines the residual risks and approves exact RC1 hashes. Approve release-signing-key creation/use, public repository/release publication and Mainnet activation separately. No renewed economic/identity/Genesis approval is needed.
2. Owner selects an independently controlled release-signing key (never a wallet key). Only after authorization, sign the unchanged SHA256SUMS using an owner-only key environment; the agent must not inspect its private key. Example with an already approved key:

   gpg --local-user "$APPROVED_RELEASE_FINGERPRINT" --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
   gpg --export "$APPROVED_RELEASE_FINGERPRINT" > release-signing-public.gpg
   gpg --show-keys --with-fingerprint release-signing-public.gpg
   gpgv --keyring ./release-signing-public.gpg SHA256SUMS.asc SHA256SUMS
   sha256sum --check SHA256SUMS

   Publish the full fingerprint through an independently authenticated channel. A key shipped beside an archive does not independently authenticate that archive. No key generation command has been executed.
3. From a NEW empty publication directory only, extract the reviewed source ZIP (or use the retained allowlisted public-source-staging), add this decision/disclosure and SHA256SUMS/signature/public signing key, and review the staged file list for custody/runtime data. Never publish the authoritative dirty worktree wholesale. Record source provenance 429badad plus exact base/overlay receipts. Initialize that new repository, explicitly stage its reviewed source/materials, commit with owner identity, add the owner-selected GitHub URL, and push only after explicit publication approval. Suggested command sequence (placeholders must be resolved by owner):

   git init --initial-branch main
   git add --pathspec-from-file ../reviewed-public-paths.txt
   git diff --cached --name-only
   git -c user.name=petereaton528-max -c user.email=petereaton528@gmail.com commit -m "Privacy Coin Mainnet V1 reviewed RC1 source"
   git remote add origin "$OWNER_APPROVED_PUBLIC_REPOSITORY_URL"
   git push -u origin main

   reviewed-public-paths.txt must contain the individually reviewed extracted source paths, not private directories. Do not run these commands in the original N2 or authoritative development repository. Do not fabricate a signed tag without approved signing authority. The publication commit will differ from the archived engineering commit; retain both provenance records.
4. Create the owner-approved GitHub release/tag and upload binary ZIP, exact source ZIP, GNU corresponding-source ZIP, SHA256SUMS, detached signature, public signing key, this decision and disclosure together. Use RELEASE.json for hashes/version/provenance; do not label the release independently audited. Review source availability and license notices before making it public. No gh release/push command is run by this assessment.
5. On a supported trusted host, verify signature/fingerprint and hashes, follow RC1 README installation, and launch ./Launch-PC.sh. Installation/ordinary launch does not activate Tor or mining. Use a fresh ordinary wallet/profile; never experiment on founder custody. Founder client migration remains owner-operated under the existing separate offline procedure.
6. Only after explicit Mainnet activation authorization, owner configures their verified SOCKS5 endpoint and intended public pcnode seeds in the GUI, clicks Connect Tor, checks approved G/network and authenticated peer status, then deliberately starts bounded mining. Public descriptors assist discovery; they are not an admission authority. Never expose the local RPC port. No service installation, background auto-start or public endpoint is authorized here.
7. Publish verified public seed descriptors and the supported installation guide. Confirm actual authenticated connectivity and canonical progress before inviting real-value use; Tor bootstrap alone is insufficient. Monitor errors, resources and canonical disagreement. Stop affected owned public services on a real integrity failure, preserve evidence and do not replay uncertain payments. No automatic founder distribution or real-value transfer is part of activation.

The next owner action is ONE explicit decision accepting or declining this hash-bound RC1 and disclosed residual risks. Signing/publication/activation still require the corresponding explicit authorizations. This closes the requested bounded internal assessment; no new feature or acceptance programme is proposed.
