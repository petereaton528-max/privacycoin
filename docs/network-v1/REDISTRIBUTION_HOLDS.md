# New substitution artifact disposition

SPHLIB_SUBSTITUTION.md/JSON supersede the four-file hold only for the exact new
source and rebuilt Linux/WSL2 artifacts from the approved substitution, now
integrated into `v1/candidate-20261011`. The post-integration artifact scope and
hashes are in `docs/evidence/network-v1-sphlib-integration-20261012/`.
The original four source byte sequences are excluded, not relicensed. The MIT
sphlib subset and independent BSD adapters are included with complete notices.
All required GNU materials remain paired. Historical archives and unchanged
Windows binaries still contain the inherited implementation and retain its holds.
Microsoft redistribution terms and Code Integrity are separate Windows issues.
No public distribution or N2 deployment is authorized.

The historical disposition below is preserved for the older artifact hashes.

---

# RC5 redistribution dispositions (2026-10-12)

Follow-up: CRYPTO_RIGHTS_AND_RUNTIME_DISPOSITION.md provides the exact four-file
history/author comparison and Windows runtime-route disposition. Its corrected
GNU_RUNTIME_COMPLIANCE.json maps the actual packaged Tor build5; the earlier
build8 map below is historical and does not prove build5 composition. The new
byte-identical build5 relink closes that correspondence defect without changing
any distributed executable. Original crypto-permission and Microsoft downstream
terms holds remain; no original author's rights have been invented.

This review continues HEAD 1182707. It does not reopen the owner's BSD decision.
The machine-readable `REDISTRIBUTION_BLOCKERS.json` lists all 351 previously
flagged files, their SHA-256, governing terms, evidence and disposition. The
existing `LICENSE_INVENTORY.json` references those results and separates package
kinds. Historical inspection archives and their blocked records remain unchanged.

## Inherited source

338 of the 351 directory-wide flags can be retained under their original terms.
The SUPERCOP Ed25519 implementation names match the author's explicit
[public-domain statement](https://ed25519.cr.yp.to/software.html). The ref10
README contains the same attribution; upstream
[issue 3942](https://github.com/monero-project/monero/issues/3942) and PR4021
identify that missing notice. Monero glue and additions retain Monero BSD,
libsodium headers retain ISC, Gladman AES retains its own source/binary terms,
and explicit public-domain notices remain intact. None is relicensed by the owner.

The historical full-source holds and current dispositions are:

| Paths under `.upstream/monero/src/crypto/` | Disposition | Consequence |
|---|---|---|
| `jh.c`, `jh.h` | Obtain an explicit grant covering Hongjun Wu's January 2011 optimized ANSI C implementation, or qualified confirmation of the existing submission permissions. | Present in full source; `jh_hash` is defined in all four Linux executables; Windows maps extract `jh.c`. Do not remove or rewrite selected cryptography as a licensing shortcut. |
| `keccak.c`, `keccak.h` | Confirm the author's MIT/public-domain grant covers this November 2011 baseline and its derived selected files. | Present in full source; `keccak`/`keccakf` defined in all four Linux executables; Windows maps extract `keccak.c`. |
| `crypto_ops_builder/api.h`, `crypto_int32.h`, `crypto_sign.h`, `crypto_uint32.h`, `crypto_verify_32.h`, `randombytes.c`, `sha512-blocks.c`, `sha512.h`, `verify.c` | Exclude from the new full-source selection and SDK subset; preserve locally. Restoring these helpers to a distribution requires tracing their copied inputs. | Old source archives remain held for these files. New source archives omit all nine. Production CMake targets compile delivered crypto-ops.c/data.c directly, and a selected-source reference check found no external generator/helper references. Original files and attribution are preserved. |

The [JH author page](https://www3.ntu.edu.sg/home/wuhj/research/jh/index.html),
round-3 ZIP (including README and cover sheet) were examined. Availability and
absence of patents do not establish an explicit copyright redistribution grant.
The [tiny_sha3 author repository](https://github.com/mjosaarinen/tiny_sha3)
has a 2015 MIT grant and describes the original 2011 work; that establishes a
promising route, not exact retrospective file coverage. Seek confirmation of
these specific implementations, not an unsupported blanket owner declaration.
No independent replacement is necessary or implemented in this licensing task.

## GNU components by artifact

| Actual component | Actual linkage/terms | Concrete requirement and current disposition |
|---|---|---|
| Old Linux/WSL2 `runtime/lib/libreadline.so.8` and `runtime/python/lib/python3.12/lib-dynload/readline.cpython-312-x86_64-linux-gnu.so` | Readline 8.2-4build1, GPL-3.0-or-later; extension dynamically links it | Old archives remain blocked: preserve GPL notices, exact Readline and affected Python source/build inputs; determine covered combination before distributing that combination. New noninteractive bundles exclude both files. All 104 ELF dependency tables were parsed; the extension is the only Readline consumer. No product code imports it. |
| `runtime/lib/libcrypt.so.1` | libxcrypt 1:4.4.36-4build1, LGPL-2.1-or-later plus retained per-file permissive terms | Exact source and distro build rules already acquired; source-pair manifest, full LGPL text, library notice and replaceable dynamic linkage retained. |
| `runtime/lib/libgcrypt.so.20` | libgcrypt20 1.10.3-2ubuntu0.2, LGPL-2.1-or-later library; GPL tools are separate | Same dynamic-library/source obligations. Its dependency is `libgpg-error.so.0`. Do not classify the library as GPL merely from a package-wide list. |
| `runtime/lib/libgpg-error.so.0` | 1.47-3build2.1, LGPL-2.1-or-later library | Same obligations; GPL utilities are not bundled as library code. |
| `runtime/lib/libseccomp.so.2` | 2.5.5-1ubuntu3.1, LGPL-2.1 library | Same obligations; source and build rules retained. |
| `runtime/lib/libsystemd.so.0` | 255.4-1ubuntu8.17, LGPL-2.1-or-later library with retained component exceptions | Same obligations. The systemd GPL executables are not bundled. Exact dependency edges and package source retained. |
| Linux `runtime/lib/libgcc_s.so.1`, `libstdc++.so.6` | GCC14 14.2.0-4ubuntu2~24.04.1, GPLv3 with GCC Runtime Library Exception 3.1 | Separate shipped runtime-library binaries retain GPL/exception notices and exact corresponding source. Eligible GCC-linked PC code is not automatically GPL. |
| Windows core's extracted `libgcc.a`, `libgcc_eh.a`, `libstdc++.a` objects; Tor/TLS helper `libgcc.a` | GCC16.2 runtime exception; independent modules built through recorded GCC commands | Preserve exception and notices. Four core maps plus two new byte-identical Tor/TLS relinks establish actual extraction. No gettext/iconv object extraction in these six binaries. The exception is not applied to arbitrary GNU libraries. |
| Source-only `external/trezor-common/` | LGPL-3.0 with retained file exceptions, disabled runtime | Retain original source/license plus GPL3/LGPL3 texts. No relinking claim for a disabled, unlinked runtime component. |

The complete library source sets and distro patches/build rules are already in
the exact paired GNU corresponding-source archive. This task did not repeat
acquisition or claim independent vendor-build reproduction. For an authorized
future download, cohost the binary and the exact hash-bound source archives with
equivalent access and no additional charge. A homepage or checksum alone is not
source delivery. Keep required access for the applicable license period.

LGPL users may replace interface-compatible shared libraries and reverse engineer
the combined application to debug those modifications. Nothing in the PC terms
prohibits that. `runtime/lib` is ordinary user-owned data in the installation;
the launcher uses `LD_LIBRARY_PATH`. Do not add runtime library hash enforcement
that prevents modification. Initial archive-integrity verification is separate.
No static LGPL combination was found in the inspected Windows extraction maps.
This is a scoped technical/license analysis, not an independent legal opinion.

## Microsoft runtime scope

Native payload contains **only two separately named Microsoft runtime DLLs**:

| File under `runtime/python/` | Version | SHA-256 |
|---|---|---|
| `vcruntime140.dll` | 14.51.36247.0 | d1f4225df2cd877dbf130d5668a021dce3f94118455ff5ec952061c30afc9ce7 |
| `vcruntime140_1.dll` | 14.51.36247.0 | a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e |

Both previously verified signatures are Valid/Microsoft. The artifact matrix lists
all 37 Python-build PE files and hashes; the retained Python LICENSE appendix
states embedded Microsoft code is present in its exe/dll/pyd files. Two DLL names
alone therefore understate scope. Windows import archives such as `libmsvcrt.a`
in GCC maps are not proof of a redistributed Microsoft OS DLL. The Tcl
`x86_64-w64-mingw32-nmakehlp.exe` is a Tcl build helper, not Microsoft `nmake.exe`;
its retained source points to the Tcl license. No MSVC compiler/debug runtime or
Microsoft redistributable installer was added by this task.

Keep the exact CPython Windows binary appendix and notices. Its downstream route
requires protective terms for distributors and end users. The Microsoft
[2026 redistribution list](https://learn.microsoft.com/en-us/visualstudio/releases/2026/redistribution)
and [Community terms](https://visualstudio.microsoft.com/license-terms/vs2026-ga-community/)
were inspected, including the actual DOCX. These are conditional on the applicable
supplier/license route; they do not independently prove owner entitlement.
The terms include downstream protection and distributor indemnity, and restrict
unreleased components and subjecting Microsoft code to excluded licenses.

**Native Windows hold:** obtain confirmation that the exact PSF-supplied binary
route permits the proposed downstream bundle, identify applicable protective
end-user/distributor terms and who undertakes any required indemnity; otherwise
use a legitimately licensed redistribution route with its matching terms.
Do not assume a VS2022 grant from the filename `140`, or silently bind the owner
to a new vendor agreement. No proposed EULA is asserted to satisfy unknown terms.
No DLLs were sourced from a machine's system directory or installed using an
unverified redistributable. The Linux/WSL2 archives contain no Windows PE runtime;
this hold does not apply to them or source-only SDK.

## First permissible source artifact

The existing Python read SDK and its original `rpc.py` dependency can be delivered
as a narrowly reviewed BSD source subset without any inherited crypto or runtime.
`SDK_SOURCE_SCOPE.md` explains the limited contents and user prerequisite. Its
hash-pinned packaging check rejects extra files and changed source. This is the
shortest source-licensing path; it is not a complete coin release. The new full source and all complete native coin binaries remain blocked by the
four selected JH/Keccak files; old source archives also retain the nine-helper
hold. Native Windows has the additional Microsoft hold.
Publication authorization remains false for every artifact.
