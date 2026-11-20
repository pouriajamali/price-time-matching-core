# 2026-11-20 - Current LTS servicing and local validation

Technology selection retains SDK 10.0.404/runtime 10.0.15/C# 14/xUnit 4.0.3, already current in preview.2. The new source-bound local verification route keeps the original matching/CLI/locks/fixtures/oracle and resource/trust guards. See [technology selection](TECHNOLOGY-20261120.md). CI is NOT_RUN per owner instruction. No changed application/runtime distributable or replacement preview.2 release is claimed.

# v0.1.0-preview.2 - Finite capacity and atomic rejection evidence

A public MIT prerelease for one synthetic instrument: deterministic price-time FIFO, resting-price trades, limit/cancel commands and rejection without ledger, sequence or trade-output effects. Twelve manually specified small-limit histories check capacity rejection/retry, full-book fills, slot reuse, lifetime IDs after fill/cancel and FIFO through rejection. Matching algorithms, CLI, matching-v1 semantics, default limits and wire framing are unchanged.

## Downloads and use

Use the [preview.2 release](https://github.com/pouriajamali/price-time-matching-core/releases/tag/v0.1.0-preview.2) for the Windows x64 ZIP, Linux x64 tar.gz and source ZIP, together with `SHA256SUMS.txt`, `SHA256SUMS.txt.sig` and `SIGNING-PUBLIC-KEY.pub`. The [README](../README.md#start-with-the-demo) contains platform commands; [provenance](../PROVENANCE.md) explains verification before execution. Use the [exact tag source](https://github.com/pouriajamali/price-time-matching-core/tree/v0.1.0-preview.2) for review or source builds; the default branch retains older implementation/history. The native archives are self-contained with .NET 10.0.15 and full runtime notices. Source pins SDK 10.0.404 and C# 14; xUnit v3 4.0.3 is test-only.

MIT covers original code; bundled upstream components retain their own licenses and complete notices. Raw signed NuGet SHA512 is distinct from normalized restore contentHash. Input admission still requires signature/chain/RFC3161 timestamp, normalized-content/member/notices, current advisory and locked offline-restore checks; no trust or dependency gate is relaxed.

## Evidence and version boundary

The already accepted baseline is [commit 2af569037bda7909503b515d766589902e7afc85](https://github.com/pouriajamali/price-time-matching-core/commit/2af569037bda7909503b515d766589902e7afc85), tree `e98b4d1b699314b74dfec7e3ef50234103afa24e`, [full run 43984534842/1](https://github.com/pouriajamali/price-time-matching-core/actions/runs/43984534842). Both Windows Server 2025 x64 and Ubuntu 24.04 x64 passed, as did aggregation. Each OS recorded 30 unit tests on .NET 10.0.15, 12 C# traces/328 engine applications, 258 independent Python applications across three modes, the 8-case/27-attempt verifier prerequisite and 7 package checks. Native extracted CLI/replay/framing/oracle/package checks were also part of that original full route.

This documentation and draft-publisher revision is later than that baseline. Its final signed tag must pass the original full two-OS [tag workflow](https://github.com/pouriajamali/price-time-matching-core/actions/workflows/verify.yml) independently; baseline receipts do not certify later bytes. The packaged `BUILD-MANIFEST.json`, exact-tag CI receipts and signed checksums identify the final source/tree/platform and archive bytes. No final-tag run ID or public-download acceptance is inferred from the baseline.

The 12 literal histories contain 60 commands/44 accepted commands. Each C# representation repeats the original and checks the rejection-erased projection; the independent Python model checks complete results and states in normal, `-O` and `PYTHONOPTIMIZE=1`. Original 1,152 application ceilings per C#/three-mode Python partition remain limits rather than observations. Finite passing traces do not prove arbitrary input correctness, benchmark performance or production suitability.

## Draft, signature and publication

The existing tag-only publisher creates a **draft prerelease** after exact-tag native verification and aggregation, retaining `--verify-tag` and the original assets/notes. It initially stages the three archives and exact pipeline checksum bytes. The established SSH key signs those checksum bytes outside CI; verification must pass for each archive with the trusted fingerprint `SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU`. Only the checksum signature and canonical public key are then added to the same draft. The complete six-asset identities and included documents are accepted before public prerelease publication and actual public-download verification. A draft, local bundle or CI artifact is not a public release; SSH provenance is not OS code signing, independent authorship or reproducible-build certification.

There is no account/market connection, multi-instrument routing, replace, market order, self-trade prevention, crash durability, venue conformance, latency improvement or financial-result claim. Historical preview.1 and its artifacts remain unchanged below.

# v0.1.0-preview.1 - Price-Time Matching Core

Published packages require exact-commit native build/test/package jobs, signed tag/checksums and actual downloadable archive verification. A prepared pipeline or local candidate is separate evidence.

Includes a deterministic one-instrument limit/cancel core, safe scan baseline and indexed alternative, independent per-command Python oracle, strict bounded JSONL adapter, user demo, Windows/Linux self-contained packages and source. No persistent book, external connection, market order, replace, self-trade prevention, venue conformance, latency improvement or profitability claim.

Final byte-framing hardening rejects a terminal bare CR without LF instead of trimming it as a line delimiter. Sixteen native regressions preserve valid LF/CRLF/final EOF forms and check multi-row and exact UTF-8 byte boundaries. The matching library, data contract and limits are unchanged; the prior local framing counterexample and red/green receipts are retained separately.

Application uses BCL only; the shipped .NET 10.0.14 runtime retains full original notices and raw signed NuGet SHA512 in SPDX 2.3, separately from normalized restore contentHash. xUnit 4.0.3 is test-only. Initial uncommitted numeric-string coercion failure is preserved privately and repaired with strict number handling before the candidate.
