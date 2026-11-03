# Trust posture — `@usehasp/verify`

This document covers the trust properties of **this repository and npm package**. For the full story of how Hasp audit exports are signed, anchored, and verified — including the manual recipe — see the authoritative source:

> **Hasp Trust Center:** <https://usehasp.com/trust>
> **Manual verification recipe:** <https://usehasp.com/trust/verify>

If anything in this file contradicts the Trust Center, the Trust Center wins.

## Why this tool exists

A signed audit export is only as trustworthy as the verifier that checks it. We do not want auditors to trust Hasp's word that an export is valid — we want them to verify it themselves, using primitives they already trust.

This package is a thin, readable convenience layer over the manual Python + `openssl` recipe at <https://usehasp.com/trust/verify>. The recipe is authoritative; the tool is a convenience.

If the tool ever produces a different verdict than the manual recipe on the same input, [open a P0 issue](https://github.com/UseHasp/verify/issues). The tool is wrong, not the recipe.

## Properties

- **Open source.** MIT, public on GitHub, no obfuscation.
- **Small where it matters.** The cryptographic primitives — `merkle.js`, `fold.js`, `canonical.js`, `checks/chain.js`, `checks/signature.js` — are 314 lines, readable in one sitting by a reviewer. That's the smallest reviewable core, not the entire trust boundary: `checks/published-key.js` establishes the key the signature check verifies against and is equally trust-critical, just larger (network I/O, key-rotation handling). `src/` totals 2,337 lines; beyond published-key resolution, the rest is schema validation, CLI ergonomics, and the v1.1 customer-segment envelope variant. See [README.md](../README.md) → "Auditable" for the file-by-file breakdown and the CI check that keeps both numbers honest.
- **Standard primitives only.** Node `crypto` (SHA-256, Ed25519) and `openssl ts -verify`. No bundled crypto beyond the pinned FreeTSA trust-root certificate (see below). No native deps.
- **Minimal, deliberate network reach.** By default the tool makes exactly one network call: the published-key check fetches the tenant's signing key from `/trust/keys/{tenant_id}` — an independent trust root, not telemetry. `--keys-file` reads it from disk instead. The TSA anchor check does not reach the network by default (it trusts a CA cert bundled with the tool); `--allow-untrusted-tsa` is an explicit opt-in to fetch the CA cert URL embedded in the export instead. Any network call the tool makes is capped at 15 s and 1 MB. No analytics, no error reporting, no update checks.
- **Reproducible.** Same input always produces the same output. No build step on the auditor's machine — the npm tarball contains the exact JS source.
- **Source-only npm package.** No prebuilt binaries. The published tarball is the same JS files you see in `src/`, plus `README.md`, `LICENSE`, `SECURITY.md`, `CHANGELOG.md`, and this trust document.
- **npm provenance + Sigstore attestation.** Every release links back to the exact GitHub commit and workflow run. Verify with `npm audit signatures` or `gh attestation verify`.

## Verifying you have the real package

```bash
npm pack @usehasp/verify
shasum -a 256 usehasp-verify-*.tgz
# Compare to the SHA-256 in the GitHub release notes at
# https://github.com/UseHasp/verify/releases

npm audit signatures
gh attestation verify usehasp-verify-*.tgz --repo UseHasp/verify
```

## Cross-checking against the manual recipe

The verifier is functionally equivalent to the recipe at <https://usehasp.com/trust/verify>. Both should produce VERIFIED on the same input.

```bash
# tool
npx @usehasp/verify export.json

# manual recipe — follow the steps at /trust/verify
```

If the verdicts disagree, the manual recipe is authoritative. File an issue with the export that triggered the disagreement (redact tenant data if needed — the failure is reproducible from the signature/chain/anchor fields alone).

## Threat model summary

| Threat | Mitigation |
|--------|------------|
| Forged entry inserted into export | Per-entry Ed25519 signature must verify against the published key. |
| Entry mutated after signing | Hash chain breaks; `chain_head_hash` no longer matches. |
| Entry deleted from middle of export | `seq` becomes non-contiguous (schema check) **and** chain breaks. |
| Entire export forged (wrong signing key) | Per-entry signatures fail against the independently-published key (published-key + signature checks); a genuine TSA anchor from another export can't be reused because the anchoring check binds `anchored_data` to THIS export's entries. |
| Already-anchored entry rewritten and re-signed by an attacker with signing-key access | Closed by a **v2** (`sha256-fold-v2`) anchor: it commits to a fold over the entire prefix, so rewriting any covered entry — even with a valid re-signature — breaks the fold recomputation (anchoring check). A **v1** (`row-hash-v1`) anchor only attests the one row it names; entries it doesn't cover are signature-protected only, until the next anchor. |
| Fabricated `fold_base` presented to smuggle a truncated or rewritten history past a v2 anchor | The fold's collision resistance closes this: for a fixed, already-issued token (`anchored_data`), no fabricated base state — nor any tampered, reordered, or thinned set of retained entries — can reproduce the anchored fold without inverting SHA-256. `fold_base` is an untrusted hint; a successful binding is evidence regardless of its origin. The fail-closed property is anchor binding itself: a truncation not backed by the true purged-prefix fold state — whether it declares a fabricated `fold_base` or none at all — leaves every v2 anchor unable to bind (fold mismatch). A *legitimate* retention rebase is additionally visible in the export: `fold_base` is present and the entry set starts at the retention boundary. |
| Operator with DB + TSA access truncates a prefix, then re-anchors a fresh lineage to present a clean-looking export | The platform cannot cryptographically tell a lawful deletion from a malicious one, so it does not try to hide either. A prefix removed outside retention maintenance is detected at the next purge, which raises an internal tamper alert **and** stamps `verification.lineage_reset_at` on every subsequent export; the verifier prints a loud `CHAIN LINEAGE WAS RESET` warning. A re-anchored, re-rooted export therefore can never read as a pristine full history — it advertises the reset. What an operator with live TSA access can still do is attest the *retained* (post-reset) rows; what they cannot do is make the reset invisible or forge attestation for the removed history. Auditors holding a prior export additionally detect the shrink directly. |
| Attacker mints their own TSA and points `tsa_cacert_url` at a CA they control (trust-root circularity) | Closed by default: the TSA check trusts only the CA certs **bundled with the tool** (`roots/` — currently FreeTSA), never `tsa_cacert_url`, unless `--allow-untrusted-tsa` is passed explicitly — the export cannot nominate its own trust root. Schema additionally enforces `https:` on the field; when a fetch does happen (`--allow-untrusted-tsa`) it is capped at 15 s and 1 MB. |
| Backdated TSA token (timestamp claims an earlier time than the data it attests) | Each token's `genTime` is parsed and compared to the newest entry the anchor is bound to; a `genTime` that predates it beyond a small clock-skew allowance fails the check as backdated. |
| Signing key leaks; attacker forges entries after the fact under the compromised key | The org revokes the key. Every entry the verifier resolves to that key then fails the key-revocation check UNLESS an already-issued TSA anchor's `genTime` proves the signature predates `revoked_at` — a forgery minted after the compromise (and thus after revocation) can never satisfy that, since a covering anchor for it would have to be minted before the compromise it postdates. |
| Compromised verifier on auditor's machine | Out of scope — re-run the manual recipe. |
| Compromised npm tarball | Provenance + Sigstore attestation; verify with `npm audit signatures` or `gh attestation verify`. |

See [SECURITY.md](../SECURITY.md) for the disclosure policy and known limitations. Field-by-field schema reference: [SCHEMA.md](./SCHEMA.md). Air-gapped verification cookbook: [AIR-GAPPED.md](./AIR-GAPPED.md).
