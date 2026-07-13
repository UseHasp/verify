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
- **Small.** Under ~400 LOC of source — readable in one sitting by a reviewer.
- **Standard primitives only.** Node `crypto` (SHA-256, Ed25519) and `openssl ts -verify`. No bundled crypto. No native deps.
- **No telemetry.** The tool touches the network for two things only: fetching the tenant's published key (`/trust/keys/{tenant_id}`) and the TSA CA cert (URL visible in the export). Each fetch is capped at 15 s and 1 MB. `--key-file` and `--ca-file` (and/or `--skip-tsa`) make it fully offline.
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
| Forged entry inserted into export | Per-entry Ed25519 signature must verify against the tenant's independently-published key. |
| Entry mutated after signing | Hash chain breaks; the recomputed `hash` no longer matches, and `chain_head_hash` no longer matches. |
| Entry deleted from middle of export | `prev_hash` linkage breaks (the surviving neighbours no longer chain) **and** `chain_head_hash` mismatches. |
| Entire export re-signed with an attacker's key | The embedded `public_key_pem` is checked against the tenant's independently-published key at `/trust/keys/{tenant_id}`; a substituted key fails the published-key match and verification stops before signatures are trusted. |
| Attacker also swaps the published key | The published key lives on a source the attacker does not control; substitution is detectable against it. Only public keys are ever published. |
| Malicious `tsa_cacert_url` in export | Schema enforces `https:`; fetch is capped at 15 s and 1 MB; `--skip-tsa` skips the fetch entirely. |
| Compromised verifier on auditor's machine | Out of scope — re-run the manual recipe. |
| Compromised npm tarball | Provenance + Sigstore attestation; verify with `npm audit signatures` or `gh attestation verify`. |

See [SECURITY.md](../SECURITY.md) for the disclosure policy and known limitations. Field-by-field schema reference: [SCHEMA.md](./SCHEMA.md). Air-gapped verification cookbook: [AIR-GAPPED.md](./AIR-GAPPED.md).
