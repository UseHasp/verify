# Air-gapped verification

`@usehasp/verify` reaches the network for one thing by default: fetching the tenant's independently-published signing key from `/trust/keys/{tenant_id}`. It has an offline override (`--keys-file`). The TSA anchor check does **not** reach the network by default — it trusts the CA certs bundled with the tool (`roots/` — currently FreeTSA, production HASP's default TSA) rather than fetching `tsa_cacert_url` from the export. Everything else — schema, hash chain, Ed25519 signatures — runs locally. This page covers two scenarios:

1. **Verify offline, today.** Useful inside an air-gapped network with no route to `/trust/keys`.
2. **Verify offline, years from now.** Long-term archival in case `/trust/keys/{tenant_id}` 404s before you need to re-verify, or the bundled TSA root has since been rotated.

## What to archive at export time

Snapshot these alongside the export so a verifier in 2034 can still get `VERIFIED`:

- `export.json` — the export itself.
- `audit-keys.json` — the tenant's published keys document from `https://app.usehasp.com/trust/keys/{tenant_id}`. (The platform's `/.well-known/audit-keys.json` is only a discovery pointer to that endpoint, not the keys themselves.) This is the independent trust anchor for the signing key; archive it so the published-key check can run offline.
- A pinned copy of `@usehasp/verify` at the version that produced `VERIFIED` — either the npm tarball (`npm pack @usehasp/verify@<version>`) or a tagged git clone. This carries its own TSA trust root (`roots/freetsa-cacert.pem`, valid until 2041), so archiving the CA cert separately is not required for the default path.
- (Optional) The CA cert at `verification.tsa_anchor_chain[*].tsa_cacert_url`, downloaded with `curl -o tsa-cacert.pem <url>` at export time — only needed if you plan to verify with `--ca-file` against an independently-obtained cert rather than the tool's bundled one, or if the export was anchored by a TSA other than the one bundled.
- (Optional) The SHA-256 of `@usehasp/verify`'s tarball, recorded against the [GitHub release notes](https://github.com/UseHasp/verify/releases), so future you can prove the verifier itself wasn't swapped.

Bundle into a tarball and stash with the export.

## Scenario 1 — verify with no network, keep all seven checks

You have the export, the published-keys doc, and `hasp-verify` on PATH (or in `node_modules`):

```bash
hasp-verify export.json --keys-file ./audit-keys.json
```

The verifier resolves the signing key's trust root — including its revocation status, if any — from the archived keys doc (no fetch) and the TSA check verifies against its bundled trust roots (no fetch), running `openssl ts -verify` exactly as it would with a freshly-downloaded cert. All seven checks (schema, chain, published-key, signature, anchoring, TSA, key-revocation) run, fully offline, with no extra flags.

This is the recommended air-gapped path. It preserves the independent-key trust property, the anchoring check's binding of each anchor to this export's history (v1: a row's hash; v2: a recomputable [history fold](../README.md#the-history-fold-sha256-fold-v2) from the export's fold base — `verification.fold_base`, or genesis when absent — see [docs/SCHEMA.md](./SCHEMA.md)), and the TSA anchor's trust property — proof that the anchored value existed at the timestamped instant, verified against a CA this tool trusts independently of the export.

If you archived a separately-obtained CA cert instead of relying on the bundled root, pass `--ca-file ./tsa-cacert.pem` in place of relying on the default.

## Scenario 2 — verify with no network and no OpenSSL

If you have the export and the published-keys doc but no `openssl` binary, you can still re-run the first six checks:

```bash
hasp-verify export.json --keys-file ./audit-keys.json --skip-tsa
```

This proves:

- the export has the expected shape (schema check),
- no entry was added, removed, or mutated after signing (chain check),
- the embedded signing key matches the independently-published key (published-key check),
- each entry was signed by the holder of the published key (signature check),
- every anchor is bound to this export's history — a v2 anchor's fold recomputes correctly, or a v1 anchor's row is present (anchoring check; runs regardless of `--skip-tsa` — it's pure computation, no I/O),
- no entry is signed under a key published as revoked without a covering anchor already proving it predates the revocation (key-revocation check) — though without TSA data this check can only pass on unrevoked keys; a revoked-key entry fails closed here since there is no anchor `genTime` available to prove it predates the compromise.

It does **not** prove *when* the chain was created — that's what the TSA anchor adds. The TSR bytes are still present in the export (`verification.tsa_anchor_chain[i].tsa_tsr_base64`); you can verify them later once `openssl` is available.

If the export has zero anchors and you still want to review it, pass `--allow-unanchored` to accept it as a pass-with-warning (`attested: none`) instead of failing the anchoring check — use this only when you're deliberately reviewing an unattested export, not as a routine bypass.

## Verifying the verifier itself

If you cached the npm tarball:

```bash
shasum -a 256 usehasp-verify-<version>.tgz
# Compare against the SHA-256 in https://github.com/UseHasp/verify/releases/tag/v<version>
```

If you have network at verification time but not at the original export time, also run `npm audit signatures` and `gh attestation verify` (see [docs/TRUST.md](./TRUST.md)).

## What to do if the TSA check fails against an old export

If `openssl ts -verify` rejects the bundled root (or a cert you archived with `--ca-file`) against an export minted years ago, the most likely cause is cert expiry or a TSA CA rotation the pinned tool version predates. Try a newer `@usehasp/verify` release (its bundled root may have been refreshed), or re-download the CA cert from the original `tsa_cacert_url` and pass it via `--ca-file` if it's still resolvable. If the TSA itself has been retired entirely, fall back to `--skip-tsa` and document the gap. The chain, signature, and anchoring checks are independent of the TSA and remain trustworthy — you still get proof the anchor is bound to this export's history, just not proof of *when*.
