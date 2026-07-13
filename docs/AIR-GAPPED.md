# Air-gapped verification

`@usehasp/verify` reaches the network for two things: fetching the tenant's published key from `/trust/keys/{tenant_id}` and fetching the TSA CA certificate from `tsa_cacert_url`. Both can be supplied from disk (`--key-file`, `--ca-file`) for fully offline operation. Everything else — schema, hash chain, published-key match, Ed25519 signatures — runs locally. This page covers two scenarios:

1. **Verify offline, today.** Useful inside an air-gapped network or when the TSA host is briefly unreachable.
2. **Verify offline, years from now.** Long-term archival in case `tsa_cacert_url` 404s before you need to re-verify.

## What to archive at export time

Snapshot these alongside the export so a verifier in 2034 can still get `VERIFIED`:

- `export.json` — the export itself.
- `published-key.pem` — the tenant's published signing key. Fetch `/trust/keys/{tenant_id}` at export time and save the matching `keys[].public_key_pem` to a PEM file.
- `tsa-cacert.pem` — the CA cert at `verification.tsa_anchor_chain[*].tsa_cacert_url`. Download with `curl -o tsa-cacert.pem <url>` at export time.
- A pinned copy of `@usehasp/verify` at the version that produced `VERIFIED` — either the npm tarball (`npm pack @usehasp/verify@<version>`) or a tagged git clone.
- (Optional) The SHA-256 of `@usehasp/verify`'s tarball, recorded against the [GitHub release notes](https://github.com/UseHasp/verify/releases), so future you can prove the verifier itself wasn't swapped.

Bundle into a tarball and stash with the export.

## Scenario 1 — verify with no network, keep all four checks

You have the export, the published-key PEM, the CA cert PEM, and `hasp-verify` on PATH (or in `node_modules`):

```bash
hasp-verify export.json --key-file ./published-key.pem --ca-file ./tsa-cacert.pem
```

The verifier reads the published key and the CA cert from disk, skips both fetches entirely, and runs `openssl ts -verify` exactly as it would online. All five checks (schema, chain, published-key, signature, TSA) run.

This is the recommended air-gapped path. It preserves the TSA anchor's trust property — proof that the chain head existed at the timestamped instant — without needing network access.

## Scenario 2 — verify with no network and no CA cert

If you have only the export and the published key, you can still re-run everything except the TSA anchor:

```bash
hasp-verify export.json --key-file ./published-key.pem --skip-tsa
```

This proves:

- the export has the expected shape (schema check),
- no entry was added, removed, or mutated after signing (chain check),
- the embedded key matches the tenant's published key (published-key check),
- each entry was signed by the holder of that key (signature check).

Without the published key, verification cannot establish a trust root and fails closed — archive `published-key.pem` alongside the export.

It does **not** prove when the chain was created — that's what the TSA anchor adds. The TSR bytes are still present in the export (`verification.tsa_anchor_chain[i].tsa_tsr_base64`); you can verify them later when a CA cert becomes available again.

## Verifying the verifier itself

If you cached the npm tarball:

```bash
shasum -a 256 usehasp-verify-<version>.tgz
# Compare against the SHA-256 in https://github.com/UseHasp/verify/releases/tag/v<version>
```

If you have network at verification time but not at the original export time, also run `npm audit signatures` and `gh attestation verify` (see [docs/TRUST.md](./TRUST.md)).

## What to do if `--ca-file` fails

If `openssl ts -verify` rejects a cert you archived years ago, the most likely cause is cert expiry. Re-download from the original `tsa_cacert_url` if it's still resolvable, or — if the TSA itself has been retired — fall back to `--skip-tsa` and document the gap. The chain + signature checks are independent of the TSA and remain trustworthy.
