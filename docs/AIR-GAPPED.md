# Air-gapped verification

`@usehasp/verify` reaches the network for exactly one thing: fetching the TSA CA certificate from `tsa_cacert_url`. Everything else — schema, hash chain, Ed25519 signatures — runs locally. This page covers two scenarios:

1. **Verify offline, today.** Useful inside an air-gapped network or when the TSA host is briefly unreachable.
2. **Verify offline, years from now.** Long-term archival in case `tsa_cacert_url` 404s before you need to re-verify.

## What to archive at export time

Snapshot these alongside the export so a verifier in 2034 can still get `VERIFIED`:

- `export.json` — the export itself.
- `tsa-cacert.pem` — the CA cert at `verification.tsa_anchor_chain[*].tsa_cacert_url`. Download with `curl -o tsa-cacert.pem <url>` at export time.
- A pinned copy of `@usehasp/verify` at the version that produced `VERIFIED` — either the npm tarball (`npm pack @usehasp/verify@<version>`) or a tagged git clone.
- (Optional) The SHA-256 of `@usehasp/verify`'s tarball, recorded against the [GitHub release notes](https://github.com/UseHasp/verify/releases), so future you can prove the verifier itself wasn't swapped.

Bundle into a tarball and stash with the export.

## Scenario 1 — verify with no network, keep all four checks

You have the export, the CA cert PEM, and `hasp-verify` on PATH (or in `node_modules`):

```bash
hasp-verify export.json --ca-file ./tsa-cacert.pem
```

The verifier reads the cert from disk, skips the fetch entirely, and runs `openssl ts -verify` exactly as it would online. All four checks (schema, chain, signature, TSA) run.

This is the recommended air-gapped path. It preserves the TSA anchor's trust property — proof that the chain head existed at the timestamped instant — without needing network access.

## Scenario 2 — verify with no network and no CA cert

If you have only the export, you can still re-run the first three checks:

```bash
hasp-verify export.json --skip-tsa
```

This proves:

- the export has the expected shape (schema check),
- no entry was added, removed, or mutated after signing (chain check),
- each entry was signed by the holder of the published key (signature check).

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
