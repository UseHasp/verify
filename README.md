<p align="center">
  <img src="https://assets.usehasp.com/GitHubReadmeHero.webp" alt="@usehasp/verify" />
</p>

<h1 align="center">@usehasp/verify</h1>

<p align="center">
  <em>Offline verifier for HASP signed audit exports. Zero telemetry. Standard primitives only.</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@usehasp/verify"><img src="https://img.shields.io/npm/v/@usehasp/verify?color=cb3837&label=npm" alt="npm version" /></a>
  <a href="https://github.com/UseHasp/verify/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/UseHasp/verify/test.yml?branch=main&label=CI" alt="CI status" /></a>
  <a href="https://docs.npmjs.com/generating-provenance-statements"><img src="https://img.shields.io/badge/npm-provenance-blue" alt="npm provenance" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license" /></a>
  <img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen" alt="Node >=20" />
</p>

---

**For auditors, compliance reviewers, and customers who want to verify HASP audit exports for themselves.**

HASP signs every audit-log entry with an Ed25519 key — published independently at a well-known URL — and chains them with SHA-256, then anchors the chain's history with RFC 3161 timestamps from an independent TSA. This tool re-runs those seven checks on an export so you don't have to trust HASP's word for it. The same checks can be run by hand from the [manual recipe](https://usehasp.com/trust/verify) — this tool is a convenience, not a trust anchor.

- **One default network call, by design.** The published-key check fetches the tenant's independently-published signing key from `/trust/keys/{tenant_id}` — that fetch is the point, not a leak: it's how the tool avoids trusting the key embedded in the export. Pass `--keys-file` to read that document from disk instead. The TSA anchor check does **not** reach the network by default — it verifies against a bundled FreeTSA root cert — so a fully offline run needs only `--keys-file`.
<!-- verify:loc core=314 total=2595 -->
- **Auditable.** The cryptographic primitives — [`merkle.js`](src/merkle.js), [`fold.js`](src/fold.js), [`canonical.js`](src/canonical.js), [`checks/chain.js`](src/checks/chain.js), and [`checks/signature.js`](src/checks/signature.js): the hash chain, the history fold, and the Ed25519 signature math — are 314 lines of plain JS over Node `crypto`. Start there; it's "read it in one sitting." That's not the *whole* trust boundary, though: [`checks/published-key.js`](src/checks/published-key.js) establishes the key the signature check verifies against — get that wrong and every signature check passes against a forged key — so it belongs on the same reading list, just not in this line count. The rest of `src/` (2,595 lines total) is that published-key resolution plus schema validation, CLI ergonomics, the v1.1 customer-segment envelope variant, and signing-key revocation ([`checks/key-revocation.js`](src/checks/key-revocation.js)) — real functionality, not padding. A CI check (`scripts/check-readme-loc.mjs`, run from the monorepo's `ci-verify.yml`) pins both numbers to the measured source so this claim can't go stale again.
- **Reproducible.** npm provenance + Sigstore attestation on every release. Same input → same verdict, forever.

<details>
<summary><strong>Table of contents</strong></summary>

- [Quickstart](#quickstart)
- [Install](#install)
- [Requirements](#requirements)
- [Usage](#usage)
- [What it checks](#what-it-checks)
- [Programmatic use](#programmatic-use)
- [Versioning &amp; support](#versioning--support)
- [Trust &amp; provenance](#trust--provenance)
- [FAQ](#faq)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

</details>

## Quickstart

```bash
# Grab a sample export and its co-published keys, then verify. Requires Node 20+ and openssl.
curl -O https://usehasp.com/trust/audit-export-sample.json
curl -o audit-keys.json https://usehasp.com/.well-known/audit-keys.json
# The sample's tenant is a throwaway with no live /trust/keys endpoint, so the
# published-key check reads its trust root from the downloaded keys doc.
# A real export from your org needs no --keys-file — its key is fetched live.
npx @usehasp/verify audit-export-sample.json --keys-file audit-keys.json
```

Expected output:

```
✓ schema valid
✓ chain intact (4 / 4 entries)
✓ published key matches (key_id …)
✓ signatures verified (4 / 4)
✓ time-attested
  — entries 1..4 time-attested (history commitment)
✓ TSA anchor valid
  — https://freetsa.org/tsr (genTime 2026-08-02T19:52:03.000Z)

VERIFIED.
```

If any check fails, the tool exits non-zero and prints which one and why. For example, a tampered chain looks like:

```
✓ schema valid
✗ chain broken at seq=2: computed <a>, declared <b>

FAILED.
```

Exit code is `1`. The failing check is named with the entry seq; checks that passed are still shown so you can see how far verification got.

This tool is a convenience layer over the manual recipe published at the [Hasp Trust Center](https://usehasp.com/trust/verify). If the tool ever disagrees with the manual recipe, the manual recipe wins — open an issue.

## Install

No install needed if you have Node 20+ and `npx`:

```bash
npx @usehasp/verify export.json
```

Or install globally:

```bash
npm install -g @usehasp/verify
hasp-verify export.json
```

## Requirements

- **Node.js 20+** (uses built-in `node:crypto` Ed25519, no native deps).
- **OpenSSL 1.1+** on `PATH` (used only for `openssl ts -verify` / `openssl ts -reply` — RFC 3161 TSA anchor check). Skip with `--skip-tsa` if you don't have it.
- **Network** to fetch the tenant's published signing key from `/trust/keys/{tenant_id}` (the trust root the published-key check resolves independently of the export). Pass `--keys-file <path>` to read that document from disk instead. The TSA anchor check does **not** need network by default — it verifies against a bundled FreeTSA root cert — so `--keys-file` alone is enough for fully offline operation.

> **macOS LibreSSL caveat.** macOS ships LibreSSL by default and `openssl ts -verify` behaves differently from OpenSSL. Install OpenSSL 3 via Homebrew (`brew install openssl@3`) and put it first on `PATH`, or pass `--skip-tsa`.

macOS:

```bash
brew install node openssl@3
```

Debian / Ubuntu:

```bash
sudo apt-get install nodejs openssl
```

## Usage

```
hasp-verify <export.json | -> [options]

Options:
  --json             Emit machine-readable JSON instead of a human report.
  --skip-tsa         Skip the RFC 3161 TSA anchor check (offline mode).
  --allow-unanchored Accept an export with zero TSA anchors as a
                     pass-with-warning instead of failing the anchoring
                     check. An anchor that IS present but doesn't bind to
                     this export still fails regardless of this flag.
  --ca-file <p>      Trust this local PEM file as the TSA CA instead of the
                     bundled FreeTSA root (no network).
  --allow-untrusted-tsa
                     Fetch each anchor's own tsa_cacert_url (embedded in the
                     export under test) instead of the bundled FreeTSA root.
                     Opt-in only — without it, an export naming its own
                     attacker-controlled CA cannot pass.
  --keys-file <p>    Read the published tenant keys from a local JSON document
                     (the /trust/keys/{tenant_id} shape) instead of
                     fetching /trust/keys — offline, and required for the sample.
  --keys-base-url <u> Base URL for the /trust/keys endpoint (default app.usehasp.com).
  --verbose          Print extra detail (success: summary; failure: full check JSON).
  -h, --help         Show help.
  -v, --version      Show version.
```

Read from stdin by passing `-` as the file argument:

```bash
cat export.json | hasp-verify - --skip-tsa
```

Verify the TSA anchor fully offline with a previously archived CA cert (see [docs/AIR-GAPPED.md](docs/AIR-GAPPED.md)):

```bash
hasp-verify export.json --ca-file ./freetsa-cacert.pem
```

Exit codes:

| Code | Meaning |
|------|---------|
| 0    | VERIFIED — all checks passed |
| 1    | FAILED — at least one check failed |
| 2    | USAGE error — bad arguments or unreadable file |

## What it checks

Algorithms are pinned: **Ed25519** for signatures, **SHA-256** for the chain and the history fold, **RFC 3161** for the timestamp anchors. The tool rejects exports that declare anything else.

Seven checks, in this order. Any failure stops the run and reports the failing check.

1. **Schema** — `schema_version` is `1.0`, all required fields present, `entries[*].seq` is 1-indexed and contiguous, `chain_head_hash` is 64-hex, TSA URLs are `https:`, and each anchor's `anchored_data` is 64-hex. `tsa_anchor_chain` may be empty. Each anchor's `algo` (absent = legacy `row-hash-v1`) must be `"row-hash-v1"` or `"sha256-fold-v2"`; `anchored_entry_id` is required when `algo` is `"sha256-fold-v2"`.
   → *proves the export has the shape downstream checks expect; malformed input fails loudly instead of being silently coerced.*
2. **Hash chain** — for every entry, `sha256(canonical_json([12 positional columns, with metadata recursively key-sorted]))` matches the declared `entry.hash`. Up to four more fields append in a fixed order — `asserted_actor_hmac`, `customer_id`, `caller_attribution`, `user_agent` — each present only when the entry carries it, with every earlier absent field in that order encoded as an explicit `null` whenever a later one is present (so no two field combinations can ever hash the same way). An entry with none of the four uses the exact 12-element form. Entries link by `prev_hash` (`null` on the first entry, previous entry's `hash` thereafter — `prev_hash` is not part of the hash). The final entry's hash matches `verification.chain_head_hash`.
   → *proves no entry was added, removed, or mutated after signing — any tampering, including stripping or adding an optional field, breaks the chain.*
3. **Published key** — resolve the tenant's audit-signing key(s) *independently* of the export (fetched from `{--keys-base-url}/trust/keys/{tenant_id}`, default `https://app.usehasp.com`; or read offline from `--keys-file`, a saved copy of that per-tenant document) and require every embedded key — `verification.public_key_pem`, or every entry of `verification.keys[]` on an export whose window spans a signing-key rotation — to match its published counterpart on key material. The signature check then verifies against these trusted keys, never the embedded ones.
   → *proves every signing key is one HASP actually publishes at a source the attacker doesn't control — an export re-signed with a forged keypair fails here instead of passing every signature check.*
4. **Signatures** — every entry's `ed25519:<base64>` signature verifies against its trusted published key over the hex `hash` string itself (`Buffer.from(entry.hash, "utf8")`) — the export's single key, or (when `verification.keys[]` is present) the key selected by that entry's own `key_id`, which fails closed if it names a key absent from the published set.
   → *proves each entry was signed by the holder of its published key, not anyone else — and, in a rotation-spanning export, by the specific key it claims.*
5. **Anchoring** — binds every anchor in `tsa_anchor_chain` to THIS export. A **v1** (`row-hash-v1`, or `algo` absent) anchor's `anchored_data` must equal some exported entry's `hash` — it attests that one row existed at token time. A **v2** (`sha256-fold-v2`) anchor requires a genesis-rooted export (`export.range.from === null`) and recomputes the [history fold](#the-history-fold-sha256-fold-v2) from `verification.fold_base` (genesis when absent) through `anchored_entry_id`'s position — it must equal `anchored_data`, attesting the prefix *since the fold base* (existence, content, order, and count) up to and including that entry. Any anchor that can't be bound fails the check; zero anchors fails unless `--allow-unanchored`. Reports **coverage**: the highest v2-bound position ("entries 1..k time-attested"), any v1 row-level attestations, and the suffix not yet covered by a history commitment ("signed, not covered by a history commitment"). Always runs — never skipped.
   → *proves an anchor is evidence for THIS export's history, not just a validly-formed timestamp — closes the gap where an attacker with signing-key access rewrites and re-signs an already-anchored entry: the row hash chain and signatures still verify, but the fold recomputation catches it.*
6. **TSA anchor** — for each anchor: decode the TSR, trust it against a CA cert from the **trust bundle shipped with this tool** (every root pinned under `roots/` — currently FreeTSA, production HASP's default TSA; see `roots/README.md` for the full set and how to add one), or `--ca-file` if given, or (only with `--allow-untrusted-tsa`) the export's own declared `tsa_cacert_url`; run `openssl ts -verify -in <tsr> -CAfile <cacert> -digest <anchor's own anchored_data>`, require `Verification: OK`. The digest is passed directly (not via `-data`) because the platform placed the raw 32 bytes of `anchored_data` as the RFC 3161 messageImprint. Each token's `genTime` is parsed (`openssl ts -reply -text`) and printed; if it predates the newest entry the anchor is bound to (beyond a small clock-skew allowance), the check fails as a backdated timestamp.
   → *proves the anchored value existed at the timestamped instant, from a TSA this tool trusts independently of the export — not one the export gets to name for itself. Combined with the anchoring check above: a v2 anchor proves the attested prefix existed in that exact state at that time; entries after the newest anchor are signature-protected only until the next anchor.*
7. **Signing-key revocation** — for each entry whose signing key is published as `revoked` (resolved in the published-key check above, never from the export itself), the entry fails UNLESS an anchor already bound above covers it with a TSA `genTime` that precedes the key's `revoked_at` — proving the signature predates the compromise. That case passes but prints a `signed_under_later_revoked_key` notice rather than passing silently. Skipped entirely when no published key in the export is revoked.
   → *proves rotation isn't the only way to respond to a compromised key: a customer can repudiate a specific key outright, and every already-issued signature under it is re-evaluated against that repudiation instead of being grandfathered in forever.*

By default the TSA check trusts only the bundled trust roots — an export that names its own CA at `tsa_cacert_url` (a value the export itself controls) is rejected with an "untrusted TSA" error unless you pass `--ca-file <path>` to trust a specific CA explicitly, or `--allow-untrusted-tsa` to fetch and trust whatever CA the export names (only for sources you already trust; this re-admits the trust-root circularity the default closes).

### The history fold (`sha256-fold-v2`)

A v2 anchor doesn't timestamp a single row — it timestamps a running commitment over the *entire prefix* of the chain up to some entry. `GENESIS` is 64 ASCII zero characters; each step folds the next row's hash in:

```
state_0 = "0000000000000000000000000000000000000000000000000000000000000000"   # 64 zeros
state_i = sha256_hex( ascii(state_{i-1}) || ascii(hash_i) )
```

where `hash_i` is the i-th sealed entry's row hash, in chain order (`created_at` asc, `id` asc, per org). An auditor can reproduce this by hand with nothing but `sha256sum`:

```bash
# Start from fold_base if the export declares one (retention-rebased
# export), otherwise from GENESIS: 64 zero chars.
state=$(jq -r '.verification.fold_base // empty' export.json)
[ -n "$state" ] || state=$(printf '0%.0s' {1..64})
for hash in $(jq -r '.entries[].hash' export.json); do
  state=$(printf '%s%s' "$state" "$hash" | sha256sum | cut -d' ' -f1)
done
echo "$state"   # compare against the anchor's anchored_data
```

If it matches `verification.tsa_anchor_chain[i].anchored_data` for the anchor whose `anchored_entry_id` is that last entry's id, the anchor attests the whole prefix existed, in that exact order and content, at the timestamped instant.

**Retention purges and `fold_base`.** Audit retention windows eventually delete the oldest sealed rows. Before deleting them, the platform folds their hashes into a per-tenant baseline and emits it as `verification.fold_base`, and the first retained entry's `prev_hash` is re-rooted to `null`. Folding the exported entries from `fold_base` then reproduces the exact fold values every earlier anchor committed to, so anchors minted *before* the purge still bind — their timestamps keep attesting the retained rows' age. The value of `fold_base` itself never needs to be trusted: a fabricated base (or any tampered retained entry) cannot reproduce an already-issued token's `anchored_data` without inverting the SHA-256 fold, so a successful binding still proves the retained rows existed, in that order, as part of the anchored history at token time. What is necessarily lost with the purged rows is only *their* attestation — the fold since `fold_base` says nothing about content that was deleted. A `fold_base`-carrying export still verifies (this is the lawful path), but the verifier prints a loud `RETENTION PURGE` notice so a reviewer never mistakes a purge-rebased export for one that starts at genesis.

**Lineage resets and `lineage_reset_at`.** A lawful retention purge always maintains `fold_base`. If instead a prefix is removed *without* that maintenance — a bug, incident tooling, or a malicious operator deleting rows directly — the platform's next purge detects the orphaned boundary, force-resets the lineage (re-rooting from genesis), raises an internal tamper alert, and stamps `verification.lineage_reset_at` on every subsequent export. The verifier prints this as a loud `CHAIN LINEAGE WAS RESET` warning: the retained rows still verify, but the export represents only history since the reset, and anything before it is gone and unverifiable. A reset export can therefore never be mistaken for a pristine full history — if you did not expect one, treat it as a finding.

> **Verifying the published sample?** Its tenant is a throwaway with no live `/trust/keys` endpoint, so pass the co-published keys document offline:
> `hasp-verify audit-export-sample.json --keys-file audit-keys.json` (download both from [usehasp.com/trust/verify](https://usehasp.com/trust/verify)).
>
> `https://usehasp.com/.well-known/audit-keys.json` is that sample tenant's key document — the same `{ tenant_id, keys[] }` shape as `/trust/keys/{tenant_id}` — published on the marketing site because the throwaway tenant has no live endpoint. It is **not** the platform's well-known document: `https://app.usehasp.com/.well-known/audit-keys.json` is a discovery pointer (`{ algo, keys_url_template }`) to `/trust/keys/{tenant_id}`, deliberately not a key list, so no single URL enumerates every tenant. For a real export, verify against `https://app.usehasp.com/trust/keys/{tenant_id}` — which the tool fetches itself.

Field-by-field schema reference: [docs/SCHEMA.md](docs/SCHEMA.md). Machine-readable JSON Schema: [schema/v1.0.json](schema/v1.0.json).

## Programmatic use

```js
import { verifyExport } from "@usehasp/verify";
import { readFile } from "node:fs/promises";

const data = JSON.parse(await readFile("export.json", "utf8"));
const result = await verifyExport(data, { skipTsa: false });

if (!result.ok) {
  for (const [name, check] of Object.entries(result.checks)) {
    if (check.ran && !check.ok) console.error(`${name}: ${check.error}`);
  }
  process.exit(1);
}
```

## Versioning & support

- **SemVer.** Tool follows [Semantic Versioning](https://semver.org). Breaking CLI flag changes, breaking programmatic API changes, and dropped Node majors bump major.
- **Node support.** Active Node LTS lines (currently 20, 22). When a Node major reaches end-of-life, it is dropped in the next minor.
- **Schema compatibility.** Each tool minor pins to one export `schema_version`. The tool will refuse exports with an unrecognised `schema_version` and tell you which tool version to install.

| Export `schema_version` | Tool version | Status   |
|-------------------------|--------------|----------|
| `1.0`                   | `1.x`        | current  |
| `1.1` (`variant: "customer_segment"`) | `>= 1.1`     | current  |

## Trust & provenance

Verify the tarball you installed came from this repo and matches the published build:

```bash
# Cryptographic provenance attached by GitHub Actions OIDC + Sigstore.
npm audit signatures

# Optional: verify Sigstore attestation against the exact build workflow.
gh attestation verify $(npm pack @usehasp/verify | tail -1) --repo UseHasp/verify
```

Both commands must succeed. If they don't, do not run the binary.

Full trust posture: [docs/TRUST.md](docs/TRUST.md). Authoritative explanation of how exports are signed, anchored, and verified: [Hasp Trust Center](https://usehasp.com/trust).

## FAQ

<details>
<summary><strong>Why no native binary?</strong></summary>

Native binaries break the reproducibility claim. The published npm tarball is the exact JS source you can read in `src/` — no build step on the auditor's machine, no opaque blob. If we shipped a binary, you would have to trust *our* build pipeline; with source-only Node, you trust *yours*.
</details>

<details>
<summary><strong>Why shell out to <code>openssl ts</code> instead of bundling an RFC 3161 client?</strong></summary>

Auditors already trust OpenSSL. Bundling our own TSR parser would mean asking auditors to trust 500 lines of crypto we wrote ourselves. `openssl ts -verify` is the same primitive the manual recipe at <https://usehasp.com/trust/verify> uses — the tool stays equivalent to the recipe.
</details>

<details>
<summary><strong>Can I run fully offline?</strong></summary>

Yes. Pass `--keys-file <path>` with a copy of the tenant's published-keys document (the default network call — everything else runs locally, including the TSA anchor check, which trusts the CA cert bundled with this tool rather than fetching one). If you don't have the keys document either, pass `--expectedKey` (programmatic use) or fall back to `--skip-tsa` plus manually diffing the embedded key against an archived copy.
</details>

<details>
<summary><strong>How does this differ from the manual recipe?</strong></summary>

It doesn't, by design. The tool is a convenience layer over the same primitives the manual recipe uses (`openssl ts -verify`, Ed25519, SHA-256, canonical JSON). Same inputs → same verdict. If they ever disagree, the manual recipe wins and the tool has a bug.
</details>

<details>
<summary><strong>Does it phone home?</strong></summary>

No. By default the tool touches the network for exactly one thing: fetching the tenant's published signing key from `/trust/keys/{tenant_id}` — this is a deliberate part of the trust model (an export re-signed with a forged key must not verify against itself), not telemetry. Pass `--keys-file <path>` to read that document from disk instead. The TSA anchor check never reaches the network by default — it trusts a CA cert bundled with the tool — unless you explicitly opt in with `--allow-untrusted-tsa`, in which case it fetches the CA cert URL embedded in the export (capped at 15 s and 1 MB). No analytics, no error reporting, no update checks.
</details>

<details>
<summary><strong>Will this still verify in 10 years?</strong></summary>

Yes. The TSA trust root the default path uses (the bundled FreeTSA cert, valid until 2041) ships inside the tool itself, so a pinned copy of `@usehasp/verify` at the version that produced `VERIFIED` carries its own trust anchor — no separate CA cert archival needed for the default path. Recommended archival bundle:

- `export.json`
- the tenant's published-keys document (`audit-keys.json` / `/trust/keys/{tenant_id}`) downloaded at export time — the published-key check's trust root
- a pinned copy of `@usehasp/verify` at the version that produced `VERIFIED`

Then run `hasp-verify export.json --keys-file ./audit-keys.json` with no network access at all — the published-key check reads the archived doc and the TSA check reads its bundled root. `--skip-tsa` lets you re-run the schema, chain, and signature checks indefinitely even without OpenSSL. Full cookbook: [docs/AIR-GAPPED.md](docs/AIR-GAPPED.md).
</details>

## Security

Report vulnerabilities to `security@usehasp.com`. See [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, coverage, and release workflow.

## License

MIT. See [LICENSE](LICENSE).

---

<p align="center">
  <a href="https://github.com/UseHasp/verify">Repository</a> ·
  <a href="https://usehasp.com/trust">Trust Center</a> ·
  <a href="https://usehasp.com/trust/verify">Manual recipe</a> ·
  <a href="https://www.npmjs.com/package/@usehasp/verify">npm</a>
</p>
