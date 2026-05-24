<p align="center">
  <img src="https://assets.usehasp.com/GitHubReadmeHero.webp" alt="@usehasp/verify" />
</p>

<h1 align="center">@usehasp/verify</h1>

<p align="center">
  <em>Offline verifier for Hasp signed audit exports. Zero telemetry. Standard primitives only.</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@usehasp/verify"><img src="https://img.shields.io/npm/v/@usehasp/verify?color=cb3837&label=npm" alt="npm version" /></a>
  <a href="https://github.com/UseHasp/verify/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/UseHasp/verify/test.yml?branch=main&label=CI" alt="CI status" /></a>
  <a href="https://docs.npmjs.com/generating-provenance-statements"><img src="https://img.shields.io/badge/npm-provenance-blue" alt="npm provenance" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license" /></a>
  <img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen" alt="Node >=20" />
</p>

---

**For auditors, compliance reviewers, and customers who want to verify Hasp audit exports for themselves.**

Hasp signs every audit-log entry with an Ed25519 key and chains them with SHA-256, then anchors the chain head with an RFC 3161 timestamp from an independent TSA. This tool re-runs those four checks on an export so you don't have to trust Hasp's word for it. The same checks can be run by hand from the [manual recipe](https://usehasp.com/trust/verify) — this tool is a convenience, not a trust anchor.

- **Offline.** No service calls. One optional network fetch (TSA CA cert) you can disable or replace with a local file.
- **Auditable.** Under 400 LOC of plain JS over Node `crypto` + `openssl ts`. Read it in one sitting.
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
# Grab a sample export and verify it. Requires Node 20+ and openssl.
curl -O https://usehasp.com/trust/audit-export-sample.json
npx @usehasp/verify audit-export-sample.json
```

Expected output:

```
✓ schema valid
✓ chain intact (4 / 4 entries)
✓ signatures verified (4 / 4)
✓ TSA anchor valid
  — https://freetsa.org/tsr

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
- **OpenSSL 1.1+** on `PATH` (used only for `openssl ts -verify` — RFC 3161 TSA anchor check). Skip with `--skip-tsa` if you don't have it.
- **Network** to fetch the TSA CA certificate (URL is in the export). Skip with `--skip-tsa` or pass `--ca-file <path>` for fully offline operation.

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
  --json           Emit machine-readable JSON instead of a human report.
  --skip-tsa       Skip the RFC 3161 TSA anchor check (offline mode).
  --ca-file <p>    Read TSA CA cert from a local PEM file (no network).
  --verbose        Print extra detail (success: summary; failure: full check JSON).
  -h, --help       Show help.
  -v, --version    Show version.
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

Algorithms are pinned: **Ed25519** for signatures, **SHA-256** for the chain, **RFC 3161** for the timestamp anchor. The tool rejects exports that declare anything else.

Four checks, in this order. Any failure stops the run and reports the failing check.

1. **Schema** — `schema_version` is `1.0`, all required fields present, `entries[*].seq` is 1-indexed and contiguous, `chain_head_hash` is 64-hex, TSA URLs are `https:`.
   → *proves the export has the shape downstream checks expect; malformed input fails loudly instead of being silently coerced.*
2. **Hash chain** — for every entry, `sha256(prev_hash_hex || canonical_json(entry_without_hash_and_signature))` matches the declared `entry.hash`. The final entry's hash matches `verification.chain_head_hash`.
   → *proves no entry was added, removed, or mutated after signing — any tampering breaks the chain.*
3. **Signatures** — every entry's `ed25519:<base64>` signature verifies against `verification.public_key_pem` over the same canonical payload.
   → *proves each entry was signed by the holder of the published key, not anyone else.*
4. **TSA anchor** — for each anchor in `tsa_anchor_chain`: decode TSR, fetch CA cert from `tsa_cacert_url` (or read from `--ca-file`), run `openssl ts -verify -in <tsr> -CAfile <cacert> -data <chain_head_hash_ascii>`, require `Verification: OK`.
   → *proves the chain head existed at the timestamped instant; an attacker who later compromises the signing key cannot retroactively forge older entries without also compromising the TSA.*

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

Yes. Pass `--skip-tsa` to skip the only network fetch (the TSA CA cert). The schema, chain, and signature checks all run locally with no network. The TSA anchor check is the only one that needs the cert — if you have the cert on disk, you can run `openssl ts -verify` manually against the embedded TSR.
</details>

<details>
<summary><strong>How does this differ from the manual recipe?</strong></summary>

It doesn't, by design. The tool is a convenience layer over the same primitives the manual recipe uses (`openssl ts -verify`, Ed25519, SHA-256, canonical JSON). Same inputs → same verdict. If they ever disagree, the manual recipe wins and the tool has a bug.
</details>

<details>
<summary><strong>Does it phone home?</strong></summary>

No. The tool touches the network for exactly one thing: fetching the TSA CA certificate at the URL embedded in the export. That fetch is capped at 15 s and 1 MB. Pass `--skip-tsa` to disable it entirely, or `--ca-file <path>` to read the cert from disk. No analytics, no error reporting, no update checks.
</details>

<details>
<summary><strong>Will this still verify in 10 years?</strong></summary>

Yes, if you archive the TSA CA certificate alongside the export. The certificate is fetched from `tsa_cacert_url` at verify time; if that URL eventually 404s, the TSR bytes in the export are still valid but unverifiable without the cert. Recommended archival bundle:

- `export.json`
- the CA cert PEM downloaded at export time (from `tsa_cacert_url`)
- a pinned copy of `@usehasp/verify` at the version that produced `VERIFIED`

Then run `hasp-verify export.json --ca-file ./tsa-cacert.pem` to verify against the local cert with no network access. `--skip-tsa` lets you re-run the schema, chain, and signature checks indefinitely even without the cert. Full cookbook: [docs/AIR-GAPPED.md](docs/AIR-GAPPED.md).
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
