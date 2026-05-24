---
"@usehasp/verify": major
---

First stable release. The CLI surface, programmatic API, and exit codes are now covered by SemVer — breaking changes will bump the major. Schema compatibility is tracked independently via `schema_version` (this release pins to `"1.0"`).

**Surface frozen at 1.0.0:**

- **CLI flags:** `--json`, `--skip-tsa`, `--ca-file <path>`, `--verbose`, `--help`, `--version`. Positional file path or `-` for stdin.
- **Exit codes:** `0` verified, `1` failed, `2` usage error.
- **Programmatic:** `verifyExport(data, opts)` returning `{ ok, checks }`.
- **Schema:** pinned to `schema_version: "1.0"`.

### Included

- Four verification checks: schema, hash chain, Ed25519 signature, RFC 3161 TSA anchor.
- `--ca-file <path>` for offline / long-term TSA verification with a locally archived CA cert.
- Stdin support (`hasp-verify -`).
- `--verbose` on success prints a Detail block (schema version, tenant id, range, entries, key id, anchors).
- Published JSON Schema document at `schema/v1.0.json` for non-JS verifiers.
- Docs: [`docs/SCHEMA.md`](docs/SCHEMA.md) field reference, [`docs/AIR-GAPPED.md`](docs/AIR-GAPPED.md) offline cookbook.
- README: Ed25519 pinning called out, per-check `→ proves:` clauses, worked failure-output example, macOS LibreSSL caveat, long-term-verification FAQ.
- `VERSION` is derived from `package.json` at load time (single source of truth).

### Trust

- npm provenance + Sigstore attestation via GitHub Actions OIDC trusted publishing.
- Source-only npm tarball — no build step, no bundled crypto, no native deps.
- Zero runtime dependencies. Standard primitives only (`node:crypto` + `openssl ts`).
