# Changelog

## 2.0.0

### Major Changes

- 10790e3: Harden trust semantics to match the claims made at usehasp.com/trust/verify: no more trust-root circularity, no more unverified timestamps, and no more silent fallback to an export's own embedded key.
  
  **TSA trust root (breaking default-behavior change).** The TSA anchor check no longer fetches `tsa_cacert_url` — a URL embedded in the export under test — by default. It now verifies against a CA cert bundled with the tool (the FreeTSA root; production HASP's configured TSA), closing a trust-root circularity where an attacker who mints their own TSA and points `tsa_cacert_url` at their own CA would previously pass. A genuine FreeTSA export verifies against the bundled root with no network fetch at all — a fully offline default that also makes `--keys-file` alone enough for air-gapped verification (previously `--skip-tsa` or `--ca-file` was also needed). Pass `--ca-file <path>` to trust a specific CA explicitly, or the new `--allow-untrusted-tsa` (`allowUntrustedTsa: true`) to opt back into fetching the export's own declared `tsa_cacert_url` — only for sources you already trust.
  
  **genTime / backdating check.** Each anchor's RFC 3161 token `genTime` is now parsed (`openssl ts -reply -text`) and surfaced in both human and `--json` output (`checks.tsa.anchors[i].genTime`, ISO 8601). If a token's `genTime` predates the newest entry it's bound to by more than a small clock-skew allowance, verification now fails with a backdating message — "no backdating" was previously an unenforced claim.
  
  **Purged-prefix notice.** An export carrying `verification.fold_base` / `.segment_fold_base` (a retention purge rebased the chain ahead of this export's window) now prints a loud, first-class `RETENTION PURGE` notice and is surfaced on the result (`result.fold_base`) — symmetrical to the existing `lineage_reset_at` notice. Verification still passes (a lawful purge is expected); the point is that a reviewer can no longer miss it. An unanchored tail (entries signed but not yet time-attested) now also prints a prominent, un-indented `UNANCHORED TAIL` warning naming the first unattested seq, not just a bulleted coverage line.
  
  **`checkSignatures` fail-closed (breaking API change).** `checkSignatures(data, opts)` no longer falls back to the export's own embedded `verification.public_key_pem` when `opts.publicKey` / `opts.publicKeys` is omitted — that was circular trust (verifying an export against itself). It now returns a fail-closed error. `verifyExport()` is unaffected — it always resolves and passes a trusted key from the published-key check.
  
  **Docs accuracy.** README, SECURITY.md, and docs/TRUST.md now correctly describe both network calls the tool can make by default or on opt-in (published-key fetch; TSA CA fetch under `--allow-untrusted-tsa`) and how to eliminate each — previously they claimed "offline, no service calls" while the published-key check reached the network by default.
  
  **Real-world canary fixed.** `.github/workflows/real-world.yml` and `scripts/verify-live-sample.mjs` now download and pass the live published-keys document via `--keys-file`, so the canary reaches `VERIFIED` through the full TSA path instead of always failing on the sample's throwaway tenant.
  
  New bundled file: `roots/freetsa-cacert.pem` (added to the npm package's `files`).

### Minor Changes

- fb86bcd: Add the published-key trust-root check. Before verifying
  signatures, the verifier now resolves the tenant's audit-signing key
  independently of the export — fetched from `/trust/keys/{tenant_id}`
  (`--keys-base-url`, default `https://app.usehasp.com`) or read offline from
  `--keys-file` (a saved copy of that per-tenant document) — and requires the
  embedded `public_key_pem` to match it on key material. Signatures are then
  verified against that trusted key, not the one embedded in the export, so an
  export re-signed with a forged keypair fails closed instead of passing every
  signature check. Verifying the published sample now requires `--keys-file`
  (its throwaway tenant has no live `/trust/keys` endpoint).
- 7f83971: Add the anchoring check (six checks total: schema → chain → published-key →
  signatures → anchoring → TSA). Before verifying an RFC 3161 token, the
  verifier now binds every anchor in `tsa_anchor_chain` to the export being
  verified:
  
  - **v1** anchors (`algo` absent, or `"row-hash-v1"`) bind by matching
    `anchored_data` against an exported entry's `hash` — attesting that one row
    existed at token time, as before.
  - **v2** anchors (`algo: "sha256-fold-v2"`) bind by recomputing a SHA-256
    history fold from genesis through `anchored_entry_id`'s position and
    requiring it to equal `anchored_data` — attesting the *entire prefix*
    (existence, content, order, and count) up to and including that entry, in a
    genesis-rooted export.
  
  This closes a gap v1-only anchoring couldn't: an attacker with signing-key
  access who rewrites an already-anchored entry and re-signs it still passes
  the hash-chain and signature checks (both operate on individual rows), but
  the anchoring check catches it — the fold recomputation no longer matches
  what was anchored. Any anchor that can't be bound to the export fails the
  check closed with a message asking for a full export; an export with zero
  anchors fails as "not time-attested" unless `--allow-unanchored` (CLI) /
  `allowUnanchored: true` (API) is passed, which accepts it as a
  pass-with-warning. On success the check reports **coverage**: how far into
  the export a history-fold anchor attests, which entries carry only a
  row-level (v1) attestation, and which suffix is signed but not yet anchored.
  
  The TSA check itself is unchanged mechanically, except it now verifies each
  anchor's own `anchored_data` (previously it asserted every anchor's
  `anchored_data` equaled `chain_head_hash`, a constraint that never held for
  history-fold anchors and has been removed from both the TSA check and the
  schema check). `schema/v1.0.json`, `docs/SCHEMA.md`, `docs/TRUST.md`, and
  `docs/AIR-GAPPED.md` are updated to match; `tsa_anchor_chain` may now be
  empty per schema (the anchoring check, not the schema, decides whether that's
  acceptable).
- 72bd983: Verify the presence-conditional `asserted_actor_hmac` entry field (ADR-PEQ4XT): entries carrying an integrator-asserted actor binding hash over a 13-element canonical array; entries without it keep the original 12-element form, so existing exports verify unchanged. Schema check accepts the optional field (64-hex when present).
- f216b73: Verify two new presence-conditional entry fields and multi-key envelopes:
  
  - `caller_attribution` (extension slot 15) and `user_agent` (slot 16) now participate in the entry digest, gated the same way `asserted_actor_hmac`/`customer_id` are — present exactly when the sealed row carries them, with earlier absent slots encoded as explicit nulls whenever a later slot is present (injectivity). Entries without either field hash byte-identically to the pre-existing form, so already-verified exports are unaffected.
  - Envelopes whose export window spans a signing-key rotation now carry `verification.keys[]` (every signing key present, each with its own `key_id`/`public_key_pem`/`published_at`) and a per-entry `key_id` selecting which key signed it. The published-key check resolves and matches every key against the tenant's published set; the signature check selects the correct key per entry and fails closed if an entry references a key absent from the trusted set. Single-key exports keep their exact pre-existing shape (no `keys[]`, no per-entry `key_id`).
- 9c7a6e3: Support the customer-segment export variant (schema 1.1, `variant: "customer_segment"`) and sealed end-customer attribution.
  
  - Entries carrying a non-null `customer_id` now hash over a 13-element canonical form (presence-based composition — entries without the key are unchanged, so every existing export verifies identically).
  - New segment checks: segment linkage via `segment_prev_hash` from the segment root (or `segment_fold_base` after a retention rebase), the segment history fold bound to its batch's Merkle root via the inclusion path (`sha256-fold-merkle-v1`), and the RFC 3161 token verified over the batch root.
  - Scoped exports surface `lineage_reset_at` exactly like org exports.
- be29477: Second TSA support: DigiCert trust root bundled, and `tsa_url` may use `http:`.
  
  HASP now anchors every audit-chain fold with two independent RFC 3161 TSAs — FreeTSA and DigiCert's public timestamp service — so exports carry an anchor from each.
  
  - **DigiCert Trusted Root G4** (`roots/digicert-trusted-root-g4.pem`) joins the default trust bundle, so the default path (no `--ca-file`, no `--allow-untrusted-tsa`) verifies DigiCert anchors offline.
  - **`tsa_url` accepts `http:` as well as `https:`** (in both `tsa_anchor_chain` and `segment_anchor_chain`). DigiCert serves RFC 3161 over plain HTTP only. `tsa_url` only names the issuing TSA — the verifier never fetches or trusts it, and the token is signed — so this widens no trust decision. `tsa_cacert_url`, which is fetched under `--allow-untrusted-tsa`, stays `https:`-only.
  
  **Upgrade required:** verifier 1.0.x rejects exports that carry a DigiCert anchor (`tsa_url: must use https: scheme`). Use this release or later to verify exports produced after HASP enables its second TSA.
- 809b55f: Support retention-safe history-fold rebasing (`verification.fold_base` and `verification.lineage_reset_at`).
  
  When the platform's audit retention purge deletes the oldest sealed rows, it folds their hashes into a per-tenant baseline emitted as the optional `verification.fold_base` field (absent/null = GENESIS, unchanged behavior). The anchoring check now recomputes each `sha256-fold-v2` anchor's history fold starting from that base, so anchors minted before a retention purge keep binding — and keep attesting the retained rows' age — after the purged prefix is gone.
  
  A new optional `verification.lineage_reset_at` marks an export whose chain lineage was force-reset because a prefix was truncated *outside* retention maintenance. Such exports still verify (the retained rows are valid), but the tool now prints a loud `CHAIN LINEAGE WAS RESET` warning and surfaces the timestamp in `--json` output, so a repaired export can never be mistaken for a pristine full history.
  
  Compatibility: exports **without** `fold_base`/`lineage_reset_at` are byte-shape-identical to before and verify the same on any version. A `fold_base`-bearing export requires this version or newer to bind its pre-purge anchors; earlier verifiers that implement the anchoring check reject it with a fold mismatch (fail-closed, never a false pass). Both new fields are additive under the existing `schema_version` "1.0".
- 76e3b8e: Add multi-root TSA trust and signing-key revocation verification.
  
  **Multi-root TSA trust bundle.** The TSA anchor check now trusts every root certificate pinned under `roots/` (concatenated into one `openssl ts -verify -CAfile`), not a single hardcoded FreeTSA cert — an anchor verifies if it matches any bundled root. Currently only FreeTSA is bundled; adding another TSA to the default trust set is a new `roots/*.pem` file, no code change. `--ca-file` and `--allow-untrusted-tsa` behavior is unchanged.
  
  **Signing-key revocation.** A new seventh check (`checks/key-revocation.js`) resolves each signing key's status (`active`/`retired`/`revoked`) from the trusted published-key source. A signature under a key published as `revoked` now fails verification, UNLESS the entry is bound by a TSA anchor whose `genTime` precedes the key's `revoked_at` — proving the signature predates the compromise — in which case it passes with a new `signed_under_later_revoked_key` notice (`result.checks.keyRevocation.notices`). Existing exports with no revoked keys are unaffected — this check is a no-op for them, so it does not change any previously-passing verdict.
  
  The CLI's human-readable output gains a line for the new check (silent pass when nothing is revoked, or one `⚠` per pre-revocation-anchored notice).

### Patch Changes

- c7ab66d: Correct documentation of the published-keys sources. The platform's `/.well-known/audit-keys.json` is a discovery pointer to the per-tenant `/trust/keys/{tenant_id}` endpoint, not a key list; `--keys-file` takes the `/trust/keys/{tenant_id}` document shape. Doc comments, `--help` text, and the README now say so. No behavior change — the published-key check already fetched `/trust/keys/{tenant_id}` directly.
- 09f018a: Remove internal ADR citations from code comments, test descriptions, and fixture metadata. Internal architecture-decision-record IDs are implementation detail of the private HASP monorepo and don't belong in a public OSS package; this is a comment-only change with no behavior difference.
- b382931: Fix the "Auditable" claim in README.md, which had drifted to a false "under 400 LOC" (actual `src/` had grown to 2,363 lines). It now states the real, measured numbers and points readers at the five files that make up the trust-critical cryptographic core — `merkle.js`, `fold.js`, `canonical.js`, `checks/chain.js`, `checks/signature.js` (314 lines) — before the rest of `src/` (schema validation, CLI, published-key handling, the v1.1 segment variant). A new CI check (`scripts/check-readme-loc.mjs`) fails the build if either number drifts from the measured source again. `docs/TRUST.md` and `CONTRIBUTING.md` carried the same stale "~400 LOC" framing and are corrected the same way.
  
  Also de-duplicated the multi-key-envelope and per-entry extension-field validation shared between `checkSchema` and `checkSegmentSchema` in `src/checks/schema.js` into two helper functions — same checks, no behavior change, 26 fewer lines. No other code, algorithm, or API changes.
- 4295bd1: Remove internal ticket references from source comments, schema descriptions, and test names. No behavior change.

## 1.0.2

### Patch Changes

- [#13](https://github.com/UseHasp/verify/pull/13) [`8965434`](https://github.com/UseHasp/verify/commit/89654341880bae3cb79950ac239a601a0483c080) Thanks [@benjamincharity](https://github.com/benjamincharity)! - Validates the hardened release pipeline end-to-end. No runtime changes — same source as 1.0.0.

  ### Why this exists

  The 1.0.0 release published with full npm-side provenance (Sigstore + SLSA), but the GitHub-side build-provenance attestation step failed because `changeset publish` removes the `.tgz` after upload, leaving the attest step with no subject. As a result, `gh attestation verify` against 1.0.0 returns 404 even though the package is genuine and provenance-signed at npm.

  1.0.1 ships through the corrected pipeline:

  - Release workflow triggers on `main` only (no more duplicate runs from staging pushes).
  - Repack step before attest, so the GitHub attestation has a subject.
  - Smoke test against the packed tarball (install into a throwaway dir, run `hasp-verify --version`, verify a fixture).
  - CODEOWNERS gates release-affecting paths.

  After this release, both verification commands documented in the README will succeed:

  ```
  npm audit signatures
  gh attestation verify $(npm pack @usehasp/verify | tail -1) --repo UseHasp/verify
  ```

  No code, dependency, or schema changes from 1.0.0.

## 1.0.1

### Patch Changes

- [#11](https://github.com/UseHasp/verify/pull/11) [`b177952`](https://github.com/UseHasp/verify/commit/b177952e218b5ff5ee37b508b4c66ae857638390) Thanks [@benjamincharity](https://github.com/benjamincharity)! - Validates the hardened release pipeline end-to-end. No runtime changes — same source as 1.0.0.

  ### Why this exists

  The 1.0.0 release published with full npm-side provenance (Sigstore + SLSA), but the GitHub-side build-provenance attestation step failed because `changeset publish` removes the `.tgz` after upload, leaving the attest step with no subject. As a result, `gh attestation verify` against 1.0.0 returns 404 even though the package is genuine and provenance-signed at npm.

  1.0.1 ships through the corrected pipeline:

  - Release workflow triggers on `main` only (no more duplicate runs from staging pushes).
  - Repack step before attest, so the GitHub attestation has a subject.
  - Smoke test against the packed tarball (install into a throwaway dir, run `hasp-verify --version`, verify a fixture).
  - CODEOWNERS gates release-affecting paths.

  After this release, both verification commands documented in the README will succeed:

  ```
  npm audit signatures
  gh attestation verify $(npm pack @usehasp/verify | tail -1) --repo UseHasp/verify
  ```

  No code, dependency, or schema changes from 1.0.0.

## 1.0.0

### Major Changes

- [`55ef766`](https://github.com/UseHasp/verify/commit/55ef766a90fc14aa6e2eb3e420a21b6f088268f4) Thanks [@benjamincharity](https://github.com/benjamincharity)! - First stable release. The CLI surface, programmatic API, and exit codes are now covered by SemVer — breaking changes will bump the major. Schema compatibility is tracked independently via `schema_version` (this release pins to `"1.0"`).

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

All notable changes to `@usehasp/verify` are documented in this file. Entries are generated from changeset files by the release pipeline — add new entries via `npm run changeset` rather than editing this file directly.

This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Format inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
