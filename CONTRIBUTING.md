# Contributing to `@usehasp/verify`

> **This repository is a published mirror.** The source of truth for `@usehasp/verify` is the `packages/verify/` directory in the private HASP monorepo. This repo's history is a one-way snapshot pushed on release — **pull requests opened here are not merged**. Issues are welcome (bug reports, verification failures, questions) and are triaged from here.

Thank you for helping keep this verifier correct and small. The bar is high: this tool exists to be distrusted by default, so changes must be reviewable by a security auditor in one sitting.

## Ground rules

- Keep the cryptographic primitives (`src/merkle.js`, `src/fold.js`, `src/canonical.js`, `src/checks/chain.js`, `src/checks/signature.js`) small and readable — a reviewer should get through those five files in one sitting. This is the smallest reviewable core, not the full trust boundary: `src/checks/published-key.js` establishes the key the signature check verifies against and is just as trust-critical, it's simply larger (network I/O, key-rotation handling) rather than pure computation — read it too. Schema validation and CLI ergonomics may grow as the envelope contract grows; do not sacrifice validation strictness (e.g. `schema.js` failing loudly on malformed input) to hit a line count. `scripts/check-readme-loc.mjs` (run in `ci-verify.yml`) pins README.md's stated line counts to the measured source — update the `<!-- verify:loc -->` marker and surrounding prose when either number moves past its tolerance.
- Standard primitives only (Node `crypto`, `fetch`, `openssl ts`). No new runtime dependencies without prior discussion.
- Any change to the verification algorithm must land in lockstep with the sample-export generator in the HASP monorepo and with the manual recipe at <https://usehasp.com/trust/verify>.
- Add a [Changeset](#release-workflow) for every user-visible change.

## Build from source

```bash
git clone https://github.com/UseHasp/verify.git
cd verify
npm install
npm run check          # biome lint + format
npm run typecheck      # tsc against the JSDoc-typed source
npm test               # vitest
npm run test:coverage  # coverage report
node src/cli.js test/fixtures/valid.json --skip-tsa
```

## Test coverage

CI enforces the following thresholds on every PR and before every release:

| Metric     | Threshold |
|------------|-----------|
| Lines      | 95 %      |
| Statements | 95 %      |
| Functions  | 93 %      |
| Branches   | 90 %      |

Coverage excludes `src/cli.js` (covered by end-to-end subprocess tests in `test/cli.test.js`, which v8 in-process instrumentation cannot observe). The four verification checks and the orchestrator are at 100 % line and function coverage.

The HTML coverage report is uploaded as a GitHub Actions artifact on every CI run.

## Fixtures

`test/fixtures/valid.json` is the canonical sample export, emitted by the **real platform emitter** (`AuditExportEnvelopeBuilder`) so its key, hash chain, and per-entry Ed25519 signatures are genuine. The offline unit tests (`schema`, `chain`, `signature`) run against it and passing is the byte-level proof that the verifier's port matches the platform format.

> **The fixture's RFC 3161 token is a PLACEHOLDER.** It is minted in an environment where freetsa.org is egress-blocked, so the TSA HTTP call is stubbed and `tsa_tsr_base64` holds throwaway bytes — the live `openssl ts -verify` path cannot pass against it. That path is covered instead by `test/tsa.test.js`, which mocks `execFile` and asserts the tool shells out to `openssl ts -verify … -digest <anchored_data>` (the digest convention) and enforces `anchored_data === chain_head_hash`. The **real** public sample with a genuine freetsa token is minted separately in an egress-capable environment and published at <https://usehasp.com/trust/audit-export-sample.json>; that one exercises the full TSA pipeline (see below).

The four `broken-*.json` fixtures are generated from `valid.json` by `test/fixtures/build-broken.js`. If `valid.json` changes, re-run that script and commit the regenerated broken fixtures.

`test/fixtures/hash-vectors.json` is a frozen **known-answer vector** for the integrity hash + per-entry signature, generated once from the platform emitter's `computeHashFromAttributes()` + signer. It is a cross-language contract: `test/hash-parity.test.js` here and a matching test on the emitter side both pin to it, so any change to the field order, metadata key-sorting, JSON encoding, or the "sign the hash hex string" convention fails against the frozen answer on whichever side drifts. Regenerating it is a deliberate act that must update the emitter, this fixture, and the parity tests together — never hand-edit it.

`valid.json` is meant to mirror the live sample published by the platform (modulo the placeholder token described above). The [real-world workflow](#real-world-verification) verifies that live sample directly and asserts the committed fixture still matches it, so generator/verifier drift is caught automatically without a manual pre-release step. You can run the same verification locally:

```bash
npm run verify:real    # download + verify the LIVE published sample (full TSA)
```

## Real-world verification

The unit suite verifies `test/fixtures/valid.json` — a copy of the published sample frozen into this repo, with the TSA CA-cert fetch stubbed. That proves the verifier is self-consistent with a file we froze; it does **not** prove the verifier still agrees with what the platform produces *now*. If the platform changes how it generates exports, the live sample changes while the committed copy keeps passing forever, hiding a real break. It also can't catch a Node crypto regression, an `openssl` behaviour change, a `fetch` change, or a CA-cert rotation — exactly the breakage a dependency or Node bump can introduce.

The [`real-world` workflow](.github/workflows/real-world.yml) closes that gap so dependency PRs can be merged on a green check instead of manual testing. It runs on every PR, on `main`, on a fortnightly schedule (1st and 15th of each month), and on demand (`workflow_dispatch`), on Node 20 and 22. It does two things:

1. **Verify the live published sample** through the **full** pipeline — downloads <https://usehasp.com/trust/audit-export-sample.json> and verifies it with real Ed25519, real SHA-256, a real network fetch of the TSA CA certificate, and a real `openssl ts -verify` of the RFC 3161 anchor (no `--skip-tsa`, no `--ca-file`, no stubbed fetch).
2. **Drift guard** — asserts the committed `test/fixtures/valid.json` still matches the live sample (structural deep-equal, via [`scripts/check-fixture-drift.mjs`](scripts/check-fixture-drift.mjs)), so the snapshot the offline unit tests rely on can't silently rot. On a mismatch it prints the diverging field paths; refresh the fixture from the live sample and regenerate the `broken-*.json` fixtures with `test/fixtures/build-broken.js`.

It is a **strict gate**: any non-`VERIFIED` result fails the job and blocks the PR, including a third-party outage (usehasp.com or freetsa.org unreachable — re-run once the service recovers). The fortnightly scheduled run surfaces generator / CA-cert drift even when no PRs are open.

## Release workflow

Releases are driven by [Changesets](https://github.com/changesets/changesets). No manual `npm version`, no manual `CHANGELOG.md` edits.

**Versioning is owned in the monorepo; this repo only publishes.** Because this repo's tree is a one-way snapshot from the monorepo, a version bump made *here* would be reverted by the next snapshot. So the bump is applied upstream, before the snapshot: the tree that lands on `main` is already versioned, and `release.yml` just publishes it. `release.yml` fails loud if it ever finds an un-consumed changeset on `main`.

### Contributing a change

1. Make your change on a feature branch (in the monorepo — PRs opened in the public mirror are not merged).
2. Run `npx changeset` — pick `patch` / `minor` / `major`, write a one-line summary. This creates a markdown file in `.changeset/`. Commit it with your code.

### Cutting a release

In the monorepo, before the snapshot is mirrored:

1. Run `npx changeset version` in `packages/verify/` — consumes the changesets, bumps `package.json`, and updates `CHANGELOG.md`. Commit the result.
2. Merge to `staging`, then promote `staging` → `main`. The push to the monorepo's `main` mirrors the (already-versioned) tree to this repo's `main`, and `release.yml` publishes it to npm under `@latest` with provenance, then tags + cuts the GitHub Release.

> **⚠️ Publish the verifier before (or with) the platform prod deploy when a change is envelope-coupled.** When the platform starts emitting a new envelope field that older verifier versions cannot handle (e.g. `verification.fold_base`), the `staging` → `main` promotion both deploys the emitting platform to production **and** mirrors the verifier — but only publishes to npm if `changeset version` was run first (step 1). If you skip step 1, production emits envelopes that no released tool can verify until a human versions and re-promotes. So for any envelope-coupled change: confirm the changeset is consumed and the version bumped in the same promotion that ships the platform change, and verify `@latest` on npm actually advanced before considering the rollout complete.

### Rehearsing a release without shipping

Two safe ways to exercise the pipeline before it can touch `@latest`:

- **Dry run** — trigger `mirror-verify.yml` or `release.yml` via *workflow_dispatch* with `dry_run=true`. The mirror computes the diff without pushing; the release builds, smoke-tests, and runs `npm publish --dry-run` without publishing. Use this to validate workflow edits.
- **Prerelease channel** — enter Changesets pre-mode (`npx changeset pre enter next`) upstream so versions publish as `X.Y.Z-next.N` under the `@next` dist-tag. This exercises the full mirror → publish → provenance path for real, but `npm i @usehasp/verify` (which resolves `@latest`) is untouched. Exit with `npx changeset pre exit` before the next stable release. Install prereleases with `npm i @usehasp/verify@next`.

## Publish pipeline security

- **Trusted publishing (OIDC)** — no long-lived `NPM_TOKEN` secret; npm verifies the GitHub Actions identity directly.
- **Provenance** — every tarball is published with `--provenance`, producing a Sigstore attestation linking it to the exact commit + workflow run. Verify with `npm audit signatures` or `gh attestation verify`.
- **Build provenance attestation** — additionally attested via `actions/attest-build-provenance`.
- **`npm audit signatures`** runs in CI before every publish to verify all dependency tarballs are signed by the npm registry.
- **Manual approval gate** — currently disabled (solo maintainer). Re-enable by uncommenting `environment: npm-production` in `.github/workflows/release.yml` and configuring the environment in repo Settings → Environments once a second maintainer joins.
- **Dependabot** keeps GitHub Actions and npm dependencies patched monthly (grouped by ecosystem+directory), configured at the monorepo root — see `.github/dependabot.yml`.
- **Branch protection** on `main` and `staging` should require: green tests, signed commits, linear history, 1 review, no force-push (configured in repo Settings).

## Verifying a published tarball

```bash
npm pack @usehasp/verify
shasum -a 256 usehasp-verify-*.tgz
# Compare to the SHA-256 in the GitHub release notes.
npm audit signatures
gh attestation verify usehasp-verify-*.tgz --repo UseHasp/verify
```
