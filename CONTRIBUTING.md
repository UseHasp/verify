# Contributing to `@usehasp/verify`

Thank you for helping keep this verifier correct and small. The bar is high: this tool exists to be distrusted by default, so changes must be reviewable by a security auditor in one sitting.

## Ground rules

- Keep the source under ~400 LOC. If a change pushes past that, split or simplify.
- Standard primitives only (Node `crypto`, `fetch`, `openssl ts`). No new runtime dependencies without prior discussion.
- Any change to the verification algorithm must land in lockstep with the generator at `apps/marketing/scripts/generate-audit-sample.js` in `UseHasp/hasp-monorepo` and with the manual recipe at <https://usehasp.com/trust/verify>.
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
| Functions  | 95 %      |
| Branches   | 90 %      |

Coverage excludes `src/cli.js` (covered by end-to-end subprocess tests in `test/cli.test.js`, which v8 in-process instrumentation cannot observe). The four verification checks and the orchestrator are at 100 % line and function coverage.

The HTML coverage report is uploaded as a GitHub Actions artifact on every CI run.

## Fixtures

All fixtures are produced by a single generator, `test/fixtures/generate.js`, from a pinned keypair and the real freetsa RFC 3161 anchor bundled in the repo. Run it after any contract change:

```bash
node test/fixtures/generate.js
```

It writes:

- `valid.json` — the canonical schema-1.0 golden export (real per-entry Ed25519 signatures over each `hash` hex, a real `prev_hash` chain rooted at genesis `null`, and the real freetsa TSR).
- `trust-keys.json` / `published-key.pem` — the tenant's independently-published key (the trust root), as the `/trust/keys` response and as a bare PEM for `--key-file`.
- `broken-hash.json`, `broken-chain.json`, `broken-signature.json`, `forged-chain.json`, `broken-tsa.json` — the negative fixtures, each failing exactly one check (`forged-chain.json` is the whole-chain forgery that must fail the published-key match).

`valid.json` is meant to mirror the live sample the platform publishes at <https://usehasp.com/trust/audit-export-sample.json>; the two must be regenerated from the same real export (tracked cross-repo under HASP-197).

## Release workflow

Releases are driven by [Changesets](https://github.com/changesets/changesets). No manual `npm version`, no manual `CHANGELOG.md` edits.

### Contributing a change

1. Make your change on a feature branch.
2. Run `npx changeset` — pick `patch` / `minor` / `major`, write a one-line summary. This creates a markdown file in `.changeset/`.
3. Commit the changeset file with your code. Open a PR against `staging` (for beta) or `main` (for stable).

### How publishes happen

| Branch | Trigger | Result |
|--------|---------|--------|
| `main` | Merge a Version PR | Stable release published to npm under `@latest`. `CHANGELOG.md` updated. Git tag + GitHub Release created. |
| `staging` | Merge with `.changeset/pre.json` present | Pre-release published under `@beta` (e.g. `0.2.0-beta.0`). |
| `main` or `staging` | Merge any PR with new `.changeset/*.md` files | The release bot opens / updates a "Version Packages" PR. Merging that PR triggers the actual publish. |

### Enter / exit beta mode

```bash
git checkout staging
npx changeset pre enter beta
git add .changeset/pre.json && git commit -m "chore: enter beta pre-mode"
# ... beta releases happen on staging pushes ...
npx changeset pre exit
git add .changeset/pre.json && git commit -m "chore: exit beta pre-mode"
# next stable release happens when staging merges to main
```

Users install betas with `npm i @usehasp/verify@beta`.

## Publish pipeline security

- **Trusted publishing (OIDC)** — no long-lived `NPM_TOKEN` secret; npm verifies the GitHub Actions identity directly.
- **Provenance** — every tarball is published with `--provenance`, producing a Sigstore attestation linking it to the exact commit + workflow run. Verify with `npm audit signatures` or `gh attestation verify`.
- **Build provenance attestation** — additionally attested via `actions/attest-build-provenance`.
- **`npm audit signatures`** runs in CI before every publish to verify all dependency tarballs are signed by the npm registry.
- **Manual approval gate** — currently disabled (solo maintainer). Re-enable by uncommenting `environment: npm-production` in `.github/workflows/release.yml` and configuring the environment in repo Settings → Environments once a second maintainer joins.
- **Dependabot** keeps GitHub Actions and dev dependencies patched weekly.
- **Branch protection** on `main` and `staging` should require: green tests, signed commits, linear history, 1 review, no force-push (configured in repo Settings).

## Verifying a published tarball

```bash
npm pack @usehasp/verify
shasum -a 256 usehasp-verify-*.tgz
# Compare to the SHA-256 in the GitHub release notes.
npm audit signatures
gh attestation verify usehasp-verify-*.tgz --repo UseHasp/verify
```
