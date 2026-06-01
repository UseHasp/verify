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

`test/fixtures/valid.json` is the canonical sample export. The four `broken-*.json` fixtures are generated from it by `test/fixtures/build-broken.js`. If `valid.json` changes, re-run that script and commit the regenerated broken fixtures.

`valid.json` itself is meant to mirror the live sample published by the platform at <https://usehasp.com/trust/audit-export-sample.json>. The [real-world workflow](#real-world-verification) verifies that live sample directly and asserts the committed fixture still matches it, so generator/verifier drift is caught automatically without a manual pre-release step. You can run the same verification locally:

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
