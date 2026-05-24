---
"@usehasp/verify": patch
---

Validates the hardened release pipeline end-to-end. No runtime changes — same source as 1.0.0.

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
