# Security Policy

This policy covers the `@usehasp/verify` package in this repository. For Hasp's overall security program, infrastructure controls, and compliance posture, see the [Hasp Security page](https://usehasp.com/security) and the [Hasp Trust Center](https://usehasp.com/trust).

## Reporting a Vulnerability

Email `security@usehasp.com` with details. Please do not open a public issue for security vulnerabilities.

We aim to acknowledge reports promptly. Remediation timeline depends on severity and is communicated during triage.

## Scope

This package verifies Hasp audit exports locally using Node `crypto` and an external `openssl ts` shell-out. Reports of incorrect verification results (false VERIFIED or false FAILED) are the highest priority.

The authoritative manual verification recipe lives at <https://usehasp.com/trust/verify>. If this tool produces a different verdict than the recipe on the same input, that is a P0 bug — please report it.

## Out of Scope

- Vulnerabilities in OpenSSL itself (report upstream).
- Vulnerabilities in Node.js runtime (report upstream).
- Issues that require an attacker to modify the verifier source on the auditor's machine.
- Issues in Hasp's hosted service — report those via the channels listed on the [Hasp Security page](https://usehasp.com/security).

## Known Limitations

- **Duplicate JSON keys.** `JSON.parse` silently keeps the last occurrence of a duplicated object key. An export crafted with duplicate keys will be canonicalized using the parser's last-key-wins value. Because the signature and hash chain cover the same canonicalized payload that the parser sees, a duplicate-key forgery cannot pass verification — the signature would not match. The behavior is documented here for auditors who may diff raw bytes against the parsed structure.
- **Network reach.** The TSA anchor check fetches `tsa_cacert_url` (URL is visible in the export). The fetch is capped at 15 s and 1 MB. The check can be skipped entirely with `--skip-tsa`. No other network calls.

## Verifying the package you installed

Every release is published with npm provenance and a Sigstore attestation tied to the exact GitHub Actions build. Verify before running:

```bash
npm audit signatures
gh attestation verify $(npm pack @usehasp/verify | tail -1) --repo UseHasp/verify
```

Full trust posture for this package: [docs/TRUST.md](docs/TRUST.md).

## Disclosure

We follow coordinated disclosure. Credit will be given in the changelog unless the reporter requests anonymity.

## Related

- [Hasp Security](https://usehasp.com/security) — program overview, controls, compliance
- [Hasp Trust Center](https://usehasp.com/trust) — how exports are signed, anchored, verified
- [Manual verification recipe](https://usehasp.com/trust/verify) — authoritative reference this tool implements
- [docs/TRUST.md](docs/TRUST.md) — trust posture for this package specifically
