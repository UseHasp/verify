---
"@usehasp/verify": major
---

Align the verifier to the real platform `schema_version: "1.0"` envelope (HASP-197).

The pre-1.x format assumed a layout the platform never produced. The verifier now implements the actual contract emitted by `AuditExportEnvelopeBuilder`:

- **Integrity hash** — `entry.hash` is recomputed as the SHA-256 of the fixed audit-log field array (`user_id … subject_id_hmac`), encoded with unescaped slashes/unicode and `metadata` recursively key-sorted. The hash no longer folds in `prev_hash`.
- **Chain linkage** — verified as the separate `entry.prev_hash === previousEntry.hash` check.
- **Signatures** — Ed25519 over the entry's `hash` **hex string** (not the raw digest bytes).
- **Published-key check (new)** — fetches `GET /trust/keys/{tenant_id}`, matches `verification.key_id`, confirms it is not revoked, and confirms it equals the embedded `public_key_pem`. Signatures verify against this published key. New flags `--keys-file`, `--keys-url`, `--skip-key-check`.
- **TSA anchor** — verified over each anchor's `anchored_data`, which is bound to its checkpoint entry's hash.

Breaking: `VerifyResult.checks` gains a `key` member; `checkSignatures(data, publicKeyPem)` now takes the trusted key explicitly; entry/envelope shapes changed. New CLI flags as above.
