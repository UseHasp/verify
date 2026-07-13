---
"@usehasp/verify": major
---

Rewrite the verifier to the real `schema_version` `1.0` audit-export contract and close the key-substitution forgery gap.

The previously published verifier targeted an audit-export format the platform never produced: it rejected genuine exports and, worse, verified signatures against the key embedded in the export itself — so an attacker who regenerated the whole chain with their own keypair passed every check. This release realigns the library to what the platform actually emits (`AuditExportEnvelopeBuilder` / `AuditLog::computeHashFromAttributes()`).

**Breaking changes**

- **Entry schema.** Entries are now the flat schema-1.0 shape (`user_id, org_id, project_id, action, entity_type, entity_id, metadata, ip_address, created_at, phi_disposition, subject_type, subject_id_hmac, prev_hash, hash, signature`) instead of `seq/timestamp/actor{}/resource{}`. Exports in the old shape are rejected.
- **Hash.** `hash` is the SHA-256 of the fixed twelve-field JSON array (only `metadata` is key-sorted; `prev_hash` is not part of the hash), encoded to match PHP `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` — not `sha256(prev_hash ‖ canonical_entry)`.
- **Signature.** Verified as a detached Ed25519 signature over the `hash` **hex string**, not the canonical payload.
- **Chain.** Linkage is `entry.prev_hash === previousEntry.hash`; the genesis `prev_hash` is `null` (not 64 zeros).
- **TSA.** Each anchor is verified over its own `anchored_data` (a 64-hex hash) instead of a global `chain_head_hash`; the `anchored_data === "chain_head_hash"` literal check is gone.

**Security fix**

- **Published-key trust root.** The embedded `public_key_pem` is now checked against the tenant's independently-published key — `GET /trust/keys/{tenant_id}`, or `--key-file` / `expectedKey` offline — and signatures are verified against that key. A whole-chain forgery re-signed with an attacker's own key fails closed. `VerifyResult.checks` gains a `publishedKey` check.

**New options / flags**

- `--key-file <pem>` / `expectedKey`, `--keys-url <url>` / `keysBaseUrl` (default `https://app.usehasp.com`).

`SCHEMA_VERSION` stays `"1.0"`.
