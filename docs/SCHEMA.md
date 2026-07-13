# Audit export schema — `schema_version` `1.0`

Field reference for what `@usehasp/verify` accepts. The authoritative source is the validator in [`src/checks/schema.js`](../src/checks/schema.js); a machine-readable JSON Schema document lives at [`../schema/v1.0.json`](../schema/v1.0.json). This page is a reader's overview. The platform reference implementations are `AuditExportEnvelopeBuilder` and `AuditLog::computeHashFromAttributes()`.

Top-level shape:

```json
{
  "schema_version": "1.0",
  "export":       { ... },
  "verification": { ... },
  "entries":      [ ... ]
}
```

## Top level

| Field            | Type     | Notes |
|------------------|----------|-------|
| `schema_version` | string   | Must be `"1.0"`. The tool refuses any other value and points at the matching tool version. |
| `export`         | object   | Provenance metadata for the export operation. |
| `verification`   | object   | Everything an auditor needs to verify the export cryptographically. |
| `entries`        | array    | The signed audit-log entries themselves, in chain order. |

## `export`

| Field            | Type          | Notes |
|------------------|---------------|-------|
| `tenant`         | string        | Human-readable tenant name. |
| `tenant_id`      | string        | Opaque, stable tenant identifier. Used to resolve the published key at `/trust/keys/{tenant_id}`. |
| `range.from`     | string        | ISO 8601 timestamp — inclusive start of the export window. |
| `range.to`       | string        | ISO 8601 timestamp — inclusive end of the export window. |
| `exported_at`    | string        | ISO 8601 timestamp — when this export was generated. |
| `exported_by`    | string \| null| Actor that triggered the export (e.g. an email); null when unattributed. |
| `entry_count`    | number        | Must equal `entries.length`. |

## `verification`

| Field                  | Type     | Notes |
|------------------------|----------|-------|
| `algo`                 | string   | Must be `"ed25519"`. The tool rejects every other value. |
| `public_key_pem`       | string   | SPKI-encoded Ed25519 public key, PEM-armored. **Must match** the tenant's independently-published key (see below) before it is trusted. |
| `key_id`               | string   | Stable identifier for the signing key. Matched against `keys[].key_id` from `/trust/keys`. |
| `key_published_at`     | string   | ISO 8601 timestamp — when this signing key was first published. |
| `chain_head_hash`      | string   | 64 lowercase hex chars (SHA-256). Must equal the last entry's `hash`. |
| `tsa_anchor_chain`     | array    | One or more RFC 3161 timestamps. Non-empty. |

### `tsa_anchor_chain[i]`

| Field                     | Type   | Notes |
|---------------------------|--------|-------|
| `checkpoint_after_entry`  | number | The position of the last entry included when this anchor was generated. Usually one anchor per export (after `entry_count`); the schema is plural so future exports can attach multiple checkpoints. |
| `tsa_url`                 | string | `https:` URL of the TSA that produced the TSR. |
| `tsa_cacert_url`          | string | `https:` URL where the TSA's CA certificate can be downloaded. The verifier fetches this at run time, capped at 15 s and 1 MB. Pass `--ca-file <path>` to read locally instead. |
| `tsa_tsr_base64`          | string | Base64-encoded RFC 3161 TimeStampResp bytes — fed to `openssl ts -verify`. |
| `anchored_data`           | string | 64-hex SHA-256 — the actual hash this TSR covers. Verified per anchor as `openssl ts -verify … -data <anchored_data>`, with `anchored_data` treated as its hex-ASCII string (the form the platform timestamps). |

## Published key — the trust root

The embedded `verification.public_key_pem` is **not** trusted on its own. The verifier resolves the tenant's key from an independent source and requires the embedded key to match it (by key material), so a whole-chain forgery signed with an attacker's own key fails closed.

- **Discovery:** `GET /.well-known/audit-keys.json` → `{ "algo": "ed25519", "keys_url_template": "…/trust/keys/{tenant_id}" }`. This is a *discovery document*, not a key dump.
- **Keys:** `GET /trust/keys/{tenant_id}` → `{ "tenant_id": "…", "keys": [{ "key_id", "public_key_pem", "published_at", "status" }] }`. The verifier finds the entry whose `key_id === verification.key_id` and asserts its `public_key_pem` matches the embedded key.
- **Offline:** pass `--key-file <pem>` (CLI) or `expectedKey` (programmatic) to supply the published key from disk instead of fetching. `--keys-url` overrides the base URL (default `https://app.usehasp.com`).

## `entries[i]`

Indexed by 0; entries are in chain order. Nullable columns may be `null`.

| Field             | Type           | Notes |
|-------------------|----------------|-------|
| `user_id`         | string \| null | Acting user; null for system / API-key actions. |
| `org_id`          | string         | Owning organization. |
| `project_id`      | string \| null | Project scope, if any. |
| `action`          | string         | Action name (e.g. `ai.chat.message`). |
| `entity_type`     | string \| null | Type of the entity acted on. |
| `entity_id`       | string \| null | Id of the entity acted on. |
| `metadata`        | object \| null | Free-form event metadata. Recursively key-sorted before hashing. |
| `ip_address`      | string \| null | Source IP, if recorded. |
| `created_at`      | string         | ISO 8601 timestamp — when the action happened. |
| `phi_disposition` | string \| null | PHI fidelity disposition (`not_present` / `redacted_at_delivery` / `reidentified_at_delivery`). |
| `subject_type`    | string \| null | Subject class, when a subject is bound. |
| `subject_id_hmac` | string \| null | HMAC of the subject identifier, when bound. |
| `prev_hash`       | string \| null | 64 hex — the previous entry's `hash`. `null` for the genesis entry (the chain anchor). |
| `hash`            | string         | 64 hex — SHA-256 of the canonical hash payload (see below). |
| `signature`       | string         | `"ed25519:<base64>"` — detached Ed25519 signature over the `hash` **hex string**, verifiable against the published key. |

## The hash payload

Each entry's `hash` is the SHA-256 (lowercase hex) of a JSON **array** of exactly these twelve fields, in this order, with no whitespace, encoded like PHP's `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`:

```
[ user_id, org_id, project_id, action, entity_type, entity_id,
  metadata, ip_address, created_at, phi_disposition,
  subject_type, subject_id_hmac ]
```

Only `metadata` is canonicalized (recursive lexical key-sort of objects; arrays keep their order). The field order of the array itself is **not** sorted. `prev_hash` is **not** part of the hash — it is a separate linkage column. Implemented in [`src/canonical.js`](../src/canonical.js).

## The signature

`signature` is a detached Ed25519 signature over the ASCII bytes of the `hash` hex string (`Buffer.from(entry.hash, "utf8")`) — not the payload, not the raw hash bytes — encoded as `"ed25519:" + base64(rawSig)`.
