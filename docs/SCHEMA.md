# Audit export schema — `schema_version` `1.0`

Field reference for what `@usehasp/verify` accepts. The authoritative source is the validator in [`src/checks/schema.js`](../src/checks/schema.js); a machine-readable JSON Schema document lives at [`../schema/v1.0.json`](../schema/v1.0.json). This page is a reader's overview. The envelope is produced by the platform's `App\Services\Audit\AuditExportEnvelopeBuilder`.

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
| `entries`        | array    | The signed audit-log entries themselves, in order. |

## `export`

| Field            | Type     | Notes |
|------------------|----------|-------|
| `tenant`         | string   | Human-readable tenant name. |
| `tenant_id`      | string   | Opaque, stable tenant identifier. Used to resolve the published-keys URL. |
| `range.from`     | string   | ISO 8601 timestamp — inclusive start of the export window. |
| `range.to`       | string   | ISO 8601 timestamp — inclusive end of the export window. |
| `exported_at`    | string   | ISO 8601 timestamp — when this export was generated. |
| `exported_by`    | string   | Actor that triggered the export (e.g. user id or service name). |
| `entry_count`    | number   | Must equal `entries.length`. |

## `verification`

| Field                  | Type     | Notes |
|------------------------|----------|-------|
| `algo`                 | string   | Must be `"ed25519"`. The tool rejects every other value. |
| `key_id`               | string   | Stable identifier for the signing key. Matched against the published-keys document. |
| `public_key_pem`       | string   | SPKI-encoded Ed25519 public key, PEM-armored. Confirmed to equal the published key for `key_id`. |
| `keys_url`             | string   | *(optional)* `https:` URL of the published-keys document. If absent, it is derived as `https://app.usehasp.com/trust/keys/{tenant_id}`. |
| `key_published_at`     | string   | ISO 8601 timestamp — when this signing key was first published. |
| `chain_head_hash`      | string   | 64 lowercase hex chars (SHA-256). Must equal the last entry's `hash`. |
| `tsa_anchor_chain`     | array    | One or more RFC 3161 timestamps over entry hashes. Non-empty. |

### `tsa_anchor_chain[i]`

| Field                     | Type   | Notes |
|---------------------------|--------|-------|
| `checkpoint_after_entry`  | number | 1-indexed position of the entry this anchor checkpoints. Its `hash` must equal `anchored_data`. |
| `tsa_url`                 | string | `https:` URL of the TSA that produced the TSR. |
| `tsa_cacert_url`          | string | `https:` URL where the TSA's CA certificate can be downloaded. Fetched at run time (capped 15 s / 1 MB); pass `--ca-file <path>` to read locally instead. |
| `tsa_tsr_base64`          | string | Base64-encoded RFC 3161 TimeStampResp bytes — fed to `openssl ts -verify`. |
| `anchored_data`           | string | 64 hex chars — the hash the TSR covers. Verified to equal the checkpoint entry's `hash`, and that the TSR covers exactly these bytes. |

## `entries[i]`

Every entry carries the full set of audit-log columns the integrity hash is computed from, so the hash is recomputable from the envelope alone.

| Field             | Type            | Notes |
|-------------------|-----------------|-------|
| `user_id`         | int/string/null | Acting user id (or null for non-user actors). |
| `org_id`          | int/string/null | Organization id. |
| `project_id`      | int/string/null | Project id (or null). |
| `action`          | string          | Action name (e.g. `ai.chat.message`). |
| `entity_type`     | string/null     | Type of the acted-on entity. |
| `entity_id`       | int/string/null | Id of the acted-on entity. |
| `metadata`        | object/array/null | Action-specific metadata. Key-sorted recursively before hashing. |
| `ip_address`      | string/null     | Source IP. |
| `created_at`      | string          | ISO 8601 timestamp of the action. |
| `phi_disposition` | string/null     | PHI handling disposition (e.g. `none`, `redacted`, `contains_phi`). |
| `subject_type`    | string/null     | Type of the data subject (e.g. `patient`). |
| `subject_id_hmac` | string/null     | HMAC of the data subject's id (never the raw id). |
| `prev_hash`       | string          | 64 hex chars — the previous entry's `hash`. For a sliced export the first entry's `prev_hash` points at a row outside the window. |
| `hash`            | string          | 64 hex chars — the row's `integrity_hash` (see below). |
| `signature`       | string          | `"ed25519:<base64>"` — detached Ed25519 signature over the `hash` hex string. |

## The integrity hash

`entry.hash` is the SHA-256 (lowercase hex) of a JSON array of the audit-log columns, in this **exact order**:

```
[ user_id, org_id, project_id, action, entity_type, entity_id,
  metadata, ip_address, created_at, phi_disposition, subject_type, subject_id_hmac ]
```

encoded the way the platform's `json_encode($array, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)` encodes it (no whitespace, slashes and non-ASCII left literal), with `metadata` first canonicalized by **recursively key-sorting every object** while preserving array/list order. The hash deliberately does **not** fold in `prev_hash`. Reference implementation: `AuditLog::computeHashFromAttributes()` on the platform; mirrored in [`src/hash.js`](../src/hash.js) and [`src/canonical.js`](../src/canonical.js).

Chain **linkage** is the separate `entry.prev_hash === previousEntry.hash` check — not a running hash.
