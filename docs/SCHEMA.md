# Audit export schema — `schema_version` `1.0`

Field reference for what `@usehasp/verify` accepts. The authoritative source is the validator in [`src/checks/schema.js`](../src/checks/schema.js); a machine-readable JSON Schema document lives at [`../schema/v1.0.json`](../schema/v1.0.json). This page is a reader's overview.

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
| `entries`        | array    | The signed audit-log entries themselves, in `seq` order. |

## `export`

| Field            | Type     | Notes |
|------------------|----------|-------|
| `tenant`         | string   | Human-readable tenant name. |
| `tenant_id`      | string   | Opaque, stable tenant identifier. |
| `range.from`     | string   | ISO 8601 UTC timestamp — inclusive start of the export window. |
| `range.to`       | string   | ISO 8601 UTC timestamp — inclusive end of the export window. |
| `exported_at`    | string   | ISO 8601 UTC timestamp — when this export was generated. |
| `exported_by`    | string   | Actor that triggered the export (e.g. user id or service name). |
| `entry_count`    | number   | Must equal `entries.length`. |

## `verification`

| Field                  | Type     | Notes |
|------------------------|----------|-------|
| `algo`                 | string   | Must be `"ed25519"`. The tool rejects every other value. |
| `public_key_pem`       | string   | SPKI-encoded Ed25519 public key, PEM-armored. Used to verify every `entry.signature`. |
| `key_id`               | string   | Stable identifier for the signing key (e.g. fingerprint or slug). For correlation across exports. |
| `key_published_at`     | string   | ISO 8601 UTC timestamp — when this signing key was first published. Lets auditors verify a key was in use during `export.range`. |
| `chain_head_hash`      | string   | 64 lowercase hex chars (SHA-256). Must equal the last entry's `hash`. This is the value the TSA timestamped. |
| `tsa_anchor_chain`     | array    | One or more RFC 3161 timestamps over `chain_head_hash`. Non-empty. |

### `tsa_anchor_chain[i]`

| Field                     | Type   | Notes |
|---------------------------|--------|-------|
| `checkpoint_after_entry`  | number | The `seq` of the last entry included when this anchor was generated. The current export protocol writes exactly one anchor (after `entry_count`), but the schema is plural so future exports can attach multiple checkpoints. |
| `tsa_url`                 | string | `https:` URL of the TSA that produced the TSR. Recorded so auditors can re-fetch a fresh TSR from the same authority if needed. |
| `tsa_cacert_url`          | string | `https:` URL where the TSA's CA certificate can be downloaded. The verifier fetches this at run time, capped at 15 s and 1 MB. Pass `--ca-file <path>` to read locally instead. |
| `tsa_tsr_base64`          | string | Base64-encoded RFC 3161 TimeStampResp bytes — fed to `openssl ts -verify`. |
| `anchored_data`           | string | Must be the literal `"chain_head_hash"`. Records what the TSR signed; rejecting any other value prevents anchor reuse across schemas. |

## `entries[i]`

Indexed by 0; `seq` is 1-indexed and contiguous (`entry[i].seq === i + 1`).

| Field        | Type   | Notes |
|--------------|--------|-------|
| `seq`        | number | 1-indexed, contiguous within the export. |
| `timestamp`  | string | ISO 8601 UTC — when the action happened. |
| `actor`      | object | Who performed the action (shape is opaque to the verifier; only existence is enforced). |
| `action`     | string | Action name (e.g. `user.login`). Opaque to the verifier. |
| `resource`   | object | What was acted on. Opaque to the verifier. |
| `prev_hash`  | string | 64 hex chars — `entries[i-1].hash`, or `"0".repeat(64)` for the first entry. |
| `hash`       | string | 64 hex chars — `sha256(prev_hash || canonical_json(entry without hash and signature))`. |
| `signature`  | string | `"ed25519:<base64>"` — Ed25519 signature over the same canonical payload, verifiable against `verification.public_key_pem`. |

## Canonical JSON

Hash and signature inputs are computed over the entry's canonical JSON form: object keys sorted lexicographically at every depth, arrays unchanged, no whitespace. Implemented in [`src/canonical.js`](../src/canonical.js).
