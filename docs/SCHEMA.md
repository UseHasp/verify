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
| `chain_head_hash`      | string   | 64 lowercase hex chars (SHA-256). Must equal the last entry's `hash`. |
| `fold_base`            | string \| null, optional | 64 lowercase hex chars. The fold state the retained chain starts from. **Absent or `null` means the history fold starts from GENESIS** (64 zeros). Set by the platform when a retention purge removed the oldest sealed rows: their hashes were folded into this baseline before deletion, so `fold(fold_base, retained hashes)` still reproduces every anchored fold value. See [README.md → The history fold](../README.md#the-history-fold-sha256-fold-v2). |
| `lineage_reset_at`     | string \| null, optional | ISO 8601 timestamp. **Present only when the chain lineage was force-reset** because a prefix was truncated *outside* retention maintenance (a bug, incident tooling, or tampering). When present, the retained rows still verify, but this export represents only history **since** the reset — pre-reset entries are absent and unverifiable. The verifier surfaces it as a loud warning; it never fails the checks. Distinct from `fold_base`: `fold_base` marks *lawful* retention, `lineage_reset_at` marks an *anomalous* truncation, and both can appear together. Absent or `null` means the lineage is intact. |
| `tsa_anchor_chain`     | array    | Zero or more RFC 3161 anchors over the chain's history. May be **empty** — an org with no anchors yet, or a range containing none. Whether an empty (or unbindable) chain is acceptable is the verifier's **anchoring check**, not a schema constraint — see [README.md → What it checks](../README.md#what-it-checks). |

There is no `instructions` field — the platform envelope does not carry one.

### `tsa_anchor_chain[i]`

Two anchor versions, distinguished by `algo`:

| Field                     | Type            | Notes |
|---------------------------|-----------------|-------|
| `checkpoint_after_entry`  | number          | The `seq`, **within this export**, of the entry this anchor binds to — the last entry its commitment covers here. Informational (the anchoring check binds via `anchored_entry_id`/`anchored_data`, not this field). After a retention purge the export is re-sequenced from 1, so this is the in-export seq, not the sealed-row count when the anchor was minted. |
| `tsa_url`                 | string          | `https:` or `http:` URL of the TSA that produced the TSR. Recorded so auditors can re-fetch a fresh TSR from the same authority if needed. Identifies the TSA only — never fetched or trusted by the verifier, and some public TSAs serve RFC 3161 over plain HTTP only (the token is signed, so transport security adds nothing). |
| `tsa_cacert_url`          | string          | `https:` URL where the TSA's CA certificate can be downloaded. The verifier does **not** trust this by default — it verifies against its bundled trust roots instead (or `--ca-file`, if given). This field is only fetched, capped at 15 s and 1 MB, when `--allow-untrusted-tsa` explicitly opts into trusting the export's own declared CA. |
| `tsa_tsr_base64`          | string          | Base64-encoded RFC 3161 TimeStampResp bytes — fed to `openssl ts -verify`. |
| `anchored_data`           | string          | 64-hex — the value the TSR signed: a single row's hash (v1) or a history-fold state (v2, see [README.md → The history fold](../README.md#the-history-fold-sha256-fold-v2)). Not required to equal `verification.chain_head_hash` — which entry(ies) it attests to is a **binding** question, resolved by the anchoring check, not this schema. The RFC 3161 request placed the raw 32 bytes `hex2bin(anchored_data)` directly as the messageImprint, so verification uses `openssl ts -verify … -digest <anchored_data>` (not `-data`). |
| `algo`                    | string, optional | `"row-hash-v1"` or `"sha256-fold-v2"`. **Absent means the legacy v1 (row-hash) anchor.** |
| `anchored_entry_id`       | string \| null, optional | The anchor's `latest_entry_id`. **Required (non-null)** when `algo` is `"sha256-fold-v2"` — the anchoring check needs it to know which entry's position to fold through. Optional and may be `null` for v1 anchors (legacy rows have no `latest_entry_id`). |

**v1 (`row-hash-v1`, or `algo` absent):** `anchored_data` is a single entry's `hash`. Attests that ONE ROW existed at token time. The anchoring check binds it by finding the exported entry whose `hash` matches.

**v2 (`sha256-fold-v2`):** `anchored_data` is the [history fold](../README.md#the-history-fold-sha256-fold-v2) state through `anchored_entry_id`'s position. Attests the entire prefix **since the fold base** — existence, content, order, and count — up to and including that entry (the fold base is GENESIS for an unpurged chain, or `verification.fold_base` after a retention purge; entries before the fold base were purged and are not attested by this anchor). Only bindable in a genesis-rooted export (`export.range.from === null`); the anchoring check recomputes the fold from `verification.fold_base` (GENESIS when absent) through the position of the entry whose `id` matches `anchored_entry_id` and requires it to equal `anchored_data`.

## `entries[i]`

Entries are **flat** rows (the exact canonical columns that feed the row hash) — there are no nested `actor` / `resource` / `timestamp` objects. Indexed by 0; `seq` is 1-indexed and contiguous (`entry[i].seq === i + 1`).

| Field             | Type          | Notes |
|-------------------|---------------|-------|
| `seq`             | number        | 1-indexed, contiguous within the export. |
| `id`              | string        | The audit row id. |
| `user_id`         | string \| null | Acting user, or null for system/API events. |
| `org_id`          | string        | Tenant the row belongs to. |
| `project_id`      | string \| null | Project scope, when project-scoped. |
| `action`          | string        | Action name (e.g. `assistant.message.sent`). Opaque to the verifier. |
| `entity_type`     | string \| null | Type of the acted-on entity. |
| `entity_id`       | string \| null | Id of the acted-on entity. |
| `metadata`        | object \| null | Event metadata. Recursively key-sorted before hashing (see below). |
| `ip_address`      | string \| null | Source IP, when recorded. |
| `created_at`      | string        | ISO 8601 — when the row was recorded. |
| `phi_disposition` | string \| null | PHI disposition column (part of the hash). |
| `subject_type`    | string \| null | PHI subject type (part of the hash). |
| `subject_id_hmac` | string \| null | PHI subject id HMAC (part of the hash). |
| `prev_hash`       | string \| null | 64 hex chars — `entries[i-1].hash`. **`null` for the first entry** (chain genesis — or the retention boundary, where the platform re-roots the chain after a purge), not an all-zeros string. Not part of the hash input. |
| `hash`            | string        | 64 hex chars — the row hash (see below). |
| `signature`       | string        | `"ed25519:<base64>"` — Ed25519 signature over the **hex `hash` string itself** (`Buffer.from(hash, "utf8")`), verifiable against `verification.public_key_pem`. |

## Row hash

Each `hash` is `sha256_hex(JSON.stringify(ARR))` where `ARR` is the 12-element positional array, in exactly this order:

```
[ user_id, org_id, project_id ?? null, action, entity_type, entity_id,
  CANON(metadata), ip_address, created_at,
  phi_disposition ?? null, subject_type ?? null, subject_id_hmac ?? null ]
```

`prev_hash` is **not** part of the hash input — the chain is linked by the separate `prev_hash === entries[i-1].hash` check. Default `JSON.stringify` byte-matches the platform's PHP `json_encode(…, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)`.

`CANON(metadata)` mirrors the platform's `canonicalizeForHash`: recursively, a plain object has its keys sorted ascending with values recursed; an array keeps its order with elements recursed; scalars (and `null`) are unchanged (an empty array stays `[]`). Implemented in [`src/canonical.js`](../src/canonical.js).
