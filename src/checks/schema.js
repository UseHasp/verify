/**
 * Check 0: schema sanity.
 *
 * Validates the top-level shape and required fields of a schema_version "1.0"
 * audit export, as emitted by the platform's AuditExportEnvelopeBuilder. Does
 * not validate cryptographic content — that's the job of the other checks. The
 * goal here is to fail loudly and early on malformed input so later checks can
 * assume the fields exist.
 *
 * Entries are the flat schema-1.0 shape (one row per audit-log entry):
 *   user_id, org_id, project_id, action, entity_type, entity_id, metadata,
 *   ip_address, created_at, phi_disposition, subject_type, subject_id_hmac,
 *   prev_hash, hash, signature
 * Nullable columns are permitted to be null (see NULLABLE_ENTRY_FIELDS).
 */

const SUPPORTED_SCHEMA = "1.0";
const HEX64 = /^[0-9a-f]{64}$/;

// Present-and-typed-or-null: platform columns that legitimately carry null.
const NULLABLE_ENTRY_FIELDS = [
  "user_id",
  "project_id",
  "entity_type",
  "entity_id",
  "ip_address",
  "phi_disposition",
  "subject_type",
  "subject_id_hmac",
];

// All fields that must be present on every entry (value may be null where the
// column is nullable; type/format is checked separately below).
const REQUIRED_ENTRY_FIELDS = [
  "user_id",
  "org_id",
  "project_id",
  "action",
  "entity_type",
  "entity_id",
  "metadata",
  "ip_address",
  "created_at",
  "phi_disposition",
  "subject_type",
  "subject_id_hmac",
  "prev_hash",
  "hash",
  "signature",
];

/**
 * @param {any} data parsed export JSON
 * @returns {{ok: true} | {ok: false, error: string}}
 */
export function checkSchema(data) {
  if (!data || typeof data !== "object") {
    return fail("export is not a JSON object");
  }
  if (data.schema_version !== SUPPORTED_SCHEMA) {
    return fail(
      `unsupported schema_version: ${JSON.stringify(data.schema_version)} (this tool supports "${SUPPORTED_SCHEMA}" — see https://github.com/UseHasp/verify#versioning--support for the compatibility table)`,
    );
  }

  const e = data.export;
  if (!e || typeof e !== "object") return fail("missing .export object");
  for (const k of ["tenant", "tenant_id", "range", "exported_at", "exported_by", "entry_count"]) {
    if (!(k in e)) return fail(`missing .export.${k}`);
  }
  if (typeof e.tenant_id !== "string") {
    return fail(".export.tenant_id must be a string (used to resolve the published key)");
  }
  if (typeof e.entry_count !== "number") {
    return fail(".export.entry_count must be a number");
  }
  if (!e.range || typeof e.range !== "object" || Array.isArray(e.range)) {
    return fail(".export.range must be an object");
  }
  for (const k of ["from", "to"]) {
    if (typeof e.range[k] !== "string") {
      return fail(`.export.range.${k} must be an ISO8601 string`);
    }
  }
  // exported_by is nullable (platform: $exportedBy?->email).
  if (e.exported_by !== null && typeof e.exported_by !== "string") {
    return fail(".export.exported_by must be a string or null");
  }

  const v = data.verification;
  if (!v || typeof v !== "object") return fail("missing .verification object");
  if (v.algo !== "ed25519") {
    return fail(`unsupported .verification.algo: ${JSON.stringify(v.algo)} (expected "ed25519")`);
  }
  for (const k of [
    "public_key_pem",
    "key_id",
    "key_published_at",
    "chain_head_hash",
    "tsa_anchor_chain",
  ]) {
    if (!(k in v)) return fail(`missing .verification.${k}`);
  }
  if (typeof v.public_key_pem !== "string") {
    return fail(".verification.public_key_pem must be a string (PEM)");
  }
  if (typeof v.key_id !== "string") {
    return fail(".verification.key_id must be a string");
  }
  if (typeof v.chain_head_hash !== "string" || !HEX64.test(v.chain_head_hash)) {
    return fail(".verification.chain_head_hash must be 64 hex chars (SHA-256)");
  }
  if (!Array.isArray(v.tsa_anchor_chain) || v.tsa_anchor_chain.length === 0) {
    return fail(".verification.tsa_anchor_chain must be a non-empty array");
  }
  for (const [i, a] of v.tsa_anchor_chain.entries()) {
    for (const k of [
      "checkpoint_after_entry",
      "tsa_url",
      "tsa_cacert_url",
      "tsa_tsr_base64",
      "anchored_data",
    ]) {
      if (!(k in a)) return fail(`missing .verification.tsa_anchor_chain[${i}].${k}`);
    }
    for (const k of ["tsa_url", "tsa_cacert_url"]) {
      const urlErr = validateHttpsUrl(a[k]);
      if (urlErr) return fail(`.verification.tsa_anchor_chain[${i}].${k}: ${urlErr}`);
    }
    if (typeof a.tsa_tsr_base64 !== "string" || a.tsa_tsr_base64.length === 0) {
      return fail(`.verification.tsa_anchor_chain[${i}].tsa_tsr_base64 must be a non-empty string`);
    }
    // anchored_data is the actual hash the TSA covers — a 64-hex SHA-256 string,
    // per anchor (not the old "chain_head_hash" literal).
    if (typeof a.anchored_data !== "string" || !HEX64.test(a.anchored_data)) {
      return fail(
        `.verification.tsa_anchor_chain[${i}].anchored_data must be 64 hex chars (SHA-256), got ${JSON.stringify(a.anchored_data)}`,
      );
    }
  }

  if (!Array.isArray(data.entries)) return fail("missing .entries array");
  if (data.entries.length !== e.entry_count) {
    return fail(
      `entry count mismatch: .export.entry_count = ${e.entry_count}, .entries.length = ${data.entries.length}`,
    );
  }
  for (const [i, entry] of data.entries.entries()) {
    if (!entry || typeof entry !== "object") return fail(`entry[${i}] not an object`);
    for (const k of REQUIRED_ENTRY_FIELDS) {
      if (!(k in entry)) return fail(`entry[${i}] missing .${k}`);
    }
    // Nullable string columns: string or null.
    for (const k of NULLABLE_ENTRY_FIELDS) {
      if (entry[k] !== null && typeof entry[k] !== "string") {
        return fail(`entry[${i}].${k} must be a string or null`);
      }
    }
    // org_id, action, created_at are non-null strings on every real entry.
    for (const k of ["org_id", "action", "created_at"]) {
      if (typeof entry[k] !== "string") {
        return fail(`entry[${i}].${k} must be a string`);
      }
    }
    // metadata is a JSON object (or null); arrays are rejected.
    if (
      entry.metadata !== null &&
      (typeof entry.metadata !== "object" || Array.isArray(entry.metadata))
    ) {
      return fail(`entry[${i}].metadata must be an object or null`);
    }
    // prev_hash: null (genesis / chain anchor) or 64-hex.
    if (
      entry.prev_hash !== null &&
      (typeof entry.prev_hash !== "string" || !HEX64.test(entry.prev_hash))
    ) {
      return fail(`entry[${i}].prev_hash must be 64 hex chars or null`);
    }
    if (typeof entry.hash !== "string" || !HEX64.test(entry.hash)) {
      return fail(`entry[${i}].hash must be 64 hex chars`);
    }
    if (typeof entry.signature !== "string" || !entry.signature.startsWith("ed25519:")) {
      return fail(`entry[${i}].signature must be "ed25519:<base64>"`);
    }
  }

  return { ok: true };
}

/**
 * @param {unknown} value
 * @returns {string | null} error message, or null if valid
 */
function validateHttpsUrl(value) {
  if (typeof value !== "string") return "must be a string URL";
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return `not a valid URL: ${JSON.stringify(value)}`;
  }
  if (parsed.protocol !== "https:") {
    return `must use https: scheme (got ${JSON.stringify(parsed.protocol)})`;
  }
  return null;
}

/**
 * @param {string} msg
 * @returns {{ok: false, error: string}}
 */
function fail(msg) {
  return { ok: false, error: msg };
}
