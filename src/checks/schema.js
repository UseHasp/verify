/**
 * Preflight: schema sanity.
 *
 * Validates the top-level shape and required fields of a schema_version "1.0"
 * envelope so the cryptographic checks downstream can assume the fields exist.
 * It does NOT validate cryptographic content — that's the job of the key,
 * chain, signature, and TSA checks.
 *
 * Reference envelope: `App\Services\Audit\AuditExportEnvelopeBuilder`.
 */
import { INTEGRITY_FIELDS } from "../hash.js";

const SUPPORTED_SCHEMA = "1.0";
const HEX64 = /^[0-9a-f]{64}$/;

// Integrity fields that must be a non-null string (the rest may be null).
const REQUIRED_STRING_FIELDS = new Set(["action", "created_at"]);

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
  if (typeof e.tenant_id !== "string" || e.tenant_id.length === 0) {
    return fail(".export.tenant_id must be a non-empty string");
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
  if (typeof v.key_id !== "string" || v.key_id.length === 0) {
    return fail(".verification.key_id must be a non-empty string");
  }
  if (typeof v.public_key_pem !== "string" || !/BEGIN PUBLIC KEY/.test(v.public_key_pem)) {
    return fail(".verification.public_key_pem must be a PEM-encoded public key");
  }
  if (typeof v.chain_head_hash !== "string" || !HEX64.test(v.chain_head_hash)) {
    return fail(".verification.chain_head_hash must be 64 hex chars (SHA-256)");
  }
  if ("keys_url" in v) {
    const urlErr = validateHttpsUrl(v.keys_url);
    if (urlErr) return fail(`.verification.keys_url: ${urlErr}`);
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
    if (typeof a.anchored_data !== "string" || !HEX64.test(a.anchored_data)) {
      return fail(
        `.verification.tsa_anchor_chain[${i}].anchored_data must be 64 hex chars (the hash the TSA covers)`,
      );
    }
    if (typeof a.tsa_tsr_base64 !== "string" || a.tsa_tsr_base64.length === 0) {
      return fail(`.verification.tsa_anchor_chain[${i}].tsa_tsr_base64 must be a base64 string`);
    }
  }

  if (!Array.isArray(data.entries)) return fail("missing .entries array");
  if (data.entries.length === 0) return fail(".entries must be a non-empty array");
  if (data.entries.length !== e.entry_count) {
    return fail(
      `entry count mismatch: .export.entry_count = ${e.entry_count}, .entries.length = ${data.entries.length}`,
    );
  }
  for (const [i, entry] of data.entries.entries()) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return fail(`entry[${i}] not an object`);
    }
    // All integrity fields must be present (even if null) so the hash is
    // recomputable from the envelope alone.
    for (const k of INTEGRITY_FIELDS) {
      if (!(k in entry)) return fail(`entry[${i}] missing .${k}`);
    }
    for (const k of REQUIRED_STRING_FIELDS) {
      if (typeof entry[k] !== "string" || entry[k].length === 0) {
        return fail(`entry[${i}].${k} must be a non-empty string`);
      }
    }
    for (const k of ["prev_hash", "hash", "signature"]) {
      if (!(k in entry)) return fail(`entry[${i}] missing .${k}`);
    }
    if (typeof entry.prev_hash !== "string" || !HEX64.test(entry.prev_hash)) {
      return fail(`entry[${i}].prev_hash must be 64 hex chars`);
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
