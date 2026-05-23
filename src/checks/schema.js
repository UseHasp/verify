/**
 * Check 0: schema sanity.
 *
 * Validates the top-level shape and required fields. Does not validate
 * cryptographic content — that's the job of the other checks. The goal here
 * is to fail loudly and early on malformed input, so later checks can assume
 * the fields exist.
 *
 * Supported schema_version: "1.0".
 */

const SUPPORTED_SCHEMA = "1.0";
const ANCHORED_DATA_LITERAL = "chain_head_hash";

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
      `unsupported schema_version: ${JSON.stringify(data.schema_version)} (expected "${SUPPORTED_SCHEMA}")`,
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
  if (typeof v.chain_head_hash !== "string" || !/^[0-9a-f]{64}$/.test(v.chain_head_hash)) {
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
    if (a.anchored_data !== ANCHORED_DATA_LITERAL) {
      return fail(
        `.verification.tsa_anchor_chain[${i}].anchored_data must be ${JSON.stringify(
          ANCHORED_DATA_LITERAL,
        )} (got ${JSON.stringify(a.anchored_data)})`,
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
    for (const k of [
      "seq",
      "timestamp",
      "actor",
      "action",
      "resource",
      "prev_hash",
      "hash",
      "signature",
    ]) {
      if (!(k in entry)) return fail(`entry[${i}] missing .${k}`);
    }
    if (entry.seq !== i + 1) {
      return fail(`entry[${i}].seq must be ${i + 1} (1-indexed, contiguous), got ${entry.seq}`);
    }
    for (const k of ["actor", "resource"]) {
      if (!entry[k] || typeof entry[k] !== "object" || Array.isArray(entry[k])) {
        return fail(`entry[${i}].${k} must be an object`);
      }
    }
    if (typeof entry.signature !== "string" || !entry.signature.startsWith("ed25519:")) {
      return fail(`entry[${i}].signature must be "ed25519:<base64>"`);
    }
    if (typeof entry.hash !== "string" || !/^[0-9a-f]{64}$/.test(entry.hash)) {
      return fail(`entry[${i}].hash must be 64 hex chars`);
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
