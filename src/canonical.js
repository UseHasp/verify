/**
 * Canonical serialization for the audit-log integrity hash.
 *
 * The platform computes each entry's `hash` in
 * `AuditLog::computeHashFromAttributes()` (apps/platform, monorepo) as:
 *
 *   sha256_hex(json_encode([
 *     user_id, org_id, project_id, action, entity_type, entity_id,
 *     metadata, ip_address, created_at, phi_disposition,
 *     subject_type, subject_id_hmac,
 *   ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE))
 *
 * Two properties matter for byte-parity with PHP:
 *
 *  1. The payload is a fixed-order JSON *array* of exactly twelve fields.
 *     The field order is significant and is NOT sorted — only `metadata` is
 *     canonicalized. `prev_hash` is deliberately NOT part of the hash.
 *  2. Only `metadata` is canonicalized (recursive key-sort of objects; arrays
 *     keep their order), so a JSONB key-order round-trip on the platform does
 *     not change the digest (AUDIT-C4).
 *
 * JS `JSON.stringify` already matches `JSON_UNESCAPED_SLASHES` (it never
 * escapes `/`) and `JSON_UNESCAPED_UNICODE` (it emits non-ASCII as UTF-8, not
 * `\uXXXX`), and emits no insignificant whitespace — so the byte output is
 * identical to PHP's for the value types that appear here (string, number,
 * boolean, null, and nested objects/arrays). See the parity test in
 * test/unit.test.js.
 */

/**
 * The twelve hashed fields, in the exact order the platform serializes them.
 * @type {readonly string[]}
 */
export const HASH_FIELD_ORDER = Object.freeze([
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
]);

/**
 * Prototype-pollution-safe recursive key-sort. Scoped to `metadata` only.
 *
 * Objects have their keys sorted lexicographically at every depth; arrays keep
 * their element order (their contents are still canonicalized). The accumulator
 * uses `Object.create(null)` so a malicious export carrying a literal
 * `__proto__` key cannot pollute `Object.prototype`. `JSON.stringify` still
 * emits the key as `"__proto__"`, preserving byte-for-byte equivalence with the
 * platform output.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
export function canonicalizeMetadata(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalizeMetadata);
  }
  if (value && typeof value === "object") {
    /** @type {Record<string, unknown>} */
    const out = Object.create(null);
    for (const k of Object.keys(value).sort()) {
      out[k] = canonicalizeMetadata(/** @type {Record<string, unknown>} */ (value)[k]);
    }
    return out;
  }
  return value;
}

/**
 * Build the canonical hash payload for one entry: the fixed-order twelve-field
 * array with `metadata` canonicalized, serialized with no whitespace. This is
 * the exact byte string the platform passes to SHA-256.
 *
 * Fields absent on the entry serialize as JSON `null`, matching the platform's
 * `$attributes[...] ?? null` behaviour.
 *
 * @param {Record<string, unknown>} entry
 * @returns {string}
 */
export function canonicalEntryPayload(entry) {
  const arr = HASH_FIELD_ORDER.map((k) => {
    if (k === "metadata") return canonicalizeMetadata(entry.metadata ?? null);
    const v = entry[k];
    return v === undefined ? null : v;
  });
  return JSON.stringify(arr);
}
