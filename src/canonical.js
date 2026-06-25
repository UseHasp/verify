/**
 * Canonical JSON encoding for the per-entry integrity hash.
 *
 * The platform computes each entry's `hash` (its `integrity_hash`) as the
 * SHA-256 of a fixed-order JSON array of audit-log columns, encoded by PHP's
 *
 *     json_encode($array, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
 *
 * with the `metadata` element first canonicalized by recursively key-sorting
 * (ksort) every object while preserving the order of arrays/lists. See
 * `AuditLog::computeHashFromAttributes()` in the platform for the reference
 * implementation. This module reproduces that encoding byte-for-byte so an
 * export can be re-hashed offline from the envelope alone.
 *
 * Why `JSON.stringify` already matches `json_encode` with those two flags:
 *   - `JSON_UNESCAPED_SLASHES` — PHP escapes `/` as `\/` by default; the flag
 *     turns that off. `JSON.stringify` never escapes `/`. Match.
 *   - `JSON_UNESCAPED_UNICODE` — PHP escapes non-ASCII as `\uXXXX` by default;
 *     the flag emits literal UTF-8. `JSON.stringify` emits literal UTF-8. Match.
 *   - Neither escapes `<`, `>`, `&`, or `'` (those need PHP's JSON_HEX_* flags,
 *     which the platform does not set). Match.
 *   - Default spacing is 0 in both. Match.
 */

/**
 * Recursively key-sort objects (ksort) while preserving array order. Returns a
 * new structure; the input is not mutated. Primitives pass through unchanged.
 *
 * Sorted objects are built on a null-prototype accumulator so an export
 * containing a literal `__proto__` key cannot pollute `Object.prototype`
 * during canonicalization. `JSON.stringify` still emits the key as
 * `"__proto__"`, preserving byte-for-byte equivalence with the platform.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
export function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value && typeof value === "object") {
    /** @type {Record<string, unknown>} */
    const sorted = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      sorted[key] = canonicalize(/** @type {Record<string, unknown>} */ (value)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Encode a value exactly as the platform's
 * `json_encode(..., JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)` would.
 * Objects are NOT sorted here — only `metadata` is canonicalized, and only by
 * the caller, so the fixed field-array order is preserved.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function encodeForHash(value) {
  return JSON.stringify(value);
}
