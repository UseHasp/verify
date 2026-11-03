/**
 * Canonical value transform for the audit-row hash.
 *
 * Mirrors the HASP platform's `AuditLog::canonicalizeForHash()` (PHP): the
 * `metadata` object is recursively key-sorted before it is placed into the
 * positional hash array, so a JSONB key-order round-trip on the platform side
 * cannot change the digest. Concretely:
 *
 *   - plain object → new object with keys sorted ascending, values recursed
 *   - array        → same array, order preserved, elements recursed
 *   - scalar/null  → returned unchanged (an empty array stays [])
 *
 * The result is a plain JS value; the chain check embeds it in the 12-element
 * positional array and runs `JSON.stringify` over the whole array. Default
 * `JSON.stringify` byte-matches PHP `json_encode(..., JSON_UNESCAPED_SLASHES |
 * JSON_UNESCAPED_UNICODE)`, so no custom escaping is needed.
 *
 * Implementation note: the sorted accumulator is `Object.create(null)` so a
 * malicious `metadata` containing a literal `__proto__` key creates an own
 * property (which `JSON.stringify` then emits as `"__proto__"`, matching PHP's
 * `ksort` + `json_encode`) instead of mutating `Object.prototype`.
 *
 * @param {unknown} value
 * @returns {unknown}
 */
export function canonicalizeForHash(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalizeForHash);
  }
  if (value && typeof value === "object") {
    /** @type {Record<string, unknown>} */
    const sorted = Object.create(null);
    for (const key of Object.keys(value).sort()) {
      sorted[key] = canonicalizeForHash(/** @type {Record<string, unknown>} */ (value)[key]);
    }
    return sorted;
  }
  return value;
}
