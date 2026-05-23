/**
 * Canonical JSON serialization for hashing and signing.
 *
 * Matches the generator at
 * apps/marketing/scripts/generate-audit-sample.js in usehasp/hasp-monorepo:
 *
 *   JSON.stringify(obj, (key, value) => {
 *     if (value && typeof value === "object" && !Array.isArray(value)) {
 *       return Object.keys(value).sort().reduce((a, k) => (a[k] = value[k], a), {});
 *     }
 *     return value;
 *   })
 *
 * Behaviour: object keys sorted lexicographically at every level;
 * arrays kept in order; no whitespace (default JSON.stringify spacing = 0).
 *
 * Implementation note: the reviver accumulator uses Object.create(null) so a
 * malicious export containing a literal `__proto__` key cannot pollute
 * Object.prototype during canonicalization. JSON.stringify still emits the
 * key as `"__proto__"`, preserving byte-for-byte equivalence with the
 * generator output.
 *
 * @param {unknown} obj
 * @returns {string}
 */
export function canonicalSorted(obj) {
  return JSON.stringify(obj, (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return Object.keys(value)
        .sort()
        .reduce(
          /** @param {Record<string, unknown>} acc */
          (acc, k) => {
            acc[k] = value[k];
            return acc;
          },
          /** @type {Record<string, unknown>} */ (Object.create(null)),
        );
    }
    return value;
  });
}
