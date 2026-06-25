/**
 * Per-entry integrity hash.
 *
 * `entry.hash` is the row's `integrity_hash`: the SHA-256 (hex) of a JSON array
 * of these audit-log columns, in this exact order, with `metadata` recursively
 * key-sorted and the whole array encoded with unescaped slashes + unicode:
 *
 *   [ user_id, org_id, project_id, action, entity_type, entity_id, metadata,
 *     ip_address, created_at, phi_disposition, subject_type, subject_id_hmac ]
 *
 * The hash deliberately does NOT fold in `prev_hash` — chain linkage is the
 * separate `entry.prev_hash === previousEntry.hash` check (see checks/chain.js).
 * Reference: `AuditLog::computeHashFromAttributes()` on the platform.
 *
 * This module is the single source of truth for the encoding: it is imported by
 * both the verifier (checks/chain.js) and the fixture generator
 * (scripts/build-fixtures.mjs), so the two cannot drift.
 */
import { createHash } from "node:crypto";
import { canonicalize, encodeForHash } from "./canonical.js";

/**
 * The audit-log columns, in the exact order the integrity hash serializes them.
 * @type {readonly string[]}
 */
export const INTEGRITY_FIELDS = Object.freeze([
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
 * Build the canonical hash input array for an entry: each integrity field in
 * order, with `metadata` recursively key-sorted. Missing fields are encoded as
 * JSON `null` (matching a SQL NULL column on the platform).
 *
 * @param {Record<string, unknown>} entry
 * @returns {unknown[]}
 */
export function integrityArray(entry) {
  return INTEGRITY_FIELDS.map((field) => {
    const value = field in entry ? entry[field] : null;
    if (value === undefined) return null;
    return field === "metadata" ? canonicalize(value) : value;
  });
}

/**
 * Compute an entry's integrity hash (lowercase SHA-256 hex).
 *
 * @param {Record<string, unknown>} entry
 * @returns {string}
 */
export function computeIntegrityHash(entry) {
  const json = encodeForHash(integrityArray(entry));
  return createHash("sha256").update(json, "utf8").digest("hex");
}
