/**
 * Check 1: hash chain integrity.
 *
 * For each entry, recompute `hash` as the SHA-256 of the canonical twelve-field
 * payload (see src/canonical.js) and compare against the declared `entry.hash`.
 * `prev_hash` is NOT part of the hash — it is a separate linkage column.
 *
 * Linkage mirrors the platform's own verifier (AuditExportEnvelopeTest, "Check
 * (b)"): walking the entries in order, each entry's `prev_hash` must equal the
 * previous entry's `hash`. The first entry's `prev_hash` is the chain anchor
 * (`null` at genesis, or a pre-window hash for a windowed export) and is not
 * linkage-checked — only recomputed. Finally, the last entry's `hash` must
 * equal `verification.chain_head_hash`.
 */
import { createHash } from "node:crypto";
import { canonicalEntryPayload } from "../canonical.js";

// Genesis anchor: the platform writes `previous_hash = null` for the first
// entry in a chain, surfaced as `prev_hash: null` in the envelope. It is NOT
// 64 zeros. Windowed exports may instead carry a real pre-window hash here.
export const GENESIS_PREV_HASH = null;

/**
 * @param {{entries: any[], verification: {chain_head_hash: string}}} data
 * @returns {{ok: true, count: number} | {ok: false, error: string}}
 */
export function checkChain(data) {
  /** @type {string | null} */
  let prev = GENESIS_PREV_HASH;
  for (const [i, entry] of data.entries.entries()) {
    // Linkage: every entry after the anchor must point at its predecessor.
    if (prev !== null && entry.prev_hash !== prev) {
      return {
        ok: false,
        error: `entry[${i}] prev_hash mismatch: declared ${fmt(entry.prev_hash)}, expected ${fmt(prev)} (previous entry's hash)`,
      };
    }
    const computed = createHash("sha256").update(canonicalEntryPayload(entry)).digest("hex");
    if (computed !== entry.hash) {
      return {
        ok: false,
        error: `chain broken at entry[${i}]: computed ${computed}, declared ${entry.hash}`,
      };
    }
    prev = entry.hash;
  }
  if (prev !== data.verification.chain_head_hash) {
    return {
      ok: false,
      error: `chain head mismatch: computed ${fmt(prev)}, declared ${data.verification.chain_head_hash}`,
    };
  }
  return { ok: true, count: data.entries.length };
}

/** @param {unknown} v */
function fmt(v) {
  return v === null ? "null (genesis)" : String(v);
}
