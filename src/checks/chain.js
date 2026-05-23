/**
 * Check 1: hash chain integrity.
 *
 * For each entry, compute SHA-256 of (prev_hash_hex || canonical_payload),
 * where canonical_payload is the entry with the `hash` and `signature`
 * fields removed and object keys sorted.
 *
 * Matches the algorithm in apps/marketing/scripts/generate-audit-sample.js
 * and the published manual recipe at /trust/verify.
 */
import { createHash } from "node:crypto";
import { canonicalSorted } from "../canonical.js";

const ZERO_HASH = "0".repeat(64);

/**
 * @param {{entries: any[], verification: {chain_head_hash: string}}} data
 * @returns {{ok: true, count: number} | {ok: false, error: string}}
 */
export function checkChain(data) {
  let prev = ZERO_HASH;
  for (const entry of data.entries) {
    if (entry.prev_hash !== prev) {
      return {
        ok: false,
        error: `entry seq=${entry.seq} prev_hash mismatch: declared ${entry.prev_hash}, computed ${prev}`,
      };
    }
    const { hash, signature, ...rest } = entry;
    void signature;
    const payload = canonicalSorted(rest);
    const computed = createHash("sha256")
      .update(prev + payload)
      .digest("hex");
    if (computed !== hash) {
      return {
        ok: false,
        error: `chain broken at seq=${entry.seq}: computed ${computed}, declared ${hash}`,
      };
    }
    prev = hash;
  }
  if (prev !== data.verification.chain_head_hash) {
    return {
      ok: false,
      error: `chain head mismatch: computed ${prev}, declared ${data.verification.chain_head_hash}`,
    };
  }
  return { ok: true, count: data.entries.length };
}
