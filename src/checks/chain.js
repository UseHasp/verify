/**
 * Check: hash chain integrity.
 *
 * Three independent guarantees, all recomputable from the envelope alone:
 *
 *   1. Integrity — for every entry, the integrity hash recomputed from its
 *      audit-log fields (see src/hash.js) equals the declared `entry.hash`.
 *      Any mutation of a hashed field breaks this.
 *   2. Linkage — every entry's `prev_hash` equals the previous entry's `hash`
 *      (the separate `prev_hash` column check; the integrity hash does NOT fold
 *      in `prev_hash`). This proves no entry was inserted or removed between two
 *      that remain.
 *   3. Anchoring — `chain_head_hash` equals the last entry's `hash`, and every
 *      TSA anchor's `anchored_data` equals the `hash` of the entry at its
 *      `checkpoint_after_entry`. This binds the timestamp(s) to this chain.
 *
 * Note on slices: an export may be a window of a longer chain, so the FIRST
 * entry's `prev_hash` legitimately points at a row outside the export. Linkage
 * is therefore only asserted between consecutive entries that are both present.
 */
import { computeIntegrityHash } from "../hash.js";

/**
 * @param {{entries: any[], verification: {chain_head_hash: string, tsa_anchor_chain: any[]}}} data
 * @returns {{ok: true, count: number} | {ok: false, error: string}}
 */
export function checkChain(data) {
  const entries = data.entries;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    const computed = computeIntegrityHash(entry);
    if (computed !== entry.hash) {
      return {
        ok: false,
        error: `chain broken at entry ${i + 1}: recomputed hash ${computed}, declared ${entry.hash}`,
      };
    }

    if (i > 0 && entry.prev_hash !== entries[i - 1].hash) {
      return {
        ok: false,
        error: `chain linkage broken at entry ${i + 1}: prev_hash ${entry.prev_hash} does not match previous entry hash ${entries[i - 1].hash}`,
      };
    }
  }

  const head = entries[entries.length - 1].hash;
  if (head !== data.verification.chain_head_hash) {
    return {
      ok: false,
      error: `chain head mismatch: last entry hash ${head}, declared chain_head_hash ${data.verification.chain_head_hash}`,
    };
  }

  // Each TSA checkpoint must anchor the hash of an actual entry in this export.
  for (const [i, anchor] of data.verification.tsa_anchor_chain.entries()) {
    const pos = anchor.checkpoint_after_entry;
    if (!Number.isInteger(pos) || pos < 1 || pos > entries.length) {
      return {
        ok: false,
        error: `tsa_anchor_chain[${i}].checkpoint_after_entry ${pos} is out of range (1..${entries.length})`,
      };
    }
    const checkpointHash = entries[pos - 1].hash;
    if (anchor.anchored_data !== checkpointHash) {
      return {
        ok: false,
        error: `tsa_anchor_chain[${i}].anchored_data ${anchor.anchored_data} does not match the hash of entry ${pos} (${checkpointHash})`,
      };
    }
  }

  return { ok: true, count: entries.length };
}
