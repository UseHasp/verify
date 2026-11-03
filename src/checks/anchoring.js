/**
 * Check: anchor binding (anchor-v2 contract §4a).
 *
 * Runs unconditionally — pure computation, no I/O, never skipped — right
 * after signatures and before the TSA check. It answers a question the TSA
 * check alone cannot: is each anchor actually evidence for THIS export?
 *
 * Two anchor versions, identified by `algo` (absent = v1):
 *
 *   - **v1 (`row-hash-v1`)**: `anchored_data` must equal some exported
 *     entry's `hash`. Attests that ONE ROW existed at token time.
 *   - **v2 (`sha256-fold-v2`)**: requires a genesis-rooted export
 *     (`export.range.from === null`) and `anchored_entry_id` present among
 *     the exported entries. Recomputes the history fold from the export's
 *     fold base — `verification.fold_base` when present (the platform's
 *     retention purge rebases the fold at the retention boundary; the value
 *     is the fold state over the purged prefix), GENESIS otherwise — through
 *     that entry's position (see `../fold.js`); it must equal `anchored_data`.
 *     Attests the ENTIRE PREFIX since the fold base — existence, content,
 *     order, and count — up to and including that entry.
 *
 * Any anchor that cannot be bound fails the check closed: an attacker who
 * rewrites an already-anchored entry (and re-signs it with a compromised or
 * legitimately-held key) breaks the fold recomputation even though the row
 * hash chain and signatures still verify — this is the gap v2 anchoring
 * closes over v1.
 *
 * Zero anchors fails closed ("export is not time-attested") unless
 * `allowUnanchored` is set, which yields pass-with-warning (`attested:
 * "none"`) — the export is verifiable but not proven to have existed at any
 * particular time.
 *
 * On success, reports coverage: the highest v2-bound position (if any) marks
 * how much of the prefix carries the strong "prefix existed as anchored"
 * proof; v1 bindings are reported as row-level attestations; anything after
 * the highest v2-bound position is signed but not yet anchored.
 */
import { foldFrom } from "../fold.js";

/**
 * @typedef {Object} AnchorBinding
 * @property {number} index index into verification.tsa_anchor_chain
 * @property {"row-hash-v1" | "sha256-fold-v2"} algo
 * @property {string} anchored_data
 * @property {number} bound_seq the seq of the entry this anchor is bound to
 * @property {string} [anchored_entry_id] v2 only
 * @property {number} [bound_position] v2 only — 1-indexed position within the exported entries
 */

/**
 * @typedef {Object} AnchoringCoverage
 * @property {number | null} attested_through_seq highest seq covered by a bound v2 (history-fold) anchor, or null if none
 * @property {number[]} row_level_attestations seqs individually attested by a bound v1 (row-hash) anchor
 * @property {number | null} unattested_from_seq first seq after attested_through_seq that is signed but not yet anchored, or null if full coverage
 * @property {number} total_entries
 */

/**
 * @typedef {{ok: true, attested: "none"}
 *   | {ok: true, attested?: undefined, bindings: AnchorBinding[], coverage: AnchoringCoverage}
 *   | {ok: false, error: string}} AnchoringResult
 */

/**
 * @param {{export: {range: {from: string | null}}, entries: Array<{id: string, seq: number, hash: string}>, verification: {tsa_anchor_chain: any[], fold_base?: string | null}}} data
 * @param {{allowUnanchored?: boolean}} [opts]
 * @returns {AnchoringResult}
 */
export function checkAnchoring(data, opts = {}) {
  const anchors = data.verification.tsa_anchor_chain;
  const entries = data.entries;

  if (anchors.length === 0) {
    if (opts.allowUnanchored) {
      return { ok: true, attested: "none" };
    }
    return {
      ok: false,
      error:
        "export is not time-attested (zero anchors in .verification.tsa_anchor_chain) — " +
        "pass --allow-unanchored (or allowUnanchored: true) to explicitly accept an unattested export",
    };
  }

  const genesisRooted = data.export.range.from === null;
  // Where the fold recomputation starts: the envelope's declared fold base
  // (set when a retention purge rebased the chain at the retention
  // boundary), or GENESIS when absent/null. Soundness does not depend on
  // trusting this value — a tampered fold_base (or tampered entries) cannot
  // reproduce an already-issued token's anchored_data without inverting the
  // SHA-256 fold.
  const foldBase = data.verification.fold_base ?? undefined;

  /** @type {AnchorBinding[]} */
  const bindings = [];
  /** @type {number[]} */
  const rowLevelSeqs = [];
  let maxV2Position = 0; // 1-indexed position within `entries`, 0 = no v2 anchor bound

  for (const [i, anchor] of anchors.entries()) {
    const algo = anchor.algo ?? "row-hash-v1";

    if (algo === "row-hash-v1") {
      const match = entries.find((e) => e.hash === anchor.anchored_data);
      if (!match) {
        return {
          ok: false,
          error:
            `anchor ${i} (row-hash-v1) anchored_data does not match any exported entry's hash — ` +
            `request a full export for time attestation`,
        };
      }
      bindings.push({ index: i, algo, anchored_data: anchor.anchored_data, bound_seq: match.seq });
      rowLevelSeqs.push(match.seq);
      continue;
    }

    // algo === "sha256-fold-v2" — schema.js already rejects any other value.
    if (!genesisRooted) {
      return {
        ok: false,
        error:
          `anchor ${i} (sha256-fold-v2) cannot be bound: this export is not genesis-rooted ` +
          `(.export.range.from is not null) — request a full export for time attestation`,
      };
    }
    const entryId = anchor.anchored_entry_id;
    const position = entries.findIndex((e) => e.id === entryId);
    if (position === -1) {
      return {
        ok: false,
        error:
          `anchor ${i} (sha256-fold-v2) anchored_entry_id ${JSON.stringify(entryId)} is not among ` +
          `the exported entries — request a full export for time attestation`,
      };
    }
    const computed = foldFrom(
      entries.slice(0, position + 1).map((e) => e.hash),
      foldBase,
    );
    if (computed !== anchor.anchored_data) {
      return {
        ok: false,
        error:
          `anchor ${i} (sha256-fold-v2) fold mismatch: computed ${computed}, declared ` +
          `${anchor.anchored_data} — the exported chain does not match the history this anchor attests`,
      };
    }
    const boundPosition = position + 1;
    bindings.push({
      index: i,
      algo,
      anchored_data: anchor.anchored_data,
      anchored_entry_id: entryId,
      bound_seq: entries[position].seq,
      bound_position: boundPosition,
    });
    if (boundPosition > maxV2Position) maxV2Position = boundPosition;
  }

  const total = entries.length;
  const attestedThroughSeq = maxV2Position > 0 ? entries[maxV2Position - 1].seq : null;
  const unattestedFromSeq = maxV2Position < total ? entries[maxV2Position].seq : null;

  return {
    ok: true,
    bindings,
    coverage: {
      attested_through_seq: attestedThroughSeq,
      row_level_attestations: rowLevelSeqs,
      unattested_from_seq: unattestedFromSeq,
      total_entries: total,
    },
  };
}
