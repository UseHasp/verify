/**
 * Check: segment anchor binding (customer-segment envelope variant).
 *
 * The segment-grain analogue of `anchoring.js`. A segment anchor
 * (`algo: "sha256-fold-merkle-v1"`) is the tuple of a segment fold state, a
 * Merkle inclusion path, and (at the TSA layer) a token over the batch root.
 * Binding an anchor to THIS export means:
 *
 *   1. Recompute the segment history fold from the export's fold base —
 *      `verification.segment_fold_base` when present (the platform's
 *      retention purge rebases the segment fold at the retention boundary),
 *      GENESIS otherwise — through the anchored entry's position. It must
 *      equal the anchor's `fold_state`. This attests the ENTIRE segment
 *      prefix — existence, content, order, and count.
 *   2. Recompute the batch root from `fold_state` along `merkle_path`. It
 *      must equal `merkle_root` — the value the RFC 3161 token is over
 *      (verified by the TSA check).
 *
 * Soundness does not depend on trusting `segment_fold_base` or the path: a
 * tampered base, thinned/reordered entries, or a forged path cannot
 * reproduce an already-issued token's root without inverting SHA-256.
 *
 * Zero anchors fails closed unless `allowUnanchored` is set. On success,
 * coverage is reported exactly like the org check: the highest fold-bound
 * entry, plus any newer entries as signed-but-not-yet-anchored.
 */
import { foldFrom } from "../fold.js";
import { rootFromPath } from "../merkle.js";

/**
 * @typedef {import("./anchoring.js").AnchoringCoverage} AnchoringCoverage
 *
 * @typedef {{ok: true, attested: "none"}
 *   | {ok: true, attested?: undefined, bindings: any[], coverage: AnchoringCoverage}
 *   | {ok: false, error: string}} SegmentAnchoringResult
 */

/**
 * @param {{entries: Array<{id: string, seq: number, hash: string}>, verification: {segment_anchor_chain: any[], segment_fold_base?: string | null}}} data
 * @param {{allowUnanchored?: boolean}} [opts]
 * @returns {SegmentAnchoringResult}
 */
export function checkSegmentAnchoring(data, opts = {}) {
  const anchors = data.verification.segment_anchor_chain;
  const entries = data.entries;

  if (anchors.length === 0) {
    if (opts.allowUnanchored) {
      return { ok: true, attested: "none" };
    }
    return {
      ok: false,
      error:
        "export is not time-attested (zero anchors in .verification.segment_anchor_chain) — " +
        "pass --allow-unanchored (or allowUnanchored: true) to explicitly accept an unattested export",
    };
  }

  const foldBase = data.verification.segment_fold_base ?? undefined;

  const bindings = [];
  let maxPosition = 0;

  for (const [i, anchor] of anchors.entries()) {
    const position = entries.findIndex((e) => e.id === anchor.anchored_entry_id);
    if (position === -1) {
      return {
        ok: false,
        error:
          `segment anchor ${i} anchored_entry_id ${JSON.stringify(anchor.anchored_entry_id)} is not ` +
          `among the exported entries — request a fresh scoped export for time attestation`,
      };
    }

    const computedFold = foldFrom(
      entries.slice(0, position + 1).map((e) => e.hash),
      foldBase,
    );
    if (computedFold !== anchor.fold_state) {
      return {
        ok: false,
        error:
          `segment anchor ${i} fold mismatch: computed ${computedFold}, declared ${anchor.fold_state} — ` +
          `the exported segment does not match the history this anchor attests`,
      };
    }

    const computedRoot = rootFromPath(anchor.fold_state, anchor.merkle_path);
    if (computedRoot !== anchor.merkle_root) {
      return {
        ok: false,
        error:
          `segment anchor ${i} inclusion mismatch: path recomputes root ${computedRoot}, declared ` +
          `${anchor.merkle_root} — the anchor's fold state is not bound to its batch root`,
      };
    }

    const boundPosition = position + 1;
    bindings.push({
      index: i,
      algo: anchor.algo,
      fold_state: anchor.fold_state,
      merkle_root: anchor.merkle_root,
      anchored_entry_id: anchor.anchored_entry_id,
      bound_seq: entries[position].seq,
      bound_position: boundPosition,
    });
    if (boundPosition > maxPosition) maxPosition = boundPosition;
  }

  const total = entries.length;

  return {
    ok: true,
    bindings,
    coverage: {
      attested_through_seq: maxPosition > 0 ? entries[maxPosition - 1].seq : null,
      row_level_attestations: [],
      unattested_from_seq: maxPosition < total ? entries[maxPosition].seq : null,
      total_entries: total,
    },
  };
}
