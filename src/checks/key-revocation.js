/**
 * Check (f): signing-key revocation (ADR-JVSATA §4).
 *
 * Rotation moves *future* signatures to a new key version; it cannot
 * repudiate a compromised key — every already-signed row keeps its original
 * `signing_key_id`, and the retired key stays published as trustworthy
 * forever. Revocation closes that gap: a signing key can be marked
 * `revoked` (`./published-key.js` resolves this status from the trusted
 * published-keys source — never from the export itself, which an attacker
 * controls).
 *
 * Rule: a signature under a revoked key FAILS verification, UNLESS the
 * entry is bound by a TSA anchor (the SAME anchor-binding machinery
 * `../checks/anchoring.js` already computed) whose `genTime` precedes the
 * key's `revoked_at` — proving the signature existed before the compromise.
 * That case PASSES, but with a loud, distinct notice
 * (`signed_under_later_revoked_key`) rather than silently.
 *
 * Runs after the anchoring and TSA checks (it needs their output: which
 * anchor covers which entry, and each anchor's TSA-attested `genTime`). When
 * `--skip-tsa` is set, there is no `genTime` to prove pre-dating with, so any
 * entry signed under a revoked key fails closed — the same "no anchor, no
 * proof" outcome as an entry with no covering anchor at all.
 */

/**
 * @typedef {Object} RevocationNotice
 * @property {"signed_under_later_revoked_key"} type
 * @property {number} entry_seq
 * @property {string} key_id
 * @property {string} revoked_at
 * @property {string} anchor_gen_time the covering anchor's genTime, which precedes revoked_at
 *
 * @typedef {{ok: true, notices: RevocationNotice[]} | {ok: false, error: string}} KeyRevocationResult
 */

/**
 * A fold-style anchor (v2 org fold, or the segment Merkle fold) attests
 * every entry up to and including `bound_seq`; a row-hash-v1 anchor attests
 * only the single entry it names.
 *
 * @param {string} algo
 * @param {number} boundSeq
 * @param {number} seq
 */
function anchorCovers(algo, boundSeq, seq) {
  return algo === "row-hash-v1" ? boundSeq === seq : boundSeq >= seq;
}

/**
 * The earliest (smallest genTime) TSA-attested anchor that covers `seq`, or
 * null if none does. Earliest, not merely "any", because it gives the
 * tightest — and therefore most likely to precede an early revocation —
 * proof that the entry existed at that time.
 *
 * @param {number} seq
 * @param {Array<{index: number, algo: string, bound_seq: number}>} bindings
 * @param {Array<{genTime: string}>} tsaAnchors bindings[i] and tsaAnchors[i] are the same anchor (both index verification.tsa_anchor_chain / segment_anchor_chain in order)
 * @returns {{genTime: string} | null}
 */
function earliestCoveringAnchor(seq, bindings, tsaAnchors) {
  /** @type {{genTime: string} | null} */
  let best = null;

  for (const binding of bindings) {
    const anchor = tsaAnchors[binding.index];
    if (!anchor || !anchorCovers(binding.algo, binding.bound_seq, seq)) continue;

    if (!best || Date.parse(anchor.genTime) < Date.parse(best.genTime)) {
      best = anchor;
    }
  }

  return best;
}

/**
 * @param {{entries: Array<{seq: number, key_id?: string}>, verification: {key_id?: string}}} data
 * @param {{
 *   keyStatuses: Record<string, {status?: string, revoked_at?: string | null}>,
 *   bindings: Array<{index: number, algo: string, bound_seq: number}>,
 *   tsaAnchors: Array<{genTime: string}>,
 * }} ctx
 * @returns {KeyRevocationResult}
 */
export function checkKeyRevocation(data, ctx) {
  /** @type {RevocationNotice[]} */
  const notices = [];

  for (const entry of data.entries) {
    // Single-key exports never carry a per-entry key_id — every
    // entry is signed by verification.key_id.
    const keyId = entry.key_id ?? data.verification.key_id;
    if (typeof keyId !== "string") continue;

    const keyStatus = ctx.keyStatuses[keyId];
    if (keyStatus?.status !== "revoked" || typeof keyStatus.revoked_at !== "string") {
      continue;
    }

    const revokedAtMs = Date.parse(keyStatus.revoked_at);
    const anchor = earliestCoveringAnchor(entry.seq, ctx.bindings, ctx.tsaAnchors);
    const anchorMs = anchor ? Date.parse(anchor.genTime) : NaN;

    if (anchor && !Number.isNaN(revokedAtMs) && !Number.isNaN(anchorMs) && anchorMs < revokedAtMs) {
      notices.push({
        type: "signed_under_later_revoked_key",
        entry_seq: entry.seq,
        key_id: keyId,
        revoked_at: keyStatus.revoked_at,
        anchor_gen_time: anchor.genTime,
      });
      continue;
    }

    return {
      ok: false,
      error:
        `entry seq=${entry.seq} is signed under key ${JSON.stringify(keyId)}, which was revoked at ` +
        `${keyStatus.revoked_at}` +
        (anchor
          ? ` — its covering anchor's genTime (${anchor.genTime}) does not precede the revocation`
          : " and no TSA anchor covers it that could prove the signature predates the revocation"),
    };
  }

  return { ok: true, notices };
}
