/**
 * Check 1: hash chain integrity.
 *
 * For each entry, recompute the row hash exactly as the HASP platform's
 * `AuditLog::computeHashFromAttributes()` does — SHA-256 over a positional
 * JSON array of the entry's canonical columns (metadata recursively
 * key-sorted) — and check it equals the declared `entry.hash`. The base form
 * is 12 elements, extended presence-conditionally under the digest-preserving
 * extension rule: an integrator-asserted actor binding appends
 * `asserted_actor_hmac`, and end-customer attribution appends `customer_id`
 * ordered after it — with the asserted slot encoded as an explicit null
 * whenever the customer slot is present, so the two extensions can never be
 * confused for one another (injectivity). Entries with neither field (all
 * prior history) hash byte-identically to the original 12-element form.
 *
 * The multi-key work extends the same cascade with two more presence-conditional slots:
 * `caller_attribution` (15) and `user_agent` (16). The platform only ever
 * populates these keys on an exported entry when the underlying row was
 * sealed under digest_version >= 2 AND the value is non-null — a legacy row
 * (sealed before the multi-key change) never carries either key in its export entry, even
 * though the raw column may hold data, because that data was never part of
 * its hash. So this check needs no notion of "digest_version" itself: key
 * presence in the entry IS the signal, exactly like the two slots before it.
 *
 * Then verify the chain links: `entries[0].prev_hash` is `null` and each
 * subsequent `prev_hash` equals the previous entry's `hash`. Finally, the
 * last entry's `hash` must equal `verification.chain_head_hash`.
 *
 * `prev_hash` is NOT part of the hash input — the chain is linked by the
 * `prev_hash`/`hash` equality check, not by folding `prev_hash` into the digest.
 *
 * Matches the algorithm the platform uses to seal each audit row and the
 * published manual recipe at /trust/verify.
 */
import { createHash } from "node:crypto";
import { canonicalizeForHash } from "../canonical.js";

/**
 * @param {{variant?: string, entries: any[], verification: {chain_head_hash?: string, segment_head_hash?: string}}} data
 * @returns {{ok: true, count: number} | {ok: false, error: string}}
 */
export function checkChain(data) {
  // The customer-segment variant links entries by `segment_prev_hash` (its
  // org-chain `prev_hash` is deliberately absent) and declares its head as
  // `segment_head_hash`. Hash recomputation is identical in both variants.
  const isSegment = data.variant === "customer_segment";
  const linkField = isSegment ? "segment_prev_hash" : "prev_hash";
  const declaredHead = isSegment
    ? data.verification.segment_head_hash
    : data.verification.chain_head_hash;

  /** @type {string | null} */
  let prev = null;
  for (const entry of data.entries) {
    if (entry[linkField] !== prev) {
      return {
        ok: false,
        error: `entry seq=${entry.seq} ${linkField} mismatch: declared ${fmt(entry[linkField])}, expected ${fmt(prev)}`,
      };
    }

    const fields = [
      entry.user_id,
      entry.org_id,
      entry.project_id ?? null,
      entry.action,
      entry.entity_type,
      entry.entity_id,
      canonicalizeForHash(entry.metadata),
      entry.ip_address,
      entry.created_at,
      entry.phi_disposition ?? null,
      entry.subject_type ?? null,
      entry.subject_id_hmac ?? null,
    ];
    // Presence-conditional extensions (digest-preserving rule): the asserted
    // actor binding is slot 13, end-customer attribution slot 14, caller
    // attribution slot 15, user_agent slot 16. Each is
    // included exactly when the entry carries it; whenever a later slot is
    // present every earlier absent slot is encoded explicitly as null, so
    // stripping, grafting, re-homing, or RELABELING any field changes the
    // recomputed digest and fails this check.
    const asserted = entry.asserted_actor_hmac ?? null;
    const customer = entry.customer_id ?? null;
    const callerAttribution = entry.caller_attribution ?? null;
    const userAgent = entry.user_agent ?? null;
    const callerAttributionPresent = callerAttribution !== null;
    const userAgentPresent = userAgent !== null;
    if (asserted !== null || customer !== null || callerAttributionPresent || userAgentPresent) {
      fields.push(asserted);
    }
    if (customer !== null || callerAttributionPresent || userAgentPresent) {
      fields.push(customer);
    }
    if (callerAttributionPresent || userAgentPresent) {
      fields.push(canonicalizeForHash(callerAttribution));
    }
    if (userAgentPresent) {
      fields.push(userAgent);
    }
    const payload = JSON.stringify(fields);
    const computed = createHash("sha256").update(payload).digest("hex");
    if (computed !== entry.hash) {
      return {
        ok: false,
        error: `chain broken at seq=${entry.seq}: computed ${computed}, declared ${entry.hash}`,
      };
    }
    prev = entry.hash;
  }

  if (prev !== declaredHead) {
    return {
      ok: false,
      error: `chain head mismatch: computed ${fmt(prev)}, declared ${declaredHead}`,
    };
  }
  return { ok: true, count: data.entries.length };
}

/** @param {string | null} v */
function fmt(v) {
  return v === null ? "null" : v;
}
