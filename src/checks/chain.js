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
 * A fifth slot, `digest_version` (17), is carried by entries sealed under
 * composition version 3 or later. Sealing the version means it cannot be
 * lowered afterwards to hide the two slots before it from verification, and
 * its presence selects byte-ordered object keys for that entry (see
 * `../canonical.js`). Removing or adding the key changes the digest.
 *
 * Then verify the chain links: each `prev_hash` after the first equals the
 * previous entry's `hash`, and the last entry's `hash` must equal
 * `verification.chain_head_hash`. The first entry's `prev_hash` is `null` in
 * an export that starts at the head of the retained chain
 * (`export.range.from === null`). An export of a time window
 * (`export.range.from` set) starts mid-chain, so its first entry's
 * `prev_hash` names the entry just before the window — an entry this export
 * does not contain. It is accepted as given: `prev_hash` is linkage metadata
 * outside the hash and the signature, so it proves nothing on its own, and a
 * windowed export is reported as not genesis-rooted by the anchoring check.
 *
 * `prev_hash` is NOT part of the hash input — the chain is linked by the
 * `prev_hash`/`hash` equality check, not by folding `prev_hash` into the digest.
 *
 * Matches the algorithm the platform uses to seal each audit row and the
 * published manual recipe at /trust/verify.
 */
import { createHash } from "node:crypto";
import { encodeCanonical } from "../canonical.js";

/**
 * @param {{variant?: string, export?: {range?: {from?: string | null}}, entries: any[], verification: {chain_head_hash?: string, segment_head_hash?: string}}} data
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

  // Only the org-grain envelope can be a mid-chain window; a segment export
  // always starts at the head of its retained segment.
  const startsMidChain = !isSegment && (data.export?.range?.from ?? null) !== null;

  /** @type {string | null} */
  let prev = null;
  for (const [index, entry] of data.entries.entries()) {
    if (index === 0 && startsMidChain) {
      prev = entry[linkField];
    }
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
      entry.metadata,
      entry.ip_address,
      entry.created_at,
      entry.phi_disposition ?? null,
      entry.subject_type ?? null,
      entry.subject_id_hmac ?? null,
    ];
    // Presence-conditional extensions (digest-preserving rule). Each is
    // included exactly when the entry carries it; whenever a later slot is
    // present every earlier absent slot is encoded explicitly as null, so
    // stripping, grafting, re-homing, or RELABELING any field changes the
    // recomputed digest and fails this check.
    // Slots 13-17, in cascade order. `digest_version` is the last: present
    // (and >= 3) exactly on entries sealed under the composition that seals
    // the version itself and orders object keys by bytes.
    // Same gate as the platform: the slot exists from version 3. (The schema
    // check rejects a lower value on a real export.)
    const digestVersion =
      Number.isInteger(entry.digest_version) && entry.digest_version >= 3
        ? entry.digest_version
        : null;
    const slots = [
      entry.asserted_actor_hmac ?? null,
      entry.customer_id ?? null,
      entry.caller_attribution ?? null,
      entry.user_agent ?? null,
      digestVersion,
    ];
    let lastPresent = -1;
    for (const [index, value] of slots.entries()) {
      if (value !== null) lastPresent = index;
    }
    fields.push(...slots.slice(0, lastPresent + 1));

    // Not JSON.stringify: the platform's encoder differs from it on floats,
    // U+2028/U+2029, key order and 64-bit integers (see ../canonical.js).
    const payload = encodeCanonical(fields, digestVersion !== null);
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
