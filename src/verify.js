/**
 * Orchestrator. Runs the six checks in order and returns a structured
 * result. The CLI is a thin wrapper around this function.
 *
 * Programmatic use:
 *
 *   import { verifyExport } from "@usehasp/verify";
 *   const result = await verifyExport(parsedJson, { skipTsa: false });
 *
 * `result.ok` is the overall pass/fail. `result.checks` is the per-check
 * detail. The CLI's JSON output is a superset of this object.
 */

import { readFileSync } from "node:fs";
import { checkAnchoring } from "./checks/anchoring.js";
import { checkChain } from "./checks/chain.js";
import { checkKeyRevocation } from "./checks/key-revocation.js";
import { checkPublishedKey } from "./checks/published-key.js";
import { checkSchema } from "./checks/schema.js";
import { checkSegmentAnchoring } from "./checks/segment-anchoring.js";
import { checkSignatures } from "./checks/signature.js";
import { checkTsa } from "./checks/tsa.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const VERSION = pkg.version;
export const SCHEMA_VERSION = "1.0";

/**
 * @typedef {Object} VerifyOptions
 * @property {boolean} [skipTsa] skip the RFC 3161 TSA anchor check
 * @property {string} [caFile] trust this local PEM file as the TSA CA instead of the bundled FreeTSA root
 * @property {boolean} [allowUntrustedTsa] fall back to fetching each anchor's own `tsa_cacert_url` (export-supplied, untrusted) instead of the bundled FreeTSA root — opt-in only
 * @property {typeof fetch} [fetcher] inject a fetch implementation (testing)
 * @property {string} [opensslPath] override the `openssl` binary path
 * @property {string} [expectedKey] PEM of the independently-published key (offline trust root)
 * @property {string} [keysFile] local published-keys document to establish the trust root (offline)
 * @property {string} [keysBaseUrl] base URL for the `/trust/keys` endpoint (default app.usehasp.com)
 * @property {boolean} [allowUnanchored] accept an export with zero TSA anchors (pass-with-warning) instead of failing the anchoring check
 */

// A TSA token's genTime is allowed to precede its bound entry's created_at by
// up to this much before the export is treated as backdated. Covers ordinary
// clock skew between the platform host and the TSA, not a deliberate forgery.
const BACKDATING_SKEW_MS = 5 * 60 * 1000;

/**
 * @typedef {{ran: false}
 *   | {ran: false, skipped: true}
 *   | ({ran: true, ok: true} & Record<string, unknown>)
 *   | {ran: true, ok: false, error: string}} CheckResult
 *
 * @typedef {{ran: false}
 *   | ({ran: true} & import("./checks/anchoring.js").AnchoringResult)} AnchoringCheckResult
 *
 * @typedef {Object} VerifyResult
 * @property {boolean} ok overall pass/fail
 * @property {{schema: CheckResult, chain: CheckResult, publishedKey: CheckResult, signatures: CheckResult, anchoring: AnchoringCheckResult, tsa: CheckResult, keyRevocation: CheckResult}} checks
 * @property {string | null} lineage_reset_at ISO timestamp when this org's chain lineage was force-reset (a prefix was truncated outside retention maintenance); null when the lineage is intact. When set, everything that verifies does so only for the post-reset history — pre-reset entries are absent and unverifiable.
 * @property {string | null} fold_base the retained chain's fold base (`verification.fold_base` / `.segment_fold_base`) when a retention purge removed a prefix ahead of this export's window; null when the export is fold-complete from genesis. Never fails verification — a lawful purge is expected — but is surfaced loudly: the purged prefix's own history is not attested by this export.
 */

/**
 * @param {unknown} data parsed audit-export JSON
 * @param {VerifyOptions} [opts]
 * @returns {Promise<VerifyResult>}
 */
export async function verifyExport(data, opts = {}) {
  /** @type {VerifyResult} */
  const out = {
    ok: false,
    checks: {
      schema: { ran: false },
      chain: { ran: false },
      publishedKey: { ran: false },
      signatures: { ran: false },
      anchoring: { ran: false },
      tsa: { ran: false },
      keyRevocation: { ran: false },
    },
    lineage_reset_at: null,
    fold_base: null,
  };

  const schemaResult = checkSchema(data);
  out.checks.schema = { ran: true, ...schemaResult };
  if (!schemaResult.ok) return out;

  // Schema check passed — the export has the shape downstream checks expect.
  const validated = /** @type {any} */ (data);
  const isSegment = validated.variant === "customer_segment";

  // Surface a lineage reset as a first-class notice. It never fails
  // verification — the retained rows verify normally — but it means this
  // export represents only history since the reset; anything before it was
  // truncated outside retention maintenance and is unverifiable here.
  out.lineage_reset_at = validated.verification?.lineage_reset_at ?? null;

  // Surface a retention-purged prefix as a first-class notice, symmetrical to
  // lineage_reset_at above. Unlike a lineage reset, this is the LAWFUL path —
  // fold_base is the platform's own record of the fold state over the rows it
  // purged under normal retention — but it still means this export's history
  // doesn't start at genesis, so a reviewer should never mistake it for one
  // that does.
  out.fold_base = isSegment
    ? (validated.verification?.segment_fold_base ?? null)
    : (validated.verification?.fold_base ?? null);

  const chainResult = checkChain(validated);
  out.checks.chain = { ran: true, ...chainResult };
  if (!chainResult.ok) return out;

  // Establish the trust root: resolve the tenant's independently-published key
  // and require the embedded key to match it. Signatures are then verified
  // against this trusted key, not the one embedded in the export.
  const keyResult = await checkPublishedKey(validated, {
    fetcher: opts.fetcher,
    expectedKey: opts.expectedKey,
    keysFile: opts.keysFile,
    keysBaseUrl: opts.keysBaseUrl,
  });
  if (!keyResult.ok) {
    out.checks.publishedKey = { ran: true, ok: false, error: keyResult.error };
    return out;
  }
  // Drop the live KeyObject(s) from the serializable summary; keep the metadata.
  const isMultiKey = "publicKeys" in keyResult;
  out.checks.publishedKey = {
    ran: true,
    ok: true,
    key_id: isMultiKey ? null : keyResult.key_id,
    // Sorted for deterministic output — Object.keys() order isn't a contract
    // worth relying on for CLI/log/test comparisons across runs or engines.
    ...(isMultiKey ? { key_ids: Object.keys(keyResult.publicKeys).sort() } : {}),
    source: keyResult.source,
  };
  // normalize to one key_id -> status map regardless of
  // single- vs multi-key shape, so checkKeyRevocation() doesn't need to know
  // which envelope variant produced it.
  const keyStatuses = isMultiKey ? keyResult.statuses : { [keyResult.key_id]: keyResult.status };

  const sigResult = checkSignatures(
    validated,
    isMultiKey ? { publicKeys: keyResult.publicKeys } : { publicKey: keyResult.publicKey },
  );
  out.checks.signatures = { ran: true, ...sigResult };
  if (!sigResult.ok) return out;

  // Pure computation, no I/O — always runs, never skipped. Binds every anchor
  // to this export before the TSA check spends effort verifying tokens whose
  // anchored_data might not even be evidence for this export's history. The
  // customer-segment variant binds segment anchors (fold + Merkle inclusion)
  // instead of org fold anchors.
  const anchoringResult = isSegment
    ? checkSegmentAnchoring(validated, { allowUnanchored: opts.allowUnanchored })
    : checkAnchoring(validated, { allowUnanchored: opts.allowUnanchored });
  out.checks.anchoring = { ran: true, ...anchoringResult };
  if (!anchoringResult.ok) return out;

  // Anchor i in tsaAnchors and anchoringResult.bindings[i] are the same
  // anchor: both iterate verification.tsa_anchor_chain (or
  // segment_anchor_chain) in order. Hoisted above the skipTsa branch so both
  // the backdating check and the key-revocation check below can use them —
  // empty when TSA is skipped, which correctly fails closed for any entry
  // signed under a revoked key (no genTime, no proof it predates revocation).
  const bindings = "bindings" in anchoringResult ? anchoringResult.bindings : [];
  /** @type {Array<{genTime: string}>} */
  let tsaAnchors = [];

  if (opts.skipTsa) {
    out.checks.tsa = { ran: false, skipped: true };
  } else {
    // For the segment variant, each RFC 3161 token is over its batch's
    // Merkle ROOT (the inclusion path binds the fold state to it — already
    // verified above), so the TSA check runs against the roots.
    const tsaInput = isSegment
      ? {
          verification: {
            tsa_anchor_chain: validated.verification.segment_anchor_chain.map(
              (/** @type {any} */ a) => ({ ...a, anchored_data: a.merkle_root }),
            ),
          },
        }
      : validated;

    const tsaResult = await checkTsa(tsaInput, {
      fetcher: opts.fetcher,
      opensslPath: opts.opensslPath,
      caFile: opts.caFile,
      allowUntrustedTsa: opts.allowUntrustedTsa,
    });
    out.checks.tsa = { ran: true, ...tsaResult };
    if (!tsaResult.ok) return out;
    tsaAnchors = tsaResult.anchors;

    // Each anchor's parsed genTime must not predate the newest entry it
    // attests — a token whose timestamp is earlier than data it's supposed to
    // cover can only mean the token (or the export) was backdated.
    const backdated = findBackdatedAnchor(validated.entries, bindings, tsaAnchors);
    if (backdated) {
      out.checks.tsa = {
        ran: true,
        ok: false,
        error:
          `TSA anchor ${backdated.index} genTime (${backdated.genTime}) predates its bound entry ` +
          `seq=${backdated.entry.seq} created_at (${backdated.entry.created_at}) by more than ` +
          `${BACKDATING_SKEW_MS / 1000}s — backdated timestamp`,
      };
      return out;
    }
  }

  // a signature under a revoked key fails verification
  // unless a covering anchor's genTime precedes the revocation — reuses the
  // same anchor-binding (`bindings`) and TSA genTime (`tsaAnchors`) data the
  // backdating check above just used.
  const revocationResult = checkKeyRevocation(validated, { keyStatuses, bindings, tsaAnchors });
  out.checks.keyRevocation = { ran: true, ...revocationResult };
  if (!revocationResult.ok) return out;

  out.ok = true;
  return out;
}

/**
 * @param {any[]} entries
 * @param {Array<{bound_seq: number}>} bindings
 * @param {Array<{genTime: string}>} anchors
 * @returns {{index: number, genTime: string, entry: any} | null}
 */
function findBackdatedAnchor(entries, bindings, anchors) {
  for (const [i, anchor] of anchors.entries()) {
    const binding = bindings[i];
    if (!binding) continue;
    const entry = entries.find((/** @type {any} */ e) => e.seq === binding.bound_seq);
    if (!entry) continue;
    const entryMs = Date.parse(entry.created_at);
    const genTimeMs = Date.parse(anchor.genTime);
    if (Number.isNaN(entryMs) || Number.isNaN(genTimeMs)) continue;
    if (genTimeMs < entryMs - BACKDATING_SKEW_MS) {
      return { index: i, genTime: anchor.genTime, entry };
    }
  }
  return null;
}
