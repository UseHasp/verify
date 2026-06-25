/**
 * Orchestrator. Runs the checks in order and returns a structured result. The
 * CLI is a thin wrapper around this function.
 *
 * Programmatic use:
 *
 *   import { verifyExport } from "@usehasp/verify";
 *   const result = await verifyExport(parsedJson, { skipTsa: false });
 *
 * `result.ok` is the overall pass/fail. `result.checks` is the per-check detail.
 *
 * Order: schema (preflight) → chain (offline integrity + linkage) →
 * published-key (fetch + match) → signatures (against the matched key) →
 * TSA anchor. Each step short-circuits on failure.
 */

import { readFileSync } from "node:fs";
import { checkChain } from "./checks/chain.js";
import { checkPublishedKey } from "./checks/key.js";
import { checkSchema } from "./checks/schema.js";
import { checkSignatures } from "./checks/signature.js";
import { checkTsa } from "./checks/tsa.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const VERSION = pkg.version;
export const SCHEMA_VERSION = "1.0";

/**
 * @typedef {Object} VerifyOptions
 * @property {boolean} [skipTsa] skip the RFC 3161 TSA anchor check
 * @property {boolean} [skipKeyCheck] skip the published-key fetch + match; verify signatures against the embedded key (provenance unconfirmed)
 * @property {string} [caFile] read TSA CA cert from this local PEM file instead of fetching `tsa_cacert_url`
 * @property {string} [keysFile] read the published-keys document from this local JSON file instead of fetching it
 * @property {string} [keysUrl] override the published-keys URL
 * @property {typeof fetch} [fetcher] inject a fetch implementation (testing)
 * @property {string} [opensslPath] override the `openssl` binary path
 */

/**
 * @typedef {{ran: false}
 *   | {ran: false, skipped: true}
 *   | ({ran: true, ok: true} & Record<string, unknown>)
 *   | {ran: true, ok: false, error: string}} CheckResult
 *
 * @typedef {Object} VerifyResult
 * @property {boolean} ok overall pass/fail
 * @property {{schema: CheckResult, chain: CheckResult, key: CheckResult, signatures: CheckResult, tsa: CheckResult}} checks
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
      key: { ran: false },
      signatures: { ran: false },
      tsa: { ran: false },
    },
  };

  const schemaResult = checkSchema(data);
  out.checks.schema = { ran: true, ...schemaResult };
  if (!schemaResult.ok) return out;

  // Schema check passed — the export has the shape downstream checks expect.
  const validated = /** @type {any} */ (data);

  const chainResult = checkChain(validated);
  out.checks.chain = { ran: true, ...chainResult };
  if (!chainResult.ok) return out;

  // Establish which key to trust. By default, the published key (fetched or
  // read from --keys-file). With --skip-key-check, fall back to the embedded
  // key, whose provenance is then unconfirmed.
  let trustedKeyPem = validated.verification.public_key_pem;
  if (opts.skipKeyCheck) {
    out.checks.key = { ran: false, skipped: true };
  } else {
    const keyResult = await checkPublishedKey(validated, {
      fetcher: opts.fetcher,
      keysFile: opts.keysFile,
      keysUrl: opts.keysUrl,
    });
    out.checks.key = { ran: true, ...keyResult };
    if (!keyResult.ok) return out;
    trustedKeyPem = keyResult.trustedPublicKeyPem;
  }

  const sigResult = checkSignatures(validated, trustedKeyPem);
  out.checks.signatures = { ran: true, ...sigResult };
  if (!sigResult.ok) return out;

  if (opts.skipTsa) {
    out.checks.tsa = { ran: false, skipped: true };
  } else {
    const tsaResult = await checkTsa(validated, {
      fetcher: opts.fetcher,
      opensslPath: opts.opensslPath,
      caFile: opts.caFile,
    });
    out.checks.tsa = { ran: true, ...tsaResult };
    if (!tsaResult.ok) return out;
  }

  out.ok = true;
  return out;
}
