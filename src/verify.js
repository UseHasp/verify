/**
 * Orchestrator. Runs the four checks in order and returns a structured
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
import { checkChain } from "./checks/chain.js";
import { checkSchema } from "./checks/schema.js";
import { checkSignatures } from "./checks/signature.js";
import { checkTsa } from "./checks/tsa.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const VERSION = pkg.version;
export const SCHEMA_VERSION = "1.0";

/**
 * @typedef {Object} VerifyOptions
 * @property {boolean} [skipTsa] skip the RFC 3161 TSA anchor check
 * @property {string} [caFile] read TSA CA cert from this local PEM file instead of fetching `tsa_cacert_url`
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
 * @property {{schema: CheckResult, chain: CheckResult, signatures: CheckResult, tsa: CheckResult}} checks
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

  const sigResult = checkSignatures(validated);
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
