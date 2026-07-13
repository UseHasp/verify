/**
 * Orchestrator. Runs the checks in order and returns a structured result. The
 * CLI is a thin wrapper around this function.
 *
 * Pipeline: schema → chain → publishedKey → signatures → tsa. It short-circuits
 * on the first failure. The `publishedKey` check resolves the tenant's
 * independently-published key and proves the embedded key matches it; the
 * signature check then verifies against that trusted key. This is what makes a
 * whole-chain forgery (attacker regenerates + re-signs with their own key)
 * fail closed instead of passing.
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
import { checkPublishedKey } from "./checks/published-key.js";
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
 * @property {string} [keyFile] read the independently-published signing key from this local PEM file instead of fetching `/trust/keys`
 * @property {string} [expectedKey] the independently-published signing key as a PEM string (programmatic offline use)
 * @property {string} [keysBaseUrl] base URL for the `/trust/keys/{tenant_id}` endpoint (default `https://app.usehasp.com`)
 * @property {typeof fetch} [fetcher] inject a fetch implementation (testing / air-gapped)
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
 * @property {{schema: CheckResult, chain: CheckResult, publishedKey: CheckResult, signatures: CheckResult, tsa: CheckResult}} checks
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

  const keyResult = await checkPublishedKey(validated, {
    fetcher: opts.fetcher,
    keyFile: opts.keyFile,
    expectedKey: opts.expectedKey,
    keysBaseUrl: opts.keysBaseUrl,
  });
  if (!keyResult.ok) {
    out.checks.publishedKey = { ran: true, ok: false, error: keyResult.error };
    return out;
  }
  // Drop the live KeyObject from the serializable summary; keep the metadata.
  out.checks.publishedKey = {
    ran: true,
    ok: true,
    key_id: keyResult.key_id,
    source: keyResult.source,
  };

  const sigResult = checkSignatures(validated, { publicKey: keyResult.publicKey });
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
