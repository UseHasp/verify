/**
 * Public type surface for @usehasp/verify.
 *
 * Hand-written to mirror the JSDoc in src/*.js. The runtime is plain
 * JavaScript; this file exists only so TypeScript consumers get
 * autocomplete and type-checking. There is no build step — what ships
 * to npm is the .js source plus this .d.ts.
 */

export const VERSION: string;
export const SCHEMA_VERSION: string;

export interface VerifyOptions {
  /** Skip the RFC 3161 TSA anchor check (offline mode). */
  skipTsa?: boolean;
  /**
   * Skip the published-key fetch + match. Signatures are then verified against
   * the export's embedded `verification.public_key_pem`, whose provenance is
   * unconfirmed.
   */
  skipKeyCheck?: boolean;
  /**
   * Read TSA CA certificate from this local PEM file instead of fetching
   * `tsa_cacert_url`. Useful for air-gapped or long-term archival verification.
   */
  caFile?: string;
  /**
   * Read the published-keys document from this local JSON file instead of
   * fetching `GET /trust/keys/{tenant_id}`. Useful for offline verification.
   */
  keysFile?: string;
  /** Override the published-keys URL. */
  keysUrl?: string;
  /** Inject a fetch implementation (for testing). */
  fetcher?: typeof fetch;
  /** Override the `openssl` binary path. */
  opensslPath?: string;
}

export type CheckOk = { ran: true; ok: true } & Record<string, unknown>;
export type CheckFail = { ran: true; ok: false; error: string };
export type CheckSkipped = { ran: false; skipped: true };
export type CheckNotRun = { ran: false };
export type CheckResult = CheckOk | CheckFail | CheckSkipped | CheckNotRun;

export interface TsaAnchorResult {
  tsa_url: string;
  anchored_data: string;
  output: string;
}

export interface VerifyResult {
  /** Overall pass/fail. True iff every ran check passed. */
  ok: boolean;
  checks: {
    schema: CheckResult;
    chain: CheckResult;
    key: CheckResult;
    signatures: CheckResult;
    tsa: CheckResult;
  };
}

/**
 * Verify a parsed Hasp audit export. Runs the schema preflight, then the chain,
 * published-key, signature, and TSA-anchor checks in order; short-circuits on
 * the first failure.
 *
 * @param data Parsed audit-export JSON (the result of `JSON.parse`).
 * @param opts Optional overrides — skip TSA / key check, supply local key or CA
 *   files, inject fetch, override openssl path.
 */
export function verifyExport(data: unknown, opts?: VerifyOptions): Promise<VerifyResult>;
