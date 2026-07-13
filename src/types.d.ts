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
   * Read TSA CA certificate from this local PEM file instead of fetching
   * `tsa_cacert_url`. Useful for air-gapped or long-term archival verification.
   */
  caFile?: string;
  /**
   * Read the independently-published signing key from this local PEM file
   * instead of fetching `/trust/keys/{tenant_id}`. The embedded
   * `verification.public_key_pem` must match it or verification fails closed.
   * Offline trust root, mirroring `caFile` for the TSA.
   */
  keyFile?: string;
  /**
   * The independently-published signing key as a PEM string. Same purpose as
   * `keyFile` for programmatic callers that already hold the key.
   */
  expectedKey?: string;
  /**
   * Base URL for the published-key endpoint `{keysBaseUrl}/trust/keys/{tenant_id}`.
   * Defaults to `https://app.usehasp.com`.
   */
  keysBaseUrl?: string;
  /** Inject a fetch implementation (for testing / air-gapped). */
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
  /** The hash (64-hex) this anchor's TSR covers. */
  anchored_data: string;
  output: string;
}

export interface VerifyResult {
  /** Overall pass/fail. True iff every ran check passed. */
  ok: boolean;
  checks: {
    schema: CheckResult;
    chain: CheckResult;
    /**
     * The trust-root check: the tenant's independently-published key was
     * resolved (via `/trust/keys`, `keyFile`, or `expectedKey`) and the
     * embedded `verification.public_key_pem` matches it. On success the check
     * carries `key_id` and `source` (where the trusted key came from).
     */
    publishedKey: CheckResult;
    signatures: CheckResult;
    tsa: CheckResult;
  };
}

/**
 * Verify a parsed Hasp audit export. Runs schema, chain, published-key,
 * signature, and TSA-anchor checks in order; short-circuits on first failure.
 *
 * @param data Parsed audit-export JSON (the result of `JSON.parse`).
 * @param opts Optional overrides — skip TSA, offline key/CA, keys URL, inject fetch, override openssl path.
 */
export function verifyExport(data: unknown, opts?: VerifyOptions): Promise<VerifyResult>;
