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
  output: string;
}

export interface VerifyResult {
  /** Overall pass/fail. True iff every ran check passed. */
  ok: boolean;
  checks: {
    schema: CheckResult;
    chain: CheckResult;
    signatures: CheckResult;
    tsa: CheckResult;
  };
}

/**
 * Verify a parsed Hasp audit export. Runs schema, chain, signature, and
 * TSA-anchor checks in order; short-circuits on first failure.
 *
 * @param data Parsed audit-export JSON (the result of `JSON.parse`).
 * @param opts Optional overrides — skip TSA, inject fetch, override openssl path.
 */
export function verifyExport(data: unknown, opts?: VerifyOptions): Promise<VerifyResult>;
